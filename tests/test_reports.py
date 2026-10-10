"""Тесты сводного отчёта (reports.full_diagnostic_report).

Главный guard: метрики (get_metrics — ~9 SSH-запросов) нужны сразу двум этапам
(«Метрики системы» и «Файрвол»). Раньше сводный прогон собирал их дважды
подряд. Тест считает фактические SSH-команды, а не текст отчёта.
"""
import os
import sys

# Чтобы импортировать модули проекта из корня, даже если pytest запущен из tests/
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

import reports as reports_mod
import metrics as metrics_mod
from support import FakeSSH


def _checker(routes=None):
    """FakeSSH + host/port: full_diagnostic_report печатает адрес сервера."""
    c = FakeSSH(routes or [])
    c.host = '203.0.113.7'
    c.port = 22
    return c


def _run(c, progress=None):
    return reports_mod.full_diagnostic_report(c, 'none', progress_cb=progress)


class TestSharedMetrics:
    def test_metrics_collected_once_per_report(self):
        """df -h / ufw status / статусы служб — ровно один раз за весь отчёт."""
        c = _checker()
        _run(c)
        assert c.count('df -h') == 1
        assert c.count('ufw status') == 1
        assert c.count('__svc_status') == 1

    def test_firewall_reuses_same_metrics_object(self, monkeypatch):
        """Файрвол печатается из тех же данных, что собраны для этапа метрик."""
        collected = {'disk': 'd', 'inodes': 'i', 'memory': 'm', 'uptime': 'u',
                     'listening_ports': 'p',
                     'firewall': {'ufw': 'Status: active'}, 'services': {}}
        calls = []

        def fake_get_metrics(checker):
            calls.append(checker)
            return collected

        monkeypatch.setattr(reports_mod, 'get_metrics', fake_get_metrics)
        out = _run(_checker())
        assert len(calls) == 1
        assert 'ufw:\nStatus: active' in out

    def test_single_reports_still_collect_themselves(self):
        """Отдельные кнопки (metrics_report/firewall_report без metrics) — как раньше."""
        c = _checker()
        metrics_mod.firewall_report(c)
        assert c.count('ufw status') == 1
        c2 = _checker()
        metrics_mod.metrics_report(c2)
        assert c2.count('df -h') == 1


class TestProgress:
    def test_progress_matches_stages(self):
        seen = []
        _run(_checker(), progress=lambda step, total, name: seen.append((step, total, name)))
        assert seen == [(i + 1, len(reports_mod.STAGES), name)
                        for i, name in enumerate(reports_mod.STAGES)]

    def test_progress_total_is_not_hardcoded_eight(self):
        """Индикатор честно говорит «1/N»: N = число реальных этапов, а не 8."""
        totals = set()
        _run(_checker(), progress=lambda step, total, name: totals.add(total))
        assert totals == {len(reports_mod.STAGES)}
        assert len(reports_mod.STAGES) == 4

    def test_progress_cb_exception_does_not_break_report(self):
        def bad_cb(step, total, name):
            raise RuntimeError('UI мёртв')

        out = _run(_checker(), progress=bad_cb)
        assert '=== ДИАГНОСТИКА ЗАВЕРШЕНА ===' in out


class TestReportContent:
    def test_report_has_all_stage_sections(self):
        out = _run(_checker())
        assert '203.0.113.7:22' in out
        assert 'Тип панели управления: none' in out
        assert '=== МЕТРИКИ СИСТЕМЫ ===' in out
        assert '=== ФАЙРВОЛ ===' in out
        assert '=== ПРОВЕРКА КОНФИГУРАЦИИ ВЕБ-СЕРВЕРА ===' in out
        assert '=== ДИАГНОСТИКА ЗАВЕРШЕНА ===' in out

    def test_sites_stage_runs_for_panel(self):
        """Этап логов вызывается с панелью: без доменов — честное сообщение."""
        out = _run(_checker())
        assert 'домены' in out.lower()
