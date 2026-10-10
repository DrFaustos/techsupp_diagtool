"""Сводный отчёт по диагностике."""
from metrics import get_metrics, metrics_report, firewall_report, web_config_report
from logs import site_logs_report

# Этапы полной диагностики (для индикатора прогресса 1/N ... N/N).
# Единственный источник имён этапов: full_diagnostic_report строит steps из
# этого списка, поэтому подпись этапа и его исполнитель не разъедутся.
STAGES = [
    "Метрики системы",
    "Файрвол",
    "Конфигурация веб-сервера",
    "Логи сайтов",
]


def full_diagnostic_report(checker, panel, progress_cb=None):
    """Сводный отчёт. progress_cb(step, total, name) вызывается по этапам.

    get_metrics() — дорогой (~9 SSH-запросов) и нужен сразу двум этапам:
    «Метрики системы» и «Файрвол». Раньше каждый этап звал его сам, и сводный
    прогон собирал метрики дважды подряд. Здесь они собираются один раз и
    переиспользуются. Собираются лениво — внутри этапа 1, чтобы progress_cb(1,
    ...) пришёл до фактического сбора (как и раньше).
    """
    cache = {}

    def shared_metrics():
        if 'metrics' not in cache:
            cache['metrics'] = get_metrics(checker)
        return cache['metrics']

    lines = []
    lines.append(f"=== Начинаем диагностику сервера {checker.host}:{checker.port} ===")
    lines.append(f"Тип панели управления: {panel}\n")

    steps = [
        (STAGES[0], lambda: metrics_report(checker, shared_metrics())),
        (STAGES[1], lambda: firewall_report(checker, shared_metrics())),
        (STAGES[2], lambda: web_config_report(checker)),
        (STAGES[3], lambda: site_logs_report(checker, panel)),
    ]
    total = len(steps)
    for i, (name, fn) in enumerate(steps, 1):
        if progress_cb:
            try:
                progress_cb(i, total, name)
            except Exception:
                pass
        if i > 1:
            lines.append("\n")
        lines.append(fn())

    lines.append("\n=== ДИАГНОСТИКА ЗАВЕРШЕНА ===")
    return "\n".join(lines)
