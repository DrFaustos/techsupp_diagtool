"""Тесты gui_hosting.py: меню «Хостинг» (без Tk и без SSH).

Тот же паттерн, что в test_gui_bitrix.py: класс-хост переопределяет
_run_in_thread (поток не запускается, вызов записывается), simpledialog
подменяется на уровне модуля. Специфика этого миксина:

- меню не привязано к панели, поэтому panel_type передаётся бэкенду
  вторым аргументом (инвентарь работает и на сервере без панели);
- «Досье домена» спрашивает домен ДО ухода в фон и без cache_key —
  оператор каждый раз жмёт его на разных доменах, кеш врал бы.
"""
import os
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

import gui_hosting as gh
from gui_hosting import HOSTING_MENU, HostingMixin
from support import FakeSSH


class _Btn:
    def __init__(self):
        self.configs = []

    def config(self, **kw):
        self.configs.append(kw)


class _Frame:
    def __init__(self):
        self.packed = 0
        self.forgotten = 0

    def pack(self, **kw):
        self.packed += 1

    def pack_forget(self):
        self.forgotten += 1


class _Dialogs:
    """Двойник simpledialog: askstring отдаёт askstring_ret и считает обращения."""

    def __init__(self, askstring_ret=None):
        self.askstring_ret = askstring_ret
        self.string_asks = 0

    def askstring(self, *a, **k):
        self.string_asks += 1
        return self.askstring_ret


class _Host(HostingMixin):
    """Владелец миксина: panel_type ставим вручную — его берёт create_widgets."""

    def __init__(self, checker=None, panel_type='fastpanel'):
        self.checker = checker
        self.panel_type = panel_type
        self.root = None
        self.host_menu_btn = _Btn()
        self.hosting_frame = _Frame()
        self.calls = []

    def _run_in_thread(self, target_func, btn=None, *args, **kwargs):
        self.calls.append((target_func, btn, args, kwargs))


# None в меню — разделитель перед точечным запросом по домену. Фильтр обязан
# стоять ДО распаковки пары: распаковка None роняет сбор тестов.
ALL_HANDLERS = [m for entry in HOSTING_MENU if entry for _, m in [entry]]

# Отчёты: (обработчик, бэкенд, cache_key). Ничего не меняют — спрашивать
# нечего, результат кешируется 60 с (прогон по сотне доменов дорогой).
REPORT_MAP = [
    ("run_host_inventory", "hosting_inventory_report", "host_inventory"),
    ("run_host_sites", "site_health_report", "host_sites"),
    ("run_host_mail", "mail_overview_report", "host_mail"),
    ("run_host_zones", "dns_zones_report", "host_zones"),
]


class TestMenuIntegrity:
    def test_every_menu_item_has_handler(self):
        host = _Host()
        for name in ALL_HANDLERS:
            assert callable(getattr(host, name, None)), name

    def test_separator_isolates_domain_dialog(self):
        # После разделителя — только «Досье домена»: единственный пункт,
        # которому нужен операторский ввод.
        sep = HOSTING_MENU.index(None)
        after = [m for entry in HOSTING_MENU[sep + 1:] if entry
                 for _, m in [entry]]
        assert after == ["run_host_domain"]


class TestNoConnection:
    @pytest.mark.parametrize("handler", ALL_HANDLERS)
    def test_silent_without_checker(self, monkeypatch, handler):
        host = _Host(checker=None)
        dialogs = _Dialogs(askstring_ret='example.com')
        monkeypatch.setattr(gh, "simpledialog", dialogs)
        getattr(host, handler)()
        assert host.calls == [], handler
        # диалог без соединения — плохая идея: оператор введёт домен впустую
        assert dialogs.string_asks == 0, handler


class TestReports:
    @pytest.mark.parametrize("handler,backend,cache_key", REPORT_MAP)
    def test_report_passes_checker_and_panel_with_cache(
            self, monkeypatch, handler, backend, cache_key):
        checker = FakeSSH()
        host = _Host(checker, panel_type='ispmanager')
        getattr(host, handler)()
        assert len(host.calls) == 1
        fn, btn, args, kwargs = host.calls[0]
        assert fn is getattr(gh, backend), handler
        assert btn is host.host_menu_btn
        # panel_type уходит вторым аргументом: без него discovery вызывал бы
        # detect_panel() заново на каждый отчёт
        assert args == (checker, 'ispmanager')
        assert kwargs == {"cache_key": cache_key}


class TestDomainDetail:
    def test_cancelled_dialog_does_not_run(self, monkeypatch):
        host = _Host(FakeSSH())
        monkeypatch.setattr(gh, "simpledialog", _Dialogs(askstring_ret=None))
        host.run_host_domain()
        assert host.calls == []

    def test_blank_domain_does_not_run(self, monkeypatch):
        host = _Host(FakeSSH())
        monkeypatch.setattr(gh, "simpledialog", _Dialogs(askstring_ret='   '))
        host.run_host_domain()
        assert host.calls == []

    def test_domain_is_stripped_and_passed_without_cache(self, monkeypatch):
        checker = FakeSSH()
        host = _Host(checker, panel_type='none')
        monkeypatch.setattr(gh, "simpledialog",
                            _Dialogs(askstring_ret=' Example.COM '))
        host.run_host_domain()
        assert len(host.calls) == 1
        fn, btn, args, kwargs = host.calls[0]
        assert fn is gh.domain_detail_report
        assert btn is host.host_menu_btn
        # домен — сразу после checker и до panel_type; кеша нет: следующий
        # клик будет про другой домен
        assert args == (checker, 'Example.COM', 'none')
        assert kwargs == {}


class TestMenuVisibility:
    def test_show_with_connection_packs_and_enables(self):
        host = _Host(FakeSSH())
        host._set_hosting_menu_visible(True)
        assert host.hosting_frame.packed == 1
        assert host.host_menu_btn.configs[-1]['state'] == 'normal'

    def test_show_after_disconnect_is_ignored(self):
        # Гонка, как у Битрикса: меню показывают по событию, которое может
        # догнать уже закрытое соединение.
        host = _Host(checker=None)
        host._set_hosting_menu_visible(True)
        assert host.hosting_frame.packed == 0
        assert host.hosting_frame.forgotten == 1
        assert host.host_menu_btn.configs[-1]['state'] == 'disabled'

    def test_hide_forgets_and_disables(self):
        host = _Host(FakeSSH())
        host._set_hosting_menu_visible(False)
        assert host.hosting_frame.forgotten == 1
        assert host.host_menu_btn.configs[-1]['state'] == 'disabled'
