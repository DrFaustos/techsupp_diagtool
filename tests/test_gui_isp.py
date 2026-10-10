"""Тесты gui_isp.py: обработчики меню ISPmanager (без Tk и без SSH).

run_isp_* состоят из трёх вещей: проверка наличия checker, подтверждение
messagebox.askyesno и _run_in_thread с функцией из panels.py. Все три
подменяются двойниками: _run_in_thread переопределяется в классе-хосте,
messagebox — на уровне модуля. Так проверяются разрушающие действия
(Kill core, отключение панели) без реального подключения, а гард целости
меню фиксирует, что после переименований у пункта не осталось пустого места.
"""
import os
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

import gui_isp
from gui_isp import ISPMANAGER_MENU, IspmanagerMixin
from support import FakeSSH


class _Btn:
    def __init__(self):
        self.configs = []

    def config(self, **kw):
        self.configs.append(kw)


class _Dialogs:
    """Двойник messagebox: askyesno отдаёт askyesno_ret и пишет обращения."""

    def __init__(self, askyesno_ret=True):
        self.askyesno_ret = askyesno_ret
        self.asked = []

    def askyesno(self, title, msg, parent=None):
        self.asked.append((title, msg))
        return self.askyesno_ret

    def showerror(self, *a, **k):
        pass


class _Host(IspmanagerMixin):
    """Владелец миксина: _run_in_thread записывается, а не запускает поток."""

    def __init__(self, checker=None):
        self.checker = checker
        self.root = None
        self.isp_menu_btn = _Btn()
        self.calls = []

    def _run_in_thread(self, target_func, btn=None, *args, **kwargs):
        self.calls.append((target_func, btn, args, kwargs))


# None в меню — разделитель, у него обработчика нет. Фильтр обязан стоять ДО
# распаковки пары: распаковка None и есть та ошибка, которую ловили.
ALL_HANDLERS = [m for entry in ISPMANAGER_MENU if entry for _, m in [entry]]
# Каждый обработчик с подтверждением и бэкенд, который он обязан вызвать.
CONFIRM_MAP = [
    ("run_isp_restart", "ispmanager_restart"),
    ("run_isp_kill", "ispmanager_kill_core"),
    ("run_isp_update", "ispmanager_update"),
    ("run_isp_ssl", "ispmanager_ssl_issue"),
    ("run_isp_disable", "ispmanager_disable"),
    ("run_isp_geoip", "ispmanager_disable_geoip"),
    ("run_isp_fix_cron", "ispmanager_fix_cron_path"),
]


class TestMenuIntegrity:
    def test_every_menu_item_has_handler(self):
        host = _Host()
        for name in ALL_HANDLERS:
            assert callable(getattr(host, name, None)), name

    def test_separator_isolates_destructive_actions(self):
        # Разделитель обязан стоять перед разрушительными действиями: всё,
        # что после None, — Kill core и отключение панели.
        sep = ISPMANAGER_MENU.index(None)
        after = [m for _, m in ISPMANAGER_MENU[sep + 1:]]
        assert after == ["run_isp_kill", "run_isp_disable"]


class TestNoConnection:
    @pytest.mark.parametrize("handler", ALL_HANDLERS)
    def test_silent_without_checker(self, monkeypatch, handler):
        host = _Host(checker=None)
        dialogs = _Dialogs()
        monkeypatch.setattr(gui_isp, "messagebox", dialogs)
        getattr(host, handler)()
        assert host.calls == [], handler
        assert dialogs.asked == [], handler


class TestConfirmation:
    @pytest.mark.parametrize("handler,backend", CONFIRM_MAP)
    def test_declined_does_not_run_anything(self, monkeypatch, handler, backend):
        host = _Host(FakeSSH())
        monkeypatch.setattr(gui_isp, "messagebox", _Dialogs(askyesno_ret=False))
        getattr(host, handler)()
        assert host.calls == []

    @pytest.mark.parametrize("handler,backend", CONFIRM_MAP)
    def test_confirmed_runs_backend_in_thread(self, monkeypatch, handler, backend):
        checker = FakeSSH()
        host = _Host(checker)
        dialogs = _Dialogs(askyesno_ret=True)
        monkeypatch.setattr(gui_isp, "messagebox", dialogs)
        getattr(host, handler)()
        assert len(host.calls) == 1
        fn, btn, args, kwargs = host.calls[0]
        assert fn is getattr(gui_isp, backend), handler
        assert btn is host.isp_menu_btn
        assert args == (checker,)
        assert kwargs == {}
        assert dialogs.asked, "обработчик обязан спросить подтверждение"


class TestNoConfirmation:
    def test_cron_check_runs_immediately(self, monkeypatch):
        # Проверка CRON PATH безвредна — спрашивать нечего, уходит сразу.
        checker = FakeSSH()
        host = _Host(checker)
        dialogs = _Dialogs()
        monkeypatch.setattr(gui_isp, "messagebox", dialogs)
        host.run_isp_cron()
        assert len(host.calls) == 1
        assert host.calls[0][0] is gui_isp.ispmanager_check_cron_path
        assert host.calls[0][2] == (checker,)
        assert dialogs.asked == []
