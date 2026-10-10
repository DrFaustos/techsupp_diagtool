"""Тесты gui_fastpanel.py: обработчики меню FastPanel (без Tk и без SSH).

Тот же паттерн, что в test_gui_isp.py: класс-хост переопределяет
_run_in_thread (поток не запускается, вызов записывается), messagebox
подменяется на уровне модуля. Отличие FastPanel — отчёты статуса и логов
уходят с cache_key (кеш 60 секунд в gui_runner), и это тоже проверяется.
"""
import os
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

import gui_fastpanel as gf
from gui_fastpanel import FASTPANEL_MENU, FastpanelMixin
from support import FakeSSH


class _Btn:
    def __init__(self):
        self.configs = []

    def config(self, **kw):
        self.configs.append(kw)


class _Dialogs:
    def __init__(self, askyesno_ret=True):
        self.askyesno_ret = askyesno_ret
        self.asked = []

    def askyesno(self, title, msg, parent=None):
        self.asked.append((title, msg))
        return self.askyesno_ret

    def showerror(self, *a, **k):
        pass


class _Host(FastpanelMixin):
    def __init__(self, checker=None):
        self.checker = checker
        self.root = None
        self.fp_menu_btn = _Btn()
        self.calls = []

    def _run_in_thread(self, target_func, btn=None, *args, **kwargs):
        self.calls.append((target_func, btn, args, kwargs))


# None в меню — разделитель (отделяет перезапуски), обработчика у него нет.
# Фильтр ДО распаковки пары: распаковка None роняет сбор тестов.
ALL_HANDLERS = [m for entry in FASTPANEL_MENU if entry for _, m in [entry]]
RESTART_MAP = [
    ("run_fp_restart", "fastpanel_restart"),
    ("run_fp_restart_web", "fastpanel_restart_web"),
]


class TestMenuIntegrity:
    def test_every_menu_item_has_handler(self):
        host = _Host()
        for name in ALL_HANDLERS:
            assert callable(getattr(host, name, None)), name


class TestNoConnection:
    @pytest.mark.parametrize("handler", ALL_HANDLERS)
    def test_silent_without_checker(self, monkeypatch, handler):
        host = _Host(checker=None)
        dialogs = _Dialogs()
        monkeypatch.setattr(gf, "messagebox", dialogs)
        getattr(host, handler)()
        assert host.calls == [], handler
        assert dialogs.asked == [], handler


class TestReadonlyReports:
    def test_status_goes_to_thread_with_cache_key(self, monkeypatch):
        checker = FakeSSH()
        host = _Host(checker)
        dialogs = _Dialogs()
        monkeypatch.setattr(gf, "messagebox", dialogs)
        host.run_fp_status()
        assert len(host.calls) == 1
        fn, btn, args, kwargs = host.calls[0]
        assert fn is gf.fastpanel_status
        assert btn is host.fp_menu_btn
        assert args == (checker,)
        assert kwargs == {"cache_key": "fp_status"}
        assert dialogs.asked == []  # отчёт ничего не меняет — спрашивать нечего

    def test_logs_goes_to_thread_with_cache_key(self, monkeypatch):
        checker = FakeSSH()
        host = _Host(checker)
        host.run_fp_logs()
        fn, _btn, args, kwargs = host.calls[0]
        assert fn is gf.fastpanel_logs
        assert args == (checker,)
        assert kwargs == {"cache_key": "fp_logs"}


class TestRestartConfirmation:
    @pytest.mark.parametrize("handler,backend", RESTART_MAP)
    def test_declined_does_not_run_anything(self, monkeypatch, handler, backend):
        host = _Host(FakeSSH())
        monkeypatch.setattr(gf, "messagebox", _Dialogs(askyesno_ret=False))
        getattr(host, handler)()
        assert host.calls == []

    @pytest.mark.parametrize("handler,backend", RESTART_MAP)
    def test_confirmed_runs_backend_without_cache(self, monkeypatch,
                                                  handler, backend):
        # Перезапуск — состояние «до перезапуска» из кеша после него врёт,
        # поэтому cache_key у перезапусков быть не должно.
        checker = FakeSSH()
        host = _Host(checker)
        dialogs = _Dialogs(askyesno_ret=True)
        monkeypatch.setattr(gf, "messagebox", dialogs)
        getattr(host, handler)()
        assert len(host.calls) == 1
        fn, btn, args, kwargs = host.calls[0]
        assert fn is getattr(gf, backend), handler
        assert btn is host.fp_menu_btn
        assert args == (checker,)
        assert kwargs == {}
        assert dialogs.asked, "перезапуск обязан спрашивать подтверждение"
