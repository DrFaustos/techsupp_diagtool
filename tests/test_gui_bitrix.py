"""Тесты gui_bitrix.py: меню «Битрикс» (без Tk и без SSH).

Тот же паттерн, что в test_gui_isp.py: класс-хост переопределяет
_run_in_thread (поток не запускается, вызов записывается), messagebox и
simpledialog подменяются на уровне модуля. Отдельно проверяются две вещи,
специфичные для этого миксина:
- гонка «фоновая проверка BitrixVM вернулась после disconnect()»:
  _set_bitrix_menu_visible обязан игнорировать show=True без checker;
- run_bx_mail_test спрашивает адрес ДО ухода в фон (_run_in_thread диалоги
  показывать не умеет) и обрезает пробелы.
"""
import os
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

import gui_bitrix as gb
from gui_bitrix import BITRIX_MENU, BitrixMixin
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
    def __init__(self, askyesno_ret=True, askstring_ret=None):
        self.askyesno_ret = askyesno_ret
        self.askstring_ret = askstring_ret
        self.asked = []
        self.string_asks = 0

    def askyesno(self, title, msg, parent=None):
        self.asked.append((title, msg))
        return self.askyesno_ret

    def askstring(self, *a, **k):
        self.string_asks += 1
        return self.askstring_ret

    def showerror(self, *a, **k):
        pass


class _FakeThreading:
    """Двойник модуля threading: Thread().start() выполняется сразу, в этом
    же потоке — иначе проверка фона в _detect_bitrix была бы гоночной."""

    def __init__(self):
        self.started = 0

    class _Thread:
        def __init__(self, target=None, daemon=None):
            self._target = target

        def start(self):
            assert callable(self._target), 'у миксина поток создаётся с target'
            self._target()

    def Thread(self, target=None, daemon=None):
        self.started += 1
        return self._Thread(target=target, daemon=daemon)


class _Host(BitrixMixin):
    def __init__(self, checker=None):
        self.checker = checker
        self.root = None
        self.bx_menu_btn = _Btn()
        self.bitrix_frame = _Frame()
        self.calls = []

    def _run_in_thread(self, target_func, btn=None, *args, **kwargs):
        self.calls.append((target_func, btn, args, kwargs))

    def _post_ui(self, fn, *args):
        fn(*args)


# None в меню — разделитель перед действиями, меняющими сервер. Фильтр обязан
# стоять ДО распаковки пары: распаковка None роняет сбор тестов.
ALL_HANDLERS = [m for entry in BITRIX_MENU if entry for _, m in [entry]]

# Отчёты: (обработчик, бэкенд, cache_key) — отчёт ничего не меняет, спрашивать
# нечего, результат кешируется 60 с.
REPORT_MAP = [
    ("run_bx_sites", "bitrix_sites_report", "bx_sites"),
    ("run_bx_ssl", "bitrix_ssl_report", "bx_ssl"),
    ("run_bx_mysql", "bitrix_mysql_report", "bx_mysql"),
    ("run_bx_cache", "bitrix_cache_report", "bx_cache"),
    ("run_bx_db_grants", "bitrix_db_grants_report", "bx_db_grants"),
    ("run_bx_db_tables", "bitrix_db_tables_report", "bx_db_tables"),
    ("run_bx_perms", "bitrix_perms_report", "bx_perms"),
    ("run_bx_php", "bitrix_php_report", "bx_php"),
    ("run_bx_cron", "bitrix_cron_report", "bx_cron"),
    ("run_bx_mail", "bitrix_mail_report", "bx_mail"),
]

# Действия с подтверждением: (обработчик, бэкенд). Кеш здесь запрещён:
# состояние «до действия» после него врёт.
CONFIRM_MAP = [
    ("run_bx_ssl_renew", "bitrix_ssl_renew"),
    ("run_bx_mysql_tune", "bitrix_mysql_tune"),
    ("run_bx_db_grants_fix", "bitrix_db_grants_fix"),
    ("run_bx_cron_install", "bitrix_cron_install"),
    ("run_bx_perms_fix", "bitrix_perms_fix"),
]


class TestMenuIntegrity:
    def test_every_menu_item_has_handler(self):
        host = _Host()
        for name in ALL_HANDLERS:
            assert callable(getattr(host, name, None)), name

    def test_separator_isolates_server_changing_actions(self):
        # После разделителя — только действия, меняющие сервер.
        sep = BITRIX_MENU.index(None)
        after = [m for entry in BITRIX_MENU[sep + 1:] if entry
                 for _, m in [entry]]
        assert after == ["run_bx_ssl_renew", "run_bx_mysql_tune",
                         "run_bx_db_grants_fix", "run_bx_mail_test",
                         "run_bx_cron_install", "run_bx_perms_fix"]


class TestNoConnection:
    @pytest.mark.parametrize("handler", ALL_HANDLERS)
    def test_silent_without_checker(self, monkeypatch, handler):
        host = _Host(checker=None)
        dialogs = _Dialogs()
        monkeypatch.setattr(gb, "messagebox", dialogs)
        monkeypatch.setattr(gb, "simpledialog", dialogs)
        getattr(host, handler)()
        assert host.calls == [], handler
        assert dialogs.asked == [], handler
        assert dialogs.string_asks == 0, handler


class TestReports:
    @pytest.mark.parametrize("handler,backend,cache_key", REPORT_MAP)
    def test_report_goes_to_thread_with_cache(
            self, monkeypatch, handler, backend, cache_key):
        checker = FakeSSH()
        host = _Host(checker)
        dialogs = _Dialogs()
        monkeypatch.setattr(gb, "messagebox", dialogs)
        getattr(host, handler)()
        assert len(host.calls) == 1
        fn, btn, args, kwargs = host.calls[0]
        assert fn is getattr(gb, backend), handler
        assert btn is host.bx_menu_btn
        assert args == (checker,)
        assert kwargs == {"cache_key": cache_key}
        assert dialogs.asked == []  # отчёт ничего не меняет

    def test_db_check_runs_without_cache(self):
        # Доступ к базе по dbconn.php — без cache_key (пароль может смениться,
        # а запрос дешёвый); проверяем, что это не потерялось при рефакторинге.
        checker = FakeSSH()
        host = _Host(checker)
        host.run_bx_db()
        assert len(host.calls) == 1
        fn, _btn, args, kwargs = host.calls[0]
        assert fn is gb.bitrix_db_check
        assert args == (checker,)
        assert kwargs == {}


class TestConfirmation:
    @pytest.mark.parametrize("handler,backend", CONFIRM_MAP)
    def test_declined_does_not_run_anything(self, monkeypatch, handler,
                                            backend):
        host = _Host(FakeSSH())
        monkeypatch.setattr(gb, "messagebox", _Dialogs(askyesno_ret=False))
        getattr(host, handler)()
        assert host.calls == []

    @pytest.mark.parametrize("handler,backend", CONFIRM_MAP)
    def test_confirmed_runs_backend_without_cache(self, monkeypatch, handler,
                                                  backend):
        checker = FakeSSH()
        host = _Host(checker)
        dialogs = _Dialogs(askyesno_ret=True)
        monkeypatch.setattr(gb, "messagebox", dialogs)
        getattr(host, handler)()
        assert len(host.calls) == 1
        fn, btn, args, kwargs = host.calls[0]
        assert fn is getattr(gb, backend), handler
        assert btn is host.bx_menu_btn
        assert args == (checker,)
        assert kwargs == {}
        assert dialogs.asked, "действие, меняющее сервер, обязано спрашивать"


class TestMailSendTest:
    def test_cancelled_dialog_does_not_run(self, monkeypatch):
        host = _Host(FakeSSH())
        monkeypatch.setattr(gb, "simpledialog",
                            _Dialogs(askstring_ret=None))
        host.run_bx_mail_test()
        assert host.calls == []

    def test_blank_address_does_not_run(self, monkeypatch):
        host = _Host(FakeSSH())
        monkeypatch.setattr(gb, "simpledialog",
                            _Dialogs(askstring_ret='   '))
        host.run_bx_mail_test()
        assert host.calls == []

    def test_address_is_stripped_and_passed(self, monkeypatch):
        checker = FakeSSH()
        host = _Host(checker)
        monkeypatch.setattr(gb, "simpledialog",
                            _Dialogs(askstring_ret=' admin@ex.com '))
        host.run_bx_mail_test()
        assert len(host.calls) == 1
        fn, btn, args, kwargs = host.calls[0]
        assert fn is gb.bitrix_mail_send_test
        assert btn is host.bx_menu_btn
        # адрес — отдельным аргументом ПОСЛЕ checker, пробелы срезаны
        assert args == (checker, 'admin@ex.com')
        assert kwargs == {}


class TestMenuVisibility:
    def test_show_with_connection_packs_and_enables(self):
        host = _Host(FakeSSH())
        host._set_bitrix_menu_visible(True)
        assert host.bitrix_frame.packed == 1
        assert host.bx_menu_btn.configs[-1]['state'] == 'normal'

    def test_show_after_disconnect_is_ignored(self):
        # Гонка: фоновая проверка вернула True уже после disconnect(). Меню
        # над закрытым соединением показывать нельзя.
        host = _Host(checker=None)
        host._set_bitrix_menu_visible(True)
        assert host.bitrix_frame.packed == 0
        assert host.bitrix_frame.forgotten == 1
        assert host.bx_menu_btn.configs[-1]['state'] == 'disabled'

    def test_hide_forgets_and_disables(self):
        host = _Host(FakeSSH())
        host._set_bitrix_menu_visible(False)
        assert host.bitrix_frame.forgotten == 1
        assert host.bx_menu_btn.configs[-1]['state'] == 'disabled'


class TestDetectBitrix:
    def test_no_checker_starts_no_thread(self, monkeypatch):
        fake_th = _FakeThreading()
        monkeypatch.setattr(gb, "threading", fake_th)
        host = _Host(checker=None)
        host._detect_bitrix()
        assert fake_th.started == 0

    def test_bitrixvm_shows_menu(self, monkeypatch):
        monkeypatch.setattr(gb, "threading", _FakeThreading())
        monkeypatch.setattr(gb, "detect_bitrix_env", lambda checker: True)
        host = _Host(FakeSSH())
        host._detect_bitrix()
        assert host.bitrix_frame.packed == 1

    def test_plain_server_keeps_menu_hidden(self, monkeypatch):
        monkeypatch.setattr(gb, "threading", _FakeThreading())
        monkeypatch.setattr(gb, "detect_bitrix_env", lambda checker: False)
        host = _Host(FakeSSH())
        host._detect_bitrix()
        assert host.bitrix_frame.packed == 0
        assert host.bitrix_frame.forgotten == 1

    def test_probe_error_keeps_menu_hidden(self, monkeypatch):
        # Ошибка самой проверки (обрыв соединения) не должна показывать меню и
        # ронять фоновый поток — except превращает её в found=False.
        def boom(checker):
            raise OSError('connection reset')

        monkeypatch.setattr(gb, "threading", _FakeThreading())
        monkeypatch.setattr(gb, "detect_bitrix_env", boom)
        host = _Host(FakeSSH())
        host._detect_bitrix()
        assert host.bitrix_frame.packed == 0
        assert host.bitrix_frame.forgotten == 1
