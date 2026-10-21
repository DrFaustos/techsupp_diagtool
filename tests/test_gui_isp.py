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
from support import FakeSSH, menu_handlers


class _Btn:
    def __init__(self):
        self.configs = []

    def config(self, **kw):
        self.configs.append(kw)


class _Dialogs:
    """Двойник messagebox + simpledialog: ответы отдаются, обращения пишутся.

    askstring нужен обработчику «Активировать по ключу»: он спрашивает секрет,
    поэтому показывается и `show` — ключ обязан вводиться со звёздочками.
    """

    def __init__(self, askyesno_ret=True, askstring_ret=None):
        self.askyesno_ret = askyesno_ret
        self.askstring_ret = askstring_ret
        self.asked = []
        self.askstring_called = []

    def askyesno(self, title, msg, parent=None):
        self.asked.append((title, msg))
        return self.askyesno_ret

    def askstring(self, title, prompt, show=None, parent=None, **kw):
        self.askstring_called.append((title, prompt, show))
        return self.askstring_ret

    def showerror(self, *a, **k):
        pass


class _Host(IspmanagerMixin):
    """Владелец миксина: _run_in_thread записывается, а не запускает поток."""

    def __init__(self, checker=None):
        self.checker = checker
        self.root = None
        self.isp_menu_btn = _Btn()
        self.calls = []
        # Живой DiagnosticApp имеет кеш диагностики (gui.py) — обработчик
        # активации обязан его протухать, поэтому заглушке тоже есть что терять.
        self._diag_cache = {}

    def _run_in_thread(self, target_func, btn=None, *args, **kwargs):
        self.calls.append((target_func, btn, args, kwargs))


# None в меню — разделитель, у него обработчика нет. Обработчики собирает общий
# menu_handlers: он фильтрует разделители и понимает вложенные подменю
# (распаковка пары списковым comprehension'ом упала бы на подменю).
ALL_HANDLERS = menu_handlers(ISPMANAGER_MENU)
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


class TestPanelDiagnostics:
    """Пункты «панель не открывается»: отчёты уходят без подтверждения."""

    @pytest.mark.parametrize("handler,backend,cache_key", [
        ("run_isp_diag", "ispmanager_panel_diag", "isp_diag"),
        # Логи намеренно БЕЗ cache_key: после только что выполненного лечения
        # оператор обязан увидеть свежий хвост, а не кеш 60-секундной давности.
        ("run_isp_logs", "ispmanager_logs_report", None),
        # Лицензия (только licctl info) — с кешем: за минуту лицензия не
        # «оживает», а пункт кликают подряд, разбираясь с панелью.
        ("run_isp_license_check", "ispmanager_license_report", "isp_license"),
    ])
    def test_reports_run_without_confirmation(self, monkeypatch, handler,
                                              backend, cache_key):
        checker = FakeSSH()
        host = _Host(checker)
        dialogs = _Dialogs()
        monkeypatch.setattr(gui_isp, "messagebox", dialogs)
        getattr(host, handler)()
        assert len(host.calls) == 1
        fn, btn, args, kwargs = host.calls[0]
        assert fn is getattr(gui_isp, backend), handler
        assert btn is host.isp_menu_btn
        assert args == (checker,)
        assert kwargs == ({"cache_key": cache_key} if cache_key else {})
        assert dialogs.asked == []


class TestUnlockAndLicense:
    """Разблокировка и лицензия меняют состояние панели — только с вопросом
    и без кеша (закешенное «до действия» после него врёт)."""

    CONFIRM = [
        ("run_isp_unlock", "ispmanager_unlock"),
        ("run_isp_license", "ispmanager_license_refresh"),
    ]

    @pytest.mark.parametrize("handler,backend", CONFIRM)
    def test_declined_does_not_run_anything(self, monkeypatch, handler, backend):
        host = _Host(FakeSSH())
        monkeypatch.setattr(gui_isp, "messagebox", _Dialogs(askyesno_ret=False))
        getattr(host, handler)()
        assert host.calls == []

    @pytest.mark.parametrize("handler,backend", CONFIRM)
    def test_confirmed_runs_backend_without_cache(self, monkeypatch, handler,
                                                  backend):
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


# ===== «Лицензия ▾ → Активировать по ключу»: секрет спрашивается ПОСЛЕ спроса =====
class TestLicenseActivateHandler:
    """Три порядка, которые здесь важны.

    1. Подтверждение ДО запроса ключа: спросить секрет, а потом отказаться,
       — плохой разговор с оператором (у него уже спрашивали пароль).
    2. Отмена диалога ключа не отправляет на сервер НИЧЕГО.
    3. Кеш отчёта «Проверить» обязан протухнуть: показать состояние «до»
       сразу после того, как мы его поменяли, — значит соврать оператору.
    """

    def test_declined_confirmation_never_asks_for_key(self, monkeypatch):
        host = _Host(FakeSSH())
        dialogs = _Dialogs(askyesno_ret=False, askstring_ret='SOME-KEY')
        monkeypatch.setattr(gui_isp, "messagebox", dialogs)
        monkeypatch.setattr(gui_isp, "simpledialog", dialogs)
        host.run_isp_license_activate()
        assert host.calls == []
        assert dialogs.asked, "пункт обязан спросить подтверждение"
        assert dialogs.askstring_called == [], "ключ спрашивается после согласия"

    def test_cancelled_key_dialog_runs_nothing(self, monkeypatch):
        host = _Host(FakeSSH())
        dialogs = _Dialogs(askyesno_ret=True, askstring_ret=None)
        monkeypatch.setattr(gui_isp, "messagebox", dialogs)
        monkeypatch.setattr(gui_isp, "simpledialog", dialogs)
        host.run_isp_license_activate()
        assert host.calls == []
        assert dialogs.askstring_called, "согласившемуся оператору показан ввод"

    def test_confirmed_key_goes_to_backend(self, monkeypatch):
        checker = FakeSSH()
        host = _Host(checker)
        dialogs = _Dialogs(askyesno_ret=True, askstring_ret='K1-ABCD-1234')
        monkeypatch.setattr(gui_isp, "messagebox", dialogs)
        monkeypatch.setattr(gui_isp, "simpledialog", dialogs)
        host.run_isp_license_activate()
        assert len(host.calls) == 1
        fn, btn, args, kwargs = host.calls[0]
        assert fn is gui_isp.ispmanager_license_activate
        assert btn is host.isp_menu_btn
        # Ключ — второй аргумент бэкенда (первым идёт checker) и без cache_key:
        # закешированный отчёт активации бессмысленен.
        assert args == (checker, 'K1-ABCD-1234')
        assert kwargs == {}

    def test_key_is_masked_on_screen(self, monkeypatch):
        # show='*': ключ вводят/вставляют, а не читают через плечо оператора.
        host = _Host(FakeSSH())
        dialogs = _Dialogs(askyesno_ret=True, askstring_ret='K1-ABCD-1234')
        monkeypatch.setattr(gui_isp, "messagebox", dialogs)
        monkeypatch.setattr(gui_isp, "simpledialog", dialogs)
        host.run_isp_license_activate()
        assert dialogs.askstring_called
        _title, _prompt, show = dialogs.askstring_called[0]
        assert show == '*'

    def test_stale_license_report_cache_is_dropped(self, monkeypatch):
        checker = FakeSSH()
        host = _Host(checker)
        host._diag_cache = {'isp_license': (0.0, '❌ Лицензия истекла'),
                            'isp_diag': (0.0, 'что-то ещё')}
        dialogs = _Dialogs(askyesno_ret=True, askstring_ret='K1-ABCD-1234')
        monkeypatch.setattr(gui_isp, "messagebox", dialogs)
        monkeypatch.setattr(gui_isp, "simpledialog", dialogs)
        host.run_isp_license_activate()
        assert 'isp_license' not in host._diag_cache
        # Чужие кеши трогать незачем — протухает ровно то, что изменилось.
        assert 'isp_diag' in host._diag_cache
        assert len(host.calls) == 1

    def test_warning_in_confirmation_names_real_risks(self, monkeypatch):
        # Подтверждение обязано говорить настоящие риски, а не абстрактное
        # «вы уверены?»: одноразовость ключа и видимость его в ps.
        host = _Host(FakeSSH())
        dialogs = _Dialogs(askyesno_ret=False)
        monkeypatch.setattr(gui_isp, "messagebox", dialogs)
        monkeypatch.setattr(gui_isp, "simpledialog", dialogs)
        host.run_isp_license_activate()
        text = " ".join(msg for _t, msg in dialogs.asked)
        assert 'одноразов' in text and 'ps' in text
        assert 'Обновить под IP' in text   # подсказка, как не сжигать ключ


class TestLicenseSubmenu:
    """Лицензия собрана в подменю: основной список не разрастается.

    Разделитель None в составе меню — не пара (подпись, значение), поэтому
    распаковку делает общий _entries: тест, который её не фильтрует, падает
    на распаковке None и ничего не проверяет.
    """

    @staticmethod
    def _entries():
        return [e for e in ISPMANAGER_MENU if e is not None]

    def test_license_group_is_a_submenu(self):
        labels = dict(self._entries())
        assert 'Лицензия ▾' in labels
        assert isinstance(labels['Лицензия ▾'], list)

    def test_submenu_order_is_read_then_treat_then_spend_key(self):
        sub = dict(self._entries())['Лицензия ▾']
        assert [m for _l, m in sub] == ["run_isp_license_check",
                                        "run_isp_license",
                                        "run_isp_license_activate"]

    def test_flat_list_did_not_grow(self):
        # Три лицензионных операции не занимают три строки верхнего меню:
        # плоских пунктов ровно 11 (было 10 до подменю и до его появления).
        flat = [v for _l, v in self._entries() if not isinstance(v, list)]
        assert len(flat) == 11

    def test_no_license_items_left_in_flat_menu(self):
        assert not [l for l, v in self._entries()
                    if not isinstance(v, list) and l.startswith('Лицензия')]

    def test_submenu_handlers_reach_the_class(self):
        # Вложенные обработчики живут на миксине так же, как плоские:
        # getattr в _fill_panel_menu достанет их по имени при построении меню.
        host = _Host()
        for name in menu_handlers(dict(self._entries())['Лицензия ▾']):
            assert callable(getattr(host, name, None)), name
