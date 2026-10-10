"""Тесты gui_admin.py: замена IP в конфигах, перезапуск служб, bash-история, редактор конфигов (без Tk и без SSH).

Тот же приём, что в test_gui_checks: класс-хост переопределяет _run_in_thread/
_run_simple/log/_display_result (потоки не запускаются, вызовы записываются),
simpledialog и messagebox подменяются на уровне модуля. Диалоги (окно истории,
редактор конфигов) собираются фабрикой-заглушкой tk/tb/ttk/scrolledtext, а
get_config_files/read_file/write_file подменены в namespace gui_admin. Так
разрушающие действия (замена IPv4/IPv6 во всех /etc) проверяются без реального
подключения, а логика редактора (автозагрузка → правка → сохранение → закрытие)
— без дисплея.
"""
import os
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

import gui_admin as ga
from gui_admin import AdminMixin
from support import FakeSSH


class _Var:
    def __init__(self, value=''):
        self._v = value
        self.history = []

    def get(self):
        return self._v

    def set(self, value):
        self._v = value
        self.history.append(value)


class _Widget:
    """Любой виджет: пишет pack/grid/config; get() читает textvariable.

    ScrolledText дополнительно держит буфер (insert/delete/get), и get() —
    как в реальном Tk — возвращает содержимое с завершающим переводом строки
    (на этом держится проверка close_editor: get(1.0, END) всегда отличается
    от прочитанного файла на '\n', поэтому закрытие спрашивает подтверждение).
    """

    def __init__(self, kind, master=None, **kw):
        self.kind = kind
        self.master = master
        self.kw = kw
        self.configs = []
        self.packs = []
        self.grids = []
        self.buf = ''

    def pack(self, **kw):
        self.packs.append(kw)

    def grid(self, **kw):
        self.grids.append(kw)

    def config(self, **kw):
        self.configs.append(kw)

    def insert(self, *a):
        self.buf += a[-1]

    def delete(self, *a):
        self.buf = ''

    def set(self, value):
        var = self.kw.get('textvariable')
        if var is not None:
            var.set(value)

    def get(self, *a):
        if self.kind == 'ScrolledText':
            return self.buf + '\n'
        var = self.kw.get('textvariable')
        return var.get() if var is not None else ''


class _DialogWidget(_Widget):
    def __init__(self, master=None, **kw):
        super().__init__('Toplevel', master, **kw)
        self.titles = []
        self.grabbed = 0
        self.transients = 0
        self.updated = 0
        self.destroyed = 0

    def title(self, text=''):
        self.titles.append(text)

    def geometry(self, geo=''):
        pass

    def minsize(self, *a, **kw):
        pass

    def transient(self, win):
        self.transients += 1

    def grab_set(self):
        self.grabbed += 1

    def update(self):
        self.updated += 1

    def destroy(self):
        self.destroyed += 1


class _TkBundle:
    """Фабрика tk/tb/ttk/scrolledtext-виджетов: всё созданное — в реестр."""

    DISABLED = 'disabled'
    NORMAL = 'normal'

    def __init__(self):
        self.widgets = []

    def __getattr__(self, name):
        # Константы tk (END, X, LEFT, RIGHT, BOTH, NONE, ...) отдаём именем-
        # строкой: виджетам-двойникам они нужны только как значения pack/grid.
        # Только имена в ВЕРХнем регистре — опечатка в имени фабрики
        # (Checkbuton) обязана остаться AttributeError, а не стать вызовом
        # строки.
        if name.isupper() and name.isidentifier() and not name.startswith('_'):
            return name.lower()
        raise AttributeError(f'_TkBundle: нет атрибута {name!r}')

    def _mk(self, kind, master=None, **kw):
        w = _Widget(kind, master, **kw)
        self.widgets.append(w)
        return w

    def Toplevel(self, master=None, **kw):
        d = _DialogWidget(master, **kw)
        self.widgets.append(d)
        return d

    def Frame(self, master=None, **kw):
        return self._mk('Frame', master, **kw)

    def Label(self, master=None, **kw):
        return self._mk('Label', master, **kw)

    def Button(self, master=None, **kw):
        return self._mk('Button', master, **kw)

    def Combobox(self, master=None, **kw):
        return self._mk('Combobox', master, **kw)

    def ScrolledText(self, master=None, **kw):
        return self._mk('ScrolledText', master, **kw)

    def StringVar(self, value='', **kw):
        return _Var(value)

    def by_kind(self, kind):
        return [w for w in self.widgets if w.kind == kind]

    def button(self, text):
        for w in self.by_kind('Button'):
            if w.kw.get('text') == text:
                return w
        raise AssertionError(f'кнопка {text!r} не создана')

    def command(self, text):
        return self.button(text).kw['command']

    def dialog(self):
        return self.by_kind('Toplevel')[0]


class _Dialogs:
    """Двойник simpledialog: очередь ответов askstring + запись обращений."""

    def __init__(self, answers=()):
        self.answers = list(answers)
        self.string_asks = []

    def askstring(self, title, prompt, initialvalue=None, parent=None):
        self.string_asks.append({'title': title, 'initialvalue': initialvalue})
        return self.answers.pop(0) if self.answers else None


class _Msg:
    def __init__(self, askyesno_ret=True):
        self.askyesno_ret = askyesno_ret
        self.events = []  # (kind, title, msg)
        self.asks = []

    def askyesno(self, title, msg, parent=None):
        self.asks.append((title, msg))
        return self.askyesno_ret

    def showerror(self, title, msg, parent=None):
        self.events.append(('error', title, msg))

    def showwarning(self, title, msg, parent=None):
        self.events.append(('warning', title, msg))

    def showinfo(self, title, msg, parent=None):
        self.events.append(('info', title, msg))


class _Host(AdminMixin):
    def __init__(self, checker=None, panel_type='PANEL'):
        self.checker = checker
        self.panel_type = panel_type
        self.root = None
        self.logs = []
        self.threads = []
        self.simples = []
        self.shown = []
        # Кнопки объявлены явно: статический анализ должен их видеть.
        self.ipv4_btn = object()
        self.ipv6_btn = object()
        self.restart_btn = object()

    def log(self, text):
        self.logs.append(text)

    def _run_in_thread(self, target_func, btn=None, *args, **kwargs):
        self.threads.append((target_func, btn, args, kwargs))

    def _run_simple(self, func, btn=None, on_done=None, *args):
        self.simples.append((func, btn, on_done, args))

    def _display_result(self, result):
        self.shown.append(result)


def _patch_dialogs(monkeypatch, answers=()):
    dialogs = _Dialogs(answers)
    monkeypatch.setattr(ga, 'simpledialog', dialogs)
    msg = _Msg()
    monkeypatch.setattr(ga, 'messagebox', msg)
    return dialogs, msg


# ==================== замена IPv4 ====================
class TestReplaceIPv4:
    def test_silent_without_checker(self, monkeypatch):
        dialogs, msg = _patch_dialogs(monkeypatch)
        host = _Host(checker=None)
        host.run_replace_ipv4()
        assert host.threads == []
        assert dialogs.string_asks == []
        assert msg.asks == []

    def test_cancel_old_ip_asks_nothing_more(self, monkeypatch):
        dialogs, msg = _patch_dialogs(monkeypatch, answers=[None])
        host = _Host(FakeSSH())
        host.run_replace_ipv4()
        assert len(dialogs.string_asks) == 1  # новый IP не спрашивали
        assert host.threads == [] and msg.asks == [] and msg.events == []

    def test_invalid_old_ip_blocks_before_second_question(self, monkeypatch):
        dialogs, msg = _patch_dialogs(monkeypatch, answers=['999-не-ip'])
        host = _Host(FakeSSH())
        host.run_replace_ipv4()
        assert msg.events == [('error', 'Ошибка', 'Неверный формат IPv4-адреса')]
        assert len(dialogs.string_asks) == 1
        assert host.threads == []

    def test_invalid_new_ip_blocks_before_confirmation(self, monkeypatch):
        dialogs, msg = _patch_dialogs(monkeypatch, answers=['10.0.0.1', 'abc'])
        host = _Host(FakeSSH())
        host.run_replace_ipv4()
        assert msg.events == [('error', 'Ошибка', 'Неверный формат IPv4-адреса')]
        assert msg.asks == []  # подтверждение не открывалось
        assert host.threads == []

    def test_declined_does_not_run(self, monkeypatch):
        dialogs, msg = _patch_dialogs(monkeypatch, answers=['10.0.0.1', '10.0.0.2'])
        msg.askyesno_ret = False
        host = _Host(FakeSSH())
        host.run_replace_ipv4()
        assert len(msg.asks) == 1  # спросил
        assert host.threads == []  # и не сделал

    def test_confirmed_passes_both_ips(self, monkeypatch):
        dialogs, msg = _patch_dialogs(monkeypatch, answers=['10.0.0.1', '10.0.0.2'])
        checker = FakeSSH()
        host = _Host(checker)
        host.run_replace_ipv4()
        assert len(host.threads) == 1
        fn, btn, args, kwargs = host.threads[0]
        assert fn is ga.replace_ipv4
        assert btn is host.ipv4_btn
        assert args == (checker, '10.0.0.1', '10.0.0.2')
        assert kwargs == {}
        # в тексте подтверждения — предупреждение о перезапуске служб
        assert 'nginx' in msg.asks[0][1]


# ==================== отмена на втором вопросе ====================
class TestCancelledSecondQuestion:
    def test_ipv4_new_ip_cancelled_launches_nothing(self, monkeypatch):
        # старый IP валиден, новый не введён («Отмена»): подтверждение не
        # открывается, replace_ipv4 не уходит
        dialogs, msg = _patch_dialogs(monkeypatch, answers=['10.0.0.1', None])
        host = _Host(FakeSSH())
        host.run_replace_ipv4()
        assert len(dialogs.string_asks) == 2
        assert msg.asks == [] and msg.events == [] and host.threads == []

    def test_ipv6_old_ip_cancelled(self, monkeypatch):
        dialogs, msg = _patch_dialogs(monkeypatch, answers=[None])
        host = _Host(FakeSSH())
        host.run_replace_ipv6()
        assert len(dialogs.string_asks) == 1   # второй раз не спрашивали
        assert msg.asks == [] and msg.events == [] and host.threads == []

    def test_ipv6_new_ip_cancelled(self, monkeypatch):
        dialogs, msg = _patch_dialogs(monkeypatch, answers=['2001:db8::1', ''])
        host = _Host(FakeSSH())
        host.run_replace_ipv6()
        assert len(dialogs.string_asks) == 2
        assert msg.asks == [] and msg.events == [] and host.threads == []


# ==================== валидатор IPv6 ====================
class TestValidIPv6:
    @pytest.mark.parametrize("value,ok", [
        ('2001:db8::1', True),
        ('::1', True),
        # scope-id разрешён парсеру с Python 3.9 — валидатор это наследует
        ('fe80::1%eth0', True),
        ('8.8.8.8', False),
        ('просто текст', False),
        ('', False),
    ])
    def test_validity(self, value, ok):
        assert _Host()._valid_ipv6(value) is ok


class TestReplaceIPv6:
    def test_silent_without_checker(self, monkeypatch):
        dialogs, _msg = _patch_dialogs(monkeypatch)
        host = _Host(checker=None)
        host.run_replace_ipv6()
        assert host.threads == [] and dialogs.string_asks == []

    def test_invalid_old_ip_blocks(self, monkeypatch):
        dialogs, msg = _patch_dialogs(monkeypatch, answers=['2001:db8::G'])
        host = _Host(FakeSSH())
        host.run_replace_ipv6()
        assert msg.events[0][0] == 'error'
        assert len(dialogs.string_asks) == 1
        assert host.threads == []

    def test_addresses_are_stripped_before_use(self, monkeypatch):
        # « 2001:db8::1 » с пробелами валиден только после strip(); именно
        # срезанное значение должно уйти и в подтверждение, и в команду.
        dialogs, msg = _patch_dialogs(
            monkeypatch, answers=[' 2001:db8::1 ', '2001:db8::2'])
        checker = FakeSSH()
        host = _Host(checker)
        host.run_replace_ipv6()
        assert len(host.threads) == 1
        fn, btn, args, _kw = host.threads[0]
        assert fn is ga.replace_ipv6 and btn is host.ipv6_btn
        assert args == (checker, '2001:db8::1', '2001:db8::2')
        assert '2001:db8::1' in msg.asks[0][1]
        # диалог обязан предупреждать, что обрабатываются ВСЕ файлы /etc
        assert 'ВСЕХ' in msg.asks[0][1]

    def test_invalid_new_ip_blocks_before_confirmation(self, monkeypatch):
        dialogs, msg = _patch_dialogs(
            monkeypatch, answers=['2001:db8::1', 'не-v6'])
        host = _Host(FakeSSH())
        host.run_replace_ipv6()
        assert msg.events[0][0] == 'error'
        assert msg.asks == [] and host.threads == []


# ==================== перезапуск служб ====================
class TestRestartServices:
    def test_silent_without_checker(self, monkeypatch):
        _d, msg = _patch_dialogs(monkeypatch)
        host = _Host(checker=None)
        host.run_restart_services()
        assert host.threads == [] and msg.asks == []

    def test_declined_does_not_run(self, monkeypatch):
        _d, msg = _patch_dialogs(monkeypatch)
        msg.askyesno_ret = False
        host = _Host(FakeSSH())
        host.run_restart_services()
        assert msg.asks and host.threads == []

    def test_confirmed_runs_in_thread(self, monkeypatch):
        _d, msg = _patch_dialogs(monkeypatch)
        checker = FakeSSH()
        host = _Host(checker)
        host.run_restart_services()
        assert len(host.threads) == 1
        fn, btn, args, kwargs = host.threads[0]
        assert fn is ga.restart_services and btn is host.restart_btn
        assert args == (checker,) and kwargs == {}


# ==================== bash-история ====================
HISTORY_ROUTES = [('bash_history', ('ls\n pwd \n\n', '', 0))]


class TestGetBashHistory:
    def test_no_connection_logs_and_returns_empty(self):
        host = _Host(checker=None)
        assert host.get_bash_history() == []
        assert host.logs == ['⚠️ Нет подключения к серверу']

    def test_stderr_reported_as_warning(self):
        checker = FakeSSH([('bash_history', ('', 'perm denied', 1))])
        host = _Host(checker)
        assert host.get_bash_history() == []
        assert host.logs and 'Ошибка при чтении' in host.logs[0]

    def test_lines_are_stripped_and_filtered(self):
        checker = FakeSSH(HISTORY_ROUTES)
        host = _Host(checker)
        assert host.get_bash_history() == ['ls', 'pwd']
        assert host.logs == []

    def test_missing_history_logged(self):
        checker = FakeSSH([('bash_history', '')])
        host = _Host(checker)
        assert host.get_bash_history() == []
        assert host.logs and 'не найдена или пуста' in host.logs[0]


class TestShowBashHistory:
    def _bundle(self, monkeypatch):
        bundle = _TkBundle()
        monkeypatch.setattr(ga, 'tk', bundle)
        monkeypatch.setattr(ga, 'tb', bundle)
        monkeypatch.setattr(ga, 'scrolledtext', bundle)
        msg = _Msg()
        monkeypatch.setattr(ga, 'messagebox', msg)
        return bundle, msg

    def test_no_connection_warns(self, monkeypatch):
        _b, msg = self._bundle(monkeypatch)
        host = _Host(checker=None)
        host.show_bash_history()
        assert msg.events[0][0] == 'warning'
        assert host.simples == []

    def test_history_read_defers_to_background(self, monkeypatch):
        self._bundle(monkeypatch)
        host = _Host(FakeSSH())
        host.show_bash_history()
        assert len(host.simples) == 1
        fn, btn, on_done, args = host.simples[0]
        assert fn == host.get_bash_history and btn is None
        assert args == () and callable(on_done)

    def test_on_done_string_is_logged(self, monkeypatch):
        bundle, msg = self._bundle(monkeypatch)
        host = _Host(FakeSSH())
        host.show_bash_history()
        on_done = host.simples[0][2]
        on_done('❌ обрыв')
        assert host.logs == ['❌ обрыв']
        assert bundle.by_kind('Toplevel') == []

    def test_on_done_empty_shows_info(self, monkeypatch):
        bundle, msg = self._bundle(monkeypatch)
        host = _Host(FakeSSH())
        host.show_bash_history()
        host.simples[0][2]([])
        assert msg.events[0][0] == 'info'
        assert bundle.by_kind('Toplevel') == []

    def test_on_done_opens_readonly_window(self, monkeypatch):
        bundle, msg = self._bundle(monkeypatch)
        host = _Host(FakeSSH())
        host.show_bash_history()
        host.simples[0][2](['ls', 'pwd'])
        toplevel = bundle.dialog()
        assert toplevel.grabbed == 1 and toplevel.transients == 1
        text = bundle.by_kind('ScrolledText')[0]
        assert text.buf == 'ls\npwd'
        assert text.configs[-1] == {'state': bundle.DISABLED}


# ==================== редактор конфигов ====================
CONF = '/etc/nginx/nginx.conf'
CONTENT = 'worker 4;'


@pytest.fixture()
def ed(monkeypatch):
    """Открытый редактор: реестр виджетов + записанные read/write."""
    checker = FakeSSH()
    host = _Host(checker)
    bundle = _TkBundle()
    msg = _Msg()
    reads, writes = [], []

    def fake_files(c, panel):
        reads_panel.append((c, panel))
        return [CONF]

    def fake_read(c, path):
        reads.append((c, path))
        return CONTENT

    def fake_write(c, path, content):
        writes.append((c, path, content))
        return 'REZULTAT'

    reads_panel = []
    monkeypatch.setattr(ga, 'tk', bundle)
    monkeypatch.setattr(ga, 'tb', bundle)
    monkeypatch.setattr(ga, 'ttk', bundle)
    monkeypatch.setattr(ga, 'scrolledtext', bundle)
    monkeypatch.setattr(ga, 'messagebox', msg)
    monkeypatch.setattr(ga, 'get_config_files', fake_files)
    monkeypatch.setattr(ga, 'read_file', fake_read)
    monkeypatch.setattr(ga, 'write_file', fake_write)
    host.run_config_editor()
    import types
    return types.SimpleNamespace(host=host, bundle=bundle, msg=msg,
                                 reads=reads, writes=writes,
                                 reads_panel=reads_panel, checker=checker)


class TestConfigEditor:
    def test_silent_without_checker(self, monkeypatch):
        called = []
        monkeypatch.setattr(ga, 'get_config_files',
                            lambda c, p: called.append(1) or [])
        host = _Host(checker=None)
        host.run_config_editor()
        assert called == []

    def test_no_files_shows_info(self, monkeypatch):
        bundle = _TkBundle()
        msg = _Msg()
        monkeypatch.setattr(ga, 'messagebox', msg)
        monkeypatch.setattr(ga, 'get_config_files', lambda c, p: [])
        host = _Host(FakeSSH())
        host.run_config_editor()
        assert msg.events[0][0] == 'info'
        assert bundle.by_kind('Toplevel') == []

    def test_panel_type_reaches_file_list(self, ed):
        assert ed.reads_panel == [(ed.checker, 'PANEL')]

    def test_first_file_autoloaded(self, ed):
        combo = ed.bundle.by_kind('Combobox')[0]
        assert combo.kw['values'] == [CONF]
        assert combo.kw['textvariable'].get() == CONF
        assert ed.reads == [(ed.checker, CONF)]
        text = ed.bundle.by_kind('ScrolledText')[0]
        assert text.buf == CONTENT
        toplevel = ed.bundle.dialog()
        assert toplevel.grabbed == 1 and toplevel.transients == 1

    def test_load_without_selection_warns(self, ed):
        combo = ed.bundle.by_kind('Combobox')[0]
        combo.kw['textvariable'].set('')
        ed.bundle.command('Загрузить')()
        assert ed.msg.events[0][0] == 'warning'
        assert len(ed.reads) == 1  # нового чтения не было

    def test_reload_reads_file_again(self, ed):
        ed.bundle.command('Перезагрузить')()
        assert ed.reads == [(ed.checker, CONF), (ed.checker, CONF)]

    def test_save_confirmed_writes_editor_content(self, ed):
        ed.bundle.command('Сохранить')()
        # Tk get(1.0, END) отдаёт текст с завершающим переводом строки
        assert ed.writes == [(ed.checker, CONF, CONTENT + '\n')]
        assert ed.host.shown == ['REZULTAT']
        assert ed.msg.events[-1][0] == 'info'

    def test_save_declined_writes_nothing(self, ed):
        ed.msg.askyesno_ret = False
        ed.bundle.command('Сохранить')()
        assert ed.writes == []
        assert ed.host.shown == []

    def test_close_asks_confirmation_then_destroys(self, ed):
        # get(1.0, END) всегда на '\n' длиннее прочитанного — закрытие обязано
        # спросить, даже если пользователь «ничего не менял».
        ed.msg.askyesno_ret = True
        ed.bundle.command('Закрыть')()
        assert ed.msg.asks and 'Закрыть' in ed.msg.asks[0][1]
        assert ed.bundle.dialog().destroyed == 1

    def test_close_declined_keeps_editor(self, ed):
        ed.msg.askyesno_ret = False
        ed.bundle.command('Закрыть')()
        assert ed.bundle.dialog().destroyed == 0
