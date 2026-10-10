"""Тесты gui_dns.py: DNS-проверка доменов, резолверы и диалог их замены (без Tk и без SSH).

Приём тот же, что в test_gui_checks / test_gui_admin: класс-хост переопределяет
_run_in_thread/_run_simple/log (потоки не запускаются, вызовы записываются),
tk/tb/ttk подменены фабрикой-заглушкой (виджеты — в реестр), simpledialog и
messagebox — двойники на уровне модуля. Отдельно закрывается ветка «DNS не
найдены»: диалог НЕ открывается, а в лог уходят resolv.conf и resolvectl —
раньше этот путь был самым вероятным на живом сервере и при этом не тестировался.
"""
import os
import sys
import types

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

import gui_dns as gd
from gui_dns import DnsMixin
from support import FakeSSH


class _Var:
    """Замена StringVar/BooleanVar: get/set + история set() (для combo.set(''))."""

    def __init__(self, value=''):
        self._v = value
        self.history = []

    def get(self):
        return self._v

    def set(self, value):
        self._v = value
        self.history.append(value)


class _Widget:
    """Любой виджет: пишет pack/grid/config; get() читает textvariable."""

    def __init__(self, kind, master=None, **kw):
        self.kind = kind
        self.master = master
        self.kw = kw
        self.configs = []
        self.packs = []
        self.grids = []

    def pack(self, **kw):
        self.packs.append(kw)

    def grid(self, **kw):
        self.grids.append(kw)

    def config(self, **kw):
        self.configs.append(kw)

    def set(self, value):
        var = self.kw.get('textvariable')
        if var is not None:
            var.set(value)

    def get(self, *a):
        var = self.kw.get('textvariable')
        return var.get() if var is not None else ''


class _Listbox(_Widget):
    """Двойник tk.Listbox: items + явно управляемая curselection.

    selection задаёт тест (в реальном Tk — результат клика): без прямого
    контроля над ней ветки «нет выбора» и «редактировать выбранный» были бы
    недостижимы.
    """

    def __init__(self, master=None, **kw):
        super().__init__('Listbox', master, **kw)
        self.items = []
        self.selection = ()

    def insert(self, index, value):
        if index == 'end':
            self.items.append(value)
        else:
            self.items.insert(index, value)

    def delete(self, first, last=None):
        # как в реальном Tk: delete(i) — один элемент, delete(0, END) — диапазон
        if last is None:
            self.items.pop(first)
            return
        end = len(self.items) if last == 'end' else int(last) + 1
        del self.items[first:end]

    def get(self, index):
        return self.items[index]

    def size(self):
        return len(self.items)

    def curselection(self):
        return self.selection


class _DialogWidget(_Widget):
    """Замена tb.Toplevel: заголовочные методы — no-op с записью вызовов."""

    def __init__(self, master=None, **kw):
        super().__init__('Toplevel', master, **kw)
        self.titles = []
        self.grabbed = 0
        self.transients = 0
        self.destroyed = 0

    def title(self, text=''):
        self.titles.append(text)

    def geometry(self, geo=''):
        pass

    def transient(self, win):
        self.transients += 1

    def grab_set(self):
        self.grabbed += 1

    def columnconfigure(self, col, **kw):
        pass

    def destroy(self):
        self.destroyed += 1


class _TkBundle:
    """Фабрика tk/tb/ttk-виджетов диалогов: каждый созданный — в реестр."""

    DISABLED = 'disabled'
    NORMAL = 'normal'

    def __init__(self):
        self.widgets = []

    def __getattr__(self, name):
        # Константы tk (END, X, LEFT, BOTH, SINGLE, ...) отдаём именем-строкой:
        # двойникам они нужны только как значения pack/grid/insert. Только
        # ВЕРХНЕРЕГИСТРОВЫЕ имена — опечатка в имени фабрики (Listbox) обязана
        # остаться AttributeError, а не молча стать строкой.
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

    def Label(self, master=None, **kw):
        return self._mk('Label', master, **kw)

    def Frame(self, master=None, **kw):
        return self._mk('Frame', master, **kw)

    def Button(self, master=None, **kw):
        return self._mk('Button', master, **kw)

    def Combobox(self, master=None, **kw):
        return self._mk('Combobox', master, **kw)

    def Checkbutton(self, master=None, **kw):
        return self._mk('Checkbutton', master, **kw)

    def Listbox(self, master=None, **kw):
        lb = _Listbox(master, **kw)
        self.widgets.append(lb)
        return lb

    def StringVar(self, value='', **kw):
        return _Var(value)

    def BooleanVar(self, value=False, **kw):
        return _Var(value)

    # --- выборка из реестра ---
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

    def var_of(self, kind, key='textvariable'):
        for w in self.by_kind(kind):
            if key in w.kw:
                return w.kw[key]
        raise AssertionError(f'виджет {kind} с {key} не найден')


class _Dialogs:
    """Двойник simpledialog: очередь ответов askstring + запись обращений."""

    def __init__(self, answers=()):
        self.answers = list(answers)
        self.string_asks = []

    def askstring(self, title, prompt, initialvalue=None, parent=None):
        self.string_asks.append(
            {'title': title, 'initialvalue': initialvalue})
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


class _Host(DnsMixin):
    def __init__(self, checker=None, panel_type='PANEL'):
        self.checker = checker
        self.panel_type = panel_type
        self.root = None
        self.current_theme = 'darkly'
        self.logs = []
        self.threads = []   # записи _run_in_thread
        self.simples = []   # записи _run_simple
        # Кнопки объявлены явно: статический анализ должен их видеть.
        self.dns_btn = object()
        self.resolv_btn = object()
        self.edit_dns_btn = object()

    def log(self, text):
        self.logs.append(text)

    def _run_in_thread(self, target_func, btn=None, *args, **kwargs):
        self.threads.append((target_func, btn, args, kwargs))

    def _run_simple(self, func, btn=None, on_done=None, *args):
        self.simples.append((func, btn, on_done, args))


def _patch(monkeypatch):
    """tk-фабрика + двойники диалогов; возвращает (bundle, msg)."""
    bundle = _TkBundle()
    msg = _Msg()
    monkeypatch.setattr(gd, 'tk', bundle)
    monkeypatch.setattr(gd, 'tb', bundle)
    monkeypatch.setattr(gd, 'ttk', bundle)
    monkeypatch.setattr(gd, 'messagebox', msg)
    return bundle, msg


# ==================== guard по подключению ====================
GUARDED = ['run_dns_check', 'run_dns_resolvers', 'run_edit_dns']


class TestNoConnection:
    @pytest.mark.parametrize("handler", GUARDED)
    def test_silent_without_checker(self, monkeypatch, handler):
        _patch(monkeypatch)
        host = _Host(checker=None)
        getattr(host, handler)()
        assert host.simples == [], handler
        assert host.threads == [], handler
        assert host.logs == [], handler


# ==================== кнопка DNS-проверки ====================
class TestRunDnsCheck:
    def test_domains_fetch_defers_to_background(self):
        # get_domains — SSH-вызов: он уходит в _run_simple, диалог откроет on_done
        checker = FakeSSH()
        host = _Host(checker)
        host.run_dns_check()
        assert host.logs == ['Получение списка доменов...']
        assert len(host.simples) == 1
        fn, btn, on_done, args = host.simples[0]
        assert fn is gd.get_domains and btn is None
        assert on_done == host._open_dns_check_dialog
        assert args == (checker, 'PANEL')


# ==================== диалог DNS-проверки ====================
@pytest.fixture()
def chk(monkeypatch):
    """Открытый _open_dns_check_dialog: доступ к переменным и колбэкам."""
    checker = FakeSSH()
    host = _Host(checker)
    bundle, msg = _patch(monkeypatch)
    host._open_dns_check_dialog(['a.example', 'b.example'])
    return types.SimpleNamespace(host=host, bundle=bundle, msg=msg,
                                 checker=checker,
                                 domain=bundle.var_of('Combobox'),
                                 local=bundle.var_of('Checkbutton', 'variable'))


class TestCheckDialog:
    def test_dialog_built_with_first_domain_prefilled(self, chk):
        combo = chk.bundle.by_kind('Combobox')[0]
        assert combo.kw['values'] == ['a.example', 'b.example']
        assert chk.domain.get() == 'a.example'
        assert chk.local.get() is False
        toplevel = chk.bundle.dialog()
        assert toplevel.grabbed == 1 and toplevel.transients == 1

    def test_string_error_logged_and_combo_emptied(self, monkeypatch):
        host = _Host(FakeSSH())
        bundle, _msg = _patch(monkeypatch)
        host._open_dns_check_dialog('❌ oboriv')
        assert host.logs == ['❌ oboriv']
        combo = bundle.by_kind('Combobox')[0]
        assert combo.kw['values'] == []
        assert combo.kw['textvariable'].history == ['']  # явный combo.set('')

    def test_empty_domain_blocked_dialog_stays(self, chk):
        chk.domain.set('   ')
        chk.bundle.command('Проверить')()
        assert chk.msg.events == [('error', 'Ошибка', 'Введите домен или IP')]
        assert chk.host.simples == []
        assert chk.bundle.dialog().destroyed == 0

    def test_remote_check_runs_dns_report_with_checker(self, chk):
        chk.domain.set('  b.example ')  # strip обязан сработать
        chk.bundle.command('Проверить')()
        assert chk.bundle.dialog().destroyed == 1
        assert len(chk.host.simples) == 1
        fn, btn, on_done, args = chk.host.simples[0]
        assert fn is gd.dns_report and btn is chk.host.dns_btn
        assert on_done is None
        assert args == (chk.checker, 'b.example')

    def test_local_toggle_drops_checker(self, chk):
        chk.local.set(True)
        chk.bundle.command('Проверить')()
        fn, btn, _cb, args = chk.host.simples[0]
        assert fn is gd.dns_report_local
        # локальный режим не дёргает сервер: домен — единственный аргумент
        assert args == ('a.example',)


# ==================== резолверы: отчёт ====================
class TestDnsResolvers:
    def test_report_args_and_cache_key(self):
        checker = FakeSSH()
        host = _Host(checker)
        host.run_dns_resolvers()
        assert len(host.threads) == 1
        fn, btn, args, kwargs = host.threads[0]
        assert fn is gd.dns_resolvers_report
        assert btn is host.resolv_btn
        assert args == (checker,)
        assert kwargs == {'cache_key': 'dns_resolvers'}


# ==================== редактор резолверов ====================
class TestRunEditDns:
    def test_current_resolvers_defer_to_background(self):
        checker = FakeSSH()
        host = _Host(checker)
        host.run_edit_dns()
        assert host.logs == ['Получение текущих DNS-резолверов...']
        assert len(host.simples) == 1
        fn, btn, on_done, args = host.simples[0]
        assert fn is gd.get_current_dns_resolvers and btn is None
        assert on_done == host._open_edit_dns_dialog
        assert args == (checker,)


RESOLV_ROUTES = [('resolv.conf', 'nameserver 1.1.1.1\n'),
                 ('resolvectl', '  DNS Servers: 1.1.1.1')]


class TestEditDialogNoData:
    def test_empty_list_dumps_diagnostics_and_warns(self, monkeypatch):
        # штатная ветка «резолверы не определились»: диалог НЕ открывается,
        # в лог уходят resolv.conf и resolvectl, пользователю — warning
        checker = FakeSSH(RESOLV_ROUTES)
        host = _Host(checker)
        bundle, msg = _patch(monkeypatch)
        host._open_edit_dns_dialog([])
        assert bundle.by_kind('Toplevel') == []
        assert msg.events[0][0] == 'warning'
        assert any('resolv.conf' in s for s in host.logs)
        assert any('resolvectl' in s for s in host.logs)

    def test_resolvectl_empty_not_logged(self, monkeypatch):
        checker = FakeSSH([('resolv.conf', 'nameserver 8.8.8.8')])
        host = _Host(checker)
        _patch(monkeypatch)
        host._open_edit_dns_dialog([])
        assert not any('resolvectl' in s for s in host.logs)

    def test_string_error_treated_as_empty(self, monkeypatch):
        host = _Host(FakeSSH(RESOLV_ROUTES))
        bundle, msg = _patch(monkeypatch)
        host._open_edit_dns_dialog('❌ ssh обрыв')
        assert host.logs[0] == '❌ ssh обрыв'
        assert msg.events[0][0] == 'warning'
        assert bundle.by_kind('Toplevel') == []


@pytest.fixture()
def edns(monkeypatch):
    """Открытый _open_edit_dns_dialog с двумя резолверами."""
    checker = FakeSSH()
    host = _Host(checker)
    bundle, msg = _patch(monkeypatch)
    dialogs = _Dialogs()
    monkeypatch.setattr(gd, 'simpledialog', dialogs)
    host._open_edit_dns_dialog(['8.8.8.8', '1.1.1.1'])
    return types.SimpleNamespace(host=host, bundle=bundle, msg=msg,
                                 dialogs=dialogs, checker=checker,
                                 lb=bundle.by_kind('Listbox')[0])


class TestEditDialogListbox:
    def test_seeded_with_current_resolvers(self, edns):
        assert edns.lb.items == ['8.8.8.8', '1.1.1.1']
        toplevel = edns.bundle.dialog()
        assert toplevel.grabbed == 1 and toplevel.transients == 1

    def test_add_valid_appends_invalid_errors(self, edns):
        edns.dialogs.answers = ['9.9.9.9']
        edns.bundle.command('Добавить')()
        assert edns.lb.items == ['8.8.8.8', '1.1.1.1', '9.9.9.9']
        edns.dialogs.answers = ['не-ip']
        edns.bundle.command('Добавить')()
        assert edns.msg.events == [('error', 'Ошибка', 'Некорректный IP-адрес')]
        assert len(edns.lb.items) == 3
        edns.dialogs.answers = [None]  # Отмена — без изменений и без ошибок
        edns.msg.events.clear()
        edns.bundle.command('Добавить')()
        assert len(edns.lb.items) == 3 and edns.msg.events == []

    def test_add_shows_current_selection_as_initial(self, edns):
        # при редактировании initialvalue — текущее значение (askstring),
        # проверяем, что редактор его действительно передаёт
        edns.lb.selection = (0,)
        edns.dialogs.answers = [None]
        edns.bundle.command('Редактировать')()
        assert edns.dialogs.string_asks[-1]['initialvalue'] == '8.8.8.8'

    def test_edit_requires_selection(self, edns):
        edns.lb.selection = ()
        edns.bundle.command('Редактировать')()
        assert edns.msg.events[0][0] == 'warning'
        assert edns.lb.items == ['8.8.8.8', '1.1.1.1']

    def test_edit_replaces_selected_in_place(self, edns):
        edns.lb.selection = (0,)
        edns.dialogs.answers = ['1.0.0.1']
        edns.bundle.command('Редактировать')()
        assert edns.lb.items == ['1.0.0.1', '1.1.1.1']  # позиция сохранена

    def test_edit_invalid_ip_keeps_list(self, edns):
        edns.lb.selection = (1,)
        edns.dialogs.answers = ['abc']
        edns.bundle.command('Редактировать')()
        assert edns.msg.events[0][0] == 'error'
        assert edns.lb.items == ['8.8.8.8', '1.1.1.1']

    def test_delete_requires_selection(self, edns):
        edns.lb.selection = ()
        edns.bundle.command('Удалить')()
        assert edns.msg.events[0][0] == 'warning'

    def test_delete_removes_selected(self, edns):
        edns.lb.selection = (1,)
        edns.bundle.command('Удалить')()
        assert edns.lb.items == ['8.8.8.8']

    def test_preset_replaces_whole_list(self, edns):
        edns.bundle.command('Google')()
        assert edns.lb.items == ['8.8.8.8', '8.8.4.4']
        edns.bundle.command('Cloudflare')()
        assert edns.lb.items == ['1.1.1.1', '1.0.0.1']
        edns.bundle.command('OpenDNS')()
        assert edns.lb.items == ['208.67.222.222', '208.67.220.220']


class TestEditDialogApply:
    def test_empty_list_blocked(self, edns):
        edns.lb.items.clear()
        edns.bundle.command('Применить изменения')()
        assert edns.msg.events[0][0] == 'warning'
        assert edns.host.threads == []

    def test_declined_confirmation_applies_nothing(self, edns):
        edns.msg.askyesno_ret = False
        edns.bundle.command('Применить изменения')()
        assert edns.msg.asks  # спросил
        assert edns.host.threads == []  # и не сделал
        assert edns.bundle.dialog().destroyed == 0  # диалог жив

    def test_confirmed_strips_blanks_and_runs_in_thread(self, edns):
        # пробелы срезаются, пустые строки выбрасываются — в set_dns_resolvers
        # обязан уходить чистый список
        edns.lb.items[:] = [' 9.9.9.9 ', '', '1.1.1.1']
        edns.bundle.command('Применить изменения')()
        assert edns.bundle.dialog().destroyed == 1
        assert len(edns.host.threads) == 1
        fn, btn, args, kwargs = edns.host.threads[0]
        assert fn is gd.set_dns_resolvers
        assert btn is edns.host.edit_dns_btn
        assert args == (edns.checker, ['9.9.9.9', '1.1.1.1'])
        assert kwargs == {}

    def test_cancel_button_closes_without_changes(self, edns):
        edns.bundle.command('Отмена')()
        assert edns.bundle.dialog().destroyed == 1
        assert edns.host.threads == []
