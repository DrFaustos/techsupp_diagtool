"""Тесты gui_checks.py: кнопки диагностики и диалог анализа логов доступа (без Tk).

Два слоя проверки.

1. Обработчики кнопок (run_*): класс-хост переопределяет _run_in_thread /
   _run_simple (потоки не запускаются, вызовы записываются), simpledialog —
   двойник с очередью ответов. Проверяются аргументы (checker, panel_type),
   cache_key и то, что пустой домен/отменённый диалог не гоняет SSH-запрос.

2. Диалог _open_access_dialog: tk/ttb/ttk подменены фабрика-заглушкой,
   виджеты собираются в реестр — оттуда достаются колбэки кнопок и
   StringVar'ы (через textvariable у созданных виджетов). Так валидация
   домена, топ-Х и даты (тип, диапазоны) проверяется без дисплея, включая
   сохранение отчёта в файл (tmp_path) и ветку ошибки записи.
"""
import os
import sys
import types

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

import gui_checks as gc
from gui_checks import ChecksMixin
from support import FakeSSH


class _Var:
    """Замена tkinter.StringVar: get/set + история set() (для combo.set(''))."""

    def __init__(self, value=''):
        self._v = value
        self.history = []

    def get(self):
        return self._v

    def set(self, value):
        self._v = value
        self.history.append(value)


class _Widget:
    """Любой ttk-виджет: пишет grid/pack/config; get() читает textvariable."""

    def __init__(self, kind, master=None, **kw):
        self.kind = kind
        self.master = master
        self.kw = kw
        self.configs = []
        self.grids = []
        self.packs = []

    def grid(self, **kw):
        self.grids.append(kw)

    def pack(self, **kw):
        self.packs.append(kw)

    def config(self, **kw):
        self.configs.append(kw)

    def set(self, value):
        var = self.kw.get('textvariable')
        if var is not None:
            var.set(value)

    def get(self):
        var = self.kw.get('textvariable')
        return var.get() if var is not None else ''


class _DialogWidget(_Widget):
    """Замена tb.Toplevel: заголовочные методы — no-op с записью вызовов."""

    def __init__(self, master=None, **kw):
        super().__init__('Toplevel', master, **kw)
        self.titles = []
        self.grabbed = 0
        self.transients = 0
        self.columns = []

    def title(self, text=''):
        self.titles.append(text)

    def geometry(self, geo=''):
        pass

    def transient(self, win):
        self.transients += 1

    def grab_set(self):
        self.grabbed += 1

    def columnconfigure(self, col, **kw):
        self.columns.append(col)


class _TkBundle:
    """Фабрика всех tk/tb/ttk-виджетов диалога: каждый созданный — в реестр.

    Доступ к внутреннему состоянию диалога (переменные, колбэки кнопок) —
    через реестр: textvariable и command лежат в kw/configs виджетов,
    созданных _open_access_dialog.
    """

    DISABLED = 'disabled'
    NORMAL = 'normal'

    def __init__(self):
        self.widgets = []

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

    def Entry(self, master=None, **kw):
        return self._mk('Entry', master, **kw)

    def Frame(self, master=None, **kw):
        return self._mk('Frame', master, **kw)

    def Button(self, master=None, **kw):
        return self._mk('Button', master, **kw)

    def Combobox(self, master=None, **kw):
        return self._mk('Combobox', master, **kw)

    def StringVar(self, value='', **kw):
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
        """command=, которым миксин позже снабдил кнопку (после .config())."""
        btn = self.button(text)
        for cfg in reversed(btn.configs):
            if 'command' in cfg:
                return cfg['command']
        raise AssertionError(f'у кнопки {text!r} не задан command')

    def var_of(self, kind, **match):
        """textvariable виджета заданного kind с указанными kw.

        Требование 'textvariable' in kw обязательно: Labels в диалоге тоже
        проходят через by_kind, а переменная привязана только к статусной
        строке — без фильтра возвращался бы первый Label без переменной.
        """
        for w in self.by_kind(kind):
            if 'textvariable' in w.kw and all(
                    w.kw.get(k) == v for k, v in match.items()):
                return w.kw['textvariable']
        raise AssertionError(f'виджет {kind} {match} не найден')

    def date_vars(self):
        """Переменные (год, месяц, день) — по ПОРЯДКУ создания внутри frame.

        По width тут искать нельзя: месяц и день созданы одинаковыми
        Entry(width=3), и выборка по ширине выдала бы одну переменную на
        двоих (тест тогда писал день в переменную месяца).
        """
        frame = self.by_kind('Frame')[0]
        entries = [w for w in self.widgets
                   if w.master is frame and 'textvariable' in w.kw]
        assert len(entries) == 3, f'в блоке даты 3 поля, найдено {len(entries)}'
        return [w.kw['textvariable'] for w in entries]


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
    def __init__(self):
        self.events = []  # (kind, title, msg)

    def showerror(self, title, msg, parent=None):
        self.events.append(('error', title, msg))

    def showwarning(self, title, msg, parent=None):
        self.events.append(('warning', title, msg))

    def showinfo(self, title, msg, parent=None):
        self.events.append(('info', title, msg))


class _Files:
    """Двойник filedialog: asksaveasfilename отдаёт подготовленный путь."""

    def __init__(self, filename=''):
        self.filename = filename
        self.asks = []

    def asksaveasfilename(self, **kw):
        self.asks.append(kw)
        return self.filename


class _Root:
    def after(self, delay, fn, *args):
        fn(*args)  # как mainloop: выполняем сразу


class _Host(ChecksMixin):
    def __init__(self, checker=None, panel_type='bitrix'):
        self.checker = checker
        self.panel_type = panel_type
        self.root = _Root()
        self.ip_var = _Var('10.0.0.5')
        self.logs = []
        self.threads = []   # записи _run_in_thread
        self.simples = []   # записи _run_simple
        self.shown = []     # записи _display_result
        # Кнопки, на которые ссылаются обработчики: объявлены явно, а не
        # setattr в цикле, — иначе статический анализ не видит атрибуты.
        self.full_btn = object()
        self.disk_btn = object()
        self.network_btn = object()
        self.firewall_btn = object()
        self.config_btn = object()
        self.logs_btn = object()
        self.oom_btn = object()
        self.ssl_btn = object()
        self.whois_btn = object()
        self.ports_btn = object()
        self.grep_btn = object()

    def log(self, text):
        self.logs.append(text)

    def _run_in_thread(self, target_func, btn=None, *args, **kwargs):
        self.threads.append((target_func, btn, args, kwargs))

    def _run_simple(self, func, btn=None, on_done=None, *args):
        self.simples.append((func, btn, on_done, args))

    def _display_result(self, result):
        self.shown.append(result)


# Одиночные отчёты: (обработчик, бэкенд, кнопка, доп. аргументы, cache_key)
REPORT_MAP = [
    ("run_disk_memory", "disk_memory_report", "disk_btn", (), 'disk'),
    ("run_network", "network_report", "network_btn", (), 'network'),
    ("run_firewall", "firewall_report", "firewall_btn", (), 'firewall'),
    ("run_config", "web_config_report", "config_btn", (), 'webconfig'),
    ("run_logs", "site_logs_report", "logs_btn", ('PANEL',), 'logs'),
    ("run_oom_search", "search_oom_logs", "oom_btn", (), 'oom'),
]

# Проверки с guard по подключению (без checker — молчание)
GUARDED = ["run_ssl_check", "run_whois", "run_port_scan", "run_grep_logs",
           "run_access_analysis"]


# ==================== одиночные отчёты ====================
class TestSingleReports:
    @pytest.mark.parametrize("handler,backend,btn,extra,cache", REPORT_MAP)
    def test_report_args_and_cache_key(self, handler, backend, btn, extra,
                                       cache):
        checker = FakeSSH()
        host = _Host(checker, panel_type='PANEL')
        getattr(host, handler)()
        assert len(host.threads) == 1
        fn, w_btn, args, kwargs = host.threads[0]
        assert fn is getattr(gc, backend), handler
        assert w_btn is getattr(host, btn)
        assert args == (checker,) + extra
        assert kwargs == {'cache_key': cache}

    def test_full_report_passes_panel_progress_cb_and_cache(self):
        checker = FakeSSH()
        host = _Host(checker, panel_type='ISP')
        host.run_full()
        assert len(host.threads) == 1
        fn, btn, args, kwargs = host.threads[0]
        assert fn is gc.full_diagnostic_report
        assert btn is host.full_btn
        assert args == (checker, 'ISP')
        assert kwargs['cache_key'] == 'full'
        # progress_cb обязан докладывать этапы через log (root.after)
        cb = kwargs['progress_cb']
        cb(1, 4, 'Метрики системы')
        assert host.logs == ['➡ Этап 1/4: Метрики системы']


# ==================== диалоги домена ====================
class TestAskDomain:
    def test_first_detected_domain_is_initial(self, monkeypatch):
        host = _Host(FakeSSH())
        seen = []

        def fake_domains(checker, panel_type):
            seen.append((checker, panel_type))
            return ['a.example', 'b.example']

        dialogs = _Dialogs(answers=[' a.example '])
        monkeypatch.setattr(gc, 'simpledialog', dialogs)
        monkeypatch.setattr(gc, 'get_domains', fake_domains)
        assert host._ask_domain('SSL-сертификат') == 'a.example'
        assert dialogs.string_asks[0]['initialvalue'] == 'a.example'
        assert seen == [(host.checker, host.panel_type)]

    def test_domains_error_still_asks(self, monkeypatch):
        def boom(checker, panel_type):
            raise OSError('ssh reset')

        dialogs = _Dialogs(answers=['manual.example'])
        monkeypatch.setattr(gc, 'simpledialog', dialogs)
        monkeypatch.setattr(gc, 'get_domains', boom)
        host = _Host(FakeSSH())
        # get_domains упал — диалог всё равно открывается, пустой
        assert host._ask_domain('WHOIS') == 'manual.example'
        assert dialogs.string_asks[0]['initialvalue'] == ''

    def test_cancel_returns_empty(self, monkeypatch):
        dialogs = _Dialogs(answers=[])  # очередь пуста -> None (Отмена)
        monkeypatch.setattr(gc, 'simpledialog', dialogs)
        monkeypatch.setattr(gc, 'get_domains', lambda c, p: [])
        host = _Host(FakeSSH())
        assert host._ask_domain('WHOIS') == ''


class TestGuardedHandlers:
    @pytest.mark.parametrize("handler", GUARDED)
    def test_silent_without_checker(self, monkeypatch, handler):
        dialogs = _Dialogs()
        monkeypatch.setattr(gc, 'simpledialog', dialogs)
        bundle = _TkBundle()
        monkeypatch.setattr(gc, 'tb', bundle)
        host = _Host(checker=None)
        getattr(host, handler)()
        assert host.simples == [], handler
        assert host.threads == [], handler
        assert host.logs == [], handler


class TestDomainHandlers:
    def _patch(self, monkeypatch):
        monkeypatch.setattr(gc, 'get_domains',
                            lambda c, p: ['site.local'])
        bundle = _TkBundle()
        monkeypatch.setattr(gc, 'tb', bundle)
        monkeypatch.setattr(gc, 'ttk', bundle)
        monkeypatch.setattr(gc, 'tk', bundle)
        return bundle

    def test_ssl_uses_entered_domain(self, monkeypatch):
        checker = FakeSSH()
        host = _Host(checker)
        self._patch(monkeypatch)
        monkeypatch.setattr(gc, 'simpledialog',
                            _Dialogs(answers=['site.local']))
        host.run_ssl_check()
        assert len(host.simples) == 1
        fn, btn, on_done, args = host.simples[0]
        assert fn is gc.ssl_cert_report
        assert btn is host.ssl_btn and on_done is None
        assert args == (checker, 'site.local')

    def test_whois_cancel_sends_nothing(self, monkeypatch):
        host = _Host(FakeSSH())
        self._patch(monkeypatch)
        monkeypatch.setattr(gc, 'simpledialog', _Dialogs(answers=[]))
        host.run_whois()
        assert host.simples == []

    def test_ssl_cancelled_domain_sends_nothing(self, monkeypatch):
        # «Отмена» в диалоге домена: SSH-запрос уходить не должен
        host = _Host(FakeSSH())
        self._patch(monkeypatch)
        monkeypatch.setattr(gc, 'simpledialog', _Dialogs(answers=[]))
        host.run_ssl_check()
        assert host.simples == []

    def test_whois_uses_entered_domain(self, monkeypatch):
        checker = FakeSSH()
        host = _Host(checker)
        self._patch(monkeypatch)
        monkeypatch.setattr(gc, 'simpledialog',
                            _Dialogs(answers=['site.local']))
        host.run_whois()
        assert len(host.simples) == 1
        fn, btn, on_done, args = host.simples[0]
        assert fn is gc.whois_report
        assert btn is host.whois_btn and on_done is None
        assert args == (checker, 'site.local')

    def test_grep_cancelled_domain_sends_nothing(self, monkeypatch):
        # пустой домен отсекается ДО второго вопроса (про паттерн не спрашиваем)
        dialogs = _Dialogs(answers=[])
        host = _Host(FakeSSH())
        self._patch(monkeypatch)
        monkeypatch.setattr(gc, 'simpledialog', dialogs)
        host.run_grep_logs()
        assert host.simples == []
        assert len(dialogs.string_asks) == 1

    def test_port_scan_uses_ip_entry(self, monkeypatch):
        checker = FakeSSH()
        host = _Host(checker)
        host.ip_var.set('203.0.113.9')
        host.run_port_scan()
        fn, _btn, on_done, args = host.simples[0]
        assert fn is gc.port_scan_report
        assert args == (checker, '203.0.113.9')

    def test_port_scan_blank_ip_falls_back_to_checker(self, monkeypatch):
        checker = FakeSSH()
        host = _Host(checker)
        host.ip_var.set('   ')
        host.run_port_scan()
        _fn, _btn, _cb, args = host.simples[0]
        assert args == (checker, None)

    def test_grep_empty_pattern_gets_default(self, monkeypatch):
        checker = FakeSSH()
        host = _Host(checker, panel_type='ISP')
        self._patch(monkeypatch)
        # 1-й askstring — домен, 2-й — паттерн (пустой: жмём ОК без ввода)
        monkeypatch.setattr(gc, 'simpledialog',
                            _Dialogs(answers=['site.local', '']))
        host.run_grep_logs()
        fn, _btn, _cb, args = host.simples[0]
        assert fn is gc.grep_logs_report
        assert args == (checker, 'ISP', 'site.local', '" 5[0-9][0-9] ')

    def test_grep_cancelled_pattern_sends_nothing(self, monkeypatch):
        host = _Host(FakeSSH())
        self._patch(monkeypatch)
        monkeypatch.setattr(gc, 'simpledialog',
                            _Dialogs(answers=['site.local', None]))
        host.run_grep_logs()
        assert host.simples == []

    def test_access_analysis_defers_dialog_to_background(self):
        # get_domains — SSH-вызов: он уходит в _run_simple, диалог откроет
        # on_done, а не mainloop
        checker = FakeSSH()
        host = _Host(checker)
        host.run_access_analysis()
        assert host.logs == ['Получение списка доменов...']
        assert len(host.simples) == 1
        fn, btn, on_done, args = host.simples[0]
        assert fn is gc.get_domains and btn is None
        assert on_done == host._open_access_dialog
        assert args == (checker, host.panel_type)


# ==================== диалог анализа логов доступа ====================
@pytest.fixture()
def dlg(monkeypatch, tmp_path):
    """Открытый _open_access_dialog: доступ к виджетам, колбэкам, двойникам."""
    checker = FakeSSH()
    host = _Host(checker, panel_type='PANEL')
    bundle = _TkBundle()
    msg = _Msg()
    files = _Files()
    monkeypatch.setattr(gc, 'tk', bundle)
    monkeypatch.setattr(gc, 'tb', bundle)
    monkeypatch.setattr(gc, 'ttk', bundle)
    monkeypatch.setattr(gc, 'messagebox', msg)
    monkeypatch.setattr(gc, 'filedialog', files)
    host._open_access_dialog(['a.example', 'b.example'])
    year_var, month_var, day_var = bundle.date_vars()
    return types.SimpleNamespace(host=host, bundle=bundle, msg=msg,
                                 files=files, tmp=tmp_path,
                                 domain=bundle.var_of('Combobox'),
                                 top=bundle.var_of('Entry', width=10),
                                 year=year_var, month=month_var, day=day_var)


def _analyze(dlg):
    return dlg.bundle.command('Анализировать')


def _save(dlg):
    return dlg.bundle.command('Сохранить отчёт')


class TestAccessDialog:
    def test_dialog_built_with_domains(self, dlg):
        combo = dlg.bundle.by_kind('Combobox')[0]
        assert combo.kw['values'] == ['a.example', 'b.example']
        assert dlg.domain.get() == 'a.example'
        toplevel = dlg.bundle.by_kind('Toplevel')[0]
        assert toplevel.grabbed == 1 and toplevel.transients == 1

    def test_string_error_is_logged_and_combo_emptied(self, monkeypatch):
        host = _Host(FakeSSH())
        bundle = _TkBundle()
        monkeypatch.setattr(gc, 'tk', bundle)
        monkeypatch.setattr(gc, 'tb', bundle)
        monkeypatch.setattr(gc, 'ttk', bundle)
        host._open_access_dialog('❌ oboriv')
        assert host.logs == ['❌ oboriv']
        combo = bundle.by_kind('Combobox')[0]
        # домены пусты: value='', плюс явный combo.set('')
        assert combo.kw['values'] == []
        assert combo.kw['textvariable'].get() == ''

    def test_empty_domain_blocked_with_error(self, dlg):
        dlg.domain.set('')
        _analyze(dlg)()
        assert dlg.host.simples == []
        assert dlg.msg.events[0][0] == 'error'

    def test_valid_analysis_runs_with_defaults(self, dlg):
        dlg.top.set('')  # пусто -> 10
        _analyze(dlg)()
        assert len(dlg.host.simples) == 1
        fn, btn, cb, args = dlg.host.simples[0]
        assert fn is gc.analyze_access_log and btn is None
        assert args == (dlg.host.checker, 'PANEL', 'a.example', 10,
                        None, None, None)
        assert callable(cb)

    def test_non_numeric_top_falls_back_to_ten(self, dlg):
        dlg.top.set('abc')
        _analyze(dlg)()
        _fn, _b, _cb, args = dlg.host.simples[0]
        assert args[3] == 10

    def test_non_numeric_date_blocked(self, dlg):
        dlg.year.set('двадцать26')
        _analyze(dlg)()
        assert dlg.host.simples == []
        assert dlg.msg.events == [('error', 'Ошибка', 'Дата должна быть числом')]

    def test_out_of_range_month_blocked(self, dlg):
        dlg.month.set('13')
        _analyze(dlg)()
        assert dlg.host.simples == []
        assert 'месяц' in dlg.msg.events[0][2]

    def test_full_date_reaches_report(self, dlg):
        dlg.year.set('2026'); dlg.month.set('10'); dlg.day.set('9')
        dlg.top.set('25')
        _analyze(dlg)()
        _fn, _b, _cb, args = dlg.host.simples[0]
        assert args == (dlg.host.checker, 'PANEL', 'a.example', 25,
                        2026, 10, 9)

    def test_buttons_lock_during_analysis_then_unlock_on_done(self, dlg):
        status = dlg.bundle.var_of('Label')  # единственная Label с textvariable
        _analyze(dlg)()
        _fn, _b, on_done, _args = dlg.host.simples[0]
        assert status.get() == 'Анализ выполняется...'
        save_btn = dlg.bundle.button('Сохранить отчёт')
        analyze_btn = dlg.bundle.button('Анализировать')
        assert save_btn.configs[-1]['state'] == 'disabled'
        assert analyze_btn.configs[-1]['state'] == 'disabled'

        on_done('ОТЧЕТ ГОТОВ')
        assert dlg.host.shown == ['ОТЧЕТ ГОТОВ']
        assert status.get() == 'Анализ завершён — можно сохранить отчёт'
        assert save_btn.configs[-1]['state'] == 'normal'
        assert analyze_btn.configs[-1]['state'] == 'normal'


class TestAccessDialogSave:
    def test_save_before_analysis_warns(self, dlg):
        _save(dlg)()
        assert dlg.msg.events[0][0] == 'warning'
        assert dlg.files.asks == []  # диалог выбора файла не открывался

    def test_save_writes_report_file(self, dlg):
        target = str(dlg.tmp / 'report.txt')
        dlg.files.filename = target
        _analyze(dlg)()
        _fn, _b, on_done, _args = dlg.host.simples[0]
        on_done('ОТЧЕТ')
        _save(dlg)()
        assert open(target, encoding='utf-8').read() == 'ОТЧЕТ'
        assert dlg.msg.events[-1][0] == 'info'

    def test_save_cancelled_writes_nothing(self, dlg):
        dlg.files.filename = ''  # пользователь нажал «Отмена»
        _analyze(dlg)()
        _fn, _b, on_done, _args = dlg.host.simples[0]
        on_done('ОТЧЕТ')
        _save(dlg)()
        assert os.listdir(dlg.tmp) == []
        assert dlg.msg.events == []  # «Отмена» — без предупреждений и ошибок

    def test_write_error_reported(self, dlg):
        dlg.files.filename = '/nonexistent-dir/report.txt'
        _analyze(dlg)()
        _fn, _b, on_done, _args = dlg.host.simples[0]
        on_done('ОТЧЕТ')
        _save(dlg)()
        assert dlg.msg.events[-1][0] == 'error'
