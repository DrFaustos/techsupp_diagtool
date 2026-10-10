"""Файловый менеджер: форматирование таблицы и подключение к окну.

gui_files.py — это разметка, её проверяем статически (AST): миксин подмешан,
кнопка ведёт в нужный метод, а каждая файловая операция уходит в _run_simple,
то есть выполняется в фоне, а не в mainloop.
"""
import ast
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

import time
import types
import tkinter as tk
from tkinter import ttk

import pytest

import gui as gui_mod
import fmanager as fm
from test_diagnostic import FakeSFTP


def _src(name):
    with open(os.path.join(ROOT, name), encoding='utf-8') as f:
        return f.read()


def _run_simple_targets(path):
    """Имена функций, которые в path вызываются через self._run_simple(...)."""
    tree = ast.parse(_src(path), filename=path)
    names = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and getattr(node.func, 'attr', '') == '_run_simple':
            if node.args and isinstance(node.args[0], ast.Name):
                names.add(node.args[0].id)
    return names


class TestFormatEntries:
    def test_dirs_get_slash_files_plain(self):
        rows = fm.format_entries([
            {'name': 'www', 'is_dir': True, 'is_link': False, 'size': 4096,
             'mode': 'drwxr-xr-x', 'mtime': 0},
            {'name': 'nginx.conf', 'is_dir': False, 'is_link': False, 'size': 1200,
             'mode': '-rw-r--r--', 'mtime': 0},
        ])
        assert rows[0][0] == 'www/' and rows[0][1] == 'папка'
        assert rows[1][0] == 'nginx.conf' and rows[1][1] == 'файл'
        # колонки в порядке, который ждёт ttk.Treeview(values=...)
        assert len(rows[0]) == 5

    def test_symlink_marked(self):
        rows = fm.format_entries([{'name': 'alive', 'is_dir': False, 'is_link': True,
                                   'size': 0, 'mode': 'lrwxrwxrwx', 'mtime': None}])
        assert rows[0][0] == 'alive@' and rows[0][1] == 'ссылка'

    def test_human_size(self):
        assert fm.human_size(0) == '0 B'
        assert fm.human_size(999) == '999 B'
        assert fm.human_size(1024) == '1.0 KB'
        assert fm.human_size(1536) == '1.5 KB'
        assert fm.human_size(5 * 1024 ** 3) == '5.0 GB'

    def test_human_size_garbage_is_safe(self):
        assert fm.human_size(None) == '?'
        assert fm.human_size(-5) == '?'
        assert fm.human_size('abc') == '?'

    def test_format_time(self):
        assert fm.format_time(0) == ''
        assert fm.format_time(None) == ''
        assert len(fm.format_time(1760000000)) == 16  # ГГГГ-ММ-ДД ЧЧ:ММ
        assert fm.format_time(10 ** 18) == ''          # невалидный timestamp не роняет

    def test_empty_input(self):
        assert fm.format_entries([]) == []


class TestFileManagerWired:
    def test_mixin_is_part_of_app(self):
        assert gui_mod.FilesMixin in gui_mod.DiagnosticApp.__mro__

    def test_button_command_points_at_mixin_method(self):
        src = _src('gui.py')
        assert 'command=self.open_file_manager' in src
        assert hasattr(gui_mod.DiagnosticApp, 'open_file_manager')

    def test_button_disabled_until_connected(self):
        # кнопка создаётся заблокированной и включается только после connect
        assert 'self.file_btn = tb.Button' in _src('gui.py')
        runner = _src('gui_runner.py')
        assert runner.index('self.file_btn.config(state=tk.NORMAL)') < \
               runner.index('def _on_connect_failure')

    def test_all_file_ops_run_in_background(self):
        """Ни одна файловая операция не должна выполняться в mainloop."""
        used = _run_simple_targets('gui_files.py')
        expected = {'list_dir', 'make_dir', 'create_file', 'rename_path',
                    'delete_path', 'download_file', 'upload_file',
                    'remote_read', 'remote_write'}
        missing = expected - used
        assert not missing, f'вызывается напрямую из UI-потока: {sorted(missing)}'

    def test_no_grab_set_on_manager(self):
        """grab_set перекрывает системные окна «Скачать»/«Загрузить».

        Проверяем по AST реальный вызов .grab_set(), а не подстроку: слово
        стоит и в docstring, и в комментарии — текстовый поиск давал ложный
        прогон.
        """
        tree = ast.parse(_src('gui_files.py'), filename='gui_files.py')
        calls = [n for n in ast.walk(tree) if isinstance(n, ast.Call)
                 and getattr(n.func, 'attr', '') == 'grab_set']
        assert not calls, f'окно менеджера хватает фокус: {len(calls)} grab_set'


# ---------- ДЫМ: окно реально открывается и рисует список ----------

def _make_app():
    """Создаёт окно; без дисплея пропускает тест, а не валит прогон."""
    try:
        return gui_mod.DiagnosticApp()
    except Exception as exc:  # TclError: no display name / cannot connect
        pytest.skip(f'GUI недоступна без дисплея: {type(exc).__name__}: {exc}')


def _sftp_checker(sftp):
    return types.SimpleNamespace(
        client=types.SimpleNamespace(open_sftp=lambda: sftp),
        reset_cancel=lambda: None)


def _sync_runner(app):
    """Синхронная замена _run_simple для тестов разметки.

    Результат фонового потока приходит в UI через root.after, который требует
    крутящегося mainloop (тесты гоняют root.update()). Что-то из этого ловит
    регресс-тест ниже (TestManagerOpens.
    test_close_during_background_task_releases_busy — там реальный поток), а
    разметку окна здесь проверяем без потока: AST-тест выше уже гарантирует,
    что прод-код зовёт _run_simple.
    """
    def run_simple(fn, btn=None, on_done=None, *args, **kwargs):
        try:
            result = fn(*args, **kwargs)
        except Exception as exc:
            result = f"❌ Ошибка: {exc}"
        (on_done or app._display_result)(result)
    return run_simple


def _top_level(app):
    for w in app.root.winfo_children():
        if isinstance(w, tk.Toplevel):
            return w
    return None


def _find_treeview(widget):
    if isinstance(widget, ttk.Treeview):
        return widget
    for child in widget.winfo_children():
        found = _find_treeview(child)
        if found is not None:
            return found
    return None


def _press_enter(tree, dialog, want, timeout=3.0):
    """Нажимает Enter в таблице и ждёт результата навигации.

    when='tail' + ожидание по дедлайну, а не один update(), — не придирка, а
    следствие замера: event_generate('<Return>') по умолчанию ставит событие в
    НАЧАЛО очереди, и под реальным оконным менеджером (машина разработчика),
    когда X-фокус новому Toplevel ещё не передан (root.focus_get() is None),
    событие до on_open не доходило вообще — на 6 прогонах из 40 таблица
    оставалась ['etc']. В CI Xvfb крутится без WM, поэтому там тест проходил и
    так, и дефект был не виден.
    """
    tree.focus_force()
    dialog.update()
    tree.event_generate('<Return>', when='tail')
    deadline = time.time() + timeout
    while time.time() < deadline:
        dialog.update()
        if [str(i) for i in tree.get_children()] == want:
            return
        time.sleep(0.002)


class TestManagerOpens:
    def test_window_lists_and_navigates(self):
        app = _make_app()
        try:
            sftp = FakeSFTP(files=['/etc/nginx/nginx.conf'],
                            dirs=['/', '/etc', '/etc/nginx'])
            app.checker = _sftp_checker(sftp)
            app._run_simple = _sync_runner(app)

            app.open_file_manager()
            dialog = _top_level(app)
            assert dialog is not None, 'окно менеджера не открылось'
            tree = _find_treeview(dialog)
            assert tree is not None, 'в окне менеджера нет таблицы файлов'

            # корень: единственный каталог etc, помечен «/»
            assert [str(i) for i in tree.get_children()] == ['etc']
            row = tree.item('etc', 'values')
            assert str(row[0]) == 'etc/' and str(row[1]) == 'папка'

            # выбор + Enter = навигация внутрь (двойной клик навешан на тот же
            # обработчик; сам Double-1 Tk синтезировать не позволяет)
            dialog.update()
            tree.selection_set('etc')
            _press_enter(tree, dialog, ['nginx'])
            assert [str(i) for i in tree.get_children()] == ['nginx']

            # и ещё один уровень вниз: /etc/nginx -> nginx.conf
            tree.selection_set('nginx')
            _press_enter(tree, dialog, ['nginx.conf'])
            assert [str(i) for i in tree.get_children()] == ['nginx.conf']
            conf_row = tree.item('nginx.conf', 'values')
            assert str(conf_row[1]) == 'файл'
            assert str(conf_row[2]) == '12 B'
        finally:
            try:
                app.root.destroy()
            except Exception:
                pass

    def test_close_during_background_task_releases_busy(self):
        """Регрессия: закрыть окно раньше, чем вернётся фоновая задача.

        Пока поток спит в SFTP, приложение уничтожается; возврат задачи ловит
        мёртвый Tk. Строки finally после бросившего root.after больше не
        должны теряться — флаг занятости обязан освободиться.
        """
        app = _make_app()
        try:
            sftp = FakeSFTP(dirs=['/'])

            def slow_open():
                time.sleep(0.5)
                return sftp

            app.checker = types.SimpleNamespace(
                client=types.SimpleNamespace(open_sftp=slow_open),
                reset_cancel=lambda: None)
            app.open_file_manager()          # реальный фон, как в проде
            assert _top_level(app) is not None
            app.root.destroy()               # закрываемся посреди загрузки

            deadline = time.time() + 5
            while time.time() < deadline and app._busy:
                time.sleep(0.02)
            assert app._busy is False, \
                '_busy завис: после закрытого окна finally не дошёл до сброса'
        finally:
            try:
                app.root.destroy()
            except Exception:
                pass


# ==================== ДИАЛОГ МЕНЕДЖЕРА БЕЗ TK ====================
#
# Выше — разметка через реальный Tk (и AST-гарды). Здесь — логика: она вся
# живёт замыканиями внутри open_file_manager, поэтому проверяется тем же
# приёмом, что gui_dns/gui_admin: фабрика-заглушка tk/tb/ttk (виджеты в
# реестр), _run_simple пишет вызовы, а on_done тест вызывает сам. Так
# закрываются ветки «окно закрыли раньше, чем вернулся фон», «выбор протух»,
# «каталог целиком не скачивается», «бинарный файл — только скачать».
import gui_files as gf


class _Var:
    """Замена StringVar: get/set + история set() (для проверки path_var)."""

    def __init__(self, value=''):
        self._v = value
        self.history = []

    def get(self):
        return self._v

    def set(self, value):
        self._v = value
        self.history.append(value)


class _Widget:
    """Любой виджет: пишет pack/bind/config; Text держит буфер."""

    def __init__(self, kind, master=None, **kw):
        self.kind = kind
        self.master = master
        self.kw = kw
        self.configs = []
        self.packs = []
        self.binds = {}
        self.buf = ''

    def pack(self, **kw):
        self.packs.append(kw)

    def config(self, **kw):
        self.configs.append(kw)

    def bind(self, seq, fn):
        self.binds[seq] = fn

    def insert(self, *a):
        self.buf += a[-1]

    def delete(self, *a):
        self.buf = ''

    def get(self, *a):
        # как в реальном Tk: Text.get('1.0', END) отдаёт текст с завершающим
        # переводом строки — на этом держится rstrip('\n') перед записью
        if self.kind == 'Text':
            return self.buf + '\n'
        var = self.kw.get('textvariable')
        return var.get() if var is not None else ''


class _Treeview(_Widget):
    """Двойник ttk.Treeview: iid -> values, selection задаётся тестом."""

    def __init__(self, master=None, **kw):
        super().__init__('Treeview', master, **kw)
        self.rows = {}
        self.sel = []
        self.headings = []

    def heading(self, col, **kw):
        self.headings.append((col, kw.get('text')))

    def column(self, col, **kw):
        pass

    def insert(self, parent, index, iid=None, values=None):
        self.rows[iid] = values

    def delete(self, *iids):
        for iid in iids:
            self.rows.pop(iid, None)

    def get_children(self):
        return list(self.rows)

    def selection(self):
        return list(self.sel)

    def selection_set(self, *iids):
        self.sel = list(iids)

    def item(self, iid, key='values'):
        return self.rows.get(iid)

    def focus_set(self):
        pass


class _DialogWidget(_Widget):
    """Замена Toplevel: title/geometry/protocol — no-op с записью."""

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
        # у окна менеджера grab_set быть не должен (иначе системные окна
        # «Скачать»/«Загрузить» не откроются) — двойник просто считает вызовы
        self.grabbed += 1

    def protocol(self, name, cmd):
        self.binds[name] = cmd

    def destroy(self):
        self.destroyed += 1


class _TkBundle:
    """Фабрика tk/tb/ttk-виджетов: каждый созданный — в реестр."""

    DISABLED = 'disabled'
    NORMAL = 'normal'

    def __init__(self):
        self.widgets = []

    def __getattr__(self, name):
        # Константы tk (END, X, LEFT, RIGHT, BOTH, NONE, ...) — именем-строкой:
        # двойникам они нужны только как значения pack/bind. Только ВЕРХНЕ-
        # РЕГИСТРОВЫЕ имена: опечатка в имени фабрики (Treeviw) обязана
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

    def Frame(self, master=None, **kw):
        return self._mk('Frame', master, **kw)

    def Label(self, master=None, **kw):
        return self._mk('Label', master, **kw)

    def Button(self, master=None, **kw):
        return self._mk('Button', master, **kw)

    def Entry(self, master=None, **kw):
        return self._mk('Entry', master, **kw)

    def Text(self, master=None, **kw):
        return self._mk('Text', master, **kw)

    def Treeview(self, master=None, **kw):
        t = _Treeview(master, **kw)
        self.widgets.append(t)
        return t

    def StringVar(self, value='', **kw):
        return _Var(value)

    # --- выборка из реестра ---
    def by_kind(self, kind):
        return [w for w in self.widgets if w.kind == kind]

    def toplevels(self):
        return self.by_kind('Toplevel')

    def tree(self):
        return self.by_kind('Treeview')[0]

    def buttons(self, text):
        return [w for w in self.by_kind('Button') if w.kw.get('text') == text]

    def button(self, text, index=0):
        found = self.buttons(text)
        if not found:
            raise AssertionError(f'кнопка {text!r} не создана')
        return found[index]

    def command(self, text, index=0):
        return self.button(text, index).kw['command']

    def var_of(self, kind):
        for w in self.by_kind(kind):
            if 'textvariable' in w.kw:
                return w.kw['textvariable']
        raise AssertionError(f'виджет {kind} с textvariable не найден')


class _Dialogs:
    """Двойник simpledialog: очередь ответов askstring."""

    def __init__(self, answers=()):
        self.answers = list(answers)
        self.string_asks = []

    def askstring(self, title, prompt, initialvalue=None, parent=None):
        self.string_asks.append({'title': title, 'initialvalue': initialvalue})
        return self.answers.pop(0) if self.answers else None


class _Files:
    """Двойник filedialog: пути «Сохранить как» / «Открыть» задаёт тест."""

    def __init__(self, save_as='', open_name=''):
        self.save_as = save_as
        self.open_name = open_name
        self.save_asks = []
        self.open_asks = []

    def asksaveasfilename(self, **kw):
        self.save_asks.append(kw)
        return self.save_as

    def askopenfilename(self, **kw):
        self.open_asks.append(kw)
        return self.open_name


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


class _Host(gf.FilesMixin):
    def __init__(self, checker=None):
        self.checker = checker
        self.root = None
        self.logs = []
        self.simples = []

    def log(self, text):
        self.logs.append(text)

    def _run_simple(self, func, btn=None, on_done=None, *args):
        self.simples.append((func, btn, on_done, args))


def _entry(name, is_dir=False, size=12, mode='-rw-r--r--'):
    return {'name': name, 'is_dir': is_dir, 'is_link': False, 'size': size,
            'mode': mode, 'mtime': 0}


def _patch(monkeypatch):
    bundle = _TkBundle()
    msg = _Msg()
    dialogs = _Dialogs()
    files = _Files()
    monkeypatch.setattr(gf, 'tk', bundle)
    monkeypatch.setattr(gf, 'tb', bundle)
    monkeypatch.setattr(gf, 'ttk', bundle)
    monkeypatch.setattr(gf, 'messagebox', msg)
    monkeypatch.setattr(gf, 'simpledialog', dialogs)
    monkeypatch.setattr(gf, 'filedialog', files)
    return bundle, msg, dialogs, files


def _finish(host, result):
    """Вызывает on_done последней фоновой задачи (как возврат из потока)."""
    _fn, _btn, on_done, _args = host.simples[-1]
    on_done(result)


@pytest.fixture()
def mgr(monkeypatch):
    """Открытый менеджер: корень перечитан, в листинге etc/ и app.conf."""
    checker = FakeSFTP(files=['/app.conf'], dirs=['/', '/etc'])
    host = _Host(checker)
    bundle, msg, dialogs, files = _patch(monkeypatch)
    host.open_file_manager()
    _finish(host, [_entry('etc', is_dir=True, mode='drwxr-xr-x'),
                   _entry('app.conf')])
    return types.SimpleNamespace(host=host, bundle=bundle, msg=msg,
                                 dialogs=dialogs, files=files,
                                 checker=checker, tree=bundle.tree(),
                                 path=bundle.var_of('Entry'),
                                 status=bundle.var_of('Label'),
                                 dialog=bundle.toplevels()[0])


def _goto(mgr, path, entries=()):
    """Ввод пути в строку + Enter, и возврат фонового list_dir."""
    mgr.path.set(path)
    mgr.bundle.by_kind('Entry')[0].binds['<Return>']('event')
    _finish(mgr.host, list(entries))


# ==================== склейка путей ====================
class TestJoin:
    def test_no_double_slashes(self):
        assert gf._join('/', 'etc') == '/etc'
        assert gf._join('/etc/', 'nginx.conf') == '/etc/nginx.conf'
        assert gf._join('/etc/nginx', 'sites') == '/etc/nginx/sites'

    def test_empty_root_becomes_absolute(self):
        assert gf._join('', 'x') == '/x'
        assert gf._join(None, 'x') == '/x'


# ==================== guard и разметка ====================
class TestOpenManager:
    def test_without_connection_warns_and_opens_nothing(self, monkeypatch):
        bundle, msg, _d, _f = _patch(monkeypatch)
        host = _Host(checker=None)
        host.open_file_manager()
        assert msg.events[0][0] == 'warning'
        assert bundle.toplevels() == []
        assert host.simples == []

    def test_dialog_opens_and_loads_root(self, mgr):
        assert mgr.dialog.grabbed == 0, 'grab_set блокирует окна Скачать/Загрузить'
        assert mgr.dialog.transients == 1
        assert mgr.status.get() == '2 записей: /'
        assert list(mgr.tree.rows) == ['etc', 'app.conf']
        assert mgr.tree.rows['etc'][0] == 'etc/'

    def test_initial_call_is_list_dir_on_root(self, monkeypatch):
        checker = FakeSFTP(dirs=['/'])
        host = _Host(checker)
        _patch(monkeypatch)
        host.open_file_manager()
        fn, btn, on_done, args = host.simples[0]
        assert fn is gf.list_dir and btn is None
        assert args == (host.checker, '/')
        assert callable(on_done)

    def test_bindings_present(self, mgr):
        assert '<Return>' in mgr.bundle.by_kind('Entry')[0].binds
        tree_binds = mgr.tree.binds
        assert '<Double-1>' in tree_binds and '<Return>' in tree_binds


# ==================== загрузка каталога ====================
class TestLoad:
    def test_relative_path_rejected_before_network(self, mgr):
        mgr.path.set('etc/nginx')
        mgr.bundle.by_kind('Entry')[0].binds['<Return>']('event')
        assert mgr.msg.events == [('error', 'Путь',
                                   'Нужен абсолютный путь, например /etc/nginx')]
        assert len(mgr.host.simples) == 1  # нового list_dir не было

    def test_error_marks_status_and_shows_dialog(self, mgr):
        mgr.path.set('/nope')
        mgr.bundle.by_kind('Entry')[0].binds['<Return>']('event')
        _finish(mgr.host, '❌ No such file')
        assert mgr.status.get() == 'Каталог не прочитан'
        assert mgr.msg.events[-1] == ('error', 'Ошибка', '❌ No such file')
        assert list(mgr.tree.rows) == ['etc', 'app.conf']  # таблица не тронута

    def test_success_updates_path_listing_and_status(self, mgr):
        _goto(mgr, '/etc', [_entry('nginx', is_dir=True, mode='drwxr-xr-x')])
        assert mgr.path.get() == '/etc'
        assert mgr.status.get() == '1 записей: /etc'
        assert list(mgr.tree.rows) == ['nginx']

    def test_closed_window_ignores_late_result(self, mgr):
        # закрыли окно, пока поток в SFTP: колбэк обязан молча выйти
        mgr.bundle.command('Закрыть')()
        mgr.path.set('/etc')
        mgr.bundle.by_kind('Entry')[0].binds['<Return>']('event')
        _finish(mgr.host, [_entry('app.conf')])
        assert mgr.status.get() == '2 записей: /'
        assert mgr.msg.events == []


# ==================== навигация ====================
class TestNavigation:
    def test_reload_relists_current_dir(self, mgr):
        _goto(mgr, '/etc', [_entry('nginx', is_dir=True)])
        before = len(mgr.host.simples)
        mgr.bundle.command('↻ Обновить')()
        _finish(mgr.host, [])
        assert len(mgr.host.simples) == before + 1
        assert mgr.host.simples[-1][3] == (mgr.checker, '/etc')

    def test_go_up_uses_parent(self, mgr):
        _goto(mgr, '/etc/nginx', [_entry('nginx.conf')])
        mgr.bundle.command('↑ Вверх')()
        assert mgr.host.simples[-1][3] == (mgr.checker, '/etc')

    def test_go_up_from_root_stays_at_root(self, mgr):
        mgr.bundle.command('↑ Вверх')()
        assert mgr.host.simples[-1][3] == (mgr.checker, '/')

    def test_open_directory_navigates_file_edits(self, mgr):
        mgr.tree.selection_set('etc')
        mgr.tree.binds['<Return>']()
        assert mgr.host.simples[-1][0] is gf.list_dir
        assert mgr.host.simples[-1][3] == (mgr.checker, '/etc')

        mgr.tree.selection_set('app.conf')
        mgr.tree.binds['<Double-1>']()
        assert mgr.host.simples[-1][0] is gf.remote_read
        assert mgr.host.simples[-1][3] == (mgr.checker, '/app.conf')

    def test_open_without_selection_warns_and_does_nothing(self, mgr):
        # на пустом выборе selected_path() обязан предупредить, а не молчать:
        # оператор жмёт Enter «в столбик» и должен понять, что ничего не выбрано
        mgr.tree.sel = []
        mgr.tree.binds['<Return>']()
        assert len(mgr.host.simples) == 1
        assert mgr.msg.events[0][0] == 'warning'


# ==================== выбор ====================
class TestSelection:
    def test_stale_selection_is_ignored(self, mgr):
        # iid из таблицы, которого нет в листинге (листинг пересобрали) —
        # операция не должна уходить на сервер
        mgr.tree.selection_set('призрак')
        mgr.bundle.command('✖ Удалить')()
        assert len(mgr.host.simples) == 1
        assert mgr.msg.events == []

    def test_no_selection_warns(self, mgr):
        mgr.tree.sel = []
        mgr.bundle.command('✎ Править')()
        assert mgr.msg.events[0][0] == 'warning'
        assert len(mgr.host.simples) == 1


# ==================== операции с подтверждением статуса ====================
class TestCreateAndChange:
    def test_mkdir_cancel_and_blank_do_nothing(self, mgr):
        for answer in (None, '   '):
            mgr.dialogs.answers = [answer]
            mgr.bundle.command('📁 Каталог')()
        assert len(mgr.host.simples) == 1

    def test_mkdir_joins_current_dir_and_strips(self, mgr):
        mgr.dialogs.answers = [' logs ']
        mgr.bundle.command('📁 Каталог')()
        fn, btn, on_done, args = mgr.host.simples[-1]
        assert fn is gf.make_dir and btn is None and callable(on_done)
        assert args == (mgr.checker, '/logs')

    def test_create_file_uses_own_backend(self, mgr):
        mgr.dialogs.answers = ['new.conf']
        mgr.bundle.command('📄 Файл')()
        assert mgr.host.simples[-1][0] is gf.create_file
        assert mgr.host.simples[-1][3] == (mgr.checker, '/new.conf')

    def test_after_change_status_first_line_log_refresh(self, mgr):
        mgr.dialogs.answers = ['logs']
        mgr.bundle.command('📁 Каталог')()
        before = len(mgr.host.simples)
        _finish(mgr.host, '✅ Каталог создан: /logs\nDETAIL')
        assert mgr.status.get() == '✅ Каталог создан: /logs'
        assert mgr.host.logs == ['✅ Каталог создан: /logs']
        # каталог обязан перечитаться: иначе оператор видит устаревшую таблицу
        assert len(mgr.host.simples) == before + 1
        assert mgr.host.simples[-1][0] is gf.list_dir

    def test_after_change_empty_result_says_done(self, mgr):
        mgr.dialogs.answers = ['logs']
        mgr.bundle.command('📁 Каталог')()
        _finish(mgr.host, '')
        assert mgr.status.get() == 'Готово'

    def test_after_change_ignored_after_close(self, mgr):
        mgr.bundle.command('Закрыть')()
        mgr.dialogs.answers = ['logs']
        mgr.bundle.command('📁 Каталог')()
        _finish(mgr.host, '✅ Каталог создан: /logs')
        assert mgr.host.logs == []
        assert len(mgr.host.simples) == 2  # перечитывания не было


class TestRename:
    def test_needs_selection(self, mgr):
        mgr.tree.sel = []
        mgr.bundle.command('Переименовать')()
        assert mgr.msg.events[0][0] == 'warning'
        assert len(mgr.host.simples) == 1

    def test_same_name_changes_nothing(self, mgr):
        mgr.tree.selection_set('app.conf')
        mgr.dialogs.answers = [' app.conf ']
        mgr.bundle.command('Переименовать')()
        assert len(mgr.host.simples) == 1

    def test_renames_inside_current_dir(self, mgr):
        _goto(mgr, '/etc', [_entry('app.conf')])
        mgr.tree.selection_set('app.conf')
        mgr.dialogs.answers = ['app.conf.bak']
        mgr.bundle.command('Переименовать')()
        fn, btn, on_done, args = mgr.host.simples[-1]
        assert fn is gf.rename_path and callable(on_done)
        assert args == (mgr.checker, '/etc/app.conf', '/etc/app.conf.bak')


class TestDelete:
    def test_declined_deletes_nothing(self, mgr):
        mgr.tree.selection_set('app.conf')
        mgr.msg.askyesno_ret = False
        mgr.bundle.command('✖ Удалить')()
        assert mgr.msg.asks  # спросил
        assert len(mgr.host.simples) == 1  # и не сделал

    def test_file_wording_and_flag(self, mgr):
        mgr.tree.selection_set('app.conf')
        mgr.bundle.command('✖ Удалить')()
        assert 'файл' in mgr.msg.asks[-1][1]
        assert mgr.host.simples[-1][3] == (mgr.checker, '/app.conf', False)

    def test_directory_warns_recursive_and_passes_flag(self, mgr):
        mgr.tree.selection_set('etc')
        mgr.bundle.command('✖ Удалить')()
        assert 'КАТАЛОГ СО ВСЕМ СОДЕРЖИМЫМ' in mgr.msg.asks[-1][1]
        assert mgr.host.simples[-1][3] == (mgr.checker, '/etc', True)


# ==================== скачать / загрузить ====================
class TestTransfer:
    def test_download_directory_is_refused(self, mgr):
        mgr.tree.selection_set('etc')
        mgr.bundle.command('⤓ Скачать')()
        assert mgr.msg.events[0][0] == 'info'
        assert mgr.files.save_asks == []
        assert len(mgr.host.simples) == 1

    def test_download_cancelled_transfers_nothing(self, mgr):
        mgr.tree.selection_set('app.conf')
        mgr.bundle.command('⤓ Скачать')()
        assert mgr.files.save_asks[-1]['initialfile'] == 'app.conf'
        assert len(mgr.host.simples) == 1

    def test_download_writes_to_chosen_local_path(self, mgr):
        mgr.files.save_as = '/tmp/app.conf.local'
        mgr.tree.selection_set('app.conf')
        mgr.bundle.command('⤓ Скачать')()
        fn, btn, on_done, args = mgr.host.simples[-1]
        assert fn is gf.download_file
        assert args == (mgr.checker, '/app.conf', '/tmp/app.conf.local')
        before = mgr.host.logs[:]
        _finish(mgr.host, '/tmp/app.conf.local')
        assert mgr.host.logs == before + ['/tmp/app.conf.local']
        assert mgr.status.get() == '/tmp/app.conf.local'

    def test_upload_cancel_opens_no_confirmation(self, mgr):
        mgr.bundle.command('⤒ Загрузить')()
        assert mgr.msg.asks == []
        assert len(mgr.host.simples) == 1

    def test_upload_declined_uploads_nothing(self, mgr):
        mgr.files.open_name = '/local/nginx.conf'
        mgr.msg.askyesno_ret = False
        mgr.bundle.command('⤒ Загрузить')()
        assert mgr.msg.asks
        assert len(mgr.host.simples) == 1

    def test_upload_uses_basename_in_current_dir(self, mgr):
        _goto(mgr, '/etc', [_entry('nginx.conf')])
        mgr.files.open_name = '/local/nginx.conf'
        mgr.bundle.command('⤒ Загрузить')()
        fn, _btn, on_done, args = mgr.host.simples[-1]
        assert fn is gf.upload_file
        assert args == (mgr.checker, '/local/nginx.conf', '/etc/nginx.conf')
        _finish(mgr.host, '/etc/nginx.conf')
        assert mgr.status.get() == '/etc/nginx.conf'

    def test_after_transfer_ignored_after_close(self, mgr):
        mgr.files.save_as = '/tmp/p'
        mgr.tree.selection_set('app.conf')
        mgr.bundle.command('⤓ Скачать')()
        mgr.bundle.command('Закрыть')()
        _finish(mgr.host, '/tmp/p')
        assert mgr.host.logs == []


# ==================== редактор текста ====================
class TestEditor:
    def test_binary_file_offers_download(self, mgr):
        _goto(mgr, '/etc', [_entry('logo.png')])
        mgr.tree.selection_set('logo.png')
        mgr.msg.askyesno_ret = False
        mgr.bundle.command('✎ Править')()
        # слово «бинарный» — в ЗАГОЛОВКЕ диалога («Похоже на бинарный файл»),
        # в тексте же — «не похож на текстовый» + предложение скачать
        assert 'бинарный' in mgr.msg.asks[-1][0]
        assert 'не похож на текстовый' in mgr.msg.asks[-1][1]
        assert mgr.files.save_asks == []  # отказ — не скачиваем
        assert mgr.host.simples[-1][0] is gf.list_dir  # чтение не открывалось

    def test_binary_file_yes_downloads_instead(self, mgr):
        _goto(mgr, '/etc', [_entry('logo.png')])
        mgr.tree.selection_set('logo.png')
        mgr.files.save_as = '/tmp/logo.png'
        mgr.bundle.command('✎ Править')()
        assert mgr.host.simples[-1][0] is gf.download_file
        assert mgr.host.simples[-1][3] == (mgr.checker, '/etc/logo.png',
                                           '/tmp/logo.png')

    def test_read_error_shows_dialog_without_editor(self, mgr):
        mgr.tree.selection_set('app.conf')
        mgr.bundle.command('✎ Править')()
        _finish(mgr.host, '❌ нет доступа')
        assert mgr.msg.events[-1][0] == 'error'
        assert len(mgr.bundle.toplevels()) == 1

    def test_editor_opens_with_content(self, mgr):
        mgr.tree.selection_set('app.conf')
        mgr.bundle.command('✎ Править')()
        _finish(mgr.host, 'root:x:0:0')
        editor = mgr.bundle.toplevels()[-1]
        assert editor.titles == ['Редактор: /app.conf']
        assert mgr.bundle.by_kind('Text')[0].buf == 'root:x:0:0'

    def test_save_declined_writes_nothing(self, mgr):
        mgr.tree.selection_set('app.conf')
        mgr.bundle.command('✎ Править')()
        _finish(mgr.host, 'root:x:0:0')
        mgr.msg.askyesno_ret = False
        mgr.bundle.command('Сохранить')()
        assert len(mgr.host.simples) == 2  # list_dir + read

    def test_save_strips_trailing_newline_and_reports(self, mgr):
        mgr.tree.selection_set('app.conf')
        mgr.bundle.command('✎ Править')()
        _finish(mgr.host, 'root:x:0:0')
        mgr.bundle.command('Сохранить')()
        fn, _btn, on_done, args = mgr.host.simples[-1]
        assert fn is gf.remote_write
        # Tk отдаёт текст с завершающим \n — на сервер обязан уйти без него
        assert args == (mgr.checker, '/app.conf', 'root:x:0:0')
        _finish(mgr.host, '✅ сохранено')
        assert mgr.msg.events[-1] == ('info', 'Готово', '✅ сохранено')

    def test_done_after_editor_close_is_swallowed(self, mgr):
        # редактор закрыли, пока запись в SFTP — messagebox в мёртвое окно
        mgr.tree.selection_set('app.conf')
        mgr.bundle.command('✎ Править')()
        _finish(mgr.host, 'root:x:0:0')
        mgr.bundle.command('Сохранить')()
        mgr.bundle.command('Закрыть', index=-1)()
        _finish(mgr.host, '✅ сохранено')
        assert mgr.msg.events == []

    def test_window_close_button_releases_editor(self, mgr):
        mgr.tree.selection_set('app.conf')
        mgr.bundle.command('✎ Править')()
        _finish(mgr.host, 'x')
        editor = mgr.bundle.toplevels()[-1]
        assert 'WM_DELETE_WINDOW' in editor.binds
        editor.binds['WM_DELETE_WINDOW']()
        assert editor.destroyed == 1


# ==================== закрытие менеджера ====================
class TestCloseManager:
    def test_close_button_destroys_window(self, mgr):
        mgr.bundle.command('Закрыть')()
        assert mgr.dialog.destroyed == 1

    def test_window_manager_close_runs_same_handler(self, mgr):
        mgr.dialog.binds['WM_DELETE_WINDOW']()
        assert mgr.dialog.destroyed == 1
