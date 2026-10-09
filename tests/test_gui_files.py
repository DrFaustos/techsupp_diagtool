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
