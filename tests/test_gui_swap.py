"""Тесты gui_swap.py: создание swap-файла и запись в /etc/fstab.

Логика _do_create_swap / _do_add_swap_to_fstab зависит только от
self.checker.run(), поэтому проверяется на FakeSSH без Tk и без дисплея.
Диалоги (simpledialog/messagebox) в create_swap/add_swap_to_fstab не дёргаются
напрямую — их наличие подтверждается AST-гардом, что работа уходит в
_run_simple (фоновый поток), а не выполняется в mainloop.
"""
import ast
import os
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from support import FakeSSH
import gui_swap as gs
from gui_swap import SwapMixin


class _Host(SwapMixin):
    """Владелец миксина: у _do_* нужен только checker, у публичных методов —
    ещё dialog-обвязка; _run_simple записывается, поток не запускается."""

    def __init__(self, checker):
        self.checker = checker
        self.root = None
        self.swap_btn = object()
        self.fstab_btn = object()
        self.simples = []

    def _run_simple(self, func, btn=None, on_done=None, *args):
        self.simples.append((func, btn, on_done, args))


class _Dialogs:
    """Двойник simpledialog: очередь ответов askstring + запись обращений."""

    def __init__(self, answers=()):
        self.answers = list(answers)
        self.string_asks = []

    def askstring(self, title, prompt, parent=None, initialvalue=None):
        self.string_asks.append({'title': title, 'parent': parent})
        return self.answers.pop(0) if self.answers else None


class _Msg:
    def __init__(self, askyesno_ret=True):
        self.askyesno_ret = askyesno_ret
        self.events = []   # (kind, title, msg)
        self.asks = []

    def askyesno(self, title, msg, parent=None):
        self.asks.append((title, msg))
        return self.askyesno_ret

    def showerror(self, title, msg, parent=None):
        self.events.append(('error', title, msg))


def _patch(monkeypatch, answers=(), askyesno_ret=True):
    dialogs = _Dialogs(answers)
    msg = _Msg(askyesno_ret)
    monkeypatch.setattr(gs, 'simpledialog', dialogs)
    monkeypatch.setattr(gs, 'messagebox', msg)
    return dialogs, msg


# ==================== публичные методы: диалог и подтверждение =========
#
# Непокрытая часть модуля — обёртки create_swap/add_swap_to_fstab: guard по
# подключению, разбор размера и подтверждение. Именно здесь рождается число,
# которое потом уходит в fallocate, поэтому «abc» обязана быть отклонена ДО
# фоновой задачи, а «Нет» в подтверждении — не запускать поток вовсе.


class TestCreateSwapDialog:
    def test_silent_without_connection(self, monkeypatch):
        dialogs, msg = _patch(monkeypatch, answers=['1024'])
        host = _Host(checker=None)
        host.create_swap()
        assert host.simples == []
        assert dialogs.string_asks == []   # размер даже не спрашивали
        assert msg.asks == []

    def test_cancelled_size_launches_nothing(self, monkeypatch):
        dialogs, msg = _patch(monkeypatch, answers=[None])
        host = _Host(FakeSSH())
        host.create_swap()
        assert len(dialogs.string_asks) == 1
        assert host.simples == [] and msg.asks == []

    def test_blank_size_launches_nothing(self, monkeypatch):
        # пустая строка — тот же отказ, что и «Отмена»: int('') не бросаем
        _d, msg = _patch(monkeypatch, answers=[''])
        host = _Host(FakeSSH())
        host.create_swap()
        assert host.simples == [] and msg.events == [] and msg.asks == []

    def test_non_numeric_size_rejected_with_error(self, monkeypatch):
        _d, msg = _patch(monkeypatch, answers=['abc'])
        host = _Host(FakeSSH())
        host.create_swap()
        assert msg.events == [('error', 'Ошибка', 'Введите целое число')]
        assert msg.asks == []          # до подтверждения не дошло
        assert host.simples == []

    def test_declined_confirmation_runs_no_thread(self, monkeypatch):
        _d, msg = _patch(monkeypatch, answers=['1024'], askyesno_ret=False)
        host = _Host(FakeSSH())
        host.create_swap()
        assert msg.asks                # спросил
        assert host.simples == []      # и не сделал

    def test_confirmed_passes_int_size_to_background(self, monkeypatch):
        _d, msg = _patch(monkeypatch, answers=['2048'])
        host = _Host(FakeSSH())
        host.create_swap()
        assert len(host.simples) == 1
        fn, btn, on_done, args = host.simples[0]
        assert fn == host._do_create_swap      # метод миксина, не голая функция
        assert btn is host.swap_btn
        assert on_done is None
        assert args == (2048,)                 # именно int, а не строка
        # в подтверждении — размер, который уйдёт в fallocate
        assert '2048' in msg.asks[0][1]


class TestAddSwapToFstabDialog:
    def test_silent_without_connection(self, monkeypatch):
        _patch(monkeypatch)
        host = _Host(checker=None)
        host.add_swap_to_fstab()
        assert host.simples == []

    def test_runs_in_background_without_confirmation(self, monkeypatch):
        # метод идемпотентен (пишет только при отсутствии записи) — спрашивать
        # нечего, уходит сразу в фон
        _d, msg = _patch(monkeypatch)
        host = _Host(FakeSSH())
        host.add_swap_to_fstab()
        assert len(host.simples) == 1
        fn, btn, on_done, args = host.simples[0]
        assert fn == host._do_add_swap_to_fstab
        assert btn is host.fstab_btn
        assert args == () and msg.asks == []


# ==================== создание swap-файла ====================
class TestCreateSwapFile:
    def test_insufficient_space_aborts_before_write(self):
        # доступно 500 МБ, просим 1024 (+100 запас) — команда не уходит
        c = FakeSSH(routes=[('df -m', '500\n')])
        out = _Host(c)._do_create_swap(1024)
        assert '❌ Недостаточно свободного места' in out
        assert c.find('fallocate') is None
        assert c.find('mkswap') is None

    def test_non_numeric_free_is_treated_as_zero(self):
        # df вернул мусор (панель/язык) — isdigit() ложно, free_mb=0
        c = FakeSSH(routes=[('df -m', '  \n')])
        out = _Host(c)._do_create_swap(1024)
        assert '❌ Недостаточно свободного места' in out
        assert c.find('fallocate') is None

    def test_full_sequence_in_order(self):
        c = FakeSSH(routes=[
            ('df -m', '4000\n'),
            ('mkswap', 'Setting up swapspace version 1, size = 1 GiB\n'),
            ('--show', '/swapfile file 1024M 0B 100%\n'),
        ])
        out = _Host(c)._do_create_swap(1024)
        assert '=== Создание swap файла размером 1024 МБ ===' in out
        # порядок: fallocate → chmod → mkswap → swapon
        idx_alloc = next(i for i, x in enumerate(c.commands) if 'fallocate' in x)
        idx_mk = next(i for i, x in enumerate(c.commands) if 'mkswap' in x)
        idx_on = next(i for i, x in enumerate(c.commands) if x == 'swapon /swapfile')
        assert idx_alloc < idx_mk < idx_on
        alloc = c.find('fallocate')
        assert alloc is not None
        assert 'fallocate -l 1024M /swapfile' in alloc
        assert 'dd if=/dev/zero of=/swapfile bs=1M count=1024' in alloc
        assert c.find('chmod 600 /swapfile') is not None
        # вывод mkswap и таблица текущих разделов
        assert 'Setting up swapspace' in out
        assert 'Текущие swap-разделы:' in out
        assert '/swapfile file 1024M' in out

    def test_stderr_from_commands_is_reported(self):
        # mkswap падает с сообщением в stderr — оно должно попасть в отчёт
        c = FakeSSH(routes=[
            ('df -m', '8000\n'),
            ('mkswap', ('', 'mkswap: /swapfile: insufficient memory', 1)),
        ])
        out = _Host(c)._do_create_swap(1024)
        assert 'STDERR: mkswap: /swapfile: insufficient memory' in out

    def test_clean_run_has_no_stderr_line(self):
        c = FakeSSH(routes=[('df -m', '8000\n'), ('--show', '/swapfile file 1024M 0B 100%')])
        out = _Host(c)._do_create_swap(1024)
        assert 'STDERR' not in out


# ==================== запись в fstab ====================
class TestAddSwapToFstab:
    def test_existing_entry_is_not_duplicated(self):
        # grep находит /swapfile — добавляющую команду слать нельзя
        c = FakeSSH(routes=[('grep -q', 'yes\n')])
        out = _Host(c)._do_add_swap_to_fstab()
        assert 'уже присутствует' in out
        assert c.find('>> /etc/fstab') is None

    def test_missing_entry_appends_line_and_shows_tail(self):
        c = FakeSSH(routes=[
            ('grep -q', 'no\n'),
            ('tail -3', '/dev/sda1 none swap sw 0 0\n'),
        ])
        out = _Host(c)._do_add_swap_to_fstab()
        append = c.find('>> /etc/fstab')
        assert append is not None
        assert '/swapfile none swap sw 0 0' in append
        assert 'Последние строки /etc/fstab:' in out
        assert '/dev/sda1 none swap sw 0 0' in out

    def test_append_error_reports_stderr(self):
        c = FakeSSH(routes=[
            ('grep -q', 'no\n'),
            ('>> /etc/fstab', ('', 'bash: /etc/fstab: Read-only file system', 1)),
        ])
        out = _Host(c)._do_add_swap_to_fstab()
        assert 'STDERR: bash: /etc/fstab: Read-only file system' in out


# ==================== гарды встраивания ====================
def _src(name):
    with open(os.path.join(ROOT, name), encoding='utf-8') as f:
        return f.read()


def _run_simple_targets(path):
    tree = ast.parse(_src(path), filename=path)
    names = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and getattr(node.func, 'attr', '') == '_run_simple':
            if not node.args:
                continue
            target = node.args[0]
            # в gui_swap цели — методы миксина: self._do_create_swap (Attribute),
            # в gui_files — голые функции fmanager (Name). Разбираем обе формы.
            if isinstance(target, ast.Name):
                names.add(target.id)
            elif isinstance(target, ast.Attribute):
                names.add(target.attr)
    return names


class TestWiring:
    def test_heavy_ops_run_in_background(self):
        """Ни fallocate, ни правка fstab не должны выполняться в mainloop."""
        used = _run_simple_targets('gui_swap.py')
        expected = {'_do_create_swap', '_do_add_swap_to_fstab'}
        assert expected <= used, f'вызывается из UI-потока: {sorted(expected - used)}'

    def test_button_command_points_at_public_methods(self):
        src = _src('gui.py')
        assert 'command=self.create_swap' in src or 'command=self.create_swap)' in src
        assert hasattr(SwapMixin, 'create_swap')
        assert hasattr(SwapMixin, 'add_swap_to_fstab')
