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

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from support import FakeSSH
from gui_swap import SwapMixin


class _Host(SwapMixin):
    """Минимальный владелец миксина: у _do_* методов нужен только checker."""

    def __init__(self, checker):
        self.checker = checker
        self.swap_btn = None
        self.fstab_btn = None


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
