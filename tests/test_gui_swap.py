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
# tkstub обязан стоять ДО импорта gui_swap: модуль делает
# «from tkinter import messagebox, simpledialog» на уровне файла, а в этом
# интерпретаторе tkinter отсутствует физически, и порядок принципиален — импорт
# ниже уже не спасёт, если боевой импорт произошёл первым. Стаб узкий и
# подключён ЯВНО этим тестом, а не глобальным conftest: причины измерены и
# описаны в tkstub.py (глобальный хук поднял 6 файлов и внёс 9 реальных
# падений, то есть подменил «неизвестно» на «известно неправильно»).
import tkstub  # noqa: F401
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
        # grep находит /swapfile — добавляющую команду слать нельзя.
        # 1.32.22: ответ обязан быть назван КОДОМ (rc=0 = совпадение найдено),
        # а не готовым словом 'yes': именно «&& echo yes || echo no» и есть
        # носитель лжи, который слайс лечит, и прежняя фикстура закрепляла его
        # как ответ сервера.
        c = FakeSSH(routes=[('grep -Fq', ('', '', 0))])
        out = _Host(c)._do_add_swap_to_fstab()
        assert 'уже присутствует' in out
        assert c.find('>> /etc/fstab') is None

    def test_missing_entry_appends_line_and_shows_tail(self):
        # rc=1 у грепа: файл ОТКРЫТ и ПРОЧИТАН, совпадений нет — единственный
        # мир, где дописывание разрешено (замер живьём, .ai-free/
        # localize13222.py). Слово 'no' прежняя фикстура брала у оболочки, а не
        # у грепа: rc всей прежней строки всегда 0, то есть фикстура описывала
        # ложь, а не измерение.
        c = FakeSSH(routes=[
            ('grep -Fq', ('', '', 1)),
            ('tail -3', '/dev/sda1 none swap sw 0 0\n'),
        ])
        out = _Host(c)._do_add_swap_to_fstab()
        append = c.find('>> /etc/fstab')
        assert append is not None
        assert '/swapfile none swap sw 0 0' in append
        assert 'Последние строки /etc/fstab:' in out
        assert '/dev/sda1 none swap sw 0 0' in out

    def test_append_error_reports_stderr(self):
        # 1.32.22: тот же перевод — отказ дописывания по READ-ONLY файлу
        # обязан опираться на rc грепа (1 = прочитан, совпадений нет), иначе
        # тест проходил бы по готовому слову.
        c = FakeSSH(routes=[
            ('grep -Fq', ('', '', 1)),
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

# ===== 1.32.22: панель не имеет права дописывать fstab, не прочитав его =====
# Замер живьём (.ai-free/localize13222.py, настоящий bash 5.3, uid=1000,
# настоящие chmod, точечная подмена PATH; прежняя боевая функция v1.32.21
# вызвана НАСТОЯЩИМ bash'ом на ТЕХ ЖЕ мирах, путь /etc/fstab переписан в
# песочницу, хеш боевого /etc/fstab сверен до и после). Форма
# «grep -q '/swapfile' /etc/fstab && echo 'yes' || echo 'no'» даёт ПЯТЬ миров с
# побайтово одинаковым out='no' rc=0, и прежняя функция во ВСЕХ ПЯТИ отправила
# «echo "/swapfile none swap sw 0 0" >> /etc/fstab»:
#   записи нет (файл прочитан)  rc=1 у грепа  — дописать верно
#   файл есть, chmod 000        rc=2          — дописать НЕЛЬЗЯ
#   файла нет                   rc=2          — дописать НЕЛЬЗЯ
#   каталог вместо файла        rc=2          — дописать НЕЛЬЗЯ
#   grep НЕТ в PATH             rc=127        — мы НЕ СПРОСИЛИ
# Конструкция && || съедает коды: оба ответа печатает оболочка, и rc всей строки
# всегда 0. Здесь ложь этого класса впервые кончается не строкой отчёта, а
# записью в файл, от которого зависит загрузка машины.
GS_UNREADABLE = ('', '', 2)
GS_LISTED = ('fstab' + chr(10), '', 0)
GS_LISTED_NO_FSTAB = ('fstab.bak' + chr(10), '', 0)
GS_NO_GREP = ('', 'bash: grep: command not found' + chr(10), 127)


class TestFstabAppendNeedsAReadFile:
    """Дописывание в fstab разрешено только по ПРОЧИТАННОМУ файлу."""

    def test_unreadable_fstab_is_not_reported_as_no_entry(self):
        # Ядро слайса. Прежний ответ: «$ echo ... >> /etc/fstab» — запись
        # дубля в файл, который греп не открыл.
        c = FakeSSH(routes=[('grep -Fq', GS_UNREADABLE),
                            ('ls -1 -p', GS_LISTED)])
        out = _Host(c)._do_add_swap_to_fstab()
        assert 'не проверено' in out, out
        assert c.find('>> /etc/fstab') is None, c.commands
        assert 'уже присутствует' not in out, out

    def test_absent_fstab_says_absent_and_does_not_append(self):
        # Отсутствующий fstab — отдельный мир: дописывание создало бы файл с
        # одной строкой swap вместо починки пути (и на systemd-хосте fstab
        # законно не используется вовсе).
        c = FakeSSH(routes=[('grep -Fq', GS_UNREADABLE),
                            ('ls -1 -p', GS_LISTED_NO_FSTAB)])
        out = _Host(c)._do_add_swap_to_fstab()
        assert 'не найден' in out, out
        assert c.find('>> /etc/fstab') is None, c.commands

    def test_unavailable_grep_does_not_append(self):
        # rc=127: «нечем спросить». Прежний код в этом мире тоже дописывал —
        # то есть отсутствие утилиты на сервере заканчивалось правкой fstab.
        c = FakeSSH(routes=[('grep -Fq', GS_NO_GREP)])
        out = _Host(c)._do_add_swap_to_fstab()
        assert 'не проверено' in out, out
        assert c.find('>> /etc/fstab') is None, c.commands

    def test_read_file_without_entry_appends(self):
        # Обратный контроль нормы: rc=1 (файл прочитан, совпадений нет) —
        # единственный мир, где дописывание разрешено, и оно обязано остаться.
        c = FakeSSH(routes=[('grep -Fq', ('', '', 1)),
                            ('tail -3', '/dev/sda1 / ext4 defaults 0 1\n')])
        out = _Host(c)._do_add_swap_to_fstab()
        assert c.find('>> /etc/fstab') is not None, c.commands
        assert 'не проверено' not in out, out
        assert '/swapfile none swap sw 0 0' in c.find('>> /etc/fstab')

    def test_question_is_fixed_strings_and_carries_no_ready_word(self):
        # Замок на ФОРМЕ спроса. «&& echo yes || echo no» — это и есть носитель
        # лжи: готовые слова, которые печатает оболочка, а rc строки всегда 0.
        # -F обязателен: без него искомый путь трактуется регулярным выражением,
        # и ложное «уже есть» отказало бы в дописывании (замер с приманкой в
        # red13222_common.txt).
        c = FakeSSH(routes=[('grep -Fq', ('', '', 1))])
        _Host(c)._do_add_swap_to_fstab()
        cmd = c.find('grep')
        assert cmd is not None, c.commands
        assert cmd.startswith('grep -Fq '), c.commands
        assert '&&' not in cmd and '||' not in cmd, c.commands
        assert 'echo' not in cmd, c.commands

