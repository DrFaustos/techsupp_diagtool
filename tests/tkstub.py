# -*- coding: utf-8 -*-
"""Бутстрап импорта gui-модулей, когда tkinter физически нет в интерпретаторе.

ЗАЧЕМ. Слайс 1.32.22 правит gui_swap.py: там «нет записи» и «не прочитали»
сливаются в одно no перед ДОПИСЫВАНИЕМ в /etc/fstab, то есть ложь заканчивается
не строкой отчёта, а записью в файл, от которого зависит загрузка машины. Но
боевой импорт модуля падает на первой строке: «ModuleNotFoundError: No module
named 'tkinter'». Зелёный по несобираемому тесту неотличим от слепого детектора
(тот же закон, из-за которого существует test_scan_actually_scans), поэтому
импортируемость надо вернуть ДО правки продукта, а не после коммита.

ПОЧЕМУ ЭТО ФАЙЛ-СТАБ, А НЕ ГЛОБАЛЬНЫЙ conftest.py (замер 1.32.22, и он дороже
самой заглушки). Первый вариант этого слайса был именно глобальный conftest. Он
поднял 6 файлов, но прогон изменился так:

    было:  1381 passed, 18 errors (collection)
    стало: 1594 passed, 9 FAILED, 11 errors

Девять реальных падений внес именно глобальный хук: test_gui_bitrix и
test_gui_hosting перестали быть «нечего собирать» и упали на
«module 'tkinter' has no attribute 'DISABLED'» (измеренная частота имён в
gui_*.py и их тестах: tk.DISABLED 71, tk.LEFT 57, tk.NORMAL 45, tk.END 28,
tk.X 21, tk.RIGHT 8, tk.BOTH 7, tk.NONE 3, tk.WORD 1, tk.SINGLE 1), а
ServerDiagnostic.spec вместо ModuleNotFoundError получил «no attribute 'Tcl'»
(спека зовёт tkinter.Tcl() за версией Tcl, и фейк ей не помощник, а вредитель).
То есть глобальный хук молча перекрасил 14 «неизвестно» в «известно
неправильно» — ровно тот класс подмены, против которого серия и написана.

Отсюда граница, которая здесь соблюдается:

  * стаб подключается ЯВНО, по файлу, и поднимает ровно то, что проверят его
    тесты: tests/test_gui_swap.py вызывает _do_* на двойнике checker и не трогает
    ни виджеты, ни константы Tk; никаких констант и никаких классов виджетов
    здесь нет НЕ по забывчивости — их отсутствие и есть граница честности;
  * подмена происходит ТОЛЬКО когда настоящий tkinter недоступен (try/except
    ImportError). На машине с Tk файл не меняет ничего: иначе мы подменяли бы
    настоящее окно фикцией именно там, где поведение надо мерить;
  * файлам, которым нужен живой Tk (виджеты, константы, mainloop),
    предназначен явный skip с причиной, а не молчаливый зелёный. Оставшиеся 7
    gui-файлов и ssh_client (paramiko, ttkbootstrap, scrolledtext, filedialog)
    поднимать здесь НЕЛЬЗЯ: это отдельный слайс с собственным замером значений
    констант, а не побочный эффект правки fstab.
"""
import sys
import types

try:
    import tkinter  # noqa: F401
except ImportError:
    _tk = types.ModuleType('tkinter')
    # Ровно те два имени, которые gui_swap импортирует на уровне файла. Ответы
    # не фиксированы: тесты подменяют их своими двойниками
    # (monkeypatch.setattr(gs, 'messagebox', ...)), здесь важна именно
    # импортируемость модуля, а не поведение диалогов.
    _tk.messagebox = types.SimpleNamespace(
        askyesno=lambda *a, **k: False,
        askokcancel=lambda *a, **k: False,
        showinfo=lambda *a, **k: None,
        showwarning=lambda *a, **k: None,
        showerror=lambda *a, **k: None)
    _tk.simpledialog = types.SimpleNamespace(
        askstring=lambda *a, **k: None,
        askinteger=lambda *a, **k: None)
    sys.modules['tkinter'] = _tk
    # Диалоги импортируются и как подмодули (from tkinter import messagebox):
    # регистрирую их в sys.modules тем же объектом, чтобы два пути импорта не
    # разъехались разными экземплярами (иначе monkeypatch бил бы по одному, а
    # продукт читал бы другой — тест зелёный по неверной причине).
    sys.modules['tkinter.messagebox'] = _tk.messagebox
    sys.modules['tkinter.simpledialog'] = _tk.simpledialog
