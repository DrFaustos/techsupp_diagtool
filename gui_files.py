"""Файловый менеджер сервера (SFTP): окно навигации и операции над файлами.

Сами файловые операции живут в fmanager.py (покрыт тестами без GUI), здесь
только разметка диалога и вызовы через RunnerMixin._run_simple: сетевой запрос
никогда не блокирует интерфейс, а кнопка «Отменить» остаётся рабочей.

Диалог НЕ делает grab_set — из него должны открываться системные окна выбора
файла (Скачать/Загрузить).
"""
import os
import posixpath
import tkinter as tk
from tkinter import filedialog, messagebox, simpledialog, ttk
import ttkbootstrap as tb

from fmanager import (
    list_dir, make_dir, create_file, delete_path, rename_path,
    download_file, upload_file, format_entries, is_text_file,
)
from files import read_file as remote_read, write_file as remote_write


def _join(path, name):
    """Склеивает удалённый путь и имя без двойных слэшей."""
    return posixpath.join('/' + (path or '/').strip('/'), name)


class FilesMixin:
    # ---------- ФАЙЛОВЫЙ МЕНЕДЖЕР ----------
    def open_file_manager(self):
        if not self.checker:
            messagebox.showwarning(
                "Нет подключения",
                "Подключитесь к серверу, чтобы открыть файлы.",
                parent=self.root)
            return

        dialog = tb.Toplevel(self.root)
        dialog.title("Файлы на сервере (SFTP)")
        dialog.geometry("860x520")
        dialog.transient(self.root)

        # Фоновые задачи возвращаются через root.after: если окно уже закрыли,
        # колбэки обязаны молча выйти, иначе TclError в mainloop.
        alive = [True]
        current = ['/']
        listing = [{}]
        editing = ['']

        path_var = tk.StringVar(value="/")
        status_var = tk.StringVar(value="Введите путь и нажмите «Открыть»")

        top = tb.Frame(dialog, bootstyle="secondary")
        top.pack(fill=tk.X, padx=10, pady=(5, 0))
        tb.Label(top, text="Путь:", bootstyle="inverse-secondary").pack(side=tk.LEFT, padx=5)
        path_entry = tb.Entry(top, textvariable=path_var)
        path_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)

        columns = ('name', 'kind', 'size', 'mode', 'mtime')
        tree = ttk.Treeview(dialog, columns=columns, show='headings')
        for col, title, width, anchor in (
            ('name', 'Имя', 320, 'w'),
            ('kind', 'Тип', 80, 'w'),
            ('size', 'Размер', 90, 'e'),
            ('mode', 'Права', 110, 'w'),
            ('mtime', 'Изменён', 130, 'w'),
        ):
            tree.heading(col, text=title)
            tree.column(col, width=width, anchor=anchor)
        tree.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)

        tb.Label(dialog, textvariable=status_var, bootstyle="inverse-secondary").pack(
            anchor='w', padx=10)

        actions = tb.Frame(dialog, bootstyle="secondary")
        actions.pack(fill=tk.X, padx=10, pady=5)

        # ---------- загрузка каталога ----------
        def load(path):
            path = (path or '').strip() or '/'
            if not path.startswith('/'):
                messagebox.showerror("Путь", "Нужен абсолютный путь, например /etc/nginx",
                                     parent=dialog)
                return

            def on_done(result):
                if not alive[0]:
                    return
                if isinstance(result, str):
                    status_var.set("Каталог не прочитан")
                    messagebox.showerror("Ошибка", result, parent=dialog)
                    return
                current[0] = path
                path_var.set(path)
                listing[0] = {e['name']: e for e in result}
                tree.delete(*tree.get_children())
                for entry, row in zip(result, format_entries(result)):
                    tree.insert('', 'end', iid=entry['name'], values=row)
                status_var.set(f"{len(result)} записей: {path}")

            self._run_simple(list_dir, None, on_done, self.checker, path)

        def reload_list():
            load(current[0])

        def go_up():
            load(posixpath.dirname(current[0].rstrip('/')) or '/')

        # ---------- выбор ----------
        def selected_path():
            """Возвращает (путь, запись) выбранной строки либо None."""
            sel = tree.selection()
            if not sel:
                messagebox.showwarning("Не выбрано",
                                       "Сначала выберите файл или каталог.",
                                       parent=dialog)
                return None
            entry = listing[0].get(str(sel[0]))
            if not entry:
                return None
            return _join(current[0], entry['name']), entry

        def after_change(result):
            """Общий исход операций, меняющих каталог: строка статуса + refresh."""
            if not alive[0]:
                return
            text = str(result).strip()
            line = text.splitlines()[0] if text else "Готово"
            status_var.set(line)
            self.log(line)
            reload_list()

        def after_transfer(result):
            if not alive[0]:
                return
            self.log(str(result))
            status_var.set(str(result))

        # ---------- операции ----------
        def do_mkdir():
            name = simpledialog.askstring("Новый каталог", "Имя каталога:", parent=dialog)
            if not name or not name.strip():
                return
            self._run_simple(make_dir, None, after_change,
                             self.checker, _join(current[0], name.strip()))

        def do_create_file():
            name = simpledialog.askstring("Новый файл", "Имя файла:", parent=dialog)
            if not name or not name.strip():
                return
            self._run_simple(create_file, None, after_change,
                             self.checker, _join(current[0], name.strip()))

        def do_rename():
            target = selected_path()
            if not target:
                return
            path, entry = target
            name = simpledialog.askstring("Переименовать", "Новое имя:",
                                          initialvalue=entry['name'], parent=dialog)
            if not name or not name.strip() or name.strip() == entry['name']:
                return
            self._run_simple(rename_path, None, after_change,
                             self.checker, path, _join(current[0], name.strip()))

        def do_delete():
            target = selected_path()
            if not target:
                return
            path, entry = target
            what = "КАТАЛОГ СО ВСЕМ СОДЕРЖИМЫМ" if entry['is_dir'] else "файл"
            if not messagebox.askyesno(
                "Подтверждение удаления",
                f"Удалить {what}: {path} ?\n\nЭто действие необратимо.",
                parent=dialog):
                return
            self._run_simple(delete_path, None, after_change,
                             self.checker, path, entry['is_dir'])

        def save_as(remote_path, suggested_name):
            local = filedialog.asksaveasfilename(parent=dialog,
                                                 initialfile=suggested_name,
                                                 title="Сохранить как")
            if not local:
                return
            self._run_simple(download_file, None, after_transfer,
                             self.checker, remote_path, local)

        def do_download():
            target = selected_path()
            if not target:
                return
            path, entry = target
            if entry['is_dir']:
                messagebox.showinfo("Каталог",
                                    "Каталог целиком не скачивается — выберите файл.",
                                    parent=dialog)
                return
            save_as(path, entry['name'])

        def do_upload():
            local = filedialog.askopenfilename(parent=dialog, title="Загрузить файл")
            if not local:
                return
            remote = _join(current[0], os.path.basename(local))
            if not messagebox.askyesno("Подтверждение",
                                       f"Загрузить {local}\nв {remote} ?",
                                       parent=dialog):
                return
            self._run_simple(upload_file, None, after_transfer,
                             self.checker, local, remote)

        # ---------- редактирование текста ----------
        def open_editor(content):
            if isinstance(content, str) and content.startswith("❌"):
                messagebox.showerror("Ошибка", content, parent=dialog)
                return

            ed = tb.Toplevel(dialog)
            ed.title(f"Редактор: {editing[0]}")
            ed.geometry("800x520")
            ed.transient(dialog)
            editor_alive = [True]

            body = tk.Text(ed, wrap=tk.NONE, font=("Courier", 10))
            body.insert('1.0', content)
            body.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)

            def save():
                text = body.get('1.0', tk.END).rstrip('\n')
                if not messagebox.askyesno(
                    "Сохранение",
                    f"Записать {editing[0]} ?\nРезервная копия создаётся автоматически.",
                    parent=ed):
                    return

                def done(result):
                    if editor_alive[0]:
                        messagebox.showinfo("Готово", str(result), parent=ed)

                self._run_simple(remote_write, None, done, self.checker, editing[0], text)

            def close_editor():
                editor_alive[0] = False
                ed.destroy()

            bar = tb.Frame(ed, bootstyle="secondary")
            bar.pack(fill=tk.X, padx=10, pady=5)
            tb.Button(bar, text="Сохранить", command=save, bootstyle="success").pack(
                side=tk.LEFT, padx=5)
            tb.Button(bar, text="Закрыть", command=close_editor,
                      bootstyle="secondary").pack(side=tk.RIGHT, padx=5)
            ed.protocol("WM_DELETE_WINDOW", close_editor)

        def do_edit(path, entry):
            if not is_text_file(path):
                if messagebox.askyesno(
                    "Похоже на бинарный файл",
                    f"{path} не похож на текстовый — редактировать нельзя.\n"
                    f"Скачать его на эту машину?",
                    parent=dialog):
                    save_as(path, entry['name'])
                return
            editing[0] = path
            self._run_simple(remote_read, None, open_editor, self.checker, path)

        def do_edit_selected():
            target = selected_path()
            if target:
                do_edit(*target)

        def on_open(event=None):
            target = selected_path()
            if not target:
                return
            path, entry = target
            if entry['is_dir']:
                load(path)
            else:
                do_edit(path, entry)

        path_entry.bind("<Return>", lambda e: load(path_var.get()))
        # Открытие выбранного: двойным кликом либо Enter (в тесте Double-1
        # синтезировать нельзя — Tk его запрещает, Return — тот же on_open).
        tree.bind("<Double-1>", on_open)
        tree.bind("<Return>", on_open)

        for text, cmd, style in (
            ("↻ Обновить", reload_list, "secondary-outline"),
            ("↑ Вверх", go_up, "secondary-outline"),
            ("📁 Каталог", do_mkdir, "secondary-outline"),
            ("📄 Файл", do_create_file, "secondary-outline"),
            ("✎ Править", do_edit_selected, "info-outline"),
            ("⤓ Скачать", do_download, "primary-outline"),
            ("⤒ Загрузить", do_upload, "primary-outline"),
            ("Переименовать", do_rename, "warning-outline"),
            ("✖ Удалить", do_delete, "danger-outline"),
        ):
            tb.Button(actions, text=text, command=cmd, bootstyle=style).pack(
                side=tk.LEFT, padx=3)

        def close_manager():
            alive[0] = False
            dialog.destroy()

        tb.Button(actions, text="Закрыть", command=close_manager,
                  bootstyle="secondary").pack(side=tk.RIGHT, padx=5)
        dialog.protocol("WM_DELETE_WINDOW", close_manager)

        load(current[0])
        tree.focus_set()
