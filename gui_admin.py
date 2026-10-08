"""Администрирование: замена IPv4/IPv6 в конфигах, перезапуск служб, bash-история, редактор конфигов.

Вынесено из gui.py без изменений исходников: константы —, функции —, методы run_replace_ipv4, _valid_ipv6, run_replace_ipv6, run_restart_services, get_bash_history, show_bash_history, run_config_editor."""

import tkinter as tk
from tkinter import messagebox, scrolledtext, simpledialog, ttk
import ttkbootstrap as tb
import re
from diagnostic import replace_ipv4, replace_ipv6, restart_services, get_config_files, read_file, write_file
from ttkbootstrap.constants import *


class AdminMixin:
    def run_replace_ipv4(self):
        if not self.checker:
            return
        old_ip = simpledialog.askstring("Замена IPv4", "Введите старый IPv4-адрес (который нужно заменить):", parent=self.root)
        if not old_ip:
            return
        if not re.match(r'^(\d{1,3}\.){3}\d{1,3}$', old_ip):
            messagebox.showerror("Ошибка", "Неверный формат IPv4-адреса")
            return
        new_ip = simpledialog.askstring("Замена IPv4", f"Введите новый IPv4-адрес (вместо {old_ip}):", parent=self.root)
        if not new_ip:
            return
        if not re.match(r'^(\d{1,3}\.){3}\d{1,3}$', new_ip):
            messagebox.showerror("Ошибка", "Неверный формат IPv4-адреса")
            return

        if messagebox.askyesno(
            "Подтверждение",
            f"Заменить {old_ip} на {new_ip} во всех .conf-файлах в /etc?\n\nБудут перезапущены nginx, mysql, apache.",
            parent=self.root
        ):
            self._run_in_thread(replace_ipv4, self.ipv4_btn, self.checker, old_ip, new_ip)

    def _valid_ipv6(self, value):
        import ipaddress
        try:
            ipaddress.IPv6Address(value)
            return True
        except (ipaddress.AddressValueError, ValueError):
            return False

    def run_replace_ipv6(self):
        if not self.checker:
            return
        old_ip = simpledialog.askstring("Замена IPv6", "Введите старый IPv6-адрес (который нужно заменить):", parent=self.root)
        if not old_ip:
            return
        if not self._valid_ipv6(old_ip.strip()):
            messagebox.showerror("Ошибка", "Неверный формат IPv6-адреса")
            return
        old_ip = old_ip.strip()
        new_ip = simpledialog.askstring("Замена IPv6", f"Введите новый IPv6-адрес (вместо {old_ip}):", parent=self.root)
        if not new_ip:
            return
        if not self._valid_ipv6(new_ip.strip()):
            messagebox.showerror("Ошибка", "Неверный формат IPv6-адреса")
            return
        new_ip = new_ip.strip()

        if messagebox.askyesno(
            "Подтверждение ⚠️",
            f"Заменить {old_ip} на {new_ip} во ВСЕХ файлах в /etc?\n\n"
            f"Внимание: обрабатываются ВСЕ файлы (включая бинарные/БД), "
            f"а не только конфиги!\n\nБудут перезапущены nginx, mysql, apache.",
            parent=self.root
        ):
            self._run_in_thread(replace_ipv6, self.ipv6_btn, self.checker, old_ip, new_ip)

    def run_restart_services(self):
        if not self.checker:
            return
        if messagebox.askyesno("Подтверждение", "Перезапустить nginx, mysql, apache?", parent=self.root):
            self._run_in_thread(restart_services, self.restart_btn, self.checker)

    def get_bash_history(self):
        """Получает историю команд из ~/.bash_history на удалённом сервере"""
        if not self.checker:
            self.log("⚠️ Нет подключения к серверу")
            return []
        out, err = self.checker.exec_command('cat ~/.bash_history 2>/dev/null | tail -100')
        if err.strip():
            self.log(f"⚠️ Ошибка при чтении истории: {err}")
            return []
        if out.strip():
            lines = [line.strip() for line in out.splitlines() if line.strip()]
            if not lines:
                self.log("ℹ️ История команд на сервере пуста.")
            return lines
        else:
            self.log("ℹ️ История команд на сервере не найдена или пуста.")
            return []

    def show_bash_history(self):
        """Открывает окно с историей команд с удалённого сервера"""
        if not self.checker:
            messagebox.showwarning("Нет подключения", "Подключитесь к серверу, чтобы получить историю команд.")
            return

        def on_history(history):
            if isinstance(history, str):
                self.log(history)
                return
            if not history:
                messagebox.showinfo("История команд", "История команд на сервере не найдена или пуста.")
                return
            dialog = tb.Toplevel(self.root)
            dialog.title("Bash История команд (с сервера)")
            dialog.geometry("600x400")
            dialog.transient(self.root)
            dialog.grab_set()
            text = scrolledtext.ScrolledText(dialog, wrap=tk.NONE, font=("Courier", 10))
            text.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
            text.insert(tk.END, "\n".join(history))
            text.config(state=tk.DISABLED)

        self._run_simple(self.get_bash_history, None, on_history)

    def run_config_editor(self):
        if not self.checker:
            return

        files = get_config_files(self.checker, self.panel_type)
        if not files:
            messagebox.showinfo("Информация", "Конфигурационные файлы не найдены.")
            return

        editor_dialog = tb.Toplevel(self.root)
        editor_dialog.title("Редактор конфигурационных файлов")
        editor_dialog.geometry("800x600")
        editor_dialog.minsize(700, 500)
        editor_dialog.transient(self.root)
        editor_dialog.grab_set()

        top_frame = tb.Frame(editor_dialog, bootstyle="secondary")
        top_frame.pack(fill=tk.X, padx=10, pady=5)

        tb.Label(top_frame, text="Файл:", bootstyle="inverse-secondary").pack(side=tk.LEFT, padx=5)

        file_var = tk.StringVar()
        file_combo = ttk.Combobox(top_frame, textvariable=file_var, values=files, width=60)
        file_combo.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)

        current_filepath = [""]
        original_content = [""]

        def _load(filepath):
            if not filepath:
                messagebox.showwarning("Внимание", "Выберите файл")
                return
            text_editor.config(state=tk.DISABLED)
            editor_dialog.update()
            content = read_file(self.checker, filepath)
            text_editor.delete(1.0, tk.END)
            text_editor.insert(tk.END, content)
            text_editor.config(state=tk.NORMAL)
            current_filepath[0] = filepath
            original_content[0] = content

        def load_file():
            _load(file_var.get().strip())

        load_btn = tb.Button(top_frame, text="Загрузить", command=load_file, bootstyle="primary")
        load_btn.pack(side=tk.LEFT, padx=5)

        editor_frame = tb.Frame(editor_dialog, bootstyle="secondary")
        editor_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)

        text_editor = scrolledtext.ScrolledText(editor_frame, wrap=tk.NONE, font=("Courier", 10))
        text_editor.pack(fill=tk.BOTH, expand=True)

        bottom_frame = tb.Frame(editor_dialog, bootstyle="secondary")
        bottom_frame.pack(fill=tk.X, padx=10, pady=5)

        def save_file():
            filepath = current_filepath[0]
            if not filepath:
                messagebox.showwarning("Внимание", "Сначала загрузите файл")
                return
            content = text_editor.get(1.0, tk.END)
            if messagebox.askyesno("Подтверждение", f"Сохранить изменения в {filepath}?", parent=editor_dialog):
                text_editor.config(state=tk.DISABLED)
                editor_dialog.update()
                result = write_file(self.checker, filepath, content)
                self._display_result(result)
                text_editor.config(state=tk.NORMAL)
                original_content[0] = content
                messagebox.showinfo("Успех", "Файл сохранён", parent=editor_dialog)

        def reload_file():
            filepath = current_filepath[0]
            if not filepath:
                messagebox.showwarning("Внимание", "Сначала загрузите файл")
                return
            _load(filepath)

        def close_editor():
            if text_editor.get(1.0, tk.END) != original_content[0]:
                if messagebox.askyesno("Подтверждение", "Закрыть редактор без сохранения изменений?", parent=editor_dialog):
                    editor_dialog.destroy()
            else:
                editor_dialog.destroy()

        tb.Button(bottom_frame, text="Сохранить", command=save_file, bootstyle="success").pack(side=tk.LEFT, padx=5)
        tb.Button(bottom_frame, text="Перезагрузить", command=reload_file, bootstyle="warning").pack(side=tk.LEFT, padx=5)
        tb.Button(bottom_frame, text="Закрыть", command=close_editor, bootstyle="danger").pack(side=tk.RIGHT, padx=5)

        file_combo.set(files[0])
        _load(files[0])
