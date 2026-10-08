"""DNS: проверка доменов, резолверы сервера и диалог их замены.

Вынесено из gui.py без изменений исходников: константы —, функции —, методы run_dns_check, _open_dns_check_dialog, run_dns_resolvers, run_edit_dns, _open_edit_dns_dialog."""

import tkinter as tk
from tkinter import messagebox, simpledialog, ttk
import ttkbootstrap as tb
import re
from diagnostic import get_domains, dns_report, dns_report_local, dns_resolvers_report, get_current_dns_resolvers, set_dns_resolvers
from gui_themes import get_theme_colors
from ttkbootstrap.constants import *


class DnsMixin:
    def run_dns_check(self):
        if not self.checker:
            return
        self.log("Получение списка доменов...")
        self._run_simple(get_domains, None, self._open_dns_check_dialog, self.checker, self.panel_type)

    def _open_dns_check_dialog(self, domains):
        if isinstance(domains, str):
            self.log(domains)
            domains = []
        domain_var = tk.StringVar()
        if domains:
            domain_var.set(domains[0])

        dialog = tb.Toplevel(self.root)
        dialog.title("DNS-проверка")
        dialog.geometry("450x230")
        dialog.transient(self.root)
        dialog.grab_set()

        tb.Label(dialog, text="Домен/IP:", bootstyle="inverse-secondary").grid(
            row=0, column=0, sticky='e', padx=5, pady=5
        )
        domain_combo = ttk.Combobox(
            dialog, textvariable=domain_var, values=domains, state='normal'
        )
        domain_combo.grid(row=0, column=1, padx=5, pady=5, sticky='ew')
        if not domains:
            domain_combo.set('')

        local_var = tk.BooleanVar(value=False)
        cb = tb.Checkbutton(
            dialog,
            text="Выполнить локально (A и PTR, NS только с сервера)",
            variable=local_var,
            bootstyle="secondary-round-toggle"
        )
        cb.grid(row=1, column=0, columnspan=2, sticky='w', padx=5, pady=5)

        def on_check():
            domain = domain_var.get().strip()
            if not domain:
                messagebox.showerror("Ошибка", "Введите домен или IP")
                return
            local = local_var.get()
            dialog.destroy()
            self.log("\n" + "="*60)
            if local:
                self._run_simple(dns_report_local, self.dns_btn, None, domain)
            else:
                self._run_simple(dns_report, self.dns_btn, None, self.checker, domain)

        tb.Button(dialog, text="Проверить", command=on_check, bootstyle="success").grid(
            row=2, column=0, columnspan=2, pady=10
        )
        dialog.columnconfigure(1, weight=1)

    def run_dns_resolvers(self):
        if not self.checker:
            return
        self._run_in_thread(dns_resolvers_report, self.resolv_btn, self.checker, cache_key='dns_resolvers')

    def run_edit_dns(self):
        if not self.checker:
            return
        self.log("Получение текущих DNS-резолверов...")
        self._run_simple(get_current_dns_resolvers, None, self._open_edit_dns_dialog, self.checker)

    def _open_edit_dns_dialog(self, current_ns):
        if isinstance(current_ns, str):
            self.log(current_ns)
            current_ns = []

        self.log(f"=== DNS-резолверы, полученные с сервера: {current_ns}")

        if not current_ns:
            out, _ = self.checker.exec_command('cat /etc/resolv.conf 2>/dev/null')
            self.log("Содержимое /etc/resolv.conf:\n" + out)
            out2, _ = self.checker.exec_command('resolvectl status 2>/dev/null | grep "DNS Servers"')
            if out2.strip():
                self.log("DNS из resolvectl:\n" + out2)
            messagebox.showwarning(
                "DNS не найдены",
                "Не удалось получить текущие DNS-серверы.\n"
                "Проверьте вывод в главном окне."
            )
            return

        dialog = tb.Toplevel(self.root)
        dialog.title("Редактирование DNS-резолверов")
        dialog.geometry("500x400")
        dialog.transient(self.root)
        dialog.grab_set()

        tb.Label(dialog, text="DNS-серверы (нажмите для редактирования):", bootstyle="inverse-secondary").pack(pady=5)

        colors = get_theme_colors(self.current_theme)

        listbox = tk.Listbox(
            dialog,
            selectmode=tk.SINGLE,
            bg=colors['bg'],
            fg=colors['fg'],
            selectbackground='#3465a4'
        )
        listbox.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        for ns in current_ns:
            listbox.insert(tk.END, ns)

        btn_frame = tb.Frame(dialog, bootstyle="secondary")
        btn_frame.pack(fill=tk.X, padx=10, pady=5)

        def add_ns():
            new_ns = simpledialog.askstring("Добавить DNS", "Введите IP-адрес DNS-сервера:", parent=dialog)
            if new_ns and re.match(r'^(\d{1,3}\.){3}\d{1,3}$', new_ns):
                listbox.insert(tk.END, new_ns)
            elif new_ns:
                messagebox.showerror("Ошибка", "Некорректный IP-адрес")

        def edit_ns():
            selection = listbox.curselection()
            if not selection:
                messagebox.showwarning("Нет выбора", "Выберите DNS-сервер для редактирования")
                return
            old = listbox.get(selection[0])
            new = simpledialog.askstring("Редактировать DNS", "Введите новый IP-адрес:", initialvalue=old, parent=dialog)
            if new and re.match(r'^(\d{1,3}\.){3}\d{1,3}$', new):
                listbox.delete(selection[0])
                listbox.insert(selection[0], new)
            elif new:
                messagebox.showerror("Ошибка", "Некорректный IP-адрес")

        def delete_ns():
            selection = listbox.curselection()
            if not selection:
                messagebox.showwarning("Нет выбора", "Выберите DNS-сервер для удаления")
                return
            listbox.delete(selection[0])

        def set_preset(preset_list):
            listbox.delete(0, tk.END)
            for ns in preset_list:
                listbox.insert(tk.END, ns)

        tb.Button(btn_frame, text="Добавить", command=add_ns, bootstyle="success").pack(side=tk.LEFT, padx=2)
        tb.Button(btn_frame, text="Редактировать", command=edit_ns, bootstyle="primary").pack(side=tk.LEFT, padx=2)
        tb.Button(btn_frame, text="Удалить", command=delete_ns, bootstyle="danger").pack(side=tk.LEFT, padx=2)

        preset_frame = tb.Frame(dialog, bootstyle="secondary")
        preset_frame.pack(fill=tk.X, padx=10, pady=5)
        tb.Label(preset_frame, text="Предустановленные наборы:", bootstyle="inverse-secondary").pack(side=tk.LEFT, padx=5)
        tb.Button(preset_frame, text="Google", command=lambda: set_preset(['8.8.8.8', '8.8.4.4']), bootstyle="info").pack(side=tk.LEFT, padx=2)
        tb.Button(preset_frame, text="Cloudflare", command=lambda: set_preset(['1.1.1.1', '1.0.0.1']), bootstyle="info").pack(side=tk.LEFT, padx=2)
        tb.Button(preset_frame, text="OpenDNS", command=lambda: set_preset(['208.67.222.222', '208.67.220.220']), bootstyle="info").pack(side=tk.LEFT, padx=2)

        def apply_changes():
            new_list = []
            for i in range(listbox.size()):
                ns = listbox.get(i)
                if ns.strip():
                    new_list.append(ns.strip())
            if not new_list:
                messagebox.showwarning("Пустой список", "Должен быть хотя бы один DNS-сервер")
                return
            if messagebox.askyesno("Подтверждение", f"Установить DNS:\n{', '.join(new_list)}?", parent=self.root):
                dialog.destroy()
                self._run_in_thread(set_dns_resolvers, self.edit_dns_btn, self.checker, new_list)

        tb.Button(dialog, text="Применить изменения", command=apply_changes, bootstyle="success").pack(pady=10)
        tb.Button(dialog, text="Отмена", command=dialog.destroy, bootstyle="secondary").pack(pady=5)
