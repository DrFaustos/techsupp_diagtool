"""Кнопки диагностики: метрики, сеть, файрвол, веб-конфиг, логи, OOM, SSL/WHOIS/порты/grep, анализ доступа.

Вынесено из gui.py без изменений исходников: константы —, функции —, методы run_full, run_disk_memory, run_network, run_firewall, run_config, run_logs, run_oom_search, _ask_domain, run_ssl_check, run_whois, run_port_scan, run_grep_logs, run_access_analysis, _open_access_dialog."""

import tkinter as tk
from tkinter import messagebox, filedialog, simpledialog, ttk
import ttkbootstrap as tb
from diagnostic import full_diagnostic_report, firewall_report, web_config_report, site_logs_report, disk_memory_report, network_report, analyze_access_log, get_domains, search_oom_logs
from webcheck import (
    ssl_cert_report, whois_report, port_scan_report, grep_logs_report,
)
from ttkbootstrap.constants import *


class ChecksMixin:
    # ---------- ДИАГНОСТИКИ ----------
    def run_full(self):
        def progress_cb(step, total, name):
            self.root.after(0, self.log, f"➡ Этап {step}/{total}: {name}")
        self._run_in_thread(
            full_diagnostic_report, self.full_btn,
            self.checker, self.panel_type,
            progress_cb=progress_cb, cache_key='full'
        )

    def run_disk_memory(self):
        self._run_in_thread(disk_memory_report, self.disk_btn, self.checker, cache_key='disk')

    def run_network(self):
        self._run_in_thread(network_report, self.network_btn, self.checker, cache_key='network')

    def run_firewall(self):
        self._run_in_thread(firewall_report, self.firewall_btn, self.checker, cache_key='firewall')

    def run_config(self):
        self._run_in_thread(web_config_report, self.config_btn, self.checker, cache_key='webconfig')

    def run_logs(self):
        self._run_in_thread(site_logs_report, self.logs_btn, self.checker, self.panel_type, cache_key='logs')

    def run_oom_search(self):
        self._run_in_thread(search_oom_logs, self.oom_btn, self.checker, cache_key='oom')

    # ---------- ДОП. ПРОВЕРКИ (SSL / WHOIS / порты / grep) ----------
    def _ask_domain(self, title):
        domains = []
        try:
            domains = get_domains(self.checker, self.panel_type) or []
        except Exception:
            domains = []
        initial = domains[0] if domains else ""
        value = simpledialog.askstring(title, "Домен:", initialvalue=initial, parent=self.root)
        return (value or "").strip()

    def run_ssl_check(self):
        if not self.checker:
            return
        domain = self._ask_domain("SSL-сертификат")
        if not domain:
            return
        self._run_simple(ssl_cert_report, self.ssl_btn, None, self.checker, domain)

    def run_whois(self):
        if not self.checker:
            return
        domain = self._ask_domain("WHOIS")
        if not domain:
            return
        self._run_simple(whois_report, self.whois_btn, None, self.checker, domain)

    def run_port_scan(self):
        if not self.checker:
            return
        host = self.ip_var.get().strip() or None
        self._run_simple(port_scan_report, self.ports_btn, None, self.checker, host)

    def run_grep_logs(self):
        if not self.checker:
            return
        domain = self._ask_domain("Grep логов")
        if not domain:
            return
        pattern = simpledialog.askstring(
            "Grep логов", "Regex-шаблон (по умолчанию 5xx/404):",
            initialvalue=r'" 5[0-9][0-9] ', parent=self.root
        )
        if pattern is None:
            return
        pattern = pattern.strip() or r'" 5[0-9][0-9] '
        self._run_simple(
            grep_logs_report, self.grep_btn, None,
            self.checker, self.panel_type, domain, pattern
        )

    # ---------- АНАЛИЗ ЛОГОВ ДОСТУПА ----------
    def run_access_analysis(self):
        if not self.checker:
            return

        # get_domains делает SSH-вызовы — грузим его в фоне, диалог откроем по готовности
        self.log("Получение списка доменов...")
        self._run_simple(
            get_domains, None, self._open_access_dialog,
            self.checker, self.panel_type
        )

    def _open_access_dialog(self, domains):
        if isinstance(domains, str):
            # пришла строка ошибки
            self.log(domains)
            domains = []

        domain_var = tk.StringVar()
        if domains:
            domain_var.set(domains[0])

        dialog = tb.Toplevel(self.root)
        dialog.title("Анализ логов доступа")
        dialog.geometry("520x360")
        dialog.transient(self.root)
        dialog.grab_set()

        row = 0
        tb.Label(dialog, text="Домен:", bootstyle="inverse-secondary").grid(
            row=row, column=0, sticky='e', padx=5, pady=5
        )
        domain_combo = ttk.Combobox(
            dialog, textvariable=domain_var, values=domains, state='normal'
        )
        domain_combo.grid(row=row, column=1, columnspan=3, padx=5, pady=5, sticky='ew')
        if not domains:
            domain_combo.set('')
        row += 1

        tb.Label(dialog, text="Топ-Х:", bootstyle="inverse-secondary").grid(
            row=row, column=0, sticky='e', padx=5, pady=5
        )
        top_var = tk.StringVar(value="10")
        tb.Entry(dialog, textvariable=top_var, width=10).grid(
            row=row, column=1, sticky='w', padx=5, pady=5
        )
        row += 1

        tb.Label(dialog, text="Фильтр по дате (опционально):", bootstyle="inverse-secondary").grid(
            row=row, column=0, sticky='e', padx=5, pady=5
        )
        year_var = tk.StringVar()
        month_var = tk.StringVar()
        day_var = tk.StringVar()
        frame_date = tb.Frame(dialog, bootstyle="secondary")
        frame_date.grid(row=row, column=1, columnspan=3, sticky='w', padx=5, pady=5)
        tb.Entry(frame_date, textvariable=year_var, width=5).pack(side='left', padx=2)
        tb.Label(frame_date, text="ГГГГ", bootstyle="inverse-secondary").pack(side='left', padx=2)
        tb.Entry(frame_date, textvariable=month_var, width=3).pack(side='left', padx=2)
        tb.Label(frame_date, text="ММ", bootstyle="inverse-secondary").pack(side='left', padx=2)
        tb.Entry(frame_date, textvariable=day_var, width=3).pack(side='left', padx=2)
        tb.Label(frame_date, text="ДД", bootstyle="inverse-secondary").pack(side='left', padx=2)
        row += 1

        last_result = [None]
        status_var = tk.StringVar(value="Готово к анализу")

        tb.Label(dialog, textvariable=status_var, bootstyle="inverse-secondary").grid(
            row=row, column=0, columnspan=4, sticky='w', padx=5
        )
        row += 1

        btn_frame = tb.Frame(dialog, bootstyle="secondary")
        btn_frame.grid(row=row, column=0, columnspan=4, pady=10)

        analyze_btn = tb.Button(btn_frame, text="Анализировать", bootstyle="success")
        analyze_btn.pack(side='left', padx=5)
        save_btn = tb.Button(btn_frame, text="Сохранить отчёт", bootstyle="primary", state=tk.DISABLED)
        save_btn.pack(side='left', padx=5)

        def on_save():
            if last_result[0] is None:
                messagebox.showwarning("Нет данных", "Сначала выполните анализ, чтобы сохранить отчёт.")
                return
            filename = filedialog.asksaveasfilename(
                defaultextension=".txt",
                filetypes=[("Text files", "*.txt"), ("All files", "*.*")],
                parent=dialog
            )
            if filename:
                try:
                    with open(filename, 'w', encoding='utf-8') as f:
                        f.write(last_result[0])
                    messagebox.showinfo("Успех", f"Отчёт сохранён в {filename}", parent=dialog)
                except Exception as e:
                    messagebox.showerror("Ошибка", f"Не удалось сохранить файл: {e}", parent=dialog)

        save_btn.config(command=on_save)

        def on_analyze():
            domain = domain_var.get().strip()
            if not domain:
                messagebox.showerror("Ошибка", "Введите домен", parent=dialog)
                return
            try:
                top_n = int(top_var.get().strip() or 10)
            except ValueError:
                top_n = 10
            try:
                year = int(year_var.get()) if year_var.get().strip() else None
                month = int(month_var.get()) if month_var.get().strip() else None
                day = int(day_var.get()) if day_var.get().strip() else None
            except ValueError:
                messagebox.showerror("Ошибка", "Дата должна быть числом", parent=dialog)
                return

            for val, name in [(year, 'год'), (month, 'месяц'), (day, 'день')]:
                if val is not None and not (
                    1 <= val <= 9999 if name == 'год' else
                    (1 <= val <= 12 if name == 'месяц' else 1 <= val <= 31)
                ):
                    messagebox.showerror("Ошибка", f"Некорректное значение для {name}", parent=dialog)
                    return

            # Диалог НЕ закрываем — чтобы осталась доступна кнопка «Сохранить отчёт».
            status_var.set("Анализ выполняется...")
            analyze_btn.config(state=tk.DISABLED)
            save_btn.config(state=tk.DISABLED)

            def on_done(result):
                last_result[0] = result
                status_var.set("Анализ завершён — можно сохранить отчёт")
                analyze_btn.config(state=tk.NORMAL)
                save_btn.config(state=tk.NORMAL)
                self._display_result(result)

            self._run_simple(
                analyze_access_log, None, on_done,
                self.checker, self.panel_type, domain, top_n, year, month, day
            )

        analyze_btn.config(command=on_analyze)

        dialog.columnconfigure(1, weight=1)
        dialog.columnconfigure(2, weight=1)
        dialog.columnconfigure(3, weight=1)
