import tkinter as tk
from tkinter import messagebox, filedialog, scrolledtext, simpledialog, ttk
import ttkbootstrap as tb
from ttkbootstrap.constants import *
import threading
import re
import os
import subprocess
from diagnostic import (
    detect_panel, full_diagnostic_report,
    metrics_report, firewall_report,
    web_config_report, site_logs_report,
    disk_memory_report, network_report,
    analyze_access_log, get_domains,
    search_oom_logs, dns_report, dns_report_local,
    dns_resolvers_report,
    get_current_dns_resolvers,
    set_dns_resolvers,
    replace_ipv4,
    replace_ipv6,
    restart_services,
    get_config_files,
    read_file,
    write_file,
    ispmanager_restart,
    ispmanager_kill_core,
    ispmanager_update,
    ispmanager_ssl_issue,
    ispmanager_disable,
    ispmanager_disable_geoip,
    ispmanager_check_cron_path,
    ispmanager_fix_cron_path
)
from ssh_client import ServerChecker


# ==================== НАСТРОЙКИ ТЕМ ====================
DARK_THEMES = ['darkly', 'cyborg', 'superhero', 'vapor', 'solar']
LIGHT_THEMES = ['flatly', 'litera', 'minty', 'pulse', 'cosmo', 'sandstone']

def get_theme_colors(theme_name):
    """Возвращает цвета для поля вывода в зависимости от темы"""
    if theme_name in DARK_THEMES:
        return {
            'bg': '#1a1a1a',
            'fg': '#d3d7cf',
            'insertbackground': 'white',
            'selectbackground': '#3465a4'
        }
    else:
        return {
            'bg': '#ffffff',
            'fg': '#000000',
            'insertbackground': 'black',
            'selectbackground': '#3465a4'
        }

def detect_system_theme():
    """
    Определяет тему ОС (Linux/GNOME) и возвращает имя темы для ttkbootstrap.
    """
    try:
        result = subprocess.run(
            ['gsettings', 'get', 'org.gnome.desktop.interface', 'gtk-theme'],
            capture_output=True, text=True, timeout=2
        )
        if result.returncode == 0:
            theme = result.stdout.strip().strip("'")
            if 'dark' in theme.lower() or 'black' in theme.lower():
                return 'darkly'
            else:
                return 'flatly'
    except Exception:
        pass
    return 'darkly'


class DiagnosticApp:
    def __init__(self):
        initial_theme = detect_system_theme()
        self.root = tb.Window(themename=initial_theme)
        self.root.title("SSH Диагностика сервера")
        self.root.geometry("1100x720")
        self.root.minsize(1000, 650)

        self.ip_var = tk.StringVar()
        self.port_var = tk.StringVar(value="22")
        self.user_var = tk.StringVar(value="root")
        self.password_var = tk.StringVar()
        self.key_var = tk.StringVar(value="~/.ssh/id_rsa")
        self.panel_var = tk.StringVar(value="auto")

        self.checker = None
        self.panel_type = None

        self.cmd_history = []
        self.history_index = -1

        self.create_widgets()
        self.cmd_entry.focus_set()

    def update_output_colors(self, theme_name=None):
        if theme_name is None:
            theme_name = self.root.style.theme.name
        colors = get_theme_colors(theme_name)
        self.output.config(
            bg=colors['bg'],
            fg=colors['fg'],
            insertbackground=colors['insertbackground'],
            selectbackground=colors['selectbackground']
        )

    def switch_theme(self, theme_name):
        try:
            self.root.style.theme_use(theme_name)
            self.update_output_colors(theme_name)
            self.current_theme = theme_name
        except Exception as e:
            messagebox.showerror("Ошибка", f"Не удалось переключить тему: {e}")

    def create_widgets(self):
        top_frame = tb.Frame(self.root, bootstyle="secondary")
        top_frame.pack(fill=tk.X, padx=10, pady=5)

        # IP
        tb.Label(top_frame, text="IP:", bootstyle="inverse-secondary").grid(
            row=0, column=0, sticky='e', padx=5
        )
        self.ip_entry = tb.Entry(top_frame, textvariable=self.ip_var, width=15)
        self.ip_entry.grid(row=0, column=1, padx=5)

        # Порт
        tb.Label(top_frame, text="Порт:", bootstyle="inverse-secondary").grid(
            row=0, column=2, sticky='e', padx=5
        )
        tb.Entry(top_frame, textvariable=self.port_var, width=6).grid(
            row=0, column=3, padx=5
        )

        # Пользователь
        tb.Label(top_frame, text="Пользователь:", bootstyle="inverse-secondary").grid(
            row=0, column=4, sticky='e', padx=5
        )
        tb.Entry(top_frame, textvariable=self.user_var, width=12).grid(
            row=0, column=5, padx=5
        )

        # Пароль
        tb.Label(top_frame, text="Пароль:", bootstyle="inverse-secondary").grid(
            row=0, column=6, sticky='e', padx=5
        )
        tb.Entry(top_frame, textvariable=self.password_var, show="*", width=12).grid(
            row=0, column=7, padx=5
        )

        # Ключ
        tb.Label(top_frame, text="Ключ:", bootstyle="inverse-secondary").grid(
            row=1, column=0, sticky='e', padx=5
        )
        tb.Entry(top_frame, textvariable=self.key_var, width=30).grid(
            row=1, column=1, columnspan=6, sticky='ew', padx=5
        )
        tb.Button(
            top_frame,
            text="Обзор",
            command=self.browse_key,
            bootstyle="secondary-outline"
        ).grid(row=1, column=7, padx=5)

        # Тип панели
        tb.Label(top_frame, text="Панель:", bootstyle="inverse-secondary").grid(
            row=2, column=0, sticky='e', padx=5
        )
        panel_frame = tb.Frame(top_frame, bootstyle="secondary")
        panel_frame.grid(row=2, column=1, columnspan=4, sticky='w', padx=5)

        for text, value in [
            ("Авто", "auto"),
            ("FastPanel", "fastpanel"),
            ("ISPmanager", "ispmanager"),
            ("Нет", "none")
        ]:
            rb = tb.Radiobutton(
                panel_frame,
                text=text,
                variable=self.panel_var,
                value=value,
                bootstyle="secondary-outline-toolbutton"
            )
            rb.pack(side='left', padx=5)

        # Кнопки диагностики (первый ряд)
        btn_frame = tb.Frame(self.root, bootstyle="secondary")
        btn_frame.pack(fill=tk.X, padx=10, pady=5)

        # Подключение
        self.connect_btn = tb.Button(
            btn_frame,
            text="Подключиться",
            command=self.connect,
            bootstyle="success"
        )
        self.connect_btn.pack(side=tk.LEFT, padx=5)

        # Основные кнопки (используем solid для лучшей видимости)
        self.full_btn = tb.Button(
            btn_frame,
            text="Полная диагностика",
            command=self.run_full,
            state=tk.DISABLED,
            bootstyle="secondary"
        )
        self.full_btn.pack(side=tk.LEFT, padx=5)

        self.disk_btn = tb.Button(
            btn_frame,
            text="Диски и память",
            command=self.run_disk_memory,
            state=tk.DISABLED,
            bootstyle="secondary"
        )
        self.disk_btn.pack(side=tk.LEFT, padx=5)

        self.network_btn = tb.Button(
            btn_frame,
            text="Сеть",
            command=self.run_network,
            state=tk.DISABLED,
            bootstyle="secondary"
        )
        self.network_btn.pack(side=tk.LEFT, padx=5)

        self.firewall_btn = tb.Button(
            btn_frame,
            text="Фаервол",
            command=self.run_firewall,
            state=tk.DISABLED,
            bootstyle="secondary"
        )
        self.firewall_btn.pack(side=tk.LEFT, padx=5)

        self.config_btn = tb.Button(
            btn_frame,
            text="Конфиги веб",
            command=self.run_config,
            state=tk.DISABLED,
            bootstyle="secondary"
        )
        self.config_btn.pack(side=tk.LEFT, padx=5)

        self.logs_btn = tb.Button(
            btn_frame,
            text="Логи сайтов",
            command=self.run_logs,
            state=tk.DISABLED,
            bootstyle="secondary"
        )
        self.logs_btn.pack(side=tk.LEFT, padx=5)

        self.access_btn = tb.Button(
            btn_frame,
            text="Анализ логов доступа",
            command=self.run_access_analysis,
            state=tk.DISABLED,
            bootstyle="secondary"
        )
        self.access_btn.pack(side=tk.LEFT, padx=5)

        self.oom_btn = tb.Button(
            btn_frame,
            text="Поиск OOM",
            command=self.run_oom_search,
            state=tk.DISABLED,
            bootstyle="secondary"
        )
        self.oom_btn.pack(side=tk.LEFT, padx=5)

        self.dns_btn = tb.Button(
            btn_frame,
            text="DNS-проверка",
            command=self.run_dns_check,
            state=tk.DISABLED,
            bootstyle="secondary"
        )
        self.dns_btn.pack(side=tk.LEFT, padx=5)

        self.resolv_btn = tb.Button(
            btn_frame,
            text="DNS-резолверы",
            command=self.run_dns_resolvers,
            state=tk.DISABLED,
            bootstyle="secondary"
        )
        self.resolv_btn.pack(side=tk.LEFT, padx=5)

        self.edit_dns_btn = tb.Button(
            btn_frame,
            text="Изменить DNS",
            command=self.run_edit_dns,
            state=tk.DISABLED,
            bootstyle="secondary"
        )
        self.edit_dns_btn.pack(side=tk.LEFT, padx=5)

        self.ipv4_btn = tb.Button(
            btn_frame,
            text="Заменить IPv4",
            command=self.run_replace_ipv4,
            state=tk.DISABLED,
            bootstyle="secondary"
        )
        self.ipv4_btn.pack(side=tk.LEFT, padx=5)

        self.ipv6_btn = tb.Button(
            btn_frame,
            text="Заменить IPv6",
            command=self.run_replace_ipv6,
            state=tk.DISABLED,
            bootstyle="secondary"
        )
        self.ipv6_btn.pack(side=tk.LEFT, padx=5)

        self.restart_btn = tb.Button(
            btn_frame,
            text="Перезапустить службы",
            command=self.run_restart_services,
            state=tk.DISABLED,
            bootstyle="secondary"
        )
        self.restart_btn.pack(side=tk.LEFT, padx=5)

        self.config_editor_btn = tb.Button(
            btn_frame,
            text="Редактор конфигов",
            command=self.run_config_editor,
            state=tk.DISABLED,
            bootstyle="secondary"
        )
        self.config_editor_btn.pack(side=tk.LEFT, padx=5)

        # ---------- ПЕРЕКЛЮЧАТЕЛЬ ТЕМ ----------
        theme_frame = tb.Frame(btn_frame, bootstyle="secondary")
        theme_frame.pack(side=tk.RIGHT, padx=10)

        tb.Label(theme_frame, text="Тема:", bootstyle="inverse-secondary").pack(side=tk.LEFT, padx=5)

        available_themes = DARK_THEMES + LIGHT_THEMES
        self.theme_var = tk.StringVar(value=detect_system_theme())

        theme_combo = ttk.Combobox(
            theme_frame,
            textvariable=self.theme_var,
            values=available_themes,
            state='readonly',
            width=12
        )
        theme_combo.pack(side=tk.LEFT, padx=5)
        theme_combo.bind('<<ComboboxSelected>>', lambda e: self.switch_theme(self.theme_var.get()))

        self.toggle_theme_btn = tb.Button(
            theme_frame,
            text="🌓",
            command=self.toggle_theme,
            bootstyle="secondary",
            width=3
        )
        self.toggle_theme_btn.pack(side=tk.LEFT, padx=5)

        # ---------- КНОПКИ ISPmanager ----------
        self.ispmanager_frame = tb.Frame(btn_frame, bootstyle="secondary")
        self.ispmanager_frame.pack(side=tk.LEFT, padx=5)
        self.ispmanager_frame.pack_forget()

        self.isp_restart_btn = tb.Button(
            self.ispmanager_frame,
            text="Перезапустить панель",
            command=self.run_isp_restart,
            state=tk.DISABLED,
            bootstyle="warning"
        )
        self.isp_restart_btn.pack(side=tk.LEFT, padx=2)

        self.isp_kill_btn = tb.Button(
            self.ispmanager_frame,
            text="Kill core",
            command=self.run_isp_kill,
            state=tk.DISABLED,
            bootstyle="danger"
        )
        self.isp_kill_btn.pack(side=tk.LEFT, padx=2)

        self.isp_update_btn = tb.Button(
            self.ispmanager_frame,
            text="Обновить панель",
            command=self.run_isp_update,
            state=tk.DISABLED,
            bootstyle="info"
        )
        self.isp_update_btn.pack(side=tk.LEFT, padx=2)

        self.isp_ssl_btn = tb.Button(
            self.ispmanager_frame,
            text="Выпуск SSL",
            command=self.run_isp_ssl,
            state=tk.DISABLED,
            bootstyle="primary"
        )
        self.isp_ssl_btn.pack(side=tk.LEFT, padx=2)

        self.isp_disable_btn = tb.Button(
            self.ispmanager_frame,
            text="Отключить панель",
            command=self.run_isp_disable,
            state=tk.DISABLED,
            bootstyle="danger"
        )
        self.isp_disable_btn.pack(side=tk.LEFT, padx=2)

        self.isp_geoip_btn = tb.Button(
            self.ispmanager_frame,
            text="Отключить GeoIP",
            command=self.run_isp_geoip,
            state=tk.DISABLED,
            bootstyle="secondary"
        )
        self.isp_geoip_btn.pack(side=tk.LEFT, padx=2)

        self.isp_cron_btn = tb.Button(
            self.ispmanager_frame,
            text="Проверить CRON",
            command=self.run_isp_cron,
            state=tk.DISABLED,
            bootstyle="secondary"
        )
        self.isp_cron_btn.pack(side=tk.LEFT, padx=2)

        self.isp_fix_cron_btn = tb.Button(
            self.ispmanager_frame,
            text="Исправить CRON",
            command=self.run_isp_fix_cron,
            state=tk.DISABLED,
            bootstyle="warning"
        )
        self.isp_fix_cron_btn.pack(side=tk.LEFT, padx=2)

        # ---------- КНОПКИ SWAP ----------
        swap_frame = tb.Frame(self.root, bootstyle="secondary")
        swap_frame.pack(fill=tk.X, padx=10, pady=5)

        self.swap_btn = tb.Button(
            swap_frame,
            text="Создать swap файл",
            command=self.create_swap,
            state=tk.DISABLED,
            bootstyle="secondary"
        )
        self.swap_btn.pack(side=tk.LEFT, padx=5)

        self.fstab_btn = tb.Button(
            swap_frame,
            text="Прописать swap в fstab",
            command=self.add_swap_to_fstab,
            state=tk.DISABLED,
            bootstyle="secondary"
        )
        self.fstab_btn.pack(side=tk.LEFT, padx=5)

        # ---------- ПРОГРЕСС-БАР ----------
        self.progress = tb.Progressbar(
            self.root,
            bootstyle="info-striped",
            mode='indeterminate',
            length=200
        )
        self.progress.pack(pady=5)
        self.progress.pack_forget()

        # ---------- ТЕКСТОВОЕ ПОЛЕ ВЫВОДА ----------
        self.output = scrolledtext.ScrolledText(
            self.root,
            wrap=tk.WORD,
            font=("Courier", 10)
        )
        self.output.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        self.update_output_colors(initial_theme)

        # ---------- ИНТЕРАКТИВНЫЙ ТЕРМИНАЛ ----------
        cmd_frame = tb.Frame(self.root, bootstyle="secondary")
        cmd_frame.pack(fill=tk.X, padx=10, pady=5)

        tb.Label(cmd_frame, text="Команда:", bootstyle="inverse-secondary").pack(
            side=tk.LEFT, padx=5
        )
        self.cmd_entry = tb.Entry(cmd_frame)
        self.cmd_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)
        self.cmd_entry.bind("<Return>", self.send_command)
        self.cmd_entry.bind("<Up>", self.history_up)
        self.cmd_entry.bind("<Down>", self.history_down)
        self.cmd_entry.bind("<Tab>", self.autocomplete)  # Добавляем автодополнение

        self.send_btn = tb.Button(
            cmd_frame,
            text="Send",
            command=self.send_command,
            state=tk.DISABLED,
            bootstyle="primary"
        )
        self.send_btn.pack(side=tk.LEFT, padx=5)

        self.history_btn = tb.Button(
            cmd_frame,
            text="История",
            command=self.show_bash_history,
            bootstyle="secondary"
        )
        self.history_btn.pack(side=tk.LEFT, padx=5)

        self.log("Ожидание подключения...")

    # ---------- АВТОДОПОЛНЕНИЕ ----------
    def autocomplete(self, event):
        """Простое автодополнение по истории команд при нажатии Tab"""
        current = self.cmd_entry.get()
        if not current:
            return "break"
        matches = [cmd for cmd in self.cmd_history if cmd.startswith(current)]
        if matches:
            # Подставляем первое совпадение
            self.cmd_entry.delete(0, tk.END)
            self.cmd_entry.insert(0, matches[0])
        return "break"

    def toggle_theme(self):
        current_theme = self.root.style.theme.name
        if current_theme in DARK_THEMES:
            new_theme = 'flatly'
        else:
            new_theme = 'darkly'
        self.switch_theme(new_theme)
        self.theme_var.set(new_theme)

    def browse_key(self):
        filename = filedialog.askopenfilename()
        if filename:
            self.key_var.set(filename)

    def log(self, text):
        self.output.insert(tk.END, text + "\n")
        self.output.see(tk.END)

    def history_up(self, event):
        if self.history_index > 0:
            self.history_index -= 1
            self.cmd_entry.delete(0, tk.END)
            self.cmd_entry.insert(0, self.cmd_history[self.history_index])
        return "break"

    def history_down(self, event):
        if self.history_index < len(self.cmd_history) - 1:
            self.history_index += 1
            self.cmd_entry.delete(0, tk.END)
            self.cmd_entry.insert(0, self.cmd_history[self.history_index])
        else:
            self.history_index = len(self.cmd_history)
            self.cmd_entry.delete(0, tk.END)
        return "break"

    def connect(self):
        ip = self.ip_var.get().strip()
        if not ip:
            messagebox.showerror("Ошибка", "Введите IP адрес")
            return
        try:
            port = int(self.port_var.get().strip())
        except ValueError:
            port = 22
        user = self.user_var.get().strip() or "root"
        password = self.password_var.get().strip()
        key_path = self.key_var.get().strip()

        self.log(f"\n=== Подключение к {ip}:{port} ...")
        self.checker = ServerChecker(ip, port, user, password, key_path)
        success, message = self.checker.connect()

        if not success:
            self.log(f"❌ {message}")
            self.checker = None
            return

        self.log(f"✅ {message}")

        if self.panel_var.get() == 'auto':
            self.panel_type = detect_panel(self.checker)
        else:
            self.panel_type = self.panel_var.get()

        self.log(f"Панель управления: {self.panel_type}")

        # Активируем кнопки
        self.full_btn.config(state=tk.NORMAL)
        self.disk_btn.config(state=tk.NORMAL)
        self.network_btn.config(state=tk.NORMAL)
        self.firewall_btn.config(state=tk.NORMAL)
        self.config_btn.config(state=tk.NORMAL)
        self.logs_btn.config(state=tk.NORMAL)
        self.access_btn.config(state=tk.NORMAL)
        self.oom_btn.config(state=tk.NORMAL)
        self.dns_btn.config(state=tk.NORMAL)
        self.resolv_btn.config(state=tk.NORMAL)
        self.edit_dns_btn.config(state=tk.NORMAL)
        self.ipv4_btn.config(state=tk.NORMAL)
        self.ipv6_btn.config(state=tk.NORMAL)
        self.restart_btn.config(state=tk.NORMAL)
        self.config_editor_btn.config(state=tk.NORMAL)
        self.swap_btn.config(state=tk.NORMAL)
        self.fstab_btn.config(state=tk.NORMAL)
        self.send_btn.config(state=tk.NORMAL)

        # ISPmanager кнопки
        if self.panel_type == 'ispmanager':
            self.ispmanager_frame.pack(side=tk.LEFT, padx=5)
            for btn in [
                self.isp_restart_btn, self.isp_kill_btn, self.isp_update_btn,
                self.isp_ssl_btn, self.isp_disable_btn, self.isp_geoip_btn,
                self.isp_cron_btn, self.isp_fix_cron_btn
            ]:
                btn.config(state=tk.NORMAL)
        else:
            self.ispmanager_frame.pack_forget()
            for btn in [
                self.isp_restart_btn, self.isp_kill_btn, self.isp_update_btn,
                self.isp_ssl_btn, self.isp_disable_btn, self.isp_geoip_btn,
                self.isp_cron_btn, self.isp_fix_cron_btn
            ]:
                btn.config(state=tk.DISABLED)

        self.connect_btn.config(text="Отключиться", bootstyle="danger", command=self.disconnect)
        self.cmd_entry.focus_set()

    # ---------- ФОНОВЫЕ ЗАДАЧИ ----------
    def _run_in_thread(self, target_func, btn=None, *args, **kwargs):
        if not self.checker:
            return
        if btn:
            btn.config(state=tk.DISABLED, text="Выполняется...")
        self.progress.pack(pady=5)
        self.progress.start(10)

        def wrapper():
            try:
                result = target_func(*args, **kwargs)
                self.root.after(0, self._display_result, result)
            except Exception as e:
                self.root.after(0, self._display_result, f"❌ Ошибка: {str(e)}")
            finally:
                self.root.after(0, self._stop_progress)
                if btn:
                    original_text = btn.cget('text').replace(' (Выполняется...)', '')
                    self.root.after(0, lambda: btn.config(state=tk.NORMAL, text=original_text))

        thread = threading.Thread(target=wrapper)
        thread.daemon = True
        thread.start()

    def _stop_progress(self):
        self.progress.stop()
        self.progress.pack_forget()

    def _display_result(self, text):
        self.log("\n" + "="*60)
        self.log(text)

    # ---------- ДИАГНОСТИКИ ----------
    def run_full(self):
        self._run_in_thread(full_diagnostic_report, self.full_btn, self.checker, self.panel_type)

    def run_disk_memory(self):
        self._run_in_thread(disk_memory_report, self.disk_btn, self.checker)

    def run_network(self):
        self._run_in_thread(network_report, self.network_btn, self.checker)

    def run_firewall(self):
        self._run_in_thread(firewall_report, self.firewall_btn, self.checker)

    def run_config(self):
        self._run_in_thread(web_config_report, self.config_btn, self.checker)

    def run_logs(self):
        self._run_in_thread(site_logs_report, self.logs_btn, self.checker, self.panel_type)

    def run_oom_search(self):
        self._run_in_thread(search_oom_logs, self.oom_btn, self.checker)

    # ---------- АНАЛИЗ ЛОГОВ ДОСТУПА ----------
    def run_access_analysis(self):
        if not self.checker:
            return

        domains = get_domains(self.checker, self.panel_type)
        domain_var = tk.StringVar()
        if domains:
            domain_var.set(domains[0])

        # Исправление ошибки Toplevel
        dialog = tb.Toplevel(self.root)
        dialog.title("Анализ логов доступа")
        dialog.geometry("500x320")
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

        def on_analyze():
            domain = domain_var.get().strip()
            if not domain:
                messagebox.showerror("Ошибка", "Введите домен")
                return
            try:
                top_n = int(top_var.get().strip() or 10)
            except ValueError:
                top_n = 10
            year = int(year_var.get()) if year_var.get().strip() else None
            month = int(month_var.get()) if month_var.get().strip() else None
            day = int(day_var.get()) if day_var.get().strip() else None

            for val, name in [(year, 'год'), (month, 'месяц'), (day, 'день')]:
                if val is not None and not (
                    1 <= val <= 9999 if name == 'год' else
                    (1 <= val <= 12 if name == 'месяц' else 1 <= val <= 31)
                ):
                    messagebox.showerror("Ошибка", f"Некорректное значение для {name}")
                    return

            dialog.destroy()
            self._run_in_thread(
                analyze_access_log, self.access_btn,
                self.checker, self.panel_type, domain, top_n, year, month, day
            )

        def on_save():
            if last_result[0] is None:
                messagebox.showwarning("Нет данных", "Сначала выполните анализ, чтобы сохранить отчёт.")
                return
            filename = filedialog.asksaveasfilename(
                defaultextension=".txt",
                filetypes=[("Text files", "*.txt"), ("All files", "*.*")]
            )
            if filename:
                try:
                    with open(filename, 'w', encoding='utf-8') as f:
                        f.write(last_result[0])
                    messagebox.showinfo("Успех", f"Отчёт сохранён в {filename}")
                except Exception as e:
                    messagebox.showerror("Ошибка", f"Не удалось сохранить файл: {e}")

        btn_frame = tb.Frame(dialog, bootstyle="secondary")
        btn_frame.grid(row=row, column=0, columnspan=4, pady=10)
        tb.Button(btn_frame, text="Анализировать", command=on_analyze, bootstyle="success").pack(side='left', padx=5)
        tb.Button(btn_frame, text="Сохранить отчёт", command=on_save, bootstyle="primary").pack(side='left', padx=5)

        dialog.columnconfigure(1, weight=1)
        dialog.columnconfigure(2, weight=1)
        dialog.columnconfigure(3, weight=1)

    # ---------- ОСТАЛЬНЫЕ ФУНКЦИИ ----------
    def create_swap(self):
        if not self.checker:
            return
        size = simpledialog.askstring(
            "Размер swap",
            "Введите размер swap файла в МБ (например, 1024):",
            parent=self.root
        )
        if not size:
            return
        try:
            size_mb = int(size)
        except ValueError:
            messagebox.showerror("Ошибка", "Введите целое число")
            return

        self.log(f"\n=== Создание swap файла размером {size_mb} МБ ===")
        cmd = f"df -m / | awk 'NR==2 {{print $4}}'"
        out, _ = self.checker.exec_command(cmd)
        free_mb = int(out.strip()) if out.strip().isdigit() else 0
        if free_mb < size_mb + 100:
            self.log(f"❌ Недостаточно свободного места (доступно {free_mb} МБ, требуется ~{size_mb+100} МБ)")
            return

        cmds = [
            f"fallocate -l {size_mb}M /swapfile 2>/dev/null || dd if=/dev/zero of=/swapfile bs=1M count={size_mb}",
            "chmod 600 /swapfile",
            "mkswap /swapfile",
            "swapon /swapfile"
        ]
        for c in cmds:
            out, err = self.checker.exec_command(c)
            self.log(f"$ {c}")
            if out.strip():
                self.log(out.strip())
            if err.strip():
                self.log("STDERR: " + err.strip())

        out, _ = self.checker.exec_command("swapon --show")
        self.log("Текущие swap-разделы:\n" + out)

    def add_swap_to_fstab(self):
        if not self.checker:
            return
        self.log("\n=== Добавление /swapfile в /etc/fstab ===")
        out, _ = self.checker.exec_command("grep -q '/swapfile' /etc/fstab && echo 'yes' || echo 'no'")
        if out.strip() == 'yes':
            self.log("Запись /swapfile уже присутствует в fstab.")
            return

        cmd = 'echo "/swapfile none swap sw 0 0" >> /etc/fstab'
        out, err = self.checker.exec_command(cmd)
        self.log(f"$ {cmd}")
        if out.strip():
            self.log(out.strip())
        if err.strip():
            self.log("STDERR: " + err.strip())
        out, _ = self.checker.exec_command("tail -3 /etc/fstab")
        self.log("Последние строки /etc/fstab:\n" + out)

    def run_dns_check(self):
        if not self.checker:
            return
        domains = get_domains(self.checker, self.panel_type)
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
            dialog.destroy()
            self.log("\n" + "="*60)
            if local_var.get():
                result = dns_report_local(domain)
            else:
                result = dns_report(self.checker, domain)
            self.log(result)

        tb.Button(dialog, text="Проверить", command=on_check, bootstyle="success").grid(
            row=2, column=0, columnspan=2, pady=10
        )
        dialog.columnconfigure(1, weight=1)

    def run_dns_resolvers(self):
        if not self.checker:
            return
        self._run_in_thread(dns_resolvers_report, self.resolv_btn, self.checker)

    def run_edit_dns(self):
        if not self.checker:
            return
        current_ns = get_current_dns_resolvers(self.checker)

        dialog = tb.Toplevel(self.root)
        dialog.title("Редактирование DNS-резолверов")
        dialog.geometry("500x400")
        dialog.transient(self.root)
        dialog.grab_set()

        tb.Label(dialog, text="DNS-серверы (нажмите для редактирования):", bootstyle="inverse-secondary").pack(pady=5)

        listbox = tk.Listbox(
            dialog,
            selectmode=tk.SINGLE,
            bg=self.root.cget('bg'),
            fg=self.root.cget('fg'),
            selectbackground=self.root.style.colors.get('primary')
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

    def run_replace_ipv6(self):
        if not self.checker:
            return
        old_ip = simpledialog.askstring("Замена IPv6", "Введите старый IPv6-адрес (который нужно заменить):", parent=self.root)
        if not old_ip:
            return
        new_ip = simpledialog.askstring("Замена IPv6", f"Введите новый IPv6-адрес (вместо {old_ip}):", parent=self.root)
        if not new_ip:
            return

        if messagebox.askyesno(
            "Подтверждение",
            f"Заменить {old_ip} на {new_ip} во всех файлах в /etc?\n\nБудут перезапущены nginx, mysql, apache.",
            parent=self.root
        ):
            self._run_in_thread(replace_ipv6, self.ipv6_btn, self.checker, old_ip, new_ip)

    def run_restart_services(self):
        if not self.checker:
            return
        if messagebox.askyesno("Подтверждение", "Перезапустить nginx, mysql, apache?", parent=self.root):
            self._run_in_thread(restart_services, self.restart_btn, self.checker)

    def get_bash_history(self):
        if not self.checker:
            return []
        out, _ = self.checker.exec_command('cat ~/.bash_history 2>/dev/null | tail -100')
        if out.strip():
            return [line.strip() for line in out.splitlines() if line.strip()]
        return []

    def show_bash_history(self):
        if not self.checker:
            return
        history = self.get_bash_history()
        if not history:
            messagebox.showinfo("История команд", "История команд не найдена или пуста.")
            return

        dialog = tb.Toplevel(self.root)
        dialog.title("Bash История команд")
        dialog.geometry("600x400")
        dialog.transient(self.root)
        dialog.grab_set()

        text = scrolledtext.ScrolledText(dialog, wrap=tk.NONE, font=("Courier", 10))
        text.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        text.insert(tk.END, "\n".join(history))
        text.config(state=tk.DISABLED)

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

        def load_file():
            filepath = file_var.get().strip()
            if not filepath:
                messagebox.showwarning("Внимание", "Выберите файл")
                return
            text_editor.config(state=tk.DISABLED)
            self.root.update()
            content = read_file(self.checker, filepath)
            text_editor.delete(1.0, tk.END)
            text_editor.insert(tk.END, content)
            text_editor.config(state=tk.NORMAL)
            current_filepath[0] = filepath

        load_btn = tb.Button(top_frame, text="Загрузить", command=load_file, bootstyle="primary")
        load_btn.pack(side=tk.LEFT, padx=5)

        editor_frame = tb.Frame(editor_dialog, bootstyle="secondary")
        editor_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)

        text_editor = scrolledtext.ScrolledText(editor_frame, wrap=tk.NONE, font=("Courier", 10))
        text_editor.pack(fill=tk.BOTH, expand=True)

        current_filepath = [""]

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
                self.root.update()
                result = write_file(self.checker, filepath, content)
                self._display_result(result)
                text_editor.config(state=tk.NORMAL)
                messagebox.showinfo("Успех", "Файл сохранён")

        def reload_file():
            filepath = current_filepath[0]
            if not filepath:
                messagebox.showwarning("Внимание", "Сначала загрузите файл")
                return
            text_editor.config(state=tk.DISABLED)
            self.root.update()
            content = read_file(self.checker, filepath)
            text_editor.delete(1.0, tk.END)
            text_editor.insert(tk.END, content)
            text_editor.config(state=tk.NORMAL)

        def close_editor():
            if text_editor.get(1.0, tk.END).strip():
                if messagebox.askyesno("Подтверждение", "Закрыть редактор без сохранения изменений?", parent=editor_dialog):
                    editor_dialog.destroy()
            else:
                editor_dialog.destroy()

        tb.Button(bottom_frame, text="Сохранить", command=save_file, bootstyle="success").pack(side=tk.LEFT, padx=5)
        tb.Button(bottom_frame, text="Перезагрузить", command=reload_file, bootstyle="warning").pack(side=tk.LEFT, padx=5)
        tb.Button(bottom_frame, text="Закрыть", command=close_editor, bootstyle="danger").pack(side=tk.RIGHT, padx=5)

        if files:
            file_combo.set(files[0])
            text_editor.config(state=tk.DISABLED)
            self.root.update()
            content = read_file(self.checker, files[0])
            text_editor.insert(tk.END, content)
            text_editor.config(state=tk.NORMAL)
            current_filepath[0] = files[0]

    # ---------- УПРАВЛЕНИЕ ISPmanager ----------
    def run_isp_restart(self):
        if not self.checker:
            return
        if messagebox.askyesno("Подтверждение", "Перезапустить панель ISPmanager?", parent=self.root):
            self._run_in_thread(ispmanager_restart, self.isp_restart_btn, self.checker)

    def run_isp_kill(self):
        if not self.checker:
            return
        if messagebox.askyesno(
            "Подтверждение",
            "Принудительно завершить процесс core (панель)?\n⚠️ Это может привести к потере данных!",
            parent=self.root
        ):
            self._run_in_thread(ispmanager_kill_core, self.isp_kill_btn, self.checker)

    def run_isp_update(self):
        if not self.checker:
            return
        if messagebox.askyesno("Подтверждение", "Обновить панель ISPmanager?\n⚠️ Обновление может занять несколько минут!", parent=self.root):
            self._run_in_thread(ispmanager_update, self.isp_update_btn, self.checker)

    def run_isp_ssl(self):
        if not self.checker:
            return
        if messagebox.askyesno(
            "Подтверждение",
            "Принудительно запустить выпуск Let's Encrypt сертификатов?\n⚠️ Процесс может занять несколько минут!",
            parent=self.root
        ):
            self._run_in_thread(ispmanager_ssl_issue, self.isp_ssl_btn, self.checker)

    def run_isp_disable(self):
        if not self.checker:
            return
        if messagebox.askyesno("Подтверждение", "Отключить панель ISPmanager?\n⚠️ Панель будет остановлена!", parent=self.root):
            self._run_in_thread(ispmanager_disable, self.isp_disable_btn, self.checker)

    def run_isp_geoip(self):
        if not self.checker:
            return
        if messagebox.askyesno("Подтверждение", "Отключить модуль авторизации GeoIP?", parent=self.root):
            self._run_in_thread(ispmanager_disable_geoip, self.isp_geoip_btn, self.checker)

    def run_isp_cron(self):
        if not self.checker:
            return
        self._run_in_thread(ispmanager_check_cron_path, self.isp_cron_btn, self.checker)

    def run_isp_fix_cron(self):
        if not self.checker:
            return
        if messagebox.askyesno("Подтверждение", "Закомментировать переменную PATH в crontab?\n⚠️ Это может повлиять на другие cron-задания!", parent=self.root):
            self._run_in_thread(ispmanager_fix_cron_path, self.isp_fix_cron_btn, self.checker)

    # ---------- ОТПРАВКА КОМАНД ----------
    def send_command(self, event=None):
        if not self.checker:
            return
        cmd = self.cmd_entry.get().strip()
        if not cmd:
            return

        self.cmd_history.append(cmd)
        self.history_index = len(self.cmd_history)

        self.cmd_entry.delete(0, tk.END)

        if cmd.lower() in ('exit', 'quit'):
            self.log("Завершение сессии...")
            self.disconnect()
            return

        self.log(f"\n$ {cmd}")
        try:
            stdout, stderr = self.checker.exec_command(cmd)
            if stdout.strip():
                self.log(stdout.strip())
            if stderr.strip():
                self.log("STDERR: " + stderr.strip())
        except Exception as e:
            self.log(f"Ошибка выполнения команды: {e}")

    def disconnect(self):
        if self.checker:
            self.checker.close()
            self.checker = None
            self.panel_type = None

        self.full_btn.config(state=tk.DISABLED)
        self.disk_btn.config(state=tk.DISABLED)
        self.network_btn.config(state=tk.DISABLED)
        self.firewall_btn.config(state=tk.DISABLED)
        self.config_btn.config(state=tk.DISABLED)
        self.logs_btn.config(state=tk.DISABLED)
        self.access_btn.config(state=tk.DISABLED)
        self.oom_btn.config(state=tk.DISABLED)
        self.dns_btn.config(state=tk.DISABLED)
        self.resolv_btn.config(state=tk.DISABLED)
        self.edit_dns_btn.config(state=tk.DISABLED)
        self.ipv4_btn.config(state=tk.DISABLED)
        self.ipv6_btn.config(state=tk.DISABLED)
        self.restart_btn.config(state=tk.DISABLED)
        self.config_editor_btn.config(state=tk.DISABLED)
        self.swap_btn.config(state=tk.DISABLED)
        self.fstab_btn.config(state=tk.DISABLED)
        self.send_btn.config(state=tk.DISABLED)

        for btn in [
            self.isp_restart_btn, self.isp_kill_btn, self.isp_update_btn,
            self.isp_ssl_btn, self.isp_disable_btn, self.isp_geoip_btn,
            self.isp_cron_btn, self.isp_fix_cron_btn
        ]:
            btn.config(state=tk.DISABLED)
        self.ispmanager_frame.pack_forget()

        self.connect_btn.config(text="Подключиться", bootstyle="success", command=self.connect)
        self.log("Соединение закрыто.")


if __name__ == "__main__":
    app = DiagnosticApp()
    app.root.mainloop()