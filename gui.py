import tkinter as tk
from tkinter import scrolledtext, ttk
import ttkbootstrap as tb
from ttkbootstrap.constants import *   # LEFT/RIGHT/TOP/BOTTOM/SUCCESS ... для create_widgets
import threading
import os
import logging
# get_theme_colors реэкспортируется: тесты и сторонние импортеры берут его из gui
from gui_themes import (
    ThemesMixin, get_theme_colors, detect_system_theme, DARK_THEMES, LIGHT_THEMES,
)
from gui_profiles import ProfilesMixin
from gui_output import OutputMixin
from gui_runner import RunnerMixin
from gui_checks import ChecksMixin
from gui_swap import SwapMixin
from gui_dns import DnsMixin
from gui_admin import AdminMixin
from gui_isp import IspmanagerMixin
from gui_files import FilesMixin


class DiagnosticApp(ThemesMixin, ProfilesMixin, OutputMixin, RunnerMixin, ChecksMixin, SwapMixin, DnsMixin, AdminMixin, IspmanagerMixin, FilesMixin):
    def __init__(self):
        self.initial_theme = detect_system_theme()
        self.root = tb.Window(themename=self.initial_theme)
        self.root.title("SSH Диагностика сервера")
        self.root.geometry("1100x720")
        self.root.minsize(1000, 650)

        self.ip_var = tk.StringVar()
        self.port_var = tk.StringVar(value="22")
        self.user_var = tk.StringVar(value="root")
        self.password_var = tk.StringVar()
        self.key_var = tk.StringVar(value="~/.ssh/id_rsa")
        self.panel_var = tk.StringVar(value="auto")
        self.profile_var = tk.StringVar()

        self.checker = None
        self.panel_type = None

        self.cmd_history = []
        self.history_index = -1
        self.current_theme = self.initial_theme

        # Флаг занятости: защита от параллельных задач и отключения во время задачи
        self._busy = False
        self._busy_lock = threading.Lock()

        # Логирование в файл с ротацией (история сохраняется после закрытия окна).
        # Файл создаётся с правами 0600 — в логе могут быть чувствительные данные.
        self._log_path = os.path.expanduser("~/.techsupp_diagtool.log")
        self._logger = logging.getLogger("techsupp_diagtool")
        if not self._logger.handlers:
            self._logger.setLevel(logging.INFO)
            try:
                from logging.handlers import RotatingFileHandler
                fh = RotatingFileHandler(self._log_path, maxBytes=1_000_000,
                                         backupCount=3, encoding="utf-8")
                fh.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
                self._logger.addHandler(fh)
                if os.path.exists(self._log_path):
                    os.chmod(self._log_path, 0o600)
            except Exception:
                pass

        self.conn_history_file = os.path.expanduser("~/.techsupp_diagtool_connections.json")
        self.conn_history = self._load_conn_history()
        self._diag_cache = {}

        self.create_widgets()
        self.cmd_entry.focus_set()
        self.output.bind("<Control-c>", lambda e: self.copy_output())
        self.output.bind("<Control-s>", lambda e: self.save_report())
        self.output.bind("<Control-f>", lambda e: self.find_in_output())


    def create_widgets(self):
        top_frame = tb.Frame(self.root, bootstyle="secondary")
        top_frame.pack(fill=tk.X, padx=10, pady=5)

        # История подключений
        tb.Label(top_frame, text="История:", bootstyle="inverse-secondary").grid(
            row=0, column=0, sticky='e', padx=5
        )
        history_vals = [f"{e['ip']}:{e['port']} ({e['user']})" for e in self.conn_history]
        self.history_combo = ttk.Combobox(top_frame, values=history_vals, width=25, state='readonly')
        self.history_combo.grid(row=0, column=1, padx=5)
        self.history_combo.bind('<<ComboboxSelected>>', self._on_history_select)

        # Профили серверов
        tb.Label(top_frame, text="Профиль:", bootstyle="inverse-secondary").grid(
            row=0, column=2, sticky='e', padx=5
        )
        self.profile_combo = ttk.Combobox(top_frame, textvariable=self.profile_var,
                                          values=sorted(self._load_profiles().keys()),
                                          width=18, state='readonly')
        self.profile_combo.grid(row=0, column=3, padx=5)
        tb.Button(top_frame, text="Загрузить", command=self.load_profile,
                  bootstyle="secondary-outline").grid(row=0, column=4, padx=2)
        tb.Button(top_frame, text="Сохранить", command=self.save_profile,
                  bootstyle="secondary-outline").grid(row=0, column=5, padx=2)
        tb.Button(top_frame, text="✖", command=self.delete_profile,
                  bootstyle="danger-outline", width=3).grid(row=0, column=6, padx=2)

        # IP
        tb.Label(top_frame, text="IP:", bootstyle="inverse-secondary").grid(
            row=1, column=0, sticky='e', padx=5
        )
        self.ip_entry = tb.Entry(top_frame, textvariable=self.ip_var, width=15)
        self.ip_entry.grid(row=1, column=1, padx=5)

        # Порт
        tb.Label(top_frame, text="Порт:", bootstyle="inverse-secondary").grid(
            row=1, column=2, sticky='e', padx=5
        )
        tb.Entry(top_frame, textvariable=self.port_var, width=6).grid(
            row=1, column=3, padx=5
        )

        # Пользователь
        tb.Label(top_frame, text="Пользователь:", bootstyle="inverse-secondary").grid(
            row=1, column=4, sticky='e', padx=5
        )
        tb.Entry(top_frame, textvariable=self.user_var, width=12).grid(
            row=1, column=5, padx=5
        )

        # Пароль
        tb.Label(top_frame, text="Пароль:", bootstyle="inverse-secondary").grid(
            row=1, column=6, sticky='e', padx=5
        )
        tb.Entry(top_frame, textvariable=self.password_var, show="*", width=12).grid(
            row=1, column=7, padx=5
        )

        # Ключ
        tb.Label(top_frame, text="Ключ:", bootstyle="inverse-secondary").grid(
            row=2, column=0, sticky='e', padx=5
        )
        tb.Entry(top_frame, textvariable=self.key_var, width=30).grid(
            row=2, column=1, columnspan=6, sticky='ew', padx=5
        )
        tb.Button(
            top_frame,
            text="Обзор",
            command=self.browse_key,
            bootstyle="secondary-outline"
        ).grid(row=2, column=7, padx=5)

        # Тип панели
        tb.Label(top_frame, text="Панель:", bootstyle="inverse-secondary").grid(
            row=3, column=0, sticky='e', padx=5
        )
        panel_frame = tb.Frame(top_frame, bootstyle="secondary")
        panel_frame.grid(row=3, column=1, columnspan=4, sticky='w', padx=5)

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

        # --- Ряд ---
        btn_frame = tb.Frame(self.root, bootstyle="secondary")
        btn_frame.pack(fill=tk.X, padx=10, pady=(0, 5))

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

        self.ssl_btn = tb.Button(btn_frame, text="SSL-сертификат",
            command=self.run_ssl_check, state=tk.DISABLED, bootstyle="secondary")
        self.ssl_btn.pack(side=tk.LEFT, padx=5)
        self.whois_btn = tb.Button(btn_frame, text="WHOIS",
            command=self.run_whois, state=tk.DISABLED, bootstyle="secondary")
        self.whois_btn.pack(side=tk.LEFT, padx=5)
        self.ports_btn = tb.Button(btn_frame, text="Порты",
            command=self.run_port_scan, state=tk.DISABLED, bootstyle="secondary")
        self.ports_btn.pack(side=tk.LEFT, padx=5)
        self.grep_btn = tb.Button(btn_frame, text="Grep логов",
            command=self.run_grep_logs, state=tk.DISABLED, bootstyle="secondary")
        self.grep_btn.pack(side=tk.LEFT, padx=5)
        self.cancel_btn = tb.Button(btn_frame, text="✖ Отменить",
            command=self.cancel_task, state=tk.DISABLED, bootstyle="danger-outline")
        self.cancel_btn.pack(side=tk.RIGHT, padx=5)

        self.cheat_btn = tb.Button(
            btn_frame,
            text="📖 Шпаргалка",
            command=self.show_cheatsheet,
            bootstyle="secondary-outline"
        )
        self.cheat_btn.pack(side=tk.LEFT, padx=5)

        # --- Ряд ---
        btn_frame = tb.Frame(self.root, bootstyle="secondary")
        btn_frame.pack(fill=tk.X, padx=10, pady=(0, 5))

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

        # --- Ряд ---
        btn_frame = tb.Frame(self.root, bootstyle="secondary")
        btn_frame.pack(fill=tk.X, padx=10, pady=(0, 5))

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

        self.file_btn = tb.Button(
            btn_frame,
            text="📁 Файлы",
            command=self.open_file_manager,
            state=tk.DISABLED,
            bootstyle="secondary"
        )
        self.file_btn.pack(side=tk.LEFT, padx=5)

        # ---------- ПЕРЕКЛЮЧАТЕЛЬ ТЕМ ----------
        theme_frame = tb.Frame(btn_frame, bootstyle="secondary")
        theme_frame.pack(side=tk.RIGHT, padx=10)

        tb.Label(theme_frame, text="Тема:", bootstyle="inverse-secondary").pack(side=tk.LEFT, padx=5)

        available_themes = DARK_THEMES + LIGHT_THEMES
        self.theme_var = tk.StringVar(value=self.initial_theme)

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

        # --- Ряд ---
        btn_frame = tb.Frame(self.root, bootstyle="secondary")
        btn_frame.pack(fill=tk.X, padx=10, pady=(0, 5))

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

        # Второй ряд ISP-кнопок (чтобы не переполнять строку)
        self.ispmanager_frame2 = tb.Frame(btn_frame, bootstyle="secondary")
        self.ispmanager_frame2.pack(side=tk.LEFT, padx=5)
        self.ispmanager_frame2.pack_forget()

        self.isp_disable_btn = tb.Button(
            self.ispmanager_frame2,
            text="Отключить панель",
            command=self.run_isp_disable,
            state=tk.DISABLED,
            bootstyle="danger"
        )
        self.isp_disable_btn.pack(side=tk.LEFT, padx=2)

        self.isp_geoip_btn = tb.Button(
            self.ispmanager_frame2,
            text="Отключить GeoIP",
            command=self.run_isp_geoip,
            state=tk.DISABLED,
            bootstyle="secondary"
        )
        self.isp_geoip_btn.pack(side=tk.LEFT, padx=2)

        self.isp_cron_btn = tb.Button(
            self.ispmanager_frame2,
            text="Проверить CRON",
            command=self.run_isp_cron,
            state=tk.DISABLED,
            bootstyle="secondary"
        )
        self.isp_cron_btn.pack(side=tk.LEFT, padx=2)

        self.isp_fix_cron_btn = tb.Button(
            self.ispmanager_frame2,
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

        # ---------- КНОПКИ ДЕЙСТВИЙ ----------
        action_frame = tb.Frame(self.root, bootstyle="secondary")
        action_frame.pack(fill=tk.X, padx=10, pady=(0, 5))
        tb.Button(
            action_frame,
            text="📋 Копировать вывод (Ctrl+C)",
            command=self.copy_output,
            bootstyle="secondary-outline"
        ).pack(side=tk.RIGHT, padx=5)
        tb.Button(
            action_frame,
            text="💾 Сохранить отчёт (Ctrl+S)",
            command=self.save_report,
            bootstyle="secondary-outline"
        ).pack(side=tk.RIGHT, padx=5)

        # ---------- ТЕКСТОВОЕ ПОЛЕ ВЫВОДА ----------
        self.output = scrolledtext.ScrolledText(
            self.root,
            wrap=tk.WORD,
            font=("Courier", 10)
        )
        self.output.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        self.update_output_colors(self.initial_theme)
        self.apply_scrollbar_style(self.initial_theme)

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
        self.cmd_entry.bind("<Tab>", self.autocomplete)

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


if __name__ == "__main__":
    app = DiagnosticApp()
    app.root.mainloop()
