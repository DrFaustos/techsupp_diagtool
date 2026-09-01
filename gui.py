import tkinter as tk
from tkinter import messagebox, filedialog, scrolledtext, simpledialog, ttk
from diagnostic import (
    detect_panel, full_diagnostic_report,
    metrics_report, firewall_report,
    web_config_report, site_logs_report,
    disk_memory_report, network_report,
    analyze_access_log, get_domains,
    search_oom_logs, dns_report, dns_report_local,
    dns_resolvers_report
)
from ssh_client import ServerChecker

class DiagnosticApp:
    def __init__(self, root):
        self.root = root
        self.root.title("SSH Диагностика сервера")
        self.root.geometry("950x720")
        self.root.minsize(900, 650)

        # Настройка тёмной темы в стиле GNOME
        self.setup_theme()

        # Переменные для данных подключения
        self.ip_var = tk.StringVar()
        self.port_var = tk.StringVar(value="22")
        self.user_var = tk.StringVar(value="root")
        self.password_var = tk.StringVar()
        self.key_var = tk.StringVar(value="~/.ssh/id_rsa")
        self.panel_var = tk.StringVar(value="auto")

        # Состояние подключения
        self.checker = None
        self.panel_type = None

        # История команд
        self.cmd_history = []
        self.history_index = -1

        # Создаём виджеты
        self.create_widgets()

        # Фокус на поле ввода команд при старте
        self.cmd_entry.focus_set()

    def setup_theme(self):
        # Цветовая схема тёмная (как GNOME)
        self.bg = "#2e3436"      # тёмно-серый
        self.fg = "#eeeeee"      # светлый текст
        self.select_bg = "#3465a4" # синий акцент
        self.btn_bg = "#3c3f41"   # кнопки
        self.btn_fg = "#ffffff"
        self.btn_active_bg = "#555753"
        self.entry_bg = "#2c2e30"
        self.entry_fg = "#ffffff"
        self.output_bg = "#1a1a1a"
        self.output_fg = "#d3d7cf"

        # Применяем к root
        self.root.configure(bg=self.bg)

        # Стиль для ttk кнопок (если используем)
        style = ttk.Style()
        style.theme_use('clam')
        style.configure('TButton', background=self.btn_bg, foreground=self.btn_fg, bordercolor='#555753', focuscolor='none')
        style.map('TButton', background=[('active', self.btn_active_bg), ('pressed', '#204a87')])

    def create_widgets(self):
        # Верхняя панель: ввод данных
        top_frame = tk.Frame(self.root, bg=self.bg)
        top_frame.pack(fill=tk.X, padx=10, pady=5)

        # IP
        tk.Label(top_frame, text="IP:", bg=self.bg, fg=self.fg).grid(row=0, column=0, sticky='e', padx=5)
        self.ip_entry = tk.Entry(top_frame, textvariable=self.ip_var, width=15, bg=self.entry_bg, fg=self.entry_fg, insertbackground='white')
        self.ip_entry.grid(row=0, column=1, padx=5)

        # Порт
        tk.Label(top_frame, text="Порт:", bg=self.bg, fg=self.fg).grid(row=0, column=2, sticky='e', padx=5)
        tk.Entry(top_frame, textvariable=self.port_var, width=6, bg=self.entry_bg, fg=self.entry_fg, insertbackground='white').grid(row=0, column=3, padx=5)

        # Пользователь
        tk.Label(top_frame, text="Пользователь:", bg=self.bg, fg=self.fg).grid(row=0, column=4, sticky='e', padx=5)
        tk.Entry(top_frame, textvariable=self.user_var, width=12, bg=self.entry_bg, fg=self.entry_fg, insertbackground='white').grid(row=0, column=5, padx=5)

        # Пароль
        tk.Label(top_frame, text="Пароль:", bg=self.bg, fg=self.fg).grid(row=0, column=6, sticky='e', padx=5)
        tk.Entry(top_frame, textvariable=self.password_var, show="*", width=12, bg=self.entry_bg, fg=self.entry_fg, insertbackground='white').grid(row=0, column=7, padx=5)

        # Ключ
        tk.Label(top_frame, text="Ключ:", bg=self.bg, fg=self.fg).grid(row=1, column=0, sticky='e', padx=5)
        tk.Entry(top_frame, textvariable=self.key_var, width=30, bg=self.entry_bg, fg=self.entry_fg, insertbackground='white').grid(row=1, column=1, columnspan=6, sticky='ew', padx=5)
        tk.Button(top_frame, text="Обзор", command=self.browse_key, bg=self.btn_bg, fg=self.btn_fg, activebackground=self.btn_active_bg).grid(row=1, column=7, padx=5)

        # Тип панели
        tk.Label(top_frame, text="Панель:", bg=self.bg, fg=self.fg).grid(row=2, column=0, sticky='e', padx=5)
        panel_frame = tk.Frame(top_frame, bg=self.bg)
        panel_frame.grid(row=2, column=1, columnspan=4, sticky='w', padx=5)
        for text, value in [("Авто", "auto"), ("FastPanel", "fastpanel"), ("ISPmanager", "ispmanager"), ("Нет", "none")]:
            rb = tk.Radiobutton(panel_frame, text=text, variable=self.panel_var, value=value,
                                bg=self.bg, fg=self.fg, selectcolor=self.select_bg, activebackground=self.bg)
            rb.pack(side='left', padx=5)

        # Кнопки диагностики (первый ряд)
        btn_frame = tk.Frame(self.root, bg=self.bg)
        btn_frame.pack(fill=tk.X, padx=10, pady=5)

        self.connect_btn = tk.Button(btn_frame, text="Подключиться", command=self.connect, bg="#4e9a06", fg=self.btn_fg, activebackground="#73d216")
        self.connect_btn.pack(side=tk.LEFT, padx=5)

        self.full_btn = tk.Button(btn_frame, text="Полная диагностика", command=self.run_full, state=tk.DISABLED,
                                bg=self.btn_bg, fg=self.btn_fg, activebackground=self.btn_active_bg)
        self.full_btn.pack(side=tk.LEFT, padx=5)

        self.disk_btn = tk.Button(btn_frame, text="Диски и память", command=self.run_disk_memory, state=tk.DISABLED,
                                bg=self.btn_bg, fg=self.btn_fg, activebackground=self.btn_active_bg)
        self.disk_btn.pack(side=tk.LEFT, padx=5)

        self.network_btn = tk.Button(btn_frame, text="Сеть", command=self.run_network, state=tk.DISABLED,
                                    bg=self.btn_bg, fg=self.btn_fg, activebackground=self.btn_active_bg)
        self.network_btn.pack(side=tk.LEFT, padx=5)

        self.firewall_btn = tk.Button(btn_frame, text="Фаервол", command=self.run_firewall, state=tk.DISABLED,
                                    bg=self.btn_bg, fg=self.btn_fg, activebackground=self.btn_active_bg)
        self.firewall_btn.pack(side=tk.LEFT, padx=5)

        self.config_btn = tk.Button(btn_frame, text="Конфиги веб", command=self.run_config, state=tk.DISABLED,
                                    bg=self.btn_bg, fg=self.btn_fg, activebackground=self.btn_active_bg)
        self.config_btn.pack(side=tk.LEFT, padx=5)

        self.logs_btn = tk.Button(btn_frame, text="Логи сайтов", command=self.run_logs, state=tk.DISABLED,
                                bg=self.btn_bg, fg=self.btn_fg, activebackground=self.btn_active_bg)
        self.logs_btn.pack(side=tk.LEFT, padx=5)

        self.access_btn = tk.Button(btn_frame, text="Анализ логов доступа", command=self.run_access_analysis, state=tk.DISABLED,
                                    bg=self.btn_bg, fg=self.btn_fg, activebackground=self.btn_active_bg)
        self.access_btn.pack(side=tk.LEFT, padx=5)

        self.oom_btn = tk.Button(btn_frame, text="Поиск OOM", command=self.run_oom_search, state=tk.DISABLED,
                                bg=self.btn_bg, fg=self.btn_fg, activebackground=self.btn_active_bg)
        self.oom_btn.pack(side=tk.LEFT, padx=5)

        self.dns_btn = tk.Button(btn_frame, text="DNS-проверка", command=self.run_dns_check, state=tk.DISABLED,
                                bg=self.btn_bg, fg=self.btn_fg, activebackground=self.btn_active_bg)
        self.dns_btn.pack(side=tk.LEFT, padx=5)

        self.resolv_btn = tk.Button(btn_frame, text="DNS-резолверы", command=self.run_dns_resolvers, state=tk.DISABLED,
                                    bg=self.btn_bg, fg=self.btn_fg, activebackground=self.btn_active_bg)
        self.resolv_btn.pack(side=tk.LEFT, padx=5)

        # Кнопки управления swap (второй ряд)
        swap_frame = tk.Frame(self.root, bg=self.bg)
        swap_frame.pack(fill=tk.X, padx=10, pady=5)

        self.swap_btn = tk.Button(swap_frame, text="Создать swap файл", command=self.create_swap, state=tk.DISABLED,
                                  bg=self.btn_bg, fg=self.btn_fg, activebackground=self.btn_active_bg)
        self.swap_btn.pack(side=tk.LEFT, padx=5)

        self.fstab_btn = tk.Button(swap_frame, text="Прописать swap в fstab", command=self.add_swap_to_fstab, state=tk.DISABLED,
                                   bg=self.btn_bg, fg=self.btn_fg, activebackground=self.btn_active_bg)
        self.fstab_btn.pack(side=tk.LEFT, padx=5)

        # Текстовое поле для вывода (с прокруткой) — тёмный фон
        self.output = scrolledtext.ScrolledText(self.root, wrap=tk.WORD, font=("Courier", 10),
                                                bg=self.output_bg, fg=self.output_fg, insertbackground='white')
        self.output.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)

        # Нижняя панель: интерактивная командная строка
        cmd_frame = tk.Frame(self.root, bg=self.bg)
        cmd_frame.pack(fill=tk.X, padx=10, pady=5)

        tk.Label(cmd_frame, text="Команда:", bg=self.bg, fg=self.fg).pack(side=tk.LEFT, padx=5)
        self.cmd_entry = tk.Entry(cmd_frame, bg=self.entry_bg, fg=self.entry_fg, insertbackground='white')
        self.cmd_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)
        self.cmd_entry.bind("<Return>", self.send_command)
        self.cmd_entry.bind("<Up>", self.history_up)
        self.cmd_entry.bind("<Down>", self.history_down)

        self.send_btn = tk.Button(cmd_frame, text="Send", command=self.send_command, state=tk.DISABLED,
                                  bg=self.btn_bg, fg=self.btn_fg, activebackground=self.btn_active_bg)
        self.send_btn.pack(side=tk.LEFT, padx=5)

        # Начальное сообщение
        self.log("Ожидание подключения...")

    def browse_key(self):
        filename = filedialog.askopenfilename()
        if filename:
            self.key_var.set(filename)

    def log(self, text):
        """Добавляет текст в поле вывода и прокручивает вниз"""
        self.output.insert(tk.END, text + "\n")
        self.output.see(tk.END)

    # ---------- УПРАВЛЕНИЕ ИСТОРИЕЙ КОМАНД ----------
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

    # ---------- ПОДКЛЮЧЕНИЕ ----------
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
        if not self.checker.connect():
            self.log("❌ Ошибка подключения. Проверьте данные доступа.")
            self.checker = None
            return

        # Определяем панель
        if self.panel_var.get() == 'auto':
            self.panel_type = detect_panel(self.checker)
        else:
            self.panel_type = self.panel_var.get()

        self.log(f"✅ Подключено. Панель управления: {self.panel_type}")

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
        self.swap_btn.config(state=tk.NORMAL)
        self.fstab_btn.config(state=tk.NORMAL)
        self.send_btn.config(state=tk.NORMAL)
        self.connect_btn.config(state=tk.DISABLED)

        # Фокус на командную строку
        self.cmd_entry.focus_set()

    # ---------- ОТПРАВКА ПРОИЗВОЛЬНОЙ КОМАНДЫ ----------
    def send_command(self, event=None):
        if not self.checker:
            return
        cmd = self.cmd_entry.get().strip()
        if not cmd:
            return

        # Добавляем в историю
        self.cmd_history.append(cmd)
        self.history_index = len(self.cmd_history)

        # Очищаем поле ввода
        self.cmd_entry.delete(0, tk.END)

        # Если exit или quit – закрываем соединение
        if cmd.lower() in ('exit', 'quit'):
            self.log("Завершение сессии...")
            self.disconnect()
            return

        # Выполняем команду
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
        self.swap_btn.config(state=tk.DISABLED)
        self.fstab_btn.config(state=tk.DISABLED)
        self.send_btn.config(state=tk.DISABLED)
        self.connect_btn.config(state=tk.NORMAL)
        self.log("Соединение закрыто.")

    # ---------- ОТДЕЛЬНЫЕ ДИАГНОСТИКИ ----------
    def run_full(self):
        if not self.checker:
            return
        self.log("\n" + "="*60)
        report = full_diagnostic_report(self.checker, self.panel_type)
        self.log(report)

    def run_disk_memory(self):
        if not self.checker:
            return
        self.log("\n" + "="*60)
        self.log(disk_memory_report(self.checker))

    def run_network(self):
        if not self.checker:
            return
        self.log("\n" + "="*60)
        self.log(network_report(self.checker))

    def run_firewall(self):
        if not self.checker:
            return
        self.log("\n" + "="*60)
        self.log(firewall_report(self.checker))

    def run_config(self):
        if not self.checker:
            return
        self.log("\n" + "="*60)
        self.log(web_config_report(self.checker))

    def run_logs(self):
        if not self.checker:
            return
        self.log("\n" + "="*60)
        self.log(site_logs_report(self.checker, self.panel_type))

    # ---------- АНАЛИЗ ЛОГОВ ДОСТУПА ----------
    def run_access_analysis(self):
        if not self.checker:
            return

        domains = get_domains(self.checker, self.panel_type)
        domain_var = tk.StringVar()
        if domains:
            domain_var.set(domains[0])

        dialog = tk.Toplevel(self.root)
        dialog.title("Анализ логов доступа")
        dialog.geometry("500x320")
        dialog.configure(bg=self.bg)
        dialog.transient(self.root)
        dialog.grab_set()

        row = 0
        # Домен
        tk.Label(dialog, text="Домен:", bg=self.bg, fg=self.fg).grid(row=row, column=0, sticky='e', padx=5, pady=5)
        domain_combo = ttk.Combobox(dialog, textvariable=domain_var, values=domains, state='normal')
        domain_combo.grid(row=row, column=1, columnspan=3, padx=5, pady=5, sticky='ew')
        if not domains:
            domain_combo.set('')
        row += 1

        # Топ-Х
        tk.Label(dialog, text="Топ-Х:", bg=self.bg, fg=self.fg).grid(row=row, column=0, sticky='e', padx=5, pady=5)
        top_var = tk.StringVar(value="10")
        tk.Entry(dialog, textvariable=top_var, width=10, bg=self.entry_bg, fg=self.entry_fg, insertbackground='white').grid(row=row, column=1, sticky='w', padx=5, pady=5)
        row += 1

        # Фильтр по дате (три поля)
        tk.Label(dialog, text="Фильтр по дате (опционально):", bg=self.bg, fg=self.fg).grid(row=row, column=0, sticky='e', padx=5, pady=5)
        year_var = tk.StringVar()
        month_var = tk.StringVar()
        day_var = tk.StringVar()
        frame_date = tk.Frame(dialog, bg=self.bg)
        frame_date.grid(row=row, column=1, columnspan=3, sticky='w', padx=5, pady=5)
        tk.Entry(frame_date, textvariable=year_var, width=5, bg=self.entry_bg, fg=self.entry_fg, insertbackground='white').pack(side='left', padx=2)
        tk.Label(frame_date, text="ГГГГ", bg=self.bg, fg=self.fg).pack(side='left', padx=2)
        tk.Entry(frame_date, textvariable=month_var, width=3, bg=self.entry_bg, fg=self.entry_fg, insertbackground='white').pack(side='left', padx=2)
        tk.Label(frame_date, text="ММ", bg=self.bg, fg=self.fg).pack(side='left', padx=2)
        tk.Entry(frame_date, textvariable=day_var, width=3, bg=self.entry_bg, fg=self.entry_fg, insertbackground='white').pack(side='left', padx=2)
        tk.Label(frame_date, text="ДД", bg=self.bg, fg=self.fg).pack(side='left', padx=2)
        row += 1

        # Переменная для хранения результата, чтобы сохранить
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
            # Преобразуем в int или None
            year = int(year_var.get()) if year_var.get().strip() else None
            month = int(month_var.get()) if month_var.get().strip() else None
            day = int(day_var.get()) if day_var.get().strip() else None

            # Проверка: если введено не число
            for val, name in [(year, 'год'), (month, 'месяц'), (day, 'день')]:
                if val is not None and not (1 <= val <= 9999 if name=='год' else (1 <= val <= 12 if name=='месяц' else 1 <= val <= 31)):
                    messagebox.showerror("Ошибка", f"Некорректное значение для {name}")
                    return

            dialog.destroy()
            self.log("\n" + "="*60)
            result = analyze_access_log(self.checker, self.panel_type, domain, top_n, year, month, day)
            self.log(result)
            # Сохраняем результат для экспорта
            last_result[0] = result

        def on_save():
            if last_result[0] is None:
                messagebox.showwarning("Нет данных", "Сначала выполните анализ, чтобы сохранить отчёт.")
                return
            filename = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text files", "*.txt"), ("All files", "*.*")])
            if filename:
                try:
                    with open(filename, 'w', encoding='utf-8') as f:
                        f.write(last_result[0])
                    messagebox.showinfo("Успех", f"Отчёт сохранён в {filename}")
                except Exception as e:
                    messagebox.showerror("Ошибка", f"Не удалось сохранить файл: {e}")

        # Кнопки "Анализировать" и "Сохранить отчёт"
        btn_frame = tk.Frame(dialog, bg=self.bg)
        btn_frame.grid(row=row, column=0, columnspan=4, pady=10)
        tk.Button(btn_frame, text="Анализировать", command=on_analyze, bg="#4e9a06", fg="white", activebackground="#73d216").pack(side='left', padx=5)
        tk.Button(btn_frame, text="Сохранить отчёт", command=on_save, bg="#3465a4", fg="white", activebackground="#204a87").pack(side='left', padx=5)

        dialog.columnconfigure(1, weight=1)
        dialog.columnconfigure(2, weight=1)
        dialog.columnconfigure(3, weight=1)
        
    # ---------- ПОИСК OOM ----------
    def run_oom_search(self):
        if not self.checker:
            return
        self.log("\n" + "="*60)
        self.log(search_oom_logs(self.checker))

    # ---------- УПРАВЛЕНИЕ SWAP ----------
    def create_swap(self):
        if not self.checker:
            return
        size = simpledialog.askstring("Размер swap", "Введите размер swap файла в МБ (например, 1024):")
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

        cmd = 'echo "/swapfile none swap sw 0 0" | sudo tee -a /etc/fstab'
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

        dialog = tk.Toplevel(self.root)
        dialog.title("DNS-проверка")
        dialog.geometry("450x230")
        dialog.configure(bg=self.bg)
        dialog.transient(self.root)
        dialog.grab_set()

        # Домен или IP
        tk.Label(dialog, text="Домен/IP:", bg=self.bg, fg=self.fg).grid(row=0, column=0, sticky='e', padx=5, pady=5)
        domain_combo = ttk.Combobox(dialog, textvariable=domain_var, values=domains, state='normal')
        domain_combo.grid(row=0, column=1, padx=5, pady=5, sticky='ew')
        if not domains:
            domain_combo.set('')

        # Чекбокс "Выполнить локально"
        local_var = tk.BooleanVar(value=False)
        cb = tk.Checkbutton(dialog, text="Выполнить локально (A и PTR, NS только с сервера)",
                            variable=local_var, bg=self.bg, fg=self.fg, selectcolor=self.select_bg)
        cb.grid(row=1, column=0, columnspan=2, sticky='w', padx=5, pady=5)

        def on_check():
            domain = domain_var.get().strip()
            if not domain:
                messagebox.showerror("Ошибка", "Введите домен или IP")
                return
            dialog.destroy()
            self.log("\n" + "="*60)
            if local_var.get():
                # Локальная проверка
                from diagnostic import dns_report_local
                result = dns_report_local(domain)
            else:
                # Проверка через сервер
                from diagnostic import dns_report
                result = dns_report(self.checker, domain)
            self.log(result)

        tk.Button(dialog, text="Проверить", command=on_check, bg="#4e9a06", fg="white", activebackground="#73d216")\
            .grid(row=2, column=0, columnspan=2, pady=10)

        dialog.columnconfigure(1, weight=1)
        
    def run_dns_resolvers(self):
        if not self.checker:
            return
        self.log("\n" + "="*60)
        result = dns_resolvers_report(self.checker)
        self.log(result)    