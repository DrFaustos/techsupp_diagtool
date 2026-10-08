"""Вывод и ввод: лог с маскированием секретов, поиск Ctrl+F, копирование, сохранение отчёта, история команд, шпаргалка.

Вынесено из gui.py без изменений исходников: константы —, функции —, методы find_in_output, show_cheatsheet, _insert_cheat, log, _mask_secrets, copy_output, save_report, history_up, history_down, autocomplete, browse_key."""

import tkinter as tk
from tkinter import messagebox, filedialog, simpledialog
import ttkbootstrap as tb
import re
from ttkbootstrap.constants import *


class OutputMixin:
    # ---------- ПОИСК В ВЫВОДЕ ----------
    def find_in_output(self):
        query = simpledialog.askstring("Поиск", "Найти в выводе:", parent=self.root)
        if not query:
            return
        self.output.tag_remove('search_hit', '1.0', tk.END)
        self.output.tag_config('search_hit', background='#ffd54f', foreground='#000000')
        start = '1.0'
        count = 0
        while True:
            pos = self.output.search(query, start, stopindex=tk.END, nocase=True)
            if not pos:
                break
            end = f"{pos}+{len(query)}c"
            self.output.tag_add('search_hit', pos, end)
            start = end
            count += 1
        if count:
            self.log(f"🔍 Найдено совпадений: {count}")
            self.output.see(self.output.tag_ranges('search_hit')[0] if self.output.tag_ranges('search_hit') else tk.END)
        else:
            self.log(f"🔍 '{query}' не найдено")

    def show_cheatsheet(self):
        dialog = tb.Toplevel(self.root)
        dialog.title("📖 Шпаргалка техподдержки")
        dialog.geometry("500x400")
        dialog.transient(self.root)
        dialog.grab_set()

        tb.Label(dialog, text="Частые команды (нажмите 'Вставить' для копирования в терминал):", bootstyle="inverse-secondary").pack(pady=5)

        cheats = [
            ("Перезапуск nginx", "systemctl restart nginx"),
            ("Перезапуск php-fpm", "systemctl restart php*-fpm"),
            ("Последние 50 строк error.log", "tail -n 50 /var/log/nginx/error.log"),
            ("Поиск 5xx ошибок сегодня", r"grep '\[5[0-9][0-9]\]' /var/log/nginx/access.log | tail -n 20"),
            ("Свободное место", "df -h"),
            ("Использование памяти", "free -m"),
            ("Топ процессов по CPU", "ps aux --sort=-%cpu | head -n 15"),
            ("Активные соединения", "ss -tulnp | grep -E ':(80|443)'"),
            ("Очистка кэша systemd", "systemctl daemon-reload"),
            ("Проверка синтаксиса nginx", "nginx -t")
        ]

        for name, cmd in cheats:
            frame = tb.Frame(dialog, bootstyle="secondary")
            frame.pack(fill=tk.X, padx=10, pady=2)
            tb.Label(frame, text=name, width=30, anchor='w').pack(side=tk.LEFT, padx=5)
            tb.Label(frame, text=cmd, font=("Courier", 9), foreground="gray").pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)
            tb.Button(frame, text="Вставить", bootstyle="info-outline", 
                      command=lambda c=cmd: self._insert_cheat(c, dialog)).pack(side=tk.RIGHT, padx=5)

        tb.Button(dialog, text="Закрыть", command=dialog.destroy, bootstyle="secondary").pack(pady=10)

    def _insert_cheat(self, cmd, dialog):
        self.cmd_entry.delete(0, tk.END)
        self.cmd_entry.insert(0, cmd)
        self.cmd_entry.focus_set()
        dialog.destroy()

    def log(self, text):
        self.output.insert(tk.END, text + "\n")
        self.output.see(tk.END)
        try:
            self._logger.info(self._mask_secrets(text))
        except Exception:
            pass

    @staticmethod
    def _mask_secrets(text):
        """Маскирует типовые секреты перед записью в лог-файл."""
        if not text:
            return text
        patterns = [
            (r'(?i)(pass(word|wd)?\s*[=:]\s*)\S+', r'\1***'),
            (r'(?i)(token\s*[=:]\s*)\S+', r'\1***'),
            (r'(?i)(api[_-]?key\s*[=:]\s*)\S+', r'\1***'),
            (r'(?i)(secret\s*[=:]\s*)\S+', r'\1***'),
        ]
        for pat, rep in patterns:
            text = re.sub(pat, rep, text)
        return text

    def copy_output(self):
        text = self.output.get(1.0, tk.END)
        self.root.clipboard_clear()
        self.root.clipboard_append(text)
        self.root.update()
        self.log("✅ Вывод скопирован в буфер обмена")

    def save_report(self):
        filename = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")],
            parent=self.root
        )
        if filename:
            try:
                with open(filename, 'w', encoding='utf-8') as f:
                    f.write(self.output.get(1.0, tk.END))
                self.log(f"✅ Отчёт сохранён в {filename}")
            except Exception as e:
                messagebox.showerror("Ошибка", f"Не удалось сохранить файл: {e}", parent=self.root)

    def history_up(self, event):
        if not self.cmd_history:
            return "break"
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

    # ---------- АВТОДОПОЛНЕНИЕ ----------
    def autocomplete(self, event):
        """Простое автодополнение по истории команд при нажатии Tab"""
        current = self.cmd_entry.get()
        if not current:
            return None
        matches = [cmd for cmd in self.cmd_history if cmd.startswith(current)]
        if matches:
            self.cmd_entry.delete(0, tk.END)
            self.cmd_entry.insert(0, matches[0])
        return "break"

    def browse_key(self):
        filename = filedialog.askopenfilename()
        if filename:
            self.key_var.set(filename)
