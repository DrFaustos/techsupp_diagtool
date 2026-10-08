"""Подключение и исполнитель задач: connect/disconnect, запуск в потоке с отменой, отправка команд.

Вынесено из gui.py без изменений исходников: константы —, функции —, методы connect, _on_connect_success, _on_connect_failure, _run_in_thread, _run_simple, _stop_progress, _display_result, cancel_task, send_command, disconnect."""

import tkinter as tk
from tkinter import messagebox
import threading
import time
from diagnostic import detect_panel
from ssh_client import ServerChecker
from ttkbootstrap.constants import *


class RunnerMixin:
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

        # Не даём запустить повторное подключение поверх активного/идущего
        with self._busy_lock:
            if self._busy:
                messagebox.showwarning("Занято", "Дождитесь завершения текущей операции.")
                return
            if self.checker is not None:
                messagebox.showinfo("Подключение", "Сначала отключитесь от текущего сервера.")
                return
            self._busy = True

        self.connect_btn.config(state=tk.DISABLED)
        self.log(f"\n=== Подключение к {ip}:{port} ...")

        def worker():
            checker = ServerChecker(ip, port, user, password, key_path)
            success, message = checker.connect()
            if success:
                if self.panel_var.get() == 'auto':
                    panel_type = detect_panel(checker)
                else:
                    panel_type = self.panel_var.get()
                self.root.after(0, self._on_connect_success, checker, panel_type, message)
            else:
                self.root.after(0, self._on_connect_failure, message)

        threading.Thread(target=worker, daemon=True).start()

    def _on_connect_success(self, checker, panel_type, message):
        self.checker = checker
        self.panel_type = panel_type
        self.log(f"✅ {message}")
        self.log(f"Панель управления: {self.panel_type}")

        # Сохраняем в историю
        self._save_conn_history(self.ip_var.get().strip(), self.port_var.get().strip(), self.user_var.get().strip())
        # Обновляем комбобокс
        self.history_combo['values'] = [f"{e['ip']}:{e['port']} ({e['user']})" for e in self.conn_history]

        # Очищаем пароль из памяти после успешного подключения
        self.password_var.set("")

        # Активируем кнопки
        self.full_btn.config(state=tk.NORMAL)
        self.disk_btn.config(state=tk.NORMAL)
        self.network_btn.config(state=tk.NORMAL)
        self.firewall_btn.config(state=tk.NORMAL)
        self.config_btn.config(state=tk.NORMAL)
        self.logs_btn.config(state=tk.NORMAL)
        self.access_btn.config(state=tk.NORMAL)
        self.oom_btn.config(state=tk.NORMAL)
        self.ssl_btn.config(state=tk.NORMAL)
        self.whois_btn.config(state=tk.NORMAL)
        self.ports_btn.config(state=tk.NORMAL)
        self.grep_btn.config(state=tk.NORMAL)
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
            self.ispmanager_frame2.pack(side=tk.LEFT, padx=5)
            for btn in [
                self.isp_restart_btn, self.isp_kill_btn, self.isp_update_btn,
                self.isp_ssl_btn, self.isp_disable_btn, self.isp_geoip_btn,
                self.isp_cron_btn, self.isp_fix_cron_btn
            ]:
                btn.config(state=tk.NORMAL)
        else:
            self.ispmanager_frame.pack_forget()
            self.ispmanager_frame2.pack_forget()
            for btn in [
                self.isp_restart_btn, self.isp_kill_btn, self.isp_update_btn,
                self.isp_ssl_btn, self.isp_disable_btn, self.isp_geoip_btn,
                self.isp_cron_btn, self.isp_fix_cron_btn
            ]:
                btn.config(state=tk.DISABLED)

        self.connect_btn.config(text="Отключиться", bootstyle="danger", command=self.disconnect)
        self.connect_btn.config(state=tk.NORMAL)
        self.cmd_entry.focus_set()
        with self._busy_lock:
            self._busy = False

    def _on_connect_failure(self, message):
        self.log(f"❌ {message}")
        self.connect_btn.config(state=tk.NORMAL)
        with self._busy_lock:
            self._busy = False

    # ---------- ФОНОВЫЕ ЗАДАЧИ ----------
    def _run_in_thread(self, target_func, btn=None, *args, **kwargs):
        """
        Запускает target_func в фоновом потоке.
        Защищает от параллельного запуска нескольких задач и от гонки
        с disconnect(): пока задача выполняется, соединение не закрывается.
        """
        cache_key = kwargs.pop('cache_key', None)
        
        # Проверка кеша (60 секунд)
        if cache_key and cache_key in self._diag_cache:
            ts, cached_result = self._diag_cache[cache_key]
            if time.time() - ts < 60:
                self.root.after(0, lambda: self._display_result(cached_result + "\n\n⚡ [Показан результат из кеша (< 60 сек). Нажмите ещё раз для обновления.]"))
                return

        with self._busy_lock:
            if self._busy:
                messagebox.showwarning("Занято", "Дождитесь завершения текущей операции.")
                return
            if not self.checker:
                return
            self._busy = True

        if btn:
            btn.config(state=tk.DISABLED)
        self.progress.pack(pady=5)
        self.progress.start(10)

        # Запоминаем checker на время задачи, чтобы disconnect его не обнулил
        active_checker = self.checker
        try:
            active_checker.reset_cancel()
        except Exception:
            pass

        def wrapper():
            try:
                result = target_func(*args, **kwargs)
                if cache_key:
                    self._diag_cache[cache_key] = (time.time(), result)
                self.root.after(0, self._display_result, result)
            except Exception as e:
                self.root.after(0, self._display_result, f"❌ Ошибка: {str(e)}")
            finally:
                self.root.after(0, self._stop_progress)
                if btn:
                    self.root.after(0, lambda b=btn: b.config(state=tk.NORMAL))
                self.root.after(0, lambda: self.cancel_btn.config(state=tk.DISABLED))
                with self._busy_lock:
                    self._busy = False
                # active_checker здесь не удаляем: del имени из внешней области
                # сделал бы его локальным в wrapper и бросил UnboundLocalError
                # в самом конце finally (поток умирал с traceback после каждой
                # задачи). Ячейка живёт в _run_in_thread и освобождается сама.

        self.cancel_btn.config(state=tk.NORMAL)
        thread = threading.Thread(target=wrapper)
        thread.daemon = True
        thread.start()

    def _run_simple(self, fn, btn=None, on_done=None, *args, **kwargs):
        """
        Запускает произвольную функцию в потоке, результат отдаёт в on_done(result).
        Используется для операций, чей вывод не является «отчётом» диагностики.
        """
        with self._busy_lock:
            if self._busy:
                messagebox.showwarning("Занято", "Дождитесь завершения текущей операции.")
                return
            if not self.checker:
                return
            self._busy = True

        # Сбрасываем возможную прошлую отмену, иначе следующая команда упадёт.
        try:
            self.checker.reset_cancel()
        except Exception:
            pass

        if btn:
            btn.config(state=tk.DISABLED)
        self.cancel_btn.config(state=tk.NORMAL)
        self.progress.pack(pady=5)
        self.progress.start(10)

        def wrapper():
            try:
                result = fn(*args, **kwargs)
            except Exception as e:
                result = f"❌ Ошибка: {str(e)}"
            finally:
                self.root.after(0, self._stop_progress)
                if btn:
                    self.root.after(0, lambda b=btn: b.config(state=tk.NORMAL))
                self.root.after(0, lambda: self.cancel_btn.config(state=tk.DISABLED))
                with self._busy_lock:
                    self._busy = False
            if on_done:
                self.root.after(0, on_done, result)
            else:
                self.root.after(0, self._display_result, result)

        threading.Thread(target=wrapper, daemon=True).start()

    def _stop_progress(self):
        self.progress.stop()
        self.progress.pack_forget()

    def _display_result(self, text):
        self.log("\n" + "="*60)
        self.log(text)

    def cancel_task(self):
        """Прерывает текущую долгую операцию."""
        if self.checker is not None:
            try:
                self.checker.cancel()
            except Exception:
                pass
        self.log("⏹ Запрошена отмена текущей операции...")

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

        def run_cmd():
            out, err, rc = self.checker.run(cmd)
            parts = []
            if out.strip():
                parts.append(out.strip())
            if rc != 0 and err.strip():
                parts.append("STDERR: " + err.strip())
            return "\n".join(parts) if parts else "(нет вывода)"

        self._run_simple(run_cmd, self.send_btn)

    def disconnect(self):
        with self._busy_lock:
            if self._busy:
                messagebox.showwarning(
                    "Идёт операция",
                    "Дождитесь завершения текущей операции перед отключением."
                )
                return

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
        self.ssl_btn.config(state=tk.DISABLED)
        self.whois_btn.config(state=tk.DISABLED)
        self.ports_btn.config(state=tk.DISABLED)
        self.grep_btn.config(state=tk.DISABLED)
        self.cancel_btn.config(state=tk.DISABLED)
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
        self.ispmanager_frame2.pack_forget()

        self.connect_btn.config(text="Подключиться", bootstyle="success", command=self.connect)
        self.log("Соединение закрыто.")
