"""Панель ISPmanager: перезапуск, kill core, обновление, SSL, отключение, GeoIP, cron.

Вынесено из gui.py без изменений исходников: константы —, функции —, методы run_isp_restart, run_isp_kill, run_isp_update, run_isp_ssl, run_isp_disable, run_isp_geoip, run_isp_cron, run_isp_fix_cron."""

from tkinter import messagebox
from diagnostic import ispmanager_restart, ispmanager_kill_core, ispmanager_update, ispmanager_ssl_issue, ispmanager_disable, ispmanager_disable_geoip, ispmanager_check_cron_path, ispmanager_fix_cron_path


class IspmanagerMixin:
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
