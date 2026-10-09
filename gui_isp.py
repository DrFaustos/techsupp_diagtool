"""Панель ISPmanager: перезапуск, kill core, обновление, SSL, отключение, GeoIP, cron.

Backend-функции живут в panels.py; здесь — раскрывающееся меню
(ISPMANAGER_MENU), помощник включения/выключения и обработчики run_isp_*
с диалогами подтверждения.
"""

from tkinter import messagebox
from diagnostic import (
    ispmanager_restart, ispmanager_kill_core, ispmanager_update,
    ispmanager_ssl_issue, ispmanager_disable, ispmanager_disable_geoip,
    ispmanager_check_cron_path, ispmanager_fix_cron_path,
)

# Состав меню: (подпись пункта, имя метода класса). None — разделитель:
# отделяет повседневные действия от разрушительных (Kill core, отключение).
ISPMANAGER_MENU = [
    ("Перезапустить панель", "run_isp_restart"),
    ("Обновить панель", "run_isp_update"),
    ("Выпустить Let's Encrypt SSL", "run_isp_ssl"),
    ("Проверить CRON PATH", "run_isp_cron"),
    ("Исправить CRON PATH", "run_isp_fix_cron"),
    ("Отключить GeoIP", "run_isp_geoip"),
    None,
    ("Kill core (принудительно)", "run_isp_kill"),
    ("Отключить панель", "run_isp_disable"),
]


class IspmanagerMixin:
    # ---------- МЕНЮ ISPmanager ----------
    # Показ/скрытие и состояние — в gui.py:_set_panel_menus_visible.
    def run_isp_restart(self):
        if not self.checker:
            return
        if messagebox.askyesno("Подтверждение", "Перезапустить панель ISPmanager?", parent=self.root):
            self._run_in_thread(ispmanager_restart, self.isp_menu_btn, self.checker)

    def run_isp_kill(self):
        if not self.checker:
            return
        if messagebox.askyesno(
            "Подтверждение",
            "Принудительно завершить процесс core (панель)?\n⚠️ Это может привести к потере данных!",
            parent=self.root
        ):
            self._run_in_thread(ispmanager_kill_core, self.isp_menu_btn, self.checker)

    def run_isp_update(self):
        if not self.checker:
            return
        if messagebox.askyesno("Подтверждение", "Обновить панель ISPmanager?\n⚠️ Обновление может занять несколько минут!", parent=self.root):
            self._run_in_thread(ispmanager_update, self.isp_menu_btn, self.checker)

    def run_isp_ssl(self):
        if not self.checker:
            return
        if messagebox.askyesno(
            "Подтверждение",
            "Принудительно запустить выпуск Let's Encrypt сертификатов?\n⚠️ Процесс может занять несколько минут!",
            parent=self.root
        ):
            self._run_in_thread(ispmanager_ssl_issue, self.isp_menu_btn, self.checker)

    def run_isp_disable(self):
        if not self.checker:
            return
        if messagebox.askyesno("Подтверждение", "Отключить панель ISPmanager?\n⚠️ Панель будет остановлена!", parent=self.root):
            self._run_in_thread(ispmanager_disable, self.isp_menu_btn, self.checker)

    def run_isp_geoip(self):
        if not self.checker:
            return
        if messagebox.askyesno("Подтверждение", "Отключить модуль авторизации GeoIP?", parent=self.root):
            self._run_in_thread(ispmanager_disable_geoip, self.isp_menu_btn, self.checker)

    def run_isp_cron(self):
        if not self.checker:
            return
        self._run_in_thread(ispmanager_check_cron_path, self.isp_menu_btn, self.checker)

    def run_isp_fix_cron(self):
        if not self.checker:
            return
        if messagebox.askyesno("Подтверждение", "Закомментировать переменную PATH в crontab?\n⚠️ Это может повлиять на другие cron-задания!", parent=self.root):
            self._run_in_thread(ispmanager_fix_cron_path, self.isp_menu_btn, self.checker)
