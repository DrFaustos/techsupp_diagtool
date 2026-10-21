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
    ispmanager_panel_diag, ispmanager_logs_report, ispmanager_unlock,
    ispmanager_license_refresh, ispmanager_license_report,
)

# Состав меню: (подпись пункта, имя метода класса). None — разделитель:
# отделяет повседневные действия от разрушительных (Kill core, отключение).
# «Проверить» стоит перед «обновить»: сначала смотрим (только чтение), потом
# лечим — и пара лицензия/разблокировка держится рядом, это две причины
# «панель не открывается».
ISPMANAGER_MENU = [
    ("Диагностика панели (:1500)", "run_isp_diag"),
    ("Логи панели", "run_isp_logs"),
    ("Перезапустить панель", "run_isp_restart"),
    ("Обновить панель", "run_isp_update"),
    ("Выпустить Let's Encrypt SSL", "run_isp_ssl"),
    ("Проверить CRON PATH", "run_isp_cron"),
    ("Исправить CRON PATH", "run_isp_fix_cron"),
    ("Отключить GeoIP", "run_isp_geoip"),
    ("Лицензия: проверить (licctl info)", "run_isp_license_check"),
    ("Лицензия: обновить (licctl fetch)", "run_isp_license"),
    ("Разблокировать панель", "run_isp_unlock"),
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

    # ---------- ДИАГНОСТИКА «ПАНЕЛЬ НЕ ОТКРЫВАЕТСЯ» ----------

    def run_isp_diag(self):
        # Только чтение (версия, процессы, порт, API, лицензия, лог) —
        # спрашивать нечего; кеш 60 с, как у отчётов FastPanel.
        if not self.checker:
            return
        self._run_in_thread(ispmanager_panel_diag, self.isp_menu_btn,
                            self.checker, cache_key='isp_diag')

    def run_isp_logs(self):
        if not self.checker:
            return
        self._run_in_thread(ispmanager_logs_report, self.isp_menu_btn,
                            self.checker)

    def run_isp_license_check(self):
        # Только чтение (licctl info) — спрашивать нечего. Кеш 60 с, как у
        # диагностики :1500: лицензия за минуту не «оживает», а пункт кликают
        # подряд, когда разбираются с панелью.
        if not self.checker:
            return
        self._run_in_thread(ispmanager_license_report, self.isp_menu_btn,
                            self.checker, cache_key='isp_license')

    def run_isp_license(self):
        if not self.checker:
            return
        if messagebox.askyesno(
            "Подтверждение",
            "Отправить запрос на сервер лицензий ISPsystem (licctl fetch)?\n"
            "Лицензия привязана к IP панели: помогает после смены IP сервера.",
            parent=self.root
        ):
            self._run_in_thread(ispmanager_license_refresh, self.isp_menu_btn,
                                self.checker)

    def run_isp_unlock(self):
        if not self.checker:
            return
        if messagebox.askyesno(
            "Подтверждение",
            "Снять блокировку панели (mgrctl -u на ispmgr и core)?\n"
            "⚠️ Блокировка бывает штатной во время обновления: если pkgupgrade "
            "идёт прямо сейчас — дождитесь его окончания.",
            parent=self.root
        ):
            self._run_in_thread(ispmanager_unlock, self.isp_menu_btn,
                                self.checker)
