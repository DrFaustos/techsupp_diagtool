"""Панель ISPmanager: перезапуск, kill core, обновление, SSL, отключение, GeoIP, cron.

Backend-функции живут в panels.py; здесь — раскрывающееся меню
(ISPMANAGER_MENU), помощник включения/выключения и обработчики run_isp_*
с диалогами подтверждения.
"""

from tkinter import messagebox, simpledialog
from diagnostic import (
    ispmanager_restart, ispmanager_kill_core, ispmanager_update,
    ispmanager_ssl_issue, ispmanager_disable, ispmanager_disable_geoip,
    ispmanager_check_cron_path, ispmanager_fix_cron_path,
    ispmanager_panel_diag, ispmanager_logs_report, ispmanager_unlock,
    ispmanager_license_refresh, ispmanager_license_report,
    ispmanager_license_activate,
)

# Состав меню: (подпись пункта, имя метода класса), None — разделитель либо
# (подпись, [пункты]) — подменю; раскладку делает gui._fill_panel_menu.
# Разделитель отделяет повседневные действия от разрушительных (Kill core,
# отключение).
#
# Лицензия собрана в подменю: операций три (посмотреть / перетянуть под IP /
# активировать по ключу) и в плоском списке они заняли бы шесть строк с
# префиксом «Лицензия:». Порядок внутри — «сначала смотрим, потом лечим», а
# ключ стоит последним: это единственная операция здесь, которая тратит
# одноразовый ключ.
ISPMANAGER_MENU = [
    ("Диагностика панели (:1500)", "run_isp_diag"),
    ("Логи панели", "run_isp_logs"),
    ("Перезапустить панель", "run_isp_restart"),
    ("Обновить панель", "run_isp_update"),
    ("Выпустить Let's Encrypt SSL", "run_isp_ssl"),
    ("Проверить CRON PATH", "run_isp_cron"),
    ("Исправить CRON PATH", "run_isp_fix_cron"),
    ("Отключить GeoIP", "run_isp_geoip"),
    ("Лицензия ▾", [
        ("Проверить (licctl info)", "run_isp_license_check"),
        ("Обновить под IP (licctl fetch)", "run_isp_license"),
        ("Активировать по ключу", "run_isp_license_activate"),
    ]),
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

    def run_isp_license_activate(self):
        # Подтверждение ДО запроса ключа: спросить секрет, а потом отказаться,
        # — плохой разговор с оператором. В вопросе названы оба реальных риска:
        # ключ одноразовый (испорченный ввод его сжигает) и licctl не умеет
        # принимать ключ из окружения, поэтому на время команды он виден в ps.
        if not self.checker:
            return
        if not messagebox.askyesno(
            "Подтверждение",
            "Активировать лицензию ISPmanager ключом "
            "(licctl fetch ispmgr <ключ>)?\n\n"
            "⚠️ Ключ одноразовый: после успешной активации его нельзя "
            "использовать снова — только перевыпустить в Client area.\n"
            "⚠️ На время выполнения команды ключ виден в ps на сервере "
            "(у licctl нет приёма вроде mgrctl -e $ENV).\n\n"
            "Лицензия привязана к IP: если IP сменился, достаточно пункта "
            "«Обновить под IP» — он не тратит ключ.",
            parent=self.root
        ):
            return
        # show='*': ключ не должен светиться на экране, его вводят/вставляют в
        # поле, а не читают через плечо оператора.
        key = simpledialog.askstring(
            "Ключ активации",
            "Ключ активации из письма или Client area\n"
            "(одноразовый, без пробелов):",
            show='*', parent=self.root)
        if key is None:
            return
        # «Проверить» кэширует отчёт 60 секунд. После активации он обязан
        # устареть: показать оператору состояние «до» сразу после того, как мы
        # его поменяли, — значит соврать ему в лицо.
        cache = getattr(self, '_diag_cache', None)
        if isinstance(cache, dict):
            cache.pop('isp_license', None)
        self._run_in_thread(ispmanager_license_activate, self.isp_menu_btn,
                            self.checker, key)

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
