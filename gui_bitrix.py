"""Меню «Битрикс»: диагностика BitrixVM — SSL, MySQL, доступ к базе, PHP, cron, почта.

Backend-функции живут в bitrix.py; здесь — состав меню (BITRIX_MENU),
обработчики run_bx_* с подтверждением для опасных действий и автопоказ меню
после подключения (_detect_bitrix вызывают из gui_runner).
"""

import threading
import tkinter as tk
from tkinter import messagebox

from diagnostic import (
    detect_bitrix_env, bitrix_sites_report,
    bitrix_ssl_report, bitrix_ssl_renew,
    bitrix_mysql_report, bitrix_mysql_tune, bitrix_db_check,
    bitrix_php_report, bitrix_cron_report, bitrix_mail_report,
)

# Состав меню: (подпись пункта, имя метода класса). None — разделитель:
# отделяет просмотр от действий, меняющих сервер.
BITRIX_MENU = [
    ("Сайты в BitrixVM", "run_bx_sites"),
    ("SSL Let's Encrypt: состояние", "run_bx_ssl"),
    ("MySQL: состояние и рекомендация", "run_bx_mysql"),
    ("Доступ к базе (dbconn.php)", "run_bx_db"),
    ("PHP: параметры и модули", "run_bx_php"),
    ("Cron-агенты Битрикс", "run_bx_cron"),
    ("Почта: postfix и mailq", "run_bx_mail"),
    None,
    ("Перевыпустить сертификаты (dehydrated)", "run_bx_ssl_renew"),
    ("MySQL: применить тюнинг", "run_bx_mysql_tune"),
]


class BitrixMixin:
    # ---------- МЕНЮ БИТРИКС ----------
    # Кнопка строится в gui.py; показ включает _detect_bitrix() после удачного
    # подключения, гасит — _set_panel_menus_visible(None) при дисконнекте.

    def _detect_bitrix(self):
        """Проверить в фоне, является ли сервер BitrixVM, и показать меню."""
        if not self.checker:
            return

        def worker():
            try:
                found = detect_bitrix_env(self.checker)
            except Exception:
                found = False
            self._post_ui(self._set_bitrix_menu_visible, found)

        threading.Thread(target=worker, daemon=True).start()

    def _set_bitrix_menu_visible(self, show):
        # Фон check может вернуться уже после disconnect(): показывать меню
        # над закрытым соединением нельзя — команды всё равно не выполнятся.
        if show and self.checker is None:
            show = False
        if show:
            self.bitrix_frame.pack(side=tk.LEFT, padx=5)
            self.bx_menu_btn.config(state=tk.NORMAL)
        else:
            self.bitrix_frame.pack_forget()
            self.bx_menu_btn.config(state=tk.DISABLED)

    # ---------- ДЕЙСТВИЯ ----------
    def run_bx_sites(self):
        if not self.checker:
            return
        self._run_in_thread(bitrix_sites_report, self.bx_menu_btn, self.checker,
                            cache_key='bx_sites')

    def run_bx_ssl(self):
        if not self.checker:
            return
        self._run_in_thread(bitrix_ssl_report, self.bx_menu_btn, self.checker,
                            cache_key='bx_ssl')

    def run_bx_mysql(self):
        if not self.checker:
            return
        self._run_in_thread(bitrix_mysql_report, self.bx_menu_btn, self.checker,
                            cache_key='bx_mysql')

    def run_bx_db(self):
        if not self.checker:
            return
        self._run_in_thread(bitrix_db_check, self.bx_menu_btn, self.checker)

    def run_bx_php(self):
        if not self.checker:
            return
        self._run_in_thread(bitrix_php_report, self.bx_menu_btn, self.checker,
                            cache_key='bx_php')

    def run_bx_cron(self):
        if not self.checker:
            return
        self._run_in_thread(bitrix_cron_report, self.bx_menu_btn, self.checker,
                            cache_key='bx_cron')

    def run_bx_mail(self):
        if not self.checker:
            return
        self._run_in_thread(bitrix_mail_report, self.bx_menu_btn, self.checker,
                            cache_key='bx_mail')

    def run_bx_ssl_renew(self):
        if not self.checker:
            return
        if messagebox.askyesno(
            "Подтверждение",
            "Запустить dehydrated -c (перевыпуск Let's Encrypt)?\n"
            "⚠️ До 1-2 минут. При лимите Let's Encrypt (5 ошибок/час на домен) "
            "новый выпуск блокируется на неделю.",
            parent=self.root
        ):
            self._run_in_thread(bitrix_ssl_renew, self.bx_menu_btn, self.checker)

    def run_bx_mysql_tune(self):
        if not self.checker:
            return
        if messagebox.askyesno(
            "Подтверждение",
            "Записать /etc/my.cnf.d/bitrix-tuning.cnf с расчётом под RAM "
            "сервера?\n⚠️ Параметры применятся только после перезапуска mysqld "
            "(сайты отвалятся на 2-5 секунд). Текущий my.cnf не меняется.",
            parent=self.root
        ):
            self._run_in_thread(bitrix_mysql_tune, self.bx_menu_btn, self.checker)
