"""Инвентарь хостинга: сайты, почта, DNS-зоны, досье домена.

Backend-функции живут в discovery.py; здесь — состав меню (HOSTING_MENU)
и обработчики run_host_*. В отличие от меню ISPmanager/FastPanel это меню
показывается при ЛЮБОМ подключении: инвентарь работает и на сервере без
панели (сайты — по vhost'ам, почта — по картам postfix и dovecot).

Долой «а сколько у меня вообще сайтов на сервере»: один пункт отвечает
полным списком с владельцами, docroot и версией PHP, второй — сразу
проверяет доступность каждого, третий — почту (домены, ящики, очередь),
четвёртый — DNS-зоны, пятый — досье на один домен (vhost + DNS + почта +
грабля Let's Encrypt с /etc/hosts).
"""

import tkinter as tk
from tkinter import messagebox, simpledialog

from diagnostic import (
    hosting_inventory_report, site_health_report, ssl_expiry_report,
    mail_overview_report, mail_auth_report, dns_zones_report,
    domain_detail_report, mailbox_create, mailbox_passwd, mailbox_delete,
)

# Состав меню: (подпись пункта, имя метода класса), None — разделитель, либо
# (подпись, [пункты]) — вложенное подменю. Разделитель отделяет сводные отчёты
# от точечных запросов; операции над ящиками свёрнуты в подменю — шесть
# пунктов в основном списке означали бы «интерфейс разросся», а здесь это одна
# строка. Разрушающие операции (смена пароля, удаление) живут в подменю после
# его разделителя.
HOSTING_MENU = [
    ("Полный инвентарь сервера", "run_host_inventory"),
    ("Сайты: список и доступность", "run_host_sites"),
    ("SSL: срок действия сертификатов", "run_host_ssl"),
    ("Почта: домены, ящики, очередь", "run_host_mail"),
    ("Почта: SPF/DKIM/DMARC/PTR", "run_host_mail_auth"),
    ("DNS-зоны на сервере", "run_host_zones"),
    None,
    ("Досье домена (всё об одном)", "run_host_domain"),
    ("Почтовые ящики ▸", [
        ("Создать ящик", "run_host_mb_create"),
        None,
        ("Сменить пароль ящика", "run_host_mb_passwd"),
        ("Удалить ящик", "run_host_mb_delete"),
    ]),
]


class HostingMixin:
    # ---------- МЕНЮ ХОСТИНГА ----------
    # Кнопка строится в gui.py; включает/гасит её gui_runner при подключении
    # и отключении (инвентарь не зависит от типа панели).

    def _set_hosting_menu_visible(self, show):
        # Как и у Битрикса: фон может вернуться уже после disconnect() —
        # показывать меню над закрытым соединением нельзя.
        if show and self.checker is None:
            show = False
        if show:
            self.hosting_frame.pack(side=tk.LEFT, padx=5)
            self.host_menu_btn.config(state=tk.NORMAL)
        else:
            self.hosting_frame.pack_forget()
            self.host_menu_btn.config(state=tk.DISABLED)

    # ---------- ДЕЙСТВИЯ ----------
    def run_host_inventory(self):
        if not self.checker:
            return
        self._run_in_thread(hosting_inventory_report, self.host_menu_btn,
                            self.checker, self.panel_type,
                            cache_key='host_inventory')

    def run_host_sites(self):
        if not self.checker:
            return
        self._run_in_thread(site_health_report, self.host_menu_btn,
                            self.checker, self.panel_type,
                            cache_key='host_sites')

    def run_host_ssl(self):
        # Отчёт только читает сертификаты (один TLS-хендшейк на домен) —
        # спрашивать нечего; кеш 60 с, как у остальных сводных отчётов.
        if not self.checker:
            return
        self._run_in_thread(ssl_expiry_report, self.host_menu_btn,
                            self.checker, self.panel_type,
                            cache_key='host_ssl')

    def run_host_mail(self):
        if not self.checker:
            return
        self._run_in_thread(mail_overview_report, self.host_menu_btn,
                            self.checker, self.panel_type,
                            cache_key='host_mail')

    def run_host_mail_auth(self):
        # Отчёт только читает DNS (5 dig-запросов на домен) — спрашивать
        # нечего; кеш 60 с, как у остальных сводных отчётов: прогон по сотне
        # доменов идёт минутами, второй клик подряд должен стоить ноль.
        if not self.checker:
            return
        self._run_in_thread(mail_auth_report, self.host_menu_btn,
                            self.checker, self.panel_type,
                            cache_key='host_mail_auth')

    def run_host_zones(self):
        if not self.checker:
            return
        self._run_in_thread(dns_zones_report, self.host_menu_btn,
                            self.checker, self.panel_type,
                            cache_key='host_zones')

    def run_host_domain(self):
        # Домен спрашиваем ДО фона: _run_in_thread диалоги не умеет, а без
        # домена досье строить не на чем.
        if not self.checker:
            return
        domain = simpledialog.askstring(
            "Досье домена",
            "Домен (например, example.com):",
            parent=self.root)
        if not domain or not domain.strip():
            return
        self._run_in_thread(domain_detail_report, self.host_menu_btn,
                            self.checker, domain.strip(), self.panel_type)

    # ---------- ОПЕРАЦИИ С ПОЧТОВЫМИ ЯЩИКАМИ ----------
    # Порядок один для всех трёх: сначала диалоги, потом фон. _run_in_thread
    # показывает только текст задачи — tk-диалог из рабочего потока открыть
    # нельзя, а без адреса/пароля слать панели нечего. cache_key нет ни у
    # одного: операция меняет состояние панели, и закешированный «инвентарь до
    # действия» после неё показывает старое.

    def _ask_mailbox_address(self, title, prompt):
        """Полный адрес ящика либо None (нет связи / оператор отменил)."""
        if not self.checker:
            return None
        address = simpledialog.askstring(title, prompt, parent=self.root)
        if not address or not address.strip():
            return None
        # Адрес стричь можно и нужно: случайный пробел панель превратила бы в
        # «не найден среди N ящиков», а создать бы попыталась ящик с пробелом.
        return address.strip()

    def _ask_mailbox_password(self, address):
        """Пароль как введён (НЕ strip: пробел — валидный символ пароля)."""
        password = simpledialog.askstring(
            "Пароль ящика",
            f"Пароль для {address}\n(не короче 8 символов, длина "
            f"проверяется до отправки):",
            show='*', parent=self.root)
        if not password:
            return None
        return password

    def run_host_mb_create(self):
        address = self._ask_mailbox_address(
            "Создать почтовый ящик",
            "Полный адрес ящика (user@example.com):")
        if address is None:
            return
        password = self._ask_mailbox_password(address)
        if password is None:
            return
        self._run_in_thread(mailbox_create, self.host_menu_btn,
                            self.checker, address, password, self.panel_type)

    def run_host_mb_passwd(self):
        address = self._ask_mailbox_address(
            "Сменить пароль ящика",
            "Полный адрес ящика (user@example.com):")
        if address is None:
            return
        # Подтверждение ДО запроса пароля: спрашивать секрет, а потом отказаться,
        # — плохой разговор с оператором.
        if not messagebox.askyesno(
                "Подтверждение",
                f"Сменить пароль ящика {address}?",
                parent=self.root):
            return
        password = self._ask_mailbox_password(address)
        if password is None:
            return
        self._run_in_thread(mailbox_passwd, self.host_menu_btn,
                            self.checker, address, password, self.panel_type)

    def run_host_mb_delete(self):
        address = self._ask_mailbox_address(
            "Удалить почтовый ящик",
            "Полный адрес ящика (user@example.com):")
        if address is None:
            return
        if not messagebox.askyesno(
                "Подтверждение",
                f"Удалить ящик {address}?\n"
                "⚠️ Письма в его почтовом каталоге будут удалены без "
                "возможности восстановления через панель.",
                parent=self.root):
            return
        self._run_in_thread(mailbox_delete, self.host_menu_btn,
                            self.checker, address, self.panel_type)
