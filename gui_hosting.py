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
from tkinter import simpledialog

from diagnostic import (
    hosting_inventory_report, site_health_report, mail_overview_report,
    dns_zones_report, domain_detail_report,
)

# Состав меню: (подпись пункта, имя метода класса). None — разделитель:
# отделяет сводные отчёты от точечного запроса по конкретному домену.
HOSTING_MENU = [
    ("Полный инвентарь сервера", "run_host_inventory"),
    ("Сайты: список и доступность", "run_host_sites"),
    ("Почта: домены, ящики, очередь", "run_host_mail"),
    ("DNS-зоны на сервере", "run_host_zones"),
    None,
    ("Досье домена (всё об одном)", "run_host_domain"),
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

    def run_host_mail(self):
        if not self.checker:
            return
        self._run_in_thread(mail_overview_report, self.host_menu_btn,
                            self.checker, self.panel_type,
                            cache_key='host_mail')

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
