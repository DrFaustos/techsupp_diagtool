"""Диалог установки SSL-сертификата: домен + PEM-секции, модалка.

Миксин SslInstallMixin — ОДИН builder на два режима, потому что раскладка
секций — единственное отличие:
  * bitrix — crt (лист) + chain (промежуточные) + key: дефолтный расклад
    dehydrated в BitrixVM;
  * plain  — fullchain (лист+промежуточные одним куском) + key: директивы
    nginx/apache едят именно fullchain.
Глубокую проверку (PEM, пара cert<->key, домен как компонент пути) делает
бэкенд ssl_install.py по коду возврата — диалог обязан лишь НЕ ПУСТОЕ собрать
и не дать закрыть окно мусором без единого PEM-блока: прогон с заведомо
битым материалом всё равно честен, но гонять ради пустоты SSH-канал незачем.

Тесты (test_gui_hosting/test_gui_bitrix) подменяют _open_ssl_install_dialog
на двуящик: живой Tk-код окна проверяется прогоном CI под Xvfb, а логика
обработчиков — без дисплея (тот же разделён, что у всех gui-диалогов).
"""

import tkinter as tk
from tkinter import messagebox, scrolledtext

import ttkbootstrap as tb


class SslInstallMixin:
    def _open_ssl_install_dialog(self, mode):
        """Собрать материал; вернуть dict или None (отмена/закрытие).

        Возврат — НЕ валидация: только «не пусто». dict:
        {'domain', 'sections': {имя: текст}}; имена секций —
        crt/chain/key для bitrix, fullchain/key для plain.
        """
        bitrix = (mode == 'bitrix')
        labels = (('Лист — секция crt', 'Промежуточные — секция chain',
                   'Приватный ключ — секция key'),
                  ('fullchain: лист + промежуточные', 'Приватный ключ — key'))
        fields = labels[0] if bitrix else labels[1]
        keys = ('crt', 'chain', 'key') if bitrix else ('fullchain', 'key')

        dialog = tb.Toplevel(self.root)
        dialog.title('Установка SSL-сертификата — '
                     + ('BitrixVM (crt/chain/key)' if bitrix
                        else 'nginx/apache (fullchain/key)'))
        dialog.geometry('780x620')
        dialog.transient(self.root)
        dialog.grab_set()

        result = {}
        domain_var = tk.StringVar()
        tb.Label(dialog, text='Домен сертификата:',
                 bootstyle='inverse-secondary').pack(anchor='w', padx=8,
                                                     pady=(6, 0))
        tb.Entry(dialog, textvariable=domain_var, width=64).pack(
            anchor='w', padx=8)
        texts = {}
        for key, caption in zip(keys, fields):
            tb.Label(dialog, text=caption + ' (вставить PEM целиком):',
                     bootstyle='inverse-secondary').pack(anchor='w',
                                                         padx=8, pady=(6, 0))
            box = scrolledtext.ScrolledText(dialog, height=6 if bitrix else 7,
                                            wrap=tk.CHAR,
                                            font=('Courier', 9))
            box.pack(fill=tk.BOTH, expand=True, padx=8)
            texts[key] = box

        def on_install():
            material = {'domain': domain_var.get().strip(),
                        'sections': {k: texts[k].get('1.0', tk.END).strip()
                                     for k in keys}}
            missing = [k for k, v in material['sections'].items() if not v]
            if not material['domain'] or missing:
                messagebox.showerror(
                    'Не заполнено',
                    'Нужны домен и все секции; пусто: '
                    + ', '.join((['домен'] if not material['domain'] else [])
                                + missing),
                    parent=dialog)
                return
            result.update(material)
            dialog.destroy()

        tb.Button(dialog, text='Установить', command=on_install,
                  bootstyle='success').pack(side=tk.BOTTOM, padx=8, pady=8)
        tb.Button(dialog, text='Отмена', command=dialog.destroy,
                  bootstyle='secondary').pack(side=tk.BOTTOM, padx=8, pady=8)
        tb.Label(dialog, bootstyle='secondary', wraplength=720, justify='left',
                 text='Модуль НЕ правит vhost\'ы: отчёт назовёт пути и '
                      'готовые директивы, а веб-сервер перезагрузит только '
                      'с пройденным configtest. Ключ ляжет файлом 0600, '
                      'временные PEM убираются всегда.').pack(
            side=tk.BOTTOM, anchor='w', padx=8)
        dialog.wait_window()
        return result or None
