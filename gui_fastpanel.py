"""Панель FastPanel: состояние, логи, перезапуск панели и веб-стека.

Backend-функции живут в panels.py; здесь — состав меню (FASTPANEL_MENU)
и обработчики run_fp_* с подтверждением для перезапусков.
"""

from tkinter import messagebox
from diagnostic import (
    fastpanel_status, fastpanel_logs, fastpanel_restart, fastpanel_restart_web,
)

# Состав меню: (подпись пункта, имя метода класса). None — разделитель перед
# действиями, на время которых сайты становятся недоступны.
FASTPANEL_MENU = [
    ("Состояние панели", "run_fp_status"),
    ("Логи панели", "run_fp_logs"),
    None,
    ("Перезапустить панель", "run_fp_restart"),
    ("Перезапустить nginx + php-fpm", "run_fp_restart_web"),
]


class FastpanelMixin:
    # ---------- МЕНЮ FastPanel ----------
    def run_fp_status(self):
        if not self.checker:
            return
        self._run_in_thread(fastpanel_status, self.fp_menu_btn, self.checker,
                            cache_key='fp_status')

    def run_fp_logs(self):
        if not self.checker:
            return
        self._run_in_thread(fastpanel_logs, self.fp_menu_btn, self.checker,
                            cache_key='fp_logs')

    def run_fp_restart(self):
        if not self.checker:
            return
        if messagebox.askyesno(
            "Подтверждение",
            "Перезапустить службу панели FastPanel?\n"
            "Сайты продолжат работать; веб-интерфейс панели пропадёт "
            "на несколько секунд.",
            parent=self.root
        ):
            self._run_in_thread(fastpanel_restart, self.fp_menu_btn, self.checker)

    def run_fp_restart_web(self):
        if not self.checker:
            return
        if messagebox.askyesno(
            "Подтверждение",
            "Перезапустить nginx и все службы php*-fpm?\n"
            "⚠️ На время перезапуска сайты недоступны (обычно 1-3 секунды).",
            parent=self.root
        ):
            self._run_in_thread(fastpanel_restart_web, self.fp_menu_btn, self.checker)
