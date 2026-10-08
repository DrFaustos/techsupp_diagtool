"""Темы оформления окна: палитра поля вывода, определение темы ОС, переключение.

Вынесено из gui.py без изменений исходников: константы DARK_THEMES, LIGHT_THEMES, функции get_theme_colors, detect_system_theme, методы update_output_colors, apply_scrollbar_style, switch_theme, toggle_theme."""

from tkinter import messagebox
import subprocess



# ==================== НАСТРОЙКИ ТЕМ ====================
DARK_THEMES = ['darkly', 'cyborg', 'superhero', 'vapor', 'solar']


LIGHT_THEMES = ['flatly', 'litera', 'minty', 'pulse', 'cosmo', 'sandstone']


def get_theme_colors(theme_name):
    """Возвращает цвета для поля вывода в зависимости от темы"""
    if theme_name in DARK_THEMES:
        return {
            'bg': '#1a1a1a',
            'fg': '#d3d7cf',
            'insertbackground': 'white',
            'selectbackground': '#3465a4'
        }
    else:
        return {
            'bg': '#ffffff',
            'fg': '#000000',
            'insertbackground': 'black',
            'selectbackground': '#3465a4'
        }


def detect_system_theme():
    """
    Определяет тему ОС (Linux/GNOME) и возвращает имя темы для ttkbootstrap.
    """
    try:
        result = subprocess.run(
            ['gsettings', 'get', 'org.gnome.desktop.interface', 'gtk-theme'],
            capture_output=True, text=True, timeout=2
        )
        if result.returncode == 0:
            theme = result.stdout.strip().strip("'")
            if 'dark' in theme.lower() or 'black' in theme.lower():
                return 'darkly'
            else:
                return 'flatly'
    except (subprocess.SubprocessError, OSError):
        pass
    return 'darkly'

class ThemesMixin:
    def update_output_colors(self, theme_name=None):
        if theme_name is None:
            theme_name = self.root.style.theme.name
        colors = get_theme_colors(theme_name)
        self.output.config(
            bg=colors['bg'],
            fg=colors['fg'],
            insertbackground=colors['insertbackground'],
            selectbackground=colors['selectbackground']
        )

    def apply_scrollbar_style(self, theme_name=None):
        """Настраивает ширину и цвет вертикальной полосы прокрутки (для tk.Scrollbar)"""
        if theme_name is None:
            theme_name = self.root.style.theme.name

        # Настраиваем скроллбар напрямую (это tk.Scrollbar, не ttk)
        if hasattr(self, 'output') and hasattr(self.output, 'vbar'):
            self.output.vbar.config(
                width=20,
                bg='#0078d4',
                activebackground='#1084d4',
                troughcolor='#2a2a2a' if theme_name in DARK_THEMES else '#e0e0e0'
            )

    def switch_theme(self, theme_name):
        try:
            self.root.style.theme_use(theme_name)
            self.update_output_colors(theme_name)
            self.apply_scrollbar_style(theme_name)
            self.current_theme = theme_name
        except Exception as e:
            messagebox.showerror("Ошибка", f"Не удалось переключить тему: {e}")

    def toggle_theme(self):
        current_theme = self.root.style.theme.name
        if current_theme in DARK_THEMES:
            new_theme = 'flatly'
        else:
            new_theme = 'darkly'
        self.switch_theme(new_theme)
        self.theme_var.set(new_theme)
