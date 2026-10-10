"""Тесты gui_themes.py: палитры, определение темы ОС, переключение (без Tk).

get_theme_colors — чистая функция. detect_system_theme дёргает gsettings
через subprocess: подменяем модульный `subprocess` лёгким двойником (важно:
двойник подсовывается как gui_themes.subprocess, а не глобально бьёт по
stdlib). Обработчики миксина работают с self.root.style / self.output /
self.theme_var — их заменяют записи-заглушки.
"""
import os
import subprocess
import sys
import types

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

import gui_themes
from gui_themes import (DARK_THEMES, ThemesMixin, detect_system_theme,
                        get_theme_colors)


class _FakeSubprocess:
    """Двойник модуля subprocess только для detect_system_theme."""

    SubprocessError = subprocess.SubprocessError
    OSError = OSError

    def __init__(self, returncode=0, stdout='', exc=None):
        self.returncode = returncode
        self.stdout = stdout
        self.exc = exc
        self.calls = []

    def run(self, cmd, **kwargs):
        self.calls.append((cmd, kwargs))
        if self.exc:
            raise self.exc
        return types.SimpleNamespace(returncode=self.returncode,
                                      stdout=self.stdout)


class _Style:
    def __init__(self, name='darkly', fail=False):
        self.theme = types.SimpleNamespace(name=name)
        self.fail = fail
        self.used = []

    def theme_use(self, name):
        if self.fail:
            raise ValueError('bad theme')
        self.theme.name = name
        self.used.append(name)


class _Widget:
    """Замена tk-виджету: пишет каждый config() в список."""

    def __init__(self):
        self.configs = []

    def config(self, **kw):
        self.configs.append(kw)


class _Output(_Widget):
    """Поле вывода СО скроллбаром — как tk.ScrolledText, у него vbar есть.

    apply_scrollbar_style проверяет скроллбар через hasattr(self.output,
    'vbar'), значит «скроллбара нет» — это физическое отсутствие атрибута
    (тогда берётся _Widget без vbar), а НЕ vbar = None: None прошёл бы hasattr
    и упал на .config().
    """

    def __init__(self):
        super().__init__()
        self.vbar = _Widget()


class _Var:
    def __init__(self, value=''):
        self._v = value

    def get(self):
        return self._v

    def set(self, value):
        self._v = value


class _Dialogs:
    def __init__(self):
        self.errors = []

    def showerror(self, *a, **k):
        self.errors.append(a)


class _Host(ThemesMixin):
    def __init__(self, theme='darkly', fail=False, vbar=True):
        self.root = types.SimpleNamespace(style=_Style(theme, fail))
        # vbar=False -> _Widget без атрибута vbar: hasattr обязан быть ложным
        self.output = _Output() if vbar else _Widget()
        self.theme_var = _Var(theme)
        self.current_theme = theme


def _vbar_cfg(host):
    """Последний config() скроллбара поля вывода.

    Обращение через getattr + assert, чтобы при регрессии тест падал с понятым
    сообщением, а не с «'NoneType' object has no attribute 'config'».
    """
    vbar = getattr(host.output, 'vbar', None)
    assert vbar is not None, 'хост обязан создать vbar'
    assert vbar.configs, 'apply_scrollbar_style обязан настроить скроллбар'
    return vbar.configs[-1]


# ==================== палитра ====================
class TestThemeColors:
    def test_dark_palette(self):
        colors = get_theme_colors('darkly')
        assert colors['bg'] == '#1a1a1a'
        assert colors['fg'] == '#d3d7cf'

    def test_light_palette(self):
        colors = get_theme_colors('flatly')
        assert colors['bg'] == '#ffffff'
        assert colors['fg'] == '#000000'

    def test_unknown_theme_falls_back_to_light(self):
        # всё, что не в DARK_THEMES, — светлая палитра (else-ветка)
        assert get_theme_colors('supernova')['bg'] == '#ffffff'

    def test_every_dark_theme_gets_dark_palette(self):
        for name in DARK_THEMES:
            assert get_theme_colors(name)['bg'] == '#1a1a1a', name


# ==================== определение темы ОС ====================
class TestDetectSystemTheme:
    def test_dark_gtk_theme_returns_darkly(self, monkeypatch):
        fake = _FakeSubprocess(stdout="'Yaru-dark'\n")
        monkeypatch.setattr(gui_themes, 'subprocess', fake)
        assert detect_system_theme() == 'darkly'

    def test_black_in_name_is_dark(self, monkeypatch):
        fake = _FakeSubprocess(stdout='"BlackBird"\n')  # кавычки тоже снимаются
        monkeypatch.setattr(gui_themes, 'subprocess', fake)
        assert detect_system_theme() == 'darkly'

    def test_light_theme_returns_flatly(self, monkeypatch):
        fake = _FakeSubprocess(stdout="'Yaru-light'\n")
        monkeypatch.setattr(gui_themes, 'subprocess', fake)
        assert detect_system_theme() == 'flatly'

    def test_failed_gsettings_falls_back_to_darkly(self, monkeypatch):
        fake = _FakeSubprocess(returncode=1, stdout="'Yaru-light'\n")
        monkeypatch.setattr(gui_themes, 'subprocess', fake)
        assert detect_system_theme() == 'darkly'

    def test_missing_gsettings_falls_back_to_darkly(self, monkeypatch):
        fake = _FakeSubprocess(exc=OSError('gsettings not found'))
        monkeypatch.setattr(gui_themes, 'subprocess', fake)
        assert detect_system_theme() == 'darkly'

    def test_timeout_falls_back_to_darkly(self, monkeypatch):
        # gsettings может зависнуть: timeout=2 + SubprocessError в except
        fake = _FakeSubprocess(exc=subprocess.TimeoutExpired('gsettings', 2))
        monkeypatch.setattr(gui_themes, 'subprocess', fake)
        assert detect_system_theme() == 'darkly'

    def test_queried_key_and_timeout(self, monkeypatch):
        fake = _FakeSubprocess(stdout="'Adwaita'\n")
        monkeypatch.setattr(gui_themes, 'subprocess', fake)
        detect_system_theme()
        cmd, kwargs = fake.calls[0]
        assert cmd[:2] == ['gsettings', 'get']
        assert cmd[-1] == 'gtk-theme'
        assert kwargs.get('timeout', 99) <= 2, 'нельзя вешать mainloop'


# ==================== обработчики миксина ====================
class TestOutputColors:
    def test_explicit_theme_updates_output(self):
        host = _Host()
        host.update_output_colors('flatly')
        assert host.output.configs[-1]['bg'] == '#ffffff'

    def test_none_uses_current_style_theme(self):
        host = _Host(theme='darkly')
        host.update_output_colors()
        assert host.output.configs[-1]['bg'] == '#1a1a1a'


class TestScrollbarStyle:
    def test_dark_theme_dark_trough(self):
        host = _Host()
        host.apply_scrollbar_style('darkly')
        cfg = _vbar_cfg(host)
        assert cfg['troughcolor'] == '#2a2a2a'
        assert cfg['width'] == 20

    def test_light_theme_light_trough(self):
        host = _Host(theme='flatly')
        host.apply_scrollbar_style('flatly')
        assert _vbar_cfg(host)['troughcolor'] == '#e0e0e0'

    def test_no_vbar_is_silent(self):
        # у output может не быть vbar (другая сборка виджета) — падать нельзя
        host = _Host(vbar=False)
        host.apply_scrollbar_style('darkly')


class TestSwitchAndToggle:
    def test_switch_updates_style_output_and_current(self):
        host = _Host(theme='darkly')
        host.switch_theme('flatly')
        assert host.root.style.used == ['flatly']
        assert host.output.configs[-1]['bg'] == '#ffffff'
        assert _vbar_cfg(host)['troughcolor'] == '#e0e0e0'
        assert host.current_theme == 'flatly'

    def test_switch_error_shows_messagebox_and_keeps_current(self, monkeypatch):
        host = _Host(theme='darkly', fail=True)
        dialogs = _Dialogs()
        monkeypatch.setattr(gui_themes, 'messagebox', dialogs)
        host.switch_theme('nope')
        assert len(dialogs.errors) == 1
        assert host.current_theme == 'darkly', 'сбойный тему не помечаем текущей'

    def test_toggle_dark_to_light(self):
        host = _Host(theme='darkly')
        host.toggle_theme()
        assert host.root.style.used == ['flatly']
        assert host.theme_var.get() == 'flatly'

    def test_toggle_light_to_dark(self):
        host = _Host(theme='flatly')
        host.toggle_theme()
        assert host.root.style.used == ['darkly']
        assert host.theme_var.get() == 'darkly'
