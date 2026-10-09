"""Страховка для gui.py перед и после нарезки на модули.

Два слоя:
1. Статический (без дисплея): все `self.<имя>`, которые использует код GUI,
   обязаны быть либо определены как метод, либо присвоены как атрибут где-то в
   gui*.py. Когда метод переносят в отдельный mixin-файл и теряют импорт или
   имя — падает именно этот тест, а не приложение у оператора.
2. Дымовой (нужен X11/Xvfb): окно реально собирается, виджеты на месте,
   кнопки до подключения заблокированы, смена темы не роняет интерфейс.
"""
import ast
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

import pytest

import gui as gui_mod


def gui_sources():
    """Все модули GUI (gui.py и будущие gui_*.py) — источник для анализа."""
    out = []
    for name in sorted(os.listdir(ROOT)):
        if name.startswith('gui') and name.endswith('.py'):
            out.append(os.path.join(ROOT, name))
    return out


def collect_defs_and_uses(paths):
    """Возвращает (определено, используется) имён self-атрибутов по AST."""
    defined = set()
    used = set()
    for path in paths:
        tree = ast.parse(open(path, encoding='utf-8').read(), filename=path)
        for node in ast.walk(tree):
            # методы (в т.ч. в mixin-классах и модульные функции)
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                defined.add(node.name)
            # self.<name> = ... / self.<name>: тип = ...
            elif isinstance(node, ast.Assign):
                for tgt in node.targets:
                    if isinstance(tgt, ast.Attribute) and \
                            isinstance(tgt.value, ast.Name) and tgt.value.id == 'self':
                        defined.add(tgt.attr)
            elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Attribute) \
                    and isinstance(node.target.value, ast.Name) and node.target.value.id == 'self':
                defined.add(node.target.attr)
            # for self.x in ... / with ... as self.x — тоже объявляют атрибут
            elif isinstance(node, (ast.For, ast.AsyncFor, ast.withitem)) or \
                    isinstance(node, ast.comprehension):
                tgt = node.target if not isinstance(node, ast.withitem) else node.optional_vars
                if isinstance(tgt, ast.Attribute) and isinstance(tgt.value, ast.Name) \
                        and tgt.value.id == 'self':
                    defined.add(tgt.attr)
            # self.<name> где угодно (в т.ч. self.x += ..., del self.x)
            if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name) \
                    and node.value.id == 'self':
                used.add(node.attr)
    return defined, used


def collect_callback_names(paths):
    """Имена методов, на которые ссылается command=self.<имя> (в т.ч. в lambda).

    Так виджеты, привязанные к `self.run_full`, не останутся висячими, если
    метод перенесли в mixin и забыли подмешать класс.
    """
    names = set()
    for path in paths:
        tree = ast.parse(open(path, encoding='utf-8').read(), filename=path)
        for node in ast.walk(tree):
            for kw in getattr(node, 'keywords', None) or []:
                if kw.arg != 'command':
                    continue
                for sub in ast.walk(kw.value):
                    if isinstance(sub, ast.Attribute) and \
                            isinstance(sub.value, ast.Name) and sub.value.id == 'self':
                        names.add(sub.attr)
    return names


class TestNoLostSelfAttributes:
    def test_every_self_reference_is_defined(self):
        paths = gui_sources()
        assert paths, 'не найдено ни одного gui*.py'
        defined, used = collect_defs_and_uses(paths)
        missing = used - defined
        assert not missing, (
            f'используются, но нигде не определены (потеряны при переносе?): '
            f'{sorted(missing)}'
        )

    def test_widget_callbacks_exist_on_class(self):
        """Каждый command=self.foo из разметки обязан существовать на классе.

        create_widgets() привязывает кнопки к методам; если метод уехал в
        неиспользуемый mixin, AttributeError всплывёт только по клику — ловим
        заранее, без реального клика.
        """
        callbacks = collect_callback_names(gui_sources())
        assert callbacks, 'не найдено ни одной кнопки с command=self.*'
        lost = sorted(n for n in callbacks
                      if not hasattr(gui_mod.DiagnosticApp, n))
        assert not lost, f'кнопки ссылаются на несуществующие методы: {lost}'

    def test_isp_menu_entries_bound(self):
        """Каждый пункт ISPMANAGER_MENU обязан вести на реальный метод класса.

        Меню собирается через getattr, поэтому `command=self.*`-скан его не
        видит; проверяем состав списка напрямую.
        """
        from gui_isp import ISPMANAGER_MENU
        methods = [m for item in ISPMANAGER_MENU if item is not None for m in (item[1],)]
        assert methods, 'ISPMANAGER_MENU пуст'
        lost = sorted(m for m in methods if not hasattr(gui_mod.DiagnosticApp, m))
        assert not lost, f'пункты меню ссылаются на несуществующие методы: {lost}'


class TestMaskSecrets:
    """Лог пишется в файл — пароли/токены в нём быть не должно."""

    def test_password_masked(self):
        assert gui_mod.DiagnosticApp._mask_secrets('password=hunter2') == 'password=***'

    def test_token_and_key_masked(self):
        assert 'secret123' not in gui_mod.DiagnosticApp._mask_secrets('token: secret123')
        assert 'abc' not in gui_mod.DiagnosticApp._mask_secrets('api_key=abc')
        assert 'zzz' not in gui_mod.DiagnosticApp._mask_secrets('SECRET: zzz')

    def test_ordinary_text_untouched(self):
        line = 'nginx: active /var/log/nginx/error.log'
        assert gui_mod.DiagnosticApp._mask_secrets(line) == line

    def test_empty_and_none_safe(self):
        assert gui_mod.DiagnosticApp._mask_secrets('') == ''
        assert gui_mod.DiagnosticApp._mask_secrets(None) is None


def _make_app():
    """Создаёт окно; без дисплея пропускает тест, а не валит прогон."""
    try:
        return gui_mod.DiagnosticApp()
    except Exception as exc:  # TclError: no display name / cannot connect
        pytest.skip(f'GUI недоступна без дисплея: {type(exc).__name__}: {exc}')


@pytest.fixture()
def app():
    instance = _make_app()
    yield instance
    try:
        instance.root.destroy()
    except Exception:
        pass


class TestWindowBuilds:
    def test_key_widgets_exist(self, app):
        for attr in ('root', 'output', 'cmd_entry', 'connect_btn', 'full_btn',
                     'disk_btn', 'send_btn', 'cancel_btn', 'ispmanager_frame',
                     'isp_menu_btn', 'isp_menu',
                     'ip_var', 'port_var', 'user_var', 'password_var', 'key_var'):
            assert hasattr(app, attr), f'нет виджета/поля {attr}'

    def test_diagnostic_buttons_disabled_before_connect(self, app):
        import tkinter as tk
        assert app.checker is None
        for attr in ('full_btn', 'disk_btn', 'network_btn', 'firewall_btn',
                     'logs_btn', 'send_btn', 'cancel_btn', 'isp_menu_btn'):
            # cget отдаёт Tcl-объект, а не str — сравниваем приведённое значение
            state = str(getattr(app, attr).cget('state'))
            assert state == tk.DISABLED, f'{attr} активен до подключения ({state})'

    def test_connect_button_ready(self, app):
        import tkinter as tk
        assert str(app.connect_btn.cget('state')) == tk.NORMAL
        assert 'Подключиться' in str(app.connect_btn.cget('text'))

    def test_log_appends_to_output(self, app):
        import tkinter as tk
        before = app.output.get('1.0', tk.END)
        app.log('проверочная строка')
        after = app.output.get('1.0', tk.END)
        assert after.startswith(before.rstrip('\n'))
        assert 'проверочная строка' in after[len(before.rstrip('\n')):]

    def test_theme_switch_updates_output_colors(self, app):
        theme = 'light' if app.current_theme in gui_mod.DARK_THEMES else 'dark'
        names = (gui_mod.LIGHT_THEMES if theme == 'light' else gui_mod.DARK_THEMES)
        app.switch_theme(names[0])
        assert app.current_theme == names[0]
        assert app.output.cget('bg') == gui_mod.get_theme_colors(names[0])['bg']
