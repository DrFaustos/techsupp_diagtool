"""Тесты gui_output.py: маскирование секретов, история команд, автодополнение.

SECURITY.md требует не ослаблять маскирование секретов в выводе/отчётах,
поэтому _mask_secrets (чистый статический метод) и путь log() -> logger
покрываются в первую очередь и без Tk-дисплея. Навигация по истории и
автодополнение работают с self.cmd_entry, который подменён лёгкой заглушкой.
"""
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from gui_output import OutputMixin


# ==================== заглушки для log()/истории ====================
class _Entry:
    """Минимальная замена tkinter-поля ввода (get/delete/insert/focus_set)."""

    def __init__(self, value=''):
        self._v = value

    def get(self):
        return self._v

    def delete(self, start, end):
        self._v = ''

    def insert(self, index, text):
        self._v = text

    def focus_set(self):
        pass


class _Output:
    def __init__(self):
        self.lines = []

    def insert(self, index, text):
        self.lines.append(text)

    def see(self, index):
        pass


class _Logger:
    def __init__(self):
        self.records = []

    def info(self, msg):
        self.records.append(msg)


class _Host(OutputMixin):
    def __init__(self, history=None):
        self.output = _Output()
        self._logger = _Logger()
        self.cmd_entry = _Entry()
        self.cmd_history = list(history or [])
        self.history_index = len(self.cmd_history)


# ==================== маскирование секретов ====================
class TestMaskSecrets:
    # staticmethod обязателен: записанный атрибутом класса статический метод
    # вызывается как self.MASK(x) с передачей self (получается лишний аргумент).
    MASK = staticmethod(OutputMixin._mask_secrets)

    def test_password_equals_masked(self):
        assert self.MASK('password=hunter2') == 'password=***'

    def test_password_colon_with_spaces(self):
        assert self.MASK('password : hunter2') == 'password : ***'

    def test_passwd_and_pass_variants(self):
        assert self.MASK('passwd=abc123') == 'passwd=***'
        assert self.MASK('pass=abc123') == 'pass=***'

    def test_case_insensitive_prefix_kept(self):
        # ключ сохраняется как есть, значение заменяется
        assert self.MASK('PASSWORD=hunter2') == 'PASSWORD=***'

    def test_token_key_secret(self):
        assert self.MASK('token=xyz') == 'token=***'
        assert self.MASK('api_key=xyz') == 'api_key=***'
        assert self.MASK('API-KEY=xyz') == 'API-KEY=***'
        assert self.MASK('secret=xyz') == 'secret=***'

    def test_multiple_secrets_in_one_line(self):
        # значения — различимые токены: однобуквенные ('a') встречались бы внутри
        # самих ключей ('password'), и проверка 'a' not in out была бы ложной
        out = self.MASK('password=AAA1 token=BBB2 secret=CCC3')
        assert 'AAA1' not in out and 'BBB2' not in out and 'CCC3' not in out
        assert out == 'password=*** token=*** secret=***'

    def test_embedded_key_is_masked(self):
        # 'dbpassword=' содержит 'password=' -> маска обязана сработать
        assert self.MASK('dbpassword=topsecret') == 'dbpassword=***'

    def test_plain_command_untouched(self):
        cmd = 'systemctl restart nginx && tail -n 50 /var/log/nginx/error.log'
        assert self.MASK(cmd) == cmd

    def test_bare_key_without_value_untouched(self):
        # нет ':=' со значением -> менять нечего
        assert self.MASK('password') == 'password'

    def test_empty_and_none_passthrough(self):
        assert self.MASK('') == ''
        assert self.MASK(None) is None

    def test_secret_value_not_present_after_mask(self):
        out = self.MASK(' connecting with password=S3cr3t! to mysql')
        assert 'S3cr3t!' not in out
        assert 'password=***' in out


class TestLogMasksBeforeFileLog:
    """Регрессия SECURITY: в файл-лог секрет уходит уже замаскированным, а
    в оконный виджет (output) — как есть."""

    def test_logger_gets_masked_text(self):
        h = _Host()
        h.log('mysql -u root password=SuperSecret')
        assert h._logger.records == ['mysql -u root password=***']
        assert 'SuperSecret' not in h._logger.records[0]

    def test_output_widget_gets_raw_text(self):
        # в виджет текст уходит как есть (плюс перевод строки) и НЕ замаскированным
        h = _Host()
        h.log('password=topsecret')
        assert h.output.lines == ['password=topsecret\n']

    def test_dead_logger_does_not_break_log(self):
        class Boom(_Logger):
            def info(self, msg):
                raise RuntimeError('файл лога закрыт')

        h = _Host()
        h._logger = Boom()
        h.log('anything')          # не должно бросить наружу
        assert h.output.lines == ['anything\n']


# ==================== история команд (стрелки вверх/вниз) ====================
class TestHistoryNavigation:
    def test_up_no_history_is_break_no_change(self):
        h = _Host(history=[])
        assert h.history_up(None) == 'break'
        assert h.cmd_entry.get() == ''

    def test_up_walks_backwards(self):
        h = _Host(history=['a', 'b', 'c'])   # history_index == 3 (конец)
        h.history_up(None)
        assert h.cmd_entry.get() == 'c' and h.history_index == 2
        h.history_up(None)
        assert h.cmd_entry.get() == 'b' and h.history_index == 1
        h.history_up(None)
        assert h.cmd_entry.get() == 'a' and h.history_index == 0
        # на вершине ещё один вверх не уходит за границу
        h.history_up(None)
        assert h.cmd_entry.get() == 'a' and h.history_index == 0

    def test_down_walks_forward_then_clears(self):
        h = _Host(history=['a', 'b', 'c'])
        h.history_index = 0
        h.cmd_entry._v = 'a'
        h.history_down(None)
        assert h.cmd_entry.get() == 'b' and h.history_index == 1
        h.history_down(None)
        assert h.cmd_entry.get() == 'c' and h.history_index == 2
        h.history_down(None)          # выход за конец: поле очищается
        assert h.cmd_entry.get() == '' and h.history_index == 3


# ==================== автодополнение по Tab ====================
class TestAutocomplete:
    def test_empty_current_returns_none(self):
        h = _Host(history=['git status'])
        assert h.autocomplete(None) is None

    def test_completes_first_prefix_match(self):
        h = _Host(history=['git status', 'git log', 'ls'])
        h.cmd_entry._v = 'git '
        assert h.autocomplete(None) == 'break'
        assert h.cmd_entry.get() == 'git status'

    def test_no_match_leaves_entry_unchanged(self):
        h = _Host(history=['git status'])
        h.cmd_entry._v = 'zzz'
        assert h.autocomplete(None) == 'break'
        assert h.cmd_entry.get() == 'zzz'
