"""Юнит-тесты для чистых функций диагностики.

Запуск:
    venv/bin/pytest -q
или:
    venv/bin/python -m pytest -q
"""
import os
import sys

# Чтобы импортировать модули проекта из корня, даже если pytest запущен из tests/
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

import pytest

from common import q
from logs import parse_access_log_line, filter_by_date
import files as files_mod


# ==================== common.q ====================
class TestQuote:
    def test_plain_path(self):
        assert q('/etc/nginx/nginx.conf') == '/etc/nginx/nginx.conf'

    def test_spaces_are_quoted(self):
        assert q('/etc/my dir/file.conf') == "'/etc/my dir/file.conf'"

    def test_command_substitution_is_neutralized(self):
        # shlex.quote оборачивает в одинарные кавычки -> $(...) не выполнится
        result = q('x$(whoami)')
        assert result.startswith("'")
        assert result.endswith("'")
        assert '$(' in result

    def test_empty_string(self):
        assert q('') == "''"


# ==================== logs.parse_access_log_line ====================
class TestParseAccessLog:
    COMBINED = (
        '127.0.0.1 - - [10/Oct/2024:13:55:36 +0300] '
        '"GET /index.html HTTP/1.1" 200 1234 "-" "curl/8.0"'
    )

    def test_combined_format(self):
        entry = parse_access_log_line(self.COMBINED)
        assert entry is not None
        assert entry['ip'] == '127.0.0.1'
        assert entry['status'] == '200'
        assert entry['request'] == 'GET /index.html HTTP/1.1'
        assert entry['agent'] == 'curl/8.0'

    def test_common_format_without_referer_agent(self):
        line = '1.2.3.4 - - [10/Oct/2024:13:55:36 +0300] "GET / HTTP/1.1" 404 0'
        entry = parse_access_log_line(line)
        assert entry is not None
        assert entry['status'] == '404'
        # отсутствующие поля заполняются прочерком
        assert entry['referer'] == '-'
        assert entry['agent'] == '-'

    def test_garbage_returns_none(self):
        assert parse_access_log_line('this is not a log line') is None
        assert parse_access_log_line('') is None


# ==================== logs.filter_by_date ====================
def _entry(datestr):
    return {'time': f'{datestr}:13:55:36 +0300'}


class TestFilterByDate:
    def test_matches_all(self):
        e = _entry('10/Oct/2024')
        assert filter_by_date(e) is True
        assert filter_by_date(e, year=2024) is True
        assert filter_by_date(e, month=10) is True
        assert filter_by_date(e, day=10) is True

    def test_year_mismatch(self):
        assert filter_by_date(_entry('10/Oct/2024'), year=2023) is False

    def test_month_mismatch(self):
        assert filter_by_date(_entry('10/Oct/2024'), month=9) is False

    def test_day_mismatch(self):
        assert filter_by_date(_entry('10/Oct/2024'), day=11) is False

    def test_none_entry(self):
        assert filter_by_date(None) is False

    def test_malformed_time(self):
        assert filter_by_date({'time': 'garbage'}) is False
        assert filter_by_date({'time': ''}) is False

    def test_unknown_month_name(self):
        # IndexError внутри -> False, без исключения
        assert filter_by_date({'time': '10/Xxx/2024:00:00:00'}) is False


# ==================== files.replace_ipv4 / replace_ipv6 ====================
class FakeChecker:
    """Минимальная заглушка SSH-клиента, пишет все команды."""

    def __init__(self):
        self.commands = []

    def run(self, cmd):
        self.commands.append(cmd)
        return '', '', 0

    def exec_command(self, cmd):
        self.commands.append(cmd)
        return '', ''

    def _find_cmd(self, needle):
        for c in self.commands:
            if needle in c:
                return c
        return None


class TestReplaceIp:
    def test_ipv4_command_escapes_both_ips(self):
        c = FakeChecker()
        files_mod.replace_ipv4(c, '123.123.123.123', '10.20.30.40')
        cmd = c._find_cmd('find /etc')
        assert cmd is not None
        assert r'123\.123\.123\.123' in cmd
        assert r'10\.20\.30\.40' in cmd
        assert "-name \"*.conf\"" in cmd

    def test_ipv4_rejects_invalid(self):
        c = FakeChecker()
        # 321 — недопустимый октет; также попытка инъекции через ;
        for bad in ('321.321.321.321', '1.1.1.1; rm -rf /', 'not-an-ip'):
            c.commands.clear()
            out = files_mod.replace_ipv4(c, bad, '10.0.0.1')
            assert c._find_cmd('find /etc') is None
            assert '❌' in out

    def test_ipv6_command_basic(self):
        c = FakeChecker()
        files_mod.replace_ipv6(c, 'fff:fff:fff:fff:fff::fff', 'ddd:ddd:ddd:ddd:ddd::ddd')
        cmd = c._find_cmd('find /etc')
        assert cmd is not None
        assert 'fff:fff:fff:fff:fff::fff' in cmd
        assert 'ddd:ddd:ddd:ddd:ddd::ddd' in cmd
        assert cmd.endswith('{} +')

    def test_ipv6_rejects_injection(self):
        c = FakeChecker()
        out = files_mod.replace_ipv6(c, "a::a/ -e 's/.*/pwned/; #", 'b::b')
        assert c._find_cmd('find /etc') is None
        assert '❌' in out

    def test_ipv6_makes_etc_backup(self):
        c = FakeChecker()
        files_mod.replace_ipv6(c, 'a::a', 'b::b')
        assert c._find_cmd('tar czf') is not None
