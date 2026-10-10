"""Тесты webcheck.py: SSL-сертификат, WHOIS, сканирование портов, grep по логам.

Реального SSH нет — команды перехватывает FakeSSH из support.py.
Граничные случаи (пустой домен и т.п.) живут в tests/test_diagnostic.py.
"""
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from support import FakeSSH
import webcheck as webcheck_mod

SSL_OUT = ("subject=CN = example.com\n"
           "issuer=C = US, O = Let's Encrypt, CN = R11\n"
           "notBefore=Aug 12 08:41:23 2026 GMT\n"
           "notAfter=Nov 10 08:41:22 2026 GMT\n"
           "X509v3 Subject Alternative Name:\n    DNS:example.com")


class TestSslCertReport:
    def test_valid_cert(self):
        c = FakeSSH(routes=[('-checkend', 'VALID\n'), ('-dates', SSL_OUT)])
        out = webcheck_mod.ssl_cert_report(c, 'example.com')
        assert '✅ Сертификат действителен' in out
        assert "issuer=C = US" in out

    def test_expired_cert(self):
        c = FakeSSH(routes=[('-checkend', 'EXPIRED\n'), ('-dates', SSL_OUT)])
        out = webcheck_mod.ssl_cert_report(c, 'example.com')
        assert '❌ Сертификат ИСТЁК' in out

    def test_no_cert_output(self):
        out = webcheck_mod.ssl_cert_report(FakeSSH(), 'example.com')
        assert '❌ Не удалось получить сертификат' in out

    def test_no_notafter_skips_checkend(self):
        # без notAfter вторую команду (проверку срока) слать не нужно
        c = FakeSSH(routes=[('-dates', 'subject=CN = example.com')])
        out = webcheck_mod.ssl_cert_report(c, 'example.com')
        assert c.count('-checkend') == 0
        assert '✅' not in out and '❌' not in out
        assert 'subject=CN = example.com' in out


class TestWhoisReport:
    def test_key_lines_extracted(self):
        raw = ('Domain Name: EXAMPLE.COM\n'
               'Registrar: RESOLVER WEBSITE INC.\n'
               'Creation Date: 2001-09-15T04:00:00Z\n'
               'не значимая строка\n'
               'Name Server: NS1.EXAMPLE.NET\n')
        c = FakeSSH(routes=[('whois', raw)])
        out = webcheck_mod.whois_report(c, 'example.com')
        assert 'Registrar:' in out
        assert 'Creation Date:' in out
        assert 'Name Server:' in out
        assert 'не значимая строка' not in out

    def test_unknown_format_falls_back_to_raw(self):
        c = FakeSSH(routes=[('whois', 'какой-то редкий вывод без ключей\n')])
        out = webcheck_mod.whois_report(c, 'example.com')
        assert 'какой-то редкий вывод' in out

    def test_empty_whois_error(self):
        out = webcheck_mod.whois_report(FakeSSH(), 'example.com')
        assert '❌ whois не установлен или домен не найден' in out


class TestPortScanReport:
    def test_open_ports_listed(self):
        c = FakeSSH(routes=[('ss -tulpn', 'tcp  LISTEN  0  128  *:22'),
                             ('/dev/tcp/', '  22 открыт\n')])
        out = webcheck_mod.port_scan_report(c, host='93.184.216.34')
        assert 'tcp  LISTEN  0  128  *:22' in out
        assert '22 открыт' in out
        probe = c.find('/dev/tcp/')
        assert probe is not None and '93.184.216.34/22' in probe

    def test_no_tools_no_open_ports(self):
        out = webcheck_mod.port_scan_report(FakeSSH(), host='127.0.0.1')
        assert '(ss/netstat недоступны)' in out
        assert 'ни один из типовых портов не ответил' in out


class TestGrepLogsReport:
    LOG_FILE = '/var/log/nginx/example.com.access.log\n'

    def test_matches_with_total(self):
        c = FakeSSH(routes=[('ls -1', self.LOG_FILE),
                             ('| grep', 'line A\nline B\n')])
        out = webcheck_mod.grep_logs_report(c, 'none', 'example.com', r'" 5\d\d ')
        assert 'line A' in out
        assert 'Всего строк:' in out

    def test_gz_logs_use_zcat(self):
        c = FakeSSH(routes=[('ls -1', '/var/log/nginx/example.com.access.log.gz\n'),
                             ('zcat', 'gz match\n')])
        out = webcheck_mod.grep_logs_report(c, 'none', 'example.com', '500')
        assert 'gz match' in out
        assert c.find('zcat') is not None

    def test_context_flag_when_requested(self):
        c = FakeSSH(routes=[('ls -1', self.LOG_FILE)])
        webcheck_mod.grep_logs_report(c, 'none', 'example.com', '500', context=3)
        # флаг контекста вставляется ДО -E: команда выглядит как 'grep -C 3 -E ...'
        cmd = c.find('grep -C 3')
        assert cmd is not None and '-E' in cmd

    def test_no_matches_message(self):
        c = FakeSSH(routes=[('ls -1', self.LOG_FILE)])
        out = webcheck_mod.grep_logs_report(c, 'none', 'example.com', '500')
        assert 'Совпадений не найдено.' in out


class TestListCommonReports:
    def test_both_5xx_and_404_sections(self):
        c = FakeSSH(routes=[('ls -1', '/var/log/nginx/example.com.access.log\n'),
                             ('| grep', 'matched\n')])
        out = webcheck_mod.list_common_reports(c, 'none', 'example.com')
        assert out.count('=== GREP ЛОГОВ') == 2
