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
import discovery
import webcheck as webcheck_mod

SSL_OUT = ("subject=CN = example.com\n"
           "issuer=C = US, O = Let's Encrypt, CN = R11\n"
           "notBefore=Aug 12 08:41:23 2026 GMT\n"
           "notAfter=Nov 10 08:41:22 2026 GMT\n"
           "X509v3 Subject Alternative Name:\n    DNS:example.com")


class TestSslCertReport:
    """Срок действия сертификата: три состояния, а не «действителен / ИСТЁК».

    Прежний вердикт строился строкой `'VALID' in out_days` из ВТОРОЙ команды
    (`openssl x509 -noout -checkend 0`), а её код возврата был выброшен.
    `timeout 10`, отсутствие openssl и разорванное соединение дают пустой
    вывод — значит «VALID» нет — и отчёт печатал «❌ Сертификат ИСТЁК».
    Оператор ехал перевыпускать сертификат, которого на этом порту, возможно,
    и нет. Это закон «не проверено ≠ провалено», нарушенный в худшую сторону:
    ложная беда дороже честного «не видно».

    Вторая половина той же беды: `-checkend 0` отвечает только «истёк ли
    СЕЙЧАС», поэтому сертификат, умирающий завтра, был «✅ действителен».
    """

    OK = SSL_OUT + '\nCERT=87'
    EXPIRED = SSL_OUT + '\nCERT=-5'
    SOON = SSL_OUT + '\nCERT=3'
    UNKNOWN = SSL_OUT + '\nCERT=none'

    def _report(self, answer):
        return webcheck_mod.ssl_cert_report(
            FakeSSH(routes=[('-dates', answer)]), 'example.com')

    def test_valid_cert_shows_the_exact_leftover(self):
        out = self._report(self.OK)
        assert '✅ SSL осталось 87 дн.' in out
        assert "issuer=C = US" in out                 # данные не потерялись

    def test_expired_cert_says_how_long_ago(self):
        assert '❌ SSL ИСТЁК 5 дн. назад' in self._report(self.EXPIRED)

    def test_dying_in_three_days_is_not_reported_as_valid(self):
        # LE живёт 90 дней: «осталось 3» — это «чинить сегодня», а не зелёное
        # «действителен». Именно это -checkend 0 и не умел сказать.
        out = self._report(self.SOON)
        assert '⚠️ SSL осталось 3 дн.' in out
        assert '✅' not in out

    def test_expiry_that_could_not_be_computed_is_not_an_expiration(self):
        # Сертификат есть, а срок посчитать не удалось (нет GNU date, редкий
        # формат notAfter). «ИСТЁК» здесь отправил бы чинить не то.
        out = self._report(self.UNKNOWN)
        assert 'ИСТЁК' not in out and 'действителен' not in out
        assert 'срок действия не определён' in out

    def test_unreachable_cert_is_not_reported_as_expired(self):
        out = webcheck_mod.ssl_cert_report(FakeSSH(), 'example.com')
        assert 'Не удалось получить сертификат' in out
        assert 'ИСТЁК' not in out

    def test_wording_is_the_one_used_by_hosting_reports(self):
        # Подпись обязана быть той же, что в сводке доступности и в «Досье
        # домена» (discovery.cert_days_label): две формулировки одной беды
        # однажды разъехались бы, и оператор не узнал бы свою беду в другом
        # отчёте.
        label = discovery.cert_days_label(-5)
        assert label in self._report(self.EXPIRED)
        assert discovery.cert_days_label(87) in self._report(self.OK)

    def test_one_handshake_per_report(self):
        # notAfter уже лежит в первом ответе: второй TLS-хендшейк ради одной
        # строки стоил вдвое дороже и заводил второй источник правды о том же
        # сертификате.
        c = FakeSSH(routes=[('-dates', self.OK)])
        webcheck_mod.ssl_cert_report(c, 'example.com')
        assert c.count('s_client') == 1
        assert '-checkend' not in ' '.join(c.commands)

    def test_report_without_expiry_data_shows_no_verdict(self):
        # Ни notAfter, ни CERT: вердикта нет — и это не «всё в порядке», и не
        # «истёк». Молчание с данными в руках честнее догадки.
        c = FakeSSH(routes=[('-dates', 'subject=CN = example.com')])
        out = webcheck_mod.ssl_cert_report(c, 'example.com')
        assert 'subject=CN = example.com' in out
        assert '✅' not in out and '❌' not in out

    def test_machine_line_is_not_shown_to_the_operator(self):
        # CERT= — служебная строка, которой мы дополнили команду ради точного
        # остатка (дни считаем на сервере: дата машины оператора к выпуску
        # сертификата отношения не имеет). Печатать её в «сыром выводе openssl»
        # нельзя: оператор принял бы её за часть сертификата.
        out = self._report(self.OK)
        assert 'CERT=' not in out

    def test_command_is_valid_shell(self):
        # Команды уходят на сервер как есть — разбор shlex обязан сходиться,
        # иначе скобки и $() разъедутся уже в ssh и отчёт соврёт про «нет
        # openssl» там, где сломался синтаксис.
        import shlex
        joined = ' '.join(shlex.split(webcheck_mod.ssl_cert_days_cmd(
            r"ex.com', \$(&; x", port=8443)))
        assert 'ex.com' in joined and 'notAfter=' in joined
        assert '8443' in joined

    def test_no_second_handshake_command_exists(self):
        # Второй сетевой пробы в модуле больше нет. Если её вернут «для
        # надёжности», вернётся и второй источник правды о том же сертификате —
        # с выброшенным rc, из-за которого всё и началось. Замок поведенческий:
        # одна сетевая команда на отчёт и `-checkend` в самой команде. Поиск по
        # исходнику модуля не годился бы: там `-checkend` помянут в docstring
        # как объяснение, что мы чинили, и тест краснел бы на тексте.
        c = FakeSSH(routes=[('-dates', self.OK)])
        webcheck_mod.ssl_cert_report(c, 'example.com')
        assert c.count('s_client') == 1
        assert not any('-checkend' in cmd for cmd in c.commands)

    def test_dead_port_yields_no_days_at_all(self):
        # Живой репро (закрытый порт) вскрыл ложь, которую я сам же внёс: пустая
        # строка для GNU `date -d` — НЕ ошибка, а «сейчас» (rc=0). Без guard
        # [ -n "$END" ] закрытый порт давал CERT=0, т.е. «⚠️ SSL осталось 0 дн.»
        # про сертификат, которого там нет. Сервер обязан вернуть CERT=none, а
        # отчёт — «не проверено».
        c = FakeSSH(routes=[('-dates', '\nCERT=none')])
        out = webcheck_mod.ssl_cert_report(c, 'example.com')
        assert 'Не удалось получить сертификат' in out
        assert 'ИСТЁК' not in out and 'осталось' not in out


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
