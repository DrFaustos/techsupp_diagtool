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
    """Итоги проб — три разных диагноза, а не одна фраза «не ответил».

    Прежний код брал `out2, _, _ = checker.run(...)`, то есть ВЫБРАСЫВАЛ код
    возврата всех 18 проб. Проверено живьём: `connection refused` — это rc=1 за
    4 мс (хост жив, он присылает RST: служба не слушает), а недоступный или
    фильтруемый хост — rc=124 за 2002 мс (пакеты молча дрейпятся). Пустой вывод
    у обоих одинаковый, поэтому отчёт печатал «ни один из типовых портов не
    ответил» и в том, и в другом случае. Диагнозы при этом ПРОТИВОПОЛОЖНЫЕ:
    «поднимай службы / перезагружай» против «службы в порядке, проверяй
    firewall и cloud security group». Оператор, которому фильтруют путь, ехал
    перезагружать живой сервер.
    """

    LISTEN_22 = 'tcp   LISTEN 0      128    0.0.0.0:22    0.0.0.0:*'

    @staticmethod
    def _stat(open_, refused, noreply, total=18):
        return (f'PORTSTAT open={open_} refused={refused} '
                f'noreply={noreply} total={total}\n')

    def _report(self, answer, routes_extra=(), host='93.184.216.34'):
        c = FakeSSH(routes=[('ss -tulpn', self.LISTEN_22),
                            ('/dev/tcp/', answer)] + list(routes_extra))
        return webcheck_mod.port_scan_report(c, host=host), c

    def test_open_ports_listed(self):
        # Было: отчёт обязан показывать и слушающие, и реально ответившие, и
        # слать пробу на указанный хост. Требование сохраняется; в фикстуру
        # добавлен PORTSTAT, потому что новой команде он нужен, а без него
        # выводы были бы «не проверено».
        c = FakeSSH(routes=[('ss -tulpn', 'tcp  LISTEN  0  128  *:22'),
                            ('/dev/tcp/', '  22 открыт\n' + self._stat(1, 17, 0))])
        out = webcheck_mod.port_scan_report(c, host='93.184.216.34')
        assert 'tcp  LISTEN  0  128  *:22' in out
        assert '22 открыт' in out
        probe = c.find('/dev/tcp/')
        assert probe is not None and '93.184.216.34' in probe

    def test_refused_everywhere_means_services_are_not_listening(self):
        out, _ = self._report(self._stat(0, 18, 0))
        assert 'Порты закрыты' in out
        assert 'RST' in out                    # хост жив: он ОТВЕТИЛ отказом
        assert 'открыт' not in out             # прежний guard: не выдумывать
                                               # открытые порты — оставляем
        assert 'не видно' not in out           # здесь как раз всё видно

    def test_silence_is_not_reported_as_closed(self):
        out, _ = self._report(self._stat(0, 0, 18))
        assert '⚠️' in out
        assert 'не видно' in out
        assert 'Порты закрыты' not in out      # вот это и было ложью
        assert 'firewall' in out               # куда идти оператору

    def test_partially_filtered_is_not_reported_as_closed(self):
        # Смешанный ответ (часть RST, часть дрейф) — про «закрыто» сказать
        # нельзя: молчащие порты мы не видели.
        out, _ = self._report(self._stat(0, 3, 15))
        assert 'Порты закрыты' not in out
        assert 'фильтр' in out

    def test_listening_locally_but_silent_out_is_called_filtering(self):
        # Решающая связка: ss ЗДЕСЬ показывает LISTEN :22, а снаружи порт молчит.
        # Это не «службы лежат» — это путь фильтруют. Данные уже в прогоне,
        # второй запрос не нужен.
        out, _ = self._report(self._stat(0, 0, 18))
        assert 'ℹ️' in out and '22' in out
        assert 'фильтрац' in out

    def test_no_probe_data_is_not_reported_as_closed(self):
        # Команда не выполнилась вообще (нет timeout/bash, обрыв) — состояния не
        # знаем, и «порты закрыты» тут было бы догадкой.
        c = FakeSSH()
        out = webcheck_mod.port_scan_report(c, host='127.0.0.1')
        assert '(ss/netstat недоступны)' in out
        assert 'Порты закрыты' not in out
        assert 'неизвестно' in out

    def test_service_line_is_not_shown_to_the_operator(self):
        out, _ = self._report('  22 открыт\n' + self._stat(1, 17, 0))
        assert 'PORTSTAT' not in out

    def test_verdict_is_consistent_with_the_denominator(self):
        # Счётчик обязательно сходится со знаменателем: «18 из 18» видно всегда,
        # иначе масштаб беды придётся считать глазами (тот же закон, что в
        # сводке доступности).
        for stat in (self._stat(0, 18, 0), self._stat(0, 0, 18),
                     self._stat(0, 3, 15)):
            out, _ = self._report(stat)
            assert '18' in out

    def test_host_cannot_escape_into_the_command(self):
        # Вскрыто живым прогоном, а не догадкой: прежний код вставлял host в
        # `</dev/tcp/{host}/{p}` неэкранированным, и host вида
        # «127.0.0.1; echo INJECTED» РЕАЛЬНО выполнял echo (в выводе был
        # «INJECTED/22», rc=0 — то есть 18 ложных «порт открыт»). Кавычки
        # внутрь пути /dev/tcp ставить нельзя (проверено: проба ломается),
        # поэтому хост уходит отдельным словом и в путь попадает позиционным
        # параметром.
        evil = "127.0.0.1; echo INJECTED"
        _, c = self._report(self._stat(0, 18, 0), host=evil)
        probe = c.find('/dev/tcp/')
        assert 'INJECTED/22' not in probe
        assert 'INJECTED/' not in probe
        assert f"'{evil}'" in probe          # экранирован как единое слово

    def test_price_is_two_commands_per_report(self):
        # Цена прогона не растёт: по-прежнему ровно две SSH-команды (ss/netstat
        # + одна проба, внутри которой 18 локальных коннектов).
        _, c = self._report(self._stat(0, 18, 0))
        assert len(c.commands) == 2


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
