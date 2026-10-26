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
    """Причина пустого whois-ответа — четыре разных диагноза, а не одна фраза.

    Прежний код: `out, _, rc = checker.run(f"timeout 15 whois ... 2>/dev/null")`.
    Во-первых, `rc` был ПРИНЯТ и НЕ ИСПОЛЬЗОВАН; во-вторых, `2>/dev/null` глушил
    ровно ту строку, которая объясняет причину. Проверено живьём на машине без
    whois: rc=127 и stderr «timeout: failed to run command 'whois': No such file
    or directory». Замер семантики timeout: 124 — убит по таймауту, 127 —
    бинарника нет, 1 — команда упала.

    И главное: «домена нет» — это НЕ пустой вывод. Живой запрос к реестрам через
    TCP/43 (утилиты whois здесь как раз нет):
      * whois.verisign-grs.com  -> `No match for "ZZQQXX-...COM".`
      * whois.tcinet.ru / nic.ru -> `No entries found for the selected source(s).`
    То есть прежняя подпись «whois не установлен или домен не найден» выбирала
    между «поставь утилиту» и «домена не существует» наугад, а третьих и четвёртых
    случаев (таймаут, пустой успешный вывод) не различала вообще.
    """

    RAW_OK = ('Domain Name: EXAMPLE.COM\n'
              'Registrar: RESOLVER WEBSITE INC.\n'
              'Creation Date: 2001-09-15T04:00:00Z\n'
              'не значимая строка\n'
              'Name Server: NS1.EXAMPLE.NET\n')

    def _report(self, res):
        return webcheck_mod.whois_report(
            FakeSSH(routes=[('whois', res)]), 'example.com')

    def test_key_lines_extracted(self):
        out = self._report(self.RAW_OK)
        assert 'Registrar:' in out
        assert 'Creation Date:' in out
        assert 'Name Server:' in out
        assert 'не значимая строка' not in out

    def test_unknown_format_falls_back_to_raw(self):
        # Вывод без ключей и без признанной фразы «нет» остаётся сырым: выдумывать
        # за реестр вердикт мы не вправе.
        out = self._report('какой-то редкий вывод без ключей\n')
        assert 'какой-то редкий вывод' in out

    def test_missing_binary_is_not_reported_as_missing_domain(self):
        # rc=127 замерен живьём на машине без whois.
        out = self._report(('', "timeout: failed to run command 'whois': "
                               "No such file or directory", 127))
        assert 'не установлен' in out
        assert 'домен не найден' not in out     # вот это и было ложью
        assert 'домен не зарегистрирован' not in out
        assert 'apt install whois' in out        # чем чинится

    def test_timeout_is_not_reported_as_missing_domain(self):
        # rc=124 — это `timeout 15` убил процесс: домен мог быть сколько угодно
        # зарегистрирован, мы просто не дождались ответа.
        out = self._report(('', '', 124))
        assert 'не успел' in out
        assert 'домен не найден' not in out
        assert 'не установлен' not in out        # утилита-то как раз есть

    def test_failure_reason_from_stderr_is_shown(self):
        # Единственный источник причины — stderr; прежняя команда глушила его.
        out = self._report(('', 'connect: Network is unreachable', 1))
        assert 'Network is unreachable' in out
        assert 'домен не найден' not in out

    def test_empty_output_with_success_is_not_verified(self):
        # rc=0 и пусто (проверено живьём: возможно). Никакого права говорить про
        # домен у такого ответа нет.
        out = self._report(('', '', 0))
        assert 'не проверено' in out
        assert 'домен не найден' not in out
        assert 'не установлен' not in out

    def test_unregistered_domain_is_named_from_the_registry_words(self):
        # Дословный ответ Verisign, снятый живьём через TCP/43.
        out = self._report('No match for "EXAMPLE.COM".\n')
        assert 'не зарегистрирован' in out
        assert 'No match for' in out             # слова реестра, а не наши
        assert 'не установлен' not in out        # утилита работала

    def test_ru_registry_phrase_is_recognized(self):
        # Дословный ответ whois.tcinet.ru и whois.nic.ru, снятый живьём.
        out = self._report('No entries found for the selected source(s).\n')
        assert 'не зарегистрирован' in out

    def test_nic_me_phrase_is_recognized(self):
        # Снято живьём: whois.nic.me отвечает коротко, без «No match».
        out = self._report('Domain not found.\n'
                           '>>> Last update of WHOIS database: 2026-10-23 <<<\n')
        assert 'не зарегистрирован' in out
        assert 'Domain not found.' in out

    def test_nominet_two_line_answer_is_recognized(self):
        # Снято живьём: whois.nic.uk даёт 'No match for ...' и ниже
        # 'This domain name has not been registered.' — обе строки настоящие.
        out = self._report('    No match for "ZZQQXX-91827364.CO.UK".\n'
                           '    This domain name has not been registered.\n')
        assert 'не зарегистрирован' in out

    def test_arin_terms_of_use_boilerplate_is_not_a_verdict(self):
        # Снято живьём: ARIN на незарегистрированный домен вернул почти пустой
        # ответ из служебных строк Terms of Use. Ни «свободен», ни «нет утилиты»
        # там выдумывать нельзя — вывод остаётся как есть.
        raw = ('#\n'
               '# ARIN WHOIS data and services are subject to the Terms of Use\n'
               '# available at: https://www.arin.net/resources/registry/whois/tou/\n')
        out = self._report(raw)
        assert 'не зарегистрирован' not in out
        assert 'Terms of Use' in out

    def test_free_domain_is_not_reported_when_keys_present(self):
        # Защита от ложного «свободен»: в выводе зарегистрированного домена
        # попадается служебное «NOT FOUND» (например, по contact-записи).
        raw = self.RAW_OK + 'Admin ID: NOT FOUND\n'
        out = self._report(raw)
        assert 'не зарегистрирован' not in out
        assert 'Registrar:' in out

    def test_stderr_is_not_thrown_away_by_the_command(self):
        # Поведенческий замок: прежнее `2>/dev/null` теряло причину. Проверяем не
        # текст комментария, а отправленную команду.
        c = FakeSSH(routes=[('whois', ('', '', 127))])
        webcheck_mod.whois_report(c, 'example.com')
        cmd = c.find('whois')
        assert cmd is not None
        assert '2>/dev/null' not in cmd
        assert c.count('whois') == 1             # цену прогона не поднимаем


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
    """«Совпадений нет» говорится только когда лог действительно прочитан.

    Прежний код: `out, _, _ = checker.run(f"{base} 2>/dev/null | grep ... | tail
    -n N")`. Три слоя лжи в одной строке:

    (1) Код возврата выброшен, а `grep` РАЗЛИЧАЕТ 1 («совпадений правда нет») и
        2 («файл не открылся: права / SELinux») — замерено живьём.
    (2) Хуже того: rc конвейера — это rc ПОСЛЕДНЕЙ команды, то есть `tail`, а она
        всегда 0. Забрать rc grep'а из такой команды невозможно даже тому, кто
        захочет: проверено живьём (`LOGSTAT grep_rc=1 rdr_rc=1 tail_rc=0`).
    (3) `2>/dev/null` глушил читателя: `.gz`, который не gzip (ротация оставила
        битый файл), даёт `gzip: not in gzip format` -> пустой вывод -> «Совпадений
        не найдено» по ВСЕМ ротированным логам.

    Плюс масштаб: `Всего строк: N` считалось по ПОКАЗАННЫМ строкам, а `tail -n`
    съедает остальные. Живой замер: 4 совпадения при limit=2 -> «Всего строк: 2».
    Для тикета «ошибок в логе нет» это противоположные ответы: «проблемы нет» и
    «мы ничего не увидели, поднимите права».

    Различение делаем POSIX-ветками ДО запуска grep'а (`[ ! -e ]` / `[ ! -r ]`), а
    НЕ `${PIPESTATUS}`: под dash последний даёт «Bad substitution» (проверено
    живьём — Ubuntu часто и есть dash). Точный total — awk-буфером за один проход,
    без второго чтения диска и без конвейера, съедающего rc.
    """

    LOG_FILE = '/var/log/nginx/example.com.access.log'

    @staticmethod
    def _read(total, *lines):
        """Ответ сервера для ПРОЧИТАННОГО лога: маркер + совпавшие строки."""
        return '\n'.join((f'LOGTOTAL {total}',) + lines) + '\n'

    def _report(self, answer, log_file=None, **kw):
        lf = log_file or self.LOG_FILE
        c = FakeSSH(routes=[('ls -1', lf + '\n'), ('grep', answer)])
        return webcheck_mod.grep_logs_report(c, 'none', 'example.com',
                                             '500', **kw), c

    def test_matches_with_total(self):
        # Прежний guard «не выдумывать совпадения» сохранён: показаны ровно строки,
        # вернувшиеся с сервера, а итог берётся из маркера, а не из хвоста.
        out, _ = self._report(self._read(2, 'line A', 'line B'))
        assert 'line A' in out
        assert '2' in out

    def test_total_counts_all_matches_not_only_shown(self):
        # Живой замер: 4 совпадения при limit=2. `tail` показывал 2, и отчёт писал
        # «Всего строк: 2» — масштаб беды занижен вдвое тем, что его не видно.
        out, _ = self._report(self._read(4, 'c 500 3', 'd 500 4'), limit=2)
        assert '4' in out
        assert 'показаны последние 2' in out

    def test_read_but_no_matches_is_the_only_honest_empty(self):
        out, _ = self._report(self._read(0))
        assert 'Совпадений нет' in out

    def test_no_server_answer_at_all_is_not_reported_as_no_matches(self):
        # Команда не выполнилась / соединение оборвалось: маркера нет. Это
        # «не проверено», а не «в логе нет 5xx» (тот же закон, v1.16/v1.17).
        out, _ = self._report('')
        assert 'не проверено' in out
        assert 'Совпадений нет' not in out

    def test_unreadable_is_not_reported_as_no_matches(self):
        out, _ = self._report('LOGSTATE unreadable\n')
        assert 'не читается' in out
        assert 'Совпадений нет' not in out       # вот это и было ложью
        assert 'прав' in out                     # чем чинится

    def test_missing_file_is_not_reported_as_no_matches(self):
        # logrotate убирает файл в середине прогона: «его нет» ≠ «в нём нет 5xx».
        out, _ = self._report('LOGSTATE missing\n')
        assert 'исчез' in out or 'не найден' in out
        assert 'Совпадений нет' not in out

    def test_missing_zcat_is_not_reported_as_no_matches(self):
        out, _ = self._report('LOGSTATE notool\n', log_file=self.LOG_FILE + '.gz')
        assert 'zcat' in out
        assert 'Совпадений нет' not in out

    def test_reader_error_is_shown_and_not_called_empty(self):
        # .gz, который не gzip (ротация оставила битый файл): прежнее `2>/dev/null`
        # глушило stderr читателя, и отчёт печатал «Совпадений не найдено» по всем
        # ротированным логам сразу. Причина приходит SSH-каналом stderr — её надо
        # показать, а не прятать (урок v1.18 про whois).
        c = FakeSSH(routes=[('ls -1', self.LOG_FILE + '.gz\n'),
                            ('grep', ('LOGTOTAL 0\n',
                                      'gzip: not in gzip format', 0))])
        out = webcheck_mod.grep_logs_report(c, 'none', 'example.com', '500')
        assert 'not in gzip format' in out
        assert 'Совпадений нет' not in out

    def test_partially_unreadable_blocks_the_empty_verdict(self):
        # Решающая связка: один лог прочитан (0 совпадений), второй не открылся.
        # «Совпадений нет» было бы утверждением о файле, которого мы не видели.
        c = FakeSSH(routes=[
            ('ls -1', self.LOG_FILE + '\n' + self.LOG_FILE + '.1\n'),
            ('grep', ['LOGSTATE unreadable\n', self._read(0)]),
        ])
        out = webcheck_mod.grep_logs_report(c, 'none', 'example.com', '500')
        assert 'не читается' in out
        assert 'Совпадений нет' not in out

    def test_service_markers_are_not_shown_to_the_operator(self):
        out, _ = self._report(self._read(2, 'line A', 'line B'))
        for marker in ('LOGTOTAL', 'LOGSTATE'):
            assert marker not in out

    def test_bad_pattern_is_not_reported_as_no_matches(self):
        # GUI принимает regex ОТ ОПЕРАТОРА. При опечатке (`5[0-9`) grep роняет rc=2
        # и молчит — прежний отчёт сказал бы «Совпадений нет», то есть «проблем в
        # логе нет» из-за неверного шаблона. Синтаксис шаблона проверяется ДО
        # чтения файла, поэтому цена ошибки — ноль прочитанных логов.
        out, _ = self._report('LOGSTATE badpattern\n')
        assert 'шаблон' in out
        assert 'Совпадений нет' not in out

    def test_gz_logs_use_zcat(self):
        _, c = self._report(self._read(1, 'gz match'),
                            log_file=self.LOG_FILE + '.gz')
        cmd = c.find('zcat')
        assert cmd is not None
        assert 'LOGTOTAL' in cmd                 # та же форма, другой читатель

    def test_context_flag_when_requested(self):
        # Прежний замок сохраняю: флаг контекста стоит ДО -E ('grep -C 3 -E ...').
        _, c = self._report(self._read(0), context=3)
        cmd = c.find('grep -C 3')
        assert cmd is not None and '-E' in cmd

    def test_reader_stderr_is_not_thrown_away(self):
        # Поведенческий замок по ОТПРАВЛЕННОЙ команде (не по исходнику — урок
        # v1.16): прежнее `2>/dev/null` теряло причину, а `tail` в конце конвейера
        # делал rc конвейера бесполезным (rc tail == 0 всегда).
        _, c = self._report(self._read(0))
        cmd = c.find('grep')
        assert cmd is not None
        assert '2>/dev/null' not in cmd
        assert 'tail -n' not in cmd              # масштаб не режется хвостом

    def test_price_is_one_grep_per_log_file(self):
        # Цена не растёт: состояние, точный total и хвост снимаются ОДНИМ прогоном
        # на файл — никаких вторых чтений диска.
        _, c = self._report(self._read(1, 'x'))
        assert c.count('grep') == 1

    # ---- пустота поиска: «не найдено» только на просмотренных каталогах ----

    def test_unreadable_dir_is_not_reported_as_no_logs(self):
        # Логи есть, но оператор под своим UID их не увидит. Прежний вывод был
        # неотличим от «логов нет» — оператор шёл искать другой домен, а не права.
        c = FakeSSH(routes=[('ls -1', 'FFDIR noperm /var/log/nginx\nFFCOUNT 0\n')])
        out = webcheck_mod.grep_logs_report(c, 'none', 'example.com', '500')
        assert 'прав' in out
        assert 'Логи для домена не найдены' not in out

    def test_missing_dir_names_the_path(self):
        c = FakeSSH(routes=[('ls -1', 'FFDIR missing /var/log/apache2\nFFCOUNT 0\n')])
        out = webcheck_mod.grep_logs_report(c, 'none', 'example.com', '500')
        assert '/var/log/apache2' in out and 'Каталога' in out

    def test_no_logs_message_survives_on_a_read_directory(self):
        # Прежнее требование (запертое в test_diagnostic) сохранено: когда каталоги
        # просмотрены и в них пусто, «не найдены» обязано звучать.
        c = FakeSSH(routes=[('ls -1', 'FFDIR ok /var/log/nginx\nFFCOUNT 0\n')])
        out = webcheck_mod.grep_logs_report(c, 'none', 'example.com', '500')
        assert 'Логи для домена не найдены' in out

    def test_unconfirmed_search_is_not_reported_as_no_logs(self):
        c = FakeSSH(routes=[])
        out = webcheck_mod.grep_logs_report(c, 'none', 'example.com', '500')
        assert 'не проверено' in out
        assert 'Логи для домена не найдены' not in out


class TestListCommonReports:
    def test_both_5xx_and_404_sections(self):
        c = FakeSSH(routes=[('ls -1', '/var/log/nginx/example.com.access.log\n'),
                             ('| grep', 'matched\n')])
        out = webcheck_mod.list_common_reports(c, 'none', 'example.com')
        assert out.count('=== GREP ЛОГОВ') == 2
