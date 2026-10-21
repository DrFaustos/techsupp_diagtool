"""Тесты logs.py: поиск логов по панелям, анализ access-логов, домены, OOM.

Реального SSH нет — команды перехватывает FakeSSH из support.py. Исключение
составляет выбор почтового файла: он реализован циклом в shell, и FakeSSH его
проверить не может (заглушка отвечает на команду целиком, а не исполняет её) —
такие проверки идут настоящим bash'ем по временным файлам.
"""
import os
import subprocess
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from support import FakeSSH, LOG_OK_1, LOG_OK_2, LOG_OK_3, LOG_OTHER_DAY, LOG_BAD
import logs as logs_mod


LOG_ALL = '\n'.join([LOG_OK_1, LOG_OK_2, LOG_OK_3, LOG_BAD, ''])


# ==================== поиск файлов логов ====================
class TestFindLogs:
    def test_fastpanel_patterns(self):
        c = FakeSSH(routes=[('ls -1', '/var/www/site/data/logs/example.error.log\n')])
        files = logs_mod.find_logs(c, 'fastpanel', 'example.com', 'error')
        assert '/var/www/site/data/logs/example.error.log' in files
        assert c.find('/var/www/*/data/logs/*example.com*.error.log') is not None

    def test_ispmanager_patterns(self):
        c = FakeSSH(routes=[('ls -1', '')])
        logs_mod.find_logs(c, 'ispmanager', 'example.com', 'error')
        assert c.find('/var/www/*/example.com/data/logs/error.log') is not None
        assert c.find('/var/www/httpd-logs/example.com.error.log') is not None

    def test_no_panel_uses_distro_paths(self):
        c = FakeSSH(routes=[('ls -1', '')])
        logs_mod.find_logs(c, 'none', 'example.com', 'error')
        assert c.find('/var/log/nginx/example.com.error.log') is not None
        assert c.find('/var/log/apache2/example.com-error.log') is not None

    def test_results_deduplicated(self):
        c = FakeSSH(routes=[('ls -1', '/a/error.log\n/a/error.log\n')])
        assert logs_mod.find_logs(c, 'none', 'example.com') == ['/a/error.log']

    def test_domain_is_sanitized_against_injection(self):
        # _safe_name вырезает shell-метасимволы: имя домена не может расшириться
        # до команды (паттерны идут в ls без кавычек — они glob'ы).
        c = FakeSSH(routes=[('ls -1', '')])
        logs_mod.find_logs(c, 'none', 'example.com$(curl evil)")')
        for cmd in c.commands:
            assert '$(' not in cmd and ';' not in cmd and '"' not in cmd
        assert 'example.comcurl' in c.commands[0]


# ==================== анализ access-логов ====================
class TestAnalyzeAccessLog:
    def test_no_logs_found(self):
        c = FakeSSH(routes=[('ls -1', '')])
        out = logs_mod.analyze_access_log(c, 'none', 'example.com')
        assert 'Не найден access-лог' in out

    def test_counters_and_tops(self):
        c = FakeSSH(routes=[
            ('ls -1', '/var/log/nginx/example.com.access.log\n'),
            ('cat ', LOG_ALL),
        ])
        out = logs_mod.analyze_access_log(c, 'none', 'example.com')
        assert 'Всего запросов: 3' in out          # LOG_BAD отброшен парсером
        assert 'Уникальных IP: 2' in out
        assert '198.51.100.7' in out               # топ-1: 2 запроса
        assert '/index.php' in out
        assert 'python-requests/2.31' in out

    def test_top_n_limits_lines(self):
        c = FakeSSH(routes=[
            ('ls -1', '/var/log/nginx/example.com.access.log\n'),
            ('cat ', LOG_ALL),
        ])
        out = logs_mod.analyze_access_log(c, 'none', 'example.com', top_n=1)
        # в топе IP остаётся только лидер, второй IP — только в счётчике
        ip_section = out.split('ПО КОЛИЧЕСТВУ ЗАПРОСОВ ---')[1].split('\n\n')[0]
        assert '198.51.100.7' in ip_section
        assert '203.0.113.9' not in ip_section

    def test_date_filter(self):
        c = FakeSSH(routes=[
            ('ls -1', '/var/log/nginx/example.com.access.log\n'),
            ('cat ', LOG_ALL + LOG_OTHER_DAY),
        ])
        out = logs_mod.analyze_access_log(c, 'none', 'example.com', day=9)
        assert 'Всего запросов: 1' in out
        assert 'день=9' in out

    def test_empty_period_message(self):
        c = FakeSSH(routes=[
            ('ls -1', '/var/log/nginx/example.com.access.log\n'),
            ('cat ', LOG_ALL),
        ])
        out = logs_mod.analyze_access_log(c, 'none', 'example.com', day=1)
        assert 'записей не найдено' in out

    def test_gzipped_logs_use_zcat(self):
        c = FakeSSH(routes=[
            ('ls -1', '/var/log/nginx/example.com.access.log.gz\n'),
            ('zcat ', LOG_ALL),
        ])
        out = logs_mod.analyze_access_log(c, 'none', 'example.com')
        assert 'Всего запросов: 3' in out
        assert c.find('zcat') is not None

    def test_limit_warning_line_is_not_read_as_file(self):
        # find_files добавляет строку '⚠️ ...' — она не должна уходит в cat
        many = '\n'.join(f'/var/log/nginx/l{i}.log' for i in range(20)) + \
               '\n⚠️ (показаны первые 20 файлов)'
        c = FakeSSH(routes=[('ls -1', many + '\n'), ('cat ', '')])
        out = logs_mod.analyze_access_log(c, 'none', 'example.com')
        assert '⚠️' not in out
        assert c.find('cat') is not None
        assert '⚠️' not in c.find('cat')


# ==================== домены ====================
class TestGetDomains:
    def test_ispmanager_uses_mgrctl(self):
        csv = 'name,domains\n1,example.com\n2,site.ru\n'
        c = FakeSSH(routes=[('mgrctl', csv)])
        assert sorted(logs_mod.get_domains(c, 'ispmanager')) == ['example.com', 'site.ru']

    def test_ispmanager_falls_back_to_configs(self):
        c = FakeSSH(routes=[('mgrctl', ''), ('ls -1', '/etc/nginx/vhosts/example\n'),
                            ('grep -h', 'example.com\n')])
        assert logs_mod.get_domains(c, 'ispmanager') == ['example.com']

    def test_plain_nginx_configs(self):
        c = FakeSSH(routes=[('ls -1', '/etc/nginx/sites-enabled/example\n'),
                            ('grep -h', 'example.com\nwww.example.com\n')])
        assert sorted(logs_mod.get_domains(c, 'none')) == ['example.com', 'www.example.com']

    def test_empty_when_nothing_found(self):
        assert logs_mod.get_domains(FakeSSH(), 'none') == []


# ==================== ошибки в логах сайтов ====================
class TestSiteLogs:
    LOGS = ('2026/10/10 13:00:01 [error] 123#0: *1 open() failed\n'
            '2026/10/10 13:00:02 [notice] worker process started\n')

    def test_collects_error_lines_per_domain(self):
        c = FakeSSH(routes=[('ls -1', '/var/log/nginx/example.com.error.log\n'),
                            ('grep -h', 'example.com\n'),
                            ('cat ', self.LOGS)])
        res = logs_mod.check_site_logs(c, 'none', ['example.com'])
        assert 'example.com' in res
        assert '[error]' in res['example.com']
        assert 'notice' not in res['example.com']

    def test_clean_logs_give_no_entries(self):
        c = FakeSSH(routes=[('ls -1', '/var/log/nginx/example.com.error.log\n'),
                            ('cat ', 'everything is fine\n')])
        assert logs_mod.check_site_logs(c, 'none', ['example.com']) == {}

    def test_report_with_domains(self):
        c = FakeSSH(routes=[('ls -1', '/var/log/nginx/example.com.error.log\n'),
                            ('grep -h', 'example.com\n'),
                            ('cat ', self.LOGS)])
        out = logs_mod.site_logs_report(c, 'none')
        assert 'Найдены домены: example.com' in out
        assert '[error]' in out

    def test_report_without_domains(self):
        out = logs_mod.site_logs_report(FakeSSH(), 'none')
        assert 'Не удалось определить домены' in out

    def test_report_when_logs_clean(self):
        c = FakeSSH(routes=[('ls -1', '/var/log/nginx/example.com.error.log\n'),
                            ('grep -h', 'example.com\n'),
                            ('cat ', 'everything is fine\n')])
        out = logs_mod.site_logs_report(c, 'none')
        assert 'Ошибок' in out and 'не обнаружено' in out


# ==================== OOM ====================
class TestSearchOom:
    def test_blocks_split_by_separator(self):
        out = ('invoked oom-killer\nKilled process 999\n'
               '--\nanother oom-killer event\n')
        c = FakeSSH(routes=[('zgrep', out)])
        rep = logs_mod.search_oom_logs(c)
        assert 'Событие #1' in rep and 'Событие #2' in rep
        assert 'Killed process 999' in rep
        # разделитель zgrep ('--') не должен остаться отдельной строкой отчёта
        # (заголовки вида '--- Событие #1 ---' сюда не попадают)
        assert '--' not in [line.strip() for line in rep.splitlines()]

    def test_no_events(self):
        rep = logs_mod.search_oom_logs(FakeSSH())
        assert rep == 'OOM-событий в логах не найдено.'

    def test_only_separators(self):
        c = FakeSSH(routes=[('zgrep', '--\n--\n')])
        assert 'OOM-событий не обнаружено' in logs_mod.search_oom_logs(c)


# ==================== почтовый лог: выбор файла ====================
# Выбор «первого непустого файла» — это цикл в shell, и FakeSSH проверить его
# не может: заглушка отвечает на команду целиком и не исполняет её. Здесь
# команды гоняются НАСТОЯЩИМ bash'ем по временным файлам. Именно в этом цикле
# живёт грабель, из-за которого проект годами не видел почту на Debian: пустой
# (ротированный) maillog обрывал цепочку, и /var/log/mail.log не спрашивался.
def _sh(cmd):
    return subprocess.run(['bash', '-c', cmd], capture_output=True, text=True)


class TestMailLogFileSelection:
    def test_empty_rotated_maillog_does_not_kill_mail_log(self, tmp_path):
        empty = tmp_path / 'maillog'
        empty.write_text('')                       # ротирован и пока пуст
        live = tmp_path / 'mail.log'
        live.write_text('AAA: to=<a@b.ru>, status=sent (250 Ok)\n')
        out = _sh(logs_mod.mail_log_files_command(
            15, paths=(str(empty), str(live))))
        assert out.returncode == 0
        text, src = logs_mod.parse_mail_log_output(out.stdout)
        assert text == 'AAA: to=<a@b.ru>, status=sent (250 Ok)'
        assert src == str(live)                    # источник назван честно

    def test_absent_first_path_still_reaches_the_second(self, tmp_path):
        live = tmp_path / 'mail.log'
        live.write_text('AAA: status=sent (250 Ok)\n')
        out = _sh(logs_mod.mail_log_files_command(
            15, paths=(str(tmp_path / 'nope'), str(live))))
        text, src = logs_mod.parse_mail_log_output(out.stdout)
        assert text and src == str(live)

    def test_both_dead_yields_empty_not_a_lie(self, tmp_path):
        # Пустой вывод = «лог не найден» (вызывающий код обязан сказать «не
        # проверено»), а не «писем не было».
        out = _sh(logs_mod.mail_log_files_command(
            15, paths=(str(tmp_path / 'nope'), str(tmp_path / 'nope2'))))
        assert out.returncode == 0 and out.stdout == ''

    def test_grep_reaches_the_second_file(self, tmp_path):
        empty = tmp_path / 'maillog'
        empty.write_text('')
        live = tmp_path / 'mail.log'
        live.write_text('A: to=<x@b.ru>, status=sent (ok)\n'
                        'B: to=<y@b.ru>, status=bounced (spam)\n')
        out = _sh(logs_mod.mail_log_grep_command(
            'status=bounced', 50, 3, paths=(str(empty), str(live))))
        text, src = logs_mod.parse_mail_log_output(out.stdout)
        assert 'status=bounced' in text and 'status=sent' not in text
        assert src == str(live)

    def test_tail_limits_the_window(self, tmp_path):
        big = tmp_path / 'mail.log'
        big.write_text(''.join(f'l{i} status=sent (ok)\n' for i in range(1000)))
        out = _sh(logs_mod.mail_log_files_command(3, paths=(str(big),)))
        lines = out.stdout.splitlines()
        assert lines[0].startswith(logs_mod.MAIL_LOG_MARK)
        assert [l.split()[0] for l in lines[1:]] == ['l997', 'l998', 'l999']

    def test_quote_in_path_stays_one_argument(self, tmp_path):
        # Путь попадает в команду через q(); проверка на `[ -s ]` обязана видеть
        # ОДИН аргумент, иначе имя файла с `$()` выполнилось бы на сервере.
        evil = tmp_path / 'ev; $(id).log'
        evil.write_text('AAA: status=sent (ok)\n')
        out = _sh(logs_mod.mail_log_files_command(15, paths=(str(evil),)))
        assert 'uid=' not in out.stdout + out.stderr
        text, src = logs_mod.parse_mail_log_output(out.stdout)
        assert text == 'AAA: status=sent (ok)' and src == str(evil)

    @pytest.mark.parametrize('builder', ['files', 'grep'])
    def test_commands_are_valid_shell(self, builder):
        cmd = (logs_mod.mail_log_files_command(15) if builder == 'files'
               else logs_mod.mail_log_grep_command("to<'a\"@b.ru>", 50, 3))
        proc = subprocess.run(['bash', '-n', '-c', cmd],
                              capture_output=True, text=True)
        assert proc.returncode == 0, proc.stderr
        assert '/var/log/maillog' in cmd and '/var/log/mail.log' in cmd


# ==================== чтение почтового лога (FakeSSH) ====================
class TestReadMailLog:
    def test_first_file_wins_and_source_is_named(self):
        c = FakeSSH(routes=[('for __p in', '#LOG /var/log/maillog\nX status=sent\n')])
        assert logs_mod.read_mail_log(c) == ('X status=sent', '/var/log/maillog')

    def test_debian_path_is_read_at_all(self):
        # Раньше этот путь не читался нигде в проекте — на Debian отчёт о почте
        # был слеп.
        c = FakeSSH(routes=[('for __p in',
                             '#LOG /var/log/mail.log\nY status=bounced\n')])
        text, src = logs_mod.read_mail_log(c)
        assert (text, src) == ('Y status=bounced', '/var/log/mail.log')

    def test_journal_fallback_when_files_are_empty(self):
        c = FakeSSH(routes=[('for __p in', ''),
                            ('journalctl', 'host postfix/master: daemon started')])
        text, src = logs_mod.read_mail_log(c)
        assert text == 'host postfix/master: daemon started'
        assert src == 'journalctl -u postfix'

    def test_no_entries_marker_is_not_a_log(self):
        # journalctl при пустом журнале печатает '-- No entries --', и прежний
        # код postfix-отчёта показывал её оператору как содержимое лога.
        c = FakeSSH(routes=[('for __p in', ''),
                            ('journalctl', '-- No entries --\n')])
        assert logs_mod.read_mail_log(c) == ('', '')

    def test_everything_dead_is_not_reported_as_no_mail(self):
        assert logs_mod.read_mail_log(FakeSSH()) == ('', '')

    def test_source_is_always_named_when_there_is_text(self):
        # Вывод без маркера (старая обвязка, тестовые заглушки) не должен дать
        # заголовок «---  (последние 15 строк) ---» с пустым источником.
        c = FakeSSH(routes=[('for __p in', 'X status=sent\n')])
        assert logs_mod.read_mail_log(c) == ('X status=sent', 'лог почты')

    def test_grep_filters_journal_too(self):
        c = FakeSSH(routes=[('for __p in', ''),
                            ('journalctl', 'A to=<x@b.ru> status=sent\nB noise\n')])
        text, src = logs_mod.read_mail_log(c, tail=50, grep='to=<x@b.ru>')
        assert text == 'A to=<x@b.ru> status=sent' and 'journalctl' in src

    def test_cost_is_one_command_per_read(self):
        c = FakeSSH(routes=[('for __p in', '#LOG /var/log/maillog\nX\n')])
        logs_mod.read_mail_log(c)
        assert c.count('for __p in') == 1
        assert c.count('journalctl') == 0          # живой файл — журнал не трогаем


# ==================== разбор строк доставки postfix ====================
# Строки взяты живыми: `status=` печатает сам postfix, текст в скобках — дословно
# ответ приёмника. Именно эта пара связывает «SPF нет» с «письмо отбили».
SENT = ('Oct 10 12:00:01 host postfix/smtp[123]: AAA1: to=<a@b.ru>, '
        'relay=mx.b.ru[1.2.3.4]:25, delay=1.1, dsn=2.0.0, status=sent (250 2.0.0 Ok)')
GMAIL_SPAM = ('Oct 10 12:00:05 host postfix/smtp[124]: AAA2: to=<c@gmail.com>, '
              'relay=gmail-smtp-in.l.google.com[142.251.8.27]:25, dsn=5.7.26, '
              'status=bounced (gmail-smtp-in.l.google.com[142.251.8.27] said: '
              '550-5.7.26 [203.0.113.9] unauthenticated mail was rejected, '
              'please learn about SPF) 19-20020a05 gsmtp')
DNS_DEFER = ('Oct 10 12:00:07 host postfix/smtp[125]: AAA3: to=<d@nowhere.tld>, '
             'relay=none, dsn=4.4.3, status=deferred (Host or domain name not '
             'found. Name service error for name=nowhere.tld type=MX)')
NO_SUCH_USER = ('Oct 10 12:00:09 host postfix/smtp[126]: AAA4: to=<e@dead.ru>, '
                'relay=none, dsn=5.1.1, status=bounced (User unknown)')
BUSY = ('Oct 10 12:00:11 host postfix/smtp[127]: AAA5: to=<f@busy.ru>, '
        'relay=mx.busy.ru[5.6.7.8]:25, dsn=4.5.0, status=deferred (451 4.7.1 '
        '<5.6.7.8>: Rate limit exceeded, try again later)')
RELAY_DENIED = ('Oct 10 12:00:14 host postfix/smtp[128]: AAA8: to=<h@x.ru>, '
                'relay=smtp.x.ru[9.9.9.9]:25, dsn=5.7.60, status=bounced '
                '(Relay access denied)')
CONN_TIMEOUT = ('Oct 10 12:00:15 host postfix/smtp[129]: AAA9: to=<i@y.ru>, '
                'relay=none, dsn=4.4.1, status=deferred (connect to '
                'mx.y.ru[8.8.8.8]:25: Connection timed out)')
EXPIRED = ('Oct 10 12:00:16 host postfix/smtp[130]: AAB0: to=<j@z.ru>, '
           'relay=none, dsn=4.4.2, status=expired (Delivery to the following '
           'recipient timed out)')
# Строки, которые доставкой НЕ являются: postfix пишет в один лог и запуск
# демонов, и connect/disconnect. Посчитать их отказами — значит нарисовать
# проблему там, где её нет.
NOT_DELIVERY = ('Oct 10 12:00:00 host postfix/master[1]: daemon started -- '
                'version 3.5.6',
                'Oct 10 12:00:02 host postfix/smtpd[9]: connect from unknown[203.0.113.5]',
                'Oct 10 12:00:12 host postfix/cleanup[7]: AAA6: message-id=<x@y>',
                '')
UNKNOWN_STATUS = ('Oct 10 12:00:13 host postfix/dovecot-lmtp[8]: AAA7: '
                  'to=<g@x.ru>, relay=dovecot-lmtp, status=dlivered (weird)')


class TestParseDeliveryEntry:
    def test_fields_are_named_not_positional(self):
        e = logs_mod.parse_delivery_entry(SENT)
        assert e['status'] == 'sent' and e['to'] == 'a@b.ru'
        assert e['relay'] == 'mx.b.ru[1.2.3.4]:25' and e['dsn'] == '2.0.0'
        assert e['reason'] == '250 2.0.0 Ok'

    @pytest.mark.parametrize('line', NOT_DELIVERY)
    def test_lines_that_are_not_delivery_give_none(self, line):
        assert logs_mod.parse_delivery_entry(line) is None

    def test_unknown_status_is_kept_not_renamed(self):
        # Переименовать незнакомый status в «bounced» — значит соврать про отказ.
        assert logs_mod.parse_delivery_entry(UNKNOWN_STATUS)['status'] == 'dlivered'

    def test_entry_without_status_field_is_none(self):
        assert logs_mod.parse_delivery_entry('to=<a@b.ru>, relay=none') is None


class TestSummarizeAndClassify:
    def test_counts_split_known_and_unknown(self):
        entries = [logs_mod.parse_delivery_entry(l) for l in
                   (SENT, GMAIL_SPAM, DNS_DEFER, UNKNOWN_STATUS)]
        counts = logs_mod.summarize_deliveries(entries)
        assert counts['sent'] == 1 and counts['bounced'] == 1
        assert counts['deferred'] == 1 and counts['expired'] == 0
        assert counts['other'] == 1                # незнакомый — в 'other'

    def test_gmail_spam_rejection_is_classified(self):
        # Ровно тот тикет, ради которого снимок затеян: Gmail пишет причину прямо
        # в отказе, и без игл spf/unauthenticated он остался бы без подсказки.
        e = logs_mod.parse_delivery_entry(GMAIL_SPAM)
        hint = logs_mod.mail_failure_hint(e['reason'])
        assert hint and hint[0] == logs_mod.SPAM_GROUP_LABEL

    @pytest.mark.parametrize('line,label', [
        (GMAIL_SPAM, 'спам или блокировка репутации'),
        (DNS_DEFER, 'DNS домена получателя'),
        (CONN_TIMEOUT, 'нет соединения с портом 25'),
        (RELAY_DENIED, 'отказ в релее / нужна авторизация'),
        (NO_SUCH_USER, 'адресата нет'),
        (BUSY, 'сервер загружен / временный отказ'),
    ])
    def test_each_real_failure_lands_in_its_group(self, line, label):
        e = logs_mod.parse_delivery_entry(line)
        assert logs_mod.mail_failure_hint(e['reason'])[0] == label

    def test_unclassifiable_reason_is_not_invented(self):
        assert logs_mod.mail_failure_hint('что-то совсем непонятное') is None

    def test_classify_line_carries_status_dsn_and_reason(self):
        _i, line, hint = logs_mod.classify_delivery(
            logs_mod.parse_delivery_entry(NO_SUCH_USER))
        assert line.startswith('❌ e@dead.ru — отбито') and 'dsn=5.1.1' in line
        assert hint[0] == 'адресата нет'

    def test_unknown_status_gets_no_icon_and_no_verdict(self):
        icon, line, hint = logs_mod.classify_delivery(
            logs_mod.parse_delivery_entry(UNKNOWN_STATUS))
        assert icon == 'ℹ️' and 'dlivered' in line
        assert not line.startswith(('✅', '❌', '⚠️'))

    def test_dsn_4xx_explains_retry_even_without_a_keyword(self):
        # Код DSN, а не текст, решает «повторять или сдаваться».
        line = ('postfix/smtp[1]: X: to=<q@w.ru>, relay=none, dsn=4.9.9, '
                'status=deferred (неизвестный текст беды)')
        _i, _l, hint = logs_mod.classify_delivery(logs_mod.parse_delivery_entry(line))
        assert hint and '4xx' in hint[0] and 'maximal_queue_lifetime' in hint[1]

    def test_domain_of_recipient(self):
        assert logs_mod.delivery_domain_of(
            logs_mod.parse_delivery_entry(GMAIL_SPAM)) == 'gmail.com'
        assert logs_mod.delivery_domain_of({'to': ''}) == ''

    def test_failure_groups_ignore_unknown_status_and_success(self):
        # Неизвестный status — не отказ: приписать причину несуществующей беде
        # нельзя (тот же закон «не проверено ≠ провалено»).
        entries = [logs_mod.parse_delivery_entry(l) for l in
                   (SENT, GMAIL_SPAM, NO_SUCH_USER, UNKNOWN_STATUS)]
        groups = logs_mod.delivery_failure_groups(entries)
        assert groups[logs_mod.SPAM_GROUP_LABEL] == 1
        assert groups['адресата нет'] == 1
        assert sum(groups.values()) == 2


# ==================== снимок доставки (в почтовой сводке) ====================
def _log_routes(*lines):
    return [('for __p in', '#LOG /var/log/mail.log\n' + '\n'.join(lines) + '\n')]


class TestMailLogSnapshot:
    def test_missing_log_is_not_reported_as_no_failures(self):
        out = logs_mod.mail_log_snapshot_lines(FakeSSH())
        text = '\n'.join(out)
        assert 'лог не найден' in text and 'ls -l /var/log/mail*' in text
        assert '✅' not in text

    def test_only_noise_lines_says_no_delivery_records(self):
        out = '\n'.join(logs_mod.mail_log_snapshot_lines(
            FakeSSH(routes=_log_routes(NOT_DELIVERY[0]))))
        assert 'Записей о доставке' in out and 'не равно' not in out
        assert '✅' not in out

    def test_failures_are_listed_with_actions(self):
        out = '\n'.join(logs_mod.mail_log_snapshot_lines(
            FakeSSH(routes=_log_routes(SENT, GMAIL_SPAM, NO_SUCH_USER))))
        assert 'отбито: 2' in out and 'ушло: 1' in out
        assert 'спам или блокировка репутации' in out
        assert 'gmail.com' in out and 'dead.ru' in out
        assert 'SPF/DKIM/DMARC/PTR' in out        # куда идти дальше

    def test_clean_window_denies_the_false_conclusion(self):
        # «Отказов нет» читается как «чинить нечего», а приёмник, режущий спам,
        # письмо НЕ отбивает — в нашем логе такой беды не видно вовсе.
        out = '\n'.join(logs_mod.mail_log_snapshot_lines(
            FakeSSH(routes=_log_routes(SENT))))
        assert '✅ Отказов нет' in out
        # Само по себе «отказов нет» обязан быть подписан границей окна: иначе
        # оператор прочитает его как «чинить нечего».
        assert 'окно лога, а не гарантия' in out

    def test_unknown_status_is_not_counted_as_failure(self):
        out = '\n'.join(logs_mod.mail_log_snapshot_lines(
            FakeSSH(routes=_log_routes(UNKNOWN_STATUS))))
        assert 'без знакомого status: 1' in out
        # Неизвестный статус — не отказ: снимок обязан сказать «отказов нет», а
        # не рисовать ❌ на строке, статус которой мы не знаем.
        assert '❌' not in out and 'Отказов нет' in out

    def test_long_failure_list_is_counted_not_dumped(self):
        # 4000 строк лога в окне GUI означают «не показано ни одной».
        lines = _log_routes(*([GMAIL_SPAM] * 20))
        out = logs_mod.mail_log_snapshot_lines(FakeSSH(routes=lines), limit=8)
        shown = [l for l in out if '↳' in l]
        assert len(shown) == 8
        assert 'скрыто отказов — 12' in '\n'.join(out)

    def test_cost_is_one_read_of_the_log(self):
        c = FakeSSH(routes=_log_routes(SENT))
        logs_mod.mail_log_snapshot_lines(c)
        assert c.count('for __p in') == 1


# ==================== дайджест доставки (в SPF-отчёте) ====================
class TestMailDeliveryDigest:
    def test_spam_refusals_confirm_the_dns_verdict(self):
        out = '\n'.join(logs_mod.mail_delivery_digest_lines(
            FakeSSH(routes=_log_routes(SENT, GMAIL_SPAM, GMAIL_SPAM))))
        assert 'отбито: 2' in out
        assert 'спам или блокировка репутации — 2' in out
        assert 'DNS-беда уже ломает доставку' in out

    def test_missing_log_is_neither_ok_nor_broken(self):
        out = '\n'.join(logs_mod.mail_delivery_digest_lines(FakeSSH()))
        assert 'не найден' in out and 'не проверено' in out
        assert '✅' not in out

    def test_no_delivery_records_is_not_clean(self):
        out = '\n'.join(logs_mod.mail_delivery_digest_lines(
            FakeSSH(routes=_log_routes(NOT_DELIVERY[0]))))
        assert 'подтверждать связку нечем' in out and 'не равно' in out

    def test_without_spam_refusals_dns_is_not_exonerated(self):
        # Написать «значит SPF ни при чём» было бы ложью: молча уехавшее в спам
        # письмо приёмник принимает с 250 Ok.
        out = '\n'.join(logs_mod.mail_delivery_digest_lines(
            FakeSSH(routes=_log_routes(SENT, DNS_DEFER))))
        assert 'отношения не имеют' in out
        assert '250 Ok' in out and 'не оправдание пустой зоны' in out

    def test_expires_and_bounces_are_counted(self):
        out = '\n'.join(logs_mod.mail_delivery_digest_lines(
            FakeSSH(routes=_log_routes(EXPIRED, NO_SUCH_USER))))
        assert 'истекло: 1' in out and 'отбито: 1' in out

    def test_digest_costs_one_read(self):
        c = FakeSSH(routes=_log_routes(SENT))
        logs_mod.mail_delivery_digest_lines(c)
        assert c.count('for __p in') == 1


# ==================== привязка отказа к домену отправления ====================
# Строка доставки (`postfix/smtp ... to=<...> status=`) отправителя НЕ содержит:
# там только to=/relay=/delay=/dsn=/status=. Конверт живёт в ДРУГОЙ записи того
# же queue-id (qmgr при активации очереди, pickup при локальной отправке,
# `sasl_username=` у smtpd при авторизации; cleanup — только message-id, man
# cleanup(8)). Поэтому ниже проверяется именно связка по queue-id, а не
# удачность формулировок: приписать отказ домену, которого в конверте нет, —
# тот же грех, что и поднять «не проверено» до «в порядке».
PICKUP_LIE = ('Oct 10 12:00:00 host postfix/pickup[6843]: BE78A40083: '
              'uid=1001 from=<web@lie.ru>')
CLEANUP_LIE = ('Oct 10 12:00:00 host postfix/cleanup[6850]: BE78A40083: '
               'message-id=<20261010.be@host>')
QMGR_LIE = ('Oct 10 12:00:01 host postfix/qmgr[21603]: BE78A40083: '
            'from=<web@lie.ru>, size=1372, nrcpt=1 (queue active)')
SMTPD_SASL = ('Oct 10 12:00:06 host postfix/submission/smtpd[7001]: '
              '9A1F2B3C4D: client=unknown[203.0.113.7], sasl_method=LOGIN, '
              'sasl_username=shop@shop.ru')
QMGR_SASL = ('Oct 10 12:00:07 host postfix/qmgr[21603]: 9A1F2B3C4D: '
             'from=<shop@shop.ru>, size=900, nrcpt=1 (queue active)')
QMGR_BOUNCE = ('Oct 10 12:00:10 host postfix/qmgr[21603]: DEADBEEF01: '
               'from=<>, size=2400, nrcpt=1 (queue active)')
REMOVED_LIE = 'Oct 10 12:00:13 host postfix/qmgr[21603]: BE78A40083: removed'
# Отказ письма, записей о входе которого в очередь в окне лога нет: «не видно»
# обязано отличаться от «не ваш домен» — иначе оператор спишет отказ чужому.
ORPHAN_FAIL = ('Oct 10 12:00:09 host postfix/smtp[131]: CAFE000111: '
               'to=<q@p.ru>, relay=none, dsn=5.1.1, status=bounced '
               '(User unknown)')
FAIL_LIE = ('Oct 10 12:00:05 host postfix/smtp[124]: BE78A40083: '
            'to=<c@gmail.com>, relay=gmail-smtp-in.l.google.com'
            '[142.251.8.27]:25, dsn=5.7.26, status=bounced (gmail-smtp-in'
            '.l.google.com said: 550-5.7.26 unauthenticated mail was rejected, '
            'please learn about SPF)')
FAIL_SHOP = ('Oct 10 12:00:08 host postfix/smtp[130]: 9A1F2B3C4D: '
             'to=<z@yandex.ru>, relay=none, dsn=4.4.1, status=deferred '
             '(connect to mx.yandex.ru[213.180.204.25]:25: Connection timed '
             'out)')
FAIL_BOUNCE = ('Oct 10 12:00:11 host postfix/smtp[132]: DEADBEEF01: '
               'to=<nowhere@dead.ru>, relay=none, dsn=5.1.1, status=bounced '
               '(User unknown)')
# journald/rsyslog пишут время в RFC3339 и без [pid] — форма префикса другая,
# а связка по queue-id обязана работать и там. Идентификаторы здесь — hex, как
# их печатает postfix: выдумывать «читаемые» id вроде LOCALID для строк, которые
# обязаны парситься, нельзя — парсер бы про них молчал, а тест бы «проходил».
ISO_QMGR = ('2026-09-25T09:41:12.318201+00:00 mail postfix/qmgr: 150E000001: '
            'from=<iso@x.ru>, size=100, nrcpt=1 (queue active)')
ISO_FAIL = ('2026-09-25T09:41:13.400000+00:00 mail postfix/smtp: 150E000001: '
            'to=<t@recv.ru>, relay=none, dsn=5.7.1, status=bounced '
            '(blocked using Spamhaus)')
# «queued as 8BDCA22DA71» — чужая очередь (письмо перенял другой MTA). Взять её
# вместо нашей означало бы искать потом причину отказа в чужом логе.
QUEUED_AS = ('Oct 10 12:00:14 host postfix/smtp[140]: F0DE000001: '
             'to=<m@b.ru>, relay=smtp.b.ru[9.9.9.9]:25, dsn=2.0.0, status=sent '
             '(250 Ok: queued as 8BDCA22DA71)')

# Полный лог для отчётных тестов: наш домен, «не наш», письмо без qmgr-строки и
# письмо с пустым конвертом — по одному, чтобы счётчики не перепутались.
SENDER_LOG = [PICKUP_LIE, CLEANUP_LIE, QMGR_LIE, FAIL_LIE,
              SMTPD_SASL, QMGR_SASL, FAIL_SHOP,
              ORPHAN_FAIL, QMGR_BOUNCE, FAIL_BOUNCE]


def _failures_of(*lines):
    """Отказы так же, как их отбирает снимок: известные статусы, кроме sent."""
    return [e for e in (logs_mod.parse_delivery_entry(l) for l in lines)
            if e and e['status'] in logs_mod.DELIVERY_STATUSES
            and e['status'] != 'sent']


class TestQueueIdParsing:
    def test_queue_id_taken_from_prefix(self):
        assert logs_mod.parse_queue_id(QMGR_LIE) == 'BE78A40083'
        assert logs_mod.parse_queue_id(FAIL_LIE) == 'BE78A40083'

    def test_iso_prefix_without_pid_supported(self):
        assert logs_mod.parse_queue_id(ISO_QMGR) == '150E000001'

    @pytest.mark.parametrize('line', (
        'Oct 10 12:00:00 host postfix/smtpd[9]: warning: queue is full',
        'Oct 10 12:00:00 host postfix/anvil[9]: statistics: max connection '
        'rate 2.00 for (a:1.2.3.4) at Oct 10 12:00:00',
        'Oct 10 12:00:00 host postfix/master[1]: fatal: open /etc/postfix/'
        'main.cf: No such file or directory',
        'Oct 10 12:00:00 host postfix/smtpd[1]: connect to unknown[1.2.3.4] '
        'failed: Connection timed out',
    ))
    def test_syslog_service_words_are_not_queue_ids(self, line):
        # Граница длины {4,…} открыла бы сюда дорогу: `warning` — семь букв.
        # Принять служебное слово за идентификатор — склеить все warning-строки
        # сервера в одно «письмо» и приписать ему чужой отказ.
        assert logs_mod.parse_queue_id(line) == ''

    def test_short_queue_id_of_old_postfix_is_accepted(self):
        # Старые версии печатают 4 символа (фикстуры проекта — AAA2, AAB0).
        # При жёсткой нижней границе привязка на таком сервере молча деградировала
        # бы в «не определён», а это читается как «письма не от наших доменов».
        line = ('Oct 10 12:00:01 host postfix/qmgr[9]: AAA2: '
                'from=<web@lie.ru>, size=100, nrcpt=1 (queue active)')
        assert logs_mod.parse_queue_id(line) == 'AAA2'
        assert logs_mod.parse_sender_entry(line)['from'] == 'web@lie.ru'

    @pytest.mark.parametrize('line', (
        'Oct 10 12:00:02 host postfix/smtpd[9]: connect from '
        'unknown[203.0.113.5]',
        'Oct 10 12:00:00 host postfix/master[1]: daemon started -- '
        'version 3.5.6',
    ))
    def test_noise_has_no_queue_id(self, line):
        # `connect from unknown[...]` формально похоже на «daemon[pid]:», но
        # идентификатора письма там нет: выдать за него «unknown» — склеить все
        # отказы приёма в одно «письмо».
        assert logs_mod.parse_queue_id(line) == ''

    def test_noqueue_is_not_a_queue_id(self):
        # smtpd пишет «NOQUEUE: reject:» — письма нет, оно не было принято.
        # Алфавит hex отсекает его уже сейчас (N, O, Q, U не шестнадцатеричные),
        # но NOT_A_QUEUE_ID остаётся явной защитой: если алфавит когда-нибудь
        # расширят, этот тест обязан остаться красным, а не тихо позеленеть.
        line = ('Oct 10 12:00:12 host postfix/smtpd[9]: NOQUEUE: reject: RCPT '
                'from unknown[203.0.113.5]: 550 Access denied')
        assert logs_mod.parse_queue_id(line) == ''

    def test_foreign_queue_id_in_reason_not_used(self):
        e = logs_mod.parse_delivery_entry(QUEUED_AS)
        assert e['qid'] == 'F0DE000001'
        assert '8BDCA22DA71' not in e['qid']


class TestSenderByQueueId:
    def test_pickup_qmgr_sasl_are_sources(self):
        idx = logs_mod.index_senders_by_queue_id(
            [PICKUP_LIE, CLEANUP_LIE, QMGR_LIE, SMTPD_SASL, ISO_QMGR])
        assert idx['BE78A40083']['from'] == 'web@lie.ru'
        assert idx['9A1F2B3C4D']['via'] == 'sasl'
        assert idx['150E000001'] == {'qid': '150E000001', 'from': 'iso@x.ru',
                                     'via': 'qmgr'}

    def test_first_record_wins(self):
        # qmgr печатает from= при каждой активации очереди, pickup — раньше.
        # Первый ответ и есть момент входа письма в очередь.
        idx = logs_mod.index_senders_by_queue_id([PICKUP_LIE, QMGR_LIE])
        assert idx['BE78A40083']['via'] == 'pickup'

    def test_cleanup_does_not_claim_sender(self):
        # cleanup(8) вставляет заголовки (message-id), а адрес конверта в лог не
        # печатает: искать его в этой строке негде.
        assert logs_mod.parse_sender_entry(CLEANUP_LIE) is None

    def test_removed_line_is_not_sender(self):
        assert logs_mod.parse_sender_entry(REMOVED_LIE) is None

    def test_empty_envelope_is_an_answer_not_a_miss(self):
        # from=<> — автоответ или уведомление о недоставке. Свести это к «не
        # нашли» нельзя: у такого письма отправителя действительно нет.
        rec = logs_mod.parse_sender_entry(QMGR_BOUNCE)
        assert rec is not None and rec['from'] == '' and rec['via'] == 'qmgr'

    def test_sasl_login_strips_trailing_comma(self):
        line = ('Oct 10 12:00:06 host postfix/smtpd[7]: 1111222233: '
                'client=h[1.2.3.4], sasl_method=LOGIN, sasl_username=a@b.ru, '
                'sasl_sender=')
        assert logs_mod.parse_sender_entry(line)['from'] == 'a@b.ru'

    def test_delivery_entry_carries_queue_id(self):
        # Без qid в разборе доставки связка невозможна в принципе.
        assert logs_mod.parse_delivery_entry(FAIL_LIE)['qid'] == 'BE78A40083'

    def test_three_states_of_sender_lookup(self):
        idx = logs_mod.index_senders_by_queue_id(
            [QMGR_LIE, QMGR_BOUNCE, ISO_QMGR])
        known = logs_mod.parse_delivery_entry(FAIL_LIE)
        assert logs_mod.sender_of_delivery(known, idx) == ('web@lie.ru', 'qmgr')
        bounce = logs_mod.parse_delivery_entry(FAIL_BOUNCE)
        assert logs_mod.sender_of_delivery(bounce, idx) == ('', 'qmgr')
        orphan = logs_mod.parse_delivery_entry(ORPHAN_FAIL)
        assert logs_mod.sender_of_delivery(orphan, idx) == ('', '')

    def test_sender_domain_of(self):
        assert logs_mod.sender_domain_of('Web@Lie.RU') == 'lie.ru'
        assert logs_mod.sender_domain_of('') == ''
        assert logs_mod.sender_domain_of('nosign') == ''


class TestFailureSenderSummary:
    def test_our_domains_come_from_inventory_only(self):
        idx = logs_mod.index_senders_by_queue_id(SENDER_LOG)
        summ = logs_mod.summarize_failure_senders(
            _failures_of(*SENDER_LOG), idx, ['lie.ru'])
        assert ('lie.ru', 1, True) in summ['known']
        # shop.ru — реальный отправитель, но в инвентаре почты его нет: назвать
        # его «нашим» было бы враньём, поэтому пометка False.
        assert ('shop.ru', 1, False) in summ['known']

    def test_empty_inventory_marks_nobody_ours(self):
        idx = logs_mod.index_senders_by_queue_id(SENDER_LOG)
        summ = logs_mod.summarize_failure_senders(
            _failures_of(*SENDER_LOG), idx)
        assert summ['known'] and not any(ours for _d, _n, ours in summ['known'])

    def test_unknown_and_empty_envelope_counted_separately(self):
        idx = logs_mod.index_senders_by_queue_id(SENDER_LOG)
        summ = logs_mod.summarize_failure_senders(
            _failures_of(*SENDER_LOG), idx, ['lie.ru'])
        # «нет qmgr-строки в окне» и «конверт пуст» — разные ответы: первое
        # лечится расширением окна лога, второе — ничем.
        assert summ['unknown'] == 1 and summ['empty'] == 1

    def test_sorted_by_count_then_name(self):
        idx = logs_mod.index_senders_by_queue_id(SENDER_LOG)
        summ = logs_mod.summarize_failure_senders(
            _failures_of(*SENDER_LOG, FAIL_LIE), idx, ['lie.ru'])
        assert summ['known'][0] == ('lie.ru', 2, True)


class TestFailureSenderLines:
    def _text(self, our_domains, compact=False):
        return '\n'.join(logs_mod.failure_sender_lines(
            _failures_of(*SENDER_LOG), '\n'.join(SENDER_LOG), our_domains,
            compact=compact))

    def test_our_domain_named_and_substantiated(self):
        text = self._text(['lie.ru'])
        assert 'По вашим почтовым доменам: lie.ru — 1' in text
        # Чем подтверждён адрес, сказано прямо: без этого строка выглядит как
        # догадка по тексту отказа.
        assert 'не угадан' in text

    def test_outsider_named_outsider(self):
        text = self._text(['lie.ru'])
        assert 'вне ваших почтовых доменов: shop.ru — 1' in text
        assert 'не значится в инвентаре' in text

    def test_no_inventory_says_it_was_not_checked(self):
        text = self._text(None)
        assert 'По вашим' not in text
        assert 'не проверялось' in text
        # Имя домена при этом остаётся: «не проверяли, чей он» ≠ «отправителей
        # нет».
        assert 'lie.ru' in text

    def test_unknown_phrased_as_not_visible(self):
        text = self._text(['lie.ru'])
        assert 'Отправитель не определён — 1' in text
        assert 'не видно' in text
        # Форма счётчика «сущность — число»: при одном отказе вывод обязан
        # читаться так же чисто, как при двенадцати.
        assert '1 отказов' not in text

    def test_empty_envelope_line(self):
        text = self._text(['lie.ru'])
        assert 'Писем без отправителя (from=<>) — 1' in text
        assert 'конверт пуст' in text

    def test_compact_is_one_line(self):
        out = logs_mod.failure_sender_lines(_failures_of(*SENDER_LOG),
                                            '\n'.join(SENDER_LOG), ['lie.ru'],
                                            compact=True)
        assert len(out) == 1
        assert 'по вашим доменам: lie.ru — 1' in out[0]
        assert 'иных отправителей: shop.ru — 1' in out[0]
        assert 'отправитель не определён: 1' in out[0]
        assert 'писем без отправителя: 1' in out[0]
        # Тире внутри этой строки стоит ровно один раз — после «отправители
        # отказов». Второе читалось бы как обрыв вывода.
        assert out[0].count(' — ') == 3  # по доменам: lie.ru — 1, иных: ... — 1

    def test_no_failures_no_lines(self):
        assert logs_mod.failure_sender_lines([], '\n'.join(SENDER_LOG),
                                            ['lie.ru']) == []

    def test_compact_head_says_no_link_when_nothing_resolved(self):
        # Ни один отказ не привязан к домену (qmgr-строк в окне нет). Бывший
        # заголовок давал тавтологию «отправители отказов — отправитель не
        # определён: 2», которая выглядит как сломанный вывод, хотя данные в
        # ней настоящие.
        lines = (ORPHAN_FAIL,
                 'Oct 10 12:00:14 host postfix/smtp[141]: DEADBEEF02: '
                 'to=<r@p.ru>, relay=none, dsn=5.1.1, status=bounced '
                 '(User unknown)')
        out = logs_mod.failure_sender_lines(_failures_of(*lines),
                                            '\n'.join(lines), ['lie.ru'],
                                            compact=True)
        assert len(out) == 1
        assert 'отказы без привязки к домену — отправитель не определён: 2' \
            in out[0]
        assert 'отправители отказов — отправитель' not in out[0]

    def test_compact_head_for_empty_envelope_only(self):
        # Пустой конверт — тоже «без привязки», но сказать надо именно про
        # конверт: «отправитель не определён» тут был бы неправдой (он известен
        # — его нет).
        out = logs_mod.failure_sender_lines(
            _failures_of(QMGR_BOUNCE, FAIL_BOUNCE),
            '\n'.join((QMGR_BOUNCE, FAIL_BOUNCE)), ['lie.ru'], compact=True)
        assert 'отказы без привязки к домену — писем без отправителя: 1' \
            in out[0]


class TestSenderInReports:
    def test_snapshot_shows_our_domain(self):
        out = '\n'.join(logs_mod.mail_log_snapshot_lines(
            FakeSSH(routes=_log_routes(*SENDER_LOG)), our_domains=['lie.ru']))
        assert 'По вашим почтовым доменам: lie.ru — 1' in out

    def test_snapshot_without_inventory_makes_no_claim(self):
        out = '\n'.join(logs_mod.mail_log_snapshot_lines(
            FakeSSH(routes=_log_routes(*SENDER_LOG))))
        assert 'По вашим' not in out and 'не проверялось' in out

    def test_snapshot_still_costs_one_read(self):
        # Индекс отправителей строится из УЖЕ прочитанного фрагмента: привязка
        # не имеет права удвоить цену отчёта.
        c = FakeSSH(routes=_log_routes(*SENDER_LOG))
        logs_mod.mail_log_snapshot_lines(c, our_domains=['lie.ru'])
        assert c.count('for __p in') == 1

    def test_digest_gets_exactly_one_sender_line(self):
        out = '\n'.join(logs_mod.mail_delivery_digest_lines(
            FakeSSH(routes=_log_routes(*SENDER_LOG)), our_domains=['lie.ru']))
        assert 'отправители отказов —' in out
        assert out.count('отправители отказов') == 1

    def test_digest_costs_one_read(self):
        c = FakeSSH(routes=_log_routes(*SENDER_LOG))
        logs_mod.mail_delivery_digest_lines(c, our_domains=['lie.ru'])
        assert c.count('for __p in') == 1

    def test_no_failures_means_no_sender_lines(self):
        # «Отказов нет» + пометка «по вашим доменам» — это уже выдуманный
        # отправитель: строк об отправителях при нулевом счёте быть не должно.
        out = '\n'.join(logs_mod.mail_log_snapshot_lines(
            FakeSSH(routes=_log_routes(SENT)), our_domains=['lie.ru']))
        assert 'По вашим' not in out and 'Отказов нет' in out
