"""Тесты logs.py: поиск логов по панелям, анализ access-логов, домены, OOM.

Реального SSH нет — команды перехватывает FakeSSH из support.py.
"""
import os
import sys

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
