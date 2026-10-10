"""Тесты bitrix.py: BitrixVM-диагностика без реального SSH (FakeSSH).

Чистые функции (расчёт буфера, генерация конфига MySQL, разбор dbconn.php,
notAfter, mailq) проверяются напрямую; отчёты — маршрутизацией команд в
FakeSSH. Порядок маршрутов важен: первое совпадение по подстроке выигрывает.
"""
import os
import shlex
import sys
from datetime import datetime

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from support import FakeSSH, FakeSftpClient
import bitrix as bx

MEM8 = '               total        used        free\nMem:            8192        4000        1000\n'
DBCONN_TEXT = '''<?php
define("DBHost", "localhost");
define("DBLogin", "bitrix_user");
define("DBPassword", "sup3r-secret");
define("DBName", "bitrix_db");
define("DBDebug", "true");
$DB(type = null) = "mysql";
'''


# ==================== окружение и сайты ====================
class TestDetect:
    def test_true_when_both_dirs(self):
        c = FakeSSH(routes=[('ls -d', '/home/bitrix\n/opt/webdir\n')])
        assert bx.detect_bitrix_env(c) is True

    def test_false_when_only_one(self):
        c = FakeSSH(routes=[('ls -d', '/opt/webdir\n')])
        assert bx.detect_bitrix_env(c) is False

    def test_false_on_empty_server(self):
        assert bx.detect_bitrix_env(FakeSSH()) is False


class TestSites:
    def test_dedup_and_filter_service_files(self):
        c = FakeSSH(routes=[
            ('site_avaliable', 'site1\nsite2\nbx_certificate.conf\ndefault\n'),
            ('site_available', 'site2\nsite3\n'),
        ])
        assert bx.bitrix_sites(c) == ['site1', 'site2', 'site3']

    def test_empty_when_no_vhosts(self):
        assert bx.bitrix_sites(FakeSSH()) == []

    def test_report_lists_sites(self):
        c = FakeSSH(routes=[('site_avaliable', 'shop.ru\n')])
        out = bx.bitrix_sites_report(c)
        assert 'shop.ru' in out and 'САЙТЫ' in out


# ==================== чистые функции ====================
class TestPure:
    def test_recommend_rounds_to_chunk(self):
        assert bx.recommend_innodb_buffer(8192) == 3200   # 3276 -> 25*128
        assert bx.recommend_innodb_buffer(16384) == 6528  # 6553 -> 51*128

    def test_recommend_min_and_bad_input(self):
        assert bx.recommend_innodb_buffer(512) == 256     # нижняя граница
        assert bx.recommend_innodb_buffer(0) is None
        assert bx.recommend_innodb_buffer(None) is None

    def test_tune_config(self):
        conf = bx.mysql_tune_config(8192)
        assert conf is not None
        assert 'innodb_buffer_pool_size = 3200M' in conf
        assert 'innodb_flush_method = O_DIRECT' in conf
        assert bx.mysql_tune_config(0) is None

    def test_parse_cnf_size(self):
        assert bx.parse_cnf_size('128M') == 128
        assert bx.parse_cnf_size('2G') == 2048
        assert bx.parse_cnf_size('134217728') == 128      # байты
        assert bx.parse_cnf_size('') is None
        assert bx.parse_cnf_size('abc') is None

    def test_parse_buffer_stats(self):
        text = ('Innodb_buffer_pool_read_requests\t1000000\n'
                'Innodb_buffer_pool_reads\t100\n')
        ratio = bx.parse_buffer_stats(text)
        assert ratio is not None
        assert abs(ratio - 99.99) < 0.01
        assert bx.parse_buffer_stats('ERROR 1045') is None

    def test_parse_dbconn_both_forms(self):
        vals = bx.parse_dbconn(DBCONN_TEXT)
        assert vals['DBHost'] == 'localhost'
        assert vals['DBLogin'] == 'bitrix_user'
        assert vals['DBName'] == 'bitrix_db'
        assert vals['DBPassword'] == 'sup3r-secret'
        assert 'DBDebug' not in vals                      # только DB*-ключи
        vals2 = bx.parse_dbconn('$DBHost = "127.0.0.1";\n$DBLogin = "u";')
        assert vals2['DBHost'] == '127.0.0.1'
        assert bx.parse_dbconn('') == {}

    def test_parse_notafter(self):
        now = datetime(2026, 10, 10, 12, 0, 0)
        days = bx.parse_notafter('notAfter=Oct 20 13:45:00 2026 GMT', now=now)
        assert days == 10
        assert bx.parse_notafter('Could not read certificate') is None

    def test_parse_mailq_count(self):
        assert bx.parse_mailq_count('-- 5 Messages') == 5
        assert bx.parse_mailq_count('Mail queue is empty') == 0
        assert bx.parse_mailq_count('bash: mailq: command not found') is None

    def test_total_mem_mb(self):
        assert bx.total_mem_mb(FakeSSH(routes=[('free -m', MEM8)])) == 8192
        assert bx.total_mem_mb(FakeSSH()) is None


# ==================== SSL ====================
class TestSSL:
    def test_report_shows_dates_and_missing_cron(self):
        c = FakeSSH(routes=[
            ('ls -1', 'site.ru\n'),
            ('openssl', 'notAfter=Oct 12 13:45:00 2099 GMT'),
        ])
        out = bx.bitrix_ssl_report(c)
        assert '✅ site.ru' in out and 'осталось' in out
        assert '⚠️ В crontab задания dehydrated нет' in out

    def test_report_no_certs(self):
        out = bx.bitrix_ssl_report(FakeSSH())
        assert 'пусто' in out

    def test_renew_requires_binary(self):
        c = FakeSSH()
        out = bx.bitrix_ssl_renew(c)
        assert '❌' in out
        assert c.find('cd /home/bitrix/dehydrated') is None

    def test_renew_runs_dehydrated(self):
        c = FakeSSH(routes=[
            ('test -x', 'ok'),
            ('dehydrated -c', 'Processing domain site.ru ... done'),
        ])
        out = bx.bitrix_ssl_renew(c)
        assert 'Код завершения: 0' in out and 'site.ru' in out


# ==================== MySQL ====================
class TestMySQL:
    def test_report_default_pool_and_no_stats(self):
        c = FakeSSH(routes=[
            ('free -m', MEM8),
            ('SHOW GLOBAL STATUS', "ERROR 1045 (28000): Access denied for user 'root'"),
        ])
        out = bx.bitrix_mysql_report(c)
        assert 'дефолт 128M' in out
        assert 'Рекомендация: 3200M' in out
        assert 'Статус InnoDB не получен' in out

    def test_report_good_pool_and_hit_ratio(self):
        c = FakeSSH(routes=[
            ('free -m', MEM8),
            ('grep -E', 'innodb_buffer_pool_size = 4096M\n'),
            ('SHOW GLOBAL STATUS',
             'Innodb_buffer_pool_read_requests\t1000000\nInnodb_buffer_pool_reads\t10\n'),
        ])
        out = bx.bitrix_mysql_report(c)
        assert '✅ Буфер не меньше рекомендации' in out
        assert '✅ Hit ratio buffer pool' in out

    def test_tune_writes_include_file(self):
        store = FakeSftpClient()
        c = FakeSSH(routes=[('free -m', MEM8), ('grep -Eq', 'ok')], client=store)
        out = bx.bitrix_mysql_tune(c)
        assert '✅' in out and 'restart mysqld' in out
        content = store.store[bx.TUNE_FILE]
        assert 'innodb_buffer_pool_size = 3200M' in content
        assert c.find('chmod 600') is not None

    def test_tune_refuses_without_includedir(self):
        store = FakeSftpClient()
        c = FakeSSH(routes=[('free -m', MEM8)], client=store)
        out = bx.bitrix_mysql_tune(c)
        assert '❌' in out and store.store == {}
        assert 'innodb_buffer_pool_size = 3200M' in out  # значения для ручной правки

    def test_tune_without_mem_changes_nothing(self):
        store = FakeSftpClient()
        c = FakeSSH(client=store)
        out = bx.bitrix_mysql_tune(c)
        assert '❌' in out and store.store == {}


# ==================== доступ к базе ====================
class TestDbCheck:
    def test_success_wipes_temp_file_and_hides_password(self):
        store = FakeSftpClient()
        c = FakeSSH(routes=[('cat', DBCONN_TEXT)], client=store)
        out = bx.bitrix_db_check(c)
        assert '✅' in out and 'DBPassword=задан' in out
        # пароль уехал только в protected-файл, но не в командную строку
        assert 'sup3r-secret' not in ' '.join(c.commands)
        assert store.store[bx.DBCHECK_CNF].count('sup3r-secret') == 1
        assert c.find('rm -f') is not None
        assert c.find('chmod 600') is not None

    def test_access_denied_gives_grant_hint(self):
        c = FakeSSH(routes=[
            ('cat', DBCONN_TEXT),
            ('SELECT 1', ('ERROR 1044 (42000): Access denied for user', '', 1)),
        ], client=FakeSftpClient())
        out = bx.bitrix_db_check(c)
        assert '❌' in out and 'GRANT' in out

    def test_missing_dbconn(self):
        c = FakeSSH(routes=[('cat', ('', 'no such file', 1))])
        out = bx.bitrix_db_check(c)
        assert '❌' in out and 'dbconn.php' in out


# ==================== топ-таблицы БД ====================
TOP_TABLES_OUT = (
    'b_cache_tag\t1843.2\t12000000\n'
    'b_user_session\t512.7\t340000\n'
    'b_iblock_element\t210.5\t48000\n'
    'b_sale_basket\t4.1\t900\n'
)


class TestTopTables:
    def test_parse_top_tables(self):
        rows = bx.parse_top_tables(TOP_TABLES_OUT)
        assert len(rows) == 4
        assert rows[0] == {'table': 'b_cache_tag', 'size_mb': 1843.2,
                           'rows': '12000000'}

    def test_parse_skips_foreign_lines(self):
        assert bx.parse_top_tables('ERROR 1142 (42000): SELECT command denied') == []
        assert bx.parse_top_tables('x\tabc\t1\n') == []
        assert bx.parse_top_tables('') == []
        assert bx.parse_top_tables(None) == []

    def test_garbage_hints_threshold(self):
        hints = '\n'.join(bx.garbage_hints(bx.parse_top_tables(TOP_TABLES_OUT)))
        assert 'b_cache_tag' in hints and 'b_user_session' in hints
        assert 'b_sale_basket' not in hints          # 4 МБ — ниже порога
        assert 'НЕ удалять вручную' in hints         # теги кеша руками не чистят

    def test_report_total_and_hints(self):
        c = FakeSSH(routes=[
            ('cat', DBCONN_TEXT),
            ('SELECT TABLE_NAME', TOP_TABLES_OUT),
        ], client=FakeSftpClient())
        out = bx.bitrix_db_tables_report(c)
        assert '=== ТОП-20 ТАБЛИЦ БАЗЫ БИТРИКС ===' in out and 'Топ-4' in out
        assert '💡 b_cache_tag' in out
        # пароль ушёл только в defaults-файл, но не в командную строку
        assert 'sup3r-secret' not in ' '.join(c.commands)
        assert c.find('rm -f') is not None

    def test_report_query_failure(self):
        c = FakeSSH(routes=[
            ('cat', DBCONN_TEXT),
            ('SELECT TABLE_NAME',
             ('ERROR 1142 (42000): SELECT command denied to user', '', 1)),
        ], client=FakeSftpClient())
        out = bx.bitrix_db_tables_report(c)
        assert '❌' in out and '1142' in out

    def test_report_no_rows(self):
        c = FakeSSH(routes=[('cat', DBCONN_TEXT), ('SELECT TABLE_NAME', '')],
                    client=FakeSftpClient())
        out = bx.bitrix_db_tables_report(c)
        assert '⚠️' in out and 'information_schema' in out


# ==================== права файлов сайта ====================
def _perms_routes(owner_cnt='0', world_cnt='0', dirs='ok'):
    """Маршруты для bitrix_perms_report: dirs — ответ на test -d/test -w."""
    return [
        ('ls -ld', 'drwxr-xr-x 42 bitrix bitrix 4096 Oct 10 12:00 /home/bitrix/www'),
        ('! -user', owner_cnt + '\n'),
        ('-perm -o+w', world_cnt + '\n'),
        ('test -d', dirs + '\n'),
    ]


class TestPerms:
    def test_report_all_good(self):
        c = FakeSSH(routes=_perms_routes())
        out = bx.bitrix_perms_report(c)
        assert '✅ Все файлы принадлежат bitrix' in out
        assert '✅ world-writable файлов нет' in out
        assert '✅ upload: запись есть' in out
        assert '/home/bitrix/www' in out

    def test_report_flags_broken_owners_and_perms(self):
        c = FakeSSH(routes=_perms_routes(owner_cnt='1234', world_cnt='7'))
        out = bx.bitrix_perms_report(c)
        assert 'Файлов с другим владельцем: 1234' in out
        assert 'доступных на запись всем (o+w): 7' in out

    def test_report_readonly_cache_dir(self):
        routes = _perms_routes()
        # кеш-каталог есть, но без записи — кеш и агенты работать не будут
        routes.append(('bitrix/cache', 'ro\n'))
        c = FakeSSH(routes=[routes[-1]] + routes[:-1])
        out = bx.bitrix_perms_report(c)
        assert '❌ bitrix/cache' in out

    def test_report_missing_docroot_stops(self):
        c = FakeSSH(routes=[('ls -ld', ('', 'No such file or directory', 1))])
        out = bx.bitrix_perms_report(c)
        assert '❌' in out and '/home/bitrix/www' in out
        assert c.find('! -user') is None      # дальше не идём

    def test_report_unparsable_count(self):
        c = FakeSSH(routes=_perms_routes(owner_cnt='find: error'))
        out = bx.bitrix_perms_report(c)
        assert 'Не удалось посчитать владельцев' in out

    def test_fix_requires_group(self):
        # группы bitrix нет -> chown отправлять нельзя
        c = FakeSSH()
        out = bx.bitrix_perms_fix(c)
        assert '❌' in out and 'bitrix' in out   # имя группы названо в ошибке
        assert c.find('chown') is None

    def test_fix_runs_expected_commands(self):
        c = FakeSSH(routes=[('getent group', 'ok')])
        out = bx.bitrix_perms_fix(c)
        assert '✅ Владелец bitrix:bitrix восстановлен' in out
        assert '✅ Каталогам выставлены 755' in out
        assert '✅ Файлам выставлены 644' in out
        assert 'upload' in out
        # {} в find -exec обязан доехать буквально, без удвоения
        assert c.find('-exec chmod 755 {} +') is not None
        assert c.find("-exec chmod g+w {} +") is not None
        # q() НЕ кавычит путь из одних безопасных символов — проверяем аргумент
        # разбором, а не поиском кавычек в строке.
        chown_cmd = c.find('chown -R')
        assert chown_cmd is not None
        parts = shlex.split(chown_cmd)
        assert parts[:3] == ['chown', '-R', 'bitrix:bitrix']
        assert '/home/bitrix/www' in parts

    def test_fix_reports_chown_failure(self):
        c = FakeSSH(routes=[
            ('getent group', 'ok'),
            ('chown -R', ('chown: cannot access', '', 1)),
        ])
        out = bx.bitrix_perms_fix(c)
        assert '❌ chown (rc=1)' in out


# ==================== PHP / cron / почта ====================
class TestPhp:
    def test_report_flags_missing_module(self):
        c = FakeSSH(routes=[
            ('php -v', 'PHP 8.1.10 (cli)'),
            ('ls -d', '/opt/php\n/opt/php-8.1\n'),
            ('php.ini', 'memory_limit = 512M'),
            ('php -m', 'curl\ngd\niconv\njson\ndom\nmbstring\nmysqli\n'
                       'openssl\nsimplexml\nxml\nzip\n'),
        ])
        out = bx.bitrix_php_report(c)
        assert 'PHP 8.1.10' in out
        assert 'memory_limit = 512M' in out
        assert 'Нет модулей: intl' in out


class TestCron:
    def test_present_cron_entry(self):
        c = FakeSSH(routes=[
            ('test -f', 'ok'),
            ('grep -F cron.sh', '7:* * * * * sudo -u bitrix /home/bitrix/www/bitrix/modules/main/tools/cron.sh'),
        ])
        out = bx.bitrix_cron_report(c)
        assert '✅' in out and 'cron.sh' in out

    def test_missing_entry_shows_recommendation(self):
        out = bx.bitrix_cron_report(FakeSSH())
        assert 'sudo -u bitrix' in out and '*/1 * * * *' in out


class TestMail:
    def test_report_ok(self):
        c = FakeSSH(routes=[
            ('is-active postfix', 'active'),
            ('mailq', 'Mail queue is empty'),
            ('/var/log/maillog', 'postfix/qmgr: status=sent'),
        ])
        out = bx.bitrix_mail_report(c)
        assert '✅ Очередь пуста' in out and 'status=sent' in out

    def test_report_queue_stuck(self):
        c = FakeSSH(routes=[('mailq', '-- 42 Messages')])
        out = bx.bitrix_mail_report(c)
        assert '42' in out and '⚠️' in out
