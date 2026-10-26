"""Тесты bitrix.py: BitrixVM-диагностика без реального SSH (FakeSSH).

Чистые функции (расчёт буфера, генерация конфига MySQL, разбор dbconn.php,
notAfter, mailq) проверяются напрямую; отчёты — маршрутизацией команд в
FakeSSH. Порядок маршрутов важен: первое совпадение по подстроке выигрывает.
"""
import os
import re
import shlex
import sys
from datetime import datetime, timedelta, timezone

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

import pytest

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

    # ============ 1.32.4: закрытый каталог — это НЕ «пустой» ================
    # Прежний код перечислял каталог так:
    #
    #     out, _, _ = checker.run(f'ls -1 {q(directory)} 2>/dev/null')
    #
    # Замер живьём (три каталога, мой uid): пустой — rc=0 и пустой stdout;
    # закрытый (chmod 000) — rc=2 и «Permission denied»; читаемый — rc=0 и
    # список имён. Различитель СУЩЕСТВОВАЛ — его выбрасывали дважды: заглушкой
    # stderr и `_, _` для кода возврата. Отчёт называл отсутствие прав
    # отсутствием сайтов, а лечение у этих случаев противоположное: поднимать
    # права против искать другой домен. Тот же закон, что закрыт для поиска
    # файлов в 1.20.0, на новом носителе.
    CLOSED = ('', "ls: cannot open directory '/etc/nginx/bx/site_avaliable': "
                  'Permission denied', 2)

    def test_closed_vhost_dir_is_not_called_no_sites(self):
        c = FakeSSH(routes=[('ls -1', self.CLOSED)])
        assert bx.bitrix_sites(c) == []
        rep = bx.bitrix_sites_report(c)
        assert 'не найдены' not in rep, rep
        assert 'прав' in rep, rep

    def test_closed_certs_dir_is_not_called_no_certs(self):
        # Замер живьём: в закрытом каталоге лежал shop.ru, а отчёт утверждал
        # «сертификаты не выпускались» — оператора это отправляет выпускать
        # сертификат, которого нельзя коснуться, а не чинить права.
        c = FakeSSH(routes=[('ls -1', ('', 'ls: cannot open directory: '
                                           'Permission denied', 2))])
        rep = bx.bitrix_ssl_report(c)
        assert 'не выпускались' not in rep, rep
        assert 'прав' in rep, rep

    def test_honest_emptiness_keeps_its_own_words(self):
        # Контрпример (закон: запрещающий guard обязан иметь контрпример).
        # rc=0 и пустой вывод — честная пустота, и выдумывать ей «нет прав»
        # нельзя: иначе правильный guard обесценит настоящие находки.
        c = FakeSSH(routes=[('ls -1', ('', '', 0))])
        rep = bx.bitrix_sites_report(c)
        assert 'не найдены' in rep, rep
        assert 'прав' not in rep, rep

    def test_stderr_is_no_longer_thrown_away(self):
        # Поведенческий замок по ОТПРАВЛЕННОЙ команде (не по исходнику):
        # 2>/dev/null терял ровно ту строку, где написана причина пустоты.
        c = FakeSSH(routes=[('ls -1', self.CLOSED)])
        bx.bitrix_sites(c)
        cmd = c.find('ls -1')
        assert cmd is not None, 'перечисление каталога не ушло на сервер'
        assert '2>/dev/null' not in cmd, cmd


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
        assert '⚠️ Задания dehydrated нет ни в crontab root' in out

    def test_report_no_certs(self):
        out = bx.bitrix_ssl_report(FakeSSH())
        assert 'пусто' in out

    def test_find_dehydrated_cron_root_wins(self):
        # игла 'grep -rlF' отличается от команды root crontab — маршруты не спорят
        c = FakeSSH(routes=[
            ('crontab -l 2>/dev/null | grep -F dehydrated',
             '30 3 * * * /home/bitrix/dehydrated/dehydrated -c\n'),
            ('grep -rlF', '/etc/cron.d/bx-dehydrated\n'),
        ])
        root, files = bx.find_dehydrated_cron(c)
        assert 'dehydrated -c' in root and files == ['/etc/cron.d/bx-dehydrated']

    def test_find_dehydrated_cron_dedups_and_sorts(self):
        c = FakeSSH(routes=[
            ('grep -rlF', '/etc/cron.daily/x\n/etc/cron.d/dehydrated\n'
                         '/etc/cron.daily/x\n'),
        ])
        root, files = bx.find_dehydrated_cron(c)
        assert root == ''
        assert files == ['/etc/cron.d/dehydrated', '/etc/cron.daily/x']

    def test_report_cron_d_is_not_an_error(self):
        # штатная раскладка BitrixVM: задания нет в root crontab, оно в cron.d
        c = FakeSSH(routes=[
            ('ls -1', 'site.ru\n'),
            ('openssl', 'notAfter=Oct 12 13:45:00 2099 GMT'),
            ('grep -rlF', '/etc/cron.d/dehydrated\n'),
        ])
        out = bx.bitrix_ssl_report(c)
        assert '✅ Перевыпуск настроен вне root crontab' in out
        assert '/etc/cron.d/dehydrated' in out
        assert 'придётся вручную' not in out

    def test_report_root_cron_shows_the_line(self):
        c = FakeSSH(routes=[
            ('crontab -l 2>/dev/null | grep -F dehydrated',
             '30 3 * * * cd /home/bitrix/dehydrated && ./dehydrated -c\n'),
        ])
        out = bx.bitrix_ssl_report(c)
        assert '✅ Перевыпуск настроен в crontab root' in out
        assert '30 3 * * *' in out

    def test_report_searches_all_cron_dirs(self):
        # отчёт обязан смотреть не только spool root: периодика BitrixVM — в cron.*
        c = FakeSSH()
        bx.bitrix_ssl_report(c)
        grep_cmd = c.find('grep -rlF')
        assert grep_cmd is not None
        for path in bx.DEHYDRATED_CRON_DIRS:
            assert path in grep_cmd, f'{path} не ищется'

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


# ==================== права на базу (GRANTS) ====================
# Формат вывода SHOW GRANTS — как у MySQL 8: объект базы в backticks сидит в
# середине ('`db`.*'), учётка — `user`@`host`.
GRANTS_USAGE_ONLY = 'GRANT USAGE ON *.* TO `bitrix_user`@`localhost`\n'
GRANTS_PARTIAL = ('GRANT USAGE ON *.* TO `bitrix_user`@`localhost`\n'
                  'GRANT SELECT, INSERT, UPDATE, DELETE ON `bitrix_db`.* '
                  'TO `bitrix_user`@`localhost`\n')
GRANTS_FULL = ('GRANT ALL PRIVILEGES ON `bitrix_db`.* '
               'TO `bitrix_user`@`localhost`\n')
GRANTS_GLOBAL_ALL = ('GRANT ALL PRIVILEGES ON *.* '
                     "TO `bitrix_user`@`localhost` WITH GRANT OPTION\n")
GRANTS_OTHER_DB = (
    'GRANT SELECT, INSERT, UPDATE, DELETE, CREATE, DROP, ALTER, INDEX, '
    'CREATE TEMPORARY TABLES, LOCK TABLES, EXECUTE, TRIGGER, SHOW VIEW, '
    'EVENT ON `old_db`.* TO `bitrix_user`@`localhost`\n')
GRANTS_TABLE_LEVEL = (GRANTS_PARTIAL +
                      'GRANT SELECT ON `bitrix_db`.`b_module` '
                      'TO `bitrix_user`@`localhost`\n')


def _grants_routes(show):
    """Иглы для чтения прав. 'SHOW GRANTS' стоит раньше любых 'GRANT'-игл:
    первое совпадение по подстроке выигрывает."""
    return [('cat', DBCONN_TEXT),
            ('SELECT CURRENT_USER()', 'bitrix_user@localhost\n'),
            ('SHOW GRANTS FOR CURRENT_USER()', show)]


class TestGrantsPure:
    def test_parse_current_user(self):
        assert bx.parse_current_user('bitrix_user@localhost') == \
            ('bitrix_user', 'localhost')
        assert bx.parse_current_user('u@%\n') == ('u', '%')
        assert bx.parse_current_user('') == (None, None)
        assert bx.parse_current_user('без собачки') == (None, None)

    def test_parse_grants_partial(self):
        parsed = bx.parse_grants(GRANTS_PARTIAL, 'bitrix_db')
        assert parsed['db'] == {'SELECT', 'INSERT', 'UPDATE', 'DELETE'}
        assert parsed['global'] == set()      # USAGE прав не даёт
        assert parsed['dbs'] == {'bitrix_db'}
        missing = bx.missing_grants(parsed)
        assert 'CREATE' in missing and 'SELECT' not in missing
        assert missing[0] == 'CREATE'         # порядок = порядок GRANT_REQUIRED

    def test_parse_grants_all_on_db(self):
        parsed = bx.parse_grants(GRANTS_FULL, 'bitrix_db')
        assert parsed['db_all'] is True
        assert bx.missing_grants(parsed) == []

    def test_parse_grants_all_global(self):
        parsed = bx.parse_grants(GRANTS_GLOBAL_ALL, 'bitrix_db')
        assert parsed['all'] is True
        assert bx.missing_grants(parsed) == []

    def test_parse_grants_table_level_collected(self):
        parsed = bx.parse_grants(GRANTS_TABLE_LEVEL, 'bitrix_db')
        assert ('b_module', {'SELECT'}) in parsed['tables']
        assert parsed['db'] == {'SELECT', 'INSERT', 'UPDATE', 'DELETE'}

    def test_parse_grants_wrong_db(self):
        # «переименовали базу»: права полные, но на другой базе
        parsed = bx.parse_grants(GRANTS_OTHER_DB, 'bitrix_db')
        assert parsed['dbs'] == {'old_db'}
        assert parsed['db'] == set()
        assert bx.missing_grants(parsed) == list(bx.GRANT_REQUIRED)

    def test_grants_sql_shape(self):
        sql = bx.grants_sql('bitrix_db', 'bitrix_user', 'localhost',
                            ['CREATE', 'DROP'])
        assert sql == ("GRANT CREATE, DROP ON `bitrix_db`.* "
                       "TO 'bitrix_user'@'localhost'; FLUSH PRIVILEGES")

    def test_ident_safe(self):
        assert bx.ident_safe('bitrix_db') and bx.ident_safe('db-1')
        assert bx.ident_safe('u') and bx.ident_safe('%')       # хост-маска
        assert not bx.ident_safe("bad'name") and not bx.ident_safe('a;b')
        assert not bx.ident_safe('') and not bx.ident_safe(None)


class TestGrantsReport:
    def test_report_full_set(self):
        c = FakeSSH(routes=_grants_routes(GRANTS_FULL),
                    client=FakeSftpClient())
        out = bx.bitrix_db_grants_report(c)
        assert '✅ Набор привилегий' in out
        assert 'bitrix_user@localhost' in out
        # пароль — только в defaults-файл; права читались ровно 2 запросом
        assert 'sup3r-secret' not in ' '.join(c.commands)
        assert c.count('--defaults-extra-file') == 2
        assert c.find('rm -f') is not None

    def test_report_missing_lists_and_shows_sql(self):
        out = bx.bitrix_db_grants_report(
            FakeSSH(routes=_grants_routes(GRANTS_PARTIAL),
                    client=FakeSftpClient()))
        assert '⚠️ Не хватает: CREATE, DROP' in out
        assert 'FLUSH PRIVILEGES' in out

    def test_report_usage_only_is_red(self):
        out = bx.bitrix_db_grants_report(
            FakeSSH(routes=_grants_routes(GRANTS_USAGE_ONLY),
                    client=FakeSftpClient()))
        assert 'Не хватает' in out and 'SELECT' in out

    def test_report_wrong_db_hint(self):
        out = bx.bitrix_db_grants_report(
            FakeSSH(routes=_grants_routes(GRANTS_OTHER_DB),
                    client=FakeSftpClient()))
        assert 'Строк прав на DBName=bitrix_db нет' in out and 'old_db' in out

    def test_report_connection_failed(self):
        c = FakeSSH(routes=[
            ('cat', DBCONN_TEXT),
            ('SELECT CURRENT_USER()', ('ERROR 2002 cannot connect', '', 1)),
        ], client=FakeSftpClient())
        out = bx.bitrix_db_grants_report(c)
        assert '❌ Подключение к базе не прошло' in out

    def test_report_missing_dbconn(self):
        out = bx.bitrix_db_grants_report(
            FakeSSH(routes=[('cat', ('', 'no such file', 1))]))
        assert '❌' in out and 'dbconn.php' in out


class TestGrantsFix:
    def test_fix_nothing_to_grant(self):
        c = FakeSSH(routes=_grants_routes(GRANTS_FULL),
                    client=FakeSftpClient())
        out = bx.bitrix_db_grants_fix(c)
        assert '⚠️ Выдавать нечего' in out
        assert c.find('mysql -N -e') is None          # GRANT не отправляли

    def test_fix_grants_and_rereads(self):
        # после выдачи перечитывание обязан увидеть полный набор —
        # для этого у иглы два последовательных ответа
        c = FakeSSH(routes=[
            ('cat', DBCONN_TEXT),
            ('SELECT CURRENT_USER()', ['bitrix_user@localhost',
                                       'bitrix_user@localhost']),
            ('SHOW GRANTS FOR CURRENT_USER()', [GRANTS_PARTIAL, GRANTS_FULL]),
        ], client=FakeSftpClient())
        out = bx.bitrix_db_grants_fix(c)
        assert '✅ Права выданы' in out
        assert 'sup3r-secret' not in ' '.join(c.commands)
        grant_cmd = c.find('mysql -N -e')
        assert grant_cmd is not None
        sql = shlex.split(grant_cmd)[-2]      # последний токен — '2>&1'
        assert 'GRANT CREATE' in sql and 'FLUSH PRIVILEGES' in sql
        # 4 обращения через defaults-файл: до выдачи и после перечитывания
        assert c.count('--defaults-extra-file') == 4

    def test_fix_root_denied(self):
        c = FakeSSH(routes=_grants_routes(GRANTS_PARTIAL) +
                    [('mysql -N -e', ('ERROR 1045 Access denied for root',
                                      '', 1))],
                    client=FakeSftpClient())
        out = bx.bitrix_db_grants_fix(c)
        assert '❌ mysql (под root) не принял' in out
        assert '.my.cnf' in out

    def test_fix_still_missing_after_grant(self):
        # перечитывание видит те же неполные права (у root нет GRANT OPTION)
        c = FakeSSH(routes=_grants_routes(GRANTS_PARTIAL),
                    client=FakeSftpClient())
        out = bx.bitrix_db_grants_fix(c)
        assert '⚠️ После выдачи всё ещё не хватает' in out
        assert 'GRANT OPTION' in out

    def test_fix_refuses_unsafe_ident(self):
        bad = DBCONN_TEXT.replace('"bitrix_db"', '"bitrix;db"')
        c = FakeSSH(routes=[('cat', bad),
                            ('SELECT CURRENT_USER()', 'bitrix_user@localhost'),
                            ('SHOW GRANTS FOR CURRENT_USER()',
                             GRANTS_PARTIAL)],
                    client=FakeSftpClient())
        out = bx.bitrix_db_grants_fix(c)
        assert '❌' in out and 'вне безопасного' in out
        assert c.find('mysql -N -e') is None


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


# ==================== почта: тест отправки ====================
SENT_ENTRY = ('Oct 10 12:00:01 host postfix/smtp[123]: AAA111: '
              'to=<operator@example.com>, relay=mx.example.com[1.2.3.4]:25, '
              'status=sent (250 2.0.0 Ok)')
BOUNCE_ENTRY = ('Oct 10 12:00:01 host postfix/smtp[123]: AAA111: '
                'to=<operator@example.com>, relay=none, '
                'status=bounced (host not found)')

# 'printf %s' — команда отправки; '/var/log/maillog' — поиск записи теста;
# 'journalctl -u postfix -n 50' — fallback; 'mailq' — очередь.
_MAIL_SEND_ROUTES = [
    ('command -v sendmail', '/usr/sbin/sendmail'),
]


def _send_routes(log_entry='', queue='Mail queue is empty', send_rc=0):
    return _MAIL_SEND_ROUTES + [
        ('printf %s', ('', '', send_rc)),
        ('/var/log/maillog', log_entry),
        ('journalctl -u postfix -n 50', ''),
        ('mailq 2>&1', queue),
    ]


class TestMailSend:
    def test_valid_email(self):
        assert bx.valid_email('a@b.ru') and bx.valid_email('op+1@site.co.uk')
        assert not bx.valid_email('a@b')            # без точки в домене
        assert not bx.valid_email('a@b.ru; rm - /')  # пробелы/точки с запятой
        assert not bx.valid_email('@b.ru') and not bx.valid_email('')
        assert not bx.valid_email(None)

    def test_bad_email_sends_nothing(self):
        c = FakeSSH()
        out = bx.bitrix_mail_send_test(c, 'плохой адрес')
        assert '❌' in out and 'не отправляю' in out
        assert c.commands == []                     # ни одной команды

    def test_no_sendmail(self):
        c = FakeSSH()                               # command -v -> пусто
        out = bx.bitrix_mail_send_test(c, 'op@example.com')
        assert '❌ sendmail не найден' in out
        assert c.find('printf %s') is None

    def test_sendmail_failure_reported(self):
        c = FakeSSH(routes=_send_routes(send_rc=1))
        out = bx.bitrix_mail_send_test(c, 'op@example.com')
        assert '❌ sendmail вернул rc=1' in out

    def test_sent_status_is_success(self):
        c = FakeSSH(routes=_send_routes(log_entry=SENT_ENTRY))
        out = bx.bitrix_mail_send_test(c, 'operator@example.com')
        assert '✅ Письмо ушло с сервера (status=sent)' in out
        assert 'SPF/PTR' in out                     # подсказка про «не дошло»
        # поиск записи шёл по точному получателю
        log_cmd = c.find('/var/log/maillog')
        assert log_cmd is not None
        assert 'to=<operator@example.com>' in log_cmd
        # письмо собиралось через q(): переносы строк доехали экранированными;
        # формат команды: printf %s <msg> | /usr/sbin/sendmail -t 2>&1
        send_cmd = c.find('printf %s')
        assert send_cmd is not None
        tokens = shlex.split(send_cmd)
        assert tokens[:2] == ['printf', '%s']
        assert '/usr/sbin/sendmail' in tokens
        assert 'Subject: ' + bx.MAIL_TEST_SUBJECT in tokens[2]

    def test_bounce_is_red(self):
        c = FakeSSH(routes=_send_routes(log_entry=BOUNCE_ENTRY))
        out = bx.bitrix_mail_send_test(c, 'operator@example.com')
        assert '❌ Письмо отбито (status=bounced)' in out

    def test_no_entry_but_queued(self):
        c = FakeSSH(routes=_send_routes(queue='-- 3 Messages'))
        out = bx.bitrix_mail_send_test(c, 'operator@example.com')
        assert '⚠️ В очереди 3 писем' in out

    def test_no_entry_empty_queue_points_to_mail_log(self):
        # Debian пишет в /var/log/mail.log, а мы его не читаем — честная подсказка
        c = FakeSSH(routes=_send_routes())
        out = bx.bitrix_mail_send_test(c, 'operator@example.com')
        assert '/var/log/mail.log' in out and 'ls -l /var/log/mail*' in out

    def test_log_and_mailq_both_dead(self):
        c = FakeSSH(routes=[
            ('command -v sendmail', '/usr/sbin/sendmail'),
            ('printf %s', ('', '', 0)),
            ('/var/log/maillog', ''),
            ('journalctl -u postfix -n 50', ''),
            ('mailq 2>&1', 'postqueue: fatal: unable to connect'),
        ])
        out = bx.bitrix_mail_send_test(c, 'operator@example.com')
        assert '⚠️ Ни лог, ни mailq не отвечают' in out


# ==================== установка cron-агентов ====================
# Порядок маршрутов: игла '| crontab -' — подстрока КОМАНДЫ УСТАНОВКИ
# ({ crontab -l 2>/dev/null; echo ...; } | crontab -), поэтому она обязана
# стоять раньше 'crontab -l 2>/dev/null', иначе установка получила бы ответ
# от маршрута чтения текущего crontab.
def _install_routes(grep_out='', cur='', setup=('', '', 0)):
    return [
        ('| crontab -', setup),
        ('crontab -l 2>/dev/null | grep', grep_out),
        ('crontab -l 2>/dev/null', cur),
        ('test -f', 'ok'),
    ]


class TestCronInstall:
    def test_missing_script_does_not_touch_crontab(self):
        c = FakeSSH()          # test -f -> '' (скрипта нет)
        out = bx.bitrix_cron_install(c)
        assert '❌' in out and 'cron.sh' in out
        assert c.find('| crontab -') is None

    def test_existing_entry_is_not_duplicated(self):
        already = bx.CRON_LINE
        c = FakeSSH(routes=_install_routes(cur=already + '\n'))
        out = bx.bitrix_cron_install(c)
        assert '⚠️' in out and 'дублировать' in out
        assert c.find('| crontab -') is None

    def test_installs_and_reads_back(self):
        c = FakeSSH(routes=_install_routes(grep_out=bx.CRON_LINE))
        out = bx.bitrix_cron_install(c)
        assert '✅ Задание в crontab:' in out and 'Агенты начнут' in out
        setup = c.find('| crontab -')
        assert setup is not None
        # строка в команде заэкранирована и доехала целиком
        assert bx.CRON_LINE in shlex.split(setup)[-1] or bx.CRON_LINE in setup
        assert c.find('crontab -l >') is not None      # бэкап до правки

    def test_crontab_rejects_line(self):
        c = FakeSSH(routes=_install_routes(setup=('bad field count', '', 1)))
        out = bx.bitrix_cron_install(c)
        assert '❌' in out and 'bad field count' in out

    def test_silent_write_is_reported_missing(self):
        # rc=0, но в crontab строки нет — верить на слово нельзя
        c = FakeSSH(routes=_install_routes(grep_out=''))
        out = bx.bitrix_cron_install(c)
        assert '❌ Строка в crontab не появилась' in out

    def test_report_and_install_share_one_line(self):
        # отчёт рекомендует ровно то, что ставит кнопка
        rep = bx.bitrix_cron_report(FakeSSH())
        assert bx.CRON_LINE in rep


# ==================== кеш (Redis / Memcached) ====================
SETTINGS_REDIS = "<?php return array('type' => 'redis', 'host' => 'localhost');"
SETTINGS_PLAIN = "<?php return array('type' => 'files');"


class TestCache:
    def test_detect_backends_needs_quoted_literal(self):
        assert bx.detect_cache_backends(SETTINGS_REDIS) == ['redis']
        assert bx.detect_cache_backends('"memcached"') == ['memcached']
        # слово без кавычек — текст комментария, а не бэкенд
        assert bx.detect_cache_backends('// redis отключён') == []
        assert bx.detect_cache_backends('') == []
        assert bx.detect_cache_backends(None) == []

    def test_first_active_unit_prefers_debian_name(self):
        # 'is-active redis' — подстрока 'is-active redis-server': порядок важен
        c = FakeSSH(routes=[
            ('is-active redis-server', 'active\n'),
            ('is-active redis', 'inactive\n'),
        ])
        assert bx.first_active_unit(c, ('redis', 'redis-server')) == 'redis-server'

    def test_first_active_unit_none(self):
        assert bx.first_active_unit(FakeSSH(), ('redis',)) is None

    def test_report_redis_ok(self):
        c = FakeSSH(routes=[
            ('cat', SETTINGS_REDIS),
            ('redis-cli ping', 'PONG'),
            ('is-active redis', 'active\n'),
            ('du -sh', '2.1G\t/home/bitrix/www/bitrix/cache\n'),
        ])
        out = bx.bitrix_cache_report(c)
        assert 'Бэкенд(ы) кеша в .settings.php: redis' in out
        assert '✅ redis: служба redis активна' in out
        assert '✅ redis-cli ping: PONG' in out
        assert '• memcached: не используется' in out
        assert 'bitrix/cache: 2.1G' in out

    def test_report_backend_configured_but_down(self):
        c = FakeSSH(routes=[('cat', SETTINGS_REDIS), ('is-active', 'inactive')])
        out = bx.bitrix_cache_report(c)
        assert '❌ redis в .settings.php указан, но служба не запущена' in out

    def test_report_ping_not_pong(self):
        c = FakeSSH(routes=[
            ('cat', SETTINGS_REDIS),
            ('is-active redis', 'active\n'),
            ('redis-cli ping', "NOAUTH Authentication required."),
        ])
        out = bx.bitrix_cache_report(c)
        assert '⚠️ redis-cli ping' in out

    def test_report_no_backend_is_the_common_case(self):
        c = FakeSSH(routes=[('cat', SETTINGS_PLAIN)])
        out = bx.bitrix_cache_report(c)
        assert '⚠️ В .settings.php кеш-бэкенда нет' in out

    def test_report_unreadable_settings(self):
        c = FakeSSH(routes=[('cat', ('', 'Permission denied', 1))])
        out = bx.bitrix_cache_report(c)
        assert '.settings.php не читается' in out


# ==================== оставшиеся ветки отчётов ====================
#
# Маршруты ниже обязаны учитывать порядок запросов внутри отчётов: игла
# 'test -d' подстрокой покрывает и 'test -w' (одна команда в отчёте прав),
# 'mailq 2>&1' стоит отдельно от 'mailq' в тесте отправки, а '/var/log/maillog'
# встречается и в отчёте, и в поиске записи теста.

class TestParseEdgeBranches:
    def test_cnf_size_kibibytes(self):
        # 'K' в my.cnf — KiB: округление вниз, 1024K = ровно 1M
        assert bx.parse_cnf_size('2048K') == 2
        assert bx.parse_cnf_size('1023K') == 0
        assert bx.parse_cnf_size(' 2g ') == 2048      # пробелы и нижний регистр

    def test_buffer_stats_skips_non_numeric(self):
        # строка похожа по префиксу, но значение не int — строка пропускается,
        # hit ratio считается по валидным строкам (None только если валидных нет)
        text = ('Innodb_buffer_pool_read_requests abc\n'
                'Innodb_buffer_pool_read_requests 100\n'
                'Innodb_buffer_pool_reads 5\n')
        assert bx.parse_buffer_stats(text) == 95.0
        # без валидных строк — None, отчёт обязан это пережить
        assert bx.parse_buffer_stats(
            'Innodb_buffer_pool_read_requests abc\n') is None

    def test_notafter_garbage_date_returns_none(self):
        # формат совпадает, даты такой нет: strptime бросает ValueError -> None,
        # SSL-отчёт обязан поставить ⚠️, а не упасть
        assert bx.parse_notafter('notAfter=Xxx 99 99:99:99 2026 GMT') is None

    def test_mailq_count_non_numeric_message_line(self):
        assert bx.parse_mailq_count('-- lots Messages') is None
        assert bx.parse_mailq_count('-- 3 Messages') == 3

    def test_grants_ignores_garbage_lines(self):
        # в выводе SHOW GRANTS оказался мусор (mysql warning) — строка
        # пропускается, остальное разбирается как обычно
        parsed = bx.parse_grants(GRANTS_PARTIAL + 'Warning: misc output\n',
                                 'bitrix_db')
        assert parsed['db'] == {'SELECT', 'INSERT', 'UPDATE', 'DELETE'}
        assert parsed['dbs'] == {'bitrix_db'}


def _notafter(days_ahead):
    """notAfter в формате openssl — относительно СЕЙЧАС.

    Фикстированная дата ('Oct 20 2026') сделала бы тест зависимым от системных
    часов: через месяц он падал бы не из-за регресса. Держим срок в днях.
    """
    dt = datetime.now(timezone.utc) + timedelta(days=days_ahead)
    return 'notAfter=' + dt.strftime('%b %d %H:%M:%S %Y') + ' GMT'


class TestSSLReportMarks:
    # ПОРЯДОК маршрутов обязателен: путь сертификата содержит '/certs', так что
    # игла '/certs' покрывает и openssl-запрос. Специфичная 'openssl' идёт
    # первой, иначе openssl получил бы список доменов (первое совпадение
    # выигрывает) и тест проходил бы ложно.
    def test_expiring_soon_is_red(self):
        # days < 14 — красный маркер: dehydrated перевыпускает за 30 дней,
        # если до истечения меньше двух недель — задание уже не работает
        c = FakeSSH(routes=[
            ('openssl', _notafter(5)),
            ('/certs', 'shop.ru\n'),
        ])
        out = bx.bitrix_ssl_report(c)
        assert '❌ shop.ru' in out and 'осталось' in out

    def test_long_lived_certificate_is_green(self):
        c = FakeSSH(routes=[
            ('openssl', _notafter(120)),
            ('/certs', 'shop.ru\n'),
        ])
        out = bx.bitrix_ssl_report(c)
        # .days у timedelta урезан (notAfter на несколько часов позже «сейчас»
        # съедает остаток суток), поэтому вместо точного '120' сверяется
        # диапазон; точная арифметика дней закреплена юнит-тестом
        # test_parse_notafter
        assert '✅ shop.ru' in out
        m = re.search(r'осталось (\d+) дн\.', out)
        assert m and 118 <= int(m.group(1)) <= 120

    def test_unparsable_certificate_is_warning(self):
        c = FakeSSH(routes=[
            ('openssl', 'Could not read certificate from /x'),
            ('/certs', 'shop.ru\n'),
        ])
        out = bx.bitrix_ssl_report(c)
        assert '⚠️ shop.ru' in out and 'осталось' not in out

    def test_dehydrated_log_tail_shown(self):
        c = FakeSSH(routes=[('tail -n 15', 'Processing domain shop.ru\n')])
        out = bx.bitrix_ssl_report(c)
        assert 'dehydrated_update.log (последние 15 строк)' in out
        assert 'Processing domain shop.ru' in out


class TestSitesReportEmpty:
    def test_no_vhosts_says_so(self):
        out = bx.bitrix_sites_report(FakeSSH())
        assert 'nginx/bx' in out and '⚠️' in out


class TestMySQLReportBranches:
    def test_ram_unparsable_does_not_crash(self):
        # строка 'Mem:' без числа (ломаный free): int() бросает, отчёт обязан
        # продолжить работу без RAM и без рекомендации
        c = FakeSSH(routes=[('free -m', 'Mem:\n')])
        out = bx.bitrix_mysql_report(c)
        assert 'Не удалось определить RAM' in out
        assert 'дефолт 128M' in out

    def test_pool_close_to_recommendation_is_not_alarming(self):
        # 8G RAM -> рекомендация 3200M; пул 3072M: не «мало в два раза» и не
        # «не меньше рекомендации» — честная ветка «близко, критичным не выглядит»
        c = FakeSSH(routes=[
            ('free -m', MEM8),
            ('grep -E', 'innodb_buffer_pool_size = 3072M\n'),
        ])
        out = bx.bitrix_mysql_report(c)
        assert 'близко, критичным не выглядит' in out

    def test_tune_write_failure_reported(self):
        store = _WriteFailClient()
        c = FakeSSH(routes=[('free -m', MEM8), ('grep -Eq', 'ok')], client=store)
        out = bx.bitrix_mysql_tune(c)
        assert '❌ Не удалось записать' in out
        assert 'Применится после' not in out


class _WriteFailClient:
    """open_sftp живой, но запись файла бросает (read-only, диск полон)."""

    def open_sftp(self):
        raise IOError('Read-only file system')


class TestGrantsErrorPaths:
    def test_report_incomplete_dbconn_names_missing_key(self):
        bad = DBCONN_TEXT.replace('define("DBName", "bitrix_db");', '')
        out = bx.bitrix_db_grants_report(FakeSSH(routes=[('cat', bad)]))
        assert 'не найдено: DBName' in out

    def test_report_grants_query_failure(self):
        # подключение есть (CURRENT_USER прочитался), а SHOW GRANTS отбит —
        # отдельная ветка, её operators видят при read-only учётке
        c = FakeSSH(routes=[
            ('cat', DBCONN_TEXT),
            ('SELECT CURRENT_USER()', 'bitrix_user@localhost\n'),
            ('SHOW GRANTS FOR CURRENT_USER()',
             ('ERROR 1045: access denied', '', 1)),
        ], client=FakeSftpClient())
        out = bx.bitrix_db_grants_report(c)
        assert 'SHOW GRANTS не прошёл' in out
        assert '1045' in out

    def test_report_mentions_table_level_grants(self):
        out = bx.bitrix_db_grants_report(
            FakeSSH(routes=_grants_routes(GRANTS_TABLE_LEVEL),
                    client=FakeSftpClient()))
        assert 'Прав на отдельные таблицы: 1' in out

    def test_report_unsafe_ident_points_to_manual(self):
        # имя базы с запрещённым символом: SQL не отправляем даже в подсказке
        bad = DBCONN_TEXT.replace('"bitrix_db"', '"bitrix db"')
        out = bx.bitrix_db_grants_report(
            FakeSSH(routes=[
                ('cat', bad),
                ('SELECT CURRENT_USER()', 'bitrix_user@localhost'),
                ('SHOW GRANTS FOR CURRENT_USER()', GRANTS_PARTIAL),
            ], client=FakeSftpClient()))
        assert 'соберите GRANT вручную' in out

    def test_fix_incomplete_dbconn(self):
        bad = DBCONN_TEXT.replace('define("DBName", "bitrix_db");', '')
        out = bx.bitrix_db_grants_fix(FakeSSH(routes=[('cat', bad)]))
        assert 'не найдено: DBName' in out

    def test_fix_reread_failure_is_reported(self):
        # GRANT прошёл (rc=0), но перечитать права не удалось: второй заход
        # CURRENT_USER падает — «верить на слово» нельзя, обязано быть ⚠️
        c = FakeSSH(routes=[
            ('cat', DBCONN_TEXT),
            ('SELECT CURRENT_USER()', ['bitrix_user@localhost',
                                       ('ERROR 2002 can\'t connect', '', 1)]),
            ('SHOW GRANTS FOR CURRENT_USER()', GRANTS_PARTIAL),
        ], client=FakeSftpClient())
        out = bx.bitrix_db_grants_fix(c)
        assert 'перечитать права не вышло' in out
        assert '✅ Права выданы' not in out


class TestPermsMissingDirs:
    def test_absent_writable_dir_is_warning(self):
        # ни ok, ни ro: каталога нет (например, merged_cache в старой сборке) —
        # ⚠️ «каталог не найден», а не ❌ «нет доступа»
        c = FakeSSH(routes=_perms_routes(dirs=''))
        out = bx.bitrix_perms_report(c)
        assert 'каталог не найден' in out

    def test_world_writable_count_unparsable_stays_quiet(self):
        # счётчик o+w не разобрался — врать про «дыру» нельзя: строки с числом
        # в отчёте не будет вообще
        c = FakeSSH(routes=_perms_routes(world_cnt='find: error'))
        out = bx.bitrix_perms_report(c)
        assert 'доступных на запись всем' not in out


class TestMailReportBranches:
    def test_mailq_dead_is_reported(self):
        c = FakeSSH(routes=[('mailq 2>&1', '')])
        out = bx.bitrix_mail_report(c)
        assert '⚠️ mailq не отвечает' in out

    def test_journalctl_fallback_when_maillog_empty(self):
        # Debian пишет не в maillog: при пустом maillog отчёт обязан показать
        # journalctl, а не сделать вид, что логов нет
        c = FakeSSH(routes=[
            ('/var/log/maillog', ''),
            ('journalctl -u postfix -n 15', 'postfix/master: daemon started'),
        ])
        out = bx.bitrix_mail_report(c)
        assert 'journalctl -u postfix' in out
        assert 'daemon started' in out


class TestMailSendUnknownStatus:
    def test_entry_without_known_status(self):
        # запись по получателю есть, но status= не распознан (deferred/OE) —
        # отчёт обязан сказать «смотрите полную строку», а не «✅ ушло»
        entry = ('Oct 10 12:00:01 host postfix/smtp[1]: AAA1: '
                 'to=<operator@example.com>, relay=none, delayed 3600 secs')
        c = FakeSSH(routes=_send_routes(log_entry=entry))
        out = bx.bitrix_mail_send_test(c, 'operator@example.com')
        assert 'без знакомого status' in out
        assert 'status=sent' not in out


class TestDbSecretSurvivesCancel:
    """Отмена посреди mysql: файл с паролем БД обязан исчезнуть ( Regression:
    rm шёл через checker.run и падал от cancel_event — пароль оставался)."""

    class _CancelDuringMysql(FakeSSH):
        """Отмена СЕРЕДИ команды, как это делает транспорт.

        cancel() закрывает канал текущего запроса, и run() на этой команде
        бросает. Дальше все обычные run() тоже отказаны — поэтому rm,
        записанный через checker.run (как было до фикса), до сервера бы не
        дошёл, и файл с паролем БД остался бы навсегда. Проходит только
        cleanup().
        """

        def __init__(self, *args, **kwargs):
            FakeSSH.__init__(self, *args, **kwargs)
            self.cancelled = False
            self.cleaned = []

        def run(self, cmd):
            self.commands.append(cmd)
            if self.cancelled or 'mysql' in cmd:
                self.cancelled = True
                raise Exception('Операция отменена')
            return self._answer(cmd)

        def cleanup(self, cmd):
            self.cleaned.append(cmd)
            self.commands.append(cmd)
            return self._answer(cmd)

    def test_wipe_survives_cancellation(self):
        store = FakeSftpClient()
        c = self._CancelDuringMysql(routes=[('cat', DBCONN_TEXT)], client=store)
        with pytest.raises(Exception, match='Операция отменена'):
            bx.bitrix_db_check(c)
        # Отмена есть, а уборка всё равно дошла — и именно служебным каналом.
        # Ищем команду с проверкой факта [ -e ], т.к. 'rm -f <cnf>' встречается
        # и в подготовке файла (первый cleanup), а не только в уборке.
        assert any('[ -e ' + bx.DBCHECK_CNF in cmd for cmd in c.cleaned), c.cleaned
        assert c.find('rm -f ' + bx.DBCHECK_CNF) is not None
        assert 'sup3r-secret' not in ' '.join(c.commands)
        # файл с паролем реально создавался (иначе проверять было бы нечего)
        assert store.store[bx.DBCHECK_CNF].count('sup3r-secret') == 1

    def test_secret_file_is_0600_before_password(self):
        # Права ставятся в том же вызове, что и создание файла: до того, как
        # в файле появится пароль (иначе окно world-readable + отмена = секрет
        # в открытом доступе для всех на сервере)
        store = FakeSftpClient()
        c = FakeSSH(routes=[('cat', DBCONN_TEXT)], client=store)
        bx.bitrix_db_check(c)
        prep = c.find('umask 077')
        assert prep is not None and 'chmod 600' in prep
        assert prep.index('umask 077') < prep.index(': >') < prep.index('chmod 600')
        assert store.store[bx.DBCHECK_CNF].count('sup3r-secret') == 1

    def test_wipe_failure_is_visible_in_report(self):
        # rm -f молчит и когда не смог (read-only /tmp, права): факт проверяем
        # [ -e ], а причина обязана дойти до отчёта. Иначе пароль БД лежит в
        # /tmp, а оператору нарисован зелёный ✅ — худший вид молчания.
        store = FakeSftpClient()
        c = FakeSSH(routes=[('cat', DBCONN_TEXT),
                            ('echo STILL_THERE', ('STILL_THERE\n', '', 0))],
                    client=store)
        out = bx.bitrix_db_check(c)
        assert '✅' in out                          # запрос-то удался
        assert c.find('STILL_THERE') is not None    # факт проверен, а не угадан
        assert 'Не удалось удалить временный файл с паролем БД' in out
        assert bx.DBCHECK_CNF in out                # путь, чтобы удалить руками
        assert 'sup3r-secret' not in out            # но сам секрет — нет

    def test_grants_report_carries_wipe_warning_too(self):
        # warn проброшен во ВСЕ отчёты, что дёргают mysql: у GRANTS свой путь
        # через _current_grants, и потерять там причину было проще всего.
        # Отчёт при этом обязан остаться читаемым, а секрет — не показан.
        store = FakeSftpClient()
        c = FakeSSH(routes=[
            ('cat', DBCONN_TEXT),
            ('SELECT CURRENT_USER', ('ERROR 1045: Access denied', '', 1)),
            ('echo STILL_THERE', ('STILL_THERE\n', '', 0)),
        ], client=store)
        out = bx.bitrix_db_grants_report(c)
        assert 'Подключение к базе не прошло' in out
        assert 'Не удалось удалить временный файл с паролем БД' in out
        assert bx.DBCHECK_CNF in out
        assert 'sup3r-secret' not in out


# ==================== почтовый лог: общая read_mail_log ====================
# Эти тесты запирают два решения, а не одну функцию.
#
# Первое: почтовый лог читает ОДНА функция (logs.read_mail_log). У нас уже были
# парные реализации, и здесь расхождение выглядело бы как «в отчёте Битрикса лог
# есть, в сводке — логов нет» на одном сервере. Дубль проверяется ПОВЕДЕНИЕМ:
# сколько команд ушло на сервер, а не разбором исходника (счётчик команд — то,
# что оператор и так видит в логе операций).
#
# Второе: Debian. Раньше читался только /var/log/maillog, а /var/log/mail.log —
# нет; об этом прямо говорил наш собственный текст («лог может писаться в
# /var/log/mail.log»), и тест констатировал «мы его не читаем». На Debian отчёт
# о почте был слеп.
GMAIL_BOUNCE = ('Oct 10 12:00:05 host postfix/smtp[124]: AAA2: to=<c@gmail.com>, '
                'relay=gmail-smtp-in.l.google.com[142.251.8.27]:25, dsn=5.7.26, '
                'status=bounced (gmail-smtp-in.l.google.com[142.251.8.27] said: '
                '550-5.7.26 unauthenticated mail was rejected, please learn '
                'about SPF)')


def _mail_log_routes(body=''):
    """Одна игла на весь выбор файла: цикл maillog/mail.log живёт ВНУТРИ команды."""
    return [('for __p in',
             ('#LOG /var/log/mail.log\n' + body + '\n') if body else '')]


class TestMailLogSingleImplementation:
    """Ни одного отдельного чтения почтового лога мимо read_mail_log."""

    def test_report_uses_the_shared_reader_only(self):
        c = FakeSSH(routes=[('is-active postfix', 'active'),
                            ('mailq', 'Mail queue is empty')]
                   + _mail_log_routes(GMAIL_BOUNCE))
        bx.bitrix_mail_report(c)
        # Ровно одна команда-чтение: цикл по обоим путям внутри неё.
        assert c.count('for __p in') == 1
        # Старых точечных чтений остаться не должно ни в каком виде.
        assert c.count('tail -n 15 /var/log/maillog') == 0
        assert c.count('journalctl -u postfix -n 15') == 0

    def test_send_test_uses_the_shared_reader_only(self):
        c = FakeSSH(routes=[('command -v sendmail', '/usr/sbin/sendmail'),
                            ('printf %s', ('', '', 0)),
                            ('mailq', 'Mail queue is empty')]
                   + _mail_log_routes('AAA: to=<op@example.com>, status=sent '
                                      '(250 Ok)'))
        bx.bitrix_mail_send_test(c, 'op@example.com')
        assert c.count('for __p in') == 1
        assert c.count('tail -n 50 /var/log/maillog') == 0
        assert c.count('journalctl -u postfix -n 50') == 0


class TestMailLogDebianPath:
    """Debian пишет в /var/log/mail.log — раньше этот путь не читался нигде."""

    def test_report_reads_mail_log_and_names_the_source(self):
        c = FakeSSH(routes=[('is-active postfix', 'active'),
                            ('mailq', 'Mail queue is empty')]
                   + _mail_log_routes(GMAIL_BOUNCE))
        out = bx.bitrix_mail_report(c)
        assert '/var/log/mail.log (последние 15 строк)' in out
        # Источник в заголовке — не украшение: по нему видно, чей rsyslog править.
        assert 'unauthenticated mail was rejected' in out
        # '-- No entries --' — вывод journalctl о пустом журнале, а не содержимое
        # лога; прежний код печатал его оператору как строки лога.
        assert '-- No entries --' not in out

    def test_send_test_finds_its_entry_on_debian(self):
        c = FakeSSH(routes=[('command -v sendmail', '/usr/sbin/sendmail'),
                            ('printf %s', ('', '', 0)),
                            ('mailq', 'Mail queue is empty')]
                   + _mail_log_routes('AAA: to=<operator@example.com>, '
                                      'relay=g[1]:25, status=sent (250 Ok)'))
        out = bx.bitrix_mail_send_test(c, 'operator@example.com')
        assert '✅ Письмо ушло с сервера (status=sent)' in out
        assert '(/var/log/mail.log)' in out
        # Поиск обязан идти по ОБОИМ путям, иначе на Debian запись «не найдена»
        # при целом логе — то есть вранье про успешно ушедшее письмо.
        cmd = c.find('for __p in')
        assert '/var/log/mail.log' in cmd and '/var/log/maillog' in cmd
        assert 'to=<operator@example.com>' in cmd

    def test_prompt_no_longer_promises_a_path_we_now_read(self):
        # Текст «лог может писаться в /var/log/mail.log» после починки стал бы
        # ложью: путь читается, обещание надо снять, а не оставить «на всякий».
        c = FakeSSH(routes=[('command -v sendmail', '/usr/sbin/sendmail'),
                            ('printf %s', ('', '', 0)),
                            ('mailq', 'Mail queue is empty')]
                   + _mail_log_routes(''))
        out = bx.bitrix_mail_send_test(c, 'operator@example.com')
        assert 'лог может писаться' not in out
        assert 'ls -l /var/log/mail*' in out         # ручная проверка осталась
        assert 'повторите через минуту' in out       # асинхронность postfix
