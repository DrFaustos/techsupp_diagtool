"""Тесты common.py: бэкапы, SFTP-запись, поиск/чтение файлов, извлечение доменов.

Реального SSH нет: команды перехватывает FakeSSH из support.py, SFTP — FakeSftpClient.
"""
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

import shlex

import pytest

from support import FakeSSH, FakeSftpClient
import common


BACKUP_OK = [('mkdir -p', ('created', '', 0)), ('test -f', ('exists', '', 0))]


class _RaisingClient:
    def open_sftp(self):
        raise IOError('ssh channel closed')


class TestEnsureBackupDir:
    def test_true_when_created(self):
        c = FakeSSH(routes=BACKUP_OK)
        assert common.ensure_backup_dir(c) is True

    def test_false_when_command_failed(self):
        c = FakeSSH(routes=[('mkdir -p', ('', 'permission denied', 1))])
        assert common.ensure_backup_dir(c) is False

    def test_creates_every_subdir(self):
        c = FakeSSH(routes=BACKUP_OK)
        common.ensure_backup_dir(c)
        for subdir in common.BACKUP_SUBDIRS.values():
            assert c.find(f'mkdir -p {subdir}') is not None


class TestCreateBackup:
    def test_returns_timestamped_path(self):
        c = FakeSSH(routes=BACKUP_OK)
        path = common.create_backup(c, '/etc/nginx/nginx.conf', 'configs')
        assert path is not None
        assert path.startswith('/root/tech_support/configs/nginx.conf.')
        assert path.endswith('.bak')

    def test_copies_original_to_backup(self):
        c = FakeSSH(routes=BACKUP_OK)
        path = common.create_backup(c, '/etc/nginx/nginx.conf', 'configs')
        cp = c.find('cp /etc/nginx/nginx.conf')
        assert cp is not None
        assert cp == f'cp /etc/nginx/nginx.conf {path} 2>&1'

    def test_missing_source_returns_none_and_no_copy(self):
        c = FakeSSH(routes=[('mkdir -p', ('created', '', 0)),
                            ('test -f', ('', '', 1))])
        assert common.create_backup(c, '/etc/nope.conf') is None
        assert c.find('cp ') is None

    def test_failed_copy_returns_none(self):
        c = FakeSSH(routes=[('mkdir -p', ('created', '', 0)),
                            ('test -f', ('', '', 1))])
        # источник есть, а вот проверка бэкапа (второй test -f) падает
        class Twice(FakeSSH):
            def __init__(self):
                super().__init__(routes=[('mkdir -p', ('created', '', 0))])
                self.tests = 0

            def run(self, cmd):
                self.commands.append(cmd)
                if cmd.startswith('test -f'):
                    self.tests += 1
                    # первый вызов — источник существует, второй — бэкапа нет
                    return ('exists', '', 0) if self.tests == 1 else ('', '', 1)
                return ('', '', 0)

        assert common.create_backup(Twice(), '/etc/nginx/nginx.conf') is None

    def test_backup_type_selects_subdir(self):
        c = FakeSSH(routes=BACKUP_OK)
        path = common.create_backup(c, '/etc/resolv.conf', 'dns')
        assert path.startswith('/root/tech_support/dns/resolv.conf.')

    def test_unknown_type_falls_back_to_configs(self):
        c = FakeSSH(routes=BACKUP_OK)
        path = common.create_backup(c, '/etc/x.conf', 'нет-такого-типа')
        assert path.startswith('/root/tech_support/configs/x.conf.')

    def test_path_with_spaces_is_quoted(self):
        c = FakeSSH(routes=BACKUP_OK)
        common.create_backup(c, '/etc/my conf/nginx.conf', 'configs')
        assert c.find("cp '/etc/my conf") is not None


class TestSaveCrontabBackup:
    def test_ok_path(self):
        c = FakeSSH(routes=[('mkdir -p', ('created', '', 0)),
                            ('crontab -l', ('ok', '', 0))])
        path = common.save_crontab_backup(c)
        assert path.startswith('/root/tech_support/crontab/crontab.')
        assert path.endswith('.bak')
        assert c.find(f'crontab -l > {path}') is not None

    def test_none_when_crontab_failed(self):
        c = FakeSSH(routes=[('mkdir -p', ('created', '', 0)),
                            ('crontab -l', ('', 'no crontab', 127))])
        assert common.save_crontab_backup(c) is None


class TestWriteRemoteFile:
    def test_writes_content_and_closes(self):
        client = FakeSftpClient()
        c = FakeSSH(client=client)
        ok, err = common.write_remote_file(c, '/etc/resolv.conf',
                                           'nameserver 1.1.1.1\n')
        assert ok is True and err is None
        assert client.store['/etc/resolv.conf'] == 'nameserver 1.1.1.1\n'
        assert client.closed == 1

    def test_open_sftp_failure_reported(self):
        c = FakeSSH(client=_RaisingClient())
        ok, err = common.write_remote_file(c, '/etc/x', 'data')
        assert ok is False
        assert 'Не удалось открыть SFTP' in err

    def test_write_error_reported(self):
        class ReadOnlyStore(FakeSftpClient):
            def open_sftp(self):
                conn = super().open_sftp()
                conn.open = lambda path, mode='r': (_ for _ in ()).throw(
                    IOError('read-only file system'))
                return conn

        c = FakeSSH(client=ReadOnlyStore())
        ok, err = common.write_remote_file(c, '/etc/x', 'data')
        assert ok is False
        assert 'read-only' in err


class TestFindFiles:
    def test_lists_files(self):
        c = FakeSSH(routes=[('ls -1', '/a.log\n/b.log\n')])
        assert common.find_files(c, '/var/log/*.log') == ['/a.log', '/b.log']

    def test_appends_limit_warning(self):
        c = FakeSSH(routes=[('ls -1', '/a.log\n/b.log\n/c.log\n')])
        files = common.find_files(c, '/var/log/*.log', 2)
        assert files[:2] == ['/a.log', '/b.log']
        assert files[-1].startswith('⚠️')
        assert 'head -2' in c.find('ls -1')

    def test_no_warning_under_limit(self):
        c = FakeSSH(routes=[('ls -1', '/a.log\n')])
        assert common.find_files(c, '/var/log/*.log', 20) == ['/a.log']

    def test_glob_is_not_quoted_on_purpose(self):
        # pattern — shell-glob, его нельзя экранировать (иначе ls ничего не найдёт)
        c = FakeSSH(routes=[('ls -1', '')])
        common.find_files(c, '/var/log/nginx/*.log')
        assert c.find('ls -1 /var/log/nginx/*.log') is not None


class TestFindFile:
    def test_returns_first_hit(self):
        c = FakeSSH(routes=[('apache2', ''), ('nginx', '/etc/nginx/nginx.conf\n')])
        got = common.find_file(c, ['/etc/apache2/apache2.conf', '/etc/nginx/nginx.conf'])
        assert got == '/etc/nginx/nginx.conf'

    def test_none_when_nothing_exists(self):
        c = FakeSSH(routes=[('ls -1', '   \n')])
        assert common.find_file(c, ['/a', '/b']) is None


class TestReadFileContent:
    def test_returns_text(self):
        c = FakeSSH(routes=[('cat ', 'hello\n')])
        assert common.read_file_content(c, '/etc/x') == 'hello\n'

    def test_none_on_error_rc(self):
        c = FakeSSH(routes=[('cat ', ('', 'No such file', 1))])
        assert common.read_file_content(c, '/etc/x') is None

    def test_path_quoted(self):
        c = FakeSSH(routes=[('cat ', '')])
        common.read_file_content(c, '/etc/my file')
        assert c.find("cat '/etc/my file'") is not None


class TestGetDomainFromConfig:
    RAW = ('server {\n'
           '    server_name example.com www.example.com;\n'
           '}\n')

    def test_extracts_domains(self):
        c = FakeSSH(routes=[('grep -h', 'example.com\nwww.example.com\n')])
        assert sorted(common.get_domain_from_config(c, '/etc/nginx/vhosts/x')) == \
            ['example.com', 'www.example.com']

    def test_filters_wildcards_placeholders(self):
        out = 'example.com\n*.example.com\n_\nlocalhost\ndefault_server\nнет-точки\n'
        c = FakeSSH(routes=[('grep -h', out)])
        assert common.get_domain_from_config(c, '/etc/nginx/vhosts/x') == ['example.com']

    def test_empty_when_no_server_name(self):
        c = FakeSSH(routes=[('grep -h', '')])
        assert common.get_domain_from_config(c, '/etc/nginx/vhosts/x') == []

    def test_config_path_quoted(self):
        c = FakeSSH(routes=[('grep -h', '')])
        common.get_domain_from_config(c, '/etc/nginx/vhosts/we; rm -rf /')
        cmd = c.find('grep -h')
        assert "'/etc/nginx/vhosts/we; rm -rf /'" in cmd


# ==================== СЛУЖЕБНЫЙ КАНАЛ: ПРАВА И УБОРКА СЕКРЕТОВ ====================
class TestServiceRun:
    def test_prefers_cleanup_channel(self):
        # У ServerChecker есть cleanup(): обязан использоваться он, иначе rm из
        # finally не доживает до уборки после нажатия «Стоп»
        class WithCleanup(FakeSSH):
            def cleanup(self, cmd):
                self.commands.append('CLEANUP:' + cmd)
                return ('', '', 0)

        c = WithCleanup()
        assert common.service_run(c, 'rm -f /tmp/x') == ('', '', 0)
        assert c.commands == ['CLEANUP:rm -f /tmp/x']

    def test_falls_back_to_run_for_plain_checkers(self):
        # Заглушки и хост-классы без cleanup() не должны ломаться
        class Plain:
            def __init__(self):
                self.seen = []

            def run(self, cmd):
                self.seen.append(cmd)
                return ('', '', 0)

        host = Plain()
        common.service_run(host, 'chmod 600 /tmp/x')
        assert host.seen == ['chmod 600 /tmp/x']


class TestPrepareSecretFile:
    SECRET = '[client]\npassword=sup3r\n'

    def test_file_is_0600_before_password_lands(self):
        store = FakeSftpClient()
        c = FakeSSH(client=store)
        ok, why = common.prepare_secret_file(c, '/tmp/.x.cnf', self.SECRET)
        assert ok is True and why is None
        prep = c.commands[0]
        # Права ставятся в ТОМ ЖЕ вызове, что и создание: между «файл есть» и
        # «файл 0600» нет ни одного SSH-раунда — ни окна чтения всеми, ни места
        # для отмены (проверено локально: umask 077 -> 600, umask 022 -> 644)
        assert 'umask 077' in prep and 'chmod 600' in prep
        assert prep.index('umask 077') < prep.index(': >') < prep.index('chmod 600')
        assert prep.index('chmod 600') < prep.index('NOWRITE')
        # пароль прилетает позже и другим каналом (SFTP), а не командой
        assert store.store['/tmp/.x.cnf'] == self.SECRET
        assert 'sup3r' not in ' '.join(c.commands)

    def test_stale_file_removed_before_creation(self):
        # По фиксированному пути мог лежать чужой файл или symlink: SFTP-запись
        # по symlink затёрла бы его цель, поэтому первым делом rm -f
        store = FakeSftpClient()
        c = FakeSSH(client=store)
        common.prepare_secret_file(c, '/tmp/.x.cnf', self.SECRET)
        prep = c.commands[0]
        assert prep.index('rm -f') < prep.index(': >')

    def test_nowrite_is_reported_and_nothing_is_written(self):
        store = FakeSftpClient()
        c = FakeSSH(routes=[(': >', ('NOWRITE\n', 'Read-only file system', 0))],
                    client=store)
        ok, why = common.prepare_secret_file(c, '/tmp/.x.cnf', self.SECRET)
        assert ok is False and 'нельзя писать' in why and 'Read-only' in why
        assert store.store == {}                     # секрет не записан

    def test_write_failure_wipes_the_empty_file(self):
        # SFTP упал ПОСЛЕ создания файла: оставленный 0600-файл по фиксированному
        # пути — мусор, который следующий запуск унаследовал бы
        c = FakeSSH(client=None)                     # open_sftp недоступен
        ok, why = common.prepare_secret_file(c, '/tmp/.x.cnf', self.SECRET)
        assert ok is False and 'не удалось записать' in why
        assert any(cmd.startswith('rm -f') for cmd in c.commands), c.commands

    def test_transport_exception_becomes_reason(self):
        class Dead(FakeSSH):
            def cleanup(self, cmd):
                raise OSError('connection reset')

        ok, why = common.prepare_secret_file(Dead(), '/tmp/.x.cnf', self.SECRET)
        assert ok is False and 'connection reset' in why


class TestRemoveRemotePath:
    def test_success_is_silent(self):
        c = FakeSSH()
        assert common.remove_remote_path(c, '/tmp/d') == (True, None)

    def test_checks_fact_not_exit_code(self):
        # rm -rf молчит и когда не смог (read-only /tmp, права): факт проверяем
        # [ -e ], иначе «файл удалён» было бы неправдой
        c = FakeSSH(routes=[('echo STILL_THERE', ('STILL_THERE\n', '', 0))])
        ok, why = common.remove_remote_path(c, '/tmp/d')
        assert ok is False and 'путь остался' in why and '/tmp/d' in why

    def test_non_recursive_flag_for_files(self):
        c = FakeSSH()
        common.remove_remote_path(c, '/tmp/x.cnf', recursive=False)
        assert c.commands[0].startswith('rm -f ')

    def test_path_with_quote_stays_one_argument(self):
        # Одинарная кавычка в пути обязана быть экранирована: иначе путь
        # распадается на два аргумента, и rm получает лишнее (а проверка [ -e ]
        # смотрит не в тот файл).
        c = FakeSSH()
        common.remove_remote_path(c, "/tmp/we're", recursive=False)
        first = c.commands[0].split(';')[0].strip()
        parts = shlex.split(first)
        assert parts == ['rm', '-f', "/tmp/we're", '2>/dev/null'], parts


    def test_transport_exception_becomes_reason(self):
        class Dead(FakeSSH):
            def cleanup(self, cmd):
                raise OSError('connection reset')

        ok, why = common.remove_remote_path(Dead(), '/tmp/d')
        assert ok is False and 'connection reset' in why
