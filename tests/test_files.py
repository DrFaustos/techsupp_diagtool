"""Тесты files.py: запись/чтение файлов с бэкапом, список конфигов, перезапуск служб.

Реального SSH/SFTP нет: команды перехватывает FakeSSH, запись файлов —
FakeSftpClient (оба из support.py).
"""
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from support import FakeSSH, FakeSftpClient
import files as files_mod

BACKUP_OK = [('mkdir -p', ('created', '', 0)), ('test -f', ('exists', '', 0))]


class _NoSftp:
    def open_sftp(self):
        raise IOError('ssh channel closed')


class TestWriteFile:
    def test_success_report_mentions_backup(self):
        client = FakeSftpClient()
        c = FakeSSH(routes=BACKUP_OK, client=client)
        out = files_mod.write_file(c, '/etc/nginx/nginx.conf', 'worker_processes auto;')
        assert '✅ Файл сохранён.' in out
        assert '/root/tech_support/configs/nginx.conf.' in out
        assert client.store['/etc/nginx/nginx.conf'] == 'worker_processes auto;'

    def test_missing_backup_warns_but_still_writes(self):
        client = FakeSftpClient()
        c = FakeSSH(routes=[('mkdir -p', ('created', '', 0)),
                            ('test -f', ('', '', 1))], client=client)
        out = files_mod.write_file(c, '/etc/nginx/nginx.conf', 'x')
        assert '⚠️ Не удалось создать резервную копию' in out
        assert '✅ Файл сохранён.' in out

    def test_write_failure_stops_report(self):
        c = FakeSSH(routes=BACKUP_OK, client=_NoSftp())
        out = files_mod.write_file(c, '/etc/x', 'data')
        assert '❌ Ошибка записи' in out
        assert 'Файл сохранён' not in out


class TestReadFile:
    def test_returns_content(self):
        c = FakeSSH(routes=[('cat ', 'hello\n')])
        assert files_mod.read_file(c, '/etc/hosts') == 'hello\n'

    def test_error_rc_reported(self):
        c = FakeSSH(routes=[('cat ', ('', 'No such file or directory', 1))])
        out = files_mod.read_file(c, '/etc/nope')
        assert out.startswith('❌ Ошибка чтения файла (rc=1)')
        assert 'No such file' in out


class TestGetConfigFiles:
    ROUTES = [('ls -d', 'exists\n'),
              ('ls -1', 'nginx.conf\n'),
              ('find ', '/usr/local/fastpanel/etc/nginx/sites/default.conf\n')]

    def test_common_paths_collected(self):
        files = files_mod.get_config_files(FakeSSH(routes=self.ROUTES), 'none')
        assert '/etc/nginx/nginx.conf' in files
        # путь с '/' на конце -> к имени из ls приклеивается сам каталог
        assert '/etc/nginx/sites-available/nginx.conf' in files
        assert files == sorted(files)
        assert len(files) <= 50

    def test_panel_paths_scanned_with_find(self):
        c = FakeSSH(routes=self.ROUTES)
        files = files_mod.get_config_files(c, 'fastpanel')
        assert '/usr/local/fastpanel/etc/nginx/sites/default.conf' in files
        assert c.find('find') is not None

    def test_no_existing_paths_returns_empty(self):
        assert files_mod.get_config_files(FakeSSH(), 'none') == []

    def test_existing_path_with_empty_listing_appends_itself(self):
        # ls -d нашёл путь, ls -1 пуст -> в список попадает сам путь: иначе
        # одиночные конфиги (nginx.conf, my.cnf) терялись бы из редактора
        c = FakeSSH(routes=[('ls -d', 'exists\n'), ('ls -1', '')])
        files = files_mod.get_config_files(c, 'none')
        assert '/etc/nginx/nginx.conf' in files
        assert '/etc/mysql/my.cnf' in files


class TestReplaceIpv4ErrorBranch:
    def test_failed_find_shows_warning(self):
        # поведение как в исходнике: предупреждение, но операция продолжается
        c = FakeSSH(routes=[('find /etc', ('', "sed: couldn't write", 1)),
                            ('list-unit-files', 'no\n')])
        out = files_mod.replace_ipv4(c, '1.1.1.1', '2.2.2.2')
        assert '⚠️ Возможны ошибки (rc=1)' in out
        assert '✅ IPv4 заменён' in out


class TestReplaceIpv6BackupFailure:
    def test_etc_backup_failure_warns(self):
        c = FakeSSH(routes=[('tar czf', ('', 'tar: /etc: permission denied', 2))])
        out = files_mod.replace_ipv6(c, 'a::a', 'b::b')
        assert '⚠️ Не удалось создать резервную копию /etc' in out
        assert '✅ IPv6 заменён' in out

    def test_sed_failure_warns_but_operation_continues(self):
        # та же ветка, что уже закрыта для IPv4: rc!=0 у find/sed —
        # предупреждение с текстом STDERR, но отчёт не обрывается
        c = FakeSSH(routes=[('find /etc', ('', "sed: couldn't edit", 1))])
        out = files_mod.replace_ipv6(c, 'a::a', 'b::b')
        assert '⚠️ Возможны ошибки (rc=1)' in out
        assert "sed: couldn't edit" in out
        assert '✅ IPv6 заменён' in out


class TestRestartServices:
    # '^apache2.service' идёт раньше 'list-unit-files': игла — подстрока
    # команды grep -q "^apache2.service", первое совпадение выигрывает.
    ROUTES = [
        ('^apache2.service', 'no\n'),
        ('list-unit-files', 'yes\n'),
        ('is-active nginx', 'active\n'),
        ('is-active mysql', ['inactive\n', 'active\n']),
    ]

    def test_mixed_results(self):
        joined = '\n'.join(files_mod.restart_services(FakeSSH(routes=self.ROUTES)))
        assert '✅ nginx (reload) выполнен' in joined
        assert '✅ mysql перезапущен (fallback)' in joined
        assert '⏭️ apache2 не установлен' in joined

    def test_restart_failure_reported(self):
        # unit есть, но is-active всегда пусто -> fallback не спасает
        c = FakeSSH(routes=[('list-unit-files', 'yes\n')])
        joined = '\n'.join(files_mod.restart_services(c))
        assert '❌ nginx не запустился' in joined
        # для nginx: reload + is-active + restart(fallback) + is-active
        assert c.count('is-active nginx') == 2
