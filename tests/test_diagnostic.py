"""Юнит-тесты для чистых функций диагностики.

Запуск:
    venv/bin/pytest -q
или:
    venv/bin/python -m pytest -q
"""
import os
import sys

# Чтобы импортировать модули проекта из корня, даже если pytest запущен из tests/
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

import pytest

from common import q
from logs import parse_access_log_line, filter_by_date
import files as files_mod


# ==================== common.q ====================
class TestQuote:
    def test_plain_path(self):
        assert q('/etc/nginx/nginx.conf') == '/etc/nginx/nginx.conf'

    def test_spaces_are_quoted(self):
        assert q('/etc/my dir/file.conf') == "'/etc/my dir/file.conf'"

    def test_command_substitution_is_neutralized(self):
        # shlex.quote оборачивает в одинарные кавычки -> $(...) не выполнится
        result = q('x$(whoami)')
        assert result.startswith("'")
        assert result.endswith("'")
        assert '$(' in result

    def test_empty_string(self):
        assert q('') == "''"


# ==================== logs.parse_access_log_line ====================
class TestParseAccessLog:
    COMBINED = (
        '127.0.0.1 - - [10/Oct/2024:13:55:36 +0300] '
        '"GET /index.html HTTP/1.1" 200 1234 "-" "curl/8.0"'
    )

    def test_combined_format(self):
        entry = parse_access_log_line(self.COMBINED)
        assert entry is not None
        assert entry['ip'] == '127.0.0.1'
        assert entry['status'] == '200'
        assert entry['request'] == 'GET /index.html HTTP/1.1'
        assert entry['agent'] == 'curl/8.0'

    def test_common_format_without_referer_agent(self):
        line = '1.2.3.4 - - [10/Oct/2024:13:55:36 +0300] "GET / HTTP/1.1" 404 0'
        entry = parse_access_log_line(line)
        assert entry is not None
        assert entry['status'] == '404'
        # отсутствующие поля заполняются прочерком
        assert entry['referer'] == '-'
        assert entry['agent'] == '-'

    def test_garbage_returns_none(self):
        assert parse_access_log_line('this is not a log line') is None
        assert parse_access_log_line('') is None


# ==================== logs.filter_by_date ====================
def _entry(datestr):
    return {'time': f'{datestr}:13:55:36 +0300'}


class TestFilterByDate:
    def test_matches_all(self):
        e = _entry('10/Oct/2024')
        assert filter_by_date(e) is True
        assert filter_by_date(e, year=2024) is True
        assert filter_by_date(e, month=10) is True
        assert filter_by_date(e, day=10) is True

    def test_year_mismatch(self):
        assert filter_by_date(_entry('10/Oct/2024'), year=2023) is False

    def test_month_mismatch(self):
        assert filter_by_date(_entry('10/Oct/2024'), month=9) is False

    def test_day_mismatch(self):
        assert filter_by_date(_entry('10/Oct/2024'), day=11) is False

    def test_none_entry(self):
        assert filter_by_date(None) is False

    def test_malformed_time(self):
        assert filter_by_date({'time': 'garbage'}) is False
        assert filter_by_date({'time': ''}) is False

    def test_unknown_month_name(self):
        # IndexError внутри -> False, без исключения
        assert filter_by_date({'time': '10/Xxx/2024:00:00:00'}) is False


# ==================== files.replace_ipv4 / replace_ipv6 ====================
class FakeChecker:
    """Минимальная заглушка SSH-клиента, пишет все команды."""

    def __init__(self):
        self.commands = []

    def run(self, cmd):
        self.commands.append(cmd)
        return '', '', 0

    def exec_command(self, cmd):
        self.commands.append(cmd)
        return '', ''

    def _find_cmd(self, needle):
        for c in self.commands:
            if needle in c:
                return c
        return None


class TestReplaceIp:
    def test_ipv4_command_escapes_both_ips(self):
        c = FakeChecker()
        files_mod.replace_ipv4(c, '123.123.123.123', '10.20.30.40')
        cmd = c._find_cmd('find /etc')
        assert cmd is not None
        assert r'123\.123\.123\.123' in cmd
        assert r'10\.20\.30\.40' in cmd
        assert "-name \"*.conf\"" in cmd

    def test_ipv4_rejects_invalid(self):
        c = FakeChecker()
        # 321 — недопустимый октет; также попытка инъекции через ;
        for bad in ('321.321.321.321', '1.1.1.1; rm -rf /', 'not-an-ip'):
            c.commands.clear()
            out = files_mod.replace_ipv4(c, bad, '10.0.0.1')
            assert c._find_cmd('find /etc') is None
            assert '❌' in out

    def test_ipv6_command_basic(self):
        c = FakeChecker()
        files_mod.replace_ipv6(c, 'fff:fff:fff:fff:fff::fff', 'ddd:ddd:ddd:ddd:ddd::ddd')
        cmd = c._find_cmd('find /etc')
        assert cmd is not None
        assert 'fff:fff:fff:fff:fff::fff' in cmd
        assert 'ddd:ddd:ddd:ddd:ddd::ddd' in cmd
        assert cmd.endswith('{} +')

    def test_ipv6_rejects_injection(self):
        c = FakeChecker()
        out = files_mod.replace_ipv6(c, "a::a/ -e 's/.*/pwned/; #", 'b::b')
        assert c._find_cmd('find /etc') is None
        assert '❌' in out

    def test_ipv6_makes_etc_backup(self):
        c = FakeChecker()
        files_mod.replace_ipv6(c, 'a::a', 'b::b')
        assert c._find_cmd('tar czf') is not None


# ==================== webcheck (SSL / WHOIS / порты / grep) ====================
import webcheck as webcheck_mod


class TestWebcheckEdgeCases:
    def test_ssl_no_domain(self):
        c = FakeChecker()
        out = webcheck_mod.ssl_cert_report(c, '')
        assert '❌' in out
        # при пустом домене команда не выполняется
        assert c.commands == []

    def test_whois_no_domain(self):
        c = FakeChecker()
        out = webcheck_mod.whois_report(c, '')
        assert '❌' in out
        assert c.commands == []

    def test_port_scan_uses_run_and_ss(self):
        c = FakeChecker()
        out = webcheck_mod.port_scan_report(c, host='127.0.0.1')
        assert 'СКАНИРОВАНИЕ ПОРТОВ' in out
        assert c._find_cmd('ss -tulpn') is not None
        assert c._find_cmd('127.0.0.1') is not None

    def test_grep_logs_no_files(self):
        c = FakeChecker()
        # find_logs вернёт пусто -> сообщение об отсутствии логов
        out = webcheck_mod.grep_logs_report(c, 'none', 'example.com', r'" 5\d\d ')
        assert '❌' in out or 'не найдены' in out


# ==================== fmanager (SFTP-менеджер файлов) ====================
import stat
import types

import fmanager as fm


class _Attr:
    def __init__(self, filename, st_mode, st_size=0, st_mtime=0):
        self.filename = filename
        self.st_mode = st_mode
        self.st_size = st_size
        self.st_mtime = st_mtime


class _FakeFile:
    def __init__(self, store, path, mode='r'):
        self.store = store
        self.path = path
        self.mode = mode

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def write(self, data):
        self.store[self.path] = self.store.get(self.path, '') + data

    def read(self):
        if self.path not in self.store:
            raise IOError('no such file in fake store')
        return self.store[self.path]


class FakeSFTP:
    """Мини-ФС: fmanager проверяется без реального SFTP-соединения."""

    def __init__(self, files=(), dirs=('/',)):
        self.files = set(files)
        self.dirs = set(dirs)
        self.written = {}
        self.ops = []
        self.closed = 0

    @staticmethod
    def _base(p):
        return p.rstrip('/').rsplit('/', 1)[-1]

    @staticmethod
    def _parent(p):
        p = p.rstrip('/')
        return p.rsplit('/', 1)[0] or '/'

    # --- интерфейс, который использует fmanager ---
    def close(self):
        self.closed += 1

    def listdir_attr(self, path):
        path = path.rstrip('/') or '/'
        if path not in self.dirs:
            raise IOError(f'no such directory: {path}')
        out = []
        for d in self.dirs:
            if d != '/' and self._parent(d) == path:
                out.append(_Attr(self._base(d), stat.S_IFDIR | 0o755))
        for f in self.files:
            if self._parent(f) == path:
                out.append(_Attr(self._base(f), stat.S_IFREG | 0o644, 12))
        return out

    def mkdir(self, path):
        self.ops.append(('mkdir', path))
        if path in self.dirs:
            raise IOError(f'exists: {path}')
        self.dirs.add(path)

    def open(self, path, mode='r'):
        self.ops.append(('open', path, mode))
        if 'w' in mode:
            self.files.add(path)
        return _FakeFile(self.written, path, mode)

    def remove(self, path):
        self.ops.append(('remove', path))
        if path not in self.files:
            raise IOError(f'no such file: {path}')
        self.files.discard(path)

    def rmdir(self, path):
        self.ops.append(('rmdir', path))
        if path not in self.dirs:
            raise IOError(f'no such dir: {path}')
        self.dirs.discard(path)

    def rename(self, old, new):
        self.ops.append(('rename', old, new))
        if old in self.files:
            self.files.discard(old)
            self.files.add(new)
        elif old in self.dirs:
            self.dirs.discard(old)
            self.dirs.add(new)
        else:
            raise IOError(f'no such path: {old}')

    def get(self, remote, local):
        self.ops.append(('get', remote, local))

    def put(self, local, remote):
        self.ops.append(('put', local, remote))
        self.files.add(remote)


def _sftp_checker(sftp):
    return types.SimpleNamespace(client=types.SimpleNamespace(open_sftp=lambda: sftp))


class TestFManager:
    def test_list_dir_dirs_first_then_alpha(self):
        sftp = FakeSFTP(files=['/srv/a.log', '/srv/z.txt'],
                        dirs=['/', '/srv', '/srv/Zet', '/srv/www'])
        entries = fm.list_dir(_sftp_checker(sftp), '/srv')
        assert [e['name'] for e in entries] == ['www', 'Zet', 'a.log', 'z.txt']
        assert entries[0]['is_dir'] is True
        assert entries[2]['is_dir'] is False
        assert sftp.closed == 1  # sftp всегда закрывается

    def test_list_dir_empty_path_lists_root(self):
        sftp = FakeSFTP(files=['/root-only.txt'], dirs=['/'])
        entries = fm.list_dir(_sftp_checker(sftp), '')
        assert [e['name'] for e in entries] == ['root-only.txt']

    def test_make_dir_creates(self):
        sftp = FakeSFTP(dirs=['/'])
        out = fm.make_dir(_sftp_checker(sftp), '/srv/new')
        assert '/srv/new' in sftp.dirs and '✅' in out

    def test_create_file_writes_empty(self):
        sftp = FakeSFTP(dirs=['/'])
        fm.create_file(_sftp_checker(sftp), '/etc/new.conf')
        assert sftp.written['/etc/new.conf'] == ''
        assert sftp.closed == 1

    def test_delete_file(self):
        sftp = FakeSFTP(files=['/etc/x.conf'])
        fm.delete_path(_sftp_checker(sftp), '/etc/x.conf')
        assert sftp.files == set()

    def test_delete_dir_is_recursive(self):
        sftp = FakeSFTP(files=['/srv/a/b.txt', '/srv/a/c.log'],
                        dirs=['/', '/srv', '/srv/a'])
        fm.delete_path(_sftp_checker(sftp), '/srv/a', is_dir=True)
        assert '/srv/a' not in sftp.dirs
        assert not any(f.startswith('/srv/a/') for f in sftp.files)

    def test_rename(self):
        sftp = FakeSFTP(files=['/etc/a.conf'])
        fm.rename_path(_sftp_checker(sftp), '/etc/a.conf', '/etc/b.conf')
        assert sftp.files == {'/etc/b.conf'}

    def test_transfer_ops(self):
        sftp = FakeSFTP(dirs=['/'])
        c = _sftp_checker(sftp)
        assert fm.download_file(c, '/etc/nginx/nginx.conf', '/tmp/n.conf') == '/tmp/n.conf'
        assert fm.upload_file(c, '/tmp/up.conf', '/etc/up.conf') == '/etc/up.conf'
        assert ('get', '/etc/nginx/nginx.conf', '/tmp/n.conf') in sftp.ops
        assert '/etc/up.conf' in sftp.files

    def test_sftp_closed_on_error(self):
        sftp = FakeSFTP(dirs=['/'])
        with pytest.raises(IOError):
            fm.list_dir(_sftp_checker(sftp), '/nope')
        assert sftp.closed == 1

    def test_is_text_file(self):
        assert fm.is_text_file('/etc/nginx/nginx.conf') is True
        assert fm.is_text_file('/etc/nginx/sites-enabled/example.com') is True
        assert fm.is_text_file('/usr/bin/bash') is False
        assert fm.is_text_file('backup.tar.gz') is False

    def test_is_text_file_edge_names(self):
        # пустое имя (пустая строка из таблицы) и дотфайлы — пограничные
        # ответы эвристики: .htaccess править можно, '' открывать нечего
        assert fm.is_text_file('') is False
        assert fm.is_text_file(None) is False
        assert fm.is_text_file('/etc/apache2/.htaccess') is True
        assert fm.is_text_file('/root/.bashrc') is True

    def test_delete_dir_recurses_into_subdirectories(self):
        # вложенный каталог: _rmtree обязан уйти в рекурсию, иначе rmdir
        # непустого каталога упал бы на живом сервере посреди удаления
        sftp = FakeSFTP(files=['/srv/a/b.txt'],
                        dirs=['/', '/srv', '/srv/a', '/srv/a/inner'])
        out = fm.delete_path(_sftp_checker(sftp), '/srv', is_dir=True)
        assert '✅ Удалено: /srv' in out
        assert not [d for d in sftp.dirs if d.startswith('/srv')]
        # порядок: сначала содержимое, потом сам каталог
        assert ('rmdir', '/srv/a/inner') in sftp.ops
        assert ('remove', '/srv/a/b.txt') in sftp.ops
        assert sftp.ops[-1] == ('rmdir', '/srv')
        assert sftp.closed == 1

    def test_filemode_garbage_is_safe(self):
        # st_mode у части записей приходит None/мусором: stat.filemode бросает
        # TypeError, а таблицаlist_dir не имеет права падать на одной записи
        assert fm._filemode(None) == '?'
        assert fm._filemode('abc') == '?'
        assert fm._filemode(0o100644) == '-rw-r--r--'


# ==================== metrics: статусы служб (без рассинхрона) ====================
import metrics as metrics_mod


class TestParseServiceStatuses:
    def test_basic_pairs(self):
        out = 'nginx=active\nmysql=inactive\nmariadb=unknown\n'
        assert metrics_mod.parse_service_statuses(out) == {
            'nginx': 'active', 'mysql': 'inactive', 'mariadb': 'unknown',
        }

    def test_empty_and_none(self):
        # система без systemd / systemctl недоступен -> пусто, без исключения
        assert metrics_mod.parse_service_statuses('') == {}
        assert metrics_mod.parse_service_statuses(None) == {}

    def test_garbage_lines_skipped(self):
        assert metrics_mod.parse_service_statuses('no equals here\n\n') == {}

    def test_blank_status_becomes_unknown(self):
        assert metrics_mod.parse_service_statuses('nginx=') == {'nginx': 'unknown'}

    def test_extra_lines_cannot_shift_statuses(self):
        # Регрессия на старый баг: `|| echo "inactive"` добавлял лишнюю строку
        # и статусы съезжали по списку. Теперь имя едет вместе со статусом,
        # поэтому любая посторонняя строка просто игнорируется.
        out = 'nginx=active\nsome junk line\napache2=inactive\nmore junk\nmysql=active'
        st = metrics_mod.parse_service_statuses(out)
        assert st == {'nginx': 'active', 'apache2': 'inactive', 'mysql': 'active'}

    def test_status_with_spaces_and_equals_inside(self):
        # split('=', 1): всё после первого '=' — статус, даже с пробелами
        assert metrics_mod.parse_service_statuses('nginx=active (running)') == {
            'nginx': 'active (running)'}


class TestServicesStatusCmd:
    def test_default_list_used(self):
        cmd = metrics_mod.services_status_cmd()
        for svc in metrics_mod.SERVICES_TO_CHECK:
            assert svc in cmd

    def test_output_format_is_name_equals_status(self):
        cmd = metrics_mod.services_status_cmd(['nginx', 'php8.2-fpm'])
        assert "printf '%s=%s\\n'" in cmd
        assert 'nginx' in cmd and 'php8.2-fpm' in cmd

    def test_service_names_are_shell_quoted(self):
        # защита от инъекции через имя службы
        cmd = metrics_mod.services_status_cmd(['evil;rm -rf /'])
        assert "'evil;rm -rf /'" in cmd


class _SvcChecker:
    """Заглушка: отвечает реальным выводом только на команду статусов служб."""

    def __init__(self, out):
        self.out = out
        self.commands = []

    def exec_command(self, cmd):
        self.commands.append(cmd)
        if '__svc_status' in cmd:
            return self.out, ''
        return '', ''

    def run(self, cmd):
        out, err = self.exec_command(cmd)
        return out, err, 0


class TestGetMetricsServices:
    def test_metrics_services_pairs_correctly(self):
        c = _SvcChecker('nginx=active\nmysql=inactive\n')
        m = metrics_mod.get_metrics(c)
        assert m['services'] == {'nginx': 'active', 'mysql': 'inactive'}

    def test_metrics_services_empty_without_systemd(self):
        c = _SvcChecker('')
        m = metrics_mod.get_metrics(c)
        assert m['services'] == {}

    def test_metrics_services_no_shift_with_junk(self):
        c = _SvcChecker('nginx=active\nWarning: junk happened\nphp8.2-fpm=inactive\n')
        m = metrics_mod.get_metrics(c)
        assert m['services'].get('php8.2-fpm') == 'inactive'
