"""Тесты dns.py: отчёты dig, локальный резолвинг, чтение и замена резолверов.

Сети нет: dig/resolvectl перехватывает FakeSSH, запись конфигов — FakeSftpClient,
socket.getaddrinfo/gethostbyaddr подменяются monkeypatch.
"""
import os
import socket
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from support import FakeSSH, FakeSftpClient
import dns as dns_mod


# ==================== dns_report (dig на сервере) ====================
DIG_FULL = [
    ('+short A', '93.184.216.34\n'),
    ('+short NS', 'ns1.example.com\nns2.example.com\n'),
    ('+short -x', 'host.example.com\n'),
]


class TestDnsReport:
    def test_a_ns_ptr_collected(self):
        out = dns_mod.dns_report(FakeSSH(routes=DIG_FULL), 'example.com')
        assert 'A-записи: 93.184.216.34' in out
        assert 'NS-записи: ns1.example.com, ns2.example.com' in out
        assert 'PTR для 93.184.216.34: host.example.com' in out

    def test_multiple_a_records(self):
        c = FakeSSH(routes=[('+short A', '1.1.1.1\n2.2.2.2\n'),
                             ('+short NS', ''), ('+short -x', '')])
        out = dns_mod.dns_report(c, 'example.com')
        assert 'A-записи: 1.1.1.1, 2.2.2.2' in out
        assert 'NS-записи не найдены.' in out

    def test_ptr_only_for_ip_input(self):
        c = FakeSSH(routes=DIG_FULL)
        out = dns_mod.dns_report(c, '203.0.113.7')
        assert 'PTR (обратный DNS): host.example.com' in out
        # для IP не должно быть A/NS-запросов
        assert c.find('+short A') is None
        assert c.find('+short NS') is None

    def test_no_a_records_means_no_ptr(self):
        c = FakeSSH(routes=[('+short A', ''), ('+short NS', 'ns1.example.com\n')])
        out = dns_mod.dns_report(c, 'example.com')
        assert 'A-записи не найдены.' in out
        assert 'Не удалось получить IP для PTR-запроса.' in out

    def test_given_ip_used_for_ptr_when_no_a(self):
        c = FakeSSH(routes=[('+short A', ''), ('+short NS', ''),
                             ('+short -x', 'host.example.com\n')])
        out = dns_mod.dns_report(c, 'example.com', ip='203.0.113.9')
        assert 'PTR для 203.0.113.9: host.example.com' in out

    def test_dig_missing_returns_not_found(self):
        out = dns_mod.dns_report(FakeSSH(), 'example.com')
        assert 'A-записи не найдены.' in out
        assert 'NS-записи не найдены.' in out

    def test_domain_is_shell_quoted(self):
        # защита от инъекции: домен с метасимволами уходит одним аргументом dig
        c = FakeSSH(routes=DIG_FULL)
        dns_mod.dns_report(c, "example.com; rm -rf /")
        cmd = c.find('+short A')
        assert cmd.count('dig') == 1
        assert "'example.com; rm -rf /'" in cmd


# ==================== dns_report_local (socket) ====================
class TestDnsReportLocal:
    # Реальный getaddrinfo отдаёт 5-элементные кортежи, IP в addr[4][0].
    ADDR = [(2, 1, 6, '', ('93.184.216.34', 0))]

    def test_a_records_and_ptr(self, monkeypatch):
        monkeypatch.setattr(dns_mod.socket, 'getaddrinfo',
                            lambda host, port, family=None: self.ADDR)
        monkeypatch.setattr(dns_mod.socket, 'gethostbyaddr',
                            lambda ip: ('host.example.com', [], []))
        out = dns_mod.dns_report_local('example.com')
        assert 'A-записи: 93.184.216.34' in out
        assert 'PTR для 93.184.216.34: host.example.com' in out

    def test_domain_not_resolving(self, monkeypatch):
        def boom(host, port, family=None):
            raise socket.gaierror('Name or service not known')

        monkeypatch.setattr(dns_mod.socket, 'getaddrinfo', boom)
        out = dns_mod.dns_report_local('nope.invalid')
        assert 'не разрешается' in out

    def test_ptr_failure_reported_not_raised(self, monkeypatch):
        monkeypatch.setattr(dns_mod.socket, 'getaddrinfo',
                            lambda host, port, family=None: self.ADDR)

        def boom(ip):
            raise socket.herror('not found')

        monkeypatch.setattr(dns_mod.socket, 'gethostbyaddr', boom)
        out = dns_mod.dns_report_local('example.com')
        assert 'PTR-запись для 93.184.216.34 не найдена.' in out

    def test_ip_input_uses_ptr(self, monkeypatch):
        monkeypatch.setattr(dns_mod.socket, 'gethostbyaddr',
                            lambda ip: ('host.example.com', [], []))
        out = dns_mod.dns_report_local('203.0.113.7')
        assert 'PTR (обратный DNS): host.example.com' in out
        assert 'A-записи' not in out


# ==================== резолверы: чтение ====================
class TestGetResolvers:
    def test_parses_nameservers(self):
        c = FakeSSH(routes=[('nameserver', '1.1.1.1\n8.8.8.8\n')])
        assert dns_mod.get_current_dns_resolvers(c) == ['1.1.1.1', '8.8.8.8']

    def test_empty_when_nothing(self):
        assert dns_mod.get_current_dns_resolvers(FakeSSH()) == []


class TestResolversReport:
    def test_lists_and_probes_each_ns(self):
        c = FakeSSH(routes=[
            ('/etc/resolv.conf', 'nameserver 1.1.1.1\nnameserver 8.8.8.8\n'),
            ('google.com A', 'доступен\n'),
        ])
        out = dns_mod.dns_resolvers_report(c)
        assert 'Найдено DNS-серверов: 2' in out
        assert '1.1.1.1: доступен' in out
        assert c.count('@') == 2  # по одному dig на каждый резолвер

    def test_unreadable_resolv_conf(self):
        out = dns_mod.dns_resolvers_report(FakeSSH())
        assert 'Не удалось прочитать /etc/resolv.conf' in out

    def test_no_nameservers(self):
        c = FakeSSH(routes=[('/etc/resolv.conf', '# пусто\n')])
        out = dns_mod.dns_resolvers_report(c)
        assert 'не найдены nameserver' in out


# ==================== резолверы: замена ====================
BACKUP_ROUTES = [
    ('mkdir -p', ('created', '', 0)),
    ('test -f', ('exists', '', 0)),
]


class TestSetResolversPlain:
    """Сценарий без systemd-resolved: правим /etc/resolv.conf напрямую."""

    def _checker(self):
        client = FakeSftpClient()
        c = FakeSSH(routes=BACKUP_ROUTES + [
            ('is-active systemd-resolved', 'inactive\n'),
            ('cat /etc/resolv.conf', 'nameserver 8.8.4.4\n'),
        ], client=client)
        return c, client

    def test_writes_new_resolv_conf(self):
        c, client = self._checker()
        out = dns_mod.set_dns_resolvers(c, ['1.1.1.1', '9.9.9.9'])
        assert client.store['/etc/resolv.conf'] == (
            '# Generated by SSH Diagnostic Tool\nnameserver 1.1.1.1\nnameserver 9.9.9.9\n')
        assert 'обновлён' in out
        assert '✅' in out

    def test_backup_is_made(self):
        c, _ = self._checker()
        out = dns_mod.set_dns_resolvers(c, ['1.1.1.1'])
        assert 'Резервная копия создана' in out
        assert c.find('cp /etc/resolv.conf') is not None

    def test_invalid_addresses_rejected_without_write(self):
        c, client = self._checker()
        out = dns_mod.set_dns_resolvers(c, ['не-dns', 'bad;ns'])
        assert 'Не передано ни одного корректного DNS-адреса' in out
        assert client.store == {}          # ничего не записано
        assert client.closed == 0

    def test_ipv6_accepted(self):
        c, client = self._checker()
        dns_mod.set_dns_resolvers(c, ['2001:4860:4860::8888'])
        assert 'nameserver 2001:4860:4860::8888' in client.store['/etc/resolv.conf']


class TestSetResolversResolved:
    """Сценарий с systemd-resolved: правим resolved.conf и resolvectl по интерфейсам."""

    def _checker(self, resolved_conf='[Resolve]\n#DNS=8.8.8.8\nCache=yes\n'):
        client = FakeSftpClient()
        c = FakeSSH(routes=[
            ('is-active systemd-resolved', 'active\n'),
            ('cat /etc/systemd/resolved.conf', resolved_conf),
            ('ip -o link show', 'eth0\n'),
            ('resolvectl dns', ('', '', 0)),
            ('resolvectl status', '  DNS Servers: 1.1.1.1\n'),
            ('cat /etc/resolv.conf', 'nameserver 127.0.0.53\n'),
        ], client=client)
        return c, client

    def test_dns_line_uncommented_and_written(self):
        c, client = self._checker()
        out = dns_mod.set_dns_resolvers(c, ['1.1.1.1'])
        written = client.store['/etc/systemd/resolved.conf']
        assert 'DNS=1.1.1.1' in written
        assert '#DNS=' not in written
        assert 'Cache=yes' in written        # остальные строки сохранены
        assert 'resolvectl' in out or '✅' in out

    def test_dns_line_added_when_absent(self):
        c, client = self._checker('[Resolve]\nCache=yes\n')
        dns_mod.set_dns_resolvers(c, ['1.1.1.1'])
        written = client.store['/etc/systemd/resolved.conf']
        assert written.index('[Resolve]') < written.index('DNS=1.1.1.1')
        assert 'Cache=yes' in written

    def test_resolvectl_called_for_each_iface(self):
        c, _ = self._checker()
        out = dns_mod.set_dns_resolvers(c, ['1.1.1.1'])
        # Первая команда 'resolvectl dns eth0 ""' — сброс старых DNS,
        # вторая — установка новых. find() вернул бы сброс, поэтому find_all.
        cmds = c.find_all('resolvectl dns eth0')
        assert 'resolvectl dns eth0 1.1.1.1 2>&1' in cmds
        assert '✅ DNS для eth0' in out

    def test_resolved_restarted(self):
        c, _ = self._checker()
        dns_mod.set_dns_resolvers(c, ['1.1.1.1'])
        assert c.find('systemctl restart systemd-resolved') is not None


# ==================== локальный резолвинг: редкие ветки ошибок ============
class TestDnsReportLocalErrors:
    ADDR = [(2, 1, 6, '', ('93.184.216.34', 0))]

    @staticmethod
    def _raiser(exc):
        def boom(*args, **kwargs):
            raise exc
        return boom

    def test_ip_ptr_herror(self, monkeypatch):
        monkeypatch.setattr(dns_mod.socket, 'gethostbyaddr',
                            self._raiser(socket.herror('not found')))
        out = dns_mod.dns_report_local('203.0.113.7')
        assert 'PTR-запись не найдена.' in out

    def test_ip_ptr_generic_error(self, monkeypatch):
        # TimeoutError — не herror, поэтому попадает в общий except
        monkeypatch.setattr(dns_mod.socket, 'gethostbyaddr',
                            self._raiser(TimeoutError('dns timeout')))
        out = dns_mod.dns_report_local('203.0.113.7')
        assert 'Ошибка PTR-запроса: dns timeout' in out

    def test_empty_addrinfo_list(self, monkeypatch):
        monkeypatch.setattr(dns_mod.socket, 'getaddrinfo',
                            lambda host, port, family=None: [])
        out = dns_mod.dns_report_local('example.com')
        assert 'A-записи не найдены.' in out

    def test_ptr_generic_error_after_a_records(self, monkeypatch):
        monkeypatch.setattr(dns_mod.socket, 'getaddrinfo',
                            lambda host, port, family=None: self.ADDR)
        monkeypatch.setattr(dns_mod.socket, 'gethostbyaddr',
                            self._raiser(TimeoutError('timeout')))
        out = dns_mod.dns_report_local('example.com')
        assert 'A-записи: 93.184.216.34' in out
        assert 'Ошибка PTR-запроса: timeout' in out

    def test_non_gaierror_is_reported_not_raised(self, monkeypatch):
        monkeypatch.setattr(dns_mod.socket, 'getaddrinfo',
                            self._raiser(RuntimeError('resolv.conf unreadable')))
        out = dns_mod.dns_report_local('example.com')
        assert 'Ошибка DNS-запроса: resolv.conf unreadable' in out


class TestDnsReportPtrMissing:
    def test_ip_without_ptr_record(self):
        # dig -x молчит (NXDOMAIN) -> «не найдена», а не падение
        out = dns_mod.dns_report(FakeSSH(), '203.0.113.7')
        assert 'PTR-запись не найдена.' in out


# ==================== отчёт по резолверам: systemd-раздел ================
class TestResolversReportSystemd:
    BASE = [('/etc/resolv.conf', 'nameserver 1.1.1.1\n'),
            ('google.com A', 'доступен\n')]

    def test_systemd_resolve_status_shown(self):
        c = FakeSSH(routes=self.BASE + [
            ('systemd-resolve', '   DNS Servers global: 1.1.1.1\n')])
        out = dns_mod.dns_resolvers_report(c)
        assert '(systemd-resolve)' in out
        assert 'DNS Servers global' in out
        # раз systemd-resolve ответил, resolvectl спрашивать не нужно
        assert c.find('resolvectl status') is None

    def test_resolvectl_fallback_shown(self):
        c = FakeSSH(routes=self.BASE + [
            ('systemd-resolve', ''),
            ('resolvectl status', '   DNS Servers global: 9.9.9.9\n')])
        out = dns_mod.dns_resolvers_report(c)
        assert '(resolvectl)' in out
        assert '9.9.9.9' in out


# ==================== замена резолверов: сбои =============================
class TestSetResolversPlainFailures:
    def test_backup_failure_warns_but_file_written(self):
        client = FakeSftpClient()
        c = FakeSSH(routes=[('is-active systemd-resolved', 'inactive\n'),
                            ('mkdir -p', ('created', '', 0)),
                            ('test -f', ('', '', 1)),
                            ('cat /etc/resolv.conf', 'nameserver 8.8.4.4\n')],
                    client=client)
        out = dns_mod.set_dns_resolvers(c, ['1.1.1.1'])
        assert '⚠️ Не удалось создать резервную копию /etc/resolv.conf' in out
        assert '✅ /etc/resolv.conf обновлён.' in out
        assert client.store['/etc/resolv.conf'] == (
            '# Generated by SSH Diagnostic Tool\nnameserver 1.1.1.1\n')

    def test_sftp_failure_stops_report(self):
        class NoSftp:
            def open_sftp(self):
                raise IOError('ssh channel closed')

        c = FakeSSH(routes=[('is-active systemd-resolved', 'inactive\n'),
                            ('mkdir -p', ('created', '', 0)),
                            ('test -f', ('exists', '', 0))], client=NoSftp())
        out = dns_mod.set_dns_resolvers(c, ['1.1.1.1'])
        assert '❌ Ошибка записи: Не удалось открыть SFTP' in out
        assert 'обновлён' not in out


class TestSetResolversResolvedFailures:
    ROUTES = [('is-active systemd-resolved', 'active\n'),
              ('ip -o link show', ''),
              ('resolvectl status', ''),
              ('cat /etc/resolv.conf', '')]

    def _checker(self, resolved_conf, client):
        return FakeSSH(routes=[('cat /etc/systemd/resolved.conf', resolved_conf)
                              ] + self.ROUTES, client=client)

    def test_config_without_resolve_section_gets_section(self):
        client = FakeSftpClient()
        c = self._checker('# тут секции нет\nCache=yes\n', client)
        dns_mod.set_dns_resolvers(c, ['1.1.1.1'])
        written = client.store['/etc/systemd/resolved.conf']
        assert '[Resolve]' in written
        assert written.rstrip('\n').endswith('DNS=1.1.1.1')
        assert 'Cache=yes' in written

    def test_resolved_conf_write_failure(self):
        class NoSftp:
            def open_sftp(self):
                raise IOError('ssh channel closed')

        c = self._checker('[Resolve]\nCache=yes\n', NoSftp())
        out = dns_mod.set_dns_resolvers(c, ['1.1.1.1'])
        assert '❌ Ошибка записи resolved.conf' in out
        assert '✅ /etc/systemd/resolved.conf обновлён.' not in out

    def test_resolvectl_failure_reported_per_interface(self):
        client = FakeSftpClient()
        c = FakeSSH(routes=[
            ('is-active systemd-resolved', 'active\n'),
            ('cat /etc/systemd/resolved.conf', '[Resolve]\nCache=yes\n'),
            ('ip -o link show', 'eth0\n'),
            # именно устанавливающая команда: сброс (resolvectl dns eth0 "")
            # остаётся с ответом по умолчанию
            ('resolvectl dns eth0 1.1.1.1',
             ('', 'Interactive authentication required', 1)),
            ('resolvectl status', ''),
            ('cat /etc/resolv.conf', ''),
        ], client=client)
        out = dns_mod.set_dns_resolvers(c, ['1.1.1.1'])
        assert '❌ Ошибка для eth0 (rc=1): Interactive authentication required' in out
        assert '✅ DNS для eth0' not in out
