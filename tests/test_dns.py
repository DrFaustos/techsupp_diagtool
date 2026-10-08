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
