"""Тесты metrics.py: определение панели, сбор метрик, сетевой отчёт, веб-конфиг.

Реального SSH нет — команды перехватывает FakeSSH из support.py.
"""
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from support import FakeSSH
import metrics as metrics_mod


# ==================== определение панели ====================
class TestDetectPanel:
    def test_fastpanel_by_binary(self):
        c = FakeSSH(routes=[('/usr/local/fastpanel/bin/fastpanel', 'yes\n')])
        assert metrics_mod.detect_panel(c) == 'fastpanel'

    def test_ispmanager_by_binary(self):
        # файл fastpanel отсутствует (default ''), mgrctl — есть
        c = FakeSSH(routes=[('/usr/local/mgr5/bin/mgrctl', 'yes\n')])
        assert metrics_mod.detect_panel(c) == 'ispmanager'

    def test_fallback_to_ps_fastpanel(self):
        c = FakeSSH(routes=[('ps aux', 'root 1 0.0 /opt/fastpanel/bin/fastpanel\n')])
        assert metrics_mod.detect_panel(c) == 'fastpanel'

    def test_fallback_to_ps_mgr5(self):
        c = FakeSSH(routes=[('ps aux', 'root 1 0.0 /usr/local/mgr5/sbin/mgr.cert\n')])
        assert metrics_mod.detect_panel(c) == 'ispmanager'

    def test_none_when_nothing_found(self):
        assert metrics_mod.detect_panel(FakeSSH()) == 'none'


# ==================== команда статусов служб ====================
class TestServicesStatusCmd:
    def test_names_quoted_and_key_value_format(self):
        cmd = metrics_mod.services_status_cmd(['nginx', 'php 8.2-fpm'])
        assert "'php 8.2-fpm'" in cmd
        assert '%s=%s' in cmd

    def test_default_list_used(self):
        cmd = metrics_mod.services_status_cmd()
        for s in ('nginx', 'mysql', 'mariadb'):
            assert s in cmd


# ==================== сбор метрик ====================
class TestGetMetrics:
    ROUTES = [
        ('df -h', 'Filesystem  Size  Used\n/dev/vda1  40G  20G\n'),
        ('df -i', 'Filesystem Inodes\n'),
        ('free -m', 'total  used\nMem  3968  1200\n'),
        ('uptime', 'up 3 days, 2:11'),
        ('ss -tulpn', 'tcp  LISTEN  0  128  *:22'),
        ('ufw status', 'Status: active'),
        ('iptables -L', 'Chain INPUT (policy ACCEPT)'),
        ('nft list', 'table inet filter'),
        ('__svc_status', 'nginx=active\nmysql=inactive\n'),
    ]

    def test_all_sections_present(self):
        m = metrics_mod.get_metrics(FakeSSH(routes=self.ROUTES))
        assert set(m) >= {'disk', 'inodes', 'memory', 'uptime',
                          'listening_ports', 'firewall', 'services'}
        assert m['services'] == {'nginx': 'active', 'mysql': 'inactive'}
        assert set(m['firewall']) == {'ufw', 'iptables', 'nftables'}


# ==================== отчёты ====================
class TestMetricsReport:
    def test_prints_passed_metrics_and_services(self):
        passed = {'disk': 'D', 'inodes': 'I', 'memory': 'M', 'uptime': 'U',
                  'listening_ports': 'P', 'services': {'nginx': 'active'}}
        out = metrics_mod.metrics_report(FakeSSH(), metrics=passed)
        assert '=== МЕТРИКИ СИСТЕМЫ ===' in out
        assert 'Диски:\nD' in out
        assert 'nginx: active' in out

    def test_disk_memory_report_three_commands(self):
        c = FakeSSH(routes=[('df -h', 'H'), ('df -i', 'I'), ('free -m', 'M')])
        out = metrics_mod.disk_memory_report(c)
        assert '=== ДИСКИ И ПАМЯТЬ ===' in out
        assert c.count('df -h') == 1
        assert c.count('df -i') == 1
        assert c.count('free -m') == 1


class TestNetworkReport:
    IP_A = ('1: lo: <LOOPBACK>\n    inet 127.0.0.1/8 scope host lo\n'
            '2: eth0: <BROADCAST>\n    inet 10.0.0.5/24 scope global eth0\n')
    IP_R = ('default via 10.0.0.1 dev eth0 proto dhcp metric 100\n'
            '10.0.0.0/24 dev eth0 proto kernel scope link src 10.0.0.5\n')
    # 'route get' раньше 'ip r': игла 'ip r' иначе проглотила бы и её.
    # Возврат — уже пост-обработанный конвейером (`| cut -f2`) адрес без 'src '.
    ROUTES = [
        ('route get', '10.0.0.5\n'),
        ('ip r', IP_R),
        ('ip a', IP_A),
        ('ifconfig.me', '203.0.113.9\n'),
    ]

    def test_nat_explained(self):
        out = metrics_mod.network_report(FakeSSH(routes=self.ROUTES))
        assert 'Интерфейс по умолчанию: eth0 (шлюз 10.0.0.1)' in out
        assert 'IP-адрес источника для исходящего трафика: 10.0.0.5' in out
        assert 'Внешний (плавающий) IP: 203.0.113.9' in out
        assert 'трафик идёт через NAT' in out

    def test_no_default_route_and_no_external_ip(self):
        routes = [('route get', ''),
                  ('ip r', '10.0.0.0/24 dev eth0 proto kernel scope link\n'),
                  ('ip a', self.IP_A),
                  ('ifconfig.me', '')]
        out = metrics_mod.network_report(FakeSSH(routes=routes))
        assert 'Интерфейс по умолчанию' not in out
        assert 'IP-адрес источника' not in out
        assert 'Внешний IP не удалось определить' in out


class TestWebConfig:
    def test_nginx_and_apache_detected(self):
        c = FakeSSH(routes=[
            ('nginx -t', 'nginx: configuration file /etc/nginx/nginx.conf test is successful'),
            ('apache2ctl', 'Syntax OK'),
        ])
        res = metrics_mod.check_web_config(c)
        assert set(res) == {'nginx', 'apache'}

    def test_nothing_detected_gives_hint(self):
        out = metrics_mod.web_config_report(FakeSSH())
        assert 'не обнаружен' in out

    def test_report_lists_every_detected_service(self):
        # раньше проверялся только check_web_config (словарь), а сам отчёт —
        # только пустая ветка; цикл по найденным сервисам не был закрыт вовсе
        c = FakeSSH(routes=[
            ('nginx -t', 'nginx: configuration file /etc/nginx/nginx.conf '
                         'test is successful'),
            ('apache2ctl', 'Syntax OK'),
        ])
        out = metrics_mod.web_config_report(c)
        assert 'nginx: nginx: configuration file' in out
        assert 'apache: Syntax OK' in out
        assert 'не обнаружен' not in out
