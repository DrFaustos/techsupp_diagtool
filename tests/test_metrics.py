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


# ============ файрвол: молчание не есть «не установлено» (1.32.11) ============
# Замер живьём (этот хост, непривилегированный пользователь): iptables и nft
# УСТАНОВЛЕНЫ (/usr/sbin), но iptables -L -n даёт rc=4 Permission denied,
# nft list ruleset — rc=1 Operation not permitted, а ufw — rc=127 command not
# found. Прежняя форма (cmd 2>/dev/null || echo готовое слово) печатала на всех
# трёх побайтово одно и то же: решение шло по пустоте stdout, а не по коду
# возврата. Отчёт о безопасности уходит и в сводку (reports.py), поэтому по нему
# оператор решает, нужен ли на хосте файрвол.
class TestFirewallProbe:
    KEYS = ('ufw', 'iptables', 'nftables')

    def _fw(self, routes):
        c = FakeSSH(routes=routes)
        return c, metrics_mod.firewall_report(c)

    def _unchecked(self, out):
        # Строки, ОБЪЯВЛЯЮЩИЕ пробел. Признание печатается отдельной строкой
        # под заголовком: firewall_report выводит значение как `fw:` + перевод
        # строки + тело (так его ждёт test_reports.py), и менять этот формат
        # ради учёта радиус — ломать проверенный контракт ради измерителя.
        # Поэтому признак — строка с признанием, а не строка заголовка: у
        # ответившего файрвола такой строки нет вовсе (замок ниже), значит
        # число строк равно числу файлов, где спрос не состоялся.
        return [ln for ln in out.splitlines() if 'не проверено' in ln]

    def test_permission_denied_is_unchecked_not_not_installed(self):
        # Ключевой случай: утилита ЕСТЬ, но спросить не удалось (rc=4, замер).
        c, out = self._fw([
            ('ufw status', ('', 'bash: line 1: ufw: command not found', 127)),
            ('iptables -L', ('', 'Permission denied', 4)),
            ('nft list', ('', 'Operation not permitted (you must be root)', 1)),
        ])
        assert 'iptables not available' not in out, out
        assert 'nftables not available' not in out, out
        assert len(self._unchecked(out)) >= 2, out
        assert 'Permission denied' in out, out

    def test_missing_binary_is_measured_fact_not_guess(self):
        # «Не установлено» допустимо только при доказательстве: rc=127 (замер).
        c, out = self._fw([
            ('ufw status', ('', 'bash: line 1: ufw: command not found', 127)),
            ('iptables -L', ('Chain INPUT (policy ACCEPT)', '', 0)),
            ('nft list', ('table inet filter', '', 0)),
        ])
        assert 'не установлено' in out, out
        assert 'Chain INPUT (policy ACCEPT)' in out, out
        assert len(self._unchecked(out)) == 0, out

    def test_silence_at_rc0_is_unchecked(self):
        # Пустой вывод при rc=0 — молчание, а не «файрвола нет».
        c, out = self._fw([
            ('ufw status', ('', '', 0)),
            ('iptables -L', ('', '', 0)),
            ('nft list', ('', '', 0)),
        ])
        assert len(self._unchecked(out)) == 3, out
        assert 'not installed' not in out and 'not available' not in out, out

    def test_real_answers_printed_as_before(self):
        # Замок от перелома: ответивший файрвол печатается как раньше
        # (test_reports.py ждёт ufw: + перевод строки + Status: active).
        c, out = self._fw([
            ('ufw status', ('Status: active', '', 0)),
            ('iptables -L', ('Chain INPUT (policy ACCEPT)', '', 0)),
            ('nft list', ('table inet filter', '', 0)),
        ])
        assert 'ufw:\nStatus: active' in out, out
        assert 'не проверено' not in out, out

    def test_no_probe_blinds_channels_or_adds_default(self):
        # Поведенческий замок: смотрим ОТПРАВЛЕННЫЕ команды, а не текст
        # исходника (упоминание не есть вызов — закон 1.32.9).
        c, out = self._fw([('ufw status', ('Status: active', '', 0))])
        asked = [cmd for cmd in c.commands
                 if 'ufw' in cmd or 'iptables' in cmd or 'nft ' in cmd]
        assert len(asked) == 3, asked
        for cmd in asked:
            assert '2>/dev/null' not in cmd, cmd
            assert '||' not in cmd, cmd
        # Подстрока обязательна: test_reports.py считает ufw status ровно раз.
        assert c.count('ufw status') == 1, c.commands

    def test_firewall_values_stay_strings(self):
        # test_reports.py передаёт готовый словарь со СТРОКАМИ: природу
        # значения менять нельзя, признанием обязана быть строка.
        m = metrics_mod.get_metrics(FakeSSH(routes=[
            ('ufw status', ('', 'Permission denied', 4)),
        ]))
        assert set(m['firewall']) == {'ufw', 'iptables', 'nftables'}
        for key, value in m['firewall'].items():
            assert isinstance(value, str), (key, type(value))
