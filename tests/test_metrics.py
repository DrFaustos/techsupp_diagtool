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

# Текст тестов 1.32.12 живёт В ЭТОМ ФАЙЛЕ и вставляется в tests/test_metrics.py
# скриптом: правки патч-скриптами с переносами внутри строковых литералов уже
# стоили серии нескольких ходов (SyntaxError из-за двойного экранирования).
# Здесь переводы строк собираются PANEL_NL.join — ни одного обратного слэша.

# Имена с префиксом PANEL_: вставляемся в чужой модуль и не имеем права ничего
# в нём затенять (уникальность сверяется скриптом вставки, а не на глаз).
PANEL_NL = chr(10)
PANEL_LS_PREFIX = 'ls -1 -p '
PANEL_PS_HEADER = PANEL_NL.join(
    ['USER PID %CPU %MEM VSZ RSS TTY STAT START TIME COMMAND', ''])
PANEL_DIR_DENIED = ('', 'ls: cannot open directory: Permission denied', 2)
PANEL_NO_PS = ('', 'bash: ps: command not found', 127)
PANEL_PS_ROW = 'root 1 0.0 0.0 1234 567 ? Sl 00:00 0:01 '
PANEL_DOTDOT = PANEL_NL.join(['.', '..', ''])
PANEL_FAST_LIST = PANEL_NL.join(['.', '..', 'fastpanel', ''])
PANEL_MGR_LIST = PANEL_NL.join(['.', '..', 'mgrctl', ''])




# ==================== определение панели ====================
class TestDetectPanel:
    """Контракт возврата панели, переведённый на достоверный спрос (1.32.12).

    Прежние фикстуры матчали форму «test -f … && echo yes || echo no» и
    решали по пустоте stdout. Замер живьём: test -f даёт rc=1 и ПУСТОЙ stderr
    и при отсутствии файла, и при отказе прав — различить нечем ни числом, ни
    каналом (ls/stat/find различают миры только локализованным текстом errno).
    Поэтому фикстуры описывают достоверный список каталога, а не молчание.
    """

    def test_fastpanel_by_binary(self):
        c = FakeSSH(routes=[('/usr/local/fastpanel/bin', PANEL_FAST_LIST)])
        assert metrics_mod.detect_panel(c) == 'fastpanel'

    def test_ispmanager_by_binary(self):
        # fastpanel: список прочитан, имени нет. Мир задаётся ЯВНО: замер
        # двойника показал default = ('', '', 0), то есть «успех с пустым
        # выводом», а не «файла нет» — прежний комментарий об этом врёт.
        c = FakeSSH(routes=[('/usr/local/fastpanel/bin', PANEL_DOTDOT),
                            ('/usr/local/mgr5/bin', PANEL_MGR_LIST)])
        assert metrics_mod.detect_panel(c) == 'ispmanager'

    def test_fallback_to_ps_fastpanel(self):
        c = FakeSSH(routes=[('/usr/local/fastpanel/bin', PANEL_DOTDOT),
                            ('/usr/local/mgr5/bin', PANEL_DOTDOT),
                            ('ps aux', PANEL_PS_HEADER + PANEL_PS_ROW + 'opt/fastpanel/bin/fastpanel' + PANEL_NL)])
        assert metrics_mod.detect_panel(c) == 'fastpanel'

    def test_fallback_to_ps_mgr5(self):
        c = FakeSSH(routes=[('/usr/local/fastpanel/bin', PANEL_DOTDOT),
                            ('/usr/local/mgr5/bin', PANEL_DOTDOT),
                            ('ps aux', PANEL_PS_HEADER + PANEL_PS_ROW + 'usr/local/mgr5/sbin/mgr.cert' + PANEL_NL)])
        assert metrics_mod.detect_panel(c) == 'ispmanager'

    def test_none_when_nothing_found(self):
        c = FakeSSH(routes=[('/usr/local/fastpanel/bin', PANEL_DOTDOT),
                            ('/usr/local/mgr5/bin', PANEL_DOTDOT),
                            ('ps aux', PANEL_PS_HEADER)])
        assert metrics_mod.detect_panel(c) == 'none'

    def test_silent_double_is_not_measured_absence(self):
        # Объявленный перевод контракта (1.32.12). Прежний тест выше
        # проверял «панелей нет» на ПУСТОМ двойнике, но пустой вывод при
        # rc=0 — это «мы не спросили», а не ответ хоста (ср.
        # parse_command_probe). Отсутствие теперь требует достоверного
        # списка каталога.
        assert (metrics_mod.detect_panel(FakeSSH())
                == metrics_mod.PANEL_UNCHECKED)

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


# ==== веб-конфиг: веб-сервер регистрируется кодом возврата, а не словом ====
# RED этого слайса (1.32.25) красен ПО СУЩЕСТВУ, а не по отсутствию имени: все
# три теста гонят существующую check_web_config на ЖИВЫХ байтах этой машины
# (замер: nginx/apache2ctl отсутствуют -> rc=127 со stdout «command not found»,
# настоящий httpd на битом конфиге -> rc=1 «AH00526: Syntax error on line 376»).
# Прежняя решалка (`if 'nginx' in out` на выводе `nginx -t 2>&1`, там же)
# вывернута: регистрирует сервер по имени ОТСУТСТВУЮЩЕЙ команды и НЕ
# регистрирует apache при честном отказе конфига.
class TestWebConfigAbsentVsBroken:
    """Веб-сервер регистрируется кодом возврата, а не словом в выводе (1.32.25).

    Миры взяты замером на этой машине (nginx и apache2ctl отсутствуют, httpd
    есть): `nginx -t 2>&1` без бинарника даёт rc=127 и НЕПУСТОЙ stdout со словом
    «command not found», а честный `httpd -t` на битом конфиге — rc=1 и AH00526 в
    stderr. Прежняя решалка (`if 'nginx' in out` по выводу `2>&1`, куда rc вообще
    не доезжал через exec_command) вывернута: она регистрирует сервер по имени
    ОТСУТСТВУЮЩЕЙ команды и теряет настоящую ошибку синтаксиса конфига.

    Ложный мир обязан ехать в том же канале, что боевой: прежняя решалка смотрит
    только stdout, и на пустом stdout она согласилась бы — такой «зелёный» тест
    проверял бы не дефект (ложнозелёный RED хуже красного).
    """
    ABSENT = 'command not found'  # живое слово rc=127 (замер: stdout при 2>&1)

    def test_absent_nginx_not_registered_as_config_check(self):
        c = FakeSSH(routes=[
            ('nginx -t', ('/bin/bash: line 1: nginx: command not found', '', 127)),
            ('apache2ctl', ('/bin/bash: line 1: apache2ctl: command not found',
                            '', 127)),
            ('httpd', ('/bin/bash: line 1: httpd: command not found', '', 127)),
        ])
        res = metrics_mod.check_web_config(c)
        assert res == {}, res
        out = metrics_mod.web_config_report(c)
        assert 'не обнаружен' in out
        assert self.ABSENT not in out

    def test_broken_apache_config_is_registered_not_dropped(self):
        c = FakeSSH(routes=[
            ('nginx -t', ('/bin/bash: line 1: nginx: command not found', '', 127)),
            ('apache2ctl', ('/bin/bash: line 1: apache2ctl: command not found',
                            '', 127)),
            ('httpd', ('', 'AH00526: Syntax error on line 376 of /tmp/broken.conf',
                       1)),
        ])
        res = metrics_mod.check_web_config(c)
        assert 'apache' in res, res
        assert 'Syntax error' in res['apache'], res['apache']
        assert self.ABSENT not in res['apache'], res['apache']

    def test_working_nginx_still_registered(self):
        c = FakeSSH(routes=[
            ('nginx -t', ('nginx: configuration file /etc/nginx/nginx.conf '
                          'test is successful', '', 0)),
            ('apache2ctl', ('/bin/bash: line 1: apache2ctl: command not found',
                            '', 127)),
            ('httpd', ('/bin/bash: line 1: httpd: command not found', '', 127)),
        ])
        res = metrics_mod.check_web_config(c)
        assert set(res) == {'nginx'}, res
        assert 'successful' in res['nginx']

class TestParseWebConfigProbe:
    """Парсер состояний — чистая функция: миры проверяются без SSH.

    Байты миров сняты живой программой на этой машине (httpd 2.4.69 есть,
    nginx/apache2ctl нет): rc=0 + AH00558 в stderr (исправный конфиг), rc=1 +
    AH00526 в stderr (битый конфиг), rc=127 + «command not found» в stdout при
    боевом 2>&1 (бинарника нет).
    """

    def test_rc_zero_with_body_is_ok(self):
        state, text, why = metrics_mod.parse_web_config_probe(
            'nginx: configuration file /etc/nginx/nginx.conf test is successful',
            '', 0)
        assert state == 'ok'
        assert 'successful' in text
        assert why is None

    def test_rc_zero_warning_in_stderr_is_ok(self):
        # Именно этот мир прежняя решалка превращала в «apache не обнаружен»:
        # ответ есть, канал — stderr, код нулевой.
        state, text, why = metrics_mod.parse_web_config_probe(
            '', "AH00558: Could not reliably determine the server's fqdn", 0)
        assert state == 'ok'
        assert 'AH00558' in text

    def test_rc_zero_silence_is_unchecked_not_ok(self):
        state, text, why = metrics_mod.parse_web_config_probe('', '', 0)
        assert state == 'unchecked'
        assert text == ''
        assert why

    def test_broken_config_is_broken_not_unchecked(self):
        state, text, why = metrics_mod.parse_web_config_probe(
            '', 'AH00526: Syntax error on line 376 of /tmp/broken.conf', 1)
        assert state == 'broken'
        assert 'Syntax error' in text
        assert why is None

    def test_absent_binaries_carry_the_measured_reason(self):
        for rc in (127, 126):
            state, text, why = metrics_mod.parse_web_config_probe(
                '/bin/sh: foo: command not found', '', rc)
            assert state == 'absent', rc
            assert text == '', rc  # отсутствие не едет в отчёт телом ответа
            assert 'command not found' in why, rc

    def test_absent_without_any_text_still_names_rc(self):
        state, text, why = metrics_mod.parse_web_config_probe('', '', 127)
        assert state == 'absent'
        assert 'rc=127' in why

    def test_silent_failure_is_unchecked(self):
        state, text, why = metrics_mod.parse_web_config_probe('', '', 137)
        assert state == 'unchecked'
        assert 'rc=137' in why


class TestWebConfigProbeForm:
    """Форма запроса: код возврата обязан принадлежать самой команде.

    Конвейер `||` и смешивание каналов `2>&1` были нужны прежней решалке,
    которая решала по слову. С конвейером код принадлежит ПОСЛЕДНЕЙ команде, и
    «apache2ctl не запустился» неотличим от «httpd ответил» (замер: обе боевые
    формы дали rc=127, хотя httpd на машине есть).
    """

    def test_command_has_no_channel_blinding_and_no_pipe(self):
        cmd = metrics_mod.web_config_probe_cmd('nginx')
        assert cmd == 'nginx -t'
        for blind in ('2>&1', '2>/dev/null', '||'):
            assert blind not in cmd, cmd

    def test_each_binary_asked_separately_and_stops_at_answer(self):
        c = FakeSSH(routes=[
            ('nginx -t', ('nginx: configuration file test is successful', '', 0)),
            ('apache2ctl', ('/bin/bash: line 1: apache2ctl: command not found',
                            '', 127)),
            ('httpd', ('', 'AH00558: could not reliably determine', 0)),
        ])
        res = metrics_mod.check_web_config(c)
        assert set(res) == {'nginx', 'apache'}
        asked = [x for x in c.commands if ' -t' in x]
        assert asked == ['nginx -t', 'apache2ctl -t', 'httpd -t'], asked
        for x in asked:
            assert '2>&1' not in x, x
            assert '||' not in x, x

    def test_unchecked_never_becomes_a_finding(self):
        # Пустой вывод при rc=0 — «не проверено»: он не должен ни регистрировать
        # сервер, ни превращаться в «конфиг в порядке».
        c = FakeSSH(routes=[
            ('nginx -t', ('', '', 0)),
            ('apache2ctl', ('', '', 0)),
            ('httpd', ('', '', 0)),
        ])
        assert metrics_mod.check_web_config(c) == {}
        out = metrics_mod.web_config_report(c)
        assert 'не обнаружен' in out


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


# ==================== СПРОС ПАНЕЛИ: ДОКАЗАТЕЛЬСТВО, А НЕ МОЛЧАНИЕ (1.32.12) ====
class TestPathEntryState:
    """Примитив «есть ли путь»: ответ обязан опираться на замер, а не на пустоту.

    Краснеет на прежнем коде отсутствующим API — иначе «панели нет» снова
    опиралось бы на молчание спросителя.

    Замер живьём (мира три: файл есть / файла нет / файл в каталоге chmod 000,
    путь на СВОЁМ дереве, значит воспроизводится и в бою):
      test -f X            -> rc=1 и ПУСТОЙ stderr в обоих отказах: различить
                              нечем ни числом, ни каналом;
      ls -d X, stat X,
      find X -maxdepth 0   ->rc одинаков в обоих отказах, миры различаются
                              только ТЕКСТОМ errno, а он локализован (родная
                              локаль «Отказано в доступе», LC_ALL=C
                              «Permission denied») -> признак по строке молча
                              сломался бы на клиентском хосте с другой локалью.
    Достоверен только ответ с rc=0, поэтому существование пути выводят из
    СПИСКА КАТАЛОГА (замер: пустой каталог даёт пустой stdout при rc=0).
    """

    FASTPANEL = '/usr/local/fastpanel/bin/fastpanel'

    def test_empty_stdout_of_listing_is_a_read_not_silence(self):
        # Ключевое отличие списка от одиночной команды: та же картина
        # (пусто + rc=0) значит «каталог пуст», а не «не проверено».
        import common as common_mod
        c = FakeSSH(routes=[('ls -1 -p', PANEL_NL.join(['', '']))])
        info = common_mod.dir_listing_info(c, '/usr/local')
        assert info['state'] == 'read'
        assert info['names'] == set()

    def test_listing_names_are_exactly_what_ls_prints(self):
        # Замер: ls -1 -p даёт суффикс «/» только НАСТОЯЩИМ каталогам
        # (симлинг на каталог — без суффикса), поэтому тип цели читается из
        # того же ответа и второго спроса не стоит.
        import common as common_mod
        c = FakeSSH(routes=[('ls -1 -p', PANEL_NL.join(
            ['bin', 'etc', 'fastpanel', '']))])
        names = common_mod.dir_listing_info(c, '/usr/local')['names']
        assert 'fastpanel' in names
        assert 'fastpanel/' not in names

    def test_unreadable_catalog_is_blocked_not_absent(self):
        # Числом «пути нет» и «прав нет» не различимы (замер: rc=2 и там, и
        # там), поэтому примитив обязан не выбирать молча: состояние blocked.
        import common as common_mod
        c = FakeSSH(routes=[('ls -1 -p', PANEL_DIR_DENIED)])
        info = common_mod.dir_listing_info(c, '/usr/local/fastpanel/bin')
        assert info['state'] == 'blocked'
        assert 'Permission denied' in info['note']

    def test_absence_is_proved_by_readable_ancestor(self):
        # Ниже не прочитано, но /usr/local прочитан при rc=0 и fastpanel в нём
        # нет -> отсутствия ДОКАЗАНЫ: это законный ответ «нет».
        import common as common_mod
        c = FakeSSH(routes=[
            ('/usr/local/fastpanel', PANEL_DIR_DENIED),
            ('/usr/local', PANEL_NL.join(['.', '..', 'bin', 'etc', ''])),
        ])
        st = common_mod.path_entry_state(c, self.FASTPANEL)
        assert st['state'] == 'absent'
        assert 'usr/local' in st['note']

    def test_nothing_readable_is_unchecked(self):
        # Если не прочитан ни один каталог, нельзя утверждать ни «есть», ни
        # «нет». Прежний код именно в этом мире печатал «панелей нет».
        import common as common_mod
        c = FakeSSH(routes=[('ls -1 -p', PANEL_DIR_DENIED)])
        st = common_mod.path_entry_state(c, self.FASTPANEL)
        assert st['state'] == 'unchecked'
        assert 'не проверено' in st['note']

    def test_found_requires_the_name_in_readable_parent(self):
        import common as common_mod
        c = FakeSSH(routes=[('/usr/local/fastpanel/bin', PANEL_NL.join(
            ['.', '..', 'fastpanel', '']))])
        st = common_mod.path_entry_state(c, self.FASTPANEL)
        assert st['state'] == 'found'

    def test_catalog_named_like_the_binary_is_not_the_binary(self):
        # Цель с суффиксом «/» — каталог: бинарником он быть не может, и
        # принимать его за панель нельзя.
        import common as common_mod
        c = FakeSSH(routes=[('/usr/local/fastpanel/bin', PANEL_NL.join(
            ['.', '..', 'fastpanel/', '']))])
        st = common_mod.path_entry_state(c, self.FASTPANEL)
        assert st['state'] == 'absent'
        assert 'каталог' in st['note']

    def test_ancestor_listing_is_asked_once(self):
        # Оба бинарника висят на /usr/local: кеш обязан убрать повторный спрос
        # общего предка. Сравнение ТОЧНОЕ: прошлая версия считала подстроку
        # 'ls -1 -p /usr/local' и ловила ещё и /usr/local/fastpanel/bin, то
        # есть проверяла не то (тот же закон серии: проверка обязана мерить
        # ровно заявленное).
        import common as common_mod
        c = FakeSSH(routes=[
            ('ls -1 -p /usr/local/fastpanel/bin', PANEL_DIR_DENIED),
            ('ls -1 -p /usr/local/mgr5/bin', PANEL_DIR_DENIED),
            ('ls -1 -p /usr/local/fastpanel', PANEL_NL.join(
                ['.', '..', 'bin/', ''])),
            ('ls -1 -p /usr/local/mgr5', PANEL_NL.join(
                ['.', '..', 'bin/', ''])),
            ('ls -1 -p /usr/local', PANEL_NL.join(
                ['.', '..', 'bin/', 'etc/', 'fastpanel/', 'mgr5/', ''])),
            ('ls -1 -p /usr', PANEL_NL.join(['.', '..', 'local/', ''])),
            ('ls -1 -p /', PANEL_NL.join(['.', '..', 'usr/', ''])),
        ])
        cache = {}
        first = common_mod.path_entry_state(c, self.FASTPANEL, cache)
        second = common_mod.path_entry_state(
            c, '/usr/local/mgr5/bin/mgrctl', cache)
        assert first['state'] == 'unchecked'
        assert second['state'] == 'unchecked'
        asked = [cmd for cmd in c.commands
                 if cmd == PANEL_LS_PREFIX + '/usr/local']
        assert len(asked) == 1, c.commands


class TestDetectPanelProbe:
    """«Панели нет» обязано быть доказательством, а не молчанием спросителя.

    Прежняя форма решала по пустоте stdout:

        test -f /usr/local/fastpanel/bin/fastpanel && echo "yes" || echo "no"

    и печатала «панелей нет» и когда бинарника нет, и когда прав не хватило
    посмотреть. Вторая ветка лгала так же: пайп
    «ps aux | grep -E "fastpanel|mgr5" | grep -v grep» даёт rc=1 и ноль байт и
    когда панелей нет, и когда ps не запустился вовсе (замер) — молчание
    читалось как «панелей нет».
    """

    FP_DIR = '/usr/local/fastpanel/bin'
    MGR_DIR = '/usr/local/mgr5/bin'

    def test_binary_in_readable_listing_is_the_panel(self):
        c = FakeSSH(routes=[(self.FP_DIR, PANEL_NL.join(
            ['.', '..', 'fastpanel', '']))])
        assert metrics_mod.detect_panel(c) == 'fastpanel'

    def test_readable_listings_without_names_is_measured_absence(self):
        # rc=0, список прочитан, имени нет -> «панелей нет» законно, но только
        # когда и вторая ветка (процессы) тоже ответила.
        c = FakeSSH(routes=[
            (self.FP_DIR, PANEL_NL.join(['.', '..', 'some-tool', ''])),
            (self.MGR_DIR, PANEL_DOTDOT),
            ('ps aux', PANEL_PS_HEADER),
        ])
        assert metrics_mod.detect_panel(c) == 'none'

    def test_unreadable_directories_are_unchecked_not_none(self):
        # Игла 'ls -1 -p' отказывает для ВСЕХ спрашиваемых каталогов: иначе
        # (замер двойником: default = ('', '', 0)) прочитанный по умолчанию
        # предок доказывал бы отсутствие, и тест зеленел бы по неверной
        # причине — ровно урок 1.27.0.
        c = FakeSSH(routes=[('ls -1 -p', PANEL_DIR_DENIED),
                            ('ps aux', PANEL_PS_HEADER)])
        assert metrics_mod.detect_panel(c) != 'none'

    def test_ps_probe_that_never_ran_is_unchecked_not_none(self):
        # Каталоги прочитаны достоверно (имён нет), но ps не запустился
        # (rc=127). Утверждать «панелей нет» нельзя: панель могла стоять в
        # пути, которого нет ни в одном проверенном каталоге. Прежний код
        # читал только stdout и печатал именно 'none'.
        c = FakeSSH(routes=[
            (self.FP_DIR, PANEL_DOTDOT),
            (self.MGR_DIR, PANEL_DOTDOT),
            ('ps aux', PANEL_NO_PS),
        ])
        assert metrics_mod.detect_panel(c) != 'none'

    def test_no_probe_blinds_channels_or_adds_default(self):
        # Форма запроса — часть контракта: заглушка канала убивает причину
        # отказа, ||-дополнение превращает любой отказ в готовое слово, пайп
        # крадёт код возврата у первой команды.
        c = FakeSSH()
        metrics_mod.detect_panel(c)
        forbidden = ['2>/dev/null', '|| echo', '&& echo', '| grep']
        bad = [cmd for cmd in c.commands
               for needle in forbidden if needle in cmd]
        assert not bad, 'спроситель лжёт формой: %s' % bad[:2]
        ps = [cmd for cmd in c.commands if 'ps' in cmd]
        assert len(ps) == 1, 'ps должен звучать ровно один раз: %s' % ps

    def test_returned_value_stays_a_string(self):
        # detect_panel читают 12 вызовов (gui_runner, discovery, logs), и все
        # они выбирают наборы путей через .get(panel_type, ...). Словарь-ответ
        # это ломает, поэтому значение обязано оставаться строкой.
        for routes in ([], [('ls -1 -p', PANEL_DIR_DENIED)]):
            value = metrics_mod.detect_panel(FakeSSH(routes=routes))
            assert isinstance(value, str), repr(value)

    def test_unchecked_marker_is_not_a_panel(self):
        """Гарантия не на совести вызывающего (замерена, а не выдумана).

        Первая формулировка этой проверки была моим дефектом: я ждал, что
        неизвестное значение везде деградирует в none-набор, а замер дал
        разное: VHOST_PATTERNS.get(panel_type, VHOST_PATTERNS['none']) при
        неизвестном значении даёт none-набор, а HTTPD_VHOST_PATTERNS.get(
        panel_type, []) — пусто. Достоверное требование другое: новый признак
        обязан НЕ попадать в ключи словарей панелей, иначе его примут за
        настоящую панель и начнут спрашивать чужие пути.
        """
        import common as common_mod
        import discovery as discovery_mod
        assert 'unchecked' not in discovery_mod.VHOST_PATTERNS
        assert 'unchecked' not in discovery_mod.HTTPD_VHOST_PATTERNS
        assert (discovery_mod.VHOST_PATTERNS.get(
            'unchecked', discovery_mod.VHOST_PATTERNS['none'])
            == discovery_mod.VHOST_PATTERNS['none'])
        assert common_mod.DOMAIN_PATHS.get('unchecked') is None

    def test_unchecked_still_asks_apache_vhosts(self):
        # Регрессия, которую новый признак внёс бы молча: discovery выбирает
        # apache-пути как HTTPD_VHOST_PATTERNS.get(panel_type, []), и при
        # неизвестном значении пути перестали бы спрашиваться (nginx-ветка так
        # не деградирует — у неё дефолт none-набор). Спрос обязан остаться.
        import discovery as discovery_mod
        c = FakeSSH(routes=[('ps aux', PANEL_PS_HEADER)])
        discovery_mod.discover_sites(c, metrics_mod.PANEL_UNCHECKED)
        apache = [cmd for cmd in c.commands if 'apache2/sites-enabled' in cmd]
        assert apache, 'apache vhosts при неизвестной панели перестали ' + \
            'спрашиваться: %s' % c.commands[:6]

# ==================== ПРИЗНАК ПО ПРОЦЕССУ И МЕТКА (1.32.12) =====
class TestPanelProcessSign:
    """Признак панели по процессу обязан смотреть argv[0], а не строку целиком.

    Живой замер (верификатор 1.32.12, настоящий bash на машине БЕЗ панелей):
    прежняя форма «ps aux | grep -E "fastpanel|mgr5" | grep -v grep» вернула
    fastpanel, потому что искомое слово стояло в командной строке самого
    наблюдателя. Подстрока в чужом выводе находит панель где угодно: в
    «vim /root/fastpanel-notes.txt», в чужом grep, в имени скрипта оператора.

    ФОРМА СТРОКИ ps — часть замера. Колонки ps aux: USER PID %CPU %MEM VSZ RSS
    TTY STAT START TIME COMMAND, то есть десять полей до COMMAND. Прежние
    фикстуры этой серии писали «root 1 0.0 /opt/...» (четыре поля), и пока
    признак был подстрокой, это не всплывало; после перехода на argv[0] такая
    фикстура покраснела бы по формату, а не по существу — ровно урок 1.27.0.
    """

    FP_DIR = '/usr/local/fastpanel/bin'
    MGR_DIR = '/usr/local/mgr5/bin'
    # Девять полей до COMMAND + её начало; десятое (TIME) — последнее перед ней.
    ROW = 'root 1 0.0 0.0 1234 567 ? Sl 00:00 0:01 '

    def clean_ps(self, command):
        """Мир, где каталоги прочитаны (имён нет), и ответ решает ps."""
        return [
            (self.FP_DIR, PANEL_DOTDOT),
            (self.MGR_DIR, PANEL_DOTDOT),
            ('ps aux', PANEL_PS_HEADER + self.ROW + command + PANEL_NL),
        ]

    def test_header_alone_is_not_a_panel(self):
        # Заголовок — не процесс: его COMMAND буквально равно 'COMMAND'.
        assert metrics_mod.panel_from_processes(PANEL_PS_HEADER) is None

    def test_word_in_foreign_command_line_is_not_a_panel(self):
        # Оператор открыл файл с таким словом в имени — панели это не делает.
        c = FakeSSH(routes=self.clean_ps('vim /root/fastpanel-notes.txt'))
        assert metrics_mod.detect_panel(c) == 'none'

    def test_grep_that_searches_the_panel_is_not_the_panel(self):
        # Ровно живой кейс: пайп, который сам ищет слово, виден в ps aux.
        c = FakeSSH(routes=self.clean_ps(
            'bash -c ps aux | grep -E fastpanel|mgr5'))
        assert metrics_mod.detect_panel(c) == 'none'

    def test_observer_own_command_line_is_not_a_panel(self):
        # Наблюдатель (скрипт диагностики) обязан выпадать из признания: его
        # argv[0] — интерпретатор, а не панель.
        c = FakeSSH(routes=self.clean_ps(
            'python3 /home/op/diagnose-fastpanel-check.py'))
        assert metrics_mod.detect_panel(c) == 'none'

    def test_panel_binary_path_is_still_detected(self):
        # Нестандартный путь (/opt/...) ловится: панель стоит не только в
        # /usr/local, и отказываться от ветки процессов нельзя.
        c = FakeSSH(routes=self.clean_ps('/opt/fastpanel/bin/fastpanel'))
        assert metrics_mod.detect_panel(c) == 'fastpanel'

    def test_ispmanager_daemon_path_is_detected(self):
        c = FakeSSH(routes=self.clean_ps('/usr/local/mgr5/sbin/mgr.cert -d'))
        assert metrics_mod.detect_panel(c) == 'ispmanager'

    def test_argv0_is_parsed_from_the_tenth_field(self):
        row = self.ROW + '/usr/local/mgr5/sbin/ihttpd -D'
        assert metrics_mod.ps_row_command(row) == (
            '/usr/local/mgr5/sbin/ihttpd -D')
        assert metrics_mod.ps_row_binary(row) == '/usr/local/mgr5/sbin/ihttpd'

    def test_short_row_is_not_guessed(self):
        # Строка короче десяти полей — не процесс: пусто, а не догадка.
        assert metrics_mod.ps_row_command('root 1 0.0 /opt/fastpanel') == ''
        assert metrics_mod.ps_row_binary('root 1 0.0 /opt/fastpanel') == ''


class TestPanelLabel:
    """Отображение: машинный маркер не имеет права попадать в лог оператора.

    gui_runner пишет f"Панель управления: {panel_type}" в лог подключения,
    поэтому значение 'unchecked' дошло бы до человека латинским словом.
    """

    def test_unchecked_is_not_shown_as_a_marker(self):
        label = metrics_mod.panel_label(metrics_mod.PANEL_UNCHECKED)
        assert 'unchecked' not in label
        assert 'не проверено' in label

    def test_measured_absence_says_it_was_checked(self):
        assert 'проверено' in metrics_mod.panel_label('none')

    def test_known_panels_keep_their_names(self):
        assert metrics_mod.panel_label('fastpanel') == 'FastPanel'
        assert metrics_mod.panel_label('ispmanager') == 'ISPmanager'

    def test_unknown_value_is_passed_through_not_invented(self):
        # Метка честна и для значения, которого словарь не знает: выдумывать
        # вместо него «не найдена» — значит подменить ответ догадкой.
        assert metrics_mod.panel_label('vapour') == 'vapour'

    def test_gui_prints_the_label_not_the_marker(self):
        # Страж по ТЕКСТУ, а не по импорту: модуль GUI в этом окружении
        # не поднимается (tkinter в хостовом python отсутствует —
        # граница объявления), а регрессия живёт именно в строке
        # вывода: f"Панель управления: {self.panel_type}" допечатала бы
        # оператору машинный маркер unchecked.
        import io
        import os
        path = os.path.join(os.path.dirname(metrics_mod.__file__),
                            'gui_runner.py')
        text = io.open(path, encoding='utf-8').read()
        assert 'panel_label(self.panel_type)' in text
        assert 'Панель управления: {self.panel_type}' not in text
