"""Тесты metrics.py: определение панели, сбор метрик, сетевой отчёт, веб-конфиг.

Реального SSH нет — команды перехватывает FakeSSH из support.py.
"""
import os
import sys

import pytest

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
        # ЗАЯВЛЕННАЯ ПЕРЕПИСКА ЗАМКА ФОРМЫ (1.32.29): прежний замок '%s=%s'
        # охранял форму, в которой 'inactive' отсутствующего юнита и
        # остановленного побайтово равны, — ровно ту ложь, что лечит слайс.
        # Новый замок — маркерная форма: имя в маркере, состояние решает rc.
        cmd = metrics_mod.services_status_cmd(['nginx', 'php 8.2-fpm'])
        assert "'php 8.2-fpm'" in cmd
        assert 'printf "@%s' in cmd
        assert 'printf "rc=%s' in cmd

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
    # Фикстура — СЫРОЙ вывод `ip route get` (разбор src/dev переехал из
    # shell-конвейера grep|cut в Python: конвейер глушил причину через
    # 2>/dev/null, зависел от GNU grep -P и решал по коду cut, а не ip).
    ROUTES = [
        ('route get', '1.1.1.1 via 10.0.0.1 dev eth0 src 10.0.0.5 uid 0\n'),
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
        assert 'Внешний IP не удалось определить' in out
        # Прежний тест проверял «строки про источник нет» — но молчаливая
        # потеря строки неотличима от «так и надо». Теперь отсутствие
        # источника обязано быть сказано С ПРИЧИНОЙ (закон серии), поэтому
        # находка строки здесь и есть проверяемое поведение.
        assert 'IP-адрес источника для исходящего трафика' not in out
        assert 'IP-адрес источника не определён' in out


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


class TestExternalIpIsAnAddressNotAChainOutput:
    """Внешний IP обязан быть адресом, а не выводом ||-цепочки (1.32.26).

    Прежний код спрашивал ОДНОЙ командой

        curl -s ifconfig.me 2>/dev/null || wget -qO- ifconfig.me 2>/dev/null
            || dig +short myip.opendns.com @resolver1.opendns.com 2>/dev/null

    и решал по непустоте stdout: exec_command контрактом отдаёт только пару
    каналов, код возврата выбрасывается в ssh_client.exec_command. Замер
    живьём на этой машине (все три утилиты установлены) дал три мира, в них
    прежний отчёт лжёт байтами, а не словами:

      curl нет, wget есть       цепочка даёт rc=0 и <!DOCTYPE html>...: отчёт
        печатает «Внешний (плавающий) IP: <!DOCTYPE html>» — HTML выдан за
        адрес;
      curl и wget нет, dig есть dig пишет диагностику отказа в STDOUT с rc=9,
        и она доезжает как «плавающий IP»;
      всё установлено, сети нет curl даёт rc=6, а -s глушит причину ЦЕЛИКОМ
        (stdout и stderr пусты), и строка отчёта советует «установите
        curl/wget/dig» там, где всё уже установлено.

    Порядок роутов в фикстурах значит: FakeSSH матчает ПОДСТРОКОЙ и берёт
    ПЕРВЫЙ подходящий, а прежний код делает ОДИН спрос на всю цепочку. Роут,
    который обязан достаться прежней коду, стоит в списке раньше остальных;
    новый код спрашивает бинарники раздельно и получает каждый свой ответ.
    """
    IP_A = '2: eth0: <BROADCAST>\n    inet 10.0.0.5/24 scope global eth0\n'
    IP_R = 'default via 10.0.0.1 dev eth0 proto dhcp metric 100\n'
    HTML = '<!DOCTYPE html>\n<html lang="en">\n<head>\n'
    DIG_FAIL = (';; communications error to 192.0.2.1#53: timed out\n'
                ';; no servers could be reached\n')
    ABSENT = 'command not found'

    def base(self):
        # 'route get' обязан стоять перед 'ip r': игла 'ip r' иначе проглотила
        # бы и её — контракт, уже закреплённый TestNetworkReport. Вывод —
        # сырая строка `ip route get`, разбор в Python.
        return [('route get', '1.1.1.1 via 10.0.0.1 dev eth0 src 10.0.0.5\n'),
                ('ip r', self.IP_R), ('ip a', self.IP_A)]

    def test_html_from_wget_is_not_reported_as_an_address(self):
        # Мир замера 1c: PATH без curl -> боевая цепочка уходит в wget и
        # возвращается rc=0 с HTML-ом страницы. Иглы — по именам бинарников:
        # команды обёрнуты в `timeout` и снабжены флагами таймаутов, точная
        # подстрока прежней формы ('-sS ifconfig.me') больше не встречается.
        c = FakeSSH(routes=self.base() + [
            ('wget', (self.HTML, '', 0)),
            ('curl', ('', '/bin/bash: line 1: curl: ' + self.ABSENT, 127)),
            ('dig', ('', '/bin/bash: line 1: dig: ' + self.ABSENT, 127)),
        ])
        out = metrics_mod.network_report(c)
        assert '<!DOCTYPE' not in out, out[-260:]
        assert self.ABSENT not in out, out[-260:]

    def test_dig_diagnostic_is_not_reported_as_an_address(self):
        # dig пишет диагностику отказа в STDOUT (rc=9): для решалки по
        # непустоте это «ответ есть», а по существу — отказ резолвера.
        c = FakeSSH(routes=self.base() + [
            ('dig', (self.DIG_FAIL, '', 9)),
            ('wget', ('', '/bin/bash: line 1: wget: ' + self.ABSENT, 127)),
            ('curl', ('', '/bin/bash: line 1: curl: ' + self.ABSENT, 127)),
        ])
        out = metrics_mod.network_report(c)
        assert ';; communications error' not in out, out[-260:]
        assert 'no servers could be reached' not in out, out[-260:]

    def test_install_advice_is_not_shown_when_tools_are_installed(self):
        # Утилиты на месте, сети нет: curl rc=6 (-s глушит причину), wget
        # rc=4, dig rc=9. Прежняя строка советует УСТАНОВИТЬ уже
        # установленное, и оператор едет ставить пакеты вместо диагностики.
        c = FakeSSH(routes=self.base() + [
            ('wget', ('', 'wget: unable to resolve host address', 4)),
            ('curl', ('', 'curl: (6) Could not resolve host: '
                       'ifconfig.me', 6)),
            ('dig', (self.DIG_FAIL, '', 9)),
        ])
        out = metrics_mod.network_report(c)
        assert 'установите' not in out, out[-260:]


class TestAsIpAddress:
    """Признак «адрес» — сам адрес, а не непустота вывода утилиты.

    Замеры живьём (1.32.26): curl даёт '135.181.169.106', wget в ЧЕСТНОМ мире
    даёт HTML-страницу страницы ifconfig.me, dig при недоступном резолвере
    пишет ';; communications error to 192.0.2.1#53: timed out' в STDOUT. Все
    три варианта непустые, поэтому решение по непустоте и выдавало HTML и
    диагностику резолвера как «плавающий IP».
    """

    def test_plain_v4_and_v6_are_addresses(self):
        assert metrics_mod.as_ip_address('135.181.169.106') == '135.181.169.106'
        assert metrics_mod.as_ip_address('2001:db8::1') == '2001:db8::1'

    def test_surrounding_blanks_and_trailing_lines_are_tolerated(self):
        # Боевые утилиты печатают адрес со переводом строки (замер: curl).
        assert metrics_mod.as_ip_address(' 203.0.113.9\n') == '203.0.113.9'
        assert (metrics_mod.as_ip_address('203.0.113.9\nлишний хвост\n')
                == '203.0.113.9')

    def test_html_and_resolver_diagnostic_are_not_addresses(self):
        # Дословные байты из замеров 1c и 1b.
        assert metrics_mod.as_ip_address('<!DOCTYPE html>\n<html lang="en">') == ''
        assert metrics_mod.as_ip_address(';; communications error to '
                                         '192.0.2.1#53: timed out') == ''

    def test_empty_is_not_an_address(self):
        for body in ('', '   ', '\n\n'):
            assert metrics_mod.as_ip_address(body) == '', repr(body)


class TestParseExternalIpProbe:
    """Пять состояний вместо «пусто / непусто»; причина — только из stderr."""

    def test_address_state_carries_the_address(self):
        state, addr, why = metrics_mod.parse_external_ip_probe(
            '203.0.113.9\n', '', 0)
        assert state == 'address'
        assert addr == '203.0.113.9'
        assert why is None

    def test_success_with_html_is_not_address_not_a_finding(self):
        state, addr, why = metrics_mod.parse_external_ip_probe(
            '<!DOCTYPE html>\n<html>', '', 0)
        assert state == 'not_address'
        assert addr == ''
        assert why and 'адресом' in why

    def test_absent_is_proved_by_rc_not_by_empty_output(self):
        for rc in (127, 126):
            state, addr, why = metrics_mod.parse_external_ip_probe(
                '', '/bin/bash: line 1: curl: command not found', rc)
            assert state == 'absent', rc
            assert addr == '', rc
            assert 'command not found' in why, rc

    def test_failure_keeps_the_stderr_reason(self):
        # Живой байт замера: curl -sS при rc=6 даёт причину в stderr.
        state, addr, why = metrics_mod.parse_external_ip_probe(
            '', 'curl: (6) Could not resolve host: ifconfig.me', 6)
        assert state == 'failed'
        assert why.startswith('curl: (6)')

    def test_silence_at_rc_zero_is_unchecked(self):
        # Мир заглушки: утилита ушла rc=0, ничего не напечатав (замер 1c).
        state, addr, why = metrics_mod.parse_external_ip_probe('', '', 0)
        assert state == 'unchecked'
        assert addr == ''
        assert why

    def test_stdout_never_leaks_into_the_reason(self):
        # Диагностика dig живёт в STDOUT (rc=9): в причину она не попадает,
        # иначе отрицание второй раз напечатает то, что уже отказ.
        state, addr, why = metrics_mod.parse_external_ip_probe(
            ';; no servers could be reached', '', 9)
        assert state == 'failed'
        assert why == 'rc=9'


class TestExternalIpNoteAndOrder:
    """Отрицание с причиной; «установите» — только когда ставить нечего."""

    def test_install_advice_only_when_nothing_is_installed(self):
        probe = {'address': '', 'notes': ['curl не найдена'],
                 'absent': ['curl', 'wget', 'dig'], 'asked': 3,
                 'all_absent': True}
        note = metrics_mod.external_ip_note(probe)
        assert 'установите' in note
        assert 'не удалось определить' in note

    def test_reasons_are_kept_and_no_install_advice(self):
        probe = {'address': '', 'notes': ['curl: (6) Could not resolve host'],
                 'absent': [], 'asked': 3, 'all_absent': False}
        note = metrics_mod.external_ip_note(probe)
        assert 'установите' not in note
        assert 'Could not resolve host' in note

    def test_probe_stops_at_the_first_valid_address(self):
        # Иглы и проверка — по боевым командам из EXTERNAL_IP_SOURCES, а не по
        # прежней голой форме 'curl -sS ifconfig.me': команды обёрнуты в
        # `timeout` и несут флаги таймаутов (риск зависания потока GUI), и
        # тест обязан переживать следующую смену формы, проверяя ПОРЯДОК, а не
        # букву строки.
        curl_cmd = metrics_mod.EXTERNAL_IP_SOURCES[0][1]
        wget_cmd = metrics_mod.EXTERNAL_IP_SOURCES[1][1]
        dig_cmd = metrics_mod.EXTERNAL_IP_SOURCES[2][1]
        c = FakeSSH(routes=[
            (curl_cmd, ('203.0.113.9\n', '', 0)),
            (wget_cmd, ('<html>', '', 0)),
            (dig_cmd, ('', '', 0)),
        ])
        probe = metrics_mod.probe_external_ip(c)
        assert probe['address'] == '203.0.113.9'
        asked = [x for x in c.commands if 'ifconfig' in x or 'dig' in x]
        assert asked == [curl_cmd], asked

    def test_probe_keps_asking_after_a_non_address(self):
        # Мир 1c: curl нет, wget отдаёт HTML. Обход обязан дойти до dig, а
        # находкой HTML не стать.
        curl_cmd = metrics_mod.EXTERNAL_IP_SOURCES[0][1]
        wget_cmd = metrics_mod.EXTERNAL_IP_SOURCES[1][1]
        dig_cmd = metrics_mod.EXTERNAL_IP_SOURCES[2][1]
        c = FakeSSH(routes=[
            (curl_cmd, ('', '/bin/bash: line 1: curl: command '
                        'not found', 127)),
            (wget_cmd, ('<!DOCTYPE html>\n<html>', '', 0)),
            (dig_cmd, (';; communications error\n', '', 9)),
        ])
        probe = metrics_mod.probe_external_ip(c)
        assert probe['address'] == ''
        assert probe['all_absent'] is False
        asked = [x for x in c.commands if 'ifconfig' in x or 'dig' in x]
        assert len(asked) == 3, asked
        assert '<!DOCTYPE' not in metrics_mod.external_ip_note(probe)

    def test_probe_reports_all_absent_without_inventing_an_answer(self):
        curl_cmd = metrics_mod.EXTERNAL_IP_SOURCES[0][1]
        wget_cmd = metrics_mod.EXTERNAL_IP_SOURCES[1][1]
        dig_cmd = metrics_mod.EXTERNAL_IP_SOURCES[2][1]
        c = FakeSSH(routes=[
            (curl_cmd, ('', 'bash: curl: command not found', 127)),
            (wget_cmd, ('', 'bash: wget: command not found', 127)),
            (dig_cmd, ('', 'bash: dig: command not found', 127)),
        ])
        probe = metrics_mod.probe_external_ip(c)
        assert probe['address'] == ''
        assert probe['all_absent'] is True
        assert 'установите' in metrics_mod.external_ip_note(probe)


# ==== веб-конфиг: веб-сервер регистрируется кодом возврата, а не словом ====
# RED этого слайса (1.32.25) красен ПО СУЩЕСТВУ, а не по отсутствию имени: все
# три теста гонят существующую check_web_config на ЖИВЫХ байтах этой машины
# (замер: nginx/apache2ctl отсутствуют -> rc=127 со stdout «command not found»,
# настоящий httpd на битом конфиге -> rc=1 «AH00526: Syntax error on line 376»).
# Прежняя решалка (`if 'nginx' in out` на выводе `nginx -t 2>&1`, там же)
# вывернута: регистрирует сервер по имени ОТСУТСТВУЮЩЕЙ команды и НЕ
# регистрирует apache при честном отказе конфига.

    def test_note_never_prints_an_empty_reason_list(self):
        # Замер живьём (1.32.26): external_ip_note для уже найденного адреса
        # возвращал 'Внешний IP не удалось определить: ' — отрицание со ссылкой
        # на причины, которых нет. network_report в такую ветку не заходит, но
        # носитель, умеющий напечатать ложь, рано или поздно её напечатает:
        # закон серии «отрицание обязано быть с причиной» проверяющий не
        # допрошен.
        cases = (
            {'address': '203.0.113.9', 'notes': [], 'absent': [], 'asked': 1,
             'all_absent': False},
            {'address': '', 'notes': [], 'absent': [], 'asked': 3,
             'all_absent': False},
        )
        for probe in cases:
            note = metrics_mod.external_ip_note(probe)
            assert 'не удалось определить' in note, repr(note)
            assert not note.rstrip().endswith(':'), repr(note)
            reason = note.split(':', 1)[1].strip()
            assert reason, repr(note)
            assert '<!DOCTYPE' not in note, repr(note)


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


# ====== СОСТОЯНИЕ СЛУЖБЫ: решается кодом возврата, а не словом (1.32.29) ======
# Замер живьём (systemd 259, этот хост; независимый оракул
# `systemctl show -p LoadState --value`): services_status_cmd спрашивал
# службы ОДНИМ циклом и терял код возврата каждой (rc сборки принадлежит
# ПОСЛЕДНЕЙ команде), а is-active пишет ОДИН И ТОТ ЖЕ stdout `inactive` для
# несуществующей службы (rc=4) и для остановленной (rc=3). По боевому
# SERVICES_TO_CHECK оракул отвечает not-found по 10 из 11 служб (жив только
# httpd), а parse_service_statuses на реальных байтах отдаёт 'inactive' всем
# — «установлено, но остановлено» про юниты, которых нет вовсе.
# Вторая половина того же дефекта: `2>/dev/null` глошила единственную строку
# с причиной, а `[ -n "$st" ] || st=unknown` превращала «мы не смогли
# спросить» в unknown, который оператор читает как диагноз.
class TestServiceStateIsDecidedByExitCode:
    def test_probe_carries_rc_of_every_service(self):
        # rc обязан сниматься ВНУТРИ итерации: иначе он принадлежит последней
        # службе и остальные приходят без ответа (замер 1.32.27).
        cmd = metrics_mod.services_status_cmd(['nginx', 'php-fpm'])
        assert 'printf "rc=' in cmd, cmd
        assert cmd.count('systemctl is-active') == 1, cmd
        # Причина живёт в stderr: заглушить её — значит оставить ответ без
        # единственного доказательства (тот же закон, что в 1.32.26).
        assert '2>/dev/null' not in cmd, cmd

    def test_absent_unit_is_not_reported_as_inactive(self):
        # Ключевой RED: эти байты машина выдаёт на НЕ существующую службу
        # (rc=4, LoadState=not-found), а прежний разбор читал их как
        # `inactive`, то есть как «установлено, но остановлено».
        out = '@nginx' + chr(10) + 'inactive' + chr(10) + 'rc=4' + chr(10)
        assert metrics_mod.parse_service_statuses(out) == {
            'nginx': 'не установлен'}

    def test_stopped_service_stays_inactive(self):
        # Та же пара байтов, но rc=3 (юнит load'ится): остановленный обязан
        # остаться остановленным, иначе правка переложит ложь, а не снимет.
        out = '@httpd' + chr(10) + 'inactive' + chr(10) + 'rc=3' + chr(10)
        assert metrics_mod.parse_service_statuses(out) == {'httpd': 'inactive'}

    def test_silence_of_the_system_is_unchecked_not_unknown(self):
        # bus dead: stdout пуст, ответ системы — в stderr (замер). Ни
        # `unknown`, ни `inactive`, ни «не установлен»: только непроверено.
        out = '@nginx' + chr(10) + 'rc=1' + chr(10)
        assert metrics_mod.parse_service_statuses(out) == {'nginx': None}

    def test_previous_answer_form_still_reads(self):
        # Обратная совместимость заперта: ответ ПРЕЖНЕЙ команды (старший
        # сервер, чужая ветка кода) читается ровно как раньше, а не
        # превращается в молчание или в выдуманное «не установлен».
        out = 'nginx=active' + chr(10) + 'mysql=inactive' + chr(10)
        assert metrics_mod.parse_service_statuses(out) == {
            'nginx': 'active', 'mysql': 'inactive'}

    def test_report_names_the_gap_instead_of_printing_none(self):
        # Молчание системы не имеет права исчезнуть из отчёта. Искать
        # признание по всему выводу нельзя: «не проверено» печатает и
        # секция файрвола, тогда проверка была бы зеленой молча. Берём
        # ровно блок служб и требуем, что заголовок в выводе один.
        routes = [
            ('df -h', 'Filesystem  Size  Used' + chr(10)),
            ('df -i', 'Filesystem Inodes' + chr(10)),
            ('free -m', 'total  used' + chr(10)),
            ('uptime', 'up 3 days'),
            ('ss -tulpn', 'tcp  LISTEN  0  128  *:22'),
            ('__svc_status', '@nginx' + chr(10) + 'rc=1' + chr(10)),
        ]
        out = metrics_mod.metrics_report(FakeSSH(routes=routes))
        assert out.count('Статусы служб:') == 1, out
        block = out.split('Статусы служб:')[-1]
        assert 'nginx' in block, block
        assert 'не проверено' in block, block
        assert 'unknown' not in block, block
        assert 'nginx: None' not in block, block


# ==================== ПРИВЯЗКА ПЛАВАЮЩЕГО IP (1.32.30) ====================
class TestInterfaceAddressesParse:
    def test_map_from_realistic_output(self):
        out = ('1: lo    inet 127.0.0.1/8 scope host lo \\       valid_lft '
               'forever preferred_lft forever' + chr(10) +
               '2: eth0    inet 10.0.0.5/24 brd 10.0.0.255 scope global eth0'
               ' \\       valid_lft forever' + chr(10) +
               '3: eth0    inet 203.0.113.9/32 scope global secondary eth0'
               ' \\       valid_lft forever')
        m = metrics_mod.parse_interface_addresses(out)
        assert m['10.0.0.5'] == [('eth0', 'global')]
        assert m['203.0.113.9'] == [('eth0', 'global')]
        assert m['127.0.0.1'] == [('lo', 'host')]

    def test_ipv6_zone_id_stripped(self):
        out = ('2: eth0    inet6 fe80::abcd%eth0/64 scope link '
               '\\       valid_lft forever')
        m = metrics_mod.parse_interface_addresses(out)
        assert m['fe80::abcd'] == [('eth0', 'link')]

    def test_garbage_lines_skipped_not_crash(self):
        # Вывод чужой машины может быть чем угодно — разбор не должен падать.
        out = ('Мусор\n'
               '2: eth0    inet не-адрес/24 scope global eth0\n'
               'короткая\n'
               '2: eth0    inet 10.0.0.5/24 scope global eth0\n')
        m = metrics_mod.parse_interface_addresses(out)
        assert m == {'10.0.0.5': [('eth0', 'global')]}

    def test_same_addr_two_interfaces(self):
        out = ('2: eth0    inet 203.0.113.9/32 scope global eth0\n'
               '3: bond0    inet 203.0.113.9/32 scope global bond0\n')
        m = metrics_mod.parse_interface_addresses(out)
        assert m['203.0.113.9'] == [('eth0', 'global'), ('bond0', 'global')]


class TestInterfaceBindReport:
    def test_bound_to_interface(self):
        c = FakeSSH(routes=[('ip -o addr',
                             '2: eth0    inet 203.0.113.9/32 scope global '
                             'eth0\n')])
        note = metrics_mod.interface_bind_note(c, '203.0.113.9', 'eth0')
        assert 'назначен интерфейсу: eth0 (scope global)' in note
        assert 'NAT' not in note

    def test_not_bound_means_provider_nat(self):
        c = FakeSSH(routes=[('ip -o addr',
                             '2: eth0    inet 10.0.0.5/24 scope global eth0'
                             '\n')])
        note = metrics_mod.interface_bind_note(c, '203.0.113.9', 'eth0')
        assert 'не назначен ни одному интерфейсу' in note
        assert 'provider NAT / DNAT / балансировщик' in note
        assert 'через eth0' in note

    def test_command_failure_is_unchecked_not_nat(self):
        # rc!=0 — «мы не спросили». Это не право говорить про «адреса нет на
        # интерфейсах»: миры лечатся противоположно.
        c = FakeSSH(routes=[('ip -o addr',
                             ('', 'RTNETLINK answers: Operation not '
                              'permitted', 2))])
        note = metrics_mod.interface_bind_note(c, '203.0.113.9')
        assert 'не проверена' in note
        assert 'не проверено' in note
        assert 'provider NAT' not in note

    def test_rc0_without_addresses_is_unchecked(self):
        # Реальная система никогда не вернёт rc=0 и ноль записей; пустой
        # вывод — молчание, а не «ни на чём не висит».
        c = FakeSSH(routes=[('ip -o addr', '')])
        note = metrics_mod.interface_bind_note(c, '203.0.113.9')
        assert 'не проверена' in note
        assert 'provider NAT' not in note


class TestNetworkReportBinding:
    # Вывод 'route get' — сырая строка ip route get (разбор в Python).
    BASE = [('route get', '1.1.1.1 via 10.0.0.1 dev eth0 src 10.0.0.5\n'),
            ('ip r', 'default via 10.0.0.1 dev eth0\n'),
            ('ip a', '2: eth0: <B>\n    inet 10.0.0.5/24 scope global eth0\n'),
            ('ifconfig.me', '203.0.113.9\n')]

    def test_nat_case_adds_unbound_note(self):
        routes = self.BASE + [('ip -o addr',
                               '2: eth0    inet 10.0.0.5/24 scope global '
                               'eth0\n')]
        out = metrics_mod.network_report(FakeSSH(routes=routes))
        assert 'трафик идёт через NAT' in out
        assert 'не назначен ни одному интерфейсу' in out

    def test_direct_public_ip_no_nat_claim(self):
        # Источник совпал с внешним ответом: адрес машины и есть внешний.
        # Прежний код печатал «трафик идёт через NAT» при ЛЮБОМ src_ip.
        routes = [('route get', '1.1.1.1 via 203.0.113.1 dev eth0 '
                                'src 203.0.113.9\n'),
                  ('ip r', 'default via 203.0.113.1 dev eth0\n'),
                  ('ip a', '2: eth0: <B>\n    inet 203.0.113.9/24 scope '
                           'global eth0\n'),
                  ('ifconfig.me', '203.0.113.9\n'),
                  ('ip -o addr', '2: eth0    inet 203.0.113.9/24 scope '
                                 'global eth0\n')]
        out = metrics_mod.network_report(FakeSSH(routes=routes))
        assert 'трафик идёт через NAT' not in out
        assert 'NAT в пути нет' in out
        assert 'назначен интерфейсу: eth0' in out

    def test_unreadable_addr_list_says_unchecked(self):
        routes = self.BASE + [('ip -o addr',
                               ('', 'bash: ip: command not found', 127))]
        out = metrics_mod.network_report(FakeSSH(routes=routes))
        assert 'Привязка 203.0.113.9 к интерфейсу не проверена' in out


# ==================== ТЕСТ СКОРОСТИ (1.32.31) ====================
class TestParseDdSpeed:
    def test_si_and_iec_units_normalize_to_megabytes(self):
        # хвост GNU dd: '... copied, 1.05 s, 256 MB/s' (SI) и тот же замер в
        # MiB/s: разные единицы обязаны приехать одним MB/s-числом.
        mb, note = metrics_mod.parse_dd_speed(
            '134217728 bytes (134 MB, 128 MiB) copied, 0.5 s, 268 MB/s',
            '', 0)
        assert mb is not None and abs(mb - 268) < 1 and note is None
        mb2, _ = metrics_mod.parse_dd_speed(
            '134217728 bytes (128 MiB) copied, 0.25 s, 512 MiB/s', '', 0)
        assert mb2 is not None and mb2 > 512  # MiB шире MB — пересчёт обязателен

    def test_nonzero_rc_is_not_zero_speed(self):
        mb, note = metrics_mod.parse_dd_speed(
            'dd: failed to truncate: File too large', '', 1)
        assert mb is None and 'rc=1' in note

    def test_rc_zero_without_speed_line_is_not_measured(self):
        # rc=0, но строки скорости нет (обрыв, чужой dd): ноль выдумывать
        # нельзя — это «не измерено».
        mb, note = metrics_mod.parse_dd_speed('128+0 records out', '', 0)
        assert mb is None and note

    def test_cancel_mid_write_maps_to_negative_rc(self):
        mb, note = metrics_mod.parse_dd_speed('', '', -1)
        assert mb is None and 'rc=-1' in note


class TestDiskSpeedTest:
    DD_OK = ('134217728 bytes (134 MB, 128 MiB) copied, 0.4 s, 335 MB/s')

    def test_happy_path_writes_measures_and_wipes(self):
        store = {}
        c = FakeSSH(routes=[('conv=fsync', (self.DD_OK, '', 0)),
                            ('iflag=direct', (self.DD_OK, '', 0))])
        out = metrics_mod.disk_speed_test(c)
        assert '335' in out and 'Скорость записи' in out
        # файл убран каналом rm с проверкой факта (rm шёл, [ -e ] чист)
        assert c.count('rm -f ' + metrics_mod.SPEED_TMP_BASE) >= 2

    def test_leftover_from_previous_run_blocks_write(self):
        # съём остатков оставил файлы — запускать dd по чужому пути нельзя:
        # замер отменён ДО записи.
        c = FakeSSH(routes=[('ls -1 ' + metrics_mod.SPEED_TMP_BASE,
                             '/tmp/.techsupp_speed.deadbeefcafe.bin')])
        out = metrics_mod.disk_speed_test(c)
        assert 'тест отменён' in out
        assert c.find('dd if=') is None

    def test_scratch_path_is_not_predictable_between_runs(self):
        # Фиксированное имя — гонка с широким окном: между съёмом остатка и dd
        # лежит отдельный SSH-запрос, а dd рутом льёт 128 МБ нулей; symlink,
        # посаженный в это окно, обнулил бы любой файл системы.
        first = metrics_mod.speed_tmp_path()
        second = metrics_mod.speed_tmp_path()
        assert first != second
        assert first.startswith(metrics_mod.SPEED_TMP_BASE)
        assert metrics_mod.dd_write_cmd(first).startswith('timeout ')
        assert metrics_mod.dd_read_cmd(first).startswith('timeout ')

    def test_absent_dd_is_not_zero(self):
        c = FakeSSH(routes=[('dd ', ('', 'bash: dd: command not found', 127))])
        out = metrics_mod.disk_speed_test(c)
        assert 'не измерена' in out and 'rc=127' in out
        assert 'MB/s' not in out

    def test_unreadable_speed_line_is_reported_not_fabricated(self):
        c = FakeSSH(routes=[('conv=fsync', ('no stats here', '', 0)),
                            ('iflag=direct', ('no stats here', '', 0))])
        out = metrics_mod.disk_speed_test(c)
        assert 'не измерена' in out and 'MB/s' not in out


class TestParsePingLatency:
    IPUTILS = ('4 packets transmitted, 4 received, 0% packet loss\n'
               'rtt min/avg/max/mdev = 9.1/12.5/18.2/3.3 ms')

    def test_avg_parsed_from_utils_line(self):
        ms, note = metrics_mod.parse_ping_latency(self.IPUTILS, '', 0)
        assert ms == 12.5 and note is None

    def test_roundtrip_prefix_variant(self):
        # старые ping пишут 'round-trip min/avg/max' — разбор по '=', не по слову
        ms, _ = metrics_mod.parse_ping_latency(
            'round-trip min/avg/max = 1/2.5/9 ms', '', 0)
        assert ms == 2.5

    def test_total_loss_is_not_latency(self):
        ms, note = metrics_mod.parse_ping_latency(
            '4 packets transmitted, 0 received, 100% packet loss', '', 1)
        assert ms is None and '100' in note

    def test_absent_ping_is_unchecked(self):
        ms, note = metrics_mod.parse_ping_latency('', 'bash: ping: not found',
                                                  127)
        assert ms is None and 'не найден' in note


class TestParseDownloadSpeed:
    def test_curl_number_is_bytes_per_second(self):
        mb, note = metrics_mod.parse_download_speed('12500000.0', '', 0, 'curl')
        assert mb is not None and abs(mb - 12.5) < 0.01 and note is None

    def test_curl_garbage_is_not_measured(self):
        mb, note = metrics_mod.parse_download_speed('', '', 0, 'curl')
        assert mb is None and note

    def test_timeout_rc_is_failure_with_reason(self):
        mb, note = metrics_mod.parse_download_speed(
            '', 'curl: (28) Operation timed out', 28, 'curl')
        assert mb is None and 'rc=28' in note

    def test_wget_progress_units(self):
        mb, note = metrics_mod.parse_download_speed(
            '2026-10-11 12:00:00 (10.5 MB/s) - saved [50000000]', '', 0,
            'wget')
        assert mb is not None and abs(mb - 10.5) < 0.01


class TestNetworkSpeedTest:
    PING_OK = ('4 packets transmitted, 4 received, 0% packet loss\n'
               'rtt min/avg/max/mdev = 9.1/12.5/18.2/3.3 ms')

    def test_happy_reports_latency_and_mbit(self):
        c = FakeSSH(routes=[('ping -c 4', (self.PING_OK, '', 0)),
                            ('curl ', ('25000000.0', '', 0))])
        out = metrics_mod.network_speed_test(c)
        assert '12.5 мс' in out
        # 25 MB/s = 200 Мбит/с — человек мыслит битами
        assert '200' in out and 'Мбит/с' in out

    def test_curl_absent_falls_back_to_wget(self):
        c = FakeSSH(routes=[
            ('ping -c 4', (self.PING_OK, '', 0)),
            ('LC_ALL=C curl', ('', 'bash: curl: command not found', 127)),
            ('wget ', ('downloaded in 4s (10.0 MB/s)', '', 0)),
        ])
        out = metrics_mod.network_speed_test(c)
        assert '10.0 MB/s' in out

    def test_both_absent_is_honestly_unmeasured(self):
        c = FakeSSH(routes=[
            ('ping -c 4', ('', 'bash: ping: command not found', 127)),
            ('LC_ALL=C curl', ('', 'bash: curl: command not found', 127)),
            ('wget ', ('', 'bash: wget: command not found', 127)),
        ])
        out = metrics_mod.network_speed_test(c)
        assert 'не измерен' in out and 'Задержка' in out
        assert 'Мбит' not in out and 'мс' not in out

    def test_ping_block_does_not_gag_bandwidth(self):
        # ICMP могут фильтровать: задержка «не измерена», канал — измеряется.
        c = FakeSSH(routes=[
            ('ping -c 4', ('2 packets transmitted, 0 received, 100% packet '
                           'loss', '', 1)),
            ('curl ', ('8000000.0', '', 0)),
        ])
        out = metrics_mod.network_speed_test(c)
        assert '⚠️ Задержка' in out
        assert '64' in out and 'Мбит/с' in out


# ============ аудит незакоммиченного среза 1.32.30/1.32.31: таймауты, честность ============
# Каждый класс ниже закрывает конкретный дефект ревю; формулировки
# «не проверено/не измерено» здесь — не стилистика, а грани, на которых
# отчёт прежде врал.


@pytest.mark.parametrize('name,cmd', metrics_mod.EXTERNAL_IP_SOURCES)
class TestExternalIpSourcesAreBounded:
    """Каждая проба внешнего IP ограничена ДВУМЯ слоями таймаута.

    ServerChecker._exec читает канал до EOF (stream.read без дедлайна),
    поэтому зависший ifconfig.me вешал рабочий поток GUI до «Стоп»; конвенция
    проекта — обёртка `timeout N` (discovery.py, webcheck.py). Родной флаг
    утилиты обязан быть рядом: убитый `timeout` процесс причину не печатает,
    а собственной таймаут утилиты печатает (curl rc=28 и т. п.).
    """

    def test_wrapper_timeout_present(self, name, cmd):
        assert cmd.startswith('timeout '), cmd

    def test_native_timeout_flag_present(self, name, cmd):
        if name == 'curl':
            assert '--max-time' in cmd, cmd
        elif name == 'wget':
            # Короткие флаги: длинных --timeout/--tries в BusyBox wget нет, а
            # мир «curl нет» — это минимальные образы именно с BusyBox.
            assert ' -T ' in cmd and ' -t 1 ' in cmd, cmd
            assert '--timeout' not in cmd and '--tries' not in cmd, cmd
        elif name == 'dig':
            assert '+time=' in cmd and '+tries=' in cmd, cmd


class TestSpeedProbesAreBounded:
    def test_ping_and_dd_wrapped_and_locale_pinned(self):
        # dd сам себя ограничить не умеет; ping без LC_ALL=C в локализованной
        # системе печатает «packet loss» переведённым и дроби с запятой —
        # разбор бы молчал, а отчёт назвал бы это «RTT-строки не было».
        assert metrics_mod.dd_write_cmd('/tmp/x.bin').startswith('timeout ')
        assert metrics_mod.dd_read_cmd('/tmp/x.bin').startswith('timeout ')
        assert metrics_mod.PING_CMD.startswith('timeout ')
        assert 'LC_ALL=C ping' in metrics_mod.PING_CMD
        assert '-c 4' in metrics_mod.PING_CMD

    def test_download_commands_fail_fast_and_honest(self):
        curl_cmd = metrics_mod.NET_DOWNLOAD_SOURCES[0][1]
        wget_cmd = metrics_mod.NET_DOWNLOAD_SOURCES[1][1]
        for cmd in (curl_cmd, wget_cmd):
            assert cmd.startswith('timeout '), cmd
        assert '--max-time 30' in curl_cmd
        # -f: 403/5xx обязан стать rc!=0, иначе скорость бан-страницы
        # выезжает в отчёт как скорость канала; -L: редирект — тоже канал.
        assert '-sSfL' in curl_cmd, curl_cmd
        assert ' -T ' in wget_cmd and ' -t 1' in wget_cmd, wget_cmd


class TestTimeoutRcReadsAsTimeoutNotAsNoise:
    def test_external_ip_probe(self):
        state, addr, why = metrics_mod.parse_external_ip_probe(
            '', '', 124)
        assert state == 'failed'
        assert 'таймаут' in why and 'rc=124' in why

    def test_wrapper_absence_is_not_blamed_on_the_tool(self):
        # rc=127 принадлежит отсутствующему `timeout`, а curl на месте:
        # solitary «curl не найдена» отправил бы оператора ставить curl.
        curl_cmd = metrics_mod.EXTERNAL_IP_SOURCES[0][1]
        c = FakeSSH(routes=[(curl_cmd, ('', 'bash: timeout: command not found',
                                        127))])
        probe = metrics_mod.probe_external_ip(c)
        assert any('curl не найдена' in n and 'timeout: command not found' in n
                   for n in probe['notes']), probe['notes']

    def test_dd_timeout(self):
        mb, note = metrics_mod.parse_dd_speed('', '', 124)
        assert mb is None and 'таймаут' in note.lower() and '124' in note

    def test_ping_timeout(self):
        ms, note = metrics_mod.parse_ping_latency('', '', 124)
        assert ms is None and 'таймаут' in note.lower()

    def test_download_timeout(self):
        mb, note = metrics_mod.parse_download_speed('', '', 124, 'curl')
        assert mb is None and 'таймаут' in note.lower()


class TestParseRouteGet:
    def test_src_and_dev_from_raw_line(self):
        src, dev = metrics_mod.parse_route_get(
            '1.1.1.1 via 10.0.0.1 dev eth0 src 10.0.0.5 uid 0\n')
        assert src == '10.0.0.5' and dev == 'eth0'

    def test_token_after_src_must_be_an_address(self):
        # Вывод чужой машины — данные: «src» может вести что угодно, и в
        # конвейере grep|cut эта проверка терялась вместе с причиной
        # (2>/dev/null глушил stderr, а grep -P — GNU-расширение).
        src, dev = metrics_mod.parse_route_get('weird output src not-an-ip')
        assert src == '' and dev == ''

    def test_empty_output(self):
        assert metrics_mod.parse_route_get('') == ('', '')


class TestNetworkReportRouteSourceHonesty:
    BASE_TAIL = [('ip r', 'default via 10.0.0.1 dev eth0\n'),
                 ('ip a', '2: eth0: <B>\n'),
                 ('ifconfig.me', '203.0.113.9\n')]

    def test_failure_reason_reaches_the_report(self):
        # Прежний 2>/dev/null глушил RTNETLINK целиком, и отчёт просто молча
        # терял строку источника.
        routes = [('route get', ('', 'RTNETLINK answers: Network is '
                                 'unreachable', 2))] + self.BASE_TAIL
        out = metrics_mod.network_report(FakeSSH(routes=routes))
        assert 'IP-адрес источника не определён' in out
        assert 'Network is unreachable' in out

    def test_no_gateway_route_does_not_print_none(self):
        # «default dev eth0 scope link» шлюза не имеет; прежний разбор печатал
        # «(интерфейс None)», а dev есть в самом выводе ip route get.
        routes = [('route get', '1.1.1.1 dev eth0 src 10.0.0.5 uid 0\n'),
                  ('ip r', 'default dev eth0 scope link\n'),
                  ('ip a', '2: eth0: <B>\n'),
                  ('ifconfig.me', '203.0.113.9\n')]
        out = metrics_mod.network_report(FakeSSH(routes=routes))
        assert ('IP-адрес источника для исходящего трафика: 10.0.0.5 '
                '(интерфейс eth0)') in out
        assert 'None' not in out

    def test_v6_src_used_when_v4_route_missing(self):
        routes = [('route get', [
            ('', 'RTNETLINK answers: Network is unreachable', 2),
            ('2001:4860:4860::8888 from :: dev eth0 '
             'src 2001:db8::5 metric 1024\n', '', 0)])] + self.BASE_TAIL
        out = metrics_mod.network_report(FakeSSH(routes=routes))
        assert 'IP-адрес источника для исходящего трафика: 2001:db8::5' in out
        assert 'не определён' not in out

    def test_public_src_differs_no_private_lie(self):
        # Публичный источник, не совпавший с ответом сервиса: прежний текст
        # называл ЛЮБОЙ src «приватным IP» и утверждал NAT.
        routes = [('route get', '1.1.1.1 via 198.51.100.1 dev eth0 '
                                'src 198.51.100.7\n')] + self.BASE_TAIL
        out = metrics_mod.network_report(FakeSSH(routes=routes))
        assert 'приватный IP 198.51.100.7' not in out
        assert 'публичный, но отличается' in out

    def test_private_answer_is_flagged_as_not_public(self):
        # ifconfig.me, отвечающий 10.x: split-horizon DNS или прозрачный
        # прокси. Печатать это как «плавающий IP» без предупреждения —
        # обещать адрес, которого в публичном интернете нет.
        routes = [('route get', '1.1.1.1 dev eth0 src 10.0.0.5\n'),
                  ('ip r', 'default dev eth0 scope link\n'),
                  ('ip a', '2: eth0: <B>\n'),
                  ('curl', ('10.0.0.5\n', '', 0)),
                  ('ip -o addr', '2: eth0    inet 10.0.0.5/24 scope '
                                 'global eth0\n')]
        out = metrics_mod.network_report(FakeSSH(routes=routes))
        assert 'приватный адрес, а не публичный' in out


class TestIfconfigFallback:
    MODERN = ('eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500\n'
              '        inet 203.0.113.9  netmask 255.255.255.255  '
              'broadcast 0.0.0.0\n'
              '        inet6 fe80::216:3eff:fe11:2233  prefixlen 64  '
              'scopeid 0x20<link>\n'
              'eth0:0  flags=4163<UP,BROADCAST>  mtu 1500\n'
              '        inet 198.51.100.7  netmask 255.255.255.255\n')
    OLD = ('eth0      Link encap:Ethernet  HWaddr 52:54:00:11:22:33\n'
           '          inet addr:10.0.0.5  Bcast:10.0.0.255  '
           'Mask:255.255.255.0\n'
           '          inet6 addr: fe80::216:3eff:fe11:2233/64 Scope:Link\n'
           'lo        Link encap:Local Loopback\n'
           '          inet addr:127.0.0.1  Mask:255.0.0.0\n')

    def test_modern_net_tools_format(self):
        m = metrics_mod.parse_ifconfig_addresses(self.MODERN)
        assert m['203.0.113.9'] == [('eth0', '')]
        assert m['fe80::216:3eff:fe11:2233'] == [('eth0', '')]
        # Алиас eth0:0 записан на родительский интерфейс — так же делает
        # разбор `ip -o addr`, где алиас есть secondary-запись того же eth0.
        assert m['198.51.100.7'] == [('eth0', '')]

    def test_old_net_tools_format(self):
        m = metrics_mod.parse_ifconfig_addresses(self.OLD)
        assert m['10.0.0.5'] == [('eth0', '')]
        assert m['127.0.0.1'] == [('lo', '')]
        assert m['fe80::216:3eff:fe11:2233'] == [('eth0', '')]

    def test_absent_ip_falls_back_to_ifconfig(self):
        # На старых и минимальных машинах `ip` нет, а ifconfig есть — и там
        # честный ответ доступен, а не «не проверено».
        c = FakeSSH(routes=[('ip -o addr', ('', 'bash: ip: command not found',
                                            127)),
                            ('ifconfig -a', self.MODERN)])
        note = metrics_mod.interface_bind_note(c, '203.0.113.9')
        assert 'назначен интерфейсу: eth0' in note

    def test_both_tools_absent_is_still_unchecked(self):
        c = FakeSSH(routes=[('ip -o addr', ('', 'bash: ip: command not found',
                                            127)),
                            ('ifconfig -a', ('', 'bash: ifconfig: command '
                                             'not found', 127))])
        note = metrics_mod.interface_bind_note(c, '203.0.113.9')
        assert 'не проверена' in note
        assert 'ifconfig' in note
        assert 'provider NAT' not in note


class TestDfFreeParse:
    OK = ('Filesystem 1024-blocks    Used Available Capacity Mounted on\n'
          '/dev/vda1     41922560 20123456  19684352  51% /\n')

    def test_free_mb_from_posix_columns(self):
        mb = metrics_mod.parse_df_free_mb(self.OK, 0)
        assert mb == 19684352 // 1024

    def test_garbage_and_failure_are_none(self):
        assert metrics_mod.parse_df_free_mb('', 0) is None
        assert metrics_mod.parse_df_free_mb(self.OK, 1) is None
        assert metrics_mod.parse_df_free_mb('Filesystem Inodes\n', 0) is None


class TestDiskSpeedRespectsFreeSpace:
    DD_OK = ('134217728 bytes (134 MB, 128 MiB) copied, 0.4 s, 335 MB/s')
    RM_ROUTES = [('ls -1 ' + metrics_mod.SPEED_TMP_BASE, '')]

    def test_full_tmp_aborts_before_write(self):
        # «забитый диск» прежний код встречал минутой гонки dd до ENOSPC;
        # честный ответ — отменить ДО записи и назвать числа.
        routes = self.RM_ROUTES + [
            ('df -k', ('Filesystem 1024-blocks Used Available Capacity '
                       'Mounted on\ntmpfs 1048576 921600 126976 88% '
                       '/tmp\n'))]
        c = FakeSSH(routes=routes)
        out = metrics_mod.disk_speed_test(c)
        assert 'тест отменён ДО записи' in out
        assert '124 МБ' in out
        assert c.find('dd if=') is None

    def test_enough_space_runs_the_test(self):
        routes = self.RM_ROUTES + [
            ('df -k', 'Filesystem 1024-blocks Used Available Capacity '
                     'Mounted on\ntmpfs 10485760 1024 10484736 1% '
                     '/tmp\n'),
            ('conv=fsync', (self.DD_OK, '', 0))]
        out = metrics_mod.disk_speed_test(FakeSSH(routes=routes))
        assert '335' in out

    def test_silent_df_does_not_forbid_the_test(self):
        # Отказ препроверки не даёт права отменять: пусть честно падает dd.
        c = FakeSSH(routes=self.RM_ROUTES + [('conv=fsync',
                                              (self.DD_OK, '', 0))])
        out = metrics_mod.disk_speed_test(c)
        assert '335' in out and c.count('df -k') == 1


class TestZeroSpeedIsNotAResult:
    def test_dd_zero(self):
        mb, note = metrics_mod.parse_dd_speed(
            '0 bytes copied, 0.0 s, 0.0 B/s', '', 0)
        assert mb is None and 'нулев' in note

    def test_curl_zero(self):
        mb, note = metrics_mod.parse_download_speed('0.000000', '', 0, 'curl')
        assert mb is None and 'нулев' in note

    def test_network_speed_never_prints_zero(self):
        c = FakeSSH(routes=[
            ('ping -c 4', (TestNetworkSpeedTest.PING_OK, '', 0)),
            ('curl ', ('0.000000', '', 0)),
            ('wget ', ('', 'bash: wget: command not found', 127))])
        out = metrics_mod.network_speed_test(c)
        assert 'Входящий канал не измерен' in out
        assert '0.0 MB/s' not in out


class TestCurlCutAtMaxTimeIsALowerBound:
    def test_parse(self):
        mb, note = metrics_mod.parse_download_speed(
            '7500000', 'curl: (28) Operation timed out after 30000 '
            'milliseconds', 28, 'curl')
        assert mb is not None and abs(mb - 7.5) < 0.01
        assert 'нижняя граница' in note

    def test_report_marks_it(self):
        c = FakeSSH(routes=[
            ('ping -c 4', (TestNetworkSpeedTest.PING_OK, '', 0)),
            ('curl ', ('7500000', 'curl: (28) Operation timed out', 28))])
        out = metrics_mod.network_speed_test(c)
        assert '7.5 MB/s' in out and 'нижняя граница' in out


class TestPingHonestLossAndLocale:
    def test_total_loss_reason_has_single_percent(self):
        # Прежний литерал 'потеряно 100%% пакетов' не проходил через
        # оператор % и печатал двойной процент прямо в отчёт.
        ms, note = metrics_mod.parse_ping_latency(
            'PING 1.1.1.1 (1.1.1.1) 56(84) bytes of data.\n'
            '4 packets transmitted, 0 received, 100% packet loss', '', 1)
        assert ms is None
        assert '100% пакетов' in note and '%%' not in note
        # Причина — строка потерь, а не безобидная шапка «PING ... bytes».
        assert 'bytes of data' not in note

    def test_total_loss_at_zero_rc_is_loss_not_missing_rtt(self):
        ms, note = metrics_mod.parse_ping_latency(
            '4 packets transmitted, 0 received, 100% packet loss', '', 0)
        assert ms is None and '100%' in note

    def test_wget_uppercase_kb_unit(self):
        mb, _ = metrics_mod.parse_download_speed('64 KB/s', '', 0, 'wget')
        assert mb is not None and abs(mb - 0.064) < 1e-9


class TestSpeedCommandsAreExecutable:
    """P0 1.33.x: `timeout N LC_ALL=C <cmd>` НЕИСПОЛНЯЕМА: shell разбирает
    присваивание только перед командным словом, а первое слово здесь timeout
    — он берёт «LC_ALL=C» как argv[0] и выходит rc=126/127 (живьём, coreutils
    9.11). FakeSSH матчит подстроки и shell не исполняет — поэтому контрактом
    служит форма, но форма ИСПОЛНЯЕМОЙ команды (фиксится одной строкой —
    тест не даёт форме уехать обратно)."""

    def test_env_prefix_before_every_speed_probe(self):
        import re as _re
        for cmd in (metrics_mod.dd_write_cmd('/tmp/x.bin'),
                    metrics_mod.dd_read_cmd('/tmp/x.bin'),
                    metrics_mod.PING_CMD,
                    metrics_mod.NET_DOWNLOAD_SOURCES[0][1],
                    metrics_mod.NET_DOWNLOAD_SOURCES[1][1]):
            assert _re.match(r'timeout \d+ env LC_ALL=C ', cmd), cmd

    def test_df_free_uses_posix_single_line(self):
        # Без -P длинное имя LVM-устройства переносит поля на вторую строку,
        # парсер читает шапку и препровервка места молча мертва.
        assert 'df -k -P' in metrics_mod.DF_FREE_CMD


class TestParseFstype:
    def test_stat_answer_wins(self):
        assert metrics_mod.parse_fstype('ext4\n', 0, '', 0) == 'ext4'

    def test_df_fallback_skips_header(self):
        out = ('Filesystem     Type 1K-blocks    Used Available Use% '
               'Mounted on\n/dev/mapper/vg--verylong-lv ext4 10485760 '
               '1048576 9000000 11% /tmp\n')
        assert metrics_mod.parse_fstype('', 127, out, 0) == 'ext4'

    def test_silence_is_unknown_not_a_guess(self):
        assert metrics_mod.parse_fstype('', 0, '', 0) == ''
        assert metrics_mod.parse_fstype('', 127, '', 1) == ''


class TestDiskSpeedTmpfs:
    DD_OK = ('134217728 bytes (134 MB, 128 MiB) copied, 0.4 s, 335 MB/s')

    def test_tmpfs_warns_and_disk_verdict_not_printed(self):
        # /tmp на systemd — RAM: dd+fsync мерит память, а вердикт «NVMe —
        # отлично» врал бы в десятки раз.
        c = FakeSSH(routes=[('conv=fsync', (self.DD_OK, '', 0)),
                            ('stat -f -c %T', 'tmpfs\n')])
        out = metrics_mod.disk_speed_test(c)
        assert 'оперативной памяти' in out
        assert 'NVMe' not in out and 'не интерпретируется' in out

    def test_real_disk_keeps_verdict(self):
        c = FakeSSH(routes=[('conv=fsync', (self.DD_OK, '', 0)),
                            ('stat -f -c %T', 'ext4\n')])
        out = metrics_mod.disk_speed_test(c)
        assert 'NVMe/SSD — отлично' in out
        assert 'оперативной памяти' not in out


class TestExternalIpHonesty:
    ROUTES_IP = ('1: lo: <LOOPBACK>\n    inet 127.0.0.1/8 scope host lo\n'
                 '2: eth0: <BROADCAST>\n    inet 10.0.0.5/24 scope global eth0\n')
    ROUTES_R = ('default via 10.0.0.1 dev eth0 proto dhcp metric 100\n')

    def _base(self, extra):
        return [('route get', '1.1.1.1 via 10.0.0.1 dev eth0 src 10.0.0.5\n'),
                ('ip r', self.ROUTES_R), ('ip a', self.ROUTES_IP)] + extra

    def test_all_absent_prints_wrapper_reason(self):
        # Без coreutils timeout все три rc=127 принадлежат ОБОЛОЧКЕ: голое
        # «установите curl/wget/dig» отправило бы ставить установленное.
        out = metrics_mod.network_report(FakeSSH(routes=self._base([
            ('curl', ('', 'sh: timeout: command not found', 127)),
            ('wget', ('', 'sh: timeout: command not found', 127)),
            ('dig', ('', 'sh: timeout: command not found', 127))])))
        assert 'timeout: command not found' in out

    def test_cross_family_pair_is_not_a_nat_arrow(self):
        # Dual-stack: NAT по v4 + публичный v6 — curl ушёл в v6, src остался
        # v4; стрелка «приватный 10.x -> плавающий 2001:...» фабриковала бы
        # NAT, которого в этом стеке нет.
        out = metrics_mod.network_report(FakeSSH(routes=self._base([
            ('ifconfig.me', '2001:db8::42\n')])))
        assert 'разные адресные семьи' in out
        assert 'трафик идёт через NAT' not in out
