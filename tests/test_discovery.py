"""Тесты discovery.py: инвентарь сайтов, почты и DNS-зон (без реального SSH).

Два слоя, как в остальных модулях:

1. Чистые парсеры (mgrctl text, mogwai-таблицы, nginx/apache vhost'ы, карты
   postfix, dovecot passwd, main.cf, zone-файлы) проверяются напрямую — они и
   есть вся «тяжёлая» логика, и именно в них рождаются ложные домены, если
   регулярка слишком жадная.
2. Репорты идут через FakeSSH из support.py: маршрутизация по подстроке,
   первое совпадение выигрывает, поэтому специфичные иглы (mgrctl, mogwai)
   идут раньше общих ('ls -1', 'cat').

Отдельно держим две грабли, из-за которых модуль написан именно так:
- панельный источник (mgrctl/mogwai) приоритетнее разбора конфигов, и уже
  заполненное поле не перетирается;
- правая часть строки postfix-карты — адрес перенаправления, а не наш домен.
"""
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

import shlex

import discovery as dc
from support import FakeSSH


# ==================== ЧИСТЫЕ ПАРСЕРЫ ====================
class TestMgrctlText:
    def test_parses_key_value_pairs(self):
        out = dc.parse_mgrctl_text(
            'name=example.com elid=42 owner=user1 '
            'docroot=/var/www/user1/example.com/data/www/example.com')
        assert len(out) == 1
        assert out[0]['name'] == 'example.com'
        assert out[0]['elid'] == '42'
        assert out[0]['docroot'].endswith('/example.com')

    def test_quoted_value_with_spaces(self):
        out = dc.parse_mgrctl_text('name=x.tld note="two words" elid=1')
        assert out[0]['note'] == 'two words'

    def test_keys_lowercased_and_garbage_skipped(self):
        out = dc.parse_mgrctl_text('NAME=X.TLD\nwarning: no such option\n\n')
        assert out == [{'name': 'X.TLD'}]

    def test_empty(self):
        assert dc.parse_mgrctl_text('') == []
        assert dc.parse_mgrctl_text(None) == []


class TestMogwaiTable:
    SITES = ('ID\tSERVER_NAME\tALIASES\tOWNER\tMODE\tPHP_VERSION\tIPS\t'
             'DOCUMENT_ROOT\n'
             '1\texample.com\twww.example.com\tex_usr\tphp_fpm\t82\t'
             '1.2.3.4\t/var/www/ex_usr/data/www/example.com')

    def test_tab_separated(self):
        rows = dc.parse_mogwai_table(self.SITES)
        assert rows[0]['SERVER_NAME'] == 'example.com'
        assert rows[0]['OWNER'] == 'ex_usr'
        assert rows[0]['DOCUMENT_ROOT'] == '/var/www/ex_usr/data/www/example.com'

    def test_space_fallback_keeps_tail_in_last_column(self):
        # Копия вывода из терминала: табов нет, в последней колонке дата с
        # внутренним пробелом — хвост обязан остаться в одной колонке.
        text = ('ID\tNAME\tENABLED\tCREATE_AT\n'
                '1\tmail.tld\t1\t2024-01-04 15:46:02+03:00')
        rows = dc.parse_mogwai_table(text)
        assert rows[0]['CREATE_AT'] == '2024-01-04 15:46:02+03:00'

    def test_header_only_or_empty(self):
        assert dc.parse_mogwai_table('only header') == []
        assert dc.parse_mogwai_table('') == []


class TestNginxVhost:
    def test_multiline(self):
        parsed = dc.parse_nginx_vhost(
            'server {\n'
            '    listen 443 ssl;\n'
            '    server_name example.com www.example.com _ *.tpl;\n'
            '    root /var/www/site;\n'
            '    ssl_certificate /etc/ssl/a.pem;\n'
            '    ssl_certificate_key /etc/ssl/a.key;\n'
            '    location ~ \\.php$ { fastcgi_pass unix:/run/php/php8.2-fpm.sock; }\n'
            '}')
        assert parsed['domains'] == ['example.com', 'www.example.com']
        assert parsed['docroot'] == '/var/www/site'
        # ssl_certificate_key не должен подменять ssl_certificate
        assert parsed['ssl'] == '/etc/ssl/a.pem'
        assert parsed['php'] == 'php8.2'

    def test_single_line_block(self):
        parsed = dc.parse_nginx_vhost(
            'server { listen 80; server_name a.tld b.tld; root /srv/x; }')
        assert parsed['domains'] == ['a.tld', 'b.tld']
        assert parsed['docroot'] == '/srv/x'

    def test_fastcgi_param_server_name_is_not_a_domain(self):
        # Классическая ложная игла: fastcgi_param SERVER_NAME $server_name
        parsed = dc.parse_nginx_vhost(
            'server {\n server_name real.tld;\n'
            ' fastcgi_param SERVER_NAME $server_name;\n}')
        assert parsed['domains'] == ['real.tld']

    def test_php_version_shape(self):
        # Версия — только php<цифры>[.<цифры>]: «-fpm.example» в версию не попал
        parsed = dc.parse_nginx_vhost(
            'server { server_name x.tld;'
            ' fastcgi_pass unix:/run/php/php-fpm.example.sock; }')
        assert parsed['php'] == ''

    def test_empty(self):
        assert dc.parse_nginx_vhost('')['domains'] == []


class TestApacheVhost:
    def test_servername_alias_and_docroot(self):
        parsed = dc.parse_apache_vhost(
            '<VirtualHost *:80>\n'
            '  ServerName site.ru\n'
            '  ServerAlias www.site.ru *.skip\n'
            '  DocumentRoot "/var/www/html"\n'
            '</VirtualHost>')
        assert parsed['domains'] == ['site.ru', 'www.site.ru']
        assert parsed['docroot'] == '/var/www/html'


class TestPostfixMap:
    def test_left_side_is_ours_right_is_redirect(self):
        boxes, domains = dc.parse_postfix_map(
            '# comment\n'
            'info@example.com user@other.tld\n'
            '@example.com redirect@x.tld')
        # правая часть с обычным адресом — перенаправление, НЕ наш домен
        assert boxes == ['info@example.com']
        assert domains == ['example.com']

    def test_catchall_right_domain_is_ours(self):
        boxes, domains = dc.parse_postfix_map('@catchall.tld @forward.tld')
        assert boxes == []
        assert 'catchall.tld' in domains and 'forward.tld' in domains

    def test_comments_and_blanks(self):
        assert dc.parse_postfix_map('# only comments\n\n') == ([], [])


class TestDovecotUsers:
    def test_addresses(self):
        assert dc.parse_dovecot_users(
            'user@example.com:{SHA}xxx:y\n#comment\na@b.c:z\nbroken-line'
        ) == ['a@b.c', 'user@example.com']


class TestMainCfDomains:
    def test_variables_and_localhost_excluded(self):
        assert dc.parse_main_cf_domains(
            'mydestination = $myhostname, localhost, localhost.localdomain, '
            'site.ru\nvirtual_mailbox_domains = mail.tld') == ['mail.tld',
                                                               'site.ru']

    def test_square_bracket_relay_excluded(self):
        assert dc.parse_main_cf_domains('mydestination = [10.0.0.1]') == []


class TestZones:
    def test_domain_from_path(self):
        assert dc.zone_domain_from_path('/etc/bind/zones/db.example.com') == \
            'example.com'
        assert dc.zone_domain_from_path('/etc/nsd/zones/site.ru.zone') == \
            'site.ru'
        # без точки в имени — это не домен
        assert dc.zone_domain_from_path('/etc/nsd/zones/site.zone') is None
        assert dc.zone_domain_from_path('') is None

    def test_serial(self):
        assert dc.parse_zone_serial(
            'example.com. IN SOA ns.admin@example.com hostmaster.example.com. '
            '2026041001 7200') == '2026041001'
        assert dc.parse_zone_serial(';comment only\nnothing here') == ''


class TestSiteStatus:
    def test_parse(self):
        assert dc.parse_site_status('HTTP=200\nHTTPS=301\nSSL=ok') == \
            {'http': '200', 'https': '301', 'ssl': 'ok'}

    def test_empty_codes_become_000(self):
        assert dc.parse_site_status('') == {'http': '000', 'https': '000',
                                            'ssl': ''}
        assert dc.parse_site_status('HTTP=\nHTTPS=') == \
            {'http': '000', 'https': '000', 'ssl': ''}

    def test_generated_command_is_valid_shell(self):
        # Команды уходят на сервер как есть — разбор shlex обязан сходиться
        parts = shlex.split(dc.site_status_command('ex.com'))
        joined = ' '.join(parts)
        assert 'ex.com' in joined and ';' in joined
        assert '-m 8' in joined

    def test_icons(self):
        assert dc.http_status_icon('000', '200') == '✅'
        assert dc.http_status_icon('200', '000') == '🟡'
        assert dc.http_status_icon('000', '000') == '❌'
        assert dc.http_status_icon('500', '000') == '❌'


class TestHostsBlockers:
    def test_loopback_binding(self):
        text = ('127.0.0.1 example.com le.example\n'
                '::1 other.tld\n'
                '93.184.216.34 real.tld')
        assert dc.hosts_le_blockers(text, 'example.com') == \
            ['127.0.0.1 example.com le.example']
        assert dc.hosts_le_blockers(text, 'real.tld') == []
        assert dc.hosts_le_blockers(text, 'other.tld') == ['::1 other.tld']

    def test_comment_part_ignored(self):
        assert dc.hosts_le_blockers('127.0.0.1 # example.com', 'example.com') == []


# ==================== ЧИТАТЕЛИ ПАНЕЛЕЙ ====================
class TestPanelReaders:
    def test_isp_list_quotes_element(self):
        c = FakeSSH(routes=[('mgrctl -m ispmgr webdomain',
                             'name=a.tld elid=1\n')])
        assert dc.isp_webdomains(c)[0]['name'] == 'a.tld'
        assert c.find('mgrctl -m ispmgr') is not None

    def test_isp_list_empty_on_garbage(self):
        c = FakeSSH(default=('connection refused', '', 1))
        assert dc.isp_webdomains(c) == []

    def test_mogwai_failure_yields_empty(self):
        c = FakeSSH(default=('', '', 127))       # mogwai не установлен
        assert dc.fp_sites(c) == []
        assert dc.fp_mail_domains(c) == []
        assert dc.fp_mail_boxes(c) == []

    def test_mogwai_args_are_passed_verbatim(self):
        c = FakeSSH(routes=[('mogwai emails boxes list --domain=',
                             'ADDRESS\t\ninfo@x.tld\t\n')])
        assert dc.fp_mail_boxes(c, 'x.tld')[0]['ADDRESS'] == 'info@x.tld'
        assert c.find('--domain=') is not None


# ==================== ИНВЕНТАРЬ: САЙТЫ ====================
ISP_WEBDOMAIN = ('name=site1.ru elid=11 owner=biz docroot=/var/www/biz/'
                 'site1.ru/data/www/site1.ru php=isp-php82\n')
NGINX_VHOST = ('/etc/nginx/vhosts/biz/site2.ru.conf',
               'server { listen 443; server_name site2.ru www.site2.ru; '
               'root /var/www/biz/site2.ru/data/www/site2.ru; }')


class TestDiscoverSites:
    def test_ispmanager_panel_plus_vhosts(self):
        c = FakeSSH(routes=[
            ('mgrctl -m ispmgr webdomain', ISP_WEBDOMAIN),
            ('ls -1 /etc/nginx/vhosts', NGINX_VHOST[0] + '\n'),
            ('cat ' + NGINX_VHOST[0], NGINX_VHOST[1]),
        ])
        sites = dc.discover_sites(c, 'ispmanager')
        assert [s['domain'] for s in sites] == ['site1.ru', 'site2.ru',
                                                'www.site2.ru']
        first = sites[0]
        assert first['owner'] == 'biz' and first['php'] == 'isp-php82'
        assert first['vhost'] == 'mgrctl webdomain'
        assert sites[1]['vhost'] == NGINX_VHOST[0]

    def test_panel_field_not_overwritten_by_config(self):
        # В vhost docroot другой — панельный (первый) источник главнее
        c = FakeSSH(routes=[
            ('mgrctl -m ispmgr webdomain', ISP_WEBDOMAIN),
            ('ls -1 /etc/nginx/vhosts', NGINX_VHOST[0] + '\n'),
            ('cat ' + NGINX_VHOST[0],
             'server { server_name site1.ru; root /wrong/place; }'),
        ])
        sites = dc.discover_sites(c, 'ispmanager')
        assert len(sites) == 1
        assert sites[0]['docroot'].endswith('site1.ru')

    def test_fastpanel_mogwai(self):
        table = ('ID\tSERVER_NAME\tOWNER\tPHP_VERSION\tDOCUMENT_ROOT\n'
                 '7\tshop.tld\tsh_usr\t83\t/var/www/sh_usr/data/www/shop.tld')
        c = FakeSSH(routes=[('mogwai sites list', table)])
        sites = dc.discover_sites(c, 'fastpanel')
        assert sites[0]['domain'] == 'shop.tld'
        assert sites[0]['owner'] == 'sh_usr'
        assert sites[0]['vhost'] == 'mogwai sites'

    def test_wildcards_and_template_names_skipped(self):
        c = FakeSSH(routes=[
            ('ls -1 /etc/nginx/sites-enabled', '/etc/nginx/sites-enabled/x\n'),
            ('cat ', 'server { listen 80 default_server; server_name _ '
                     '*.tpl localhost no-dot; root /srv; }'),
        ])
        assert dc.discover_sites(c, 'none') == []

    def test_apache_vhosts_for_ispmanager(self):
        c = FakeSSH(routes=[
            ('ls -1 /etc/httpd/vhosts', '/etc/httpd/vhosts/biz/old.ru.conf\n'),
            ('cat /etc/httpd/vhosts',
             '<VirtualHost *:80>\n ServerName old.ru\n'
             ' DocumentRoot /var/www/old\n</VirtualHost>'),
        ])
        sites = dc.discover_sites(c, 'ispmanager')
        assert sites[0]['domain'] == 'old.ru'
        assert sites[0]['docroot'] == '/var/www/old'

    def test_limit_warning_entry_skipped(self):
        # find_files при переполнении добавляет строку «⚠️ …» — она не путь
        c = FakeSSH(routes=[('ls -1 /etc/nginx/sites-enabled',
                             '⚠️ (показаны первые 50 файлов)\n')])
        assert dc.discover_sites(c, 'none') == []

    def test_panel_autodetected_when_not_passed(self):
        c = FakeSSH(routes=[('test -f /usr/local/mgr5/bin/mgrctl', 'yes')])
        sites = dc.discover_sites(c)          # panel_type=None -> detect_panel
        assert sites == []
        assert c.find('test -f /usr/local/mgr5/bin/mgrctl') is not None


# ==================== ИНВЕНТАРЬ: ПОЧТА ====================
class TestDiscoverMail:
    def test_sources_merged(self):
        c = FakeSSH(routes=[
            ('mgrctl -m ispmgr maildomain', 'name=panel.tld elid=3\n'),
            ('cat /etc/postfix/virtual', 'info@map.tld user@else.tld\n'),
            ('cat /etc/dovecot/users', 'box@dovecot.tld:{SHA}x:y\n'),
            ('cat /etc/postfix/main.cf',
             'virtual_mailbox_domains = maincf.tld\n'),
        ])
        found = dc.discover_mail_domains(c, 'ispmanager')
        assert set(found) == {'panel.tld', 'map.tld', 'dovecot.tld',
                              'maincf.tld'}
        assert found['panel.tld'] == ['mgrctl maildomain']

    def test_fastpanel_sources(self):
        table = 'ID\tNAME\tENABLED\n1\tmail.tld\t1\n'
        c = FakeSSH(routes=[('mogwai emails domains list', table)])
        found = dc.discover_mail_domains(c, 'fastpanel')
        assert found['mail.tld'] == ['mogwai emails domains']

    def test_localhost_excluded(self):
        c = FakeSSH(routes=[('cat /etc/postfix/virtual',
                             'postmaster@localhost root\n')])
        assert dc.discover_mail_domains(c, 'none') == {}

    def test_boxes_dedup_and_domain_filter(self):
        c = FakeSSH(routes=[
            ('cat /etc/postfix/virtual',
             'info@x.tld dest@y.tld\nsales@x.tld user@y.tld\n'),
            ('cat /etc/dovecot/users', 'info@x.tld:{SHA}a:b\n'),
        ])
        all_boxes = dc.discover_mailboxes(c, 'none')
        addrs = [a for a, _ in all_boxes]
        # user@y.tld — ПРАВАЯ часть строки карты, адрес доставки на чужой
        # сервер: ящиком этого сервера он не является и в список не попадает
        assert addrs == ['info@x.tld', 'sales@x.tld']
        # дедуп: info@x.tld лежит и в карте, и в dovecot — источник первый
        assert dict(all_boxes)['info@x.tld'] == 'postfix virtual'
        only_x = dc.discover_mailboxes(c, 'none', domain='x.tld')
        assert [a for a, _ in only_x] == ['info@x.tld', 'sales@x.tld']

    def test_fastpanel_boxes_merged_first(self):
        c = FakeSSH(routes=[
            ('mogwai emails boxes list', 'ADDRESS\ninfo@x.tld\n'),
            ('cat /etc/postfix/virtual', 'info@x.tld dest@y.tld\n'),
        ])
        boxes = dc.discover_mailboxes(c, 'fastpanel')
        assert dict(boxes)['info@x.tld'] == 'mogwai emails boxes'


# ==================== ИНВЕНТАРЬ: DNS-ЗОНЫ ====================
class TestDiscoverZones:
    def test_panel_zone_plus_files(self):
        c = FakeSSH(routes=[
            ('mgrctl -m ispmgr dnszone',
             'name=panel.tld elid=5 filename=/var/named/zones/db.panel.tld\n'),
            ('ls -1 /var/named/zones/db',
             '/var/named/zones/db.panel.tld\n'),
            ('ls -1 /etc/bind/zones/db', '/etc/bind/zones/db.file.tld\n'),
            ('cat /var/named/zones/db.panel.tld',
             'panel.tld. SOA ns hostmaster@panel.tld. 2026010101 3600\n'),
            ('cat /etc/bind/zones/db.file.tld',
             'file.tld. SOA ns admin@file.tld. 2026020202 3600\n'),
        ])
        zones = dc.discover_dns_zones(c, 'ispmanager')
        assert [z['domain'] for z in zones] == ['file.tld', 'panel.tld']
        panel = zones[1]
        assert panel['source'] == 'mgrctl dnszone'
        assert panel['serial'] == '2026010101'
        assert zones[0]['serial'] == '2026020202'

    def test_no_zones_report_says_ns_elsewhere(self):
        out = dc.dns_zones_report(FakeSSH(), 'none')
        assert 'Зон не найдено' in out and 'NS' in out

    def test_zone_without_path_has_empty_serial(self):
        c = FakeSSH(routes=[('mgrctl -m ispmgr dnszone', 'name=x.tld elid=1\n')])
        zones = dc.discover_dns_zones(c, 'ispmanager')
        assert zones[0]['serial'] == ''


# ==================== ОТЧЁТЫ ====================
class TestSiteHealth:
    def test_empty_inventory(self):
        out = dc.site_health_report(FakeSSH(), 'none')
        assert 'Сайты не обнаружены' in out

    def test_lists_sites_and_status(self):
        c = FakeSSH(routes=[
            ('mgrctl -m ispmgr webdomain', ISP_WEBDOMAIN),
            ("printf 'HTTP=", 'HTTP=200\nHTTPS=301\nSSL=ok'),
        ])
        out = dc.site_health_report(c, 'ispmanager')
        assert 'Найдено сайтов: 1' in out
        assert 'site1.ru' in out and 'http=200' in out and 'https=301' in out
        assert 'SSL ok' in out

    def test_https_dead_warns_ssl(self):
        c = FakeSSH(routes=[
            ('mgrctl -m ispmgr webdomain', ISP_WEBDOMAIN),
            ("printf 'HTTP=", 'HTTP=000\nHTTPS=000\nSSL=bad'),
        ])
        out = dc.site_health_report(c, 'ispmanager')
        assert '❌' in out
        # SSL-пометка ставится только когда HTTPS вообще отвечает
        assert 'SSL<30д' not in out

    def test_health_check_is_capped(self):
        rows = ''.join(f'name=site{i}.tld elid={i} owner=u\n'
                       for i in range(30))
        c = FakeSSH(routes=[('mgrctl -m ispmgr webdomain', rows)])
        out = dc.site_health_report(c, 'ispmanager')
        assert 'доступность проверялась для первых 25 из 30' in out
        # ровно 25 внешних проб, а не 30
        assert c.count("printf 'HTTP=") == 25


class TestMailOverview:
    def test_domains_boxes_queue_services(self):
        # Службы спрашиваются ОДНОЙ командой services_status_cmd (в ней нет
        # подстроки 'systemctl is-active postfix' — имена идут через аргумент
        # shell-функции), поэтому игла — служебный маркер скрипта, а ответ —
        # весь вывод 'имя=статус' разом.
        c = FakeSSH(routes=[
            ('cat /etc/postfix/virtual', 'info@x.tld dest@y.tld\n'),
            ('mailq', '-- 12 Messages'),
            ('__svc_status', 'postfix=active\ndovecot=inactive\nrspamd=unknown'),
        ])
        out = dc.mail_overview_report(c, 'none')
        # x.tld — единственный наш домен: dest@y.tld стоит в правой части
        # (доставка), y.tld сервер не обслуживает
        assert 'Почтовых доменов: 1' in out
        assert 'info@x.tld' in out
        assert 'Очередь postfix: писем — 12' in out and '⚠️' in out
        assert 'postfix: active' in out and 'dovecot: inactive' in out
        # unknown (юнита нет) показывается, но не как «не активна»
        assert 'rspamd: unknown' in out
        # службы, про которые панель ничего не ответила, в отчёте не выдумываются
        assert 'exim4' not in out and 'opendkim' not in out

    def test_empty_queue_and_no_domains(self):
        c = FakeSSH(routes=[('mailq', 'Mail queue is empty')])
        out = dc.mail_overview_report(c, 'none')
        assert 'Почтовые домены не найдены' in out
        assert 'Очередь postfix: пуста' in out

    def test_mailq_unavailable(self):
        out = dc.mail_overview_report(FakeSSH(), 'none')
        assert 'mailq недоступен' in out


class TestInventoryAndDomain:
    def test_inventory_joins_three_parts(self):
        c = FakeSSH(routes=[('mailq', 'Mail queue is empty')])
        out = dc.hosting_inventory_report(c, 'none')
        assert '=== САЙТЫ И ИХ ДОСТУПНОСТЬ ===' in out
        assert '=== ПОЧТОВЫЙ СЕРВЕР: ИНВЕНТАРЬ ===' in out
        assert '=== DNS-ЗОНЫ НА СЕРВЕРЕ ===' in out

    def test_domain_detail_unknown_domain(self):
        out = dc.domain_detail_report(FakeSSH(), 'nope', 'none')
        assert 'Домен не задан корректно' in out

    def test_domain_detail_full_dossier(self):
        c = FakeSSH(routes=[
            ('mgrctl -m ispmgr webdomain', ISP_WEBDOMAIN),
            ("printf 'HTTP=", 'HTTP=301\nHTTPS=200\nSSL=ok'),
            # AAAA обязан стоять раньше 'dig +short A': первое совпадение по
            # подстроке выигрывает, иначе AAAA получил бы ответ A-запроса
            ('dig +short AAAA', ''),
            ('dig +short A', '93.184.216.34'),
            ('dig +short MX', '10 mail.site1.ru.'),
            ('cat /etc/postfix/virtual', 'info@site1.ru dest@other.tld\n'),
            ('cat /etc/hosts', '127.0.0.1 site1.ru\n'),
            ('/data/logs/access.log', '/var/www/biz/site1.ru/logs/access.log'),
        ])
        out = dc.domain_detail_report(c, 'Site1.RU', 'ispmanager')
        assert 'ДОСЬЕ ДОМЕНА site1.ru' in out          # регистр нормализован
        assert 'biz' in out
        assert 'https=200' in out
        assert 'A: 93.184.216.34' in out
        assert 'AAAA: — нет записей' in out
        assert 'MX: 10 mail.site1.ru.' in out
        assert 'info@site1.ru' in out
        assert 'привязан к loopback' in out

    def test_domain_detail_not_found_anywhere(self):
        out = dc.domain_detail_report(FakeSSH(), 'ghost.tld', 'none')
        assert 'Домен не найден ни в списке панели' in out
        assert 'не заявлен как почтовый' in out

    def test_detail_reports_logs_when_present(self):
        c = FakeSSH(routes=[
            ('mgrctl -m ispmgr webdomain', ISP_WEBDOMAIN),
            ('/data/logs/access.log', '/var/www/biz/site1.ru/logs/access.log'),
        ])
        out = dc.domain_detail_report(c, 'site1.ru', 'ispmanager')
        assert 'Лог доступа: /var/www/biz/site1.ru/logs/access.log' in out
