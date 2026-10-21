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
import subprocess

import pytest

import discovery as dc
from support import FakeSSH, FakeSftpClient


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
        assert dc.parse_site_status(
            'HTTP=200\nHTTPS=301\nSSL=ok\nCERT=87') == \
            {'http': '200', 'https': '301', 'ssl': 'ok', 'cert_days': 87}

    def test_parse_expired_certificate_is_negative(self):
        # Истёкший сертификат — отрицательное число дней: «истёк 3 дня назад»
        # и «осталось 5» по одному флагу SSL=bad не различить
        assert dc.parse_site_status(
            'HTTP=200\nHTTPS=200\nSSL=bad\nCERT=-3')['cert_days'] == -3

    def test_cert_none_is_not_a_number(self):
        # Команда печатает CERT=none, когда TLS-хендшейк не состоялся:
        # превращать это в 0 нельзя (0 означало бы «истекает сегодня»)
        assert dc.parse_site_status('SSL=none\nCERT=none')['cert_days'] is None

    def test_empty_codes_become_000(self):
        assert dc.parse_site_status('') == {'http': '000', 'https': '000',
                                            'ssl': '', 'cert_days': None}
        assert dc.parse_site_status('HTTP=\nHTTPS=') == \
            {'http': '000', 'https': '000', 'ssl': '', 'cert_days': None}

    def test_generated_command_is_valid_shell(self):
        # Команды уходят на сервер как есть — разбор shlex обязан сходиться
        parts = shlex.split(dc.site_status_command('ex.com'))
        joined = ' '.join(parts)
        assert 'ex.com' in joined and ';' in joined
        assert '-m 8' in joined
        # Один TLS-хендшейк на домен: -enddate читается раз, из него же и
        # признак ok/bad, и дни (второй s_client удваивал бы цену прогона)
        assert joined.count('openssl s_client') == 1
        assert 'CERT=' in joined

    def test_cert_days_parser(self):
        assert dc.parse_cert_days('CERT=87') == 87
        assert dc.parse_cert_days('CERT=-3') == -3
        assert dc.parse_cert_days('CERT=none') is None
        assert dc.parse_cert_days('garbage') is None
        assert dc.parse_cert_days('') is None
        assert dc.parse_cert_days(None) is None

    def test_cert_days_icons(self):
        assert dc.cert_days_icon(None) == '❓'     # сертификат не получен
        assert dc.cert_days_icon(-1) == '❌'        # истёк
        assert dc.cert_days_icon(0) == '⚠️'         # истечёт сегодня
        assert dc.cert_days_icon(29) == '⚠️'        # порог 30 дней
        assert dc.cert_days_icon(30) == '✅'

    def test_cert_days_label(self):
        assert 'ИСТЁК 3 дн.' in dc.cert_days_label(-3)
        assert 'осталось 87 дн.' in dc.cert_days_label(87)
        assert 'не получен' in dc.cert_days_label(None)

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
            ("printf 'HTTP=",
             'HTTP=200\nHTTPS=301\nSSL=ok\nCERT=87'),
        ])
        out = dc.site_health_report(c, 'ispmanager')
        assert 'Найдено сайтов: 1' in out
        assert 'site1.ru' in out and 'http=200' in out and 'https=301' in out
        # Точный остаток вместо прежнего бинарного «SSL ok»: LE живёт 90 дней,
        # оператору важно «87», а не «ok»
        assert '✅ SSL осталось 87 дн.' in out

    def test_expired_cert_shows_negative_days(self):
        c = FakeSSH(routes=[
            ('mgrctl -m ispmgr webdomain', ISP_WEBDOMAIN),
            ("printf 'HTTP=",
             'HTTP=200\nHTTPS=443\nSSL=bad\nCERT=-3'),
        ])
        out = dc.site_health_report(c, 'ispmanager')
        assert '❌ SSL ИСТЁК 3 дн. назад' in out

    def test_https_dead_reports_no_ssl_probe(self):
        c = FakeSSH(routes=[
            ('mgrctl -m ispmgr webdomain', ISP_WEBDOMAIN),
            ("printf 'HTTP=", 'HTTP=000\nHTTPS=000\nSSL=bad'),
        ])
        out = dc.site_health_report(c, 'ispmanager')
        assert '❌' in out
        # HTTPS молчит — SSL-пометки нет: сертификат чужого хоста (дефолтный
        # vhost) в строке домена выводить нельзя, оператор принял бы его за свой
        assert 'SSL' not in out

    def test_ssl_expiry_report_empty(self):
        out = dc.ssl_expiry_report(FakeSSH(), 'none')
        assert 'не на чём' in out

    def test_ssl_expiry_groups_and_sorts(self):
        # Ответы привязаны к домену иглой по «-servername домен»: маршрут по
        # подстроке не зависит от порядка обхода, а значит тест не зависит от
        # сортировки инвентаря (иначе порядок блоков зависел бы от случайного).
        # Кавычек в игле нет намеренно: q() = shlex.quote, а домен состоит из
        # безопасных символов — реальная команда уходит без кавычек.
        c = FakeSSH(routes=[
            ('mgrctl -m ispmgr webdomain',
             'name=expired.tld elid=1\nname=soon.tld elid=2\n'
             'name=ok.tld elid=3\nname=quiet.tld elid=4\n'),
            ('s_client -servername expired.tld',
             "HTTP=200\nHTTPS=443\nSSL=bad\nCERT=-5"),
            ('s_client -servername soon.tld',
             "HTTP=200\nHTTPS=200\nSSL=bad\nCERT=10"),
            ('s_client -servername ok.tld',
             "HTTP=200\nHTTPS=200\nSSL=ok\nCERT=200"),
            ('s_client -servername quiet.tld',
             "HTTP=200\nHTTPS=000\nSSL=none\nCERT=none"),
        ])
        out = dc.ssl_expiry_report(c, 'ispmanager')
        assert 'Истекло: 1, истекает < 30 дн.: 1' in out
        # Пробелы в именах доменов выравниваются, поэтому сравниваем позиции:
        # мертвые сертификаты обязаны быть выше живых — за ними и открывают.
        i_exp = out.index('СЕРТИФИКАТЫ ИСТЕКЛИ')
        i_warn = out.index('ИСТЕКАЮТ МЕНЕЕ ЧЕМ ЗА 30 ДНЕЙ')
        i_ok = out.index('В порядке')
        i_quiet = out.index('СЕРТИФИКАТ НЕ ПОЛУЧЕН')
        assert i_exp < i_warn < i_ok < i_quiet
        assert 'expired.tld' in out[i_exp:i_warn]
        assert 'soon.tld' in out[i_warn:i_ok]
        assert 'ok.tld' in out[i_ok:i_quiet]
        # У молчащего HTTPS отдельная причина — «https не отвечает», а не «истёк»
        assert 'https не отвечает' in out[i_quiet:]
        # Подсказка, где лечить, обязана быть, когда есть что лечить
        assert "Let's Encrypt" in out

    def test_ssl_expiry_healthy_has_no_scrolling(self):
        c = FakeSSH(routes=[
            ('mgrctl -m ispmgr webdomain', 'name=ok.tld elid=1\n'),
            ('s_client -servername ok.tld',
             "HTTP=200\nHTTPS=200\nSSL=ok\nCERT=87"),
        ])
        out = dc.ssl_expiry_report(c, 'ispmanager')
        assert 'Истекло: 0, истекает < 30 дн.: 0' in out
        assert 'СЕРТИФИКАТЫ ИСТЕКЛИ' not in out
        assert 'СЕРТИФИКАТ НЕ ПОЛУЧЕН' not in out

    def test_ssl_expiry_is_capped_too(self):
        rows = ''.join(f'name=site{i}.tld elid={i} owner=u\n'
                       for i in range(30))
        c = FakeSSH(routes=[('mgrctl -m ispmgr webdomain', rows)])
        out = dc.ssl_expiry_report(c, 'ispmanager')
        assert 'Проверено доменов: 25 из 30' in out
        assert c.count("s_client -servername") == 25

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


# ==================== ОПЕРАЦИИ С ЯЩИКАМИ: чистые функции ====================
class TestMailboxValidation:
    def test_address_is_normalized(self):
        # Панель хранит ящики строчными: 'Info@Site.RU' без нормализации создал
        # бы дубль, который ни списком, ни удалением не находится
        assert dc.parse_mailbox_address('  Info@Example.COM ') == \
            (('info', 'example.com'), None)

    def test_punycode_domain_accepted(self):
        # Кириллический домен оператор обязан дать punycode — проверка это
        # принимает и не пытается кодировать сам
        assert dc.parse_mailbox_address('a@xn--80ak6aa92e.com')[0] == \
            ('a', 'xn--80ak6aa92e.com')

    def test_simple_two_level_domain_ok(self):
        assert dc.parse_mailbox_address('a@b.c')[0] == ('a', 'b.c')

    @pytest.mark.parametrize('bad,fragment', [
        ('nodomain', 'полным адресом'),
        ('two@@ex.com', 'полным адресом'),
        ('bad name@ex.com', 'допустимы'),
        ('info@ex..com', 'не похож на домен'),
        ('info@-example.com', 'не похож на домен'),
        ('info@рф.рф', 'punycode'),
        ('', 'полным адресом'),
        (None, 'полным адресом'),
    ])
    def test_rejected_with_human_reason(self, bad, fragment):
        parsed, err = dc.parse_mailbox_address(bad)
        assert parsed is None
        assert fragment in err


class TestMailboxCommands:
    """Сборщики команд: синтаксис — из официальной документации панелей."""

    def test_isp_create_matches_kb_script(self):
        # KB ispmanager (массовое создание): email.edit domainname/name/plid/
        # aliases/sok=ok, БЕЗ elid — именно создание. Пароль — отдельным -e
        # (ISPsystem, «Mgrctl utility»), в argv его нет вовсе.
        cmd = dc.isp_mailbox_env_command(
            dc.isp_mailbox_create_args('info', 'example.com'))
        assert 'email.edit' in cmd and 'elid' not in cmd
        assert 'domainname=example.com' in cmd and 'name=info' in cmd
        assert 'plid=example.com' in cmd and "aliases=''" in cmd
        assert 'sok=ok' in cmd
        assert "-e 'passwd=$DIAG_MAILBOX_SECRET'" in cmd
        assert 'Sec ret1' not in cmd and 'passwd=Sec' not in cmd

    def test_isp_passwd_targets_by_full_address(self):
        # elid ящика — полный адрес (KB: email.responder elid=admin@domain.com)
        cmd = dc.isp_mailbox_env_command(
            dc.isp_mailbox_passwd_args('info@example.com'))
        assert 'email.edit' in cmd and 'elid=info@example.com' in cmd
        assert 'sok=ok' in cmd
        assert "-e 'confirm=$DIAG_MAILBOX_SECRET'" in cmd

    def test_isp_delete_uses_email_delete(self):
        cmd = dc.isp_mailbox_delete_command('info@example.com')
        assert 'email.delete' in cmd and 'elid=info@example.com' in cmd

    def test_fp_create_matches_kb(self):
        # KB FASTPANEL: mogwai emails boxes create --domain --login --password
        cmd = dc.fp_mailbox_create_command('info', 'example.com', 'pw 12345')
        assert 'mogwai emails boxes create' in cmd
        assert '--domain=example.com' in cmd and '--login=info' in cmd
        assert "--password='pw 12345'" in cmd

    def test_fp_delete_takes_numeric_id_only(self):
        assert dc.fp_mailbox_delete_command(7) == \
            'mogwai emails boxes delete -b 7 2>&1'
        # строка-цифра тоже проходит (из вывода boxes list приходят строки)
        assert '-b 12' in dc.fp_mailbox_delete_command('12')
        # мусор обязан упасть: 'delete -b <мусор>' хуже, чем исключение
        with pytest.raises((ValueError, TypeError)):
            dc.fp_mailbox_delete_command('7; rm -rf /')

    def test_env_file_keeps_tainted_password_as_one_value(self):
        """Заражённый пароль в env-файле обязан остаться ОДНИМ значением.

        Кривое экранирование здесь опаснее, чем в argv: файл источников
        (`.`) исполняется тем же bash, и неразрешённая кавычка превратила бы
        $(rm -rf /) в команду на сервере.
        """
        evil = "x'$(rm -rf /)`tick`\"dq\" && rm -rf /"
        content = dc.mailbox_secret_content(evil)
        assert content.startswith('export DIAG_MAILBOX_SECRET=')
        assert content.endswith('\n') and content.count('\n') == 1
        proc = subprocess.run(['bash', '-n', '-c', content],
                              capture_output=True, text=True)
        assert proc.returncode == 0, content
        parts = shlex.split(content.strip())
        assert len(parts) == 2 and parts[0] == 'export', parts
        assert parts[1].startswith('DIAG_MAILBOX_SECRET='), parts
        # значение дошло текстом, а не развернулось в команду
        assert '$(rm -rf /)' in parts[1]

    def test_all_commands_are_valid_shell_and_injection_safe(self):
        """Заражённое значение обязано остаться ОДНИМ параметром команды.

        Проверяем другое: каждый токен, куда попало значение, начинается с имени
        параметра. Кривая кавычка распала бы '$(rm -rf /)' на отдельные
        аргументы (rm, -rf) — вот это и есть настоящая инъекция.
        """
        evil = "x'$(rm -rf /)`tick`\"dq\""
        prefixes = ('--password=', 'elid=', 'name=', 'domainname=', 'plid=')
        for cmd in (dc.isp_mailbox_delete_command('a@ex.com; rm -rf /'),
                    dc.isp_mailbox_env_command(
                        dc.isp_mailbox_create_args('a; rm -rf /',
                                                   'ex.com; rm -rf /')),
                    dc.fp_mailbox_create_command('a', 'ex.com', evil)):
            parts = shlex.split(cmd)
            tainted = [p for p in parts if 'rm -rf' in p]
            assert tainted, cmd                       # значение дошло, а не исчезло
            for token in tainted:
                assert token.startswith(prefixes), (cmd, token)
            assert 'rm' not in parts and '-rf' not in parts, cmd
            proc = subprocess.run(['bash', '-n', '-c', cmd],
                                  capture_output=True, text=True)
            assert proc.returncode == 0, cmd

    def test_isp_password_reaches_panel_twice_by_design(self):
        # passwd + confirm — требование панели (форма создания ящика). Тест
        # держит это как договор: убрав confirm, получим невнятную ошибку API.
        # Обе ссылки указывают на одну переменную — секрет передаётся дважды.
        parts = shlex.split(dc.isp_mailbox_env_command(
            dc.isp_mailbox_create_args('a', 'ex.com')))
        assert parts.count('-e') == 2
        assert parts.count('passwd=$DIAG_MAILBOX_SECRET') == 1
        assert parts.count('confirm=$DIAG_MAILBOX_SECRET') == 1


# ============ ОПЕРАЦИИ С ЯЩИКАМИ: пред-проверки и маскирование ============
# Guard — единственное, что стоит между оператором и разрушающей командой
# панели. Проверяем его отдельно от исполнения: на FakeSSH видно и «панель
# ответила ошибкой», и «список не получен» — обе ветки обязаны отказывать.
ISP_MAIL_ENV = [
    ('mgrctl -m ispmgr maildomain', 'name=example.com elid=3\n'),
    ('mgrctl -m ispmgr email',
     'name=info@example.com domainname=example.com\n'),
]


class TestMailboxGuard:
    def test_create_ok_for_new_box_on_mail_domain(self):
        c = FakeSSH(routes=ISP_MAIL_ENV)
        assert dc.mailbox_guard(c, 'new@example.com', 'ispmanager',
                                'create') is None

    def test_address_is_normalized_before_check(self):
        # 'Info@EXAMPLE.com' — тот же ящик, что info@example.com: без
        # нормализации guard пропустил бы дубль, а панель молча поменяла бы
        # пароль существующего ящика
        c = FakeSSH(routes=ISP_MAIL_ENV)
        reason = dc.mailbox_guard(c, '  Info@EXAMPLE.COM ', 'ispmanager',
                                  'create')
        assert reason and 'уже существует' in reason

    def test_create_requires_mail_domain(self):
        c = FakeSSH(routes=ISP_MAIL_ENV)
        reason = dc.mailbox_guard(c, 'a@other.tld', 'ispmanager', 'create')
        assert 'не является почтовым доменом' in reason
        # известные домены показаны: оператору нужно знать, куда идти
        assert 'example.com' in reason

    def test_passwd_requires_existing_box(self):
        c = FakeSSH(routes=ISP_MAIL_ENV)
        assert dc.mailbox_guard(c, 'info@example.com', 'ispmanager',
                                'passwd') is None
        reason = dc.mailbox_guard(c, 'ghost@example.com', 'ispmanager',
                                  'delete')
        assert 'не найден' in reason

    def test_unknown_box_list_refuses_destructive_mode(self):
        # Список ящиков НЕ получен (mgrctl упал): «не нашёл» и «не знаю» —
        # разные вещи. Удалить по unverifiable-адресу дороже, чем не удалить.
        c = FakeSSH(routes=[('mgrctl -m ispmgr maildomain',
                             'name=example.com elid=3\n'),
                            ('mgrctl -m ispmgr email',
                             'ERROR: connection refused\n')])
        known, ok = dc.known_mailbox_addresses(c, 'ispmanager')
        assert known == set() and ok is False
        reason = dc.mailbox_guard(c, 'info@example.com', 'ispmanager',
                                  'delete')
        assert 'Список ящиков панели не получен' in reason

    def test_empty_list_is_a_real_empty_not_unknown(self):
        # Панель ответла корректно и списком ничего: создать ПЕРВЫЙ ящик можно
        c = FakeSSH(routes=[('mgrctl -m ispmgr maildomain',
                             'name=example.com elid=3\n'),
                            ('mgrctl -m ispmgr email', '')])
        known, ok = dc.known_mailbox_addresses(c, 'ispmanager')
        assert known == set() and ok is True
        assert dc.mailbox_guard(c, 'first@example.com', 'ispmanager',
                                'create') is None

    def test_fastpanel_source_used(self):
        c = FakeSSH(routes=[
            ('mogwai emails domains list', 'ID\tNAME\n1\texample.com\n'),
            ('mogwai emails boxes list', 'ID\tADDRESS\n5\tinfo@example.com\n'),
        ])
        known, ok = dc.known_mailbox_addresses(c, 'fastpanel')
        assert known == {'info@example.com'} and ok
        assert dc.mailbox_guard(c, 'info@example.com', 'fastpanel',
                                'passwd') is None
        assert 'не найден' in dc.mailbox_guard(c, 'nope@example.com',
                                               'fastpanel', 'delete')

    @pytest.mark.parametrize('mode', ['create', 'passwd', 'delete'])
    def test_bad_address_never_reaches_panel(self, mode):
        # Команда не отправляется вообще: проверок нет в маршрутах, и любой
        # вызов run() попадёт в default -> команда была бы видна в c.commands
        c = FakeSSH(routes=ISP_MAIL_ENV)
        assert dc.mailbox_guard(c, 'garbage', 'ispmanager', mode) is not None
        assert c.commands == []


class TestIspRows:
    def test_ok_rows(self):
        c = FakeSSH(routes=[('mgrctl -m ispmgr email',
                             'name=a@b.c elid=1\n')])
        rows, ok, raw = dc.isp_rows(c, 'email')
        assert ok and rows[0]['name'] == 'a@b.c' and raw

    def test_error_in_stdout_is_not_ok(self):
        # mgrctl пишет ошибку в stdout, rc при этом бывает 0 — «успех»
        # решается по содержимому, иначе guard посчитал бы пустоту списком
        c = FakeSSH(routes=[('mgrctl -m ispmgr email',
                             ('ERROR=access denied', '', 0))])
        rows, ok, raw = dc.isp_rows(c, 'email')
        assert ok is False and 'access denied' in raw

    def test_stderr_shown_when_stdout_empty(self):
        c = FakeSSH(routes=[('mgrctl -m ispmgr email',
                             ('', 'no such manager', 1))])
        _rows, ok, raw = dc.isp_rows(c, 'email')
        assert ok is False and raw == 'no such manager'


class TestRedactSecrets:
    def test_password_with_space_is_fully_masked(self):
        # Regression: регэксп по пробелам съедал только первое слово,
        # 'sup3r secret' уезжал в отчёт наполовину. В argv ISPmanager пароля
        # теперь нет вовсе — но панель может вернуть его в тексте ошибки.
        out = dc.redact_secrets("panel reply: passwd='sup3r secret' rejected")
        assert 'sup3r' not in out and 'secret' not in out
        assert 'passwd=***' in out

    def test_env_reference_is_not_masked(self):
        # -e 'passwd=$DIAG_MAILBOX_SECRET' — НЕ секрет, в нём только имя
        # переменной. Замаскировав её, мы лишаем оператора возможности
        # повторить команду руками (главная ценность показа команды).
        cmd = dc.isp_mailbox_env_command(dc.isp_mailbox_create_args('a', 'ex.com'))
        assert dc.redact_secrets(cmd) == cmd

    def test_plain_values_masked(self):
        out = dc.redact_secrets(dc.fp_mailbox_create_command('a', 'ex.com',
                                                            'pw12345678'))
        assert 'pw12345678' not in out and '--password=***' in out

    def test_multiline_output_masked_by_regex(self):
        # Вывод панели — не команда, shlex по нему не проходит; значения в
        # кавычках регэксп обязан снимать целиком
        out = dc.redact_secrets('bad passwd=abc123\n'
                               'confirm="with space" x')
        assert 'abc123' not in out and 'with space' not in out

    def test_benign_text_untouched(self):
        cmd = 'mogwai emails boxes delete -b 7 2>&1'
        assert dc.redact_secrets(cmd) == cmd

    def test_empty_and_none_safe(self):
        assert dc.redact_secrets('') == ''
        assert dc.redact_secrets(None) == ''

    def test_password_policy_refuses_short_before_panel(self):
        assert dc.password_policy('') and 'не задан' in dc.password_policy('')
        assert '8' in dc.password_policy('abc123')
        assert dc.password_policy('longenough') is None
        # ровно граница: 8 символов проходит
        assert dc.password_policy('12345678') is None


class TestFindFpMailboxId:
    def test_found_case_insensitive(self):
        rows = [{'ID': '12', 'ADDRESS': 'Info@Example.COM'}]
        assert dc.find_fp_mailbox_id(rows, 'info@example.com') == 12

    def test_missing_returns_none(self):
        rows = [{'ID': '12', 'ADDRESS': 'info@example.com'}]
        assert dc.find_fp_mailbox_id(rows, 'nope@example.com') is None

    def test_non_numeric_id_is_none_not_crash(self):
        rows = [{'ID': 'N/A', 'ADDRESS': 'a@b.c'}]
        assert dc.find_fp_mailbox_id(rows, 'a@b.c') is None

    def test_empty_rows(self):
        assert dc.find_fp_mailbox_id([], 'a@b.c') is None


# ==================== ДЕЙСТВИЯ С ЯЩИКАМИ: исполнение ====================
# Иглы обязательно ТОЧНЫЕ: 'mgrctl -m ispmgr email' — подстрока команды
# email.edit, и без хвоста '2>&1'mgrctl eats the sequence element meant for
# the list re-read. Порядок маршрутов тоже решает: специфичные иглы вперёд.
ISP_LIST = "mgrctl -m ispmgr email 2>&1"


# Каталог под env-файл берётся из mktemp: без маршрута на него новый код
# ЧЕСТНО отказывается (пароль нельзя передать безопасно) — падение теста с
# «mktemp не создал каталог» означает именно это, а не поломку операций.
SECRET_DIR = '/tmp/diagn_mail.TESTDIR'


def isp_env(lists, edit=('maildomain', 'name=example.com elid=3\n'),
            mktemp=(SECRET_DIR + '\n', '', 0), sftp='auto'):
    """FakeSSH с почтовым доменом, списком ящиков (последовательность) и edit."""
    routes = [
        ('mgrctl -m ispmgr maildomain', edit[1]),
        ('mgrctl -m ispmgr email.edit', ('', '', 0)),
        ('mgrctl -m ispmgr email.delete', ('', '', 0)),
        ('mktemp -d', mktemp),
        (ISP_LIST, lists),
    ]
    if sftp == 'auto':
        sftp = FakeSftpClient()
    return FakeSSH(routes=routes, client=sftp)


class TestMailboxActionsIspmanager:
    def test_create_confirmed_by_list_reread(self):
        c = isp_env(['name=info@example.com elid=5\n',
                     'name=info@example.com elid=5\n'
                     'name=new@example.com elid=6\n'])
        out = dc.mailbox_create(c, ' new@Example.com ', 'Sup3rSecret!',
                                'ispmanager')
        assert '✅ Ящик new@example.com создан' in out
        # Команда показана (повторить руками) и маска в ней
        assert '$ /usr/local/mgr5/sbin/mgrctl -m ispmgr email.edit' in out
        # Показываем команду ПАНЕЛИ, а не обвязку (source/rm): её содержимое
        # совпадает с примером из документации ISPsystem, т.е. её можно
        # повторить руками, экспортировав переменную.
        assert "-e 'passwd=$DIAG_MAILBOX_SECRET'" in out
        assert 'source' not in out and out.count('rm -rf') == 0
        # Пароль не уехал ни в команду-эхо, ни в отчёт
        assert 'Sup3rSecret!' not in out
        # Предупреждение обязано соответствовать каналу: в ps пароля НЕ было
        assert 'виден в ps' not in out
        assert 'в ps на сервере он не светился' in out

    def test_password_checked_before_any_panel_call(self):
        # Короткий пароль: панель не дёргается вообще (ни maildomain, ни edit)
        c = isp_env([''])
        out = dc.mailbox_create(c, 'a@example.com', 'short', 'ispmanager')
        assert '8 символов' in out
        assert c.commands == []

    def test_empty_password_no_call(self):
        c = isp_env([''])
        assert '❌ Пароль не задан' in dc.mailbox_create(c, 'a@example.com', '',
                                                        'ispmanager')
        assert c.commands == []

    def test_create_blocked_before_panel_when_domain_not_mail(self):
        c = isp_env([''])
        out = dc.mailbox_create(c, 'a@other.tld', 'Sup3rSecret!', 'ispmanager')
        assert '⛔ Операция отменена до отправки команды панели' in out
        assert c.find('email.edit') is None      # разрушающей команды не было

    def test_create_blocked_when_box_exists(self):
        c = isp_env(['name=info@example.com elid=5\n'])
        out = dc.mailbox_create(c, 'INFO@example.com', 'Sup3rSecret!',
                                'ispmanager')
        assert 'уже существует' in out
        assert c.find('email.edit') is None

    def test_panel_error_is_reported_and_not_claimed_ok(self):
        c = FakeSSH(routes=[
            ('mgrctl -m ispmgr maildomain', 'name=example.com elid=3\n'),
            ('mgrctl -m ispmgr email.edit',
             ('ERROR=weak password', 'rc', 0)),
            ('mktemp -d', SECRET_DIR + '\n'),
            (ISP_LIST, ''),
        ], client=FakeSftpClient())
        out = dc.mailbox_create(c, 'a@example.com', 'Sup3rSecret!',
                                'ispmanager')
        assert 'weak password' in out
        assert 'создан' not in out

    def test_warning_when_list_unreadable_after_success(self):
        # Команда прошла, но перечитать список не удалось: честно говорим
        # «проверьте вручную», а не рапортуем успех по rc=0
        c = FakeSSH(routes=[
            ('mgrctl -m ispmgr maildomain', 'name=example.com elid=3\n'),
            ('mgrctl -m ispmgr email.edit', ('', '', 0)),
            ('mktemp -d', SECRET_DIR + '\n'),
            (ISP_LIST, ['name=info@example.com\n', 'ERROR=timeout']),
        ], client=FakeSftpClient())
        out = dc.mailbox_create(c, 'a@example.com', 'Sup3rSecret!',
                                'ispmanager')
        assert 'список ящиков после неё не получен' in out
        assert '✅' not in out

    def test_create_silent_panel_but_box_absent_warns(self):
        c = isp_env(['name=info@example.com elid=5\n',
                     'name=info@example.com elid=5\n'])
        out = dc.mailbox_create(c, 'a@example.com', 'Sup3rSecret!',
                                'ispmanager')
        assert 'не появился в списке панели' in out
        assert '✅' not in out

    def test_delete_confirmed_absent(self):
        c = isp_env(['name=info@example.com elid=5\n', ''])
        out = dc.mailbox_delete(c, 'Info@Example.COM', 'ispmanager')
        assert '✅ Ящик info@example.com удалён' in out
        assert 'email.delete' in c.find('email.delete')

    def test_delete_survives_despite_panel_silence_if_still_listed(self):
        c = isp_env(['name=info@example.com elid=5\n'] * 2)
        out = dc.mailbox_delete(c, 'info@example.com', 'ispmanager')
        assert 'всё ещё в списке' in out
        assert '✅' not in out

    def test_passwd_confirmed(self):
        c = isp_env(['name=info@example.com elid=5\n'] * 2)
        out = dc.mailbox_passwd(c, 'info@example.com', 'Sup3rSecret!',
                                'ispmanager')
        assert '✅ Ящик info@example.com: пароль изменён' in out
        assert 'elid=info@example.com' in c.find('email.edit')

    def test_no_panel_means_no_command(self):
        c = isp_env([''])
        out = dc.mailbox_create(c, 'a@example.com', 'Sup3rSecret!', 'none')
        assert 'недоступно' in out and 'mogwai' in out
        assert c.find('email.edit') is None


class TestMailboxSecretChannel:
    """Канал пароля мимо argv: ISPmanager либо получает секрет из окружения,
    либо отказывается. Тихий фолбэк «посвечу пароль аргументом» запрещён —
    он и есть тот долг, который этот канал закрывает.
    """

    def test_no_sftp_means_no_panel_call(self):
        # checker.client=None: write_remote_file не сможет открыть SFTP.
        # Команда панели не должна уйти НИКОГДА — без env-файла -e раскроется
        # в пустой пароль, и панель либо откажет, либо (хуже) поставит его.
        c = isp_env(['name=info@example.com elid=5\n'], sftp=None)
        out = dc.mailbox_create(c, 'a@example.com', 'Sup3rSecret!', 'ispmanager')
        assert 'Не удалось записать env-файл' in out
        assert c.find('email.edit') is None
        # каталог, который mktemp всё-таки создал, обязан быть вычищен
        assert c.find('rm -rf ' + SECRET_DIR) is not None

    def test_no_mktemp_means_no_panel_call(self):
        # Нет mktemp (read-only /tmp, нет coreutils) — значит нет и безопасного
        # канала. Отказ обязан объяснять причину, а не молчать.
        c = isp_env(['name=info@example.com elid=5\n'],
                    mktemp=('', 'mktemp: No such file or directory', 1))
        out = dc.mailbox_passwd(c, 'info@example.com', 'Sup3rSecret!',
                                'ispmanager')
        assert 'mktemp не создал каталог' in out
        assert 'Передать пароль безопасно нельзя' in out
        assert c.find('email.edit') is None

    def test_mktemp_junk_is_not_trusted_as_a_path(self):
        # Ответ mktemp идёт в путь, а затем в `. <путь>`. Строка, не похожая на
        # абсолютный путь (мусор, предупреждение, многострочный вывод), не должна
        # превращаться в команду.
        c = isp_env(['name=info@example.com elid=5\n'],
                    mktemp='warning: something odd\n')
        out = dc.mailbox_create(c, 'a@example.com', 'Sup3rSecret!', 'ispmanager')
        assert '⛔' in out and c.find('email.edit') is None
        # и тем более в команду source этот текст не попал
        assert 'warning: something odd' not in ' '.join(
            cmd for cmd in c.commands if cmd.startswith('.'))

    def test_secret_file_is_created_0600_and_never_named_in_argv(self):
        sftp = FakeSftpClient()
        c = isp_env(['name=info@example.com elid=5\n',
                     'name=info@example.com elid=5\n'
                     'name=a@example.com elid=7\n'], sftp=sftp)
        dc.mailbox_create(c, 'a@example.com', 'Sup3rSecret!', 'ispmanager')
        # файл создан ДО команды панели (иначе -e раскроется в пустой пароль)
        assert c.find('chmod 600') is not None
        assert c.find('chmod 600 ' + SECRET_DIR) is not None
        assert list(sftp.store) == [SECRET_DIR + '/secret.env']
        assert sftp.store[SECRET_DIR + '/secret.env'].startswith(
            'export DIAG_MAILBOX_SECRET=')
        run_idx = [i for i, cmd in enumerate(c.commands)
                   if 'email.edit' in cmd and cmd.startswith('.')]
        chmod_idx = [i for i, cmd in enumerate(c.commands)
                     if cmd.startswith('chmod 600')]
        assert run_idx and chmod_idx and chmod_idx[0] < run_idx[0]

    def test_password_never_reaches_the_server_command_line(self):
        # Главный гард слайса: ни в одной отправленной команде пароля нет.
        # Раньше он был и в passwd=..., и в confirm=... (дважды на команду).
        sftp = FakeSftpClient()
        c = isp_env(['name=info@example.com elid=5\n',
                     'name=info@example.com elid=5\n'
                     'name=a@example.com elid=7\n'], sftp=sftp)
        dc.mailbox_passwd(c, 'info@example.com', 'Sup3r secret with spaces',
                          'ispmanager')
        assert not [cmd for cmd in c.commands if 'Sup3r' in cmd]
        # секрет дошёл до панели: в env-файле он есть (и только там)
        assert "Sup3r secret with spaces" in sftp.store[
            SECRET_DIR + '/secret.env']

    def test_secret_dir_removed_even_if_panel_errors(self):
        # Панель ответила ошибкой — файл с паролем всё равно обязан исчезнуть.
        # Очистка двойная: rm -rf внутри составной команды (после rc=$?) и
        # страховкой на python-стороне — команда может не дойти до своего rm,
        # если оператор отменил задачу (канал закрывается).
        # Маршрут email.edit задаём СВОИМ списком: FakeSSH берёт первое
        # совпадение, вставка в routes после общего email.edit ничего бы не
        # изменила (прожжённая грабля подстрок).
        c = FakeSSH(routes=[
            ('mgrctl -m ispmgr maildomain', 'name=example.com elid=3\n'),
            ('mgrctl -m ispmgr email.edit', ('ERROR=weak password', '', 1)),
            ('mktemp -d', SECRET_DIR + '\n'),
            (ISP_LIST, 'name=info@example.com elid=5\n'),
        ], client=FakeSftpClient())
        out = dc.mailbox_create(c, 'a@example.com', 'Sup3rSecret!', 'ispmanager')
        assert '❌ Панель ответила ошибкой (rc=1)' in out
        assert 'weak password' in out
        assert 'Sup3rSecret!' not in out                 # и в ошибке панели не светится
        assert 'rm -rf ' + SECRET_DIR + ' 2>/dev/null' in c.commands
        wrapped = [cmd for cmd in c.commands if cmd.startswith('. ')]
        assert wrapped and 'rm -rf ' + SECRET_DIR in wrapped[0]

    def test_full_wrapped_command_is_valid_shell(self):
        # Команда с `. файла`, &&, rc=$? и rm -rf — составная; её обязан
        # принимать bash -n наравне с остальными командами проекта.
        cmd = dc.isp_secret_run_command(
            SECRET_DIR, dc.isp_mailbox_create_args('a; x', "ex'.com"))
        proc = subprocess.run(['bash', '-n', '-c', cmd],
                              capture_output=True, text=True)
        assert proc.returncode == 0, proc.stderr
        shlex.split(cmd)
        # rc снимается ДО rm: иначе провал панели выглядел бы успехом
        assert cmd.index('rc=$?') < cmd.index('rm -rf')


class TestMailboxActionsFastpanel:
    FP_ENV = [
        ('mogwai emails domains list', 'ID\tNAME\n1\texample.com\n'),
        ('mogwai emails boxes create', ('', '', 0)),
        ('mogwai emails boxes delete', ('', '', 0)),
        ('mogwai emails boxes list', 'ID\tADDRESS\n5\tinfo@example.com\n'),
    ]

    def test_create_uses_kb_command(self):
        c = FakeSSH(routes=self.FP_ENV)
        out = dc.mailbox_create(c, 'new@example.com', 'Sup3rSecret!',
                                'fastpanel')
        assert 'mogwai emails boxes create' in out
        # ящика new@ в списке mogwai нет (заглушка отдаёт info@) — честное ⚠️
        assert 'не появился в списке панели' in out
        assert 'Sup3rSecret!' not in out

    def test_delete_by_numeric_id(self):
        c = FakeSSH(routes=[
            ('mogwai emails domains list', 'ID\tNAME\n1\texample.com\n'),
            ('mogwai emails boxes delete', ('', '', 0)),
            ('mogwai emails boxes list',
             ['ID\tADDRESS\n5\tinfo@example.com\n',
              'ID\tADDRESS\n5\tinfo@example.com\n',
              'ID\tADDRESS\n']),
        ])
        out = dc.mailbox_delete(c, 'info@example.com', 'fastpanel')
        assert c.find('mogwai emails boxes delete -b 5') is not None
        assert '✅ Ящик info@example.com удалён' in out

    def test_delete_refused_without_numeric_id(self):
        # ID не число → удалять нельзя: 'delete -b <мусор>' хуже отказа
        c = FakeSSH(routes=[
            ('mogwai emails domains list', 'ID\tNAME\n1\texample.com\n'),
            ('mogwai emails boxes list', 'ID\tADDRESS\nN/A\tinfo@example.com\n'),
        ])
        out = dc.mailbox_delete(c, 'info@example.com', 'fastpanel')
        assert 'не вернул числовой ID' in out
        assert c.find('boxes delete') is None

    def test_passwd_unsupported_without_inventing_flags(self):
        # У mogwai нет смены пароля ящика — выдумывать --password нельзя;
        # команда создания не должна быть вызвана «вместо» неё
        c = FakeSSH(routes=self.FP_ENV)
        out = dc.mailbox_passwd(c, 'info@example.com', 'Sup3rSecret!',
                                'fastpanel')
        assert 'не предусмотрена' in out
        assert c.find('boxes create') is None
        assert c.find('boxes delete') is None
