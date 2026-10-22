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


# ---------- сводка доступности: масштаб беды над списком ----------
# Игла '-servername домен' есть И в health-пробе, И в SSL-отчёте (одна и та же
# site_status_command), поэтому одна фикстура кормит оба отчёта и не зависит от
# порядка обхода инвентаря.

def _site_rows(names):
    return ''.join(f'name={d} elid={i} owner=u\n'
                   for i, d in enumerate(names, 1))


def _site_routes(names, answers):
    return [('mgrctl -m ispmgr webdomain', _site_rows(names))] + [
        ('s_client -servername ' + d, text) for d, text in answers.items()]


OK_SITE = 'HTTP=200\nHTTPS=200\nSSL=ok\nCERT=200'
HTTP_ONLY = 'HTTP=200\nHTTPS=000\nSSL=none\nCERT=none'
DEAD_SITE = 'HTTP=000\nHTTPS=000\nSSL=none\nCERT=none'
EXPIRED_SITE = 'HTTP=200\nHTTPS=200\nSSL=bad\nCERT=-4'
SOON_SITE = 'HTTP=200\nHTTPS=200\nSSL=bad\nCERT=9'
NO_CERT_SITE = 'HTTP=200\nHTTPS=500\nSSL=none\nCERT=none'


class TestSiteHealthSummary:
    """Сколько сайтов лежит — до чтения списка из 25 строк.

    Считается ПО ТОЙ ЖЕ функции, что напечатала иконку. Подсчёт по символу «❌»
    в готовом тексте запрещён: в строке сайта ДВЕ иконки — `http_status_icon`
    (сайт молчит) и `cert_days_icon` (сертификат просрочен), и «❌» посчитал бы
    мёртвый сертификат как упавший сайт. Та же грабля, что с «🌐» в SPF-отчёте.
    """

    # ---------- чистая функция ----------
    def test_summary_names_the_checked_denominator(self):
        out = '\n'.join(dc.site_health_summary(ok=1, http_only=1, silent=1,
                                               total=4))
        assert 'Проверено доступности: 3 из 4' in out

    def test_categories_sum_up_to_the_checked_count(self):
        # Ни один проверенный домен не имеет права потеряться в сводке: если
        # иконку поменяют и она выпадет из распознавания, сумма разойдётся с
        # знаменателем и этот тест покраснеет вместо тихой лжи.
        out = '\n'.join(dc.site_health_summary(ok=10, http_only=5, silent=2,
                                               unknown=1, total=18))
        assert 'Проверено доступности: 18 из 18' in out

    def test_unrecognized_icon_is_admitted_not_swallowed(self):
        # Неизвестная иконка = «мы не поняли», а не «в порядке». Молча отнести
        # её в ok значило бы занизить число бед.
        out = '\n'.join(dc.site_health_summary(ok=3, unknown=1, total=4))
        assert 'Не распознано — 1' in out

    def test_zero_categories_are_not_printed(self):
        out = '\n'.join(dc.site_health_summary(ok=4, total=4))
        assert 'HTTPS 2xx/3xx — 4' in out
        assert 'молчит' not in out and 'только HTTP' not in out
        assert 'SSL:' not in out

    def test_ssl_categories_printed_only_when_present(self):
        out = '\n'.join(dc.site_health_summary(ok=2, cert_expired=1,
                                               cert_soon=2, total=3))
        assert 'SSL: истёк — 1, истекает < 30 дн. — 2' in out

    def test_denominator_already_names_the_unchecked(self):
        # ОТДЕЛЬНАЯ строка «домены без проверки» запрещена намеренно (и этот
        # тест записан ПОСЛЕ того, как я её требовал): знаменатель «25 из 30»
        # сам называет число непроверенных, а снизу стоит сноска
        # HEALTH_CHECK_LIMIT. Третье упоминание — тот же повтор, ради отказа
        # от которого в v1.13 была удалена сводка «расхождений нет».
        out = '\n'.join(dc.site_health_summary(ok=25, total=30))
        assert 'Проверено доступности: 25 из 30' in out
        assert 'не проверя' not in out
        assert 'HEALTH_CHECK_LIMIT' not in out

    def test_nothing_checked_is_silence(self):
        assert dc.site_health_summary() == []

    # ---------- интеграция в отчёт ----------
    def test_summary_counts_kinds_not_icons(self):
        names = ['good.ru', 'http.ru', 'dead.ru']
        c = FakeSSH(routes=_site_routes(
            names, {'good.ru': OK_SITE, 'http.ru': HTTP_ONLY,
                    'dead.ru': DEAD_SITE}))
        out = dc.site_health_report(c, 'ispmanager')
        assert 'Проверено доступности: 3 из 3' in out
        assert 'HTTPS 2xx/3xx — 1, только HTTP — 1, молчит — 1' in out

    def test_dead_certificate_is_not_counted_as_a_dead_site(self):
        # В строке этого домена ДВА креста: ✅ по доступности и ❌ по SSL.
        # Наивный подсчёт «❌» дал бы «молчит — 1» про сайт, который на самом
        # деле отвечает.
        c = FakeSSH(routes=_site_routes(['exp.ru'], {'exp.ru': EXPIRED_SITE}))
        out = dc.site_health_report(c, 'ispmanager')
        assert 'HTTPS 2xx/3xx — 1' in out
        assert 'молчит — 1' not in out
        assert 'SSL: истёк — 1' in out

    def test_ssl_icons_are_counted(self):
        names = ['exp.ru', 'soon.ru', 'nocert.ru', 'good.ru']
        c = FakeSSH(routes=_site_routes(
            names, {'exp.ru': EXPIRED_SITE, 'soon.ru': SOON_SITE,
                    'nocert.ru': NO_CERT_SITE, 'good.ru': OK_SITE}))
        out = dc.site_health_report(c, 'ispmanager')
        assert ('SSL: истёк — 1, истекает < 30 дн. — 1, '
                'сертификат не получен — 1') in out

    def test_cert_is_not_counted_when_https_silent(self):
        # При молчащем HTTPS SSL-пометка в строке не печатается (сертификат
        # чужого дефолтного vhost нельзя показывать как свой). Значит и в
        # счётчике его быть не может: считать то, что не показал, — врать.
        c = FakeSSH(routes=_site_routes(['quiet.ru'], {'quiet.ru': DEAD_SITE}))
        out = dc.site_health_report(c, 'ispmanager')
        assert 'SSL:' not in out
        assert 'молчит — 1' in out

    def test_summary_printed_above_the_status_list(self):
        c = FakeSSH(routes=_site_routes(['good.ru'], {'good.ru': OK_SITE}))
        out = dc.site_health_report(c, 'ispmanager').splitlines()
        head = next(i for i, l in enumerate(out) if 'Проверено доступности' in l)
        gate = next(i for i, l in enumerate(out)
                    if 'Проверка доступности' in l)
        body = next(i for i, l in enumerate(out) if 'http=200' in l)
        assert gate < head < body      # сразу под заголовком блока, ДО строк

    def test_unchecked_domains_named_by_the_denominator(self):
        names = [f'site{i}.ru' for i in range(30)]
        c = FakeSSH(routes=[('mgrctl -m ispmgr webdomain', _site_rows(names))])
        out = dc.site_health_report(c, 'ispmanager')
        assert 'Проверено доступности: 25 из 30' in out
        # Отдельная строка про непроверенные запрещена: 25 из 30 + сноска
        # HEALTH_CHECK_LIMIT снизу говорят то же самое.
        assert 'не проверя' not in out

    def test_summary_costs_no_extra_probes(self):
        # Сводка считается из уже полученных ответов: строка, которая стоит
        # ещё одного хендшейка на домен, удвоила бы цену прогона.
        names = [f'site{i}.ru' for i in range(30)]
        c = FakeSSH(routes=[('mgrctl -m ispmgr webdomain', _site_rows(names))])
        dc.site_health_report(c, 'ispmanager')
        assert c.count("printf 'HTTP=") == 25

    def test_all_healthy_still_reports_the_number(self):
        # Пустая сводка была бы неотличима от «не считали»: число говорим
        # всегда, проблемные категории — только когда они есть.
        names = ['a1.ru', 'a2.ru']
        c = FakeSSH(routes=_site_routes(names, {n: OK_SITE for n in names}))
        out = dc.site_health_report(c, 'ispmanager')
        assert 'Проверено доступности: 2 из 2' in out
        assert 'HTTPS 2xx/3xx — 2' in out
        assert 'молчит' not in out


class TestSslHeadHonesty:
    """Шапка SSL-отчёта не имеет права оставлять «всё в порядке» недосказанным.

    До фикса шапка говорила «Истекло: 0, истекает < 30 дн.: 0» — и оператор,
    прочитавший её, уже решил, что с SSL всё хорошо. А ниже, за всем списком,
    прятался блок «СЕРТИФИКАТ НЕ ПОЛУЧЕН» на пять доменов: там просто нет
    HTTPS. Это тот же закон, что «не проверено ≠ провалено» и «≠ в порядке».
    """

    # ---------- чистая функция ----------
    def test_not_received_cert_is_named_in_the_head(self):
        out = '\n'.join(dc.ssl_expiry_head_lines(not_received=5))
        assert 'Сертификат не получен — 5' in out
        assert 'не «с SSL всё в порядке»' in out
        assert 'блоке ниже' in out              # куда смотреть за деталями

    def test_not_received_is_counted_only_over_checked_domains(self):
        # Число берётся из проверенных доменов: приписать ему домены за limit
        # значило бы соврать дважды — и про масштаб беды, и про знаменатель.
        c = FakeSSH(routes=[
            ('mgrctl -m ispmgr webdomain',
             _site_rows([f'site{i}.tld' for i in range(30)])),
            ('s_client -servername site0.tld', 'HTTP=200\nHTTPS=200\n'
             'SSL=ok\nCERT=200'),
            ('s_client -servername site1.tld', 'HTTP=200\nHTTPS=200\n'
             'SSL=ok\nCERT=200'),
            ('s_client -servername site2.tld', 'HTTP=200\nHTTPS=200\n'
             'SSL=ok\nCERT=200'),
        ])
        out = dc.ssl_expiry_report(c, 'ispmanager')
        assert 'Сертификат не получен — 22' in out
        assert 'Сертификат не получен — 30' not in out
        assert 'Проверено доменов: 25 из 30' in out

    def test_clean_run_prints_nothing_new(self):
        assert dc.ssl_expiry_head_lines() == []
        assert dc.ssl_expiry_head_lines(not_received=0) == []

    # ---------- интеграция в отчёт ----------
    def test_head_names_quiet_domains_above_the_list(self):
        c = FakeSSH(routes=[
            ('mgrctl -m ispmgr webdomain', 'name=quiet.tld elid=1\n'),
            ('s_client -servername quiet.tld',
             'HTTP=200\nHTTPS=000\nSSL=none\nCERT=none'),
        ])
        out = dc.ssl_expiry_report(c, 'ispmanager').splitlines()
        head = next(i for i, l in enumerate(out)
                    if 'Сертификат не получен — 1' in l)
        body = next(i for i, l in enumerate(out)
                    if 'СЕРТИФИКАТ НЕ ПОЛУЧЕН' in l)
        assert head < body
        # Прежняя формулировка шапки не поехала: её держат другие тесты.
        assert any('Истекло: 0, истекает < 30 дн.: 0' in l for l in out)

    def test_head_counts_only_the_checked_quiet_domains(self):
        names = [f'site{i}.tld' for i in range(30)]
        c = FakeSSH(routes=[('mgrctl -m ispmgr webdomain', _site_rows(names))])
        out = dc.ssl_expiry_report(c, 'ispmanager')
        # Ни один сайт не отвечает → все ПРОВЕРЕННЫЕ «без сертификата»; пять
        # доменов за limit в это число попасть не могут (их не проверяли).
        assert 'Сертификат не получен — 25' in out
        assert 'Сертификат не получен — 30' not in out
        assert 'Проверено доменов: 25 из 30' in out

    def test_uncapped_healthy_run_stays_silent(self):
        c = FakeSSH(routes=[
            ('mgrctl -m ispmgr webdomain', 'name=ok.tld elid=1\n'),
            ('s_client -servername ok.tld', OK_SITE),
        ])
        out = dc.ssl_expiry_report(c, 'ispmanager')
        assert 'Сертификат не получен' not in out
        assert 'Не проверялось' not in out

    def test_head_costs_no_extra_handshakes(self):
        names = [f'site{i}.tld' for i in range(30)]
        c = FakeSSH(routes=[('mgrctl -m ispmgr webdomain', _site_rows(names))])
        dc.ssl_expiry_report(c, 'ispmanager')
        assert c.count('s_client -servername') == 25


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


# ==================== доставка из лога внутри почтовых отчётов ==============
# Снимок и дайджест встроены в существующие отчёты, а не вынесены отдельным
# пунктом меню: тикет «письма уходят в спам» закрывается одним прогоном, и меню
# не разрастается. Перекрываются ровно те места, ради которых они встроены —
# причина отказа печатается рядом с DNS-диагнозом — и цена: лог читается ОДИН
# раз на прогон, а не на домен (25 доменов × чтение лога = минуты простоя GUI).
GMAIL_SPAM_BOUNCE = (
    'Oct 10 12:00:05 host postfix/smtp[124]: AAA2: to=<c@gmail.com>, '
    'relay=gmail-smtp-in.l.google.com[142.251.8.27]:25, dsn=5.7.26, '
    'status=bounced (gmail-smtp-in.l.google.com[142.251.8.27] said: '
    '550-5.7.26 [203.0.113.9] unauthenticated mail was rejected, please '
    'learn about SPF)')
# Запись о входе того же письма в очередь. Строка доставки (`smtp`) отправителя
# не содержит — конверт печатает `qmgr` по тому же queue-id. Queue-id здесь
# короткий (AAA2), как у старых версий postfix: при жёсткой нижней границе длины
# привязка на таком сервере молча не срабатывала бы, и оператор прочитал бы это
# как «письма не от наших доменов».
QMGR_LIE = ('Oct 10 12:00:01 host postfix/qmgr[21603]: AAA2: '
            'from=<info@lie.ru>, size=1000, nrcpt=1 (queue active)')


def _log_routes(*lines):
    # read_mail_log выбирает maillog/mail.log циклом ВНУТРИ одной команды,
    # поэтому и игла одна: подменять каждую команду дистрибутива по отдельности
    # означало бы тестировать не тот код, который уходит на сервер.
    return [('for __p in',
             '#LOG /var/log/mail.log\n' + '\n'.join(lines) + '\n')]


class TestDeliveryInInventory:
    """Почтовая сводка обязана объяснять ПРИЧИНУ, а не только считать очередь."""

    def test_inventory_shows_failure_reason_from_log(self):
        c = FakeSSH(routes=[('mailq', '-- 4 Messages'),
                            ('__svc_status', 'postfix=active\n')]
                   + _log_routes(GMAIL_SPAM_BOUNCE))
        out = dc.mail_overview_report(c, 'none')
        assert 'Доставка по логу' in out
        # Группа причины, а не сырая строка лога: из этих слов оператор понимает,
        # куда идти (DNS и репутация), а не «копай postfix».
        assert 'спам или блокировка репутации' in out
        assert 'gmail.com' in out                       # кому бьёт — видно

    def test_dead_log_is_not_reported_as_clean(self):
        # «Не проверено» не имеет права печататься как «в порядке»: иначе сводка
        # с молчаливым логом закрыла бы тикет ложным «отказов нет».
        c = FakeSSH(routes=[('mailq', 'Mail queue is empty')])
        out = dc.mail_overview_report(c, 'none')
        assert 'лог не найден' in out
        assert 'Отказов нет' not in out

    def test_snapshot_costs_one_log_read_per_run(self):
        c = FakeSSH(routes=[('mailq', 'Mail queue is empty')]
                   + _log_routes(GMAIL_SPAM_BOUNCE))
        dc.mail_overview_report(c, 'none')
        assert c.count('for __p in') == 1


# Иглы внешних запросов обязаны стоять раньше локальных: '@1.1.1.1' встречается в
# команде внешнего запроса, а первое совпадение по подстроке выигрывает.
AUTH_ROUTES = [
    ('cat /etc/resolv.conf', 'nameserver 127.0.0.53\n'),
    ('mgrctl -m ispmgr dnszone', 'name=lie.ru elid=1\n'),
    ('a.root-servers.net', '198.41.0.4\n'),
    ('__bad=0', 'rc=0\n'),
    (' @1.1.1.1', 'rc=0\n'),
    ('dig +short TXT', '"v=spf1 ip4:10.0.0.5 -all"\n'),
    ('dig +short A', '10.0.0.5\n'),
    ('-x 10.0.0.5', 'mail.lie.ru.\n'),
]


class TestDeliveryDigestInMailAuth:
    """Дайджест в SPF-отчёте: доказательство, что DNS-беда УЖЕ ломает почту."""

    def test_spam_bounce_confirms_the_dns_verdict(self):
        c = FakeSSH(routes=[('mgrctl -m ispmgr maildomain',
                             'name=lie.ru elid=1\n')] + AUTH_ROUTES
                   + _log_routes(GMAIL_SPAM_BOUNCE))
        out = dc.mail_auth_report(c, 'ispmanager')
        assert 'Что лог говорит о доставке' in out
        assert 'спам или блокировка репутации — 1' in out
        # Главная фраза слайса: отказ приёмника связан с проваленным DNS.
        assert 'DNS-беда уже ломает доставку' in out

    def test_digest_is_read_once_even_for_many_domains(self):
        # Дайджест вызывается вне цикла по доменам. Гард не даст вернуть его
        # внутрь: 25 доменов означали бы 25 чтений лога и висящее окно GUI.
        rows = 'name=a.ru elid=1\nname=b.ru elid=2\nname=lie.ru elid=3\n'
        c = FakeSSH(routes=[('mgrctl -m ispmgr maildomain', rows)] + AUTH_ROUTES
                   + _log_routes(GMAIL_SPAM_BOUNCE))
        out = dc.mail_auth_report(c, 'ispmanager')
        assert 'Проверено доменов: 3' in out
        assert c.count('for __p in') == 1

    def test_dead_log_refuses_to_confirm_instead_of_faking_clean(self):
        c = FakeSSH(routes=[('mgrctl -m ispmgr maildomain',
                             'name=lie.ru elid=1\n')] + AUTH_ROUTES)
        out = dc.mail_auth_report(c, 'ispmanager')
        assert 'не найден' in out and 'не проверено' in out
        assert 'DNS-беда уже ломает доставку' not in out


class TestSenderAttributionInReports:
    """Отказ обязан быть подписан ДОМЕНОМ ОТПРАВЛЕНИЯ, а не только получателем.

    Оператор чинит свой домен, а не gmail: «письма отбивает Gmail» для него
    бесполезно, нужно «у домена lie.ru письма отбивают за SPF». Отправителя в
    строке доставки нет — он берётся join'ом по queue-id, и пометка «ваши»
    ставится только по инвентарю почтовых доменов панели.
    """

    def test_spf_report_names_the_sending_domain(self):
        c = FakeSSH(routes=[('mgrctl -m ispmgr maildomain',
                             'name=lie.ru elid=1\n')] + AUTH_ROUTES
                   + _log_routes(QMGR_LIE, GMAIL_SPAM_BOUNCE))
        out = dc.mail_auth_report(c, 'ispmanager')
        # Ключевая фраза слайса: тикет закрывается именем домена.
        assert 'по вашим доменам: lie.ru — 1' in out

    def test_spf_report_still_costs_one_log_read(self):
        # Индекс отправителей строится из УЖЕ прочитанного фрагмента. Гард не
        # даст «починить» привязку вторым чтением лога: при 25 доменах это
        # означало бы висящее окно GUI.
        rows = 'name=a.ru elid=1\nname=lie.ru elid=2\n'
        c = FakeSSH(routes=[('mgrctl -m ispmgr maildomain', rows)] + AUTH_ROUTES
                   + _log_routes(QMGR_LIE, GMAIL_SPAM_BOUNCE))
        dc.mail_auth_report(c, 'ispmanager')
        assert c.count('for __p in') == 1

    def test_overview_substantiates_the_sending_domain(self):
        c = FakeSSH(routes=[('mgrctl -m ispmgr maildomain',
                             'name=lie.ru elid=1\n'),
                            ('mailq', '-- 1 Messages'),
                            ('__svc_status', 'postfix=active\n')] + AUTH_ROUTES
                   + _log_routes(QMGR_LIE, GMAIL_SPAM_BOUNCE))
        out = dc.mail_overview_report(c, 'ispmanager')
        assert 'По вашим почтовым доменам: lie.ru — 1' in out
        # Адрес подтверждён записью очереди, а не угадан по тексту отказа — это
        # обязано быть сказано, иначе строка выглядит догадкой.
        assert 'не угадан' in out

    def test_overview_without_panel_inventory_makes_no_claim(self):
        # panel_type='none': инвентаря почтовых доменов нет, и называть домен
        # «вашим» нечем. Поднять «не проверяли» до «ваши» — тот же грех, что и
        # «не проверено» → «в порядке».
        c = FakeSSH(routes=[('mailq', '-- 1 Messages'),
                            ('__svc_status', 'postfix=active\n')]
                   + _log_routes(QMGR_LIE, GMAIL_SPAM_BOUNCE))
        out = dc.mail_overview_report(c, 'none')
        assert 'По вашим' not in out
        assert 'не проверялось' in out
        # При этом сам отправитель не теряется: «не проверяли, чей он» ≠
        # «отправителей нет».
        assert 'lie.ru' in out

    def test_failure_of_foreign_sender_is_named_foreign(self):
        # lie.ru в инвентаре, письмо шлёт chuj.ru: назвать его «вашим» нельзя,
        # но и молчать нельзя — отказ реальный.
        foreign = ('Oct 10 12:00:01 host postfix/qmgr[21603]: AAA2: '
                   'from=<spam@chuj.ru>, size=1000, nrcpt=1 (queue active)')
        c = FakeSSH(routes=[('mgrctl -m ispmgr maildomain',
                             'name=lie.ru elid=1\n'),
                            ('mailq', '-- 1 Messages'),
                            ('__svc_status', 'postfix=active\n')] + AUTH_ROUTES
                   + _log_routes(foreign, GMAIL_SPAM_BOUNCE))
        out = dc.mail_overview_report(c, 'ispmanager')
        assert 'По вашим' not in out
        assert 'вне ваших почтовых доменов: chuj.ru — 1' in out
        assert 'не значится в инвентаре' in out

    def test_sender_missing_from_window_is_not_called_foreign(self):
        # Если qmgr-строки в окне лога нет, отказ обязан быть подписан «не
        # видно», а не «не ваш домен»: второе — ложное оправдание домена.
        c = FakeSSH(routes=[('mgrctl -m ispmgr maildomain',
                             'name=lie.ru elid=1\n'),
                            ('mailq', '-- 1 Messages'),
                            ('__svc_status', 'postfix=active\n')] + AUTH_ROUTES
                   + _log_routes(GMAIL_SPAM_BOUNCE))
        out = dc.mail_overview_report(c, 'ispmanager')
        assert 'Отправитель не определён — 1' in out
        assert 'не видно' in out
        assert 'вне ваших' not in out


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

    # ---------- SSL-подпись в досье: три состояния, а не «истекает/нет» ----------
    # Команда пробы знает о сертификате только «ok / не ok»: SSL=bad — это и
    # «истёк 4 дня назад» (браузер уже ругается), и «истекёт через 9 дней» (чинить
    # на неделе). Досье печатало ровно эту двусмысленность строкой «истекает/нет»,
    # хотя точный остаток (CERT=) в проекте давно есть и показан в сводке
    # доступности и в SSL-отчёте. Беды с разной срочностью выглядели одинаково.

    def _dossier(self, probe_answer, dom='site1.ru'):
        c = FakeSSH(routes=[
            ('mgrctl -m ispmgr webdomain', ISP_WEBDOMAIN),
            ("printf 'HTTP=", probe_answer),
        ])
        return dc.domain_detail_report(c, dom, 'ispmanager'), c

    # Подпись берём ровно ту же, что печатает сводка доступности
    # ('❌ SSL ИСТЁК 4 дн. назад'): два отчёта обязаны называть беду одними
    # словами, иначе оператор не узнает в досье свою же строку из сводки.
    def test_dossier_names_the_exact_cert_days(self):
        out, _ = self._dossier('HTTP=200\nHTTPS=200\nSSL=ok\nCERT=87')
        assert '✅ SSL осталось 87 дн.' in out
        assert 'истекает/нет' not in out

    def test_dossier_does_not_call_an_expired_cert_soon(self):
        out, _ = self._dossier('HTTP=200\nHTTPS=200\nSSL=bad\nCERT=-4')
        assert '❌ SSL ИСТЁК 4 дн. назад' in out
        assert 'истекает/нет' not in out
        out2, _ = self._dossier('HTTP=200\nHTTPS=200\nSSL=bad\nCERT=9')
        assert '⚠️ SSL осталось 9 дн.' in out2

    def test_dossier_explains_a_missing_cert_by_the_real_reason(self):
        # HTTPS отвечает, а сертификата нет: «порт закрыт» был бы ложной причиной,
        # а прежняя подпись «истекает/нет» ещё и утверждала бы, что сертификат
        # есть и просто истекает.
        out, _ = self._dossier('HTTP=200\nHTTPS=500\nSSL=none\nCERT=none')
        assert ('❓ SSL сертификат не получен '
                '(https отвечает без рабочего TLS)') in out
        assert 'истёк' not in out and 'истекает' not in out
        assert 'порт закрыт' not in out      # порт ОТКРЫТ: причина не должна врать

    def test_missing_cert_label_does_not_invent_a_closed_port(self):
        # cert_days_label(None) не знает про порт — значит не имеет права
        # про него говорить. Причина живёт в no_cert_reason, где код ответа есть.
        assert 'порт' not in dc.cert_days_label(None)

    def test_dossier_stays_silent_about_ssl_when_https_is_dead(self):
        out, _ = self._dossier('HTTP=000\nHTTPS=000\nSSL=none\nCERT=none')
        line = next(l for l in out.splitlines() if 'Доступность:' in l)
        # Сертификат чужого дефолтного vhost показывать в строке домена нельзя —
        # оператор принял бы его за свой (то же правило, что в сводке).
        assert 'SSL' not in line

    def test_dossier_and_health_share_one_cert_formulation(self):
        # Один и тот же ответ пробы обязан называться одинаково в двух отчётах:
        # две формулировки однажды разъехались бы («истёк» против «просрочен»), и
        # оператор не узнал бы в досье свою же беду из сводки.
        probe = 'HTTP=200\nHTTPS=200\nSSL=bad\nCERT=-4'
        out, _ = self._dossier(probe)
        c = FakeSSH(routes=[('mgrctl -m ispmgr webdomain', ISP_WEBDOMAIN),
                            ("printf 'HTTP=", probe)])
        label = 'ИСТЁК 4 дн. назад'
        assert label in dc.site_health_report(c, 'ispmanager')
        assert label in out

    def test_dossier_ssl_note_costs_no_extra_probe(self):
        # Подпись строится из уже снятой пробы: второй вызов site_status_command
        # ради одной строки удвоил бы число внешних хендшейков на домен.
        _out, c = self._dossier('HTTP=200\nHTTPS=200\nSSL=ok\nCERT=87')
        assert c.count("printf 'HTTP=") == 1

    def test_no_cert_reason_is_shared_between_reports(self):
        # Причина «сертификата нет» обязана быть одной на все отчёты: порт
        # закрыт чинят фаерволлом, «нет рабочего TLS» — конфиг vhost.
        assert dc.no_cert_reason('000') == 'https не отвечает'
        assert dc.no_cert_reason('500') == 'https отвечает без рабочего TLS'

    def test_visibility_of_the_note_decided_in_one_place(self):
        # Guard на ЕДИНСТВЕННОЕ решение «показывать ли SSL-пометку»: от него
        # зависят и строка, и сводный счётчик. Если условие продублировать в
        # печатающей функции, сводка начнёт считать ❓, которого в строках нет
        # (или промолчит о показанном), — тот же разъезд, что лечился везде.
        cases = [
            ({'https': '000', 'cert_days': None}, None),   # молчит
            ({'https': '', 'cert_days': -1}, None),        # молчит, и даже истёк
            ({'https': '500', 'cert_days': None}, 'none'),     # порт открыт
            ({'https': '200', 'cert_days': -4}, 'expired'),
            ({'https': '301', 'cert_days': 9}, 'soon'),
            ({'https': '200', 'cert_days': 200}, 'ok'),
        ]
        for status, expected in cases:
            assert dc.cert_note_state(status) == expected, status

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


# ============ ПИСЬМА В СПАМ: SPF / DKIM / DMARC / PTR =====================
# Причина №1 в тикетах «почта работает, а письма уходят в спам» — DNS, а не
# postfix. Вся тяжесть логики в чистых парсерах, они проверяются напрямую;
# отчёты идут через FakeSSH. Две грабли, из-за которых блок написан именно так:
#  - «DKIM нет» честно только при переборе селекторов: у FASTPANEL это
#    dkim._domainkey (kb.fastpanel.direct), у ISPmanager/opendkim — default, у
#    rspamd свои. Проверка одного имени наврёт оператору;
#  - dig с сервера показывает ЛОКАЛЬНУЮ зону, если зону обслуживает он сам или
#    резолвер смотрит в localhost. «SPF есть» при пустой публичной зоне — ложный
#    диагноз, поэтому источник записей печатается в отчёте.

DKIM_1024 = 'v=DKIM1; k=rsa; p=' + 'A' * 216     # штатный RSA-1024 в base64
DKIM_512 = 'v=DKIM1; k=rsa; p=' + 'A' * 106      # RSA-512: строгие приёмники не примут
DKIM_REVOKED = 'v=DKIM1; k=rsa; p='              # именно так отзывают ключ

MAIL_AUTH_COMMANDS = ('a_query_command', 'spf_query_command',
                      'dmarc_query_command', 'dkim_query_command')


class TestSpfParsing:
    def test_normal_record_is_ok(self):
        r = dc.parse_spf(['v=spf1 ip4:93.184.216.34 include:_spf.google.com ~all'])
        assert r['status'] == 'ok'
        assert r['includes'] == ['_spf.google.com']
        assert r['lookups'] == 2          # своя зона + один include

    def test_no_txt_at_all(self):
        r = dc.parse_spf([])
        assert r['status'] == 'bad' and 'TXT-записей у домена нет' in r['detail']

    def test_txt_present_but_not_spf(self):
        #_verdyt тот же, а подсказка другая: оператору стоит искать запись в
        # другой зоне, а не ставить новую
        r = dc.parse_spf(['google-site-verification=abc123'])
        assert r['status'] == 'bad' and 'среди 1 TXT' in r['detail']

    def test_typo_without_one_is_bad(self):
        # Типичная опечатка: 'v=spf ' без единицы — приёмщик запись не видит
        r = dc.parse_spf(['v=spf ip4:1.1.1.1 -all'])
        assert r['status'] == 'bad' and 'без 1' in r['detail']

    def test_two_records_is_permerror(self):
        # RFC 7208 §3.6: две SPF-записи — это не SPF, приёмник ОТКЛОНЯЕТ письма
        r = dc.parse_spf(['v=spf1 ip4:1.1.1.1 -all', 'v=spf1 include:x.ru ~all'])
        assert r['status'] == 'bad' and 'PermError' in r['detail']

    def test_too_many_includes_breaks_the_rfc_limit(self):
        rec = 'v=spf1 ' + ' '.join(f'include:d{i}.ru' for i in range(12)) + ' -all'
        r = dc.parse_spf([rec])
        assert r['status'] == 'bad' and r['lookups'] == 13

    def test_exactly_ten_lookups_is_still_ok(self):
        # Граница: 10 DNS-запросов по RFC 7208 ещё легальны, 11 — уже PermError
        rec = 'v=spf1 ' + ' '.join(f'include:d{i}.ru' for i in range(9)) + ' -all'
        assert dc.parse_spf([rec])['status'] == 'ok'

    def test_plus_all_opens_the_domain(self):
        r = dc.parse_spf(['v=spf1 +all'])
        assert r['status'] == 'bad' and 'ЛЮБОГО' in r['detail']

    def test_missing_all_mechanism_is_warn_not_bad(self):
        # Запись применяется, но формально не запрещает чужие серверы: это
        # замечание, а не провал — письма-то доходят
        r = dc.parse_spf(['v=spf1 ip4:1.1.1.1'])
        assert r['status'] == 'warn' and 'all' in r['detail']

    def test_redirect_is_ok_without_mechanism(self):
        # redirect= сам отвечает за исход, требовать в нём all — ложный упрёк
        r = dc.parse_spf(['v=spf1 redirect=_spf.example.com'])
        assert r['status'] == 'ok'

    def test_long_record_is_truncated_in_detail(self):
        # Отчёт читают с экрана: полная запись на 300 символов разор бы вёрстку
        r = dc.parse_spf(['v=spf1 ' + ' '.join(f'ip4:10.0.{i}.1' for i in range(40)) + ' -all'])
        assert len(r['detail']) < 120 and r['detail'].endswith('…')


class TestDkimParsing:
    def test_normal_key_is_ok(self):
        r = dc.parse_dkim(f'dkim._domainkey.ex.com|{DKIM_1024}', 'ex.com')
        assert r['status'] == 'ok' and r['selectors'] == ['dkim']

    @pytest.mark.parametrize('selector', ['dkim', 'default', 'mail', 's1'])
    def test_panel_and_mta_selectors_are_found(self, selector):
        # Смысл списка селекторов: «DKIM нет» можно сказать только перебором.
        # У FASTPANEL dkim, у ISPmanager/opendkim default, у rspamd свои.
        r = dc.parse_dkim(f'{selector}._domainkey.ex.com|{DKIM_1024}', 'ex.com')
        assert r['status'] == 'ok' and r['selectors'] == [selector]

    def test_silence_lists_how_many_selectors_were_looked_up(self):
        # Оператор обязан видеть, что проверяли не одно имя: иначе он решит,
        # что программа «просто не нашла» его селектор
        r = dc.parse_dkim('', 'ex.com')
        assert r['status'] == 'bad'
        assert f'{len(dc.MAIL_AUTH_SELECTORS)}' in r['detail']

    def test_empty_p_is_a_revoked_key_not_a_record(self):
        r = dc.parse_dkim(f'dkim._domainkey.ex.com|{DKIM_REVOKED}', 'ex.com')
        assert r['status'] == 'bad' and 'отозван' in r['detail']

    def test_key_rotation_keeps_the_live_key(self):
        # Ротация: отозванный ключ — первая TXT, боевой — вторая строка БЕЗ
        # имени селектора. Без «якоря» домен выглядел бы «ключ отозван».
        out = f'dkim._domainkey.ex.com|{DKIM_REVOKED}\n' + DKIM_1024
        r = dc.parse_dkim(out, 'ex.com')
        assert r['status'] == 'ok' and r['selectors'] == ['dkim']

    def test_foreign_record_resets_the_anchor(self):
        # Чужой домен в том же выводе не имеет права приписать свой ключ нашим
        out = (f'old._domainkey.other.com|{DKIM_REVOKED}\n'
               f'dkim._domainkey.ex.com|{DKIM_1024}')
        r = dc.parse_dkim(out, 'ex.com')
        assert r['selectors'] == ['dkim'] and r['revoked'] == []

    def test_short_key_is_warn(self):
        r = dc.parse_dkim(f'mail._domainkey.ex.com|{DKIM_512}', 'ex.com')
        assert r['status'] == 'warn' and '1024' in r['detail']

    def test_chunked_key_is_joined_into_one(self):
        # TXT длиннее 255 символов dig печатает кусками в кавычках: без склейки
        # ключ выглядел бы оборванным, а хвост записи — отсутствующим
        rec = '"v=DKIM1; k=rsa; p=' + 'A' * 150 + '" "B' * 1 + 'B' * 99 + '"'
        r = dc.parse_dkim('dkim._domainkey.ex.com|' + rec, 'ex.com')
        assert r['status'] == 'ok'

    def test_cname_and_foreign_domain_are_ignored(self):
        assert dc.parse_dkim('dkim._domainkey.ex.com|dkim.example.net.',
                             'ex.com')['status'] == 'bad'
        assert dc.parse_dkim(f'dkim._domainkey.OTHER.com|{DKIM_1024}',
                             'ex.com')['status'] == 'bad'

    def test_selector_case_is_normalised(self):
        r = dc.parse_dkim(f'DKIM._DOMAINKEY.EX.COM|{DKIM_1024}', 'EX.com')
        assert r['selectors'] == ['dkim']


class TestDmarcParsing:
    def test_missing_dmarc_is_warn_not_bad(self):
        # RFC 7489 — рекомендация: без DMARC письма ходят. ❌ за это рисовать
        # нельзя, иначе оператор побеждает несуществующую проблему.
        assert dc.parse_dmarc([])['status'] == 'warn'

    def test_reject_with_reports_is_ok(self):
        r = dc.parse_dmarc(['v=DMARC1; p=reject; rua=mailto:dmarc@ex.com'])
        assert r['status'] == 'ok' and r['policy'] == 'reject'

    def test_none_policy_is_monitoring_only(self):
        r = dc.parse_dmarc(['v=DMARC1; p=none'])
        assert r['status'] == 'warn' and 'наблюдение' in r['detail']

    def test_strict_policy_without_rua_warns(self):
        # Письма уже отклоняются, а сводок о чужой рассылке оператор не увидит:
        # самая дорогая комбинация — сломанная доставка без диагностики
        r = dc.parse_dmarc(['v=DMARC1; p=quarantine'])
        assert r['status'] == 'warn' and 'rua' in r['detail']

    def test_unknown_policy_is_warn(self):
        r = dc.parse_dmarc(['v=DMARC1; p=quarintine'])      # опечатка оператора
        assert r['status'] == 'warn' and 'не распознан' in r['detail']

    def test_record_without_policy_is_not_applied(self):
        #RFC 7489: тег p обязателен. Выдумать вместо него «p=none» означало бы
        # сказать оператору, что DMARC работает в режиме наблюдения, хотя он не
        # работает вовсе.
        r = dc.parse_dmarc(['v=DMARC1; rua=mailto:x@ex.com'])
        assert r['status'] == 'warn' and r['policy'] == ''
        assert 'обязательного тега p' in r['detail']


class TestMailAuthHelpers:
    def test_ptr_is_normalised(self):
        assert dc.parse_ptr('mail.ex.com.') == 'mail.ex.com'
        assert dc.parse_ptr('  \n  MAIL.Ex.COM.') == 'mail.ex.com'
        assert dc.parse_ptr('') == ''

    def test_first_ipv4_skips_cname(self):
        # PTR спрашивается по адресу. Вернуть CNAME значило бы спросить
        # `dig -x some-cdn.net` и получить неправдоподобное «PTR нет».
        assert dc.first_ipv4('ex.com. 93.184.216.34') == '93.184.216.34'
        assert dc.first_ipv4('cdn.net.') == ''
        assert dc.first_ipv4('999.1.1.1') == ''        # не адрес вовсе
        assert dc.first_ipv4('') == ''

    def test_dns_txt_joins_chunks_and_drops_empty_lines(self):
        assert dc.parse_dns_txt('"v=spf1 ip4:1.2.3.4 " "-all"') == \
            ['v=spf1 ip4:1.2.3.4 -all']
        assert dc.parse_dns_txt('a\n\n  \nb\n') == ['a', 'b']
        assert dc.parse_dns_txt('') == []


class TestWhereTheRecordsAreSeen:
    def test_loopback_resolver_is_disclosed(self):
        c = FakeSSH(routes=[('cat /etc/resolv.conf', 'nameserver 127.0.0.53\n')])
        assert '127.0.0.53' in dc.resolver_view_note(c)

    def test_private_resolver_is_disclosed(self):
        c = FakeSSH(routes=[('cat /etc/resolv.conf', 'nameserver 192.168.1.10\n')])
        assert '192.168.1.10' in dc.resolver_view_note(c)

    def test_public_resolver_is_silent(self):
        # Публичный резолвер видит интернет — пугать оператора локальными зонами
        # не за что
        c = FakeSSH(routes=[('cat /etc/resolv.conf', 'nameserver 1.1.1.1\n')])
        assert dc.resolver_view_note(c) == ''

    def test_unreadable_resolv_conf_is_silent(self):
        # Не знаем — не выдумываем: пустая строка значит «никакой пометки»
        assert dc.resolver_view_note(FakeSSH()) == ''

    def test_own_zone_adds_the_outside_check_command(self):
        note = dc.zone_view_note('ex.com', {'ex.com'})
        assert 'локальное содержимое' in note
        assert 'dig +short TXT ex.com @1.1.1.1' in note

    def test_subdomain_of_own_zone_is_caught(self):
        assert dc.zone_view_note('mail.ex.com', {'ex.com'}) != ''

    def test_foreign_zone_is_silent(self):
        assert dc.zone_view_note('ex.com', {'other.tld'}) == ''


class TestMailAuthCommands:
    @pytest.mark.parametrize('name', MAIL_AUTH_COMMANDS)
    def test_command_is_valid_shell(self, name):
        cmd = getattr(dc, name)('ex.com')
        shlex.split(cmd)
        proc = subprocess.run(['bash', '-n', '-c', cmd],
                              capture_output=True, text=True)
        assert proc.returncode == 0, f'{name}: {proc.stderr}'

    @pytest.mark.parametrize('name', MAIL_AUTH_COMMANDS)
    def test_evil_domain_stays_one_argument(self, name):
        # Домен приходит из панели и из ввода оператора: кавычка не имеет права
        # рождать вторую команду — q() обязан оставить её частью одного аргумента
        evil = "ex.com'; touch /tmp/PWNED; echo '"
        parts = shlex.split(getattr(dc, name)(evil))
        assert 'touch' not in parts and ';' not in parts

    def test_ptr_command_names_the_address_only(self):
        assert dc.ptr_query_command('1.2.3.4') == 'dig +short -x 1.2.3.4 2>/dev/null'

    def test_dkim_loops_over_every_known_selector(self):
        # Одна команда обязана покрыть все селекторы панелей и MTA: иначе
        # «DKIM нет» останется правдой только для одного из них
        cmd = dc.dkim_query_command('ex.com')
        for sel in dc.MAIL_AUTH_SELECTORS:
            assert f'{sel}._domainkey.ex.com' in cmd

    def test_record_names_are_the_rfc_positions(self):
        # SPF — на самом домене, DMARC — на _dmarc (RFC 7489), DKIM — на
        # <selector>._domainkey: спросить не там значит соврать про «записи нет»
        assert dc.spf_query_command('ex.com').startswith('dig +short TXT ex.com')
        assert '_dmarc.ex.com' in dc.dmarc_query_command('ex.com')
        assert '._domainkey.ex.com' in dc.dkim_query_command('ex.com')


class TestMailAuthReport:
    def test_two_domains_worst_first(self):
        c = FakeSSH(routes=[
            ('mgrctl -m ispmgr maildomain',
             'name=good.ru elid=1\nname=bad.ru elid=2\n'),
            ('cat /etc/resolv.conf', 'nameserver 1.1.1.1\n'),
            ('dig +short A', '93.184.216.34'),
            ('dig +short -x', 'mail.good.ru.'),
            ('dig +short TXT good.ru', '"v=spf1 ip4:93.184.216.34 -all"'),
            ('dig +short TXT bad.ru', ''),
            ('dig +short TXT _dmarc.good.ru',
             '"v=DMARC1; p=reject; rua=mailto:p@good.ru"'),
            ('dig +short TXT _dmarc.bad.ru', ''),
            ('for __dk in dkim._domainkey.good.ru',
             'dkim._domainkey.good.ru|' + DKIM_1024 + '\n'),
            ('for __dk in dkim._domainkey.bad.ru', ''),
        ])
        out = dc.mail_auth_report(c, 'ispmanager')
        assert '=== ПОЧТА: SPF / DKIM / DMARC / PTR ===' in out
        assert 'Провалено: 1, с замечаниями: 0' in out
        # Оператору нужно «что чинить первым», а не алфавитный список
        assert out.index('bad.ru') < out.index('good.ru')
        assert 'подпись по селектору: dkim' in out
        assert 'Как чинить' in out
        # у чистого приёмника подписи нет намеренно — не выдумываем беду good.ru
        assert 'DMARC ✅' in out

    def test_verdict_is_the_worst_check_not_the_average(self):
        # Три ok и один провал: домен обязан попасть в проваленные, потому что
        # в спам письмо кладёт одна проваленная проверка, а не средняя
        c = FakeSSH(routes=[
            ('mgrctl -m ispmgr maildomain', 'name=mix.ru elid=1\n'),
            ('dig +short A', '93.184.216.34'),
            ('dig +short -x', ''),                                  # PTR нет
            ('dig +short TXT mix.ru', '"v=spf1 ip4:93.184.216.34 -all"'),
            ('dig +short TXT _dmarc.mix.ru',
             '"v=DMARC1; p=reject; rua=mailto:p@mix.ru"'),
            ('for __dk in dkim._domainkey.mix.ru',
             'dkim._domainkey.mix.ru|' + DKIM_1024 + '\n'),
        ])
        out = dc.mail_auth_report(c, 'ispmanager')
        assert 'Провалено: 1' in out
        assert 'обратной записи нет' in out

    def test_limit_and_counters(self):
        rows = ''.join(f'name=mx{i}.tld elid={i}\n' for i in range(60))
        c = FakeSSH(routes=[('mgrctl -m ispmgr maildomain', rows)])
        out = dc.mail_auth_report(c, 'ispmanager')
        assert 'Проверено доменов: 25 из 60' in out
        assert 'проверены первые 25 из 60' in out

    def test_price_is_bounded_and_ptr_needs_an_address(self):
        # Без лимита прогон по сотне доменов вешал бы окно на минуты. У этих
        # доменов нет A-записи, поэтому PTR не спрашивается: 4 команды на домен.
        rows = ''.join(f'name=mx{i}.tld elid={i}\n' for i in range(30))
        c = FakeSSH(routes=[('mgrctl -m ispmgr maildomain', rows)])
        dc.mail_auth_report(c, 'ispmanager')
        assert c.count('dig ') == 4 * dc.HEALTH_CHECK_LIMIT

    def test_ptr_is_not_invented_without_an_address(self):
        # Без A-записи спрашивать -x нечего; рисовать ❌ «PTR нет» было бы враньём
        c = FakeSSH(routes=[('mgrctl -m ispmgr maildomain',
                             'name=only.ru elid=1\n')])
        out = dc.mail_auth_report(c, 'ispmanager')
        assert 'PTR не проверен' in out
        assert c.count('dig +short -x') == 0

    def test_local_zone_and_local_resolver_are_disclosed(self):
        # Главная ложь, которую обязан закрывать отчёт: «SPF есть» по записи из
        # локальной зоны, которой нет в интернете
        c = FakeSSH(routes=[
            ('mgrctl -m ispmgr maildomain', 'name=ex.com elid=1\n'),
            ('mgrctl -m ispmgr dnszone', 'name=ex.com elid=9\n'),
            ('cat /etc/resolv.conf', 'nameserver 10.0.0.5\n'),
        ])
        out = dc.mail_auth_report(c, 'ispmanager')
        assert 'локальное содержимое' in out
        assert '10.0.0.5' in out
        assert '@1.1.1.1' in out

    def test_public_resolver_adds_no_fear_note(self):
        c = FakeSSH(routes=[
            ('mgrctl -m ispmgr maildomain', 'name=ex.com elid=1\n'),
            ('cat /etc/resolv.conf', 'nameserver 8.8.8.8\n'),
        ])
        out = dc.mail_auth_report(c, 'ispmanager')
        assert 'локальное содержимое' not in out and '@1.1.1.1' not in out

    def test_no_mail_domains_says_so(self):
        out = dc.mail_auth_report(FakeSSH(), 'none')
        assert 'Почтовые домены не найдены' in out


class TestMailAuthLines:
    def test_five_queries_per_domain_when_address_is_known(self):
        c = FakeSSH(routes=[('dig +short A', '93.184.216.34'),
                            ('dig +short -x', 'mail.ex.com.')])
        verdict, _lines, ip, _state = dc.mail_auth_lines(c, 'ex.com')
        assert ip == '93.184.216.34'
        assert c.count('dig ') == 5          # A, SPF, DMARC, DKIM, PTR
        assert verdict in dc.AUTH_SEVERITY

    def test_no_ptr_query_without_an_address(self):
        c = FakeSSH()
        _v, _l, ip, _state = dc.mail_auth_lines(c, 'ex.com')
        assert ip == '' and c.count('dig +short -x') == 0

    def test_header_can_be_hidden_for_embedded_use(self):
        # В «Досье домена» домен уже написан в шапке отчёта — строку со статусами
        # того же домена дублировать не нужно
        _v, with_header, _ip, _s = dc.mail_auth_lines(FakeSSH(), 'ex.com')
        _v, no_header, _ip, _s = dc.mail_auth_lines(FakeSSH(), 'ex.com',
                                                    header=False)
        assert len(no_header) < len(with_header)
        assert any(l.lstrip().startswith('ex.com') for l in with_header)
        assert not any(l.lstrip().startswith('ex.com') for l in no_header)

    def test_note_is_printed_once(self):
        _v, lines, _ip, _s = dc.mail_auth_lines(FakeSSH(), 'ex.com',
                                                note='ЗОНА ЛОКАЛЬНАЯ')
        assert sum(1 for l in lines if 'ЗОНА ЛОКАЛЬНАЯ' in l) == 1

    def test_verify_state_is_not_claimed_without_a_check(self):
        # Сверки не было (резолвера не передавали) — состояние пустое. Если бы
        # здесь вернулся 'same', сводка написала бы «расхождений нет» про домен,
        # который никто с интернетом не сверял.
        _v, _l, _ip, state = dc.mail_auth_lines(FakeSSH(), 'ex.com')
        assert state == ''


class TestSpfSuggestionBasis:
    """Основание SPF-подсказки обязано описывать ровно то, что в строке.

    Здесь заперта ложь, которую прогон вскрыл в первой же версии: запись
    `v=spf1 a mx ~all` подписывалась словами «из A-записи домена», хотя A-записи
    не было. Оператор такую подпись проглатывает не глядя и копирует строку в
    зону — а неверная SPF ломает доставку всего домена.
    """

    @pytest.mark.parametrize('ip,mech', [
        ('93.184.216.34', 'ip4:93.184.216.34'),
        ('', 'a'),
        ('10.0.0.5', 'a'),
        ('192.168.1.20', 'a'),
        ('172.20.0.3', 'a'),
        ('127.0.0.1', 'a'),
    ])
    def test_mechanism_matches_what_is_known(self, ip, mech):
        assert dc.spf_basis(ip)[0] == mech
        assert dc.spf_suggestion(ip) == f'v=spf1 {mech} mx ~all'

    def test_public_address_is_declared_as_coming_from_the_a_record(self):
        assert 'взят из A-записи' in dc.spf_basis('93.184.216.34')[1]

    def test_without_an_address_the_hint_does_not_claim_one(self):
        note = dc.spf_basis('')[1]
        assert 'не получена' in note and 'взят из A-записи' not in note

    def test_private_address_is_not_offered_as_ip4(self):
        # Публичный SPF с ip4:10.0.0.5 не совпадёт ни с одной сессией: приёмник
        # смотрит на адрес TCP-сессии. Предложить его = выдать мёртвую запись.
        mech, note = dc.spf_basis('10.0.0.5')
        assert mech == 'a' and 'ip4:10.0.0.5' not in dc.spf_suggestion('10.0.0.5')
        assert 'приватный' in note

    def test_start_is_softfail_not_hardfail(self):
        # -all отклоняет письма CRM/рассылок, которых оператор ещё не знает.
        # Проходить границу «мягко» — осознанная стартовая точка, не финал.
        assert dc.spf_suggestion('1.2.3.4').endswith('~all')


class TestMailAuthFixes:
    """«Что вставить в DNS» — по машинночитаемому reason, а не по тексту.

    Подсказка, привязанная к фразе отчёта, отвалилась бы молча при первом же
    перефразировании и показала бы оператору неверную запись; поэтому ветки
    расходятся по полю reason, и здесь есть тест, который это сторожит.
    """

    @staticmethod
    def _spf_fix(txts, ip='93.184.216.34'):
        """Подсказка про SPF на фоне «остальное в порядке».

        DKIM/DMARC/PTR передаются dict'ами только с 'reason' — заодно гард:
        генератор обязан читать reason и не зависеть от остальных полей.
        """
        return dc.mail_auth_fixes('ex.com', dc.parse_spf(txts),
                                  {'reason': 'ok'}, {'reason': 'ok'},
                                  'ok', ip=ip)

    @staticmethod
    def _dkim_fix(dkim_out, ip='1.2.3.4'):
        return dc.mail_auth_fixes('ex.com', {'reason': 'ok'},
                                  dc.parse_dkim(dkim_out, 'ex.com'),
                                  {'reason': 'ok'}, 'ok', ip=ip)

    @staticmethod
    def _dmarc_fix(txts, ip='1.2.3.4'):
        return dc.mail_auth_fixes('ex.com', {'reason': 'ok'}, {'reason': 'ok'},
                                  dc.parse_dmarc(txts), 'ok', ip=ip)

    # ---------- привязка к reason, а не к формулировке ----------
    def test_hint_follows_reason_not_the_wording(self):
        # Формулировку отчёта мы правим ради читаемости. Если бы генератор
        # разбирал detail, после такого правки подсказка отвалилась бы МОЛЧА.
        spf = dc.parse_spf([])
        spf['detail'] = 'СОВСЕМ ДРУГОЙ ТЕКСТ ОТЧЁТА'
        fixes = dc.mail_auth_fixes('ex.com', spf, {'reason': 'ok'},
                                   {'reason': 'ok'}, 'ok', ip='1.2.3.4')
        assert fixes and 'v=spf1 ip4:1.2.3.4 mx ~all' in fixes[0]

    def test_every_spf_reason_has_its_own_advice(self):
        cases = [
            ([], 'missing', 'добавить TXT'),
            (['v=spf ip4:1.1.1.1'], 'broken_version', 'с единицей'),
            (['v=spf1 -all', 'v=spf1 ~all'], 'duplicate', 'ровно одну'),
            (['v=spf1 ' + ' '.join(f'include:d{i}.ru' for i in range(12)) + ' -all'],
             'too_many_lookups', 'DNS-запросов'),
            (['v=spf1 +all'], 'plus_all', '~all'),
            (['v=spf1 ip4:1.1.1.1'], 'no_mechanism', 'дописать'),
        ]
        for txts, reason, needle in cases:
            parsed = dc.parse_spf(txts)
            assert parsed['reason'] == reason, reason
            fixes = self._spf_fix(txts)
            assert len(fixes) == 1 and needle in fixes[0], reason

    def test_healthy_spf_gets_no_advice(self):
        assert self._spf_fix(['v=spf1 ip4:1.1.1.1 -all']) == []

    # ---------- SPF: формат записи живёт в одном месте ----------
    @pytest.mark.parametrize('ip', ['93.184.216.34', '', '10.0.0.5'])
    def test_record_in_the_hint_is_exactly_spf_suggestion(self, ip):
        # Оператор копирует в зону СТРОКУ из подсказки. Если подсказка пересоберёт
        # её у себя, в зоне окажется не та запись, которую мы объяснили.
        fixes = self._spf_fix([], ip=ip)
        printed = fixes[0].split('\u201e')[1].split('\u201c')[0]
        assert printed == dc.spf_suggestion(ip)

    def test_private_ip_hint_never_offers_a_dead_record(self):
        fixes = self._spf_fix([], ip='10.0.0.5')
        assert 'ip4:10.0.0.5' not in fixes[0]

    # ---------- DKIM: готовой записи не бывает ----------
    @pytest.mark.parametrize('dkim_out', [
        '',                                                # missing
        'dkim._domainkey.ex.com|v=DKIM1; k=rsa; p=',      # revoked
        'dkim._domainkey.ex.com|v=DKIM1; k=rsa; p=' + 'A' * 100,   # short
    ])
    def test_dkim_never_prints_a_record(self, dkim_out):
        # Публичный ключ выводится из приватного, который на сервере. Выдуманная
        # «готовая» запись = подпись, которую приёмник отвергнет, а оператор
        # решит, что «всё сделали».
        for fix in self._dkim_fix(dkim_out):
            assert 'v=DKIM1' not in fix

    def test_dkim_advice_shows_where_to_take_the_real_record(self):
        fix = ' '.join(self._dkim_fix(''))
        assert 'готовую запись не даём' in fix
        assert '/etc/rspamd/dkim' in fix and '/etc/opendkim/keys' in fix
        # .key — приватный ключ: публикация его в DNS = полная компрометация
        assert 'никогда не .key' in fix

    def test_revoked_key_is_not_confused_with_a_missing_one(self):
        # Один совет на «нет записи» и «запись есть, но ключ отозван» был бы
        # ошибкой: во втором случае DNS-запись уже стоит и её не надо создавать,
        # надо выпускать новый ключ.
        missing = ' '.join(self._dkim_fix(''))
        revoked = ' '.join(self._dkim_fix('dkim._domainkey.ex.com|v=DKIM1; k=rsa; p='))
        assert 'отозван' in revoked and 'отозван' not in missing

    def test_short_key_advice_names_the_remedy(self):
        fix = ' '.join(self._dkim_fix(
            'dkim._domainkey.ex.com|v=DKIM1; k=rsa; p=' + 'A' * 100))
        assert '2048' in fix
        # «подписки» — бессмыслица, которую дал первый черновик; ключ короткий,
        # а не подписка
        assert 'подписки' not in fix

    # ---------- DMARC: одну запись правят, а не плодят ----------
    def test_missing_dmarc_starts_at_none_with_reports(self):
        fix = ' '.join(self._dmarc_fix([]))
        assert '_dmarc.ex.com' in fix and 'p=none' in fix
        assert 'rua=mailto:dmarc@ex.com' in fix

    def test_existing_weak_dmarc_is_not_replaced_by_a_second_record(self):
        # Подсказка про p=none при уже существующей записи оператор понял бы как
        # «добавить ещё одну», а две DMARC-записи — это не DMARC.
        for txts in (['v=DMARC1; p=none'], ['v=DMARC1; p=reject']):
            for fix in self._dmarc_fix(txts):
                assert 'v=DMARC1' not in fix, txts

    def test_monitoring_policy_is_not_called_a_failure(self):
        # p=none — осознанный первый шаг, а не беда: совет должен объяснять,
        # когда поднимать режим, а не требовать reject сразу.
        fix = ' '.join(self._dmarc_fix(['v=DMARC1; p=none; rua=mailto:a@b.c']))
        assert 'сводки' in fix and 'quarantine' in fix

    def test_record_without_policy_tag_is_told_to_add_p(self):
        fix = ' '.join(self._dmarc_fix(['v=DMARC1; rua=mailto:a@b.c']))
        assert 'тег p' in fix

    # ---------- PTR ----------
    def test_missing_ptr_points_at_the_address_owner(self):
        fixes = dc.mail_auth_fixes('ex.com', {'reason': 'ok'}, {'reason': 'ok'},
                                   {'reason': 'ok'}, 'bad', ip='203.0.113.7')
        assert len(fixes) == 1 and '203.0.113.7' in fixes[0]
        assert 'хостер' in fixes[0] and 'панели' in fixes[0]

    def test_unchecked_ptr_invents_no_advice(self):
        # PTR не проверялся (не было IPv4) — советовать нечего, и выдуманная
        # «обратная запись для » была бы враньём.
        fixes = dc.mail_auth_fixes('ex.com', {'reason': 'ok'}, {'reason': 'ok'},
                                   {'reason': 'ok'}, 'warn', ip='')
        assert fixes == []

    def test_clean_domain_gets_no_advice_at_all(self):
        fixes = dc.mail_auth_fixes('ex.com', {'reason': 'ok'}, {'reason': 'ok'},
                                   {'reason': 'ok'}, 'ok', ip='1.2.3.4')
        assert fixes == []


class TestMailAuthHintsInReports:
    def test_hints_are_printed_after_checks_and_only_where_broken(self):
        # Третье поле — состояние сверки; здесь его не проверяют (сверки нет),
        # но распаковка обязана соответствовать возврату, иначе тест упадёт на
        # «too many values», а не на смысле.
        _v, lines, _state = dc.summarize_mail_auth('bad.ru', '', '', '', '',
                                                  ip='93.184.216.34')
        # Ищем именно строку диагноза PTR, а не заголовок со статусами (в нём
        # «PTR» тоже есть, и первое вхождение было бы тривиально верным).
        ptr_line = next(i for i, l in enumerate(lines)
                        if l.lstrip().startswith('PTR'))
        hint_line = next(i for i, l in enumerate(lines) if l.lstrip().startswith('→'))
        assert hint_line > ptr_line               # сначала диагноз, потом совет
        # Четыре беды — четыре совета: SPF, DKIM, DMARC и PTR. Пустых советов
        # («всё хорошо») здесь быть не должно.
        assert sum(1 for l in lines if l.lstrip().startswith('→')) == 4

    def test_configured_domain_prints_no_hints(self):
        good = 'v=DKIM1; k=rsa; p=' + 'A' * 216
        _v, lines, _state = dc.summarize_mail_auth(
            'good.ru', '"v=spf1 ip4:1.2.3.4 -all"',
            '"v=DMARC1; p=reject; rua=mailto:p@good.ru"',
            'dkim._domainkey.good.ru|' + good + '\n',
            'mail.good.ru.', ip='1.2.3.4')
        assert not any('→' in l for l in lines)

    def test_hints_cost_no_extra_dns_queries(self):
        # Подсказки строятся из уже полученных ответов (в т.ч. из A-записи):
        # совет, который стоит ещё одного запроса на домен, удвоил бы цену прогона.
        c = FakeSSH(routes=[('dig +short A', '93.184.216.34')])
        _v, lines, _ip, _state = dc.mail_auth_lines(c, 'ex.com')
        assert any(l.lstrip().startswith('→') for l in lines)
        # A, SPF, DMARC, DKIM, PTR — ровно те же пять, что и без подсказок
        assert c.count('dig ') == 5

    def test_report_carries_the_hint_for_the_broken_domain(self):
        c = FakeSSH(routes=[
            ('mgrctl -m ispmgr maildomain', 'name=bad.ru elid=1\n'),
            ('cat /etc/resolv.conf', 'nameserver 1.1.1.1\n'),
            ('dig +short A', '93.184.216.34'),
            ('dig +short -x', ''),
        ])
        out = dc.mail_auth_report(c, 'ispmanager')
        assert '→ SPF: добавить TXT „v=spf1 ip4:93.184.216.34 mx ~all“' in out
        assert '→ PTR: запросить обратную запись для 93.184.216.34' in out
        # DKIM остаётся зоной честности: готовую TXT-signature отчёт не печатает
        assert 'v=DKIM1' not in out


# ---------- внешняя сверка с публичным DNS ----------
# Здесь заперты грабли, которые вскрыл живой прогон dig, а не догадки:
#  - резолвер задаётся ТОЛЬКО через @server: positional-форма (`dig A name
#    1.1.1.1`) адрес сервером не считает, запрос уходил на местный резолвер и
#    отвечал за 0.0 с даже при заведомо мёртвом IP — «сверка извне» печатала бы
#    локальную зону с подписью «из интернета»;
#  - пустой вывод при недоступном резолвере неотличим от честного «записей
#    нет», поэтому решение принимает rc из самой команды;
#  - непроверенное не имеет права печататься как «в порядке».

def _verify_routes(spf='"v=spf1 ip4:10.0.0.5 -all"',
                   dmarc='"v=DMARC1; p=reject; rua=mailto:p@lie.ru"',
                   dkim=DKIM_1024, ip='10.0.0.5', ptr='mail.lie.ru.',
                   ext_spf='rc=0\n', ext_dmarc='rc=0\n', ext_ptr='rc=0\n',
                   ext_ip='93.184.216.34\nrc=0\n', ext_rc='rc=0\n',
                   probe='198.41.0.4\n', rows='name=lie.ru elid=1\n'):
    """Маршрут «локально всё зелёное, извне — пусто».

    Порядок игл важен: внешние запросы содержат '@1.1.1.1', локальные — нет,
    поэтому внешние стоят раньше и не перехватываются общими иглами.
    """
    return [
        ('mgrctl -m ispmgr maildomain', rows),
        ('cat /etc/resolv.conf', 'nameserver 127.0.0.53\n'),
        ('a.root-servers.net', probe),                 # probe жив
        ('__bad=0', ext_rc),                           # внешний DKIM-цикл
        ('A lie.ru @', ext_ip),                        # внешняя A
        ('TXT _dmarc.lie.ru @', ext_dmarc),
        ('TXT lie.ru @', ext_spf),
        ('-x 93.184.216.34 @', ext_ptr),
        ('@1.1.1.1', 'rc=0\n'),                        # прочий внешний запрос
        ('dig +short TXT lie.ru', spf + '\n'),
        ('dig +short TXT _dmarc.lie.ru', dmarc + '\n'),
        ('dig +short A lie.ru', ip + '\n'),
        ('-x ' + ip, ptr + '\n'),
        ('for __dk', f'dkim._domainkey.lie.ru|{dkim}\n'),
    ]


def _diff_lines(out):
    """Строки «🌐» как таковые.

    Считать просто `'🌐' in line` нельзя: символ встречается и в пометке
    «сверка с публичным DNS: см. строки «🌐»», и тест засчитал бы её за
    расхождение (проверено на живом прогоне).
    """
    return [l for l in out.splitlines() if l.lstrip().startswith('🌐')]


def _fix_lines(out, kind):
    return [l for l in out.splitlines() if l.lstrip().startswith('→ ' + kind)]


class TestExternalVerifyCommands:
    """Команды сверки: резолвер, rc и защита от сырого имени."""

    def test_resolver_is_passed_with_at_sign(self):
        # Без @ dig считает адрес ещё одним ИМЕНЕМ и спрашивает местный
        # резолвер: проверка «извне» показывала бы локальную зону.
        cmd = dc.external_query_command('TXT', 'ex.com')
        assert 'TXT ex.com @1.1.1.1' in cmd
        assert 'TXT ex.com 1.1.1.1' not in cmd

    def test_answer_code_is_printed(self):
        # Без rc пустой вывод при недоступном резолвере = «записей нет», и
        # сверка сама стала бы источником лжи.
        assert 'rc=' in dc.external_query_command('TXT', 'ex.com')
        assert 'rc=' in dc.external_dkim_query_command('ex.com')

    def test_dkim_flag_covers_the_whole_loop(self):
        # Код последней команды цикла ничего не говорит о предыдущих: одна
        # таймаутная итерация выглядела бы как «извне записей нет».
        cmd = dc.external_dkim_query_command('ex.com')
        assert '__bad' in cmd and '|| __bad=1' in cmd

    def test_probe_asks_a_name_that_must_exist(self):
        # Пустой ответ от 1.1.1.1 значит «мы не у дел», а не «интернет есть».
        assert dc.EXTERNAL_PROBE_NAME in dc.external_probe_command()
        assert '@1.1.1.1' in dc.external_probe_command()

    @pytest.mark.parametrize('rtype', ['rm -rf /', 'TXT; touch /tmp/PWNED', ''])
    def test_raw_query_type_is_refused(self, rtype):
        # rtype попадает в команду НЕ через q(): список разрешённых типов —
        # единственная преграда на пути сырого имени в shell.
        with pytest.raises(ValueError):
            dc.external_query_command(rtype, 'ex.com')

    @pytest.mark.parametrize('rtype', dc.EXTERNAL_QUERY_TYPES)
    def test_allowed_types_are_valid_shell(self, rtype):
        cmd = dc.external_query_command(rtype, 'ex.com')
        shlex.split(cmd)
        proc = subprocess.run(['bash', '-n', '-c', cmd],
                              capture_output=True, text=True)
        assert proc.returncode == 0, proc.stderr

    def test_evil_domain_stays_one_argument(self):
        evil = "ex.com'; touch /tmp/PWNED; echo '"
        for cmd in (dc.external_query_command('TXT', evil),
                    dc.external_dkim_query_command(evil),
                    dc.external_probe_command()):
            parts = shlex.split(cmd)
            assert 'touch' not in parts and ';' not in parts


class TestParseExternalAnswer:
    """Разбор вывода сверки: rc и мусор, который dig пишет в stdout."""

    def test_empty_answer_with_rc0_is_a_real_empty_zone(self):
        assert dc.parse_external_answer('rc=0\n') == ('', 0)

    def test_values_are_kept_and_rc_removed(self):
        text, rc = dc.parse_external_answer('"v=spf1 -all"\nrc=0\n')
        assert text == '"v=spf1 -all"' and rc == 0

    def test_unreachable_resolver_is_not_an_empty_zone(self):
        # Проверено живым dig: при недоступном резолвере ошибка летит в STDOUT
        # (2>/dev/null не спасает), и без отсечения ушла бы в парсер TXT.
        out = (';; communications error to 1.1.1.1#53: timed out\n'
               ';; no servers could be reached\nrc=9\n')
        text, rc = dc.parse_external_answer(out)
        assert text == '' and rc == 9

    def test_error_tail_after_selector_name_is_cut(self):
        # В DKIM-цикле имя печатается до запроса, поэтому ошибка приклеена к
        # нему: парсер не должен увидеть «;;» значением записи.
        out = ('dkim._domainkey.ex.com|;; communications error\n'
               ';; no servers could be reached\nrc=1\n')
        text, rc = dc.parse_external_answer(out)
        assert ';;' not in text and rc == 1

    def test_missing_rc_means_no_answer(self):
        assert dc.parse_external_answer('"v=spf1 -all"\n')[1] is None

    def test_garbage_rc_is_not_an_answer(self):
        assert dc.parse_external_answer('rc=нет\n')[1] is None


class TestPublicResolverProbe:
    def test_first_answering_resolver_is_chosen(self):
        c = FakeSSH(routes=[('dig +short A', '198.41.0.4\n')])
        assert dc.public_resolver(c) == dc.PUBLIC_RESOLVERS[0]

    def test_dead_resolvers_mean_no_verification(self):
        assert dc.public_resolver(FakeSSH()) == ''

    def test_garbage_answer_is_not_liveness(self):
        # «Резолвер жив» обязан означать ответ-адрес: иначе любой мусор в
        # stdout сошёл бы за подтверждение, и сверка началась бы вслепую.
        c = FakeSSH(routes=[('dig +short A', 'connection refused\n')])
        assert dc.public_resolver(c) == ''

    def test_probe_is_one_command_per_resolver(self):
        c = FakeSSH()
        dc.public_resolver(c)
        assert c.count('dig ') == len(dc.PUBLIC_RESOLVERS)


class TestExternalVerification:
    """Главный смысл слайса: локальная зона не может врать безнаказанно."""

    def test_local_lie_is_exposed_and_verdict_follows_the_public_view(self):
        # Локально всё зелёное (приватный ip4 из локальной зоны, локальный PTR),
        # публичная зона пуста. Именно тут старый отчёт врал: «SPF ✅».
        c = FakeSSH(routes=_verify_routes())
        out = dc.mail_auth_report(c, 'ispmanager')
        assert 'Провалено: 1, с замечаниями: 0' in out
        assert '[извне]' in out
        # Пересчёт гарда осознанный: сверху добавилась групповая сводка, и она
        # тоже начинается с «🌐». Оставить «== 4» означало бы, что сводка
        # пришла бы как «позеленевший» тест; ослабить хелпер — потерять смысл.
        # Поэтому считаем раздельно: одна сводка сверху и ровно по одной
        # телесной строке на каждую из четырёх проверок.
        diffs = _diff_lines(out)
        assert len(diffs) == 5
        assert sum(1 for l in diffs if l.startswith('🌐 Расходится')) == 1
        assert sum(1 for l in diffs if 'извне' in l) == 4   # SPF, DKIM, DMARC, PTR
        assert 'TXT-записей у домена нет вообще' in out

    def test_local_lines_stay_printed(self):
        # По локальным строкам ищут, где именно зона разошлась: убрать их —
        # значит оставить оператора с двумя правками в двух местах.
        c = FakeSSH(routes=_verify_routes())
        out = dc.mail_auth_report(c, 'ispmanager')
        assert 'подпись по селектору: dkim' in out     # локальный DKIM
        assert 'v=spf1 ip4:10.0.0.5 -all' in out       # локальный SPF

    def test_hints_use_the_public_a_record_not_the_private_one(self):
        # Локальная A показывает 10.0.0.5: в публичном SPF такой ip4 не
        # совпадёт ни с одной сессией. Основанием обязан стать внешний ответ.
        c = FakeSSH(routes=_verify_routes())
        out = dc.mail_auth_report(c, 'ispmanager')
        hint = _fix_lines(out, 'SPF')[0]
        assert 'ip4:93.184.216.34' in hint and 'ip4:10.0.0.5' not in hint

    def test_hint_follows_the_public_record_not_the_local_one(self):
        # Локально «+all» (беда), публично запись правильная: совет «чините
        # +all» был бы выдуманной бедой — приёмник-то видит вторую запись.
        c = FakeSSH(routes=_verify_routes(
            spf='"v=spf1 +all"',
            ext_spf='"v=spf1 ip4:93.184.216.34 -all"\nrc=0\n'))
        out = dc.mail_auth_report(c, 'ispmanager')
        assert not _fix_lines(out, 'SPF')

    def test_public_problem_gets_the_hint_even_when_local_is_clean(self):
        c = FakeSSH(routes=_verify_routes(
            spf='"v=spf1 ip4:10.0.0.5 -all"', ext_spf='"v=spf1 +all"\nrc=0\n'))
        out = dc.mail_auth_report(c, 'ispmanager')
        assert _fix_lines(out, 'SPF')
        assert '+all' in _fix_lines(out, 'SPF')[0]

    def test_dkim_record_is_never_printed_after_verification(self):
        # Граница честности не зависит от появления второго источника: TXT
        # выводится из приватного ключа, которого нет ни локально, ни «извне».
        c = FakeSSH(routes=_verify_routes())
        out = dc.mail_auth_report(c, 'ispmanager')
        assert 'v=DKIM1' not in out

    def test_identical_zones_say_so_instead_of_staying_silent(self):
        c = FakeSSH(routes=_verify_routes(
            ip='93.184.216.34',
            spf='"v=spf1 ip4:93.184.216.34 -all"',
            ext_spf='"v=spf1 ip4:93.184.216.34 -all"\nrc=0\n',
            ext_dmarc='"v=DMARC1; p=reject; rua=mailto:p@lie.ru"\nrc=0\n',
            ext_ptr='mail.lie.ru.\nrc=0\n',
            ext_rc=f'dkim._domainkey.lie.ru|{DKIM_1024}\nrc=0\n'))
        out = dc.mail_auth_report(c, 'ispmanager')
        assert 'публичные записи совпадают' in out
        assert len(_diff_lines(out)) == 1              # ровно одно сообщение
        # Держим гард словами: групповая фраза «расхождений нет» запрещена,
        # потому что то же самое уже напечатано в теле (и там назван резолвер).
        # Повтор оператор читает как невнимательность и перестаёт доверять.
        assert 'Расходится с публичной зоной' not in out
        assert 'Расхождений с публичной зоной нет' not in out
        assert 'Провалено: 0, с замечаниями: 0' in out

    def test_price_of_verification(self):
        # 1 probe + 5 локальных + 5 внешних. Ценой сверки нельзя делать
        # удвоение времени прогона по всем доменам: gate решает, кому сверять.
        c = FakeSSH(routes=_verify_routes())
        dc.mail_auth_report(c, 'ispmanager')
        assert c.count('dig ') == 11

    def test_probe_is_asked_once_per_run_not_per_domain(self):
        rows = 'name=lie.ru elid=1\nname=two.ru elid=2\n'
        c = FakeSSH(routes=_verify_routes(rows=rows))
        dc.mail_auth_report(c, 'ispmanager')
        assert c.count('a.root-servers.net') == 1


class TestVerifySummary:
    """Масштаб беды — до чтения списка доменов.

    При 25 доменах оператор обязан узнать «у 4 зона расходится с интернетом»
    первой строкой: это ответ на решение «править зону централизованно» либо
    «разбираться по доменам». Считается СОСТОЯНИЕМ сверки каждого домена, а не
    символом «🌐» в тексте: этот символ печатается в трёх несходных случаях —
    «разошлось», «совпало», «сверить не удалось» — и подсчёт по подстроке дал бы
    число, которого нет.
    """

    # ---------- чистая функция: счётчик по состоянию ----------
    def test_diverged_line_carries_the_verified_denominator(self):
        # «4» без «из скольких сверено» было бы манипуляцией: 4 расхождения при
        # одном сверенном домене и при двадцати — разный масштаб работ.
        out = '\n'.join(dc.mail_auth_verify_lines(diverged=4, same=21))
        assert 'Расходится с публичной зоной: 4 (сверено доменов: 25)' in out
        assert 'по ПУБЛИЧНОЙ зоне' in out

    def test_matches_get_no_summary_line(self):
        # Ветка «совпало» запрещена запертым гардом «ровно одно сообщение»: в
        # теле каждого домена уже напечатано «публичные записи совпадают» — там
        # назван и резолвер. Повтор оператор читает как невнимательность.
        assert dc.mail_auth_verify_lines(diverged=0, same=25) == []

    def test_unverified_is_its_own_line_not_a_clean_verdict(self):
        out = '\n'.join(dc.mail_auth_verify_lines(unverified=12))
        assert 'Сверить с публичной зоной не удалось: 12' in out
        assert 'по ЛОКАЛЬНЫМ данным' in out
        # «не видно», а не «расхождений нет» — иначе сводка сама стала бы
        # источником ложного «в порядке».
        assert '«не видно»' in out
        assert 'dig +short TXT' in out                   # чем проверить вручную

    def test_no_check_at_all_is_silence_not_zero_divergences(self):
        # Сверки не было ни у кого (зоны внешние): «расхождений нет» означало бы
        # «мы проверили и всё чисто», чего мы не проверяли.
        assert dc.mail_auth_verify_lines() == []

    def test_diverged_and_unverified_printed_separately(self):
        out = '\n'.join(dc.mail_auth_verify_lines(diverged=2, same=3,
                                                  unverified=20))
        assert 'Расходится с публичной зоной: 2 (сверено доменов: 5)' in out
        assert 'Сверить с публичной зоной не удалось: 20' in out
        # Числа не складываются: 2 беды и 20 «не видно» — разные решения.
        assert 'не удалось: 22' not in out

    # ---------- интеграция в отчёт ----------
    def test_summary_names_the_scale_above_the_domain_list(self):
        c = FakeSSH(routes=_verify_routes())
        out = dc.mail_auth_report(c, 'ispmanager')
        assert '🌐 Расходится с публичной зоной: 1 (сверено доменов: 1)' in out
        lines = out.splitlines()
        head = next(i for i, l in enumerate(lines) if 'Расходится' in l)
        body = next(i for i, l in enumerate(lines)
                    if l.startswith('lie.ru'))
        assert head < body                   # масштаб — ДО списка, а не после

    def test_summary_counts_only_checked_domains(self):
        # Проверены первые `limit` из большего списка: приписать счётчику
        # домены, которые не проверялись, — соврать про масштаб беды. За limit
        # обязан уйти zzz.ru: фикстура _verify_routes заточена под lie.ru
        # (иглы содержат его имя), а домен с пустой зоной с обеих сторон
        # расхождения не даёт — с «aaa.ru» этот кейс молча проверял не то.
        rows = 'name=lie.ru elid=1\nname=zzz.ru elid=2\n'
        c = FakeSSH(routes=_verify_routes(rows=rows))
        out = dc.mail_auth_report(c, 'ispmanager', limit=1)
        assert 'Проверено доменов: 1 из 2' in out
        assert 'Расходится с публичной зоной: 1 (сверено доменов: 1)' in out
        assert 'сверено доменов: 2' not in out

    def test_unverified_count_is_reported_in_the_header(self):
        c = FakeSSH(routes=_verify_routes(
            ext_rc='', ext_ip='', ext_spf='', ext_dmarc='', ext_ptr=''))
        out = dc.mail_auth_report(c, 'ispmanager')
        assert 'Сверить с публичной зоной не удалось: 1' in out
        assert 'Расходится с публичной зоной' not in out

    def test_summary_costs_no_extra_dns_queries(self):
        # Сводка считается из уже полученных ответов (11 = probe + 5 локальных
        # + 5 внешних, как до появления сводки). Строка, которая стоит ещё
        # одного запроса, удвоила бы цену прогона.
        c = FakeSSH(routes=_verify_routes())
        dc.mail_auth_report(c, 'ispmanager')
        assert c.count('dig ') == 11


class TestUnverifiedIsNotClean:
    """Непроверенное ≠ проваленное, но и ≠ «в порядке»."""

    def test_failed_verification_is_a_warning_not_a_clean_domain(self):
        c = FakeSSH(routes=_verify_routes(
            ext_rc='', ext_ip='', ext_spf='', ext_dmarc='', ext_ptr=''))
        out = dc.mail_auth_report(c, 'ispmanager')
        assert 'Провалено: 0, с замечаниями: 1' in out
        assert '[не сверено]' in out
        assert 'сверить не удалось' in out
        assert 'dig +short TXT lie.ru @1.1.1.1' in out   # чем проверить вручную

    def test_dead_public_resolvers_cost_no_domain_queries(self):
        # Резолверов нет — не тратим 5 запросов на домен вслепую, но и не
        # печатаем домен проверенным.
        c = FakeSSH(routes=_verify_routes(probe=''))
        out = dc.mail_auth_report(c, 'ispmanager')
        assert c.count('a.root-servers.net') == len(dc.PUBLIC_RESOLVERS)
        assert sum(1 for x in c.commands
                   if '@' in x and 'root-servers' not in x) == 0
        assert '[не сверено]' in out
        assert 'Провалено: 0, с замечаниями: 1' in out

    def test_failure_never_softens_a_real_problem(self):
        # Поднимаем только ok → warn: bad обязан остаться bad — понижения
        # строгости отчёт не имеет права делать.
        c = FakeSSH(routes=_verify_routes(spf='', ext_rc='', ext_ip='',
                                          ext_spf='', ext_dmarc='', ext_ptr=''))
        out = dc.mail_auth_report(c, 'ispmanager')
        assert 'Провалено: 1' in out

    # ---------- PTR: «не получили ответ» ≠ «записи нет» ----------
    @pytest.mark.parametrize('ip,name,answered,status', [
        ('', 'anything', True, 'warn'),      # спрашивать нечего
        ('93.184.216.34', '', False, 'warn'),   # запросил, ответа нет
        ('93.184.216.34', '', True, 'bad'),     # честный пустой ответ
        ('93.184.216.34', 'mail.ex.com', True, 'ok'),
    ])
    def test_ptr_has_three_states_not_two(self, ip, name, answered, status):
        # Свести «таймаут» к «пустому ответу» — значит заявить «обратной записи
        # нет» на основании недоступного DNS.
        assert dc._ptr_view(ip, name, answered)[0] == status

    def test_ptr_timeout_is_not_reported_as_a_missing_record(self):
        # Внешняя A получена, а -x упало по таймауту: внешний PTR обязан стать
        # «не проверен», а не ❌.
        c = FakeSSH(routes=_verify_routes(ext_ptr=''))
        out = dc.mail_auth_report(c, 'ispmanager')
        ptr_line = [l for l in _diff_lines(out) if 'PTR' in l]
        assert ptr_line and 'не получен' in ptr_line[0]
        assert '93.184.216.34' in ptr_line[0]
        assert 'обратной записи нет' not in '\n'.join(ptr_line)

    def test_ptr_answered_flag_is_per_query(self):
        # Общий 'answered' PTR не покрывает: он идёт пятым и зависит от внешней A.
        c = FakeSSH(routes=[('-x 1.2.3.4 @', ';; no servers\nrc=9\n'),
                            ('@1.1.1.1', '1.2.3.4\nrc=0\n')])
        ans = dc.external_auth_answers(c, 'ex.com')
        assert ans['answered'] and not ans['ptr_answered']

    def test_no_verification_when_local_view_is_public(self):
        # Внешний резолвер и чужая зона: ложный ✅ невозможен, платить 5
        # запросов и probe не за что.
        routes = [(n, r) for n, r in _verify_routes()
                  if n != 'cat /etc/resolv.conf']
        c = FakeSSH(routes=routes)
        out = dc.mail_auth_report(c, 'ispmanager')
        assert c.count('dig ') == 5
        assert c.count('a.root-servers.net') == 0
        assert '[извне]' not in out and '[не сверено]' not in out


class TestZoneViewNoteAfterVerify:
    def test_manual_command_is_dropped_when_report_already_verified(self):
        note = dc.zone_view_note('ex.com', {'ex.com'}, verified=True)
        assert 'см. строки' in note
        assert 'dig +short TXT' not in note        # работу сделали за оператора

    def test_manual_command_survives_while_verification_is_pending(self):
        assert 'dig +short TXT ex.com @1.1.1.1' in dc.zone_view_note(
            'ex.com', {'ex.com'})

    def test_note_never_claims_a_finished_verification_it_cannot_see(self):
        # verified=True приходит от вызывающего, который знает лишь «резолвер
        # жив»: «выполнена» было бы ложью при отказе ответить по домену.
        assert 'выполнена' not in dc.zone_view_note('ex.com', {'ex.com'},
                                                    verified=True)


class TestDomainDetailMailAuth:
    def test_mail_domain_gets_the_auth_block(self):
        c = FakeSSH(routes=[
            ('cat /etc/postfix/virtual', 'info@ex.com dest@other.tld\n'),
            ('dig +short AAAA', ''),            # раньше 'dig +short A': совпадение по подстроке
            ('dig +short A', '93.184.216.34'),
            ('dig +short -x', 'mail.ex.com'),
            ('dig +short TXT _dmarc.ex.com',
             '"v=DMARC1; p=reject; rua=mailto:p@ex.com"'),
            ('for __dk in dkim._domainkey.ex.com',
             'dkim._domainkey.ex.com|' + DKIM_1024 + '\n'),
            ('dig +short TXT ex.com', '"v=spf1 ip4:93.184.216.34 -all"'),
        ])
        out = dc.domain_detail_report(c, 'ex.com', 'none')
        assert 'DNS-аутентификация отправки' in out
        assert 'подпись по селектору: dkim' in out
        assert 'p=reject, отчёты rua настроены' in out

    def test_web_only_domain_is_not_shamed(self):
        # У чисто веб-домена SPF может не быть намеренно: ❌ напротив него был бы
        # ложным диагнозом, поэтому аутентификацию спрашиваем только у почтового
        c = FakeSSH()
        out = dc.domain_detail_report(c, 'web-only.ru', 'none')
        assert 'не заявлен как почтовый' in out
        assert 'DNS-аутентификация' not in out
        # Спрашивать TXT у домена, который почту не принимает, не за чем
        assert c.count('dig +short TXT') == 0


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


# ============ РОДИТЕЛЬ ЯЩИКА (plid) БЕРЁТСЯ ИЗ ПАНЕЛИ ======================
class TestMailParent:
    """plid — parent list unique identifier, т.е. name элемента maildomain
    (ISPsystem, «Service parameters»). Значит его нельзя вырезать из ввода
    оператора: берём из списка панели — тем написанием, каким его хранит панель.
    """

    def test_canonical_name_comes_from_panel_not_from_input(self):
        # Панель хранит домен «Example.COM»; оператор ввёл lower. Резолв обязан
        # вернуть написание панели — email.edit принимает именно его.
        c = FakeSSH(routes=[('mgrctl -m ispmgr maildomain',
                             'name=Example.COM elid=3\n')])
        name, why = dc.isp_mail_parent(c, 'example.com')
        assert name == 'Example.COM' and why is None

    def test_error_list_is_not_treated_as_empty(self):
        # «Панель ответила ошибкой» и «почтовых доменов нет» — разные ответы.
        # По ошибке резолв запрещён: plid уехал бы наугад.
        c = FakeSSH(routes=[('mgrctl -m ispmgr maildomain',
                             'ERROR: connection refused\n')])
        name, why = dc.isp_mail_parent(c, 'example.com')
        assert name is None
        assert 'Панель не вернула список почтовых доменов' in why
        # Причина с первой строкой ответа панели: оператору нужно видеть, ЧТО
        # именно сказал mgrctl, а не только «мы не смогли».
        assert 'connection refused' in why

    def test_valid_empty_list_is_a_real_absence(self):
        # mgrctl ответил чисто и пустотой: домена правда нет — отказ со списком
        # (пустым), а не «панель не ответила».
        c = FakeSSH(routes=[('mgrctl -m ispmgr maildomain', '')])
        name, why = dc.isp_mail_parent(c, 'example.com')
        assert name is None
        assert 'не найден среди почтовых доменов панели' in why
        assert 'maildomain: —' in why

    def test_missing_domain_lists_known_parents(self):
        c = FakeSSH(routes=[('mgrctl -m ispmgr maildomain',
                             'name=alpha.tld elid=1\nname=beta.tld elid=2\n')])
        name, why = dc.isp_mail_parent(c, 'gamma.tld')
        assert name is None and 'alpha.tld, beta.tld' in why


class TestMailboxCreateParentResolution:
    """Создание ящика: без подтверждённого родителя команда панели не уходит.

    Роль резолва именно в этом: guard пропускает домен, найденный где угодно
    (панель, postfix-карты, dovecot), а plid обязан быть элементом maildomain.
    Домен, который postfix принимает, но панель как почтовый не знает, — ровно
    тот случай, когда раньше уезжал plid=<строка из адреса>.
    """

    @staticmethod
    def _env(maildomain, virtual='catch@legacy.tld\n', boxes=('', '')):
        sftp = FakeSftpClient()
        c = FakeSSH(routes=[
            ('mgrctl -m ispmgr maildomain', maildomain),
            ('postfix/virtual', virtual),
            (ISP_LIST, boxes),
            ('mgrctl -m ispmgr email.edit', ('', '', 0)),
            ('mktemp -d', SECRET_DIR + '\n'),
        ], client=sftp)
        return c, sftp

    def test_domain_known_only_to_postfix_is_refused(self):
        c, sftp = self._env('name=other.tld elid=3\n')
        out = dc.mailbox_create(c, 'info@legacy.tld', 'Sup3rSecret!',
                                'ispmanager')
        # Guard домен пропустил (postfix его принимает) — и именно резолв
        # остановил операцию: панели такой родитель неизвестен.
        assert '⛔' in out and 'не найден среди почтовых доменов панели' in out
        assert c.find('email.edit') is None
        assert c.find('mktemp') is None
        # Секрет не готовился там, где операция уже отменена.
        assert sftp.store == {} or all('DIAG_MAILBOX_SECRET' not in v
                                       for v in sftp.store.values())

    def test_parent_refusal_happens_before_secret_is_written(self):
        # Порядок принципиален: сначала родитель, потом env-файл с паролем.
        c, _ = self._env('')                      # maildomain пуст
        dc.mailbox_create(c, 'info@other.tld', 'Sup3rSecret!', 'ispmanager')
        order = [cmd for cmd in c.commands
                 if 'maildomain' in cmd or 'mktemp' in cmd or 'email.edit' in cmd]
        assert order and 'maildomain' in order[0]
        assert not [cmd for cmd in order if 'mktemp' in cmd or 'email.edit' in cmd]

    def test_panel_writing_is_used_in_plid_and_shown_to_operator(self):
        c, _ = self._env('name=Example.COM elid=3\n', virtual='',
                         boxes=['', 'name=new@example.com elid=6\n'])
        out = dc.mailbox_create(c, 'new@example.com', 'Sup3rSecret!',
                                'ispmanager')
        # Разница написаний обязана быть показана, иначе оператор решит, что
        # панель завела ящик «на другой домен».
        assert 'ℹ️ Родитель-домен взят из панели: Example.COM' in out
        assert 'в запросе было example.com' in out
        edit = c.find('email.edit')
        assert 'plid=Example.COM' in edit and 'domainname=Example.COM' in edit
        assert '✅ Ящик new@example.com создан' in out

    def test_identical_writing_adds_no_notice(self):
        c, _ = self._env('name=example.com elid=3\n', virtual='',
                         boxes=['', 'name=new@example.com elid=6\n'])
        out = dc.mailbox_create(c, 'new@example.com', 'Sup3rSecret!',
                                'ispmanager')
        assert 'Родитель-домен взят из панели' not in out   # шуметь не о чем
        assert '✅ Ящик new@example.com создан' in out

    def test_passwd_does_not_need_parent_resolution(self):
        # Смена пароля идёт по elid (полный адрес) — родителя не резолвим и
        # maildomain не читаем лишний раз сверх guard'а.
        c = isp_env(['name=info@example.com elid=5\n'] * 2)
        out = dc.mailbox_passwd(c, 'info@example.com', 'Sup3rSecret!',
                                'ispmanager')
        assert '✅ Ящик info@example.com: пароль изменён' in out
        assert c.count('mgrctl -m ispmgr maildomain') == 1   # только guard
        assert 'Родитель-домен' not in out


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
        assert 'Не удалось подготовить env-файл' in out
        assert 'SFTP' in out
        assert c.find('email.edit') is None
        # каталог, который mktemp всё-таки создал, обязан быть вычищен
        # (уборка — rm + проверка факта одним вызовом)
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
        # Файл создан ДО команды панели (иначе -e раскроется в пустой пароль)
        # и права выставлены в ТОМ ЖЕ вызове, что и создание: umask 077 + : >
        # + chmod 600 одной строкой — между «файл есть» и «файл 0600» нет ни
        # одного SSH-раунда, а значит нет и окна, в котором пароль читается
        # всеми (отмена туда не вклинивается даже теоретически).
        prep = c.find('umask 077')
        assert prep is not None
        assert 'chmod 600 ' + SECRET_DIR in prep
        assert ': > ' + SECRET_DIR + '/secret.env' in prep
        assert prep.index('umask 077') < prep.index(': >')
        assert prep.index(': >') < prep.index('chmod 600')
        assert list(sftp.store) == [SECRET_DIR + '/secret.env']
        assert sftp.store[SECRET_DIR + '/secret.env'].startswith(
            'export DIAG_MAILBOX_SECRET=')
        run_idx = [i for i, cmd in enumerate(c.commands)
                   if 'email.edit' in cmd and cmd.startswith('.')]
        prep_idx = [i for i, cmd in enumerate(c.commands)
                    if 'umask 077' in cmd]
        assert run_idx and prep_idx and prep_idx[0] < run_idx[0]

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
        assert c.find('rm -rf ' + SECRET_DIR) is not None
        # уборка проверяет факт: одного rm мало (rc молчит и когда не вышло)
        assert c.find('STILL_THERE') is not None
        wrapped = [cmd for cmd in c.commands if cmd.startswith('. ')]
        assert wrapped and 'rm -rf ' + SECRET_DIR in wrapped[0]

    class _CancelDuringPanelCall(FakeSSH):
        """Отмена СЕРЕДИ команды панели — как ведёт себя транспорт.

        cancel() закрывает канал текущего запроса: run() на этой команде
        бросает, и все последующие run() тоже отказаны. Проходит только
        cleanup() — именно поэтому уборка секрета ходит им.
        """

        def __init__(self, *args, **kwargs):
            FakeSSH.__init__(self, *args, **kwargs)
            self.cancelled = False
            self.cleaned = []

        def run(self, cmd):
            self.commands.append(cmd)
            if self.cancelled or 'email.edit' in cmd:
                self.cancelled = True
                raise Exception('Операция отменена')
            return self._answer(cmd)

        def cleanup(self, cmd):
            self.cleaned.append(cmd)
            self.commands.append(cmd)
            return self._answer(cmd)

    def test_wipe_survives_cancellation(self):
        # Регресс: rm шёл через run() и падал от cancel_event — файл с паролем
        # переживал отмену (воспроизведено: ПРОВОНИЛСЯ=True). Теперь уборка
        # идёт служебным каналом и обязана дойти даже после «Стоп».
        store = FakeSftpClient()
        c = self._CancelDuringPanelCall(
            routes=[('mgrctl -m ispmgr maildomain', 'name=example.com elid=3\n'),
                    ('mktemp -d', SECRET_DIR + '\n'),
                    (ISP_LIST, 'name=info@example.com elid=5\n')],
            client=store)
        with pytest.raises(Exception, match='Операция отменена'):
            dc.mailbox_create(c, 'a@example.com', 'Sup3rSecret!', 'ispmanager')
        # Среди служебных команд обязана быть именно УБОРКА каталога (rm +
        # проверка факта [ -e ]), а не только подготовка файла: cleaned[0] —
        # это prepare_secret_file, поэтому ищем по содержимому, а не по индексу.
        assert any('[ -e ' + SECRET_DIR in cmd for cmd in c.cleaned), c.cleaned
        # секрет в env-файле реально создавался — проверять было на что
        assert 'Sup3rSecret!' in store.store[SECRET_DIR + '/secret.env']
        assert 'Sup3rSecret!' not in ' '.join(c.commands)

    def test_cancellation_with_failed_wipe_is_reported(self):
        # Худший исход: отмена И убрать не удалось. Оператор обязан увидеть и
        # то, и другое, иначе не узнает, что пароль лежит на сервере.
        store = FakeSftpClient()
        c = self._CancelDuringPanelCall(
            routes=[('mgrctl -m ispmgr maildomain', 'name=example.com elid=3\n'),
                    ('mktemp -d', SECRET_DIR + '\n'),
                    ('echo STILL_THERE', ('STILL_THERE\n', '', 0))],
            client=store)
        with pytest.raises(Exception) as excinfo:
            dc.mailbox_create(c, 'a@example.com', 'Sup3rSecret!', 'ispmanager')
        text = str(excinfo.value)
        assert 'Операция отменена' in text
        assert 'Не удалось удалить временный каталог' in text
        assert SECRET_DIR in text                 # путь, чтобы удалить руками

    def test_failed_wipe_goes_into_the_report(self):
        # Обычный прогон (без отмены), но rm не смог: «файл удалён» врать не
        # имеет права — вместо этого предупреждение с путём.
        store = FakeSftpClient()
        c = isp_env(['name=info@example.com elid=5\n',
                     'name=info@example.com elid=5\n'
                     'name=a@example.com elid=7\n'], sftp=store)
        c.routes.append(('echo STILL_THERE', ('STILL_THERE\n', '', 0)))
        out = dc.mailbox_create(c, 'a@example.com', 'Sup3rSecret!', 'ispmanager')
        assert '✅ Ящик a@example.com создан' in out
        assert 'Не удалось удалить временный каталог' in out
        assert SECRET_DIR in out
        assert 'Файл удалён' not in out

    def test_successful_wipe_keeps_the_honest_note(self):
        store = FakeSftpClient()
        c = isp_env(['name=info@example.com elid=5\n',
                     'name=info@example.com elid=5\n'
                     'name=a@example.com elid=7\n'], sftp=store)
        out = dc.mailbox_create(c, 'a@example.com', 'Sup3rSecret!', 'ispmanager')
        assert 'в ps на сервере он не светился' in out
        assert 'Файл удалён сразу после команды панели' in out
        assert 'Не удалось удалить' not in out

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
