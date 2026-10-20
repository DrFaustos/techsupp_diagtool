"""Инвентарь хостинга: сайты, домены, почта, DNS-зоны — обнаружение и проверки.

Полный список того, что реально размещено на сервере панели: сайты (mgrctl /
mogwai + разбор vhost'ов), почтовые домены и ящики (панель + postfix/dovecot),
DNS-зоны (панель + BIND/nsd). Плюс проверка доступности каждого сайта и
сводный отчёт «что на сервере живёт».

Команды панелей — из официальной документации, а не на память:
  ispmanager.com/knowledge-base/useful-commands-for-ispmanager-6   (mgrctl, licctl)
  kb.fastpanel.direct/ru/cli/                                      (mogwai)

Всё, что разбирает текст (CSV mgrctl, таблицы mogwai, конфиги nginx/apache,
postfix-карты), — чистые функции: проверяются тестами без SSH.
"""
import re

from common import q, find_files, read_file_content
from logs import find_logs
from metrics import detect_panel, services_status_cmd, parse_service_statuses
from bitrix import parse_mailq_count

MGR5 = '/usr/local/mgr5'
MGRCTL = f'{MGR5}/sbin/mgrctl -m ispmgr'
LICCTL = f'{MGR5}/sbin/licctl'
CORE_INFO = f'{MGR5}/bin/core ispmgr -i'

# Где искать vhost'ы и почту в каждой конфигурации. Панельный источник
# (mgrctl/mogwai) всегда приоритетнее разбора конфигов: конфиг — запасной путь
# для серверов без панели и для «кривых» vhost, записанных руками.
VHOST_PATTERNS = {
    'ispmanager': [
        '/etc/nginx/vhosts/*/*.conf',
        '/etc/nginx/conf.d/*.conf',
        f'{MGR5}/etc/nginx/vhosts/*/*.conf',
    ],
    'fastpanel': [
        '/etc/nginx/fastpanel2-available/*/*.conf',
        '/etc/nginx/sites-enabled/*.conf',
    ],
    'none': [
        '/etc/nginx/sites-enabled/*',
        '/etc/nginx/conf.d/*.conf',
    ],
}
HTTPD_VHOST_PATTERNS = {
    'ispmanager': ['/etc/httpd/vhosts/*/*.conf'],
    'fastpanel': [],
    'none': ['/etc/apache2/sites-enabled/*.conf', '/etc/httpd/conf.d/*.conf'],
}
ZONE_PATTERNS = [
    '/var/named/zones/db.*',
    '/etc/bind/zones/db.*',
    '/var/lib/named/zones/db.*',
    '/etc/nsd/zones/*.zone',
]
MAIL_MAPS = [
    ('postfix virtual', '/etc/postfix/virtual'),
    ('postfix virtusertable', '/etc/postfix/virtusertable'),
]
DOVECOT_USERS = '/etc/dovecot/users'
POSTFIX_MAIN_CF = '/etc/postfix/main.cf'
MAIL_SERVICES = ('postfix', 'exim4', 'dovecot', 'opendkim', 'rspamd')
# Максимум сайтов, для которых в отчёте проверяем HTTP/SSL (по одному
# внешнему запросу на сайт — на сотне доменов отчёт шёл бы минутами).
HEALTH_CHECK_LIMIT = 25


# ==================== ЧИСТЫЕ ПАРСЕРЫ (тестируются без SSH) ====================
# Формат вывода mgrctl (text): одна строка на элемент, пары key=value через
# пробел; значение может быть в двойных кавычках. Ключевое: CSV/JSON у mgrctl
# в старых версиях нет, а text отдаётся всегда — на него и опираемся.
_MGR_KV_RE = re.compile(r'(\w+)=(?:"([^"]*)"|(\S+))')


def parse_mgrctl_text(text):
    """Вывод `mgrctl -m ispmgr <element>` -> список dict по одной строке.

    Строка без '=' (комментарий, предупреждение) пропускается. Ключи — в
    нижний регистр: панель отдаёт их в разном регистре от модуля к модулю.
    """
    rows = []
    for line in (text or '').splitlines():
        line = line.strip()
        if not line or '=' not in line:
            continue
        row = {}
        for m in _MGR_KV_RE.finditer(line):
            value = m.group(2) if m.group(2) is not None else m.group(3)
            row[m.group(1).lower()] = value.strip()
        if row:
            rows.append(row)
    return rows


def parse_mogwai_table(text):
    """Вывод `mogwai ... list` (колонки через табы) -> список dict.

    Разделитель — таб; если табов нет (копия вывода из терминала), колонки
    режутся по пробелам, а последняя получает хвост целиком: в нём дата вида
    '2024-01-04 15:46:02+03:00' с внутренним пробелом.
    """
    lines = [l for l in (text or '').splitlines() if l.strip()]
    if len(lines) < 2:
        return []

    def cols(line, n=None):
        if '\t' in line:
            return [c.strip() for c in line.split('\t')]
        if n:
            return [c.strip() for c in line.split(None, n - 1)]
        return line.split()

    header = [h.upper() for h in cols(lines[0])]
    out = []
    for line in lines[1:]:
        parts = cols(line, len(header))
        out.append(dict(zip(header, parts)))
    return out


# Директивы ищутся не только с начала строки: конфиги обычно многострочные,
# но однострочные блоки (`server { listen 80; server_name x.tld; root ...; }`)
# тоже встречаются. Якорь — граница блока (^, { или ;), поэтому строки вида
# `fastcgi_param SERVER_NAME $server_name;` не матчатся (в верхнем регистре, а
# в нижнем значение $server_name без точки и отсекается фильтром имён).
# ssl_certificate_key не матчится: после ssl_certificate идёт '_', а не пробел.
_SERVER_NAME_RE = re.compile(r'(?:^|[{;])\s*server_name\s+([^;{]+);', re.MULTILINE)
_NGINX_ROOT_RE = re.compile(r'(?:^|[{;])\s*root\s+(\S+)\s*;', re.MULTILINE)
_NGINX_SSL_RE = re.compile(r'(?:^|[{;])\s*ssl_certificate\s+(\S+)\s*;', re.MULTILINE)
# Версия PHP берётся строго вида php<цифры>[.<цифры>]: класс [\d._-]+ жрал бы
# и «-fpm.example» из имени sock, превращая версию в мусор.
_PHP_SOCK_RE = re.compile(r'fastcgi_pass\s+[^;]*?(php\d+(?:\.\d+)?)')


def parse_nginx_vhost(text):
    """nginx vhost -> {'domains', 'docroot', 'ssl', 'php'}.

    server_name бывает в нескольких блоках server; шаблонные имена (_, *.rt,
    localhost) в инвентарь не попадают.
    """
    text = text or ''
    domains = []
    for m in _SERVER_NAME_RE.finditer(text):
        for name in m.group(1).split():
            name = name.strip().lower()
            if (not name or name in ('_', 'localhost')
                    or name.startswith('*.') or name.startswith('.')
                    or '.' not in name):
                continue
            if name not in domains:
                domains.append(name)
    root = _NGINX_ROOT_RE.search(text)
    ssl = _NGINX_SSL_RE.search(text)
    php = _PHP_SOCK_RE.search(text)
    return {
        'domains': sorted(domains),
        'docroot': root.group(1) if root else '',
        'ssl': ssl.group(1) if ssl else '',
        'php': php.group(1) if php else '',
    }


_APACHE_NAME_RE = re.compile(r'^\s*Server(?:Name|Alias)\s+(.+)$',
                             re.IGNORECASE | re.MULTILINE)
_APACHE_ROOT_RE = re.compile(r'^\s*DocumentRoot\s+"?([^"\s]+)"?',
                             re.IGNORECASE | re.MULTILINE)


def parse_apache_vhost(text):
    """Apache vhost -> {'domains', 'docroot'} (ServerName + ServerAlias)."""
    domains = []
    for m in _APACHE_NAME_RE.finditer(text or ''):
        for name in m.group(1).split():
            name = name.strip().lower()
            if name.startswith('*.') or '.' not in name or name == 'localhost':
                continue
            if name not in domains:
                domains.append(name)
    root = _APACHE_ROOT_RE.search(text or '')
    return {'domains': sorted(domains), 'docroot': root.group(1) if root else ''}


def parse_postfix_map(text):
    """Карта postfix (virtual/virtusertable) -> (ящики, домены).

    Формат строк: 'user@example.com box@other.tld', '@example.com @other.tld',
    комментарии — с '#'. Домен берётся из левой части (левая '@domain' — это
    «вся почта домена»), ящик — левая часть с локальной частью.
    """
    boxes, domains = set(), set()
    for line in (text or '').splitlines():
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        parts = line.split()
        left = parts[0].lower()
        if '@' in left:
            domains.add(left.split('@', 1)[1])
            if not left.startswith('@'):
                boxes.add(left)
        for token in parts[1:]:
            token = token.lower()
            if token.startswith('@'):
                domains.add(token[1:])
    return sorted(boxes), sorted(domains)


def parse_dovecot_users(text):
    """Passwd-файл dovecot ('user@example.com:key:key') -> список адресов."""
    boxes = set()
    for line in (text or '').splitlines():
        line = line.strip()
        if '@' not in line or line.startswith('#'):
            continue
        addr = line.split(':', 1)[0].strip().lower()
        if '.' in addr.split('@', 1)[-1]:
            boxes.add(addr)
    return sorted(boxes)


_MAIN_CF_DIRECTIVES = ('mydestination', 'virtual_mailbox_domains',
                       'virtual_alias_domains')


def parse_main_cf_domains(text):
    """Домены почтового домена из main.cf (без $myhostname-переменных)."""
    domains = set()
    for directive in _MAIN_CF_DIRECTIVES:
        for m in re.finditer(rf'^{directive}\s*=\s*(.+)$', text or '',
                             re.MULTILINE):
            for token in m.group(1).split(','):
                token = token.strip().lower()
                if ('.' in token and '$' not in token
                        and 'localhost' not in token
                        and not token.startswith('[')):
                    domains.add(token)
    return sorted(domains)


def zone_domain_from_path(path):
    """'/etc/bind/zones/db.example.com' -> 'example.com' (nsd: *.zone)."""
    base = (path or '').rstrip('/').rsplit('/', 1)[-1]
    if base.startswith('db.'):
        base = base[3:]
    if base.endswith('.zone'):
        base = base[:-5]
    if '.' not in base or ' ' in base or base.startswith('.'):
        return None
    return base.lower()


_SERIAL_RE = re.compile(r'^\d{8,12}$')


def parse_zone_serial(text):
    """Serial из zone-файла: первый токен-дата после SOA (обычно YYYYMMDDnn)."""
    for line in (text or '').splitlines():
        if line.strip().startswith(';'):
            continue
        for token in line.replace('(', ' ').replace(')', ' ').split():
            if _SERIAL_RE.match(token):
                return token
    return ''


def site_status_command(domain):
    """Одна команда: коды ответов http/https и «SSL истечёт < 30 дней?»."""
    d = q(domain)
    return (
        "printf 'HTTP=%s\\n' \"$(curl -s -m 8 -o /dev/null -w '%{http_code}' "
        f"http://{d}/ 2>/dev/null)\"; "
        "printf 'HTTPS=%s\\n' \"$(curl -sk -m 8 -o /dev/null -w '%{http_code}' "
        f"https://{d}/ 2>/dev/null)\"; "
        "printf 'SSL=%s\\n' \"$(echo | timeout 8 openssl s_client -servername "
        f"{d} -connect {d}:443 2>/dev/null "
        "| openssl x509 -noout -checkend 2592000 >/dev/null 2>&1 "
        "&& echo ok || echo bad)\""
    )


def parse_site_status(out):
    """'HTTP=200\\nHTTPS=301\\nSSL=ok' -> dict (пустые коды -> '000')."""
    vals = {}
    for line in (out or '').splitlines():
        key, _, value = line.partition('=')
        vals[key.strip().upper()] = value.strip()
    return {'http': vals.get('HTTP') or '000',
            'https': vals.get('HTTPS') or '000',
            'ssl': vals.get('SSL', '')}


def http_status_icon(http, https):
    """Зелёный — HTTPS отвечает 2xx/3xx; жёлтый — только HTTP; красный — тихоня."""
    if https not in ('000', '') and https[0] in '23':
        return '✅'
    if http not in ('000', '') and http[0] in '23':
        return '🟡'
    return '❌'


HOSTS_LE_PREFIXES = ('127.0.0.1', '::1')


def hosts_le_blockers(text, domain):
    """Строки /etc/hosts, где домен висит на 127.0.0.1/::1.

    Грабля из KB FASTPANEL: при таком соответствии выпуск Let's Encrypt
    падает, потому что ACME-check приходит на loopback.
    """
    dom = (domain or '').lower()
    hits = []
    for line in (text or '').splitlines():
        line = line.split('#')[0].strip()
        parts = line.split()
        if len(parts) >= 2 and parts[0] in HOSTS_LE_PREFIXES:
            if any(p.lower() == dom for p in parts[1:]):
                hits.append(line)
    return hits


# ==================== ЧИТАТЕЛИ ПАНЕЛЕЙ ====================
def isp_list(checker, element):
    """Список элементов панели: `mgrctl -m ispmgr <element>` (text-формат).

    Элемент берётся из списка панели (webdomain, maildomain, dnszone, mail,
    usr, db) — это не пользовательский ввод, поэтому кавычки только защита
    от опечатки в коде.
    """
    out, _, _ = checker.run(f'{MGRCTL} {q(element)} 2>/dev/null')
    return parse_mgrctl_text(out)


def isp_webdomains(checker):
    return isp_list(checker, 'webdomain')


def isp_maildomains(checker):
    return isp_list(checker, 'maildomain')


def isp_dnszones(checker):
    return isp_list(checker, 'dnszone')


def isp_users(checker):
    return isp_list(checker, 'usr')


def mogwai(checker, args):
    """CLI FastPanel (mogwai требует root — панель и так обслуживают под root)."""
    out, _, rc = checker.run(f'mogwai {args} 2>/dev/null')
    return out, rc


def fp_sites(checker):
    out, rc = mogwai(checker, 'sites list')
    return parse_mogwai_table(out) if rc == 0 else []


def fp_mail_domains(checker):
    out, rc = mogwai(checker, 'emails domains list')
    return parse_mogwai_table(out) if rc == 0 else []


def fp_mail_boxes(checker, domain=None):
    extra = f' --domain={q(domain)}' if domain else ''
    out, rc = mogwai(checker, f'emails boxes list{extra}')
    return parse_mogwai_table(out) if rc == 0 else []


# ==================== ИНВЕНТАРЬ: САЙТЫ ====================
def discover_sites(checker, panel_type=None):
    """Список сайтов: панельный источник + разбор vhost'ов, сведё по домену.

    Каждая запись: domain, owner, docroot, php, vhost (откуда узнали).
    """
    if panel_type is None:
        panel_type = detect_panel(checker)
    sites = {}

    def add(domain, **info):
        dom = (domain or '').strip().lower()
        if not dom or '.' not in dom or dom.startswith('*.'):
            return
        rec = sites.setdefault(dom, {'domain': dom, 'owner': '', 'docroot': '',
                                     'php': '', 'vhost': ''})
        # Первый источник главнее: панель (mgrctl/mogwai) идёт раньше конфигов,
        # а поле уже заполнено — не перетираем.
        for key, value in info.items():
            if value and not rec.get(key):
                rec[key] = value

    if panel_type == 'ispmanager':
        for row in isp_webdomains(checker):
            add(row.get('name'),
                owner=row.get('owner', '') or row.get('usr', ''),
                docroot=row.get('docroot', ''),
                php=row.get('php', '') or row.get('phpversion', ''),
                vhost='mgrctl webdomain')
    elif panel_type == 'fastpanel':
        for row in fp_sites(checker):
            add(row.get('SERVER_NAME') or row.get('NAME'),
                owner=row.get('OWNER', ''),
                docroot=row.get('DOCUMENT_ROOT', ''),
                php=row.get('PHP_VERSION', ''),
                vhost='mogwai sites')

    for pattern in VHOST_PATTERNS.get(panel_type, VHOST_PATTERNS['none']):
        for path in find_files(checker, pattern, limit=50):
            if path.startswith('⚠️'):
                continue
            parsed = parse_nginx_vhost(read_file_content(checker, path) or '')
            for dom in parsed['domains']:
                add(dom, docroot=parsed['docroot'], php=parsed['php'],
                    vhost=path)
    for pattern in HTTPD_VHOST_PATTERNS.get(panel_type, []):
        for path in find_files(checker, pattern, limit=50):
            if path.startswith('⚠️'):
                continue
            parsed = parse_apache_vhost(read_file_content(checker, path) or '')
            for dom in parsed['domains']:
                add(dom, docroot=parsed['docroot'], vhost=path)

    return sorted(sites.values(), key=lambda s: s['domain'])


# ==================== ИНВЕНТАРЬ: ПОЧТА ====================
def discover_mail_domains(checker, panel_type=None):
    """{домен: [источники]} — панель, postfix-карты, dovecot, main.cf."""
    if panel_type is None:
        panel_type = detect_panel(checker)
    found = {}

    def add(domain, source):
        dom = (domain or '').strip().lower()
        if dom and '.' in dom and 'localhost' not in dom:
            found.setdefault(dom, []).append(source)

    if panel_type == 'ispmanager':
        for row in isp_maildomains(checker):
            add(row.get('name'), 'mgrctl maildomain')
    elif panel_type == 'fastpanel':
        for row in fp_mail_domains(checker):
            add(row.get('NAME'), 'mogwai emails domains')

    for source, path in MAIL_MAPS:
        content = read_file_content(checker, path)
        if content:
            for dom in parse_postfix_map(content)[1]:
                add(dom, source)

    dovecot = read_file_content(checker, DOVECOT_USERS)
    if dovecot:
        for addr in parse_dovecot_users(dovecot):
            add(addr.split('@', 1)[1], 'dovecot users')

    main_cf = read_file_content(checker, POSTFIX_MAIN_CF)
    if main_cf:
        for dom in parse_main_cf_domains(main_cf):
            add(dom, 'postfix main.cf')

    return found


def discover_mailboxes(checker, panel_type=None, domain=None):
    """Список ящиков (addr, источник). domain — фильтр по домену."""
    if panel_type is None:
        panel_type = detect_panel(checker)
    boxes = []

    if panel_type == 'fastpanel':
        for row in fp_mail_boxes(checker, domain):
            addr = (row.get('ADDRESS') or '').strip().lower()
            if addr:
                boxes.append((addr, 'mogwai emails boxes'))

    for source, path in MAIL_MAPS:
        content = read_file_content(checker, path)
        if content:
            boxes.extend((addr, source)
                         for addr in parse_postfix_map(content)[0])

    dovecot = read_file_content(checker, DOVECOT_USERS)
    if dovecot:
        boxes.extend((addr, 'dovecot users')
                     for addr in parse_dovecot_users(dovecot))

    if domain:
        suffix = '@' + domain.lower()
        boxes = [b for b in boxes if b[0].endswith(suffix)]

    # Дедуп по адресу, источник — первый (mogwai/mgrctl приоритетнее файлов).
    seen, out = set(), []
    for addr, source in boxes:
        if addr not in seen:
            seen.add(addr)
            out.append((addr, source))
    return sorted(out)


# ==================== ИНВЕНТАРЬ: DNS-ЗОНЫ ====================
def discover_dns_zones(checker, panel_type=None):
    """[{domain, path, serial, source}] — панель + файлы зон BIND/nsd."""
    if panel_type is None:
        panel_type = detect_panel(checker)
    zones = {}

    if panel_type == 'ispmanager':
        for row in isp_dnszones(checker):
            dom = (row.get('name') or '').strip().lower()
            if dom:
                zones[dom] = {'domain': dom,
                              'path': row.get('filename', '')
                                      or row.get('file', ''),
                              'source': 'mgrctl dnszone'}

    paths = []
    for pattern in ZONE_PATTERNS:
        out, _, _ = checker.run(f'ls -1 {pattern} 2>/dev/null | head -100')
        paths.extend(p.strip() for p in (out or '').splitlines() if p.strip())
    for path in paths:
        dom = zone_domain_from_path(path)
        if dom and dom not in zones:
            zones[dom] = {'domain': dom, 'path': path, 'source': 'zone files'}

    result = sorted(zones.values(), key=lambda z: z['domain'])
    for zone in result:
        if zone['path']:
            zone['serial'] = parse_zone_serial(
                read_file_content(checker, zone['path']) or '')
        else:
            zone['serial'] = ''
    return result


# ==================== ОТЧЁТЫ ====================
def site_health_lines(checker, sites, limit=HEALTH_CHECK_LIMIT):
    """HTTP/HTTPS-коды и SSL-сроки по сайтам (не больше limit внешних проб)."""
    lines = []
    for site in sites[:limit]:
        status = parse_site_status(
            checker.exec_command(site_status_command(site['domain']))[0])
        icon = http_status_icon(status['http'], status['https'])
        ssl = ''
        if status['https'] not in ('000', ''):
            ssl = '  SSL ok' if status['ssl'] == 'ok' else '  ⚠️ SSL<30д/нет'
        lines.append(f"  {icon} {site['domain']:45s} "
                     f"http={status['http']:3s} https={status['https']:3s}"
                     f"{ssl}")
    if len(sites) > limit:
        lines.append(f"  … доступность проверялась для первых {limit} "
                     f"из {len(sites)}")
    return lines


def site_health_report(checker, panel_type=None):
    sites = discover_sites(checker, panel_type)
    lines = ["=== САЙТЫ И ИХ ДОСТУПНОСТЬ ==="]
    if not sites:
        lines.append("Сайты не обнаружены (ни панельного списка, ни vhost'ов).")
        return "\n".join(lines)
    lines.append(f"Найдено сайтов: {len(sites)}\n")
    for site in sites:
        parts = [f"  {site['domain']}"]
        meta = []
        if site['owner']:
            meta.append(f"владельцем: {site['owner']}")
        if site['docroot']:
            meta.append(f"docroot: {site['docroot']}")
        if site['php']:
            meta.append(f"php: {site['php']}")
        if meta:
            parts.append('      ' + ' | '.join(meta))
        parts.append(f"      источник: {site['vhost']}")
        lines.append("\n".join(parts))
    lines.append("\n--- Проверка доступности ---")
    lines.extend(site_health_lines(checker, sites))
    return "\n".join(lines)


def mail_overview_report(checker, panel_type=None):
    """Почта: домены, ящики, очередь postfix, состояние служб."""
    if panel_type is None:
        panel_type = detect_panel(checker)
    lines = ["=== ПОЧТОВЫЙ СЕРВЕР: ИНВЕНТАРЬ ==="]

    domains = discover_mail_domains(checker, panel_type)
    if domains:
        lines.append(f"Почтовых доменов: {len(domains)}")
        for dom in sorted(domains):
            boxes = discover_mailboxes(checker, panel_type, domain=dom)
            addrs = ', '.join(addr for addr, _ in boxes[:15]) or '—'
            lines.append(f"  {dom}  (ящиков: {len(boxes)})")
            lines.append(f"      {addrs}")
            if len(boxes) > 15:
                lines.append(f"      … ещё {len(boxes) - 15}")
    else:
        lines.append("Почтовые домены не найдены.")

    out, _ = checker.exec_command('mailq 2>&1 | tail -1')
    queued = parse_mailq_count(out or '')
    if queued is None:
        lines.append("\nОчередь postfix: mailq недоступен")
    elif queued == 0:
        lines.append("\nОчередь postfix: пуста ✅")
    else:
        icon = '⚠️' if queued > 10 else 'ℹ️'
        lines.append(f"\n{icon} Очередь postfix: писем — {queued}")

    statuses = parse_service_statuses(
        checker.exec_command(services_status_cmd(list(MAIL_SERVICES)))[0])
    lines.append("\nПочтовые службы:")
    for svc in MAIL_SERVICES:
        status = statuses.get(svc)
        if status is None:
            continue
        icon = {'active': '✅', 'inactive': '⚪'}.get(status, '⚠️')
        lines.append(f"  {icon} {svc}: {status}")
    return "\n".join(lines)


def dns_zones_report(checker, panel_type=None):
    zones = discover_dns_zones(checker, panel_type)
    lines = ["=== DNS-ЗОНЫ НА СЕРВЕРЕ ==="]
    if not zones:
        lines.append("Зон не найдено — сервер не является NS для этих доменов "
                     "(DNS тогда у регистратора/в облаке).")
        return "\n".join(lines)
    lines.append(f"Найдено зон: {len(zones)}\n")
    for zone in zones:
        serial = zone['serial'] or '?'
        lines.append(f"  {zone['domain']:45s} serial={serial:>12s} "
                     f"[{zone['source']}]")
    return "\n".join(lines)


def hosting_inventory_report(checker, panel_type=None):
    """Один отчёт на все: сайты + почта + DNS-зоны (меню «🌐 Хостинг ▾»)."""
    if panel_type is None:
        panel_type = detect_panel(checker)
    return "\n\n".join((
        site_health_report(checker, panel_type),
        mail_overview_report(checker, panel_type),
        dns_zones_report(checker, panel_type),
    ))


def domain_detail_report(checker, domain, panel_type=None):
    """Всё об одном домене: vhost, docroot, HTTP/SSL, DNS, почта, грабли LE."""
    if panel_type is None:
        panel_type = detect_panel(checker)
    dom = (domain or '').strip().lower()
    lines = [f"=== ДОСЬЕ ДОМЕНА {dom} ==="]
    if not dom or '.' not in dom:
        lines.append("❌ Домен не задан корректно")
        return "\n".join(lines)

    site = next((s for s in discover_sites(checker, panel_type)
                 if s['domain'] == dom), None)
    if site:
        lines.append(f"Сайт: владелец={site['owner'] or '?'} "
                     f"docroot={site['docroot'] or '?'} "
                     f"php={site['php'] or '?'}")
        lines.append(f"Конфиг: {site['vhost']}")
        for log in find_logs(checker, panel_type, dom, 'access')[:2]:
            lines.append(f"Лог доступа: {log}")
        for log in find_logs(checker, panel_type, dom, 'error')[:2]:
            lines.append(f"Лог ошибок: {log}")
    else:
        lines.append("⚠️ Домен не найден ни в списке панели, ни в vhost'ах. "
                     "Проверьте, что A-запись вообще указывает на этот сервер.")

    status = parse_site_status(checker.exec_command(site_status_command(dom))[0])
    icon = http_status_icon(status['http'], status['https'])
    lines.append(f"\n{icon} Доступность: http={status['http']} "
                 f"https={status['https']}"
                 + ('' if status['https'] in ('000', '')
                    else f" | SSL {'ok' if status['ssl'] == 'ok' else 'истекает/нет'}"))

    lines.append("\nDNS (с самого сервера, dig):")
    for rtype in ('A', 'AAAA', 'MX'):
        out, _ = checker.exec_command(f'dig +short {rtype} {q(dom)} 2>/dev/null')
        values = ' '.join((out or '').split())
        lines.append(f"  {rtype}: {values or '— нет записей'}")

    mail_domains = discover_mail_domains(checker, panel_type)
    if dom in mail_domains:
        boxes = discover_mailboxes(checker, panel_type, domain=dom)
        lines.append(f"\nДомен почтовый (источники: {', '.join(mail_domains[dom])}), "
                     f"ящиков: {len(boxes)}")
        for addr, source in boxes[:20]:
            lines.append(f"  {addr}  [{source}]")
    else:
        lines.append("\nДомен не заявлен как почтовый на этом сервере.")

    hosts = read_file_content(checker, '/etc/hosts') or ''
    blockers = hosts_le_blockers(hosts, dom)
    if blockers:
        lines.append("\n⚠️ Домен привязан к loopback в /etc/hosts — выпуск "
                     "Let's Encrypt будет падать (KB FASTPANEL):")
        lines.extend(f"  {line}" for line in blockers)
    return "\n".join(lines)
