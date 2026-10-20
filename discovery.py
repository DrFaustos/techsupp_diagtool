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
import shlex

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
    """Одна команда: коды http/https + «SSL < 30 дней?» + точный остаток в днях.

    Один TLS-хендшейк на домен, а не два: -enddate читается один раз, а 'SSL='
    выводится из него же сравнением с date. Дни считаем НА СЕРВЕРЕ: дата и час
    машины оператора к выпуску сертификата отношения не имеют.
    """
    d = q(domain)
    return (
        f"TLS=$(echo | timeout 8 openssl s_client -servername {d} "
        f"-connect {d}:443 2>/dev/null "
        "| openssl x509 -noout -enddate 2>/dev/null | cut -d= -f2-); "
        'EPOCH=$(date -d "$TLS" +%s 2>/dev/null); '
        "printf 'HTTP=%s\\n' \"$(curl -s -m 8 -o /dev/null -w '%{http_code}' "
        f"http://{d}/ 2>/dev/null)\"; "
        "printf 'HTTPS=%s\\n' \"$(curl -sk -m 8 -o /dev/null -w '%{http_code}' "
        f"https://{d}/ 2>/dev/null)\"; "
        'if [ -z "$EPOCH" ]; then printf "SSL=none\\nCERT=none\\n"; '
        'else NOW=$(date +%s); LEFT=$(( (EPOCH - NOW) / 86400 )); '
        'if [ "$EPOCH" -gt $(( NOW + 2592000 )) ]; then printf "SSL=ok\\n"; '
        'else printf "SSL=bad\\n"; fi; printf "CERT=%s\\n" "$LEFT"; fi'
    )


def parse_site_status(out):
    """'HTTP=200\\nHTTPS=301\\nSSL=ok' -> dict (пустые коды -> '000')."""
    vals = {}
    for line in (out or '').splitlines():
        key, _, value = line.partition('=')
        vals[key.strip().upper()] = value.strip()
    cert = None
    if vals.get('CERT', '') not in ('', 'none'):
        try:
            cert = int(vals['CERT'])
        except ValueError:
            cert = None
    return {'http': vals.get('HTTP') or '000',
            'https': vals.get('HTTPS') or '000',
            'ssl': vals.get('SSL', ''),
            'cert_days': cert}


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


# ==================== SSL: ТОЧНЫЙ ОСТАТОК СЕРТИФИКАТА ====================
# site_status_command отдаёт по домену и бинарное 'SSL=ok|bad' (порог 30 дней),
# и точный остаток 'CERT=<дней>'. Дни нужны отдельно: сертификат Let's Encrypt
# живёт 90 дней, и «истёк позавчера» для оператора не то же, что «осталось 5»,
# а по одному флагу ok/bad их не разделить. Считает сервер (date -d — GNU,
# серверы у нас Linux): часы машины оператора к выпуску сертификата отношения
# не имеют. Отрицательное число — сертификат уже истёк.
SSL_WARN_DAYS = 30


def parse_cert_days(out):
    """'CERT=87' -> 87; 'CERT=-3' -> -3 (истёк); 'CERT=none'/мусор -> None."""
    for line in (out or '').splitlines():
        key, _, value = line.partition('=')
        if key.strip().upper() != 'CERT':
            continue
        try:
            return int(value.strip())
        except ValueError:
            return None
    return None


def cert_days_icon(days):
    """Иконка по остатку: None — сертификат не получен (порт/нет TLS)."""
    if days is None:
        return '❓'
    if days < 0:
        return '❌'
    if days < SSL_WARN_DAYS:
        return '⚠️'
    return '✅'


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
def cert_days_label(days):
    """Человеческая подпись остатка: 'осталось 87 дн.', 'истёк 3 дн. назад'."""
    if days is None:
        return 'сертификат не получен (порт закрыт/нет TLS)'
    if days < 0:
        return f'ИСТЁК {-days} дн. назад'
    return f'осталось {days} дн.'


def site_health_lines(checker, sites, limit=HEALTH_CHECK_LIMIT):
    """HTTP/HTTPS-коды и остаток SSL по сайтам (не больше limit внешних проб)."""
    lines = []
    for site in sites[:limit]:
        status = parse_site_status(
            checker.exec_command(site_status_command(site['domain']))[0])
        icon = http_status_icon(status['http'], status['https'])
        ssl = ''
        if status['https'] not in ('000', ''):
            days = status['cert_days']
            ssl = f"  {cert_days_icon(days)} SSL {cert_days_label(days)}"
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


def ssl_expiry_report(checker, panel_type=None, limit=HEALTH_CHECK_LIMIT):
    """Остаток SSL-сертификатов по всем сайтам инвентаря, проблемные — сверху.

    Отличие от «Сайты и доступность»: тут НЕ важны коды ответа — только срок
    сертификата, отсортированный по остатку. На сервере с сотней доменов
    оператору нужен ответ «что умереть может первым», а не простыня по алфавиту.
    Дни берём из той же пробы, что и коды (site_status_command), — один
    TLS-хендшейк на домен; ограничение limit — как у health-check.
    """
    sites = discover_sites(checker, panel_type)
    lines = ["=== SSL: СРОК ДЕЙСТВИЯ СЕРТИФИКАТОВ ==="]
    if not sites:
        lines.append("Сайты не обнаружены — проверять сертификаты не на чём.")
        return "\n".join(lines)

    probed = sites[:limit]
    rows = []
    for site in probed:
        status = parse_site_status(
            checker.exec_command(site_status_command(site['domain']))[0])
        rows.append((site['domain'], status['cert_days'], status['https']))

    # Сортировка: сначала истёкшие (отрицательные), потом по возрастанию
    # остатка; None (сертификат не получен) — в конец: «нет HTTPS» — это
    # отдельная проблема, а не «скоро истечёт».
    rows.sort(key=lambda r: (r[1] is None, r[1] if r[1] is not None else 0))

    expired = [r for r in rows if r[1] is not None and r[1] < 0]
    warning = [r for r in rows
               if r[1] is not None and 0 <= r[1] < SSL_WARN_DAYS]
    lines.append(f"Проверено доменов: {len(rows)} из {len(sites)}. "
                 f"Истекло: {len(expired)}, истекает < {SSL_WARN_DAYS} дн.: "
                 f"{len(warning)}")
    if expired:
        lines.append("\n❌ СЕРТИФИКАТЫ ИСТЕКЛИ (браузер показывает предупреждение):")
        for dom, days, _ in expired:
            lines.append(f"  {dom:45s} {cert_days_label(days)}")
    if warning:
        lines.append(f"\n⚠️ ИСТЕКАЮТ МЕНЕЕ ЧЕМ ЗА {SSL_WARN_DAYS} ДНЕЙ:")
        for dom, days, _ in warning:
            lines.append(f"  {dom:45s} {cert_days_label(days)}")

    rest = [r for r in rows if r[1] is not None and r[1] >= SSL_WARN_DAYS]
    if rest:
        lines.append("\n✅ В порядке (>= %d дн.):" % SSL_WARN_DAYS)
        for dom, days, _ in rest:
            lines.append(f"  {dom:45s} {cert_days_label(days)}")

    quiet = [r for r in rows if r[1] is None]
    if quiet:
        lines.append("\n❓ СЕРТИФИКАТ НЕ ПОЛУЧЕН (порт 443 молчит или нет TLS):")
        for dom, _, https_code in quiet:
            why = ('https отвечает без рабочего TLS'
                   if https_code not in ('000', '') else 'https не отвечает')
            lines.append(f"  {dom:45s} {why}")

    if len(sites) > limit:
        lines.append(f"\n… проверены первые {limit} из {len(sites)} доменов "
                     f"(HEALTH_CHECK_LIMIT)")
    if expired or warning:
        lines.append("\nВыпуск Let's Encrypt: в меню панели — «Выпустить "
                     "Let's Encrypt SSL» (ISPmanager) или certbot/dehydrated "
                     "в терминале ниже.")
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


# ==================== ОПЕРАЦИИ С ПОЧТОВЫМИ ЯЩИКАМИ ====================
# Синтаксис панелей — из официальной документации, а не на память:
#   ispmanager: knowledge-base/massovoe-sozdanie-pochtovyh-yashhikov —
#               `mgrctl email.edit domainname= name= plid= aliases= passwd=
#                confirm= sok=ok` (без elid функция СОЗДАЁТ ящик);
#               elid ящика — элемент name функции email, т.е. полный адрес
#               (пример autoresponder: elid=admin@domain.com)
#   FASTPANEL : kb.fastpanel.direct/ru/cli/email — `mogwai emails boxes
#               create --domain= --login= --password=` и `boxes delete -b <ID>`,
#               где ID числовой и берётся из строки `boxes list`
# Команды собирают чистые функции (проверяются тестами без SSH): операционные
# функции ниже лишь валидируют ввод, выполняют команду и показывают ответ
# панели. Пароль нигде не печатается в отчёте; в ps на сервере он виден —
# предупреждение входит в отчёт (тот же компромисс, что у mogwai chpasswd).

MAILBOX_LOCAL_RE = re.compile(r'^[a-z0-9._%+-]{1,64}$')
MAILBOX_DOMAIN_RE = re.compile(
    r'^(?=.{1,253}$)[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?'
    r'(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$')
# FASTPANEL отклоняет короткий пароль сам (KB), ISPmanager требует стойкость по
# умолчанию. Отказать до отправки честнее, чем показать непонятную ошибку панели.
MAILBOX_MIN_PASSWORD = 8


def parse_mailbox_address(address):
    """'User@Example.COM ' -> (('user', 'example.com'), None) либо (None, текст).

    Адрес приводится к нижнему регистру: почтовые системы регистр домена не
    различают, а панель хранит ящики строчными — 'Info@Site.RU' создал бы дубль,
    который потом не находится ни списком, ни удалением. Не-ASCII сознально
    отклоняем: для кириллического домена оператор обязан ввести punycode,
    иначе панель заведёт ящик с адресом, который нигде не совпадёт с вводом.
    """
    text = (address or '').strip().lower()
    if text.count('@') != 1:
        return None, 'Ящик задаётся полным адресом: user@example.com'
    local, domain = text.split('@', 1)
    if not MAILBOX_LOCAL_RE.match(local):
        return None, ('В имени ящика допустимы буквы, цифры и . _ % + - '
                      f'(получено «{local}»)')
    if not MAILBOX_DOMAIN_RE.match(domain):
        return None, (f'Домен «{domain}» не похож на домен (для кириллического '
                      'нужна punycode-форма вида xn--...)')
    return (local, domain), None


def isp_mailbox_create_command(local, domain, password):
    """email.edit БЕЗ elid = создание ящика (так же делает скрипт из KB)."""
    return (f'{MGRCTL} email.edit domainname={q(domain)} name={q(local)} '
            f'plid={q(domain)} aliases={q("")} passwd={q(password)} '
            f'confirm={q(password)} sok=ok 2>&1')


def isp_mailbox_passwd_command(address, password):
    """email.edit c elid — смена пароля существующего ящика."""
    return (f'{MGRCTL} email.edit elid={q(address)} passwd={q(password)} '
            f'confirm={q(password)} sok=ok 2>&1')


def isp_mailbox_delete_command(address):
    """email.delete: elid — элемент name функции email (полный адрес ящика)."""
    return f'{MGRCTL} email.delete elid={q(address)} 2>&1'


def fp_mailbox_create_command(local, domain, password):
    """mogwai emails boxes create — параметры дословно из KB FASTPANEL."""
    return (f'mogwai emails boxes create --domain={q(domain)} '
            f'--login={q(local)} --password={q(password)} 2>&1')


def fp_mailbox_delete_command(box_id):
    """-b принимает только числовой ID из `mogwai emails boxes list`.

    int() здесь — не украшение: оператор вводит адрес, а ID берётся из вывода
    панели (find_fp_mailbox_id). Если там мусор, бросок лучше, чем `delete -b
    <что-то>`; вызывающий код обязан проверить None до вызова.
    """
    return f'mogwai emails boxes delete -b {int(box_id)} 2>&1'


def find_fp_mailbox_id(rows, address):
    """ID ящика по адресу в выводе `mogwai emails boxes list` (или None)."""
    want = (address or '').strip().lower()
    for row in rows:
        if (row.get('ADDRESS') or '').strip().lower() == want:
            ident = (row.get('ID') or '').strip()
            return int(ident) if ident.isdigit() else None
    return None


def isp_rows(checker, func):
    """Элементы панели + признак «панель ответила без ошибки»: (rows, ok, текст).

    mgrctl пишет ошибку в stdout (ERROR=...), а код возврата у него не всегда
    ненулевой, поэтому «успех» решается по содержимому, а не по rc. Ошибочный
    ответ при этом обязан быть виден оператору — вывод идёт сюда как текст.
    """
    out, err, rc = checker.run(f'{MGRCTL} {q(func)} 2>&1')
    rows = parse_mgrctl_text(out)
    raw = (out or '').strip() or (err or '').strip()
    ok = rc == 0 and not _mgrctl_says_error(raw, rows)
    return rows, ok, raw


def _mgrctl_says_error(raw, rows):
    """Отличает ответ панели «ошибка» от корректного (возможно пустого) списка.

    mgrctl пишет ошибку в двух видах: `ERROR=текст` (разбирается парсером как
    пара) и `ERROR: текст` (без '=' — парсер строку просто пропускает, и по
    разобранным ключам такая ошибка НЕ видна). Поэтому смотрим и на разобранные
    ключи, и на начало сырых строк. Поиск именно с начала строки, а не по
    подстроке: домен error-log.example.com внутри значения не должен означать
    «панель ответила ошибкой».
    """
    if any('error' in row for row in rows):
        return True
    for line in (raw or '').splitlines():
        if line.strip().lower().startswith('error'):
            return True
    return False


def known_mailbox_addresses(checker, panel_type=None):
    """(множество адресов, ok). ok=False — список НЕ получен.

    Пустое множество и ok=False — разные вещи: первое честное «ящиков нет»
    (создать первый ящик можно), второе означает, что мы ничего не знаем, и по
    нему нельзя ни разрешать, ни запрещать операцию.
    """
    if panel_type is None:
        panel_type = detect_panel(checker)
    if panel_type == 'ispmanager':
        rows, ok, _ = isp_rows(checker, 'email')
        return ({r['name'].strip().lower() for r in rows if r.get('name')},
                ok)
    if panel_type == 'fastpanel':
        out, rc = mogwai(checker, 'emails boxes list')
        if rc != 0:
            return set(), False
        return ({r['ADDRESS'].strip().lower()
                 for r in parse_mogwai_table(out) if r.get('ADDRESS')}, True)
    return set(), False


# create: ящика ещё нет; passwd/delete: ящик обязан существовать.
MAILBOX_MODES = ('create', 'passwd', 'delete')


def mailbox_guard(checker, address, panel_type=None, mode='create'):
    """None, если операцию можно слать панели; иначе — текст причины отказа.

    Проверяется ровно то, на чём панель отвечает невнятно:
    - домен обязан быть почтовым доменом этого сервера — иначе панель заведёт
      ящик на домен, почту которого сервер не принимает, и оператор будет
      ждать письма, которое никогда не придёт;
    - create: ящика ещё нет (у ISPmanager на существующем elid edit меняет
      пароль молча — оператор решит, что создал второй ящик);
    - passwd/delete: ящик есть. Если список ящиков не получен, отказываем:
      удалить «похожий, но не тот» адрес дороже, чем не удалить ничего.
    """
    parsed, err = parse_mailbox_address(address)
    if parsed is None:
        return err
    local, domain = parsed
    addr = f'{local}@{domain}'

    mail_domains = {d.lower() for d in discover_mail_domains(checker,
                                                             panel_type)}
    if domain not in mail_domains:
        shown = ', '.join(sorted(mail_domains)[:8]) or '—'
        return (f'Домен {domain} не является почтовым доменом этого сервера '
                f'(известные: {shown}). Сначала добавьте домен в панель.')

    known, ok = known_mailbox_addresses(checker, panel_type)
    if mode == 'create':
        if ok and addr in known:
            return (f'Ящик {addr} уже существует — для смены пароля есть '
                    '«Сменить пароль ящика».')
        return None
    if not ok:
        return ('Список ящиков панели не получен — подтвердить существование '
                f'{addr} нельзя, операция отменена.')
    if addr not in known:
        return (f'Ящик {addr} не найден среди {len(known)} ящиков панели — '
                'адрес обязан совпадать точно.')
    return None


def password_policy(password):
    """Текст причины отказа либо None. Проверка ДО отправки — панель отказала
    бы сама, но её сообщение («пароль не соответствует требованиям») оператору
    ничего не говорит."""
    if not password:
        return 'Пароль не задан'
    if len(password) < MAILBOX_MIN_PASSWORD:
        return (f'Панель требует пароль не короче '
                f'{MAILBOX_MIN_PASSWORD} символов')
    return None


_SECRET_KEYS = ('passwd', 'confirm', 'password', 'secret')
_SECRET_RE = re.compile(
    r'(?i)\b(' + '|'.join(_SECRET_KEYS) + r')=(\'[^\']*\'|"[^"]*"|\S+)')


def redact_secrets(text):
    """passwd=/confirm=/password= — в отчёте только звёздочки.

    Команду mgrctl мы показываем оператору, чтобы операцию можно было
    повторить руками; без маскирования пароль уехал бы в окно вывода, а
    оттуда — в сохранённый отчёт (gui маскирует лог-файл, но не наш ответ).

    Сначала — честный разбор shlex: значение с пробелом живёт в кавычках, и
    регэксп по пробелам его разрезал бы пополам, оставив хвост пароля в отчёте
    (regression: 'sup3r secret' маскировался до '*** secret'). Если текст не
    является командой (вывод панели, многострочный), применяется регэксп,
    который умеет значения в кавычках целиком.
    """
    if not text:
        return text or ''
    if '\n' not in text:
        try:
            parts = shlex.split(text)
        except ValueError:
            parts = None
        if parts is not None:
            redacted = False
            for i, token in enumerate(parts):
                key, sep, _value = token.partition('=')
                if sep and key.lower() in _SECRET_KEYS:
                    parts[i] = f'{key}=***'
                    redacted = True
            if redacted:
                return ' '.join(parts)
    return _SECRET_RE.sub(lambda m: f'{m.group(1)}=***', text)


def panel_unsupported(panel_type, what):
    """Отчёт «панель это не умеет» — вместо тихого молчания или кривой команды."""
    return [f"⚠️ {what} недоступно для панели '{panel_type or 'не определена'}'.",
            "    Поддерживаются ISPmanager (mgrctl email.*) и FASTPANEL "
            "(mogwai emails boxes ...)."]


# ==================== ДЕЙСТВИЯ С ЯЩИКАМИ ====================
# Порядок в каждой операции одинаковый и он принципиален:
#   1) guard (адрес/домен/существование) — до любой команды панели;
#   2) сама команда;
#   3) ПЕРЕЧИТЫВАНИЕ списка панели. rc=0 у mgrctl не означает «ящик создан»:
#      панель отвечает sok-подтверждением и при частично применённой операции,
#      поэтому проверяем факт — адрес появился/исчез из списка.
def _mailbox_action(checker, address, password, panel_type, mode):
    """Общее исполнение: поддержка панели -> guard -> команда -> перечитывание."""
    titles = {'create': 'СОЗДАНИЕ ПОЧТОВОГО ЯЩИКА',
              'passwd': 'СМЕНА ПАРОЛЯ ПОЧТОВОГО ЯЩИКА',
              'delete': 'УДАЛЕНИЕ ПОЧТОВОГО ЯЩИКА'}
    verbs = {'create': 'создан', 'passwd': 'пароль изменён', 'delete': 'удалён'}
    lines = [f"=== {titles[mode]} ==="]

    # Поддержка панели проверяется ПЕРВОЙ и до любого обращения к серверу.
    # Иначе на сервере без панели guard отказал бы сообщением «домен не
    # почтовый» — мы действительно не знаем почтовых доменов без панели, но
    # оператору нужно честное «эта панель так не умеет», а не ложная причина.
    if panel_type not in ('ispmanager', 'fastpanel'):
        lines.extend(panel_unsupported(panel_type, titles[mode].lower()))
        return "\n".join(lines)
    if panel_type == 'fastpanel' and mode == 'passwd':
        # У mogwai нет команды смены пароля ящика — только create/delete
        # (KB FASTPANEL, CLI/Email). Придумывать флаг --password у
        # несуществующей команды нельзя, а лезть на сервер за списком ящиков,
        # чтобы сообщить «не умею», — лишние запросы.
        lines.append("⚠️ Смена пароля ящика в CLI FASTPANEL не предусмотрена")
        lines.append("    (mogwai emails boxes умеет только create/delete).")
        lines.append("    Смените пароль в панели: Почта → Ящики → «Изменить».")
        return "\n".join(lines)

    parsed, err = parse_mailbox_address(address)
    if parsed is None:
        lines.append(f"❌ {err}")
        return "\n".join(lines)
    local, domain = parsed
    addr = f'{local}@{domain}'

    if mode in ('create', 'passwd'):
        why = password_policy(password)
        if why:
            lines.append(f"❌ {why}")
            return "\n".join(lines)

    reason = mailbox_guard(checker, addr, panel_type, mode)
    if reason:
        lines.append(f"⛔ Операция отменена до отправки команды панели:\n   {reason}")
        return "\n".join(lines)

    if panel_type == 'ispmanager':
        if mode == 'create':
            cmd = isp_mailbox_create_command(local, domain, password)
        elif mode == 'passwd':
            cmd = isp_mailbox_passwd_command(addr, password)
        else:
            cmd = isp_mailbox_delete_command(addr)
    else:  # fastpanel (passwd отсеян выше)
        if mode == 'create':
            cmd = fp_mailbox_create_command(local, domain, password)
        else:
            rows, _rc = mogwai(checker, 'emails boxes list')
            box_id = find_fp_mailbox_id(parse_mogwai_table(rows), addr)
            if box_id is None:
                lines.append(f"⛔ mogwai не вернул числовой ID ящика {addr} — "
                             "удаление отменено (нужен именно ID из boxes list).")
                return "\n".join(lines)
            cmd = fp_mailbox_delete_command(box_id)

    lines.append("$ " + redact_secrets(cmd))
    out, errtxt, rc = checker.run(cmd)
    report = (out or '').strip() or (errtxt or '').strip()
    if rc != 0:
        lines.append(f"❌ Панель ответила ошибкой (rc={rc}): "
                     f"{redact_secrets(report) or 'без сообщения'}")
        return "\n".join(lines)
    if report:
        lines.append(redact_secrets(report))

    # Подтверждение фактом, а не кодом возврата.
    known, ok = known_mailbox_addresses(checker, panel_type)
    if not ok:
        lines.append("⚠️ Команда выполнена, но список ящиков после неё не "
                     "получен — проверьте вручную («Почта: домены, ящики»).")
    elif mode == 'delete':
        if addr not in known:
            lines.append(f"✅ Ящик {addr} удалён (в списке панели его нет)")
        else:
            lines.append(f"⚠️ Панель не сообщила об ошибке, но {addr} всё ещё "
                         "в списке — проверьте вручную.")
    else:
        if addr in known:
            verb = verbs[mode]
            lines.append(f"✅ Ящик {addr}: {verb}" if mode == 'passwd'
                         else f"✅ Ящик {addr} создан и виден в списке панели")
        else:
            lines.append(f"⚠️ Команда прошла без ошибки, но {addr} не появился "
                         "в списке панели — проверьте вручную.")

    if mode in ('create', 'passwd'):
        lines.append("⚠️ Пароль передавался аргументом команды и был виден в ps:")
        lines.append("   при возможности смените его на постоянный через панель.")
    return "\n".join(lines)


def mailbox_create(checker, address, password, panel_type=None):
    if panel_type is None:
        panel_type = detect_panel(checker)
    return _mailbox_action(checker, address, password, panel_type, 'create')


def mailbox_passwd(checker, address, password, panel_type=None):
    if panel_type is None:
        panel_type = detect_panel(checker)
    return _mailbox_action(checker, address, password, panel_type, 'passwd')


def mailbox_delete(checker, address, panel_type=None):
    if panel_type is None:
        panel_type = detect_panel(checker)
    return _mailbox_action(checker, address, '', panel_type, 'delete')
