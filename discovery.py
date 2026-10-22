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

from common import (q, find_files, read_file_content, write_remote_file,
                    prepare_secret_file, remove_remote_path)
from logs import (find_logs, mail_log_snapshot_lines,
                  mail_delivery_digest_lines)
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


HTTP_STATE_ICON = {'ok': '✅', 'http_only': '🟡', 'silent': '❌'}


def http_site_state(http, https):
    """Состояние доступности: 'ok' / 'http_only' / 'silent'.

    Единая классификация, из которой берут И иконку строки, И сводный счётчик.
    Второй реализации не будет сознательно: два набора правил однажды
    разъехались бы, и сводка стала бы считать одну беду, а строка — другую
    (оператор прочитал бы «молчит — 1» там, где лежит другой сайт).
    """
    if https not in ('000', '') and https[0] in '23':
        return 'ok'
    if http not in ('000', '') and http[0] in '23':
        return 'http_only'
    return 'silent'


def http_status_icon(http, https):
    """Зелёный — HTTPS отвечает 2xx/3xx; жёлтый — только HTTP; красный — тихоня."""
    return HTTP_STATE_ICON[http_site_state(http, https)]


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


CERT_STATE_ICON = {'expired': '❌', 'soon': '⚠️', 'ok': '✅', 'none': '❓'}


def cert_state(days):
    """Состояние сертификата: 'expired' / 'soon' / 'ok' / 'none' (не получен).

    Как и http_site_state — единственная классификация: из неё берут и иконку
    строки, и сводный счётчик. Второй реализации нет намеренно.
    """
    if days is None:
        return 'none'
    if days < 0:
        return 'expired'
    if days < SSL_WARN_DAYS:
        return 'soon'
    return 'ok'


def cert_days_icon(days):
    """Иконка по остатку: None — сертификат не получен (порт/нет TLS)."""
    return CERT_STATE_ICON[cert_state(days)]


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


def site_health_probe(checker, sites, limit=HEALTH_CHECK_LIMIT):
    """Одна проба на домен; состояния — ТЕМИ ЖЕ функциями, что печатают иконки.

    Возвращает (домен, состояние_доступности, состояние_сертификата, статус).
    Состояние сертификата равен None, когда SSL-пометка в строке не печатается
    (HTTPS молчит: сертификат чужого дефолтного vhost нельзя показывать как
    свой). Считать тогда сертификат в сводке — значит учесть то, что отчёт
    намеренно не показал.
    """
    rows = []
    for site in sites[:limit]:
        status = parse_site_status(
            checker.exec_command(site_status_command(site['domain']))[0])
        cert = (cert_state(status['cert_days'])
                if status['https'] not in ('000', '') else None)
        rows.append((site['domain'],
                     http_site_state(status['http'], status['https']),
                     cert, status))
    return rows


def site_health_render(probed):
    """Строки состояния по уже снятой пробе (второй прогон проб — не здесь)."""
    lines = []
    for dom, state, cert, status in probed:
        ssl = ''
        if cert is not None:
            ssl = (f"  {CERT_STATE_ICON[cert]} SSL "
                   f"{cert_days_label(status['cert_days'])}")
        lines.append(f"  {HTTP_STATE_ICON[state]} {dom:45s} "
                     f"http={status['http']:3s} https={status['https']:3s}"
                     f"{ssl}")
    return lines


def site_health_counts(probed):
    """Счётчики категорий из тех же состояний, что напечатали иконки."""
    known = ('ok', 'http_only', 'silent')
    return dict(
        ok=sum(1 for r in probed if r[1] == 'ok'),
        http_only=sum(1 for r in probed if r[1] == 'http_only'),
        silent=sum(1 for r in probed if r[1] == 'silent'),
        unknown=sum(1 for r in probed if r[1] not in known),
        cert_expired=sum(1 for r in probed if r[2] == 'expired'),
        cert_soon=sum(1 for r in probed if r[2] == 'soon'),
        cert_none=sum(1 for r in probed if r[2] == 'none'))


def site_health_summary(ok=0, http_only=0, silent=0, unknown=0,
                        cert_expired=0, cert_soon=0, cert_none=0, total=0):
    """Сколько сайтов лежит — строки в шапку блока, до чтения списка.

    Считается СОСТОЯНИЕМ, а не символом «❌» в готовом тексте: в строке домена
    ДВЕ иконки — доступности (сайт молчит) и сертификата (истёк), и подсчёт по
    символу дал бы «мёртвых сайтов» больше, чем их есть. Та же грабля, что с
    «🌐» в SPF-отчёте.

    Число непроверенных доменов называет знаменатель («25 из 30») плюс сноска
    про HEALTH_CHECK_LIMIT снизу: отдельной строки о них нет намеренно —
    третье упоминание оператор читает как невнимательность.
    """
    checked = ok + http_only + silent + unknown
    if not checked:
        return []
    parts = []
    if ok:
        parts.append(f'HTTPS 2xx/3xx — {ok}')
    if http_only:
        parts.append(f'только HTTP — {http_only}')
    if silent:
        parts.append(f'молчит — {silent}')
    if unknown:
        # Неизвестное состояние = «мы не поняли», а не «в порядке»: молча
        # отнести его в ok значило бы занизить число бед.
        parts.append(f'Не распознано — {unknown}')
    lines = [f"Проверено доступности: {checked} из {total or checked}"
             + (': ' + ', '.join(parts) if parts else '.')]
    cert_parts = []
    if cert_expired:
        cert_parts.append(f'истёк — {cert_expired}')
    if cert_soon:
        cert_parts.append(f'истекает < {SSL_WARN_DAYS} дн. — {cert_soon}')
    if cert_none:
        cert_parts.append(f'сертификат не получен — {cert_none}')
    if cert_parts:
        # Отдельная строка: мёртвый сертификат и молчащий сайт — разные беды,
        # чинят их разные люди (let's encrypt против nginx).
        lines.append('   SSL: ' + ', '.join(cert_parts))
    return lines


def site_health_footnote(sites, limit=HEALTH_CHECK_LIMIT):
    """Сноска о том, что за limit доступность не смотрели (один текст на всех)."""
    if len(sites) <= limit:
        return []
    return [f"  … доступность проверялась для первых {limit} из {len(sites)}"]


def site_health_lines(checker, sites, limit=HEALTH_CHECK_LIMIT):
    """HTTP/HTTPS-коды и остаток SSL по сайтам (не больше limit внешних проб)."""
    return (site_health_render(site_health_probe(checker, sites, limit))
            + site_health_footnote(sites, limit))


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
    # Проба снимается ОДИН раз и кормит И сводку, И список: второй вызов
    # site_health_probe означал бы ещё 25 внешних хендшейков на прогон (и GUI
    # висел бы вдвое дольше). Сводка печатается ДО строк: при 25 доменах
    # оператор обязан узнать масштаб беды, а не досчитывать иконки глазами.
    probed = site_health_probe(checker, sites)
    lines.extend(site_health_summary(**site_health_counts(probed),
                                     total=len(sites)))
    lines.extend(site_health_render(probed))
    lines.extend(site_health_footnote(sites))
    return "\n".join(lines)


def ssl_expiry_head_lines(not_received=0):
    """Что шапка SSL-отчёта обязана сказать, кроме «истекло / истекает».

    До этой правки шапка говорила «Истекло: 0, истекает < 30 дн.: 0» — и
    оператор, прочитавший её, уже решил, что с SSL всё хорошо. А блок «СЕРТИФИКАТ
    НЕ ПОЛУЧЕН» (порт 443 молчит) прятался под всем списком доменов. Неполученный
    сертификат — не «истёк» и не «в порядке»: это третье состояние, и то, что о
    нём молчит первая строка, нарушает закон «не проверено ≠ в порядке».

    Число берётся только из ПРОВЕРЕННЫХ доменов: домены за HEALTH_CHECK_LIMIT не
    могли «не получить» сертификат, который никто не запрашивал. Отдельной
    строки про них нет: знаменатель «25 из 30» в той же шапке называет их и так.
    """
    if not not_received:
        return []
    return [f"   Сертификат не получен — {not_received}: HTTPS не отвечает или "
            f"отвечает без рабочего TLS. Это не «с SSL всё в порядке»,",
            "   и не «истекло»: список таких доменов — в блоке ниже."]


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
    quiet = [r for r in rows if r[1] is None]
    lines.append(f"Проверено доменов: {len(rows)} из {len(sites)}. "
                 f"Истекло: {len(expired)}, истекает < {SSL_WARN_DAYS} дн.: "
                 f"{len(warning)}")
    # Сразу под шапкой, а не под всем списком: «Истекло: 0» — ещё не «всё в
    # порядке», если у половины доменов сертификат не получен вообще.
    lines.extend(ssl_expiry_head_lines(not_received=len(quiet)))
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

    if quiet:
        # Список уже посчитан выше (для шапки) — второй фильтр означал бы
        # вторую реализацию того же счёта.
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

    # mailq отвечает «сколько писем стоит», но не отвечает «почему». Причина
    # живёт в логе: `status=bounced ... 550 ...` — это и есть ответ на тикет
    # «письма уходят в спам». Снимок идёт внутрь этой сводки, а не отдельным
    # пунктом меню: тикет закрывается одним прогоном, а меню не разрастается.
    #
    # Здесь снимок получает ЕЩЁ и список почтовых доменов сервера. Без него
    # отчёт показал бы «отправители: lie.ru — 3» без ответа на вопрос «а lie.ru
    # вообще наш?»: называть домен нашим по догадке — то же враньё, что и
    # поднимать «не проверено» до «в порядке». Инвентарь уже запрошен строкой
    # выше, поэтому вторая цена — ноль.
    lines.append('')
    lines.extend(mail_log_snapshot_lines(checker, our_domains=domains))

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


# ======== ПИСЬМА В СПАМ: SPF / DKIM / DMARC / PTR (DNS, не синтаксис панели) ==
# Причина №1 в тикетах «почта работает, а письма уходят в спам» — не postfix и
# не панель, а DNS: нет SPF, нет DKIM, нет DMARC, нет PTR. Проверка стоит
# несколько dig-запросов на домен и НЕ требует синтаксиса панелей — тот же dig,
# что уже работает в «Досье домена» и в dns.py.
#
# Селектор DKIM обязан быть СПИСКОМ, а не одним именем: запись живёт в
# <selector>._domainkey.<domain>, а получатель ищет её по тегу s= из заголовка
# DKIM-Signature. Сказать «DKIM нет» честно можно только перечислив селекторы,
# которые реально ставят панель и MTA:
#   dkim                — FASTPANEL (kb.fastpanel.direct: «Name: dkim._domainkey»)
#   default             — ISPmanager / opendkim по умолчанию
#   mail, s1, s2, k1-k3 — rspamd; google — Workspace
# Молчание по всем ним = «нет подписи ни по одному из известных селекторов», а
# не «подписи нет вообще». Эта оговорка входит в отчёт: без неё проверка врёт.
#
# TXT длиннее 255 символов DNS хранит несколькими строками, и dig выдаёт их
# кусками в кавычках: швы склеиваются (_join_txt_chunks), иначе DKIM-ключ
# выглядел бы оборванным, а «-all» в хвосте SPF — отсутствующим.
MAIL_AUTH_SELECTORS = ('dkim', 'default', 'mail', 's1', 's2', 'k1', 'k2', 'k3',
                       'google')
# RFC 7208 §4.6.4: разбор SPF ограничен 10 DNS-запросами. Больше — PermError, и
# приёмщик письмо ОТКЛОНЯЕТ, хотя синтаксически запись правильная.
MAX_SPF_LOOKUPS = 10
# Оценка длины RSA-ключа по base64-строке записи. Точный размер по base64 не
# вычислить (внутри ASN.1-обёртка), поэтому порог — ОЦЕНКА, и в отчёте мы пишем
# «короче 1024 бит», а не «это 512-битный ключ». SubjectPublicKeyInfo для
# RSA-1024 ≈ 162 байта ≈ 216 символов base64, для RSA-512 ≈ 106 символов.
# Берём 200: штатные 1024-битные ключи панелей не задевает, 512-битные ловит
# (часть приёмников, в том числе строгие правила Microsoft, их не принимает).
DKIM_MIN_KEY_B64 = 200
AUTH_ICON = {'ok': '✅', 'warn': '⚠️', 'bad': '❌'}
# Вердикт домена = ХУДШАЯ из проверок: в спам письмо кладёт одна проваленная
# проверка, а не средняя арифметическая.
AUTH_SEVERITY = {'ok': 0, 'warn': 1, 'bad': 2}

# ---------- внешняя сверка (dig из точки зрения интернета) ----------
# Когда зону обслуживает этот же сервер (или резолвер смотрит в localhost),
# `dig` показывает ЛОКАЛЬНОЕ содержимое зоны. Предупредить об этом мало:
# оператор получает «SPF ✅» и останавливается, а публичная зона может быть
# пустой. Поэтому проект сам повторяет те же запросы к публичному резолверу.
PUBLIC_RESOLVERS = ('1.1.1.1', '8.8.8.8')
# Без таймаута недоступный резолвер вешает канал на 5 с × попытки; с ними
# `dig` отвечает rc=9 примерно за секунду (проверено живым прогоном).
DNS_TIMEOUT_ARGS = '+timeout=2 +tries=1'
# rc=0 означает «DNS-сервер ответил» (в т.ч. NXDOMAIN и пустой ответ), rc=9 —
# «до сервера не достучались». Различать их обязательно: пустой вывод при rc=9
# был бы прочитан как «записей нет», и сверка сама стала бы источником лжи.
DIG_RC_ANSWERED = 0


# ---------- команды (собираются чистыми функциями — тесты без SSH) ----------
def a_query_command(domain):
    """A-запись домена: из неё берём IP, по которому спрашиваем PTR."""
    return f'dig +short A {q(domain)} 2>/dev/null'


def spf_query_command(domain):
    """SPF — TXT на самом домене (RFC 7208)."""
    return f'dig +short TXT {q(domain)} 2>/dev/null'


def dmarc_query_command(domain):
    """DMARC — TXT на _dmarc.<domain> (RFC 7489)."""
    return f'dig +short TXT {q('_dmarc.' + domain)} 2>/dev/null'


def dkim_query_command(domain, selectors=MAIL_AUTH_SELECTORS):
    """TXT по всем селекторам ОДНОЙ командой; вывод — 'имя|значение'.

    Имя печатается целиком, без shell-срезки ${var%...}: парсер срезает суффикс
    сам, зато в отчёте видно, какой именно селектор дал запись, и цикл не
    ломается на именах с подчёркиваниями.
    """
    names = ' '.join(q(f'{s}._domainkey.{domain}') for s in selectors)
    return (f'for __dk in {names}; do printf "%s|" "$__dk"; '
            f'dig +short TXT "$__dk" 2>/dev/null; printf "\\n"; done')


def ptr_query_command(ip):
    """PTR по IP. Вызывается только когда IP известен — иначе нечего спрашивать."""
    return f'dig +short -x {q(ip)} 2>/dev/null'


# Внешняя сверка: те же записи, но спросить у публичного резолвера.
# rtype приходит только из EXTERNAL_QUERY_TYPES — в команду он попадает НЕ
# через q(), поэтому список проверяется здесь: иначе будущий вызывающий смог бы
# подсунуть в dig сырое имя и вся защита q() обнулилась бы.
EXTERNAL_QUERY_TYPES = ('TXT', 'A', '-x')
# Имя для проверки «резолвер вообще отвечает». Нужен заведомо живой хост:
# пустой ответ от 1.1.1.1 означает не «интернет есть», а «мы не у дел».
EXTERNAL_PROBE_NAME = 'a.root-servers.net'


def external_query_command(rtype, name, resolver=PUBLIC_RESOLVERS[0]):
    """Запрос к публичному резолверу; в выводе — ответ и строка «rc=N».

    rc печатается ОБЯЗАТЕЛЬНО. Без него пустой вывод при недоступном резолвере
    (dig отвечает rc=9) не отличим от честного «записей нет» (rc=0), и сверка,
    призванная снимать ложь, сама начала бы врать оператору.
    """
    if rtype not in EXTERNAL_QUERY_TYPES:
        raise ValueError(f'разрешены только запросы {EXTERNAL_QUERY_TYPES}')
    # Резолвер — строго через @server. Живой прогон показал, что positional-форма
    # (`dig A name 1.1.1.1`) адрес сервером не считает: запрос уходил на местный
    # резолвер и отвечал за 0.0 с даже при заведомо мёртвом IP. Оставить её —
    # значит выдать локальную зону с подписью «из интернета», то есть ровно ту
    # ложь, ради исправления которой сверка и пишется.
    return (f'dig +short {rtype} {q(name)} @{q(resolver)} {DNS_TIMEOUT_ARGS} '
            f'2>/dev/null; printf "rc=%s\\n" $?')


def external_probe_command(resolver=PUBLIC_RESOLVERS[0]):
    """Жив ли публичный резолвер: спрашиваем имя, обязанное иметь запись.

    Один запрос на весь прогон, а не на каждый домен. Если резолвер недоступен,
    сверки не будет вовсе и отчёт скажет «сверить не удалось» — вместо
    «записей нет», которая была бы ложью о чужом DNS.
    """
    return (f'dig +short A {q(EXTERNAL_PROBE_NAME)} @{q(resolver)} '
            f'{DNS_TIMEOUT_ARGS} 2>/dev/null')


def public_resolver(checker, resolvers=PUBLIC_RESOLVERS):
    """Первый публичный резолвер, который ОТВЕЧАЕТ (или '').

    Один probe на резолвер за прогон, а не на домен: домен с пустой зоной
    отвечает так же пусто, как недоступный резолвер, и по запросу к самому
    домену «жив ли DNS» не отличить. Поэтому спрашиваем заведомо живое имя.

    '' — сверять нечем, и отчёт обязан сказать об этом словами «сверить не
    удалось», а не промолчать: отсутствие сверки, выдаваемое за «наружу всё
    чисто», было бы второй ложью вместо первой.
    """
    for resolver in resolvers:
        # first_ipv4, а не «непустой вывод»: ответ обязан быть адресом, иначе
        # любой мусор в stdout сошёл бы за «резолвер жив».
        if first_ipv4(checker.exec_command(
                external_probe_command(resolver))[0]):
            return resolver
    return ''


# ---------- чистые парсеры ----------
def _join_txt_chunks(text):
    """'AAA' 'BBB' -> AAABBB: склейка частей длинной TXT, разбитых dig."""
    return (text or '').replace('" "', '').replace('"', '').strip()


def parse_dns_txt(out):
    """Вывод `dig +short TXT` -> список значений (швы склеены, пустые выброшены)."""
    return [v for v in (_join_txt_chunks(line) for line in (out or '').splitlines())
            if v]


def parse_ptr(out):
    """'mail.example.com.' -> 'mail.example.com'; пусто -> '' (записи нет)."""
    for line in (out or '').splitlines():
        name = line.strip().rstrip('.').lower()
        if name:
            return name
    return ''


def first_ipv4(out):
    """Первый IPv4 из `dig +short A` ('' для CNAME и для пустого ответа).

    CNAME на cdn — не редкость, а PTR спрашивается по адресу, не по имени:
    вернуть здесь CNAME означало бы спросить `-x some-cdn.net` и получить
    неправдоподобный «PTR нет».
    """
    for token in (out or '').split():
        token = token.rstrip('.')
        if (re.fullmatch(r'\d{1,3}(\.\d{1,3}){3}', token)
                and all(int(octet) <= 255 for octet in token.split('.'))):
            return token
    return ''


def parse_spf(txts):
    """TXT домена -> {'status','reason','detail','lookups','includes'}.

    bad — SPF нет или он такой, что приёмник его не применит; warn — SPF есть,
    но с ловушкой; ok. «TXT нет вообще» и «TXT есть, но не SPF» различаются в
    detail: во втором случае оператору стоит искать запись в другой зоне.

    reason — машинночитаемый код беды ('missing', 'broken_version', 'duplicate',
    'too_many_lookups', 'plus_all', 'no_mechanism', 'ok'). Подсказка «что
    вставить» строится по нему, а НЕ по тексту detail: формулировки мы правим
    ради читаемости отчёта, и подсказка, привязанная к фразе, отвалилась бы на
    первом же перефразировании — молча, показав оператору неверную запись.
    """
    spf = [t for t in txts if t.lower().startswith('v=spf1')]
    if not spf:
        broken = [t for t in txts if t.lower().startswith('v=spf')]
        if broken:
            # Типичная опечатка: 'v=spf ' без единицы — приёмщик запись не видит
            return {'status': 'bad', 'reason': 'broken_version', 'lookups': 1,
                    'includes': [],
                    'detail': 'запись начинается с „v=spf“ без 1 — SPF не '
                              'распознаётся: ' + broken[0][:80]}
        return {'status': 'bad', 'reason': 'missing', 'lookups': 1,
                'includes': [],
                'detail': (('TXT-записей у домена нет вообще' if not txts
                            else f'SPF (v=spf1) нет среди {len(txts)} TXT-записей')
                           + ' — письмо без SPF приёмники кладут в спам')}
    includes = [token.lower().split(':', 1)[1]
                for record in spf for token in record.split()
                if token.lower().startswith('include:')]
    lookups = 1 + len(includes)
    low = spf[0].lower()
    shown = spf[0] if len(spf[0]) <= 88 else spf[0][:85] + '…'
    if len(spf) > 1:
        # RFC 7208 §3.6: две SPF-записи — это не SPF, приёмник отвечает PermError
        return {'status': 'bad', 'reason': 'duplicate', 'lookups': lookups,
                'includes': includes,
                'detail': f'{len(spf)} SPF-записи — по RFC 7208 это PermError, '
                          f'письма отклоняются; оставьте одну'}
    if lookups > MAX_SPF_LOOKUPS:
        return {'status': 'bad', 'reason': 'too_many_lookups',
                'lookups': lookups, 'includes': includes,
                'detail': f'{lookups} DNS-запросов (include: {len(includes)}) > '
                          f'{MAX_SPF_LOOKUPS} — по RFC 7208 PermError, часть '
                          f'приёмников письмо отклонит'}
    if ' redirect=' in low:
        return {'status': 'ok', 'reason': 'ok', 'lookups': lookups,
                'includes': includes, 'detail': shown + '  (redirect=)'}
    if '+all' in low:
        return {'status': 'bad', 'reason': 'plus_all', 'lookups': lookups,
                'includes': includes,
                'detail': shown + ' — „+all“ разрешает отправлять с ЛЮБОГО IP, '
                                  'фильтры такую запись не учитывают'}
    if not re.search(r'(^|\s)[-?~]all(\s|$)', low):
        return {'status': 'warn', 'reason': 'no_mechanism', 'lookups': lookups,
                'includes': includes,
                'detail': shown + ' — нет механизма all: формально разрешены '
                                  'чужие серверы'}
    return {'status': 'ok', 'reason': 'ok', 'lookups': lookups,
            'includes': includes, 'detail': shown}


def parse_dkim(out, domain):
    """Строки 'имя|значение' -> {'status','reason','selectors','revoked','detail'}.

    Пустой p= — отдельный случай, а не «запись есть»: так отзывают ключ, и
    подпись с такой записью получатель проверить не сможет (частая грабля после
    «чистили DNS»). Строк без v=DKIM1 (CNAME на чужую зону, мусор) не считаем.

    reason ('ok' | 'short_key' | 'revoked' | 'missing') — по нему подсказка
    решает, что можно сказать оператору: для DKIM готовую запись не выдают
    никогда (приватный ключ живёт на сервере), и различать «нет» / «отозван» /
    «короткий» важно, иначе совет был бы один на все три беды.
    """
    suffix = '._domainkey.' + domain.lower()
    found, short, revoked = [], [], []
    current = ''
    for line in (out or '').splitlines():
        name, sep, raw = line.partition('|')
        if sep:
            low = name.strip().lower()
            if not low.endswith(suffix):
                current = ''          # строка чужого домена — сбрасываем якорь
                continue
            current = low[:-len(suffix)] or '?'
            raw_value = raw
        else:
            # Ротация ключа: у селектора бывает несколько TXT, и dig печатает их
            # отдельными строками БЕЗ имени. Якорь — последний селектор: иначе
            # второй (боевой) ключ терялся бы, а первый с пустым p= выглядел бы
            # как «ключ отозван».
            if not current:
                continue
            raw_value = line
        selector = current
        value = _join_txt_chunks(raw_value)
        if not value.lower().startswith('v=dkim1'):
            continue
        key = ''
        for token in value.replace(';', ' ').split():
            if token.lower().startswith('p='):
                key = token[2:].strip()
        if not key:
            revoked.append(selector)
        else:
            found.append(selector)
            if len(key) < DKIM_MIN_KEY_B64:
                short.append(selector)
    if not found and not revoked:
        return {'status': 'bad', 'reason': 'missing', 'selectors': [],
                'revoked': [],
                'detail': f'записи нет ни по одному из '
                          f'{len(MAIL_AUTH_SELECTORS)} проверенных селекторов'}
    if not found:
        return {'status': 'bad', 'reason': 'revoked', 'selectors': [],
                'revoked': revoked,
                'detail': f'запись есть, но p= пустой ({", ".join(revoked)}): '
                          f'ключ отозван — подпись проверить нельзя'}
    detail = 'подпись по селектору: ' + ', '.join(found[:4])
    if revoked:
        detail += f' (+{len(revoked)} с пустым p=)'
    if short:
        return {'status': 'warn', 'reason': 'short_key', 'selectors': found,
                'revoked': revoked,
                'detail': f'ключ короче 1024 бит: {", ".join(short[:4])} — '
                          f'строгие приёмники такую подпись не примут'}
    return {'status': 'ok', 'reason': 'ok', 'selectors': found,
            'revoked': revoked, 'detail': detail}


def parse_dmarc(txts):
    """TXT _dmarc -> {'status','reason','policy','rua','detail'}.

    Отсутствие DMARC — warn, а не bad: по RFC 7489 это рекомендация, и письма
    без него продолжают доходить. Рисовать за это ❌ нельзя.

    reason ('ok' | 'missing' | 'no_policy_tag' | 'bad_policy' | 'monitoring' |
    'no_rua') — по нему подсказка различает «записи нет вовсе» (можно выдать
    шаблон) и «запись есть, но настроена слабо» (её правят, а не плодят вторую).
    """
    rec = next((t for t in txts if t.lower().startswith('v=dmarc1')), None)
    if not rec:
        return {'status': 'warn', 'reason': 'missing', 'policy': '', 'rua': '',
                'detail': 'записи _dmarc нет: без DMARC SPF и DKIM к заголовку '
                          'From не применяются — поддомен могут слать от вашего '
                          'имени'}
    fields = {}
    for token in rec.split(';'):
        key, sep, value = token.partition('=')
        if sep:
            fields[key.strip().lower()] = value.strip()
    policy = (fields.get('p') or '').lower()
    rua = fields.get('rua') or ''
    if 'p' not in fields:
        # RFC 7489 делает тег p обязательным: без него приёмник запись не
        # применяет. Назвать это «p=none» было бы враньём — режим наблюдения
        # хотя бы собирает сводки, а здесь DMARC не работает вовсе.
        return {'status': 'warn', 'reason': 'no_policy_tag', 'policy': '',
                'rua': rua,
                'detail': 'нет обязательного тега p: по RFC 7489 приёмник такую '
                          'запись не применяет, DMARC не работает'}
    if policy not in ('none', 'quarantine', 'reject'):
        return {'status': 'warn', 'reason': 'bad_policy', 'policy': policy,
                'rua': rua,
                'detail': f'режим p={policy or "—"} не распознан — приёмник '
                          f'применит NONE'}
    if policy == 'none':
        return {'status': 'warn', 'reason': 'monitoring', 'policy': policy,
                'rua': rua,
                'detail': 'p=none — только наблюдение, письма не отклоняются'
                          + ('' if rua else '; rua нет — сводок не будет')}
    if not rua:
        return {'status': 'warn', 'reason': 'no_rua', 'policy': policy,
                'rua': rua,
                'detail': f'p={policy}, но rua нет: сводки о чужой рассылке с '
                          f'домена приходить не будут'}
    return {'status': 'ok', 'reason': 'ok', 'policy': policy, 'rua': rua,
            'detail': f'p={policy}, отчёты rua настроены'}


def external_dkim_query_command(domain, selectors=MAIL_AUTH_SELECTORS,
                                resolver=PUBLIC_RESOLVERS[0]):
    """Тот же цикл селекторов, что и локальный, но у публичного резолвера.

    rc — ФЛАГ по всему циклу, а не код последней команды: иначе одна
    таймаутная итерация выглядела бы как «извне записей нет», а сверка,
    которая врёт про чужой DNS, хуже отсутствия сверки.
    """
    names = ' '.join(q(f'{s}._domainkey.{domain}') for s in selectors)
    return (f'__bad=0; for __dk in {names}; do printf "%s|" "$__dk"; '
            f'dig +short TXT "$__dk" @{q(resolver)} {DNS_TIMEOUT_ARGS} '
            f'2>/dev/null || __bad=1; printf "\\n"; done; '
            f'printf "rc=%s\\n" "$__bad"')


def parse_external_answer(out):
    """Вывод внешней команды -> (строки ответа, rc или None).

    Строки «;; ...» отсекаются не для красоты: при недоступном резолвере dig
    пишет «;; communications error to ...» в STDOUT (2>/dev/null от этого не
    спасает — проверено живым прогоном), и без отсечения текст ошибки ушёл бы в
    парсер TXT как значение записи. В цикле DKIM та же ошибка приклеена к имени
    после «|» — её отсекаем по той же причине.
    """
    lines, rc = [], None
    for raw in (out or '').splitlines():
        line = raw.strip()
        if not line or line.startswith(';;'):
            continue
        if line.startswith('rc='):
            value = line[3:].strip()
            rc = int(value) if value.lstrip('-').isdigit() else None
            continue
        name, sep, value = raw.partition('|')
        if sep and value.lstrip().startswith(';;'):
            raw = name + sep
        lines.append(raw.rstrip())
    return '\n'.join(lines), rc


def external_auth_answers(checker, domain, resolver=PUBLIC_RESOLVERS[0]):
    """Ответы «из интернета» по домену — те же запросы, что и локальные.

    Пять команд (A, TXT домена, _dmarc, цикл селекторов DKIM, PTR по ВНЕШНЕЙ
    A). Формат вывода совпадает с локальным, поэтому разбор — тот же код:
    второй половины правил у программы не появляется.
    Возвращает {'a','spf','dmarc','dkim','ptr': (текст, rc), 'ip', 'answered'}.

    A спрашиваем сами и PTR берём по внешней A: локальная A тоже может врать
    (10.x из локальной зоны), а проверять обратную запись по адресу, которого в
    интернете нет, значит выдумывать вердикт про чужую in-addr зону.

    'answered' — все ли обязательные ответы получены (PTR обязателен только
    когда есть внешняя A). Если нет, сверку делать нечем: пустой вывод при
    недоступном резолвере не отличим от честного «записей нет», и заявить
    «извне SPF нет» означало бы соврать про чужую зону.
    """
    answers = {}
    for kind, cmd in (('a', external_query_command('A', domain, resolver)),
                      ('spf', external_query_command('TXT', domain, resolver)),
                      ('dmarc', external_query_command('TXT',
                                                       '_dmarc.' + domain,
                                                       resolver)),
                      ('dkim', external_dkim_query_command(domain,
                                                           resolver=resolver))):
        # run(), а не exec_command(): нужен rc — он и различает «зона пуста»
        # (dig ответил rc=0 и молчит) от «до резолвера не достучались» (rc=9).
        answers[kind] = parse_external_answer(checker.run(cmd)[0])
    answers['ip'] = first_ipv4(answers['a'][0])
    answers['ptr'] = (parse_external_answer(checker.run(
                          external_query_command('-x', answers['ip'],
                                                 resolver))[0])
                      if answers['ip'] else ('', None))
    answers['answered'] = all(answers[k][1] == DIG_RC_ANSWERED
                              for k in ('a', 'spf', 'dmarc', 'dkim'))
    # У PTR собственный признак ответа: он зависит от внешней A и идёт пятым,
    # поэтому общий 'answered' его не покрывает. Без флага таймаут по -x
    # выглядел бы «обратной записи нет» (❌) — враньё про чужую in-addr зону.
    # Когда адреса нет вовсе, запрос не уходил: _ptr_view сам скажет «нечего
    # спрашивать», и True здесь означает «претензий к PTR нет».
    answers['ptr_answered'] = (not answers['ip']
                               or answers['ptr'][1] == DIG_RC_ANSWERED)
    return answers


EXTERNAL_KINDS = (('SPF', 'spf'), ('DKIM', 'dkim'), ('DMARC', 'dmarc'))


def external_parseds(domain, answers):
    """Внешние ответы, разобранные ТЕМИ ЖЕ парсерами, что и локальные.

    Второй набор правил разбора однажды начал бы противоречить первому: «извне
    SPF нет» и «SPF в порядке» про одну и ту же запись — это не сверка, а спор
    двух половин программы, который оператор читает как «отчёт врёт».
    """
    return {'spf': parse_spf(parse_dns_txt(answers['spf'][0])),
            'dkim': parse_dkim(answers['dkim'][0], domain),
            'dmarc': parse_dmarc(parse_dns_txt(answers['dmarc'][0]))}


def auth_differs(before, after):
    """Отличается ли разбор «из интернета» от локального.

    Сравниваем status, reason И detail. Ограничиться первыми двумя было бы
    подтасовкой: две SPF-записи бывают одновременно `ok` и при этом разными
    (`ip4:1.1.1.1 -all` против `a ~all`), а оператору важно видеть именно это —
    публичная зона может быть старше той, что он правит в панели.
    """
    return (before['status'], before['reason'], before['detail']) != \
           (after['status'], after['reason'], after['detail'])


# ---------- откуда видно записи (без этого вывод был бы ложью) ----------
def resolver_view_note(checker):
    """Предупреждение, если сервер резолвит сам себя: видны локальные зоны."""
    content = read_file_content(checker, '/etc/resolv.conf') or ''
    for line in content.splitlines():
        parts = line.split()
        if len(parts) >= 2 and parts[0] == 'nameserver':
            ns = parts[1]
            if ns.startswith('127.') or ns == '::1' or _is_private_ip(ns):
                return (f'резолвер сервера — {ns}, видны записи локальных зон, '
                        f'а не интернета')
            return ''
    return ''


def _is_private_ip(ip):
    return (ip.startswith('10.') or ip.startswith('192.168.')
            or bool(re.match(r'^172\.(1[6-9]|2\d|3[01])\.', ip)))


def zone_is_local_view(domain, zones, resolver_note=''):
    """Мог ли локальный dig наврать про этот домен (источник условия И текста).

    Непустой ответ = «показано локальное содержимое»: зона лежит здесь либо
    резолвер смотрит в localhost. Это единственное основание лезть в интернет:
    сверять все домены подряд — платить 5 лишних запросов на каждый там, где
    ложный ✅ невозможен (записи локально нет — из неё и так не следует «есть»).
    """
    bits = []
    if any(domain == z or domain.endswith('.' + z) for z in zones):
        bits.append(f'зона {domain} обслуживается этим сервером — видно её '
                    f'локальное содержимое')
    if resolver_note:
        bits.append(resolver_note)
    return bits


def zone_view_note(domain, zones, resolver_note='', verified=False):
    """Откуда видны записи домена: локальная зона / локальный резолвер / ''.

    На сервере с собственной зоной dig чаще всего спрашивает localhost и
    показывает файл зоны. «SPF есть» при пустой ПУБЛИЧНОЙ зоне был бы ложным
    диагнозом, поэтому источник пишется в отчёте и даётся команда сверки извне.

    verified=True значит «сверку уже выполнил сам отчёт» (см. external_diff):
    оставлять тогда команду ручной сверки — просить оператора делать работу,
    которая за него сделана, и он по привычке повторит её вручную.
    """
    bits = zone_is_local_view(domain, zones, resolver_note)
    if not bits:
        return ''
    # Формулировка нейтральна умышленно: «выполнена» было бы ложью, когда
    # резолвер жив, но ответить по домену мы не смогли — провал говорит об этом
    # отдельной строкой «🌐» ниже, а не молчанием.
    bits.append('сверка с публичным DNS: см. строки «🌐»' if verified
                else f'сверьте извне: dig +short TXT {domain} @1.1.1.1')
    return '; '.join(bits)


# ---------- «что вставить в DNS»: подсказки по машинночитаемым reason ----------
# Отчёт «где чинить» оператор читает и так. Недоступный ответ — «что именно
# вставить». Генератор строит его по полю reason, а НЕ по тексту detail:
# формулировки отчёта правятся ради читаемости, и подсказка, привязанная к
# фразе, отвалилась бы молча и показала бы оператору неверную запись.
#
# Граница честности: DKIM не генерируется НИКОГДА. Публичная TXT выводится из
# приватного ключа, который живёт на сервере (rspamd — /etc/rspamd/dkim,
# opendkim — /etc/opendkim/keys/<домен>/; панель FASTPANEL кладёт свою копию в
# раздел «Почта → DKIM»). Выдуманная «готовая» DKIM-запись = подпись, которую
# приёмник отвергнет, а оператор решит, что «мы всё сделали». Поэтому для DKIM
# даётся только путь, где взять настоящую запись.
#
# SPF собирается из фактов, которые мы уже достали этим прогоном (A-запись), —
# новых запросов подсказка не стоит. ~all, а не -all: жёсткий запрет ломает
# доставку через сторонние ретрансляторы (CRM, рассылки), а softfail письмо не
# отклоняет — это безопасная точка старта, а не финальная настройка.
def spf_suggestion(ip=''):
    """Стартовая SPF-запись из фактических данных домена.

    Механизмы выбираются по тому, что реально известно: ip4 — только если мы
    видим ПУБЛИЧНЫЙ IPv4 домена, иначе a (справит приёмник, IP может
    смениться). mx добавляется всегда: для домена, который только принимает
    почту, шлюзом часто значится именно MX-хост. ~all вместо -all — не
    перестраховка: -all отклоняет письма от CRM/рассылок, которые оператор
    ещё не внёс в запись.
    """
    return f'v=spf1 {spf_basis(ip)[0]} mx ~all'


def spf_basis(ip=''):
    """(механизм, откуда он взялся) — подпись обязана соответствовать записи.

    Три разных случая, и путать их нельзя: ложная подпись «из A-записи» под
    записью с механизмом a оператор проглотит не глядя, а скопированная в зону
    SPF ломает доставку всего домена.

    Приватный адрес (10.x, 192.168.x, 172.16-31.x, 127.x) — отдельный случай,
    а не частность: его даёт локальная зона или домен за NAT. Публичный SPF с
    ip4:10.0.0.5 приёмником не совпадёт никогда (он смотрит на адрес TCP-сессии),
    поэтому предлагать его значило бы выдать заведомо мёртвую запись.
    """
    if not ip:
        return 'a', ('A-запись домена не получена, поэтому механизм a, а не '
                     'ip4: проверьте, что A-запись вообще указывает на этот сервер')
    if _is_private_ip(ip) or ip.startswith('127.'):
        return 'a', (f'A-запись домена — {ip}, это приватный адрес: в публичной '
                     f'SPF он не совпадёт ни с какой сессией. Механизм a; '
                     f'публичный IP отправки сверьте у хостера')
    return f'ip4:{ip}', f'ip4 взят из A-записи домена ({ip})'


def dmarc_suggestion(domain):
    """Первый шаг DMARC: p=none + rua на сам домен (RFC 7489).

    p=none ничего не отклоняет и только собирает сводки — поднять режим сразу
    до reject без этих сводок значит дать приёмнику право убивать письма, о
    которых мы ничего не знаем. rua на тот же домен принципиально: rua на
    ЧУЖОЙ домен приёмник обязан верифицировать отдельным DNS-тестом, и
    «настроенная» сводка на самом деле не приходила бы никогда.
    """
    return f'v=DMARC1; p=none; rua=mailto:dmarc@{domain}'


# Пути MTA названы как «обычно так»: панель может хранить ключи в своей БД, а
# не в файле. Поэтому подсказка указывает, ГДЕ смотреть, и запрещает брать не
# то: в .key лежит приватный ключ, публикация его в DNS = полная компрометация
# подписи.
DKIM_WHERE_HINT = (
    "готовую запись не даём: публичный ключ выводится из приватного, а он на "
    "сервере. Включите подпись в панели (FASTPANEL: Почта → «DKIM» у домена; "
    "ISPmanager: DKIM у почтового домена) либо возьмите TXT из ключей MTA — "
    "обычно /etc/rspamd/dkim или /etc/opendkim/keys/<домен>/; брать .txt, "
    "никогда не .key (там приватный ключ)")


def mail_auth_fixes(domain, spf, dkim, dmarc, ptr_status, ip=''):
    """Строки «что сделать» — только по reason, без новых DNS-запросов.

    Возвращает [] когда чинить нечего: пустой блок честнее списка советов про
    уже настроенный домен. Ответственность за ложь здесь прямая: неверная
    SPF-строка, скопированная оператором в зону, ломает доставку всего домена.
    """
    fixes = []
    # Основание SPF-подсказки считаем один раз: текст совета обязан описывать
    # ровно тот механизм, который попал в строку (см. spf_basis).
    spf_basis_note = spf_basis(ip)[1]

    if spf['reason'] == 'missing':
        # Строку берём из spf_suggestion, а не пересобираем здесь: два формата
        # одной записи однажды разъехались бы, а оператор копирует в зону
        # именно её — разошёлся бы формат, и в зоне оказалась бы другая запись,
        # чем та, что мы объяснили.
        fixes.append(f'SPF: добавить TXT „{spf_suggestion(ip)}“ — '
                     f'{spf_basis_note}; если письмо уходит через сторонние '
                     f'сервисы (CRM, рассылки), добавьте их include: до '
                     f'перехода на -all')
    elif spf['reason'] == 'broken_version':
        fixes.append('SPF: заменить запись — должно быть „v=spf1“ с единицей, '
                     'с „v=spf“ приёмник запись не видит')
    elif spf['reason'] == 'duplicate':
        fixes.append('SPF: оставить ровно одну TXT с v=spf1 — две записи по '
                     'RFC 7208 это PermError, письма отклоняются')
    elif spf['reason'] == 'too_many_lookups':
        fixes.append(f'SPF: меньше {MAX_SPF_LOOKUPS} DNS-запросов — '
                     f'сейчас {spf["lookups"]}; include: заменяйте на ip4:/a: '
                     f'— они запросов не стоят')
    elif spf['reason'] == 'plus_all':
        fixes.append('SPF: „+all“ заменить на „~all“ — +all разрешает '
                     'отправлять с ЛЮБОГО IP, фильтры запись игнорируют')
    elif spf['reason'] == 'no_mechanism':
        fixes.append('SPF: дописать в конец „~all“ — без механизма all чужие '
                     'серверы формально не запрещены')

    if dkim['reason'] == 'missing':
        fixes.append('DKIM: ' + DKIM_WHERE_HINT)
    elif dkim['reason'] == 'revoked':
        fixes.append('DKIM: p= пустой — ключ отозван; выпускать новый и '
                     'публиковать новую TXT, старую запись не «реанимировать»')
    elif dkim['reason'] == 'short_key':
        fixes.append('DKIM: сгенерировать ключ 2048 бит и перевыпустить запись '
                     '(подписи с коротким ключом часть приёмников не принимает)')

    if dmarc['reason'] == 'missing':
        fixes.append(f'DMARC: добавить TXT на _dmarc.{domain} '
                     f'„{dmarc_suggestion(domain)}“ — p=none только собирает '
                     f'сводки, ничего не отклоняя; режим поднимут после них')
    elif dmarc['reason'] == 'no_policy_tag':
        fixes.append('DMARC: добавить обязательный тег p (none/quarantine/'
                     'reject) — без него приёмник запись не применяет')
    elif dmarc['reason'] == 'bad_policy':
        fixes.append('DMARC: p= принимает none, quarantine или reject — '
                     'остальное трактуется как none')
    elif dmarc['reason'] == 'monitoring':
        fixes.append('DMARC: p=none безопасен; когда rua-сводки покажут, что '
                     'чужой рассылки нет, поднимите до p=quarantine')
    elif dmarc['reason'] == 'no_rua':
        fixes.append(f'DMARC: добавить rua=mailto:dmarc@{domain} — иначе '
                     f'сводок о чужой рассылке с домена не будет')

    if ptr_status == 'bad':
        fixes.append(f'PTR: запросить обратную запись для {ip} у владельца '
                     f'адреса (хостер/дата-центр) — из панели она не настраивается')
    return fixes


def _ptr_view(ip, name, answered=True):
    """(статус, текст) PTR по уже известному адресу.

    Различаем три случая, а не два: «нечего спрашивать» (адреса нет), «спросили,
    но ответа не получили» (answered=False) и «получили честный пустой ответ»
    (записи действительно нет). Свести второй к третьему — значит заявить
    оператору «обратной записи нет» на основании таймаута: ровно то же враньё,
    с которым воюет весь модуль, только в обратную сторону.
    """
    if not ip:
        return 'warn', 'PTR не проверен: A-запись не получена'
    if not answered:
        return 'warn', (f'PTR для {ip} не получен: резолвер не ответил — '
                        f'назвать это «записи нет» нельзя')
    if name:
        return 'ok', name
    return 'bad', (f'для {ip} обратной записи нет — Google/Microsoft такую '
                   f'почту режут')


def summarize_mail_auth(domain, spf_out, dmarc_out, dkim_out, ptr_out,
                        ip='', note='', header=True, ext=None, resolver='',
                        verify_wanted=False):
    """(вердикт, строки) по СЫРЫМ выводам dig — чистая, все ветки в тестах.

    ip='' означает «A-записи нет»: PTR в этом случае НЕ проверен, и это warn, а
    не ❌ — мы не знаем про него ничего, врать оператору нельзя.

    ext — ответы «из интернета» (external_auth_answers). Если сверка состоялась
    ('answered'), вердикт, иконки шапки и подсказки считаются по ПУБЛИЧНОЙ
    картине: письмо судит приёмник, который видит DNS интернета, а не файл
    локальной зоны. Локальные строки при этом остаются напечатаны — по ним и
    ищут, где именно зона разошлась; расхождение помечается «🌐».

    verify_wanted — «сверка этому домену была нужна, но резолвера не нашлось»
    (probe мёртв). Без флага функция не отличила бы «сверять нечего» от
    «сверять нечем»: в обоих случаях ext — None, а следствия разные: во втором
    случае локальные ✅ ничем не подтверждены.
    """
    local = {'spf': parse_spf(parse_dns_txt(spf_out)),
             'dkim': parse_dkim(dkim_out, domain),
             'dmarc': parse_dmarc(parse_dns_txt(dmarc_out))}
    ptr_status, ptr_text = _ptr_view(ip, parse_ptr(ptr_out))

    verified = bool(ext and ext.get('answered'))
    if verified:
        # Разбор внешний — теми же парсерами: второй половины правил у
        # программы не появляется.
        shown = external_parseds(domain, ext)
        # PTR обязан иметь собственный признак ответа: общий 'answered' его не
        # покрывает (PTR зависит от внешней A и запрос позднее), иначе таймаут
        # по -x прочитался бы как «обратной записи нет».
        v_ptr_status, v_ptr_text = _ptr_view(
            ext.get('ip', ''), parse_ptr(ext['ptr'][0]),
            bool(ext.get('ptr_answered', True)))
    else:
        shown = local
        v_ptr_status, v_ptr_text = ptr_status, ptr_text

    verdict = max((shown['spf']['status'], shown['dkim']['status'],
                   shown['dmarc']['status'], v_ptr_status),
                  key=AUTH_SEVERITY.__getitem__)
    # Непроверенное не имеет права выглядеть как «в порядке». Если сверку
    # хотели, но сделать не смогли (резолвер жив, а по домену не ответил — или
    # мёртвы оба публичных), домен был бы напечатан здоровым: «Провалено: 0, с
    # замечаниями: 0» от программы, которая тут же пишет «сверить не удалось».
    # Поднимаем ok → warn: bad остаётся bad, warn остаётся warn — понижать
    # строгость мы не имеем права.
    unverified = (ext is not None or verify_wanted) and not verified
    if unverified and verdict == 'ok':
        verdict = 'warn'
    pad = '    ' if header else '  '
    lines = []
    if header:
        lines.append(f'{domain:42s} SPF {AUTH_ICON[shown["spf"]["status"]]}  '
                     f'DKIM {AUTH_ICON[shown["dkim"]["status"]]}  '
                     f'DMARC {AUTH_ICON[shown["dmarc"]["status"]]}  '
                     f'PTR {AUTH_ICON[v_ptr_status]}'
                     # Без метки шапка «противоречила» бы строке ниже: SPF ❌
                     # в шапке и «v=spf1 … -all» в теле оператор прочитал бы
                     # как ошибку программы, а не как разрыв зоны.
                     # «[не сверено]» — вторая половина той же честности: иконки
                     # показаны по ЛОКАЛЬНЫМ данным, и без метки их прочитали бы
                     # как подтверждённые публичной зоной.
                     + ('   [извне]' if verified
                        else '   [не сверено]' if unverified else ''))
    lines.append(f'{pad}SPF   {local["spf"]["detail"]}')
    dkim_note = ''
    if local['dkim']['status'] == 'bad' and not local['dkim']['revoked']:
        dkim_note = (' — если подписывает другой селектор, проверьте '
                     f'<selector>._domainkey (искали: '
                     f'{", ".join(MAIL_AUTH_SELECTORS[:5])}…)')
    lines.append(f'{pad}DKIM  {local["dkim"]["detail"]}{dkim_note}')
    lines.append(f'{pad}DMARC {local["dmarc"]["detail"]}')
    lines.append(f'{pad}PTR   {ptr_text}')

    if verified:
        # Печатаем только расхождения: три одинаковые строки на каждый домен
        # оператор пролистнёт, а нужное потеряется.
        diffs = [f"{pad}🌐 {label:5s} извне {AUTH_ICON[shown[key]['status']]} "
                 f"{shown[key]['detail']}"
                 for label, key in EXTERNAL_KINDS
                 if auth_differs(local[key], shown[key])]
        if v_ptr_status != ptr_status:
            diffs.append(f"{pad}🌐 PTR   извне {AUTH_ICON[v_ptr_status]} "
                         f"{v_ptr_text}")
        lines.extend(diffs or [
            f'{pad}🌐 сверка через {resolver}: публичные записи совпадают '
            f'с локальными'])
    elif ext is not None:
        # Probe был жив, а ответить по домену мы не смогли. Смолчать — значит
        # оставить пометку «см. строки «🌐»» без единой строки «🌐»: оператор
        # прочитает это как «сверили, расхождений нет». Вердикт при этом
        # считается по локальным данным и помечен честно — «не сверен».
        lines.append(f'{pad}🌐 сверить не удалось: {resolver} не ответил по '
                     f'этому домену — строки выше показаны по ЛОКАЛЬНЫМ '
                     f'данным, проверьте вручную: '
                     f'dig +short TXT {domain} @1.1.1.1')

    # Состояние сверки — наружу, ТЕМ ЖЕ кодом, что напечатал строки «🌐».
    # Сводка обязана считать именно его, а не искать «🌐» в готовом тексте:
    # этот символ означает ТРИ разные вещи — «зона разошлась», «публичные
    # записи совпали», «сверить не удалось». Подсчёт по подстроке смешал бы
    # беду с «не проверено» (а у пометки «см. строки «🌐»» символ вовсе
    # служебный), и оператор получил бы число, которого не существует.
    if verified:
        diff_state = 'diverged' if diffs else 'same'
    elif ext is not None or verify_wanted:
        # Сверить хотели и не смогли: резолвер жив, но по домену не ответил,
        # либо публичных резолверов не нашлось вовсе.
        diff_state = 'unverified'
    else:
        # Сверять было нечего: зона не локальная и резолвер внешний — локальные
        # ответы и есть ответы интернета. Про сверку тогда не пишем ничего.
        diff_state = ''

    # Подсказки — только там, где чинить есть что: у настроенного домена список
    # пуст, и дописывать «всё хорошо» некуда (вердикт ok это уже сказал).
    # Строим их по ПУБЛИЧНОЙ картине: чинить надо то, что видит приёмник.
    for fix in mail_auth_fixes(domain, shown['spf'], shown['dkim'],
                               shown['dmarc'], v_ptr_status,
                               ip=(ext.get('ip', '') if verified else ip)):
        lines.append(f'{pad}→ {fix}')
    if note:
        lines.append(f'{pad}⚠️ {note}')
    # Третье поле — состояние сверки ('diverged' / 'same' / 'unverified' / '').
    # Оно нужно вызывающему, чтобы посчитать масштаб беды ДО чтения списка
    # доменов, и взято из тех же переменных, что напечатали строки «🌐».
    return verdict, lines, diff_state


def mail_auth_lines(checker, domain, note='', header=True, resolver='',
                    verify_wanted=False):
    """(вердикт, строки, ip) по ОДНОМУ домену: 5 dig-запросов, не больше.

    Вынесено из mail_auth_report, чтобы «Досье домена» показывало ровно те же
    проверки тем же кодом: две реализации однажды разъехались бы формулировками,
    и оператор видел бы в одном месте «DKIM нет», а в другом — «DKIM ❓».
    PTR спрашивается только когда есть IPv4: спрашивать -x у CNAME бессмысленно.

    resolver — непустой означает «повторить те же запросы наружу» (только там,
    где локальная зона могла наврать; решает вызывающий через
    zone_is_local_view). Цена — ещё 5 запросов, поэтому «просто всегда» это не
    включается ни при каких обстоятельствах.

    verify_wanted — «сверка была нужна, но резолвера не нашлось»: без него
    домен с локально-зелёной зоной выглядел бы проверенным.

    Четвёртый элемент — состояние сверки ('diverged' / 'same' /
    'unverified' / ''), чтобы сводка считала масштаб беды из факта, а не из
    текста. Порядок первых трёх (вердикт, строки, ip) не менялся: ip был
    добавлен тем же способом.
    """
    ip = first_ipv4(checker.exec_command(a_query_command(domain))[0])
    verdict, lines, diff_state = summarize_mail_auth(
        domain,
        checker.exec_command(spf_query_command(domain))[0],
        checker.exec_command(dmarc_query_command(domain))[0],
        checker.exec_command(dkim_query_command(domain))[0],
        checker.exec_command(ptr_query_command(ip))[0] if ip else '',
        ip=ip, note=note, header=header,
        ext=external_auth_answers(checker, domain, resolver) if resolver else None,
        resolver=resolver, verify_wanted=verify_wanted)
    return verdict, lines, ip, diff_state


MAIL_AUTH_FIX_HINT = (
    "\nКак чинить: SPF, DKIM и DMARC — DNS-записи домена, их правят там, где у "
    "домена зона (панель → DNS либо регистратор/облако). Готовую строку даёт "
    "строка «→» под соответствующей проверкой домена — её и копируют, а не "
    "сочиняют свою. DKIM — исключение: там запись берут из ключа MTA или "
    "включают подпись в панели (см. «→ DKIM»). PTR настраивает владелец "
    "IP-адреса (хостер), а не панель.")


def mail_auth_verify_lines(diverged=0, same=0, unverified=0):
    """Сколько доменов расходится с публичной зоной — строки в шапку отчёта.

    Считается по СОСТОЯНИЮ сверки каждого домена, а не по символу «🌐» в
    готовом тексте. Этот символ печатается в трёх несходных случаях — «зона
    разошлась», «публичные записи совпали с локальными», «сверить не удалось»,
    — и подсчёт по подстроке дал бы число, которого нет: оператор прочитал бы
    «расходится: 7» там, где семь доменов просто не удалось проверить. Смешать
    беду с «не проверено» — тот же грех, что и «не проверено» → «в порядке».

    Здесь же причина, по которой молчание — правильный ответ: если сверки не
    было ни у одного домена (зоны внешние, смотреть нечего), печатать «расхождений
    нет» нельзя. Не проверяли — это не «в порядке».
    """
    if not (diverged or same or unverified):
        return []
    lines = []
    if diverged:
        # Число без «из скольких сверено» было бы манипуляцией: «4» при одном
        # сверенном домене и «4» при двадцати — разный масштаб работ.
        lines.append(f"🌐 Расходится с публичной зоной: {diverged} "
                     f"(сверено доменов: {diverged + same}) — вердикты и "
                     f"строки «→» ниже показаны по ПУБЛИЧНОЙ зоне: письмо "
                     f"судит приёмник,")
        lines.append("   который видит DNS интернета, а не файл локальной "
                     "зоны. Править надо там, где зона живёт для всех.")
    # Ветки «совпало» здесь нет намеренно, и поймал это запертый тест
    # «ровно одно сообщение»: в теле каждого домена уже напечатано
    # «🌐 сверка через {resolver}: публичные записи совпадают», то есть
    # назван даже резолвер. Вторая строка сверху ничего не добавляла бы, а
    # оператор прочитал бы одно и то же дважды и перестал бы доверять выводу.
    # Чинить при совпадении нечего — группировать нечего.
    if unverified:
        # Отдельная строка, а не плюс к предыдущей: «не сверено» не обязано
        # выглядеть как «в порядке» и не обязано прятаться за «расхождений нет».
        lines.append(f"🌐 Сверить с публичной зоной не удалось: {unverified} — "
                     f"их вердикты получены по ЛОКАЛЬНЫМ данным и помечены "
                     f"«[не сверено]». Это «не видно»,")
        lines.append("   а не «расхождений нет»: проверить вручную — "
                     "dig +short TXT <домен> @1.1.1.1")
    return lines


def mail_auth_report(checker, panel_type=None, limit=HEALTH_CHECK_LIMIT):
    """SPF/DKIM/DMARC/PTR по почтовым доменам сервера: худшие — сверху.

    Цена — 5 DNS-запросов на домен (A, TXT, _dmarc, цикл по селекторам DKIM,
    PTR) и тот же limit, что у проверки доступности сайтов. Группировки по
    блокам здесь нет намеренно: вердикт домена определяется худшей проверкой,
    поэтому «плохие сверху, хорошие снизу» отвечает на вопрос «что чинить
    первым» лучше, чем три списка по статусам.

    Внешняя сверка (ещё 5 запросов) идёт только у доменов, где локальный dig
    мог наврать, и только если публичный резолвер отвечает; жив ли он —
    спрашивается ОДИН раз на прогон, а не на домен.
    """
    if panel_type is None:
        panel_type = detect_panel(checker)
    lines = ["=== ПОЧТА: SPF / DKIM / DMARC / PTR ==="]
    domains = sorted(discover_mail_domains(checker, panel_type))
    if not domains:
        lines.append("Почтовые домены не найдены — проверять нечего.")
        return "\n".join(lines)

    zones = {z['domain'] for z in discover_dns_zones(checker, panel_type)}
    resolver_note = resolver_view_note(checker)
    # Условие и текст пометки берём из одной функции (zone_is_local_view),
    # иначе «где сверять» и «где написано, что надо сверять» разъехались бы.
    need = {dom: zone_is_local_view(dom, zones, resolver_note)
            for dom in domains[:limit]}
    # Пробуем резолвер только когда сверка нужна хоть кому-то: платить запрос
    # за probe на сервере с внешним DNS и публичным резолвером не за что.
    resolver = public_resolver(checker) if any(need.values()) else ''
    checked = []
    for dom in domains[:limit]:
        verdict, detail, _ip, diff_state = mail_auth_lines(
            checker, dom, resolver=resolver if need[dom] else '',
            # Нужна, но не сделана (резолверов не нашлось) — вердикт по
            # локальным данным, и он не имеет права печататься как проверенный.
            verify_wanted=bool(need[dom]) and not resolver,
            note=zone_view_note(dom, zones, resolver_note,
                                verified=bool(resolver) and bool(need[dom])))
        checked.append((AUTH_SEVERITY[verdict], dom, detail, diff_state))

    # Худшие сверху; порядок внутри одной беды — алфавитный, иначе список
    # менялся бы от прогона к прогону и оператор не узнал бы свой домен.
    checked.sort(key=lambda item: (-item[0], item[1]))
    bad = sum(1 for item in checked if item[0] == AUTH_SEVERITY['bad'])
    warn = sum(1 for item in checked if item[0] == AUTH_SEVERITY['warn'])
    lines.append(f"Проверено доменов: {len(checked)} из {len(domains)}. "
                 f"Провалено: {bad}, с замечаниями: {warn}.")
    # Масштаб беды — до чтения списка. При 25 доменах оператор обязан узнать
    # «у 4 зона расходится с интернетом» в первой строке, а не досчитывая 🌐
    # глазами: счётчик ведёт к решению «править зону централизованно» либо
    # «разбираться по доменам».
    lines.extend(mail_auth_verify_lines(
        diverged=sum(1 for item in checked if item[3] == 'diverged'),
        same=sum(1 for item in checked if item[3] == 'same'),
        unverified=sum(1 for item in checked if item[3] == 'unverified')))
    lines.append("Худшие сверху: в спам письмо кладёт одна проваленная "
                 "проверка, а не средняя.")
    for _sev, _dom, detail, _state in checked:
        lines.append('')
        lines.extend(detail)

    if len(domains) > limit:
        lines.append(f"\n… проверены первые {limit} из {len(domains)} доменов "
                     f"(HEALTH_CHECK_LIMIT)")
    lines.append(MAIL_AUTH_FIX_HINT)
    lines.append("ℹ️ Домен, который только принимает почту, можно не "
                 "подписывать — но уходящее с него письмо без SPF/DKIM почти "
                 "всегда попадёт в спам.")
    # Подтверждение диагноза фактами доставки. Вызывается ПОСЛЕ цикла, а не
    # внутри: лог читается ОДИН раз на прогон (иначе 25 доменов = 25 чтений
    # лога, и GUI висел бы минутами). Дайджест может как подтвердить связку
    # («письма реально отбивают за спам»), так и честно отказаться её
    # подтверждать — второе не читается как «чинить нечего» (текст ниже это
    # опровергает).
    lines.append('')
    # our_domains = инвентарь почтовых доменов этого сервера (он уже собран в
    # начале отчёта). Пометка «ваши домены» ставится только по нему: назвать
    # домен нашим по виду адреса — врать оператору, который понесёт это клиенту.
    lines.extend(mail_delivery_digest_lines(checker, our_domains=domains))
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
        # Аутентификация спрашивается ТОЛЬКО у почтового домена: у чисто веб-
        # домена SPF может не быть намеренно, и ❌ напротив него был бы ложным
        # диагнозом. Две дополнительные команды (resolv.conf и список зон) идут
        # ради честной пометки «dig показывает локальную зону, а не интернет».
        zones = {z['domain'] for z in discover_dns_zones(checker, panel_type)}
        resolver_note = resolver_view_note(checker)
        # Условие внешней сверки берём из той же функции, что и текст пометки:
        # иначе «где сверять» и «где написано, что сверять надо» однажды
        # разъехались бы, и домен остался бы с локальной правкой без проверки.
        need = zone_is_local_view(dom, zones, resolver_note)
        resolver = public_resolver(checker) if need else ''
        _verdict, auth_lines, _ip, _state = mail_auth_lines(
            checker, dom, header=False, resolver=resolver,
            verify_wanted=bool(need) and not resolver,
            note=zone_view_note(dom, zones, resolver_note,
                                verified=bool(resolver)))
        lines.append("\nDNS-аутентификация отправки (SPF/DKIM/DMARC/PTR):")
        lines.extend(auth_lines)
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


# ==================== ПАРОЛЬ МИМО argv (ISPmanager) ====================
# Панель берёт секрет из окружения: `-e '<param>=$ENV_NAME>` (ISPsystem,
# «Mgrctl utility» — доступно с COREmanager 5.325+). Это единственный способ
# убрать пароль из argv: exec_command у нас = `bash -c '<вся строка>'`, поэтому
# `export SECRET=пароль` внутри команды светился бы в ps ровно так же, как
# passwd=пароль. Проверено локально: после `. файла` env дочернего процесса
# содержит переменную (1), `ps -eo args | grep -v grep | grep -c '<пароль>'` = 0.
MAILBOX_SECRET_ENV = 'DIAG_MAILBOX_SECRET'
MAILBOX_SECRET_FILE = 'secret.env'
MAILBOX_SECRET_TMP = '/tmp/diagn_mail.XXXXXXXX'


def mailbox_secret_content(password):
    """Содержимое env-файла: export ИМЯ='значение'.

    export ОБЯЗАТЕЛЕН: без него `.` объявляет переменную только в текущем
    shell, и mgrctl как дочерний процесс её не увидел бы (проверено: env | grep
    даёт 0 совпадений). Значение экранировано q() (shlex.quote) — bash снимает
    одинарные кавычки при source, поэтому пароль с пробелом, $, ` или кавычкой
    доходит до панели байт в байт.
    """
    return f'export {MAILBOX_SECRET_ENV}={q(password)}\n'


def secret_dir_command():
    """mktemp, а не фиксированный путь: /diag_mail.XXXX создаётся атомарно.

    Фиксированный /tmp/xxx на расшаренном сервере — это symlink/race-проблема
    (кто-то мог создать файл заранее). Каталог от mktemp — 0700 и уникальный.
    """
    return f'mktemp -d {MAILBOX_SECRET_TMP} 2>/dev/null'


def isp_mail_parent(checker, domain):
    """Каноническое имя почтового домена из панели: (имя, None) | (None, причина).

    ISPsystem, «Service parameters»: plid — parent list unique identifier, то
    есть name элемента функции maildomain (в KB-скрипте массового создания там
    стоит plid="$domain"). Значит родителя берём ИЗ СПИСКА ПАНЕЛИ, а не из
    строки, которую ввёл оператор: панель хранит домен своим написанием
    (регистр, punycode), и только оно принимается email.edit. Молча подставить
    «похожее» нельзя — панель заведёт ящик не там либо ответит невнятно.

    Список читается через isp_rows, а не isp_maildomains: только isp_rows
    отличает «почтовых доменов нет» от «панель ответила ошибкой». По ошибке
    резолв запрещён — plid уехал бы наугад.
    """
    rows, ok, raw = isp_rows(checker, 'maildomain')
    if not ok:
        raw = (raw or '').strip()
        detail = raw.splitlines()[0] if raw else ''
        return None, ('Панель не вернула список почтовых доменов (maildomain)'
                      + (f': {detail}' if detail else '')
                      + ' — подтвердить родителя нельзя, операция отменена.')
    wanted = (domain or '').strip().lower()
    for row in rows:
        name = (row.get('name') or '').strip()
        if name.lower() == wanted:
            return name, None
    names = sorted({(r.get('name') or '').strip()
                    for r in rows if r.get('name')})
    shown = ', '.join(names[:8]) or '—'
    return None, (f'Домен {domain} не найден среди почтовых доменов панели '
                  f'(maildomain: {shown}). Родителем ящика может быть только '
                  'элемент этого списка — сначала добавьте домен в панель.')


def isp_mailbox_create_args(local, domain):
    """email.edit БЕЗ elid = создание ящика (так же делает скрипт из KB).

    Пароля здесь нет намеренно: он придёт через -e (см. isp_mailbox_env_command).
    sok=ok — параметр функции, поэтому стоит до -e, как в синтаксисе у ISPsystem
    (funcname [param=value ...] [-e '<param>=$ENV']).

    domain сюда передаётся уже каноническим (см. isp_mail_parent): domainname и
    plid обязаны быть одним и тем же именем элемента maildomain.
    """
    return ['email.edit', f'domainname={q(domain)}', f'name={q(local)}',
            f'plid={q(domain)}', f'aliases={q("")}', 'sok=ok']


def isp_mailbox_passwd_args(address):
    """email.edit с elid — смена пароля существующего ящика."""
    return ['email.edit', f'elid={q(address)}', 'sok=ok']


def isp_mailbox_env_command(args, env_name=MAILBOX_SECRET_ENV):
    """mgrctl <func> <params> -e 'passwd=$ENV' -e 'confirm=$ENV'.

    В строке нет секрета — только имя переменной, поэтому её можно показать
    оператору (операцию можно повторить руками, экспортировав переменную) и
    она не нуждается в маскировании. Кавычки из q() — не для shell: mgrctl сам
    раскрывает $ИМЯ из своего окружения, пример в документации ISPsystem
    показывает именно -e 'passwd=$SECRET_PASSWORD'.
    """
    return (f'{MGRCTL} ' + ' '.join(args) +
            f' -e {q("passwd=$" + env_name)}'
            f' -e {q("confirm=$" + env_name)} 2>&1')


def isp_secret_run_command(secret_dir, args, env_name=MAILBOX_SECRET_ENV):
    """. env-файл -> mgrctl -e -> удаление файла, даже если панель ошиблась.

    rc=$? снимается ДО rm: иначе кодом возврата строки стал бы rm, и провал
    панели выглядел бы успехом (классическая грабля «очистка съела rc»).
    """
    return ('. ' + q(f'{secret_dir}/{MAILBOX_SECRET_FILE}') + ' && ' +
            isp_mailbox_env_command(args, env_name) +
            '; rc=$?; rm -rf ' + q(secret_dir) + ' 2>/dev/null; exit $rc')


def prepare_mailbox_secret(checker, password):
    """Готовит каталог с env-файлом секрета: (путь, None) либо (None, причина).

    Порядок: mktemp -d (0700, имя уникальное и создаётся атомарно) ->
    prepare_secret_file (файл 0600 появляется ДО пароля) -> SFTP-запись.

    SFTP, а не `cat > file <<'EOF'`: наш транспорт — exec_command, то есть
    `bash -c '<вся строка>'`, и пароль в heredoc был бы виден в ps ровно так
    же, как в passwd=... Файл пишет ДРУГОЙ канал, а в argv сервера остаётся
    только путь.
    """
    out, err, rc = checker.run(secret_dir_command())
    text = (out or '').strip()
    secret_dir = text.splitlines()[-1].strip() if text else ''
    if rc != 0 or not secret_dir.startswith('/'):
        # Фолбэк «тогда пароль аргументом» здесь запрещён сознательно: он и
        # есть тот долг, который закрывается этой веткой.
        detail = (err or '').strip() or text
        return None, ('mktemp не создал каталог для env-файла'
                      + (f': {detail}' if detail else '')
                      + '. Передать пароль безопасно нельзя, операция отменена.')
    path = f'{secret_dir}/{MAILBOX_SECRET_FILE}'
    # prepare_secret_file: файл получает 0600 ДО появления пароля (umask 077 +
    # chmod в одной команде, служебным каналом). Прежний порядок
    # «write_remote_file, потом chmod» оставлял окно world-readable файла, а
    # отмена между этими шагами запирала его там навсегда.
    ok, why = prepare_secret_file(checker, path, mailbox_secret_content(password))
    if not ok:
        # Пароль в файл не лёг, но каталог убрать всё равно надо; если не
        # вышло — говорим путь: молчать про оставленный мусор нельзя.
        gone, _ = remove_remote_path(checker, secret_dir)
        extra = '' if gone else f' (каталог {secret_dir} остался — удалите вручную)'
        return None, f'Не удалось подготовить env-файл с паролем: {why}{extra}'
    return secret_dir, None


def wipe_mailbox_secret(checker, secret_dir):
    """Убирает каталог с env-файлом: None либо текст беды для оператора.

    Идёт служебным каналом (remove_remote_path -> cleanup), поэтому справляется
    и ПОСЛЕ cancel(): «оператор нажал Стоп» не означает «оставь пароль на
    диске» — раньше rm шёл через обычный run, падал от cancel_event и файл с
    паролем переживал операцию (воспроизведено на заглушке транспорта).

    Молчать при неудаче нельзя: без строки в отчёте оператор не узнает, что
    секрет лежит на сервере, и не удалит его руками.
    """
    ok, why = remove_remote_path(checker, secret_dir)
    if ok:
        return None
    return ('Не удалось удалить временный каталог с паролем: ' + str(why) +
            f'. Удалите вручную: rm -rf {q(secret_dir)}')


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
                key, sep, value = token.partition('=')
                # Ссылка на окружение (-e 'passwd=$DIAG_MAILBOX_SECRET') — НЕ
                # секрет: в ней только имя переменной. Маскировать её — значит
                # лишить оператора возможности повторить команду руками.
                if sep and key.lower() in _SECRET_KEYS and not value.startswith('$'):
                    parts[i] = f'{key}=***'
                    redacted = True
            if redacted:
                return ' '.join(parts)
    return _SECRET_RE.sub(_redact_match, text)


def _redact_match(m):
    """Регэксп-фолбэк: значение-ссылка на переменную не маскируется."""
    if m.group(2).lstrip('\'"').startswith('$'):
        return m.group(0)
    return f'{m.group(1)}=***'


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

    # Собираем команду. Для ISPmanager пароль идёт ОТДЕЛЬНЫМ каналом (env-файл),
    # поэтому секрет готовим ЗДЕСЬ, а не в начале операции: до guard писать файл
    # с паролем на сервер, где операция всё равно отменена, — лишний секрет.
    secret_dir = None
    shown = None                       # что показать оператору (без обвязки)
    if panel_type == 'ispmanager':
        if mode == 'create':
            # plid — parent list unique identifier (name элемент maildomain),
            # поэтому родителя берём у панели, а не из ввода оператора. Резолв
            # идёт ПОСЛЕ guard (лишний секрет на диске не нужен) и ДО подготовки
            # секрета: без подтверждённого родителя команда не уходит, и писать
            # env-файл туда незачем.
            parent, why = isp_mail_parent(checker, domain)
            if parent is None:
                lines.append(f"⛔ {why}")
                return "\n".join(lines)
            if parent != domain:
                # Разница написания обязана быть видна: иначе оператор решит,
                # что панель завела ящик «на другой домен».
                lines.append(f"ℹ️ Родитель-домен взят из панели: {parent} "
                             f"(в запросе было {domain}) — панель хранит домен "
                             "своим написанием, plid обязан совпадать с ним.")
                domain = parent
            args = isp_mailbox_create_args(local, domain)
        elif mode == 'passwd':
            args = isp_mailbox_passwd_args(addr)
        else:
            args = None                # удаление — секрета нет
        if args is None:
            cmd = isp_mailbox_delete_command(addr)
        else:
            secret_dir, why = prepare_mailbox_secret(checker, password)
            if secret_dir is None:
                lines.append(f"⛔ {why}")
                return "\n".join(lines)
            cmd = isp_secret_run_command(secret_dir, args)
            # В отчёте — команду панели, а не обвязку (source/rm): её содержимое
            # совпадает с примером из документации ISPsystem, значит её можно
            # повторить руками, экспортировав переменную.
            shown = isp_mailbox_env_command(args)
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

    lines.append("$ " + redact_secrets(shown or cmd))
    secret_note = None
    try:
        try:
            out, errtxt, rc = checker.run(cmd)
        finally:
            # Уборка — в finally и служебным каналом (cleanup). Прежний
            # checker.run падал от cancel_event ещё до rm, и файл с паролем
            # переживал отмену (воспроизведено на заглушке транспорта):
            # «оператор нажал Стоп» не значит «оставь пароль на диске».
            if secret_dir:
                secret_note = wipe_mailbox_secret(checker, secret_dir)
    except Exception as exc:
        # Отмена/обрыв канала: отчёт оператору не покажут (gui показывает
        # только текст исключения), поэтому беда с уборкой вешается на него.
        if secret_note:
            raise Exception(f"{exc}\n⚠️ {secret_note}") from exc
        raise
    if secret_note:
        lines.append(f"⚠️ {secret_note}")
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
        # Предупреждение обязано соответствовать фактическому каналу передачи:
        # наврать «был виден в ps» там, где мы его убрали, — обесценить сам
        # фикс (оператор перестанет верить отчёту целиком).
        if panel_type == 'ispmanager':
            lines.append("ℹ️ Пароль передан через временный файл 0600 и окружение")
            lines.append("   процесса — в ps на сервере он не светился.")
            if secret_note is None:
                lines.append("   Файл удалён сразу после команды панели.")
        else:
            # FASTPANEL: mogwai не умеет принимать пароль из окружения или со
            # stdin — только --password=аргумент. Это ограничение CLI панели,
            # честно говорим о нём, а не делаем вид, что его нет.
            lines.append("⚠️ CLI FASTPANEL принимает пароль только аргументом —")
            lines.append("   он был виден в ps на сервере. При возможности")
            lines.append("   смените пароль на постоянный через панель.")
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
