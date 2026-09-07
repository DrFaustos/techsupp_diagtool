import time
import re
import os
from collections import Counter
from datetime import datetime
from ssh_client import ServerChecker

# ==================== КОНФИГУРАЦИИ ====================
BACKUP_DIR = "/root/tech_backup"
BACKUP_SUBDIRS = {
    'configs': f"{BACKUP_DIR}/configs",
    'dns': f"{BACKUP_DIR}/dns",
    'crontab': f"{BACKUP_DIR}/crontab",
    'swap': f"{BACKUP_DIR}/swap"
}

LOG_PATHS = {
    'fastpanel': {
        'error': '/var/www/*/data/logs/*error.log',
        'access': '/var/www/*/data/logs/*access.log',
        'home_error': '/home/*/logs/*error.log',
        'home_access': '/home/*/logs/*access.log'
    },
    'ispmanager': {
        'error': '/var/www/*/data/logs/error.log',
        'access': '/var/www/*/data/logs/access.log',
        'httpd_error': '/var/www/httpd-logs/*.error.log',
        'httpd_access': '/var/www/httpd-logs/*.access.log'
    },
    'none': {
        'nginx_error': '/var/log/nginx/*error.log',
        'nginx_access': '/var/log/nginx/*access.log',
        'apache_error': '/var/log/apache2/*error.log',
        'apache_access': '/var/log/apache2/*access.log',
        'httpd_error': '/var/log/httpd/*error_log',
        'httpd_access': '/var/log/httpd/*access_log'
    }
}

DOMAIN_PATHS = {
    'fastpanel': [
        '/etc/nginx/fastpanel2-available/*/*.conf',
        '/usr/local/fastpanel/etc/nginx/sites-available/*',
        '/etc/nginx/sites-available/*'
    ],
    'ispmanager': [
        '/etc/nginx/vhosts/*/*.conf',
        '/etc/nginx/vhosts/*.conf',
        '/usr/local/mgr5/etc/nginx/vhosts/*.conf',
        '/usr/local/mgr5/etc/nginx/vhosts/*/*.conf',
        '/usr/local/mgr5/etc/nginx/sites-enabled/*.conf',
        '/usr/local/mgr5/etc/nginx/conf.d/*.conf',
        '/etc/nginx/sites-enabled/*',
        '/etc/nginx/conf.d/*.conf'
    ],
    'none': [
        '/etc/nginx/sites-enabled/*',
        '/etc/nginx/conf.d/*.conf',
        '/etc/apache2/sites-enabled/*.conf'
    ]
}

# ==================== ВСПОМОГАТЕЛЬНЫЕ ФУНКЦИИ ====================
def ensure_backup_dir(checker):
    """Создаёт директорию для бэкапов, если её нет"""
    out, _ = checker.exec_command(f'mkdir -p {BACKUP_DIR} 2>/dev/null && echo "created"')
    for subdir in BACKUP_SUBDIRS.values():
        checker.exec_command(f'mkdir -p {subdir} 2>/dev/null')
    return out.strip() == 'created'

def create_backup(checker, filepath, backup_type='configs'):
    """
    Создаёт резервную копию файла с временной меткой в соответствующей поддиректории.
    Возвращает путь к бэкапу или None в случае ошибки.
    """
    ensure_backup_dir(checker)
    
    filename = os.path.basename(filepath)
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    backup_filename = f"{filename}.{timestamp}.bak"
    backup_path = f"{BACKUP_SUBDIRS.get(backup_type, BACKUP_SUBDIRS['configs'])}/{backup_filename}"
    
    out, _ = checker.exec_command(f'test -f {filepath} && echo "exists"')
    if out.strip() != 'exists':
        return None
    
    out, err = checker.exec_command(f'cp {filepath} {backup_path} 2>&1')
    if err.strip():
        return None
    
    out, _ = checker.exec_command(f'test -f {backup_path} && echo "exists"')
    if out.strip() == 'exists':
        return backup_path
    return None

def find_files(checker, pattern, limit=20):
    """Находит файлы по паттерну и возвращает список с предупреждением об ограничении"""
    cmd = f"ls -1 {pattern} 2>/dev/null | head -{limit}"
    out, _ = checker.exec_command(cmd)
    files = [f.strip() for f in out.split('\n') if f.strip()]
    if len(files) >= limit:
        files.append(f"⚠️ (показаны первые {limit} файлов)")
    return files

def find_file(checker, patterns):
    """Находит первый существующий файл из списка паттернов"""
    for pattern in patterns:
        out, _ = checker.exec_command(f"ls -1 {pattern} 2>/dev/null | head -1")
        if out.strip():
            return out.strip()
    return None

def read_file_content(checker, filepath):
    """Читает содержимое файла"""
    out, err = checker.exec_command(f'cat {filepath} 2>/dev/null')
    if err.strip():
        return None
    return out

def get_domain_from_config(checker, config_path):
    """Извлекает домены из конфигурационного файла"""
    cmd = f"grep -h 'server_name' {config_path} 2>/dev/null | sed 's/.*server_name\\s*\\([^;]*\\);.*/\\1/' | tr -s ' ' '\\n' | grep -v '^_' | grep -v '^$' | grep -v 'localhost' | grep -v 'default_server' | grep -v '^\\*'"
    out, _ = checker.exec_command(cmd)
    domains = []
    if out.strip():
        for d in out.split('\n'):
            d = d.strip()
            if d and '.' in d and not d.startswith('_') and not d.startswith('*'):
                domains.append(d)
    return list(set(domains))

# ==================== ОПРЕДЕЛЕНИЕ ПАНЕЛИ ====================
def detect_panel(checker):
    cmds = {
        'fastpanel': 'test -f /usr/local/fastpanel/bin/fastpanel && echo "yes" || echo "no"',
        'ispmanager': 'test -f /usr/local/mgr5/bin/mgrctl && echo "yes" || echo "no"'
    }
    for panel, cmd in cmds.items():
        out, _ = checker.exec_command(cmd)
        if out.strip() == 'yes':
            return panel
    out, _ = checker.exec_command('ps aux | grep -E "fastpanel|mgr5" | grep -v grep')
    if 'fastpanel' in out.lower():
        return 'fastpanel'
    if 'mgr5' in out.lower():
        return 'ispmanager'
    return 'none'

# ==================== СБОР МЕТРИК ====================
def get_metrics(checker):
    """Собирает системные метрики (по отдельности для надёжности)"""
    metrics = {}
    
    out, _ = checker.exec_command('df -h')
    metrics['disk'] = out
    
    out, _ = checker.exec_command('df -i')
    metrics['inodes'] = out
    
    out, _ = checker.exec_command('free -m')
    metrics['memory'] = out
    
    out, _ = checker.exec_command('uptime')
    metrics['uptime'] = out
    
    out, _ = checker.exec_command('ss -tulpn 2>/dev/null || netstat -tulpn 2>/dev/null')
    metrics['listening_ports'] = out
    
    firewall = {}
    out, _ = checker.exec_command('ufw status 2>/dev/null || echo "ufw not installed"')
    firewall['ufw'] = out
    out, _ = checker.exec_command('iptables -L -n 2>/dev/null || echo "iptables not available"')
    firewall['iptables'] = out
    out, _ = checker.exec_command('nft list ruleset 2>/dev/null || echo "nftables not available"')
    firewall['nftables'] = out
    metrics['firewall'] = firewall
    
    services = ['nginx', 'apache2', 'httpd', 'php-fpm', 'mysql', 'mariadb', 'php7.4-fpm']
    cmd = '; '.join([f'systemctl is-active {svc} 2>/dev/null || echo "inactive"' for svc in services])
    out, _ = checker.exec_command(cmd)
    statuses = out.strip().split('\n')
    metrics['services'] = {svc: statuses[i] if i < len(statuses) else 'unknown' for i, svc in enumerate(services)}
    
    return metrics

# ==================== ПОИСК ЛОГОВ ====================
def find_logs(checker, panel_type, domain, log_type='error'):
    """Находит логи для домена (унифицированная функция)"""
    log_files = []
    limit = 20
    
    if panel_type == 'fastpanel':
        patterns = [
            f'/var/www/*/data/logs/*{domain}*.{log_type}.log',
            f'/home/*/logs/*{domain}*.{log_type}.log'
        ]
        for pattern in patterns:
            log_files.extend(find_files(checker, pattern, limit))
            
    elif panel_type == 'ispmanager':
        patterns = [
            f'/var/www/*/{domain}/data/logs/{log_type}.log',
            f'/var/www/*/{domain}/logs/{log_type}.log',
            f'/var/www/httpd-logs/{domain}.{log_type}.log'
        ]
        for pattern in patterns:
            log_files.extend(find_files(checker, pattern, limit))
            
    else:
        patterns = [
            f'/var/log/nginx/{domain}.{log_type}.log',
            f'/var/log/apache2/{domain}-{log_type}.log',
            f'/var/log/httpd/{domain}-{log_type}_log'
        ]
        for pattern in patterns:
            log_files.extend(find_files(checker, pattern, limit))
    
    return list(set(log_files))

def parse_access_log_line(line):
    """Парсит одну строку access-лога"""
    pattern = re.compile(
        r'^(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] "(?P<request>[^"]*)" (?P<status>\d{3}) (?P<size>\S+) "(?P<referer>[^"]*)" "(?P<agent>[^"]*)"'
    )
    match = pattern.match(line)
    if not match:
        return None
    return match.groupdict()

def filter_by_date(entry, year=None, month=None, day=None):
    """Фильтрует запись по дате"""
    if not entry:
        return False
    time_str = entry.get('time', '')
    try:
        date_part = time_str.split(':')[0]
        parts = date_part.split('/')
        if len(parts) == 3:
            log_day = int(parts[0])
            month_names = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun',
                          'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec']
            log_month = month_names.index(parts[1]) + 1
            log_year = int(parts[2])
            
            if year is not None and log_year != year:
                return False
            if month is not None and log_month != month:
                return False
            if day is not None and log_day != day:
                return False
            return True
    except:
        pass
    return False

# ==================== ФУНКЦИИ ДЛЯ ОТДЕЛЬНЫХ ПРОВЕРОК ====================
def disk_memory_report(checker):
    out_h, _ = checker.exec_command('df -h')
    out_i, _ = checker.exec_command('df -i')
    out_f, _ = checker.exec_command('free -m')
    return f"=== ДИСКИ И ПАМЯТЬ ===\nДиски (df -h):\n{out_h}\n\nInodes (df -i):\n{out_i}\n\nПамять (free -m):\n{out_f}"

def network_report(checker):
    out_a, _ = checker.exec_command('ip a')
    out_r, _ = checker.exec_command('ip r')
    
    default_iface = None
    default_gw = None
    for line in out_r.splitlines():
        if line.startswith('default'):
            parts = line.split()
            if len(parts) >= 5 and parts[0] == 'default' and parts[1] == 'via':
                default_gw = parts[2]
                default_iface = parts[4]
                break
    
    out_get, _ = checker.exec_command('ip route get 1.1.1.1 2>/dev/null | grep -oP "src \\S+" | cut -d" " -f2')
    src_ip = out_get.strip()
    
    out_ext, _ = checker.exec_command('curl -s ifconfig.me 2>/dev/null || wget -qO- ifconfig.me 2>/dev/null || dig +short myip.opendns.com @resolver1.opendns.com 2>/dev/null')
    external_ip = out_ext.strip()
    
    lines = []
    lines.append("=== СЕТЕВЫЕ ИНТЕРФЕЙСЫ (ip a) ===")
    lines.append(out_a)
    lines.append("\n=== МАРШРУТЫ (ip r) ===")
    lines.append(out_r)
    
    if default_iface:
        lines.append(f"\nИнтерфейс по умолчанию: {default_iface} (шлюз {default_gw})")
    if src_ip:
        lines.append(f"IP-адрес источника для исходящего трафика: {src_ip} (интерфейс {default_iface})")
    if external_ip:
        lines.append(f"Внешний (плавающий) IP: {external_ip}")
        if src_ip:
            lines.append(f"  (трафик идёт через NAT: приватный IP {src_ip} на интерфейсе {default_iface} -> плавающий IP {external_ip})")
    else:
        lines.append("\nВнешний IP не удалось определить (проверьте доступность ifconfig.me или установите curl/wget/dig)")
    
    return "\n".join(lines)

# ==================== АНАЛИЗ ЛОГОВ ДОСТУПА ====================
def analyze_access_log(checker, panel_type, domain, top_n=10, year=None, month=None, day=None):
    """Анализирует access-логи"""
    log_files = find_logs(checker, panel_type, domain, 'access')
    if not log_files:
        return f"❌ Не найден access-лог для домена {domain}"
    
    ip_counter = Counter()
    uri_counter = Counter()
    agent_counter = Counter()
    total_requests = 0
    unique_ips = set()
    
    for log_file in log_files:
        if log_file.startswith('⚠️'):
            continue
        content = read_file_content(checker, log_file)
        if not content:
            continue
        
        if log_file.endswith('.gz'):
            out, _ = checker.exec_command(f'zcat {log_file} 2>/dev/null')
            content = out
        
        for line in content.splitlines():
            entry = parse_access_log_line(line)
            if not entry:
                continue
            
            if not filter_by_date(entry, year, month, day):
                continue
            
            ip = entry['ip']
            request = entry['request']
            agent = entry['agent']
            parts = request.split()
            uri = parts[1] if len(parts) >= 2 else request
            
            ip_counter[ip] += 1
            uri_counter[uri] += 1
            agent_counter[agent] += 1
            total_requests += 1
            unique_ips.add(ip)
    
    if total_requests == 0:
        filters = []
        if year: filters.append(f"год={year}")
        if month: filters.append(f"месяц={month}")
        if day: filters.append(f"день={day}")
        return f"За указанный период ({' '.join(filters)}) записей не найдено."
    
    lines_out = []
    lines_out.append(f"=== АНАЛИЗ ПОСЕЩЕНИЙ ДЛЯ {domain} ===")
    lines_out.append(f"Обработано файлов: {len(log_files)}")
    filters = []
    if year: filters.append(f"год={year}")
    if month: filters.append(f"месяц={month}")
    if day: filters.append(f"день={day}")
    lines_out.append(f"Фильтр: {' '.join(filters) if filters else 'все записи'}")
    lines_out.append(f"Всего запросов: {total_requests}")
    lines_out.append(f"Уникальных IP: {len(unique_ips)}")
    lines_out.append("")
    
    lines_out.append(f"--- ТОП-{top_n} IP ПО КОЛИЧЕСТВУ ЗАПРОСОВ ---")
    for ip, cnt in ip_counter.most_common(top_n):
        lines_out.append(f"{ip:20} {cnt:>6}")
    
    lines_out.append("")
    lines_out.append(f"--- ТОП-{top_n} ЗАПРАШИВАЕМЫХ URI ---")
    for uri, cnt in uri_counter.most_common(top_n):
        lines_out.append(f"{uri:40} {cnt:>6}")
    
    lines_out.append("")
    lines_out.append(f"--- ТОП-{top_n} USER-AGENT ---")
    for agent, cnt in agent_counter.most_common(top_n):
        short_agent = agent[:80] + '...' if len(agent) > 80 else agent
        lines_out.append(f"{short_agent:50} {cnt:>6}")
    
    return "\n".join(lines_out)

# ==================== ПОИСК ДОМЕНОВ ====================
def get_domains(checker, panel_type):
    domains = []
    
    if panel_type == 'ispmanager':
        out, _ = checker.exec_command('mgrctl -m webdomain list --output-format csv 2>/dev/null')
        if out.strip():
            for line in out.strip().split('\n')[1:]:
                parts = line.split(',')
                if len(parts) >= 2:
                    domain = parts[1].strip()
                    if domain and domain not in domains:
                        domains.append(domain)
            if domains:
                return list(set(domains))
    
    paths = DOMAIN_PATHS.get(panel_type, DOMAIN_PATHS['none'])
    for pattern in paths:
        out, _ = checker.exec_command(f'ls -1 {pattern} 2>/dev/null | head -10')
        if out.strip():
            for config_file in out.splitlines():
                if config_file.strip():
                    domains.extend(get_domain_from_config(checker, config_file.strip()))
    
    return list(set(domains))

# ==================== ПРОВЕРКА ЛОГОВ САЙТОВ ====================
def check_site_logs(checker, panel_type, domains):
    errors = {}
    for domain in domains:
        log_files = find_logs(checker, panel_type, domain, 'error')
        for log_file in log_files:
            if log_file.startswith('⚠️'):
                continue
            content = read_file_content(checker, log_file)
            if content:
                lines = content.splitlines()[-200:]
                for line in lines:
                    if re.search(r'error|fail|critical|fatal|panic|warning', line, re.I):
                        if domain not in errors:
                            errors[domain] = []
                        errors[domain].append(f"{log_file}: {line.strip()}")
    
    result = {}
    for domain, err_lines in errors.items():
        if err_lines:
            result[f"{domain}:{log_file}"] = '\n'.join(err_lines[:10])
    return result

# ==================== ВЕБ-КОНФИГУРАЦИЯ ====================
def check_web_config(checker):
    results = {}
    out, _ = checker.exec_command('nginx -t 2>&1')
    if 'nginx' in out or 'syntax is ok' in out.lower():
        results['nginx'] = out.strip()
    out, _ = checker.exec_command('apache2ctl -t 2>&1 || httpd -t 2>&1')
    if 'syntax ok' in out.lower() or 'apache' in out.lower():
        results['apache'] = out.strip()
    return results

# ==================== ОТЧЁТЫ ====================
def metrics_report(checker):
    metrics = get_metrics(checker)
    lines = []
    lines.append("=== МЕТРИКИ СИСТЕМЫ ===")
    lines.append("Диски:\n" + metrics['disk'])
    lines.append("Inodes:\n" + metrics['inodes'])
    lines.append("Память:\n" + metrics['memory'])
    lines.append("Нагрузка:\n" + metrics['uptime'])
    lines.append("Слушающие порты:\n" + metrics['listening_ports'])
    lines.append("Статусы служб:")
    for svc, status in metrics['services'].items():
        lines.append(f"  {svc}: {status}")
    return "\n".join(lines)

def firewall_report(checker):
    metrics = get_metrics(checker)
    lines = ["=== ФАЙРВОЛ ==="]
    for fw, output in metrics['firewall'].items():
        lines.append(f"{fw}:\n{output}")
    return "\n".join(lines)

def web_config_report(checker):
    results = check_web_config(checker)
    lines = ["=== ПРОВЕРКА КОНФИГУРАЦИИ ВЕБ-СЕРВЕРА ==="]
    if results:
        for svc, output in results.items():
            lines.append(f"{svc}: {output}")
    else:
        lines.append("Веб-сервер (nginx/apache) не обнаружен или не удалось проверить конфиг.")
    return "\n".join(lines)

def site_logs_report(checker, panel):
    domains = get_domains(checker, panel)
    lines = []
    if domains:
        lines.append(f"Найдены домены: {', '.join(domains)}")
        lines.append("\n=== ОШИБКИ В ЛОГАХ САЙТОВ ===")
        site_errors = check_site_logs(checker, panel, domains)
        if site_errors:
            for key, err in site_errors.items():
                lines.append(f"\n{key}:\n{err}")
        else:
            lines.append("Ошибок (по ключевым словам) в логах сайтов не обнаружено.")
    else:
        lines.append("Не удалось определить домены для проверки логов.")
    return "\n".join(lines)

def full_diagnostic_report(checker, panel):
    lines = []
    lines.append(f"=== Начинаем диагностику сервера {checker.host}:{checker.port} ===")
    lines.append(f"Тип панели управления: {panel}\n")
    lines.append(metrics_report(checker))
    lines.append("\n" + firewall_report(checker))
    lines.append("\n" + web_config_report(checker))
    lines.append("\n" + site_logs_report(checker, panel))
    lines.append("\n=== ДИАГНОСТИКА ЗАВЕРШЕНА ===")
    return "\n".join(lines)

# ==================== DNS ФУНКЦИИ ====================
def dns_report_local(domain):
    import socket
    lines = []
    lines.append(f"=== ЛОКАЛЬНАЯ DNS-ПРОВЕРКА ДЛЯ {domain} ===")
    
    ip_pattern = re.compile(r'^(\d{1,3}\.){3}\d{1,3}$')
    is_ip = bool(ip_pattern.match(domain))
    
    if is_ip:
        try:
            ptr = socket.gethostbyaddr(domain)[0]
            lines.append(f"PTR (обратный DNS): {ptr}")
        except socket.herror:
            lines.append("PTR-запись не найдена.")
        except Exception as e:
            lines.append(f"Ошибка PTR-запроса: {e}")
        return "\n".join(lines)
    
    try:
        a_records = socket.getaddrinfo(domain, None, socket.AF_INET)
        ips = list(set([addr[4][0] for addr in a_records]))
        if ips:
            lines.append(f"A-записи: {', '.join(ips)}")
            try:
                ptr = socket.gethostbyaddr(ips[0])[0]
                lines.append(f"PTR для {ips[0]}: {ptr}")
            except socket.herror:
                lines.append(f"PTR-запись для {ips[0]} не найдена.")
            except Exception as e:
                lines.append(f"Ошибка PTR-запроса: {e}")
        else:
            lines.append("A-записи не найдены.")
    except socket.gaierror:
        lines.append("Ошибка: домен не разрешается (A-запись отсутствует).")
    except Exception as e:
        lines.append(f"Ошибка DNS-запроса: {e}")
    
    lines.append("(NS-записи доступны только при проверке с сервера)")
    return "\n".join(lines)

def dns_report(checker, domain, ip=None):
    lines = []
    lines.append(f"=== DNS-ПРОВЕРКА НА СЕРВЕРЕ ДЛЯ {domain} ===")
    
    ip_pattern = re.compile(r'^(\d{1,3}\.){3}\d{1,3}$')
    is_ip = bool(ip_pattern.match(domain))
    
    if is_ip:
        cmd = f"dig +short -x {domain} 2>/dev/null"
        out, _ = checker.exec_command(cmd)
        if out.strip():
            lines.append(f"PTR (обратный DNS): {out.strip()}")
        else:
            lines.append("PTR-запись не найдена.")
        return "\n".join(lines)
    
    target_ip = ip
    if not target_ip:
        cmd = f"dig +short A {domain} 2>/dev/null"
        out, _ = checker.exec_command(cmd)
        if out.strip():
            a_records = out.splitlines()
            lines.append(f"A-записи: {', '.join(a_records)}")
            target_ip = a_records[0].strip()
        else:
            lines.append("A-записи не найдены.")
    
    cmd = f"dig +short NS {domain} 2>/dev/null"
    out, _ = checker.exec_command(cmd)
    if out.strip():
        lines.append(f"NS-записи: {', '.join(out.splitlines())}")
    else:
        lines.append("NS-записи не найдены.")
    
    if target_ip:
        cmd = f"dig +short -x {target_ip} 2>/dev/null"
        out, _ = checker.exec_command(cmd)
        if out.strip():
            lines.append(f"PTR для {target_ip}: {out.strip()}")
        else:
            lines.append(f"PTR-запись для {target_ip} не найдена.")
    else:
        lines.append("Не удалось получить IP для PTR-запроса.")
    
    return "\n".join(lines)

def dns_resolvers_report(checker):
    lines = []
    lines.append("=== DNS-РЕЗОЛВЕРЫ НА СЕРВЕРЕ ===")
    
    out, _ = checker.exec_command('cat /etc/resolv.conf 2>/dev/null')
    if not out.strip():
        lines.append("❌ Не удалось прочитать /etc/resolv.conf")
        return "\n".join(lines)
    
    lines.append("Содержимое /etc/resolv.conf:\n" + out)
    
    nameservers = []
    for line in out.splitlines():
        if line.strip().startswith('nameserver'):
            parts = line.split()
            if len(parts) >= 2:
                nameservers.append(parts[1])
    
    if not nameservers:
        lines.append("❌ В /etc/resolv.conf не найдены nameserver'ы")
        return "\n".join(lines)
    
    lines.append(f"\nНайдено DNS-серверов: {len(nameservers)}")
    lines.append("Проверка доступности:")
    
    for ns in nameservers:
        cmd = f"dig +timeout=2 +tries=1 @{ns} google.com A 2>/dev/null | grep -q 'NOERROR' && echo 'доступен' || echo 'недоступен'"
        out, _ = checker.exec_command(cmd)
        status = out.strip() if out.strip() else "недоступен"
        lines.append(f"  {ns}: {status}")
    
    out, _ = checker.exec_command('systemd-resolve --status 2>/dev/null | grep "DNS Servers"')
    if out.strip():
        lines.append("\nТекущие DNS-серверы (systemd-resolve):")
        lines.append(out.strip())
    else:
        out, _ = checker.exec_command('resolvectl status 2>/dev/null | grep "DNS Servers"')
        if out.strip():
            lines.append("\nТекущие DNS-серверы (resolvectl):")
            lines.append(out.strip())
    
    return "\n".join(lines)

def get_current_dns_resolvers(checker):
    out, _ = checker.exec_command('grep -E "^nameserver" /etc/resolv.conf 2>/dev/null | awk \'{print $2}\'')
    if out.strip():
        return [ns.strip() for ns in out.splitlines() if ns.strip()]
    return []

def set_dns_resolvers(checker, nameservers):
    lines = []
    lines.append("=== ИЗМЕНЕНИЕ DNS-РЕЗОЛВЕРОВ ===")
    
    out, _ = checker.exec_command('systemctl is-active systemd-resolved 2>/dev/null')
    if out.strip() != 'active':
        lines.append("systemd-resolved не активен. Редактируем /etc/resolv.conf напрямую.")
        
        backup_path = create_backup(checker, '/etc/resolv.conf', 'dns')
        if backup_path:
            lines.append(f"✅ Резервная копия создана: {backup_path}")
        else:
            lines.append("⚠️ Не удалось создать резервную копию /etc/resolv.conf")
        
        new_content = "# Generated by SSH Diagnostic Tool\n"
        for ns in nameservers:
            new_content += f"nameserver {ns}\n"
        cmd = f'echo "{new_content}" > /etc/resolv.conf'
        out, err = checker.exec_command(cmd + ' 2>&1')
        if err.strip():
            lines.append(f"❌ Ошибка записи: {err.strip()}")
        else:
            lines.append("✅ /etc/resolv.conf обновлён.")
            out_check, _ = checker.exec_command('cat /etc/resolv.conf')
            lines.append("\nСодержимое /etc/resolv.conf:\n" + out_check)
        return "\n".join(lines)
    
    lines.append("Обнаружен systemd-resolved. Настраиваем глобальные DNS и интерфейсы.")
    
    out_conf, _ = checker.exec_command('cat /etc/systemd/resolved.conf 2>/dev/null')
    new_conf_lines = []
    dns_found = False
    for line in out_conf.splitlines():
        if re.match(r'^#?\s*DNS\s*=', line):
            new_conf_lines.append(f'DNS={ " ".join(nameservers) }')
            dns_found = True
        else:
            new_conf_lines.append(line)
    if not dns_found:
        resolved_section = False
        for i, line in enumerate(new_conf_lines):
            if re.match(r'^\s*\[Resolve\]\s*$', line):
                resolved_section = True
                new_conf_lines.insert(i+1, f'DNS={ " ".join(nameservers) }')
                break
        if not resolved_section:
            new_conf_lines.append('[Resolve]')
            new_conf_lines.append(f'DNS={ " ".join(nameservers) }')
    new_content = '\n'.join(new_conf_lines)
    new_content_escaped = new_content.replace('"', '\\"')
    cmd = f'echo "{new_content_escaped}" > /etc/systemd/resolved.conf'
    out, err = checker.exec_command(cmd + ' 2>&1')
    if err.strip():
        lines.append(f"❌ Ошибка записи resolved.conf: {err.strip()}")
    else:
        lines.append("✅ /etc/systemd/resolved.conf обновлён.")
    
    cmd_iface = "ip -o link show | awk -F': ' '{print $2}' | grep -v lo"
    out_ifaces, _ = checker.exec_command(cmd_iface)
    interfaces = [iface.strip() for iface in out_ifaces.splitlines() if iface.strip()]
    for iface in interfaces:
        checker.exec_command(f'resolvectl dns {iface} "" 2>/dev/null')
        cmd = f'resolvectl dns {iface} ' + ' '.join(nameservers)
        out, err = checker.exec_command(cmd + ' 2>&1')
        if err.strip() and 'error' in err.lower():
            lines.append(f"❌ Ошибка для {iface}: {err.strip()}")
        else:
            lines.append(f"✅ DNS для {iface}: {', '.join(nameservers)}")
    
    checker.exec_command('systemctl restart systemd-resolved 2>/dev/null')
    lines.append("Перезапущен systemd-resolved.")
    
    out_check, _ = checker.exec_command('resolvectl status | grep -E "Global|DNS Servers"')
    lines.append("\nТекущие DNS (resolvectl):\n" + (out_check if out_check.strip() else "нет данных"))
    out_resolv, _ = checker.exec_command('cat /etc/resolv.conf')
    lines.append("\nСодержимое /etc/resolv.conf:\n" + out_resolv)
    
    return "\n".join(lines)

# ==================== РАБОТА С ФАЙЛАМИ (С БЭКАПАМИ) ====================
def write_file(checker, filepath, content):
    """Записывает содержимое в файл с созданием резервной копии"""
    lines = []
    lines.append(f"=== СОХРАНЕНИЕ ФАЙЛА: {filepath} ===")
    
    # СОЗДАЁМ БЭКАП
    backup_path = create_backup(checker, filepath, 'configs')
    if backup_path:
        lines.append(f"✅ Резервная копия создана: {backup_path}")
    else:
        lines.append("⚠️ Не удалось создать резервную копию файла")
    
    # Записываем новое содержимое
    cmd = f"cat > {filepath} <<'EOF'\n{content}\nEOF"
    out, err = checker.exec_command(cmd + ' 2>&1')
    if err.strip():
        lines.append(f"❌ Ошибка записи: {err}")
        return "\n".join(lines)
    
    lines.append("✅ Файл сохранён.")
    return "\n".join(lines)

def read_file(checker, filepath):
    out, err = checker.exec_command(f'cat {filepath} 2>/dev/null')
    if err.strip():
        return f"❌ Ошибка чтения файла: {err}"
    return out

def get_config_files(checker, panel_type):
    files = []
    common_paths = [
        '/etc/nginx/nginx.conf',
        '/etc/nginx/sites-available/',
        '/etc/nginx/sites-enabled/',
        '/etc/nginx/conf.d/',
        '/etc/apache2/apache2.conf',
        '/etc/apache2/sites-available/',
        '/etc/apache2/sites-enabled/',
        '/etc/apache2/conf-available/',
        '/etc/apache2/conf-enabled/',
        '/etc/httpd/conf/httpd.conf',
        '/etc/httpd/conf.d/',
        '/etc/php/*/php.ini',
        '/etc/php/*/fpm/php.ini',
        '/etc/php/*/cli/php.ini',
        '/etc/mysql/mysql.conf.d/mysqld.cnf',
        '/etc/mysql/my.cnf',
    ]
    
    panel_paths = {
        'fastpanel': [
            '/usr/local/fastpanel/etc/nginx/',
            '/usr/local/fastpanel/etc/php/',
            '/etc/nginx/fastpanel2-available/',
        ],
        'ispmanager': [
            '/usr/local/mgr5/etc/nginx/',
            '/usr/local/mgr5/etc/apache2/',
            '/usr/local/mgr5/etc/php/',
        ]
    }
    
    for path in common_paths:
        out, _ = checker.exec_command(f'ls -d {path} 2>/dev/null && echo "exists"')
        if out.strip() == 'exists':
            out2, _ = checker.exec_command(f'ls -1 {path} 2>/dev/null | head -20')
            if out2.strip():
                for f in out2.splitlines():
                    if f.strip():
                        files.append(f"{path}{f}" if path.endswith('/') else path)
            else:
                files.append(path)
    
    if panel_type in panel_paths:
        for path in panel_paths[panel_type]:
            out, _ = checker.exec_command(f'ls -d {path} 2>/dev/null && echo "exists"')
            if out.strip() == 'exists':
                out2, _ = checker.exec_command(f'find {path} -type f -name "*.conf" 2>/dev/null | head -20')
                if out2.strip():
                    for f in out2.splitlines():
                        if f.strip():
                            files.append(f)
    
    return sorted(list(set(files)))[:50]

# ==================== УПРАВЛЕНИЕ ISPmanager ====================
def ispmanager_restart(checker):
    lines = []
    lines.append("=== ПЕРЕЗАПУСК ISPmanager ===")
    out, err = checker.exec_command('/usr/local/mgr5/sbin/mgrctl -m ispmgr exit 2>&1')
    if err.strip():
        lines.append(f"❌ Ошибка: {err}")
    else:
        lines.append("✅ Команда на перезапуск отправлена через mgrctl")
    checker.exec_command('sleep 3')
    out2, _ = checker.exec_command('/usr/local/mgr5/sbin/mgrctl -m ispmgr sysinfo 2>&1 | head -1')
    lines.append("✅ Панель работает" if 'error' not in out2.lower() else "⚠️ Панель возможно не запустилась")
    return "\n".join(lines)

def ispmanager_kill_core(checker):
    lines = []
    lines.append("=== ПРИНУДИТЕЛЬНОЕ ЗАВЕРШЕНИЕ CORE ===")
    checker.exec_command('killall core 2>&1')
    checker.exec_command('pkill -9 core 2>&1')
    checker.exec_command('sleep 2')
    out, _ = checker.exec_command('ps aux | grep core | grep -v grep')
    lines.append("✅ Процесс core завершён" if not out.strip() else "⚠️ Процесс core всё ещё работает")
    return "\n".join(lines)

def ispmanager_update(checker):
    lines = []
    lines.append("=== ОБНОВЛЕНИЕ ISPmanager ===")
    lines.append("⚠️ Обновление может занять несколько минут...")
    out, err = checker.exec_command('/usr/local/mgr5/sbin/pkgupgrade.sh coremanager 2>&1')
    lines.append("✅ Обновление завершено" if not err.strip() else f"❌ Ошибка обновления: {err}")
    return "\n".join(lines)

def ispmanager_ssl_issue(checker):
    lines = []
    lines.append("=== ПРИНУДИТЕЛЬНЫЙ ВЫПУСК LET'S ENCRYPT ===")
    lines.append("⚠️ Процесс может занять несколько минут...")
    out, err = checker.exec_command('/usr/local/mgr5/sbin/mgrctl -m ispmgr letsencrypt.periodic 2>&1')
    lines.append("✅ Команда выполнена" if not err.strip() else f"❌ Ошибка: {err}")
    return "\n".join(lines)

def ispmanager_disable(checker):
    lines = []
    lines.append("=== ОТКЛЮЧЕНИЕ ISPmanager ===")
    lines.append("⚠️ Панель будет остановлена!")
    checker.exec_command('chmod -x /usr/local/mgr5/bin/core 2>&1')
    checker.exec_command('killall core 2>&1')
    checker.exec_command('killall ihttpd 2>&1')
    lines.append("✅ Панель отключена")
    lines.append("⚠️ Для включения выполните: chmod +x /usr/local/mgr5/bin/core && /usr/local/mgr5/bin/core")
    return "\n".join(lines)

def ispmanager_disable_geoip(checker):
    lines = []
    lines.append("=== ОТКЛЮЧЕНИЕ GEOIP В ISPmanager ===")
    out, err = checker.exec_command('/usr/local/mgr5/sbin/mgrctl -m ispmgr usrparam setgeoip=off sok=ok 2>&1')
    lines.append("✅ GeoIP отключён" if not err.strip() else f"❌ Ошибка: {err}")
    return "\n".join(lines)

def ispmanager_check_cron_path(checker):
    lines = []
    lines.append("=== ПРОВЕРКА CRON PATH ===")
    out, _ = checker.exec_command('crontab -l 2>/dev/null | grep "^PATH="')
    lines.append(f"⚠️ Найдена переменная PATH в crontab:\n{out}" if out.strip() else "✅ Переменная PATH не найдена в crontab")
    return "\n".join(lines)

def ispmanager_fix_cron_path(checker):
    lines = []
    lines.append("=== ИСПРАВЛЕНИЕ CRON PATH ===")
    # СОЗДАЁМ БЭКАП CRONTAB
    backup_path = create_backup(checker, '/tmp/crontab_backup.txt', 'crontab')
    if backup_path:
        lines.append(f"✅ Резервная копия crontab создана: {backup_path}")
    else:
        lines.append("⚠️ Не удалось создать резервную копию crontab")
    
    checker.exec_command('crontab -l > /tmp/crontab_backup.txt 2>/dev/null')
    out, err = checker.exec_command("crontab -l 2>/dev/null | sed 's/^PATH=/#PATH=/' | crontab - 2>&1")
    lines.append("✅ Переменная PATH закомментирована" if not err.strip() else f"❌ Ошибка: {err}")
    return "\n".join(lines)

# ==================== ПОИСК OOM ====================
def search_oom_logs(checker):
    """Поиск событий Out-Of-Memory в системных логах"""
    cmd = "zgrep -B 5 -A 5 -i 'out of memory\\|killed process\\|oom-killer' /var/log/kern.log* /var/log/syslog* 2>/dev/null"
    out, err = checker.exec_command(cmd)
    if not out.strip():
        return "OOM-событий в логах не найдено."
    
    lines = out.splitlines()
    report_lines = []
    report_lines.append("=== ПОИСК OOM-СОБЫТИЙ В ЛОГАХ ===")
    report_lines.append("Файлы: /var/log/kern.log*, /var/log/syslog*")
    report_lines.append("")
    
    blocks = []
    current_block = []
    for line in lines:
        if line.strip() == '--':
            if current_block:
                blocks.append('\n'.join(current_block))
                current_block = []
        else:
            current_block.append(line)
    if current_block:
        blocks.append('\n'.join(current_block))
    
    if not blocks:
        return "OOM-событий не обнаружено (пустые блоки)."
    
    for i, block in enumerate(blocks, 1):
        report_lines.append(f"--- Событие #{i} ---")
        report_lines.append(block)
        report_lines.append("")
    
    return "\n".join(report_lines)

# ==================== ЗАМЕНА IP ====================
def replace_ipv4(checker, old_ip, new_ip):
    lines = []
    lines.append(f"=== ЗАМЕНА IPv4: {old_ip} -> {new_ip} ===")
    old_escaped = old_ip.replace('.', '\.')
    cmd = f"find /etc -type f -name '*.conf' -exec sed -i -e 's#{old_escaped}#{new_ip}#g' '{{}}' \\; 2>/dev/null"
    out, err = checker.exec_command(cmd)
    if err.strip():
        lines.append(f"⚠️ Возможны ошибки: {err.strip()}")
    lines.append("✅ IPv4 заменён во всех .conf-файлах в /etc.")
    lines.extend(restart_services(checker))
    return "\n".join(lines)

def replace_ipv6(checker, old_ip, new_ip):
    lines = []
    lines.append(f"=== ЗАМЕНА IPv6: {old_ip} -> {new_ip} ===")
    cmd = f"find /etc -type f -exec sed -i 's/{old_ip}/{new_ip}/g' '{{}}' + 2>/dev/null"
    out, err = checker.exec_command(cmd)
    if err.strip():
        lines.append(f"⚠️ Возможны ошибки: {err.strip()}")
    lines.append("✅ IPv6 заменён во всех файлах в /etc.")
    lines.extend(restart_services(checker))
    return "\n".join(lines)

# ==================== ПЕРЕЗАПУСК СЛУЖБ ====================
def restart_services(checker):
    lines = []
    lines.append("\n=== ПЕРЕЗАПУСК СЛУЖБ ===")
    services = ['nginx', 'mysql', 'apache2']
    for svc in services:
        out, _ = checker.exec_command(f'systemctl list-unit-files | grep -q "^{svc}.service" && echo "yes" || echo "no"')
        if out.strip() == 'yes':
            checker.exec_command(f'systemctl restart {svc} 2>/dev/null')
            status, _ = checker.exec_command(f'systemctl is-active {svc} 2>/dev/null')
            lines.append(f"✅ {svc} {'перезапущен' if status.strip() == 'active' else 'не запустился'}")
        else:
            lines.append(f"⏭️ {svc} не установлен")
    return lines