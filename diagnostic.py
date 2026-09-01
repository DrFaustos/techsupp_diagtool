import time
import re
from collections import Counter
from datetime import datetime, timedelta
from ssh_client import ServerChecker

# ------------------- ОПРЕДЕЛЕНИЕ ПАНЕЛИ -------------------
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

# ------------------- СБОР МЕТРИК (возвращает словарь) -------------------
def get_metrics(checker):
    metrics = {}
    out, _ = checker.exec_command('df -h')
    metrics['disk'] = out
    out, _ = checker.exec_command('df -i')
    metrics['inodes'] = out
    out, _ = checker.exec_command('free -m')
    metrics['memory'] = out
    out, _ = checker.exec_command('uptime')
    metrics['uptime'] = out
    firewall = {}
    out, _ = checker.exec_command('ufw status 2>/dev/null || echo "ufw not installed"')
    firewall['ufw'] = out
    out, _ = checker.exec_command('iptables -L -n 2>/dev/null || echo "iptables not available"')
    firewall['iptables'] = out
    out, _ = checker.exec_command('nft list ruleset 2>/dev/null || echo "nftables not available"')
    firewall['nftables'] = out
    metrics['firewall'] = firewall
    out, _ = checker.exec_command('ss -tulpn 2>/dev/null || netstat -tulpn 2>/dev/null')
    metrics['listening_ports'] = out
    services = ['nginx', 'apache2', 'httpd', 'php-fpm', 'mysql', 'mariadb', 'php7.4-fpm']
    services_status = {}
    for svc in services:
        out, _ = checker.exec_command(f'systemctl is-active {svc} 2>/dev/null || echo "inactive"')
        services_status[svc] = out.strip()
    metrics['services'] = services_status
    return metrics

def get_domains(checker, panel_type):
    domains = []
    
    # === ISPmanager: сначала пробуем mgrctl (самый надёжный способ) ===
    if panel_type == 'ispmanager':
        out, _ = checker.exec_command('mgrctl -m webdomain list --output-format csv 2>/dev/null')
        if out.strip():
            lines = out.strip().split('\n')
            for line in lines:
                parts = line.split(',')
                if len(parts) >= 2:
                    domain = parts[1].strip()
                    if domain and domain not in domains:
                        domains.append(domain)
            if domains:
                return list(set(domains))  # убираем дубли
    
    # === Если mgrctl не сработал или не ISPmanager – парсим конфиги ===
    search_paths = []
    if panel_type == 'fastpanel':
        search_paths = [
            '/usr/local/fastpanel/etc/nginx/sites-available/*',
            '/etc/nginx/sites-available/*'
        ]
    elif panel_type == 'ispmanager':
        # Основные пути для ISPmanager: vhosts (пользовательские), sites-enabled, conf.d
        search_paths = [
            '/etc/nginx/vhosts/*/*.conf',              # пользовательские vhosts (www-root/domain.conf)
            '/etc/nginx/vhosts/*.conf',                # если конфиги прямо в vhosts (на всякий случай)
            '/usr/local/mgr5/etc/nginx/vhosts/*.conf', # стандартные пути ISPmanager
            '/usr/local/mgr5/etc/nginx/vhosts/*/*.conf',
            '/usr/local/mgr5/etc/nginx/sites-enabled/*.conf',
            '/usr/local/mgr5/etc/nginx/conf.d/*.conf',
            '/etc/nginx/sites-enabled/*',
            '/etc/nginx/conf.d/*.conf'
        ]
    else:  # none или не определено
        search_paths = [
            '/etc/nginx/sites-enabled/*',
            '/etc/nginx/conf.d/*.conf',
            '/etc/apache2/sites-enabled/*.conf'
        ]

    for path_pattern in search_paths:
        # Извлекаем server_name, разбиваем по пробелам, фильтруем мусор
        cmd = f"grep -h 'server_name' {path_pattern} 2>/dev/null | sed 's/.*server_name\\s*\\([^;]*\\);.*/\\1/' | tr -s ' ' '\\n' | grep -v '^_' | grep -v '^$' | grep -v 'localhost' | grep -v 'default_server' | grep -v '^\\*'"
        out, _ = checker.exec_command(cmd)
        if out.strip():
            for d in out.split('\n'):
                d = d.strip()
                # Проверяем, что это похоже на домен (содержит точку и не начинается с цифры/спецсимвола)
                if d and '.' in d and not d.startswith('_') and not d.startswith('*'):
                    domains.append(d)
    
    # Убираем дубли и сортируем
    return list(set(domains))

def check_site_logs(checker, panel_type, domains):
    errors = {}
    for domain in domains:
        log_paths = []
        if panel_type == 'fastpanel':
            cmd = f"find /var/www -type f -path '*/data/logs/{domain}.error.log' 2>/dev/null"
            out, _ = checker.exec_command(cmd)
            if out.strip():
                log_paths.extend(out.strip().split('\n'))
            cmd = f"find /home -type f -path '*/logs/{domain}.error.log' 2>/dev/null"
            out, _ = checker.exec_command(cmd)
            if out.strip():
                log_paths.extend(out.strip().split('\n'))
        elif panel_type == 'ispmanager':
            # Стандартные пути ISPmanager
            cmd = f"find /var/www -type f -path '*/{domain}/data/logs/error.log' 2>/dev/null"
            out, _ = checker.exec_command(cmd)
            if out.strip():
                log_paths.extend(out.strip().split('\n'))
            cmd = f"find /var/www -type f -path '*/{domain}/logs/error.log' 2>/dev/null"
            out, _ = checker.exec_command(cmd)
            if out.strip():
                log_paths.extend(out.strip().split('\n'))
            # Новая проверка: /var/www/httpd-logs/domain.error.log
            cmd = f"test -f /var/www/httpd-logs/{domain}.error.log && echo 'exists'"
            out, _ = checker.exec_command(cmd)
            if out.strip() == 'exists':
                log_paths.append(f"/var/www/httpd-logs/{domain}.error.log")
        else:
            log_paths = [
                f'/var/log/nginx/{domain}.error.log',
                f'/var/log/apache2/{domain}-error.log',
                f'/var/log/httpd/{domain}-error_log'
            ]
        for log_file in log_paths:
            check_cmd = f'test -f {log_file} && echo "exists"'
            out, _ = checker.exec_command(check_cmd)
            if out.strip() == 'exists':
                cmd = f'tail -200 {log_file} | grep -iE "error|fail|critical|fatal|panic|warning"'
                err_out, _ = checker.exec_command(cmd)
                if err_out.strip():
                    errors[f"{domain}:{log_file}"] = err_out.strip()
    return errors

def check_web_config(checker):
    results = {}
    out, _ = checker.exec_command('nginx -t 2>&1')
    if 'nginx' in out or 'syntax is ok' in out.lower():
        results['nginx'] = out.strip()
    out, _ = checker.exec_command('apache2ctl -t 2>&1 || httpd -t 2>&1')
    if 'syntax ok' in out.lower() or 'apache' in out.lower():
        results['apache'] = out.strip()
    return results

# ----------- ФУНКЦИИ, ВОЗВРАЩАЮЩИЕ ФОРМАТИРОВАННЫЕ СТРОКИ -----------
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

# ---------- НОВЫЕ ФУНКЦИИ ДЛЯ ОТДЕЛЬНЫХ ПРОВЕРОК ----------
def disk_memory_report(checker):
    out, _ = checker.exec_command('df -h')
    df_h = out
    out, _ = checker.exec_command('df -i')
    df_i = out
    out, _ = checker.exec_command('free -m')
    free_m = out
    return f"=== ДИСКИ И ПАМЯТЬ ===\nДиски (df -h):\n{df_h}\nInodes (df -i):\n{df_i}\nПамять (free -m):\n{free_m}"

def network_report(checker):
    out_a, _ = checker.exec_command('ip a')
    out_r, _ = checker.exec_command('ip r')

    # Определяем интерфейс по умолчанию и шлюз
    default_iface = None
    default_gw = None
    for line in out_r.splitlines():
        if line.startswith('default'):
            parts = line.split()
            if len(parts) >= 5 and parts[0] == 'default' and parts[1] == 'via':
                default_gw = parts[2]
                default_iface = parts[4]  # dev
                break

    # Определяем IP-адрес, используемый для исходящего трафика
    out_get, _ = checker.exec_command(
        'ip route get 1.1.1.1 2>/dev/null | grep -oP "src \\S+" | cut -d" " -f2'
    )
    src_ip = out_get.strip()

    # Определяем внешний (плавающий) IP через публичный сервис
    out_ext, _ = checker.exec_command(
        'curl -s ifconfig.me 2>/dev/null || '
        'wget -qO- ifconfig.me 2>/dev/null || '
        'dig +short myip.opendns.com @resolver1.opendns.com 2>/dev/null'
    )
    external_ip = out_ext.strip()

    # Формируем отчёт
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

def analyze_access_log(checker, panel_type, domain, top_n=10, year=None, month=None, day=None):
    """
    Анализирует access-лог(и) указанного домена (включая ротационные .gz).
    year, month, day – опциональные числовые фильтры (если None – не фильтровать).
    Возвращает форматированную строку отчёта.
    """
    import os

    # --- 1. Находим основной файл лога, чтобы определить директорию ---
    log_path = None
    if panel_type == 'fastpanel':
        cmd = f"find /var/www -type f -path '*/data/logs/{domain}.access.log' 2>/dev/null | head -1"
        out, _ = checker.exec_command(cmd)
        if out.strip():
            log_path = out.strip()
        else:
            cmd = f"find /home -type f -path '*/logs/{domain}.access.log' 2>/dev/null | head -1"
            out, _ = checker.exec_command(cmd)
            if out.strip():
                log_path = out.strip()
    elif panel_type == 'ispmanager':
        cmd = f"find /var/www -type f -path '*/{domain}/data/logs/access.log' 2>/dev/null | head -1"
        out, _ = checker.exec_command(cmd)
        if out.strip():
            log_path = out.strip()
        else:
            cmd = f"find /var/www -type f -path '*/{domain}/logs/access.log' 2>/dev/null | head -1"
            out, _ = checker.exec_command(cmd)
            if out.strip():
                log_path = out.strip()
        if not log_path:
            cmd = f"test -f /var/www/httpd-logs/{domain}.access.log && echo 'exists'"
            out, _ = checker.exec_command(cmd)
            if out.strip() == 'exists':
                log_path = f"/var/www/httpd-logs/{domain}.access.log"
    else:
        possible_paths = [
            f'/var/log/nginx/{domain}.access.log',
            f'/var/log/apache2/{domain}-access.log',
            f'/var/log/httpd/{domain}-access_log'
        ]
        for p in possible_paths:
            out, _ = checker.exec_command(f'test -f {p} && echo "exists"')
            if out.strip() == 'exists':
                log_path = p
                break

    if not log_path:
        return f"❌ Не найден access-лог для домена {domain}"

    # --- 2. Получаем директорию и список всех access.log* файлов ---
    log_dir = os.path.dirname(log_path)
    # Ищем все файлы access.log* (включая сжатые) в этой директории
    cmd = f"ls -1 {log_dir}/{domain}.access.log* 2>/dev/null"
    out, _ = checker.exec_command(cmd)
    if not out.strip():
        return f"❌ В директории {log_dir} нет файлов access.log*"

    log_files = [f.strip() for f in out.split('\n') if f.strip()]
    # Сортируем: сначала несжатые, затем сжатые (можно по имени, но нам важен порядок)
    log_files.sort(key=lambda x: (x.endswith('.gz'), x))  # сначала .log, потом .gz

    # --- 3. Читаем все файлы и собираем статистику ---
    ip_counter = Counter()
    uri_counter = Counter()
    agent_counter = Counter()
    total_requests = 0
    unique_ips = set()
    log_pattern = re.compile(
        r'^(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] "(?P<request>[^"]*)" (?P<status>\d{3}) (?P<size>\S+) "(?P<referer>[^"]*)" "(?P<agent>[^"]*)"'
    )

    for fname in log_files:
        # Определяем команду чтения: zcat для .gz, cat для остальных
        if fname.endswith('.gz'):
            read_cmd = f"zcat {fname} 2>/dev/null"
        else:
            read_cmd = f"cat {fname} 2>/dev/null"
        out, err = checker.exec_command(read_cmd)
        if err.strip():
            continue  # пропускаем проблемные файлы
        lines = out.splitlines()
        for line in lines:
            match = log_pattern.match(line)
            if not match:
                continue
            data = match.groupdict()
            # Извлекаем дату из временной метки [dd/MMM/yyyy:hh:mm:ss +zzzz]
            time_str = data['time']
            try:
                # Парсим дату: [01/Jun/2025:12:34:56 +0000] -> извлекаем день, месяц, год
                # Делим по ':' и берём первую часть (до двоеточия)
                date_part = time_str.split(':')[0]  # "01/Jun/2025"
                # Разбиваем по '/'
                parts = date_part.split('/')
                if len(parts) == 3:
                    log_day = int(parts[0])
                    # Преобразуем месяц из трёхбуквенного в номер (Jan=1, Feb=2, ...)
                    month_names = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun',
                                   'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec']
                    try:
                        log_month = month_names.index(parts[1]) + 1
                    except ValueError:
                        log_month = None
                    log_year = int(parts[2])
                else:
                    continue
            except:
                continue

            # Фильтр по дате (если заданы)
            if year is not None and log_year != year:
                continue
            if month is not None and log_month != month:
                continue
            if day is not None and log_day != day:
                continue

            ip = data['ip']
            request = data['request']
            agent = data['agent']
            parts = request.split()
            if len(parts) >= 2:
                uri = parts[1]
            else:
                uri = request

            ip_counter[ip] += 1
            uri_counter[uri] += 1
            agent_counter[agent] += 1
            total_requests += 1
            unique_ips.add(ip)

    if total_requests == 0:
        return f"За указанный период (фильтры: год={year}, месяц={month}, день={day}) записей не найдено."

    # --- 4. Формируем отчёт ---
    lines_out = []
    lines_out.append(f"=== АНАЛИЗ ПОСЕЩЕНИЙ ДЛЯ {domain} ===")
    lines_out.append(f"Директория логов: {log_dir}")
    lines_out.append(f"Обработано файлов: {len(log_files)}")
    if year or month or day:
        filters = []
        if year: filters.append(f"год={year}")
        if month: filters.append(f"месяц={month}")
        if day: filters.append(f"день={day}")
        lines_out.append(f"Фильтр: {' '.join(filters)}")
    else:
        lines_out.append("Период: все записи")
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

def search_oom_logs(checker):
    """
    Поиск событий Out-Of-Memory в системных логах (kern.log, syslog и ротации).
    Возвращает форматированную строку отчёта.
    """
    # Ищем во всех файлах kern.log* и syslog* с контекстом ±5 строк
    cmd = "zgrep -B 5 -A 5 -i 'out of memory\\|killed process\\|oom-killer' /var/log/kern.log* /var/log/syslog* 2>/dev/null"
    out, err = checker.exec_command(cmd)
    if not out.strip():
        return "OOM-событий в логах не найдено."

    lines = out.splitlines()
    report_lines = []
    report_lines.append("=== ПОИСК OOM-СОБЫТИЙ В ЛОГАХ ===")
    report_lines.append("Файлы: /var/log/kern.log*, /var/log/syslog*")
    report_lines.append("")

    # Разбиваем вывод на блоки, разделённые "--"
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
def dns_report_local(domain):
    """
    Выполняет DNS-проверку локально (с ПК, на котором запущена программа).
    Возвращает форматированную строку с A-записями и PTR.
    NS-записи не проверяются локально (только через сервер).
    """
    import socket
    lines = []
    lines.append(f"=== ЛОКАЛЬНАЯ DNS-ПРОВЕРКА ДЛЯ {domain} ===")

    # Определяем, является ли domain IP-адресом
    import re
    ip_pattern = re.compile(r'^(\d{1,3}\.){3}\d{1,3}$')
    is_ip = bool(ip_pattern.match(domain))

    if is_ip:
        # Обратный PTR-запрос для IP
        try:
            ptr = socket.gethostbyaddr(domain)[0]
            lines.append(f"PTR (обратный DNS): {ptr}")
        except socket.herror:
            lines.append("PTR-запись не найдена.")
        except Exception as e:
            lines.append(f"Ошибка PTR-запроса: {e}")
        return "\n".join(lines)

    # A-записи (IPv4)
    try:
        a_records = socket.getaddrinfo(domain, None, socket.AF_INET)
        ips = list(set([addr[4][0] for addr in a_records]))
        if ips:
            lines.append(f"A-записи: {', '.join(ips)}")
            # PTR для первого IP
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
    """
    Выполняет DNS-проверку на сервере через dig.
    Если ip указан, делает PTR-запрос для этого IP.
    Иначе:
      - A-запись для domain
      - NS-запись для domain
      - PTR-запрос для первого полученного IP (если есть)
    Возвращает форматированную строку.
    """
    import re

    lines = []
    lines.append(f"=== DNS-ПРОВЕРКА НА СЕРВЕРЕ ДЛЯ {domain} ===")

    # Проверяем, является ли domain IP-адресом
    ip_pattern = re.compile(r'^(\d{1,3}\.){3}\d{1,3}$')
    is_ip = bool(ip_pattern.match(domain))

    if is_ip:
        # Если введён IP, делаем только PTR
        cmd = f"dig +short -x {domain} 2>/dev/null"
        out, _ = checker.exec_command(cmd)
        if out.strip():
            lines.append(f"PTR (обратный DNS): {out.strip()}")
        else:
            lines.append("PTR-запись не найдена.")
        return "\n".join(lines)

    # Если ip передан явно, используем его для PTR
    target_ip = ip
    if not target_ip:
        # Получаем A-запись для домена
        cmd = f"dig +short A {domain} 2>/dev/null"
        out, _ = checker.exec_command(cmd)
        if out.strip():
            a_records = out.splitlines()
            lines.append(f"A-записи: {', '.join(a_records)}")
            target_ip = a_records[0].strip()
        else:
            lines.append("A-записи не найдены.")

    # NS-записи
    cmd = f"dig +short NS {domain} 2>/dev/null"
    out, _ = checker.exec_command(cmd)
    if out.strip():
        lines.append(f"NS-записи: {', '.join(out.splitlines())}")
    else:
        lines.append("NS-записи не найдены.")

    # PTR-запрос, если есть IP
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
    """
    Проверяет DNS-резолверы, используемые на сервере.
    Читает /etc/resolv.conf, проверяет доступность nameserver'ов.
    Возвращает форматированную строку.
    """
    lines = []
    lines.append("=== DNS-РЕЗОЛВЕРЫ НА СЕРВЕРЕ ===")

    # Читаем /etc/resolv.conf
    out, _ = checker.exec_command('cat /etc/resolv.conf 2>/dev/null')
    if not out.strip():
        lines.append("❌ Не удалось прочитать /etc/resolv.conf")
        return "\n".join(lines)

    lines.append("Содержимое /etc/resolv.conf:\n" + out)

    # Извлекаем nameserver'ы
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

    # Проверяем каждый nameserver простым запросом к google.com
    for ns in nameservers:
        # Проверяем, отвечает ли DNS-сервер на запрос (например, dig google.com @ns +timeout=2)
        cmd = f"dig +timeout=2 +tries=1 @{ns} google.com A 2>/dev/null | grep -q 'NOERROR' && echo 'доступен' || echo 'недоступен'"
        out, _ = checker.exec_command(cmd)
        status = out.strip() if out.strip() else "недоступен"
        lines.append(f"  {ns}: {status}")

    # Определяем текущий резолвер, используемый системой
    # Можно посмотреть через systemd-resolve, если есть
    out, _ = checker.exec_command('systemd-resolve --status 2>/dev/null | grep "DNS Servers"')
    if out.strip():
        lines.append("\nТекущие DNS-серверы (systemd-resolve):")
        lines.append(out.strip())
    else:
        # fallback: проверить через resolvectl
        out, _ = checker.exec_command('resolvectl status 2>/dev/null | grep "DNS Servers"')
        if out.strip():
            lines.append("\nТекущие DNS-серверы (resolvectl):")
            lines.append(out.strip())

    return "\n".join(lines)
def get_current_dns_resolvers(checker):
    """
    Возвращает список текущих nameserver'ов, извлечённых из /etc/resolv.conf.
    """
    out, _ = checker.exec_command('grep -E "^nameserver" /etc/resolv.conf 2>/dev/null | awk \'{print $2}\'')
    if out.strip():
        return [ns.strip() for ns in out.splitlines() if ns.strip()]
    return []

def set_dns_resolvers(checker, nameservers):
    """
    Устанавливает новые DNS-резолверы для всех интерфейсов (кроме lo) через resolvectl.
    Если resolvectl не активен, редактирует /etc/resolv.conf.
    nameservers – список IP-адресов.
    Возвращает строку с результатом операции.
    """
    import re
    lines = []
    lines.append("=== ИЗМЕНЕНИЕ DNS-РЕЗОЛВЕРОВ ===")

    # Проверяем, есть ли systemd-resolved
    out, _ = checker.exec_command('systemctl is-active systemd-resolved 2>/dev/null')
    if out.strip() == 'active':
        lines.append("Обнаружен systemd-resolved. Используем resolvectl для всех интерфейсов.")

        # Получаем список всех интерфейсов (кроме lo)
        cmd_iface = "ip -o link show | awk -F': ' '{print $2}' | grep -v lo"
        out_ifaces, _ = checker.exec_command(cmd_iface)
        interfaces = [iface.strip() for iface in out_ifaces.splitlines() if iface.strip()]

        if not interfaces:
            lines.append("Не найдены интерфейсы для настройки DNS.")
            return "\n".join(lines)

        # Сначала сбрасываем DNS для всех интерфейсов (чтобы удалить старые)
        for iface in interfaces:
            checker.exec_command(f'resolvectl dns {iface} "" 2>/dev/null')
            lines.append(f"Сброшены DNS для {iface}.")

        # Устанавливаем новые DNS для каждого интерфейса
        for iface in interfaces:
            # Команда: resolvectl dns <iface> <ip1> <ip2> ...
            cmd = f'resolvectl dns {iface} ' + ' '.join(nameservers)
            out, err = checker.exec_command(cmd + ' 2>&1')
            if err.strip() and 'error' in err.lower():
                lines.append(f"❌ Ошибка установки DNS для {iface}: {err.strip()}")
            else:
                lines.append(f"✅ DNS установлены для {iface}: {', '.join(nameservers)}")

        # Проверяем текущие DNS
        out_check, _ = checker.exec_command('resolvectl dns')
        lines.append("\nТекущие DNS (resolvectl):\n" + out_check)

        # Также можно установить глобальные (на случай, если интерфейсы не указаны)
        checker.exec_command('resolvectl dns ' + ' '.join(nameservers) + ' 2>/dev/null')
        return "\n".join(lines)

    # Если resolvectl не активен, редактируем /etc/resolv.conf напрямую
    lines.append("systemd-resolved не активен. Редактируем /etc/resolv.conf напрямую (создаём резервную копию).")
    checker.exec_command('cp /etc/resolv.conf /etc/resolv.conf.bak.$(date +%Y%m%d%H%M%S)')
    new_content = "# Generated by SSH Diagnostic Tool\n"
    for ns in nameservers:
        if re.match(r'^(\d{1,3}\.){3}\d{1,3}$', ns):
            new_content += f"nameserver {ns}\n"
        else:
            lines.append(f"⚠️ IP-адрес {ns} пропущен (некорректный формат).")
    cmd = f'echo "{new_content}" > /etc/resolv.conf'
    out, err = checker.exec_command(cmd + ' 2>&1')
    if err.strip():
        lines.append(f"❌ Ошибка записи: {err.strip()}")
    else:
        lines.append("✅ /etc/resolv.conf обновлён.")
        out_check, _ = checker.exec_command('cat /etc/resolv.conf')
        lines.append("\nНовое содержимое:\n" + out_check)
    return "\n".join(lines)