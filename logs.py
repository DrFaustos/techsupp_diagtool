"""Поиск и анализ логов, определение доменов, поиск OOM."""
import re
from collections import Counter

from common import DOMAIN_PATHS, q, find_files, read_file_content, get_domain_from_config
from metrics import detect_panel  # noqa: F401 (реэкспорт для удобства)


# ==================== ПОИСК ЛОГОВ ====================
def find_logs(checker, panel_type, domain, log_type='error'):
    """Находит логи для домена (унифицированная функция)"""
    log_files = []
    limit = 20
    safe_domain = domain.replace('/', '').replace('..', '').replace('*', '').replace('?', '')

    if panel_type == 'fastpanel':
        patterns = [
            f'/var/www/*/data/logs/*{safe_domain}*.{log_type}.log',
            f'/home/*/logs/*{safe_domain}*.{log_type}.log'
        ]
        for pattern in patterns:
            log_files.extend(find_files(checker, pattern, limit))
    elif panel_type == 'ispmanager':
        patterns = [
            f'/var/www/*/{safe_domain}/data/logs/{log_type}.log',
            f'/var/www/*/{safe_domain}/logs/{log_type}.log',
            f'/var/www/httpd-logs/{safe_domain}.{log_type}.log'
        ]
        for pattern in patterns:
            log_files.extend(find_files(checker, pattern, limit))
    else:
        patterns = [
            f'/var/log/nginx/{safe_domain}.{log_type}.log',
            f'/var/log/apache2/{safe_domain}-{log_type}.log',
            f'/var/log/httpd/{safe_domain}-{log_type}_log'
        ]
        for pattern in patterns:
            log_files.extend(find_files(checker, pattern, limit))

    return list(set(log_files))


def parse_access_log_line(line):
    """Парсит строку access-лога (combined/common log format)"""
    pattern = re.compile(
        r'^(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] "(?P<request>[^"]*)" (?P<status>\d{3}) (?P<size>\S+)(?: "(?P<referer>[^"]*)" "(?P<agent>[^"]*)")?'
    )
    match = pattern.match(line)
    if not match:
        return None
    data = match.groupdict()
    data['referer'] = data.get('referer') or '-'
    data['agent'] = data.get('agent') or '-'
    return data


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
    except (ValueError, IndexError):
        return False
    return False


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
        if log_file.endswith('.gz'):
            content, _ = checker.exec_command(f'zcat {q(log_file)} 2>/dev/null')
        else:
            content = read_file_content(checker, log_file)
        if not content:
            continue

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
                        errors.setdefault(domain, []).append(f"{log_file}: {line.strip()}")

    result = {}
    for domain, err_lines in errors.items():
        if err_lines:
            result[domain] = '\n'.join(err_lines[:10])
    return result


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


# ==================== ПОИСК OOM ====================
def search_oom_logs(checker):
    """Поиск событий Out-Of-Memory в системных логах"""
    cmd = "zgrep -B 5 -A 5 -i 'out of memory\\|killed process\\|oom-killer' /var/log/kern.log* /var/log/syslog* 2>/dev/null"
    out, err = checker.exec_command(cmd)
    if not out.strip():
        return "OOM-событий в логах не найдено."
    lines = out.splitlines()
    report_lines = ["=== ПОИСК OOM-СОБЫТИЙ В ЛОГАХ ===", "Файлы: /var/log/kern.log*, /var/log/syslog*", ""]
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
