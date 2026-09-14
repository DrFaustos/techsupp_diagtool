"""Определение панели, системные метрики и базовые отчёты."""
from common import LOG_PATHS, DOMAIN_PATHS, get_domain_from_config


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
