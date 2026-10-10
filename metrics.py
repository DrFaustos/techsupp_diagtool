"""Определение панели, системные метрики и базовые отчёты."""
from common import LOG_PATHS, DOMAIN_PATHS, get_domain_from_config, q


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


# ==================== СЛУЖБЫ: СТАТУСЫ ====================
# Список проверяемых служб. php-fpm перечислен и как общий unit-шаблон,
# и с версиями, которые ставят панели (FastPanel/ISPmanager).
SERVICES_TO_CHECK = [
    'nginx', 'apache2', 'httpd',
    'php-fpm', 'php7.4-fpm', 'php8.0-fpm', 'php8.1-fpm', 'php8.2-fpm', 'php8.3-fpm',
    'mysql', 'mariadb',
]


def services_status_cmd(services=None):
    """Shell-команда, печатающая строку 'имя=статус' для каждой службы.

    Почему так, а не `systemctl is-active NAME || echo "inactive"`:
    `systemctl is-active` пишет статус в stdout даже когда служба не активна
    (rc != 0), поэтому `|| echo "inactive"` добавлял ВТОРУЮ строку. Список
    строк становился длиннее списка имён, и статусы съезжали: nginx мог
    показать статус apache2 и т.д. Формат 'имя=статус' делает рассинхрон
    невозможным — имя едет вместе со своим статусом.
    """
    services = services if services is not None else SERVICES_TO_CHECK
    args = ' '.join(q(s) for s in services)
    return (
        '__svc_status() { st=$(systemctl is-active "$1" 2>/dev/null); '
        '[ -n "$st" ] || st=unknown; '
        "printf '%s=%s\\n' \"$1\" \"$st\"; }; "
        f'for __s in {args}; do __svc_status "$__s"; done'
    )


def parse_service_statuses(out):
    """Разбирает вывод 'имя=статус' в dict. Чистая функция (тесты без SSH).

    Пустой вывод (система без systemd / systemctl недоступен) -> {}.
    """
    statuses = {}
    for line in (out or '').splitlines():
        line = line.strip()
        if not line or '=' not in line:
            continue
        name, status = line.split('=', 1)
        name = name.strip()
        if name:
            statuses[name] = status.strip() or 'unknown'
    return statuses


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

    out, _ = checker.exec_command(services_status_cmd())
    metrics['services'] = parse_service_statuses(out)

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
def metrics_report(checker, metrics=None):
    # metrics — уже собранный get_metrics() словарь: сводный отчёт
    # (reports.full_diagnostic_report) собирает метрики один раз и отдаёт их
    # сюда и в firewall_report, а не по разу на каждый этап.
    if metrics is None:
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


def firewall_report(checker, metrics=None):
    if metrics is None:
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
