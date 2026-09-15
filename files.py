"""Работа с файлами/конфигами, замена IP, перезапуск служб."""
import ipaddress
from datetime import datetime

from common import BACKUP_SUBDIRS, q, ensure_backup_dir, create_backup, write_remote_file


# ==================== РАБОТА С ФАЙЛАМИ (С БЭКАПАМИ) ====================
def write_file(checker, filepath, content):
    """Записывает содержимое в файл с созданием резервной копии (через SFTP)."""
    lines = []
    lines.append(f"=== СОХРАНЕНИЕ ФАЙЛА: {filepath} ===")

    backup_path = create_backup(checker, filepath, 'configs')
    if backup_path:
        lines.append(f"✅ Резервная копия создана: {backup_path}")
    else:
        lines.append("⚠️ Не удалось создать резервную копию файла")

    ok, err = write_remote_file(checker, filepath, content)
    if not ok:
        lines.append(f"❌ Ошибка записи: {err}")
        return "\n".join(lines)

    lines.append("✅ Файл сохранён.")
    return "\n".join(lines)


def read_file(checker, filepath):
    out, err, rc = checker.run(f'cat {q(filepath)} 2>/dev/null')
    if rc != 0:
        return f"❌ Ошибка чтения файла (rc={rc}): {err.strip()}"
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
        out, _ = checker.exec_command(f'ls -d {q(path)} 2>/dev/null && echo "exists"')
        if out.strip() == 'exists':
            out2, _ = checker.exec_command(f'ls -1 {q(path)} 2>/dev/null | head -20')
            if out2.strip():
                for f in out2.splitlines():
                    if f.strip():
                        files.append(f"{path}{f}" if path.endswith('/') else path)
            else:
                files.append(path)
    if panel_type in panel_paths:
        for path in panel_paths[panel_type]:
            out, _ = checker.exec_command(f'ls -d {q(path)} 2>/dev/null && echo "exists"')
            if out.strip() == 'exists':
                out2, _ = checker.exec_command(f'find {q(path)} -type f -name "*.conf" 2>/dev/null | head -20')
                if out2.strip():
                    for f in out2.splitlines():
                        if f.strip():
                            files.append(f)
    return sorted(list(set(files)))[:50]


# ==================== ЗАМЕНА IP ====================
def _valid_ipv4(value):
    try:
        ipaddress.IPv4Address(value)
        return True
    except (ipaddress.AddressValueError, ValueError):
        return False


def _valid_ipv6(value):
    try:
        ipaddress.IPv6Address(value)
        return True
    except (ipaddress.AddressValueError, ValueError):
        return False


def replace_ipv4(checker, old_ip, new_ip):
    """Замена старого IPv4 на новый во всех *.conf в /etc (как в ручной команде)."""
    lines = [f"=== ЗАМЕНА IPv4: {old_ip} -> {new_ip} ==="]
    if not (_valid_ipv4(old_ip) and _valid_ipv4(new_ip)):
        lines.append("❌ Некорректный IPv4-адрес — операция отменена.")
        return "\n".join(lines)
    # Экранируем точки, как в исходной команде: s#123\.123\.123\.123#...#g
    old_escaped = old_ip.replace('.', '\\.')
    new_escaped = new_ip.replace('.', '\\.')
    cmd = (
        f"find /etc -type f -name \"*.conf\" "
        f"-exec sed -i -e 's#{old_escaped}#{new_escaped}#g' '{{}}' \\;"
    )
    out, err, rc = checker.run(cmd)
    if rc != 0:
        lines.append(f"⚠️ Возможны ошибки (rc={rc}): {err.strip() or out.strip()}")
    lines.append("✅ IPv4 заменён во всех .conf-файлах в /etc.")
    lines.append("")
    lines.append("=== ПРОВЕРКА КОНФИГУРАЦИИ NGINX ===")
    out_nginx, _ = checker.exec_command('nginx -t 2>&1')
    lines.append(out_nginx.strip() if out_nginx.strip() else "(вывод пуст)")
    lines.append("")
    lines.append("=== SYSTEMD DAEMON-RELOAD ===")
    _, _, drc = checker.run('systemctl daemon-reload 2>&1')
    lines.append("✅ daemon-reload выполнен" if drc == 0 else f"⚠️ daemon-reload вернул rc={drc}")
    lines.extend(restart_services(checker))
    return "\n".join(lines)


def replace_ipv6(checker, old_ip, new_ip):
    """Замена старого IPv6 на новый во всех файлах в /etc (как в ручной команде).

    old_ip/new_ip строго валидируются как IPv6 — это исключает инъекцию команд,
    поскольку в shell подставляются только проверенные [0-9a-fA-F:].
    """
    lines = [f"=== ЗАМЕНА IPv6: {old_ip} -> {new_ip} ==="]
    if not (_valid_ipv6(old_ip) and _valid_ipv6(new_ip)):
        lines.append("❌ Некорректный IPv6-адрес — операция отменена.")
        return "\n".join(lines)

    # Автобэкап /etc перед массовой заменой (сама команда замены не меняется)
    ensure_backup_dir(checker)
    ts = datetime.now().strftime('%Y%m%d_%H%M%S')
    etc_backup = f"{BACKUP_SUBDIRS['configs']}/etc_{ts}.tar.gz"
    _, _, brc = checker.run(f"tar czf {q(etc_backup)} /etc 2>/dev/null")
    if brc == 0:
        lines.append(f"✅ Резервная копия /etc создана: {etc_backup}")
    else:
        lines.append("⚠️ Не удалось создать резервную копию /etc (продолжаем)")

    # old_ip/new_ip прошли строгую проверку IPv6Address -> метасимволы невозможны.
    cmd = f"find /etc -type f -exec sed -i 's/{old_ip}/{new_ip}/g' {{}} +"
    out, err, rc = checker.run(cmd)
    if rc != 0:
        lines.append(f"⚠️ Возможны ошибки (rc={rc}): {err.strip() or out.strip()}")
    lines.append("✅ IPv6 заменён во всех файлах в /etc.")
    lines.append("")
    lines.append("=== ПРОВЕРКА КОНФИГУРАЦИИ NGINX ===")
    out_nginx, _ = checker.exec_command('nginx -t 2>&1')
    lines.append(out_nginx.strip() if out_nginx.strip() else "(вывод пуст)")
    lines.append("")
    lines.append("=== SYSTEMD DAEMON-RELOAD ===")
    _, _, drc = checker.run('systemctl daemon-reload 2>&1')
    lines.append("✅ daemon-reload выполнен" if drc == 0 else f"⚠️ daemon-reload вернул rc={drc}")
    lines.extend(restart_services(checker))
    return "\n".join(lines)


# ==================== ПЕРЕЗАПУСК СЛУЖБ ====================
def restart_services(checker):
    lines = ["\n=== ПЕРЕЗАПУСК / ПЕРЕЗАГРУЗКА СЛУЖБ ==="]
    services = {
        'nginx': 'reload',
        'mysql': 'restart',
        'apache2': 'reload'
    }
    for svc, action in services.items():
        out, _, _ = checker.run(f'systemctl list-unit-files | grep -q "^{svc}.service" && echo "yes" || echo "no"')
        if out.strip() == 'yes':
            _, _, arc = checker.run(f'systemctl {action} {svc} 2>/dev/null')
            status, _, _ = checker.run(f'systemctl is-active {svc} 2>/dev/null')
            if status.strip() == 'active':
                lines.append(f"✅ {svc} ({action}) выполнен")
            else:
                _, _, rrc = checker.run(f'systemctl restart {svc} 2>/dev/null')
                status2, _, _ = checker.run(f'systemctl is-active {svc} 2>/dev/null')
                if status2.strip() == 'active':
                    lines.append(f"✅ {svc} перезапущен (fallback)")
                else:
                    lines.append(f"❌ {svc} не запустился (rc={rrc}, reload rc={arc})")
        else:
            lines.append(f"⏭️ {svc} не установлен")
    return lines
