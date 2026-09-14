"""DNS-функции: проверка записей, работа с резолверами."""
import re

from common import q, create_backup, write_remote_file


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
        cmd = f"dig +short -x {q(domain)} 2>/dev/null"
        out, _ = checker.exec_command(cmd)
        if out.strip():
            lines.append(f"PTR (обратный DNS): {out.strip()}")
        else:
            lines.append("PTR-запись не найдена.")
        return "\n".join(lines)

    target_ip = ip
    if not target_ip:
        cmd = f"dig +short A {q(domain)} 2>/dev/null"
        out, _ = checker.exec_command(cmd)
        if out.strip():
            a_records = out.splitlines()
            lines.append(f"A-записи: {', '.join(a_records)}")
            target_ip = a_records[0].strip()
        else:
            lines.append("A-записи не найдены.")

    cmd = f"dig +short NS {q(domain)} 2>/dev/null"
    out, _ = checker.exec_command(cmd)
    if out.strip():
        lines.append(f"NS-записи: {', '.join(out.splitlines())}")
    else:
        lines.append("NS-записи не найдены.")

    if target_ip:
        cmd = f"dig +short -x {q(target_ip)} 2>/dev/null"
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
        cmd = f"dig +timeout=2 +tries=1 @{q(ns)} google.com A 2>/dev/null | grep -q 'NOERROR' && echo 'доступен' || echo 'недоступен'"
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

    valid_ns = []
    for ns in nameservers:
        ns = ns.strip()
        if re.match(r'^(\d{1,3}\.){3}\d{1,3}$', ns) or re.match(r'^[0-9a-fA-F:]+$', ns):
            valid_ns.append(ns)
    if not valid_ns:
        lines.append("❌ Не передано ни одного корректного DNS-адреса.")
        return "\n".join(lines)

    out, _ = checker.exec_command('systemctl is-active systemd-resolved 2>/dev/null')
    if out.strip() != 'active':
        lines.append("systemd-resolved не активен. Редактируем /etc/resolv.conf напрямую.")
        backup_path = create_backup(checker, '/etc/resolv.conf', 'dns')
        if backup_path:
            lines.append(f"✅ Резервная копия создана: {backup_path}")
        else:
            lines.append("⚠️ Не удалось создать резервную копию /etc/resolv.conf")

        new_content = "# Generated by SSH Diagnostic Tool\n"
        for ns in valid_ns:
            new_content += f"nameserver {ns}\n"

        ok, err = write_remote_file(checker, '/etc/resolv.conf', new_content)
        if not ok:
            lines.append(f"❌ Ошибка записи: {err}")
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
            new_conf_lines.append(f'DNS={" ".join(valid_ns)}')
            dns_found = True
        else:
            new_conf_lines.append(line)
    if not dns_found:
        resolved_section = False
        for i, line in enumerate(new_conf_lines):
            if re.match(r'^\s*\[Resolve\]\s*$', line):
                resolved_section = True
                new_conf_lines.insert(i + 1, f'DNS={" ".join(valid_ns)}')
                break
        if not resolved_section:
            new_conf_lines.append('[Resolve]')
            new_conf_lines.append(f'DNS={" ".join(valid_ns)}')
    new_content = '\n'.join(new_conf_lines) + '\n'

    ok, err = write_remote_file(checker, '/etc/systemd/resolved.conf', new_content)
    if not ok:
        lines.append(f"❌ Ошибка записи resolved.conf: {err}")
    else:
        lines.append("✅ /etc/systemd/resolved.conf обновлён.")

    out_ifaces, _ = checker.exec_command("ip -o link show | awk -F': ' '{print $2}' | grep -v lo")
    interfaces = [iface.strip() for iface in out_ifaces.splitlines() if iface.strip()]
    for iface in interfaces:
        checker.exec_command(f'resolvectl dns {q(iface)} "" 2>/dev/null')
        cmd = 'resolvectl dns ' + q(iface) + ' ' + ' '.join(q(ns) for ns in valid_ns)
        out, err = checker.exec_command(cmd + ' 2>&1')
        if err.strip() and 'error' in err.lower():
            lines.append(f"❌ Ошибка для {iface}: {err.strip()}")
        else:
            lines.append(f"✅ DNS для {iface}: {', '.join(valid_ns)}")

    checker.exec_command('systemctl restart systemd-resolved 2>/dev/null')
    lines.append("Перезапущен systemd-resolved.")

    out_check, _ = checker.exec_command('resolvectl status | grep -E "Global|DNS Servers"')
    lines.append("\nТекущие DNS (resolvectl):\n" + (out_check if out_check.strip() else "нет данных"))
    out_resolv, _ = checker.exec_command('cat /etc/resolv.conf')
    lines.append("\nСодержимое /etc/resolv.conf:\n" + out_resolv)
    return "\n".join(lines)
