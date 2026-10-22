"""Дополнительные проверки: SSL-сертификаты, WHOIS, порты, массовый grep по логам."""
import re

from common import q
from discovery import (CERT_STATE_ICON, cert_days_label, cert_state,
                       parse_cert_days)
from logs import find_logs, get_domains


def ssl_cert_days_cmd(domain, port=443):
    """Одна сетевая команда: данные сертификата + остаток в днях на сервере.

    Не было второго хендшейка: срок проверялся ОТДЕЛЬНОЙ командой
    (`openssl x509 -checkend 0`), а её код возврата был выброшен — `timeout`,
    отсутствие openssl или разорванное соединение давали пустой вывод, «VALID»
    в нём не было, и отчёт печатал «❌ Сертификат ИСТЁК». Ложная беда дороже
    честного «не видно»: оператор ехал перевыпускать сертификат.

    `notAfter` уже лежит в выводе `-dates`, поэтому остаток добирается локальной
    `date` на сервере, а не новым сетевым запросом. Дни считаем ИМЕННО там: дата
    машины оператора к выпуску сертификата отношения не имеет (то же правило,
    что в `discovery.site_status_command`). Не удалось посчитать — `CERT=none`,
    и это «не определено», а не «истёк».

    Проверка `[ -n "$END" ]` обязательна и это не перестраховка: пустая строка
    для GNU `date -d` — НЕ ошибка, а «сейчас» (rc=0). Без guard'а закрытый порт
    (не `notAfter`, пустая `END`) давал `CERT=0`, то есть «⚠️ SSL осталось 0 дн.»
    про сертификат, которого там нет, — ту самую ложь, ради которой правка.
    """
    d = q(domain)
    return (
        f'''CERT=$(echo | timeout 10 openssl s_client -servername {d}'''
        f''' -connect {d}:{int(port)} 2>/dev/null'''
        f''' | openssl x509 -noout -subject -issuer -dates'''
        f''' -ext subjectAltName 2>/dev/null); '''
        f'''printf '%s\n' "$CERT"; '''
        f'''END=$(printf '%s\n' "$CERT" | sed -n 's/^notAfter=//p'); '''
        f'''if [ -n "$END" ]; then EPOCH=$(date -d "$END" +%s 2>/dev/null); fi; '''
        f'''NOW=$(date +%s); '''
        f'''if [ -z "$EPOCH" ]; then printf 'CERT=none\n'; '''
        f'''else printf 'CERT=%s\n' "$(( (EPOCH - NOW) / 86400 ))"; fi'''
    )


def ssl_cert_report(checker, domain, port=443):
    """Проверяет SSL-сертификат домена: срок действия, эмитент, SAN."""
    lines = [f"=== SSL-СЕРТИФИКАТ ДЛЯ {domain}:{port} ==="]
    if not domain:
        lines.append("❌ Домен не задан")
        return "\n".join(lines)

    out, _, _ = checker.run(ssl_cert_days_cmd(domain, port))
    # CERT= — служебная строка НАШЕЙ команды: к сертификату она отношения не
    # имеет, и в «сыром выводе openssl» оператор принял бы её за его поле.
    # Отфильтровываем ДО решения «получены ли данные»: иначе наша же строка
    # CERT=... выглядела бы как ответ сервера и «не удалось получить» бы
    # промолчало, уступив место вердикту о сроке несуществующего сертификата.
    data = '\n'.join(l for l in out.splitlines()
                     if not l.startswith('CERT=')).strip()
    if not data:
        # «Не получили ответ» ≠ «сертификат истёк» — ровно тот же закон, что
        # заперт для dig и для почтового лога.
        lines.append("❌ Не удалось получить сертификат (порт закрыт, нет "
                     "openssl или домен недоступен): это «не проверено», "
                     "а не «истёк».")
        return "\n".join(lines)

    lines.append(data)

    days = parse_cert_days(out)
    if days is None:
        # Сертификат в руках, а срок посчитать не удалось (не GNU date, редкий
        # формат notAfter). Ни зелёного, ни красного: любое из них было бы
        # догадкой, а догадка про сертификат стоит оператору вечера работы.
        lines.append("❓ SSL срок действия не определён: сервер не посчитал "
                     "остаток по notAfter (проверьте GNU date). Проверьте срок "
                     "вручную — командой ниже.")
    else:
        # Подпись — та же, что в сводке доступности и в «Досье домена»
        # (discovery.cert_days_label): две формулировки одной беды однажды
        # разъехались бы, и оператор не узнал бы свою беду в другом отчёте.
        lines.append(f"{CERT_STATE_ICON[cert_state(days)]} SSL "
                     f"{cert_days_label(days)}")
    return "\n".join(lines)


def whois_report(checker, domain):
    """WHOIS-запрос для домена: даты, NS, регистратор."""
    lines = [f"=== WHOIS ДЛЯ {domain} ==="]
    if not domain:
        lines.append("❌ Домен не задан")
        return "\n".join(lines)

    out, _, rc = checker.run(f"timeout 15 whois {q(domain)} 2>/dev/null")
    if not out.strip():
        lines.append("❌ whois не установлен или домен не найден")
        return "\n".join(lines)

    keys = ('registrar:', 'creation date:', 'created:', 'updated date:',
            'expiry date:', 'expiration date:', 'registry expiry date:',
            'registrant organization:', 'name server:', 'nserver:', 'status:')
    found = []
    for line in out.splitlines():
        low = line.strip().lower()
        if any(low.startswith(k) for k in keys):
            found.append(line.strip())
    if found:
        lines.extend(found)
    else:
        lines.append(out.strip()[:2000])
    return "\n".join(lines)


def port_scan_report(checker, host=None):
    """Сканирование слушающих портов + проверка типовых портов (аналог nmap -T4)."""
    lines = ["=== СКАНИРОВАНИЕ ПОРТОВ ==="]
    out, _, _ = checker.run('ss -tulpn 2>/dev/null || netstat -tulpn 2>/dev/null')
    if out.strip():
        lines.append("Слушающие порты (ss/netstat):")
        lines.append(out.strip())
    else:
        lines.append("(ss/netstat недоступны)")

    # Быстрая проверка типовых открытых портов извне (connect через /dev/tcp)
    common_ports = [21, 22, 25, 53, 80, 110, 143, 443, 465, 587, 993, 995,
                    3306, 5432, 6379, 8080, 8443, 27017]
    target = host or "127.0.0.1"
    checks = "; ".join(
        f"timeout 1 bash -c '</dev/tcp/{target}/{p}' 2>/dev/null && echo '  {p} открыт'"
        for p in common_ports
    )
    out2, _, _ = checker.run(checks + " 2>/dev/null")
    lines.append(f"\nТиповые порты на {target}:")
    lines.append(out2.strip() if out2.strip() else "  (ни один из типовых портов не ответил)")
    return "\n".join(lines)


def grep_logs_report(checker, panel_type, domain, pattern, context=0, limit=200):
    """Массовый grep по логам домена (например, все 5xx или 404)."""
    lines = [f"=== GREP ЛОГОВ: {domain} / '{pattern}' ==="]
    log_files = find_logs(checker, panel_type, domain, 'access')
    log_files += find_logs(checker, panel_type, domain, 'error')
    log_files = [f for f in log_files if not f.startswith('⚠️')]
    if not log_files:
        lines.append("❌ Логи для домена не найдены")
        return "\n".join(lines)

    ctx = f"-C {int(context)} " if context else ""
    total = 0
    for lf in log_files:
        if lf.endswith('.gz'):
            base = f"zcat {q(lf)}"
        else:
            base = f"cat {q(lf)}"
        cmd = f"{base} 2>/dev/null | grep {ctx}-E {q(pattern)} | tail -n {int(limit)}"
        out, _, _ = checker.run(cmd)
        if out.strip():
            lines.append(f"\n--- {lf} ---")
            lines.append(out.strip())
            total += len(out.strip().splitlines())
    if total == 0:
        lines.append("Совпадений не найдено.")
    else:
        lines.append(f"\nВсего строк: {total}")
    return "\n".join(lines)


def list_common_reports(checker, panel_type, domain):
    """Набор частых отчётов: 5xx, 404, топ IP."""
    lines = []
    lines.append(grep_logs_report(checker, panel_type, domain, r'" 5[0-9][0-9] ', limit=100))
    lines.append("\n" + grep_logs_report(checker, panel_type, domain, r'" 404 ', limit=100))
    return "\n".join(lines)
