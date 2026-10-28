"""DNS-функции: проверка записей, работа с резолверами."""
import re
import socket

from common import (q, create_backup, write_remote_file, read_file_info,
                    # Состояние резолвера спрашивает ОДНА функция
                    # (1.32.6-1.32.7): пустой stdout systemctl —
                    # «система не ответила», а не «не активно», и
                    # решать по нему нельзя нигде и ни в какой
                    # форме, здесь особенно: ветка пишет файл.
                    unit_status_info,
                    resolver_probe_info)

# Пути объявлены константами, а не вшиты в строки: вопрос к файлу (чтение)
# и ответ в него (запись) обязаны называть ОДНО значение. В прежнем коде
# «/etc/resolv.conf» был написан пять раз: правка одного места разъезжалась с остальными
# с остальными (тот же закон, что привёл к FSTAB_PATH в 1.32.22).
RESOLV_CONF = '/etc/resolv.conf'
RESOLVED_CONF = '/etc/systemd/resolved.conf'

# Отказ чтения называется ОДНОЙ строкой во всех трёх точках: оператор читает
# один диагноз, где бы он ни возник. Слово «не прочитан» — не «не найден» и
# не «пуст»: причину называет носитель (RF_TEXT), поэтому здесь нет ни одной
# выдуманной формулировки (закон серии: отчёт обязан называть источник).
READ_GAP = '❌ {path} не прочитан: {reason}. Это НЕ «резолверов нет».'


def _nameservers_from_text(text):
    """Резолверы из содержимого resolv.conf — ОДИН парсер для отчёта и диалога.

    Прежний код считывал одно и то же два раза разными способами: отчёт
    разбирал строки python'ом (`startswith('nameserver')`), а диалог — пайпом
    `grep -E "^nameserver" | awk`. Два парсера на один признак однажды
    разъезжаются, и оператор видит в отчёте один список, а в диалоге другой.

    Комментированная строка не резолвер: `# nameserver 9.9.9.9` — это не
    работающий сервер, и прежний `grep -E "^nameserver"` её отбрасывал только
    потому, что якорь `^` не пропускал '#'; здесь это сказано явно.
    """
    found = []
    for line in (text or '').splitlines():
        line = line.strip()
        if not line.startswith('nameserver'):
            continue
        parts = line.split()
        if len(parts) >= 2:
            found.append(parts[1])
    return found


# ==================== ОДИН ВОПРОС dig (1.32.24) ====================
# Прежний вид спрашивал dig через exec_command: по контракту он отдаёт только
# stdout и stderr (exit_status выбрасывается внутри SSH-клиента, ssh_client.py
# строка 127), и решал по пустоте stdout — if out.strip(). Замер живьём (этот
# хост, dig 9.18) дал пять миров, ДВА из которых прежний отчёт печатал как
# НАЙДЕННЫЕ ЗАПИСИ:
#
#   резолвер не отвечает    rc=9   stdout НЕПУСТОЙ: ';; communications error to
#                             127.0.0.1#53: connection refused' — боевой отчёт
#                             выдавал «A-записи: ;; communications error ...»,
#                             то есть строку ошибки резолвера за адрес хоста
#                             (решающий мир слайса)
#   ответ непригоден        rc=0   stdout ';; Warning: Message parser reports
#                             malformed message packet.' — та же подмена;
#                             «не найдены» по такому выводу было бы второй
#                             ложью: сервер не говорил, что записей нет. Снято
#                             собственным DNS-сервером на rcode=3 и rcode=2
#   бинарника dig нет       rc=127 stdout пуст, stderr 'command not found' —
#                             прежний код подписывал это «не найдены»: диагноз
#                             домену там, где спрашивать было не чем
#   живой сервер, записей нет rc=0 stdout пуст — единственное честное
#                             «не найдены» (замер: NXDOMAIN приходит при rc=0)
#   живой сервер с записью  rc=0   stdout '93.184.216.34' — записи
#
# Отдельно: '2>/dev/null' глушил единственный канал с причиной, а конвейер
# отдал бы код возврата последней команде (урок серии про пайпы). Поэтому
# вопрос задаёт ОДНА функция без пайпа и без заглушек, а решение принимает
# парсер по (out, err, rc).
DIG_UNCHECKED_NOTE = ('⚠️ {label}: не проверено — {why}. Это «мы не спросили», '
                      'а не «записей нет»: проверьте, что dig установлен '
                      'на хосте')


def dig_records_cmd(rtype, target):
    """Одна POSIX-команда: записи типа rtype для target в форме +short.

    Без `2>/dev/null`, без `2>&1` и без конвейера: код возврата обязан
    принадлежать dig, а stderr — доехать до парсера причиной отказа. Ни `&&`,
    ни `||`: решение принимает парсер по фактам, а не оболочка по умолчанию.

    Тип записи (A, NS, -x) идёт без кавычек: это литерал программы, а не ввод
    оператора, и кавычка сломала бы саму форму «+short A». Домен и адрес
    экранируются q(): без этого домен вида «example.com; rm -rf /» стал бы
    второй командой (замок test_domain_is_shell_quoted).
    """
    return 'dig +short ' + rtype + ' ' + q(target)


def parse_dig_records(out, err, rc):
    """('records'|'none'|'fail'|'unchecked', записи, признание или None).

    Различает четыре состояния, а не «пусто / непусто»:

      records   — rc=0 и в stdout есть содержательные строки;
      none      — rc=0, содержательных строк нет и оба канала чисты: сервер
                  ответил, записей нет (замер: NXDOMAIN приходит при rc=0);
      fail      — отказ ОТВЕТИВШЕЙ стороны: rc != 0 с текстом причины либо
                  rc=0 с непригодным выводом (служебные строки «;; Warning»);
      unchecked — rc=127: спрашивать было не чем. По этому состоянию диагноз
                  не печатается (закон 1.32.10) и лечивающее действие по нему
                  не совершается.

    Отсечение префикса «;;» обязательно: это служебные строки dig, а не
    записи. Замер показал, что при битом пакете warning едет именно в stdout
    при rc=0, поэтому «rc=0 и stdout непустой» НЕ означает «есть запись».
    """
    def first(text):
        lines = [ln.strip() for ln in (text or '').splitlines() if ln.strip()]
        return lines[0][:200] if lines else ''

    if rc == 127:
        return 'unchecked', [], (first(err) or 'dig не найден (rc=127)')
    if rc != 0:
        return ('fail', [],
                first(err) or first(out) or ('dig не выполнен (rc=%s)' % rc))
    body, junk = [], []
    for line in (out or '').splitlines():
        line = line.strip()
        if not line:
            continue
        (junk if line.startswith(';;') else body).append(line)
    if body:
        return 'records', body, None
    why = first(err) or (junk[0] if junk else '')
    if why:
        return ('fail', [],
                (why[:200] + ': сервер не дал внятного ответа (rc=0)'))
    return 'none', [], None


def dig_records_info(checker, rtype, target):
    """Записи dig с СИЛОЙ ответа: {rtype, target, state, records, why, checked}.

    checked=False — система ничего не ответила: вызывающий обязан сказать
    «не проверено», а не «не найдено».
    """
    out, err, rc = checker.run(dig_records_cmd(rtype, target))
    state, records, why = parse_dig_records(out, err, rc)
    return {'rtype': rtype, 'target': target, 'state': state,
            'records': records, 'why': why, 'checked': state != 'unchecked'}


def _dig_lines(info, label, none_line):
    """Строки отчёта по состоянию ОДНОГО вопроса dig.

    Отрицательные состояния называются РАЗНЫМИ словами, потому что лечатся
    по-разному: «не найдены» — проверять домен, «не получены» — разбираться с
    резолвером, «не проверено» — ничего не утверждать. Прежний код схлопывал
    все три в «не найдены» либо в напечатанную строку ошибки.
    """
    if info['state'] == 'records':
        return [f"{label}: {', '.join(info['records'])}"]
    if info['state'] == 'none':
        return [none_line]
    if info['state'] == 'fail':
        return [f"❌ {label} — не получены: {info['why']}"]
    return [DIG_UNCHECKED_NOTE.format(label=label, why=info['why'])]


# ==================== DNS ФУНКЦИИ ====================
def dns_report_local(domain):
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
    """Записи домена глазами САМОГО сервера — с силой ответа dig.

    Прежний вид читал dig через exec_command (тот по контракту отдаёт только
    stdout и stderr: exit_status выбрасывается внутри SSH-клиента) и решал по
    пустоте stdout. Замер живьём (этот хост, dig 9.18): «резолвер не отвечает»
    даёт rc=9 и НЕПУСТОЙ stdout ';; communications error to 127.0.0.1#53:
    connection refused' — прежний отчёт печатал «A-записи: ;; communications
    error ...», то есть строку ошибки резолвера выдавал за адрес хоста.
    «Бинарника dig нет» (rc=127, спрашивать было не чем) подписывался
    «не найдены» — диагноз домену там, где проверки не было.

    Вопрос и разбор теперь у носителя dig_records_info (одна команда без
    пайпов и заглушек канала), здесь остаются только формулировки для
    оператора; три отрицания называются тремя разными словами, потому что
    лечатся по-разному.
    """
    lines = []
    lines.append(f"=== DNS-ПРОВЕРКА НА СЕРВЕРЕ ДЛЯ {domain} ===")

    ip_pattern = re.compile(r'^(\d{1,3}\.){3}\d{1,3}$')
    is_ip = bool(ip_pattern.match(domain))

    if is_ip:
        info = dig_records_info(checker, '-x', domain)
        lines.extend(_dig_lines(info, 'PTR (обратный DNS)',
                                'PTR-запись не найдена.'))
        return "\n".join(lines)

    target_ip = ip
    if not target_ip:
        info_a = dig_records_info(checker, 'A', domain)
        if info_a['state'] == 'records':
            target_ip = info_a['records'][0]
        lines.extend(_dig_lines(info_a, 'A-записи', 'A-записи не найдены.'))

    info_ns = dig_records_info(checker, 'NS', domain)
    lines.extend(_dig_lines(info_ns, 'NS-записи', 'NS-записи не найдены.'))

    if target_ip:
        info_ptr = dig_records_info(checker, '-x', target_ip)
        lines.extend(_dig_lines(info_ptr, 'PTR для ' + target_ip,
                                'PTR-запись для %s не найдена.' % target_ip))
    else:
        lines.append("Не удалось получить IP для PTR-запроса.")

    return "\n".join(lines)
def dns_resolvers_report(checker):
    lines = []
    lines.append("=== DNS-РЕЗОЛВЕРЫ НА СЕРВЕРЕ ===")

    # Прежняя форма решала ПО ПУСТОТЕ stdout: `cat ПУТЬ 2>/dev/null` и
    # `if not out.strip()`. Пустоту дают три РАЗНЫХ мира (замер, породивший
    # read_file_info в 1.21.0: rc=1 у cat — это и «нет прав», и «нет файла», а
    # rc=0 бывает у прочитанного пустого файла), а лечатся они противоположно:
    # права, раскладка, и «резолвинг ведёт systemd-resolved — не трогай».
    # Код возврата выбрасывался на входе в функцию (out, _, _), а канал с
    # причиной глушил 2>/dev/null.
    read = read_file_info(checker, RESOLV_CONF)
    if read['content'] is None:
        lines.append(READ_GAP.format(path=RESOLV_CONF,
                                     reason=read['reason'] or ''))
        return "\n".join(lines)

    content = read['content']
    lines.append("Содержимое %s:\n%s" % (RESOLV_CONF,
                                         content if content.strip() else '(пусто)'))

    nameservers = _nameservers_from_text(content)
    if not nameservers:
        if not content.strip():
            # Прочитанный ПУСТОЙ файл — не «не удалось прочитать»: на хостах с
            # resolved resolv.conf законно пуст, и «не удалось» отправило бы
            # оператора проверять права там, где всё в порядке.
            lines.append("❌ %s пуст: в нём не найдены nameserver'ы — вероятно, "
                         "резолвинг ведёт systemd-resolved, и «сменить резолверы» "
                         "здесь значит править не тот файл." % RESOLV_CONF)
        else:
            lines.append("❌ В %s не найдены nameserver'ы" % RESOLV_CONF)
        return "\n".join(lines)

    lines.append(f"\nНайдено DNS-серверов: {len(nameservers)}")
    lines.append("Проверка доступности:")

    for ns in nameservers:
        # Доступность меряет общий зонд (1.32.10): решение по ОТВЕТУ сервера,
        # а не по наличию слова NOERROR. Замер живьём: побайтово одинаковое
        # «недоступен» давали (а) живой сервер, ответивший NXDOMAIN, (б)
        # бинарника dig нет (rc=127 — спрашивать было не чем), (в) пустой
        # вывод. Пайп с `grep -q NOERROR && echo ... || echo ...` выбрасывал
        # и код dig, и stderr с причиной, а python-дополнение
        # `else "недоступен"` добавляло четвёртый вход в ту же ложь. По
        # «не проверено» диагноз не печатается: по слову «недоступен»
        # оператор жмёт «сменить резолверы», а set_dns_resolvers
        # перезаписывает /etc/resolv.conf.
        probe = resolver_probe_info(checker, ns)
        if not probe['checked']:
            lines.append(f"  {ns}: не проверено")
            lines.append("  " + probe['note'])
        elif probe['state'] == 'ok':
            lines.append(f"  {ns}: доступен")
        else:
            lines.append(f"  {ns}: недоступен ({probe['note']})")

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
    """Список резолверов либо СТРОКА-ОТЧЁТ, если файл не прочитан.

    Контракт возвращаемого значения — не мелочь: значение ест gui_dns.
    _open_edit_dns_dialog, и там список открывает диалог редактирования, а
    строка только логируется (тот же контракт, что у get_domains). Прежний код
    при отказе чтения возвращал [] — то есть «резолверов нет», — и диалог
    открывался поверх признака, которого не было: оператор жмёт «Применить», и
    set_dns_resolvers перезаписывает конфиг.

    Пайп `grep -E "^nameserver" ... | awk` выбрасывал код grep (rc конвейера
    принадлежит awk) и глушил причину, поэтому «не прочитали», «файла нет» и
    «в файле нет записей» для него были одним [].
    """
    read = read_file_info(checker, RESOLV_CONF)
    if read['content'] is None:
        return READ_GAP.format(path=RESOLV_CONF, reason=read['reason'] or '')
    return _nameservers_from_text(read['content'])


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

    resolved = unit_status_info(checker, 'systemd-resolved')
    if resolved['status'] is None:
        # Молчание systemctl — это «мы не спросили», а не «не активно».
        # Прежний код решал по «!= active» и на пустом ответе выбирал
        # ветку записи: делал резервную копию и перезаписывал
        # /etc/resolv.conf. Замер живьём (хост без systemd, bus мёртв):
        # ЛЮБОЙ is-active отвечает пустым stdout при rc=1, причина живёт в
        # stderr — а её как раз и глушил 2>/dev/null. Под управлением
        # живого resolved /etc/resolv.conf — симлинк на stub-файл, поэтому
        # запись по непроверенному признаку ломает резолвинг машины.
        # Опасное действие не совершается: ни cp, ни запись.
        lines.append('⚠️ Состояние systemd-resolved не проверено — резолверы не меняем.')
        lines.append(resolved['note'])
        return "\n".join(lines)

    if resolved['status'] != 'active':
        lines.append("systemd-resolved не активен. Редактируем %s напрямую."
                     % RESOLV_CONF)
        backup_path = create_backup(checker, RESOLV_CONF, 'dns')
        if backup_path:
            lines.append(f"✅ Резервная копия создана: {backup_path}")
        else:
            lines.append("⚠️ Не удалось создать резервную копию %s" % RESOLV_CONF)

        new_content = "# Generated by SSH Diagnostic Tool\n"
        for ns in valid_ns:
            new_content += f"nameserver {ns}\n"

        ok, err = write_remote_file(checker, RESOLV_CONF, new_content)
        if not ok:
            lines.append(f"❌ Ошибка записи: {err}")
        else:
            lines.append("✅ %s обновлён." % RESOLV_CONF)
            # Проверка результата обязана смотреть ФАЙЛ, а не наше намерение:
            # форма прежнего контроля (exec_command + cat без состояния) здесь
            # оставлена намеренно — она только показывает, что записалось, и
            # ничего не решает по пустоте.
            out_check, _ = checker.exec_command('cat ' + q(RESOLV_CONF))
            lines.append("\nСодержимое %s:\n%s" % (RESOLV_CONF, out_check))
        return "\n".join(lines)

    lines.append("Обнаружен systemd-resolved. Настраиваем глобальные DNS и интерфейсы.")
    # Это тяжёлое место слайса: ниже по new_conf_lines строится НОВЫЙ
    # /etc/systemd/resolved.conf и уходит на машину через write_remote_file.
    # Прежняя форма при отказе чтения давала out_conf == '' ->
    # new_conf_lines == [] -> dns_found == False, и файл перезаписывался
    # содержимым из двух строк: FallbackDNS, DNSSEC, Cache, Domains, MulticastDNS
    # терялись молча (замер: cat различает «нет прав» и «нет файла» одним rc=1,
    # а 2>/dev/null прятал единственную строку с причиной).
    # Развилка смотрит state, а не только content: у read_file_info у missing
    # content тоже None, но ОТСУТСТВИЕ доказано — создавать [Resolve] честно
    # (терять нечего). Отказ — только unreadable / unchecked / isdir / readerr.
    read_conf = read_file_info(checker, RESOLVED_CONF)
    if read_conf['state'] != 'missing' and read_conf['content'] is None:
        lines.append('❌ %s не прочитан: %s — файл НЕ меняем. Перезапись по '
                     'непрочитанному конфигу оставила бы в нём только [Resolve] '
                     'и DNS=, и прочие настройки резолвинга (FallbackDNS, '
                     'DNSSEC, Cache, Domains) потерялись бы.'
                     % (RESOLVED_CONF, read_conf['reason'] or ''))
        lines.append('Пока файл не читается, не меняем и per-interface DNS, и '
                     'службу: часть настроек мы не видели.')
        return "\n".join(lines)
    # Итерация — по ПРОЧИТАННОМУ содержимому (src_lines), накопление — в
    # new_conf_lines. Два разных списка, и это не стиль: тело цикла делает
    # append в new_conf_lines, поэтому обход того же списка не заканчивается
    # никогда (замер: прогон test_dns висел 240 с, compile при этом зелёный).
    src_lines = [] if read_conf['content'] is None \
        else read_conf['content'].splitlines()
    new_conf_lines = []
    dns_found = False
    for line in src_lines:
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

    ok, err = write_remote_file(checker, RESOLVED_CONF, new_content)
    if not ok:
        lines.append(f"❌ Ошибка записи {RESOLVED_CONF}: {err}")
    else:
        lines.append("✅ %s обновлён." % RESOLVED_CONF)

    out_ifaces, _, _ = checker.run("ip -o link show | awk -F': ' '{print $2}' | grep -v lo")
    interfaces = [iface.strip() for iface in out_ifaces.splitlines() if iface.strip()]
    for iface in interfaces:
        checker.run(f'resolvectl dns {q(iface)} "" 2>/dev/null')
        cmd = 'resolvectl dns ' + q(iface) + ' ' + ' '.join(q(ns) for ns in valid_ns)
        out, err, rc = checker.run(cmd + ' 2>&1')
        if rc != 0:
            lines.append(f"❌ Ошибка для {iface} (rc={rc}): {err.strip() or out.strip()}")
        else:
            lines.append(f"✅ DNS для {iface}: {', '.join(valid_ns)}")

    checker.run('systemctl restart systemd-resolved 2>/dev/null')
    lines.append("Перезапущен systemd-resolved.")

    out_check, _ = checker.exec_command('resolvectl status | grep -E "Global|DNS Servers"')
    lines.append("\nТекущие DNS (resolvectl):\n" + (out_check if out_check.strip() else "нет данных"))
    out_resolv, _ = checker.exec_command('cat /etc/resolv.conf')
    lines.append("\nСодержимое /etc/resolv.conf:\n" + out_resolv)
    return "\n".join(lines)
