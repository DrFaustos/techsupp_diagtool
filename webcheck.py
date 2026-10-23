"""Дополнительные проверки: SSL-сертификаты, WHOIS, порты, массовый grep по логам."""
import re

from common import log_reader, q
from discovery import (CERT_STATE_ICON, cert_days_label, cert_state,
                       parse_cert_days)
from logs import find_logs, find_logs_info, get_domains


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


# Сколько секунд жнём ответ реестра. Замер `timeout`: убил по таймауту -> rc=124,
# бинарника нет -> rc=127 (проверено живьём, а не по мануалу).
WHOIS_TIMEOUT = 15

# Фразы, которыми реестры ОТВЕЧАЮТ «такого домена нет». Сняты живьём через TCP/43
# (утилиты whois на машине как раз не было — об этом и правка), а не выдуманы:
#   whois.verisign-grs.com  -> 'No match for "ZZQQXX-...COM".'
#   whois.tcinet.ru / nic.ru -> 'No entries found for the selected source(s).'
# Справочник RU-TLD добавляет 'DOMAIN NOT FOUND' (centralnic), 'NOT FOUND' (.pro),
# 'No entries found' (nic.re/pm/tf/wf); живые запросы дали ещё 'Domain not found.'
# (whois.nic.me) и 'This domain name has not been registered.' (whois.nic.uk).
# ВАЖНО: «домена нет» — это НЕ пустой вывод, поэтому прежняя подпись «whois не
# установлен или домен не найден» выбирала между «поставь утилиту» и «домена не
# существует» наугад.
WHOIS_ABSENT_PHRASES = ('no match for', 'no entries found', 'no data found',
                        'no object found', 'no such domain', 'no such object',
                        'has not been registered', 'not found')

# Поля, наличие которых означает: запись есть, домен зарегистрирован. Их же роль —
# защита от ложного «свободен»: служебное NOT FOUND в contact-строке реестра не
# должно перевести зарегистрированный домен в «не зарегистрирован».
WHOIS_RECORD_KEYS = ('registrar:', 'creation date:', 'created:', 'updated date:',
                     'expiry date:', 'expiration date:', 'registry expiry date:',
                     'registrant organization:', 'name server:', 'nserver:',
                     'status:', 'domain name:', 'domain:', 'paid-till:', 'state:')


def whois_first_line(text, limit=160):
    """Первая непустая строка — ровно столько причины, сколько нужно прочитать."""
    for line in (text or '').splitlines():
        if line.strip():
            return line.strip()[:limit]
    return ''


def whois_no_data_lines(err, rc, seconds=WHOIS_TIMEOUT):
    """Почему вывода нет — РАЗНЫЕ диагнозы вместо одной фразы-гадалки.

    Прежний код принимал rc и не использовал его, а `2>/dev/null` глушил ровно
    ту строку, где написана причина. Замерено живьём на машине без whois:
    rc=127 и stderr «timeout: failed to run command 'whois': No such file or
    directory». Лечить rc=127 и rc=124 нужно противоположным: в одном ставить
    утилиту, в другом — понимать, что реестр просто молчит дольше 15 секунд.
    """
    reason = whois_first_line(err)
    if rc == 127:
        return ["❌ whois на сервере не установлен (rc=127): запрос НЕ выполнялся. "
                "Поставьте утилиту: apt install whois (Debian/Ubuntu) или "
                "yum install whois / dnf install whois.",
                f"   Ответ системы: {reason}" if reason else
                "   Ответ системы: (stderr пуст — проверьте, что PATH не срезан)"]
    if rc == 124:
        return [f"⚠️ whois не успел ответить за {seconds} сек (rc=124): реестр "
                f"отвечал дольше. Про домен ничего неизвестно — он может быть "
                f"сколько угодно зарегистрирован. Повторите проверку или "
                f"проверьте исходящий порт 43 (его часто блокируют).",
                f"   Ответ системы: {reason}" if reason else
                "   Ответ системы: (реестр молчал до таймаута)"]
    if rc:
        return [f"⚠️ Запрос whois не выполнен (rc={rc}) — это «не проверено». "
                "Повторите проверку с другого сервера.",
                f"   Ответ системы: {reason}" if reason else
                "   Ответ системы: (stderr пуст — причины нет, а догадываться "
                "про домен мы не будем)"]
    return ["❓ Ответ реестра пуст без ошибки (rc=0) — состояние не проверено: "
            "домен может быть и занят, и свободен. Проверьте другим способом "
            "(RDAP, другой сервер)."]


def whois_record_lines(out):
    """Строки-поля регистрационной записи (пусто — записи в выводе нет).

    ЕДИНСТВЕННОЕ место, где решается «запись есть». Раньше этот признак считался
    дважды — здесь для вывода и заново внутри `whois_absent_line`, — и это ровно
    тот разъезд, который лечат последние релизы: сводка однажды начала бы
    утверждать «не зарегистрирован» над уже напечатанным полем `registrar:`.
    """
    found = []
    for line in out.splitlines():
        low = line.strip().lower()
        if any(low.startswith(k) for k in WHOIS_RECORD_KEYS):
            found.append(line.strip())
    return found


def whois_absent_line(out, record_lines=None):
    """Строка реестра «домена нет» — но только если записи в выводе нет вовсе.

    Иначе служебное «NOT FOUND» внутри записи зарегистрированного домена
    (например, в contact-строке) дало бы оператору ложный «свободен».
    """
    if record_lines is None:
        record_lines = whois_record_lines(out)
    if record_lines:
        return None
    for line in out.splitlines():
        low = line.strip().lower()
        if any(p in low for p in WHOIS_ABSENT_PHRASES):
            return line.strip()
    return None


def whois_report(checker, domain):
    """WHOIS-запрос для домена: даты, NS, регистратор.

    Причина пустого ответа читается из rc И stderr: один пустой stdout дают "
    «утилиты нет», «реестр молчит», «запрос упал» и «регистратор ответил пусто»,
    а лечатся они по-разному.
    """
    lines = [f"=== WHOIS ДЛЯ {domain} ==="]
    if not domain:
        lines.append("❌ Домен не задан")
        return "\n".join(lines)

    # Без `2>/dev/null`: именно в stderr лежит ответ на вопрос «почему пусто».
    out, err, rc = checker.run(f"timeout {WHOIS_TIMEOUT} whois {q(domain)}")
    if not out.strip():
        lines.extend(whois_no_data_lines(err, rc))
        return "\n".join(lines)

    found = whois_record_lines(out)
    if found:
        lines.extend(found)
        return "\n".join(lines)

    absent = whois_absent_line(out, found)
    if absent:
        # Слова реестра, а не наша догадка: оператор должен видеть, чем именно
        # реестр подтверждает ответ.
        lines.append("ℹ️ Домен не зарегистрирован — так ответил реестр (его "
                     "слова, а не наша догадка):")
        lines.append(f"   «{absent}»")
        return "\n".join(lines)

    # Ключей нет, признанной фразы «нет» тоже: за реестр вердикт не выдумываем.
    lines.append(out.strip()[:2000])
    return "\n".join(lines)


# Типовые порты, которые проверяет «Сканирование портов».
COMMON_PORTS = [21, 22, 25, 53, 80, 110, 143, 443, 465, 587, 993, 995,
                3306, 5432, 6379, 8080, 8443, 27017]

_PORTSTAT_RE = re.compile(
    r'PORTSTAT open=(\d+) refused=(\d+) noreply=(\d+) total=(\d+)')
_OPEN_LINE_RE = re.compile(r'^\s+(\d+) открыт', re.M)
_LISTEN_PORT_RE = re.compile(r':(\d{1,5})$')


def port_probe_cmd(target, ports=None):
    """Одна команда: 18 локальных коннектов и счётчик ИСХОДОВ проб.

    Исходы различимы, и раньше именно это выбрасывалось (`out2, _, _ =
    checker.run(...)`). Проверено живьём: `connection refused` — rc=1 за 4 мс
    (хост ЖИВ, он присылает RST: служба не слушает), недоступный или фильтруемый
    хост — rc=124 за 2002 мс (пакеты молча дрейпятся). Пустой stdout у обоих
    одинаковый, поэтому прежняя фраза «ни один из типовых портов не ответил»
    закрывала два ПРОТИВОПОЛОЖНЫХ диагноза: «поднимай службы / перезагружай» и
    «службы в порядке, проверяй firewall». Оператор, которому фильтруют путь,
    ехал перезагружать живой сервер.

    Хост уходит отдельным словом, а в путь /dev/tcp попадает позиционным
    параметром: кавычки ВНУТРИ пути ставить нельзя (проверено — проба ломается и
    даёт rc=1, то есть «закрыто» там, где мы просто не смогли проверить), а
    неэкранированная вставка РЕАЛЬНО выполняла чужой код (живой прогон с
    host='127.0.0.1; echo INJECTED' дал «INJECTED/22» и rc=0 — 18 ложных
    «порт открыт»).
    """
    ports = ports or COMMON_PORTS
    plist = ' '.join(str(int(p)) for p in ports)
    return (
        f'''T={q(str(target))}; OPEN=0; REFUSED=0; NOREPLY=0; '''
        f'''for p in {plist}; do '''
        '''if timeout 1 bash -c '</dev/tcp/"$1"/"$2"' _ "$T" "$p" 2>/dev/null; '''
        '''then printf '  %s открыт\\n' "$p"; OPEN=$((OPEN+1)); '''
        '''else rc=$?; if [ "$rc" -ge 124 ]; then NOREPLY=$((NOREPLY+1)); '''
        '''else REFUSED=$((REFUSED+1)); fi; fi; '''
        '''done; TOTAL=$((OPEN+REFUSED+NOREPLY)); '''
        '''printf 'PORTSTAT open=%s refused=%s noreply=%s total=%s\\n' '''
        '''"$OPEN" "$REFUSED" "$NOREPLY" "$TOTAL"'''
    )


def parse_port_stat(out):
    """Счётчик исходов из служебной строки PORTSTAT (None — данных нет).

    None — это «не проверено», а НЕ «порты закрыты»: команды могла не быть
    (нет bash/timeout, обрыв соединения).
    """
    found = None
    for line in out.splitlines():
        m = _PORTSTAT_RE.search(line)
        if m:
            found = m
    if not found:
        return None
    return {'open': int(found.group(1)), 'refused': int(found.group(2)),
            'noreply': int(found.group(3)), 'total': int(found.group(4))}


def parse_listening_ports(out):
    """Номера TCP-портов в состоянии LISTEN из вывода ss/netstat.

    Только LISTEN и только tcp: udp-записи (systemd-resolved 5353) и ESTAB
    (активные соединения) иначе выдали бы «слушает тут», которой нет.
    """
    ports = set()
    for line in out.splitlines():
        fields = line.split()
        if not fields or fields[0].lower() not in ('tcp', 'tcp6'):
            continue
        if not any(f.lower() == 'listen' for f in fields):
            continue
        for field in fields:
            m = _LISTEN_PORT_RE.search(field)
            if not m:
                continue
            port = int(m.group(1))
            if 1 <= port <= 65535:
                ports.add(port)
            break
    return ports


def port_scan_verdict(out2, listening, shown, ports=None):
    """Итог проб: три разных диагноза вместо одной фразы «не ответил».

    Единственный источник и иконки, и слов, и цифр — один `stat`, поэтому
    вердикт не разъедется со счётчиком (тот же закон, что в ssl_cert_report).
    """
    stat = parse_port_stat(out2)
    lines = []
    if shown:
        lines.append(shown)
    if stat is None:
        lines.append("❓ Состояние проб неизвестно: команда не вернула счётчик "
                     "(нет bash/timeout или обрыв соединения) — это "
                     "«не проверено», а не «порты закрыты». Повторите проверку.")
        return lines

    total = stat['total']
    opened, refused, noreply = stat['open'], stat['refused'], stat['noreply']
    if opened == 0 and refused == total:
        lines.append(f"❌ Порты закрыты: {refused} из {total} соединений "
                     f"отклонены (RST) — хост жив и ОТВЕЧАЕТ, службы не "
                     f"слушают. Смотри вывод ss выше: поднимай нужные службы, "
                     f"перезагрузка сервера здесь не при чём.")
    elif noreply == total:
        lines.append(f"⚠️ Порты не видно: {noreply} из {total} молчат — пакеты "
                     f"дрейфуют. Хост недоступен ИЛИ путь фильтруют (firewall, "
                     f"cloud security group, ваш IP). Это НЕ «порты закрыты»: "
                     f"службы могут работать.")
    elif noreply:
        lines.append(f"⚠️ Ответили не на всё: из {total} молчат {noreply} "
                     f"(похоже на фильтр — firewall / cloud security group), "
                     f"отклонены (RST) {refused}, отвечают {opened}. Про "
                     f"«порты закрыты» говорить нельзя: молчащие мы не видели.")
    else:
        lines.append(f"✅ Все {total} из {total} соединений отвечают "
                     f"(открыто {opened}, отклонено RST {refused}).")

    if noreply:
        # Решающая связка: ss ЗДЕСЬ показывает LISTEN, а снаружи порт молчит.
        # Это не упавшая служба, это фильтрация пути. Данные уже в прогоне —
        # второй сетевой запрос не нужен.
        outside = set(int(p) for p in _OPEN_LINE_RE.findall(shown))
        silent = sorted(p for p in listening
                        if p in (ports or COMMON_PORTS) and p not in outside)
        if silent:
            shown_list = ', '.join(str(p) for p in silent[:8])
            lines.append(f"ℹ️ Порт(а) {shown_list} слушают на самом сервере "
                         f"(ss их показывает), но снаружи молчат — это "
                         f"фильтрация пути, а не упавшая служба: проверяйте "
                         f"firewall, cloud security group и свой IP.")
    return lines


def port_scan_report(checker, host=None):
    """Сканирование слушающих портов + проверка типовых портов (аналог nmap -T4)."""
    lines = ["=== СКАНИРОВАНИЕ ПОРТОВ ==="]
    out, _, _ = checker.run('ss -tulpn 2>/dev/null || netstat -tulpn 2>/dev/null')
    listening = parse_listening_ports(out)
    if out.strip():
        lines.append("Слушающие порты (ss/netstat):")
        lines.append(out.strip())
    else:
        lines.append("(ss/netstat недоступны)")

    target = host or "127.0.0.1"
    out2, _, _ = checker.run(port_probe_cmd(target, COMMON_PORTS))
    # PORTSTAT — служебная строка НАШЕЙ команды: к выводу утилит она отношения
    # не имеет, и оператор принял бы её за результат сканирования.
    shown = '\n'.join(l for l in out2.splitlines()
                      if 'PORTSTAT' not in l).strip()
    lines.append(f"\nТиповые порты на {target}:")
    lines.extend(port_scan_verdict(out2, listening, shown, COMMON_PORTS))
    return "\n".join(lines)


# Состояния, которые команда greпа сообщает маркером LOGSTATE. Пустой вывод без
# маркера — это «ответ не дошёл» (обрыв, отмена), а не «совпадений нет».
LOG_STATE_TEXT = {
    'badpattern': ("❌ Шаблон не разобран — файл даже не читался. Пока шаблон "
                   "неверен, «совпадений нет» про лог сказать нельзя: проверьте "
                   "регэксп (у grep -E свои правила)"),
    'missing': ("❌ Файл лога исчез между поиском и чтением — обычно так делает "
                "logrotate в момент прогона. Это НЕ «в логе нет ошибок»: "
                "повторите проверку после ротации"),
    'unreadable': ("❌ Файл лога не читается: не хватает прав (логи часто "
                   "640 root:adm). Это «мы ничего не увидели», а не «ошибок "
                   "нет» — прогоните отчётом под root или добавьте оператора в "
                   "группу"),
}

# awk-буфер: считает ВСЕ совпадения и хранит только последние L строк. Нужен
# именно он, а не `tail -n`: в конвейере с tail код возврата конвейера равен rc
# tail (всегда 0), а «Всего строк» считалось по показанному хвосту — при 4
# совпадениях и лимите 2 отчёт писал «Всего строк: 2» (замерено).
#
# M — фильтр «что считать совпадением». Он нужен, когда greп запущен с -C/-n:
# там совпавшая строка помечена номером («12:...»), а строка контекста — «12-».
# Без фильтра awk посчитал бы контекст как совпадения — завышение того же класса,
# что хвост (проверено живьём: 2 совпадения + контекст давали больше).
_LOG_AWK = ('{k++;buf[(k-1)%L]=$0; if(M==""||$0~M)n++}'
            ' END{printf "LOGTOTAL %d\\n", n;'
            ' s=(k>L)?k-L+1:1; for(i=s;i<=k;i++) print buf[(i-1)%L]}')


def grep_log_command(filepath, pattern, context=0, limit=200):
    """Одна POSIX-команда: состояние файла + точный итог + хвост совпадений.

    Порядок веток важнее всего, что в ней есть: шаблон проверяется ПЕРВЫМ, до
    чтения файла. Замерено живьём (bash и dash): `grep -E "$P" /dev/null` даёт
    rc=1 для валидного шаблона и rc=2 для разбитого (`5[0-9`, `[a-`, `(`).
    Именно без конвейера: в конвейере rc принадлежит последней команде, а
    проверка вида `printf '' | grep -E "$P"` битый шаблон НЕ отличает — у greпа
    на пустом входе rc=1 по любой причине (проверено). Оператор вводит шаблон в
    GUI свободно, поэтому опечатка раньше превращалась в «Совпадений не
    найдено», то есть в «проблем в логе нет».

    Readability решается ветками `[ ! -e ]` / `[ ! -r ]`, а не `${PIPESTATUS}`:
    под dash (обычный /bin/sh в Debian/Ubuntu) PIPESTATUS даёт «Bad
    substitution» — проверка живьём.

    stderr читателя НЕ глушится: `gzip: not in gzip format` приходит SSH-каналом
    и показывает, что ротированный .gz битый, — прежний `2>/dev/null` прятал это
    и печатал «Совпадений не найдено» по всем архивам сразу.
    """
    reader = log_reader(filepath)
    # -n добавляется только вместе с -C и только ради честного счёта: он даёт
    # префикс «номер:» на совпавших строках, по которому awk отличает совпадение
    # от строки контекста. Один проход по файлу — никакой второй цены.
    flags = f"-C {int(context)} -n " if context else ""
    awk_m = '^[0-9]+:' if context else ''
    return (
        f'F={q(str(filepath))}; P={q(pattern)}; L={max(1, int(limit))}; '
        f'grep -E "$P" /dev/null >/dev/null 2>&1; rc=$?; '
        f'if [ "$rc" -ge 2 ]; then echo LOGSTATE badpattern; '
        f'elif [ ! -e "$F" ]; then echo LOGSTATE missing; '
        f'elif [ ! -r "$F" ]; then echo LOGSTATE unreadable; '
        f'elif ! command -v {reader} >/dev/null 2>&1; '
        f'then echo "LOGSTATE notool {reader}"; '
        f'elif ! command -v awk >/dev/null 2>&1; '
        f'then echo "LOGSTATE notool awk"; '
        f'else {reader} "$F" | grep {flags}-E "$P" '
        f'| awk -v L="$L" -v M="{awk_m}" \'{_LOG_AWK}\'; fi'
    )


def parse_grep_answer(out):
    """(state, total, строки) из ответа команды. total=None — ответа не было.

    state ставится только на честном маркере LOGSTATE; отсутствие и маркера, и
    LOGTOTAL означает «данных нет» (обрыв/отмена), и это НЕ право сказать
    «совпадений нет» — тот же закон, что в v1.16 и v1.17.
    """
    state = None
    total = None
    lines = []
    for line in (out or '').splitlines():
        if line.startswith('LOGSTATE '):
            state = line.split(' ', 1)[1].strip()
        elif line.startswith('LOGTOTAL ') or line.startswith('LOGCOUNT '):
            try:
                total = int(line.split(' ', 1)[1].strip())
            except ValueError:
                total = None
        else:
            lines.append(line)
    return state, total, lines


def grep_logs_report(checker, panel_type, domain, pattern, context=0, limit=200):
    """Массовый grep по логам домена (например, все 5xx или 404).

    «Совпадений нет» печатается ТОЛЬКО когда хотя бы один лог действительно
    прочитан и ни один не отвалился. Раньше `out, _, _ = checker.run(...)`
    выбрасывал код возврата, а `tail` в конце конвейера сделал бы его бесполезным
    и для того, кто захотел бы его взять (rc конвейера = rc tail = 0).
    """
    lines = [f"=== GREP ЛОГОВ: {domain} / '{pattern}' ==="]
    acc = find_logs_info(checker, panel_type, domain, 'access')
    err = find_logs_info(checker, panel_type, domain, 'error')
    # Без дедупликации один и тот же файл попадал в поиск дважды (маски access и
    # error пересекаются), и «Всего строк» удваивалось: масштаб беды завышался
    # тем же способом, что раньше занижался хвостом.
    log_files = list(dict.fromkeys(acc['paths'] + err['paths']))
    notes = list(dict.fromkeys(acc['notes'] + err['notes']))
    if not log_files:
        # «Не найдены» — только когда каталоги действительно просмотрены. Роды
        # пустоты лечатся по-разному: закрытый каталог — это права, отсутствующий
        # — раскладка/тип панели, а неподтверждённый ответ не лечится ничем, кроме
        # повтора. Подпись «не найдены» отправляла оператора не туда.
        if notes:
            lines.append("❌ Логи домена не просмотрены:")
            lines.extend(f"   {n}" for n in notes)
        elif not (acc['checked'] or err['checked']):
            lines.append("❓ Логи домена: состояние не проверено — сервер не "
                         "подтвердил просмотр ни одного каталога. Повторите "
                         "проверку.")
        else:
            lines.append("❌ Логи для домена не найдены")
        return "\n".join(lines)

    total = 0
    shown = 0
    read_files = 0
    unseen = []  # (файл, причина) — то, о чём мы НЕ имеем права судить
    for lf in log_files:
        out, err, rc = checker.run(grep_log_command(lf, pattern, context, limit))
        state, file_total, matches = parse_grep_answer(out)
        if state:
            if state.startswith('notool'):
                # Маркер несёт имя утилиты («notool zcat»): без него отчёт сказал бы
                # «нет утилиты» и заставил бы оператора гадать, какой именно. Если
                # имя всё же не дошло (обрыв), берём того читателя, которого сами
                # и попросили проверять, — мы знаем его по расширению файла.
                name = state.split(' ', 1)[1].strip() if ' ' in state else ''
                name = name or log_reader(lf)
                unseen.append((lf, f"на сервере нет {name}: файл не прочитан — "
                                   f"это «не проверено», а не «совпадений нет»"))
            else:
                unseen.append((lf, LOG_STATE_TEXT.get(state, state)))
            continue
        if file_total is None:
            reason = (err or '').strip().splitlines()
            unseen.append((lf, "Сервер не вернул ни состояния, ни итога — "
                               f"состояние не проверено"
                               f"{' (' + reason[0][:120] + ')' if reason else ''}"))
            continue
        if (err or '').strip():
            # Читатель (cat/zcat) ругался: файл прочитан не полностью, и его
            # нулевой итог — не «ошибок нет», а «мы не сумели прочитать».
            reason = (err or '').strip().splitlines()[0][:160]
            unseen.append((lf, f"читатель сообщил об ошибке: {reason} — вывод "
                               f"неполон, «совпадений нет» по этому файлу "
                               f"сказать нельзя"))
            if not matches:
                continue
        read_files += 1
        total += file_total
        shown += len(matches)
        if matches:
            lines.append(f"\n--- {lf} ---")
            lines.append("\n".join(matches))

    for lf, reason in unseen:
        lines.append(f"\n⚠️ {lf}\n   {reason}")

    if not read_files:
        lines.append("\n❓ Ни один лог не прочитан — по этому домену состояние "
                     "не проверено: утверждать «совпадений нет» не на чём.")
        return "\n".join(lines)

    hidden = len(unseen)
    if total == 0 and hidden:
        lines.append(f"\n⚠️ Прочитано {read_files} из {read_files + hidden} "
                     f"файлов, в прочитанных совпадений 0. Про «совпадений нет» "
                     f"речи нет: {hidden} файл(ов) мы не видели (выше).")
    elif total == 0:
        lines.append("\nСовпадений нет.")
    elif shown < total:
        lines.append(f"\nВсего совпадений: {total} (показаны последние {shown} "
                     f"из {total}; лимит на файл {int(limit)})")
    else:
        lines.append(f"\nВсего совпадений: {total} (показаны все)")
    if hidden and total:
        lines.append(f"⚠️ При этом {hidden} файл(ов) не прочитаны — итог может "
                     f"быть меньше реального (причины выше).")
    return "\n".join(lines)


def list_common_reports(checker, panel_type, domain):
    """Набор частых отчётов: 5xx, 404, топ IP."""
    lines = []
    lines.append(grep_logs_report(checker, panel_type, domain, r'" 5[0-9][0-9] ', limit=100))
    lines.append("\n" + grep_logs_report(checker, panel_type, domain, r'" 404 ', limit=100))
    return "\n".join(lines)
