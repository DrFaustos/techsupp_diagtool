"""Определение панели, системные метрики и базовые отчёты."""
from common import (LOG_PATHS, DOMAIN_PATHS, get_domain_from_config, q,
                    command_probe_info,
                     path_entry_state)


# ==================== ОПРЕДЕЛЕНИЕ ПАНЕЛИ ====================
# Прежняя форма решала по пустоте stdout:
#
#     test -f /usr/local/fastpanel/bin/fastpanel && echo "yes" || echo "no"
#
# и печатала «панели нет» и когда бинарника нет, и когда прав не хватило
# посмотреть. Замер живьём: test -f даёт rc=1 и ПУСТОЙ stderr в обоих отказах —
# различить нечем ни числом, ни каналом, а ls/stat/find различают миры только
# локализованным текстом errno (на клиентском хосте с другой локалью признак по
# строке молча сломался бы). Поэтому панель ищут достоверными списками
# каталогов (см. path_entry_state), а отсутствие формулируется только там, где
# список прочитан при rc=0 и имени в нём нет.
PANEL_BINARIES = (
    ('fastpanel', '/usr/local/fastpanel/bin/fastpanel'),
    ('ispmanager', '/usr/local/mgr5/bin/mgrctl'),
)

# Значение, когда спрос не состоялся. Оно НЕ равно 'none': «панелей нет» —
# измеренный ответ, а не следствие нехватки прав. Потребители выбирают наборы
# путей через .get(panel_type, ...), поэтому неизвестное значение деградирует в
# «none»-наборы, а не роняет отчёт (проверено тестом).
PANEL_UNCHECKED = 'unchecked'

# Процессы спрашиваем ОДНИМ запросом без пайпа: код возврата конвейера
# принадлежит последней команде, и «ps не запустился» неотличим от «процессов
# нет» (замер: rc=1 и ноль байт в обоих мирах).
PANEL_PROCESSES_CMD = 'ps aux'

# Признак по процессу снимается из argv[0], а НЕ из строки вывода целиком.
# Живой замер (верификатор 1.32.12) показал хуже прежнего диагноза: на машине
# БЕЗ панелей «ps aux | grep -E "fastpanel|mgr5"» выдавал fastpanel — слово
# нашлось в командной строке самого наблюдателя. Подстрока в чужом выводе
# находит панель в «vim /root/fastpanel-notes.txt» и в grep'е, который сам её
# ищет. Здесь сравнивается, ЧЕМ запущен процесс, а не что написано в строке.
PANEL_PROCESS_SIGNS = (
    ('fastpanel', ('fastpanel', '/fastpanel/')),
    ('ispmanager', ('mgrctl', '/mgr5/')),
)

# Человекочитаемое отображение. Закон серии: «не проверено» не печатается как
# факт и не показывается оператору машинным маркером (gui_runner пишет эту
# строку в лог подключения).
PANEL_STATE_TEXT = {
    'fastpanel': 'FastPanel',
    'ispmanager': 'ISPmanager',
    'none': 'не найдена (проверено)',
    PANEL_UNCHECKED: 'не проверено (не хватило прав спросить)',
}


def panel_label(panel_type):
    '''То, что можно показать человеку: метка состояния или само значение.

    Неизвестное значение отдаётся как есть: выдумывать вместо него «не
    найдена» означало бы подменить ответ хоста догадкой.
    '''
    if not panel_type:
        # Значения нет вовсе (соединение не установлено, выбор не сделан):
        # «не определена» — честнее, чем печатать None или выдумывать ответ.
        return 'не определена'
    return PANEL_STATE_TEXT.get(panel_type, panel_type)


def ps_row_command(line):
    '''Поле COMMAND строки `ps aux`: всё после десятого поля.

    Полей ровно одиннадцать (USER PID %CPU %MEM VSZ RSS TTY STAT START TIME
    COMMAND), поэтому split(None, 10). Короткая строка — не строка процесса:
    возвращаем пусто, а не угадываем.
    '''
    parts = (line or '').split(None, 10)
    if len(parts) < 11:
        return ''
    return parts[10].strip()


def ps_row_binary(line):
    '''argv[0] процесса — чем он запущен (первое слово команды).'''
    command = ps_row_command(line)
    if not command:
        return ''
    return command.split(' ')[0]


def panel_from_processes(text):
    '''Панель по argv[0] процессов либо None — если ни один не подошёл.

    Строка заголовка отбрасывается: её поле COMMAND буквально равно 'COMMAND'.
    '''
    for line in (text or '').splitlines():
        binary = ps_row_binary(line)
        if not binary or binary == 'COMMAND':
            continue
        base = binary.rsplit('/', 1)[-1]
        for panel, signs in PANEL_PROCESS_SIGNS:
            if base in signs or any(sign in binary for sign in signs):
                return panel
    return None


def detect_panel(checker):
    '''Панель хоста: имя, 'none' (доказано) или PANEL_UNCHECKED (не спросили).'''
    cache = {}
    unproven = []
    for panel, path in PANEL_BINARIES:
        state = path_entry_state(checker, path, cache)
        if state['state'] == 'found':
            return panel
        if state['state'] != 'absent':
            unproven.append(state['note'])
    # Вторая ветка — процессы: панель может стоять в нестандартном пути
    # (/opt/fastpanel/...), которого нет ни в одном проверенном каталоге, так
    # что одних каталогов для «панелей нет» недостаточно.
    ps = command_probe_info(checker, PANEL_PROCESSES_CMD)
    if ps['state'] == 'ok':
        hit = panel_from_processes(ps['text'])
        if hit:
            return hit
    elif ps['state'] == 'absent':
        # ps нет в PATH: процесс мы не увидели ни в каком виде.
        unproven.append(ps['note'])
    if unproven or ps['state'] != 'ok':
        # Утверждать отсутствие можно, только когда каждый спрос состоялся.
        return PANEL_UNCHECKED
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

    # Доступность спрашивает общий зонд (1.32.11): решение по коду возврата и
    # каналам, а не по пустоте stdout. Прежняя форма
    #   cmd 2>/dev/null || echo "not installed"
    # на этой машине печатала «not installed» и там, где утилиты нет (ufw,
    # rc=127), и там, где она ЕСТЬ, но отказали права (iptables -L -n rc=4,
    # nft list ruleset rc=1): три разных мира сходились в одну строку отчёта о
    # безопасности, по которому оператор решает, нужен ли файрвол. Заглушка
    # 2>/dev/null глушила единственное доказательство отсутствия бинарника —
    # «command not found» живёт в stderr у оболочки. Значение остаётся строкой:
    # словарь уходит в firewall_report и в сводку (reports.py), где его ждут
    # строки.
    firewall = {}
    for name, cmd in (('ufw', 'ufw status'),
                      ('iptables', 'iptables -L -n'),
                      ('nftables', 'nft list ruleset')):
        probe = command_probe_info(checker, cmd)
        firewall[name] = probe['text'] if probe['state'] == 'ok' else probe['note']
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
# Прежняя решалка выглядела так (и была зелёной, потому что фикстуры подавали
# только честные ответы):
#
#     out, _ = checker.exec_command('nginx -t 2>&1')
#     if 'nginx' in out or 'syntax is ok' in out.lower():
#         results['nginx'] = out.strip()
#
# exec_command контрактом отдаёт только пару каналов: код возврата выбрасывается
# в ssh_client.exec_command, поэтому решать было слову. Замер живьём на этой
# машине (nginx и apache2ctl ОТСУТСТВУЮТ, httpd есть) дал решалку, вывернутую
# наизнанку:
#
#     nginx -t 2>&1                        rc=127  'nginx: command not found'
#         -> 'nginx' in out есть ИСТИНА, в отчёте «nginx: command not found»
#     apache2ctl -t 2>&1 || httpd -t 2>&1  rc=127  'apache2ctl: command not found'
#         -> 'apache' in out.lower() есть ИСТИНА: apache появляется в отчёте из
#            текста ОТСУТСТВИЯ бинарника
#     httpd -t  на битом конфиге           rc=1    'AH00526: Syntax error ...'
#         -> прежняя решалка apache НЕ регистрирует: настоящая ошибка конфига
#            теряется
#
# То есть отчёт заявлял проверку конфигурации несуществующего веб-сервера и
# молчал, когда конфиг действительно сломан. Плюс конвейер ||: код возврата
# принадлежит ПОСЛЕДНЕЙ команде, поэтому «apache2ctl не запустился» и «httpd
# ответил» имели один код — бинарники спрашиваются раздельно.
#
# command_probe_info (1.32.11) здесь НЕ переиспользуется: он отвечает на вопрос
# «состоялся ли спрос» и на rc != 0 с пустым stdout даёт unchecked, а здесь
# честный отказ веб-сервера (rc != 0 с текстом ошибки) — ценность, а не провал
# спроса. Второй читатель того же сигнала разъезжается релизами, поэтому
# состояния описаны своим парсером, а не натянуты на чужой.

# Порядок обхода прежний (сначала apache2ctl, потом httpd), чтобы поведение на
# машинах, где apache2ctl есть, не поехало.
WEB_PROBE_BINS = (
    ('nginx', ('nginx',)),
    ('apache', ('apache2ctl', 'httpd')),
)


def web_config_probe_cmd(binary):
    '''Форма запроса: без смешивания каналов и без ||-дополнения.

    2>&1 был нужен прежней решалке: она решала по слову и слову надо было
    собраться в один канал. Решалке по коду возврата каналы нужны порознь —
    «command not found» пишет в stderr оболочка, а тест конфигурации пишет
    веб-сервер, и путать эти два источника нельзя.
    '''
    return binary + ' -t'


def parse_web_config_probe(out, err, rc):
    '''('ok' | 'broken' | 'absent' | 'unchecked', тело ответа, причина|None).

    Четыре состояния, а не два: «конфиг сломан» — ответ программы, «сервера нет»
    — доказательство отсутствия (rc=127/126), «не проверено» — молчание или
    странный код. Пустой вывод НЕ является основанием назвать сервер
    отсутствующим: отсутствие доказывает только код возврата оболочки.
    '''
    def first_line(text):
        lines = (text or '').strip().splitlines()
        return lines[0][:200] if lines else ''

    out_t = (out or '').strip()
    err_t = (err or '').strip()
    body = chr(10).join(p for p in (out_t, err_t) if p)
    if rc == 127:
        return 'absent', '', first_line(err_t or out_t) or 'rc=127'
    if rc == 126:
        return 'absent', '', first_line(err_t or out_t) or 'rc=126'
    if rc == 0:
        if not body:
            return 'unchecked', '', 'пустой вывод при rc=0'
        return 'ok', body, None
    if not body:
        return 'unchecked', '', 'пустой вывод при rc=%s' % rc
    return 'broken', body, None


def web_config_probe(checker, kind, binaries):
    '''Один веб-сервер: {'kind', 'binary', 'state', 'text', 'why', 'checked'}.

    Бинарники обходятся по очереди, обход останавливается на ПЕРВОМ ответившем:
    отсутствующий бинарник — не повод молчать о втором, а ответивший — не повод
    спрашивать следующего (его код возврата ничего не скажет о первом).
    '''
    why = ''
    for binary in binaries:
        out, err, rc = checker.run(web_config_probe_cmd(binary))
        state, text, why = parse_web_config_probe(out, err, rc)
        if state != 'absent':
            return {'kind': kind, 'binary': binary, 'state': state,
                    'text': text, 'why': why or '',
                    'checked': state != 'unchecked'}
    return {'kind': kind, 'binary': '', 'state': 'absent', 'text': '',
            'why': why or 'ни один бинарник не найден (rc=127)',
            'checked': True}


def check_web_config(checker):
    '''{имя сервера: текст его ответа} — только на ДОСТОВЕРНЫЙ ответ.

    Отсутствие (rc=127/126) в словарь не попадает: его и ждёт ветка «не
    обнаружен». «Не проверено» не попадает тоже: печатать молчание как результат
    проверки конфига — тот самый дефект, который серия закрывает состоянием
    «не проверено». Общая строка отчёта («не обнаружен или не удалось
    проверить») покрывает оба отрицания честнее, чем ложное «конфиг в порядке».
    '''
    results = {}
    for kind, binaries in WEB_PROBE_BINS:
        probe = web_config_probe(checker, kind, binaries)
        if probe['state'] in ('absent', 'unchecked'):
            continue
        results[kind] = probe['text']
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
