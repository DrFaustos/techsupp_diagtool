"""Определение панели, системные метрики и базовые отчёты."""
import ipaddress
import re
from uuid import uuid4

from common import (LOG_PATHS, DOMAIN_PATHS, get_domain_from_config, q,
                    command_probe_info, path_entry_state,
                    parse_marker_sections, parse_unit_state,
                    remove_remote_path, UNIT_NO_ANSWER)


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
    """Shell-команда: маркер '@имя', статус и 'rc=N' на каждую службу.

    Почему решает КОД ВОЗВРАТА (1.32.29): `is-active` пишет ОДИНАКОВЫЙ
    stdout 'inactive' и для остановленной службы (rc=3), и для юнита,
    которого нет вовсе (rc=4) — различие несёт только rc (замер на живом
    systemd 259; оракул — `systemctl show -p LoadState --value`). Прежняя
    форма теряла rc: `st=$(...)` оставлял код присваивания, а цикл отдал бы
    код ПОСЛЕДНЕЙ команды, поэтому rc снимается ВНУТРИ итерации, сразу за
    systemctl. `2>/dev/null` больше не ставим: при мёртвом bus stdout пуст,
    и единственная строка с причиной живёт в stderr — заглушив её, прошлый
    код выдумывал 'unknown' вместо честного «не проверено». Имя едет вместе
    со своим статусом (маркерная секция) — рассинхрон старых `|| echo`
    невозможен. Имя иглы `__svc_status` сохранено: на неё сажаются маршруты
    тестов и счётчик одного зонда на отчёт (tests/test_reports.py).
    """
    services = services if services is not None else SERVICES_TO_CHECK
    args = ' '.join(q(s) for s in services)
    return (
        '__svc_status() { printf "@%s\\n" "$1"; '
        'LC_ALL=C systemctl is-active "$1"; '
        'printf "rc=%s\\n" "$?"; }; '
        f'for __s in {args}; do __svc_status "$__s"; done'
    )


def parse_service_statuses(out):
    """Разбирает ответ зонда служб в dict. Чистая функция (тесты без SSH).

    Формы ответа читаются ОБЩИМ носителем (common.parse_marker_sections /
    common.parse_unit_state — тот же код, что у panels, 1.32.29):
      '@имя' + статус + 'rc=N' — состояние решает rc: rc=4 при статусе ->
        «не установлен»; статуса нет (bus dead) -> None;
      'имя=статус' (ответ ПРЕЖНЕЙ команды) -> читается ровно как раньше.
    Пустой вывод (система без systemd / systemctl недоступен) -> {}.
    Отсутствующий ключ — службу не спрашивали; None — спросили, ответа нет.
    Это разные миры: первый молчит законно, второй обязан быть назван.
    """
    text = out or ''
    if any(line.startswith('@') for line in text.splitlines()):
        return {name: parse_unit_state(body) for name, body
                in parse_marker_sections(text).items()}
    statuses = {}
    for line in text.splitlines():
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


# Источник исходящего трафика спрашивается СЫРОЙ командой, а не конвейером
# `ip route get 1.1.1.1 2>/dev/null | grep -oP "src \S+" | cut -d" " -f2`:
# * 2>/dev/null глушило причину (RTNETLINK отвечает в stderr: «Network is
#   unreachable» — это ответ, а не молчание);
# * `grep -oP` — GNU-расширение: BusyBox grep отвечает «invalid option», а
#   код возврата конвейера принадлежит cut, то есть «не спросили» выглядело
#   бы как «адреса нет» — тот же закон 1.32.26 про решение по коду;
# * то, что вернул конвейер, никак не проверялось на «это адрес» — выводом
#   «IP-адреса источника» могла стать любая строка.
# Без IPv4-маршрута спрашивается IPv6: на v6-only-сетях источник живёт там.
ROUTE_GET_V4_CMD = 'ip route get 1.1.1.1'
ROUTE_GET_V6_CMD = 'ip route get 2001:4860:4860::8888'


# Адреса, которые не могут быть настоящим исходящим адресом сервера в
# публичном интернете: RFC1918, CGNAT 100.64/10 (реальная практика хостинга),
# loopback/link-local и IPv6-ULA. Намеренно НЕ ipaddress.is_private: она
# считает «приватными» и служебно-документальные сети (TEST-NET и
# подобные), которых в природе как egress не бывает, — детектор ловил бы их,
# как ловят стендовые адреса в тестах, и путал служебное с операционным.
_EGRESS_INTERNAL_NETS = tuple(ipaddress.ip_network(p) for p in (
    '10.0.0.0/8', '100.64.0.0/10', '127.0.0.0/8', '169.254.0.0/16',
    '172.16.0.0/12', '192.168.0.0/16', '::1/128', 'fc00::/7', 'fe80::/10',
))


def _is_internal_addr(addr):
    """True для адресов «изнутри сети»: ответ внешнего сервиса с таким
    адресом означает split-horizon DNS или прозрачный прокси, а src с таким
    адресом — честный NAT-мир."""
    return any(addr in net for net in _EGRESS_INTERNAL_NETS)


def parse_route_get(out):
    """(src | '', dev | '') из строки `ip route get`.

    src обязан быть адресом (as_ip_address), а не первым токеном после «src»:
    вывод чужой машины — данные, а не доверенный результат. dev нужен сам по
    себе: маршрут «default dev eth0 scope link» шлюза «via» не имеет, прежний
    разбор оставлял default_iface=None и отчёт печатал «(интерфейс None)».
    """
    src = dev = ''
    tokens = (out or '').split()
    for i, tok in enumerate(tokens):
        if not src and tok == 'src' and i + 1 < len(tokens):
            src = as_ip_address(tokens[i + 1])
        elif not dev and tok == 'dev' and i + 1 < len(tokens):
            dev = tokens[i + 1]
    return src, dev


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

    out_get, err_get, rc_get = checker.run(ROUTE_GET_V4_CMD)
    src_ip, src_dev = parse_route_get(out_get)
    src_note = ''
    if not src_ip:
        out6, err6, rc6 = checker.run(ROUTE_GET_V6_CMD)
        src_ip, src_dev = parse_route_get(out6)
        if not src_ip:
            # Отсутствие источника — тоже ответ оператора, а не тишина:
            # молчаливая потеря строки неотличима от «так и надо».
            why = next((ln.strip() for ln in (err_get or '').splitlines()
                        if ln.strip()), '') or \
                next((ln.strip() for ln in (err6 or '').splitlines()
                      if ln.strip()), '')
            src_note = ('IP-адрес источника не определён: ip route get (v4 и v6) '
                        'не дал адреса src (rc=%s/%s)' % (rc_get, rc6)
                        + (': ' + why[:160] if why else ''))

    ext = probe_external_ip(checker)
    external_ip = ext['address']

    iface_src = src_dev or default_iface

    lines = []
    lines.append("=== СЕТЕВЫЕ ИНТЕРФЕЙСЫ (ip a) ===")
    lines.append(out_a)
    lines.append("\n=== МАРШРУТЫ (ip r) ===")
    lines.append(out_r)

    if default_iface:
        lines.append(f"\nИнтерфейс по умолчанию: {default_iface} (шлюз {default_gw})")
    if src_ip:
        lines.append(f"IP-адрес источника для исходящего трафика: {src_ip}"
                     + (f" (интерфейс {iface_src})" if iface_src else ''))
    elif src_note:
        lines.append(src_note)
    if external_ip:
        lines.append(f"Внешний (плавающий) IP: {external_ip}")
        try:
            ext_addr = ipaddress.ip_address(external_ip)
        except ValueError:
            ext_addr = None
        if ext_addr is not None and _is_internal_addr(ext_addr):
            # Сервис вернул адрес из приватного диапазона: домен ifconfig.me
            # резолвится внутри сети или по пути прозрачный прокси. Печатать
            # такое как «плавающий IP» без предупреждения — обещать оператору
            # поиск адреса, которого в публичном интернете нет.
            lines.append('  ⚠️ это приватный адрес, а не публичный: DNS сервиса '
                         'отвечает изнутри сети или по пути прозрачный прокси — '
                         'плавающим этот адрес не является')
        if src_ip and external_ip != src_ip:
            try:
                src_addr = ipaddress.ip_address(src_ip)
            except ValueError:
                src_addr = None
            if (src_addr is not None and ext_addr is not None
                    and src_addr.version != ext_addr.version):
                # Dual-stack: NAT по v4 + публичный v6. curl предпочёл v6 и
                # вернул 2001:…, а ip route get (v4) дал src 10.x — адреса из
                # РАЗНЫХ стеков. Стрелка «приватный 10.x -> плавающий 2001:…»
                # фабриковала бы NAT, которого в этом стеке нет.
                lines.append(f"  (адрес источника {src_ip} (v{src_addr.version}) и "
                             f"ответ сервиса {external_ip} (v{ext_addr.version}) — "
                             "разные адресные семьи: не сравниваются, NAT по этой "
                             "паре не определить)")
            elif src_addr is not None and _is_internal_addr(src_addr):
                iface_txt = (f' на интерфейсе {iface_src}' if iface_src else '')
                lines.append(f"  (трафик идёт через NAT: приватный IP {src_ip}{iface_txt} -> плавающий IP {external_ip})")
            else:
                # Источник публичный, но НЕ совпал с ответом сервиса: утверждать
                # «приватный IP ... -> плавающий» прежний код мог и про публичный
                # src. Различаются два мира (NAT/шлюз против нескольких публичных
                # адресов у сервера), и двумя числами они не разводятся.
                lines.append(f"  (адрес источника {src_ip} публичный, но отличается "
                             f"от ответа {external_ip}: либо по пути замена адреса "
                             "(шлюз/NAT провайдера), либо у сервера несколько "
                             "публичных адресов — по этим данным не различить)")
        elif src_ip and external_ip == src_ip:
            # Прежний код печатал «трафик идёт через NAT» при ЛЮБОМ src_ip,
            # то есть утверждал NAT и там, где сервер сам владеет публичным
            # адресом (источник совпал с ответом ifconfig.me).
            iface_txt = (f'интерфейса {iface_src}, ' if iface_src else '')
            lines.append(f"  (внешний адрес — собственный адрес "
                         f"{iface_txt}NAT в пути нет)")
        lines.append('')
        lines.append(interface_bind_note(checker, external_ip,
                                   iface_src))
    else:
        lines.append("\n" + external_ip_note(ext))

    return "\n".join(lines)


# ==================== ВНЕШНИЙ IP ====================
# Прежняя решалка спрашивала три утилиты ОДНОЙ ||-цепочкой через exec_command
# (код возврата выбрасывается в ssh_client.exec_command) и решала по непустоте
# stdout:
#
#     out_ext, _ = checker.exec_command('curl -s ifconfig.me 2>/dev/null || '
#                                       'wget -qO- ifconfig.me 2>/dev/null || '
#                                       'dig +short ... 2>/dev/null')
#     external_ip = out_ext.strip()
#
# Замер живьём на этой машине (curl, wget и dig УСТАНОВЛЕНЫ) дал три мира, в
# которых отчёт печатал мусор как находку:
#
#   PATH без curl      -> цепочка уходит в wget: rc=0, stdout='<<!DOCTYPE html>…'
#       => «Внешний (плавающий) IP: <!DOCTYPE html>» — страница выдана за адрес;
#   PATH без curl/wget -> dig при недоступном резолвере пишет диагностику в
#       STDOUT с rc=9 => «Внешний (плавающий) IP: ;; communications error…»;
#   всё установлено, сети нет: curl rc=6, а -s глушит причину ЦЕЛИКОМ (оба
#       канала пусты) => строка советует «установите curl/wget/dig» там, где
#       всё уже установлено, и оператор едет ставить пакеты.
#
# Конвейер || делал хуже: на rc=0 он останавливается, поэтому при curl, ушедшем
# rc=0 с пустым выводом (замер заглушкой) wget и dig не спрашивались вовсе —
# «не спросили» выглядело как «спросили и не получили ответа».
#
# Форма -sS вместо -s: замер — `curl -sS` даёт 'curl: (6) Could not resolve
# host: …' в stderr при том же rc=6, тогда как `curl -s` оставляет оба канала
# пустыми. Причина обязана доезжать: отрицание без причины в этой серии не
# печатается.
#
# command_probe_info (1.32.11) и web_config_probe (1.32.25) здесь НЕ
# переиспользуются: тем же байтом задают ДРУГОЙ вопрос. Веб-конфигу достаточно
# ПЕРВОГО ответа (текст ошибки сервера и есть находка), внешнему IP нужен
# именно валидный адрес, поэтому обход идёт до первой строки, которой хватит
# быть адресом, а причины остальных отказов сохраняются для строки отрицания.
# Таймаут на каждой пробе, и двумя слоями. ServerChecker._exec читает канал до
# EOF (ssh_client.py stream.read без дедлайна), так что зависшее соединение с
# ifconfig.me вешало бы рабочий поток GUI до нажатия «Стоп»; конвенция проекта
# — внешний обёртка `timeout N` (discovery.py, webcheck.py). Родной флаг
# утилиты (--max-time / -T / +time=) кладёт первый слой: утилита сама выходит
# с rc=28/таймаут и ПЕЧАТАЕТ причину, тогда как `timeout` убивает процесс с
# rc=124 и без внятного stderr — обёртка страхует зависание самой утилиты.
# Короткие флаги wget (-T -t), а не длинные (--timeout --tries): fallback-мир
# «curl нет» — это минимальные образы с BusyBox, где длинных опций нет.
EXTERNAL_IP_SOURCES = (
    # https, а не голый http: MITM по пути подменил бы «внешний IP» и тем
    # самим сфабриковал вывод NAT/привязки в network_report. TLS-сертификат
    # сервиса — якорь доверия; dig остался UDP-дугом сознательно (третий
    # fallback, его честность — отдельный разговор про DNSSEC).
    ('curl', 'timeout 12 curl -sS --max-time 8 https://ifconfig.me'),
    ('wget', 'timeout 12 wget -qO- -T 5 -t 1 https://ifconfig.me'),
    ('dig', 'timeout 10 dig +short +time=2 +tries=1 myip.opendns.com '
            '@resolver1.opendns.com'),
)


def as_ip_address(text):
    '''Первая непустая строка ответа как IP-адрес, если он им является.

    Решать непустотой нельзя (замеры выше): вывод утилиты — это HTML, диагностика
    резолвера или адрес, и все три варианта непустые. Признак — сам адрес,
    проверка стандартной библиотекой, без разбора форматов чужих утилит.
    '''
    lines = [l.strip() for l in (text or '').strip().splitlines() if l.strip()]
    if not lines:
        return ''
    try:
        return str(ipaddress.ip_address(lines[0]))
    except ValueError:
        return ''


def parse_external_ip_probe(out, err, rc):
    '''('address'|'not_address'|'failed'|'absent'|'unchecked', адрес, причина).

    Пять состояний, а не два. Причина берётся ТОЛЬКО из stderr: stdout — тело
    ответа утилиты, и печатать его в строке отрицания нельзя, иначе диагностика
    («;; communications error…», HTML) уедет в отчёт второй раз — уже в другом
    качестве. Отсутствие доказывает код возврата оболочки (rc=127/126), а не
    пустой вывод.
    '''
    def first_line(text):
        lines = (text or '').strip().splitlines()
        return lines[0][:160] if lines else ''

    out_t = (out or '').strip()
    err_t = (err or '').strip()
    if rc == 127 or rc == 126:
        return 'absent', '', first_line(err_t or out_t) or ('rc=%s' % rc)
    if rc == 124:
        # Убийство обёрткой `timeout`: процесс не успел ответить. Это отказ с
        # причиной «точка недоступна», а не «утилиты нет»; убитый процесс
        # stderr написать не успел, поэтому текст даём сами, иначе оператор
        # увидел бы голое «rc=124».
        return 'failed', '', ('ответ не получен: проверка прервана '
                              'таймаутом (rc=124)')
    if rc == 0:
        if not out_t:
            return 'unchecked', '', 'пустой ответ (rc=0)'
        address = as_ip_address(out_t)
        if address:
            return 'address', address, None
        return 'not_address', '', 'ответ не является адресом'
    return 'failed', '', first_line(err_t) or ('rc=%s' % rc)


def probe_external_ip(checker):
    '''Внешний IP: {'address', 'notes', 'absent', 'asked', 'all_absent'}.

    Утилиты спрашиваются раздельно и обход продолжается, пока не найден адрес:
    отказ одной — не повод утверждать, что адреса нет, и не повод молчать о
    причине остальных.
    '''
    address = ''
    notes = []
    absent = []
    asked = 0
    for name, cmd in EXTERNAL_IP_SOURCES:
        out, err, rc = checker.run(cmd)
        asked += 1
        state, addr, why = parse_external_ip_probe(out, err, rc)
        if state == 'address':
            address = addr
            break
        if state == 'absent':
            absent.append(name)
            note = '%s не найдена' % name
            # Команда обёрнута в `timeout`, и rc=127 принадлежит ОБОЛОЧКЕ
            # обёртки: на машине без coreutils-`timeout` отчёт сказал бы «curl
            # не найдена» при установленном curl. Если stderr не назвал саму
            # утилиту — причина обязана доехать, иначе оператор поедет ставить
            # не тот пакет.
            if why and name not in why:
                note += ' (%s)' % why
            notes.append(note)
        elif why and why.startswith(name):
            notes.append(why)
        else:
            notes.append('%s: %s' % (name, why or state))
    return {'address': address, 'notes': notes, 'absent': absent,
            'asked': asked,
            'all_absent': bool(absent) and len(absent) == asked}


def external_ip_note(probe):
    '''Отрицание с причиной; «установите» — только когда ставить нечего.

    Прежняя строка содержала совет установить на всех мирах сразу, поэтому в
    мире «всё установлено, сети нет» она отправляла оператора ставить пакеты.
    '''
    if probe['all_absent']:
        # Причины обязаны доехать и здесь: без бинарника `timeout` все три
        # rc=127 принадлежат ОБОЛОЧКЕ, а не утилитам, — голое «установите
        # curl/wget/dig» отправило бы оператора ставить установленные пакеты,
        # тогда как notes уже кричат «timeout: command not found».
        detail = '; '.join(probe['notes']) if probe['notes'] else ''
        return ('Внешний IP не удалось определить: ни одна утилита не найдена ('
                + ', '.join(name for name, _cmd in EXTERNAL_IP_SOURCES)
                + ') — установите любую из них'
                + (': ' + detail if detail else ''))
    reasons = probe['notes']
    if not reasons:
        # Пустой список причин — это тоже отрицание, и оно обязано
        # читаться: без ветки функция печатала «...: » с пустым
        # перечислением (замер живьём 1.32.26).
        reasons = ['утилиты не дали ответа']
    return ('Внешний IP не удалось определить: ' + '; '.join(reasons))


# ==================== ПРИВЯЗКА ПЛАВАЮЩЕГО IP К ИНТЕРФЕЙСУ (1.32.30) ==========
# Внешний IP из ifconfig.me — это ответ ДРУГОЙ машины: где живёт сам адрес,
# знает только сервер. `ip -o addr` — один запрос, одна строка на адрес:
# с -o переносов внутри записи нет, и разбор не зависит от ширины терминала
# (без -o continuation-строки с valid_lft лезут в разбор отдельными
# записями).
IP_ADDR_CMD = 'ip -o addr'
# Второй источник тех же адресов, когда бинарника `ip` нет вовсе (минимальные
# образы и очень старые системы, где остались только net-tools): честный ответ
# лучше честного «не проверено», а спросить больше нечего.
IFCONFIG_CMD = 'ifconfig -a'


def parse_interface_addresses(out):
    """{адрес: [(имя_интерфейса, scope), ...]} из вывода `ip -o addr`.

    Строка формата `2: eth0    inet 10.0.0.5/24 brd ... scope global eth0\\`:
    имя — второй токен, адрес — токен после inet/inet6 (префикс срезан),
    scope — токен после слова scope. Неадресуемые токены пропускаются, а не
    роняют разбор: вывод чужой машины подтверждать ipaddress дороже, чем
    молча пропустить мусор.
    """
    mapping = {}
    for line in (out or '').splitlines():
        tokens = line.split()
        if len(tokens) < 4:
            continue
        iface = tokens[1]
        for j, tok in enumerate(tokens):
            if tok not in ('inet', 'inet6') or j + 1 >= len(tokens):
                continue
            raw = tokens[j + 1].split('/', 1)[0]
            # fe80::1%eth0 — зона в скоуп-айди не адрес; сверять будем тело.
            body = raw.split('%', 1)[0]
            try:
                addr = str(ipaddress.ip_address(body))
            except ValueError:
                continue
            scope = ''
            if 'scope' in tokens and tokens.index('scope') + 1 < len(tokens):
                scope = tokens[tokens.index('scope') + 1]
            entry = (iface, scope)
            if entry not in mapping.setdefault(addr, []):
                mapping[addr].append(entry)
    return mapping


IFCONFIG_BLOCK_RE = re.compile(r'^([A-Za-z0-9._-]+?):(\s|$)')


def parse_ifconfig_addresses(out):
    """{адрес: [(имя, ''), ...]} из вывода `ifconfig -a` — второй источник.

    Две эпохи net-tools: старая печатает заголовок «eth0      Link encap:...»
    и адрес «inet addr:10.0.0.5  Mask:...», новая — заголовок «eth0: flags=»
    и адрес «inet 10.0.0.5 netmask ...»; то же для inet6 (ещё и зона
    «fe80::1%eth0»). Алиас eth0:0 — отдельным блоком, адрес записывается на
    родительский интерфейс: так же делает разбор `ip -o addr`, где алиас —
    secondary-запись того же eth0. Scope у ifconfig нет, поле остаётся
    пустым — решение о привязке на нём не строится.
    """
    mapping = {}
    iface = ''
    for line in (out or '').splitlines():
        if line[:1] not in (' ', '\t', ''):
            head = IFCONFIG_BLOCK_RE.match(line)
            if head:
                iface = head.group(1)
            elif 'Link encap' in line:
                # Старые net-tools: «eth0      Link encap:Ethernet» — имени с
                # двоеточия нет, берётся первый токен строки-заголовка.
                iface = line.split()[0]
        if not iface:
            continue
        tokens = line.split()
        for i, tok in enumerate(tokens):
            raw = ''
            if tok in ('inet', 'inet6') and i + 1 < len(tokens):
                raw = tokens[i + 1]
                # Старые net-tools печатают inet6 с оторванным маркером:
                # «inet6 addr: fe80::1/64» — адрес стоит ПОСЛЕ tok'ена 'addr:'.
                if raw == 'addr:' and i + 2 < len(tokens):
                    raw = tokens[i + 2]
            elif tok.startswith('addr:'):
                raw = tok[len('addr:'):]
            if not raw:
                continue
            raw = raw.split('addr:', 1)[-1]
            body = raw.split('/', 1)[0].split('%', 1)[0]
            try:
                addr = str(ipaddress.ip_address(body))
            except ValueError:
                continue
            entry = (iface, '')
            if entry not in mapping.setdefault(addr, []):
                mapping[addr].append(entry)
    return mapping


def interface_bind_note(checker, external_ip, default_iface=None):
    """Где живёт внешний адрес: интерфейс, NAT провайдера или «не спросили».

    Три мира, и третий — не два первых:
    * адрес на интерфейсе (или нескольких) — плавающий назначен серверу;
    * адреса нет ни на одном интерфейсе — адрес реализован ВНЕ сервера
      (provider NAT / DNAT / балансировщик), на сервере его «нет и быть не
      должно» — это ответ, а не отказ;
    * список адресов не прочитан (rc!=0 или rc=0 без единой записи) —
      о привязке ничего не известно. Прежняя логика «пусто -> NAT» выла бы
      третий мир за второй: `ip` без прав, bus-мёртвый netlink и пустой
      вывод дают тот же ноль адресов, что и настоящая отсутствующая привязка.

    Когда бинарника `ip` нет (rc=127/126 — доказательство отсутствия, а не
    отказа спрашивать), адреса спрашиваются у `ifconfig -a`: на старых и
    минимальных машинах это второй честный источник, и «не проверено» там,
    где ответ был доступен, — тоже ложь (зеркальный мир внешнего IP, где
    curl меняется wget).
    """
    out, err, rc = checker.run(IP_ADDR_CMD)
    tool = '`ip -o addr`'
    ip_absent = rc in (127, 126)
    if ip_absent:
        tool = '`ifconfig -a`'
        out, err, rc = checker.run(IFCONFIG_CMD)
    if rc != 0:
        why = next((ln.strip() for ln in (err or '').splitlines() if ln.strip()),
                   f'код возврата {rc}')[:160]
        return (f'⚠️ Привязка {external_ip} к интерфейсу не проверена: '
                + ('бинарника `ip` нет, и ' if ip_absent else '')
                + f'{tool} не ответила (rc={rc}): {why} — это «не '
                  'проверено», а не «адреса нет на интерфейсах»')
    mapping = (parse_ifconfig_addresses(out) if ip_absent
               else parse_interface_addresses(out))
    if not mapping:
        return (f'⚠️ Привязка {external_ip} к интерфейсу не проверена: '
                + ('бинарника `ip` нет, и ' if ip_absent else '')
                + f'{tool} вернула 0 без единого адреса — это «не '
                  'проверено», а не «адреса нет на интерфейсах»')
    # Ключи mapping нормализованы ipaddress (IPv6 — lowercase сжатый). Внешний
    # адрес в штатном пути пришёл уже нормализованным (as_ip_address), но
    # функция публичная: сырой «2001:DB8::1» или полная форма IPv6 не совпали
    # бы с ключом и прочитались как «адрес вне сервера» — ложь о NAT.
    try:
        probe_addr = str(ipaddress.ip_address(str(external_ip).strip()))
    except ValueError:
        return (f'⚠️ Привязка {external_ip} к интерфейсу не проверена: «{external_ip}» '
                'не является адресом — это «не проверено», а не «адреса нет»')
    entries = mapping.get(probe_addr)
    if entries:
        where = ', '.join(f'{iface} (scope {scope})' if scope else iface
                          for iface, scope in entries)
        return (f'✅ Плавающий IP {external_ip} назначен интерфейсу: {where}'
                + ('' if len(entries) == 1 else
                   ' — адрес на нескольких интерфейсах'))
    iface_count = len({iface for addrs in mapping.values()
                       for iface, _scope in addrs})
    return (f'ℹ️ Адрес {external_ip} не назначен ни одному интерфейсу сервера '
            f'(просмотрено {iface_count}) — адрес реализован вне сервера: '
            'provider NAT / DNAT / балансировщик. На самом сервере его и не '
            'может быть: искать ifcfg-строку с ним бесполезно.'
            + (f' Исходящий трафик идёт через {default_iface}.'
               if default_iface else ''))


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
        if status is None:
            # Ответ системы не дошёл (bus dead): признаться СЛОВОМ, а не
            # напечатать 'None' и не выдумать диагноз (1.32.29).
            status = UNIT_NO_ANSWER
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


# ==================== ТЕСТ СКОРОСТИ ДИСКА (1.32.31) ====================
# Зачем отдельная проба: get_metrics() показывает df/free/uptime, но не цену
# записи. «Сервер тормозит» на RAID с севшим диском и на загруженном I/O
# выглядит одинаково по метрикам — различает их фактическая скорость.
#
# Почему ЗАПИСЬ, а не чтение: первое же чтение оставляет файл в page cache, и
# второй прогон меряет оперативную память, а не диск (цифра врёт в десятки раз).
# conv=fsync заставляет dd дождаться реального сброса на носитель: без него
# замер останавливается на контроллере кеша и показывает скорость RAM.
#
# Файл — путь со случайным суффиксом на прогон. Фиксированное имя было бы
# гонкой с широким окном: между съёмом остатка и `dd` лежит отдельный SSH-запрос
# (`df -k`), то есть десятки миллисекунд, а dd работает рутом и льёт 128 МБ
# нулей — symlink, посаженный в это окно локальным пользователем, обнулил бы
# ЛЮБОЙ файл системы. Съём остатка ДО замера остаётся (от прошлого прогона мог
# остаться наш же файл), но защищаться им больше нечем не заменяется. Уборка —
# каналом cleanup с проверкой факта `[ -e ]`, как секреты серии: отмена посреди
# замера не должна оставить 128 МБ в /tmp.
SPEED_TMP_BASE = '/tmp/.techsupp_speed'
SPEED_MB = 128


def speed_tmp_path():
    """Имя тестового файла на один прогон: /tmp/.techsupp_speed.<12 hex>.bin."""
    return '%s.%s.bin' % (SPEED_TMP_BASE, uuid4().hex[:12])


# Съём остатков прошлых прогонов. ГЛОБ идёт в команду неэкранированным —
# сознательно: это константа модуля, а не ввод оператора, и в кавычках она
# перестала бы быть глобом. `ls` после `rm` — проверка факта, а не кода
# возврата: rm не ругается даже на то, чего нет. Пустой stdout означает «в
# префиксе ничего не осталось».
SWEEP_SPEED_CMD = ('rm -f ' + SPEED_TMP_BASE + '.*.bin 2>/dev/null; '
                   'ls -1 ' + SPEED_TMP_BASE + '.*.bin 2>/dev/null')


# `timeout` — конвенция проекта для команд без собственного дедлайна: dd не
# умеет ограничивать себя, а висящий на умершенном I/O носитель процесс
# держал бы канал (и поток GUI) до «Стоп». Убийство даёт rc=124 — парсер
# читает его как «не измерено», файл снимает уборка.
# env ОБЯЗАТЕЛЕН: shell разбирает присваивание LC_ALL=C только перед самим
# командным словом, а здесь первое слово — `timeout`; без env он принял бы
# «LC_ALL=C» за имя программы и вышел бы rc=126/127 (замер живьём, coreutils
# 9.11: `timeout 5 LC_ALL=C echo ok` → «не удалось выполнить команду»).
DD_WRITE_TPL = ("timeout 120 env LC_ALL=C dd if=/dev/zero of={p} bs=1M "
                "count={n} conv=fsync 2>&1")
# Чтение мимо page cache (O_DIRECT) — для ручного повтора; продукт Writes-only
# (чтение после записи меряет кеш, а не диск). iflag=direct не всякая ФС
# держит — потому это подсказка оператору, а не второй обязательный прогон.
DD_READ_TPL = ("timeout 120 env LC_ALL=C dd if={p} of=/dev/null bs=1M "
               "iflag=direct")


def dd_write_cmd(path, size_mb=SPEED_MB):
    """Команда замера записи для файла конкретного прогона."""
    return DD_WRITE_TPL.format(p=q(path), n=size_mb)


def dd_read_cmd(path):
    """Команда чтения мимо кеша для файла конкретного прогона."""
    return DD_READ_TPL.format(p=q(path))


# Тип ФС под /tmp спрашивается ДО замера: на systemd-дистрибутивах /tmp по
# умолчанию tmpfs, dd пишет в память, conv=fsync там ничего не ждёт — и в
# отчёт едет скорость RAM с вердиктом про NVMe. `stat -f -c %T` есть и у GNU,
# и у BusyBox; `df -PT` — fallback (колонка Type вторая, -P запрещает перенос
# длинного имени устройства). Пустой ответ — «тип не определён», предупреж-
# дения тогда нет: выдумывать тип ФС нельзя, как и цифру.
RAM_FILESYSTEMS = ('tmpfs', 'ramfs')
STAT_FSTYPE_CMD = 'stat -f -c %T /tmp'
DF_FSTYPE_CMD = 'df -PT /tmp'


def parse_fstype(out_stat, rc_stat, out_df, rc_df):
    """Имя ФС /tmp (в нижнем регистре) или '' — «не спрашивали/не удалось»."""
    if rc_stat == 0 and (out_stat or '').strip():
        return (out_stat or '').strip().splitlines()[-1].strip().lower()
    if rc_df == 0:
        for line in reversed((out_df or '').splitlines()):
            tokens = line.split()
            # -PT даёт 7 колонок; шапка тоже семь, её выдаёт слово Type.
            if len(tokens) >= 7 and tokens[1].lower() != 'type':
                return tokens[1].lower()
    return ''


# Сколько места требовать под тест: сам файл плюс запас (другой процесс пишет
# параллельно, ext4 резервирует 5% под root).
DF_FREE_CMD = 'df -k -P /tmp'
DF_HEADROOM_MB = 32

# dd печатает статистику в stderr (мы слили её в stdout через 2>&1). Формат
# хвоста: '... copied, 0.394 s, 341 MB/s'. Единицы SI (B,kB,MB,GB) или IEC
# (KiB,MiB,GiB). LC_ALL=C фиксирует десятичную точку и латиницу; без него на
# локали с запятой число разбирается неверно.
DD_SPEED_RE = re.compile(r'([0-9]+(?:\.[0-9]+)?)\s*([kKMGT]?i?B)/s')
_BYTE_UNITS = {
    'B': 1.0, 'kB': 1e3, 'KB': 1e3, 'MB': 1e6, 'GB': 1e9, 'TB': 1e12,
    # 'KB' — то же значение, что 'kB': старые сборки wget/busybox печатают
    # прогресс заглавной K; отказ «неизвестная единица» на законном выводе
    # был бы честнее только на бумаге.
    'KiB': 1024.0, 'MiB': 1024.0 ** 2, 'GiB': 1024.0 ** 3,
    'TiB': 1024.0 ** 4,
}


def parse_dd_speed(out, err, rc):
    """(MB/с | None, признание|None) по отчёту dd.

    Решает код: rc!=0 — тест не завершён (conv=fsync не поддержан, кончилось
    место, отмена оборвала канал => rc=-1), и это «не измерено», а не «ноль».
    rc=0 без строки скорости — тоже «не измерено»: выдумывать цифру по
    неполному выводу нельзя (закон серии про пустой вывод).
    """
    text = (out or '') + (err or '')
    if rc == 124:
        # Убийство обёрткой `timeout`: зависший носитель. Частичные статистики
        # dd печатать бессмысленно — цифра по оборванному замеру врёт бы.
        return None, ('dd не уложился в таймаут (rc=124) — диск, '
                      'вероятно, завис; замер прерван')
    if rc != 0:
        why = next((ln.strip() for ln in text.splitlines() if ln.strip()),
                   '')[:160]
        return None, 'dd вернул rc=%s%s' % (
            rc, (': ' + why) if why else '')
    found = DD_SPEED_RE.findall(text)
    if not found:
        return None, 'dd не вернул строку скорости (rc=0)'
    value, unit = found[-1]
    factor = _BYTE_UNITS.get(unit)
    if not factor:
        return None, 'неизвестная единица скорости dd: %s' % unit
    mb = (float(value) * factor) / 1e6
    if mb <= 0:
        # rc=0 и ноль — это отказ подсистемы (например, дырявый FS, съевший
        # запись), а не результат: «0.0 MB/s» в графе «скорость» оператор
        # прочитает как измеренную скорость канала записи.
        return None, 'dd сообщил нулевую скорость (rc=0) — это отказ, а не результат'
    return mb, None


def parse_df_free_mb(out, rc):
    """Свободно МБ на файловой системе df -k, либо None («не спросили»).

    POSIX-колонка 4 — Available в 1024-байтовых блоках; df длинное имя
    устройства переносит на вторую строку (5 полей), поэтому ищется последняя
    строка не короче 6 полей. None — это «препроверка не состоялась»: её
    отказ НЕ даёт права отменять тест (сам dd честно упадёт с причиной), но и
    права писать цифру без цифры тоже нет.
    """
    if rc != 0:
        return None
    for line in reversed((out or '').splitlines()):
        tokens = line.split()
        if len(tokens) >= 6:
            try:
                return int(tokens[3]) // 1024
            except ValueError:
                return None
    return None


def disk_speed_test(checker):
    """Замер скорости записи: dd пишет SPEED_MB МБ с fsync, файл убирается."""
    lines = ["=== ТЕСТ СКОРОСТИ ДИСКА (dd: запись %d МБ, conv=fsync) ==="
             % SPEED_MB]
    target = speed_tmp_path()
    write_cmd = dd_write_cmd(target)
    read_cmd = dd_read_cmd(target)
    # Снять возможный остаток прошлых прогонов ДО записи: по чужому файлу или
    # symlink идти dd нельзя.
    out_sweep, _err_sweep, _rc_sweep = checker.run(SWEEP_SPEED_CMD)
    left = (out_sweep or '').strip()
    if left:
        lines.append('❌ старую тестовую запись не снять: '
                     + ', '.join(left.splitlines()[:3])
                     + ' — тест отменён')
        return "\n".join(lines)

    # Место спрашивается ПОСЛЕ съёма остатка (иначе сами себе съели) и ДО
    # записи: на забитом диске dd дописал бы до отказа и бросил бы файл, а
    # честный отказ «No space left» оператор прочитал бы только через минуту
    # гонки. Неотвечающий df (rc!=0, мусор в выводе) — не право отменять:
    # тогда пусть честно падает сам dd.
    out_df, _err_df, rc_df = checker.run(DF_FREE_CMD)
    free_mb = parse_df_free_mb(out_df, rc_df)
    if free_mb is not None and free_mb < SPEED_MB + DF_HEADROOM_MB:
        lines.append(f'❌ тест отменён ДО записи: в /tmp свободно {free_mb} МБ, '
                     f'нужно не менее {SPEED_MB + DF_HEADROOM_MB} МБ '
                     f'(файл {SPEED_MB} МБ плюс запас) — освободите место')
        return "\n".join(lines)

    # Тип ФС — до замера: предостережение обязано стоять НАД цифрой, чтобы
    # оператор читал «tmpfs» раньше, чем увидит «NVMe — отлично».
    out_fs, _err_fs, rc_fs = checker.run(STAT_FSTYPE_CMD)
    out_dft, _err_t, rc_dft = checker.run(DF_FSTYPE_CMD)
    fs_type = parse_fstype(out_fs, rc_fs, out_dft, rc_dft)
    if fs_type in RAM_FILESYSTEMS:
        lines.append('⚠️ /tmp живёт в оперативной памяти (' + fs_type +
                     '): цифра ниже — скорость RAM, а не диска')

    out, err, rc = checker.run(write_cmd)
    mb, note = parse_dd_speed(out, err, rc)
    if mb is None:
        lines.append('❌ Скорость записи не измерена: ' + note)
        tail = '\n'.join(l for l in ((out or '') + (err or '')).splitlines()
                         if l.strip())
        if tail:
            lines.append('  отклик dd: ' + tail[-240:])
    elif fs_type in RAM_FILESYSTEMS:
        # Вердикт про NVMe/SSD/HDD тут был бы ложью: сравнивать не с чем.
        lines.append('✅ Скорость записи: %.1f MB/s '
                     '(tmpfs — не интерпретируется как скорость диска)' % mb)
    else:
        lines.append('✅ Скорость записи: %.1f MB/s (%s)' % (
            mb, _speed_verdict(mb)))

    # Уборка — всегда, каналом cleanup: отмена или неудача замера не право
    # оставить SPEED_MB МБ в /tmp. Причина обязана дойти до оператора.
    ok, why = remove_remote_path(checker, target, recursive=False)
    if not ok:
        lines.append('⚠️ тестовый файл не удалён: ' + why
                     + ' — удалите вручную: rm -f ' + target)
    lines.append('')
    lines.append('Команды для ручного повтора (тот же прогон без утилиты):')
    lines.append('  ' + write_cmd)
    lines.append('  ' + read_cmd)
    lines.append('    (тестовый файл уже снят уборкой — сначала повторите '
                 'запись; чтение мимо кеша, если ФС не поддерживает '
                 'O_DIRECT — без iflag=direct цифра будет скоростью page cache)')
    return "\n".join(lines)


def _speed_verdict(mb_per_s):
    """Бытовая оценка скорости записи для человека, а не голое число."""
    if mb_per_s >= 200:
        return 'NVMe/SSD — отлично'
    if mb_per_s >= 80:
        return 'быстрый SSD'
    if mb_per_s >= 30:
        return 'SSD ниже ожидаемого или диск загружен'
    if mb_per_s >= 8:
        return 'похоже на HDD'
    return 'очень медленно — проверьте диск (degraded RAID? I/O wait?)'


# ==================== ТЕСТ СКОРОСТИ СЕТИ (1.32.31) ====================
# Два разных вопроса, две пробы:
#   * ЗАДЕРЖКА (ping): «тормоза» в SSH и отклике — это latency и потерянные
#     пакеты, их не видно в скорости канала;
#   * ПРОПУСКНАЯ СПОСОБНОСТЬ (скачивание): «медленные загрузки» — это bitrate.
# ping решает потерями и средним RTT; curl — %{speed_download} (байт/с),
# который НЕ зависит от локали (в отличие от прогресс-строк wget). Утилиты
# спрашиваются раздельно, как внешний IP: отсутствие ping — не «нет сети», а
# «не спросили задержку», и не снимает замер пропускной способности.
# LC_ALL=C обязателен и пингу: в локализованном выводе iputils строка потерь
# печатается переведённой («потерь»), а разделитель дробной части в RTT —
# запятая, и регулярки разбора не совпадают; молчание regex отчёт прочитал бы
# как «RTT-строки не было». `timeout` — общий конвенционный предохранитель
# (зависание на маршрутизаторе держало бы канал до «Стоп»).
PING_CMD = 'timeout 20 env LC_ALL=C ping -c 4 -W 3 1.1.1.1'
NET_TEST_URL = 'https://speed.cloudflare.com/__down?bytes=50000000'
# curl: -f — чтобы 403/5xx НЕ считались успешным скачиванием (без -f curl
# выходит rc=0 с телом страницы отказа, и speed_download меряет скорость
# бан-страницы — «канал» из байтов ошибки); -L — редирект тоже канал, а без
# -L его байты (несколько килобайт 301) выдавались бы за скорость; -sS —
# причина без прогресс-мусора; --max-time 30 — потолок гонки, а `timeout 45`
# — страховка на случай зависания самой утилиты (rc=124 vs собственный
# rc=28 с числом-нижнеграницей на stdout).
# wget: короткие -T/-t — длинные --timeout/--tries отсутствуют в BusyBox
# wget, а fallback-мир «curl нет» — это именно минимальные образы.
NET_DOWNLOAD_SOURCES = (
    ('curl', "timeout 45 env LC_ALL=C curl -sSfL -o /dev/null "
             "-w '%{speed_download}' --max-time 30 " + q(NET_TEST_URL)),
    # wget — второй, когда curl нет: скорость берётся из прогресс-строки
    # '12.3 MB/s' (единицы те же, что разбирает DD_SPEED_RE).
    ('wget', 'timeout 45 env LC_ALL=C wget -T 25 -t 1 -O /dev/null '
             + q(NET_TEST_URL) + ' 2>&1'),
)
# Строка итога ping (iputils): 'rtt min/avg/max/mdev = 11.1/12.3/... ms';
# старые версии пишут 'round-trip ... = ...'. Ищем числа после '=' и берём
# второе (avg), не завязываясь на префиксе.
PING_AVG_RE = re.compile(r'=\s*([0-9]+(?:\.[0-9]+)?)/([0-9]+(?:\.[0-9]+)?)')
PING_LOSS_RE = re.compile(r'([\d.]+)%\s*packet loss')


def parse_ping_latency(out, err, rc):
    """(avg_ms | None, note): (avg задержки, потеря ли) по отклику ping.

    rc=1 при 100% потерь — это измеренное «хост не отвечает», а не отказ
    инструмента: отличие от rc=127 (ping не установлен) принципиально.
    Строка потерь читается ДО ветки rc!=0: при 100% потерь RTT-строки нет, и
    без этого порядка единственный содержательный ответ хоста
    («0 received, 100% packet loss») тонул бы в «первой непустой строке»
    вывода, которой обычно является шапка «PING 1.1.1.1 … bytes of data».
    """
    text = (out or '') + (err or '')
    if rc == 127 or rc == 126:
        return None, 'ping не найден (rc=%s) — задержка не проверена' % rc
    if rc == 124:
        return None, ('ping не уложился в таймаут (rc=124) — '
                      'задержка не измерена')
    loss = PING_LOSS_RE.search(text)
    if loss and float(loss.group(1)) >= 100:
        # Бывший текст 'потеряно 100%% пакетов' печатался как есть: строковый
        # литерал не проходил через оператор %, и оператор видел двойной
        # процент.
        return None, ('потеряно 100% пакетов — хост не отвечает '
                      'или ICMP фильтруется')
    avg = PING_AVG_RE.search(text)
    if avg:
        val = float(avg.group(2))
        return val, (('потери %s%% пакетов' % loss.group(1))
                     if loss and float(loss.group(1)) > 0 else None)
    if rc != 0:
        why = next((ln.strip() for ln in text.splitlines() if ln.strip()),
                   '')[:160]
        return None, 'ping вернул rc=%s%s — задержка не измерена' % (
            rc, (': ' + why) if why else '')
    return None, 'ping не вернул строку RTT (rc=0)'


def parse_download_speed(out, err, rc, source):
    """(MB/с | None, note): битрейт скачивания из ответа источника.

    curl отдаёт %{speed_download} как чистое число байт/с в stdout (локале не
    подвержен); wget — единицы в прогресс-строке. Решает код: rc!=0 — канал не
    прошёл (нет сети, 4xx/5xx — с -f они коды, а не «успех», отмена =>
    таймаут), это «не измерено». Два исключения из того же закона честности:
    rc=28 (лимит --max-time) с числом на stdout — это нижняя граница канала
    за 30 секунд, а не провал: цифра доезжает с пометкой; ноль при rc=0 —
    сервис отдал 0 байт, «0 МБ/с» результатом быть не может.
    """
    if rc == 127 or rc == 126:
        return None, '%s не найден (rc=%s)' % (source, rc)
    body = (out or '').strip()
    if rc in (28, 124) and source == 'curl':
        # curl при --max-time печатает speed_download оборванного переноса —
        # сколько канал реально тянул все 30 секунд. Отказаться от этого числа
        # значило бы «не измерено» там, где канал ответил; выдать его без
        # пометки — соврать про потолок. rc=124 (убит обёрткой `timeout` уже
        # после curl-ного лимита — завис сам вывод/канал) — тот же мир: число
        # на stdout есть, и оно нижняя граница, а не «нет результата».
        try:
            val = float(body)
        except ValueError:
            val = 0.0
        if val > 0:
            return val / 1e6, ('скачивание прервано лимитом — это нижняя '
                               'граница канала, не вся его скорость')
    if rc == 124:
        return None, ('%s не уложился в таймаут (rc=124) — канал '
                      'не измерен' % source)
    if rc != 0:
        text = (out or '') + (err or '')
        why = next((ln.strip() for ln in text.splitlines() if ln.strip()),
                   '')[:160]
        return None, '%s вернул rc=%s%s' % (source, rc,
                                            (': ' + why) if why else '')
    if source == 'curl':
        try:
            val = float(body)
        except ValueError:
            return None, 'curl не вернул число скорости (rc=0)'
        if val <= 0:
            return None, ('curl сообщил нулевую скорость (rc=0) — сервер отдал '
                          'пустой ответ, это не результат пропускной способности')
        return val / 1e6, None
    found = DD_SPEED_RE.findall(body)
    if not found:
        return None, 'wget не вернул строку скорости (rc=0)'
    value, unit = found[-1]
    factor = _BYTE_UNITS.get(unit)
    if not factor:
        return None, 'wget вернул неизвестную единицу: %s' % unit
    mbps = (float(value) * factor) / 1e6
    if mbps <= 0:
        return None, 'wget сообщил нулевую скорость (rc=0) — это не результат'
    return mbps, None


def network_speed_test(checker):
    """Задержка (ping) + пропускная способность (скачивание), каждая проба
    независима: отсутствие одной не глушит другую."""
    lines = ["=== ТЕСТ СКОРОСТИ СЕТИ (задержка + входящий канал) ==="]

    out, err, rc = checker.run(PING_CMD)
    ms, note = parse_ping_latency(out, err, rc)
    if ms is None:
        lines.append('⚠️ Задержка: ' + note)
    else:
        verdict = ('отлично' if ms < 20 else 'нормально' if ms < 80
                   else 'высокая' if ms < 150 else 'очень высокая')
        line = '✅ Задержка (avg): %.1f мс — %s' % (ms, verdict)
        if note:
            line += ' (⚠️ ' + note + ')'
        lines.append(line)

    mbps = None
    dl_note = ''
    for source, cmd in NET_DOWNLOAD_SOURCES:
        out, err, rc = checker.run(cmd)
        mbps, note = parse_download_speed(out, err, rc, source)
        if mbps is not None:
            break
        dl_note += (dl_note and '; ') + note
    if mbps is None:
        lines.append('⚠️ Входящий канал не измерен: ' + dl_note)
    else:
        # note у успеха — пометка к цифре (например «нижняя граница» после
        # rc=28); выбросить её значило бы выдать половину за целое.
        line = '✅ Входящая скорость: %.1f MB/s ≈ %.0f Мбит/с' % (
            mbps, mbps * 8)
        if note:
            line += ' (⚠️ ' + note + ')'
        lines.append(line)
    lines.append('')
    lines.append('Команды для ручного повтора:')
    lines.append('  ' + PING_CMD)
    lines.append('  ' + NET_DOWNLOAD_SOURCES[0][1])
    return "\n".join(lines)
