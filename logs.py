"""Поиск и анализ логов, определение доменов, поиск OOM."""
import re
from collections import Counter

from common import (DOMAIN_PATHS, q, find_files, find_files_info,
                    read_file_content, get_domain_from_config)
from metrics import detect_panel  # noqa: F401 (реэкспорт для удобства)


def _safe_name(name):
    """Оставляет только безопасные для имени/glob символы (без shell-метасимволов)."""
    return re.sub(r'[^A-Za-z0-9._-]', '', name or '')


# ==================== ПОИСК ЛОГОВ ====================
# Перечень паттернов живёт в ОДНОЙ функции: его зовут и find_logs, и
# find_logs_info. Две копии перечня разъезжаются незаметно — тогда на одном и том
# же сервере в одном отчёте логи «есть», а в другом «их нет». Ровно та грабля,
# что уже лечили: cert_state (1.16.0), whois_record_lines (1.18.0), log_reader
# (1.19.0).
def _log_patterns(panel_type, safe_domain, log_type):
    """Каталоги/маски логов домена для панели (панель может быть не определена)."""
    if panel_type == 'fastpanel':
        return [
            f'/var/www/*/data/logs/*{safe_domain}*.{log_type}.log',
            f'/home/*/logs/*{safe_domain}*.{log_type}.log'
        ]
    if panel_type == 'ispmanager':
        return [
            f'/var/www/*/{safe_domain}/data/logs/{log_type}.log',
            f'/var/www/*/{safe_domain}/logs/{log_type}.log',
            f'/var/www/httpd-logs/{safe_domain}.{log_type}.log'
        ]
    return [
        f'/var/log/nginx/{safe_domain}.{log_type}.log',
        f'/var/log/apache2/{safe_domain}-{log_type}.log',
        f'/var/log/httpd/{safe_domain}-{log_type}_log'
    ]


def find_logs_info(checker, panel_type, domain, log_type='error', limit=20):
    """Логи домена и ЧЕМ объясняется пустота: {'paths', 'notes', 'checked'}.

    checked=False — сервер не подтвердил просмотр ни одного каталога (в ответе не
    было ни FFDIR, ни FFCOUNT): это «не проверено». Раньше такой ответ печатался
    как «Не найден … лог», т.е. «не проверено» было подписано как «логов нет».
    notes — готовые оператору строки про закрытые/отсутствующие каталоги.
    """
    paths, notes, checked = [], [], False
    for pattern in _log_patterns(panel_type, _safe_name(domain), log_type):
        info = find_files_info(checker, pattern, limit)
        if info['dirs'] or info['total'] is not None:
            checked = True
        for p in info['paths']:
            if p not in paths:
                paths.append(p)
        for n in info['notes']:
            if n not in notes:
                notes.append(n)
    return {'paths': paths, 'notes': notes, 'checked': checked}


def find_logs(checker, panel_type, domain, log_type='error'):
    """Находит логи для домена (унифицированная функция).

    Совместимость сохранена: предупреждения идут тем же списком отдельными
    ⚠️-строками, а потребители (discovery, panels, GUI) фильтруют их как не-пути.
    Отчёту, который обязан объяснить пустоту, нужен find_logs_info — иначе причина
    отфильтруется и на выходе снова встанет «не найдено».
    """
    info = find_logs_info(checker, panel_type, domain, log_type)
    return info['paths'] + info['notes']


# ==================== ПОЧТОВЫЙ ЛОГ (одна реализация на весь проект) ==========
# Почтовый лог читают несколько отчётов (postfix-отчёт Битрикса, тест отправки,
# сводка по почте). Читать его обязана ОДНА функция: проект уже обжёгся на
# парных реализациях, которые разъезжаются (mail_auth_lines вынесены именно по
# этой причине), а здесь расхождение означало бы «в одном отчёте лог есть, в
# другом — „логов нет“» на одном и том же сервере.
#
# Порядок путей — не каприз, а раскладка дистрибутивов: RHEL/CentOS/Alma пишут
# в /var/log/maillog, Debian/Ubuntu — в /var/log/mail.log. Раньше проект читал
# ТОЛЬКО maillog; об этом было написано в его собственном тексте («лог может
# писаться в /var/log/mail.log»), а тест прямо констатировал: «Debian пишет в
# /var/log/mail.log, а мы его не читаем». То есть на Debian отчёт о почте был
# слеп и честно об этом сообщал — но слепота, пусть и признанная, всё равно
# оставляла оператора с «причину не нашли».
MAIL_LOG_PATHS = ('/var/log/maillog', '/var/log/mail.log')
# Юнит, к которому syslog уходит в systemd-журнал (postfix: syslog_facility =
# mail, syslog_name = postfix — qmgr(8)). Fallback обязателен: в современных
# Debian/Ubuntu rsyslog может не писать почтовый файл вовсе.
MAIL_LOG_SERVICE = 'postfix'
# Маркер источника в выводе: отчёт обязан говорить, ОТКУДА прочитан лог, иначе
# «пусто» из journalctl и «пусто» из отсутствующего файла выглядят одинаково.
MAIL_LOG_MARK = '#LOG'


def _paths_arg(paths):
    """Список путей одним аргументом shell'а (каждый через q()).

    Пути передаются списком, а не зашиты в команду: выбор файла — цикл в shell,
    и без подмены путей он непроверяем (FakeSSH отвечает на команду целиком и
    «первый пустой, второй живой» сымитировать не может). Проверяется настоящим
    bash'ем на временных файлах (tests/test_logs.py).
    """
    return ' '.join(q(p) for p in (paths or MAIL_LOG_PATHS))


def mail_log_files_command(tail=15, paths=MAIL_LOG_PATHS):
    """Команда: последние tail строк первого непустого почтового файла.

    Проверка `[ -s ]`, а не `tail … || tail …`, обязательна: `tail` несуществу-
    ющего файла даёт rc=1, но ротированный и пока пустой maillog дал бы rc=0 с
    пустым выводом — и второй путь не спросился бы никогда. Разрываем цепочку
    только по содержимому.
    """
    return (f'for __p in {_paths_arg(paths)}; do if [ -s "$__p" ]; then '
            f'__t=$(tail -n {int(tail)} "$__p" 2>/dev/null); '
            f'if [ -n "$__t" ]; then printf "{MAIL_LOG_MARK} %s\\n%s\\n" '
            f'"$__p" "$__t"; break; fi; fi; done')


def mail_log_grep_command(needle, tail=50, keep=3, paths=MAIL_LOG_PATHS):
    """Команда: последние keep записей лога, содержащие needle.

    Ищем по всему найденному файлу, а не по одному maillog: иначе тест отправки
    на Debian так и остался бы с «записи теста не видно» при целом логе.
    """
    return (f'for __p in {_paths_arg(paths)}; do if [ -s "$__p" ]; then '
            f'__t=$(tail -n {int(tail)} "$__p" 2>/dev/null '
            f'| grep -F {q(needle)} | tail -n {int(keep)}); '
            f'if [ -n "$__t" ]; then printf "{MAIL_LOG_MARK} %s\\n%s\\n" '
            f'"$__p" "$__t"; break; fi; fi; done')


def mail_log_journal_command(tail=15):
    """Fallback на systemd-журнал — с тем же именем юнита, что и в syslog."""
    return (f'journalctl -u {q(MAIL_LOG_SERVICE)} -n {int(tail)} --no-pager '
            f'2>/dev/null')


def parse_mail_log_output(out):
    """(текст, источник) из вывода команд выше; маркер источника — первая строка.

    Маркер обязан срезаться здесь, а не в каждом вызывающем коде: иначе одна из
    сторон однажды напечатала бы «#LOG /var/log/mail.log» оператору как строку
    лога.
    """
    lines = (out or '').splitlines()
    if lines and lines[0].startswith(MAIL_LOG_MARK + ' '):
        return '\n'.join(lines[1:]).strip(), lines[0][len(MAIL_LOG_MARK):].strip()
    return '\n'.join(lines).strip(), ''


# journalctl при пустом журнале отвечает НЕ пустотой, а строкой
# '-- No entries --'. Принять её за лог — значит показать оператору «лог есть»
# на сервере, где писем не было вовсе (ровно этот дефект был в прежнем коде
# postfix-отчёта: он печатал её как содержимое лога).
JOURNAL_NO_ENTRIES = '-- No entries --'


def read_mail_log(checker, tail=15, grep=None, keep=3, paths=MAIL_LOG_PATHS):
    """Последние записи почтового лога: (текст, откуда).

    Файлы (maillog → mail.log), при пустом результате — journalctl. Возвращает
    ('', '') только когда не ответил НИКТО: это отдельное состояние, и вызывающий
    код обязан сказать «лог не найден», а не «писем нет» — «не проверено» никогда
    не превращается в «в порядке» или в «провалено».
    """
    cmd = (mail_log_grep_command(grep, tail=tail, keep=keep, paths=paths)
           if grep else mail_log_files_command(tail, paths=paths))
    text, source = parse_mail_log_output(checker.exec_command(cmd)[0])
    if text:
        # Источник обязан быть назван ВСЕГДА, когда текст есть: без маркера
        # (вывод без #LOG — так отвечают тесты и старые серверы с другой
        # обвязкой) вызывающий код напечатал бы «---  (последние 15 строк) ---»
        # и оператор не понял бы, откуда взялись строки.
        return text, source or 'лог почты'
    out, _ = checker.exec_command(mail_log_journal_command(tail))
    lines = [l for l in out.splitlines() if l.strip() != JOURNAL_NO_ENTRIES]
    if grep:
        lines = [l for l in lines if grep in l]
    kept = lines[-keep:] if grep else [l for l in lines if l.strip()]
    if kept:
        return '\n'.join(kept).strip(), f'journalctl -u {MAIL_LOG_SERVICE}'
    return '', ''


# ==================== РАЗБОР СТРОК ДОСТАВКИ POSTFIX ====================
# Строка доставки — единственная запись postfix, из которой видно, ЧТО стало с
# письмом: to=, relay=, dsn= и status= печатаются самим postfix (см. qmgr(8):
# «Problems and transactions are logged to the syslog daemon», статусы — из
# bounce/defer/trace). Разбираем именно её, а не «ищем слово error»: без status=
# любой вывод лога — это каша, в которой оператор найдёт что угодно.
#
# Держим разбор чистыми функциями (без SSH): весь смысл в том, чтобы ветки
# «спам / dns / сеть / адресат» проверялись тестами, а не живой почтой.
DELIVERY_STATUSES = ('sent', 'bounced', 'deferred', 'expired')
DELIVERY_STATUS_LABEL = {'sent': 'ушло', 'bounced': 'отбито',
                         'deferred': 'отложено', 'expired': 'истекло'}
DELIVERY_STATUS_ICON = {'sent': '✅', 'bounced': '❌', 'deferred': '⚠️',
                        'expired': '❌'}
# Порядок важен: первое совпадение выигрывает, поэтому специфичное стоит раньше
# общего. Основание у каждой группы — дословные фразы, которые в логе печатает
# приёмник (они приходят в скобках после status=), а не наша догадка; отчёт
# обязан напечатать и оригинал строки, чтобы группировка не выглядела диагнозом.
MAIL_FAILURE_HINTS = (
    # Иглы включают spf/dkim/dmarc/unauthenticated не «на всякий случай»: Gmail
    # прямо пишет причину в отказе («unauthenticated mail was rejected, please
    # learn about SPF»), и без этих слов ровно тот тикет, ради которого снимок и
    # затеян, остался бы без подсказки.
    ('спам или блокировка репутации',
     ('spam', 'blacklist', 'black list', 'blocked', 'content match',
      'deemed unsolicited', 'reputation', 'unauthenticated', 'spf', 'dkim',
      'dmarc', '5.7.1'),
     'Спам-фильтр приёмника или чёрный список IP. Лечится не postfix, а DNS и '
     'репутацией: пункт «Почта: SPF/DKIM/DMARC/PTR» + проверка IP в '
     'спам-списках (MXToolbox/blacklist).'),
    ('DNS домена получателя',
     ('name or service not known', 'temporary failure in name resolution',
      'host or domain name not found', 'no mx', 'name not found',
      'host not found'),
     'Домен получателя или его MX не разобрались. Проверьте MX получателя и '
     'резолвер самого сервера: dig +short MX домен @1.1.1.1.'),
    ('нет соединения с портом 25',
     ('connection timed out', 'connection refused', 'network is unreachable',
      'no route to host', 'host not reachable', 'connect to'),
     'Соединение с портом 25 получателя не установлено. Частые причины: '
     'хостинг блокирует исходящий 25 (у многих провайдеров он закрывается по '
     'умолчанию), фаервол, или MX получателя мёртв.'),
    ('отказ в релее / нужна авторизация',
     ('relay access denied', 'relay not permitted', 'relay not allowed',
      'authentication required', 'sasl', '5.7.60'),
     'Приёмник не принимает почту от этого сервера без авторизации: письмо '
     'отправлено не через тот SMTP, который ожидается, или сервер в релей-списке '
     'не значится.'),
    ('адресата нет',
     ('user unknown', 'no such user', 'mailbox unavailable', 'mailbox not found',
      'recipient address rejected', 'does not accept', 'unknown user'),
     'Ящика получателя не существует, либо домен его не принимает. Повторная '
     'попытка не поможет: postfix отобьёт письмо и вернёт уведомление '
     'отправителю.'),
    ('сервер загружен / временный отказ',
     ('too many connections', 'try again later', 'system busy', 'service not available',
      '451 ', '452 ', '450 '),
     'Приёмник отказал временно (код 4xx). Postfix сам повторит попытку с '
     'экспоненциальной задержкой и сдастся только через maximal_queue_lifetime '
     '(по умолчанию 5 дней) — трогать ничего не нужно.'),
)
# Код DSN, а не текст, определяет «повторять или сдаваться»: 4.x.x — временная
# неудача (доставка будет продолжена), 5.x.x — постоянная (postfix отобьёт
# письмо). Это RFC 3463 и поведение qmgr, описанное в qmgr(8).
DSN_TEMPORARY_PREFIX = '4.'
DSN_PERMANENT_PREFIX = '5.'
# Сколько отказов печатается в сводке: показывать 4000 строк лога в окне GUI —
# значит не показать ни одной. Остальные считаются счётчиком.
MAIL_LOG_SNAPSHOT_TAIL = 200
MAIL_FAILURE_LIMIT = 8


def parse_delivery_entry(line):
    """Разобрать строку доставки postfix в dict или None, если это не она.

    Поля берём именованные, а не позиционные: порядок `to=, relay=, delay=`
    меняется между postfix/smtp и postfix/qmgr, а `delayed 3600 secs` вообще
    приходит без `delay=`. None означает «эта строка — не доставка» (postfix в
    один лог пишет и запуск демонов, и connect/disconnect), и вызывающий код
    обязан такую строку пропустить, а не посчитать отказом.
    """
    line = (line or '').strip()
    status = re.search(r'status=(\w+)', line)
    if not status:
        return None
    to = re.search(r'to=<([^>]*)>', line)
    relay = re.search(r'relay=([^,]*)', line)
    dsn = re.search(r'dsn=([0-9]+(?:\.[0-9]+)*)', line)
    # Причину берём «всё после открывающей скобки», а не «между первой скобкой и
    # закрывающей в конце строки». Прежний шаблон терял причину целиком в двух
    # обычных для живого сервера случаях: postfix дробит многострочный SMTP-ответ
    # (Gmail отвечает «550-…» несколькими записями), а rsyslog обрезает строку по
    # $MaxLine — закрывающей скобки в хвосте просто нет. Потерянная причина — это
    # потерянный диагноз: «письмо отбито» остаётся голой строкой, а ровно кейс
    # «Gmail отбил за SPF» — без подсказки.
    reason = ''
    opening = re.search(r'status=\w+\s*\(', line)
    if opening:
        reason = line[opening.end():].strip()
        # Снимаем ОДНУ закрывающую скобку с конца (она закрывает нашу); если её
        # нет — строка обрезана, и причину показываем как есть, а не молчим.
        if reason.endswith(')'):
            reason = reason[:-1].rstrip()
    return {'status': status.group(1).lower(),
            'qid': parse_queue_id(line),
            'to': to.group(1).strip() if to else '',
            'relay': relay.group(1).strip() if relay else '',
            'dsn': dsn.group(1) if dsn else '',
            'reason': reason}


# ==================== ОТПРАВИТЕЛЬ ПО QUEUE-ID ====================
# Отказ в логе подписан получателем (`to=`), а оператор мыслит отправителем:
# «какой МОЙ домен тонет». В строке `postfix/smtp ... to=<...> status=` поля
# отправителя НЕТ — там только `to=, relay=, delay=, dsn=, status=`. Отправитель
# живёт в ДРУГОЙ записи того же письма:
#   postfix/qmgr[21603]: 14B40C65A1: from=<user@domain.com>, size=1372, nrcpt=1 (queue active)
#   postfix/pickup[6843]: BE78A40083: uid=1001 from=<user@domain.com>
#   postfix/submission/smtpd[..]: 9A1F2B3C4D: client=.., sasl_method=LOGIN, sasl_username=user@x.ru
# (cleanup пишет только message-id, конверт — нет: cleanup(8) «Insert missing
# message headers», адрес конверта в лог не печатает).
#
# Поэтому здесь честный join по queue-id, а не попытка угадать отправителя по
# тексту отказа. И из этого следуют два состояния, которые ОБЯЗАНЫ различаться:
#   - записи о входе письма в очередь нет в окне лога  → «не определено»
#     (qmgr пишет `from=` в момент активации очереди, smtp — позже; для письма,
#     простоявшего в deferred час, qmgr-строка уже старше окна);
#   - `from=<>` пустой → это НЕ «не нашли», это автоответ/bounce (MAILER-DAEMON).
# Свести второе к первому (или наоборот) — значит наврать оператору про чужое
# письмо. Приписать отказ домену, которого в конверте нет, — тот же грех, что
# «не проверено» → «в порядке».
# Идентификатор очереди postfix — шестнадцатеричная строка ВЕРХНЕГО регистра;
# длина зависит от версии и сборки (наблюдаем 4 у старых и 10–11 у новых:
# `AAA2`, `14B40C65A1`, `BCB39380B63`). Поэтому границу длины пришлось опустить
# до 4: при жёсткой нижней границе на сервере с короткими id привязка молча
# деградировала бы в «отправитель не определён», а оператор прочитал бы это как
# «эти письма — не от наших доменов». Тихая потеря данных, притворившаяся
# выводом, — ровно тот грех, который проект запрещает.
#
# Но короткая граница открывает другую дыру, и опаснее: на позицию
# `daemon[pid]: <токен>:` попадают СЛУЖЕБНЫЕ слова — `postfix/smtpd[9]:
# warning: queue is full`, `postfix/qmgr[9]: statistics: max connection rate`.
# Принять `warning` за идентификатор — значит склеить все warning-строки сервера
# в одно «письмо» и приписать его отказ тому домену, который случайно попался
# рядом. Ложный идентификатор хуже пропущенного: пропущенный честно печатается
# как «не определён», а ложный врёт оператору. Отсекаем алфавитом — hex
# верхнего регистра, как его печатает postfix; служебные слова в него не входят.
# Фикстуры проекта (AAA2, AAA1, AAB0, 9A1F2B3C4D) hex-совместимы.
QUEUE_ID_RE = re.compile(r'[A-Za-z0-9_.-]+(?:\[\d+\])?:\s+([0-9A-F]{4,20}):\s')
# Отказ smtpd пишет «NOQUEUE: reject:»: письма нет, оно не было принято. В hex
# это слово не входит, но список ниже оставлен намеренно: он объясняет смысл и
# переживёт любое расширение алфавита.
NOT_A_QUEUE_ID = {'NOQUEUE'}
SENDER_RE = re.compile(r'\bfrom=<([^>]*)>')
SASL_RE = re.compile(r'\bsasl_username=(\S+)')


def parse_queue_id(line):
    """Queue-id записи или ''.

    Берётся из префикса (`daemon[pid]: QID:`), а не из текста причины: в
    `status=sent (250 Ok: queued as 8BDCA22DA71)` второй идентификатор — чужая
    очередь (postfix перенял письмо), и склеить с ним отказ означало бы искать
    потом причину в чужом логе.
    """
    m = QUEUE_ID_RE.search(line or '')
    if not m or m.group(1) in NOT_A_QUEUE_ID:
        return ''
    return m.group(1)


def parse_sender_entry(line):
    """{'qid', 'from', 'via'} из записи о входе письма в очередь, иначе None.

    Источник — qmgr (конверт при активации), pickup (локальная отправка) или
    smtpd с SASL-авторизацией (там есть логин ящика). None означает «эта строка
    отправителя не описывает» (запуск демона, `removed`, connect/disconnect).
    Пустой `from` при НЕ-none результате — осмысленный ответ: конверт пуст.
    """
    line = (line or '').strip()
    qid = parse_queue_id(line)
    if not qid:
        return None
    m = SENDER_RE.search(line)
    if m:
        # pickup даёт 'uid=1001 from=<a@b>', qmgr — 'from=<a@b>, size=...'.
        # Отличаем их, чтобы в отчёте сказать, откуда взялся адрес.
        return {'qid': qid, 'from': m.group(1).strip(),
                'via': 'pickup' if 'uid=' in line else 'qmgr'}
    m = SASL_RE.search(line)
    if m:
        return {'qid': qid, 'from': m.group(1).strip().rstrip(','),
                'via': 'sasl'}
    return None


def index_senders_by_queue_id(lines):
    """{queue-id: {'from', 'via'}} по всему фрагменту лога.

    Первое вхождение выигрывает (setdefault): qmgr печатает `from=` при каждой
    активации очереди, адрес от этого не меняется, а `removed` и `retry`
    покрываются условием парсера (там `from=` нет).
    """
    index = {}
    for line in lines or ():
        entry = parse_sender_entry(line)
        if entry:
            index.setdefault(entry['qid'], entry)
    return index


def sender_of_delivery(entry, senders):
    """(адрес, как_узнали) отправителя записи доставки.

    Варианты второго поля — не декорация, а честная градация: 'qmgr', 'pickup',
    'sasl' (отправитель известен) и '' (в окне лога нет записи о входе письма в
    очередь). Последнее обязан видеть оператор: иначе он решит, что писем не
    было, а не то, что лог их не показывает.
    """
    qid = entry.get('qid') or ''
    if not qid:
        return '', ''
    rec = senders.get(qid)
    if not rec:
        return '', ''
    return rec['from'], rec['via']


def sender_domain_of(addr):
    """Домен из адреса отправителя ('' — адреса нет или он без домена)."""
    addr = (addr or '').strip()
    return addr.split('@')[-1].strip().lower() if '@' in addr else ''


def summarize_failure_senders(failures, senders, our_domains=()):
    """{'known': [(домен, число, наш_ли)], 'empty': N, 'unknown': N}.

    our_domains берётся из инвентаря панели (discover_mail_domains), а не из
    догадки по тексту: назвать чужой домен «нашим» было бы враньём ровно того
    же сорта, что и поднятие «не проверено» до «в порядке». Поэтому домен,
    которого нет в списке почтовых доменов сервера, печатается без пометки и не
    попадает в строку «по вашим доменам».
    """
    ours = {str(d).strip().lower() for d in (our_domains or ())}
    counts = Counter()
    empty = unknown = 0
    for e in failures:
        addr, via = sender_of_delivery(e, senders)
        if not via:
            unknown += 1
            continue
        if not addr:
            # Пустой конверт: автоответ и bounce-уведомления (MAILER-DAEMON).
            empty += 1
            continue
        counts[sender_domain_of(addr)] += 1
    known = sorted(((dom, n, dom in ours) for dom, n in counts.items()),
                   key=lambda item: (-item[1], item[0]))
    return {'known': known, 'empty': empty, 'unknown': unknown}


def failure_sender_lines(failures, log_text, our_domains=None, compact=False):
    """Строки «кто отправлял эти отказы» (compact=True — ровно одна строка).

    Индекс строится из УЖЕ ПРОЧИТАННОГО фрагмента: читать лог вторичный раз
    означало бы удвоить цену отчёта, а привязка к отправителю ради этого и
    затевалась.

    Здесь нет ни одной догадки и ни одного «похоже на наш». «Наш» домен —
    только тот, что назван инвентарём почтовых доменов (our_domains); если его
    не передавали (None), пометка «ваши» не ставится и это пишется отдельно:
    «не проверяли» и «не нашли» — разные ответы, и оператору нужен именно тот,
    который был.
    """
    if not failures:
        return []
    senders = index_senders_by_queue_id((log_text or '').splitlines())
    summ = summarize_failure_senders(failures, senders, our_domains or ())
    known = summ['known']
    ours = [(dom, n) for dom, n, is_ours in known if is_ours]
    others = [(dom, n) for dom, n, is_ours in known if not is_ours]
    our_names = {str(d).strip().lower() for d in (our_domains or ())}

    if compact:
        parts = []
        if ours:
            parts.append('по вашим доменам: ' +
                         ', '.join(f'{d} — {n}' for d, n in ours[:4]))
        if others:
            parts.append('иных отправителей: ' +
                         ', '.join(f'{d} — {n}' for d, n in others[:3]))
        if summ['unknown']:
            # Двоеточие, а не тире: вся строка открывается словами
            # «отправители отказов — », и второе тире в той же фразе читается
            # как обрыв вывода («отправители отказов — отправитель не определён
            # — 1»). Одиночная часть обязана читаться так же чисто, как список.
            parts.append(f"отправитель не определён: {summ['unknown']}")
        if summ['empty']:
            parts.append(f"писем без отправителя: {summ['empty']}")
        if not parts:
            return []
        # Заголовок подстраивается под содержимое. Когда ни один отказ не
        # привязан к домену, фраза «отправители отказов — отправитель не
        # определён: 1» читается как тавтология и как сломанный вывод, хотя
        # данные в ней настоящие. Про домены в этом случае молчим честно: их
        # просто не удалось установить.
        head = ('отправители отказов' if (ours or others)
                else 'отказы без привязки к домену')
        return [f'   {head} — ' + '; '.join(parts)]

    lines = []
    if ours:
        lines.append('   По вашим почтовым доменам: ' +
                     ', '.join(f'{d} — {n}' for d, n in ours))
        lines.append('      адрес подтверждён записью qmgr/pickup/sasl того же '
                     'queue-id, а не угадан по тексту отказа.')
    if others:
        listed = ', '.join(f'{d} — {n}' for d, n in others)
        if our_names:
            lines.append(f'   Отправители вне ваших почтовых доменов: {listed} '
                         '— домен не значится в инвентаре почты этого сервера '
                         '(письмо могло уйти через сторонний сервис или от '
                         'чужого локального пользователя).')
        else:
            lines.append(f'   Отправители отказов: {listed} — какие домены '
                         'считать вашими, не проверялось: инвентарь почтовых '
                         'доменов для этого отчёта не запрашивался.')
    # Форма «сущность — число», как в остальных счётчиках проекта
    # («Очередь postfix: писем — 5»): при 1 вывод читается так же чисто, как
    # при 12, и второму помощнику склонения здесь не место — две схемы счёта в
    # одном отчёте оператор прочитал бы как невнимательность.
    if summ['unknown']:
        # Без объяснения ПРИЧИНЫ: «письмо из deferred» — лишь один из вариантов
        # (ещё — ротация лога и просто короткий window). Факт один: записи нет в
        # прочитанном фрагменте, и называть это «не ваш домен» нельзя.
        lines.append(f"   Отправитель не определён — {summ['unknown']}: записи "
                     'qmgr с from=<…> об этих письмах в прочитанное окно лога '
                     'не попала. Это «не видно», а не «не ваш домен».')
    if summ['empty']:
        lines.append(f"   Писем без отправителя (from=<>) — {summ['empty']}: "
                     'автоответы и уведомления о недоставке. Их нельзя приписать '
                     'ни одному домену — конверт пуст.')
    return lines


def mail_failure_hint(text):
    """(группа причины, что делать) по тексту отказа или None.

    None — это ответ, а не промах: собрать «уникальную причину» из произвольной
    строки лога нельзя, а выдуманная причина хуже её отсутствия (оператор
    понесёт её клиенту). В этом случае отчёт печатает оригинал.
    """
    low = (text or '').lower()
    for label, needles, action in MAIL_FAILURE_HINTS:
        if any(n in low for n in needles):
            return label, action
    return None


def delivery_domain_of(entry):
    """Домен получателя записи (пусто, если адреса нет — врать не будем)."""
    to = entry.get('to') or ''
    return to.split('@')[-1].strip().lower() if '@' in to else ''


def summarize_deliveries(entries):
    """{status: count} по разобранным записям — только известные статусы.

    Неизвестный статус (чужой MTA или новая версия postfix) не приписывается ни
    к одному из четырёх и не считается отказом: он уходит в 'other', и отчёт
    обязан показать, что такое было, вместо «✅ отказов нет».
    """
    counts = {s: 0 for s in DELIVERY_STATUSES}
    counts['other'] = 0
    for e in entries:
        counts[e['status'] if e.get('status') in counts else 'other'] += 1
    return counts


def classify_delivery(entry):
    """Человеческая расшифровка одной записи: (иконка, строка, подсказка|None)."""
    status = entry.get('status') or ''
    icon = DELIVERY_STATUS_ICON.get(status, 'ℹ️')
    label = DELIVERY_STATUS_LABEL.get(status, status or 'неизвестно')
    who = entry.get('to') or 'адрес не указан'
    reason = entry.get('reason') or ''
    line = f"{icon} {who} — {label}"
    if entry.get('dsn'):
        line += f" (dsn={entry['dsn']})"
    if reason:
        line += f": {reason}"
    hint = mail_failure_hint(reason)
    if hint is None and entry.get('dsn', '').startswith(DSN_TEMPORARY_PREFIX):
        hint = ('временный отказ по коду 4xx',
                f'Postfix повторит попытку сам и сдастся только через '
                f'maximal_queue_lifetime (по умолчанию 5 дней).')
    return icon, line, hint


def mail_log_snapshot_lines(checker, tail=MAIL_LOG_SNAPSHOT_TAIL,
                           limit=MAIL_FAILURE_LIMIT, our_domains=None):
    """Снимок почтовой доставки: очередь не объясняет причин, объясняет лог.

    mailq отвечает «сколько писем стоит», но не отвечает «почему». Именно здесь
    рождается ответ на тикет «письма уходят в спам / не доходят»: строка
    `status=bounced ... said: 550 ...` связывает DNS-проверки с реальными
    отказами. Если лог не найден — говорим «не найден», а не «отказов нет»:
    «не проверено» не имеет права печататься как «в порядке».
    """
    text, source = read_mail_log(checker, tail=tail)
    if not text:
        return ['Последние отказы доставки: почтовый лог не найден — '
                f"{' и '.join(MAIL_LOG_PATHS)} и journalctl не ответили.",
                '   Причина отказа установить нельзя; проверить вручную: '
                'ls -l /var/log/mail*']
    entries = [e for e in (parse_delivery_entry(l) for l in text.splitlines()) if e]
    lines = [f"Доставка по логу ({source}, последние {tail} строк):"]
    if not entries:
        lines.append('   Записей о доставке в этом фрагменте нет — письма в '
                     'последние строки лога не уходили (это не «всё в порядке»).')
        return lines
    counts = summarize_deliveries(entries)
    parts = [f"{DELIVERY_STATUS_LABEL[s]}: {counts[s]}"
             for s in DELIVERY_STATUSES if counts[s]]
    if counts['other']:
        parts.append(f"без знакомого status: {counts['other']}")
    lines.append('   ' + ' · '.join(parts))
    # Отказ — только ЗАКОМБИНИРОВАННЫЙ статус из четырёх известных. Считать
    # отказом незнакомый status (чужой MTA, новая версия postfix) нельзя: это
    # снова «не проверено → провалено». Такие записи уже показаны счётчиком
    # «без знакомого status» строкой выше.
    failures = [e for e in entries
                if e['status'] in DELIVERY_STATUSES and e['status'] != 'sent']
    if not failures:
        lines.append(f'   ✅ Отказов нет ни в одной из разобранных записей '
                     f'({len(entries)}). Это окно лога, а не гарантия: письма '
                     f'старше {tail} строк здесь не видно.')
        return lines
    shown = 0
    for e in failures:
        if shown >= limit:
            break
        _icon, line, hint = classify_delivery(e)
        lines.append('   ' + line)
        if hint:
            lines.append(f'      ↳ {hint[0]}: {hint[1]}')
        else:
            lines.append('      ↳ причину не классифицируем — текст выше '
                         'дословно из лога, смотреть нужно его.')
        shown += 1
    if len(failures) > shown:
        # Та же форма счётчика, что в строках об отправителях ниже: «и ещё 1
        # отказов» при одном отказе читается как ошибка, а две схемы счёта в
        # одном снимке — как невнимательность.
        lines.append(f'   … скрыто отказов — {len(failures) - shown} (показаны '
                     f'первые {limit})')
    domains = sorted({d for d in (delivery_domain_of(e) for e in failures) if d})
    if domains:
        lines.append('   Домены получателей с отказами: ' + ', '.join(domains[:10])
                     + (' …' if len(domains) > 10 else ''))
    # «Кому бьёт» без «кто слал» оператору бесполезно: чинит он свой домен, а не
    # gmail. Индекс строится из ЭТОГО ЖЕ фрагмента лога — вторичного чтения нет.
    lines.extend(failure_sender_lines(failures, text, our_domains))
    lines.append('   Если отказы «спам/блокировка» — следующий шаг: пункт '
                 '«Почта: SPF/DKIM/DMARC/PTR» (причина в DNS, а не в postfix).')
    return lines


# ==================== ДАЙДЖЕСТ ДОСТАВКИ (подтверждение диагноза в других
# ================= отчётах)
# SPF-отчёт доказывает, что в DNS беда, но не доказывает, что она УЖЕ ломает
# почту. Доказательство — в логе: `status=bounced ... 550 ...`. Дайджест —
# КОРОТКАЯ версия снимка (3–4 строки) для отчётов, где лог служит лишь
# подтверждением диагноза, а не предметом проверки; полный снимок живёт в
# почтовой сводке. Одна реализация разбора, два способа подачи — иначе через
# полгода два отчёта начали бы по-разному считать одни и те же строки.
MAIL_DIGEST_TAIL = 200
SPAM_GROUP_LABEL = 'спам или блокировка репутации'


def delivery_failure_groups(entries):
    """{группа причины: число отказов} — только известные статусы-отказы.

    Неизвестный status сюда не попадает: он не отказ (см. закон «не проверено ≠
    провалено»), и приписать его какой-нибудь причине означало бы выдумать
    причину несуществующей беды.
    """
    groups = Counter()
    for e in entries:
        status = e.get('status')
        if status not in DELIVERY_STATUSES or status == 'sent':
            continue
        hint = mail_failure_hint(e.get('reason') or '')
        groups[hint[0] if hint else 'причина не распознана'] += 1
    return groups


def mail_delivery_digest_lines(checker, tail=MAIL_DIGEST_TAIL,
                               our_domains=None):
    """3–4 строки: подтверждает (или честно не подтверждает) связку с DNS.

    Цена — ОДИН чтение лога на прогон: в SPF-отчёте до HEALTH_CHECK_LIMIT
    доменов, и платить чтением лога за каждый означало бы повесить GUI на
    минуты. Дайджест вызывается вне цикла по доменам.
    """
    text, source = read_mail_log(checker, tail=tail)
    if not text:
        # Каждое предложение — отдельной строкой: перенос посреди фразы в GUI
        # читается как оборванный вывод.
        return ['Что лог говорит о доставке: почтовый лог не найден.',
                '   Связать DNS-проверки с реальными отказами нельзя — это не '
                '«всё в порядке», а «не проверено».',
                '   Проверить вручную: ls -l /var/log/mail*']
    entries = [e for e in (parse_delivery_entry(l) for l in text.splitlines()) if e]
    if not entries:
        return [f'Что лог говорит о доставке ({source}, последние {tail} строк):',
                '   Записей о статусе доставки нет — подтверждать связку нечем. '
                'Обычно это',
                '   значит, что с сервера сейчас не отправляют; «записей нет» '
                'не равно «всё в порядке».']
    counts = summarize_deliveries(entries)
    parts = [f'{DELIVERY_STATUS_LABEL[s]}: {counts[s]}'
             for s in DELIVERY_STATUSES if counts[s]]
    if counts['other']:
        parts.append(f"без знакомого status: {counts['other']}")
    lines = [f'Что лог говорит о доставке ({source}, последние {tail} строк):',
             '   ' + (' · '.join(parts) if parts
                      else 'записей о статусе доставки нет')]
    groups = delivery_failure_groups(entries)
    refused = sum(groups.values())
    if not refused:
        # Самое опасное место дайджеста: соблазн прочитать «отказов нет» как
        # «чинить нечего». Приёмник, который режет спам, письмо НЕ отбивает — он
        # принимает его с 250 Ok и молча кладёт в спам, и в НАШЕМ логе этого не
        # видно вовсе. Поэтому здесь пишется опровержение ложного вывода.
        lines.append('   Отказов доставки в этом окне нет — но читать это как '
                     '«чинить нечего» нельзя:')
        lines.append('   приёмник, режущий спам, письмо не отбивает, а принимает '
                     'и кладёт в спам —')
        lines.append('   в логе отправителя такое не отображается.')
        return lines
    top = ', '.join(f'{label} — {n}'
                    for label, n in groups.most_common(3))
    lines.append(f'   причины отказов: {top}'
                 + (f' (всего отказов: {refused})' if refused > 3 else ''))
    # Одна строка вместо полного списка: дайджест — подтверждение диагноза, а не
    # предмет проверки. Отправитель берётся join'ом по queue-id из того же
    # фрагмента, который уже прочитан, поэтому «+1 строка в отчёте» не стоит
    # «+1 чтение лога».
    refused_entries = [e for e in entries
                       if e['status'] in DELIVERY_STATUSES
                       and e['status'] != 'sent']
    lines.extend(failure_sender_lines(refused_entries, text, our_domains,
                                      compact=True))
    spam = groups.get(SPAM_GROUP_LABEL, 0)
    if spam:
        lines.append(f'   ↳ {spam} из них — спам-фильтр/блокировка: DNS-беда уже '
                     f'ломает доставку,')
        lines.append('     строки «→» выше — что именно вставить в DNS.')
    else:
        # Отсутствие спам-отказов не снимает подозрения с DNS: приёмник, молча
        # положивший письмо в спам, отвечает 250 Ok и в логе отправителя не
        # светится вовсе. Написать тут «значит SPF ни при чём» было бы ложью.
        lines.append('   ↳ отказов «спам/блокировка» тут нет: остальные причины '
                     'к SPF/DKIM')
        lines.append('     отношения не имеют. Но это не оправдание пустой зоны: '
                     'письмо, молча')
        lines.append('     уехавшее в спам, приёмник принимает с 250 Ok — в нашем '
                     'логе его нет.')
    return lines


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
    info = find_logs_info(checker, panel_type, domain, 'access')
    log_files = info['paths']
    if not log_files:
        # Пустота бывает трёх родов; «логов нет» — только третий.
        if info['notes']:
            return "\n".join([f"❌ Access-лог домена {domain} не просмотрен:"]
                             + info['notes'])
        if not info['checked']:
            return (f"❓ Access-лог домена {domain}: состояние не проверено — "
                    f"сервер не подтвердил просмотр ни одного каталога. "
                    f"Повторите проверку: прошлая могла оборваться.")
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
    out, _, _ = checker.run(cmd)
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
