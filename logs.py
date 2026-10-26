"""Поиск и анализ логов, определение доменов, поиск OOM."""
import re
from collections import Counter

from common import (DOMAIN_PATHS, q, find_files, find_files_info,
                    read_file_content, read_file_info,
                    domains_from_configs_info, DOMAIN_CONFIG_LIMIT,
                    DOMAIN_TRUNCATED_NOTE, LS_E2BIG_RC)
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

    unread = []
    viewed = 0
    for log_file in log_files:
        if log_file.startswith('⚠️'):
            continue
        read = read_file_info(checker, log_file)
        if read['content'] is None:
            unread.append(f"⚠️ Лог {log_file} не просмотрен: {read['reason']}")
            continue
        viewed += 1
        content = read['content']
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
        # Ни одной записи мы не увидели ДВУМЯ разными способами: записей правда
        # не было (файлы прочитаны) или файлы остались непрочитанными. Прежний код
        # не различал: `if not content: continue` молча глотал лог с правами 0600,
        # и отчёт говорил «записей не найдено» — оператор шёл искать отсутствие
        # посещений, а не права (тот же закон, что 1.19.0/1.20.0).
        if unread and viewed == 0:
            return "\n".join([f"❌ Access-лог домена {domain} не просмотрен:"]
                             + unread)
        filters = []
        if year: filters.append(f"год={year}")
        if month: filters.append(f"месяц={month}")
        if day: filters.append(f"день={day}")
        tail = ("\n" + "\n".join(unread)) if unread else ""
        return (f"За указанный период ({' '.join(filters)}) записей не найдено."
                + tail)

    lines_out = []
    lines_out.append(f"=== АНАЛИЗ ПОСЕЩЕНИЙ ДЛЯ {domain} ===")
    # Прочитанные файлы, а не найденные: прежняя строка считала len(log_files) и
    # при закрытом логе врала про полноту проверки («обработано 2» из прочитанного
    # одного).
    lines_out.append(f"Обработано файлов: {viewed}")
    if unread:
        lines_out.append("Часть логов не просмотрена:")
        lines_out.extend(unread)
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
def get_domains_info(checker, panel_type):
    """Домены веб-сервера и ЧЕМ объясняется пустота: {'domains','notes','checked'}.

    Прежний вид:

        out, _ = checker.exec_command(f'ls -1 {pattern} 2>/dev/null | head -10')

    Два вранья в одной строке. Во-первых, в `_` выбрасывался единственный
    источник причины пустоты — «нет прав на каталог vhost'ов» и «каталога нет»
    для оператора означали «доменов нет», хотя лечение противоположное (поднять
    права против менять раскладку). Во-вторых, `head -10` резал список молча: на
    сервере с 40 конфигами отчёт «смотрел» десять и называл это полным списком
    доменов — теперь считает awk (FFCOUNT), и срезка видна.

    checked=False — сервер не подтвердил просмотр ни одного каталога: это «не
    проверено», а не «доменов нет» (тот же закон, что в 1.19.0 и 1.20.0).
    """
    domains = []
    notes = []
    checked = False

    if panel_type == 'ispmanager':
        # `2>/dev/null` убирал ровно то, что случилось с панелью. `mgrctl:
        # command not found` и «панель ответила пустым списком» — разные ответы:
        # во втором случае доменов действительно нет, в первом — мы не узнали.
        out, err, rc = checker.run('mgrctl -m webdomain list --output-format csv')
        if out.strip():
            for line in out.strip().split('\n')[1:]:
                parts = line.split(',')
                if len(parts) >= 2:
                    domain = parts[1].strip()
                    if domain and domain not in domains:
                        domains.append(domain)
            if domains:
                return {'domains': list(set(domains)), 'notes': [],
                        'checked': True}
        if rc != 0 or (err or '').strip():
            why = next((l.strip() for l in (err or '').splitlines() if l.strip()),
                       f'код возврата {rc}')[:160]
            notes.append(f"⚠️ Панель (mgrctl) не ответила про домены: «{why}». "
                         f"Домены искались по конфигам веб-сервера — список может "
                         f"быть неполным")

    configs = []
    truncated = False
    for pattern in DOMAIN_PATHS.get(panel_type, DOMAIN_PATHS['none']):
        # DOMAIN_CONFIG_LIMIT (1.32.0) вместо прежней десятки. Держать 10
        # заставляла ЦЕНА: каждый конфиг читался отдельным SSH-раундом
        # (замер живьём: 10 файлов = 11 команд, 50 = 51, 200 = 201). Сводная
        # команда этого же слайса читает всю пачку за один заход (замер:
        # 200 путей = 1 команда, 7.5 КБ при бюджете ~2 МБ, rc=0, stderr
        # пуст), поэтому срезка перестала быть ценовой и осталась чистой
        # ложью: замер 40 реальных конфигей - оператор видел 10 доменов.
        info = find_files_info(checker, pattern, DOMAIN_CONFIG_LIMIT)
        # 1.32.3: «проверено» решается ДОШЕДШИМ СПИСКОМ, а не состоянием
        # каталога. Замер живьём (парк 20 000 конфигов, ulimit -s 1024): ls не
        # исполнилась — список аргументов не влез (rc=126), — а примитив вернул
        # FFDIR ok + FFCOUNT 0 при rc конвейера 0. Прежняя строка решала по
        # FFDIR ok и подписывала «домены не найдены» как успешную проверку.
        # Сравнение с LS_E2BIG_RC (та же константа, что в примитиве), а не с
        # единицей и не разбором текста заметки (закон 1.31.0).
        list_failed = info.get('ls_rc') == LS_E2BIG_RC
        if not list_failed and (info['dirs'] or info['total'] is not None):
            checked = True
        # Признание о срезке изымается ПО ПОЛЮ trunc_note, а не сравнением
        # или поиском по тексту: разбор localized формулировки однажды
        # разъезжается с самим текстом (закон 1.31.0). Ниже она пересказана
        # на языке доменов.
        trunc = info.get('trunc_note')
        if trunc:
            truncated = True
        for note in info['notes']:
            if note == trunc:
                continue
            if note not in notes:
                notes.append(note)
        for config_file in info['paths']:
            if config_file not in configs:
                configs.append(config_file)

    # Слайс 1.32.0: срезка обязана быть названа на языке ДОМЕНОВ. Строка
    # примитива говорит про ФАЙЛЫ («Показаны первые N файлов из M»), а этот
    # отчёт печатает заголовок «Найдены домены: ...» - связку «файл -> домен»
    # оператор не проходит и читает десять имён как полный список сайтов.
    # Поэтому строку примитива здесь НЕ показываем (она про другой отчёт), а
    # ставим свою, с числом прочитанных конфигей.
    #
    # total не суммируется: шаблоны панелей перекрываются (одни и те же файлы
    # лежат в sites-enabled и в conf.d), и сумма total'ов соврала бы о
    # масштабе. Называется то, что известно точно, - сколько конфигей
    # прочитано и из них извлечены домены.
    if truncated:
        notes.append(DOMAIN_TRUNCATED_NOTE.format(shown=len(configs)))

    # Чтение конфигов — ОДИН вызов на весь прогон (1.29.0). Прежняя plain-
    # версия возвращала только список, поэтому «нет прав на конфиг» и «конфига
    # нет» схлопывались в пустоту, и get_domains_info докладывал «доменов нет»
    # по файлам, содержимое которых не читал; лечения у них противоположные
    # (поднимать права против менять раскладку панели). По одному вызову на
    # файл дало бы обратную беду: признание на каждый файл, и отчёт утонул бы
    # (замер: 10 конфигов 0000 = 10 одинаковых строк). Агрегатор даёт ОДНУ
    # строку на основание и называет число файлов.
    cfg, cfg_notes = domains_from_configs_info(checker, configs)
    domains.extend(cfg)
    for note in cfg_notes:
        if note not in notes:
            notes.append(note)

    return {'domains': list(set(domains)), 'notes': notes, 'checked': checked}


def get_domains(checker, panel_type):
    """Список доменов веб-сервера (причины пустоты — в get_domains_info)."""
    return get_domains_info(checker, panel_type)['domains']


# ==================== ПРОВЕРКА ЛОГОВ САЙТОВ ====================
def check_site_logs_info(checker, panel_type, domains):
    """Ошибки в логах сайтов + ЧТО МЫ НЕ ПРОСМОТРЕЛИ.

    {'errors': {домен: текст}, 'unread': [готовые строки], 'viewed': int}

    Прежняя форма возвращала только словарь ошибок, а непрочитанный лог просто
    пропускался (`if content:`). Следствие: лог с правами 0600 root, который
    оператор под своим UID открыть не может, попадал в ту же ветку, что и чисто
    проверенный лог, и отчёт говорил «Ошибок в логах сайтов не обнаружено».
    То есть «мы не увидели» было подписано как «ошибок нет» — ровно та ложь,
    которую этот релиз закрывает в поиске логов (1.20.0), но уровнем ниже.

    `unread` — строки оператору (там же и причины из find_logs_info: закрытый
    или отсутствующий каталог логов). `viewed` — сколько файлов прочитано,
    чтобы «не просмотрено» не выглядело как «проверено и чисто».
    """
    errors = {}
    unread = []
    viewed = 0
    for domain in domains:
        info = find_logs_info(checker, panel_type, domain, 'error')
        for note in info['notes']:
            if note not in unread:
                unread.append(note)
        if not info['paths']:
            if not info['checked']:
                note = (f"⚠️ Логи {domain}: сервер не подтвердил просмотр ни "
                        f"одного каталога — состояние не проверено, повторите "
                        f"проверку")
                if note not in unread:
                    unread.append(note)
            continue
        for log_file in info['paths']:
            read = read_file_info(checker, log_file)
            if read['content'] is None:
                note = f"⚠️ Лог {log_file} не просмотрен: {read['reason']}"
                if note not in unread:
                    unread.append(note)
                continue
            viewed += 1
            content = read['content']
            if content:
                log_lines = content.splitlines()[-200:]
                for line in log_lines:
                    if re.search(r'error|fail|critical|fatal|panic|warning', line, re.I):
                        errors.setdefault(domain, []).append(f"{log_file}: {line.strip()}")

    result = {}
    for domain, err_lines in errors.items():
        if err_lines:
            result[domain] = '\n'.join(err_lines[:10])
    return {'errors': result, 'unread': unread, 'viewed': viewed}


def check_site_logs(checker, panel_type, domains):
    """Ошибки в логах сайтов словарём {домен: текст} (причины — в *_info)."""
    return check_site_logs_info(checker, panel_type, domains)['errors']


def site_logs_report(checker, panel):
    dom = get_domains_info(checker, panel)
    domains = dom['domains']
    lines = []
    if not domains:
        # Разделяем «доменов нет» и «мы ничего не узнали» (закон 1.19-1.20).
        for note in dom['notes']:
            lines.append(f"   {note}")
        if dom['checked']:
            lines.append("Не удалось определить домены для проверки логов.")
        else:
            lines.append("❓ Домены для проверки логов не определены: каталоги "
                         "конфигов не подтверждены сервером — состояние не "
                         "проверено. Повторите проверку: прошлая могла "
                         "оборваться.")
        return "\n".join(lines)

    lines.append(f"Найдены домены: {', '.join(domains)}")
    if dom['notes']:
        lines.append("   Список доменов может быть неполным:")
        for note in dom['notes']:
            lines.append(f"   {note}")
    lines.append("\n=== ОШИБКИ В ЛОГАХ САЙТОВ ===")
    site = check_site_logs_info(checker, panel, domains)
    if site['errors']:
        for key, err in site['errors'].items():
            lines.append(f"\n{key}:\n{err}")
    if site['unread']:
        lines.append(f"\n❌ Часть логов сайтов не просмотрена "
                     f"(прочитано файлов: {site['viewed']}):")
        lines.extend(site['unread'])
    if not site['errors'] and not site['unread']:
        lines.append("Ошибок (по ключевым словам) в логах сайтов не обнаружено.")
    return "\n".join(lines)


# ==================== ПОИСК OOM ====================
# Пути логов — ОДИН список: его зовут и команда, и строка «Файлы: …». Раньше они
# были записаны дважды (в cmd и в заголовке отчёта) — разъехавшийся дубль обещает
# «искали в одних файлах, отчитались по другим» (ср. cert_state 1.16.0,
# whois_record_lines 1.18.0, log_reader 1.19.0, _log_patterns 1.20.0).
OOM_GLOBS = ('/var/log/kern.log*', '/var/log/syslog*')

# Шаблон прежний: BRE с `\|` (zgrep кормит grep без -E). Замерено живьём: тот же
# набор слов без -E и без \| не находит ничего, поэтому менять его нельзя.
OOM_PATTERN = 'out of memory\\|killed process\\|oom-killer'

# Причины, по которым поиск не был полным. Тексты — оператору.
OOM_TEXT = {
    'unread': ("⚠️ Файл {path} не просмотрен: не читается под этим пользователем "
               "— нет прав (обычно нужен root или членство в группе adm/syslog). "
               "Его события в отчёте не участвовали"),
    'badgz': ("⚠️ Файл {path} не просмотрен: gzip не смог открыть архив (битый "
              "или недокачанный лог) — содержимое этого файла в отчёте не "
              "участвовало, а zgrep об этом молчит"),
    'noglob': ("⚠️ Ни одного из файлов {globs} на сервере нет — смотреть было "
               "негде. Обычно ядро пишет в журнал systemd: "
               "journalctl -k --grep=oom"),
    'notool': ("⚠️ zgrep не установлен — ротированные архивы не проверялись, "
               "поиск по ним не выполнялся"),
}


def search_oom_cmd():
    """Одна POSIX-команда: состояние каждого файла + честный zgrep.

    Прежний вид:

        cmd = "zgrep … /var/log/kern.log* /var/log/syslog* 2>/dev/null"
        out, _, _ = checker.run(cmd)        # rc принят и выброшен
        if not out.strip(): return "OOM-событий в логах не найдено."

    Пустой вывод тут дают пять разных вещей, и подписаны они были одинаково.
    Замерено живьём (uid=1000, продуктовый BRE-шаблон, bash и dash — одинаково):

        oom.log       rc=0  stdout=73  err=''         события ЕСТЬ
        kern.log      rc=1  stdout=0   err=''         прочитан, совпадений нет
        locked.log    rc=2  stdout=0   err=gzip: …: Permission denied
        nothere*.log  rc=2  stdout=0   err=gzip: …: No such file or directory
        bad.log.gz    rc=1  stdout=0   err=''         ← НЕ отличим от «чисто»

    Последний случай и есть причина отдельной проверки архива: zgrep на битом .gz
    молчит с rc=1, поэтому о нём говорит только `gzip -t` (без своего 2>/dev/null,
    иначе ответ системы снова потеряется).

    Отличие от прошлых слайсов: glob'ов несколько, и раскрытие делает шелл
    сервера. Литерал с `*`, который не раскрылся, обязан быть пропущен (case по
    `*`) — иначе «нет такого файла» было бы посчитано как «файл есть, событий
    нет». Тот же закон, что в 1.20.0 для каталогов логов.

    `${PIPESTATUS}` нет (dash: «Bad substitution»), `$(…)` нет (замок инъекции),
    `2>/dev/null` нет — в нём лежала единственная строка с причиной. Служебный
    блок печатается ДО границы OOMEND, тело zgrep — после, поэтому строка лога
    вида «OOMSTAT 99 99 99» не может подделать состояние (проверено живьём).

    Маркеры печатаются СРАЗУ (echo), а не копятся в переменную. Первая версия
    собирала их в `s="$s\nOOMUNREAD $f"` и выводила одним printf: внутри
    двойных кавычек шелл НЕ раскрывает `\n` (это литерал backslash-n), а
    `printf '%s'` не раскрывает escape в аргументе — все маркеры сливались в
    одну строку и парсер не видел ни одного. Поймано живым прогоном команды из
    продукта: тесты этого не ловили, потому что служебный блок в них собирает
    helper, а не шелл.
    """
    return ('set -- ' + ' '.join(OOM_GLOBS) + '; n=0; u=0; b=0'
            '; for f in "$@"; do case "$f" in *"*"*) continue;; esac; n=$((n+1)); '
            'if [ ! -r "$f" ]; then u=$((u+1)); echo "OOMUNREAD $f"; continue; fi; '
            'case "$f" in *.gz) gzip -t "$f" || { b=$((b+1)); echo "OOMBADGZ $f"; }'
            ';; esac; '
            'done; '
            'if command -v zgrep >/dev/null; then '
            "printf 'OOMSTAT %d %d %d\\nOOMEND\\n' \"$n\" \"$u\" \"$b\"; "
            "zgrep -B 5 -A 5 -i '" + OOM_PATTERN + "' \"$@\"; "
            "else printf 'OOMSTAT %d %d %d notool\\nOOMEND\\n' \"$n\" \"$u\" \"$b\"; "
            'fi')


def parse_oom_answer(out):
    """Служебный блок и тело zgrep из ответа команды.

    Служебное берётся строго ДО ПЕРВОГО OOMEND: содержимое логов идёт после
    границы и не может ни добавить, ни снять состояние. Маркеров нет (обрыв или
    чужая реализация) — checked=False, тело = весь ответ (совместимость).
    """
    head, body, in_body = [], [], False
    for line in (out or '').splitlines():
        if in_body:
            body.append(line)
        elif line.strip() == 'OOMEND':
            in_body = True
        else:
            head.append(line)

    def _int(value):
        try:
            return int(value)
        except (TypeError, ValueError):
            return 0

    seen, files, unread, badgz, notool = False, 0, [], [], False
    for line in head:
        s = line.strip()
        if s.startswith('OOMSTAT '):
            seen = True
            parts = s.split()
            files = _int(parts[1]) if len(parts) > 1 else 0
            notool = 'notool' in parts[4:]
        elif s.startswith('OOMUNREAD '):
            unread.append(s.split(' ', 1)[1].strip())
        elif s.startswith('OOMBADGZ '):
            badgz.append(s.split(' ', 1)[1].strip())

    if not seen:
        body = (out or '').splitlines()
    # Блоки zgrep: '--' разделяет совпадения, внутри блока -5/+5 строк контекста.
    blocks, current = [], []
    for line in body:
        if line.strip() == '--':
            if current:
                blocks.append('\n'.join(current))
                current = []
            continue
        current.append(line)
    if current:
        blocks.append('\n'.join(current))
    return {'checked': seen, 'files': files, 'unread': unread, 'badgz': badgz,
            'notool': notool, 'events': blocks,
            'empty_blocks': bool([l for l in body if l.strip()]) and not blocks}


def search_oom_info(checker):
    """Поиск OOM + ЧЕМ объясняется его пустота.

    dict(events, notes, unread, badgz, files_seen, checked, globs).
    """
    out, _err, _rc = checker.run(search_oom_cmd())
    p = parse_oom_answer(out)
    notes = []
    if p['notool']:
        notes.append(OOM_TEXT['notool'])
    for path in p['unread']:
        notes.append(OOM_TEXT['unread'].format(path=path))
    for path in p['badgz']:
        notes.append(OOM_TEXT['badgz'].format(path=path))
    if p['checked'] and p['files'] == 0:
        # Файлов нет вовсе: на systemd-хосте это норма, и «событий не было» тут
        # ложь — мы не смотрели.
        notes.append(OOM_TEXT['noglob'].format(globs=', '.join(OOM_GLOBS)))
    return {'events': p['events'], 'notes': notes, 'unread': p['unread'],
            'badgz': p['badgz'], 'files_seen': p['files'],
            'checked': p['checked'], 'empty_blocks': p['empty_blocks'],
            'globs': list(OOM_GLOBS)}


def search_oom_logs(checker):
    """Поиск событий Out-Of-Memory в системных логах.

    «OOM-событий не найдено» печатается только когда хотя бы один лог реально
    прочитан и ни один не отвалился; иначе — причина (права / битый архив /
    файлов нет / ответ не пришёл).
    """
    info = search_oom_info(checker)
    if info['events']:
        lines = ["=== ПОИСК OOM-СОБЫТИЙ В ЛОГАХ ===",
                 "Файлы: " + ", ".join(info['globs']), ""]
        for i, block in enumerate(info['events'], 1):
            lines.append(f"--- Событие #{i} ---")
            lines.append(block)
            lines.append("")
        if info['notes']:
            # Найденное терять нельзя, но и объявлять проверку полной нельзя.
            lines.append(f"❌ Часть логов не просмотрена "
                         f"(прочитано файлов: {info['files_seen'] - len(info['unread'])}):")
            lines.extend(info['notes'])
        return "\n".join(lines)
    if info['notes']:
        return "\n".join(["❌ Поиск OOM выполнен не полностью:"] + info['notes'])
    if info['empty_blocks']:
        return "OOM-событий не обнаружено (пустые блоки)."
    if not info['checked']:
        return ("❓ Итог поиска OOM не подтверждён: сервер не вернул ни состояния "
                "файлов, ни итога — состояние не проверено. Повторите проверку: "
                "прошлая могла оборваться.")
    return "OOM-событий в логах не найдено."
