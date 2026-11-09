"""Работа с файлами/конфигами, замена IP, перезапуск служб."""
import ipaddress
import re
from datetime import datetime

from common import (BACKUP_SUBDIRS, q, ensure_backup_dir, create_backup,
                    create_backup_info, backup_stamp,
                    write_remote_file, RF_TEXT, read_file_info,
                    find_files_info, FF_DIR_TEXT,
                    # Состояние юнита спрашивает ОДНА функция (1.32.6):
                    # пустой stdout systemctl — «система не ответила», и
                    # решать по нему нельзя нигде. Здесь это дороже отчёта:
                    # по молчанию делался лишний restart и печатался
                    # красный «не запустился».)
                    unit_presence_info,
                    unit_status_info)


# ==================== РАБОТА С ФАЙЛАМИ (С БЭКАПАМИ) ====================
def write_file(checker, filepath, content):
    """Записывает содержимое в файл с созданием резервной копии (через SFTP).

    Прежний вид говорил «⚠️ Не удалось создать резервную копию файла» и молчал
    о причине, хотя она измерима (замер: cp пишет её в stdout). Оператор обязан
    увидеть, что именно отказало, и что правка уйдёт без отката; «прав не
    хватило посмотреть» не имеет права звучать как «файла нет».
    """
    lines = []
    lines.append(f"=== СОХРАНЕНИЕ ФАЙЛА: {filepath} ===")

    backup = create_backup_info(checker, filepath, 'configs')
    if backup['state'] == 'done':
        lines.append(f"✅ Резервная копия создана: {backup['path']}")
    else:
        lines.append("⚠️ Не удалось создать резервную копию файла")
        if backup['note']:
            lines.append(("⚠️ " if backup['state'] == 'unchecked'
                          else "   Причина: ") + backup['note'])
        lines.append("⚠️ Правка уйдёт без возможности откатить.")

    ok, err = write_remote_file(checker, filepath, content)
    if not ok:
        lines.append(f"❌ Ошибка записи: {err}")
        return "\n".join(lines)

    lines.append("✅ Файл сохранён.")
    return "\n".join(lines)

def read_file(checker, filepath):
    """Читает файл для редактора: строка с ❌ — только настоящая неудача.

    Прежний вид:

        out, err, rc = checker.run(f'cat {q(filepath)} 2>/dev/null')
        if rc != 0:
            return f"❌ Ошибка чтения файла (rc={rc}): {err.strip()}"

    Сообщение обещало причину ПОСЛЕ двоеточия, а та же команда (`2>/dev/null`)
    её же и заглушала. Замер живьём (uid=1000, /bin/bash) — четыре разных
    состояния под одной подписью с ПУСТЫМ хвостом:

        locked.conf    rc=1 stdout=0 stderr=''  -> '❌ Ошибка чтения файла (rc=1): '
        nope.conf      rc=1 stdout=0 stderr=''  -> '❌ Ошибка чтения файла (rc=1): '
        lockd/x.conf   rc=1 stdout=0 stderr=''  -> '❌ Ошибка чтения файла (rc=1): '
        каталог        rc=1 stdout=0 stderr=''  -> '❌ Ошибка чтения файла (rc=1): '

    Хуже подписи другое: вызывающий код (`gui_admin._load`) вставляет
    возвращённое в редактор и не различает текст ошибки и содержимое, поэтому
    «Сохранить» записывало строку ошибки на сервер по пути конфига. Отсюда
    правила: неудача ОБЯЗАНА начинаться с ❌ (по этому её распознаёт
    `gui_files`), обязана называть состояние словами (`rc=1` — не диагноз, он
    сливает права и отсутствие) и обязана содержать «не прочитан», чтобы не
    походить на содержимое. Успех возвращается байт в байт: завершающий перевод
    строки — часть файла, редактор вернёт его на сервер.
    """
    info = read_file_info(checker, filepath)
    if info['content'] is not None:
        return info['content']
    reason = info['reason'] or RF_TEXT['unchecked']
    return f"❌ Файл {filepath} не прочитан: {reason}"


# Где живут конфиги. Список — константа модуля, а не локальная переменная:
# тест цены прогона обязан видеть, что проверок ровно столько, сколько путей,
# а не вдвое больше (прежний код тратил по ДВЕ слепые команды на каждый путь).
# Каталог заканчивается '/' — к нему в поиске добавляется '/*', чтобы `ls`
# печатал ПОЛНЫЕ пути (иначе редактор получил бы имена без каталога).
CONFIG_PATHS = [
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

PANEL_CONFIG_PATHS = {
    'fastpanel': [
        '/usr/local/fastpanel/etc/nginx/',
        '/usr/local/fastpanel/etc/php/',
        '/etc/nginx/fastpanel2-available/',
    ],
    'ispmanager': [
        '/etc/nginx/vhosts/',
        '/usr/local/mgr5/etc/nginx/',
        '/usr/local/mgr5/etc/apache2/',
        '/usr/local/mgr5/etc/php/',
    ]
}

CONFIG_LIMIT = 20      # файлов на один путь
CONFIG_MAX = 50        # всего в списке: диалог с двумястами пунктами не читают

NOT_SEARCHED_NOTE = ("⚠️ Ни один из {n} путей не подтвердил поиск: сервер вернул "
                     "пустой ответ без состояния каталога. О конфиг-файлах ничего "
                     "не известно — это «не проверено», а не «файлов нет». "
                     "Повторите проверку: прошлая могла оборваться")


def get_config_files_info(checker, panel_type):
    """(список конфигов, notes): что нашли И чем объяснена пустота.

    Прежний вид:

        out, _ = checker.exec_command(f'ls -d {q(path)} 2>/dev/null && echo "exists"')
        if out.strip() == 'exists':

    Функция была мертва на ЛЮБОМ сервере. Замер живьём (uid=1000, /bin/bash):

        out=$(ls -d /etc/hosts 2>/dev/null && echo "exists")  -> "/etc/hosts\\nexists"
        [ "$out" = exists ]                                  -> ложь ВСЕГДА

    `ls -d` печатает сам путь, `echo` идёт второй строкой, а `strip()` убирает
    только края. То есть get_config_files возвращал [] всегда, и редактор
    честно рапортовал «Конфигурационные файлы не найдены» на сервере, где все
    конфиги есть. Тесты этого не видели: двойник возвращал идеальный 'exists\\n',
    которого ls не выдаёт никогда (урок: двойник обязан говорить то, что
    говорит система).

    Второе враньё — `2>/dev/null`: в stderr лежит единственная строка, где
    написано, почему пусто («Permission denied» против «No such file or
    directory»), а для оператора это два разных действия — поднимать права или
    проверять раскладку. Третье: пустой ПРОЧИТАННЫЙ каталог добавлялся в список
    как файл, и редактор открывал каталог как конфиг (ровно isdir из 1.21.0).

    Теперь состояние каталога и список даёт примитив find_files_info (1.20.0)
    — ОДНОЙ командой на путь вместо двух слепых, поэтому различение состояний
    не подорожало. Панельные каталоги обходятся `find` (рекурсивно — так и
    было), но без `2>/dev/null`: вывод `find` про права и про отсутствие
    файла читаются из stderr.
    """
    files = []
    notes = []
    asked = 0
    confirmed = 0

    for path in CONFIG_PATHS:
        # glob намеренно НЕ через q(): в кавычках ls ищет файл со звездой в
        # имени — так '/etc/php/*/php.ini' терялся из редактора всегда.
        pattern = path + '*' if path.endswith('/') else path
        info = find_files_info(checker, pattern, CONFIG_LIMIT)
        asked += 1
        files.extend(info['paths'])
        # total is None и пустые dirs — ответа нашей команды не было вовсе
        # (обрыв, чужой ls). Молчать в этом случае значит соврать, что путей
        # нет; но и жалобу на каждый из 16 путей печатать нельзя — причина
        # у них одна.
        if info['dirs'] or info['total'] is not None:
            confirmed += 1
        for note in info['notes']:
            if note not in notes:
                notes.append(note)

    for path in PANEL_CONFIG_PATHS.get(panel_type, []):
        # LC_ALL=C: классификатор ниже читает текст errno, а на сервере с
        # ru_RU find пишет «Отказано в доступе» — ветка «нет прав» молчала бы
        # и закрытый каталог подавался бы как «прочитан, файлов нет» (тот же
        # закон 1.32.12, из-за которого текстовые признаки вытесняются rc;
        # здесь rc не различает миры — find даёт 0 и с предупреждениями).
        out, err = checker.exec_command(
            f'LC_ALL=C find {q(path)} -type f | head -{CONFIG_LIMIT}')
        # Из строки убираем ТОЛЬКО перевод строки. strip() резал бы и пробелы
        # на краях имени: «/etc/nginx/vhosts/мой сайт .conf» превращалось бы в
        # путь без пробела на конце, редактор открывал бы его, а «Сохранить»
        # писал бы по СОСРЕДОТОЧЕННОМУ пути — то есть заводил бы второй файл
        # рядом с настоящим (тот же закон, что у read_file: возвращаемое
        # значение редактор вернёт на сервер байт в байт).
        for line in (out or '').split('\n'):
            found = line.rstrip('\r')
            if found.strip():
                files.append(found)
        low = (err or '').lower()
        why = next((l.strip() for l in (err or '').splitlines() if l.strip()),
                   '')[:160]
        if 'permission denied' in low:
            note = FF_DIR_TEXT['noperm'].format(path=path, why=why)
        elif 'no such file' in low:
            note = FF_DIR_TEXT['missing'].format(path=path, why=why)
        elif why:
            # Любой нераспознанный stderr — «не проверено», а не «файлов
            # нет»: I/O error, 'find: command not found', прочий errno (rc
            # пайпа принадлежит head и нам не принадлежит). Молчать здесь
            # значило бы подать сломанный спрос как честный пустой ответ.
            note = FF_DIR_TEXT['blocked'].format(path=path, why=why)
        else:
            # Пустой вывод БЕЗ ошибки: каталог прочитан, файлов нет — честный
            # ответ. Жалоба на него обесценила бы настоящие предупреждения
            # (то же решение, что в 1.24.0–1.26.0).
            note = None
        if note and note not in notes:
            notes.append(note)

    if asked and not confirmed:
        notes.append(NOT_SEARCHED_NOTE.format(n=asked))
    return sorted(set(files))[:CONFIG_MAX], notes


def get_config_files(checker, panel_type):
    """Список конфиг-файлов — прежняя форма без причин пустоты.

    ''-списка тут мало: он значит и «файлов нет», и «мы не смогли посмотреть».
    Редактор обязан звать get_config_files_info.
    """
    return get_config_files_info(checker, panel_type)[0]


# ==================== ЗАМЕНА IP ====================
# Адрес уходит в sed-паттерн, поэтому права на подстановку даёт НЕ «валиден ли
# IP», а алфавит строки. Замер живьём на интерпретаторе проекта (Python 3.15):
# IPv6Address("fe80::1%'; touch PWN ; '") — ВАЛИДЕН (scope ID после '%' принимает
# произвольный ASCII), а апостроф разрывает кавычение 's/.../.../g' — то есть
# «проверили IP» раньше не значило «в команде только адрес» (1.32.30).
_IP_TEXT_RE = re.compile(r'[0-9a-fA-F:.]+\Z')

# Заглушка для re.search, когда маркера прав в выводе нет: «прав не снято»,
# а не «прав 000» — пустая строка в отчёте честнее выдуманного значения.
_NO_MODE = type('_NoMode', (), {'group': staticmethod(lambda n: '')})


def _ip_in_sed(value):
    """True, если строка — адрес из допустимого алфавита, иначе False.

    Только [0-9a-fA-F:.]: без '/', '%', пробелов и кавычек. Кавычки и перевод
    строки исключаются самим классом, поэтому метасимволы в sed невозможны.

    Право на подстановку имеет ТОЛЬКО str. Не-строку (int) принимал
    ipaddress.IPv4Address(1) — валидатор пропускал, `_sed_ip_pattern` падал на
    value[0] (замер на venv 3.15: TypeError 'int' object is not subscriptable),
    а прошла бы такая строка через `str()` — sed выжигал бы одиночную цифру во
    всём /etc. Короткие формы («1», «01.2.3.4», «1.2») отбраковывает сам
    ipaddress — замер на venv 3.15: AddressValueError, поэтому алфавита и
    проверки типа хватает; ослаблять их нельзя (пункт 5 закона серии:
    не-строка — это не адрес).
    """
    return isinstance(value, str) and bool(_IP_TEXT_RE.match(value))


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


def _sed_ip_pattern(value):
    r"""BRE-паттерн sed для адреса: точки экранированы, границы слова по месту.

    Неэкранированная точка матчит любой символ (замер паттерна: 1.2.3.4
    попадал в 211x2x3x4x5). Границы \</\> защищают от подстрочных попаданий
    (1.2.3.4 внутри 211.2.3.45 — замер до правки: портило чужие конфиги).
    Границы ставятся только там, где они вообще способны сработать: в GNU sed
    ':' — не-word символ, и \</ перед паттерном, начинающимся с ':' ( '::1' ),
    не матчится никогда — замена молча не происходит (замер sed 4.10:
    'b=::1' c \</::1\>/ не изменился, без границ — изменился).
    """
    body = str(value).replace('.', '\\.')
    if body[0].isalnum() or body[0] == '_':
        body = '\\<' + body
    if body[-1].isalnum() or body[-1] == '_':
        body = body + '\\>'
    return body


def _etc_backup_or_veto(checker, lines):
    """Резерв /etc перед массовой заменой; путь к резерву или None (операция снята).

    Прежняя ipv6-ветка печатала «не удалось создать резерв (продолжаем)» и
    шла переписывать /etc без средства отката, а ipv4-ветка вообще не делала
    резерва (закон серии: право на destructive-операцию даёт записанный
    откат, а не обещание).
    """
    ensure_backup_dir(checker)
    ts = backup_stamp()
    etc_backup = f"{BACKUP_SUBDIRS['configs']}/etc_{ts}.tar.gz"
    # Архив /etc — это тень /etc/shadow, ключей и панельных паролей. Без umask
    # он создаётся по umask вызывающего (замер на venv-машине, GNU tar 1.35:
    # без umask файл 0644 — читать может любой локальный пользователь сервера),
    # то есть «мы сделали откат» оборачивалась бы выгрузкой секретов в общее
    # место. umask 077 ставится ДО создания файла (права должны быть у файла с
    # первой секунды, а не «записали, потом починили» — тот же порядок, что у
    # prepare_secret_file), chmod 600 — страховка для случая, когда файл уже
    # занимали. Код возврата отдаём ТАРОВСКИЙ (__tar): chmod не имеет права ни
    # отменить успех резерва, ни объявить его провалом.
    # -P убирает служебную строку «Removing leading /»: иначе при провале её
    # печатают ПЕРВОЙ и оператор читает её как причину (замер tar 1.35 на
    # битом пути: без -P первая строка — именно это уведомление, а не ошибка).
    q_backup = q(etc_backup)
    out, err, brc = checker.run(
        f'umask 077; tar czf {q_backup} -P /etc 2>&1; __tar=$?; '
        f'chmod 600 {q_backup} 2>/dev/null; '
        f'printf "\\nARCHMODE=%s\\n" "$(stat -c %a {q_backup} 2>/dev/null)"; '
        f'exit $__tar')
    body = '\n'.join([(out or ''), (err or '')])
    why = next((l.strip() for l in (out or err or '').splitlines()
                if l.strip() and not l.startswith('ARCHMODE=')), '')[:160]
    if brc == 1:
        # Замер (GNU tar 1.35): rc=1 — это НЕ «архива нет», а «файл изменился
        # во время чтения»: архив на диске и в нём есть почти всё, но один
        # файл внутри может быть рассогласован. «Резерв не создан» соврал бы
        # про факт (файл создан), а «резерв готов» врал бы про смысл (откат,
        # который не ручается за весь /etc, откатом не считается). Операцию
        # это по-прежнему снимает.
        lines.append('⚠️ Резерв /etc неполный (tar rc=1'
                     + (f': {why}' if why else '') + f'): архив {etc_backup} '
                     'создан, но часть файлов могла измениться при считывании.')
        lines.append('❌ Правка снята: рассогласованный откат откатом не '
                     'считаем; повторите замену, когда /etc затихнет.')
        return None
    if brc != 0:
        lines.append(f'❌ Правка снята: резерв /etc не создан (rc={brc}'
                     + (f': {why}' if why else '') + '). Без отката массовую '
                     'замену не отправляем.')
        return None
    # Права названы СНИМКОМ, а не намерением: «сделали 0600» без stat — то же
    # обещание без замера, из-за которого вся серия воюет с кодами «на веру».
    mode = (re.search(r'ARCHMODE=(\S+)', body) or _NO_MODE).group(1)
    if mode != '600':
        lines.append(f"⚠️ Резерв /etc НЕ защищён от чтения другими "
                     f"пользователями (права {mode or 'не сняты'}): архив "
                     f"содержит /etc/shadow и ключи. Правку делаем, но "
                     f"файл {etc_backup} надо снять или закрыть вручную.")
    lines.append(f'✅ Резервная копия /etc: {etc_backup} '
                 f'(откат: tar xzf {q(etc_backup)} -C /)')
    return etc_backup


def replace_ipv4(checker, old_ip, new_ip):
    """Замена старого IPv4 на новый во всех *.conf в /etc (как в ручной команде).

    Право на подстановку даёт алфавит строки (_ip_in_sed), а не только факт
    валидности адреса; sed-паттерн экранирован и ограничен границами слова.
    """
    lines = [f"=== ЗАМЕНА IPv4: {old_ip} -> {new_ip} ==="]
    if not (_valid_ipv4(old_ip) and _valid_ipv4(new_ip)
            and _ip_in_sed(old_ip) and _ip_in_sed(new_ip)):
        lines.append("❌ Некорректный IPv4-адрес — операция отменена.")
        return "\n".join(lines)
    etc_backup = _etc_backup_or_veto(checker, lines)
    if etc_backup is None:
        return "\n".join(lines)
    # Экранируем точки и границы: s#\<1\.2\.3\.4\>#...#g
    cmd = (
        f"find /etc -type f -name \"*.conf\" "
        f"-exec sed -i -e 's#{_sed_ip_pattern(old_ip)}#{new_ip}#g' '{{}}' \\;"
    )
    out, err, rc = checker.run(cmd)
    if rc == 0:
        lines.append("✅ IPv4 заменён во всех .conf-файлах в /etc (rc=0).")
    else:
        # Прежняя форма печатала «✅ заменён» и здесь тоже: частичный провал
        # (часть файлов не переписана — права, read-only) читался как полный
        # успех. Полноту по этому rc утверждать нельзя, но и «ничего не
        # сделано» — нельзя: какие файлы переписались, не измеряно.
        why = next((l.strip() for l in (err or out or '').splitlines()
                    if l.strip()), '')[:160]
        lines.append(f"⚠️ Замена НЕ подтверждена целиком (rc={rc}"
                     + (f': {why}' if why else '') + f'). Часть файлов может '
                     f'быть не переписана; резерв: {etc_backup}')
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

    Раньше комментарий утверждал: «strictly валидируются → инъекция
    исключена». Это было ложью: IPv6Address принимает scope ID после '%'
    (замер на venv проекта: "fe80::1%'; touch PWN ; '" — VALID), а scope —
    произвольный ASCII. Теперь право на подстановку даёт алфавит
    (_ip_in_sed: только [0-9a-fA-F:.]), а не факт валидности.
    """
    lines = [f"=== ЗАМЕНА IPv6: {old_ip} -> {new_ip} ==="]
    if not (_valid_ipv6(old_ip) and _valid_ipv6(new_ip)
            and _ip_in_sed(old_ip) and _ip_in_sed(new_ip)):
        lines.append("❌ Некорректный IPv6-адрес — операция отменена.")
        return "\n".join(lines)

    # Автобэкап /etc перед массовой заменой — и вето, если резерв не записан.
    etc_backup = _etc_backup_or_veto(checker, lines)
    if etc_backup is None:
        return "\n".join(lines)

    cmd = (f"find /etc -type f -exec sed -i "
           f"'s/{_sed_ip_pattern(old_ip)}/{new_ip}/g' {{}} +")
    out, err, rc = checker.run(cmd)
    if rc == 0:
        lines.append("✅ IPv6 заменён во всех файлах в /etc (rc=0).")
    else:
        why = next((l.strip() for l in (err or out or '').splitlines()
                    if l.strip()), '')[:160]
        lines.append(f"⚠️ Замена НЕ подтверждена целиком (rc={rc}"
                     + (f': {why}' if why else '') + f'). Часть файлов может '
                     f'быть не переписана; резерв: {etc_backup}')
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
        presence = unit_presence_info(checker, svc)
        if not presence['checked']:
            # Молчание list-unit-files — «мы не спросили», а не «службы нет».
            # Прежний признак: list-unit-files | grep -q ... && echo yes ||
            # echo no. Замер живьём: побайтово одинаковый 'no' rc=0 дают и
            # genuine отсутствие, и bus-мёртвый systemctl, и пустой вывод —
            # конвейер выбрасывает И код systemctl, И непустоту его stdout, а
            # '|| echo no' довершает подмену: «мы не спросили» становится
            # «службы нет». По «не проверено» действие не предпринимается: ни
            # reload, ни вопрос is-active, ни ложного «не установлен».
            lines.append(f"⚠️ {svc}: наличие не проверено, "
                         f"{action} по непроверенному признаку не предпринят")
            lines.append(presence['note'])
            continue
        if presence['presence'] != 'present':
            # Здесь ответила система: genuine «юнита нет в списке». Прежний
            # вердикт сохранён дословно — он правдив по существу.
            lines.append(f"⏭️ {svc} не установлен")
            continue
        _, _, arc = checker.run(f'systemctl {action} {svc} 2>/dev/null')
        status = unit_status_info(checker, svc)
        if not status['checked']:
            # Молчание systemctl — «мы не спросили», а не «не активно». Прежний
            # код решал по пустой строке и по ней же делал лишний `systemctl
            # restart` (fallback): действие по непроверенному признаку. Ни
            # fallback, ни красного диагноза, ни второго вопроса — только
            # причина, снятая с незаглушённого stderr.
            lines.append(f"⚠️ {svc}: состояние после {action} не проверено, "
                         f"перезапуск по непроверенному признаку не предпринят")
            lines.append(status['note'])
            continue
        if status['status'] == 'active':
            lines.append(f"✅ {svc} ({action}) выполнен")
            continue
        # Здесь ответила система, а не мы промолчали: прежний путь (fallback
        # restart) и прежние вердикты сохраняются дословно.
        _, _, rrc = checker.run(f'systemctl restart {svc} 2>/dev/null')
        after = unit_status_info(checker, svc)
        if not after['checked']:
            # Перезапуск сделан по настоящему ответу, но подтвердить его чем?
            # Молчание не подтверждает и не опровергает: утверждать «запущен»
            # или «не запустился» по нему нельзя.
            lines.append(f"⚠️ {svc} перезапуск отправлен (rc={rrc}), но "
                         f"состояние после него не проверено")
            lines.append(after['note'])
        elif after['status'] == 'active':
            lines.append(f"✅ {svc} перезапущен (fallback)")
        else:
            lines.append(f"❌ {svc} не запустился (rc={rrc}, reload rc={arc})")
    return lines
