"""Общие конфигурации и вспомогательные функции диагностики."""
import os
import shlex
from datetime import datetime

# Единственный источник правды о версии. От неё зависят заголовок окна,
# CHANGELOG.md и тег релиза (тэг всегда v<__version__>).
__version__ = "1.27.0"

# ==================== КОНФИГУРАЦИИ ====================
BACKUP_DIR = "/root/tech_support"
BACKUP_SUBDIRS = {
    'configs': f"{BACKUP_DIR}/configs",
    'dns': f"{BACKUP_DIR}/dns",
    'crontab': f"{BACKUP_DIR}/crontab",
    'swap': f"{BACKUP_DIR}/swap"
}

LOG_PATHS = {
    'fastpanel': {
        'error': '/var/www/*/data/logs/*error.log',
        'access': '/var/www/*/data/logs/*access.log',
        'home_error': '/home/*/logs/*error.log',
        'home_access': '/home/*/logs/*access.log'
    },
    'ispmanager': {
        'error': '/var/www/*/data/logs/error.log',
        'access': '/var/www/*/data/logs/access.log',
        'httpd_error': '/var/www/httpd-logs/*.error.log',
        'httpd_access': '/var/www/httpd-logs/*.access.log'
    },
    'none': {
        'nginx_error': '/var/log/nginx/*error.log',
        'nginx_access': '/var/log/nginx/*access.log',
        'apache_error': '/var/log/apache2/*error.log',
        'apache_access': '/var/log/apache2/*access.log',
        'httpd_error': '/var/log/httpd/*error_log',
        'httpd_access': '/var/log/httpd/*access_log'
    }
}

DOMAIN_PATHS = {
    'fastpanel': [
        '/etc/nginx/fastpanel2-available/*/*.conf',
        '/usr/local/fastpanel/etc/nginx/sites-available/*',
        '/etc/nginx/sites-available/*'
    ],
    'ispmanager': [
        '/etc/nginx/vhosts/*/*',
        '/etc/nginx/vhosts/*',
        '/etc/nginx/vhosts/*/*.conf',
        '/etc/nginx/vhosts/*.conf',
        '/usr/local/mgr5/etc/nginx/vhosts/*.conf',
        '/usr/local/mgr5/etc/nginx/vhosts/*/*.conf',
        '/usr/local/mgr5/etc/nginx/sites-enabled/*.conf',
        '/usr/local/mgr5/etc/nginx/conf.d/*.conf',
        '/etc/nginx/sites-enabled/*',
        '/etc/nginx/conf.d/*.conf'
    ],
    'none': [
        '/etc/nginx/sites-enabled/*',
        '/etc/nginx/conf.d/*.conf',
        '/etc/apache2/sites-enabled/*.conf'
    ]
}


# ==================== ВСПОМОГАТЕЛЬНЫЕ ФУНКЦИИ ====================
def q(value):
    """Безопасное экранирование значения для вставки в shell-команду."""
    return shlex.quote(str(value))


def ensure_backup_dir(checker):
    """Создаёт директорию для бэкапов, если её нет"""
    out, _, rc = checker.run(f'mkdir -p {q(BACKUP_DIR)} 2>/dev/null && echo "created"')
    for subdir in BACKUP_SUBDIRS.values():
        checker.run(f'mkdir -p {q(subdir)} 2>/dev/null')
    return rc == 0 and out.strip() == 'created'


def create_backup(checker, filepath, backup_type='configs'):
    """
    Создаёт резервную копию файла с временной меткой в соответствующей поддиректории.
    Возвращает путь к бэкапу или None в случае ошибки.
    """
    ensure_backup_dir(checker)

    filename = os.path.basename(filepath)
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    backup_filename = f"{filename}.{timestamp}.bak"
    backup_path = f"{BACKUP_SUBDIRS.get(backup_type, BACKUP_SUBDIRS['configs'])}/{backup_filename}"

    out, _, rc = checker.run(f'test -f {q(filepath)} && echo "exists"')
    if rc != 0 or out.strip() != 'exists':
        return None

    _, _, rc = checker.run(f'cp {q(filepath)} {q(backup_path)} 2>&1')
    if rc != 0:
        return None

    out, _, rc = checker.run(f'test -f {q(backup_path)} && echo "exists"')
    if rc == 0 and out.strip() == 'exists':
        return backup_path
    return None


def save_crontab_backup(checker):
    """Сохраняет текущий crontab в файл бэкапа. Возвращает путь или None."""
    ensure_backup_dir(checker)
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    backup_path = f"{BACKUP_SUBDIRS['crontab']}/crontab.{timestamp}.bak"
    out, _, rc = checker.run(f'crontab -l > {q(backup_path)} 2>/dev/null && echo "ok"')
    if rc == 0 and out.strip() == 'ok':
        return backup_path
    return None


def write_remote_file(checker, filepath, content):
    """
    Надёжно записывает содержимое в удалённый файл через SFTP.
    Возвращает (success: bool, error: str|None).
    """
    try:
        sftp = checker.client.open_sftp()
    except Exception as e:
        return False, f"Не удалось открыть SFTP: {e}"
    try:
        with sftp.open(filepath, 'w') as f:
            f.write(content)
        return True, None
    except Exception as e:
        return False, str(e)
    finally:
        sftp.close()


# ==================== СЛУЖЕБНЫЙ КАНАЛ: УБОРКА СЕКРЕТОВ ====================
def service_run(checker, command):
    """Команда, которую отмена обязана пропустить: chmod/rm над секретом.

    Отмена означает «прекрати работу», а не «оставь файл с паролем на диске».
    У ServerChecker для этого есть cleanup(); у тестовых заглушек его может не
    быть — тогда обычный run, иначе тесты перестали бы видеть уборку.
    """
    cleanup = getattr(checker, 'cleanup', None)
    if cleanup is not None:
        return cleanup(command)
    return checker.run(command)


def prepare_secret_file(checker, filepath, content):
    """Создаёт файл с паролем сразу безопасным: (True, None) либо (False, причина).

    Порядок принципиален и в нём весь смысл:

    1. `rm -f` — по фиксированному пути мог лежать чужой файл или symlink
       (атака на /tmp/.techsupp_*.cnf): SFTP-запись пошла бы по symlink и
       затёрла бы его цель.
    2. создание при `umask 077` + `chmod 600` — файл получает 0600 ДО того,
       как в нём появится пароль. Прежний порядок «записали, потом chmod»
       давал окно world-readable файла, а отмена между этими шагами оставляла
       его навсегда (chmod шёл через cancel-гейт).
    3. SFTP пишет в УЖЕ созданный файл: truncate прав не меняет (проверено:
       umask 022 -> 644, umask 077 -> 600, после перезаписи снова 600).

    Все команды идут через service_run — уборка и права не должны зависеть от
    того, нажал ли оператор «Стоп».
    """
    target = q(filepath)
    cmd = (f'rm -f {target} 2>/dev/null; umask 077; : > {target} 2>/dev/null; '
           f'chmod 600 {target} 2>/dev/null; '
           f'if [ ! -w {target} ]; then echo NOWRITE; fi')
    try:
        out, err, _rc = service_run(checker, cmd)
    except Exception as e:
        return False, f'не удалось создать файл {filepath}: {e}'
    if 'NOWRITE' in (out or ''):
        detail = (err or '').strip()
        return False, (f'в {filepath} нельзя писать (файл чужой или /tmp только '
                       f'для чтения)' + (f': {detail}' if detail else ''))
    ok, why = write_remote_file(checker, filepath, content)
    if not ok:
        remove_remote_path(checker, filepath, recursive=False)
        return False, f'не удалось записать {filepath}: {why}'
    return True, None


def remove_remote_path(checker, path, recursive=True):
    """Удаляет удалённый путь и ПРОВЕРЯЕТ факт: возвращает (ok, причина).

    Код возврата rm ни о чём не говорит (`rm -rf` не ругается даже на несуществующее),
    поэтому факт проверяем тем же вызовом — `[ -e путь ]`. Остаться должен либо
    подтверждённый успех (тогда в отчёте честно пишется «файл удалён»), либо
    причина, которую оператор обязан увидеть.

    Идёт через service_run: cancel() не должен превращать уборку в «секрет
    пережил операцию» (именно так и было, пока rm шёл через обычный run).
    """
    flag = '-rf' if recursive else '-f'
    target = q(path)
    command = (f'rm {flag} {target} 2>/dev/null; '
               f'if [ -e {target} ]; then echo STILL_THERE; fi')
    try:
        out, _err, _rc = service_run(checker, command)
    except Exception as e:
        return False, f'команда удаления не прошла: {e}'
    if 'STILL_THERE' in (out or ''):
        return False, f'путь остался на сервере: {path}'
    return True, None


# Состояние каталога, которое команда спрашивает ДО ls. Пустой вывод `ls` дают
# четыре разных ситуации, и две из них для оператора означают противоположные
# действия (менять параметры поиска против поднимать права).
FF_DIR_TEXT = {
    'missing': ("⚠️ Каталога {path} нет на сервере — искать в нём негде: "
                "проверьте раскладку и тип панели"),
    'noperm': ("⚠️ Каталог {path} не читается под этим пользователем: нет прав "
               "на каталог (нужны r-x). Файлы могут быть — это «мы не увидели», "
               "а не «файлов нет»: прогоните под root или добавьте оператора в "
               "группу"),
    'blocked': ("⚠️ Путь {path} недоступен под этим пользователем — ответ "
                "системы: «{why}». Проверить содержимое нельзя, поэтому о файлах "
                "ничего не известно: это «не проверено», а не «файлов нет». "
                "Прогоните под root или дайте оператору доступ (обычно группа adm)"),
}

# awk вместо `head`: считает ВСЕ файлы и печатает только первые L. `head -N`
# резал список молча — оператор не знал, сколько логов не участвовало в отчёте.
_FF_AWK = '{k++; if(k<=L) print} END{printf "FFCOUNT %d\\n", k}'


def find_files_cmd(pattern, limit=20):
    """Одна POSIX-команда: состояние каталога + список + честное число файлов.

    Строится так, потому что код возврата тут бесполезен. Замерено живьём:
    `ls -1 GLOB` даёт rc=2 и для «файлов нет», и для «каталога нет», и для «нет
    прав» (текст stderr различает, rc — нет). Строить на rc, как в 1.18.0 и
    1.19.0, здесь нельзя; различает только ветки `[ ! -d ]` / `[ ! -r ]`
    / `[ ! -x ]` по каталогу, поэтому они стоят ДО ls.

    `${PIPESTATUS}` не используем: под dash (обычный /bin/sh в Debian/Ubuntu) он
    «Bad substitution», а после присваивания `o=$(…|…)` относится не к конвейеру
    (обе грабли замерены живьём на прошлых слайсах).

    Какие каталоги спрашивать — считает python, а не shell. В паттернах панелей
    `*` стоит в середине пути ('/var/www/*/data/logs/*.log'), поэтому одного
    dirname мало: берём (а) префикс до первого `*` — он никогда не содержит
    glob, его можно спросить напрямую, и (б) dirname целиком — он ловит закрытый
    каталог ГЛУБИЕ первого `*`. Без пункта (а) кейс «нет прав» врал: при закрытом
    /var/www глоб не раскрывается, dirname остаётся со звёздочкой, `[ ! -d ]`
    отвечает «нет каталога» — и оператор вместо «подними права» идёт искать
    другой домен (замерено живьём на первой версии формы).

    Раскрытие — `set --` + `for d in "$@"`, а не `for d in $D`: pathname
    expansion не бьёт имена по пробелам (у панелей бывают '/var/www/my site/…'),
    а нераскрывшийся кандидант остаётся с `*` и честно пропускается — выдумывать
    про него «каталога нет» нельзя. `$(dirname …)` не используем вообще: во-первых
    `${PIPESTATUS}`/подстановки ломаются о dash, во-вторых команда с `$( )`
    перестала бы быть читаемой как `ls -1 <glob>` буквально.

    `stderr` не глушится: `2>/dev/null` терял ровно ту строку
    (`Permission denied` / `No such file or directory`), где написана причина
    пустоты.

    ВНИМАНИЕ: pattern — shell-glob, он НЕ экранируется через q() намеренно и
    уходит в `ls -1` буквально: в кавычках ls искал бы файл с `*` в имени.
    """
    n = max(1, int(limit))
    prefix = pattern.split('*', 1)[0]
    prefix = prefix[:prefix.rfind('/') + 1]
    parent = pattern[:pattern.rfind('/')] if '/' in pattern else ''
    cands = []
    for cand in (prefix, parent):
        cand = cand.rstrip('/')
        if cand and cand not in cands:
            cands.append(cand)
    return (
        f'set -- {" ".join(cands)}; '
        'for d in "$@"; do '
        'case "$d" in *"*"*) continue;; esac; '
        'if [ ! -d "$d" ]; then echo "FFDIR missing $d"; '
        'elif [ ! -r "$d" ] || [ ! -x "$d" ]; then echo "FFDIR noperm $d"; '
        'else echo "FFDIR ok $d"; fi; '
        'done; '
        f'ls -1 {pattern} | awk -v L="{n}" \'{_FF_AWK}\''
    )


def parse_find_answer(out):
    """(пути, состояния каталогов, total) из ответа команды.

    total=None — маркера FFCOUNT не было (обрыв, чужая реализация): выдумывать
    число не имеем права. Пустой список каталогов — то же самое: мы не знаем,
    читали ли каталог.
    """
    paths, dirs, total = [], [], None
    for line in (out or '').splitlines():
        s = line.strip()
        if not s:
            continue
        if s.startswith('FFCOUNT '):
            try:
                total = int(s.split(' ', 1)[1].strip())
            except ValueError:
                total = None
        elif s.startswith('FFDIR '):
            parts = s.split(' ', 2)
            dirs.append((parts[1] if len(parts) > 1 else '',
                         parts[2] if len(parts) > 2 else ''))
        else:
            paths.append(s)
    return paths, dirs, total


def find_files_info(checker, pattern, limit=20):
    """Ищет файлы и возвращает, ЧЕМЫ объясняется пустота.

    dict(paths, dirs, total, notes). notes — готовые оператору строки про
    закрытые/отсутствующие каталоги и про срезку лимитом; они начинаются с
    «⚠️», поэтому уже написанные потребители (logs, discovery, webcheck)
    отфильтруют их как не-пути, ничего в себе не меняя.
    """
    out, err, _rc = checker.run(find_files_cmd(pattern, limit))
    paths, dirs, total = parse_find_answer(out)
    # Приоритет у ответа системы, а не у `[ ! -d ]`. Замерено живьём: когда закрыт
    # РОДИТЕЛЬСКИЙ каталог, `[ ! -d ]` отвечает «нет каталога» — он физически не
    # может отличить «его нет» от «его не видно» (нужен x на каждый сегмент выше).
    # Строка `Permission denied` в stderr различает, а `2>/dev/null` в прежней
    # команде выбрасывал именно её. Пока система говорит про права, утверждать
    # «каталога нет, проверьте раскладку» нельзя: это отправит оператора чинить не
    # то (первое поколение этой правки врал ровно так — поймано живым прогоном).
    if 'permission denied' in (err or '').lower() and not paths:
        dirs = [('blocked' if st == 'missing' else st, p) for st, p in dirs]
        if not dirs:
            parent = pattern[:pattern.rfind('/')] or pattern
            dirs = [('blocked', parent)]
    why = ''
    for line in (err or '').splitlines():
        if line.strip():
            why = line.strip()[:160]
            break
    # Один и тот же каталог приходит дважды (префикс до `*` и dirname от него же:
    # '/var/log/nginx/' и '/var/log/nginx'). Дедуп здесь, а не в команде: решение
    # «что показывать оператору» должно жить в одном месте (грабель v1.18 —
    # признак, посчитанный дважды, однажды разъезжается).
    seen = set()
    uniq = []
    for state, path in dirs:
        key = (state, path.rstrip('/'))
        if key not in seen:
            seen.add(key)
            uniq.append((state, path.rstrip('/')))
    dirs = uniq
    notes = []
    for state, path in dirs:
        text = FF_DIR_TEXT.get(state)
        if text:
            notes.append(text.format(path=path, why=why))
    if total is not None and total > len(paths):
        notes.append(f"⚠️ Показаны первые {len(paths)} файлов из {total}: "
                     f"остальные в этом отчёте не участвовали")
    return {'paths': paths, 'dirs': dirs, 'total': total, 'notes': notes}


def find_files(checker, pattern, limit=20):
    """Находит файлы по паттерну; предупреждения — отдельными ⚠️-строками.

    ВНИМАНИЕ: pattern — это shell-glob (напр. '/var/log/nginx/*.log'),
    поэтому он НЕ экранируется через q() намеренно.
    """
    info = find_files_info(checker, pattern, limit)
    return info['paths'] + info['notes']


def find_file_info(checker, patterns):
    """(первый найденный путь, причины пустоты) — различает «нет файла» и «нет прав».

    Прежний `find_file` возвращал None на любую неудачу:

        out, _, _ = checker.run(f"ls -1 {pattern} 2>/dev/null | head -1")

    То есть «файла нет», «каталога нет» и «нет прав на каталог» — три ответа с
    ПРОТИВОПОЛОЖНЫМ лечением — сливались в одно None, а вызывающий код
    (поиск конфига среди нескольких раскладок) не мог отличить «пробуй следующий
    путь» от «у тебя нет прав ничего увидеть». Различение уже посчитано в
    find_files_info (v1.20.0), здесь оно только отдаётся наружу.
    """
    notes = []
    for pattern in patterns:
        info = find_files_info(checker, pattern, 1)
        if info['paths']:
            return info['paths'][0], []
        notes.extend(info['notes'])
    return None, notes


def find_file(checker, patterns):
    """Находит первый существующий файл из списка паттернов (glob, без q())."""
    return find_file_info(checker, patterns)[0]


# Причина, по которой файл не прочитан. Тексты — оператору, а не в лог.
RF_TEXT = {
    'unreadable': "не читается под этим пользователем: нет прав на файл "
                  "(обычно нужен root или членство в группе файла)",
    'missing': "файла нет на сервере — проверьте раскладку и тип панели",
    'isdir': "по этому пути каталог, а не файл",
    'unchecked': "состояние не проверено: сервер не подтвердил чтение (ответ "
                 "пуст). Повторите проверку: прошлая могла оборваться",
}

def log_reader(path):
    """Читатель файла: `zcat` для ротированных .gz, иначе `cat`.

    Одно место на весь проект: его зовут и construction команды (read_file_cmd),
    и webcheck (grep_log_command). Записанный дважды признак однажды разъезжается
    — отчёт начинает называть отсутствующей не ту утилиту (грабель v1.18.0,
    лечилась в v1.19.0 на `whois_record_lines`/`log_reader`).
    """
    return 'zcat' if str(path).endswith('.gz') else 'cat'


_RF_MARK = 'RFSTATE '


def read_file_cmd(path, reader=None):
    """Одна POSIX-команда: состояние файла + его содержимое.

    Штатная форма чтения была `cat {q(path)} 2>/dev/null` с `if rc != 0: return
    None`. Замерено живьём (uid=1000), rc=1 дают два противоположных случая:

        locked.conf       rc=1  stderr=cat: …: Permission denied
        nope.conf         rc=1  stderr=cat: …: No such file or directory

    а `2>/dev/null` выбрасывал ровно ту строку, где написана причина. Плюс rc=0
    бывает и у прочитанного пустого файла, и у прочитанного файла — «пусто» тоже
    нуждалось в отдельном ответе.

    POSIX-тесты `[ -e ]`/`[ -r ]` дают первичное состояние, НО `cat` вызывается
    ВСЕГДА: у файла внутри закрытого каталога `[ ! -e ]` отвечает «нет файла»
    (stat невозможен без x на каталог), хотя система говорит «Permission denied»
    — тот же закон, что спас в 1.20.0 на уровне каталога, но уровнем ниже.
    Поэтому свидетель (stderr) обязан быть, а решает python.

    Маркер состояния — ПЕРВАЯ строка ответа, содержимое идёт после: иначе файл,
    первой строкой которого стоит «RFSTATE …», выглядел бы как служебный ответ
    (подделка состояния данными — замерено).

    `${PIPESTATUS}` нет вовсе (dash: «Bad substitution»), `$(…)` нет (ломает
    замок инъекции и читаемость), `2>/dev/null` нет (губит причину).

    Читатель — `log_reader(path)`, то есть для ротированных `.gz` это `zcat`.
    Архивы раньше читались отдельной строкой со своим `2>/dev/null`
    (`zcat … 2>/dev/null` в analyze_access_log), и «архив битый» для отчёта был
    тем же, что «записей нет». Различение уже есть здесь — второй реализации не
    будет (единый читатель, как `log_reader` в 1.19.0).
    """
    p = q(path)
    r = reader or log_reader(path)
    return (f'if [ -d {p} ]; then echo "RFSTATE isdir"; '
            f'elif [ ! -e {p} ]; then echo "RFSTATE missing"; '
            f'elif [ ! -r {p} ]; then echo "RFSTATE unreadable"; '
            f'else echo "RFSTATE readable"; fi; '
            f'{r} {p}')


def parse_read_answer(out, err):
    """(state, content) из ответа read_file_cmd; state=None — маркера не было.

    Тело отдаётся БАЙТ В БАЙТ. Прежний вариант собирал его как
    `'\\n'.join(splitlines()[1:])`, а splitlines() отбрасывает завершающий
    перевод строки и режет по '\\r\\n', выбрасывая сам '\\r'. Замер живьём
    (read_file_info против НАСТОЯЩИХ файлов, /bin/bash, uid=1000) — 4 из 6
    форматов возвращались укороченными:

        'worker 4;\\n'       -> 'worker 4;'      <<< потеря
        'a;\\nb;\\n'           -> 'a;\\nb;'           <<< потеря
        'a;\\n\\n\\n'            -> 'a;\\n\\n'          <<< потеря
        'a;\\r\\nb;\\r\\n'       -> 'a;\\nb;'           <<< потеря (и \\r тоже)

    Для лога это безразлично (его всё равно считают splitlines'ом), для
    редактора конфига — тихая порча данных: `gui_files` при сохранении делает
    rstrip('\\n'), поэтому «открыл → Сохранить» без единой правки переписывал
    конфиг без завершающей строки. Различить «не прочитал» и «прочитал иначе»
    мало: нельзя ещё и соврать в самом прочитанном. Отсюда partition('\\n') —
    он снимает ровно служебную первую строку и больше ничего не трогает.
    """
    head, _sep, body = (out or '').partition('\n')
    if head.startswith(_RF_MARK):
        return (head[len(_RF_MARK):].strip() or None, body)
    return None, None


def read_file_info(checker, filepath):
    """Читает файл и возвращает СОСТОЯНИЕ, а не только содержимое.

    dict(state, content, reason): state — readable / unreadable / missing /
    isdir / unchecked, reason — готовая строка оператору (None, если файл
    прочитан). Пустой прочитанный файл — `readable` с `content == ''`, а не
    ошибка: «конфиг пустой» и «я не мог его прочитать» — разные диагнозы, и
    потребитель (`if content:`) раньше их не различал вовсе.
    """
    out, err, rc = checker.run(read_file_cmd(filepath))
    state, body = parse_read_answer(out, err)
    low = (err or '').lower()
    why = next((l.strip() for l in (err or '').splitlines() if l.strip()), '')[:160]

    if state is None:
        # Маркера нет: ответ от прежней/чужой команды либо обрыв на середине.
        if out:
            return {'state': None, 'content': out, 'reason': None}
        if rc != 0 and 'permission denied' in low:
            state = 'unreadable'
        elif rc != 0 and 'no such file' in low:
            state = 'missing'
        else:
            # Ответ системы цитируется: «gzip: not in gzip format» и «dig: command
            # not found» — разные диагнозы, а выдумывать вместо них «пусто» нельзя.
            return {'state': 'unchecked', 'content': None,
                    'reason': (RF_TEXT['unchecked'] +
                               (f". Ответ системы: «{why}»" if why else ''))}
        return {'state': state, 'content': None,
                'reason': RF_TEXT.get(state, RF_TEXT['unchecked'])}

    if state == 'missing' and 'permission denied' in low:
        # Решающий случай (замер живьём): у файла внутри закрытого каталога
        # `[ -e ]` врал «нет файла», а система отвечала Permission denied.
        # Поверить тесту — значит отправить оператора проверять раскладку
        # вместо прав.
        state = 'unreadable'
    elif state == 'readable' and rc != 0 and (err or '').strip():
        # Тест права дал «читаем», но упал сам читатель: битый .gz (`gzip: stdin:
        # not in gzip format`), пропавший в момент чтения диск, отсутствующий
        # zcat. Прочитанное недостоверно как полное: итог по такому файлу — «не
        # просмотрено», а не «пусто» (тот же закон, что в 1.19.0 для grep логов).
        return {'state': 'readerr', 'content': None,
                'reason': (f"читатель ({log_reader(filepath)}) сообщил об ошибке: "
                           f"«{why}» — вывод неполон, «пусто» по этому файлу "
                           f"сказать нельзя")}
    if state == 'readable':
        return {'state': state, 'content': body, 'reason': None}
    return {'state': state, 'content': None,
            'reason': RF_TEXT.get(state, RF_TEXT['unchecked'])}


def read_file_content(checker, filepath):
    """Читает содержимое файла; None — если прочитать не удалось.

    Состояние (почему не удалось) видно в read_file_info.
    """
    return read_file_info(checker, filepath)['content']


def get_domain_from_config(checker, config_path):
    """Извлекает домены из конфигурационного файла"""
    cmd = f"grep -h 'server_name' {q(config_path)} 2>/dev/null | sed 's/.*server_name\\s*\\([^;]*\\);.*/\\1/' | tr -s ' ' '\\n' | grep -v '^_' | grep -v '^$' | grep -v 'localhost' | grep -v 'default_server' | grep -v '^\\*'"
    out, _, _ = checker.run(cmd)
    domains = []
    if out.strip():
        for d in out.split('\n'):
            d = d.strip()
            if d and '.' in d and not d.startswith('_') and not d.startswith('*'):
                domains.append(d)
    return list(set(domains))
