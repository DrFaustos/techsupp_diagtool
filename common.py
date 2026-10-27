"""Общие конфигурации и вспомогательные функции диагностики."""
import os
import shlex
from datetime import datetime

# Единственный источник правды о версии. От неё зависят заголовок окна,
# CHANGELOG.md и тег релиза (тэг всегда v<__version__>).
__version__ = "1.32.16"

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

# Сколько конфигей веб-сервера читаем на поиск доменов (слайс 1.32.0).
#
# Прежняя срезка была равна 10 и держалась ЦЕНОЙ: каждый конфиг читался
# отдельным SSH-раундом (замер живьём: 10 файлов = 11 команд, 50 = 51,
# 200 = 201). Сводная команда этого же слайса читает всю пачку за один
# заход, и граница перестала быть ценовой: замер 200 путей - ОДНА команда,
# 7.5 КБ при бюджете аргументов ~2 МБ, rc=0, stderr пуст.
#
# 200 - не «на вырвет»: это число, при котором срезка перестает быть ложью
# для типового парка (замер: при 40 конфигей оператор видел 10 доменов).
# Парк больше лимита легитимен, но обязан быть назван - см.
# DOMAIN_TRUNCATED_NOTE.
DOMAIN_CONFIG_LIMIT = 200

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


BACKUP_PROBE = '.wprobe'


def _writable_question(path):
    """Один вопрос о каталоге: создать и ФАКТИЧЕСКИ в него записать.

    Прежняя форма решала по слову-маркеру и прятала причину:

        out, _, rc = checker.run(f'mkdir -p ... 2>/dev/null && echo "created"')
        for subdir in BACKUP_SUBDIRS.values():
            checker.run(...)
        return rc == 0 and out.strip() == 'created'

    Замер живьём (uid=1000, настоящий bash, BACKUP_DIR подменён на временный):
    в мире «каталог есть, но 0555» mkdir выходит с нулём и печатает «created»,
    хотя пробная запись в него отклонена — признак не различал «создан» и
    «не принимает запись». Второй корень: ответы по четырём подкаталогам
    выбрасывались, поэтому при занятом ФАЙЛОМ пути configs функция возвращала
    True (mkdir по нему rc=1 со словами о файле, которые глохли в /dev/null).

    Носитель ответа — код возврата ПРОБНОЙ ЗАПИСИ. mkdir остаётся побочным
    эффектом того же спроса, поэтому цена не растёт: пять каталогов — пять
    вопросов, как и раньше. Слово-маркера нет, `&&` нет (прежний тест запрещает
    его в спросах), `;` снимает rc до уборки, а `exit` возвращает именно код
    записи, а не удаления.
    """
    probe = q(path) + '/' + BACKUP_PROBE
    return ('mkdir -p %s 2>&1; : > %s 2>&1; r=$?; rm -f %s; exit $r'
            % (q(path), probe, probe))


def ensure_backup_dir_info(checker):
    """Пригодность каталога бэкапов: {ok, note, dirs}.

    dirs — по каждому спрошенному пути: '' (пишет) или почему нет. Право
    сказать «каталог готов» даёт только удачная пробная запись (закон серии:
    право на «готово» даёт перечитанный факт, а не обещание команды).
    """
    dirs = {}
    for path in [BACKUP_DIR] + list(BACKUP_SUBDIRS.values()):
        out, err, rc = checker.run(_writable_question(path))
        if rc == 0:
            dirs[path] = ''
            continue
        why = _first_line(out) or _first_line(err)
        dirs[path] = ('не принимает запись (rc=%s)%s'
                      % (rc, ': ' + why if why else ''))
    bad = dict((p, w) for p, w in dirs.items() if w)
    note = '; '.join('%s — %s' % (p, w) for p, w in bad.items())
    return {'ok': not bad, 'note': note, 'dirs': dirs}


def ensure_backup_dir(checker):
    """Создаёт директорию для бэкапов, если её нет.

    Тонкая обёртка над ensure_backup_dir_info: потребители (files.py,
    create_backup_info, diagnostic) завязаны на bool и не обязаны знать
    причины. Кто хочет назвать отказ — берёт ensure_backup_dir_info.
    """
    return ensure_backup_dir_info(checker)['ok'] is True


def _backup_dir_note(backup_path, dinfo):
    """Что сказать о каталоге бэкапов, если он не принимает запись.

    Называется именно тот подкаталог, куда должен был лечь бэкап: лечение
    «каталог не пишет» (права, занятое имя) другое, чем «файл не читается».
    """
    if dinfo.get('ok'):
        return None
    subdir = os.path.dirname(backup_path)
    why = dinfo.get('dirs', {}).get(subdir)
    return ('каталог %s недоступен для записи%s'
            % (subdir, ': ' + why if why else ''))

def create_backup_info(checker, filepath, backup_type='configs'):
    """Резервная копия файла с временной меткой: {path, state, note}.

    Прежний вид возвращал путь либо None и решал по СЛОВУ «exists» в stdout:

        out, _, rc = checker.run(f'test -f {q(filepath)} && echo "exists"')
        if rc != 0 or out.strip() != 'exists':
            return None
        _, _, rc = checker.run(f'cp {q(filepath)} {q(backup_path)} 2>&1')
        if rc != 0:
            return None

    Замер живьём (uid=1000, настоящий bash, BACKUP_DIR подменён на временный):
    три РАЗНЫХ мира давали неотличимый None — «файла нет» (cp не спрашивается),
    «файл есть, но не читается» (cp спрашивается и пишет причину в stdout, потому
    что команда с 2>&1, а `_, _, rc =` выбрасывает оба канала), «путь непроходим»
    (cp не спрашивается). Плюс bool от ensure_backup_dir выбрасывался вовсе.

    state:
    done     — cp вернул 0 И бэкап ПЕРЕЧИТАН (право на «готово» даёт факт, а не
               цепочка кодов возврата — закон 1.32.13);
    absent   — отсутствия источника ДОКАЗАНЫ достоверным списком каталога;
    unchecked — источника не видно (прав не хватило): это «мы не спросили»,
               его нельзя отчитывать как «файла нет»;
    failed   — cp отказал или обещанный файл не появился; note держит причину
               словами и код возврата.

    Носитель присутствия — file_presence (1.32.14): ответ в коде возврата,
    отсутствие — по достоверному списку. Маркер-слово из спросов уходит.
    cp не спрашивается ни при absent, ни при unchecked — прежний замок цел.
    """
    dinfo = ensure_backup_dir_info(checker)

    filename = os.path.basename(filepath)
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    backup_filename = f"{filename}.{timestamp}.bak"
    backup_path = f"{BACKUP_SUBDIRS.get(backup_type, BACKUP_SUBDIRS['configs'])}/{backup_filename}"

    info = {'path': None, 'state': 'unchecked', 'note': '',
            'backup_path': backup_path}
    cache = {}
    presence = file_presence(checker, filepath, cache)
    if presence['state'] != 'found':
        # Ни читать, ни копировать то, чего нет (или чего мы не видели),
        # запрещено: прежний замок сохранён как есть.
        info['state'] = presence['state']
        info['note'] = presence['note']
        return info

    out, err, rc = checker.run(f'cp {q(filepath)} {q(backup_path)} 2>&1')
    reason = _first_line(out) or _first_line(err)
    if rc != 0:
        info['state'] = 'failed'
        parts = ['cp вернул rc=%s%s' % (rc, ': ' + reason if reason else '')]
        if not dinfo['ok']:
            parts.append(_backup_dir_note(backup_path, dinfo))
        info['note'] = '; '.join(parts)
        return info

    reread = file_presence(checker, backup_path, cache)
    if reread['state'] != 'found':
        info['state'] = 'failed'
        parts = ['cp вернул 0, а бэкапа нет: %s' % (reread['note']
                                                  or reread['state'])]
        if not dinfo['ok']:
            parts.append(_backup_dir_note(backup_path, dinfo))
        info['note'] = '; '.join(parts)
        return info

    info['state'] = 'done'
    info['path'] = backup_path
    info['note'] = _backup_dir_note(backup_path, dinfo) or ''
    return info


def create_backup(checker, filepath, backup_type='configs'):
    """
    Создаёт резервную копию файла с временной меткой в соответствующей поддиректории.
    Возвращает путь к бэкапу или None в случае ошибки.

    Тонкая обёртка над create_backup_info: потребители (files.py, dns.py,
    panels.py) завязаны на path|None и не обязаны знать про состояния. Кто
    хочет назвать причину — берёт create_backup_info.
    """
    info = create_backup_info(checker, filepath, backup_type)
    return info['path'] if info['state'] == 'done' else None

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

# ==================== ls НЕ ИСПОЛНИЛАСЬ: argv не влез (1.32.3) =============
# Код возврата shell, когда команду не исполнили вовсе: список аргументов не
# влез в лимит (E2BIG). Замерено живьём на парке 20 000 конфигов при
# ulimit -s 1024: и bash, и dash дают 126, одинаково при LC_ALL=C и C.UTF-8.
#
# Числом 2 ls отвечает честно: «глоб не раскрылся», «каталога нет», «нет прав»
# (замер тех же живых каталогов — rc=2 во всех трёх случаях). Склеивать 126 и 2
# в одну ветку нельзя: у прежних трёх диагнозов лечение противоположное новому
# (менять раскладку / поднимать права против сужать шаблон), и один общий текст
# отправил бы оператора чинить не то.
LS_E2BIG_RC = 126

# Пустота, у которой причина — не «файлов нет», а «мы не смогли спросить».
# Слова «слишком много» обязательны: оператор должен увидеть, что список не
# получен, а не прочесть пустоту как ответ сервера (замер живой формы: rc=0,
# FFDIR ok, FFCOUNT 0 при rc ls = 126 — отчёт выглядел как успешная проверка).
LS_ARGV_NOTE = ('⚠️ Список файлов не получен: путей слишком много для одного '
                'вызова (лимит аргументов командной строки). По этому шаблону '
                'ничего не проверено — это «не проверено», а не «файлов нет»: '
                'уточните шаблон (каталог конкретного домена)')

# awk вместо `head`: считает ВСЕ файлы и печатает только первые L. `head -N`
# резал список молча — оператор не знал, сколько логов не участвовало в отчёте.
#
# 1.32.3: awk научился пропускать маркер `FFRC n`, НЕ считая его файлом. Иначе
# FFCOUNT соврал бы на единицу (маркер — не путь), а оператор прочитал бы его
# как имя лога или домена — тот же класс, что «FFDIR» в списке путей. Сам маркер
# awk печатает: python читает его из stdout и узнаёт код возврата ls, который
# иначе тонет под кодом возврата awk (замер: rc конвейера = 0 при rc ls = 126).
# Порядок строк (маркер ДО FFCOUNT, он идёт из тела awk, а не из END) и коды
# (126 — argv не влез, 2 — глоб не раскрылся) взяты из живого замера на парке
# 20 000 файлов под bash И под dash, при LC_ALL=C и C.UTF-8.
_FF_AWK = ('{if (substr($0,1,5)=="FFRC ") {print; next} k++; if(k<=L) print} '
           'END{printf "FFCOUNT %d\\n", k}')


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

    1.32.3: код возврата ls снимается ВНУТРИ группы (`{ ls -1 …; echo "FFRC
    $?"; }`) и уходит в канал отдельной строкой-маркером. Код возврата
    конвейера принадлежит awk, и на сервере с большим парком это врало: ls
    падала с «Argument list too long» (rc=126, замерено в bash и dash), а
    отчёт видел rc=0, FFDIR ok и FFCOUNT 0 — то есть «файлов нет, проверено»
    там, где список не запрашивался (замер: 20 000 файлов при ulimit -s 1024).
    `${PIPESTATUS}` для этого не годится (под dash — «Bad substitution»,
    замерено на прошлых слайсах); POSIX-способ один: снять `$?` до awk.

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
        f'{{ ls -1 {pattern}; echo "FFRC $?"; }} | awk -v L="{n}" '
        f'\'{_FF_AWK}\''
    )


def parse_find_answer(out):
    """(пути, состояния каталогов, total, rc ls) из ответа команды.

    total=None — маркера FFCOUNT не было (обрыв, чужая реализация): выдумывать
    число не имеем права. Пустой список каталогов — то же самое: мы не знаем,
    читали ли каталог.

    ls_rc=None — маркера FFRC не было: команда старой формы или чужая
    реализация, про код возврата ls ничего не известно. Выдумывать ему 0
    нельзя: «неизвестно» и «успех» — разные ответы (закон 1.16–1.19).

    Маркеры распознаются ДО ветки путей: строка, которую парсер не знает,
    уезжает в paths — и оператор читает «FFRC 126» как имя домена или лога.
    RED этого слайса поймал ровно это: агрегатор доменов рождал заметку
    «Домены по FFRC 126 не определены» на строку протокола.
    """
    paths, dirs, total, ls_rc = [], [], None, None
    for line in (out or '').splitlines():
        s = line.strip()
        if not s:
            continue
        if s.startswith('FFCOUNT '):
            try:
                total = int(s.split(' ', 1)[1].strip())
            except ValueError:
                total = None
        elif s.startswith('FFRC '):
            try:
                ls_rc = int(s.split(' ', 1)[1].strip())
            except ValueError:
                ls_rc = None
        elif s.startswith('FFDIR '):
            parts = s.split(' ', 2)
            dirs.append((parts[1] if len(parts) > 1 else '',
                         parts[2] if len(parts) > 2 else ''))
        else:
            paths.append(s)
    # 1.32.3: ls НЕ ИСПОЛНИЛАСЬ (argv не влез, rc=126 - см. LS_E2BIG_RC).
    # Обнуляем здесь, а не в find_files_info: этот парсер - единственное место,
    # где протокол расшифровывается, и ложный FFCOUNT 0, оставленный ему на
    # разбор наружу, дожил бы до любого другого потребителя (find_file_info
    # читает его напрямую). Числа 0 мы не видели: awk посчитал ноль строк
    # несостоявшегося вывода - это «не проверено», а не «нул файлов» (закон
    # 1.16-1.19). Путей при несостоявшейся ls быть не может в принципе.
    if ls_rc == LS_E2BIG_RC:
        paths, total = [], None
    return paths, dirs, total, ls_rc


def find_files_info(checker, pattern, limit=20):
    """Ищет файлы и возвращает, ЧЕМЫ объясняется пустота.

    dict(paths, dirs, total, notes, ls_rc). notes — готовые оператору строки
    про закрытые/отсутствующие каталоги и про срезку лимитом; они начинаются с
    «⚠️», поэтому уже написанные потребители (logs, discovery, webcheck)
    отфильтруют их как не-пути, ничего в себе не меняя.

    ls_rc — код возврата ls (None, если маркера FFRC в ответе не было). Решать
    «проверено или нет» обязаны им, а не разбором текста notes (закон 1.31.0) и
    не состоянием каталога: каталог может быть полностью читаем (FFDIR ok), а
    список — не получен (слайс 1.32.3).
    """
    out, err, _rc = checker.run(find_files_cmd(pattern, limit))
    paths, dirs, total, ls_rc = parse_find_answer(out)
    # 1.32.3: ls не исполнилась — argv не влез (rc=126, см. LS_E2BIG_RC).
    # Списка файлов у нас нет, и прежний вывод (FFDIR ok + FFCOUNT 0) был
    # неотличим от честной пустоты каталога. Пустоту без объяснения показывать
    # нельзя, а выдуманное число 0 — тем более (закон «не проверено ≠ 0»).
    #
    # Пути и total ЗДЕСЬ НЕ трогаются: их обнуляет parse_find_answer —
    # единственное место, где расшифровывается протокол. Признак, посчитанный
    # дважды, однажды разъезжается (грабель v1.18, записан в law серии).
    argv_full = ls_rc == LS_E2BIG_RC
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
    if argv_full:
        # Каталог подтверждён (FFDIR ok), а списка файлов нет. Заметка
        # обязательна: пустота без объяснения оператором читается как «файлов
        # нет», а лечение другое — не искать другой домен, а сузить шаблон.
        notes.append(LS_ARGV_NOTE)
    trunc_note = None
    if total is not None and total > len(paths):
        trunc_note = (f"⚠️ Показаны первые {len(paths)} файлов из {total}: "
                      f"остальные в этом отчёте не участвовали")
        notes.append(trunc_note)
    # trunc_note (1.32.0): та же строка ещё и отдельным полем. Нужно для
    # потребителя, которому срезка мешает в чужих словах: get_domains_info
    # пересказывает её на языке ДОМЕНОВ (отчёт печатает «Найдены домены», и
    # «показаны первые 10 ФАЙЛОВ» под таким заголовком оператор не соотносит
    # со списком). Изъять строку он обязан по этому полю, а не сравнением или
    # поиском по тексту: разбор localized формулировки однажды разъезжается с
    # самим текстом (закон 1.31.0, куплен на «состояние решается rc, а не
    # словами»).
    # ls_rc наружу (1.32.3): потребителю, который решает «проверено или нет»,
    # нужен код, а не разбор текста заметки (закон 1.31.0: состояние решается
    # признаком, а не словами). Сравнивать его обязаны с LS_E2BIG_RC — с той же
    # константой, а не с повторной единицей.
    return {'paths': paths, 'dirs': dirs, 'total': total, 'notes': notes,
            'trunc_note': trunc_note, 'ls_rc': ls_rc}


# ==================== ПРИЗНАК SYSTEMD-ЮНИТА (1.32.6) ====================
# Тот же класс, что у счётчика find ниже, но носитель — признак, а не число.
# Замер живьём на хосте без systemd (каталог /run/systemd/system отсутствует,
# bus мёртв): ЛЮБОЙ `systemctl is-active ЮНИТ` отвечает пустым stdout при rc=1,
# а причина («System has not been booted with systemd as init system (PID 1).
# Can't operate.») живёт в stderr. Прежние носители глушили stderr через
# 2>/dev/null и решали по пустой строке «не активно» — молчание сервера
# превращалось в измеренный факт, а отчёт печатал «служба не запущена» там,
# где система ничего не ответила.
#
# Тем же прогоном снято обратное, запрещающее брать признак из кода возврата:
# `systemctl is-system-running` даёт «offline» ПРИ rc=1, то есть ответ системы
# бывает и при ненулевом коде. Значит признак — непустота stdout, а код годится
# только на «команды нет вовсе». Различие держится КАНАЛАМИ: текст сообщения
# локализуется (урок 1.28.0), поэтому разбирать его как признак нельзя.
UNIT_UNCHECKED_NOTE = ('⚠️ Состояние службы не проверено: «{why}». Это «мы не '
                       'спросили», а не «служба не запущена»: система без '
                       'systemd, недоступный bus либо обрыв канала')


def unit_status_cmd(unit):
    """Одна команда, спрашивающая состояние systemd-юнита.

    Ни 2>/dev/null, ни 2>&1: пустой stdout обязан оставаться различимым, а
    stderr — оставаться объяснением. Склейка каналов убила бы то самое
    различие, из-за которого этот раздел и появился. Имя юнита экранируется:
    здесь это имя, а не glob (в отличие от паттернов find_files_cmd).
    """
    return f'systemctl is-active {q(unit)}'


def parse_unit_status(out, err, rc):
    """(статус | None, признание | None) из ответа systemctl is-active.

    Непустой stdout — ОТВЕТ системы, даже при rc != 0 (замер: inactive и
    offline возвращают rc=1). Пустой stdout — ответа не было: статус None, и
    подставлять ему «inactive» нельзя, это и есть подмена «не проверено».

    Причина берётся первая строкой stderr: второй строкой systemctl обычно
    повторяет то же самое, а оператору нужно то, с чего начинается лечение.
    """
    text = (out or '').strip()
    if text:
        return text.splitlines()[0].strip(), None
    lines = (err or '').strip().splitlines()
    why = lines[0][:200] if lines else f'пустой вывод (rc={rc})'
    return None, UNIT_UNCHECKED_NOTE.format(why=why)


def unit_status_info(checker, unit):
    """Состояние юнита и СИЛА ответа: {'unit', 'status', 'checked', 'note'}.

    checked=False — система ничего не ответила. По такому ответу нельзя
    утверждать ни «активна», ни «не запущена»: вызывающий обязан сказать «не
    проверено» (закон серии 1.16-1.19: «не проверено» не имеет права
    печататься как факт).
    """
    out, err, rc = checker.run(unit_status_cmd(unit))
    status, note = parse_unit_status(out, err, rc)
    return {'unit': unit, 'status': status, 'checked': status is not None,
            'note': note}


# ==================== ПРИЗНАК НАЛИЧИЯ ЮНИТА (1.32.9) ====================
# Тот же класс, что у is-active выше, но носитель — вопрос «установлена ли
# служба». Прежний носитель (files.py) решал конструкцией
#   systemctl list-unit-files | grep -q "^svc.service" && echo yes || echo no
# Замер живьём: строка 'no' rc=0 возникает одинаково, когда (а) службы нет в
# списке, (б) systemctl молчит (bus мёртв, каталог /run/systemd/system пуст),
# (в) вывод пуст. Конвейер выбрасывает И код systemctl, И непустоту его stdout,
# а '|| echo no' довершает подмену: «мы не спросили» становится «службы нет».
# Поэтому команда перестраивается так, чтобы решение о присутствии принимал
# shell по НЕПУСТОТЕ stdout systemctl, а сила ответа доехала различимо:
# present/absent — ответ системы, unknown + причина в stderr — ответа не было.
UNIT_PRESENCE_UNCHECKED_NOTE = (
    '⚠️ Наличие службы не проверено: «{why}». Это «мы не спросили», а не '
    '«служба не установлена»: система без systemd, недоступный bus либо обрыв')


def unit_presence_cmd(unit):
    """Одна POSIX-команда: present / absent / unknown для systemd-юнита.

    Решение по НЕПУСТОТЕ stdout самого list-unit-files (закон 1.32.6: непустой
    вывод — ответ системы, пустой — «не спросили»). Ни 2>/dev/null, ни 2>&1:
    при молчании stderr обязан доехать как причина. Конвейер
    `list-unit-files | grep -q ... && echo yes || echo no` непригоден: его
    stdout и rc принадлежат не systemctl, и замер даёт побайтово одинаковый
    'no' rc=0 и при genuine отсутствии, и при bus-мёртвом systemctl, и при
    пустом выводе. echo вместо printf намеренно: у формы команды нет
    бэкслешей вообще, и весь класс дефектов экранирования серии 1.32.8 ей не
    страшен. Точка в [.] — grep-безопасное класс-обозначение (POSIX grep не
    гарантирует обратный слэш перед точкой).
    """
    return ('list=$(systemctl list-unit-files); '
            'if [ -n "$list" ]; then '
            'if echo "$list" | grep -q "^{u}[.]service"; then '
            'echo present; else echo absent; fi; '
            'else echo unknown; fi').format(u=q(unit))


def parse_unit_presence(out, err, rc):
    """(present|absent|unknown, признание|None) из ответа команды присутствия.

    Только 'present'/'absent' — ответ. Всё остальное (пусто, мусор от битого
    shell, 'unknown') — «не проверено»: подставлять молчанию «absent» нельзя,
    это и есть тот дефект, который раздел и лечит.
    """
    text = (out or '').strip()
    if text == 'present':
        return 'present', None
    if text == 'absent':
        return 'absent', None
    lines = (err or '').strip().splitlines()
    why = lines[0][:200] if lines else 'пустой вывод (rc=%d)' % rc
    return 'unknown', UNIT_PRESENCE_UNCHECKED_NOTE.format(why=why)


def unit_presence_info(checker, unit):
    """Наличие юнита и СИЛА ответа: {'unit', 'presence', 'checked', 'note'}.

    checked=False — система ничего не ответила: вызывающий обязан сказать «не
    проверено», а не «не установлен» (закон серии: «не проверено» не печатается
    как факт).
    """
    out, err, rc = checker.run(unit_presence_cmd(unit))
    presence, note = parse_unit_presence(out, err, rc)
    return {'unit': unit, 'presence': presence,
            'checked': presence != 'unknown', 'note': note}


# ==================== ЗОНД ДОСТУПНОСТИ РЕЗОЛВЕРА (1.32.10) ====================
# Тот же корень, что у is-active (1.32.6) и у list-unit-files (1.32.9), но
# носитель — доступность DNS-сервера, и ложь здесь дороже: по слову
# «недоступен» оператор жмёт «сменить резолверы», а set_dns_resolvers
# перезаписывает /etc/resolv.conf.
#
# Прежний носитель (dns.py) решал конструкцией
#   dig +timeout=2 +tries=1 @NS google.com A 2>/dev/null \
#       | grep -q 'NOERROR' && echo доступен || echo недоступен
# Замер живьём (этот хост, dig 9.18): побайтово одинаковое «недоступен» дают
# (а) сервер, ответивший NXDOMAIN — то есть ЖИВОЙ сервер, чья запись просто
# отсутствует; (б) бинарника dig нет вовсе (rc=127 — мы не спрашивали);
# (в) пустой вывод. Пайп выбрасывает И код dig, И stderr, где живёт причина
# («communications error ... connection refused»), а '|| echo' довершает
# подмену. Отдельно python-дополнение `out.strip() else "недоступен"` —
# четвёртый вход в ту же ложь, а exec_command() отдаёт только каналы, значит
# rc=127 неразличим с тишиной в принципе.
#
# Поэтому зона — ОДНА команда без пайпа и без заглушек: код возврата
# принадлежит dig, stderr целый, состояние решает парсер по фактам. Никаких
# бэкслешей в форме нет вовсе (урок 1.32.9: нечего экранировать — нечего
# ломать).
RESOLVER_UNCHECKED_NOTE = (
    '⚠️ Доступность резолвера не проверена: «{why}». Это «мы не спросили», '
    'а не состояние сервера: возможно, на хосте нет dig либо оборвался канал')


def resolver_probe_cmd(resolver, probe='google.com'):
    """Одна POSIX-команда, спрашивающая доступность резолвера.

    Без `2>/dev/null`, без `2>&1` и без конвейера: rc обязан принадлежать
    dig, а stderr — доехать как причина. Ни `&&`/`||`: решение принимает
    парсер по фактам, а не оболочка по умолчанию. Адрес резолвера и имя
    проверки экранируются через q(): это имена, а не glob.
    """
    return ('dig +timeout=2 +tries=1 @' + q(resolver) + ' ' + q(probe) +
            ' A')


def parse_resolver_probe(out, err, rc):
    """('ok'|'down'|'unchecked', признание|None) из ответа dig.

    Признак — ОТВЕТ сервера, а не наличие записи. Замер: NXDOMAIN приходит
    при rc=0 и с полным выводом, то есть сервер работает, а отсутствующая
    запись — не его неисправность. Поэтому любой статус-заголовок ответа
    ('status: ...') означает «сервер ответил». Молчание при rc=127 — этого
    бинарника нет: спрашивать не чем, ответ unknown.
    """
    def first(text):
        lines = (text or '').strip().splitlines()
        return lines[0][:200] if lines else ''

    text = (out or '') + (err or '')
    if rc == 127:
        why = first(err) or 'команда не найдена (rc=127)'
        return 'unchecked', RESOLVER_UNCHECKED_NOTE.format(why=why)
    if 'status:' in text:
        # Сервер ответил. Любой статус (NOERROR, NXDOMAIN, SERVFAIL) — это
        # ответ, а не отказ: резолвер доступен.
        return 'ok', None
    if not text.strip():
        why = 'пустой вывод (rc=%s)' % rc
        return 'unchecked', RESOLVER_UNCHECKED_NOTE.format(why=why)
    # Ответа нет, но каналы не пусты: dig сам сказал, почему (замер:
    # 'communications error to 127.0.0.1#53: connection refused',
    # 'timed out' при rc=9). Это отказ сервера, а не наше молчание.
    why = first(err) or first(out)
    return 'down', why


def resolver_probe_info(checker, resolver, probe='google.com'):
    """Доступность резолвера и СИЛА ответа: {resolver, state, checked, note}.

    checked=False — система ничего не ответила: вызывающий обязан сказать
    «не проверено», а не «недоступен» (закон серии: «не проверено» не
    печатается как факт, и по нему не совершается вылечивающее действие).
    """
    out, err, rc = checker.run(resolver_probe_cmd(resolver, probe))
    state, note = parse_resolver_probe(out, err, rc)
    return {'resolver': resolver, 'state': state,
            'checked': state != 'unchecked', 'note': note}


# ==================== ЗОНД ДОСТУПНОСТИ КОМАНДЫ (1.32.11) ====================
'''Различение ответа, отсутствующей утилиты и несостоявшегося запроса.

Тот же корень, что у 1.32.6-1.32.10: пустой stdout спросителя читался как
измеренный факт. Носитель — формы вида «cmd 2>/dev/null || echo готовое
слово», где решение принималось по пустоте stdout, а не по коду возврата.

Замер живьём (этот хост, от непривилегированного пользователя):
  ufw status        rc=127, stderr: command not found  (утилиты нет)
  iptables -L -n    rc=4,   stderr: Permission denied  (утилита ЕСТЬ)
  nft list ruleset  rc=1,   stderr: Operation not permitted (ЕСТЬ)
Прежняя форма печатала на всех трёх побайтово одно и то же, поэтому три
разных мира сходили в отчёте о безопасности в одну строку. Отдельно
2>/dev/null глушило единственную подсказку про отсутствующий бинарник: она
живёт в stderr у оболочки, а не в stdout команды.

Эмодзи в признании намеренно нет: различение обязано идти по слову
«не проверено», а не по знаку (урок серии — замок на символе, собранном по
памяти, оказывался истинным всегда).
'''
COMMAND_UNCHECKED_NOTE = (
    'Состояние не проверено: «{why}». Это «мы не спросили», а не ответ хоста: '
    'запрос не состоялся (нет прав, нет бинарника, пустой вывод)')


def command_probe_cmd(cmd):
    '''Форма запроса: сама команда, без заглушек каналов и без ||-дополнения.

    Код возврата обязан принадлежать самой команде, а stderr — доехать как
    причина. Заглушка канала убивала подсказку про отсутствующий бинарник, а
    ||-дополнение превращало любой отказ в готовый ответ.

    Форма зачищается ЗДЕСЬ, а не на совести вызывающего: замер показал, что
    первая версия («просто strip») сохраняла переданную заглушку —
    command_probe_cmd('  ufw status 2>/dev/null  ') вернул 'ufw status
    2>/dev/null'. Такой примитив гарантировал бы честный канал только пока
    вызывающий не забыл заглушку, то есть гарантией не был.
    '''
    text = (cmd or '').strip()
    # ||-дополнение: любой отказ становится готовым словом. Отсекаем хвост,
    # вместе с ним уходит и echo-ложь (замер: 'X not installed' при rc=0).
    if '||' in text:
        text = text.split('||', 1)[0].strip()
    # Заглушки каналов: подсказка про отсутствующий бинарник живёт в stderr у
    # оболочки (rc=127/126), заглушив канал, мы теряем единственное доказательство.
    for blind in ('2>/dev/null', '2>&1', '1>&2', '>/dev/null'):
        if blind in text:
            text = text.replace(blind, ' ')
    return text.strip()


def parse_command_probe(out, err, rc):
    '''('ok' | 'absent' | 'unchecked', признание или None) по замеренным формам.

    'absent' — только при доказательстве отсутствия бинарника (rc=127/126):
    тогда «не установлено» есть измеренный факт. Отказ прав (rc=4, rc=1 при
    пустом stdout) и пустой вывод при rc=0 — 'unchecked': спрашивать не чем,
    значит состояния мы не знаем.
    '''
    def first(text):
        lines = (text or '').strip().splitlines()
        return lines[0][:200] if lines else ''

    text = (out or '').strip()
    if rc == 127:
        return 'absent', first(err) or 'command not found (rc=127)'
    if rc == 126:
        return 'absent', first(err) or 'command not executable (rc=126)'
    if text:
        return 'ok', None
    if rc != 0:
        return 'unchecked', first(err) or first(out) or ('rc=%s' % rc)
    return 'unchecked', 'пустой вывод (rc=0)'


def command_probe_info(checker, cmd):
    '''Один честный запрос: {command, state, checked, text, note}.

    checked ложно ровно для unchecked: по нему нельзя ни печатать диагноз, ни
    совершать вылечивающее действие (закон серии: «не проверено» не печатается
    как факт). text — вывод команды, note — причина отказа или признание.
    '''
    out, err, rc = checker.run(command_probe_cmd(cmd))
    state, why = parse_command_probe(out, err, rc)
    info = {'command': cmd, 'state': state, 'checked': state != 'unchecked',
            'text': (out or '').strip(), 'note': why or ''}
    if state == 'absent':
        info['note'] = 'не установлено: ' + (why or '')
    elif state == 'unchecked':
        info['note'] = COMMAND_UNCHECKED_NOTE.format(why=why or 'молчание')
    return info


# ==================== СПРОС ПУТИ СПИСКОМ КАТАЛОГА (1.32.12) ==================
# Форма test -f непригодна там, где отказ прав обязан отличаться от отсутствия
# файла. Замер живьём (три мира песочницы: файл есть / файла нет / файл в
# каталоге chmod 000, путь на СВОЁМ дереве — значит воспроизводится и в бою):
#
#     test -f X && echo yes || echo no  ->  «no» при rc=0 в ОБОИХ отказах,
#                                           stderr пуст: различить нечем ни
#                                           числом, ни каналом
#     ls -d X, stat X, find X -maxdepth 0  ->  ОДИН И ТОТ ЖЕ rc для «нет файла»
#                                           и «нет прав»; миры различаются
#                                           только ТЕКСТОМ errno, а он
#                                           локализован (родная локаль —
#                                           «Отказано в доступе», LC_ALL=C —
#                                           «Permission denied»): признак по
#                                           строке молча сломался бы на
#                                           клиентском хосте с другой локалью.
#
# Достоверен только ответ с rc=0. Поэтому существование пути выводят из СПИСКА
# КАТАЛОГА-РОДИТЕЛЯ: пустой вывод при rc=0 — это пустой каталог, а не молчание
# (замер), тогда как для одиночной команды та же картина значит «не проверено»
# (ср. parse_command_probe). Если каталог не прочитан, поднимаемся к ближайшему
# читаемому предку: нет имени следующего компонента в его достоверном списке —
# отсутствия ДОКАЗАНЫ; прочесть ниже не удалось — «не проверено» с причиной.
DIR_LISTING_CMD = 'ls -1 -p'

PATH_ENTRY_UNCHECKED_NOTE = (
    'Состояние не проверено: «{why}». Это «мы не спросили», а не ответ хоста: '
    'каталог не прочитан, значит отсутствия не доказаны'
)


def _first_line(text):
    '''Первая непустая строка канала — она идёт в признание как причина.'''
    lines = (text or '').strip().splitlines()
    return lines[0][:200] if lines else ''


def dir_listing_info(checker, path, cache=None):
    '''Достоверный список каталога: {path, state, names, note}.

    read    — rc=0, имена достоверны (пустой вывод = пустой каталог, замер);
    absent  — самого ls нет (rc=127/126: доказательство живёт в stderr у
              оболочки, заглушать канал нельзя);
    blocked — каталог не прочитан. Числом «пути нет» и «прав нет» НЕ РАЗЛИЧИМЫ
              (замер: rc=2 в обоих мирах), поэтому и не пытаемся различать:
              здесь рождается «не проверено», а не догадка.

    Имена сохраняются как их печатает ls -1 -p: у каталога суффикс «/», у
    обычного файла суффикса нет (замер). Тип имени берётся из того же ответа,
    второго спроса нет. cache убирает повторный спрос общего предка у нескольких
    проверяемых путей (на чистом хосте /usr/local звучит один раз).
    '''
    if cache is not None and path in cache:
        return cache[path]
    out, err, rc = checker.run(DIR_LISTING_CMD + ' ' + q(path))
    info = {'path': path, 'state': 'read', 'names': set(), 'note': ''}
    if rc == 0:
        info['names'] = set(ln for ln in (out or '').splitlines() if ln)
    elif rc in (126, 127):
        info['state'] = 'absent'
        info['note'] = _first_line(err) or ('ls недоступен (rc=%s)' % rc)
    else:
        info['state'] = 'blocked'
        info['note'] = _first_line(err) or _first_line(out) or ('rc=%s' % rc)
    if cache is not None:
        cache[path] = info
    return info


def path_entry_state(checker, path, cache=None):
    '''Есть ли путь на хосте — по достоверным спискам каталогов.

    {path, state, note}, state:
    found     — имя цели есть в достоверном списке родителя БЕЗ суффикса «/»,
                то есть это файл (или симлинг на файл), а не каталог с тем же
                именем;
    absent    — отсутствия ДОКАЗАНЫ: в достоверном списке родителя или
                ближайшего читаемого предка нет имени следующего компонента;
    unchecked — ниже прочитанного не видно (прав не хватило или нет самого ls):
                ни «есть», ни «нет» утверждать нельзя.

    Спуск явный: k — длина префикса пути, directory = '/', + первые k-1
    компонентов, name = k-й компонент. Прошлая формула (имя по индексу цикла)
    зеркалилилась на середине пути: в мире «предок читается, ниже 000» она
    выдавала absent вместо unchecked, то есть лгала ровно тем способом, который
    этот слайс и лечит.

    У ПРОМЕЖУТОЧНЫХ компонентов суффикс «/» не требуется: достаточно, что имя
    есть в списке. Требовать каталог значило бы связать ответ с тем, как ls
    помечает симлинг на каталог, а ошибиться в эту сторону значит объявить
    «пути нет» там, где панель стоит в симлинге.
    '''
    parts = [p for p in (path or '').split('/') if p]
    if not parts:
        return {'path': path, 'state': 'unchecked',
                'note': PATH_ENTRY_UNCHECKED_NOTE.format(why='пустой путь')}
    reason = ''
    for k in range(len(parts), 0, -1):
        directory = '/' + '/'.join(parts[:k - 1])
        name = parts[k - 1]
        listing = dir_listing_info(checker, directory, cache)
        if listing['state'] != 'read':
            # Каталог не прочитан: пробуем предка — он может читаться, и тогда
            # отсутствие будет доказано уже там.
            reason = listing['note'] or reason
            continue
        names = listing['names']
        if k == len(parts):
            # Цель: суффикс «/» означает каталог, а нас интересует файл.
            if name in names:
                return {'path': path, 'state': 'found', 'note': ''}
            if name + '/' in names:
                return {'path': path, 'state': 'absent',
                        'note': '«%s» в %s — каталог, а не файл'
                                % (name, directory)}
            return {'path': path, 'state': 'absent',
                    'note': 'имени «%s» в достоверном списке %s нет'
                            % (name, directory)}
        if name in names or name + '/' in names:
            continue
        return {'path': path, 'state': 'absent',
                'note': 'имени «%s» в достоверном списке %s нет'
                        % (name, directory)}
    return {'path': path, 'state': 'unchecked',
            'note': PATH_ENTRY_UNCHECKED_NOTE.format(
                why=reason or 'ни один каталог не прочитан')}

# ============ ПРИСУТСТВИЕ ФАЙЛА: ответ в коде возврата (1.32.14) ============
# Прежняя форма «test -f PATH && echo yes» решала по СЛОВУ в stdout и выбрасывала
# код возврата. Замер живьём (uid=1000, настоящий bash; факт «файл был» доказан
# ВОЗВРАТОМ прав, а не os.path.exists — на непроходимом пути он тоже врёт):
#   каталог 000 (непроходим)  -> test -f: out='' rc=1 err='': ПОБАЙТОВО то же,
#                               что при «файла нет», а файл на месте;
#   каталог 111 (проход есть) -> test -f: out='yes' rc=0, а ls -1 -p родителя
#                               даёт rc=2: файл виден, прочесть список нельзя.
# Отсюда комбинированный носитель: «есть» говорит КОД ВОЗВРАТА (rc=0 — это
# измерение, а не пустота), а «нет» имеет право утверждать только достоверный
# список каталога. Второй мир и запрещает наивную замену на один список: она
# превратила бы верный «файл есть» в «не проверено» и подарила бы ложный отказ
# читать лог. Ни один верный ответ прежнего кода не теряется.
FILE_PRESENCE_CMD = 'test -f'

FILE_PRESENCE_UNCHECKED_NOTE = (
    'Состояние не проверено: {why}. Это «мы не спросили», а не ответ хоста: '
    'ни код возврата, ни список каталога не дали ответа, значит нельзя '
    'утверждать ни «есть», ни «нет»')


def file_presence(checker, path, cache=None):
    """Есть ли файл: ответ в коде возврата, отсутствие — по списку каталога.

    {path, state, note}, state:
    found     — rc=0 от test -f: это измеренный ответ, а не пустой вывод,
                поэтому список каталога к нему не спрашивается (замер мира 111:
                списка там прочесть нельзя, а файл есть);
    absent    — отсутствия ДОКАЗАНЫ: родитель прочитан (rc=0 у ls -1 -p) и
                имени цели в достоверном списке нет;
    unchecked — rc!=0 и список прочесть не удалось (нет прав на каталог, нет
                самого ls): «не видно» и «нет» неразличимы побайтово, поэтому
                здесь рождается «не проверено», а не догадка.

    cache — словарь dir_listing_info: у нескольких путей общий предок
    спрашивается один раз (боевой отчёт по трём логам платит 4 спроса).
    """
    target = (path or '').strip()
    info = {'path': target, 'state': 'unchecked', 'note': ''}
    if not target:
        info['note'] = FILE_PRESENCE_UNCHECKED_NOTE.format(why='пустой путь')
        return info
    out, err, rc = checker.run(FILE_PRESENCE_CMD + ' ' + q(target))
    if rc == 0:
        info['state'] = 'found'
        return info
    why = _first_line(err) or _first_line(out)
    parent, _, name = target.rpartition('/')
    parent = parent or '/'
    listing = dir_listing_info(checker, parent, cache)
    if listing['state'] == 'read':
        if name in listing['names']:
            # Список достоверен и имя в нём есть: молчанию кода возврата не
            # верим — такой мир (файл появился между спросами) честнее назвать
            # найденным, чем объявить отсутствующим.
            info['state'] = 'found'
            info['note'] = ('имя «%s» есть в достоверном списке %s'
                            % (name, parent))
            return info
        if name + '/' in listing['names']:
            info['state'] = 'absent'
            info['note'] = ('«%s» в достоверном списке %s — каталог, а не файл'
                            % (name, parent))
            return info
        info['state'] = 'absent'
        info['note'] = ('имени «%s» в достоверном списке %s нет'
                        % (name, parent))
        return info
    info['note'] = FILE_PRESENCE_UNCHECKED_NOTE.format(
        why='; '.join(x for x in (('запрос вернул rc=%s%s'
                                   % (rc, ': ' + why if why else '')),
                                  listing['note']) if x))
    return info

# ============ ПРОЦЕССЫ: носитель, цель, убийство (1.32.13) =================
# Прежние формы решали по ИМЕНИ процесса и по пустоте конвейера. Замер живьём
# (настоящий bash, живость по State из /proc после reap): «pkill core» без -x
# убил ЧУЖОЙ coredns (pgrep и pkill матчают имя как подстроку); «pgrep -x core»
# нашёл и чужой /opt/vendor/core (то же имя файла, другая установка);
# «pgrep -f <путь>» нашёл чужой «tail -f <тот же путь>» и пропустил запуски
# «exec -a core» и «cd && exec ./core»; «ps aux | grep core | grep -v grep» на
# «ps: command not found» дал пустоту, которую отчёт прочитал как «завершён»
# при живом процессе.
#
# Носитель — один «ps -eo pid=,args=» без пайпа: у конвейера код возврата
# принадлежит последней команде, и «утилита не запустилась» неотличимо от
# «процессов нет». Пустой вывод при rc=0 здесь достоверен (пустой список — это
# измеренное отсутствие), при rc=127 — «не проверено» (замер: rc=127 выдаёт
# оболочка, stdout пуст, доказательство живёт в stderr).
#
# Целью считается процесс, у которого argv[0] РАВЕН пути: путь в чужих
# аргументах панелью не является. Для убийства имя не переиспользуется —
# убивают названные pid, а право на «готово» даёт только перечитанный список.
PROCESS_LIST_CMD = 'ps -eo pid=,args='
PROCESS_KILL_CMD = 'kill -9'

PROCESS_UNCHECKED_NOTE = (
    'Состояние не проверено: «{why}». Это «мы не спросили», а не ответ хоста: '
    'список процессов не получен, значит нельзя утверждать ни «работает», '
    'ни «остановлен»')


def parse_process_table(text):
    """Строки «ps -eo pid=,args=» -> список (pid, argv0).

    Замер: без второго «=» ps печатает заголовок, первым полем у него стоит
    COMMAND (не число), поэтому заголовок отсекается самим признаком числа.
    Короткая строка — не процесс: её не угадываем, а отбрасываем.
    """
    rows = []
    for line in (text or '').splitlines():
        parts = line.split(None, 1)
        if len(parts) < 2 or not parts[0].isdigit():
            continue
        rows.append((parts[0], parts[1].split(' ')[0]))
    return rows


def process_probe(checker, path, cache=None):
    """Работает ли процесс, запущенный именно этим путём.

    {path, state, checked, pids, similar, note}, state:
    running   — argv[0] какого-то процесса равен path;
    absent    — список прочитан (rc=0) и такого процесса в нём нет: отсутствие
                ДОКАЗАНО списком, а не выведено из пустоты;
    unchecked — списка нет (утилиты нет, отказ, непустой отказ) — ответа мы не
                знаем и права на диагноз не имеем.

    similar — pid процессов с тем же именем файла, но запущенных из другого
    пути. Это НЕ цель (замер: pgrep -x убивает их вместе с ней), и промолчать
    о них нельзя: оператор иначе решит, что панель не запущена.

    cache — словарь для нескольких целей в ОДНОМ снимке: список
    процессов один и тот же, и платить сетевым round-trip за каждую
    цель нечем. Кеш обязан жить ровно в рамках одного снимка:
    процесс_kill его не получает (см. ниже).
    """
    if cache is not None and PROCESS_LIST_CMD in cache:
        out, err, rc = cache[PROCESS_LIST_CMD]
    else:
        out, err, rc = checker.run(PROCESS_LIST_CMD)
        if cache is not None:
            cache[PROCESS_LIST_CMD] = (out, err, rc)
    target = (path or '').strip()
    name = target.rsplit('/', 1)[-1]
    info = {'path': target, 'state': 'unchecked', 'checked': False,
            'pids': [], 'similar': [], 'note': ''}
    if rc != 0:
        why = _first_line(err) or _first_line(out)
        info['note'] = PROCESS_UNCHECKED_NOTE.format(
            why=why or ('список процессов не получен (rc=%s)' % rc))
        return info
    for pid, argv0 in parse_process_table(out):
        if argv0 == target:
            info['pids'].append(pid)
        elif name and argv0.rsplit('/', 1)[-1] == name:
            info['similar'].append(pid)
    info['checked'] = True
    info['state'] = 'running' if info['pids'] else 'absent'
    if info['similar']:
        info['note'] = ('тот же файл запущен из другого пути: pid '
                        + ', '.join(info['similar'])
                        + ' — это не цель, её не трогаем')
    return info


def process_kill(checker, pids, target=None):
    """Убивает названные pid и перечитывает список, если названа цель.

    Решать по ответу убивающей команды нельзя: отказ прав и «процесса нет»
    дают один и тот же rc=1 (замер: у kill без аргументов rc=2, у
    несуществующего pid rc=1, у отказа прав rc=1). Единственное право на
    «готово» — повторный достоверный список, где цели больше нет.
    """
    wanted = [str(p) for p in (pids or []) if str(p).isdigit()]
    if not wanted:
        return {'state': 'nothing-to-kill', 'checked': True, 'pids': [],
                'similar': [], 'note': 'убивать нечего: pid не названы'}
    out, err, rc = checker.run(PROCESS_KILL_CMD + ' ' + ' '.join(wanted))
    why = _first_line(err) or _first_line(out)
    result = {'state': 'unchecked', 'checked': False, 'pids': wanted,
              'similar': [], 'note': ''}
    if not target:
        # Перечитать нечем: цель не названа, значит и права на «готово» нет.
        result['note'] = PROCESS_UNCHECKED_NOTE.format(
            why=why or 'путь цели не назван, перечитать нечего')
        return result
    # Кеш сюда не передаётся НАМЕРЕННО: снимок ДО убийства не имеет
    # права решать, убит ли процесс ПОСЛЕ него. Ответ самой убивающей
    # команды различить отказ прав и «процесса нет» не может (замер:
    # rc=1 в обоих мирах), поэтому перечитка обязана быть свежей.
    probe = process_probe(checker, target)
    result['pids'] = probe['pids']
    result['similar'] = probe['similar']
    if not probe['checked']:
        result['note'] = ('отказ убийства: «%s»; %s' % (why, probe['note'])
                          if why and rc != 0 else probe['note'])
        return result
    result['checked'] = True
    if probe['pids']:
        result['state'] = 'alive'
        result['note'] = ('процесс жив' + ('; отказ убийства: «%s»' % why
                                           if rc != 0 and why else ''))
        return result
    result['state'] = 'gone'
    return result

# ==================== СЧЁТЧИК find (1.32.5) ====================
# `find … 2>/dev/null | wc -l` непригоден как ответ «нарушений нет»: код возврата
# конвейера принадлежит wc (то есть всегда 0), а stderr find глох в заглушке.
# Замер живьём (mawk 1.3.4, реальный парк): закрытый chmod 000 каталог и
# несуществующий пользователь дают ровно «0» при rc конвейера 0 — то же число,
# что даёт честная пустота. Отчёт по такому ответу печатал «✅ Все файлы
# принадлежат bitrix» и «✅ world-writable файлов нет», то есть ложно-чистый
# вердикт проверки безопасности.
#
# Отказ от wc обязателен, но НЕдостаточен. Признак полноты — код возврата САМОГО
# find, снятый внутри группы до awk (канон 1.32.3; PIPESTATUS под dash — «Bad
# substitution»). Число строк «find: » признаком быть не может: если find не
# запустился вовсе (rc=127), строк ошибок ноль, и вердикт снова стал бы
# ложно-чистым — ровно тот класс, который этот слайс и лечит.
_COUNT_AWK = ('{if (substr($0,1,6)=="find: ") {print "FERR " $0; next} '
              'if (substr($0,1,6)=="FCOUNT" || substr($0,1,4)=="FRC ") '
              '{print; next} k++} '
              'END{printf "FCOUNT %d\\n", k+0}')


def count_find_cmd(root, expr):
    """Одна POSIX-команда: сколько находит find и дошёл ли обход до конца.

    `root` экранируется через q(): это имя каталога, а не glob (в отличие от
    паттернов find_files_cmd, где `*` обязан дойти до shell буквально). `expr`
    пишется вызывающим кодом и уходит литерально: через q() он стал бы одним
    аргументом «-mindepth 1 -type f», и find ничего бы не нашёл.

    stderr find идёт в канал (`2>&1`): в нём единственная строка с причиной
    пустоты. awk превращает её в маркер FERR и НЕ считает найденным файлом, а
    маркеры печатает, но не считает — иначе счётчик соврал бы на их число
    (тот же закон, что заперт для `FFRC` в 1.32.3).
    """
    return (f'{{ find {q(root)} {expr} 2>&1; echo "FRC $?"; }} | '
            f"awk '{_COUNT_AWK}'")


def parse_count_answer(out):
    """(число, rc find, первая причина) из ответа count_find_cmd.

    count=None — маркера FCOUNT не было (обрыв канала, чужая реализация):
    выдумывать ноль нельзя, «не проверено» и «нул нарушений» — разные ответы
    (закон 1.16–1.19). То же для rc: None — неизвестно, 0 — обход дошёл.

    Причина берётся первая и только одна: второй строкой find обычно повторяет
    то же самое, а оператору нужна та, с которой начинается лечение.
    """
    count = rc = None
    reason = ''
    for line in (out or '').splitlines():
        s = line.strip()
        if s.startswith('FCOUNT '):
            try:
                count = int(s.split(' ', 1)[1].strip())
            except ValueError:
                count = None
        elif s.startswith('FRC '):
            try:
                rc = int(s.split(' ', 1)[1].strip())
            except ValueError:
                rc = None
        elif s.startswith('FERR ') and not reason:
            reason = s[5:].strip()[:160]
    return count, rc, (reason or None)


def count_find_info(checker, root, expr):
    """Сколько нашёл find и ЧЕМ объяснена неполнота: {'count','complete','note'}.

    complete=False — обход не дошёл до конца (нет прав, нет пути, find не
    запустился) или ответ не распознан: найденное число в этом случае означает
    «столько увидели», и по нему нельзя утверждать «нарушений нет».
    """
    out, _err, _rc = checker.run(count_find_cmd(root, expr))
    count, frc, reason = parse_count_answer(out)
    if count is None or frc is None:
        # Маркеров нет: прежний голый ответ wc (одна цифра) тоже попадает сюда,
        # и он не результат — мы не знаем, дошёл ли обход.
        return {'count': count, 'complete': False,
                'note': '⚠️ Ответ счётчика не распознан (нет маркеров FCOUNT/FRC)'
                        ' — проверка неполна: о дереве ничего не известно, это '
                        '«не проверено», а не «нарушений нет»'}
    if frc == 0:
        return {'count': count, 'complete': True, 'note': None}
    why = reason if reason else f'код возврата find {frc}'
    return {'count': count, 'complete': False,
            'note': f'⚠️ Обход {root} не дошёл до конца: «{why}». Проверка '
                    f'неполна: {count} — это «столько увидели», а не «столько '
                    'есть»: утверждать «нарушений нет» по нему нельзя'}


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


# Формулировки состояний — теми же словами, что RF_TEXT (1.21.0) и FF_DIR_TEXT
# (1.20.0): оператор читает один словарь во всех отчётах.
DOMAIN_GAP_TEXT = {
    'unreadable': "нет прав на файл конфига — домены по нему НЕ проверены "
                  "(обычно нужен root или членство в группе файла)",
    'missing': "файла конфига нет на сервере — проверьте раскладку и тип панели",
    'isdir': "по этому пути каталог, а не файл конфига",
}
DOMAIN_UNCHECKED_NOTE = ("⚠️ Домены по {path} не определены — состояние не "
                         "проверено: «{why}». Это НЕ «доменов нет»")

# Слайс 1.32.0. Главная ложь, измеренная живьём (40 реальных конфигей на
# сервере, настоящая ФС): get_domains_info докладывал 10 доменов. Признание о
# срезке существовало, но было подписано словом «файлы» («Показаны первые 10
# файлов из 40»), а отчёт печатает заголовок «Найдены домены: …» — связку
# «файл -> домен» оператор не проходит и читает заголовок как полный список.
# Поэтому потребитель пересказывает срезку вот этой строкой, на языке доменов.
#
# Число total здесь НАМЕРЕННО не называется. find_files_info знает total по
# ОДНОМУ шаблону, а get_domains_info идёт по списку шаблонов, которые у панелей
# ПЕРЕКРЫВАЮТСЯ ('/etc/nginx/sites-enabled/*' и '/etc/nginx/conf.d/*.conf'
# описывают одни и те же файлы): сложить total'ы — значит соврать о масштабе
# (при трёх перекрывающихся шаблонах реальные 500 файлов дали бы 1500).
# Называется то число, которое известно точно: сколько конфигей прочитано.
DOMAIN_TRUNCATED_NOTE = (
    "⚠️ Список доменов неполный: прочитаны {shown} конфигей веб-сервера, а "
    "каталоги отдают больше — домены по непрочитанным конфигам не проверены")


def domains_from_config_text(text):
    """Домены из строк `server_name ...;` — чистая функция, без I/O.

    Прежний код вынимал домены пайпом `sed | tr | grep -v` в шелле и терял на
    этом четыре диагноза (замер живьём на настоящих файлах, uid=1000,
    /bin/bash):

        '#    server_name uhatil.tld;'          -> ['uhatil.tld']   комментарий
        '   # server_name staryj.tld;'          -> ['staryj.tld']   комментарий
        'server_names_hash_bucket_size 128.0;'  -> ['128.0']        НЕ директива
        'server_name hodovyj.tld; # ...ljevoj;' -> ['ljevoj.tld']   настоящий
                                                                     домен ПОТЕРЯН

    Последняя строка — двойная ложь: жадный `.*server_name` в sed брал
    ПОСЛЕДНИЙ server_name строки. По выдуманным именам `check_site_logs` ищет
    /var/log/nginx/128.0.error.log и рапортует о домене, которого нет.

    Отсюда три правила, которых у шелла не было:
      1. комментарий — не директива (`#` в начале строки и в её хвосте);
      2. директива опознаётся по префиксу С ГРАНИЦЕЙ, а не по подстроке, иначе
         `server_names_hash_bucket_size` становится `server_name`;
      3. за `server_name` обязаны следовать токены (`server_name;` — ошибка
         синтаксиса nginx, доменов там нет).

    Фильтр унаследован от прежнего пайпа: `*`-шаблоны, `_`, `localhost`,
    `default_server` и всё без точки доменами не считаются. Значение без
    завершающей `;` (слегка побитый конфиг) доменом остаётся: молчать хуже,
    чем назвать.
    """
    found = []
    for line in (text or '').splitlines():
        s = line.strip()
        if s.startswith('#'):
            continue
        if '#' in s:
            s = s.split('#', 1)[0].strip()
        if not s.startswith('server_name'):
            continue
        rest = s[len('server_name'):]
        if rest[:1] not in ('', ' ', '\t'):
            continue          # 'server_names_...' — другая директива
        for tok in rest.strip().rstrip(';').strip().split():
            tok = tok.strip('"').rstrip(',;')
            if not tok or tok[0] in ('_', '*'):
                continue
            if tok in ('localhost', 'default_server'):
                continue
            if '.' in tok:
                found.append(tok)
    return sorted(set(found))


def _tidy_citation(text, path):
    """Ответ системы без пути и без «дырок», оставшихся от его вырезания.

    grep печатает путь в каждом сообщении: `grep: /etc/x.conf: Permission
    denied`. Путь вырезается (иначе десять закрытых файлов дали бы десять
    разных ключей и сводка рассыпалась), но вырезание оставляет на шве дыру:
    `grep: : Permission denied`. Первую правку я сделал `replace(' : ', ': ')`
    и получил `grep:: Permission denied` — то есть сам и прорезал дыру глубже
    (показал живой контроль на настоящем /bin/bash). Правильно сворачивать
    сам шов: два разделителя, между которыми не осталось текста, — это один
    разделитель. Цитата — единственное, что оператор читает как доказательство,
    поэтому её режут по шву, а не по живому.
    """
    t = str(text or '').replace(str(path), '')
    while ': :' in t:
        t = t.replace(': :', ':')
    while '::' in t:
        t = t.replace('::', ':')
    while t.startswith(':') or t.startswith(' '):
        t = t.lstrip(':').lstrip()
    return ' '.join(t.split())


def classify_grep_probe(rc, body, path, err=''):
    """Один ответ grep → {'domains', 'kind', 'why'} — чистая функция.

    Таблица состояний ОДНА на обе формы чтения конфигов: прежнюю пофайловую
    (одна SSH-команда на файл) и новую сводную (одна команда на пачку,
    domain_configs_probe_cmd). Иначе две формы однажды разъедутся — тот же
    закон, из-за которого разбор `server_name` уже вынесен в
    domains_from_config_text одним местом.

    Состояние решается КОДОМ ВОЗВРАТА И КАНАЛОМ, а не текстом ответа
    (закон 1.31.0: локализованная формулировка — не основание). Замер живьём на настоящем /bin/bash, реальные файлы:

        rc=0 + непустой stdout   прочитан, есть совпадения   kind=None
        rc=1 + пустой stderr     прочитан, server_name нет   kind=None
        rc=2 + Permission denied закрыт 0000                 'unreadable'
        rc=2 + No such file      конфига нет                 'missing'
        rc=2 + Is a directory    путь — каталог              'isdir'

    kind=None — «пробел не закрыт» (молчать честно), kind — «пробел есть»;
    признание нужно только там, где отчёт иначе врёт (закон 1.19–1.28).

    'why' — ответ системы (цитируется, а не подменяется удобным диагнозом) с
    ВЫРЕЗАННЫМ путём. Путь печатается в каждом сообщении grep, и без вырезания
    десять закрытых файлов дали бы десять РАЗНЫХ ключей — сводка рассыпалась бы
    на десять строк (замер живьём: 10 конфигов 0000 = 10 одинаковых признаний).
    Разные же ответы системы («memory exhausted» против «input file is also the
    output») обязаны остаться раздельными: это разные основания.

    'body' — stdout ответа, 'err' — stderr. Прежняя форма звала grep с `2>&1` и
    получала всё в stdout; сводная форма тоже объединяет каналы (rc снимается
    до печати). Поэтому 'err' необязателен, но если он есть — приоритет причины
    у него, как было в одиночной форме.
    """
    text_out = str(body or '')
    text_err = str(err or '')
    low = (text_out + ' ' + text_err).lower()

    if rc == 0:
        if text_out.strip():
            return {'domains': domains_from_config_text(text_out),
                    'kind': None, 'why': ''}
        # rc=0 без совпадений для grep не бывает (успех обязан совпадением):
        # ответ оборвался — это пробел, а не «server_name нет».
        return {'domains': [], 'kind': 'unchecked',
                'why': 'grep вернул успех с пустым выводом'}

    if rc == 1 and not text_err.strip():
        # Штатный ответ grep «файл прочитан, совпадений нет» — ответ системы.
        return {'domains': [], 'kind': None, 'why': ''}

    kind = None
    if 'permission denied' in low:
        kind = 'unreadable'
    elif 'is a directory' in low:
        kind = 'isdir'
    elif 'no such file' in low:
        kind = 'missing'
    why = next((line.strip() for line in (text_err or text_out).splitlines()
                if line.strip()), '')[:200]
    key = _tidy_citation(why, path) or f'код возврата {rc}'
    return {'domains': [], 'kind': kind or 'unchecked', 'why': key}


# Маркер одного ответа в сводной команде чтения конфигов. Формат строки:
# '@F <rc><TAB><путь>' — путь печатается ПОСЛЕ rc и через TAB, потому что сам
# путь может содержать пробелы ('/var/www/my site/a.conf' — панели кладут
# каталоги и так) и даже кириллицу (замер живьём: оба случая разбираются).
DOMAIN_PROBE_MARKER = '@F'


def domain_configs_probe_cmd(config_paths):
    """Одна команда на ВСЮ пачку конфигов: rc и ответ на каждый файл.

    Зачем: прежнее чтение звало `_domain_config_probe` по одному разу на файл,
    и цена честности росла линейно. Замер живьём на настоящем /bin/bash этого
    хоста, 200 реальных конфигей: 10 файлов = 11 SSH-команд, 50 = 51, 200 =
    201. Из-за этого же `get_domains_info` держал limit=10 и докладывал 10
    доменов при 40 на сервере — оператор читал это как «доменов больше нет».
    Поднять лимит, не удешевив чтение, означало бы умножить SSH-заходы.

    Форма проверена живьём (замер этого слайса): `v=$(grep … 2>&1)` и `r=$?`
    без промежуточного echo — иначе первая же печать крадёт $? и rc станет
    нулём printf, а не grep'а (урок 1.31.0, куплен второй раз).

    Пайпа нет ЦЕЛИКОМ: rc принадлежит последней команде пайпа, а не grep
    (урок 1.28.0). `${PIPESTATUS}` не используем — под dash (обычный /bin/sh в
    Debian/Ubuntu) это «Bad substitution» (замерено на прошлых слайсах).

    `2>/dev/null` нет: в stderr лежит ровно та строка, где написана причина
    пустоты («Permission denied» против «No such file or directory» —
    противоположные лечения).

    Пустой список путей безопасен: `set --` без аргументов, цикл молчит
    (замер: вывод пуст, rc=0).
    """
    quoted = ' '.join(q(p) for p in (config_paths or []))
    return (
        f'set -- {quoted}; '
        'for f in "$@"; do '
        'v=$(grep -h \'server_name\' "$f" 2>&1); '
        'r=$?; '
        f'printf \'{DOMAIN_PROBE_MARKER} %s\\t%s\\n\' "$r" "$f"; '
        'printf \'%s\\n\' "$v"; '
        'done'
    )


def parse_domain_probe_answer(out):
    """[{path, rc, body}] из ответа сводной команды; [] — ответа не было.

    rc не разбирается / маркера нет — запись НЕ создаётся: выдумывать состояние
    нельзя, а «ни одной записи при непустом запросе» обязано превратиться в
    признание «не проверено» (это решает вызывающая сводка), а не в «доменов
    нет». Молчание обрыва здесь не диагноз (закон 1.19–1.31).

    Тело ответа — строки до следующего маркера; при rc=1 оно приходит пустым,
    при rc=2 содержит сообщение системы («grep: …: Permission denied»).
    """
    rows = []
    cur = None
    buf = []
    for line in str(out or '').splitlines():
        if line.startswith(DOMAIN_PROBE_MARKER + ' '):
            if cur is not None:
                cur['body'] = '\n'.join(buf)
                rows.append(cur)
            cur = None
            buf = []
            rest = line[len(DOMAIN_PROBE_MARKER) + 1:]
            head, sep, path = rest.partition('\t')
            try:
                rc = int(head.strip())
            except ValueError:
                continue          # битый маркер — не ответ системы
            if not sep:
                continue          # путь не пришёл: разбор невозможен
            cur = {'path': path, 'rc': rc, 'body': ''}
            continue
        if cur is not None:
            buf.append(line)
    if cur is not None:
        cur['body'] = '\n'.join(buf)
        rows.append(cur)
    return rows


def _domain_config_probe(checker, config_path):
    """Один конфиг → {'domains', 'kind', 'why'}; kind=None — молчать честно.

    Слайс 1.32.0: состояние больше НЕ решается здесь — разбор живёт в
    classify_grep_probe одним местом, чтобы сводная форма (одна команда на
    пачку) не могла разъехаться с этой. Команда и её rc остались прежними,
    поэтому запертые тесты одиночной формы продолжают ловить пайп и /dev/null.
    """
    cmd = f"grep -h 'server_name' {q(config_path)} 2>&1"
    out, err, rc = checker.run(cmd)
    return classify_grep_probe(rc, out, config_path, err)


BATCH_MISSING_WHY = 'сводная команда сервера не вернула ответа на этот конфиг'


def _config_probes(checker, paths):
    """{путь: probe} на ВСЮ пачку — ОДНА SSH-команда (слайс 1.32.0).

    Цена — причина, по которой существует эта функция: прежний цикл звал
    `_domain_config_probe` на каждый файл, и честность дорожала линейно
    (замер живьём, 200 реальных конфигей: 10 файлов = 11 SSH-команд,
    50 = 51, 200 = 201). Из-за этой же цены `get_domains_info` держал
    limit=10 и докладывал 10 доменов при 40 на сервере.

    Один путь остаётся на одиночной форме: её заперли тесты 1.29.0 (цена
    «одна команда», отсутствие пайпа и `2>/dev/null`) и она привычна
    оператору; вторая команда на тот же файл была бы лишним заходом.

    Ответа на путь нет (обрыв канала, таймаут, чужая реализация) — probe
    получает kind='unchecked': молчать нельзя, «доменов нет» при непустом
    запросе — ложь (закон 1.19–1.31). Причина тут же цитируется у системы,
    если она что-то ответила в stderr; выдумывать ответ мы не имеем права.
    """
    if len(paths) == 1:
        return {paths[0]: _domain_config_probe(checker, paths[0])}

    out, err, _rc = checker.run(domain_configs_probe_cmd(paths))
    probes = {}
    for row in parse_domain_probe_answer(out):
        probes.setdefault(row['path'],
                          classify_grep_probe(row['rc'], row['body'],
                                              row['path']))
    missing = [p for p in paths if p not in probes]
    if missing:
        why = next((line.strip() for line in (err or '').splitlines()
                    if line.strip()), '')[:160] or BATCH_MISSING_WHY
        for path in missing:
            probes[path] = {'domains': [], 'kind': 'unchecked', 'why': why}
    return probes


def domains_from_configs_info(checker, config_paths):
    """(домены, notes) по СПИСКУ конфигов: одно признание на основание.

    Второй дефект этого же слайса, который показал первый GREEN: причина
    дошла до оператора — но десятью строками. Десять конфигов с правами 0000
    давали ДЕСЯТЬ одинаковых «⚠️ Домены по …: нет прав» (замер живьём), и
    отчёт тонул: признание, которого десять, оператор перестаёт читать. Тот же
    закон, что лечился «одним признанием на прогон» в 1.28.0 и в сводке
    каталогов логов 1.20.0.

    Группировка — по (состояние, ответ системы), а НЕ по файлу:

      * «нет прав» и «конфига нет на сервере» НЕ сливаются в одну строку —
        лечения противоположные (поднимать права против менять раскладку
        панели);
      * два разных ответа системы («memory exhausted» и «input file is also
        the output») тоже не сливаются: это разные основания, и каждое
        цитируется;
      * внутри одной группы пути считаются числом: «по 10 файлам (…)» — цифру
        оператор обязан видеть, иначе сводка врёт о масштабе пробела.

    Найденное при этом не теряется: 9 прочитанных + 1 закрытый дают 9 доменов
    и одну заметку, а не «доменов нет».
    """
    paths = [str(p) for p in (config_paths or [])]
    if not paths:
        # Ни одного конфига: спрашивать нечего, молчание честно (признание на
        # пустой запрос было бы выдуманным пробелом).
        return [], []
    probes = _config_probes(checker, paths)
    domains = []
    groups = {}
    order = []
    for path in paths:
        probe = probes[path]
        domains.extend(probe['domains'])
        if probe['kind'] is None:
            continue
        key = (probe['kind'], probe['why'])
        if key not in groups:
            groups[key] = {'kind': probe['kind'], 'why': probe['why'],
                           'paths': []}
            order.append(key)
        groups[key]['paths'].append(path)

    notes = []
    for key in order:
        group = groups[key]
        paths = group['paths']
        if len(paths) == 1:
            where = paths[0]
        else:
            where = (f"{len(paths)} файлам ({paths[0]} "
                     f"и ещё {len(paths) - 1})")
        if group['kind'] == 'unchecked':
            notes.append(DOMAIN_UNCHECKED_NOTE.format(path=where,
                                                      why=group['why']))
        else:
            notes.append(f"⚠️ Домены по {where}: " + DOMAIN_GAP_TEXT[group['kind']]
                         + (f" ({group['why']})" if group['why'] else ''))
    return sorted(set(domains)), notes


def get_domain_from_config_info(checker, config_path):
    """(домены, notes): список И чем объяснена пустота.

    Прежний вид:

        grep -h 'server_name' … 2>/dev/null | sed … | tr … | grep -v …

    Терялись ТРИ вещи сразу — ровно как в 1.28.0 на systemctl:
      1. `2>/dev/null` выбрасывал единственную строку, где написано ПОЧЕМУ
         пусто;
      2. пайп **забирал код возврата**: конвейер отдаёт rc последней команды
         (`grep -v`), а тот сообщает лишь «фильтр что-то пропустил». Про права
         пайп не говорит НИКОГДА — проверено: на закрытом 0000, отсутствующем
         файле и каталоге прежняя команда давала rc=1 и пустой вывод,
         идентичный «server_name нет»;
      3. вывод был УЖЕ извлечёнными именами, поэтому тестовый двойник описывал
         ответ, которого grep не выдаёт никогда, и чинить пайп под зелёными
         тестами было нельзя (урок 1.27.0).

    Замер живьём (этот хост, uid=1000), ОДНА команда
    `grep -h 'server_name' ПУТЬ 2>&1`, rc принадлежит grep'у:

        читаемый, домены есть     rc=0 'server_name example.com www.example.com;'
        прочитан, server_name нет rc=1 ''
        ЗАКРЫТ 0000               rc=2 'grep: ...: Permission denied'
        ОТСУТСТВУЕТ               rc=2 'grep: ...: No such file or directory'
        КАТАЛОГ                   rc=2 'grep: ...: Is a directory'

    То есть «нет прав» и «конфига нет» — противоположные действия (поднимать
    права против менять раскладку панели) — давали один ответ `[]`, и
    `get_domains_info` докладывал «доменов нет». Цена не выросла: была одна
    SSH-команда, осталась одна.

    notes пуст и при найденных доменах, и при честном rc=1 («прочитано,
    совпадений нет») — признание нужно только на пробел (закон 1.19–1.28).
    """
    # Один файл — частный случай сводки по списку (domains_from_configs_info):
    # формулировка при этом остаётся прежней, «⚠️ Домены по <путь>: …», потому
    # что заперта тестами и привычна оператору. Команда живёт в
    # _domain_config_probe — одном месте на обе формы.
    return domains_from_configs_info(checker, [config_path])


def get_domain_from_config(checker, config_path):
    """Домены из конфигурационного файла (причины пустоты — в _info-форме).

    Пустой список здесь значит и «доменов нет», и «мы не смогли посмотреть»:
    отчёту, которому важно различать, обязан звать
    get_domain_from_config_info.
    """
    return get_domain_from_config_info(checker, config_path)[0]
