"""Управление панелями: ISPmanager (mgrctl) и FastPanel (systemd-юниты)."""
import re

from common import (q, find_files_info,
                     file_presence, process_kill, process_probe,
                     crontab_read_info, save_crontab_backup_info,
                     crontab_write_info)


# ==================== УПРАВЛЕНИЕ ISPmanager ====================
def ispmanager_restart(checker):
    lines = ["=== ПЕРЕЗАПУСК ISPmanager ==="]
    out, err, rc = checker.run('/usr/local/mgr5/sbin/mgrctl -m ispmgr exit 2>&1')
    if rc != 0:
        lines.append(f"❌ Ошибка (rc={rc}): {err.strip() or out.strip()}")
    else:
        lines.append("✅ Команда на перезапуск отправлена через mgrctl")
    checker.exec_command('sleep 3')
    out2, _, _ = checker.run('/usr/local/mgr5/sbin/mgrctl -m ispmgr sysinfo 2>&1 | head -1')
    lines.append("✅ Панель работает" if 'error' not in out2.lower() else "⚠️ Панель возможно не запустилась")
    return "\n".join(lines)


# Пути цели убийства — константы: они же фигурируют в диагностике, и у
# команды убийства не должно права собирать путь из кавычек на месте.
ISP_CORE_BIN = '/usr/local/mgr5/bin/core'
ISP_IHTTPD_BIN = '/usr/local/mgr5/bin/ihttpd'


def process_state_label(info):
    """Состояние процесса словами: ТРИ ответа вместо прежних двух.

    Прежняя форма печатала «❌ не запущен» и когда список процессов не был
    получен вовсе (замер: rc=127, пустой stdout — оболочка сообщает «command
    not found», утилиту нет). Оператор читал это как «демона нет» и искал
    причину в панели, а не в том, что мы не спросили.
    """
    if not info['checked']:
        return 'не проверено: ' + (info['note'] or 'список процессов не прочитан')
    return '✅ запущен' if info['state'] == 'running' else '❌ не запущен'


def ispmanager_kill_core(checker):
    """Завершает core по pid из достоверного списка процессов.

    Прежний код решал по ИМЕНИ: «killall core», «pkill -9 core», а потом
    «ps aux | grep core | grep -v grep». Живой замер на этом хосте (настоящий
    bash, живость по State из /proc после reap):

      * «pkill -9 core» убил ЧУЖОЙ coredns — pgrep и pkill матчают имя как
        подстроку, то есть штатная кнопка была отказом обслуживания чужих
        процессов, а не только лживым отчётом;
      * «killall core» и «pkill -x core» чужой coredns пощадили, но «pgrep -x
        core» находит и чужой /opt/vendor/core — то же имя файла, другая
        установка: убивать по имени в принципе нечем;
      * пустое наблюдение значило «завершён» даже тогда, когда ps не
        запустилось: процесс оставался живым.

    Поэтому цель берётся из argv[0], равного пути панели, а убиваются
    названные pid. Пауза прежнего кода («sleep 2») была костылём поверх
    ложного признака: строка зомби «[core] <defunct>» содержит слово core, и
    «завершён» наступал лишь через пару секунд; признак по argv[0] зомби в
    цели не считает никогда, потому что его argv0 — «[core]».
    """
    lines = ["=== ПРИНУДИТЕЛЬНОЕ ЗАВЕРШЕНИЕ CORE ==="]
    probe = process_probe(checker, ISP_CORE_BIN)
    if not probe['checked']:
        lines.append("⚠️ " + (probe['note'] or 'список процессов не прочитан'))
        return "\n".join(lines)
    if probe['state'] == 'absent':
        lines.append("Процесс core не запущен: список процессов прочитан, "
                     "цели в нём нет")
        if probe['note']:
            lines.append("ℹ️ " + probe['note'])
        return "\n".join(lines)
    result = process_kill(checker, probe['pids'], target=ISP_CORE_BIN)
    if result['state'] == 'gone':
        lines.append("✅ Процесс core завершён")
    elif result['state'] == 'alive':
        lines.append("⚠️ Процесс core всё ещё работает")
        if result['note']:
            lines.append("ℹ️ " + result['note'])
    else:
        # Убивать пробовали, но перечитать нечем: право на «готово» даёт
        # только перечитанный список (отказ прав и «процесса нет» дают один
        # и тот же rc=1 — замер).
        lines.append("⚠️ " + (result['note'] or 'состояние не проверено'))
    if result['similar']:
        lines.append("ℹ️ тот же файл запущен из другого пути — его не трогаем")
    return "\n".join(lines)

def ispmanager_update(checker):
    lines = ["=== ОБНОВЛЕНИЕ ISPmanager ==="]
    lines.append("⚠️ Обновление может занять несколько минут...")
    out, err, rc = checker.run('/usr/local/mgr5/sbin/pkgupgrade.sh coremanager 2>&1')
    lines.append("✅ Обновление завершено" if rc == 0 else f"❌ Ошибка обновления (rc={rc}): {err.strip() or out.strip()}")
    return "\n".join(lines)


def ispmanager_ssl_issue(checker):
    lines = ["=== ПРИНУДИТЕЛЬНЫЙ ВЫПУСК LET'S ENCRYPT ==="]
    lines.append("⚠️ Процесс может занять несколько минут...")
    out, err, rc = checker.run('/usr/local/mgr5/sbin/mgrctl -m ispmgr letsencrypt.periodic 2>&1')
    lines.append("✅ Команда выполнена" if rc == 0 else f"❌ Ошибка (rc={rc}): {err.strip() or out.strip()}")
    return "\n".join(lines)


def ispmanager_disable(checker):
    lines = ["=== ОТКЛЮЧЕНИЕ ISPmanager ==="]
    lines.append("⚠️ Панель будет остановлена!")
    checker.exec_command('chmod -x /usr/local/mgr5/bin/core 2>&1')
    checker.exec_command('killall core 2>&1')
    checker.exec_command('killall ihttpd 2>&1')
    lines.append("✅ Панель отключена")
    lines.append("⚠️ Для включения выполните: chmod +x /usr/local/mgr5/bin/core && /usr/local/mgr5/bin/core")
    return "\n".join(lines)


def ispmanager_disable_geoip(checker):
    lines = ["=== ОТКЛЮЧЕНИЕ GEOIP В ISPmanager ==="]
    out, err, rc = checker.run('/usr/local/mgr5/sbin/mgrctl -m ispmgr usrparam setgeoip=off sok=ok 2>&1')
    lines.append("✅ GeoIP отключён" if rc == 0 else f"❌ Ошибка (rc={rc}): {err.strip() or out.strip()}")
    return "\n".join(lines)


def ispmanager_check_cron_path(checker):
    """PATH в crontab: «найдена» / «нет» / «прочитать не удалось».

    Прежняя форма:

        out, _ = checker.exec_command('crontab -l 2>/dev/null | grep "^PATH="')

    теряла и код возврата (exec_command отдаёт только каналы), и причину — она
    глохла в /dev/null. Пустой вывод дают оба мира: «PATH нет» и «crontab не
    прочитан» (замер живьём: rc=1, вывод пуст). Оператор читал «✅ Переменная
    PATH не найдена» там, где панель вообще не ответила. Признак спрашивает
    ОДНА функция на весь проект — crontab_read_info, та же, что у правки.
    """
    lines = ["=== ПРОВЕРКА CRON PATH ==="]
    read = crontab_read_info(checker)
    if read['state'] == 'failed':
        lines.append("❌ Текущий crontab не прочитан (%s) — проверять PATH "
                     "нечем" % read['note'])
        return "\n".join(lines)
    hits = [ln for ln in (read['text'] or '').splitlines()
            if ln.startswith('PATH=')]
    if hits:
        lines.append("⚠️ Найдена переменная PATH в crontab:\n"
                     + "\n".join(hits))
    else:
        lines.append("✅ Переменная PATH не найдена в crontab")
    return "\n".join(lines)


def ispmanager_fix_cron_path(checker):
    """Комментирует PATH в crontab, только если есть прочитанный оригинал и
    записанный резерв.

    Боевая форма решала по нулю кода возврата целого конвейера:

        crontab -l 2>/dev/null | sed 's/^PATH=/#PATH=/' | crontab - 2>&1

    Замер живьём (настоящий bash, подставной crontab с хранилищем, uid=1000) в
    мире нечитаемого crontab: rc=0 и ПОТЕРЯНЫ ВСЕ задания, отчёт — «✅
    Переменная PATH закомментирована». Причина в двух местах: чтение прятало
    диагноз в /dev/null, а rc конвейера принадлежит ПОСЛЕДНЕМУ элементу
    (`false | true` даёт 0), то есть успехом считалась запись, а не прочтение.
    Третья: «резерв» делался из /tmp/crontab_current.txt, который редирект
    создаёт до запуска утилиты, — при отказе чтения он нулевой (замер: 0 байт
    против 104 в норме), а нулевой бэкап при откате затирает рабочий crontab.

    Теперь право на запись дают прочитанный оригинал, принятый резерв и
    ПЕРЕЧИТАННЫЙ после правки текст. Менять нечего — значит ничего не пишем:
    пустое тело для `crontab -` есть «записать ПУСТОЙ crontab» (замер: rc=0,
    хранилище опустело).
    """
    lines = ["=== ИСПРАВЛЕНИЕ CRON PATH ==="]
    read = crontab_read_info(checker)
    if read['state'] == 'failed':
        lines.append("❌ Текущий crontab не прочитан (%s) — правку отменяю: "
                     "иначе существующие задания будут стёрты" % read['note'])
        return "\n".join(lines)
    original = read['text'] or ''
    targets = [ln for ln in original.splitlines()
               if ln.startswith('PATH=')]
    if not targets:
        lines.append("ℹ️ Переменная PATH в crontab не найдена — менять нечего,"
                     " crontab не тронут")
        return "\n".join(lines)

    info = save_crontab_backup_info(checker)
    if info['state'] == 'failed':
        lines.append("❌ Резервная копия crontab не записана: %s — правку "
                     "отменяю: без отката менять нельзя" % info['note'])
        return "\n".join(lines)
    if info['state'] == 'done':
        lines.append("✅ Резервная копия crontab: %s" % info['path'])
    else:
        lines.append("ℹ️ Текущий crontab пуст — бэкап не требуется")

    body = "".join(('#' + ln if ln.startswith('PATH=') else ln) + '\n'
                   for ln in original.splitlines())
    written = crontab_write_info(checker, body)
    if written['state'] == 'done':
        lines.append("✅ Переменная PATH закомментирована")
    elif written['state'] == 'unverified':
        lines.append("❌ Правка не подтверждена: %s — проверьте crontab -l "
                     "вручную" % written['note'])
    else:
        lines.append("❌ crontab не принят (%s) — проверьте crontab -l "
                     "вручную" % written['note'])
    return "\n".join(lines)


# ==================== УПРАВЛЕНИЕ FASTPANEL ====================
# FastPanel 2.x ставит юнит fastpanel2-engine, FastPanel 1.x — fastpanel.
FASTPANEL_UNITS = ['fastpanel2-engine', 'fastpanel']

# Логи панели в обоих поколениях; порядок — от нового к старому.
FASTPANEL_LOGS = [
    '/var/log/fastpanel2/engine.log',
    '/var/log/fastpanel/fastpanel.log',
]


# Ответ systemctl на «юнита нет» и на «systemctl нечем говорить» — РАЗНЫЕ
# диагнозы с противоположным лечением (ставить панель против чинить systemd /
# смотреть в контейнере). Маркеры собраны по замерам живьём и по текстам
# systemd (systemd №229+): см. docstring systemd_unit_state.
SYSTEMD_DEAD_MARKS = (
    'not been booted with systemd',   # 'System has not been booted ... Can't operate.'
    'failed to connect to bus',       # 'Failed to connect to bus: Host is down'
    'failed to connect to dbus',
    'could not connect to dbus',
    'talk to init daemon',            # 'Failed to talk to init daemon.'
    'running in a chroot',
    'cannot communicate with',
)
SYSTEMD_ABSENT_MARKS = (
    'no such file or directory',      # 'Failed to get unit file list for X.unit: ...'
    'could not be found',             # 'Unit X.service could not be found.'
    'not-found',
    'no unit file',
    'loaded not-found',
)

UNIT_UNCHECKED_NOTE = (
    "⚠️ Наличие службы панели проверить не удалось — состояние не проверено: "
    "«{why}». Это пробел, а не диагноз: ответьте на причину (права, systemd, "
    "PATH) и повторите, а не ставьте панель")


def systemd_unit_state(out, err, rc):
    """(состояние, причина) ответа `systemctl cat <юнит>` -> unit|absent|unknown.

    Прежний вид:

        out, _, _ = checker.run(f'systemctl cat {q(unit)} 2>/dev/null | head -1')
        if out.strip():
            return unit

    Тут терялись ДВЕ вещи сразу. `2>/dev/null` глушил единственную строку, где
    написано ПОЧЕМУ пусто. А `| head -1` ещё и забирал себе код возврата: пайп
    отдаёт rc последней команды, то есть `head`, а он доволен всегда. Замер
    живьём (этот хост, PID1=bwrap, systemd нет):

        systemctl cat fastpanel2-engine 2>/dev/null | head -1  -> rc=0 stdout=''
        systemctl cat definitely-no-such-unit    ... | head -1 -> rc=0 stdout=''
        systemctl cat fastpanel2-engine 2>&1                   -> rc=1
            'System has not been booted with systemd as init system (PID 1).
             Can't operate. / Failed to connect to bus: Host is down'

    То есть «юнита нет», «systemctl говорить не может» и «сервер вообще не
    ответил» давали ОДИН ответ — None, и вызывающий код (`fastpanel_restart`)
    писал «Служба панели не найдена» и отказывался перезапускать. Оператор шёл
    переустанавливать панель на хосте, где нужно было смотреть systemd.

    Поэтому команда меняется (rc обязан принадлежать systemctl), а состояния
    различаются так:

        rc=0 + непустой stdout -> 'unit'    (юнит есть — это ответ системы)
        rc=127                 -> 'unknown' (бинарника systemctl нет)
        rc!=0 + DEAD-маркер    -> 'unknown' (systemctl/bus мёртв)
        rc!=0 + ABSENT-маркер  -> 'absent'  (юнита нет — это ответ системы)
        всё остальное          -> 'unknown'

    ПОРЯДОК проверок критичен: rc=127 даёт текст «No such file or directory»
    (его печатает оболочка, а не systemd). Если сначала смотреть маркеры
    отсутствия, «systemctl нет» станет «юнита нет» — ровно та подмена, из-за
    которой оператор пойдёт ставить панель вместо починки PATH.

    'unknown' — это «не проверено»: его обязан признать отчёт (закон серии
    1.19–1.27), 'absent' — честный диагноз, признания не требует.
    """
    text = f'{out or ""} {err or ""}'.lower()
    why = next((line.strip() for line in (err or out or '').splitlines()
                if line.strip()), '')[:200] or f'код возврата {rc}'
    if rc == 127:
        return 'unknown', why
    if rc == 0:
        if (out or '').strip():
            return 'unit', ''
        # Молчаливый успех: команда прошла, вывода нет — мы ничего не узнали.
        return 'unknown', 'systemctl cat вернул пустой вывод без ошибки'
    if any(mark in text for mark in SYSTEMD_DEAD_MARKS):
        return 'unknown', why
    if any(mark in text for mark in SYSTEMD_ABSENT_MARKS):
        return 'absent', ''
    return 'unknown', why


def fastpanel_unit_info(checker):
    """(юнит панели | None, признание | None).

    `systemctl cat` спрашиваем вместо `is-active`: нам важно, что юнит
    существует, а не что он запущен (панель как раз могла упасть).

    Второе поле — не «причина отсутствия», а признание НЕПРОВЕРЕННОСТИ: его нет,
    когда система ответила (найден юнит или ответила «его нет»), и оно есть,
    когда спросить не получилось. Складывать их в одно значение нельзя:
    `fastpanel_restart` по-разному лечит «панели нет» и «мы не смогли посмотреть».
    """
    unknown = ''
    for unit in FASTPANEL_UNITS:
        out, err, rc = checker.run(f'systemctl cat {q(unit)} 2>&1')
        state, why = systemd_unit_state(out, err, rc)
        if state == 'unit':
            # Нашли — признаний нет: вопрос закрыт ответом системы.
            return unit, None
        if state == 'unknown' and not unknown:
            unknown = why
    if unknown:
        return None, UNIT_UNCHECKED_NOTE.format(why=unknown)
    return None, None


def fastpanel_unit(checker):
    """Первый установленный systemd-юнит панели (или None).

    None здесь значит и «юнита нет», и «мы не смогли посмотреть». Отчёт обязан
    звать fastpanel_unit_info — иначе он повторит враньё 1.27 и ниже.
    """
    return fastpanel_unit_info(checker)[0]


def find_fastpanel_logs_info(checker, limit=10):
    """(логи панели, notes): список И чем объяснена пустота.

    Прежний вид:

        out, _, _ = checker.run(f'ls -1 {pattern} 2>/dev/null | head -{limit}')

    `2>/dev/null` выбрасывал ровно ту строку, где написано, почему пусто: «нет
    прав на /var/log/fastpanel2» и «каталога нет» — два противоположных действия
    (поднимать права против проверять раскладку панели), а оператор читал одно
    «Логи панели не найдены». Замер живьём на несуществующем пути:

        прежняя команда                     -> rc=0 stdout='' (та же пустота и
                                               при закрытом каталоге)
        find_files_info (примитив 1.20)     -> dirs=[('missing','/var/log/fastpanel2')]
                                               total=0, note «Каталога ... нет на
                                               сервере — искать в нём негде»

    Паттерны — ровные пути без звёздочек, поэтому примитиву достаточно проверить
    их родительский каталог; команду это не удорожает: ОДНА на путь, как и было.
    """
    found = []
    notes = []
    asked = 0
    confirmed = 0
    for pattern in FASTPANEL_LOGS:
        info = find_files_info(checker, pattern, limit)
        asked += 1
        found.extend(info['paths'])
        if info['dirs'] or info['total'] is not None:
            confirmed += 1
        for note in info['notes']:
            if note not in notes:
                notes.append(note)
    if asked and not confirmed:
        # Сервер не подтвердил просмотр ни одного каталога: «не проверено», а не
        # «логов нет». Одна строка на прогон — причина общая, а N одинаковых
        # предупреждений оператор прочитает как N разных бед.
        notes.append(f"⚠️ Поиск логов панели не завершён: ни один из {asked} "
                     f"путей не подтверждён сервером — это «не проверено», а не "
                     f"«логов нет»")
    return found, notes


def find_fastpanel_logs(checker, limit=10):
    """Существующие логи панели (причины пустоты — в find_fastpanel_logs_info)."""
    return find_fastpanel_logs_info(checker, limit)[0]


def fastpanel_restart(checker):
    lines = ["=== ПЕРЕЗАПУСК ПАНЕЛИ FASTPANEL ==="]
    unit, unchecked = fastpanel_unit_info(checker)
    if not unit:
        # Отказ обязан называть своё основание. «Не найдена» и «не посмотрели» —
        # разные действия: в первом случае панель ставят, во втором чинят доступ
        # к systemd. Прежний текст одинаково врал обоим, причём на хосте без
        # systemd — всегда вторым.
        if unchecked:
            lines.append("❌ Перезапуск не отправлен: " + unchecked)
        else:
            lines.append("❌ Служба панели не найдена "
                         "(fastpanel2-engine / fastpanel)")
        return "\n".join(lines)

    lines.append(f"Юнит панели: {unit}")
    out, err, rc = checker.run(f'systemctl restart {q(unit)} 2>&1')
    if rc != 0:
        lines.append(f"❌ Не удалось перезапустить (rc={rc}): {err.strip() or out.strip()}")
        return "\n".join(lines)

    out2, _, _ = checker.run(f'systemctl is-active {q(unit)} 2>&1')
    status = out2.strip() or 'unknown'
    lines.append(f"✅ Панель перезапущена (состояние: {status})"
                 if status == 'active' else f"⚠️ Состояние после перезапуска: {status}")
    return "\n".join(lines)


def fastpanel_logs(checker):
    lines = ["=== ЛОГИ ПАНЕЛИ FASTPANEL ==="]
    logs, gaps = find_fastpanel_logs_info(checker)
    if not logs:
        if gaps:
            # «Не проверено» не имеет права печататься как «не найдены» (закон
            # 1.19–1.27). Прежняя строка «Логи панели не найдены по путям»
            # оставалась в выводе и после правки — т.е. ложь просто переехала бы
            # в соседнюю строку того же отчёта. Пути просмотра при этом обязаны
            # остаться: по ним и чинят (заперто тестом).
            lines.extend(gaps)
            lines.append("   Смотрели по путям: " + ", ".join(FASTPANEL_LOGS))
        else:
            # Просмотр подтверждён, файлов нет — это честный ответ, а не пробел.
            lines.append("⚠️ Логи панели не найдены по путям: "
                         + ", ".join(FASTPANEL_LOGS))
        return "\n".join(lines)

    for path in logs:
        out, _, _ = checker.run(f'tail -n 30 {q(path)} 2>&1')
        lines.append(f"\n--- {path} (последние 30 строк) ---")
        lines.append(out.strip() or "(файл пуст)")
    return "\n".join(lines)


# Службы, которыми управляет FastPanel.
#
# Прежняя форма спрашивала их одной сбор строкой
#
#     systemctl is-active nginx 2>/dev/null; systemctl is-active php-fpm
#     2>/dev/null; systemctl is-active mysql 2>/dev/null || systemctl
#     is-active mariadb 2>/dev/null
#
# в ней терялось ВСЁ сразу: код возврата сборки принадлежал ПОСЛЕДНЕЙ команде,
# stdout четырёх служб шёл в один поток без разделителей («active active» —
# непонятно, чей), `2>/dev/null` глушил единственную строку с причиной, а
# `|| mariadb` вообще молча пропускал mariadb, когда mysql «ответил».
#
# Замер живьём на хосте без systemd (настоящий /bin/bash, PID1 не systemd):
#
#     for s in nginx php-fpm mysql mariadb; do printf "@%s\n" "$s";
#     LC_ALL=C systemctl is-active "$s"; done
#       stdout: '@nginx\n@php-fpm\n@mysql\n@mariadb\n'   (тел — НЕТ)
#       stderr: 'System has not been booted with systemd as init system
#                (PID 1). Can't operate.'
#
# То есть система ничего не ответила про службы, но прежний отчёт на этом
# печатал «nginx / php-fpm / mysql(mariadb): unknown», и оператор читал его как
# «стек мёртв». Пустое ТЕЛО под маркером и есть признак «не проверено».
#
# Ограничение закрыто в 1.32.27: `systemctl is-active` для несуществующей
# службы печатает 'inactive' — «юнита нет» и «стоит, но остановлена» по
# stdout неразличимы (замер пары на живом systemd: побайтово равный вывод,
# rc 4 против 3; оракул — systemctl show -p LoadState). Раньше это
# называлось «сознательно не чинится», потому что различать обещали только
# через `systemctl cat` (+1 запрос на службу). Код возврата лежал в том же
# канале: цикл снимает rc ВНУТРИ итерации (у сборки он принадлежал последней
# команде), и parse_stack_unit_state читает его из тела секции.
PANEL_STACK_UNITS = ('nginx', 'php-fpm', 'mysql', 'mariadb')

# Порт веб-интерфейса панели. Литерал 8888 до этого был вшит в код в трёх
# местах (здесь, в fastpanel_diag и в комментарии); с появлением параметра
# `port=` он обязан стать константой — по образцу ISP_PANEL_PORT. Старые сборки
# FastPanel слушают 4444, но менять значение под них нельзя: это другой хост, а
# не другая ветка кода (проверка живьём делалась на 8888/8899).
FASTPANEL_PORT = 8888

# Схемы, которыми спрашивают панель: HTTPS первой, потому что панель отдаёт
# именно https, а HTTP-ответ на 8888 — отдельный диагноз (редирект или
# голый порт).
# Протокол `v=$(curl …); echo "rc=$? code=$v"` — единственный замеренный
# способ сохранить И HTTP-код, И код возврата: любой промежуточный `echo`
# крадёт $? (замер: 'rc=0 code=000' вместо честного 'rc=7 code=000').
PANEL_SCHEMES = ('https', 'http')

# Коды возврата curl, которые являются ОТВЕТОМ системы (а не отказом
# отвечать). 127 здесь нет намеренно: это «бинарника curl нет» — пробел.
CURL_RC_ANSWER = {
    6: 'не разрешился хост',
    7: 'отказ в соединении (порт не слушает)',
    28: 'таймаут',
    35: 'слушает, но не по TLS — стучимся не туда',
}

STACK_NO_ANSWER = 'не проверено'
STACK_UNIT_ABSENT = 'не установлен'
ENDPOINT_NO_ANSWER = 'не проверено'

STACK_UNCHECKED_NOTE = (
    "⚠️ Состояние служб не проверено ({n} из {total}): systemctl ответил про "
    "канал, а не про службы — «{why}». Это пробел, а не диагноз службам: "
    "чинить доступ к systemd, а не перезапускать панель")

# Общий закон серии: признание НЕ имеет права называть диагноз, против
# которого оно предупреждает. Прежний текст «Это НЕ «порт не отвечает»» делал
# непроверяемым сам контроль «в строке эндпоинта нет «не отвечает»» — он падал
# на тексте признания, а не на подмене. Класс заперт сторожем
# TestNotesDoNotQuoteDiagnoses (tests/test_panels.py).
ENDPOINT_UNCHECKED_NOTE = (
    "⚠️ Веб-интерфейс :{port} не проверен ({n} из {total}): curl не выполнен — "
    "«{why}». Это пробел, а не диагноз порту: без curl проверка невозможна")


def parse_marker_sections(out):
    """Разобрать stdout с маркерами '@метка' в {метка: [непустые строки]}.

    Маркеры нужны потому, что вывод нескольких команд в один поток неразличим:
    без них не понять, где кончается ответ одной службы и начинается другой.
    Метка заводится printf'ом НАМЕРЕННО — это единственный способ сохранить
    структуру, не раздувая число SSH-запросов.
    """
    sections = {}
    key = None
    for line in (out or '').splitlines():
        if line.startswith('@'):
            key = line[1:].strip()
            sections.setdefault(key, [])
            continue
        if key is not None and line.strip():
            sections[key].append(line.strip())
    return sections


def _first_line(text):
    return next((ln.strip() for ln in (text or '').splitlines()
                 if ln.strip()), '')[:200]


def parse_stack_unit_state(body):
    """Статус одной службы по телу её маркерной секции (форма 1.32.27).

    Тело цикла — строки между маркерами: статус и 'rc=N'. «Юнита нет» и
    «стоит, но остановлена» stdout-ом неразличимы: на живом systemd пара
    несуществующей и остановленной службы даёт побайтово равный 'inactive',
    различие несёт только rc (4 против 3; оракул — systemctl show
    -p LoadState). Прежний код бросал rc: у цикла он принадлежит последней
    команде. Поэтому здесь:
      rc=4 при наличии статуса -> «не установлен»;
      rc=0/3 при наличии статуса -> сам статус (active / inactive / failed);
      статуса нет (bus dead: тело состоит только из 'rc=1') -> None, то есть
        «не проверено», а не выдуманное «не установлен»;
      rc-строки нет вовсе (ответ прежней формы) -> прежний статус без изменений.
    """
    rc = None
    status = ''
    for line in body:
        s = line.strip()
        if s.startswith('rc=') and s[3:].isdigit():
            rc = int(s[3:])
        elif s and not status:
            status = s
    if not status:
        return None
    if rc == 4:
        return STACK_UNIT_ABSENT
    return status


def panel_stack_view(out, err):
    """(строка служб, признание|None) по маркерному ответу `is-active`.

    Различение — по КАНАЛУ и по КОДУ ВОЗВРАТА (1.32.27). Сообщение про bus
    локализуется так же, как вывод dpkg (урок 1.28.0), поэтому текст им
    не признак: статуса в теле нет (bus dead даёт только 'rc=N') — это
    «не проверено». Статус есть — это ответ системы; rc=4 при статусе —
    «не установлен» (см. parse_stack_unit_state).
    """
    sections = parse_marker_sections(out)
    why = _first_line(err)
    parts, missing = [], 0
    for unit in PANEL_STACK_UNITS:
        body = sections.get(unit) or []
        state = parse_stack_unit_state(body)
        if state is None:
            parts.append(f'{unit}: {STACK_NO_ANSWER}')
            missing += 1
        else:
            parts.append(f'{unit}: {state}')
    note = None
    if missing:
        note = STACK_UNCHECKED_NOTE.format(
            n=missing, total=len(PANEL_STACK_UNITS),
            why=why or 'systemctl вернул пустой вывод')
    return ' / '.join(parts), note


def panel_endpoint_view(out, err, port=FASTPANEL_PORT):
    """({схема: ответ}, признание|None) по маркерному curl-дуэту.

    Замер живьём (настоящий curl и настоящий http.server на 127.0.0.1):

        живой порт          -> '@https\\nrc=0 code=200'
        порт закрыт         -> 'rc=7 code=000'      — ОТВЕТ (порт не слушает)
        http-порт под https -> 'rc=35 code=000'     — порт СЛУШАЕТ, но не TLS
        бинарника curl нет  -> 'rc=127 code=…: command not found' — ПРОБЕЛ

    Прежний `curl … 2>/dev/null` на последней строке давал пустоту и в отчёте
    звучало «не отвечает»: оператор шёл перезапускать панель вместо того, чтобы
    поставить curl. Поэтому rc=127 и отсутствие секции — пробел, а всё
    остальное — ответ системы.
    """
    sections = parse_marker_sections(out)
    answers, missing = {}, 0
    why = _first_line(err)
    for scheme in PANEL_SCHEMES:
        body = sections.get(scheme) or []
        if not body:
            answers[scheme] = ENDPOINT_NO_ANSWER
            missing += 1
            why = why or 'curl не ответил'
            continue
        head = body[0]
        rc_m = re.search(r'rc=(\d+)', head)
        # `.*$`, а НЕ `\S*`: HTTP-код идёт без пробелов, но на
        # НЕвыполненном curl в это поле попадает ответ системы целиком, а он
        # через пробелы. Замер живьём (отсутствующий бинарник, настоящий
        # /bin/bash):
        #   'rc=127 code=/bin/bash: line 1: curl: command not found'
        #     \S*  -> '/bin/bash:'                    (огрызок)
        #     .*   -> '/bin/bash: line 1: curl: command not found'
        # Признание, обрезанное до первого слова, ничего оператору не говорит:
        # та же болезнь (диагноз системы потерян по дороге в отчёт), против
        # которой написан весь слайс.
        code_m = re.search(r'code=(.*)$', head)
        rc = int(rc_m.group(1)) if rc_m else None
        code = (code_m.group(1) if code_m else '').strip()
        if rc == 127:
            answers[scheme] = ENDPOINT_NO_ANSWER
            missing += 1
            why = _first_line(code) or why or 'curl не выполнен'
        elif rc == 0:
            answers[scheme] = code or 'rc=0 без HTTP-кода'
        elif rc in CURL_RC_ANSWER:
            answers[scheme] = CURL_RC_ANSWER[rc]
        elif rc is None:
            answers[scheme] = ENDPOINT_NO_ANSWER
            missing += 1
            why = why or head
        else:
            answers[scheme] = f'код curl {rc}' + (f' ({code})' if code else '')
    note = None
    if missing:
        note = ENDPOINT_UNCHECKED_NOTE.format(
            port=port, n=missing, total=len(PANEL_SCHEMES),
            why=why or 'менеджер не ответил')
    return answers, note


def _stack_probe_cmd():
    """Одна SSH-команда, спрашивающая все службы стека с маркерами."""
    names = ' '.join(q(unit) for unit in PANEL_STACK_UNITS)
    return ('for s in %s; do printf "@%%s\\n" "$s"; '
            'LC_ALL=C systemctl is-active "$s"; '
            'printf "rc=%%s\n" "$?"; done' % names)


def _endpoint_probe_cmd(port=FASTPANEL_PORT, schemes=PANEL_SCHEMES):
    """Одна SSH-команда, меряющая HTTPS и HTTP с сохранением rc каждого."""
    names = ' '.join(q(s) for s in schemes)
    return ('for p in %s; do printf "@%%s\\n" "$p"; '
            'v=$(curl -sk -m 5 -o /dev/null -w "%%{http_code}" '
            '"$p://127.0.0.1:%d/" 2>&1); echo "rc=$? code=$v"; done'
            % (names, port))


def fastpanel_status(checker):
    """Состояние панели, её nginx/php-fpm и доступность веб-интерфейса."""
    lines = ["=== СОСТОЯНИЕ ПАНЕЛИ FASTPANEL ==="]

    unit, unchecked = fastpanel_unit_info(checker)
    if unit:
        out, err, _ = checker.run(f'systemctl is-active {q(unit)} 2>&1')
        # stdout и stderr разделены намеренно: у остановленной службы stdout
        # = 'inactive' (ответ системы), а при мёртвом bus stdout пуст, а текст
        # живёт в stderr (замер) — 'unknown' смешивал эти два случая.
        status = out.strip() or f'не проверено ({_first_line(err) or "пустой ответ"})'
        lines.append(f"Служба панели {unit}: {status}")
    elif unchecked:
        # Тот же закон, что в 1.19–1.27: «не проверено» не имеет права
        # печататься как «не найдена». Здесь это ещё и дежурный ответ на
        # любом хосте без systemd (контейнер, chroot, сломанный bus).
        lines.append(unchecked)
    else:
        lines.append("⚠️ Служба панели не найдена")

    out, err, _ = checker.run(_stack_probe_cmd())
    stack, stack_note = panel_stack_view(out, err)
    lines.append(" / ".join(PANEL_STACK_UNITS) + ": " + stack)
    if stack_note:
        lines.append(stack_note)

    # Панель FastPanel слушает 8888 (или 4444 в старых сборках) — проверяем локально.
    out, err, _ = checker.run(_endpoint_probe_cmd())
    answers, endpoint_note = panel_endpoint_view(out, err)
    lines.append(f"Веб-интерфейс :{FASTPANEL_PORT} (https/http): "
                 + ' / '.join(f'{s}={answers[s]}' for s in PANEL_SCHEMES))
    if endpoint_note:
        lines.append(endpoint_note)

    # `| tail -3` уехал на python: пайп забирал себе код возврата nginx -t
    # (он отдаёт rc=1 при битом конфиге — tail доволен всегда).
    out, _, _ = checker.run('LC_ALL=C nginx -t 2>&1')
    shown = '\n'.join(out.strip().splitlines()[-3:])
    lines.append(f"Синтаксис nginx: {shown or 'нет ответа'}")
    return "\n".join(lines)


def php_fpm_units(checker):
    """Установленные службы php-fpm (FastPanel ставит версии вида php8.2-fpm).

    Список парсится в Python, а не awk'ом внутри `$(...)`: вложенные кавычки
    в такой команде раскрываются непредсказуемо (awk ломался на `$1`).
    """
    out, _, _ = checker.run(
        'systemctl list-units --type=service --all --no-legend --no-pager '
        "'*php*-fpm*' 2>/dev/null"
    )
    units = []
    for line in out.splitlines():
        parts = line.split()
        if parts and parts[0].endswith('.service'):
            name = parts[0][:-len('.service')]
            if 'php' in name and 'fpm' in name and name not in units:
                units.append(name)
    return units


def fastpanel_restart_web(checker):
    """Перезапуск веб-стека, которым управляет панель (nginx + все php-fpm)."""
    lines = ["=== ПЕРЕЗАПУСК WEB-СТЕКА (nginx + php-fpm) ==="]
    out, _, _ = checker.run('nginx -t 2>&1 | tail -2')
    if 'ok' not in out.lower() and 'successful' not in out.lower():
        lines.append(f"❌ nginx -t не пройден, перезапуск не выполнен: "
                     f"{out.strip() or 'нет вывода'}")
        return "\n".join(lines)
    lines.append("✅ nginx -t пройден")

    out, err, rc = checker.run('systemctl restart nginx 2>&1')
    lines.append("✅ nginx перезапущен" if rc == 0
                 else f"❌ nginx: {err.strip() or out.strip()}")

    units = php_fpm_units(checker)
    if not units:
        lines.append("⚠️ Службы php*-fpm не найдены")
        return "\n".join(lines)

    done = []
    for unit in units:
        o, e, r = checker.run(f'systemctl restart {q(unit)} 2>&1')
        if r == 0:
            done.append(unit)
        else:
            lines.append(f"❌ {unit}: {(e or o).strip()}")
    if done:
        lines.append("✅ php-fpm перезапущен: " + ", ".join(done))
    return "\n".join(lines)


# ==================== ISPmanager: ДИАГНОСТИКА «ПАНЕЛЬ НЕ ОТКРЫВАЕТСЯ» ====
# Самое частое обращение по ISPmanager: веб-интерфейс на :1500 молчит, либо
# «Access to the panel is blocked by the administrator», либо слетела лицензия
# после переустановки/смены IP. Пути логов и команды — из документации
# ispmanager (knowledge-base «Useful commands for ispmanager 6»):
#   core ispmgr -V          — версия
#   licctl info|fetch       — лицензия
#   mgrctl -m ispmgr -u/-l  — разблокировка/блокировка
#   var/ispmgr.log, core.log, pkg.log — логи модуля, ядра и установщика
ISP_LOG_PATHS = [
    '/usr/local/mgr5/var/ispmgr.log',
    '/usr/local/mgr5/var/core.log',
    '/usr/local/mgr5/var/pkg.log',
]
ISP_PANEL_PORT = 1500


def ispmanager_logs_report(checker, tail=40):
    """Хвосты логов панели (пути — константы модуля, q() для защитного цитирования).

    Прежний вид:

        out, _, _ = checker.run(f'test -f {q(path)} && echo yes')
        if out.strip() != 'yes':
            continue
        ...
    if not found:
        lines.append("⚠️ Логи панели не найдены по путям: ...")

    Код возврата там ВЫБРОШЕН (out, _, _), а решало слово «yes». Замер живьём:
    при непроходимом каталоге форма даёт ровно то же, что при «файла нет»
    (out='' rc=1 err=''), и отчёт печатал «Логи панели не найдены» там, где
    логи лежат на месте — оператор искал причину в панели, а не в правах.
    Теперь три состояния: хвост читается только там, где файл найден; «не
    найдены» говорится только по доказанному списку; нечитаемое называется
    «не проверено» с причиной из stderr.
    """
    lines = ["=== ЛОГИ ПАНЕЛИ ISPmanager ==="]
    presence_cache = {}
    missing = []
    unchecked = []
    found = False
    for path in ISP_LOG_PATHS:
        info = file_presence(checker, path, presence_cache)
        if info['state'] == 'found':
            found = True
            out, _, _ = checker.run(f'tail -n {int(tail)} {q(path)} 2>&1')
            lines.append(f"\n--- {path} (последние {tail} строк) ---")
            lines.append(out.strip() or "(файл пуст)")
        elif info['state'] == 'absent':
            missing.append(path)
        else:
            unchecked.append((path, info['note']))
    if missing:
        lines.append("⚠️ Логи панели не найдены по путям: "
                     + ", ".join(missing))
    for path, note in unchecked:
        # Молчать об этом нельзя: пустое наблюдение преждний код читал как
        # «файла нет», и ложь уезжала в отчёт.
        lines.append(f"⚠️ {path}: " + (note or 'состояние не проверено'))
    if not found and not missing and not unchecked:
        lines.append("⚠️ Логи панели не найдены по путям: "
                     + ", ".join(ISP_LOG_PATHS))
    return "\n".join(lines)

def ispmanager_panel_diag(checker):
    """Почему панель не открывается: процессы, порт, API, лицензия, лог."""
    lines = ["=== ДИАГНОСТИКА ПАНЕЛИ ISPmanager ==="]

    out, _, _ = checker.run('/usr/local/mgr5/bin/core ispmgr -V 2>&1')
    version = out.strip()
    lines.append(f"Версия панели: {version or 'не определена (файл core повреждён?)'}")

    proc_cache = {}
    core_proc = process_probe(checker, ISP_CORE_BIN, proc_cache)
    ihttpd_proc = process_probe(checker, ISP_IHTTPD_BIN,
                                proc_cache)
    lines.append(f"Процесс core: {process_state_label(core_proc)}")
    lines.append(f"Веб-сервер панели ihttpd: {process_state_label(ihttpd_proc)}")
    for proc in (core_proc, ihttpd_proc):
        if proc['state'] == 'absent' and proc['note']:
            lines.append("ℹ️ " + proc['note'])

    out, _, _ = checker.run(
        "curl -sk -m 5 -o /dev/null -w '%{http_code}' "
        f"https://127.0.0.1:{ISP_PANEL_PORT}/ 2>/dev/null")
    code = out.strip() or '000'
    lines.append(f"Веб-интерфейс :{ISP_PANEL_PORT} (https с localhost): {code}")
    if code in ('000', ''):
        lines.append("⚠️ Порт панели не отвечает — панель недоступна даже локально.")

    out, _, rc = checker.run(
        '/usr/local/mgr5/sbin/mgrctl -m ispmgr sysinfo 2>&1 | head -3')
    probe = (out or '').strip()
    low = probe.lower()
    # Пустой вывод = mgrctl не ответил (ядро мертво или сокет недоступен),
    # а rc при этом бывает нулевой — считать такое «API отвечает» нельзя.
    if rc != 0 or not probe or 'error' in low or 'block' in low:
        lines.append(f"⚠️ Ответ API панели: {probe or 'молчит'}")
        lines.append("   Если есть «Access to the panel is blocked by the")
        lines.append("   administrator» — панель заблокирована (часто это идёт")
        lines.append("   штатное обновление): см. «Разблокировать панель».")
    else:
        lines.append("✅ API панели отвечает")

    out, _, _ = checker.run('/usr/local/mgr5/sbin/licctl info ispmgr 2>&1 | head -10')
    lic = out.strip()
    lines.append("\nЛицензия (licctl info ispmgr):")
    lines.append(lic or "⚠️ licctl молчит — попробуйте «Лицензия: обновить»")
    low = lic.lower()
    if 'not found' in low or 'invalid' in low or 'expired' in low:
        lines.append("⚠️ Лицензия не активна: панель работает ещё несколько дней, "
                     "затем откажет полностью. Проверьте IP панели в биллинге — "
                     "лицензия привязана к IP (licctl fetch перетянет под текущий).")

    out, _, _ = checker.run(
        f'tail -n 15 {q(ISP_LOG_PATHS[0])} 2>/dev/null')
    if out.strip():
        lines.append(f"\n--- {ISP_LOG_PATHS[0]} (последние 15 строк) ---")
        lines.append(out.strip())
    return "\n".join(lines)


def ispmanager_unlock(checker):
    """mgrctl -u: снять блокировку модуля ispmgr и ядра (доки ispmanager)."""
    lines = ["=== РАЗБЛОКИРОВАНИЕ ПАНЕЛИ ISPmanager ==="]
    out, err, rc = checker.run('/usr/local/mgr5/sbin/mgrctl -m ispmgr -u 2>&1')
    if rc != 0:
        lines.append(f"❌ модуль ispmgr (rc={rc}): {err.strip() or out.strip()}")
    else:
        lines.append("✅ Модуль ispmgr разблокирован")
    out2, err2, rc2 = checker.run('/usr/local/mgr5/sbin/mgrctl -m core -u 2>&1')
    if rc2 != 0:
        lines.append(f"❌ ядро core (rc={rc2}): {err2.strip() or out2.strip()}")
    else:
        lines.append("✅ Ядро панели разблокировано")
    if rc == 0 or rc2 == 0:
        lines.append("⚠️ Блокировка бывает штатной во время pkgupgrade: если")
        lines.append("   обновление идёт прямо сейчас — дождитесь его окончания.")
    return "\n".join(lines)


def ispmanager_license_refresh(checker):
    """licctl fetch ispmgr: перетянуть лицензию под текущий IP сервера."""
    lines = ["=== ОБНОВЛЕНИЕ ЛИЦЕНЗИИ ISPmanager ==="]
    out, err, rc = checker.run('/usr/local/mgr5/sbin/licctl fetch ispmgr 2>&1')
    if rc == 0:
        lines.append("✅ Запрос на сервер лицензий выполнен")
    else:
        lines.append(f"❌ Ошибка (rc={rc}): {err.strip() or out.strip()}")
    out2, _, _ = checker.run('/usr/local/mgr5/sbin/licctl info ispmgr 2>&1 | head -10')
    lines.append("\nСостояние лицензии теперь:")
    lines.append(out2.strip() or "(licctl info вернул пусто)")
    return "\n".join(lines)


# ==================== ISPmanager: ЛИЦЕНЗИЯ (ТОЛЬКО ЧТЕНИЕ) ================
# Отдельный пункт вместо запуска всей диагностики :1500, когда оператора
# интересует ровно один вопрос — «жива ли лицензия» (тот же принцип, по которому
# SSL-сроки вынесены из отчёта о доступности сайтов). Формат licctl info — из
# документации ISPsystem (knowledge-base «Where to find the panel version and
# license ID»): строки Name / Expire / Update end. Дни до окончания считаем НА
# СЕРВЕРЕ (date -d), а не на машине оператора: их часы расходятся (тот же приём,
# что в SSL-пробе CERT=). Команда через echo, а не printf, — в ней нет \n-escape.
LICCTL = '/usr/local/mgr5/sbin/licctl'
LICENSE_WARN_DAYS = 30
LICENSE_CHECK_CMD = (
    'LIC=$(' + LICCTL + ' info ispmgr 2>&1 | head -n 20); '
    '_d() { D=$(printf %s "$1" | tr -cd "0-9-"); [ -z "$D" ] && return; '
    'E=$(date -d "$D" +%s 2>/dev/null); [ -z "$E" ] && return; '
    'printf %s "$(( (E - $(date +%s)) / 86400 ))"; }; '
    'EXP=$(printf %s "$LIC" | sed -n "s/^[Ee]xpire:[[:space:]]*//p" | head -n 1); '
    'UPD=$(printf %s "$LIC" | sed -n "s/^[Uu]pdate[^:]*:[[:space:]]*//p" | head -n 1); '
    'echo "LIC_EXPIRE=$EXP"; echo "LIC_DAYS=$(_d "$EXP")"; '
    'echo "LIC_UPDATE=$UPD"; echo "LIC_UPDATE_DAYS=$(_d "$UPD")"; '
    'echo "---"; echo "$LIC"'
)


def parse_license_info(out):
    """Разбор вывода LICENSE_CHECK_CMD: служебные поля + сырой текст licctl.

    Служебные строки идут до разделителя '---', ниже — дословный вывод licctl.
    Дни — int либо None (пусто/не число: панель не дала даты или licctl не
    нашёлся). 'raw' — что показывать оператору как есть.
    """
    head, sep, body = (out or '').partition('\n---\n')
    fields = {}
    for line in head.splitlines():
        key, eq, value = line.partition('=')
        if eq:
            fields[key.strip()] = value.strip()

    def days(key):
        try:
            return int(fields.get(key, ''))
        except ValueError:
            return None

    return {'expire': fields.get('LIC_EXPIRE', ''),
            'days': days('LIC_DAYS'),
            'update': fields.get('LIC_UPDATE', ''),
            'update_days': days('LIC_UPDATE_DAYS'),
            'raw': (body if sep else (out or '')).strip()}


def license_status_line(days):
    """Строка-вердикт по остатку дней (None — дату определить не удалось)."""
    if days is None:
        return "❓ Дата окончания лицензии не определена"
    if days < 0:
        return f"❌ Лицензия истекла {-days} дн. назад"
    if days < LICENSE_WARN_DAYS:
        return f"⚠️ Лицензия истекает через {days} дн."
    return f"✅ Лицензия активна, осталось {days} дн."


def ispmanager_license_report(checker):
    """licctl info ispmgr + остаток дней (считаем на сервере)."""
    lines = ["=== ЛИЦЕНЗИЯ ISPmanager ==="]
    out, err, _rc = checker.run(LICENSE_CHECK_CMD)
    info = parse_license_info(out)
    raw = info['raw'] or (err or '').strip()
    if not raw:
        # licctl молчит: чаще это отсутствие интернета, а не мёртвая лицензия.
        # Вешать «лицензия умерла» по пустому выводу нельзя (грабля из диагностики).
        lines.append("⚠️ licctl info ispmgr не вернул ничего.")
        lines.append("   Чаще это отсутствие интернета на сервере, а не мёртвая")
        lines.append("   лицензия. Проверьте сеть, затем «Лицензия: обновить».")
        return "\n".join(lines)

    if 'command not found' in raw.lower() or 'no such file' in raw.lower():
        # Отдельная ветка: «licctl нет на машине» и «лицензия плохая» — разные
        # диагнозы. Команда собрана с 2>&1, поэтому сообщение shell
        # («licctl: command not found») приходит к нам в stdout и выглядело бы
        # как «состояние лицензии».
        lines.append("❌ licctl не найден на сервере — панель ISPmanager здесь,")
        lines.append("   похоже, не установлена (либо путь /usr/local/mgr5 другой).")
        lines.append(raw)
        return "\n".join(lines)

    lines.append(license_status_line(info['days']))
    if info['expire']:
        lines.append(f"   Окончание лицензии: {info['expire']}")
    if info['update']:
        upd = f"   Срок обновлений: {info['update']}"
        if info['update_days'] is not None:
            upd += (" (истёк)" if info['update_days'] < 0
                    else f" (осталось {info['update_days']} дн.)")
        lines.append(upd)
    if 'trial' in raw.lower():
        lines.append("   Тип: Trial — ограниченный срок, функциональность урезана")
    lines.append("")
    lines.append(raw)
    if info['days'] is None:
        # Две РАЗНЫЕ причины пустого остатка, и путать их нельзя:
        # даты нет вовсе (другая версия licctl, свой формат) либо дата есть,
        # но её не распознала серверная date (BusyBox/BSD: у неё нет -d).
        if info['expire']:
            lines.append(f"\n⚠️ Дата окончания «{info['expire']}» получена, но")
            lines.append("   серверная date её не распознала (в BusyBox/BSD нет")
            lines.append("   ключа -d): срок смотрите в выводе licctl выше.")
        else:
            lines.append("\n⚠️ Строку «Expire» найти не удалось — смотрите")
            lines.append("   вывод выше: возможно, другой формат licctl.")
    elif info['days'] < LICENSE_WARN_DAYS:
        lines.append("\n→ Лицензия привязана к IP панели: после смены IP сервера")
        lines.append("   выполните «Лицензия: обновить (licctl fetch)».")
    return "\n".join(lines)


# ==================== ISPmanager: АКТИВАЦИЯ ЛИЦЕНЗИИ ПО КЛЮЧУ =============
# Синтаксис — официальный док ISPsystem «Activating a license with a key»:
#     /usr/local/mgr5/sbin/licctl fetch mgrName key
# Именно fetch с ключом. Формы «licctl activate ispmgr <ключ>» в официальной
# документации НЕТ (она встречается только в сторонних KB), поэтому в код она
# не бралась. Ключ одноразовый: повторно активировать им нельзя — нужен новый
# ключ в Client area (то же говорит док).
#
# Ключ — секрет, но официального способа передать его мимо argv у licctl НЕТ
# (в отличие от mgrctl, где есть -e 'param=$ENV', см. discovery.py). Мы убираем
# ключ из ОТЧЁТА (оператор видит «fetch ispmgr ***») и честно говорим, что на
# время работы процесса licctl он был виден в ps. Врать про «безопасный канал»
# там, где его нет, нельзя: одно выдуманное предупреждение обесценивает все
# остальные.
LICENSE_KEY_MASK = '***'


def license_key_policy(key):
    """Текст причины отказа либо None. Проверка ДО отправки — своя, а не панели.

    Пустой ключ отсекается обязательно: `licctl fetch ispmgr` БЕЗ ключа — это
    ДРУГАЯ операция (перетянуть лицензию на текущий IP). Отправить её вместо
    активации значит молча тронуть лицензию не тем действием.

    Переносы строк и управляющие символы означают, что в поле попал не ключ
    (обычно так вставляют кусок письма или пару команд). Команда у нас
    экранируется q(), поэтому инъекции здесь не было бы и без проверки, но
    licctl принял бы мусор как ключ и сжёг одноразовый ключ зря.
    """
    if key is None or not key.strip():
        return ('Ключ активации не задан. Без ключа licctl fetch перетягивает '
                'лицензию на текущий IP — для этого есть отдельный пункт '
                '«Обновить под IP (licctl fetch)».')
    cleaned = key.strip()
    if cleaned != key:
        key = cleaned          # поля ввода часто тянут пробелы по краям
    if any(ch.isspace() or ord(ch) < 32 for ch in key):
        return ('Ключ активации не должен содержать пробелов и переносов — '
                'похоже, вставлено не значение ключа. Скопируйте ключ целиком '
                'из письма или из Client area.')
    return None


def mask_license_key(text, key):
    """Убирает ключ из текста ответа: licctl может повторить его в сообщении."""
    text = text or ''
    return text.replace(key, LICENSE_KEY_MASK) if key else text


def ispmanager_license_activate(checker, key):
    """licctl fetch ispmgr <ключ> и ПЕРЕЧИТЫВАНИЕ licctl info.

    Код возврата licctl нам не доказательство: активация могла не состояться,
    а утилиты иногда выходят с нулём. Факт — только состояние лицензии после
    запроса, поэтому licctl info перечитывается всегда, и вердикт пишем по нему
    (тот же принцип, что с перечитыванием списка ящиков после операций).
    """
    lines = ["=== АКТИВАЦИЯ ЛИЦЕНЗИИ ISPmanager ПО КЛЮЧУ ==="]
    why = license_key_policy(key)
    if why:
        lines.append(f"⛔ {why}")
        lines.append("   Ни одна команда на сервер не отправлялась.")
        return "\n".join(lines)
    key = key.strip()

    cmd = f'{LICCTL} fetch ispmgr {q(key)} 2>&1'
    # Показываем команду с маской: её смысл (какая именно команда была) виден,
    # а ключ — нет, поэтому отчёт можно сохранить или переслать.
    lines.append(f"$ {LICCTL} fetch ispmgr {LICENSE_KEY_MASK} 2>&1")
    out, err, rc = checker.run(cmd)
    report = mask_license_key((out or '').strip() or (err or '').strip(), key)
    if rc != 0:
        lines.append(f"❌ Ошибка (rc={rc}): {report or 'без сообщения'}")
    elif report:
        lines.append(f"licctl: {report}")
    else:
        lines.append("✅ Запрос на сервер лицензий выполнен (licctl без вывода)")
    lines.append("")

    # ---------- подтверждение фактом: состояние лицензии после запроса ----------
    lines.append("Проверка после запроса (licctl info):")
    info_out, info_err, _ = checker.run(LICENSE_CHECK_CMD)
    info = parse_license_info(info_out)
    raw = info['raw'] or (info_err or '').strip()
    if not raw:
        lines.append("⚠️ licctl info после активации не вернул ничего — срок не")
        lines.append("   подтвердить. Проверьте сеть на сервере и «Проверить».")
        return "\n".join(lines)
    lines.append(license_status_line(info['days']))
    if info['expire']:
        lines.append(f"   Окончание лицензии: {info['expire']}")
    if raw:
        lines.append("")
        lines.append(mask_license_key(raw, key))

    # Вердикт — по ПЕРЕЧИТАННОМУ состоянию, и тут три разных случая, которые
    # нельзя сводить к двум: «срок есть и он в будущем», «срок есть и он в
    # прошлом» и «сервер не дал понятной даты». Третья ветка не имеет права
    # выглядеть как успех: licctl мог принять ключ и не изменить лицензию, а
    # непонятный формат вывода — не доказательство активации.
    if rc == 0:
        if info['days'] is None:
            lines.append("\n⚠️ Запрос прошёл без ошибки, но срок действия")
            lines.append("   лицензии после него не определить — активацию")
            lines.append("   подтвердить нельзя. Выполните «Проверить» и")
            lines.append("   смотрите вывод licctl выше.")
        elif info['days'] >= 0:
            lines.append("\n✅ Лицензия активна после запроса по ключу.")
        else:
            lines.append("\n⚠️ Запрос прошёл без ошибки, но лицензия НЕ активна")
            lines.append("   — ключ уже использован или IP не совпадает.")
            lines.append("   Перевыпустите ключ в Client area и повторите.")
    lines.append("")
    lines.append("ℹ️ Ключ активации одноразовый: для повторной активации")
    lines.append("   понадобится новый ключ (Client area → Generate a new key).")
    lines.append("⚠️ На время выполнения licctl ключ был виден в ps: у licctl нет")
    lines.append("   способа принять ключ из окружения (в отличие от mgrctl -e).")
    return "\n".join(lines)


# ==================== FASTPANEL: ДИАГНОСТИКА И СБРОС ПАРОЛЯ ==============
# По KB FASTPANEL (kb.fastpanel.direct/ru/troubleshoot/): 404 на :8888 чаще
# всего означает снятый менеджером пакетов пакет fastpanel2. Пароль fastuser
# меняется через mogwai chpasswd (docs.fastvps.ru FAQ).

PKG_UNCHECKED_NOTE = (
    "пакет fastpanel2 не проверен: «{why}». Это пробел, а не диагноз пакету: "
    "лечение — права/PATH на хосте, а не переустановка панели")


# Формы без пайпа: rc=127 (бинарника нет) и rc=2 (база/lock недоступны) при
# прежнем `dpkg -l 2>/dev/null | grep … | head -3` схлопывались в ту же
# пустоту, что и «пакета нет», а fastpanel_diag подписывал её «типичная
# причина 404 … apt install fastpanel2» — по этой строке решают про
# переустановку панели.
#
#  * `2>&1` вместо `2>/dev/null`: ответ системы — единственное, что объясняет
#    пробел;
#  * пайпа нет вообще: конвейер отдаёт rc последней команды (grep/head), а не
#    пакетному менеджеру (урок 1.28.0, закуплен в третий раз);
#  * шаблон в кавычках: без них shell раскрывает `fastpanel2*` в имена ФАЙЛОВ
#    из cwd и dpkg отвечает «no packages found matching /…/fastpanel2x» с
#    rc=0 — ложное «пакета нет» при УСТАНОВЛЕННОМ пакете (замер живьём);
#  * `LC_ALL=C`: в русской локали dpkg пишет тот же ответ по-русски при том же
#    rc (замер). Решение принимается по rc — он локализации не подлежит, а
#    C нужен, чтобы ЦИТАТА для оператора читалась одинаково на любом хосте;
#  * ограничение в 3 строки переехало с `| head -3` на python, иначе rc
#    достался бы head, а не менеджеру;
#  * фильтр по имени пакета ПЕРЕЕХАЛ СЛЕДОМ (1.30.0, поймано живым контролем):
#    прежнему коду он был нужен не только чтобы найти пакет, но и чтобы отсечь
#    табличную ЛЕГЕНДУ dpkg — 5 шапок вида 'Desired=Unknown/Install/…' и
#    '||/ Name Version Architecture Description' (замер: они идут ПЕРЕД
#    строками пакетов). Без фильтра отчёт печатал «✅ Пакет панели:
#    Desired=Unknown/…», то есть терял версию пакета — ради строки его и
#    читают. На python фильтр стоит столько же, сколько `grep -i`, но не стоит
#    кода возврата.
# Игла, а не решение: по ней берётся СТРОКА пакета для отчёта (см. выше), а
# вердикт выносится только по коду возврата.
PKG_NEEDLE = 'fastpanel2'
#
# rpm зовётся `rpm -q`, а НЕ `rpm -qa`: у `-qa` «нет совпадений» — это rc=0, и
# тогда пустой вывод означает сразу ДВА несводимых ответа («пакета нет» и
# «канал оборвался»). Различить их нельзя никаким маркером (текст сообщения
# «no packages matched fastpanel2» содержит само имя пакета и к тому же
# локализован), а значит по `-qa` вердикт «пакета нет» вынести невозможно и
# единственный честный выход — молчать всегда. `rpm -q` отвечает на шаблон
# rc=1, как dpkg, поэтому обе ветки получают ОДНУ таблицу состояний.
# (Поведение rpm на этом хосте НЕ замерено — rpm отсутствует; форма взята из
# документации и заперта тестами как решение, а не как замер.)
PKG_TOOLS = (
    ('dpkg', "LC_ALL=C dpkg -l 'fastpanel2*' 2>&1"),
    ('rpm', "LC_ALL=C rpm -q 'fastpanel2*' 2>&1"),
)


def _pkg_probe(tool, cmd, checker):
    """Один пакетный менеджер → (kind, строка, почему). kind: found|absent|unchecked.

    Таблица ЕДИНА для dpkg и rpm и решается кодом возврата, а не текстом
    (замер: ru-локаль меняет слова dpkg, не rc; сообщение rpm к тому же содержит
    само имя пакета, так что маркером быть не может вовсе):

        rc=127                      unchecked (бинарника нет: не «пакета нет»)
        rc=0 + строки с именем      found
        rc=0, вывод без имени       unchecked (не ответ на наш шаблон)
        rc=0, пустой вывод          unchecked (обрыв канала — НЕ «пакета нет»)
        rc=1                        absent («пакета нет» — ответ системы)
        rc=2/прочее                 unchecked (ошибка: lock, права, битая база)

    Развилки по инструменту нет именно потому, что `rpm` зовётся как `rpm -q`
    (см. PKG_TOOLS): он отвечает на «не установлен» rc=1, как dpkg. Прежний
    `rpm -qa` давал «нет совпадений» как rc=0 с ПУСТЫМ выводом — то же самое,
    что оборванный канал, и свести их к одному диагнозу было нельзя.
    """
    out, err, rc = checker.run(cmd)
    text_out = out or ''
    why = next((line.strip() for line in (err or text_out).splitlines()
                if line.strip()), '')[:200]
    nonempty = [line.strip() for line in text_out.splitlines() if line.strip()]
    # Строки ОТВЕТА, относящиеся к пакету (см. PKG_NEEDLE): тот же фильтр, что
    # раньше делал `grep -i fastpanel2`, но без пайпа (он стоил кода возврата).
    hits = [line for line in nonempty if PKG_NEEDLE in line.lower()][:3]

    if rc == 127:
        return 'unchecked', '', f'{tool} не выполнен: {why or "бинарника нет"}'
    if rc == 0:
        if hits:
            return 'found', '\n'.join(hits), ''
        if not nonempty:
            # Пустой ответ при «успехе»: у обоих менеджеров успех обязан
            # совпадением (иначе rc=1), поэтому это обрыв канала, а НЕ «пакета
            # нет». Именно эту ветку давал прежний `rpm -qa` под вопросом
            # «пакета нет» — единственный вид пустоты, который нельзя свести к
            # диагнозу, поэтому здесь всегда пробел.
            return 'unchecked', '', f'{tool} вернул успех с пустым выводом'
        # Вывод есть, а строк про пакет в нём нет: это не ответ на наш шаблон
        # (обрыв, чужой вывод). Выдать его за найденную панель — показать
        # оператору чужие строки как пакет, поэтому здесь пробел.
        return ('unchecked', '',
                f'{tool}: rc=0, но в выводе нет строк про {PKG_NEEDLE}')
    if rc == 1:
        return 'absent', '', ''
    return 'unchecked', '', f'{tool}: {why or f"код возврата {rc}"}'


def fastpanel_package_status_info(checker):
    """(строка пакета, состояние, признание): состояние — found|absent|unchecked.

    Прежний `fastpanel_package_status` возвращал строку или '', поэтому
    «пакета нет» (настоящая причина 404 из KB FastPanel) и «мы не смогли
    спросить» (нет dpkg, нет прав на базу, бинарник не выполнен) были одним
    значением. Здесь они разные, и consumer обязан назвать второе отдельно:
    лечения противоположные — переустанавливать пакет против чинить доступ.

    Второй инструмент зовётся ТОЛЬКО когда первый не вынес вердикта: dpkg
    уверенно сказал «пакета нет» на Debian-хосте — rpm там спрашивать нечего.
    """
    whys = []
    for tool, cmd in PKG_TOOLS:
        kind, pkg, why = _pkg_probe(tool, cmd, checker)
        if kind in ('found', 'absent'):
            return pkg, kind, ''
        if why:
            whys.append(why)
    return '', 'unchecked', PKG_UNCHECKED_NOTE.format(
        why='; '.join(whys) or 'менеджер пакетов не ответил')


def fastpanel_package_status(checker):
    """Строка пакета fastpanel2 (dpkg или rpm — ОС в парке разная) или ''.

    Пустая строка здесь значит и «пакета нет», и «мы не смогли проверить»:
    отчёту, которому важно различать (это именно «панель не открывается»),
    обязан звать fastpanel_package_status_info.
    """
    return fastpanel_package_status_info(checker)[0]


# ==================== Журнал, FQDN, состояние службы (1.31.0) ==============
#
# Замеры живьём (этот хост: journalctl и hostname есть, bus мёртв):
#
#   journalctl -u nginx -n 15 --no-pager 2>&1   -> rc=0, '-- No entries --'
#   journalctl -u networ-such-unit-xyz ...      -> rc=0, '-- No entries --'
#   hostname -f 2>/dev/null  (бинарника нет)    -> rc=127 + ПУСТО
#   hostname -f 2>&1         (бинарника нет)    -> rc=127 + 'command not found'
#
# Первая строка замера — главное ОГРАНИЧЕНИЕ, а не победа: journalctl не
# различает «записей нет», «юнита нет» и «bus мёртв» — на всех трёх он печатает
# '-- No entries --' при rc=0. Выдумывать различение, которого система не даёт,
# нельзя (закон серии), поэтому здесь честный ОДИН ответ: «записей нет» с
# цитатой системы. Различима ДРУГАЯ подмена, против которой и написан слайс:
# прежний `journalctl … 2>/dev/null` на rc=127 и на любой ошибке давал пустоту,
# а пустота в diag означала МОЛЧАНИЕ — строки журнала просто не было. Молчание
# в отчёте «панель не открывается» читается оператором как «проверили, чисто».
#
# LC_ALL=C здесь обязателен: '-- No entries --' локализуется, а разбор идёт по
# этой строке (текст как маркер допустим ТОЛЬКО при зафиксированной локали,
# иначе — урок 1.28.0 про ru-локаль вывод dpkg).
JOURNAL_NO_ENTRIES = '-- no entries --'

JOURNAL_UNCHECKED_NOTE = (
    "⚠️ Журнал {unit} не проверен: journalctl не ответил — «{why}». Это "
    "пробел, а не диагноз журналу: сначала бинарник и доступ, потом выводы о "
    "панели")

JOURNAL_EMPTY_ANSWER = (
    "ℹ️ Журнал {unit}: записей нет — ответ системы «{quote}»")

FQDN_UNCHECKED_NOTE = (
    "⚠️ FQDN не проверен (hostname -f): «{why}». Это пробел, а не диагноз "
    "имени: совет про hostnamectl был бы выдумкой")

# Коды возврата curl, которые означают «порту от нас ничего не дошло» — то есть
# имеют право назваться «не отвечает». 127 здесь нет НАМЕРЕННО: это «бинарника
# curl нет» — пробел, а не диагноз порту (решающий случай слайса).
CURL_RC_SILENT = (6, 7, 28)


def panel_journal_lines(out, err, rc, unit):
    """Строки отчёта о журнале службы: ТРИ состояния вместо прежних двух.

    Прежний код знал только «не пусто -> печатать»:

        out, _, _ = checker.run(f'journalctl -u {unit} -n 15 --no-pager'
                                ' 2>/dev/null')
        if out.strip():
            lines.append(...)

    Поэтому «журнал пуст», «journalctl не выполнен» (rc=127 — хост без
    journalctl) и «journalctl упал» (нет места на диске) сливались в ОТСУТСТВИЕ
    строки, то есть в «всё в порядке». Здесь:

        rc != 0                      -> признание с цитатой ответа
        rc == 0 + пустой вывод       -> признание (так journalctl не отвечает)
        rc == 0 + '-- No entries --' -> ответ системы: записей нет
        rc == 0 + строки             -> сами строки (найденное не теряется)
    """
    why = _first_line(err or out)
    if rc != 0:
        return [JOURNAL_UNCHECKED_NOTE.format(
            unit=unit, why=why or f'код возврата {rc}')]
    body = [ln.strip() for ln in (out or '').splitlines() if ln.strip()]
    if not body:
        return [JOURNAL_UNCHECKED_NOTE.format(
            unit=unit, why='journalctl вернул успех с пустым выводом')]
    if len(body) == 1 and body[0].lower() == JOURNAL_NO_ENTRIES:
        return [JOURNAL_EMPTY_ANSWER.format(unit=unit, quote=body[0])]
    return [f'--- Журнал {unit} (последние 15 строк) ---'] + body


def panel_fqdn_lines(out, err, rc):
    """Строки отчёта про FQDN: три состояния вместо прежних двух.

    Прежний `hostname -f 2>/dev/null` при отсутствующем hostname давал rc=127 и
    пустоту, а пустота означала «молчать»: оператор не узнавал, что имя вообще
    не посмотрели — и что совета про hostnamectl нет не потому, что имя в
    порядке, а потому что проверять было нечем.
    """
    if rc != 0:
        return [FQDN_UNCHECKED_NOTE.format(
            why=_first_line(err or out) or f'код возврата {rc}')]
    fqdn = _first_line(out)
    if not fqdn:
        return [FQDN_UNCHECKED_NOTE.format(
            why='hostname -f ответил пусто при rc=0')]
    if '.' in fqdn:
        return []
    return [f"\n⚠️ hostname «{fqdn}» без точки — ProFTPD и выпуск",
            "   сертификатов могут ругаться. Лечение:",
            "   hostnamectl hostname www.example.com"]


def panel_service_state_lines(out, err, rc, unit):
    """Строка состояния службы панели: ответ системы против пробела.

    Прежняя форма `out.strip() or 'unknown'` с иконкой ❌ печатала «unknown» и
    когда служба реально остановлена (stdout='inactive', rc=3 — ОТВЕТ), и когда
    systemctl не ответил ничего (мёртвый bus: stdout пуст, текст в stderr —
    ПРОБЕЛ). Первое — диагноз, второе признанием обязано назваться; 'unknown'
    с ❌ стирал разницу, и оператор шёл перезапускать панель там, где надо
    смотреть systemd.
    """
    state = _first_line(out)
    if state:
        icon = '✅' if state == 'active' else '❌'
        return [f'{icon} Служба {unit}: {state}']
    why = _first_line(err or out)
    return [f'⚠️ Служба {unit}: не проверено — '
            f'«{why or f"пустой ответ systemctl (rc={rc})"}»']


def panel_endpoint_rcs(out):
    """{схема: код возврата curl} по маркерному ответу дуэта.

    Нужны именно коды, а не тексты: решение «имеет ли право прозвучать «порт
    не отвечает»» обязано опираться на rc. Формулировка как признак не
    годится — она локализуется (урок 1.28.0).
    """
    rcs = {}
    for scheme, body in parse_marker_sections(out).items():
        m = re.search(r'rc=(\d+)', body[0]) if body else None
        rcs[scheme] = int(m.group(1)) if m else None
    return rcs


def fastpanel_diag(checker):
    """Панель не открывается / 404: юнит, journal, пакет, порт, лог, hostname."""
    lines = ["=== ДИАГНОСТИКА ПАНЕЛИ FASTPANEL ==="]

    unit, unchecked = fastpanel_unit_info(checker)
    if unit:
        out, err, rc = checker.run(f'systemctl is-active {q(unit)} 2>&1')
        lines.extend(panel_service_state_lines(out, err, rc, unit))
        out, err, rc = checker.run(
            f'LC_ALL=C journalctl -u {q(unit)} -n 15 --no-pager 2>&1')
        lines.extend(panel_journal_lines(out, err, rc, unit))
    elif unchecked:
        # «Панель не открывается» — самый ответственный отчёт серии: по нему
        # оператор решает, переустанавливать ли панель. Прежняя строка
        # «Служба панели не найдена» на хосте без systemd (контейнер, chroot,
        # мёртвый bus) была ложью ВСЕГДА, потому что `2>/dev/null | head -1`
        # не умеет отвечать «не смогли посмотреть» в принципе.
        # Иконка ❌ сюда НЕ ставится: само признание уже помечено ⚠️, а «❌ ⚠️»
        # читается как две противоречащие метки — диагноз и пробел одновременно
        # (дефект, который внёл прошлый слайс; заперт
        # test_unit_unchecked_has_no_error_icon).
        lines.append(unchecked)
    else:
        lines.append("❌ Служба панели не найдена (fastpanel2-engine / fastpanel)")

    # Три состояния, а не два (1.30.0). Прежняя plain-форма возвращала строку
    # или '', и на пустоте здесь всегда звучало «❌ Пакет НЕ найден — типичная
    # причина 404 … apt install fastpanel2», хотя ту же пустоту давали «dpkg не
    # выполнен» (rc=127 — хост без dpkg) и «нет прав на базу пакетов» (rc=2):
    # прежняя команда теряла и то, и другое, потому что
    # `2>/dev/null | grep | head` возвращал rc=0 и пустоту на всех состояниях
    # (замер живьём). По этой строке решают про переустановку панели.
    pkg, pkg_kind, pkg_note = fastpanel_package_status_info(checker)
    if pkg_kind == 'found':
        lines.append(f"\n✅ Пакет панели: {pkg}")
    elif pkg_kind == 'absent':
        # Честный ответ менеджера пакетов: это и есть настоящая причина 404
        # из KB FastPanel, поэтому совет вернуть пакет обязан остаться.
        lines.append("\n❌ Пакет fastpanel2 НЕ найден — типичная причина 404 на :8888:")
        lines.append("   его снимает менеджер пакетов при разрешении зависимостей.")
        lines.append("   Вернуть: apt install fastpanel2 (или yum install fastpanel2).")
    else:
        # Пробел обязан быть назван: «переустанавливать панель» и «починить
        # доступ к менеджеру пакетов» — противоположные действия.
        lines.append(f"\n⚠️ {pkg_note}")

    # Тот же протокол, что в fastpanel_status: одна SSH-команда, код возврата
    # каждой схемы сохранён явно. Прежняя форма глушила причину через
    # `2>/dev/null`, а пустоту читала как '000' — из-за чего «curl не
    # установлен», «порт закрыт» и обрыв канала давали ОДНУ строку «Порт 8888
    # не отвечает», и оператор перезапускал панель вместо того, чтобы поставить
    # curl.
    out, err, _ = checker.run(_endpoint_probe_cmd())
    answers, endpoint_note = panel_endpoint_view(out, err)
    lines.append(f"\nВеб-интерфейс :{FASTPANEL_PORT} (https/http): "
                 + ' / '.join(f'{sch}={answers[sch]}'
                              for sch in PANEL_SCHEMES))
    if endpoint_note:
        # Пробел назван: «перезапустить панель» и «поставить curl» —
        # противоположные действия.
        lines.append(endpoint_note)
    elif panel_endpoint_rcs(out).get('https') in CURL_RC_SILENT:
        # Найденный факт не теряется (закон серии): при честном отказе строка
        # «порт не отвечает» обязана остаться — это ответ системы, а не пробел.
        lines.append(f"⚠️ Порт {FASTPANEL_PORT} не отвечает — смотрите статус "
                     f"службы и журнал выше.")

    logs, log_gaps = find_fastpanel_logs_info(checker, limit=1)
    for path in logs[:1]:
        out, _, _ = checker.run(f'tail -n 20 {q(path)} 2>&1')
        lines.append(f"\n--- {path} (последние 20 строк) ---")
        lines.append(out.strip() or "(файл пуст)")
    if not logs and log_gaps:
        # Пустой список логов в отчёте «панель не открывается» оператор читает
        # как «логировать нечего»; закрытый каталог логов — другой ответ и
        # другое лечение (права), и здесь он обязан быть назван.
        lines.extend(log_gaps)

    # `2>&1`, а не `2>/dev/null`: на отсутствующем hostname прежняя форма
    # давала rc=127 и пустоту, а пустота означала «молчать» — оператор считал,
    # что FQDN в порядке (замер живьём).
    out, err, rc = checker.run('hostname -f 2>&1')
    lines.extend(panel_fqdn_lines(out, err, rc))
    return "\n".join(lines)


def fastpanel_reset_password(checker, new_password):
    """mogwai chpasswd: сброс пароля fastuser (доступен только под root)."""
    lines = ["=== СБРОС ПАРОЛЯ fastuser (FASTPANEL) ==="]
    if not new_password:
        lines.append("❌ Пароль не задан")
        return "\n".join(lines)
    if len(new_password) < 8:
        lines.append("❌ FASTPANEL требует пароль не короче 8 символов")
        return "\n".join(lines)
    out, err, rc = checker.run(
        f'mogwai chpasswd --username=fastuser --password={q(new_password)} 2>&1')
    if rc == 0:
        lines.append("✅ Пароль изменён (логин входа в панель: fastuser)")
    else:
        lines.append(f"❌ Не удалось (rc={rc}): {err.strip() or out.strip()}")
    lines.append("⚠️ Пароль передавался аргументом команды и был виден в ps:")
    lines.append("   при возможности смените его на постоянный через панель.")
    return "\n".join(lines)
