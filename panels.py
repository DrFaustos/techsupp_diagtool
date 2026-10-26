"""Управление панелями: ISPmanager (mgrctl) и FastPanel (systemd-юниты)."""
from common import q, create_backup, find_files_info


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


def ispmanager_kill_core(checker):
    lines = ["=== ПРИНУДИТЕЛЬНОЕ ЗАВЕРШЕНИЕ CORE ==="]
    checker.exec_command('killall core 2>&1')
    checker.exec_command('pkill -9 core 2>&1')
    checker.exec_command('sleep 2')
    out, _ = checker.exec_command('ps aux | grep core | grep -v grep')
    lines.append("✅ Процесс core завершён" if not out.strip() else "⚠️ Процесс core всё ещё работает")
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
    lines = ["=== ПРОВЕРКА CRON PATH ==="]
    out, _ = checker.exec_command('crontab -l 2>/dev/null | grep "^PATH="')
    lines.append(f"⚠️ Найдена переменная PATH в crontab:\n{out}" if out.strip() else "✅ Переменная PATH не найдена в crontab")
    return "\n".join(lines)


def ispmanager_fix_cron_path(checker):
    lines = ["=== ИСПРАВЛЕНИЕ CRON PATH ==="]
    # Сначала сохраняем текущий crontab, потом делаем бэкап файла.
    checker.exec_command('crontab -l > /tmp/crontab_current.txt 2>/dev/null')
    backup_path = create_backup(checker, '/tmp/crontab_current.txt', 'crontab')
    if backup_path:
        lines.append(f"✅ Резервная копия crontab создана: {backup_path}")
    else:
        lines.append("⚠️ Не удалось создать резервную копию crontab")

    out, err, rc = checker.run("crontab -l 2>/dev/null | sed 's/^PATH=/#PATH=/' | crontab - 2>&1")
    lines.append("✅ Переменная PATH закомментирована" if rc == 0 else f"❌ Ошибка (rc={rc}): {err.strip() or out.strip()}")
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
    "«{why}». Это НЕ «юнита нет»: ответьте на причину (права, systemd, PATH) и "
    "повторите, а не ставьте панель")


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


def fastpanel_status(checker):
    """Состояние панели, её nginx/php-fpm и доступность веб-интерфейса."""
    lines = ["=== СОСТОЯНИЕ ПАНЕЛИ FASTPANEL ==="]

    unit, unchecked = fastpanel_unit_info(checker)
    if unit:
        out, _, _ = checker.run(f'systemctl is-active {q(unit)} 2>&1')
        lines.append(f"Служба панели {unit}: {out.strip() or 'unknown'}")
    elif unchecked:
        # Тот же закон, что в 1.19–1.27: «не проверено» не имеет права
        # печататься как «не найдена». Здесь это ещё и дежурный ответ на
        # любом хосте без systemd (контейнер, chroot, сломанный bus).
        lines.append(unchecked)
    else:
        lines.append("⚠️ Служба панели не найдена")

    out, _, _ = checker.run(
        'systemctl is-active nginx 2>/dev/null; '
        'systemctl is-active php-fpm 2>/dev/null; '
        'systemctl is-active mysql 2>/dev/null || systemctl is-active mariadb 2>/dev/null'
    )
    lines.append("nginx / php-fpm / mysql(mariadb): " + (out.strip().replace("\n", " / ") or "unknown"))

    # Панель FastPanel слушает 8888 (или 4444 в старых сборках) — проверяем локально.
    out, _, _ = checker.run(
        "curl -sk -m 5 -o /dev/null -w '%{http_code}' https://127.0.0.1:8888/ 2>/dev/null; "
        "echo; curl -s -m 5 -o /dev/null -w '%{http_code}' http://127.0.0.1:8888/ 2>/dev/null"
    )
    codes = [c.strip() for c in out.split("\n") if c.strip()]
    lines.append(f"Веб-интерфейс :8888 (https/http коды): {' / '.join(codes) or 'не отвечает'}")

    out, _, _ = checker.run('nginx -t 2>&1 | tail -3')
    lines.append(f"Синтаксис nginx: {out.strip() or 'нет вывода'}")
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
    """Хвосты логов панели (пути — константы модуля, q() для защитного цитирования)."""
    lines = ["=== ЛОГИ ПАНЕЛИ ISPmanager ==="]
    found = False
    for path in ISP_LOG_PATHS:
        out, _, _ = checker.run(f'test -f {q(path)} && echo yes')
        if out.strip() != 'yes':
            continue
        found = True
        out, _, _ = checker.run(f'tail -n {int(tail)} {q(path)} 2>&1')
        lines.append(f"\n--- {path} (последние {tail} строк) ---")
        lines.append(out.strip() or "(файл пуст)")
    if not found:
        lines.append("⚠️ Логи панели не найдены по путям: " + ", ".join(ISP_LOG_PATHS))
    return "\n".join(lines)


def ispmanager_panel_diag(checker):
    """Почему панель не открывается: процессы, порт, API, лицензия, лог."""
    lines = ["=== ДИАГНОСТИКА ПАНЕЛИ ISPmanager ==="]

    out, _, _ = checker.run('/usr/local/mgr5/bin/core ispmgr -V 2>&1')
    version = out.strip()
    lines.append(f"Версия панели: {version or 'не определена (файл core повреждён?)'}")

    out, _, _ = checker.run('pgrep -f "/usr/local/mgr5/bin/core" >/dev/null && echo yes')
    core_up = out.strip() == 'yes'
    out, _, _ = checker.run('pgrep -f "/usr/local/mgr5/bin/ihttpd" >/dev/null && echo yes')
    ihttpd_up = out.strip() == 'yes'
    lines.append(f"Процесс core: {'✅ запущен' if core_up else '❌ не запущен'}")
    lines.append(f"Веб-сервер панели ihttpd: "
                 f"{'✅ запущен' if ihttpd_up else '❌ не запущен'}")

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

def fastpanel_package_status(checker):
    """Строка пакета fastpanel2 (dpkg или rpm — ОС в парке разная) или ''."""
    out, _, _ = checker.run(
        "dpkg -l 2>/dev/null | grep -i 'fastpanel2' | head -3")
    if out.strip():
        return out.strip()
    out, _, _ = checker.run('rpm -qa 2>/dev/null | grep -i fastpanel2 | head -3')
    return out.strip()


def fastpanel_diag(checker):
    """Панель не открывается / 404: юнит, journal, пакет, порт, лог, hostname."""
    lines = ["=== ДИАГНОСТИКА ПАНЕЛИ FASTPANEL ==="]

    unit, unchecked = fastpanel_unit_info(checker)
    if unit:
        out, _, _ = checker.run(f'systemctl is-active {q(unit)} 2>&1')
        status = out.strip() or 'unknown'
        icon = '✅' if status == 'active' else '❌'
        lines.append(f"{icon} Служба {unit}: {status}")
        out, _, _ = checker.run(
            f'journalctl -u {q(unit)} -n 15 --no-pager 2>/dev/null')
        if out.strip():
            lines.append(f"--- journal {unit} (последние 15 строк) ---")
            lines.append(out.strip())
    elif unchecked:
        # «Панель не открывается» — самый ответственный отчёт серии: по нему
        # оператор решает, переустанавливать ли панель. Прежняя строка
        # «Служба панели не найдена» на хосте без systemd (контейнер, chroot,
        # мёртвый bus) была ложью ВСЕГДА, потому что `2>/dev/null | head -1`
        # не умеет отвечать «не смогли посмотреть» в принципе.
        lines.append("❌ " + unchecked)
    else:
        lines.append("❌ Служба панели не найдена (fastpanel2-engine / fastpanel)")

    pkg = fastpanel_package_status(checker)
    if pkg:
        lines.append(f"\n✅ Пакет панели: {pkg}")
    else:
        lines.append("\n❌ Пакет fastpanel2 НЕ найден — типичная причина 404 на :8888:")
        lines.append("   его снимает менеджер пакетов при разрешении зависимостей.")
        lines.append("   Вернуть: apt install fastpanel2 (или yum install fastpanel2).")

    out, _, _ = checker.run(
        "curl -sk -m 5 -o /dev/null -w '%{http_code}' "
        "https://127.0.0.1:8888/ 2>/dev/null")
    code = out.strip() or '000'
    lines.append(f"\nВеб-интерфейс :8888 (https с localhost): {code}")
    if code in ('000', ''):
        lines.append("⚠️ Порт 8888 не отвечает — смотрите статус службы и journal выше.")

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

    out, _, _ = checker.run('hostname -f 2>/dev/null')
    host_f = out.strip()
    if host_f and '.' not in host_f:
        lines.append(f"\n⚠️ hostname «{host_f}» без точки — ProFTPD и выпуск")
        lines.append("   сертификатов могут ругаться. Лечение:")
        lines.append("   hostnamectl hostname www.example.com")
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
