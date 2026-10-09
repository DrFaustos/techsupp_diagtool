"""Управление панелями: ISPmanager (mgrctl) и FastPanel (systemd-юниты)."""
from common import q, create_backup


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


def fastpanel_unit(checker):
    """Первый установленный systemd-юнит панели (или None).

    `systemctl cat` спрашиваем вместо `is-active`: нам важно, что юнит
    существует, а не что он запущен (панель как раз могла упасть).
    """
    for unit in FASTPANEL_UNITS:
        out, _, _ = checker.run(f'systemctl cat {q(unit)} 2>/dev/null | head -1')
        if out.strip():
            return unit
    return None


def find_fastpanel_logs(checker, limit=10):
    """Существующие логи панели (glob'ы намеренно без q())."""
    found = []
    for pattern in FASTPANEL_LOGS:
        out, _, _ = checker.run(f'ls -1 {pattern} 2>/dev/null | head -{limit}')
        found.extend(f.strip() for f in out.splitlines() if f.strip())
    return found


def fastpanel_restart(checker):
    lines = ["=== ПЕРЕЗАПУСК ПАНЕЛИ FASTPANEL ==="]
    unit = fastpanel_unit(checker)
    if not unit:
        lines.append("❌ Служба панели не найдена (fastpanel2-engine / fastpanel)")
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
    logs = find_fastpanel_logs(checker)
    if not logs:
        lines.append("⚠️ Логи панели не найдены по путям: " + ", ".join(FASTPANEL_LOGS))
        return "\n".join(lines)

    for path in logs:
        out, _, _ = checker.run(f'tail -n 30 {q(path)} 2>&1')
        lines.append(f"\n--- {path} (последние 30 строк) ---")
        lines.append(out.strip() or "(файл пуст)")
    return "\n".join(lines)


def fastpanel_status(checker):
    """Состояние панели, её nginx/php-fpm и доступность веб-интерфейса."""
    lines = ["=== СОСТОЯНИЕ ПАНЕЛИ FASTPANEL ==="]

    unit = fastpanel_unit(checker)
    if unit:
        out, _, _ = checker.run(f'systemctl is-active {q(unit)} 2>&1')
        lines.append(f"Служба панели {unit}: {out.strip() or 'unknown'}")
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
