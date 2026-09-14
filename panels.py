"""Управление панелью ISPmanager."""
from common import create_backup


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
