"""Общие конфигурации и вспомогательные функции диагностики."""
import os
import shlex
from datetime import datetime

# Единственный источник правды о версии. От неё зависят заголовок окна,
# CHANGELOG.md и тег релиза (тэг всегда v<__version__>).
__version__ = "1.5.0"

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


def find_files(checker, pattern, limit=20):
    """Находит файлы по паттерну и возвращает список с предупреждением об ограничении.

    ВНИМАНИЕ: pattern — это shell-glob (напр. '/var/log/nginx/*.log'),
    поэтому он НЕ экранируется через q() намеренно.
    """
    cmd = f"ls -1 {pattern} 2>/dev/null | head -{limit}"
    out, _, _ = checker.run(cmd)
    files = [f.strip() for f in out.split('\n') if f.strip()]
    if len(files) >= limit:
        files.append(f"⚠️ (показаны первые {limit} файлов)")
    return files


def find_file(checker, patterns):
    """Находит первый существующий файл из списка паттернов (glob, без q())."""
    for pattern in patterns:
        out, _, _ = checker.run(f"ls -1 {pattern} 2>/dev/null | head -1")
        if out.strip():
            return out.strip()
    return None


def read_file_content(checker, filepath):
    """Читает содержимое файла"""
    out, _, rc = checker.run(f'cat {q(filepath)} 2>/dev/null')
    if rc != 0:
        return None
    return out


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
