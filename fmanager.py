"""Файловый менеджер: навигация и операции с файлами/каталогами на сервере.

Работает через SFTP (paramiko) — команды не собираются в shell, что исключает
инъекции. Для обмена с локальной машиной — get/put.
"""
import os
import stat
import posixpath
from datetime import datetime


def _filemode(mode):
    try:
        return stat.filemode(mode)
    except Exception:
        return '?'


def list_dir(checker, path):
    """Возвращает список записей каталога.

    Каждая запись: name, is_dir, is_link, size, mode, mtime.
    Каталоги идут первыми, далее по алфавиту.
    """
    path = (path or '/').strip() or '/'
    sftp = checker.client.open_sftp()
    try:
        attrs = sftp.listdir_attr(path)
    finally:
        sftp.close()

    entries = []
    for a in attrs:
        entries.append({
            'name': a.filename,
            'is_dir': stat.S_ISDIR(a.st_mode or 0),
            'is_link': stat.S_ISLNK(a.st_mode or 0),
            'size': int(a.st_size or 0),
            'mode': _filemode(a.st_mode or 0),
            'mtime': int(a.st_mtime or 0),
        })
    entries.sort(key=lambda e: (not e['is_dir'], e['name'].lower()))
    return entries


def make_dir(checker, path):
    sftp = checker.client.open_sftp()
    try:
        sftp.mkdir(path)
    finally:
        sftp.close()
    return f"✅ Каталог создан: {path}"


def create_file(checker, path):
    sftp = checker.client.open_sftp()
    try:
        with sftp.open(path, 'w') as f:
            f.write('')
    finally:
        sftp.close()
    return f"✅ Файл создан: {path}"


def _rmtree(sftp, path):
    """Рекурсивное удаление каталога (только по явному подтверждению в GUI)."""
    for a in sftp.listdir_attr(path):
        child = posixpath.join(path, a.filename)
        if stat.S_ISDIR(a.st_mode or 0):
            _rmtree(sftp, child)
        else:
            sftp.remove(child)
    sftp.rmdir(path)


def delete_path(checker, path, is_dir=False):
    sftp = checker.client.open_sftp()
    try:
        if is_dir:
            _rmtree(sftp, path)
        else:
            sftp.remove(path)
    finally:
        sftp.close()
    return f"✅ Удалено: {path}"


def rename_path(checker, old_path, new_path):
    sftp = checker.client.open_sftp()
    try:
        sftp.rename(old_path, new_path)
    finally:
        sftp.close()
    return f"✅ Переименовано: {old_path} -> {new_path}"


def download_file(checker, remote_path, local_path):
    sftp = checker.client.open_sftp()
    try:
        sftp.get(remote_path, local_path)
    finally:
        sftp.close()
    return local_path


def upload_file(checker, local_path, remote_path):
    sftp = checker.client.open_sftp()
    try:
        sftp.put(local_path, remote_path)
    finally:
        sftp.close()
    return remote_path


_TEXT_EXT = ('.conf', '.cnf', '.ini', '.cfg', '.txt', '.log', '.json', '.yaml',
             '.yml', '.xml', '.html', '.htm', '.php', '.py', '.sh', '.service',
             '.env', '.htaccess', '.md', '.css', '.js', '.sql', '.rules', '.list')

_BINARY_EXT = ('.gz', '.tgz', '.bz2', '.xz', '.zip', '.tar', '.rar', '.7z',
               '.jpg', '.jpeg', '.png', '.gif', '.webp', '.ico', '.bmp', '.svgz',
               '.so', '.o', '.a', '.bin', '.exe', '.dll', '.pdf', '.mp4', '.mp3',
               '.avi', '.mov', '.deb', '.rpm', '.iso', '.db', '.sqlite',
               '.woff', '.woff2', '.ttf', '.eot', '.pyc', '.pyo', '.class',
               '.jar', '.war', '.vmdk', '.qcow2', '.img', '.swp',
               '.xls', '.xlsx', '.doc', '.docx', '.ppt', '.pptx', '.odt')


def is_text_file(name):
    """Эвристика по имени: можно ли открывать файл в текстовом редакторе.

    Порядок решений: дотфайлы -> бинарные расширения -> текстовые ->
    имя-домен (панели называют vhost'ы `sites-enabled/example.com`).
    Файл без расширения считается НЕ текстовым: в /usr/bin и /usr/sbin
    безрасширительные имена — это почти всегда ELF-бинарники.
    """
    base = os.path.basename(name or '').lower()
    if not base:
        return False
    if base.startswith('.'):
        return True  # .htaccess, .bashrc
    if '.' not in base:
        return False  # bash, mysqld
    ext = base[base.rindex('.'):]
    if ext in _BINARY_EXT:
        return False
    if ext in _TEXT_EXT:
        return True
    # Остаток — похожие на домен имена: example.com, site.ru.net
    return 2 <= len(ext) - 1 <= 8 and ext[1:].isalpha()


# ==================== ПОДГОТОВКА ЗАПИСЕЙ ДЛЯ ТАБЛИЦЫ ====================
_SIZE_UNITS = ('B', 'KB', 'MB', 'GB', 'TB')


def human_size(num):
    """Размер в человекочитаемом виде. Мусор на входе -> '?' (таблица не падает)."""
    try:
        n = float(num)
    except (TypeError, ValueError):
        return '?'
    if n < 0:
        return '?'
    for unit in _SIZE_UNITS:
        if n < 1024 or unit == _SIZE_UNITS[-1]:
            return f'{int(n)} {unit}' if unit == 'B' else f'{n:.1f} {unit}'
        n /= 1024


def format_time(ts):
    """Unix-время -> 'ГГГГ-ММ-ДД ЧЧ:ММ'. 0/None/битое значение -> пустая строка."""
    if not ts:
        return ''
    try:
        return datetime.fromtimestamp(int(ts)).strftime('%Y-%m-%d %H:%M')
    except (OverflowError, OSError, ValueError, TypeError):
        return ''


def format_entries(entries):
    """Записи list_dir -> строки для ttk.Treeview.

    Порядок колонок: (имя, тип, размер, права, изменён). Каталоги помечаются
    «/», symlink'и — «@»: оператор не спутает их с обычным файлом перед
    удалением (rm каталога рекурсивен).
    """
    rows = []
    for e in entries:
        name = e.get('name', '')
        if e.get('is_dir'):
            kind, label = 'папка', name + '/'
        elif e.get('is_link'):
            kind, label = 'ссылка', name + '@'
        else:
            kind, label = 'файл', name
        rows.append((label, kind, human_size(e.get('size', 0)),
                     e.get('mode', '?'), format_time(e.get('mtime'))))
    return rows
