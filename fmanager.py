"""Файловый менеджер: навигация и операции с файлами/каталогами на сервере.

Работает через SFTP (paramiko) — команды не собираются в shell, что исключает
инъекции. Для обмена с локальной машиной — get/put.
"""
import os
import stat
import posixpath
from datetime import datetime

# Носитель резерва один на весь проект: create_backup_info различает «файла
# нет» и «источник не виден» и сам перечитывает созданный бэкап. Своя
# реализация «cp и поверим» здесь означала бы второй источник права на
# перезапись, который разъезжается с files.py и ssl_install.py.
from common import create_backup_info


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


# SSH_FX_NO_SUCH_FILE (2) — единственный код, дающий право сказать «нет».
# Прочие коды (PERMISSION_DENIED=3, CONNECTION_LOST=14, ...) и сетевые обрывы —
# это «не проверено»: молчаливое False здесь означало бы «цели нет», и rename
# перезаписал бы цель, которую мы не видели (тот же закон, что у file_presence
# в common.py: ложное «нет» дороже отказа).
_SSH_FX_NO_SUCH_FILE = 2


def checked_path(path):
    """Абсолютный путь без '.' и '..' — либо текст причины (операция снята).

    GUI собирает путь как `posixpath.join(каталог, имя_из_диалога)`, а имя
    оператор вводит с клавиатуры: «../../etc/passwd» склеивается в
    «/var/www/../../etc/passwd» и сервер честно разворачивает его в
    /etc/passwd. Оператор в этот момент видит окно «в каталоге /var/www» и
    ожидает файл там — правка «в текущем каталоге» ушла бы в другую ветку
    дерева (для каталога это ещё и рекурсивное удаление). Граница не от
    злоумышленника — свои права на сервер у оператора есть, — а от несогласия
    окна и дела.

    Нормализация сравнивает, а не переписывает: молча подставить нормальный
    путь значило бы сделать то, чего оператор не просил.
    """
    text = (path or '').strip()
    if not text.startswith('/'):
        return f"❌ Путь должен быть абсолютным: {path!r} — операция снята"
    parts = text.split('/')
    if '.' in parts[1:] or '..' in parts[1:]:
        return (f"❌ Путь содержит '.' или '..': {path} — операция снята, имя "
                "не должно переходить наверх (иначе «в текущем каталоге» "
                "развернётся в другую ветку дерева)")
    return None


def _stat_state(sftp, path):
    """True или False; прочий отказ — IOError наружу («не проверено»)."""
    try:
        sftp.stat(path)
        return True
    except IOError as e:
        code = e.args[0] if e.args else None
        if code == _SSH_FX_NO_SUCH_FILE:
            return False
        raise


def _exists(sftp, path):
    """True/False только по достоверному ответу; прочий отказ — исключение."""
    return _stat_state(sftp, path)


def make_dir(checker, path):
    veto = checked_path(path)
    if veto:
        return veto
    sftp = checker.client.open_sftp()
    try:
        sftp.mkdir(path)
    finally:
        sftp.close()
    return f"✅ Каталог создан: {path}"


def create_file(checker, path):
    """Создаёт ПУСТОЙ файл и не имеет права тронуть существующий.

    Прежняя форма открывала 'w': «Создать файл» поверх существующего означало
    обнулить его содержимое и получить «✅ Файл создан» (запись без чтения
    исходного состояния — тот же закон, что у write_remote_file для конфигов).

    Режим — 'wx', а не 'x': paramiko переводит 'x' в CREATE|EXCL БЕЗ бита
    WRITE (sftp_client._convert_flags), такое открытие сервер либо отклоняет
    (SSH_FX_BAD_FLAG — протокол требует READ и/или WRITE), либо даёт handle,
    в который write в принципе невозможен. 'wx' = WRITE+CREATE+TRUNC+EXCL:
    экзистенцию по-прежнему защищает EXCL — гонку между проверкой и открытием
    закрывает сервер, а не наши намерения.
    """
    veto = checked_path(path)
    if veto:
        return veto
    sftp = checker.client.open_sftp()
    try:
        try:
            if _exists(sftp, path):
                return f"❌ Файл уже существует: {path} — создание отменено, " \
                       "содержимое не тронуто"
        except IOError as e:
            return f"❌ существование {path} не проверено ({e}) — создание " \
                   "отменено"
        with sftp.open(path, 'wx') as f:
            f.write('')
    except IOError as e:
        # Гонка (_exists прошёл, файл появился в окне) или отказ сервера:
        # EXCL бьёт IOError'ем наружу — модуль обязан назвать беду сам, как
        # в остальных ветках, а не отдавать голый exception раннеру.
        text = str(e)
        if 'Failure' in text or 'exist' in text.lower():
            return f"❌ файл {path} появился между проверкой и созданием " \
                   "(занят гонкой) — создание отменено, содержимое не тронуто"
        return f"❌ не удалось создать {path}: {text[:200]}"
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
    veto = checked_path(path)
    if veto:
        # Для каталога это единственная защита от «rm -rf не туда»: диалог
        # показывает один каталог, а сервер разворачивает '..' в другой.
        return veto
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
    """Переименовывает и не затирает цель.

    SFTP-переименование в переименование на сервере может перезаписать
    существующую цель (posix-rename@openssh.com); прежняя форма рапортовала
    «✅ Переименовано» и в этом мире — проверка цели до команды.
    """
    veto = checked_path(old_path) or checked_path(new_path)
    if veto:
        return veto
    sftp = checker.client.open_sftp()
    try:
        try:
            if _exists(sftp, new_path):
                return f"❌ Цель уже существует: {new_path} — переименование " \
                       "отменено"
        except IOError as e:
            # Не «цели нет», а «мы не увидели цели»: rename по такому
            # признаку может стереть существующий файл. Отмена.
            return f"❌ цель {new_path} не проверена ({e}) — переименование " \
                   "отменено"
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


def _backup_for_overwrite(checker, remote_path):
    """Право перезаписать существующий файл: (текст отказа, None) или (None, путь резерва).

    Носитель — общий для проекта create_backup_info (тот же закон, что у
    массовой замены IP в files.py и у _backup_gate в ssl_install.py: право на
    destructive-операцию даёт записанный и перечитанный откат, а не намерение).
    Тип 'configs' — как у files.write_file: оператор ищет откат в одном месте,
    а не в четырёх, в зависимости от того, какой кнопкой он воспользовался.

    Три состояния носителя дают три разных ответа, и «резерв не нужен» среди
    них ровно одно:
      done      — бэкап записан и перечитан, перезапись разрешена;
      absent    — отсутствия источника ДОКАЗАНЫ списком каталога: но сюда мы
                  попали именно потому, что SFTP stat цель УВИДЕЛ. Значит это
                  не «писать нечего», а расхождение двух спросов (цель —
                  каталог, а не файл, или путь за время между спросами сменил
                  хозяина). Разрешить перезапись по такому расхождению — то же
                  «ложное нет», которое серия запрещает везде;
      unchecked — источника не видно (прав не хватило): «мы не спросили».
    Прочие (failed) — cp отказал или обещанный файл не появился.
    """
    info = create_backup_info(checker, remote_path, 'configs')
    state = info['state']
    if state == 'done':
        return None, info['path']
    why = info['note'] or state
    if state == 'absent':
        why = ('носитель резерва не видит здесь файла, хотя SFTP его видит '
               '(' + why + ')')
    elif state == 'unchecked':
        why = 'источник резерва не прочитан (' + why + ')'
    else:
        why = 'резерв не принялся (' + why + ')'
    return ('❌ цель %s существует, а резерв не создан: %s — загрузка отменена, '
            'на сервер не отправлено ничего' % (remote_path, why)), None


def upload_file(checker, local_path, remote_path):
    """Загружает файл; перезапись существовавшего — только по принятому резерву.

    Прежняя форма возвращала просто путь: «✅ ...» не отличалось от случая,
    где на сервере лежала другая версия файла и была стёрта. Один клик по
    «⤒ Загрузить» снимал предыдущую версию без средства откатиться.

    Отказ stat — это НЕ «цели нет». Прежний вид (без catch) бросал IOError
    наружу, и оператор видел «❌ Ошибка: [Errno 3] Permission denied» вместо
    того, что загрузка НЕ отправлена и почему (create_file и rename_path ту же
    вилку закрывают словами здесь же, в модуле, а не в раннере GUI).

    Порядок «резерв до put», а не «put с последующим извинением»: копия, снятая
    после затирания, это копия уже новых байтов.
    """
    veto = checked_path(remote_path)
    if veto:
        return veto
    sftp = checker.client.open_sftp()
    backup = None
    try:
        try:
            existed = _exists(sftp, remote_path)
        except IOError as e:
            # Тот же закон, что у rename_path: «не увидели цель» — это не
            # «цели нет», и путать их нельзя. Бросок наружу GUI показывал как
            # «❌ Ошибка: [Errno 3] Permission denied» без слова о том, что
            # загрузка НЕ отправлена; теперь это ответ модуля.
            return f"❌ цель {remote_path} не проверена ({e}) — загрузка " \
                   "отменена, на сервер не отправлено ничего"
        if existed:
            # Новый файл (цели нет достоверно) идёт мимо этой ветки: резервить
            # нечего, и прежний путь загрузки не меняется.
            veto, backup = _backup_for_overwrite(checker, remote_path)
            if veto:
                # Отказ резерва СНИМАЕТ операцию: put не отправлен, старый
                # файл на сервере не тронут.
                return veto
        sftp.put(local_path, remote_path)
    finally:
        sftp.close()
    if existed:
        return f"✅ Загружено (существовавший файл перезаписан, резерв: " \
               f"{backup}): {remote_path}"
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
