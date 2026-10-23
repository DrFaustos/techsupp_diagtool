"""Работа с файлами/конфигами, замена IP, перезапуск служб."""
import ipaddress
from datetime import datetime

from common import (BACKUP_SUBDIRS, q, ensure_backup_dir, create_backup,
                    write_remote_file, RF_TEXT, read_file_info,
                    find_files_info, FF_DIR_TEXT)


# ==================== РАБОТА С ФАЙЛАМИ (С БЭКАПАМИ) ====================
def write_file(checker, filepath, content):
    """Записывает содержимое в файл с созданием резервной копии (через SFTP)."""
    lines = []
    lines.append(f"=== СОХРАНЕНИЕ ФАЙЛА: {filepath} ===")

    backup_path = create_backup(checker, filepath, 'configs')
    if backup_path:
        lines.append(f"✅ Резервная копия создана: {backup_path}")
    else:
        lines.append("⚠️ Не удалось создать резервную копию файла")

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
        out, err = checker.exec_command(
            f'find {q(path)} -type f | head -{CONFIG_LIMIT}')
        files.extend(line.strip() for line in (out or '').splitlines()
                     if line.strip())
        low = (err or '').lower()
        why = next((l.strip() for l in (err or '').splitlines() if l.strip()),
                   '')[:160]
        if 'permission denied' in low:
            note = FF_DIR_TEXT['noperm'].format(path=path, why=why)
        elif 'no such file' in low:
            note = FF_DIR_TEXT['missing'].format(path=path, why=why)
        else:
            # Пустой вывод без ошибки: каталог прочитан, файлов нет — честный
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


def replace_ipv4(checker, old_ip, new_ip):
    """Замена старого IPv4 на новый во всех *.conf в /etc (как в ручной команде)."""
    lines = [f"=== ЗАМЕНА IPv4: {old_ip} -> {new_ip} ==="]
    if not (_valid_ipv4(old_ip) and _valid_ipv4(new_ip)):
        lines.append("❌ Некорректный IPv4-адрес — операция отменена.")
        return "\n".join(lines)
    # Экранируем точки, как в исходной команде: s#123\.123\.123\.123#...#g
    old_escaped = old_ip.replace('.', '\\.')
    new_escaped = new_ip.replace('.', '\\.')
    cmd = (
        f"find /etc -type f -name \"*.conf\" "
        f"-exec sed -i -e 's#{old_escaped}#{new_escaped}#g' '{{}}' \\;"
    )
    out, err, rc = checker.run(cmd)
    if rc != 0:
        lines.append(f"⚠️ Возможны ошибки (rc={rc}): {err.strip() or out.strip()}")
    lines.append("✅ IPv4 заменён во всех .conf-файлах в /etc.")
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

    old_ip/new_ip строго валидируются как IPv6 — это исключает инъекцию команд,
    поскольку в shell подставляются только проверенные [0-9a-fA-F:].
    """
    lines = [f"=== ЗАМЕНА IPv6: {old_ip} -> {new_ip} ==="]
    if not (_valid_ipv6(old_ip) and _valid_ipv6(new_ip)):
        lines.append("❌ Некорректный IPv6-адрес — операция отменена.")
        return "\n".join(lines)

    # Автобэкап /etc перед массовой заменой (сама команда замены не меняется)
    ensure_backup_dir(checker)
    ts = datetime.now().strftime('%Y%m%d_%H%M%S')
    etc_backup = f"{BACKUP_SUBDIRS['configs']}/etc_{ts}.tar.gz"
    _, _, brc = checker.run(f"tar czf {q(etc_backup)} /etc 2>/dev/null")
    if brc == 0:
        lines.append(f"✅ Резервная копия /etc создана: {etc_backup}")
    else:
        lines.append("⚠️ Не удалось создать резервную копию /etc (продолжаем)")

    # old_ip/new_ip прошли строгую проверку IPv6Address -> метасимволы невозможны.
    cmd = f"find /etc -type f -exec sed -i 's/{old_ip}/{new_ip}/g' {{}} +"
    out, err, rc = checker.run(cmd)
    if rc != 0:
        lines.append(f"⚠️ Возможны ошибки (rc={rc}): {err.strip() or out.strip()}")
    lines.append("✅ IPv6 заменён во всех файлах в /etc.")
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
        out, _, _ = checker.run(f'systemctl list-unit-files | grep -q "^{svc}.service" && echo "yes" || echo "no"')
        if out.strip() == 'yes':
            _, _, arc = checker.run(f'systemctl {action} {svc} 2>/dev/null')
            status, _, _ = checker.run(f'systemctl is-active {svc} 2>/dev/null')
            if status.strip() == 'active':
                lines.append(f"✅ {svc} ({action}) выполнен")
            else:
                _, _, rrc = checker.run(f'systemctl restart {svc} 2>/dev/null')
                status2, _, _ = checker.run(f'systemctl is-active {svc} 2>/dev/null')
                if status2.strip() == 'active':
                    lines.append(f"✅ {svc} перезапущен (fallback)")
                else:
                    lines.append(f"❌ {svc} не запустился (rc={rrc}, reload rc={arc})")
        else:
            lines.append(f"⏭️ {svc} не установлен")
    return lines
