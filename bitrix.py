"""Диагностика 1С-Битрикс (BitrixVM / Bitrix Framework).

Отчёты собраны по самым частым обращениям техподдержки: не перевыпустился
Let's Encrypt (dehydrated), тормоза из-за дефолтного innodb_buffer_pool_size,
Access denied для пользователя БД из dbconn.php, молчащие cron-агенты,
настройки PHP и зависшая почта. Расчёт буфера InnoDB, генерация конфига MySQL,
разбор dbconn.php и mailq — чистые функции: проверяются тестами без SSH.
"""
import re
from datetime import datetime, timezone

from common import q, write_remote_file

# ==================== ПУТИ BITRIXVM ====================
# Раскладку не «исправляем»: в реальном BitrixVM каталог vhost'ов пишется с
# исторической опечаткой avaliable, на старых сборках другого нет.
BITRIX_HOME = '/home/bitrix'
BITRIX_DOCROOT = '/home/bitrix/www'
WEBDIR = '/opt/webdir'
DEHYDRATED = '/home/bitrix/dehydrated'
DEHYDRATED_BIN = '/home/bitrix/dehydrated/dehydrated'
DEHYDRATED_LOG = '/home/bitrix/dehydrated_update.log'
DBCONN_PATH = f'{BITRIX_DOCROOT}/bitrix/php_interface/dbconn.php'
SITE_DIRS = ('/etc/nginx/bx/site_avaliable', '/etc/nginx/bx/site_available')
MYSQL_CNF = '/etc/my.cnf'
MYSQL_CNF_DIR = '/etc/my.cnf.d'
TUNE_FILE = f'{MYSQL_CNF_DIR}/bitrix-tuning.cnf'
DBCHECK_CNF = '/tmp/.techsupp_dbcheck.cnf'
CRON_SH = f'{BITRIX_DOCROOT}/bitrix/modules/main/tools/cron.sh'

# Параметры PHP, на которые смотрит тест «Битрикс» и которые чаще всего ломают
# загрузку каталога/импорта.
PHP_PARAMS = (
    'memory_limit', 'max_execution_time', 'max_input_vars', 'post_max_size',
    'upload_max_filesize', 'opcache.enable', 'opcache.memory_consumption',
    'opcache.validate_timestamps',
)
# Ключи my.cnf, которые показывают в отчёте.
MYSQL_PARAMS = (
    'innodb_buffer_pool_size', 'innodb_flush_method',
    'innodb_flush_log_at_trx_commit', 'innodb_log_file_size',
    'max_connections', 'tmp_table_size', 'max_heap_table_size',
    'query_cache_size',
)
# Модули из списка требований 1С-Битрикс (check.php), сокращённо.
REQUIRED_MODULES = (
    'curl', 'dom', 'gd', 'iconv', 'intl', 'json', 'mbstring', 'mysqli',
    'openssl', 'simplexml', 'xml', 'zip',
)
_DB_KEYS = ('DBHost', 'DBLogin', 'DBPassword', 'DBName')


# ==================== ЧИСТЫЕ ФУНКЦИИ (тестируются без SSH) ====================
def _params_re(params):
    """RegExp для grep -E: активные (не закомментированные) строки параметров."""
    return '^\\s*(' + '|'.join(re.escape(p) for p in params) + ')\\s*='


def recommend_innodb_buffer(mem_mb, pct=40):
    """Рекомендуемый innodb_buffer_pool_size в МБ.

    На BitrixVM MySQL соседствует с nginx/php-fpm/sphinx, поэтому 40% RAM,
    а не «70-80% как на выделенном сервере MySQL». Округление вниз до
    кратности chunk_size 128M — иначе MySQL молча округляет по-своему.
    """
    if not mem_mb or mem_mb <= 0:
        return None
    mb = mem_mb * pct // 100
    return max(256, mb // 128 * 128)


def mysql_tune_config(mem_mb, pct=40):
    """Содержимое include-файла /etc/my.cnf.d/bitrix-tuning.cnf (или None)."""
    pool = recommend_innodb_buffer(mem_mb, pct)
    if pool is None:
        return None
    lines = [
        '# Добавлено ServerDiagnostic: InnoDB под 1С-Битрикс.',
        f'# Расчёт от RAM {mem_mb} МБ: buffer pool {pool} МБ (~{pct}% RAM).',
        '[mysqld]',
        f'innodb_buffer_pool_size = {pool}M',
        'innodb_flush_method = O_DIRECT',
        'innodb_file_per_table = 1',
        'innodb_flush_log_at_trx_commit = 2',
        'max_connections = 200',
        '# innodb_log_file_size менять отдельно: на MySQL < 8 требует чистой',
        '# остановки и пересоздания ib_logfile — здесь оставлено как подсказка:',
        '# innodb_log_file_size = 256M',
    ]
    return '\n'.join(lines) + '\n'


def parse_cnf_size(value):
    """'128M' / '2G' / '134217728' (байты) -> МБ; None если не разбирается."""
    if not value:
        return None
    v = str(value).strip().upper()
    try:
        if v.endswith('K'):
            return int(v[:-1]) // 1024
        if v.endswith('M'):
            return int(v[:-1])
        if v.endswith('G'):
            return int(v[:-1]) * 1024
        return int(v) // (1024 * 1024)
    except ValueError:
        return None


def parse_buffer_stats(text):
    """Hit ratio buffer pool в % по выводу SHOW GLOBAL STATUS (или None)."""
    stats = {}
    for line in (text or '').splitlines():
        parts = line.split()
        if len(parts) == 2 and parts[0].startswith('Innodb_buffer_pool_read'):
            try:
                stats[parts[0]] = int(parts[1])
            except ValueError:
                pass
    req = stats.get('Innodb_buffer_pool_read_requests')
    reads = stats.get('Innodb_buffer_pool_reads')
    if not req or reads is None:
        return None
    return (1 - reads / req) * 100


_DEFINE_RE = re.compile(r"""define\(\s*['"](\w+)['"]\s*,\s*['"]([^'"]*)['"]""")
_VAR_RE = re.compile(r"""\$(DBHost|DBLogin|DBPassword|DBName)\s*=\s*['"]([^'"]*)['"]""")


def parse_dbconn(text):
    """DBHost/DBLogin/DBPassword/DBName из dbconn.php.

    Поддерживает обе формы: define("DBHost", "...") и старую $DBHost = "...".
    Пароль возвращается здесь, но в отчёты наружу попадает только маска.
    """
    vals = {}
    for m in _DEFINE_RE.finditer(text or ''):
        if m.group(1) in _DB_KEYS:
            vals[m.group(1)] = m.group(2)
    for m in _VAR_RE.finditer(text or ''):
        vals.setdefault(m.group(1), m.group(2))
    return vals


def parse_notafter(text, now=None):
    """'notAfter=Oct 12 13:45:00 2026 GMT' -> целых дней до истечения (или None)."""
    m = re.search(r'notAfter=(\w{3} \d{1,2} [\d:]{8} \d{4})', text or '')
    if not m:
        return None
    try:
        dt = datetime.strptime(m.group(1), '%b %d %H:%M:%S %Y')
    except ValueError:
        return None
    # и dt, и now — наивные UTC: openssl отдаёт notAfter в GMT, а test-passed
    # `now` тоже наивный. Aware-вычитание уронило бы TypeError, поэтому
    # .replace(tzinfo=None), а не просто datetime.now(timezone.utc).
    return (dt - (now or datetime.now(timezone.utc).replace(tzinfo=None))).days


def parse_mailq_count(text):
    """Число писем в выводе mailq ('-- 5 Messages'); пустая очередь -> 0;
    нераспознанный вывод -> None."""
    for line in (text or '').splitlines():
        parts = line.split()
        if len(parts) >= 2 and parts[0] == '--' and parts[-1].startswith('Message'):
            try:
                return int(parts[1])
            except ValueError:
                return None
    if 'Mail queue is empty' in (text or ''):
        return 0
    return None


# ==================== ОКРУЖЕНИЕ И САЙТЫ ====================
def detect_bitrix_env(checker):
    """True, если на сервере BitrixVM: есть и /opt/webdir, и /home/bitrix."""
    out, _, _ = checker.run(f'ls -d {q(WEBDIR)} {q(BITRIX_HOME)} 2>/dev/null')
    found = {line.strip() for line in out.splitlines() if line.strip()}
    return WEBDIR in found and BITRIX_HOME in found


def bitrix_sites(checker):
    """Имена сайтов по конфигам vhost'ов BitrixVM (без служебных файлов)."""
    sites = []
    for directory in SITE_DIRS:
        out, _, _ = checker.run(f'ls -1 {q(directory)} 2>/dev/null')
        for line in out.splitlines():
            name = line.strip()
            if (not name or name.endswith('.conf')
                    or name in ('default', 'templates') or name in sites):
                continue
            sites.append(name)
    return sites


def bitrix_sites_report(checker):
    lines = ['=== САЙТЫ В BITRIXVM ===']
    sites = bitrix_sites(checker)
    if not sites:
        lines.append("⚠️ Конфиги vhost'ов в /etc/nginx/bx не найдены")
        return '\n'.join(lines)
    for site in sites:
        lines.append(f'• {site}')
    return '\n'.join(lines)


# ==================== SSL (dehydrated) ====================
def bitrix_ssl_report(checker):
    lines = ["=== SSL LET'S ENCRYPT (dehydrated) ==="]
    certs_dir = f'{DEHYDRATED}/certs'
    out, _, _ = checker.run(f'ls -1 {q(certs_dir)} 2>/dev/null')
    domains = [d.strip() for d in out.splitlines() if d.strip()]
    if not domains:
        lines.append(f'⚠️ В {certs_dir} пусто — сертификаты не выпускались '
                     '(или BitrixVM старше 7.2)')

    for dom in domains:
        pem = f'{certs_dir}/{dom}/fullchain.pem'
        out, _, _ = checker.run(f'openssl x509 -enddate -noout -in {q(pem)} 2>&1')
        raw = out.strip() or 'openssl: нет вывода'
        days = parse_notafter(raw)
        if days is None:
            mark = '⚠️'
        elif days < 14:
            mark = '❌'
        else:
            mark = '✅'
        tail = f', осталось {days} дн.' if days is not None else ''
        lines.append(f'{mark} {dom}: {raw}{tail}')

    out, _, _ = checker.run('crontab -l 2>/dev/null | grep -F dehydrated')
    lines.append('✅ Перевыпуск настроен в cron' if out.strip()
                 else '⚠️ В crontab задания dehydrated нет — перевыпускать придётся вручную')

    out, _, _ = checker.run(f'tail -n 15 {q(DEHYDRATED_LOG)} 2>/dev/null')
    if out.strip():
        lines.append(f'--- {DEHYDRATED_LOG} (последние 15 строк) ---')
        lines.append(out.strip())
    return '\n'.join(lines)


def bitrix_ssl_renew(checker):
    lines = ['=== ПЕРЕВЫПУСК СЕРТИФИКАТОВ DEHYDRATED ===']
    out, _, _ = checker.run(f'test -x {q(DEHYDRATED_BIN)} && echo ok')
    if out.strip() != 'ok':
        lines.append(f'❌ {DEHYDRATED_BIN} не найден — выпуск сертификатов '
                     'не настроен (BitrixVM < 7.2 или стоит certbot)')
        return '\n'.join(lines)

    lines.append('⚠️ Запуск dehydrated -c: до 1-2 минут; возможны отказы из-за '
                 'DNS (нет A/www), нехватки места и лимита LE 5 ошибок/час.')
    out, err, rc = checker.run(
        f'cd {q(DEHYDRATED)} && {q(DEHYDRATED_BIN)} -c 2>&1 | tail -25')
    lines.append(f'Код завершения: {rc}')
    lines.append(out.strip() or err.strip() or '(без вывода)')
    lines.append(f'Лог: {DEHYDRATED_LOG}')
    return '\n'.join(lines)


# ==================== MYSQL ====================
def total_mem_mb(checker):
    """Всего RAM в МБ по `free -m` (парсинг в Python, без awk)."""
    out, _, _ = checker.run('free -m')
    for line in out.splitlines():
        parts = line.split()
        if parts and parts[0].rstrip(':').lower() == 'mem':
            try:
                return int(parts[1])
            except (IndexError, ValueError):
                return None
    return None


def bitrix_mysql_report(checker):
    lines = ['=== MYSQL ПОД БИТРИКС ===']
    mem = total_mem_mb(checker)
    lines.append(f'RAM сервера: {mem} МБ' if mem else '⚠️ Не удалось определить RAM')

    out, _, _ = checker.run(f'grep -E {q(_params_re(MYSQL_PARAMS))} {q(MYSQL_CNF)} 2>/dev/null')
    pool = None
    current = {}
    for line in out.splitlines():
        key, _, value = line.partition('=')
        current[key.strip().lower()] = value.split('#')[0].strip()
    pool = parse_cnf_size(current.get('innodb_buffer_pool_size'))

    if pool is None:
        lines.append('⚠️ innodb_buffer_pool_size в /etc/my.cnf не задан — '
                     'работает дефолт 128M (для Битрикса мало почти всегда)')
    else:
        lines.append(f'innodb_buffer_pool_size = {pool}M')

    rec = recommend_innodb_buffer(mem) if mem else None
    if rec is not None:
        if pool is None or pool * 2 < rec:
            lines.append(f'💡 Рекомендация: {rec}M (~40% RAM). '
                         f'«MySQL: применить тюнинг» запишет {TUNE_FILE}.')
        elif pool >= rec:
            lines.append('✅ Буфер не меньше рекомендации')
        else:
            lines.append(f'💡 Рекомендация: {rec}M (~40% RAM), текущий {pool}M — '
                         'близко, критичным не выглядит')

    out, _, _ = checker.run(
        "mysql -N -e \"SHOW GLOBAL STATUS LIKE 'Innodb_buffer_pool_read%'\" 2>&1")
    ratio = parse_buffer_stats(out)
    if ratio is None:
        first = (out.strip().splitlines() or [''])[0]
        lines.append(f'⚠️ Статус InnoDB не получен (нужен доступ root к mysql): {first}')
    else:
        mark = '✅' if ratio >= 99 else '⚠️'
        lines.append(f'{mark} Hit ratio buffer pool: {ratio:.1f}% '
                     '(ниже 99% — много чтений с диска)')
    return '\n'.join(lines)


def bitrix_mysql_tune(checker):
    lines = ['=== MYSQL: ОПТИМИЗАЦИЯ ПОД БИТРИКС ===']
    mem = total_mem_mb(checker)
    if not mem:
        lines.append('❌ Не удалось определить объём RAM — ничего не меняем')
        return '\n'.join(lines)

    conf = mysql_tune_config(mem)
    pattern = '^!includedir\\s+' + re.escape(MYSQL_CNF_DIR)
    out, _, _ = checker.run(f'grep -Eq {q(pattern)} {q(MYSQL_CNF)} 2>/dev/null && echo ok')
    if out.strip() != 'ok':
        lines.append(f'❌ {MYSQL_CNF} не подключает {MYSQL_CNF_DIR} — правку '
                     'пришлось бы делать в сам my.cnf. Значения для ручной правки:')
        lines.extend((conf or '').splitlines())
        return '\n'.join(lines)

    ok, err = write_remote_file(checker, TUNE_FILE, conf)
    if not ok:
        lines.append(f'❌ Не удалось записать {TUNE_FILE}: {err}')
        return '\n'.join(lines)
    checker.run(f'chmod 600 {q(TUNE_FILE)} 2>/dev/null')

    pool = recommend_innodb_buffer(mem)
    lines.append(f'✅ Записан {TUNE_FILE} (RAM {mem} МБ, buffer pool {pool}M)')
    lines.append('⚠️ Применится после systemctl restart mysqld — сайты отвалятся '
                 'на 2-5 секунд. Перезапуск делайте вручную из меню панели.')
    lines.append('⚠️ Buffer pool выше 40-50% RAM не поднимайте: на сервере ещё '
                 'nginx, php-fpm и sphinx.')
    return '\n'.join(lines)


# ==================== ДОСТУП К БАЗЕ ====================
def _db_credentials(checker):
    """(vals, None) либо (None, [строки-ошибки]) — реквизиты из dbconn.php.

    Пароль здесь не печатается: строки ошибок идут прямо в отчёт оператору.
    """
    out, _, rc = checker.run(f'cat {q(DBCONN_PATH)} 2>/dev/null')
    if rc != 0 or not out.strip():
        return None, [f'❌ {DBCONN_PATH} не читается — проверьте, что сайт в '
                      f'{BITRIX_DOCROOT}']
    vals = parse_dbconn(out)
    missing = [k for k in ('DBHost', 'DBLogin', 'DBName') if not vals.get(k)]
    if missing:
        return None, ['❌ В dbconn.php не найдено: ' + ', '.join(missing)]
    return vals, None


def _db_query(checker, sql):
    """Запрос от имени Битрикс-пользователя: (True, stdout) либо (False, вывод).

    Пароль не уходит в аргументы mysql (его видно в ps): он во временном
    файле 0600, который удаляется в finally — даже если mysql упал.
    """
    vals, errors = _db_credentials(checker)
    if vals is None:
        return False, '\n'.join(errors or [])
    content = ('[client]\n'
               f"host={vals['DBHost']}\nuser={vals['DBLogin']}\n"
               f"password={vals.get('DBPassword', '')}\ndatabase={vals['DBName']}\n")
    ok, err = write_remote_file(checker, DBCHECK_CNF, content)
    if not ok:
        return False, f'❌ Не удалось подготовить файл проверки: {err}'
    checker.run(f'chmod 600 {q(DBCHECK_CNF)} 2>/dev/null')
    try:
        out, _, rc = checker.run(
            f'mysql --defaults-extra-file={q(DBCHECK_CNF)} -N -e {q(sql)} 2>&1')
        return rc == 0, out.strip()
    finally:
        checker.run(f'rm -f {q(DBCHECK_CNF)}')


def bitrix_db_check(checker):
    lines = ['=== ПРОВЕРКА ДОСТУПА К БАЗЕ (dbconn.php) ===']
    vals, errors = _db_credentials(checker)
    if vals is None:
        lines.extend(errors or [])
        return '\n'.join(lines)

    # Пароль наружу не печатаем: в отчёте только факт, задан он или нет.
    lines.append(f"DBHost={vals['DBHost']} DBLogin={vals['DBLogin']} "
                 f"DBName={vals['DBName']} "
                 f"DBPassword={'задан' if vals.get('DBPassword') else 'ПУСТОЙ'}")

    ok, out = _db_query(checker, 'SELECT 1')
    if ok:
        lines.append('✅ Битрикс-пользователь подключается к базе (SELECT 1 прошёл)')
        return '\n'.join(lines)

    detail = out or 'mysql: нет вывода'
    lines.append(f'❌ Подключение не прошло: {detail}')
    low = detail.lower()
    if 'access denied' in low:
        lines.append('💡 Проверьте пароль в dbconn.php и права: '
                     f"SHOW GRANTS FOR '{vals['DBLogin']}'@'{vals['DBHost']}'; "
                     'нужны SELECT/INSERT/UPDATE/DELETE, при нехватке — GRANT '
                     f"ON `{vals['DBName']}`.* ... ; FLUSH PRIVILEGES;")
    elif 'unknown database' in low:
        lines.append('💡 DBName в dbconn.php не совпадает с реальным именем базы.')
    elif "can't connect" in low or 'connection refused' in low:
        lines.append('💡 MySQL не слушает адрес из DBHost: проверьте службу '
                     'mysqld и DBHost (localhost vs 127.0.0.1 vs контейнер).')
    return '\n'.join(lines)


# ==================== РАЗМЕР ТАБЛИЦ ====================
# Запрос к information_schema: база берётся из defaults-файла (database=...),
# одинарных кавычек в SQL нет — q() в _db_query их не ломает.
TOP_TABLES_SQL = (
    'SELECT TABLE_NAME, ROUND((DATA_LENGTH+INDEX_LENGTH)/1024/1024,1), TABLE_ROWS '
    'FROM information_schema.TABLES WHERE TABLE_SCHEMA = DATABASE() '
    'ORDER BY (DATA_LENGTH+INDEX_LENGTH) DESC LIMIT 20'
)

# Порог, с которого таблица-«мусорщик» попадает в рекомендации.
GARBAGE_WARN_MB = 100

# Подсказки по таблицам, которые в Битриксе разрастаются именно мусором.
# b_cache_tag вручную не чистят: удаление тегов ломает инкрементальный кеш,
# поэтому подсказка — про штатные механизмы, не про DELETE.
GARBAGE_HINTS = {
    'b_user_session': 'сессии: штатная задача «Очистка неактивных сессий» '
                      'или DELETE по DATE_LAST (сначала SELECT COUNT)',
    'b_cache_tag': 'теги кеша: НЕ удалять вручную — чистить штатной «Очисткой '
                   'кеша» в админке, ручное DELETE ломает инкрементальный кеш',
    'b_cache_filter_tag': 'теги фильтра: как и b_cache_tag — только штатная '
                          'очистка кеша',
    'b_stat_hit': 'статистика визитов: отключите модуль статистики или '
                  'архивируйте старые записи',
    'b_stat_session': 'статистика сессий: чистить вместе с b_stat_hit',
    'b_log': 'журнал событий: уменьшите срок хранения в настройках продукта',
    'b_sale_basket': 'брошенные корзины: удаляйте позиции старше N дней '
                     '(сначала SELECT COUNT по DATE_INSERT)',
}


def parse_top_tables(text):
    """Вывод `mysql -N` (TAB-разделённые колонки) -> список строк отчёта.

    Колонки: имя, размер МБ, примерное число строк. Посторонние строки
    (например 'ERROR 1142 ...' от нехватки прав на information_schema)
    пропускаются: на них отчёт отвечает отдельным предупреждением.
    """
    rows = []
    for line in (text or '').splitlines():
        parts = line.split('\t')
        if len(parts) < 3:
            continue
        try:
            size_mb = float(parts[1])
        except ValueError:
            continue
        rows.append({'table': parts[0], 'size_mb': size_mb, 'rows': parts[2]})
    return rows


def garbage_hints(rows, warn_mb=GARBAGE_WARN_MB):
    """Строки-рекомендации по таблицам-мусорщикам тяжелее warn_mb."""
    sizes = {r['table']: r['size_mb'] for r in rows}
    return [f'💡 {table} ({sizes[table]:.0f} МБ) — {hint}'
            for table, hint in GARBAGE_HINTS.items()
            if sizes.get(table, 0) >= warn_mb]


def bitrix_db_tables_report(checker):
    lines = ['=== ТОП-20 ТАБЛИЦ БАЗЫ БИТРИКС ===']
    ok, out = _db_query(checker, TOP_TABLES_SQL)
    if not ok:
        lines.append('❌ Запрос к information_schema не прошёл:')
        lines.extend((out or 'mysql: нет вывода').splitlines())
        return '\n'.join(lines)

    rows = parse_top_tables(out)
    if not rows:
        lines.append('⚠️ Таблицы не перечислены: нет прав на information_schema '
                     'или база пуста')
        return '\n'.join(lines)

    total = sum(r['size_mb'] for r in rows)
    lines.append(f'Топ-{len(rows)}, сумма показанных: {total:.0f} МБ')
    for row in rows:
        mark = '  ⚠️' if row['table'] in GARBAGE_HINTS else ''
        lines.append(f"{row['size_mb']:9.1f} МБ  {row['table']:<40} "
                     f"строк: {row['rows']}{mark}")

    hints = garbage_hints(rows)
    if hints:
        lines.append('')
        lines.extend(hints)
        lines.append('⚠️ Перед любой чисткой — бэкап дампом mysqldump; таблицы '
                     'с префиксом b_ кроме перечисленных мусором не являются.')
    return '\n'.join(lines)


# ==================== ПРАВА ФАЙЛОВ САЙТА ====================
# В BitrixVM сайт принадлежит пользователю/группе bitrix: php работает от него,
# а www (Apache/nginx) входит в группу bitrix и только поэтому читает файлы.
# После «распаковали архив под root» или cp -r владельцы уезжают в root — и
# сайт падает на записи кеша/upload.
SITE_OWNER = 'bitrix'
SITE_GROUP = 'bitrix'

# Каталоги, без записи в которых Битрикс не работает (пути от корня сайта).
WRITABLE_DIRS = ('bitrix/cache', 'bitrix/managed_cache', 'bitrix/data',
                 'upload', 'bitrix/php_interface')


def bitrix_perms_report(checker):
    lines = ['=== ПРАВА ФАЙЛОВ САЙТА ===']
    out, _, rc = checker.run(f'ls -ld {q(BITRIX_DOCROOT)} 2>/dev/null')
    if rc != 0 or not out.strip():
        lines.append(f'❌ {BITRIX_DOCROOT} не найден — проверьте корень сайта')
        return '\n'.join(lines)
    lines.append(f'Корень сайта: {out.strip()}')

    out, _, _ = checker.run(
        f'find {q(BITRIX_DOCROOT)} -mindepth 1 ! -user {q(SITE_OWNER)} 2>/dev/null | wc -l')
    cnt = out.strip()
    if cnt == '0':
        lines.append(f'✅ Все файлы принадлежат {SITE_OWNER}')
    elif cnt.isdigit():
        lines.append(f'⚠️ Файлов с другим владельцем: {cnt} — починка: '
                     '«Права файлов: починить» ниже в меню')
    else:
        lines.append('⚠️ Не удалось посчитать владельцев (find не отработал)')

    out, _, _ = checker.run(
        f'find {q(BITRIX_DOCROOT)} -type f -perm -o+w 2>/dev/null | wc -l')
    cnt = out.strip()
    if cnt == '0':
        lines.append('✅ world-writable файлов нет')
    elif cnt.isdigit():
        lines.append(f'⚠️ Файлов, доступных на запись всем (o+w): {cnt} — '
                     'потенциальная дыра, ищите через '
                     f'find {BITRIX_DOCROOT} -type f -perm -o+w')

    for rel in WRITABLE_DIRS:
        path = f'{BITRIX_DOCROOT}/{rel}'
        out, _, _ = checker.run(
            f'test -d {q(path)} && (test -w {q(path)} && echo ok || echo ro)')
        mark = out.strip()
        if mark == 'ok':
            lines.append(f'✅ {rel}: запись есть')
        elif mark == 'ro':
            lines.append(f'❌ {rel}: каталог есть, но НЕ доступен для записи — '
                         'кеш/агенты работать не будут')
        else:
            lines.append(f'⚠️ {rel}: каталог не найден')
    return '\n'.join(lines)


def bitrix_perms_fix(checker):
    lines = ['=== ВОССТАНОВЛЕНИЕ ПРАВ САЙТА ===']
    out, _, _ = checker.run(f'getent group {q(SITE_GROUP)} >/dev/null && echo ok')
    if out.strip() != 'ok':
        lines.append(f'❌ Группы {SITE_GROUP} нет в системе — прервано, '
                     'chown на несуществующую группу ничего не починит')
        return '\n'.join(lines)

    lines.append('⚠️ Идём по всему документ-корню: на больших сайтах 1-5 минут.')
    out, err, rc = checker.run(
        f'chown -R {SITE_OWNER}:{SITE_GROUP} {q(BITRIX_DOCROOT)} 2>&1 | tail -5')
    lines.append(f'❌ chown (rc={rc}): {(out or err).strip() or "нет вывода"}'
                 if rc != 0 else f'✅ Владелец {SITE_OWNER}:{SITE_GROUP} восстановлен')

    out, err, rc = checker.run(
        f'find {q(BITRIX_DOCROOT)} -type d -exec chmod 755 {{}} + 2>&1 | tail -3')
    lines.append('✅ Каталогам выставлены 755' if rc == 0
                 else f'❌ chmod каталогов (rc={rc}): {(out or err).strip()}')

    out, err, rc = checker.run(
        f'find {q(BITRIX_DOCROOT)} -type f -exec chmod 644 {{}} + 2>&1 | tail -3')
    lines.append('✅ Файлам выставлены 644' if rc == 0
                 else f'❌ chmod файлов (rc={rc}): {(out or err).strip()}')

    # upload пишет веб-процесс от www — ему нужна запись GROUP'ой
    # (владельцем upload остаётся bitrix, 664 + группа bitrix достаточно).
    out, err, rc = checker.run(
        f'find {q(BITRIX_DOCROOT)}/upload -exec chmod g+w {{}} + 2>&1 | tail -3')
    lines.append('✅ upload: добавлена запись группой (www в группе bitrix)'
                 if rc == 0 else '⚠️ upload: chmod g+w не прошёл')
    lines.append('💡 Если php-FPM работает от bitrix (FastPanel/ISPmanager '
                 'иногда ставят www) — сверьте владельца процессов: '
                 'ps -o user,cmd -C php-fpm')
    return '\n'.join(lines)


# ==================== PHP ====================
def bitrix_php_report(checker):
    lines = ['=== PHP ПОД БИТРИКС ===']
    out, _, _ = checker.run('php -v 2>/dev/null | head -1')
    lines.append(f'Версия по умолчанию: {out.strip() or "php недоступен в PATH"}')

    out, _, _ = checker.run('ls -d /opt/php /opt/php-[0-9]* 2>/dev/null | head -6')
    phps = [p.strip() for p in out.splitlines() if p.strip()]
    if phps:
        lines.append('Установлено в /opt: ' + ', '.join(phps))

    for php_dir in phps[:3]:
        ini = f'{php_dir}/etc/php.ini'
        out, _, _ = checker.run(f'grep -E {q(_params_re(PHP_PARAMS))} {q(ini)} 2>/dev/null')
        if out.strip():
            lines.append(f'--- {ini} ---')
            lines.append(out.strip())

    out, _, _ = checker.run('php -m 2>/dev/null')
    loaded = {m.strip().lower() for m in out.splitlines() if m.strip()}
    if loaded:
        missing = [m for m in REQUIRED_MODULES if m not in loaded]
        lines.append('✅ Все обязательные модули на месте' if not missing
                     else f'⚠️ Нет модулей: {", ".join(missing)}')
    return '\n'.join(lines)


# ==================== CRON-АГЕНТЫ ====================
def bitrix_cron_report(checker):
    lines = ['=== CRON-АГЕНТЫ БИТРИКС ===']
    out, _, _ = checker.run(f'test -f {q(CRON_SH)} && echo ok')
    if out.strip() == 'ok':
        lines.append(f'✅ {CRON_SH} на месте')
    else:
        lines.append(f'⚠️ {CRON_SH} не найден — проверьте, что сайт на '
                     f'Битрикс стоит в {BITRIX_DOCROOT}')

    out, _, _ = checker.run('crontab -l 2>/dev/null | grep -F cron.sh')
    if out.strip():
        lines.append('✅ Задание cron.sh в crontab root:')
        lines.append(out.strip())
    else:
        lines.append('⚠️ Задания cron.sh в crontab нет: агенты крутятся на каждом')
        lines.append('   хите и тормозят отдачу страниц. Рекомендуемая строка')
        lines.append('   (crontab -e от root):')
        lines.append(f'   */1 * * * * sudo -u bitrix {CRON_SH} >/dev/null 2>&1')
    return '\n'.join(lines)


# ==================== ПОЧТА ====================
def bitrix_mail_report(checker):
    lines = ['=== ОТПРАВКА ПОЧТЫ (postfix) ===']
    out, _, _ = checker.run('systemctl is-active postfix 2>&1 | head -1')
    lines.append(f'Служба postfix: {out.strip() or "unknown"}')

    out, _, _ = checker.run('mailq 2>&1')
    count = parse_mailq_count(out)
    if count is None:
        first = (out.strip().splitlines() or [''])[0]
        lines.append(f'⚠️ mailq не отвечает: {first}')
    elif count == 0:
        lines.append('✅ Очередь пуста')
    else:
        lines.append(f'⚠️ В очереди {count} писем — частые причины: спам-фильтр '
                     'получателя, blacklist IP, неверный PTR')

    out, _, _ = checker.run('tail -n 15 /var/log/maillog 2>/dev/null')
    if out.strip():
        lines.append('--- /var/log/maillog (последние 15 строк) ---')
        lines.append(out.strip())
    else:
        out, _, _ = checker.run('journalctl -u postfix -n 15 --no-pager 2>/dev/null')
        if out.strip():
            lines.append('--- journalctl -u postfix (15 строк) ---')
            lines.append(out.strip())
    return '\n'.join(lines)
