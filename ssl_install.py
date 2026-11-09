"""Установка SSL-сертификатов: BitrixVM (раскладка dehydrated) и обычный nginx/apache.

Чем этот слайс отличается от «выпуска» (dehydrated в bitrix.py, certbot,
панельные letsencrypt): здесь оператор приносит ГОТОВЫЙ сертификат (выданный
где угодно) и просит положить его куда надо. Раскладки секций разные:
  * BitrixVM — три секции: crt (лист), chain (промежуточные), key;
  * обычная конфигурация nginx/apache — две: fullchain (лист + промежуточные
    одним куском) и key.
Модуль НЕ редактирует vhost'ы: право на правку чужих конфигов у кнопки
«установить сертификат» нет — отчёт называет пути и готовые директивы, которые
оператор вставляет сам (и перечисляет, что уже перезагружено).

Законы серии, которые здесь решают:
  * решение — код возврата, а не текст: парсинг PEM, пара cert<->key,
    срок действия (`openssl x509 -checkend`), `nginx -t`, reload — всё по rc;
    CN/SAN против домена — единственное текстовое ⚠️-ярус: у openssl на
    имена кода возврата нет, и вето по тексту этот модуль не объявляет;
  * секрет (приватный ключ) попадает в файл, уже имеющий 0600
    (prepare_secret_file — и в проверочный temp, и в целевой privkey.pem),
    не светится ни в одной командной строке (SFTP/argv — исключены) и
    убирается каналом cleanup на любом выходе, включая «Операция отменена»:
    обёртка ловит исключение, убирает temp-пути и перевыбрасывает;
  * перезапись только прочитанного и забэкапленного: отказ резерва снимает
    операцию (тот же вето, что у массовой замены IP);
  * домен — компонент пути, поэтому проходит allowlist символов, а не
    «похоже на домен глазами»;
  * PEM не склеивается в shell-командах: файлы пишет SFTP, в shell уходят
    только пути (проверочные — со случайным суффиксом, см. temp_paths).
"""
import posixpath
import re
from uuid import uuid4

from common import (q, create_backup_info, group_presence_info,
                    prepare_secret_file, remove_remote_path,
                    unit_presence_info)
from bitrix import DEHYDRATED

# Временные файлы для проверок openssl. Имя — НЕ фиксированная константа:
# prepare_secret_file снимает ловушку «по пути уже лежит чужой файл» сносом
# перед созданием, но между `rm -f` и `: >` остаётся окно, в которое локальный
# атакующий, знавший имя заранее, успевает подложить symlink (CWE-377 — на
# фиксированные /tmp-имена ругался и bandit). Случайный 48-битный суффикс,
# рождённый здесь и не известный никому до отправки команды, делает имя
# неугадываемым — то есть закрывает то же окно. Уборка — каналом cleanup
# («оператор нажал Стоп» не означает «оставь ключ на диске») и обёрткой
# try/except: исключение отмены не имеет права переживать проверочный ключ.
TMP_CERT_BASE = '/tmp/.techsupp_ssl_cert'
TMP_CHAIN_BASE = '/tmp/.techsupp_ssl_chain'
TMP_KEY_BASE = '/tmp/.techsupp_ssl_key'


def temp_paths():
    """Пусть проверочных PEM на один прогон: (cert, chain, key)."""
    tag = uuid4().hex[:12]
    return ('%s.%s.pem' % (TMP_CERT_BASE, tag),
            '%s.%s.pem' % (TMP_CHAIN_BASE, tag),
            '%s.%s.pem' % (TMP_KEY_BASE, tag))

# PEM-блок целиком (включая границы) — то, что пишем на диск.
_PEM_RE = re.compile(r'-----BEGIN ([A-Z0-9 ]+)-----(.+?)-----END \1-----',
                     re.S)
_KEY_LABELS = ('PRIVATE KEY', 'RSA PRIVATE KEY', 'EC PRIVATE KEY',
               'DSA PRIVATE KEY', 'ENCRYPTED PRIVATE KEY')

# Домен — часть пути /home/bitrix/dehydrated/certs/<домен>/: allowlist, а не
# «валидатор красивых имён». Punycode проходит как обычные ASCII-буквы.
_DOMAIN_RE = re.compile(
    r'^(?=.{1,253}$)[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?'
    r'(\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*$')


# ==================== ЧИСТЫЕ ФУНКЦИИ (тестируются без SSH) ====================
def split_pem(text):
    """PEM-текст на (сертификаты, ключи, прочее, ошибки).

    Блоки собираются ВМЕСТЕ с границами — именно так их и пишут на диск.
    '\r' режется: буфер обмена Windows приносит CRLF, а доверенные
    потребители (nginx) CRLF простят, наш подсчёт блоков — нет бы.
    """
    certs, keys, other, errors = [], [], [], []
    body = (text or '').replace('\r\n', '\n').replace('\r', '\n')
    if not body.strip():
        # Пустая секция — «не заполнили», это решает режим, а не парсер:
        # иначе прогон BitrixVM ругался бы на ненаполненный fullchain.
        return certs, keys, other, errors
    for m in _PEM_RE.finditer(body):
        label = m.group(1).strip()
        block = m.group(0)
        # PEM на диске обязан кончаться переводом строки (конвенция и многие
        # читатели требуют); regex границы не включает его — добавляем.
        if not block.endswith('\n'):
            block += '\n'
        if label == 'CERTIFICATE':
            certs.append(block)
        elif label in _KEY_LABELS:
            keys.append(block)
        else:
            other.append(label)
    if not certs and not keys:
        errors.append('ни одного PEM-блока не найдено: вставьте текст '
                      'вместе с строками -----BEGIN ... ----- / -----END ... -----')
    if other:
        errors.append('блоки неподходящего типа пропущены: '
                      + ', '.join(sorted(set(other)))
                      + ' — принимаются сертификаты и приватные ключи')
    return certs, keys, other, errors


def safe_domain(domain):
    """Домен, которому можно быть компонентом пути, или None.

    Не «валиден ли домен по RFC», а «пройдёт ли он в путь и в q() без
    сюрпризов»: буквы/цифры/дефис/точки, без слэшей, точек-подряд и ведущих
    дефисов. '' и мусор — None: вызывающий обязан отказать, а не чинить.
    Регистр понижается: DNS регистронезависим, а путь — нет; 'Site.RU' создал
    бы второй каталог certs/Site.RU рядом с certs/site.ru, который nginx не
    читает, — тихое дублирование вместо обновления сертификата.
    """
    value = (domain or '').strip().rstrip('.').lower()
    if not value or '..' in value or not _DOMAIN_RE.match(value):
        return None
    return value


def safe_dir_path(dir_path):
    """Абсолютный нормализованный каталог без '..' или None.

    q() спасает от инъекции, но не от '../': относительный путь разворачивался
    бы относительно HOME shell'а (у root это /root), и установка клала бы файлы
    куда угодно вне заявленного каталога. Нормализация ДО проверки: '/a/../b'
    и '/a//b' — это проходы мимо наивной проверки на '..'.
    """
    value = (dir_path or '').strip()
    if not value.startswith('/'):
        return None
    try:
        normalized = posixpath.normpath(value)
    except ValueError:
        return None
    if '..' in normalized.split('/') or not normalized.startswith('/'):
        return None
    return normalized


def cert_names_from_output(text):
    """Имена сертификата из вывода пары openssl-команд: (names|None, прочитано).

    SAN сильнее CN: браузеры по RFC 6125 при наличии subjectAltName на CN не
    смотрят, поэтому сначала DNS-ярки, commonName — только когда SAN нет
    (старые выпуски). -ext subjectAltName появился в openssl 1.1.1; на
    1.0.2 (старые BitrixVM) в выводе остаётся commonName из -subject
    -nameopt multiline — regex это переживает. Ничего не разобрали —
    (None, False): «не проверено», а не «не совпало».
    """
    body = text or ''
    dns = re.findall(r'DNS\s*:\s*([A-Za-z0-9*._-]+)', body)
    if dns:
        return dns, True
    cn = re.findall(r'commonName\s*=\s*([^\s,]+)', body)
    if cn:
        return cn, True
    return None, False


def name_matches_domain(pattern, domain):
    """Совпадает ли имя из сертификата с доменом.

    Wildcard покрывает РОВНО один левый уровень: '*.site.ru' годится для
    www.site.ru, но не для site.ru и не для a.b.site.ru. Регистр в DNS не
    значит ничего — сравнение по lowercase.
    """
    p = (pattern or '').strip().lower()
    d = (domain or '').strip().lower()
    if not p or not d:
        return False
    if p == d:
        return True
    if p.startswith('*.'):
        suffix = p[1:]                     # '.site.ru'
        if len(d) <= len(suffix) or not d.endswith(suffix):
            return False
        return '.' not in d[:len(d) - len(suffix)]
    return False


def bitrix_cert_paths(domain):
    """Раскладка dehydrated: cert.pem / chain.pem / fullchain.pem / privkey.pem."""
    base = '%s/certs/%s' % (DEHYDRATED, domain)
    return {'cert': base + '/cert.pem', 'chain': base + '/chain.pem',
            'fullchain': base + '/fullchain.pem', 'key': base + '/privkey.pem'}


def plain_cert_paths(dir_path, domain):
    """Обычная раскладка: <каталог>/<домен>/{fullchain.pem,privkey.pem}."""
    base = '%s/%s' % (dir_path.rstrip('/'), domain)
    return {'fullchain': base + '/fullchain.pem', 'key': base + '/privkey.pem'}


def check_sections(mode, crt='', chain='', fullchain='', key=''):
    """(ok, ошибки, подготовленные тексты) по секциям выбранного режима.

    Bitrix: crt — ровно один лист, chain — не меньше одного сертификата,
    key — ровно один ключ. Plain: fullchain — от одного сертификата (лист —
    первый), key — ровно один ключ. «Ровно один» — не педантизм: два листа в
    crt означают, что оператор вставил не то, и угадать, какой из них лист,
    мы не вправе.
    """
    errors = []
    c_certs, c_keys, _o, errs = split_pem(crt)
    errors += ['секция crt: ' + e for e in errs]
    h_certs, h_keys, _o, errs = split_pem(chain)
    errors += ['секция chain: ' + e for e in errs]
    f_certs, f_keys, _o, errs = split_pem(fullchain)
    errors += ['секция fullchain: ' + e for e in errs]
    k_certs, k_keys, _o, errs = split_pem(key)
    errors += ['секция key: ' + e for e in errs]

    if k_certs:
        errors.append('секция key: сертификат в ключах не размещают — '
                      'перепутаны секции')
    if len(k_keys) != 1:
        errors.append('секция key: ключ должен быть ровно один, найдено %d'
                      % len(k_keys))
    if k_keys and ('ENCRYPTED PRIVATE KEY' in k_keys[0]
                   or 'Proc-Type: 4,ENCRYPTED' in k_keys[0]):
        # Ключ под паролем: снять пароль нечем, значит проверка пары
        # cert<->key невозможна в принципе, а nginx прочитает такой файл
        # только с настроенным SSLPassPhraseDialog. Отказ с лечением — тот
        # же класс, что «два листа в crt»: угадывать мы не вправе. Без
        # этого шага openssl pkey в не-TTY канале зависал бы на запросе
        # пароля (спрос < /dev/null ниже лишь превращает вечный стоп в
        # ошибку, но диагностикой быть не может).
        errors.append('секция key: ключ зашифрован паролем — снимите его: '
                      'openssl pkey -in key.pem -out key-plain.pem')

    leaf = chain_pem = full_pem = None
    n_certs = 0
    chain_only = False
    if mode == 'bitrix':
        if c_keys:
            errors.append('секция crt: ключ в сертификате не размещают')
        if len(c_certs) > 1:
            errors.append('секция crt: найден %d сертификат(а) — нужен один '
                          'лист' % len(c_certs))
        if h_keys:
            errors.append('секция chain: ключ в цепочке не размещают')
        if not c_certs and not any(e.startswith('секция crt') for e in errors):
            errors.append('секция crt: сертификат не найден')
        if not h_certs:
            errors.append('секция chain: промежуточные сертификаты не найдены '
                          '(для BitrixVM chain обязателен)')
        if not errors:
            leaf = c_certs[0]
            chain_pem = '\n'.join(h_certs) + '\n'
            full_pem = leaf.rstrip('\n') + '\n' + chain_pem
            n_certs = len(c_certs)
    else:  # plain (nginx/apache): fullchain + key
        if f_keys:
            errors.append('секция fullchain: ключ в цепочке не размещают')
        if not f_certs and not any(e.startswith('секция fullchain')
                                   for e in errors):
            errors.append('секция fullchain: сертификат не найден')
        if f_certs:
            full_pem = '\n'.join(f_certs) + '\n'
            n_certs = len(f_certs)
            chain_only = len(f_certs) == 1
    if errors:
        return False, errors, {}
    return True, [], {'leaf': leaf, 'chain': chain_pem, 'fullchain': full_pem,
                      'key': k_keys[0], 'n_certs': n_certs,
                      'chain_only': chain_only}


# ==================== СЕРВЕРНАЯ ПРОВЕРКА МАТЕРИАЛА ====================
def _clean_temps(checker, paths):
    """Уборка временных PEM — каналом cleanup (переживает отмену)."""
    notes = []
    for path in paths:
        ok, why = remove_remote_path(checker, path, recursive=False)
        if not ok:
            notes.append(why)
    return notes


def _write_temps(checker, paths, leaf, chain, key):
    """Проверочные файлы на сервере: (ok, причина). Секрет — только 0600."""
    for path, content in zip(paths, (leaf, chain or '', key)):
        if content is None:
            continue
        ok, why = prepare_secret_file(checker, path, content)
        if not ok:
            return False, why
    return True, None


def openssl_material_info(checker, cert_path, key_path, chain_path,
                          domain=None, with_chain=True):
    """Разбираются ли материал и пара cert<->key на СЕРВЕРЕ: {parsed, matched,
    expired, verify, lines}.

    Пара берётся сравнением публичных ключей: `openssl x509 -pubkey` против
    `openssl pkey -pubout` — это работает и для RSA, и для EC (modulus-сравнение
    умерло бы на EC). Сравнение в [ "$a" = "$b" ]: rc принадлежит тесту, а не
    openssl; но сначала проверяется РАЗБОР каждого файла отдельным rc, иначе
    два непарсящихся файла дали бы два пустых pubkey — «равны» и ложный ✅.
    Все опросы openssl идут с < /dev/null: на запросе пароля или ещё каком
    stdin-спросе не-TTY канал завис бы навсегда (команда не вернула бы rc —
    и весь отчёт встал бы).
    Срок действия решает rc `-checkend`: 1 — истёк/истечёт в окне, 0 — нет,
    иной rc — «не спросили» (ни «в силе», ни «истёк» утверждать нельзя).
    verify цепочки — ⚠️-информация, не вето: доверенные корни на разных
    дистрибутивах отличаются, а лист с ключом в паре ставится и без верифика.
    """
    lines = []
    out, err, rc = checker.run(f'openssl x509 -in {q(cert_path)} -noout '
                               '-subject -issuer -enddate < /dev/null 2>&1')
    if rc != 0:
        return {'parsed': False,
                'why': 'сертификат не разбирается openssl: '
                       + (out.strip() or err.strip() or f'rc={rc}')[:200],
                'lines': []}
    lines.extend('  ' + ln for ln in out.splitlines() if ln.strip())
    m = re.search(r'notAfter=(.+)', out)
    not_after = m.group(1).strip() if m else ''
    out, err, rc = checker.run(f'openssl pkey -in {q(key_path)} -noout '
                               '< /dev/null 2>&1')
    if rc != 0:
        return {'parsed': False,
                'why': 'ключ не разбирается openssl: '
                       + (out.strip() or err.strip() or f'rc={rc}')[:200],
                'lines': lines}
    lines.append('  ✅ ключ читается openssl')
    # Сравнение пары — с guard'ом на ПУСТОТУ и семантикой rc: две пустые
    # подстановки (openssl упал в рантайме, OOM) были бы «равны» и дали бы
    # ложное ✅ «одна пара»; любой rc!=0 был ложным «НЕ совпадает», тогда как
    # rc=124/126/127 — это «не спросили». EMPTY ловится по stdout (rc теста
    # при exit 0 нулевой), несверка — по rc вне {0,1}.
    out, err, rc = checker.run(
        f'a="$(openssl x509 -in {q(cert_path)} -noout -pubkey 2>/dev/null)"; '
        f'b="$(openssl pkey -in {q(key_path)} -pubout < /dev/null 2>/dev/null)"; '
        f'if [ -z "$a" ] || [ -z "$b" ]; then echo EMPTY; exit 0; fi; '
        f'[ "$a" = "$b" ]')
    if (out or '').strip() == 'EMPTY':
        return {'parsed': True, 'matched': False,
                'why': 'пара cert/key не проверена: openssl не выдал публичный '
                       'ключ (пустые pubkey) — ставить непроверенную пару '
                       'нельзя, установка отменена',
                'lines': lines}
    if rc == 1:
        return {'parsed': True, 'matched': False,
                'why': 'публичный ключ сертификата НЕ совпадает с приватным '
                       'ключом: nginx с такой парой не поднимет TLS',
                'lines': lines}
    if rc != 0:
        return {'parsed': True, 'matched': False,
                'why': f'пара cert/key не проверена (сравнение вернуло rc={rc}, '
                       'не 0 и не 1) — это «мы не спросили», а не «не '
                       'совпадает»; ставить непроверенную пару нельзя',
                'lines': lines}
    lines.append('  ✅ сертификат и ключ — одна пара')
    # Истёкший сертификат — вето: браузер отвергнет соединение по дате,
    # сайт с «установленным» сертификатом лежит, и это больнее отмены
    # (оператор принёс не тот файл — как два листа в crt, угадываемое «не
    # тот» не лечится установкой). Запас до 30 дней — только ⚠️: перевыпуск
    # дело оператора, а не кнопки.
    _, _, rc_exp = checker.run(f'openssl x509 -in {q(cert_path)} -noout '
                               '-checkend 0 < /dev/null 2>&1')
    if rc_exp == 1:
        return {'parsed': True, 'matched': True, 'expired': True,
                'why': 'срок действия сертификата истёк'
                       + (f' (notAfter {not_after})' if not_after else '')
                       + ': браузеры отвергнут TLS по дате',
                'lines': lines}
    elif rc_exp == 0:
        _, _, rc_soon = checker.run(
            f'openssl x509 -in {q(cert_path)} -noout -checkend 2592000 '
            '< /dev/null 2>&1')
        if rc_soon == 1:
            lines.append('  ⚠️ до конца срока меньше 30 дней'
                         + (f' (notAfter {not_after})' if not_after else '')
                         + ' — планируйте перевыпуск')
        elif rc_soon != 0:
            lines.append('  ⚠️ близость срока не проверена (openssl вернул '
                         f'rc={rc_soon}) — это «мы не спросили», а не '
                         '«запас есть»')
    else:
        lines.append('  ⚠️ срок действия не проверен (openssl -checkend '
                     f'вернул rc={rc_exp}) — это «мы не спросили», а не '
                     '«сертификат в силе»')
    # Совпадение CN/SAN с доменом. У openssl нет кода возврата за имена
    # (-checkhost печатает ответ, rc не выставляет), поэтому это единственный
    # текстовый шаг модуля — и сознательно ⚠️-ярус без вето: сертификат для
    # example.ru могут осознанно ставить как заготовку, но смолчать модуль
    # не вправе: иначе оператор узнает о несовпадении из браузера.
    if domain:
        out_n, _err_n, _rc_n = checker.run(
            f'openssl x509 -in {q(cert_path)} -noout -ext subjectAltName '
            f'< /dev/null 2>&1; openssl x509 -in {q(cert_path)} -noout '
            '-subject -nameopt multiline < /dev/null 2>&1')
        names, read = cert_names_from_output(out_n)
        if not read:
            lines.append('  ⚠️ CN/SAN сертификата не прочитаны — совпадение '
                         'с доменом не проверено: это «мы не спросили», а '
                         'не «имя совпало»')
        elif not any(name_matches_domain(n, domain) for n in names):
            lines.append('  ⚠️ сертификат выдан для '
                         + ', '.join(sorted(set(names))[:4])
                         + ', а ставим для ' + domain + ': браузеры покажут '
                         'несовпадение имени. Установка продолжена — '
                         'проверьте, тот ли это сертификат')
    verify = None
    if with_chain:
        # Форма проверки — «доверенный корень + промежуточные как untrusted»:
        # `openssl verify -CAfile <chain>` без корня в цепочке падает ВСЕГДА
        # («error 2 unable to get issuer certificate», проверено живьём), т.е.
        # прежняя команда либо врала «цепочка не подтверждена» на здоровой
        # цепочке, либо вообще не проверяла CRT↔chain. Корни берутся из
        # системного набора; нет набора — честное «не спросили», не ⚠️.
        out, err, rc = checker.run(
            'ca=""; for c in /etc/ssl/certs/ca-certificates.crt '
            '/etc/pki/tls/certs/ca-bundle.crt /etc/pki/ca-trust/extracted/'
            'pem/ca-bundle.trust.crt; do [ -r "$c" ] && ca="$c" && break; '
            'done; if [ -z "$ca" ]; then echo NOCACERT; exit 0; fi; '
            f'openssl verify -CAfile "$ca" -untrusted {q(chain_path)} '
            f'{q(cert_path)} < /dev/null 2>&1')
        text = (out or err).strip()
        if 'NOCACERT' in text:
            # Это «мы не спросили», а не «цепочка кривая»: отсутствие
            # системного набора корней не даёт права ни на ✅, ни на ⚠️.
            lines.append('  ⚠️ цепочка не проверена: системный набор доверенных '
                         'корней не найден — это «мы не спросили», а не '
                         '«цепочка неверна»')
        elif rc == 0:
            lines.append('  ✅ цепочка подтверждена openssl verify до '
                         'доверенного корня')
        else:
            verify = ('⚠️ openssl verify не подтвердил цепочку до доверенного '
                      'корня: ' + (text.splitlines() or [''])[0][:180]
                      + ' — установка продолжается (пара cert<->key верна); '
                      'проверьте, что chain содержит промежуточные именно '
                      'этого выпуска')
    return {'parsed': True, 'matched': True, 'verify': verify, 'lines': lines}


# ==================== ОБЩАЯ ЧАСТЬ УСТАНОВОК ====================
def _backup_gate(checker, paths):
    """Право перезаписать цель даёт принятый резерв. {ok, lines}.

    create_backup_info сам различает «файла нет» (писать нечего — ок) и
    «источник не виден» (unchecked) — второй мир обязан снять операцию:
    перезаписать то, чего не видели, прежняя серия запрещала везде.
    """
    lines, ok = [], True
    for path in paths:
        info = create_backup_info(checker, path, backup_type='certs')
        if info['state'] == 'absent':
            continue
        if info['state'] == 'done':
            lines.append(f'  🗂 резерв {path} → {info["path"]}')
            continue
        lines.append(f'  ❌ {path}: {info["note"] or info["state"]}')
        ok = False
    return ok, lines


def _reload_web(checker):
    """Перезагрузка веб-служб после установки. Решает rc, конфиг тестируется
    ДО reload — битый конфиг не должен уронить работающий сервер.
    """
    lines = []
    out, err, rc = checker.run('LC_ALL=C nginx -t 2>&1')
    if rc in (126, 127):
        # PATH не-интерактивного shell может не видеть /sbin|/usr/sbin — на
        # установленном nginx rc=127 врал бы «вероятно, не установлен».
        out, err, rc = checker.run('LC_ALL=C /usr/sbin/nginx -t 2>&1')
    if rc == 127 or rc == 126:
        lines.append('  ℹ️ nginx -t не спросить (rc=%s) — nginx, вероятно, '
                     'не установлен' % rc)
    elif rc != 0:
        shown = '\n  '.join((out or err).strip().splitlines()[-3:])
        lines.append(f'  ❌ nginx -t НЕ пройден (rc={rc}):\n  {shown}\n'
                     '  ⚠️ файлы сертификатов записаны, nginx НЕ перезагружен: '
                     'чините конфиг или откатывайте резервы из строк выше')
    else:
        presence = unit_presence_info(checker, 'nginx')
        if presence['presence'] != 'present' or not presence['checked']:
            lines.append('  ⚠️ nginx -t пройден, но юнит nginx не подтверждён '
                         '(' + (presence.get('note')
                                or presence['presence'])
                         + ') — перезагрузку выполните сами')
        else:
            rout, rerr, rrc = checker.run('systemctl reload nginx 2>&1')
            # 2>&1 вливает stderr ДАЛЁКОЙ команды в stdout — канал err здесь
            # всегда пуст, и прежнее чтение rerr теряло причину на каждом
            # отказе («reload nginx вернул rc=1: » без хвоста).
            lines.append('  ✅ nginx перезапущен (reload, rc=0)' if rrc == 0
                         else f'  ❌ reload nginx вернул rc={rrc}: '
                              + ((rout or rerr) or '').strip()[:160])
    # Apache: BitrixVM и обычные панели держат его не всегда — спрос короткий.
    out, err, rc = checker.run('LC_ALL=C apache2ctl configtest 2>&1')
    if rc in (126, 127):
        out, err, rc = checker.run('LC_ALL=C httpd -t 2>&1')
        apache_bin = 'httpd'
    else:
        apache_bin = 'apache2ctl'
    if rc in (126, 127):
        return lines  # apache не установлен — молчание честно по двум rc
    if rc != 0:
        lines.append(f'  ❌ {apache_bin} configtest не пройден (rc={rc}) — '
                     'apache НЕ перезагружен')
        return lines
    reloaded = False
    unchecked_note = ''
    for unit in ('apache2', 'httpd'):
        presence = unit_presence_info(checker, unit)
        if presence['presence'] == 'present' and presence['checked']:
            rout, rerr, arrc = checker.run(f'systemctl reload {unit} 2>&1')
            lines.append(f'  ✅ {unit} перезапущен (reload)' if arrc == 0
                         else f'  ❌ reload {unit} вернул rc={arrc}: '
                              + ((rout or rerr) or '').strip()[:160])
            reloaded = True
            break
        if presence['presence'] == 'unchecked' and not unchecked_note:
            unchecked_note = presence.get('note') or 'unchecked'
    if not reloaded:
        # Конфиг прошёл, а юнита нет (SysV, контейнер) — nginx-ветка такое
        # положение печатает, apache-ветка молчала: оператор считал бы, что
        # перезагрузка состоялась.
        lines.append('  ⚠️ configtest пройден, но юнит apache2/httpd не '
                     'подтверждён (' + (unchecked_note or 'не найден')
                     + ') — перезагрузку выполните сами')
    return lines


# ==================== УСТАНОВКИ ====================
def _ssl_bitrix_lines(checker, tmp, domain, crt_pem, chain_pem, key_pem):
    """Кладёт сертификат в раскладку dehydrated BitrixVM.

    tmp — пути проверочных PEM от temp_paths(); второй возврат — «файлы
    создавались», по нему обёртка решает, обязан ли был состояться cleanup.

    Секции: crt — лист, chain — промежуточные, key — приватный ключ. Файлы
    cert.pem/chain.pem/fullchain.pem/privkey.pem в
    /home/bitrix/dehydrated/certs/<домен>/, права 0644 (ключ 0600), владелец
    bitrix:bitrix — если пользователь и группа есть в системе (спрос по rc;
    отказ владения не отменяет установку, а называется).
    """
    lines = ['=== УСТАНОВКА SSL (BitrixVM / dehydrated) ===']
    dom = safe_domain(domain)
    if dom is None:
        lines.append('❌ Домен не прошёл проверку имени (ожидается вида '
                     'example.ru) — установка отменена')
        return lines, False
    ok, errors, parts = check_sections('bitrix', crt=crt_pem, chain=chain_pem,
                                       key=key_pem)
    if not ok:
        lines.extend('❌ ' + e for e in errors)
        return lines, False
    paths = bitrix_cert_paths(dom)

    # С этого момента проверочные файлы ИЛИ уже созданы, ИЛИ попытка их
    # создания оставляла след: уборка обязана случиться и при частичном
    # успехе _write_temps — флаг ставится ДО вызова, а не после.
    temps_used = True
    wrote_temps, why = _write_temps(checker, tmp, parts['leaf'],
                                    parts['chain'], parts['key'])
    if not wrote_temps:
        lines.append('❌ проверочные файлы на сервере не созданы: ' + why)
        return lines, temps_used
    check = openssl_material_info(checker, tmp[0], tmp[2], tmp[1],
                                  domain=dom, with_chain=True)
    lines.extend(check['lines'])
    if not check['parsed']:
        lines.append('❌ ' + check['why'] + ' — установка отменена')
        return lines, temps_used
    if not check['matched']:
        lines.append('❌ ' + check['why'] + ' — установка отменена')
        return lines, temps_used
    if check.get('expired'):
        lines.append('❌ ' + check['why'] + ' — установка отменена')
        return lines, temps_used
    if check['verify']:
        lines.append(check['verify'])

    gate_ok, gate_lines = _backup_gate(checker, [paths['cert'],
                                                 paths['chain'],
                                                 paths['fullchain'],
                                                 paths['key']])
    lines.extend(gate_lines)
    if not gate_ok:
        lines.append('❌ отказ резерва снимает установку: ничего не '
                     'перезаписано')
        return lines, temps_used

    # Каталог сертификатов: mkdir + проверка ТИПА одним составным выводом.
    # На BitrixVM certs/ пишет пользователь bitrix (= скомпрометированный
    # сайт): посаженный symlink-каталог mkdir -p принял бы за существующую
    # директорию (rc=0), а root дописал бы файлы в цель ссылки. Маркеры
    # DIRSYMLINK/NOTDIR решают вместо rc: у составной команды rc принадлежит
    # последнему if, а не mkdir.
    cert_dir = paths['cert'].rsplit('/', 1)[0]
    dq = q(cert_dir)
    out_m, err_m, mrc = checker.run(
        f'mkdir -p {dq} 2>&1; if [ -L {dq} ]; then echo DIRSYMLINK; '
        f'elif [ ! -d {dq} ]; then echo NOTDIR; fi')
    text_m = out_m or ''
    if 'DIRSYMLINK' in text_m:
        lines.append(f'❌ по пути {cert_dir} лежит symlink — установка отменена, '
                     'цель ссылки не тронута')
        return lines, temps_used
    if 'NOTDIR' in text_m or mrc != 0:
        lines.append(f'❌ каталог {cert_dir} не создан: '
                     + (out_m or err_m or '').replace('NOTDIR', '').strip()[:160]
                     + ' — установка отменена')
        return lines, temps_used

    targets = ((paths['cert'], parts['leaf'], False),
               (paths['chain'], parts['chain'], False),
               (paths['fullchain'], parts['fullchain'], False),
               (paths['key'], parts['key'], True))
    failed = False
    for path, content, secret in targets:
        # Каждый файл — только prepare_secret_file: symlink-veto, noclobber
        # и права (0600 ключ, 0644 сертификат) ДО содержимого. Прежний
        # write_remote_file для публичных файлов шёл по symlink как по
        # обычному файлу (SFTP open 'w'): root перезаписывал цель ссылки из
        # bitrix-writable каталога — тот класс, что уже залечен для ключей.
        # Отдельный chmod после записи убран: он сам был окном (chmod по
        # подставленному symlink целит в цель), а права теперь выставлены
        # на создании.
        ok, why = prepare_secret_file(checker, path, content,
                                      mode='600' if secret else '644')
        if not ok:
            lines.append(f'❌ не записан {path}: {why}')
            failed = True
    if failed:
        lines.append('❌ установка НЕ завершена: часть файлов не записана '
                     '— проверьте строки выше; сервер НЕ перезагружен, '
                     'записанное можно откатить резервами из строк выше')
        return lines, temps_used
    lines.append('  ✅ записаны cert.pem, chain.pem, fullchain.pem, '
                 'privkey.pem в ' + cert_dir)
    # Владелец bitrix:bitrix — норма BitrixVM; пользователя спрашиваем по rc,
    # как группу (1.32.21): `id -u NAME` даёт rc=0 (uid в stdout), rc=1 —
    # «такого пользователя нет» (GNU coreutils), rc=126/127 — id не спросить.
    # 2>/dev/null тут НЕЛЬЗЯ: при отказе обязан доехать причина, а решение
    # решает код, а не форма stdout (uid здесь вообще не нужен — chown идёт по
    # имени). group_presence_info закрывает группу тем же кодом возврата.
    id_out, id_err, idrc = checker.run('id -u bitrix')
    grp = group_presence_info(checker, 'bitrix')
    user_state = ('present' if idrc == 0 else
                  'absent' if idrc == 1 else 'unchecked')
    if user_state == 'unchecked':
        why = (id_err or '').strip().splitlines()
        lines.append('  ⚠️ пользователя bitrix не спросить (rc=%s%s) — '
                     'владелец не менялся' % (
                         idrc, ': ' + why[0][:120] if why else ''))
    elif user_state == 'absent':
        lines.append('  ℹ️ пользователя bitrix в системе нет — владелец '
                     'не менялся')
    elif grp['state'] == 'absent':
        lines.append('  ℹ️ пользователя bitrix есть, но группы bitrix нет — '
                     'владелец не менялся')
    elif grp['state'] == 'unchecked':
        lines.append('  ⚠️ группу bitrix не спросить ('
                     + (grp.get('note') or 'rc!=0/1/2')
                     + ') — владелец не менялся')
    else:
        # Glob `cert_dir/*` разыменовывал symlink-записи из каталога (chown
        # без -h идёт по ссылке): bitrix-writable каталог + glob = chown
        # чужого дерева рутом. Явный список — ровно те четыре пути, которые
        # мы сами создали и проверили на symlink.
        cout, cerr, chrc = checker.run(
            'chown bitrix:bitrix ' + ' '.join(
                q(paths[k]) for k in ('cert', 'chain', 'fullchain', 'key')
            ) + ' 2>&1')
        lines.append('  ✅ владелец bitrix:bitrix выставлен' if chrc == 0
                     else f'  ⚠️ chown bitrix:bitrix не прошёл (rc={chrc}): '
                          + ((cout or cerr) or '').strip()[:160])
    lines.append('')
    lines.extend(_reload_web(checker))
    lines.append('')
    lines.append('ℹ️ Dehydrated может перезаписать эти файлы при '
                 'перевыпуске: если сертификат платный и LE-задание '
                 'живёт — отключите задание (см. отчёт SSL BitrixVM).')
    return lines, temps_used

def _ssl_plain_lines(checker, tmp, domain, fullchain_pem, key_pem,
                      dir_path='/etc/ssl/diagtool'):
    """Кладёт fullchain+key в <каталог>/<домен>/ и перезагружает веб-службы.

    vhost'ы НЕ правятся — см. шапку модуля; отчёт печатает директивы для
    вставки. Каталог по умолчанию /etc/ssl/diagtool: штатные каталоги панелей
    и certbot заняты их процессами и будут затёрты их же перевыпуском —
    влезать в их территорию кнопка не имеет права.
    """
    lines = ['=== УСТАНОВКА SSL (nginx / apache) ===']
    dom = safe_domain(domain)
    if dom is None:
        lines.append('❌ Домен не прошёл проверку имени — установка отменена')
        return lines, False
    ok, errors, parts = check_sections('plain', fullchain=fullchain_pem,
                                       key=key_pem)
    if not ok:
        lines.extend('❌ ' + e for e in errors)
        return lines, False
    base = safe_dir_path(dir_path)
    if base is None:
        lines.append('❌ каталог должен быть абсолютным путём без «..»: '
                     'относительный разворачивается относительно HOME shell\'а '
                     'и кладёт файлы вне заявленного места — установка отменена')
        return lines, False
    paths = plain_cert_paths(base, dom)

    leaf = parts['fullchain'].split('-----END CERTIFICATE-----', 1)[0] \
        + '-----END CERTIFICATE-----\n'
    temps_used = True
    wrote_temps, why = _write_temps(checker, tmp, leaf, parts['fullchain'],
                                    parts['key'])
    if not wrote_temps:
        lines.append('❌ проверочные файлы на сервере не созданы: ' + why)
        return lines, temps_used
    check = openssl_material_info(checker, tmp[0], tmp[2], tmp[1],
                                  domain=dom, with_chain=True)
    lines.extend(check['lines'])
    if not check['parsed']:
        lines.append('❌ ' + check['why'] + ' — установка отменена')
        return lines, temps_used
    if not check['matched']:
        lines.append('❌ ' + check['why'] + ' — установка отменена')
        return lines, temps_used
    if check.get('expired'):
        lines.append('❌ ' + check['why'] + ' — установка отменена')
        return lines, temps_used
    if check['verify']:
        lines.append(check['verify'])
    if parts['chain_only']:
        lines.append('⚠️ в fullchain ОДИН сертификат: без промежуточных '
                     'часть клиентов (Android, часть curl) оборвёт TLS — '
                     'добавьте chain в ту же секцию')

    gate_ok, gate_lines = _backup_gate(checker, [paths['fullchain'],
                                                 paths['key']])
    lines.extend(gate_lines)
    if not gate_ok:
        lines.append('❌ отказ резерва снимает установку: ничего не '
                     'перезаписано')
        return lines, temps_used

    base_dir = paths['fullchain'].rsplit('/', 1)[0]
    bdq = q(base_dir)
    out_m, err_m, mrc = checker.run(
        f'mkdir -p {bdq} 2>&1; if [ -L {bdq} ]; then echo DIRSYMLINK; '
        f'elif [ ! -d {bdq} ]; then echo NOTDIR; fi')
    text_m = out_m or ''
    if 'DIRSYMLINK' in text_m:
        lines.append(f'❌ по пути {base_dir} лежит symlink — установка отменена, '
                     'цель ссылки не тронута')
        return lines, temps_used
    if 'NOTDIR' in text_m or mrc != 0:
        lines.append(f'❌ каталог {base_dir} не создан: '
                     + (out_m or err_m or '').replace('NOTDIR', '').strip()[:160]
                     + ' — установка отменена')
        return lines, temps_used
    failed = False
    for path, content, secret in ((paths['fullchain'],
                                   parts['fullchain'], False),
                                  (paths['key'], parts['key'], True)):
        # Тот же закон, что в bitrix-ветке: каждый файл кладёт только
        # prepare_secret_file (symlink-veto, noclobber, права 644/0600 ДО
        # содержимого). Прежний SFTP-записчик шёл по symlink; отдельный chmod
        # после записи был вторым таким же окном.
        ok, why = prepare_secret_file(checker, path, content,
                                      mode='600' if secret else '644')
        if not ok:
            lines.append(f'❌ не записан {path}: {why}')
            failed = True
    if failed:
        lines.append('❌ установка НЕ завершена: часть файлов не записана, '
                     'сервер НЕ перезагружен, записанное можно откатить '
                     'резервами из строк выше')
        return lines, temps_used
    lines.append('  ✅ записаны fullchain.pem и privkey.pem в ' + base_dir)
    lines.append('')
    lines.extend(_reload_web(checker))
    lines.append('')
    lines.append('Укажите в конфиге веб-сервера (файлы vhost\'ов этот '
                 'инструмент не трогает):')
    lines.append('  nginx:   ssl_certificate     ' + paths['fullchain']
                 + ';')
    lines.append('           ssl_certificate_key ' + paths['key'] + ';')
    lines.append('  apache:  SSLCertificateFile    ' + paths['fullchain'])
    lines.append('           SSLCertificateKeyFile ' + paths['key'])
    return lines, temps_used


def _wipe_temps_on_abort(checker, tmp, exc):
    """Отмена/обрыв посреди прогона: секрет не переживает его, а хвост
    функции до такого выхода не доходит — убираем здесь и перевыбрасываем.

    remove_remote_path сам исключений не бросает (причину он возвращает), так
    что перевыбросить здесь можно только исходную причину прогона. Ключа в
    str(exc) быть не может: тексты модуля — причины команд, а не содержимое
    файлов; gui печатает именно str(exc).
    """
    notes = _clean_temps(checker, tmp)
    if notes:
        exc.args = (str(exc) + ' — временные PEM убраны не полностью: '
                    + '; '.join(notes) + '; вручную: rm -f '
                    + ' '.join(tmp),)
    return exc


def ssl_install_bitrix(checker, domain, crt_pem, chain_pem, key_pem):
    """Публичная установка BitrixVM: строки носителя + уборка временных PEM.

    Уборка — СНАРУЖИ основного тела и каналом cleanup: она обязана случиться
    на любом выходе. Прежний хвост функции не догонялся при «Операция
    отменена»: cancel() превращает следующую команду в исключение, а
    проверочный ключ к этому моменту уже лежит на диске — try/except закрывает
    и этот выход. Но обязана она и не трогать канал зря: при отказе до первой
    записи (битый домен, кривые секции, шифрованный ключ) временных файлов нет
    — просить rm нечего, и отчёт такой прогон идёт без единой команды.
    """
    tmp = temp_paths()
    try:
        lines, temps_used = _ssl_bitrix_lines(checker, tmp, domain, crt_pem,
                                              chain_pem, key_pem)
    except BaseException as exc:
        # BaseException, не Exception: KeyboardInterrupt/SystemExit — тоже
        # выходы, после которых проверочный приватный ключ не обязан жить в
        # /tmp (у гибнущего процесса своей уборки уже не будет).
        raise _wipe_temps_on_abort(checker, tmp, exc)
    if temps_used:
        notes = _clean_temps(checker, tmp)
        if notes:
            lines.append('⚠️ временные PEM убраны не полностью: '
                         + '; '.join(notes))
            lines.append('   вручную: rm -f ' + ' '.join(tmp))
    return '\n'.join(lines)


def ssl_install_plain(checker, domain, fullchain_pem, key_pem,
                      dir_path='/etc/ssl/diagtool'):
    """Публичная установка nginx/apache: строки носителя + уборка временных PEM.

    Уборка — только если проверочные файлы создавались (тот же закон, что у
    bitrix-обёртки): отказ на домене или секциях не имеет права стрелять
    командами в сервер. Исключение (отмена посреди прогона) убирает temp-пути
    безусловно — см. _wipe_temps_on_abort.
    """
    tmp = temp_paths()
    try:
        lines, temps_used = _ssl_plain_lines(checker, tmp, domain,
                                             fullchain_pem, key_pem, dir_path)
    except BaseException as exc:
        # См. bitrix-обёртку: гибель процесса не отменяет уборку ключа.
        raise _wipe_temps_on_abort(checker, tmp, exc)
    if temps_used:
        notes = _clean_temps(checker, tmp)
        if notes:
            lines.append('⚠️ временные PEM убраны не полностью: '
                         + '; '.join(notes))
            lines.append('   вручную: rm -f ' + ' '.join(tmp))
    return '\n'.join(lines)
