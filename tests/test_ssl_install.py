"""Тесты ssl_install.py: разбор секций, отказные ветки, полный прогон установок.

Реального SSH/SFTP нет — команды перехватывает FakeSSH, файлы пишет
FakeSftpClient из support.py. Ключевые проверяемые инварианты: приватный ключ
не имеет права появляться ни в командных строках, ни в тексте отчёта (только
в SFTP-контенте), целевой privkey.pem создаётся сразу 0600 (prepare_secret_file),
перезапись возможна только после принятого резерва, nginx/apache перезагружаются
ТОЛЬКО при пройденном configtest, проверочные PEM имеют непредсказуемое имя на
прогон и убираются на любом пути — включая «Операция отменена».
"""
import os
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from support import FakeSSH, FakeSftpClient
import ssl_install as si

CERT = ('-----BEGIN CERTIFICATE-----\n'
        'MIIB_CERTIFICATE_BODY_1\n'
        '-----END CERTIFICATE-----\n')
CERT2 = ('-----BEGIN CERTIFICATE-----\n'
         'MIIB_CERTIFICATE_BODY_2\n'
         '-----END CERTIFICATE-----')
KEY = ('-----BEGIN PRIVATE KEY-----\n'
       'MIIEvSECRET_KEY_MATERIAL_zzz\n'
       '-----END PRIVATE KEY-----\n')
KEY_ENC = ('-----BEGIN ENCRYPTED PRIVATE KEY-----\n'
           'MIIFSECRET_ENCRYPTED_zzz\n'
           '-----END ENCRYPTED PRIVATE KEY-----\n')


def ok_routes(store):
    """Маршруты успешного сервера: openssl, резерв (пустой каталог), systemd.

    Иглы -checkend и subjectAltName идут ПЕРЕД общей 'openssl x509 -in':
    первая совпавшая игла выигрывает, а команды этих опросов тоже содержат
    'openssl x509 -in' — без порядка тест жил бы на случайной подсказке
    (молчаливый двойник — закон support.py).
    """
    return [
        ('-checkend 2592000', ('Certificate will not expire', '', 0)),
        ('-checkend 0', ('Certificate will not expire', '', 0)),
        ('-ext subjectAltName',
         'X509v3 Subject Alternative Name: \n    DNS:site.ru\n'
         'subject=\n    commonName = site.ru\n'),
        ('openssl x509 -in', 'subject=CN = site.ru\n'
                             'issuer=CN = R3\nnotAfter=Jan  1 00:00:00 2099 '
                             'GMT\n'),
        ('openssl pkey -in', ('', '', 0)),
        ('="$(openssl pkey', ('', '', 0)),        # пара совпала (новая форма)
        ('openssl verify', 'OK\n'),
        ('ls -1 -p', ('', '', 0)),                # каталог целей пуст: absent
        ('id -u bitrix', '1001\n'),
        ('getent group', 'bitrix:x:1001:\n'),
        ('nginx -t', 'nginx: configuration file is ok\n'),
        # Составная проба присутствия (unit_presence_cmd) сама печатает
        # present/absent — двойник обязан отвечать языком парсера, а не
        # сырым списком юнитов (тот же закон, что в test_files.py).
        ('list-unit-files', 'present\n'),
        ('systemctl reload nginx', ('', '', 0)),
        ('apache2ctl configtest', ('', 'not found', 127)),
        ('httpd -t', ('', 'not found', 127)),
    ]


class TestSplitPem:
    def test_certs_keys_mixed(self):
        certs, keys, other, errors = si.split_pem(CERT + CERT2 + KEY)
        assert len(certs) == 2 and len(keys) == 1
        assert not errors and not other

    def test_crlf_normalized(self):
        certs, keys, _o, errors = si.split_pem((CERT + KEY).replace(
            '\n', '\r\n'))
        assert len(certs) == 1 and len(keys) == 1 and not errors

    def test_no_blocks_is_error_not_empty(self):
        certs, keys, _o, errors = si.split_pem('просто текст без PEM')
        assert certs == [] and keys == [] and errors

    def test_other_block_named(self):
        block = '-----BEGIN RSA PUBLIC KEY-----\nAAA\n-----END RSA PUBLIC KEY-----'
        _c, _k, other, errors = si.split_pem(CERT + block)
        assert other == ['RSA PUBLIC KEY'] and errors


class TestSafeDomain:
    def test_ok(self):
        # Регистр понижается: DNS регистронезависим, путь — нет; 'Site.RU'
        # создал бы второй каталог, который nginx не читает.
        assert si.safe_domain(' Site.RU ') == 'site.ru'
        assert si.safe_domain('xn--80aqc2a.xn--p1ai') == 'xn--80aqc2a.xn--p1ai'

    def test_rejects_path_and_garbage(self):
        for bad in ('', 'a b.ru', '../../etc', 'a;rm -rf /', 'a\nb',
                    '.ru', '-x.ru', 'a' * 300 + '.ru', 'a..b.ru'):
            assert si.safe_domain(bad) is None, bad

    def test_trailing_dot_stripped(self):
        assert si.safe_domain('site.ru.') == 'site.ru'


class TestCheckSections:
    def test_bitrix_ok_builds_fullchain(self):
        ok, errors, parts = si.check_sections('bitrix', crt=CERT, chain=CERT2,
                                              key=KEY)
        assert ok, errors
        assert parts['fullchain'].startswith(CERT.strip())
        assert CERT2 in parts['fullchain']
        assert parts['chain'].strip() == CERT2.strip()

    def test_bitrix_two_leafs_rejected(self):
        ok, errors, _p = si.check_sections('bitrix', crt=CERT + CERT2,
                                           chain=CERT2, key=KEY)
        assert not ok and any('crt' in e for e in errors)

    def test_key_section_with_cert_rejected(self):
        ok, errors, _p = si.check_sections('bitrix', crt=CERT, chain=CERT2,
                                           key=KEY + CERT)
        assert not ok and any('key' in e for e in errors)

    def test_two_keys_rejected(self):
        ok, errors, _p = si.check_sections('bitrix', crt=CERT, chain=CERT2,
                                           key=KEY + KEY)
        assert not ok

    def test_plain_fullchain_and_single_cert_flagged(self):
        ok, errors, parts = si.check_sections('plain', fullchain=CERT + CERT2,
                                              key=KEY)
        assert ok and not parts['chain_only']
        ok, errors, parts = si.check_sections('plain', fullchain=CERT, key=KEY)
        assert ok and parts['chain_only']

    def test_bitrix_requires_chain(self):
        ok, errors, _p = si.check_sections('bitrix', crt=CERT, chain='',
                                           key=KEY)
        assert not ok and any('chain' in e for e in errors)


class TestBitrixInstall:
    def test_happy_writes_backup_reload_and_wipes_temps(self):
        store = FakeSftpClient()
        c = FakeSSH(routes=ok_routes(store), client=store)
        out = si.ssl_install_bitrix(c, 'site.ru', CERT, CERT2, KEY)
        assert '✅' in out and 'записаны cert.pem' in out
        base = '/home/bitrix/dehydrated/certs/site.ru'
        assert set(store.store) >= {base + '/cert.pem', base + '/chain.pem',
                                    base + '/fullchain.pem',
                                    base + '/privkey.pem'}
        assert store.store[base + '/privkey.pem'] == KEY
        # ключ не имел права уехать ни в одну командную строку
        joined = '\n'.join(c.commands)
        assert 'SECRET_KEY_MATERIAL' not in joined
        assert 'chown bitrix:bitrix' in joined
        assert 'systemctl reload nginx' in joined
        # временные PEM убраны каналом cleanup: НЕ «rm -f <префикс>» (в иглу
        # попадает rm из prepare_secret_file — vacuous), а команда уборки с
        # проверкой факта STILL_THERE, нацеленная на temp-путь
        assert any(si.TMP_CERT_BASE in cmd and 'STILL_THERE' in cmd
                   for cmd in c.commands)
        assert 'убраны не полностью' not in out

    def test_pair_mismatch_aborts_before_writes(self):
        store = FakeSftpClient()
        routes = [('="$(openssl pkey', ('', '', 1)),       # pubkey НЕ совпал
                  ] + ok_routes(store)
        c = FakeSSH(routes=routes, client=store)
        out = si.ssl_install_bitrix(c, 'site.ru', CERT, CERT2, KEY)
        assert 'НЕ совпадает' in out
        assert store.store == {}
        assert 'systemctl reload nginx' not in '\n'.join(c.commands)

    def test_unparseable_cert_aborts(self):
        store = FakeSftpClient()
        routes = [('openssl x509 -in',
                   ('unable to load Certificate', '', 1))] + ok_routes(store)
        c = FakeSSH(routes=routes, client=store)
        out = si.ssl_install_bitrix(c, 'site.ru', CERT, CERT2, KEY)
        assert 'не разбирается openssl' in out
        assert store.store == {}

    def test_backup_veto_blocks_overwrite(self):
        # cert.pem В ИСХОДНИКЕ есть (виден в листинге), но cp не проходит:
        # право перезаписать даёт принятый резерв, отказ снимает всё.
        store = FakeSftpClient()
        base = '/home/bitrix/dehydrated/certs/site.ru'
        routes = [
            ('ls -1 -p', 'cert.pem\n'),                    # файл есть
            ('cp ', ('cp: cannot open', '', 1)),           # резерв не удался
        ] + ok_routes(store)
        c = FakeSSH(routes=routes, client=store)
        out = si.ssl_install_bitrix(c, 'site.ru', CERT, CERT2, KEY)
        assert 'отказ резерва снимает установку' in out
        assert store.store == {}

    def test_nginx_t_fail_blocks_reload(self):
        store = FakeSftpClient()
        routes = [('nginx -t',
                   ('nginx: [emerg] bad ssl directive', '', 1)),
                  ('list-unit-files', 'nginx.service enabled\n'),
                  ('apache2ctl configtest', ('', 'not found', 127)),
                  ('httpd -t', ('', 'not found', 127)),
                  ] + ok_routes(store)
        c = FakeSSH(routes=routes, client=store)
        out = si.ssl_install_bitrix(c, 'site.ru', CERT, CERT2, KEY)
        assert 'nginx -t НЕ пройден' in out
        assert 'systemctl reload nginx' not in '\n'.join(c.commands)
        # файлы при этом записаны — отчёт обязан это назвать честно
        assert 'НЕ перезагружен' in out

    def test_bad_domain_no_ssh_at_all(self):
        c = FakeSSH()
        out = si.ssl_install_bitrix(c, '../etc', CERT, CERT2, KEY)
        assert '❌' in out and c.commands == []

    def test_cleanup_leftover_is_named(self):
        store = FakeSftpClient()
        # Игла по ВЕРИФИЦИРУющей части уборки («[ -e путь»): rm -f с тем же
        # префиксом есть и в prepare_secret_file, а путь теперь со случайным
        # суффиксом — полная прежняя строка не совпала бы никогда.
        routes = [("[ -e " + si.TMP_CERT_BASE, 'STILL_THERE')] + \
            ok_routes(store)
        c = FakeSSH(routes=routes, client=store)
        out = si.ssl_install_bitrix(c, 'site.ru', CERT, CERT2, KEY)
        assert 'убраны не полностью' in out
        # и ручная подсказка называет реальный путь прогона, а не мертвяк
        assert 'rm -f ' + si.TMP_CERT_BASE in out


class TestPlainInstall:
    def test_happy_writes_directives_and_reload(self):
        store = FakeSftpClient()
        c = FakeSSH(routes=ok_routes(store), client=store)
        out = si.ssl_install_plain(c, 'site.ru', CERT + CERT2, KEY)
        base = '/etc/ssl/diagtool/site.ru'
        assert store.store[base + '/fullchain.pem'].startswith(
            CERT.strip())
        assert store.store[base + '/privkey.pem'] == KEY
        assert 'ssl_certificate     ' + base + '/fullchain.pem;' in out
        assert 'SSLCertificateKeyFile ' + base + '/privkey.pem' in out
        assert 'systemctl reload nginx' in '\n'.join(c.commands)
        assert 'SECRET_KEY_MATERIAL' not in '\n'.join(c.commands)

    def test_single_cert_fullchain_warned(self):
        store = FakeSftpClient()
        c = FakeSSH(routes=ok_routes(store), client=store)
        out = si.ssl_install_plain(c, 'site.ru', CERT, KEY)
        assert 'ОДИН сертификат' in out   # установка есть, но warning назван

    def test_apache_reload_when_no_nginx(self):
        store = FakeSftpClient()
        routes = [
            ('nginx -t', ('', 'not found', 127)),
            ('apache2ctl configtest', 'Syntax OK\n'),
            # Присутствие юнита решается составной пробой, чей stdout —
            # present/absent; иглы точные по имени, иначе один ответ
            # доставался бы и apache2, и httpd.
            ('apache2[.]service', 'absent'),
            ('httpd[.]service', 'present'),
            ('systemctl reload httpd', ('', '', 0)),
        ] + ok_routes(store)
        # ok_routes содержит nginx-маршруты — игла apache идёт раньше
        c = FakeSSH(routes=routes, client=store)
        out = si.ssl_install_plain(c, 'site.ru', CERT + CERT2, KEY)
        assert 'httpd' in out
        joined = '\n'.join(c.commands)
        assert 'systemctl reload httpd' in joined
        assert 'systemctl reload apache2' not in joined

    def test_custom_dir_used(self):
        store = FakeSftpClient()
        c = FakeSSH(routes=ok_routes(store), client=store)
        si.ssl_install_plain(c, 'site.ru', CERT + CERT2, KEY,
                             dir_path='/etc/ssl/custom/')
        assert '/etc/ssl/custom/site.ru/fullchain.pem' in store.store


class TestEncryptedKey:
    """Ключ под паролем: пару проверить нечем — отказ с лечением, до SSH."""

    def test_encrypted_pkcs8_rejected(self):
        ok, errors, _p = si.check_sections('plain', fullchain=CERT + CERT2,
                                           key=KEY_ENC)
        assert not ok and any('зашифрован' in e for e in errors)

    def test_proc_type_encrypted_rejected(self):
        legacy = ('-----BEGIN RSA PRIVATE KEY-----\n'
                  'Proc-Type: 4,ENCRYPTED\nDEK-Info: AES-256-CBC,00\n\n'
                  'TU9DS19NQVRFUklBTF8=\n'
                  '-----END RSA PRIVATE KEY-----\n')
        ok, errors, _p = si.check_sections('plain', fullchain=CERT + CERT2,
                                           key=legacy)
        assert not ok and any('зашифрован' in e for e in errors)

    def test_refusal_sends_no_commands(self):
        c = FakeSSH()
        out = si.ssl_install_plain(c, 'site.ru', CERT + CERT2, KEY_ENC)
        assert 'зашифрован' in out
        assert c.commands == []


class TestNameMatch:
    """Чистые правила CN/SAN — без сервера."""

    def test_san_wins_over_cn(self):
        names, read = si.cert_names_from_output(
            'X509v3 Subject Alternative Name: \n    DNS:site.ru, '
            'DNS:*.site.ru\nsubject=\n    commonName = other.ru\n')
        assert read and names == ['site.ru', '*.site.ru']

    def test_cn_fallback(self):
        names, read = si.cert_names_from_output(
            'subject=\n    commonName = site.ru\n')
        assert read and names == ['site.ru']

    def test_nothing_parsed_is_unchecked(self):
        names, read = si.cert_names_from_output('Unknown entry '
                                                'subjectAltName')
        assert names is None and not read

    def test_wildcard_covers_one_label(self):
        assert si.name_matches_domain('*.site.ru', 'www.site.ru')
        assert si.name_matches_domain('*.Site.RU', 'WWW.site.ru')
        assert not si.name_matches_domain('*.site.ru', 'site.ru')
        assert not si.name_matches_domain('*.site.ru', 'a.b.site.ru')
        assert si.name_matches_domain('SITE.ru', 'site.ru')
        assert not si.name_matches_domain('', 'site.ru')

    def test_mismatch_warns_without_veto(self):
        store = FakeSftpClient()
        routes = [('-ext subjectAltName',
                   'X509v3 Subject Alternative Name: \n    DNS:other.ru\n')] \
            + ok_routes(store)
        c = FakeSSH(routes=routes, client=store)
        out = si.ssl_install_plain(c, 'site.ru', CERT + CERT2, KEY)
        assert 'несовпадение имени' in out and 'other.ru' in out
        # ⚠️-ярус: установка состоялась, но оператор предупреждён
        assert 'записаны fullchain.pem' in out

    def test_wildcard_match_silent(self):
        store = FakeSftpClient()
        routes = [('-ext subjectAltName',
                   'X509v3 Subject Alternative Name: \n    DNS:*.site.ru\n')] \
            + ok_routes(store)
        c = FakeSSH(routes=routes, client=store)
        out = si.ssl_install_plain(c, 'www.site.ru', CERT + CERT2, KEY)
        assert 'несовпадение имени' not in out

    def test_unreadable_names_is_unchecked(self):
        store = FakeSftpClient()
        routes = [('-ext subjectAltName', 'Unknown entry subjectAltName\n')
                  ] + ok_routes(store)
        c = FakeSSH(routes=routes, client=store)
        out = si.ssl_install_plain(c, 'site.ru', CERT + CERT2, KEY)
        assert 'не прочитаны' in out and 'не проверено' in out


class TestExpiry:
    """Срок действия: вето по rc -checkend, предупреждение по 30 дням."""

    def test_expired_vetoes_before_writes(self):
        store = FakeSftpClient()
        routes = [('-checkend 0', ('Certificate will expire', '', 1))] \
            + ok_routes(store)
        c = FakeSSH(routes=routes, client=store)
        out = si.ssl_install_bitrix(c, 'site.ru', CERT, CERT2, KEY)
        assert 'истёк' in out and 'отменена' in out
        assert '2099' in out          # notAfter названа, а не «когда-то»
        assert store.store == {}
        joined = '\n'.join(c.commands)
        assert 'systemctl reload nginx' not in joined
        # отказ — но проверочный ключ обязан быть убран: командой уборки с
        # проверкой факта (STILL_THERE-ветка), а не любым `rm -f` префикса —
        # prepare_secret_file тоже делает rm и обесценивает такую иглу
        assert any(si.TMP_KEY_BASE in cmd and 'STILL_THERE' in cmd
                   for cmd in c.commands)

    def test_expiring_soon_warns_but_installs(self):
        store = FakeSftpClient()
        routes = [('-checkend 2592000', ('Certificate will expire', '', 1))] \
            + ok_routes(store)
        c = FakeSSH(routes=routes, client=store)
        out = si.ssl_install_plain(c, 'site.ru', CERT + CERT2, KEY)
        assert 'меньше 30 дней' in out
        assert 'записаны fullchain.pem' in out

    def test_checkend_unchecked_is_named(self):
        store = FakeSftpClient()
        routes = [('-checkend 0', ('', 'openssl: unknown option', 2))] \
            + ok_routes(store)
        c = FakeSSH(routes=routes, client=store)
        out = si.ssl_install_plain(c, 'site.ru', CERT + CERT2, KEY)
        assert 'срок действия не проверен' in out
        assert 'не спросили' in out


class TestSecretHygiene:
    """Инварианты секрета: argv, права, temps, отмена, stdin."""

    def _run_happy(self):
        store = FakeSftpClient()
        c = FakeSSH(routes=ok_routes(store), client=store)
        out = si.ssl_install_bitrix(c, 'site.ru', CERT, CERT2, KEY)
        return store, c, out

    def test_key_never_reaches_commands_or_report(self):
        store, c, out = self._run_happy()
        assert store.store  # прогон состоялся
        joined = '\n'.join(c.commands)
        assert 'SECRET_KEY_MATERIAL' not in joined
        assert 'CERTIFICATE_BODY' not in joined
        assert 'SECRET_KEY_MATERIAL' not in out   # и в тексте отчёта

    def test_target_key_file_is_prepared_before_content(self):
        store, c, out = self._run_happy()
        base = '/home/bitrix/dehydrated/certs/site.ru'
        prep = c.find(': > ' + base + '/privkey.pem')
        assert prep, 'целевой privkey.pem не создавался prepare_secret_file'
        assert 'umask 077' in prep and 'chmod 600' in prep
        # ключ не должен доставаться публичной chmod: 0600 дан ДО содержимого
        assert not [cmd for cmd in c.commands
                    if cmd.startswith('chmod 644') and 'privkey' in cmd]

    def test_temp_names_unpredictable_between_runs(self):
        # фиксированное имя — окно symlink-атаки между rm -f и : > (CWE-377)
        first, second = si.temp_paths(), si.temp_paths()
        assert set(first).isdisjoint(second)
        assert all(p.startswith(si.TMP_KEY_BASE) is (i == 2)
                   for i, p in enumerate(first))

    def test_pkey_queries_never_read_stdin(self):
        store, c, out = self._run_happy()
        for cmd in c.commands:
            if 'openssl pkey' in cmd:
                assert '< /dev/null' in cmd, cmd

    def test_chmod_644_failure_is_named(self):
        # Права публичного файла выставлены НА СОЗДАНИИ (prepare_secret_file,
        # mode='644'), отказ chmod помечен маркером CHMODFAIL и обязан назвать
        # беду и снять запись: прежний отдельный `chmod 644` после SFTP-записи
        # тонул в пустом err-канале и был вторым symlink-окном.
        store = FakeSftpClient()
        routes = [('chmod 644', ('CHMODFAIL', '', 1))] + ok_routes(store)
        c = FakeSSH(routes=routes, client=store)
        out = si.ssl_install_bitrix(c, 'site.ru', CERT, CERT2, KEY)
        assert 'не удалось выставить права 644' in out
        assert 'сервер НЕ перезагружен' in out
        assert not [cmd for cmd in c.commands if cmd.startswith('chmod 644')]

    def test_cancel_mid_run_wipes_temp_key(self):
        store = FakeSftpClient()

        class Cancelled(FakeSSH):
            """Отмена, как её делает ServerChecker._exec: следующая команда
            бросает, канал cleanup (rm) остаётся живым."""

            def run(self, cmd):
                if 'mkdir -p' in cmd:
                    raise Exception('Операция отменена')
                return FakeSSH.run(self, cmd)

        c = Cancelled(routes=ok_routes(store), client=store)
        with pytest.raises(Exception) as exc:
            si.ssl_install_bitrix(c, 'site.ru', CERT, CERT2, KEY)
        assert 'Операция отменена' in str(exc.value)
        assert 'SECRET_KEY_MATERIAL' not in str(exc.value)
        key_temps = [p for p in store.deleted if p.startswith(si.TMP_KEY_BASE)]
        assert key_temps, 'проверочный ключ пережил отмену'
        assert store.deleted[key_temps[0]] == KEY   # убран именно ключ
        assert not [p for p in store.store
                    if p.startswith(si.TMP_KEY_BASE)]


class TestPathAndVerifyHardening:
    """Ревью 1.33.x: форма openssl verify, пустые pubkey, symlink-каталог
    целей, явный список chown, валидация каталога — всё решаемо на shape и
    на отказе, значит обязано быть в тесте, а не в комментарии."""

    def test_safe_dir_path_absolute_normalized(self):
        assert si.safe_dir_path('/etc/ssl/diagtool/') == '/etc/ssl/diagtool'
        assert si.safe_dir_path('/etc/ssl/../../root') == '/root'
        assert si.safe_dir_path('etc/ssl') is None
        assert si.safe_dir_path('') is None

    def test_relative_dir_rejected_before_any_command(self):
        store = FakeSftpClient()
        c = FakeSSH(routes=ok_routes(store), client=store)
        out = si.ssl_install_plain(c, 'site.ru', CERT + CERT2, KEY,
                                   dir_path='etc/evil')
        assert 'абсолютным' in out
        assert store.store == {} and c.commands == []

    def test_verify_uses_untrusted_chain_and_root_bundle(self):
        # `openssl verify -CAfile <chain>` без корня падает ВСЕГДА (живьём
        # rc=2 'unable to get issuer certificate') — корректная форма
        # -CAfile <набор корней> -untrusted <chain>.
        store = FakeSftpClient()
        c = FakeSSH(routes=ok_routes(store), client=store)
        si.ssl_install_bitrix(c, 'site.ru', CERT, CERT2, KEY)
        cmd = c.find('openssl verify')
        assert '-untrusted' in cmd and 'ca-certificates.crt' in cmd

    def test_no_ca_bundle_is_unchecked_not_mismatch(self):
        store = FakeSftpClient()
        routes = [('openssl verify', 'NOCACERT\n')] + ok_routes(store)
        c = FakeSSH(routes=routes, client=store)
        out = si.ssl_install_bitrix(c, 'site.ru', CERT, CERT2, KEY)
        assert 'не спросили' in out and 'записаны cert.pem' in out

    def test_empty_pubkey_pair_is_unchecked_veto(self):
        # Две пустые подстановки были «равны» — ложное ✅ «одна пара».
        store = FakeSftpClient()
        routes = [('="$(openssl pkey', ('EMPTY', '', 0))] + ok_routes(store)
        c = FakeSSH(routes=routes, client=store)
        out = si.ssl_install_bitrix(c, 'site.ru', CERT, CERT2, KEY)
        assert 'не проверена' in out and 'отменена' in out
        assert 'одна пара' not in out
        assert store.store == {}

    def test_unexpected_rc_pair_is_unchecked_not_mismatch(self):
        # rc=124 (дедлайн канала) принадлежал [ -o ] тесту, а отчёт кричал
        # «НЕ совпадает» — того оператор не спрашивал.
        store = FakeSftpClient()
        routes = [('="$(openssl pkey', ('', 'deadline exceeded', 124))] \
            + ok_routes(store)
        c = FakeSSH(routes=routes, client=store)
        out = si.ssl_install_bitrix(c, 'site.ru', CERT, CERT2, KEY)
        assert 'мы не спросили' in out and 'НЕ совпадает' not in out

    def test_target_dir_symlink_refuses_write(self):
        # certs/<домен> на BitrixVM пишет bitrix (= скомпрометированный сайт):
        # mkdir -p принимает symlink-каталог как существующий.
        store = FakeSftpClient()
        routes = [('mkdir -p', 'DIRSYMLINK\n')] + ok_routes(store)
        c = FakeSSH(routes=routes, client=store)
        out = si.ssl_install_bitrix(c, 'site.ru', CERT, CERT2, KEY)
        assert 'symlink' in out and 'отменена' in out
        assert store.store == {}
        assert 'systemctl reload nginx' not in '\n'.join(c.commands)

    def test_chown_is_explicit_list_not_glob(self):
        # glob разыменовывал symlink-записи каталога (chown без -h).
        store = FakeSftpClient()
        c = FakeSSH(routes=ok_routes(store), client=store)
        si.ssl_install_bitrix(c, 'site.ru', CERT, CERT2, KEY)
        ch = c.find('chown bitrix:bitrix')
        assert '/*' not in ch and 'privkey.pem' in ch
