"""Тесты files.py: запись/чтение файлов с бэкапом, список конфигов, перезапуск служб.

Реального SSH/SFTP нет: команды перехватывает FakeSSH, запись файлов —
FakeSftpClient (оба из support.py).
"""
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from support import FakeSSH, FakeSftpClient
import files as files_mod

BACKUP_OK = [('mkdir -p', ('created', '', 0)), ('test -f', ('exists', '', 0))]


class _NoSftp:
    def open_sftp(self):
        raise IOError('ssh channel closed')


class TestWriteFile:
    def test_success_report_mentions_backup(self):
        client = FakeSftpClient()
        c = FakeSSH(routes=BACKUP_OK, client=client)
        out = files_mod.write_file(c, '/etc/nginx/nginx.conf', 'worker_processes auto;')
        assert '✅ Файл сохранён.' in out
        assert '/root/tech_support/configs/nginx.conf.' in out
        assert client.store['/etc/nginx/nginx.conf'] == 'worker_processes auto;'

    def test_missing_backup_warns_but_still_writes(self):
        client = FakeSftpClient()
        c = FakeSSH(routes=[('mkdir -p', ('created', '', 0)),
                            ('test -f', ('', '', 1))], client=client)
        out = files_mod.write_file(c, '/etc/nginx/nginx.conf', 'x')
        assert '⚠️ Не удалось создать резервную копию' in out
        assert '✅ Файл сохранён.' in out

    def test_write_failure_stops_report(self):
        c = FakeSSH(routes=BACKUP_OK, client=_NoSftp())
        out = files_mod.write_file(c, '/etc/x', 'data')
        assert '❌ Ошибка записи' in out
        assert 'Файл сохранён' not in out


class TestReadFile:
    """read_file — то, что редактор вставляет в окно, а потом пишет на сервер.

    Прежний вид (files.py):

        out, err, rc = checker.run(f'cat {q(filepath)} 2>/dev/null')
        if rc != 0:
            return f"❌ Ошибка чтения файла (rc={rc}): {err.strip()}"
        return out

    Сообщение обещало причину ПОСЛЕ двоеточия, а та же команда (2>/dev/null) её
    же и заглушала. Замер живьём (uid=1000, /bin/bash) — четыре разных
    состояния под одной подписью с ПУСТЫМ хвостом:

        locked.conf    rc=1 stdout=0 stderr=''  -> '❌ Ошибка чтения файла (rc=1): '
        nope.conf      rc=1 stdout=0 stderr=''  -> '❌ Ошибка чтения файла (rc=1): '
        lockd/x.conf   rc=1 stdout=0 stderr=''  -> '❌ Ошибка чтения файла (rc=1): '
        каталог        rc=1 stdout=0 stderr=''  -> '❌ Ошибка чтения файла (rc=1): '

    А вызывающий код (gui_admin._load) вставляет возвращённое в редактор и не
    различает текст ошибки и содержимое — «Сохранить» записало бы строку
    ошибки вместо конфига. Отсюда два замка: неудача ОБЯЗАНА начинаться с ❌
    (по этому распознаёт gui_files) и обязан называть причину словами, а не
    кодом возврата (rc=1 — не диагноз, он сливает права и отсутствие).
    """

    def test_returns_content(self):
        c = FakeSSH(routes=[('cat ', 'hello\n')])
        assert files_mod.read_file(c, '/etc/hosts') == 'hello\n'

    def test_returns_content_byte_exact(self):
        # Завершающий '\\n' — часть файла: редактор вернёт его на сервер.
        c = FakeSSH(routes=[('RFSTATE', ('RFSTATE readable\nworker 4;\n', '', 0))])
        assert files_mod.read_file(c, '/etc/nginx/nginx.conf') == 'worker 4;\n'

    def test_unreadable_names_rights_not_rc(self):
        c = FakeSSH(routes=[('RFSTATE',
                             ('RFSTATE unreadable', 'cat: Permission denied', 1))])
        out = files_mod.read_file(c, '/etc/shadow')
        assert out.startswith('❌')
        assert 'прав' in out
        assert 'rc=1' not in out          # код возврата — не диагноз
        assert 'не прочитан' in out       # строка не похожа на содержимое

    def test_missing_is_not_reported_as_no_rights(self):
        c = FakeSSH(routes=[('RFSTATE',
                             ('RFSTATE missing', 'cat: No such file or directory', 1))])
        out = files_mod.read_file(c, '/etc/nope')
        assert out.startswith('❌')
        assert 'нет' in out
        assert 'прав' not in out          # иначе оператор пойдёт менять chmod

    def test_directory_is_told_as_directory(self):
        c = FakeSSH(routes=[('RFSTATE',
                             ('RFSTATE isdir', 'cat: Is a directory', 1))])
        out = files_mod.read_file(c, '/etc/nginx')
        assert out.startswith('❌')
        assert 'каталог' in out

    def test_unconfirmed_answer_is_not_called_empty_file(self):
        # Ни маркера, ни содержимого: «я не узнал», а не «файл пустой».
        c = FakeSSH(routes=[])
        out = files_mod.read_file(c, '/etc/x')
        assert out.startswith('❌')
        assert 'не проверено' in out

    def test_missing_is_not_reported_as_rc_only(self):
        # РЕФОРМУЛИРОВКА запертого guard'а (объявленно). Прежняя версия
        # `assert 'No such file' in out` проверяла mock: ровно эту строку
        # продукт сам и глушил своим 2>/dev/null, в реальном ответе её не
        # было (замер). Инвариант («отказ назван») сохранён строго, но
        # проверяется состояние, а не цитата, которую продукт обязан был
        # потерять.
        c = FakeSSH(routes=[('cat ', ('', 'No such file or directory', 1))])
        out = files_mod.read_file(c, '/etc/nope')
        assert out.startswith('❌')
        assert 'нет' in out
        assert 'rc=1' not in out

    def test_sent_command_keeps_stderr_and_price(self):
        # Замок по ОТПРАВЛЕННОЙ команде (уроки 1.16–1.22): в 2>/dev/null
        # лежала единственная причина, а цену поднимать нельзя.
        c = FakeSSH(routes=[('RFSTATE', ('RFSTATE readable\nx\n', '', 0))])
        files_mod.read_file(c, '/etc/nginx/nginx.conf')
        cmd = c.find('RFSTATE')
        assert cmd is not None
        assert '2>/dev/null' not in cmd
        assert 'head -' not in cmd
        assert len(c.commands) == 1


def _ff(paths, dirs=(), total=None):
    """Ответ примитива find_files_cmd (v1.20): пути + FFCOUNT + FFDIR.

    Двойник обязан говорить то, что говорит настоящий сервер. Прежний маршрут
    `('ls -d', 'exists\\n')` возвращал ответ, которого `ls` не выдаёт НИКОГДА:
    `ls -d ПУТЬ` печатает сам путь, а `echo exists` идёт отдельной строкой.
    Живой замер (uid=1000, /bin/bash):

        out=$(ls -d /etc/hosts 2>/dev/null && echo "exists")   -> "/etc/hosts\\nexists"
        [ "$out" = exists ]                                    -> ложь всегда

    Из-за нереалистичного двойника тесты проходили над мёртвой функцией.
    """
    out = [f'FFDIR {st} {p}' for st, p in dirs] + list(paths)
    out.append(f'FFCOUNT {total if total is not None else len(paths)}')
    return '\n'.join(out) + '\n'


# «Всё просмотрено, файлов нет» — базовый ответ для путей, которых тест не
# касается: иначе в notes лезут признания о непросмотренных путях, и проверка
# конкретной причины становится неточной.
NOTHING = [('FFCOUNT', 'FFCOUNT 0\n')]


class TestGetConfigFiles:
    # Реалистичные ответы: `ls -1 <glob>` печатает ПОЛНЫЕ пути, а не имена.
    ROUTES = [('/etc/nginx/nginx.conf', _ff(['/etc/nginx/nginx.conf'])),
              ('/etc/nginx/sites-available',
               _ff(['/etc/nginx/sites-available/nginx.conf'])),
              ('/usr/local/fastpanel/etc/nginx',
               _ff(['/usr/local/fastpanel/etc/nginx/sites/default.conf']))]

    def test_common_paths_collected(self):
        files = files_mod.get_config_files(FakeSSH(routes=self.ROUTES), 'none')
        assert '/etc/nginx/nginx.conf' in files
        assert '/etc/nginx/sites-available/nginx.conf' in files
        assert files == sorted(files)
        assert len(files) <= 50

    def test_panel_paths_scanned_with_find(self):
        c = FakeSSH(routes=self.ROUTES)
        files = files_mod.get_config_files(c, 'fastpanel')
        assert '/usr/local/fastpanel/etc/nginx/sites/default.conf' in files
        assert c.find('find') is not None

    def test_no_existing_paths_returns_empty(self):
        assert files_mod.get_config_files(FakeSSH(), 'none') == []


class TestConfigFileSearchExplainsGaps:
    """Редактор обязан называть ПРИЧИНУ пустого списка, а не «файлы не найдены».

    Корневая причина найдена живьём, а не по чтению кода: условие
    `out.strip() == 'exists'` не истина никогда, поэтому на реальном сервере
    get_config_files возвращал [] ВСЕГДА — не только без прав. GUI честно
    рапортовал «Конфигурационные файлы не найдены» там, где все конфиги есть.
    """

    def test_existing_config_reaches_the_list(self):
        # Тот самый кейс, который на живом сервере не работал никогда.
        c = FakeSSH(routes=[('/etc/nginx/nginx.conf',
                             _ff(['/etc/nginx/nginx.conf']))] + NOTHING)
        files, notes = files_mod.get_config_files_info(c, 'none')
        assert '/etc/nginx/nginx.conf' in files and notes == []

    def test_closed_directory_names_the_reason(self):
        c = FakeSSH(routes=[('conf.d',
                             _ff([], dirs=[('noperm', '/etc/nginx/conf.d')]))]
                    + NOTHING)
        files, notes = files_mod.get_config_files_info(c, 'none')
        assert '/etc/nginx/conf.d' not in files
        assert any('conf.d' in n and 'прав' in n for n in notes)

    def test_closed_directory_is_not_called_absent(self):
        # Диагнозы противоположны и лечатся по-разному: «подними права» против
        # «проверь раскладку». Смешать их — отправить оператора не туда.
        c = FakeSSH(routes=[('conf.d',
                             _ff([], dirs=[('noperm', '/etc/nginx/conf.d')]))]
                    + NOTHING)
        _files, notes = files_mod.get_config_files_info(c, 'none')
        note = ' '.join(notes)
        assert 'нет на сервере' not in note

    def test_missing_directory_is_called_missing(self):
        c = FakeSSH(routes=[('conf.d',
                             _ff([], dirs=[('missing', '/etc/nginx/conf.d')]))]
                    + NOTHING)
        _files, notes = files_mod.get_config_files_info(c, 'none')
        assert any('conf.d' in n and 'нет на сервере' in n for n in notes)

    def test_readable_empty_directory_makes_no_complaint(self):
        # Каталог прочитан, файлов нет — честный ответ. Жалоба на него
        # обесценила бы настоящие предупреждения (то же решение, 1.24–1.26).
        c = FakeSSH(routes=[('conf.d',
                             _ff([], dirs=[('ok', '/etc/nginx/conf.d')]))])
        files, notes = files_mod.get_config_files_info(c, 'none')
        assert files == [] and notes == []

    def test_empty_directory_is_not_offered_as_a_file(self):
        # Прежний код добавлял в список сам путь каталога («иначе потеряются
        # одиночные конфиги») — а одиночный конфиг находится веткой файла и
        # так. Каталог в списке «файлов» = редактор открывает каталог как
        # файл, ровно isdir из v1.21.0.
        c = FakeSSH(routes=[('conf.d',
                             _ff([], dirs=[('ok', '/etc/nginx/conf.d')]))])
        files, _notes = files_mod.get_config_files_info(c, 'none')
        assert not [f for f in files if 'conf.d' in f]

    def test_closed_panel_directory_names_the_reason(self):
        c = FakeSSH(
            routes=[('/usr/local/mgr5/etc/nginx',
                     ('', "find: ‘/usr/local/mgr5/etc/nginx’: "
                      "Permission denied", 1))] + NOTHING)
        files, notes = files_mod.get_config_files_info(c, 'ispmanager')
        assert not [f for f in files if 'mgr5' in f]
        assert any('mgr5' in n and 'прав' in n for n in notes)

    def test_panel_files_are_listed_without_complaint(self):
        c = FakeSSH(
            routes=[('/usr/local/mgr5/etc/nginx',
                     '/usr/local/mgr5/etc/nginx/mgr.conf\n')] + NOTHING)
        files, notes = files_mod.get_config_files_info(c, 'ispmanager')
        assert '/usr/local/mgr5/etc/nginx/mgr.conf' in files and notes == []

    def test_missing_panel_directory_is_called_missing(self):
        c = FakeSSH(
            routes=[('/usr/local/mgr5/etc/nginx',
                     ('', "find: ‘/usr/local/mgr5/etc/nginx’: "
                      "No such file or directory", 1))] + NOTHING)
        _files, notes = files_mod.get_config_files_info(c, 'ispmanager')
        note = ' '.join(notes)
        assert 'mgr5' in note and 'нет на сервере' in note and 'прав' not in note

    def test_glob_paths_reach_the_shell_unquoted(self):
        # '/etc/php/*/php.ini' в кавычках q() — ls ищет файл со звездой в
        # имени и, естественно, не находит: php.ini терялся из редактора.
        c = FakeSSH(routes=NOTHING)
        files_mod.get_config_files_info(c, 'none')
        assert c.find('ls -1 /etc/php/*/php.ini') is not None

    def test_no_command_blinds_stderr(self):
        # В stderr лежит ровно та строка, где написана причина пустоты.
        c = FakeSSH(routes=NOTHING)
        files_mod.get_config_files_info(c, 'none')
        assert not [cmd for cmd in c.commands if '2>/dev/null' in cmd]

    def test_search_costs_one_command_per_path(self):
        # Различение состояний не имеет права дорожать: примитив v1.20 делает
        # состояние каталога и список ОДНОЙ командой, прежний код тратил две
        # слепые на каждый путь.
        c = FakeSSH(routes=NOTHING)
        files_mod.get_config_files_info(c, 'none')
        assert len(c.commands) == len(files_mod.CONFIG_PATHS)

    def test_wrapper_keeps_plain_list(self):
        # Совместимость: внешние потребители (diagnostic, старые тесты) ждут
        # список, а не кортеж.
        c = FakeSSH(routes=[('/etc/nginx/nginx.conf',
                             _ff(['/etc/nginx/nginx.conf']))] + NOTHING)
        assert files_mod.get_config_files(c, 'none') == ['/etc/nginx/nginx.conf']

    def test_unconfirmed_search_is_confessed(self):
        # Сервер не вернул ни FFDIR, ни FFCOUNT (обрыв, чужой ls): «пусто» по
        # такому прогону сказать нельзя — это «не проверено» (тот же закон,
        # что unchecked в read_file_info).
        c = FakeSSH()
        files, notes = files_mod.get_config_files_info(c, 'none')
        assert files == [] and notes

    def test_unconfirmed_paths_are_named_once(self):
        # Заметка — про сбой поиска, а не про каждый из 16 путей: 16 строк
        # в диалоге оператор не прочитает, а причину потеряет.
        c = FakeSSH()
        _files, notes = files_mod.get_config_files_info(c, 'none')
        assert len(notes) == 1


class TestReplaceIpv4ErrorBranch:
    def test_failed_find_shows_warning(self):
        # поведение как в исходнике: предупреждение, но операция продолжается
        c = FakeSSH(routes=[('find /etc', ('', "sed: couldn't write", 1)),
                            ('list-unit-files', 'no\n')])
        out = files_mod.replace_ipv4(c, '1.1.1.1', '2.2.2.2')
        assert '⚠️ Возможны ошибки (rc=1)' in out
        assert '✅ IPv4 заменён' in out


class TestReplaceIpv6BackupFailure:
    def test_etc_backup_failure_warns(self):
        c = FakeSSH(routes=[('tar czf', ('', 'tar: /etc: permission denied', 2))])
        out = files_mod.replace_ipv6(c, 'a::a', 'b::b')
        assert '⚠️ Не удалось создать резервную копию /etc' in out
        assert '✅ IPv6 заменён' in out

    def test_sed_failure_warns_but_operation_continues(self):
        # та же ветка, что уже закрыта для IPv4: rc!=0 у find/sed —
        # предупреждение с текстом STDERR, но отчёт не обрывается
        c = FakeSSH(routes=[('find /etc', ('', "sed: couldn't edit", 1))])
        out = files_mod.replace_ipv6(c, 'a::a', 'b::b')
        assert '⚠️ Возможны ошибки (rc=1)' in out
        assert "sed: couldn't edit" in out
        assert '✅ IPv6 заменён' in out


class TestRestartServices:
    # '^apache2.service' идёт раньше 'list-unit-files': игла — подстрока
    # команды grep -q "^apache2.service", первое совпадение выигрывает.
    ROUTES = [
        ('^apache2.service', 'no\n'),
        ('list-unit-files', 'yes\n'),
        ('is-active nginx', 'active\n'),
        ('is-active mysql', ['inactive\n', 'active\n']),
    ]

    def test_mixed_results(self):
        joined = '\n'.join(files_mod.restart_services(FakeSSH(routes=self.ROUTES)))
        assert '✅ nginx (reload) выполнен' in joined
        assert '✅ mysql перезапущен (fallback)' in joined
        assert '⏭️ apache2 не установлен' in joined

    def test_restart_failure_reported(self):
        # unit есть, но is-active всегда пусто -> fallback не спасает
        c = FakeSSH(routes=[('list-unit-files', 'yes\n')])
        joined = '\n'.join(files_mod.restart_services(c))
        assert '❌ nginx не запустился' in joined
        # для nginx: reload + is-active + restart(fallback) + is-active
        assert c.count('is-active nginx') == 2
