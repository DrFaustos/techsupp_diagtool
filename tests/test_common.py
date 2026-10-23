"""Тесты common.py: бэкапы, SFTP-запись, поиск/чтение файлов, извлечение доменов.

Реального SSH нет: команды перехватывает FakeSSH из support.py, SFTP — FakeSftpClient.
"""
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

import shlex

import pytest

from support import FakeSSH, FakeSftpClient
import common


BACKUP_OK = [('mkdir -p', ('created', '', 0)), ('test -f', ('exists', '', 0))]


class _RaisingClient:
    def open_sftp(self):
        raise IOError('ssh channel closed')


class TestEnsureBackupDir:
    def test_true_when_created(self):
        c = FakeSSH(routes=BACKUP_OK)
        assert common.ensure_backup_dir(c) is True

    def test_false_when_command_failed(self):
        c = FakeSSH(routes=[('mkdir -p', ('', 'permission denied', 1))])
        assert common.ensure_backup_dir(c) is False

    def test_creates_every_subdir(self):
        c = FakeSSH(routes=BACKUP_OK)
        common.ensure_backup_dir(c)
        for subdir in common.BACKUP_SUBDIRS.values():
            assert c.find(f'mkdir -p {subdir}') is not None


class TestCreateBackup:
    def test_returns_timestamped_path(self):
        c = FakeSSH(routes=BACKUP_OK)
        path = common.create_backup(c, '/etc/nginx/nginx.conf', 'configs')
        assert path is not None
        assert path.startswith('/root/tech_support/configs/nginx.conf.')
        assert path.endswith('.bak')

    def test_copies_original_to_backup(self):
        c = FakeSSH(routes=BACKUP_OK)
        path = common.create_backup(c, '/etc/nginx/nginx.conf', 'configs')
        cp = c.find('cp /etc/nginx/nginx.conf')
        assert cp is not None
        assert cp == f'cp /etc/nginx/nginx.conf {path} 2>&1'

    def test_missing_source_returns_none_and_no_copy(self):
        c = FakeSSH(routes=[('mkdir -p', ('created', '', 0)),
                            ('test -f', ('', '', 1))])
        assert common.create_backup(c, '/etc/nope.conf') is None
        assert c.find('cp ') is None

    def test_failed_copy_returns_none(self):
        c = FakeSSH(routes=[('mkdir -p', ('created', '', 0)),
                            ('test -f', ('', '', 1))])
        # источник есть, а вот проверка бэкапа (второй test -f) падает
        class Twice(FakeSSH):
            def __init__(self):
                super().__init__(routes=[('mkdir -p', ('created', '', 0))])
                self.tests = 0

            def run(self, cmd):
                self.commands.append(cmd)
                if cmd.startswith('test -f'):
                    self.tests += 1
                    # первый вызов — источник существует, второй — бэкапа нет
                    return ('exists', '', 0) if self.tests == 1 else ('', '', 1)
                return ('', '', 0)

        assert common.create_backup(Twice(), '/etc/nginx/nginx.conf') is None

    def test_backup_type_selects_subdir(self):
        c = FakeSSH(routes=BACKUP_OK)
        path = common.create_backup(c, '/etc/resolv.conf', 'dns')
        assert path.startswith('/root/tech_support/dns/resolv.conf.')

    def test_unknown_type_falls_back_to_configs(self):
        c = FakeSSH(routes=BACKUP_OK)
        path = common.create_backup(c, '/etc/x.conf', 'нет-такого-типа')
        assert path.startswith('/root/tech_support/configs/x.conf.')

    def test_path_with_spaces_is_quoted(self):
        c = FakeSSH(routes=BACKUP_OK)
        common.create_backup(c, '/etc/my conf/nginx.conf', 'configs')
        assert c.find("cp '/etc/my conf") is not None


class TestSaveCrontabBackup:
    def test_ok_path(self):
        c = FakeSSH(routes=[('mkdir -p', ('created', '', 0)),
                            ('crontab -l', ('ok', '', 0))])
        path = common.save_crontab_backup(c)
        assert path.startswith('/root/tech_support/crontab/crontab.')
        assert path.endswith('.bak')
        assert c.find(f'crontab -l > {path}') is not None

    def test_none_when_crontab_failed(self):
        c = FakeSSH(routes=[('mkdir -p', ('created', '', 0)),
                            ('crontab -l', ('', 'no crontab', 127))])
        assert common.save_crontab_backup(c) is None


class TestWriteRemoteFile:
    def test_writes_content_and_closes(self):
        client = FakeSftpClient()
        c = FakeSSH(client=client)
        ok, err = common.write_remote_file(c, '/etc/resolv.conf',
                                           'nameserver 1.1.1.1\n')
        assert ok is True and err is None
        assert client.store['/etc/resolv.conf'] == 'nameserver 1.1.1.1\n'
        assert client.closed == 1

    def test_open_sftp_failure_reported(self):
        c = FakeSSH(client=_RaisingClient())
        ok, err = common.write_remote_file(c, '/etc/x', 'data')
        assert ok is False
        assert 'Не удалось открыть SFTP' in err

    def test_write_error_reported(self):
        class ReadOnlyStore(FakeSftpClient):
            def open_sftp(self):
                conn = super().open_sftp()
                conn.open = lambda path, mode='r': (_ for _ in ()).throw(
                    IOError('read-only file system'))
                return conn

        c = FakeSSH(client=ReadOnlyStore())
        ok, err = common.write_remote_file(c, '/etc/x', 'data')
        assert ok is False
        assert 'read-only' in err


class TestFindFiles:
    """«Не найдено» говорится только когда посмотреть было на что.

    Прежний код: `out, _, _ = checker.run(f"ls -1 {pattern} 2>/dev/null |
    head -{limit}")`. Пустой вывод давали ЧЕТЫРЕ разных состояния, и все четыре
    подписывались одинаково (в `grep_logs_report` — «❌ Логи для домена не
    найдены»):

      1) файлов правда нет (каталог есть, пуст) — «логов нет» честно;
      2) каталога нет — другая раскладка/панель определена неверно;
      3) нет прав на каталог (логи 0750 root:adm, оператор под своим UID) —
         логи ЕСТЬ, но мы их никогда не увидим;
      4) лимит срезал список — часть логов просто не участвовала в отчёте.

    (2) и (3) для оператора противоположны: во втором случае менять параметры,
    в первом — права. Замерено живьём: честный rc у `ls` на все три случая —
    rc=2 («no such file» и «permission denied» неразличимы), различает только
    текст stderr и ветки `[ -d ]` / `[ -r ]` / `[ -x ]` по каталогу. Отсюда
    форма команды: состояние каталога спрашивается ДО ls, stderr не глушится,
    а число файлов считает awk (FFCOUNT), а не `head`, который резал список
    молча.
    """

    @staticmethod
    def _ok(*paths, total=None):
        """Ответ сервера по прочитанному каталогу: пути + FFCOUNT + FFDIR ok."""
        out = list(paths)
        out.append(f"FFCOUNT {total if total is not None else len(paths)}")
        return '\n'.join(out) + '\n'

    def test_lists_files(self):
        c = FakeSSH(routes=[('FFCOUNT', self._ok('/a.log', '/b.log'))])
        assert common.find_files(c, '/var/log/*.log') == ['/a.log', '/b.log']

    def test_limit_warning_names_the_real_total(self):
        # Прежний маркер говорил «показаны первые 20» и молчал о том, сколько
        # их всего: оператор не знал, сколько логов НЕ участвовало в отчёте.
        # Замер живьём: 30 файлов, head -20 -> «показаны первые 20».
        c = FakeSSH(routes=[('FFCOUNT', self._ok(*['/l%d.log' % i for i in range(20)],
                                                 total=30))])
        files = common.find_files(c, '/var/log/*.log', 20)
        assert files[:20] == ['/l%d.log' % i for i in range(20)]
        assert files[-1].startswith('⚠️')
        assert '20' in files[-1] and '30' in files[-1]

    def test_no_warning_when_nothing_was_cut(self):
        c = FakeSSH(routes=[('FFCOUNT', self._ok('/a.log'))])
        assert common.find_files(c, '/var/log/*.log', 20) == ['/a.log']

    def test_missing_directory_is_reported_as_such(self):
        # «Каталога нет» = раскладка/панель не те: менять надо параметры поиска.
        c = FakeSSH(routes=[('FFCOUNT', 'FFDIR missing /var/log/apache2\nFFCOUNT 0\n')])
        files = common.find_files(c, '/var/log/apache2/*.log', 20)
        # Пути — пустые; вместо них ⚠️-строка (её фильтруют как не-путь), т.е.
        # молчание невозможно: consumers увидят причину.
        assert [f for f in files if not f.startswith('⚠️')] == []
        assert any('Каталога' in f for f in files)
        info = common.find_files_info(c, '/var/log/apache2/*.log', 20)
        assert info['dirs'][0][0] == 'missing'
        assert 'нет' in info['notes'][0] and '/var/log/apache2' in info['notes'][0]

    def test_unreadable_directory_is_not_called_missing_files(self):
        # Решающий случай: логи есть, но оператор под своим UID их не увидит.
        # Прежний вывод был идентичен «логов нет» — оператор шёл искать другой
        # домен, а не права.
        c = FakeSSH(routes=[('FFCOUNT',
                             'FFDIR noperm /var/www/httpd-logs\nFFCOUNT 0\n')])
        info = common.find_files_info(c, '/var/www/httpd-logs/*.log', 20)
        assert info['paths'] == []
        assert info['dirs'][0][0] == 'noperm'
        note = ' '.join(info['notes'])
        assert 'прав' in note
        assert 'не найдено' not in note and 'не найдены' not in note

    def test_readable_empty_directory_has_no_alibi(self):
        # Каталог прочитан, файлов нет — вот это и есть честное «не найдено»,
        # и выдумывать ему «нет прав» нельзя.
        c = FakeSSH(routes=[('FFCOUNT', 'FFDIR ok /var/log/nginx\nFFCOUNT 0\n')])
        info = common.find_files_info(c, '/var/log/nginx/*.log', 20)
        assert info['paths'] == [] and info['notes'] == []
        assert info['dirs'][0][0] == 'ok'

    def test_partial_access_keeps_the_paths_it_got(self):
        # Панельные паттерны раскрываются в несколько каталогов: один закрыт,
        # другой читается — найденное терять нельзя, но и молчать нельзя.
        c = FakeSSH(routes=[('FFCOUNT',
                             'FFDIR noperm /var/www/a/data/logs\n'
                             'FFDIR ok /var/www/b/data/logs\n'
                             '/var/www/b/data/logs/x.log\nFFCOUNT 1\n')])
        files = common.find_files(c, '/var/www/*/data/logs/*.log', 20)
        assert files == ['/var/www/b/data/logs/x.log', files[-1]]
        assert files[-1].startswith('⚠️') and 'прав' in files[-1]

    def test_legacy_warning_line_is_not_treated_as_a_path(self):
        # Обратная совместимость: старые/чужие выводы могут нести «⚠️ ...»
        # строкой — она не путь (её фильтруют 4 потребителя).
        c = FakeSSH(routes=[('FFCOUNT', '/a.log\n⚠️ (показаны первые 20 файлов)\n')])
        assert common.find_files(c, '/var/log/*.log', 20) == ['/a.log',
                                                             '⚠️ (показаны первые 20 файлов)']

    def test_answer_without_markers_keeps_paths_and_invents_nothing(self):
        # Ответ без FFCOUNT (обрыв, чужая реализация): пути сохраняем, total не
        # выдумываем — закон «не проверено ≠ 0» из v1.16-v1.19.
        c = FakeSSH(routes=[('ls -1', '/a.log\n/b.log\n')])
        info = common.find_files_info(c, '/var/log/*.log', 20)
        assert info['paths'] == ['/a.log', '/b.log']
        assert info['total'] is None
        assert info['dirs'] == []

    def test_reader_stderr_is_not_thrown_away(self):
        # Поведенческий замок по ОТПРАВЛЕННОЙ команде (не по исходнику):
        # прежнее 2>/dev/null теряло «Permission denied» — единственную строку,
        # объясняющую пустоту.
        c = FakeSSH(routes=[('FFCOUNT', self._ok('/a.log'))])
        common.find_files(c, '/var/log/nginx/*.log', 20)
        cmd = c.find('ls -1')
        assert cmd is not None
        assert '2>/dev/null' not in cmd
        assert 'head -' not in cmd          # срезка больше не молчит
        assert 'PIPESTATUS' not in cmd      # dash: «Bad substitution»

    def test_glob_is_not_quoted_on_purpose(self):
        # pattern — shell-glob: его нельзя экранировать, иначе ls ничего не
        # найдёт. Прежний замок искал «ls -1 /var/log/nginx/*.log» буквально и
        # сдох бы на любой форме с переменной; запираю смысл: glob дошёл до ls
        # без кавычек вокруг переменной.
        c = FakeSSH(routes=[('FFCOUNT', self._ok('/a.log'))])
        common.find_files(c, '/var/log/nginx/*.log', 20)
        cmd = c.find('ls -1')
        assert '/var/log/nginx/*.log' in cmd
        assert 'ls -1 "$P"' not in cmd and "ls -1 '$P'" not in cmd

    def test_directory_state_is_asked_before_listing(self):
        # rc=ls различает только «всё хорошо» и «что-то нет» (замер: rc=2 и для
        # «нет файла», и для «нет прав»), поэтому состояние каталога спрашивается
        # отдельной POSIX-веткой ДО ls.
        c = FakeSSH(routes=[('FFCOUNT', self._ok('/a.log'))])
        common.find_files(c, '/var/log/nginx/*.log', 20)
        cmd = c.find('ls -1')
        assert cmd.index('-d "') < cmd.index('ls -1')
        assert '-r "' in cmd and '-x "' in cmd

    def test_price_is_one_command(self):
        c = FakeSSH(routes=[('FFCOUNT', self._ok('/a.log'))])
        common.find_files(c, '/var/log/nginx/*.log', 20)
        assert len(c.commands) == 1


class TestFindFile:
    def test_returns_first_hit(self):
        c = FakeSSH(routes=[('apache2', ''), ('nginx', '/etc/nginx/nginx.conf\n')])
        got = common.find_file(c, ['/etc/apache2/apache2.conf', '/etc/nginx/nginx.conf'])
        assert got == '/etc/nginx/nginx.conf'

    def test_none_when_nothing_exists(self):
        c = FakeSSH(routes=[('ls -1', '   \n')])
        assert common.find_file(c, ['/a', '/b']) is None

    # --- почему None: «нет файла» и «нет прав» лечатся противоположно ---

    def test_unreadable_dir_is_not_reported_as_absent_file(self):
        # Конфиг есть, но оператор под своим UID его не увидит никогда. Прежний
        # ответ был неотличим от «файла нет» — оператор шёл искать другой путь.
        c = FakeSSH(routes=[('ls -1', 'FFDIR noperm /etc/nginx\nFFCOUNT 0\n')])
        path, notes = common.find_file_info(c, ['/etc/nginx/nginx.conf'])
        assert path is None
        assert notes and 'прав' in notes[0]

    def test_missing_dir_names_the_path(self):
        c = FakeSSH(routes=[('ls -1', 'FFDIR missing /etc/httpd\nFFCOUNT 0\n')])
        path, notes = common.find_file_info(c, ['/etc/httpd/conf/httpd.conf'])
        assert path is None
        assert notes and '/etc/httpd' in notes[0]

    def test_found_path_has_no_invented_reason(self):
        c = FakeSSH(routes=[('ls -1', '/etc/nginx/nginx.conf\nFFCOUNT 1\n')])
        path, notes = common.find_file_info(c, ['/etc/nginx/nginx.conf'])
        assert path == '/etc/nginx/nginx.conf'
        assert notes == []


class TestReadFileContent:
    """«Прочитано пусто», «нет прав», «файла нет» — три разных ответа.

    Прежний код: `out, _, rc = checker.run(f'cat {q(path)} 2>/dev/null')`;
    `if rc != 0: return None`. Замерено живьём (uid=1000):

      ok.conf          rc=0 stdout=18      empty.conf  rc=0 stdout=0
      locked.conf      rc=1 stdout=0  stderr=cat: …: Permission denied
      nope.conf        rc=1 stdout=0  stderr=cat: …: No such file or directory
      locked_dir/x.conf rc=1 stdout=0 stderr=cat: …: Permission denied

    То есть rc=1 сливает «нет прав» и «нет файла» в одно None, а 2>/dev/null
    выбрасывал единственную строку, где написана причина. Потребители гасят
    None в `or ''` (discovery.py), поэтому «конфиг пустой» и «я не имел права
    его читать» для оператора неразличимы.

    И та же грабля v1.20 на уровне ФАЙЛА: `[ ! -e ]` у файла внутри закрытого
    каталога отвечает «нет файла» (stat невозможен без x на каталог), хотя
    система говорит Permission denied. Поэтому cat вызывается ВСЕГДА — его
    stderr свидетель, а python при Permission denied перекрывает missing.
    """

    @staticmethod
    def _ans(state, body=''):
        return f'RFSTATE {state}\n' + body

    def test_returns_text(self):
        c = FakeSSH(routes=[('cat ', 'hello\n')])
        assert common.read_file_content(c, '/etc/x') == 'hello\n'

    def test_none_on_error_rc(self):
        c = FakeSSH(routes=[('cat ', ('', 'No such file', 1))])
        assert common.read_file_content(c, '/etc/x') is None

    def test_path_quoted(self):
        c = FakeSSH(routes=[('cat ', '')])
        common.read_file_content(c, '/etc/my file')
        assert c.find("cat '/etc/my file'") is not None

    def test_readed_empty_file_is_not_an_error(self):
        # Пустой файл — прочитанный файл. Его нельзя записывать в «не удалось».
        c = FakeSSH(routes=[('RFSTATE', (self._ans('readable'), '', 0))])
        info = common.read_file_info(c, '/etc/empty')
        assert info['state'] == 'readable'
        assert info['content'] == ''
        assert info['reason'] is None

    def test_unreadable_is_not_missing(self):
        c = FakeSSH(routes=[('RFSTATE',
                             (self._ans('unreadable'), 'cat: Permission denied', 1))])
        info = common.read_file_info(c, '/etc/shadow')
        assert info['state'] == 'unreadable'
        assert info['content'] is None
        assert 'прав' in info['reason']

    def test_missing_says_missing(self):
        c = FakeSSH(routes=[('RFSTATE',
                             (self._ans('missing'), 'cat: No such file', 1))])
        info = common.read_file_info(c, '/etc/postfix/virtual')
        assert info['state'] == 'missing'
        assert info['content'] is None
        assert 'нет' in info['reason']

    def test_permission_denied_overrides_the_missing_test(self):
        # РЕШАЮЩИЙ случай (замер живьём): у файла внутри закрытого каталога
        # `[ -e ]` отвечает «нет файла», а система — «Permission denied».
        # Верить тесту — значит отправить оператора проверять раскладку вместо
        # прав. Тот же закон, что salv в 1.20.0, но уровнем ниже.
        c = FakeSSH(routes=[('RFSTATE',
                             (self._ans('missing'),
                              'cat: /var/www/x/data/logs/e.log: Permission denied',
                              1))])
        info = common.read_file_info(c, '/var/www/x/data/logs/e.log')
        assert info['state'] == 'unreadable'
        assert 'прав' in info['reason']

    def test_empty_answer_is_not_verified(self):
        # Ни маркера, ни содержимого, ни stderr: не «файла нет», а «не проверено»
        # (закон 1.16-1.20).
        c = FakeSSH(routes=[])
        info = common.read_file_info(c, '/etc/x')
        assert info['content'] is None
        assert info['state'] == 'unchecked'
        assert 'не проверено' in info['reason']

    def test_state_marker_is_the_first_line_so_content_cannot_spoof_it(self):
        # Замер: файл, первая строка которого «RFSTATE readable», не должен
        # выглядеть как служебный ответ — наш маркер стоит ПЕРВЫМ, контент со
        # второй строки.
        c = FakeSSH(routes=[('RFSTATE',
                             ('RFSTATE readable\nRFSTATE readable\nданные', '', 0))])
        info = common.read_file_info(c, '/etc/x')
        assert info['content'] == 'RFSTATE readable\nданные'

    def test_reader_stderr_is_not_thrown_away(self):
        # Замок по ОТПРАВЛЕННОЙ команде (урок 1.16): 2>/dev/null терял причину.
        c = FakeSSH(routes=[('RFSTATE', (self._ans('readable'), '', 0))])
        common.read_file_info(c, '/etc/x')
        cmd = c.find('cat ')
        assert cmd is not None
        assert '2>/dev/null' not in cmd

    def test_cat_runs_even_when_state_test_failed(self):
        # cat обязан вызываться и при unreadable/missing: его stderr — единственный
        # свидетель, отличающий права от отсутствия.
        c = FakeSSH(routes=[('RFSTATE', (self._ans('missing'), '', 1))])
        common.read_file_info(c, '/etc/x')
        cmd = c.find('cat ')
        assert cmd is not None
        assert 'RFSTATE' in cmd            # состояние и чтение — одна команда
        assert len(c.commands) == 1         # цена не выросла

    def test_directory_is_not_read_as_empty_file(self):
        c = FakeSSH(routes=[('RFSTATE',
                             (self._ans('isdir'), 'cat: Is a directory', 1))])
        info = common.read_file_info(c, '/etc/nginx')
        assert info['state'] == 'isdir'
        assert info['content'] is None


class TestReadAnswerIsByteExact:
    """Содержимое файла возвращается БАЙТ В БАЙТ: завершающий перевод строки —
    часть файла, а не оформление ответа.

    Прежний парсер собирал тело как `'\\n'.join(splitlines()[1:])`. Замер
    живьём (read_file_info против НАСТОЯЩИХ файлов, /bin/bash, uid=1000):
    4 из 6 форматов вернулись укороченными —

        'worker 4;\\n'      -> 'worker 4;'      <<< потеря
        'a;\\nb;\\n'        -> 'a;\\nb;'         <<< потеря
        'a;\\n\\n\\n'       -> 'a;\\n\\n'        <<< потеря
        'a;\\r\\nb;\\r\\n'  -> 'a;\\nb;'         <<< потеря (и \\r тоже)

    Для лога это безразлично (его считают splitlines'ом), для редактора конфига
    — тихая порча данных: `gui_files` при сохранении делает rstrip('\\n'), так
    что «открыл → Сохранить» без правок переписывает конфиг без завершающей
    строки. Различать «не прочитал» и «прочитал иначе» мало — надо ещё не
    соврать в самом прочитанном.
    """

    @staticmethod
    def _read(body):
        c = FakeSSH(routes=[('RFSTATE', ('RFSTATE readable\n' + body, '', 0))])
        return common.read_file_info(c, '/etc/x')['content']

    def test_trailing_newline_survives(self):
        assert self._read('worker 4;\n') == 'worker 4;\n'

    def test_several_trailing_newlines_survive(self):
        assert self._read('a;\n\n\n') == 'a;\n\n\n'

    def test_crlf_is_not_rewritten(self):
        # splitlines() режет по \\r\\n и выбрасывает сам \\r: файл Windows-
        #образца вернулся бы с изменёнными окончаниями строк.
        assert self._read('a;\r\nb;\r\n') == 'a;\r\nb;\r\n'

    def test_body_without_trailing_newline_is_unchanged(self):
        assert self._read('worker 4;') == 'worker 4;'

    def test_empty_body_is_empty_string(self):
        assert self._read('') == ''

    def test_answer_without_marker_is_passed_verbatim(self):
        # Обрыв/чужая реализация: что пришло, то и содержимое — додумывать
        # нельзя, в том числе отрезая у него конец.
        c = FakeSSH(routes=[('cat ', 'hello\n')])
        assert common.read_file_content(c, '/etc/x') == 'hello\n'

    def test_marker_still_stripped_from_body(self):
        # Фикс не должен вернуть маркер в содержимое: он служебный.
        content = self._read('worker 4;\n')
        assert 'RFSTATE' not in content


class TestGetDomainFromConfig:
    RAW = ('server {\n'
           '    server_name example.com www.example.com;\n'
           '}\n')

    def test_extracts_domains(self):
        c = FakeSSH(routes=[('grep -h', 'example.com\nwww.example.com\n')])
        assert sorted(common.get_domain_from_config(c, '/etc/nginx/vhosts/x')) == \
            ['example.com', 'www.example.com']

    def test_filters_wildcards_placeholders(self):
        out = 'example.com\n*.example.com\n_\nlocalhost\ndefault_server\nнет-точки\n'
        c = FakeSSH(routes=[('grep -h', out)])
        assert common.get_domain_from_config(c, '/etc/nginx/vhosts/x') == ['example.com']

    def test_empty_when_no_server_name(self):
        c = FakeSSH(routes=[('grep -h', '')])
        assert common.get_domain_from_config(c, '/etc/nginx/vhosts/x') == []

    def test_config_path_quoted(self):
        c = FakeSSH(routes=[('grep -h', '')])
        common.get_domain_from_config(c, '/etc/nginx/vhosts/we; rm -rf /')
        cmd = c.find('grep -h')
        assert "'/etc/nginx/vhosts/we; rm -rf /'" in cmd


# ==================== СЛУЖЕБНЫЙ КАНАЛ: ПРАВА И УБОРКА СЕКРЕТОВ ====================
class TestServiceRun:
    def test_prefers_cleanup_channel(self):
        # У ServerChecker есть cleanup(): обязан использоваться он, иначе rm из
        # finally не доживает до уборки после нажатия «Стоп»
        class WithCleanup(FakeSSH):
            def cleanup(self, cmd):
                self.commands.append('CLEANUP:' + cmd)
                return ('', '', 0)

        c = WithCleanup()
        assert common.service_run(c, 'rm -f /tmp/x') == ('', '', 0)
        assert c.commands == ['CLEANUP:rm -f /tmp/x']

    def test_falls_back_to_run_for_plain_checkers(self):
        # Заглушки и хост-классы без cleanup() не должны ломаться
        class Plain:
            def __init__(self):
                self.seen = []

            def run(self, cmd):
                self.seen.append(cmd)
                return ('', '', 0)

        host = Plain()
        common.service_run(host, 'chmod 600 /tmp/x')
        assert host.seen == ['chmod 600 /tmp/x']


class TestPrepareSecretFile:
    SECRET = '[client]\npassword=sup3r\n'

    def test_file_is_0600_before_password_lands(self):
        store = FakeSftpClient()
        c = FakeSSH(client=store)
        ok, why = common.prepare_secret_file(c, '/tmp/.x.cnf', self.SECRET)
        assert ok is True and why is None
        prep = c.commands[0]
        # Права ставятся в ТОМ ЖЕ вызове, что и создание: между «файл есть» и
        # «файл 0600» нет ни одного SSH-раунда — ни окна чтения всеми, ни места
        # для отмены (проверено локально: umask 077 -> 600, umask 022 -> 644)
        assert 'umask 077' in prep and 'chmod 600' in prep
        assert prep.index('umask 077') < prep.index(': >') < prep.index('chmod 600')
        assert prep.index('chmod 600') < prep.index('NOWRITE')
        # пароль прилетает позже и другим каналом (SFTP), а не командой
        assert store.store['/tmp/.x.cnf'] == self.SECRET
        assert 'sup3r' not in ' '.join(c.commands)

    def test_stale_file_removed_before_creation(self):
        # По фиксированному пути мог лежать чужой файл или symlink: SFTP-запись
        # по symlink затёрла бы его цель, поэтому первым делом rm -f
        store = FakeSftpClient()
        c = FakeSSH(client=store)
        common.prepare_secret_file(c, '/tmp/.x.cnf', self.SECRET)
        prep = c.commands[0]
        assert prep.index('rm -f') < prep.index(': >')

    def test_nowrite_is_reported_and_nothing_is_written(self):
        store = FakeSftpClient()
        c = FakeSSH(routes=[(': >', ('NOWRITE\n', 'Read-only file system', 0))],
                    client=store)
        ok, why = common.prepare_secret_file(c, '/tmp/.x.cnf', self.SECRET)
        assert ok is False and 'нельзя писать' in why and 'Read-only' in why
        assert store.store == {}                     # секрет не записан

    def test_write_failure_wipes_the_empty_file(self):
        # SFTP упал ПОСЛЕ создания файла: оставленный 0600-файл по фиксированному
        # пути — мусор, который следующий запуск унаследовал бы
        c = FakeSSH(client=None)                     # open_sftp недоступен
        ok, why = common.prepare_secret_file(c, '/tmp/.x.cnf', self.SECRET)
        assert ok is False and 'не удалось записать' in why
        assert any(cmd.startswith('rm -f') for cmd in c.commands), c.commands

    def test_transport_exception_becomes_reason(self):
        class Dead(FakeSSH):
            def cleanup(self, cmd):
                raise OSError('connection reset')

        ok, why = common.prepare_secret_file(Dead(), '/tmp/.x.cnf', self.SECRET)
        assert ok is False and 'connection reset' in why


class TestRemoveRemotePath:
    def test_success_is_silent(self):
        c = FakeSSH()
        assert common.remove_remote_path(c, '/tmp/d') == (True, None)

    def test_checks_fact_not_exit_code(self):
        # rm -rf молчит и когда не смог (read-only /tmp, права): факт проверяем
        # [ -e ], иначе «файл удалён» было бы неправдой
        c = FakeSSH(routes=[('echo STILL_THERE', ('STILL_THERE\n', '', 0))])
        ok, why = common.remove_remote_path(c, '/tmp/d')
        assert ok is False and 'путь остался' in why and '/tmp/d' in why

    def test_non_recursive_flag_for_files(self):
        c = FakeSSH()
        common.remove_remote_path(c, '/tmp/x.cnf', recursive=False)
        assert c.commands[0].startswith('rm -f ')

    def test_path_with_quote_stays_one_argument(self):
        # Одинарная кавычка в пути обязана быть экранирована: иначе путь
        # распадается на два аргумента, и rm получает лишнее (а проверка [ -e ]
        # смотрит не в тот файл).
        c = FakeSSH()
        common.remove_remote_path(c, "/tmp/we're", recursive=False)
        first = c.commands[0].split(';')[0].strip()
        parts = shlex.split(first)
        assert parts == ['rm', '-f', "/tmp/we're", '2>/dev/null'], parts


    def test_transport_exception_becomes_reason(self):
        class Dead(FakeSSH):
            def cleanup(self, cmd):
                raise OSError('connection reset')

        ok, why = common.remove_remote_path(Dead(), '/tmp/d')
        assert ok is False and 'connection reset' in why
