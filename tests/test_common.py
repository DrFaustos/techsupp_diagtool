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

    # ============ 1.32.3: глоб не влез в argv (E2BIG) =====================
    # Замер живьём (парк 20 000 файлов конфигураций, ulimit -s 1024): боевая
    # команда давала rc=0, FFDIR ok, FFCOUNT 0 и в stderr
    # «Argument list too long». Отчёт говорил «файлов нет, проверено» там, где
    # ls даже не запустилась: код возврата конвейера принадлежит awk, а не ls.
    # Различает случай только rc самой ls — 126 (замерено в bash и dash, при
    # LC_ALL=C и C.UTF-8), тогда как «глоб не раскрылся» — это rc=2.
    # Порядок строк СПИСАН С ЖИВОГО ЗАМЕРА (probe1323.py, bash и dash дают
    # одинаково): 'FFRC 126\nFFCOUNT 0\n'. Маркер идёт ДО FFCOUNT, потому что
    # печатается в канал до END-блока awk. Первая версия фикстуры была написана
    # с обратным порядком - по представлению о выводе, а не по замеру.
    E2BIG = ('FFDIR ok /etc/nginx/conf.d\n'
             'FFRC 126\n'
             'FFCOUNT 0\n')
    E2BIG_ERR = '/bin/sh: line 1: /usr/bin/ls: Argument list too long'

    def test_ls_that_never_ran_is_not_reported_as_no_files(self):
        # Главный кейс слайса: каталог существует и читается (FFDIR ok), но
        # список не был получен. Прежний вывод был неотличим от честной пустоты,
        # а лечение противоположное: не «домена нет», а «сужайте паттерн».
        c = FakeSSH(routes=[('ls -1', (self.E2BIG, self.E2BIG_ERR, 0))])
        info = common.find_files_info(c, '/etc/nginx/conf.d/*.conf', 20)
        assert info['paths'] == []
        # total обязан стать None, а не 0: выдуманное число — закон 1.16-1.19.
        assert info['total'] is None, (
            'total=0 при несостоявшейся ls — это число, которого мы не видели')
        note = ' '.join(info['notes'])
        assert note, 'пустота без объяснения: оператор прочитает её как «нет файлов»'
        assert 'слишком много' in note.lower(), note
        assert 'не найдено' not in note and 'не найдены' not in note, note
        # Список от примитива тоже не имеет права притворяться списком.
        assert [f for f in common.find_files(c, '/etc/nginx/conf.d/*.conf', 20)
                if not f.startswith('⚠️')] == []

    def test_rc_marker_is_not_a_path(self):
        # Контрпример новой строке протокола. Маркер, который парсер не знает,
        # уезжает в paths — и оператор читает «FFRC 126» как имя домена или
        # лога. Тот же класс, что двойник, заговоривший старым языком (1.32.0).
        paths, dirs, total, ls_rc = common.parse_find_answer(self.E2BIG)
        assert paths == [], paths
        assert any(st == 'ok' for st, _p in dirs), dirs
        assert total is None
        # Код обязан доходить до парсера: без него «ls не исполнилась»
        # неотличимо от «файлов нет», и весь слайс теряет предмет.
        assert ls_rc == 126, ls_rc

    def test_command_captures_ls_rc_before_the_pipeline(self):
        # Поведенческий замок по ОТПРАВЛЕННОЙ команде. rc конвейера — это rc
        # awk; поэтому код ls обязан сниматься внутри группы, ДО первой печати
        # в канал. PIPESTATUS под dash — «Bad substitution» (замерено), значит
        # единственный POSIX-способ — группа со снятием $?.
        cmd = common.find_files_cmd('/etc/nginx/conf.d/*.conf', 20)
        assert 'FFRC' in cmd, 'код возврата ls снова тонет под awk: %r' % cmd
        assert 'PIPESTATUS' not in cmd
        assert cmd.index('FFRC') < cmd.index('awk'), (
            'маркер снимается после awk — то есть уже чужой код')
        # «не раскрылось» (rc=2) и «не исполнилось» (rc=126) обязаны остаться
        # различимыми: глотать оба кода нельзя.
        assert '$?' in cmd

    def test_zero_rc_marker_keeps_the_honest_emptiness(self):
        # Обратная сторона: FFRC 0 — обычная проверка, и выдумывать ей беду
        # нельзя (иначе «правильный» guard обесценит настоящие находки).
        c = FakeSSH(routes=[('ls -1',
                             'FFDIR ok /var/log/nginx\n'
                             'FFRC 0\nFFCOUNT 0\n')])
        info = common.find_files_info(c, '/var/log/nginx/*.log', 20)
        assert info['paths'] == [] and info['notes'] == []
        assert info['total'] == 0
        assert info['ls_rc'] == 0
        assert info['dirs'][0][0] == 'ok'

    # ============ 1.32.5: счётчик find обязан различать пустоту и отказ ======
    # bitrix_perms_report считал нарушения как `find … 2>/dev/null | wc -l`.
    # Код возврата конвейера принадлежит wc, а stderr заглушён, поэтому отказ
    # («нет прав», «нет такого пользователя») выглядел как «нарушений 0».
    # Замер живьём (mawk 1.3.4, реальный парк): закрытый каталог — FCOUNT 0 при
    # FERR 1; неизвестный пользователь — FCOUNT 0 при FERR 1; читаемый каталог
    # с одним файлом — FCOUNT 1 при FERR 0; честный пустой — FCOUNT 0 FERR 0.
    # Контрпример снят там же: файл с именем «find: weird» в открытом каталоге
    # остаётся в счёте, а не в ошибках, — строка данных это путь, он начинается
    # с корня, а не с «find: ».
    #
    # Признак полноты — код возврата САМОГО find (маркер FRC, канон 1.32.3), а
    # НЕ число строк «find: ». Причина измерена: если find не запущен вовсе
    # (rc=127), строк ошибок НОЛЬ, и признак по тексту снова дал бы ложно-чистый
    # вердикт — тот самый класс, который этот слайс и лечит.
    def test_count_command_keeps_stderr_and_markers(self):
        cmd = common.count_find_cmd('/home/bitrix/www',
                                    '-mindepth 1 -type f -perm -o+w')
        assert '2>&1' in cmd, cmd
        assert '2>/dev/null' not in cmd, 'причина отказа снова тонет: %r' % cmd
        assert 'wc -l' not in cmd, 'код возврата конвейера съедается wc'
        assert 'FCOUNT' in cmd and 'FERR' in cmd, cmd
        assert '-perm -o+w' in cmd, 'предикат обязан дойти буквально'

    def test_count_command_quotes_root_with_spaces(self):
        # Замок на экранирование. Прежнее наивное ожидание («путь всегда в
        # кавычках») было бы ложью: q() есть shlex.quote, и он НЕ кавычит путь
        # без спецсимволов. Проверяем случай, где кавычки обязательны.
        cmd = common.count_find_cmd('/home/bitrix/my www', '-mindepth 1')
        assert "'/home/bitrix/my www'" in cmd, cmd

    def test_count_answer_reads_both_markers(self):
        # Тройка (число, rc find, первая причина). Причина — не украшение: у
        # «Permission denied» и «No such file or directory» противоположное
        # лечение (поднимать права против проверять путь), склеивать их нельзя
        # — тот же закон, что запрещает mixing rc=2 и rc=126 в 1.32.3.
        assert common.parse_count_answer('FCOUNT 3\nFRC 0\n') == (3, 0, None)
        assert common.parse_count_answer('FCOUNT 0\nFRC 1\n') == (0, 1, None)
        # find не запустился вовсе: строк ошибок нет, а вердикт обязан быть
        # НЕполным (иначе «✅ нарушений нет» вернётся тем же путём).
        assert common.parse_count_answer('FCOUNT 0\nFRC 127\n') == (0, 127, None)

    def test_count_answer_keeps_the_first_reason(self):
        out = ('FERR find: cannot open directory /home/bitrix/www: '
               'Permission denied\n'
               'FERR find: /home/bitrix/www/upload: Permission denied\n'
               'FCOUNT 0\nFRC 1\n')
        count, rc, reason = common.parse_count_answer(out)
        assert count == 0 and rc == 1
        assert reason and 'Permission denied' in reason
        assert reason.count('Permission denied') == 1, 'берётся первая причина'

    def test_count_answer_without_markers_is_not_zero(self):
        # Тот же закон, что FFCOUNT/FFRC: ответа не было — это не «нул».
        # Голый ответ старой формы (просто число от wc) без маркеров — тоже не
        # результат: мы не знаем, дошёл ли обход до конца.
        assert common.parse_count_answer('') == (None, None, None)
        assert common.parse_count_answer('0\n') == (None, None, None)

    def test_count_info_refuses_to_call_failure_a_zero(self):
        c = FakeSSH(routes=[('find ', 'FCOUNT 0\nFRC 1\n')])
        info = common.count_find_info(c, '/home/bitrix/www',
                                      '-mindepth 1 ! -user bitrix')
        assert info['count'] == 0
        assert info['complete'] is False
        assert info['note'] and 'неполна' in info['note']

    def test_count_info_without_answer_is_not_complete(self):
        # Обрыв/чужая реализация: маркеров нет — вердикт не имеет силы.
        c = FakeSSH(routes=[('find ', '0\n')])
        info = common.count_find_info(c, '/home/bitrix/www', '-mindepth 1')
        assert info['count'] is None
        assert info['complete'] is False and info['note']

    def test_count_info_honest_zero_is_complete(self):
        # Контрпример: FRC 0 — обход дошёл до конца, complete=True и note
        # отсутствует. Выдумывать проверке беду нельзя.
        c = FakeSSH(routes=[('find ', 'FCOUNT 0\nFRC 0\n')])
        info = common.count_find_info(c, '/home/bitrix/www',
                                      '-mindepth 1 -type f')
        assert info['count'] == 0 and info['complete'] is True
        assert info['note'] is None

    # ===== 1.32.6: признак systemd-юнита обязан иметь силу =====
    # Тот же класс дефекта, что у счётчика выше, но носитель — признак, а не
    # число. Замер живьём на хосте без systemd (каталог /run/systemd/system
    # отсутствует, bus мёртв): `systemctl is-active ЛЮБОЙ_юнит` отвечает пустым
    # stdout при rc=1, а причина («System has not been booted with systemd as
    # init system (PID 1). Can't operate.») живёт в stderr. Прежний код глушил
    # stderr и решал по пустой строке «не активно».
    # Тем же прогоном снято обратное, что запрещает брать признак из кода
    # возврата: `systemctl is-system-running` даёт «offline» при rc=1 — ответ
    # системы при ненулевом коде. Значит признак — непустота stdout, а канал
    # stderr остаётся объяснением. Тот же способ, что уже лечил panels.py.
    NO_SYSTEMD_ERR = ("System has not been booted with systemd as init "
                      "system (PID 1). Can't operate.")

    def test_unit_status_command_keeps_channels_apart(self):
        cmd = common.unit_status_cmd('redis-server')
        assert 'is-active' in cmd and 'redis-server' in cmd, cmd
        assert '2>/dev/null' not in cmd, 'причина отказа снова тонет: %r' % cmd
        # 2>&1 запрещён не ради формы: он склеивает причину с ответом, и
        # «пустой stdout» перестаёт быть различимым. Различие держится
        # каналами (урок panels.py и 1.28.0 про локализованный текст).
        assert '2>&1' not in cmd, cmd

    def test_unit_status_cmd_quotes_unit_names_with_spaces(self):
        # Тот же закон, что у find-счётчика: q() есть shlex.quote, и кавычки
        # обязательны там, где имя со спецсимволом.
        cmd = common.unit_status_cmd('php 8.2-fpm')
        assert "'php 8.2-fpm'" in cmd, cmd

    def test_parse_unit_status_answer_is_a_channel_not_rc(self):
        assert common.parse_unit_status('active\n', '', 0) == ('active',
                                                                None)
        # Ответ системы при ненулевом rc остаётся ОТВЕТОМ (замер: offline, rc=1;
        # inactive systemctl тоже возвращает rc=1).
        assert common.parse_unit_status('inactive\n', '', 3) == ('inactive',
                                                                 None)
        assert common.parse_unit_status('offline\n', '', 1) == ('offline',
                                                                None)

    def test_parse_unit_status_empty_stdout_is_not_a_status(self):
        status, note = common.parse_unit_status('', self.NO_SYSTEMD_ERR, 1)
        assert status is None
        assert note and 'не проверено' in note, note
        assert 'systemd' in note, 'причина обязана доехать до оператора'
        # Оба канала пусты (обрыв, чужая реализация): тоже «не проверено»,
        # а не «не активно».
        status, note = common.parse_unit_status('', '', 1)
        assert status is None and note and 'не проверено' in note, note

    def test_parse_unit_status_no_answer_at_all(self):
        assert common.parse_unit_status(None, None, None)[0] is None

    def test_unit_status_info_carries_the_reason(self):
        c = FakeSSH(routes=[('is-active', ('', 'Failed to connect to bus: '
                                           'Host is down', 1))])
        info = common.unit_status_info(c, 'redis-server')
        assert info['status'] is None and info['checked'] is False
        assert 'не проверено' in info['note'] and 'bus' in info['note']

    def test_unit_status_info_real_answer_is_checked(self):
        # Контрпример: настоящий ответ остаётся ответом. Выдумывать ему
        # неполноту нельзя, иначе «не проверено» обесценит настоящие находки.
        c = FakeSSH(routes=[('is-active', 'active\n')])
        info = common.unit_status_info(c, 'redis-server')
        assert info['status'] == 'active' and info['checked'] is True
        assert info['note'] is None

    def test_rc_two_is_not_relabelled_as_argv_flood(self):
        # Второй обязательный контрпример. Замер живьём: «глоб не раскрылся»,
        # «каталога нет» и «нет прав» дают rc=2, а argv-голод — rc=126. Глотнуть
        # оба кода одной веткой значило бы переврать три честных диагноза
        # (лечение у них противоположное: менять раскладку против сужать шаблон).
        # Диагноз rc=2 несут строки FFDIR и stderr — здесь проверям, что
        # «неправильная» ветка к ним не приклеилась.
        c = FakeSSH(routes=[('ls -1',
                             'FFDIR ok /var/log/nginx\n'
                             'FFRC 2\n'
                             'FFCOUNT 0\n')])
        info = common.find_files_info(c, '/var/log/nginx/*.log', 20)
        note = ' '.join(info['notes'])
        assert 'слишком много' not in note.lower(), note
        assert info['ls_rc'] == 2
        assert info['total'] == 0

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
    # Двойник обязан говорить ЯЗЫКОМ СИСТЕМЫ (урок 1.27.0). Прежний роут
    # ('grep -h', 'example.com') описывал ответ, которого grep не выдаёт
    # никогда: grep печатает СТРОКУ КОНФИГА ЦЕЛИКОМ, а уже извлечённое имя
    # домена производил пайп sed/tr/grep. Пока двойник врал, пайп можно было
    # чинить сколько угодно — тесты остались бы зелёными над мёртвой логикой.
    GREP_OK = '    server_name example.com www.example.com;\n'

    def test_extracts_domains(self):
        c = FakeSSH(routes=[('grep -h', self.GREP_OK)])
        assert sorted(common.get_domain_from_config(c, '/etc/nginx/vhosts/x')) == \
            ['example.com', 'www.example.com']

    def test_filters_wildcards_placeholders(self):
        # Ответ grep — директива целиком; фильтр обязан отсечь то же, что
        # отсекал прежний пайп.
        c = FakeSSH(routes=[('grep -h',
                             'server_name example.com *.example.com _ '
                             'localhost default_server нет-точки;\n')])
        assert common.get_domain_from_config(c, '/etc/nginx/vhosts/x') == \
            ['example.com']

    def test_empty_when_no_server_name(self):
        # Честный ответ grep «файл прочитан, совпадений нет»: rc=1 + пустой
        # вывод. Именно его прежний код не умел отличить от «нет прав».
        c = FakeSSH(routes=[('grep -h', ('', '', 1))])
        assert common.get_domain_from_config(c, '/etc/nginx/vhosts/x') == []

    def test_config_path_quoted(self):
        c = FakeSSH(routes=[('grep -h', ('', '', 1))])
        common.get_domain_from_config(c, '/etc/nginx/vhosts/we; rm -rf /')
        cmd = c.find('grep -h')
        assert "'/etc/nginx/vhosts/we; rm -rf /'" in cmd


# ==================== ПАРСЕР server_name: прежний sed врал содержимым ========
class TestServerNamesParsing:
    """Чистая функция: без I/O, поэтому каждая ловушка — один короткий кейс.

    Все «ЛОЖЬ» ниже — не догадка, а прямой замер прежней команды на настоящих
    файлах (uid=1000, /bin/bash):

        '#    server_name uhatil.tld;'          -> ['uhatil.tld']
        '   # server_name staryj.tld;'          -> ['staryj.tld']
        'server_names_hash_bucket_size 128.0;'  -> ['128.0']
        'server_name hodovyj.tld; # ... ljevoj' -> ['ljevoj.tld']  <<< настоящий
                                                                      домен ПОТЕРЯН

    Формально это не «нет прав», а «есть лишние домены»: по выдуманным именам
    check_site_logs ищет /var/log/nginx/<выдумка>.error.log и рапортует о
    домене, которого на сервере нет.
    """

    @staticmethod
    def parse(text):
        return sorted(common.domains_from_config_text(text))

    def test_plain_directive(self):
        assert self.parse('server_name zhivoy.tld;') == ['zhivoy.tld']

    def test_tab_separated_directive(self):
        assert self.parse('\t\tserver_name\t\ttabovij.tld;\t') == ['tabovij.tld']

    def test_several_domains_on_one_line(self):
        assert self.parse('server_name a.tld b.tld c.tld;') == \
            ['a.tld', 'b.tld', 'c.tld']

    def test_several_directive_lines(self):
        assert self.parse('server_name a.tld;\nserver_name b.tld;\n') == \
            ['a.tld', 'b.tld']

    def test_commented_line_is_not_a_domain(self):
        assert self.parse('#    server_name uhatil.tld;') == []

    def test_indented_comment_is_not_a_domain(self):
        assert self.parse('    # server_name staryj.tld;') == []

    def test_trailing_comment_neither_adds_nor_replaces(self):
        # Прежний sed (жадный `.*server_name`) брал ПОСЛЕДНИЙ server_name в
        # строке: отчёт терял настоящий домен и называл выдуманный.
        got = self.parse('server_name hodovyj.tld; # server_name ljevoj.tld;')
        assert got == ['hodovyj.tld']

    def test_similar_directive_is_not_a_domain(self):
        # 'server_names_hash_bucket_size' начинается на 'server_name', но
        # директивой server_name не является: прежний sed доставал из неё
        # '128.0', и инвентарь доменов получал домен «128.0».
        assert self.parse('server_names_hash_bucket_size 128.0;') == []

    def test_wildcard_placeholder_and_localhost_filtered(self):
        assert self.parse('server_name *.a.tld _ localhost default_server '
                          'bezy-tochki zhivoy.tld;') == ['zhivoy.tld']

    def test_dedup_keeps_every_real_domain(self):
        got = common.domains_from_config_text('server_name b.tld a.tld b.tld;')
        assert sorted(got) == ['a.tld', 'b.tld']

    def test_value_without_semicolon_is_still_a_domain(self):
        # Слегка побитый конфиг: домен всё равно есть, молчать хуже, чем
        # назвать его (прежний sed на этом кейсе молчал).
        assert self.parse('server_name bez-zap-toy.tld') == ['bez-zap-toy.tld']


# ==================== Чем объяснена пустота: rc=2 принадлежит grep'у ========
class TestGetDomainFromConfigExplainsGaps:
    """Три rc grep'а без пайпа = три разных ответа оператору.

    Замер живьём (этот хост, uid=1000), `grep -h 'server_name' ПУТЬ 2>&1`:

        читаемый, домены есть     rc=0 'server_name example.com www.example.com;'
        прочитан, server_name нет rc=1 ''
        ЗАКРЫТ 0000               rc=2 'grep: ...: Permission denied'
        ОТСУТСТВУЕТ               rc=2 'grep: ...: No such file or directory'
        КАТАЛОГ                   rc=2 'grep: ...: Is a directory'

    Прежний пайп (`grep ... 2>/dev/null | sed ... | tr ... | grep -v ...`)
    отдавал rc ПОСЛЕДНЕЙ команды — то есть 0/1 по результату фильтра, — и на
    всех пяти состояниях про права не говорил НИКОГДА, а `2>/dev/null`
    выбрасывал единственную строку, где причина написана. Это тот же закон,
    что куплен в 1.28.0 на systemctl: пайп обнуляет rc владельца команды.
    """

    GREP_OK = '    server_name example.com www.example.com;\n'
    LOCKED = ('', 'grep: /etc/nginx/vhosts/x: Permission denied', 2)
    GONE = ('', 'grep: /etc/nginx/vhosts/x: No such file or directory', 2)
    ADIR = ('', 'grep: /etc/nginx/vhosts/x: Is a directory', 2)

    def test_found_config_makes_no_complaint(self):
        c = FakeSSH(routes=[('grep -h', self.GREP_OK)])
        domains, notes = common.get_domain_from_config_info(c, '/etc/nginx/vhosts/x')
        assert sorted(domains) == ['example.com', 'www.example.com']
        assert notes == []

    def test_read_without_server_name_is_honest_silence(self):
        # «Файл прочитан, совпадений нет» — ответ системы, а не пробел:
        # признание обесценило бы настоящие (тот же закон, что для пустого
        # прочитанного каталога логов в 1.24-1.28).
        c = FakeSSH(routes=[('grep -h', ('', '', 1))])
        domains, notes = common.get_domain_from_config_info(c, '/etc/nginx/vhosts/x')
        assert domains == [] and notes == []

    def test_locked_config_is_not_reported_as_no_domains(self):
        c = FakeSSH(routes=[('grep -h', self.LOCKED)])
        domains, notes = common.get_domain_from_config_info(c, '/etc/nginx/vhosts/x')
        assert domains == []
        assert notes and 'прав' in notes[0]
        assert 'нет на сервере' not in notes[0]

    def test_missing_config_says_absent_and_names_the_path(self):
        c = FakeSSH(routes=[('grep -h', self.GONE)])
        domains, notes = common.get_domain_from_config_info(c, '/etc/nginx/vhosts/x')
        assert domains == []
        assert notes and 'нет на сервере' in notes[0]
        assert '/etc/nginx/vhosts/x' in notes[0]
        assert 'прав' not in notes[0]

    def test_directory_is_not_a_config(self):
        c = FakeSSH(routes=[('grep -h', self.ADIR)])
        domains, notes = common.get_domain_from_config_info(c, '/etc/nginx/vhosts/x')
        assert domains == []
        assert notes and 'каталог' in notes[0]

    def test_system_answer_is_quoted_without_a_hole(self):
        # Живой контроль первого GREEN (настоящий /bin/bash) показал калеку:
        # путь вырезан из сообщения grep, а дыра по шву осталась —
        # «(grep:: Permission denied)». Цитата — единственное, что оператор
        # читает как доказательство; её режут по шву, а не по живому.
        c = FakeSSH(routes=[('grep -h', self.LOCKED)])
        _d, notes = common.get_domain_from_config_info(c, '/etc/nginx/vhosts/x')
        assert notes and 'grep: Permission denied' in notes[0]
        assert '::' not in notes[0], 'дыра по шву вырезания пути'
        assert ' : ' not in notes[0], 'дыра по шву вырезания пути'

    def test_unknown_grep_failure_is_unchecked_and_quoted(self):
        # Ответ системы цитируется, а не превращается в удобный диагноз.
        c = FakeSSH(routes=[('grep -h', ('', 'grep: memory exhausted', 2))])
        domains, notes = common.get_domain_from_config_info(c, '/etc/nginx/vhosts/x')
        assert domains == []
        assert notes and 'не проверено' in notes[0]
        assert 'memory exhausted' in notes[0]

    def test_silent_server_is_not_reported_as_no_domains(self):
        # rc=0 с пустым выводом grep не бывает (rc=0 обязан совпадением):
        # это обрыв ответа, а не «server_name нет».
        domains, notes = common.get_domain_from_config_info(FakeSSH(), '/etc/nginx/x')
        assert domains == []
        assert notes and 'не проверено' in notes[0]

    def test_command_leaves_rc_with_grep(self):
        c = FakeSSH()
        common.get_domain_from_config(c, '/etc/nginx/x')
        cmd = c.find('grep -h')
        assert cmd is not None
        assert '2>/dev/null' not in cmd, 'причина пустоты снова в /dev/null'
        assert '2>&1' in cmd
        # Пайп обязан исчезнуть ЦЕЛИКОМ: rc принадлежит последней команде
        # пайпа, а не grep (урок 1.28.0, закуплен второй раз).
        for part in ('| sed', '| tr', '| grep'):
            assert part not in cmd, f'в команде остался пайп {part!r}'

    def test_price_is_one_command(self):
        # Честность не должна стоить SSH-заходов: прежний пайп был ОДНОЙ
        # командой, новая grep-форма — тоже одна.
        c = FakeSSH(routes=[('grep -h', self.GREP_OK)])
        common.get_domain_from_config(c, '/etc/nginx/a.conf')
        assert len(c.commands) == 1

    def test_wrapper_keeps_plain_list(self):
        # Совместимость: публичная форма по-прежнему отдаёт только список.
        c = FakeSSH(routes=[('grep -h', self.GREP_OK)])
        assert sorted(common.get_domain_from_config(c, '/etc/nginx/x')) == \
            ['example.com', 'www.example.com']
        c2 = FakeSSH(routes=[('grep -h', self.LOCKED)])
        assert common.get_domain_from_config(c2, '/etc/nginx/x') == []


# ==================== АГРЕГАЦИЯ: 10 закрытых конфигов ≠ 10 признаний ========
class TestDomainsFromConfigsAggregates:
    """Одно признание на ПРИЧИНУ, а не на файл (закон 1.24–1.28).

    Замер живьём после первого GREEN этого слайса: десять конфигов с правами
    0000 давали ДЕСЯТЬ одинаковых строк в get_domains_info()['notes']. Отчёт
    тонул в признании, а признание, которого десять, оператор перестаёт читать
    — тот же дефект, что лечился «одним признанием на прогон» в 1.28.0.
    """

    PATHS = ['/etc/nginx/conf.d/site%d.conf' % i for i in range(10)]

    def _checker(self, grep_answer, drop=()):
        """Двойник НОВОЙ сводной команды (1.32.0) через общий механизм.

        ПЕРЕФОРМУЛИРОВАНО ОБЪЯВЛЕННО (урок 1.27.0). Прежний двойник подменял
        ответ на `grep -h <путь>`, потому что сводка ходила по файлам. Как
        только чтение переводится на ОДНУ команду, старый двойник молчал бы на
        ней, а молчание продукт обязан толковать как пробел: тесты «группы не
        сливаются» зазеленели бы по НЕВЕРНОЙ причине. Язык двойника обязан
        следовать за языком системы.

        Раскрытие пачки (shell-семантика `set -- …; for f in "$@"` и сборка
        printf-маркеров) живёт в ОДНОМ месте — tests/support.py. Прежняя
        локальная копия протокола была бы вторым парсером: она обязана
        разъехаться с настоящим форматом ровно тогда, когда начнёт что-то
        значить (тот же закон, из-за которого разбор server_name вынесен в
        domains_from_config_text одним местом).

        Здесь остаётся только модель ответа внутреннего grep:
        grep_answer(path) -> (out, err, rc), а drop — пути БЕЗ ответа (обрыв
        сводной команды в середине: таймаут канала, чужая реализация).
        """
        to_drop = set(drop)

        class Batch(FakeSSH):
            def _batch_row(self, path):
                if path in to_drop:
                    return None
                return grep_answer(path)
        return Batch()

    def test_ten_locked_configs_give_one_note(self):
        c = self._checker(lambda p: ('', 'grep: %s: Permission denied' % p, 2))
        domains, notes = common.domains_from_configs_info(c, self.PATHS)
        assert domains == []
        assert len(notes) == 1, 'отчёт тонет: %d одинаковых признаний' % len(notes)
        assert 'прав' in notes[0]
        assert '10' in notes[0], 'сводка обязана назвать число файлов'
        assert 'site0.conf' in notes[0], 'сводка обязана дать пример пути'

    def test_missing_files_are_not_mixed_with_permission_denied(self):
        # Противоположные лечения (поднимать права против менять раскладку
        # панели) не имеют права сливаться в одно признание.
        def answer(p):
            if p.endswith('site0.conf'):
                return ('', 'grep: %s: Permission denied' % p, 2)
            return ('', 'grep: %s: No such file or directory' % p, 2)

        c = self._checker(answer)
        domains, notes = common.domains_from_configs_info(c, self.PATHS)
        assert domains == []
        assert len(notes) == 2
        assert any('прав' in n and 'нет на сервере' not in n for n in notes)
        assert any('нет на сервере' in n for n in notes)

    def test_different_system_answers_do_not_merge(self):
        # Разные ответы системы — разные основания: схлопнуть их значит
        # соврать про причину (ответ системы цитируется, а не подменяется).
        def answer(p):
            if p.endswith('site0.conf'):
                return ('', 'grep: memory exhausted', 2)
            return ('', 'grep: input file is also the output', 2)

        c = self._checker(answer)
        _domains, notes = common.domains_from_configs_info(c, self.PATHS)
        assert len(notes) == 2

    def test_readable_configs_stay_silent_and_keep_domains(self):
        # Найденное нельзя терять ради признания, а признание нельзя
        # превращать в шум: 9 прочитанных + 1 закрытый = 9 доменов и 1 строка.
        def answer(p):
            if p.endswith('site3.conf'):
                return ('', 'grep: %s: Permission denied' % p, 2)
            return ('server_name %s;\n'
                    % p.rsplit('/', 1)[-1].replace('.conf', '.tld'), '', 0)

        c = self._checker(answer)
        domains, notes = common.domains_from_configs_info(c, self.PATHS)
        assert len(domains) == 9
        assert len(notes) == 1 and 'site3.conf' in notes[0]

    def test_no_files_is_silence(self):
        assert common.domains_from_configs_info(FakeSSH(), []) == ([], [])

    # ПЕРЕФОРМУЛИРОВАНО ОБЪЯВЛЕННО (слайс 1.32.0). Прежний тест звался
    # test_price_is_one_command_per_config и ЗАПРЕТАЛ цену «одна команда на
    # файл». Для своей версии он был честным, но именно он делал невозможным
    # поднятие лимита: замер живьём, 200 реальных конфигей - 10 файлов = 11
    # SSH-команд, 50 = 51, 200 = 201. Из-за этой цены get_domains_info держал
    # limit=10 и докладывал 10 доменов при 40 на сервере, а оператор читал это
    # как «доменов больше нет». Требование цены меняется на противоположное:
    # ОДНА команда на всю пачку.
    def test_price_is_one_command_for_the_whole_batch(self):
        c = self._checker(lambda p: ('server_name a.tld;', '', 0))
        common.domains_from_configs_info(c, self.PATHS)
        assert len(c.commands) == 1, (
            'чтение пачки стоит %d SSH-команд; при линейной цене лимит нельзя '
            'поднять, поэтому оператор видит не весь список доменов'
            % len(c.commands))

    def test_dropped_batch_answer_is_admission_not_silence(self):
        # Инвертированный контроль: сводная команда оборвалась и не вернула
        # НИ ОДНОГО ответа. Молчание здесь запрещено: «доменов нет» при
        # непустом запросе - это ложь (закон 1.19-1.31).
        c = self._checker(lambda p: ('server_name a.tld;', '', 0),
                          drop=tuple(self.PATHS))
        domains, notes = common.domains_from_configs_info(c, self.PATHS)
        assert domains == []
        assert len(notes) == 1, 'пробел обязан быть назван ровно один раз'
        assert 'не провер' in notes[0]

    def test_partial_batch_answer_keeps_found_and_admits_the_rest(self):
        # Найденное нельзя терять ради признания: ответы пришли на 6 путей из
        # 10 - домены этих 6 обязаны остаться, а недостающие - быть названы
        # одним признанием с числом (иначе оператор не узнает о масштабе).
        lost = tuple(self.PATHS[6:])
        c = self._checker(lambda p: ('server_name %s.tld;'
                                     % p.rsplit('/', 1)[-1][:-5], '', 0),
                          drop=lost)
        domains, notes = common.domains_from_configs_info(c, self.PATHS)
        assert len(domains) == 6, domains
        assert len(notes) == 1 and '4' in notes[0], notes

    def test_empty_request_does_not_ask_server(self):
        # Цена тоже часть честности: при пустом списке сводка не имеет права
        # слать команду «в никуда» (set -- без аргументов).
        c = FakeSSH()
        assert common.domains_from_configs_info(c, []) == ([], [])
        assert c.commands == []


# ============ СВОДКА ЧТЕНИЯ КОНФИГОВ: ОДНА КОМАНДА НА ПАЧКУ =================
# Живой замер (слайс 1.32.0, фаза Reproduce): чтение N конфигов стоило N
# SSH-раундов - domains_from_configs_info звал _domain_config_probe по одному
# разу на каждый файл. Замер на настоящем /bin/bash этого хоста, 200 реальных
# конфигей: limit=10 -> 11 команд, limit=50 -> 51, limit=200 -> 201.
#
# Отсюда следовала ГЛАВНАЯ ложь слайса (замер же): оператор видел 10 доменов
# при 40 конфигах на сервере. Поднять лимит было нельзя - он умножал бы
# SSH-заходы. Значит сначала удешевление: ОДНА команда с printf-маркерами и
# отдельным rc на каждый ответ (тот же протокол, что заперт для стека и порта
# панели в 1.31.0), и только потом лимит.
#
# Эталонный ответ СНИТ ЖИВЬЁМ с настоящими файлами (читаемый, закрытый 0000,
# отсутствующий, каталог, rc=1 без server_name, путь с пробелом, путь с
# кириллицей) - двойник обязан говорить языком системы, а не удобным выводом
# (урок 1.27.0: роуты 'active\nactive' и '200\n000' описывали ответ, которого
# настоящие команды не выдают никогда, и тесты проходили по НЕВЕРНОЙ причине).
MARKER_PROBE_ANSWER = (
    "@F 0\t/etc/conf.d/ok.conf\nserver_name alfa.example.com;\n"
    "@F 0\t/etc/conf.d/ok2.conf\n    server_name bravo.tld www.example.com;\n"
    "@F 1\t/etc/conf.d/nosn.conf\n\n"
    "@F 2\t/etc/conf.d/locked.conf\ngrep: /etc/conf.d/locked.conf: "
    "Permission denied\n"
    "@F 2\t/etc/conf.d/netu.conf\ngrep: /etc/conf.d/netu.conf: No such file "
    "or directory\n"
    "@F 2\t/etc/conf.d/katalog.conf\ngrep: /etc/conf.d/katalog.conf: Is a "
    "directory\n"
    "@F 0\t/etc/conf.d/comment.conf\n#    server_name ghost.tld;\n"
    "server_name real.tld; # comment.tld\n"
    "@F 0\t/etc/conf.d/my site.conf\nserver_name space.tld;\n"
)


class TestDomainConfigsBatchProtocol:
    PATHS = ['/etc/conf.d/site%d.conf' % i for i in range(5)]

    def test_probe_command_is_one_round_and_keeps_rc_per_file(self):
        cmd = common.domain_configs_probe_cmd(self.PATHS)
        assert cmd.count('grep') == 1, 'grep обязан вызываться внутри цикла'
        assert '2>/dev/null' not in cmd, 'причина пустоты снова в /dev/null'
        assert '|' not in cmd, 'пайп забрал бы rc grep (урок 1.28.0)'
        assert '${PIPESTATUS' not in cmd, 'под dash это Bad substitution'
        assert 'r=$?' in cmd, 'rc обязан сниматься ДО printf (echo крадёт $?)'
        assert '"$f"' in cmd, 'путь обязано кавычить: имена бывают с пробелом'
        assert '@F' in cmd and 'printf' in cmd

    def test_probe_command_quotes_paths(self):
        cmd = common.domain_configs_probe_cmd(['/var/www/my site/a.conf'])
        assert "'/var/www/my site/a.conf'" in cmd, cmd

    def test_probe_answer_parser_keeps_rc_path_and_body(self):
        got = common.parse_domain_probe_answer(MARKER_PROBE_ANSWER)
        assert [(g['path'], g['rc']) for g in got] == [
            ('/etc/conf.d/ok.conf', 0), ('/etc/conf.d/ok2.conf', 0),
            ('/etc/conf.d/nosn.conf', 1), ('/etc/conf.d/locked.conf', 2),
            ('/etc/conf.d/netu.conf', 2), ('/etc/conf.d/katalog.conf', 2),
            ('/etc/conf.d/comment.conf', 0), ('/etc/conf.d/my site.conf', 0)]
        assert got[3]['body'] == ('grep: /etc/conf.d/locked.conf: '
                                  'Permission denied')
        assert got[2]['body'] == '', 'rc=1 обязан прийти с пустым телом'

    def test_batch_and_single_forms_agree_on_every_state(self):
        # Решающий тест слайса: сводка не имеет права потерять НИ ОДНОГО
        # различения, которое уже умела пофайловая форма. Сравниваются ДВЕ
        # формы на одном микше состояний.
        batch_rows = common.parse_domain_probe_answer(MARKER_PROBE_ANSWER)
        via_batch = [common.classify_grep_probe(g['rc'], g['body'], g['path'])
                     for g in batch_rows]
        # Та же пачка пофайлово: каналы разделены (grep без 2>&1).
        routes = []
        for g in batch_rows:
            if g['rc'] == 0:
                routes.append((g['path'], (g['body'], '', 0)))
            elif g['rc'] == 1:
                routes.append((g['path'], ('', '', 1)))
            else:
                routes.append((g['path'], ('', g['body'], 2)))
        c = FakeSSH(routes=routes)
        via_single = [common._domain_config_probe(c, g['path'])
                      for g in batch_rows]
        assert [(x['kind'], x['why']) for x in via_batch] == \
               [(x['kind'], x['why']) for x in via_single], \
               'сводка потеряла различение: %s vs %s' % (via_batch, via_single)
        kinds = [x['kind'] for x in via_batch]
        assert kinds.count(None) == 5, kinds
        assert kinds.count('unreadable') == 1
        assert kinds.count('missing') == 1
        assert kinds.count('isdir') == 1
        assert sorted(common.classify_grep_probe(
            0, 'server_name real.tld; # comment.tld', '')['domains']) == \
            ['real.tld'], 'комментарий не имеет права стать доменом'

    def test_truncated_batch_answer_is_not_read_as_silence(self):
        # Обрыв канала (чужая реализация/таймаут): ни одного маркера. Вводить
        # молчанием «доменов нет» нельзя - это пробел (закон 1.19-1.31).
        assert common.parse_domain_probe_answer('') == []
        assert common.parse_domain_probe_answer(
            'server_name a.tld;\n') == []


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

# ============ ПРОЦЕССЫ: носитель, цель, убийство (1.32.13) =================
# Приговор прежним формам вынесен ЖИВЫМ замером на этом хосте (настоящий
# bash, живость — по /proc State после reap):
#  * pkill core (без -x, ровно как в panels.ispmanager_kill_core) УБИЛ ЧУЖОЙ
#    coredns: pgrep/pkill матчают имя как подстроку;
#  * pgrep -x core нашёл и чужой /opt/vendor/core (тот же basename, другая
#    установка) — то есть убил бы не ту панель;
#  * pgrep -f "<путь core>" нашёл чужой «tail -f <тот же путь>» и ПРОПУСТИЛ
#    запуски «exec -a core» и «cd && exec ./core»;
#  * пайп ps aux | grep core | grep -v grep потерял код возврата (rc
#    принадлежит последней команде) и на «ps: command not found» дал пустоту,
#    которую отчёт прочитал как «✅ Процесс core завершён» при живом процессе.
# Носитель — один ps -eo pid=,args= без пайпа; цель — argv[0], равный пути.


class TestProcessProbe:
    TARGET = "/usr/local/mgr5/bin/core"
    CORE = "      1 /usr/local/mgr5/bin/core -D"
    TAIL = "    424 /usr/bin/tail -f /usr/local/mgr5/bin/core"
    VENDOR = "    500 /opt/vendor/core -d"
    NOISE = "     42 /usr/bin/tail -f /var/log/notes.txt"
    # Замер: ps -eo pid=,args (без второго =) печатает COMMAND первой строкой.
    HEADER = "        COMMAND"

    def table(self, *rows):
        return chr(10).join(rows) + chr(10)

    def probe(self, routes=None, default=("", "", 0)):
        c = FakeSSH(routes=routes or [], default=default)
        return c, common.process_probe(c, self.TARGET)

    def test_carrier_is_one_command_without_pipe(self):
        c = FakeSSH(routes=[("ps -eo", self.table(self.CORE))])
        common.process_probe(c, self.TARGET)
        assert c.commands == [common.PROCESS_LIST_CMD]
        cmd = c.commands[0]
        for forbidden in ("|", "&&", "||", ">", "grep", "pgrep", "pkill"):
            assert forbidden not in cmd, cmd

    def test_exact_path_is_running(self):
        c, info = self.probe([("ps -eo", self.table(self.CORE, self.TAIL))])
        assert info["state"] == "running"
        assert info["checked"] is True
        assert info["pids"] == ["1"]

    def test_path_in_foreign_arguments_is_not_the_daemon(self):
        # Ровно тот процесс, который находил pgrep -f по пути панели.
        c, info = self.probe([("ps -eo", self.table(self.TAIL))])
        assert info["state"] == "absent"
        assert info["pids"] == []

    def test_same_name_in_another_path_is_not_the_daemon(self):
        c, info = self.probe([("ps -eo", self.table(self.VENDOR))])
        assert info["state"] == "absent"
        # О похожем имени обязаны сказать словами: это кандидат «запущено не
        # по нашему пути», а не молчаливое «процесса нет».
        assert info["similar"] == ["500"]
        assert info["note"]

    def test_absence_is_measured_not_assumed(self):
        c, info = self.probe([("ps -eo", self.table(self.TAIL, self.VENDOR,
                                                    self.NOISE))])
        assert info["state"] == "absent"
        assert info["checked"] is True
        assert info["pids"] == [] and info["similar"] == ["500"]

    def test_header_row_is_not_a_process(self):
        c, info = self.probe([("ps -eo", self.table(self.HEADER, self.CORE))])
        assert info["state"] == "running" and info["pids"] == ["1"]

    def test_short_rubbish_row_is_not_guessed(self):
        c, info = self.probe([("ps -eo", self.table("x", self.CORE))])
        assert info["pids"] == ["1"]

    def test_missing_utility_is_unchecked_not_absent(self):
        # Замер: rc=127 выдаёт оболочка, stdout пуст. Прежний пайп на этом же
        # ответе печатал «завершён» — ровно тот отказ, что лечит слайс.
        c, info = self.probe(default=("", "ps: command not found", 127))
        assert info["state"] == "unchecked"
        assert info["checked"] is False
        assert info["pids"] == []
        assert info["note"]

    def test_unreadable_table_is_unchecked(self):
        c, info = self.probe(default=("", "cannot open /proc", 1))
        assert info["state"] == "unchecked"
        assert info["checked"] is False


class TestProcessKill:
    TARGET = "/usr/local/mgr5/bin/core"
    CORE = "      1 /usr/local/mgr5/bin/core -D"
    OTHER = "     42 /usr/bin/tail -f /var/log/notes.txt"

    def kill(self, routes, pids=("1",)):
        c = FakeSSH(routes=routes)
        return c, common.process_kill(c, list(pids), target=self.TARGET)

    def test_kill_asks_only_named_pids(self):
        c = FakeSSH()
        common.process_kill(c, ["12", "34"], target=self.TARGET)
        cmd = c.find("kill")
        assert cmd is not None and "12" in cmd and "34" in cmd
        # Имя процесса в команду убийства не едет: по имени убивали чужое.
        for sent in c.commands:
            assert "core" not in sent, sent

    def test_gone_is_proved_by_reading_the_list_again(self):
        c, result = self.kill([("kill", ""), ("ps -eo", self.OTHER + chr(10))])
        assert result["state"] == "gone"
        assert result["checked"] is True
        assert c.count("ps -eo") == 1

    def test_alive_target_stays_alive(self):
        c, result = self.kill([("kill", ""),
                               ("ps -eo", self.CORE + chr(10))])
        assert result["state"] == "alive"
        assert result["checked"] is True

    def test_confirmation_that_never_arrived_is_unchecked(self):
        # Убил — но перечитать нечем: «готово» здесь не право на отчёт.
        c, result = self.kill([("kill", ""),
                               ("ps -eo", ("", "ps: command not found", 127))])
        assert result["state"] == "unchecked"
        assert result["checked"] is False

    def test_refused_kill_keeps_its_reason(self):
        c, result = self.kill([("kill", ("", "kill: (1) - Operation not "
                                          "permitted", 1)),
                               ("ps -eo", self.CORE + chr(10))])
        assert result["state"] == "alive"
        assert "permitted" in result["note"]

    def test_kill_without_pids_does_not_ask_anything(self):
        c, result = self.kill([], pids=())
        assert c.find("kill") is None
        assert result["state"] == "nothing-to-kill"

class TestProcessProbeCache:
    """Один спрос на несколько целей; кеш НЕ переживает убийство."""

    TARGET = "/usr/local/mgr5/bin/core"
    OTHER = "/usr/local/mgr5/bin/ihttpd"
    CORE = "      1 /usr/local/mgr5/bin/core -D"
    IHTTPD = "      7 /usr/local/mgr5/bin/ihttpd -c conf"
    SLEEP = "     42 /usr/bin/sleep 300"

    def test_two_targets_cost_one_question(self):
        c = FakeSSH(routes=[("ps -eo", self.CORE + chr(10) + self.IHTTPD
                             + chr(10))])
        cache = {}
        first = common.process_probe(c, self.TARGET, cache)
        second = common.process_probe(c, self.OTHER, cache)
        assert c.count("ps -eo") == 1
        assert first["pids"] == ["1"] and second["pids"] == ["7"]

    def test_refused_table_is_not_asked_twice(self):
        # Причина отказа — та же команда, значит ответ тот же: повторный спрос
        # ничего бы не добавил и только замедлил бы отчёт.
        c = FakeSSH(default=("", "ps: command not found", 127))
        cache = {}
        a = common.process_probe(c, self.TARGET, cache)
        b = common.process_probe(c, self.OTHER, cache)
        assert c.count("ps -eo") == 1
        assert a["state"] == "unchecked" and b["state"] == "unchecked"

    def test_kill_rereads_without_any_cache(self):
        # Решающий контрпример: первый список и второй (после убийства) —
        # РАЗНЫЕ миры. Передай process_kill кеш — и «✅ завершён» печатался
        # бы по снимку ДО убийства, то есть ровно та ложь, что лечит серия.
        c = FakeSSH(routes=[
            ("kill", ""),
            ("ps -eo", [self.CORE + chr(10), self.SLEEP + chr(10)]),
        ])
        probe = common.process_probe(c, self.TARGET)
        assert probe["pids"] == ["1"]
        result = common.process_kill(c, probe["pids"], target=self.TARGET)
        assert result["state"] == "gone"
        assert c.count("ps -eo") == 2

    def test_probe_without_cache_always_asks(self):
        # Отсутствие кеша — прежнее поведение: каждый спрос настоящий.
        c = FakeSSH(routes=[("ps -eo", self.CORE + chr(10))])
        common.process_probe(c, self.TARGET)
        common.process_probe(c, self.TARGET)
        assert c.count("ps -eo") == 2

# ========== ПРИСУТСТВИЕ ФАЙЛА: rc как ответ, список как доказательство =====
# Замер живьём (uid=1000, настоящий bash, «файл был» доказан возвратом прав):
#  * каталог 000 (непроходим): test -f -> out='' rc=1 err='' — ПОБАЙТОВО то же,
#    что при «файла нет», а файл при этом ЕСТЬ (содержимое читается после
#    возврата прав). Значит прежний признак физически не может различить миры.
#  * каталог 111 (проход есть, список не читается): test -f -> 'yes' rc=0, а
#    ls -1 -p -> rc=2. Замена носителя на ОДИН список превратила бы ВЕРНЫЙ
#    ответ «файл есть» в «не проверено» — ложь в другую сторону и ложный
#    отказ читать лог. Поэтому носитель комбинированный.
#  * «ls: command not found» -> rc=127: списка нет, отсутствия не доказаны.
NO_LS = ('', 'ls: command not found', 127)
LIST_NO = ('ispmgr.log', '', 0)


class TestFilePresence:
    def test_state_vocabulary_is_three_not_two(self):
        c = FakeSSH(routes=[('test -f /a/b', ('', '', 0))])
        info = common.file_presence(c, '/a/b')
        assert info['state'] in ('found', 'absent', 'unchecked')
        assert info['path'] == '/a/b'

    def test_code_return_is_the_answer_not_the_word(self):
        # Прежний признак решал по СЛОВУ «yes». Здесь достаточно кода возврата:
        # пустой stdout при rc=0 — это «файл есть», а не «мы ничего не знаем».
        c = FakeSSH(routes=[('test -f /a/b', ('', '', 0))])
        assert common.file_presence(c, '/a/b')['state'] == 'found'

    def test_reachable_file_never_costs_a_directory_read(self):
        # Замок против регресса мира 111: если test -f сказал rc=0, список
        # каталога не нужен вовсе — он бы только добавил спрос и ничего не
        # мог бы опровергнуть.
        c = FakeSSH(routes=[('test -f /a/b', ('yes', '', 0))])
        info = common.file_presence(c, '/a/b')
        assert info['state'] == 'found'
        assert c.count('ls -1 -p') == 0

    def test_absence_is_proved_by_a_read_listing(self):
        c = FakeSSH(routes=[('test -f /a/b/nope.log', ('', '', 1)),
                            ('ls -1 -p /a/b', LIST_NO)])
        info = common.file_presence(c, '/a/b/nope.log')
        assert info['state'] == 'absent'
        assert 'достоверн' in info['note']

    def test_unreachable_catalog_is_unchecked_not_absent(self):
        # Решающий отказ слайса: прежний код на этом же бое печатал «не
        # найдено», а файл был на месте (замер с возвратом прав).
        c = FakeSSH(routes=[('test -f /a/b/ispmgr.log', ('', '', 1)),
                            ('ls -1 -p /a/b',
                             ('', 'ls: невозможно открыть каталог', 2))])
        info = common.file_presence(c, '/a/b/ispmgr.log')
        assert info['state'] == 'unchecked'
        assert 'невозможно открыть' in info['note']

    def test_missing_listing_utility_is_unchecked(self):
        c = FakeSSH(routes=[('test -f /a/b/ispmgr.log', ('', '', 1)),
                            ('ls -1 -p /a/b', NO_LS)])
        assert common.file_presence(c, '/a/b/ispmgr.log')['state'] == \
            'unchecked'

    def test_question_carries_no_marker_word(self):
        # Слово-маркер в спросе — прежний признак; он и есть причина лжи,
        # когда вывод пуст, а rc никто не смотрит.
        c = FakeSSH(routes=[('test -f', ('', '', 1)),
                            ('ls -1 -p', LIST_NO)])
        common.file_presence(c, '/a/b/nope.log')
        asked = [s for s in c.commands if s.startswith('test -f')]
        assert asked
        for sent in asked:
            assert 'echo' not in sent, sent
            assert '&&' not in sent, sent

    def test_common_parent_is_listed_once(self):
        c = FakeSSH(routes=[('test -f', ('', '', 1)),
                            ('ls -1 -p', LIST_NO)])
        cache = {}
        common.file_presence(c, '/a/b/x.log', cache)
        common.file_presence(c, '/a/b/y.log', cache)
        assert c.count('ls -1 -p /a/b') == 1

    def test_no_cache_asks_every_time(self):
        c = FakeSSH(routes=[('test -f', ('', '', 1)),
                            ('ls -1 -p', LIST_NO)])
        common.file_presence(c, '/a/b/x.log')
        common.file_presence(c, '/a/b/y.log')
        assert c.count('ls -1 -p /a/b') == 2

# ===== БЭКАП: отказ обязан иметь причину, а не превращаться в None =====
# Замер живьём (uid=1000, настоящий bash, BACKUP_DIR подменён на временный:
# с боевым /root/tech_support мир «источник есть» возвращал None и база замера
# лгала — этот подвох снят отдельно). Прежний код:
#
#     out, _, rc = checker.run(f'test -f {q(filepath)} && echo "exists"')
#     if rc != 0 or out.strip() != 'exists':
#         return None
#     _, _, rc = checker.run(f'cp {q(filepath)} {q(backup_path)} 2>&1')
#     if rc != 0:
#         return None
#
# Три РАЗНЫХ мира (файла нет / файл не читается / путь непроходим) дают
# неотличимый None. При этом причины измерены и различимы: «не readable»
# доходит до cp, а cp пишет причину в STDOUT (команда с 2>&1), который боевой
# код выбрасывает через `_, _, rc =`. Слово-маркер «exists» — тот же признак по
# пустоте, что лечила вся серия 1.32.6 — 1.32.14.
NOT_READABLE = ('cp: невозможно открыть \'/etc/x.conf\' для чтения: '
                'Отказано в доступе', '', 1)
LIST_EMPTY = ('', '', 0)          # пустой вывод при rc=0 = пустой каталог
LIST_NO_LS = ('', 'ls: command not found', 127)
LIST_BLOCKED = ('', 'ls: невозможно открыть каталог', 2)


class TestCreateBackupInfo:
    def test_state_vocabulary_is_four(self):
        # done | absent | unchecked | failed — четыре, а не «путь или None».
        c = FakeSSH(routes=[('mkdir -p', ('created', '', 0)),
                            ('test -f', ('', '', 0)),
                            ('cp ', ('', '', 0))])
        info = common.create_backup_info(c, '/etc/nginx/nginx.conf')
        assert info['state'] in ('done', 'absent', 'unchecked', 'failed')
        assert info['state'] == 'done'
        assert info['path'] and info['path'].endswith('.bak')

    def test_success_is_paid_by_rereading_not_by_cps_rc(self):
        # Право на «готово» даёт ПЕРЕЧИТАННЫЙ факт, а не цепочка rc (закон
        # 1.32.13 для процессов): cp может вернуть 0 и ничего не создать.
        # Прежняя редакция этой фикстуры давала перечитыванию rc=0, то есть
        # «файл есть»: тест с именем про перечитывание мерил бы доверие к rc
        # cp. Корректный мир: cp вернул 0, а бэкапа в ДОСТОВЕРНОМ списке
        # каталога нет (пустой вывод при rc=0 — пустой каталог, замер).
        c = FakeSSH(routes=[('mkdir -p', ('created', '', 0)),
                            ('test -f /etc/nginx/nginx.conf', ('', '', 0)),
                            ('cp ', ('', '', 0)),
                            ('test -f /root/tech_support', ('', '', 1)),
                            ('ls -1 -p /root/tech_support', LIST_EMPTY)])
        info = common.create_backup_info(c, '/etc/nginx/nginx.conf')
        assert info['state'] == 'failed'
        assert info['path'] is None
        assert c.find('cp ') is not None   # cp был, но ему не верим

    def test_marker_word_is_gone_from_questions(self):
        # Ни «exists», ни «&& echo» в спросах присутствовать не должно: именно
        # слово в stdout было признаком, который нельзя отличить от молчания.
        c = FakeSSH(routes=[('mkdir -p', ('created', '', 0)),
                            ('test -f', ('', '', 0)),
                            ('cp ', ('', '', 0))])
        common.create_backup_info(c, '/etc/nginx/nginx.conf')
        for sent in c.commands:
            if sent.startswith('test -f'):
                assert 'echo' not in sent, sent
                assert '&&' not in sent, sent

    def test_measured_absence_does_not_touch_cp(self):
        # Прежний замок сохранён: читать и копировать то, чего нет, запрещено.
        c = FakeSSH(routes=[('mkdir -p', ('created', '', 0)),
                            ('test -f /etc/nope.conf', ('', '', 1)),
                            ('ls -1 -p /etc', LIST_EMPTY)])
        info = common.create_backup_info(c, '/etc/nope.conf')
        assert info['state'] == 'absent'
        assert c.find('cp ') is None
        assert 'достоверн' in info['note']

    def test_unreachable_source_is_unchecked_not_absent(self):
        # Решающее различие слайса: прежний код на этом же мире возвращал
        # None, неотличимый от «файла нет»; теперь «мы не спросили».
        c = FakeSSH(routes=[('mkdir -p', ('created', '', 0)),
                            ('test -f /root/x.conf', ('', '', 1)),
                            ('ls -1 -p /root', LIST_BLOCKED)])
        info = common.create_backup_info(c, '/root/x.conf')
        assert info['state'] == 'unchecked'
        assert c.find('cp ') is None
        assert 'невозможно открыть' in info['note']

    def test_failure_carries_the_reason_words(self):
        # Причина живёт в stdout (cp запущен с 2>&1); прежний код терял оба
        # канала (`_, _, rc =`). Оператор обязан увидеть, что чинить.
        c = FakeSSH(routes=[('mkdir -p', ('created', '', 0)),
                            ('test -f /etc/x.conf', ('', '', 0)),
                            ('cp ', NOT_READABLE)])
        info = common.create_backup_info(c, '/etc/x.conf')
        assert info['state'] == 'failed'
        assert 'невозможно открыть' in info['note']
        assert '1' in info['note']          # код возврата тоже назван

    def test_backup_dir_failure_is_named_not_silently_retried_via_cp(self):
        # ensure_backup_dir возвращает bool, который прежний код выбрасывал.
        # Отказ каталога обязан попасть в причину, если бэкап не сложился.
        c = FakeSSH(routes=[('mkdir -p', ('', '', 1)),
                            ('test -f /etc/nginx/nginx.conf', ('', '', 0)),
                            ('cp ', ('cp: невозможно создать обычный файл: '
                                     'Отказано в доступе', '', 1))])
        info = common.create_backup_info(c, '/etc/nginx/nginx.conf')
        assert info['state'] == 'failed'
        assert 'Отказано в доступе' in info['note']

    def test_create_backup_stays_a_path_or_none(self):
        # Обратная совместимость — часть контракта: потребители (files.py,
        # dns.py, panels.py) и 44 теста завязаны на path|None.
        ok = FakeSSH(routes=[('mkdir -p', ('created', '', 0)),
                             ('test -f', ('', '', 0)),
                             ('cp ', ('', '', 0))])
        assert common.create_backup(ok, '/etc/nginx/nginx.conf',
                                    'configs').endswith('.bak')
        gone = FakeSSH(routes=[('mkdir -p', ('created', '', 0)),
                               ('test -f /etc/nope.conf', ('', '', 1)),
                               ('ls -1 -p /etc', LIST_EMPTY)])
        assert common.create_backup(gone, '/etc/nope.conf') is None

    def test_unknown_backup_type_still_falls_back_to_configs(self):
        c = FakeSSH(routes=[('mkdir -p', ('created', '', 0)),
                            ('test -f', ('', '', 0)),
                            ('cp ', ('', '', 0))])
        info = common.create_backup_info(c, '/etc/x.conf', 'нет-такого-типа')
        assert info['state'] == 'done'
        assert '/configs/x.conf.' in info['path']
