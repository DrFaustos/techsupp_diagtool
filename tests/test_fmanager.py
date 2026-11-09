"""Тесты fmanager.py: операции файлового менеджера над сервером через SFTP.

Реального SSH нет: вместо него ДВОЙНИК-ФС в этом файле. Он здесь свой, а не
из support.py, по той же причине, по какой support.py исполняет режимы open:
двойник обязан говорить то, что говорит paramiko. Прежний FakeSftpClient умел
только `open` и `stat` — put/get/mkdir/remove/rename в нём отсутствовали,
поэтому тесты «переименование не затёрло цель» и «загрузка не молча перезаписала»
в продукте не проверяемы: вызов упал бы на отсутствующем методе.

Законы, которые здесь стоят (сняты с кода fmanager.py и support.py):

  * «цели нет» говорит ТОЛЬКО код SSH_FX_NO_SUCH_FILE (2); прочий код — это
    «не проверено», а право на перезапись из него не следует;
  * создал — значит пустой файл, а не обнулённый чужой (режим 'wx');
  * имя из диалога не имеет права разворачиваться в другую ветку дерева
    («..»);
  * каталог удаляется рекурсивно, но СИМВОЛИЧЕСКАЯ ссылка на каталог — это
    ссылка: снимается сама, а не её цель;
  * перезапись существующей цели стоит только по принятому резерву (закон
    files._etc_backup_or_veto и ssl_install._backup_gate): отказ носителя
    резерва снимает загрузку, а новый файл идёт без резерва и без лишних
    спросов на сервер.
"""
import os
import stat
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

import fmanager as fm
from common import BACKUP_SUBDIRS, q
from support import FakeSSH

_S_IFLNK = stat.S_IFLNK


class _Attrs:
    """Как paramiko.SFTPAttributes: имя + режим + размер + mtime."""

    def __init__(self, filename, mode, size=0, mtime=0):
        self.filename = filename
        self.st_mode = mode
        self.st_size = size
        self.st_mtime = mtime


class _Handle:
    """Handle из open(): запись только в разрешённых режимах, как у SFTP."""

    def __init__(self, sftp, path, mode):
        self.sftp = sftp
        self.path = path
        self.mode = mode
        self.chunks = []

    def write(self, data):
        if 'w' not in self.mode and 'a' not in self.mode:
            raise IOError(3, 'Permission denied: режим открытия без WRITE')
        self.chunks.append(data)
        return len(data)

    def read(self):
        return self.sftp.files.get(self.path, '')

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.sftp.files[self.path] = ''.join(self.chunks)
        return False


class FakeSftp:
    """Мини-ФС сервера. stat бросает IOError с ПЕРВЫМ аргументом-кодом, как
    paramiko: по этому коду fmanager различает «нет», «нет прав» и обрыв."""

    NO_SUCH = 2
    PERM = 3
    EXISTS = 4

    def __init__(self, files=None, dirs=None, stat_errors=None, links=()):
        self.files = dict(files or {})
        self.dirs = set(dirs or ['/'])
        self.stat_errors = dict(stat_errors or {})   # путь -> код отказа
        self.links = set(links)
        self.renames = []
        self.puts = []
        self.removed = []
        self.rmdirs = []
        self.mkdirs = []
        self.closed = 0

    # --- контракты paramiko, которые использует fmanager ------------------
    def stat(self, path):
        if path in self.stat_errors:
            raise IOError(self.stat_errors[path], 'stat failed: %s' % path)
        if path in self.files or path in self.dirs or path in self.links:
            return len(self.files.get(path, ''))
        raise IOError(self.NO_SUCH, 'No such file: %s' % path)

    def open(self, path, mode='r'):
        # paramiko: 'x' добавляет EXCL и сервер отвечает EXISTS, если занято.
        if 'x' in mode and path in self.files:
            raise IOError(self.EXISTS, 'Already exists: %s' % path)
        handle = _Handle(self, path, mode)
        if 'w' in mode and path not in self.files:
            self.files[path] = ''
        return handle

    def mkdir(self, path):
        if path in self.dirs or path in self.files:
            raise IOError(self.EXISTS, 'Already exists: %s' % path)
        self.mkdirs.append(path)
        self.dirs.add(path)

    def remove(self, path):
        if path in self.dirs:
            raise IOError(43, 'Directory non-empty')   # EISDIR-ish
        if path not in self.files and path not in self.links:
            raise IOError(self.NO_SUCH, 'No such file: %s' % path)
        self.removed.append(path)
        self.files.pop(path, None)
        self.links.discard(path)

    def rmdir(self, path):
        if path not in self.dirs:
            raise IOError(self.NO_SUCH, 'Not a directory: %s' % path)
        if any(o.startswith(path.rstrip('/') + '/') for o in
               list(self.files) + list(self.dirs) + list(self.links)):
            raise IOError(39, 'Directory non-empty')
        self.rmdirs.append(path)
        self.dirs.discard(path)

    def rename(self, old, new):
        # posix-rename@openssh.com перезаписывает цель — ровно та опасность,
        # ради которой fmanager спрашивает цель ДО вызова.
        if old not in self.files and old not in self.dirs and old not in self.links:
            raise IOError(self.NO_SUCH, 'No such file: %s' % old)
        self.renames.append((old, new))
        if old in self.files:
            self.files[new] = self.files.pop(old)
        elif old in self.dirs:
            self.dirs.discard(old)
            self.dirs.add(new)
        else:
            self.links.discard(old)
            self.links.add(new)

    def put(self, local, remote):
        self.puts.append((local, remote))
        with open(local, 'rb') as f:          # читаем как сервер, не «верим»
            self.files[remote] = f.read().decode('utf-8', 'ignore')

    def listdir_attr(self, path):
        prefix = path.rstrip('/') + '/'
        out = []
        for name in sorted(self.dirs | set(self.files) | self.links):
            if not name.startswith(prefix) or name == path:
                continue
            rest = name[len(prefix):]
            if not rest or '/' in rest:
                continue
            if name in self.dirs:
                mode = stat.S_IFDIR | 0o755
            elif name in self.links:
                mode = _S_IFLNK | 0o777
            else:
                mode = stat.S_IFREG | 0o644
            out.append(_Attrs(rest, mode, len(self.files.get(name, ''))))
        return out

    def close(self):
        self.closed += 1


class _Client:
    def __init__(self, sftp):
        self._sftp = sftp

    def open_sftp(self):
        return self._sftp


def _checker(sftp, routes=None):
    """FakeSSH вокруг двойника ФС; routes — сценарий ответов shell (спрос резерва)."""
    return FakeSSH(client=_Client(sftp), routes=routes)


class TestPresenceIsDecidedByCode:
    """«Цели нет» даёт только SSH_FX_NO_SUCH_FILE (2), прочий код — «не видно»."""

    def test_permission_denied_is_not_absence(self):
        sftp = FakeSftp(stat_errors={'/etc/x.conf': FakeSftp.PERM})
        with pytest.raises(IOError) as got:
            fm._exists(sftp, '/etc/x.conf')
        assert got.value.args[0] == FakeSftp.PERM

    def test_no_such_file_is_false(self):
        sftp = FakeSftp()
        assert fm._exists(sftp, '/etc/нет-такого') is False


class TestCreateFile:
    def test_existing_file_is_not_truncated(self):
        # Прежний режим 'w' обнулял чужой файл и рапортовал «✅ Файл создан».
        sftp = FakeSftp(files={'/etc/nginx/nginx.conf': 'worker_processes 4;'})
        out = fm.create_file(_checker(sftp), '/etc/nginx/nginx.conf')
        assert out.startswith('❌') and 'уже существует' in out
        assert sftp.files['/etc/nginx/nginx.conf'] == 'worker_processes 4;'

    def test_absent_file_is_created_empty(self):
        sftp = FakeSftp()
        out = fm.create_file(_checker(sftp), '/etc/nginx/new.conf')
        assert out.startswith('✅')
        assert sftp.files['/etc/nginx/new.conf'] == ''

    def test_race_is_lost_by_server_not_by_us(self):
        # Проверка «занято» прошла, а файл заняли между проверкой и открытием:
        # режим 'wx' (CREATE|EXCL) отвечает EXISTS, и нашего слова в этом решении
        # нет — содержимое чужого файла не пострадает. Голый IOError наружу
        # раннер печатал бы как «❌ Ошибка: …» без объяснения: модуль обязан
        # назвать беду сам (вежливый отказ вместо исключения).
        sftp = FakeSftp()
        real_open = sftp.open

        def racing_open(path, mode='r'):
            sftp.files[path] = 'чужие данные'
            return real_open(path, mode)

        sftp.open = racing_open
        out = fm.create_file(_checker(sftp), '/etc/race.conf')
        assert out.startswith('❌') and 'появился между проверкой' in out
        assert sftp.files['/etc/race.conf'] == 'чужие данные'

    def test_unseen_target_cancels_creation(self):
        sftp = FakeSftp(stat_errors={'/etc/locked.conf': FakeSftp.PERM})
        out = fm.create_file(_checker(sftp), '/etc/locked.conf')
        assert out.startswith('❌') and 'не проверено' in out
        assert '/etc/locked.conf' not in sftp.files

    def test_handle_is_closed_on_every_exit(self):
        sftp = FakeSftp(stat_errors={'/etc/locked.conf': FakeSftp.PERM})
        fm.create_file(_checker(sftp), '/etc/locked.conf')
        assert sftp.closed == 1
        sftp2 = FakeSftp()
        fm.create_file(_checker(sftp2), '/etc/ok.conf')
        assert sftp2.closed == 1


class TestRenameKeepsTarget:
    def test_existing_target_is_not_overwritten(self):
        sftp = FakeSftp(files={'/etc/a.conf': 'новое', '/etc/b.conf': 'важное'})
        out = fm.rename_path(_checker(sftp), '/etc/a.conf', '/etc/b.conf')
        assert out.startswith('❌') and 'Цель уже существует' in out
        assert sftp.files['/etc/b.conf'] == 'важное'
        assert sftp.renames == []          # переименование НЕ отправлено

    def test_unseen_target_cancels_rename(self):
        # Не «цели нет», а «цели не увидели» (обрыв, права): под таким
        # признаком rename может стереть существующий файл.
        sftp = FakeSftp(files={'/etc/a.conf': 'новое'},
                        stat_errors={'/etc/b.conf': FakeSftp.PERM})
        out = fm.rename_path(_checker(sftp), '/etc/a.conf', '/etc/b.conf')
        assert out.startswith('❌') and 'не проверена' in out
        assert sftp.renames == []

    def test_free_target_renames(self):
        sftp = FakeSftp(files={'/etc/a.conf': 'данные'})
        out = fm.rename_path(_checker(sftp), '/etc/a.conf', '/etc/c.conf')
        assert out.startswith('✅')
        assert sftp.renames == [('/etc/a.conf', '/etc/c.conf')]
        assert sftp.files['/etc/c.conf'] == 'данные'


class TestUpload:
    """put() читает локальный файл по-настоящему — temporary_directory не в счёт."""

    def _local(self, tmp_path, text):
        src = tmp_path / 'файл с пробелом.txt'
        src.write_text(text, encoding='utf-8')
        return str(src)

    def test_overwrite_is_named_in_the_answer(self, tmp_path):
        sftp = FakeSftp(files={'/etc/r.conf': 'старая версия'})
        out = fm.upload_file(_checker(sftp), self._local(tmp_path, 'новая версия'),
                             '/etc/r.conf')
        assert 'перезаписан' in out and '/etc/r.conf' in out
        assert sftp.files['/etc/r.conf'] == 'новая версия'

    def test_new_file_answer_stays_a_path(self, tmp_path):
        sftp = FakeSftp()
        src = self._local(tmp_path, 'данные')
        assert fm.upload_file(_checker(sftp), src, '/etc/new.conf') == '/etc/new.conf'
        assert sftp.files['/etc/new.conf'] == 'данные'

    def test_unseen_target_is_an_answer_not_a_traceback(self):
        # Прежний вид бросал IOError наружу; GUI показывал «❌ Ошибка:
        # [Errno 3] Permission denied» без слова о том, что загрузка НЕ
        # отправлена.
        sftp = FakeSftp(stat_errors={'/etc/r.conf': FakeSftp.PERM})
        out = fm.upload_file(_checker(sftp), '/локальный/файл.txt', '/etc/r.conf')
        assert out.startswith('❌') and 'не проверена' in out
        assert sftp.puts == [] and sftp.files == {}

    def test_connection_is_closed_on_the_veto_path(self):
        sftp = FakeSftp(stat_errors={'/etc/r.conf': FakeSftp.PERM})
        fm.upload_file(_checker(sftp), '/л.txt', '/etc/r.conf')
        assert sftp.closed == 1


class TestOverwriteNeedsAcceptedBackup:
    """Перезапись существующей цели стоит только по принятому резерву.

    Закон тот же, что у массовой замены IP (files._etc_backup_or_veto) и у
    установки сертификатов (ssl_install._backup_gate): право на разрушающую
    операцию даёт записанный и перечитанный откат. Прежний upload_file жал
    put по существующему пути и рапортовал о перезаписи — оператор терял
    предыдущую версию файла одним кликом, без средства откатиться.
    """

    def _local(self, tmp_path, text):
        src = tmp_path / 'новая_версия.conf'
        src.write_text(text, encoding='utf-8')
        return str(src)

    def test_existing_target_is_backed_up_before_put(self, tmp_path):
        # Двойник по умолчанию отвечает rc=0 на всё: резерв принимается, и
        # ответ обязан назвать, КУДА лёг откат, а не только факт перезаписи.
        sftp = FakeSftp(files={'/etc/r.conf': 'старая версия'})
        c = _checker(sftp)
        out = fm.upload_file(c, self._local(tmp_path, 'новая версия'), '/etc/r.conf')
        cp = c.find('cp ')
        assert cp is not None, 'резерв не спросили до перезаписи'
        assert q('/etc/r.conf') in cp
        assert cp.startswith('cp ') and '.bak' in cp
        assert BACKUP_SUBDIRS['configs'] in out
        assert 'перезаписан' in out and sftp.puts

    def test_refused_backup_cancels_the_upload(self, tmp_path):
        # cp отказал: put НЕ отправляется, прежняя версия остаётся на месте.
        sftp = FakeSftp(files={'/etc/r.conf': 'старая версия'})
        c = _checker(sftp, routes=[('cp ', ('cp: cannot create regular file: '
                                            'Read-only file system', '', 1))])
        out = fm.upload_file(c, self._local(tmp_path, 'новая версия'), '/etc/r.conf')
        assert out.startswith('❌')
        assert 'Read-only file system' in out      # причина названа словами cp
        assert 'не отправлено ничего' in out
        assert sftp.puts == [] and sftp.files['/etc/r.conf'] == 'старая версия'
        assert c.find('cp ') is not None           # спрос успел прозвучать

    def test_unreadable_source_is_not_absence(self, tmp_path):
        # «test -f» молчит в правах, список каталога не прочитан: это
        # unchecked, а не «файла нет» (common.file_presence). Молчать под этим
        # признаком — значит перезаписать то, чего не видели.
        sftp = FakeSftp(files={'/etc/r.conf': 'старая версия'})
        c = _checker(sftp, routes=[
            ('test -f', ('', 'Permission denied', 1)),
            ('ls -1 -p', ('', 'Permission denied', 2)),
        ])
        out = fm.upload_file(c, self._local(tmp_path, 'новая версия'), '/etc/r.conf')
        assert out.startswith('❌') and 'не прочитан' in out
        assert sftp.puts == [] and sftp.files['/etc/r.conf'] == 'старая версия'

    def test_shell_disagreement_is_not_permission_to_overwrite(self, tmp_path):
        # SFTP цель видит, а достоверный список каталога её не содержит:
        # состояния разошлись. «Писать нечего» здесь — ложное «нет», и прежняя
        # серия запрещает решать по нему destructive-операцию.
        sftp = FakeSftp(files={'/etc/r.conf': 'старая версия'})
        c = _checker(sftp, routes=[
            ('test -f', ('', 'Не является обычным файлом', 1)),
            ('ls -1 -p', ('', '', 0)),             # пустой достоверный список
        ])
        out = fm.upload_file(c, self._local(tmp_path, 'новая версия'), '/etc/r.conf')
        assert out.startswith('❌') and 'SFTP его видит' in out
        assert sftp.puts == []

    def test_promised_backup_that_did_not_appear_cancels_upload(self, tmp_path):
        # cp вернул 0, а бэкапа на диске нет: право на «резерв есть» даёт
        # перечитанный факт, а не код возврата (закон 1.32.13 в create_backup_info).
        sftp = FakeSftp(files={'/etc/r.conf': 'старая версия'})
        c = _checker(sftp, routes=[
            ('test -f /root/tech_support', ('', 'No such file', 1)),
            ('ls -1 -p /root/tech_support', ('', 'Permission denied', 2)),
        ])
        out = fm.upload_file(c, self._local(tmp_path, 'новая версия'), '/etc/r.conf')
        assert out.startswith('❌') and 'а бэкапа нет' in out
        assert sftp.puts == [] and sftp.files['/etc/r.conf'] == 'старая версия'

    def test_refusal_still_closes_the_connection(self, tmp_path):
        sftp = FakeSftp(files={'/etc/r.conf': 'старая версия'})
        c = _checker(sftp, routes=[('cp ', ('cp: Input/output error', '', 1))])
        fm.upload_file(c, self._local(tmp_path, 'новая версия'), '/etc/r.conf')
        assert sftp.closed == 1

    def test_new_file_is_uploaded_without_any_backup(self, tmp_path):
        # Новое имя: резервить нечего, и модуль не имеет права платить за это
        # спросами на сервере — прежний путь загрузки обязан остаться как шёл.
        sftp = FakeSftp()
        c = _checker(sftp)
        src = self._local(tmp_path, 'данные')
        assert fm.upload_file(c, src, '/etc/new.conf') == '/etc/new.conf'
        assert c.commands == [], 'для нового файла резерв не спрашивают'
        assert sftp.files['/etc/new.conf'] == 'данные'


class TestDotDotIsRefused:
    """Имя из диалога склеивается с каталогом и сервер разворачивает '..'."""

    def test_paths_reach_no_transport(self):
        sftp = FakeSftp(files={'/etc/passwd': 'root:*:0:0::/root:/bin/bash'})
        c = _checker(sftp)
        for call in (lambda: fm.make_dir(c, '/var/www/../../etc/evil'),
                     lambda: fm.create_file(c, '/var/www/../../etc/passwd'),
                     lambda: fm.delete_path(c, '/var/www/../../etc/passwd'),
                     lambda: fm.rename_path(c, '/var/www/x', '/etc/../../etc/x'),
                     lambda: fm.upload_file(c, '/локал.txt',
                                            '/var/www/../etc/x')):
            out = call()
            assert isinstance(out, str) and out.startswith('❌'), out
        assert sftp.mkdirs == [] and sftp.removed == [] and sftp.puts == []
        assert sftp.files['/etc/passwd'].startswith('root:')

    def test_relative_path_is_refused(self):
        sftp = FakeSftp()
        assert fm.make_dir(_checker(sftp), 'etc/nginx').startswith('❌')

    def test_plain_nested_path_is_allowed(self):
        sftp = FakeSftp(dirs=['/etc', '/etc/nginx'])
        out = fm.make_dir(_checker(sftp), '/etc/nginx/conf.d')
        assert out.startswith('✅')


class TestDelete:
    def test_directory_is_removed_bottom_up(self):
        sftp = FakeSftp(dirs=['/etc', '/etc/d', '/etc/d/sub'],
                        files={'/etc/d/a.conf': 'a', '/etc/d/sub/b.conf': 'b'})
        out = fm.delete_path(_checker(sftp), '/etc/d', is_dir=True)
        assert out.startswith('✅')
        assert sftp.rmdirs == ['/etc/d/sub', '/etc/d']
        assert not [p for p in sftp.files if p.startswith('/etc/d/')]

    def test_symlink_to_directory_is_unlinked_not_walked(self):
        # listdir_attr отдаёт lstat-режим: у ссылки S_ISLNK, а не S_IFDIR,
        # значит снимается сама ссылка. Пройти по ней внутрь — значит удалить
        # каталог, который оператор в списке видел одной строкой.
        sftp = FakeSftp(dirs=['/etc', '/etc/d', '/var/lib/important'],
                        files={'/etc/d/keep.conf': 'k'},
                        links={'/etc/d/link': '/var/lib/important'})
        out = fm.delete_path(_checker(sftp), '/etc/d', is_dir=True)
        assert out.startswith('✅')
        assert '/etc/d/link' in sftp.removed
        assert '/var/lib/important' in sftp.dirs       # цель цела
        assert 'keep.conf' not in sftp.files

    def test_file_removal_names_the_path(self):
        sftp = FakeSftp(files={'/etc/x.conf': 'x'})
        assert fm.delete_path(_checker(sftp), '/etc/x.conf') == '✅ Удалено: /etc/x.conf'
        assert sftp.removed == ['/etc/x.conf']


class TestListingStillLaysOut:
    """Список каталога — то, что видит оператор перед удалением."""

    def test_dirs_first_links_marked(self):
        sftp = FakeSftp(dirs=['/etc', '/etc/подкаталог'],
                        files={'/etc/файл.conf': 'abc'},
                        links={'/etc/ссылка': '/etc/файл.conf'})
        entries = fm.list_dir(_checker(sftp), '/etc')
        rows = fm.format_entries(entries)
        labels = [r[0] for r in rows]
        # Папка первой (is_dir), дальше по алфавиту: 'ссылка' < 'файл'.
        assert labels == ['подкаталог/', 'ссылка@', 'файл.conf']
        assert [r[1] for r in rows] == ['папка', 'ссылка', 'файл']
        assert rows[2][2] == '3 B'

    def test_empty_path_falls_back_to_root(self):
        sftp = FakeSftp(dirs=['/', '/etc'])
        assert [e['name'] for e in fm.list_dir(_checker(sftp), '')] == ['etc']
