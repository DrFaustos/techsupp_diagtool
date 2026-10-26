"""Общие заглушки SSH/SFTP для тестов (без реального соединения).

FakeSSH имитирует ServerChecker: ответы подбираются по подстроке команды,
первое совпадение выигрывает — поэтому в routes сначала идут более специфичные
иглы. Так же, как настоящий сервер, заглушка различает run() -> (out, err, rc)
и exec_command() -> (out, err).

С 1.32.0 заглушка умеет РАСКРЫВАТЬ сводную команду чтения конфигов
(`set -- п1 п2 …; for f in "$@"; do v=$(grep -h 'server_name' "$f" 2>&1); …`) —
делает ровно то, что на сервере делает shell: берёт каждый путь, спрашивает
внутреннюю grep-команду у собственных routes и пакует ответы в printf-маркеры
с отдельным rc. Без этого любая существующая маршрутизация ('grep -h', …)
на новой команде молчала бы, а молчание продукт обязан толковать как пробел:
tесты зазеленели бы по НЕВЕРНОЙ причине (урок 1.27.0). Механизм живёт в ОДНОМ
месте — второй реализации протокола в тестах быть не должно.

Формат маркера и поведение каналов СНЯТЫ ЖИВЬЁМ (замер 1.32.0, настоящий
/bin/bash, реальные файлы): тело = stdout+stderr grep'а (команда объединяет
каналы через 2>&1), stderr самой сводной команды при этом пуст.
"""

import shlex

from common import q

BATCH_MARKER = '@F'


def batch_paths(cmd):
    """Пути из сводной команды: участок между `set --` и первым `;`, через shlex.

    Наивный перебор токенов, начинающихся с '/', вытащил бы ещё и аргументы
    printf; а cmd.split("'")[1] даёт НЕ путь, а слово server_name: кавычек в
    команде две, и первая пара — вокруг паттерна. Проверено прогоном: такой
    разбор молча кормит все файлы одним ответом, и тест «группы не сливаются»
    ничего не проверяет.
    """
    if 'set --' not in cmd or BATCH_MARKER not in cmd:
        return []
    seg = cmd.split('set --', 1)[1].split(';', 1)[0]
    try:
        return shlex.split(seg)
    except ValueError:
        return []


def menu_handlers(menu):
    """Имена обработчиков из состава меню — рекурсивно, включая подменю.

    Состав меню: [(подпись, имя_метода)], None (разделитель) либо
    (подпись, [пункты]) — вложенное подменю. Раньше тесты распаивали пару
    списковым comprehension'ом; с появлением подменю он бросил бы TypeError на
    getattr(список), поэтому сбор вынесен сюда и стал общим для всех меню.
    Подписи подменю и разделители в список не попадают — обработчика у них нет.
    """
    out = []
    for entry in menu:
        if entry is None:
            continue
        _label, value = entry
        if isinstance(value, (list, tuple)):
            out.extend(menu_handlers(value))
        else:
            out.append(value)
    return out


class FakeSSH:
    """Заглушка ServerChecker с маршрутизацией команд по подстроке."""

    def __init__(self, routes=None, default=('', '', 0), client=None):
        self.routes = []
        for needle, res in (routes or []):
            if isinstance(res, list):
                # Последовательность ответов на одну иглу: каждое следующее
                # совпадение получает следующий элемент (для сценариев
                # «проверил — починил — проверил снова»). Последний элемент —
                # постоянный.
                res = [self._norm(r) for r in res]
            else:
                res = self._norm(res)
            self.routes.append((needle, res))
        self.default = default
        self.client = client
        self.commands = []
        # ServerChecker живёт с host/port (их печатает сводный отчёт), поэтому
        # заглушка тоже их имеет — иначе тестам приходится приклеивать атрибуты
        # снаружи.
        self.host = 'test-host'
        self.port = 22

    @staticmethod
    def _norm(res):
        if isinstance(res, str):
            return (res, '', 0)
        if len(res) == 2:
            return (res[0], res[1], 0)
        return res

    def _batch_row(self, path):
        """Один ответ сводной команды: (out, err, rc) либо None — ответа нет.

        None — это модель ОБРЫВА сводной команды в середине (таймаут канала,
        чужая реализация): путь не получает маркера вовсе. Переопределяется
        тестами, которым нужен именно обрыв, а не честный ответ grep.
        """
        return self._answer(f"grep -h 'server_name' {q(path)} 2>&1")

    def _batch_out(self, cmd):
        """Маркерный вывод на сводную команду — как у настоящего shell.

        Тело = stdout + stderr внутреннего grep: сводная команда объединяет
        каналы (2>&1), поэтому раздельных каналов у неё нет (замер живьём:
        stderr самой сводной команды пуст).
        """
        out = []
        for path in batch_paths(cmd):
            row = self._batch_row(path)
            if row is None:
                continue
            o, e, rc = self._norm(row)
            out.append(f'{BATCH_MARKER} {int(rc)}\t{path}')
            body = ((o or '') + (e or '')).rstrip('\n')
            if body:
                out.append(body)
        return '\n'.join(out) + ('\n' if out else '')

    @staticmethod
    def ls_glob(cmd):
        """Glob (аргумент ls) из команды find_files_cmd — разбор формы в одном месте.

        Тесты, проверяющие «имя домена не стало командой», обязаны смотреть на
        ТОЛЬКО glob: `;` и `"` есть в самой служебной конструкции shell (состояние
        каталога спрашивается ДО ls, а с 1.32.3 там же снимается rc), и прежний
        naive-split принимал написанную нами часть за имя домена — замок краснел
        по причине, не связанной с инъекцией.

        Граница определена списком известных терминаторов, а не «всем, что
        дальше»: форма команды меняется релизами (1.20.0 — составная, 1.32.3 —
        группа с FFRC), и каждый тест не должен переучивать её заново.
        """
        if 'ls -1 ' not in cmd:
            return None
        tail = cmd.split('ls -1 ', 1)[1]
        ends = [i for i in (tail.find('; echo "FFRC'), tail.find(' |'))
                if i != -1]
        return tail[:min(ends)] if ends else tail

    @staticmethod
    def _with_ls_rc(cmd, res):
        """Догоняет ответ find_files_cmd до протокола FFRC (1.32.3).

        Боевая команда с 1.32.3 снимает код возврата ls ВНУТРИ группы, до
        конвейера с awk: код возврата конвейера принадлежит awk, и на сервере с
        большим парком это врало — «ls не запустилась (Argument list too
        long)» выглядело как честное «файлов нет, проверено» (замер живьём:
        rc=0, FFDIR ok, FFCOUNT 0 при rc ls = 126).

        Маркер обязан уметь говорить и двойник. Молчаливый двойник дал бы
        зелёные тесты по НЕВЕРНОЙ причине — тот же закон, что заперт выше для
        раскрытия пачки (1.32.0) и зафиксирован в v1.27.0.

        Признак берётся из КОМАНДЫ (она требует маркер), а не из ответа: если
        фикстура сама вынесла FFRC 2 или FFRC 126, она не трогается — два
        источника одного признака однажды разъезжаются. Позиция строки (перед
        FFCOUNT) и сам код сняты живьём в bash и dash, а не из удобства
        парсера.

        Пустой ответ остаётся пустым: подставить туда FFRC 0 значило бы
        выдумать успешный заход там, где сервер молчал (закон «не проверено»).
        """
        if 'FFRC' not in cmd or 'ls -1' not in cmd:
            return res
        out, err, rc = FakeSSH._norm(res)
        lines = (out or '').splitlines()
        if not lines or any(ln.startswith('FFRC ') for ln in lines):
            return (out, err, rc)
        mark = 'FFRC 0'
        for i, ln in enumerate(lines):
            if ln.startswith('FFCOUNT'):
                lines.insert(i, mark)
                break
        else:
            lines.append(mark)
        return ('\n'.join(lines) + '\n', err, rc)

    def _answer(self, cmd):
        # Раскрытие пачки — ПЕРВЫМ делом, до маршрутизации: на сервере первым
        # работает shell, а не наша логика. Иначе роут с широкой иглой ('grep')
        # перехватил бы сводную команду целиком, и двойник отвечал бы на всю
        # пачку одним ответом — тест «группы не сливаются» умер бы молча.
        if batch_paths(cmd):
            return (self._batch_out(cmd), '', 0)
        for needle, res in self.routes:
            if needle in cmd:
                if isinstance(res, list):
                    if len(res) > 1:
                        return res.pop(0)
                    return res[0]
                return res
        return self.default

    def run(self, cmd):
        self.commands.append(cmd)
        # Одна точка подключения протокола FFRC: и маршрутизованный ответ, и
        # default, и последовательность ответов получают маркер одинаково.
        # Переопределённые _answer двойники (эмуляция awk-срезки) попадают под
        # ту же обёртку — иначе они заговорили бы старым языком протокола.
        return self._with_ls_rc(cmd, self._answer(cmd))

    def exec_command(self, cmd):
        out, err, _ = self.run(cmd)
        return out, err

    def cleanup(self, cmd):
        """Как ServerChecker.cleanup: уборка вне отмены, но в self.commands."""
        return self.run(cmd)

    def find(self, needle):
        """Первая команда, содержащая needle (или None)."""
        for c in self.commands:
            if needle in c:
                return c
        return None

    def count(self, needle):
        return sum(1 for c in self.commands if needle in c)

    def find_all(self, needle):
        """Все команды, содержащие needle (порядок — как отправлялись)."""
        return [c for c in self.commands if needle in c]


class _RecordFile:
    def __init__(self, store, path):
        self.store = store
        self.path = path

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def write(self, data):
        self.store[self.path] = self.store.get(self.path, '') + data

    def read(self):
        if self.path not in self.store:
            raise IOError('no such file in fake store')
        return self.store[self.path]


class FakeSftpConn:
    """То, что возвращает client.open_sftp(): запись/чтение файлов в памяти."""

    def __init__(self, store):
        self.store = store
        self.closed = 0

    def open(self, path, mode='r'):
        return _RecordFile(self.store, path)

    def close(self):
        self.closed += 1


class FakeSftpClient:
    """Имитация paramiko-клиента: нужен common.write_remote_file и fmanager."""

    def __init__(self):
        self.store = {}
        self.conns = []

    def open_sftp(self):
        conn = FakeSftpConn(self.store)
        self.conns.append(conn)
        return conn

    @property
    def closed(self):
        return sum(c.closed for c in self.conns)


# Строка combined log format для тестов парсера и анализа access-логов.
LOG_OK_1 = ('198.51.100.7 - - [10/Oct/2026:13:55:36 +0300] '
            '"GET /index.php HTTP/1.1" 200 5432 "-" "Mozilla/5.0 (X11; Linux x86_64)"')
LOG_OK_2 = ('203.0.113.9 - - [10/Oct/2026:13:55:40 +0300] '
            '"GET /index.php HTTP/1.1" 500 231 "http://example.com/" "curl/8.0"')
LOG_OK_3 = ('198.51.100.7 - - [10/Oct/2026:13:56:01 +0300] '
            '"POST /wp-login.php HTTP/1.1" 404 1700 "-" "python-requests/2.31"')
LOG_OTHER_DAY = ('198.51.100.7 - - [09/Oct/2026:11:00:00 +0300] '
                 '"GET /old HTTP/1.1" 200 100 "-" "curl/8.0"')
LOG_BAD = 'вот это совсем не лог'
