"""Общие заглушки SSH/SFTP для тестов (без реального соединения).

FakeSSH имитирует ServerChecker: ответы подбираются по подстроке команды,
первое совпадение выигрывает — поэтому в routes сначала идут более специфичные
иглы. Так же, как настоящий сервер, заглушка различает run() -> (out, err, rc)
и exec_command() -> (out, err).
"""


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

    @staticmethod
    def _norm(res):
        if isinstance(res, str):
            return (res, '', 0)
        if len(res) == 2:
            return (res[0], res[1], 0)
        return res

    def _answer(self, cmd):
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
        return self._answer(cmd)

    def exec_command(self, cmd):
        out, err, _ = self.run(cmd)
        return out, err

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
