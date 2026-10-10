"""Тесты ssh_client.py: подключение, heartbeat, выполнение команд, отмена.

paramiko подменяется заглушкой — реального SSH нет. Проверка идёт по тому,
что именно передаётся в paramiko.SSHClient и как разбираются его исключения.
"""
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

import pytest

import ssh_client as sc


# ==================== заглушка paramiko ====================
class _Stream:
    def __init__(self, data=b'', channel=None):
        self._data = data
        self.channel = channel

    def read(self):
        return self._data


class _Channel:
    def __init__(self, exit_status=0, raise_status=False):
        self.exit_status = exit_status
        self.raise_status = raise_status
        self.closed = 0

    def recv_exit_status(self):
        if self.raise_status:
            raise RuntimeError('channel closed')
        return self.exit_status

    def close(self):
        self.closed += 1


class _Transport:
    def __init__(self, active=True, raise_exc=False):
        self.active = active
        self.raise_exc = raise_exc

    def is_active(self):
        if self.raise_exc:
            raise RuntimeError('transport died')
        return self.active


class FakeSSHClient:
    instances = []

    def __init__(self):
        self.connect_kwargs = None
        self.policies = []
        self.loaded_system = False
        self.loaded_host_keys = []
        self.closed = 0
        self.transport = None
        self.exec_result = None
        FakeSSHClient.instances.append(self)

    def load_system_host_keys(self):
        self.loaded_system = True

    def load_host_keys(self, path):
        self.loaded_host_keys.append(path)

    def set_missing_host_key_policy(self, policy):
        self.policies.append(type(policy).__name__)

    def connect(self, **kwargs):
        self.connect_kwargs = kwargs
        exc = getattr(FakeParamiko, 'connect_exc', None)
        if exc:
            raise exc

    def get_transport(self):
        return self.transport

    def exec_command(self, cmd):
        self.last_cmd = cmd
        channel = self.exec_channel
        return (None, _Stream(self.exec_result[0], channel),
                _Stream(self.exec_result[1], channel))

    def close(self):
        self.closed += 1


class _Policy:
    pass


class FakeParamiko:
    SSHClient = FakeSSHClient
    RejectPolicy = _Policy
    AuthenticationException = type('AuthenticationException', (Exception,), {})
    SSHException = type('SSHException', (Exception,), {})
    connect_exc = None


@pytest.fixture(autouse=True)
def _patch_paramiko(monkeypatch):
    FakeSSHClient.instances = []
    FakeParamiko.connect_exc = None
    monkeypatch.setattr(sc, 'paramiko', FakeParamiko)
    # известным хостам считаем несуществующими: load_host_keys не дёргается
    monkeypatch.setattr(os.path, 'exists', lambda p: False)
    yield


def _checker(**kw):
    return sc.ServerChecker('h.example', 22, 'root', password='secret', **kw)


# ==================== connect ====================
class TestConnect:
    def test_password_login_success_clears_password(self):
        c = _checker()
        ok, msg = c.connect()
        assert (ok, msg) == (True, 'Подключено')
        client = FakeSSHClient.instances[0]
        assert client.connect_kwargs['password'] == 'secret'
        assert client.connect_kwargs['hostname'] == 'h.example'
        assert client.connect_kwargs['port'] == 22
        # секрет не должен жить в объекте после подключения
        assert c.password is None
        # MITM-политика: неизвестные ключи отклоняются
        assert client.policies == ['_Policy']
        assert client.loaded_system is True

    def test_key_login_uses_key_filename(self, monkeypatch):
        monkeypatch.setattr(os.path, 'exists', lambda p: True)
        c = sc.ServerChecker('h', 22, 'root', key_filename='~/.ssh/id_rsa')
        ok, _ = c.connect()
        assert ok is True
        client = FakeSSHClient.instances[0]
        assert 'key_filename' in client.connect_kwargs
        assert 'password' not in client.connect_kwargs
        # known_hosts подхвачен, когда файл существует
        assert client.loaded_host_keys

    def test_auth_exception_message(self):
        FakeParamiko.connect_exc = FakeParamiko.AuthenticationException('bad')
        ok, msg = _checker().connect()
        assert ok is False and 'Ошибка аутентификации' in msg

    def test_ssh_exception_message(self):
        FakeParamiko.connect_exc = FakeParamiko.SSHException('kex failed')
        ok, msg = _checker().connect()
        assert ok is False and 'SSH ошибка: kex failed' in msg

    def test_generic_exception_includes_host(self):
        FakeParamiko.connect_exc = OSError('timed out')
        ok, msg = _checker().connect()
        assert ok is False
        assert 'h.example:22' in msg and 'OSError' in msg

    def test_password_cleared_on_every_failure(self):
        for exc in (FakeParamiko.AuthenticationException('x'),
                    FakeParamiko.SSHException('x'), OSError('x')):
            FakeParamiko.connect_exc = exc
            c = _checker()
            c.connect()
            assert c.password is None


# ==================== is_alive ====================
class TestIsAlive:
    def test_false_without_client(self):
        assert _checker().is_alive() is False

    def test_true_when_transport_active(self):
        c = _checker()
        c.connect()
        FakeSSHClient.instances[0].transport = _Transport(active=True)
        assert c.is_alive() is True

    def test_false_when_transport_dead_or_missing(self):
        c = _checker()
        c.connect()
        FakeSSHClient.instances[0].transport = _Transport(active=False)
        assert c.is_alive() is False
        FakeSSHClient.instances[0].transport = None
        assert c.is_alive() is False

    def test_false_on_exception(self):
        c = _checker()
        c.connect()
        FakeSSHClient.instances[0].transport = _Transport(raise_exc=True)
        assert c.is_alive() is False


# ==================== выполнение команд ====================
class TestExec:
    def _connected(self, out=b'', err=b'', exit_status=0, raise_status=False):
        c = _checker()
        c.connect()
        client = FakeSSHClient.instances[0]
        channel = _Channel(exit_status=exit_status, raise_status=raise_status)
        client.exec_channel = channel
        client.exec_result = (out, err)
        return c, client, channel

    def test_run_returns_triple(self):
        c, _, ch = self._connected(out=b'ok\n', err=b'warn\n', exit_status=3)
        assert c.run('ls') == ('ok\n', 'warn\n', 3)

    def test_exec_command_pair(self):
        c, _, _ = self._connected(out=b'a', err=b'b')
        assert c.exec_command('ls') == ('a', 'b')

    def test_non_utf8_bytes_are_dropped_not_crash(self):
        # decode(errors='ignore'): невалидные байты ОТБРАСЫВАЮТСЯ (не заменяются
        # на U+FFFD), валидная часть сохраняется, исключения нет.
        c, _, _ = self._connected(out=b'ok\n\xff\xfe')
        out, err, rc = c.run('ls')
        assert out == 'ok\n' and rc == 0

    def test_exit_status_error_becomes_minus_one(self):
        c, _, _ = self._connected(out=b'x', raise_status=True)
        assert c.run('ls') == ('x', '', -1)

    def test_no_connection_raises(self):
        with pytest.raises(Exception, match='Нет активного соединения'):
            _checker().run('ls')

    def test_cancel_blocks_next_command(self):
        c, _, _ = self._connected(out=b'x')
        c.cancel()
        with pytest.raises(Exception, match='Операция отменена'):
            c.run('ls')
        c.reset_cancel()
        assert c.run('ls')[0] == 'x'


# ==================== cancel / close ====================
class TestCancelClose:
    def test_cancel_closes_running_channel(self):
        c = _checker()
        c.connect()
        client = FakeSSHClient.instances[0]
        client.exec_channel = _Channel()
        client.exec_result = (b'', b'')
        c._current_channel = client.exec_channel
        c.cancel()
        assert client.exec_channel.closed == 1
        assert c.cancel_event.is_set()

    def test_close_releases_client(self):
        c = _checker()
        c.connect()
        client = FakeSSHClient.instances[0]
        c.close()
        assert client.closed == 1
        assert c.client is None

    def test_close_without_client_is_quiet(self):
        _checker().close()  # не должно бросить
