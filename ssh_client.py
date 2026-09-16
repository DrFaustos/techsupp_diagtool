import paramiko
import os
import threading


class ServerChecker:
    def __init__(self, host, port, username, password=None, key_filename=None):
        self.host = host
        self.port = port
        self.username = username
        self.password = password
        self.key_filename = os.path.expanduser(key_filename) if key_filename else None
        self.client = None
        # Событие отмены: используется для прерывания долгих задач.
        self.cancel_event = threading.Event()
        # Канал текущей команды (для принудительного закрытия).
        self._current_channel = None

    def cancel(self):
        """Запрашивает отмену текущей/следующих долгих операций."""
        self.cancel_event.set()
        ch = self._current_channel
        if ch is not None:
            try:
                ch.close()
            except Exception:
                pass

    def reset_cancel(self):
        self.cancel_event.clear()

    def connect(self):
        """Подключается к серверу. Возвращает (success, message)"""
        self.client = paramiko.SSHClient()
        # RejectPolicy: неизвестные ключи хостов отклоняются (защита от MITM).
        self.client.load_system_host_keys()
        try:
            known_hosts = os.path.expanduser('~/.ssh/known_hosts')
            if os.path.exists(known_hosts):
                self.client.load_host_keys(known_hosts)
        except Exception:
            pass
        self.client.set_missing_host_key_policy(paramiko.RejectPolicy())

        common_kwargs = dict(
            hostname=self.host,
            port=self.port,
            username=self.username,
            timeout=10,
            allow_agent=False,
            look_for_keys=False,
        )
        try:
            if self.key_filename and os.path.exists(self.key_filename):
                self.client.connect(key_filename=self.key_filename, **common_kwargs)
            else:
                self.client.connect(password=self.password or '', **common_kwargs)
            self.password = None
            return True, "Подключено"
        except paramiko.AuthenticationException:
            self.password = None
            return False, "Ошибка аутентификации: проверьте логин/пароль или ключ"
        except paramiko.SSHException as e:
            self.password = None
            return False, f"SSH ошибка: {str(e)}"
        except Exception as e:
            self.password = None
            error_msg = (
                f"Ошибка подключения к {self.host}:{self.port}\n"
                f"Тип: {type(e).__name__}\nСообщение: {str(e)}"
            )
            return False, error_msg

    def is_alive(self):
        """Проверяет живость соединения (для heartbeat)."""
        if not self.client:
            return False
        try:
            transport = self.client.get_transport()
            return bool(transport and transport.is_active())
        except Exception:
            return False

    def _exec(self, command):
        """Низкоуровневый запуск: возвращает (stdout, stderr, exit_status)."""
        if not self.client:
            raise Exception("Нет активного соединения")
        if self.cancel_event.is_set():
            raise Exception("Операция отменена")

        stdin, stdout, stderr = self.client.exec_command(command)
        self._current_channel = stdout.channel
        # Читаем каналы параллельно, чтобы избежать deadlock при большом выводе.
        stdout_chunks = []
        stderr_chunks = []

        def _read(stream, sink):
            try:
                sink.append(stream.read())
            except Exception:
                pass

        t_out = threading.Thread(target=_read, args=(stdout, stdout_chunks))
        t_err = threading.Thread(target=_read, args=(stderr, stderr_chunks))
        t_out.start()
        t_err.start()
        t_out.join()
        t_err.join()

        try:
            exit_status = stdout.channel.recv_exit_status()
        except Exception:
            exit_status = -1
        self._current_channel = None

        out = b''.join(stdout_chunks).decode('utf-8', errors='ignore')
        err = b''.join(stderr_chunks).decode('utf-8', errors='ignore')
        return out, err, exit_status

    def exec_command(self, command):
        """Обратная совместимость: возвращает (stdout, stderr)."""
        out, err, _ = self._exec(command)
        return out, err

    def run(self, command):
        """Возвращает (stdout, stderr, exit_status)."""
        return self._exec(command)

    def close(self):
        if self.client:
            try:
                self.client.close()
            except Exception:
                pass
            self.client = None
