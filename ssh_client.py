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

    def connect(self):
        """Подключается к серверу. Возвращает (success, message)"""
        self.client = paramiko.SSHClient()
        # RejectPolicy: неизвестные ключи хостов отклоняются (защита от MITM).
        # Известные хосты берутся из системного ~/.ssh/known_hosts.
        self.client.set_missing_host_key_policy(paramiko.RejectPolicy())
        self.client.load_system_host_keys()
        try:
            known_hosts = os.path.expanduser('~/.ssh/known_hosts')
            if os.path.exists(known_hosts):
                self.client.load_host_keys(known_hosts)
        except Exception:
            pass

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
            # Пароль больше не нужен — очищаем из памяти.
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

    def _exec(self, command):
        """Низкоуровневый запуск: возвращает (stdout, stderr, exit_status)."""
        if not self.client:
            raise Exception("Нет активного соединения")
        stdin, stdout, stderr = self.client.exec_command(command)
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

        # Код возврата команды (0 = успех).
        try:
            exit_status = stdout.channel.recv_exit_status()
        except Exception:
            exit_status = -1

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
