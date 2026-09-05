import paramiko
import os
import traceback

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
        # Используем WarningPolicy для безопасности
        self.client.set_missing_host_key_policy(paramiko.WarningPolicy())
        try:
            if self.key_filename and os.path.exists(self.key_filename):
                self.client.connect(
                    hostname=self.host,
                    port=self.port,
                    username=self.username,
                    key_filename=self.key_filename,
                    timeout=10,
                    allow_agent=False,
                    look_for_keys=False
                )
            else:
                self.client.connect(
                    hostname=self.host,
                    port=self.port,
                    username=self.username,
                    password=self.password or '',
                    timeout=10,
                    allow_agent=False,
                    look_for_keys=False
                )
            return True, "Подключено"
        except paramiko.AuthenticationException:
            return False, "Ошибка аутентификации: проверьте логин/пароль или ключ"
        except paramiko.SSHException as e:
            return False, f"SSH ошибка: {str(e)}"
        except Exception as e:
            error_msg = f"Ошибка подключения к {self.host}:{self.port}\nТип: {type(e).__name__}\nСообщение: {str(e)}"
            return False, error_msg

    def exec_command(self, command):
        if not self.client:
            raise Exception("Нет активного соединения")
        stdin, stdout, stderr = self.client.exec_command(command)
        return stdout.read().decode('utf-8', errors='ignore'), stderr.read().decode('utf-8', errors='ignore')

    def close(self):
        if self.client:
            self.client.close()