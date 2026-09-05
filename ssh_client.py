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
        self.client = paramiko.SSHClient()
        # Используем более безопасную политику
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
            return True
        except Exception as e:
            print(f"Ошибка подключения к {self.host}:{self.port}")
            print(f"Тип ошибки: {type(e).__name__}")
            print(f"Сообщение: {str(e)}")
            traceback.print_exc()
            return False

    def exec_command(self, command):
        if not self.client:
            raise Exception("Нет активного соединения")
        stdin, stdout, stderr = self.client.exec_command(command)
        return stdout.read().decode('utf-8', errors='ignore'), stderr.read().decode('utf-8', errors='ignore')

    def close(self):
        if self.client:
            self.client.close()