import paramiko
import os
import threading
import time


# Жёсткий потолок ожидания команды на КАНАЛЕ (секунды). Раньше _exec читал
# stream.read() до EOF: зависшая удалённая команда (умерший носитель, молчащий
# резолвер, сдохший сокет) держала рабочий поток GUI до нажатия «Стоп», а
# shell-обёртка `timeout N` (конвенция модулей: максимум N=120 — dd в
# metrics.py) от этого не лечит: бинарного `timeout` в системе может не
# оказаться, а канал зависает независимо от неё. 600 выбраны заведомо больше
# всех обёрток проекта, чтобы сначала всегда срабатывала обёртка (её rc=124
# парсеры уже понимают), а наш потолок оставался сеткой, а не щитом. Для
# долгих операций (замер dd, скачивание файла) потолок передаётся параметром
# timeout конкретного вызова.
DEFAULT_COMMAND_TIMEOUT = 600

# Код возврата при истечении потолка — тот же, каким coreutils `timeout`
# убивает не успевшую команду. Существующие парсеры (metrics.parse_dd_speed,
# metrics.parse_external_ip_probe, webcheck.whois_no_data_lines) уже читают
# rc=124 как «таймаут», поэтому зависший канал отчитывается тем же знаком,
# что и зависшая команда, — и другим чем «команда отработала с пустым
# выводом» (у той rc=0), чего требовал контракт различимости.
COMMAND_DEADLINE_RC = 124

# Шаг опроса готовности канала (сек). 0.05 — баланс между задержкой
# обнаружения конца команды и шумом в CPU; потолок считается по time.monotonic
# на каждой итерации, поэтому на длительность ожидания шаг не влияет.
_POLL_INTERVAL = 0.05

# Максимум байт за один неблокирующий дрейж буфера канала.
_READ_CHUNK = 32768


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

    def _exec(self, command, ignore_cancel=False, timeout=None):
        """Низкоуровневый запуск: возвращает (stdout, stderr, exit_status).

        ignore_cancel=True — только для служебных команд (см. cleanup):
        «оператор нажал Стоп» означает «прекрати работу», а не «оставь файл с
        паролем на диске».

        timeout — жёсткий потолок ожидания на канале, сек; None означает
        DEFAULT_COMMAND_TIMEOUT. Реализован дрейжем канала по признакам
        готовности (recv_ready/recv_stderr_ready/exit_status_ready), а не
        read() до EOF: зависший канал теперь заканчивается за конечное время
        сам, без «Стоп». Потолок именно на канале, а не на потоках-читателях:
        читатель, оставленный висеть на мёртвом сокете, тек бы потоком до
        конца жизни процесса.
        """
        if not self.client:
            raise Exception("Нет активного соединения")
        if not ignore_cancel and self.cancel_event.is_set():
            raise Exception("Операция отменена")
        ceiling = DEFAULT_COMMAND_TIMEOUT if timeout is None else timeout

        # timeout у exec_command — штатный API paramiko: ограничивает не
        # чтение, а открытие сессии (open_session), где на мёртвом transport
        # можно зависнуть ещё до получения канала.
        _stdin, stdout, _stderr = self.client.exec_command(command, timeout=ceiling)
        chan = stdout.channel
        # stdin закрывается сразу: команда, читающая stdin (openssl на запросе
        # passphrase, `cat` без аргументов), иначе висела бы на всём потолке
        # канала — поштучное `< /dev/null` в отчётах было прикрытием именно
        # этой дыры. Ни один вызов проекта в stdin не пишет.
        try:
            chan.shutdown_write()
        except Exception:
            pass
        self._current_channel = chan
        out_chunks = []
        err_chunks = []
        deadline = time.monotonic() + ceiling
        expired = False
        try:
            while True:
                if not ignore_cancel and self.cancel_event.is_set():
                    # Отмена могла прийти в зазоре между возвратом
                    # exec_command и присваиванием _current_channel — cancel()
                    # тогда не нашёл бы канала. Закрываем сами: в paramiko
                    # закрытие взводит exit_status_ready, цикл выйдет на этой
                    # же итерации, а rc станет -1 (статус не приходил) — ровно
                    # как вела себя отмена раньше.
                    try:
                        chan.close()
                    except Exception:
                        pass
                try:
                    # Оба буфера дрейжим в одном цикле: stdout и stderr
                    # мультиплексируются одним каналом, и невычитанный stderr
                    # забил бы окно и заблокировал команду (тот же deadlock,
                    # ради которого раньше поднимали два потока).
                    if chan.recv_ready():
                        out_chunks.append(chan.recv(_READ_CHUNK))
                    if chan.recv_stderr_ready():
                        err_chunks.append(chan.recv_stderr(_READ_CHUNK))
                    # Выход готов, но данные могли прийти пакетом позже
                    # exit-status — ждём, пока оба буфера опустеют.
                    finished = (chan.exit_status_ready()
                                and not chan.recv_ready()
                                and not chan.recv_stderr_ready())
                except Exception:
                    # Канал умер посреди команды (обрыв TCP, смерть transport):
                    # останавливаемся, забранное сохраняем, exit status
                    # получаем ниже (там же, где и раньше, — -1 при отказе).
                    break
                if finished:
                    break
                if time.monotonic() >= deadline:
                    expired = True
                    break
                time.sleep(_POLL_INTERVAL)
        finally:
            # Канал обязан быть снят и на пути исключения: иначе cancel()
            # позже дёрнет close() на канале от уже завершённой команды.
            self._current_channel = None

        if expired:
            # Потолок истёк — канал закрываем, чтобы зависшая команда не
            # осталась жить на сервере с нашей стороны соединения.
            try:
                chan.close()
            except Exception:
                pass
            # Догружаем остаток, пришедший между последней проверкой и
            # закрытием: частичный вывод честнее пустого (парсеры rc=124 всё
            # равно читают по коду, но текст помогает оператору).
            try:
                while chan.recv_ready():
                    out_chunks.append(chan.recv(_READ_CHUNK))
                while chan.recv_stderr_ready():
                    err_chunks.append(chan.recv_stderr(_READ_CHUNK))
            except Exception:
                pass
            exit_status = COMMAND_DEADLINE_RC
        else:
            try:
                exit_status = chan.recv_exit_status()
            except Exception:
                exit_status = -1

        out = b''.join(out_chunks).decode('utf-8', errors='ignore')
        err = b''.join(err_chunks).decode('utf-8', errors='ignore')
        if expired:
            # Различимость обязательна: «пусто и rc=0» означает «команда
            # отработала», висящий канал обязан выглядеть иначе — rc=124 как
            # у coreutils `timeout` плюс явная причина в stderr.
            if err and not err.endswith('\n'):
                err += '\n'
            err += 'deadline exceeded after %gs\n' % ceiling
        return out, err, exit_status

    def exec_command(self, command, timeout=None):
        """Обратная совместимость: возвращает (stdout, stderr).

        timeout — потолок на канале (см. _exec); по умолчанию
        DEFAULT_COMMAND_TIMEOUT.
        """
        out, err, _ = self._exec(command, timeout=timeout)
        return out, err

    def run(self, command, timeout=None):
        """Возвращает (stdout, stderr, exit_status).

        timeout — потолок на канале (см. _exec); долгим операциям (замер dd,
        скачивание) передавать явно, остальным хватит DEFAULT_COMMAND_TIMEOUT.
        """
        return self._exec(command, timeout=timeout)

    def cleanup(self, command, timeout=None):
        """Служебная команда (chmod/rm над секретами): проходит после cancel().

        «Оператор нажал Стоп» означает «прекрати работу», а не «оставь файл с
        паролем на диске». Исключение (обрванное соединение) не глотаем:
        вызывающий обязан сообщить, что секрет мог остаться. Потолок канала
        действует и здесь (cancel уборку не отменяет, а зависший сокет не имеет
        права вешать поток уборки): убранное сообщит rc=0, неубранное — rc=124
        или -1, и вызывающий честно скажет, что секрет мог пережить операцию.
        """
        return self._exec(command, ignore_cancel=True, timeout=timeout)

    def close(self):
        if self.client:
            try:
                self.client.close()
            except Exception:
                pass
            self.client = None
