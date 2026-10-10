"""Тесты gui_runner.py: подключение, фоновые задачи, отмена, команды, дисконнект (без Tk).

Класс-хост собирает те же атрибуты, что создаёт gui.DiagnosticApp, но вместо
виджетов — записи о config(). Модуль threading подменён синхронным
исполнителем: Thread().start() выполняет target на месте, а root.after
складывает колбэки в очередь — тест сливает её сам. Гонки нет, порядок
детерминирован. messagebox / ServerChecker / detect_panel подменяются на
уровне модуля gui_runner (monkeypatch.setattr), как в остальных GUI-тестах.
"""
import os
import sys
import threading
import time
import tkinter as tk

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

import gui_runner as gr
from gui_runner import RunnerMixin
from support import FakeSSH


class _Var:
    """Замена tkinter.StringVar."""

    def __init__(self, value=''):
        self._v = value

    def get(self):
        return self._v

    def set(self, value):
        self._v = value


class _W:
    """Замена виджета: пишет config(), помнит focus_set и combo['values']=..."""

    def __init__(self):
        self.configs = []
        self.focus = 0
        self.items = {}

    def config(self, **kw):
        self.configs.append(kw)

    def focus_set(self):
        self.focus += 1

    def __setitem__(self, key, value):
        self.items[key] = value

    def last(self, key):
        for cfg in reversed(self.configs):
            if key in cfg:
                return cfg[key]
        return None


class _Entry(_W):
    """Поле команды: get()/delete(0, END)."""

    def __init__(self, value=''):
        super().__init__()
        self._v = value

    def get(self):
        return self._v

    def delete(self, first, last):
        self._v = ''


class _Root:
    """root.after не исполняет, а копит; flush() прогоняет накопленное.

    broken=True имитирует закрытое окно: after() бросает RuntimeError,
    как настоящий Tcl после destroy().
    """

    def __init__(self):
        self.pending = []
        self.broken = False

    def after(self, ms, fn, *args):
        if self.broken:
            raise RuntimeError('root window has been destroyed')
        self.pending.append((fn, args))

    def flush(self):
        while self.pending:
            fn, args = self.pending.pop(0)
            fn(*args)


class _Progress:
    def __init__(self):
        self.events = []

    def pack(self, **kw):
        self.events.append('pack')

    def start(self, *a):
        self.events.append('start')

    def stop(self):
        self.events.append('stop')

    def pack_forget(self):
        self.events.append('forget')


class _SyncThreading:
    """Замена модуля threading для gui_runner: start() исполняет target сразу.

    Тесту не нужен настоящий поток — нужна детерминированная последовательность
    «задача отработала -> колбэки в очереди -> flush».
    """

    def __init__(self):
        self.started = 0

    def Thread(self, target=None, daemon=None):
        outer = self

        class _T:
            def start(self):
                outer.started += 1
                if target is not None:
                    target()

        return _T()


class _Box:
    """messagebox: пишет (kind, title, msg) вместо реальных диалогов."""

    def __init__(self):
        self.calls = []

    def showerror(self, title, msg):
        self.calls.append(('error', title, msg))

    def showwarning(self, title, msg):
        self.calls.append(('warning', title, msg))

    def showinfo(self, title, msg):
        self.calls.append(('info', title, msg))

    def kinds(self, kind):
        return [c for c in self.calls if c[0] == kind]


class _Checker(FakeSSH):
    """FakeSSH плюс методы жизненного цикла ServerChecker."""

    def __init__(self, connected=True, message='ok', routes=None):
        super().__init__(routes=routes)
        self.connected_result = (connected, message)
        self.closed = 0
        self.cancels = 0
        self.resets = 0

    def connect(self):
        return self.connected_result

    def close(self):
        self.closed += 1

    def cancel(self):
        self.cancels += 1

    def reset_cancel(self):
        self.resets += 1


class _BrokenLifecycle(_Checker):
    """reset_cancel/cancel бросают (канал уже умер) — GUI обязан проглотить."""

    def reset_cancel(self):
        raise RuntimeError('канал закрыт')

    def cancel(self):
        raise RuntimeError('канал закрыт')


BUTTONS = ('full_btn', 'disk_btn', 'network_btn', 'firewall_btn', 'config_btn',
           'logs_btn', 'access_btn', 'oom_btn', 'ssl_btn', 'whois_btn',
           'ports_btn', 'grep_btn', 'dns_btn', 'resolv_btn', 'edit_dns_btn',
           'ipv4_btn', 'ipv6_btn', 'restart_btn', 'config_editor_btn',
           'file_btn', 'swap_btn', 'fstab_btn', 'send_btn', 'cancel_btn')


class Host(RunnerMixin):
    """Минимальный «gui.DiagnosticApp»: ровно то, что трогает RunnerMixin."""

    def __init__(self):
        self.ip_var = _Var('10.0.0.1')
        self.port_var = _Var('22')
        self.user_var = _Var('root')
        self.password_var = _Var('hunter2')
        self.key_var = _Var('')
        self.panel_var = _Var('auto')
        self.checker = None
        self.panel_type = None
        self._busy = False
        self._busy_lock = threading.Lock()
        self.root = _Root()
        self.progress = _Progress()
        self.logs = []
        for name in BUTTONS:
            setattr(self, name, _W())
        self.connect_btn = _W()
        self.cmd_entry = _Entry('')
        self.cmd_history = []
        self.history_index = 0
        self._diag_cache = {}
        self.conn_history = []
        self.history_combo = _W()
        self.saved = []
        self.panel_menus = []
        self.bitrix_shows = []
        self.bitrix_detects = 0

    def log(self, msg):
        self.logs.append(msg)

    def _save_conn_history(self, ip, port, user):
        self.saved.append((ip, port, user))

    def _set_panel_menus_visible(self, panel):
        self.panel_menus.append(panel)

    def _set_bitrix_menu_visible(self, show):
        self.bitrix_shows.append(show)

    def _detect_bitrix(self):
        self.bitrix_detects += 1

    def text(self):
        return '\n'.join(self.logs)


class Env:
    """Хост + подмены на уровне модуля gui_runner."""

    def __init__(self, monkeypatch, host):
        self.host = host
        self.box = _Box()
        self.threads = _SyncThreading()
        self.made = []
        self.detect_calls = []
        self.checker = _Checker()
        monkeypatch.setattr(gr, 'messagebox', self.box)
        monkeypatch.setattr(gr, 'threading', self.threads)
        monkeypatch.setattr(
            gr, 'detect_panel',
            lambda ck: self.detect_calls.append(ck) or 'ispmanager')
        monkeypatch.setattr(
            gr, 'ServerChecker',
            lambda ip, port, user, password, key: self.made.append(
                dict(ip=ip, port=port, user=user, password=password, key=key)
            ) or self.checker)


@pytest.fixture()
def host():
    return Host()


@pytest.fixture()
def env(monkeypatch, host):
    return Env(monkeypatch, host)


@pytest.fixture()
def connected(env):
    """Хост с «установленным» соединением (без реального connect())."""
    env.host.checker = env.checker
    return env


class TestConnect:
    def test_empty_ip_rejected(self, env):
        env.host.ip_var.set('   ')
        env.host.connect()
        assert env.box.kinds('error')
        assert env.threads.started == 0

    @pytest.mark.parametrize('raw,expected', [('2222', 2222), ('abc', 22), ('', 22)])
    def test_port_parsed_with_fallback(self, env, raw, expected):
        env.host.port_var.set(raw)
        env.host.connect()
        assert env.made[0]['port'] == expected

    def test_busy_refuses_second_connect(self, env):
        env.host._busy = True
        env.host.connect()
        assert env.box.kinds('warning')
        assert env.threads.started == 0

    def test_existing_checker_refuses(self, env):
        env.host.checker = env.checker
        env.host.connect()
        assert env.box.kinds('info')
        assert env.threads.started == 0

    def test_credentials_passed_and_button_locked(self, env):
        env.host.key_var.set('/root/.ssh/id')
        env.host.connect()
        assert env.made[0] == dict(ip='10.0.0.1', port=22, user='root',
                                   password='hunter2', key='/root/.ssh/id')
        # Пока идёт подключение, кнопка заблокирована — защита от двойного клика.
        assert env.host.connect_btn.last('state') == tk.DISABLED

    def test_success_auto_panel(self, env):
        env.host.conn_history = [{'ip': '1.1.1.1', 'port': '22', 'user': 'root'}]
        env.host.connect()
        env.host.root.flush()
        h = env.host
        assert h.checker is env.checker
        assert h.panel_type == 'ispmanager'
        assert env.detect_calls == [env.checker]
        assert h.password_var.get() == ''      # пароль стёрт из формы
        assert h._busy is False
        assert h.full_btn.last('state') == tk.NORMAL
        assert h.send_btn.last('state') == tk.NORMAL
        assert h.connect_btn.last('text') == 'Отключиться'
        assert h.connect_btn.last('command') == h.disconnect
        assert h.panel_menus == ['ispmanager']
        assert h.bitrix_detects == 1           # BitrixVM ищется на каждом подключении
        assert h.cmd_entry.focus == 1
        assert h.saved == [('10.0.0.1', '22', 'root')]
        assert h.history_combo.items['values'] == ['1.1.1.1:22 (root)']

    def test_manual_panel_skips_detection(self, env):
        env.host.panel_var.set('fastpanel')
        env.host.connect()
        env.host.root.flush()
        assert env.host.panel_type == 'fastpanel'
        assert env.detect_calls == []

    def test_failure_logs_and_unlocks(self, env):
        env.checker = _Checker(connected=False, message='нет доступа')
        env.host.connect()
        env.host.root.flush()
        h = env.host
        assert '❌ нет доступа' in h.text()
        assert h.checker is None
        assert h._busy is False
        assert h.connect_btn.last('state') == tk.NORMAL


class TestRunInThread:
    def test_cache_fresh_shows_without_thread(self, connected):
        h = connected.host
        h._diag_cache['k'] = (time.time(), 'данные из кеша')
        ran = []
        h._run_in_thread(lambda: ran.append(1), cache_key='k')
        h.root.flush()
        assert not ran
        assert connected.threads.started == 0
        assert 'данные из кеша' in h.text()
        assert 'Показан результат из кеша' in h.text()
        assert h._busy is False

    def test_cache_expired_reruns(self, connected):
        h = connected.host
        h._diag_cache['k'] = (time.time() - 61, 'устарело')
        h._run_in_thread(lambda: 'свежее', cache_key='k')
        h.root.flush()
        assert 'устарело' not in h.text()
        assert 'свежее' in h.text()
        assert h._diag_cache['k'][1] == 'свежее'

    def test_busy_warning(self, connected):
        h = connected.host
        h._busy = True
        h._run_in_thread(lambda: 'x')
        assert connected.box.kinds('warning')
        assert connected.threads.started == 0

    def test_disconnected_returns_silently(self, connected):
        h = connected.host
        h.checker = None
        h._run_in_thread(lambda: 'x')
        assert not connected.box.calls
        assert connected.threads.started == 0
        assert h._busy is False                # флаг не должен «залипать»

    def test_result_progress_and_cache(self, connected):
        h = connected.host
        btn = _W()
        h._run_in_thread(lambda x: f'готово {x}', btn, 'дела', cache_key='k')
        # До flush: кнопка занята, прогресс крутится, отмена доступна.
        assert btn.last('state') == tk.DISABLED
        assert h.cancel_btn.last('state') == tk.NORMAL
        h.root.flush()
        assert 'готово дела' in h.text()       # args дошли до target
        assert h.progress.events == ['pack', 'start', 'stop', 'forget']
        assert btn.last('state') == tk.NORMAL
        assert h.cancel_btn.last('state') == tk.DISABLED
        assert h._diag_cache['k'][1] == 'готово дела'
        assert h.checker.resets == 1           # прошлая отмена сброшена
        assert h._busy is False

    def test_target_exception_shown(self, connected):
        h = connected.host

        def boom():
            raise ValueError('сбой сети')

        h._run_in_thread(boom)
        h.root.flush()
        assert '❌ Ошибка: сбой сети' in h.text()
        assert h.progress.events[-2:] == ['stop', 'forget']
        assert h._busy is False

    def test_destroyed_root_still_releases_busy(self, connected):
        """Регресс: после закрытия окна флаг занятости обязан сброситься.

        Раньше исключение из root.after() улетало прямо из finally и строки
        после него не выполнялись — приложение навсегда считало себя занятым.
        """
        h = connected.host
        h.root.broken = True
        h._run_in_thread(lambda: 'r')
        assert connected.threads.started == 1
        assert h._busy is False

    def test_checker_without_reset_cancel_tolerated(self, connected):
        h = connected.host
        h.checker = FakeSSH()                  # у старой заглушки нет reset_cancel
        h._run_in_thread(lambda: 'ok')
        h.root.flush()
        assert 'ok' in h.text()
        assert h._busy is False


class TestRunSimple:
    def test_on_done_receives_result(self, connected):
        h = connected.host
        done = []
        h._run_simple(lambda: 'сделано', on_done=lambda r: done.append(r))
        h.root.flush()
        assert done == ['сделано']
        assert h.progress.events == ['pack', 'start', 'stop', 'forget']
        assert h.checker.resets == 1
        assert h._busy is False

    def test_display_by_default(self, connected):
        h = connected.host
        h._run_simple(lambda: 'просто вывод')
        h.root.flush()
        assert 'просто вывод' in h.text()

    def test_button_restored_after_done(self, connected):
        h = connected.host
        btn = _W()
        h._run_simple(lambda: 'ok', btn)
        assert btn.last('state') == tk.DISABLED   # на время задачи
        h.root.flush()
        assert btn.last('state') == tk.NORMAL

    def test_busy_warning(self, connected):
        h = connected.host
        h._busy = True
        h._run_simple(lambda: 'x')
        assert connected.box.kinds('warning')
        assert connected.threads.started == 0

    def test_disconnected_returns_silently(self, connected):
        h = connected.host
        h.checker = None
        h._run_simple(lambda: 'x')
        assert connected.threads.started == 0
        assert h._busy is False

    def test_exception_shown(self, connected):
        h = connected.host

        def boom():
            raise RuntimeError('сдохла сессия')

        h._run_simple(boom)
        h.root.flush()
        assert '❌ Ошибка: сдохла сессия' in h.text()
        assert h._busy is False

    def test_reset_cancel_failure_does_not_block_task(self, connected):
        """Сброс прошлой отмены на мёртвом канале не должен срывать задачу."""
        h = connected.host
        h.checker = _BrokenLifecycle()
        h._run_simple(lambda: 'ok')
        h.root.flush()
        assert 'ok' in h.text()
        assert h._busy is False


class TestPostUi:
    def test_callback_queued_and_run(self, host):
        calls = []
        host._post_ui(lambda v: calls.append(v), 'а')
        assert calls == []                     # пока нет flush — нет и вызова
        host.root.flush()
        assert calls == ['а']

    def test_destroyed_root_swallowed(self, host):
        host.root.broken = True
        host._post_ui(lambda: None)            # не должно бросить


class TestCancelTask:
    def test_cancel_forwarded_to_checker(self, connected):
        connected.host.cancel_task()
        assert connected.host.checker.cancels == 1
        assert '⏹' in connected.host.text()

    def test_no_checker_only_log(self, host):
        host.cancel_task()
        assert '⏹' in host.text()

    def test_cancel_failure_is_swallowed(self, connected):
        """cancel() на мёртвом канале не должен кидать в mainloop."""
        connected.host.checker = _BrokenLifecycle()
        connected.host.cancel_task()
        assert '⏹' in connected.host.text()


class TestSendCommand:
    def test_requires_checker(self, host):
        host.cmd_entry = _Entry('ls')
        host.send_command()
        assert host.cmd_history == []

    def test_blank_ignored(self, connected):
        connected.host.cmd_entry = _Entry('    ')
        connected.host.send_command()
        assert connected.host.cmd_history == []
        assert connected.threads.started == 0

    def test_exit_disconnects_without_running(self, connected):
        h = connected.host
        closed = []
        h.disconnect = lambda: closed.append(True)
        h.cmd_entry = _Entry('exit')
        h.send_command()
        assert closed == [True]
        assert h.checker.commands == []        # команду не гоняли по SSH

    def test_stdout_and_history(self, connected):
        h = connected.host
        h.checker = _Checker(routes=[('uname', 'Linux x86_64')])
        h.cmd_entry = _Entry('uname -a')
        h.send_command()
        h.root.flush()
        assert '$ uname -a' in h.text()
        assert 'Linux x86_64' in h.text()
        assert h.cmd_history == ['uname -a']
        assert h.history_index == 1
        assert h.cmd_entry.get() == ''         # поле очищено после отправки

    def test_stderr_on_failed_rc(self, connected):
        h = connected.host
        h.checker = _Checker(routes=[('fail', ('', 'нет такого файла', 2))])
        h.cmd_entry = _Entry('fail')
        h.send_command()
        h.root.flush()
        assert 'STDERR: нет такого файла' in h.text()

    def test_empty_output_placeholder(self, connected):
        h = connected.host
        h.checker = _Checker()
        h.cmd_entry = _Entry('true')
        h.send_command()
        h.root.flush()
        assert '(нет вывода)' in h.text()


class TestDisconnect:
    def test_busy_blocks_disconnect(self, connected):
        h = connected.host
        h._busy = True
        h.disconnect()
        assert connected.box.kinds('warning')
        assert h.checker is connected.checker  # соединение не закрыто
        assert connected.checker.closed == 0

    def test_full_close_resets_state(self, connected):
        h = connected.host
        h.panel_type = 'ispmanager'
        h.disconnect()
        assert h.checker is None
        assert h.panel_type is None
        assert connected.checker.closed == 1
        assert h.panel_menus == [None]
        assert h.bitrix_shows == [False]
        assert h.full_btn.last('state') == tk.DISABLED
        assert h.send_btn.last('state') == tk.DISABLED
        assert h.cancel_btn.last('state') == tk.DISABLED
        assert h.connect_btn.last('text') == 'Подключиться'
        assert h.connect_btn.last('command') == h.connect
        assert 'Соединение закрыто.' in h.text()

    def test_disconnect_without_checker_is_safe(self, host):
        host.disconnect()
        assert 'Соединение закрыто.' in host.text()
