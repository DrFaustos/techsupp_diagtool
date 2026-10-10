"""Тесты gui_profiles.py: профили серверов и история подключений (без Tk).

Вся файловая логика (json-чтение/запись, права 0600, дедупликация и лимит
истории, выбор записи) не требует дисплея: путь к файлу подменяется на
tmp_path, Tk-переменные — лёгкими заглушками, а messagebox/simpledialog —
записывающими двойниками. Проверяем в т.ч. то, что профили и история
пишутся с правами владельца (SECURITY: пароли/ключи не должны читаться
посторонними).
"""
import json
import os
import stat
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

import gui_profiles as gp
from gui_profiles import ProfilesMixin


class _Var:
    """Замена tkinter.StringVar (get/set)."""

    def __init__(self, value=''):
        self._v = value

    def get(self):
        return self._v

    def set(self, value):
        self._v = value


class _Combo:
    """Замена ttk.Combobox: у ProfilesMixin берётся только .get()."""

    def __init__(self, value=''):
        self._v = value

    def get(self):
        return self._v

    def set(self, value):
        self._v = value


class _Dialogs:
    """Двойник messagebox + simpledialog: возвращает заготовки, пишет ошибки."""

    def __init__(self):
        self.askstring_ret: "str | None" = None
        self.askyesno_ret = True
        self.errors = []

    def askstring(self, *a, **k):
        return self.askstring_ret

    def askyesno(self, *a, **k):
        return self.askyesno_ret

    def showerror(self, *a, **k):
        self.errors.append(a)


class _Host(ProfilesMixin):
    def __init__(self, profiles_path, history_path):
        self.root = None
        self._path = str(profiles_path)
        self.conn_history_file = str(history_path)
        self.conn_history = []
        self.ip_var = _Var()
        self.port_var = _Var('22')
        self.user_var = _Var('root')
        self.key_var = _Var('~/.ssh/id_rsa')
        self.panel_var = _Var('auto')
        self.profile_var = _Var()
        self.profile_combo = {}
        self.history_combo = _Combo()
        self.logs = []

    def _profiles_file(self):
        return self._path

    def log(self, text):
        self.logs.append(text)


def _mode(path):
    return stat.S_IMODE(os.stat(path).st_mode)


# ==================== загрузка профилей ====================
class TestLoadProfiles:
    def test_missing_file_returns_empty(self, tmp_path):
        h = _Host(tmp_path / 'p.json', tmp_path / 'h.json')
        assert h._load_profiles() == {}

    def test_valid_file_parsed(self, tmp_path):
        p = tmp_path / 'p.json'
        p.write_text(json.dumps({'prod': {'ip': '1.2.3.4'}}), encoding='utf-8')
        h = _Host(p, tmp_path / 'h.json')
        assert h._load_profiles() == {'prod': {'ip': '1.2.3.4'}}

    def test_corrupt_file_degrades_to_empty(self, tmp_path):
        p = tmp_path / 'p.json'
        p.write_text('{ это не json', encoding='utf-8')
        h = _Host(p, tmp_path / 'h.json')
        assert h._load_profiles() == {}


# ==================== сохранение профилей: права 0600 ====================
class TestSaveProfiles:
    def test_written_with_owner_only_perms(self, tmp_path):
        p = tmp_path / 'p.json'
        h = _Host(p, tmp_path / 'h.json')
        h._save_profiles({'prod': {'ip': '1.2.3.4'}})
        assert json.loads(p.read_text(encoding='utf-8')) == {'prod': {'ip': '1.2.3.4'}}
        assert _mode(p) == 0o600

    def test_failure_reported_via_messagebox(self, tmp_path, monkeypatch):
        dlg = _Dialogs()
        monkeypatch.setattr(gp, 'messagebox', dlg)
        # путь-каталог вместо файла -> open('w') бросит, обработчик покажет ошибку
        h = _Host(tmp_path, tmp_path / 'h.json')
        h._save_profiles({'x': 1})
        assert dlg.errors and 'Не удалось сохранить профили' in dlg.errors[0][1]


# ==================== save_profile ====================
class TestSaveProfile:
    def test_empty_ip_blocks_with_error(self, tmp_path, monkeypatch):
        dlg = _Dialogs()
        monkeypatch.setattr(gp, 'messagebox', dlg)
        monkeypatch.setattr(gp, 'simpledialog', dlg)
        h = _Host(tmp_path / 'p.json', tmp_path / 'h.json')
        h.save_profile()                       # ip_var пуст
        assert dlg.errors
        assert not os.path.exists(h._profiles_file())

    def test_cancelled_name_stops(self, tmp_path, monkeypatch):
        dlg = _Dialogs()
        dlg.askstring_ret = None               # пользователь отменил ввод имени
        monkeypatch.setattr(gp, 'messagebox', dlg)
        monkeypatch.setattr(gp, 'simpledialog', dlg)
        h = _Host(tmp_path / 'p.json', tmp_path / 'h.json')
        h.ip_var.set('203.0.113.7')
        h.save_profile()
        assert not os.path.exists(h._profiles_file())

    def test_saves_all_fields(self, tmp_path, monkeypatch):
        dlg = _Dialogs()
        dlg.askstring_ret = '  Прод  '         # имя с пробелами -> strip
        monkeypatch.setattr(gp, 'messagebox', dlg)
        monkeypatch.setattr(gp, 'simpledialog', dlg)
        h = _Host(tmp_path / 'p.json', tmp_path / 'h.json')
        h.ip_var.set('203.0.113.7')
        h.port_var.set('2222')
        h.user_var.set('admin')
        h.key_var.set('~/.ssh/id_ed25519')
        h.panel_var.set('fastpanel')
        h.save_profile()

        data = h._load_profiles()
        assert data['Прод'] == {
            'ip': '203.0.113.7', 'port': '2222', 'user': 'admin',
            'key': '~/.ssh/id_ed25519', 'panel': 'fastpanel',
        }
        assert h.profile_combo['values'] == ['Прод']   # комбобокс обновлён
        assert any('сохранён' in line for line in h.logs)


# ==================== load_profile ====================
class TestLoadProfile:
    def test_no_name_is_noop(self, tmp_path):
        h = _Host(tmp_path / 'p.json', tmp_path / 'h.json')
        h.load_profile()
        assert h.ip_var.get() == ''

    def test_unknown_profile_is_noop(self, tmp_path):
        h = _Host(tmp_path / 'p.json', tmp_path / 'h.json')
        h.profile_var.set('нет-такого')
        h.load_profile()
        assert h.ip_var.get() == ''

    def test_populates_all_vars(self, tmp_path):
        p = tmp_path / 'p.json'
        p.write_text(json.dumps({'prod': {
            'ip': '1.1.1.1', 'port': '2200', 'user': 'ops',
            'key': '/k', 'panel': 'ispmanager'}}), encoding='utf-8')
        h = _Host(p, tmp_path / 'h.json')
        h.profile_var.set('prod')
        h.load_profile()
        assert (h.ip_var.get(), h.port_var.get(), h.user_var.get(),
                h.key_var.get(), h.panel_var.get()) == \
               ('1.1.1.1', '2200', 'ops', '/k', 'ispmanager')

    def test_missing_keys_use_defaults(self, tmp_path):
        p = tmp_path / 'p.json'
        p.write_text(json.dumps({'prod': {'ip': '9.9.9.9'}}), encoding='utf-8')
        h = _Host(p, tmp_path / 'h.json')
        h.profile_var.set('prod')
        h.load_profile()
        assert h.ip_var.get() == '9.9.9.9'
        assert h.port_var.get() == '22'          # default
        assert h.user_var.get() == 'root'        # default


# ==================== delete_profile ====================
class TestDeleteProfile:
    def test_declined_keeps_profile(self, tmp_path, monkeypatch):
        dlg = _Dialogs()
        dlg.askyesno_ret = False
        monkeypatch.setattr(gp, 'messagebox', dlg)
        p = tmp_path / 'p.json'
        p.write_text(json.dumps({'prod': {'ip': '1.1.1.1'}}), encoding='utf-8')
        h = _Host(p, tmp_path / 'h.json')
        h.profile_var.set('prod')
        h.delete_profile()
        assert 'prod' in h._load_profiles()

    def test_confirmed_removes_and_refreshes(self, tmp_path, monkeypatch):
        dlg = _Dialogs()
        monkeypatch.setattr(gp, 'messagebox', dlg)
        p = tmp_path / 'p.json'
        p.write_text(json.dumps({'prod': {'ip': '1.1.1.1'},
                                 'test': {'ip': '2.2.2.2'}}), encoding='utf-8')
        h = _Host(p, tmp_path / 'h.json')
        h.profile_var.set('prod')
        h.delete_profile()
        assert h._load_profiles() == {'test': {'ip': '2.2.2.2'}}
        assert h.profile_combo['values'] == ['test']


# ==================== история подключений ====================
class TestConnHistory:
    def test_missing_file_empty(self, tmp_path):
        h = _Host(tmp_path / 'p.json', tmp_path / 'h.json')
        assert h._load_conn_history() == []

    def test_entry_added_to_front(self, tmp_path):
        h = _Host(tmp_path / 'p.json', tmp_path / 'h.json')
        h._save_conn_history('1.1.1.1', 22, 'root')
        assert h.conn_history == [{'ip': '1.1.1.1', 'port': '22', 'user': 'root'}]
        assert _mode(h.conn_history_file) == 0o600

    def test_duplicate_moves_to_front_not_repeated(self, tmp_path):
        h = _Host(tmp_path / 'p.json', tmp_path / 'h.json')
        h._save_conn_history('1.1.1.1', '22', 'root')
        h._save_conn_history('2.2.2.2', '22', 'root')
        h._save_conn_history('1.1.1.1', '22', 'root')     # повтор -> в начало
        ips = [e['ip'] for e in h.conn_history]
        assert ips == ['1.1.1.1', '2.2.2.2']
        assert len(h.conn_history) == 2

    def test_capped_at_ten(self, tmp_path):
        h = _Host(tmp_path / 'p.json', tmp_path / 'h.json')
        for i in range(15):
            h._save_conn_history(f'10.0.0.{i}', '22', 'root')
        assert len(h.conn_history) == 10
        assert h.conn_history[0]['ip'] == '10.0.0.14'   # самый свежий сверху

    def test_port_stored_as_string(self, tmp_path):
        h = _Host(tmp_path / 'p.json', tmp_path / 'h.json')
        h._save_conn_history('1.1.1.1', 2222, 'root')
        assert h.conn_history[0]['port'] == '2222'

    def test_load_reloads_from_disk(self, tmp_path):
        hp = tmp_path / 'h.json'
        h = _Host(tmp_path / 'p.json', hp)
        h._save_conn_history('1.1.1.1', '22', 'root')
        # новый хост читает то же содержимое с диска
        h2 = _Host(tmp_path / 'p.json', hp)
        assert h2._load_conn_history() == [{'ip': '1.1.1.1', 'port': '22', 'user': 'root'}]


# ==================== выбор записи из истории ====================
class TestHistorySelect:
    def _host(self, tmp_path):
        h = _Host(tmp_path / 'p.json', tmp_path / 'h.json')
        h.conn_history = [{'ip': '5.6.7.8', 'port': '2200', 'user': 'ops'}]
        return h

    def test_matching_string_fills_vars(self, tmp_path):
        h = self._host(tmp_path)
        h.history_combo._v = '5.6.7.8:2200 (ops)'
        h._on_history_select(None)
        assert (h.ip_var.get(), h.port_var.get(), h.user_var.get()) == \
               ('5.6.7.8', '2200', 'ops')

    def test_no_match_leaves_vars(self, tmp_path):
        h = self._host(tmp_path)
        h.ip_var.set('keep-me')
        h.history_combo._v = 'неизвестная запись'
        h._on_history_select(None)
        assert h.ip_var.get() == 'keep-me'


# ==================== отказоустойчивость: ветки, что были непокрыты =========
#
# Три оставшиеся ветки — это не «счастье», а поломка на живом сервере: пустое
# имя профиля при удалении, битый JSON истории, сбой записи истории (диск/право).
# Каждая обязана отработать молча, а не уронить приложение: история подключений
# не критична, в отличие от профилей (там _save_profiles показывает messagebox —
# см. TestSaveProfiles), поэтому здесь обработчик просто глотает исключение.


class TestDeleteProfileGuard:
    def test_empty_name_is_noop(self, tmp_path, monkeypatch):
        # profile_var пуст — подтверждение не открывается, файл не трогается
        dlg = _Dialogs()
        monkeypatch.setattr(gp, 'messagebox', dlg)
        p = tmp_path / 'p.json'
        p.write_text(json.dumps({'prod': {'ip': '1.1.1.1'}}), encoding='utf-8')
        h = _Host(p, tmp_path / 'h.json')
        h.delete_profile()                    # profile_var == ''
        assert dlg.askyesno_ret is True       # но спросить не должны были
        assert 'prod' in h._load_profiles()   # файл не изменён


class TestConnHistoryResilience:
    def test_corrupt_history_file_degrades_to_empty(self, tmp_path):
        # битый JSON на диске не должен ронять загрузку — пустой список
        hp = tmp_path / 'h.json'
        hp.write_text('[ { это не json', encoding='utf-8')
        h = _Host(tmp_path / 'p.json', hp)
        assert h._load_conn_history() == []

    def test_truncated_history_file_degrades_to_empty(self, tmp_path):
        # оборванная запись (например, упала на середине json.dump) — то же
        hp = tmp_path / 'h.json'
        hp.write_text('[{"ip": "1.1.1.1"', encoding='utf-8')
        h = _Host(tmp_path / 'p.json', hp)
        assert h._load_conn_history() == []

    def test_write_failure_is_swallowed_but_memory_updated(self, tmp_path):
        # conn_history_file указывает на каталог -> open('w') бросит;
        # наружу бросок идти не должен, но in-memory история уже обновлена —
        # так прод ведёт себя сейчас, и тест это закрепляет
        h = _Host(tmp_path / 'p.json', tmp_path)   # путь = каталог
        h._save_conn_history('1.1.1.1', '22', 'root')   # не должно бросить
        assert h.conn_history == [{'ip': '1.1.1.1', 'port': '22', 'user': 'root'}]

    def test_chmod_failure_is_swallowed(self, tmp_path, monkeypatch):
        # запись прошла, но os.chmod упал (файл на read-only-фс) — не роняем;
        # данные на диске при этом корректны
        hp = tmp_path / 'h.json'
        h = _Host(tmp_path / 'p.json', hp)

        def boom(path, mode):
            raise OSError('read-only file system')

        monkeypatch.setattr(gp.os, 'chmod', boom)
        h._save_conn_history('1.1.1.1', '22', 'root')
        # json уже легло до chmod — файл читается
        assert json.loads(hp.read_text(encoding='utf-8')) == \
            [{'ip': '1.1.1.1', 'port': '22', 'user': 'root'}]
