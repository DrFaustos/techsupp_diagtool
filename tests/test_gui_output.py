"""Тесты gui_output.py: маскирование секретов, история команд, автодополнение.

SECURITY.md требует не ослаблять маскирование секретов в выводе/отчётах,
поэтому _mask_secrets (чистый статический метод) и путь log() -> logger
покрываются в первую очередь и без Tk-дисплея. Навигация по истории и
автодополнение работают с self.cmd_entry, который подменён лёгкой заглушкой.
"""
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from gui_output import OutputMixin


# ==================== заглушки для log()/истории ====================
class _Entry:
    """Минимальная замена tkinter-поля ввода (get/delete/insert/focus_set)."""

    def __init__(self, value=''):
        self._v = value

    def get(self):
        return self._v

    def delete(self, start, end):
        self._v = ''

    def insert(self, index, text):
        self._v = text

    def focus_set(self):
        pass


class _Output:
    def __init__(self):
        self.lines = []

    def insert(self, index, text):
        self.lines.append(text)

    def see(self, index):
        pass


class _Logger:
    def __init__(self):
        self.records = []

    def info(self, msg):
        self.records.append(msg)


class _Host(OutputMixin):
    def __init__(self, history=None):
        self.output = _Output()
        self._logger = _Logger()
        self.cmd_entry = _Entry()
        self.cmd_history = list(history or [])
        self.history_index = len(self.cmd_history)


# ==================== маскирование секретов ====================
class TestMaskSecrets:
    # staticmethod обязателен: записанный атрибутом класса статический метод
    # вызывается как self.MASK(x) с передачей self (получается лишний аргумент).
    MASK = staticmethod(OutputMixin._mask_secrets)

    def test_password_equals_masked(self):
        assert self.MASK('password=hunter2') == 'password=***'

    def test_password_colon_with_spaces(self):
        assert self.MASK('password : hunter2') == 'password : ***'

    def test_passwd_and_pass_variants(self):
        assert self.MASK('passwd=abc123') == 'passwd=***'
        assert self.MASK('pass=abc123') == 'pass=***'

    def test_case_insensitive_prefix_kept(self):
        # ключ сохраняется как есть, значение заменяется
        assert self.MASK('PASSWORD=hunter2') == 'PASSWORD=***'

    def test_token_key_secret(self):
        assert self.MASK('token=xyz') == 'token=***'
        assert self.MASK('api_key=xyz') == 'api_key=***'
        assert self.MASK('API-KEY=xyz') == 'API-KEY=***'
        assert self.MASK('secret=xyz') == 'secret=***'

    def test_multiple_secrets_in_one_line(self):
        # значения — различимые токены: однобуквенные ('a') встречались бы внутри
        # самих ключей ('password'), и проверка 'a' not in out была бы ложной
        out = self.MASK('password=AAA1 token=BBB2 secret=CCC3')
        assert 'AAA1' not in out and 'BBB2' not in out and 'CCC3' not in out
        assert out == 'password=*** token=*** secret=***'

    def test_embedded_key_is_masked(self):
        # 'dbpassword=' содержит 'password=' -> маска обязана сработать
        assert self.MASK('dbpassword=topsecret') == 'dbpassword=***'

    def test_plain_command_untouched(self):
        cmd = 'systemctl restart nginx && tail -n 50 /var/log/nginx/error.log'
        assert self.MASK(cmd) == cmd

    def test_bare_key_without_value_untouched(self):
        # нет ':=' со значением -> менять нечего
        assert self.MASK('password') == 'password'

    def test_empty_and_none_passthrough(self):
        assert self.MASK('') == ''
        assert self.MASK(None) is None

    def test_secret_value_not_present_after_mask(self):
        out = self.MASK(' connecting with password=S3cr3t! to mysql')
        assert 'S3cr3t!' not in out
        assert 'password=***' in out


class TestLogMasksBeforeFileLog:
    """Регрессия SECURITY: в файл-лог секрет уходит уже замаскированным, а
    в оконный виджет (output) — как есть."""

    def test_logger_gets_masked_text(self):
        h = _Host()
        h.log('mysql -u root password=SuperSecret')
        assert h._logger.records == ['mysql -u root password=***']
        assert 'SuperSecret' not in h._logger.records[0]

    def test_output_widget_gets_raw_text(self):
        # в виджет текст уходит как есть (плюс перевод строки) и НЕ замаскированным
        h = _Host()
        h.log('password=topsecret')
        assert h.output.lines == ['password=topsecret\n']

    def test_dead_logger_does_not_break_log(self):
        class Boom(_Logger):
            def info(self, msg):
                raise RuntimeError('файл лога закрыт')

        h = _Host()
        h._logger = Boom()
        h.log('anything')          # не должно бросить наружу
        assert h.output.lines == ['anything\n']


# ==================== история команд (стрелки вверх/вниз) ====================
class TestHistoryNavigation:
    def test_up_no_history_is_break_no_change(self):
        h = _Host(history=[])
        assert h.history_up(None) == 'break'
        assert h.cmd_entry.get() == ''

    def test_up_walks_backwards(self):
        h = _Host(history=['a', 'b', 'c'])   # history_index == 3 (конец)
        h.history_up(None)
        assert h.cmd_entry.get() == 'c' and h.history_index == 2
        h.history_up(None)
        assert h.cmd_entry.get() == 'b' and h.history_index == 1
        h.history_up(None)
        assert h.cmd_entry.get() == 'a' and h.history_index == 0
        # на вершине ещё один вверх не уходит за границу
        h.history_up(None)
        assert h.cmd_entry.get() == 'a' and h.history_index == 0

    def test_down_walks_forward_then_clears(self):
        h = _Host(history=['a', 'b', 'c'])
        h.history_index = 0
        h.cmd_entry._v = 'a'
        h.history_down(None)
        assert h.cmd_entry.get() == 'b' and h.history_index == 1
        h.history_down(None)
        assert h.cmd_entry.get() == 'c' and h.history_index == 2
        h.history_down(None)          # выход за конец: поле очищается
        assert h.cmd_entry.get() == '' and h.history_index == 3


# ==================== автодополнение по Tab ====================
class TestAutocomplete:
    def test_empty_current_returns_none(self):
        h = _Host(history=['git status'])
        assert h.autocomplete(None) is None

    def test_completes_first_prefix_match(self):
        h = _Host(history=['git status', 'git log', 'ls'])
        h.cmd_entry._v = 'git '
        assert h.autocomplete(None) == 'break'
        assert h.cmd_entry.get() == 'git status'

    def test_no_match_leaves_entry_unchanged(self):
        h = _Host(history=['git status'])
        h.cmd_entry._v = 'zzz'
        assert h.autocomplete(None) == 'break'
        assert h.cmd_entry.get() == 'zzz'


# ==================== поиск, буфер, сохранение, шпаргалка ====================
#
# Это остальные методы миксина — те, что трогает пользователь, но которые не
# видно в coverage, пока не дёрнешь: find_in_output (цикл по Text.search),
# copy_output (clipboard), save_report (реальная запись файла), browse_key и
# шпаргалка. Дисплей не нужен: Text/search эмулируется честно (с движением
# стартового индекса — иначе неверный сдвиг start дал бы бесконечный цикл),
# root/filedialog/messagebox/simpledialog/tb подменяются на уровне модуля.
import gui_output as go


class _Text:
    """Эмуляция tk.Text ровно для find_in_output/copy_output/save_report.

    Индексы Tk переводятся в смещения одной строки ('L.C' -> C, плюс
    суффикс '+Nc'), поэтому search действительно продвигается: если код
    забудет сдвинуть start, тест уйдёт в бесконечный цикл, а не пройдёт.
    """

    def __init__(self, buf=''):
        self.buf = buf
        self.lines = []
        self.ops = []          # (op, tag, *args)
        self.ranges = []
        self.seen = []

    # --- общий интерфейс Text ---
    def insert(self, index, text):
        self.lines.append(text)

    def see(self, index):
        self.seen.append(index)

    def get(self, start, end):
        return self.buf

    def tag_remove(self, tag, start, end):
        self.ops.append(('remove', tag, start, end))

    def tag_config(self, tag, **kw):
        self.ops.append(('config', tag))

    def tag_add(self, tag, pos, end):
        self.ops.append(('add', tag, pos, end))
        self.ranges.append(pos)

    def tag_ranges(self, tag):
        return tuple(self.ranges)

    # --- поиск ---
    def _offset(self, index):
        index = str(index)
        if '+' in index:
            base, rest = index.split('+', 1)
            return self._offset(base) + int(rest.rstrip('c'))
        line, col = index.split('.')
        return int(col)

    def search(self, query, start, stopindex=None, nocase=False):
        from_start = self._offset(start)
        hay = self.buf.lower() if nocase else self.buf
        needle = query.lower() if nocase else query
        i = hay.find(needle, from_start)
        return '' if i < 0 else f'1.{i}'


class _Root:
    def __init__(self):
        self.clip = []
        self.events = []
        self.cleared = 0

    def clipboard_clear(self):
        self.cleared += 1
        self.clip = []

    def clipboard_append(self, text):
        self.clip.append(text)

    def update(self):
        self.events.append('update')


class _Var:
    def __init__(self, value=''):
        self._v = value

    def set(self, value):
        self._v = value

    def get(self):
        return self._v


class _Msg:
    def __init__(self):
        self.events = []

    def showerror(self, title, msg, parent=None):
        self.events.append(('error', title, msg))


class _Ask:
    """Двойник simpledialog: одно значение на askstring."""

    def __init__(self, answer=None):
        self.answer = answer
        self.asks = []

    def askstring(self, title, prompt, parent=None, initialvalue=None):
        self.asks.append(title)
        return self.answer


class _Files:
    def __init__(self, save_as='', open_name=''):
        self.save_as = save_as
        self.open_name = open_name
        self.save_asks = []
        self.open_asks = []

    def asksaveasfilename(self, **kw):
        self.save_asks.append(kw)
        return self.save_as

    def askopenfilename(self, **kw):
        self.open_asks.append(kw)
        return self.open_name


class _DialogWidget:
    kind = 'Toplevel'

    def __init__(self, **kw):
        self.kw = kw
        self.titles = []
        self.grabbed = 0
        self.transients = 0
        self.destroyed = 0
        self.packs = []

    def title(self, text=''):
        self.titles.append(text)

    def geometry(self, geo=''):
        pass

    def transient(self, win):
        self.transients += 1

    def grab_set(self):
        self.grabbed += 1

    def pack(self, **kw):
        self.packs.append(kw)

    def destroy(self):
        self.destroyed += 1


class _Widget:
    def __init__(self, kind, master=None, **kw):
        self.kind = kind
        self.master = master
        self.kw = kw
        self.packs = []

    def pack(self, **kw):
        self.packs.append(kw)


class _TkBundle:
    """Фабрика tb/tk-виджетов шпаргалки: всё созданное — в реестр."""

    X = 'x'
    LEFT = 'left'
    RIGHT = 'right'

    def __init__(self):
        self.widgets = []

    def Toplevel(self, master=None, **kw):
        d = _DialogWidget(**kw)
        self.widgets.append(d)
        return d

    def Frame(self, master=None, **kw):
        return self._mk('Frame', master, **kw)

    def Label(self, master=None, **kw):
        return self._mk('Label', master, **kw)

    def Button(self, master=None, **kw):
        return self._mk('Button', master, **kw)

    def _mk(self, kind, master=None, **kw):
        w = _Widget(kind, master, **kw)
        self.widgets.append(w)
        return w

    def buttons(self, text):
        return [w for w in self.widgets
                if w.kind == 'Button' and w.kw.get('text') == text]

    def command(self, text, index=0):
        return self.buttons(text)[index].kw['command']


class _Host2(OutputMixin):
    """Хост с виджетами, которых нет у _Host: output-с-поиском, root, key_var."""

    def __init__(self, buf='', history=None):
        self.output = _Text(buf)
        self._logger = _Logger()
        self.root = _Root()
        self.cmd_entry = _Entry()
        self.key_var = _Var('')
        self.cmd_history = list(history or [])
        self.history_index = len(self.cmd_history)


# ---------- поиск по выводу ----------
class TestFindInOutput:
    def _run(self, monkeypatch, buf, answer):
        h = _Host2(buf)
        ask = _Ask(answer)
        monkeypatch.setattr(go, 'simpledialog', ask)
        h.find_in_output()
        return h

    def test_cancel_and_blank_query_do_nothing(self, monkeypatch):
        for answer in (None, ''):
            h = self._run(monkeypatch, 'abc', answer)
            assert h.output.ops == [], answer
            assert h.output.lines == [], answer

    def test_search_is_case_insensitive(self, monkeypatch):
        h = self._run(monkeypatch, 'xxABCxx', 'abc')
        adds = [op for op in h.output.ops if op[0] == 'add']
        assert len(adds) == 1
        assert h.output.lines == ['🔍 Найдено совпадений: 1\n']

    def test_all_occurrences_highlighted_and_scrolled(self, monkeypatch):
        # стартовый индекс обязан сдвигаться за найденное: иначе этот же
        # тест крутил бы бесконечный цикл
        h = self._run(monkeypatch, 'err xx err xx err', 'err')
        adds = [op for op in h.output.ops if op[0] == 'add']
        assert [op[2] for op in adds] == ['1.0', '1.7', '1.14']
        assert h.output.lines == ['🔍 Найдено совпадений: 3\n']
        # log() сам прокручивает вывод в конец (see(END)), поэтому первое
        # значение — от него; поверх поиск обязан увести на ПЕРВОЕ совпадение,
        # а не на последнее
        assert h.output.seen == ['end', '1.0']

    def test_no_hits_reports_and_clears_previous_marks(self, monkeypatch):
        h = self._run(monkeypatch, 'nginx ok', 'zzz')
        # старая подсветка снимается ДО поиска — это обязательный шаг
        assert h.output.ops[0] == ('remove', 'search_hit', '1.0', 'end')
        assert not [op for op in h.output.ops if op[0] == 'add']
        assert h.output.lines == ["🔍 'zzz' не найдено\n"]
        # прокрутка одна — от log(): ветке «не найдено» водить некуда,
        # дополнительного see() быть не должно
        assert h.output.seen == ['end']


# ---------- копирование в буфер ----------
class TestCopyOutput:
    def test_copies_all_text_and_logs(self):
        h = _Host2('ОТЧЁТ\n')
        h.copy_output()
        assert h.root.cleared == 1
        assert h.root.clip == ['ОТЧЁТ\n']
        assert h.root.events == ['update']
        assert h.output.lines == ['✅ Вывод скопирован в буфер обмена\n']

    def test_logger_receives_masked_copy_notice(self):
        h = _Host2('x')
        h.copy_output()
        assert h._logger.records == ['✅ Вывод скопирован в буфер обмена']


# ---------- сохранение отчёта ----------
class TestSaveReport:
    def test_writes_file_and_logs_path(self, monkeypatch, tmp_path):
        target = str(tmp_path / 'report.txt')
        h = _Host2('ОТЧЁТ 1\n')
        files = _Files(save_as=target)
        monkeypatch.setattr(go, 'filedialog', files)
        h.save_report()
        assert open(target, encoding='utf-8').read() == 'ОТЧЁТ 1\n'
        assert h.output.lines == [f'✅ Отчёт сохранён в {target}\n']
        # диалог обязан предлагать .txt и ссылаться на окно-владелец
        assert files.save_asks[0]['defaultextension'] == '.txt'
        assert files.save_asks[0]['parent'] is h.root

    def test_cancelled_dialog_writes_nothing(self, monkeypatch, tmp_path):
        h = _Host2('ОТЧЁТ')
        monkeypatch.setattr(go, 'filedialog', _Files(save_as=''))
        h.save_report()
        assert h.output.lines == []
        assert list(tmp_path.iterdir()) == []

    def test_write_error_shows_message_not_exception(self, monkeypatch):
        h = _Host2('ОТЧЁТ')
        msg = _Msg()
        monkeypatch.setattr(go, 'filedialog',
                            _Files(save_as='/nonexistent-dir/r.txt'))
        monkeypatch.setattr(go, 'messagebox', msg)
        h.save_report()                       # не должно бросить наружу
        assert msg.events[0][0] == 'error'
        assert 'Не удалось сохранить' in msg.events[0][2]
        assert h.output.lines == []           # «сохранён» не врал


# ---------- шпаргалка ----------
class TestCheatsheet:
    def _open(self, monkeypatch):
        bundle = _TkBundle()
        monkeypatch.setattr(go, 'tb', bundle)
        h = _Host2()
        h.show_cheatsheet()
        return h, bundle

    def test_dialog_is_modal_and_lists_every_command(self, monkeypatch):
        h, bundle = self._open(monkeypatch)
        dialog = bundle.widgets[0]
        assert dialog.grabbed == 1 and dialog.transients == 1
        assert dialog.titles == ['📖 Шпаргалка техподдержки']
        # кнопок «Вставить» — по числу пар (имя, команда)
        assert len(bundle.buttons('Вставить')) == 10

    def test_insert_puts_command_into_entry_and_closes(self, monkeypatch):
        h, bundle = self._open(monkeypatch)
        bundle.command('Вставить')()          # первая строка — nginx
        assert h.cmd_entry.get() == 'systemctl restart nginx'
        assert bundle.widgets[0].destroyed == 1

    def test_insert_uses_own_row_command_not_last_loop_value(self, monkeypatch):
        # classic lambda-in-loop: без cmd=cmd все кнопки вставляли бы
        # последнюю команду шпаргалки
        h, bundle = self._open(monkeypatch)
        bundle.command('Вставить', index=9)()
        assert h.cmd_entry.get() == 'nginx -t'

    def test_close_button_destroys_dialog(self, monkeypatch):
        h, bundle = self._open(monkeypatch)
        bundle.command('Закрыть')()
        assert bundle.widgets[0].destroyed == 1

    def test_insert_clears_previous_entry_text(self, monkeypatch):
        h, bundle = self._open(monkeypatch)
        h.cmd_entry._v = 'старый ввод'
        bundle.command('Вставить')()
        assert h.cmd_entry.get() == 'systemctl restart nginx'


# ---------- выбор файла ключа ----------
class TestBrowseKey:
    def test_chosen_path_lands_in_key_var(self, monkeypatch):
        h = _Host2()
        monkeypatch.setattr(go, 'filedialog',
                            _Files(open_name='/home/u/.ssh/id_ed25519'))
        h.browse_key()
        assert h.key_var.get() == '/home/u/.ssh/id_ed25519'

    def test_cancelled_dialog_keeps_previous_value(self, monkeypatch):
        h = _Host2()
        h.key_var.set('/old/key')
        monkeypatch.setattr(go, 'filedialog', _Files(open_name=''))
        h.browse_key()
        assert h.key_var.get() == '/old/key'
