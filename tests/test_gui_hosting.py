"""Тесты gui_hosting.py: меню «Хостинг» (без Tk и без SSH).

Тот же паттерн, что в test_gui_bitrix.py: класс-хост переопределяет
_run_in_thread (поток не запускается, вызов записывается), simpledialog
подменяется на уровне модуля. Специфика этого миксина:

- меню не привязано к панели, поэтому panel_type передаётся бэкенду
  вторым аргументом (инвентарь работает и на сервере без панели);
- «Досье домена» спрашивает домен ДО ухода в фон и без cache_key —
  оператор каждый раз жмёт его на разных доменах, кеш врал бы.
"""
import os
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

import gui_hosting as gh
from gui_hosting import HOSTING_MENU, HostingMixin
from support import FakeSSH, menu_handlers


class _Btn:
    def __init__(self):
        self.configs = []

    def config(self, **kw):
        self.configs.append(kw)


class _Frame:
    def __init__(self):
        self.packed = 0
        self.forgotten = 0

    def pack(self, **kw):
        self.packed += 1

    def pack_forget(self):
        self.forgotten += 1


class _Dialogs:
    """Двойник simpledialog + messagebox.

    askstring отдаёт askstring_ret либо по очереди элементы askstring_seq —
    операции с ящиками спрашивают ДВЕ вещи подряд (адрес, затем пароль), и
    тесту важно знать, до какого вопроса дело дошло. askyesno отдаёт
    askyesno_ret и пишет обращения: разрушающие операции обязаны спрашивать
    подтверждение, а тест — видеть, что спросили ровно один раз.
    """

    def __init__(self, askstring_ret=None, askstring_seq=None,
                 askyesno_ret=True):
        self.askstring_ret = askstring_ret
        self.askstring_seq = list(askstring_seq) if askstring_seq else None
        self.askyesno_ret = askyesno_ret
        self.string_asks = 0
        self.asked = []

    def askstring(self, *a, **k):
        self.string_asks += 1
        if self.askstring_seq is not None:
            return self.askstring_seq.pop(0) if self.askstring_seq else None
        return self.askstring_ret

    def askyesno(self, title, msg, parent=None):
        self.asked.append((title, msg))
        return self.askyesno_ret

    def showerror(self, *a, **k):
        pass


class _Host(HostingMixin):
    """Владелец миксина: panel_type ставим вручную — его берёт create_widgets."""

    def __init__(self, checker=None, panel_type='fastpanel'):
        self.checker = checker
        self.panel_type = panel_type
        self.root = None
        self.host_menu_btn = _Btn()
        self.hosting_frame = _Frame()
        self.calls = []

    def _run_in_thread(self, target_func, btn=None, *args, **kwargs):
        self.calls.append((target_func, btn, args, kwargs))


# None в меню — разделитель перед точечным запросом по домену. Обработчики
# собирает общий menu_handlers: он понимает и вложенные подменю, и разделители.
ALL_HANDLERS = menu_handlers(HOSTING_MENU)

# Отчёты: (обработчик, бэкенд, cache_key). Ничего не меняют — спрашивать
# нечего, результат кешируется 60 с (прогон по сотне доменов дорогой).
REPORT_MAP = [
    ("run_host_inventory", "hosting_inventory_report", "host_inventory"),
    ("run_host_sites", "site_health_report", "host_sites"),
    ("run_host_ssl", "ssl_expiry_report", "host_ssl"),
    ("run_host_mail", "mail_overview_report", "host_mail"),
    ("run_host_mail_auth", "mail_auth_report", "host_mail_auth"),
    ("run_host_zones", "dns_zones_report", "host_zones"),
]


class TestSslExpiryEntry:
    """Пункт «SSL: срок действия сертификатов» — в списке, но НЕ в «досье».

    Порядок пунктов важен: SSL-отчёт стоит рядом с «Сайты и доступность»
    (это парная проверка того же инвентаря), а разделитель по-прежнему
    отделяет сводные отчёты от диалога про конкретный домен.
    """

    def test_ssl_entry_is_before_the_separator(self):
        sep = HOSTING_MENU.index(None)
        before = menu_handlers(HOSTING_MENU[:sep])
        assert before.index("run_host_ssl") == before.index("run_host_sites") + 1

    def test_ssl_report_probes_https_once_per_domain(self):
        # Цена пункта — один TLS-хендшейк на домен и не больше limit: без
        # лимита прогон по сотне доменов вешал бы окно на минуты.
        import discovery as dc
        rows = ''.join(f'name=site{i}.tld elid={i}\n' for i in range(60))
        c = FakeSSH(routes=[('mgrctl -m ispmgr webdomain', rows)])
        out = dc.ssl_expiry_report(c, 'ispmanager')
        assert c.count('s_client -servername') == dc.HEALTH_CHECK_LIMIT
        assert 'Проверено доменов: 25 из 60' in out


class TestMailAuthEntry:
    """Пункт «Почта: SPF/DKIM/DMARC/PTR» — вторая строка почтовой группы.

    Он стоит рядом с «Почта: домены, ящики, очередь» по той же логике, по
    которой SSL-отчёт стоит рядом с доступностью сайтов: это парная проверка
    того же объекта, только смотрит она в DNS, а не в панель. Отдельным
    подменю пункт не сделан намеренно: в меню хостинга подменю уже есть
    (операции над ящиками), а сводные отчёты оператору выгоднее видеть
    плоским списком.
    """

    def test_entry_sits_right_after_the_mail_inventory(self):
        sep = HOSTING_MENU.index(None)
        before = menu_handlers(HOSTING_MENU[:sep])
        assert before.index("run_host_mail_auth") == before.index("run_host_mail") + 1

    def test_it_is_a_report_not_an_operator_dialog(self):
        # После разделителя живёт только то, где нужен ввод оператора. Отчёт
        # по всем доменам ввод не спрашивает — значит обязан быть до разделителя.
        sep = HOSTING_MENU.index(None)
        assert "run_host_mail_auth" in menu_handlers(HOSTING_MENU[:sep])
        assert "run_host_mail_auth" not in menu_handlers(HOSTING_MENU[sep + 1:])

    def test_main_list_is_still_flat_except_the_mailbox_submenu(self):
        # «Интерфейс не разрастается»: седьмой сводный отчёт не добавляет ни
        # подменю, ни вложенности — ровно одну строку в основной список.
        subs = [e for e in HOSTING_MENU if e and isinstance(e[1], list)]
        assert len(subs) == 1 and subs[0][0] == "Почтовые ящики ▸"
        top = [e for e in HOSTING_MENU if e and not isinstance(e[1], list)]
        assert len(top) == 7


class TestMenuIntegrity:
    def test_every_menu_item_has_handler(self):
        host = _Host()
        for name in ALL_HANDLERS:
            assert callable(getattr(host, name, None)), name

    def test_separator_isolates_operator_input(self):
        # После разделителя — только то, чему нужен ввод оператора: «Досье
        # домена» и подменю ящиков (menu_handlers разворачивает его вложенные
        # пункты, поэтому они видны гарду).
        sep = HOSTING_MENU.index(None)
        after = menu_handlers(HOSTING_MENU[sep + 1:])
        assert after == ["run_host_domain", "run_host_mb_create",
                         "run_host_mb_passwd", "run_host_mb_delete"]

    def test_mailbox_ops_are_grouped_into_submenu(self):
        # Требование «интерфейс не разрастается»: операции над ящиками — ОДНА
        # строка основного списка, а не три пункта.
        sub = [entry for entry in HOSTING_MENU
               if entry and isinstance(entry[1], list)]
        assert len(sub) == 1
        assert menu_handlers([sub[0]]) == ["run_host_mb_create",
                                           "run_host_mb_passwd",
                                           "run_host_mb_delete"]

    def test_destructive_mailbox_ops_after_inner_separator(self):
        # Внутри подменю разделитель отделяет создание (безвозвратно не меняет
        # данных) от смены пароля и удаления.
        sub = [entry for entry in HOSTING_MENU
               if entry and isinstance(entry[1], list)][0][1]
        sep = sub.index(None)
        assert [m for _, m in sub[:sep]] == ["run_host_mb_create"]
        assert [m for _, m in sub[sep + 1:]] == ["run_host_mb_passwd",
                                                 "run_host_mb_delete"]


class TestNoConnection:
    @pytest.mark.parametrize("handler", ALL_HANDLERS)
    def test_silent_without_checker(self, monkeypatch, handler):
        host = _Host(checker=None)
        dialogs = _Dialogs(askstring_ret='example.com')
        monkeypatch.setattr(gh, "simpledialog", dialogs)
        getattr(host, handler)()
        assert host.calls == [], handler
        # диалог без соединения — плохая идея: оператор введёт домен впустую
        assert dialogs.string_asks == 0, handler


class TestReports:
    @pytest.mark.parametrize("handler,backend,cache_key", REPORT_MAP)
    def test_report_passes_checker_and_panel_with_cache(
            self, monkeypatch, handler, backend, cache_key):
        checker = FakeSSH()
        host = _Host(checker, panel_type='ispmanager')
        getattr(host, handler)()
        assert len(host.calls) == 1
        fn, btn, args, kwargs = host.calls[0]
        assert fn is getattr(gh, backend), handler
        assert btn is host.host_menu_btn
        # panel_type уходит вторым аргументом: без него discovery вызывал бы
        # detect_panel() заново на каждый отчёт
        assert args == (checker, 'ispmanager')
        assert kwargs == {"cache_key": cache_key}


class TestDomainDetail:
    def test_cancelled_dialog_does_not_run(self, monkeypatch):
        host = _Host(FakeSSH())
        monkeypatch.setattr(gh, "simpledialog", _Dialogs(askstring_ret=None))
        host.run_host_domain()
        assert host.calls == []

    def test_blank_domain_does_not_run(self, monkeypatch):
        host = _Host(FakeSSH())
        monkeypatch.setattr(gh, "simpledialog", _Dialogs(askstring_ret='   '))
        host.run_host_domain()
        assert host.calls == []

    def test_domain_is_stripped_and_passed_without_cache(self, monkeypatch):
        checker = FakeSSH()
        host = _Host(checker, panel_type='none')
        monkeypatch.setattr(gh, "simpledialog",
                            _Dialogs(askstring_ret=' Example.COM '))
        host.run_host_domain()
        assert len(host.calls) == 1
        fn, btn, args, kwargs = host.calls[0]
        assert fn is gh.domain_detail_report
        assert btn is host.host_menu_btn
        # домен — сразу после checker и до panel_type; кеша нет: следующий
        # клик будет про другой домен
        assert args == (checker, 'Example.COM', 'none')
        assert kwargs == {}


class TestMailboxOperations:
    """Операции над ящиками: диалоги ДО фона, подтверждение, без кеша.

    cache_key запрещён всем трём: операция меняет состояние панели, а
    закешированный «инвентарь до действия» показал бы оператору старый список
    ящиков после создания нового.
    """

    def test_create_asks_address_then_password(self, monkeypatch):
        checker = FakeSSH()
        host = _Host(checker, panel_type='ispmanager')
        dialogs = _Dialogs(askstring_seq=[' New@Example.com ', 'Sup3r!Pass'])
        monkeypatch.setattr(gh, "simpledialog", dialogs)
        host.run_host_mb_create()
        assert dialogs.string_asks == 2, "адрес и пароль — два вопроса подряд"
        assert len(host.calls) == 1
        fn, btn, args, kwargs = host.calls[0]
        assert fn is gh.mailbox_create
        assert btn is host.host_menu_btn
        # адрес стрижется (пробел панель съела бы как часть имени), пароль —
        # КАК ВВЕДЁН: пробел для пароля валидный символ
        assert args == (checker, 'New@Example.com', 'Sup3r!Pass', 'ispmanager')
        assert kwargs == {}

    def test_create_cancelled_address_does_not_ask_password(self, monkeypatch):
        # Спрашивать пароль, когда адрес уже отменён, — плохой разговор
        host = _Host(FakeSSH())
        dialogs = _Dialogs(askstring_seq=[None])
        monkeypatch.setattr(gh, "simpledialog", dialogs)
        host.run_host_mb_create()
        assert host.calls == []
        assert dialogs.string_asks == 1

    def test_create_blank_address_does_not_run(self, monkeypatch):
        host = _Host(FakeSSH())
        monkeypatch.setattr(gh, "simpledialog", _Dialogs(askstring_ret='   '))
        host.run_host_mb_create()
        assert host.calls == []

    def test_create_cancelled_password_does_not_run(self, monkeypatch):
        host = _Host(FakeSSH())
        dialogs = _Dialogs(askstring_seq=['a@example.com', None])
        monkeypatch.setattr(gh, "simpledialog", dialogs)
        host.run_host_mb_create()
        assert host.calls == []

    def test_passwd_confirms_before_asking_password(self, monkeypatch):
        checker = FakeSSH()
        host = _Host(checker, panel_type='fastpanel')
        dialogs = _Dialogs(askstring_seq=['info@example.com', 'Sup3r!Pass'],
                           askyesno_ret=True)
        monkeypatch.setattr(gh, "simpledialog", dialogs)
        monkeypatch.setattr(gh, "messagebox", dialogs)
        host.run_host_mb_passwd()
        assert len(dialogs.asked) == 1, "подтверждение обязано быть ровно одно"
        assert 'info@example.com' in dialogs.asked[0][1]
        assert len(host.calls) == 1
        fn, _btn, args, kwargs = host.calls[0]
        assert fn is gh.mailbox_passwd
        assert args == (checker, 'info@example.com', 'Sup3r!Pass', 'fastpanel')
        assert kwargs == {}

    def test_passwd_declined_never_asks_password(self, monkeypatch):
        # Спросить пароль, а потом отказаться — значит показать секрет лишнему
        # окну. Отказ должен отсекать всё до второго диалога.
        host = _Host(FakeSSH())
        dialogs = _Dialogs(askstring_seq=['info@example.com'],
                           askyesno_ret=False)
        monkeypatch.setattr(gh, "simpledialog", dialogs)
        monkeypatch.setattr(gh, "messagebox", dialogs)
        host.run_host_mb_passwd()
        assert host.calls == []
        assert dialogs.string_asks == 1, "пароль спрашивается после подтверждения"

    def test_delete_confirms_and_warns_about_letters(self, monkeypatch):
        checker = FakeSSH()
        host = _Host(checker, panel_type='ispmanager')
        dialogs = _Dialogs(askstring_seq=['info@example.com'],
                           askyesno_ret=True)
        monkeypatch.setattr(gh, "simpledialog", dialogs)
        monkeypatch.setattr(gh, "messagebox", dialogs)
        host.run_host_mb_delete()
        assert len(dialogs.asked) == 1
        # Удаление ящика уносит почтовый каталог — предупреждение обязательное
        assert 'Письма' in dialogs.asked[0][1]
        assert len(host.calls) == 1
        fn, _btn, args, kwargs = host.calls[0]
        assert fn is gh.mailbox_delete
        assert args == (checker, 'info@example.com', 'ispmanager')
        assert kwargs == {}

    def test_delete_declined_runs_nothing(self, monkeypatch):
        host = _Host(FakeSSH())
        dialogs = _Dialogs(askstring_seq=['info@example.com'],
                           askyesno_ret=False)
        monkeypatch.setattr(gh, "simpledialog", dialogs)
        monkeypatch.setattr(gh, "messagebox", dialogs)
        host.run_host_mb_delete()
        assert host.calls == []


class TestMenuVisibility:
    def test_show_with_connection_packs_and_enables(self):
        host = _Host(FakeSSH())
        host._set_hosting_menu_visible(True)
        assert host.hosting_frame.packed == 1
        assert host.host_menu_btn.configs[-1]['state'] == 'normal'

    def test_show_after_disconnect_is_ignored(self):
        # Гонка, как у Битрикса: меню показывают по событию, которое может
        # догнать уже закрытое соединение.
        host = _Host(checker=None)
        host._set_hosting_menu_visible(True)
        assert host.hosting_frame.packed == 0
        assert host.hosting_frame.forgotten == 1
        assert host.host_menu_btn.configs[-1]['state'] == 'disabled'

    def test_hide_forgets_and_disables(self):
        host = _Host(FakeSSH())
        host._set_hosting_menu_visible(False)
        assert host.hosting_frame.forgotten == 1
        assert host.host_menu_btn.configs[-1]['state'] == 'disabled'
