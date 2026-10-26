"""Тесты logs.py: поиск логов по панелям, анализ access-логов, домены, OOM.

Реального SSH нет — команды перехватывает FakeSSH из support.py. Исключение
составляет выбор почтового файла: он реализован циклом в shell, и FakeSSH его
проверить не может (заглушка отвечает на команду целиком, а не исполняет её) —
такие проверки идут настоящим bash'ем по временным файлам.
"""
import os
import subprocess
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from support import FakeSSH, LOG_OK_1, LOG_OK_2, LOG_OK_3, LOG_OTHER_DAY, LOG_BAD
import logs as logs_mod


LOG_ALL = '\n'.join([LOG_OK_1, LOG_OK_2, LOG_OK_3, LOG_BAD, ''])


# ==================== поиск файлов логов ====================
class TestFindLogs:
    def test_fastpanel_patterns(self):
        c = FakeSSH(routes=[('ls -1', '/var/www/site/data/logs/example.error.log\n')])
        files = logs_mod.find_logs(c, 'fastpanel', 'example.com', 'error')
        assert '/var/www/site/data/logs/example.error.log' in files
        assert c.find('/var/www/*/data/logs/*example.com*.error.log') is not None

    def test_ispmanager_patterns(self):
        c = FakeSSH(routes=[('ls -1', '')])
        logs_mod.find_logs(c, 'ispmanager', 'example.com', 'error')
        assert c.find('/var/www/*/example.com/data/logs/error.log') is not None
        assert c.find('/var/www/httpd-logs/example.com.error.log') is not None

    def test_no_panel_uses_distro_paths(self):
        c = FakeSSH(routes=[('ls -1', '')])
        logs_mod.find_logs(c, 'none', 'example.com', 'error')
        assert c.find('/var/log/nginx/example.com.error.log') is not None
        assert c.find('/var/log/apache2/example.com-error.log') is not None

    def test_results_deduplicated(self):
        c = FakeSSH(routes=[('ls -1', '/a/error.log\n/a/error.log\n')])
        assert logs_mod.find_logs(c, 'none', 'example.com') == ['/a/error.log']

    def test_domain_is_sanitized_against_injection(self):
        # _safe_name вырезает shell-метасимволы: имя домена не может расшириться
        # до команды (паттерны идут в ls без кавычек — они glob'ы).
        #
        # ФОРМУ ЗАМКА МЕНЯЮ ОСОЗНАННО и объявляю это. Прежний вариант запирал
        # требование «метасимволы из имени домена не станут командой» как «символа
        # ; и " нет во всей строке». С составной POSIX-формой (состояние каталога
        # спрашивается ДО ls — см. common.find_files_cmd) `;` и `"` есть в самой
        # конструкции shell: прежний замок запрещал бы само различение, за которое
        # стоят релизы 1.18-1.20. Инвариант сохраняю строго, но на месте угрозы:
        # имя домена попадает ТОЛЬКО в сегмент glob'а, и метасимволов не должно
        # быть именно там.
        #
        # БУКВЫ остаются — и это правильно. _safe_name вырезает метасимволы и
        # склеивает 'example.com$(curl evil)")' в 'example.comcurlevil': подстрока
        # curl тут обычный текст имени, она не может стать командой. Прежний замок
        # сам этого ожидал (assert 'example.comcurl' in commands[0]), поэтому
        # запрещать буквы было бы неверно.
        attack = 'example.com$(curl evil)")'
        c = FakeSSH(routes=[('ls -1', '')])
        logs_mod.find_logs(c, 'none', attack)
        assert c.commands, 'поиск должен был уйти на сервер'
        for cmd in c.commands:
            # Подстановки команд не должно быть НИ В ОДНОЙ отправленной команде,
            # включая служебную часть (её пишем мы сами — она обязана быть чистой).
            assert '$(' not in cmd and '`' not in cmd
            if 'ls -1 ' in cmd:
                # Границу glob'а знает двойник (support.FakeSSH.ls_glob), а не
                # локальный split: с 1.32.3 после glob'а стоит НАША служебная
                # часть `; echo "FFRC $?"; }`, и прежний split(' |') принимал её
                # за имя домена — замок краснел не по инъекции, а по форме
                # команды. Разбор формы в одном месте (тот же закон, что держит
                # FFDIR/FFCOUNT в одном месте).
                glob = c.ls_glob(cmd)
                assert glob, 'glob обязан дойти до ls буквально'
                for ch in ';$"`|&<>(){}[]*?!\\\'\n':
                    if ch != '*':
                        assert ch not in glob, f'{ch!r} в glob из имени домена'
                # Имя домена дошло до ls буквально. Звёздочку здесь НЕ требуем:
                # паттерны панели 'none' — конкретные имена файлов
                # ('/var/log/nginx/домен.error.log'), без glob-символов вовсе.
                assert 'example.comcurl' in glob
        assert 'example.comcurl' in c.commands[0]


class TestMissingLogsReason:
    """Причина пустоты доходит до оператора, а не подменяется «не найдено».

    common.find_files умеет различать «каталога нет», «нет прав», «срезал
    лимит», но find_logs отдаёт заметки тем же списком, что и пути, а каждый
    потребитель отфильтровывает их как не-пути (logs.py и webcheck.py). В
    итоге на выходе снова стояло «Не найден … лог» — ложь возвращалась на
    последнем шаге. Заперто здесь, а не только в common.
    """

    def test_unreadable_dir_is_not_reported_as_missing_logs(self):
        c = FakeSSH(routes=[('ls -1', 'FFDIR noperm /var/log/nginx\nFFCOUNT 0\n')])
        out = logs_mod.analyze_access_log(c, 'none', 'example.com')
        assert 'прав' in out
        assert 'Не найден access-лог' not in out

    def test_missing_dir_names_the_path_it_could_not_read(self):
        c = FakeSSH(routes=[('ls -1', 'FFDIR missing /var/log/apache2\nFFCOUNT 0\n')])
        out = logs_mod.analyze_access_log(c, 'none', 'example.com')
        assert '/var/log/apache2' in out and 'Каталога' in out

    def test_unconfirmed_answer_is_not_verified(self):
        # Ни путей, ни маркеров: «не проверено», а не «логов нет» (закон 1.16+).
        c = FakeSSH(routes=[])
        out = logs_mod.analyze_access_log(c, 'none', 'example.com')
        assert 'не проверено' in out
        assert 'Не найден access-лог' not in out

    def test_find_logs_info_separates_paths_from_reasons(self):
        c = FakeSSH(routes=[('ls -1', 'FFDIR ok /var/log/nginx\n'
                                       '/var/log/nginx/a.log\nFFCOUNT 1\n')])
        info = logs_mod.find_logs_info(c, 'none', 'example.com', 'access')
        assert info['paths'] == ['/var/log/nginx/a.log']
        assert info['notes'] == [] and info['checked'] is True

    def test_find_logs_stays_compatible_for_older_consumers(self):
        # find_logs зовут discovery/panels/GUI: совместимость обязана остаться.
        c = FakeSSH(routes=[('ls -1', 'FFDIR noperm /var/log/nginx\nFFCOUNT 0\n')])
        got = logs_mod.find_logs(c, 'none', 'example.com')
        assert [g for g in got if not g.startswith('⚠️')] == []
        assert any(g.startswith('⚠️') for g in got)


# ==================== анализ access-логов ====================
class TestAnalyzeAccessLog:
    def test_no_logs_found(self):
        # ЗАМОК ПЕРЕФОРМУЛЕН ОБЪЯВЛЕННО: раньше пустой ОТВЕТ (даже без единого
        # маркера состояния каталога) запирался как «Не найден access-лог», т.е.
        # «не проверено» было заперто как «логов нет» — ровно та ложь, которую
        # лечат релизы 1.16-1.20. Теперь «Не найден» заперт на проверенном
        # пустом каталоге (FFDIR ok), а неподтверждённый ответ заперт отдельно
        # ниже (test_unconfirmed_answer_is_not_verified).
        c = FakeSSH(routes=[('ls -1', 'FFDIR ok /var/log/nginx\nFFCOUNT 0\n')])
        out = logs_mod.analyze_access_log(c, 'none', 'example.com')
        assert 'Не найден access-лог' in out
        assert 'не проверено' not in out

    def test_counters_and_tops(self):
        c = FakeSSH(routes=[
            ('ls -1', '/var/log/nginx/example.com.access.log\n'),
            ('cat ', LOG_ALL),
        ])
        out = logs_mod.analyze_access_log(c, 'none', 'example.com')
        assert 'Всего запросов: 3' in out          # LOG_BAD отброшен парсером
        assert 'Уникальных IP: 2' in out
        assert '198.51.100.7' in out               # топ-1: 2 запроса
        assert '/index.php' in out
        assert 'python-requests/2.31' in out

    def test_top_n_limits_lines(self):
        c = FakeSSH(routes=[
            ('ls -1', '/var/log/nginx/example.com.access.log\n'),
            ('cat ', LOG_ALL),
        ])
        out = logs_mod.analyze_access_log(c, 'none', 'example.com', top_n=1)
        # в топе IP остаётся только лидер, второй IP — только в счётчике
        ip_section = out.split('ПО КОЛИЧЕСТВУ ЗАПРОСОВ ---')[1].split('\n\n')[0]
        assert '198.51.100.7' in ip_section
        assert '203.0.113.9' not in ip_section

    def test_date_filter(self):
        c = FakeSSH(routes=[
            ('ls -1', '/var/log/nginx/example.com.access.log\n'),
            ('cat ', LOG_ALL + LOG_OTHER_DAY),
        ])
        out = logs_mod.analyze_access_log(c, 'none', 'example.com', day=9)
        assert 'Всего запросов: 1' in out
        assert 'день=9' in out

    def test_empty_period_message(self):
        c = FakeSSH(routes=[
            ('ls -1', '/var/log/nginx/example.com.access.log\n'),
            ('cat ', LOG_ALL),
        ])
        out = logs_mod.analyze_access_log(c, 'none', 'example.com', day=1)
        assert 'записей не найдено' in out

    def test_gzipped_logs_use_zcat(self):
        c = FakeSSH(routes=[
            ('ls -1', '/var/log/nginx/example.com.access.log.gz\n'),
            ('zcat ', LOG_ALL),
        ])
        out = logs_mod.analyze_access_log(c, 'none', 'example.com')
        assert 'Всего запросов: 3' in out
        assert c.find('zcat') is not None

    # ПЕРЕФОРМУЛИРОВАНО ОБЪЯВЛЕННО (тот же закон, что в 1.20.0). Инвариант
    # заперт прежний и остаётся строгим: строка-предупреждение от find_files не
    # должна уходить в `cat` и не должна появляться в выводе. Но fixture прежде
    # отвечал на `ls -1` БЕЗ FFCOUNT, то есть записывал не подтверждённый
    # сервером просмотр как штатный; теперь такие 20 логов честно получают
    # «состояние не проверено» и отчёт обязан их показать. Поэтому каталог
    # подтверждён (FFCOUNT), а проверка строки лимита осталась прежней.
    def test_limit_warning_line_is_not_read_as_file(self):
        many = '\n'.join(f'/var/log/nginx/l{i}.log' for i in range(20)) + \
               '\n⚠️ (показаны первые 20 файлов)'
        c = FakeSSH(routes=[('RFSTATE', ('RFSTATE readable\n', '', 0)),
                            ('ls -1', many + '\nFFCOUNT 20\n')])
        out = logs_mod.analyze_access_log(c, 'none', 'example.com')
        assert '⚠️' not in out
        assert c.find('RFSTATE') is not None
        assert '⚠️' not in c.find('RFSTATE')

    # --- нечитаемый access-лог не имеет права называться «трафика не было» ---

    def test_unreadable_access_log_is_not_called_no_records(self):
        # Решающий случай: права 0600 root на access-лог. Прежний код делал
        # `if not content: continue` и на нуле печатал «За указанный период
        # записей не найдено» — оператор искал отсутствие посещений, а не права.
        c = FakeSSH(routes=[
            ('ls -1', '/var/log/nginx/example.com.access.log\nFFCOUNT 1\n'),
            ('RFSTATE', ('RFSTATE unreadable\n', 'cat: Permission denied', 1)),
        ])
        out = logs_mod.analyze_access_log(c, 'none', 'example.com')
        assert 'не просмотрен' in out
        assert 'прав' in out
        assert 'не найдено' not in out

    def test_broken_gz_is_not_called_no_records(self):
        # .gz читался как `zcat f 2>/dev/null`: «не gzip-архив» и «пустой архив»
        # для отчёта были одно и то же. Ответ системы обязан дойти.
        c = FakeSSH(routes=[
            ('ls -1', '/var/log/nginx/example.com.access.log.gz\nFFCOUNT 1\n'),
            ('zcat ', ('', 'gzip: stdin: not in gzip format', 1)),
        ])
        out = logs_mod.analyze_access_log(c, 'none', 'example.com')
        assert 'gzip' in out
        assert 'не найдено' not in out

    def test_partially_read_still_counts_traffic_it_saw(self):
        # Найденное терять нельзя: посчитанный трафик остаётся, но отчёт обязан
        # сказать, что часть логов в нём не участвовала.
        c = FakeSSH(routes=[
            ('ls -1', '/var/log/nginx/a.access.log\n'
                      '/var/log/nginx/b.access.log\nFFCOUNT 2\n'),
            ('a.access.log', ('RFSTATE readable\n' + LOG_ALL, '', 0)),
            ('RFSTATE', ('RFSTATE unreadable\n', 'cat: Permission denied', 1)),
        ])
        out = logs_mod.analyze_access_log(c, 'none', 'example.com')
        assert 'Всего запросов:' in out
        assert 'b.access.log' in out and 'не просмотрен' in out

    def test_processed_files_count_is_honest(self):
        # Прежняя строка «Обработано файлов: N» считала НАЙДЕННЫЕ файлы, а не
        # прочитанные: при одном закрытом логе отчёт врал про полноту проверки.
        c = FakeSSH(routes=[
            ('ls -1', '/var/log/nginx/a.access.log\n'
                      '/var/log/nginx/b.access.log\nFFCOUNT 2\n'),
            ('a.access.log', ('RFSTATE readable\n' + LOG_ALL, '', 0)),
            ('RFSTATE', ('RFSTATE unreadable\n', 'cat: Permission denied', 1)),
        ])
        out = logs_mod.analyze_access_log(c, 'none', 'example.com')
        assert 'Обработано файлов: 1' in out
        assert 'Обработано файлов: 2' not in out

    def test_zcat_stderr_is_not_thrown_away(self):
        # Замок по ОТПРАВЛЕННОЙ команде: 2>/dev/null терял «not in gzip format».
        c = FakeSSH(routes=[
            ('ls -1', '/var/log/nginx/x.access.log.gz\nFFCOUNT 1\n'),
            ('zcat ', ('', 'x', 1)),
        ])
        logs_mod.analyze_access_log(c, 'none', 'example.com')
        assert c.find('zcat') is not None
        assert '2>/dev/null' not in c.find('zcat')


# ==================== домены ====================
class TestGetDomains:
    def test_ispmanager_uses_mgrctl(self):
        csv = 'name,domains\n1,example.com\n2,site.ru\n'
        c = FakeSSH(routes=[('mgrctl', csv)])
        assert sorted(logs_mod.get_domains(c, 'ispmanager')) == ['example.com', 'site.ru']

    def test_ispmanager_falls_back_to_configs(self):
        c = FakeSSH(routes=[('mgrctl', ''), ('ls -1', '/etc/nginx/vhosts/example\n'),
                            ('grep -h', 'server_name example.com;\n')])
        assert logs_mod.get_domains(c, 'ispmanager') == ['example.com']

    def test_plain_nginx_configs(self):
        c = FakeSSH(routes=[('ls -1', '/etc/nginx/sites-enabled/example\n'),
                            ('grep -h', 'server_name example.com www.example.com;\n')])
        assert sorted(logs_mod.get_domains(c, 'none')) == ['example.com', 'www.example.com']

    def test_empty_when_nothing_found(self):
        assert logs_mod.get_domains(FakeSSH(), 'none') == []


class TestGetDomainsReason:
    """Почему доменов «нет»: прежний код `out, _ = checker.exec_command(
    f'ls -1 {pattern} 2>/dev/null | head -10')` выбрасывал в `_` ровно ту строку,
    где написана причина (нет прав на каталог vhost'ов / нет самого каталога).
    Оператор получал «Не удалось определить домены для проверки логов» и шёл
    искать другой домен, а не права.
    """

    def test_locked_conf_dir_is_not_reported_as_no_domains(self):
        c = FakeSSH(routes=[('ls -1', 'FFDIR noperm /etc/nginx/vhosts\nFFCOUNT 0\n')])
        info = logs_mod.get_domains_info(c, 'none')
        assert info['domains'] == []
        assert any('прав' in n for n in info['notes'])
        assert info['checked'] is True

    def test_missing_conf_dir_names_the_path(self):
        c = FakeSSH(routes=[('ls -1', 'FFDIR missing /etc/nginx/vhosts\nFFCOUNT 0\n')])
        info = logs_mod.get_domains_info(c, 'none')
        assert any('/etc/nginx/vhosts' in n for n in info['notes'])

    def test_verified_empty_dir_is_not_unchecked(self):
        # Каталог просмотрен и пуст — «доменов нет» честно, никакого «не
        # проверено» выдумывать нельзя.
        c = FakeSSH(routes=[('ls -1',
                             'FFDIR ok /etc/nginx/sites-enabled\nFFCOUNT 0\n')])
        info = logs_mod.get_domains_info(c, 'none')
        assert info['notes'] == [] and info['checked'] is True

    def test_no_answer_at_all_is_unchecked(self):
        info = logs_mod.get_domains_info(FakeSSH(), 'none')
        assert info['domains'] == [] and info['checked'] is False

    # ПЕРЕФОРМУЛИРОВАНО ОБЪЯВЛЕННО (урок 1.27.0): прежний роут
    # ('grep -h', 'example.com') описывал ответ, которого grep не выдаёт
    # никогда, — grep печатает СТРОКУ КОНФИГА ЦЕЛИКОМ, а имя домена извлекал
    # sed-пайп. Двойник отвечал «уже готовым доменом», поэтому под зелёными
    # тестами нельзя было ни починить пайп, ни заметить, что он теряет причины
    # пустоты. Язык системы восстановлен.
    def test_get_domains_stays_compatible(self):
        # Совместимость: публичная форма продолжает возвращать список доменов.
        c = FakeSSH(routes=[('ls -1', '/etc/nginx/sites-enabled/example\nFFCOUNT 1\n'),
                            ('grep -h', 'server_name example.com;\n')])
        assert logs_mod.get_domains(c, 'none') == ['example.com']

    def test_unreadable_config_reaches_domains_info(self):
        # Решающий случай слайса: каталог просмотрен, конфиг НАЙДЕН, но его
        # содержимое не прочитано. Прежний get_domains_info звал plain-форму
        # (только список) и докладывал «доменов нет» — оператор шёл менять
        # раскладку панели вместо того, чтобы поднимать права.
        c = FakeSSH(routes=[
            ('ls -1', '/etc/nginx/conf.d/site.conf\nFFCOUNT 1\n'),
            ('grep -h', ('', 'grep: /etc/nginx/conf.d/site.conf: '
                             'Permission denied', 2)),
        ])
        info = logs_mod.get_domains_info(c, 'none')
        assert info['domains'] == []
        assert info['checked'] is True
        assert any('прав' in n for n in info['notes'])
        assert 'нет на сервере' not in ''.join(info['notes'])

    def test_mgrctl_silence_is_told_not_hidden(self):
        # Панельный источник молчит (mgrctl нет/упал) — это надо сказать: иначе
        # «домены не найдены» означает «панель не ответила».
        c = FakeSSH(routes=[('mgrctl', ('', 'bash: mgrctl: command not found', 127))])
        info = logs_mod.get_domains_info(c, 'ispmanager')
        assert any('mgrctl' in n for n in info['notes'])

    def test_stderr_of_mgrctl_is_not_thrown_away(self):
        c = FakeSSH(routes=[('mgrctl', ('', 'x', 1))])
        logs_mod.get_domains_info(c, 'ispmanager')
        assert c.find('mgrctl') is not None
        assert '2>/dev/null' not in c.find('mgrctl')

    def test_ten_locked_configs_do_not_drown_the_report(self):
        # Решающий случай второй половины слайса. Первый GREEN донёс причину
        # до оператора — но ДЕСЯТЬЮ строками: по одной на каждый закрытый
        # конфиг (замер живьём). Признание, которого десять, обесценивается,
        # поэтому сводка обязана быть одна и назвать число файлов.
        paths = ['/etc/nginx/conf.d/site%d.conf' % i for i in range(10)]

        class TenLocked(FakeSSH):
            # ПЕРЕФОРМУЛИРОВАНО ОБЪЯВЛЕННО (слайс 1.32.0). Прежний перехват
            # «если в команде есть grep — ответить одной ошибкой» был честен,
            # пока чтение ходило по файлам. Как только пачка стала ОДНОЙ
            # маркерной командой, он глушил её целиком: пустой stdout при
            # непустом stderr — ответ, которого настоящая сводка не выдаёт
            # НИКОГДА (printf печатает маркеры при любом rc). Продукт правомерно
            # вернул «не проверено», а тест требовал «нет прав» и падал. Лечится
            # не продукт, а язык двойника: моделируется ответ ВНУТРЕННЕГО grep
            # на каждый путь, через общий хук раскрытия пачки (support.py).
            def _batch_row(self, path):
                return ('', 'grep: %s: Permission denied' % path, 2)

        c = TenLocked(routes=[('ls -1', '\n'.join(paths) + '\nFFCOUNT 10\n')])
        info = logs_mod.get_domains_info(c, 'none')
        assert info['domains'] == []
        assert info['checked'] is True
        assert len(info['notes']) == 1
        assert 'прав' in info['notes'][0]


# ========== СПИСОК ДОМЕНОВ НЕ ИМЕЕТ ПРАВА БЫТЬ ОБРЕЗАННЫМ МОЛЧА ==========
class TestDomainListNotSilentlyTruncated:
    """Главная ложь слайса 1.32.0 — измеренная, а не предположенная.

    Замер живьём (настоящий /bin/bash этого хоста, 40 реальных файлов):

        get_domains_info(...)  ->  в списке 10 доменов, на сервере их 40

    Признание о срезке существовало, но говорило про ФАЙЛЫ («Показаны первые
    10 файлов из 40: остальные в этом отчёте не участвовали»), а отчёт
    печатает заголовок «Найдены домены: …». Связку «файл -> домен» оператор
    не проходит: он читает заголовок как полный список и идёт искать
    пропавший сайт по другому основанию.

    Поднять лимит раньше было нельзя: чтение конфига стоило один SSH-раунд
    (замер: 10 файлов = 11 команд, 50 = 51, 200 = 201). После сводной команды
    этого же слайса пачка читается одной командой (замер: 200 путей = одна
    команда, 7.5 КБ, rc=0, stderr пуст) — только тогда срезку и перестали
    держать из-за цены.
    """

    @staticmethod
    def _paths(n):
        return ['/etc/nginx/conf.d/site%04d.conf' % i for i in range(n)]

    class Readable(FakeSSH):
        """Честный ответ системы: каждый конфиг читаем и несёт свой домен.

        FakeSSH не исполняет awk, поэтому срезку по L двойник эмулирует САМ.
        Без этого parse_find_answer получил бы все пути и total, равный их
        числу: срезки не существовало бы вовсе, и тест признания стал бы
        тривиально-зелёным (признание не родилось бы никогда).
        """

        LOGS_SEEN = ('FFDIR ok /var/log/nginx\nFFCOUNT 0\n')

        def _answer(self, cmd):
            # Логи — отдельным специфичным роутом (первое совпадение выигрывает):
            # иначе каталог логов ответил бы списком конфигей, а проверка
            # «признание о срезке дошло до отчёта» ловила бы вместо него
            # заметку «Логи … не проверено» и стала бы тривиально-зелёной.
            if '/var/log' in cmd:
                return (self.LOGS_SEEN, '', 0)
            if 'ls -1' in cmd and '-v L="' in cmd:
                out, err, rc = super()._answer(cmd)
                limit = int(cmd.partition('-v L="')[2].split('"', 1)[0])
                found = [ln for ln in out.splitlines() if ln.startswith('/')]
                kept = found[:limit] + ['FFCOUNT %d' % len(found)]
                return '\n'.join(kept) + '\n', err, rc
            return super()._answer(cmd)

        def _batch_row(self, path):
            # Ответ ВНУТРЕННЕГО grep (общий хук раскрытия пачки, support.py):
            # двойник обязан говорить языком системы, а не удобным выводом.
            return ('server_name %s;\n'
                    % path.rsplit('/', 1)[-1].replace('.conf', '.tld'),
                    '', 0)

    def _checker(self, n):
        return self.Readable(routes=[('ls -1', '\n'.join(self._paths(n)) +
                                      '\nFFCOUNT %d\n' % n)])

    def test_forty_configs_give_forty_domains_not_ten(self):
        # Решающий тест: найденное нельзя терять. Система ответила на все 40
        # конфигей — отчёт обязан называть 40 доменов, а не десять.
        info = logs_mod.get_domains_info(self._checker(40), 'none')
        assert len(info['domains']) == 40, (
            'оператор видит %d доменов при 40 конфигей на сервере'
            % len(info['domains']))
        assert info['notes'] == [], (
            'всё прочитано — признание о срезке выдумывать нельзя: %s'
            % info['notes'])

    def test_argv_flood_is_never_reported_as_no_domains(self):
        # Доменный уровень того же дефекта (1.32.3): примитив обязан довезти
        # признание до оператора. Замер живьём (20 000 конфигов, ulimit -s
        # 1024): боевая команда даёт rc=0, FFDIR ok, FFCOUNT 0, stderr
        # «Argument list too long»,rc ls = 126. Списков файлов мы НЕ получили,
        # а прежний отчёт говорил «доменов нет»: checked лепился на FFDIR ok,
        # не спрашивая, дошёл ли список.
        e2big = 'FFDIR ok /etc/nginx/conf.d\nFFRC 126\nFFCOUNT 0\n'
        c = FakeSSH(routes=[('ls -1',
                             (e2big,
                              '/bin/sh: line 1: /usr/bin/ls: Argument list '
                              'too long', 0))])
        info = logs_mod.get_domains_info(c, 'none')
        assert info['domains'] == []
        assert info['checked'] is False, (
            'список файлов не получен, а отчёт подписывает это «проверено»: %s'
            % info['notes'])
        assert any('слишком много' in n.lower() for n in info['notes']), (
            'пустота без объяснения: оператор прочитает её как «доменов нет»: %s'
            % info['notes'])

    def test_real_truncation_is_admitted_in_domain_language(self):
        # Парк больше лимита — срезка легитимна, но обязана быть названа на
        # языке ДОМЕНОВ: прежняя строка говорила про файлы, и оператор не
        # соотносил её со списком доменов под заголовком «Найдены домены».
        info = logs_mod.get_domains_info(self._checker(500), 'none')
        assert 0 < len(info['domains']) < 500
        assert len(info['notes']) == 1, (
            'один пробел не имеет права быть назван дважды: %s' % info['notes'])
        note = info['notes'][0]
        assert 'домен' in note, (
            'признание о срезке обязано говорить про домены: %r' % note)
        assert 'не провер' in note, (
            'срезанная часть не проверена — это обязано быть сказано: %r'
            % note)

    def test_price_does_not_grow_with_the_number_of_configs(self):
        # Замок цены (закрыт сводной командой выше по файлу, это НЕ RED).
        # Честность не имеет права дорожать линейно внутри самого поиска
        # доменов, иначе поднятие лимита запрещено фактом цены — круг
        # замкнётся (именно так и было до сводной команды).
        small = self._checker(10)
        logs_mod.get_domains_info(small, 'none')
        big = self._checker(400)
        logs_mod.get_domains_info(big, 'none')
        assert len(big.commands) == len(small.commands), (
            'поиск доменов дорожает с числом конфигей: %d против %d'
            % (len(big.commands), len(small.commands)))

    def test_truncation_note_needs_a_real_truncation(self):
        # Инвертированный контроль: каталог просмотрен и пуст — «доменов нет»
        # честно, признания о срезке быть не должно (закон серии: признание
        # нужно только на пробел).
        c = FakeSSH(routes=[('ls -1',
                             'FFDIR ok /etc/nginx/conf.d\nFFCOUNT 0\n')])
        info = logs_mod.get_domains_info(c, 'none')
        assert info['domains'] == [] and info['checked'] is True
        assert info['notes'] == []

    def test_incomplete_list_is_told_in_the_report(self):
        # Признание обязано доходить до оператора, а не жить только в dict:
        # site_logs_report печатает заголовок «Найдены домены: …» и обязан
        # сказать, что список неполный. Логи при этом ЗАКРЫТЫ ОТДЕЛЬНЫМ
        # честным роутом (каталог просмотрен и пуст), поэтому фраза
        # «не провер» во выводе может прийти только из признания о срезке.
        out = logs_mod.site_logs_report(self._checker(500), 'none')
        assert 'Найдены домены' in out
        assert 'не провер' in out, (
            'отчёт обрезал список доменов молча: %r' % out[:400])


# ==================== ошибки в логах сайтов ====================
class TestSiteLogs:
    LOGS = ('2026/10/10 13:00:01 [error] 123#0: *1 open() failed\n'
            '2026/10/10 13:00:02 [notice] worker process started\n')

    def test_collects_error_lines_per_domain(self):
        c = FakeSSH(routes=[('ls -1', '/var/log/nginx/example.com.error.log\n'),
                            ('grep -h', 'server_name example.com;\n'),
                            ('cat ', self.LOGS)])
        res = logs_mod.check_site_logs(c, 'none', ['example.com'])
        assert 'example.com' in res
        assert '[error]' in res['example.com']
        assert 'notice' not in res['example.com']

    def test_clean_logs_give_no_entries(self):
        c = FakeSSH(routes=[('ls -1', '/var/log/nginx/example.com.error.log\n'),
                            ('cat ', 'everything is fine\n')])
        assert logs_mod.check_site_logs(c, 'none', ['example.com']) == {}

    def test_report_with_domains(self):
        c = FakeSSH(routes=[('ls -1', '/var/log/nginx/example.com.error.log\n'),
                            ('grep -h', 'server_name example.com;\n'),
                            ('cat ', self.LOGS)])
        out = logs_mod.site_logs_report(c, 'none')
        assert 'Найдены домены: example.com' in out
        assert '[error]' in out

    # ПЕРЕФОРМУЛИРОВАНО ОБЪЯВЛЕННО (тот же закон, что в 1.20.0): прежний тест
    # записывал «Не удалось определить домены» на ПУСТОЙ ответ сервера, т.е.
    # «мы ничего не узнали» было заперто как «доменов нет». Теперь утверждение
    # про отсутствие доменов заперто на ПРОСМОТРЕННОМ пустом каталоге, а
    # неподтверждённый ответ — отдельным тестом ниже.
    def test_report_without_domains(self):
        c = FakeSSH(routes=[('ls -1', 'FFDIR ok /etc/nginx/sites-enabled\nFFCOUNT 0\n')])
        out = logs_mod.site_logs_report(c, 'none')
        assert 'Не удалось определить домены' in out
        assert 'не проверено' not in out

    def test_report_unconfirmed_dirs_is_not_no_domains(self):
        out = logs_mod.site_logs_report(FakeSSH(), 'none')
        assert 'не проверено' in out
        assert 'Не удалось определить домены' not in out

    # ПЕРЕФОРМУЛИРОВАНО ОБЪЯВЛЕННО: «Ошибок не обнаружено» было заперто на
    # ответе, в котором каталог логов НЕ подтверждён (нет FFCOUNT/FFDIR) — т.е.
    # «мы не смотрели» было заперто как «чисто». Ответ с подтверждённым
    # просмотром остаётся запертым строго как раньше.
    def test_report_when_logs_clean(self):
        c = FakeSSH(routes=[('ls -1',
                             '/var/log/nginx/example.com.error.log\nFFCOUNT 1\n'),
                            ('grep -h', 'server_name example.com;\n'),
                            ('cat ', 'everything is fine\n')])
        out = logs_mod.site_logs_report(c, 'none')
        assert 'Ошибок' in out and 'не обнаружено' in out
        assert 'не просмотрена' not in out

    # --- нечитаемый лог не имеет права называться «чисто» ---

    # 'grep -h' — это чтение конфига в get_domains_info: без него домен не
    # определился бы и отчёт встал бы на «домены не определены», не дойдя до
    # логов (проверено прогоном: проверка «не просмотрен» тогда ничего не
    # проверяла). Ответ — СТРОКА КОНФИГА, а не готовый домен (язык системы).
    UNREADABLE = [('ls -1', '/var/log/nginx/example.com.error.log\nFFCOUNT 1\n'),
                  ('grep -h', 'server_name example.com;\n'),
                  ('RFSTATE', ('RFSTATE unreadable\n', 'cat: Permission denied', 1))]

    def test_unreadable_logs_are_not_called_clean(self):
        c = FakeSSH(routes=list(self.UNREADABLE))
        info = logs_mod.check_site_logs_info(c, 'none', ['example.com'])
        assert info['errors'] == {}
        assert info['unread'] and 'example.com.error.log' in info['unread'][0]
        assert 'прав' in info['unread'][0]

    def test_check_site_logs_compat_stays_a_dict(self):
        c = FakeSSH(routes=list(self.UNREADABLE))
        assert logs_mod.check_site_logs(c, 'none', ['example.com']) == {}

    def test_report_says_logs_were_not_viewed(self):
        # Решающий случай слайса: раньше отчёт говорил «Ошибок в логах сайтов не
        # обнаружено», хотя ни один лог не был прочитан.
        c = FakeSSH(routes=list(self.UNREADABLE))
        out = logs_mod.site_logs_report(c, 'none')
        assert 'не просмотрен' in out
        assert 'прав' in out
        assert 'не обнаружено' not in out

    def test_partially_read_logs_say_what_was_missed(self):
        # Один лог прочитан, второй закрыт: найденное терять нельзя, но и
        # объявлять проверку полной нельзя.
        c = FakeSSH(routes=[('ls -1', '/var/log/nginx/a.error.log\n'
                                      '/var/log/nginx/b.error.log\nFFCOUNT 2\n'),
                            ('a.error.log', ('RFSTATE readable\nboom: fatal error\n',
                                             '', 0)),
                            ('b.error.log', ('RFSTATE unreadable\n',
                                             'cat: Permission denied', 1)),
                            ('RFSTATE', ('RFSTATE unreadable\n',
                                         'cat: Permission denied', 1))])
        info = logs_mod.check_site_logs_info(c, 'none', ['example.com'])
        assert 'fatal error' in info['errors'].get('example.com', '')
        assert info['unread'] and 'b.error.log' in info['unread'][0]
        assert 'a.error.log' not in info['unread'][0]


# ==================== OOM ====================
class TestSearchOom:
    """Прежний вид (logs.py):

        cmd = "zgrep -B 5 -A 5 -i '...' /var/log/kern.log* /var/log/syslog* 2>/dev/null"
        out, _, _ = checker.run(cmd)          # rc принят и выброшен
        if not out.strip():
            return "OOM-событий в логах не найдено."

    Замерено живьём (uid=1000, продуктовый BRE-шаблон, bash и dash — одинаково):

        oom.log       rc=0  out_len=73   err=''            события ЕСТЬ
        kern.log      rc=1  out_len=0    err=''            прочитан, совпадений нет
        locked.log    rc=2  out_len=0    err=gzip: …: Permission denied
        nothere*.log  rc=2  out_len=0    err=gzip: …: No such file or directory
        bad.log.gz    rc=1  out_len=0    err=''            ← НЕ отличим от «чисто»

    То есть «OOM-событий не найдено» печаталось и когда лог не читался под этим
    UID, и когда /var/log/syslog* не существует (systemd-journal вместо syslog —
    типичная Ubuntu 22.04+), и когда ротированный архив битый. Битый .gz худший:
    zgrep на нём молчит с rc=1, поэтому различает только отдельная проверка
    архива (gzip -t) — её и запираем.
    """

    @staticmethod
    def _ans(stat, body='', unread=(), badgz=()):
        """Служебный блок (до OOMEND) + тело zgrep — как в команде продукта."""
        head = ['OOMSTAT ' + stat]
        head += [f'OOMUNREAD {p}' for p in unread]
        head += [f'OOMBADGZ {p}' for p in badgz]
        return '\n'.join(head + ['OOMEND']) + '\n' + body

    def test_blocks_split_by_separator(self):
        out = ('invoked oom-killer\nKilled process 999\n'
               '--\nanother oom-killer event\n')
        c = FakeSSH(routes=[('zgrep', self._ans('1 0 0', out))])
        rep = logs_mod.search_oom_logs(c)
        assert 'Событие #1' in rep and 'Событие #2' in rep
        assert 'Killed process 999' in rep
        # разделитель zgrep ('--') не должен остаться отдельной строкой отчёта
        # (заголовки вида '--- Событие #1 ---' сюда не попадают)
        assert '--' not in [line.strip() for line in rep.splitlines()]
        # служебные маркеры оператору не показываются
        assert 'OOMSTAT' not in rep and 'OOMEND' not in rep

    # ПЕРЕФОРМУЛИРОВАНО ОБЪЯВЛЕННО (тот же закон, что 1.20.0/1.21.0): прежний
    # тест запирал ПУСТОЙ ответ сервера как «OOM-событий не найдено», т.е. «мы
    # ничего не узнали» было заперто как «событий нет». Теперь «не найдено»
    # заперто на подтверждённом просмотре, а неподтверждённый ответ — отдельный
    # тест ниже.
    def test_no_events(self):
        c = FakeSSH(routes=[('zgrep', self._ans('2 0 0'))])
        rep = logs_mod.search_oom_logs(c)
        assert rep == 'OOM-событий в логах не найдено.'

    def test_only_separators(self):
        c = FakeSSH(routes=[('zgrep', '--\n--\n')])
        assert 'OOM-событий не обнаружено' in logs_mod.search_oom_logs(c)

    def test_unconfirmed_answer_is_not_no_events(self):
        # Ни маркеров, ни тела: обрыв/отмена — это «не проверено».
        rep = logs_mod.search_oom_logs(FakeSSH())
        assert 'не проверено' in rep
        assert 'не найдено' not in rep

    def test_locked_log_is_not_called_no_oom(self):
        # Решающий случай: логи есть, но под этим UID не читаются. Прежний ответ
        # был неотличим от «событий нет» — оператор шёл искать причину в памяти,
        # а не в правах.
        c = FakeSSH(routes=[('zgrep', (
            self._ans('2 1 0', unread=['/var/log/syslog']),
            'gzip: /var/log/syslog: Permission denied', 2))])
        rep = logs_mod.search_oom_logs(c)
        assert 'прав' in rep
        assert 'не найдено' not in rep
        assert '/var/log/syslog' in rep

    def test_partly_readable_logs_are_not_called_full_check(self):
        # Один лог прочитан, второй закрыт: найденное терять нельзя, но и
        # объявлять проверку полной нельзя.
        c = FakeSSH(routes=[('zgrep', (
            self._ans('2 1 0', 'oom-killer: gfp_mask=0x1\n',
                     unread=['/var/log/syslog']),
            'gzip: /var/log/syslog: Permission denied', 2))])
        rep = logs_mod.search_oom_logs(c)
        assert 'Событие #1' in rep
        assert 'не просмотрена' in rep and '/var/log/syslog' in rep

    def test_missing_kernel_logs_points_to_journal_not_to_no_oom(self):
        # Типичная Ubuntu 22.04+/Debian 12+: /var/log/kern.log* и syslog* нет,
        # ядро пишет в journald. «Событий не было» здесь — ложь: мы не смотрели.
        c = FakeSSH(routes=[('zgrep', (
            self._ans('0 0 0'),
            'gzip: /var/log/kern.log*.gz: No such file or directory', 2))])
        rep = logs_mod.search_oom_logs(c)
        assert 'journalctl' in rep
        assert '/var/log/kern.log*' in rep
        assert 'не найдено' not in rep

    def test_broken_gz_is_told_and_not_silence(self):
        # Замер: zgrep на битом .gz молчит с rc=1 — без отдельной проверки
        # архива он неотличим от «прочитано, совпадений нет».
        c = FakeSSH(routes=[('zgrep', (
            self._ans('2 0 1', badgz=['/var/log/syslog.2.gz']),
            'gzip: /var/log/syslog.2.gz: not in gzip format', 1))])
        rep = logs_mod.search_oom_logs(c)
        assert '/var/log/syslog.2.gz' in rep
        assert 'gzip' in rep
        assert rep.splitlines()[0].startswith('❌')

    def test_answer_without_markers_still_parsed_when_body_present(self):
        # Совместимость (тот же приём, что read_file_info): ответ от прежней/
        # чужой команды без маркеров разбирается как раньше, а не выбрасывается.
        c = FakeSSH(routes=[('zgrep', 'invoked oom-killer\nKilled process 7\n')])
        rep = logs_mod.search_oom_logs(c)
        assert 'Событие #1' in rep and 'Killed process 7' in rep

    def test_log_content_cannot_spoof_service_markers(self):
        # Содержимое лога идёт ПОСЛЕ границы OOMEND: строки «OOMSTAT …» внутри
        # лога не имеют права менять состояние отчёта (замер со spoof.log).
        body = ('oom-killer: gfp_mask=0x1\n'
                'OOMSTAT 99 99 99\n'
                'OOMUNREAD /var/log/fake.log\n')
        c = FakeSSH(routes=[('zgrep', self._ans('1 0 0', body))])
        info = logs_mod.search_oom_info(c)
        assert info['unread'] == [] and info['badgz'] == []
        assert info['files_seen'] == 1

    def test_search_oom_info_shape(self):
        c = FakeSSH(routes=[('zgrep', self._ans('3 1 1', unread=['/a'],
                                                badgz=['/b.gz']))])
        info = logs_mod.search_oom_info(c)
        assert info['files_seen'] == 3
        assert info['unread'] == ['/a'] and info['badgz'] == ['/b.gz']
        assert info['checked'] is True and info['events'] == []

    def test_search_oom_logs_compat_is_a_string(self):
        c = FakeSSH(routes=[('zgrep', self._ans('2 0 0'))])
        assert isinstance(logs_mod.search_oom_logs(c), str)

    def test_file_list_in_report_is_the_single_source(self):
        # Пути логов были записаны дважды (в команде и в строке «Файлы: …») —
        # разъехавшийся дубль обещает отчёт про одни файлы при поиске в других.
        # Заперто на прогоне С событиями: именно тогда строка «Файлы: …» едет в
        # отчёт (без событий отчёт остаётся короткой честной строкой).
        c = FakeSSH(routes=[('zgrep', self._ans('2 0 0',
                                                'oom-killer: gfp_mask=0x1\n'))])
        rep = logs_mod.search_oom_logs(c)
        assert 'Файлы:' in rep
        for glob in logs_mod.OOM_GLOBS:
            assert glob in rep
            assert glob in c.find('zgrep')
        # один источник: «Файлы:» перечисляет ровно то, что ушло в команду
        assert rep.split('Файлы:')[1].splitlines()[0].strip(
            ' ,') == ', '.join(logs_mod.OOM_GLOBS)

    # ---------- замки по ОТПРАВЛЕННОЙ команде ----------

    def test_sent_command_keeps_stderr_and_honest_limits(self):
        c = FakeSSH(routes=[('zgrep', self._ans('1 0 0'))])
        logs_mod.search_oom_logs(c)
        cmd = c.find('zgrep')
        assert cmd is not None
        assert '2>/dev/null' not in cmd        # терял Permission denied / not in gzip
        assert 'head -' not in cmd             # резал бы блоки молча
        assert 'PIPESTATUS' not in cmd         # dash: «Bad substitution»
        # Замок инъекции: подстановки команды быть не должно. НЕ `'(' not in
        # cmd`: `$((n+1))` — POSIX-арифметика, а не command substitution, и
        # прежняя формулировка запрещала бы сам подсчёт файлов (моя ошибка в
        # этом guard'e, найдена прогоном, а не рассуждением).
        assert '`' not in cmd
        assert '$(' not in cmd.replace('$((', '')
        assert len(c.commands) == 1            # цена не выросла

    def test_archive_check_reports_its_own_error(self):
        # `gzip -t … 2>/dev/null` оставил бы битый архив без объяснения —
        # ответ системы обязан дойти (тот же закон, что для zgrep).
        c = FakeSSH(routes=[('zgrep', self._ans('1 0 1', badgz=['/x.gz']))])
        logs_mod.search_oom_logs(c)
        cmd = c.find('gzip -t')
        assert cmd is not None
        assert 'gzip -t' in cmd and '2>/dev/null' not in cmd.split('gzip -t', 1)[1][:40]


# ==================== почтовый лог: выбор файла ====================
# Выбор «первого непустого файла» — это цикл в shell, и FakeSSH проверить его
# не может: заглушка отвечает на команду целиком и не исполняет её. Здесь
# команды гоняются НАСТОЯЩИМ bash'ем по временным файлам. Именно в этом цикле
# живёт грабель, из-за которого проект годами не видел почту на Debian: пустой
# (ротированный) maillog обрывал цепочку, и /var/log/mail.log не спрашивался.
def _sh(cmd):
    return subprocess.run(['bash', '-c', cmd], capture_output=True, text=True)


class TestMailLogFileSelection:
    def test_empty_rotated_maillog_does_not_kill_mail_log(self, tmp_path):
        empty = tmp_path / 'maillog'
        empty.write_text('')                       # ротирован и пока пуст
        live = tmp_path / 'mail.log'
        live.write_text('AAA: to=<a@b.ru>, status=sent (250 Ok)\n')
        out = _sh(logs_mod.mail_log_files_command(
            15, paths=(str(empty), str(live))))
        assert out.returncode == 0
        text, src = logs_mod.parse_mail_log_output(out.stdout)
        assert text == 'AAA: to=<a@b.ru>, status=sent (250 Ok)'
        assert src == str(live)                    # источник назван честно

    def test_absent_first_path_still_reaches_the_second(self, tmp_path):
        live = tmp_path / 'mail.log'
        live.write_text('AAA: status=sent (250 Ok)\n')
        out = _sh(logs_mod.mail_log_files_command(
            15, paths=(str(tmp_path / 'nope'), str(live))))
        text, src = logs_mod.parse_mail_log_output(out.stdout)
        assert text and src == str(live)

    def test_both_dead_yields_empty_not_a_lie(self, tmp_path):
        # Пустой вывод = «лог не найден» (вызывающий код обязан сказать «не
        # проверено»), а не «писем не было».
        out = _sh(logs_mod.mail_log_files_command(
            15, paths=(str(tmp_path / 'nope'), str(tmp_path / 'nope2'))))
        assert out.returncode == 0 and out.stdout == ''

    def test_grep_reaches_the_second_file(self, tmp_path):
        empty = tmp_path / 'maillog'
        empty.write_text('')
        live = tmp_path / 'mail.log'
        live.write_text('A: to=<x@b.ru>, status=sent (ok)\n'
                        'B: to=<y@b.ru>, status=bounced (spam)\n')
        out = _sh(logs_mod.mail_log_grep_command(
            'status=bounced', 50, 3, paths=(str(empty), str(live))))
        text, src = logs_mod.parse_mail_log_output(out.stdout)
        assert 'status=bounced' in text and 'status=sent' not in text
        assert src == str(live)

    def test_tail_limits_the_window(self, tmp_path):
        big = tmp_path / 'mail.log'
        big.write_text(''.join(f'l{i} status=sent (ok)\n' for i in range(1000)))
        out = _sh(logs_mod.mail_log_files_command(3, paths=(str(big),)))
        lines = out.stdout.splitlines()
        assert lines[0].startswith(logs_mod.MAIL_LOG_MARK)
        assert [l.split()[0] for l in lines[1:]] == ['l997', 'l998', 'l999']

    def test_quote_in_path_stays_one_argument(self, tmp_path):
        # Путь попадает в команду через q(); проверка на `[ -s ]` обязана видеть
        # ОДИН аргумент, иначе имя файла с `$()` выполнилось бы на сервере.
        evil = tmp_path / 'ev; $(id).log'
        evil.write_text('AAA: status=sent (ok)\n')
        out = _sh(logs_mod.mail_log_files_command(15, paths=(str(evil),)))
        assert 'uid=' not in out.stdout + out.stderr
        text, src = logs_mod.parse_mail_log_output(out.stdout)
        assert text == 'AAA: status=sent (ok)' and src == str(evil)

    @pytest.mark.parametrize('builder', ['files', 'grep'])
    def test_commands_are_valid_shell(self, builder):
        cmd = (logs_mod.mail_log_files_command(15) if builder == 'files'
               else logs_mod.mail_log_grep_command("to<'a\"@b.ru>", 50, 3))
        proc = subprocess.run(['bash', '-n', '-c', cmd],
                              capture_output=True, text=True)
        assert proc.returncode == 0, proc.stderr
        assert '/var/log/maillog' in cmd and '/var/log/mail.log' in cmd


# ==================== чтение почтового лога (FakeSSH) ====================
class TestReadMailLog:
    def test_first_file_wins_and_source_is_named(self):
        c = FakeSSH(routes=[('for __p in', '#LOG /var/log/maillog\nX status=sent\n')])
        assert logs_mod.read_mail_log(c) == ('X status=sent', '/var/log/maillog')

    def test_debian_path_is_read_at_all(self):
        # Раньше этот путь не читался нигде в проекте — на Debian отчёт о почте
        # был слеп.
        c = FakeSSH(routes=[('for __p in',
                             '#LOG /var/log/mail.log\nY status=bounced\n')])
        text, src = logs_mod.read_mail_log(c)
        assert (text, src) == ('Y status=bounced', '/var/log/mail.log')

    def test_journal_fallback_when_files_are_empty(self):
        c = FakeSSH(routes=[('for __p in', ''),
                            ('journalctl', 'host postfix/master: daemon started')])
        text, src = logs_mod.read_mail_log(c)
        assert text == 'host postfix/master: daemon started'
        assert src == 'journalctl -u postfix'

    def test_no_entries_marker_is_not_a_log(self):
        # journalctl при пустом журнале печатает '-- No entries --', и прежний
        # код postfix-отчёта показывал её оператору как содержимое лога.
        c = FakeSSH(routes=[('for __p in', ''),
                            ('journalctl', '-- No entries --\n')])
        assert logs_mod.read_mail_log(c) == ('', '')

    def test_everything_dead_is_not_reported_as_no_mail(self):
        assert logs_mod.read_mail_log(FakeSSH()) == ('', '')

    def test_source_is_always_named_when_there_is_text(self):
        # Вывод без маркера (старая обвязка, тестовые заглушки) не должен дать
        # заголовок «---  (последние 15 строк) ---» с пустым источником.
        c = FakeSSH(routes=[('for __p in', 'X status=sent\n')])
        assert logs_mod.read_mail_log(c) == ('X status=sent', 'лог почты')

    def test_grep_filters_journal_too(self):
        c = FakeSSH(routes=[('for __p in', ''),
                            ('journalctl', 'A to=<x@b.ru> status=sent\nB noise\n')])
        text, src = logs_mod.read_mail_log(c, tail=50, grep='to=<x@b.ru>')
        assert text == 'A to=<x@b.ru> status=sent' and 'journalctl' in src

    def test_cost_is_one_command_per_read(self):
        c = FakeSSH(routes=[('for __p in', '#LOG /var/log/maillog\nX\n')])
        logs_mod.read_mail_log(c)
        assert c.count('for __p in') == 1
        assert c.count('journalctl') == 0          # живой файл — журнал не трогаем


# ==================== разбор строк доставки postfix ====================
# Строки взяты живыми: `status=` печатает сам postfix, текст в скобках — дословно
# ответ приёмника. Именно эта пара связывает «SPF нет» с «письмо отбили».
SENT = ('Oct 10 12:00:01 host postfix/smtp[123]: AAA1: to=<a@b.ru>, '
        'relay=mx.b.ru[1.2.3.4]:25, delay=1.1, dsn=2.0.0, status=sent (250 2.0.0 Ok)')
GMAIL_SPAM = ('Oct 10 12:00:05 host postfix/smtp[124]: AAA2: to=<c@gmail.com>, '
              'relay=gmail-smtp-in.l.google.com[142.251.8.27]:25, dsn=5.7.26, '
              'status=bounced (gmail-smtp-in.l.google.com[142.251.8.27] said: '
              '550-5.7.26 [203.0.113.9] unauthenticated mail was rejected, '
              'please learn about SPF) 19-20020a05 gsmtp')
DNS_DEFER = ('Oct 10 12:00:07 host postfix/smtp[125]: AAA3: to=<d@nowhere.tld>, '
             'relay=none, dsn=4.4.3, status=deferred (Host or domain name not '
             'found. Name service error for name=nowhere.tld type=MX)')
NO_SUCH_USER = ('Oct 10 12:00:09 host postfix/smtp[126]: AAA4: to=<e@dead.ru>, '
                'relay=none, dsn=5.1.1, status=bounced (User unknown)')
BUSY = ('Oct 10 12:00:11 host postfix/smtp[127]: AAA5: to=<f@busy.ru>, '
        'relay=mx.busy.ru[5.6.7.8]:25, dsn=4.5.0, status=deferred (451 4.7.1 '
        '<5.6.7.8>: Rate limit exceeded, try again later)')
RELAY_DENIED = ('Oct 10 12:00:14 host postfix/smtp[128]: AAA8: to=<h@x.ru>, '
                'relay=smtp.x.ru[9.9.9.9]:25, dsn=5.7.60, status=bounced '
                '(Relay access denied)')
CONN_TIMEOUT = ('Oct 10 12:00:15 host postfix/smtp[129]: AAA9: to=<i@y.ru>, '
                'relay=none, dsn=4.4.1, status=deferred (connect to '
                'mx.y.ru[8.8.8.8]:25: Connection timed out)')
EXPIRED = ('Oct 10 12:00:16 host postfix/smtp[130]: AAB0: to=<j@z.ru>, '
           'relay=none, dsn=4.4.2, status=expired (Delivery to the following '
           'recipient timed out)')
# Строки, которые доставкой НЕ являются: postfix пишет в один лог и запуск
# демонов, и connect/disconnect. Посчитать их отказами — значит нарисовать
# проблему там, где её нет.
NOT_DELIVERY = ('Oct 10 12:00:00 host postfix/master[1]: daemon started -- '
                'version 3.5.6',
                'Oct 10 12:00:02 host postfix/smtpd[9]: connect from unknown[203.0.113.5]',
                'Oct 10 12:00:12 host postfix/cleanup[7]: AAA6: message-id=<x@y>',
                '')
UNKNOWN_STATUS = ('Oct 10 12:00:13 host postfix/dovecot-lmtp[8]: AAA7: '
                  'to=<g@x.ru>, relay=dovecot-lmtp, status=dlivered (weird)')


class TestParseDeliveryEntry:
    def test_fields_are_named_not_positional(self):
        e = logs_mod.parse_delivery_entry(SENT)
        assert e['status'] == 'sent' and e['to'] == 'a@b.ru'
        assert e['relay'] == 'mx.b.ru[1.2.3.4]:25' and e['dsn'] == '2.0.0'
        assert e['reason'] == '250 2.0.0 Ok'

    @pytest.mark.parametrize('line', NOT_DELIVERY)
    def test_lines_that_are_not_delivery_give_none(self, line):
        assert logs_mod.parse_delivery_entry(line) is None

    def test_unknown_status_is_kept_not_renamed(self):
        # Переименовать незнакомый status в «bounced» — значит соврать про отказ.
        assert logs_mod.parse_delivery_entry(UNKNOWN_STATUS)['status'] == 'dlivered'

    def test_entry_without_status_field_is_none(self):
        assert logs_mod.parse_delivery_entry('to=<a@b.ru>, relay=none') is None


class TestSummarizeAndClassify:
    def test_counts_split_known_and_unknown(self):
        entries = [logs_mod.parse_delivery_entry(l) for l in
                   (SENT, GMAIL_SPAM, DNS_DEFER, UNKNOWN_STATUS)]
        counts = logs_mod.summarize_deliveries(entries)
        assert counts['sent'] == 1 and counts['bounced'] == 1
        assert counts['deferred'] == 1 and counts['expired'] == 0
        assert counts['other'] == 1                # незнакомый — в 'other'

    def test_gmail_spam_rejection_is_classified(self):
        # Ровно тот тикет, ради которого снимок затеян: Gmail пишет причину прямо
        # в отказе, и без игл spf/unauthenticated он остался бы без подсказки.
        e = logs_mod.parse_delivery_entry(GMAIL_SPAM)
        hint = logs_mod.mail_failure_hint(e['reason'])
        assert hint and hint[0] == logs_mod.SPAM_GROUP_LABEL

    @pytest.mark.parametrize('line,label', [
        (GMAIL_SPAM, 'спам или блокировка репутации'),
        (DNS_DEFER, 'DNS домена получателя'),
        (CONN_TIMEOUT, 'нет соединения с портом 25'),
        (RELAY_DENIED, 'отказ в релее / нужна авторизация'),
        (NO_SUCH_USER, 'адресата нет'),
        (BUSY, 'сервер загружен / временный отказ'),
    ])
    def test_each_real_failure_lands_in_its_group(self, line, label):
        e = logs_mod.parse_delivery_entry(line)
        assert logs_mod.mail_failure_hint(e['reason'])[0] == label

    def test_unclassifiable_reason_is_not_invented(self):
        assert logs_mod.mail_failure_hint('что-то совсем непонятное') is None

    def test_classify_line_carries_status_dsn_and_reason(self):
        _i, line, hint = logs_mod.classify_delivery(
            logs_mod.parse_delivery_entry(NO_SUCH_USER))
        assert line.startswith('❌ e@dead.ru — отбито') and 'dsn=5.1.1' in line
        assert hint[0] == 'адресата нет'

    def test_unknown_status_gets_no_icon_and_no_verdict(self):
        icon, line, hint = logs_mod.classify_delivery(
            logs_mod.parse_delivery_entry(UNKNOWN_STATUS))
        assert icon == 'ℹ️' and 'dlivered' in line
        assert not line.startswith(('✅', '❌', '⚠️'))

    def test_dsn_4xx_explains_retry_even_without_a_keyword(self):
        # Код DSN, а не текст, решает «повторять или сдаваться».
        line = ('postfix/smtp[1]: X: to=<q@w.ru>, relay=none, dsn=4.9.9, '
                'status=deferred (неизвестный текст беды)')
        _i, _l, hint = logs_mod.classify_delivery(logs_mod.parse_delivery_entry(line))
        assert hint and '4xx' in hint[0] and 'maximal_queue_lifetime' in hint[1]

    def test_domain_of_recipient(self):
        assert logs_mod.delivery_domain_of(
            logs_mod.parse_delivery_entry(GMAIL_SPAM)) == 'gmail.com'
        assert logs_mod.delivery_domain_of({'to': ''}) == ''

    def test_failure_groups_ignore_unknown_status_and_success(self):
        # Неизвестный status — не отказ: приписать причину несуществующей беде
        # нельзя (тот же закон «не проверено ≠ провалено»).
        entries = [logs_mod.parse_delivery_entry(l) for l in
                   (SENT, GMAIL_SPAM, NO_SUCH_USER, UNKNOWN_STATUS)]
        groups = logs_mod.delivery_failure_groups(entries)
        assert groups[logs_mod.SPAM_GROUP_LABEL] == 1
        assert groups['адресата нет'] == 1
        assert sum(groups.values()) == 2


# ==================== снимок доставки (в почтовой сводке) ====================
def _log_routes(*lines):
    return [('for __p in', '#LOG /var/log/mail.log\n' + '\n'.join(lines) + '\n')]


class TestMailLogSnapshot:
    def test_missing_log_is_not_reported_as_no_failures(self):
        out = logs_mod.mail_log_snapshot_lines(FakeSSH())
        text = '\n'.join(out)
        assert 'лог не найден' in text and 'ls -l /var/log/mail*' in text
        assert '✅' not in text

    def test_only_noise_lines_says_no_delivery_records(self):
        out = '\n'.join(logs_mod.mail_log_snapshot_lines(
            FakeSSH(routes=_log_routes(NOT_DELIVERY[0]))))
        assert 'Записей о доставке' in out and 'не равно' not in out
        assert '✅' not in out

    def test_failures_are_listed_with_actions(self):
        out = '\n'.join(logs_mod.mail_log_snapshot_lines(
            FakeSSH(routes=_log_routes(SENT, GMAIL_SPAM, NO_SUCH_USER))))
        assert 'отбито: 2' in out and 'ушло: 1' in out
        assert 'спам или блокировка репутации' in out
        assert 'gmail.com' in out and 'dead.ru' in out
        assert 'SPF/DKIM/DMARC/PTR' in out        # куда идти дальше

    def test_clean_window_denies_the_false_conclusion(self):
        # «Отказов нет» читается как «чинить нечего», а приёмник, режущий спам,
        # письмо НЕ отбивает — в нашем логе такой беды не видно вовсе.
        out = '\n'.join(logs_mod.mail_log_snapshot_lines(
            FakeSSH(routes=_log_routes(SENT))))
        assert '✅ Отказов нет' in out
        # Само по себе «отказов нет» обязан быть подписан границей окна: иначе
        # оператор прочитает его как «чинить нечего».
        assert 'окно лога, а не гарантия' in out

    def test_unknown_status_is_not_counted_as_failure(self):
        out = '\n'.join(logs_mod.mail_log_snapshot_lines(
            FakeSSH(routes=_log_routes(UNKNOWN_STATUS))))
        assert 'без знакомого status: 1' in out
        # Неизвестный статус — не отказ: снимок обязан сказать «отказов нет», а
        # не рисовать ❌ на строке, статус которой мы не знаем.
        assert '❌' not in out and 'Отказов нет' in out

    def test_long_failure_list_is_counted_not_dumped(self):
        # 4000 строк лога в окне GUI означают «не показано ни одной».
        lines = _log_routes(*([GMAIL_SPAM] * 20))
        out = logs_mod.mail_log_snapshot_lines(FakeSSH(routes=lines), limit=8)
        shown = [l for l in out if '↳' in l]
        assert len(shown) == 8
        assert 'скрыто отказов — 12' in '\n'.join(out)

    def test_cost_is_one_read_of_the_log(self):
        c = FakeSSH(routes=_log_routes(SENT))
        logs_mod.mail_log_snapshot_lines(c)
        assert c.count('for __p in') == 1


# ==================== дайджест доставки (в SPF-отчёте) ====================
class TestMailDeliveryDigest:
    def test_spam_refusals_confirm_the_dns_verdict(self):
        out = '\n'.join(logs_mod.mail_delivery_digest_lines(
            FakeSSH(routes=_log_routes(SENT, GMAIL_SPAM, GMAIL_SPAM))))
        assert 'отбито: 2' in out
        assert 'спам или блокировка репутации — 2' in out
        assert 'DNS-беда уже ломает доставку' in out

    def test_missing_log_is_neither_ok_nor_broken(self):
        out = '\n'.join(logs_mod.mail_delivery_digest_lines(FakeSSH()))
        assert 'не найден' in out and 'не проверено' in out
        assert '✅' not in out

    def test_no_delivery_records_is_not_clean(self):
        out = '\n'.join(logs_mod.mail_delivery_digest_lines(
            FakeSSH(routes=_log_routes(NOT_DELIVERY[0]))))
        assert 'подтверждать связку нечем' in out and 'не равно' in out

    def test_without_spam_refusals_dns_is_not_exonerated(self):
        # Написать «значит SPF ни при чём» было бы ложью: молча уехавшее в спам
        # письмо приёмник принимает с 250 Ok.
        out = '\n'.join(logs_mod.mail_delivery_digest_lines(
            FakeSSH(routes=_log_routes(SENT, DNS_DEFER))))
        assert 'отношения не имеют' in out
        assert '250 Ok' in out and 'не оправдание пустой зоны' in out

    def test_expires_and_bounces_are_counted(self):
        out = '\n'.join(logs_mod.mail_delivery_digest_lines(
            FakeSSH(routes=_log_routes(EXPIRED, NO_SUCH_USER))))
        assert 'истекло: 1' in out and 'отбито: 1' in out

    def test_digest_costs_one_read(self):
        c = FakeSSH(routes=_log_routes(SENT))
        logs_mod.mail_delivery_digest_lines(c)
        assert c.count('for __p in') == 1


# ==================== привязка отказа к домену отправления ====================
# Строка доставки (`postfix/smtp ... to=<...> status=`) отправителя НЕ содержит:
# там только to=/relay=/delay=/dsn=/status=. Конверт живёт в ДРУГОЙ записи того
# же queue-id (qmgr при активации очереди, pickup при локальной отправке,
# `sasl_username=` у smtpd при авторизации; cleanup — только message-id, man
# cleanup(8)). Поэтому ниже проверяется именно связка по queue-id, а не
# удачность формулировок: приписать отказ домену, которого в конверте нет, —
# тот же грех, что и поднять «не проверено» до «в порядке».
PICKUP_LIE = ('Oct 10 12:00:00 host postfix/pickup[6843]: BE78A40083: '
              'uid=1001 from=<web@lie.ru>')
CLEANUP_LIE = ('Oct 10 12:00:00 host postfix/cleanup[6850]: BE78A40083: '
               'message-id=<20261010.be@host>')
QMGR_LIE = ('Oct 10 12:00:01 host postfix/qmgr[21603]: BE78A40083: '
            'from=<web@lie.ru>, size=1372, nrcpt=1 (queue active)')
SMTPD_SASL = ('Oct 10 12:00:06 host postfix/submission/smtpd[7001]: '
              '9A1F2B3C4D: client=unknown[203.0.113.7], sasl_method=LOGIN, '
              'sasl_username=shop@shop.ru')
QMGR_SASL = ('Oct 10 12:00:07 host postfix/qmgr[21603]: 9A1F2B3C4D: '
             'from=<shop@shop.ru>, size=900, nrcpt=1 (queue active)')
QMGR_BOUNCE = ('Oct 10 12:00:10 host postfix/qmgr[21603]: DEADBEEF01: '
               'from=<>, size=2400, nrcpt=1 (queue active)')
REMOVED_LIE = 'Oct 10 12:00:13 host postfix/qmgr[21603]: BE78A40083: removed'
# Отказ письма, записей о входе которого в очередь в окне лога нет: «не видно»
# обязано отличаться от «не ваш домен» — иначе оператор спишет отказ чужому.
ORPHAN_FAIL = ('Oct 10 12:00:09 host postfix/smtp[131]: CAFE000111: '
               'to=<q@p.ru>, relay=none, dsn=5.1.1, status=bounced '
               '(User unknown)')
FAIL_LIE = ('Oct 10 12:00:05 host postfix/smtp[124]: BE78A40083: '
            'to=<c@gmail.com>, relay=gmail-smtp-in.l.google.com'
            '[142.251.8.27]:25, dsn=5.7.26, status=bounced (gmail-smtp-in'
            '.l.google.com said: 550-5.7.26 unauthenticated mail was rejected, '
            'please learn about SPF)')
FAIL_SHOP = ('Oct 10 12:00:08 host postfix/smtp[130]: 9A1F2B3C4D: '
             'to=<z@yandex.ru>, relay=none, dsn=4.4.1, status=deferred '
             '(connect to mx.yandex.ru[213.180.204.25]:25: Connection timed '
             'out)')
FAIL_BOUNCE = ('Oct 10 12:00:11 host postfix/smtp[132]: DEADBEEF01: '
               'to=<nowhere@dead.ru>, relay=none, dsn=5.1.1, status=bounced '
               '(User unknown)')
# journald/rsyslog пишут время в RFC3339 и без [pid] — форма префикса другая,
# а связка по queue-id обязана работать и там. Идентификаторы здесь — hex, как
# их печатает postfix: выдумывать «читаемые» id вроде LOCALID для строк, которые
# обязаны парситься, нельзя — парсер бы про них молчал, а тест бы «проходил».
ISO_QMGR = ('2026-09-25T09:41:12.318201+00:00 mail postfix/qmgr: 150E000001: '
            'from=<iso@x.ru>, size=100, nrcpt=1 (queue active)')
ISO_FAIL = ('2026-09-25T09:41:13.400000+00:00 mail postfix/smtp: 150E000001: '
            'to=<t@recv.ru>, relay=none, dsn=5.7.1, status=bounced '
            '(blocked using Spamhaus)')
# «queued as 8BDCA22DA71» — чужая очередь (письмо перенял другой MTA). Взять её
# вместо нашей означало бы искать потом причину отказа в чужом логе.
QUEUED_AS = ('Oct 10 12:00:14 host postfix/smtp[140]: F0DE000001: '
             'to=<m@b.ru>, relay=smtp.b.ru[9.9.9.9]:25, dsn=2.0.0, status=sent '
             '(250 Ok: queued as 8BDCA22DA71)')

# Полный лог для отчётных тестов: наш домен, «не наш», письмо без qmgr-строки и
# письмо с пустым конвертом — по одному, чтобы счётчики не перепутались.
SENDER_LOG = [PICKUP_LIE, CLEANUP_LIE, QMGR_LIE, FAIL_LIE,
              SMTPD_SASL, QMGR_SASL, FAIL_SHOP,
              ORPHAN_FAIL, QMGR_BOUNCE, FAIL_BOUNCE]


def _failures_of(*lines):
    """Отказы так же, как их отбирает снимок: известные статусы, кроме sent."""
    return [e for e in (logs_mod.parse_delivery_entry(l) for l in lines)
            if e and e['status'] in logs_mod.DELIVERY_STATUSES
            and e['status'] != 'sent']


class TestQueueIdParsing:
    def test_queue_id_taken_from_prefix(self):
        assert logs_mod.parse_queue_id(QMGR_LIE) == 'BE78A40083'
        assert logs_mod.parse_queue_id(FAIL_LIE) == 'BE78A40083'

    def test_iso_prefix_without_pid_supported(self):
        assert logs_mod.parse_queue_id(ISO_QMGR) == '150E000001'

    @pytest.mark.parametrize('line', (
        'Oct 10 12:00:00 host postfix/smtpd[9]: warning: queue is full',
        'Oct 10 12:00:00 host postfix/anvil[9]: statistics: max connection '
        'rate 2.00 for (a:1.2.3.4) at Oct 10 12:00:00',
        'Oct 10 12:00:00 host postfix/master[1]: fatal: open /etc/postfix/'
        'main.cf: No such file or directory',
        'Oct 10 12:00:00 host postfix/smtpd[1]: connect to unknown[1.2.3.4] '
        'failed: Connection timed out',
    ))
    def test_syslog_service_words_are_not_queue_ids(self, line):
        # Граница длины {4,…} открыла бы сюда дорогу: `warning` — семь букв.
        # Принять служебное слово за идентификатор — склеить все warning-строки
        # сервера в одно «письмо» и приписать ему чужой отказ.
        assert logs_mod.parse_queue_id(line) == ''

    def test_short_queue_id_of_old_postfix_is_accepted(self):
        # Старые версии печатают 4 символа (фикстуры проекта — AAA2, AAB0).
        # При жёсткой нижней границе привязка на таком сервере молча деградировала
        # бы в «не определён», а это читается как «письма не от наших доменов».
        line = ('Oct 10 12:00:01 host postfix/qmgr[9]: AAA2: '
                'from=<web@lie.ru>, size=100, nrcpt=1 (queue active)')
        assert logs_mod.parse_queue_id(line) == 'AAA2'
        assert logs_mod.parse_sender_entry(line)['from'] == 'web@lie.ru'

    @pytest.mark.parametrize('line', (
        'Oct 10 12:00:02 host postfix/smtpd[9]: connect from '
        'unknown[203.0.113.5]',
        'Oct 10 12:00:00 host postfix/master[1]: daemon started -- '
        'version 3.5.6',
    ))
    def test_noise_has_no_queue_id(self, line):
        # `connect from unknown[...]` формально похоже на «daemon[pid]:», но
        # идентификатора письма там нет: выдать за него «unknown» — склеить все
        # отказы приёма в одно «письмо».
        assert logs_mod.parse_queue_id(line) == ''

    def test_noqueue_is_not_a_queue_id(self):
        # smtpd пишет «NOQUEUE: reject:» — письма нет, оно не было принято.
        # Алфавит hex отсекает его уже сейчас (N, O, Q, U не шестнадцатеричные),
        # но NOT_A_QUEUE_ID остаётся явной защитой: если алфавит когда-нибудь
        # расширят, этот тест обязан остаться красным, а не тихо позеленеть.
        line = ('Oct 10 12:00:12 host postfix/smtpd[9]: NOQUEUE: reject: RCPT '
                'from unknown[203.0.113.5]: 550 Access denied')
        assert logs_mod.parse_queue_id(line) == ''

    def test_foreign_queue_id_in_reason_not_used(self):
        e = logs_mod.parse_delivery_entry(QUEUED_AS)
        assert e['qid'] == 'F0DE000001'
        assert '8BDCA22DA71' not in e['qid']


class TestSenderByQueueId:
    def test_pickup_qmgr_sasl_are_sources(self):
        idx = logs_mod.index_senders_by_queue_id(
            [PICKUP_LIE, CLEANUP_LIE, QMGR_LIE, SMTPD_SASL, ISO_QMGR])
        assert idx['BE78A40083']['from'] == 'web@lie.ru'
        assert idx['9A1F2B3C4D']['via'] == 'sasl'
        assert idx['150E000001'] == {'qid': '150E000001', 'from': 'iso@x.ru',
                                     'via': 'qmgr'}

    def test_first_record_wins(self):
        # qmgr печатает from= при каждой активации очереди, pickup — раньше.
        # Первый ответ и есть момент входа письма в очередь.
        idx = logs_mod.index_senders_by_queue_id([PICKUP_LIE, QMGR_LIE])
        assert idx['BE78A40083']['via'] == 'pickup'

    def test_cleanup_does_not_claim_sender(self):
        # cleanup(8) вставляет заголовки (message-id), а адрес конверта в лог не
        # печатает: искать его в этой строке негде.
        assert logs_mod.parse_sender_entry(CLEANUP_LIE) is None

    def test_removed_line_is_not_sender(self):
        assert logs_mod.parse_sender_entry(REMOVED_LIE) is None

    def test_empty_envelope_is_an_answer_not_a_miss(self):
        # from=<> — автоответ или уведомление о недоставке. Свести это к «не
        # нашли» нельзя: у такого письма отправителя действительно нет.
        rec = logs_mod.parse_sender_entry(QMGR_BOUNCE)
        assert rec is not None and rec['from'] == '' and rec['via'] == 'qmgr'

    def test_sasl_login_strips_trailing_comma(self):
        line = ('Oct 10 12:00:06 host postfix/smtpd[7]: 1111222233: '
                'client=h[1.2.3.4], sasl_method=LOGIN, sasl_username=a@b.ru, '
                'sasl_sender=')
        assert logs_mod.parse_sender_entry(line)['from'] == 'a@b.ru'

    def test_delivery_entry_carries_queue_id(self):
        # Без qid в разборе доставки связка невозможна в принципе.
        assert logs_mod.parse_delivery_entry(FAIL_LIE)['qid'] == 'BE78A40083'

    def test_three_states_of_sender_lookup(self):
        idx = logs_mod.index_senders_by_queue_id(
            [QMGR_LIE, QMGR_BOUNCE, ISO_QMGR])
        known = logs_mod.parse_delivery_entry(FAIL_LIE)
        assert logs_mod.sender_of_delivery(known, idx) == ('web@lie.ru', 'qmgr')
        bounce = logs_mod.parse_delivery_entry(FAIL_BOUNCE)
        assert logs_mod.sender_of_delivery(bounce, idx) == ('', 'qmgr')
        orphan = logs_mod.parse_delivery_entry(ORPHAN_FAIL)
        assert logs_mod.sender_of_delivery(orphan, idx) == ('', '')

    def test_sender_domain_of(self):
        assert logs_mod.sender_domain_of('Web@Lie.RU') == 'lie.ru'
        assert logs_mod.sender_domain_of('') == ''
        assert logs_mod.sender_domain_of('nosign') == ''


class TestFailureSenderSummary:
    def test_our_domains_come_from_inventory_only(self):
        idx = logs_mod.index_senders_by_queue_id(SENDER_LOG)
        summ = logs_mod.summarize_failure_senders(
            _failures_of(*SENDER_LOG), idx, ['lie.ru'])
        assert ('lie.ru', 1, True) in summ['known']
        # shop.ru — реальный отправитель, но в инвентаре почты его нет: назвать
        # его «нашим» было бы враньём, поэтому пометка False.
        assert ('shop.ru', 1, False) in summ['known']

    def test_empty_inventory_marks_nobody_ours(self):
        idx = logs_mod.index_senders_by_queue_id(SENDER_LOG)
        summ = logs_mod.summarize_failure_senders(
            _failures_of(*SENDER_LOG), idx)
        assert summ['known'] and not any(ours for _d, _n, ours in summ['known'])

    def test_unknown_and_empty_envelope_counted_separately(self):
        idx = logs_mod.index_senders_by_queue_id(SENDER_LOG)
        summ = logs_mod.summarize_failure_senders(
            _failures_of(*SENDER_LOG), idx, ['lie.ru'])
        # «нет qmgr-строки в окне» и «конверт пуст» — разные ответы: первое
        # лечится расширением окна лога, второе — ничем.
        assert summ['unknown'] == 1 and summ['empty'] == 1

    def test_sorted_by_count_then_name(self):
        idx = logs_mod.index_senders_by_queue_id(SENDER_LOG)
        summ = logs_mod.summarize_failure_senders(
            _failures_of(*SENDER_LOG, FAIL_LIE), idx, ['lie.ru'])
        assert summ['known'][0] == ('lie.ru', 2, True)


class TestFailureSenderLines:
    def _text(self, our_domains, compact=False):
        return '\n'.join(logs_mod.failure_sender_lines(
            _failures_of(*SENDER_LOG), '\n'.join(SENDER_LOG), our_domains,
            compact=compact))

    def test_our_domain_named_and_substantiated(self):
        text = self._text(['lie.ru'])
        assert 'По вашим почтовым доменам: lie.ru — 1' in text
        # Чем подтверждён адрес, сказано прямо: без этого строка выглядит как
        # догадка по тексту отказа.
        assert 'не угадан' in text

    def test_outsider_named_outsider(self):
        text = self._text(['lie.ru'])
        assert 'вне ваших почтовых доменов: shop.ru — 1' in text
        assert 'не значится в инвентаре' in text

    def test_no_inventory_says_it_was_not_checked(self):
        text = self._text(None)
        assert 'По вашим' not in text
        assert 'не проверялось' in text
        # Имя домена при этом остаётся: «не проверяли, чей он» ≠ «отправителей
        # нет».
        assert 'lie.ru' in text

    def test_unknown_phrased_as_not_visible(self):
        text = self._text(['lie.ru'])
        assert 'Отправитель не определён — 1' in text
        assert 'не видно' in text
        # Форма счётчика «сущность — число»: при одном отказе вывод обязан
        # читаться так же чисто, как при двенадцати.
        assert '1 отказов' not in text

    def test_empty_envelope_line(self):
        text = self._text(['lie.ru'])
        assert 'Писем без отправителя (from=<>) — 1' in text
        assert 'конверт пуст' in text

    def test_compact_is_one_line(self):
        out = logs_mod.failure_sender_lines(_failures_of(*SENDER_LOG),
                                            '\n'.join(SENDER_LOG), ['lie.ru'],
                                            compact=True)
        assert len(out) == 1
        assert 'по вашим доменам: lie.ru — 1' in out[0]
        assert 'иных отправителей: shop.ru — 1' in out[0]
        assert 'отправитель не определён: 1' in out[0]
        assert 'писем без отправителя: 1' in out[0]
        # Тире внутри этой строки стоит ровно один раз — после «отправители
        # отказов». Второе читалось бы как обрыв вывода.
        assert out[0].count(' — ') == 3  # по доменам: lie.ru — 1, иных: ... — 1

    def test_no_failures_no_lines(self):
        assert logs_mod.failure_sender_lines([], '\n'.join(SENDER_LOG),
                                            ['lie.ru']) == []

    def test_compact_head_says_no_link_when_nothing_resolved(self):
        # Ни один отказ не привязан к домену (qmgr-строк в окне нет). Бывший
        # заголовок давал тавтологию «отправители отказов — отправитель не
        # определён: 2», которая выглядит как сломанный вывод, хотя данные в
        # ней настоящие.
        lines = (ORPHAN_FAIL,
                 'Oct 10 12:00:14 host postfix/smtp[141]: DEADBEEF02: '
                 'to=<r@p.ru>, relay=none, dsn=5.1.1, status=bounced '
                 '(User unknown)')
        out = logs_mod.failure_sender_lines(_failures_of(*lines),
                                            '\n'.join(lines), ['lie.ru'],
                                            compact=True)
        assert len(out) == 1
        assert 'отказы без привязки к домену — отправитель не определён: 2' \
            in out[0]
        assert 'отправители отказов — отправитель' not in out[0]

    def test_compact_head_for_empty_envelope_only(self):
        # Пустой конверт — тоже «без привязки», но сказать надо именно про
        # конверт: «отправитель не определён» тут был бы неправдой (он известен
        # — его нет).
        out = logs_mod.failure_sender_lines(
            _failures_of(QMGR_BOUNCE, FAIL_BOUNCE),
            '\n'.join((QMGR_BOUNCE, FAIL_BOUNCE)), ['lie.ru'], compact=True)
        assert 'отказы без привязки к домену — писем без отправителя: 1' \
            in out[0]


class TestSenderInReports:
    def test_snapshot_shows_our_domain(self):
        out = '\n'.join(logs_mod.mail_log_snapshot_lines(
            FakeSSH(routes=_log_routes(*SENDER_LOG)), our_domains=['lie.ru']))
        assert 'По вашим почтовым доменам: lie.ru — 1' in out

    def test_snapshot_without_inventory_makes_no_claim(self):
        out = '\n'.join(logs_mod.mail_log_snapshot_lines(
            FakeSSH(routes=_log_routes(*SENDER_LOG))))
        assert 'По вашим' not in out and 'не проверялось' in out

    def test_snapshot_still_costs_one_read(self):
        # Индекс отправителей строится из УЖЕ прочитанного фрагмента: привязка
        # не имеет права удвоить цену отчёта.
        c = FakeSSH(routes=_log_routes(*SENDER_LOG))
        logs_mod.mail_log_snapshot_lines(c, our_domains=['lie.ru'])
        assert c.count('for __p in') == 1

    def test_digest_gets_exactly_one_sender_line(self):
        out = '\n'.join(logs_mod.mail_delivery_digest_lines(
            FakeSSH(routes=_log_routes(*SENDER_LOG)), our_domains=['lie.ru']))
        assert 'отправители отказов —' in out
        assert out.count('отправители отказов') == 1

    def test_digest_costs_one_read(self):
        c = FakeSSH(routes=_log_routes(*SENDER_LOG))
        logs_mod.mail_delivery_digest_lines(c, our_domains=['lie.ru'])
        assert c.count('for __p in') == 1

    def test_no_failures_means_no_sender_lines(self):
        # «Отказов нет» + пометка «по вашим доменам» — это уже выдуманный
        # отправитель: строк об отправителях при нулевом счёте быть не должно.
        out = '\n'.join(logs_mod.mail_log_snapshot_lines(
            FakeSSH(routes=_log_routes(SENT)), our_domains=['lie.ru']))
        assert 'По вашим' not in out and 'Отказов нет' in out
