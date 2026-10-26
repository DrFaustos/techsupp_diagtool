"""Тесты panels.py: действия ISPmanager и FastPanel.

Реального SSH нет — команды перехватывает FakeSSH из support.py. Порядок
маршрутов важен: первое совпадение по подстроке выигрывает, поэтому более
специфичные иглы ('systemctl restart') идут раньше общих ('fastpanel2-engine'),
иначе команда перезапуска получила бы ответ от маршрута поиска юнита.
"""
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

import pytest
import shlex

from support import FakeSSH
import panels as panels_mod


# ==================== fastpanel_unit ====================
class TestFastpanelUnit:
    def test_prefers_fastpanel2_engine(self):
        c = FakeSSH(routes=[('systemctl cat fastpanel2-engine', '[Unit]\n')])
        assert panels_mod.fastpanel_unit(c) == 'fastpanel2-engine'

    def test_falls_back_to_fastpanel1(self):
        c = FakeSSH(routes=[
            ('systemctl cat fastpanel2-engine', ''),
            ('systemctl cat fastpanel', '[Unit]\n'),
        ])
        assert panels_mod.fastpanel_unit(c) == 'fastpanel'

    def test_none_when_no_unit_installed(self):
        # Панель не найдена: пустой вывод systemctl cat на обоих юнитах.
        c = FakeSSH()
        assert panels_mod.fastpanel_unit(c) is None

    def test_unit_names_are_quoted(self):
        # Имя юнита подставляется через q() — инъекция в команду невозможна.
        c = FakeSSH()
        panels_mod.fastpanel_unit(c)
        for cmd in c.commands:
            assert 'rm' not in cmd
            parts = shlex.split(cmd)
            assert any(p in panels_mod.FASTPANEL_UNITS for p in parts)


# ==================== find_fastpanel_logs ====================
class TestFindFastpanelLogs:
    def test_returns_existing_logs(self):
        c = FakeSSH(routes=[
            ('ls -1 /var/log/fastpanel2', '/var/log/fastpanel2/engine.log\n'),
            ('ls -1 /var/log/fastpanel/fastpanel.log', ''),
        ])
        assert panels_mod.find_fastpanel_logs(c) == ['/var/log/fastpanel2/engine.log']

    def test_collects_from_both_generations(self):
        c = FakeSSH(routes=[
            ('ls -1 /var/log/fastpanel2/engine.log', '/var/log/fastpanel2/engine.log\n'),
            ('ls -1 /var/log/fastpanel/fastpanel.log', '/var/log/fastpanel/fastpanel.log\n'),
        ])
        assert panels_mod.find_fastpanel_logs(c) == [
            '/var/log/fastpanel2/engine.log', '/var/log/fastpanel/fastpanel.log',
        ]

    def test_empty_when_absent(self):
        assert panels_mod.find_fastpanel_logs(FakeSSH()) == []


# ==================== fastpanel_restart ====================
class TestFastpanelRestart:
    def test_restart_reports_active(self):
        c = FakeSSH(routes=[
            ('systemctl restart', ('', '', 0)),
            ('systemctl is-active', 'active\n'),
            ('systemctl cat fastpanel2-engine', '[Unit]\n'),
        ])
        out = panels_mod.fastpanel_restart(c)
        assert '✅' in out and 'fastpanel2-engine' in out and 'active' in out

    def test_missing_unit_does_not_restart(self):
        # Если юнита нет, `systemctl restart` отправлять нельзя (rc всё равно
        # был бы нулевым у заглушки — проверяем сам факт отсутствия команды).
        c = FakeSSH()
        out = panels_mod.fastpanel_restart(c)
        assert '❌' in out
        assert c.find('systemctl restart') is None

    def test_failed_restart_shows_error(self):
        c = FakeSSH(routes=[
            ('systemctl restart', ('', 'Job for fastpanel2-engine.service failed', 1)),
            ('systemctl cat', '[Unit]\n'),
        ])
        out = panels_mod.fastpanel_restart(c)
        assert '❌' in out and 'failed' in out


# ==================== fastpanel_logs ====================
class TestFastpanelLogs:
    def test_tails_found_logs(self):
        c = FakeSSH(routes=[
            ('ls -1 /var/log/fastpanel2', '/var/log/fastpanel2/engine.log\n'),
            ('ls -1 /var/log/fastpanel/fastpanel.log', ''),
            ('tail -n 30', 'engine started\n'),
        ])
        out = panels_mod.fastpanel_logs(c)
        assert '/var/log/fastpanel2/engine.log' in out and 'engine started' in out

    def test_reports_missing_logs(self):
        out = panels_mod.fastpanel_logs(FakeSSH())
        assert '⚠️' in out and '/var/log/fastpanel2/engine.log' in out


# ==================== fastpanel_status ====================
class TestFastpanelStatus:
    def test_status_collects_stack_and_endpoint(self):
        c = FakeSSH(routes=[
            ('systemctl cat fastpanel2-engine', '[Unit]\n'),
            ('is-active nginx', 'active\nactive\nactive\n'),
            ('curl', '200\n000'),
            ('nginx -t', 'nginx: configuration file /etc/nginx/nginx.conf test is successful\n'),
        ])
        out = panels_mod.fastpanel_status(c)
        assert 'fastpanel2-engine' in out
        assert '8888' in out and '200' in out
        assert 'successful' in out

    def test_status_without_unit(self):
        # Переформулировано объявленно (1.28.0). Было заперто: МОЛЧАНИЕ сервера
        # (FakeSSH без маршрутов = «мы не посмотрели») как «Служба панели не
        # найдена» — ровно та ложь, которую чинит слайс (закон 1.19–1.27:
        # «не проверено» ≠ «нет»). Инвариант усилен, а не ослаблен: честный
        # ответ системы «юнита нет» обязан и впредь называться «не найдена»,
        # а молчание — признаться.
        c = FakeSSH(routes=[('systemctl cat', UNIT_ABSENT)])
        out = panels_mod.fastpanel_status(c)
        assert 'Служба панели не найдена' in out
        out2 = panels_mod.fastpanel_status(FakeSSH())
        assert 'не проверено' in out2 and 'не найдена' not in out2


# ==================== php_fpm_units ====================
class TestPhpFpmUnits:
    UNIT_LIST = (
        '  php8.1-fpm.service loaded active running The PHP 8.1 FastCGI Process Manager\n'
        '  php8.2-fpm.service loaded active running The PHP 8.2 FastCGI Process Manager\n'
        '  nginx.service loaded active running A high performance web server\n'
    )

    def test_parses_only_php_fpm_units(self):
        c = FakeSSH(routes=[('list-units', self.UNIT_LIST)])
        assert panels_mod.php_fpm_units(c) == ['php8.1-fpm', 'php8.2-fpm']

    def test_dedupes_and_skips_garbage(self):
        c = FakeSSH(routes=[('list-units', 'php8.2-fpm.service\n\nне юнит\n')])
        assert panels_mod.php_fpm_units(c) == ['php8.2-fpm']

    def test_empty_without_systemd(self):
        assert panels_mod.php_fpm_units(FakeSSH()) == []

    def test_no_nested_quotes_in_command(self):
        # Регрессия: Awk внутри $(...) ломался на вложенных кавычках.
        c = FakeSSH()
        panels_mod.php_fpm_units(c)
        cmd = c.find('list-units')
        assert 'awk' not in cmd and '$(' not in cmd


# ==================== fastpanel_restart_web ====================
class TestFastpanelRestartWeb:
    GOOD = ('nginx: the configuration file /etc/nginx/nginx.conf syntax is ok\n'
            'nginx: configuration file /etc/nginx/nginx.conf test is successful\n')

    def test_restarts_nginx_and_every_fpm(self):
        c = FakeSSH(routes=[
            ('nginx -t', self.GOOD),
            ('systemctl restart nginx', ('', '', 0)),
            ('list-units', TestPhpFpmUnits.UNIT_LIST),
            ('systemctl restart php8.1-fpm', ('', '', 0)),
            ('systemctl restart php8.2-fpm', ('', '', 0)),
        ])
        out = panels_mod.fastpanel_restart_web(c)
        assert 'nginx перезапущен' in out
        assert 'php8.1-fpm' in out and 'php8.2-fpm' in out

    def test_broken_config_blocks_restart(self):
        # Главная защита операции: при неуспешном nginx -t ничего не перезапускаем.
        c = FakeSSH(routes=[
            ('nginx -t', 'nginx: configuration test FAILED\n'),
            ('list-units', TestPhpFpmUnits.UNIT_LIST),
        ])
        out = panels_mod.fastpanel_restart_web(c)
        assert '❌' in out
        assert c.find('systemctl restart') is None

    def test_reports_failed_fpm_unit(self):
        c = FakeSSH(routes=[
            ('nginx -t', self.GOOD),
            ('systemctl restart nginx', ('', '', 0)),
            ('list-units', 'php8.2-fpm.service loaded active running x\n'),
            ('systemctl restart php8.2-fpm', ('', 'unit is masked', 1)),
        ])
        out = panels_mod.fastpanel_restart_web(c)
        assert 'php8.2-fpm' in out and 'masked' in out


# ==================== ISPmanager (регрессии существующего поведения) ====
class TestIspmanagerCronFix:
    def test_backup_before_edit(self):
        c = FakeSSH(routes=[
            ('crontab -l >', ('', '', 0)),
            ('test -f', 'exists'),
            ('sed', ('', '', 0)),
        ])
        out = panels_mod.ispmanager_fix_cron_path(c)
        assert '✅' in out
        assert c.find('cp') is not None, 'резервная копия не создавалась'

    def test_no_path_variable_is_ok(self):
        out = panels_mod.ispmanager_check_cron_path(FakeSSH())
        assert '✅' in out


# ==================== все команды панелей синтаксически валидны =========
class TestGeneratedCommandsAreValidShell:
    """Каждая команда, ушедшая на сервер, должна быть валидным shell.

    Ловит кривые кавычки (regression: awk внутри $(...)), пока тесты гоняются
    на машине без systemd и панели.
    """

    def _all_commands(self):
        good = ('nginx: syntax is ok\nnginx: test is successful\n')
        c = FakeSSH(routes=[
            ('nginx -t', good),
            ('list-units', 'php8.2-fpm.service loaded active running x\n'),
            ('systemctl cat', '[Unit]\n'),
            ('is-active', 'active\n'),
            ('ls -1', ''),
            ('crontab -l', 'PATH=/usr/bin\n'),
            ('mgrctl', 'ok'),
            ('tail', 'line\n'),
            ('curl', '200\n'),
            ('test -f', 'exists'),
        ])
        panels_mod.fastpanel_restart(c)
        panels_mod.fastpanel_logs(c)
        panels_mod.fastpanel_status(c)
        panels_mod.fastpanel_restart_web(c)
        panels_mod.php_fpm_units(c)
        panels_mod.ispmanager_restart(c)
        panels_mod.ispmanager_update(c)
        panels_mod.ispmanager_ssl_issue(c)
        panels_mod.ispmanager_disable_geoip(c)
        panels_mod.ispmanager_check_cron_path(c)
        panels_mod.ispmanager_fix_cron_path(c)
        # Диагностика и действия «панель не открывается» — самые молодые ветки,
        # в них больше всего подстановок (порты, пути логов, пароль)
        panels_mod.ispmanager_logs_report(c)
        panels_mod.ispmanager_panel_diag(c)
        panels_mod.ispmanager_unlock(c)
        panels_mod.ispmanager_license_refresh(c)
        # Лицензия «только чтение»: команда собрана из кучи подстановок и
        # shell-функции — её обязан проверить bash -n наравне с остальными
        panels_mod.ispmanager_license_report(c)
        # Активация по ключу: ключ идёт аргументом и обязан быть экранирован —
        # именно такие команды ломаются кавычками чаще всего
        panels_mod.ispmanager_license_activate(c, "KEY'with;space`tick`")
        panels_mod.fastpanel_package_status(c)
        panels_mod.fastpanel_diag(c)
        panels_mod.fastpanel_reset_password(c, "Passw0rd 'quoted\"")
        return list(c.commands)

    def test_commands_parse_with_shlex_and_bash(self):
        import subprocess
        cmds = self._all_commands()
        assert cmds, 'панели не отправили ни одной команды'
        for cmd in cmds:
            shlex.split(cmd)  # не должно бросать ValueError на незакрытой кавычке
            proc = subprocess.run(['bash', '-n', '-c', cmd],
                                  capture_output=True, text=True)
            assert proc.returncode == 0, f'bash -n не принял:\n{cmd}\n{proc.stderr}'


# ==================== ISPmanager: ветки, которых не было ====================
class TestIspmanagerRestart:
    def test_success_path(self):
        c = FakeSSH(routes=[('mgrctl -m ispmgr exit', ('', '', 0)),
                            ('sysinfo', 'kernel=linux')])
        out = panels_mod.ispmanager_restart(c)
        assert '✅ Команда на перезапуск отправлена через mgrctl' in out
        assert '✅ Панель работает' in out
        assert c.find('sleep 3') is not None

    def test_failure_reports_rc_and_warns_when_panel_down(self):
        c = FakeSSH(routes=[('mgrctl -m ispmgr exit',
                             ('', 'connection refused', 1)),
                            ('sysinfo', 'connection failed: error')])
        out = panels_mod.ispmanager_restart(c)
        assert '❌ Ошибка (rc=1): connection refused' in out
        assert '⚠️ Панель возможно не запустилась' in out


class TestIspmanagerKillCore:
    def test_core_gone_after_kill(self):
        c = FakeSSH(routes=[('ps aux | grep core', '')])
        out = panels_mod.ispmanager_kill_core(c)
        assert '✅ Процесс core завершён' in out
        assert c.find('killall core') is not None
        assert c.find('pkill -9 core') is not None
        assert c.find('sleep 2') is not None

    def test_core_still_running_is_warned(self):
        c = FakeSSH(routes=[('ps aux | grep core',
                             'root 1 0.0 /usr/local/mgr5/bin/core\n')])
        out = panels_mod.ispmanager_kill_core(c)
        assert '⚠️ Процесс core всё ещё работает' in out


class TestIspmanagerDisable:
    def test_disable_blocks_binary_and_kills_daemons(self):
        c = FakeSSH()
        out = panels_mod.ispmanager_disable(c)
        assert '✅ Панель отключена' in out
        assert '⚠️ Для включения выполните: chmod +x' in out
        assert c.find('chmod -x /usr/local/mgr5/bin/core') is not None
        assert c.find('killall core') is not None
        assert c.find('killall ihttpd') is not None


class TestIspmanagerCronFixBackupFailure:
    def test_missing_backup_warns_but_fix_still_runs(self):
        # test -f с rc=1: create_backup возвращает None (ни источника, ни бэкапа)
        c = FakeSSH(routes=[('crontab -l > /tmp', ('', '', 0)),
                            ('mkdir -p', ('created', '', 0)),
                            ('test -f', ('', '', 1)),
                            ('| sed', ('', '', 0))])
        out = panels_mod.ispmanager_fix_cron_path(c)
        assert '⚠️ Не удалось создать резервную копию crontab' in out
        assert '✅ Переменная PATH закомментирована' in out


class TestFastpanelRestartWebNoFpm:
    def test_missing_php_fpm_units_reported(self):
        c = FakeSSH(routes=[('nginx -t', TestFastpanelRestartWeb.GOOD),
                            ('systemctl restart nginx', ('', '', 0)),
                            ('list-units', '')])
        out = panels_mod.fastpanel_restart_web(c)
        assert 'nginx перезапущен' in out
        assert '⚠️ Службы php*-fpm не найдены' in out
        # перезапуск должен остаться ровно один (nginx): без юнитов луп пуст
        assert c.count('systemctl restart') == 1


# ============ ISPmanager: ДИАГНОСТИКА «ПАНЕЛЬ НЕ ОТКРЫВАЕТСЯ» ==============
# Отчёт самый частый и самый опасный ложными выводами: «порт молчит»,
# «панель заблокирована» и «лицензия слетела» — три РАЗНЫЕ причины, и тесты
# держат их разделёнными. Иглы маршрутов учитывают, что строка
# '/usr/local/mgr5/bin/core' встречается и в команде версии (`core ispmgr -V`),
# и в pgrep, поэтому для процессов игла берётся с хвостом `>/dev/null`.
class TestIspmanagerLogsReport:
    def test_existing_logs_get_tails(self):
        c = FakeSSH(routes=[
            ('test -f /usr/local/mgr5/var/ispmgr.log', 'yes'),
            ('test -f /usr/local/mgr5/var/core.log', 'yes'),
            ('tail -n 40 /usr/local/mgr5/var/ispmgr.log', 'module started'),
            ('tail -n 40 /usr/local/mgr5/var/core.log', ''),
        ])
        out = panels_mod.ispmanager_logs_report(c)
        assert 'ispmgr.log (последние 40 строк)' in out
        assert 'module started' in out
        # пустой лог показывается как «файл пуст», а не пропадает из отчёта
        assert '(файл пуст)' in out
        # существование проверяется по всем трём путям
        assert c.count('test -f /usr/local/mgr5/var') == 3

    def test_tail_length_is_honored(self):
        c = FakeSSH(routes=[('test -f', 'yes'), ('tail -n 7', 'x')])
        panels_mod.ispmanager_logs_report(c, tail=7)
        assert c.find('tail -n 7') is not None

    def test_no_logs_says_where_it_looked(self):
        c = FakeSSH(routes=[('test -f', ('', '', 1))])
        out = panels_mod.ispmanager_logs_report(c)
        assert '⚠️ Логи панели не найдены' in out
        assert '/usr/local/mgr5/var/pkg.log' in out
        # читать то, чего нет, запрещено
        assert c.find('tail') is None


class TestIspmanagerPanelDiag:
    def test_healthy_panel(self):
        c = FakeSSH(routes=[
            ('core ispmgr -V', '6.4.2'),
            ('bin/core" >/dev/null', 'yes'),
            ('ihttpd', 'yes'),
            ('127.0.0.1:1500', '302'),
            ('sysinfo', 'elid=1'),
            ('licctl info', 'license: ok, expires 2027'),
            ('tail -n 15', ''),
        ])
        out = panels_mod.ispmanager_panel_diag(c)
        assert 'Версия панели: 6.4.2' in out
        assert 'Процесс core: ✅ запущен' in out
        assert 'ihttpd: ✅ запущен' in out
        assert ':1500 (https с localhost): 302' in out
        assert '✅ API панели отвечает' in out
        assert 'не отвечает' not in out
        assert 'не активна' not in out

    def test_dead_panel_reports_every_missing_piece(self):
        # Заглушка молчит на всём: ровно то, что видит оператор, когда
        # панель не открывается вообще.
        c = FakeSSH()
        out = panels_mod.ispmanager_panel_diag(c)
        assert 'Версия панели: не определена' in out
        assert out.count('❌ не запущен') == 2
        assert 'Порт панели не отвечает' in out
        # пустой ответ mgrctl — это «молчит», а не «отвечает»
        assert '✅ API панели отвечает' not in out and 'молчит' in out

    def test_blocked_panel_is_reported_as_blocked(self):
        c = FakeSSH(routes=[
            ('sysinfo', ('ERROR: Access to the panel is blocked by the '
                         'administrator', '', 1)),
        ])
        out = panels_mod.ispmanager_panel_diag(c)
        assert 'Ответ API панели' in out
        assert 'Разблокировать панель' in out
        assert '✅ API панели отвечает' not in out

    def test_dead_license_warns_about_ip(self):
        c = FakeSSH(routes=[('licctl info', 'license not found')])
        out = panels_mod.ispmanager_panel_diag(c)
        assert 'Лицензия не активна' in out and 'licctl fetch' in out

    def test_silent_licctl_is_not_a_dead_license(self):
        # licctl может молчать без интернета — вешать «лицензия умерла» нельзя
        c = FakeSSH(routes=[('licctl info', '')])
        out = panels_mod.ispmanager_panel_diag(c)
        assert 'licctl молчит' in out
        assert 'Лицензия не активна' not in out

    def test_log_tail_appended_when_present(self):
        c = FakeSSH(routes=[('tail -n 15', 'FATAL: cannot bind :1500')])
        out = panels_mod.ispmanager_panel_diag(c)
        assert 'FATAL: cannot bind :1500' in out


class TestIspmanagerUnlock:
    def test_both_targets_unlocked(self):
        c = FakeSSH()
        out = panels_mod.ispmanager_unlock(c)
        assert '✅ Модуль ispmgr разблокирован' in out
        assert '✅ Ядро панели разблокировано' in out
        assert 'pkgupgrade' in out
        assert c.find('mgrctl -m ispmgr -u') is not None
        assert c.find('mgrctl -m core -u') is not None

    def test_per_target_error(self):
        c = FakeSSH(routes=[('mgrctl -m ispmgr -u',
                             ('', 'permission denied', 1))])
        out = panels_mod.ispmanager_unlock(c)
        assert '❌ модуль ispmgr (rc=1): permission denied' in out
        assert '✅ Ядро панели разблокировано' in out
        # частичный успех тоже обязан напомнить про штатную блокировку
        assert 'pkgupgrade' in out

    def test_total_failure_has_no_healthy_hint(self):
        c = FakeSSH(default=('', 'no such manager', 2))
        out = panels_mod.ispmanager_unlock(c)
        assert '❌ модуль ispmgr (rc=2)' in out
        assert '❌ ядро core (rc=2)' in out
        assert 'pkgupgrade' not in out


class TestIspmanagerLicenseRefresh:
    def test_fetch_then_info(self):
        c = FakeSSH(routes=[('licctl fetch ispmgr', ''),
                            ('licctl info', 'license: ok')])
        out = panels_mod.ispmanager_license_refresh(c)
        assert '✅ Запрос на сервер лицензий выполнен' in out
        assert 'Состояние лицензии теперь:' in out and 'license: ok' in out

    def test_failure_shows_error_and_still_reports(self):
        c = FakeSSH(routes=[('licctl fetch ispmgr',
                             ('', 'network unreachable', 1)),
                            ('licctl info', '')])
        out = panels_mod.ispmanager_license_refresh(c)
        assert '❌ Ошибка (rc=1): network unreachable' in out
        assert '(licctl info вернул пусто)' in out


# ============ ISPmanager: ЛИЦЕНЗИЯ ОТДЕЛЬНЫМ ПУНКТОМ (ТОЛЬКО ЧТЕНИЕ) =======
class TestIspmanagerLicenseReport:
    """Остаток дней считает СЕРВЕР, отчёт различает четыре состояния.

    Служебные поля (LIC_DAYS и т.п.) в тестах задаём руками: их вырабатывает
    shell-команда на сервере, и проверка «date -d вызывается там, а не здесь»
    вынесена в отдельный гард test_days_are_computed_on_server.
    """

    # Дословный вывод licctl info ispmgr из документации ISPsystem
    LIC = ('OS: Ubuntu 22.04.4 (x86_64)\nManager: ispmgr (6.124.0)\nID: 0\n'
           'Name: Trial License\nExpire: 2025-07-11\nUpdate end: (2026-04-30)\n')

    @staticmethod
    def _srv(expire='2025-07-11', days='-467', update='(2026-04-30)',
             update_days='-174', lic=None):
        return (f'LIC_EXPIRE={expire}\nLIC_DAYS={days}\n'
                f'LIC_UPDATE={update}\nLIC_UPDATE_DAYS={update_days}\n---\n'
                + (TestIspmanagerLicenseReport.LIC if lic is None else lic))

    def _report(self, out, default=None):
        c = FakeSSH(routes=[('licctl info ispmgr 2>&1 | head -n 20', out)],
                    **({} if default is None else {'default': default}))
        return panels_mod.ispmanager_license_report(c), c

    # ---------- вердикты по остатку ----------
    def test_expired_license_names_how_long_ago(self):
        out, c = self._report(self._srv())
        assert '❌ Лицензия истекла 467 дн. назад' in out
        assert 'Окончание лицензии: 2025-07-11' in out
        assert 'Срок обновлений: (2026-04-30) (истёк)' in out
        # подсказка про смену IP уместна, когда срок уже горит
        assert 'licctl fetch' in out
        assert 'Trial' in out and 'licctl info ispmgr' in c.commands[0]

    def test_expiring_soon_is_warning_not_death(self):
        out, _ = self._report(self._srv(days='12', update_days='200'))
        assert '⚠️ Лицензия истекает через 12 дн.' in out
        assert 'истекла' not in out
        assert '(осталось 200 дн.)' in out
        assert 'licctl fetch' in out

    def test_healthy_license_has_no_rescue_hint(self):
        out, _ = self._report(self._srv(days='200', update_days='400'))
        assert '✅ Лицензия активна, осталось 200 дн.' in out
        # подсказка «перетянуть лицензию» на здоровой панели — шум
        assert 'licctl fetch' not in out

    def test_threshold_is_exactly_warn_days(self):
        # 30 дн. — ещё «в порядке» (порог строгий), 29 — уже предупреждение
        assert '✅' in panels_mod.license_status_line(panels_mod.LICENSE_WARN_DAYS)
        assert '⚠️' in panels_mod.license_status_line(
            panels_mod.LICENSE_WARN_DAYS - 1)
        # ноль дней — ещё не «истекла», но уже тревога
        assert '⚠️' in panels_mod.license_status_line(0)
        assert '❌' in panels_mod.license_status_line(-1)
        assert '❓' in panels_mod.license_status_line(None)

    # ---------- две разные причины «неизвестного» срока ----------
    def test_missing_expire_line_says_so(self):
        out, _ = self._report(self._srv(expire='', days='', lic=self.LIC.replace(
            'Expire: 2025-07-11\n', '')))
        assert '❓ Дата окончания лицензии не определена' in out
        assert 'найти не удалось' in out
        assert 'date её не распознала' not in out

    def test_date_ignored_by_busybox_date_is_not_missing_line(self):
        # Дата licctl вернул, а серверная date (BusyBox/BSD без -d) её не понял.
        # Писать «строку Expire найти не удалось» — врать: оператор искал бы не там.
        out, _ = self._report(self._srv(expire='2027-01-01', days=''))
        assert 'серверная date её не распознала' in out
        assert 'BusyBox' in out
        assert 'найти не удалось' not in out
        assert 'Окончание лицензии: 2027-01-01' in out

    # ---------- отказ панели/сервера, а не лицензии ----------
    def test_silent_licctl_is_not_a_dead_license(self):
        # licctl молчит чаще без интернета: вешать «лицензия истекла» нельзя
        out, _ = self._report('', default=('', '', 0))
        assert 'не вернул ничего' in out
        assert '❌' not in out and 'истекла' not in out

    def test_missing_binary_is_not_reported_as_license_state(self):
        # Команда собрана с 2>&1, поэтому «command not found» приходит в stdout
        # и без отдельной ветки выглядел бы как «состояние лицензии».
        out, _ = self._report('bash: /usr/local/mgr5/sbin/licctl: '
                              'No such file or directory')
        assert '❌ licctl не найден на сервере' in out
        assert 'Дата окончания' not in out

    def test_trial_flag_only_when_panel_says_trial(self):
        lic = self.LIC.replace('Name: Trial License', 'Name: Business License')
        out, _ = self._report(self._srv(days='200', update_days='400', lic=lic))
        assert 'Trial' not in out

    def test_days_are_computed_on_server_not_on_operators_laptop(self):
        # Дни обязана считать серверная date -d: часы машины оператора
        # расходятся с серверными (тот же приём, что CERT= в SSL-пробе).
        _out, c = self._report(self._srv(days='200'))
        assert c.count('licctl info ispmgr') == 1      # один вызов licctl
        cmd = c.commands[0]
        assert 'date -d' in cmd and 'date +%s' in cmd
        # Служебные поля отделены от текста licctl разделителем: без него
        # парсер не отличил бы «Expire: ...» из вывода licctl от своих строк.
        assert 'echo "---"' in cmd

    # ---------- чистый парсер ----------
    def test_parser_splits_service_fields_and_raw(self):
        info = panels_mod.parse_license_info(self._srv())
        assert info['expire'] == '2025-07-11'
        assert info['days'] == -467
        assert info['update_days'] == -174
        assert info['raw'].startswith('OS: Ubuntu')   # текст licctl как есть

    def test_parser_survives_junk_and_empty(self):
        for text in ('', None, 'совсем не наш формат', 'LIC_DAYS=не-число'):
            info = panels_mod.parse_license_info(text)
            assert info['days'] is None
            assert info['raw'] is not None


# ======= ISPmanager: АКТИВАЦИЯ ЛИЦЕНЗИИ ПО КЛЮЧУ (licctl fetch mgrName key) ==
# Синтаксис — официальный док ISPsystem «Activating a license with a key»:
#     /usr/local/mgr5/sbin/licctl fetch mgrName key
# Формы «licctl activate ...» в официальной документации НЕТ (она встречается
# только в сторонних KB) — гард test_no_invented_activate_subcommand не даст
# занести её в код после нас.
KEY = 'K1-TESTKEY-0000'


class TestIspmanagerLicenseActivate:
    """licctl fetch ispmgr <ключ>, и вердикт — по ПЕРЕЧИТАННОМУ licctl info.

    Код возврата licctl нам не доказательство, поэтому licctl info вызывается
    всегда (в том числе после ошибки) и вердикт пишется по состоянию лицензии.
    """

    @staticmethod
    def _srv(**kw):
        return TestIspmanagerLicenseReport._srv(**kw)

    @staticmethod
    def _fake(fetch=('', '', 0), info=None):
        return FakeSSH(routes=[
            ('licctl fetch ispmgr', fetch),
            ('licctl info ispmgr 2>&1 | head -n 20',
             TestIspmanagerLicenseActivate._srv(**(info or {}))),
        ])

    # ---------- отказ ДО отправки ----------
    def test_empty_key_refuses_without_any_command(self):
        c = FakeSSH()
        out = panels_mod.ispmanager_license_activate(c, '   ')
        assert '⛔ Ключ активации не задан' in out
        assert 'Ни одна команда на сервер не отправлялась' in out
        assert c.commands == []

    def test_none_key_refuses_without_any_command(self):
        c = FakeSSH()
        assert '⛔' in panels_mod.ispmanager_license_activate(c, None)
        assert c.commands == []

    def test_fetch_without_key_is_a_different_operation(self):
        # licctl fetch БЕЗ ключа перетягивает лицензию на текущий IP. Молча
        # отправить её вместо активации — значит тронуть лицензию не тем
        # действием, поэтому отказ обязан называть альтернативный пункт.
        out = panels_mod.ispmanager_license_activate(FakeSSH(), '')
        assert 'перетягивает' in out and 'Обновить под IP' in out

    @pytest.mark.parametrize('bad', ['ABC DEF', 'ABC\nDEF', 'ABC\tDEF'])
    def test_key_with_whitespace_is_refused(self, bad):
        # Инъекции тут не было бы и без проверки (q() экранирует), но licctl
        # принял бы мусор как ключ и сжёг ОДНОРАЗОВЫЙ ключ зря.
        c = FakeSSH()
        out = panels_mod.ispmanager_license_activate(c, bad)
        assert 'не должен содержать пробелов и переносов' in out
        assert c.commands == []

    # ---------- сама команда ----------
    def test_command_matches_official_documentation(self):
        c = self._fake()
        panels_mod.ispmanager_license_activate(c, KEY)
        assert c.count('licctl fetch') == 1
        parts = shlex.split(c.find('licctl fetch'))
        assert parts[:4] == ['/usr/local/mgr5/sbin/licctl', 'fetch',
                             'ispmgr', KEY]

    def test_no_invented_activate_subcommand(self):
        # «licctl activate» — синтаксис из сторонней KB. Если кто-то (в т.ч.
        # следующий коммит) занесёт его в код — падает тест, а не сервер.
        c = self._fake()
        panels_mod.ispmanager_license_activate(c, KEY)
        assert not [cmd for cmd in c.commands if 'activate' in cmd]

    def test_weird_key_stays_one_argument(self):
        evil = "AB'CD;touch"
        c = self._fake()
        panels_mod.ispmanager_license_activate(c, evil)
        parts = shlex.split(c.find('licctl fetch'))
        assert parts[3] == evil                      # значение дошло целиком
        assert 'touch' not in parts                  # отдельной команды нет

    # ---------- ключ обязан оставаться секретом отчёта ----------
    def test_key_never_appears_in_report(self):
        c = self._fake()
        out = panels_mod.ispmanager_license_activate(c, KEY)
        assert KEY not in out
        assert 'licctl fetch ispmgr *** 2>&1' in out   # смысл виден, ключ — нет

    def test_key_repeated_by_licctl_is_masked(self):
        # licctl способен напечатать ключ в сообщении об ошибке — отчёт обязан
        # быть чистым: его сохраняют в файл и пересылают в тикет.
        c = self._fake(fetch=(f'invalid key {KEY} for this IP', '', 1))
        out = panels_mod.ispmanager_license_activate(c, KEY)
        assert KEY not in out
        assert 'invalid key *** for this IP' in out

    # ---------- подтверждение фактом, а не кодом возврата ----------
    def test_info_is_reread_even_after_error(self):
        c = self._fake(fetch=('', 'network unreachable', 1))
        out = panels_mod.ispmanager_license_activate(c, KEY)
        assert '❌ Ошибка (rc=1): network unreachable' in out
        assert c.count('licctl info ispmgr') == 1
        assert '✅ Лицензия активна' not in out

    def test_success_verdict_from_reread_state(self):
        c = self._fake(info={'days': '200', 'update_days': '400'})
        out = panels_mod.ispmanager_license_activate(c, KEY)
        assert '✅ Лицензия активна после запроса по ключу.' in out
        assert 'Окончание лицензии: 2025-07-11' in out

    def test_accepted_but_still_expired_is_not_called_success(self):
        # Ключ мог быть уже использован: licctl молчит, состояние не меняется.
        c = self._fake(info={})
        out = panels_mod.ispmanager_license_activate(c, KEY)
        assert 'НЕ активна' in out and 'Перевыпустите' in out
        assert '✅ Лицензия активна' not in out

    def test_unknown_date_is_not_reported_as_active(self):
        # Третья ветка: сервер не дал понятной даты. Рапортовать «активна»
        # нельзя — это не доказательство активации.
        c = self._fake(info={'days': '', 'update_days': ''})
        out = panels_mod.ispmanager_license_activate(c, KEY)
        assert 'подтвердить нельзя' in out
        assert '✅ Лицензия активна' not in out

    def test_silent_info_after_activation_says_so(self):
        c = FakeSSH(routes=[
            ('licctl fetch ispmgr', ('', '', 0)),
            ('licctl info ispmgr 2>&1 | head -n 20', ''),
        ])
        out = panels_mod.ispmanager_license_activate(c, KEY)
        assert 'не вернул ничего' in out
        assert '✅ Лицензия активна' not in out

    # ---------- честность про канал передачи ключа ----------
    def test_one_time_key_and_ps_warning(self):
        c = self._fake(info={'days': '200', 'update_days': '400'})
        out = panels_mod.ispmanager_license_activate(c, KEY)
        assert 'Ключ активации одноразовый' in out
        # Врать про «безопасный канал» там, где его нет, нельзя: licctl не
        # умеет принимать ключ из окружения (в отличие от mgrctl -e $ENV).
        assert 'был виден в ps' in out and 'mgrctl -e' in out


# ============== FASTPANEL: ДИАГНОСТИКА И СБРОС ПАРОЛЯ ======================
class TestFastpanelPackageStatus:
    def test_dpkg_wins_and_rpm_is_not_asked(self):
        c = FakeSSH(routes=[('dpkg -l', 'ii  fastpanel2  2.14  amd64')])
        assert panels_mod.fastpanel_package_status(c) == \
            'ii  fastpanel2  2.14  amd64'
        assert c.find('rpm') is None

    def test_rpm_fallback_for_red_hat_family(self):
        # rpm зовётся как `rpm -q` (см. PKG_TOOLS), а не `rpm -qa`.
        c = FakeSSH(routes=[('rpm -q', 'fastpanel2-2.14-1.el8.x86_64')])
        assert panels_mod.fastpanel_package_status(c) == \
            'fastpanel2-2.14-1.el8.x86_64'

    def test_absent_package(self):
        # Инвариант совместимости ПУБЛИЧНОЙ формы (она обязана оставаться
        # строкой). Различение «пакета нет» и «мы не смогли спросить» — в
        # TestFastpanelPackageStates: именно его терял consumer.
        assert panels_mod.fastpanel_package_status(FakeSSH()) == ''


# ============ ПАКЕТ ПАНЕЛИ: «НЕ НАЙДЕН» против «НЕ ПРОВЕРЕН» ================
class TestFastpanelPackageStates:
    """Таблица состояний пакетного менеджера.

    Прежний вид (panels.py):

        dpkg -l 2>/dev/null | grep -i 'fastpanel2' | head -3

    терял ДВЕ вещи сразу — ровно как 1.28.0 на systemctl и 1.29.0 на grep'е
    конфигов: `2>/dev/null` глушил причину, а пайп забирал код возврата
    (конвейер отдаёт rc `head`, он доволен всегда). Замер живьём (этот хост,
    uid=1000, реальный /bin/bash + controlled fake-бинарники в PATH):

        есть пакет            rc=0  'ii  fastpanel2-engine 1.2-3 …'
        пакета нет (реальный) rc=1  'dpkg-query: no packages found matching …'
        бинарника нет         rc=127 'bash: dpkg: command not found'
        упал (нет прав)       rc=2  'dpkg: error: cannot access repository lock…'

    ПРЕЖНЯЯ команда на последних трёх давала rc=0 и пустой вывод — идентично
    «пакета нет», а `fastpanel_diag` подписывал это «типичная причина 404 на
    :8888 … apt install fastpanel2». По этой строке решают про переустановку
    панели — самый дорогой вид лжи в серии.

    Локализация (замерено): в русской локали dpkg пишет «шаблону fastpanel2*
    не соответствует ни один пакет» при ТОМ ЖЕ rc=1. Значит текстовым
    маркером быть не может: решение — по rc, а `LC_ALL=C` нужен только чтобы
    ЦИТАТА для оператора была читаемой на любой локали хоста.
    """

    DPKG_FOUND = ('ii  fastpanel2-engine   2.14  amd64   FastPanel engine\n',
                  '', 0)
    DPKG_ABSENT = ('', 'dpkg-query: no packages found matching fastpanel2*\n', 1)
    NO_BINARY = ('', 'bash: dpkg: command not found\n', 127)
    DPKG_DENIED = ('', 'dpkg: error: cannot access repository lock: '
                       'Permission denied\n', 2)
    RU_LOCALIZED = ('', 'dpkg-query: шаблону fastpanel2* не соответствует '
                        'ни один пакет\n', 1)
    # rc=0 без вывода для `dpkg -l шаблон` не бывает (успех обязан
    # совпадением) — значит ответ оборвался.
    TRUNCATED = ('', '', 0)
    RPM_FOUND = ('fastpanel2-2.14-1.el8.x86_64\n', '', 0)
    # `rpm -q` (PKG_TOOLS) на «не установлен» отвечает rc=1, как dpkg, — обе
    # ветки делят одну таблицу. Пустой вывод при rc=0 — это обрыв (см. ниже),
    # а не «пакета нет»: различить их нельзя, поэтому вердикт по пустоте.
    RPM_ABSENT = ('', 'package fastpanel2* is not installed\n', 1)
    # rpm об ошибке (битая БД, нет прав) — rc != 0,1; rc=1 у rpm это ровно
    # «не установлен», поэтому ошибка обязана нести ДРУГОЙ код.
    RPM_DENIED = ('', 'rpm: error: cannot open Packages index: Permission '
                      'denied\n', 2)

    # --- решение принимается по rc, а не по тексту -------------------------

    def test_found_is_found(self):
        c = FakeSSH(routes=[('dpkg', self.DPKG_FOUND)])
        pkg, kind, note = panels_mod.fastpanel_package_status_info(c)
        assert kind == 'found' and 'fastpanel2-engine' in pkg
        assert note == ''

    def test_honest_absent_is_absent_not_unchecked(self):
        # «Пакета нет» — ответ системы, его надо назвать прямо: именно этот
        # случай и есть настоящая причина 404 из KB FastPanel.
        c = FakeSSH(routes=[('dpkg', self.DPKG_ABSENT)])
        _pkg, kind, note = panels_mod.fastpanel_package_status_info(c)
        assert kind == 'absent'
        assert note == ''

    def test_localized_answer_is_still_absent(self):
        # Тот же rc=1, но текст по-русски (реальная ru-локаль хоста). Если бы
        # классификатор искал 'no packages found', локализованный хост слеп бы
        # и получил «не проверено» вместо честного «пакета нет».
        c = FakeSSH(routes=[('dpkg', self.RU_LOCALIZED)])
        _pkg, kind, _note = panels_mod.fastpanel_package_status_info(c)
        assert kind == 'absent'

    def test_missing_binary_is_never_absent_package(self):
        # Хост без dpkg (RHEL/Alpine): «dpkg не выполнен» — это НЕ «пакета
        # нет». Прежний код именно здесь врал всего чаще.
        c = FakeSSH(routes=[('dpkg', self.NO_BINARY), ('rpm', self.RPM_FOUND)])
        pkg, kind, note = panels_mod.fastpanel_package_status_info(c)
        assert kind == 'found' and 'fastpanel2' in pkg   # второй инструмент отработал

    def test_both_tools_unavailable_is_unchecked(self):
        # Ни один менеджер не выполнен → отчёт обязан признать пробел.
        c = FakeSSH(routes=[('dpkg', self.NO_BINARY), ('rpm', self.NO_BINARY)])
        _pkg, kind, note = panels_mod.fastpanel_package_status_info(c)
        assert kind == 'unchecked'
        assert note and 'не провер' in note.lower()
        assert 'НЕ найден' not in note and 'apt install' not in note

    def test_permission_denied_is_unchecked_and_quotes_the_answer(self):
        # Ответ системы цитируется, а не подменяется удобным диагнозом.
        c = FakeSSH(routes=[('dpkg', self.DPKG_DENIED), ('rpm', self.DPKG_DENIED)])
        _pkg, kind, note = panels_mod.fastpanel_package_status_info(c)
        assert kind == 'unchecked'
        assert 'не провер' in note.lower()
        assert 'Permission denied' in note

    def test_dpkg_truncated_and_rpm_unavailable_is_unchecked(self):
        # dpkg при rc=0 обязан совпадать (замер: нет совпадений -> rc=1),
        # поэтому rc=0 без строк — обрыв ответа, а не «пакета нет». Вердикт
        # не вынесен НИ ОДНИМ инструментом: rpm тоже недоступен.
        c = FakeSSH(routes=[('dpkg', self.TRUNCATED), ('rpm', self.NO_BINARY)])
        _pkg, kind, note = panels_mod.fastpanel_package_status_info(c)
        assert kind == 'unchecked'
        assert 'не провер' in note.lower()
        assert 'apt install' not in note

    def test_second_tool_may_give_the_verdict(self):
        # ПАРНЫЙ кейс: обрыв dpkg (rc=0 пусто) не отменяет вердикт второго
        # инструмента. `rpm -q` на «не установлен» отвечает rc=1 — как dpkg, —
        # и именно rc=1 даёт absent (не пустой вывод: та же пустота была бы
        # обрывом канала и обязана остаться пробелом).
        # Поведение rpm на этом хосте НЕ замерено (rpm отсутствует) — форма
        # взята из документации; заперт фиксирует решение, а не замер.
        c = FakeSSH(routes=[('dpkg', self.TRUNCATED), ('rpm', self.RPM_ABSENT)])
        _pkg, kind, _note = panels_mod.fastpanel_package_status_info(c)
        assert kind == 'absent'

    def test_rpm_is_asked_only_when_dpkg_gave_no_verdict(self):
        # DPKG нашёл — второй инструмент не зовём (заперто и раньше).
        c = FakeSSH(routes=[('dpkg', self.DPKG_FOUND)])
        panels_mod.fastpanel_package_status_info(c)
        assert c.find('rpm') is None
        # DPKG уверенно сказал «пакета нет» (Debian-хост) — rpm тоже не нужен.
        c2 = FakeSSH(routes=[('dpkg', self.DPKG_ABSENT)])
        panels_mod.fastpanel_package_status_info(c2)
        assert c2.find('rpm') is None
        # DPKG не ответил (бинарника нет / упал) — спрашиваем rpm.
        c3 = FakeSSH(routes=[('dpkg', self.NO_BINARY), ('rpm', self.RPM_ABSENT)])
        _pkg, kind, _note = panels_mod.fastpanel_package_status_info(c3)
        assert c3.find('rpm') is not None
        assert kind == 'absent'

    def test_silence_is_unchecked_not_absent(self):
        # ИНВЕРТИРОВАННЫЙ КОНТРОЛЬ. Именно этот случай — молчание двойника
        # (нет маршрутов: rc=0 и пусто) — был дырой, найденной при смене формы
        # `rpm -qa → rpm -q`: прежняя ветка «у rpm пустой вывод при rc=0 = нет
        # совпадений» превращала молчание в диагноз, и запертый
        # test_missing_package_explains_404 проходил по НЕВЕРНОЙ причине —
        # «apt install fastpanel2» звучал там, где систему не спросили.
        # Молчание обязано оставаться пробелом (закон серии: «не смогли
        # посмотреть» != «система ответила: нет»).
        c = FakeSSH()
        _pkg, kind, note = panels_mod.fastpanel_package_status_info(c)
        assert kind == 'unchecked'
        assert 'apt install' not in note and 'НЕ найден' not in note
        out = panels_mod.fastpanel_diag(c)
        assert 'Пакет fastpanel2 НЕ найден' not in out

    def test_rpm_empty_rc0_is_unchecked_not_absent(self):
        # КЛЮЧЕВОЙ закон смены формы `rpm -qa → rpm -q`. Пустой вывод при rc=0
        # НЕ переносит неоднозначность: одинаково выглядят «пакета нет» (так
        # отвечал прежний `rpm -qa`) и «канал оборвался», а молчание FakeSSH —
        # именно такое. Различить нельзя никаким маркером (текст rpm содержит
        # само имя пакета), значит по пустоте вердикт выносить нельзя и вердикт
        # «пакета нет» переехал на rc=1 (`rpm -q`).
        c = FakeSSH(routes=[('dpkg', self.NO_BINARY), ('rpm', self.TRUNCATED)])
        _pkg, kind, _note = panels_mod.fastpanel_package_status_info(c)
        assert kind == 'unchecked'

    def test_rpm_error_is_unchecked(self):
        c = FakeSSH(routes=[('dpkg', self.NO_BINARY), ('rpm', self.RPM_DENIED)])
        _pkg, kind, note = panels_mod.fastpanel_package_status_info(c)
        assert kind == 'unchecked' and 'Permission denied' in note

    # --- публичная форма остаётся строкой ----------------------------------

    def test_plain_form_keeps_string(self):
        c = FakeSSH(routes=[('dpkg', self.DPKG_FOUND)])
        assert 'fastpanel2-engine' in panels_mod.fastpanel_package_status(c)
        c2 = FakeSSH(routes=[('dpkg', self.DPKG_ABSENT)])
        assert panels_mod.fastpanel_package_status(c2) == ''
        c3 = FakeSSH(routes=[('dpkg', self.NO_BINARY), ('rpm', self.NO_BINARY)])
        assert panels_mod.fastpanel_package_status(c3) == ''

    def test_output_is_capped_without_head_pipe(self):
        # Ограничение в 3 строки было в пайпе (`| head -3`); без пайпа оно
        # обязано остаться, но на python — иначе rc вернётся не менеджеру.
        body = '\n'.join(f'ii  fastpanel2-mod{i} 1.0 all x' for i in range(9))
        c = FakeSSH(routes=[('dpkg', (body + '\n', '', 0))])
        pkg, kind, _note = panels_mod.fastpanel_package_status_info(c)
        assert kind == 'found'
        assert len(pkg.splitlines()) == 3

    # --- фильтр по имени пакета: он держит отчёт читаемым -------------------

    def test_table_legend_is_not_the_package(self):
        # Поймано ЖИВЫМ контролем на настоящем dpkg этого хоста: `dpkg -l`
        # печатает 5 строк табличной ЛЕГЕНДЫ до строк пакетов
        # ('Desired=Unknown/Install/Remove/Purge/Hold', '||/ Name Version …').
        # Прежний код отсекал их `grep -i fastpanel2`; снимая пайп ради кода
        # возврата, я зря снял вместе с ним и фильтрацию — и отчёт печатал
        # «✅ Пакет панели: Desired=Unknown/…», то есть терял версию пакета,
        # ради которой строку и читают. Фильтрация обязана вернуться, но на
        # python: в пайпе она стоила кода возврата (уроки 1.28.0 и 1.29.0).
        legend = ('Desired=Unknown/Install/Remove/Purge/Hold\n'
                  '| Status=Not/Inst/Conf-files/Unpacked/halF-conf\n'
                  '|/ Err?=(none)/Reinst-required (Status,Err: uppercase=bad)\n'
                  '||/ Name           Version         Architecture Description\n'
                  '+++-==============-===============-============-======\n'
                  'ii  fastpanel2-engine 2.14 amd64 FastPanel engine\n')
        c = FakeSSH(routes=[('dpkg', (legend, '', 0))])
        pkg, kind, _note = panels_mod.fastpanel_package_status_info(c)
        assert kind == 'found'
        assert 'Desired=' not in pkg and '||/ Name' not in pkg
        assert 'fastpanel2-engine' in pkg

    def test_success_without_the_package_name_is_unchecked(self):
        # ПАРНЫЙ кейс: rc=0, текст есть, но НИ ОДНОЙ строки про fastpanel2 —
        # значит это не ответ на наш шаблон (обрыв, чужой вывод). Выдать его
        # за «найденный пакет» — показать оператору чужие строки как панель;
        # этот ответ обязан быть признан пробелом.
        junk = ('some daemon chatter\n'
                'another line without the name\n')
        c = FakeSSH(routes=[('dpkg', (junk, '', 0)),
                            ('rpm', TestFastpanelPackageStates.NO_BINARY)])
        _pkg, kind, note = panels_mod.fastpanel_package_status_info(c)
        assert kind == 'unchecked'
        assert 'fastpanel2' in note.lower()

    def test_rpm_output_is_filtered_by_the_name_too(self):
        # rpm выводит только имена, но фильтр держим одинаковым для обоих
        # инструментов: он же — источник строки пакета в отчёте.
        out = 'nginx-1.20-1.el8.x86_64\nfastpanel2-2.14-1.el8.x86_64\n'
        c = FakeSSH(routes=[('dpkg', self.NO_BINARY), ('rpm', (out, '', 0))])
        pkg, kind, _note = panels_mod.fastpanel_package_status_info(c)
        assert kind == 'found'
        assert pkg == 'fastpanel2-2.14-1.el8.x86_64'

    # --- замок команды: rc обязан принадлежать менеджеру пакетов -----------

    def test_command_gives_rc_to_the_package_manager(self):
        c = FakeSSH(routes=[('dpkg', self.DPKG_ABSENT)])
        panels_mod.fastpanel_package_status(c)
        cmd = c.find('dpkg')
        assert cmd is not None
        assert '2>/dev/null' not in cmd, 'причина пустоты снова в /dev/null'
        assert '2>&1' in cmd
        for part in ('| grep', '| head', '| awk', '| sed'):
            assert part not in cmd, f'в команде остался пайп {part!r}'

    def test_template_is_quoted_against_glob_expansion(self):
        # Замер живьём: без кавычек shell раскрывает fastpanel2* в имена
        # ФАЙЛОВ из cwd, и dpkg отвечает «no packages found matching
        # /…/fastpanel2x» с rc=0 — ложное «пакета нет» при УСТАНОВЛЕЕННОМ
        # пакете. Шаблон обязан дойти до dpkg в кавычках.
        c = FakeSSH(routes=[('dpkg', self.DPKG_ABSENT)])
        panels_mod.fastpanel_package_status(c)
        cmd = c.find('dpkg')
        assert "'fastpanel2*'" in cmd, cmd

    def test_citation_language_is_pinned_with_lc_all(self):
        # На ru-локали цитата dpkg выходит по-русски (замер). rc от локали не
        # зависит, но оператор должен читать одно и то же на любом хосте.
        c = FakeSSH(routes=[('dpkg', self.DPKG_ABSENT)])
        panels_mod.fastpanel_package_status(c)
        assert 'LC_ALL=C' in c.find('dpkg')

    def test_price_is_one_or_two_commands(self):
        c = FakeSSH(routes=[('dpkg', self.DPKG_FOUND)])
        panels_mod.fastpanel_package_status(c)
        assert len(c.commands) == 1
        c2 = FakeSSH(routes=[('dpkg', self.NO_BINARY), ('rpm', self.RPM_FOUND)])
        panels_mod.fastpanel_package_status(c2)
        assert len(c2.commands) == 2


class TestFastpanelDiag:
    def test_healthy(self):
        c = FakeSSH(routes=[
            ('systemctl cat fastpanel2-engine', '[Unit]\n'),
            ('systemctl is-active', 'active'),
            ('journalctl', 'engine started'),
            ('dpkg -l', 'ii  fastpanel2'),
            ('127.0.0.1:8888', '200'),
            ('ls -1 /var/log/fastpanel2', '/var/log/fastpanel2/engine.log\n'),
            ('tail -n 20', 'engine.log line'),
            ('hostname -f', 'www.example.com'),
        ])
        out = panels_mod.fastpanel_diag(c)
        assert '✅ Служба fastpanel2-engine: active' in out
        assert 'engine started' in out
        assert '✅ Пакет панели: ii  fastpanel2' in out
        assert ':8888 (https с localhost): 200' in out
        assert 'engine.log line' in out
        # FQDN в порядке — совет про hostnamectl не к месту
        assert 'hostnamectl' not in out

    def test_missing_package_explains_404(self):
        # Грабля из KB FASTPANEL: 404 на :8888 = снятый пакет панели.
        # Переформулировано объявленно (1.28.0 — для юнита, 1.30.0 — для
        # пакета): раньше тест запирал «пакета нет» за МОЛЧАНИЕМ двойника
        # (FakeSSH без маршрута dpkg = «не проверено»), и «apt install»
        # проходил по неверной причине — через rpm-ветку пустоты при rc=0.
        # Теперь заперт держится за ЧЕСТНЫЙ ответ dpkg (rc=1); молчание
        # признаётся пробелом в test_package_unchecked_is_not_apt_install.
        c = FakeSSH(routes=[('systemctl cat', UNIT_ABSENT),
                            ('dpkg', TestFastpanelPackageStates.DPKG_ABSENT)])
        out = panels_mod.fastpanel_diag(c)
        assert '❌ Служба панели не найдена' in out
        assert 'Пакет fastpanel2 НЕ найден' in out
        assert 'apt install fastpanel2' in out
        assert 'Порт 8888 не отвечает' in out

    def test_package_unchecked_is_not_apt_install(self):
        # Решающий случай слайса. Решающий он потому, что ЭТА строка —
        # самое дорогое решение в отчёте: по ней оператор переустанавливает
        # панель. Прежний fastpanel_diag звал plain-форму (строка или '') и
        # на пустоте печатал «❌ Пакет fastpanel2 НЕ найден — типичная причина
        # 404 … Вернуть: apt install fastpanel2». Пустота же возникала и
        # тогда, когда менеджер пакетов не удалось ВЫПОЛНИТЬ (rc=127 — хост
        # без dpkg, rc=2 — нет прав на базу/lock): замер живьём показал, что
        # прежняя команда на них давала rc=0 и пустой вывод, то есть совет
        # переустанавливать панель звучал на хосте с ЦЕЛОЙ панелью.
        c = FakeSSH(routes=[('systemctl cat', UNIT_ABSENT),
                            ('dpkg', TestFastpanelPackageStates.NO_BINARY),
                            ('rpm', TestFastpanelPackageStates.NO_BINARY)])
        out = panels_mod.fastpanel_diag(c)
        assert 'не провер' in out.lower()
        assert 'Пакет fastpanel2 НЕ найден' not in out
        assert 'apt install' not in out

    def test_honest_absent_package_still_explains_404(self):
        # Найденное нельзя терять ради признания (закон 1.19–1.29): когда
        # менеджер пакетов ЧЕСТНО ответил «пакета нет» (rc=1 у dpkg), это и
        # есть настоящая причина 404 из KB FastPanel — совет обязан остаться.
        c = FakeSSH(routes=[('systemctl cat', UNIT_ABSENT),
                            ('dpkg', TestFastpanelPackageStates.DPKG_ABSENT)])
        out = panels_mod.fastpanel_diag(c)
        assert 'Пакет fastpanel2 НЕ найден' in out
        assert 'apt install fastpanel2' in out
        assert 'не провер' in out.lower()

    def test_hostname_without_dot_hint(self):
        c = FakeSSH(routes=[('systemctl cat', '[Unit]'),
                            ('hostname -f', 'srv123')])
        out = panels_mod.fastpanel_diag(c)
        assert 'hostname «srv123» без точки' in out
        assert 'hostnamectl hostname' in out

    def test_empty_log_reported_as_empty(self):
        c = FakeSSH(routes=[('ls -1 /var/log/fastpanel2',
                             '/var/log/fastpanel2/engine.log\n'),
                            ('tail -n 20', '')])
        assert '(файл пуст)' in panels_mod.fastpanel_diag(c)


class TestFastpanelResetPassword:
    def test_empty_password_does_nothing(self):
        c = FakeSSH()
        out = panels_mod.fastpanel_reset_password(c, '')
        assert '❌ Пароль не задан' in out
        assert c.commands == []

    def test_short_password_rejected_by_panel_rules(self):
        # FASTPANEL сам требует >= 8 символов: не отправляем заведомо
        # отклоняемую команду
        c = FakeSSH()
        out = panels_mod.fastpanel_reset_password(c, 'abc123')
        assert 'не короче 8 символов' in out
        assert c.commands == []

    def test_success_quotes_password_and_warns(self):
        c = FakeSSH()
        out = panels_mod.fastpanel_reset_password(c, "Str0ng! P'a'ss")
        assert '✅ Пароль изменён' in out
        assert 'виден в ps' in out
        parts = shlex.split(c.find('mogwai chpasswd'))
        assert '--username=fastuser' in parts
        assert "--password=Str0ng! P'a'ss" in parts
        assert c.count('mogwai chpasswd') == 1

    def test_failure_shows_stderr(self):
        c = FakeSSH(default=('', 'mogwai: only root', 1))
        out = panels_mod.fastpanel_reset_password(c, 'LongEnough1')
        assert '❌ Не удалось (rc=1): mogwai: only root' in out


# ==================== fastpanel_unit: «НЕ ПРОВЕРЕНО» ≠ «ЮНИТА НЕТ» ==========
# Живой репро (этот хост, PID1=bwrap, systemd нет). Прежняя команда
#
#     systemctl cat UNIT 2>/dev/null | head -1
#
# давала rc=0 и ПУСТОЙ stdout и на «юнита нет», и на мёртвый systemd, и на
# отсутствующий бинарник: пайп с head забирает себе код возврата, а
# 2>/dev/null глушит единственную строку с причиной. Замер:
#
#     fastpanel2-engine        rc=0 out=''   err=''
#     definitely-no-such-unit  rc=0 out=''   err=''
#     systemctl cat ... 2>&1   rc=1 'System has not been booted with systemd
#                                    as init system (PID 1). Can't operate.'
#
# То есть fastpanel_unit возвращал None на ЛЮБОМ хосте без живого systemd, а
# fastpanel_restart по этому «неванию» писал «Служба панели не найдена» и НЕ
# отправлял systemctl restart — оператор лечил отсутствие панели там, где
# нужно было смотреть доступ к systemd.
UNIT_OK = '[Unit]\nDescription=FastPanel 2 engine\n'
UNIT_ABSENT = ('', 'Failed to get unit file list for fastpanel2-engine.unit: '
                   'No such file or directory', 1)
UNIT_DEAD = ('', "System has not been booted with systemd as init system "
                 "(PID 1). Can't operate.\nFailed to connect to bus: Host is down",
             1)
# Грабельный кейс: rc=127 даёт текст «No such file or directory». Если смотреть
# только на текст, «systemctl нет» станет «юнита нет» — ровно та подмена, из-за
# которой оператор пойдёт ставить панель вместо починки PATH.
UNIT_NO_BINARY = ('', 'bash: line 1: systemctl: command not found', 127)


class TestSystemdUnitState:
    """Классификатор ответов systemctl — три разных диагноза вместо None."""

    @pytest.mark.parametrize('out, err, rc, want', [
        (UNIT_OK, '', 0, 'unit'),
        ('', UNIT_ABSENT[1], 1, 'absent'),
        ('', UNIT_DEAD[1], 1, 'unknown'),
        ('', UNIT_NO_BINARY[1], 127, 'unknown'),
        ('', '', 0, 'unknown'),          # сервер молчит: это не «юнита нет»
        ('', 'в чём-то незнакомом', 1, 'unknown'),   # не выдумываем диагноз
    ])
    def test_states(self, out, err, rc, want):
        assert panels_mod.systemd_unit_state(out, err, rc)[0] == want

    def test_missing_binary_wins_over_its_own_text(self):
        # Текст rc=127 содержит «No such file or directory»; проверка по rc
        # обязана идти ДО разбора маркеров отсутствия юнита.
        out, err = panels_mod.systemd_unit_state('', 'sh: systemctl: not found',
                                                127)
        assert out == 'unknown'


class TestFastpanelUnitDistinguishesStates:
    def test_live_unit_is_found_without_confession(self):
        c = FakeSSH(routes=[('systemctl cat', UNIT_OK)])
        unit, why = panels_mod.fastpanel_unit_info(c)
        assert unit == 'fastpanel2-engine' and why is None

    def test_true_absence_is_honest_and_silent(self):
        # Система ОТВЕТИЛА «юнита нет» — это диагноз, а не пробел: признание
        # не нужно, иначе оно обесценит настоящие.
        c = FakeSSH(routes=[('systemctl cat', UNIT_ABSENT)])
        unit, why = panels_mod.fastpanel_unit_info(c)
        assert unit is None and why is None

    def test_dead_systemd_is_not_reported_as_absent_unit(self):
        c = FakeSSH(routes=[('systemctl cat', UNIT_DEAD)])
        unit, why = panels_mod.fastpanel_unit_info(c)
        assert unit is None
        assert why and 'не проверено' in why
        assert 'booted' in why or 'bus' in why

    def test_missing_systemctl_binary_is_unknown_not_absent(self):
        c = FakeSSH(routes=[('systemctl cat', UNIT_NO_BINARY)])
        unit, why = panels_mod.fastpanel_unit_info(c)
        assert unit is None and why is not None
        assert 'не проверено' in why

    def test_silent_server_is_not_reported_as_absent_unit(self):
        unit, why = panels_mod.fastpanel_unit_info(FakeSSH())
        assert unit is None and why is not None and 'не проверено' in why

    def test_second_unit_still_found_after_unknown_first(self):
        # Первый юнит — «не посмотрели», второй ответил «его нет»: находка
        # есть, признания быть не должно.
        c = FakeSSH(routes=[('systemctl cat fastpanel2-engine', UNIT_DEAD),
                            ('systemctl cat fastpanel', UNIT_OK)])
        unit, why = panels_mod.fastpanel_unit_info(c)
        assert unit == 'fastpanel' and why is None

    def test_command_leaves_rc_with_systemctl(self):
        c = FakeSSH()
        panels_mod.fastpanel_unit_info(c)
        cmd = c.find('systemctl cat')
        assert cmd is not None
        assert '2>/dev/null' not in cmd, 'причина пустоты снова в /dev/null'
        assert '2>&1' in cmd
        assert '| head' not in cmd, 'пайп обнуляет rc systemctl'

    def test_wrapper_keeps_plain_shape(self):
        c = FakeSSH(routes=[('systemctl cat', UNIT_OK)])
        assert panels_mod.fastpanel_unit(c) == 'fastpanel2-engine'
        assert panels_mod.fastpanel_unit(FakeSSH(routes=[('systemctl cat',
                                                          UNIT_ABSENT)])) is None


class TestFastpanelRefusalsNameTheirGround:
    """Отказ обязан называть своё основание: «не найдена» и «не посмотрели» —
    разные решения оператора (ставить панель против чинить systemd)."""

    def test_restart_with_dead_systemd_does_not_claim_absence(self):
        c = FakeSSH(routes=[('systemctl cat', UNIT_DEAD)])
        out = panels_mod.fastpanel_restart(c)
        assert '❌' in out
        assert c.find('systemctl restart') is None
        assert 'не проверено' in out
        assert 'не найдена' not in out

    def test_restart_on_true_absence_still_says_absent(self):
        c = FakeSSH(routes=[('systemctl cat', UNIT_ABSENT)])
        out = panels_mod.fastpanel_restart(c)
        assert '❌' in out and 'не найдена' in out
        assert c.find('systemctl restart') is None

    def test_status_without_a_view_says_unchecked(self):
        c = FakeSSH(routes=[('systemctl cat', UNIT_DEAD)])
        out = panels_mod.fastpanel_status(c)
        assert 'не проверено' in out and 'не найдена' not in out

    def test_diag_names_the_blocker(self):
        c = FakeSSH(routes=[('systemctl cat', UNIT_DEAD)])
        out = panels_mod.fastpanel_diag(c)
        assert 'не проверено' in out and 'не найдена' not in out


# ==================== Логи панели: примитив 1.20 вместо слепого ls =========
def _ff(paths=(), dirs=()):
    """Реалистичный ответ примитива поиска: FFDIR-состояния + paths + FFCOUNT.

    Двойник обязан говорить языком системы (урок 1.27.0): 'exists\\n' описывал
    ответ, которого ls не выдаёт никогда, и 1492 теста были зелёными над
    мёртвой функцией.
    """
    out = [f'FFDIR {st} {p}' for st, p in dirs] + list(paths)
    out.append(f'FFCOUNT {len(paths)}')
    return '\n'.join(out) + '\n'


NOTHING = [('FFCOUNT', 'FFCOUNT 0\n')]


class TestFastpanelLogsExplainsGaps:
    def test_closed_log_dir_is_not_reported_as_absent(self):
        c = FakeSSH(routes=[('/var/log/fastpanel2/engine.log',
                             _ff(dirs=[('noperm', '/var/log/fastpanel2')]))]
                    + NOTHING)
        logs, notes = panels_mod.find_fastpanel_logs_info(c)
        assert logs == []
        assert notes and 'прав' in ' '.join(notes)
        assert 'нет на сервере' not in ' '.join(notes)

    def test_missing_log_dir_names_the_path(self):
        c = FakeSSH(routes=[('/var/log/fastpanel2/engine.log',
                             _ff(dirs=[('missing', '/var/log/fastpanel2')]))]
                    + NOTHING)
        logs, notes = panels_mod.find_fastpanel_logs_info(c)
        assert logs == []
        assert '/var/log/fastpanel2' in ' '.join(notes)
        assert 'нет на сервере' in ' '.join(notes)
        assert 'прав' not in ' '.join(notes)

    def test_found_logs_make_no_complaint(self):
        c = FakeSSH(routes=[('/var/log/fastpanel2/engine.log',
                             _ff(paths=['/var/log/fastpanel2/engine.log'],
                                 dirs=[('ok', '/var/log/fastpanel2')]))]
                    + NOTHING)
        logs, notes = panels_mod.find_fastpanel_logs_info(c)
        assert logs == ['/var/log/fastpanel2/engine.log'] and notes == []

    def test_unconfirmed_search_is_confessed_once(self):
        # Пустой ответ без FFDIR/FFCOUNT — «не проверено», а не «логов нет».
        logs, notes = panels_mod.find_fastpanel_logs_info(FakeSSH())
        assert logs == []
        assert len(notes) == 1 and 'не' in notes[0]

    def test_report_carries_the_reason_and_the_paths(self):
        c = FakeSSH(routes=[('/var/log/fastpanel2/engine.log',
                             _ff(dirs=[('noperm', '/var/log/fastpanel2')]))]
                    + NOTHING)
        out = panels_mod.fastpanel_logs(c)
        assert '⚠️' in out
        assert 'прав' in out
        # заперто ранее: пути просмотра обязаны остаться — по ним и чинят
        assert '/var/log/fastpanel2/engine.log' in out

    def test_no_command_blinds_stderr(self):
        c = FakeSSH()
        panels_mod.find_fastpanel_logs_info(c)
        assert c.commands
        for cmd in c.commands:
            assert '2>/dev/null' not in cmd

    def test_wrapper_keeps_plain_list(self):
        c = FakeSSH(routes=[('/var/log/fastpanel2/engine.log',
                             _ff(paths=['/var/log/fastpanel2/engine.log'],
                                 dirs=[('ok', '/var/log/fastpanel2')]))]
                    + NOTHING)
        assert panels_mod.find_fastpanel_logs(c) == \
            ['/var/log/fastpanel2/engine.log']
