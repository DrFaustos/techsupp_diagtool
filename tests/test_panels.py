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
        out = panels_mod.fastpanel_status(FakeSSH())
        assert 'Служба панели не найдена' in out


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


# ============== FASTPANEL: ДИАГНОСТИКА И СБРОС ПАРОЛЯ ======================
class TestFastpanelPackageStatus:
    def test_dpkg_wins_and_rpm_is_not_asked(self):
        c = FakeSSH(routes=[('dpkg -l', 'ii  fastpanel2  2.14  amd64')])
        assert panels_mod.fastpanel_package_status(c) == \
            'ii  fastpanel2  2.14  amd64'
        assert c.find('rpm -qa') is None

    def test_rpm_fallback_for_red_hat_family(self):
        c = FakeSSH(routes=[('rpm -qa', 'fastpanel2-2.14-1.el8.x86_64')])
        assert panels_mod.fastpanel_package_status(c) == \
            'fastpanel2-2.14-1.el8.x86_64'

    def test_absent_package(self):
        assert panels_mod.fastpanel_package_status(FakeSSH()) == ''


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
        # Грабля из KB FASTPANEL: 404 на :8888 = снятый пакет панели
        c = FakeSSH()
        out = panels_mod.fastpanel_diag(c)
        assert '❌ Служба панели не найдена' in out
        assert 'Пакет fastpanel2 НЕ найден' in out
        assert 'apt install fastpanel2' in out
        assert 'Порт 8888 не отвечает' in out

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
