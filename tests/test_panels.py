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
