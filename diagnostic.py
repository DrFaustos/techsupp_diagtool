"""
Фасад модуля диагностики.

Раньше весь код был в одном файле; теперь он разбит на модули:
  - common.py   — конфигурации и вспомогательные функции
  - metrics.py  — определение панели, метрики, отчёты, веб-конфиг
  - logs.py     — поиск/анализ логов, домены, OOM
  - dns.py      — DNS-проверки и резолверы
  - files.py    — файлы, конфиги, замена IP, перезапуск служб
  - panels.py   — управление ISPmanager
  - reports.py  — сводный отчёт

Этот модуль сохранён для обратной совместимости импортов (gui.py импортирует
всё именно отсюда). Прямое использование модулей предпочтительнее в новом коде.
"""
# --- common ---
from common import (  # noqa: F401
    BACKUP_DIR, BACKUP_SUBDIRS, LOG_PATHS, DOMAIN_PATHS,
    q, ensure_backup_dir, create_backup, save_crontab_backup,
    write_remote_file, find_files, find_file, read_file_content,
    get_domain_from_config,
)

# --- metrics ---
from metrics import (  # noqa: F401
    detect_panel, get_metrics,
    disk_memory_report, network_report,
    check_web_config,
    metrics_report, firewall_report, web_config_report,
)

# --- logs ---
from logs import (  # noqa: F401
    find_logs, parse_access_log_line, filter_by_date,
    analyze_access_log, get_domains, check_site_logs, site_logs_report,
    search_oom_logs,
)

# --- dns ---
from dns import (  # noqa: F401
    dns_report_local, dns_report, dns_resolvers_report,
    get_current_dns_resolvers, set_dns_resolvers,
)

# --- files ---
from files import (  # noqa: F401
    write_file, read_file, get_config_files,
    replace_ipv4, replace_ipv6, restart_services,
)

# --- panels ---
from panels import (  # noqa: F401
    ispmanager_restart, ispmanager_kill_core, ispmanager_update,
    ispmanager_ssl_issue, ispmanager_disable, ispmanager_disable_geoip,
    ispmanager_check_cron_path, ispmanager_fix_cron_path,
)

# --- reports ---
from reports import full_diagnostic_report  # noqa: F401


__all__ = [
    'BACKUP_DIR', 'BACKUP_SUBDIRS', 'LOG_PATHS', 'DOMAIN_PATHS',
    'q', 'ensure_backup_dir', 'create_backup', 'save_crontab_backup',
    'write_remote_file', 'find_files', 'find_file', 'read_file_content',
    'get_domain_from_config',
    'detect_panel', 'get_metrics',
    'disk_memory_report', 'network_report', 'check_web_config',
    'metrics_report', 'firewall_report', 'web_config_report',
    'find_logs', 'parse_access_log_line', 'filter_by_date',
    'analyze_access_log', 'get_domains', 'check_site_logs', 'site_logs_report',
    'search_oom_logs',
    'dns_report_local', 'dns_report', 'dns_resolvers_report',
    'get_current_dns_resolvers', 'set_dns_resolvers',
    'write_file', 'read_file', 'get_config_files',
    'replace_ipv4', 'replace_ipv6', 'restart_services',
    'ispmanager_restart', 'ispmanager_kill_core', 'ispmanager_update',
    'ispmanager_ssl_issue', 'ispmanager_disable', 'ispmanager_disable_geoip',
    'ispmanager_check_cron_path', 'ispmanager_fix_cron_path',
    'full_diagnostic_report',
]
