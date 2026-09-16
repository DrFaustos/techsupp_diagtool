"""Сводный отчёт по диагностике."""
from metrics import metrics_report, firewall_report, web_config_report
from logs import site_logs_report

# Этапы полной диагностики (для индикатора прогресса 1/8 ... 8/8)
STAGES = [
    "Метрики системы",
    "Файрвол",
    "Конфигурация веб-сервера",
    "Логи сайтов",
]


def full_diagnostic_report(checker, panel, progress_cb=None):
    """Сводный отчёт. progress_cb(step, total, name) вызывается по этапам."""
    lines = []
    lines.append(f"=== Начинаем диагностику сервера {checker.host}:{checker.port} ===")
    lines.append(f"Тип панели управления: {panel}\n")

    steps = [
        ("Метрики системы", lambda: metrics_report(checker)),
        ("Файрвол", lambda: firewall_report(checker)),
        ("Конфигурация веб-сервера", lambda: web_config_report(checker)),
        ("Логи сайтов", lambda: site_logs_report(checker, panel)),
    ]
    total = len(steps)
    for i, (name, fn) in enumerate(steps, 1):
        if progress_cb:
            try:
                progress_cb(i, total, name)
            except Exception:
                pass
        if i > 1:
            lines.append("\n")
        lines.append(fn())

    lines.append("\n=== ДИАГНОСТИКА ЗАВЕРШЕНА ===")
    return "\n".join(lines)
