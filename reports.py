"""Сводный отчёт по диагностике."""
from metrics import metrics_report, firewall_report, web_config_report
from logs import site_logs_report


def full_diagnostic_report(checker, panel):
    lines = []
    lines.append(f"=== Начинаем диагностику сервера {checker.host}:{checker.port} ===")
    lines.append(f"Тип панели управления: {panel}\n")
    lines.append(metrics_report(checker))
    lines.append("\n" + firewall_report(checker))
    lines.append("\n" + web_config_report(checker))
    lines.append("\n" + site_logs_report(checker, panel))
    lines.append("\n=== ДИАГНОСТИКА ЗАВЕРШЕНА ===")
    return "\n".join(lines)
