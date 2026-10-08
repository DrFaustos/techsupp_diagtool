"""Swap: создание файла подкачки и запись в /etc/fstab с бэкапом и подтверждением.

Вынесено из gui.py без изменений исходников: константы —, функции —, методы create_swap, _do_create_swap, add_swap_to_fstab, _do_add_swap_to_fstab."""

from tkinter import messagebox, simpledialog


class SwapMixin:
    # ---------- ОСТАЛЬНЫЕ ФУНКЦИИ ----------
    def create_swap(self):
        if not self.checker:
            return
        size = simpledialog.askstring(
            "Размер swap",
            "Введите размер swap файла в МБ (например, 1024):",
            parent=self.root
        )
        if not size:
            return
        try:
            size_mb = int(size)
        except ValueError:
            messagebox.showerror("Ошибка", "Введите целое число")
            return

        if messagebox.askyesno("Подтверждение", f"Создать swap файл размером {size_mb} МБ?", parent=self.root):
            self._run_simple(self._do_create_swap, self.swap_btn, None, size_mb)

    def _do_create_swap(self, size_mb):
        lines = [f"=== Создание swap файла размером {size_mb} МБ ==="]
        out, err, rc = self.checker.run("df -m / | awk 'NR==2 {print $4}'")
        free_mb = int(out.strip()) if out.strip().isdigit() else 0
        if free_mb < size_mb + 100:
            lines.append(f"❌ Недостаточно свободного места (доступно {free_mb} МБ, требуется ~{size_mb+100} МБ)")
            return "\n".join(lines)

        cmds = [
            f"fallocate -l {size_mb}M /swapfile 2>/dev/null || dd if=/dev/zero of=/swapfile bs=1M count={size_mb}",
            "chmod 600 /swapfile",
            "mkswap /swapfile",
            "swapon /swapfile"
        ]
        for c in cmds:
            out, err, rc = self.checker.run(c)
            lines.append(f"$ {c}")
            if out.strip():
                lines.append(out.strip())
            if rc != 0 and err.strip():
                lines.append("STDERR: " + err.strip())

        out, err, rc = self.checker.run("swapon --show")
        lines.append("Текущие swap-разделы:\n" + out)
        return "\n".join(lines)

    def add_swap_to_fstab(self):
        if not self.checker:
            return
        self._run_simple(self._do_add_swap_to_fstab, self.fstab_btn)

    def _do_add_swap_to_fstab(self):
        lines = ["=== Добавление /swapfile в /etc/fstab ==="]
        out, err, rc = self.checker.run("grep -q '/swapfile' /etc/fstab && echo 'yes' || echo 'no'")
        if out.strip() == 'yes':
            lines.append("Запись /swapfile уже присутствует в fstab.")
            return "\n".join(lines)

        cmd = 'echo "/swapfile none swap sw 0 0" >> /etc/fstab'
        out, err, rc = self.checker.run(cmd)
        lines.append(f"$ {cmd}")
        if rc != 0 and err.strip():
            lines.append("STDERR: " + err.strip())
        out, err, rc = self.checker.run("tail -3 /etc/fstab")
        lines.append("Последние строки /etc/fstab:\n" + out)
        return "\n".join(lines)
