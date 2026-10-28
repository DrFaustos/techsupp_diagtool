"""Swap: создание файла подкачки и запись в /etc/fstab с бэкапом и подтверждением.

Вынесено из gui.py без изменений исходников: константы —, функции —, методы create_swap, _do_create_swap, add_swap_to_fstab, _do_add_swap_to_fstab."""

from tkinter import messagebox, simpledialog

from common import file_pattern_info, q

# Путь и запись объявлены константами, а не вшиты в строки команд: вопрос к
# файлу и ответ в него должны называть ОДНО и то же значение (в прежном коде
# путь был написан дважды, и «где именно ищем» с «что именно допишем» могли
# разъехаться правкой одной строки из двух).
FSTAB_PATH = '/etc/fstab'
SWAP_FSTAB_ENTRY = '/swapfile none swap sw 0 0'


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
        # Прежняя форма решала по СЛОВУ, которое печатала ОБОЛОЧКА:
        # «grep -q '/swapfile' /etc/fstab && echo 'yes' || echo 'no'». Замер
        # живьём (.ai-free/localize13222.py, настоящий bash 5.3, настоящие
        # chmod, PATH подменён в env ребёнка): ПЯТЬ миров дают побайтово
        # одинаковый out='no' rc=0 — «файл прочитан, записи нет», «файл есть,
        # chmod 000», «файла нет», «каталог вместо файла», «grep нечем
        # спросить» — и прежняя функция во ВСЕХ ПЯТИ отправляла дописывание.
        # Это первая ложь серии, которая кончается не строкой отчёта, а записью
        # в файл, от которого зависит загрузка машины. Конструкция && || заодно
        # съедает коды возврата: rc всей строки всегда 0, различить миры мог
        # только сам греп (0 есть / 1 прочитан и нет / 2 не открылся / 127
        # нечем спросить), а его код выбрасывался.
        # fixed=True обязателен: искомое — фиксированный текст, а молчаливый
        # -E меняет ОТВЕТ (замер приманкой: -E находит /swapXfile по запросу
        # '/swap.file', -F — нет). Ложное «уже есть» значило бы ОТКАЗ дописать,
        # то есть молчаливый swap, который не включится после перезагрузки.
        pat = file_pattern_info(self.checker, FSTAB_PATH, SWAP_FSTAB_ENTRY,
                                fixed=True)
        if pat['state'] == 'found':
            lines.append('Запись %s уже присутствует в %s — файл не меняем.'
                         % (SWAP_FSTAB_ENTRY, FSTAB_PATH))
            return "\n".join(lines)
        if pat['state'] in ('unreadable', 'unchecked'):
            # Мир «не прочитали» и мир «нечем спросить»: прежний ответ в обоих
            # был одна и та же запись в fstab.
            lines.append('❌ %s: %s — дописывание НЕ отправлено: добавить '
                         'запись в файл, который мы не прочитали, нельзя, а '
                         'дубль в fstab чинится только правкой вручную.'
                         % (FSTAB_PATH, pat['note']))
            return "\n".join(lines)
        if pat['state'] == 'absent':
            lines.append('❌ %s не найден — %s. Дописывание создало бы файл из '
                         'одной строки swap вместо починки пути к конфигу '
                         '(на systemd-хостах fstab законно отсутствует).'
                         % (FSTAB_PATH, pat['note']))
            return "\n".join(lines)
        # rc=1: файл ОТКРЫТ и ПРОЧИТАН, совпадений нет — единственный мир, где
        # дописывание разрешено, и он обязан был остаться прежним жестом.
        cmd = 'echo %s >> %s' % (q(SWAP_FSTAB_ENTRY), q(FSTAB_PATH))
        out, err, rc = self.checker.run(cmd)
        lines.append(f"$ {cmd}")
        if rc != 0 and err.strip():
            lines.append("STDERR: " + err.strip())
        out, err, rc = self.checker.run('tail -3 ' + q(FSTAB_PATH))
        lines.append("Последние строки /etc/fstab:\n" + out)
        return "\n".join(lines)
