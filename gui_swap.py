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
SWAP_TARGET = '/swapfile'

# Вопрос о свободном месте задаётся ОДНОЙ командой с маркером, а не
# `df -m / | awk …`: у конвейера код возврата принадлежит awk, а не df, поэтому
# «df не найден», «df не смог» и «в выводе нет второй строки» были
# неразличимы и вали пустой строкой. Пустая строка прежним кодом читалась как
# 0 МБ, а 0 МБ — как «места не хватает»: отрицание о диске, которого никто не
# измерял. Маркер даёт три разных мира, и отказ по месту печатается только там,
# где число действительно прочитано.
SWAP_FREE_CMD = ('out=$(df -Pm / 2>&1); rc=$?; '
                 'if [ "$rc" -ne 0 ]; then echo "SWAPFREE fail $rc"; '
                 'else echo "$out" | awk \'NR==2 {print "SWAPFREE ok " $4}\'; fi')


def parse_swap_free(out):
    """('ok', МБ) | ('fail', None) | ('unchecked', None) из ответа маркера.

    'fail' — df вернул ненулевой код (прав/неправ, но он отказал), 'unchecked' —
    маркера нет вовсе (обрыв, awk не нашёл второй строки, команда не дошла).
    Оба — НЕ право сказать «места нет».
    """
    for line in (out or '').splitlines():
        parts = line.split()
        if len(parts) >= 2 and parts[0] == 'SWAPFREE':
            if parts[1] == 'ok' and len(parts) >= 3 and parts[2].isdigit():
                return 'ok', int(parts[2])
            return 'fail', None
    return 'unchecked', None


def parse_swapon(out, target=SWAP_TARGET):
    """True/False/None: активен ли файл подкачки по выводу `swapon --show`.

    None — вывода нет вообще: «не проверено», а не «не активен». Прежний отчёт
    печатал список как есть: пустой список после упавшего mkswap выглядел как
    «разделов нет», и оператор читал это как факт о системе, а не как провал
    одной из четырёх команд.
    """
    if not (out or '').strip():
        return None
    name = target.rsplit('/', 1)[-1]
    for line in out.splitlines():
        cells = line.split()
        if cells and (cells[0] == target or cells[0].endswith('/' + name)):
            return True
    return False


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
        # Ноль и отрицательное число проходят int() без ошибки, но команды с
        # таким размером не существует: `fallocate -l -5M` отказывает по-своему,
        # а заголовок отчёта уже пообещал «-5 МБ».
        if size_mb <= 0:
            messagebox.showerror("Ошибка", "Размер должен быть больше нуля")
            return

        if messagebox.askyesno("Подтверждение", f"Создать swap файл размером {size_mb} МБ?", parent=self.root):
            self._run_simple(self._do_create_swap, self.swap_btn, None, size_mb)

    def _do_create_swap(self, size_mb):
        lines = [f"=== Создание swap файла размером {size_mb} МБ ==="]
        out, _err, _rc = self.checker.run(SWAP_FREE_CMD)
        state, free_mb = parse_swap_free(out)
        if state != 'ok':
            # Отказ измерить — это НЕ «места нет». Прежний код на пустом выводе
            # (df не установлен, df не смог, в выводе нет второй строки) печатал
            # «Недостаточно свободного места (доступно 0 МБ)» — отрицание о
            # диске, которого никто не мерил.
            lines.append('❌ Свободное место не прочитано (%s) — создание НЕ '
                         'отправлено: решение о месте принимается по числу, а '
                         'не по пустоте.'
                         % ('df отказал' if state == 'fail'
                            else 'ответ не разобран'))
            return "\n".join(lines)
        if free_mb < size_mb + 100:
            lines.append(f"❌ Недостаточно свободного места (доступно {free_mb} МБ, требуется ~{size_mb+100} МБ)")
            return "\n".join(lines)

        cmds = [
            f"fallocate -l {size_mb}M {q(SWAP_TARGET)} 2>/dev/null || dd if=/dev/zero of={q(SWAP_TARGET)} bs=1M count={size_mb}",
            f"chmod 600 {q(SWAP_TARGET)}",
            f"mkswap {q(SWAP_TARGET)}",
            f"swapon {q(SWAP_TARGET)}",
        ]
        for c in cmds:
            out, err, rc = self.checker.run(c)
            lines.append(f"$ {c}")
            if out.strip():
                lines.append(out.strip())
            if rc != 0:
                # Цепочка прерывается на первом отказе. Прежний код гнал все
                # четыре команды всегда: после не создавшегося файла оставались
                # mkswap и swapon со своими отказами, и в отчёте было четыре
                # строки шума вместо одной настоящей причины.
                detail = (err.strip() or out.strip()).splitlines()
                lines.append(f"❌ команда не выполнена (rc={rc})"
                             + (f": {detail[0][:200]}" if detail else '')
                             + ' — остальные команды НЕ отправлены')
                if 'fallocate' not in c and 'dd if=' not in c:
                    # Файл создан (первая команда прошла), а mkswap/swapon
                    # упали: на диске остался осиротевший /swapfile. Само
                    # удаление — решение оператора (файл может быть нужен для
                    # повторной попытки), поэтому советом, а не rm за спиной.
                    lines.append(f'ℹ️ файл {SWAP_TARGET} уже лежит на диске — '
                                 'после починки повторите со второй команды '
                                 f'или уберите: rm -f {SWAP_TARGET}')
                break

        # Состояние спрашивается ВСЕГДА, в том числе после отказа: это единственная
        # строка отчёта, которая говорит о факте, а не о намерении. `swapon -s`
        # — ответ на older util-linux (2.23), где `--show` нет: без запасной
        # формы работающий swap попал бы в «не проверено».
        out, _err, rc = self.checker.run('swapon --show 2>/dev/null')
        if rc != 0:
            out, _err, _rc = self.checker.run('swapon -s 2>/dev/null')
        active = parse_swapon(out)
        if active is None:
            lines.append('❓ Состояние swap не проверено: `swapon --show` и '
                         '`swapon -s` не ответили. Это «мы не спросили», а не '
                         '«файл не активен».')
        elif active:
            lines.append(f'✅ {SWAP_TARGET} активен:\n' + out.strip())
        else:
            lines.append(f'❌ {SWAP_TARGET} в списке активных не найден:\n'
                         + (out.strip() or 'список пуст'))
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
