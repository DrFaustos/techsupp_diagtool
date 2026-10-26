"""Сторож релизной истории: subject коммита обязан быть текстом, а не кодом.

Зачем этот файл появился (измерено, а не предположено). Релизный коммит v1.32.0
был создан и запушен с subject'ом

    import subprocess, sys sys.path.insert(0, 'tests') import test_text_hygiene as H

то есть первыми строками python-скрипта. Причина: коммит и проверка сообщения
были вызваны двумя heredoc в одной команде

    git commit -q -F - <<'MSG' && venv/bin/python - <<'PY'
    ...
    MSG
    ...
    PY

тело второго ушло в stdin первого. Файлы в коммите были правильные (дерево
совпало с тегом), а проверка текстовой гигиены прошла ЗЕЛЁНОЙ: она смотрела на
склейки букв и не смотрела на то, чем subject является как текст.

Это тот же класс дефекта, что лечит вся серия, только в другом месте: не отчёт
врёт оператору, а история врёт тому, кто читает git log. И та же ошибка метода:
тривиально-зелёная проверка.

Почему guard живёт в этом файле, а не в отдельном модуле. Скрипт, которым чинят
испорченный коммит, лежит в `.ai-free/` и в репозиторий не попадает (каталог в
.gitignore). Тест, который коммитится, не имеет права его импортировать: первый
же прогон на свежем клоне дал бы ImportError, и весь набор стал бы красным по
причине, не связанной с предметом проверки. Поэтому признаки объявлены здесь;
скрипт-фикстура импортирует их отсюда, а не заводит второй набор.

Область: коммиты, на которые указывают теги v* (цепочка релизов). Служебные
коммиты серии под сторож не берутся: guard обязан ловить то, что видно на
странице релиза, а не тонуть в шуме сотен строк.
"""
import re
import subprocess

import common

# Нижняя граница числа релизных тегов: заведомо ниже фактического (проверено
# прогоном). Нужна, чтобы пустой или урезанный список тегов не сделал guard
# тривиально-зелёным — ровно та слепота, из-за которой этот файл появился.
MIN_RELEASE_TAGS = 8

# ==================== РЕШЕНИЕ: что считается дефектом ====================
# Признаки структурированные: subject, в который попал исходник, выдаёт себя
# синтаксисом языка, а не «невнятным вкусом».
CODE_SUBJECT_RES = (
    ('PYTHON-IMPORT', re.compile(r'^\s*(import|from)\s+\w')),
    ('SYSPATH', re.compile(r'sys\.path\.insert')),
    ('HEREDOC', re.compile(r"<<\s*[-']?\w")),
    ('PY-CALL', re.compile(r'venv/|python3?(\s|$)|pytest')),
    ('PY-DEF', re.compile(r'\b(def|lambda|assert|elif)\s')),
    ('PY-DUNDER', re.compile(r'__\w+__')),
    ('STRAY-HEREDOC-TOKEN', re.compile(r'(?<![\w.])PY(?![\w.])')),
)

# От заголовка тега требуется только одно: быть текстом (тот же guard, что и
# для subject коммита). Формат НЕ проверяется, и это решение куплено замером, а
# не удобством. Здесь висел замок «единый формат vX.Y.Z: что закрыто принят с
# v1.28.0». Проход по всем 35 релизным тегам этого репозитория показал, что
# единого формата нет: минимум четыре стиля — «Релиз 1.19.0: …»,
# «build: релиз 1.6.0 …», «rel: v1.1.0 …», «v1.32.0: …» — и при этом все 35
# заголовков являются текстом (BAD itogo: 0).
#
# Замок, которого в истории не было, краснеет на прошлом и тем обесценивает
# настоящие находки: это та же ошибка, что невымеренный лимит в 10 конфигов.
# Требование к формату имел право ввести только объявленный владельцем
# переписывание истории, а не тест, написанный по представлению о series.
STYLE_BASELINE = ('Релиз', 'build', 'rel', 'v')


def subject_defect(subject):
    """Причина, по которой subject не годится на роль текста, либо None."""
    text = (subject or '').strip()
    if not text:
        return 'ПУСТО'
    for name, rx in CODE_SUBJECT_RES:
        if rx.search(text):
            return name
    return None


def git_out(*args):
    """git без shell: именно shell (heredoc) здесь всё и сломал."""
    p = subprocess.run(('git',) + args, capture_output=True, text=True)
    assert p.returncode == 0, 'git %s -> rc=%d: %s' % (
        ' '.join(args), p.returncode, p.stderr[:160])
    return p.stdout.strip()


def commit_defects(sha):
    """[(причина, фрагмент)] для коммита: subject + следы heredoc в теле.

    Тело проверяется отдельным признаком: в испорченном коммите на одной из
    строк тела остался маркер `PY` — то есть в сообщение уехал не только
    subject, а и хвост чужого скрипта. Subject этого не описывает.
    """
    bad = []
    subject = git_out('log', '-1', '--pretty=%s', sha)
    reason = subject_defect(subject)
    if reason:
        bad.append((reason, subject[:80]))
    body = git_out('log', '-1', '--pretty=%b', sha)
    for n, line in enumerate(body.splitlines(), 1):
        if line.strip() in ('PY', 'MSG', 'EOF'):
            bad.append(('ОСТАТОК-HEREDOC-МАРКЕРА',
                        'строка тела %d: %r' % (n, line.strip())))
            break
    return bad


# ==================== РЕЕСТР ИЗВЕСТНОЙ ЛЖИ (самопроверяемый) ==============
# subject коммита v1.32.0 испорчен и уже опубликован (он на origin/main).
# Переписывать опубликованную историю force-push'ем без ведома владельца я не
# вправе, поэтому дефект не прячется, а лежит здесь — с sha, а не с тегом.
#
# Реестр не имеет права становиться свалкой разрешений:
# test_declared_defect_is_actually_there требует, чтобы каждая запись
# соответствовала НАСТОЯЩЕМУ дефекту guard'а. Починят историю — запись станет
# ложью и guard покраснеет сам, молчать не даст.
KNOWN_BROKEN_SUBJECTS = {
    'df825151a45ca1d86095ab87d5db01aa2e9cd590': (
        'subject коммита v1.32.0 = первые строки python-скрипта: два heredoc в '
        'одной команде (git commit -F - && python - <<PY). Файлы в коммите '
        'правильные; описано в CHANGELOG 1.32.1. Лечится заменой коммита (то '
        'же дерево, другое сообщение) — решение о force-push принимает '
        'владелец; скрипт .ai-free/fixup132.py готов.'),
}


def release_tags():
    """ВСЕ теги вида vX.Y.Z — без среза «последние N», чтобы guard не забывал
    собственные релизы, когда серия станет длиннее любого числа."""
    out = git_out('for-each-ref', 'refs/tags/',
                  '--format=%(refname:lstrip=2)', '--sort=-creatordate')
    tags = [t for t in out.split('\n') if re.fullmatch(r'v\d+\.\d+\.\d+', t)]
    assert len(tags) >= MIN_RELEASE_TAGS, (
        'релизных тегов %d, ожидалось не меньше %d: урезанный список — и guard '
        'тривиально зелёный' % (len(tags), MIN_RELEASE_TAGS))
    return tags


def release_commits():
    return [(t, git_out('rev-parse', t + '^{}')) for t in release_tags()]


# ==================== ПРИМЕРЫ: guard обязан видеть и шум ==================
CODE_TRAPS = (
    "import subprocess, sys sys.path.insert(0, 'tests') "
    "import test_text_hygiene as H",
    'venv/bin/python - <<PY import io s = io.open(P).read()',
    'assert not bad, bad[:4]; print(%r)',
    'def build_report(rows): return rows[:10]',
    'PY\nСписок доменов перестал обрезаться молча',
    '__version__ = 1.32.0',
)

OK_SUBJECTS = (
    'Домены больше не обрезаются молча: 10 из 40 были правдой',
    'Пакет панели больше не врёт про переустановку',
    'Fix shell quoting in the config probe command',
    'Сторож текстовой гигиены расширен до 10 файлов',
    'Slices 1.19-1.31: honesty over convenience',
)


class TestCommitSubjectGuard:
    def test_guard_sees_a_code_subject(self):
        # Контрпример ПЕРВЫМ делом: ноль находок неотличим от слепого guard'а
        # (тот же закон, что заперт в test_text_hygiene.py).
        for trap in CODE_TRAPS:
            assert subject_defect(trap), 'GUARD СЛЕПОЙ: %r' % trap[:70]

    def test_guard_accepts_plain_subjects(self):
        # Обратная сторона того же закона: guard, который ловит нормальные
        # subject'ы, обесценивает настоящие находки — шум есть та же слепота.
        for ok in OK_SUBJECTS:
            assert not subject_defect(ok), 'ЛОЖНОЕ срабатывание: %r' % ok[:70]

    def test_every_release_commit_subject_is_text(self):
        # Покрытие: все релизные теги, кроме единственного записанного дефекта.
        broken = set(KNOWN_BROKEN_SUBJECTS)
        bad = []
        for tag, sha in release_commits():
            if sha in broken:
                continue
            found = commit_defects(sha)
            if found:
                bad.append('%s (%s): %s' % (tag, sha[:7], found[0]))
        assert not bad, 'дефекты релизной истории сверх реестра:\n  %s' % (
            '\n  '.join(bad))

    def test_declared_defect_is_actually_there(self):
        # Инвертированный контроль самого реестра: каждая запись обязана
        # указывать на релизный коммит И быть видимой guard'у. Иначе реестр
        # переживёт починку и превратится в разрешение молчать.
        tags = dict(release_commits())
        for sha, why in KNOWN_BROKEN_SUBJECTS.items():
            assert sha in tags.values(), (
                'запись реестра %s не на релизном коммите' % sha[:7])
            assert commit_defects(sha), (
                'реестр считает %s испорченным, а guard его не видит: либо '
                'запись устарела (историю починили — удалить запись), либо '
                'guard слепой. Причина записи: %s' % (sha[:7], why[:60]))

    def test_release_tag_subjects_are_text(self):
        # Измеримое требование к заголовку тега: он обязан быть текстом. Дело не
        # в формате — см. комментарий к замеру 35 тегов выше.
        bad = []
        for tag, _sha in release_commits():
            head = git_out('for-each-ref', 'refs/tags/' + tag,
                           '--format=%(contents:subject)')
            reason = subject_defect(head)
            if reason:
                bad.append('%s: %s — %r' % (tag, reason, head[:70]))
        assert not bad, 'заголовок релизного тега не является текстом:\n  %s' % (
            '\n  '.join(bad))

    def test_series_keeps_several_tag_subject_styles(self):
        # Инвертированный контроль к предыдущему тесту. Пока заголовки
        # разнородны, соблазн «добавить проверку формата» выглядит безвредно и
        # именно поэтому опасен. Замер фиксирует разнородность как ФАКТ
        # истории: если число стилей изменится — историю переписывали, и этот
        # тест обязан быть переписан объявленно, а не подправлен молча.
        styles = set()
        for tag, _sha in release_commits():
            head = git_out('for-each-ref', 'refs/tags/' + tag,
                           '--format=%(contents:subject)')
            styles.add(head.split(':', 1)[0].split()[0])
        seen = tuple(s for s in STYLE_BASELINE
                     if any(st.startswith(s) for st in styles))
        assert len(seen) >= 3, (
            'начал у заголовков тегов %d из ожидаемых минимум 3 (%s): фактические '
            'стили %s — история стала однородной, этот тест надо переписать '
            'объявленно' % (len(seen), '/'.join(STYLE_BASELINE),
                            ' '.join(sorted(styles))))

    def test_guard_covers_the_release_it_ships_in(self):
        # Guard обязан касаться собственного релиза, иначе «починим потом»
        # живёт вечно. До выпуска тега текущего релиза проверяется предыдущий:
        # покрытие полное (release_tags берёт все теги), поэтому вопрос только
        # в том, какой коммит уже существует.
        tags = dict(release_commits())
        current = 'v' + common.__version__
        target = current if current in tags else release_tags()[0]
        assert target in tags, 'guard остался без собственного релиза: %s' % target
        sha = tags[target]
        if sha in KNOWN_BROKEN_SUBJECTS:
            assert commit_defects(sha), 'задекларированный дефект исчез'
        else:
            assert not commit_defects(sha), (
                'собственный релиз %s (%s) не прошёл guard: %s'
                % (target, sha[:7], commit_defects(sha)[0]))
