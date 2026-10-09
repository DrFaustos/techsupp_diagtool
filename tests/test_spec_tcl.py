"""
Спека PyInstaller обязана класть Tcl-модули (.tm) в раскладку tcl8/<версия>/.

tm-механизм Tcl (tm::Defaults -> tm::roots) ищет модули только в
<dirname(tcl_library)>/tcl8/<major.minor>/, а PyInstaller раскладывает их
плоско в _internal/_tcl_data/tcl8/ — этот путь tm не смотрит. Пока msgcat
не виден, 'package require msgcat' не находит его, и ttkbootstrap падает на
старте с '::msgcat::mcmset: invalid command name' на любой машине без
системного Tcl (релизный бинарник v1.0.0 именно так и не запускался).
"""
import os
import re
import sys
import types

import pytest

SPEC = os.path.join(os.path.dirname(os.path.abspath(__file__)), os.pardir,
                    "ServerDiagnostic.spec")


def _ensure_collect_all() -> None:
    """Дать преамбуле спеки collect_all, если PyInstaller не установлен.

    Преамбула спеки делает `from PyInstaller.utils.hooks import collect_all`,
    а в CI PyInstaller не ставится (он нужен только для сборки). Нам важны
    Tcl-модули, а collect_all разлагает ttkbootstrap/paramiko — его результат
    в этих проверках не читается, поэтому без пакета подставляем стаб.
    """
    try:  # developer-машина: берём настоящий хук
        import PyInstaller.utils.hooks  # noqa: F401
        return
    except ImportError:
        pass
    root = types.ModuleType("PyInstaller")
    utils = types.ModuleType("PyInstaller.utils")
    hooks = types.ModuleType("PyInstaller.utils.hooks")
    setattr(hooks, "collect_all", lambda name: ([], [], []))
    setattr(utils, "hooks", hooks)
    setattr(root, "utils", utils)
    sys.modules.setdefault("PyInstaller", root)
    sys.modules.setdefault("PyInstaller.utils", utils)
    sys.modules.setdefault("PyInstaller.utils.hooks", hooks)


def _spec_datas() -> list:
    """Выполнить преамбулу спеки (до Analysis) и вернуть список datas."""
    with open(SPEC, encoding="utf-8") as fh:
        src = fh.read()
    pre = src.split("a = Analysis(")[0]
    _ensure_collect_all()
    ns = {}
    exec(compile(pre, SPEC, "exec"), ns)
    return list(ns["datas"])


@pytest.fixture(scope="module")
def tm_datas() -> list:
    """Пары (источник, пункт назначения) для всех .tm из спеки.

    Если Tcl-модулей в окружении вообще нет (минимальный образ без tcl-tk),
    раскладку проверить не на чем — скипаем, а не валим прогон.
    """
    tm = [(src, dst) for src, dst in _spec_datas() if src.endswith(".tm")]
    if not tm:
        pytest.skip("в этом окружении нет Tcl-модулей .tm — раскладку проверить нечем")
    return tm


def test_msgcat_lands_in_version_layout(tm_datas):
    msgcat = [dst for src, dst in tm_datas
              if os.path.basename(src).startswith("msgcat")]
    assert msgcat, "msgcat .tm вообще не попадает в бандл"
    for dst in msgcat:
        assert re.fullmatch(r"tcl8/\d+\.\d+", dst), (
            f"msgcat едет в {dst!r}, а tm ищет его в tcl8/<major.minor>/")


def test_no_tm_in_flat_tcl8_dir(tm_datas):
    # Плоский tcl8/ — раскладка, в которой tm модуль НЕ находит (проверено
    # прогоном бандла с закрытым /usr/share/tcltk).
    for src, dst in tm_datas:
        assert dst != "tcl8", f"{src} раскладывается плоско — бинарник упадёт"


def test_tm_sources_exist(tm_datas):
    for src, _dst in tm_datas:
        assert os.path.isfile(src), src
