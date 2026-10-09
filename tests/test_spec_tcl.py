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

SPEC = os.path.join(os.path.dirname(__file__), os.pardir, "ServerDiagnostic.spec")


def _spec_datas() -> list:
    """Выполнить преамбулу спеки (до Analysis) и вернуть список datas."""
    with open(SPEC, encoding="utf-8") as fh:
        src = fh.read()
    pre = src.split("a = Analysis(")[0]
    ns = {"collect_all": lambda name: ([], [], [])}  # сторонние пакеты не нужны
    exec(compile(pre, SPEC, "exec"), ns)
    return list(ns["datas"])


def test_tcl_modules_land_in_version_layout():
    tm = [(src, dst) for src, dst in _spec_datas() if src.endswith(".tm")]
    msgcat = [dst for src, dst in tm
              if os.path.basename(src).startswith("msgcat")]
    assert msgcat, "msgcat .tm вообще не попадает в бандл"
    for dst in msgcat:
        assert re.fullmatch(r"tcl8/\d+\.\d+", dst), (
            f"msgcat едет в {dst!r}, а tm ищет его в tcl8/<major.minor>/")


def test_no_tm_in_flat_tcl8_dir():
    # Плоский tcl8/ — раскладка, в которой tm модуль НЕ находит (проверено
    # прогоном бандла с закрытым /usr/share/tcltk).
    for src, dst in _spec_datas():
        if src.endswith(".tm"):
            assert dst != "tcl8", f"{src} раскладывается плоско — бинарник упадёт"


def test_tm_sources_exist():
    for src, _dst in _spec_datas():
        if src.endswith(".tm"):
            assert os.path.isfile(src), src
