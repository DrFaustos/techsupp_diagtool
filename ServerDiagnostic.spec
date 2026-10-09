# -*- mode: python ; coding: utf-8 -*-
import glob
import os
import tkinter

from PyInstaller.utils.hooks import collect_all

datas = []
binaries = []
hiddenimports = ['PIL', 'PIL.Image', 'PIL.ImageTk', 'PIL._tkinter_finder']
tmp_ret = collect_all('ttkbootstrap')
datas += tmp_ret[0]; binaries += tmp_ret[1]; hiddenimports += tmp_ret[2]
tmp_ret = collect_all('paramiko')
datas += tmp_ret[0]; binaries += tmp_ret[1]; hiddenimports += tmp_ret[2]


def collect_tcl_modules(library, tcl_version):
    """Tcl-модули (.tm: msgcat, http, platform, tcltest) PyInstaller раскладывает
    плоско в _internal/_tcl_data/tcl8/, а tm-механизм (tm::Defaults -> roots
    dirname(tcl_library)) ищет их в _internal/tcl8/<версия>/. Пока модулей там
    нет, 'package require msgcat' на машине без системного Tcl даёт
    '::msgcat::mcmset: invalid command name', и ttkbootstrap падает на старте.
    Кладём .tm дубликатом в _internal/tcl8/<версия>/ — их найдёт сам tm,
    правки в коде приложения не нужны (проверено прогоном бандла с закрытым
    /usr/share/tcltk)."""
    out, seen = [], set()
    root = os.path.join(library, 'tcl8')
    dest_dir = os.path.join('tcl8', tcl_version)
    for src in sorted(glob.glob(os.path.join(root, '**', '*.tm'), recursive=True)):
        sub = os.path.relpath(os.path.dirname(src), root)  # '' или 'platform'
        dst = dest_dir if sub == '.' else os.path.join(dest_dir, sub)
        key = (dst, os.path.basename(src))
        if key in seen:
            continue
        seen.add(key)
        out.append((src, dst))
    return out


# Tcl-интерпретатор без Tk (useTk=0) — дисплея не требует. Закрывать его нечем:
# у _tkinter.tkapp нет close(), а процесс сборки короткоживущий.
_tcl = tkinter.Tcl()
_tcl_lib = os.path.normpath(_tcl.eval('set tcl_library'))
# 8.6.14 -> 8.6: tm строит пути поиска по major.minor из package provide Tcl
_tcl_ver = '.'.join(_tcl.eval('info patchlevel').split('.')[:2])
datas += collect_tcl_modules(_tcl_lib, _tcl_ver)


a = Analysis(
    ['main.py'],
    pathex=[],
    binaries=binaries,
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
    optimize=0,
)
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name='ServerDiagnostic',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)
