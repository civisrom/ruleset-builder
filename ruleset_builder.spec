# -*- mode: python ; coding: utf-8 -*-
import sys
from pathlib import Path

root = Path(SPECPATH)
a = Analysis(
    [str(root / 'main.py')],
    pathex=[str(root)],
    binaries=[],
    datas=[(str(root / 'icon.png'), '.')],
    hiddenimports=[],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
)
pyz = PYZ(a.pure)
exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name='RulesetBuilder',
    console=sys.platform not in ('win32', 'darwin'),
    icon=str(root / 'icon.ico') if sys.platform == 'win32' else None,
)
if sys.platform == 'darwin':
    app = BUNDLE(exe, name='RulesetBuilder.app', icon=str(root / 'icon.png'),
                 bundle_identifier='io.github.civisrom.rulesetbuilder')
