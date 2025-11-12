# -*- mode: python ; coding: utf-8 -*-

block_cipher = None

import sys
import os

# Chemin vers ton script Python
script_path = os.path.abspath("block_mobile_and_firewall.py")

a = Analysis(
    [script_path],
    pathex=[os.path.dirname(script_path)],
    binaries=[],
    datas=[],
    hiddenimports=[],
    hookspath=[],
    runtime_hooks=[],
    excludes=[],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name="BlockMobileFirewall",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    console=False,          # <- Ne montre pas de console
    uac_admin=True,         # <- Demande les droits admin
)

coll = COLLECT(
    exe,
    a.binaries,
    a.zipfiles,
    a.datas,
    strip=False,
    upx=True,
    name="BlockMobileFirewall"
)
