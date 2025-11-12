# block_mobiles_with_oui.spec
# Spécification PyInstaller personnalisée pour créer l'exécutable Windows

# Import de PyInstaller
from PyInstaller.utils.hooks import collect_submodules

# Inclure tous les sous-modules d'encodage (évite certains problèmes)
hiddenimports = collect_submodules('encodings')

block_cipher = None

a = Analysis(
    ['block_mobiles_with_oui.py'],  # Ton script Python
    pathex=['.'],                   # Dossier actuel
    binaries=[],
    datas=[],
    hiddenimports=hiddenimports,
    hookspath=[],
    runtime_hooks=[],
    excludes=[],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
)

exe = EXE(
    a.pure,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    [],
    name='BlockMobileFirewall',  # Nom de ton .exe final
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,  # <---- pas de console visible
    uac_admin=True, # <---- demande UAC admin
)
