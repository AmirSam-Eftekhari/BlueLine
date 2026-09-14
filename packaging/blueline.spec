# BlueLine PyInstaller spec — SINGLE-FILE BUILD.
#
# Produces exactly one file: dist/BlueLine.exe. No sibling _internal
# folder, no DLLs alongside it, nothing else to copy or ship — the user
# can move that one file anywhere (a USB stick, a different machine, a
# folder with no write access to its parent) and it still runs.
#
# How this is achieved: the EXE() call below bundles every dependency
# (Python runtime, Flask, the UI's HTML/CSS/JS, the app icon) directly
# into the single executable, and there is no COLLECT() step — a
# COLLECT step is what produces the folder-style build, so it's
# deliberately omitted here.
#
# At runtime, PyInstaller unpacks bundled data (the ui/ folder) into a
# temporary directory it manages itself (exposed as sys._MEIPASS) — this
# app already handles that correctly (see app/core/paths.py), including
# storing scan history in a proper per-user data directory rather than
# next to the executable, so the single file truly has no other
# dependency.
#
# Run this ON WINDOWS (this project's build sandbox has no Windows/mingw
# toolchain, so this file is written and reviewed here but the actual
# .exe has to be produced and verified on your machine):
#
#   pip install -r requirements.txt
#   pip install pyinstaller pywebview
#   pyinstaller packaging/blueline.spec
#
# Output: dist/BlueLine.exe  (a single file — that's it, nothing else to ship)

# -*- mode: python ; coding: utf-8 -*-
from pathlib import Path

block_cipher = None
PROJECT_ROOT = Path(SPECPATH).parent  # noqa: F821 (SPECPATH is injected by PyInstaller)
ICON_PATH = PROJECT_ROOT / "ui" / "static" / "assets" / "blueline.ico"

a = Analysis(
    [str(PROJECT_ROOT / "app" / "desktop_launcher.py")],
    pathex=[str(PROJECT_ROOT)],
    binaries=[],
    datas=[
        (str(PROJECT_ROOT / "ui"), "ui"),
    ],
    hiddenimports=[
        "app.api_server", "app.core.orchestrator", "app.core.paths",
        "app.analyzers.python_static", "app.analyzers.js_static", "app.analyzers.java_static",
        "app.analyzers.go_static", "app.analyzers.ruby_static", "app.analyzers.php_static",
        "app.analyzers.c_cpp_static", "app.analyzers.dependency", "app.analyzers.config_analyzer",
        "app.analyzers.web_api", "app.runtime.dynamic", "app.fuzzing.engine", "app.fuzzing.mutator",
        "app.persistence.store", "app.reporting.html_report", "app.reporting.json_report",
        "app.reporting.csv_report", "app.reporting.charts",
    ],
    hookspath=[],
    runtime_hooks=[],
    excludes=[],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,     # bundled INTO the exe (single-file mode)
    a.zipfiles,     # bundled INTO the exe (single-file mode)
    a.datas,        # bundled INTO the exe (single-file mode) — this is the ui/ folder
    [],
    name="BlueLine",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,   # let PyInstaller manage its own temp extraction dir
    console=True,   # keep a console window in v1 so engine logs/errors are visible;
                    # set to False once you've confirmed everything works end to end
    icon=str(ICON_PATH) if ICON_PATH.exists() else None,
)

# Deliberately no COLLECT() step here — COLLECT is what produces the
# folder-style "onedir" build. Single-file output stops at EXE() above.
