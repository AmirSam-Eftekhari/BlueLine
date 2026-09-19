# BlueLine PyInstaller spec — SINGLE-FILE BUILD
#
# Produces:
#     dist/BlueLine.exe
#
# No COLLECT() step is used, so this is a true --onefile build.
#
# Build on Windows:
#
#     pip install -r requirements.txt
#     pip install pyinstaller pywebview
#     pyinstaller --clean packaging/blueline.spec
#
# Output:
#
#     dist/BlueLine.exe


from pathlib import Path


# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------

# SPECPATH is provided by PyInstaller and points to the directory containing
# this .spec file.
#
# Project layout:
#
#   BlueLine/
#   ├── app/
#   ├── ui/
#   ├── packaging/
#   │   └── blueline.spec
#   └── ...
#
SPEC_DIR = Path(SPECPATH).resolve()
PROJECT_ROOT = SPEC_DIR.parent

ENTRY_POINT = PROJECT_ROOT / "app" / "desktop_launcher.py"
UI_DIR = PROJECT_ROOT / "ui"
ICON_PATH = UI_DIR / "static" / "assets" / "blueline.ico"


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------

if not ENTRY_POINT.exists():
    raise FileNotFoundError(
        f"BlueLine entry point not found:\n{ENTRY_POINT}"
    )

if not UI_DIR.exists():
    raise FileNotFoundError(
        f"BlueLine UI directory not found:\n{UI_DIR}"
    )


# ---------------------------------------------------------------------------
# Analysis
# ---------------------------------------------------------------------------

a = Analysis(
    [str(ENTRY_POINT)],

    pathex=[
        str(PROJECT_ROOT),
    ],

    binaries=[],

    datas=[
        # Bundle the complete UI into the executable.
        #
        # At runtime PyInstaller extracts this into _MEIPASS/ui.
        (str(UI_DIR), "ui"),
    ],

    hiddenimports=[
        # Core
        "app.api_server",
        "app.core.orchestrator",
        "app.core.paths",

        # Static analyzers
        "app.analyzers.python_static",
        "app.analyzers.js_static",
        "app.analyzers.java_static",
        "app.analyzers.go_static",
        "app.analyzers.ruby_static",
        "app.analyzers.php_static",
        "app.analyzers.rust_static",
        "app.analyzers.kotlin_static",
        "app.analyzers.swift_static",
        "app.analyzers.scala_static",
        "app.analyzers.c_cpp_static",

        # Other analyzers
        "app.analyzers.dependency",
        "app.analyzers.config_analyzer",
        "app.analyzers.web_api",
        "app.analyzers.binary_analysis",
        "app.analyzers.elf_parser",

        # Runtime / fuzzing
        "app.runtime.dynamic",
        "app.fuzzing.engine",
        "app.fuzzing.mutator",

        # Persistence / logging
        "app.persistence.store",
        "app.core.logging_setup",

        # Reporting
        "app.reporting.html_report",
        "app.reporting.json_report",
        "app.reporting.csv_report",
        "app.reporting.charts",
        "app.reporting.pdf_report",
    ],

    hookspath=[],
    runtime_hooks=[],

    excludes=[],

    # Keep Python modules in the PYZ archive.
    noarchive=False,
)


# ---------------------------------------------------------------------------
# Python bytecode archive
# ---------------------------------------------------------------------------

pyz = PYZ(
    a.pure,
    a.zipped_data,
)


# ---------------------------------------------------------------------------
# Single-file executable
# ---------------------------------------------------------------------------
#
# IMPORTANT:
# There is intentionally NO COLLECT() call.
#
# EXE() receives:
#   - Python bytecode
#   - native binaries / DLLs
#   - zipfiles
#   - bundled data
#
# and creates one executable.

exe = EXE(
    pyz,

    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,

    [],

    name="BlueLine",

    debug=False,

    bootloader_ignore_signals=False,

    strip=False,

    upx=True,
    upx_exclude=[],

    # Keep console enabled initially so startup/build/runtime errors
    # are visible during validation.
    console=True,

    icon=str(ICON_PATH) if ICON_PATH.exists() else None,

    # Single-file executable.
    #
    # PyInstaller extracts bundled resources to a temporary _MEI* directory
    # at runtime and removes them when the process exits.
    #
    # No external _internal directory is produced.
)