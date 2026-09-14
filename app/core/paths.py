"""
Path resolution for BlueLine.

This module exists for exactly one reason: a single-file PyInstaller
build (`--onefile`) is NOT the same execution environment as running
from source, and code that works in one silently breaks in the other if
it isn't handled explicitly:

  - Bundled data files (the `ui/` folder) are unpacked at runtime into a
    temporary directory (`sys._MEIPASS`), not found next to the script.
  - The current working directory when someone double-clicks a .exe is
    unpredictable — it should not be relied on for where to read UI
    assets from, and writing scan history relative to "wherever the exe
    happened to be launched from" breaks the moment the .exe sits in a
    read-only location (e.g. Program Files) or the user runs it via a
    shortcut with a different working directory.

Every place in the codebase that needs the UI folder or the database
path goes through here instead of constructing paths itself, so the
single-file requirement is satisfied in exactly one place.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path


def is_frozen() -> bool:
    """True when running as a PyInstaller-built executable (onefile or
    onedir), False when running from source with a normal Python interpreter."""
    return bool(getattr(sys, "frozen", False))


def bundle_root() -> Path:
    """Where bundled data files (the ui/ folder) actually live at runtime.

    - Frozen (onefile): PyInstaller unpacks data into a temp dir exposed
      as sys._MEIPASS. This changes on every run — that's expected and fine,
      since it's read-only application assets, not user data.
    - Frozen (onedir): falls back to the executable's own directory.
    - Source: the project root (two levels up from this file).
    """
    if is_frozen():
        meipass = getattr(sys, "_MEIPASS", None)
        if meipass:
            return Path(meipass)
        return Path(sys.executable).resolve().parent
    return Path(__file__).resolve().parent.parent.parent


def ui_dir() -> Path:
    return bundle_root() / "ui"


def user_data_dir() -> Path:
    """Where BlueLine stores scan history — a proper per-user application
    data directory, NOT next to the executable and NOT the current working
    directory. This is what makes the packaged .exe truly standalone: it
    can be moved, run from a read-only location, or launched via a
    shortcut with any working directory, and scan history still persists
    in the same place every time.
    """
    if sys.platform == "win32":
        base = os.environ.get("LOCALAPPDATA") or os.environ.get("APPDATA") or str(Path.home())
        d = Path(base) / "BlueLine"
    elif sys.platform == "darwin":
        d = Path.home() / "Library" / "Application Support" / "BlueLine"
    else:
        base = os.environ.get("XDG_DATA_HOME") or str(Path.home() / ".local" / "share")
        d = Path(base) / "blueline"
    d.mkdir(parents=True, exist_ok=True)
    return d


def default_db_path() -> str:
    return str(user_data_dir() / "blueline_data.sqlite3")
