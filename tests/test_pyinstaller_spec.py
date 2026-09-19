"""
Tests for packaging/blueline.spec.

A PyInstaller .spec file is not a data file — it's a Python script that
PyInstaller `exec()`s with `Analysis`, `PYZ`, `EXE`, `SPECPATH`, and a
few others injected as globals. That means a real bug in it (like the
`cipher=` parameter this project shipped, which PyInstaller 6.0 removed
entirely) doesn't show up as invalid syntax — it's a `TypeError` raised
the moment the constructor runs, which happens before a single byte
reaches `dist/`. That's exactly the failure this project's own user hit:
"the dist folder isn't even created."

This can be caught without a Windows machine or PyInstaller installed:
stub out `Analysis`/`PYZ`/`EXE` with the parameter set current
PyInstaller (6.x) actually accepts — deliberately REJECTING keyword
arguments PyInstaller has removed — and `exec()` the real spec file
against those stubs. If the spec passes a removed parameter, the stub
raises the same `TypeError` a real PyInstaller run would, and this test
fails immediately, in this sandbox, instead of only being discoverable
by a user running a real Windows build.
"""

import ast
import unittest
from pathlib import Path

SPEC_PATH = Path(__file__).resolve().parent.parent / "packaging" / "blueline.spec"


class _StubToc(list):
    """Analysis()/PYZ() outputs are TOC (table of contents) list-likes
    in real PyInstaller; a plain list stands in fine for every use this
    spec file makes of them (attribute access via a.pure/a.scripts/etc.)."""


class StubAnalysis:
    # Deliberately mirrors current PyInstaller's actual accepted kwargs.
    # `cipher` is deliberately NOT in this list — PyInstaller 6.0 removed
    # it, so a spec that still passes it must fail here exactly like it
    # would against the real class.
    def __init__(self, scripts, pathex=None, binaries=None, datas=None,
                 hiddenimports=None, hookspath=None, hooksconfig=None,
                 runtime_hooks=None, excludes=None, noarchive=False,
                 module_collection_mode=None, optimize=0):
        self.scripts = scripts
        self.pathex = pathex or []
        self.binaries = _StubToc(binaries or [])
        self.datas = _StubToc(datas or [])
        self.hiddenimports = hiddenimports or []
        self.pure = _StubToc()
        self.zipped_data = _StubToc()
        self.zipfiles = _StubToc()  # real Analysis attribute (bundled zip-format eggs)


class StubPYZ:
    def __init__(self, toc, zipped_data=None, name=None):
        self.toc = toc


class StubEXE:
    def __init__(self, pyz, scripts, *rest, name=None, debug=False,
                 bootloader_ignore_signals=False, strip=False, upx=True,
                 upx_exclude=None, console=True, icon=None,
                 exclude_binaries=False, **extra_unexpected_kwargs):
        # Any keyword this stub didn't explicitly list lands in
        # **extra_unexpected_kwargs — assert nothing does, which is a
        # more general safety net than hand-picking every removed name.
        if extra_unexpected_kwargs:
            raise TypeError(f"EXE() got unexpected keyword arguments: "
                             f"{sorted(extra_unexpected_kwargs)}")
        self.name = name
        self.console = console
        self.icon = icon


class TestPyInstallerSpecFile(unittest.TestCase):
    @staticmethod
    def _code_only(source: str) -> str:
        """Strips full-line comments before searching for a pattern, so
        this doesn't false-positive on the spec file's own prose
        explaining what NOT to do (e.g. a comment that says 'don't use
        cipher=' would otherwise trip a naive substring search)."""
        return "\n".join(line for line in source.splitlines()
                          if not line.strip().startswith("#"))

    def test_spec_file_is_valid_python_syntax(self):
        source = SPEC_PATH.read_text()
        ast.parse(source, filename=str(SPEC_PATH))  # raises SyntaxError if not

    def test_spec_file_does_not_pass_removed_cipher_parameter(self):
        code = self._code_only(SPEC_PATH.read_text())
        self.assertNotIn("cipher=", code,
                          "cipher= was removed entirely in PyInstaller 6.0 — passing it crashes "
                          "the spec file before dist/ is created")

    def test_spec_executes_successfully_against_current_pyinstaller_api_shape(self):
        """The actual regression test: exec() the real spec file with
        Analysis/PYZ/EXE/SPECPATH stubbed to match what PyInstaller 6.x
        really accepts. This is exactly the failure mode a Windows user
        hit — reproduced and fixed without needing Windows or
        PyInstaller installed here."""
        source = SPEC_PATH.read_text()
        globals_dict = {
            "Analysis": StubAnalysis,
            "PYZ": StubPYZ,
            "EXE": StubEXE,
            "SPECPATH": str(SPEC_PATH.parent),
            "__builtins__": __builtins__,
        }
        try:
            exec(compile(source, str(SPEC_PATH), "exec"), globals_dict)
        except TypeError as e:
            self.fail(f"blueline.spec raised TypeError against the current PyInstaller API shape "
                      f"(this is the exact bug that left dist/ empty for a real user): {e}")

        exe = globals_dict.get("exe")
        self.assertIsNotNone(exe, "spec file did not define an 'exe' object")
        self.assertEqual(exe.name, "BlueLine")

    def test_spec_bundles_the_ui_directory(self):
        source = SPEC_PATH.read_text()
        self.assertIn('"ui"', source)

    def test_spec_has_no_collect_step(self):
        # A COLLECT() call is what produces the folder-style "onedir"
        # build the user explicitly said they don't want.
        code = self._code_only(SPEC_PATH.read_text())
        self.assertNotRegex(code, r"\bCOLLECT\s*\(",
                             "A COLLECT() call would produce a dist/BlueLine/ folder instead of "
                             "a single dist/BlueLine.exe file")


if __name__ == "__main__":
    unittest.main()
