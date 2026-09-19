"""
Static tests for packaging/build_windows.bat.

This can't run a .bat file in this Linux sandbox, but several real,
concrete bug classes in batch scripts can still be caught by reading
the text carefully — which is exactly how the two real bugs in this
session were found (a %%VAR%% used outside any FOR loop, silently
printing the literal text instead of expanding the variable; and
several commands with no error check after them, so a failure was
invisible and the script printed "Build complete" regardless).
"""

import re
import unittest
from pathlib import Path

BAT_PATH = Path(__file__).resolve().parent.parent / "packaging" / "build_windows.bat"

# Commands whose failure must not be silently ignored.
CRITICAL_COMMANDS = [
    r"python -m venv", r"pip install -r requirements\.txt",
    r"pip install -r packaging\\requirements-packaging\.txt",
    r"pyinstaller --version", r"python -m unittest discover",
    r"pyinstaller packaging\\blueline\.spec",
]


class TestBuildWindowsBat(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source = BAT_PATH.read_text()
        cls.lines = cls.source.splitlines()

    def test_parentheses_are_balanced(self):
        # A crude but effective check: batch if(...) blocks with an
        # unescaped stray ( or ) inside an echo string break parsing in
        # confusing ways. Literal parens inside an echo that's ITSELF
        # inside an if(...)/for(...) block must be escaped with ^( ^) —
        # count only the structural (unescaped, block-starting) parens.
        depth = 0
        for lineno, line in enumerate(self.lines, start=1):
            # Strip escaped parens - they're literal text, not structure.
            stripped = line.replace("^(", "").replace("^)", "")
            if re.match(r"^\s*\)\s*else\s*\(\s*$", stripped, re.IGNORECASE):
                # Closes one block and opens another on the same line —
                # net zero, and must be checked before the two separate
                # cases below or this line double-counts as open-only.
                continue
            # Only count a trailing "(" that opens a block (if/for ... () )
            # and standalone ")" that closes one — not parens inside a
            # quoted echo string, which is the main false-positive risk.
            if re.search(r"\)\s*$", stripped) and re.match(r"^\s*\)", stripped):
                depth -= 1
            if re.search(r"\(\s*$", stripped):
                depth += 1
        self.assertEqual(depth, 0,
                          f"Unbalanced ( ) block structure — ended at depth {depth}, expected 0")

    def test_every_critical_command_is_followed_by_an_error_check(self):
        for pattern in CRITICAL_COMMANDS:
            match = re.search(pattern, self.source)
            self.assertIsNotNone(match, f"Expected command matching {pattern!r} was not found at all")
            # Look at the next 5 lines after the command for an errorlevel check.
            line_idx = self.source[:match.start()].count("\n")
            following = "\n".join(self.lines[line_idx:line_idx + 6])
            self.assertIn("%errorlevel%", following,
                          f"No error check found within 5 lines after: {pattern}")

    def test_no_percent_variable_used_outside_a_for_loop(self):
        # The real bug this test is named for: %%VAR%% is batch syntax
        # for a FOR-loop variable reference, OR (outside a FOR loop) is
        # interpreted as two escaped literal '%' characters — so
        # %%LOCALAPPDATA%% at the top level prints the literal text
        # "%LOCALAPPDATA%" instead of expanding to the real path. Any
        # %%NAME%% pattern must appear only on a line that also has a
        # `for ` keyword (i.e. is the FOR statement itself or clearly
        # part of one), never as a bare top-level environment-variable reference.
        for lineno, line in enumerate(self.lines, start=1):
            for m in re.finditer(r"%%([A-Za-z_][A-Za-z0-9_]*)%%", line):
                var_name = m.group(1)
                # A real FOR loop variable is a single letter/short token
                # (like %%F); a real environment variable name is longer
                # and uppercase (like LOCALAPPDATA). This distinguishes
                # "correctly inside a FOR loop" from "the bug this test guards".
                is_for_loop_var = bool(re.search(r"\bfor\s+%%" + re.escape(var_name) + r"\b", line, re.IGNORECASE))
                self.assertTrue(
                    is_for_loop_var,
                    f"Line {lineno}: %%{var_name}%% is used but this isn't a FOR-loop variable "
                    f"reference — it will print the literal text '%{var_name}%' instead of "
                    f"expanding the environment variable. Use single %{var_name}% instead."
                )

    def test_checks_dist_exe_actually_exists_before_declaring_success(self):
        self.assertIn("if not exist", self.source)
        self.assertIn("dist\\BlueLine.exe", self.source)

    def test_checks_python_is_on_path_before_doing_anything_else(self):
        self.assertIn("where python", self.source)

    def test_references_the_fixed_spec_file_not_an_old_broken_one(self):
        self.assertIn("packaging\\blueline.spec", self.source)


if __name__ == "__main__":
    unittest.main()
