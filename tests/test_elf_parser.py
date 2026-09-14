import unittest
from pathlib import Path

from app.analyzers.elf_parser import extract_strings, parse_elf

FIXTURES = Path(__file__).resolve().parent.parent / "test-targets" / "vulnerable-binaries"


class TestElfParser(unittest.TestCase):
    """Ground truth for these fixtures was independently confirmed with
    `file` and `readelf -d` on the real compiled binaries before writing
    these assertions (see docs/ARCHITECTURE.md for the exact commands)."""

    def test_dynamic_pie_binary(self):
        info = parse_elf(str(FIXTURES / "normal_dynamic"))
        self.assertTrue(info.is_elf)
        self.assertEqual(info.bitness, 64)
        self.assertEqual(info.machine, "x86-64")
        self.assertTrue(info.is_pie)
        self.assertFalse(info.stripped)
        self.assertFalse(info.statically_linked)
        self.assertIn("libc.so.6", info.needed_libraries)
        self.assertEqual(info.parse_warnings, [])

    def test_static_binary_has_no_needed_libraries(self):
        info = parse_elf(str(FIXTURES / "normal_static"))
        self.assertTrue(info.is_elf)
        self.assertTrue(info.statically_linked)
        self.assertEqual(info.needed_libraries, [])
        self.assertFalse(info.is_pie)  # static builds default to non-PIE in this test environment

    def test_stripped_binary_detected(self):
        info = parse_elf(str(FIXTURES / "normal_stripped"))
        self.assertTrue(info.stripped)
        # Stripping symbols doesn't remove dynamic linking info.
        self.assertIn("libc.so.6", info.needed_libraries)

    def test_nopie_binary_detected(self):
        info = parse_elf(str(FIXTURES / "normal_nopie"))
        self.assertFalse(info.is_pie)
        self.assertEqual(info.elf_type_raw, 2)  # ET_EXEC

    def test_pie_binary_detected(self):
        info = parse_elf(str(FIXTURES / "normal_pie"))
        self.assertTrue(info.is_pie)
        self.assertEqual(info.elf_type_raw, 3)  # ET_DYN

    def test_non_elf_file_is_not_an_error(self):
        info = parse_elf(str(FIXTURES.parent / "vulnerable-python" / "app_vuln.py"))
        self.assertFalse(info.is_elf)
        self.assertEqual(info.parse_warnings, [])  # "not an ELF" is not a parse failure

    def test_truncated_file_does_not_crash(self):
        import tempfile
        with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as f:
            f.write(b"\x7fELF" + b"\x00" * 10)  # magic present, everything else missing
            path = f.name
        try:
            info = parse_elf(path)  # must not raise
            self.assertTrue(info.is_elf)
        finally:
            import os
            os.unlink(path)

    def test_garbage_file_does_not_crash(self):
        import tempfile
        with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as f:
            f.write(bytes(range(256)) * 4)
            path = f.name
        try:
            info = parse_elf(path)  # must not raise
            self.assertFalse(info.is_elf)
        finally:
            import os
            os.unlink(path)

    def test_nonexistent_file_does_not_crash(self):
        info = parse_elf("/definitely/does/not/exist")
        self.assertFalse(info.is_elf)
        self.assertTrue(info.parse_warnings)

    def test_fuzz_truncation_and_corruption_never_crashes(self):
        """Broken target = test data, not an analyzer failure (project-wide
        principle) — enforced here with 500 randomly truncated/corrupted
        variants of a real binary. Fixed seed for reproducibility."""
        import random
        import tempfile
        import os

        with open(FIXTURES / "normal_dynamic", "rb") as f:
            real_data = f.read()

        rng = random.Random(42)
        for i in range(500):
            data = bytearray(real_data)
            if rng.choice([True, False]):
                data = data[:rng.randint(0, len(data))]
            else:
                for _ in range(rng.randint(1, 20)):
                    idx = rng.randint(0, len(data) - 1)
                    data[idx] = rng.randint(0, 255)

            with tempfile.NamedTemporaryFile(delete=False) as tf:
                tf.write(bytes(data))
                path = tf.name
            try:
                parse_elf(path)  # must never raise, regardless of how mangled the input is
            except Exception as e:  # pragma: no cover
                self.fail(f"parse_elf raised on fuzz iteration {i}: {e.__class__.__name__}: {e}")
            finally:
                os.unlink(path)


class TestStringExtraction(unittest.TestCase):
    def test_extracts_known_strings_from_real_binary(self):
        strings = extract_strings(str(FIXTURES / "normal_dynamic"))
        # The binary's own source printed "%s %f\n" and linked against
        # libc.so.6 — that library name is a printable string in the
        # dynamic section, a very reliable "did extraction actually work" check.
        self.assertTrue(any("libc.so.6" in s for s in strings))

    def test_respects_minimum_length(self):
        import tempfile, os
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(b"\x00ab\x00abcdef\x00cd\x00")
            path = f.name
        try:
            strings = extract_strings(path, min_length=5)
            self.assertIn("abcdef", strings)
            self.assertNotIn("ab", strings)
            self.assertNotIn("cd", strings)
        finally:
            os.unlink(path)

    def test_nonexistent_file_returns_empty_not_a_crash(self):
        self.assertEqual(extract_strings("/definitely/does/not/exist"), [])


if __name__ == "__main__":
    unittest.main()
