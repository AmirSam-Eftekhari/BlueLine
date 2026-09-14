import struct
import tempfile
import unittest
import os

from app.analyzers.elf_parser import parse_pe


def build_minimal_pe64(machine=0x8664, subsystem=3, timestamp=0x12345678, num_sections=1) -> bytes:
    """Constructs a byte-exact, spec-conformant minimal PE32+ file —
    DOS header + PE signature + COFF header + optional header — with no
    section data or real code. This is what tests/test_pe_parser.py
    validates the parser against, since no real Windows binary was
    available in this project's Linux build sandbox. Every field is
    placed at the offset the PE/COFF spec defines; this function is the
    "known-correct" ground truth for the assertions below.
    """
    dos_header = bytearray(64)
    dos_header[0:2] = b"MZ"
    e_lfanew = 64
    struct.pack_into("<I", dos_header, 0x3C, e_lfanew)

    pe_signature = b"PE\x00\x00"

    size_of_optional_header = 112  # enough to include the Subsystem field at +68 plus a margin
    coff_header = struct.pack(
        "<HHIIIHH",
        machine, num_sections, timestamp,
        0,  # PointerToSymbolTable
        0,  # NumberOfSymbols
        size_of_optional_header,
        0x0102,  # Characteristics (EXECUTABLE_IMAGE | ...) — value doesn't matter for this parser
    )

    optional_header = bytearray(size_of_optional_header)
    struct.pack_into("<H", optional_header, 0, 0x20b)  # Magic: PE32+
    struct.pack_into("<H", optional_header, 68, subsystem)

    return bytes(dos_header) + pe_signature + coff_header + bytes(optional_header)


class TestPeParser(unittest.TestCase):
    def _write_and_parse(self, data: bytes):
        with tempfile.NamedTemporaryFile(suffix=".exe", delete=False) as f:
            f.write(data)
            path = f.name
        try:
            return parse_pe(path)
        finally:
            os.unlink(path)

    def test_parses_machine_subsystem_and_timestamp(self):
        data = build_minimal_pe64(machine=0x8664, subsystem=2, timestamp=0xDEADBEEF, num_sections=3)
        info = self._write_and_parse(data)
        self.assertTrue(info.is_pe)
        self.assertEqual(info.machine, "x86-64")
        self.assertEqual(info.subsystem, "Windows GUI")
        self.assertEqual(info.timestamp, 0xDEADBEEF)
        self.assertEqual(info.number_of_sections, 3)
        self.assertEqual(info.bitness, 64)
        self.assertEqual(info.parse_warnings, [])

    def test_console_subsystem(self):
        data = build_minimal_pe64(subsystem=3)
        info = self._write_and_parse(data)
        self.assertEqual(info.subsystem, "Windows Console")

    def test_x86_32_machine_type(self):
        data = build_minimal_pe64(machine=0x14c)
        info = self._write_and_parse(data)
        self.assertEqual(info.machine, "x86 (32-bit)")

    def test_non_pe_file_is_not_an_error(self):
        info = self._write_and_parse(b"not a PE file at all, just text")
        self.assertFalse(info.is_pe)
        self.assertEqual(info.parse_warnings, [])

    def test_elf_file_is_correctly_not_pe(self):
        # An ELF binary starts with different magic bytes ("MZ" is
        # Windows-only) — must not be misidentified as PE.
        from pathlib import Path
        elf_path = Path(__file__).resolve().parent.parent / "test-targets" / "vulnerable-binaries" / "normal_dynamic"
        info = parse_pe(str(elf_path))
        self.assertFalse(info.is_pe)

    def test_mz_header_without_pe_signature(self):
        # A plain DOS executable (MZ header, no PE signature) must be
        # distinguished from a real PE file, not silently misparsed.
        dos_only = bytearray(128)
        dos_only[0:2] = b"MZ"
        struct.pack_into("<I", dos_only, 0x3C, 64)
        dos_only[64:68] = b"XXXX"  # not "PE\x00\x00"
        info = self._write_and_parse(bytes(dos_only))
        self.assertFalse(info.is_pe)
        self.assertTrue(info.parse_warnings)

    def test_truncated_pe_does_not_crash(self):
        data = build_minimal_pe64()
        for cut in range(0, len(data), 7):  # try many truncation points
            info = self._write_and_parse(data[:cut])  # must never raise
            self.assertIsNotNone(info)

    def test_nonexistent_file_does_not_crash(self):
        info = parse_pe("/definitely/does/not/exist")
        self.assertFalse(info.is_pe)
        self.assertTrue(info.parse_warnings)


if __name__ == "__main__":
    unittest.main()
