"""
Minimal ELF parser (stdlib `struct` only — no pyelftools, which wasn't
installable in this build environment's package index).

This implements just enough of the ELF spec to answer the questions the
BlueLine binary analyzer needs: architecture, PIE/no-PIE, stripped or
not, and the list of dynamically-linked library dependencies (DT_NEEDED).
It is NOT a general-purpose ELF library — no relocation processing, no
symbol resolution, no debug-info parsing.

Validated against ground truth from `readelf`/`file` on real binaries
compiled during development (see tests/test_binary_analysis.py):
normal dynamic/PIE, statically-linked, stripped, and non-PIE builds of
the same source file, so every code path here has been checked against
an independent, well-established tool's output on a real binary — not
just against this parser's own assumptions.

64-bit little-endian (x86-64, aarch64) is the fully-tested path, since
that's what this build environment could actually produce and verify.
32-bit and big-endian parsing follow the same spec and are implemented,
but were not validated against a real compiled binary here (no 32-bit
libc / cross toolchain available) — treat those two cases as
lower-confidence.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field

ELF_MAGIC = b"\x7fELF"

EI_CLASS = 4
EI_DATA = 5

E_MACHINE = {
    3: "x86 (32-bit)", 8: "MIPS", 20: "PowerPC", 21: "PowerPC64",
    40: "ARM", 62: "x86-64", 183: "AArch64", 243: "RISC-V",
}

ET_TYPE = {1: "Relocatable", 2: "Executable (no PIE)", 3: "Shared object / PIE", 4: "Core dump"}

PT_INTERP = 3
DT_NEEDED = 1
DT_NULL = 0


@dataclass
class ElfInfo:
    is_elf: bool = False
    bitness: int = 0             # 32 or 64
    endianness: str = ""         # "little" or "big"
    machine: str = "unknown"
    elf_type_raw: int = 0
    elf_type: str = "unknown"
    entry_point: int = 0
    is_pie: bool = False         # ET_DYN AND has PT_INTERP (an executable, not a plain .so)
    interpreter: str = ""
    stripped: bool = True
    statically_linked: bool = True
    needed_libraries: list[str] = field(default_factory=list)
    section_names: list[str] = field(default_factory=list)
    parse_warnings: list[str] = field(default_factory=list)


def parse_elf(path: str) -> ElfInfo:
    info = ElfInfo()
    try:
        with open(path, "rb") as fh:
            data = fh.read()
    except OSError as e:
        info.parse_warnings.append(f"Could not read file: {e}")
        return info

    if len(data) < 4 or data[:4] != ELF_MAGIC:
        return info  # not an ELF file; is_elf stays False, no error — this is a normal "not applicable" case

    info.is_elf = True

    if len(data) < 16:
        info.parse_warnings.append("File has the ELF magic bytes but is too short to contain a "
                                    "full e_ident block — likely truncated or corrupted")
        return info

    ei_class = data[EI_CLASS]
    ei_data = data[EI_DATA]
    info.bitness = 64 if ei_class == 2 else 32 if ei_class == 1 else 0
    info.endianness = "little" if ei_data == 1 else "big" if ei_data == 2 else "unknown"
    endian_char = "<" if info.endianness == "little" else ">"

    if info.bitness not in (32, 64) or info.endianness == "unknown":
        info.parse_warnings.append("Unrecognized ELF class/endianness byte — cannot parse further")
        return info

    try:
        if info.bitness == 64:
            fmt = endian_char + "HHIQQQIHHHHHH"
            size = struct.calcsize(fmt)
            fields = struct.unpack(fmt, data[16:16 + size])
            (e_type, e_machine, e_version, e_entry, e_phoff, e_shoff, e_flags,
             e_ehsize, e_phentsize, e_phnum, e_shentsize, e_shnum, e_shstrndx) = fields
        else:
            fmt = endian_char + "HHIIIIIHHHHHH"
            size = struct.calcsize(fmt)
            fields = struct.unpack(fmt, data[16:16 + size])
            (e_type, e_machine, e_version, e_entry, e_phoff, e_shoff, e_flags,
             e_ehsize, e_phentsize, e_phnum, e_shentsize, e_shnum, e_shstrndx) = fields
    except struct.error as e:
        info.parse_warnings.append(f"Truncated or malformed ELF header: {e}")
        return info

    info.entry_point = e_entry
    info.elf_type_raw = e_type
    info.elf_type = ET_TYPE.get(e_type, f"unknown ({e_type})")
    info.machine = E_MACHINE.get(e_machine, f"unknown (0x{e_machine:x})")

    # -- Program headers: look for PT_INTERP to distinguish a PIE
    # executable (ET_DYN + has an interpreter) from a plain shared
    # library (ET_DYN, no interpreter needed since it's never run directly).
    try:
        ph_fmt = (endian_char + "IIQQQQQQ") if info.bitness == 64 else (endian_char + "IIIIIIII")
        ph_size = struct.calcsize(ph_fmt)
        for i in range(e_phnum):
            off = e_phoff + i * e_phentsize
            if off + ph_size > len(data):
                break
            entry = struct.unpack(ph_fmt, data[off:off + ph_size])
            p_type = entry[0]
            if info.bitness == 64:
                p_offset, p_filesz = entry[2], entry[5]
            else:
                p_offset, p_filesz = entry[1], entry[4]
            if p_type == PT_INTERP:
                raw = data[p_offset:p_offset + p_filesz]
                info.interpreter = raw.split(b"\x00", 1)[0].decode(errors="replace")
    except (struct.error, IndexError) as e:
        info.parse_warnings.append(f"Could not parse program headers: {e}")

    info.is_pie = (e_type == 3 and bool(info.interpreter))

    # -- Section headers: needed for stripped-detection and DT_NEEDED. --
    try:
        sh_fmt = (endian_char + "IIQQQQIIQQ") if info.bitness == 64 else (endian_char + "IIIIIIIIII")
        sh_size = struct.calcsize(sh_fmt)
        if e_shstrndx >= e_shnum or e_shoff == 0:
            return info  # no section headers (common for some stripped/minimal binaries) — not an error

        def read_section(idx: int):
            off = e_shoff + idx * e_shentsize
            raw = struct.unpack(sh_fmt, data[off:off + sh_size])
            # (sh_name, sh_type, sh_flags, sh_addr, sh_offset, sh_size, sh_link, sh_info, sh_addralign, sh_entsize)
            return raw

        shstrtab_hdr = read_section(e_shstrndx)
        shstrtab_off, shstrtab_size = shstrtab_hdr[4], shstrtab_hdr[5]
        shstrtab_data = data[shstrtab_off:shstrtab_off + shstrtab_size]

        def name_at(offset: int) -> str:
            end = shstrtab_data.find(b"\x00", offset)
            return shstrtab_data[offset:end if end != -1 else None].decode(errors="replace")

        sections = {}
        for i in range(e_shnum):
            raw = read_section(i)
            name = name_at(raw[0])
            sections[name] = raw
            info.section_names.append(name)

        info.stripped = ".symtab" not in sections

        if ".dynamic" in sections and ".dynstr" in sections:
            info.statically_linked = False
            dyn_off, dyn_size = sections[".dynamic"][4], sections[".dynamic"][5]
            dynstr_off, dynstr_size = sections[".dynstr"][4], sections[".dynstr"][5]
            dynstr_data = data[dynstr_off:dynstr_off + dynstr_size]

            dyn_entry_fmt = (endian_char + "qQ") if info.bitness == 64 else (endian_char + "iI")
            dyn_entry_size = struct.calcsize(dyn_entry_fmt)
            count = dyn_size // dyn_entry_size
            for i in range(count):
                off = dyn_off + i * dyn_entry_size
                d_tag, d_val = struct.unpack(dyn_entry_fmt, data[off:off + dyn_entry_size])
                if d_tag == DT_NULL:
                    break
                if d_tag == DT_NEEDED:
                    end = dynstr_data.find(b"\x00", d_val)
                    lib_name = dynstr_data[d_val:end if end != -1 else None].decode(errors="replace")
                    info.needed_libraries.append(lib_name)
        else:
            info.statically_linked = True

    except (struct.error, IndexError, KeyError) as e:
        info.parse_warnings.append(f"Could not fully parse section headers: {e}")

    return info


def extract_strings(path: str, min_length: int = 5, max_strings: int = 5000) -> list[str]:
    """A real (if simple) equivalent of the `strings` command: scans raw
    bytes for runs of printable ASCII of at least min_length. Used
    against any binary/executable, not just ELF."""
    try:
        with open(path, "rb") as fh:
            data = fh.read()
    except OSError:
        return []

    results = []
    current = bytearray()
    for byte in data:
        if 32 <= byte < 127:  # printable ASCII
            current.append(byte)
        else:
            if len(current) >= min_length:
                results.append(current.decode("ascii", errors="replace"))
                if len(results) >= max_strings:
                    return results
            current = bytearray()
    if len(current) >= min_length:
        results.append(current.decode("ascii", errors="replace"))
    return results


PE_MACHINE = {0x14c: "x86 (32-bit)", 0x8664: "x86-64", 0x1c0: "ARM", 0xaa64: "ARM64"}
PE_SUBSYSTEM = {2: "Windows GUI", 3: "Windows Console", 1: "Native (driver)"}


@dataclass
class PeInfo:
    is_pe: bool = False
    machine: str = "unknown"
    bitness: int = 0             # 32 or 64, from the optional header magic
    subsystem: str = "unknown"
    number_of_sections: int = 0
    timestamp: int = 0
    parse_warnings: list[str] = field(default_factory=list)


def parse_pe(path: str) -> PeInfo:
    """
    Minimal PE/COFF header parser — deliberately scoped to fixed-offset
    header fields only (machine type, section count, subsystem, build
    timestamp). It does NOT parse the import table (which needs RVA ->
    file-offset translation via section headers, and the resulting DLL
    import list) — that was left out rather than shipped unvalidated,
    since no real Windows PE binary was available in this build
    environment to check it against. What's here was validated against
    a synthetic-but-spec-conformant PE64 file constructed byte-for-byte
    from the documented format (see tests/test_pe_parser.py) — real
    execution of this exact parsing logic against known-correct input,
    just not against a real-world Windows binary.
    """
    info = PeInfo()
    try:
        with open(path, "rb") as fh:
            data = fh.read()
    except OSError as e:
        info.parse_warnings.append(f"Could not read file: {e}")
        return info

    if len(data) < 64 or data[:2] != b"MZ":
        return info  # not a PE file — normal "not applicable" case

    try:
        e_lfanew = struct.unpack("<I", data[0x3C:0x40])[0]
        if e_lfanew + 24 > len(data) or data[e_lfanew:e_lfanew + 4] != b"PE\x00\x00":
            info.parse_warnings.append("MZ header present but no valid PE signature found "
                                        "at the expected offset — likely a plain DOS executable, "
                                        "not a PE file")
            return info

        info.is_pe = True
        coff_off = e_lfanew + 4
        machine, num_sections, timestamp, _symtab_ptr, _num_syms, opt_hdr_size, _characteristics = \
            struct.unpack("<HHIIIHH", data[coff_off:coff_off + 20])
        info.machine = PE_MACHINE.get(machine, f"unknown (0x{machine:x})")
        info.number_of_sections = num_sections
        info.timestamp = timestamp

        opt_off = coff_off + 20
        if opt_hdr_size >= 2 and opt_off + 2 <= len(data):
            magic = struct.unpack("<H", data[opt_off:opt_off + 2])[0]
            info.bitness = 32 if magic == 0x10b else 64 if magic == 0x20b else 0
            # Subsystem field lives at a fixed offset from the start of the
            # optional header, same position for both PE32 and PE32+: 68 bytes in.
            subsystem_off = opt_off + 68
            if subsystem_off + 2 <= len(data):
                subsystem = struct.unpack("<H", data[subsystem_off:subsystem_off + 2])[0]
                info.subsystem = PE_SUBSYSTEM.get(subsystem, f"unknown ({subsystem})")
    except struct.error as e:
        info.parse_warnings.append(f"Truncated or malformed PE header: {e}")

    return info
