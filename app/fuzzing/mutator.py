"""
Mutation engine for BlueLine's fuzzer.

This is a real, working mutation-based generator. It is explicitly
BLACK-BOX: it has no code-coverage feedback loop (that would require
compile-time instrumentation of the target, which is out of scope for a
"point BlueLine at an arbitrary target" tool). It still does something
genuinely useful: systematically generates the classic categories of
adversarial input that trip up naive input handling.
"""

from __future__ import annotations

import random

BOUNDARY_INTS = [-1, 0, 1, 127, 128, 255, 256, 32767, 32768, 65535, 65536,
                 2**31 - 1, 2**31, 2**32 - 1, -(2**31), -(2**63)]

WEIRD_STRINGS = [
    "", " ", "\x00", "\x00" * 8, "A" * 10_000, "A" * 100_000,
    "%s%s%s%s%s%s%s%s", "%n%n%n%n", "{{7*7}}", "${7*7}",
    "../" * 20 + "etc/passwd", "..\\" * 20 + "windows\\system32",
    "'; DROP TABLE users; --", "<script>alert(1)</script>",
    "\u202e\u0000", "😀" * 500, "\r\n\r\n", "NaN", "Infinity", "-Infinity",
    "null", "undefined", "true", "false", "0x41414141",
]

ENCODINGS = ["utf-8", "utf-16", "latin-1"]


class Mutator:
    def __init__(self, seed: int | None = None):
        self.rng = random.Random(seed)

    def boundary_values(self) -> list[str]:
        return [str(v) for v in BOUNDARY_INTS]

    def weird_strings(self) -> list[str]:
        return list(WEIRD_STRINGS)

    def mutate_string(self, base: str, n: int = 20) -> list[str]:
        """Generate n mutations of a seed string using classic fuzzing
        transforms: bit flips, truncation, duplication, byte insertion."""
        out = []
        base_bytes = bytearray(base.encode("utf-8", errors="ignore") or b"seed")
        for _ in range(n):
            b = bytearray(base_bytes)
            choice = self.rng.randint(0, 5)
            if choice == 0 and b:  # flip a random bit
                idx = self.rng.randrange(len(b))
                b[idx] ^= 1 << self.rng.randint(0, 7)
            elif choice == 1:  # truncate
                cut = self.rng.randint(0, max(1, len(b)))
                b = b[:cut]
            elif choice == 2:  # duplicate a chunk
                if b:
                    i = self.rng.randrange(len(b))
                    j = min(len(b), i + self.rng.randint(1, 8))
                    b = b + b[i:j] * self.rng.randint(1, 50)
            elif choice == 3:  # insert random bytes
                pos = self.rng.randrange(len(b) + 1)
                junk = bytes(self.rng.randint(0, 255) for _ in range(self.rng.randint(1, 16)))
                b = b[:pos] + bytearray(junk) + b[pos:]
            elif choice == 4:  # insert a null byte mid-string
                pos = self.rng.randrange(len(b) + 1)
                b = b[:pos] + b"\x00" + b[pos:]
            else:  # oversized repeat
                b = b * self.rng.randint(10, 1000)
            out.append(b.decode("utf-8", errors="replace"))
        return out

    def malformed_json(self) -> list[str]:
        return [
            "{", "}", "[", "]", "{,}", '{"a":}', '{"a": undefined}',
            '{"a": 1, "a": 2}', "null", '{"__proto__": {"polluted": true}}',
            '{"a": ' + ("[" * 5000) + "}", '{"a": "\\u0000"}',
        ]

    def generate_batch(self, seeds: list[str], total: int) -> list[bytes]:
        """Produces a batch of `total` candidate inputs mixing all
        strategies, deduplicated, encoded to bytes for execution."""
        candidates: list[str] = []
        candidates.extend(self.boundary_values())
        candidates.extend(self.weird_strings())
        candidates.extend(self.malformed_json())
        for seed in seeds or ["seed"]:
            remaining = max(0, total - len(candidates))
            if remaining <= 0:
                break
            candidates.extend(self.mutate_string(seed, n=min(remaining, 40)))
        # Pad/trim to requested size
        while len(candidates) < total and seeds:
            candidates.extend(self.mutate_string(self.rng.choice(seeds), n=1))
        candidates = candidates[:total]
        seen = set()
        out = []
        for c in candidates:
            if c in seen:
                continue
            seen.add(c)
            out.append(c.encode("utf-8", errors="replace"))
        return out
