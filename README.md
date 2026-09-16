# BlueLine — Universal Security & Reliability Assessment Platform

*Assume nothing. Test aggressively. Prove what you find.*

BlueLine is an offline-first tool that profiles a target (source
repository, script, or executable), runs every analyzer that genuinely
applies to it, and reports findings with separate severity, confidence,
and validation-status fields — plus an honest account of what was and
wasn't tested. No target data leaves your machine.

## What's real in this build

Everything below is implemented and covered by an automated test in
`tests/` — nothing here is a stub, a mock, or a hand-picked demo:

- **Target discovery** — language/build-system/package-manager/entry-point
  detection from the actual filesystem.
- **Python static analysis** (`FULL_SUPPORT`) — real AST-based rule engine,
  ~15 rule classes (injection, insecure deserialization, weak crypto,
  hardcoded secrets, path traversal, Flask misconfig, etc.), with basic
  same-function taint tracking for SQL-injection detection.
- **JavaScript/TypeScript, Java, Go, Ruby, PHP, Rust, Kotlin, Swift, and
  Scala static analysis** (`PARTIAL_SUPPORT`) — pattern-based, not full
  parsers (see Limitations), each with 6-10 real rules covering
  injection, weak crypto, hardcoded secrets, and language-specific
  issues (TLS misconfig, XXE, LFI, unsafe deserialization, object
  injection, unsafe/transmute, force-unwrap panics, etc.).
- **C/C++ static analysis** (`EXPERIMENTAL`) — pattern-matching on a
  small set of classically dangerous libc calls, deliberately low
  confidence.
- **Web/API analysis** (`PARTIAL_SUPPORT`) — real, read-only HTTP checks
  (GET/HEAD/OPTIONS only, never state-changing) against a live URL
  target: missing security headers, insecure cookie flags, CORS
  misconfiguration (verified by actually sending a probe `Origin` header
  and checking whether the server reflects it), server-banner
  disclosure, and plaintext-HTTP transport. Point BlueLine at
  `http://host:port/` instead of a filesystem path to use it. Not a full
  active vulnerability scanner — no auth/session/injection testing
  against live endpoints in this build.
- **Binary/executable analysis** (`PARTIAL_SUPPORT`) — a real ELF parser
  (built on Python's stdlib `struct`, no external dependency) extracts
  architecture, PIE/no-PIE, stripped/not-stripped, and dynamically
  linked library dependencies. Validated against `readelf`/`file`
  ground truth on 5 real compiled binaries (normal, static, stripped,
  PIE, non-PIE) with an exact match on every property, then
  stress-tested with 500 randomly truncated/corrupted variants of a
  real binary with zero crashes. PE (Windows) header metadata (machine
  type, subsystem, section count, timestamp) is also parsed — validated
  against a synthetic, byte-exact spec-conformant PE64 fixture, since no
  real Windows binary was available in this build environment; the PE
  import table (linked DLLs) is not parsed. Also extracts strings from
  any executable format to catch embedded private keys and hardcoded
  secrets. Mach-O (macOS) gets string extraction only.
- **Dependency analysis** — parses `requirements.txt`/`package.json`,
  checked against a small curated local sample of real historical CVEs.
  Never fabricates a CVE for a package outside that sample.
- **Configuration analysis** — `.env` secret detection, Dockerfile
  misconfiguration checks.
- **Dynamic analysis & fuzzing** — real subprocess sandboxing (CPU/memory
  limits, process-group isolation, timeout handling) and real black-box
  mutation-based fuzzing. Verified to find a planted crash independently
  via both engines, which the correlation layer then merges into one
  `CONFIRMED` finding. Dynamic analysis (not fuzzing, for performance
  reasons — see Limitations) also monitors file and network activity via
  `psutil` polling against the real running process, validated against
  real subprocesses that actually open a file and actually connect to a
  local TCP listener, both correctly detected end-to-end through the
  full orchestrator. Fuzzing is behavior-guided across generations: an
  input that reaches an observably new program behavior gets mutated
  further in the next generation instead of every generation only
  mutating the original static seeds — proven, not just implemented, by
  a head-to-head test against a deliberately staged two-condition bug
  where the old flat approach found it in 0/5 trials and the new
  generational approach found it reliably (see
  `tests/test_fuzzing_generational.py`).
- **Risk engine** — transparent, documented formula (see
  `app/core/risk.py`); severity and confidence are always shown
  separately, never conflated.
- **Coverage engine** — reports what fraction of applicable analysis
  actually ran; a failed analyzer stage shows 0% for that stage, not a
  silently-inflated total.
- **Finding correlation** — deduplicates and merges findings from
  multiple detectors into one root issue.
- **Persistence** — SQLite-backed scan history, thread-safe (a real
  concurrency bug here was caught and fixed during development —
  see `docs/ARCHITECTURE.md`). Stored in a proper per-user app-data
  directory, never next to the executable or tied to the current
  working directory — this is what makes the packaged `.exe` a true
  single standalone file (see Windows `.exe` note below).
- **Structured logging** — five separate JSON-lines log streams
  (application, scanner, analyzer, security, runtime) in your user data
  directory, verified to actually get written during a real scan, and
  verified to never leak finding evidence/secret strings into the
  security log (metadata only — finding ID, category, location).
- **Reporting** — HTML, JSON, SARIF 2.1.0, CSV, and PDF, all genuinely
  generated from real scan data. The HTML report includes real,
  data-driven SVG charts (severity donut, coverage bars) — verified by
  actually rendering the report to an image and inspecting it (see
  `docs/ARCHITECTURE.md`), not just by inspecting the generating code.
  PDF export reuses that same HTML/CSS (converted via `wkhtmltopdf`, a
  system binary) rather than a separate template — verified by
  generating a real multi-page PDF from a real scan and rendering it
  back to an image to confirm it looks right, with a clear, catchable
  error (never a crash) if `wkhtmltopdf` isn't installed.
- **CLI** — `scan`, `report`, `compare`, `history`, with CI-friendly exit
  codes.
- **Local web UI** — served by a Flask API bound to `127.0.0.1` only;
  every screen calls the real API, no mock data anywhere. Includes a
  live severity-breakdown chart on the Findings screen, built from the
  same math as the report's chart (independently verified in Node's V8
  engine — see `docs/ARCHITECTURE.md`). Accessibility was checked, not
  assumed: WCAG AA color-contrast ratios are computed directly from the
  live CSS (`tests/test_accessibility.py`, which caught and fixed a real
  4.5:1-vs-3.6:1 failure in the muted-text color on both themes), nav
  items and finding toggles are real `<button>`s with keyboard support
  and `aria-expanded`/`aria-current` state, the scan profile picker uses
  real radio inputs, and live scan updates go through `aria-live`
  regions.
- **Orchestrator error isolation** — a deliberately broken analyzer in
  the test suite proves one bad analyzer cannot crash the whole scan.

Run `python -m unittest discover -s tests -v` to see all of this for
yourself, including a genuine detection benchmark
(`tests/test_benchmark.py`) against intentionally-vulnerable fixtures in
`test-targets/`.

## Installation

```bash
pip install -r requirements.txt
```

## Running BlueLine

**Web UI (recommended):**
```bash
python -m app.api_server
# then open http://127.0.0.1:8642 in your browser
```

**Desktop window** (opens a native window if `pywebview` is installed,
otherwise falls back to your default browser — see Limitations):
```bash
pip install pywebview   # optional, for a native window
python -m app.desktop_launcher
```

**CLI:**
```bash
python -m app.cli scan /path/to/target --profile standard --out report.html
python -m app.cli report <scan_id> --format sarif
python -m app.cli compare <scan_id_a> <scan_id_b>
python -m app.cli history
```

**Windows `.exe`:** see `packaging/build_windows.bat` — run it on a
Windows machine (see Limitations for why it can't be built here). It
produces a single standalone `dist\BlueLine.exe` — no accompanying
folder or files to ship alongside it. Scan history is stored in your
OS's per-user app-data directory (`%LOCALAPPDATA%\BlueLine` on Windows),
not next to the executable, so the `.exe` can be moved or run from
anywhere, including a read-only location.

## Limitations — read this before trusting a scan

BlueLine tells you what it tested, not that your code is safe. Specific,
current limitations of this build:

1. **JavaScript/TypeScript analysis is regex/pattern-based**, not a real
   AST parser. It will miss issues a real parser would catch (e.g. a
   destructured `const { exec } = require('child_process')` followed by
   a bare `exec(...)` call is not currently recognized) and can
   false-positive on matches inside strings/comments.
2. **C/C++ analysis is experimental** — pattern-matching on ~6 dangerous
   libc calls only, no real parser, no data-flow analysis. Expect both
   false negatives and false positives.
3. **Dependency vulnerability data is a small local sample** (12 entries,
   see `app/analyzers/dependency.py`), not a live feed. A package not
   flagged has NOT been verified safe — it may simply not be in the
   sample. Wire `VulnerabilityFeed` to a real source (OSV.dev, GitHub
   Advisory DB) for production use.
4. **Fuzzing has no code-coverage feedback** (no compile-time
   instrumentation of the target) — but it IS behavior-guided across
   generations, mutating inputs that reach a new observable program
   behavior rather than only ever mutating the original static seeds.
   It will reliably find bugs reachable by its mutation corpus (boundary
   values, malformed structures, oversized/null-byte input, etc.) and
   staged bugs reachable by combining two of those in sequence, but not
   bugs that need a specific, non-obvious input with no observable
   intermediate signal to reach. A target that echoes its input back
   verbatim can make many inputs look "new" to the behavior-guided
   corpus; growth is capped per generation to bound the resulting
   overhead rather than let it consume the whole time budget. Fuzzing
   also does NOT monitor file/network activity (only single-run Dynamic
   Analysis does) — a deliberate tradeoff, since polling every one of
   potentially thousands of fuzz cases would add meaningful overhead.
5. **File/network activity monitoring is polling-based** (every 30ms via
   `psutil`), not a kernel-level hook (no ptrace/eBPF) — a file opened
   and closed faster than the poll interval can be missed. This is a
   real, stated limitation, not a hidden one.
6. **No analyzers for niche/less common languages** (Dart, Elixir,
   Haskell, C#, Perl, etc.) — 11 languages now have real analyzers
   (Python full; JS/TS, Java, Go, Ruby, PHP, Rust, Kotlin, Swift, Scala
   partial; C/C++ experimental). Anything else is detected by target
   discovery but explicitly marked `UNSUPPORTED`, never silently skipped.
7. **Binary analysis: ELF is fully parsed and validated; PE gets header
   metadata only (no import table); Mach-O gets string extraction only**
   — see `docs/SUPPORTED_TARGETS.md` for the exact breakdown and why.
8. **The Web/API analyzer is passive/read-only** — real GET/HEAD/OPTIONS
   checks for headers, cookies, CORS, transport, and banner disclosure
   (see above), verified against a live deliberately-misconfigured local
   test server. It does not test authentication, sessions, or injection
   against a live endpoint, and does not crawl beyond the single URL given.
9. **The Windows `.exe` was written but not built or run** in this
   project's development environment, which had no Windows/mingw
   toolchain and no network route to `pyinstaller`/`pywebview`. The
   `.spec` file and build script are ready to run on Windows — see
   `docs/ARCHITECTURE.md` for the full account of what could and
   couldn't be verified where.
10. **The local API server uses Flask's built-in development server**
   (fine for a single local user; swap in `waitress` if you want a more
   production-grade local server).
11. **PDF export depends on the `wkhtmltopdf` system binary being
   installed** — it isn't bundled with BlueLine (it's a separate OS-level
   install, not a `pip` package). If it's missing, PDF export returns a
   clear error naming what to install rather than crashing or silently
   producing nothing; every other report format is unaffected.

None of this is hidden in the product either — the same capability
levels and limitations surface in the Target Setup screen, the
Settings screen, and every generated report.

## Project layout

See `docs/ARCHITECTURE.md` for the full architecture writeup, including
the plugin interface for adding new analyzers.

## Further documentation

- `docs/CLI.md` — full command reference
- `docs/SECURITY_MODEL.md` — sandboxing, isolation, and what BlueLine
  does (and doesn't) do when analyzing untrusted targets
- `docs/FINDINGS_AND_RISK.md` — how to read severity, confidence,
  validation status, the risk formula, and coverage
- `docs/SUPPORTED_TARGETS.md` — the full target-type and language
  capability matrix
- `docs/TROUBLESHOOTING.md` — common issues and how to resolve them
- `docs/ARCHITECTURE.md` — plugin interface, directory layout, and an
  honest account of what could and couldn't be verified in this build's
  development environment
