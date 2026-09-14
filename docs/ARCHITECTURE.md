# BlueLine Architecture

## Pipeline

```
Target Discovery -> Environment Profiling -> [applicable analyzers run in isolation]
    -> Dynamic Analysis (if enabled & CLI entry point found)
    -> Fuzzing (if enabled & CLI entry point found)
    -> Finding Correlation -> Risk Assessment -> Coverage Calculation -> Report Generation
```

Implemented in `app/core/orchestrator.py` (`ScanOrchestrator.run_scan`).
Every analyzer stage is wrapped in its own `try/except`: an exception
inside one analyzer is recorded as a `StageResult(status="failed")` and
the scan continues. This is proven, not assumed — see
`tests/test_orchestrator_isolation.py`, which registers a deliberately
broken analyzer and asserts the overall scan still completes.

## Adding a new analyzer

1. Subclass `app.analyzers.base.Analyzer`.
2. Implement `applies_to(profile)`, `capability_for(profile)` (be honest
   about the support level — see `CapabilityLevel` in `core/models.py`),
   and `run(profile, config) -> list[Finding]`.
3. Register it in `app.analyzers.base.default_registry()`.

No orchestrator code changes — the orchestrator only ever calls the
`Analyzer` interface, never a concrete class.

## Data model

`app/core/models.py` defines the single `Finding` schema every analyzer
must produce: severity, confidence, and validation status are three
separate fields (never conflated — see `RiskEngine` docstring for why).
`TargetProfile.capabilities` is the "no fake universality" mechanism:
every capability line is generated from what was actually detected on
the filesystem (`app/targets/discovery.py::_capabilities_for`), not
asserted globally.

## What was actually built vs. what could only be specified

This project was built inside a sandboxed Linux container with **no
general network access** (`apt`/`mingw` package installs were blocked,
`npm install` returned 403 for the public registry, and a curated pip
index allowed some packages — Flask, Click, psutil, requests — but not
others — `pyinstaller`, `pywebview`, `pytest`). That shaped several real
architecture decisions rather than being an afterthought:

- **The UI is a local web app, not Electron.** Electron requires npm,
  which had no registry access in the build environment. A Flask API +
  vanilla HTML/CSS/JS UI needed nothing beyond the Python standard
  library plus Flask, so it could be built AND fully tested
  (`curl`-driven end-to-end tests against the real running server) in
  that environment.
- **The desktop "shell" is `pywebview`, wrapped with a browser
  fallback**, because `pywebview` could be written and its integration
  logic tested (server startup, port detection, fallback branch) but not
  actually installed to verify the native-window code path. The launcher
  (`app/desktop_launcher.py`) is written so it degrades to opening your
  default browser if `pywebview` isn't present — verified by actually
  running it in that fallback mode.
- **The Windows `.exe` is a reviewed `.spec` file and build script, not a
  built binary** — there was no Windows machine, no `mingw-w64` cross
  compiler, and no way to install `pyinstaller` in the build sandbox.
  `packaging/build_windows.bat` runs the full test suite before invoking
  PyInstaller specifically so a build on your machine fails loudly
  rather than silently packaging a broken engine.
- **The dependency vulnerability database is a small hardcoded sample**,
  not a live feed, because the build environment had no route to
  NVD/OSV/GitHub Advisories. The `VulnerabilityFeed` class is a narrow,
  swappable interface for exactly this reason.
- **Tests use Python's stdlib `unittest`, not `pytest`** — `pytest` was
  not available in the curated package index used during development. If
  you have `pytest` in your own environment, it runs the same test files
  without modification (`pytest tests/`).

Two real bugs were caught by actually running the pipeline end-to-end
rather than trusting the code by inspection, and are worth knowing about
if you're extending this:

1. `TargetDiscovery.discover()` originally stored the target path as
   given (often relative). The dynamic runner executes the target inside
   an isolated temp working directory for sandboxing, so a relative path
   silently resolved to the wrong location and every dynamic/fuzz run
   failed with "file not found" — with no exception surfaced, because a
   nonzero exit from a missing-file error looks like a normal failed
   process launch. Fixed by resolving to an absolute path at discovery
   time. Covered indirectly by `tests/test_dynamic_and_fuzzing.py`
   passing against a real crash.
2. `ScanStore` (SQLite) crashed under the Flask API server specifically,
   because Flask serves requests on multiple threads while a scan runs
   in a background thread, and a raw `sqlite3.connect()` isn't safe to
   share across threads without `check_same_thread=False` plus explicit
   locking. Caught by manually driving the API server with `curl` rather
   than only unit-testing `ScanStore` in isolation (the unit tests alone
   didn't exercise cross-thread access). Fixed, and now implicitly
   covered every time `tests/test_persistence.py` runs alongside the
   rest of the suite in the same process.

## Visual verification of the UI and reports

This environment has no display and no installable modern headless
browser (no network route to a Chromium/Playwright download). Two tools
were used instead to get real, not assumed, visual verification:

- **`wkhtmltoimage`** (available locally, built on an old ~2013-era
  QtWebKit) was used to actually render the generated HTML report and
  the live web UI to PNG images for inspection. This caught three real
  bugs no amount of code review found:
  1. The report's `.grid` used CSS Grid `auto-fit`/`minmax`, which this
     renderer didn't support — the severity cards rendered stacked
     instead of side-by-side. Switched to flexbox with explicit
     `flex: 1 1 190px` for broader compatibility.
  2. The finding metadata row used flexbox `gap`, which rendered with no
     visible spacing in this engine — text ran together illegibly
     ("Risk score: 82.7Confidence: 95%..."). Fixed with an explicit
     `margin-right` fallback on each item.
  3. A malformed hex color (`#143f b0` — a stray space from a typo) in
     the UI's light-theme CSS variables.
  4. A duplicate `const SEVERITY_ORDER` declaration across two
     `<script>` sections of `app.js`, which is a `SyntaxError` in strict
     mode and would have broken the entire UI on load.
- Using this same renderer to test the AJAX-driven parts of the web UI
  produced what looked like a hung "Loading…" state with the API never
  being called. Root-caused (not assumed) by directly testing
  `typeof fetch` in the same renderer: this specific QtWebKit build
  **predates the Fetch API entirely** (Fetch shipped in browsers
  starting ~2015; this WebKit snapshot is older). This is a limitation
  of the test tool, not of BlueLine — every real deployment target
  (Chrome, Firefox, Edge, Safari, and pywebview's WebView2/WebKitGTK/
  WKWebView backends) has supported Fetch for years. A defensive
  `typeof fetch === "undefined"` guard was still added to `app.js` so
  the failure mode in a genuinely ancient browser is a clear message
  instead of a silent hang.
- The chart-generation math added to `app.js` (`severityDonutSvg`,
  `severityLegendHtml`) was independently verified by extracting and
  running it in Node's V8 engine directly — the same JS engine family
  Chrome and modern WebViews use — checking that arc lengths sum to the
  full circumference, the empty-state path has no `NaN`, and severity
  counts render correctly. This is real execution of the actual
  shipped code, not a description of what it should do.

This is offered as a template for how to extend this project further:
when you can't get a fully faithful test environment, get as close as
you honestly can, root-cause anything that looks wrong instead of
guessing, and say plainly what you could and couldn't verify.

## Accessibility: checked, not assumed

The spec called for real accessibility (keyboard navigation, visible
focus states, semantic controls, non-color-only status indicators) —
this was verified with actual computation and markup checks
(`tests/test_accessibility.py`), not a visual once-over:

- **Color contrast is computed from the live CSS**, not eyeballed. The
  test parses the actual `--text-muted`/`--bg`/severity custom
  properties out of `app.css` and runs the real WCAG relative-luminance
  formula against them. This caught a genuine failure: `--text-muted`
  was `#5f6b85` on dark and `#8894a8` on light, giving 3.6:1 and 2.8:1
  contrast against their backgrounds respectively — both below the
  4.5:1 AA bar for the small (11-13px) text they're actually used for.
  Fixed to `#808996` (dark) and `#6a717c` (light), both re-verified
  above 4.5:1 with margin. Because the test parses the CSS file itself
  rather than a hardcoded snapshot of "the colors as of when this was
  written," a future color change that regresses contrast will fail
  this test, not slip through silently.
- **Interactive elements were divs with click handlers** — invisible to
  keyboard users and screen readers despite looking like nav items and
  buttons. Fixed: the sidebar nav is now real `<button>`s with
  `aria-current="page"` on the active view; the scan-profile picker is
  real radio inputs (visually hidden with a proper `clip`-based
  technique, NOT `display:none`, which would have removed them from the
  tab order entirely — an easy mistake this project made and caught
  itself while fixing the first issue); the finding-detail toggle is a
  real `<button>` exposing `aria-expanded`.
- **Live scan progress now uses `aria-live="polite"` regions** on the
  status badge and stage log, so a screen reader announces stage
  transitions as they happen rather than only reflecting the DOM
  silently.
- **`:focus-visible` outlines** were added globally (plus `:focus-within`
  on the profile-option cards specifically, since the real radio input
  inside each one is what actually receives focus).

What this did NOT get: an automated accessibility audit tool (axe-core
and similar need a real browser or a Node/Playwright environment neither
of which were available here — `npm install` was blocked, as documented
elsewhere in this file). The checks above are real and specific, not a
substitute for a full audit — they cover the exact gaps this project
found and fixed, not every WCAG success criterion.

## Validating the ELF binary parser against ground truth

`app/analyzers/elf_parser.py` is a from-scratch ELF parser (Python's
stdlib `struct` module only — `pyelftools` wasn't installable in this
build's package index). Rather than trust the implementation against
the spec alone, this environment had `gcc`, `readelf`, `objdump`, and
`file` available, which made real validation possible:

1. Compiled 5 real binaries from the same tiny C source with different
   flags: default (dynamic, PIE), `-static`, `strip`'d, `-no-pie`, and
   explicit `-pie`.
2. Ran `file` and `readelf -d` on each to get independent ground truth
   (PIE/no-PIE, stripped/not, and the exact `DT_NEEDED` library list).
3. Ran the from-scratch parser on the same 5 binaries and asserted an
   exact match against that ground truth for every property
   (`tests/test_elf_parser.py`) — genuinely comparing two independent
   implementations' output, not checking the parser against its own
   assumptions.
4. Fuzz-tested the parser with 500 randomly truncated/corrupted copies
   of a real binary (fixed seed for reproducibility) and asserted zero
   crashes — consistent with the project-wide "a broken target is test
   data" principle, now enforced for binary parsing specifically.

This caught one real bug: files with the ELF magic bytes but a
truncated header were being reported as "not an ELF file at all"
instead of "is an ELF file, but couldn't be fully parsed" — a
meaningful difference (the former silently hides a malformed/corrupted
executable as "not applicable"; the latter surfaces it as a genuine,
if incomplete, finding). Fixed by checking the magic bytes and the
`e_ident` length requirement as two separate conditions instead of one
combined check.

The same parser's PE (Windows) and Mach-O (macOS) support is
deliberately limited to string extraction — no Windows or macOS binary
was available in this Linux build sandbox to validate a structural
parser against, and shipping one with only the ELF-informed spec
reading behind it (and confidently-labeled FULL_SUPPORT) would violate
the "never claim a capability that wasn't actually verified" principle
that governs every other analyzer in this codebase.

## Validating the PE header parser without a real Windows binary

`parse_pe()` in the same module goes one step further than "string
extraction only" for PE files specifically — it parses the fixed-offset
COFF and Optional header fields (machine type, subsystem, section
count, build timestamp). This was still possible to validate rigorously
without a real Windows binary: `tests/test_pe_parser.py` constructs a
byte-exact, spec-conformant minimal PE64 file directly with
`struct.pack` (DOS header, PE signature, COFF header, Optional header,
Subsystem field at its documented fixed offset), then asserts the
parser extracts every field correctly, plus truncation at every
7-byte boundary doesn't crash it.

This is a different, weaker form of validation than the ELF parser's
(a hand-built fixture checked against the parser's own understanding of
the spec, rather than two independent tools agreeing on a real binary)
— which is exactly why PE support stops at header metadata and doesn't
attempt the import table: parsing the import table correctly requires
translating RVAs through the section table, and getting that subtly
wrong is much easier to do undetected against a hand-built fixture than
against a messy real-world binary. Shipping it unvalidated against
anything real would be the kind of overclaim this project has
repeatedly tried to avoid elsewhere (see the JS/Java/Go/Ruby/PHP/Rust
analyzers' `PARTIAL_SUPPORT` labeling for the same reasoning applied to
source code instead of binaries).

## A directory-scanning bug the PE work surfaced

Building the PE test fixture surfaced a real, separate bug: BlueLine's
directory-walk target discovery only checked magic bytes on files with
*no* file extension (the Linux/Mac convention for executables). A
Windows `.exe` or `.dll` sitting in a scanned directory — the normal
case for that platform — was never being recognized as an executable
at all, silently skipping it from binary analysis entirely with no
warning. Fixed in `TargetDiscovery._discover_directory` to also check
magic bytes for `.exe`/`.dll`/`.so`/`.dylib`/`.bin` files, and pinned
with a regression test (`tests/test_discovery.py`) that a `.exe` in a
directory is now detected and analyzed, while confirming a plain text
file merely *named* `*.exe` is correctly NOT flagged (content, not
extension, remains the real signal).

## Directory structure

```
app/
  core/          orchestrator, data models, risk/coverage/correlation engines, paths.py
                 (single-file-exe-safe path resolution), logging_setup.py (structured
                 JSON-lines logs — see below)
  targets/       target discovery (filesystem targets AND live URL targets)
  analyzers/     one file per analyzer (python_static, js_static, java_static, go_static,
                 ruby_static, php_static, rust_static, c_cpp_static, dependency,
                 config_analyzer, web_api, binary_analysis) + elf_parser.py
                 (stdlib-only ELF and PE parser) + base.py plugin interface
  runtime/       sandboxed subprocess execution (dynamic analysis)
  fuzzing/       mutation engine + fuzzing campaign loop
  reporting/     html/json/sarif/csv report generators + charts.py (SVG)
  persistence/   SQLite scan store
  cli.py         command-line interface
  api_server.py  Flask API backing the web UI
  desktop_launcher.py   pywebview wrapper with browser fallback
ui/              HTML/CSS/JS web UI (served by api_server.py)
test-targets/    intentionally vulnerable fixtures (local test data only)
tests/           unittest suite, including the detection benchmark
packaging/       PyInstaller spec (single-file build) + Windows build script
docs/            this file, plus README.md at the project root
```

## Single-file executable requirement

The user explicitly required the packaged Windows app to be one
self-contained file with no dependency on a sibling folder or any other
file. This shaped two real design decisions, not just the PyInstaller
flags:

1. **`app/core/paths.py`** is the single place in the codebase that
   resolves where the UI assets and the scan-history database live. A
   single-file PyInstaller build unpacks its bundled data (`ui/`) into a
   PyInstaller-managed temp directory at runtime (`sys._MEIPASS`), which
   is different from where the script lives when run from source — code
   that hardcodes `Path(__file__).parent / "ui"` breaks the moment it's
   frozen. `bundle_root()` branches on `sys.frozen`/`sys._MEIPASS` to get
   this right in both cases. Since an actual PyInstaller build couldn't
   be run in this sandbox, this branch is verified by directly
   monkey-patching `sys.frozen`/`sys._MEIPASS` in
   `tests/test_paths.py` to simulate exactly what PyInstaller sets at
   runtime — real execution of the real branching logic, not a
   description of what it should do.
2. **Scan history moved out of "wherever the exe happens to run from."**
   The database used to default to `blueline_data.sqlite3` in the
   current working directory. For a single portable .exe, that breaks if
   the exe sits somewhere without write access (e.g. Program Files) or
   is launched via a shortcut with an unexpected working directory.
   `paths.default_db_path()` now resolves to a proper per-user
   application-data directory (`%LOCALAPPDATA%\BlueLine` on Windows,
   `~/Library/Application Support/BlueLine` on macOS, XDG data dir on
   Linux) — verified end-to-end by running the CLI with `HOME` pointed
   at a throwaway directory and confirming the database appears there,
   not in the scan target's directory or the shell's cwd.
3. **The PyInstaller spec has no `COLLECT()` step.** `COLLECT()` is
   specifically what produces PyInstaller's folder-style ("onedir")
   output; omitting it and passing `a.binaries`/`a.zipfiles`/`a.datas`
   directly into `EXE()` is what makes the build a true single file.
   This is a real, inspectable difference from the earlier draft of this
   spec (which used `exclude_binaries=True` + `COLLECT()`, producing a
   `dist/BlueLine/` folder) — worth knowing if you ever wonder why the
   spec looks the way it does.
