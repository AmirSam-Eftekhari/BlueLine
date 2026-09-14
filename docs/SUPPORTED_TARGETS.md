# Supported Target Types and Languages

BlueLine never claims universal support — every capability below is
generated live from what `TargetDiscovery` actually detects on your
target, and shown identically in the Target Setup screen, the Settings
screen, and every report. This page is the same information laid out
as a reference table.

## Target types

| Target | How to point BlueLine at it | Status |
|---|---|---|
| Directory / repository | A filesystem path | Full support — the primary use case |
| Single source file | A filesystem path to one file | Full support |
| Executable (CLI) | A path to a runnable script/binary, or a directory containing one | Dynamic analysis + fuzzing apply if an entry point is found |
| Running web/API service | An `http://` or `https://` URL | Passive header/cookie/CORS/transport checks only — see `docs/SECURITY_MODEL.md` |
| Compiled binary (deep inspection: imports, strings, linked libraries) | ELF: full support (parsed with a real stdlib-only parser, validated against `readelf`/`file`). PE (Windows) / Mach-O (macOS): string extraction only — magic bytes detected, no internal structure parsed | See `docs/ARCHITECTURE.md` for the exact validation methodology |
| Container image (build/run and analyze) | — | **Not implemented** — Dockerfiles are analyzed as *configuration* (`ConfigurationAnalyzer`), but no analyzer builds or runs a container image |
| Robotics controller / specialized software | Whatever software layer it exposes (source, script, or executable) | Analyzed through the same language/executable analyzers above — no dedicated robotics adapter exists, per the "no robotics-only architecture" principle, but also nothing robotics-specific has been validated |

## Binary/executable analysis

| Format | Capability | What it actually does |
|---|---|---|
| ELF (Linux/Unix) | Full — architecture, PIE/no-PIE, stripped/not, dynamically linked library list, entry point | Real stdlib-only parser, validated against `readelf -d` and `file` on 5 real compiled binaries with an exact match, then fuzz-tested with 500 corrupted/truncated variants (zero crashes) |
| PE (Windows) | Header metadata only — machine type, subsystem, section count, build timestamp | Real stdlib-only parser, validated against a byte-exact synthetic spec-conformant fixture (no real Windows binary was available in this build). Import table (linked DLLs) NOT parsed. |
| Mach-O (macOS) | String extraction only | Detected by magic bytes; no header parsing |
| Any executable format | String-based secret/private-key detection | Applies regardless of container format — scans for `-----BEGIN ... PRIVATE KEY-----` headers and credential-shaped strings |

Target discovery detects executables both by having no file extension
(the Linux/Mac convention) and by common Windows executable extensions
(`.exe`, `.dll`) checked against magic bytes — a `.exe` sitting in a
scanned directory is recognized the same way a Linux binary with no
extension is.

## Language static analysis

| Language | Capability | What it actually does |
|---|---|---|
| Python | `FULL_SUPPORT` | Real AST parser (`ast` module), ~15 rule classes, basic same-function SQL-injection taint tracking |
| JavaScript / TypeScript | `PARTIAL_SUPPORT` | Regex/line-pattern based, 10 rules |
| Java | `PARTIAL_SUPPORT` | Regex/line-pattern based, 10 rules |
| Go | `PARTIAL_SUPPORT` | Regex/line-pattern based, 8 rules |
| Ruby | `PARTIAL_SUPPORT` | Regex/line-pattern based, 9 rules |
| PHP | `PARTIAL_SUPPORT` | Regex/line-pattern based, 9 rules |
| Rust | `PARTIAL_SUPPORT` | Regex/line-pattern based, 7 rules |
| C / C++ | `EXPERIMENTAL` | Pattern-matching on 6 dangerous libc calls only, confidence capped at 50% |
| Kotlin, Swift, Scala, etc. | `UNSUPPORTED` | Detected by file extension where recognized, but no analyzer runs — never silently skipped, always shown as unsupported |

Why the split between `FULL_SUPPORT` and `PARTIAL_SUPPORT`: Python's
analyzer uses a real parser and understands actual program structure
(it can trace a value from an f-string assignment to a `cursor.execute()`
call three lines later). The pattern-based analyzers match against the
literal text of each line — real, useful, but blind to anything that
spans a parser-level construct (variable reassignment, control flow,
multi-line expressions) rather than a single line's text.

## Dependency ecosystems

| Manifest | Parsed? | Checked against vulnerability data? |
|---|---|---|
| `requirements.txt` (pip) | Yes | Yes — small curated local sample (12 entries) |
| `package.json` (npm) | Yes | Yes — same curated sample |
| `Pipfile.lock`, `package-lock.json`, `yarn.lock`, `Cargo.toml`, `go.mod`, `composer.json`, `Gemfile` | Detected (shown in the target profile) | **Not parsed for version checking** — only `requirements.txt` and `package.json` are actually read by `DependencyAnalyzer` in this build |

## Configuration analysis

| File | Checked for |
|---|---|
| `.env*` | Secret-shaped values committed as literals |
| `Dockerfile` | Unpinned `:latest` base images, running as root, `ADD <url>` without integrity verification |
| Generic YAML/TOML/INI/`.conf` | Detected and listed in the target profile, but no rule-based content checks in this build |

## Reports

| Format | Status |
|---|---|
| HTML | Full — includes real SVG charts (severity donut, coverage bars) |
| JSON | Full — the complete `ScanResult` as structured data |
| SARIF 2.1.0 | Full — validated shape (`tests/test_js_c_and_reports.py`), suitable for CI/code-scanning integration |
| CSV | Full — one row per finding |
| PDF | Full — real conversion of the same HTML report via `wkhtmltopdf` (a system binary, not bundled; falls back to a clear error naming what to install if it's missing) |
