# BlueLine Security Model

BlueLine's core design principle: **the target is untrusted input.** A
target may contain malformed files, malicious archives, crafted
binaries, or code designed to crash or exploit whatever analyzes it.
BlueLine treats every one of those as expected test data, not as an
excuse for BlueLine itself to misbehave. This document describes what's
actually implemented, file by file — not an aspirational policy.

## Static analysis: read-only, always

Every static analyzer (`app/analyzers/python_static.py`, `js_static.py`,
`java_static.py`, `go_static.py`, `ruby_static.py`, `php_static.py`,
`c_cpp_static.py`) only ever calls `Path.read_text()` on target files.
None of them execute, `eval()`, import, or otherwise run target code —
they parse or pattern-match against the *text* of the file. A file
containing `os.system("rm -rf /")` as a string literal is data to be
flagged, never something that gets run.

Malformed files are handled explicitly: `python_static.py` catches
`SyntaxError`/`ValueError`/`OSError` around `ast.parse()` per file and
skips that file rather than aborting the whole analyzer (see
`tests/test_python_analyzer.py::test_broken_file_does_not_crash_analyzer`,
which feeds it deliberately invalid Python and asserts no exception
escapes).

## Dynamic analysis and fuzzing: sandboxed subprocess execution

`app/runtime/dynamic.py` (`DynamicRunner`) is the only place in BlueLine
that executes target code, and it does so deliberately conservatively:

- **Isolated working directory.** Every run happens in a fresh
  `tempfile.mkdtemp()`, never the target's own source directory — so a
  target can't overwrite its own source files or read siblings it
  shouldn't.
- **Resource limits (POSIX).** Before exec, the child process has
  `RLIMIT_CPU`, `RLIMIT_AS` (address space/memory), and `RLIMIT_NOFILE`
  applied via `preexec_fn`, and is placed in its own process group via
  `os.setsid()`.
- **Hard timeout with real process-group kill.** `subprocess.communicate(timeout=...)`
  plus `os.killpg()` on timeout — a target that forks children or
  ignores SIGTERM doesn't survive past the configured timeout.
- **No shell involved.** Every invocation uses an explicit argv list
  (`shell=False`); BlueLine never builds a shell command string from
  target-derived data.
- **Bounded output capture.** stdout/stderr are truncated at 64KB
  (`MAX_CAPTURED_BYTES`) before being stored, so a target that floods
  output can't exhaust BlueLine's own memory or bloat the database
  unboundedly.

The fuzzing engine (`app/fuzzing/engine.py`) reuses `DynamicRunner` for
every test case — it does not have a separate, less-sandboxed execution
path.

## Archive/file handling

`test-targets/` fixtures include a deliberately crafted `tarfile.extractall()`
call *as an example of what to flag*, not as something BlueLine itself
does. BlueLine's own code never extracts an archive from a target as
part of analysis — the tar-traversal rule (`PY-TAR-TRAVERSAL`) is a
static pattern match against the target's source text, and the config
analyzer only ever *reads* Dockerfiles/`.env` files as text.

## File and network activity monitoring: observation, not interception

`app/runtime/dynamic.py::_ActivityMonitor` polls the running child
process (via `psutil`, every 30ms) for open file handles and network
connections during single-run Dynamic Analysis. This is passive
observation of the process the sandbox already controls — it does not
hook, intercept, or modify any syscall, and it cannot block or alter
what the target does; it can only see what psutil's `/proc`-based
introspection already exposes for a process the current user owns.
Validated against real subprocesses that actually open a file and
actually connect to a real local TCP listener (`tests/test_activity_monitoring.py`)
— both were correctly detected, including through the full orchestrator
pipeline producing a real finding. This is deliberately scoped to
single-run Dynamic Analysis only, not the fuzzing loop, since polling
overhead across potentially thousands of fuzz cases was judged not
worth the tradeoff.

## Binary analysis: parsing, never executing

`app/analyzers/elf_parser.py` and `app/analyzers/binary_analysis.py`
only ever call `open(path, "rb").read()` and parse the resulting bytes
with `struct.unpack()` — they never execute, load, or dynamic-link the
target binary. A malicious ELF file is just a byte sequence to this
parser, the same way a malicious Python file is just text to
`python_static.py`. Malformed/corrupted binaries are explicitly handled
(caught `struct.error`/`IndexError`, never a bare crash) and covered by
a 500-iteration fuzz test against randomly truncated/corrupted real
binary data (`tests/test_elf_parser.py`).

## Web/API analyzer: the one component that makes network requests

`app/analyzers/web_api.py` is the only analyzer that talks to a network
target rather than reading local files. Its constraints (see the
module's own docstring for the full rationale):

- Only `GET`, `HEAD`, and `OPTIONS` — never a state-changing verb.
- Only the single URL provided — no crawling, no following arbitrary
  links.
- Short timeouts (`TIMEOUT_SECONDS = 6`), and any failure becomes an
  `INFORMATIONAL`/`UNVERIFIED` finding, never a retry loop or a crash.
- Real TLS certificate validation on outbound requests
  (`ssl.create_default_context()`) — BlueLine doesn't disable its own
  certificate checking when *it* is the client, even though it flags
  *other* code for doing that (`GO-INSECURE-SKIP-VERIFY`, etc.).

## Offline-first: what actually calls out to the network

Core analysis (everything except the Web/API analyzer pointed at a URL
you provided) never makes a network call. The dependency analyzer
(`app/analyzers/dependency.py`) checks package versions against a small
**local, hardcoded** curated sample — it does not call out to
NVD/OSV/npm/PyPI. If you wire `VulnerabilityFeed` to a live source in
your own deployment, that becomes an explicit, separate, optional
integration — exactly as required by "if an optional external service
is ever supported, it must be clearly separated from the offline core."

## Local API server: localhost-only

`app/api_server.py` binds explicitly to `127.0.0.1` (see `main()` and
every `app.run(...)` call in `desktop_launcher.py`) — never `0.0.0.0`.
This is a local desktop tool's backend, not a network service, and
nothing in the codebase should ever change that binding without a very
deliberate reason.

## Structured logging: metadata only, never target content

`app/core/logging_setup.py` writes five separate JSON-lines log streams
(application, scanner, analyzer, security, runtime — see
`docs/TROUBLESHOOTING.md` for locations). The security log specifically
records HIGH/CRITICAL findings for audit purposes, but deliberately logs
only metadata (finding ID, category, severity, location) — never the
finding's evidence or code snippet, which could itself contain a real
secret string or source code extracted from the target. This is
verified, not just intended:
`tests/test_logging.py::test_security_log_never_contains_finding_evidence_or_snippets`
runs a real scan against a fixture with a known hardcoded secret and
asserts that exact string never appears anywhere in the resulting log
file.

## What BlueLine does NOT claim

- It does not claim to detect every vulnerability in every target — see
  the Limitations section of the main README and every analyzer's
  declared `CapabilityLevel`.
- It does not claim a target with zero findings is secure — see the
  exact phrasing in `app/reporting/html_report.py`'s executive summary
  and `app/core/coverage.py`'s note field.
- It does not attempt to defeat sandboxes, escape containers, or attack
  anything beyond the single target path/URL the user explicitly
  provided.
