# Troubleshooting

## "No findings" but I know my code has issues

Check the target profile's **Declared Capabilities** first (Target Setup
screen, or the top of any report). If your language shows
`UNSUPPORTED`, no analyzer ran against it — that's not the same as
"scanned and found clean." See `docs/SUPPORTED_TARGETS.md`.

If your language is supported but a specific issue wasn't caught: the
pattern-based analyzers (everything except Python) match line-by-line
text patterns, not real parsed structure. A pattern spanning multiple
lines, going through an intermediate variable, or using an unusual call
style can be missed. This is a documented, real limitation — see each
analyzer's module docstring — not a bug to report unless the exact
pattern in `README.md`'s Limitations section doesn't already cover it.

## Dynamic analysis / fuzzing shows "no invocable entry point"

`TargetDiscovery` looks for specific filenames (`main.py`, `app.py`,
`__main__.py`, `index.js`, `server.js`, `main.go`, `main.c`, `main.cpp`)
or an executable file. If your entry point has a different name, rename
it, add a matching wrapper, or point BlueLine directly at the specific
file instead of the containing directory.

## A scan says "completed" but coverage is well under 100%

That's expected and correct if an analyzer stage failed or was skipped
— check the Stage Execution Log section of the report for the specific
stage and error. A failed stage always shows 0% for that stage
specifically (`app/core/coverage.py`); it does not get averaged away or
hidden.

## The Web/API analyzer says "Target did not respond"

- Confirm the URL is reachable from the machine running BlueLine, not
  just from your browser (if BlueLine runs in a container/VM without
  access to the same network, this will fail).
- The analyzer uses a 6-second timeout (`TIMEOUT_SECONDS` in
  `app/analyzers/web_api.py`) — a slow-starting local dev server might
  need a moment before you scan it.
- This finding is deliberately `INFORMATIONAL`/`UNVERIFIED`, never a
  crash — if you see anything other than that one clean finding, that's
  a bug, please report it.

## The desktop app opens a browser tab instead of a native window

`pywebview` isn't installed. `python -m app.desktop_launcher` explicitly
checks for it and falls back to your default browser rather than
failing — install it (`pip install pywebview`) for a native window. See
`README.md`'s Limitations section for why this couldn't be verified in
the original build environment.

## Building the Windows `.exe` fails

- **If `dist\` isn't created at all and the error mentions `cipher` or
  an unexpected keyword argument in `Analysis()`/`PYZ()`:** you have an
  old copy of `packaging/blueline.spec` from before this was fixed. The
  fixed spec no longer passes `cipher=` at all (PyInstaller 6.0 removed
  that parameter entirely) — pull the latest version of this project.
- Make sure you're running `packaging/build_windows.bat` **on Windows**
  — it can't be cross-compiled from Linux/macOS in this project (no
  `mingw`/Wine dependency was ever introduced specifically to keep this
  requirement honest rather than papering over it).
- The script runs the full test suite before packaging and aborts the
  build if any test fails — if it stops there, fix the failing test
  first; don't skip straight to PyInstaller.
- The script now checks the exit code of every step and stops with a
  specific message on the first failure, and verifies
  `dist\BlueLine.exe` actually exists before declaring success — if
  you're seeing a silent "Build complete" with no `.exe`, you also have
  an old copy of `build_windows.bat`.
- If PyInstaller complains about a missing module, add it to
  `hiddenimports` in `packaging/blueline.spec` — dynamic imports
  (anything imported inside a function rather than at module top level)
  are the most common cause.
- For anything else, re-run with `pyinstaller packaging\blueline.spec
  --log-level DEBUG` and read the actual traceback — it names the exact
  line and error far more precisely than guessing from outside a real
  Windows/PyInstaller environment ever can.

## PDF export fails or is missing from the UI

PDF export converts the same HTML report via the `wkhtmltopdf` system
binary, which is not bundled with BlueLine. Install it from
https://wkhtmltopdf.org/ or your OS package manager
(`apt install wkhtmltopdf`, `brew install wkhtmltopdf`, etc.). Every
other report format (HTML, JSON, SARIF, CSV) works regardless.

## Where are the logs?

Five separate JSON-lines log files live in `<user data dir>/logs/`
(same base directory as the scan database — see below):
`app.log` (server/CLI lifecycle), `scanner.log` (every stage
transition for every scan), `analyzer.log` (analyzer exceptions),
`security.log` (every HIGH/CRITICAL finding, metadata only — never the
actual evidence/secret string), and `runtime.log` (dynamic/fuzzing
crash events). Each line is a JSON object — pipe through `jq` or
`python -m json.tool` per-line for readable output. Logs rotate at 5MB
with 3 backups kept, so they won't grow unbounded.

## Scan history seems to have disappeared

Scan history lives in your OS's per-user app-data directory (see
`app/core/paths.py::user_data_dir()`), **not** next to wherever you ran
BlueLine from. On Windows that's `%LOCALAPPDATA%\BlueLine`; on macOS
`~/Library/Application Support/BlueLine`; on Linux the XDG data
directory (usually `~/.local/share/blueline`). If you explicitly passed
`--db` to the CLI, history is wherever that path pointed instead.

## `pip install` fails for a packaging-only dependency (`pyinstaller`, `pywebview`)

These are packaging-time dependencies (in
`packaging/requirements-packaging.txt`), not runtime ones — you don't
need them to run BlueLine itself, only to build the `.exe`. If your pip
index is restricted (as it was in this project's original build
sandbox), try a different network/index, or a different machine
entirely for the packaging step.
