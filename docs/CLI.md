# BlueLine CLI Reference

All commands are run as `python -m app.cli <command> [options]` from the
project root (or `blueline <command>` if you've packaged/aliased it).

## `scan` — run a scan against a target

```bash
python -m app.cli scan <target> [--profile quick|standard|deep|maximum] [--db PATH] [--out FILE]
```

| Option | Default | Meaning |
|---|---|---|
| `target` | *(required)* | A file, directory, or `http(s)://` URL |
| `--profile` | `standard` | Scan depth — see [Scan Profiles](#scan-profiles) below |
| `--db` | your OS user-data dir | Path to the local SQLite scan database |
| `--out` | *(none)* | If given, also write an HTML report to this path |

**Exit codes** (CI-friendly):
- `0` — scan completed, no HIGH or CRITICAL findings
- `1` — scan completed, at least one HIGH or CRITICAL finding
- `2` — the scan itself errored (e.g. unknown scan ID for other commands)

Example:
```bash
python -m app.cli scan ./my-project --profile deep --out report.html
python -m app.cli scan http://127.0.0.1:5000/ --profile quick
```

## `report` — generate a report for a completed scan

```bash
python -m app.cli report <scan_id> [--format html|json|sarif|csv|pdf] [--out FILE] [--db PATH]
```

| Option | Default | Meaning |
|---|---|---|
| `scan_id` | *(required)* | Printed at the end of `scan`, or from `history` |
| `--format` | `html` | Output format |
| `--out` | `<scan_id>.<format>` | Output file path |

Example:
```bash
python -m app.cli report scan_968e1d8971 --format sarif --out results.sarif.json
python -m app.cli report scan_968e1d8971 --format pdf --out report.pdf
```
The SARIF output is designed for CI/developer-tool integration (GitHub
code scanning, etc.) — see [Reports](#reports) below. PDF export needs
the `wkhtmltopdf` system binary installed (not a Python package) — if
it's missing, the command exits with a clear message naming what to
install rather than a stack trace.

## `compare` — regression analysis between two scans

```bash
python -m app.cli compare <scan_id_a> <scan_id_b> [--db PATH]
```

Prints new findings, resolved findings, and any finding that got *worse*
(moved to a higher severity) between scan A (earlier) and scan B (later).
Findings are matched by a stable fingerprint (category + subcategory +
component + location), not by ID, so the same underlying issue is
recognized across scans even though each scan generates fresh finding
IDs.

## `history` — list previous scans

```bash
python -m app.cli history [--target PATH] [--db PATH]
```

Without `--target`, lists all scans across all targets, most recent
first. With `--target`, filters to scans of that specific target path.

## Global notes

- Every command accepts `--db` to point at a different scan database —
  useful for keeping separate history per project, or for CI where you
  might want a throwaway database per run (`--db /tmp/ci-scan.sqlite3`).
- There is currently no `--json`/machine-readable flag on `scan`,
  `compare`, or `history` themselves (their terminal output is
  human-readable); use `report --format json` for machine-readable scan
  output.
- The CLI and the web UI share the same underlying engine and database
  format — a scan started from the CLI shows up in the web UI's history
  and vice versa, as long as they point at the same `--db` / user-data
  directory.
