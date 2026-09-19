<div align="center">

<img src="./ui/static/assets/blueline_256.png" width="110" alt="BlueLine logo" />

# BlueLine

### Universal Security & Reliability Assessment Platform

**Assume nothing. Test aggressively. Prove what you find.**

<br>

[![Offline First](https://img.shields.io/badge/Architecture-Offline--First-111827?style=for-the-badge)](#)
[![Python](https://img.shields.io/badge/Python-3.x-111827?style=for-the-badge\&logo=python\&logoColor=3776AB)](#)
[![Security](https://img.shields.io/badge/Focus-Security-111827?style=for-the-badge\&logo=shield\&logoColor=22C55E)](#)
[![Testing](https://img.shields.io/badge/Testing-Automated-111827?style=for-the-badge\&logo=pytest\&logoColor=F59E0B)](#)

<br>

**Static Analysis · Dynamic Analysis · Fuzzing · Binary Analysis · Web Security · Risk · Reporting**

</div>

---

## ⚡ What is BlueLine?

**BlueLine** is an offline-first security and reliability assessment platform for:

```text
Source repositories    Scripts    Executables    Live Web Targets
```

BlueLine discovers what a target actually is, determines which analysis capabilities genuinely apply, runs them, correlates their results, and produces evidence-backed findings.

Every finding keeps these concepts separate:

```text
Severity       Confidence       Validation       Risk       Coverage
```

That distinction matters.

> **Not finding a vulnerability is not the same as proving that a target is safe.**

BlueLine therefore reports not only **what it found**, but also **what it tested and what it could not test**.

**No target data is uploaded to a remote BlueLine service.**

---

<div align="center">

### 🧠 The Core Idea

> **Don't silently skip.**

> **Don't fabricate intelligence.**

> **Don't hide failures.**

> **Don't call it verified without verification.**

</div>

---

# 🧩 Analysis Stack

<table>
<tr>
<td width="50%" valign="top">

### 🔎 Static Analysis

* Python AST engine
* JavaScript / TypeScript
* Java
* Go
* Ruby
* PHP
* Rust
* Kotlin
* Swift
* Scala
* Experimental C / C++

</td>
<td width="50%" valign="top">

### 🧪 Runtime Analysis

* Dynamic execution
* Resource limits
* Process isolation
* File activity monitoring
* Network activity monitoring
* Behavior-guided fuzzing
* Crash detection
* Finding correlation

</td>
</tr>

<tr>
<td width="50%" valign="top">

### ⚙️ Binary & Dependency Analysis

* ELF parsing
* PE metadata
* Mach-O string extraction
* Architecture detection
* PIE detection
* Stripped binary detection
* Dependency inspection
* Local CVE matching
* Embedded secret extraction

</td>
<td width="50%" valign="top">

### 🌐 Web & Configuration

* HTTP security headers
* Cookie flags
* CORS probing
* Server banner disclosure
* Plaintext HTTP detection
* `.env` secrets
* Dockerfile checks
* Package configuration analysis

</td>
</tr>
</table>

---

# 🏗️ Architecture

```text
                         ┌─────────────────────────┐
                         │         TARGET          │
                         │ Repo / Script / EXE / URL│
                         └────────────┬────────────┘
                                      │
                                      ▼
                         ┌─────────────────────────┐
                         │     TARGET DISCOVERY    │
                         │ Language · Build System  │
                         │ Package · Entry Point   │
                         └────────────┬────────────┘
                                      │
                                      ▼
                  ┌────────────────────────────────────┐
                  │          ORCHESTRATION              │
                  └───────┬────────┬────────┬──────────┘
                          │        │        │
            ┌─────────────┘        │        └─────────────┐
            ▼                      ▼                      ▼
      ┌─────────────┐       ┌─────────────┐       ┌─────────────┐
      │    STATIC   │       │   DYNAMIC   │       │    BINARY   │
      │   ANALYSIS  │       │   ANALYSIS  │       │   ANALYSIS  │
      └──────┬──────┘       └──────┬──────┘       └──────┬──────┘
             │                     │                     │
             └──────────────┬──────┴──────┬──────────────┘
                            │             │
                            ▼             ▼
                     ┌────────────┐  ┌────────────┐
                     │  FUZZING   │  │  WEB/API   │
                     └─────┬──────┘  └─────┬──────┘
                           │               │
                           └───────┬───────┘
                                   ▼
                         ┌─────────────────────┐
                         │ FINDING CORRELATION │
                         │ Deduplicate · Merge │
                         └──────────┬──────────┘
                                    │
                      ┌─────────────┼─────────────┐
                      ▼             ▼             ▼
                ┌──────────┐ ┌────────────┐ ┌────────────┐
                │   RISK   │ │  COVERAGE  │ │ VALIDATION │
                │  ENGINE  │ │   ENGINE   │ │   STATUS   │
                └────┬─────┘ └─────┬──────┘ └─────┬──────┘
                     │             │              │
                     └─────────────┼──────────────┘
                                   ▼
                         ┌─────────────────────┐
                         │      REPORTING      │
                         │ HTML · JSON · SARIF │
                         │ CSV · PDF           │
                         └─────────────────────┘
```

---

# 🛡️ Capability Matrix

| Target / Analyzer       |      Capability      |
| :---------------------- | :------------------: |
| Python                  |   🟢 `FULL_SUPPORT`  |
| JavaScript / TypeScript | 🟡 `PARTIAL_SUPPORT` |
| Java                    | 🟡 `PARTIAL_SUPPORT` |
| Go                      | 🟡 `PARTIAL_SUPPORT` |
| Ruby                    | 🟡 `PARTIAL_SUPPORT` |
| PHP                     | 🟡 `PARTIAL_SUPPORT` |
| Rust                    | 🟡 `PARTIAL_SUPPORT` |
| Kotlin                  | 🟡 `PARTIAL_SUPPORT` |
| Swift                   | 🟡 `PARTIAL_SUPPORT` |
| Scala                   | 🟡 `PARTIAL_SUPPORT` |
| C / C++                 |   🟠 `EXPERIMENTAL`  |
| ELF                     | 🟡 `PARTIAL_SUPPORT` |
| PE                      | 🟡 `PARTIAL_SUPPORT` |
| Mach-O                  | 🟡 `PARTIAL_SUPPORT` |
| Web / API               | 🟡 `PARTIAL_SUPPORT` |

Unsupported targets are **explicitly reported**.

They are never silently skipped.

---

# 🐍 Python Static Analysis

Python receives the deepest static analysis implementation.

BlueLine uses a real **AST-based rule engine** with approximately 15 rule classes covering:

* SQL injection
* Command injection
* Insecure deserialization
* Weak cryptography
* Hardcoded secrets
* Path traversal
* Flask misconfiguration
* Dangerous function usage
* Security-sensitive configuration

The SQL injection engine also performs **same-function taint tracking**, allowing potentially unsafe data flow to be connected to SQL execution.

---

# 🌐 Web / API Analysis

BlueLine can analyze a live HTTP target:

```text
http://host:port/
```

The analyzer is deliberately **read-only**.

Allowed methods:

```text
GET    HEAD    OPTIONS
```

Checks include:

* Security headers
* Cookie security flags
* CORS behavior
* Server banner disclosure
* Plaintext HTTP transport

CORS is actively verified by sending an `Origin` probe and checking the server's response.

This is **not** intended to be a full active web vulnerability scanner.

No authentication attacks, session attacks, injection testing, or state-changing requests are performed.

---

# 💻 Binary Analysis

## ELF

BlueLine contains a built-in ELF parser implemented using Python's standard-library `struct`.

It extracts:

```text
Architecture

PIE / non-PIE

Stripped / non-stripped

Dynamic library dependencies
```

Validation was performed against `readelf` and `file` using five real binaries:

```text
Normal

Static

Stripped

PIE

Non-PIE
```

Every tested property matched ground truth exactly.

The parser was additionally stress-tested against:

> **500 randomly truncated / corrupted variants**

with:

> **0 crashes**

---

## Windows PE

Current PE analysis extracts:

* Machine type
* Subsystem
* Section count
* Timestamp

Validation was performed against a synthetic, byte-exact PE64 fixture.

PE import-table parsing is not currently implemented.

---

## macOS Mach-O

Mach-O targets currently receive string extraction.

---

# 🧪 Dynamic Analysis

BlueLine executes targets under controlled subprocess conditions:

```text
CPU limits

Memory limits

Timeout handling

Process-group isolation
```

Runtime activity can also be monitored.

### File Activity

A real subprocess opening a file was detected end-to-end.

### Network Activity

A real subprocess connecting to a local TCP listener was also detected end-to-end.

The monitoring layer uses `psutil` polling.

---

# 💥 Behavior-Guided Fuzzing

BlueLine's fuzzer is not simply:

```text
seed → mutate → seed → mutate → seed → ...
```

Instead, it promotes inputs that produce **new observable behavior**.

```text
             ┌─────────────┐
             │ Seed Corpus │
             └──────┬──────┘
                    ▼
               ┌─────────┐
               │ Mutate  │
               └────┬────┘
                    ▼
               ┌─────────┐
               │ Execute │
               └────┬────┘
                    ▼
             ┌─────────────┐
             │ New Behavior│
             │   observed? │
             └──────┬──────┘
                    │
              ┌─────┴─────┐
             YES          NO
              │            │
              ▼            ▼
        Next Generation  Discard
```

The generational strategy was tested against a deliberately staged two-condition bug.

| Strategy              |      Detection |
| :-------------------- | -------------: |
| Flat mutation         | `0 / 5` trials |
| Generational mutation |       Reliable |

This behavior is backed by an automated test:

```text
tests/test_fuzzing_generational.py
```

---

# 🔗 Finding Correlation

Multiple analyzers can independently identify the same root issue.

BlueLine merges those results instead of producing redundant findings.

```text
Static Finding
       │
       ├──────────────┐
       │              │
       ▼              ▼
Dynamic Finding    Fuzz Finding
       │              │
       └───────┬──────┘
               ▼
       ┌───────────────┐
       │   CORRELATE   │
       └───────┬───────┘
               ▼
       ┌────────────────┐
       │  Single Root   │
       │     Issue      │
       └────────────────┘
```

A planted crash was independently detected by both **dynamic analysis and fuzzing** and merged into one:

```text
CONFIRMED
```

finding.

---

# 📐 Risk, Confidence & Validation

BlueLine deliberately keeps these dimensions separate.

### Severity

How serious the potential issue is.

### Confidence

How strongly the evidence supports the finding.

### Validation

Whether the behavior has been independently verified.

### Risk

The calculated aggregate representation defined by the project's documented risk model.

This prevents a common mistake in security tooling:

> **Treating "high severity" and "high confidence" as the same thing.**

See:

```text
docs/FINDINGS_AND_RISK.md
```

---

# 📊 Coverage Engine

BlueLine reports what percentage of **applicable analysis actually ran**.

If an analyzer fails:

```text
Analyzer failure
      ↓
Stage coverage = 0%
      ↓
Failure remains visible
```

The scan cannot quietly become "more complete" because a component failed.

Capability and limitation information is also surfaced in:

* Target Setup
* Settings
* Generated reports

---

# 🗃️ Persistence

Scan history is stored in SQLite.

The storage layer is:

* Thread-safe
* Per-user
* Independent of the executable location
* Independent of the current working directory

On Windows:

```text
%LOCALAPPDATA%\BlueLine
```

This allows the packaged application to remain a true standalone executable.

```text
BlueLine.exe
    │
    ├── can be moved
    ├── can run from read-only locations
    └── does not require a companion data folder
```

Scans can be deleted individually or cleared completely.

```bash
python -m app.cli delete <scan_id>
python -m app.cli delete --all
```

---

# 📝 Structured Security Logging

BlueLine maintains five independent JSON-lines streams:

```text
application.log
scanner.log
analyzer.log
security.log
runtime.log
```

The security stream intentionally contains metadata rather than sensitive evidence.

It records things such as:

```text
Finding ID

Category

Location
```

but does **not** leak:

```text
Secret values

Finding evidence

Sensitive target contents
```

This behavior is verified during real scans.

---

# 📄 Reporting

BlueLine generates:

| Format      | Status |
| :---------- | :----: |
| HTML        |    ✅   |
| JSON        |    ✅   |
| SARIF 2.1.0 |    ✅   |
| CSV         |    ✅   |
| PDF         |    ✅   |

### HTML Reports

Reports contain data-driven SVG visualizations:

* Severity distribution
* Coverage breakdown

These are generated from real scan data and verified by actually rendering the report.

### PDF Reports

PDF generation reuses the same HTML/CSS report through `wkhtmltopdf`.

If `wkhtmltopdf` is unavailable, BlueLine returns a clear error instead of silently failing.

---

# 🖥️ Local Web UI

BlueLine includes a local Flask API and web interface.

The server binds to:

```text
127.0.0.1
```

Every screen communicates with the real API.

**No mock data.**

The UI includes:

```text
Target Setup

Scan Profiles

Findings

Severity Breakdown

Coverage

History

Settings

Reports
```

Accessibility is actively tested.

The suite verifies:

* WCAG AA contrast ratios
* Keyboard navigation
* Semantic `<button>` controls
* `aria-expanded`
* `aria-current`
* Radio-based scan profile selection
* `aria-live` regions

The accessibility tests even caught a real contrast failure during development.

---

# ⌨️ CLI

### Scan

```bash
python -m app.cli scan /path/to/target --profile standard --out report.html
```

### Report

```bash
python -m app.cli report <scan_id> --format sarif
```

### Compare

```bash
python -m app.cli compare <scan_id_a> <scan_id_b>
```

### History

```bash
python -m app.cli history
```

### Delete

```bash
python -m app.cli delete <scan_id>
```

or:

```bash
python -m app.cli delete --all
```

The CLI exposes CI-friendly exit codes for automation.

---

# 🚀 Installation

```bash
pip install -r requirements.txt
```

---

# ▶️ Running BlueLine

### Web UI

```bash
python -m app.api_server
```

Then open:

```text
http://127.0.0.1:8642
```

### Native Desktop Window

```bash
pip install pywebview
python -m app.desktop_launcher
```

If `pywebview` is unavailable, BlueLine falls back to the default browser.

### Windows Executable

Build using:

```text
packaging/build_windows.bat
```

Expected output:

```text
dist/
└── BlueLine.exe
```

The executable is designed as a standalone file.

---

# 🧪 Verification

BlueLine follows a simple engineering principle:

<div align="center">

### **If a capability is claimed, there should be a test behind it.**

</div>

Run the complete suite:

```bash
python -m unittest discover -s tests -v
```

The suite covers:

```text
Target discovery

Static analysis

Binary parsing

Corrupted binaries

Dependency detection

Web/API checks

Dynamic execution

Fuzzing

Generational fuzzing

Finding correlation

Risk calculation

Coverage

Persistence

Concurrency

Structured logging

HTML reporting

PDF reporting

Accessibility

CLI behavior

Windows packaging

Analyzer failure isolation

Detection benchmarks
```

Intentionally vulnerable targets are maintained under:

```text
test-targets/
```

---

# 📚 Documentation

| Document                             | Purpose                                    |
| :----------------------------------- | :----------------------------------------- |
| `docs/ARCHITECTURE.md`               | Architecture and analyzer plugin interface |
| `docs/CLI.md`                        | Complete command reference                 |
| `docs/SECURITY_MODEL.md`             | Isolation and threat model                 |
| `docs/FINDINGS_AND_RISK.md`          | Risk, severity, confidence and validation  |
| `docs/SUPPORTED_TARGETS.md`          | Capability matrix                          |
| `docs/TROUBLESHOOTING.md`            | Common issues                              |
| `docs/BlueLine_Project_Proposal.pdf` | Project proposal                           |

---

# ⚠️ Limitations

<details>
<summary><strong>Read before trusting a scan</strong></summary>

<br>

BlueLine is deliberately transparent about its boundaries.

### JavaScript / TypeScript

Pattern-based analysis rather than a complete AST parser.

This can produce both false positives and false negatives.

### C / C++

Experimental pattern-based analysis with limited rules and no complete data-flow engine.

### Dependency Intelligence

The bundled vulnerability database is a small local dataset containing 12 historical CVE entries.

A package that is not flagged is **not proven safe**.

### Fuzzing

No code-coverage instrumentation is currently used.

Behavior-guided generation improves exploration, but highly specific bugs with no observable intermediate behavior can remain undiscovered.

### Runtime Monitoring

File/network monitoring is polling-based at approximately 30 ms intervals.

Very short-lived activity may be missed.

### Language Coverage

Languages such as:

```text
Dart

Elixir

Haskell

C#

Perl
```

are currently unsupported.

They are explicitly reported as `UNSUPPORTED`.

### Binary Analysis

ELF receives the deepest binary analysis.

PE currently provides header metadata but does not parse the import table.

Mach-O currently receives string extraction.

### Web Analysis

The web analyzer is deliberately passive/read-only.

It does not perform:

```text
Authentication attacks

Session testing

Injection testing

Crawling

State-changing requests
```

### Windows Packaging

The development environment did not provide a Windows/mingw toolchain, so the final executable could not be built and executed directly in the development environment.

A real Windows build exposed two actual issues:

1. An obsolete `cipher=` PyInstaller parameter.
2. Missing build-script error handling.

Both were fixed and both failure modes are covered by automated tests.

### Local API Server

The Flask development server is suitable for a single local user.

For a more production-oriented local deployment, a WSGI server such as `waitress` can be substituted.

### PDF

PDF export requires the system-level `wkhtmltopdf` executable.

It is not bundled with BlueLine.

</details>

---

# 🔐 Design Principles

<table>
<tr>

<td align="center" width="25%">

### 🚫

**Don't silently skip**

</td>

<td align="center" width="25%">

### 🧠

**Don't fabricate**

</td>

<td align="center" width="25%">

### 🔍

**Don't hide failures**

</td>

<td align="center" width="25%">

### ✅

**Verify claims**

</td>

</tr>
</table>

BlueLine is built around a simple idea:

> A security tool should be honest about both its **findings** and its **blind spots**.

---

# 📁 Project Structure

```text
BlueLine/

│
├── app/
│   ├── analyzers/
│   ├── core/
│   ├── ...
│   ├── api_server.py
│   ├── cli.py
│   └── desktop_launcher.py
│
├── tests/
├── test-targets/
├── docs/
│   ├── ARCHITECTURE.md
│   ├── BlueLine_Project_Proposal.pdf
│   ├── CLI.md
│   ├── FINDINGS_AND_RISK.md
│   ├── SECURITY_MODEL.md
│   ├── SUPPORTED_TARGETS.md
│   └── TROUBLESHOOTING.md
│
├── packaging/
│   └── build_windows.bat
│
├── requirements.txt
└── README.md
```

---

<div align="center">

<img src="./ui/static/assets/blueline_256.png" width="110" alt="BlueLine logo" />

# BlueLine

### Security analysis without pretending.

**Assume nothing. Test aggressively. Prove what you find.**

<br>

`Static` · `Dynamic` · `Fuzzing` · `Binary` · `Web` · `Risk` · `Reporting`

</div>
