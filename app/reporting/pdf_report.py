"""
PDF report generation.

Renders the same HTML report (`html_report.generate_html_report`) to
PDF via the `wkhtmltopdf` binary, run as a subprocess. This is NOT a
new report design — it reuses the exact HTML/CSS that's already
generated and tested, so there's no separate PDF-specific template to
drift out of sync with the HTML one.

`wkhtmltopdf` is a system binary, not a Python package — it may not be
installed on every machine that runs BlueLine. This module checks for
it explicitly and raises a clear, catchable `PdfGenerationError` (never
a bare crash) when it's missing, rather than silently producing nothing
or pretending PDF export always works. Callers (CLI, API) are expected
to catch this and tell the user plainly what to install.
"""

from __future__ import annotations

import shutil
import subprocess
import tempfile
from pathlib import Path

from app.core.models import ScanResult
from app.reporting.html_report import generate_html_report


class PdfGenerationError(Exception):
    """Raised when PDF generation cannot proceed — missing binary, or
    the conversion itself failed. Always carries a human-readable reason."""


def wkhtmltopdf_available() -> bool:
    return shutil.which("wkhtmltopdf") is not None


def generate_pdf_report(result: ScanResult, timeout_seconds: int = 30) -> bytes:
    """Returns the PDF file content as bytes. Raises PdfGenerationError
    (never a bare exception) if wkhtmltopdf isn't installed or the
    conversion fails."""
    if not wkhtmltopdf_available():
        raise PdfGenerationError(
            "PDF export requires the 'wkhtmltopdf' binary, which isn't installed on this "
            "machine. Install it from https://wkhtmltopdf.org/ (or your OS package manager) "
            "and try again — or use the HTML report, which contains the same content."
        )

    html_content = generate_html_report(result)

    with tempfile.TemporaryDirectory() as tmp:
        html_path = Path(tmp) / "report.html"
        pdf_path = Path(tmp) / "report.pdf"
        html_path.write_text(html_content, encoding="utf-8")

        try:
            proc = subprocess.run(
                ["wkhtmltopdf", "--quiet", "--enable-local-file-access",
                 str(html_path), str(pdf_path)],
                capture_output=True, timeout=timeout_seconds,
            )
        except subprocess.TimeoutExpired as e:
            raise PdfGenerationError(f"PDF generation timed out after {timeout_seconds}s") from e
        except OSError as e:
            raise PdfGenerationError(f"Could not run wkhtmltopdf: {e}") from e

        if not pdf_path.exists() or pdf_path.stat().st_size == 0:
            stderr = proc.stderr.decode(errors="replace")[:500] if proc.stderr else ""
            raise PdfGenerationError(f"wkhtmltopdf did not produce a PDF file. {stderr}")

        return pdf_path.read_bytes()
