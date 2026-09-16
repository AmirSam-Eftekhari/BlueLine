"""
Local persistence layer.

Uses SQLite (stdlib, no extra dependency) to store scans, target
profiles, and findings so previous scans can be reopened and compared.
Stores the full ScanResult as JSON alongside a few indexed columns for
fast listing/filtering — a pragmatic, real approach for a local desktop
tool (not a distributed system that needs a normalized schema).
"""

from __future__ import annotations

import json
import sqlite3
import threading
from pathlib import Path
from typing import Optional

from app.core.models import ScanResult, Severity

SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
    scan_id TEXT PRIMARY KEY,
    target_path TEXT NOT NULL,
    profile TEXT NOT NULL,
    status TEXT NOT NULL,
    started_at TEXT NOT NULL,
    finished_at TEXT,
    critical_count INTEGER DEFAULT 0,
    high_count INTEGER DEFAULT 0,
    medium_count INTEGER DEFAULT 0,
    low_count INTEGER DEFAULT 0,
    info_count INTEGER DEFAULT 0,
    overall_coverage REAL DEFAULT 0,
    result_json TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_scans_target ON scans(target_path);
CREATE INDEX IF NOT EXISTS idx_scans_started ON scans(started_at);
"""


class ScanStore:
    def __init__(self, db_path: str = "blueline_data.sqlite3"):
        self.db_path = db_path
        Path(db_path).parent.mkdir(parents=True, exist_ok=True) if Path(db_path).parent != Path("") else None
        # check_same_thread=False + an explicit lock: BlueLine's API server
        # runs each scan in a background thread and serves HTTP requests on
        # others, so this store is legitimately used from multiple threads.
        # SQLite's C-level connection object isn't safe for concurrent use
        # without serializing access ourselves.
        self._conn = sqlite3.connect(db_path, check_same_thread=False)
        self._lock = threading.Lock()
        with self._lock:
            self._conn.executescript(SCHEMA)
            self._conn.commit()

    def save(self, result: ScanResult) -> None:
        counts = result.severity_counts()
        with self._lock:
            self._save_locked(result, counts)

    def _save_locked(self, result: ScanResult, counts: dict) -> None:
        self._conn.execute(
            """INSERT OR REPLACE INTO scans
               (scan_id, target_path, profile, status, started_at, finished_at,
                critical_count, high_count, medium_count, low_count, info_count,
                overall_coverage, result_json)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (
                result.scan_id, result.target_profile.target_path, result.config.profile,
                result.status, result.started_at, result.finished_at,
                counts["CRITICAL"], counts["HIGH"], counts["MEDIUM"], counts["LOW"],
                counts["INFORMATIONAL"], result.coverage.get("overall_assessment_coverage", 0),
                json.dumps(result.as_dict()),
            ),
        )
        self._conn.commit()

    def load(self, scan_id: str) -> Optional[dict]:
        with self._lock:
            row = self._conn.execute("SELECT result_json FROM scans WHERE scan_id = ?", (scan_id,)).fetchone()
        if not row:
            return None
        return json.loads(row[0])

    def list_history(self, target_path: Optional[str] = None, limit: int = 50) -> list[dict]:
        with self._lock:
            if target_path:
                rows = self._conn.execute(
                    """SELECT scan_id, target_path, profile, status, started_at, finished_at,
                              critical_count, high_count, medium_count, low_count, info_count, overall_coverage
                       FROM scans WHERE target_path = ? ORDER BY started_at DESC LIMIT ?""",
                    (target_path, limit),
                ).fetchall()
            else:
                rows = self._conn.execute(
                    """SELECT scan_id, target_path, profile, status, started_at, finished_at,
                              critical_count, high_count, medium_count, low_count, info_count, overall_coverage
                       FROM scans ORDER BY started_at DESC LIMIT ?""",
                    (limit,),
                ).fetchall()
        cols = ["scan_id", "target_path", "profile", "status", "started_at", "finished_at",
                "critical_count", "high_count", "medium_count", "low_count", "info_count", "overall_coverage"]
        return [dict(zip(cols, r)) for r in rows]

    def compare(self, scan_id_a: str, scan_id_b: str) -> dict:
        """Regression comparison: previous (a) vs current (b)."""
        a = self.load(scan_id_a)
        b = self.load(scan_id_b)
        if not a or not b:
            raise ValueError("One or both scan IDs not found")

        fp_a = {f["fingerprint"]: f for f in a["findings"]}
        fp_b = {f["fingerprint"]: f for f in b["findings"]}

        new_findings = [f for fp, f in fp_b.items() if fp not in fp_a]
        resolved_findings = [f for fp, f in fp_a.items() if fp not in fp_b]
        unchanged = [f for fp, f in fp_b.items() if fp in fp_a]

        worsened = []
        for fp, f_b in fp_b.items():
            f_a = fp_a.get(fp)
            if f_a and _severity_rank(f_b["severity"]) > _severity_rank(f_a["severity"]):
                worsened.append({"fingerprint": fp, "from": f_a["severity"], "to": f_b["severity"],
                                  "title": f_b["title"]})

        def counts_for(scan):
            c = {s.value: 0 for s in Severity}
            for f in scan["findings"]:
                c[f["severity"]] += 1
            return c

        return {
            "previous_scan_id": scan_id_a,
            "current_scan_id": scan_id_b,
            "severity_counts_previous": counts_for(a),
            "severity_counts_current": counts_for(b),
            "new_findings": new_findings,
            "resolved_findings": resolved_findings,
            "worsened_findings": worsened,
            "unchanged_count": len(unchanged),
        }

    def close(self):
        self._conn.close()


def _severity_rank(sev: str) -> int:
    return {"INFORMATIONAL": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}.get(sev, 0)
