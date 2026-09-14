"""
Structured logging.

Five separate log streams, each its own rotating file under
paths.user_data_dir() / "logs" — not one undifferentiated stream, per
the product requirement to separate application logs, scanner logs,
analyzer logs, security events, and runtime events:

    blueline.app       — process lifecycle (server start/stop, CLI invocation)
    blueline.scanner   — orchestrator stage transitions (started/completed/failed/skipped)
    blueline.analyzer  — per-analyzer warnings/errors (a broken analyzer's exception, etc.)
    blueline.security  — HIGH/CRITICAL findings only — the "what did we actually find
                          that matters" trail, kept separate so it's not buried in
                          routine scanner noise
    blueline.runtime   — dynamic analysis / fuzzing execution events (crashes, timeouts)

Each entry is a single JSON line (not a free-text message) — genuinely
structured, not just labeled. Deliberately excludes finding evidence
snippets/raw_output (which can contain target source code or extracted
strings) from the log record itself — logs carry metadata (finding id,
category, severity, location) for diagnosing BlueLine's OWN behavior,
not a copy of everything BlueLine read from the target. This is the
same "don't expose unnecessary sensitive target contents" principle
applied to logging specifically.
"""

from __future__ import annotations

import json
import logging
import logging.handlers
import threading
from datetime import datetime, timezone
from pathlib import Path

from app.core import paths

_LOGGERS: dict[str, logging.Logger] = {}
_LOCK = threading.Lock()

LOG_NAMES = ["app", "scanner", "analyzer", "security", "runtime"]


class _JsonLineFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        extra = getattr(record, "structured", None)
        if extra:
            payload["data"] = extra
        return json.dumps(payload, default=str)


def _build_logger(name: str) -> logging.Logger:
    logger = logging.getLogger(f"blueline.{name}")
    logger.setLevel(logging.INFO)
    logger.propagate = False  # don't also dump to the root logger / stderr

    log_dir = paths.user_data_dir() / "logs"
    log_dir.mkdir(parents=True, exist_ok=True)
    handler = logging.handlers.RotatingFileHandler(
        log_dir / f"{name}.log", maxBytes=5 * 1024 * 1024, backupCount=3, encoding="utf-8",
    )
    handler.setFormatter(_JsonLineFormatter())
    logger.addHandler(handler)
    return logger


def get_logger(name: str) -> logging.Logger:
    """name is one of LOG_NAMES ('app', 'scanner', 'analyzer', 'security', 'runtime')."""
    with _LOCK:
        if name not in _LOGGERS:
            _LOGGERS[name] = _build_logger(name)
        return _LOGGERS[name]


def log_structured(stream: str, message: str, **data) -> None:
    """Convenience wrapper: log_structured('scanner', 'stage completed', stage='X', findings=3)."""
    logger = get_logger(stream)
    logger.info(message, extra={"structured": data})


def log_dirs() -> Path:
    return paths.user_data_dir() / "logs"
