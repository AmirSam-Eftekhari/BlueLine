"""
Dynamic analysis / controlled execution engine.

Runs a target (a script or executable BlueLine can actually invoke) as a
real subprocess with resource limits, captures its actual behavior, and
classifies the outcome. This is real process execution and observation —
not simulated. Isolation approach:

  - Runs in a dedicated temp working directory (never the target's own
    directory, so the target can't clobber project files).
  - Hard wall-clock timeout via subprocess timeout + process-group kill
    (so children can't survive the parent being killed).
  - On POSIX, applies RLIMIT_CPU / RLIMIT_AS / RLIMIT_NOFILE via
    `preexec_fn` so a runaway target can't consume unbounded CPU/memory.
  - Captures stdout/stderr (size-capped) and exit code.
  - Never executes with shell=True — always an explicit argv list.

This is intentionally conservative: it does NOT attempt to defeat
sandboxing, escape containers, or execute anything the user didn't
explicitly point BlueLine at. The target is the user's own authorized
artifact.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
import tempfile
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

try:
    import psutil
except ImportError:  # pragma: no cover - psutil is a declared dependency, but degrade gracefully
    psutil = None

MAX_CAPTURED_BYTES = 64 * 1024


@dataclass
class ExecutionObservation:
    command: list[str]
    input_data: Optional[bytes]
    exit_code: Optional[int]
    stdout: str
    stderr: str
    duration_seconds: float
    timed_out: bool
    classification: str  # "normal" | "nonzero_exit" | "crash" | "timeout" | "spawn_error"
    error: Optional[str] = None
    file_activity: list[str] = field(default_factory=list)      # file paths observed open during execution
    network_activity: list[str] = field(default_factory=list)   # "ip:port" remote endpoints observed
    activity_monitoring_available: bool = True  # False if psutil/platform couldn't support it


class _ActivityMonitor:
    """Polls the child process (and its children) for open files and
    network connections while it runs. This is real observation via
    psutil against the actual running process — not simulated — but it
    is polling-based (every 30ms), so a file opened and closed faster
    than that between polls can be missed. That's a real, stated
    limitation, not a hidden one (see docs/SECURITY_MODEL.md)."""

    def __init__(self, pid: int, poll_interval: float = 0.03):
        self.pid = pid
        self.poll_interval = poll_interval
        self.file_paths: set[str] = set()
        self.network_endpoints: set[str] = set()
        self.available = psutil is not None
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None

    def start(self):
        if not self.available:
            return
        self._thread = threading.Thread(target=self._poll_loop, daemon=True)
        self._thread.start()

    def _poll_loop(self):
        try:
            proc = psutil.Process(self.pid)
        except psutil.NoSuchProcess:
            return
        while not self._stop.is_set():
            try:
                procs = [proc] + proc.children(recursive=True)
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                break
            for p in procs:
                try:
                    for f in p.open_files():
                        self.file_paths.add(f.path)
                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    pass
                try:
                    conns = p.net_connections() if hasattr(p, "net_connections") else p.connections()
                    for c in conns:
                        if c.raddr:
                            self.network_endpoints.add(f"{c.raddr.ip}:{c.raddr.port}")
                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess, AttributeError):
                    pass
            if self._stop.wait(self.poll_interval):
                break

    def stop(self):
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=1.0)


class DynamicRunner:
    def __init__(self, timeout_seconds: int = 5, max_memory_mb: int = 256):
        self.timeout_seconds = timeout_seconds
        self.max_memory_mb = max_memory_mb

    def _preexec(self):
        """POSIX-only resource limiting, applied in the child before exec."""
        if sys.platform == "win32":
            return None

        def _limit():
            import resource
            try:
                resource.setrlimit(resource.RLIMIT_CPU, (self.timeout_seconds + 2, self.timeout_seconds + 2))
            except (ValueError, OSError):
                pass
            try:
                mem_bytes = self.max_memory_mb * 1024 * 1024
                resource.setrlimit(resource.RLIMIT_AS, (mem_bytes, mem_bytes))
            except (ValueError, OSError):
                pass
            try:
                resource.setrlimit(resource.RLIMIT_NOFILE, (64, 64))
            except (ValueError, OSError):
                pass
            try:
                os.setsid()  # own process group, so we can kill children on timeout
            except OSError:
                pass

        return _limit

    def run(self, command: list[str], input_data: Optional[bytes] = None,
            cwd: Optional[str] = None, monitor_activity: bool = False) -> ExecutionObservation:
        work_dir = cwd or tempfile.mkdtemp(prefix="blueline_run_")
        started = time.monotonic()
        timed_out = False
        try:
            proc = subprocess.Popen(
                command,
                stdin=subprocess.PIPE if input_data is not None else subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                cwd=work_dir,
                shell=False,
                preexec_fn=self._preexec() if sys.platform != "win32" else None,
            )
        except OSError as e:
            return ExecutionObservation(command=command, input_data=input_data, exit_code=None,
                                         stdout="", stderr="", duration_seconds=0.0, timed_out=False,
                                         classification="spawn_error", error=str(e))

        monitor = _ActivityMonitor(proc.pid) if monitor_activity else None
        if monitor:
            monitor.start()

        try:
            stdout, stderr = proc.communicate(input=input_data, timeout=self.timeout_seconds)
        except subprocess.TimeoutExpired:
            timed_out = True
            self._kill_tree(proc)
            try:
                stdout, stderr = proc.communicate(timeout=2)
            except Exception:
                stdout, stderr = b"", b""

        if monitor:
            monitor.stop()

        duration = time.monotonic() - started
        exit_code = proc.returncode

        classification = self._classify(exit_code, timed_out, stderr)

        return ExecutionObservation(
            command=command,
            input_data=input_data,
            exit_code=exit_code,
            stdout=_truncate(stdout),
            stderr=_truncate(stderr),
            duration_seconds=round(duration, 3),
            timed_out=timed_out,
            file_activity=sorted(monitor.file_paths) if monitor else [],
            network_activity=sorted(monitor.network_endpoints) if monitor else [],
            activity_monitoring_available=(monitor.available if monitor else True),
            classification=classification,
        )

    @staticmethod
    def _kill_tree(proc: subprocess.Popen):
        try:
            if sys.platform == "win32":
                proc.kill()
            else:
                pgid = os.getpgid(proc.pid)
                os.killpg(pgid, 9)
        except (ProcessLookupError, OSError):
            try:
                proc.kill()
            except Exception:
                pass

    @staticmethod
    def _classify(exit_code: Optional[int], timed_out: bool, stderr: bytes) -> str:
        if timed_out:
            return "timeout"
        if exit_code is None:
            return "spawn_error"
        if os.name != "nt" and exit_code < 0:
            # Negative return code from subprocess on POSIX means the
            # child was killed by signal -exit_code (e.g. SIGSEGV=11,
            # SIGABRT=6, SIGFPE=8) — a genuine crash, not just a nonzero exit.
            return "crash"
        if exit_code == 0:
            return "normal"
        stderr_text = stderr.decode(errors="ignore").lower()
        crash_markers = ("segmentation fault", "segfault", "traceback (most recent call last)",
                          "unhandled exception", "core dumped", "stack overflow", "assertion failed",
                          "sanitizer")
        if any(m in stderr_text for m in crash_markers):
            return "crash"
        return "nonzero_exit"


def _truncate(data: bytes) -> str:
    text = data.decode(errors="ignore")
    if len(text) > MAX_CAPTURED_BYTES:
        return text[:MAX_CAPTURED_BYTES] + f"\n...[truncated, {len(text)} bytes total]"
    return text
