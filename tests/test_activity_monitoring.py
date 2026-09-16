import socket
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path

from app.runtime.dynamic import DynamicRunner


class TestActivityMonitoring(unittest.TestCase):
    def test_detects_real_file_open(self):
        with tempfile.TemporaryDirectory() as tmp:
            target_file = str(Path(tmp) / "sentinel.txt")
            script = Path(tmp) / "opener.py"
            script.write_text(
                "import time\n"
                f"f = open({target_file!r}, 'w')\n"
                "f.write('hello')\n"
                "time.sleep(0.3)\n"  # give the poll thread (30ms interval) time to observe it
                "f.close()\n"
            )
            runner = DynamicRunner(timeout_seconds=5)
            obs = runner.run([sys.executable, str(script)], monitor_activity=True)
            self.assertTrue(obs.activity_monitoring_available)
            self.assertTrue(any(target_file in f for f in obs.file_activity),
                             f"Expected {target_file} in {obs.file_activity}")

    def test_detects_real_network_connection(self):
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.bind(("127.0.0.1", 0))
        port = server.getsockname()[1]
        server.listen(1)

        def accept_once():
            try:
                conn, _ = server.accept()
                time.sleep(0.3)
                conn.close()
            except OSError:
                pass

        t = threading.Thread(target=accept_once, daemon=True)
        t.start()
        try:
            with tempfile.TemporaryDirectory() as tmp:
                script = Path(tmp) / "netclient.py"
                script.write_text(
                    "import socket, time\n"
                    "s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)\n"
                    f"s.connect(('127.0.0.1', {port}))\n"
                    "time.sleep(0.3)\n"
                    "s.close()\n"
                )
                runner = DynamicRunner(timeout_seconds=5)
                obs = runner.run([sys.executable, str(script)], monitor_activity=True)
                self.assertTrue(any(str(port) in n for n in obs.network_activity),
                                 f"Expected port {port} in {obs.network_activity}")
        finally:
            server.close()
            t.join(timeout=1)

    def test_no_monitoring_when_not_requested(self):
        with tempfile.TemporaryDirectory() as tmp:
            script = Path(tmp) / "quiet.py"
            script.write_text("print('hi')\n")
            runner = DynamicRunner(timeout_seconds=5)
            obs = runner.run([sys.executable, str(script)])  # monitor_activity defaults to False
            self.assertEqual(obs.file_activity, [])
            self.assertEqual(obs.network_activity, [])

    def test_quiet_script_shows_no_activity(self):
        with tempfile.TemporaryDirectory() as tmp:
            script = Path(tmp) / "quiet.py"
            script.write_text("print('hi')\n")
            runner = DynamicRunner(timeout_seconds=5)
            obs = runner.run([sys.executable, str(script)], monitor_activity=True)
            self.assertEqual(obs.network_activity, [])

    def test_monitoring_does_not_break_crash_detection(self):
        # Activity monitoring runs alongside the existing crash/timeout
        # classification — it must not interfere with it.
        with tempfile.TemporaryDirectory() as tmp:
            script = Path(tmp) / "crasher.py"
            script.write_text("raise RuntimeError('boom')\n")
            runner = DynamicRunner(timeout_seconds=5)
            obs = runner.run([sys.executable, str(script)], monitor_activity=True)
            self.assertEqual(obs.classification, "crash")

    def test_monitoring_survives_process_that_exits_immediately(self):
        # A process that exits before the poll thread gets a chance to
        # observe anything must not crash the monitor or the runner.
        with tempfile.TemporaryDirectory() as tmp:
            script = Path(tmp) / "instant.py"
            script.write_text("pass\n")
            runner = DynamicRunner(timeout_seconds=5)
            obs = runner.run([sys.executable, str(script)], monitor_activity=True)
            self.assertEqual(obs.classification, "normal")

    def test_run_does_not_leak_its_own_temp_directory(self):
        # Regression: DynamicRunner used to create a fresh
        # tempfile.mkdtemp() sandbox per run and never clean it up —
        # a single 100-case fuzzing campaign left 100 empty directories
        # behind in /tmp, unboundedly, for the lifetime of the machine.
        import glob
        import os as _os
        before = set(glob.glob(_os.path.join(tempfile.gettempdir(), "blueline_run_*")))
        with tempfile.TemporaryDirectory() as tmp:
            script = Path(tmp) / "quiet.py"
            script.write_text("print('hi')\n")
            runner = DynamicRunner(timeout_seconds=5)
            for _ in range(5):
                runner.run([sys.executable, str(script)])
        after = set(glob.glob(_os.path.join(tempfile.gettempdir(), "blueline_run_*")))
        self.assertEqual(after - before, set(),
                          "DynamicRunner.run() leaked its own temp sandbox directory")

    def test_run_does_not_delete_a_caller_provided_cwd(self):
        # The cleanup fix must only remove directories DynamicRunner
        # itself created via mkdtemp() — never a cwd the caller explicitly passed.
        with tempfile.TemporaryDirectory() as caller_dir:
            script = Path(caller_dir) / "quiet.py"
            script.write_text("print('hi')\n")
            runner = DynamicRunner(timeout_seconds=5)
            runner.run([sys.executable, str(script)], cwd=caller_dir)
            self.assertTrue(Path(caller_dir).exists(), "Runner deleted a caller-provided cwd")


if __name__ == "__main__":
    unittest.main()
