"""
Intentionally vulnerable fixture. Local test data only — never deploy this.
Each bug below is tagged with the BlueLine rule ID it should trigger.
"""

import hashlib
import os
import pickle
import subprocess
import tarfile
import tempfile

import yaml

API_KEY = "sk_live_51H8x9aQwErTyUiOpAsDfGhJk"  # PY-HARDCODED-SECRET


def run_user_command(user_input):
    os.system("echo " + user_input)  # PY-OS-SYSTEM


def run_shell(cmd):
    subprocess.call(cmd, shell=True)  # PY-SUBPROC-SHELL


def load_config(raw_yaml):
    return yaml.load(raw_yaml)  # PY-YAML-UNSAFE


def load_session(blob):
    return pickle.loads(blob)  # PY-PICKLE-LOAD


def weak_hash(password):
    return hashlib.md5(password.encode()).hexdigest()  # PY-WEAK-HASH


def run_query(cursor, table_name):
    query = "SELECT * FROM " + table_name + " WHERE active=1"
    cursor.execute(query)  # PY-SQL-CONCAT


def make_temp_file():
    path = tempfile.mktemp()  # PY-TEMP-INSECURE
    return path


def extract_archive(archive_path, dest):
    with tarfile.open(archive_path) as tar:
        tar.extractall(dest)  # PY-TAR-TRAVERSAL


def check_permission(user):
    assert user.is_admin  # PY-ASSERT-SECURITY


def risky_eval(expr):
    return eval(expr)  # PY-EVAL-EXEC


def swallow_errors():
    try:
        1 / 0
    except:  # PY-BROAD-EXCEPT
        pass


def crash_on_specific_input(payload: str):
    """A deliberate, deterministic bug for the dynamic/fuzz engine to find:
    any input starting with 'BOOM' triggers an unhandled exception."""
    if payload.startswith("BOOM"):
        raise RuntimeError("simulated crash for fuzz-detection testing")
    if len(payload) > 50000:
        # simulate a hang-like condition on oversized input
        total = 0
        for _ in range(len(payload) * 2000):
            total += 1
        return total
    return len(payload)


if __name__ == "__main__":
    import sys
    data = sys.stdin.buffer.read()
    try:
        text = data.decode("utf-8", errors="replace")
    except Exception:
        text = ""
    result = crash_on_specific_input(text)
    print(f"processed {result} chars")
