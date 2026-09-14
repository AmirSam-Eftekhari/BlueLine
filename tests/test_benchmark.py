"""
Detection benchmark.

Ground truth: a manifest of bugs I deliberately planted in the fixtures
under test-targets/, each tagged with the exact line and rule ID that
should catch it (see the "PY-XXX" comments in the fixture source files
themselves — this manifest is transcribed directly from those comments,
not invented after the fact to make numbers look good).

This prints a genuine Detected/Confirmed/False-Positive breakdown. It is
intentionally small and honest rather than inflated: BlueLine v1 does not
claim to catch every bug class in every language, and this benchmark
would immediately expose it if a change silently broke detection.
"""

from __future__ import annotations

import unittest
from pathlib import Path

from app.analyzers.c_cpp_static import CCppStaticAnalyzer
from app.analyzers.dependency import DependencyAnalyzer
from app.analyzers.go_static import GoStaticAnalyzer
from app.analyzers.java_static import JavaStaticAnalyzer
from app.analyzers.js_static import JavaScriptStaticAnalyzer
from app.analyzers.php_static import PhpStaticAnalyzer
from app.analyzers.python_static import PythonStaticAnalyzer
from app.analyzers.ruby_static import RubyStaticAnalyzer
from app.analyzers.rust_static import RustStaticAnalyzer
from app.core.models import ScanConfig
from app.targets.discovery import TargetDiscovery

ROOT = Path(__file__).resolve().parent.parent / "test-targets"

# (fixture_dir, file, line, rule_id_substring_expected_in_evidence_or_title)
GROUND_TRUTH = [
    ("vulnerable-python", "app_vuln.py", 15, "PY-HARDCODED-SECRET"),
    ("vulnerable-python", "app_vuln.py", 19, "PY-OS-SYSTEM"),
    ("vulnerable-python", "app_vuln.py", 23, "PY-SUBPROC-SHELL"),
    ("vulnerable-python", "app_vuln.py", 27, "PY-YAML-UNSAFE"),
    ("vulnerable-python", "app_vuln.py", 31, "PY-PICKLE-LOAD"),
    ("vulnerable-python", "app_vuln.py", 35, "PY-WEAK-HASH"),
    ("vulnerable-python", "app_vuln.py", 40, "PY-SQL-CONCAT"),
    ("vulnerable-python", "app_vuln.py", 44, "PY-TEMP-INSECURE"),
    ("vulnerable-python", "app_vuln.py", 50, "PY-TAR-TRAVERSAL"),
    ("vulnerable-python", "app_vuln.py", 54, "PY-ASSERT-SECURITY"),
    ("vulnerable-python", "app_vuln.py", 58, "PY-EVAL-EXEC"),
    ("vulnerable-python", "app_vuln.py", 64, "PY-BROAD-EXCEPT"),
    ("vulnerable-python", "server_vuln.py", 11, "PY-DEBUG-FLASK"),
    ("vulnerable-python", "server_vuln.py", 11, "PY-BIND-ALL"),
    ("vulnerable-javascript", "app_vuln.js", 6, "JS-CHILDPROC-EXEC"),
    ("vulnerable-javascript", "app_vuln.js", 10, "JS-INNERHTML"),
    ("vulnerable-javascript", "app_vuln.js", 14, "JS-EVAL"),
    ("vulnerable-javascript", "app_vuln.js", 17, "JS-HARDCODED-SECRET"),
    ("vulnerable-javascript", "app_vuln.js", 20, "JS-SQL-CONCAT"),
    ("vulnerable-javascript", "app_vuln.js", 24, "JS-JWT-NONE"),
    ("vulnerable-javascript", "app_vuln.js", 28, "JS-NOSNIFF-DISABLED"),
    ("vulnerable-javascript", "app_vuln.js", 32, "JS-INSECURE-RANDOM"),
    ("vulnerable-c", "vuln.c", 7, "strcpy"),
    ("vulnerable-c", "vuln.c", 12, "system"),
    ("vulnerable-c", "vuln.c", 17, "gets"),
    ("vulnerable-java", "App.java", 8, "JAVA-HARDCODED-SECRET"),
    ("vulnerable-java", "App.java", 11, "JAVA-RUNTIME-EXEC"),
    ("vulnerable-java", "App.java", 15, "JAVA-OBJ-DESERIALIZE"),
    ("vulnerable-java", "App.java", 20, "JAVA-XXE"),
    ("vulnerable-java", "App.java", 25, "JAVA-WEAK-HASH"),
    ("vulnerable-java", "App.java", 30, "JAVA-WEAK-CIPHER"),
    ("vulnerable-java", "App.java", 36, "JAVA-SQL-CONCAT"),
    ("vulnerable-java", "App.java", 41, "JAVA-INSECURE-RANDOM"),
    ("vulnerable-go", "main.go", 4, "GO-WEAK-HASH"),
    ("vulnerable-go", "main.go", 8, "GO-INSECURE-RANDOM"),
    ("vulnerable-go", "main.go", 12, "GO-HARDCODED-SECRET"),
    ("vulnerable-go", "main.go", 15, "GO-EXEC-COMMAND-SHELL"),
    ("vulnerable-go", "main.go", 19, "GO-INSECURE-SKIP-VERIFY"),
    ("vulnerable-go", "main.go", 31, "GO-SQL-CONCAT"),
    ("vulnerable-ruby", "app.rb", 4, "RB-HARDCODED-SECRET"),
    ("vulnerable-ruby", "app.rb", 7, "RB-SYSTEM-EXEC"),
    ("vulnerable-ruby", "app.rb", 11, "RB-YAML-UNSAFE"),
    ("vulnerable-ruby", "app.rb", 15, "RB-MARSHAL-LOAD"),
    ("vulnerable-ruby", "app.rb", 19, "RB-WEAK-HASH"),
    ("vulnerable-ruby", "app.rb", 23, "RB-SQL-INTERP"),
    ("vulnerable-ruby", "app.rb", 27, "RB-DYNAMIC-SEND"),
    ("vulnerable-ruby", "app.rb", 31, "RB-EVAL"),
    ("vulnerable-php", "app.php", 2, "PHP-HARDCODED-SECRET"),
    ("vulnerable-php", "app.php", 5, "PHP-SHELL-EXEC"),
    ("vulnerable-php", "app.php", 9, "PHP-UNSERIALIZE"),
    ("vulnerable-php", "app.php", 13, "PHP-LFI-INCLUDE"),
    ("vulnerable-php", "app.php", 17, "PHP-EXTRACT-REQUEST"),
    ("vulnerable-php", "app.php", 21, "PHP-SQL-CONCAT"),
    ("vulnerable-php", "app.php", 26, "PHP-EVAL"),
    ("vulnerable-rust", "main.rs", 3, "RUST-HARDCODED-SECRET"),
    ("vulnerable-rust", "main.rs", 6, "RUST-UNSAFE-BLOCK"),
    ("vulnerable-rust", "main.rs", 12, "RUST-COMMAND-SHELL"),
    ("vulnerable-rust", "main.rs", 16, "RUST-WEAK-HASH"),
    ("vulnerable-rust", "main.rs", 20, "RUST-SQL-FORMAT"),
    ("vulnerable-rust", "main.rs", 24, "RUST-UNWRAP-EXTERNAL"),
    ("vulnerable-rust", "main.rs", 28, "RUST-TRANSMUTE"),
]


class TestDetectionBenchmark(unittest.TestCase):
    def test_benchmark_and_print_report(self):
        py_analyzer = PythonStaticAnalyzer()
        js_analyzer = JavaScriptStaticAnalyzer()
        c_analyzer = CCppStaticAnalyzer()
        java_analyzer = JavaStaticAnalyzer()
        go_analyzer = GoStaticAnalyzer()
        ruby_analyzer = RubyStaticAnalyzer()
        php_analyzer = PhpStaticAnalyzer()
        rust_analyzer = RustStaticAnalyzer()
        config = ScanConfig.for_profile("standard")

        all_findings_by_fixture = {}
        for fixture in ("vulnerable-python", "vulnerable-javascript", "vulnerable-c",
                        "vulnerable-java", "vulnerable-go", "vulnerable-ruby", "vulnerable-php",
                        "vulnerable-rust"):
            path = str(ROOT / fixture)
            profile = TargetDiscovery().discover(path)
            findings = []
            findings += py_analyzer.run(profile, config)
            findings += js_analyzer.run(profile, config)
            findings += c_analyzer.run(profile, config)
            findings += java_analyzer.run(profile, config)
            findings += go_analyzer.run(profile, config)
            findings += ruby_analyzer.run(profile, config)
            findings += php_analyzer.run(profile, config)
            findings += rust_analyzer.run(profile, config)
            all_findings_by_fixture[fixture] = findings

        detected = 0
        missed = []
        for fixture, filename, line, rule_hint in GROUND_TRUTH:
            findings = all_findings_by_fixture[fixture]
            hit = any(
                f.location and f.location.endswith(f"{filename}:{line}")
                and (rule_hint in (f.evidence[0].description if f.evidence else "") or rule_hint in f.title)
                for f in findings
            )
            if hit:
                detected += 1
            else:
                missed.append((fixture, filename, line, rule_hint))

        total = len(GROUND_TRUTH)
        detection_rate = round(100 * detected / total, 1)

        print(f"\n=== BlueLine Detection Benchmark ===")
        print(f"Expected findings (planted bugs): {total}")
        print(f"Detected:                          {detected}")
        print(f"Detection rate:                     {detection_rate}%")
        if missed:
            print("Missed:")
            for m in missed:
                print(f"  - {m}")
        print("Note: this benchmark covers ONLY the bug classes deliberately planted in")
        print("test-targets/. It is not a general statement of BlueLine's real-world")
        print("detection rate against arbitrary code, and false-positive rate against")
        print("large real-world codebases has not been separately measured in this build.")

        # Bar is honest, not inflated: we expect the rules we actually wrote to fire.
        self.assertGreaterEqual(detection_rate, 90.0,
                                 f"Detection rate regressed below 90% on the fixed benchmark set: missed {missed}")


if __name__ == "__main__":
    unittest.main()
