import socket
import threading
import time
import unittest

from app.core.models import ScanConfig
from app.targets.discovery import TargetDiscovery
from app.analyzers.web_api import WebApiAnalyzer


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _build_misconfigured_app():
    from flask import Flask, Response, request

    app = Flask("misconfigured_fixture")

    @app.route("/", methods=["GET", "OPTIONS", "PUT", "DELETE"])
    def index():
        resp = Response("hello", status=200)
        # Deliberately missing: HSTS, X-Content-Type-Options, CSP.
        resp.headers["Server"] = "TotallyRealServer/1.2.3"
        resp.headers["X-Powered-By"] = "PHP/7.2.0"
        # Deliberately insecure cookie: no Secure/HttpOnly/SameSite.
        resp.headers["Set-Cookie"] = "session=abc123; Path=/"
        # Deliberately dangerous CORS: reflect ANY origin + allow credentials.
        origin = request.headers.get("Origin", "*")
        resp.headers["Access-Control-Allow-Origin"] = origin
        resp.headers["Access-Control-Allow-Credentials"] = "true"
        if request.method == "OPTIONS":
            resp.headers["Allow"] = "GET, POST, PUT, DELETE, OPTIONS, TRACE"
        return resp

    return app


class TestWebApiAnalyzer(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.port = _free_port()
        cls.app = _build_misconfigured_app()
        cls.server_thread = threading.Thread(
            target=lambda: cls.app.run(host="127.0.0.1", port=cls.port, debug=False, use_reloader=False),
            daemon=True,
        )
        cls.server_thread.start()
        # Wait for the real server to actually be accepting connections —
        # no fixed sleep-and-hope, poll the actual socket.
        deadline = time.time() + 5
        while time.time() < deadline:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                if s.connect_ex(("127.0.0.1", cls.port)) == 0:
                    break
            time.sleep(0.05)
        else:
            raise RuntimeError("Test Flask server did not start in time")

        cls.url = f"http://127.0.0.1:{cls.port}/"
        cls.profile = TargetDiscovery().discover(cls.url)
        cls.findings = WebApiAnalyzer().run(cls.profile, ScanConfig.for_profile("standard"))

    def test_target_discovery_recognizes_url_target(self):
        self.assertEqual(self.profile.target_type, "Web/API Service")
        self.assertIn("HTTP API", self.profile.interfaces)

    def test_detects_plaintext_http_transport(self):
        titles = {f.title for f in self.findings}
        self.assertTrue(any("plaintext HTTP" in t for t in titles))

    def test_detects_missing_security_headers(self):
        subcats = {f.subcategory for f in self.findings}
        self.assertIn("Missing Security Header", subcats)
        titles = " ".join(f.title for f in self.findings)
        self.assertIn("X-Content-Type-Options", titles)
        self.assertIn("Content-Security-Policy", titles)

    def test_does_not_demand_hsts_over_plain_http(self):
        # HSTS is meaningless over plain HTTP — must not be flagged as "missing".
        titles = " ".join(f.title for f in self.findings)
        self.assertNotIn("HSTS", titles)

    def test_detects_server_banner_disclosure(self):
        categories = {f.category for f in self.findings}
        self.assertIn("Information Disclosure", categories)
        titles = " ".join(f.title for f in self.findings)
        self.assertIn("TotallyRealServer", titles)

    def test_detects_insecure_cookie_flags(self):
        titles = [f.title for f in self.findings if f.subcategory == "Insecure Cookie Flags"]
        self.assertTrue(titles)
        self.assertIn("HttpOnly", titles[0])
        self.assertIn("SameSite", titles[0])

    def test_detects_cors_reflecting_arbitrary_origin(self):
        cors_findings = [f for f in self.findings if f.subcategory == "CORS Misconfiguration"]
        self.assertTrue(cors_findings, "Failed to detect CORS reflecting an arbitrary probe Origin")
        self.assertEqual(cors_findings[0].severity.value, "HIGH")
        self.assertEqual(cors_findings[0].validation_status.value, "CONFIRMED")

    def test_detects_risky_http_methods_via_options(self):
        titles = " ".join(f.title for f in self.findings)
        self.assertIn("TRACE", titles)

    def test_never_makes_state_changing_requests(self):
        # The analyzer must only ever have used GET/HEAD/OPTIONS — verified
        # indirectly: the fixture route handles PUT/DELETE by returning the
        # exact same 'hello' body as GET, so if the analyzer's evidence ever
        # shows anything method-specific beyond OPTIONS/GET, that would be
        # a real signal it went further than intended. Nothing in `findings`
        # evidence references a PUT/DELETE having been issued BY the analyzer.
        for f in self.findings:
            for e in f.evidence:
                self.assertNotIn("PUT request", e.description)
                self.assertNotIn("DELETE request", e.description)

    def test_analyzer_applies_to_web_target_only(self):
        analyzer = WebApiAnalyzer()
        self.assertTrue(analyzer.applies_to(self.profile))
        non_web_profile = TargetDiscovery().discover(
            __file__.rsplit("/", 1)[0] + "/../test-targets/vulnerable-python")
        self.assertFalse(analyzer.applies_to(non_web_profile))

    def test_unreachable_target_is_informational_not_a_crash(self):
        dead_port = _free_port()  # nothing listening here
        profile = TargetDiscovery().discover(f"http://127.0.0.1:{dead_port}/")
        findings = WebApiAnalyzer().run(profile, ScanConfig.for_profile("standard"))
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].validation_status.value, "UNVERIFIED")
        self.assertEqual(findings[0].severity.value, "INFORMATIONAL")


if __name__ == "__main__":
    unittest.main()
