"""
Web/API analyzer — real, but deliberately narrow-scope and safe.

This makes actual network requests, unlike every other analyzer in
BlueLine. To stay inside "controlled, authorized, non-destructive"
testing (per the product's security philosophy), it:

  - Only ever issues GET, HEAD, and OPTIONS requests. Never PUT/POST/
    DELETE/PATCH — this is a passive configuration check, not an active
    exploitation attempt.
  - Only ever talks to the single URL the user provided. No crawling,
    no following links, no scanning a whole site.
  - Uses short timeouts and fails closed (a network error becomes an
    INFORMATIONAL finding, never a crash and never a retry storm).

What it checks is real: missing security headers, cookie flags, CORS
misconfiguration (checked by literally sending a probe Origin header and
seeing whether the server reflects it), server-banner disclosure, and
plaintext-HTTP transport. What it does NOT do: authentication testing,
injection testing, business-logic testing, or anything resembling an
active attack — those would need per-application knowledge this
analyzer doesn't have, and BlueLine does not claim it has them.
"""

from __future__ import annotations

import ssl
import urllib.error
import urllib.request
from urllib.parse import urlparse

from app.analyzers.base import Analyzer
from app.core.models import (
    AnalyzerCapability, CapabilityLevel, DetectionMethod, Evidence, Finding,
    RiskFactors, ScanConfig, Severity, TargetProfile, ValidationStatus, new_finding_id,
)

TIMEOUT_SECONDS = 6
PROBE_ORIGIN = "https://blueline-cors-probe.invalid"

SECURITY_HEADERS = {
    "Strict-Transport-Security": ("HTTPS transport without HSTS", Severity.MEDIUM,
        "Without Strict-Transport-Security, a user's first visit (or a stripped connection) can "
        "be downgraded to plain HTTP, enabling interception.",
        "Add a Strict-Transport-Security header (e.g. max-age=31536000; includeSubDomains) on all HTTPS responses."),
    "X-Content-Type-Options": ("Missing X-Content-Type-Options", Severity.LOW,
        "Without 'nosniff', some browsers may MIME-sniff a response and execute it as a different "
        "content type than intended, contributing to XSS in some scenarios.",
        "Add 'X-Content-Type-Options: nosniff' to all responses."),
    "Content-Security-Policy": ("Missing Content-Security-Policy", Severity.MEDIUM,
        "Without a CSP, the browser has no application-level restriction on script/style/frame "
        "sources, reducing defense-in-depth against XSS.",
        "Add a Content-Security-Policy appropriate to the application (start with a report-only "
        "policy if unsure)."),
}


class WebApiAnalyzer(Analyzer):
    name = "web_api"
    display_name = "Web/API Analyzer"
    detection_method = "CONFIGURATION_ANALYSIS"

    def applies_to(self, profile: TargetProfile) -> bool:
        return profile.target_type == "Web/API Service" and profile.target_path.lower().startswith(("http://", "https://"))

    def capability_for(self, profile: TargetProfile) -> AnalyzerCapability:
        return AnalyzerCapability(self.display_name, CapabilityLevel.PARTIAL_SUPPORT,
                                   "Real read-only checks only (GET/HEAD/OPTIONS) — no auth, "
                                   "injection, or business-logic testing")

    def run(self, profile: TargetProfile, config: ScanConfig) -> list[Finding]:
        url = profile.target_path
        findings: list[Finding] = []
        parsed = urlparse(url)

        # -- Primary GET request first: don't claim ANYTHING is confirmed,
        # including the transport scheme, until we know the target actually
        # responded. An unreachable http:// URL is "unreachable", not a
        # confirmed plaintext-transport finding.
        headers = {}
        try:
            req = urllib.request.Request(url, method="GET", headers={"Origin": PROBE_ORIGIN})
            ctx = ssl.create_default_context()
            with urllib.request.urlopen(req, timeout=TIMEOUT_SECONDS, context=ctx if parsed.scheme == "https" else None) as resp:
                headers = {k: v for k, v in resp.getheaders()}
                cookies = resp.headers.get_all("Set-Cookie") or []
        except urllib.error.HTTPError as e:
            # A real HTTP error response still confirms reachability and has headers to check.
            headers = {k: v for k, v in e.headers.items()} if e.headers else {}
            cookies = e.headers.get_all("Set-Cookie") if e.headers else []
        except Exception as e:
            findings.append(self._finding(
                url, "Target did not respond to analysis requests", "Reliability", "Unreachable",
                Severity.INFORMATIONAL, 50, ValidationStatus.UNVERIFIED,
                f"Could not complete a GET request: {e.__class__.__name__}: {e}",
                "Verify the URL is correct and reachable from this machine, then re-run the scan.",
                None,
            ))
            return findings

        # -- Transport: plaintext HTTP (only asserted now that we know the
        # target actually responded over that scheme) ----------------------
        if parsed.scheme == "http":
            findings.append(self._finding(
                url, "Service reachable over plaintext HTTP", "Cryptography", "Missing Transport Encryption",
                Severity.HIGH, 70, ValidationStatus.CONFIRMED,
                "All traffic (including any credentials or session tokens) is visible to anyone "
                "on the network path.",
                "Serve exclusively over HTTPS and redirect all HTTP traffic to HTTPS.",
                RiskFactors(impact=8, exploitability=5, exposure=6, confidence=70, reproducibility=9),
            ))

        findings.extend(self._check_security_headers(url, headers))
        findings.extend(self._check_server_banner(url, headers))
        findings.extend(self._check_cookies(url, cookies, parsed.scheme))
        findings.extend(self._check_cors(url, headers))
        findings.extend(self._check_options(url))
        return findings

    # ---------------------------------------------------------------------
    def _check_security_headers(self, url, headers) -> list[Finding]:
        out = []
        lower_headers = {k.lower(): v for k, v in headers.items()}
        for header_name, (title, sev, impact, remediation) in SECURITY_HEADERS.items():
            if header_name.lower() == "strict-transport-security" and not url.lower().startswith("https"):
                continue  # HSTS is meaningless to demand over plain HTTP
            if header_name.lower() not in lower_headers:
                out.append(self._finding(
                    url, title, "Configuration", "Missing Security Header", sev, 60,
                    ValidationStatus.CONFIRMED, impact, remediation,
                    RiskFactors(impact=5, exploitability=2, exposure=5, confidence=60, reproducibility=9),
                ))
        return out

    def _check_server_banner(self, url, headers) -> list[Finding]:
        out = []
        lower_headers = {k.lower(): v for k, v in headers.items()}
        for banner_header in ("server", "x-powered-by"):
            if banner_header in lower_headers:
                value = lower_headers[banner_header]
                out.append(self._finding(
                    url, f"Server banner discloses implementation detail ({banner_header}: {value})",
                    "Information Disclosure", "Banner Disclosure", Severity.LOW, 55,
                    ValidationStatus.CONFIRMED,
                    "Revealing the exact server/framework/version narrows an attacker's search for "
                    "known vulnerabilities affecting that specific version.",
                    f"Suppress or generify the {banner_header} header at the server/proxy level.",
                    RiskFactors(impact=3, exploitability=2, exposure=4, confidence=55, reproducibility=9),
                ))
        return out

    def _check_cookies(self, url, cookies, scheme) -> list[Finding]:
        out = []
        for cookie in cookies:
            attrs = cookie.lower()
            name = cookie.split("=")[0].strip()
            missing = []
            if scheme == "https" and "secure" not in attrs:
                missing.append("Secure")
            if "httponly" not in attrs:
                missing.append("HttpOnly")
            if "samesite" not in attrs:
                missing.append("SameSite")
            if missing:
                out.append(self._finding(
                    url, f"Cookie '{name}' missing {', '.join(missing)} attribute(s)",
                    "Session Management", "Insecure Cookie Flags", Severity.MEDIUM, 75,
                    ValidationStatus.CONFIRMED,
                    "Missing cookie flags increase exposure to session hijacking (missing Secure/"
                    "HttpOnly) or cross-site request forgery (missing SameSite).",
                    "Set Secure, HttpOnly, and SameSite=Lax (or Strict) on all session/auth cookies.",
                    RiskFactors(impact=6, exploitability=4, exposure=5, confidence=75, reproducibility=9),
                ))
        return out

    def _check_cors(self, url, headers) -> list[Finding]:
        out = []
        lower_headers = {k.lower(): v for k, v in headers.items()}
        acao = lower_headers.get("access-control-allow-origin")
        acac = lower_headers.get("access-control-allow-credentials", "").lower()
        if acao == PROBE_ORIGIN:
            out.append(self._finding(
                url, "CORS reflects arbitrary Origin header", "Cross-Origin Resource Sharing",
                "CORS Misconfiguration", Severity.HIGH, 85, ValidationStatus.CONFIRMED,
                "The server echoed back an arbitrary, unrecognized Origin in "
                "Access-Control-Allow-Origin — this was verified by sending a probe Origin "
                f"({PROBE_ORIGIN}) that has no legitimate reason to be trusted, and the server "
                "trusted it anyway. Combined with credentialed requests, this can let any website "
                "read authenticated responses from this API on a victim's behalf.",
                "Validate Origin against an explicit allow-list server-side; never reflect an "
                "arbitrary Origin back verbatim.",
                RiskFactors(impact=8, exploitability=6, exposure=6, confidence=85, reproducibility=9),
            ))
        elif acao == "*" and acac == "true":
            out.append(self._finding(
                url, "CORS allows all origins with credentials enabled", "Cross-Origin Resource Sharing",
                "CORS Misconfiguration", Severity.CRITICAL, 90, ValidationStatus.CONFIRMED,
                "Access-Control-Allow-Origin: * together with Access-Control-Allow-Credentials: "
                "true is an invalid combination that browsers are supposed to reject, but its "
                "presence indicates a fundamental misunderstanding of the CORS model server-side "
                "and often coexists with other origin-validation bugs.",
                "Never combine a wildcard origin with credentialed requests; use an explicit "
                "origin allow-list instead.",
                RiskFactors(impact=9, exploitability=5, exposure=6, confidence=90, reproducibility=9),
            ))
        return out

    def _check_options(self, url) -> list[Finding]:
        out = []
        try:
            req = urllib.request.Request(url, method="OPTIONS")
            ctx = ssl.create_default_context()
            with urllib.request.urlopen(req, timeout=TIMEOUT_SECONDS,
                                         context=ctx if url.lower().startswith("https") else None) as resp:
                allow = resp.getheader("Allow", "")
        except urllib.error.HTTPError as e:
            allow = e.headers.get("Allow", "") if e.headers else ""
        except Exception:
            return out  # OPTIONS not supported / connection issue — not itself a finding

        risky = {m for m in ("PUT", "DELETE", "TRACE", "CONNECT") if m in allow.upper()}
        if risky:
            out.append(self._finding(
                url, f"Potentially sensitive HTTP methods enabled: {', '.join(sorted(risky))}",
                "Configuration", "Exposed HTTP Methods", Severity.LOW, 35, ValidationStatus.SUSPECTED,
                "These methods being listed as allowed doesn't confirm they're exploitable, but "
                "TRACE in particular has historically enabled cross-site tracing attacks, and "
                "PUT/DELETE being open at the edge is worth confirming is intentional.",
                "Disable HTTP methods that aren't actually needed by the application.",
                RiskFactors(impact=4, exploitability=3, exposure=4, confidence=35, reproducibility=8),
            ))
        return out

    def _finding(self, url, title, category, subcategory, severity, confidence, validation,
                 impact, remediation, risk_factors) -> Finding:
        return Finding(
            id=new_finding_id(prefix="BL-WEB"),
            title=title, category=category, subcategory=subcategory, severity=severity,
            confidence=confidence, validation_status=validation,
            affected_target=url, affected_component=url, location=url,
            detection_method=DetectionMethod.CONFIGURATION_ANALYSIS,
            evidence=[Evidence(description=f"Observed via live HTTP request to {url}")],
            impact=impact, remediation=remediation, risk_factors=risk_factors,
            detector_sources=[self.name],
        )
