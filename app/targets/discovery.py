"""
Target discovery.

Given a path (directory, single file, or executable), builds a
TargetProfile: languages present, build systems, package managers,
dependency counts, entry points, config files, container definitions,
and detected interfaces. This never claims a capability that wasn't
actually verified against the filesystem.
"""

from __future__ import annotations

import fnmatch
import os
import stat
from pathlib import Path

from app.core.models import TargetProfile, AnalyzerCapability, CapabilityLevel

EXT_LANGUAGE_MAP = {
    ".py": "Python",
    ".js": "JavaScript",
    ".jsx": "JavaScript",
    ".mjs": "JavaScript",
    ".ts": "TypeScript",
    ".tsx": "TypeScript",
    ".c": "C",
    ".h": "C",
    ".cpp": "C++",
    ".cc": "C++",
    ".cxx": "C++",
    ".hpp": "C++",
    ".java": "Java",
    ".go": "Go",
    ".rb": "Ruby",
    ".rs": "Rust",
    ".php": "PHP",
    ".sh": "Shell",
}

BUILD_SYSTEM_FILES = {
    "CMakeLists.txt": "CMake",
    "Makefile": "Make",
    "pom.xml": "Maven",
    "build.gradle": "Gradle",
    "build.gradle.kts": "Gradle",
    "setup.py": "setuptools",
    "pyproject.toml": "Python (pyproject)",
    "Cargo.toml": "Cargo",
    "go.mod": "Go Modules",
}

PACKAGE_MANAGER_FILES = {
    "requirements.txt": "pip",
    "Pipfile": "pipenv",
    "Pipfile.lock": "pipenv",
    "pyproject.toml": "pip/poetry",
    "package.json": "npm",
    "package-lock.json": "npm",
    "yarn.lock": "yarn",
    "pnpm-lock.yaml": "pnpm",
    "Cargo.toml": "cargo",
    "go.mod": "go modules",
    "composer.json": "composer",
    "Gemfile": "bundler",
}

CONFIG_FILE_PATTERNS = [
    "*.env", ".env*", "*.yaml", "*.yml", "Dockerfile", "docker-compose*.yml",
    "*.ini", "*.conf", "*.cfg", "*.toml",
]

CONTAINER_FILES = ["Dockerfile", "docker-compose.yml", "docker-compose.yaml"]

EXECUTABLE_MAGIC = {
    b"MZ": "PE (Windows executable)",
    b"\x7fELF": "ELF (Linux executable)",
    b"\xca\xfe\xba\xbe": "Mach-O / Java class (fat binary)",
    b"\xcf\xfa\xed\xfe": "Mach-O (macOS executable)",
}


class TargetDiscovery:
    def __init__(self, exclude_globs: list[str] | None = None):
        self.exclude_globs = exclude_globs or [
            "**/node_modules/**", "**/.git/**", "**/venv/**", "**/.venv/**",
            "**/__pycache__/**", "**/dist/**", "**/build/**",
        ]

    def _excluded(self, path: str) -> bool:
        return any(fnmatch.fnmatch(path, pat) for pat in self.exclude_globs)

    def discover(self, target_path: str) -> TargetProfile:
        if target_path.strip().lower().startswith(("http://", "https://")):
            return self._discover_web_target(target_path.strip())

        p = Path(target_path).expanduser().resolve()
        warnings: list[str] = []

        if not p.exists():
            profile = TargetProfile(target_path=target_path, target_type="Unknown")
            profile.discovery_warnings.append(f"Path does not exist: {target_path}")
            return profile

        if p.is_file():
            return self._discover_single_file(p)

        return self._discover_directory(p, warnings)

    # ------------------------------------------------------------------
    def _discover_web_target(self, url: str) -> TargetProfile:
        """A URL target: no filesystem involved. Reachability is checked
        with a single lightweight request so the profile can honestly
        report whether the service actually responded, without doing
        any deeper probing at discovery time (that's the analyzer's job)."""
        warnings: list[str] = []
        reachable = False
        try:
            import urllib.request
            req = urllib.request.Request(url, method="HEAD")
            with urllib.request.urlopen(req, timeout=4) as resp:
                reachable = 200 <= resp.status < 500
        except Exception as e:
            warnings.append(f"Target did not respond to an initial HEAD request: {e}")

        profile = TargetProfile(
            target_path=url,
            target_type="Web/API Service",
            interfaces=["HTTP API"],
            discovery_warnings=warnings,
        )
        if not reachable:
            profile.discovery_warnings.append(
                "Reachability could not be confirmed — analysis will still be attempted, but "
                "results may be incomplete if the service is actually unreachable.")
        profile.capabilities = self._capabilities_for(profile)
        return profile

    # ------------------------------------------------------------------
    def _discover_single_file(self, p: Path) -> TargetProfile:
        warnings = []
        target_type = "Source File"
        executables = []
        languages = []

        try:
            with open(p, "rb") as fh:
                head = fh.read(4)
            for magic, label in EXECUTABLE_MAGIC.items():
                if head.startswith(magic):
                    target_type = f"Executable ({label})"
                    executables.append(str(p))
                    break
        except OSError as e:
            warnings.append(f"Could not read file header: {e}")

        if target_type == "Source File":
            lang = EXT_LANGUAGE_MAP.get(p.suffix.lower())
            if lang:
                languages.append(lang)

        is_exec_bit = False
        try:
            is_exec_bit = bool(p.stat().st_mode & stat.S_IXUSR)
        except OSError:
            pass

        interfaces = ["CLI"] if (is_exec_bit or target_type.startswith("Executable")) else []

        size = p.stat().st_size if p.exists() else 0
        profile = TargetProfile(
            target_path=str(p),
            target_type=target_type,
            languages=languages,
            executables=executables,
            interfaces=interfaces,
            file_count=1,
            total_size_bytes=size,
            discovery_warnings=warnings,
        )
        profile.capabilities = self._capabilities_for(profile)
        return profile

    # ------------------------------------------------------------------
    def _discover_directory(self, root: Path, warnings: list[str]) -> TargetProfile:
        languages: set[str] = set()
        build_systems: set[str] = set()
        package_managers: set[str] = set()
        config_files: list[str] = []
        container_files: list[str] = []
        entry_points: list[str] = []
        test_suites: list[str] = []
        executables: list[str] = []
        dependency_count = 0
        file_count = 0
        total_size = 0
        has_http_hint = False

        for dirpath, dirnames, filenames in os.walk(root):
            rel_dir = os.path.relpath(dirpath, root)
            if self._excluded(dirpath) or self._excluded(rel_dir):
                dirnames[:] = []
                continue
            dirnames[:] = [d for d in dirnames if not self._excluded(os.path.join(dirpath, d))]

            for fname in filenames:
                fpath = Path(dirpath) / fname
                rel = os.path.relpath(fpath, root)
                if self._excluded(rel):
                    continue

                file_count += 1
                try:
                    total_size += fpath.stat().st_size
                except OSError:
                    pass

                ext = fpath.suffix.lower()
                if ext in EXT_LANGUAGE_MAP:
                    languages.add(EXT_LANGUAGE_MAP[ext])

                if fname in BUILD_SYSTEM_FILES:
                    build_systems.add(BUILD_SYSTEM_FILES[fname])
                if fname in PACKAGE_MANAGER_FILES:
                    package_managers.add(PACKAGE_MANAGER_FILES[fname])
                if fname in CONTAINER_FILES:
                    container_files.append(rel)
                if any(fnmatch.fnmatch(fname, pat) for pat in CONFIG_FILE_PATTERNS):
                    config_files.append(rel)

                lower = fname.lower()
                if lower in ("main.py", "app.py", "__main__.py", "index.js", "server.js", "main.go", "main.c", "main.cpp"):
                    entry_points.append(rel)
                if "test" in lower and ext in (".py", ".js", ".ts"):
                    test_suites.append(rel)

                if fname == "requirements.txt":
                    dependency_count += self._count_lines_nonblank(fpath)
                if fname == "package.json":
                    dependency_count += self._count_package_json_deps(fpath)

                if ext in (".py", ".js", ".ts"):
                    try:
                        content_head = fpath.read_text(errors="ignore")[:20000]
                        if any(tok in content_head for tok in (
                            "Flask(", "FastAPI(", "express(", "@app.route", "app.get(", "app.post(",
                            "http.createServer", "HTTPServer",
                        )):
                            has_http_hint = True
                    except OSError:
                        pass

                # Executable detection: always check common executable
                # extensions explicitly (.exe/.dll on Windows are real
                # executables, unlike Linux/Mac convention of no extension),
                # and also check extension-less files by magic bytes since
                # that's the common case on Linux/Mac.
                if not ext or ext in (".exe", ".dll", ".so", ".dylib", ".bin"):
                    try:
                        with open(fpath, "rb") as fh:
                            head = fh.read(4)
                        for magic, label in EXECUTABLE_MAGIC.items():
                            if head.startswith(magic):
                                executables.append(rel)
                                break
                    except OSError:
                        pass

        interfaces = []
        if has_http_hint:
            interfaces.append("HTTP API")
        if entry_points or executables:
            interfaces.append("CLI")

        if languages:
            target_type = "Multi-language Application" if len(languages) > 1 else f"{next(iter(languages))} Application"
        else:
            target_type = "Unclassified Directory"
            warnings.append("No recognized source languages detected in this directory.")

        profile = TargetProfile(
            target_path=str(root),
            target_type=target_type,
            languages=sorted(languages),
            build_systems=sorted(build_systems),
            package_managers=sorted(package_managers),
            dependencies_count=dependency_count,
            entry_points=entry_points[:25],
            config_files=config_files[:50],
            interfaces=interfaces,
            executables=executables[:25],
            test_suites_detected=test_suites[:25],
            container_definitions=container_files,
            file_count=file_count,
            total_size_bytes=total_size,
            discovery_warnings=warnings,
        )
        profile.capabilities = self._capabilities_for(profile)
        return profile

    @staticmethod
    def _count_lines_nonblank(path: Path) -> int:
        try:
            lines = path.read_text(errors="ignore").splitlines()
            return len([ln for ln in lines if ln.strip() and not ln.strip().startswith("#")])
        except OSError:
            return 0

    @staticmethod
    def _count_package_json_deps(path: Path) -> int:
        import json
        try:
            data = json.loads(path.read_text(errors="ignore"))
            return len(data.get("dependencies", {})) + len(data.get("devDependencies", {}))
        except (OSError, ValueError):
            return 0

    @staticmethod
    def _capabilities_for(profile: TargetProfile) -> list[AnalyzerCapability]:
        """Honest capability declaration based on what was actually found.
        This is what the UI shows as the target profile's analysis surface —
        it must never assert a capability that isn't backed by a registered
        analyzer that applies_to() this profile."""
        caps = []
        if "Python" in profile.languages:
            caps.append(AnalyzerCapability("Python Static Analysis", CapabilityLevel.FULL_SUPPORT,
                                            "AST-based rule engine"))
        if "JavaScript" in profile.languages or "TypeScript" in profile.languages:
            caps.append(AnalyzerCapability("JavaScript/TypeScript Static Analysis", CapabilityLevel.PARTIAL_SUPPORT,
                                            "Heuristic/regex-based; no full AST/type-flow analysis yet"))
        if "C" in profile.languages or "C++" in profile.languages:
            caps.append(AnalyzerCapability("C/C++ Static Analysis", CapabilityLevel.EXPERIMENTAL,
                                            "Pattern-based only; no real parser, high false-negative rate"))
        if "Java" in profile.languages:
            caps.append(AnalyzerCapability("Java Static Analysis", CapabilityLevel.PARTIAL_SUPPORT,
                                            "Heuristic/regex-based; no real parser"))
        if "Go" in profile.languages:
            caps.append(AnalyzerCapability("Go Static Analysis", CapabilityLevel.PARTIAL_SUPPORT,
                                            "Heuristic/regex-based; no real parser"))
        if "Ruby" in profile.languages:
            caps.append(AnalyzerCapability("Ruby Static Analysis", CapabilityLevel.PARTIAL_SUPPORT,
                                            "Heuristic/regex-based; no real parser"))
        if "PHP" in profile.languages:
            caps.append(AnalyzerCapability("PHP Static Analysis", CapabilityLevel.PARTIAL_SUPPORT,
                                            "Heuristic/regex-based; no real parser"))
        if "Rust" in profile.languages:
            caps.append(AnalyzerCapability("Rust Static Analysis", CapabilityLevel.PARTIAL_SUPPORT,
                                            "Heuristic/regex-based; no real parser"))
        if profile.package_managers:
            caps.append(AnalyzerCapability("Dependency Analysis", CapabilityLevel.PARTIAL_SUPPORT,
                                            "Checked against a small curated local vulnerability sample, "
                                            "not a live CVE database"))
        if profile.config_files or profile.container_definitions:
            caps.append(AnalyzerCapability("Configuration Analysis", CapabilityLevel.FULL_SUPPORT))
        if profile.executables:
            caps.append(AnalyzerCapability("Binary/Executable Analysis", CapabilityLevel.PARTIAL_SUPPORT,
                                            "ELF metadata/PIE/stripped/linked-libraries parsing validated "
                                            "against real compiled binaries; PE/Mach-O get string "
                                            "extraction only, no internal structure parsing in this build"))
        if "CLI" in profile.interfaces:
            caps.append(AnalyzerCapability("Dynamic Analysis (CLI)", CapabilityLevel.PARTIAL_SUPPORT,
                                            "Subprocess execution with resource limits; stdin/argv fuzzing"))
        else:
            caps.append(AnalyzerCapability("Dynamic Analysis", CapabilityLevel.UNSUPPORTED,
                                            "No runnable entry point detected"))
        if "HTTP API" in profile.interfaces:
            caps.append(AnalyzerCapability("Web/API Analysis", CapabilityLevel.PARTIAL_SUPPORT,
                                            "Real read-only checks (GET/HEAD/OPTIONS only) for security "
                                            "headers, cookie flags, CORS misconfiguration, server-banner "
                                            "disclosure, and plaintext-HTTP transport. Not a full active "
                                            "vulnerability scanner — no auth/session/injection testing "
                                            "against live endpoints in this build."))
        for lang in profile.languages:
            if lang not in ("Python", "JavaScript", "TypeScript", "C", "C++", "Java", "Go", "Ruby", "PHP", "Rust"):
                caps.append(AnalyzerCapability(f"{lang} Static Analysis", CapabilityLevel.UNSUPPORTED,
                                                "No analyzer implemented yet"))
        return caps
