"""
Analyzer plugin interface.

Every analyzer (static, dependency, configuration, dynamic, fuzzing) is a
subclass of Analyzer. The orchestrator only ever calls the methods defined
here — it never imports a concrete analyzer by name. New analyzers are
added by writing a class and calling register(); no orchestrator code
changes.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Optional

from app.core.models import AnalyzerCapability, Finding, TargetProfile, ScanConfig


class Analyzer(ABC):
    #: unique machine name, e.g. "python_static"
    name: str = "unnamed_analyzer"
    #: human label shown in UI/reports
    display_name: str = "Unnamed Analyzer"
    #: detection method category this analyzer belongs to
    detection_method: str = "STATIC_ANALYSIS"

    @abstractmethod
    def applies_to(self, profile: TargetProfile) -> bool:
        """Return True if this analyzer has anything to do for this target."""
        raise NotImplementedError

    @abstractmethod
    def capability_for(self, profile: TargetProfile) -> AnalyzerCapability:
        """Declare, honestly, what level of support this analyzer offers
        for this specific target (FULL_SUPPORT / PARTIAL_SUPPORT / etc)."""
        raise NotImplementedError

    @abstractmethod
    def run(self, profile: TargetProfile, config: ScanConfig) -> list[Finding]:
        """Execute the analysis and return findings. Must not raise for
        expected bad-target conditions (malformed files etc) — catch and
        return an empty/partial list; the orchestrator handles true
        crashes as a stage failure regardless, but well-behaved analyzers
        should isolate their own per-file errors internally so a single
        broken file doesn't kill an entire analyzer's coverage."""
        raise NotImplementedError


class AnalyzerRegistry:
    def __init__(self):
        self._analyzers: dict[str, Analyzer] = {}

    def register(self, analyzer: Analyzer) -> None:
        self._analyzers[analyzer.name] = analyzer

    def get(self, name: str) -> Optional[Analyzer]:
        return self._analyzers.get(name)

    def all(self) -> list[Analyzer]:
        return list(self._analyzers.values())

    def applicable(self, profile: TargetProfile) -> list[Analyzer]:
        return [a for a in self._analyzers.values() if a.applies_to(profile)]


def default_registry() -> AnalyzerRegistry:
    """Builds the standard registry. This is the ONE place that knows
    about concrete analyzer classes — everything downstream works only
    against the Analyzer interface."""
    from app.analyzers.python_static import PythonStaticAnalyzer
    from app.analyzers.js_static import JavaScriptStaticAnalyzer
    from app.analyzers.java_static import JavaStaticAnalyzer
    from app.analyzers.go_static import GoStaticAnalyzer
    from app.analyzers.ruby_static import RubyStaticAnalyzer
    from app.analyzers.php_static import PhpStaticAnalyzer
    from app.analyzers.dependency import DependencyAnalyzer
    from app.analyzers.config_analyzer import ConfigurationAnalyzer
    from app.analyzers.c_cpp_static import CCppStaticAnalyzer
    from app.analyzers.web_api import WebApiAnalyzer
    from app.analyzers.binary_analysis import BinaryAnalyzer
    from app.analyzers.rust_static import RustStaticAnalyzer

    reg = AnalyzerRegistry()
    reg.register(PythonStaticAnalyzer())
    reg.register(JavaScriptStaticAnalyzer())
    reg.register(JavaStaticAnalyzer())
    reg.register(GoStaticAnalyzer())
    reg.register(RubyStaticAnalyzer())
    reg.register(PhpStaticAnalyzer())
    reg.register(RustStaticAnalyzer())
    reg.register(CCppStaticAnalyzer())
    reg.register(DependencyAnalyzer())
    reg.register(ConfigurationAnalyzer())
    reg.register(WebApiAnalyzer())
    reg.register(BinaryAnalyzer())
    return reg
