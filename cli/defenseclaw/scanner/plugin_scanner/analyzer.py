"""Analyzer interface and ScanContext."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Protocol

from defenseclaw.scanner.plugin_scanner.types import (
    Finding,
    PluginManifest,
)


@dataclass
class SourceFile:
    """Pre-collected and parsed source file."""

    path: str
    rel_path: str
    content: str
    lines: list[str]
    code_lines: list[str]
    in_test_path: bool


@dataclass
class ScanContext:
    """Shared state passed to all analyzers."""

    plugin_dir: str
    manifest: PluginManifest | None
    source_files: list[SourceFile] = field(default_factory=list)
    profile: str = "default"
    capabilities: set[str] = field(default_factory=set)
    finding_counter: list[int] = field(default_factory=lambda: [1])  # mutable int
    previous_findings: list[Finding] = field(default_factory=list)
    metadata: dict[str, object] = field(default_factory=dict)


class Analyzer(Protocol):
    """Every analyzer implements analyze(ctx) and returns findings."""

    @property
    def name(self) -> str: ...

    def analyze(self, ctx: ScanContext) -> list[Finding]: ...
