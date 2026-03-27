"""Plugin scanner."""

from __future__ import annotations

import time
from datetime import datetime, timedelta, timezone

from defenseclaw.models import Finding, ScanResult
from defenseclaw.scanner.plugin_scanner import scan_plugin
from defenseclaw.scanner.plugin_scanner.types import (
    PluginScanOptions,
)
from defenseclaw.scanner.plugin_scanner.types import (
    ScanResult as PluginScanResult,
)

SCANNER_NAME = "defenseclaw-plugin-scanner"


class PluginScannerWrapper:
    def __init__(self, binary: str = SCANNER_NAME) -> None:
        # binary param kept for backward-compat but no longer used
        self._binary = binary

    def name(self) -> str:
        return "plugin-scanner"

    def scan(
        self,
        target: str,
        *,
        policy: str = "",
        profile: str = "",
        use_llm: bool = False,
        llm_model: str = "",
        llm_api_key: str = "",
        llm_provider: str = "",
        llm_consensus_runs: int = 0,
        disable_meta: bool = False,
        lenient: bool = False,
    ) -> ScanResult:
        start = time.monotonic()

        # Map CLI flags to PluginScanOptions
        options = PluginScanOptions()
        if policy:
            options.policy = policy
        elif lenient:
            options.policy = "permissive"
        if profile:
            options.profile = profile

        # Run the scanner
        result: PluginScanResult = scan_plugin(target, options)

        elapsed = time.monotonic() - start

        # Convert rich plugin_scanner.Finding -> models.Finding
        findings: list[Finding] = []
        for f in result.findings:
            if getattr(f, "suppressed", False):
                continue
            findings.append(Finding(
                id=f.id,
                severity=f.severity,
                title=f.title,
                description=f.description,
                location=f.location or "",
                remediation=f.remediation or "",
                scanner="plugin-scanner",
                tags=list(f.tags) if f.tags else [],
            ))

        return ScanResult(
            scanner="plugin-scanner",
            target=target,
            timestamp=datetime.now(timezone.utc),
            findings=findings,
            duration=timedelta(seconds=elapsed),
        )
