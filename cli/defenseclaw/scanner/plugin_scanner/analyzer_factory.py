"""Centralized analyzer construction."""

from __future__ import annotations

from defenseclaw.scanner.plugin_scanner.analyzer_classes import (
    BundleSizeAnalyzer,
    ClawManifestAnalyzer,
    DependencyAnalyzer,
    DirectoryStructureAnalyzer,
    InstallScriptAnalyzer,
    JsonConfigAnalyzer,
    LockfileAnalyzer,
    MetaAnalyzer,
    PermissionsAnalyzer,
    SourceAnalyzer,
    ToolAnalyzer,
)


def build_analyzers(
    *,
    profile: str = "default",
    disabled_analyzers: list[str] | None = None,
    llm: dict | None = None,
) -> list:
    """Build the full analyzer pipeline.

    Core analyzers are always included unless explicitly disabled.
    LLM analyzer is included when llm["enabled"] is true.
    MetaAnalyzer runs last with LLM enhancement when available.
    """
    disabled = set(disabled_analyzers or [])

    # Phase 1: Pattern-based analyzers
    core = [
        PermissionsAnalyzer(),
        DependencyAnalyzer(),
        InstallScriptAnalyzer(),
        ToolAnalyzer(),
        SourceAnalyzer(),
        DirectoryStructureAnalyzer(),
        ClawManifestAnalyzer(),
        BundleSizeAnalyzer(),
        JsonConfigAnalyzer(),
        LockfileAnalyzer(),
    ]

    filtered = [a for a in core if a.name not in disabled]

    # Phase 2: LLM analyzer (opt-in, runs after pattern analyzers)
    if llm and llm.get("enabled") and "llm" not in disabled:
        from defenseclaw.scanner.plugin_scanner.llm_analyzer import LLMAnalyzer

        filtered.append(
            LLMAnalyzer(
                {
                    "model": llm.get("model", ""),
                    "api_key": llm.get("api_key") or None,
                    "api_base": llm.get("api_base") or None,
                    "provider": llm.get("provider") or None,
                    "max_tokens": llm.get("max_output_tokens"),
                    "consensus_runs": llm.get("consensus_runs"),
                    "python_binary": llm.get("python_binary") or None,
                }
            )
        )

    # Phase 3: Meta analyzer (last -- cross-references all previous findings)
    if "meta" not in disabled:
        filtered.append(MetaAnalyzer(llm))

    return filtered
