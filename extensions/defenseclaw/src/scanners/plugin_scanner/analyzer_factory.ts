/**
 * Centralized analyzer construction — modeled after the skill scanner's
 * build_analyzers() in analyzer_factory.py.
 *
 * Every entry point (CLI binary, VSCode extension, API) MUST build analyzers
 * through this function so that:
 * - All core analyzers are always included.
 * - Analyzer toggling via disabledAnalyzers is respected.
 * - Adding or removing a core analyzer only requires a change here.
 */
import type { Analyzer, BuildAnalyzersOptions } from "./analyzer.js";
import {
  PermissionsAnalyzer,
  DependencyAnalyzer,
  InstallScriptAnalyzer,
  ToolAnalyzer,
  SourceAnalyzer,
  DirectoryStructureAnalyzer,
  ClawManifestAnalyzer,
  BundleSizeAnalyzer,
  JsonConfigAnalyzer,
  LockfileAnalyzer,
  MetaAnalyzer,
} from "./analyzer_classes.js";

/**
 * Build the full analyzer pipeline.
 *
 * Core analyzers are always included unless explicitly disabled.
 * The MetaAnalyzer runs last and receives findings from all previous analyzers.
 */
export function buildAnalyzers(options?: BuildAnalyzersOptions): Analyzer[] {
  const disabled = new Set(options?.disabledAnalyzers ?? []);

  const core: Analyzer[] = [
    // Phase 1: Manifest checks
    new PermissionsAnalyzer(),
    new DependencyAnalyzer(),
    new InstallScriptAnalyzer(),
    new ToolAnalyzer(),
    // Phase 2: Source analysis (heaviest, runs pattern matching)
    new SourceAnalyzer(),
    // Phase 3: Structural checks
    new DirectoryStructureAnalyzer(),
    new ClawManifestAnalyzer(),
    new BundleSizeAnalyzer(),
    new JsonConfigAnalyzer(),
    new LockfileAnalyzer(),
  ];

  const filtered = core.filter((a) => !disabled.has(a.name));

  // Meta analyzer always runs last (cross-references previous findings).
  // It can be disabled explicitly.
  if (!disabled.has("meta")) {
    filtered.push(new MetaAnalyzer());
  }

  return filtered;
}
