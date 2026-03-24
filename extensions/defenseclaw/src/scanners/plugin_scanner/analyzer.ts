/**
 * Analyzer interface and ScanContext — modeled after the skill scanner's
 * BaseAnalyzer / Skill pattern (skill_scanner/core/analyzers/base.py).
 *
 * Every analyzer implements `analyze(ctx)` and returns findings.
 * The factory function `buildAnalyzers()` composes the analyzer list.
 */
import type {
  Finding,
  PluginManifest,
  ScanProfile,
  ScanMetadata,
} from "../../types.js";

// ---------------------------------------------------------------------------
// Scan context — shared state passed to all analyzers
// ---------------------------------------------------------------------------

export interface SourceFile {
  /** Absolute path to the file. */
  path: string;
  /** Path relative to the plugin root. */
  relPath: string;
  /** Raw file content. */
  content: string;
  /** Lines split from content. */
  lines: string[];
  /** Lines with single-line comments stripped (for pattern matching). */
  codeLines: string[];
  /** Whether this file is in a test/fixture/dist path. */
  inTestPath: boolean;
}

export interface ScanContext {
  /** Absolute path to the plugin directory. */
  pluginDir: string;
  /** Parsed plugin manifest (null if missing). */
  manifest: PluginManifest | null;
  /** Pre-collected and parsed source files (.ts, .js, .mjs). */
  sourceFiles: SourceFile[];
  /** Active scan profile. */
  profile: ScanProfile;
  /** Detected capabilities (mutated by analyzers). */
  capabilities: Set<string>;
  /** Running finding counter for stable IDs (mutated by analyzers). */
  findingCounter: { value: number };
  /** Findings from previous analyzers (for meta/cross-reference). */
  previousFindings: Finding[];
  /** Metadata collected during scanning. */
  metadata: Partial<ScanMetadata>;
}

// ---------------------------------------------------------------------------
// Analyzer interface
// ---------------------------------------------------------------------------

export interface Analyzer {
  /** Unique analyzer name (used for attribution and toggling). */
  readonly name: string;
  /** Run analysis and return findings. */
  analyze(ctx: ScanContext): Promise<Finding[]>;
}

// ---------------------------------------------------------------------------
// Analyzer factory options
// ---------------------------------------------------------------------------

export interface BuildAnalyzersOptions {
  profile?: ScanProfile;
  /** Disabled analyzer names — these will be excluded from the pipeline. */
  disabledAnalyzers?: string[];
}
