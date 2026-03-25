#!/usr/bin/env node
/**
 * CLI shim for defenseclaw-plugin-scanner — prints ScanResult JSON to stdout.
 * Run after: npm run build (compiles TypeScript to dist/).
 *
 * Kept under scripts/ (not bin/) because the repo root .gitignore ignores bin/.
 */
import { dirname, join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const __dirname = dirname(fileURLToPath(import.meta.url));
const modUrl = pathToFileURL(
  join(__dirname, "..", "dist", "scanners", "plugin_scanner", "index.js"),
).href;
const { scanPlugin } = await import(modUrl);

function usage() {
  console.error(`Usage: defenseclaw-plugin-scanner <plugin-dir> [options]

Options:
  --policy <preset|path>   default | strict | permissive | path to YAML
  --profile <default|strict>
  --use-llm                (policy YAML should enable LLM; flag reserved)
  --no-meta                (not applied; use policy file)
  --lenient                (not applied; use permissive policy)`);
  process.exit(2);
}

const argv = process.argv.slice(2);
if (argv.length === 0 || argv[0] === "-h" || argv[0] === "--help") usage();

const positional = [];
const options = {};
for (let i = 0; i < argv.length; i++) {
  const a = argv[i];
  if (a === "--policy") options.policy = argv[++i];
  else if (a === "--profile") {
    const p = argv[++i];
    if (p === "default" || p === "strict") options.profile = p;
    else {
      console.error(`error: invalid --profile ${p}`);
      process.exit(2);
    }
  } else if (a === "--use-llm" || a === "--no-meta" || a === "--lenient") {
    /* Python CLI passes these; TS scan uses policy YAML for LLM/meta toggles */
  } else if (a.startsWith("--")) {
    console.error(`error: unknown flag ${a}`);
    process.exit(2);
  } else positional.push(a);
}

const target = positional[0];
if (!target) usage();

try {
  const result = await scanPlugin(target, options);
  process.stdout.write(`${JSON.stringify(result)}\n`);
} catch (err) {
  console.error(err);
  process.exit(1);
}
