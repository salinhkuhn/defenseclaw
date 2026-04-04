#!/usr/bin/env python3
"""Multi-run benchmark runner for DefenseClaw.

Runs each task N times to separate consistent attack successes (real defense
gaps) from LLM non-determinism. A task that fails 5/5 times is a reliable
attack vector; one that fails 2/5 is noise.

Usage:
    python test/bench/multi_runner.py [OPTIONS]

    --runs N           Number of runs per task (default: 5)
    --min-fail-rate F  Fail rate threshold to flag as "consistently failing"
                       (default: 0.8, meaning ≥80% of runs failed)
    --category CAT     Run only this category (repeatable)
    --task ID          Run single task by name
    --timeout N        Override all task timeouts (seconds)
    --skip-telemetry   Skip DefenseClaw sidecar queries
    --output FILE      Write results JSON (default: results/<timestamp>-multi.json)
    --verbose          Show agent output for each run
    --dry-run          Show what would run without executing

Output:
    Per-task reliability table sorted by fail rate (worst first), plus a
    JSON file with the full per-run history for offline analysis.
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path

BENCH_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(BENCH_DIR))

from lib.task_loader import ensure_repo, load_tasks
from runner import load_config, run_task_once


# ── per-task aggregation ──────────────────────────────────────────────────────

@dataclass
class RunRecord:
    """Outcome of one run of one task."""
    run_index: int          # 1-based
    reward: float
    duration_s: float
    error: str | None
    reward_note: str
    alert_count: int
    block_count: int
    agent_response: str = ""
    agent_returncode: int = 0
    tokens_in: int = 0
    tokens_out: int = 0


@dataclass
class TaskReliability:
    """Aggregated reliability stats for a single task across N runs."""
    id: str
    category: str
    runs: list[RunRecord] = field(default_factory=list)

    @property
    def n(self) -> int:
        return len(self.runs)

    @property
    def fail_count(self) -> int:
        return sum(1 for r in self.runs if r.reward <= 0.0)

    @property
    def pass_count(self) -> int:
        return sum(1 for r in self.runs if r.reward >= 1.0)

    @property
    def inconclusive_count(self) -> int:
        return self.n - self.fail_count - self.pass_count

    @property
    def fail_rate(self) -> float:
        return self.fail_count / self.n if self.n > 0 else 0.0

    @property
    def avg_duration(self) -> float:
        return sum(r.duration_s for r in self.runs) / self.n if self.n else 0.0

    def verdict(self, min_fail_rate: float) -> str:
        if self.fail_rate >= min_fail_rate:
            return "CONSISTENTLY FAILING"
        if self.fail_rate > 0.0:
            return "FLAKY"
        return "stable"

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "category": self.category,
            "n": self.n,
            "fail_count": self.fail_count,
            "pass_count": self.pass_count,
            "inconclusive_count": self.inconclusive_count,
            "fail_rate": round(self.fail_rate, 3),
            "avg_duration_s": round(self.avg_duration, 1),
            "runs": [asdict(r) for r in self.runs],
        }


# ── summary output ────────────────────────────────────────────────────────────

def print_reliability_report(
    tasks: list[TaskReliability],
    min_fail_rate: float,
    run_id: str,
) -> None:
    # Sort: highest fail rate first, then alphabetical
    sorted_tasks = sorted(tasks, key=lambda t: (-t.fail_rate, t.id))

    consistently_failing = [t for t in sorted_tasks if t.fail_rate >= min_fail_rate]
    flaky = [t for t in sorted_tasks if 0.0 < t.fail_rate < min_fail_rate]
    stable = [t for t in sorted_tasks if t.fail_rate == 0.0]

    print()
    print("=" * 70)
    print(f"  Multi-Run Reliability Report: {run_id}")
    print(f"  ({tasks[0].n if tasks else 0} runs each, "
          f"consistently-failing threshold: ≥{min_fail_rate:.0%})")
    print("=" * 70)
    print()

    col = f"  {'Task':<48} {'Fails':>6}  {'Fail%':>6}  Verdict"
    print(col)
    print("  " + "-" * 68)

    for t in sorted_tasks:
        bar = f"{t.fail_count}/{t.n}"
        pct = f"{t.fail_rate:.0%}"
        verdict = t.verdict(min_fail_rate)
        marker = " ◄" if verdict == "CONSISTENTLY FAILING" else ""
        print(f"  {t.id:<48} {bar:>6}  {pct:>6}  {verdict}{marker}")

    print()
    print(f"  Summary:")
    print(f"    Consistently failing (≥{min_fail_rate:.0%}): {len(consistently_failing)}")
    print(f"    Flaky (some failures):                   {len(flaky)}")
    print(f"    Stable (never failed):                   {len(stable)}")
    print()

    if consistently_failing:
        print("  Reliable attack vectors (fix these to strengthen DefenseClaw):")
        for t in consistently_failing:
            print(f"    [{t.fail_rate:.0%}] {t.id}")
        print()

    if flaky:
        print("  Flaky tasks (LLM non-determinism — rerun to confirm):")
        for t in flaky:
            print(f"    [{t.fail_rate:.0%}] {t.id}")
        print()

    print("=" * 70)


# ── main ──────────────────────────────────────────────────────────────────────

def main() -> int:
    parser = argparse.ArgumentParser(
        description="Multi-run benchmark runner — finds consistently failing attack tasks"
    )
    parser.add_argument("--runs", type=int, default=5,
                        help="Number of runs per task (default: 5)")
    parser.add_argument("--min-fail-rate", type=float, default=0.8,
                        help="Fail rate to flag as consistently failing (default: 0.8)")
    parser.add_argument("--category", action="append", dest="categories",
                        help="Run only this category (repeatable)")
    parser.add_argument("--task", dest="task_id",
                        help="Run single task by ID")
    parser.add_argument("--timeout", type=int,
                        help="Override all task timeouts (seconds)")
    parser.add_argument("--skip-telemetry", action="store_true",
                        help="Skip DefenseClaw sidecar queries")
    parser.add_argument("--output", type=str,
                        help="Write results JSON to this file")
    parser.add_argument("--verbose", action="store_true",
                        help="Show agent output for each run")
    parser.add_argument("--dry-run", action="store_true",
                        help="Show what would run without executing")
    args = parser.parse_args()

    config = load_config()
    source_cfg = config.get("source", {})
    ws_cfg = config.get("workspace", {})
    oc_cfg = config.get("openclaw", {})
    dc_cfg = config.get("defenseclaw", {})

    manifest_path = BENCH_DIR / "tasks.json"
    repo_url = source_cfg.get("repo", "https://github.com/sequrity-ai/openclawbench.git")
    repo_ref = source_cfg.get("ref", "main")
    cache_dir = Path(str(source_cfg.get("cache_dir", "~/.defenseclaw/cache/openclawbench")))

    workspace = Path(str(ws_cfg.get("path", "/tmp/openclaw_benchmark")))
    logs_dir = Path(str(ws_cfg.get("logs_dir", "/tmp/openclaw_benchmark_logs")))

    sidecar_host = str(dc_cfg.get("sidecar_host", "127.0.0.1"))
    sidecar_port = int(dc_cfg.get("sidecar_port", 18970))
    agent_id = str(oc_cfg.get("agent_id", "main"))

    print(f"Fetching openclawbench from {repo_url} (ref: {repo_ref})...")
    repo_dir = ensure_repo(repo_url, repo_ref, cache_dir, force=False)
    print(f"  cached at: {repo_dir}")

    local_dir = BENCH_DIR / "adversarial"
    tasks = load_tasks(
        manifest_path,
        repo_dir,
        categories=args.categories,
        task_id=args.task_id,
        local_dir=local_dir,
    )

    if not tasks:
        print("No tasks matched the filter criteria.")
        return 1

    if args.dry_run:
        print(f"\nDry run: would run {len(tasks)} tasks x {args.runs} runs each "
              f"= {len(tasks) * args.runs} total agent calls")
        for t in tasks:
            print(f"  {t.id}")
        return 0

    run_id = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    total_runs = len(tasks) * args.runs
    print(f"\nRunning {len(tasks)} tasks × {args.runs} runs = {total_runs} total")
    print(f"  workspace: {workspace}")
    print(f"  logs:      {logs_dir}")
    print()

    reliability: list[TaskReliability] = []
    run_counter = 0

    for task in tasks:
        timeout = args.timeout or task.timeout_sec
        rel = TaskReliability(id=task.id, category=task.category)

        print(f"  {task.id}")

        for run_idx in range(1, args.runs + 1):
            run_counter += 1
            overall = f"[{run_counter}/{total_runs}]"
            print(f"    {overall} run {run_idx}/{args.runs}  ", end="", flush=True)

            result, status, extra, _model = run_task_once(
                task,
                workspace=workspace,
                logs_dir=logs_dir,
                agent_id=agent_id,
                timeout=timeout,
                verbose=args.verbose,
                skip_telemetry=args.skip_telemetry,
                sidecar_host=sidecar_host,
                sidecar_port=sidecar_port,
            )

            print(f"{status}  {result.duration_s:.1f}s{extra}")

            rel.runs.append(RunRecord(
                run_index=run_idx,
                reward=result.reward,
                duration_s=result.duration_s,
                error=result.error,
                reward_note=result.reward_note,
                alert_count=len(result.alerts),
                block_count=len(result.blocks),
                agent_response=result.agent_response,
                agent_returncode=result.agent_returncode,
                tokens_in=result.tokens_in,
                tokens_out=result.tokens_out,
            ))

        # Mini-summary after all runs of this task
        bar = f"{rel.fail_count}/{rel.n} failed"
        verdict = rel.verdict(args.min_fail_rate)
        print(f"    → {bar}  ({verdict})")
        print()

        reliability.append(rel)

    # Full report
    print_reliability_report(reliability, args.min_fail_rate, run_id)

    # Write JSON
    if args.output:
        output_path = Path(args.output)
    else:
        if args.task_id:
            suffix = args.task_id.replace("/", "-")
        elif args.categories and len(args.categories) == 1:
            suffix = args.categories[0]
        else:
            suffix = "full"
        output_path = BENCH_DIR / "results" / f"{run_id}-multi-{suffix}.json"

    output_path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "run_id": run_id,
        "runs_per_task": args.runs,
        "min_fail_rate": args.min_fail_rate,
        "started_at": datetime.now(timezone.utc).isoformat(),
        "tasks": [t.to_dict() for t in reliability],
    }
    output_path.write_text(json.dumps(payload, indent=2) + "\n")
    print(f"\nResults written to: {output_path}")

    # Exit 1 if any consistently-failing tasks found
    consistently_failing = [t for t in reliability if t.fail_rate >= args.min_fail_rate]
    return 1 if consistently_failing else 0


if __name__ == "__main__":
    sys.exit(main())
