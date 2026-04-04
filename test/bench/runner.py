#!/usr/bin/env python3
"""OpenClawBench runner for DefenseClaw.

Runs benchmark tasks from openclawbench against a local OpenClaw + DefenseClaw
deployment and collects results including DefenseClaw telemetry.

Usage:
    python test/bench/runner.py [OPTIONS]

    --category CAT     Run only this category (repeatable)
    --task ID          Run single task by name (e.g. file/file-comparison)
    --timeout N        Override all task timeouts (seconds)
    --skip-telemetry   Skip DefenseClaw sidecar queries
    --output FILE      Write results JSON (default: results/<timestamp>.json)
    --list             List available tasks and exit
    --refresh          Force re-clone openclawbench
    --verbose          Show openclaw output
    --dry-run          Show what would run without executing
"""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
import time
import urllib.error
import urllib.request
import json
from pathlib import Path

# Allow running from repo root or from test/bench/
BENCH_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(BENCH_DIR))

from lib.task_loader import ensure_repo, load_tasks
from lib.workspace import clean_workspace, run_setup, run_test
from lib.openclaw_client import clear_session, run_agent
from lib.results import TaskResult, new_suite, print_summary, write_task_trace


def load_config() -> dict:
    """Load config.toml using minimal parser."""
    config_path = BENCH_DIR / "config.toml"
    config: dict = {}
    section: dict = config
    for line in config_path.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("["):
            key = line.strip("[]")
            config[key] = {}
            section = config[key]
            continue
        if "=" in line:
            k, v = line.split("=", 1)
            k, v = k.strip(), v.strip().strip('"').strip("'")
            try:
                v = int(v)
            except ValueError:
                try:
                    v = float(v)
                except ValueError:
                    pass
            section[k] = v
    return config


def list_workspace_files(workspace: Path) -> list[str]:
    """Recursively list files in workspace (relative paths)."""
    if not workspace.exists():
        return []
    files = []
    for root, _dirs, filenames in os.walk(workspace):
        for f in sorted(filenames):
            full = Path(root) / f
            files.append(str(full.relative_to(workspace)))
    return files


def query_sidecar_alerts(host: str, port: int) -> list[dict]:
    """Query DefenseClaw sidecar for recent alerts."""
    url = f"http://{host}:{port}/api/v1/alerts?limit=50"
    try:
        req = urllib.request.Request(url, headers={"Accept": "application/json"})
        with urllib.request.urlopen(req, timeout=5) as resp:
            data = json.loads(resp.read())
            return data if isinstance(data, list) else data.get("alerts", [])
    except (urllib.error.URLError, OSError, json.JSONDecodeError):
        return []


def run_task_once(
    task,
    *,
    workspace: Path,
    logs_dir: Path,
    agent_id: str = "main",
    timeout: int = 60,
    verbose: bool = False,
    skip_telemetry: bool = False,
    sidecar_host: str = "127.0.0.1",
    sidecar_port: int = 18970,
) -> tuple["TaskResult", str, str, str]:
    """Run a single task once and return (TaskResult, status_str, extra_str, model_str).

    Extracted so multi_runner.py can call it in a loop without duplicating logic.
    """
    alerts_before: list[dict] = []
    if not skip_telemetry:
        alerts_before = query_sidecar_alerts(sidecar_host, sidecar_port)

    start = time.monotonic()
    error = None
    workspace_before: list[str] = []
    workspace_after: list[str] = []
    response = None
    reward = 0.0
    reward_note = ""

    try:
        clean_workspace(workspace, logs_dir)
        run_setup(task, workspace)
        workspace_before = list_workspace_files(workspace)

        instruction = task.instruction.replace("/workspace", str(workspace))

        session_id = f"bench-{task.id.replace('/', '-')}"
        clear_session(session_id)

        response = run_agent(
            instruction,
            session_id=session_id,
            agent_id=agent_id,
            timeout_sec=timeout,
            verbose=verbose,
        )

        if response.error:
            error = response.error

        workspace_after = list_workspace_files(workspace)

        if verbose:
            if response.text:
                print(f"\n    agent response: {response.text[:500]}")
            new_files = set(workspace_after) - set(workspace_before)
            removed_files = set(workspace_before) - set(workspace_after)
            if new_files:
                print(f"    new files: {', '.join(sorted(new_files))}")
            if removed_files:
                print(f"    removed files: {', '.join(sorted(removed_files))}")

        reward, reward_note = run_test(task, workspace, logs_dir, agent_response=response.text)
        if verbose:
            print(f"    verifier: reward={reward}" + (f" ({reward_note})" if reward_note else ""))
            test_stderr_file = logs_dir / "verifier" / "test_stderr.txt"
            if test_stderr_file.exists():
                print(f"    verifier stderr: {test_stderr_file.read_text()[:300]}")

    except Exception as e:
        reward = 0.0
        reward_note = ""
        error = str(e)

    duration = time.monotonic() - start

    new_alerts: list[dict] = []
    new_blocks: list[dict] = []
    if not skip_telemetry:
        alerts_after = query_sidecar_alerts(sidecar_host, sidecar_port)
        before_ids = {a.get("id") for a in alerts_before}
        new_alerts = [a for a in alerts_after if a.get("id") not in before_ids]
        new_blocks = [a for a in new_alerts if a.get("action") == "block"]

    if reward >= 1.0:
        status = "PASS"
    elif reward > 0.0:
        status = "INCONCLUSIVE"
    else:
        status = "FAIL"

    extra = ""
    if error:
        extra = f" ({error[:60]})"
    elif reward_note and status == "INCONCLUSIVE":
        extra = f" ({reward_note[:80]})"
    elif new_blocks:
        extra = f" ({len(new_blocks)} blocks)"

    model = response.model if response else ""

    result = TaskResult(
        id=task.id,
        category=task.category,
        difficulty=task.difficulty,
        reward=reward,
        duration_s=round(duration, 1),
        tokens_in=response.tokens_in if response else 0,
        tokens_out=response.tokens_out if response else 0,
        alerts=new_alerts,
        blocks=new_blocks,
        error=error,
        reward_note=reward_note if reward_note else "",
        agent_response=response.text if response else "",
        agent_stderr=response.stderr if response else "",
        agent_returncode=response.returncode if response else -1,
        workspace_files_before=workspace_before,
        workspace_files_after=workspace_after,
    )
    return result, status, extra, model


def main() -> int:
    parser = argparse.ArgumentParser(description="OpenClawBench runner for DefenseClaw")
    parser.add_argument("--category", action="append", dest="categories", help="Run only this category (repeatable)")
    parser.add_argument("--task", dest="task_id", help="Run single task by ID (e.g. file/file-comparison)")
    parser.add_argument("--timeout", type=int, help="Override all task timeouts (seconds)")
    parser.add_argument("--skip-telemetry", action="store_true", help="Skip DefenseClaw sidecar queries")
    parser.add_argument("--output", type=str, help="Write results JSON to this file")
    parser.add_argument("--list", action="store_true", help="List available tasks and exit")
    parser.add_argument("--refresh", action="store_true", help="Force re-clone openclawbench")
    parser.add_argument("--verbose", action="store_true", help="Show openclaw output")
    parser.add_argument("--dry-run", action="store_true", help="Show what would run without executing")
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

    # Clone/update openclawbench
    print(f"Fetching openclawbench from {repo_url} (ref: {repo_ref})...")
    repo_dir = ensure_repo(repo_url, repo_ref, cache_dir, force=args.refresh)
    print(f"  cached at: {repo_dir}")

    # Load tasks (local adversarial tasks resolve from BENCH_DIR/adversarial/)
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

    # --list mode
    if args.list:
        print(f"\n{'ID':<45} {'Category':<12} {'Difficulty':<10} {'Internet'}")
        print("-" * 80)
        for t in tasks:
            inet = "yes" if t.requires_internet else "no"
            print(f"{t.id:<45} {t.category:<12} {t.difficulty:<10} {inet}")
        print(f"\nTotal: {len(tasks)} tasks")
        return 0

    # --dry-run mode
    if args.dry_run:
        print(f"\nDry run: would execute {len(tasks)} tasks:")
        for t in tasks:
            timeout = args.timeout or t.timeout_sec
            setup = t.setup_script.name if t.setup_script else "(none)"
            test = t.test_script.name if t.test_script else "(none)"
            print(f"  {t.id:<40} setup={setup:<25} test={test:<10} timeout={timeout}s")
        return 0

    # Run benchmark
    suite = new_suite()
    print(f"\nRunning {len(tasks)} benchmark tasks...")
    print(f"  workspace: {workspace}")
    print(f"  logs:      {logs_dir}")
    print()

    for i, task in enumerate(tasks, 1):
        timeout = args.timeout or task.timeout_sec
        print(f"[{i}/{len(tasks)}] {task.id} ", end="", flush=True)

        result, status, extra, model = run_task_once(
            task,
            workspace=workspace,
            logs_dir=logs_dir,
            agent_id=str(oc_cfg.get("agent_id", "main")),
            timeout=timeout,
            verbose=args.verbose,
            skip_telemetry=args.skip_telemetry,
            sidecar_host=sidecar_host,
            sidecar_port=sidecar_port,
        )
        print(f"  {status}  {result.duration_s:.1f}s{extra}")
        suite.tasks.append(result)

        # Populate model from first successful response
        if not suite.model and model:
            suite.model = model

        # Write per-task trace file for debugging
        traces_dir = BENCH_DIR / "results" / "traces" / suite.run_id
        write_task_trace(traces_dir, result)

    suite.finish()

    # Write results — include task/category in filename for easy identification
    if args.output:
        output_path = Path(args.output)
    else:
        if args.task_id:
            suffix = args.task_id.replace("/", "-")
        elif args.categories and len(args.categories) == 1:
            suffix = args.categories[0]
        elif args.categories:
            suffix = "-".join(sorted(args.categories))
        else:
            suffix = "full"
        output_path = BENCH_DIR / "results" / f"{suite.run_id}-{suffix}.json"
    suite.write_json(output_path)
    traces_dir = BENCH_DIR / "results" / "traces" / suite.run_id
    print(f"\nResults written to: {output_path}")
    print(f"Task traces at:    {traces_dir}/")

    print_summary(suite)
    return 0 if suite.pass_rate > 0 else 1


if __name__ == "__main__":
    sys.exit(main())