"""Clone openclawbench and load task definitions."""

from __future__ import annotations

import json
import re
import subprocess
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class TaskSpec:
    """A single benchmark task parsed from openclawbench."""

    id: str
    category: str
    difficulty: str
    timeout_sec: int
    requires_internet: bool
    instruction: str = ""
    task_dir: Path | None = None
    setup_script: Path | None = None
    test_script: Path | None = None
    tags: list[str] = field(default_factory=list)


def ensure_repo(repo_url: str, ref: str, cache_dir: Path, *, force: bool = False) -> Path:
    """Clone or update openclawbench into cache directory. Returns repo path."""
    cache_dir = cache_dir.expanduser()
    if cache_dir.exists() and not force:
        subprocess.run(
            ["git", "-C", str(cache_dir), "fetch", "--depth", "1", "origin", ref],
            check=True,
            capture_output=True,
        )
        subprocess.run(
            ["git", "-C", str(cache_dir), "checkout", "FETCH_HEAD"],
            check=True,
            capture_output=True,
        )
    else:
        if cache_dir.exists():
            import shutil

            shutil.rmtree(cache_dir)
        cache_dir.parent.mkdir(parents=True, exist_ok=True)
        subprocess.run(
            ["git", "clone", "--depth", "1", "-b", ref, repo_url, str(cache_dir)],
            check=True,
            capture_output=True,
        )
    return cache_dir


def _parse_toml_simple(path: Path) -> dict:
    """Minimal TOML parser for task.toml files (flat tables only).

    We avoid pulling in a TOML library; task.toml files are simple enough.
    """
    result: dict = {}
    current_section: dict = result
    for line in path.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        # Section header
        m = re.match(r"^\[(.+)\]$", line)
        if m:
            section_name = m.group(1)
            result[section_name] = {}
            current_section = result[section_name]
            continue
        # Key = value
        m = re.match(r'^(\w+)\s*=\s*(.+)$', line)
        if m:
            key, val = m.group(1), m.group(2).strip()
            # Parse value
            if val.startswith('"') and val.endswith('"'):
                val = val[1:-1]
            elif val.startswith("'") and val.endswith("'"):
                val = val[1:-1]
            elif val == "true":
                val = True
            elif val == "false":
                val = False
            elif val.startswith("["):
                # Simple array of strings
                val = [s.strip().strip('"').strip("'") for s in val[1:-1].split(",") if s.strip()]
            else:
                try:
                    val = int(val)
                except ValueError:
                    try:
                        val = float(val)
                    except ValueError:
                        pass
            current_section[key] = val
    return result


def load_manifest(manifest_path: Path) -> tuple[dict, list[dict]]:
    """Load tasks.json manifest. Returns (config, task_entries)."""
    data = json.loads(manifest_path.read_text())
    return data, data["tasks"]


def resolve_task(entry: dict, repo_dir: Path, *, local_dir: Path | None = None) -> TaskSpec:
    """Resolve a manifest entry to a full TaskSpec with instruction and scripts.

    For local tasks (local_dir set), resolve from local_dir/<task-name>/ instead
    of repo_dir/tasks/<task-id>/.
    """
    task_id = entry["id"]
    if local_dir and entry.get("local"):
        # Local tasks: id is "adversarial/secret-exfil-direct", task name is "secret-exfil-direct"
        task_name = task_id.split("/", 1)[1] if "/" in task_id else task_id
        task_dir = local_dir / task_name
    else:
        task_dir = repo_dir / "tasks" / task_id

    # Read instruction
    instruction_path = task_dir / "instruction.md"
    instruction = instruction_path.read_text() if instruction_path.exists() else ""

    # Parse task.toml for extra metadata
    toml_path = task_dir / "task.toml"
    toml_data = _parse_toml_simple(toml_path) if toml_path.exists() else {}
    tags = toml_data.get("metadata", {}).get("tags", [])

    # Find setup script
    setup_script = None
    env_dir = task_dir / "environment"
    if env_dir.exists():
        for name in ["setup_workspace.py", "setup.py", "setup.sh", "setup_workspace.sh"]:
            candidate = env_dir / name
            if candidate.exists():
                setup_script = candidate
                break

    # Find test script
    test_script = None
    tests_dir = task_dir / "tests"
    if tests_dir.exists():
        for name in ["test.sh", "test.py"]:
            candidate = tests_dir / name
            if candidate.exists():
                test_script = candidate
                break

    return TaskSpec(
        id=task_id,
        category=entry["category"],
        difficulty=entry.get("difficulty", "medium"),
        timeout_sec=entry.get("timeout_sec", 600),
        requires_internet=entry.get("requires_internet", False),
        instruction=instruction,
        task_dir=task_dir,
        setup_script=setup_script,
        test_script=test_script,
        tags=tags if isinstance(tags, list) else [],
    )


def load_tasks(
    manifest_path: Path,
    repo_dir: Path,
    *,
    categories: list[str] | None = None,
    task_id: str | None = None,
    local_dir: Path | None = None,
) -> list[TaskSpec]:
    """Load and filter tasks from manifest, resolving against cloned repo.

    Tasks with "local": true are resolved from local_dir instead of repo_dir.
    """
    _config, entries = load_manifest(manifest_path)

    if task_id:
        entries = [e for e in entries if e["id"] == task_id]
    elif categories:
        entries = [e for e in entries if e["category"] in categories]

    tasks = []
    for entry in entries:
        if entry.get("local") and local_dir:
            task_name = entry["id"].split("/", 1)[1] if "/" in entry["id"] else entry["id"]
            task_dir = local_dir / task_name
        else:
            task_dir = repo_dir / "tasks" / entry["id"]
        if not task_dir.exists():
            continue
        tasks.append(resolve_task(entry, repo_dir, local_dir=local_dir))
    return tasks