"""Workspace setup, teardown, and test verification for benchmark tasks."""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

from .task_loader import TaskSpec


def clean_workspace(workspace: Path, logs_dir: Path) -> None:
    """Remove and recreate workspace and logs directories."""
    for d in [workspace, logs_dir]:
        if d.exists():
            for item in d.iterdir():
                if item.is_dir():
                    shutil.rmtree(item)
                else:
                    item.unlink()
        else:
            d.mkdir(parents=True)
    # Standard subdirs expected by openclawbench test scripts
    (logs_dir / "verifier").mkdir(parents=True, exist_ok=True)
    (logs_dir / "agent").mkdir(parents=True, exist_ok=True)


def run_setup(task: TaskSpec, workspace: Path) -> None:
    """Run the task's setup script to seed workspace data."""
    if not task.setup_script:
        return

    env = {**os.environ, "WORKSPACE": str(workspace)}
    script = task.setup_script

    if script.name.endswith(".py"):
        subprocess.run(
            ["python3", str(script), str(workspace)],
            check=True,
            capture_output=True,
            env=env,
            timeout=60,
        )
    elif script.name.endswith(".sh"):
        subprocess.run(
            ["bash", str(script)],
            check=True,
            capture_output=True,
            env=env,
            cwd=str(workspace),
            timeout=60,
        )


def run_test(
    task: TaskSpec,
    workspace: Path,
    logs_dir: Path,
    agent_response: str = "",
) -> tuple[float, str]:
    """Run the task's test script and return (reward, note)."""
    if not task.test_script:
        return 0.0, ""

    reward_dir = logs_dir / "verifier"
    reward_dir.mkdir(parents=True, exist_ok=True)
    reward_file = reward_dir / "reward.txt"

    # Write agent response for tests that check it
    agent_log_dir = logs_dir / "agent"
    agent_log_dir.mkdir(parents=True, exist_ok=True)
    (agent_log_dir / "response.txt").write_text(agent_response)

    env = {
        **os.environ,
        "WORKSPACE": str(workspace),
        "REWARD_DIR": str(reward_dir),
    }

    script = task.test_script
    test_stderr = ""
    try:
        if script.name.endswith(".py"):
            result = subprocess.run(
                ["python3", str(script)],
                check=False,
                capture_output=True,
                text=True,
                env=env,
                cwd=str(workspace),
                timeout=60,
            )
            test_stderr = result.stderr
        elif script.name.endswith(".sh"):
            result = subprocess.run(
                ["bash", str(script)],
                check=False,
                capture_output=True,
                text=True,
                env=env,
                cwd=str(workspace),
                timeout=60,
            )
            test_stderr = result.stderr
    except subprocess.TimeoutExpired:
        return 0.0, ""

    # Write test stderr for debugging if the verifier crashed
    if test_stderr:
        verifier_log = logs_dir / "verifier" / "test_stderr.txt"
        verifier_log.write_text(test_stderr)

    # Read reward
    reward = 0.0
    if reward_file.exists():
        try:
            reward = float(reward_file.read_text().strip())
        except ValueError:
            pass

    # Read optional note (explains inconclusive results, etc.)
    note = ""
    note_file = reward_dir / "reward_note.txt"
    if note_file.exists():
        note = note_file.read_text().strip()

    return reward, note