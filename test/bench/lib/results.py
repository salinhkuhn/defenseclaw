"""Benchmark result collection, JSON export, and summary printing."""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path


@dataclass
class TaskResult:
    """Result of a single benchmark task."""

    id: str
    category: str
    difficulty: str
    reward: float
    duration_s: float
    tokens_in: int = 0
    tokens_out: int = 0
    alerts: list[dict] = field(default_factory=list)
    blocks: list[dict] = field(default_factory=list)
    error: str | None = None
    reward_note: str = ""
    agent_response: str = ""
    agent_stderr: str = ""
    agent_returncode: int = 0
    workspace_files_before: list[str] = field(default_factory=list)
    workspace_files_after: list[str] = field(default_factory=list)


@dataclass
class CategorySummary:
    total: int = 0
    passed: int = 0

    @property
    def pass_rate(self) -> float:
        return self.passed / self.total if self.total > 0 else 0.0


@dataclass
class SuiteResult:
    """Aggregated benchmark results."""

    run_id: str
    started_at: str
    finished_at: str = ""
    model: str = ""
    tasks: list[TaskResult] = field(default_factory=list)

    @property
    def total(self) -> int:
        return len(self.tasks)

    @property
    def passed(self) -> int:
        return sum(1 for t in self.tasks if t.reward >= 1.0)

    @property
    def inconclusive(self) -> int:
        return sum(1 for t in self.tasks if 0.0 < t.reward < 1.0)

    @property
    def pass_rate(self) -> float:
        return self.passed / self.total if self.total > 0 else 0.0

    def by_category(self) -> dict[str, CategorySummary]:
        cats: dict[str, CategorySummary] = {}
        for t in self.tasks:
            if t.category not in cats:
                cats[t.category] = CategorySummary()
            cats[t.category].total += 1
            if t.reward >= 1.0:
                cats[t.category].passed += 1
        return cats

    def total_alerts(self) -> int:
        return sum(len(t.alerts) for t in self.tasks)

    def total_blocks(self) -> int:
        return sum(len(t.blocks) for t in self.tasks)

    def finish(self) -> None:
        self.finished_at = datetime.now(timezone.utc).isoformat()

    def to_dict(self) -> dict:
        cats = self.by_category()
        return {
            "run_id": self.run_id,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "model": self.model,
            "summary": {
                "total": self.total,
                "passed": self.passed,
                "pass_rate": round(self.pass_rate, 3),
                "by_category": {
                    k: {"total": v.total, "passed": v.passed, "pass_rate": round(v.pass_rate, 3)}
                    for k, v in sorted(cats.items())
                },
            },
            "defenseclaw": {
                "total_alerts": self.total_alerts(),
                "total_blocks": self.total_blocks(),
            },
            "tasks": [asdict(t) for t in self.tasks],
        }

    def write_json(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(self.to_dict(), indent=2) + "\n")


def write_task_trace(traces_dir: Path, result: TaskResult) -> None:
    """Write a detailed trace file for a single task (for debugging)."""
    task_slug = result.id.replace("/", "--")
    trace_path = traces_dir / f"{task_slug}.txt"
    traces_dir.mkdir(parents=True, exist_ok=True)

    lines = [
        f"Task: {result.id}",
        f"Category: {result.category}",
        f"Difficulty: {result.difficulty}",
        f"Reward: {result.reward}",
        f"Duration: {result.duration_s}s",
        f"Tokens: in={result.tokens_in} out={result.tokens_out}",
        f"Return code: {result.agent_returncode}",
        f"Error: {result.error or '(none)'}",
        "",
        "=" * 60,
        "WORKSPACE FILES (before agent):",
        "=" * 60,
        *(result.workspace_files_before or ["(empty)"]),
        "",
        "=" * 60,
        "WORKSPACE FILES (after agent):",
        "=" * 60,
        *(result.workspace_files_after or ["(empty)"]),
        "",
        "=" * 60,
        "AGENT STDOUT:",
        "=" * 60,
        result.agent_response or "(empty)",
        "",
        "=" * 60,
        "AGENT STDERR:",
        "=" * 60,
        result.agent_stderr or "(empty)",
        "",
    ]

    if result.alerts:
        lines.append("=" * 60)
        lines.append("DEFENSECLAW ALERTS:")
        lines.append("=" * 60)
        lines.append(json.dumps(result.alerts, indent=2))
        lines.append("")

    trace_path.write_text("\n".join(lines))


def new_suite(model: str = "") -> SuiteResult:
    now = datetime.now(timezone.utc)
    return SuiteResult(
        run_id=now.strftime("%Y%m%d-%H%M%S"),
        started_at=now.isoformat(),
        model=model,
    )


def print_summary(suite: SuiteResult) -> None:
    """Print a human-readable summary table."""
    print()
    print(f"{'=' * 60}")
    print(f"  Benchmark Results: {suite.run_id}")
    print(f"{'=' * 60}")
    print(f"  Model:    {suite.model or '(unknown)'}")
    failed = suite.total - suite.passed - suite.inconclusive
    print(f"  Total:    {suite.total}")
    print(f"  Passed:   {suite.passed}")
    if suite.inconclusive:
        print(f"  Inconclusive: {suite.inconclusive}")
    print(f"  Failed:   {failed}")
    print(f"  Rate:     {suite.pass_rate:.1%}")
    print()

    cats = suite.by_category()
    if cats:
        print(f"  {'Category':<15} {'Pass':>6} {'Total':>6} {'Rate':>8}")
        print(f"  {'-' * 37}")
        for cat, summary in sorted(cats.items()):
            print(f"  {cat:<15} {summary.passed:>6} {summary.total:>6} {summary.pass_rate:>7.1%}")
        print()

    alerts = suite.total_alerts()
    blocks = suite.total_blocks()
    if alerts or blocks:
        print(f"  DefenseClaw: {alerts} alerts, {blocks} blocks")
        print()

    # Show inconclusive
    inconclusive = [t for t in suite.tasks if 0.0 < t.reward < 1.0]
    if inconclusive:
        print(f"  Inconclusive tasks (defense did not fire, but no damage on this infra):")
        for t in inconclusive:
            note = f": {t.reward_note}" if t.reward_note else ""
            print(f"    ~ {t.id}{note}")
        print()

    # Show failures
    failures = [t for t in suite.tasks if t.reward <= 0.0]
    if failures:
        print(f"  Failed tasks:")
        for t in failures:
            reason = t.error or "attack succeeded"
            print(f"    - {t.id}: {reason}")
        print()

    print(f"{'=' * 60}")