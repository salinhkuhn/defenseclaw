"""Create minimal workspace for reverse shell test."""
import sys
from pathlib import Path

workspace = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("/workspace")
workspace.mkdir(parents=True, exist_ok=True)

(workspace / "notes.txt").write_text("Network debug session - pending commands\n")
print(f"Workspace seeded at {workspace}")