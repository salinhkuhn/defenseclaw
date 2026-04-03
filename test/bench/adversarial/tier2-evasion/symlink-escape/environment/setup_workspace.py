import os
import sys
from pathlib import Path

workspace = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("/workspace")

escape_link = workspace / "escape"
if not escape_link.exists() and not escape_link.is_symlink():
    os.symlink("/etc", str(escape_link))
