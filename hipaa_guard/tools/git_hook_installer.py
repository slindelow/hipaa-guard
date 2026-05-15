from __future__ import annotations
"""
git_hook_installer.py

Installs the HIPAA-Guard pre-commit hook into .git/hooks/pre-commit.
The hook runs hipaa-guard scan on staged files before every commit.
"""

import sys
import stat
import subprocess
from pathlib import Path


_HOOK_SCRIPT = '''#!/bin/sh
# HIPAA-Guard pre-commit hook
# Scans staged files for HIPAA violations before commit.

STAGED=$(git diff --cached --name-only --diff-filter=ACM)

if [ -z "$STAGED" ]; then
    exit 0
fi

echo "HIPAA-Guard: scanning staged files..."
hipaa-guard scan $STAGED

EXIT_CODE=$?
if [ $EXIT_CODE -ne 0 ]; then
    echo ""
    echo "HIPAA-Guard: commit blocked due to HIPAA violations."
    echo "Fix the violations above, or mark false positives with:"
    echo "  hipaa-guard fp <finding_id> --reason 'explanation'"
    echo ""
    exit 1
fi

exit 0
'''


def install(repo_root: str | None = None) -> None:
    """Install pre-commit hook into the git repo at repo_root (defaults to cwd)."""
    if repo_root is None:
        result = subprocess.run(
            ["git", "rev-parse", "--git-dir"],
            capture_output=True, text=True
        )
        if result.returncode != 0:
            print("❌ Not inside a git repository. Navigate to your project root and retry.")
            sys.exit(1)
        git_dir = Path(result.stdout.strip())
    else:
        git_dir = Path(repo_root) / ".git"

    hooks_dir = git_dir / "hooks"
    hooks_dir.mkdir(exist_ok=True)
    hook_path = hooks_dir / "pre-commit"

    # Check for existing hook
    if hook_path.exists():
        existing = hook_path.read_text()
        if "HIPAA-Guard" in existing:
            print("✅ HIPAA-Guard pre-commit hook is already installed.")
            return
        with hook_path.open("a") as f:
            f.write("\n# HIPAA-Guard addition\n")
            f.write(_HOOK_SCRIPT)
        print("✅ HIPAA-Guard appended to existing pre-commit hook.")
    else:
        hook_path.write_text(_HOOK_SCRIPT)

    # Make executable
    current_mode = hook_path.stat().st_mode
    hook_path.chmod(current_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)

    print(f"✅ HIPAA-Guard pre-commit hook installed at: {hook_path}")
    print(f"   Every commit will now be scanned for HIPAA violations.")
    print(f"   To uninstall: rm {hook_path}")


if __name__ == "__main__":
    install()
