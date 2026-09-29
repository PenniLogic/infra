"""Install only this repository's managed pre-commit hook; preserve custom hooks."""

from pathlib import Path
import os
import subprocess
import sys


ROOT = Path(__file__).resolve().parents[1]
HOOK = "#!/bin/sh\n# PenniLogic managed pre-commit v1\nexec python scripts/check_repository.py --staged\n"


def main():
    custom = subprocess.run(
        ["git", "config", "--get", "core.hooksPath"], cwd=ROOT,
        capture_output=True, text=True, encoding="utf-8",
    )
    if custom.returncode not in (0, 1):
        print("Cannot inspect configured hooks path", file=sys.stderr)
        return 1
    if custom.stdout.strip():
        print("Custom hooks path preserved; integrate the repository check manually.", file=sys.stderr)
        return 1
    result = subprocess.run(
        ["git", "rev-parse", "--git-path", "hooks/pre-commit"], cwd=ROOT,
        capture_output=True, text=True, encoding="utf-8",
    )
    if result.returncode:
        print("Cannot locate repository hook directory", file=sys.stderr)
        return 1
    path = Path(result.stdout.strip())
    if not path.is_absolute():
        path = ROOT / path
    if path.is_symlink() or (path.exists() and path.read_text(encoding="utf-8") != HOOK):
        print("Existing custom pre-commit hook preserved; integrate the repository check manually.", file=sys.stderr)
        return 1
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(HOOK, encoding="utf-8", newline="\n")
    if os.name != "nt":
        path.chmod(0o755)
    print("Managed pre-commit hook installed; no global settings changed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
