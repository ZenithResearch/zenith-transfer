#!/usr/bin/env python3
"""Keep one previous build, plus any backup still in use. Dry-run by default."""
import argparse
import json
from pathlib import Path
import re
import shutil
import subprocess


def in_use(path):
    # Process arguments can retain an old pathname after a running app is moved.
    # lsof checks open files/mapped executable vnodes in the actual backup.
    try:
        result = subprocess.run(["lsof", "-nP", "+D", str(path)],
                                capture_output=True, text=True, timeout=15)
    except (OSError, subprocess.TimeoutExpired):
        return True
    return bool(result.stdout or result.stderr) or result.returncode != 1


def prune(artifacts, apply=False, busy=in_use):
    if artifacts.is_symlink() or not artifacts.is_dir():
        return []
    groups = [[], []]
    for path in artifacts.iterdir():
        if path.is_symlink() or not path.is_dir():
            continue
        if re.fullmatch(r"CastaliaWallet\.previous\.\d+\.xcframework", path.name):
            groups[0].append(path)
        elif re.fullmatch(r"transfer-previous\.[A-Za-z0-9]+", path.name):
            # Never treat arbitrary content under Artifacts as disposable.
            if set(p.name for p in path.iterdir()) <= {"Zenith Transfer.app", ".DS_Store"}:
                groups[1].append(path)
    results = []
    for group in groups:
        ordered = sorted(group, key=lambda p: (p.stat().st_mtime_ns, p.name), reverse=True)
        for path in ordered[1:]:  # Always retain the newest rollback build.
            if busy(path):
                results.append({"backup": path.name, "action": "kept-in-use-or-unverified"})
            else:
                if apply:
                    shutil.rmtree(path)
                results.append({"backup": path.name, "action": "removed" if apply else "would-remove"})
    return results


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--apply", action="store_true")
    args = parser.parse_args()
    print(json.dumps(prune(Path(__file__).resolve().parent.parent / "Artifacts", args.apply)))
