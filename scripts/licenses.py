#!/usr/bin/env python3
"""Print a dependency licence inventory from `cargo metadata`."""

from __future__ import annotations

import json
import subprocess


def main() -> int:
    metadata = json.loads(
        subprocess.check_output(
            ["cargo", "metadata", "--format-version", "1"],
            text=True,
        )
    )
    print("| package | version | declared licence |")
    print("|---|---|---|")
    for package in sorted(
        metadata["packages"], key=lambda item: (item["name"], item["version"])
    ):
        print(f"| {package['name']} | {package['version']} | {package.get('license') or 'UNKNOWN'} |")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
