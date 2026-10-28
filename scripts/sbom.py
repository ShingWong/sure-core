#!/usr/bin/env python3
"""Generate a minimal CycloneDX 1.5 SBOM from `cargo metadata`.

Usage: python3 scripts/sbom.py > sbom.cdx.json
No third-party Python packages are required.
"""

from __future__ import annotations

import datetime
import json
import subprocess
import sys
from pathlib import Path


def main() -> int:
    root = Path(__file__).resolve().parent.parent
    raw = subprocess.check_output(
        ["cargo", "metadata", "--format-version", "1"],
        cwd=root,
        text=True,
    )
    metadata = json.loads(raw)
    components = []
    for package in sorted(metadata["packages"], key=lambda item: (item["name"], item["version"])):
        component = {
            "type": "library",
            "name": package["name"],
            "version": package["version"],
            "purl": f"pkg:cargo/{package['name']}@{package['version']}",
        }
        license_value = package.get("license")
        if license_value:
            if " OR " in license_value or " AND " in license_value:
                component["licenses"] = [{"expression": license_value}]
            else:
                component["licenses"] = [{"license": {"id": license_value}}]
        components.append(component)

    bom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "version": 1,
        "metadata": {
            "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "component": {
                "type": "application",
                "name": "sure-core",
                "version": "0.1.0",
            },
        },
        "components": components,
    }
    json.dump(bom, sys.stdout, indent=2, sort_keys=False)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
