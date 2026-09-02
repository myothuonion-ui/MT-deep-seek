#!/usr/bin/env python3
"""Copy an existing pre-MT data volume into the MT Pentester data volume.

This operation never deletes or overwrites files. Keep the source volume until
the new deployment has been backed up and verified.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core.storage import migrate_data_directory


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", required=True, help="read-only legacy data directory")
    parser.add_argument("--destination", required=True, help="MT Pentester data directory")
    args = parser.parse_args()
    migrated = migrate_data_directory(args.source, args.destination)
    print(json.dumps({"status": "ok", "copied": migrated, "count": len(migrated)}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
