#!/usr/bin/env python3
"""Fetches ChromiumOS D-Bus .proto schemas for a ChromeOS test image release.

Reads the release manifest for `<board>/<release>` from the public
`chromiumos-image-archive` GCS bucket, resolves the exact `chromiumos/platform2`
Git revision, downloads the D-Bus `.proto` files and `LICENSE`, and writes
`scripts/protos/metadata.json` (the single source of truth for the pinned
ChromeOS test image and its matching protobuf schemas).

Usage:
  uv run scripts/protos/update.py --release <RELEASE> [--board <BOARD>]
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import re
import sys
import urllib.request
import xml.etree.ElementTree as ET
from pathlib import Path

GCS_ARCHIVE_ROOT = "https://storage.googleapis.com/chromiumos-image-archive"
PLATFORM2_REPO = "https://chromium.googlesource.com/chromiumos/platform2"
PROTO_DIR = Path(__file__).resolve().parent
METADATA_PATH = PROTO_DIR / "metadata.json"
RELEASE_RE = re.compile(r"^R\d+-\d+\.\d+\.\d+$")

TARGETS: dict[str, str] = {
    "LICENSE": "LICENSE",
    "arc/arc.proto": "system_api/dbus/arc/arc.proto",
    "vm_applications/apps.proto": "system_api/dbus/vm_applications/apps.proto",
    "vm_concierge/concierge_service.proto": "system_api/dbus/vm_concierge/concierge_service.proto",
    "vm_cicerone/cicerone_service.proto": "system_api/dbus/vm_cicerone/cicerone_service.proto",
}


def resolve_board(explicit_board: str | None, meta_path: Path) -> str:
    if explicit_board is not None and explicit_board.strip():
        return explicit_board.strip()
    if meta_path.is_file():
        existing = json.loads(meta_path.read_text(encoding="utf-8"))
        board = existing.get("board")
        if isinstance(board, str) and board.strip():
            return board.strip()
    raise RuntimeError(
        f"--board was not specified and no existing 'board' was found in {meta_path}"
    )


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Update scripts/protos/metadata.json and vendored ChromiumOS .proto files."
    )
    parser.add_argument(
        "--release",
        required=True,
        help="ChromiumOS release version to pin (format: R<milestone>-<version>, required; no default)",
    )
    parser.add_argument(
        "--board",
        default=None,
        help=(
            "ChromiumOS board name (if omitted, reads existing 'board' from "
            "scripts/protos/metadata.json; required if metadata.json does not exist)"
        ),
    )
    args = parser.parse_args()

    cros_release = args.release.strip()
    if not RELEASE_RE.match(cros_release):
        raise ValueError(
            f"--release must match 'R<milestone>-<major>.<minor>.<patch>', got {cros_release!r}"
        )
    board = resolve_board(args.board, METADATA_PATH)

    manifest_url = f"{GCS_ARCHIVE_ROOT}/{board}/{cros_release}/manifest.xml"
    print(f"Fetching manifest: {manifest_url}")
    with urllib.request.urlopen(manifest_url, timeout=30) as resp:
        manifest_xml = resp.read()

    root = ET.fromstring(manifest_xml)
    platform2_rev: str | None = None
    for proj in root.findall("project"):
        if proj.attrib.get("name") == "chromiumos/platform2":
            platform2_rev = proj.attrib.get("revision")
            break

    if not platform2_rev:
        raise RuntimeError(f"Could not find chromiumos/platform2 revision in {manifest_url}")

    print(f"Resolved chromiumos/platform2 revision: {platform2_rev}")

    file_hashes: dict[str, str] = {}
    for local_rel, remote_path in TARGETS.items():
        url = f"{PLATFORM2_REPO}/+/{platform2_rev}/{remote_path}?format=TEXT"
        print(f"Fetching {local_rel} from {url}")
        with urllib.request.urlopen(url, timeout=30) as resp:
            raw_b64 = resp.read()
        content = base64.b64decode(raw_b64)
        dest = PROTO_DIR / local_rel
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_bytes(content)
        file_hashes[local_rel] = hashlib.sha256(content).hexdigest()

    metadata = {
        "board": board,
        "cros_release": cros_release,
        "manifest_url": manifest_url,
        "platform2_repo": PLATFORM2_REPO,
        "platform2_revision": platform2_rev,
        "files": file_hashes,
    }
    METADATA_PATH.write_text(
        json.dumps(metadata, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    print(f"Wrote {METADATA_PATH}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
