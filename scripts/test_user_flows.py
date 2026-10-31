#!/usr/bin/env python3
"""End-to-end verification of the arch-baguette ChromeOS UI user setup flow in a ChromeOS VM.

All user-facing steps are driven through the real ChromeOS UI (Chrome DevTools
Protocol over an SSH port forward to Chrome's DevToolsActivePort) using the
exact commands parsed from `README.md` fenced code blocks, while a passive,
side-effect-free initialization timeline recorder monitors D-Bus signals
(`org.chromium.VmConcierge` and `org.chromium.VmCicerone`), read-only D-Bus
queries, Chrome UMA histograms, and system logs:

  - Flow (`termina` VM name + ChromeOS Settings Linux Installer UI):
    1. Opens `chrome-untrusted://crosh/` and runs the `vmc create ... termina`
      command parsed from `README.md`.
    2. Starts a passive system D-Bus signal monitor (`dbus-monitor --system`)
      before clicking **Install** to timestamp `VmStartingUpSignal`,
      `VmStartedSignal`, and `ContainerStarted` (`termina`/`penguin`).
    3. Opens `chrome://os-settings/`, navigates to **About ChromeOS** ->
      **Developers** -> **Linux development environment**, and clicks **Set up**.
    4. In `chrome://crostini-installer`, clicks **Next**, enters a custom
      username (`terminauser`), clicks **Install**, and waits for the
      installer dialog to finish and launch the ChromeOS Terminal app.
    5. Observes the auto-opened `chrome-untrusted://terminal` window, gates
      readiness on cicerone's `ContainerStarted` signal for `termina`/`penguin`,
      allows recovery via a fresh Terminal tab from the Terminal Home app ONLY
      for the single proven slow-runner case (initial Terminal buffer equals
      `Launching vmshell failed: Error starting crostini for terminal: 50 (CONTAINER_SETUP_FAILED)`
      caused by `SetUpVmUser` call #2 hitting its 20s `Deadline Exceeded` between
      `InstallerClosed` and `ContainerStarted`), and verifies an interactive
      shell (`id -nu` == `terminauser`) inside the ChromeOS Terminal app.
    6. Runs the documented `vsh termina penguin` command in `crosh` once (no
      retry) and asserts the guest login shell belongs to `terminauser`.
    7. Verifies the Arch Linux guest environment (`/etc/os-release`), UID 1000
      username (`terminauser`), primary group `terminauser` (GID 1000), exact
      supplementary group set (`audio`, `cdrom`, `dialout`, `disk`, `floppy`,
      `kvm`, `netdev`, `sudo`, `tss`, `video`), and active `cros-garcon.service`,
      and prints the complete initialization timeline and read-only D-Bus/UMA state.
"""

from __future__ import annotations

import argparse
import base64
import calendar
import dataclasses
import hashlib
import json
import os
import re
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time
import urllib.request
from pathlib import Path
from typing import Any, Callable, TypeVar

import google.protobuf
from google.protobuf.message import DecodeError, Message
from grpc_tools import protoc

GCS_ARCHIVE_ROOT = "https://storage.googleapis.com/chromiumos-image-archive"
TESTING_RSA_GITILES_URL = (
    "https://chromium.googlesource.com/chromiumos/chromite/+/refs/heads/main/"
    "ssh_keys/testing_rsa?format=TEXT"
)
REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_README_PATH = REPO_ROOT / "README.md"
DEFAULT_PROTO_DIR = Path(__file__).resolve().parent / "protos"
CROS_RELEASE_RE = re.compile(r"^R(\d+)-(\d+\.\d+\.\d+)$")

# Exact terminal.js output when chrome.terminalPrivate.openVmshellProcess fails with
# CrostiniResult::CONTAINER_SETUP_FAILED (50) after SetUpVmUser hits its 20s gRPC deadline.
KNOWN_INITIAL_TERMINAL_TIMEOUT_ERROR = (
    "Launching vmshell failed: Error starting crostini for terminal: 50 (CONTAINER_SETUP_FAILED)"
)

# Expected guest user identity created by Chrome's Crostini installer via
# CrostiniManager::SetUpBaguetteUser (chrome/browser/ash/crostini/crostini_manager.cc)
# -> Concierge SetUpVmUser -> maitred::ServiceImpl::SetUpUser
# (platform2/vm_tools/maitred/service_impl.cc), which filters the requested group list
# against existing groups in /etc/group inside baguette_arch_rootfs.img.zst.
EXPECTED_GUEST_UID = 1000
EXPECTED_GUEST_GID = 1000
EXPECTED_GUEST_SUPPLEMENTARY_GROUPS: frozenset[str] = frozenset(
    {
        "audio",
        "cdrom",
        "dialout",
        "disk",
        "floppy",
        "kvm",
        "netdev",
        "sudo",
        "tss",
        "video",
    }
)

TMessage = TypeVar("TMessage", bound=Message)


def log(msg: str) -> None:
    timestamp = time.strftime("%H:%M:%S")
    print(f"[{timestamp}] {msg}", flush=True)


def parse_cros_release_str(cros_release: str) -> tuple[str, str]:
    """Parses `R<milestone>-<version>` into `(milestone, version)` or raises `RuntimeError`."""
    m = CROS_RELEASE_RE.match(cros_release.strip())
    if not m:
        raise RuntimeError(
            f"Invalid ChromiumOS release string {cros_release!r}; expected 'R<milestone>-<x>.<y>.<z>'"
        )
    return m.group(1), m.group(2)


@dataclasses.dataclass(frozen=True)
class ReadmeCommands:
    termina_create: str
    termina_reentry_vsh: str


@dataclasses.dataclass(frozen=True)
class CrosProtoModules:
    metadata: dict[str, Any]
    concierge_pb2: Any
    cicerone_pb2: Any
    _temp_dir: tempfile.TemporaryDirectory[str]


_CROS_PROTOS: CrosProtoModules | None = None
_CROS_PROTOS_LOCK = threading.Lock()


def verify_vendored_protos(proto_dir: Path = DEFAULT_PROTO_DIR) -> dict[str, Any]:
    """Verifies `scripts/protos/metadata.json` and the SHA-256 of every vendored `.proto` file."""
    meta_path = proto_dir / "metadata.json"
    if not meta_path.is_file():
        raise RuntimeError(f"Missing vendored proto metadata file: {meta_path}")
    try:
        meta = json.loads(meta_path.read_text(encoding="utf-8"))
    except Exception as exc:
        raise RuntimeError(f"Failed to parse {meta_path}: {exc}") from exc

    for req_key in ("board", "cros_release", "platform2_revision", "manifest_url", "platform2_repo"):
        val = meta.get(req_key)
        if not isinstance(val, str) or not val.strip():
            raise RuntimeError(f"Invalid or missing {req_key!r} in {meta_path}: {val!r}")

    _ = parse_cros_release_str(meta["cros_release"])
    expected_manifest_url = f"{GCS_ARCHIVE_ROOT}/{meta['board']}/{meta['cros_release']}/manifest.xml"
    if meta["manifest_url"] != expected_manifest_url:
        raise RuntimeError(
            f"Mismatched manifest_url in {meta_path}: expected {expected_manifest_url!r}, "
            f"got {meta['manifest_url']!r}"
        )

    files_map = meta.get("files")
    if not isinstance(files_map, dict) or not files_map:
        raise RuntimeError(f"Invalid or empty 'files' map in {meta_path}")

    for rel_path, expected_sha in files_map.items():
        if not isinstance(rel_path, str) or not isinstance(expected_sha, str):
            raise RuntimeError(f"Invalid file entry in {meta_path}: {rel_path!r}: {expected_sha!r}")
        full_path = proto_dir / rel_path
        if not full_path.is_file():
            raise RuntimeError(
                f"Vendored file {rel_path!r} listed in {meta_path} does not exist at {full_path}"
            )
        actual_sha = hashlib.sha256(full_path.read_bytes()).hexdigest()
        if actual_sha != expected_sha:
            raise RuntimeError(
                f"SHA-256 mismatch for vendored file {full_path}: "
                f"expected {expected_sha}, got {actual_sha} "
                f"(run `uv run scripts/protos/update.py --release <RELEASE>`)"
            )

    actual_protos = {
        str(p.relative_to(proto_dir).as_posix()) for p in proto_dir.rglob("*.proto")
    }
    expected_protos = {k for k in files_map if k.endswith(".proto")}
    if actual_protos != expected_protos:
        raise RuntimeError(
            f"Unlisted or missing .proto files in {proto_dir}: "
            f"actual={sorted(actual_protos)} vs metadata={sorted(expected_protos)}"
        )

    return meta


def verify_lsb_release_matches_metadata(lsb_release_text: str, meta: dict[str, Any]) -> None:
    """Aborts if the booted ChromeOS VM's `/etc/lsb-release` differs from `scripts/protos/metadata.json`."""
    kv: dict[str, str] = {}
    for raw_line in lsb_release_text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if "=" not in line:
            raise ValueError(f"Malformed line in /etc/lsb-release: {raw_line!r}")
        k, v = line.split("=", 1)
        kv[k.strip()] = v.strip()

    expected_board = meta["board"]
    expected_release = meta["cros_release"]
    expected_builder_path = f"{expected_board}/{expected_release}"
    actual_builder_path = kv.get("CHROMEOS_RELEASE_BUILDER_PATH", "")
    if actual_builder_path != expected_builder_path:
        raise RuntimeError(
            f"Booted ChromeOS image CHROMEOS_RELEASE_BUILDER_PATH={actual_builder_path!r} "
            f"does not match vendored proto metadata {expected_builder_path!r}"
        )

    milestone = kv.get("CHROMEOS_RELEASE_CHROME_MILESTONE", "")
    version = kv.get("CHROMEOS_RELEASE_VERSION", "")
    reconstructed = f"R{milestone}-{version}"
    if reconstructed != expected_release:
        raise RuntimeError(
            f"Booted ChromeOS image release {reconstructed!r} "
            f"(CHROMEOS_RELEASE_CHROME_MILESTONE={milestone!r}, "
            f"CHROMEOS_RELEASE_VERSION={version!r}) does not match "
            f"vendored proto metadata {expected_release!r}"
        )


def load_cros_protos(proto_dir: Path = DEFAULT_PROTO_DIR) -> CrosProtoModules:
    """Compiles the vendored ChromiumOS `.proto` files via `grpc_tools.protoc` and loads `_pb2` modules."""
    global _CROS_PROTOS
    with _CROS_PROTOS_LOCK:
        if _CROS_PROTOS is not None and proto_dir == DEFAULT_PROTO_DIR:
            return _CROS_PROTOS

        meta = verify_vendored_protos(proto_dir)
        pb_ver = google.protobuf.__version__
        if not pb_ver.startswith("7."):
            raise RuntimeError(
                f"Expected google.protobuf major version 7.x matching uv.lock, got {pb_ver!r}"
            )

        tmp_dir = tempfile.TemporaryDirectory(prefix="cros-protos-")
        proto_files = [
            str(proto_dir / "arc/arc.proto"),
            str(proto_dir / "vm_applications/apps.proto"),
            str(proto_dir / "vm_concierge/concierge_service.proto"),
            str(proto_dir / "vm_cicerone/cicerone_service.proto"),
        ]
        rc = protoc.main(
            [
                "grpc_tools.protoc",
                f"-I{proto_dir}",
                f"--python_out={tmp_dir.name}",
                *proto_files,
            ]
        )
        if rc != 0:
            raise RuntimeError(f"grpc_tools.protoc failed with exit code {rc}")

        sys.path.insert(0, tmp_dir.name)
        try:
            import importlib

            importlib.invalidate_caches()
            concierge_pb2 = importlib.import_module("vm_concierge.concierge_service_pb2")
            cicerone_pb2 = importlib.import_module("vm_cicerone.cicerone_service_pb2")
        finally:
            sys.path.remove(tmp_dir.name)

        loaded = CrosProtoModules(
            metadata=meta,
            concierge_pb2=concierge_pb2,
            cicerone_pb2=cicerone_pb2,
            _temp_dir=tmp_dir,
        )
        if proto_dir == DEFAULT_PROTO_DIR:
            _CROS_PROTOS = loaded
        return loaded


def parse_and_validate_proto(raw: bytes, msg_cls: type[TMessage], context: str) -> TMessage:
    """Strictly parses `raw` into `msg_cls` and rejects corrupt wire bytes or unknown fields."""
    msg = msg_cls()
    try:
        parsed_len = msg.ParseFromString(raw)
    except DecodeError as exc:
        raise ValueError(
            f"{context}: failed to decode {msg_cls.DESCRIPTOR.full_name} "
            f"(len={len(raw)}, hex={raw.hex()}): {exc}"
        ) from exc
    if parsed_len != len(raw):
        raise ValueError(
            f"{context}: incomplete parse of {msg_cls.DESCRIPTOR.full_name}: "
            f"consumed {parsed_len} of {len(raw)} bytes (hex={raw.hex()})"
        )
    size_with_unknown = msg.ByteSize()
    msg.DiscardUnknownFields()
    size_without_unknown = msg.ByteSize()
    if size_with_unknown != size_without_unknown:
        raise ValueError(
            f"{context}: {msg_cls.DESCRIPTOR.full_name} contained unknown protobuf fields "
            f"(byte_size {size_with_unknown} -> {size_without_unknown}, hex={raw.hex()})"
        )
    return msg


def require_non_empty_str(val: str, field_name: str, context: str, raw: bytes) -> str:
    if not isinstance(val, str) or not val.strip():
        raise ValueError(
            f"{context}: required string field {field_name!r} is empty (hex={raw.hex()})"
        )
    return val


def require_enum_name(
    enum_wrapper: Any,
    val: int,
    field_name: str,
    context: str,
    raw: bytes,
    disallow_zero_unknown: bool = True,
) -> str:
    try:
        name = str(enum_wrapper.Name(val))
    except ValueError as exc:
        raise ValueError(
            f"{context}: unknown enum value {val} for field {field_name!r} (hex={raw.hex()})"
        ) from exc
    if disallow_zero_unknown and val == 0 and "UNKNOWN" in name:
        raise ValueError(
            f"{context}: enum field {field_name!r} has unset/UNKNOWN value 0 ({name}, hex={raw.hex()})"
        )
    return name


def split_shell_commands(block: str) -> list[str]:
    """Joins backslash-continued lines and returns non-empty logical command lines."""
    joined = re.sub(r"\s*\\\s*\n\s*", " ", block.strip())
    cmds: list[str] = []
    for raw_line in joined.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        line = re.sub(r"\s+#.*$", "", line).strip()
        if line:
            cmds.append(line)
    return cmds


def extract_section_sh_blocks(markdown: str, heading_prefix: str) -> list[list[str]]:
    """Extracts fenced `sh`/`bash` command blocks under a `### <heading_prefix>` section."""
    pattern = re.compile(
        rf"^###\s+{re.escape(heading_prefix)}[^\n]*\n(.*?)(?=^###|^##|\Z)",
        re.MULTILINE | re.DOTALL,
    )
    match = pattern.search(markdown)
    if not match:
        raise ValueError(f"Could not find section starting with '### {heading_prefix}' in README")
    section_body = match.group(1)
    fence_pattern = re.compile(r"```(?:sh|bash)?\n(.*?)```", re.DOTALL)
    blocks = [split_shell_commands(m.group(1)) for m in fence_pattern.finditer(section_body)]
    return [b for b in blocks if b]


def extract_readme_commands(readme_path: Path = DEFAULT_README_PATH) -> ReadmeCommands:
    """Parses the exact user-facing crosh commands from README.md."""
    text = readme_path.read_text(encoding="utf-8")

    setup_blocks = extract_section_sh_blocks(text, "Setup:")
    if len(setup_blocks) < 2:
        raise ValueError(
            f"Expected '### Setup:' in {readme_path} to have at least 2 fenced code blocks "
            f"(`vmc create ... termina` and `vsh termina penguin`), got: {setup_blocks!r}"
        )
    if len(setup_blocks[0]) != 1:
        raise ValueError(
            f"Expected '### Setup:' block 1 in {readme_path} to be a single `vmc create` command, "
            f"got: {setup_blocks[0]!r}"
        )
    if len(setup_blocks[1]) != 1:
        raise ValueError(
            f"Expected '### Setup:' block 2 in {readme_path} to be a single `vsh` command, "
            f"got: {setup_blocks[1]!r}"
        )

    return ReadmeCommands(
        termina_create=setup_blocks[0][0],
        termina_reentry_vsh=setup_blocks[1][0],
    )


def to_dbus_byte_arg(payload: bytes) -> str:
    return "array:byte:" + ",".join(f"0x{b:02x}" for b in payload)


_HEX_BYTE_RE = re.compile(r"^[0-9a-fA-F]{2}$")
_DBUS_METHOD_RETURN_RE = re.compile(
    r"^method return time=\d+\.\d+ sender=\S+ -> destination=\S+ serial=\d+ reply_serial=\d+$"
)
_DBUS_SIGNAL_HEADER_RE = re.compile(
    r"^signal time=\d+\.\d+ sender=\S+ -> destination=(?:\(null destination\)|\S+) "
    r"serial=\d+ path=(\S+); interface=([A-Za-z0-9_.]+); member=([A-Za-z0-9_]+)$"
)

MONITORED_DBUS_SIGNALS: frozenset[tuple[str, str]] = frozenset(
    {
        ("org.chromium.VmConcierge", "VmStartingUpSignal"),
        ("org.chromium.VmConcierge", "VmStartedSignal"),
        ("org.chromium.VmConcierge", "VmGuestUserlandReadySignal"),
        ("org.chromium.VmConcierge", "VmStoppingSignal"),
        ("org.chromium.VmConcierge", "VmStoppedSignal"),
        ("org.chromium.VmCicerone", "ContainerStarted"),
        ("org.chromium.VmCicerone", "ContainerShutdown"),
        ("org.chromium.VmCicerone", "PendingAppListUpdates"),
        ("org.chromium.VmCicerone", "TremplinStarted"),
    }
)


def _parse_hex_byte_tokens(tokens: list[str], context: str, raw_line: str) -> list[str]:
    for tok in tokens:
        if not _HEX_BYTE_RE.match(tok):
            raise ValueError(
                f"{context}: invalid hex byte token {tok!r} in line {raw_line!r}"
            )
    return tokens


def parse_dbus_send_byte_array(output: str, context: str = "dbus-send") -> bytes:
    """Strictly parses `dbus-send --print-reply` output containing a single `array of bytes [...]` (or empty `array [\\n]`)."""
    non_empty = [ln for ln in output.splitlines() if ln.strip()]
    if len(non_empty) < 2:
        raise ValueError(f"{context}: truncated or empty dbus-send output:\n{output}")
    if not _DBUS_METHOD_RETURN_RE.match(non_empty[0].strip()):
        raise ValueError(
            f"{context}: expected 'method return ...' header on line 1, got {non_empty[0]!r}"
        )

    first_body = non_empty[1]
    # In dbus-print-message.c, a 0-length `ay` (byte array) has subiter arg_type == DBUS_TYPE_INVALID,
    # so `dbus-send --print-reply` prints `   array [\n   ]` instead of `   array of bytes [`.
    if first_body == "   array [":
        if len(non_empty) != 3 or non_empty[2] != "   ]":
            raise ValueError(
                f"{context}: expected exact closing '   ]' after empty '   array [', got:\n{output}"
            )
        return b""

    if not first_body.startswith("   array of bytes ["):
        raise ValueError(
            f"{context}: expected indented 'array of bytes [' (or empty '   array [') on line 2, got {first_body!r}"
        )

    hex_tokens: list[str] = []
    after_open = first_body.split("[", 1)[1]
    if "]" in after_open:
        if len(non_empty) != 2:
            raise ValueError(
                f"{context}: unexpected extra lines after closing ']' in:\n{output}"
            )
        before_close, after_close = after_open.split("]", 1)
        if after_close.strip():
            raise ValueError(
                f"{context}: unexpected trailing text after ']' on line 2: {first_body!r}"
            )
        hex_tokens.extend(_parse_hex_byte_tokens(before_close.split(), context, first_body))
        return bytes.fromhex("".join(hex_tokens))

    hex_tokens.extend(_parse_hex_byte_tokens(after_open.split(), context, first_body))
    closed = False
    for idx, ln in enumerate(non_empty[2:], start=3):
        if closed:
            raise ValueError(
                f"{context}: unexpected extra line {idx} after closing ']': {ln!r}"
            )
        if not ln.startswith("   "):
            raise ValueError(
                f"{context}: expected indented array line {idx}, got {ln!r}"
            )
        if "]" in ln:
            before_close, after_close = ln.split("]", 1)
            if after_close.strip():
                raise ValueError(
                    f"{context}: unexpected trailing text after ']' on line {idx}: {ln!r}"
                )
            hex_tokens.extend(_parse_hex_byte_tokens(before_close.split(), context, ln))
            closed = True
        else:
            toks = ln.split()
            if not toks:
                raise ValueError(f"{context}: empty line inside array of bytes")
            hex_tokens.extend(_parse_hex_byte_tokens(toks, context, ln))

    if not closed:
        raise ValueError(f"{context}: unclosed 'array of bytes [' in:\n{output}")
    return bytes.fromhex("".join(hex_tokens))


class DbusMonitorSignalParser:
    """Strict line-by-line parser for `dbus-monitor --system` signal blocks."""

    def __init__(self) -> None:
        self._state: str = "IDLE"
        self._cur_iface: str = ""
        self._cur_member: str = ""
        self._hex_tokens: list[str] = []

    def feed_line(self, raw_line: str) -> tuple[str, str, bytes] | None:
        line = raw_line.rstrip("\r\n")
        if not line.strip():
            return None

        if not line[0].isspace():
            if self._state in (
                "WAIT_ARRAY_OPEN",
                "WAIT_EMPTY_ARRAY_CLOSE",
                "IN_ARRAY",
                "WAIT_DBUS_NAME_STRING",
            ):
                raise ValueError(
                    f"dbus-monitor signal {self._cur_iface}.{self._cur_member} ended "
                    f"before body completed (state={self._state}, next line: {line!r})"
                )
            if not line.startswith("signal "):
                raise ValueError(f"Unexpected top-level dbus-monitor line: {line!r}")
            m = _DBUS_SIGNAL_HEADER_RE.match(line)
            if not m:
                raise ValueError(f"Malformed dbus-monitor signal header: {line!r}")
            _path, iface, member = m.group(1), m.group(2), m.group(3)
            if iface == "org.freedesktop.DBus" and member in ("NameAcquired", "NameLost"):
                self._state = "WAIT_DBUS_NAME_STRING"
                self._cur_iface = iface
                self._cur_member = member
                self._hex_tokens = []
                return None
            if (iface, member) not in MONITORED_DBUS_SIGNALS:
                raise ValueError(
                    f"Unexpected D-Bus signal {iface}.{member} on dbus-monitor stream: {line!r}"
                )
            self._state = "WAIT_ARRAY_OPEN"
            self._cur_iface = iface
            self._cur_member = member
            self._hex_tokens = []
            return None

        # Indented body line
        ctx = f"dbus-monitor({self._cur_iface}.{self._cur_member})"
        if self._state == "IDLE":
            raise ValueError(f"Indented dbus-monitor line before any signal header: {line!r}")
        if self._state == "AFTER_ARRAY":
            raise ValueError(
                f"{ctx}: unexpected extra body line after signal body completed: {line!r}"
            )
        if self._state == "WAIT_DBUS_NAME_STRING":
            m_name = re.match(r'^   string "(:[^"]+)"$', line)
            if not m_name:
                raise ValueError(
                    f"{ctx}: expected '   string \":1.xxx\"' body line, got {line!r}"
                )
            self._state = "AFTER_ARRAY"
            return (
                self._cur_iface,
                self._cur_member,
                m_name.group(1).encode("utf-8"),
            )
        if self._state == "WAIT_ARRAY_OPEN":
            if line == "   array [":
                self._state = "WAIT_EMPTY_ARRAY_CLOSE"
                return None
            if not line.startswith("   array of bytes ["):
                raise ValueError(
                    f"{ctx}: expected '   array of bytes [' (or empty '   array ['), got {line!r}"
                )
            after_open = line.split("[", 1)[1]
            if "]" in after_open:
                before_close, after_close = after_open.split("]", 1)
                if after_close.strip():
                    raise ValueError(
                        f"{ctx}: unexpected trailing text after ']': {line!r}"
                    )
                self._hex_tokens.extend(
                    _parse_hex_byte_tokens(before_close.split(), ctx, line)
                )
                self._state = "AFTER_ARRAY"
                return (
                    self._cur_iface,
                    self._cur_member,
                    bytes.fromhex("".join(self._hex_tokens)),
                )
            self._hex_tokens.extend(_parse_hex_byte_tokens(after_open.split(), ctx, line))
            self._state = "IN_ARRAY"
            return None

        if self._state == "WAIT_EMPTY_ARRAY_CLOSE":
            if line != "   ]":
                raise ValueError(
                    f"{ctx}: expected exact '   ]' closing empty '   array [', got {line!r}"
                )
            self._state = "AFTER_ARRAY"
            return (self._cur_iface, self._cur_member, b"")

        if self._state == "IN_ARRAY":
            if "]" in line:
                before_close, after_close = line.split("]", 1)
                if after_close.strip():
                    raise ValueError(
                        f"{ctx}: unexpected trailing text after ']': {line!r}"
                    )
                self._hex_tokens.extend(
                    _parse_hex_byte_tokens(before_close.split(), ctx, line)
                )
                self._state = "AFTER_ARRAY"
                return (
                    self._cur_iface,
                    self._cur_member,
                    bytes.fromhex("".join(self._hex_tokens)),
                )
            toks = line.split()
            self._hex_tokens.extend(_parse_hex_byte_tokens(toks, ctx, line))
            return None

        raise AssertionError(f"Unreachable parser state: {self._state!r}")

    def finish(self) -> None:
        if self._state in (
            "WAIT_ARRAY_OPEN",
            "WAIT_EMPTY_ARRAY_CLOSE",
            "IN_ARRAY",
            "WAIT_DBUS_NAME_STRING",
        ):
            raise ValueError(
                f"dbus-monitor stream ended mid-signal {self._cur_iface}.{self._cur_member} "
                f"(state={self._state})"
            )


def parse_rfc3339_utc(ts_str: str) -> float:
    """Strictly parses `YYYY-MM-DDTHH:MM:SS.ffffffZ` from `/var/log/messages` into epoch seconds."""
    m = re.match(
        r"^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})(?:\.(\d+))?Z$",
        ts_str.strip(),
    )
    if not m:
        raise ValueError(f"Invalid RFC3339 UTC timestamp: {ts_str!r}")
    base_sec = calendar.timegm(time.strptime(m.group(1), "%Y-%m-%dT%H:%M:%S"))
    frac = float(f"0.{m.group(2)}") if m.group(2) else 0.0
    return float(base_sec) + frac


def verify_guest_user_identity(
    uid_str: str,
    user_str: str,
    gid_str: str,
    group_str: str,
    all_groups_str: str,
    expected_username: str,
    expected_supp_groups: frozenset[str] = EXPECTED_GUEST_SUPPLEMENTARY_GROUPS,
) -> None:
    """Strictly validates guest user UID, primary group (GID 1000), and exact supplementary groups."""
    try:
        uid = int(uid_str.strip())
    except ValueError as exc:
        raise RuntimeError(f"Invalid guest UID output {uid_str!r}") from exc
    if uid != EXPECTED_GUEST_UID:
        raise RuntimeError(f"Expected guest UID {EXPECTED_GUEST_UID}, got {uid}")

    actual_user = user_str.strip()
    if actual_user != expected_username:
        raise RuntimeError(f"Expected guest username {expected_username!r}, got {actual_user!r}")

    try:
        gid = int(gid_str.strip())
    except ValueError as exc:
        raise RuntimeError(f"Invalid guest primary GID output {gid_str!r}") from exc
    if gid != EXPECTED_GUEST_GID:
        raise RuntimeError(f"Expected guest primary GID {EXPECTED_GUEST_GID}, got {gid}")

    actual_primary_group = group_str.strip()
    if actual_primary_group != expected_username:
        raise RuntimeError(
            f"Expected guest primary group {expected_username!r}, got {actual_primary_group!r}"
        )

    group_tokens = all_groups_str.strip().split()
    if expected_username not in group_tokens:
        raise RuntimeError(
            f"Primary group {expected_username!r} missing from `id -Gn` output: {all_groups_str!r}"
        )
    actual_supp = frozenset(g for g in group_tokens if g != expected_username)
    if actual_supp != expected_supp_groups:
        missing = sorted(expected_supp_groups - actual_supp)
        extra = sorted(actual_supp - expected_supp_groups)
        raise RuntimeError(
            f"Guest supplementary groups mismatch for {expected_username!r}: "
            f"expected={sorted(expected_supp_groups)}, actual={sorted(actual_supp)} "
            f"(missing={missing}, extra={extra})"
        )


def classify_initial_terminal_failure(
    initial_buffer: str,
    entries: list[TimelineEntry],
    container_started_rel_sec: float,
) -> None:
    """Allowlists ONLY the single proven slow-runner initial Terminal timeout; hard-fails everything else.

    Recovery via a fresh Terminal tab is permitted if and only if ALL hold:
      (a) `initial_buffer.strip()` equals `KNOWN_INITIAL_TERMINAL_TIMEOUT_ERROR`:
          `"Launching vmshell failed: Error starting crostini for terminal: 50 (CONTAINER_SETUP_FAILED)"`.
      (b) Host concierge/Chrome logs show the exact matching cause for that Terminal launch
          (`SetUpVmUser` call #2 after `InstallerClosed`):
            - exactly one `SetUpVmUserFailed` entry, for `call #2`, with `"SetUpUser RPC failed: Deadline Exceeded"`,
            - exactly one `SetUpBaguetteUserFailed` entry with `"Failed to set up baguette user: Deadline Exceeded"`,
            - exactly one `RestartCrostiniFailed` entry with
              `'Failed to restart Crostini with error code: 50, container: (type:6:BAGUETTE vm:"termina" container:"penguin")'`.
      (c) Using the log timestamps (`rel_sec`) of those failure entries, `SetUpVmUser` call #2 and
          all three failure log entries occurred after `InstallerClosed` and strictly before
          the validated `ContainerStarted` signal (and before `ContainerReadyLog` if present).
    """
    cleaned_buf = initial_buffer.strip()
    if cleaned_buf != KNOWN_INITIAL_TERMINAL_TIMEOUT_ERROR:
        raise RuntimeError(
            "Initial Terminal tab failed with an unrecognized or incomplete buffer "
            f"(expected exact {KNOWN_INITIAL_TERMINAL_TIMEOUT_ERROR!r}, "
            f"got {cleaned_buf!r})"
        )

    installer_closed = [e for e in entries if e.source == "ui" and e.name == "InstallerClosed"]
    if len(installer_closed) != 1:
        raise RuntimeError(
            f"Expected exactly 1 InstallerClosed entry in timeline, found {len(installer_closed)}"
        )
    ic_rel = installer_closed[0].rel_sec

    setup_calls = [e for e in entries if e.source == "concierge" and e.name == "SetUpVmUser"]
    call2_entries = [e for e in setup_calls if e.detail.startswith("call #2:")]
    if len(call2_entries) != 1:
        raise RuntimeError(
            f"Expected SetUpVmUser call #2 in concierge logs for initial Terminal launch, "
            f"found {len(call2_entries)} (all SetUpVmUser calls: {setup_calls!r})"
        )
    call2_rel = call2_entries[0].rel_sec
    if not (ic_rel <= call2_rel < container_started_rel_sec):
        raise RuntimeError(
            f"SetUpVmUser call #2 timestamp t+{call2_rel:.1f}s is not between "
            f"InstallerClosed (t+{ic_rel:.1f}s) and ContainerStarted (t+{container_started_rel_sec:.1f}s)"
        )

    setup_vm_failed = [
        e for e in entries if e.source == "concierge" and e.name == "SetUpVmUserFailed"
    ]
    if len(setup_vm_failed) != 1 or not (
        setup_vm_failed[0].detail.startswith("call #2 failed after ")
        and "SetUpUser RPC failed: Deadline Exceeded" in setup_vm_failed[0].detail
    ):
        raise RuntimeError(
            "Expected exactly 1 concierge SetUpVmUserFailed for call #2 with "
            f"'SetUpUser RPC failed: Deadline Exceeded', got: {setup_vm_failed!r}"
        )

    baguette_failed = [
        e for e in entries if e.source == "chrome" and e.name == "SetUpBaguetteUserFailed"
    ]
    if len(baguette_failed) != 1 or (
        "Failed to set up baguette user: Deadline Exceeded" not in baguette_failed[0].detail
    ):
        raise RuntimeError(
            "Expected exactly 1 chrome SetUpBaguetteUserFailed with "
            f"'Failed to set up baguette user: Deadline Exceeded', got: {baguette_failed!r}"
        )

    restart_failed = [
        e for e in entries if e.source == "chrome" and e.name == "RestartCrostiniFailed"
    ]
    expected_restart_msg = (
        'Failed to restart Crostini with error code: 50, '
        'container: (type:6:BAGUETTE vm:"termina" container:"penguin")'
    )
    if len(restart_failed) != 1 or expected_restart_msg not in restart_failed[0].detail:
        raise RuntimeError(
            f"Expected exactly 1 chrome RestartCrostiniFailed with {expected_restart_msg!r}, "
            f"got: {restart_failed!r}"
        )

    container_ready_logs = [
        e for e in entries if e.source == "cicerone" and e.name == "ContainerReadyLog"
    ]
    upper_bound_rel = container_started_rel_sec
    if container_ready_logs:
        upper_bound_rel = min(upper_bound_rel, container_ready_logs[0].rel_sec)

    for fail_entry in (setup_vm_failed[0], baguette_failed[0], restart_failed[0]):
        if not (ic_rel <= fail_entry.rel_sec < upper_bound_rel):
            raise RuntimeError(
                f"Failure log {fail_entry.name} at t+{fail_entry.rel_sec:.1f}s did not occur "
                f"between InstallerClosed (t+{ic_rel:.1f}s) and container readiness "
                f"(t+{upper_bound_rel:.1f}s / ContainerStarted t+{container_started_rel_sec:.1f}s): "
                f"{fail_entry!r}"
            )


def run_self_test(readme_path: Path = DEFAULT_README_PATH) -> None:
    """Fast offline unit test verifying README extraction, vendored protos, and strict D-Bus parsers."""
    log(f"Running offline self-test against {readme_path} and {DEFAULT_PROTO_DIR}...")
    cmds = extract_readme_commands(readme_path)
    assert cmds.termina_create.startswith("vmc create "), cmds.termina_create
    assert cmds.termina_create.endswith(" termina"), cmds.termina_create
    assert cmds.termina_reentry_vsh == "vsh termina penguin", cmds.termina_reentry_vsh

    # 1. Verify vendored .proto SHA-256 digests against metadata.json and compile via protoc
    protos = load_cros_protos(DEFAULT_PROTO_DIR)
    meta = protos.metadata
    conc = protos.concierge_pb2
    cic = protos.cicerone_pb2

    # Verify negative case: tampered vendored .proto file must fail verify_vendored_protos
    with tempfile.TemporaryDirectory() as tmp_pdir:
        shutil.copytree(DEFAULT_PROTO_DIR, Path(tmp_pdir) / "protos")
        tampered = Path(tmp_pdir) / "protos/arc/arc.proto"
        tampered.write_text(tampered.read_text(encoding="utf-8") + "\n// tampered\n", encoding="utf-8")
        try:
            verify_vendored_protos(Path(tmp_pdir) / "protos")
        except RuntimeError:
            pass
        else:
            raise AssertionError("Expected RuntimeError when a vendored .proto file is modified")

    # 2. Verify /etc/lsb-release matching against metadata.json (positive + negative)
    pinned_board = str(meta["board"])
    pinned_release = str(meta["cros_release"])
    pinned_milestone, pinned_version = parse_cros_release_str(pinned_release)
    wrong_milestone = str(int(pinned_milestone) - 1)
    wrong_version = "0.0.0"
    wrong_release = f"R{wrong_milestone}-{wrong_version}"
    good_lsb = (
        f"CHROMEOS_RELEASE_BUILDER_PATH={pinned_board}/{pinned_release}\n"
        f"CHROMEOS_RELEASE_CHROME_MILESTONE={pinned_milestone}\n"
        f"CHROMEOS_RELEASE_VERSION={pinned_version}\n"
    )
    verify_lsb_release_matches_metadata(good_lsb, meta)
    for bad_lsb in (
        f"CHROMEOS_RELEASE_BUILDER_PATH={pinned_board}/{wrong_release}\n"
        f"CHROMEOS_RELEASE_CHROME_MILESTONE={wrong_milestone}\n"
        f"CHROMEOS_RELEASE_VERSION={wrong_version}\n",
        f"CHROMEOS_RELEASE_BUILDER_PATH={pinned_board}/{pinned_release}\n"
        f"CHROMEOS_RELEASE_CHROME_MILESTONE={wrong_milestone}\n"
        f"CHROMEOS_RELEASE_VERSION={pinned_version}\n",
        f"CHROMEOS_RELEASE_BUILDER_PATH={pinned_board}-other/{pinned_release}\n"
        f"CHROMEOS_RELEASE_CHROME_MILESTONE={pinned_milestone}\n"
        f"CHROMEOS_RELEASE_VERSION={pinned_version}\n",
    ):
        try:
            verify_lsb_release_matches_metadata(bad_lsb, meta)
        except RuntimeError:
            pass
        else:
            raise AssertionError(f"Expected RuntimeError on mismatched lsb-release: {bad_lsb!r}")

    # 3. Round-trip real captured D-Bus payloads through DbusMonitorSignalParser,
    #    parse_dbus_send_byte_array, and InitTimelineRecorder signal validation
    sample_owner = "483c91bbeb9f2f163f30c8dea260f4d8d1c87b4f"
    real_get_vm_info_reply = (
        "method return time=1793376373.228710 sender=:1.175 -> destination=:1.197 serial=91 reply_serial=2\n"
        "   array of bytes [\n"
        "      08 01 12 0f 0d 64 73 5c 1a 10 18 18 20 20 01 30 06 40 01\n"
        "   ]\n"
    )
    raw_vm_info = parse_dbus_send_byte_array(real_get_vm_info_reply, "test GetVmInfo")
    vm_info_resp = parse_and_validate_proto(raw_vm_info, conc.GetVmInfoResponse, "test GetVmInfo")
    assert vm_info_resp.success is True
    assert vm_info_resp.vm_info.pid == 24
    assert vm_info_resp.vm_info.cid == 32
    assert conc.VmInfo.VmType.Name(vm_info_resp.vm_info.vm_type) == "BAGUETTE"
    assert conc.VmStatus.Name(vm_info_resp.vm_info.status) == "VM_STATUS_RUNNING"

    # 3b. Verify empty byte-array (`   array [\n   ]`) parsing for both dbus-send and dbus-monitor
    empty_list_containers_reply = (
        "method return time=1793443903.001918 sender=:1.179 -> destination=:1.213 serial=105 reply_serial=2\n"
        "   array [\n"
        "   ]\n"
    )
    raw_empty_lc = parse_dbus_send_byte_array(
        empty_list_containers_reply, "test empty ListRunningContainers"
    )
    assert raw_empty_lc == b"", raw_empty_lc
    empty_lc_resp = parse_and_validate_proto(
        raw_empty_lc, cic.ListRunningContainersResponse, "test empty ListRunningContainers"
    )
    assert list(empty_lc_resp.containers) == []

    empty_sig_parser = DbusMonitorSignalParser()
    assert (
        empty_sig_parser.feed_line(
            "signal time=1793443903.001918 sender=:1.179 -> destination=(null destination) "
            "serial=42 path=/org/chromium/VmCicerone; interface=org.chromium.VmCicerone; member=PendingAppListUpdates"
        )
        is None
    )
    assert empty_sig_parser.feed_line("   array [") is None
    ev_empty = empty_sig_parser.feed_line("   ]")
    empty_sig_parser.finish()
    assert ev_empty == ("org.chromium.VmCicerone", "PendingAppListUpdates", b"")

    # Build real signal stream (NameAcquired + VmStartingUpSignal + VmStartedSignal + ContainerStarted + PendingAppListUpdates)
    sig_starting = conc.VmStartingUpSignal(
        name="termina",
        owner_id=sample_owner,
        vm_type=conc.VmInfo.VmType.BAGUETTE,
        cid=32,
    ).SerializeToString()
    sig_started = conc.VmStartedSignal(
        name="termina",
        owner_id=sample_owner,
        vm_info=vm_info_resp.vm_info,
        status=conc.VmStatus.VM_STATUS_RUNNING,
    ).SerializeToString()
    sig_container = cic.ContainerStartedSignal(
        vm_name="termina",
        container_name="penguin",
        owner_id=sample_owner,
        container_username="terminauser",
        container_homedir="/home/terminauser",
        sftp_vsock_port=4201566639,
        container_token="9aa4fe0f-1346-4bdb-ac9c-62c9e9444f0e",
    ).SerializeToString()
    sig_applist = cic.PendingAppListUpdatesSignal(
        vm_name="termina",
        container_name="penguin",
        count=0,
    ).SerializeToString()

    def _fmt_dbus_sig(iface: str, member: str, payload: bytes) -> str:
        hex_str = " ".join(f"{b:02x}" for b in payload)
        return (
            f"signal time=1793376347.100000 sender=:1.175 -> destination=(null destination) "
            f"serial=42 path=/org/chromium/{iface.split('.')[-1]}; interface={iface}; member={member}\n"
            f"   array of bytes [\n"
            f"      {hex_str}\n"
            f"   ]\n"
        )

    monitor_stream = (
        "signal time=1793376341.005000 sender=org.freedesktop.DBus -> destination=:1.198 "
        "serial=2 path=/org/freedesktop/DBus; interface=org.freedesktop.DBus; member=NameAcquired\n"
        '   string ":1.198"\n'
        "signal time=1793376341.006000 sender=org.freedesktop.DBus -> destination=:1.198 "
        "serial=4 path=/org/freedesktop/DBus; interface=org.freedesktop.DBus; member=NameLost\n"
        '   string ":1.198"\n'
        + _fmt_dbus_sig("org.chromium.VmConcierge", "VmStartingUpSignal", sig_starting)
        + _fmt_dbus_sig("org.chromium.VmConcierge", "VmStartedSignal", sig_started)
        + _fmt_dbus_sig("org.chromium.VmCicerone", "ContainerStarted", sig_container)
        + _fmt_dbus_sig("org.chromium.VmCicerone", "PendingAppListUpdates", sig_applist)
    )
    mon_parser = DbusMonitorSignalParser()
    rec = InitTimelineRecorder(None, sample_owner, expected_username="terminauser")  # type: ignore[arg-type]
    rec.t_install_mono = time.monotonic()
    parsed_events: list[tuple[str, str]] = []
    for ln in monitor_stream.splitlines():
        ev = mon_parser.feed_line(ln)
        if ev is not None:
            iface, member, raw_bytes = ev
            rec._handle_dbus_signal(iface, member, raw_bytes)
            parsed_events.append((iface, member))
    mon_parser.finish()
    assert len(parsed_events) == 6, parsed_events
    assert rec.monitor_unique_name == ":1.198"
    assert rec._monitor_subscribed_event.is_set() is True
    assert rec.is_container_started() is True
    rec.verify_required_dbus_signal_sequence()

    # Negative signal sequence checks (missing or out-of-order signals must fail)
    for bad_seq_entries in (
        [
            TimelineEntry(1.0, "dbus", "VmStartedSignal", "vm='termina'"),
            TimelineEntry(2.0, "dbus", "ContainerStarted", "vm='termina' container='penguin'"),
        ],
        [
            TimelineEntry(2.0, "dbus", "VmStartedSignal", "vm='termina'"),
            TimelineEntry(1.0, "dbus", "VmStartingUpSignal", "vm='termina'"),
            TimelineEntry(3.0, "dbus", "ContainerStarted", "vm='termina' container='penguin'"),
        ],
    ):
        bad_seq_rec = InitTimelineRecorder(None, sample_owner, expected_username="terminauser")  # type: ignore[arg-type]
        bad_seq_rec._entries = list(bad_seq_entries)
        try:
            bad_seq_rec.verify_required_dbus_signal_sequence()
        except RuntimeError:
            pass
        else:
            raise AssertionError(f"Expected RuntimeError on invalid signal sequence: {bad_seq_entries!r}")

    # 4. Verify negative cases for protobuf & D-Bus text parsers (must abort aggressively)
    for bad_payload_desc, bad_fn in [
        (
            "truncated wire bytes",
            lambda: parse_and_validate_proto(sig_container[:-1], cic.ContainerStartedSignal, "trunc"),
        ),
        (
            "unknown wire field tag",
            lambda: parse_and_validate_proto(
                sig_container + b"\xf8\x0f\x01", cic.ContainerStartedSignal, "unk"
            ),
        ),
        (
            "wrong message type bytes (GetVmInfoResponse decoded as ContainerStartedSignal)",
            lambda: parse_and_validate_proto(raw_vm_info, cic.ContainerStartedSignal, "wrong_type"),
        ),
        (
            "missing required container_username in ContainerStarted",
            lambda: rec._handle_dbus_signal(
                "org.chromium.VmCicerone",
                "ContainerStarted",
                cic.ContainerStartedSignal(
                    vm_name="termina", container_name="penguin", owner_id=sample_owner
                ).SerializeToString(),
            ),
        ),
        (
            "unknown enum value in VmStartedSignal",
            lambda: require_enum_name(conc.VmStatus, 999, "status", "enum_test", b"\x20\xe7\x07"),
        ),
        (
            "malformed dbus-send output (missing method return)",
            lambda: parse_dbus_send_byte_array("   array of bytes [\n      08 01\n   ]\n", "bad_send"),
        ),
        (
            "malformed dbus-send output (non-hex byte token)",
            lambda: parse_dbus_send_byte_array(
                "method return time=1.0 sender=:1.1 -> destination=:1.2 serial=1 reply_serial=1\n"
                "   array of bytes [\n      08 zz\n   ]\n",
                "bad_hex",
            ),
        ),
        (
            "malformed dbus-monitor signal (unclosed array of bytes)",
            lambda: [
                DbusMonitorSignalParser().feed_line(x)
                for x in (
                    "signal time=1.0 sender=:1.1 -> destination=(null destination) serial=1 "
                    "path=/org/chromium/VmCicerone; interface=org.chromium.VmCicerone; member=ContainerStarted",
                    "   array of bytes [",
                    "      0a 07",
                    "signal time=2.0 sender=:1.1 -> destination=(null destination) serial=2 "
                    "path=/org/chromium/VmCicerone; interface=org.chromium.VmCicerone; member=ContainerStarted",
                )
            ],
        ),
        (
            "unexpected D-Bus signal member on dbus-monitor",
            lambda: DbusMonitorSignalParser().feed_line(
                "signal time=1.0 sender=:1.1 -> destination=(null destination) serial=1 "
                "path=/org/chromium/VmCicerone; interface=org.chromium.VmCicerone; member=BogusSignal"
            ),
        ),
        (
            "malformed dbus-send non-empty generic array [ 08 ]",
            lambda: parse_dbus_send_byte_array(
                "method return time=1.0 sender=:1.1 -> destination=:1.2 serial=1 reply_serial=1\n"
                "   array [ 08 ]\n",
                "bad_generic_array_inline",
            ),
        ),
        (
            "malformed dbus-send non-empty generic array [\\n 08 \\n]",
            lambda: parse_dbus_send_byte_array(
                "method return time=1.0 sender=:1.1 -> destination=:1.2 serial=1 reply_serial=1\n"
                "   array [\n      08\n   ]\n",
                "bad_generic_array_multiline",
            ),
        ),
        (
            "malformed dbus-send unclosed empty array [",
            lambda: parse_dbus_send_byte_array(
                "method return time=1.0 sender=:1.1 -> destination=:1.2 serial=1 reply_serial=1\n"
                "   array [\n",
                "bad_unclosed_empty_array",
            ),
        ),
        (
            "malformed dbus-monitor non-empty generic array [\\n 08 \\n]",
            lambda: [
                p.feed_line(x)
                for p in (DbusMonitorSignalParser(),)
                for x in (
                    "signal time=1.0 sender=:1.1 -> destination=(null destination) serial=1 "
                    "path=/org/chromium/VmCicerone; interface=org.chromium.VmCicerone; member=PendingAppListUpdates",
                    "   array [",
                    "      08",
                    "   ]",
                )
            ],
        ),
        (
            "malformed dbus-monitor unclosed empty array [",
            lambda: (
                lambda p: (
                    p.feed_line(
                        "signal time=1.0 sender=:1.1 -> destination=(null destination) serial=1 "
                        "path=/org/chromium/VmCicerone; interface=org.chromium.VmCicerone; member=PendingAppListUpdates"
                    ),
                    p.feed_line("   array ["),
                    p.finish(),
                )
            )(DbusMonitorSignalParser()),
        ),
    ]:
        try:
            bad_fn()
        except ValueError:
            pass
        else:
            raise AssertionError(f"Expected ValueError on negative test: {bad_payload_desc}")

    assert parse_rfc3339_utc("2026-10-30T16:01:34.115657Z") > 0

    # 5. Unit-test classify_initial_terminal_failure with real CI run-2 evidence + negative variants
    ci_run2_entries = [
        TimelineEntry(0.0, "ui", "InstallClicked", "user='terminauser'"),
        TimelineEntry(51.8, "concierge", "SetUpVmUser", "call #1: Received request: SetUpVmUser"),
        TimelineEntry(57.2, "concierge", "SetUpVmUserDone", "call #1 completed in <=5.3s"),
        TimelineEntry(
            106.4,
            "ui",
            "InstallerClosed",
            "closed after 106.1s (last_progress='Configuring the Linux container. This might take up to 30 minutes.')",
        ),
        TimelineEntry(126.5, "concierge", "SetUpVmUser", "call #2: Received request: SetUpVmUser"),
        TimelineEntry(
            146.5,
            "concierge",
            "SetUpVmUserFailed",
            "call #2 failed after 20.0s: SetUpUser RPC failed: Deadline Exceeded",
        ),
        TimelineEntry(
            146.5,
            "chrome",
            "SetUpBaguetteUserFailed",
            "[chrome/browser/ash/crostini/crostini_manager.cc:3030] Failed to set up baguette user: Deadline Exceeded",
        ),
        TimelineEntry(
            146.5,
            "chrome",
            "RestartCrostiniFailed",
            '[chrome/browser/ash/crostini/crostini_manager.cc:1067] Failed to restart Crostini with error code: 50, container: (type:6:BAGUETTE vm:"termina" container:"penguin")',
        ),
        TimelineEntry(
            149.3,
            "cicerone",
            "ContainerReadyLog",
            "Startup of container penguin at IP  for VM termina completed.",
        ),
        TimelineEntry(
            150.0,
            "dbus",
            "ContainerStarted",
            "vm='termina' container='penguin' user='terminauser' homedir='/home/terminauser'",
        ),
    ]
    classify_initial_terminal_failure(
        KNOWN_INITIAL_TERMINAL_TIMEOUT_ERROR,
        ci_run2_entries,
        container_started_rel_sec=150.0,
    )

    for neg_desc, neg_buf, neg_entries, neg_cs_rel in [
        (
            "different terminal error code",
            "Launching vmshell failed: Error starting crostini for terminal: 22 (CONTAINER_START_FAILED)",
            ci_run2_entries,
            150.0,
        ),
        (
            "progress bar timeout without error 50",
            "[=========\\ ] Configuring the Linux container",
            ci_run2_entries,
            150.0,
        ),
        (
            "failure occurred after ContainerStarted",
            KNOWN_INITIAL_TERMINAL_TIMEOUT_ERROR,
            ci_run2_entries,
            140.0,
        ),
        (
            "missing log correlation (no RestartCrostiniFailed)",
            KNOWN_INITIAL_TERMINAL_TIMEOUT_ERROR,
            [e for e in ci_run2_entries if e.name != "RestartCrostiniFailed"],
            150.0,
        ),
        (
            "multiple candidate RestartCrostiniFailed entries",
            KNOWN_INITIAL_TERMINAL_TIMEOUT_ERROR,
            [
                *ci_run2_entries,
                TimelineEntry(
                    147.0,
                    "chrome",
                    "RestartCrostiniFailed",
                    'Failed to restart Crostini with error code: 50, container: (type:6:BAGUETTE vm:"termina" container:"penguin")',
                ),
            ],
            150.0,
        ),
    ]:
        try:
            classify_initial_terminal_failure(neg_buf, neg_entries, neg_cs_rel)
        except RuntimeError:
            pass
        else:
            raise AssertionError(f"Expected RuntimeError for negative classifier test: {neg_desc}")

    # 6. Unit-test verify_guest_user_identity (positive + negative cases)
    good_groups_str = "terminauser audio cdrom dialout disk floppy kvm netdev sudo tss video"
    verify_guest_user_identity(
        "1000", "terminauser", "1000", "terminauser", good_groups_str, "terminauser"
    )
    for bad_id_desc, bad_id_args in [
        ("wrong UID", ("1001", "terminauser", "1000", "terminauser", good_groups_str, "terminauser")),
        ("wrong GID", ("1000", "terminauser", "1001", "terminauser", good_groups_str, "terminauser")),
        ("wrong primary group", ("1000", "terminauser", "1000", "users", good_groups_str, "terminauser")),
        (
            "missing supplementary group (kvm)",
            (
                "1000",
                "terminauser",
                "1000",
                "terminauser",
                "terminauser audio cdrom dialout disk floppy netdev sudo tss video",
                "terminauser",
            ),
        ),
        (
            "extra supplementary group (plugdev)",
            (
                "1000",
                "terminauser",
                "1000",
                "terminauser",
                good_groups_str + " plugdev",
                "terminauser",
            ),
        ),
    ]:
        try:
            verify_guest_user_identity(*bad_id_args)
        except RuntimeError:
            pass
        else:
            raise AssertionError(f"Expected RuntimeError for guest identity check: {bad_id_desc}")

    # 7. Verify guest boot diagnostic parser and monotonic clock timeline anchoring
    dummy_rec = InitTimelineRecorder(None, "deadbeef")  # type: ignore[arg-type]
    dummy_rec.t_install_vm_epoch = 1000.0
    sample_guest_diag = (
        "===GUEST_CLOCK_SYNC===\n"
        "uptime_sec=30.00\n"
        "epoch_sec=1030.500000000\n"
        "===GUEST_STAT_MTIMES===\n"
        "/etc/passwd|1016|1970-01-01 00:16:56.250000000 +0000|uid=0 gid=0 mode=644\n"
        "/home/terminauser|1017|1970-01-01 00:16:57.500000000 +0000|uid=1000 gid=1000 mode=700\n"
        "/var/lib/systemd/linger/terminauser|1018|1970-01-01 00:16:58.750000000 +0000|uid=0 gid=0 mode=644\n"
        "===GUEST_LIST_JOBS===\n"
        "No jobs running.\n"
        "===GUEST_SYSTEMD_UNIT_SHOW===\n"
        "Id=first-boot-cros.service\n"
        "ActiveState=inactive\n"
        "SubState=dead\n"
        "Result=success\n"
        "InactiveExitTimestampMonotonic=12400000\n"
        "ActiveEnterTimestampMonotonic=28400000\n"
        "ExecMainStartTimestampMonotonic=12450000\n"
        "ExecMainExitTimestampMonotonic=28390000\n"
        "ExecMainStatus=0\n"
        "\n"
        "Id=maitred.service\n"
        "ActiveState=active\n"
        "SubState=running\n"
        "Result=success\n"
        "InactiveExitTimestampMonotonic=12420000\n"
        "ActiveEnterTimestampMonotonic=12500000\n"
        "ExecMainStartTimestampMonotonic=12480000\n"
        "ExecMainExitTimestampMonotonic=0\n"
        "ExecMainStatus=0\n"
        "===GUEST_ANALYZE===\n"
        "Startup finished in 1.2s (kernel) + 1.5s (userspace) = 2.7s\n"
        "===GUEST_CRITICAL_CHAIN===\n"
        "multi-user.target @1.5s\n"
        "===GUEST_BLAME===\n"
        "1.0s first-boot-cros.service\n"
        "===GUEST_USER_ANALYZE===\n"
        "Startup finished in 0.5s (userspace)\n"
        "===GUEST_USER_CRITICAL_CHAIN===\n"
        "default.target @0.5s\n"
        "===GUEST_USER_BLAME===\n"
        "0.2s cros-garcon.service\n"
        "===GUEST_GARCON_STATUS===\n"
        "Active: active (running)\n"
        "===GUEST_JOURNAL_MONO===\n"
        "[   12.500000] VM systemd[1]: Started maitred.\n"
        "===GUEST_JOURNAL_JSON===\n"
        + json.dumps(
            {
                "_COMM": "systemd",
                "MESSAGE": "Started maitred.",
                "__MONOTONIC_TIMESTAMP": "12500000",
                "__REALTIME_TIMESTAMP": "1010000000",
            }
        )
        + "\n"
        + json.dumps(
            {
                "SYSLOG_IDENTIFIER": "maitred",
                "MESSAGE": "Received request to setup a new user.",
                "__MONOTONIC_TIMESTAMP": "13500000",
                "__REALTIME_TIMESTAMP": "1011000000",
            }
        )
        + "\n"
        + json.dumps(
            {
                "SYSLOG_IDENTIFIER": "useradd",
                "MESSAGE": "new user: name=terminauser, UID=1000, GID=1000, home=/home/terminauser, shell=/bin/bash, from=none",
                "__MONOTONIC_TIMESTAMP": "15500000",
                "__REALTIME_TIMESTAMP": "1013000000",
            }
        )
        + "\n"
        + json.dumps(
            {
                "SYSLOG_IDENTIFIER": "garcon",
                "MESSAGE": "Server listening on vsock port",
                "__MONOTONIC_TIMESTAMP": "19500000",
                "__REALTIME_TIMESTAMP": "1020000000",
            }
        )
        + "\n"
    )
    dummy_rec._parse_guest_diagnostics(sample_guest_diag, first_host_setup_user_rel=14.0, strict=True)
    assert any("Startup finished" in ln for ln in dummy_rec.guest_summary_lines)
    assert any("first-boot-cros.service:" in ln for ln in dummy_rec.guest_summary_lines)
    by_name = {e.name: e for e in dummy_rec.all_entries()}
    assert abs(by_name["MaitredStarted"].rel_sec - 13.0) < 1e-3, by_name["MaitredStarted"]
    assert abs(by_name["MaitredSetUpUser"].rel_sec - 14.0) < 1e-3, by_name["MaitredSetUpUser"]
    assert abs(by_name["UseraddDone"].rel_sec - 16.0) < 1e-3, by_name["UseraddDone"]
    assert abs(by_name["GarconLog"].rel_sec - 20.0) < 1e-3, by_name["GarconLog"]
    mtime_entries = [e for e in dummy_rec.all_entries() if e.name == "GuestFileMtime"]
    assert len(mtime_entries) == 3, mtime_entries

    # Also verify non-strict guest diagnostics parsing when user session hasn't started yet
    partial_rec = InitTimelineRecorder(None, "deadbeef")  # type: ignore[arg-type]
    partial_rec.t_install_vm_epoch = 1000.0
    partial_rec._parse_guest_diagnostics(
        "===GUEST_CLOCK_SYNC===\nuptime_sec=20.0\nepoch_sec=1025.0\n"
        "===GUEST_JOURNAL_MONO===\n[ 10.000000] VM systemd[1]: Starting First boot script...\n",
        first_host_setup_user_rel=None,
        strict=False,
    )
    assert any("Starting First boot script" in ln for ln in partial_rec.guest_summary_lines)

    # Verify negative cases (missing section or missing code blocks)
    with tempfile.TemporaryDirectory() as tmp:
        bad_readme = Path(tmp) / "README.md"
        bad_readme.write_text("# Empty\n", encoding="utf-8")
        try:
            extract_readme_commands(bad_readme)
        except ValueError:
            pass
        else:
            raise AssertionError("Expected ValueError on README missing '### Setup:' section")

        bad_readme.write_text(
            "### Setup: Test\n```sh\nvmc create --vm-type BAGUETTE termina\n```\n",
            encoding="utf-8",
        )
        try:
            extract_readme_commands(bad_readme)
        except ValueError:
            pass
        else:
            raise AssertionError("Expected ValueError when second code block is missing")

    log(
        "Self-test passed! Extracted README commands:\n"
        f"  Setup create:       {cmds.termina_create}\n"
        f"  Setup vsh re-entry: {cmds.termina_reentry_vsh}"
    )


def find_free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


def find_sbin_tool(name: str) -> str:
    found = shutil.which(name, path=f"{os.environ.get('PATH', '')}:/usr/sbin:/sbin")
    if not found:
        raise FileNotFoundError(f"Required host binary '{name}' not found in PATH or /usr/sbin")
    return found


def detect_host_qemu_cpu_arg() -> str:
    """Selects QEMU -cpu model matching chromite/lib/vm.py for Intel vs AMD KVM hosts."""
    cpuinfo = Path("/proc/cpuinfo").read_text(encoding="utf-8")
    if "AuthenticAMD" in cpuinfo:
        return "Opteron_G4,-invpcid,-tsc-deadline,check,svm=on"
    if "GenuineIntel" in cpuinfo:
        return "Haswell-noTSX,-invpcid,-tsc-deadline,check,vmx=on"
    raise RuntimeError("Unsupported host CPU vendor in /proc/cpuinfo (expected GenuineIntel or AuthenticAMD)")


def default_vm_ram_gb() -> int:
    """Clamps default VM RAM between 4 GiB and 8 GiB based on host MemAvailable."""
    meminfo = Path("/proc/meminfo").read_text(encoding="utf-8")
    for line in meminfo.splitlines():
        if line.startswith("MemAvailable:"):
            avail_kib = int(line.split()[1])
            avail_gib = avail_kib // (1024 * 1024)
            return min(8, max(4, avail_gib - 2))
    raise RuntimeError("MemAvailable entry not found in /proc/meminfo")


def assert_host_kvm_available() -> None:
    kvm_path = Path("/dev/kvm")
    if not kvm_path.exists():
        raise RuntimeError("/dev/kvm does not exist on the host; KVM is required for nested VM tests")
    if not os.access(kvm_path, os.R_OK | os.W_OK):
        raise RuntimeError("/dev/kvm is not readable/writable by the current user (try `sudo chmod 0666 /dev/kvm`)")


def ensure_testing_rsa(cache_dir: Path) -> Path:
    key_path = cache_dir / "testing_rsa"
    if not key_path.exists():
        log(f"Downloading public ChromeOS testing_rsa key to {key_path}...")
        cache_dir.mkdir(parents=True, exist_ok=True)
        with urllib.request.urlopen(TESTING_RSA_GITILES_URL, timeout=30) as resp:
            raw_b64 = resp.read()
        key_path.write_bytes(base64.b64decode(raw_b64))
    key_path.chmod(0o600)
    return key_path


def ensure_cros_image(cache_dir: Path, meta: dict[str, Any]) -> Path:
    board = str(meta["board"])
    cros_release = str(meta["cros_release"])
    img_dir = cache_dir / f"{board}-{cros_release}"
    img_path = img_dir / "chromiumos_test_image.bin"
    if img_path.exists():
        log(f"Using cached ChromeOS image: {img_path}")
        return img_path

    img_dir.mkdir(parents=True, exist_ok=True)
    url = f"{GCS_ARCHIVE_ROOT}/{board}/{cros_release}/chromiumos_test_image.tar.xz"
    log(f"Stream-extracting {url} into {img_dir} (sparse)...")
    cmd = f"curl -fL --retry 3 '{url}' | tar --sparse -xJ -C '{img_dir}'"
    subprocess.run(["bash", "-o", "pipefail", "-c", cmd], check=True)
    if not img_path.exists():
        raise FileNotFoundError(f"Expected {img_path} after extracting {url}")
    return img_path


class CDPConnection:
    """Thin synchronous Chrome DevTools Protocol client over `websocket-client`."""

    def __init__(self, ws_url: str, timeout: float = 30.0) -> None:
        import websocket  # Imported lazily so `--self-test` can run even before venv setup if needed

        self.ws = websocket.create_connection(ws_url, timeout=timeout, suppress_origin=True)
        self._next_id = 0
        self.events: list[dict] = []

    def call(
        self,
        method: str,
        params: dict | None = None,
        timeout: float = 30.0,
        allow_error: bool = False,
    ) -> dict:
        self._next_id += 1
        req_id = self._next_id
        self.ws.settimeout(timeout)
        self.ws.send(json.dumps({"id": req_id, "method": method, "params": params or {}}))
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            raw = self.ws.recv()
            if not raw:
                continue
            msg = json.loads(raw)
            if msg.get("id") == req_id:
                if "error" in msg and not allow_error:
                    raise RuntimeError(f"CDP {method} error: {msg['error']}")
                return msg.get("result", msg)
            self.events.append(msg)
        raise TimeoutError(f"Timed out waiting for CDP response to {method} (id={req_id})")

    def eval_js(self, expression: str, await_promise: bool = False, timeout: float = 30.0):
        res = self.call(
            "Runtime.evaluate",
            {
                "expression": expression,
                "returnByValue": True,
                "awaitPromise": await_promise,
            },
            timeout=timeout,
        )
        if "exceptionDetails" in res:
            raise RuntimeError(f"JS exception: {res['exceptionDetails']}")
        return res.get("result", {}).get("value")

    def close(self) -> None:
        try:
            self.ws.close()
        except Exception:
            pass


class CroshTab:
    """Drives a `chrome-untrusted://crosh/` or `chrome-untrusted://terminal/` tab via CDP."""

    def __init__(self, label: str, conn: CDPConnection) -> None:
        self.label = label
        self.conn = conn

    def get_text(self) -> str:
        js = """(() => {
            if (!window.term_ || !window.term_.term || !window.term_.term.buffer) return '';
            const buf = window.term_.term.buffer.active;
            const lines = [];
            for (let i = 0; i < buf.length; i++) {
                const line = buf.getLine(i);
                if (line) lines.push(line.translateToString(true));
            }
            while (lines.length && lines[lines.length - 1] === '') lines.pop();
            return lines.join('\\n');
        })()"""
        return self.conn.eval_js(js) or ""

    def send_line(self, line: str) -> None:
        """Types a command line into xterm.js and presses Enter."""
        self.conn.call("Page.bringToFront")
        # Use xterm.js's native paste() to feed the exact string through term.onData
        # -> io.onVTKeystroke -> chrome.terminalPrivate.sendInput without triggering
        # libapps terminal_emulator.js keyCode collisions on ASCII 34/36/39/45/46,
        # then dispatch a real Enter keystroke to submit the line.
        self.conn.eval_js(
            f"""(() => {{
                window.term_.term.focus();
                window.term_.term.paste({json.dumps(line)});
                return true;
            }})()"""
        )
        time.sleep(0.1)
        self.conn.call(
            "Input.dispatchKeyEvent",
            {
                "type": "rawKeyDown",
                "windowsVirtualKeyCode": 13,
                "nativeVirtualKeyCode": 13,
                "key": "Enter",
                "code": "Enter",
                "text": "\r",
                "unmodifiedText": "\r",
            },
        )
        self.conn.call(
            "Input.dispatchKeyEvent",
            {
                "type": "keyUp",
                "windowsVirtualKeyCode": 13,
                "nativeVirtualKeyCode": 13,
                "key": "Enter",
                "code": "Enter",
            },
        )

    def wait_for(self, predicate, timeout: float = 120.0, desc: str = "output") -> str:
        deadline = time.monotonic() + timeout
        last = ""
        while time.monotonic() < deadline:
            last = self.get_text()
            if predicate(last):
                return last
            time.sleep(0.5)
        raise TimeoutError(
            f"Timed out waiting for {desc} in {self.label}. Last terminal buffer:\n{last}"
        )

    def run_crosh_cmd(self, cmd: str, timeout: float = 180.0, check_no_error: bool = True) -> str:
        """Types `cmd` at a `crosh>` prompt and waits for the next `crosh>` prompt."""
        before = self.get_text()
        prev_prompts = before.count("crosh>")
        log(f"  [{self.label}] crosh> {cmd}")
        self.send_line(cmd)
        after = self.wait_for(
            lambda txt: txt.count("crosh>") > prev_prompts and txt.rstrip().endswith("crosh>"),
            timeout=timeout,
            desc=f"completion of `{cmd}`",
        )
        parts = after.split("crosh>")
        delta = parts[-2] if len(parts) >= 2 else after
        if check_no_error and ("ERROR - ERROR: command failed" in delta or "Error:" in delta):
            raise RuntimeError(
                f"Command `{cmd}` failed in {self.label}:\n{delta.strip()}"
            )
        return delta.strip()

    def close(self) -> None:
        self.conn.close()


@dataclasses.dataclass
class TimelineEntry:
    rel_sec: float
    source: str
    name: str
    detail: str


class InitTimelineRecorder:
    """Passive, side-effect-free recorder of VM/container initialization signals, logs, and UMA."""

    def __init__(
        self,
        vm: ChromeOSVM,
        owner_hash: str,
        expected_username: str = "terminauser",
        on_vm_starting_up: Callable[[], None] | None = None,
        on_vm_started: Callable[[], None] | None = None,
    ) -> None:
        self.vm = vm
        self.owner_hash = owner_hash
        self.expected_username = expected_username
        self.on_vm_starting_up = on_vm_starting_up
        self.on_vm_started = on_vm_started
        self._protos = load_cros_protos()
        self.t_install_mono: float | None = None
        self.t_install_vm_epoch: float | None = None
        self.msg_line_cursor: int = 0
        self.chrome_line_cursor: int = 0
        self._lock = threading.Lock()
        self._entries: list[TimelineEntry] = []
        self._host_log_entries: list[TimelineEntry] = []
        self._guest_log_entries: list[TimelineEntry] = []
        self._monitor_subscribed_event = threading.Event()
        self.monitor_unique_name: str = ""
        self._container_started_event = threading.Event()
        self.container_started_rel_sec: float | None = None
        self.container_started_detail: str = ""
        self._fatal_error: Exception | None = None
        self._mon_proc: subprocess.Popen[str] | None = None
        self._reader_thread: threading.Thread | None = None
        self._stderr_thread: threading.Thread | None = None
        self._stderr_lines: list[str] = []
        self._stop_requested = False
        self.readonly_summary_lines: list[str] = []
        self.guest_summary_lines: list[str] = []
        self.messages_excerpt: str = ""
        self.chrome_excerpt: str = ""

    def all_entries(self) -> list[TimelineEntry]:
        with self._lock:
            combined = self._entries + self._host_log_entries + self._guest_log_entries
        return sorted(combined, key=lambda e: e.rel_sec)

    def _get_stderr_text(self) -> str:
        with self._lock:
            return "\n".join(self._stderr_lines).strip()

    def check_no_fatal_error(self) -> None:
        with self._lock:
            err = self._fatal_error
        if err is not None:
            raise RuntimeError(
                f"Fatal D-Bus/protobuf validation error in background monitor: {err}"
            ) from err
        if self._mon_proc is not None and not self._stop_requested:
            rc = self._mon_proc.poll()
            if rc is not None:
                stderr_txt = self._get_stderr_text()
                raise RuntimeError(
                    f"dbus-monitor process exited prematurely before stop_and_collect "
                    f"(returncode={rc}, stderr={stderr_txt!r})"
                )

    def start(self) -> None:
        """Starts background `dbus-monitor --system` on the VM and waits for `NameAcquired` before `Install`."""
        self.msg_line_cursor = int(
            self.vm.ssh("wc -l < /var/log/messages").stdout.strip() or "0"
        )
        self.chrome_line_cursor = int(
            self.vm.ssh("wc -l < /var/log/chrome/chrome").stdout.strip() or "0"
        )
        match_rules = " ".join(
            f'"type=\'signal\',interface=\'{iface}\',member=\'{member}\'"'
            for iface, member in sorted(MONITORED_DBUS_SIGNALS)
        )
        remote_cmd = f"exec dbus-monitor --system {match_rules}"
        self._mon_proc = subprocess.Popen(
            [*self.vm._ssh_base_cmd(), remote_cmd],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
        )
        self._stderr_thread = threading.Thread(target=self._read_stderr_loop, daemon=True)
        self._stderr_thread.start()
        self._reader_thread = threading.Thread(target=self._read_events_loop, daemon=True)
        self._reader_thread.start()

        if not self._monitor_subscribed_event.wait(timeout=15.0):
            self.check_no_fatal_error()
            rc = self._mon_proc.poll()
            raise RuntimeError(
                "Timed out waiting for dbus-monitor org.freedesktop.DBus.NameAcquired "
                f"subscription signal (returncode={rc}, stderr={self._get_stderr_text()!r})"
            )
        self.check_no_fatal_error()
        log(
            f"  [timeline] Passive D-Bus signal monitor subscribed on system bus "
            f"(NameAcquired={self.monitor_unique_name})"
        )

    def _read_stderr_loop(self) -> None:
        assert self._mon_proc is not None and self._mon_proc.stderr is not None
        for line in self._mon_proc.stderr:
            stripped = line.rstrip("\r\n")
            if stripped:
                with self._lock:
                    self._stderr_lines.append(stripped)

    def mark_install_clicked(self, username: str) -> None:
        self.check_no_fatal_error()
        now_mono = time.monotonic()
        vm_epoch_str = self.vm.ssh("date -u +%s.%N").stdout.strip()
        with self._lock:
            self.t_install_mono = now_mono
            self.t_install_vm_epoch = float(vm_epoch_str)
            self._entries.append(
                TimelineEntry(
                    0.0,
                    "ui",
                    "InstallClicked",
                    f"Clicked Install in chrome://crostini-installer (user={username!r})",
                )
            )

    def _rel_mono(self, mono_ts: float | None = None) -> float:
        now = mono_ts if mono_ts is not None else time.monotonic()
        if self.t_install_mono is None:
            return 0.0
        return max(0.0, now - self.t_install_mono)

    def record_ui(self, name: str, detail: str) -> float:
        self.check_no_fatal_error()
        rel = self._rel_mono()
        with self._lock:
            self._entries.append(TimelineEntry(rel, "ui", name, detail))
        return rel

    def _read_events_loop(self) -> None:
        assert self._mon_proc is not None and self._mon_proc.stdout is not None
        parser = DbusMonitorSignalParser()
        try:
            for line in self._mon_proc.stdout:
                if self._stop_requested:
                    return
                ev = parser.feed_line(line)
                if ev is not None:
                    iface, member, raw_bytes = ev
                    self._handle_dbus_signal(iface, member, raw_bytes)
            if not self._stop_requested:
                parser.finish()
                try:
                    rc = self._mon_proc.wait(timeout=1.0)
                except subprocess.TimeoutExpired:
                    rc = self._mon_proc.poll()
                if self._stderr_thread is not None:
                    self._stderr_thread.join(timeout=1.0)
                raise RuntimeError(
                    "dbus-monitor stdout reached EOF prematurely before stop_and_collect "
                    f"(returncode={rc}, stderr={self._get_stderr_text()!r})"
                )
        except Exception as exc:
            with self._lock:
                if self._fatal_error is None:
                    self._fatal_error = exc
            log(f"  [timeline] FATAL error in D-Bus signal monitor: {exc}")
            self._monitor_subscribed_event.set()
            self._container_started_event.set()

    def _handle_dbus_signal(self, iface: str, member: str, raw: bytes) -> None:
        ctx = f"{iface}.{member}"
        if (iface, member) == ("org.freedesktop.DBus", "NameAcquired"):
            unique_name = raw.decode("utf-8")
            if not unique_name.startswith(":"):
                raise ValueError(f"{ctx}: invalid unique bus name {unique_name!r}")
            with self._lock:
                self.monitor_unique_name = unique_name
            return

        if (iface, member) == ("org.freedesktop.DBus", "NameLost"):
            unique_name = raw.decode("utf-8")
            with self._lock:
                expected_name = self.monitor_unique_name
            if not expected_name or unique_name != expected_name:
                raise ValueError(
                    f"{ctx}: NameLost unique bus name {unique_name!r} does not match "
                    f"NameAcquired {expected_name!r}"
                )
            self._monitor_subscribed_event.set()
            return

        conc = self._protos.concierge_pb2
        cic = self._protos.cicerone_pb2
        rel = self._rel_mono()

        if (iface, member) == ("org.chromium.VmConcierge", "VmStartingUpSignal"):
            sig = parse_and_validate_proto(raw, conc.VmStartingUpSignal, ctx)
            vm_name = require_non_empty_str(sig.name, "name", ctx, raw)
            _ = require_non_empty_str(sig.owner_id, "owner_id", ctx, raw)
            vm_type_name = require_enum_name(
                conc.VmInfo.VmType, sig.vm_type, "vm_type", ctx, raw
            )
            if sig.cid <= 0:
                raise ValueError(f"{ctx}: invalid cid={sig.cid} (hex={raw.hex()})")
            detail = f"vm={vm_name!r} vm_type={vm_type_name}({sig.vm_type}) cid={sig.cid}"
            with self._lock:
                self._entries.append(TimelineEntry(rel, "dbus", member, detail))
            if vm_name == "termina" and self.on_vm_starting_up is not None:
                self.on_vm_starting_up()
                self.on_vm_starting_up = None
            return

        if (iface, member) == ("org.chromium.VmConcierge", "VmStartedSignal"):
            sig = parse_and_validate_proto(raw, conc.VmStartedSignal, ctx)
            vm_name = require_non_empty_str(sig.name, "name", ctx, raw)
            _ = require_non_empty_str(sig.owner_id, "owner_id", ctx, raw)
            status_name = require_enum_name(conc.VmStatus, sig.status, "status", ctx, raw)
            vm_type_name = require_enum_name(
                conc.VmInfo.VmType, sig.vm_info.vm_type, "vm_info.vm_type", ctx, raw
            )
            if sig.vm_info.pid <= 0 or sig.vm_info.cid <= 0:
                raise ValueError(
                    f"{ctx}: invalid vm_info pid={sig.vm_info.pid} cid={sig.vm_info.cid} "
                    f"(hex={raw.hex()})"
                )
            detail = (
                f"vm={vm_name!r} status={status_name}({sig.status}) "
                f"vm_type={vm_type_name}({sig.vm_info.vm_type}) "
                f"pid={sig.vm_info.pid} cid={sig.vm_info.cid}"
            )
            with self._lock:
                self._entries.append(TimelineEntry(rel, "dbus", member, detail))
            if vm_name == "termina" and self.on_vm_started is not None:
                self.on_vm_started()
                self.on_vm_started = None
            return

        if (iface, member) == ("org.chromium.VmConcierge", "VmGuestUserlandReadySignal"):
            sig = parse_and_validate_proto(raw, conc.VmGuestUserlandReadySignal, ctx)
            vm_name = require_non_empty_str(sig.name, "name", ctx, raw)
            _ = require_non_empty_str(sig.owner_id, "owner_id", ctx, raw)
            detail = f"vm={vm_name!r} ready={sig.ready}"
            with self._lock:
                self._entries.append(TimelineEntry(rel, "dbus", member, detail))
            return

        if (iface, member) == ("org.chromium.VmConcierge", "VmStoppingSignal"):
            sig = parse_and_validate_proto(raw, conc.VmStoppingSignal, ctx)
            vm_name = require_non_empty_str(sig.name, "name", ctx, raw)
            _ = require_non_empty_str(sig.owner_id, "owner_id", ctx, raw)
            if sig.cid <= 0:
                raise ValueError(f"{ctx}: invalid cid={sig.cid} (hex={raw.hex()})")
            detail = f"vm={vm_name!r} cid={sig.cid}"
            with self._lock:
                self._entries.append(TimelineEntry(rel, "dbus", member, detail))
            return

        if (iface, member) == ("org.chromium.VmConcierge", "VmStoppedSignal"):
            sig = parse_and_validate_proto(raw, conc.VmStoppedSignal, ctx)
            vm_name = require_non_empty_str(sig.name, "name", ctx, raw)
            _ = require_non_empty_str(sig.owner_id, "owner_id", ctx, raw)
            reason_name = require_enum_name(
                conc.VmStopReason,
                sig.reason,
                "reason",
                ctx,
                raw,
                disallow_zero_unknown=False,
            )
            detail = f"vm={vm_name!r} cid={sig.cid} reason={reason_name}({sig.reason})"
            with self._lock:
                self._entries.append(TimelineEntry(rel, "dbus", member, detail))
            return

        if (iface, member) == ("org.chromium.VmCicerone", "ContainerStarted"):
            sig = parse_and_validate_proto(raw, cic.ContainerStartedSignal, ctx)
            vm_name = require_non_empty_str(sig.vm_name, "vm_name", ctx, raw)
            container_name = require_non_empty_str(sig.container_name, "container_name", ctx, raw)
            owner_id = require_non_empty_str(sig.owner_id, "owner_id", ctx, raw)
            user = require_non_empty_str(sig.container_username, "container_username", ctx, raw)
            homedir = require_non_empty_str(sig.container_homedir, "container_homedir", ctx, raw)
            if not homedir.startswith("/"):
                raise ValueError(
                    f"{ctx}: expected absolute container_homedir, got {homedir!r} (hex={raw.hex()})"
                )
            detail = (
                f"vm={vm_name!r} container={container_name!r} "
                f"user={user!r} homedir={homedir!r}"
            )
            with self._lock:
                self._entries.append(TimelineEntry(rel, "dbus", member, detail))
                if vm_name == "termina" and container_name == "penguin":
                    if owner_id != self.owner_hash:
                        raise ValueError(
                            f"{ctx}: owner_id mismatch: expected {self.owner_hash!r}, "
                            f"got {owner_id!r} (hex={raw.hex()})"
                        )
                    if user != self.expected_username:
                        raise ValueError(
                            f"{ctx}: container_username mismatch: expected {self.expected_username!r}, "
                            f"got {user!r} (hex={raw.hex()})"
                        )
                    self.container_started_rel_sec = rel
                    self.container_started_detail = detail
                    self._container_started_event.set()
            return

        if (iface, member) == ("org.chromium.VmCicerone", "ContainerShutdown"):
            sig = parse_and_validate_proto(raw, cic.ContainerShutdownSignal, ctx)
            vm_name = require_non_empty_str(sig.vm_name, "vm_name", ctx, raw)
            container_name = require_non_empty_str(sig.container_name, "container_name", ctx, raw)
            _ = require_non_empty_str(sig.owner_id, "owner_id", ctx, raw)
            detail = f"vm={vm_name!r} container={container_name!r}"
            with self._lock:
                self._entries.append(TimelineEntry(rel, "dbus", member, detail))
            return

        if (iface, member) == ("org.chromium.VmCicerone", "PendingAppListUpdates"):
            sig = parse_and_validate_proto(raw, cic.PendingAppListUpdatesSignal, ctx)
            vm_name = require_non_empty_str(sig.vm_name, "vm_name", ctx, raw)
            container_name = require_non_empty_str(sig.container_name, "container_name", ctx, raw)
            detail = f"vm={vm_name!r} container={container_name!r} count={sig.count}"
            with self._lock:
                self._entries.append(TimelineEntry(rel, "dbus", member, detail))
            return

        if (iface, member) == ("org.chromium.VmCicerone", "TremplinStarted"):
            sig = parse_and_validate_proto(raw, cic.TremplinStartedSignal, ctx)
            vm_name = require_non_empty_str(sig.vm_name, "vm_name", ctx, raw)
            owner_id = require_non_empty_str(sig.owner_id, "owner_id", ctx, raw)
            detail = f"vm={vm_name!r} owner_id={owner_id!r}"
            with self._lock:
                self._entries.append(TimelineEntry(rel, "dbus", member, detail))
            return

        raise ValueError(f"Unhandled D-Bus signal {ctx}")

    def verify_required_dbus_signal_sequence(self) -> None:
        """Asserts that `VmStartingUpSignal` -> `VmStartedSignal` -> `ContainerStarted` for `termina` arrived in order."""
        with self._lock:
            dbus_entries = [
                e for e in self._entries if e.source == "dbus" and "vm='termina'" in e.detail
            ]
        names_in_order = [e.name for e in dbus_entries]
        required = ("VmStartingUpSignal", "VmStartedSignal", "ContainerStarted")
        indices: list[int] = []
        for req_name in required:
            if req_name not in names_in_order:
                raise RuntimeError(
                    f"Missing required D-Bus signal {req_name!r} for 'termina' on dbus-monitor stream "
                    f"(observed: {names_in_order!r})"
                )
            indices.append(names_in_order.index(req_name))
        if not (indices[0] < indices[1] < indices[2]):
            raise RuntimeError(
                f"Required D-Bus signals for 'termina' arrived out of order: "
                f"expected {required!r}, observed {names_in_order!r}"
            )

    def is_container_started(self) -> bool:
        self.check_no_fatal_error()
        return self._container_started_event.is_set()

    def query_garcon_session_info_readonly(self) -> Any:
        """Read-only D-Bus call to `VmCicerone.GetGarconSessionInfo`."""
        cic = self._protos.cicerone_pb2
        ctx = "VmCicerone.GetGarconSessionInfo"
        req = cic.GetGarconSessionInfoRequest(
            vm_name="termina",
            container_name="penguin",
            owner_id=self.owner_hash,
        ).SerializeToString()
        res = self.vm.ssh(
            f"dbus-send --system --type=method_call --print-reply "
            f"--dest=org.chromium.VmCicerone /org/chromium/VmCicerone "
            f"org.chromium.VmCicerone.GetGarconSessionInfo {to_dbus_byte_arg(req)}",
            check=True,
            timeout=15,
        )
        raw_resp = parse_dbus_send_byte_array(res.stdout, ctx)
        resp = parse_and_validate_proto(raw_resp, cic.GetGarconSessionInfoResponse, ctx)
        require_enum_name(
            cic.GetGarconSessionInfoResponse.Status,
            resp.status,
            "status",
            ctx,
            raw_resp,
        )
        if resp.status == cic.GetGarconSessionInfoResponse.Status.SUCCEEDED:
            user = require_non_empty_str(resp.container_username, "container_username", ctx, raw_resp)
            homedir = require_non_empty_str(resp.container_homedir, "container_homedir", ctx, raw_resp)
            if user != self.expected_username:
                raise ValueError(
                    f"{ctx}: expected container_username={self.expected_username!r}, "
                    f"got {user!r} (hex={raw_resp.hex()})"
                )
            if not homedir.startswith("/"):
                raise ValueError(
                    f"{ctx}: expected absolute container_homedir, got {homedir!r} (hex={raw_resp.hex()})"
                )
        return resp

    def wait_for_container_started(self, timeout: float = 300.0) -> float:
        """Waits strictly on `dbus-monitor`'s `VmCicerone.ContainerStarted` signal and cross-checks `GetGarconSessionInfo`."""
        cic = self._protos.cicerone_pb2
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            self.check_no_fatal_error()
            if self._container_started_event.wait(timeout=1.0):
                self.check_no_fatal_error()
                assert self.container_started_rel_sec is not None
                info = self.query_garcon_session_info_readonly()
                status_name = cic.GetGarconSessionInfoResponse.Status.Name(info.status)
                if info.status != cic.GetGarconSessionInfoResponse.Status.SUCCEEDED:
                    raise RuntimeError(
                        "GetGarconSessionInfo disagreed with ContainerStarted signal: "
                        f"expected SUCCEEDED, got {status_name}({info.status})"
                    )
                if info.container_username != self.expected_username:
                    raise RuntimeError(
                        "GetGarconSessionInfo username disagreed with ContainerStarted signal: "
                        f"expected {self.expected_username!r}, got {info.container_username!r}"
                    )
                return self.container_started_rel_sec
        self.check_no_fatal_error()
        raise TimeoutError(
            f"Timed out after {timeout:.0f}s waiting for cicerone ContainerStarted(termina/penguin) signal on dbus-monitor"
        )

    def scrape_host_logs(self) -> float | None:
        """Idempotently scrapes `/var/log/messages` and `/var/log/chrome/chrome` since `start()`."""
        first_host_setup_user_rel: float | None = None
        new_host_entries: list[TimelineEntry] = []

        msg_out = self.vm.ssh(
            f"set -o pipefail; test -r /var/log/messages; "
            f"tail -n +{self.msg_line_cursor + 1} /var/log/messages | "
            f"{{ grep -E 'vm_concierge|vm_cicerone|seneschal|vshd|garcon|maitred' || [ $? -eq 1 ]; }} | "
            f"{{ grep -v 'BalloonTrace:' || [ $? -eq 1 ]; }}",
            check=True,
            timeout=30,
        ).stdout.strip()
        self.messages_excerpt = msg_out
        setup_user_seq = 0
        pending_setup_user: tuple[int, float] | None = None
        for line in msg_out.splitlines():
            parts = line.split(None, 3)
            if len(parts) < 4 or not re.match(r"^\d{4}-\d{2}-\d{2}T", parts[0]):
                continue
            epoch = parse_rfc3339_utc(parts[0])
            rel = (
                max(0.0, epoch - self.t_install_vm_epoch)
                if self.t_install_vm_epoch is not None
                else 0.0
            )
            proc_tag = parts[2]
            msg_body = parts[3]

            # Since vm_concierge is single-threaded, any subsequent vm_concierge log line
            # (or cicerone LaunchVshd) after SetUpVmUser that isn't a SetUpUser RPC error
            # marks completion of the synchronous SetUpVmUser handler on vm_concierge's thread.
            if pending_setup_user is not None:
                seq_idx, start_rel = pending_setup_user
                if "SetUpUser RPC failed:" in msg_body or "SetUpUser RPC returned an error:" in msg_body:
                    dur = max(0.0, rel - start_rel)
                    new_host_entries.append(
                        TimelineEntry(
                            rel,
                            "concierge",
                            "SetUpVmUserFailed",
                            f"call #{seq_idx} failed after {dur:.1f}s: {msg_body}",
                        )
                    )
                    pending_setup_user = None
                    continue
                elif proc_tag.startswith("vm_concierge") or "Received LaunchVshd request" in msg_body:
                    dur = max(0.0, rel - start_rel)
                    new_host_entries.append(
                        TimelineEntry(
                            rel,
                            "concierge",
                            "SetUpVmUserDone",
                            f"call #{seq_idx} completed in <={dur:.1f}s (followed by {msg_body[:60]})",
                        )
                    )
                    pending_setup_user = None

            if "Received request: CreateDiskImage" in msg_body:
                new_host_entries.append(TimelineEntry(rel, "concierge", "CreateDiskImage", msg_body))
            elif "Found existing disk at " in msg_body:
                new_host_entries.append(TimelineEntry(rel, "concierge", "FoundExistingDisk", msg_body))
            elif "Invoking VM: /usr/bin/crosvm" in msg_body:
                new_host_entries.append(
                    TimelineEntry(rel, "concierge", "InvokeCrosvm", "Invoking /usr/bin/crosvm ...")
                )
            elif "Received NotifyVmStarted request" in msg_body:
                new_host_entries.append(TimelineEntry(rel, "cicerone", "NotifyVmStarted", msg_body))
            elif "Started VM with pid " in msg_body:
                new_host_entries.append(TimelineEntry(rel, "concierge", "StartedVm", msg_body))
            elif "Received request: SetUpVmUser" in msg_body:
                setup_user_seq += 1
                if setup_user_seq == 1:
                    first_host_setup_user_rel = rel
                pending_setup_user = (setup_user_seq, rel)
                new_host_entries.append(
                    TimelineEntry(
                        rel, "concierge", "SetUpVmUser", f"call #{setup_user_seq}: {msg_body}"
                    )
                )
            elif "Startup of container " in msg_body:
                new_host_entries.append(TimelineEntry(rel, "cicerone", "ContainerReadyLog", msg_body))
            elif "VM with requested name is already running" in msg_body:
                new_host_entries.append(
                    TimelineEntry(rel, "concierge", "StartVmAlreadyRunning", msg_body)
                )
            elif "Garcon channel not connected" in msg_body:
                new_host_entries.append(TimelineEntry(rel, "cicerone", "GarconChannelWait", msg_body))
            elif "Received LaunchVshd request" in msg_body:
                new_host_entries.append(TimelineEntry(rel, "cicerone", "LaunchVshd", msg_body))
            elif "Received RegisterVshSession request" in msg_body:
                new_host_entries.append(
                    TimelineEntry(rel, "cicerone", "RegisterVshSession", msg_body)
                )

        self.chrome_excerpt = self.vm.ssh(
            f"set -o pipefail; test -r /var/log/chrome/chrome; "
            f"tail -n +{self.chrome_line_cursor + 1} /var/log/chrome/chrome | "
            f"{{ grep -iE 'crostini|baguette|termina|cicerone|concierge|vsh' || [ $? -eq 1 ]; }}",
            check=True,
            timeout=30,
        ).stdout.strip()
        for line in self.chrome_excerpt.splitlines():
            parts = line.split(None, 3)
            if len(parts) < 4 or not re.match(r"^\d{4}-\d{2}-\d{2}T", parts[0]):
                continue
            epoch = parse_rfc3339_utc(parts[0])
            rel = (
                max(0.0, epoch - self.t_install_vm_epoch)
                if self.t_install_vm_epoch is not None
                else 0.0
            )
            c_body = parts[3]
            if "Failed to set up baguette user:" in c_body:
                new_host_entries.append(
                    TimelineEntry(rel, "chrome", "SetUpBaguetteUserFailed", c_body)
                )
            elif "Failed to restart Crostini with error code:" in c_body:
                new_host_entries.append(
                    TimelineEntry(rel, "chrome", "RestartCrostiniFailed", c_body)
                )
            elif "Unable to mount files for a container that's not running" in c_body:
                new_host_entries.append(TimelineEntry(rel, "chrome", "SshfsMountSkipped", c_body))

        with self._lock:
            self._host_log_entries = new_host_entries
        return first_host_setup_user_rel

    def _collect_readonly_dbus_snapshot(self, strict_dbus: bool = True) -> None:
        conc = self._protos.concierge_pb2
        cic = self._protos.cicerone_pb2

        # 1a. VmConcierge.GetVmInfo
        def _query_get_vm_info() -> None:
            ctx_vm = "VmConcierge.GetVmInfo"
            req_vm = conc.GetVmInfoRequest(
                name="termina", owner_id=self.owner_hash
            ).SerializeToString()
            res_vm = self.vm.ssh(
                f"dbus-send --system --type=method_call --print-reply "
                f"--dest=org.chromium.VmConcierge /org/chromium/VmConcierge "
                f"org.chromium.VmConcierge.GetVmInfo {to_dbus_byte_arg(req_vm)}",
                check=True,
                timeout=15,
            )
            raw_vm = parse_dbus_send_byte_array(res_vm.stdout, ctx_vm)
            vm_resp = parse_and_validate_proto(raw_vm, conc.GetVmInfoResponse, ctx_vm)
            if not vm_resp.success:
                if strict_dbus:
                    raise RuntimeError(f"{ctx_vm} returned success=false (hex={raw_vm.hex()})")
                self.readonly_summary_lines.append(
                    f"VmConcierge.GetVmInfo(termina): success={vm_resp.success}"
                )
                return
            vm_type_name = require_enum_name(
                conc.VmInfo.VmType, vm_resp.vm_info.vm_type, "vm_info.vm_type", ctx_vm, raw_vm
            )
            vm_status_name = require_enum_name(
                conc.VmStatus, vm_resp.vm_info.status, "vm_info.status", ctx_vm, raw_vm
            )
            if vm_resp.vm_info.pid <= 0 or vm_resp.vm_info.cid <= 0:
                raise ValueError(
                    f"{ctx_vm}: invalid pid={vm_resp.vm_info.pid} cid={vm_resp.vm_info.cid}"
                )
            self.readonly_summary_lines.append(
                f"VmConcierge.GetVmInfo(termina): success={vm_resp.success} "
                f"status={vm_status_name}({vm_resp.vm_info.status}) "
                f"vm_type={vm_type_name}({vm_resp.vm_info.vm_type}) "
                f"cid={vm_resp.vm_info.cid} pid={vm_resp.vm_info.pid}"
            )

        # 1b. VmConcierge.ListVms
        def _query_list_vms() -> None:
            ctx_lv = "VmConcierge.ListVms"
            req_lv = conc.ListVmsRequest(owner_id=self.owner_hash).SerializeToString()
            res_lv = self.vm.ssh(
                f"dbus-send --system --type=method_call --print-reply "
                f"--dest=org.chromium.VmConcierge /org/chromium/VmConcierge "
                f"org.chromium.VmConcierge.ListVms {to_dbus_byte_arg(req_lv)}",
                check=True,
                timeout=15,
            )
            raw_lv = parse_dbus_send_byte_array(res_lv.stdout, ctx_lv)
            lv_resp = parse_and_validate_proto(raw_lv, conc.ListVmsResponse, ctx_lv)
            if not lv_resp.success and strict_dbus:
                raise RuntimeError(
                    f"{ctx_lv} returned success=false: {lv_resp.failure_reason!r} (hex={raw_lv.hex()})"
                )
            vm_names = [
                require_non_empty_str(entry.name, "vms[].name", ctx_lv, raw_lv)
                for entry in lv_resp.vms
            ]
            if strict_dbus and "termina" not in vm_names:
                raise RuntimeError(f"{ctx_lv}: expected 'termina' in running VMs, got {vm_names!r}")
            self.readonly_summary_lines.append(
                f"VmConcierge.ListVms: success={lv_resp.success} vms={vm_names}"
            )

        # 1c. VmCicerone.ListRunningContainers
        def _query_list_containers() -> None:
            ctx_lc = "VmCicerone.ListRunningContainers"
            req_lc = cic.ListRunningContainersRequest(owner_id=self.owner_hash).SerializeToString()
            res_lc = self.vm.ssh(
                f"dbus-send --system --type=method_call --print-reply "
                f"--dest=org.chromium.VmCicerone /org/chromium/VmCicerone "
                f"org.chromium.VmCicerone.ListRunningContainers {to_dbus_byte_arg(req_lc)}",
                check=True,
                timeout=15,
            )
            raw_lc = parse_dbus_send_byte_array(res_lc.stdout, ctx_lc)
            lc_resp = parse_and_validate_proto(raw_lc, cic.ListRunningContainersResponse, ctx_lc)
            containers = [
                f"{require_non_empty_str(c.vm_name, 'containers[].vm_name', ctx_lc, raw_lc)}/"
                f"{require_non_empty_str(c.container_name, 'containers[].container_name', ctx_lc, raw_lc)}"
                for c in lc_resp.containers
            ]
            if strict_dbus and "termina/penguin" not in containers:
                raise RuntimeError(
                    f"{ctx_lc}: expected 'termina/penguin' in running containers, got {containers!r}"
                )
            self.readonly_summary_lines.append(
                f"VmCicerone.ListRunningContainers: {containers}"
            )

        # 1d. VmCicerone.GetGarconSessionInfo
        def _query_garcon_info() -> None:
            garcon_info = self.query_garcon_session_info_readonly()
            status_name = cic.GetGarconSessionInfoResponse.Status.Name(garcon_info.status)
            if strict_dbus and garcon_info.status != cic.GetGarconSessionInfoResponse.Status.SUCCEEDED:
                raise RuntimeError(
                    f"VmCicerone.GetGarconSessionInfo(termina/penguin) status={status_name}"
                )
            self.readonly_summary_lines.append(
                f"VmCicerone.GetGarconSessionInfo(termina/penguin): "
                f"status={status_name}({garcon_info.status}) "
                f"user={garcon_info.container_username!r} "
                f"homedir={garcon_info.container_homedir!r}"
            )

        for query_fn in (
            _query_get_vm_info,
            _query_list_vms,
            _query_list_containers,
            _query_garcon_info,
        ):
            if strict_dbus:
                query_fn()
            else:
                try:
                    query_fn()
                except Exception as exc:
                    self.readonly_summary_lines.append(f"Read-only D-Bus query error: {exc}")

    def _collect_uma_histograms(self, strict_dbus: bool = True) -> None:
        b_conn = self.vm.connect_browser_cdp()
        try:
            for h_name in (
                "Crostini.BaguetteReadyWait",
                "Crostini.TimeToInstallSuccess",
                "Crostini.SetupResult",
                "Crostini.RestarterResult.Installer",
            ):
                if strict_dbus:
                    h_res = b_conn.call("Browser.getHistogram", {"name": h_name})
                    hist = h_res.get("histogram")
                    if not isinstance(hist, dict) or not hist:
                        raise RuntimeError(
                            f"Browser.getHistogram({h_name!r}) returned empty result: {h_res!r}"
                        )
                    buckets = [
                        f"[{b['low']}..{b['high']}):{b['count']}"
                        for b in hist.get("buckets", [])
                    ]
                    self.readonly_summary_lines.append(
                        f"UMA {h_name}: count={hist.get('count')} "
                        f"sum={hist.get('sum')} buckets={buckets}"
                    )
                else:
                    try:
                        h_res = b_conn.call(
                            "Browser.getHistogram", {"name": h_name}, allow_error=True
                        )
                        if "error" in h_res:
                            self.readonly_summary_lines.append(
                                f"UMA {h_name}: <not recorded ({h_res['error'].get('message', h_res['error'])})>"
                            )
                            continue
                        hist = h_res.get("histogram")
                        if not isinstance(hist, dict) or not hist:
                            self.readonly_summary_lines.append(f"UMA {h_name}: <not recorded>")
                            continue
                        buckets = [
                            f"[{b['low']}..{b['high']}):{b['count']}"
                            for b in hist.get("buckets", [])
                        ]
                        self.readonly_summary_lines.append(
                            f"UMA {h_name}: count={hist.get('count')} "
                            f"sum={hist.get('sum')} buckets={buckets}"
                        )
                    except Exception as exc:
                        self.readonly_summary_lines.append(f"UMA {h_name} query error: {exc}")
        finally:
            b_conn.close()

    def _collect_guest_diagnostics(
        self, first_host_setup_user_rel: float | None, strict_dbus: bool = True
    ) -> None:
        # Split guest diagnostics into 5 small, targeted read-only `vsh` commands, each with
        # its own 25s-30s timeout, running the fastest system/unit/journal checks FIRST:
        #   1. GUEST_UNIT_TIMING (timeout=25): /proc/uptime + UTC epoch sync, nanosecond `stat`
        #      mtimes on /etc/passwd, /etc/group, /home/terminauser, /var/lib/systemd/linger/terminauser,
        #      /dev/.container_token, /etc/ssh/ssh_host_*_key, `systemctl list-jobs`, and
        #      `systemctl show` monotonic start/exit timestamps for first-boot-cros.service,
        #      maitred.service, vshd.service, systemd-logind.service, ldconfig.service,
        #      user-runtime-dir@1000.service, and user@1000.service.
        #   2. GUEST_JOURNAL_MONO (timeout=30): `journalctl -b -o short-monotonic` filtered
        #      directly by unit (-u ...) and SYSLOG_IDENTIFIER=... (no full-journal grep pipe).
        #   3. GUEST_JOURNAL_JSON (timeout=30): `journalctl -b -o json` with the same native
        #      unit and SYSLOG_IDENTIFIER filters.
        #   4. GUEST_SYSTEM_ANALYZE (timeout=25): system-level `systemd-analyze blame`,
        #      `systemd-analyze`, and `systemd-analyze critical-chain`.
        #   5. GUEST_USER_ANALYZE (timeout=30): user-level `systemd-analyze --user` and
        #      `systemctl --user status` via `setpriv --reuid=1000 --regid=1000 --init-groups`
        #      (avoiding PAM/pam_systemd blocking when logind or user@1000 is slow or failed).
        # When `strict_dbus=True` (passing path), every step runs under `set -euo pipefail`
        # with `check=True` and `_parse_guest_diagnostics(..., strict=True)` requires all
        # sections and required maitred/garcon journal events to be present and non-empty.
        # When `strict_dbus=False` (failure path), each step is isolated in its own try/except
        # so one slow or failing step never loses the others.
        shell_flags = "set -euo pipefail; " if strict_dbus else "set -uo pipefail; "
        vsh_prefix = (
            f"sudo -u chronos CROS_USER_ID_HASH={self.owner_hash} "
            f"vsh --vm_name=termina --owner_id={self.owner_hash} --user=root -- sh -lc "
        )
        journal_filter_args = (
            "-u first-boot-cros.service "
            "-u maitred.service "
            "-u vshd.service "
            "-u systemd-logind.service "
            "-u user-runtime-dir@1000.service "
            "-u user@1000.service "
            "-u ldconfig.service "
            "SYSLOG_IDENTIFIER=first-boot-cros "
            "SYSLOG_IDENTIFIER=maitred "
            "SYSLOG_IDENTIFIER=useradd "
            "SYSLOG_IDENTIFIER=usermod "
            "SYSLOG_IDENTIFIER=garcon "
            "SYSLOG_IDENTIFIER=sommelier "
            "SYSLOG_IDENTIFIER=vshd"
        )
        user_env_prefix = (
            "setpriv --reuid=1000 --regid=1000 --init-groups "
            "env XDG_RUNTIME_DIR=/run/user/1000 "
            "DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/1000/bus "
        )

        steps: list[tuple[str, int, str]] = [
            (
                "unit_timing_and_stat",
                25,
                vsh_prefix
                + "'"
                + shell_flags
                + 'echo "===GUEST_CLOCK_SYNC==="; '
                + "read -r up _ < /proc/uptime; "
                + 'echo "uptime_sec=$up"; '
                + 'date -u +"epoch_sec=%s.%N"; '
                + 'echo "===GUEST_STAT_MTIMES==="; '
                + "for p in /etc/passwd /etc/group /etc/shadow /etc/gshadow /home /home/"
                + self.expected_username
                + " /var/lib/systemd/linger /var/lib/systemd/linger/"
                + self.expected_username
                + " /dev/.container_token /etc/ssh/ssh_host_rsa_key /etc/ssh/ssh_host_ed25519_key; do "
                + 'if [ -e "$p" ]; then TZ=UTC0 stat -c "%n|%Y|%y|uid=%u gid=%g mode=%a" "$p"; '
                + 'else echo "$p|MISSING"; fi; done; '
                + f"id {self.expected_username} 2>&1 || true; "
                + 'echo "===GUEST_LIST_JOBS==="; '
                + "systemctl list-jobs --no-pager 2>&1; "
                + 'echo "===GUEST_SYSTEMD_UNIT_SHOW==="; '
                + "systemctl show --no-pager "
                + "-p Id -p ActiveState -p SubState -p Result "
                + "-p InactiveExitTimestampMonotonic -p ActiveEnterTimestampMonotonic "
                + "-p ActiveExitTimestampMonotonic -p InactiveEnterTimestampMonotonic "
                + "-p ExecMainStartTimestampMonotonic -p ExecMainExitTimestampMonotonic "
                + "-p ExecMainStatus "
                + "first-boot-cros.service maitred.service vshd.service systemd-logind.service "
                + "ldconfig.service user-runtime-dir@1000.service user@1000.service"
                + "'",
            ),
            (
                "journal_mono",
                30,
                vsh_prefix
                + "'"
                + shell_flags
                + 'echo "===GUEST_JOURNAL_MONO==="; '
                + f"journalctl -b -o short-monotonic --no-pager {journal_filter_args}"
                + "'",
            ),
            (
                "journal_json",
                30,
                vsh_prefix
                + "'"
                + shell_flags
                + 'echo "===GUEST_JOURNAL_JSON==="; '
                + f"journalctl -b -o json --no-pager {journal_filter_args}"
                + "'",
            ),
            (
                "system_analyze",
                25,
                vsh_prefix
                + "'"
                + shell_flags
                + 'echo "===GUEST_BLAME==="; '
                + "systemd-analyze blame --no-pager 2>&1; "
                + 'echo "===GUEST_ANALYZE==="; '
                + "systemd-analyze --no-pager 2>&1; "
                + 'echo "===GUEST_CRITICAL_CHAIN==="; '
                + "systemd-analyze critical-chain --no-pager 2>&1"
                + "'",
            ),
            (
                "user_analyze",
                30,
                vsh_prefix
                + "'"
                + shell_flags
                + 'echo "===GUEST_USER_ANALYZE==="; '
                + f"{user_env_prefix}systemd-analyze --user --no-pager 2>&1; "
                + 'echo "===GUEST_USER_CRITICAL_CHAIN==="; '
                + f"{user_env_prefix}systemd-analyze --user critical-chain --no-pager 2>&1; "
                + 'echo "===GUEST_USER_BLAME==="; '
                + f"{user_env_prefix}systemd-analyze --user blame --no-pager 2>&1; "
                + 'echo "===GUEST_GARCON_STATUS==="; '
                + f"{user_env_prefix}systemctl --user status cros-garcon.service "
                + "sommelier@0.service sommelier-x@0.service sommelier@1.service sommelier-x@1.service --no-pager 2>&1"
                + "'",
            ),
        ]

        combined_chunks: list[str] = []
        step_errors: list[str] = []
        for step_name, step_timeout, step_cmd in steps:
            if strict_dbus:
                res = self.vm.ssh(step_cmd, check=True, timeout=step_timeout)
                combined_chunks.append(res.stdout)
            else:
                try:
                    res = self.vm.ssh(step_cmd, check=False, timeout=step_timeout)
                    if res.stdout:
                        combined_chunks.append(res.stdout)
                    if res.returncode != 0:
                        err_snip = (res.stderr or "").strip().replace("\n", " | ")[:200]
                        step_errors.append(
                            f"step {step_name!r} exited with rc={res.returncode} (stderr={err_snip!r})"
                        )
                except Exception as exc:
                    step_errors.append(f"step {step_name!r} failed: {exc}")

        if step_errors:
            self.guest_summary_lines.append("[guest diagnostic step warnings]")
            for se in step_errors:
                self.guest_summary_lines.append(f"  {se}")

        self._parse_guest_diagnostics(
            "\n".join(combined_chunks),
            first_host_setup_user_rel=first_host_setup_user_rel,
            strict=strict_dbus,
        )

    def stop_and_collect(self, strict_dbus: bool = True) -> None:
        """Stops the D-Bus monitor and collects read-only D-Bus state, UMA histograms, and logs."""
        if strict_dbus:
            self.check_no_fatal_error()

        self._stop_requested = True
        if self._mon_proc is not None:
            try:
                self._mon_proc.terminate()
                self._mon_proc.wait(timeout=3)
            except Exception:
                try:
                    self._mon_proc.kill()
                except Exception:
                    pass
            self._mon_proc = None
        if self._reader_thread is not None:
            self._reader_thread.join(timeout=2.0)
            self._reader_thread = None
        if self._stderr_thread is not None:
            self._stderr_thread.join(timeout=2.0)
            self._stderr_thread = None

        if strict_dbus:
            self.check_no_fatal_error()
            self.verify_required_dbus_signal_sequence()

        self.readonly_summary_lines.clear()

        with self._lock:
            ic_entries = [e for e in self._entries if e.source == "ui" and e.name == "InstallerClosed"]
            cs_rel = self.container_started_rel_sec
        if ic_entries and cs_rel is not None:
            ic_rel = ic_entries[0].rel_sec
            self.readonly_summary_lines.append(
                f"InstallerClosed vs ContainerStarted: installer_closed=t+{ic_rel:.1f}s "
                f"container_started=t+{cs_rel:.1f}s "
                f"(installer_closed_before_container_started={ic_rel < cs_rel})"
            )

        # 1. Read-only D-Bus queries: GetVmInfo, ListVms, ListRunningContainers, GetGarconSessionInfo
        if strict_dbus:
            self._collect_readonly_dbus_snapshot(strict_dbus=True)
        else:
            try:
                self._collect_readonly_dbus_snapshot(strict_dbus=False)
            except Exception as exc:
                self.readonly_summary_lines.append(f"Read-only D-Bus snapshot error: {exc}")

        # 2. Chrome UMA histograms via CDP (read-only, raw counts/buckets without timeout inference)
        if strict_dbus:
            self._collect_uma_histograms(strict_dbus=True)
        else:
            try:
                self._collect_uma_histograms(strict_dbus=False)
            except Exception as exc:
                self.readonly_summary_lines.append(f"UMA histogram query error: {exc}")

        # 3. Scrape /var/log/messages and /var/log/chrome/chrome since start()
        if strict_dbus:
            first_host_setup_user_rel = self.scrape_host_logs()
        else:
            try:
                first_host_setup_user_rel = self.scrape_host_logs()
            except Exception as exc:
                first_host_setup_user_rel = None
                self.readonly_summary_lines.append(f"Host log scrape error: {exc}")

        # 4. Post-hoc read-only guest boot & user-session diagnostics via root vsh
        self.guest_summary_lines.clear()
        if strict_dbus:
            self._collect_guest_diagnostics(first_host_setup_user_rel, strict_dbus=True)
        else:
            try:
                self._collect_guest_diagnostics(first_host_setup_user_rel, strict_dbus=False)
            except Exception as exc:
                self.guest_summary_lines.append(f"Guest diagnostics error: {exc}")

    def _parse_guest_diagnostics(
        self,
        raw_out: str,
        first_host_setup_user_rel: float | None = None,
        strict: bool = True,
    ) -> None:
        sections: dict[str, list[str]] = {}
        cur_sec: str | None = None
        for line in raw_out.splitlines():
            if line.startswith("===GUEST_") and line.endswith("==="):
                cur_sec = line.strip("=")
                sections[cur_sec] = []
            elif cur_sec is not None:
                sections[cur_sec].append(line)

        # Parse guest /proc/uptime + date -u +%s.%N clock sync if present
        guest_uptime_sec: float | None = None
        guest_epoch_sec: float | None = None
        for cline in sections.get("GUEST_CLOCK_SYNC", []):
            cline = cline.strip()
            if cline.startswith("uptime_sec="):
                try:
                    guest_uptime_sec = float(cline.split("=", 1)[1])
                except ValueError:
                    pass
            elif cline.startswith("epoch_sec="):
                try:
                    guest_epoch_sec = float(cline.split("=", 1)[1])
                except ValueError:
                    pass

        parsed_json: list[dict] = []
        first_guest_setup_mono: float | None = None
        for jline in sections.get("GUEST_JOURNAL_JSON", []):
            jline = jline.strip()
            if not jline:
                continue
            try:
                obj = json.loads(jline)
            except json.JSONDecodeError:
                if strict:
                    raise
                continue
            parsed_json.append(obj)
            msg = str(obj.get("MESSAGE", ""))
            mono_us = int(obj.get("__MONOTONIC_TIMESTAMP", 0) or 0)
            if (
                first_guest_setup_mono is None
                and "Received request to setup a new user" in msg
                and mono_us > 0
            ):
                first_guest_setup_mono = mono_us / 1_000_000.0

        if strict and (not parsed_json or first_guest_setup_mono is None):
            raise RuntimeError(
                "Guest journal JSON diagnostics missing 'Received request to setup a new user' entry"
            )

        guest_boot_rel_sec: float | None = None
        guest_boot_epoch: float | None = None
        if guest_uptime_sec is not None and guest_epoch_sec is not None:
            guest_boot_epoch = guest_epoch_sec - guest_uptime_sec
        if first_host_setup_user_rel is not None and first_guest_setup_mono is not None:
            guest_boot_rel_sec = first_host_setup_user_rel - first_guest_setup_mono
        elif guest_boot_epoch is not None and self.t_install_vm_epoch is not None:
            guest_boot_rel_sec = guest_boot_epoch - self.t_install_vm_epoch

        new_guest_entries: list[TimelineEntry] = []

        # Summarize and project GUEST_STAT_MTIMES (nanosecond UTC mtimes of /etc/passwd, /home/terminauser, linger, etc.)
        stat_lines = [ln.strip() for ln in sections.get("GUEST_STAT_MTIMES", []) if ln.strip()]
        if stat_lines:
            self.guest_summary_lines.append("[guest filesystem mtimes & user identity]")
            for sln in stat_lines:
                self.guest_summary_lines.append(f"  {sln}")
                parts = sln.split("|")
                if len(parts) == 4 and parts[1] != "MISSING":
                    fpath, epoch_int_s, human_utc, meta_s = parts
                    mtime_epoch: float | None = None
                    m_utc = re.match(
                        r"^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})(?:\.(\d+))?\s+\+0000$",
                        human_utc.strip(),
                    )
                    if m_utc:
                        base_s = calendar.timegm(
                            time.strptime(m_utc.group(1), "%Y-%m-%d %H:%M:%S")
                        )
                        frac_s = float(f"0.{m_utc.group(2)}") if m_utc.group(2) else 0.0
                        mtime_epoch = float(base_s) + frac_s
                    else:
                        try:
                            mtime_epoch = float(epoch_int_s)
                        except ValueError:
                            mtime_epoch = None
                    if (
                        mtime_epoch is not None
                        and self.t_install_vm_epoch is not None
                        and mtime_epoch >= self.t_install_vm_epoch - 2.0
                    ):
                        rel = max(0.0, mtime_epoch - self.t_install_vm_epoch)
                        g_tag = ""
                        if guest_boot_epoch is not None:
                            g_tag = f"(guest+{max(0.0, mtime_epoch - guest_boot_epoch):.2f}s) "
                        elif guest_boot_rel_sec is not None:
                            g_tag = f"(guest+{max(0.0, rel - guest_boot_rel_sec):.2f}s) "
                        new_guest_entries.append(
                            TimelineEntry(
                                rel,
                                "guest",
                                "GuestFileMtime",
                                f"{g_tag}{fpath} mtime={human_utc.strip()} ({meta_s})",
                            )
                        )

        # Summarize GUEST_LIST_JOBS if present
        job_lines = [ln.strip() for ln in sections.get("GUEST_LIST_JOBS", []) if ln.strip()]
        if job_lines:
            self.guest_summary_lines.append("[systemctl list-jobs (system)]")
            for jln in job_lines[:30]:
                self.guest_summary_lines.append(f"  {jln}")

        # Parse and summarize GUEST_SYSTEMD_UNIT_SHOW monotonic timestamps
        unit_show_raw = "\n".join(sections.get("GUEST_SYSTEMD_UNIT_SHOW", [])).strip()
        if unit_show_raw:
            self.guest_summary_lines.append("[systemd unit monotonic timing (systemctl show)]")
            for block in re.split(r"\n\s*\n", unit_show_raw):
                props: dict[str, str] = {}
                for bln in block.splitlines():
                    if "=" in bln:
                        k, v = bln.split("=", 1)
                        props[k.strip()] = v.strip()
                unit_id = props.get("Id", "")
                if not unit_id:
                    continue
                act_state = props.get("ActiveState", "")
                sub_state = props.get("SubState", "")
                result = props.get("Result", "")
                exec_status = props.get("ExecMainStatus", "")
                inact_exit_us = int(props.get("InactiveExitTimestampMonotonic", "0") or "0")
                act_enter_us = int(props.get("ActiveEnterTimestampMonotonic", "0") or "0")
                exec_start_us = int(props.get("ExecMainStartTimestampMonotonic", "0") or "0")
                exec_exit_us = int(props.get("ExecMainExitTimestampMonotonic", "0") or "0")
                start_us = exec_start_us or inact_exit_us
                end_us = exec_exit_us or act_enter_us
                start_s = start_us / 1_000_000.0
                end_s = end_us / 1_000_000.0
                dur_str = (
                    f"{end_s - start_s:.2f}s"
                    if (start_us > 0 and end_us >= start_us)
                    else "in-flight/n/a"
                )
                host_window = ""
                if guest_boot_rel_sec is not None and start_us > 0:
                    h_start = max(0.0, guest_boot_rel_sec + start_s)
                    new_guest_entries.append(
                        TimelineEntry(
                            h_start,
                            "guest",
                            f"UnitStart({unit_id})",
                            f"(guest+{start_s:.2f}s) systemctl show start ({act_state}/{sub_state})",
                        )
                    )
                    if end_us >= start_us and end_us > 0:
                        h_end = max(0.0, guest_boot_rel_sec + end_s)
                        host_window = f" host=t+{h_start:.1f}s..t+{h_end:.1f}s"
                        if exec_exit_us > 0:
                            new_guest_entries.append(
                                TimelineEntry(
                                    h_end,
                                    "guest",
                                    f"UnitDone({unit_id})",
                                    f"(guest+{end_s:.2f}s) systemctl show exit dur={dur_str} result={result} status={exec_status}",
                                )
                            )
                    else:
                        host_window = f" host=t+{h_start:.1f}s..(running)"
                self.guest_summary_lines.append(
                    f"  {unit_id}: state={act_state}/{sub_state} result={result} "
                    f"guest=+{start_s:.2f}s..+{end_s:.2f}s (dur={dur_str}, exit_status={exec_status})"
                    f"{host_window}"
                )

        for label, key, max_lines in (
            ("systemd-analyze (system)", "GUEST_ANALYZE", 120),
            ("systemd-analyze critical-chain (system)", "GUEST_CRITICAL_CHAIN", 120),
            ("systemd-analyze blame top-12 (system)", "GUEST_BLAME", 12),
            ("systemd-analyze --user (terminauser@)", "GUEST_USER_ANALYZE", 120),
            ("systemd-analyze --user critical-chain (terminauser@)", "GUEST_USER_CRITICAL_CHAIN", 120),
            ("systemd-analyze --user blame top-12 (terminauser@)", "GUEST_USER_BLAME", 12),
            ("systemctl --user status cros-garcon & sommelier", "GUEST_GARCON_STATUS", 120),
            ("journalctl -b -o short-monotonic (filtered)", "GUEST_JOURNAL_MONO", 160),
        ):
            sec_lines = [ln for ln in sections.get(key, []) if ln.strip()]
            if not sec_lines:
                if strict:
                    raise RuntimeError(
                        f"Guest diagnostics section {key!r} ({label}) is missing or empty"
                    )
                self.guest_summary_lines.append(f"[{label}]: <empty or unavailable>")
                continue
            self.guest_summary_lines.append(f"[{label}]")
            for ln in sec_lines[:max_lines]:
                self.guest_summary_lines.append(f"  {ln}")

        # Project key guest journal events onto the unified t+X.Xs timeline
        setup_user_guest_seq = 0
        for obj in parsed_json:
            msg = str(obj.get("MESSAGE", ""))
            comm = str(obj.get("_COMM", ""))
            syslog_id = str(obj.get("SYSLOG_IDENTIFIER", ""))
            unit = str(obj.get("_SYSTEMD_UNIT", "") or obj.get("UNIT", ""))
            ident = f"{comm} {syslog_id} {unit}".lower()
            rt_us = int(obj.get("__REALTIME_TIMESTAMP", 0) or 0)
            mono_us = int(obj.get("__MONOTONIC_TIMESTAMP", 0) or 0)
            g_mono = mono_us / 1_000_000.0
            if guest_boot_rel_sec is not None and mono_us > 0:
                rel = max(0.0, guest_boot_rel_sec + g_mono)
            elif rt_us and self.t_install_vm_epoch is not None:
                rel = max(0.0, (rt_us / 1_000_000.0) - self.t_install_vm_epoch)
            else:
                continue
            tag = f"(guest+{g_mono:.2f}s) "

            if "Starting First boot script" in msg:
                new_guest_entries.append(TimelineEntry(rel, "guest", "FirstBootStart", tag + msg))
            elif "first-boot-cros" in ident and (
                "Resize device" in msg
                or "FileSystem / has been resized" in msg
                or "ssh-keygen:" in msg
                or "Removed " in msg
            ):
                new_guest_entries.append(TimelineEntry(rel, "guest", "FirstBootStep", tag + msg))
            elif "Finished First boot script" in msg:
                new_guest_entries.append(TimelineEntry(rel, "guest", "FirstBootDone", tag + msg))
            elif "Starting Rebuild Dynamic Linker Cache" in msg:
                new_guest_entries.append(TimelineEntry(rel, "guest", "LdconfigStart", tag + msg))
            elif "Finished Rebuild Dynamic Linker Cache" in msg:
                new_guest_entries.append(TimelineEntry(rel, "guest", "LdconfigDone", tag + msg))
            elif "Starting User Login Management" in msg:
                new_guest_entries.append(TimelineEntry(rel, "guest", "LogindStart", tag + msg))
            elif "Started User Login Management" in msg:
                new_guest_entries.append(TimelineEntry(rel, "guest", "LogindReady", tag + msg))
            elif "Started maitred" in msg:
                new_guest_entries.append(TimelineEntry(rel, "guest", "MaitredStarted", tag + msg))
            elif "Wrote container token to /dev/.container_token" in msg:
                new_guest_entries.append(
                    TimelineEntry(rel, "guest", "ContainerTokenWrote", tag + msg)
                )
            elif "Received request to setup a new user" in msg:
                setup_user_guest_seq += 1
                new_guest_entries.append(
                    TimelineEntry(
                        rel,
                        "guest",
                        "MaitredSetUpUser",
                        f"{tag}call #{setup_user_guest_seq}: {msg}",
                    )
                )
            elif "already exists" in msg and "maitred" in ident:
                new_guest_entries.append(
                    TimelineEntry(rel, "guest", "MaitredUserExists", tag + msg)
                )
            elif "useradd" in ident and "new group:" in msg:
                new_guest_entries.append(TimelineEntry(rel, "guest", "UseraddGroup", tag + msg))
            elif "useradd" in ident and "new user:" in msg:
                new_guest_entries.append(TimelineEntry(rel, "guest", "UseraddDone", tag + msg))
            elif "useradd" in ident and "add '" in msg and (
                "group 'audio'" in msg or "shadow group 'video'" in msg
            ):
                new_guest_entries.append(
                    TimelineEntry(rel, "guest", "UseraddGroupMembership", tag + msg)
                )
            elif "usermod" in ident:
                new_guest_entries.append(TimelineEntry(rel, "guest", "Usermod", tag + msg))
            elif "maitred" in ident and (
                "failed" in msg.lower() or "error" in msg.lower() or "linger" in msg.lower()
            ):
                new_guest_entries.append(TimelineEntry(rel, "guest", "MaitredLog", tag + msg))
            elif "Starting User Runtime Directory /run/user/1000" in msg:
                new_guest_entries.append(
                    TimelineEntry(rel, "guest", "UserRuntimeDirStart", tag + msg)
                )
            elif "Finished User Runtime Directory /run/user/1000" in msg:
                new_guest_entries.append(
                    TimelineEntry(rel, "guest", "UserRuntimeDirDone", tag + msg)
                )
            elif "Starting User Manager for UID 1000" in msg:
                new_guest_entries.append(TimelineEntry(rel, "guest", "User1000Start", tag + msg))
            elif "Started User Manager for UID 1000" in msg:
                new_guest_entries.append(TimelineEntry(rel, "guest", "User1000Ready", tag + msg))
            elif "Starting Parent sommelier" in msg or "Starting X11 sommelier" in msg:
                new_guest_entries.append(TimelineEntry(rel, "guest", "SommelierStart", tag + msg))
            elif "Started Parent sommelier" in msg or "Started X11 sommelier" in msg:
                new_guest_entries.append(TimelineEntry(rel, "guest", "SommelierReady", tag + msg))
            elif "sommelier" in msg.lower() and (
                "timed out" in msg
                or "failed" in msg.lower()
                or "scheduled restart" in msg.lower()
                or "main process exited" in msg.lower()
            ):
                new_guest_entries.append(TimelineEntry(rel, "guest", "SommelierIssue", tag + msg))
            elif "still waiting for /dev/.container_token" in msg:
                new_guest_entries.append(
                    TimelineEntry(rel, "guest", "SommelierWaitToken", tag + msg)
                )
            elif "Started Chromium OS Garcon Bridge" in msg:
                new_guest_entries.append(
                    TimelineEntry(rel, "guest", "GarconServiceStarted", tag + msg)
                )
            elif "garcon" in ident and "systemd" not in ident:
                new_guest_entries.append(
                    TimelineEntry(rel, "guest", "GarconLog", tag + msg[:140])
                )
            elif "vshd" in ident and "systemd" not in ident:
                new_guest_entries.append(
                    TimelineEntry(rel, "guest", "GuestVshd", tag + msg[:140])
                )

        with self._lock:
            self._guest_log_entries = new_guest_entries

    def format_report(self, include_raw_logs: bool = False) -> str:
        sorted_entries = self.all_entries()
        lines = ["=== INITIALIZATION TIMELINE (relative to Install click) ==="]
        for e in sorted_entries:
            lines.append(f"  t+{e.rel_sec:6.1f}s  [{e.source:<9}] {e.name}: {e.detail}")
        lines.append("  --- Read-Only D-Bus & UMA Snapshot ---")
        for s_line in self.readonly_summary_lines:
            lines.append(f"  {s_line}")
        if self.guest_summary_lines:
            lines.append("  --- Guest Boot & Service Timing Summary (read-only) ---")
            for g_line in self.guest_summary_lines:
                lines.append(f"  {g_line}")
        if include_raw_logs:
            if self.messages_excerpt:
                lines.append("  --- /var/log/messages excerpt ---")
                for m_line in self.messages_excerpt.splitlines()[-40:]:
                    lines.append(f"    {m_line}")
            if self.chrome_excerpt:
                lines.append("  --- /var/log/chrome/chrome excerpt ---")
                for c_line in self.chrome_excerpt.splitlines()[-30:]:
                    lines.append(f"    {c_line}")
        lines.append("===========================================================")
        return "\n".join(lines)


class HostQemuCpuThrottler:
    """Optional host-side SIGSTOP/SIGCONT duty-cycle throttler on QEMU to simulate slow CI runners."""

    def __init__(
        self,
        pid_file: Path,
        quota_pct: int | None,
        initial_delay_sec: float = 3.0,
    ) -> None:
        self.pid_file = pid_file
        self.quota_pct = quota_pct
        self.initial_delay_sec = initial_delay_sec
        self._stop_event = threading.Event()
        self._thread: threading.Thread | None = None

    def start(self) -> None:
        if self.quota_pct is None or self.quota_pct >= 100:
            return
        if not (5 <= self.quota_pct < 100):
            raise ValueError(f"--qemu-cpu-quota-pct must be between 5 and 100, got {self.quota_pct}")
        if self._thread is not None:
            return
        pid = int(self.pid_file.read_text().strip())
        self._stop_event.clear()
        self._thread = threading.Thread(target=self._run, args=(pid,), daemon=True)
        self._thread.start()

    def _run(self, pid: int) -> None:
        if self.initial_delay_sec > 0 and self._stop_event.wait(timeout=self.initial_delay_sec):
            return
        assert self.quota_pct is not None
        effective_quota_pct = (
            max(5, self.quota_pct - 2) if self.initial_delay_sec == 0.0 else self.quota_pct
        )
        log(
            f"  [throttle] Throttling host QEMU PID {pid} to {effective_quota_pct}% CPU duty cycle "
            f"(requested={self.quota_pct}%, initial_delay={self.initial_delay_sec:.1f}s)..."
        )
        period = 0.100  # 100 ms period so Chrome's 4s timers still wake promptly
        run_slice = period * (effective_quota_pct / 100.0)
        stop_slice = period - run_slice
        try:
            while not self._stop_event.is_set():
                os.kill(pid, signal.SIGSTOP)
                if self._stop_event.wait(timeout=stop_slice):
                    break
                os.kill(pid, signal.SIGCONT)
                if self._stop_event.wait(timeout=run_slice):
                    break
        except ProcessLookupError:
            pass
        finally:
            try:
                os.kill(pid, signal.SIGCONT)
            except ProcessLookupError:
                pass

    def stop(self) -> None:
        if self._thread is not None:
            self._stop_event.set()
            self._thread.join(timeout=2.0)
            self._thread = None


class ChromeOSVM:
    def __init__(
        self,
        base_image: Path,
        ssh_key: Path,
        work_dir: Path,
        qemu_bin: str = "qemu-system-x86_64",
        qemu_bios_dir: str | None = None,
        ram_gb: int | None = None,
        smp: int | None = None,
        cpu_quota_pct: int | None = None,
        throttle_from_vm_start: bool = False,
    ) -> None:
        self.base_image = base_image
        self.ssh_key = ssh_key
        self.work_dir = work_dir
        self.qemu_bin = qemu_bin
        self.qemu_bios_dir = qemu_bios_dir
        self.ram_gb = ram_gb if ram_gb is not None else default_vm_ram_gb()
        self.smp = smp if smp is not None else min(8, os.cpu_count() or 4)
        self.cpu_quota_pct = cpu_quota_pct
        self.throttle_from_vm_start = throttle_from_vm_start
        self.ssh_port = find_free_port()
        self.vm_image = self.work_dir / "cros_vm.bin"
        self.pid_file = self.work_dir / "kvm.pid"
        self.serial_log = self.work_dir / "kvm.serial"
        self.owner_hash: str | None = None
        self._devtools_fwd_proc: subprocess.Popen | None = None
        self._local_dt_port: int | None = None
        self._remote_dt_port: int | None = None
        self._browser_ws_path: str | None = None

    def _ssh_base_cmd(self) -> list[str]:
        return [
            "ssh",
            "-i",
            str(self.ssh_key),
            "-o",
            "IdentitiesOnly=yes",
            "-o",
            "StrictHostKeyChecking=no",
            "-o",
            "UserKnownHostsFile=/dev/null",
            "-o",
            "ConnectTimeout=5",
            "-o",
            "ServerAliveInterval=20",
            "-o",
            "ServerAliveCountMax=6",
            "-p",
            str(self.ssh_port),
            "root@127.0.0.1",
        ]

    def ssh(
        self,
        remote_cmd: str,
        check: bool = True,
        timeout: int = 300,
        capture_output: bool = True,
    ) -> subprocess.CompletedProcess[str]:
        try:
            return subprocess.run(
                [*self._ssh_base_cmd(), remote_cmd],
                check=check,
                text=True,
                timeout=timeout,
                capture_output=capture_output,
            )
        except subprocess.CalledProcessError as exc:
            log(f"SSH command failed (rc={exc.returncode}):\nSTDOUT:\n{exc.stdout}\nSTDERR:\n{exc.stderr}")
            raise

    def scp_to(self, local_path: Path, remote_path: str) -> None:
        cmd = [
            "scp",
            "-i",
            str(self.ssh_key),
            "-o",
            "IdentitiesOnly=yes",
            "-o",
            "StrictHostKeyChecking=no",
            "-o",
            "UserKnownHostsFile=/dev/null",
            "-P",
            str(self.ssh_port),
            str(local_path),
            f"root@127.0.0.1:{remote_path}",
        ]
        subprocess.run(cmd, check=True, timeout=180)

    def wait_for_ssh(
        self, timeout_sec: int = 90, different_from_boot_id: str | None = None
    ) -> str:
        deadline = time.monotonic() + timeout_sec
        while time.monotonic() < deadline:
            res = self.ssh(
                "cat /proc/sys/kernel/random/boot_id", check=False, timeout=8
            )
            if res.returncode == 0:
                boot_id = res.stdout.strip()
                if boot_id and (
                    different_from_boot_id is None or boot_id != different_from_boot_id
                ):
                    return boot_id
            time.sleep(1.5)
        raise TimeoutError(f"Timed out waiting for SSH on 127.0.0.1:{self.ssh_port}")

    def assert_guest_kvm_available(self) -> None:
        res = self.ssh("test -c /dev/kvm", check=False, timeout=15)
        if res.returncode != 0:
            diag = self.ssh(
                "grep -E 'vendor_id|model name|flags' /proc/cpuinfo | head -n 6; "
                "head -n 1 /sys/module/kvm_*/parameters/nested 2>&1 || true",
                check=False,
                timeout=15,
            )
            raise RuntimeError(
                "Nested KVM (/dev/kvm) is missing inside the ChromeOS VM!\n"
                f"Diagnostics:\n{diag.stdout}\n{diag.stderr}"
            )

    def start(self) -> None:
        assert_host_kvm_available()
        self.work_dir.mkdir(parents=True, exist_ok=True)
        log(f"Preparing working ChromeOS disk image at {self.vm_image}...")
        reflink = subprocess.run(
            ["cp", "--reflink=always", str(self.base_image), str(self.vm_image)],
            capture_output=True,
        )
        if reflink.returncode != 0:
            subprocess.run(
                ["cp", "--sparse=always", str(self.base_image), str(self.vm_image)],
                check=True,
            )
        # Grow disk sparsely by +12 GiB and resize partition 1 (STATE) on the host
        # so /mnt/stateful_partition has ~15 GiB free while using 0 extra host bytes.
        subprocess.run(["truncate", "-s", "+12G", str(self.vm_image)], check=True)
        subprocess.run(
            [find_sbin_tool("sgdisk"), "-e", str(self.vm_image)],
            check=True,
            stdout=subprocess.DEVNULL,
        )
        # Capture stderr to silence parted's harmless `sh: udevadm: not found` warning on disk image files.
        parted_res = subprocess.run(
            [find_sbin_tool("parted"), "-s", str(self.vm_image), "resizepart", "1", "100%"],
            check=False,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            text=True,
        )
        if parted_res.returncode != 0:
            raise RuntimeError(f"parted resizepart failed: {parted_res.stderr}")

        cpu_arg = detect_host_qemu_cpu_arg()
        qemu_cmd = [self.qemu_bin]
        if self.qemu_bios_dir:
            qemu_cmd += ["-L", self.qemu_bios_dir]
        qemu_cmd += [
            "-m",
            f"{self.ram_gb}G",
            "-smp",
            str(self.smp),
            "-daemonize",
            "-pidfile",
            str(self.pid_file),
            "-serial",
            f"file:{self.serial_log}",
            "-cpu",
            cpu_arg,
            "-usb",
            "-device",
            "nec-usb-xhci",
            "-device",
            "usb-tablet",
            "-device",
            "usb-kbd",
            "-device",
            "virtio-net,netdev=eth0",
            "-device",
            "virtio-scsi-pci,id=scsi",
            "-device",
            "virtio-rng",
            "-device",
            "scsi-hd,drive=hd,rotation_rate=1",
            "-drive",
            f"if=none,id=hd,file={self.vm_image},cache=unsafe,format=raw,discard=unmap",
            "-netdev",
            f"user,id=eth0,net=10.0.2.0/27,hostfwd=tcp:127.0.0.1:{self.ssh_port}-:22",
            "-enable-kvm",
            "-display",
            "none",
            "-vga",
            "virtio",
        ]
        log(
            f"Booting QEMU ChromeOS VM on SSH port {self.ssh_port} "
            f"(ram={self.ram_gb}G, smp={self.smp}, cpu={cpu_arg})..."
        )
        subprocess.run(qemu_cmd, check=True)
        self.wait_for_ssh()
        lsb_release = self.ssh("cat /etc/lsb-release").stdout
        protos = load_cros_protos()
        verify_lsb_release_matches_metadata(lsb_release, protos.metadata)
        self.assert_guest_kvm_available()
        log(
            f"SSH connected to ChromeOS VM (verified /etc/lsb-release == "
            f"{protos.metadata['board']}/{protos.metadata['cros_release']}, nested /dev/kvm present)."
        )

    def stop(self) -> None:
        if self._devtools_fwd_proc is not None:
            try:
                self._devtools_fwd_proc.terminate()
                self._devtools_fwd_proc.wait(timeout=3)
            except Exception:
                try:
                    self._devtools_fwd_proc.kill()
                except Exception:
                    pass
            self._devtools_fwd_proc = None

        if self.pid_file.exists():
            try:
                pid = int(self.pid_file.read_text().strip())
                comm_path = Path(f"/proc/{pid}/comm")
                if comm_path.exists() and comm_path.read_text().strip().startswith("qemu-system"):
                    os.kill(pid, signal.SIGCONT)
                    os.kill(pid, signal.SIGTERM)
                    deadline = time.monotonic() + 5.0
                    while time.monotonic() < deadline and comm_path.exists():
                        time.sleep(0.2)
                    if comm_path.exists():
                        os.kill(pid, signal.SIGKILL)
                    log(f"Terminated QEMU PID {pid}.")
            except (ProcessLookupError, PermissionError, ValueError, OSError):
                pass
            self.pid_file.unlink(missing_ok=True)

    def prepare_nested_vm_host_and_login(self, baguette_image: Path) -> str:
        log("Removing rootfs verification to apply nested-KVM vm_concierge fix...")
        pre_boot_id = self.ssh("cat /proc/sys/kernel/random/boot_id").stdout.strip()
        self.ssh(
            "/usr/share/vboot/bin/make_dev_ssd.sh --remove_rootfs_verification --partitions 2"
        )
        self.ssh("reboot", check=False)
        self.wait_for_ssh(timeout_sec=120, different_from_boot_id=pre_boot_id)
        self.assert_guest_kvm_available()

        log("Expanding /dev/sda1 (/mnt/stateful_partition) and patching vm_concierge for nested KVM...")
        # Why vm_concierge is binary-patched here:
        # In nested KVM on Intel/AMD hosts, QEMU exposes CPU vulnerability sysfs files
        # (/sys/devices/system/cpu/vulnerabilities/{l1tf,mds}) that cause
        # UntrustedVMUtils::SafeToRunVirtualMachines in vm_concierge to reject starting
        # untrusted guest VMs unless patched to read "Not affected". We also replace
        # `printk.devkmsg=on` with `quiet loglevel=0 ` so inner crosvm boot logs do not
        # flood serial console I/O.
        setup_script = """
set -euo pipefail
mount -o remount,rw /
resize2fs /dev/sda1
df -h /mnt/stateful_partition

echo "Not affected" > /etc/not_affected
chmod 644 /etc/not_affected

python3 -c '
p = "/usr/bin/vm_concierge"
d = open(p, "rb").read()
for old in [b"/sys/devices/system/cpu/vulnerabilities/l1tf", b"/sys/devices/system/cpu/vulnerabilities/mds"]:
    assert old in d, f"Expected {old!r} in {p}"
    slashes = len(old) - len(b"/etc/not_affected")
    new = b"/etc/" + (b"/" * slashes) + b"not_affected"
    assert len(old) == len(new)
    d = d.replace(old, new)
old2 = b"printk.devkmsg=on"
new2 = b"quiet loglevel=0 "
assert old2 in d, f"Expected {old2!r} in {p}"
assert len(old2) == len(new2)
d = d.replace(old2, new2)
open(p + ".patched", "wb").write(d)
'
chmod 755 /usr/bin/vm_concierge.patched
mv /usr/bin/vm_concierge.patched /usr/bin/vm_concierge

if ! grep -q "enable-features=Baguette" /etc/chrome_dev.conf; then
  echo "--enable-features=Baguette,Crostini,CrostiniContainerless" >> /etc/chrome_dev.conf
fi
stop vm_concierge || true
sync
"""
        res_setup = self.ssh(setup_script)
        log(f"Stateful partition resized:\n{res_setup.stdout.strip()}")

        log("Logging in ChromeOS session...")
        login_script = """
set -euo pipefail
stop vm_concierge || true
/usr/local/autotest/bin/autologin.py -d \
  --disable-feature=CryptohomeRecoveryByDefaultForConsumers \
  -w --no-popup-notification
HASH=$(ls /home/user/)
dbus-send --system --type=method_call --print-reply \
  --dest=org.chromium.ChromeFeaturesService /org/chromium/ChromeFeaturesService \
  org.chromium.ChromeFeaturesServiceInterface.IsCrostiniEnabled "string:$HASH"
"""
        res_login = self.ssh(login_script, timeout=180)
        if "boolean true" not in res_login.stdout:
            raise RuntimeError(f"IsCrostiniEnabled did not return true:\n{res_login.stdout}")
        owner_hash = self.ssh("ls /home/user/").stdout.strip()
        if not owner_hash:
            raise RuntimeError("Failed to find mounted cryptohome hash under /home/user/")
        self.owner_hash = owner_hash
        log(f"Logged in (IsCrostiniEnabled=true)! CROS_USER_ID_HASH = {owner_hash}")

        remote_dl = f"/home/user/{owner_hash}/MyFiles/Downloads/baguette_arch_rootfs.img.zst"
        log(f"Copying {baguette_image} -> {remote_dl}...")
        self.scp_to(baguette_image, remote_dl)
        local_sha = hashlib.sha256(baguette_image.read_bytes()).hexdigest()
        remote_sha = self.ssh(f"sha256sum '{remote_dl}'").stdout.split()[0]
        if local_sha != remote_sha:
            raise RuntimeError(f"SHA256 mismatch: {local_sha} != {remote_sha}")
        log(f"Verified image SHA256 inside ChromeOS VM: {local_sha}")

        self._setup_devtools_tunnel()
        return remote_dl

    def _setup_devtools_tunnel(self) -> None:
        dt_lines = self.ssh("cat /home/chronos/DevToolsActivePort").stdout.strip().splitlines()
        self._remote_dt_port = int(dt_lines[0].strip())
        self._browser_ws_path = dt_lines[1].strip()
        self._local_dt_port = find_free_port()
        log(
            f"Forwarding host 127.0.0.1:{self._local_dt_port} -> "
            f"ChromeOS DevTools 127.0.0.1:{self._remote_dt_port}..."
        )
        self._devtools_fwd_proc = subprocess.Popen(
            [
                *self._ssh_base_cmd()[:-1],
                "-N",
                "-L",
                f"127.0.0.1:{self._local_dt_port}:127.0.0.1:{self._remote_dt_port}",
                self._ssh_base_cmd()[-1],
            ],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        deadline = time.monotonic() + 15.0
        last_err: Exception | None = None
        while time.monotonic() < deadline:
            try:
                _ = self.list_cdp_targets()
                return
            except Exception as exc:
                last_err = exc
                time.sleep(0.3)
        raise TimeoutError(
            f"Timed out establishing SSH port forward to Chrome DevToolsActivePort (last error: {last_err})"
        )

    def connect_browser_cdp(self) -> CDPConnection:
        assert self._local_dt_port and self._browser_ws_path
        return CDPConnection(f"ws://127.0.0.1:{self._local_dt_port}{self._browser_ws_path}")

    def list_cdp_targets(self) -> list[dict]:
        assert self._local_dt_port and self._remote_dt_port
        url = f"http://127.0.0.1:{self._local_dt_port}/json/list"
        raw = urllib.request.urlopen(url, timeout=15).read()
        targets = json.loads(raw)
        for tgt in targets:
            if "webSocketDebuggerUrl" in tgt:
                tgt["webSocketDebuggerUrl"] = tgt["webSocketDebuggerUrl"].replace(
                    f"127.0.0.1:{self._remote_dt_port}",
                    f"127.0.0.1:{self._local_dt_port}",
                )
        return targets

    def open_crosh_tab(self, label: str) -> CroshTab:
        browser_conn = self.connect_browser_cdp()
        try:
            tid = browser_conn.call(
                "Target.createTarget", {"url": "chrome-untrusted://crosh/"}
            )["targetId"]
        finally:
            browser_conn.close()

        for _ in range(40):
            for tgt in self.list_cdp_targets():
                if tgt.get("id") == tid and "webSocketDebuggerUrl" in tgt:
                    conn = CDPConnection(tgt["webSocketDebuggerUrl"])
                    tab = CroshTab(label, conn)
                    tab.wait_for(
                        lambda txt: txt.rstrip().endswith("crosh>"),
                        timeout=30,
                        desc=f"{label} initial crosh> prompt",
                    )
                    log(f"Opened {label} (`chrome-untrusted://crosh/`, target={tid})")
                    return tab
            time.sleep(0.3)
        raise RuntimeError(f"Failed to attach to crosh tab {label} ({tid})")

    def verify_guest_user_session(self, vm_name: str, expected_username: str) -> None:
        assert self.owner_hash
        uid_res = self.ssh(
            f"sudo -u chronos CROS_USER_ID_HASH={self.owner_hash} "
            f"vsh --vm_name={vm_name} --owner_id={self.owner_hash} --user=root -- id -nu 1000",
            timeout=30,
        )
        actual_username = uid_res.stdout.strip()
        log(f"  [{vm_name}] UID 1000 user in guest: '{actual_username}'")
        if actual_username != expected_username:
            raise RuntimeError(
                f"Expected UID 1000 username '{expected_username}', got '{actual_username}'"
            )

        log(
            f"Verifying in-guest OS, UID/GID 1000, primary group '{expected_username}', "
            f"exact supplementary groups {sorted(EXPECTED_GUEST_SUPPLEMENTARY_GROUPS)}, "
            f"and active cros-garcon.service for VM '{vm_name}'..."
        )
        check_cmd = (
            f"sudo -u chronos CROS_USER_ID_HASH={self.owner_hash} "
            f"vsh --vm_name={vm_name} --owner_id={self.owner_hash} --user={actual_username} -- sh -lc '"
            "set -euo pipefail; "
            'grep -q "Arch Linux" /etc/os-release; '
            'echo "OS=$(. /etc/os-release && echo $PRETTY_NAME)"; '
            'echo "ID=$(id)"; '
            'echo "UID=$(id -u)"; '
            'echo "USER=$(id -nu)"; '
            'echo "GID=$(id -g)"; '
            'echo "GROUP=$(id -ng)"; '
            'echo "GROUPS=$(id -Gn)"; '
            "GARCON=$(systemctl --user is-active cros-garcon.service); "
            'echo "GARCON=$GARCON"; '
            '[ "$GARCON" = "active" ]\''
        )
        res = self.ssh(check_cmd, timeout=30)
        kv: dict[str, str] = {}
        for line in res.stdout.strip().splitlines():
            log(f"  [{vm_name}] {line}")
            if "=" in line:
                k, v = line.split("=", 1)
                kv[k.strip()] = v.strip()

        verify_guest_user_identity(
            uid_str=kv.get("UID", ""),
            user_str=kv.get("USER", ""),
            gid_str=kv.get("GID", ""),
            group_str=kv.get("GROUP", ""),
            all_groups_str=kv.get("GROUPS", ""),
            expected_username=expected_username,
        )

    def run_settings_crostini_installer_ui(
        self,
        username: str,
        timeline: InitTimelineRecorder,
        throttler: HostQemuCpuThrottler | None = None,
    ) -> dict:
        """Drives ChromeOS Settings -> About ChromeOS -> Developers -> Set up -> crostini-installer.

        Returns the initial `chrome-untrusted://terminal` vmshell CDP target dictionary opened by
        the installer upon completion.
        """
        log("Opening `chrome://os-settings/` via CDP...")
        browser_conn = self.connect_browser_cdp()
        try:
            # chrome://os-settings/ is a System Web App (SWA); Target.createTarget triggers
            # LaunchSystemWebAppAsync and returns CDP error -32000 ("Failed to open a new tab")
            # while opening the SWA window asynchronously. Only that exact SWA launch response
            # or a direct targetId is permitted.
            swa_res = browser_conn.call(
                "Target.createTarget", {"url": "chrome://os-settings/"}, allow_error=True
            )
            if "error" in swa_res:
                err_obj = swa_res["error"]
                if not (
                    isinstance(err_obj, dict)
                    and err_obj.get("code") == -32000
                    and err_obj.get("message") == "Failed to open a new tab"
                ):
                    raise RuntimeError(
                        f"Unexpected CDP error launching chrome://os-settings/: {swa_res!r}"
                    )
            elif "targetId" not in swa_res:
                raise RuntimeError(
                    f"Unexpected CDP response launching chrome://os-settings/: {swa_res!r}"
                )
        finally:
            browser_conn.close()

        settings_conn: CDPConnection | None = None
        for _ in range(40):
            for tgt in self.list_cdp_targets():
                if "chrome://os-settings" in tgt.get("url", "") and "webSocketDebuggerUrl" in tgt:
                    settings_conn = CDPConnection(tgt["webSocketDebuggerUrl"])
                    break
            if settings_conn is not None:
                break
            time.sleep(0.5)
        if settings_conn is None:
            raise RuntimeError("Could not find `chrome://os-settings/` target in CDP")

        try:
            log(
                "Navigating OS Settings UI: clicking `About ChromeOS` -> "
                "`Developers` -> `Linux development environment` -> `Set up`..."
            )
            for _ in range(40):
                nav_res = settings_conn.eval_js("""(() => {
                    const ui = document.querySelector('os-settings-ui');
                    if (!ui || !ui.shadowRoot) return 'no-ui';
                    const menu = ui.shadowRoot.querySelector('os-settings-menu');
                    if (!menu || !menu.shadowRoot) return 'no-menu';
                    const aboutItem = menu.shadowRoot.querySelector('os-settings-menu-item[path="/help"]');
                    if (!aboutItem) return 'no-about-item';
                    aboutItem.click();
                    const main = ui.shadowRoot.querySelector('os-settings-main');
                    if (!main || !main.shadowRoot) return 'no-main';
                    const container = main.shadowRoot.querySelector('main-page-container');
                    if (!container || !container.shadowRoot) return 'no-container';
                    const aboutPage = container.shadowRoot.querySelector('os-about-page');
                    if (!aboutPage || !aboutPage.shadowRoot) return 'no-about-page';
                    const card = aboutPage.shadowRoot.querySelector('crostini-settings-card');
                    if (!card || !card.shadowRoot) return 'no-crostini-card';
                    const settingsCard = card.shadowRoot.querySelector('settings-card');
                    const header = settingsCard ? settingsCard.getAttribute('header-text') : '';
                    const label = card.shadowRoot.querySelector('#crostini .start')?.innerText?.split('\\n')[0]?.trim();
                    const btn = card.shadowRoot.querySelector('#enableCrostiniButton');
                    if (!btn || btn.disabled) return 'no-or-disabled-btn:' + header + ':' + label;
                    const btnText = btn.innerText.trim();
                    btn.click();
                    return 'CLICKED_SETUP:' + header + ' | ' + label + ' | ' + btnText;
                })()""")
                if isinstance(nav_res, str) and nav_res.startswith("CLICKED_SETUP:"):
                    log(f"  OS Settings UI action: {nav_res}")
                    break
                time.sleep(0.5)
            else:
                raise RuntimeError(f"Failed to click Set up button in OS Settings: {nav_res}")
        finally:
            settings_conn.close()

        installer_conn: CDPConnection | None = None
        for _ in range(40):
            for tgt in self.list_cdp_targets():
                if (
                    "chrome://crostini-installer" in tgt.get("url", "")
                    and "webSocketDebuggerUrl" in tgt
                ):
                    installer_conn = CDPConnection(tgt["webSocketDebuggerUrl"])
                    break
            if installer_conn is not None:
                break
            time.sleep(0.5)
        if installer_conn is None:
            raise RuntimeError("`chrome://crostini-installer` dialog did not open after clicking Set up")

        try:
            for _ in range(30):
                step1 = installer_conn.eval_js("""(() => {
                    const app = document.querySelector('crostini-installer-app');
                    if (!app || !app.shadowRoot) return 'no-app';
                    const nextBtn = app.shadowRoot.querySelector('#next');
                    if (!nextBtn || nextBtn.hidden) return 'no-next';
                    nextBtn.click();
                    return 'CLICKED_NEXT';
                })()""")
                if step1 == "CLICKED_NEXT":
                    log("  Clicked `Next` in `chrome://crostini-installer`.")
                    break
                time.sleep(0.5)
            else:
                raise RuntimeError("Failed to click `#next` in `chrome://crostini-installer`")

            for _ in range(30):
                step2 = installer_conn.eval_js(f"""(() => {{
                    const app = document.querySelector('crostini-installer-app');
                    if (!app || !app.shadowRoot) return 'no-app';
                    const input = app.shadowRoot.querySelector('#username');
                    const installBtn = app.shadowRoot.querySelector('#install');
                    if (!input || !installBtn || installBtn.hidden) return 'no-input-or-install';
                    input.value = {json.dumps(username)};
                    input.dispatchEvent(new Event('input', {{ bubbles: true, composed: true }}));
                    input.dispatchEvent(new Event('change', {{ bubbles: true, composed: true }}));
                    if (installBtn.disabled) return 'install-disabled';
                    installBtn.click();
                    return 'CLICKED_INSTALL:' + input.value;
                }})()""")
                if isinstance(step2, str) and step2.startswith("CLICKED_INSTALL:"):
                    timeline.mark_install_clicked(username)
                    log(f"  Clicked `Install` in `chrome://crostini-installer` ({step2}).")
                    break
                time.sleep(0.5)
            else:
                raise RuntimeError(
                    f"Failed to set username and click `#install` in `chrome://crostini-installer`: {step2}"
                )

            log("  Waiting for `chrome://crostini-installer` to finish provisioning `termina`...")
            t0 = time.monotonic()
            last_status: dict[str, str] = {"err": "", "installing": ""}
            while time.monotonic() - t0 < 420:
                timeline.check_no_fatal_error()
                targets = self.list_cdp_targets()
                installer_open = any(
                    "chrome://crostini-installer" in x.get("url", "") for x in targets
                )
                if not installer_open:
                    if last_status.get("err"):
                        raise RuntimeError(
                            "`chrome://crostini-installer` closed with an error displayed: "
                            f"{last_status['err']} (last progress: {last_status.get('installing')!r})"
                        )
                    elapsed = time.monotonic() - t0
                    timeline.record_ui(
                        "InstallerClosed",
                        f"closed after {elapsed:.1f}s (last_progress={last_status.get('installing')!r})",
                    )
                    term_deadline = time.monotonic() + 20.0
                    vmshell_tgt: dict | None = None
                    while time.monotonic() < term_deadline:
                        for x in self.list_cdp_targets():
                            if "chrome-untrusted://terminal/html/terminal.html?command=vmshell" in x.get(
                                "url", ""
                            ):
                                vmshell_tgt = x
                                break
                        if vmshell_tgt is not None:
                            break
                        time.sleep(0.5)
                    if vmshell_tgt is None:
                        raise RuntimeError(
                            "`chrome://crostini-installer` closed after "
                            f"{elapsed:.1f}s (last progress: {last_status.get('installing')!r}), "
                            "but the ChromeOS Terminal app (`chrome-untrusted://terminal` vmshell tab) did not open"
                        )
                    log(
                        f"  `chrome://crostini-installer` completed and closed in {elapsed:.1f}s "
                        f"(last progress: {last_status.get('installing')!r}, "
                        f"Terminal app vmshell target={vmshell_tgt.get('id')})."
                    )
                    return vmshell_tgt
                try:
                    status = installer_conn.eval_js("""(() => {
                        const app = document.querySelector('crostini-installer-app');
                        if (!app || !app.shadowRoot) return null;
                        const err = app.shadowRoot.querySelector('#error-message:not([hidden]) div')?.innerText?.trim()
                            || app.shadowRoot.querySelector('#error-message div')?.innerText?.trim();
                        const installing = app.shadowRoot.querySelector('#installing-message div')?.innerText?.trim();
                        return { err: err || '', installing: installing || '' };
                    })()""")
                    if isinstance(status, dict):
                        if status.get("installing"):
                            last_status["installing"] = status["installing"]
                        if status.get("err"):
                            last_status["err"] = status["err"]
                            raise RuntimeError(
                                f"`chrome://crostini-installer` failed with UI error: {status['err']} "
                                f"(last progress: {last_status.get('installing')!r})"
                            )
                except RuntimeError as exc:
                    if "`chrome://crostini-installer` failed with UI error:" in str(exc):
                        raise
                    # If the installer dialog closed while `eval_js` was in flight, the next loop
                    # iteration handles `not installer_open`; if it is still open, fail immediately.
                    still_open = any(
                        "chrome://crostini-installer" in x.get("url", "")
                        for x in self.list_cdp_targets()
                    )
                    if still_open:
                        raise
                except Exception:
                    still_open = any(
                        "chrome://crostini-installer" in x.get("url", "")
                        for x in self.list_cdp_targets()
                    )
                    if still_open:
                        raise
                time.sleep(1.5)
            raise TimeoutError(
                "Timed out waiting for `chrome://crostini-installer` to finish "
                f"(last status: {last_status!r})"
            )
        finally:
            installer_conn.close()

    def _open_fresh_terminal_from_home(self, old_target_ids: set[str]) -> CroshTab:
        """Clicks `penguin` in `chrome-untrusted://terminal/html/terminal.html#home` to launch a fresh Terminal tab."""
        home_tgt: dict | None = None
        for tgt in self.list_cdp_targets():
            if "chrome-untrusted://terminal/html/terminal.html#home" in tgt.get("url", ""):
                home_tgt = tgt
                break
        if home_tgt is None:
            raise RuntimeError(
                "Could not find `chrome-untrusted://terminal/html/terminal.html#home` target to relaunch Terminal"
            )
        home_conn = CDPConnection(home_tgt["webSocketDebuggerUrl"])
        try:
            for _ in range(30):
                click_res = home_conn.eval_js("""(() => {
                    const app = document.querySelector('terminal-home-app');
                    if (!app || !app.shadowRoot) return 'no-app';
                    const links = Array.from(app.shadowRoot.querySelectorAll('a[href*="command=vmshell"]'));
                    if (!links.length) return 'no-links';
                    const href = links[0].getAttribute('href');
                    links[0].click();
                    return 'CLICKED:' + href;
                })()""")
                if isinstance(click_res, str) and click_res.startswith("CLICKED:"):
                    log(f"  [Terminal-Home] Launched fresh Terminal tab via `{click_res}`")
                    break
                time.sleep(0.5)
            else:
                raise RuntimeError(f"Failed to click penguin container in Terminal Home: {click_res}")
        finally:
            home_conn.close()

        deadline = time.monotonic() + 20.0
        while time.monotonic() < deadline:
            for tgt in self.list_cdp_targets():
                tid = tgt.get("id", "")
                if (
                    tid not in old_target_ids
                    and "chrome-untrusted://terminal/html/terminal.html?command=vmshell" in tgt.get("url", "")
                    and "webSocketDebuggerUrl" in tgt
                ):
                    log(f"  Attached to fresh Terminal vmshell tab (target={tid})")
                    return CroshTab("Terminal-App-Fresh", CDPConnection(tgt["webSocketDebuggerUrl"]))
            time.sleep(0.4)
        raise RuntimeError("Timed out waiting for fresh Terminal vmshell tab after clicking penguin in Terminal Home")

    def verify_terminal_app_with_readiness_gate(
        self,
        initial_vmshell_tgt: dict,
        username: str,
        timeline: InitTimelineRecorder,
        throttler: HostQemuCpuThrottler | None = None,
    ) -> None:
        """Observes the installer-opened Terminal tab, gates on `ContainerStarted`, and verifies the Terminal shell."""
        initial_tid = initial_vmshell_tgt["id"]
        initial_tab = CroshTab(
            "Terminal-App-Initial", CDPConnection(initial_vmshell_tgt["webSocketDebuggerUrl"])
        )
        active_tab: CroshTab | None = None
        try:
            log("  Observing installer-opened ChromeOS Terminal app window...")
            obs_deadline = time.monotonic() + 120.0
            initial_reached_prompt = False
            initial_first_output_logged = False
            initial_final_buffer = ""
            while time.monotonic() < obs_deadline:
                timeline.check_no_fatal_error()
                txt = initial_tab.get_text()
                initial_final_buffer = txt
                if not initial_first_output_logged and txt.strip():
                    initial_first_output_logged = True
                    first_ln = txt.strip().splitlines()[0][:140]
                    timeline.record_ui("InitialTerminalFirstOutput", first_ln)
                if f"[{username}@" in txt and txt.rstrip().endswith("$"):
                    initial_reached_prompt = True
                    break
                if (
                    txt.strip() == KNOWN_INITIAL_TERMINAL_TIMEOUT_ERROR
                    or "Launching vmshell failed:" in txt
                    or "[process exited" in txt
                    or "ERROR vsh:" in txt
                ):
                    break
                time.sleep(0.5)

            if initial_reached_prompt:
                # Ensure ContainerStarted is also recorded on the timeline
                cs_rel = timeline.wait_for_container_started(timeout=60.0)
                if throttler is not None:
                    throttler.stop()
                obs_rel = timeline.record_ui(
                    "InitialTerminalObserved",
                    f"reached prompt [{username}@penguin]$ "
                    f"({timeline._rel_mono() - cs_rel:+.1f}s relative to ContainerStarted)",
                )
                log(
                    f"  [Terminal-App-Initial] Reached prompt at t+{obs_rel:.1f}s "
                    f"(ContainerStarted at t+{cs_rel:.1f}s)."
                )
                active_tab = initial_tab
            else:
                cs_already_fired = timeline.is_container_started()
                snippet = initial_final_buffer.strip().replace("\n", " | ")
                obs_rel = timeline.record_ui(
                    "InitialTerminalObserved",
                    f"no prompt (container_started_already={cs_already_fired}): {snippet[:200]}",
                )
                log(
                    f"  WARNING: Installer-opened Terminal tab did not reach prompt at t+{obs_rel:.1f}s "
                    f"(ContainerStarted already fired={cs_already_fired}).\n"
                    f"  Installer-opened Terminal buffer:\n{initial_final_buffer}"
                )
                log("  Waiting on D-Bus readiness gate: `VmCicerone.ContainerStarted` (termina/penguin)...")
                cs_rel = timeline.wait_for_container_started(timeout=300.0)
                if throttler is not None:
                    throttler.stop()
                timeline.scrape_host_logs()
                classify_initial_terminal_failure(
                    initial_buffer=initial_final_buffer,
                    entries=timeline.all_entries(),
                    container_started_rel_sec=cs_rel,
                )
                log(
                    f"  Verified known slow-runner initial Terminal error-50 timeout before "
                    f"`VmCicerone.ContainerStarted` (t+{cs_rel:.1f}s). "
                    "Relaunching fresh Terminal tab from Terminal Home (`#home`)..."
                )
                fresh_tab = self._open_fresh_terminal_from_home({initial_tid})
                timeline.record_ui(
                    "FreshTerminalLaunched",
                    "Clicked penguin in chrome-untrusted://terminal/html/terminal.html#home",
                )
                active_tab = fresh_tab
                try:
                    fresh_timeout = 180.0
                    fresh_deadline = time.monotonic() + fresh_timeout
                    fresh_first_output_logged = False
                    while time.monotonic() < fresh_deadline:
                        timeline.check_no_fatal_error()
                        ftxt = fresh_tab.get_text()
                        if not fresh_first_output_logged and ftxt.strip():
                            fresh_first_output_logged = True
                            first_ln = ftxt.strip().splitlines()[0][:140]
                            fo_rel = timeline.record_ui("FreshTerminalFirstOutput", first_ln)
                            log(f"  [Terminal-App-Fresh] First output at t+{fo_rel:.1f}s: {first_ln}")
                        if f"[{username}@" in ftxt and ftxt.rstrip().endswith("$"):
                            pr_rel = timeline.record_ui(
                                "FreshTerminalPromptReached",
                                f"reached prompt [{username}@penguin]$",
                            )
                            log(f"  [Terminal-App-Fresh] Reached prompt at t+{pr_rel:.1f}s.")
                            break
                        if (
                            "Launching vmshell failed:" in ftxt
                            or "[process exited" in ftxt
                            or "ERROR vsh:" in ftxt
                        ):
                            raise RuntimeError(
                                "Fresh Terminal tab failed even after ContainerStarted:\n" + ftxt
                            )
                        time.sleep(0.5)
                    else:
                        raise TimeoutError(
                            f"Timed out ({fresh_timeout:.0f}s) waiting for fresh Terminal tab prompt "
                            f"after ContainerStarted. Buffer:\n{fresh_tab.get_text()}"
                        )
                except Exception:
                    fresh_tab.close()
                    raise

            # Run interactive command in the active Terminal app tab
            assert active_tab is not None
            marker = f"TERM_USER_{int(time.monotonic() * 1000)}="
            active_tab.send_line(f'echo "{marker}$(id -nu)"')
            active_tab.wait_for(
                lambda txt: f"\n{marker}{username}" in txt and txt.rstrip().endswith("$"),
                timeout=30,
                desc=f"`id -nu` == {username} in {active_tab.label}",
            )
            ver_rel = timeline.record_ui(
                "TerminalPromptVerified",
                f"Confirmed `id -nu` == {username!r} in {active_tab.label}",
            )
            log(f"  [{active_tab.label}] Verified interactive shell user `{username}` at t+{ver_rel:.1f}s")
        finally:
            if throttler is not None:
                throttler.stop()
            initial_tab.close()
            if active_tab is not None and active_tab is not initial_tab:
                active_tab.close()

    def _wait_for_new_guest_prompt(
        self, tab: CroshTab, prev_prompts: int, username: str, timeout: float, desc: str
    ) -> None:
        def _check(txt: str) -> bool:
            if "ERROR - ERROR: command failed" in txt.split("vsh termina penguin")[-1]:
                raise RuntimeError(
                    f"`vsh termina penguin` failed in {tab.label} (after ContainerStarted!):\n{txt}"
                )
            return txt.count(f"[{username}@") > prev_prompts and txt.rstrip().endswith("$")

        tab.wait_for(_check, timeout=timeout, desc=desc)

    def _assert_guest_shell_in_crosh(self, tab: CroshTab, expected_username: str) -> None:
        """Runs `id -nu` inside the active guest shell in `tab` and exits back to `crosh>`."""
        marker = f"USER_CHECK_{int(time.monotonic() * 1000)}="
        prev_crosh_prompts = tab.get_text().count("crosh>")
        tab.send_line(f'echo "{marker}$(id -nu)"')
        tab.wait_for(
            lambda txt: f"\n{marker}{expected_username}" in txt
            and txt.rstrip().endswith("$"),
            timeout=30,
            desc=f"`id -nu` == {expected_username} in {tab.label}",
        )
        log(f"  [{tab.label}] Confirmed guest shell user via crosh UI: `{expected_username}`")
        tab.send_line("exit")
        tab.wait_for(
            lambda txt: txt.count("crosh>") > prev_crosh_prompts
            and txt.rstrip().endswith("crosh>"),
            timeout=30,
            desc=f"exit guest shell back to crosh> in {tab.label}",
        )

    def test_flow_termina(
        self, readme_cmds: ReadmeCommands, username: str = "terminauser"
    ) -> None:
        assert self.owner_hash
        h = self.owner_hash
        log("=== Starting Flow: `termina` VM + ChromeOS Settings UI Installer ===")
        throttler = HostQemuCpuThrottler(
            self.pid_file,
            self.cpu_quota_pct,
            initial_delay_sec=0.0 if self.throttle_from_vm_start else 3.0,
        )
        timeline = InitTimelineRecorder(
            self,
            h,
            expected_username=username,
            on_vm_started=throttler.start,
        )
        crosh = self.open_crosh_tab("Termina-Crosh")
        failed = False
        try:
            log("Step 1: Running `vmc create` command from README.md in crosh...")
            crosh.run_crosh_cmd(readme_cmds.termina_create, timeout=180)

            log("Step 2: Starting passive D-Bus init timeline monitor & driving ChromeOS Settings UI...")
            timeline.start()
            initial_vmshell_tgt = self.run_settings_crostini_installer_ui(
                username=username, timeline=timeline, throttler=throttler
            )

            log("Step 3: Verifying ChromeOS Terminal app (`chrome-untrusted://terminal`) gated on `ContainerStarted`...")
            self.verify_terminal_app_with_readiness_gate(
                initial_vmshell_tgt=initial_vmshell_tgt,
                username=username,
                timeline=timeline,
                throttler=throttler,
            )

            log(f"Step 4: Verifying README crosh shell entry (`{readme_cmds.termina_reentry_vsh}`, single attempt)...")
            prev_guest_prompts = crosh.get_text().count(f"[{username}@")
            log(f"  [{crosh.label}] crosh> {readme_cmds.termina_reentry_vsh}")
            crosh.send_line(readme_cmds.termina_reentry_vsh)
            self._wait_for_new_guest_prompt(
                crosh,
                prev_guest_prompts,
                username,
                timeout=30,
                desc=f"`{readme_cmds.termina_reentry_vsh}` shell prompt for `{username}`",
            )
            self._assert_guest_shell_in_crosh(crosh, expected_username=username)
            timeline.record_ui(
                "CroshVshVerified",
                f"`{readme_cmds.termina_reentry_vsh}` -> `id -nu` == {username!r}",
            )

            log("Step 5: Collecting read-only D-Bus/UMA timeline & verifying in-guest systemd state...")
            timeline.stop_and_collect(strict_dbus=True)
            log("\n" + timeline.format_report(include_raw_logs=False))
            self.verify_guest_user_session("termina", expected_username=username)
        except Exception:
            failed = True
            throttler.stop()
            try:
                timeline.stop_and_collect(strict_dbus=False)
                log("\n" + timeline.format_report(include_raw_logs=True))
            except Exception as diag_exc:
                log(f"Failed collecting timeline diagnostics: {diag_exc}")
            raise
        finally:
            throttler.stop()
            crosh.close()
            if not failed:
                self.ssh(
                    f"sudo -u chronos CROS_USER_ID_HASH={h} VMC_NONINTERACTIVE=1 vmc stop termina"
                )
                self.ssh(
                    f"sudo -u chronos CROS_USER_ID_HASH={h} VMC_NONINTERACTIVE=1 vmc destroy termina"
                )
        log("=== Flow (`termina`) PASSED ===")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--self-test",
        action="store_true",
        help="Run fast offline self-test of README command extraction, vendored protos, and D-Bus parsers",
    )
    parser.add_argument(
        "--readme",
        type=Path,
        default=DEFAULT_README_PATH,
        help=f"Path to README.md (default: {DEFAULT_README_PATH})",
    )
    parser.add_argument(
        "--baguette-image",
        type=Path,
        default=Path("out/image/baguette_arch_rootfs.img.zst"),
        help="Path to baguette_arch_rootfs.img.zst to test",
    )
    parser.add_argument(
        "--cros-image",
        type=Path,
        default=None,
        help="Optional path to pre-extracted chromiumos_test_image.bin",
    )
    parser.add_argument(
        "--ssh-key",
        type=Path,
        default=None,
        help="Optional path to ChromeOS testing_rsa SSH private key",
    )
    parser.add_argument(
        "--cache-dir",
        type=Path,
        default=Path("/tmp/cros-vm-cache"),
        help="Cache directory for downloaded ChromeOS VM image and SSH key",
    )
    parser.add_argument(
        "--qemu-bin",
        default=os.environ.get("QEMU_BIN", "qemu-system-x86_64"),
        help="Path to qemu-system-x86_64 binary",
    )
    parser.add_argument(
        "--qemu-bios-dir",
        default=os.environ.get("QEMU_BIOS_DIR"),
        help="Optional path to QEMU BIOS/firmware directory (-L)",
    )
    parser.add_argument(
        "--qemu-smp",
        type=int,
        default=None,
        help="Override QEMU vCPU count (-smp) for testing slow/constrained runners",
    )
    parser.add_argument(
        "--qemu-ram-gb",
        type=int,
        default=None,
        help="Override QEMU RAM in GiB (-m) for testing constrained runners",
    )
    parser.add_argument(
        "--qemu-cpu-quota-pct",
        type=int,
        default=None,
        help="Optional host-side CPU duty-cycle quota (5..100%%) applied during installer to simulate slow CI runners",
    )
    parser.add_argument(
        "--qemu-throttle-from-vm-start",
        action="store_true",
        help="Start --qemu-cpu-quota-pct throttling immediately at VmStartingUpSignal (0s delay) so inner crosvm boot and SetUpVmUser #1 are also throttled",
    )
    args = parser.parse_args()

    if args.self_test:
        run_self_test(args.readme)
        return 0

    protos = load_cros_protos()
    log(
        f"Verified vendored ChromiumOS protos: board={protos.metadata['board']} "
        f"release={protos.metadata['cros_release']} "
        f"platform2={protos.metadata['platform2_revision']}"
    )

    readme_cmds = extract_readme_commands(args.readme)
    if not args.baguette_image.exists():
        raise FileNotFoundError(f"Baguette image not found: {args.baguette_image}")

    args.cache_dir.mkdir(parents=True, exist_ok=True)
    ssh_key = args.ssh_key or ensure_testing_rsa(args.cache_dir)
    ssh_key.chmod(0o600)
    cros_image = args.cros_image or ensure_cros_image(args.cache_dir, protos.metadata)

    with tempfile.TemporaryDirectory(prefix="cros-e2e-", dir=args.cache_dir) as tmp_dir:
        vm = ChromeOSVM(
            base_image=cros_image,
            ssh_key=ssh_key,
            work_dir=Path(tmp_dir),
            qemu_bin=args.qemu_bin,
            qemu_bios_dir=args.qemu_bios_dir,
            ram_gb=args.qemu_ram_gb,
            smp=args.qemu_smp,
            cpu_quota_pct=args.qemu_cpu_quota_pct,
            throttle_from_vm_start=args.qemu_throttle_from_vm_start,
        )
        try:
            vm.start()
            _ = vm.prepare_nested_vm_host_and_login(args.baguette_image)
            vm.test_flow_termina(readme_cmds)
            log("ALL REQUESTED USER FLOWS PASSED END-TO-END!")
            return 0
        finally:
            vm.stop()


if __name__ == "__main__":
    sys.exit(main())
