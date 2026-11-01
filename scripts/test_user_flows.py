#!/usr/bin/env python3
"""End-to-end verification of the arch-baguette ChromeOS UI user setup flow in a ChromeOS VM.

Drives the documented `README.md` `termina` + ChromeOS Settings Linux installer flow over
Chrome DevTools Protocol (CDP), gates Terminal readiness on `VmCicerone.ContainerStarted`,
verifies `crosh` `vsh termina penguin` re-entry and guest UID/GID/group/`cros-garcon` contracts,
and records a passive D-Bus, UMA, log, and host/ChromeOS resource timeline.
"""

from __future__ import annotations

import argparse
import base64
import calendar
import dataclasses
import hashlib
import json
import math
import os
import re
import shlex
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any, Callable, Iterable, TypeVar

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

        proto_files = [
            str(proto_dir / "arc/arc.proto"),
            str(proto_dir / "vm_applications/apps.proto"),
            str(proto_dir / "vm_concierge/concierge_service.proto"),
            str(proto_dir / "vm_cicerone/cicerone_service.proto"),
        ]
        with tempfile.TemporaryDirectory(prefix="cros-protos-") as tmp_dir:
            rc = protoc.main(
                [
                    "grpc_tools.protoc",
                    f"-I{proto_dir}",
                    f"--python_out={tmp_dir}",
                    *proto_files,
                ]
            )
            if rc != 0:
                raise RuntimeError(f"grpc_tools.protoc failed with exit code {rc}")

            sys.path.insert(0, tmp_dir)
            try:
                import importlib

                importlib.invalidate_caches()
                concierge_pb2 = importlib.import_module("vm_concierge.concierge_service_pb2")
                cicerone_pb2 = importlib.import_module("vm_cicerone.cicerone_service_pb2")
            finally:
                sys.path.remove(tmp_dir)

        loaded = CrosProtoModules(
            metadata=meta,
            concierge_pb2=concierge_pb2,
            cicerone_pb2=cicerone_pb2,
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


class _DbusByteArrayParser:
    """Shared state machine for `dbus-print-message.c` byte-array bodies (`array of bytes [...]` or empty `array [\\n]`)."""

    def __init__(self, context: str) -> None:
        self.context = context
        self.state = "WAIT_OPEN"
        self._hex_tokens: list[str] = []

    def feed_line(self, line: str) -> bytes | None:
        if self.state == "DONE":
            raise ValueError(
                f"{self.context}: unexpected extra line after closing ']': {line!r}"
            )
        if self.state == "WAIT_OPEN":
            # In dbus-print-message.c, a 0-length `ay` has subiter arg_type == DBUS_TYPE_INVALID,
            # printing `   array [\n   ]` instead of `   array of bytes [`.
            if line == "   array [":
                self.state = "WAIT_EMPTY_CLOSE"
                return None
            if not line.startswith("   array of bytes ["):
                raise ValueError(
                    f"{self.context}: expected '   array of bytes [' (or empty '   array ['), got {line!r}"
                )
            after_open = line.split("[", 1)[1]
            if "]" in after_open:
                before_close, after_close = after_open.split("]", 1)
                if after_close.strip():
                    raise ValueError(
                        f"{self.context}: unexpected trailing text after ']': {line!r}"
                    )
                self._hex_tokens.extend(_parse_hex_byte_tokens(before_close.split(), self.context, line))
                self.state = "DONE"
                return bytes.fromhex("".join(self._hex_tokens))
            self._hex_tokens.extend(_parse_hex_byte_tokens(after_open.split(), self.context, line))
            self.state = "IN_ARRAY"
            return None

        if self.state == "WAIT_EMPTY_CLOSE":
            if line != "   ]":
                raise ValueError(
                    f"{self.context}: expected exact '   ]' closing empty '   array [', got {line!r}"
                )
            self.state = "DONE"
            return b""

        if self.state == "IN_ARRAY":
            if not line.startswith("   "):
                raise ValueError(f"{self.context}: expected indented array line, got {line!r}")
            if "]" in line:
                before_close, after_close = line.split("]", 1)
                if after_close.strip():
                    raise ValueError(
                        f"{self.context}: unexpected trailing text after ']': {line!r}"
                    )
                self._hex_tokens.extend(_parse_hex_byte_tokens(before_close.split(), self.context, line))
                self.state = "DONE"
                return bytes.fromhex("".join(self._hex_tokens))
            toks = line.split()
            if not toks:
                raise ValueError(f"{self.context}: empty line inside array of bytes")
            self._hex_tokens.extend(_parse_hex_byte_tokens(toks, self.context, line))
            return None

        raise AssertionError(f"Unreachable _DbusByteArrayParser state: {self.state!r}")

    def ensure_done(self) -> None:
        if self.state != "DONE":
            raise ValueError(
                f"{self.context}: unclosed byte array body (state={self.state})"
            )


def parse_dbus_send_byte_array(output: str, context: str = "dbus-send") -> bytes:
    """Strictly parses `dbus-send --print-reply` output containing a single `array of bytes [...]` (or empty `array [\\n]`)."""
    non_empty = [ln.rstrip("\r\n") for ln in output.splitlines() if ln.strip()]
    if len(non_empty) < 2:
        raise ValueError(f"{context}: truncated or empty dbus-send output:\n{output}")
    if not _DBUS_METHOD_RETURN_RE.match(non_empty[0].strip()):
        raise ValueError(
            f"{context}: expected 'method return ...' header on line 1, got {non_empty[0]!r}"
        )
    parser = _DbusByteArrayParser(context)
    result: bytes | None = None
    for ln in non_empty[1:]:
        out = parser.feed_line(ln)
        if out is not None:
            result = out
    parser.ensure_done()
    assert result is not None
    return result


class DbusMonitorSignalParser:
    """Strict line-by-line parser for `dbus-monitor --system` signal blocks."""

    def __init__(self) -> None:
        self._state: str = "IDLE"
        self._cur_iface: str = ""
        self._cur_member: str = ""
        self._body_parser: _DbusByteArrayParser | None = None

    def _ensure_not_mid_signal(self, reason: str) -> None:
        if self._state in ("WAIT_DBUS_NAME_STRING", "IN_BODY"):
            raise ValueError(
                f"dbus-monitor signal {self._cur_iface}.{self._cur_member} ended "
                f"before body completed ({reason}, state={self._state})"
            )

    def feed_line(self, raw_line: str) -> tuple[str, str, bytes] | None:
        line = raw_line.rstrip("\r\n")
        if not line.strip():
            return None

        if not line[0].isspace():
            self._ensure_not_mid_signal(f"next line: {line!r}")
            if not line.startswith("signal "):
                raise ValueError(f"Unexpected top-level dbus-monitor line: {line!r}")
            m = _DBUS_SIGNAL_HEADER_RE.match(line)
            if not m:
                raise ValueError(f"Malformed dbus-monitor signal header: {line!r}")
            _path, iface, member = m.group(1), m.group(2), m.group(3)
            self._cur_iface = iface
            self._cur_member = member
            if iface == "org.freedesktop.DBus" and member in ("NameAcquired", "NameLost"):
                self._state = "WAIT_DBUS_NAME_STRING"
                self._body_parser = None
                return None
            if (iface, member) not in MONITORED_DBUS_SIGNALS:
                raise ValueError(
                    f"Unexpected D-Bus signal {iface}.{member} on dbus-monitor stream: {line!r}"
                )
            self._state = "IN_BODY"
            self._body_parser = _DbusByteArrayParser(f"dbus-monitor({iface}.{member})")
            return None

        ctx = f"dbus-monitor({self._cur_iface}.{self._cur_member})"
        if self._state == "IDLE":
            raise ValueError(f"Indented dbus-monitor line before any signal header: {line!r}")
        if self._state == "AFTER_BODY":
            raise ValueError(
                f"{ctx}: unexpected extra body line after signal body completed: {line!r}"
            )
        if self._state == "WAIT_DBUS_NAME_STRING":
            m_name = re.match(r'^   string "(:[^"]+)"$', line)
            if not m_name:
                raise ValueError(f"{ctx}: expected '   string \":1.xxx\"' body line, got {line!r}")
            self._state = "AFTER_BODY"
            return (self._cur_iface, self._cur_member, m_name.group(1).encode("utf-8"))

        assert self._state == "IN_BODY" and self._body_parser is not None
        parsed_bytes = self._body_parser.feed_line(line)
        if parsed_bytes is not None:
            self._state = "AFTER_BODY"
            return (self._cur_iface, self._cur_member, parsed_bytes)
        return None

    def finish(self) -> None:
        self._ensure_not_mid_signal("EOF")


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


def _fmt_rel_t(rel_sec: float) -> str:
    sign = "+" if rel_sec >= 0.0 else "-"
    return f"t{sign}{abs(rel_sec):6.1f}s"


def classify_initial_terminal_failure(
    initial_buffer: str,
    entries: list[TimelineEntry],
    container_started_rel_sec: float,
) -> None:
    """Allowlists ONLY the single proven slow-runner initial Terminal timeout; hard-fails everything else.

    Recovery via a fresh Terminal tab is permitted if and only if ALL hold, using
    single-clock-domain ordering comparisons (never comparing host `CLOCK_MONOTONIC` UI/D-Bus
    timestamps directly against ChromeOS VM `CLOCK_REALTIME` log timestamps):
      (a) `initial_buffer.strip()` equals `KNOWN_INITIAL_TERMINAL_TIMEOUT_ERROR`.
      (b) Host `CLOCK_MONOTONIC` domain (`ui`/`dbus`): `InstallerClosed` occurred strictly
          before `ContainerStarted` (`ic_rel < container_started_rel_sec`).
      (c) ChromeOS VM `CLOCK_REALTIME` log domain (`concierge`/`chrome`/`cicerone`):
          `SetUpVmUser` call #1 started and completed (`SetUpVmUserDone` call #1),
          `SetUpVmUser` call #2 started at/after call #1 completed, the exact 3 error-50
          deadline-exceeded log entries occurred at/after call #2 started, and all 3 occurred
          strictly before `ContainerReadyLog` (`vm_cicerone` container startup completion).
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
    if not (ic_rel < container_started_rel_sec):
        raise RuntimeError(
            f"InstallerClosed ({_fmt_rel_t(ic_rel)}) did not occur strictly before "
            f"ContainerStarted ({_fmt_rel_t(container_started_rel_sec)})"
        )

    setup_calls = [e for e in entries if e.source == "concierge" and e.name == "SetUpVmUser"]
    call1_entries = [e for e in setup_calls if e.detail.startswith("call #1:")]
    if len(call1_entries) != 1:
        raise RuntimeError(
            f"Expected SetUpVmUser call #1 in concierge logs, found {len(call1_entries)} "
            f"(all SetUpVmUser calls: {setup_calls!r})"
        )
    call1_done_entries = [
        e
        for e in entries
        if e.source == "concierge"
        and e.name == "SetUpVmUserDone"
        and e.detail.startswith("call #1 ")
    ]
    if len(call1_done_entries) != 1:
        raise RuntimeError(
            f"Expected SetUpVmUserDone for call #1 in concierge logs, "
            f"found {len(call1_done_entries)}: {call1_done_entries!r}"
        )
    call1_rel = call1_entries[0].rel_sec
    call1_done_rel = call1_done_entries[0].rel_sec
    if not (call1_rel <= call1_done_rel):
        raise RuntimeError(
            f"SetUpVmUser call #1 completion ({_fmt_rel_t(call1_done_rel)}) preceded "
            f"call #1 start ({_fmt_rel_t(call1_rel)})"
        )

    call2_entries = [e for e in setup_calls if e.detail.startswith("call #2:")]
    if len(call2_entries) != 1:
        raise RuntimeError(
            f"Expected SetUpVmUser call #2 in concierge logs for initial Terminal launch, "
            f"found {len(call2_entries)} (all SetUpVmUser calls: {setup_calls!r})"
        )
    call2_rel = call2_entries[0].rel_sec
    if not (call1_done_rel <= call2_rel):
        raise RuntimeError(
            f"SetUpVmUser call #2 ({_fmt_rel_t(call2_rel)}) did not occur at/after "
            f"installer SetUpVmUser call #1 completion ({_fmt_rel_t(call1_done_rel)})"
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
        e
        for e in entries
        if e.source == "cicerone"
        and e.name == "ContainerReadyLog"
        and "container penguin" in e.detail
        and "VM termina" in e.detail
    ]
    if len(container_ready_logs) != 1:
        raise RuntimeError(
            "Expected exactly 1 cicerone ContainerReadyLog for termina/penguin in VM logs, "
            f"got: {container_ready_logs!r}"
        )
    ready_log_rel = container_ready_logs[0].rel_sec

    for fail_entry in (setup_vm_failed[0], baguette_failed[0], restart_failed[0]):
        if not (call2_rel <= fail_entry.rel_sec < ready_log_rel):
            raise RuntimeError(
                f"Failure log {fail_entry.name} at {_fmt_rel_t(fail_entry.rel_sec)} did not occur "
                f"between SetUpVmUser call #2 ({_fmt_rel_t(call2_rel)}) and "
                f"ContainerReadyLog ({_fmt_rel_t(ready_log_rel)}): {fail_entry!r}"
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
    vendor = read_local_host_runner_info().vendor_id
    if vendor == "AuthenticAMD":
        return "Opteron_G4,-invpcid,-tsc-deadline,check,svm=on"
    if vendor == "GenuineIntel":
        return "Haswell-noTSX,-invpcid,-tsc-deadline,check,vmx=on"
    raise RuntimeError(
        f"Unsupported host CPU vendor {vendor!r} in /proc/cpuinfo (expected GenuineIntel or AuthenticAMD)"
    )


def default_vm_ram_gb() -> int:
    """Clamps default VM RAM between 4 GiB and 8 GiB based on host MemAvailable."""
    avail_gib = int(read_local_host_runner_info().mem_avail_mib // 1024)
    return min(8, max(4, avail_gib - 2))


def assert_host_kvm_available() -> None:
    kvm_path = Path("/dev/kvm")
    if not kvm_path.exists():
        raise RuntimeError("/dev/kvm does not exist on the host; KVM is required for nested VM tests")
    if not os.access(kvm_path, os.R_OK | os.W_OK):
        raise RuntimeError("/dev/kvm is not readable/writable by the current user (try `sudo chmod 0666 /dev/kvm`)")


def ensure_testing_rsa(cache_dir: Path) -> Path:
    key_path = cache_dir / "testing_rsa"
    if not (key_path.is_file() and key_path.stat().st_size > 0):
        log(f"Downloading public ChromeOS testing_rsa key to {key_path}...")
        cache_dir.mkdir(parents=True, exist_ok=True)
        with urllib.request.urlopen(TESTING_RSA_GITILES_URL, timeout=30) as resp:
            decoded = base64.b64decode(resp.read())
        if not decoded:
            raise RuntimeError(f"Downloaded empty testing_rsa key from {TESTING_RSA_GITILES_URL}")
        fd, tmp_name = tempfile.mkstemp(prefix=".testing_rsa.", dir=cache_dir)
        tmp_path = Path(tmp_name)
        try:
            with os.fdopen(fd, "wb") as f:
                f.write(decoded)
            tmp_path.chmod(0o600)
            os.replace(tmp_path, key_path)
        finally:
            tmp_path.unlink(missing_ok=True)
    key_path.chmod(0o600)
    return key_path


def ensure_cros_image(cache_dir: Path, meta: dict[str, Any]) -> Path:
    board = str(meta["board"])
    cros_release = str(meta["cros_release"])
    img_dir = cache_dir / f"{board}-{cros_release}"
    img_path = img_dir / "chromiumos_test_image.bin"
    if img_path.is_file() and img_path.stat().st_size > 0:
        log(f"Using cached ChromeOS image: {img_path}")
        return img_path

    img_dir.mkdir(parents=True, exist_ok=True)
    img_path.unlink(missing_ok=True)
    url = f"{GCS_ARCHIVE_ROOT}/{board}/{cros_release}/chromiumos_test_image.tar.xz"
    log(f"Stream-extracting {url} into {img_dir} (sparse, atomic)...")
    with tempfile.TemporaryDirectory(prefix=".extract-", dir=img_dir) as stage_dir_str:
        stage_dir = Path(stage_dir_str)
        cmd = f"curl -fL --retry 3 '{url}' | tar --sparse -xJ -C '{stage_dir}'"
        subprocess.run(["bash", "-o", "pipefail", "-c", cmd], check=True)
        staged_img = stage_dir / "chromiumos_test_image.bin"
        if not staged_img.is_file() or staged_img.stat().st_size <= 0:
            raise FileNotFoundError(
                f"Expected non-empty {staged_img.name} after extracting {url}"
            )
        os.replace(staged_img, img_path)
    return img_path


class CDPError(RuntimeError):
    """Structured Chrome DevTools Protocol error including operation, target, step, and elapsed wait."""


class CDPTimeoutError(TimeoutError):
    """Structured Chrome DevTools Protocol timeout including operation, target, step, and elapsed wait."""


class VMCommandTimeoutError(TimeoutError):
    """Structured VM ssh/vsh/scp timeout including operation, step, command summary, and elapsed wait."""


def _summarize_cmd(cmd: str, max_len: int = 120) -> str:
    flat = " ".join(cmd.split())
    return flat if len(flat) <= max_len else (flat[: max_len - 3] + "...")


def format_vm_cmd_error_context(
    *,
    operation: str,
    step: str,
    cmd_summary: str,
    elapsed_sec: float,
    timeout_sec: float,
) -> str:
    return (
        f"operation={operation!r} step={step!r} cmd={cmd_summary!r} "
        f"waited={elapsed_sec:.2f}s (timeout={timeout_sec:.1f}s)"
    )


def _is_ws_timeout_exc(exc: BaseException) -> bool:
    if isinstance(exc, (TimeoutError, socket.timeout)):
        return True
    if isinstance(exc, urllib.error.URLError) and isinstance(
        exc.reason, (TimeoutError, socket.timeout)
    ):
        return True
    cls_name = exc.__class__.__name__
    if "Timeout" in cls_name:
        return True
    msg_low = str(exc).lower()
    return "timed out" in msg_low or "timeout" in msg_low


def format_cdp_error_context(
    *,
    operation: str,
    target_label: str,
    target_url: str,
    target_id: str,
    step: str,
    elapsed_sec: float,
    timeout_sec: float,
) -> str:
    return (
        f"operation={operation!r} target={target_label!r} "
        f"url={target_url!r} target_id={target_id!r} "
        f"step={step!r} waited={elapsed_sec:.2f}s (timeout={timeout_sec:.1f}s)"
    )


class CDPConnection:
    """Thin synchronous Chrome DevTools Protocol client over `websocket-client`."""

    def __init__(
        self,
        ws_url: str,
        timeout: float = 45.0,
        *,
        target_label: str = "cdp-target",
        target_url: str = "",
        target_id: str = "",
        step_getter: Callable[[], str] | None = None,
        connect_fn: Callable[..., Any] | None = None,
    ) -> None:
        self.default_timeout = timeout
        self.target_label = target_label
        self.target_url = target_url or ws_url
        if target_id:
            self.target_id = target_id
        elif "/devtools/" in ws_url:
            self.target_id = ws_url.rstrip("/").rsplit("/", 1)[-1]
        else:
            self.target_id = "<unknown>"
        self._step_getter = step_getter
        self._next_id = 0

        t0 = time.monotonic()
        try:
            if connect_fn is not None:
                self.ws = connect_fn(ws_url, timeout=timeout, suppress_origin=True)
            else:
                import websocket  # Imported lazily so offline unit tests can import this module

                self.ws = websocket.create_connection(
                    ws_url, timeout=timeout, suppress_origin=True
                )
        except Exception as exc:
            elapsed = time.monotonic() - t0
            ctx = self._ctx("WebSocket.connect", elapsed, timeout)
            if _is_ws_timeout_exc(exc):
                raise CDPTimeoutError(
                    f"CDP WebSocket connect timed out ({ctx}): {type(exc).__name__}: {exc}"
                ) from exc
            raise CDPError(
                f"CDP WebSocket connect failed ({ctx}): {type(exc).__name__}: {exc}"
            ) from exc

    @classmethod
    def from_target(
        cls,
        tgt: dict[str, Any],
        *,
        label: str,
        timeout: float = 45.0,
        step_getter: Callable[[], str] | None = None,
        connect_fn: Callable[..., Any] | None = None,
    ) -> CDPConnection:
        return cls(
            str(tgt["webSocketDebuggerUrl"]),
            timeout=timeout,
            target_label=label,
            target_url=str(tgt.get("url", "")),
            target_id=str(tgt.get("id", "")),
            step_getter=step_getter,
            connect_fn=connect_fn,
        )

    def current_step(self) -> str:
        if self._step_getter is not None:
            return self._step_getter()
        return "<unspecified-step>"

    def _ctx(self, operation: str, elapsed_sec: float, timeout_sec: float) -> str:
        return format_cdp_error_context(
            operation=operation,
            target_label=self.target_label,
            target_url=self.target_url,
            target_id=self.target_id,
            step=self.current_step(),
            elapsed_sec=elapsed_sec,
            timeout_sec=timeout_sec,
        )

    def call(
        self,
        method: str,
        params: dict | None = None,
        timeout: float | None = None,
        allow_error: bool = False,
        op_desc: str | None = None,
    ) -> dict:
        eff_timeout = self.default_timeout if timeout is None else timeout
        self._next_id += 1
        req_id = self._next_id
        op = f"{op_desc} [{method}#{req_id}]" if op_desc else f"{method}#{req_id}"
        t0 = time.monotonic()
        deadline = t0 + eff_timeout
        payload = json.dumps({"id": req_id, "method": method, "params": params or {}})
        try:
            self.ws.settimeout(eff_timeout)
            self.ws.send(payload)
        except Exception as exc:
            elapsed = time.monotonic() - t0
            ctx = self._ctx(f"{op} (send)", elapsed, eff_timeout)
            if _is_ws_timeout_exc(exc):
                raise CDPTimeoutError(
                    f"CDP send timed out ({ctx}): {type(exc).__name__}: {exc}"
                ) from exc
            raise CDPError(
                f"CDP send failed ({ctx}): {type(exc).__name__}: {exc}"
            ) from exc

        empty_frames = 0
        while True:
            rem = deadline - time.monotonic()
            if rem <= 0:
                elapsed = time.monotonic() - t0
                raise CDPTimeoutError(
                    f"Timed out waiting for CDP response ({self._ctx(op, elapsed, eff_timeout)})"
                )
            try:
                self.ws.settimeout(max(0.05, rem))
                raw = self.ws.recv()
            except Exception as exc:
                elapsed = time.monotonic() - t0
                ctx = self._ctx(f"{op} (recv)", elapsed, eff_timeout)
                if _is_ws_timeout_exc(exc):
                    raise CDPTimeoutError(
                        f"Timed out waiting for CDP response ({ctx}): {type(exc).__name__}: {exc}"
                    ) from exc
                raise CDPError(
                    f"CDP WebSocket recv failed ({ctx}): {type(exc).__name__}: {exc}"
                ) from exc

            if not raw:
                empty_frames += 1
                if not getattr(self.ws, "connected", True) or empty_frames >= 8:
                    elapsed = time.monotonic() - t0
                    raise CDPError(
                        f"CDP WebSocket closed/EOF while waiting for response "
                        f"({self._ctx(f'{op} (recv)', elapsed, eff_timeout)})"
                    )
                continue
            empty_frames = 0
            try:
                msg = json.loads(raw)
            except json.JSONDecodeError as exc:
                elapsed = time.monotonic() - t0
                raise CDPError(
                    f"Malformed JSON frame from CDP ({self._ctx(op, elapsed, eff_timeout)}): {raw[:200]!r}"
                ) from exc
            if msg.get("id") == req_id:
                if "error" in msg and not allow_error:
                    elapsed = time.monotonic() - t0
                    raise CDPError(
                        f"CDP protocol error ({self._ctx(op, elapsed, eff_timeout)}): {msg['error']}"
                    )
                return msg.get("result", msg)

    def eval_js(
        self,
        expression: str,
        await_promise: bool = False,
        timeout: float | None = None,
        op_desc: str | None = None,
    ) -> Any:
        eff_timeout = self.default_timeout if timeout is None else timeout
        t0 = time.monotonic()
        res = self.call(
            "Runtime.evaluate",
            {
                "expression": expression,
                "returnByValue": True,
                "awaitPromise": await_promise,
            },
            timeout=eff_timeout,
            op_desc=op_desc,
        )
        if "exceptionDetails" in res:
            elapsed = time.monotonic() - t0
            op = op_desc or "Runtime.evaluate"
            raise CDPError(
                f"CDP JavaScript exception ({self._ctx(op, elapsed, eff_timeout)}): {res['exceptionDetails']}"
            )
        return res.get("result", {}).get("value")

    def poll_js(
        self,
        expression: str,
        done_pred: Callable[[Any], bool],
        *,
        op_desc: str,
        timeout: float = 30.0,
        interval: float = 0.5,
    ) -> Any:
        """Evaluates `expression` until `done_pred(val)` holds or raises `CDPTimeoutError`."""
        t0 = time.monotonic()
        deadline = t0 + timeout
        last_val: Any = None
        while time.monotonic() < deadline:
            last_val = self.eval_js(expression, op_desc=op_desc)
            if done_pred(last_val):
                return last_val
            time.sleep(interval)
        ctx = self._ctx(op_desc, time.monotonic() - t0, timeout)
        raise CDPTimeoutError(
            f"Timed out in {op_desc} ({ctx}; last state={last_val!r})"
        )

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

    def get_text(self, timeout: float | None = None) -> str:
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
        return (
            self.conn.eval_js(
                js,
                timeout=timeout,
                op_desc=f"{self.label}.get_text (read xterm buffer)",
            )
            or ""
        )

    def send_line(self, line: str) -> None:
        """Types a command line into xterm.js and presses Enter."""
        short_cmd = line if len(line) <= 48 else (line[:45] + "...")
        self.conn.call(
            "Page.bringToFront",
            op_desc=f"{self.label}.send_line(Page.bringToFront)",
        )
        # Use xterm.js's native paste() to feed the exact string through term.onData
        # -> io.onVTKeystroke -> chrome.terminalPrivate.sendInput without triggering
        # libapps terminal_emulator.js keyCode collisions on ASCII 34/36/39/45/46,
        # then dispatch a real Enter keystroke to submit the line.
        self.conn.eval_js(
            f"""(() => {{
                window.term_.term.focus();
                window.term_.term.paste({json.dumps(line)});
                return true;
            }})()""",
            op_desc=f"{self.label}.send_line(xterm.paste {short_cmd!r})",
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
            op_desc=f"{self.label}.send_line(Enter rawKeyDown)",
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
            op_desc=f"{self.label}.send_line(Enter keyUp)",
        )

    def wait_for(self, predicate, timeout: float = 120.0, desc: str = "output") -> str:
        t0 = time.monotonic()
        deadline = t0 + timeout
        last = ""
        while True:
            rem = deadline - time.monotonic()
            if rem <= 0:
                break
            per_call_timeout = min(self.conn.default_timeout, max(5.0, rem))
            last = self.get_text(timeout=per_call_timeout)
            if predicate(last):
                return last
            sleep_sec = min(0.5, max(0.0, deadline - time.monotonic()))
            if sleep_sec <= 0:
                break
            time.sleep(sleep_sec)
        elapsed = time.monotonic() - t0
        ctx = self.conn._ctx(f"{self.label}.wait_for({desc})", elapsed, timeout)
        raise CDPTimeoutError(
            f"Timed out waiting for {desc} ({ctx}). Last terminal buffer:\n{last}"
        )

    def run_crosh_cmd(self, cmd: str, timeout: float = 180.0) -> str:
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
        if "ERROR - ERROR: command failed" in delta or "Error:" in delta:
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


@dataclasses.dataclass(frozen=True)
class HostRunnerInfo:
    vendor_id: str
    model_name: str
    nproc: int
    mem_total_mib: float
    mem_avail_mib: float


@dataclasses.dataclass(frozen=True)
class CpuStatCounters:
    user: int
    nice: int
    system: int
    idle: int
    iowait: int
    irq: int
    softirq: int
    steal: int
    clk_tck: int = 100

    @property
    def busy_ticks(self) -> int:
        # In Linux fs/proc/stat.c, `guest` and `guest_nice` are already included in `user` and `nice`.
        return self.user + self.nice + self.system + self.irq + self.softirq

    @property
    def total_ticks(self) -> int:
        return self.busy_ticks + self.idle + self.iowait + self.steal


@dataclasses.dataclass(frozen=True)
class CpuDeltaPct:
    busy_pct: float
    iowait_pct: float
    steal_pct: float
    steal_sec: float


@dataclasses.dataclass(frozen=True)
class PsiMetricLine:
    avg10: float
    total_us: int


@dataclasses.dataclass(frozen=True)
class PsiResource:
    some: PsiMetricLine
    full: PsiMetricLine | None


@dataclasses.dataclass(frozen=True)
class CrosTopProc:
    pid: int
    comm: str
    hint: str
    ticks: int


@dataclasses.dataclass(frozen=True)
class CrosResourceSample:
    mono_ts: float
    rel_sec: float
    uptime_sec: float
    nproc: int
    clk_tck: int
    load1: float
    cros_cpu: CpuStatCounters
    psi_cpu: PsiResource
    psi_memory: PsiResource
    psi_io: PsiResource
    mem_total_kib: int
    mem_avail_kib: int
    swap_total_kib: int
    swap_free_kib: int
    dirty_kib: int
    writeback_kib: int
    host_cpu: CpuStatCounters
    host_load1: float
    host_mem_avail_mib: float
    proc_dt_sec: float = 0.0
    top_procs: tuple[CrosTopProc, ...] = ()


# Read-only ChromeOS VM JSONL resource snapshot script executed via `python3 -u` over SSH
# (zero child process forks per sample and immune to mawk sandbox restrictions).
_CROS_RESOURCE_PY_SCRIPT = r"""
import json, os, sys, time

PROC = os.environ.get("CROS_RES_PROC_ROOT", "/proc")
NPROC = os.cpu_count() or 1
CLK_TCK = int(os.sysconf("SC_CLK_TCK"))
SELF_PID = os.getpid()
MEM_KEYS = {"MemTotal", "MemAvailable", "SwapTotal", "SwapFree", "Dirty", "Writeback"}
_prev_uptime = None
_prev_procs = None
_cl_cache = {}

def _clean(s: str, limit: int) -> str:
    return " ".join("".join(c if 32 <= ord(c) < 127 else " " for c in s).split())[:limit]

def _parse_cl(pid: int, raw_cl: bytes) -> tuple[bool, str, str]:
    if pid == SELF_PID:
        return False, "cros_res_sampler", ""
    if not raw_cl:
        return False, "kthread", ""
    first_chunk = raw_cl.split(b"\x00", 1)[0].decode("utf-8", "replace")
    args = (
        first_chunk.split()
        if " --" in first_chunk
        else [a.decode("utf-8", "replace") for a in raw_cl.split(b"\x00") if a]
    )
    if not args:
        return False, "", ""
    arg0 = args[0].rsplit("/", 1)[-1]
    if arg0 == "crosvm":
        sub = "crosvm"
        for i, a in enumerate(args[1:], 1):
            if a in ("run", "device", "devices"):
                nxt = args[i + 1] if a != "run" and i + 1 < len(args) else ""
                sub = f"{a}:{nxt}" if nxt and not nxt.startswith("-") else a
                break
        return True, _clean(sub, 24), arg0
    if arg0 == "chrome":
        ctype = sub = gl = ""
        ext = False
        for a in args[1:]:
            if a.startswith("--type="):
                ctype = a.split("=", 1)[1]
            elif a.startswith("--utility-sub-type="):
                sub = a.split("=", 1)[1].rsplit(".", 1)[-1]
            elif a == "--extension-process":
                ext = True
            elif a.startswith("--use-angle="):
                gl = a.split("=", 1)[1]
            elif a.startswith("--use-gl=") and not gl:
                gl = a.split("=", 1)[1]
        if not ctype:
            return False, "browser", arg0
        tag = sub if ctype == "utility" else ("ext" if ctype == "renderer" and ext else (gl if ctype == "gpu-process" else ""))
        return False, _clean(f"--type={ctype}({tag})" if tag else f"--type={ctype}", 48), arg0
    if "base64.b64decode" in " ".join(args[:4]):
        return False, "cros_res_oneshot", arg0
    return False, _clean(" ".join(args[1:3]), 48), _clean(arg0, 48)

def _scan_procs(uptime_sec: float) -> tuple[float, list[dict]]:
    global _prev_uptime, _prev_procs, _cl_cache
    cur_procs, rows = {}, []
    for ent in os.listdir(PROC):
        if not ent.isdigit():
            continue
        pid = int(ent)
        try:
            with open(f"{PROC}/{ent}/stat", "rb") as f:
                raw = f.read()
            lp, rp = raw.find(b"("), raw.rfind(b") ")
            if lp < 0 or rp < 0:
                continue
            comm = _clean(raw[lp + 1 : rp].decode("utf-8", "replace"), 48) or "?"
            rest = raw[rp + 2 :].split()
            ticks, st = int(rest[11]) + int(rest[12]), int(rest[19])
        except (OSError, ValueError, IndexError):
            continue
        key = (pid, st)
        cur_procs[key] = ticks
        rows.append((key, pid, comm, ticks, st))
    _cl_cache = {k: _cl_cache[k] for k in cur_procs if k in _cl_cache}
    if _prev_procs is None or _prev_uptime is None or uptime_sec <= _prev_uptime:
        _prev_procs, _prev_uptime = cur_procs, uptime_sec
        return 0.0, []
    dt_sec = max(1e-4, round(uptime_sec - _prev_uptime, 4))
    new_floor = max(0, int(_prev_uptime * CLK_TCK) - CLK_TCK)
    cands, c_subs, c_ticks, c_cnt = [], {}, 0, 0
    for key, pid, comm, ticks, st in rows:
        dt = (ticks - _prev_procs[key]) if key in _prev_procs else (ticks if st >= new_floor else 0)
        if dt <= 0:
            continue
        meta = _cl_cache.get(key)
        if meta is None:
            try:
                with open(f"{PROC}/{pid}/cmdline", "rb") as f:
                    raw_cl = f.read(8192)
            except OSError:
                raw_cl = b""
            meta = _cl_cache[key] = _parse_cl(pid, raw_cl)
        is_c, cl_hint, arg0 = meta
        if is_c or comm.startswith("crosvm"):
            c_ticks += dt
            c_cnt += 1
            sub = comm if comm != "crosvm" else (cl_hint or "crosvm")
            c_subs[sub] = c_subs.get(sub, 0) + dt
        else:
            cands.append((dt, pid, comm, cl_hint or (arg0 if arg0 != comm else "")))
    if c_ticks > 0:
        subs = ",".join(k for k, _ in sorted(c_subs.items(), key=lambda kv: (-kv[1], kv[0]))[:3])
        cands.append((c_ticks, 0, "crosvm", _clean(f"{c_cnt}p:{subs}" if subs else f"{c_cnt}p", 48)))
    cands.sort(key=lambda r: (-r[0], r[2], r[1]))
    _prev_procs, _prev_uptime = cur_procs, uptime_sec
    return dt_sec, [{"pid": p, "comm": c, "hint": h, "ticks": t} for t, p, c, h in cands[:5]]

def emit_once() -> None:
    with open(f"{PROC}/uptime", "r", encoding="utf-8") as f:
        uptime_sec = float(f.read().split()[0])
    with open(f"{PROC}/loadavg", "r", encoding="utf-8") as f:
        load1 = float(f.read().split()[0])
    with open(f"{PROC}/stat", "r", encoding="utf-8") as f:
        stat_cpu = f.readline().strip()
    psi = {}
    for p in ("cpu", "memory", "io"):
        pp = f"{PROC}/pressure/{p}"
        if os.path.exists(pp):
            with open(pp, "r", encoding="utf-8") as f:
                psi[p] = [ln.strip() for ln in f.read().splitlines() if ln.strip()]
        else:
            psi[p] = []
    mem = {}
    with open(f"{PROC}/meminfo", "r", encoding="utf-8") as f:
        for ml in f:
            parts = ml.split()
            if len(parts) >= 2:
                k = parts[0].rstrip(":")
                if k in MEM_KEYS:
                    mem[k] = int(parts[1])
    proc_dt_sec, top_procs = _scan_procs(uptime_sec)
    print(json.dumps({
        "nproc": NPROC, "clk_tck": CLK_TCK, "uptime_sec": uptime_sec, "load1": load1,
        "stat_cpu": stat_cpu, "psi": psi, "mem_kib": mem,
        "proc_dt_sec": proc_dt_sec, "top_procs": top_procs,
    }), flush=True)

if len(sys.argv) > 1 and sys.argv[1] == "--loop":
    interval = float(sys.argv[2])
    while True:
        emit_once()
        time.sleep(interval)
else:
    with open(f"{PROC}/uptime", "r", encoding="utf-8") as f:
        _scan_procs(float(f.read().split()[0]))
    time.sleep(float(os.environ.get("CROS_RES_ONESHOT_SEC", "0.25")))
    emit_once()
""".strip()

_CROS_RESOURCE_PY_B64 = base64.b64encode(_CROS_RESOURCE_PY_SCRIPT.encode("utf-8")).decode("ascii")

CROS_RESOURCE_SNAPSHOT_CMD = (
    f"exec python3 -u -c 'import base64; exec(base64.b64decode(\"{_CROS_RESOURCE_PY_B64}\").decode(\"utf-8\"))'"
)

CROS_RESOURCE_SAMPLER_LOOP_CMD = (
    f"exec python3 -u -c 'import base64; exec(base64.b64decode(\"{_CROS_RESOURCE_PY_B64}\").decode(\"utf-8\"))' --loop 6"
)


def parse_host_runner_info(cpuinfo_text: str, meminfo_text: str, nproc: int) -> HostRunnerInfo:
    """Strictly parses host `/proc/cpuinfo`, `/proc/meminfo`, and CPU count."""
    if nproc <= 0:
        raise ValueError(f"Invalid host nproc={nproc}")
    vendor_id = ""
    model_name = ""
    for line in cpuinfo_text.splitlines():
        if ":" not in line:
            continue
        k, v = line.split(":", 1)
        key, val = k.strip(), v.strip()
        if key == "vendor_id" and not vendor_id:
            vendor_id = val
        elif key == "model name" and not model_name:
            model_name = val
        if vendor_id and model_name:
            break
    if not vendor_id:
        raise ValueError("Missing 'vendor_id' in host /proc/cpuinfo")
    if not model_name:
        raise ValueError("Missing 'model name' in host /proc/cpuinfo")

    mem_kv: dict[str, int] = {}
    for line in meminfo_text.splitlines():
        if ":" not in line:
            continue
        k, rest = line.split(":", 1)
        toks = rest.strip().split()
        if toks and toks[0].isdigit():
            mem_kv[k.strip()] = int(toks[0])
    if "MemTotal" not in mem_kv or mem_kv["MemTotal"] <= 0:
        raise ValueError("Missing or invalid 'MemTotal' in host /proc/meminfo")
    if "MemAvailable" not in mem_kv:
        raise ValueError("Missing 'MemAvailable' in host /proc/meminfo")
    return HostRunnerInfo(
        vendor_id=vendor_id,
        model_name=model_name,
        nproc=nproc,
        mem_total_mib=mem_kv["MemTotal"] / 1024.0,
        mem_avail_mib=mem_kv["MemAvailable"] / 1024.0,
    )


def parse_proc_stat_cpu_line(
    stat_text: str, context: str, clk_tck: int = 100
) -> CpuStatCounters:
    """Strictly parses aggregate `cpu ...` line from `/proc/stat`."""
    if clk_tck <= 0:
        raise ValueError(f"{context}: invalid clk_tck={clk_tck}")
    for line in stat_text.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        parts = stripped.split()
        if parts[0] == "cpu":
            if len(parts) < 9:
                raise ValueError(
                    f"{context}: expected >=8 integer fields on aggregate 'cpu' line, got {stripped!r}"
                )
            try:
                vals = [int(x) for x in parts[1:9]]
            except ValueError as exc:
                raise ValueError(f"{context}: non-integer field in {stripped!r}") from exc
            if any(v < 0 for v in vals):
                raise ValueError(f"{context}: negative CPU counter in {stripped!r}")
            return CpuStatCounters(
                user=vals[0],
                nice=vals[1],
                system=vals[2],
                idle=vals[3],
                iowait=vals[4],
                irq=vals[5],
                softirq=vals[6],
                steal=vals[7],
                clk_tck=clk_tck,
            )
    raise ValueError(f"{context}: missing aggregate 'cpu ' line in /proc/stat")


def compute_cpu_delta_pct(start: CpuStatCounters, end: CpuStatCounters) -> CpuDeltaPct:
    """Computes CPU busy/iowait/steal % and stolen CPU-seconds between two `/proc/stat` snapshots."""
    dt = end.total_ticks - start.total_ticks
    if dt < 0:
        raise ValueError(f"CPU total ticks went backwards: start={start.total_ticks} end={end.total_ticks}")
    if dt == 0:
        return CpuDeltaPct(0.0, 0.0, 0.0, 0.0)
    d_busy = max(0, end.busy_ticks - start.busy_ticks)
    d_iow = max(0, end.iowait - start.iowait)
    d_stl = max(0, end.steal - start.steal)
    tck = float(end.clk_tck if end.clk_tck > 0 else 100)
    return CpuDeltaPct(
        busy_pct=100.0 * d_busy / dt,
        iowait_pct=100.0 * d_iow / dt,
        steal_pct=100.0 * d_stl / dt,
        steal_sec=d_stl / tck,
    )


def _parse_psi_line(raw_line: str, context: str) -> tuple[str, PsiMetricLine]:
    parts = raw_line.strip().split()
    if len(parts) != 5 or parts[0] not in ("some", "full"):
        raise ValueError(f"{context}: malformed PSI line {raw_line!r}")
    kind = parts[0]
    kv: dict[str, str] = {}
    for tok in parts[1:]:
        if "=" not in tok:
            raise ValueError(f"{context}: malformed PSI token {tok!r} in {raw_line!r}")
        k, v = tok.split("=", 1)
        kv[k] = v
    for req_k in ("avg10", "avg60", "avg300", "total"):
        if req_k not in kv:
            raise ValueError(f"{context}: missing {req_k!r} in PSI line {raw_line!r}")
    try:
        avg10 = float(kv["avg10"])
        avg60 = float(kv["avg60"])
        avg300 = float(kv["avg300"])
        total_us = int(kv["total"])
    except ValueError as exc:
        raise ValueError(f"{context}: invalid numeric value in PSI line {raw_line!r}") from exc
    if total_us < 0 or avg10 < 0.0 or avg60 < 0.0 or avg300 < 0.0:
        raise ValueError(f"{context}: negative value in PSI line {raw_line!r}")
    return kind, PsiMetricLine(avg10=avg10, total_us=total_us)


def _parse_psi_resource(lines: list[str], name: str, require_full: bool) -> PsiResource:
    ctx = f"/proc/pressure/{name}"
    if not lines or lines == ["MISSING"]:
        raise ValueError(f"{ctx}: missing PSI metrics")
    by_kind: dict[str, PsiMetricLine] = {}
    for ln in lines:
        if not isinstance(ln, str):
            raise ValueError(f"{ctx}: expected string PSI line, got {ln!r}")
        kind, metric = _parse_psi_line(ln, ctx)
        if kind in by_kind:
            raise ValueError(f"{ctx}: duplicate {kind!r} line in {lines!r}")
        by_kind[kind] = metric
    if "some" not in by_kind:
        raise ValueError(f"{ctx}: missing 'some' line in {lines!r}")
    if require_full and "full" not in by_kind:
        raise ValueError(f"{ctx}: missing 'full' line in {lines!r}")
    return PsiResource(some=by_kind["some"], full=by_kind.get("full"))


def read_local_host_runner_info() -> HostRunnerInfo:
    cpuinfo = Path("/proc/cpuinfo").read_text(encoding="utf-8")
    meminfo = Path("/proc/meminfo").read_text(encoding="utf-8")
    nproc = os.cpu_count() or 0
    return parse_host_runner_info(cpuinfo, meminfo, nproc)


def read_local_host_dynamic_sample() -> tuple[CpuStatCounters, float, float]:
    clk_tck = int(os.sysconf("SC_CLK_TCK"))
    stat_txt = Path("/proc/stat").read_text(encoding="utf-8")
    host_cpu = parse_proc_stat_cpu_line(stat_txt, "host /proc/stat", clk_tck=clk_tck)
    load_toks = Path("/proc/loadavg").read_text(encoding="utf-8").split()
    if len(load_toks) < 3:
        raise ValueError(f"Malformed host /proc/loadavg: {load_toks!r}")
    host_load1 = float(load_toks[0])
    mem_txt = Path("/proc/meminfo").read_text(encoding="utf-8")
    for line in mem_txt.splitlines():
        if line.startswith("MemAvailable:"):
            return host_cpu, host_load1, int(line.split()[1]) / 1024.0
    raise ValueError("Missing MemAvailable in host /proc/meminfo")


_REQUIRED_CROS_RES_KEYS = frozenset(
    {"nproc", "clk_tck", "uptime_sec", "load1", "stat_cpu", "psi", "mem_kib", "proc_dt_sec", "top_procs"}
)
_REQUIRED_CROS_MEM_KEYS = frozenset(
    {"MemTotal", "MemAvailable", "SwapTotal", "SwapFree", "Dirty", "Writeback"}
)
_REQUIRED_TOP_PROC_KEYS = frozenset({"pid", "comm", "hint", "ticks"})
_MAX_CROS_TOP_PROCS = 5


def _require_strict_int(val: Any, name: str) -> int:
    if isinstance(val, bool) or not isinstance(val, int):
        raise ValueError(f"Expected int for {name}, got {val!r}")
    return val


def _require_strict_num(val: Any, name: str) -> float:
    if isinstance(val, bool) or not isinstance(val, (int, float)) or not math.isfinite(val):
        raise ValueError(f"Expected finite float/int for {name}, got {val!r}")
    return float(val)


def parse_cros_resource_json(
    raw_json_line: str,
    *,
    mono_ts: float,
    rel_sec: float,
    host_cpu: CpuStatCounters,
    host_load1: float,
    host_mem_avail_mib: float,
) -> CrosResourceSample:
    """Strictly parses and validates a single JSONL ChromeOS resource sample line."""
    try:
        obj = json.loads(raw_json_line)
    except json.JSONDecodeError as exc:
        raise ValueError(f"Malformed JSON in ChromeOS resource sample: {raw_json_line!r}") from exc
    if not isinstance(obj, dict):
        raise ValueError(f"Expected JSON object for ChromeOS resource sample, got {type(obj).__name__}")
    actual_keys = frozenset(obj.keys())
    if actual_keys != _REQUIRED_CROS_RES_KEYS:
        missing = sorted(_REQUIRED_CROS_RES_KEYS - actual_keys)
        extra = sorted(actual_keys - _REQUIRED_CROS_RES_KEYS)
        raise ValueError(
            f"ChromeOS resource sample keys mismatch (missing={missing}, extra={extra}): {raw_json_line!r}"
        )

    nproc = _require_strict_int(obj["nproc"], "nproc")
    clk_tck = _require_strict_int(obj["clk_tck"], "clk_tck")
    uptime_sec = _require_strict_num(obj["uptime_sec"], "uptime_sec")
    load1 = _require_strict_num(obj["load1"], "load1")
    proc_dt_sec = _require_strict_num(obj["proc_dt_sec"], "proc_dt_sec")
    if nproc <= 0 or clk_tck <= 0 or uptime_sec <= 0.0 or load1 < 0.0 or proc_dt_sec < 0.0:
        raise ValueError(f"Out-of-range ChromeOS scalar resource fields: {obj!r}")
    if not isinstance(obj["stat_cpu"], str):
        raise ValueError(f"Expected string stat_cpu, got {obj['stat_cpu']!r}")
    cros_cpu = parse_proc_stat_cpu_line(obj["stat_cpu"], "ChromeOS /proc/stat", clk_tck=clk_tck)

    psi_map = obj["psi"]
    if not isinstance(psi_map, dict) or frozenset(psi_map.keys()) != frozenset({"cpu", "memory", "io"}):
        raise ValueError(f"Invalid ChromeOS psi object: {psi_map!r}")
    for pk, pv in psi_map.items():
        if not isinstance(pv, list):
            raise ValueError(f"Expected list for psi[{pk!r}], got {pv!r}")
    psi_cpu = _parse_psi_resource(psi_map["cpu"], "cpu", require_full=False)
    psi_memory = _parse_psi_resource(psi_map["memory"], "memory", require_full=True)
    psi_io = _parse_psi_resource(psi_map["io"], "io", require_full=True)

    mem_map = obj["mem_kib"]
    if not isinstance(mem_map, dict) or frozenset(mem_map.keys()) != _REQUIRED_CROS_MEM_KEYS:
        raise ValueError(f"Missing or unexpected keys in ChromeOS mem_kib: {mem_map!r}")
    mem_ints = {mk: _require_strict_int(mv, f"mem_kib.{mk}") for mk, mv in mem_map.items()}
    if mem_ints["MemTotal"] <= 0 or any(v < 0 for v in mem_ints.values()):
        raise ValueError(f"Invalid ChromeOS mem_kib values: {mem_ints!r}")

    raw_top = obj["top_procs"]
    if not isinstance(raw_top, list) or len(raw_top) > _MAX_CROS_TOP_PROCS:
        raise ValueError(f"Expected top_procs list of <={_MAX_CROS_TOP_PROCS} entries, got {raw_top!r}")
    if proc_dt_sec == 0.0 and raw_top:
        raise ValueError(f"Expected empty top_procs when proc_dt_sec == 0.0, got {raw_top!r}")
    top_procs: list[CrosTopProc] = []
    seen_crosvm = False
    for idx, item in enumerate(raw_top):
        if not isinstance(item, dict) or frozenset(item.keys()) != _REQUIRED_TOP_PROC_KEYS:
            raise ValueError(f"Invalid top_procs[{idx}] object: {item!r}")
        pid = _require_strict_int(item["pid"], f"top_procs[{idx}].pid")
        ticks = _require_strict_int(item["ticks"], f"top_procs[{idx}].ticks")
        comm, hint = item["comm"], item["hint"]
        if (
            pid < 0 or ticks <= 0
            or not isinstance(comm, str) or not (1 <= len(comm) <= 64)
            or not isinstance(hint, str) or len(hint) > 64
        ):
            raise ValueError(f"Invalid field values in top_procs[{idx}]: {item!r}")
        if pid == 0 and comm != "crosvm":
            raise ValueError(f"pid=0 reserved for grouped crosvm entry, got {item!r}")
        if comm == "crosvm":
            if pid != 0 or seen_crosvm:
                raise ValueError(f"Unaggregated or duplicate crosvm entry in top_procs: {raw_top!r}")
            seen_crosvm = True
        top_procs.append(CrosTopProc(pid=pid, comm=comm, hint=hint, ticks=ticks))

    return CrosResourceSample(
        mono_ts=mono_ts,
        rel_sec=rel_sec,
        uptime_sec=uptime_sec,
        nproc=nproc,
        clk_tck=clk_tck,
        load1=load1,
        cros_cpu=cros_cpu,
        psi_cpu=psi_cpu,
        psi_memory=psi_memory,
        psi_io=psi_io,
        mem_total_kib=mem_ints["MemTotal"],
        mem_avail_kib=mem_ints["MemAvailable"],
        swap_total_kib=mem_ints["SwapTotal"],
        swap_free_kib=mem_ints["SwapFree"],
        dirty_kib=mem_ints["Dirty"],
        writeback_kib=mem_ints["Writeback"],
        host_cpu=host_cpu,
        host_load1=host_load1,
        host_mem_avail_mib=host_mem_avail_mib,
        proc_dt_sec=proc_dt_sec,
        top_procs=tuple(top_procs),
    )


def _format_top_procs(
    intervals: list[CrosResourceSample],
    *,
    limit: int = _MAX_CROS_TOP_PROCS,
    pct_only: bool = False,
) -> tuple[float, list[str]]:
    valid = [s for s in intervals if s.proc_dt_sec > 0.0]
    total_dt = sum(s.proc_dt_sec for s in valid)
    if total_dt <= 0.0:
        return 0.0, []
    crosvm_sec = 0.0
    crosvm_peak_p = 0
    crosvm_subs: dict[str, float] = {}
    by_proc: dict[tuple[str, str], float] = {}
    proc_pids: dict[tuple[str, str], set[int]] = {}
    for s in valid:
        tck = float(s.clk_tck if s.clk_tck > 0 else 100)
        for p in s.top_procs:
            cpu_s = p.ticks / tck
            if p.pid == 0:
                crosvm_sec += cpu_s
                cnt_part, sep, subs_part = p.hint.partition(":")
                if cnt_part.endswith("p") and cnt_part[:-1].isdigit():
                    crosvm_peak_p = max(crosvm_peak_p, int(cnt_part[:-1]))
                elif not sep and p.hint:
                    crosvm_subs[p.hint] = crosvm_subs.get(p.hint, 0.0) + cpu_s
                if subs_part:
                    subs_list = [x for x in subs_part.split(",") if x]
                    share = cpu_s / max(1, len(subs_list))
                    for sub in subs_list:
                        crosvm_subs[sub] = crosvm_subs.get(sub, 0.0) + share
            else:
                key = (p.comm, p.hint)
                by_proc[key] = by_proc.get(key, 0.0) + cpu_s
                proc_pids.setdefault(key, set()).add(p.pid)
    ranked: list[tuple[float, str]] = []
    if crosvm_sec > 0.0:
        top_subs = [k for k, _ in sorted(crosvm_subs.items(), key=lambda kv: (-kv[1], kv[0]))[:3]]
        p_lbl = f"{crosvm_peak_p}p" if crosvm_peak_p > 0 else "grp"
        ranked.append(
            (crosvm_sec, f"crosvm[{p_lbl}:{','.join(top_subs)}]" if top_subs else f"crosvm[{p_lbl}]")
        )
    for (comm, hint), cpu_s in by_proc.items():
        pids = proc_pids[(comm, hint)]
        pid_lbl = f"#{next(iter(pids))}" if len(pids) == 1 else f"[{len(pids)}pids]"
        hint_lbl = f"({hint})" if hint else ""
        ranked.append((cpu_s, f"{comm}{pid_lbl}{hint_lbl}"))
    ranked.sort(key=lambda r: (-r[0], r[1]))
    fmt = (
        (lambda lbl, s: f"{lbl}:{100.0 * s / total_dt:.0f}%")
        if pct_only
        else (lambda lbl, s: f"{lbl}={s:.2f}s({100.0 * s / total_dt:.1f}%)")
    )
    return total_dt, [fmt(lbl, sec) for sec, lbl in ranked[:limit]]


def summarize_resource_diagnostics(
    host_info: HostRunnerInfo | None,
    samples: list[CrosResourceSample],
    *,
    install_mono: float | None = None,
    installer_closed_rel_sec: float | None = None,
    sampler_warnings: list[str] | None = None,
    strict: bool = True,
    include_samples: bool = False,
) -> list[str]:
    """Formats a host + ChromeOS VM resource pressure summary (plus periodic sample rows on failure)."""
    warnings = list(sampler_warnings or [])
    if strict:
        if warnings:
            raise RuntimeError(f"Resource diagnostics sampler errors: {warnings}")
        if host_info is None:
            raise RuntimeError("Missing host runner CPU/memory info in strict mode")

    reanchored = [
        dataclasses.replace(s, rel_sec=(s.mono_ts - install_mono) if install_mono is not None else s.rel_sec)
        for s in samples
    ]
    if strict:
        if len(reanchored) < 2:
            raise RuntimeError(
                f"Expected >=2 ChromeOS resource samples for delta analysis, got {len(reanchored)}"
            )
        if not any(s.rel_sec >= 0.0 for s in reanchored):
            raise RuntimeError(
                "No ChromeOS resource samples were recorded at or after InstallClicked"
            )
        if reanchored[-1].uptime_sec <= reanchored[0].uptime_sec:
            raise RuntimeError(
                f"Non-increasing ChromeOS uptime across resource samples: "
                f"{reanchored[0].uptime_sec} -> {reanchored[-1].uptime_sec}"
            )

    out: list[str] = []
    if warnings:
        out.append("[resource diagnostics warnings]")
        out.extend(f"  {w}" for w in warnings)

    if host_info is not None and len(reanchored) < 2:
        out.append(
            f"Host runner: vendor={host_info.vendor_id} model={host_info.model_name!r} "
            f"nproc={host_info.nproc} ram_total={host_info.mem_total_mib / 1024.0:.1f}GiB "
            f"avail={host_info.mem_avail_mib / 1024.0:.1f}GiB (samples={len(reanchored)})"
        )
        if not reanchored:
            out.append("ChromeOS VM: <no resource samples collected>")
            return out

    if not reanchored:
        out.append("Host/ChromeOS resource diagnostics: <no samples collected>")
        return out

    pre_or_at_install = [s for s in reanchored if s.rel_sec <= 0.5]
    s_base = pre_or_at_install[-1] if pre_or_at_install else reanchored[0]
    s_end = reanchored[-1]
    if s_end is s_base and len(reanchored) >= 2:
        s_base, s_end = reanchored[0], reanchored[-1]

    window_samples = [s for s in reanchored if s.mono_ts >= s_base.mono_ts]
    if strict and not any(s.proc_dt_sec > 0.0 for s in window_samples[1:]):
        raise RuntimeError(
            "Expected >=1 ChromeOS resource sample interval with proc_dt_sec > 0"
        )
    span_sec = max(0.0, s_end.uptime_sec - s_base.uptime_sec)
    host_delta = (
        compute_cpu_delta_pct(s_base.host_cpu, s_end.host_cpu)
        if span_sec > 0
        else CpuDeltaPct(0.0, 0.0, 0.0, 0.0)
    )
    cros_delta = (
        compute_cpu_delta_pct(s_base.cros_cpu, s_end.cros_cpu)
        if span_sec > 0
        else CpuDeltaPct(0.0, 0.0, 0.0, 0.0)
    )

    if host_info is not None:
        host_min_avail_gib = min(s.host_mem_avail_mib for s in window_samples) / 1024.0
        host_peak_load1 = max(s.host_load1 for s in window_samples)
        out.append(
            f"Host runner: vendor={host_info.vendor_id} model={host_info.model_name!r} "
            f"nproc={host_info.nproc} ram_total={host_info.mem_total_mib / 1024.0:.1f}GiB "
            f"min_avail={host_min_avail_gib:.1f}GiB load1_peak={host_peak_load1:.2f} "
            f"cpu_busy={host_delta.busy_pct:.1f}% iowait={host_delta.iowait_pct:.1f}% "
            f"steal={host_delta.steal_pct:.2f}% ({host_delta.steal_sec:.2f} cpu-s)"
        )

    load1_avg = sum(s.load1 for s in window_samples) / len(window_samples)
    load1_peak = max(s.load1 for s in window_samples)
    mem_total_mib = s_end.mem_total_kib / 1024.0
    out.append(
        f"ChromeOS VM: vcpus={s_end.nproc} ram_total={mem_total_mib:.0f}MiB "
        f"samples={len(window_samples)} span={span_sec:.1f}s "
        f"(t{s_base.rel_sec:+.1f}s..t{s_end.rel_sec:+.1f}s) "
        f"load1_avg={load1_avg:.2f} load1_peak={load1_peak:.2f} "
        f"cpu_busy={cros_delta.busy_pct:.1f}% iowait={cros_delta.iowait_pct:.1f}% "
        f"guest_steal={cros_delta.steal_pct:.2f}% ({cros_delta.steal_sec:.2f} cpu-s)"
    )

    def _psi_delta(
        getter: Callable[[CrosResourceSample], PsiMetricLine | None],
    ) -> tuple[float, float, float]:
        b_m, e_m = getter(s_base), getter(s_end)
        if b_m is None or e_m is None or span_sec <= 0.0:
            return 0.0, 0.0, 0.0
        d_sec = max(0, e_m.total_us - b_m.total_us) / 1_000_000.0
        pk10 = max((getter(s).avg10 for s in window_samples if getter(s) is not None), default=0.0)
        return d_sec, 100.0 * d_sec / span_sec, pk10

    cpu_s_sec, cpu_s_pct, cpu_pk10 = _psi_delta(lambda s: s.psi_cpu.some)
    mem_s_sec, mem_s_pct, mem_s_pk10 = _psi_delta(lambda s: s.psi_memory.some)
    mem_f_sec, mem_f_pct, mem_f_pk10 = _psi_delta(lambda s: s.psi_memory.full)
    io_s_sec, io_s_pct, io_s_pk10 = _psi_delta(lambda s: s.psi_io.some)
    io_f_sec, io_f_pct, io_f_pk10 = _psi_delta(lambda s: s.psi_io.full)
    out.append(
        f"ChromeOS PSI: cpu_some={cpu_s_sec:.2f}s ({cpu_s_pct:.1f}%, pk10={cpu_pk10:.1f}) | "
        f"mem_some={mem_s_sec:.2f}s ({mem_s_pct:.1f}%, pk10={mem_s_pk10:.1f}) "
        f"mem_full={mem_f_sec:.2f}s ({mem_f_pct:.1f}%, pk10={mem_f_pk10:.1f}) | "
        f"io_some={io_s_sec:.2f}s ({io_s_pct:.1f}%, pk10={io_s_pk10:.1f}) "
        f"io_full={io_f_sec:.2f}s ({io_f_pct:.1f}%, pk10={io_f_pk10:.1f})"
    )

    min_avail_mib = min(s.mem_avail_kib for s in window_samples) / 1024.0
    min_avail_pct = 100.0 * min_avail_mib / max(1.0, mem_total_mib)
    swap_total_mib = s_end.swap_total_kib / 1024.0
    base_swap_used_mib = (s_base.swap_total_kib - s_base.swap_free_kib) / 1024.0
    swap_used_peak_mib = max((s.swap_total_kib - s.swap_free_kib) for s in window_samples) / 1024.0
    swap_growth_mib = max(0.0, swap_used_peak_mib - base_swap_used_mib)
    dirty_peak_mib = max((s.dirty_kib + s.writeback_kib) for s in window_samples) / 1024.0
    out.append(
        f"ChromeOS mem: avail_min={min_avail_mib:.0f}MiB ({min_avail_pct:.1f}%) "
        f"swap_used_pk={swap_used_peak_mib:.0f}/{swap_total_mib:.0f}MiB "
        f"(+{swap_growth_mib:.0f}MiB) dirty+wb_pk={dirty_peak_mib:.1f}MiB"
    )

    run_intervals = [s for s in window_samples[1:] if s.proc_dt_sec > 0.0]
    run_proc_dt, run_top_strs = _format_top_procs(run_intervals)
    if run_proc_dt > 0.0:
        out.append(
            f"ChromeOS top CPU (run, sampled={run_proc_dt:.1f}s, 100%=1vCPU): "
            f"{', '.join(run_top_strs) if run_top_strs else '<idle>'}"
        )
    if installer_closed_rel_sec is not None:
        strict_post = [
            s for s in run_intervals if (s.rel_sec - s.proc_dt_sec) >= installer_closed_rel_sec
        ]
        post_intervals = (
            strict_post
            if sum(s.proc_dt_sec for s in strict_post) >= 2.0
            else [s for s in run_intervals if s.rel_sec > installer_closed_rel_sec]
        )
        post_dt, post_top_strs = _format_top_procs(post_intervals)
        if post_dt > 0.0:
            out.append(
                f"ChromeOS top CPU (post-InstallerClosed t{installer_closed_rel_sec:+.1f}s+, "
                f"sampled={post_dt:.1f}s): {', '.join(post_top_strs) if post_top_strs else '<idle>'}"
            )

    bottleneck_tags: list[str] = []
    if host_delta.steal_pct >= 5.0 or cros_delta.steal_pct >= 5.0:
        bottleneck_tags.append(
            f"hypervisor/host steal (host={host_delta.steal_pct:.1f}%, guest={cros_delta.steal_pct:.1f}%)"
        )
    if cpu_s_pct >= 10.0 or cros_delta.busy_pct >= 75.0 or load1_peak >= s_end.nproc * 1.25:
        bottleneck_tags.append(
            f"CPU-contention (cros_busy={cros_delta.busy_pct:.1f}%, psi_cpu_some={cpu_s_pct:.1f}%, load1_pk={load1_peak:.2f}/{s_end.nproc}vCPU)"
        )
    if io_s_pct >= 10.0 or cros_delta.iowait_pct >= 10.0:
        bottleneck_tags.append(
            f"IO-stall (psi_io_some={io_s_pct:.1f}%, io_full={io_f_pct:.1f}%, iowait={cros_delta.iowait_pct:.1f}%)"
        )
    if mem_s_pct >= 5.0 or swap_growth_mib >= 16.0 or min_avail_pct < 12.0:
        bottleneck_tags.append(
            f"memory/reclaim (psi_mem_some={mem_s_pct:.1f}%, mem_full={mem_f_pct:.1f}%, swap_growth=+{swap_growth_mib:.0f}MiB, avail_min={min_avail_mib:.0f}MiB)"
        )
    profile_str = "; ".join(bottleneck_tags) if bottleneck_tags else "no major CPU/memory/IO stall observed"
    out.append(f"Observed resource profile: {profile_str}")

    if include_samples:
        chosen_indices = _select_sample_indices(window_samples, max_rows=24)
        out.append(
            f"[periodic samples ({len(chosen_indices)}/{len(window_samples)} shown, relative to Install click)]"
        )
        for pos, idx in enumerate(chosen_indices):
            cur = window_samples[idx]
            if pos == 0:
                c_cpu_str, h_stl_str, dswp_str, top_str = "baseline", "base", "+0MiB", ""
            else:
                prev_idx = chosen_indices[pos - 1]
                prv = window_samples[prev_idx]
                cd = compute_cpu_delta_pct(prv.cros_cpu, cur.cros_cpu)
                hd = compute_cpu_delta_pct(prv.host_cpu, cur.host_cpu)
                c_cpu_str = f"{cd.busy_pct:4.1f}%(iow={cd.iowait_pct:.1f}%,stl={cd.steal_pct:.1f}%)"
                h_stl_str = f"{hd.steal_pct:.1f}%"
                prv_swp = prv.swap_total_kib - prv.swap_free_kib
                cur_swp = cur.swap_total_kib - cur.swap_free_kib
                dswp_str = f"{(cur_swp - prv_swp) / 1024.0:+.0f}MiB"
                _, row_top = _format_top_procs(
                    window_samples[prev_idx + 1 : idx + 1], pct_only=True
                )
                top_str = f" top=[{', '.join(row_top)}]" if row_top else " top=[<idle>]"
            avail_m = cur.mem_avail_kib / 1024.0
            swp_m = (cur.swap_total_kib - cur.swap_free_kib) / 1024.0
            out.append(
                f"  {_fmt_rel_t(cur.rel_sec)}: load1={cur.load1:4.2f} cros_cpu={c_cpu_str} "
                f"psi10(c/m/i)={cur.psi_cpu.some.avg10:.1f}/{cur.psi_memory.some.avg10:.1f}/{cur.psi_io.some.avg10:.1f} "
                f"avail={avail_m:.0f}MiB swap={swp_m:.0f}MiB({dswp_str}) host_stl={h_stl_str}{top_str}"
            )
    return out


def _select_sample_indices(
    window_samples: list[CrosResourceSample], max_rows: int = 24
) -> list[int]:
    n = len(window_samples)
    if max_rows < 2:
        raise ValueError(f"max_rows must be >=2, got {max_rows}")
    if n <= max_rows:
        return list(range(n))
    peak_idx = max(
        range(n),
        key=lambda i: (
            window_samples[i].psi_cpu.some.avg10
            + window_samples[i].psi_memory.some.avg10
            + window_samples[i].psi_io.some.avg10,
            window_samples[i].load1,
        ),
    )
    chosen: set[int] = {0, n - 1, peak_idx}
    if len(chosen) > max_rows:
        return [0, n - 1]
    even_budget = max_rows - (1 if peak_idx not in (0, n - 1) else 0)
    for slot in range(even_budget):
        chosen.add(round(slot * (n - 1) / (even_budget - 1)))
    ordered = sorted(chosen)
    while len(ordered) > max_rows:
        for cand in ordered[1:-1]:
            if cand != peak_idx:
                ordered.remove(cand)
                break
    return ordered


def _terminate_proc(proc: subprocess.Popen[Any] | None) -> None:
    if proc is None:
        return
    try:
        proc.terminate()
        proc.wait(timeout=3)
    except Exception:
        try:
            proc.kill()
        except Exception:
            pass


def _run_diag(
    strict: bool, err_sink: list[str], label: str, fn: Callable[[], None]
) -> None:
    if strict:
        fn()
        return
    try:
        fn()
    except Exception as exc:
        err_sink.append(f"{label}: {exc}")


class _BackgroundSshStream:
    """Line-buffered background SSH process with stderr capture and premature-EOF detection."""

    def __init__(
        self,
        name: str,
        cmd: list[str],
        *,
        on_line: Callable[[str], None],
        on_eof: Callable[[], None] | None = None,
        on_fatal: Callable[[Exception], None],
    ) -> None:
        self.name = name
        self.cmd = cmd
        self._on_line = on_line
        self._on_eof = on_eof
        self._on_fatal = on_fatal
        self._lock = threading.Lock()
        self._stderr_lines: list[str] = []
        self._stop_requested = False
        self.fatal_error: Exception | None = None
        self.proc: subprocess.Popen[str] | None = None
        self._stderr_thread: threading.Thread | None = None
        self._reader_thread: threading.Thread | None = None

    def start(self) -> None:
        self.proc = subprocess.Popen(
            self.cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
        )
        self._stderr_thread = threading.Thread(target=self._read_stderr, daemon=True)
        self._stderr_thread.start()
        self._reader_thread = threading.Thread(target=self._read_stdout, daemon=True)
        self._reader_thread.start()

    def stderr_text(self) -> str:
        with self._lock:
            return "\n".join(self._stderr_lines).strip()

    def poll_rc(self) -> int | None:
        return self.proc.poll() if self.proc is not None else None

    def _read_stderr(self) -> None:
        assert self.proc is not None and self.proc.stderr is not None
        for line in self.proc.stderr:
            stripped = line.rstrip("\r\n")
            if stripped:
                with self._lock:
                    self._stderr_lines.append(stripped)

    def _read_stdout(self) -> None:
        assert self.proc is not None and self.proc.stdout is not None
        try:
            for line in self.proc.stdout:
                if self._stop_requested:
                    return
                self._on_line(line)
            if not self._stop_requested:
                if self._on_eof is not None:
                    self._on_eof()
                try:
                    rc = self.proc.wait(timeout=1.0)
                except subprocess.TimeoutExpired:
                    rc = self.proc.poll()
                if self._stderr_thread is not None:
                    self._stderr_thread.join(timeout=1.0)
                raise RuntimeError(
                    f"{self.name} stdout reached EOF prematurely before stop_and_collect "
                    f"(returncode={rc}, stderr={self.stderr_text()!r})"
                )
        except Exception as exc:
            with self._lock:
                if self.fatal_error is None:
                    self.fatal_error = exc
            log(f"  [timeline] FATAL error in {self.name}: {exc}")
            self._on_fatal(exc)

    def check_healthy(self, stop_requested: bool) -> None:
        with self._lock:
            err = self.fatal_error
        if err is not None:
            raise RuntimeError(f"Fatal error in background {self.name}: {err}") from err
        if self.proc is not None and not stop_requested:
            rc = self.proc.poll()
            if rc is not None:
                raise RuntimeError(
                    f"{self.name} process exited prematurely before stop_and_collect "
                    f"(returncode={rc}, stderr={self.stderr_text()!r})"
                )

    def stop(self) -> None:
        self._stop_requested = True
        _terminate_proc(self.proc)
        self.proc = None
        for th in (self._reader_thread, self._stderr_thread):
            if th is not None:
                th.join(timeout=2.0)
        self._reader_thread = None
        self._stderr_thread = None


class InitTimelineRecorder:
    """Passive, side-effect-free recorder of VM/container initialization signals, logs, UMA, and resource pressure."""

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
        self._res_first_sample_event = threading.Event()
        self._mon_stream: _BackgroundSshStream | None = None
        self._res_stream: _BackgroundSshStream | None = None
        self.host_runner_info: HostRunnerInfo | None = None
        self._resource_samples: list[CrosResourceSample] = []
        self._final_res_snapshot_taken = False
        self._stop_requested = False
        self._collected_sections: set[str] = set()
        self._first_host_setup_user_rel: float | None = None
        self.readonly_summary_lines: list[str] = []
        self.resource_summary_lines: list[str] = []
        self.resource_sample_lines: list[str] = []
        self.guest_summary_lines: list[str] = []
        self.guest_verbose_lines: list[str] = []
        self.messages_excerpt: str = ""
        self.chrome_excerpt: str = ""

    def all_entries(self) -> list[TimelineEntry]:
        with self._lock:
            combined = self._entries + self._host_log_entries + self._guest_log_entries
        return sorted(combined, key=lambda e: e.rel_sec)

    def check_no_fatal_error(self) -> None:
        for stream in (self._mon_stream, self._res_stream):
            if stream is not None:
                stream.check_healthy(self._stop_requested)

    def start(self) -> None:
        """Starts background `dbus-monitor --system` and periodic resource sampler on the VM before `Install`."""
        self.host_runner_info = read_local_host_runner_info()
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
        dbus_parser = DbusMonitorSignalParser()

        def _on_dbus_line(line: str) -> None:
            ev = dbus_parser.feed_line(line)
            if ev is not None:
                self._handle_dbus_signal(*ev)

        def _wake_waiters(_exc: Exception) -> None:
            self._monitor_subscribed_event.set()
            self._res_first_sample_event.set()
            self._container_started_event.set()

        self._mon_stream = _BackgroundSshStream(
            "dbus-monitor",
            [*self.vm._ssh_base_cmd(), f"exec dbus-monitor --system {match_rules}"],
            on_line=_on_dbus_line,
            on_eof=dbus_parser.finish,
            on_fatal=_wake_waiters,
        )
        self._res_stream = _BackgroundSshStream(
            "ChromeOS resource sampler",
            [*self.vm._ssh_base_cmd(), CROS_RESOURCE_SAMPLER_LOOP_CMD],
            on_line=self._on_resource_line,
            on_fatal=_wake_waiters,
        )
        self._mon_stream.start()
        self._res_stream.start()

        if not self._monitor_subscribed_event.wait(timeout=15.0):
            self.check_no_fatal_error()
            raise RuntimeError(
                "Timed out waiting for dbus-monitor org.freedesktop.DBus.NameAcquired "
                f"subscription signal (returncode={self._mon_stream.poll_rc()}, "
                f"stderr={self._mon_stream.stderr_text()!r})"
            )
        if not self._res_first_sample_event.wait(timeout=15.0):
            self.check_no_fatal_error()
            raise RuntimeError(
                "Timed out waiting for initial ChromeOS resource diagnostics sample "
                f"(returncode={self._res_stream.poll_rc()}, "
                f"stderr={self._res_stream.stderr_text()!r})"
            )
        self.check_no_fatal_error()
        log(
            f"  [timeline] Passive D-Bus monitor (NameAcquired={self.monitor_unique_name}) "
            f"& periodic ChromeOS resource sampler started "
            f"(host={self.host_runner_info.vendor_id} {self.host_runner_info.model_name}, "
            f"nproc={self.host_runner_info.nproc})."
        )

    def _record_resource_json_line(self, raw_json_line: str, mono_ts: float) -> None:
        host_cpu, host_load1, host_mem_avail_mib = read_local_host_dynamic_sample()
        with self._lock:
            t_inst = self.t_install_mono
        rel_sec = (mono_ts - t_inst) if t_inst is not None else 0.0
        sample = parse_cros_resource_json(
            raw_json_line,
            mono_ts=mono_ts,
            rel_sec=rel_sec,
            host_cpu=host_cpu,
            host_load1=host_load1,
            host_mem_avail_mib=host_mem_avail_mib,
        )
        with self._lock:
            self._resource_samples.append(sample)
        self._res_first_sample_event.set()

    def _on_resource_line(self, line: str) -> None:
        stripped = line.strip()
        if stripped:
            self._record_resource_json_line(stripped, time.monotonic())

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
        return 0.0 if self.t_install_mono is None else (now - self.t_install_mono)

    def record_ui(self, name: str, detail: str) -> float:
        self.check_no_fatal_error()
        rel = self._rel_mono()
        with self._lock:
            self._entries.append(TimelineEntry(rel, "ui", name, detail))
        return rel

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
        signal_specs: dict[tuple[str, str], tuple[type[Message], str, bool]] = {
            ("org.chromium.VmConcierge", "VmStartingUpSignal"): (conc.VmStartingUpSignal, "name", True),
            ("org.chromium.VmConcierge", "VmStartedSignal"): (conc.VmStartedSignal, "name", True),
            ("org.chromium.VmConcierge", "VmGuestUserlandReadySignal"): (conc.VmGuestUserlandReadySignal, "name", True),
            ("org.chromium.VmConcierge", "VmStoppingSignal"): (conc.VmStoppingSignal, "name", True),
            ("org.chromium.VmConcierge", "VmStoppedSignal"): (conc.VmStoppedSignal, "name", True),
            ("org.chromium.VmCicerone", "ContainerStarted"): (cic.ContainerStartedSignal, "vm_name", True),
            ("org.chromium.VmCicerone", "ContainerShutdown"): (cic.ContainerShutdownSignal, "vm_name", True),
            ("org.chromium.VmCicerone", "PendingAppListUpdates"): (cic.PendingAppListUpdatesSignal, "vm_name", False),
            ("org.chromium.VmCicerone", "TremplinStarted"): (cic.TremplinStartedSignal, "vm_name", True),
        }
        spec = signal_specs.get((iface, member))
        if spec is None:
            raise ValueError(f"Unhandled D-Bus signal {ctx}")

        msg_cls, vm_field, has_owner_id = spec
        sig: Any = parse_and_validate_proto(raw, msg_cls, ctx)
        vm_name = require_non_empty_str(getattr(sig, vm_field), vm_field, ctx, raw)
        owner_id = require_non_empty_str(sig.owner_id, "owner_id", ctx, raw) if has_owner_id else ""
        rel = self._rel_mono()
        post_hook: Callable[[], None] | None = None

        if member == "VmStartingUpSignal":
            vm_type = require_enum_name(conc.VmInfo.VmType, sig.vm_type, "vm_type", ctx, raw)
            if sig.cid <= 0:
                raise ValueError(f"{ctx}: invalid cid={sig.cid} (hex={raw.hex()})")
            detail = f"vm={vm_name!r} vm_type={vm_type}({sig.vm_type}) cid={sig.cid}"
            if vm_name == "termina" and self.on_vm_starting_up is not None:
                cb, self.on_vm_starting_up = self.on_vm_starting_up, None
                post_hook = cb
        elif member == "VmStartedSignal":
            status_name = require_enum_name(conc.VmStatus, sig.status, "status", ctx, raw)
            vm_type = require_enum_name(conc.VmInfo.VmType, sig.vm_info.vm_type, "vm_info.vm_type", ctx, raw)
            if sig.vm_info.pid <= 0 or sig.vm_info.cid <= 0:
                raise ValueError(
                    f"{ctx}: invalid vm_info pid={sig.vm_info.pid} cid={sig.vm_info.cid} (hex={raw.hex()})"
                )
            detail = (
                f"vm={vm_name!r} status={status_name}({sig.status}) "
                f"vm_type={vm_type}({sig.vm_info.vm_type}) pid={sig.vm_info.pid} cid={sig.vm_info.cid}"
            )
            if vm_name == "termina" and self.on_vm_started is not None:
                cb, self.on_vm_started = self.on_vm_started, None
                post_hook = cb
        elif member == "VmGuestUserlandReadySignal":
            detail = f"vm={vm_name!r} ready={sig.ready}"
        elif member == "VmStoppingSignal":
            if sig.cid <= 0:
                raise ValueError(f"{ctx}: invalid cid={sig.cid} (hex={raw.hex()})")
            detail = f"vm={vm_name!r} cid={sig.cid}"
        elif member == "VmStoppedSignal":
            reason_name = require_enum_name(
                conc.VmStopReason, sig.reason, "reason", ctx, raw, disallow_zero_unknown=False
            )
            detail = f"vm={vm_name!r} cid={sig.cid} reason={reason_name}({sig.reason})"
        elif member == "ContainerStarted":
            container_name = require_non_empty_str(sig.container_name, "container_name", ctx, raw)
            user = require_non_empty_str(sig.container_username, "container_username", ctx, raw)
            homedir = require_non_empty_str(sig.container_homedir, "container_homedir", ctx, raw)
            if not homedir.startswith("/"):
                raise ValueError(f"{ctx}: expected absolute container_homedir, got {homedir!r} (hex={raw.hex()})")
            detail = f"vm={vm_name!r} container={container_name!r} user={user!r} homedir={homedir!r}"
            if vm_name == "termina" and container_name == "penguin":
                if owner_id != self.owner_hash:
                    raise ValueError(
                        f"{ctx}: owner_id mismatch: expected {self.owner_hash!r}, got {owner_id!r} (hex={raw.hex()})"
                    )
                if user != self.expected_username:
                    raise ValueError(
                        f"{ctx}: container_username mismatch: expected {self.expected_username!r}, got {user!r} (hex={raw.hex()})"
                    )
                with self._lock:
                    self._entries.append(TimelineEntry(rel, "dbus", member, detail))
                    self.container_started_rel_sec = rel
                    self._container_started_event.set()
                return
        elif member == "ContainerShutdown":
            container_name = require_non_empty_str(sig.container_name, "container_name", ctx, raw)
            detail = f"vm={vm_name!r} container={container_name!r}"
        elif member == "PendingAppListUpdates":
            container_name = require_non_empty_str(sig.container_name, "container_name", ctx, raw)
            detail = f"vm={vm_name!r} container={container_name!r} count={sig.count}"
        else:  # TremplinStarted
            detail = f"vm={vm_name!r} owner_id={owner_id!r}"

        with self._lock:
            self._entries.append(TimelineEntry(rel, "dbus", member, detail))
        if post_hook is not None:
            post_hook()

    def verify_required_dbus_signal_sequence(self) -> None:
        """Asserts that `VmStartingUpSignal` -> `VmStartedSignal` -> `ContainerStarted` for `termina` arrived in order."""
        with self._lock:
            names_in_order = [
                e.name for e in self._entries if e.source == "dbus" and "vm='termina'" in e.detail
            ]
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
            vm_name="termina", container_name="penguin", owner_id=self.owner_hash
        )
        resp, raw_resp = self.vm.dbus_call_proto(
            "org.chromium.VmCicerone", "GetGarconSessionInfo", req, cic.GetGarconSessionInfoResponse
        )
        require_enum_name(
            cic.GetGarconSessionInfoResponse.Status, resp.status, "status", ctx, raw_resp
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
            timeout=60,
            op_desc="scrape_host_logs(/var/log/messages)",
            cmd_summary="tail /var/log/messages | grep vm_concierge|...",
        ).stdout.strip()
        self.messages_excerpt = msg_out
        setup_user_seq = 0
        pending_setup_user: tuple[int, float] | None = None
        for line in msg_out.splitlines():
            parts = line.split(None, 3)
            if len(parts) < 4 or not re.match(r"^\d{4}-\d{2}-\d{2}T", parts[0]):
                continue
            epoch = parse_rfc3339_utc(parts[0])
            rel = (epoch - self.t_install_vm_epoch) if self.t_install_vm_epoch is not None else 0.0
            proc_tag, msg_body = parts[2], parts[3]

            # vm_concierge is single-threaded: any subsequent vm_concierge log line (or cicerone
            # LaunchVshd) that is not a SetUpUser RPC error marks completion of SetUpVmUser.
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
                if proc_tag.startswith("vm_concierge") or "Received LaunchVshd request" in msg_body:
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
                    TimelineEntry(rel, "concierge", "SetUpVmUser", f"call #{setup_user_seq}: {msg_body}")
                )
            elif "Startup of container " in msg_body:
                new_host_entries.append(TimelineEntry(rel, "cicerone", "ContainerReadyLog", msg_body))
            elif "VM with requested name is already running" in msg_body:
                new_host_entries.append(TimelineEntry(rel, "concierge", "StartVmAlreadyRunning", msg_body))
            elif "Garcon channel not connected" in msg_body:
                new_host_entries.append(TimelineEntry(rel, "cicerone", "GarconChannelWait", msg_body))
            elif "Received LaunchVshd request" in msg_body:
                new_host_entries.append(TimelineEntry(rel, "cicerone", "LaunchVshd", msg_body))
            elif "Received RegisterVshSession request" in msg_body:
                new_host_entries.append(TimelineEntry(rel, "cicerone", "RegisterVshSession", msg_body))

        if pending_setup_user is not None:
            seq_idx, start_rel = pending_setup_user
            new_host_entries.append(
                TimelineEntry(
                    start_rel,
                    "concierge",
                    "SetUpVmUserInFlight",
                    f"call #{seq_idx} still in flight at log scrape (no completion or RPC error logged yet)",
                )
            )

        self.chrome_excerpt = self.vm.ssh(
            f"set -o pipefail; test -r /var/log/chrome/chrome; "
            f"tail -n +{self.chrome_line_cursor + 1} /var/log/chrome/chrome | "
            f"{{ grep -iE 'crostini|baguette|termina|cicerone|concierge|vsh' || [ $? -eq 1 ]; }}",
            check=True,
            timeout=60,
            op_desc="scrape_host_logs(/var/log/chrome/chrome)",
            cmd_summary="tail /var/log/chrome/chrome | grep crostini|...",
        ).stdout.strip()
        for line in self.chrome_excerpt.splitlines():
            parts = line.split(None, 3)
            if len(parts) < 4 or not re.match(r"^\d{4}-\d{2}-\d{2}T", parts[0]):
                continue
            epoch = parse_rfc3339_utc(parts[0])
            rel = (epoch - self.t_install_vm_epoch) if self.t_install_vm_epoch is not None else 0.0
            c_body = parts[3]
            if "Failed to set up baguette user:" in c_body:
                new_host_entries.append(TimelineEntry(rel, "chrome", "SetUpBaguetteUserFailed", c_body))
            elif "Failed to restart Crostini with error code:" in c_body:
                new_host_entries.append(TimelineEntry(rel, "chrome", "RestartCrostiniFailed", c_body))
            elif "Unable to mount files for a container that's not running" in c_body:
                new_host_entries.append(TimelineEntry(rel, "chrome", "SshfsMountSkipped", c_body))

        with self._lock:
            self._host_log_entries = new_host_entries
        return first_host_setup_user_rel

    def _collect_readonly_dbus_snapshot(self, strict_dbus: bool = True) -> None:
        conc = self._protos.concierge_pb2
        cic = self._protos.cicerone_pb2

        def _query_get_vm_info() -> None:
            ctx_vm = "VmConcierge.GetVmInfo"
            vm_resp, raw_vm = self.vm.dbus_call_proto(
                "org.chromium.VmConcierge",
                "GetVmInfo",
                conc.GetVmInfoRequest(name="termina", owner_id=self.owner_hash),
                conc.GetVmInfoResponse,
            )
            if not vm_resp.success:
                if strict_dbus:
                    raise RuntimeError(f"{ctx_vm} returned success=false (hex={raw_vm.hex()})")
                self.readonly_summary_lines.append(f"VmConcierge.GetVmInfo(termina): success={vm_resp.success}")
                return
            vm_type = require_enum_name(conc.VmInfo.VmType, vm_resp.vm_info.vm_type, "vm_info.vm_type", ctx_vm, raw_vm)
            vm_status = require_enum_name(conc.VmStatus, vm_resp.vm_info.status, "vm_info.status", ctx_vm, raw_vm)
            if vm_resp.vm_info.pid <= 0 or vm_resp.vm_info.cid <= 0:
                raise ValueError(f"{ctx_vm}: invalid pid={vm_resp.vm_info.pid} cid={vm_resp.vm_info.cid}")
            self.readonly_summary_lines.append(
                f"VmConcierge.GetVmInfo(termina): success={vm_resp.success} "
                f"status={vm_status}({vm_resp.vm_info.status}) "
                f"vm_type={vm_type}({vm_resp.vm_info.vm_type}) "
                f"cid={vm_resp.vm_info.cid} pid={vm_resp.vm_info.pid}"
            )

        def _query_list_vms() -> None:
            ctx_lv = "VmConcierge.ListVms"
            lv_resp, raw_lv = self.vm.dbus_call_proto(
                "org.chromium.VmConcierge",
                "ListVms",
                conc.ListVmsRequest(owner_id=self.owner_hash),
                conc.ListVmsResponse,
            )
            if not lv_resp.success and strict_dbus:
                raise RuntimeError(
                    f"{ctx_lv} returned success=false: {lv_resp.failure_reason!r} (hex={raw_lv.hex()})"
                )
            vm_names = [require_non_empty_str(entry.name, "vms[].name", ctx_lv, raw_lv) for entry in lv_resp.vms]
            if strict_dbus and "termina" not in vm_names:
                raise RuntimeError(f"{ctx_lv}: expected 'termina' in running VMs, got {vm_names!r}")
            self.readonly_summary_lines.append(f"VmConcierge.ListVms: success={lv_resp.success} vms={vm_names}")

        def _query_list_containers() -> None:
            ctx_lc = "VmCicerone.ListRunningContainers"
            lc_resp, raw_lc = self.vm.dbus_call_proto(
                "org.chromium.VmCicerone",
                "ListRunningContainers",
                cic.ListRunningContainersRequest(owner_id=self.owner_hash),
                cic.ListRunningContainersResponse,
            )
            containers = [
                f"{require_non_empty_str(c.vm_name, 'containers[].vm_name', ctx_lc, raw_lc)}/"
                f"{require_non_empty_str(c.container_name, 'containers[].container_name', ctx_lc, raw_lc)}"
                for c in lc_resp.containers
            ]
            if strict_dbus and "termina/penguin" not in containers:
                raise RuntimeError(f"{ctx_lc}: expected 'termina/penguin' in running containers, got {containers!r}")
            self.readonly_summary_lines.append(f"VmCicerone.ListRunningContainers: {containers}")

        def _query_garcon_info() -> None:
            garcon_info = self.query_garcon_session_info_readonly()
            status_name = cic.GetGarconSessionInfoResponse.Status.Name(garcon_info.status)
            if strict_dbus and garcon_info.status != cic.GetGarconSessionInfoResponse.Status.SUCCEEDED:
                raise RuntimeError(f"VmCicerone.GetGarconSessionInfo(termina/penguin) status={status_name}")
            self.readonly_summary_lines.append(
                f"VmCicerone.GetGarconSessionInfo(termina/penguin): "
                f"status={status_name}({garcon_info.status}) "
                f"user={garcon_info.container_username!r} homedir={garcon_info.container_homedir!r}"
            )

        for query_fn in (_query_get_vm_info, _query_list_vms, _query_list_containers, _query_garcon_info):
            _run_diag(strict_dbus, self.readonly_summary_lines, "Read-only D-Bus query error", query_fn)

    def _collect_uma_histograms(self, strict_dbus: bool = True) -> None:
        self.vm.set_step("step5:collect_uma_histograms")
        b_conn = self.vm.connect_browser_cdp(label="Browser-UMA")
        try:
            for h_name in (
                "Crostini.BaguetteReadyWait",
                "Crostini.TimeToInstallSuccess",
                "Crostini.SetupResult",
                "Crostini.RestarterResult.Installer",
            ):

                def _fetch_one(name: str = h_name) -> None:
                    h_res = b_conn.call(
                        "Browser.getHistogram",
                        {"name": name},
                        allow_error=not strict_dbus,
                        op_desc=f"UMA:getHistogram({name})",
                    )
                    if "error" in h_res:
                        self.readonly_summary_lines.append(
                            f"UMA {name}: <not recorded ({h_res['error'].get('message', h_res['error'])})>"
                        )
                        return
                    hist = h_res.get("histogram")
                    if not isinstance(hist, dict) or not hist:
                        if strict_dbus:
                            raise RuntimeError(f"Browser.getHistogram({name!r}) returned empty result: {h_res!r}")
                        self.readonly_summary_lines.append(f"UMA {name}: <not recorded>")
                        return
                    buckets = [f"[{b['low']}..{b['high']}):{b['count']}" for b in hist.get("buckets", [])]
                    self.readonly_summary_lines.append(
                        f"UMA {name}: count={hist.get('count')} sum={hist.get('sum')} buckets={buckets}"
                    )

                _run_diag(strict_dbus, self.readonly_summary_lines, f"UMA {h_name} query error", _fetch_one)
        finally:
            b_conn.close()

    # On slow 4-vCPU nested-KVM CI runners (load1~7, psi_cpu~50%), a minimal `vsh` call
    # (`ssh -> sudo -> vsh -> LaunchVshd/RegisterVshSession`) takes ~22s just to open the
    # guest shell; 120s leaves ~4-5x headroom for vsh startup plus systemd/journal queries.
    GUEST_DIAG_TIMEOUT_SEC = 120

    def _collect_guest_diagnostics(
        self, first_host_setup_user_rel: float | None, strict_dbus: bool = True
    ) -> None:
        shell_flags = "set -euo pipefail; " if strict_dbus else "set -uo pipefail; "
        q_user = shlex.quote(self.expected_username)
        id_check_cmd = f"id {q_user} 2>&1; " if strict_dbus else f"id {q_user} 2>&1 || true; "
        journal_filter_args = (
            "-u first-boot-cros.service -u maitred.service -u vshd.service "
            "-u systemd-logind.service -u user-runtime-dir@1000.service -u user@1000.service "
            "-u ldconfig.service "
            "SYSLOG_IDENTIFIER=first-boot-cros SYSLOG_IDENTIFIER=maitred "
            "SYSLOG_IDENTIFIER=useradd SYSLOG_IDENTIFIER=usermod "
            "SYSLOG_IDENTIFIER=garcon SYSLOG_IDENTIFIER=sommelier SYSLOG_IDENTIFIER=vshd"
        )
        journal_fields = "MESSAGE,_COMM,SYSLOG_IDENTIFIER,_SYSTEMD_UNIT,UNIT"
        sys_summary_sh = (
            'echo "===GUEST_CLOCK_SYNC==="; '
            "read -r up _ < /proc/uptime; "
            'echo "uptime_sec=$up"; '
            'date -u +"epoch_sec=%s.%N"; '
            + id_check_cmd
            + 'echo "===GUEST_LIST_JOBS==="; '
            "systemctl list-jobs --no-pager 2>&1; "
            'echo "===GUEST_SYSTEMD_UNIT_SHOW==="; '
            "systemctl show --no-pager "
            "-p Id -p ActiveState -p SubState -p Result "
            "-p InactiveExitTimestampMonotonic -p ActiveEnterTimestampMonotonic "
            "-p ActiveExitTimestampMonotonic -p InactiveEnterTimestampMonotonic "
            "-p ExecMainStartTimestampMonotonic -p ExecMainExitTimestampMonotonic "
            "-p ExecMainStatus "
            "first-boot-cros.service maitred.service vshd.service systemd-logind.service "
            "ldconfig.service user-runtime-dir@1000.service user@1000.service; "
            'echo "===GUEST_ANALYZE==="; '
            "systemd-analyze --no-pager 2>&1; "
            'echo "===GUEST_BLAME==="; '
            "systemd-analyze blame --no-pager 2>&1 | sed -n '1,8p'; "
        )
        journal_sh = (
            'echo "===GUEST_JOURNAL_JSON==="; '
            f"journalctl -b -o json --output-fields={journal_fields} --no-pager "
            f"{journal_filter_args} | sed -n '1,400p'"
        )
        user_env_prefix = (
            "setpriv --reuid=1000 --regid=1000 --init-groups "
            "env XDG_RUNTIME_DIR=/run/user/1000 DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/1000/bus "
        )
        user_summary_inner = (
            f"{shell_flags}"
            'echo "===GUEST_USER_ANALYZE==="; '
            "systemd-analyze --user --no-pager 2>&1; "
            'echo "===GUEST_USER_BLAME==="; '
            "systemd-analyze --user blame --no-pager 2>&1 | sed -n '1,8p'"
        )
        if strict_dbus:
            steps: list[tuple[str, int, str]] = [
                (
                    "guest_diag:summary",
                    self.GUEST_DIAG_TIMEOUT_SEC,
                    shell_flags
                    + sys_summary_sh
                    + f"{user_env_prefix}bash -c {shlex.quote(user_summary_inner)}; "
                    + journal_sh,
                )
            ]
        else:
            user_verbose_inner = (
                f"{user_summary_inner}; "
                'echo "===GUEST_USER_CRITICAL_CHAIN==="; '
                "systemd-analyze --user critical-chain --no-pager 2>&1; "
                'echo "===GUEST_GARCON_STATUS==="; '
                "systemctl --user status cros-garcon.service "
                "sommelier@0.service sommelier-x@0.service sommelier@1.service sommelier-x@1.service --no-pager 2>&1"
            )
            steps = [
                (
                    "guest_diag:system",
                    self.GUEST_DIAG_TIMEOUT_SEC,
                    shell_flags
                    + sys_summary_sh
                    + 'echo "===GUEST_CRITICAL_CHAIN==="; '
                    + "systemd-analyze critical-chain --no-pager 2>&1; "
                    + journal_sh,
                ),
                (
                    "guest_diag:user",
                    self.GUEST_DIAG_TIMEOUT_SEC,
                    f"{user_env_prefix}bash -c {shlex.quote(user_verbose_inner)}",
                ),
            ]

        combined_chunks: list[str] = []
        step_errors: list[str] = []
        for step_name, step_timeout, remote_sh in steps:
            if strict_dbus:
                res = self.vm.vsh(
                    "termina",
                    "root",
                    remote_sh,
                    check=True,
                    timeout=step_timeout,
                    op_desc=step_name,
                )
                combined_chunks.append(res.stdout)
            else:
                try:
                    res = self.vm.vsh(
                        "termina",
                        "root",
                        remote_sh,
                        check=False,
                        timeout=step_timeout,
                        op_desc=step_name,
                    )
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
            self.guest_summary_lines.extend(f"  {se}" for se in step_errors)

        self._parse_guest_diagnostics(
            "\n".join(combined_chunks),
            first_host_setup_user_rel=first_host_setup_user_rel,
            strict=strict_dbus,
            include_verbose=not strict_dbus,
        )

    def _collect_resource_diagnostics(self, strict_dbus: bool = True) -> None:
        sampler_warnings: list[str] = []
        if self._res_stream is not None:
            with self._res_stream._lock:
                res_err = self._res_stream.fatal_error
            if res_err is not None:
                if strict_dbus:
                    raise RuntimeError(
                        f"Fatal ChromeOS resource diagnostics error in background sampler: {res_err}"
                    ) from res_err
                sampler_warnings.append(f"background sampler error: {res_err}")

        if self.host_runner_info is None:
            _run_diag(
                strict_dbus,
                sampler_warnings,
                "host runner info read failed",
                lambda: setattr(self, "host_runner_info", read_local_host_runner_info()),
            )

        if not self._final_res_snapshot_taken and self.vm is not None:
            if strict_dbus:
                fin_res = self.vm.ssh(
                    CROS_RESOURCE_SNAPSHOT_CMD,
                    check=True,
                    timeout=45,
                    op_desc="resource_diag:final_snapshot",
                    cmd_summary="python3 <CROS_RESOURCE_SNAPSHOT>",
                )
                self._record_resource_json_line(fin_res.stdout.strip(), time.monotonic())
                self._final_res_snapshot_taken = True
            else:
                try:
                    fin_res = self.vm.ssh(
                        CROS_RESOURCE_SNAPSHOT_CMD,
                        check=False,
                        timeout=30,
                        op_desc="resource_diag:final_snapshot",
                        cmd_summary="python3 <CROS_RESOURCE_SNAPSHOT>",
                    )
                    if fin_res.returncode == 0 and fin_res.stdout.strip():
                        self._record_resource_json_line(fin_res.stdout.strip(), time.monotonic())
                        self._final_res_snapshot_taken = True
                    else:
                        err_snip = (fin_res.stderr or "").strip().replace("\n", " | ")[:200]
                        sampler_warnings.append(
                            f"final ChromeOS resource snapshot exited with rc={fin_res.returncode} (stderr={err_snip!r})"
                        )
                except Exception as exc:
                    sampler_warnings.append(f"final ChromeOS resource snapshot failed: {exc}")

        with self._lock:
            samples_copy = list(self._resource_samples)
            t_inst = self.t_install_mono
            ic_entries = [
                e for e in self._entries if e.source == "ui" and e.name == "InstallerClosed"
            ]
        ic_rel = ic_entries[0].rel_sec if ic_entries else None

        self.resource_summary_lines = summarize_resource_diagnostics(
            self.host_runner_info,
            samples_copy,
            install_mono=t_inst,
            installer_closed_rel_sec=ic_rel,
            sampler_warnings=sampler_warnings,
            strict=strict_dbus,
            include_samples=False,
        )
        full_with_samples = summarize_resource_diagnostics(
            self.host_runner_info,
            samples_copy,
            install_mono=t_inst,
            installer_closed_rel_sec=ic_rel,
            sampler_warnings=sampler_warnings,
            strict=False,
            include_samples=True,
        )
        self.resource_sample_lines = full_with_samples[len(self.resource_summary_lines) :]

    def _collect_section(
        self,
        key: str,
        err_label: str,
        err_sink: list[str],
        strict_dbus: bool,
        fn: Callable[[], None],
        rollback_list: list[str] | None = None,
    ) -> None:
        if key in self._collected_sections:
            return
        mark = len(rollback_list) if rollback_list is not None else 0
        if strict_dbus:
            try:
                fn()
            except Exception:
                if rollback_list is not None:
                    del rollback_list[mark:]
                raise
        else:
            try:
                fn()
            except Exception as exc:
                err_sink.append(f"{err_label}: {exc}")
        self._collected_sections.add(key)

    def stop_and_collect(self, strict_dbus: bool = True) -> None:
        """Stops the D-Bus monitor + resource sampler and collects read-only D-Bus, resource, UMA, and log state."""
        if strict_dbus:
            self.check_no_fatal_error()

        self._stop_requested = True
        for stream in (self._mon_stream, self._res_stream):
            if stream is not None:
                stream.stop()
        set_vm_step = getattr(self.vm, "set_step", lambda _s: None)

        set_vm_step("step5:collect_resources")
        self._collect_section(
            "resources",
            "Resource diagnostics error",
            self.resource_summary_lines,
            strict_dbus,
            lambda: self._collect_resource_diagnostics(strict_dbus=strict_dbus),
            rollback_list=self.resource_summary_lines,
        )

        if strict_dbus:
            self.check_no_fatal_error()
            self.verify_required_dbus_signal_sequence()

        if "header" not in self._collected_sections:
            self.readonly_summary_lines.clear()
            with self._lock:
                ic_entries = [e for e in self._entries if e.source == "ui" and e.name == "InstallerClosed"]
                cs_rel = self.container_started_rel_sec
            if ic_entries and cs_rel is not None:
                ic_rel = ic_entries[0].rel_sec
                self.readonly_summary_lines.append(
                    f"InstallerClosed vs ContainerStarted: installer_closed={_fmt_rel_t(ic_rel).strip()} "
                    f"container_started={_fmt_rel_t(cs_rel).strip()} "
                    f"(installer_closed_before_container_started={ic_rel < cs_rel})"
                )
            self._collected_sections.add("header")

        set_vm_step("step5:collect_readonly_dbus")
        self._collect_section(
            "readonly_dbus",
            "Read-only D-Bus snapshot error",
            self.readonly_summary_lines,
            strict_dbus,
            lambda: self._collect_readonly_dbus_snapshot(strict_dbus=strict_dbus),
            rollback_list=self.readonly_summary_lines,
        )
        set_vm_step("step5:collect_uma_histograms")
        self._collect_section(
            "uma",
            "UMA histogram query error",
            self.readonly_summary_lines,
            strict_dbus,
            lambda: self._collect_uma_histograms(strict_dbus=strict_dbus),
            rollback_list=self.readonly_summary_lines,
        )
        set_vm_step("step5:collect_host_logs")
        self._collect_section(
            "host_logs",
            "Host log scrape error",
            self.readonly_summary_lines,
            strict_dbus,
            lambda: setattr(self, "_first_host_setup_user_rel", self.scrape_host_logs()),
        )
        set_vm_step("step5:collect_guest_diag")
        self._collect_section(
            "guest_diag",
            "Guest diagnostics error",
            self.guest_summary_lines,
            strict_dbus,
            lambda: self._collect_guest_diagnostics(
                self._first_host_setup_user_rel, strict_dbus=strict_dbus
            ),
            rollback_list=self.guest_summary_lines,
        )

    def _parse_guest_diagnostics(
        self,
        raw_out: str,
        first_host_setup_user_rel: float | None = None,
        strict: bool = True,
        include_verbose: bool = True,
    ) -> None:
        sections: dict[str, list[str]] = {}
        cur_sec: str | None = None
        for line in raw_out.splitlines():
            if line.startswith("===GUEST_") and line.endswith("==="):
                cur_sec = line.strip("=")
                sections[cur_sec] = []
            elif cur_sec is not None:
                sections[cur_sec].append(line)

        guest_uptime_sec: float | None = None
        guest_epoch_sec: float | None = None
        for cline in sections.get("GUEST_CLOCK_SYNC", []):
            cline = cline.strip()
            for pfx, attr in (("uptime_sec=", "up"), ("epoch_sec=", "ep")):
                if cline.startswith(pfx):
                    try:
                        val = float(cline.split("=", 1)[1])
                    except ValueError:
                        if strict:
                            raise
                        val = None
                    if attr == "up":
                        guest_uptime_sec = val
                    else:
                        guest_epoch_sec = val
        if strict and (
            guest_uptime_sec is None
            or guest_uptime_sec <= 0
            or guest_epoch_sec is None
            or guest_epoch_sec <= 0
        ):
            raise RuntimeError(
                "Guest diagnostics GUEST_CLOCK_SYNC missing valid positive uptime_sec/epoch_sec: "
                f"uptime_sec={guest_uptime_sec!r} epoch_sec={guest_epoch_sec!r}"
            )

        parsed_json: list[tuple[dict[str, Any], int, int]] = []
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
            raw_mono = obj.get("__MONOTONIC_TIMESTAMP")
            if raw_mono in (None, ""):
                if strict:
                    raise ValueError(f"Guest journal JSON entry missing __MONOTONIC_TIMESTAMP: {obj!r}")
                mono_us = 0
            else:
                try:
                    mono_us = int(raw_mono)
                except (TypeError, ValueError):
                    if strict:
                        raise
                    mono_us = 0
            raw_rt = obj.get("__REALTIME_TIMESTAMP")
            if raw_rt in (None, ""):
                rt_us = 0
            else:
                try:
                    rt_us = int(raw_rt)
                except (TypeError, ValueError):
                    if strict:
                        raise
                    rt_us = 0
            parsed_json.append((obj, mono_us, rt_us))
            msg = str(obj.get("MESSAGE", ""))
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
        if first_host_setup_user_rel is not None and first_guest_setup_mono is not None:
            guest_boot_rel_sec = first_host_setup_user_rel - first_guest_setup_mono
        elif (
            guest_uptime_sec is not None
            and guest_epoch_sec is not None
            and self.t_install_vm_epoch is not None
        ):
            guest_boot_rel_sec = (guest_epoch_sec - guest_uptime_sec) - self.t_install_vm_epoch

        new_guest_entries: list[TimelineEntry] = []

        job_lines = [ln.strip() for ln in sections.get("GUEST_LIST_JOBS", []) if ln.strip()]
        if strict and not job_lines:
            raise RuntimeError("Guest diagnostics section 'GUEST_LIST_JOBS' is missing or empty")
        if job_lines:
            self.guest_summary_lines.append("[systemctl list-jobs (system)]")
            self.guest_summary_lines.extend(f"  {jln}" for jln in job_lines[:20])

        unit_show_raw = "\n".join(sections.get("GUEST_SYSTEMD_UNIT_SHOW", [])).strip()
        if strict and not unit_show_raw:
            raise RuntimeError(
                "Guest diagnostics section 'GUEST_SYSTEMD_UNIT_SHOW' is missing or empty"
            )
        expected_units = {
            "first-boot-cros.service",
            "maitred.service",
            "vshd.service",
            "systemd-logind.service",
            "ldconfig.service",
            "user-runtime-dir@1000.service",
            "user@1000.service",
        }
        seen_units: set[str] = set()

        def _parse_mono_prop(props_map: dict[str, str], prop_key: str) -> int:
            raw_val = props_map.get(prop_key, "").strip()
            if not raw_val:
                return 0
            try:
                return int(raw_val)
            except ValueError:
                if strict:
                    raise
                return 0

        if unit_show_raw:
            self.guest_summary_lines.append("[systemd unit monotonic timing (systemctl show)]")
            for block in re.split(r"\n\s*\n", unit_show_raw):
                props = {
                    k.strip(): v.strip()
                    for bln in block.splitlines()
                    if "=" in bln
                    for k, v in [bln.split("=", 1)]
                }
                unit_id = props.get("Id", "")
                if not unit_id:
                    continue
                seen_units.add(unit_id)
                act_state, sub_state = props.get("ActiveState", ""), props.get("SubState", "")
                result, exec_status = props.get("Result", ""), props.get("ExecMainStatus", "")
                inact_exit_us = _parse_mono_prop(props, "InactiveExitTimestampMonotonic")
                act_enter_us = _parse_mono_prop(props, "ActiveEnterTimestampMonotonic")
                exec_start_us = _parse_mono_prop(props, "ExecMainStartTimestampMonotonic")
                exec_exit_us = _parse_mono_prop(props, "ExecMainExitTimestampMonotonic")
                start_us = exec_start_us or inact_exit_us
                end_us = exec_exit_us or act_enter_us
                start_s, end_s = start_us / 1_000_000.0, end_us / 1_000_000.0
                dur_str = (
                    f"{end_s - start_s:.3f}s"
                    if (start_us > 0 and end_us >= start_us)
                    else "in-flight/n/a"
                )
                act_dur_extra = (
                    f", activate_dur={(act_enter_us - inact_exit_us) / 1_000_000.0:.3f}s"
                    if (inact_exit_us > 0 and act_enter_us >= inact_exit_us)
                    else ""
                )
                host_window = ""
                if guest_boot_rel_sec is not None and start_us > 0:
                    h_start = guest_boot_rel_sec + start_s
                    new_guest_entries.append(
                        TimelineEntry(
                            h_start,
                            "guest",
                            f"UnitStart({unit_id})",
                            f"(guest+{start_s:.2f}s) systemctl show start ({act_state}/{sub_state})",
                        )
                    )
                    if end_us >= start_us and end_us > 0:
                        h_end = guest_boot_rel_sec + end_s
                        host_window = f" host={_fmt_rel_t(h_start).strip()}..{_fmt_rel_t(h_end).strip()}"
                        if exec_exit_us > 0:
                            new_guest_entries.append(
                                TimelineEntry(
                                    h_end,
                                    "guest",
                                    f"UnitDone({unit_id})",
                                    f"(guest+{end_s:.2f}s) systemctl show exit dur={dur_str}{act_dur_extra} result={result} status={exec_status}",
                                )
                            )
                    else:
                        host_window = f" host={_fmt_rel_t(h_start).strip()}..(running)"
                self.guest_summary_lines.append(
                    f"  {unit_id}: state={act_state}/{sub_state} result={result} "
                    f"guest=+{start_s:.3f}s..+{end_s:.3f}s (dur={dur_str}{act_dur_extra}, exit_status={exec_status})"
                    f"{host_window}"
                )
        if strict:
            missing_units = sorted(expected_units - seen_units)
            if missing_units:
                raise RuntimeError(
                    f"GUEST_SYSTEMD_UNIT_SHOW missing expected systemd units: {missing_units!r}"
                )

        self.guest_verbose_lines.clear()
        for label, key, max_lines, verbose_only in (
            ("systemd-analyze (system)", "GUEST_ANALYZE", 12, False),
            ("systemd-analyze blame top-8 (system)", "GUEST_BLAME", 8, False),
            ("systemd-analyze --user (terminauser@)", "GUEST_USER_ANALYZE", 12, False),
            ("systemd-analyze --user blame top-8 (terminauser@)", "GUEST_USER_BLAME", 8, False),
            ("systemd-analyze critical-chain (system)", "GUEST_CRITICAL_CHAIN", 80, True),
            ("systemd-analyze --user critical-chain (terminauser@)", "GUEST_USER_CRITICAL_CHAIN", 80, True),
            ("systemctl --user status cros-garcon & sommelier", "GUEST_GARCON_STATUS", 80, True),
        ):
            if verbose_only and not include_verbose:
                continue
            sec_lines = [ln for ln in sections.get(key, []) if ln.strip()]
            dest = self.guest_verbose_lines if verbose_only else self.guest_summary_lines
            if not sec_lines:
                if strict:
                    raise RuntimeError(f"Guest diagnostics section {key!r} ({label}) is missing or empty")
                dest.append(f"[{label}]: <empty or unavailable>")
                continue
            dest.append(f"[{label}]")
            dest.extend(f"  {ln}" for ln in sec_lines[:max_lines])

        if include_verbose and parsed_json:
            self.guest_verbose_lines.append("[journalctl -b (monotonic, filtered)]")
            for obj, mono_us, _rt_us in parsed_json[:140]:
                ident_label = str(obj.get("SYSLOG_IDENTIFIER") or obj.get("_COMM") or "guest")
                self.guest_verbose_lines.append(
                    f"  [{mono_us / 1_000_000.0:10.6f}] {ident_label}: {obj.get('MESSAGE', '')}"
                )

        # Project daemon-level guest journal events onto the unified timeline (unit start/done
        # are already projected above from `systemctl show` monotonic properties).
        setup_user_guest_seq = 0
        for obj, mono_us, rt_us in parsed_json:
            msg = str(obj.get("MESSAGE", ""))
            comm = str(obj.get("_COMM", ""))
            syslog_id = str(obj.get("SYSLOG_IDENTIFIER", ""))
            unit = str(obj.get("_SYSTEMD_UNIT", "") or obj.get("UNIT", ""))
            ident = f"{comm} {syslog_id} {unit}".lower()
            g_mono = mono_us / 1_000_000.0
            if guest_boot_rel_sec is not None and mono_us > 0:
                rel = guest_boot_rel_sec + g_mono
            elif rt_us and self.t_install_vm_epoch is not None:
                rel = (rt_us / 1_000_000.0) - self.t_install_vm_epoch
            else:
                continue
            tag = f"(guest+{g_mono:.2f}s) "

            ev_name: str | None = None
            ev_detail = tag + msg
            if "first-boot-cros" in ident and "systemd" not in ident:
                ev_name = "FirstBootStep"
            elif "Started maitred" in msg:
                ev_name = "MaitredStarted"
            elif "Wrote container token to /dev/.container_token" in msg:
                ev_name = "ContainerTokenWrote"
            elif "Received request to setup a new user" in msg:
                setup_user_guest_seq += 1
                ev_name = "MaitredSetUpUser"
                ev_detail = f"{tag}call #{setup_user_guest_seq}: {msg}"
            elif "already exists" in msg and "maitred" in ident:
                ev_name = "MaitredUserExists"
            elif "useradd" in ident and ("new group:" in msg or "new user:" in msg):
                ev_name = "UseraddDone" if "new user:" in msg else "UseraddGroup"
            elif "usermod" in ident:
                ev_name = "Usermod"
            elif "maitred" in ident and any(w in msg.lower() for w in ("failed", "error", "linger")):
                ev_name = "MaitredLog"
            elif "still waiting for /dev/.container_token" in msg:
                ev_name = "SommelierWaitToken"
            elif "sommelier" in msg.lower() and any(
                w in msg.lower() for w in ("timed out", "failed", "scheduled restart", "main process exited")
            ):
                ev_name = "SommelierIssue"
            elif "garcon" in ident and "systemd" not in ident:
                ev_name, ev_detail = "GarconLog", tag + msg[:140]
            elif "vshd" in ident and "systemd" not in ident:
                ev_name, ev_detail = "GuestVshd", tag + msg[:140]

            if ev_name is not None:
                new_guest_entries.append(TimelineEntry(rel, "guest", ev_name, ev_detail))

        with self._lock:
            self._guest_log_entries = new_guest_entries

    def format_report(self, include_raw_logs: bool = False) -> str:
        sorted_entries = self.all_entries()
        lines = ["=== INITIALIZATION TIMELINE (relative to Install click) ==="]
        for e in sorted_entries:
            lines.append(f"  {_fmt_rel_t(e.rel_sec)}  [{e.source:<9}] {e.name}: {e.detail}")
        lines.append("  --- Runner & ChromeOS Resource Diagnostics (read-only) ---")
        if self.resource_summary_lines:
            lines.extend(f"  {r_line}" for r_line in self.resource_summary_lines)
            if include_raw_logs and self.resource_sample_lines:
                lines.extend(f"  {s_line}" for s_line in self.resource_sample_lines)
        else:
            lines.append("  <not collected>")
        lines.append("  --- Read-Only D-Bus & UMA Snapshot ---")
        lines.extend(f"  {s_line}" for s_line in self.readonly_summary_lines)
        if self.guest_summary_lines:
            lines.append("  --- Guest Boot & Service Timing Summary (read-only) ---")
            lines.extend(f"  {g_line}" for g_line in self.guest_summary_lines)
            if include_raw_logs and self.guest_verbose_lines:
                lines.extend(f"  {v_line}" for v_line in self.guest_verbose_lines)
        if include_raw_logs:
            if self.messages_excerpt:
                lines.append("  --- /var/log/messages excerpt ---")
                lines.extend(f"    {m_line}" for m_line in self.messages_excerpt.splitlines()[-40:])
            if self.chrome_excerpt:
                lines.append("  --- /var/log/chrome/chrome excerpt ---")
                lines.extend(f"    {c_line}" for c_line in self.chrome_excerpt.splitlines()[-30:])
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
        log(
            f"  [throttle] Throttling host QEMU PID {pid} to {self.quota_pct}% CPU duty cycle "
            f"(initial_delay={self.initial_delay_sec:.1f}s)..."
        )
        period = 0.100  # 100 ms period so Chrome's 4s timers still wake promptly
        run_slice = period * (self.quota_pct / 100.0)
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


def _pid_matches_qemu(pid: int, qemu_bin: str, proc_root: Path = Path("/proc")) -> bool:
    """Returns True iff `/proc/<pid>` is a live userland QEMU/KVM process matching `qemu_bin`."""
    proc_dir = proc_root / str(pid)
    comm_path = proc_dir / "comm"
    cmdline_path = proc_dir / "cmdline"
    try:
        if not comm_path.exists():
            return False
        comm = comm_path.read_text(encoding="utf-8", errors="replace").strip()
        raw_cmdline = cmdline_path.read_bytes() if cmdline_path.exists() else b""
    except OSError:
        return False
    # Kernel threads (e.g. `kvm-irqfd-clean`, `kvm-pit/...`) have empty `/proc/<pid>/cmdline`.
    if not raw_cmdline:
        return False
    argv0 = raw_cmdline.split(b"\x00", 1)[0].decode("utf-8", errors="replace")
    argv0_name = Path(argv0).name
    expected_name = Path(qemu_bin).name
    return bool(
        (expected_name and (argv0_name == expected_name or comm == expected_name[:15]))
        or argv0_name.startswith(("qemu-system", "qemu-kvm"))
        or argv0_name in ("kvm", "qemu-kvm")
        or comm.startswith(("qemu-system", "qemu-kvm"))
    )


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
        self._current_step: str = "init"

    def set_step(self, step: str) -> None:
        self._current_step = step

    def get_step(self) -> str:
        return self._current_step

    def _ssh_common_opts(self) -> list[str]:
        return [
            "-i",
            str(self.ssh_key),
            "-o",
            "IdentitiesOnly=yes",
            "-o",
            "StrictHostKeyChecking=no",
            "-o",
            "UserKnownHostsFile=/dev/null",
        ]

    def _ssh_base_cmd(self) -> list[str]:
        return [
            "ssh",
            *self._ssh_common_opts(),
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

    def _run_vm_cmd(
        self,
        argv: list[str],
        *,
        op_desc: str,
        cmd_summary: str,
        timeout: int,
        check: bool = True,
        capture_output: bool = True,
    ) -> subprocess.CompletedProcess[str]:
        t0 = time.monotonic()
        try:
            return subprocess.run(
                argv, check=check, text=True, timeout=timeout, capture_output=capture_output
            )
        except subprocess.TimeoutExpired as exc:
            raw_err = (
                exc.stderr.decode("utf-8", "replace")
                if isinstance(exc.stderr, bytes)
                else (exc.stderr or "")
            )
            err_snip = " | ".join(ln.strip() for ln in raw_err.splitlines() if ln.strip())[:160]
            ctx = format_vm_cmd_error_context(
                operation=op_desc,
                step=self.get_step(),
                cmd_summary=_summarize_cmd(cmd_summary),
                elapsed_sec=time.monotonic() - t0,
                timeout_sec=timeout,
            )
            raise VMCommandTimeoutError(
                f"VM command timed out ({ctx})" + (f"; stderr={err_snip!r}" if err_snip else "")
            ) from exc
        except subprocess.CalledProcessError as exc:
            log(
                f"VM command failed ({op_desc}, step={self.get_step()!r}, rc={exc.returncode}):\n"
                f"STDOUT:\n{exc.stdout}\nSTDERR:\n{exc.stderr}"
            )
            raise

    def ssh(
        self,
        remote_cmd: str,
        check: bool = True,
        timeout: int = 300,
        capture_output: bool = True,
        *,
        op_desc: str = "ssh",
        cmd_summary: str | None = None,
    ) -> subprocess.CompletedProcess[str]:
        return self._run_vm_cmd(
            [*self._ssh_base_cmd(), remote_cmd],
            op_desc=op_desc,
            cmd_summary=cmd_summary or remote_cmd,
            timeout=timeout,
            check=check,
            capture_output=capture_output,
        )

    def scp_to(
        self,
        local_path: Path,
        remote_path: str,
        *,
        timeout: int = 180,
        op_desc: str = "scp_to",
    ) -> None:
        self._run_vm_cmd(
            ["scp", *self._ssh_common_opts(), "-P", str(self.ssh_port), str(local_path), f"root@127.0.0.1:{remote_path}"],
            op_desc=op_desc,
            cmd_summary=f"{local_path.name} -> {remote_path}",
            timeout=timeout,
        )

    def dbus_call_proto(
        self,
        dest: str,
        method: str,
        req_msg: Message,
        resp_cls: type[TMessage],
        timeout: int = 30,
    ) -> tuple[TMessage, bytes]:
        """Executes a synchronous D-Bus protobuf method call on the system bus and validates the reply."""
        obj_path = "/" + dest.replace(".", "/")
        ctx = f"{dest.rsplit('.', 1)[-1]}.{method}"
        res = self.ssh(
            f"dbus-send --system --type=method_call --print-reply "
            f"--dest={dest} {obj_path} {dest}.{method} "
            f"{to_dbus_byte_arg(req_msg.SerializeToString())}",
            check=True,
            timeout=timeout,
            op_desc=f"dbus_call_proto({ctx})",
            cmd_summary=f"dbus-send {dest}.{method}",
        )
        raw_resp = parse_dbus_send_byte_array(res.stdout, ctx)
        return parse_and_validate_proto(raw_resp, resp_cls, ctx), raw_resp

    def vsh(
        self,
        vm_name: str,
        user: str,
        sh_script: str,
        *,
        check: bool = True,
        timeout: int = 60,
        op_desc: str | None = None,
    ) -> subprocess.CompletedProcess[str]:
        """Runs `sh -lc <sh_script>` inside `vm_name` via `vsh` as `chronos`."""
        assert self.owner_hash
        cmd = (
            f"sudo -u chronos CROS_USER_ID_HASH={shlex.quote(self.owner_hash)} "
            f"vsh --vm_name={shlex.quote(vm_name)} --owner_id={shlex.quote(self.owner_hash)} "
            f"--user={shlex.quote(user)} -- sh -lc {shlex.quote(sh_script)}"
        )
        return self.ssh(
            cmd,
            check=check,
            timeout=timeout,
            op_desc=op_desc or f"vsh({vm_name},{user})",
            cmd_summary=sh_script,
        )

    def vmc(self, *args: str, timeout: int = 120) -> subprocess.CompletedProcess[str]:
        """Runs non-interactive `vmc <args...>` as `chronos`."""
        assert self.owner_hash
        quoted = " ".join(shlex.quote(a) for a in args)
        return self.ssh(
            f"sudo -u chronos CROS_USER_ID_HASH={shlex.quote(self.owner_hash)} "
            f"VMC_NONINTERACTIVE=1 vmc {quoted}",
            timeout=timeout,
            op_desc=f"vmc({args[0]})" if args else "vmc",
            cmd_summary=f"vmc {' '.join(args)}",
        )

    def wait_for_ssh(
        self, timeout_sec: int = 90, different_from_boot_id: str | None = None
    ) -> str:
        t0 = time.monotonic()
        deadline = t0 + timeout_sec
        while time.monotonic() < deadline:
            try:
                res = self.ssh(
                    "cat /proc/sys/kernel/random/boot_id",
                    check=False,
                    timeout=8,
                    op_desc="wait_for_ssh:probe",
                )
            except VMCommandTimeoutError:
                res = None
            if res is not None and res.returncode == 0:
                boot_id = res.stdout.strip()
                if boot_id and (
                    different_from_boot_id is None or boot_id != different_from_boot_id
                ):
                    return boot_id
            time.sleep(1.5)
        ctx = format_vm_cmd_error_context(
            operation="wait_for_ssh",
            step=self.get_step(),
            cmd_summary=f"ssh root@127.0.0.1:{self.ssh_port} boot_id",
            elapsed_sec=time.monotonic() - t0,
            timeout_sec=timeout_sec,
        )
        raise VMCommandTimeoutError(f"Timed out waiting for SSH ({ctx})")

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
        self.set_step("prepare:boot_cros_vm")
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
        _terminate_proc(self._devtools_fwd_proc)
        self._devtools_fwd_proc = None

        if self.pid_file.exists():
            try:
                pid = int(self.pid_file.read_text().strip())
                proc_dir = Path(f"/proc/{pid}")
                if _pid_matches_qemu(pid, self.qemu_bin):
                    os.kill(pid, signal.SIGCONT)
                    os.kill(pid, signal.SIGTERM)
                    deadline = time.monotonic() + 5.0
                    while time.monotonic() < deadline and proc_dir.exists():
                        time.sleep(0.2)
                    if proc_dir.exists():
                        os.kill(pid, signal.SIGKILL)
                    log(f"Terminated QEMU PID {pid}.")
            except (ProcessLookupError, PermissionError, ValueError, OSError):
                pass
            self.pid_file.unlink(missing_ok=True)

    def prepare_nested_vm_host_and_login(self, baguette_image: Path) -> str:
        self.set_step("prepare:remove_rootfs_verification_and_reboot")
        log("Removing rootfs verification to apply nested-KVM vm_concierge fix...")
        pre_boot_id = self.ssh("cat /proc/sys/kernel/random/boot_id").stdout.strip()
        self.ssh(
            "/usr/share/vboot/bin/make_dev_ssd.sh --remove_rootfs_verification --partitions 2"
        )
        try:
            self.ssh("reboot", check=False, timeout=20, op_desc="prepare:reboot")
        except VMCommandTimeoutError:
            pass
        self.wait_for_ssh(timeout_sec=120, different_from_boot_id=pre_boot_id)
        self.assert_guest_kvm_available()

        self.set_step("prepare:resize_stateful_and_patch_concierge")
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

        self.set_step("prepare:autologin")
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

        self.set_step("prepare:scp_baguette_image")
        remote_dl = f"/home/user/{owner_hash}/MyFiles/Downloads/baguette_arch_rootfs.img.zst"
        log(f"Copying {baguette_image} -> {remote_dl}...")
        self.scp_to(baguette_image, remote_dl, op_desc="prepare:scp_baguette_image")
        local_sha = hashlib.sha256(baguette_image.read_bytes()).hexdigest()
        remote_sha = self.ssh(f"sha256sum '{remote_dl}'").stdout.split()[0]
        if local_sha != remote_sha:
            raise RuntimeError(f"SHA256 mismatch: {local_sha} != {remote_sha}")
        log(f"Verified image SHA256 inside ChromeOS VM: {local_sha}")

        self._setup_devtools_tunnel()
        return remote_dl

    def _setup_devtools_tunnel(self) -> None:
        self.set_step("prepare:setup_devtools_tunnel")
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
        tunnel_timeout = 20.0
        t0 = time.monotonic()
        deadline = t0 + tunnel_timeout
        last_err: Exception | None = None
        while time.monotonic() < deadline:
            try:
                _ = self.list_cdp_targets(timeout=5.0)
                return
            except Exception as exc:
                last_err = exc
                time.sleep(0.3)
        ctx = format_cdp_error_context(
            operation="SSH -L DevTools tunnel readiness probe",
            target_label="DevToolsTunnel",
            target_url=f"http://127.0.0.1:{self._local_dt_port}/json/list",
            target_id="browser",
            step=self.get_step(),
            elapsed_sec=time.monotonic() - t0,
            timeout_sec=tunnel_timeout,
        )
        raise CDPTimeoutError(
            f"Timed out establishing SSH port forward to Chrome DevToolsActivePort ({ctx}; last error: {last_err})"
        )

    def connect_browser_cdp(self, label: str = "Browser-Root") -> CDPConnection:
        assert self._local_dt_port and self._browser_ws_path
        ws_url = f"ws://127.0.0.1:{self._local_dt_port}{self._browser_ws_path}"
        return CDPConnection(
            ws_url,
            target_label=label,
            target_url=ws_url,
            target_id=self._browser_ws_path.rsplit("/", 1)[-1] or "browser",
            step_getter=self.get_step,
        )

    def list_cdp_targets(self, timeout: float = 20.0) -> list[dict]:
        assert self._local_dt_port and self._remote_dt_port
        url = f"http://127.0.0.1:{self._local_dt_port}/json/list"
        t0 = time.monotonic()
        try:
            raw = urllib.request.urlopen(url, timeout=timeout).read()
            targets = json.loads(raw)
        except Exception as exc:
            elapsed = time.monotonic() - t0
            ctx = format_cdp_error_context(
                operation="HTTP GET /json/list",
                target_label="DevToolsHTTP",
                target_url=url,
                target_id="<json-list>",
                step=self.get_step(),
                elapsed_sec=elapsed,
                timeout_sec=timeout,
            )
            if _is_ws_timeout_exc(exc):
                raise CDPTimeoutError(
                    f"CDP target list HTTP request timed out ({ctx}): {type(exc).__name__}: {exc}"
                ) from exc
            raise CDPError(
                f"CDP target list HTTP request failed ({ctx}): {type(exc).__name__}: {exc}"
            ) from exc
        for tgt in targets:
            if "webSocketDebuggerUrl" in tgt:
                tgt["webSocketDebuggerUrl"] = tgt["webSocketDebuggerUrl"].replace(
                    f"127.0.0.1:{self._remote_dt_port}",
                    f"127.0.0.1:{self._local_dt_port}",
                )
        return targets

    def wait_for_cdp_target(
        self,
        predicate: Callable[[dict[str, Any]], bool],
        *,
        operation: str,
        target_label: str,
        target_url: str,
        target_id: str = "<pending>",
        timeout: float = 30.0,
        interval: float = 0.4,
        require_ws: bool = True,
        err_prefix: str | None = None,
    ) -> dict[str, Any]:
        """Polls `list_cdp_targets()` until `predicate(tgt)` matches or raises `CDPTimeoutError`."""
        t0 = time.monotonic()
        deadline = t0 + timeout
        while time.monotonic() < deadline:
            for tgt in self.list_cdp_targets():
                if (not require_ws or "webSocketDebuggerUrl" in tgt) and predicate(tgt):
                    return tgt
            time.sleep(interval)
        ctx = format_cdp_error_context(
            operation=operation,
            target_label=target_label,
            target_url=target_url,
            target_id=target_id,
            step=self.get_step(),
            elapsed_sec=time.monotonic() - t0,
            timeout_sec=timeout,
        )
        prefix = err_prefix or f"Timed out waiting for CDP target {target_label!r}"
        raise CDPTimeoutError(f"{prefix} ({ctx})")

    def connect_cdp_target(
        self,
        predicate: Callable[[dict[str, Any]], bool],
        *,
        operation: str,
        target_label: str,
        target_url: str,
        target_id: str = "<pending>",
        timeout: float = 30.0,
        interval: float = 0.4,
        err_prefix: str | None = None,
    ) -> CDPConnection:
        tgt = self.wait_for_cdp_target(
            predicate,
            operation=operation,
            target_label=target_label,
            target_url=target_url,
            target_id=target_id,
            timeout=timeout,
            interval=interval,
            require_ws=True,
            err_prefix=err_prefix,
        )
        return CDPConnection.from_target(tgt, label=target_label, step_getter=self.get_step)

    def open_crosh_tab(self, label: str) -> CroshTab:
        self.set_step(f"open_crosh_tab({label})")
        browser_conn = self.connect_browser_cdp(label=f"Browser-CreateCrosh({label})")
        try:
            tid = browser_conn.call(
                "Target.createTarget",
                {"url": "chrome-untrusted://crosh/"},
                op_desc=f"open_crosh_tab({label}):Target.createTarget",
            )["targetId"]
        finally:
            browser_conn.close()

        conn = self.connect_cdp_target(
            lambda tgt: tgt.get("id") == tid,
            operation=f"attach_target({label})",
            target_label=label,
            target_url="chrome-untrusted://crosh/",
            target_id=str(tid),
            timeout=30.0,
            interval=0.3,
            err_prefix="Failed to attach to crosh tab",
        )
        tab = CroshTab(label, conn)
        tab.wait_for(
            lambda txt: txt.rstrip().endswith("crosh>"),
            timeout=45.0,
            desc=f"{label} initial crosh> prompt",
        )
        log(f"Opened {label} (`chrome-untrusted://crosh/`, target={tid})")
        return tab

    def verify_guest_user_session(self, vm_name: str, expected_username: str) -> None:
        self.set_step("step5:verify_guest_user_session")
        log(
            f"Verifying in-guest OS, UID/GID 1000, primary group '{expected_username}', "
            f"exact supplementary groups {sorted(EXPECTED_GUEST_SUPPLEMENTARY_GROUPS)}, "
            f"and active cros-garcon.service for VM '{vm_name}'..."
        )
        check_script = (
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
            '[ "$GARCON" = "active" ]'
        )
        res = self.vsh(
            vm_name,
            expected_username,
            check_script,
            timeout=InitTimelineRecorder.GUEST_DIAG_TIMEOUT_SEC,
            op_desc=f"verify_guest_user_session({vm_name})",
        )
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
    ) -> dict:
        """Drives ChromeOS Settings -> About ChromeOS -> Developers -> Set up -> crostini-installer.

        Returns the initial `chrome-untrusted://terminal` vmshell CDP target dictionary opened by
        the installer upon completion.
        """
        self.set_step("step2:open_os_settings")
        log("Opening `chrome://os-settings/` via CDP...")
        t_launch0 = time.monotonic()
        browser_conn = self.connect_browser_cdp(label="Browser-LaunchOSSettings")
        try:
            # chrome://os-settings/ is a System Web App (SWA); Target.createTarget triggers
            # LaunchSystemWebAppAsync and returns CDP error -32000 ("Failed to open a new tab")
            # while opening the SWA window asynchronously. Only that exact SWA launch response
            # or a direct targetId is permitted.
            swa_res = browser_conn.call(
                "Target.createTarget",
                {"url": "chrome://os-settings/"},
                allow_error=True,
                op_desc="launch chrome://os-settings/ SWA",
            )
            if "error" in swa_res:
                err_obj = swa_res["error"]
                if not (
                    isinstance(err_obj, dict)
                    and err_obj.get("code") == -32000
                    and err_obj.get("message") == "Failed to open a new tab"
                ):
                    raise CDPError(
                        f"Unexpected CDP error launching chrome://os-settings/ "
                        f"({browser_conn._ctx('launch chrome://os-settings/ SWA', time.monotonic() - t_launch0, browser_conn.default_timeout)}): {swa_res!r}"
                    )
            elif "targetId" not in swa_res:
                raise CDPError(
                    f"Unexpected CDP response launching chrome://os-settings/ "
                    f"({browser_conn._ctx('launch chrome://os-settings/ SWA', time.monotonic() - t_launch0, browser_conn.default_timeout)}): {swa_res!r}"
                )
        finally:
            browser_conn.close()

        settings_conn = self.connect_cdp_target(
            lambda tgt: "chrome://os-settings" in tgt.get("url", ""),
            operation="find_target(chrome://os-settings)",
            target_label="OS-Settings",
            target_url="chrome://os-settings/",
            timeout=30.0,
            interval=0.5,
            err_prefix="Could not find `chrome://os-settings/` target in CDP",
        )
        try:
            self.set_step("step2:navigate_os_settings_click_setup")
            log(
                "Navigating OS Settings UI: clicking `About ChromeOS` -> "
                "`Developers` -> `Linux development environment` -> `Set up`..."
            )
            nav_res = settings_conn.poll_js(
                """(() => {
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
                })()""",
                lambda val: isinstance(val, str) and val.startswith("CLICKED_SETUP:"),
                op_desc="OS-Settings:navigate_and_click_setup",
                timeout=30.0,
            )
            log(f"  OS Settings UI action: {nav_res}")
        finally:
            settings_conn.close()

        self.set_step("step2:attach_crostini_installer")
        installer_conn = self.connect_cdp_target(
            lambda tgt: "chrome://crostini-installer" in tgt.get("url", ""),
            operation="find_target(chrome://crostini-installer)",
            target_label="Crostini-Installer",
            target_url="chrome://crostini-installer/",
            timeout=30.0,
            interval=0.5,
            err_prefix="`chrome://crostini-installer` dialog did not open after clicking Set up",
        )
        try:
            self.set_step("step2:installer_click_next")
            installer_conn.poll_js(
                """(() => {
                    const app = document.querySelector('crostini-installer-app');
                    if (!app || !app.shadowRoot) return 'no-app';
                    const nextBtn = app.shadowRoot.querySelector('#next');
                    if (!nextBtn || nextBtn.hidden) return 'no-next';
                    nextBtn.click();
                    return 'CLICKED_NEXT';
                })()""",
                lambda val: val == "CLICKED_NEXT",
                op_desc="Crostini-Installer:click_next",
                timeout=30.0,
            )
            log("  Clicked `Next` in `chrome://crostini-installer`.")

            self.set_step("step2:installer_click_install")
            step2 = installer_conn.poll_js(
                f"""(() => {{
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
                }})()""",
                lambda val: isinstance(val, str) and val.startswith("CLICKED_INSTALL:"),
                op_desc="Crostini-Installer:set_username_and_click_install",
                timeout=30.0,
            )
            timeline.mark_install_clicked(username)
            log(f"  Clicked `Install` in `chrome://crostini-installer` ({step2}).")

            self.set_step("step2:wait_installer_complete")
            log("  Waiting for `chrome://crostini-installer` to finish provisioning `termina`...")
            installer_finish_timeout = 420.0
            t0 = time.monotonic()
            last_status: dict[str, str] = {"err": "", "installing": ""}
            while time.monotonic() - t0 < installer_finish_timeout:
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
                    self.set_step("step2:attach_initial_terminal_vmshell")
                    vmshell_tgt = self.wait_for_cdp_target(
                        lambda x: "chrome-untrusted://terminal/html/terminal.html?command=vmshell"
                        in x.get("url", ""),
                        operation="wait_for_target(Terminal-App-Initial vmshell)",
                        target_label="Terminal-App-Initial",
                        target_url="chrome-untrusted://terminal/html/terminal.html?command=vmshell",
                        timeout=45.0,
                        interval=0.5,
                        err_prefix=(
                            f"`chrome://crostini-installer` closed after {elapsed:.1f}s "
                            f"(last progress: {last_status.get('installing')!r}), but the ChromeOS "
                            "Terminal app (`chrome-untrusted://terminal` vmshell tab) did not open"
                        ),
                    )
                    log(
                        f"  `chrome://crostini-installer` completed and closed in {elapsed:.1f}s "
                        f"(last progress: {last_status.get('installing')!r}, "
                        f"Terminal app vmshell target={vmshell_tgt.get('id')})."
                    )
                    return vmshell_tgt
                try:
                    status = installer_conn.eval_js(
                        """(() => {
                        const app = document.querySelector('crostini-installer-app');
                        if (!app || !app.shadowRoot) return null;
                        const err = app.shadowRoot.querySelector('#error-message:not([hidden]) div')?.innerText?.trim()
                            || app.shadowRoot.querySelector('#error-message div')?.innerText?.trim();
                        const installing = app.shadowRoot.querySelector('#installing-message div')?.innerText?.trim();
                        return { err: err || '', installing: installing || '' };
                    })()""",
                        timeout=30.0,
                        op_desc="Crostini-Installer:poll_status",
                    )
                except (CDPError, CDPTimeoutError):
                    # If the installer dialog closed while `eval_js` was in flight, the next loop
                    # iteration handles `not installer_open`; if it is still open, fail immediately.
                    still_open = any(
                        "chrome://crostini-installer" in x.get("url", "")
                        for x in self.list_cdp_targets()
                    )
                    if still_open:
                        raise
                    status = None
                if isinstance(status, dict):
                    if status.get("installing"):
                        last_status["installing"] = status["installing"]
                    if status.get("err"):
                        last_status["err"] = status["err"]
                        raise RuntimeError(
                            f"`chrome://crostini-installer` failed with UI error: {status['err']} "
                            f"(last progress: {last_status.get('installing')!r})"
                        )
                time.sleep(1.5)
            ctx = installer_conn._ctx(
                "Crostini-Installer:wait_for_finish",
                time.monotonic() - t0,
                installer_finish_timeout,
            )
            raise CDPTimeoutError(
                f"Timed out waiting for `chrome://crostini-installer` to finish ({ctx}; last status={last_status!r})"
            )
        finally:
            installer_conn.close()

    def _open_fresh_terminal_from_home(self, old_target_ids: set[str]) -> CroshTab:
        """Clicks `penguin` in `chrome-untrusted://terminal/html/terminal.html#home` to launch a fresh Terminal tab."""
        self.set_step("step3:relaunch_fresh_terminal_from_home")
        home_conn = self.connect_cdp_target(
            lambda tgt: "chrome-untrusted://terminal/html/terminal.html#home" in tgt.get("url", ""),
            operation="find_target(Terminal-Home #home)",
            target_label="Terminal-Home",
            target_url="chrome-untrusted://terminal/html/terminal.html#home",
            target_id="<missing>",
            timeout=15.0,
            interval=0.4,
            err_prefix="Could not find `chrome-untrusted://terminal/html/terminal.html#home` target to relaunch Terminal",
        )
        try:
            click_res = home_conn.poll_js(
                """(() => {
                    const app = document.querySelector('terminal-home-app');
                    if (!app || !app.shadowRoot) return 'no-app';
                    const links = Array.from(app.shadowRoot.querySelectorAll('a[href*="command=vmshell"]'));
                    if (!links.length) return 'no-links';
                    const href = links[0].getAttribute('href');
                    links[0].click();
                    return 'CLICKED:' + href;
                })()""",
                lambda val: isinstance(val, str) and val.startswith("CLICKED:"),
                op_desc="Terminal-Home:click_penguin_vmshell",
                timeout=30.0,
            )
            log(f"  [Terminal-Home] Launched fresh Terminal tab via `{click_res}`")
        finally:
            home_conn.close()

        fresh_tgt = self.wait_for_cdp_target(
            lambda tgt: (
                tgt.get("id", "") not in old_target_ids
                and "chrome-untrusted://terminal/html/terminal.html?command=vmshell" in tgt.get("url", "")
            ),
            operation="wait_for_target(Terminal-App-Fresh vmshell)",
            target_label="Terminal-App-Fresh",
            target_url="chrome-untrusted://terminal/html/terminal.html?command=vmshell",
            timeout=45.0,
            interval=0.4,
            err_prefix="Timed out waiting for fresh Terminal vmshell tab after clicking penguin in Terminal Home",
        )
        log(f"  Attached to fresh Terminal vmshell tab (target={fresh_tgt.get('id')})")
        return CroshTab(
            "Terminal-App-Fresh",
            CDPConnection.from_target(
                fresh_tgt, label="Terminal-App-Fresh", step_getter=self.get_step
            ),
        )

    def _observe_terminal_until_prompt_or_error(
        self,
        tab: CroshTab,
        username: str,
        timeline: InitTimelineRecorder,
        *,
        timeout: float,
        first_output_event: str,
        log_first_output: bool = False,
    ) -> tuple[str, str]:
        """Polls `tab` until prompt (`'prompt'`), vmshell error (`'error'`), or deadline (`'timeout'`)."""
        deadline = time.monotonic() + timeout
        first_output_logged = False
        last_txt = ""
        while time.monotonic() < deadline:
            timeline.check_no_fatal_error()
            txt = tab.get_text()
            last_txt = txt
            if not first_output_logged and txt.strip():
                first_output_logged = True
                first_ln = txt.strip().splitlines()[0][:140]
                fo_rel = timeline.record_ui(first_output_event, first_ln)
                if log_first_output:
                    log(f"  [{tab.label}] First output at t+{fo_rel:.1f}s: {first_ln}")
            if f"[{username}@" in txt and txt.rstrip().endswith("$"):
                return "prompt", txt
            if (
                txt.strip() == KNOWN_INITIAL_TERMINAL_TIMEOUT_ERROR
                or "Launching vmshell failed:" in txt
                or "[process exited" in txt
                or "ERROR vsh:" in txt
            ):
                return "error", txt
            time.sleep(0.5)
        return "timeout", last_txt

    def verify_terminal_app_with_readiness_gate(
        self,
        initial_vmshell_tgt: dict,
        username: str,
        timeline: InitTimelineRecorder,
        throttler: HostQemuCpuThrottler | None = None,
    ) -> None:
        """Observes the installer-opened Terminal tab, gates on `ContainerStarted`, and verifies the Terminal shell."""
        self.set_step("step3:observe_initial_terminal")
        initial_tid = initial_vmshell_tgt["id"]
        initial_tab = CroshTab(
            "Terminal-App-Initial",
            CDPConnection.from_target(
                initial_vmshell_tgt,
                label="Terminal-App-Initial",
                step_getter=self.get_step,
            ),
        )
        active_tab: CroshTab | None = None
        try:
            log("  Observing installer-opened ChromeOS Terminal app window...")
            outcome, initial_final_buffer = self._observe_terminal_until_prompt_or_error(
                initial_tab,
                username,
                timeline,
                timeout=120.0,
                first_output_event="InitialTerminalFirstOutput",
            )

            if outcome == "prompt":
                # Ensure ContainerStarted is also recorded on the timeline
                self.set_step("step3:wait_container_started")
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
                self.set_step("step3:wait_container_started")
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
                    self.set_step("step3:observe_fresh_terminal")
                    fresh_timeout = 180.0
                    t_fresh0 = time.monotonic()
                    f_outcome, last_ftxt = self._observe_terminal_until_prompt_or_error(
                        fresh_tab,
                        username,
                        timeline,
                        timeout=fresh_timeout,
                        first_output_event="FreshTerminalFirstOutput",
                        log_first_output=True,
                    )
                    if f_outcome == "prompt":
                        pr_rel = timeline.record_ui(
                            "FreshTerminalPromptReached",
                            f"reached prompt [{username}@penguin]$",
                        )
                        log(f"  [Terminal-App-Fresh] Reached prompt at t+{pr_rel:.1f}s.")
                    elif f_outcome == "error":
                        raise RuntimeError(
                            "Fresh Terminal tab failed even after ContainerStarted:\n" + last_ftxt
                        )
                    else:
                        ctx = fresh_tab.conn._ctx(
                            "Terminal-App-Fresh:wait_for_shell_prompt",
                            time.monotonic() - t_fresh0,
                            fresh_timeout,
                        )
                        raise CDPTimeoutError(
                            f"Timed out waiting for fresh Terminal tab prompt after ContainerStarted "
                            f"({ctx}). Buffer:\n{last_ftxt}"
                        )
                except Exception:
                    fresh_tab.close()
                    raise

            # Run interactive command in the active Terminal app tab
            assert active_tab is not None
            self.set_step("step3:verify_terminal_interactive_shell")
            marker = f"TERM_USER_{int(time.monotonic() * 1000)}="
            active_tab.send_line(f'echo "{marker}$(id -nu)"')
            active_tab.wait_for(
                lambda txt: f"\n{marker}{username}" in txt and txt.rstrip().endswith("$"),
                timeout=45.0,
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
        self.set_step("step4:verify_crosh_guest_shell")
        marker = f"USER_CHECK_{int(time.monotonic() * 1000)}="
        prev_crosh_prompts = tab.get_text().count("crosh>")
        tab.send_line(f'echo "{marker}$(id -nu)"')
        tab.wait_for(
            lambda txt: f"\n{marker}{expected_username}" in txt
            and txt.rstrip().endswith("$"),
            timeout=45.0,
            desc=f"`id -nu` == {expected_username} in {tab.label}",
        )
        log(f"  [{tab.label}] Confirmed guest shell user via crosh UI: `{expected_username}`")
        tab.send_line("exit")
        tab.wait_for(
            lambda txt: txt.count("crosh>") > prev_crosh_prompts
            and txt.rstrip().endswith("crosh>"),
            timeout=45.0,
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
            on_vm_starting_up=throttler.start if self.throttle_from_vm_start else None,
            on_vm_started=None if self.throttle_from_vm_start else throttler.start,
        )
        crosh = self.open_crosh_tab("Termina-Crosh")
        failed = False
        report_logged = False
        try:
            self.set_step("step1:vmc_create")
            log("Step 1: Running `vmc create` command from README.md in crosh...")
            crosh.run_crosh_cmd(readme_cmds.termina_create, timeout=180)

            self.set_step("step2:start_timeline_monitor")
            log("Step 2: Starting passive D-Bus init timeline monitor & driving ChromeOS Settings UI...")
            timeline.start()
            initial_vmshell_tgt = self.run_settings_crostini_installer_ui(
                username=username, timeline=timeline
            )

            log("Step 3: Verifying ChromeOS Terminal app (`chrome-untrusted://terminal`) gated on `ContainerStarted`...")
            self.verify_terminal_app_with_readiness_gate(
                initial_vmshell_tgt=initial_vmshell_tgt,
                username=username,
                timeline=timeline,
                throttler=throttler,
            )

            self.set_step("step4:crosh_vsh_reentry")
            log(f"Step 4: Verifying README crosh shell entry (`{readme_cmds.termina_reentry_vsh}`, single attempt)...")
            prev_guest_prompts = crosh.get_text().count(f"[{username}@")
            log(f"  [{crosh.label}] crosh> {readme_cmds.termina_reentry_vsh}")
            crosh.send_line(readme_cmds.termina_reentry_vsh)
            self._wait_for_new_guest_prompt(
                crosh,
                prev_guest_prompts,
                username,
                timeout=45.0,
                desc=f"`{readme_cmds.termina_reentry_vsh}` shell prompt for `{username}`",
            )
            self._assert_guest_shell_in_crosh(crosh, expected_username=username)
            timeline.record_ui(
                "CroshVshVerified",
                f"`{readme_cmds.termina_reentry_vsh}` -> `id -nu` == {username!r}",
            )

            self.set_step("step5:verify_guest_and_collect")
            log("Step 5: Verifying in-guest systemd/user state & collecting read-only D-Bus/UMA timeline...")
            self.verify_guest_user_session("termina", expected_username=username)
            timeline.stop_and_collect(strict_dbus=True)
            log("\n" + timeline.format_report(include_raw_logs=False))
            report_logged = True
        except Exception:
            failed = True
            throttler.stop()
            if not report_logged:
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
                self.set_step("cleanup:vmc_stop_destroy")
                self.vmc("stop", "termina")
                self.vmc("destroy", "termina")
        log("=== Flow (`termina`) PASSED ===")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
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
        help="Optional host-side CPU duty-cycle quota (5..99%%) applied 3s after VmStartedSignal (or immediately at VmStartingUpSignal with --qemu-throttle-from-vm-start) to simulate slow CI runners",
    )
    parser.add_argument(
        "--qemu-throttle-from-vm-start",
        action="store_true",
        help="Start --qemu-cpu-quota-pct throttling immediately at VmStartingUpSignal (0s delay) so inner crosvm boot and SetUpVmUser #1 are also throttled",
    )
    args = parser.parse_args()

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
