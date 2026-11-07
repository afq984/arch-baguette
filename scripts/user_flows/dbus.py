"""Vendored ChromiumOS `.proto` verification, strict D-Bus parsers, and `ContainerStarted` monitor."""

from __future__ import annotations

import dataclasses
import hashlib
import importlib
import json
import re
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path
from typing import Any, Callable, TypeVar

import google.protobuf
from google.protobuf.message import DecodeError, Message
from grpc_tools import protoc

from . import (
    DEFAULT_PROTO_DIR,
    GCS_ARCHIVE_ROOT,
    FlowDiagnosticsObserver,
    fmt_rel_t,
    log,
    terminate_proc,
)

TMessage = TypeVar("TMessage", bound=Message)

CROS_RELEASE_RE = re.compile(r"^R(\d+)-(\d+\.\d+\.\d+)$")
_HEX_BYTE_RE = re.compile(r"^[0-9a-fA-F]{2}$")
_DBUS_METHOD_RETURN_RE = re.compile(
    r"^method return time=\d+\.\d+ sender=\S+ -> destination=\S+ serial=\d+ reply_serial=\d+$"
)
_DBUS_SIGNAL_HEADER_RE = re.compile(
    r"^signal time=\d+\.\d+ sender=\S+ -> destination=(?:\(null destination\)|\S+) "
    r"serial=\d+ path=(\S+); interface=([A-Za-z0-9_.]+); member=([A-Za-z0-9_]+)$"
)

# Single source of truth for monitored D-Bus signals:
# (interface, member) -> (proto_module_attr, message_class_name, vm_name_field, has_owner_id)
DBUS_SIGNAL_SPECS: dict[tuple[str, str], tuple[str, str, str, bool]] = {
    ("org.chromium.VmConcierge", "VmStartingUpSignal"): ("concierge_pb2", "VmStartingUpSignal", "name", True),
    ("org.chromium.VmConcierge", "VmStartedSignal"): ("concierge_pb2", "VmStartedSignal", "name", True),
    ("org.chromium.VmConcierge", "VmGuestUserlandReadySignal"): ("concierge_pb2", "VmGuestUserlandReadySignal", "name", True),
    ("org.chromium.VmConcierge", "VmStoppingSignal"): ("concierge_pb2", "VmStoppingSignal", "name", True),
    ("org.chromium.VmConcierge", "VmStoppedSignal"): ("concierge_pb2", "VmStoppedSignal", "name", True),
    ("org.chromium.VmCicerone", "ContainerStarted"): ("cicerone_pb2", "ContainerStartedSignal", "vm_name", True),
    ("org.chromium.VmCicerone", "ContainerShutdown"): ("cicerone_pb2", "ContainerShutdownSignal", "vm_name", True),
    ("org.chromium.VmCicerone", "PendingAppListUpdates"): ("cicerone_pb2", "PendingAppListUpdatesSignal", "vm_name", False),
    ("org.chromium.VmCicerone", "TremplinStarted"): ("cicerone_pb2", "TremplinStartedSignal", "vm_name", True),
}
MONITORED_DBUS_SIGNALS: frozenset[tuple[str, str]] = frozenset(DBUS_SIGNAL_SPECS)


@dataclasses.dataclass(frozen=True)
class CrosProtoModules:
    metadata: dict[str, Any]
    concierge_pb2: Any
    cicerone_pb2: Any


_CROS_PROTOS: CrosProtoModules | None = None
_CROS_PROTOS_LOCK = threading.Lock()


def parse_cros_release_str(cros_release: str) -> tuple[str, str]:
    """Parses `R<milestone>-<version>` into `(milestone, version)` or raises `RuntimeError`."""
    m = CROS_RELEASE_RE.match(cros_release.strip())
    if not m:
        raise RuntimeError(
            f"Invalid ChromiumOS release string {cros_release!r}; expected 'R<milestone>-<x>.<y>.<z>'"
        )
    return m.group(1), m.group(2)


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
            f"Mismatched manifest_url in {meta_path}: expected {expected_manifest_url!r}, got {meta['manifest_url']!r}"
        )

    files_map = meta.get("files")
    if not isinstance(files_map, dict) or not files_map:
        raise RuntimeError(f"Invalid or empty 'files' map in {meta_path}")

    for rel_path, expected_sha in files_map.items():
        if not isinstance(rel_path, str) or not isinstance(expected_sha, str):
            raise RuntimeError(f"Invalid file entry in {meta_path}: {rel_path!r}: {expected_sha!r}")
        full_path = proto_dir / rel_path
        if not full_path.is_file():
            raise RuntimeError(f"Vendored file {rel_path!r} listed in {meta_path} does not exist at {full_path}")
        actual_sha = hashlib.sha256(full_path.read_bytes()).hexdigest()
        if actual_sha != expected_sha:
            raise RuntimeError(
                f"SHA-256 mismatch for vendored file {full_path}: expected {expected_sha}, got {actual_sha} "
                f"(run `uv run scripts/protos/update.py --release <RELEASE>`)"
            )

    actual_protos = {str(p.relative_to(proto_dir).as_posix()) for p in proto_dir.rglob("*.proto")}
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

    expected_release = meta["cros_release"]
    expected_builder = f"{meta['board']}/{expected_release}"
    actual_builder = kv.get("CHROMEOS_RELEASE_BUILDER_PATH", "")
    if actual_builder != expected_builder:
        raise RuntimeError(
            f"Booted ChromeOS image CHROMEOS_RELEASE_BUILDER_PATH={actual_builder!r} "
            f"does not match vendored proto metadata {expected_builder!r}"
        )

    milestone = kv.get("CHROMEOS_RELEASE_CHROME_MILESTONE", "")
    version = kv.get("CHROMEOS_RELEASE_VERSION", "")
    reconstructed = f"R{milestone}-{version}"
    if reconstructed != expected_release:
        raise RuntimeError(
            f"Booted ChromeOS image release {reconstructed!r} "
            f"(CHROMEOS_RELEASE_CHROME_MILESTONE={milestone!r}, CHROMEOS_RELEASE_VERSION={version!r}) "
            f"does not match vendored proto metadata {expected_release!r}"
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
            raise RuntimeError(f"Expected google.protobuf major version 7.x matching uv.lock, got {pb_ver!r}")

        proto_files = [
            str(proto_dir / rel)
            for rel in (
                "arc/arc.proto",
                "vm_applications/apps.proto",
                "vm_concierge/concierge_service.proto",
                "vm_cicerone/cicerone_service.proto",
            )
        ]
        with tempfile.TemporaryDirectory(prefix="cros-protos-") as tmp_dir:
            rc = protoc.main(["grpc_tools.protoc", f"-I{proto_dir}", f"--python_out={tmp_dir}", *proto_files])
            if rc != 0:
                raise RuntimeError(f"grpc_tools.protoc failed with exit code {rc}")
            sys.path.insert(0, tmp_dir)
            try:
                importlib.invalidate_caches()
                conc_pb2 = importlib.import_module("vm_concierge.concierge_service_pb2")
                cic_pb2 = importlib.import_module("vm_cicerone.cicerone_service_pb2")
            finally:
                sys.path.remove(tmp_dir)

        loaded = CrosProtoModules(metadata=meta, concierge_pb2=conc_pb2, cicerone_pb2=cic_pb2)
        if proto_dir == DEFAULT_PROTO_DIR:
            _CROS_PROTOS = loaded
        return loaded


def parse_and_validate_proto(raw: bytes, msg_cls: type[TMessage], context: str) -> TMessage:
    """Strictly parses `raw` into `msg_cls` and rejects corrupt wire bytes or unknown fields."""
    msg = msg_cls()
    full_name = msg_cls.DESCRIPTOR.full_name
    try:
        parsed_len = msg.ParseFromString(raw)
    except DecodeError as exc:
        raise ValueError(f"{context}: failed to decode {full_name} (len={len(raw)}, hex={raw.hex()}): {exc}") from exc
    if parsed_len != len(raw):
        raise ValueError(
            f"{context}: incomplete parse of {full_name}: consumed {parsed_len} of {len(raw)} bytes (hex={raw.hex()})"
        )
    size_with_unknown = msg.ByteSize()
    msg.DiscardUnknownFields()
    size_without_unknown = msg.ByteSize()
    if size_with_unknown != size_without_unknown:
        raise ValueError(
            f"{context}: {full_name} contained unknown protobuf fields "
            f"(byte_size {size_with_unknown} -> {size_without_unknown}, hex={raw.hex()})"
        )
    return msg


def require_non_empty_str(val: str, field_name: str, context: str, raw: bytes) -> str:
    if not isinstance(val, str) or not val.strip():
        raise ValueError(f"{context}: required string field {field_name!r} is empty (hex={raw.hex()})")
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
        raise ValueError(f"{context}: unknown enum value {val} for field {field_name!r} (hex={raw.hex()})") from exc
    if disallow_zero_unknown and val == 0 and "UNKNOWN" in name:
        raise ValueError(f"{context}: enum field {field_name!r} has unset/UNKNOWN value 0 ({name}, hex={raw.hex()})")
    return name


def to_dbus_byte_arg(payload: bytes) -> str:
    return "array:byte:" + ",".join(f"0x{b:02x}" for b in payload)


class _DbusByteArrayParser:
    """Shared state machine for `dbus-print-message.c` byte-array bodies (`array of bytes [...]` or empty `array [\\n]`)."""

    def __init__(self, context: str) -> None:
        self.context = context
        self.state = "WAIT_OPEN"
        self._hex_tokens: list[str] = []

    def _add_tokens(self, tokens: list[str], raw_line: str) -> None:
        for tok in tokens:
            if not _HEX_BYTE_RE.match(tok):
                raise ValueError(f"{self.context}: invalid hex byte token {tok!r} in line {raw_line!r}")
        self._hex_tokens.extend(tokens)

    def _finish_bracket(self, body: str, raw_line: str) -> bytes:
        before_close, after_close = body.split("]", 1)
        if after_close.strip():
            raise ValueError(f"{self.context}: unexpected trailing text after ']': {raw_line!r}")
        self._add_tokens(before_close.split(), raw_line)
        self.state = "DONE"
        return bytes.fromhex("".join(self._hex_tokens))

    def feed_line(self, line: str) -> bytes | None:
        if self.state == "DONE":
            raise ValueError(f"{self.context}: unexpected extra line after closing ']': {line!r}")
        if self.state == "WAIT_OPEN":
            # In dbus-print-message.c, a 0-length `ay` prints `   array [\n   ]`.
            if line == "   array [":
                self.state = "WAIT_EMPTY_CLOSE"
                return None
            if not line.startswith("   array of bytes ["):
                raise ValueError(
                    f"{self.context}: expected '   array of bytes [' (or empty '   array ['), got {line!r}"
                )
            after_open = line.split("[", 1)[1]
            if "]" in after_open:
                return self._finish_bracket(after_open, line)
            self._add_tokens(after_open.split(), line)
            self.state = "IN_ARRAY"
            return None
        if self.state == "WAIT_EMPTY_CLOSE":
            if line != "   ]":
                raise ValueError(f"{self.context}: expected exact '   ]' closing empty '   array [', got {line!r}")
            self.state = "DONE"
            return b""
        if not line.startswith("   "):
            raise ValueError(f"{self.context}: expected indented array line, got {line!r}")
        if "]" in line:
            return self._finish_bracket(line, line)
        toks = line.split()
        if not toks:
            raise ValueError(f"{self.context}: empty line inside array of bytes")
        self._add_tokens(toks, line)
        return None

    def ensure_done(self) -> None:
        if self.state != "DONE":
            raise ValueError(f"{self.context}: unclosed byte array body (state={self.state})")


def parse_dbus_send_byte_array(output: str, context: str = "dbus-send") -> bytes:
    """Strictly parses `dbus-send --print-reply` output containing a single byte array."""
    non_empty = [ln.rstrip("\r\n") for ln in output.splitlines() if ln.strip()]
    if len(non_empty) < 2:
        raise ValueError(f"{context}: truncated or empty dbus-send output:\n{output}")
    if not _DBUS_METHOD_RETURN_RE.match(non_empty[0].strip()):
        raise ValueError(f"{context}: expected 'method return ...' header on line 1, got {non_empty[0]!r}")
    parser = _DbusByteArrayParser(context)
    result: bytes | None = None
    for ln in non_empty[1:]:
        if (out := parser.feed_line(ln)) is not None:
            result = out
    parser.ensure_done()
    assert result is not None
    return result


class DbusMonitorSignalParser:
    """Strict line-by-line parser for `dbus-monitor --system` signal blocks."""

    def __init__(self) -> None:
        self._state = "IDLE"
        self._cur_iface = ""
        self._cur_member = ""
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
            _, iface, member = m.groups()
            self._cur_iface, self._cur_member = iface, member
            if iface == "org.freedesktop.DBus" and member in ("NameAcquired", "NameLost"):
                self._state, self._body_parser = "WAIT_DBUS_NAME_STRING", None
                return None
            if (iface, member) not in MONITORED_DBUS_SIGNALS:
                raise ValueError(f"Unexpected D-Bus signal {iface}.{member} on dbus-monitor stream: {line!r}")
            self._state = "IN_BODY"
            self._body_parser = _DbusByteArrayParser(f"dbus-monitor({iface}.{member})")
            return None

        ctx = f"dbus-monitor({self._cur_iface}.{self._cur_member})"
        if self._state == "IDLE":
            raise ValueError(f"Indented dbus-monitor line before any signal header: {line!r}")
        if self._state == "AFTER_BODY":
            raise ValueError(f"{ctx}: unexpected extra body line after signal body completed: {line!r}")
        if self._state == "WAIT_DBUS_NAME_STRING":
            m_name = re.match(r'^   string "(:[^"]+)"$', line)
            if not m_name:
                raise ValueError(f"{ctx}: expected '   string \":1.xxx\"' body line, got {line!r}")
            self._state = "AFTER_BODY"
            return (self._cur_iface, self._cur_member, m_name.group(1).encode("utf-8"))

        assert self._state == "IN_BODY" and self._body_parser is not None
        if (parsed_bytes := self._body_parser.feed_line(line)) is not None:
            self._state = "AFTER_BODY"
            return (self._cur_iface, self._cur_member, parsed_bytes)
        return None

    def finish(self) -> None:
        self._ensure_not_mid_signal("EOF")


def decode_dbus_signal(
    protos: CrosProtoModules, iface: str, member: str, raw: bytes
) -> tuple[str, str, str, Any]:
    """Validates and decodes a monitored D-Bus signal into `(vm_name, owner_id, detail, msg)`."""
    ctx = f"{iface}.{member}"
    spec = DBUS_SIGNAL_SPECS.get((iface, member))
    if spec is None:
        raise ValueError(f"Unhandled D-Bus signal {ctx}")

    pkg_attr, cls_name, vm_field, has_owner_id = spec
    msg_cls = getattr(getattr(protos, pkg_attr), cls_name)
    conc = protos.concierge_pb2

    sig: Any = parse_and_validate_proto(raw, msg_cls, ctx)
    vm_name = require_non_empty_str(getattr(sig, vm_field), vm_field, ctx, raw)
    owner_id = require_non_empty_str(sig.owner_id, "owner_id", ctx, raw) if has_owner_id else ""

    if member == "VmStartingUpSignal":
        vm_type = require_enum_name(conc.VmInfo.VmType, sig.vm_type, "vm_type", ctx, raw)
        if sig.cid <= 0:
            raise ValueError(f"{ctx}: invalid cid={sig.cid} (hex={raw.hex()})")
        detail = f"vm={vm_name!r} vm_type={vm_type}({sig.vm_type}) cid={sig.cid}"
    elif member == "VmStartedSignal":
        status_name = require_enum_name(conc.VmStatus, sig.status, "status", ctx, raw)
        vm_type = require_enum_name(conc.VmInfo.VmType, sig.vm_info.vm_type, "vm_info.vm_type", ctx, raw)
        if sig.vm_info.pid <= 0 or sig.vm_info.cid <= 0:
            raise ValueError(f"{ctx}: invalid vm_info pid={sig.vm_info.pid} cid={sig.vm_info.cid} (hex={raw.hex()})")
        detail = (
            f"vm={vm_name!r} status={status_name}({sig.status}) "
            f"vm_type={vm_type}({sig.vm_info.vm_type}) pid={sig.vm_info.pid} cid={sig.vm_info.cid}"
        )
    elif member == "VmGuestUserlandReadySignal":
        detail = f"vm={vm_name!r} ready={sig.ready}"
    elif member == "VmStoppingSignal":
        if sig.cid <= 0:
            raise ValueError(f"{ctx}: invalid cid={sig.cid} (hex={raw.hex()})")
        detail = f"vm={vm_name!r} cid={sig.cid}"
    elif member == "VmStoppedSignal":
        reason = require_enum_name(conc.VmStopReason, sig.reason, "reason", ctx, raw, disallow_zero_unknown=False)
        detail = f"vm={vm_name!r} cid={sig.cid} reason={reason}({sig.reason})"
    elif member == "ContainerStarted":
        cname = require_non_empty_str(sig.container_name, "container_name", ctx, raw)
        user = require_non_empty_str(sig.container_username, "container_username", ctx, raw)
        homedir = require_non_empty_str(sig.container_homedir, "container_homedir", ctx, raw)
        if not homedir.startswith("/"):
            raise ValueError(f"{ctx}: expected absolute container_homedir, got {homedir!r} (hex={raw.hex()})")
        detail = f"vm={vm_name!r} container={cname!r} user={user!r} homedir={homedir!r}"
    elif member in ("ContainerShutdown", "PendingAppListUpdates"):
        cname = require_non_empty_str(sig.container_name, "container_name", ctx, raw)
        suffix = f" count={sig.count}" if member == "PendingAppListUpdates" else ""
        detail = f"vm={vm_name!r} container={cname!r}{suffix}"
    else:  # TremplinStarted
        detail = f"vm={vm_name!r} owner_id={owner_id!r}"

    return vm_name, owner_id, detail, sig


class BackgroundSshStream:
    """Manages a long-running SSH subprocess with background stdout/stderr readers and EOF checks."""

    def __init__(
        self,
        name: str,
        cmd: list[str],
        *,
        on_line: Callable[[str], None],
        on_eof: Callable[[], None] | None = None,
        on_fatal: Callable[[Exception], None] | None = None,
        stdin_pipe: bool = False,
    ) -> None:
        self.name = name
        self.cmd = cmd
        self._on_line = on_line
        self._on_eof = on_eof
        self._on_fatal = on_fatal
        self._stdin_pipe = stdin_pipe
        self._lock = threading.Lock()
        self._stderr_lines: list[str] = []
        self._stop_requested = False
        self._eof_expected = False
        self.fatal_error: Exception | None = None
        self.proc: subprocess.Popen[str] | None = None
        self._stderr_thread: threading.Thread | None = None
        self._reader_thread: threading.Thread | None = None

    def start(self) -> None:
        self.proc = subprocess.Popen(
            self.cmd,
            stdin=subprocess.PIPE if self._stdin_pipe else None,
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
            if stripped := line.rstrip("\r\n"):
                with self._lock:
                    self._stderr_lines.append(stripped)

    def _read_stdout(self) -> None:
        assert self.proc is not None and self.proc.stdout is not None
        try:
            for line in self.proc.stdout:
                if self._stop_requested:
                    return
                self._on_line(line)
            if not self._stop_requested and not self._eof_expected:
                if self._on_eof is not None:
                    self._on_eof()
                try:
                    rc = self.proc.wait(timeout=1.0)
                except subprocess.TimeoutExpired:
                    rc = self.proc.poll()
                if self._stderr_thread is not None:
                    self._stderr_thread.join(timeout=1.0)
                raise RuntimeError(
                    f"{self.name} stdout reached EOF prematurely before stop "
                    f"(returncode={rc}, stderr={self.stderr_text()!r})"
                )
        except Exception as exc:
            with self._lock:
                if self.fatal_error is None:
                    self.fatal_error = exc
            log(f"  [stream] FATAL error in {self.name}: {exc}")
            if self._on_fatal is not None:
                self._on_fatal(exc)

    def check_healthy(self) -> None:
        with self._lock:
            err = self.fatal_error
        if err is not None:
            raise RuntimeError(f"Fatal error in background {self.name}: {err}") from err
        if self.proc is not None and not self._stop_requested and (rc := self.proc.poll()) is not None:
            raise RuntimeError(
                f"{self.name} process exited prematurely before stop (returncode={rc}, stderr={self.stderr_text()!r})"
            )

    def stop_with_stdin_eof(self, timeout: float = 10.0) -> bool:
        """Signals EOF on stdin so `--loop` processes emit a final sample and exit cleanly."""
        if self.proc is None or self.proc.stdin is None or self._reader_thread is None:
            self.stop()
            return False
        self._eof_expected = True
        try:
            self.proc.stdin.close()
        except OSError:
            pass
        self._reader_thread.join(timeout=timeout)
        with self._lock:
            err = self.fatal_error
        clean = (not self._reader_thread.is_alive()) and (err is None)
        self.stop()
        return clean

    def stop(self) -> None:
        self._stop_requested = True
        terminate_proc(self.proc)
        self.proc = None
        for th in (self._reader_thread, self._stderr_thread):
            if th is not None:
                th.join(timeout=2.0)
        self._reader_thread = self._stderr_thread = None


BALLOON_STOP_RPC_TIMEOUT_SEC = 60


class DbusSignalMonitor:
    """Monitors `VmConcierge`/`VmCicerone` D-Bus signals and gates on `ContainerStarted`."""

    def __init__(
        self,
        vm: Any,
        *,
        owner_hash: str,
        expected_username: str = "terminauser",
        observer: FlowDiagnosticsObserver | None = None,
        stop_balloon_timer_on_vm_started: bool = False,
    ) -> None:
        self.vm = vm
        self.owner_hash = owner_hash
        self.expected_username = expected_username
        self.observer = observer or FlowDiagnosticsObserver()
        self.stop_balloon_timer_on_vm_started = stop_balloon_timer_on_vm_started
        self.balloon_timer_stopped = False
        self._balloon_dispatched = False
        self._balloon_thread: threading.Thread | None = None
        self._balloon_error: BaseException | None = None
        self.protos = load_cros_protos()
        self._lock = threading.Lock()
        self.t_install_mono: float | None = None
        self.monitor_unique_name = ""
        self._subscribed_event = threading.Event()
        self._container_started_event = threading.Event()
        self.container_started_rel_sec: float | None = None
        self._signals: list[tuple[str, str]] = []  # (member, vm_name)
        self._stream: BackgroundSshStream | None = None

    def rel_mono(self, mono_ts: float | None = None) -> float:
        now = mono_ts if mono_ts is not None else time.monotonic()
        with self._lock:
            t_inst = self.t_install_mono
        return 0.0 if t_inst is None else (now - t_inst)

    def mark_install_clicked(self, mono_ts: float) -> None:
        with self._lock:
            self.t_install_mono = mono_ts

    def _raise_if_balloon_error(self) -> None:
        with self._lock:
            err = self._balloon_error
        if err is not None:
            raise err

    def _join_balloon_thread(self, *, timeout: float) -> threading.Thread | None:
        with self._lock:
            th = self._balloon_thread
        if th is not None and th is not threading.current_thread():
            th.join(timeout=timeout)
        return th

    def check_healthy(self) -> None:
        if self._stream is not None:
            self._stream.check_healthy()
        self._raise_if_balloon_error()
        self.observer.check_healthy()

    def start(self) -> None:
        match_rules = " ".join(
            f'"type=\'signal\',interface=\'{iface}\',member=\'{member}\'"'
            for iface, member in sorted(MONITORED_DBUS_SIGNALS)
        )
        parser = DbusMonitorSignalParser()
        self._stream = BackgroundSshStream(
            "dbus-monitor",
            [*self.vm.ssh_base_cmd(), f"exec dbus-monitor --system {match_rules}"],
            on_line=lambda ln: self._handle_signal(*ev) if (ev := parser.feed_line(ln)) is not None else None,
            on_eof=parser.finish,
            on_fatal=lambda _exc: (self._subscribed_event.set(), self._container_started_event.set()),
        )
        self._stream.start()
        if not self._subscribed_event.wait(timeout=15.0):
            self.check_healthy()
            raise RuntimeError(
                "Timed out waiting for dbus-monitor org.freedesktop.DBus.NameAcquired/NameLost "
                f"subscription handshake (returncode={self._stream.poll_rc()}, stderr={self._stream.stderr_text()!r})"
            )
        self.check_healthy()
        log(f"  [dbus] Subscribed system dbus-monitor (NameAcquired={self.monitor_unique_name}).")

    def _handle_signal(self, iface: str, member: str, raw: bytes) -> None:
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
                    f"{ctx}: NameLost unique bus name {unique_name!r} does not match NameAcquired {expected_name!r}"
                )
            self._subscribed_event.set()
            return

        vm_name, owner_id, detail, sig = decode_dbus_signal(self.protos, iface, member, raw)
        rel = self.rel_mono()

        if member == "ContainerStarted" and vm_name == "termina" and sig.container_name == "penguin":
            if owner_id != self.owner_hash:
                raise ValueError(f"{ctx}: owner_id mismatch: expected {self.owner_hash!r}, got {owner_id!r} (hex={raw.hex()})")
            if sig.container_username != self.expected_username:
                raise ValueError(
                    f"{ctx}: container_username mismatch: expected {self.expected_username!r}, "
                    f"got {sig.container_username!r} (hex={raw.hex()})"
                )
            with self._lock:
                self._signals.append((member, vm_name))
                self.container_started_rel_sec = rel
                self._container_started_event.set()
        else:
            with self._lock:
                self._signals.append((member, vm_name))

        self.observer.on_dbus_signal(iface=iface, member=member, vm_name=vm_name, detail=detail, rel_sec=rel, msg=sig)
        if self.stop_balloon_timer_on_vm_started and member == "VmStartedSignal" and vm_name == "termina":
            if owner_id != self.owner_hash:
                raise ValueError(f"{ctx}: owner_id mismatch: expected {self.owner_hash!r}, got {owner_id!r} (hex={raw.hex()})")
            should_dispatch = False
            with self._lock:
                if not self._balloon_dispatched:
                    self._balloon_dispatched = True
                    should_dispatch = True
            if should_dispatch:
                th = threading.Thread(
                    target=self._run_stop_balloon_timer,
                    args=(rel,),
                    name="dbus-stop-balloon-timer",
                    daemon=True,
                )
                with self._lock:
                    self._balloon_thread = th
                th.start()

    def _run_stop_balloon_timer(self, signal_rel_sec: float) -> None:
        try:
            self.stop_concierge_balloon_timer(rel_sec=signal_rel_sec)
        except BaseException as exc:
            with self._lock:
                if self._balloon_error is None:
                    self._balloon_error = exc
            self._subscribed_event.set()
            self._container_started_event.set()

    def stop_concierge_balloon_timer(self, *, rel_sec: float | None = None) -> None:
        """Stops concierge's 1 Hz balloon resize timer via `VmConcierge.SetBalloonTimer(0)`.

        Balloon resizing is orthogonal to what this user-flow test covers and adds 1 Hz guest
        virtio-balloon stats/inflate churn under nested virtualization. Concierge starts
        `balloon_resizing_timer_` right before emitting `VmStartedSignal` (`OnControlSocketReady`),
        so dispatching `SetBalloonTimer(timer_interval_millis=0)` on a dedicated worker thread when
        `VmStartedSignal` arrives stops it without blocking `dbus-monitor` signal consumption.
        """
        conc = self.protos.concierge_pb2
        ctx = "VmConcierge.SetBalloonTimer"
        resp, raw_resp = self.vm.dbus_call_proto(
            "org.chromium.VmConcierge",
            "SetBalloonTimer",
            conc.SetBalloonTimerRequest(timer_interval_millis=0),
            conc.SuccessFailureResponse,
            timeout=BALLOON_STOP_RPC_TIMEOUT_SEC,
        )
        if not resp.success:
            raise RuntimeError(
                f"{ctx}(timer_interval_millis=0) failed: failure_reason={resp.failure_reason!r} (hex={raw_resp.hex()})"
            )
        with self._lock:
            self.balloon_timer_stopped = True
        done_rel = self.rel_mono()
        trig = f" (triggered at {fmt_rel_t(rel_sec).strip()})" if rel_sec is not None else ""
        log(f"  [dbus] Stopped concierge 1 Hz balloon resize timer via {ctx}(0) at {fmt_rel_t(done_rel).strip()}{trig}.")

    def is_container_started(self) -> bool:
        self.check_healthy()
        return self._container_started_event.is_set()

    def query_garcon_session_info(self) -> Any:
        """Read-only D-Bus call to `VmCicerone.GetGarconSessionInfo`."""
        cic = self.protos.cicerone_pb2
        ctx = "VmCicerone.GetGarconSessionInfo"
        resp, raw_resp = self.vm.dbus_call_proto(
            "org.chromium.VmCicerone",
            "GetGarconSessionInfo",
            cic.GetGarconSessionInfoRequest(vm_name="termina", container_name="penguin", owner_id=self.owner_hash),
            cic.GetGarconSessionInfoResponse,
        )
        require_enum_name(cic.GetGarconSessionInfoResponse.Status, resp.status, "status", ctx, raw_resp)
        if resp.status == cic.GetGarconSessionInfoResponse.Status.SUCCEEDED:
            user = require_non_empty_str(resp.container_username, "container_username", ctx, raw_resp)
            homedir = require_non_empty_str(resp.container_homedir, "container_homedir", ctx, raw_resp)
            if user != self.expected_username:
                raise ValueError(
                    f"{ctx}: expected container_username={self.expected_username!r}, got {user!r} (hex={raw_resp.hex()})"
                )
            if not homedir.startswith("/"):
                raise ValueError(f"{ctx}: expected absolute container_homedir, got {homedir!r} (hex={raw_resp.hex()})")
        return resp

    def wait_for_container_started(self, timeout: float = 300.0) -> float:
        """Waits on `VmCicerone.ContainerStarted` and cross-checks `GetGarconSessionInfo`."""
        cic = self.protos.cicerone_pb2
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            self.check_healthy()
            if self._container_started_event.wait(timeout=1.0):
                self.check_healthy()
                assert self.container_started_rel_sec is not None
                info = self.query_garcon_session_info()
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
                self.observer.on_readiness_gate_passed(self.container_started_rel_sec)
                return self.container_started_rel_sec
        self.check_healthy()
        raise TimeoutError(
            f"Timed out after {timeout:.0f}s waiting for cicerone ContainerStarted(termina/penguin) signal on dbus-monitor"
        )

    def verify_required_signal_sequence(self) -> None:
        """Asserts `VmStartingUpSignal` -> `VmStartedSignal` -> `ContainerStarted` arrived in order."""
        with self._lock:
            names = [m for m, vm_name in self._signals if vm_name == "termina"]
        required = ("VmStartingUpSignal", "VmStartedSignal", "ContainerStarted")
        for req_name in required:
            if req_name not in names:
                raise RuntimeError(
                    f"Missing required D-Bus signal {req_name!r} for 'termina' on dbus-monitor stream (observed: {names!r})"
                )
        i0, i1, i2 = (names.index(r) for r in required)
        if not (i0 < i1 < i2):
            raise RuntimeError(
                f"Required D-Bus signals for 'termina' arrived out of order: expected {required!r}, observed {names!r}"
            )
        if self.stop_balloon_timer_on_vm_started:
            join_sec = float(BALLOON_STOP_RPC_TIMEOUT_SEC + 15)
            th = self._join_balloon_thread(timeout=join_sec)
            self._raise_if_balloon_error()
            if th is not None and th.is_alive():
                raise RuntimeError(f"VmConcierge.SetBalloonTimer(0) worker thread still running after {join_sec:.0f}s")
            if not self.balloon_timer_stopped:
                raise RuntimeError("VmConcierge.SetBalloonTimer(0) did not complete after VmStartedSignal")

    def stop(self, *, raise_errors: bool = True) -> None:
        if self._stream is not None:
            self._stream.stop()
            self._stream = None
        join_sec = float(BALLOON_STOP_RPC_TIMEOUT_SEC + 15) if raise_errors else 5.0
        self._join_balloon_thread(timeout=join_sec)
        if raise_errors:
            self._raise_if_balloon_error()
