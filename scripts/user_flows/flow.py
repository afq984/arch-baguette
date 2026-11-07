"""End-to-end ChromeOS Settings Linux installer, Terminal readiness gate, and crosh user flow."""

from __future__ import annotations

import calendar
import dataclasses
import json
import os
import re
import shlex
import sys
import time
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import Any, NoReturn

from . import DEFAULT_README_PATH, FlowDiagnosticsObserver, TimelineEntry, fmt_rel_t, log
from .cdp import CDPConnection, CDPError, CDPTimeoutError, CroshTab, sleep_backoff
from .dbus import DbusSignalMonitor
from .vm import ChromeOSVM

# Exact terminal.js output when chrome.terminalPrivate.openVmshellProcess fails with
# CrostiniResult::CONTAINER_SETUP_FAILED (50) after SetUpVmUser hits its 20s gRPC deadline.
KNOWN_INITIAL_TERMINAL_TIMEOUT_ERROR = (
    "Launching vmshell failed: Error starting crostini for terminal: 50 (CONTAINER_SETUP_FAILED)"
)

# Expected guest user identity created by Chrome's Crostini installer -> Concierge SetUpVmUser
# -> maitred SetUpUser against existing groups in /etc/group inside baguette_arch_rootfs.img.zst.
EXPECTED_GUEST_UID = 1000
EXPECTED_GUEST_GID = 1000
EXPECTED_GUEST_SUPPLEMENTARY_GROUPS: frozenset[str] = frozenset(
    {"audio", "cdrom", "dialout", "disk", "floppy", "kvm", "netdev", "sudo", "tss", "video"}
)

# On constrained 4-vCPU nested-KVM CI runners, a minimal `vsh` invocation can take ~22s just to
# open the guest shell; 120s leaves ~4-5x headroom for vsh startup plus user-session checks.
GUEST_VSH_TIMEOUT_SEC = 120
LOG_FLUSH_TIMEOUT_SEC = 10.0
TERMINAL_POLL_FLOOR_SEC = 1.5
SETUP_USER_DEADLINE_MIN_SEC = 15.0
SETUP_USER_DEADLINE_MAX_SEC = 35.0
FINAL_PASS_LINE = "ALL REQUESTED USER FLOWS PASSED END-TO-END!"
_TERMINAL_HOME_URL = "chrome-untrusted://terminal/html/terminal.html#home"
_TERMINAL_VMSHELL_URL = "chrome-untrusted://terminal/html/terminal.html?command=vmshell"
_EVIDENCE_SENTINEL = "Host concierge/cicerone entries since "
_BALLOON_NOISE_TOKENS = ("BalloonTrace", "BalloonInit", "balloon stats")


@dataclasses.dataclass(frozen=True)
class ReadmeCommands:
    termina_create: str
    termina_reentry_vsh: str


@dataclasses.dataclass(frozen=True)
class TerminalRelaunch:
    call_index: int
    req_entry: TimelineEntry
    fail_entry: TimelineEntry
    post_container_started: bool
    reason: str = "Known slow-runner SetUpVmUser 20s gRPC deadline (code 50)"
    daemon_label: str = "Concierge"
    rule_id: str = "S2"
    rule_name: str = "SetUpVmUser 20s deadline"

    @property
    def duration_sec(self) -> float:
        return self.fail_entry.rel_sec - self.req_entry.rel_sec


@dataclasses.dataclass(frozen=True)
class FlowResult:
    terminal_relaunch: TerminalRelaunch | None = None
    terminal_relaunches: tuple[TerminalRelaunch, ...] = ()

    @property
    def all_relaunches(self) -> tuple[TerminalRelaunch, ...]:
        if self.terminal_relaunches:
            return self.terminal_relaunches
        return (self.terminal_relaunch,) if self.terminal_relaunch is not None else ()


def format_final_pass_line(result: FlowResult | None = None) -> str:
    ev = result.terminal_relaunch if result is not None else None
    if ev is None or not ev.post_container_started:
        return FINAL_PASS_LINE
    cause = (
        f"LaunchVshd call #{ev.call_index} vsh 5s poll timeout"
        if "ListenForVshd" in ev.reason
        else f"SetUpVmUser call #{ev.call_index} {ev.duration_sec:.1f}s deadline"
    )
    return f"{FINAL_PASS_LINE} (1 Terminal relaunch used after post-ContainerStarted {cause})"


def _escape_gha_command_value(val: str, *, for_property: bool = False) -> str:
    out = val.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")
    if for_property:
        out = out.replace(":", "%3A").replace(",", "%2C")
    return out


def emit_ci_relaunch_warning(
    result: FlowResult | None,
    *,
    env: Mapping[str, str] | None = None,
    stream: Any = None,
) -> list[str]:
    """Emits GitHub Actions `::warning::` annotations and `$GITHUB_STEP_SUMMARY` lines on relaunch."""
    if result is None or not result.all_relaunches:
        return []
    eff_env = os.environ if env is None else env
    out_stream = sys.stdout if stream is None else stream
    summary_path_raw = eff_env.get("GITHUB_STEP_SUMMARY", "").strip()
    annotations: list[str] = []
    summary_lines: list[str] = []
    for ev in result.all_relaunches:
        scope = "post-ContainerStarted" if ev.post_container_started else "pre-ContainerStarted"
        req_t = fmt_rel_t(ev.req_entry.rel_sec).strip()
        err_t = fmt_rel_t(ev.fail_entry.rel_sec).strip()
        title = _escape_gha_command_value(f"Terminal relaunch ({ev.rule_id} - {ev.rule_name})", for_property=True)
        msg = _escape_gha_command_value(
            f"E2E passed after Terminal relaunch [rule={ev.rule_id} ({ev.rule_name}), scope={scope}, "
            f"call=#{ev.call_index}]: {ev.reason} | evidence ({ev.daemon_label} {req_t} -> {err_t}, "
            f"dur={ev.duration_sec:.1f}s): {ev.fail_entry.detail}"
        )
        ann = f"::warning title={title}::{msg}"
        annotations.append(ann)
        print(ann, file=out_stream, flush=True)
        summary_lines.append(
            f"- **Terminal relaunch (`{ev.rule_id}: {ev.rule_name}`, `{scope}`)**: {ev.reason} — "
            f"evidence (`{ev.daemon_label}`, `req={req_t} -> err={err_t}`, `dur={ev.duration_sec:.1f}s`): "
            f"`{ev.fail_entry.detail}`\n"
        )
    if summary_path_raw:
        with Path(summary_path_raw).open("a", encoding="utf-8") as fh:
            fh.writelines(summary_lines)
    return annotations


def split_shell_commands(block: str) -> list[str]:
    """Joins backslash-continued lines and returns non-empty logical command lines."""
    joined = re.sub(r"\s*\\\s*\n\s*", " ", block.strip())
    cmds: list[str] = []
    for raw_line in joined.splitlines():
        line = raw_line.strip()
        if line and not line.startswith("#"):
            if cleaned := re.sub(r"\s+#.*$", "", line).strip():
                cmds.append(cleaned)
    return cmds


def extract_section_sh_blocks(markdown: str, heading_prefix: str) -> list[list[str]]:
    """Extracts fenced `sh`/`bash` command blocks under a `### <heading_prefix>` section."""
    match = re.search(
        rf"^###\s+{re.escape(heading_prefix)}[^\n]*\n(.*?)(?=^###|^##|\Z)",
        markdown,
        re.MULTILINE | re.DOTALL,
    )
    if not match:
        raise ValueError(f"Could not find section starting with '### {heading_prefix}' in README")
    blocks = [
        split_shell_commands(m.group(1))
        for m in re.finditer(r"```(?:sh|bash)?\n(.*?)```", match.group(1), re.DOTALL)
    ]
    return [b for b in blocks if b]


def extract_readme_commands(readme_path: Path = DEFAULT_README_PATH) -> ReadmeCommands:
    """Parses the exact user-facing crosh commands from README.md."""
    setup_blocks = extract_section_sh_blocks(readme_path.read_text(encoding="utf-8"), "Setup:")
    if len(setup_blocks) < 2:
        raise ValueError(
            f"Expected '### Setup:' in {readme_path} to have at least 2 fenced code blocks "
            f"(`vmc create ... termina` and `vsh termina penguin`), got: {setup_blocks!r}"
        )
    for idx, desc in ((0, "`vmc create`"), (1, "`vsh`")):
        if len(setup_blocks[idx]) != 1:
            raise ValueError(
                f"Expected '### Setup:' block {idx + 1} in {readme_path} to be a single {desc} "
                f"command, got: {setup_blocks[idx]!r}"
            )
    return ReadmeCommands(setup_blocks[0][0], setup_blocks[1][0])


def _parse_expected_int(raw: str, label: str, expected: int) -> None:
    try:
        val = int(raw.strip())
    except ValueError as exc:
        raise RuntimeError(f"Invalid guest {label} output {raw!r}") from exc
    if val != expected:
        raise RuntimeError(f"Expected guest {label} {expected}, got {val}")


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
    _parse_expected_int(uid_str, "UID", EXPECTED_GUEST_UID)
    if user_str.strip() != expected_username:
        raise RuntimeError(f"Expected guest username {expected_username!r}, got {user_str.strip()!r}")
    _parse_expected_int(gid_str, "primary GID", EXPECTED_GUEST_GID)
    if group_str.strip() != expected_username:
        raise RuntimeError(
            f"Expected guest primary group {expected_username!r}, got {group_str.strip()!r}"
        )
    group_tokens = all_groups_str.strip().split()
    if expected_username not in group_tokens:
        raise RuntimeError(
            f"Primary group {expected_username!r} missing from `id -Gn` output: {all_groups_str!r}"
        )
    actual_supp = frozenset(g for g in group_tokens if g != expected_username)
    if actual_supp != expected_supp_groups:
        raise RuntimeError(
            f"Guest supplementary groups mismatch for {expected_username!r}: "
            f"expected={sorted(expected_supp_groups)}, actual={sorted(actual_supp)} "
            f"(missing={sorted(expected_supp_groups - actual_supp)}, "
            f"extra={sorted(actual_supp - expected_supp_groups)})"
        )


def verify_guest_user_session(vm: ChromeOSVM, vm_name: str, expected_username: str) -> None:
    """Verifies in-guest OS, UID/GID 1000, exact supplementary groups, and active `cros-garcon`."""
    vm.set_step("step5:verify_guest_user_session")
    log(
        f"Verifying in-guest OS, UID/GID 1000, primary group '{expected_username}', "
        f"exact supplementary groups {sorted(EXPECTED_GUEST_SUPPLEMENTARY_GROUPS)}, "
        f"and active cros-garcon.service for VM '{vm_name}'..."
    )
    check_script = (
        'set -euo pipefail; grep -q "Arch Linux" /etc/os-release; '
        'echo "OS=$(. /etc/os-release && echo $PRETTY_NAME)"; '
        'echo "ID=$(id)"; echo "UID=$(id -u)"; echo "USER=$(id -nu)"; '
        'echo "GID=$(id -g)"; echo "GROUP=$(id -ng)"; echo "GROUPS=$(id -Gn)"; '
        'GARCON=$(systemctl --user is-active cros-garcon.service); echo "GARCON=$GARCON"; '
        '[ "$GARCON" = "active" ]'
    )
    res = vm.vsh(
        vm_name,
        expected_username,
        check_script,
        timeout=GUEST_VSH_TIMEOUT_SEC,
        op_desc=f"verify_guest_user_session({vm_name})",
    )
    kv: dict[str, str] = {}
    for line in res.stdout.strip().splitlines():
        log(f"  [{vm_name}] {line}")
        if "=" in line:
            k, v = line.split("=", 1)
            kv[k.strip()] = v.strip()
    verify_guest_user_identity(
        kv.get("UID", ""),
        kv.get("USER", ""),
        kv.get("GID", ""),
        kv.get("GROUP", ""),
        kv.get("GROUPS", ""),
        expected_username,
    )


def parse_rfc3339_utc(ts_str: str) -> float:
    """Strictly parses `YYYY-MM-DDTHH:MM:SS.ffffffZ` from `/var/log/messages` into epoch seconds."""
    m = re.match(r"^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})(?:\.(\d+))?Z$", ts_str.strip())
    if not m:
        raise ValueError(f"Invalid RFC3339 UTC timestamp: {ts_str!r}")
    base_sec = calendar.timegm(time.strptime(m.group(1), "%Y-%m-%dT%H:%M:%S"))
    return float(base_sec) + (float(f"0.{m.group(2)}") if m.group(2) else 0.0)


_MSG_SUBSTRING_EVENTS: tuple[tuple[str, str, str, str | None], ...] = (
    ("Received request: CreateDiskImage", "concierge", "CreateDiskImage", None),
    ("Found existing disk at ", "concierge", "FoundExistingDisk", None),
    ("Invoking VM: /usr/bin/crosvm", "concierge", "InvokeCrosvm", "Invoking /usr/bin/crosvm ..."),
    ("Received NotifyVmStarted request", "cicerone", "NotifyVmStarted", None),
    ("Started VM with pid ", "concierge", "StartedVm", None),
    ("Startup of container ", "cicerone", "ContainerReadyLog", None),
    ("VM with requested name is already running", "concierge", "StartVmAlreadyRunning", None),
    ("Garcon channel not connected", "cicerone", "GarconChannelWait", None),
    ("Received RegisterVshSession request", "cicerone", "RegisterVshSession", None),
)
_CHROME_SUBSTRING_EVENTS: tuple[tuple[str, str], ...] = (
    ("Failed to set up baguette user:", "SetUpBaguetteUserFailed"),
    ("Failed to restart Crostini with error code:", "RestartCrostiniFailed"),
    ("Unable to mount files for a container that's not running", "SshfsMountSkipped"),
)


def parse_host_init_logs(
    messages_text: str,
    chrome_text: str,
    t_install_vm_epoch: float | None,
) -> tuple[list[TimelineEntry], float | None]:
    """Parses ChromeOS `/var/log/messages` and `/var/log/chrome/chrome` init milestones.

    Preserves signed relative timestamps (`epoch - t_install_vm_epoch`) without clamping
    pre-Install entries, and records `SetUpVmUserInFlight` if a call has not logged completion yet.
    """
    first_host_setup_user_rel: float | None = None
    entries: list[TimelineEntry] = []
    setup_user_seq = launch_vshd_seq = 0
    pending_setup_user: tuple[int, float] | None = None
    pending_launch_vshd: tuple[int, float] | None = None
    malformed_ts: list[str] = []
    last_rel = 0.0

    def _rel_or_skip(ts_token: str, src_name: str) -> float | None:
        nonlocal last_rel
        try:
            epoch_val = parse_rfc3339_utc(ts_token)
        except ValueError:
            malformed_ts.append(f"{src_name}:{ts_token!r}")
            return None
        if t_install_vm_epoch is None:
            return 0.0
        last_rel = epoch_val - t_install_vm_epoch
        return last_rel

    for line in messages_text.splitlines():
        parts = line.split(None, 3)
        if len(parts) < 4 or not re.match(r"^\d{4}-\d{2}-\d{2}T", parts[0]):
            continue
        if (rel := _rel_or_skip(parts[0], "messages")) is None:
            continue
        proc_tag, msg_body = parts[2], parts[3]

        # Heuristic: vm_concierge processes D-Bus requests on a single service thread,
        # so any subsequent vm_concierge[...] line (or cicerone LaunchVshd) that is not
        # a SetUpUser RPC error indicates the preceding SetUpVmUser RPC has returned.
        if pending_setup_user is not None:
            seq_idx, start_rel = pending_setup_user
            dur = max(0.0, rel - start_rel)
            if proc_tag.startswith("vm_concierge[") and (
                "SetUpUser RPC failed:" in msg_body or "SetUpUser RPC returned an error:" in msg_body
            ):
                entries.append(
                    TimelineEntry(rel, "concierge", "SetUpVmUserFailed", f"call #{seq_idx} failed after {dur:.1f}s: {line.strip()}")
                )
                pending_setup_user = None
                continue
            if proc_tag.startswith("vm_concierge[") or "Received LaunchVshd request" in msg_body:
                entries.append(
                    TimelineEntry(rel, "concierge", "SetUpVmUserDone", f"call #{seq_idx} completed in <={dur:.1f}s (followed by {msg_body[:60]})")
                )
                pending_setup_user = None

        if pending_launch_vshd is not None and proc_tag.startswith("vm_cicerone["):
            lv_idx, lv_start_rel = pending_launch_vshd
            pending_launch_vshd = None
            if parts[1] == "ERR":
                ev_name = (
                    "LaunchVshdNoContainer"
                    if msg_body.strip() == "Requested container does not exist: penguin"
                    else "LaunchVshdFailed"
                )
                entries.append(
                    TimelineEntry(rel, "cicerone", ev_name, f"call #{lv_idx} failed after {max(0.0, rel - lv_start_rel):.3f}s: {line.strip()}")
                )
                continue

        if proc_tag.startswith("vm_concierge[") and msg_body == "Received request: SetUpVmUser":
            setup_user_seq += 1
            if setup_user_seq == 1:
                first_host_setup_user_rel = rel
            pending_setup_user = (setup_user_seq, rel)
            entries.append(TimelineEntry(rel, "concierge", "SetUpVmUser", f"call #{setup_user_seq}: {line.strip()}"))
        elif proc_tag.startswith("vm_cicerone[") and "Received LaunchVshd request" in msg_body:
            launch_vshd_seq += 1
            pending_launch_vshd = (launch_vshd_seq, rel)
            entries.append(TimelineEntry(rel, "cicerone", "LaunchVshd", f"call #{launch_vshd_seq}: {line.strip()}"))
        elif proc_tag.startswith("vm_concierge[") and "timer_interval_millis is 0" in msg_body:
            entries.append(TimelineEntry(rel, "concierge", "BalloonTimerStopped", msg_body))
        else:
            for needle, src, ev_name, fixed_detail in _MSG_SUBSTRING_EVENTS:
                if needle in msg_body:
                    entries.append(TimelineEntry(rel, src, ev_name, fixed_detail or msg_body))
                    break

    if pending_setup_user is not None:
        seq_idx, start_rel = pending_setup_user
        entries.append(
            TimelineEntry(
                start_rel,
                "concierge",
                "SetUpVmUserInFlight",
                f"call #{seq_idx} still in flight at log scrape (no completion or RPC error logged yet)",
            )
        )

    for line in chrome_text.splitlines():
        parts = line.split(None, 3)
        if len(parts) < 4 or not re.match(r"^\d{4}-\d{2}-\d{2}T", parts[0]):
            continue
        if (rel := _rel_or_skip(parts[0], "chrome")) is None:
            continue
        for needle, ev_name in _CHROME_SUBSTRING_EVENTS:
            if needle in parts[3]:
                entries.append(TimelineEntry(rel, "chrome", ev_name, parts[3]))
                break

    if malformed_ts:
        detail = f"skipped {len(malformed_ts)} malformed RFC3339 UTC timestamp line(s) (first={malformed_ts[0]})"
        log(f"  WARNING: parse_host_init_logs {detail}")
        entries.append(TimelineEntry(last_rel, "parser", "MalformedTimestamp", detail))

    return entries, first_host_setup_user_rel


class HostLogScraper:
    """Tracks `/var/log/messages` and `/var/log/chrome/chrome` line cursors for classifier checks."""

    def __init__(self) -> None:
        self.msg_line_cursor = self.chrome_line_cursor = 0
        self.t_install_vm_epoch: float | None = None
        self.last_entries: list[TimelineEntry] = []
        self.first_host_setup_user_rel: float | None = None
        self.messages_excerpt = self.chrome_excerpt = ""

    def capture_cursors(self, vm: ChromeOSVM) -> None:
        self.msg_line_cursor = int(
            vm.ssh("wc -l < /var/log/messages", op_desc="log_cursor:messages").stdout.strip() or "0"
        )
        self.chrome_line_cursor = int(
            vm.ssh("wc -l < /var/log/chrome/chrome", op_desc="log_cursor:chrome").stdout.strip() or "0"
        )

    def mark_install_clicked(self, vm_epoch_sec: float) -> None:
        self.t_install_vm_epoch = vm_epoch_sec

    def scrape(self, vm: ChromeOSVM) -> list[TimelineEntry]:
        self.messages_excerpt = vm.ssh(
            f"set -o pipefail; test -r /var/log/messages; "
            f"tail -n +{self.msg_line_cursor + 1} /var/log/messages | "
            f"{{ grep -E 'vm_concierge|vm_cicerone|seneschal|vmlog_forwarder|crosvm|VM\\([0-9]+\\)|vshd|garcon|maitred' || [ $? -eq 1 ]; }} | "
            f"{{ grep -v 'BalloonTrace:' || [ $? -eq 1 ]; }}",
            check=True,
            timeout=60,
            op_desc="scrape_host_logs(/var/log/messages)",
            cmd_summary="tail /var/log/messages | grep vm_concierge|...",
        ).stdout.strip()
        self.chrome_excerpt = vm.ssh(
            f"set -o pipefail; test -r /var/log/chrome/chrome; "
            f"tail -n +{self.chrome_line_cursor + 1} /var/log/chrome/chrome | "
            f"{{ grep -iE 'crostini|baguette|termina|terminal|cicerone|concierge|vsh' || [ $? -eq 1 ]; }}",
            check=True,
            timeout=60,
            op_desc="scrape_host_logs(/var/log/chrome/chrome)",
            cmd_summary="tail /var/log/chrome/chrome | grep crostini|...",
        ).stdout.strip()
        self.last_entries, self.first_host_setup_user_rel = parse_host_init_logs(
            self.messages_excerpt, self.chrome_excerpt, self.t_install_vm_epoch
        )
        return self.last_entries

    def _filter_excerpt_since(
        self, excerpt: str, since_rel_sec: float, *, max_lines: int, ignore: tuple[str, ...] = ()
    ) -> list[str]:
        out: list[str] = []
        keep = self.t_install_vm_epoch is None
        for line in excerpt.splitlines():
            if any(sub in line for sub in ignore):
                continue
            head = line.split(None, 1)[0] if line.strip() else ""
            if re.match(r"^\d{4}-\d{2}-\d{2}T", head):
                if self.t_install_vm_epoch is None:
                    keep = True
                else:
                    try:
                        keep = (parse_rfc3339_utc(head) - self.t_install_vm_epoch) >= since_rel_sec
                    except ValueError:
                        keep = True
            if keep and line.strip():
                out.append(f"    {line}")
        return out[-max_lines:]

    def format_window_tail(self, since_rel_sec: float, *, max_lines: int = 40) -> str:
        """Formats bounded host concierge/cicerone/seneschal/crosvm and Chrome lines since `since_rel_sec`."""
        host_lines = [
            f"    {fmt_rel_t(e.rel_sec)} [{e.source}] {e.name}: {e.detail}"
            for e in self.last_entries
            if e.source in ("concierge", "cicerone", "parser") and e.rel_sec >= since_rel_sec
        ][-max_lines:]
        raw_msg_lines = self._filter_excerpt_since(self.messages_excerpt, since_rel_sec, max_lines=max_lines)
        chrome_lines = self._filter_excerpt_since(
            self.chrome_excerpt, since_rel_sec, max_lines=max_lines, ignore=("task queue exceeded allotted deadline",)
        )
        lbl = fmt_rel_t(since_rel_sec).strip()
        return "\n".join(
            (
                f"  Host concierge/cicerone entries since {lbl} (last <={max_lines}):",
                *(host_lines or ("    (none)",)),
                f"  Host /var/log/messages (concierge/cicerone/seneschal/crosvm) since {lbl} (last <={max_lines}):",
                *(raw_msg_lines or ("    (none)",)),
                f"  Chrome crostini/terminal/vsh log lines since {lbl} (last <={max_lines}):",
                *(chrome_lines or ("    (none)",)),
            )
        )


def _compact_crosvm_ps_lines(ps_part: str, *, max_lines: int = 65) -> list[str]:
    """Deduplicates repeated `/usr/bin/crosvm ...` command lines across thread rows and caps length."""
    if not (raw_lines := ps_part.splitlines()):
        return ["    (none)"]
    seen: set[str] = set()
    out: list[str] = []
    for ln in raw_lines:
        if (idx := ln.find("/usr/bin/crosvm ")) >= 0:
            tail = ln[idx:]
            if len(tail) > 80 and tail in seen:
                ln = f"{ln[:idx]}/usr/bin/crosvm ... (same cmdline)"
            else:
                seen.add(tail)
        out.append(f"    {ln}")
    if len(out) > max_lines:
        out = [*out[:max_lines], f"    ... ({len(out) - max_lines} more crosvm thread rows omitted)"]
    return out


def collect_baguette_boot_evidence(
    vm: ChromeOSVM,
    owner_hash: str | None,
    *,
    max_console_head_lines: int = 60,
    max_console_lines: int = 80,
) -> str:
    """Reads Baguette's host-persisted console log (head + tail) and `crosvm` thread table.

    On R156 (`platform2@4f4daab2`), `vm_tools/init/vmlog_forwarder.conf.in:26` starts
    `vmlog_forwarder --syslog=false`, so guest console lines are not mirrored to `/var/log/messages`.
    `Service::StartVmInternal` (`vm_tools/concierge/service.cc:544,1536,4387`) and
    `LogPipeManager::OnVmStartingUpSignal` (`vm_tools/syslog/log_pipe.cc:67-74,244-264`) write
    `/run/daemon-store/crosvm/<owner_hash>/log/<base64(vm_name)>.log` (`dGVybWluYQ==.log`, fed via
    `earlycon`/`serial`, `virtio-console`, and `debugcon` in `termina_vm.cc:201-204`), which persists
    on disk after `~TerminaVm()` (`termina_vm.cc:139,320`) stops `crosvm` on `StartVm` timeout.
    """
    if not owner_hash or not hasattr(vm, "ssh"):
        return ""
    log_dir = f"/run/daemon-store/crosvm/{owner_hash}/log"
    head_n, tail_n = int(max_console_head_lines), int(max_console_lines)
    limit_n = head_n + tail_n
    script = (
        f"d={shlex.quote(log_dir)}; echo '===CONSOLE==='; "
        'if [ -d "$d" ]; then ls -la "$d" 2>&1; found=0; '
        'for f in "$d"/*.log; do [ -e "$f" ] || continue; found=1; '
        'sz=$(wc -c < "$f" 2>/dev/null || echo "?"); lc=$(wc -l < "$f" 2>/dev/null || echo 0); '
        f'echo "--- $(basename "$f") (${{sz}} bytes, ${{lc}} lines, first <={head_n} + last <={tail_n}) ---"; '
        f'if [ ! -s "$f" ]; then echo "(empty 0-byte file)"; '
        f'elif [ "$lc" -le {limit_n} ]; then cat "$f" 2>&1; '
        f'else head -n {head_n} "$f" 2>&1; echo "... ($((lc - {limit_n})) lines omitted) ..."; tail -n {tail_n} "$f" 2>&1; fi; done; '
        '[ "$found" -eq 1 ] || echo "(no *.log files present)"; '
        'else echo "(directory not present: $d)"; fi; '
        "echo '===CROSVM_PS==='; "
        "ps_out=$(ps -ww -eL -o pid,lwp,stat,pcpu,pmem,etime,wchan:20,comm,args 2>/dev/null "
        "|| ps -ww -eL -o pid,tid,stat,pcpu,pmem,etime,comm,args 2>/dev/null || ps -ww -ef 2>&1); "
        'hdr=$(printf "%s\\n" "$ps_out" | head -n 1); '
        'body=$(printf "%s\\n" "$ps_out" | awk \'NR>1 && $0 !~ /===CROSVM_PS===/ && ($0 ~ /[c]rosvm|[p]civirtio|VM\\([0-9]+\\)/)\'); '
        'if [ -n "$body" ]; then printf "%s\\n%s\\n" "$hdr" "$body"; '
        'else echo "(no crosvm processes running; concierge ~TerminaVm() stops failed StartVm instances before returning)"; fi'
    )
    try:
        res = vm.ssh(
            script,
            check=False,
            timeout=15,
            op_desc="collect_baguette_boot_evidence(console+crosvm_ps)",
            cmd_summary="head+tail /run/daemon-store/crosvm/.../log/*.log + ps crosvm",
        )
    except Exception as exc:
        return f"  Baguette VM console log & crosvm ps: (probe failed: {exc})"
    raw = (res.stdout or "").strip()
    if "===CROSVM_PS===" in raw:
        cons_part, ps_part = raw.split("===CROSVM_PS===", 1)
        cons_part, ps_part = cons_part.replace("===CONSOLE===", "", 1).strip(), ps_part.strip()
    else:
        cons_part = raw or f"(ssh probe rc={res.returncode} stderr={(res.stderr or '').strip()!r})"
        ps_part = "(unavailable)"
    return "\n".join(
        (
            f"  Baguette VM console log ({log_dir}, first <={head_n} + last <={tail_n} lines):",
            *([f"    {ln}" for ln in cons_part.splitlines()] or ["    (empty)"]),
            "  Host crosvm processes/threads (ps):",
            *_compact_crosvm_ps_lines(ps_part),
        )
    )


def format_fatal_flow_evidence(
    vm: ChromeOSVM,
    log_scraper: HostLogScraper,
    *,
    since_rel_sec: float = 0.0,
    scrape: bool = True,
    max_console_head_lines: int = 60,
    max_console_lines: int = 80,
) -> str:
    """Scrapes and formats bounded host/Chrome logs, Baguette console log, and `crosvm` `ps`."""
    if scrape:
        try:
            log_scraper.scrape(vm)
        except Exception:
            pass
    parts = [log_scraper.format_window_tail(since_rel_sec)]
    if boot_ev := collect_baguette_boot_evidence(
        vm,
        getattr(vm, "owner_hash", None),
        max_console_head_lines=max_console_head_lines,
        max_console_lines=max_console_lines,
    ):
        parts.append(boot_ev)
    return "\n".join(parts)


def _has_flow_evidence(exc: BaseException) -> bool:
    if _EVIDENCE_SENTINEL in str(exc):
        return True
    return any(_EVIDENCE_SENTINEL in note for note in getattr(exc, "__notes__", ()))


def _reraise_with_flow_evidence(
    exc: BaseException,
    vm: ChromeOSVM,
    log_scraper: HostLogScraper,
    *,
    since_rel_sec: float = 0.0,
) -> NoReturn:
    if _has_flow_evidence(exc):
        if sys.exc_info()[1] is exc:
            raise
        raise exc
    tunnel_dead_exc: CDPError | None = None
    if isinstance(exc, CDPError) and hasattr(vm, "check_devtools_tunnel_alive"):
        try:
            vm.check_devtools_tunnel_alive()
        except CDPError as tunnel_exc:
            tunnel_dead_exc = tunnel_exc
    diag = format_fatal_flow_evidence(vm, log_scraper, since_rel_sec=since_rel_sec, scrape=True)
    if tunnel_dead_exc is not None:
        tunnel_dead_exc.add_note(diag)
        raise tunnel_dead_exc from exc
    exc.add_note(diag)
    if sys.exc_info()[1] is exc:
        raise
    raise exc


_VSH_ERR_PREFIX = r"(?:(?:\d{4}-\d{2}-\d{2}T\S+\s+)?ERROR vsh:\s+\[[^\]]*vsh\.cc[^\]]*\]|\[[^\]]*ERROR:[^\]]*vsh\.cc[^\]]*\])\s+"
_PRE_CS_VSH_NO_CONTAINER_RE = re.compile(
    rf"^{_VSH_ERR_PREFIX}Failed to launch vshd for termina:penguin: [Rr]equested container does not exist: penguin$"
)
_VSH_POLL_TIMEOUT_RE = re.compile(rf"^{_VSH_ERR_PREFIX}Poll timed out after waiting 5 seconds\.$")
_CODE50_EXACT_RE = re.compile(rf"^{re.escape(KNOWN_INITIAL_TERMINAL_TIMEOUT_ERROR)}$")
_VSH_WARNING_RE = re.compile(r"^(?:\d{4}-\d{2}-\d{2}T\S+\s+)?WARNING vsh:\s+\[[^\]]+\]\s+")


def _call_idx(detail: str, suffix: str = ":") -> int | None:
    m = re.match(rf"^call #(\d+){suffix}", detail)
    return int(m.group(1)) if m else None


def _match_terminal_error_text(buf: str, pattern: re.Pattern[str], *, allow_vsh_noise: bool) -> str | None:
    cleaned = buf.strip()
    if not allow_vsh_noise:
        return cleaned if pattern.fullmatch(cleaned) else None
    rem = [
        ln
        for raw in cleaned.splitlines()
        if (ln := raw.strip())
        and not _VSH_WARNING_RE.match(ln)
        and not (ln.startswith("[") and "ERROR" not in ln and "FATAL" not in ln)
    ]
    if not rem:
        return None
    if len(rem) == 1 and pattern.search(rem[0]):
        return rem[0]
    joined = "".join(rem)
    return joined if pattern.search(joined) and joined.count("ERROR") == 1 else None


def _match_pre_cs_vsh_no_container(
    _err_line: str, entries: list[TimelineEntry], tab_launched_rel: float, _cs_rel: float | None, _attempt: int
) -> TerminalRelaunch:
    lv_reqs = {
        idx: e
        for e in entries
        if e.source == "cicerone"
        and e.name == "LaunchVshd"
        and (idx := _call_idx(e.detail)) is not None
        and ": Received LaunchVshd request" in e.detail
    }
    ready = [e.rel_sec for e in entries if e.source == "cicerone" and e.name == "ContainerReadyLog"]
    earliest_ready = min(ready) if ready else None
    reason = "Premature LaunchVshd before cros-garcon ready (requested container does not exist)"
    matched = [
        TerminalRelaunch(
            idx,
            lv_reqs[idx],
            e,
            False,
            reason,
            "Cicerone",
            rule_id="S1",
            rule_name="pre-ContainerStarted LaunchVshd",
        )
        for e in entries
        if e.source == "cicerone"
        and e.name == "LaunchVshdNoContainer"
        and (idx := _call_idx(e.detail, " failed after ")) is not None
        and "ERR vm_cicerone[" in e.detail
        and e.detail.endswith(": Requested container does not exist: penguin")
        and idx in lv_reqs
        and lv_reqs[idx].rel_sec >= tab_launched_rel
        and (earliest_ready is None or e.rel_sec < earliest_ready)
    ]
    if len(matched) != 1:
        raise RuntimeError(
            "Expected a single pre-ContainerReadyLog vm_cicerone 'Requested container does not "
            f"exist: penguin' LaunchVshd failure at/after {fmt_rel_t(tab_launched_rel)}, found {len(matched)}"
        )
    return matched[0]


def _match_post_cs_vsh_poll_timeout(
    err_line: str, entries: list[TimelineEntry], tab_launched_rel: float, _cs_rel: float | None, _attempt: int
) -> TerminalRelaunch:
    failed_lv = {
        idx
        for e in entries
        if e.source == "cicerone"
        and e.name in ("LaunchVshdNoContainer", "LaunchVshdFailed")
        and (idx := _call_idx(e.detail, " failed after ")) is not None
    }
    lv_post = [
        (idx, e)
        for e in entries
        if e.source == "cicerone"
        and e.name == "LaunchVshd"
        and (idx := _call_idx(e.detail)) is not None
        and ": Received LaunchVshd request" in e.detail
        and idx not in failed_lv
        and e.rel_sec >= tab_launched_rel
    ]
    if len(lv_post) != 1:
        raise RuntimeError(
            "Expected a single cicerone 'Received LaunchVshd request' at/after "
            f"{fmt_rel_t(tab_launched_rel)} for vsh ListenForVshd timeout, found {len(lv_post)}"
        )
    lv_idx, lv_req = lv_post[0]
    fail_ev = TimelineEntry(lv_req.rel_sec + 5.0, "vsh", "ListenForVshdTimeout", f"call #{lv_idx}: {err_line}")
    return TerminalRelaunch(
        lv_idx,
        lv_req,
        fail_ev,
        True,
        "Known slow-runner vsh 5s ListenForVshd poll timeout (vsh.cc:240)",
        "Cicerone",
        rule_id="S3",
        rule_name="post-ContainerStarted ListenForVshd",
    )


def _match_setup_vm_user_deadline(
    _err_line: str, entries: list[TimelineEntry], tab_launched_rel: float, cs_rel: float | None, attempt: int
) -> TerminalRelaunch:
    reqs = {
        idx: e
        for e in entries
        if e.source == "concierge"
        and e.name == "SetUpVmUser"
        and (idx := _call_idx(e.detail)) is not None
        and ": Received request: SetUpVmUser" in e.detail
    }
    ready = [e.rel_sec for e in entries if e.source == "cicerone" and e.name == "ContainerReadyLog"]
    matched = [
        TerminalRelaunch(
            idx,
            reqs[idx],
            e,
            cs_rel is not None
            and (
                attempt >= 1
                or (bool(ready) and reqs[idx].rel_sec >= ready[-1])
                or (not ready and tab_launched_rel >= cs_rel)
            ),
            rule_id="S2",
            rule_name="SetUpVmUser 20s deadline",
        )
        for e in entries
        if e.source == "concierge"
        and e.name == "SetUpVmUserFailed"
        and (idx := _call_idx(e.detail, " failed after ")) is not None
        and "ERR vm_concierge[" in e.detail
        and e.detail.endswith(": SetUpUser RPC failed: Deadline Exceeded")
        and idx in reqs
        and reqs[idx].rel_sec >= tab_launched_rel
        and SETUP_USER_DEADLINE_MIN_SEC <= (e.rel_sec - reqs[idx].rel_sec) <= SETUP_USER_DEADLINE_MAX_SEC
    ]
    if len(matched) != 1:
        raise RuntimeError(
            "Expected a single concierge SetUpVmUser ~20s 'Deadline Exceeded' failure "
            f"at/after tab launch ({fmt_rel_t(tab_launched_rel)}), found {len(matched)}"
        )
    return matched[0]


@dataclasses.dataclass(frozen=True)
class _TerminalFailureRule:
    rule_id: str
    name: str
    error_re: re.Pattern[str]
    allow_vsh_noise: bool
    slot: str  # "pre_cs_only" | "post_cs_only" | "either"
    match_log: Callable[[str, list[TimelineEntry], float, float | None, int], TerminalRelaunch]
    is_settled: Callable[[list[TimelineEntry], float], bool]


_TERMINAL_FAILURE_RULES: tuple[_TerminalFailureRule, ...] = (
    _TerminalFailureRule(
        rule_id="S1",
        name="pre-ContainerStarted LaunchVshd",
        error_re=_PRE_CS_VSH_NO_CONTAINER_RE,
        allow_vsh_noise=True,
        slot="pre_cs_only",
        match_log=_match_pre_cs_vsh_no_container,
        is_settled=lambda entries, floor: any(
            e.name in ("LaunchVshdNoContainer", "LaunchVshdFailed") and e.rel_sec >= floor for e in entries
        ),
    ),
    _TerminalFailureRule(
        rule_id="S2",
        name="SetUpVmUser 20s deadline",
        error_re=_CODE50_EXACT_RE,
        allow_vsh_noise=False,
        slot="either",
        match_log=_match_setup_vm_user_deadline,
        is_settled=lambda entries, floor: (
            any(e.name == "SetUpVmUserFailed" and e.rel_sec >= floor for e in entries)
            and not any(e.name == "SetUpVmUserInFlight" for e in entries)
        ),
    ),
    _TerminalFailureRule(
        rule_id="S3",
        name="post-ContainerStarted ListenForVshd",
        error_re=_VSH_POLL_TIMEOUT_RE,
        allow_vsh_noise=True,
        slot="post_cs_only",
        match_log=_match_post_cs_vsh_poll_timeout,
        is_settled=lambda entries, floor: any(
            e.name.startswith("LaunchVshd") and e.rel_sec >= floor for e in entries
        ),
    ),
)


def _slot_eligible(slot: str, *, attempt: int, cs_rel: float | None, post_cs_used: bool) -> bool:
    if attempt >= 2 or post_cs_used:
        return False
    if slot == "pre_cs_only":
        return attempt == 0 and cs_rel is None
    if slot == "post_cs_only":
        return cs_rel is not None
    return not (attempt >= 1 and cs_rel is None)


def _find_terminal_rule(terminal_buffer: str) -> tuple[_TerminalFailureRule, str] | None:
    for rule in _TERMINAL_FAILURE_RULES:
        if (err_line := _match_terminal_error_text(terminal_buffer, rule.error_re, allow_vsh_noise=rule.allow_vsh_noise)) is not None:
            return rule, err_line
    return None


def classify_terminal_setup_failure(
    terminal_buffer: str,
    entries: list[TimelineEntry],
    *,
    tab_launched_rel_sec: float,
    container_started_rel_sec: float | None,
    attempt: int = 0,
    post_cs_relaunch_used: bool = False,
) -> TerminalRelaunch:
    """Allowlists known slow-runner SetUpVmUser ~20s deadline, pre-CS LaunchVshd, or post-CS vsh 5s poll timeout."""
    found = _find_terminal_rule(terminal_buffer)
    if found is None:
        raise RuntimeError(
            "Terminal tab failed with an unrecognized or incomplete buffer "
            f"(expected exact {KNOWN_INITIAL_TERMINAL_TIMEOUT_ERROR!r}, pre-ContainerStarted "
            "vsh 'requested container does not exist: penguin', or post-ContainerStarted "
            f"vsh 'Poll timed out after waiting 5 seconds.', got {terminal_buffer.strip()!r})"
        )
    rule, err_line = found
    if not _slot_eligible(
        rule.slot, attempt=attempt, cs_rel=container_started_rel_sec, post_cs_used=post_cs_relaunch_used
    ):
        raise RuntimeError(
            f"Terminal {rule.name} retry not eligible (attempt={attempt}, "
            f"container_started_rel_sec={container_started_rel_sec}, "
            f"post_cs_relaunch_used={post_cs_relaunch_used})"
        )
    return rule.match_log(err_line, entries, tab_launched_rel_sec, container_started_rel_sec, attempt)


def format_terminal_relaunch_banner(
    ev: TerminalRelaunch,
    *,
    failed_label: str,
    target_id: str,
    tab_launched_rel_sec: float,
    cs_rel_sec: float,
) -> str:
    scope = "1/1 post-ContainerStarted" if ev.post_container_started else "pre-ContainerStarted installer tab"
    prefix = f"{ev.daemon_label}:"
    return "\n".join(
        (
            f"  WARNING: TERMINAL RELAUNCH TRIGGERED [{ev.rule_id}: {ev.rule_name}] ({scope})",
            f"    Reason:    {ev.reason} on {failed_label} (target={target_id})",
            f"    Timings:   launch={fmt_rel_t(tab_launched_rel_sec).strip()} | req={fmt_rel_t(ev.req_entry.rel_sec).strip()} -> err={fmt_rel_t(ev.fail_entry.rel_sec).strip()} (dur={ev.duration_sec:.1f}s) | ContainerStarted={fmt_rel_t(cs_rel_sec).strip()}",
            f"    {prefix:<10} {ev.req_entry.detail}",
            f"    {prefix:<10} {ev.fail_entry.detail}",
        )
    )


class _FlowTracker:
    """Coordinates monotonic/VM-epoch anchors, UI events, `DbusSignalMonitor`, and `HostLogScraper`."""

    def __init__(
        self,
        vm: ChromeOSVM,
        dbus_mon: DbusSignalMonitor,
        log_scraper: HostLogScraper,
        observer: FlowDiagnosticsObserver,
    ) -> None:
        self.vm = vm
        self.dbus_mon = dbus_mon
        self.log_scraper = log_scraper
        self.observer = observer
        self.ui_entries: list[TimelineEntry] = []
        self.relaunches: list[TerminalRelaunch] = []
        self.initial_tab_launched_rel = 0.0
        self.vm_clock_skew_sec = 0.5

    def check_healthy(self) -> None:
        self.dbus_mon.check_healthy()

    def mark_install_clicked(self, username: str) -> None:
        self.check_healthy()
        now_mono = time.monotonic()
        vm_epoch = float(self.vm.ssh("date -u +%s.%N", op_desc="install_clicked:vm_epoch").stdout.strip())
        self.vm_clock_skew_sec = (time.monotonic() - now_mono) + 0.5
        self.dbus_mon.mark_install_clicked(now_mono)
        self.log_scraper.mark_install_clicked(vm_epoch)
        self.ui_entries.append(
            TimelineEntry(0.0, "ui", "InstallClicked", f"Clicked Install in chrome://crostini-installer (user={username!r})")
        )
        self.observer.on_install_clicked(username=username, mono_ts=now_mono, vm_epoch_sec=vm_epoch)

    def record_ui(self, name: str, detail: str) -> float:
        self.check_healthy()
        rel = self.dbus_mon.rel_mono()
        self.ui_entries.append(TimelineEntry(rel, "ui", name, detail))
        self.observer.on_ui_event(name, detail, rel)
        return rel

    def combined_classifier_entries(self) -> list[TimelineEntry]:
        return sorted(self.ui_entries + self.log_scraper.last_entries, key=lambda e: e.rel_sec)


def run_settings_crostini_installer_ui(
    vm: ChromeOSVM, username: str, tracker: _FlowTracker
) -> dict[str, Any]:
    """Drives ChromeOS Settings -> About ChromeOS -> Developers -> Set up -> crostini-installer.

    Returns the initial `chrome-untrusted://terminal` vmshell CDP target opened by the installer,
    attaching bounded host/Chrome/Baguette-console/crosvm-ps evidence on fatal failure.
    """
    installer_conn: CDPConnection | None = None
    try:
        vm.set_step("step2:open_os_settings")
        log("Opening `chrome://os-settings/` via CDP...")
        vm.launch_swa_or_target(
            "chrome://os-settings/", label="Browser-LaunchOSSettings", op_desc="launch chrome://os-settings/ SWA"
        )
        settings_conn = vm.connect_cdp_target(
            lambda tgt: "chrome://os-settings" in tgt.get("url", ""),
            operation="find_target(chrome://os-settings)",
            target_label="OS-Settings",
            target_url="chrome://os-settings/",
            timeout=30.0,
            interval=0.5,
            err_prefix="Could not find `chrome://os-settings/` target in CDP",
        )
        tracker.record_ui("OSSettingsAttached", "Attached to chrome://os-settings/")
        try:
            vm.set_step("step2:navigate_os_settings_click_setup")
            log(
                "Navigating OS Settings UI: clicking `About ChromeOS` -> "
                "`Developers` -> `Linux development environment` -> `Set up`..."
            )
            nav_res = settings_conn.poll_js(
                """(() => {
                    const ui = document.querySelector('os-settings-ui');
                    if (!ui?.shadowRoot) return 'no-ui';
                    const aboutItem = ui.shadowRoot.querySelector('os-settings-menu')?.shadowRoot
                        ?.querySelector('os-settings-menu-item[path="/help"]');
                    if (!aboutItem) return 'no-about-item';
                    aboutItem.click();
                    const card = ui.shadowRoot.querySelector('os-settings-main')?.shadowRoot
                        ?.querySelector('main-page-container')?.shadowRoot
                        ?.querySelector('os-about-page')?.shadowRoot
                        ?.querySelector('crostini-settings-card');
                    if (!card?.shadowRoot) return 'no-crostini-card';
                    const header = card.shadowRoot.querySelector('settings-card')?.getAttribute('header-text') || '';
                    const label = card.shadowRoot.querySelector('#crostini .start')?.innerText?.split('\\n')[0]?.trim();
                    const btn = card.shadowRoot.querySelector('#enableCrostiniButton');
                    if (!btn || btn.disabled) return 'no-or-disabled-btn:' + header + ':' + label;
                    btn.click();
                    return 'CLICKED_SETUP:' + header + ' | ' + label + ' | ' + btn.innerText.trim();
                })()""",
                lambda val: isinstance(val, str) and val.startswith("CLICKED_SETUP:"),
                op_desc="OS-Settings:navigate_and_click_setup",
                timeout=30.0,
            )
            log(f"  OS Settings UI action: {nav_res}")
        finally:
            settings_conn.close()

        vm.set_step("step2:attach_crostini_installer")
        installer_conn = vm.connect_cdp_target(
            lambda tgt: "chrome://crostini-installer" in tgt.get("url", ""),
            operation="find_target(chrome://crostini-installer)",
            target_label="Crostini-Installer",
            target_url="chrome://crostini-installer/",
            timeout=30.0,
            interval=0.5,
            err_prefix="`chrome://crostini-installer` dialog did not open after clicking Set up",
        )
        tracker.record_ui("InstallerAttached", "Attached to chrome://crostini-installer/")
        vm.close_cdp_targets_matching("chrome://os-settings", label="OS-Settings")

        vm.set_step("step2:installer_click_next")
        installer_conn.poll_js(
            """(() => {
                const nextBtn = document.querySelector('crostini-installer-app')?.shadowRoot?.querySelector('#next');
                if (!nextBtn || nextBtn.hidden) return 'no-next';
                nextBtn.click();
                return 'CLICKED_NEXT';
            })()""",
            lambda val: val == "CLICKED_NEXT",
            op_desc="Crostini-Installer:click_next",
            timeout=30.0,
        )
        log("  Clicked `Next` in `chrome://crostini-installer`.")

        vm.set_step("step2:installer_click_install")
        step2 = installer_conn.poll_js(
            f"""(() => {{
                const root = document.querySelector('crostini-installer-app')?.shadowRoot;
                const input = root?.querySelector('#username');
                const installBtn = root?.querySelector('#install');
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
        tracker.mark_install_clicked(username)
        log(f"  Clicked `Install` in `chrome://crostini-installer` ({step2}).")

        vm.set_step("step2:wait_installer_complete")
        log("  Waiting for `chrome://crostini-installer` to finish provisioning `termina`...")
        installer_finish_timeout = 420.0
        t0 = time.monotonic()
        deadline = t0 + installer_finish_timeout
        poll_interval = 1.0
        last_status: dict[str, str] = {"err": "", "installing": ""}
        last_open_rel = tracker.dbus_mon.rel_mono()
        while time.monotonic() < deadline:
            tracker.check_healthy()
            eval_err: Exception | None = None
            try:
                status = installer_conn.eval_js(
                    """(() => {
                    const root = document.querySelector('crostini-installer-app')?.shadowRoot;
                    if (!root) return null;
                    const err = root.querySelector('#error-message:not([hidden]) div')?.innerText?.trim()
                        || root.querySelector('#error-message div')?.innerText?.trim();
                    const installing = root.querySelector('#installing-message div')?.innerText?.trim();
                    return { err: err || '', installing: installing || '' };
                })()""",
                    timeout=30.0,
                    op_desc="Crostini-Installer:poll_status",
                )
            except (CDPError, CDPTimeoutError) as exc:
                eval_err, status = exc, None
            if isinstance(status, dict):
                if status.get("installing"):
                    last_status["installing"] = status["installing"]
                if status.get("err"):
                    last_status["err"] = status["err"]
                    raise RuntimeError(
                        f"`chrome://crostini-installer` failed with UI error: {status['err']} "
                        f"(last progress: {last_status.get('installing')!r})"
                    )
                last_open_rel = tracker.dbus_mon.rel_mono()
                poll_interval = sleep_backoff(poll_interval, 3.0, deadline)
                continue

            if not any("chrome://crostini-installer" in x.get("url", "") for x in vm.list_cdp_targets()):
                if last_status.get("err"):
                    raise RuntimeError(
                        "`chrome://crostini-installer` closed with an error displayed: "
                        f"{last_status['err']} (last progress: {last_status.get('installing')!r})"
                    )
                tracker.initial_tab_launched_rel = max(0.0, last_open_rel - tracker.vm_clock_skew_sec)
                elapsed = time.monotonic() - t0
                tracker.record_ui(
                    "InstallerClosed", f"closed after {elapsed:.1f}s (last_progress={last_status.get('installing')!r})"
                )
                vm.set_step("step2:attach_initial_terminal_vmshell")
                vmshell_tgt = vm.wait_for_cdp_target(
                    lambda x: _TERMINAL_VMSHELL_URL in x.get("url", ""),
                    operation="wait_for_target(Terminal-App-Initial vmshell)",
                    target_label="Terminal-App-Initial",
                    target_url=_TERMINAL_VMSHELL_URL,
                    timeout=45.0,
                    interval=0.5,
                    err_prefix=(
                        f"`chrome://crostini-installer` closed after {elapsed:.1f}s "
                        f"(last progress: {last_status.get('installing')!r}), but the ChromeOS "
                        "Terminal app (`chrome-untrusted://terminal` vmshell tab) did not open"
                    ),
                )
                tracker.record_ui("InitialTerminalAttached", f"target={vmshell_tgt.get('id')}")
                log(
                    f"  `chrome://crostini-installer` completed and closed in {elapsed:.1f}s "
                    f"(last progress: {last_status.get('installing')!r}, "
                    f"Terminal app vmshell target={vmshell_tgt.get('id')})."
                )
                return vmshell_tgt
            if eval_err is not None:
                raise eval_err
            poll_interval = sleep_backoff(poll_interval, 3.0, deadline)
        ctx = installer_conn.error_context(
            "Crostini-Installer:wait_for_finish", time.monotonic() - t0, installer_finish_timeout
        )
        raise CDPTimeoutError(
            f"Timed out waiting for `chrome://crostini-installer` to finish ({ctx}; last status={last_status!r})"
        )
    except (CDPError, CDPTimeoutError, RuntimeError) as exc:
        _reraise_with_flow_evidence(exc, vm, tracker.log_scraper, since_rel_sec=0.0)
    finally:
        if installer_conn is not None:
            installer_conn.close()


def _open_fresh_terminal_from_home(
    vm: ChromeOSVM, old_target_ids: set[str], tracker: _FlowTracker, *, label: str = "Terminal-App-Fresh"
) -> CroshTab:
    """Clicks `penguin` in `chrome-untrusted://terminal/html/terminal.html#home` to launch a fresh Terminal tab."""
    vm.set_step("step3:relaunch_fresh_terminal_from_home")
    if not any(_TERMINAL_HOME_URL in str(t.get("url", "")) for t in vm.list_cdp_targets()):
        vm.launch_swa_or_target(
            _TERMINAL_HOME_URL, label="Browser-LaunchTerminalHome", op_desc=f"launch {_TERMINAL_HOME_URL} SWA"
        )
    home_conn = vm.connect_cdp_target(
        lambda tgt: _TERMINAL_HOME_URL in tgt.get("url", ""),
        operation="find_target(Terminal-Home #home)",
        target_label="Terminal-Home",
        target_url=_TERMINAL_HOME_URL,
        target_id="<missing>",
        timeout=30.0,
        interval=0.4,
        err_prefix=f"Could not find `{_TERMINAL_HOME_URL}` target to relaunch Terminal",
    )
    try:
        click_res = home_conn.poll_js(
            """(() => {
                const links = Array.from(
                    document.querySelector('terminal-home-app')?.shadowRoot
                        ?.querySelectorAll('a[href*="command=vmshell"]') || []
                );
                if (!links.length) return 'no-links';
                links[0].click();
                return 'CLICKED:' + links[0].getAttribute('href');
            })()""",
            lambda val: isinstance(val, str) and val.startswith("CLICKED:"),
            op_desc="Terminal-Home:click_penguin_vmshell",
            timeout=30.0,
        )
        log(f"  [Terminal-Home] Launched {label} tab via `{click_res}`")
    finally:
        home_conn.close()

    fresh_tgt = vm.wait_for_cdp_target(
        lambda tgt: tgt.get("id", "") not in old_target_ids and _TERMINAL_VMSHELL_URL in tgt.get("url", ""),
        operation=f"wait_for_target({label} vmshell)",
        target_label=label,
        target_url=_TERMINAL_VMSHELL_URL,
        timeout=45.0,
        interval=0.4,
        err_prefix="Timed out waiting for fresh Terminal vmshell tab after clicking penguin in Terminal Home",
    )
    tracker.record_ui("FreshTerminalLaunched", f"Clicked penguin in {_TERMINAL_HOME_URL} ({label})")
    log(f"  Attached to {label} vmshell tab (target={fresh_tgt.get('id')})")
    return CroshTab(
        label,
        CDPConnection.from_target(
            fresh_tgt, label=label, step_getter=vm.get_step, on_error=vm.check_devtools_tunnel_alive
        ),
    )


def disable_terminal_close_on_exit(vm: ChromeOSVM) -> None:
    """Disables Terminal's default `close-on-exit` pref so failed `vsh` tabs stay open and diagnosable.

    Terminal's `Terminal.exit` (`terminal.js`) calls `window.close()` when `vsh` exits after writing
    to the PTY if `/hterm/profiles/default/close-on-exit` is true (its default). Writing `false` to
    `crostini.terminal_settings` via `chrome.terminalPrivate.setPrefs` (the same pref store written
    by Terminal Settings) retains `vsh`'s stderr output in the tab instead of closing the target.
    """
    vm.set_step("step2:disable_terminal_close_on_exit")
    vm.launch_swa_or_target(
        _TERMINAL_HOME_URL, label="Browser-TerminalPrefInit", op_desc=f"launch {_TERMINAL_HOME_URL} for pref init"
    )
    pref_conn = vm.connect_cdp_target(
        lambda tgt: _TERMINAL_HOME_URL in tgt.get("url", ""),
        operation="find_target(Terminal-PrefInit #home)",
        target_label="Terminal-PrefInit",
        target_url=_TERMINAL_HOME_URL,
        timeout=30.0,
        interval=0.4,
        err_prefix="Could not open Terminal #home to configure close-on-exit=false",
    )
    try:
        pref_conn.poll_js(
            "typeof chrome?.terminalPrivate?.getPrefs === 'function' "
            "&& typeof chrome?.terminalPrivate?.setPrefs === 'function'",
            bool,
            op_desc="Terminal-PrefInit:wait_terminalPrivate",
            timeout=15.0,
        )
        readback = pref_conn.eval_js(
            """(async () => {
                const p = 'crostini.terminal_settings', k = '/hterm/profiles/default/close-on-exit';
                const call = (fn, arg) => new Promise((res, rej) => fn(arg, (v) => {
                    const e = chrome.runtime?.lastError?.message; e ? rej(new Error(e)) : res(v);
                }));
                const cur = await call(chrome.terminalPrivate.getPrefs, [p]);
                await call(chrome.terminalPrivate.setPrefs, { [p]: Object.assign({}, cur?.[p] || {}, { [k]: false }) });
                return (await call(chrome.terminalPrivate.getPrefs, [p]))?.[p]?.[k];
            })()""",
            await_promise=True,
            timeout=15.0,
            op_desc="Terminal-PrefInit:set_and_verify_close_on_exit",
        )
        if not (isinstance(readback, bool) and readback is False):
            raise RuntimeError(
                f"Terminal close-on-exit pref readback mismatch after setPrefs: expected False, got {readback!r}"
            )
        log("  Verified Terminal pref `/hterm/profiles/default/close-on-exit` = False.")
    finally:
        pref_conn.close()
        vm.close_cdp_page_targets_by_url((_TERMINAL_HOME_URL,), label="Terminal-PrefInit")


def _classify_terminal_failure_with_flush(
    vm: ChromeOSVM,
    terminal_buffer: str,
    tracker: _FlowTracker,
    *,
    tab_launched_rel_sec: float,
    container_started_rel_sec: float | None,
    attempt: int,
    post_cs_relaunch_used: bool,
) -> TerminalRelaunch:
    """Scrapes host logs (allowing rsyslog flush) and classifies allowlisted Terminal errors."""
    flush_deadline = time.monotonic() + LOG_FLUSH_TIMEOUT_SEC
    found = _find_terminal_rule(terminal_buffer)
    while True:
        tracker.log_scraper.scrape(vm)
        entries = tracker.combined_classifier_entries()
        launch_floor = tab_launched_rel_sec
        if attempt == 0:
            if call1_done := [
                e.rel_sec
                for e in entries
                if e.source == "concierge" and e.name == "SetUpVmUserDone" and e.detail.startswith("call #1 ")
            ]:
                launch_floor = max(launch_floor, call1_done[-1])
        try:
            return classify_terminal_setup_failure(
                terminal_buffer,
                entries,
                tab_launched_rel_sec=launch_floor,
                container_started_rel_sec=container_started_rel_sec,
                attempt=attempt,
                post_cs_relaunch_used=post_cs_relaunch_used,
            )
        except RuntimeError:
            rem = flush_deadline - time.monotonic()
            if (
                found is None
                or not _slot_eligible(
                    found[0].slot,
                    attempt=attempt,
                    cs_rel=container_started_rel_sec,
                    post_cs_used=post_cs_relaunch_used,
                )
                or found[0].is_settled(entries, launch_floor)
                or rem <= 0
            ):
                raise
            time.sleep(min(0.8, rem))


def _observe_terminal_until_prompt_or_error(
    tab: CroshTab,
    username: str,
    tracker: _FlowTracker,
    *,
    timeout: float,
    first_output_event: str,
    log_first_output: bool = False,
) -> tuple[str, str]:
    """Polls `tab` until prompt (`'prompt'`), vmshell error (`'error'`), or deadline (`'timeout'`)."""
    deadline = time.monotonic() + timeout
    poll_interval = TERMINAL_POLL_FLOOR_SEC
    first_output_logged = False
    last_txt = ""
    while time.monotonic() < deadline:
        tracker.check_healthy()
        txt = last_txt = tab.get_text(max_lines=24)
        if not first_output_logged and txt.strip():
            first_output_logged = True
            first_ln = txt.strip().splitlines()[0][:140]
            fo_rel = tracker.record_ui(first_output_event, first_ln)
            if log_first_output:
                log(f"  [{tab.label}] First output at t+{fo_rel:.1f}s: {first_ln}")
        if f"[{username}@" in txt and txt.rstrip().endswith("$"):
            return "prompt", txt
        has_vsh_err = bool(
            re.search(r"(?:ERROR|FATAL)[:\s].*\bvsh(?:_client)?\.cc\b", txt) or "Failed to launch vshd for " in txt
        )
        if (
            txt.strip() == KNOWN_INITIAL_TERMINAL_TIMEOUT_ERROR
            or "Launching vmshell failed:" in txt
            or "[process exited" in txt
            or has_vsh_err
        ):
            if has_vsh_err:
                time.sleep(0.1)
            return "error", (tab.get_text() or txt)
        poll_interval = sleep_backoff(poll_interval, 2.5, deadline)
    try:
        last_txt = tab.get_text() or last_txt
    except (CDPError, CDPTimeoutError, OSError):
        pass
    return "timeout", last_txt


def verify_terminal_app_with_readiness_gate(
    vm: ChromeOSVM,
    initial_vmshell_tgt: dict[str, Any],
    username: str,
    tracker: _FlowTracker,
) -> TerminalRelaunch | None:
    """Observes Terminal in a single readiness-gated loop and verifies interactive shell identity."""
    seen_target_ids: set[str] = {str(initial_vmshell_tgt["id"])}
    active_tab: CroshTab | None = CroshTab(
        "Terminal-App-Initial",
        CDPConnection.from_target(
            initial_vmshell_tgt,
            label="Terminal-App-Initial",
            step_getter=vm.get_step,
            on_error=vm.check_devtools_tunnel_alive,
        ),
    )
    tab_launched_rel = tracker.initial_tab_launched_rel
    post_cs_relaunch: TerminalRelaunch | None = None
    last_relaunch: TerminalRelaunch | None = None
    attempt = 0
    try:
        # Do NOT call Target.closeTarget on Tab 0 (`terminal.html#home`) while a
        # vmshell tab is open: Terminal pins `#home` (`web_app::IsTabClosable` is
        # false when tab count > 1), so ClosePage() aborts `#home` parsing via
        # `Document::DispatchUnloadEvents` (`StopParsing()`) without closing it.
        log("  Observing installer-opened ChromeOS Terminal app window...")
        while True:
            assert active_tab is not None
            vm.set_step(f"step3:observe_terminal_{attempt}")
            obs_timeout = 120.0 if attempt == 0 else 180.0
            t_obs0 = time.monotonic()
            outcome, last_txt = _observe_terminal_until_prompt_or_error(
                active_tab,
                username,
                tracker,
                timeout=obs_timeout,
                first_output_event="InitialTerminalFirstOutput" if attempt == 0 else "FreshTerminalFirstOutput",
                log_first_output=(attempt > 0),
            )

            if outcome == "prompt":
                vm.set_step("step3:wait_container_started")
                cs_rel = tracker.dbus_mon.wait_for_container_started(timeout=60.0)
                pr_rel = tracker.record_ui(
                    "InitialTerminalObserved" if attempt == 0 else "FreshTerminalPromptReached",
                    f"reached prompt [{username}@penguin]$ in {active_tab.label}",
                )
                log(f"  [{active_tab.label}] Reached prompt at t+{pr_rel:.1f}s (ContainerStarted at t+{cs_rel:.1f}s).")
                break

            if outcome == "timeout":
                if hasattr(vm, "check_devtools_tunnel_alive"):
                    vm.check_devtools_tunnel_alive()
                ctx = active_tab.conn.error_context(
                    f"{active_tab.label}:wait_for_shell_prompt", time.monotonic() - t_obs0, obs_timeout
                )
                raise CDPTimeoutError(
                    f"Timed out waiting for {active_tab.label} prompt ({ctx}). Buffer:\n{last_txt}"
                )

            cs_already = tracker.dbus_mon.is_container_started()
            cs_rel_pre = tracker.dbus_mon.container_started_rel_sec if cs_already else None
            failed_tid, failed_label = str(active_tab.conn.target_id), active_tab.label
            obs_rel = tracker.record_ui(
                "InitialTerminalObserved" if attempt == 0 else "FreshTerminalObserved",
                f"no prompt (container_started_already={cs_already}): {last_txt.strip().replace(chr(10), ' | ')[:200]}",
            )
            log(f"  WARNING: {failed_label} failed at t+{obs_rel:.1f}s (ContainerStarted already fired={cs_already}):\n{last_txt}")
            ev = _classify_terminal_failure_with_flush(
                vm,
                last_txt,
                tracker,
                tab_launched_rel_sec=tab_launched_rel,
                container_started_rel_sec=cs_rel_pre,
                attempt=attempt,
                post_cs_relaunch_used=(post_cs_relaunch is not None),
            )
            vm.set_step("step3:close_failed_terminal")
            vm.close_crosh_tab(active_tab)
            active_tab = None

            vm.set_step("step3:wait_container_started")
            if not cs_already:
                log("  Waiting on D-Bus readiness gate: `VmCicerone.ContainerStarted` (termina/penguin)...")
            cs_rel = tracker.dbus_mon.wait_for_container_started(timeout=300.0 if not cs_already else 60.0)
            last_relaunch = ev
            tracker.relaunches.append(ev)
            if ev.post_container_started:
                post_cs_relaunch = ev
            log(
                "\n"
                + format_terminal_relaunch_banner(
                    ev,
                    failed_label=failed_label,
                    target_id=failed_tid,
                    tab_launched_rel_sec=tab_launched_rel,
                    cs_rel_sec=cs_rel,
                )
            )
            tab_launched_rel = max(
                ev.fail_entry.rel_sec + 0.001, tracker.dbus_mon.rel_mono() - tracker.vm_clock_skew_sec
            )
            next_label = "Terminal-App-Relaunch" if ev.post_container_started else "Terminal-App-Fresh"
            active_tab = _open_fresh_terminal_from_home(vm, seen_target_ids, tracker, label=next_label)
            seen_target_ids.add(str(active_tab.conn.target_id))
            vm.close_cdp_targets_matching(
                _TERMINAL_VMSHELL_URL, label="Terminal-Stale", exclude_ids={active_tab.conn.target_id}
            )
            attempt += 1

        assert active_tab is not None
        vm.set_step("step3:verify_terminal_interactive_shell")
        marker = f"TERM_USER_{int(time.monotonic() * 1000)}="
        active_tab.send_line(f'echo "{marker}$(id -nu)"')
        active_tab.wait_for(
            lambda txt: f"\n{marker}{username}" in txt and txt.rstrip().endswith("$"),
            timeout=45.0,
            desc=f"`id -nu` == {username} in {active_tab.label}",
            max_lines=16,
        )
        ver_rel = tracker.record_ui(
            "TerminalPromptVerified", f"Confirmed `id -nu` == {username!r} in {active_tab.label}"
        )
        log(f"  [{active_tab.label}] Verified interactive shell user `{username}` at t+{ver_rel:.1f}s")
        return last_relaunch
    except (CDPError, CDPTimeoutError, RuntimeError) as exc:
        _reraise_with_flow_evidence(exc, vm, tracker.log_scraper, since_rel_sec=tab_launched_rel)
    finally:
        if active_tab is not None:
            vm.close_crosh_tab(active_tab)
        vm.close_cdp_targets_matching("chrome-untrusted://terminal", label="Terminal-App")


def _wait_for_new_guest_prompt(
    tab: CroshTab, prev_prompts: int, username: str, timeout: float, desc: str
) -> None:
    def _check(txt: str) -> bool:
        if "ERROR - ERROR: command failed" in txt.split("vsh termina penguin")[-1]:
            raise RuntimeError(f"`vsh termina penguin` failed in {tab.label} (after ContainerStarted!):\n{txt}")
        return txt.count(f"[{username}@") > prev_prompts and txt.rstrip().endswith("$")

    tab.wait_for(_check, timeout=timeout, desc=desc, max_lines=24 if prev_prompts == 0 else None)


def _assert_guest_shell_in_crosh(vm: ChromeOSVM, tab: CroshTab, expected_username: str) -> None:
    """Runs `id -nu` inside the active guest shell in `tab` and exits back to `crosh>`."""
    vm.set_step("step4:verify_crosh_guest_shell")
    marker = f"USER_CHECK_{int(time.monotonic() * 1000)}="
    prev_crosh_prompts = tab.get_text().count("crosh>")
    tab.send_line(f'echo "{marker}$(id -nu)"')
    tab.wait_for(
        lambda txt: f"\n{marker}{expected_username}" in txt and txt.rstrip().endswith("$"),
        timeout=45.0,
        desc=f"`id -nu` == {expected_username} in {tab.label}",
        max_lines=16,
    )
    log(f"  [{tab.label}] Confirmed guest shell user via crosh UI: `{expected_username}`")
    tab.send_line("exit")
    tab.wait_for(
        lambda txt: txt.count("crosh>") > prev_crosh_prompts and txt.rstrip().endswith("crosh>"),
        timeout=45.0,
        desc=f"exit guest shell back to crosh> in {tab.label}",
    )


def verify_concierge_balloon_timer_stopped(vm: ChromeOSVM, msg_line_cursor: int) -> None:
    """Verifies in unfiltered `/var/log/messages` that concierge stopped its balloon timer cleanly.

    Reads raw `vm_concierge` lines directly (bypassing `HostLogScraper.scrape()`'s `BalloonTrace:`
    filter) and asserts that after `SetBalloonTimer(0)` logs its stop message, zero `BalloonTrace`,
    `BalloonInit`, or `balloon stats` lines occur for the remainder of the flow.
    """
    raw = vm.ssh(
        f"set -o pipefail; test -r /var/log/messages; "
        f"tail -n +{msg_line_cursor + 1} /var/log/messages | {{ grep 'vm_concierge\\[' || [ $? -eq 1 ]; }}",
        check=True,
        timeout=30,
        op_desc="verify_concierge_balloon_timer_stopped(/var/log/messages)",
    ).stdout
    lines = [ln.strip() for ln in raw.splitlines() if ln.strip()]
    start_idx = next((i for i, ln in enumerate(lines) if "Starting balloon resize timer" in ln), -1)
    if start_idx < 0:
        raise RuntimeError(
            "Expected concierge 'Starting balloon resize timer' line in unfiltered "
            f"/var/log/messages, found none ({len(lines)} vm_concierge lines)"
        )
    stop_indices = [
        i
        for i, ln in enumerate(lines[start_idx + 1 :], start=start_idx + 1)
        if "timer_interval_millis is 0" in ln and ("Stopping balloon timer" in ln or "Stop the timer" in ln)
    ]
    if not stop_indices:
        raise RuntimeError(
            "Expected concierge SetBalloonTimer(0) stop log after 'Starting balloon resize timer' "
            f"in unfiltered /var/log/messages, found none (tail={lines[start_idx : start_idx + 12]!r})"
        )
    stop_idx = stop_indices[-1]
    is_balloon = lambda ln: any(tok in ln for tok in _BALLOON_NOISE_TOKENS)
    if post_balloon := [ln for ln in lines[stop_idx + 1 :] if is_balloon(ln)]:
        raise RuntimeError(
            f"Unexpected concierge balloon activity after SetBalloonTimer(0) stopped the timer: {post_balloon[:5]!r}"
        )
    pre_balloon_count = sum(1 for ln in lines[start_idx:stop_idx] if is_balloon(ln))
    log(
        f"  Verified concierge balloon timer stopped in unfiltered /var/log/messages "
        f"({lines[stop_idx].split(None, 3)[-1]!r}; pre-stop balloon lines={pre_balloon_count}, "
        "post-stop balloon lines=0)."
    )


def run_termina_user_flow(
    vm: ChromeOSVM,
    readme_cmds: ReadmeCommands,
    *,
    username: str = "terminauser",
    observer: FlowDiagnosticsObserver | None = None,
) -> FlowResult:
    """Executes the full `termina` + Settings Linux installer + Terminal + `crosh` E2E flow."""
    assert vm.owner_hash
    obs = observer or vm.observer
    log("=== Starting Flow: `termina` VM + ChromeOS Settings UI Installer ===")
    log_scraper = HostLogScraper()
    # Stop concierge's 1 Hz BalanceAvailableBalloonPolicy timer once Baguette starts:
    # memory ballooning is orthogonal to this user-flow test and inflates ~1.5 GiB via
    # 1 Hz virtio-balloon stats/reclaim churn during SetUpVmUser under nested virtualization.
    dbus_mon = DbusSignalMonitor(
        vm,
        owner_hash=vm.owner_hash,
        expected_username=username,
        observer=obs,
        stop_balloon_timer_on_vm_started=True,
    )
    tracker = _FlowTracker(vm, dbus_mon, log_scraper, obs)

    crosh: CroshTab | None = None
    failed = report_logged = False
    relaunch_ev: TerminalRelaunch | None = None
    try:
        log_scraper.capture_cursors(vm)
        crosh = vm.open_crosh_tab("Termina-Crosh")
        vm.set_step("step1:vmc_create")
        log("Step 1: Running `vmc create` command from README.md in crosh...")
        crosh.run_crosh_cmd(readme_cmds.termina_create, timeout=180)
        vm.close_crosh_tab(crosh)
        crosh = None

        disable_terminal_close_on_exit(vm)

        vm.set_step("step2:start_dbus_monitor")
        log("Step 2: Subscribing system D-Bus monitor & driving ChromeOS Settings UI...")
        dbus_mon.start()
        try:
            obs.on_before_flow(
                vm, owner_hash=vm.owner_hash, username=username, log_scraper=log_scraper, dbus_mon=dbus_mon
            )
            initial_vmshell_tgt = run_settings_crostini_installer_ui(vm, username=username, tracker=tracker)

            log("Step 3: Verifying ChromeOS Terminal app (`chrome-untrusted://terminal`) gated on `ContainerStarted`...")
            relaunch_ev = verify_terminal_app_with_readiness_gate(
                vm, initial_vmshell_tgt=initial_vmshell_tgt, username=username, tracker=tracker
            )

            vm.set_step("step4:crosh_vsh_reentry")
            log(f"Step 4: Verifying README crosh shell entry (`{readme_cmds.termina_reentry_vsh}`, single attempt)...")
            crosh = vm.open_crosh_tab("Termina-Crosh")
            log(f"  [{crosh.label}] crosh> {readme_cmds.termina_reentry_vsh}")
            crosh.send_line(readme_cmds.termina_reentry_vsh)
            _wait_for_new_guest_prompt(
                crosh, 0, username, timeout=45.0, desc=f"`{readme_cmds.termina_reentry_vsh}` shell prompt for `{username}`"
            )
            _assert_guest_shell_in_crosh(vm, crosh, expected_username=username)
            tracker.record_ui("CroshVshVerified", f"`{readme_cmds.termina_reentry_vsh}` -> `id -nu` == {username!r}")
            vm.close_crosh_tab(crosh)
            crosh = None

            vm.set_step("step5:verify_guest_and_collect")
            log("Step 5: Verifying D-Bus signal sequence, balloon timer stop, and in-guest user/garcon state...")
            dbus_mon.verify_required_signal_sequence()
            verify_concierge_balloon_timer_stopped(vm, log_scraper.msg_line_cursor)
            verify_guest_user_session(vm, "termina", expected_username=username)
        finally:
            dbus_mon.stop(raise_errors=(sys.exc_info()[1] is None))

        obs.collect(strict=True)
        if report := obs.format_report(include_verbose=False):
            log("\n" + report)
        report_logged = True
    except Exception as exc:
        failed = True
        if not report_logged:
            try:
                obs.collect(strict=False)
                if report := obs.format_report(include_verbose=True):
                    log("\n" + report)
            except Exception as diag_exc:
                log(f"Failed collecting diagnostics: {diag_exc}")
        _reraise_with_flow_evidence(exc, vm, log_scraper, since_rel_sec=0.0)
    finally:
        if obs is not vm.observer:
            obs.close()
        vm.close_crosh_tab(crosh)
        if not failed:
            vm.set_step("cleanup:vmc_stop_destroy")
            vm.vmc("stop", "termina")
            vm.vmc("destroy", "termina")
    log("=== Flow (`termina`) PASSED ===")
    return FlowResult(terminal_relaunch=relaunch_ev, terminal_relaunches=tuple(tracker.relaunches))
