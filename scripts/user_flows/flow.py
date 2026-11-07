"""End-to-end ChromeOS Settings Linux installer, Terminal readiness gate, and crosh user flow."""

from __future__ import annotations

import calendar
import dataclasses
import json
import re
import time
from pathlib import Path
from typing import Any

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
TERMINAL_POLL_FLOOR_SEC = 0.5
_TERMINAL_HOME_URL = "chrome-untrusted://terminal/html/terminal.html#home"
_TERMINAL_VMSHELL_URL = "chrome-untrusted://terminal/html/terminal.html?command=vmshell"


@dataclasses.dataclass(frozen=True)
class ReadmeCommands:
    termina_create: str
    termina_reentry_vsh: str


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


def classify_initial_terminal_failure(
    initial_buffer: str,
    entries: list[TimelineEntry],
    *,
    container_started_rel_sec: float,
) -> None:
    """Allowlists the single pre-ContainerStarted slow-runner SetUpVmUser call #2 deadline."""
    cleaned_buf = initial_buffer.strip()
    if cleaned_buf != KNOWN_INITIAL_TERMINAL_TIMEOUT_ERROR:
        raise RuntimeError(
            "Initial Terminal tab failed with an unrecognized or incomplete buffer "
            f"(expected exact {KNOWN_INITIAL_TERMINAL_TIMEOUT_ERROR!r}, got {cleaned_buf!r})"
        )
    installer_closed = [e for e in entries if e.source == "ui" and e.name == "InstallerClosed"]
    if len(installer_closed) != 1:
        raise RuntimeError(f"Expected 1 InstallerClosed entry in timeline, found {len(installer_closed)}")
    ic_rel = installer_closed[0].rel_sec
    call2 = [e for e in entries if e.source == "concierge" and e.name == "SetUpVmUser" and e.detail.startswith("call #2:")]
    if len(call2) != 1 or not (ic_rel <= call2[0].rel_sec < container_started_rel_sec):
        raise RuntimeError(f"Expected pre-ContainerStarted SetUpVmUser call #2 after InstallerClosed, got {call2!r}")
    failed = [
        e
        for e in entries
        if e.source == "concierge"
        and e.name == "SetUpVmUserFailed"
        and e.detail.startswith("call #2 failed after ")
        and "SetUpUser RPC failed: Deadline Exceeded" in e.detail
    ]
    if len(failed) != 1 or any(e.name == "SetUpVmUserInFlight" for e in entries):
        raise RuntimeError(f"Expected settled concierge SetUpVmUserFailed for call #2, got {failed!r}")


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

    Returns the initial `chrome-untrusted://terminal` vmshell CDP target opened by the installer.
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
    return CroshTab(label, CDPConnection.from_target(fresh_tgt, label=label, step_getter=vm.get_step))


def verify_terminal_app_with_readiness_gate(
    vm: ChromeOSVM,
    initial_vmshell_tgt: dict[str, Any],
    username: str,
    tracker: _FlowTracker,
) -> None:
    """Observes installer-opened Terminal gated on `ContainerStarted` and verifies interactive shell."""
    initial_tid = str(initial_vmshell_tgt["id"])
    initial_tab = CroshTab(
        "Terminal-App-Initial",
        CDPConnection.from_target(initial_vmshell_tgt, label="Terminal-App-Initial", step_getter=vm.get_step),
    )
    active_tab: CroshTab | None = initial_tab
    try:
        log("  Observing installer-opened ChromeOS Terminal app window...")
        vm.set_step("step3:observe_terminal_0")
        deadline = time.monotonic() + 120.0
        poll_interval = TERMINAL_POLL_FLOOR_SEC
        reached_prompt = first_logged = False
        last_txt = ""
        while time.monotonic() < deadline:
            tracker.check_healthy()
            txt = last_txt = initial_tab.get_text(max_lines=24)
            if not first_logged and txt.strip():
                first_logged = True
                tracker.record_ui("InitialTerminalFirstOutput", txt.strip().splitlines()[0][:140])
            if f"[{username}@" in txt and txt.rstrip().endswith("$"):
                reached_prompt = True
                break
            if (
                txt.strip() == KNOWN_INITIAL_TERMINAL_TIMEOUT_ERROR
                or "Launching vmshell failed:" in txt
                or "[process exited" in txt
                or "ERROR vsh:" in txt
            ):
                break
            poll_interval = sleep_backoff(poll_interval, 2.5, deadline)

        if reached_prompt:
            vm.set_step("step3:wait_container_started")
            cs_rel = tracker.dbus_mon.wait_for_container_started(timeout=60.0)
            pr_rel = tracker.record_ui("InitialTerminalObserved", f"reached prompt [{username}@penguin]$")
            log(f"  [Terminal-App-Initial] Reached prompt at t+{pr_rel:.1f}s (ContainerStarted at t+{cs_rel:.1f}s).")
        else:
            cs_already = tracker.dbus_mon.is_container_started()
            tracker.record_ui(
                "InitialTerminalObserved",
                f"no prompt (container_started_already={cs_already}): {last_txt.strip().replace(chr(10), ' | ')[:200]}",
            )
            vm.close_crosh_tab(initial_tab)
            active_tab = None
            vm.set_step("step3:wait_container_started")
            cs_rel = tracker.dbus_mon.wait_for_container_started(timeout=300.0)
            tracker.log_scraper.scrape(vm)
            classify_initial_terminal_failure(
                last_txt, tracker.combined_classifier_entries(), container_started_rel_sec=cs_rel
            )
            active_tab = _open_fresh_terminal_from_home(vm, {initial_tid}, tracker)
            _wait_for_new_guest_prompt(active_tab, 0, username, timeout=180.0, desc="fresh Terminal prompt")

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


def run_termina_user_flow(
    vm: ChromeOSVM,
    readme_cmds: ReadmeCommands,
    *,
    username: str = "terminauser",
    observer: FlowDiagnosticsObserver | None = None,
) -> None:
    """Executes the full `termina` + Settings Linux installer + Terminal + `crosh` E2E flow."""
    assert vm.owner_hash
    obs = observer or vm.observer
    log("=== Starting Flow: `termina` VM + ChromeOS Settings UI Installer ===")
    log_scraper = HostLogScraper()
    dbus_mon = DbusSignalMonitor(vm, owner_hash=vm.owner_hash, expected_username=username, observer=obs)
    tracker = _FlowTracker(vm, dbus_mon, log_scraper, obs)

    crosh: CroshTab | None = None
    failed = report_logged = False
    try:
        log_scraper.capture_cursors(vm)
        crosh = vm.open_crosh_tab("Termina-Crosh")
        vm.set_step("step1:vmc_create")
        log("Step 1: Running `vmc create` command from README.md in crosh...")
        crosh.run_crosh_cmd(readme_cmds.termina_create, timeout=180)
        vm.close_crosh_tab(crosh)
        crosh = None

        vm.set_step("step2:start_dbus_monitor")
        log("Step 2: Subscribing system D-Bus monitor & driving ChromeOS Settings UI...")
        dbus_mon.start()
        try:
            obs.on_before_flow(
                vm, owner_hash=vm.owner_hash, username=username, log_scraper=log_scraper, dbus_mon=dbus_mon
            )
            initial_vmshell_tgt = run_settings_crostini_installer_ui(vm, username=username, tracker=tracker)

            log("Step 3: Verifying ChromeOS Terminal app (`chrome-untrusted://terminal`) gated on `ContainerStarted`...")
            verify_terminal_app_with_readiness_gate(
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
            log("Step 5: Verifying D-Bus signal sequence and in-guest user/garcon state...")
            dbus_mon.verify_required_signal_sequence()
            verify_guest_user_session(vm, "termina", expected_username=username)
        finally:
            dbus_mon.stop()

        obs.collect(strict=True)
        if report := obs.format_report(include_verbose=False):
            log("\n" + report)
        report_logged = True
    except Exception:
        failed = True
        if not report_logged:
            try:
                obs.collect(strict=False)
                if report := obs.format_report(include_verbose=True):
                    log("\n" + report)
            except Exception as diag_exc:
                log(f"Failed collecting diagnostics: {diag_exc}")
        raise
    finally:
        if obs is not vm.observer:
            obs.close()
        vm.close_crosh_tab(crosh)
        if not failed:
            vm.set_step("cleanup:vmc_stop_destroy")
            vm.vmc("stop", "termina")
            vm.vmc("destroy", "termina")
    log("=== Flow (`termina`) PASSED ===")
