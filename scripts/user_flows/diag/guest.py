"""In-guest systemd unit timing and monotonic journal diagnostics collector."""

from __future__ import annotations

import argparse
import json
import re
import shlex
from typing import Any

from user_flows import FlowDiagnosticsObserver, TimelineEntry, fmt_rel_t
from user_flows.diag import DiagContext

# Single source of truth for guest systemd units queried via `journalctl`, `systemctl show`,
# and validated in strict mode.
EXPECTED_GUEST_UNITS: tuple[str, ...] = (
    "first-boot-cros.service",
    "maitred.service",
    "vshd.service",
    "systemd-logind.service",
    "ldconfig.service",
    "user-runtime-dir@1000.service",
    "user@1000.service",
)

GUEST_SYSLOG_IDENTIFIERS: tuple[str, ...] = (
    "first-boot-cros",
    "maitred",
    "useradd",
    "usermod",
    "garcon",
    "sommelier",
    "vshd",
)

# On constrained 4-vCPU nested-KVM CI runners, `vsh` session startup alone can take ~22s;
# 120s leaves 4-5x headroom for `vsh` startup plus systemd/journal queries.
GUEST_DIAG_TIMEOUT_SEC = 120


def parse_guest_diagnostics(
    raw_out: str,
    *,
    first_host_setup_user_rel: float | None = None,
    t_install_vm_epoch: float | None = None,
    strict: bool = True,
    include_verbose: bool = False,
) -> tuple[list[str], list[str], list[TimelineEntry]]:
    """Parses delimited `===GUEST_*===` output into summary lines, verbose lines, and timeline entries."""
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
                raise ValueError(
                    f"Guest journal JSON entry missing __MONOTONIC_TIMESTAMP: {obj!r}"
                )
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
        and t_install_vm_epoch is not None
    ):
        guest_boot_rel_sec = (guest_epoch_sec - guest_uptime_sec) - t_install_vm_epoch

    summary_lines: list[str] = []
    verbose_lines: list[str] = []
    timeline_entries: list[TimelineEntry] = []

    job_lines = [ln.strip() for ln in sections.get("GUEST_LIST_JOBS", []) if ln.strip()]
    if strict and not job_lines:
        raise RuntimeError("Guest diagnostics section 'GUEST_LIST_JOBS' is missing or empty")
    if job_lines:
        summary_lines.append("[systemctl list-jobs (system)]")
        summary_lines.extend(f"  {jln}" for jln in job_lines[:20])

    unit_show_raw = "\n".join(sections.get("GUEST_SYSTEMD_UNIT_SHOW", [])).strip()
    if strict and not unit_show_raw:
        raise RuntimeError(
            "Guest diagnostics section 'GUEST_SYSTEMD_UNIT_SHOW' is missing or empty"
        )
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
        summary_lines.append("[systemd unit monotonic timing (systemctl show)]")
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
                timeline_entries.append(
                    TimelineEntry(
                        h_start,
                        "guest",
                        f"UnitStart({unit_id})",
                        f"(guest+{start_s:.2f}s) systemctl show start ({act_state}/{sub_state})",
                    )
                )
                if end_us >= start_us and end_us > 0:
                    h_end = guest_boot_rel_sec + end_s
                    host_window = (
                        f" host={fmt_rel_t(h_start).strip()}..{fmt_rel_t(h_end).strip()}"
                    )
                    if exec_exit_us > 0:
                        timeline_entries.append(
                            TimelineEntry(
                                h_end,
                                "guest",
                                f"UnitDone({unit_id})",
                                f"(guest+{end_s:.2f}s) systemctl show exit dur={dur_str}{act_dur_extra} "
                                f"result={result} status={exec_status}",
                            )
                        )
                else:
                    host_window = f" host={fmt_rel_t(h_start).strip()}..(running)"
            summary_lines.append(
                f"  {unit_id}: state={act_state}/{sub_state} result={result} "
                f"guest=+{start_s:.3f}s..+{end_s:.3f}s (dur={dur_str}{act_dur_extra}, exit_status={exec_status})"
                f"{host_window}"
            )
    if strict:
        missing_units = sorted(set(EXPECTED_GUEST_UNITS) - seen_units)
        if missing_units:
            raise RuntimeError(
                f"GUEST_SYSTEMD_UNIT_SHOW missing expected systemd units: {missing_units!r}"
            )

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
        dest = verbose_lines if verbose_only else summary_lines
        if not sec_lines:
            if strict:
                raise RuntimeError(
                    f"Guest diagnostics section {key!r} ({label}) is missing or empty"
                )
            dest.append(f"[{label}]: <empty or unavailable>")
            continue
        dest.append(f"[{label}]")
        dest.extend(f"  {ln}" for ln in sec_lines[:max_lines])

    if include_verbose and parsed_json:
        verbose_lines.append("[journalctl -b (monotonic, filtered)]")
        for obj, mono_us, _rt_us in parsed_json[:140]:
            ident_label = str(obj.get("SYSLOG_IDENTIFIER") or obj.get("_COMM") or "guest")
            verbose_lines.append(
                f"  [{mono_us / 1_000_000.0:10.6f}] {ident_label}: {obj.get('MESSAGE', '')}"
            )

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
        elif rt_us and t_install_vm_epoch is not None:
            rel = (rt_us / 1_000_000.0) - t_install_vm_epoch
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
        elif "maitred" in ident and any(
            w in msg.lower() for w in ("failed", "error", "linger")
        ):
            ev_name = "MaitredLog"
        elif "still waiting for /dev/.container_token" in msg:
            ev_name = "SommelierWaitToken"
        elif "sommelier" in msg.lower() and any(
            w in msg.lower()
            for w in ("timed out", "failed", "scheduled restart", "main process exited")
        ):
            ev_name = "SommelierIssue"
        elif "garcon" in ident and "systemd" not in ident:
            ev_name, ev_detail = "GarconLog", tag + msg[:140]
        elif "vshd" in ident and "systemd" not in ident:
            ev_name, ev_detail = "GuestVshd", tag + msg[:140]

        if ev_name is not None:
            timeline_entries.append(TimelineEntry(rel, "guest", ev_name, ev_detail))

    return summary_lines, verbose_lines, timeline_entries


def build_guest_diag_commands(username: str, *, strict: bool) -> list[tuple[str, int, str]]:
    """Builds the remote `vsh` command list (1 fast call on strict pass, 2 split calls on failure)."""
    shell_flags = "set -euo pipefail; " if strict else "set -uo pipefail; "
    q_user = shlex.quote(username or "terminauser")
    id_check_cmd = f"id {q_user} 2>&1; " if strict else f"id {q_user} 2>&1 || true; "
    units_str = " ".join(EXPECTED_GUEST_UNITS)
    journal_unit_flags = " ".join(f"-u {u}" for u in EXPECTED_GUEST_UNITS)
    journal_ident_flags = " ".join(
        f"SYSLOG_IDENTIFIER={ident}" for ident in GUEST_SYSLOG_IDENTIFIERS
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
        f"-p ExecMainStatus {units_str}; "
        'echo "===GUEST_ANALYZE==="; '
        "systemd-analyze --no-pager 2>&1; "
        'echo "===GUEST_BLAME==="; '
        "systemd-analyze blame --no-pager 2>&1 | sed -n '1,8p'; "
    )
    journal_sh = (
        'echo "===GUEST_JOURNAL_JSON==="; '
        f"journalctl -b -o json --output-fields={journal_fields} --no-pager "
        f"{journal_unit_flags} {journal_ident_flags} | sed -n '1,400p'"
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
    if strict:
        return [
            (
                "guest_diag:summary",
                GUEST_DIAG_TIMEOUT_SEC,
                shell_flags
                + sys_summary_sh
                + f"{user_env_prefix}bash -c {shlex.quote(user_summary_inner)}; "
                + journal_sh,
            )
        ]

    user_verbose_inner = (
        f"{user_summary_inner}; "
        'echo "===GUEST_USER_CRITICAL_CHAIN==="; '
        "systemd-analyze --user critical-chain --no-pager 2>&1; "
        'echo "===GUEST_GARCON_STATUS==="; '
        "systemctl --user status cros-garcon.service "
        "sommelier@0.service sommelier-x@0.service sommelier@1.service sommelier-x@1.service --no-pager 2>&1"
    )
    return [
        (
            "guest_diag:system",
            GUEST_DIAG_TIMEOUT_SEC,
            shell_flags
            + sys_summary_sh
            + 'echo "===GUEST_CRITICAL_CHAIN==="; '
            + "systemd-analyze critical-chain --no-pager 2>&1; "
            + journal_sh,
        ),
        (
            "guest_diag:user",
            GUEST_DIAG_TIMEOUT_SEC,
            f"{user_env_prefix}bash -c {shlex.quote(user_verbose_inner)}",
        ),
    ]


class GuestDiagnosticsObserver(FlowDiagnosticsObserver):
    """Collects read-only guest systemd unit timings and journal milestones over `vsh`."""

    def __init__(self, ctx: DiagContext) -> None:
        self.ctx = ctx
        self.summary_lines: list[str] = []
        self.verbose_lines: list[str] = []

    def collect(self, *, strict: bool) -> None:
        vm = self.ctx.vm
        if vm is None:
            if strict:
                raise RuntimeError("Missing VM instance for guest diagnostics")
            return
        vm.set_step("step5:collect_guest_diag")
        steps = build_guest_diag_commands(self.ctx.username, strict=strict)
        combined_chunks: list[str] = []
        step_errors: list[str] = []
        for step_name, step_timeout, remote_sh in steps:
            if strict:
                res = vm.vsh(
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
                    res = vm.vsh(
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

        with self.ctx.lock:
            first_host_rel = self.ctx.first_host_setup_user_rel
            t_inst_epoch = self.ctx.t_install_vm_epoch

        summary, verbose, guest_entries = parse_guest_diagnostics(
            "\n".join(combined_chunks),
            first_host_setup_user_rel=first_host_rel,
            t_install_vm_epoch=t_inst_epoch,
            strict=strict,
            include_verbose=not strict,
        )
        self.summary_lines = []
        if step_errors:
            self.summary_lines.append("[guest diagnostic step warnings]")
            self.summary_lines.extend(f"  {se}" for se in step_errors)
        self.summary_lines.extend(summary)
        self.verbose_lines = verbose
        with self.ctx.lock:
            self.ctx.extra_timeline_entries.extend(guest_entries)

    def format_report(self, *, include_verbose: bool) -> str:
        if not self.summary_lines and not (include_verbose and self.verbose_lines):
            return ""
        lines = ["=== GUEST BOOT & SERVICE TIMING SUMMARY (read-only) ==="]
        lines.extend(f"  {ln}" for ln in self.summary_lines)
        if include_verbose and self.verbose_lines:
            lines.extend(f"  {ln}" for ln in self.verbose_lines)
        lines.append("=======================================================")
        return "\n".join(lines)


def create_observer(args: argparse.Namespace, ctx: DiagContext) -> FlowDiagnosticsObserver:
    del args
    return GuestDiagnosticsObserver(ctx)
