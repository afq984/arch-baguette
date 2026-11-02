"""Optional modular diagnostics plugin loader and shared context for ChromeOS E2E tests.

Each diagnostic feature lives in its own self-contained submodule under `user_flows.diag`
so individual diagnostic commits can be dropped, cherry-picked, or toggled via `--diag`
without touching shared files or causing merge conflicts.
"""

from __future__ import annotations

import argparse
import dataclasses
import importlib
import importlib.util
import threading
from pathlib import Path
from typing import Any

from user_flows import (
    CompositeDiagnosticsObserver,
    FlowDiagnosticsObserver,
    TimelineEntry,
)

# Ordered so data producers run `collect()` before consumers (`renderer_urls` & `cpuinfo`
# before `resources`; `timeline` host-log scrape before `guest` monotonic clock alignment).
KNOWN_DIAG_MODULES: tuple[str, ...] = (
    "throttle",
    "cpuinfo",
    "renderer_urls",
    "top_procs",
    "resources",
    "timeline",
    "guest",
)


@dataclasses.dataclass
class DiagContext:
    """Shared per-run state across active diagnostic observers."""

    work_dir: Path
    lock: threading.Lock = dataclasses.field(default_factory=threading.Lock)
    vm: Any = None
    owner_hash: str = ""
    username: str = ""
    log_scraper: Any = None
    dbus_mon: Any = None
    t_install_mono: float | None = None
    t_install_vm_epoch: float | None = None
    container_started_rel_sec: float | None = None
    first_host_setup_user_rel: float | None = None
    ui_entries: list[TimelineEntry] = dataclasses.field(default_factory=list)
    dbus_entries: list[TimelineEntry] = dataclasses.field(default_factory=list)
    extra_timeline_entries: list[TimelineEntry] = dataclasses.field(default_factory=list)
    guest_cpu_summary_line: str = ""
    renderer_urls: dict[int, str] = dataclasses.field(default_factory=dict)
    resources_enabled: bool = False
    top_procs_ext: Any = None


class DiagContextRecorder(FlowDiagnosticsObserver):
    """Records shared anchors, UI milestones, and D-Bus signals into `DiagContext`."""

    def __init__(self, ctx: DiagContext) -> None:
        self.ctx = ctx

    def on_vm_started(self, vm: Any) -> None:
        with self.ctx.lock:
            self.ctx.vm = vm

    def on_before_flow(
        self,
        vm: Any,
        *,
        owner_hash: str,
        username: str,
        log_scraper: Any = None,
        dbus_mon: Any = None,
    ) -> None:
        with self.ctx.lock:
            self.ctx.vm = vm
            self.ctx.owner_hash = owner_hash
            self.ctx.username = username
            self.ctx.log_scraper = log_scraper
            self.ctx.dbus_mon = dbus_mon

    def on_install_clicked(
        self, *, username: str, mono_ts: float, vm_epoch_sec: float
    ) -> None:
        detail = f"Clicked Install in chrome://crostini-installer (user={username!r})"
        with self.ctx.lock:
            self.ctx.t_install_mono = mono_ts
            self.ctx.t_install_vm_epoch = vm_epoch_sec
            self.ctx.ui_entries.append(TimelineEntry(0.0, "ui", "InstallClicked", detail))

    def on_ui_event(self, name: str, detail: str, rel_sec: float) -> None:
        with self.ctx.lock:
            self.ctx.ui_entries.append(TimelineEntry(rel_sec, "ui", name, detail))

    def on_dbus_signal(
        self,
        *,
        iface: str,
        member: str,
        vm_name: str,
        detail: str,
        rel_sec: float,
        msg: Any,
    ) -> None:
        del iface, vm_name, msg
        with self.ctx.lock:
            self.ctx.dbus_entries.append(TimelineEntry(rel_sec, "dbus", member, detail))

    def on_readiness_gate_passed(self, rel_sec: float) -> None:
        with self.ctx.lock:
            self.ctx.container_started_rel_sec = rel_sec


def discover_installed_modules() -> dict[str, Any]:
    """Imports all installed submodules from `KNOWN_DIAG_MODULES` in collection order."""
    loaded: dict[str, Any] = {}
    for mod_name in KNOWN_DIAG_MODULES:
        fq_name = f"user_flows.diag.{mod_name}"
        if importlib.util.find_spec(fq_name) is not None:
            loaded[mod_name] = importlib.import_module(fq_name)
    return loaded


def parse_diag_selection(spec: str, installed_names: set[str]) -> set[str]:
    """Parses `--diag` (`all`, `none`, or comma-separated names) against installed plugins."""
    cleaned = spec.strip().lower()
    if cleaned == "all":
        return set(installed_names)
    if cleaned in ("none", "off", ""):
        return set()
    requested = {tok.strip() for tok in cleaned.split(",") if tok.strip()}
    unknown = sorted(requested - installed_names)
    if unknown:
        avail = ", ".join(sorted(installed_names)) or "<none installed>"
        raise ValueError(
            f"Unknown --diag module(s) {unknown!r}; installed diagnostics: {avail}"
        )
    return requested


def register_cli_args(parser: argparse.ArgumentParser) -> None:
    installed = discover_installed_modules()
    avail = ",".join(installed.keys()) if installed else "none"
    parser.add_argument(
        "--diag",
        default="all",
        help=(
            f"Diagnostics plugins to enable: 'all' (default), 'none', or comma-separated "
            f"subset of installed plugins ({avail})"
        ),
    )
    for mod in installed.values():
        reg_fn = getattr(mod, "register_cli_args", None)
        if reg_fn is not None:
            reg_fn(parser)


def build_observer(args: argparse.Namespace, *, work_dir: Path) -> FlowDiagnosticsObserver:
    installed = discover_installed_modules()
    selected = parse_diag_selection(getattr(args, "diag", "all"), set(installed.keys()))
    # Always honor explicit `--qemu-cpu-quota-pct` when `throttle` is installed, even with `--diag none`.
    if "throttle" in installed and getattr(args, "qemu_cpu_quota_pct", None) is not None:
        selected.add("throttle")
    if not selected:
        return FlowDiagnosticsObserver()

    ctx = DiagContext(work_dir=work_dir)
    observers: list[FlowDiagnosticsObserver] = [DiagContextRecorder(ctx)]
    for name, mod in installed.items():
        if name not in selected:
            continue
        obs = mod.create_observer(args, ctx)
        if obs is not None:
            observers.append(obs)
    if len(observers) == 1:
        return FlowDiagnosticsObserver()
    return CompositeDiagnosticsObserver(observers)
