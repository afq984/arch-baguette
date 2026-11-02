"""Initialization timeline, read-only D-Bus state snapshot, and Chrome UMA histogram collector."""

from __future__ import annotations

import argparse
from typing import Any, Callable

from user_flows import FlowDiagnosticsObserver, TimelineEntry, fmt_rel_t
from user_flows.dbus import (
    load_cros_protos,
    require_enum_name,
    require_non_empty_str,
)
from user_flows.diag import DiagContext

MONITORED_UMA_HISTOGRAMS: tuple[str, ...] = (
    "Crostini.BaguetteReadyWait",
    "Crostini.TimeToInstallSuccess",
    "Crostini.SetupResult",
    "Crostini.RestarterResult.Installer",
)


def _run_step(
    strict: bool, err_sink: list[str], label: str, fn: Callable[[], None]
) -> None:
    if strict:
        fn()
        return
    try:
        fn()
    except Exception as exc:
        err_sink.append(f"{label}: {exc}")


class TimelineDiagnosticsObserver(FlowDiagnosticsObserver):
    """Collects unified timeline entries, read-only D-Bus state, and Crostini UMA histograms."""

    def __init__(self, ctx: DiagContext) -> None:
        self.ctx = ctx
        self.readonly_summary_lines: list[str] = []
        self.host_log_entries: list[TimelineEntry] = []
        self.messages_excerpt: str = ""
        self.chrome_excerpt: str = ""

    def _collect_readonly_dbus(self, *, strict: bool) -> None:
        vm = self.ctx.vm
        if vm is None:
            if strict:
                raise RuntimeError("Missing VM instance for read-only D-Bus snapshot")
            return
        protos = (
            self.ctx.dbus_mon.protos
            if self.ctx.dbus_mon is not None
            else load_cros_protos()
        )
        conc = protos.concierge_pb2
        cic = protos.cicerone_pb2
        owner_hash = self.ctx.owner_hash

        def _query_get_vm_info() -> None:
            ctx_vm = "VmConcierge.GetVmInfo"
            vm_resp, raw_vm = vm.dbus_call_proto(
                "org.chromium.VmConcierge",
                "GetVmInfo",
                conc.GetVmInfoRequest(name="termina", owner_id=owner_hash),
                conc.GetVmInfoResponse,
            )
            if not vm_resp.success:
                if strict:
                    raise RuntimeError(f"{ctx_vm} returned success=false (hex={raw_vm.hex()})")
                self.readonly_summary_lines.append(
                    f"VmConcierge.GetVmInfo(termina): success={vm_resp.success}"
                )
                return
            vm_type = require_enum_name(
                conc.VmInfo.VmType, vm_resp.vm_info.vm_type, "vm_info.vm_type", ctx_vm, raw_vm
            )
            vm_status = require_enum_name(
                conc.VmStatus, vm_resp.vm_info.status, "vm_info.status", ctx_vm, raw_vm
            )
            if vm_resp.vm_info.pid <= 0 or vm_resp.vm_info.cid <= 0:
                raise ValueError(
                    f"{ctx_vm}: invalid pid={vm_resp.vm_info.pid} cid={vm_resp.vm_info.cid}"
                )
            self.readonly_summary_lines.append(
                f"VmConcierge.GetVmInfo(termina): success={vm_resp.success} "
                f"status={vm_status}({vm_resp.vm_info.status}) "
                f"vm_type={vm_type}({vm_resp.vm_info.vm_type}) "
                f"cid={vm_resp.vm_info.cid} pid={vm_resp.vm_info.pid}"
            )

        def _query_list_vms() -> None:
            ctx_lv = "VmConcierge.ListVms"
            lv_resp, raw_lv = vm.dbus_call_proto(
                "org.chromium.VmConcierge",
                "ListVms",
                conc.ListVmsRequest(owner_id=owner_hash),
                conc.ListVmsResponse,
            )
            if not lv_resp.success and strict:
                raise RuntimeError(
                    f"{ctx_lv} returned success=false: {lv_resp.failure_reason!r} (hex={raw_lv.hex()})"
                )
            vm_names = [
                require_non_empty_str(entry.name, "vms[].name", ctx_lv, raw_lv)
                for entry in lv_resp.vms
            ]
            if strict and "termina" not in vm_names:
                raise RuntimeError(
                    f"{ctx_lv}: expected 'termina' in running VMs, got {vm_names!r}"
                )
            self.readonly_summary_lines.append(
                f"VmConcierge.ListVms: success={lv_resp.success} vms={vm_names}"
            )

        def _query_list_containers() -> None:
            ctx_lc = "VmCicerone.ListRunningContainers"
            lc_resp, raw_lc = vm.dbus_call_proto(
                "org.chromium.VmCicerone",
                "ListRunningContainers",
                cic.ListRunningContainersRequest(owner_id=owner_hash),
                cic.ListRunningContainersResponse,
            )
            containers = [
                f"{require_non_empty_str(c.vm_name, 'containers[].vm_name', ctx_lc, raw_lc)}/"
                f"{require_non_empty_str(c.container_name, 'containers[].container_name', ctx_lc, raw_lc)}"
                for c in lc_resp.containers
            ]
            if strict and "termina/penguin" not in containers:
                raise RuntimeError(
                    f"{ctx_lc}: expected 'termina/penguin' in running containers, got {containers!r}"
                )
            self.readonly_summary_lines.append(
                f"VmCicerone.ListRunningContainers: {containers}"
            )

        def _query_garcon_info() -> None:
            if self.ctx.dbus_mon is not None:
                garcon_info = self.ctx.dbus_mon.query_garcon_session_info()
            else:
                req = cic.GetGarconSessionInfoRequest(
                    vm_name="termina", container_name="penguin", owner_id=owner_hash
                )
                garcon_info, raw_g = vm.dbus_call_proto(
                    "org.chromium.VmCicerone",
                    "GetGarconSessionInfo",
                    req,
                    cic.GetGarconSessionInfoResponse,
                )
                require_enum_name(
                    cic.GetGarconSessionInfoResponse.Status,
                    garcon_info.status,
                    "status",
                    "VmCicerone.GetGarconSessionInfo",
                    raw_g,
                )
            status_name = cic.GetGarconSessionInfoResponse.Status.Name(garcon_info.status)
            if strict and garcon_info.status != cic.GetGarconSessionInfoResponse.Status.SUCCEEDED:
                raise RuntimeError(
                    f"VmCicerone.GetGarconSessionInfo(termina/penguin) status={status_name}"
                )
            self.readonly_summary_lines.append(
                f"VmCicerone.GetGarconSessionInfo(termina/penguin): "
                f"status={status_name}({garcon_info.status}) "
                f"user={garcon_info.container_username!r} homedir={garcon_info.container_homedir!r}"
            )

        for query_fn in (
            _query_get_vm_info,
            _query_list_vms,
            _query_list_containers,
            _query_garcon_info,
        ):
            _run_step(strict, self.readonly_summary_lines, "Read-only D-Bus query error", query_fn)

    def _collect_uma_histograms(self, *, strict: bool) -> None:
        vm = self.ctx.vm
        if vm is None:
            if strict:
                raise RuntimeError("Missing VM instance for UMA histogram query")
            return
        b_conn = vm.connect_browser_cdp(label="Browser-UMA")
        try:
            for h_name in MONITORED_UMA_HISTOGRAMS:

                def _fetch_one(name: str = h_name) -> None:
                    h_res = b_conn.call(
                        "Browser.getHistogram",
                        {"name": name},
                        allow_error=not strict,
                        op_desc=f"UMA:getHistogram({name})",
                    )
                    if "error" in h_res:
                        err_msg = h_res["error"].get("message", h_res["error"])
                        self.readonly_summary_lines.append(
                            f"UMA {name}: <not recorded ({err_msg})>"
                        )
                        return
                    hist = h_res.get("histogram")
                    if not isinstance(hist, dict) or not hist:
                        if strict:
                            raise RuntimeError(
                                f"Browser.getHistogram({name!r}) returned empty result: {h_res!r}"
                            )
                        self.readonly_summary_lines.append(f"UMA {name}: <not recorded>")
                        return
                    buckets = [
                        f"[{b['low']}..{b['high']}):{b['count']}"
                        for b in hist.get("buckets", [])
                    ]
                    self.readonly_summary_lines.append(
                        f"UMA {name}: count={hist.get('count')} sum={hist.get('sum')} buckets={buckets}"
                    )

                _run_step(
                    strict,
                    self.readonly_summary_lines,
                    f"UMA {h_name} query error",
                    _fetch_one,
                )
        finally:
            b_conn.close()

    def _collect_host_logs(self) -> None:
        scraper = self.ctx.log_scraper
        vm = self.ctx.vm
        if scraper is None or vm is None:
            return
        entries = scraper.scrape(vm)
        self.host_log_entries = list(entries)
        self.messages_excerpt = scraper.messages_excerpt
        self.chrome_excerpt = scraper.chrome_excerpt
        with self.ctx.lock:
            self.ctx.first_host_setup_user_rel = scraper.first_host_setup_user_rel

    def collect(self, *, strict: bool) -> None:
        self.readonly_summary_lines.clear()
        with self.ctx.lock:
            ic_entries = [
                e for e in self.ctx.ui_entries if e.source == "ui" and e.name == "InstallerClosed"
            ]
            cs_rel = self.ctx.container_started_rel_sec
        if ic_entries and cs_rel is not None:
            ic_rel = ic_entries[0].rel_sec
            self.readonly_summary_lines.append(
                f"InstallerClosed vs ContainerStarted: installer_closed={fmt_rel_t(ic_rel).strip()} "
                f"container_started={fmt_rel_t(cs_rel).strip()} "
                f"(installer_closed_before_container_started={ic_rel < cs_rel})"
            )

        set_step = getattr(self.ctx.vm, "set_step", lambda _s: None)
        set_step("step5:collect_readonly_dbus")
        _run_step(
            strict,
            self.readonly_summary_lines,
            "Read-only D-Bus snapshot error",
            lambda: self._collect_readonly_dbus(strict=strict),
        )
        set_step("step5:collect_uma_histograms")
        _run_step(
            strict,
            self.readonly_summary_lines,
            "UMA histogram query error",
            lambda: self._collect_uma_histograms(strict=strict),
        )
        set_step("step5:collect_host_logs")
        _run_step(
            strict,
            self.readonly_summary_lines,
            "Host log scrape error",
            self._collect_host_logs,
        )

    def format_report(self, *, include_verbose: bool) -> str:
        with self.ctx.lock:
            combined = (
                list(self.ctx.ui_entries)
                + list(self.ctx.dbus_entries)
                + list(self.host_log_entries)
                + list(self.ctx.extra_timeline_entries)
            )
        sorted_entries = sorted(combined, key=lambda e: e.rel_sec)
        lines = ["=== INITIALIZATION TIMELINE (relative to Install click) ==="]
        for entry in sorted_entries:
            lines.append(
                f"  {fmt_rel_t(entry.rel_sec)}  [{entry.source:<9}] {entry.name}: {entry.detail}"
            )
        lines.append("  --- Read-Only D-Bus & UMA Snapshot ---")
        lines.extend(f"  {s_line}" for s_line in self.readonly_summary_lines)
        if include_verbose:
            if self.messages_excerpt:
                lines.append("  --- /var/log/messages excerpt ---")
                lines.extend(
                    f"    {m_line}" for m_line in self.messages_excerpt.splitlines()[-40:]
                )
            if self.chrome_excerpt:
                lines.append("  --- /var/log/chrome/chrome excerpt ---")
                lines.extend(
                    f"    {c_line}" for c_line in self.chrome_excerpt.splitlines()[-30:]
                )
        lines.append("===========================================================")
        return "\n".join(lines)


def create_observer(args: argparse.Namespace, ctx: DiagContext) -> FlowDiagnosticsObserver:
    del args
    return TimelineDiagnosticsObserver(ctx)
