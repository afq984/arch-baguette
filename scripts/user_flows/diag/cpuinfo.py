"""ChromeOS guest `/proc/cpuinfo` ISA and nested SVM/VMX virtualization flag summary."""

from __future__ import annotations

import argparse
import dataclasses
from typing import Any

from user_flows import FlowDiagnosticsObserver
from user_flows.diag import DiagContext

GUEST_ISA_REPORT_FLAGS: tuple[str, ...] = (
    "arch_capabilities",
    "avx",
    "avx2",
    "avx512f",
    "bmi1",
    "bmi2",
    "erms",
    "f16c",
    "fma",
    "fsgsbase",
    "invpcid",
    "pti",
    "xsavec",
    "xsaveopt",
    "xsaves",
)

GUEST_SVM_FEATURE_FLAGS: tuple[str, ...] = (
    "npt",
    "nrip_save",
    "vmcb_clean",
    "flushbyasid",
    "decodeassists",
    "tsc_scale",
    "v_vmsave_vmload",
    "avic",
    "x2avic",
    "vgif",
    "vnmi",
    "lbrv",
    "svm_lock",
    "pausefilter",
)


@dataclasses.dataclass(frozen=True)
class GuestCpuInfo:
    vendor_id: str
    model_name: str
    flags: frozenset[str]
    vmx_flags: frozenset[str] = frozenset()


def parse_guest_cpuinfo(cpuinfo_text: str) -> GuestCpuInfo:
    """Strictly parses ChromeOS guest `/proc/cpuinfo` flags and nested VMX/SVM bits."""
    vendor_id = ""
    model_name = ""
    flags: frozenset[str] | None = None
    vmx_flags: frozenset[str] = frozenset()
    for line in cpuinfo_text.splitlines():
        if not line.strip() and vendor_id and model_name and flags is not None:
            break
        if ":" not in line:
            continue
        k, v = line.split(":", 1)
        key, val = k.strip(), v.strip()
        if key == "vendor_id" and not vendor_id:
            vendor_id = val
        elif key == "model name" and not model_name:
            model_name = val
        elif key == "flags" and flags is None:
            flags = frozenset(tok for tok in val.split() if tok)
        elif key == "vmx flags" and not vmx_flags:
            vmx_flags = frozenset(tok for tok in val.split() if tok)
    if not vendor_id:
        raise ValueError("Missing 'vendor_id' in guest /proc/cpuinfo")
    if not model_name:
        raise ValueError("Missing 'model name' in guest /proc/cpuinfo")
    if not flags:
        raise ValueError("Missing or empty 'flags' in guest /proc/cpuinfo")
    return GuestCpuInfo(
        vendor_id=vendor_id,
        model_name=model_name,
        flags=flags,
        vmx_flags=vmx_flags,
    )


def format_guest_cpuinfo_summary(info: GuestCpuInfo) -> str:
    """Formats ChromeOS guest CPU model, key ISA flags, and SVM/VMX nested virt bits."""
    isa_present = [f for f in GUEST_ISA_REPORT_FLAGS if f in info.flags]
    if "svm" in info.flags:
        svm_bits = [f for f in GUEST_SVM_FEATURE_FLAGS if f in info.flags]
        virt_str = f"svm[{','.join(svm_bits)}]"
    elif "vmx" in info.flags:
        virt_str = f"vmx[{','.join(sorted(info.vmx_flags))}]"
    else:
        virt_str = "none"
    yn = lambda flg: "yes" if flg in info.flags else "no"
    return (
        f"ChromeOS CPU: vendor={info.vendor_id} model={info.model_name!r} "
        f"avx2={yn('avx2')} fma={yn('fma')} xsaveopt={yn('xsaveopt')} "
        f"isa=[{','.join(isa_present)}] virt={virt_str}"
    )


class GuestCpuInfoObserver(FlowDiagnosticsObserver):
    """Reads ChromeOS `/proc/cpuinfo` and shares its formatted summary via `DiagContext`."""

    def __init__(self, ctx: DiagContext) -> None:
        self.ctx = ctx
        self.info: GuestCpuInfo | None = None

    def _read_and_store(self, vm: Any) -> None:
        raw = vm.ssh("cat /proc/cpuinfo", op_desc="cpuinfo_diag:read").stdout
        self.info = parse_guest_cpuinfo(raw)
        summary = format_guest_cpuinfo_summary(self.info)
        with self.ctx.lock:
            self.ctx.guest_cpu_summary_line = summary

    def on_before_flow(
        self,
        vm: Any,
        *,
        owner_hash: str,
        username: str,
        log_scraper: Any = None,
        dbus_mon: Any = None,
    ) -> None:
        del owner_hash, username, log_scraper, dbus_mon
        self._read_and_store(vm)

    def collect(self, *, strict: bool) -> None:
        if self.info is not None:
            return
        if self.ctx.vm is None:
            if strict:
                raise RuntimeError("Missing VM instance for guest /proc/cpuinfo read")
            return
        try:
            self._read_and_store(self.ctx.vm)
        except Exception:
            if strict:
                raise

    def format_report(self, *, include_verbose: bool) -> str:
        del include_verbose
        # When `resources` is active, `resources` prints `guest_cpu_summary_line` inline.
        with self.ctx.lock:
            if self.ctx.resources_enabled or not self.ctx.guest_cpu_summary_line:
                return ""
            return f"=== CHROMEOS CPU SUMMARY ===\n  {self.ctx.guest_cpu_summary_line}\n============================"


def create_observer(args: argparse.Namespace, ctx: DiagContext) -> FlowDiagnosticsObserver:
    del args
    return GuestCpuInfoObserver(ctx)
