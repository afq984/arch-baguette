"""System-level host and ChromeOS VM resource pressure sampler (CPU, PSI, memory, swap)."""

from __future__ import annotations

import argparse
import base64
import dataclasses
import json
import math
import os
import threading
import time
from pathlib import Path
from typing import Any, Callable, Mapping

from user_flows import FlowDiagnosticsObserver, fmt_rel_t, log
from user_flows.dbus import BackgroundSshStream
from user_flows.diag import DiagContext

CROS_RESOURCE_SAMPLE_INTERVAL_SEC = 15


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
    extra: Any = None


_BASE_REMOTE_PY_HEADER = r"""
import json, os, select, sys, time

PROC = os.environ.get("CROS_RES_PROC_ROOT", "/proc")
NPROC = os.cpu_count() or 1
CLK_TCK = int(os.sysconf("SC_CLK_TCK"))
MEM_KEYS = {"MemTotal", "MemAvailable", "SwapTotal", "SwapFree", "Dirty", "Writeback"}
_last_uptime = None
""".strip()

_NOOP_SCAN_EXTRA_PY = """
def _scan_extra(_uptime_sec: float) -> dict:
    return {}
""".strip()

_BASE_REMOTE_PY_LOOP = r"""
def emit_once() -> None:
    global _last_uptime
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
    extra = _scan_extra(uptime_sec)
    _last_uptime = uptime_sec
    print(json.dumps({
        "nproc": NPROC, "clk_tck": CLK_TCK, "uptime_sec": uptime_sec, "load1": load1,
        "stat_cpu": stat_cpu, "psi": psi, "mem_kib": mem, "extra": extra,
    }), flush=True)

interval = float(sys.argv[2]) if len(sys.argv) > 2 else 15.0
while True:
    emit_once()
    try:
        r, _, _ = select.select([0], [], [], interval)
    except (OSError, ValueError):
        time.sleep(interval)
        continue
    if r and not os.read(0, 64):
        with open(f"{PROC}/uptime", "r", encoding="utf-8") as f:
            now_up = float(f.read().split()[0])
        if _last_uptime is not None and now_up - _last_uptime < 0.05:
            time.sleep(0.05)
        emit_once()
        break
""".strip()


def build_remote_sampler_script(top_procs_ext: Any = None) -> str:
    extra_defs = (
        top_procs_ext.remote_py_defs
        if top_procs_ext is not None
        else _NOOP_SCAN_EXTRA_PY
    )
    return f"{_BASE_REMOTE_PY_HEADER}\n\n{extra_defs}\n\n{_BASE_REMOTE_PY_LOOP}\n"


def build_remote_sampler_loop_cmd(
    *,
    top_procs_ext: Any = None,
    interval_sec: float = CROS_RESOURCE_SAMPLE_INTERVAL_SEC,
) -> str:
    script = build_remote_sampler_script(top_procs_ext)
    b64 = base64.b64encode(script.encode("utf-8")).decode("ascii")
    return (
        f"exec python3 -u -c 'import base64; exec(base64.b64decode(\"{b64}\").decode(\"utf-8\"))' "
        f"--loop {interval_sec}"
    )


def parse_host_runner_info(
    cpuinfo_text: str, meminfo_text: str, nproc: int
) -> HostRunnerInfo:
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


def compute_cpu_delta_pct(
    start: CpuStatCounters, end: CpuStatCounters
) -> CpuDeltaPct:
    dt = end.total_ticks - start.total_ticks
    if dt < 0:
        raise ValueError(
            f"CPU total ticks went backwards: start={start.total_ticks} end={end.total_ticks}"
        )
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
        raise ValueError(
            f"{context}: invalid numeric value in PSI line {raw_line!r}"
        ) from exc
    if total_us < 0 or avg10 < 0.0 or avg60 < 0.0 or avg300 < 0.0:
        raise ValueError(f"{context}: negative value in PSI line {raw_line!r}")
    return kind, PsiMetricLine(avg10=avg10, total_us=total_us)


def _parse_psi_resource(
    lines: list[str], name: str, require_full: bool
) -> PsiResource:
    ctx = f"/proc/pressure/{name}"
    if not lines:
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
    {"nproc", "clk_tck", "uptime_sec", "load1", "stat_cpu", "psi", "mem_kib", "extra"}
)
_REQUIRED_CROS_MEM_KEYS = frozenset(
    {"MemTotal", "MemAvailable", "SwapTotal", "SwapFree", "Dirty", "Writeback"}
)


def require_strict_int(val: Any, name: str) -> int:
    if isinstance(val, bool) or not isinstance(val, int):
        raise ValueError(f"Expected int for {name}, got {val!r}")
    return val


def require_strict_num(val: Any, name: str) -> float:
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
    top_procs_ext: Any = None,
) -> CrosResourceSample:
    """Strictly parses and validates a single JSONL ChromeOS resource sample line."""
    try:
        obj = json.loads(raw_json_line)
    except json.JSONDecodeError as exc:
        raise ValueError(
            f"Malformed JSON in ChromeOS resource sample: {raw_json_line!r}"
        ) from exc
    if not isinstance(obj, dict):
        raise ValueError(
            f"Expected JSON object for ChromeOS resource sample, got {type(obj).__name__}"
        )
    actual_keys = frozenset(obj.keys())
    if actual_keys != _REQUIRED_CROS_RES_KEYS:
        missing = sorted(_REQUIRED_CROS_RES_KEYS - actual_keys)
        extra = sorted(actual_keys - _REQUIRED_CROS_RES_KEYS)
        raise ValueError(
            f"ChromeOS resource sample keys mismatch (missing={missing}, extra={extra}): {raw_json_line!r}"
        )

    nproc = require_strict_int(obj["nproc"], "nproc")
    clk_tck = require_strict_int(obj["clk_tck"], "clk_tck")
    uptime_sec = require_strict_num(obj["uptime_sec"], "uptime_sec")
    load1 = require_strict_num(obj["load1"], "load1")
    if nproc <= 0 or clk_tck <= 0 or uptime_sec <= 0.0 or load1 < 0.0:
        raise ValueError(f"Out-of-range ChromeOS scalar resource fields: {obj!r}")
    if not isinstance(obj["stat_cpu"], str):
        raise ValueError(f"Expected string stat_cpu, got {obj['stat_cpu']!r}")
    cros_cpu = parse_proc_stat_cpu_line(
        obj["stat_cpu"], "ChromeOS /proc/stat", clk_tck=clk_tck
    )

    psi_map = obj["psi"]
    if not isinstance(psi_map, dict) or frozenset(psi_map.keys()) != frozenset(
        {"cpu", "memory", "io"}
    ):
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
    mem_ints = {
        mk: require_strict_int(mv, f"mem_kib.{mk}") for mk, mv in mem_map.items()
    }
    if mem_ints["MemTotal"] <= 0 or any(v < 0 for v in mem_ints.values()):
        raise ValueError(f"Invalid ChromeOS mem_kib values: {mem_ints!r}")

    raw_extra = obj["extra"]
    if not isinstance(raw_extra, dict):
        raise ValueError(f"Expected dict for extra, got {raw_extra!r}")
    parsed_extra = (
        top_procs_ext.parse_extra(raw_extra, clk_tck=clk_tck)
        if top_procs_ext is not None
        else None
    )

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
        extra=parsed_extra,
    )


def select_sample_indices(
    window_samples: list[CrosResourceSample], max_rows: int = 24
) -> list[int]:
    """Selects <= `max_rows` evenly spaced sample indices while preserving first, last, and peak PSI."""
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


def summarize_resource_diagnostics(
    host_info: HostRunnerInfo | None,
    samples: list[CrosResourceSample],
    *,
    guest_cpu_summary_line: str = "",
    renderer_urls: Mapping[int, str] | None = None,
    top_procs_ext: Any = None,
    install_mono: float | None = None,
    installer_closed_rel_sec: float | None = None,
    sampler_warnings: list[str] | None = None,
    strict: bool = True,
) -> tuple[list[str], list[str]]:
    """Computes `(summary_lines, periodic_sample_lines)` in a single pass."""
    warnings = list(sampler_warnings or [])
    if strict:
        if warnings:
            raise RuntimeError(f"Resource diagnostics sampler errors: {warnings}")
        if host_info is None:
            raise RuntimeError("Missing host runner CPU/memory info in strict mode")

    reanchored = [
        dataclasses.replace(
            s, rel_sec=(s.mono_ts - install_mono) if install_mono is not None else s.rel_sec
        )
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

    summary: list[str] = []
    if warnings:
        summary.append("[resource diagnostics warnings]")
        summary.extend(f"  {w}" for w in warnings)

    if len(reanchored) < 2:
        if host_info is not None:
            summary.append(
                f"Host runner: vendor={host_info.vendor_id} model={host_info.model_name!r} "
                f"nproc={host_info.nproc} ram_total={host_info.mem_total_mib / 1024.0:.1f}GiB "
                f"avail={host_info.mem_avail_mib / 1024.0:.1f}GiB (samples={len(reanchored)})"
            )
        if guest_cpu_summary_line:
            summary.append(guest_cpu_summary_line)
        if not reanchored:
            summary.append("ChromeOS VM: <no resource samples collected>")
            return summary, []

    pre_or_at_install = [s for s in reanchored if s.rel_sec <= 0.5]
    s_base = pre_or_at_install[-1] if pre_or_at_install else reanchored[0]
    s_end = reanchored[-1]
    if s_end is s_base and len(reanchored) >= 2:
        s_base, s_end = reanchored[0], reanchored[-1]

    window_samples = [s for s in reanchored if s.mono_ts >= s_base.mono_ts]
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

    if host_info is not None and len(reanchored) >= 2:
        host_min_avail_gib = min(s.host_mem_avail_mib for s in window_samples) / 1024.0
        host_peak_load1 = max(s.host_load1 for s in window_samples)
        summary.append(
            f"Host runner: vendor={host_info.vendor_id} model={host_info.model_name!r} "
            f"nproc={host_info.nproc} ram_total={host_info.mem_total_mib / 1024.0:.1f}GiB "
            f"min_avail={host_min_avail_gib:.1f}GiB load1_peak={host_peak_load1:.2f} "
            f"cpu_busy={host_delta.busy_pct:.1f}% iowait={host_delta.iowait_pct:.1f}% "
            f"steal={host_delta.steal_pct:.2f}% ({host_delta.steal_sec:.2f} cpu-s)"
        )
        if guest_cpu_summary_line:
            summary.append(guest_cpu_summary_line)

    load1_avg = sum(s.load1 for s in window_samples) / len(window_samples)
    load1_peak = max(s.load1 for s in window_samples)
    mem_total_mib = s_end.mem_total_kib / 1024.0
    summary.append(
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
        pk10 = max(
            (m.avg10 for s in window_samples if (m := getter(s)) is not None),
            default=0.0,
        )
        return d_sec, 100.0 * d_sec / span_sec, pk10

    cpu_s_sec, cpu_s_pct, cpu_pk10 = _psi_delta(lambda s: s.psi_cpu.some)
    mem_s_sec, mem_s_pct, mem_s_pk10 = _psi_delta(lambda s: s.psi_memory.some)
    mem_f_sec, mem_f_pct, mem_f_pk10 = _psi_delta(lambda s: s.psi_memory.full)
    io_s_sec, io_s_pct, io_s_pk10 = _psi_delta(lambda s: s.psi_io.some)
    io_f_sec, io_f_pct, io_f_pk10 = _psi_delta(lambda s: s.psi_io.full)
    summary.append(
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
    swap_used_peak_mib = (
        max((s.swap_total_kib - s.swap_free_kib) for s in window_samples) / 1024.0
    )
    swap_growth_mib = max(0.0, swap_used_peak_mib - base_swap_used_mib)
    dirty_peak_mib = (
        max((s.dirty_kib + s.writeback_kib) for s in window_samples) / 1024.0
    )
    summary.append(
        f"ChromeOS mem: avail_min={min_avail_mib:.0f}MiB ({min_avail_pct:.1f}%) "
        f"swap_used_pk={swap_used_peak_mib:.0f}/{swap_total_mib:.0f}MiB "
        f"(+{swap_growth_mib:.0f}MiB) dirty+wb_pk={dirty_peak_mib:.1f}MiB"
    )

    if top_procs_ext is not None:
        summary.extend(
            top_procs_ext.format_summary_lines(
                window_samples,
                installer_closed_rel_sec=installer_closed_rel_sec,
                renderer_urls=renderer_urls,
                strict=strict,
            )
        )

    bottleneck_tags: list[str] = []
    if host_delta.steal_pct >= 5.0 or cros_delta.steal_pct >= 5.0:
        bottleneck_tags.append(
            f"hypervisor/host steal (host={host_delta.steal_pct:.1f}%, guest={cros_delta.steal_pct:.1f}%)"
        )
    if cpu_s_pct >= 10.0 or cros_delta.busy_pct >= 75.0 or load1_peak >= s_end.nproc * 1.25:
        bottleneck_tags.append(
            f"CPU-contention (cros_busy={cros_delta.busy_pct:.1f}%, psi_cpu_some={cpu_s_pct:.1f}%, "
            f"load1_pk={load1_peak:.2f}/{s_end.nproc}vCPU)"
        )
    if io_s_pct >= 10.0 or cros_delta.iowait_pct >= 10.0:
        bottleneck_tags.append(
            f"IO-stall (psi_io_some={io_s_pct:.1f}%, io_full={io_f_pct:.1f}%, iowait={cros_delta.iowait_pct:.1f}%)"
        )
    if mem_s_pct >= 5.0 or swap_growth_mib >= 16.0 or min_avail_pct < 12.0:
        bottleneck_tags.append(
            f"memory/reclaim (psi_mem_some={mem_s_pct:.1f}%, mem_full={mem_f_pct:.1f}%, "
            f"swap_growth=+{swap_growth_mib:.0f}MiB, avail_min={min_avail_mib:.0f}MiB)"
        )
    profile_str = (
        "; ".join(bottleneck_tags)
        if bottleneck_tags
        else "no major CPU/memory/IO stall observed"
    )
    summary.append(f"Observed resource profile: {profile_str}")

    chosen_indices = select_sample_indices(window_samples, max_rows=24)
    sample_rows = [
        f"[periodic samples ({len(chosen_indices)}/{len(window_samples)} shown, relative to Install click)]"
    ]
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
            top_str = (
                top_procs_ext.format_row_suffix(
                    window_samples[prev_idx + 1 : idx + 1], renderer_urls=renderer_urls
                )
                if top_procs_ext is not None
                else ""
            )
        avail_m = cur.mem_avail_kib / 1024.0
        swp_m = (cur.swap_total_kib - cur.swap_free_kib) / 1024.0
        sample_rows.append(
            f"  {fmt_rel_t(cur.rel_sec)}: load1={cur.load1:4.2f} cros_cpu={c_cpu_str} "
            f"psi10(c/m/i)={cur.psi_cpu.some.avg10:.1f}/{cur.psi_memory.some.avg10:.1f}/{cur.psi_io.some.avg10:.1f} "
            f"avail={avail_m:.0f}MiB swap={swp_m:.0f}MiB({dswp_str}) host_stl={h_stl_str}{top_str}"
        )
    return summary, sample_rows


class ResourceDiagnosticsObserver(FlowDiagnosticsObserver):
    """Runs the background 15s JSONL resource sampler over SSH and summarizes system pressure."""

    def __init__(self, ctx: DiagContext) -> None:
        self.ctx = ctx
        self.ctx.resources_enabled = True
        self._lock = threading.Lock()
        self._first_sample_event = threading.Event()
        self._stream: BackgroundSshStream | None = None
        self.host_runner_info: HostRunnerInfo | None = None
        self.samples: list[CrosResourceSample] = []
        self.summary_lines: list[str] = []
        self.sample_lines: list[str] = []

    def _on_line(self, line: str) -> None:
        stripped = line.strip()
        if not stripped:
            return
        now_mono = time.monotonic()
        host_cpu, host_load1, host_mem_avail_mib = read_local_host_dynamic_sample()
        with self.ctx.lock:
            t_inst = self.ctx.t_install_mono
            ext = self.ctx.top_procs_ext
        rel_sec = (now_mono - t_inst) if t_inst is not None else 0.0
        sample = parse_cros_resource_json(
            stripped,
            mono_ts=now_mono,
            rel_sec=rel_sec,
            host_cpu=host_cpu,
            host_load1=host_load1,
            host_mem_avail_mib=host_mem_avail_mib,
            top_procs_ext=ext,
        )
        with self._lock:
            self.samples.append(sample)
        self._first_sample_event.set()

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
        self.host_runner_info = read_local_host_runner_info()
        loop_cmd = build_remote_sampler_loop_cmd(top_procs_ext=self.ctx.top_procs_ext)
        self._stream = BackgroundSshStream(
            "ChromeOS resource sampler",
            [*vm.ssh_base_cmd(), loop_cmd],
            on_line=self._on_line,
            on_fatal=lambda _exc: self._first_sample_event.set(),
            stdin_pipe=True,
        )
        self._stream.start()
        if not self._first_sample_event.wait(timeout=15.0):
            self.check_healthy()
            raise RuntimeError(
                "Timed out waiting for initial ChromeOS resource diagnostics sample "
                f"(returncode={self._stream.poll_rc()}, stderr={self._stream.stderr_text()!r})"
            )
        self.check_healthy()
        log(
            f"  [resources] Periodic ChromeOS resource sampler started "
            f"(host={self.host_runner_info.vendor_id} {self.host_runner_info.model_name}, "
            f"nproc={self.host_runner_info.nproc})."
        )

    def check_healthy(self) -> None:
        if self._stream is not None:
            self._stream.check_healthy()

    def collect(self, *, strict: bool) -> None:
        set_step = getattr(self.ctx.vm, "set_step", lambda _s: None)
        set_step("step5:collect_resources")
        warnings: list[str] = []
        if self._stream is not None:
            if strict:
                self._stream.check_healthy()
            with self._lock:
                prev_count = len(self.samples)
            clean_eof = self._stream.stop_with_stdin_eof(timeout=10.0)
            res_err = self._stream.fatal_error
            self._stream = None
            with self._lock:
                emitted_final = len(self.samples) > prev_count
            if res_err is not None:
                if strict:
                    raise RuntimeError(
                        f"Fatal ChromeOS resource sampler error: {res_err}"
                    ) from res_err
                warnings.append(f"background sampler error: {res_err}")
            elif not clean_eof or not emitted_final:
                msg = (
                    f"ChromeOS resource sampler stdin-EOF final flush incomplete "
                    f"(clean_eof={clean_eof}, emitted_final={emitted_final})"
                )
                if strict:
                    raise RuntimeError(msg)
                warnings.append(msg)

        if self.host_runner_info is None:
            try:
                self.host_runner_info = read_local_host_runner_info()
            except Exception as exc:
                if strict:
                    raise
                warnings.append(f"host runner info read failed: {exc}")

        with self._lock:
            samples_copy = list(self.samples)
        with self.ctx.lock:
            t_inst = self.ctx.t_install_mono
            ic_entries = [
                e for e in self.ctx.ui_entries if e.source == "ui" and e.name == "InstallerClosed"
            ]
            guest_cpu_line = self.ctx.guest_cpu_summary_line
            renderer_urls = dict(self.ctx.renderer_urls)
            ext = self.ctx.top_procs_ext
        ic_rel = ic_entries[0].rel_sec if ic_entries else None

        self.summary_lines, self.sample_lines = summarize_resource_diagnostics(
            self.host_runner_info,
            samples_copy,
            guest_cpu_summary_line=guest_cpu_line,
            renderer_urls=renderer_urls,
            top_procs_ext=ext,
            install_mono=t_inst,
            installer_closed_rel_sec=ic_rel,
            sampler_warnings=warnings,
            strict=strict,
        )

    def format_report(self, *, include_verbose: bool) -> str:
        if not self.summary_lines:
            return ""
        lines = ["=== RUNNER & CHROMEOS RESOURCE DIAGNOSTICS (read-only) ==="]
        lines.extend(f"  {ln}" for ln in self.summary_lines)
        if include_verbose and self.sample_lines:
            lines.extend(f"  {ln}" for ln in self.sample_lines)
        lines.append("==========================================================")
        return "\n".join(lines)

    def close(self) -> None:
        if self._stream is not None:
            self._stream.stop()
            self._stream = None


def create_observer(args: argparse.Namespace, ctx: DiagContext) -> FlowDiagnosticsObserver:
    del args
    return ResourceDiagnosticsObserver(ctx)
