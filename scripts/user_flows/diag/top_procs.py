"""Per-process ChromeOS `/proc/<pid>/stat` top-CPU extension and sampler CPU budget guard."""

from __future__ import annotations

import argparse
import dataclasses
import math
from typing import Any, Mapping, Sequence

from user_flows import FlowDiagnosticsObserver, fmt_rel_t
from user_flows.diag import DiagContext

# In-VM sampler CPU ceiling (% of 1 vCPU across sampled intervals) to catch any `/proc` scan regression.
CROS_SAMPLER_MAX_CPU_PCT = 3.0
SAMPLER_INTERVAL_SEC = 15
MAX_CROS_TOP_PROCS = 5

_REQUIRED_EXTRA_KEYS = frozenset({"proc_dt_sec", "sampler_ticks", "top_procs"})
_REQUIRED_TOP_PROC_KEYS = frozenset({"pid", "comm", "hint", "ticks"})


@dataclasses.dataclass(frozen=True)
class CrosTopProc:
    pid: int
    comm: str
    hint: str
    ticks: int


@dataclasses.dataclass(frozen=True)
class TopProcsSampleExtra:
    proc_dt_sec: float
    sampler_ticks: int
    top_procs: tuple[CrosTopProc, ...]


REMOTE_TOP_PROCS_PY_DEFS = r"""
SELF_PID = os.getpid()
_prev_uptime = None
_prev_procs = None
_meta_cache = {}

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
    return False, _clean(" ".join(args[1:3]), 48), _clean(arg0, 48)

def _scan_extra(uptime_sec: float) -> dict:
    global _prev_uptime, _prev_procs, _meta_cache
    has_prev = (
        _prev_procs is not None
        and _prev_uptime is not None
        and uptime_sec > _prev_uptime
    )
    dt_sec = max(1e-4, round(uptime_sec - _prev_uptime, 4)) if has_prev else 0.0
    new_floor = max(0, int(_prev_uptime * CLK_TCK) - CLK_TCK) if has_prev else 0
    cur_procs = {}
    cands, c_subs, c_ticks, c_cnt = [], {}, 0, 0
    sampler_ticks = 0
    for ent in os.listdir(PROC):
        if not ent.isdigit():
            continue
        pid = int(ent)
        try:
            fd = os.open(f"{PROC}/{ent}/stat", os.O_RDONLY)
            try:
                raw = os.read(fd, 1024)
            finally:
                os.close(fd)
            rp = raw.rfind(b") ")
            if rp < 0:
                continue
            rest = raw[rp + 2 :].split(None, 20)
            ticks = int(rest[11]) + int(rest[12])
            st = int(rest[19])
        except (OSError, ValueError, IndexError):
            continue
        cur_procs[pid] = (st, ticks)
        if not has_prev:
            continue
        prev = _prev_procs.get(pid)
        dt = (ticks - prev[1]) if (prev is not None and prev[0] == st) else (ticks if st >= new_floor else 0)
        if pid == SELF_PID and dt > 0:
            sampler_ticks = dt
        if dt <= 0:
            continue
        meta = _meta_cache.get(pid)
        if meta is None or meta[0] != st:
            lp = raw.find(b"(")
            comm = (_clean(raw[lp + 1 : rp].decode("utf-8", "replace"), 48) if lp >= 0 else "") or "?"
            if pid == SELF_PID:
                is_c, hint = False, "cros_res_sampler"
            else:
                try:
                    cfd = os.open(f"{PROC}/{ent}/cmdline", os.O_RDONLY)
                    try:
                        raw_cl = os.read(cfd, 4096)
                    finally:
                        os.close(cfd)
                except OSError:
                    raw_cl = b""
                is_c, cl_hint, arg0 = _parse_cl(pid, raw_cl)
                hint = cl_hint or (arg0 if arg0 != comm else "")
            meta = _meta_cache[pid] = (st, comm, is_c, hint)
        _, comm, is_c, hint = meta
        if is_c or comm.startswith("crosvm"):
            c_ticks += dt
            c_cnt += 1
            sub = comm if comm != "crosvm" else (hint or "crosvm")
            c_subs[sub] = c_subs.get(sub, 0) + dt
        else:
            cands.append((dt, pid, comm, hint))
    if _meta_cache:
        _meta_cache = {
            p: m for p, m in _meta_cache.items() if p in cur_procs and cur_procs[p][0] == m[0]
        }
    _prev_procs, _prev_uptime = cur_procs, uptime_sec
    if not has_prev:
        return {"proc_dt_sec": 0.0, "sampler_ticks": 0, "top_procs": []}
    if c_ticks > 0:
        subs = ",".join(k for k, _ in sorted(c_subs.items(), key=lambda kv: (-kv[1], kv[0]))[:3])
        cands.append((c_ticks, 0, "crosvm", _clean(f"{c_cnt}p:{subs}" if subs else f"{c_cnt}p", 48)))
    cands.sort(key=lambda r: (-r[0], r[2], r[1]))
    return {
        "proc_dt_sec": dt_sec,
        "sampler_ticks": sampler_ticks,
        "top_procs": [{"pid": p, "comm": c, "hint": h, "ticks": t} for t, p, c, h in cands[:5]],
    }
""".strip()


def _req_int(val: Any, name: str) -> int:
    if isinstance(val, bool) or not isinstance(val, int):
        raise ValueError(f"Expected int for {name}, got {val!r}")
    return val


def _req_num(val: Any, name: str) -> float:
    if isinstance(val, bool) or not isinstance(val, (int, float)) or not math.isfinite(val):
        raise ValueError(f"Expected finite float/int for {name}, got {val!r}")
    return float(val)


def parse_top_procs_extra(raw_extra: dict[str, Any]) -> TopProcsSampleExtra:
    """Strictly validates the `extra` dict emitted by `REMOTE_TOP_PROCS_PY_DEFS`."""
    if frozenset(raw_extra.keys()) != _REQUIRED_EXTRA_KEYS:
        raise ValueError(f"Unexpected top_procs extra keys: {raw_extra!r}")
    proc_dt_sec = _req_num(raw_extra["proc_dt_sec"], "proc_dt_sec")
    sampler_ticks = _req_int(raw_extra["sampler_ticks"], "sampler_ticks")
    if proc_dt_sec < 0.0 or sampler_ticks < 0:
        raise ValueError(f"Negative proc_dt_sec or sampler_ticks: {raw_extra!r}")
    if proc_dt_sec == 0.0 and sampler_ticks != 0:
        raise ValueError(
            f"Expected sampler_ticks == 0 when proc_dt_sec == 0.0, got {sampler_ticks!r}"
        )
    raw_top = raw_extra["top_procs"]
    if not isinstance(raw_top, list) or len(raw_top) > MAX_CROS_TOP_PROCS:
        raise ValueError(
            f"Expected top_procs list of <={MAX_CROS_TOP_PROCS} entries, got {raw_top!r}"
        )
    if proc_dt_sec == 0.0 and raw_top:
        raise ValueError(f"Expected empty top_procs when proc_dt_sec == 0.0, got {raw_top!r}")

    top_procs: list[CrosTopProc] = []
    seen_crosvm = False
    for idx, item in enumerate(raw_top):
        if not isinstance(item, dict) or frozenset(item.keys()) != _REQUIRED_TOP_PROC_KEYS:
            raise ValueError(f"Invalid top_procs[{idx}] object: {item!r}")
        pid = _req_int(item["pid"], f"top_procs[{idx}].pid")
        ticks = _req_int(item["ticks"], f"top_procs[{idx}].ticks")
        comm, hint = item["comm"], item["hint"]
        if (
            pid < 0
            or ticks <= 0
            or not isinstance(comm, str)
            or not (1 <= len(comm) <= 64)
            or not isinstance(hint, str)
            or len(hint) > 64
        ):
            raise ValueError(f"Invalid field values in top_procs[{idx}]: {item!r}")
        if pid == 0 and comm != "crosvm":
            raise ValueError(f"pid=0 reserved for grouped crosvm entry, got {item!r}")
        if comm == "crosvm":
            if pid != 0 or seen_crosvm:
                raise ValueError(
                    f"Unaggregated or duplicate crosvm entry in top_procs: {raw_top!r}"
                )
            seen_crosvm = True
        top_procs.append(CrosTopProc(pid=pid, comm=comm, hint=hint, ticks=ticks))

    return TopProcsSampleExtra(
        proc_dt_sec=proc_dt_sec,
        sampler_ticks=sampler_ticks,
        top_procs=tuple(top_procs),
    )


def format_top_procs(
    intervals: Sequence[Any],
    *,
    limit: int = MAX_CROS_TOP_PROCS,
    pct_only: bool = False,
    renderer_urls: Mapping[int, str] | None = None,
) -> tuple[float, list[str]]:
    valid = [
        s
        for s in intervals
        if isinstance(getattr(s, "extra", None), TopProcsSampleExtra)
        and s.extra.proc_dt_sec > 0.0
    ]
    total_dt = sum(s.extra.proc_dt_sec for s in valid)
    if total_dt <= 0.0:
        return 0.0, []
    crosvm_sec = 0.0
    crosvm_peak_p = 0
    crosvm_subs: dict[str, float] = {}
    by_proc: dict[tuple[str, str], float] = {}
    proc_pids: dict[tuple[str, str], set[int]] = {}
    for s in valid:
        tck = float(s.clk_tck if s.clk_tck > 0 else 100)
        for p in s.extra.top_procs:
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
                eff_hint = p.hint
                if (
                    renderer_urls
                    and p.comm == "chrome"
                    and p.hint.startswith("--type=renderer")
                    and p.pid in renderer_urls
                ):
                    eff_hint = f"{p.hint} {renderer_urls[p.pid]}"
                key = (p.comm, eff_hint)
                by_proc[key] = by_proc.get(key, 0.0) + cpu_s
                proc_pids.setdefault(key, set()).add(p.pid)
    ranked: list[tuple[float, str]] = []
    if crosvm_sec > 0.0:
        top_subs = [
            k for k, _ in sorted(crosvm_subs.items(), key=lambda kv: (-kv[1], kv[0]))[:3]
        ]
        p_lbl = f"{crosvm_peak_p}p" if crosvm_peak_p > 0 else "grp"
        ranked.append(
            (
                crosvm_sec,
                f"crosvm[{p_lbl}:{','.join(top_subs)}]" if top_subs else f"crosvm[{p_lbl}]",
            )
        )
    for (comm, hint), cpu_s in by_proc.items():
        pids = proc_pids[(comm, hint)]
        pid_lbl = f"#{next(iter(pids))}" if len(pids) == 1 else f"[{len(pids)}pids]"
        hint_lbl = f"({hint})" if hint else ""
        ranked.append((cpu_s, f"{comm}{pid_lbl}{hint_lbl}"))
    ranked.sort(key=lambda item: (-item[0], item[1]))
    fmt = (
        (lambda lbl, sec: f"{lbl}:{100.0 * sec / total_dt:.0f}%")
        if pct_only
        else (lambda lbl, sec: f"{lbl}={sec:.2f}s({100.0 * sec / total_dt:.1f}%)")
    )
    return total_dt, [fmt(lbl, sec) for sec, lbl in ranked[:limit]]


class TopProcsExtension:
    """Extension object attached to `DiagContext.top_procs_ext`."""

    remote_py_defs = REMOTE_TOP_PROCS_PY_DEFS

    def parse_extra(self, raw_extra: dict[str, Any], *, clk_tck: int) -> TopProcsSampleExtra:
        del clk_tck
        return parse_top_procs_extra(raw_extra)

    def format_summary_lines(
        self,
        window_samples: Sequence[Any],
        *,
        installer_closed_rel_sec: float | None = None,
        renderer_urls: Mapping[int, str] | None = None,
        strict: bool = True,
    ) -> list[str]:
        run_intervals = [
            s
            for s in window_samples[1:]
            if isinstance(getattr(s, "extra", None), TopProcsSampleExtra)
            and s.extra.proc_dt_sec > 0.0
        ]
        if strict and not run_intervals:
            raise RuntimeError(
                "Expected >=1 ChromeOS resource sample interval with proc_dt_sec > 0"
            )
        out: list[str] = []
        run_proc_dt, run_top_strs = format_top_procs(
            run_intervals, renderer_urls=renderer_urls
        )
        if run_proc_dt > 0.0:
            sampler_cpu_sec = sum(
                s.extra.sampler_ticks / float(s.clk_tck if s.clk_tck > 0 else 100)
                for s in run_intervals
            )
            sampler_avg_pct = 100.0 * sampler_cpu_sec / run_proc_dt
            sampler_peak_pct = max(
                (
                    100.0
                    * (s.extra.sampler_ticks / float(s.clk_tck if s.clk_tck > 0 else 100))
                    / s.extra.proc_dt_sec
                    for s in run_intervals
                ),
                default=0.0,
            )
            out.append(
                f"ChromeOS sampler: cpu={sampler_cpu_sec:.2f}s ({sampler_avg_pct:.2f}% of 1vCPU, "
                f"peak={sampler_peak_pct:.1f}%, budget<={CROS_SAMPLER_MAX_CPU_PCT:.1f}%, "
                f"interval={SAMPLER_INTERVAL_SEC}s)"
            )
            if strict and sampler_avg_pct > CROS_SAMPLER_MAX_CPU_PCT:
                raise RuntimeError(
                    f"ChromeOS resource sampler exceeded CPU budget: {sampler_avg_pct:.2f}% of 1vCPU > "
                    f"{CROS_SAMPLER_MAX_CPU_PCT:.1f}% (cpu={sampler_cpu_sec:.2f}s over {run_proc_dt:.1f}s, "
                    f"peak={sampler_peak_pct:.1f}%)"
                )
            perf_procs = [
                f"{fmt_rel_t(s.rel_sec).strip()}:{p.comm}#{p.pid}({p.hint})"
                for s in run_intervals
                for p in s.extra.top_procs
                if p.comm in ("perf", "quipper")
            ]
            if perf_procs:
                if strict:
                    raise RuntimeError(
                        "Unexpected ChromeOS profiling process in top_procs despite quipper bind-mount: "
                        f"{perf_procs}"
                    )
                out.append(
                    f"ChromeOS profiling warning: unexpected top_procs entries {perf_procs}"
                )
            out.append(
                f"ChromeOS top CPU (run, sampled={run_proc_dt:.1f}s, 100%=1vCPU): "
                f"{', '.join(run_top_strs) if run_top_strs else '<idle>'}"
            )
        if installer_closed_rel_sec is not None:
            strict_post = [
                s
                for s in run_intervals
                if (s.rel_sec - s.extra.proc_dt_sec) >= installer_closed_rel_sec
            ]
            post_intervals = (
                strict_post
                if sum(s.extra.proc_dt_sec for s in strict_post) >= 2.0
                else [s for s in run_intervals if s.rel_sec > installer_closed_rel_sec]
            )
            post_dt, post_top_strs = format_top_procs(
                post_intervals, renderer_urls=renderer_urls
            )
            if post_dt > 0.0:
                out.append(
                    f"ChromeOS top CPU (post-InstallerClosed t{installer_closed_rel_sec:+.1f}s+, "
                    f"sampled={post_dt:.1f}s): {', '.join(post_top_strs) if post_top_strs else '<idle>'}"
                )
        return out

    def format_row_suffix(
        self,
        slice_samples: Sequence[Any],
        *,
        renderer_urls: Mapping[int, str] | None = None,
    ) -> str:
        _, row_top = format_top_procs(
            slice_samples, pct_only=True, renderer_urls=renderer_urls
        )
        return f" top=[{', '.join(row_top)}]" if row_top else " top=[<idle>]"


class TopProcsDiagnosticsObserver(FlowDiagnosticsObserver):
    """Registers `TopProcsExtension` on `DiagContext` before `resources` starts its SSH loop."""

    def __init__(self, ctx: DiagContext) -> None:
        self.ctx = ctx
        with self.ctx.lock:
            self.ctx.top_procs_ext = TopProcsExtension()


def create_observer(args: argparse.Namespace, ctx: DiagContext) -> FlowDiagnosticsObserver:
    del args
    return TopProcsDiagnosticsObserver(ctx)
