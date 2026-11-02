"""Browser CDP `TracingStartedInBrowser` renderer PID -> compact URL attribution."""

from __future__ import annotations

import argparse
import time
import urllib.parse
from typing import Any

from user_flows import FlowDiagnosticsObserver
from user_flows.cdp import CDPError, CDPTimeoutError
from user_flows.diag import DiagContext

_SNAPSHOT_UI_EVENTS: frozenset[str] = frozenset(
    {
        "OSSettingsAttached",
        "InstallerAttached",
        "InitialTerminalObserved",
        "FreshTerminalPromptReached",
        "TerminalPromptVerified",
        "CroshVshVerified",
    }
)


def compact_cdp_target_url(url: str, title: str = "") -> str:
    """Formats a CDP target URL concisely for renderer CPU attribution."""
    raw = url.strip()
    if not raw:
        clean_title = " ".join(title.split())[:48]
        return f"[{clean_title}]" if clean_title else "<empty-url>"
    sp = urllib.parse.urlsplit(raw)
    if sp.scheme in ("chrome", "chrome-untrusted", "http", "https"):
        base = f"{sp.scheme}://{sp.netloc}{sp.path}"
        q_suffix = ""
        if sp.query:
            for qk, qv in urllib.parse.parse_qsl(sp.query, keep_blank_values=False):
                if qk == "command" and qv:
                    q_suffix = f"?command={qv[:24]}"
                    break
        frag_suffix = f"#{sp.fragment[:24]}" if sp.fragment else ""
        return (base + q_suffix + frag_suffix)[:88]
    if sp.scheme == "chrome-extension":
        ext_id = sp.netloc[:8] if len(sp.netloc) > 8 else sp.netloc
        return f"chrome-extension://{ext_id}{sp.path}"[:88]
    if raw == "about:blank" and title.strip() and title.strip() != raw:
        return f"about:blank[{title.strip()[:32]}]"
    return raw[:88]


def snapshot_cdp_renderer_pids(
    vm: Any, urls: dict[int, str] | None = None
) -> dict[int, str]:
    """Queries Browser CDP targets via `TracingStartedInBrowser` to map renderer PID -> URL."""
    merged: dict[int, str] = dict(urls or {})
    browser_conn = vm.connect_browser_cdp(label="Browser-RendererPIDs")
    try:
        res = browser_conn.call(
            "Target.getTargets",
            {"filter": [{}]},
            timeout=10.0,
            op_desc="snapshot_cdp_renderer_pids:getTargets",
        )
        target_infos = res.get("targetInfos")
        if not isinstance(target_infos, list):
            return merged
        for ti in target_infos:
            if not isinstance(ti, dict):
                continue
            ttype = str(ti.get("type", ""))
            if ttype in ("", "browser", "tab", "service_worker", "shared_worker", "worker"):
                continue
            tid = str(ti.get("targetId", ""))
            if not tid:
                continue
            ti_url = str(ti.get("url", ""))
            ti_title = str(ti.get("title", ""))
            sid = ""
            try:
                att = browser_conn.call(
                    "Target.attachToTarget",
                    {"targetId": tid, "flatten": True},
                    timeout=5.0,
                    allow_error=True,
                    op_desc=f"snapshot_cdp_renderer_pids:attach({tid})",
                )
                sid = str(att.get("sessionId", "")) if isinstance(att, dict) else ""
                if not sid:
                    continue
                frames_found: list[dict[str, Any]] = []
                trace_complete = False

                def _collect_trace_ev(ev: dict[str, Any]) -> None:
                    nonlocal trace_complete
                    method = ev.get("method")
                    if method == "Tracing.tracingComplete":
                        trace_complete = True
                        return
                    if method != "Tracing.dataCollected":
                        return
                    vals = ev.get("params", {}).get("value", [])
                    if not isinstance(vals, list):
                        return
                    for item in vals:
                        if isinstance(item, dict) and item.get("name") == "TracingStartedInBrowser":
                            frs = item.get("args", {}).get("data", {}).get("frames", [])
                            if isinstance(frs, list):
                                frames_found.extend(f for f in frs if isinstance(f, dict))

                start_res = browser_conn.call(
                    "Tracing.start",
                    {
                        "categories": "-*,disabled-by-default-devtools.timeline",
                        "transferMode": "ReportEvents",
                    },
                    timeout=5.0,
                    allow_error=True,
                    op_desc=f"snapshot_cdp_renderer_pids:trace_start({tid})",
                    session_id=sid,
                    on_event=_collect_trace_ev,
                )
                if isinstance(start_res, dict) and "error" in start_res:
                    continue
                browser_conn.call(
                    "Tracing.end",
                    {},
                    timeout=5.0,
                    allow_error=True,
                    op_desc=f"snapshot_cdp_renderer_pids:trace_end({tid})",
                    session_id=sid,
                    on_event=_collect_trace_ev,
                )
                trace_deadline = time.monotonic() + 5.0
                while not trace_complete:
                    rem = trace_deadline - time.monotonic()
                    if rem <= 0:
                        break
                    ev_msg = browser_conn.recv_frame(
                        rem, op_desc=f"snapshot_cdp_renderer_pids:trace_complete({tid})"
                    )
                    _collect_trace_ev(ev_msg)

                for fr in frames_found:
                    raw_pid = fr.get("processId")
                    if isinstance(raw_pid, bool) or not isinstance(raw_pid, int) or raw_pid <= 0:
                        continue
                    fr_id = str(fr.get("frame", ""))
                    fr_url = ti_url if (fr_id == tid and ti_url) else str(fr.get("url") or ti_url)
                    fr_title = ti_title if fr_id == tid else str(fr.get("name") or "")
                    compact_url = compact_cdp_target_url(fr_url, fr_title)
                    if compact_url.startswith("about:blank") and raw_pid in merged:
                        continue
                    merged[raw_pid] = compact_url
            except (CDPError, CDPTimeoutError):
                continue
            finally:
                if sid:
                    try:
                        browser_conn.call(
                            "Target.detachFromTarget",
                            {"sessionId": sid},
                            timeout=3.0,
                            allow_error=True,
                            op_desc=f"snapshot_cdp_renderer_pids:detach({tid})",
                        )
                    except (CDPError, CDPTimeoutError):
                        pass
    finally:
        browser_conn.close()
    return merged


class RendererUrlObserver(FlowDiagnosticsObserver):
    """Snapshots renderer PID -> URL mappings into `DiagContext.renderer_urls`."""

    def __init__(self, ctx: DiagContext) -> None:
        self.ctx = ctx

    def _snapshot(self, *, best_effort: bool) -> None:
        vm = self.ctx.vm
        if vm is None:
            return
        with self.ctx.lock:
            existing = dict(self.ctx.renderer_urls)
        try:
            updated = snapshot_cdp_renderer_pids(vm, existing)
        except (CDPError, CDPTimeoutError):
            if not best_effort:
                raise
            return
        with self.ctx.lock:
            self.ctx.renderer_urls.update(updated)

    def on_ui_event(self, name: str, detail: str, rel_sec: float) -> None:
        del detail, rel_sec
        if name in _SNAPSHOT_UI_EVENTS:
            self._snapshot(best_effort=True)

    def collect(self, *, strict: bool) -> None:
        if self.ctx.vm is None:
            if strict:
                raise RuntimeError("Missing VM instance for Browser CDP renderer PID snapshot")
            return
        self._snapshot(best_effort=not strict)


def create_observer(args: argparse.Namespace, ctx: DiagContext) -> FlowDiagnosticsObserver:
    del args
    return RendererUrlObserver(ctx)
