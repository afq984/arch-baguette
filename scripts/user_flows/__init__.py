"""Modular ChromeOS E2E user-flow verification package and diagnostics extension API."""

from __future__ import annotations

import dataclasses
import subprocess
import time
from pathlib import Path
from typing import Any, Sequence

GCS_ARCHIVE_ROOT = "https://storage.googleapis.com/chromiumos-image-archive"
REPO_ROOT = Path(__file__).resolve().parent.parent.parent
DEFAULT_README_PATH = REPO_ROOT / "README.md"
DEFAULT_PROTO_DIR = REPO_ROOT / "scripts" / "protos"


def log(msg: str) -> None:
    print(f"[{time.strftime('%H:%M:%S')}] {msg}", flush=True)


def fmt_rel_t(rel_sec: float) -> str:
    """Formats signed seconds relative to `InstallClicked` without clamping negative values."""
    return f"t{'+' if rel_sec >= 0.0 else '-'}{abs(rel_sec):6.1f}s"


def terminate_proc(proc: subprocess.Popen[Any] | None, *, wait_sec: float = 3.0) -> None:
    if proc is None or proc.poll() is not None:
        return
    try:
        proc.terminate()
        proc.wait(timeout=wait_sec)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait(timeout=2.0)
    except OSError:
        pass


@dataclasses.dataclass
class TimelineEntry:
    rel_sec: float
    source: str
    name: str
    detail: str


class FlowDiagnosticsObserver:
    """Extension-point interface for optional E2E diagnostics and instrumentation.

    The base E2E runner uses this no-op implementation by default so the core flow
    runs with zero diagnostics attached. Diagnostic layers subclass this interface
    and compose via `CompositeDiagnosticsObserver`.
    """

    def on_vm_started(self, vm: Any) -> None:
        """Called once the ChromeOS QEMU VM has booted and SSH is reachable."""

    def on_before_flow(
        self, vm: Any, *, owner_hash: str, username: str, log_scraper: Any = None, dbus_mon: Any = None
    ) -> None:
        """Called at the start of Step 2 before opening ChromeOS Settings."""

    def on_step(self, step: str) -> None:
        """Called whenever `ChromeOSVM.set_step` transitions to a new step."""

    def on_install_clicked(self, *, username: str, mono_ts: float, vm_epoch_sec: float) -> None:
        """Called immediately when `Install` is clicked in `chrome://crostini-installer`."""

    def on_ui_event(self, name: str, detail: str, rel_sec: float) -> None:
        """Called at UI milestones relative to `InstallClicked`."""

    def on_dbus_signal(
        self, *, iface: str, member: str, vm_name: str, detail: str, rel_sec: float, msg: Any
    ) -> None:
        """Called for each decoded D-Bus signal observed on `dbus-monitor`."""

    def on_readiness_gate_passed(self, rel_sec: float) -> None:
        """Called once `VmCicerone.ContainerStarted` and `GetGarconSessionInfo` succeed."""

    def check_healthy(self) -> None:
        """Polled during waits; raise `RuntimeError` if a background monitor failed."""

    def collect(self, *, strict: bool) -> None:
        """Stops passive monitors and collects diagnostic data.

        When `strict=True` (passing run), any diagnostic failure MUST raise.
        When `strict=False` (failing run), collectors record inline warnings without
        masking the primary test failure.
        """

    def format_report(self, *, include_verbose: bool) -> str:
        """Returns a human-readable diagnostics report, or `""` when none are attached."""
        return ""

    def close(self) -> None:
        """Idempotently releases background processes or host throttlers on teardown."""


class CompositeDiagnosticsObserver(FlowDiagnosticsObserver):
    """Chains multiple `FlowDiagnosticsObserver` instances with strict/idempotent collection."""

    def __init__(self, observers: Sequence[FlowDiagnosticsObserver]) -> None:
        self.observers: list[FlowDiagnosticsObserver] = list(observers)
        self._collected: set[int] = set()
        self.collector_errors: list[str] = []

    def _fanout(self, method: str, *args: Any, **kwargs: Any) -> None:
        for obs in self.observers:
            getattr(obs, method)(*args, **kwargs)

    def on_vm_started(self, vm: Any) -> None:
        self._fanout("on_vm_started", vm)

    def on_before_flow(self, vm: Any, **kwargs: Any) -> None:
        self._fanout("on_before_flow", vm, **kwargs)

    def on_step(self, step: str) -> None:
        self._fanout("on_step", step)

    def on_install_clicked(self, **kwargs: Any) -> None:
        self._fanout("on_install_clicked", **kwargs)

    def on_ui_event(self, name: str, detail: str, rel_sec: float) -> None:
        self._fanout("on_ui_event", name, detail, rel_sec)

    def on_dbus_signal(self, **kwargs: Any) -> None:
        self._fanout("on_dbus_signal", **kwargs)

    def on_readiness_gate_passed(self, rel_sec: float) -> None:
        self._fanout("on_readiness_gate_passed", rel_sec)

    def check_healthy(self) -> None:
        self._fanout("check_healthy")

    def collect(self, *, strict: bool) -> None:
        for idx, obs in enumerate(self.observers):
            if idx in self._collected:
                continue
            if strict:
                obs.collect(strict=True)
                self._collected.add(idx)
            else:
                try:
                    obs.collect(strict=False)
                    self._collected.add(idx)
                except Exception as exc:
                    self.collector_errors.append(f"{type(obs).__name__}: {type(exc).__name__}: {exc}")

    def format_report(self, *, include_verbose: bool) -> str:
        sections = [
            text
            for obs in self.observers
            if (text := obs.format_report(include_verbose=include_verbose).strip())
        ]
        if self.collector_errors:
            sections.append(
                "\n".join(("=== DIAGNOSTICS COLLECTION ERRORS ===", *(f"  {e}" for e in self.collector_errors)))
            )
        return "\n\n".join(sections)

    def close(self) -> None:
        for obs in self.observers:
            try:
                obs.close()
            except Exception as exc:
                log(f"Warning closing {type(obs).__name__}: {exc}")
