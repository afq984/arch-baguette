"""Optional host-side SIGSTOP/SIGCONT duty-cycle throttler on QEMU for local slow-runner testing."""

from __future__ import annotations

import argparse
import os
import signal
import threading
from pathlib import Path
from typing import Any

from user_flows import FlowDiagnosticsObserver, log
from user_flows.diag import DiagContext
from user_flows.vm import pid_matches_qemu


def validate_quota_pct(quota_pct: int | None) -> None:
    if quota_pct is None:
        return
    if not (5 <= quota_pct <= 100):
        raise ValueError(
            f"--qemu-cpu-quota-pct must be between 5 and 100, got {quota_pct}"
        )


class HostQemuCpuThrottler:
    """Host-side 100ms-period SIGSTOP/SIGCONT duty-cycle throttler on the QEMU process."""

    def __init__(
        self,
        pid_file: Path,
        quota_pct: int | None,
        *,
        qemu_bin: str = "qemu-system-x86_64",
        initial_delay_sec: float = 3.0,
    ) -> None:
        validate_quota_pct(quota_pct)
        self.pid_file = pid_file
        self.quota_pct = quota_pct
        self.qemu_bin = qemu_bin
        self.initial_delay_sec = initial_delay_sec
        self._stop_event = threading.Event()
        self._thread: threading.Thread | None = None

    def start(self) -> None:
        validate_quota_pct(self.quota_pct)
        if self.quota_pct is None or self.quota_pct == 100 or self._thread is not None:
            return
        pid = int(self.pid_file.read_text(encoding="utf-8").strip())
        if not pid_matches_qemu(pid, self.qemu_bin):
            raise RuntimeError(
                f"Refusing to throttle PID {pid}: does not match live QEMU binary {self.qemu_bin!r}"
            )
        self._stop_event.clear()
        self._thread = threading.Thread(target=self._run, args=(pid,), daemon=True)
        self._thread.start()

    def _run(self, pid: int) -> None:
        if self.initial_delay_sec > 0 and self._stop_event.wait(timeout=self.initial_delay_sec):
            return
        assert self.quota_pct is not None
        log(
            f"  [throttle] Throttling host QEMU PID {pid} to {self.quota_pct}% CPU duty cycle "
            f"(initial_delay={self.initial_delay_sec:.1f}s)..."
        )
        period = 0.100  # 100 ms period so Chrome's 4s timers still wake promptly
        run_slice = period * (self.quota_pct / 100.0)
        stop_slice = period - run_slice
        try:
            while not self._stop_event.is_set():
                os.kill(pid, signal.SIGSTOP)
                if self._stop_event.wait(timeout=stop_slice):
                    break
                os.kill(pid, signal.SIGCONT)
                if self._stop_event.wait(timeout=run_slice):
                    break
        except ProcessLookupError:
            pass
        finally:
            try:
                os.kill(pid, signal.SIGCONT)
            except ProcessLookupError:
                pass

    def stop(self) -> None:
        if self._thread is not None:
            self._stop_event.set()
            self._thread.join(timeout=2.0)
            self._thread = None


class QemuThrottleObserver(FlowDiagnosticsObserver):
    """Starts `HostQemuCpuThrottler` on `VmStartingUpSignal`/`VmStartedSignal` and stops at readiness gate."""

    def __init__(
        self,
        ctx: DiagContext,
        *,
        quota_pct: int,
        throttle_from_vm_start: bool,
        qemu_bin: str,
    ) -> None:
        self.ctx = ctx
        self.trigger_member = (
            "VmStartingUpSignal" if throttle_from_vm_start else "VmStartedSignal"
        )
        self._triggered = False
        self.throttler = HostQemuCpuThrottler(
            ctx.work_dir / "kvm.pid",
            quota_pct,
            qemu_bin=qemu_bin,
            initial_delay_sec=0.0 if throttle_from_vm_start else 3.0,
        )

    def on_vm_started(self, vm: Any) -> None:
        if hasattr(vm, "pid_file"):
            self.throttler.pid_file = vm.pid_file
        if hasattr(vm, "qemu_bin"):
            self.throttler.qemu_bin = vm.qemu_bin

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
        del iface, detail, rel_sec, msg
        if not self._triggered and vm_name == "termina" and member == self.trigger_member:
            self._triggered = True
            self.throttler.start()

    def on_readiness_gate_passed(self, rel_sec: float) -> None:
        del rel_sec
        self.throttler.stop()

    def collect(self, *, strict: bool) -> None:
        del strict
        self.throttler.stop()

    def close(self) -> None:
        self.throttler.stop()


def register_cli_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--qemu-cpu-quota-pct",
        type=int,
        default=None,
        help="Optional host CPU duty-cycle quota %% (5..100) on QEMU during Termina startup/SetUpUser",
    )
    parser.add_argument(
        "--qemu-throttle-from-vm-start",
        action="store_true",
        default=False,
        help="Start QEMU CPU throttling at VmStartingUpSignal (0s delay) instead of VmStartedSignal (3s delay)",
    )


def create_observer(
    args: argparse.Namespace, ctx: DiagContext
) -> FlowDiagnosticsObserver | None:
    quota_pct = getattr(args, "qemu_cpu_quota_pct", None)
    validate_quota_pct(quota_pct)
    if quota_pct is None or quota_pct == 100:
        return None
    return QemuThrottleObserver(
        ctx,
        quota_pct=quota_pct,
        throttle_from_vm_start=bool(getattr(args, "qemu_throttle_from_vm_start", False)),
        qemu_bin=str(getattr(args, "qemu_bin", "qemu-system-x86_64")),
    )
