"""Offline unit tests for `scripts/user_flows/diag/throttle.py`."""

from __future__ import annotations

import signal
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

SCRIPTS_DIR = Path(__file__).resolve().parent.parent / "scripts"
if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))

import test_user_flows  # noqa: E402
from user_flows.diag import DiagContext, throttle  # noqa: E402
from user_flows import diag  # noqa: E402


class QemuThrottlerTests(unittest.TestCase):
    def test_cli_validation_and_duty_cycle_without_silent_offset(self) -> None:
        parser = test_user_flows.build_arg_parser(diag)
        with tempfile.TemporaryDirectory() as td:
            for bad_val in ("0", "4", "101", "-10"):
                bad_args = parser.parse_args(["--qemu-cpu-quota-pct", bad_val])
                with self.assertRaisesRegex(ValueError, "between 5 and 100"):
                    diag.build_observer(bad_args, work_dir=Path(td))

            # 100% is accepted as no-op
            args_100 = parser.parse_args(["--qemu-cpu-quota-pct", "100"])
            self.assertIsNone(throttle.create_observer(args_100, DiagContext(work_dir=Path(td))))

    def test_throttler_sigstop_sigcont_lifecycle_and_signal_triggers(self) -> None:
        kills: list[tuple[int, int]] = []
        with (
            tempfile.TemporaryDirectory() as td,
            mock.patch.object(throttle, "pid_matches_qemu", return_value=True),
            mock.patch.object(
                throttle.os, "kill", side_effect=lambda pid, sig: kills.append((pid, int(sig)))
            ),
        ):
            pid_file = Path(td) / "kvm.pid"
            pid_file.write_text("42424\n", encoding="utf-8")
            ctx = DiagContext(work_dir=Path(td))
            obs = throttle.QemuThrottleObserver(
                ctx,
                quota_pct=25,
                throttle_from_vm_start=False,
                qemu_bin="qemu-system-x86_64",
            )
            obs.throttler.initial_delay_sec = 0.0
            # VmStartingUpSignal ignored when throttle_from_vm_start=False
            obs.on_dbus_signal(
                iface="org.chromium.VmConcierge",
                member="VmStartingUpSignal",
                vm_name="termina",
                detail="",
                rel_sec=1.0,
                msg=None,
            )
            self.assertIsNone(obs.throttler._thread)

            # VmStartedSignal starts throttling; readiness gate stops and sends final SIGCONT
            obs.on_dbus_signal(
                iface="org.chromium.VmConcierge",
                member="VmStartedSignal",
                vm_name="termina",
                detail="",
                rel_sec=2.0,
                msg=None,
            )
            deadline = time.monotonic() + 2.0
            while len(kills) < 2 and time.monotonic() < deadline:
                time.sleep(0.01)
            obs.on_readiness_gate_passed(10.0)
            self.assertIsNone(obs.throttler._thread)
            self.assertGreaterEqual(len(kills), 2)
            self.assertEqual(kills[0], (42424, int(signal.SIGSTOP)))
            self.assertEqual(kills[-1], (42424, int(signal.SIGCONT)))


if __name__ == "__main__":
    unittest.main()
