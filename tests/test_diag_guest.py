"""Offline unit tests for `scripts/user_flows/diag/guest.py`."""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from typing import Any

SCRIPTS_DIR = Path(__file__).resolve().parent.parent / "scripts"
if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))

from user_flows.diag import DiagContext, guest  # noqa: E402


def _make_sample_guest_output(*, omit_unit: str = "", omit_setup_msg: bool = False) -> str:
    unit_blocks: list[str] = []
    for idx, u in enumerate(guest.EXPECTED_GUEST_UNITS, 1):
        if u == omit_unit:
            continue
        start_us = idx * 1_000_000
        end_us = start_us + 250_000
        unit_blocks.append(
            f"Id={u}\n"
            "ActiveState=active\n"
            "SubState=running\n"
            "Result=success\n"
            f"InactiveExitTimestampMonotonic={start_us}\n"
            f"ActiveEnterTimestampMonotonic={end_us}\n"
            f"ExecMainStartTimestampMonotonic={start_us}\n"
            f"ExecMainExitTimestampMonotonic={end_us}\n"
            "ExecMainStatus=0"
        )
    jlines: list[str] = []
    if not omit_setup_msg:
        jlines.append(
            json.dumps(
                {
                    "__MONOTONIC_TIMESTAMP": "2500000",
                    "__REALTIME_TIMESTAMP": "1700000005000000",
                    "SYSLOG_IDENTIFIER": "maitred",
                    "MESSAGE": "Received request to setup a new user: terminauser",
                }
            )
        )
    jlines.append(
        json.dumps(
            {
                "__MONOTONIC_TIMESTAMP": "2700000",
                "__REALTIME_TIMESTAMP": "1700000005200000",
                "SYSLOG_IDENTIFIER": "useradd",
                "MESSAGE": "new user: name=terminauser, UID=1000, GID=1000",
            }
        )
    )
    return "\n".join(
        [
            "===GUEST_CLOCK_SYNC===",
            "uptime_sec=12.5",
            "epoch_sec=1700000015.0",
            "===GUEST_LIST_JOBS===",
            "No jobs running.",
            "===GUEST_SYSTEMD_UNIT_SHOW===",
            "\n\n".join(unit_blocks),
            "===GUEST_ANALYZE===",
            "Startup finished in 1.2s (userspace)",
            "===GUEST_BLAME===",
            "400ms first-boot-cros.service",
            "===GUEST_USER_ANALYZE===",
            "Startup finished in 300ms (userspace)",
            "===GUEST_USER_BLAME===",
            "120ms cros-garcon.service",
            "===GUEST_CRITICAL_CHAIN===",
            "multi-user.target @1.2s",
            "===GUEST_USER_CRITICAL_CHAIN===",
            "default.target @300ms",
            "===GUEST_GARCON_STATUS===",
            "Active: active (running)",
            "===GUEST_JOURNAL_JSON===",
            *jlines,
        ]
    )


class GuestDiagnosticsTests(unittest.TestCase):
    def test_parse_guest_diagnostics_strict_and_timeline_projection(self) -> None:
        raw = _make_sample_guest_output()
        summary, verbose, entries = guest.parse_guest_diagnostics(
            raw,
            first_host_setup_user_rel=5.0,
            strict=True,
            include_verbose=False,
        )
        self.assertTrue(any("first-boot-cros.service" in ln for ln in summary))
        self.assertEqual(verbose, [])
        # MaitredSetUpUser at guest+2.5s aligned to host rel 5.0s -> guest boot at t+2.5s
        setup_ev = [e for e in entries if e.name == "MaitredSetUpUser"]
        self.assertEqual(len(setup_ev), 1)
        self.assertAlmostEqual(setup_ev[0].rel_sec, 5.0, places=3)

        # Missing expected unit fails in strict mode
        with self.assertRaisesRegex(RuntimeError, "missing expected systemd units"):
            guest.parse_guest_diagnostics(
                _make_sample_guest_output(omit_unit="maitred.service"),
                first_host_setup_user_rel=5.0,
                strict=True,
            )

        # Missing SetUpUser journal message fails in strict mode
        with self.assertRaisesRegex(RuntimeError, "Received request to setup a new user"):
            guest.parse_guest_diagnostics(
                _make_sample_guest_output(omit_setup_msg=True),
                first_host_setup_user_rel=5.0,
                strict=True,
            )

    def test_observer_single_step_strict_vs_split_non_strict(self) -> None:
        calls: list[tuple[str, int]] = []

        class _FakeVM:
            def set_step(self, step: str) -> None:
                del step

            def vsh(
                self, vm_name: str, user: str, cmd: str, **kwargs: Any
            ) -> subprocess.CompletedProcess[str]:
                del vm_name, user, cmd
                calls.append((kwargs["op_desc"], kwargs["timeout"]))
                return subprocess.CompletedProcess([], 0, stdout=_make_sample_guest_output(), stderr="")

        with tempfile.TemporaryDirectory() as td:
            ctx = DiagContext(
                work_dir=Path(td),
                vm=_FakeVM(),
                username="terminauser",
                first_host_setup_user_rel=4.0,
            )
            obs = guest.GuestDiagnosticsObserver(ctx)
            obs.collect(strict=True)
            self.assertEqual(calls, [("guest_diag:summary", guest.GUEST_DIAG_TIMEOUT_SEC)])
            self.assertIn("GUEST BOOT & SERVICE TIMING SUMMARY", obs.format_report(include_verbose=False))
            self.assertTrue(len(ctx.extra_timeline_entries) >= 2)

            calls.clear()
            obs.collect(strict=False)
            self.assertEqual(
                calls,
                [
                    ("guest_diag:system", guest.GUEST_DIAG_TIMEOUT_SEC),
                    ("guest_diag:user", guest.GUEST_DIAG_TIMEOUT_SEC),
                ],
            )
            verbose_rep = obs.format_report(include_verbose=True)
            self.assertIn("critical-chain", verbose_rep)
            self.assertIn("journalctl -b (monotonic, filtered)", verbose_rep)


if __name__ == "__main__":
    unittest.main()
