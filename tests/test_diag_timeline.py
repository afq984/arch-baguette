"""Offline unit tests for `scripts/user_flows/diag/timeline.py`."""

from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path
from typing import Any
from unittest import mock

SCRIPTS_DIR = Path(__file__).resolve().parent.parent / "scripts"
if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))

from user_flows import TimelineEntry, dbus, flow  # noqa: E402
from user_flows.diag import DiagContext, timeline  # noqa: E402


class TimelineDiagnosticsTests(unittest.TestCase):
    def test_strict_and_non_strict_collection_and_report_formatting(self) -> None:
        protos = dbus.load_cros_protos()
        conc = protos.concierge_pb2
        cic = protos.cicerone_pb2

        class _FakeBrowserConn:
            def __init__(self, empty: bool = False) -> None:
                self.empty = empty
                self.closed = False

            def call(self, method: str, params: dict[str, Any], **kwargs: Any) -> dict[str, Any]:
                del method, kwargs
                if self.empty:
                    return {"histogram": {}}
                return {
                    "histogram": {
                        "name": params["name"],
                        "count": 1,
                        "sum": 42,
                        "buckets": [{"low": 40, "high": 50, "count": 1}],
                    }
                }

            def close(self) -> None:
                self.closed = True

        class _FakeVM:
            def __init__(self, empty_uma: bool = False) -> None:
                self.empty_uma = empty_uma
                self.steps: list[str] = []

            def set_step(self, step: str) -> None:
                self.steps.append(step)

            def dbus_call_proto(
                self, iface: str, method: str, req: Any, resp_cls: Any
            ) -> tuple[Any, bytes]:
                del iface, req
                if method == "GetVmInfo":
                    msg = resp_cls(
                        success=True,
                        vm_info=conc.VmInfo(
                            vm_type=conc.VmInfo.VmType.BAGUETTE,
                            status=conc.VmStatus.VM_STATUS_RUNNING,
                            pid=4321,
                            cid=32,
                        ),
                    )
                elif method == "ListVms":
                    msg = resp_cls(
                        success=True,
                        vms=[conc.ExtendedVmInfo(name="termina")],
                    )
                elif method == "ListRunningContainers":
                    msg = resp_cls(
                        containers=[{"vm_name": "termina", "container_name": "penguin"}]
                    )
                else:
                    msg = resp_cls(
                        status=cic.GetGarconSessionInfoResponse.Status.SUCCEEDED,
                        container_username="terminauser",
                        container_homedir="/home/terminauser",
                    )
                return msg, msg.SerializeToString()

            def connect_browser_cdp(self, *, label: str) -> _FakeBrowserConn:
                del label
                return _FakeBrowserConn(empty=self.empty_uma)

        scraper = mock.MagicMock(spec=flow.HostLogScraper)
        scraper.scrape.return_value = [
            TimelineEntry(2.5, "concierge", "SetUpVmUserCall", "call #1: Setting up user")
        ]
        scraper.first_host_setup_user_rel = 2.5
        scraper.messages_excerpt = "2026-10-31T10:00:02.500000Z INFO vm_concierge: Setting up user"
        scraper.chrome_excerpt = "2026-10-31T10:00:03.000000Z ERROR chrome: sample"

        with tempfile.TemporaryDirectory() as td:
            ctx = DiagContext(
                work_dir=Path(td),
                vm=_FakeVM(empty_uma=False),
                owner_hash="owner123",
                username="terminauser",
                log_scraper=scraper,
                container_started_rel_sec=12.0,
                ui_entries=[
                    TimelineEntry(0.0, "ui", "InstallClicked", "clicked"),
                    TimelineEntry(8.0, "ui", "InstallerClosed", "closed"),
                ],
                dbus_entries=[
                    TimelineEntry(12.0, "dbus", "ContainerStarted", "vm='termina'")
                ],
                extra_timeline_entries=[
                    TimelineEntry(3.0, "guest", "MaitredSetUpUser", "call #1")
                ],
            )
            obs = timeline.TimelineDiagnosticsObserver(ctx)
            obs.collect(strict=True)
            self.assertEqual(ctx.first_host_setup_user_rel, 2.5)

            normal_rep = obs.format_report(include_verbose=False)
            self.assertIn("installer_closed_before_container_started=True", normal_rep)
            self.assertIn("VmConcierge.GetVmInfo(termina): success=True", normal_rep)
            self.assertIn("UMA Crostini.TimeToInstallSuccess: count=1", normal_rep)
            self.assertIn("[guest    ] MaitredSetUpUser: call #1", normal_rep)
            self.assertNotIn("/var/log/messages excerpt", normal_rep)

            verbose_rep = obs.format_report(include_verbose=True)
            self.assertIn("/var/log/messages excerpt", verbose_rep)
            self.assertIn("/var/log/chrome/chrome excerpt", verbose_rep)

            # Strict mode fails loud on empty UMA histogram; non-strict records "<not recorded>"
            ctx.vm = _FakeVM(empty_uma=True)
            with self.assertRaisesRegex(RuntimeError, "returned empty result"):
                obs.collect(strict=True)
            obs.collect(strict=False)
            self.assertTrue(
                any("<not recorded>" in ln for ln in obs.readonly_summary_lines)
            )


if __name__ == "__main__":
    unittest.main()
