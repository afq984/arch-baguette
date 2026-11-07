"""Offline unit tests for `scripts/user_flows/flow.py`."""

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

from user_flows import DEFAULT_README_PATH, FlowDiagnosticsObserver, TimelineEntry, fmt_rel_t, flow, vm  # noqa: E402


def _dummy_vm(**attrs: Any) -> vm.ChromeOSVM:
    inst = object.__new__(vm.ChromeOSVM)
    inst._current_step = "init"
    inst.observer = FlowDiagnosticsObserver()
    for k, v in attrs.items():
        setattr(inst, k, v)
    return inst


class FlowModuleTests(unittest.TestCase):
    def test_extract_readme_commands_positive_and_negative(self) -> None:
        cmds = flow.extract_readme_commands(DEFAULT_README_PATH)
        self.assertTrue(cmds.termina_create.startswith("vmc create "), cmds.termina_create)
        self.assertIn("--vm-type BAGUETTE", cmds.termina_create)
        self.assertTrue(cmds.termina_create.endswith(" termina"), cmds.termina_create)
        self.assertEqual(cmds.termina_reentry_vsh, "vsh termina penguin")

        with tempfile.TemporaryDirectory() as tmp:
            bad_readme = Path(tmp) / "README.md"
            for content in (
                "# Empty\n",
                "### Setup: Test\n```sh\nvmc create --vm-type BAGUETTE termina\n```\n",
            ):
                bad_readme.write_text(content, encoding="utf-8")
                with self.assertRaises(ValueError):
                    flow.extract_readme_commands(bad_readme)

    def test_verify_guest_user_identity(self) -> None:
        good_groups = "terminauser audio cdrom dialout disk floppy kvm netdev sudo tss video"
        flow.verify_guest_user_identity("1000", "terminauser", "1000", "terminauser", good_groups, "terminauser")
        for desc, args in (
            ("wrong UID", ("1001", "terminauser", "1000", "terminauser", good_groups, "terminauser")),
            ("wrong GID", ("1000", "terminauser", "1001", "terminauser", good_groups, "terminauser")),
            ("wrong primary group", ("1000", "terminauser", "1000", "users", good_groups, "terminauser")),
            (
                "missing kvm group",
                ("1000", "terminauser", "1000", "terminauser", good_groups.replace(" kvm", ""), "terminauser"),
            ),
            ("extra plugdev group", ("1000", "terminauser", "1000", "terminauser", f"{good_groups} plugdev", "terminauser")),
        ):
            with self.subTest(desc=desc), self.assertRaises(RuntimeError):
                flow.verify_guest_user_identity(*args)

    def test_parse_host_init_logs_negative_rel_and_inflight(self) -> None:
        self.assertEqual(fmt_rel_t(-2.4), "t-   2.4s")
        t_inst = flow.parse_rfc3339_utc("2026-10-30T16:00:10.000000Z")
        messages = (
            "2026-10-30T16:00:08.500000Z localhost vm_concierge[100]: Found existing disk at /x\n"
            "2026-10-30T16:00:15.000000Z localhost vm_concierge[100]: Received request: SetUpVmUser\n"
            "2026-10-30T16:00:16.000000Z localhost vm_concierge_helper: unrelated daemon line\n"
            "2026-10-30T16:00:99.000000Z localhost vm_concierge[100]: malformed second field\n"
        )
        chrome_bad = (
            "2026-10-30T16:00:17+00:00 INFO chrome[1]: Failed to set up baguette user: bad tz\n"
            "2026-10-30T16:00:18.000000Z ERROR chrome[1]: Failed to set up baguette user: real err\n"
        )
        entries, first_rel = flow.parse_host_init_logs(messages, chrome_bad, t_inst)
        self.assertAlmostEqual(first_rel or 0.0, 5.0, places=3)
        by_name = {e.name: e for e in entries}
        self.assertAlmostEqual(by_name["FoundExistingDisk"].rel_sec, -1.5, places=3)
        self.assertNotIn("SetUpVmUserDone", by_name)
        self.assertIn("SetUpVmUserInFlight", by_name)
        self.assertIn("call #1 still in flight", by_name["SetUpVmUserInFlight"].detail)
        self.assertIn("SetUpBaguetteUserFailed", by_name)
        self.assertIn("MalformedTimestamp", by_name)
        self.assertIn("skipped 2 malformed RFC3339 UTC timestamp line(s)", by_name["MalformedTimestamp"].detail)
        with self.assertRaises(ValueError):
            flow.parse_rfc3339_utc("2026-10-30T16:00:99.000000Z")

    def test_classify_initial_terminal_failure(self) -> None:
        t_inst = flow.parse_rfc3339_utc("2026-11-01T13:04:26.300000Z")
        msgs = (
            "2026-11-01T13:05:55.820000Z INFO vm_concierge[2964]: Received request: SetUpVmUser\n"
            "2026-11-01T13:06:12.410000Z INFO vm_concierge[2964]: Received request: GetVmInfo\n"
            "2026-11-01T13:07:21.400000Z INFO vm_concierge[2964]: Received request: SetUpVmUser\n"
            "2026-11-01T13:07:41.402100Z ERR vm_concierge[2964]: SetUpUser RPC failed: Deadline Exceeded\n"
        )
        host_entries, _ = flow.parse_host_init_logs(msgs, "", t_inst)
        entries = [TimelineEntry(145.0, "ui", "InstallerClosed", "closed"), *host_entries]
        flow.classify_initial_terminal_failure(
            flow.KNOWN_INITIAL_TERMINAL_TIMEOUT_ERROR, entries, container_started_rel_sec=284.3
        )
        with self.assertRaises(RuntimeError):
            flow.classify_initial_terminal_failure("Launching vmshell failed: 22", entries, container_started_rel_sec=284.3)

    def test_verify_concierge_balloon_timer_stopped(self) -> None:
        good_unfiltered = (
            "2026-11-02T15:19:38.700000Z INFO vm_concierge[2910]: New VM. Starting balloon resize timer\n"
            "2026-11-02T15:19:39.700000Z INFO vm_concierge[2910]: BalloonTrace throttled with size window: 214 MIB\n"
            "2026-11-02T15:19:39.850000Z INFO vm_concierge[2910]: Stopping balloon timer since timer_interval_millis is 0\n"
            "2026-11-02T15:20:39.731093Z INFO vm_concierge[2910]: Received request: SetUpVmUser\n"
        )
        entries, _ = flow.parse_host_init_logs(good_unfiltered, "", flow.parse_rfc3339_utc("2026-11-02T13:04:49.760000Z"))
        self.assertIn("BalloonTimerStopped", [e.name for e in entries])

        seen_cmds: list[str] = []
        fake_vm = _dummy_vm(ssh=lambda cmd, **_kw: seen_cmds.append(cmd) or mock.MagicMock(stdout=good_unfiltered))
        flow.verify_concierge_balloon_timer_stopped(fake_vm, 120)
        self.assertIn("tail -n +121 /var/log/messages", seen_cmds[0])
        self.assertNotIn("BalloonTrace:", seen_cmds[0])

        for desc, bad_raw in (
            ("missing start line", "2026-11-02T15:19:39.850000Z INFO vm_concierge[2910]: Stopping balloon timer since timer_interval_millis is 0\n"),
            ("missing stop line", "2026-11-02T15:19:38.700000Z INFO vm_concierge[2910]: New VM. Starting balloon resize timer\n"),
            ("BalloonTrace after stop", good_unfiltered + "2026-11-02T15:20:41.000000Z INFO vm_concierge[2910]: BalloonTrace:[termina,0,678,6005,299,6271]\n"),
            ("balloon stats timeout after stop", good_unfiltered + "2026-11-02T15:20:41.000000Z ERR vm_concierge[2910]: Failed to retrieve balloon stats\n"),
        ):
            fake_vm.ssh = lambda _cmd, _r=bad_raw, **_kw: mock.MagicMock(stdout=_r)  # type: ignore[method-assign]
            with self.subTest(desc=desc), self.assertRaises(RuntimeError):
                flow.verify_concierge_balloon_timer_stopped(fake_vm, 0)

        self.assertGreaterEqual(flow.TERMINAL_POLL_FLOOR_SEC, 1.5)


if __name__ == "__main__":
    unittest.main()
