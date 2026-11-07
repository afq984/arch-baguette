"""Offline unit tests for `scripts/user_flows/flow.py`."""

from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

SCRIPTS_DIR = Path(__file__).resolve().parent.parent / "scripts"
if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))

from user_flows import DEFAULT_README_PATH, TimelineEntry, fmt_rel_t, flow  # noqa: E402


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


if __name__ == "__main__":
    unittest.main()
