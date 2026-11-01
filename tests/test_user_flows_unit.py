#!/usr/bin/env python3
"""Offline unit tests for `scripts/test_user_flows.py` (stdlib `unittest`)."""

from __future__ import annotations

import contextlib
import dataclasses
import io
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from typing import Any
from unittest import mock

REPO_ROOT = Path(__file__).resolve().parent.parent
SCRIPTS_DIR = REPO_ROOT / "scripts"
if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))

import test_user_flows as tuf  # noqa: E402


class WebSocketTimeoutException(Exception):
    """Matches `websocket-client`'s `WebSocketTimeoutException` (does not subclass `TimeoutError`)."""


class WebSocketConnectionClosedException(Exception):
    pass


class _FakeWS:
    def __init__(self, responses: list[Any], connected: bool = True) -> None:
        self._responses = list(responses)
        self.connected = connected
        self.sent: list[str] = []
        self.last_timeout: float | None = None

    def settimeout(self, t: float) -> None:
        self.last_timeout = t

    def send(self, payload: str) -> None:
        self.sent.append(payload)

    def recv(self) -> str:
        if not self._responses:
            self.connected = False
            return ""
        nxt = self._responses.pop(0)
        if isinstance(nxt, BaseException):
            raise nxt
        return str(nxt)

    def close(self) -> None:
        self.connected = False


class ReadmeAndVendoredProtosTests(unittest.TestCase):
    def test_extract_readme_commands_positive_and_negative(self) -> None:
        cmds = tuf.extract_readme_commands(tuf.DEFAULT_README_PATH)
        self.assertTrue(cmds.termina_create.startswith("vmc create "), cmds.termina_create)
        self.assertIn("--vm-type BAGUETTE", cmds.termina_create)
        self.assertTrue(cmds.termina_create.endswith(" termina"), cmds.termina_create)
        self.assertEqual(cmds.termina_reentry_vsh, "vsh termina penguin")

        with tempfile.TemporaryDirectory() as tmp:
            bad_readme = Path(tmp) / "README.md"
            bad_readme.write_text("# Empty\n", encoding="utf-8")
            with self.assertRaises(ValueError):
                tuf.extract_readme_commands(bad_readme)

            bad_readme.write_text(
                "### Setup: Test\n```sh\nvmc create --vm-type BAGUETTE termina\n```\n",
                encoding="utf-8",
            )
            with self.assertRaises(ValueError):
                tuf.extract_readme_commands(bad_readme)

    def test_vendored_protos_and_lsb_release_matching(self) -> None:
        protos = tuf.load_cros_protos(tuf.DEFAULT_PROTO_DIR)
        meta = protos.metadata

        with tempfile.TemporaryDirectory() as tmp_pdir:
            copied = Path(tmp_pdir) / "protos"
            shutil.copytree(tuf.DEFAULT_PROTO_DIR, copied)
            tampered = copied / "arc/arc.proto"
            tampered.write_text(tampered.read_text(encoding="utf-8") + "\n// tampered\n", encoding="utf-8")
            with self.assertRaises(RuntimeError):
                tuf.verify_vendored_protos(copied)

        with self.assertRaises(RuntimeError):
            tuf.parse_cros_release_str("156-16827.0.0")

        pinned_board = str(meta["board"])
        pinned_release = str(meta["cros_release"])
        pinned_milestone, pinned_version = tuf.parse_cros_release_str(pinned_release)
        wrong_milestone = str(int(pinned_milestone) - 1)
        wrong_version = "0.0.0"
        wrong_release = f"R{wrong_milestone}-{wrong_version}"
        good_lsb = (
            f"CHROMEOS_RELEASE_BUILDER_PATH={pinned_board}/{pinned_release}\n"
            f"CHROMEOS_RELEASE_CHROME_MILESTONE={pinned_milestone}\n"
            f"CHROMEOS_RELEASE_VERSION={pinned_version}\n"
        )
        tuf.verify_lsb_release_matches_metadata(good_lsb, meta)

        for desc, bad_lsb, exc_cls in (
            (
                "wrong release",
                f"CHROMEOS_RELEASE_BUILDER_PATH={pinned_board}/{wrong_release}\n"
                f"CHROMEOS_RELEASE_CHROME_MILESTONE={wrong_milestone}\n"
                f"CHROMEOS_RELEASE_VERSION={wrong_version}\n",
                RuntimeError,
            ),
            (
                "mismatched milestone vs builder path",
                f"CHROMEOS_RELEASE_BUILDER_PATH={pinned_board}/{pinned_release}\n"
                f"CHROMEOS_RELEASE_CHROME_MILESTONE={wrong_milestone}\n"
                f"CHROMEOS_RELEASE_VERSION={pinned_version}\n",
                RuntimeError,
            ),
            (
                "wrong board",
                f"CHROMEOS_RELEASE_BUILDER_PATH={pinned_board}-other/{pinned_release}\n"
                f"CHROMEOS_RELEASE_CHROME_MILESTONE={pinned_milestone}\n"
                f"CHROMEOS_RELEASE_VERSION={pinned_version}\n",
                RuntimeError,
            ),
            ("malformed line without '='", "NOT_KEY_VALUE\n", ValueError),
        ):
            with self.subTest(desc=desc), self.assertRaises(exc_cls):
                tuf.verify_lsb_release_matches_metadata(bad_lsb, meta)


class DbusAndProtobufParserTests(unittest.TestCase):
    def setUp(self) -> None:
        self.protos = tuf.load_cros_protos(tuf.DEFAULT_PROTO_DIR)
        self.conc = self.protos.concierge_pb2
        self.cic = self.protos.cicerone_pb2
        self.sample_owner = "483c91bbeb9f2f163f30c8dea260f4d8d1c87b4f"

    def test_dbus_send_and_monitor_round_trip_and_signal_ordering(self) -> None:
        real_get_vm_info_reply = (
            "method return time=1793376373.228710 sender=:1.175 -> destination=:1.197 serial=91 reply_serial=2\n"
            "   array of bytes [\n"
            "      08 01 12 0f 0d 64 73 5c 1a 10 18 18 20 20 01 30 06 40 01\n"
            "   ]\n"
        )
        raw_vm_info = tuf.parse_dbus_send_byte_array(real_get_vm_info_reply, "test GetVmInfo")
        vm_info_resp = tuf.parse_and_validate_proto(
            raw_vm_info, self.conc.GetVmInfoResponse, "test GetVmInfo"
        )
        self.assertTrue(vm_info_resp.success)
        self.assertEqual(vm_info_resp.vm_info.pid, 24)
        self.assertEqual(vm_info_resp.vm_info.cid, 32)
        self.assertEqual(self.conc.VmInfo.VmType.Name(vm_info_resp.vm_info.vm_type), "BAGUETTE")
        self.assertEqual(self.conc.VmStatus.Name(vm_info_resp.vm_info.status), "VM_STATUS_RUNNING")

        # Single-line `array of bytes [ 08 01 ]` also parses cleanly
        inline_reply = (
            "method return time=1.0 sender=:1.1 -> destination=:1.2 serial=1 reply_serial=1\n"
            "   array of bytes [ 08 01 ]\n"
        )
        self.assertEqual(tuf.parse_dbus_send_byte_array(inline_reply, "inline"), b"\x08\x01")

        # Empty `   array [\n   ]` on both dbus-send and dbus-monitor
        empty_reply = (
            "method return time=1793443903.001918 sender=:1.179 -> destination=:1.213 serial=105 reply_serial=2\n"
            "   array [\n"
            "   ]\n"
        )
        raw_empty = tuf.parse_dbus_send_byte_array(empty_reply, "empty ListRunningContainers")
        self.assertEqual(raw_empty, b"")
        empty_lc = tuf.parse_and_validate_proto(
            raw_empty, self.cic.ListRunningContainersResponse, "empty ListRunningContainers"
        )
        self.assertEqual(list(empty_lc.containers), [])

        empty_sig_parser = tuf.DbusMonitorSignalParser()
        self.assertIsNone(
            empty_sig_parser.feed_line(
                "signal time=1793443903.001918 sender=:1.179 -> destination=(null destination) "
                "serial=42 path=/org/chromium/VmCicerone; interface=org.chromium.VmCicerone; member=PendingAppListUpdates"
            )
        )
        self.assertIsNone(empty_sig_parser.feed_line("   array ["))
        self.assertEqual(
            empty_sig_parser.feed_line("   ]"),
            ("org.chromium.VmCicerone", "PendingAppListUpdates", b""),
        )
        empty_sig_parser.finish()

        sig_starting = self.conc.VmStartingUpSignal(
            name="termina",
            owner_id=self.sample_owner,
            vm_type=self.conc.VmInfo.VmType.BAGUETTE,
            cid=32,
        ).SerializeToString()
        sig_started = self.conc.VmStartedSignal(
            name="termina",
            owner_id=self.sample_owner,
            vm_info=vm_info_resp.vm_info,
            status=self.conc.VmStatus.VM_STATUS_RUNNING,
        ).SerializeToString()
        sig_container = self.cic.ContainerStartedSignal(
            vm_name="termina",
            container_name="penguin",
            owner_id=self.sample_owner,
            container_username="terminauser",
            container_homedir="/home/terminauser",
            sftp_vsock_port=4201566639,
            container_token="9aa4fe0f-1346-4bdb-ac9c-62c9e9444f0e",
        ).SerializeToString()
        sig_applist = self.cic.PendingAppListUpdatesSignal(
            vm_name="termina", container_name="penguin", count=0
        ).SerializeToString()

        def _fmt_sig(iface: str, member: str, payload: bytes) -> str:
            hex_str = " ".join(f"{b:02x}" for b in payload)
            return (
                f"signal time=1793376347.100000 sender=:1.175 -> destination=(null destination) "
                f"serial=42 path=/org/chromium/{iface.split('.')[-1]}; interface={iface}; member={member}\n"
                f"   array of bytes [\n      {hex_str}\n   ]\n"
            )

        monitor_stream = (
            "signal time=1793376341.005000 sender=org.freedesktop.DBus -> destination=:1.198 "
            "serial=2 path=/org/freedesktop/DBus; interface=org.freedesktop.DBus; member=NameAcquired\n"
            '   string ":1.198"\n'
            "signal time=1793376341.006000 sender=org.freedesktop.DBus -> destination=:1.198 "
            "serial=4 path=/org/freedesktop/DBus; interface=org.freedesktop.DBus; member=NameLost\n"
            '   string ":1.198"\n'
            + _fmt_sig("org.chromium.VmConcierge", "VmStartingUpSignal", sig_starting)
            + _fmt_sig("org.chromium.VmConcierge", "VmStartedSignal", sig_started)
            + _fmt_sig("org.chromium.VmCicerone", "ContainerStarted", sig_container)
            + _fmt_sig("org.chromium.VmCicerone", "PendingAppListUpdates", sig_applist)
        )

        cb_hits: list[str] = []
        rec = tuf.InitTimelineRecorder(
            None,  # type: ignore[arg-type]
            self.sample_owner,
            expected_username="terminauser",
            on_vm_starting_up=lambda: cb_hits.append("starting"),
            on_vm_started=lambda: cb_hits.append("started"),
        )
        rec.t_install_mono = time.monotonic()
        mon_parser = tuf.DbusMonitorSignalParser()
        parsed_events: list[tuple[str, str]] = []
        for ln in monitor_stream.splitlines():
            ev = mon_parser.feed_line(ln)
            if ev is not None:
                rec._handle_dbus_signal(*ev)
                parsed_events.append((ev[0], ev[1]))
        mon_parser.finish()

        self.assertEqual(len(parsed_events), 6)
        self.assertEqual(rec.monitor_unique_name, ":1.198")
        self.assertTrue(rec._monitor_subscribed_event.is_set())
        self.assertTrue(rec.is_container_started())
        rec.verify_required_dbus_signal_sequence()

        # One-shot callbacks do not re-fire on duplicate signals
        rec._handle_dbus_signal("org.chromium.VmConcierge", "VmStartingUpSignal", sig_starting)
        rec._handle_dbus_signal("org.chromium.VmConcierge", "VmStartedSignal", sig_started)
        self.assertEqual(cb_hits, ["starting", "started"])

        for desc, bad_seq in (
            (
                "missing VmStartingUpSignal",
                [
                    tuf.TimelineEntry(1.0, "dbus", "VmStartedSignal", "vm='termina'"),
                    tuf.TimelineEntry(2.0, "dbus", "ContainerStarted", "vm='termina' container='penguin'"),
                ],
            ),
            (
                "out-of-order VmStartingUpSignal",
                [
                    tuf.TimelineEntry(2.0, "dbus", "VmStartedSignal", "vm='termina'"),
                    tuf.TimelineEntry(1.0, "dbus", "VmStartingUpSignal", "vm='termina'"),
                    tuf.TimelineEntry(3.0, "dbus", "ContainerStarted", "vm='termina' container='penguin'"),
                ],
            ),
        ):
            with self.subTest(desc=desc), self.assertRaises(RuntimeError):
                bad_rec = tuf.InitTimelineRecorder(None, self.sample_owner)  # type: ignore[arg-type]
                bad_rec._entries = list(bad_seq)
                bad_rec.verify_required_dbus_signal_sequence()

    def test_negative_protobuf_and_dbus_parsers(self) -> None:
        raw_vm_info = bytes.fromhex("0801120f0d64735c1a10181820200130064001")
        sig_container = self.cic.ContainerStartedSignal(
            vm_name="termina",
            container_name="penguin",
            owner_id=self.sample_owner,
            container_username="terminauser",
            container_homedir="/home/terminauser",
        ).SerializeToString()
        rec = tuf.InitTimelineRecorder(None, self.sample_owner, expected_username="terminauser")  # type: ignore[arg-type]

        def _feed_all(lines: tuple[str, ...], call_finish: bool = False) -> None:
            p = tuf.DbusMonitorSignalParser()
            for x in lines:
                p.feed_line(x)
            if call_finish:
                p.finish()

        cases: list[tuple[str, Any]] = [
            (
                "truncated wire bytes",
                lambda: tuf.parse_and_validate_proto(
                    sig_container[:-1], self.cic.ContainerStartedSignal, "trunc"
                ),
            ),
            (
                "unknown wire field tag",
                lambda: tuf.parse_and_validate_proto(
                    sig_container + b"\xf8\x0f\x01", self.cic.ContainerStartedSignal, "unk"
                ),
            ),
            (
                "wrong message type bytes",
                lambda: tuf.parse_and_validate_proto(
                    raw_vm_info, self.cic.ContainerStartedSignal, "wrong_type"
                ),
            ),
            (
                "missing container_username in ContainerStarted",
                lambda: rec._handle_dbus_signal(
                    "org.chromium.VmCicerone",
                    "ContainerStarted",
                    self.cic.ContainerStartedSignal(
                        vm_name="termina", container_name="penguin", owner_id=self.sample_owner
                    ).SerializeToString(),
                ),
            ),
            (
                "mismatched owner_id in ContainerStarted",
                lambda: rec._handle_dbus_signal(
                    "org.chromium.VmCicerone",
                    "ContainerStarted",
                    self.cic.ContainerStartedSignal(
                        vm_name="termina",
                        container_name="penguin",
                        owner_id="other_owner",
                        container_username="terminauser",
                        container_homedir="/home/terminauser",
                    ).SerializeToString(),
                ),
            ),
            (
                "unknown enum value",
                lambda: tuf.require_enum_name(
                    self.conc.VmStatus, 999, "status", "enum_test", b"\x20\xe7\x07"
                ),
            ),
            (
                "missing method return header",
                lambda: tuf.parse_dbus_send_byte_array("   array of bytes [\n      08 01\n   ]\n", "bad"),
            ),
            (
                "non-hex byte token",
                lambda: tuf.parse_dbus_send_byte_array(
                    "method return time=1.0 sender=:1.1 -> destination=:1.2 serial=1 reply_serial=1\n"
                    "   array of bytes [\n      08 zz\n   ]\n",
                    "bad_hex",
                ),
            ),
            (
                "unclosed array of bytes on dbus-monitor",
                lambda: _feed_all(
                    (
                        "signal time=1.0 sender=:1.1 -> destination=(null destination) serial=1 "
                        "path=/org/chromium/VmCicerone; interface=org.chromium.VmCicerone; member=ContainerStarted",
                        "   array of bytes [",
                        "      0a 07",
                        "signal time=2.0 sender=:1.1 -> destination=(null destination) serial=2 "
                        "path=/org/chromium/VmCicerone; interface=org.chromium.VmCicerone; member=ContainerStarted",
                    )
                ),
            ),
            (
                "unexpected D-Bus signal member",
                lambda: _feed_all(
                    (
                        "signal time=1.0 sender=:1.1 -> destination=(null destination) serial=1 "
                        "path=/org/chromium/VmCicerone; interface=org.chromium.VmCicerone; member=BogusSignal",
                    )
                ),
            ),
            (
                "non-empty generic array [ 08 ]",
                lambda: tuf.parse_dbus_send_byte_array(
                    "method return time=1.0 sender=:1.1 -> destination=:1.2 serial=1 reply_serial=1\n"
                    "   array [ 08 ]\n",
                    "bad_generic_inline",
                ),
            ),
            (
                "non-empty generic multiline array",
                lambda: tuf.parse_dbus_send_byte_array(
                    "method return time=1.0 sender=:1.1 -> destination=:1.2 serial=1 reply_serial=1\n"
                    "   array [\n      08\n   ]\n",
                    "bad_generic_multi",
                ),
            ),
            (
                "unclosed empty array on dbus-send",
                lambda: tuf.parse_dbus_send_byte_array(
                    "method return time=1.0 sender=:1.1 -> destination=:1.2 serial=1 reply_serial=1\n"
                    "   array [\n",
                    "bad_unclosed_send",
                ),
            ),
            (
                "non-empty generic multiline array on dbus-monitor",
                lambda: _feed_all(
                    (
                        "signal time=1.0 sender=:1.1 -> destination=(null destination) serial=1 "
                        "path=/org/chromium/VmCicerone; interface=org.chromium.VmCicerone; member=PendingAppListUpdates",
                        "   array [",
                        "      08",
                        "   ]",
                    )
                ),
            ),
            (
                "unclosed empty array at EOF on dbus-monitor",
                lambda: _feed_all(
                    (
                        "signal time=1.0 sender=:1.1 -> destination=(null destination) serial=1 "
                        "path=/org/chromium/VmCicerone; interface=org.chromium.VmCicerone; member=PendingAppListUpdates",
                        "   array [",
                    ),
                    call_finish=True,
                ),
            ),
        ]
        for desc, fn in cases:
            with self.subTest(desc=desc), self.assertRaises(ValueError):
                fn()


class IdentityAndSlowRunnerClassifierTests(unittest.TestCase):
    def test_verify_guest_user_identity(self) -> None:
        good_groups = "terminauser audio cdrom dialout disk floppy kvm netdev sudo tss video"
        tuf.verify_guest_user_identity(
            "1000", "terminauser", "1000", "terminauser", good_groups, "terminauser"
        )
        for desc, args in (
            ("wrong UID", ("1001", "terminauser", "1000", "terminauser", good_groups, "terminauser")),
            ("wrong GID", ("1000", "terminauser", "1001", "terminauser", good_groups, "terminauser")),
            ("wrong primary group", ("1000", "terminauser", "1000", "users", good_groups, "terminauser")),
            (
                "missing kvm group",
                (
                    "1000",
                    "terminauser",
                    "1000",
                    "terminauser",
                    "terminauser audio cdrom dialout disk floppy netdev sudo tss video",
                    "terminauser",
                ),
            ),
            (
                "extra plugdev group",
                ("1000", "terminauser", "1000", "terminauser", good_groups + " plugdev", "terminauser"),
            ),
        ):
            with self.subTest(desc=desc), self.assertRaises(RuntimeError):
                tuf.verify_guest_user_identity(*args)

    def test_classify_initial_terminal_failure_and_clock_domain_skew(self) -> None:
        self.assertGreater(tuf.parse_rfc3339_utc("2026-10-30T16:01:34.115657Z"), 0)
        ci_entries = [
            tuf.TimelineEntry(0.0, "ui", "InstallClicked", "user='terminauser'"),
            tuf.TimelineEntry(51.8, "concierge", "SetUpVmUser", "call #1: Received request: SetUpVmUser"),
            tuf.TimelineEntry(57.2, "concierge", "SetUpVmUserDone", "call #1 completed in <=5.3s"),
            tuf.TimelineEntry(
                106.4,
                "ui",
                "InstallerClosed",
                "closed after 106.1s (last_progress='Configuring the Linux container.')",
            ),
            tuf.TimelineEntry(126.5, "concierge", "SetUpVmUser", "call #2: Received request: SetUpVmUser"),
            tuf.TimelineEntry(
                146.5,
                "concierge",
                "SetUpVmUserFailed",
                "call #2 failed after 20.0s: SetUpUser RPC failed: Deadline Exceeded",
            ),
            tuf.TimelineEntry(
                146.5,
                "chrome",
                "SetUpBaguetteUserFailed",
                "Failed to set up baguette user: Deadline Exceeded",
            ),
            tuf.TimelineEntry(
                146.5,
                "chrome",
                "RestartCrostiniFailed",
                'Failed to restart Crostini with error code: 50, container: (type:6:BAGUETTE vm:"termina" container:"penguin")',
            ),
            tuf.TimelineEntry(
                149.3,
                "cicerone",
                "ContainerReadyLog",
                "Startup of container penguin at IP  for VM termina completed.",
            ),
            tuf.TimelineEntry(
                150.0,
                "dbus",
                "ContainerStarted",
                "vm='termina' container='penguin' user='terminauser' homedir='/home/terminauser'",
            ),
        ]
        tuf.classify_initial_terminal_failure(
            tuf.KNOWN_INITIAL_TERMINAL_TIMEOUT_ERROR, ci_entries, container_started_rel_sec=150.0
        )

        # 1.5s UI poll + host-vs-VM clock skew where InstallerClosed (host monotonic) > call #2 (VM realtime)
        poll_skew_entries = [
            tuf.TimelineEntry(127.9, e.source, e.name, e.detail) if e.name == "InstallerClosed" else e
            for e in ci_entries
        ]
        tuf.classify_initial_terminal_failure(
            tuf.KNOWN_INITIAL_TERMINAL_TIMEOUT_ERROR,
            poll_skew_entries,
            container_started_rel_sec=150.0,
        )

        for desc, buf, entries, cs_rel in (
            (
                "different terminal error code",
                "Launching vmshell failed: Error starting crostini for terminal: 22 (CONTAINER_START_FAILED)",
                ci_entries,
                150.0,
            ),
            ("progress bar timeout without error 50", "[===] Configuring", ci_entries, 150.0),
            (
                "InstallerClosed at/after ContainerStarted",
                tuf.KNOWN_INITIAL_TERMINAL_TIMEOUT_ERROR,
                ci_entries,
                106.0,
            ),
            (
                "failure at/after ContainerReadyLog",
                tuf.KNOWN_INITIAL_TERMINAL_TIMEOUT_ERROR,
                [
                    tuf.TimelineEntry(145.0, e.source, e.name, e.detail)
                    if e.name == "ContainerReadyLog"
                    else e
                    for e in ci_entries
                ],
                150.0,
            ),
            (
                "SetUpVmUser call #2 preceded call #1 completion",
                tuf.KNOWN_INITIAL_TERMINAL_TIMEOUT_ERROR,
                [
                    tuf.TimelineEntry(55.0, e.source, e.name, e.detail)
                    if (e.name == "SetUpVmUser" and e.detail.startswith("call #2:"))
                    else e
                    for e in ci_entries
                ],
                150.0,
            ),
            (
                "missing ContainerReadyLog",
                tuf.KNOWN_INITIAL_TERMINAL_TIMEOUT_ERROR,
                [e for e in ci_entries if e.name != "ContainerReadyLog"],
                150.0,
            ),
            (
                "missing RestartCrostiniFailed",
                tuf.KNOWN_INITIAL_TERMINAL_TIMEOUT_ERROR,
                [e for e in ci_entries if e.name != "RestartCrostiniFailed"],
                150.0,
            ),
            (
                "duplicate RestartCrostiniFailed",
                tuf.KNOWN_INITIAL_TERMINAL_TIMEOUT_ERROR,
                [
                    *ci_entries,
                    tuf.TimelineEntry(
                        147.0,
                        "chrome",
                        "RestartCrostiniFailed",
                        'Failed to restart Crostini with error code: 50, container: (type:6:BAGUETTE vm:"termina" container:"penguin")',
                    ),
                ],
                150.0,
            ),
        ):
            with self.subTest(desc=desc), self.assertRaises(RuntimeError):
                tuf.classify_initial_terminal_failure(buf, entries, cs_rel)


class DiagnosticsAndLogScraperTests(unittest.TestCase):
    def test_guest_diagnostics_strict_and_non_strict(self) -> None:
        unit_blocks = "\n\n".join(
            [
                "Id=first-boot-cros.service\nActiveState=inactive\nSubState=dead\nResult=success\n"
                "InactiveExitTimestampMonotonic=12400000\nActiveEnterTimestampMonotonic=28400000\n"
                "ExecMainStartTimestampMonotonic=12450000\nExecMainExitTimestampMonotonic=28390000\nExecMainStatus=0",
                "Id=maitred.service\nActiveState=active\nSubState=running\nResult=success\n"
                "InactiveExitTimestampMonotonic=12420000\nActiveEnterTimestampMonotonic=12500000\n"
                "ExecMainStartTimestampMonotonic=12480000\nExecMainExitTimestampMonotonic=0\nExecMainStatus=0",
                *[
                    f"Id={u}\nActiveState=active\nSubState=running\nResult=success\n"
                    "InactiveExitTimestampMonotonic=12000000\nActiveEnterTimestampMonotonic=13000000\n"
                    "ExecMainStartTimestampMonotonic=12100000\nExecMainExitTimestampMonotonic=0\nExecMainStatus=0"
                    for u in (
                        "vshd.service",
                        "systemd-logind.service",
                        "ldconfig.service",
                        "user-runtime-dir@1000.service",
                        "user@1000.service",
                    )
                ],
            ]
        )
        sample_diag = (
            "===GUEST_CLOCK_SYNC===\n"
            "uptime_sec=30.00\n"
            "epoch_sec=1030.500000000\n"
            "===GUEST_LIST_JOBS===\n"
            "No jobs running.\n"
            "===GUEST_SYSTEMD_UNIT_SHOW===\n"
            + unit_blocks
            + "\n===GUEST_ANALYZE===\n"
            "Startup finished in 1.2s (kernel) + 1.5s (userspace) = 2.7s\n"
            "===GUEST_CRITICAL_CHAIN===\n"
            "multi-user.target @1.5s\n"
            "===GUEST_BLAME===\n"
            "1.0s first-boot-cros.service\n"
            "===GUEST_USER_ANALYZE===\n"
            "Startup finished in 0.5s (userspace)\n"
            "===GUEST_USER_CRITICAL_CHAIN===\n"
            "default.target @0.5s\n"
            "===GUEST_USER_BLAME===\n"
            "0.2s cros-garcon.service\n"
            "===GUEST_GARCON_STATUS===\n"
            "Active: active (running)\n"
            "===GUEST_JOURNAL_JSON===\n"
            + "\n".join(
                json.dumps(entry)
                for entry in (
                    {
                        "_COMM": "systemd",
                        "MESSAGE": "Started maitred.",
                        "__MONOTONIC_TIMESTAMP": "12500000",
                        "__REALTIME_TIMESTAMP": "1010000000",
                    },
                    {
                        "SYSLOG_IDENTIFIER": "maitred",
                        "MESSAGE": "Received request to setup a new user.",
                        "__MONOTONIC_TIMESTAMP": "13500000",
                        "__REALTIME_TIMESTAMP": "1011000000",
                    },
                    {
                        "SYSLOG_IDENTIFIER": "useradd",
                        "MESSAGE": "new user: name=terminauser, UID=1000, GID=1000",
                        "__MONOTONIC_TIMESTAMP": "15500000",
                        "__REALTIME_TIMESTAMP": "1013000000",
                    },
                    {
                        "SYSLOG_IDENTIFIER": "garcon",
                        "MESSAGE": "Server listening on vsock port",
                        "__MONOTONIC_TIMESTAMP": "19500000",
                        "__REALTIME_TIMESTAMP": "1020000000",
                    },
                )
            )
            + "\n"
        )
        rec = tuf.InitTimelineRecorder(None, "deadbeef")  # type: ignore[arg-type]
        rec.t_install_vm_epoch = 1000.0
        rec._parse_guest_diagnostics(sample_diag, first_host_setup_user_rel=14.0, strict=True)
        self.assertTrue(any("Startup finished" in ln for ln in rec.guest_summary_lines))
        self.assertTrue(any("first-boot-cros.service:" in ln for ln in rec.guest_summary_lines))
        # Verbose sections are formatted from JSON/status and gated on include_raw_logs=True
        self.assertNotIn("[journalctl -b (monotonic, filtered)]", rec.format_report(include_raw_logs=False))
        self.assertIn("[journalctl -b (monotonic, filtered)]", rec.format_report(include_raw_logs=True))
        by_name = {e.name: e for e in rec.all_entries()}
        self.assertAlmostEqual(by_name["MaitredStarted"].rel_sec, 13.0, places=3)
        self.assertAlmostEqual(by_name["MaitredSetUpUser"].rel_sec, 14.0, places=3)
        self.assertAlmostEqual(by_name["UseraddDone"].rel_sec, 16.0, places=3)
        self.assertAlmostEqual(by_name["GarconLog"].rel_sec, 20.0, places=3)
        self.assertIn("UnitStart(first-boot-cros.service)", by_name)
        self.assertIn("UnitDone(first-boot-cros.service)", by_name)

        for desc, bad_diag, exc_cls in (
            (
                "corrupt uptime_sec",
                sample_diag.replace("uptime_sec=30.00", "uptime_sec=not_a_float"),
                ValueError,
            ),
            (
                "empty GUEST_LIST_JOBS",
                sample_diag.replace("No jobs running.\n", ""),
                RuntimeError,
            ),
            (
                "missing user@1000.service in GUEST_SYSTEMD_UNIT_SHOW",
                sample_diag.replace("Id=user@1000.service", "Id=other.service"),
                RuntimeError,
            ),
            (
                "missing MaitredSetUpUser journal entry",
                sample_diag.replace("Received request to setup a new user.", "Unrelated log"),
                RuntimeError,
            ),
        ):
            with self.subTest(desc=desc), self.assertRaises(exc_cls):
                bad_rec = tuf.InitTimelineRecorder(None, "deadbeef")  # type: ignore[arg-type]
                bad_rec.t_install_vm_epoch = 1000.0
                bad_rec._parse_guest_diagnostics(bad_diag, first_host_setup_user_rel=14.0, strict=True)

        # Non-strict mode tolerates incomplete boot diagnostics and formats monotonic journal lines
        partial_rec = tuf.InitTimelineRecorder(None, "deadbeef")  # type: ignore[arg-type]
        partial_rec.t_install_vm_epoch = 1000.0
        partial_rec._parse_guest_diagnostics(
            "===GUEST_CLOCK_SYNC===\nuptime_sec=20.0\nepoch_sec=1025.0\n"
            "===GUEST_JOURNAL_JSON===\n"
            + json.dumps(
                {
                    "SYSLOG_IDENTIFIER": "first-boot-cros",
                    "MESSAGE": "Generating SSH host keys...",
                    "__MONOTONIC_TIMESTAMP": "10000000",
                    "__REALTIME_TIMESTAMP": "1015000000",
                }
            )
            + "\n",
            first_host_setup_user_rel=None,
            strict=False,
        )
        self.assertIn("Generating SSH host keys...", partial_rec.format_report(include_raw_logs=True))
        self.assertTrue(any(e.name == "FirstBootStep" for e in partial_rec.all_entries()))

    def test_scrape_host_logs_negative_rel_and_inflight_setup_user(self) -> None:
        self.assertEqual(tuf._fmt_rel_t(-2.4), "t-   2.4s")

        class _FakeLogVM:
            def ssh(self, cmd: str, **_kw: Any) -> subprocess.CompletedProcess[str]:
                if "/var/log/messages" in cmd:
                    out = (
                        "2026-10-30T16:00:08.500000Z localhost vm_concierge[100]: Found existing disk at /x\n"
                        "2026-10-30T16:00:15.000000Z localhost vm_concierge[100]: Received request: SetUpVmUser\n"
                    )
                else:
                    out = ""
                return subprocess.CompletedProcess(["ssh"], 0, stdout=out, stderr="")

        rec = tuf.InitTimelineRecorder(_FakeLogVM(), "deadbeef")  # type: ignore[arg-type]
        rec.t_install_vm_epoch = tuf.parse_rfc3339_utc("2026-10-30T16:00:10.000000Z")
        rec.scrape_host_logs()
        rep = rec.format_report()
        self.assertIn("t-   1.5s  [concierge] FoundExistingDisk:", rep)
        self.assertIn("t+   5.0s  [concierge] SetUpVmUserInFlight: call #1 still in flight", rep)

    def test_collect_section_rollback_and_idempotency(self) -> None:
        rec = tuf.InitTimelineRecorder(None, "deadbeef")  # type: ignore[arg-type]
        calls: list[str] = []

        rec._collect_section(
            "ok_sec",
            "ok error",
            rec.readonly_summary_lines,
            True,
            lambda: (calls.append("ok"), rec.readonly_summary_lines.append("OK_LINE"))[-1],  # type: ignore[func-returns-value]
            rollback_list=rec.readonly_summary_lines,
        )

        def _fail_midway() -> None:
            calls.append("fail_attempt")
            rec.readonly_summary_lines.append("PARTIAL_LINE")
            raise RuntimeError("boom")

        with self.assertRaises(RuntimeError):
            rec._collect_section(
                "flaky_sec",
                "Flaky section error",
                rec.readonly_summary_lines,
                True,
                _fail_midway,
                rollback_list=rec.readonly_summary_lines,
            )
        # Partial lines from failed strict step are rolled back; ok_sec stays collected
        self.assertEqual(rec.readonly_summary_lines, ["OK_LINE"])
        self.assertIn("ok_sec", rec._collected_sections)
        self.assertNotIn("flaky_sec", rec._collected_sections)

        # Fallback non-strict pass skips ok_sec and records error for flaky_sec
        rec._collect_section(
            "ok_sec",
            "ok error",
            rec.readonly_summary_lines,
            False,
            lambda: calls.append("ok_again"),
            rollback_list=rec.readonly_summary_lines,
        )
        rec._collect_section(
            "flaky_sec",
            "Flaky section error",
            rec.readonly_summary_lines,
            False,
            _fail_midway,
            rollback_list=rec.readonly_summary_lines,
        )
        self.assertEqual(calls, ["ok", "fail_attempt", "fail_attempt"])
        self.assertTrue(any("Flaky section error: boom" in ln for ln in rec.readonly_summary_lines))

    def test_collect_guest_diagnostics_passing_vs_failure_and_vm_timeouts(self) -> None:
        unit_blocks = "\n\n".join(
            f"Id={u}\nActiveState=active\nSubState=running\nResult=success\n"
            "InactiveExitTimestampMonotonic=1000000\nActiveEnterTimestampMonotonic=2000000\n"
            "ExecMainStartTimestampMonotonic=1100000\nExecMainExitTimestampMonotonic=0\nExecMainStatus=0"
            for u in (
                "first-boot-cros.service",
                "maitred.service",
                "vshd.service",
                "systemd-logind.service",
                "ldconfig.service",
                "user-runtime-dir@1000.service",
                "user@1000.service",
            )
        )
        summary_out = (
            "===GUEST_CLOCK_SYNC===\nuptime_sec=25.0\nepoch_sec=1025.0\n"
            "===GUEST_LIST_JOBS===\nNo jobs running.\n"
            f"===GUEST_SYSTEMD_UNIT_SHOW===\n{unit_blocks}\n"
            "===GUEST_ANALYZE===\nStartup finished in 2.0s\n"
            "===GUEST_BLAME===\n0.9s first-boot-cros.service\n"
            "===GUEST_USER_ANALYZE===\nStartup finished in 0.4s\n"
            "===GUEST_USER_BLAME===\n0.2s cros-garcon.service\n"
            "===GUEST_JOURNAL_JSON===\n"
            + json.dumps(
                {
                    "SYSLOG_IDENTIFIER": "maitred",
                    "MESSAGE": "Received request to setup a new user.",
                    "__MONOTONIC_TIMESTAMP": "5000000",
                    "__REALTIME_TIMESTAMP": "1005000000",
                }
            )
            + "\n"
        )
        vsh_calls: list[tuple[str, int, str | None]] = []

        class _FakeDiagVM:
            def vsh(
                self, _vm: str, _user: str, sh_script: str, *, check: bool = True, timeout: int = 60, op_desc: str | None = None
            ) -> subprocess.CompletedProcess[str]:
                vsh_calls.append((sh_script, timeout, op_desc))
                if not check and op_desc == "guest_diag:user":
                    raise tuf.VMCommandTimeoutError("VM command timed out (operation='guest_diag:user' step='step5:collect_guest_diag')")
                extra = "===GUEST_CRITICAL_CHAIN===\nmulti-user.target @1.5s\n" if not check else ""
                return subprocess.CompletedProcess(["vsh"], 0, stdout=summary_out + extra, stderr="")

        pass_rec = tuf.InitTimelineRecorder(_FakeDiagVM(), "deadbeef")  # type: ignore[arg-type]
        pass_rec.t_install_vm_epoch = 1000.0
        pass_rec._collect_guest_diagnostics(first_host_setup_user_rel=6.0, strict_dbus=True)
        self.assertEqual(len(vsh_calls), 1)
        sh_pass, pass_timeout, pass_op = vsh_calls[0]
        self.assertEqual(pass_timeout, 120)
        self.assertEqual(pass_op, "guest_diag:summary")
        self.assertIn("--output-fields=MESSAGE,_COMM,SYSLOG_IDENTIFIER,_SYSTEMD_UNIT,UNIT", sh_pass)
        self.assertNotIn("critical-chain", sh_pass)
        self.assertNotIn("systemctl --user status", sh_pass)
        self.assertEqual(pass_rec.guest_verbose_lines, [])

        # Passing path strictly propagates guest diagnostic timeout
        class _HungVM:
            def vsh(self, *_a: Any, **_kw: Any) -> subprocess.CompletedProcess[str]:
                raise tuf.VMCommandTimeoutError("VM command timed out (operation='guest_diag:summary')")

        with self.assertRaises(tuf.VMCommandTimeoutError):
            tuf.InitTimelineRecorder(_HungVM(), "deadbeef")._collect_guest_diagnostics(6.0, strict_dbus=True)  # type: ignore[arg-type]

        # Failure path fetches verbose dumps and records timeouts without masking primary exception
        vsh_calls.clear()
        fail_rec = tuf.InitTimelineRecorder(_FakeDiagVM(), "deadbeef")  # type: ignore[arg-type]
        fail_rec.t_install_vm_epoch = 1000.0
        fail_rec._collect_guest_diagnostics(first_host_setup_user_rel=6.0, strict_dbus=False)
        self.assertEqual([c[2] for c in vsh_calls], ["guest_diag:system", "guest_diag:user"])
        self.assertIn("critical-chain", vsh_calls[0][0])
        self.assertIn("systemctl --user status", vsh_calls[1][0])
        self.assertTrue(any("guest_diag:user" in ln for ln in fail_rec.guest_summary_lines))
        self.assertTrue(any("critical-chain" in ln for ln in fail_rec.guest_verbose_lines))

        # ChromeOSVM.ssh / vsh / scp_to / wait_for_ssh wrap subprocess.TimeoutExpired with context
        vm = object.__new__(tuf.ChromeOSVM)
        vm.ssh_key = Path("/tmp/testing_rsa")
        vm.ssh_port = 42222
        vm.owner_hash = "deadbeef"
        vm._current_step = "step5:collect_guest_diag"
        with mock.patch.object(
            tuf.subprocess,
            "run",
            side_effect=subprocess.TimeoutExpired(cmd=["ssh"], timeout=120, stderr="vsh launch hung\n"),
        ):
            with self.assertRaises(tuf.VMCommandTimeoutError) as ctx_vsh:
                vm.vsh("termina", "root", "journalctl -b -o json", timeout=120, op_desc="guest_diag:summary")
            msg = str(ctx_vsh.exception)
            self.assertNotIsInstance(ctx_vsh.exception, subprocess.TimeoutExpired)
            for tok in (
                "operation='guest_diag:summary'",
                "step='step5:collect_guest_diag'",
                "cmd='journalctl -b -o json'",
                "timeout=120.0s",
                "vsh launch hung",
            ):
                self.assertIn(tok, msg)

            with self.assertRaises(tuf.VMCommandTimeoutError) as ctx_scp:
                vm.scp_to(Path("/tmp/baguette.img.zst"), "/home/user/x/baguette.img.zst", timeout=15, op_desc="prepare:scp")
            self.assertIn("operation='prepare:scp'", str(ctx_scp.exception))
            self.assertIn("baguette.img.zst -> /home/user/x/baguette.img.zst", str(ctx_scp.exception))

            vm._current_step = "prepare:boot_cros_vm"
            clock = iter([0.0, 0.0, 0.1, 0.2, 2.0, 2.0])
            with mock.patch.object(tuf.time, "sleep"), mock.patch.object(tuf.time, "monotonic", side_effect=lambda: next(clock, 2.0)):
                with self.assertRaises(tuf.VMCommandTimeoutError) as ctx_wssh:
                    vm.wait_for_ssh(timeout_sec=1)
            self.assertIn("operation='wait_for_ssh'", str(ctx_wssh.exception))
            self.assertIn("step='prepare:boot_cros_vm'", str(ctx_wssh.exception))


class CDPClientMockTests(unittest.TestCase):
    FAKE_TGT = {
        "id": "9F2A1B",
        "url": "chrome-untrusted://terminal/html/terminal.html?command=vmshell",
        "webSocketDebuggerUrl": "ws://127.0.0.1:41234/devtools/page/9F2A1B",
    }

    def test_cdp_timeout_and_error_wrapping(self) -> None:
        with self.assertRaises(tuf.CDPTimeoutError) as ctx_conn:
            tuf.CDPConnection.from_target(
                self.FAKE_TGT,
                label="Terminal-App-Initial",
                timeout=12.0,
                step_getter=lambda: "step3:observe_initial_terminal",
                connect_fn=lambda *_a, **_kw: (_ for _ in ()).throw(
                    WebSocketTimeoutException("Connection timed out")
                ),
            )
        for tok in (
            "WebSocket.connect",
            "Terminal-App-Initial",
            "chrome-untrusted://terminal/html/terminal.html?command=vmshell",
            "9F2A1B",
            "step3:observe_initial_terminal",
            "waited=",
        ):
            self.assertIn(tok, str(ctx_conn.exception))

        hung_tab = tuf.CroshTab(
            "Terminal-App-Initial",
            tuf.CDPConnection.from_target(
                self.FAKE_TGT,
                label="Terminal-App-Initial",
                timeout=30.0,
                step_getter=lambda: "step3:observe_initial_terminal",
                connect_fn=lambda *_a, **_kw: _FakeWS([WebSocketTimeoutException("")]),
            ),
        )
        with self.assertRaises(tuf.CDPTimeoutError) as ctx_recv:
            hung_tab.get_text()
        for tok in (
            "Terminal-App-Initial.get_text",
            "Runtime.evaluate#1",
            "target='Terminal-App-Initial'",
            "target_id='9F2A1B'",
            "step='step3:observe_initial_terminal'",
            "waited=",
        ):
            self.assertIn(tok, str(ctx_recv.exception))

        for desc, frames, kind in (
            ("closed socket", [WebSocketConnectionClosedException("closed")], "call"),
            ("empty EOF frame", [], "call"),
            (
                "CDP protocol error",
                [json.dumps({"id": 1, "error": {"code": -32000, "message": "Target closed"}})],
                "call",
            ),
            (
                "JS exceptionDetails",
                [json.dumps({"id": 1, "result": {"exceptionDetails": {"text": "TypeError"}}})],
                "eval_js",
            ),
        ):
            with self.subTest(desc=desc), self.assertRaises(tuf.CDPError) as ctx_err:
                conn = tuf.CDPConnection.from_target(
                    self.FAKE_TGT,
                    label="Crostini-Installer",
                    timeout=15.0,
                    step_getter=lambda: "step2:wait_installer_complete",
                    connect_fn=lambda *_a, _f=frames, **_kw: _FakeWS(_f),
                )
                if kind == "call":
                    conn.call("DOM.getDocument", op_desc="Installer:getDocument")
                else:
                    conn.eval_js("window.boom()", op_desc="Installer:poll_status")
            for tok in (
                "target='Crostini-Installer'",
                "target_id='9F2A1B'",
                "step='step2:wait_installer_complete'",
                "waited=",
            ):
                self.assertIn(tok, str(ctx_err.exception))

        # allow_error=True returns error object instead of raising
        allow_conn = tuf.CDPConnection.from_target(
            self.FAKE_TGT,
            label="Browser-LaunchOSSettings",
            connect_fn=lambda *_a, **_kw: _FakeWS(
                [json.dumps({"id": 1, "error": {"code": -32000, "message": "Failed to open a new tab"}})]
            ),
        )
        res = allow_conn.call("Target.createTarget", allow_error=True)
        self.assertEqual(res["error"]["code"], -32000)

    def test_poll_js_wait_for_and_wait_for_cdp_target(self) -> None:
        poll_conn = tuf.CDPConnection.from_target(
            self.FAKE_TGT,
            label="Crostini-Installer",
            step_getter=lambda: "step2:installer_click_next",
            connect_fn=lambda *_a, **_kw: _FakeWS(
                [
                    json.dumps({"id": 1, "result": {"result": {"value": "no-next"}}}),
                    json.dumps({"id": 2, "result": {"result": {"value": "CLICKED_NEXT"}}}),
                ]
            ),
        )
        self.assertEqual(
            poll_conn.poll_js(
                "click()",
                lambda v: v == "CLICKED_NEXT",
                op_desc="Crostini-Installer:click_next",
                timeout=2.0,
                interval=0.01,
            ),
            "CLICKED_NEXT",
        )

        timeout_poll = tuf.CDPConnection.from_target(
            self.FAKE_TGT,
            label="OS-Settings",
            step_getter=lambda: "step2:navigate_os_settings_click_setup",
            connect_fn=lambda *_a, **_kw: _FakeWS(
                [
                    json.dumps({"id": i, "result": {"result": {"value": "no-ui"}}})
                    for i in range(1, 30)
                ]
            ),
        )
        with self.assertRaises(tuf.CDPTimeoutError) as ctx_poll:
            timeout_poll.poll_js(
                "nav()",
                lambda v: v == "CLICKED_SETUP",
                op_desc="OS-Settings:navigate_and_click_setup",
                timeout=0.05,
                interval=0.01,
            )
        self.assertIn("last state='no-ui'", str(ctx_poll.exception))

        wait_tab = tuf.CroshTab(
            "Termina-Crosh",
            tuf.CDPConnection.from_target(
                self.FAKE_TGT,
                label="Termina-Crosh",
                step_getter=lambda: "step4:crosh_vsh_reentry",
                connect_fn=lambda *_a, **_kw: _FakeWS(
                    [
                        json.dumps({"id": i, "result": {"result": {"value": "[===  ] Starting VM..."}}})
                        for i in range(1, 20)
                    ]
                ),
            ),
        )
        with self.assertRaises(tuf.CDPTimeoutError) as ctx_wait:
            wait_tab.wait_for(lambda txt: "crosh>" in txt, timeout=0.08, desc="crosh> prompt")
        for tok in ("Termina-Crosh.wait_for(crosh> prompt)", "[===  ] Starting VM..."):
            self.assertIn(tok, str(ctx_wait.exception))

        # ChromeOSVM.wait_for_cdp_target positive & timeout
        dummy_vm = object.__new__(tuf.ChromeOSVM)
        dummy_vm._current_step = "step2:attach_crostini_installer"
        batches = [[], [self.FAKE_TGT]]
        dummy_vm.list_cdp_targets = lambda timeout=20.0: batches.pop(0) if batches else []  # type: ignore[method-assign]
        found = dummy_vm.wait_for_cdp_target(
            lambda t: t.get("id") == "9F2A1B",
            operation="find_target(test)",
            target_label="TestTarget",
            target_url="chrome://test/",
            timeout=1.0,
            interval=0.01,
        )
        self.assertEqual(found["id"], "9F2A1B")

        with self.assertRaises(tuf.CDPTimeoutError) as ctx_tgt:
            dummy_vm.wait_for_cdp_target(
                lambda _t: False,
                operation="find_target(missing)",
                target_label="MissingTarget",
                target_url="chrome://missing/",
                timeout=0.04,
                interval=0.01,
            )
        self.assertIn("step='step2:attach_crostini_installer'", str(ctx_tgt.exception))


class ResourceDiagnosticsAndQemuPidTests(unittest.TestCase):
    def _sample_json_dict(self, **overrides: Any) -> dict[str, Any]:
        base: dict[str, Any] = {
            "nproc": 2,
            "clk_tck": 100,
            "uptime_sec": 50.0,
            "load1": 0.40,
            "stat_cpu": "cpu  500 0 200 9200 50 10 10 30 0 0",
            "psi": {
                "cpu": ["some avg10=1.50 avg60=0.50 avg300=0.10 total=100000"],
                "memory": [
                    "some avg10=0.00 avg60=0.00 avg300=0.00 total=10000",
                    "full avg10=0.00 avg60=0.00 avg300=0.00 total=5000",
                ],
                "io": [
                    "some avg10=0.20 avg60=0.10 avg300=0.00 total=200000",
                    "full avg10=0.10 avg60=0.05 avg300=0.00 total=150000",
                ],
            },
            "mem_kib": {
                "MemTotal": 4096000,
                "MemAvailable": 2800000,
                "SwapTotal": 6144000,
                "SwapFree": 6133760,
                "Dirty": 512,
                "Writeback": 0,
            },
            "proc_dt_sec": 0.0,
            "top_procs": [],
        }
        base.update(overrides)
        return base

    def test_resource_parsers_summary_and_downsampling(self) -> None:
        host_amd = tuf.parse_host_runner_info(
            "processor\t: 0\nvendor_id\t: AuthenticAMD\nmodel name\t: AMD EPYC 7763 64-Core Processor\n",
            "MemTotal:       16384000 kB\nMemAvailable:   12288000 kB\n",
            4,
        )
        self.assertEqual(host_amd.vendor_id, "AuthenticAMD")
        self.assertAlmostEqual(host_amd.mem_total_mib, 16000.0, places=2)

        c0 = tuf.parse_proc_stat_cpu_line("cpu  100 10 50 800 20 5 5 10 30 0\n", "c0", clk_tck=100)
        c1 = tuf.parse_proc_stat_cpu_line("cpu  250 10 100 830 50 5 5 50 80 0\n", "c1", clk_tck=100)
        c2 = tuf.parse_proc_stat_cpu_line("cpu  450 10 180 860 50 5 5 50 80 0\n", "c2", clk_tck=100)
        cdelta = tuf.compute_cpu_delta_pct(c0, c1)
        self.assertAlmostEqual(cdelta.busy_pct, 200.0 / 3.0, places=2)
        self.assertAlmostEqual(cdelta.iowait_pct, 10.0, places=2)
        self.assertAlmostEqual(cdelta.steal_pct, 40.0 / 3.0, places=2)
        self.assertAlmostEqual(cdelta.steal_sec, 0.40, places=3)

        rs0 = tuf.parse_cros_resource_json(
            json.dumps(self._sample_json_dict()),
            mono_ts=99.0,
            rel_sec=-1.0,
            host_cpu=c0,
            host_load1=1.2,
            host_mem_avail_mib=12000.0,
        )
        stressed_mem = {
            "MemTotal": 4096000, "MemAvailable": 420000, "SwapTotal": 6144000,
            "SwapFree": 5900000, "Dirty": 16384, "Writeback": 4096,
        }
        rs1 = tuf.parse_cros_resource_json(
            json.dumps(self._sample_json_dict(
                uptime_sec=60.0, load1=3.20,
                stat_cpu="cpu  1900 0 500 9350 150 10 10 80 1100 0",
                psi={
                    "cpu": ["some avg10=48.00 avg60=15.00 avg300=4.00 total=3600000", "full avg10=0.00 avg60=0.00 avg300=0.00 total=0"],
                    "memory": ["some avg10=6.50 avg60=2.00 avg300=0.50 total=610000", "full avg10=2.10 avg60=0.80 avg300=0.20 total=205000"],
                    "io": ["some avg10=18.40 avg60=5.00 avg300=1.00 total=1700000", "full avg10=12.00 avg60=3.50 avg300=0.70 total=1150000"],
                },
                mem_kib=stressed_mem,
                proc_dt_sec=10.0,
                top_procs=[
                    {"pid": 0, "comm": "crosvm", "hint": "3p:run,v_wl", "ticks": 1400},
                    {"pid": 2745, "comm": "chrome", "hint": "--type=gpu-process(swiftshader)", "ticks": 300},
                    {"pid": 2707, "comm": "chrome", "hint": "browser", "ticks": 150},
                ],
            )),
            mono_ts=109.0, rel_sec=9.0, host_cpu=c1, host_load1=2.4, host_mem_avail_mib=11500.0,
        )
        rs2 = tuf.parse_cros_resource_json(
            json.dumps(self._sample_json_dict(
                uptime_sec=70.0, load1=4.80,
                stat_cpu="cpu  3100 0 900 9400 150 10 10 80 1100 0",
                psi={
                    "cpu": ["some avg10=60.00 avg60=25.00 avg300=8.00 total=7600000"],
                    "memory": ["some avg10=6.50 avg60=2.00 avg300=0.50 total=610000", "full avg10=2.10 avg60=0.80 avg300=0.20 total=205000"],
                    "io": ["some avg10=18.40 avg60=5.00 avg300=1.00 total=3200000", "full avg10=12.00 avg60=3.50 avg300=0.70 total=2150000"],
                },
                mem_kib=stressed_mem,
                proc_dt_sec=10.0,
                top_procs=[
                    {"pid": 3102, "comm": "chrome", "hint": "--type=gpu-process(swiftshader)", "ticks": 900},
                    {"pid": 4866, "comm": "crash_reporter", "hint": "--user=2745:6:1000:1000:chrome", "ticks": 600},
                    {"pid": 0, "comm": "crosvm", "hint": "2p:run", "ticks": 400},
                ],
            )),
            mono_ts=119.0, rel_sec=19.0, host_cpu=c2, host_load1=2.6, host_mem_avail_mib=11400.0,
        )

        # Compact green-run summary includes aggregate top CPU (whole run + post-InstallerClosed)
        # and omits per-sample rows/top=[...]
        compact = "\n".join(
            tuf.summarize_resource_diagnostics(
                host_amd,
                [rs0, rs1, rs2],
                install_mono=100.0,
                installer_closed_rel_sec=9.0,
                strict=True,
                include_samples=False,
            )
        )
        self.assertIn("vendor=AuthenticAMD", compact)
        self.assertIn("ChromeOS top CPU (run, sampled=20.0s, 100%=1vCPU):", compact)
        self.assertIn("crosvm[3p:run,v_wl]=18.00s(90.0%)", compact)
        self.assertIn("chrome[2pids](--type=gpu-process(swiftshader))=12.00s(60.0%)", compact)
        self.assertIn("ChromeOS top CPU (post-InstallerClosed t+9.0s+, sampled=10.0s):", compact)
        self.assertIn("chrome#3102(--type=gpu-process(swiftshader))=9.00s(90.0%)", compact)
        self.assertIn("crash_reporter#4866(--user=2745:6:1000:1000:chrome)=6.00s(60.0%)", compact)
        self.assertIn("CPU-contention", compact)
        self.assertIn("IO-stall", compact)
        self.assertIn("memory/reclaim", compact)
        self.assertNotIn("[periodic samples", compact)
        self.assertNotIn("top=[", compact)

        verbose = "\n".join(
            tuf.summarize_resource_diagnostics(
                host_amd,
                [rs0, rs1, rs2],
                install_mono=100.0,
                installer_closed_rel_sec=9.0,
                strict=True,
                include_samples=True,
            )
        )
        self.assertIn("[periodic samples (3/3 shown", verbose)
        self.assertIn("top=[crosvm[3p:run,v_wl]:140%", verbose)
        self.assertIn("top=[chrome#3102(--type=gpu-process(swiftshader)):90%", verbose)

        # Strict vs non-strict checks (including missing interval proc_dt_sec > 0)
        rs1_zero_dt = dataclasses.replace(rs1, proc_dt_sec=0.0, top_procs=())
        for desc, kwargs in (
            ("only 1 sample", {"host_info": host_amd, "samples": [rs0], "install_mono": 100.0}),
            (
                "no sample with proc_dt_sec > 0",
                {"host_info": host_amd, "samples": [rs0, rs1_zero_dt], "install_mono": 100.0},
            ),
            (
                "sampler warning present",
                {
                    "host_info": host_amd,
                    "samples": [rs0, rs1],
                    "install_mono": 100.0,
                    "sampler_warnings": ["ssh exited rc=255"],
                },
            ),
            ("missing host_info", {"host_info": None, "samples": [rs0, rs1], "install_mono": 100.0}),
        ):
            with self.subTest(desc=desc):
                with self.assertRaises(RuntimeError):
                    tuf.summarize_resource_diagnostics(**kwargs, strict=True)  # type: ignore[arg-type]
                self.assertGreaterEqual(
                    len(tuf.summarize_resource_diagnostics(**kwargs, strict=False)),  # type: ignore[arg-type]
                    1,
                )

        # Negative parser checks (boolean-as-int, bounds, >5 top_procs, crosvm grouping invariants)
        def _parse_override(**kw: Any) -> tuf.CrosResourceSample:
            return tuf.parse_cros_resource_json(
                json.dumps(self._sample_json_dict(**kw)),
                mono_ts=1.0,
                rel_sec=0.0,
                host_cpu=c0,
                host_load1=1.0,
                host_mem_avail_mib=1000.0,
            )

        neg_cases: list[tuple[str, Any]] = [
            ("missing CPU vendor_id", lambda: tuf.parse_host_runner_info("model name : X\n", "MemTotal: 100 kB\nMemAvailable: 50 kB\n", 2)),
            ("short /proc/stat line", lambda: tuf.parse_proc_stat_cpu_line("cpu 1 2 3\n", "bad")),
            ("backwards CPU ticks", lambda: tuf.compute_cpu_delta_pct(c1, c0)),
            ("boolean as int for nproc", lambda: _parse_override(nproc=True)),
            ("boolean for proc_dt_sec", lambda: _parse_override(proc_dt_sec=True)),
            ("negative proc_dt_sec", lambda: _parse_override(proc_dt_sec=-0.1)),
            ("non-empty top_procs with proc_dt_sec=0", lambda: _parse_override(proc_dt_sec=0.0, top_procs=[{"pid": 10, "comm": "chrome", "hint": "browser", "ticks": 5}])),
            (">5 entries in top_procs", lambda: _parse_override(proc_dt_sec=1.0, top_procs=[{"pid": 10 + i, "comm": "p", "hint": "", "ticks": 10 - i} for i in range(6)])),
            ("boolean pid in top_procs", lambda: _parse_override(proc_dt_sec=1.0, top_procs=[{"pid": True, "comm": "chrome", "hint": "", "ticks": 5}])),
            ("boolean ticks in top_procs", lambda: _parse_override(proc_dt_sec=1.0, top_procs=[{"pid": 10, "comm": "chrome", "hint": "", "ticks": True}])),
            ("zero ticks in top_procs", lambda: _parse_override(proc_dt_sec=1.0, top_procs=[{"pid": 10, "comm": "chrome", "hint": "", "ticks": 0}])),
            ("pid=0 on non-crosvm", lambda: _parse_override(proc_dt_sec=1.0, top_procs=[{"pid": 0, "comm": "chrome", "hint": "browser", "ticks": 5}])),
            ("ungrouped crosvm pid > 0", lambda: _parse_override(proc_dt_sec=1.0, top_procs=[{"pid": 3825, "comm": "crosvm", "hint": "1p:run", "ticks": 5}])),
            ("duplicate crosvm entries", lambda: _parse_override(proc_dt_sec=1.0, top_procs=[{"pid": 0, "comm": "crosvm", "hint": "1p:run", "ticks": 10}, {"pid": 0, "comm": "crosvm", "hint": "1p:v_wl", "ticks": 5}])),
            ("extra key in top_procs item", lambda: _parse_override(proc_dt_sec=1.0, top_procs=[{"pid": 10, "comm": "c", "hint": "", "ticks": 5, "x": 1}])),
            ("unexpected extra top-level key", lambda: _parse_override(extra_key=1)),
            ("missing psi.io", lambda: _parse_override(psi={"cpu": ["some avg10=0.0 avg60=0.0 avg300=0.0 total=0"], "memory": ["some avg10=0.0 avg60=0.0 avg300=0.0 total=0", "full avg10=0.0 avg60=0.0 avg300=0.0 total=0"]})),
            ("missing MemAvailable in mem_kib", lambda: _parse_override(mem_kib={"MemTotal": 4096000, "SwapTotal": 1024, "SwapFree": 1024, "Dirty": 0, "Writeback": 0})),
        ]
        for desc, fn in neg_cases:
            with self.subTest(desc=desc), self.assertRaises(ValueError):
                fn()

        # Downsampling cap (<=24 rows) + displayed-row delta & top_procs preservation across skipped samples
        for test_n in (25, 33, 45, 60, 89):
            many = [
                dataclasses.replace(
                    rs0,
                    mono_ts=100.0 + i,
                    rel_sec=float(i),
                    uptime_sec=50.0 + i,
                    load1=99.0 if i == 19 else 0.4,
                    cros_cpu=dataclasses.replace(
                        rs0.cros_cpu, user=rs0.cros_cpu.user + i * 20, idle=rs0.cros_cpu.idle + i * 80
                    ),
                    host_cpu=dataclasses.replace(
                        rs0.host_cpu, user=rs0.host_cpu.user + i * 20, idle=rs0.host_cpu.idle + i * 80
                    ),
                    swap_free_kib=6133760 - (51200 if i >= 18 else 0),
                    proc_dt_sec=0.0 if i == 0 else 1.0,
                    top_procs=(
                        (tuf.CrosTopProc(4866, "crash_reporter", "--user=chrome", 95),)
                        if i == 18
                        else ((tuf.CrosTopProc(0, "crosvm", "2p:run", 20),) if i > 0 else ())
                    ),
                )
                for i in range(test_n)
            ]
            sel = tuf._select_sample_indices(many, max_rows=24)
            self.assertLessEqual(len(sel), 24)
            self.assertEqual(sel[0], 0)
            self.assertEqual(sel[-1], test_n - 1)
            self.assertIn(19, sel)
            if test_n == 89:
                self.assertNotIn(18, sel)
                ds_out = "\n".join(
                    tuf.summarize_resource_diagnostics(
                        host_amd, many, install_mono=100.0, strict=True, include_samples=True
                    )
                )
                self.assertIn("(+50MiB)", ds_out)
                self.assertIn("crash_reporter#4866(--user=chrome)", ds_out)

    def test_remote_sampler_script_top_procs_and_crosvm_grouping(self) -> None:
        def _write_stat(proc_dir: Path, pid: int, comm: str, utime: int, stime: int, start: int, cmdline: bytes) -> None:
            d = proc_dir / str(pid)
            d.mkdir(exist_ok=True)
            fields_after_comm = ["S"] + ["0"] * 10 + [str(utime), str(stime)] + ["0"] * 6 + [str(start)] + ["0"] * 20
            (d / "stat").write_bytes(f"{pid} ({comm}) {' '.join(fields_after_comm)}\n".encode("utf-8"))
            (d / "cmdline").write_bytes(cmdline)

        with tempfile.TemporaryDirectory() as tmp_str:
            fp = Path(tmp_str)
            (fp / "pressure").mkdir()
            (fp / "pressure/cpu").write_text("some avg10=1.00 avg60=0.50 avg300=0.10 total=1000\n", encoding="utf-8")
            for p in ("memory", "io"):
                (fp / f"pressure/{p}").write_text("some avg10=0.00 avg60=0.00 avg300=0.00 total=0\nfull avg10=0.00 avg60=0.00 avg300=0.00 total=0\n", encoding="utf-8")
            (fp / "loadavg").write_text("2.50 1.00 0.50 2/200 5000\n", encoding="utf-8")
            (fp / "stat").write_text("cpu  100 0 50 900 0 0 0 0 0 0\n", encoding="utf-8")
            (fp / "meminfo").write_text("MemTotal: 4096000 kB\nMemAvailable: 3000000 kB\nSwapTotal: 1024 kB\nSwapFree: 1024 kB\nDirty: 0 kB\nWriteback: 0 kB\n", encoding="utf-8")
            (fp / "uptime").write_text("100.00 380.00\n", encoding="utf-8")
            for pid, comm, u, s, st, cl in (
                (3800, "crosvm", 200, 50, 1000, b"/usr/bin/crosvm\x00--syslog-tag\x00VM(32)\x00run\x00"),
                (3801, "v_wl", 40, 10, 1002, b"/usr/bin/crosvm\x00--syslog-tag\x00VM(32)\x00run\x00"),
                (3802, "crosvm", 10, 5, 1003, b"/usr/bin/crosvm\x00device\x00block\x00--socket=/x\x00"),
                (2700, "chrome", 100, 20, 500, b"/opt/google/chrome/chrome\x00--enable-wayland-server\x00"),
                (2740, "chrome", 80, 10, 510, b"/opt/google/chrome/chrome --type=gpu-process --homedir=/home/chronos/u-abc --use-angle=swiftshader\x00*=2,chrome_browser_main_posix=2\x00"),
                (2760, "chrome", 20, 5, 520, b"/opt/google/chrome/chrome\x00--type=utility\x00--utility-sub-type=network.mojom.NetworkService\x00"),
                (900, "(odd) worker", 50, 0, 600, b""),
            ):
                _write_stat(fp, pid, comm, u, s, st, cl)

            script_head = tuf._CROS_RESOURCE_PY_SCRIPT.split("\nif len(sys.argv)", 1)[0]
            prev_env = os.environ.get("CROS_RES_PROC_ROOT")
            os.environ["CROS_RES_PROC_ROOT"] = str(fp)
            try:
                ns: dict[str, Any] = {}
                exec(script_head, ns)
                buf0, buf1 = io.StringIO(), io.StringIO()
                with contextlib.redirect_stdout(buf0):
                    ns["emit_once"]()
                (fp / "uptime").write_text("105.00 395.00\n", encoding="utf-8")
                for pid, comm, u, s, st, cl in (
                    (3800, "crosvm", 450, 100, 1000, b"/usr/bin/crosvm\x00--syslog-tag\x00VM(32)\x00run\x00"),
                    (3801, "v_wl", 90, 20, 1002, b"/usr/bin/crosvm\x00--syslog-tag\x00VM(32)\x00run\x00"),
                    (3802, "crosvm", 20, 10, 1003, b"/usr/bin/crosvm\x00device\x00block\x00--socket=/x\x00"),
                    (2700, "chrome", 140, 30, 500, b"/opt/google/chrome/chrome\x00--enable-wayland-server\x00"),
                    (2740, "chrome", 260, 30, 510, b"/opt/google/chrome/chrome --type=gpu-process --homedir=/home/chronos/u-abc --use-angle=swiftshader\x00*=2,chrome_browser_main_posix=2\x00"),
                    (2760, "chrome", 30, 5, 520, b"/opt/google/chrome/chrome\x00--type=utility\x00--utility-sub-type=network.mojom.NetworkService\x00"),
                    (900, "(odd) worker", 25, 0, 10200, b""),
                    (4866, "crash_reporter", 110, 10, 10150, b"/sbin/crash_reporter\x00--user=2740:6:chrome\x00"),
                    (55, "old_missed", 9999, 0, 100, b"/sbin/old\x00"),
                ):
                    _write_stat(fp, pid, comm, u, s, st, cl)
                with contextlib.redirect_stdout(buf1):
                    ns["emit_once"]()
            finally:
                if prev_env is None:
                    os.environ.pop("CROS_RES_PROC_ROOT", None)
                else:
                    os.environ["CROS_RES_PROC_ROOT"] = prev_env

            host_cpu = tuf.parse_proc_stat_cpu_line("cpu 10 0 10 100 0 0 0 0 0 0\n", "h")
            s0 = tuf.parse_cros_resource_json(
                buf0.getvalue().strip(), mono_ts=1.0, rel_sec=0.0, host_cpu=host_cpu, host_load1=0.5, host_mem_avail_mib=8000.0
            )
            self.assertEqual(s0.proc_dt_sec, 0.0)
            self.assertEqual(s0.top_procs, ())

            s1 = tuf.parse_cros_resource_json(
                buf1.getvalue().strip(), mono_ts=6.0, rel_sec=5.0, host_cpu=host_cpu, host_load1=0.5, host_mem_avail_mib=8000.0
            )
            self.assertAlmostEqual(s1.proc_dt_sec, 5.0, places=3)
            self.assertEqual(len(s1.top_procs), 5)
            # #1: grouped crosvm = (550-250) + (110-50) + (30-15) = 300 + 60 + 15 = 375 ticks
            self.assertEqual(s1.top_procs[0], tuf.CrosTopProc(0, "crosvm", "3p:run,v_wl,device:block", 375))
            # #2: chrome gpu-process = 290 - 90 = 200 ticks
            self.assertEqual(s1.top_procs[1], tuf.CrosTopProc(2740, "chrome", "--type=gpu-process(swiftshader)", 200))
            # #3: newly spawned crash_reporter = 120 ticks
            self.assertEqual(s1.top_procs[2], tuf.CrosTopProc(4866, "crash_reporter", "--user=2740:6:chrome", 120))
            # #4: chrome browser = 170 - 120 = 50 ticks
            self.assertEqual(s1.top_procs[3], tuf.CrosTopProc(2700, "chrome", "browser", 50))
            # #5: reused PID 900 `(odd) worker` = 25 ticks (old_missed PID 55 had dt=0)
            self.assertEqual(s1.top_procs[4], tuf.CrosTopProc(900, "(odd) worker", "kthread", 25))

    def test_pid_matches_qemu(self) -> None:
        with tempfile.TemporaryDirectory() as fake_proc_str:
            fp = Path(fake_proc_str)
            for pid_num, comm_txt, cmdline_bytes in (
                (101, "qemu-system-x86", b"/usr/bin/qemu-system-x86_64\x00-enable-kvm\x00"),
                (102, "kvm", b"/usr/bin/kvm\x00-m\x004G\x00"),
                (103, "my-custom-vmm", b"/opt/vmm/my-custom-vmm\x00-daemonize\x00"),
                (104, "kvm-pit/101", b""),
                (105, "python3", b"python3\x00-m\x00http.server\x00"),
            ):
                d = fp / str(pid_num)
                d.mkdir()
                (d / "comm").write_text(comm_txt + "\n", encoding="utf-8")
                (d / "cmdline").write_bytes(cmdline_bytes)
            self.assertTrue(tuf._pid_matches_qemu(101, "qemu-system-x86_64", proc_root=fp))
            self.assertTrue(tuf._pid_matches_qemu(102, "/usr/bin/kvm", proc_root=fp))
            self.assertTrue(tuf._pid_matches_qemu(103, "/opt/vmm/my-custom-vmm", proc_root=fp))
            self.assertFalse(tuf._pid_matches_qemu(104, "/usr/bin/kvm", proc_root=fp))
            self.assertFalse(tuf._pid_matches_qemu(105, "qemu-system-x86_64", proc_root=fp))


if __name__ == "__main__":
    unittest.main()
