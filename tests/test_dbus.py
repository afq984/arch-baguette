"""Offline unit tests for `scripts/user_flows/dbus.py`."""

from __future__ import annotations

import shutil
import sys
import tempfile
import time
import unittest
from pathlib import Path
from typing import Any

SCRIPTS_DIR = Path(__file__).resolve().parent.parent / "scripts"
if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))

from user_flows import DEFAULT_PROTO_DIR, FlowDiagnosticsObserver, dbus  # noqa: E402

_METHOD_RET_HDR = "method return time=1.0 sender=:1.1 -> destination=:1.2 serial=1 reply_serial=1\n"


def _sig_hdr(member: str, iface: str = "org.chromium.VmCicerone") -> str:
    return (
        f"signal time=1.0 sender=:1.1 -> destination=(null destination) serial=1 "
        f"path=/org/chromium/{iface.split('.')[-1]}; interface={iface}; member={member}"
    )


class VendoredProtosAndLsbTests(unittest.TestCase):
    def test_vendored_protos_and_lsb_release_matching(self) -> None:
        protos = dbus.load_cros_protos(DEFAULT_PROTO_DIR)
        meta = protos.metadata

        with tempfile.TemporaryDirectory() as tmp_pdir:
            copied = Path(tmp_pdir) / "protos"
            shutil.copytree(DEFAULT_PROTO_DIR, copied)
            tampered = copied / "arc/arc.proto"
            tampered.write_text(tampered.read_text(encoding="utf-8") + "\n// tampered\n", encoding="utf-8")
            with self.assertRaises(RuntimeError):
                dbus.verify_vendored_protos(copied)

        with self.assertRaises(RuntimeError):
            dbus.parse_cros_release_str("156-16827.0.0")

        board, rel = str(meta["board"]), str(meta["cros_release"])
        ms, ver = dbus.parse_cros_release_str(rel)
        bad_ms, bad_ver = str(int(ms) - 1), "0.0.0"
        mk_lsb = lambda b, r, m, v: (
            f"CHROMEOS_RELEASE_BUILDER_PATH={b}/{r}\n"
            f"CHROMEOS_RELEASE_CHROME_MILESTONE={m}\n"
            f"CHROMEOS_RELEASE_VERSION={v}\n"
        )
        dbus.verify_lsb_release_matches_metadata(mk_lsb(board, rel, ms, ver), meta)

        for desc, bad_lsb, exc_cls in (
            ("wrong release", mk_lsb(board, f"R{bad_ms}-{bad_ver}", bad_ms, bad_ver), RuntimeError),
            ("mismatched milestone vs builder path", mk_lsb(board, rel, bad_ms, ver), RuntimeError),
            ("wrong board", mk_lsb(f"{board}-other", rel, ms, ver), RuntimeError),
            ("malformed line without '='", "NOT_KEY_VALUE\n", ValueError),
        ):
            with self.subTest(desc=desc), self.assertRaises(exc_cls):
                dbus.verify_lsb_release_matches_metadata(bad_lsb, meta)


class DbusAndProtobufParserTests(unittest.TestCase):
    def setUp(self) -> None:
        self.protos = dbus.load_cros_protos(DEFAULT_PROTO_DIR)
        self.conc = self.protos.concierge_pb2
        self.cic = self.protos.cicerone_pb2
        self.sample_owner = "483c91bbeb9f2f163f30c8dea260f4d8d1c87b4f"

    def test_dbus_send_and_empty_array_parsing(self) -> None:
        real_reply = (
            "method return time=1793376373.228710 sender=:1.175 -> destination=:1.197 serial=91 reply_serial=2\n"
            "   array of bytes [\n      08 01 12 0f 0d 64 73 5c 1a 10 18 18 20 20 01 30 06 40 01\n   ]\n"
        )
        raw_vm_info = dbus.parse_dbus_send_byte_array(real_reply, "test GetVmInfo")
        vm_info_resp = dbus.parse_and_validate_proto(raw_vm_info, self.conc.GetVmInfoResponse, "test GetVmInfo")
        self.assertTrue(vm_info_resp.success)
        self.assertEqual((vm_info_resp.vm_info.pid, vm_info_resp.vm_info.cid), (24, 32))
        self.assertEqual(self.conc.VmInfo.VmType.Name(vm_info_resp.vm_info.vm_type), "BAGUETTE")
        self.assertEqual(self.conc.VmStatus.Name(vm_info_resp.vm_info.status), "VM_STATUS_RUNNING")

        self.assertEqual(
            dbus.parse_dbus_send_byte_array(_METHOD_RET_HDR + "   array of bytes [ 08 01 ]\n", "inline"),
            b"\x08\x01",
        )
        raw_empty = dbus.parse_dbus_send_byte_array(_METHOD_RET_HDR + "   array [\n   ]\n", "empty ListRunningContainers")
        self.assertEqual(raw_empty, b"")
        empty_lc = dbus.parse_and_validate_proto(
            raw_empty, self.cic.ListRunningContainersResponse, "empty ListRunningContainers"
        )
        self.assertEqual(list(empty_lc.containers), [])

        empty_sig_parser = dbus.DbusMonitorSignalParser()
        self.assertIsNone(empty_sig_parser.feed_line(_sig_hdr("PendingAppListUpdates")))
        self.assertIsNone(empty_sig_parser.feed_line("   array ["))
        self.assertEqual(
            empty_sig_parser.feed_line("   ]"), ("org.chromium.VmCicerone", "PendingAppListUpdates", b"")
        )
        empty_sig_parser.finish()

    def test_dbus_monitor_subscription_and_signal_sequence(self) -> None:
        raw_vm_info = bytes.fromhex("0801120f0d64735c1a10181820200130064001")
        vm_info_resp = dbus.parse_and_validate_proto(raw_vm_info, self.conc.GetVmInfoResponse, "test GetVmInfo")
        sig_starting = self.conc.VmStartingUpSignal(
            name="termina", owner_id=self.sample_owner, vm_type=self.conc.VmInfo.VmType.BAGUETTE, cid=32
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

        fmt_sig = lambda iface, member, payload: (
            f"{_sig_hdr(member, iface)}\n   array of bytes [\n      {' '.join(f'{b:02x}' for b in payload)}\n   ]\n"
        )
        monitor_stream = (
            "signal time=1793376341.005000 sender=org.freedesktop.DBus -> destination=:1.198 "
            "serial=2 path=/org/freedesktop/DBus; interface=org.freedesktop.DBus; member=NameAcquired\n"
            '   string ":1.198"\n'
            "signal time=1793376341.006000 sender=org.freedesktop.DBus -> destination=:1.198 "
            "serial=4 path=/org/freedesktop/DBus; interface=org.freedesktop.DBus; member=NameLost\n"
            '   string ":1.198"\n'
            + fmt_sig("org.chromium.VmConcierge", "VmStartingUpSignal", sig_starting)
            + fmt_sig("org.chromium.VmConcierge", "VmStartedSignal", sig_started)
            + fmt_sig("org.chromium.VmCicerone", "ContainerStarted", sig_container)
            + fmt_sig("org.chromium.VmCicerone", "PendingAppListUpdates", sig_applist)
        )

        observed_members: list[str] = []

        class _SpyObserver(FlowDiagnosticsObserver):
            def on_dbus_signal(
                self, *, iface: str, member: str, vm_name: str, detail: str, rel_sec: float, msg: Any
            ) -> None:
                observed_members.append(f"{member}:{vm_name}")

        def _replay(mon_inst: dbus.DbusSignalMonitor) -> None:
            p = dbus.DbusMonitorSignalParser()
            for ln in monitor_stream.splitlines():
                if (ev := p.feed_line(ln)) is not None:
                    mon_inst._handle_signal(*ev)
            p.finish()

        mon = dbus.DbusSignalMonitor(
            None, owner_hash=self.sample_owner, expected_username="terminauser", observer=_SpyObserver()
        )
        mon.mark_install_clicked(time.monotonic())
        _replay(mon)

        self.assertEqual(mon.monitor_unique_name, ":1.198")
        self.assertTrue(mon._subscribed_event.is_set())
        self.assertTrue(mon.is_container_started())
        mon.verify_required_signal_sequence()
        self.assertEqual(
            observed_members,
            [
                "VmStartingUpSignal:termina",
                "VmStartedSignal:termina",
                "ContainerStarted:termina",
                "PendingAppListUpdates:termina",
            ],
        )

        for desc, bad_signals in (
            ("missing VmStartingUpSignal", [("VmStartedSignal", "termina"), ("ContainerStarted", "termina")]),
            (
                "out-of-order VmStartingUpSignal",
                [("VmStartedSignal", "termina"), ("VmStartingUpSignal", "termina"), ("ContainerStarted", "termina")],
            ),
        ):
            with self.subTest(desc=desc), self.assertRaises(RuntimeError):
                bad_mon = dbus.DbusSignalMonitor(None, owner_hash=self.sample_owner)
                bad_mon._signals = list(bad_signals)
                bad_mon.verify_required_signal_sequence()

        # Verify async SetBalloonTimer(0) worker thread on VmStartedSignal (non-blocking reader
        # timestamps + timeout=60 + error surfacing via check_healthy/verify_required_signal_sequence/stop).
        balloon_calls: list[tuple[str, str, int, int, str]] = []

        class _FakeBalloonVm:
            def __init__(self, success: bool = True, gate: Any = None) -> None:
                self.success = success
                self.gate = gate

            def dbus_call_proto(
                self_vm, dest: str, method: str, req_msg: Any, resp_cls: Any, timeout: int = 30
            ) -> tuple[Any, bytes]:
                import threading as _th  # noqa: PLC0415

                if self_vm.gate is not None:
                    self_vm.gate.wait(timeout=5.0)
                balloon_calls.append(
                    (dest, method, int(req_msg.timer_interval_millis), int(timeout), _th.current_thread().name)
                )
                resp = resp_cls(success=self_vm.success, failure_reason="" if self_vm.success else "boom")
                return resp, resp.SerializeToString()

        import threading  # noqa: PLC0415

        release_gate = threading.Event()
        b_mon = dbus.DbusSignalMonitor(
            _FakeBalloonVm(True, gate=release_gate),
            owner_hash=self.sample_owner,
            expected_username="terminauser",
            stop_balloon_timer_on_vm_started=True,
        )
        b_mon.mark_install_clicked(time.monotonic())
        t_replay0 = time.monotonic()
        _replay(b_mon)
        replay_elapsed = time.monotonic() - t_replay0
        # Reader thread completed _replay (including ContainerStarted) immediately while SetBalloonTimer is still blocked!
        self.assertLess(replay_elapsed, 0.25)
        self.assertTrue(b_mon.is_container_started())
        self.assertFalse(b_mon.balloon_timer_stopped)
        assert b_mon.container_started_rel_sec is not None
        self.assertLess(b_mon.container_started_rel_sec, 0.25)

        release_gate.set()
        b_mon.verify_required_signal_sequence()
        self.assertTrue(b_mon.balloon_timer_stopped)
        b_mon.stop()
        self.assertEqual(len(balloon_calls), 1)
        self.assertEqual(
            balloon_calls[0][:4],
            ("org.chromium.VmConcierge", "SetBalloonTimer", 0, dbus.BALLOON_STOP_RPC_TIMEOUT_SEC),
        )
        self.assertEqual(balloon_calls[0][4], "dbus-stop-balloon-timer")

        with self.assertRaisesRegex(RuntimeError, "SetBalloonTimer\\(0\\) did not complete"):
            unstopped = dbus.DbusSignalMonitor(
                _FakeBalloonVm(True), owner_hash=self.sample_owner, stop_balloon_timer_on_vm_started=True
            )
            unstopped._signals = list(b_mon._signals)
            unstopped.verify_required_signal_sequence()

        for surface_name, surface_fn in (
            ("check_healthy", lambda m: (m._join_balloon_thread(timeout=2.0), m.check_healthy())),
            ("verify_required_signal_sequence", lambda m: m.verify_required_signal_sequence()),
            ("stop", lambda m: m.stop()),
        ):
            with self.subTest(surface=surface_name), self.assertRaisesRegex(RuntimeError, "failure_reason='boom'"):
                fail_mon = dbus.DbusSignalMonitor(
                    _FakeBalloonVm(False), owner_hash=self.sample_owner, stop_balloon_timer_on_vm_started=True
                )
                fail_mon._signals = [("VmStartingUpSignal", "termina"), ("ContainerStarted", "termina")]
                fail_mon._handle_signal("org.chromium.VmConcierge", "VmStartedSignal", sig_started)
                # Ensure signal ordering is VmStartingUpSignal -> VmStartedSignal -> ContainerStarted for sequence check.
                fail_mon._signals = [
                    ("VmStartingUpSignal", "termina"),
                    ("VmStartedSignal", "termina"),
                    ("ContainerStarted", "termina"),
                ]
                surface_fn(fail_mon)
            fail_mon.stop(raise_errors=False)

    def test_negative_protobuf_and_dbus_parsers(self) -> None:
        raw_vm_info = bytes.fromhex("0801120f0d64735c1a10181820200130064001")
        sig_container = self.cic.ContainerStartedSignal(
            vm_name="termina",
            container_name="penguin",
            owner_id=self.sample_owner,
            container_username="terminauser",
            container_homedir="/home/terminauser",
        ).SerializeToString()
        mon = dbus.DbusSignalMonitor(None, owner_hash=self.sample_owner, expected_username="terminauser")

        def _feed_all(lines: tuple[str, ...], call_finish: bool = False) -> None:
            p = dbus.DbusMonitorSignalParser()
            for x in lines:
                p.feed_line(x)
            if call_finish:
                p.finish()

        for desc, fn in (
            ("truncated wire bytes", lambda: dbus.parse_and_validate_proto(sig_container[:-1], self.cic.ContainerStartedSignal, "trunc")),
            ("unknown wire field tag", lambda: dbus.parse_and_validate_proto(sig_container + b"\xf8\x0f\x01", self.cic.ContainerStartedSignal, "unk")),
            ("wrong message type bytes", lambda: dbus.parse_and_validate_proto(raw_vm_info, self.cic.ContainerStartedSignal, "wrong_type")),
            (
                "missing container_username in ContainerStarted",
                lambda: mon._handle_signal(
                    "org.chromium.VmCicerone",
                    "ContainerStarted",
                    self.cic.ContainerStartedSignal(vm_name="termina", container_name="penguin", owner_id=self.sample_owner).SerializeToString(),
                ),
            ),
            (
                "mismatched owner_id in ContainerStarted",
                lambda: mon._handle_signal(
                    "org.chromium.VmCicerone",
                    "ContainerStarted",
                    self.cic.ContainerStartedSignal(
                        vm_name="termina", container_name="penguin", owner_id="other_owner", container_username="terminauser", container_homedir="/home/terminauser"
                    ).SerializeToString(),
                ),
            ),
            ("unknown enum value", lambda: dbus.require_enum_name(self.conc.VmStatus, 999, "status", "enum_test", b"\x20\xe7\x07")),
            ("missing method return header", lambda: dbus.parse_dbus_send_byte_array("   array of bytes [\n      08 01\n   ]\n", "bad")),
            ("non-hex byte token", lambda: dbus.parse_dbus_send_byte_array(_METHOD_RET_HDR + "   array of bytes [\n      08 zz\n   ]\n", "bad_hex")),
            ("unclosed array of bytes on dbus-monitor", lambda: _feed_all((_sig_hdr("ContainerStarted"), "   array of bytes [", "      0a 07", _sig_hdr("ContainerStarted")))),
            ("unexpected D-Bus signal member", lambda: _feed_all((_sig_hdr("BogusSignal"),))),
            ("non-empty generic array [ 08 ]", lambda: dbus.parse_dbus_send_byte_array(_METHOD_RET_HDR + "   array [ 08 ]\n", "bad_generic_inline")),
            ("non-empty generic multiline array", lambda: dbus.parse_dbus_send_byte_array(_METHOD_RET_HDR + "   array [\n      08\n   ]\n", "bad_generic_multi")),
            ("unclosed empty array on dbus-send", lambda: dbus.parse_dbus_send_byte_array(_METHOD_RET_HDR + "   array [\n", "bad_unclosed_send")),
            ("non-empty generic multiline array on dbus-monitor", lambda: _feed_all((_sig_hdr("PendingAppListUpdates"), "   array [", "      08", "   ]"))),
            ("unclosed empty array at EOF on dbus-monitor", lambda: _feed_all((_sig_hdr("PendingAppListUpdates"), "   array ["), call_finish=True)),
        ):
            with self.subTest(desc=desc), self.assertRaises(ValueError):
                fn()


if __name__ == "__main__":
    unittest.main()
