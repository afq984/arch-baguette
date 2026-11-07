"""Offline unit tests for `scripts/user_flows/vm.py` and `CompositeDiagnosticsObserver`."""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from typing import Any
from unittest import mock

SCRIPTS_DIR = Path(__file__).resolve().parent.parent / "scripts"
if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))

from user_flows import CompositeDiagnosticsObserver, FlowDiagnosticsObserver, cdp, vm  # noqa: E402


class _FakeWS:
    def __init__(self, responses: list[str]) -> None:
        self._responses = list(responses)
        self.connected = True
        self.sent: list[str] = []

    def settimeout(self, _t: float) -> None:
        pass

    def send(self, payload: str) -> None:
        self.sent.append(payload)

    def recv(self) -> str:
        return self._responses.pop(0) if self._responses else ""

    def close(self) -> None:
        self.connected = False


def _new_vm(**attrs: Any) -> vm.ChromeOSVM:
    inst = object.__new__(vm.ChromeOSVM)
    inst.observer = FlowDiagnosticsObserver()
    inst._current_step = "init"
    for k, v in attrs.items():
        setattr(inst, k, v)
    return inst


class ChromeOSVMAndHelpersTests(unittest.TestCase):
    def test_host_cpu_mem_and_qemu_cpu_arg(self) -> None:
        amd_cpuinfo = "processor\t: 0\nvendor_id\t: AuthenticAMD\nmodel name\t: AMD EPYC 7763\n"
        intel_cpuinfo = "processor\t: 0\nvendor_id\t: GenuineIntel\nmodel name\t: Intel Xeon\n"
        info = vm.read_host_cpu_and_mem(amd_cpuinfo, "MemTotal: 16384000 kB\nMemAvailable: 12288000 kB\n")
        self.assertEqual(info.vendor_id, "AuthenticAMD")
        self.assertAlmostEqual(info.mem_total_mib, 16000.0, places=2)
        self.assertEqual(vm.detect_host_qemu_cpu_arg(amd_cpuinfo), "Opteron_G4,-invpcid,-tsc-deadline,check,svm=on")
        self.assertEqual(vm.detect_host_qemu_cpu_arg(intel_cpuinfo), "Haswell-noTSX,-invpcid,-tsc-deadline,check,vmx=on")
        with self.assertRaisesRegex(RuntimeError, "Unsupported host CPU vendor"):
            vm.detect_host_qemu_cpu_arg("processor : 0\nvendor_id : MysteryCPU\n")

    def test_pid_matches_qemu(self) -> None:
        with tempfile.TemporaryDirectory() as fake_proc_str:
            fp = Path(fake_proc_str)
            for pid_num, comm_txt, cmdline_bytes, bin_arg, expected in (
                (101, "qemu-system-x86", b"/usr/bin/qemu-system-x86_64\x00-enable-kvm\x00", "qemu-system-x86_64", True),
                (102, "kvm", b"/usr/bin/kvm\x00-m\x004G\x00", "/usr/bin/kvm", True),
                (103, "my-custom-vmm", b"/opt/vmm/my-custom-vmm\x00-daemonize\x00", "/opt/vmm/my-custom-vmm", True),
                (104, "kvm-pit/101", b"", "/usr/bin/kvm", False),
                (105, "python3", b"python3\x00-m\x00http.server\x00", "qemu-system-x86_64", False),
            ):
                d = fp / str(pid_num)
                d.mkdir()
                (d / "comm").write_text(comm_txt + "\n", encoding="utf-8")
                (d / "cmdline").write_bytes(cmdline_bytes)
                self.assertEqual(vm.pid_matches_qemu(pid_num, bin_arg, proc_root=fp), expected)

    def test_vm_command_timeout_wrapping(self) -> None:
        inst = _new_vm(
            ssh_key=Path("/tmp/testing_rsa"),
            ssh_port=42222,
            owner_hash="deadbeef",
            _current_step="step5:verify_guest_user_session",
        )
        with mock.patch.object(
            vm.subprocess, "run", side_effect=subprocess.TimeoutExpired(cmd=["ssh"], timeout=120, stderr="vsh launch hung\n")
        ):
            with self.assertRaises(vm.VMCommandTimeoutError) as ctx_vsh:
                inst.vsh("termina", "root", "journalctl -b -o json", timeout=120, op_desc="guest_diag:summary")
            msg = str(ctx_vsh.exception)
            self.assertNotIsInstance(ctx_vsh.exception, subprocess.TimeoutExpired)
            for tok in (
                "operation='guest_diag:summary'",
                "step='step5:verify_guest_user_session'",
                "cmd='journalctl -b -o json'",
                "timeout=120.0s",
                "vsh launch hung",
            ):
                self.assertIn(tok, msg)

            with self.assertRaises(vm.VMCommandTimeoutError) as ctx_scp:
                inst.scp_to(Path("/tmp/baguette.img.zst"), "/home/user/x/baguette.img.zst", timeout=15, op_desc="prepare:scp")
            self.assertIn("operation='prepare:scp'", str(ctx_scp.exception))

            inst.set_step("prepare:boot_cros_vm")
            clock = iter([0.0, 0.0, 0.1, 0.2, 2.0, 2.0])
            with (
                mock.patch.object(vm.time, "sleep"),
                mock.patch.object(vm.time, "monotonic", side_effect=lambda: next(clock, 2.0)),
                self.assertRaises(vm.VMCommandTimeoutError) as ctx_wssh,
            ):
                inst.wait_for_ssh(timeout_sec=1)
            self.assertIn("operation='wait_for_ssh'", str(ctx_wssh.exception))
            self.assertIn("step='prepare:boot_cros_vm'", str(ctx_wssh.exception))

    def test_wait_for_cdp_target_and_close_targets(self) -> None:
        fake_tgt = {
            "id": "9F2A1B",
            "url": "chrome-untrusted://terminal/html/terminal.html?command=vmshell",
            "webSocketDebuggerUrl": "ws://127.0.0.1:41234/devtools/page/9F2A1B",
        }
        dummy_vm = _new_vm(_current_step="step2:attach_crostini_installer")
        batches = [[], [fake_tgt]]
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

        with self.assertRaises(cdp.CDPTimeoutError) as ctx_tgt:
            dummy_vm.wait_for_cdp_target(
                lambda _t: False,
                operation="find_target(missing)",
                target_label="MissingTarget",
                target_url="chrome://missing/",
                timeout=0.04,
                interval=0.01,
            )
        self.assertIn("step='step2:attach_crostini_installer'", str(ctx_tgt.exception))

        tab_ws = _FakeWS([json.dumps({"id": 1, "result": {"result": {"value": True}}})])
        tail_tab = cdp.CroshTab(
            "Terminal-App-Initial",
            cdp.CDPConnection.from_target(fake_tgt, label="Terminal-App-Initial", connect_fn=lambda *_a, **_kw: tab_ws),
        )
        browser_ws = _FakeWS([json.dumps({"id": 1, "result": {"success": True}}), json.dumps({"id": 1, "result": {"success": True}})])
        dummy_vm.connect_browser_cdp = lambda label="Browser-Root": cdp.CDPConnection(  # type: ignore[method-assign]
            "ws://127.0.0.1:41234/devtools/browser/root", target_label=label, connect_fn=lambda *_a, **_kw: browser_ws
        )
        dummy_vm.close_crosh_tab(tail_tab)
        dummy_vm.list_cdp_targets = lambda timeout=20.0: [  # type: ignore[method-assign]
            {"id": "T1", "type": "page", "url": "chrome-untrusted://terminal/html/terminal.html#home"},
            {"id": "T2", "type": "page", "url": "chrome-untrusted://terminal/html/terminal.html?command=vmshell"},
        ]
        self.assertEqual(dummy_vm.close_cdp_targets_matching("chrome-untrusted://terminal", label="Terminal-Stale", exclude_ids={"T2"}), 1)
        self.assertEqual([json.loads(s)["params"]["targetId"] for s in browser_ws.sent], ["9F2A1B", "T1"])

    def test_composite_diagnostics_observer_strict_and_idempotent(self) -> None:
        noop = FlowDiagnosticsObserver()
        noop.collect(strict=True)
        self.assertEqual(noop.format_report(include_verbose=False), "")

        calls: list[str] = []

        class _OkObs(FlowDiagnosticsObserver):
            def collect(self, *, strict: bool) -> None:
                calls.append(f"ok:{strict}")

            def format_report(self, *, include_verbose: bool) -> str:
                return f"OK(verbose={include_verbose})"

        class _FlakyObs(FlowDiagnosticsObserver):
            def collect(self, *, strict: bool) -> None:
                calls.append(f"flaky:{strict}")
                raise RuntimeError("collector boom")

            def format_report(self, *, include_verbose: bool) -> str:
                return "PARTIAL_FLAKY"

        comp = CompositeDiagnosticsObserver([_OkObs(), _FlakyObs()])
        with self.assertRaisesRegex(RuntimeError, "collector boom"):
            comp.collect(strict=True)
        comp.collect(strict=False)
        self.assertEqual(calls, ["ok:True", "flaky:True", "flaky:False"])
        rep = comp.format_report(include_verbose=True)
        for tok in ("OK(verbose=True)", "PARTIAL_FLAKY", "_FlakyObs: RuntimeError: collector boom"):
            self.assertIn(tok, rep)



if __name__ == "__main__":
    unittest.main()
