"""Offline unit tests for `scripts/user_flows/diag/cpuinfo.py`."""

from __future__ import annotations

import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

SCRIPTS_DIR = Path(__file__).resolve().parent.parent / "scripts"
if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))

from user_flows.diag import DiagContext, cpuinfo  # noqa: E402


class GuestCpuInfoTests(unittest.TestCase):
    def test_parse_and_format_intel_vmx_and_amd_svm_cpuinfo(self) -> None:
        intel = cpuinfo.parse_guest_cpuinfo(
            "processor\t: 0\n"
            "vendor_id\t: GenuineIntel\n"
            "model name\t: Intel Xeon\n"
            "flags\t\t: fpu avx avx2 fma xsaveopt vmx\n"
            "vmx flags\t: ept vpid\n\n"
        )
        intel_line = cpuinfo.format_guest_cpuinfo_summary(intel)
        self.assertIn("avx2=yes fma=yes xsaveopt=yes", intel_line)
        self.assertIn("virt=vmx[ept,vpid]", intel_line)

        amd = cpuinfo.parse_guest_cpuinfo(
            "processor\t: 0\n"
            "vendor_id\t: AuthenticAMD\n"
            "model name\t: AMD EPYC\n"
            "flags\t\t: fpu avx avx2 svm npt nrip_save\n"
        )
        amd_line = cpuinfo.format_guest_cpuinfo_summary(amd)
        self.assertIn("virt=svm[npt,nrip_save]", amd_line)

        with self.assertRaisesRegex(ValueError, "Missing or empty 'flags' in guest /proc/cpuinfo"):
            cpuinfo.parse_guest_cpuinfo("vendor_id: GenuineIntel\nmodel name: Test\n")

    def test_observer_standalone_report_vs_resources_inline(self) -> None:
        class _FakeVM:
            def ssh(self, cmd: str, **kwargs: object) -> subprocess.CompletedProcess[str]:
                del cmd, kwargs
                return subprocess.CompletedProcess(
                    [],
                    0,
                    stdout="vendor_id: GenuineIntel\nmodel name: Test\nflags: fpu vmx\n",
                    stderr="",
                )

        with tempfile.TemporaryDirectory() as td:
            ctx = DiagContext(work_dir=Path(td), vm=_FakeVM())
            obs = cpuinfo.GuestCpuInfoObserver(ctx)
            obs.collect(strict=True)
            self.assertIn("CHROMEOS CPU SUMMARY", obs.format_report(include_verbose=False))
            ctx.resources_enabled = True
            self.assertEqual(obs.format_report(include_verbose=False), "")


if __name__ == "__main__":
    unittest.main()
