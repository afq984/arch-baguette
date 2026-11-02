"""Offline unit tests for `scripts/user_flows/diag/resources.py`."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

SCRIPTS_DIR = Path(__file__).resolve().parent.parent / "scripts"
if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))

from user_flows.diag import resources  # noqa: E402


def _make_raw_sample_json(
    *,
    uptime_sec: float = 10.0,
    load1: float = 1.2,
    busy_ticks: int = 200,
    idle_ticks: int = 800,
    psi_cpu_us: int = 100_000,
) -> str:
    return json.dumps(
        {
            "nproc": 4,
            "clk_tck": 100,
            "uptime_sec": uptime_sec,
            "load1": load1,
            "stat_cpu": f"cpu {busy_ticks} 0 0 {idle_ticks} 10 0 0 5 0 0",
            "psi": {
                "cpu": [f"some avg10=5.00 avg60=2.00 avg300=1.00 total={psi_cpu_us}"],
                "memory": [
                    "some avg10=0.00 avg60=0.00 avg300=0.00 total=0",
                    "full avg10=0.00 avg60=0.00 avg300=0.00 total=0",
                ],
                "io": [
                    "some avg10=1.00 avg60=0.50 avg300=0.10 total=20000",
                    "full avg10=0.50 avg60=0.20 avg300=0.05 total=10000",
                ],
            },
            "mem_kib": {
                "MemTotal": 4194304,
                "MemAvailable": 2097152,
                "SwapTotal": 2097152,
                "SwapFree": 2000000,
                "Dirty": 1024,
                "Writeback": 0,
            },
            "extra": {},
        }
    )


class ResourceDiagnosticsTests(unittest.TestCase):
    def test_remote_sampler_loop_stdin_eof_emits_two_samples(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            proc_root = Path(td)
            (proc_root / "uptime").write_text("42.50 100.00\n", encoding="utf-8")
            (proc_root / "loadavg").write_text("0.75 0.50 0.25 1/100 999\n", encoding="utf-8")
            (proc_root / "stat").write_text("cpu  100 0 50 800 10 0 0 2 0 0\n", encoding="utf-8")
            (proc_root / "meminfo").write_text(
                "MemTotal: 4194304 kB\nMemAvailable: 3000000 kB\n"
                "SwapTotal: 1048576 kB\nSwapFree: 1048576 kB\n"
                "Dirty: 128 kB\nWriteback: 0 kB\n",
                encoding="utf-8",
            )
            pdir = proc_root / "pressure"
            pdir.mkdir()
            (pdir / "cpu").write_text(
                "some avg10=1.00 avg60=0.50 avg300=0.10 total=1000\n", encoding="utf-8"
            )
            for name in ("memory", "io"):
                (pdir / name).write_text(
                    "some avg10=0.00 avg60=0.00 avg300=0.00 total=0\n"
                    "full avg10=0.00 avg60=0.00 avg300=0.00 total=0\n",
                    encoding="utf-8",
                )

            script = resources.build_remote_sampler_script()
            env = {**os.environ, "CROS_RES_PROC_ROOT": str(proc_root)}
            proc = subprocess.Popen(
                [sys.executable, "-u", "-c", script, "--loop", "60"],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                env=env,
            )
            out, err = proc.communicate(input="", timeout=5.0)
            self.assertEqual(proc.returncode, 0, msg=err)
            lines = [ln for ln in out.splitlines() if ln.strip()]
            self.assertEqual(len(lines), 2)
            host_cpu = resources.CpuStatCounters(100, 0, 50, 800, 0, 0, 0, 0)
            s0 = resources.parse_cros_resource_json(
                lines[0], mono_ts=10.0, rel_sec=0.0, host_cpu=host_cpu, host_load1=0.5, host_mem_avail_mib=4096.0
            )
            self.assertEqual(s0.mem_total_kib, 4194304)

    def test_single_pass_summary_and_peak_preserving_row_selection(self) -> None:
        host_info = resources.HostRunnerInfo(
            vendor_id="GenuineIntel",
            model_name="Test CPU",
            nproc=8,
            mem_total_mib=16384.0,
            mem_avail_mib=12288.0,
        )
        samples: list[resources.CrosResourceSample] = []
        for idx in range(30):
            h_cpu = resources.CpuStatCounters(100 * (idx + 1), 0, 50, 1000 * (idx + 1), 0, 0, 0, 0)
            raw = _make_raw_sample_json(
                uptime_sec=10.0 + idx * 5.0,
                load1=9.5 if idx == 13 else 1.0,
                busy_ticks=200 + idx * 50,
                idle_ticks=800 + idx * 150,
                psi_cpu_us=100_000 + idx * 50_000,
            )
            samples.append(
                resources.parse_cros_resource_json(
                    raw,
                    mono_ts=100.0 + idx * 5.0,
                    rel_sec=-5.0 + idx * 5.0,
                    host_cpu=h_cpu,
                    host_load1=1.0,
                    host_mem_avail_mib=8192.0,
                )
            )

        summary, rows = resources.summarize_resource_diagnostics(
            host_info,
            samples,
            guest_cpu_summary_line="ChromeOS CPU: vendor=GenuineIntel model='Test CPU'",
            install_mono=105.0,
            strict=True,
        )
        self.assertTrue(any(ln.startswith("Host runner:") for ln in summary))
        self.assertTrue(any(ln.startswith("ChromeOS CPU:") for ln in summary))
        self.assertTrue(any(ln.startswith("ChromeOS PSI:") for ln in summary))
        # Header + <= 24 rows, and peak load1=9.50 at idx=13 is preserved
        self.assertLessEqual(len(rows), 25)
        self.assertTrue(any("load1=9.50" in r for r in rows))

        # Strict mode rejects <2 samples or boolean fields
        with self.assertRaisesRegex(RuntimeError, "Expected >=2 ChromeOS resource samples"):
            resources.summarize_resource_diagnostics(host_info, samples[:1], strict=True)
        bad = json.loads(_make_raw_sample_json())
        bad["nproc"] = True
        with self.assertRaisesRegex(ValueError, "Expected int for nproc"):
            resources.parse_cros_resource_json(
                json.dumps(bad),
                mono_ts=1.0,
                rel_sec=0.0,
                host_cpu=samples[0].host_cpu,
                host_load1=1.0,
                host_mem_avail_mib=4096.0,
            )


if __name__ == "__main__":
    unittest.main()
