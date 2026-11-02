"""Offline unit tests for `scripts/user_flows/diag/top_procs.py`."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import unittest
from pathlib import Path

SCRIPTS_DIR = Path(__file__).resolve().parent.parent / "scripts"
if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))

from user_flows.diag import resources, top_procs  # noqa: E402


class TopProcsDiagnosticsTests(unittest.TestCase):
    def test_remote_top_procs_scan_with_live_proc_and_stdin_eof(self) -> None:
        ext = top_procs.TopProcsExtension()
        script = resources.build_remote_sampler_script(ext)
        proc = subprocess.Popen(
            [sys.executable, "-u", "-c", script, "--loop", "60"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            env=dict(os.environ),
        )
        out, err = proc.communicate(input="", timeout=5.0)
        self.assertEqual(proc.returncode, 0, msg=err)
        lines = [ln for ln in out.splitlines() if ln.strip()]
        self.assertEqual(len(lines), 2)
        h_cpu = resources.CpuStatCounters(100, 0, 50, 800, 0, 0, 0, 0)
        s0 = resources.parse_cros_resource_json(
            lines[0],
            mono_ts=1.0,
            rel_sec=-1.0,
            host_cpu=h_cpu,
            host_load1=0.5,
            host_mem_avail_mib=4096.0,
            top_procs_ext=ext,
        )
        s1 = resources.parse_cros_resource_json(
            lines[1],
            mono_ts=2.0,
            rel_sec=1.0,
            host_cpu=h_cpu,
            host_load1=0.5,
            host_mem_avail_mib=4096.0,
            top_procs_ext=ext,
        )
        self.assertEqual(s0.extra.proc_dt_sec, 0.0)
        self.assertGreater(s1.extra.proc_dt_sec, 0.0)

    def test_crosvm_grouping_renderer_url_attribution_budget_and_perf_guard(self) -> None:
        ext = top_procs.TopProcsExtension()
        h_cpu = resources.CpuStatCounters(100, 0, 50, 800, 0, 0, 0, 0)

        def _mk_sample(
            mono_ts: float,
            rel_sec: float,
            uptime: float,
            extra: dict[str, object],
        ) -> resources.CrosResourceSample:
            payload = {
                "nproc": 4,
                "clk_tck": 100,
                "uptime_sec": uptime,
                "load1": 2.0,
                "stat_cpu": f"cpu {int(uptime * 20)} 0 0 {int(uptime * 80)} 0 0 0 0 0 0",
                "psi": {
                    "cpu": ["some avg10=2.00 avg60=1.00 avg300=0.50 total=50000"],
                    "memory": [
                        "some avg10=0.00 avg60=0.00 avg300=0.00 total=0",
                        "full avg10=0.00 avg60=0.00 avg300=0.00 total=0",
                    ],
                    "io": [
                        "some avg10=0.00 avg60=0.00 avg300=0.00 total=0",
                        "full avg10=0.00 avg60=0.00 avg300=0.00 total=0",
                    ],
                },
                "mem_kib": {
                    "MemTotal": 4194304,
                    "MemAvailable": 2097152,
                    "SwapTotal": 1048576,
                    "SwapFree": 1048576,
                    "Dirty": 0,
                    "Writeback": 0,
                },
                "extra": extra,
            }
            return resources.parse_cros_resource_json(
                json.dumps(payload),
                mono_ts=mono_ts,
                rel_sec=rel_sec,
                host_cpu=h_cpu,
                host_load1=1.0,
                host_mem_avail_mib=4096.0,
                top_procs_ext=ext,
            )

        s0 = _mk_sample(
            100.0,
            0.0,
            10.0,
            {"proc_dt_sec": 0.0, "sampler_ticks": 0, "top_procs": []},
        )
        s1 = _mk_sample(
            115.0,
            15.0,
            25.0,
            {
                "proc_dt_sec": 15.0,
                "sampler_ticks": 10,  # 0.1s / 15s = 0.67% <= 3.0%
                "top_procs": [
                    {"pid": 0, "comm": "crosvm", "hint": "4p:run,device:block", "ticks": 600},
                    {"pid": 3210, "comm": "chrome", "hint": "--type=renderer", "ticks": 150},
                ],
            },
        )
        lines = ext.format_summary_lines(
            [s0, s1],
            installer_closed_rel_sec=5.0,
            renderer_urls={3210: "chrome-untrusted://terminal/html/terminal.html"},
            strict=True,
        )
        joined = "\n".join(lines)
        self.assertIn("ChromeOS sampler: cpu=0.10s (0.67% of 1vCPU", joined)
        self.assertIn("crosvm[4p:device:block,run]=6.00s(40.0%)", joined)
        self.assertIn("chrome#3210(--type=renderer chrome-untrusted://terminal/html/terminal.html)", joined)
        self.assertIn("post-InstallerClosed", joined)

        # Budget overrun fails in strict mode
        s_over = _mk_sample(
            115.0,
            15.0,
            25.0,
            {
                "proc_dt_sec": 10.0,
                "sampler_ticks": 50,  # 0.5s / 10s = 5.0% > 3.0%
                "top_procs": [],
            },
        )
        with self.assertRaisesRegex(RuntimeError, "exceeded CPU budget"):
            ext.format_summary_lines([s0, s_over], strict=True)

        # Unexpected perf/quipper fails in strict mode
        s_perf = _mk_sample(
            115.0,
            15.0,
            25.0,
            {
                "proc_dt_sec": 10.0,
                "sampler_ticks": 5,
                "top_procs": [{"pid": 999, "comm": "perf", "hint": "record", "ticks": 200}],
            },
        )
        with self.assertRaisesRegex(RuntimeError, "Unexpected ChromeOS profiling process"):
            ext.format_summary_lines([s0, s_perf], strict=True)

        # Unaggregated crosvm pid != 0 rejected by parser
        with self.assertRaisesRegex(ValueError, "Unaggregated or duplicate crosvm"):
            top_procs.parse_top_procs_extra(
                {
                    "proc_dt_sec": 5.0,
                    "sampler_ticks": 1,
                    "top_procs": [{"pid": 123, "comm": "crosvm", "hint": "run", "ticks": 10}],
                }
            )


if __name__ == "__main__":
    unittest.main()
