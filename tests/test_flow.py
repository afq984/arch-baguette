"""Offline unit tests for `scripts/user_flows/flow.py`."""

from __future__ import annotations

import io
import subprocess
import sys
import tempfile
import traceback
import unittest
from pathlib import Path
from typing import Any
from unittest import mock

SCRIPTS_DIR = Path(__file__).resolve().parent.parent / "scripts"
if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))

from user_flows import DEFAULT_README_PATH, FlowDiagnosticsObserver, cdp, fmt_rel_t, flow, vm  # noqa: E402


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

    _RUN6_T_INST = flow.parse_rfc3339_utc("2026-11-01T13:04:26.300000Z")
    _RUN6_PRE_MSGS = (
        "2026-11-01T13:05:55.820000Z INFO vm_concierge[2964]: Received request: SetUpVmUser\n"
        "2026-11-01T13:06:12.410000Z INFO vm_concierge[2964]: Received request: GetVmInfo\n"
        "2026-11-01T13:07:21.400000Z INFO vm_concierge[2964]: Received request: SetUpVmUser\n"
        "2026-11-01T13:07:41.402100Z ERR vm_concierge[2964]: SetUpUser RPC failed: Deadline Exceeded\n"
    )
    # Verbatim post-ContainerStarted excerpt from ci-pr8-run6.log (L1031-1046).
    _RUN6_POST_MSGS = (
        _RUN6_PRE_MSGS
        + "2026-11-01T13:09:09.981770Z ERR vm_cicerone[2973]: Garcon channel not connected after 5 seconds.\n"
        + "2026-11-01T13:09:09.983474Z INFO vm_cicerone[2973]: Startup of container penguin at IP  for VM termina completed.\n"
        + "2026-11-01T13:09:21.377559Z INFO vm_concierge[2964]: Received request: CreateDiskImage\n"
        + "2026-11-01T13:09:21.434482Z INFO vm_concierge[2964]: Received request: StartVm\n"
        + "2026-11-01T13:09:21.434544Z INFO vm_concierge[2964]: VM with requested name is already running\n"
        + "2026-11-01T13:09:21.495249Z INFO vm_concierge[2964]: Received request: SetUpVmUser\n"
        + "2026-11-01T13:09:41.498329Z ERR vm_concierge[2964]: SetUpUser RPC failed: Deadline Exceeded\n"
    )

    def test_classify_terminal_setup_failure_real_logs(self) -> None:
        pre_entries, _ = flow.parse_host_init_logs(self._RUN6_PRE_MSGS, "", self._RUN6_T_INST)
        post_entries, _ = flow.parse_host_init_logs(self._RUN6_POST_MSGS, "", self._RUN6_T_INST)

        # Positive 1: pre-ContainerStarted installer-opened tab (call #2).
        ev_pre = flow.classify_terminal_setup_failure(
            flow.KNOWN_INITIAL_TERMINAL_TIMEOUT_ERROR,
            pre_entries,
            tab_launched_rel_sec=145.6,
            container_started_rel_sec=None,
            attempt=0,
        )
        self.assertEqual((ev_pre.call_index, ev_pre.post_container_started), (2, False))
        self.assertEqual(flow.format_final_pass_line(flow.FlowResult(terminal_relaunch=ev_pre)), flow.FINAL_PASS_LINE)

        # Positive 2: post-ContainerStarted fresh tab (call #3 from ci-pr8-run6.log).
        base_post_kw: dict[str, Any] = dict(
            terminal_buffer=flow.KNOWN_INITIAL_TERMINAL_TIMEOUT_ERROR,
            entries=post_entries,
            tab_launched_rel_sec=291.4,
            container_started_rel_sec=284.3,
            attempt=1,
        )
        ev_post = flow.classify_terminal_setup_failure(**base_post_kw)
        self.assertEqual((ev_post.call_index, ev_post.post_container_started), (3, True))
        self.assertAlmostEqual(ev_post.duration_sec, 20.003, places=2)
        banner = flow.format_terminal_relaunch_banner(
            ev_post, failed_label="Terminal-App-Fresh", target_id="C04C0783", tab_launched_rel_sec=291.4, cs_rel_sec=284.3
        )
        self.assertEqual(len(banner.splitlines()), 5)
        self.assertIn("1/1 post-ContainerStarted", banner)
        self.assertIn("SetUpUser RPC failed: Deadline Exceeded", banner)
        self.assertIn(
            "1 Terminal relaunch used after post-ContainerStarted SetUpVmUser call #3 20.0s deadline",
            flow.format_final_pass_line(flow.FlowResult(terminal_relaunch=ev_post)),
        )

        no_deadline_entries, _ = flow.parse_host_init_logs(
            "2026-11-01T13:09:21.495249Z INFO vm_concierge[2964]: Received request: SetUpVmUser\n"
            "2026-11-01T13:09:22.100000Z INFO vm_concierge[2964]: Received request: GetVmInfo\n",
            "",
            self._RUN6_T_INST,
        )
        for desc, override in (
            ("code 22 CONTAINER_START_FAILED", {"terminal_buffer": "Launching vmshell failed: Error starting crostini for terminal: 22 (CONTAINER_START_FAILED)"}),
            ("code 50 without deadline line", {"entries": no_deadline_entries}),
            ("deadline line older than tab launch", {"entries": pre_entries}),
            ("post-ContainerStarted budget exhausted", {"post_cs_relaunch_used": True}),
            ("overall attempt budget exhausted", {"attempt": 2}),
        ):
            with self.subTest(desc=desc), self.assertRaises(RuntimeError):
                flow.classify_terminal_setup_failure(**{**base_post_kw, **override})

    def test_terminal_readiness_loop_relaunch_and_fail_fast(self) -> None:
        self.assertGreaterEqual(flow.TERMINAL_POLL_FLOOR_SEC, 1.5)
        order: list[str] = []
        t_inst, pre_msgs, post_msgs = self._RUN6_T_INST, self._RUN6_PRE_MSGS, self._RUN6_POST_MSGS

        class _FakeDbusMon:
            def __init__(self) -> None:
                self._started = False
                self.container_started_rel_sec: float | None = None

            def check_healthy(self) -> None:
                pass

            def rel_mono(self) -> float:
                return 291.4 if self._started else 196.0

            def is_container_started(self) -> bool:
                return self._started

            def wait_for_container_started(self, timeout: float = 300.0) -> float:
                order.append(f"wait_cs:{int(timeout)}")
                self._started, self.container_started_rel_sec = True, 284.3
                return 284.3

        class _FakeScraper(flow.HostLogScraper):
            def __init__(self, dbus_mon: _FakeDbusMon, *, fail_scrape: bool = False) -> None:
                super().__init__()
                self._dbus_mon, self._fail_scrape = dbus_mon, fail_scrape

            def scrape(self, _vm: Any) -> list[Any]:
                order.append("scrape")
                if self._fail_scrape:
                    raise OSError("ssh scrape transport failed")
                self.last_entries, _ = flow.parse_host_init_logs(
                    post_msgs if self._dbus_mon.is_container_started() else pre_msgs, "", t_inst
                )
                return self.last_entries

        class _FakeTab:
            def __init__(self, label: str, tid: str) -> None:
                self.label = label
                self.conn = mock.MagicMock(target_id=tid)

            def send_line(self, _line: str) -> None:
                order.append(f"send_line:{self.label}")

            def wait_for(self, *_a: Any, **_kw: Any) -> str:
                order.append(f"wait_for:{self.label}")
                return "[terminauser@penguin ~]$"

        dummy_vm = _dummy_vm(
            close_crosh_tab=lambda tab: order.append(f"close_crosh_tab:{tab.conn.target_id}"),
            close_cdp_targets_matching=lambda url_sub, *, label, exclude_ids=None: (
                order.append(f"close_matching:{label}:{url_sub}:{sorted(exclude_ids or ())}") or 0
            ),
            close_cdp_page_targets_by_url=lambda urls, *, label, exclude_ids=None: (
                order.append(f"close_exact:{label}:{sorted(urls)}:{sorted(exclude_ids or ())}") or 1
            ),
        )
        dbus_mon = _FakeDbusMon()
        tracker = flow._FlowTracker(dummy_vm, dbus_mon, _FakeScraper(dbus_mon), FlowDiagnosticsObserver())  # type: ignore[arg-type]
        tracker.initial_tab_launched_rel = 145.6
        init_tgt = {"id": "INIT_TID", "url": "chrome-untrusted://terminal/?command=vmshell", "webSocketDebuggerUrl": "ws://127.0.0.1:9/x"}
        outcomes = iter(
            [
                ("error", flow.KNOWN_INITIAL_TERMINAL_TIMEOUT_ERROR),
                ("error", flow.KNOWN_INITIAL_TERMINAL_TIMEOUT_ERROR),
                ("prompt", "[terminauser@penguin ~]$"),
            ]
        )
        fresh_tids = iter(["FRESH_1", "RELAUNCH_2"])
        with (
            mock.patch.object(cdp.CDPConnection, "from_target", side_effect=lambda tgt, **_kw: mock.MagicMock(target_id=tgt["id"])),
            mock.patch.object(flow, "_observe_terminal_until_prompt_or_error", side_effect=lambda *_a, **_kw: next(outcomes)),
            mock.patch.object(
                flow,
                "_open_fresh_terminal_from_home",
                side_effect=lambda _vm, old_ids, _tr, *, label="Terminal-App-Fresh": (
                    order.append(f"open:{label}:{sorted(old_ids)}") or _FakeTab(label, next(fresh_tids))
                ),
            ),
            mock.patch.object(flow, "LOG_FLUSH_TIMEOUT_SEC", 0.0),
        ):
            ev = flow.verify_terminal_app_with_readiness_gate(dummy_vm, init_tgt, "terminauser", tracker)

        self.assertIsNotNone(ev)
        assert ev is not None
        self.assertEqual(ev.call_index, 3)
        self.assertFalse(any("Terminal-Home-Idle" in s or "#home" in s for s in order))
        self.assertIn("close_matching:Terminal-Stale:chrome-untrusted://terminal/html/terminal.html?command=vmshell:['FRESH_1']", order)
        self.assertEqual(order[-2:], ["close_crosh_tab:RELAUNCH_2", "close_matching:Terminal-App:chrome-untrusted://terminal:[]"])
        self.assertLess(order.index("close_crosh_tab:INIT_TID"), order.index("wait_cs:300"))
        self.assertLess(order.index("wait_cs:300"), order.index("open:Terminal-App-Fresh:['INIT_TID']"))
        self.assertIn("open:Terminal-App-Relaunch:['FRESH_1', 'INIT_TID']", order)

        # Code 22 and timeout fail fast with bounded host/Chrome window diagnostics; scrape errors propagate.
        order.clear()
        dbus2 = _FakeDbusMon()
        scraper2 = _FakeScraper(dbus2)
        scraper2.mark_install_clicked(t_inst)
        scraper2.chrome_excerpt = (
            "2026-11-01T13:04:20.000000Z INFO chrome[1]: before window crostini line\n"
            "2026-11-01T13:06:00.000000Z WARNING chrome[1]: [terminal] task queue exceeded allotted deadline by 40ms\n"
            "2026-11-01T13:06:05.000000Z ERROR chrome[1]: [crostini_manager.cc] container start failed: 22\n"
        )
        tracker2 = flow._FlowTracker(dummy_vm, dbus2, scraper2, FlowDiagnosticsObserver())  # type: ignore[arg-type]
        with (
            mock.patch.object(cdp.CDPConnection, "from_target", side_effect=lambda tgt, **_kw: mock.MagicMock(target_id=tgt["id"], error_context=lambda *_a: "ctx")),
            mock.patch.object(dummy_vm, "check_devtools_tunnel_alive", lambda: None, create=True),
        ):
            with (
                mock.patch.object(
                    flow,
                    "_observe_terminal_until_prompt_or_error",
                    return_value=("error", "Launching vmshell failed: Error starting crostini for terminal: 22 (CONTAINER_START_FAILED)"),
                ),
                self.assertRaisesRegex(RuntimeError, "unrecognized or incomplete buffer") as cm2,
            ):
                flow.verify_terminal_app_with_readiness_gate(dummy_vm, init_tgt, "terminauser", tracker2)
            self.assertNotIn("wait_cs:300", order)
            rendered2 = "".join(traceback.format_exception(cm2.exception))
            for tok in (
                "Host concierge/cicerone entries since t+   0.0s",
                "Chrome crostini/terminal/vsh log lines since t+   0.0s",
                "container start failed: 22",
            ):
                self.assertIn(tok, rendered2)
            for excluded in ("before window crostini line", "task queue exceeded allotted deadline"):
                self.assertNotIn(excluded, rendered2)

            with (
                mock.patch.object(flow, "_observe_terminal_until_prompt_or_error", return_value=("timeout", "[/          ]")),
                self.assertRaises(cdp.CDPTimeoutError) as cm_to,
            ):
                flow.verify_terminal_app_with_readiness_gate(dummy_vm, init_tgt, "terminauser", tracker2)
            rendered_to = "".join(traceback.format_exception(cm_to.exception))
            self.assertIn("Host concierge/cicerone entries since t+   0.0s", rendered_to)
            self.assertIn("container start failed: 22", rendered_to)

        dbus3 = _FakeDbusMon()
        tracker3 = flow._FlowTracker(dummy_vm, dbus3, _FakeScraper(dbus3, fail_scrape=True), FlowDiagnosticsObserver())  # type: ignore[arg-type]
        with (
            mock.patch.object(cdp.CDPConnection, "from_target", side_effect=lambda tgt, **_kw: mock.MagicMock(target_id=tgt["id"])),
            mock.patch.object(flow, "_observe_terminal_until_prompt_or_error", return_value=("error", flow.KNOWN_INITIAL_TERMINAL_TIMEOUT_ERROR)),
            self.assertRaisesRegex(OSError, "ssh scrape transport failed"),
        ):
            flow.verify_terminal_app_with_readiness_gate(dummy_vm, init_tgt, "terminauser", tracker3)

    # Real diagci-run3 sample-8 pre-ContainerStarted LaunchVshd self-close + sample-1 GetGarconSessionInfo error.
    _RUN3_S8_T_INST = flow.parse_rfc3339_utc("2026-11-02T13:04:49.760000Z")
    _RUN3_S8_MSGS = (
        "2026-11-02T13:05:17.956419Z INFO vm_concierge[2938]: Received request: SetUpVmUser\n"
        "2026-11-02T13:05:18.950000Z INFO vm_concierge[2938]: BalloonTrace throttled\n"
        "2026-11-02T13:06:29.026838Z INFO vm_concierge[2938]: Received request: SetUpVmUser\n"
        "2026-11-02T13:06:32.587221Z INFO vm_cicerone[2951]: Received LaunchVshd request\n"
        "2026-11-02T13:06:32.587687Z ERR vm_cicerone[2951]: Requested container does not exist: penguin\n"
        "2026-11-02T13:06:39.000000Z INFO vm_cicerone[2951]: Received GetGarconSessionInfo request\n"
        "2026-11-02T13:06:39.000500Z ERR vm_cicerone[2951]: Requested container does not exist: penguin\n"
        "2026-11-02T13:06:40.657831Z INFO vm_cicerone[2951]: Startup of container penguin at IP  for VM termina completed.\n"
    )

    def test_disable_close_on_exit_and_pre_gate_vsh_no_container(self) -> None:
        pref_ops: list[str] = []
        pref_vm = _dummy_vm(
            launch_swa_or_target=lambda url, **kw: pref_ops.append(f"launch:{url}"),
            close_cdp_page_targets_by_url=lambda urls, *, label, exclude_ids=None: pref_ops.append(f"close:{label}:{list(urls)}") or 1,
        )
        for readback_val, ok in ((False, True), (True, False), (0, False)):
            pref_ops.clear()
            fake_pref_conn = mock.MagicMock(
                poll_js=mock.MagicMock(return_value=True),
                eval_js=mock.MagicMock(return_value=readback_val),
                close=mock.MagicMock(side_effect=lambda: pref_ops.append("conn_close")),
            )
            pref_vm.connect_cdp_target = lambda *_a, _c=fake_pref_conn, **_kw: _c  # type: ignore[method-assign]
            if ok:
                flow.disable_terminal_close_on_exit(pref_vm)
                self.assertTrue(fake_pref_conn.eval_js.call_args.kwargs["await_promise"])
            else:
                with self.assertRaisesRegex(RuntimeError, "close-on-exit pref readback mismatch"):
                    flow.disable_terminal_close_on_exit(pref_vm)
            self.assertEqual(
                pref_ops,
                [
                    "launch:chrome-untrusted://terminal/html/terminal.html#home",
                    "conn_close",
                    "close:Terminal-PrefInit:['chrome-untrusted://terminal/html/terminal.html#home']",
                ],
            )

        entries, _ = flow.parse_host_init_logs(self._RUN3_S8_MSGS, "", self._RUN3_S8_T_INST)
        tid = "18D9B115931EAC4B3915094325B1E8C6"
        vsh_buf = (
            "[===========] Ready\n"
            "ERROR vsh: [../../../../../tmp/portage/chromeos-base/vm_host_tools-0.0.2-r3925/"
            "work/vm_host_tools-0.0.2/vm_tools/vsh/vsh.cc:173] Failed to launch vshd for "
            "termina:penguin: requested container does not exist: penguin"
        )
        vsh_syslog_buf = (
            "2026-11-02T13:06:32.587900Z ERROR vsh: [vsh.cc(198)] "
            "Failed to launch vshd for termina:penguin: requested container does not exist: penguin"
        )
        base_kw: dict[str, Any] = dict(
            terminal_buffer=vsh_buf, entries=entries, tab_launched_rel_sec=84.4, container_started_rel_sec=None, attempt=0
        )
        for buf_variant in (vsh_buf, vsh_syslog_buf):
            ev = flow.classify_terminal_setup_failure(**{**base_kw, "terminal_buffer": buf_variant})
            self.assertEqual((ev.call_index, ev.post_container_started, ev.daemon_label), (1, False, "Cicerone"))
        banner = flow.format_terminal_relaunch_banner(
            ev, failed_label="Terminal-App-Initial", target_id=tid, tab_launched_rel_sec=84.4, cs_rel_sec=111.2
        )
        self.assertIn("pre-ContainerStarted installer tab", banner)
        self.assertIn("Cicerone:  call #1 failed after 0.000s:", banner)
        self.assertEqual(flow.format_final_pass_line(flow.FlowResult(terminal_relaunch=ev)), flow.FINAL_PASS_LINE)

        post_ready, _ = flow.parse_host_init_logs(
            "2026-11-02T13:06:30.000000Z INFO vm_cicerone[2951]: Startup of container penguin at IP  for VM termina completed.\n"
            + self._RUN3_S8_MSGS,
            "",
            self._RUN3_S8_T_INST,
        )
        garcon_only, _ = flow.parse_host_init_logs("\n".join(self._RUN3_S8_MSGS.splitlines()[5:7]), "", self._RUN3_S8_T_INST)
        for desc, override in (
            ("attempt >= 1 fatal", {"attempt": 1}),
            ("ContainerStarted already fired", {"container_started_rel_sec": 80.0}),
            ("LaunchVshd older than tab launch", {"tab_launched_rel_sec": 105.0}),
            ("LaunchVshd after ContainerReadyLog", {"entries": post_ready}),
            ("GetGarconSessionInfo error without LaunchVshd", {"entries": garcon_only}),
            ("pre-CS vsh 5s poll timeout rejected", {"terminal_buffer": "[ERROR:vm_tools/vsh/vsh.cc:247] Poll timed out after waiting 5 seconds."}),
        ):
            with self.subTest(desc=desc), self.assertRaises(RuntimeError):
                flow.classify_terminal_setup_failure(**{**base_kw, **override})

        steps: list[str] = []
        dummy_vm = _dummy_vm(
            close_crosh_tab=lambda *_a, **_kw: 0,
            close_cdp_targets_matching=lambda *_a, **_kw: 0,
            check_devtools_tunnel_alive=lambda: steps.append("check_tunnel"),
        )
        scraper = flow.HostLogScraper()
        scraper.scrape = lambda _vm: setattr(scraper, "last_entries", entries) or entries  # type: ignore[method-assign]
        fresh_tab = mock.MagicMock(label="Terminal-App-Fresh", conn=mock.MagicMock(target_id="FRESH_1"))
        dbus_mon = mock.MagicMock(
            container_started_rel_sec=None,
            is_container_started=mock.MagicMock(side_effect=[False, True]),
            rel_mono=mock.MagicMock(return_value=112.0),
            wait_for_container_started=mock.MagicMock(
                side_effect=lambda timeout=300.0: setattr(dbus_mon, "container_started_rel_sec", 111.2)
                or steps.append(f"wait_cs:{int(timeout)}")
                or 111.2
            ),
        )
        tr = flow._FlowTracker(dummy_vm, dbus_mon, scraper, FlowDiagnosticsObserver())
        tr.initial_tab_launched_rel = 84.4
        obs_seq = iter([("error", vsh_buf), ("prompt", "[terminauser@penguin ~]$")])
        with (
            mock.patch.object(cdp.CDPConnection, "from_target", return_value=mock.MagicMock(target_id=tid)),
            mock.patch.object(flow, "_observe_terminal_until_prompt_or_error", side_effect=lambda *_a, **_kw: next(obs_seq)),
            mock.patch.object(flow, "_open_fresh_terminal_from_home", side_effect=lambda *_a, **kw: steps.append(f"open:{kw['label']}") or fresh_tab),
            mock.patch.object(flow, "LOG_FLUSH_TIMEOUT_SEC", 0.0),
        ):
            self.assertIsNotNone(flow.verify_terminal_app_with_readiness_gate(dummy_vm, {"id": tid}, "terminauser", tr))
            self.assertEqual(steps, ["wait_cs:300", "open:Terminal-App-Fresh", "wait_cs:60"])

        steps.clear()
        with (
            mock.patch.object(cdp.CDPConnection, "from_target", return_value=mock.MagicMock(target_id=tid)),
            mock.patch.object(
                flow, "_observe_terminal_until_prompt_or_error", side_effect=cdp.CDPError("WebSocketConnectionClosedException: Connection was lost")
            ),
            self.assertRaises(cdp.CDPError) as cm_disc,
        ):
            flow.verify_terminal_app_with_readiness_gate(dummy_vm, {"id": tid}, "terminauser", tr)
        self.assertEqual(steps, ["check_tunnel"])
        self.assertIn("Host concierge/cicerone entries since ", "".join(traceback.format_exception(cm_disc.exception)))

        lv_err_entries, _ = flow.parse_host_init_logs(
            "2026-11-02T13:06:32.000000Z INFO vm_cicerone[2951]: Received LaunchVshd request\n"
            "2026-11-02T13:06:37.001000Z ERR vm_cicerone[2951]: Failed to launch vshd in container: Deadline Exceeded\n",
            "",
            self._RUN3_S8_T_INST,
        )
        self.assertEqual([e.name for e in lv_err_entries], ["LaunchVshd", "LaunchVshdFailed"])
        tail_txt = scraper.format_window_tail(0.0, max_lines=1)
        self.assertIn("(last <=1):", tail_txt)
        self.assertIn("ContainerReadyLog", tail_txt)

    def test_classify_post_cs_vsh_listen_timeout_s3(self) -> None:
        # Verbatim cand-run3 sample-3 (e2e-sample-3.log L60-61, L95-102).
        t_inst = flow.parse_rfc3339_utc("2026-11-02T18:17:20.410000Z")
        s3_msgs = (
            "2026-11-02T18:24:07.180771Z INFO vm_concierge[3033]: VM with requested name is already running\n"
            "2026-11-02T18:24:07.211666Z INFO vm_concierge[3033]: Received request: SetUpVmUser\n"
            "2026-11-02T18:24:20.038826Z INFO vm_cicerone[3046]: Received LaunchVshd request\n"
        )
        s3_buf = (
            "WARNING vsh: [../libchrome-0.0.1/platform2/libchrome/dbus/bus.cc:652] "
            "Bus::SendWithReplyAndBlock took 1096ms to process message: type=method_call, "
            "path=/org/chromium/VmCicerone, interface=org.chromium.VmCicerone, member=LaunchVshd\n"
            "ERROR vsh: [../../../../../tmp/portage/chromeos-base/vm_host_tools-0.0.2-r3925/"
            "work/vm_host_tools-0.0.2/vm_tools/vsh/vsh.cc:240] Poll timed out after waiting 5 seconds."
        )
        s3_entries, _ = flow.parse_host_init_logs(s3_msgs, "", t_inst)
        base_kw: dict[str, Any] = dict(
            terminal_buffer=s3_buf, entries=s3_entries, tab_launched_rel_sec=406.8, container_started_rel_sec=406.5, attempt=1
        )
        for buf in (s3_buf, "[\\          ]\n" + s3_buf):
            ev = flow.classify_terminal_setup_failure(**{**base_kw, "terminal_buffer": buf})
            self.assertEqual((ev.call_index, ev.post_container_started, ev.daemon_label), (1, True, "Cicerone"))
        banner = flow.format_terminal_relaunch_banner(
            ev, failed_label="Terminal-App-Fresh", target_id="42FF70C6", tab_launched_rel_sec=406.8, cs_rel_sec=406.5
        )
        for tok in ("1/1 post-ContainerStarted", "ListenForVshd", "Received LaunchVshd request"):
            self.assertIn(tok, banner)
        self.assertIn(
            "1 Terminal relaunch used after post-ContainerStarted LaunchVshd call #1 vsh 5s poll timeout",
            flow.format_final_pass_line(flow.FlowResult(terminal_relaunch=ev)),
        )
        lv_err, _ = flow.parse_host_init_logs(
            s3_msgs + "2026-11-02T18:24:25.040000Z ERR vm_cicerone[3046]: Failed to launch vshd\n", "", t_inst
        )
        for desc, override in (
            ("pre-CS rejected", {"container_started_rel_sec": None}),
            ("missing LaunchVshd line", {"entries": [e for e in s3_entries if e.name != "LaunchVshd"]}),
            ("stale LaunchVshd before tab launch", {"tab_launched_rel_sec": 425.0}),
            ("cicerone LaunchVshd ERR present", {"entries": lv_err}),
            ("post-CS budget already used", {"post_cs_relaunch_used": True}),
            ("attempt budget exhausted", {"attempt": 2}),
        ):
            with self.subTest(desc=desc), self.assertRaises(RuntimeError):
                flow.classify_terminal_setup_failure(**{**base_kw, **override})

    def test_verify_concierge_balloon_timer_stopped(self) -> None:
        good_unfiltered = (
            "2026-11-02T15:19:38.700000Z INFO vm_concierge[2910]: New VM. Starting balloon resize timer\n"
            "2026-11-02T15:19:39.700000Z INFO vm_concierge[2910]: BalloonTrace throttled with size window: 214 MIB\n"
            "2026-11-02T15:19:39.850000Z INFO vm_concierge[2910]: Stopping balloon timer since timer_interval_millis is 0\n"
            "2026-11-02T15:20:39.731093Z INFO vm_concierge[2910]: Received request: SetUpVmUser\n"
        )
        entries, _ = flow.parse_host_init_logs(good_unfiltered, "", self._RUN3_S8_T_INST)
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

    def test_installer_and_pre_terminal_failures_attach_full_boot_evidence_once(self) -> None:
        owner_hash = "40b64e162fc1c96a5cb528822324554f4dffadef"
        t_inst = flow.parse_rfc3339_utc("2026-11-02T13:04:12.300000Z")
        raw_msgs = (
            "2026-11-02T13:04:05.000000Z INFO vm_concierge[3036]: pre-install CreateDiskImage noise\n"
            "2026-11-02T13:04:13.381184Z INFO vm_concierge[3036]: Received request: StartVm\n"
            "2026-11-02T13:04:13.495996Z INFO seneschal[2997]: Started server on /run/seneschal/scoped_dirDqcVKU\n"
            "2026-11-02T13:04:13.572448Z INFO vm_concierge[3036]: Invoking VM: /usr/bin/crosvm --syslog-tag VM(32) run\n"
            "2026-11-02T13:04:14.100000Z WARNING VM(32)[3812]: virtio_console: early message\n"
            "2026-11-02T13:09:13.674636Z ERR vm_concierge[3036]: Timed out waiting for VM to start: No such file or directory (2)\n"
            "2026-11-02T13:09:13.675569Z ERR vm_concierge[3036]: Error starting VM. VmStartCheckerStatus=3\n"
            "2026-11-02T13:09:15.701157Z WARNING vm_concierge[3036]: Shutdown RPC failed for VM 32 with error code 14: Connection timed out\n"
            "2026-11-02T13:09:25.711654Z WARNING vm_concierge[3036]: Failed to stop VM 32 via crosvm socket\n"
        )
        raw_chrome = (
            "2026-11-02T13:04:04.000000Z INFO chrome[2731:2731]: pre-install crostini line\n"
            "2026-11-02T13:09:13.382193Z ERROR chrome[2731:2731]: [crostini_manager.cc:515] Timed out in state kStartTerminaVm\n"
            "2026-11-02T13:09:13.383363Z ERROR chrome[2731:2731]: [crostini_manager.cc:1067] Failed to restart Crostini with error code: 54\n"
        )
        probe_out = (
            "===CONSOLE===\ndrwX------ 2 crosvm crosvm 80 Nov  2 13:04 .\n"
            "--- dGVybWluYQ==.log (142 bytes, 2 lines, first <=60 + last <=80) ---\n"
            "[    0.412345] systemd[1]: Systemd 258 running in system mode\n"
            "[  OK  ] Mounted /opt/google/cros-containers.\n"
            "===CROSVM_PS===\n"
            "(no crosvm processes running; concierge ~TerminaVm() stops failed StartVm instances before returning)\n"
        )
        seen_ssh: list[str] = []

        def _fake_ssh(cmd: str, **_kw: Any) -> Any:
            seen_ssh.append(cmd)
            for needle, out in (
                ("===CONSOLE===", probe_out),
                ("wc -l <", "10\n"),
                ("date -u +%s.%N", f"{t_inst:.6f}\n"),
                ("/var/log/messages", raw_msgs),
                ("/var/log/chrome/chrome", raw_chrome),
            ):
                if needle in cmd:
                    return mock.MagicMock(returncode=0, stdout=out, stderr="")
            raise AssertionError(f"Unexpected ssh command: {cmd}")

        fake_vm = _dummy_vm(
            owner_hash=owner_hash,
            ssh=_fake_ssh,
            launch_swa_or_target=lambda *_a, **_kw: None,
            close_cdp_targets_matching=lambda *_a, **_kw: 0,
            open_crosh_tab=lambda _lbl: mock.MagicMock(run_crosh_cmd=lambda *_a, **_kw: None),
            close_crosh_tab=lambda *_a, **_kw: None,
        )
        self.assertEqual(flow.collect_baguette_boot_evidence(fake_vm, None), "")

        settings_conn = mock.MagicMock(poll_js=mock.MagicMock(return_value="CLICKED_SETUP:Developers | | Set up"))
        inst_conn = mock.MagicMock(
            poll_js=mock.MagicMock(side_effect=["CLICKED_NEXT", "CLICKED_INSTALL:terminauser"]),
            eval_js=mock.MagicMock(
                return_value={
                    "err": "Error starting the virtual machine. Please try again.",
                    "installing": "This process may take a few minutes. Starting the virtual machine.",
                }
            ),
        )
        fake_vm.connect_cdp_target = mock.MagicMock(side_effect=[settings_conn, inst_conn])  # type: ignore[method-assign]
        readme_cmds = flow.ReadmeCommands("vmc create --vm-type BAGUETTE termina", "vsh termina penguin")
        with (
            mock.patch.object(flow, "disable_terminal_close_on_exit", lambda _vm: None),
            mock.patch.object(flow, "DbusSignalMonitor") as mock_dbus_cls,
        ):
            mock_dbus_cls.return_value.rel_mono.return_value = 300.1
            with self.assertRaisesRegex(RuntimeError, "Error starting the virtual machine") as cm_inst:
                flow.run_termina_user_flow(fake_vm, readme_cmds)

        msg = "".join(traceback.format_exception(cm_inst.exception))
        self.assertEqual(msg.count("Host concierge/cicerone entries since "), 1)
        self.assertTrue(any("vmlog_forwarder|crosvm|VM\\([0-9]+\\)" in c for c in seen_ssh))
        self.assertTrue(any(f"/run/daemon-store/crosvm/{owner_hash}/log" in c for c in seen_ssh))
        for tok in (
            "Host /var/log/messages (concierge/cicerone/seneschal/crosvm) since t+   0.0s",
            "seneschal[2997]: Started server",
            "VM(32)[3812]: virtio_console: early message",
            "Error starting VM. VmStartCheckerStatus=3",
            "Failed to stop VM 32 via crosvm socket",
            "Timed out in state kStartTerminaVm",
            f"Baguette VM console log (/run/daemon-store/crosvm/{owner_hash}/log, first <=60 + last <=80 lines):",
            "Mounted /opt/google/cros-containers.",
            "Host crosvm processes/threads (ps):",
            "no crosvm processes running",
        ):
            self.assertIn(tok, msg)
        for excluded in ("pre-install CreateDiskImage noise", "pre-install crostini line"):
            self.assertNotIn(excluded, msg)

        seen_ssh.clear()
        with (
            mock.patch.object(flow, "disable_terminal_close_on_exit", side_effect=RuntimeError("pref init failed")),
            mock.patch.object(flow, "DbusSignalMonitor"),
            self.assertRaisesRegex(RuntimeError, "pref init failed") as cm_pre,
        ):
            flow.run_termina_user_flow(fake_vm, readme_cmds)
        pre_msg = "".join(traceback.format_exception(cm_pre.exception))
        self.assertEqual(pre_msg.count("Host concierge/cicerone entries since "), 1)
        self.assertIn("pre-install CreateDiskImage noise", pre_msg)
        self.assertIn(
            f"Baguette VM console log (/run/daemon-store/crosvm/{owner_hash}/log, first <=60 + last <=80 lines):",
            pre_msg,
        )

        with tempfile.TemporaryDirectory() as tmp:
            log_dir_real = Path(tmp) / "log"
            log_dir_real.mkdir()
            (log_dir_real / "short.log").write_text("".join(f"short-{i:03d}\n" for i in range(1, 14)))
            (log_dir_real / "long.log").write_text("".join(f"long-{i:03d}\n" for i in range(1, 201)))
            sh_vm = _dummy_vm(
                ssh=lambda cmd, **_kw: subprocess.run(
                    ["sh", "-c", cmd.replace(f"/run/daemon-store/crosvm/{owner_hash}/log", str(log_dir_real))],
                    capture_output=True,
                    text=True,
                    check=False,
                )
            )
            ev = flow.collect_baguette_boot_evidence(sh_vm, owner_hash)
        self.assertEqual(ev.count("short-001"), 1)
        self.assertEqual(ev.count("short-013"), 1)
        self.assertEqual(ev.count("lines omitted"), 1)
        self.assertIn("... (60 lines omitted) ...", ev)
        for present in ("long-001", "long-060", "long-121", "long-200"):
            self.assertIn(present, ev)
        for omitted in ("long-061", "long-120"):
            self.assertNotIn(omitted, ev)

        long_cmd = "/usr/bin/crosvm --syslog-tag VM(32) run --cpus 4 --mem 6921 " + ("--flag=val " * 10)
        compacted = "\n".join(
            flow._compact_crosvm_ps_lines(
                "\n".join(
                    (
                        "PID LWP STAT %CPU %MEM ELAPSED WCHAN COMMAND COMMAND",
                        f"3695 3695 Sl 0.1 5.9 00:36 ep_poll crosvm {long_cmd}",
                        f"3695 3722 Rl 99.0 5.9 00:36 - crosvm_vcpu0 {long_cmd}",
                        f"3701 3701 Sl 0.0 0.9 00:36 skb_wait pcivirtio-block {long_cmd}",
                    )
                )
            )
        )
        self.assertEqual(compacted.count(long_cmd), 1)
        self.assertEqual(compacted.count("/usr/bin/crosvm ... (same cmdline)"), 2)
        self.assertIn("crosvm_vcpu0", compacted)
        self.assertIn("pcivirtio-block", compacted)

    def test_reraise_with_flow_evidence_preserves_traceback_tunnel_cause_and_idempotence(self) -> None:
        scrape_count = 0
        scraper = flow.HostLogScraper()

        def _count_scrape(_vm: Any) -> list[Any]:
            nonlocal scrape_count
            scrape_count += 1
            return []

        scraper.scrape = _count_scrape  # type: ignore[method-assign]
        alive_vm = _dummy_vm(owner_hash=None, check_devtools_tunnel_alive=lambda: None)

        orig_holder: list[RuntimeError] = []

        def _deep_cdp_helper() -> None:
            err = RuntimeError("boom in deep helper")
            orig_holder.append(err)
            raise err

        caught_deep: RuntimeError | None = None
        try:
            try:
                _deep_cdp_helper()
            except RuntimeError as exc_inner:
                flow._reraise_with_flow_evidence(exc_inner, alive_vm, scraper)
        except RuntimeError as caught:
            caught_deep = caught
        self.assertIsNotNone(caught_deep)
        assert caught_deep is not None
        self.assertIs(caught_deep, orig_holder[0])
        self.assertEqual(scrape_count, 1)
        self.assertEqual(len(getattr(caught_deep, "__notes__", ())), 1)
        deep_tb = "".join(traceback.format_exception(caught_deep))
        self.assertIn("in _deep_cdp_helper", deep_tb)
        self.assertIn("Host concierge/cicerone entries since ", deep_tb)

        # Idempotence across __notes__ (including TimeoutError subclasses).
        class _CustomTimeout(TimeoutError):
            pass

        scrape_count = 0
        with self.assertRaises(_CustomTimeout) as cm_idemp:
            try:
                try:
                    raise _CustomTimeout("first timeout")
                except _CustomTimeout as e1:
                    flow._reraise_with_flow_evidence(e1, alive_vm, scraper)
            except _CustomTimeout as e2:
                flow._reraise_with_flow_evidence(e2, alive_vm, scraper)
        self.assertEqual(scrape_count, 1)
        self.assertEqual(len(getattr(cm_idemp.exception, "__notes__", ())), 1)

        # Dead DevTools SSH tunnel chains `raise tunnel_exc from exc` and stays idempotent.
        scrape_count = 0
        tunnel_err = cdp.CDPError("DevTools SSH -L tunnel died (returncode=255)")
        dead_vm = _dummy_vm(
            owner_hash=None,
            check_devtools_tunnel_alive=mock.MagicMock(side_effect=tunnel_err),
        )
        orig_cdp = cdp.CDPError("WebSocketConnectionClosedException")

        def _deep_ws_recv() -> None:
            raise orig_cdp

        caught_tun: cdp.CDPError | None = None
        try:
            try:
                try:
                    _deep_ws_recv()
                except cdp.CDPError as cdp_e1:
                    flow._reraise_with_flow_evidence(cdp_e1, dead_vm, scraper)
            except cdp.CDPError as cdp_e2:
                flow._reraise_with_flow_evidence(cdp_e2, dead_vm, scraper)
        except cdp.CDPError as caught:
            caught_tun = caught

        self.assertIsNotNone(caught_tun)
        assert caught_tun is not None
        self.assertIs(caught_tun, tunnel_err)
        self.assertIs(caught_tun.__cause__, orig_cdp)
        self.assertEqual(scrape_count, 1)
        self.assertEqual(len(getattr(caught_tun, "__notes__", ())), 1)
        tun_tb = "".join(traceback.format_exception(caught_tun))
        self.assertIn("in _deep_ws_recv", tun_tb)
        self.assertIn("WebSocketConnectionClosedException", tun_tb)
        self.assertIn("The above exception was the direct cause of the following exception:", tun_tb)
        self.assertIn("DevTools SSH -L tunnel died", tun_tb)

    def test_emit_ci_relaunch_warning_and_step_summary(self) -> None:
        buf_empty = io.StringIO()
        self.assertEqual(flow.emit_ci_relaunch_warning(flow.FlowResult(), env={}, stream=buf_empty), [])
        self.assertEqual(buf_empty.getvalue(), "")

        s1_entries, _ = flow.parse_host_init_logs(self._RUN3_S8_MSGS, "", self._RUN3_S8_T_INST)
        ev_s1 = flow.classify_terminal_setup_failure(
            "ERROR vsh: [vsh.cc(198)] Failed to launch vshd for termina:penguin: requested container does not exist: penguin",
            s1_entries,
            tab_launched_rel_sec=84.4,
            container_started_rel_sec=None,
            attempt=0,
        )
        post_entries, _ = flow.parse_host_init_logs(self._RUN6_POST_MSGS, "", self._RUN6_T_INST)
        ev_s2 = flow.classify_terminal_setup_failure(
            flow.KNOWN_INITIAL_TERMINAL_TIMEOUT_ERROR,
            post_entries,
            tab_launched_rel_sec=291.4,
            container_started_rel_sec=284.3,
            attempt=1,
        )
        self.assertEqual(ev_s1.rule_id, "S1")
        self.assertEqual(ev_s2.rule_id, "S2")

        with tempfile.TemporaryDirectory() as td:
            summary_file = Path(td) / "step_summary.md"
            out_buf = io.StringIO()
            res = flow.FlowResult(terminal_relaunch=ev_s2, terminal_relaunches=(ev_s1, ev_s2))
            anns = flow.emit_ci_relaunch_warning(
                res, env={"GITHUB_STEP_SUMMARY": str(summary_file)}, stream=out_buf
            )
            self.assertEqual(len(anns), 2)
            out_lines = out_buf.getvalue().splitlines()
            self.assertEqual(len(out_lines), 2)
            self.assertTrue(out_lines[0].startswith("::warning title=Terminal relaunch (S1 - pre-ContainerStarted LaunchVshd)::"))
            self.assertIn("Requested container does not exist: penguin", out_lines[0])
            self.assertTrue(out_lines[1].startswith("::warning title=Terminal relaunch (S2 - SetUpVmUser 20s deadline)::"))
            self.assertIn("SetUpUser RPC failed: Deadline Exceeded", out_lines[1])
            summary_txt = summary_file.read_text(encoding="utf-8")
            self.assertIn("`S1: pre-ContainerStarted LaunchVshd`", summary_txt)
            self.assertIn("`S2: SetUpVmUser 20s deadline`", summary_txt)


if __name__ == "__main__":
    unittest.main()
