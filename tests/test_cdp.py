"""Offline unit tests for `scripts/user_flows/cdp.py`."""

from __future__ import annotations

import json
import sys
import time
import unittest
from pathlib import Path
from typing import Any
from unittest import mock

SCRIPTS_DIR = Path(__file__).resolve().parent.parent / "scripts"
if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))

from user_flows import cdp  # noqa: E402


class WebSocketTimeoutException(Exception):
    """Matches `websocket-client`'s `WebSocketTimeoutException` (does not subclass `TimeoutError`)."""


class WebSocketConnectionClosedException(Exception):
    pass


class FakeWS:
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


FAKE_TGT = {
    "id": "9F2A1B",
    "url": "chrome-untrusted://terminal/html/terminal.html?command=vmshell",
    "webSocketDebuggerUrl": "ws://127.0.0.1:41234/devtools/page/9F2A1B",
}


def _make_conn(
    frames: list[Any] | FakeWS,
    *,
    label: str = "Terminal-App-Initial",
    step: str = "init",
    timeout: float = 30.0,
) -> cdp.CDPConnection:
    ws = frames if isinstance(frames, FakeWS) else FakeWS(frames)
    return cdp.CDPConnection.from_target(
        FAKE_TGT, label=label, timeout=timeout, step_getter=lambda: step, connect_fn=lambda *_a, **_kw: ws
    )


class CDPConnectionTests(unittest.TestCase):
    def test_connect_and_recv_timeout_wrapping(self) -> None:
        with self.assertRaises(cdp.CDPTimeoutError) as ctx_conn:
            cdp.CDPConnection.from_target(
                FAKE_TGT,
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
            FAKE_TGT["url"],
            "9F2A1B",
            "step3:observe_initial_terminal",
            "waited=",
        ):
            self.assertIn(tok, str(ctx_conn.exception))

        hung_tab = cdp.CroshTab(
            "Terminal-App-Initial",
            _make_conn([WebSocketTimeoutException("")], step="step3:observe_initial_terminal"),
        )
        with self.assertRaises(cdp.CDPTimeoutError) as ctx_recv:
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

    def test_protocol_and_js_error_wrapping(self) -> None:
        for desc, frames, kind in (
            ("closed socket", [WebSocketConnectionClosedException("closed")], "call"),
            ("empty EOF frame", [], "call"),
            ("CDP protocol error", [json.dumps({"id": 1, "error": {"code": -32000, "message": "Target closed"}})], "call"),
            ("JS exceptionDetails", [json.dumps({"id": 1, "result": {"exceptionDetails": {"text": "TypeError"}}})], "eval_js"),
        ):
            with self.subTest(desc=desc), self.assertRaises(cdp.CDPError) as ctx_err:
                conn = _make_conn(
                    frames, label="Crostini-Installer", step="step2:wait_installer_complete", timeout=15.0
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

    def test_allow_error_and_session_events(self) -> None:
        seen_events: list[dict[str, Any]] = []
        ws = FakeWS(
            [
                json.dumps({"method": "Page.loadEventFired", "params": {}}),
                json.dumps({"id": 1, "error": {"code": -32000, "message": "Failed to open a new tab"}}),
            ]
        )
        conn = _make_conn(ws, label="Browser-LaunchOSSettings")
        res = conn.call("Target.createTarget", allow_error=True, session_id="SID1", on_event=seen_events.append)
        self.assertEqual(res["error"]["code"], -32000)
        self.assertEqual(len(seen_events), 1)
        self.assertEqual(json.loads(ws.sent[0])["sessionId"], "SID1")

    def test_poll_js_and_sleep_backoff(self) -> None:
        poll_conn = _make_conn(
            [
                json.dumps({"id": 1, "result": {"result": {"value": "no-next"}}}),
                json.dumps({"id": 2, "result": {"result": {"value": "CLICKED_NEXT"}}}),
            ],
            label="Crostini-Installer",
            step="step2:installer_click_next",
        )
        self.assertEqual(
            poll_conn.poll_js(
                "click()", lambda v: v == "CLICKED_NEXT", op_desc="Crostini-Installer:click_next", timeout=2.0, interval=0.01
            ),
            "CLICKED_NEXT",
        )

        timeout_poll = _make_conn(
            [json.dumps({"id": i, "result": {"result": {"value": "no-ui"}}}) for i in range(1, 30)],
            label="OS-Settings",
            step="step2:navigate_os_settings_click_setup",
        )
        with self.assertRaises(cdp.CDPTimeoutError) as ctx_poll:
            timeout_poll.poll_js(
                "nav()", lambda v: v == "CLICKED_SETUP", op_desc="OS-Settings:navigate_and_click_setup", timeout=0.05, interval=0.01
            )
        self.assertIn("last state='no-ui'", str(ctx_poll.exception))

        with mock.patch.object(cdp.time, "sleep"):
            self.assertAlmostEqual(cdp.sleep_backoff(0.5, 2.5, time.monotonic() + 10.0), 0.7)
            self.assertAlmostEqual(cdp.sleep_backoff(2.0, 2.5, time.monotonic() + 10.0), 2.5)
            self.assertAlmostEqual(cdp.sleep_backoff(0.01, 2.5, time.monotonic() + 10.0), 0.01)

    def test_crosh_tab_wait_for_and_bounded_max_lines(self) -> None:
        wait_tab = cdp.CroshTab(
            "Termina-Crosh",
            _make_conn(
                [json.dumps({"id": i, "result": {"result": {"value": "[===  ] Starting VM..."}}}) for i in range(1, 20)],
                label="Termina-Crosh",
                step="step4:crosh_vsh_reentry",
            ),
        )
        with self.assertRaises(cdp.CDPTimeoutError) as ctx_wait:
            wait_tab.wait_for(lambda txt: "crosh>" in txt, timeout=0.08, desc="crosh> prompt")
        for tok in ("Termina-Crosh.wait_for(crosh> prompt)", "[===  ] Starting VM..."):
            self.assertIn(tok, str(ctx_wait.exception))

        tail_ws = FakeWS([json.dumps({"id": 1, "result": {"result": {"value": "tail line"}}})])
        tail_tab = cdp.CroshTab("Terminal-App-Initial", _make_conn(tail_ws))
        self.assertEqual(tail_tab.get_text(max_lines=16), "tail line")
        expr = json.loads(tail_ws.sent[0])["params"]["expression"]
        self.assertIn("end - 16 + 1", expr)
        self.assertIn("ln.isWrapped", expr)


if __name__ == "__main__":
    unittest.main()
