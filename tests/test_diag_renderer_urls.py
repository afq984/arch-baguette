"""Offline unit tests for `scripts/user_flows/diag/renderer_urls.py`."""

from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path
from typing import Any

SCRIPTS_DIR = Path(__file__).resolve().parent.parent / "scripts"
if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))

from user_flows.diag import DiagContext, renderer_urls  # noqa: E402


class RendererUrlsTests(unittest.TestCase):
    def test_compact_cdp_target_url_variants(self) -> None:
        self.assertEqual(
            renderer_urls.compact_cdp_target_url(
                "chrome-untrusted://terminal/html/terminal.html?command=vmshell&foo=bar#home"
            ),
            "chrome-untrusted://terminal/html/terminal.html?command=vmshell#home",
        )
        self.assertEqual(
            renderer_urls.compact_cdp_target_url(
                "chrome-extension://abcdefghijklmnop/background.html"
            ),
            "chrome-extension://abcdefgh/background.html",
        )
        self.assertEqual(
            renderer_urls.compact_cdp_target_url("about:blank", "Helper Frame"),
            "about:blank[Helper Frame]",
        )
        self.assertEqual(renderer_urls.compact_cdp_target_url("", "Title Only"), "[Title Only]")

    def test_snapshot_cdp_renderer_pids_extracts_process_id_and_preserves_non_blank(self) -> None:
        class _FakeBrowserConn:
            def __init__(self) -> None:
                self.detached: list[str] = []

            def call(self, method: str, params: dict[str, Any], **kwargs: Any) -> dict[str, Any]:
                if method == "Target.getTargets":
                    return {
                        "targetInfos": [
                            {
                                "targetId": "T1",
                                "type": "page",
                                "url": "chrome-untrusted://terminal/html/terminal.html?command=vmshell",
                                "title": "Terminal",
                            },
                            {
                                "targetId": "T2",
                                "type": "service_worker",
                                "url": "chrome://os-settings/sw.js",
                                "title": "",
                            },
                        ]
                    }
                if method == "Target.attachToTarget":
                    return {"sessionId": "S1"}
                if method == "Tracing.start":
                    on_ev = kwargs["on_event"]
                    on_ev(
                        {
                            "method": "Tracing.dataCollected",
                            "params": {
                                "value": [
                                    {
                                        "name": "TracingStartedInBrowser",
                                        "args": {
                                            "data": {
                                                "frames": [
                                                    {"frame": "T1", "processId": 4567, "url": ""},
                                                    {"frame": "sub", "processId": 4567, "url": "about:blank"},
                                                ]
                                            }
                                        },
                                    }
                                ]
                            },
                        }
                    )
                    return {}
                if method == "Tracing.end":
                    kwargs["on_event"]({"method": "Tracing.tracingComplete"})
                    return {}
                if method == "Target.detachFromTarget":
                    self.detached.append(params["sessionId"])
                    return {}
                raise AssertionError(f"Unexpected method {method}")

            def close(self) -> None:
                pass

        conn = _FakeBrowserConn()

        class _FakeVM:
            def connect_browser_cdp(self, *, label: str) -> _FakeBrowserConn:
                del label
                return conn

        with tempfile.TemporaryDirectory() as td:
            ctx = DiagContext(work_dir=Path(td), vm=_FakeVM())
            obs = renderer_urls.RendererUrlObserver(ctx)
            obs.on_ui_event("InitialTerminalObserved", "observed", 10.0)
            self.assertEqual(
                ctx.renderer_urls,
                {4567: "chrome-untrusted://terminal/html/terminal.html?command=vmshell"},
            )
            self.assertEqual(conn.detached, ["S1"])


if __name__ == "__main__":
    unittest.main()
