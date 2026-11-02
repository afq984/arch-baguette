"""Offline unit tests for `scripts/user_flows/diag/__init__.py` plugin loader and CLI selector."""

from __future__ import annotations

import sys
import tempfile
import types
import unittest
from pathlib import Path
from unittest import mock

SCRIPTS_DIR = Path(__file__).resolve().parent.parent / "scripts"
if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))

import test_user_flows  # noqa: E402
from user_flows import (  # noqa: E402
    CompositeDiagnosticsObserver,
    FlowDiagnosticsObserver,
)
from user_flows import diag  # noqa: E402


class DiagLoaderTests(unittest.TestCase):
    def test_parse_diag_selection_all_none_subset_and_unknown(self) -> None:
        installed = {"timeline", "guest", "resources"}
        self.assertEqual(diag.parse_diag_selection("all", installed), installed)
        self.assertEqual(diag.parse_diag_selection("none", installed), set())
        self.assertEqual(diag.parse_diag_selection("off", installed), set())
        self.assertEqual(
            diag.parse_diag_selection("timeline, guest", installed),
            {"timeline", "guest"},
        )
        with self.assertRaisesRegex(ValueError, "Unknown --diag module"):
            diag.parse_diag_selection("timeline,bogus", installed)

    def test_build_observer_with_mocked_submodules_and_context_recorder(self) -> None:
        events: list[str] = []

        class _FakeTimelineObs(FlowDiagnosticsObserver):
            def __init__(self, ctx: diag.DiagContext) -> None:
                self.ctx = ctx

            def collect(self, *, strict: bool) -> None:
                events.append(f"collect:{strict}:{len(self.ctx.ui_entries)}:{len(self.ctx.dbus_entries)}")

            def format_report(self, *, include_verbose: bool) -> str:
                return f"timeline_report(verbose={include_verbose})"

        fake_mod = types.ModuleType("user_flows.diag.timeline")
        fake_mod.create_observer = lambda _args, ctx: _FakeTimelineObs(ctx)  # type: ignore[attr-defined]

        with (
            tempfile.TemporaryDirectory() as td,
            mock.patch.object(
                diag, "discover_installed_modules", return_value={"timeline": fake_mod}
            ),
        ):
            parser = test_user_flows.build_arg_parser(diag)
            args_none = parser.parse_args(["--diag", "none"])
            obs_none = diag.build_observer(args_none, work_dir=Path(td))
            self.assertIs(type(obs_none), FlowDiagnosticsObserver)

            args_all = parser.parse_args(["--diag", "all"])
            obs_all = diag.build_observer(args_all, work_dir=Path(td))
            self.assertIsInstance(obs_all, CompositeDiagnosticsObserver)

            obs_all.on_install_clicked(
                username="terminauser", mono_ts=100.0, vm_epoch_sec=1700000000.0
            )
            obs_all.on_ui_event("InstallerClosed", "closed", 12.5)
            obs_all.on_dbus_signal(
                iface="org.chromium.VmCicerone",
                member="ContainerStarted",
                vm_name="termina",
                detail="vm='termina'",
                rel_sec=15.0,
                msg=None,
            )
            obs_all.on_readiness_gate_passed(15.0)
            obs_all.collect(strict=True)
            self.assertEqual(events, ["collect:True:2:1"])
            self.assertEqual(
                obs_all.format_report(include_verbose=False),
                "timeline_report(verbose=False)",
            )


if __name__ == "__main__":
    unittest.main()
