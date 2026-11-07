#!/usr/bin/env python3
"""End-to-end verification of the arch-baguette ChromeOS UI user setup flow in a ChromeOS VM.

Drives the documented `README.md` `termina` + ChromeOS Settings Linux installer flow over
Chrome DevTools Protocol (CDP), gates Terminal readiness on `VmCicerone.ContainerStarted`,
and verifies `crosh` `vsh termina penguin` re-entry and guest UID/GID/group/`cros-garcon` contracts.
"""

from __future__ import annotations

import argparse
import importlib
import importlib.util
import os
import sys
import tempfile
from pathlib import Path
from typing import Any

from user_flows import DEFAULT_README_PATH, FlowDiagnosticsObserver, log
from user_flows.dbus import load_cros_protos
from user_flows.flow import (
    emit_ci_relaunch_warning,
    extract_readme_commands,
    format_final_pass_line,
    run_termina_user_flow,
)
from user_flows.vm import ChromeOSVM, ensure_cros_image, ensure_testing_rsa


def load_optional_diag_plugin() -> Any | None:
    """Loads `user_flows.diag` when installed; returns `None` on the base-only branch."""
    return importlib.import_module("user_flows.diag") if importlib.util.find_spec("user_flows.diag") else None


def build_arg_parser(diag_plugin: Any | None = None) -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    add = parser.add_argument
    add("--readme", type=Path, default=DEFAULT_README_PATH, help=f"Path to README.md (default: {DEFAULT_README_PATH})")
    add("--baguette-image", type=Path, default=Path("out/image/baguette_arch_rootfs.img.zst"), help="Path to baguette_arch_rootfs.img.zst to test")
    add("--cros-image", type=Path, default=None, help="Optional path to pre-extracted chromiumos_test_image.bin")
    add("--ssh-key", type=Path, default=None, help="Optional path to ChromeOS testing_rsa SSH private key")
    add("--cache-dir", type=Path, default=Path("/tmp/cros-vm-cache"), help="Cache directory for downloaded ChromeOS VM image and SSH key")
    add("--qemu-bin", default=os.environ.get("QEMU_BIN", "qemu-system-x86_64"), help="Path to qemu-system-x86_64 binary")
    add("--qemu-bios-dir", default=os.environ.get("QEMU_BIOS_DIR"), help="Optional path to QEMU BIOS/firmware directory (-L)")
    add("--qemu-smp", type=int, default=None, help="Override QEMU vCPU count (-smp) for testing constrained runners")
    add("--qemu-ram-gb", type=int, default=None, help="Override QEMU RAM in GiB (-m) for testing constrained runners")
    if diag_plugin is not None:
        diag_plugin.register_cli_args(parser)
    return parser


def main(argv: list[str] | None = None) -> int:
    diag_plugin = load_optional_diag_plugin()
    args = build_arg_parser(diag_plugin).parse_args(argv)

    protos = load_cros_protos()
    meta = protos.metadata
    log(
        f"Verified vendored ChromiumOS protos: board={meta['board']} "
        f"release={meta['cros_release']} platform2={meta['platform2_revision']}"
    )

    readme_cmds = extract_readme_commands(args.readme)
    if not args.baguette_image.exists():
        raise FileNotFoundError(f"Baguette image not found: {args.baguette_image}")

    args.cache_dir.mkdir(parents=True, exist_ok=True)
    ssh_key = args.ssh_key or ensure_testing_rsa(args.cache_dir)
    ssh_key.chmod(0o600)
    cros_image = args.cros_image or ensure_cros_image(args.cache_dir, meta)

    with tempfile.TemporaryDirectory(prefix="cros-e2e-", dir=args.cache_dir) as tmp_dir:
        work_dir = Path(tmp_dir)
        observer = diag_plugin.build_observer(args, work_dir=work_dir) if diag_plugin else FlowDiagnosticsObserver()
        vm = ChromeOSVM(
            base_image=cros_image,
            ssh_key=ssh_key,
            work_dir=work_dir,
            qemu_bin=args.qemu_bin,
            qemu_bios_dir=args.qemu_bios_dir,
            ram_gb=args.qemu_ram_gb,
            smp=args.qemu_smp,
            observer=observer,
        )
        try:
            vm.start()
            _ = vm.prepare_nested_vm_host_and_login(args.baguette_image)
            flow_result = run_termina_user_flow(vm, readme_cmds, observer=observer)
            emit_ci_relaunch_warning(flow_result)
            log(format_final_pass_line(flow_result))
            return 0
        finally:
            vm.stop()


if __name__ == "__main__":
    sys.exit(main())
