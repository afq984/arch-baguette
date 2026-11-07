"""ChromeOS QEMU VM lifecycle, SSH/vsh/vmc transport, nested-KVM rig prep, and CDP target helpers."""

from __future__ import annotations

import base64
import dataclasses
import hashlib
import json
import os
import shlex
import shutil
import signal
import socket
import subprocess
import tempfile
import time
import urllib.request
from pathlib import Path
from typing import Any, Callable, Iterable, TypeVar

from google.protobuf.message import Message

from . import GCS_ARCHIVE_ROOT, FlowDiagnosticsObserver, log, terminate_proc
from .cdp import (
    CDPConnection,
    CDPError,
    CDPTimeoutError,
    CroshTab,
    format_cdp_error_context,
    is_ws_timeout_exc,
    sleep_backoff,
)
from .dbus import (
    load_cros_protos,
    parse_and_validate_proto,
    parse_dbus_send_byte_array,
    to_dbus_byte_arg,
    verify_lsb_release_matches_metadata,
)

TMessage = TypeVar("TMessage", bound=Message)

TESTING_RSA_GITILES_URL = (
    "https://chromium.googlesource.com/chromiumos/chromite/+/refs/heads/main/ssh_keys/testing_rsa?format=TEXT"
)

class VMCommandTimeoutError(TimeoutError):
    """Structured VM ssh/vsh/scp timeout including operation, step, command summary, and elapsed wait."""


def _summarize_cmd(cmd: str, max_len: int = 120) -> str:
    flat = " ".join(cmd.split())
    return flat if len(flat) <= max_len else (flat[: max_len - 3] + "...")


def format_vm_cmd_error_context(
    *, operation: str, step: str, cmd_summary: str, elapsed_sec: float, timeout_sec: float
) -> str:
    return (
        f"operation={operation!r} step={step!r} cmd={cmd_summary!r} "
        f"waited={elapsed_sec:.2f}s (timeout={timeout_sec:.1f}s)"
    )


@dataclasses.dataclass(frozen=True)
class HostCpuMemInfo:
    vendor_id: str
    model_name: str
    nproc: int
    mem_total_mib: float
    mem_avail_mib: float


def read_host_cpu_and_mem(
    cpuinfo_text: str | None = None, meminfo_text: str | None = None
) -> HostCpuMemInfo:
    """Reads host CPU vendor/model/core count and total/available RAM from `/proc`."""
    c_txt = cpuinfo_text if cpuinfo_text is not None else Path("/proc/cpuinfo").read_text("utf-8", "replace")
    m_txt = meminfo_text if meminfo_text is not None else Path("/proc/meminfo").read_text("utf-8", "replace")
    vendor_id = model_name = ""
    nproc = 0
    for line in c_txt.splitlines():
        if ":" in line:
            k, v = (x.strip() for x in line.split(":", 1))
            if k == "processor":
                nproc += 1
            elif k == "vendor_id" and not vendor_id:
                vendor_id = v
            elif k == "model name" and not model_name:
                model_name = v
    mem_kv = {
        k.strip(): int(toks[0])
        for line in m_txt.splitlines()
        if ":" in line
        for k, rest in (line.split(":", 1),)
        if (toks := rest.split())
    }
    if "MemTotal" not in mem_kv or "MemAvailable" not in mem_kv:
        raise ValueError("Host /proc/meminfo missing MemTotal or MemAvailable")
    return HostCpuMemInfo(
        vendor_id=vendor_id or "unknown",
        model_name=model_name or "unknown",
        nproc=max(1, nproc),
        mem_total_mib=mem_kv["MemTotal"] / 1024.0,
        mem_avail_mib=mem_kv["MemAvailable"] / 1024.0,
    )


def detect_host_qemu_cpu_arg(cpuinfo_text: str | None = None) -> str:
    """Selects QEMU `-cpu` model matching `chromite/lib/vm.py` for Intel vs AMD KVM hosts."""
    mem_stub = "MemTotal: 8388608 kB\nMemAvailable: 6291456 kB\n" if cpuinfo_text is not None else None
    info = read_host_cpu_and_mem(cpuinfo_text=cpuinfo_text, meminfo_text=mem_stub)
    if info.vendor_id == "AuthenticAMD":
        return "Opteron_G4,-invpcid,-tsc-deadline,check,svm=on"
    if info.vendor_id == "GenuineIntel":
        return "Haswell-noTSX,-invpcid,-tsc-deadline,check,vmx=on"
    raise RuntimeError(
        f"Unsupported host CPU vendor {info.vendor_id!r} in /proc/cpuinfo (expected GenuineIntel or AuthenticAMD)"
    )


def default_vm_ram_gb() -> int:
    """Clamps default VM RAM between 4 GiB and 8 GiB based on host MemAvailable."""
    return min(8, max(4, int(read_host_cpu_and_mem().mem_avail_mib // 1024) - 2))


def assert_host_kvm_available() -> None:
    kvm_path = Path("/dev/kvm")
    if not kvm_path.exists():
        raise RuntimeError("/dev/kvm does not exist on the host; KVM is required for nested VM tests")
    if not os.access(kvm_path, os.R_OK | os.W_OK):
        raise RuntimeError(
            "/dev/kvm is not readable/writable by the current user (try `sudo chmod 0666 /dev/kvm`)"
        )


def find_free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


def find_sbin_tool(name: str) -> str:
    found = shutil.which(name, path=f"{os.environ.get('PATH', '')}:/usr/sbin:/sbin")
    if not found:
        raise FileNotFoundError(f"Required host binary '{name}' not found in PATH or /usr/sbin")
    return found


def ensure_testing_rsa(cache_dir: Path) -> Path:
    key_path = cache_dir / "testing_rsa"
    if not (key_path.is_file() and key_path.stat().st_size > 0):
        log(f"Downloading public ChromeOS testing_rsa key to {key_path}...")
        cache_dir.mkdir(parents=True, exist_ok=True)
        with urllib.request.urlopen(TESTING_RSA_GITILES_URL, timeout=30) as resp:
            decoded = base64.b64decode(resp.read())
        if not decoded:
            raise RuntimeError(f"Downloaded empty testing_rsa key from {TESTING_RSA_GITILES_URL}")
        fd, tmp_name = tempfile.mkstemp(prefix=".testing_rsa.", dir=cache_dir)
        tmp_path = Path(tmp_name)
        try:
            with os.fdopen(fd, "wb") as f:
                f.write(decoded)
            tmp_path.chmod(0o600)
            os.replace(tmp_path, key_path)
        finally:
            tmp_path.unlink(missing_ok=True)
    key_path.chmod(0o600)
    return key_path


def ensure_cros_image(cache_dir: Path, meta: dict[str, Any]) -> Path:
    board, cros_release = str(meta["board"]), str(meta["cros_release"])
    img_dir = cache_dir / f"{board}-{cros_release}"
    img_path = img_dir / "chromiumos_test_image.bin"
    if img_path.is_file() and img_path.stat().st_size > 0:
        log(f"Using cached ChromeOS image: {img_path}")
        return img_path

    img_dir.mkdir(parents=True, exist_ok=True)
    img_path.unlink(missing_ok=True)
    url = f"{GCS_ARCHIVE_ROOT}/{board}/{cros_release}/chromiumos_test_image.tar.xz"
    log(f"Stream-extracting {url} into {img_dir} (sparse, atomic)...")
    with tempfile.TemporaryDirectory(prefix=".extract-", dir=img_dir) as stage_dir_str:
        stage_dir = Path(stage_dir_str)
        subprocess.run(
            ["bash", "-o", "pipefail", "-c", f"curl -fL --retry 3 '{url}' | tar --sparse -xJ -C '{stage_dir}'"],
            check=True,
        )
        staged_img = stage_dir / "chromiumos_test_image.bin"
        if not staged_img.is_file() or staged_img.stat().st_size <= 0:
            raise FileNotFoundError(f"Expected non-empty {staged_img.name} after extracting {url}")
        os.replace(staged_img, img_path)
    return img_path


def pid_matches_qemu(pid: int, qemu_bin: str, proc_root: Path = Path("/proc")) -> bool:
    """Returns True iff `/proc/<pid>` is a live userland QEMU/KVM process matching `qemu_bin`."""
    proc_dir = proc_root / str(pid)
    try:
        if not (proc_dir / "comm").exists():
            return False
        comm = (proc_dir / "comm").read_text("utf-8", "replace").strip()
        raw_cmdline = (proc_dir / "cmdline").read_bytes() if (proc_dir / "cmdline").exists() else b""
    except OSError:
        return False
    # Kernel threads (e.g. `kvm-irqfd-clean`, `kvm-pit/...`) have empty `/proc/<pid>/cmdline`.
    if not raw_cmdline:
        return False
    argv0_name = Path(raw_cmdline.split(b"\x00", 1)[0].decode("utf-8", "replace")).name
    expected_name = Path(qemu_bin).name
    return bool(
        (expected_name and (argv0_name == expected_name or comm == expected_name[:15]))
        or argv0_name.startswith(("qemu-system", "qemu-kvm"))
        or argv0_name in ("kvm", "qemu-kvm")
        or comm.startswith(("qemu-system", "qemu-kvm"))
    )


class ChromeOSVM:
    """Manages QEMU ChromeOS VM lifecycle, SSH/vsh/vmc execution, and CDP connections."""

    def __init__(
        self,
        base_image: Path,
        ssh_key: Path,
        work_dir: Path,
        qemu_bin: str = "qemu-system-x86_64",
        qemu_bios_dir: str | None = None,
        ram_gb: int | None = None,
        smp: int | None = None,
        observer: FlowDiagnosticsObserver | None = None,
    ) -> None:
        self.base_image = base_image
        self.ssh_key = ssh_key
        self.work_dir = work_dir
        self.qemu_bin = qemu_bin
        self.qemu_bios_dir = qemu_bios_dir
        self.ram_gb = ram_gb if ram_gb is not None else default_vm_ram_gb()
        self.smp = smp if smp is not None else min(8, os.cpu_count() or 4)
        self.observer = observer or FlowDiagnosticsObserver()
        self.ssh_port = find_free_port()
        self.vm_image = self.work_dir / "cros_vm.bin"
        self.pid_file = self.work_dir / "kvm.pid"
        self.serial_log = self.work_dir / "kvm.serial"
        self.owner_hash: str | None = None
        self._devtools_fwd_proc: subprocess.Popen[Any] | None = None
        self._local_dt_port: int | None = None
        self._remote_dt_port: int | None = None
        self._browser_ws_path: str | None = None
        self._current_step = "init"

    def set_step(self, step: str) -> None:
        self._current_step = step
        self.observer.on_step(step)

    def get_step(self) -> str:
        return self._current_step

    def _ssh_common_opts(self) -> list[str]:
        return [
            "-i", str(self.ssh_key),
            "-o", "IdentitiesOnly=yes",
            "-o", "StrictHostKeyChecking=no",
            "-o", "UserKnownHostsFile=/dev/null",
        ]

    def ssh_base_cmd(self) -> list[str]:
        return [
            "ssh", *self._ssh_common_opts(),
            "-o", "ConnectTimeout=5",
            "-o", "ServerAliveInterval=20",
            "-o", "ServerAliveCountMax=6",
            "-p", str(self.ssh_port),
            "root@127.0.0.1",
        ]

    def _run_vm_cmd(
        self,
        argv: list[str],
        *,
        op_desc: str,
        cmd_summary: str,
        timeout: int,
        check: bool = True,
        capture_output: bool = True,
    ) -> subprocess.CompletedProcess[str]:
        t0 = time.monotonic()
        try:
            return subprocess.run(argv, check=check, text=True, timeout=timeout, capture_output=capture_output)
        except subprocess.TimeoutExpired as exc:
            raw_err = exc.stderr.decode("utf-8", "replace") if isinstance(exc.stderr, bytes) else (exc.stderr or "")
            err_snip = " | ".join(ln.strip() for ln in raw_err.splitlines() if ln.strip())[:160]
            ctx = format_vm_cmd_error_context(
                operation=op_desc,
                step=self.get_step(),
                cmd_summary=_summarize_cmd(cmd_summary),
                elapsed_sec=time.monotonic() - t0,
                timeout_sec=timeout,
            )
            raise VMCommandTimeoutError(
                f"VM command timed out ({ctx})" + (f"; stderr={err_snip!r}" if err_snip else "")
            ) from exc
        except subprocess.CalledProcessError as exc:
            log(
                f"VM command failed ({op_desc}, step={self.get_step()!r}, rc={exc.returncode}):\n"
                f"STDOUT:\n{exc.stdout}\nSTDERR:\n{exc.stderr}"
            )
            raise

    def ssh(
        self,
        remote_cmd: str,
        check: bool = True,
        timeout: int = 300,
        capture_output: bool = True,
        *,
        op_desc: str = "ssh",
        cmd_summary: str | None = None,
    ) -> subprocess.CompletedProcess[str]:
        return self._run_vm_cmd(
            [*self.ssh_base_cmd(), remote_cmd],
            op_desc=op_desc,
            cmd_summary=cmd_summary or remote_cmd,
            timeout=timeout,
            check=check,
            capture_output=capture_output,
        )

    def scp_to(self, local_path: Path, remote_path: str, *, timeout: int = 180, op_desc: str = "scp_to") -> None:
        self._run_vm_cmd(
            ["scp", *self._ssh_common_opts(), "-P", str(self.ssh_port), str(local_path), f"root@127.0.0.1:{remote_path}"],
            op_desc=op_desc,
            cmd_summary=f"{local_path.name} -> {remote_path}",
            timeout=timeout,
        )

    def dbus_call_proto(
        self, dest: str, method: str, req_msg: Message, resp_cls: type[TMessage], timeout: int = 30
    ) -> tuple[TMessage, bytes]:
        """Executes a synchronous D-Bus protobuf method call on the system bus and validates the reply."""
        ctx = f"{dest.rsplit('.', 1)[-1]}.{method}"
        res = self.ssh(
            f"dbus-send --system --type=method_call --print-reply "
            f"--dest={dest} /{dest.replace('.', '/')} {dest}.{method} "
            f"{to_dbus_byte_arg(req_msg.SerializeToString())}",
            check=True,
            timeout=timeout,
            op_desc=f"dbus_call_proto({ctx})",
            cmd_summary=f"dbus-send {dest}.{method}",
        )
        raw_resp = parse_dbus_send_byte_array(res.stdout, ctx)
        return parse_and_validate_proto(raw_resp, resp_cls, ctx), raw_resp

    def vsh(
        self,
        vm_name: str,
        user: str,
        sh_script: str,
        *,
        check: bool = True,
        timeout: int = 60,
        op_desc: str | None = None,
    ) -> subprocess.CompletedProcess[str]:
        """Runs `sh -lc <sh_script>` inside `vm_name` via `vsh` as `chronos`."""
        assert self.owner_hash
        oh = shlex.quote(self.owner_hash)
        cmd = (
            f"sudo -u chronos CROS_USER_ID_HASH={oh} "
            f"vsh --vm_name={shlex.quote(vm_name)} --owner_id={oh} "
            f"--user={shlex.quote(user)} -- sh -lc {shlex.quote(sh_script)}"
        )
        return self.ssh(cmd, check=check, timeout=timeout, op_desc=op_desc or f"vsh({vm_name},{user})", cmd_summary=sh_script)

    def vmc(self, *args: str, timeout: int = 120) -> subprocess.CompletedProcess[str]:
        """Runs non-interactive `vmc <args...>` as `chronos`."""
        assert self.owner_hash
        quoted = " ".join(shlex.quote(a) for a in args)
        return self.ssh(
            f"sudo -u chronos CROS_USER_ID_HASH={shlex.quote(self.owner_hash)} VMC_NONINTERACTIVE=1 vmc {quoted}",
            timeout=timeout,
            op_desc=f"vmc({args[0]})" if args else "vmc",
            cmd_summary=f"vmc {' '.join(args)}",
        )

    def wait_for_ssh(self, timeout_sec: int = 90, different_from_boot_id: str | None = None) -> str:
        t0 = time.monotonic()
        deadline = t0 + timeout_sec
        while time.monotonic() < deadline:
            try:
                res = self.ssh("cat /proc/sys/kernel/random/boot_id", check=False, timeout=8, op_desc="wait_for_ssh:probe")
            except VMCommandTimeoutError:
                res = None
            if res is not None and res.returncode == 0:
                boot_id = res.stdout.strip()
                if boot_id and (different_from_boot_id is None or boot_id != different_from_boot_id):
                    return boot_id
            time.sleep(1.5)
        ctx = format_vm_cmd_error_context(
            operation="wait_for_ssh",
            step=self.get_step(),
            cmd_summary=f"ssh root@127.0.0.1:{self.ssh_port} boot_id",
            elapsed_sec=time.monotonic() - t0,
            timeout_sec=timeout_sec,
        )
        raise VMCommandTimeoutError(f"Timed out waiting for SSH ({ctx})")

    def assert_guest_kvm_available(self) -> None:
        if self.ssh("test -c /dev/kvm", check=False, timeout=15).returncode != 0:
            diag = self.ssh(
                "grep -E 'vendor_id|model name|flags' /proc/cpuinfo | head -n 6; "
                "head -n 1 /sys/module/kvm_*/parameters/nested 2>&1 || true",
                check=False,
                timeout=15,
            )
            raise RuntimeError(
                f"Nested KVM (/dev/kvm) is missing inside the ChromeOS VM!\nDiagnostics:\n{diag.stdout}\n{diag.stderr}"
            )

    def start(self) -> None:
        assert_host_kvm_available()
        self.work_dir.mkdir(parents=True, exist_ok=True)
        log(f"Preparing working ChromeOS disk image at {self.vm_image}...")
        reflink = subprocess.run(["cp", "--reflink=always", str(self.base_image), str(self.vm_image)], capture_output=True)
        if reflink.returncode != 0:
            subprocess.run(["cp", "--sparse=always", str(self.base_image), str(self.vm_image)], check=True)
        # Grow disk sparsely by +12 GiB and resize partition 1 (STATE) on the host
        # so /mnt/stateful_partition has ~15 GiB free while using 0 extra host bytes.
        subprocess.run(["truncate", "-s", "+12G", str(self.vm_image)], check=True)
        subprocess.run([find_sbin_tool("sgdisk"), "-e", str(self.vm_image)], check=True, stdout=subprocess.DEVNULL)
        parted_res = subprocess.run(
            [find_sbin_tool("parted"), "-s", str(self.vm_image), "resizepart", "1", "100%"],
            check=False, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True,
        )
        if parted_res.returncode != 0:
            raise RuntimeError(f"parted resizepart failed: {parted_res.stderr}")

        cpu_arg = detect_host_qemu_cpu_arg()
        qemu_cmd = [self.qemu_bin, *(["-L", self.qemu_bios_dir] if self.qemu_bios_dir else [])]
        qemu_cmd += [
            "-m", f"{self.ram_gb}G", "-smp", str(self.smp),
            "-daemonize", "-pidfile", str(self.pid_file), "-serial", f"file:{self.serial_log}",
            "-cpu", cpu_arg, "-usb",
            "-device", "nec-usb-xhci", "-device", "usb-tablet", "-device", "usb-kbd",
            "-device", "virtio-net,netdev=eth0", "-device", "virtio-scsi-pci,id=scsi",
            "-device", "virtio-rng", "-device", "scsi-hd,drive=hd,rotation_rate=1",
            "-drive", f"if=none,id=hd,file={self.vm_image},cache=unsafe,format=raw,discard=unmap",
            "-netdev", f"user,id=eth0,net=10.0.2.0/27,hostfwd=tcp:127.0.0.1:{self.ssh_port}-:22",
            "-enable-kvm", "-display", "none", "-vga", "virtio",
        ]
        log(f"Booting QEMU ChromeOS VM on SSH port {self.ssh_port} (ram={self.ram_gb}G, smp={self.smp}, cpu={cpu_arg})...")
        self.set_step("prepare:boot_cros_vm")
        subprocess.run(qemu_cmd, check=True)
        self.wait_for_ssh()
        protos = load_cros_protos()
        verify_lsb_release_matches_metadata(self.ssh("cat /etc/lsb-release").stdout, protos.metadata)
        self.assert_guest_kvm_available()
        self.observer.on_vm_started(self)
        log(
            f"SSH connected to ChromeOS VM (verified /etc/lsb-release == "
            f"{protos.metadata['board']}/{protos.metadata['cros_release']}, nested /dev/kvm present)."
        )

    def stop(self) -> None:
        try:
            self.observer.close()
        except Exception as exc:
            log(f"Warning closing observer during VM stop: {exc}")
        terminate_proc(self._devtools_fwd_proc)
        self._devtools_fwd_proc = None

        if self.pid_file.exists():
            try:
                pid = int(self.pid_file.read_text().strip())
                proc_dir = Path(f"/proc/{pid}")
                if pid_matches_qemu(pid, self.qemu_bin):
                    os.kill(pid, signal.SIGCONT)
                    os.kill(pid, signal.SIGTERM)
                    deadline = time.monotonic() + 5.0
                    while time.monotonic() < deadline and proc_dir.exists():
                        time.sleep(0.2)
                    if proc_dir.exists():
                        os.kill(pid, signal.SIGKILL)
                    log(f"Terminated QEMU PID {pid}.")
            except (ProcessLookupError, PermissionError, ValueError, OSError):
                pass
            self.pid_file.unlink(missing_ok=True)

    def prepare_nested_vm_host_and_login(self, baguette_image: Path) -> str:
        self.set_step("prepare:remove_rootfs_verification_and_reboot")
        log("Removing rootfs verification to apply nested-KVM vm_concierge fix...")
        pre_boot_id = self.ssh("cat /proc/sys/kernel/random/boot_id").stdout.strip()
        self.ssh("/usr/share/vboot/bin/make_dev_ssd.sh --remove_rootfs_verification --partitions 2")
        try:
            self.ssh("reboot", check=False, timeout=20, op_desc="prepare:reboot")
        except VMCommandTimeoutError:
            pass
        self.wait_for_ssh(timeout_sec=120, different_from_boot_id=pre_boot_id)
        self.assert_guest_kvm_available()

        self.set_step("prepare:resize_stateful_and_patch_concierge")
        log("Expanding /dev/sda1 (/mnt/stateful_partition) and patching vm_concierge for nested KVM...")
        # In nested KVM on Intel/AMD hosts, QEMU exposes CPU vulnerability sysfs files
        # (/sys/devices/system/cpu/vulnerabilities/{l1tf,mds}) that cause vm_concierge to
        # reject untrusted guest VMs unless patched to read "Not affected". Also replace
        # `printk.devkmsg=on` with `quiet loglevel=0 ` to quiet inner crosvm serial I/O.
        setup_script = """
set -euo pipefail
mount -o remount,rw /
resize2fs /dev/sda1
df -h /mnt/stateful_partition
echo "Not affected" > /etc/not_affected
chmod 644 /etc/not_affected
python3 -c '
p = "/usr/bin/vm_concierge"
d = open(p, "rb").read()
for old in [b"/sys/devices/system/cpu/vulnerabilities/l1tf", b"/sys/devices/system/cpu/vulnerabilities/mds"]:
    assert old in d, f"Expected {old!r} in {p}"
    new = b"/etc/" + (b"/" * (len(old) - len(b"/etc/not_affected"))) + b"not_affected"
    assert len(old) == len(new)
    d = d.replace(old, new)
old2, new2 = b"printk.devkmsg=on", b"quiet loglevel=0 "
assert old2 in d and len(old2) == len(new2), f"Expected {old2!r} in {p}"
open(p + ".patched", "wb").write(d.replace(old2, new2))
'
chmod 755 /usr/bin/vm_concierge.patched
mv /usr/bin/vm_concierge.patched /usr/bin/vm_concierge
if ! grep -q "enable-features=Baguette" /etc/chrome_dev.conf; then
  echo "--enable-features=Baguette,Crostini,CrostiniContainerless" >> /etc/chrome_dev.conf
fi
stop vm_concierge || true
sync
"""
        res_setup = self.ssh(setup_script)
        log(f"Stateful partition resized:\n{res_setup.stdout.strip()}")

        self.set_step("prepare:autologin")
        log("Logging in ChromeOS session...")
        res_login = self.ssh(
            "set -euo pipefail\nstop vm_concierge || true\n"
            "/usr/local/autotest/bin/autologin.py -d "
            "--disable-feature=CryptohomeRecoveryByDefaultForConsumers "
            "-w --no-popup-notification\n"
            'HASH=$(ls /home/user/)\necho "CROS_OWNER_HASH=$HASH"\n'
            "dbus-send --system --type=method_call --print-reply "
            "--dest=org.chromium.ChromeFeaturesService /org/chromium/ChromeFeaturesService "
            'org.chromium.ChromeFeaturesServiceInterface.IsCrostiniEnabled "string:$HASH"',
            timeout=180,
        )
        if "boolean true" not in res_login.stdout:
            raise RuntimeError(f"IsCrostiniEnabled did not return true:\n{res_login.stdout}")
        markers = {
            k: v.strip()
            for ln in res_login.stdout.splitlines()
            if "=" in ln
            for k, v in (ln.split("=", 1),)
        }
        owner_hash = markers.get("CROS_OWNER_HASH", "")
        if not owner_hash:
            raise RuntimeError("Failed to find mounted cryptohome hash under /home/user/")
        self.owner_hash = owner_hash
        log(f"Logged in (IsCrostiniEnabled=true)! CROS_USER_ID_HASH = {owner_hash}")

        self.set_step("prepare:scp_baguette_image")
        remote_dl = f"/home/user/{owner_hash}/MyFiles/Downloads/baguette_arch_rootfs.img.zst"
        log(f"Copying {baguette_image} -> {remote_dl}...")
        self.scp_to(baguette_image, remote_dl, op_desc="prepare:scp_baguette_image")
        local_sha = hashlib.sha256(baguette_image.read_bytes()).hexdigest()
        remote_sha = self.ssh(f"sha256sum '{remote_dl}'").stdout.split()[0]
        if local_sha != remote_sha:
            raise RuntimeError(f"SHA256 mismatch: {local_sha} != {remote_sha}")
        log(f"Verified image SHA256 inside ChromeOS VM: {local_sha}")

        self._setup_devtools_tunnel()
        return remote_dl

    def _cdp_ctx(
        self, operation: str, target_label: str, target_url: str, target_id: str, t0: float, timeout: float
    ) -> str:
        return format_cdp_error_context(
            operation=operation,
            target_label=target_label,
            target_url=target_url,
            target_id=target_id,
            step=self.get_step(),
            elapsed_sec=time.monotonic() - t0,
            timeout_sec=timeout,
        )

    def _setup_devtools_tunnel(self) -> None:
        self.set_step("prepare:setup_devtools_tunnel")
        dt_lines = self.ssh("cat /home/chronos/DevToolsActivePort").stdout.strip().splitlines()
        self._remote_dt_port, self._browser_ws_path = int(dt_lines[0].strip()), dt_lines[1].strip()
        self._local_dt_port = find_free_port()
        log(f"Forwarding host 127.0.0.1:{self._local_dt_port} -> ChromeOS DevTools 127.0.0.1:{self._remote_dt_port}...")
        base_ssh = self.ssh_base_cmd()
        fwd = f"127.0.0.1:{self._local_dt_port}:127.0.0.1:{self._remote_dt_port}"
        cmd = [*base_ssh[:-1], "-N", "-L", fwd, base_ssh[-1]]
        self._devtools_fwd_proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        tunnel_timeout, t0 = 20.0, time.monotonic()
        deadline = t0 + tunnel_timeout
        last_err: Exception | None = None
        while time.monotonic() < deadline:
            try:
                _ = self.list_cdp_targets(timeout=5.0)
                return
            except Exception as exc:
                last_err = exc
                time.sleep(0.3)
        ctx = self._cdp_ctx(
            "SSH -L DevTools tunnel readiness probe",
            "DevToolsTunnel",
            f"http://127.0.0.1:{self._local_dt_port}/json/list",
            "browser",
            t0,
            tunnel_timeout,
        )
        raise CDPTimeoutError(
            f"Timed out establishing SSH port forward to Chrome DevToolsActivePort ({ctx}; last error: {last_err})"
        )

    def connect_browser_cdp(self, label: str = "Browser-Root") -> CDPConnection:
        assert self._local_dt_port and self._browser_ws_path
        ws_url = f"ws://127.0.0.1:{self._local_dt_port}{self._browser_ws_path}"
        return CDPConnection(
            ws_url,
            target_label=label,
            target_url=ws_url,
            target_id=self._browser_ws_path.rsplit("/", 1)[-1] or "browser",
            step_getter=self.get_step,
        )

    def list_cdp_targets(self, timeout: float = 20.0) -> list[dict[str, Any]]:
        assert self._local_dt_port and self._remote_dt_port
        url = f"http://127.0.0.1:{self._local_dt_port}/json/list"
        t0 = time.monotonic()
        try:
            targets = json.loads(urllib.request.urlopen(url, timeout=timeout).read())
        except Exception as exc:
            ctx = self._cdp_ctx("HTTP GET /json/list", "DevToolsHTTP", url, "<json-list>", t0, timeout)
            err_cls = CDPTimeoutError if is_ws_timeout_exc(exc) else CDPError
            verb = "timed out" if err_cls is CDPTimeoutError else "failed"
            raise err_cls(f"CDP target list HTTP request {verb} ({ctx}): {type(exc).__name__}: {exc}") from exc
        for tgt in targets:
            if "webSocketDebuggerUrl" in tgt:
                tgt["webSocketDebuggerUrl"] = tgt["webSocketDebuggerUrl"].replace(
                    f"127.0.0.1:{self._remote_dt_port}", f"127.0.0.1:{self._local_dt_port}"
                )
        return targets

    def wait_for_cdp_target(
        self,
        predicate: Callable[[dict[str, Any]], bool],
        *,
        operation: str,
        target_label: str,
        target_url: str,
        target_id: str = "<pending>",
        timeout: float = 30.0,
        interval: float = 0.4,
        max_interval: float = 2.0,
        require_ws: bool = True,
        err_prefix: str | None = None,
    ) -> dict[str, Any]:
        """Polls `list_cdp_targets()` until `predicate(tgt)` matches or raises `CDPTimeoutError`."""
        t0 = time.monotonic()
        deadline = t0 + timeout
        while time.monotonic() < deadline:
            for tgt in self.list_cdp_targets():
                if (not require_ws or "webSocketDebuggerUrl" in tgt) and predicate(tgt):
                    return tgt
            interval = sleep_backoff(interval, max_interval, deadline)
        ctx = self._cdp_ctx(operation, target_label, target_url, target_id, t0, timeout)
        raise CDPTimeoutError(f"{err_prefix or f'Timed out waiting for CDP target {target_label!r}'} ({ctx})")

    def connect_cdp_target(
        self,
        predicate: Callable[[dict[str, Any]], bool],
        *,
        operation: str,
        target_label: str,
        target_url: str,
        target_id: str = "<pending>",
        timeout: float = 30.0,
        interval: float = 0.4,
        err_prefix: str | None = None,
    ) -> CDPConnection:
        tgt = self.wait_for_cdp_target(
            predicate,
            operation=operation,
            target_label=target_label,
            target_url=target_url,
            target_id=target_id,
            timeout=timeout,
            interval=interval,
            require_ws=True,
            err_prefix=err_prefix,
        )
        return CDPConnection.from_target(tgt, label=target_label, step_getter=self.get_step)

    def launch_swa_or_target(self, url: str, *, label: str, op_desc: str) -> None:
        """Launches a URL or System Web App via Browser CDP `Target.createTarget`."""
        t0 = time.monotonic()
        browser_conn = self.connect_browser_cdp(label=label)
        try:
            # System Web Apps (`chrome://os-settings/`, `chrome-untrusted://terminal/`) return
            # CDP error -32000 ("Failed to open a new tab") while opening asynchronously.
            res = browser_conn.call("Target.createTarget", {"url": url}, allow_error=True, op_desc=op_desc)
            err = res.get("error")
            if err is not None:
                if not (isinstance(err, dict) and err.get("code") == -32000 and err.get("message") == "Failed to open a new tab"):
                    ctx = browser_conn.error_context(op_desc, time.monotonic() - t0, browser_conn.default_timeout)
                    raise CDPError(f"Unexpected CDP error launching {url} ({ctx}): {res!r}")
            elif "targetId" not in res:
                ctx = browser_conn.error_context(op_desc, time.monotonic() - t0, browser_conn.default_timeout)
                raise CDPError(f"Unexpected CDP response launching {url} ({ctx}): {res!r}")
        finally:
            browser_conn.close()

    def close_cdp_targets(self, target_ids: Iterable[str], *, label: str = "target") -> int:
        ids = [tid for tid in dict.fromkeys(target_ids) if tid and not tid.startswith("<")]
        if not ids:
            return 0
        try:
            browser_conn = self.connect_browser_cdp(label=f"Browser-Close({label})")
        except (CDPError, CDPTimeoutError):
            return 0
        closed = 0
        try:
            for tid in ids:
                res = browser_conn.call(
                    "Target.closeTarget", {"targetId": tid}, timeout=15.0, allow_error=True,
                    op_desc=f"close_cdp_target({label}:{tid})",
                )
                closed += bool(res.get("success"))
        except (CDPError, CDPTimeoutError):
            pass
        finally:
            browser_conn.close()
        return closed

    def close_cdp_targets_matching(
        self, url_substr: str, *, label: str, exclude_ids: set[str] | None = None
    ) -> int:
        skip = exclude_ids or set()
        try:
            tids = [
                str(t.get("id", ""))
                for t in self.list_cdp_targets()
                if str(t.get("id", "")) not in skip and url_substr in str(t.get("url", ""))
            ]
        except (CDPError, CDPTimeoutError):
            return 0
        return self.close_cdp_targets(tids, label=label)

    def open_crosh_tab(self, label: str) -> CroshTab:
        self.set_step(f"open_crosh_tab({label})")
        browser_conn = self.connect_browser_cdp(label=f"Browser-CreateCrosh({label})")
        try:
            tid = browser_conn.call(
                "Target.createTarget",
                {"url": "chrome-untrusted://crosh/"},
                op_desc=f"open_crosh_tab({label}):Target.createTarget",
            )["targetId"]
        finally:
            browser_conn.close()

        conn = self.connect_cdp_target(
            lambda tgt: tgt.get("id") == tid,
            operation=f"attach_target({label})",
            target_label=label,
            target_url="chrome-untrusted://crosh/",
            target_id=str(tid),
            timeout=30.0,
            interval=0.3,
            err_prefix="Failed to attach to crosh tab",
        )
        tab = CroshTab(label, conn)
        tab.wait_for(
            lambda txt: txt.rstrip().endswith("crosh>"),
            timeout=45.0,
            desc=f"{label} initial crosh> prompt",
            max_lines=8,
        )
        log(f"Opened {label} (`chrome-untrusted://crosh/`, target={tid})")
        return tab

    def close_crosh_tab(self, tab: CroshTab | None) -> None:
        if tab is not None:
            tid = tab.conn.target_id
            tab.suppress_beforeunload()
            tab.close()
            self.close_cdp_targets([tid], label=tab.label)
