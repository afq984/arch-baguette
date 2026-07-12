#!/usr/bin/env bash
# Contract asserts against a built rootfs DIRECTORY (pre-image). See DESIGN.md
# "Tests". Works rootless: everything that must resolve names inside the
# target (getent, visudo, pacman) runs in a userns chroot of the rootfs.
#
# Usage: verify-rootfs.sh [--dev-user NAME] [--skip-baguette-repo] <rootfs-dir>
#   --dev-user NAME        rootfs was built with image/build.sh --dev-user NAME
#                          (expect that user; otherwise assert NO uid >= 1000)
#   --skip-baguette-repo   rootfs was built without the [baguette] packages;
#                          package-dependent asserts are SKIPped
#
# Output: one "PASS|FAIL|SKIP  <assert>" line each; exit 1 if any FAIL.
set -euo pipefail

DEV_USER=""
SKIP_BAGUETTE=0
ROOTFS=""

while [ $# -gt 0 ]; do
    case "$1" in
        --dev-user)   shift; DEV_USER="${1%%:*}" ;;
        --dev-user=*) arg="${1#--dev-user=}"; DEV_USER="${arg%%:*}" ;;
        --skip-baguette-repo) SKIP_BAGUETTE=1 ;;
        -h|--help) sed -n '2,/^set -euo/p' "${BASH_SOURCE[0]}" | sed '$d;s/^# \{0,1\}//'; exit 0 ;;
        -*) echo "error: unknown option: $1" >&2; exit 2 ;;
        *) ROOTFS="$1" ;;
    esac
    shift
done

[ -n "${ROOTFS}" ] || { echo "usage: $0 [--dev-user NAME] [--skip-baguette-repo] <rootfs-dir>" >&2; exit 2; }
ROOTFS="$(cd "${ROOTFS}" && pwd)"
[ -d "${ROOTFS}/etc" ] || { echo "error: ${ROOTFS} does not look like a rootfs (no etc/)" >&2; exit 2; }

# --- runners ---------------------------------------------------------------
if [ "${EUID}" -eq 0 ]; then
    # ROOTFUL branch — UNTESTED (CI containers); rootless is the primary path.
    as_root() { "$@"; }
else
    as_root() { unshare --map-auto --map-root-user -- "$@"; }
fi
in_chroot() { as_root chroot "${ROOTFS}" "$@"; }

# --- result plumbing ---------------------------------------------------------
NPASS=0 NFAIL=0 NSKIP=0
pass() { NPASS=$((NPASS + 1)); printf 'PASS  %s\n' "$1"; }
fail() { NFAIL=$((NFAIL + 1)); printf 'FAIL  %s\n' "$1"; }
skip() { NSKIP=$((NSKIP + 1)); printf 'SKIP  %s\n' "$1"; }
# check "description" cmd [args...]  — PASS if cmd succeeds (output discarded)
check() {
    local desc="$1"; shift
    if "$@" >/dev/null 2>&1; then pass "${desc}"; else fail "${desc}"; fi
}

echo "== verify-rootfs: ${ROOTFS}"
echo "== mode: dev-user='${DEV_USER:-<none>}' skip-baguette-repo=${SKIP_BAGUETTE}"

if [ "${SKIP_BAGUETTE}" -eq 0 ] && \
   ! find "${ROOTFS}/var/lib/pacman/local" -maxdepth 1 -name 'baguette-base-*' 2>/dev/null | grep -q .; then
    echo "note: baguette-base not in the pacman db — if this rootfs was built" >&2
    echo "      with --skip-baguette-repo, pass --skip-baguette-repo here too." >&2
fi

# ---------------------------------------------------------------------------
# A. Build-generated contract (always asserted)
# ---------------------------------------------------------------------------
check "hostname is 'penguin'" \
    grep -qx 'penguin' "${ROOTFS}/etc/hostname"
check "/etc/hosts has 127.0.0.1 localhost" \
    grep -Eq '^127\.0\.0\.1[[:space:]]+localhost$' "${ROOTFS}/etc/hosts"
check "/etc/hosts has 127.0.1.1 penguin" \
    grep -Eq '^127\.0\.1\.1[[:space:]]+penguin$' "${ROOTFS}/etc/hosts"
check "/etc/hosts has 100.115.92.2 arc" \
    grep -Eq '^100\.115\.92\.2[[:space:]]+arc$' "${ROOTFS}/etc/hosts"
check "locale.conf sets LANG=en_US.UTF-8" \
    grep -qx 'LANG=en_US.UTF-8' "${ROOTFS}/etc/locale.conf"
# NB: Arch's stock locale.gen lines carry trailing whitespace — tolerate it
check "locale.gen enables en_US.UTF-8" \
    grep -Eq '^en_US\.UTF-8 UTF-8[[:space:]]*$' "${ROOTFS}/etc/locale.gen"

if [ "$(readlink "${ROOTFS}/etc/resolv.conf" 2>/dev/null)" = "/run/resolv.conf" ]; then
    pass "/etc/resolv.conf is a symlink to /run/resolv.conf"
else
    fail "/etc/resolv.conf is a symlink to /run/resolv.conf (got: $(readlink "${ROOTFS}/etc/resolv.conf" 2>/dev/null || echo '<not a symlink>'))"
fi

if [ -f "${ROOTFS}/etc/machine-id" ] && [ ! -s "${ROOTFS}/etc/machine-id" ]; then
    pass "/etc/machine-id exists and is empty"
else
    fail "/etc/machine-id exists and is empty"
fi

if compgen -G "${ROOTFS}/etc/ssh/ssh_host_*" >/dev/null; then
    fail "no ssh host keys (/etc/ssh/ssh_host_*)"
else
    pass "no ssh host keys (/etc/ssh/ssh_host_*)"
fi

if [ -z "$(find "${ROOTFS}/var/cache/pacman/pkg" -mindepth 1 2>/dev/null)" ]; then
    pass "pacman cache is empty (/var/cache/pacman/pkg)"
else
    fail "pacman cache is empty (/var/cache/pacman/pkg)"
fi

if [ -f "${ROOTFS}/etc/fstab" ] && grep -Evq '^[[:space:]]*(#|$)' "${ROOTFS}/etc/fstab"; then
    fail "no active /etc/fstab entries (default subvolume does the job)"
else
    pass "no active /etc/fstab entries (default subvolume does the job)"
fi

check "in-target pacman keyring populated (pacman-key trustdb)" \
    test -s "${ROOTFS}/etc/pacman.d/gnupg/trustdb.gpg"

# in-guest `pacman -Syu` must function: stock pacman-mirrorlist ships all
# Server lines commented; the build installs a working one
check "/etc/pacman.d/mirrorlist has an active Server line" \
    grep -Eq '^Server[[:space:]]*=' "${ROOTFS}/etc/pacman.d/mirrorlist"

# maitred invokes /usr/sbin/useradd by absolute path (usr-merge must satisfy it)
check "/usr/sbin/useradd resolves and is executable (in chroot)" \
    in_chroot test -x /usr/sbin/useradd

# uid >= 1000 policy (65534 = nobody)
mapfile -t high_uids < <(awk -F: '$3 >= 1000 && $3 != 65534 {print $1":"$3}' "${ROOTFS}/etc/passwd")
if [ -z "${DEV_USER}" ]; then
    if [ "${#high_uids[@]}" -eq 0 ]; then
        pass "no passwd entries with uid >= 1000 (userless production image)"
    else
        fail "no passwd entries with uid >= 1000 (found: ${high_uids[*]})"
    fi
else
    if [ "${#high_uids[@]}" -eq 1 ] && [ "${high_uids[0]}" = "${DEV_USER}:1000" ]; then
        pass "exactly one uid >= 1000 entry: ${DEV_USER} (uid 1000)"
    else
        fail "exactly one uid >= 1000 entry: ${DEV_USER}:1000 (found: ${high_uids[*]:-none})"
    fi
fi

# ---------------------------------------------------------------------------
# B. Contract groups (maitred SetUpUser hard-rejects if any is missing)
# ---------------------------------------------------------------------------
# Verified empirically on the built rootfs (2026-07-12): Arch itself provides
# audio/disk/kvm/video (systemd sysusers basic.conf, applied at pacstrap time
# by the 20-systemd-sysusers pacman hook), floppy (filesystem package) and
# tss (tpm2-tss, via tpm2-tools). It does NOT provide cdrom/dialout anywhere
# (no sysusers fragment declares them; Arch uses optical/uucp) — contrary to
# DESIGN's "Verified facts", those must also come from baguette-base's
# sysusers.d.
#
# The real contract is maitred's getgrnam at RUNTIME, so a group satisfies
# the assert if it is materialized in /etc/group now (getent) OR declared in
# a sysusers.d fragment (systemd-sysusers materializes it at boot; a `u`
# line also creates the matching group).
group_resolves() {
    in_chroot getent group "$1" >/dev/null 2>&1 && return 0
    grep -Ehqs "^[gu][[:space:]]+$1([[:space:]]|\$)" \
        "${ROOTFS}"/usr/lib/sysusers.d/*.conf "${ROOTFS}"/etc/sysusers.d/*.conf
}
ARCH_PROVIDED_GROUPS=(audio disk floppy kvm tss video)
PKG_PROVIDED_GROUPS=(cdrom dialout netdev plugdev sudo)
for g in "${ARCH_PROVIDED_GROUPS[@]}"; do
    check "group '${g}' resolves (getent in chroot, or sysusers.d)" group_resolves "${g}"
done
for g in "${PKG_PROVIDED_GROUPS[@]}"; do
    if [ "${SKIP_BAGUETTE}" -eq 1 ] && [ -z "${DEV_USER}" ]; then
        # provided by baguette-base's sysusers.d (and by build.sh's groupadd
        # only when a dev user is baked) — nothing provides them in this build
        skip "group '${g}' resolves (baguette-base not installed)"
    else
        check "group '${g}' resolves (getent in chroot, or sysusers.d)" group_resolves "${g}"
    fi
done

# ---------------------------------------------------------------------------
# C. Dev user (only for --dev-user builds)
# ---------------------------------------------------------------------------
if [ -n "${DEV_USER}" ]; then
    if [ "$(in_chroot id -u "${DEV_USER}" 2>/dev/null)" = "1000" ]; then
        pass "dev user '${DEV_USER}' exists with uid 1000"
    else
        fail "dev user '${DEV_USER}' exists with uid 1000"
    fi
    user_groups=" $(in_chroot id -nG "${DEV_USER}" 2>/dev/null) "
    missing_groups=""
    for g in "${ARCH_PROVIDED_GROUPS[@]}" "${PKG_PROVIDED_GROUPS[@]}"; do
        case "${user_groups}" in *" ${g} "*) ;; *) missing_groups="${missing_groups} ${g}" ;; esac
    done
    if [ -z "${missing_groups}" ]; then
        pass "dev user is in all 11 contract groups"
    else
        fail "dev user is in all 11 contract groups (missing:${missing_groups})"
    fi
    check "dev user shell is /bin/bash" \
        grep -Eq "^${DEV_USER}:[^:]*:1000:[^:]*:[^:]*:[^:]*:/bin/bash$" "${ROOTFS}/etc/passwd"
    check "dev user home directory exists" test -d "${ROOTFS}/home/${DEV_USER}"
    check "dev user linger enabled (/var/lib/systemd/linger/${DEV_USER})" \
        test -f "${ROOTFS}/var/lib/systemd/linger/${DEV_USER}"
    if as_root grep -Eq "^${DEV_USER}:\\\$" "${ROOTFS}/etc/shadow"; then
        pass "dev user has a password hash in /etc/shadow"
    else
        fail "dev user has a password hash in /etc/shadow"
    fi
fi

# ---------------------------------------------------------------------------
# D. Package-shipped contract (SKIPped for --skip-baguette-repo builds)
# ---------------------------------------------------------------------------
pkg_check() {  # pkg_check "description" cmd [args...]
    local desc="$1"; shift
    if [ "${SKIP_BAGUETTE}" -eq 1 ]; then
        skip "${desc} (--skip-baguette-repo)"
    elif "$@" >/dev/null 2>&1; then
        pass "${desc}"
    else
        fail "${desc}"
    fi
}

for p in baguette-base cros-sommelier cros-garcon cros-wayland cros-port-listener cros-notificationd; do
    pkg_check "package '${p}' installed" in_chroot pacman -Q "${p}"
done

# sudoers: %sudo NOPASSWD only (no %wheel), 0440, parses
SUDOERS="${ROOTFS}/etc/sudoers.d/10-baguette"
pkg_check "sudoers drop-in /etc/sudoers.d/10-baguette exists" test -f "${SUDOERS}"
if [ "${SKIP_BAGUETTE}" -eq 1 ]; then
    skip "sudoers mode is 0440 (--skip-baguette-repo)"
    skip "sudoers grants %sudo NOPASSWD (--skip-baguette-repo)"
    skip "sudoers has no %wheel grant (--skip-baguette-repo)"
    skip "sudoers config parses (visudo -c in chroot) (--skip-baguette-repo)"
else
    if [ "$(stat -c %a "${SUDOERS}" 2>/dev/null)" = "440" ]; then
        pass "sudoers mode is 0440"
    else
        fail "sudoers mode is 0440 (got: $(stat -c %a "${SUDOERS}" 2>/dev/null || echo missing))"
    fi
    check "sudoers grants %sudo NOPASSWD" \
        grep -Eq '^%sudo[[:space:]]+ALL=\(ALL(:ALL)?\)[[:space:]]+NOPASSWD:[[:space:]]+ALL$' "${SUDOERS}"
    # directive lines only — comments may legitimately mention %wheel
    if grep -Eq '^[[:space:]]*%wheel' "${SUDOERS}" 2>/dev/null; then
        fail "sudoers has no %wheel grant"
    else
        pass "sudoers has no %wheel grant"
    fi
    check "sudoers config parses (visudo -c in chroot)" in_chroot visudo -c
fi
# /etc/sudoers.d itself must keep the sudo package's 0750 (baguette-base
# 0.1.0-1 shipped it 0755 -> pacman "directory permissions differ" warning)
if [ "${SKIP_BAGUETTE}" -eq 1 ]; then
    skip "/etc/sudoers.d directory mode is 0750 (--skip-baguette-repo)"
else
    sudoersd_mode="$(stat -c %a "${ROOTFS}/etc/sudoers.d" 2>/dev/null)"
    if [ "${sudoersd_mode}" = "750" ]; then
        pass "/etc/sudoers.d directory mode is 0750"
    else
        fail "/etc/sudoers.d directory mode is 0750 (got: ${sudoersd_mode:-missing})"
    fi
fi

# sftp-server shim: maitred/garcon use the Debian path /usr/lib/openssh/
# sftp-server; Arch's openssh ships /usr/lib/ssh/sftp-server. baguette-base
# >= 0.1.0-2 ships a relative symlink that must RESOLVE with openssh installed.
if [ "${SKIP_BAGUETTE}" -eq 1 ]; then
    skip "/usr/lib/openssh/sftp-server shim resolves (--skip-baguette-repo)"
else
    if [ -L "${ROOTFS}/usr/lib/openssh/sftp-server" ] \
       && in_chroot test -x /usr/lib/openssh/sftp-server; then
        pass "/usr/lib/openssh/sftp-server shim resolves (-> $(readlink "${ROOTFS}/usr/lib/openssh/sftp-server"))"
    else
        fail "/usr/lib/openssh/sftp-server shim resolves (got: $(readlink "${ROOTFS}/usr/lib/openssh/sftp-server" 2>/dev/null || echo '<missing>'))"
    fi
fi

# /mnt layout (replicates official image exactly)
pkg_check "/mnt/chromeos/fonts is a directory" test -d "${ROOTFS}/mnt/chromeos/fonts"
pkg_check "/mnt/shared is a directory" test -d "${ROOTFS}/mnt/shared"
if [ "${SKIP_BAGUETTE}" -eq 1 ]; then
    skip "/mnt/chromeos/shared -> /mnt/shared symlink (--skip-baguette-repo)"
else
    if [ "$(readlink "${ROOTFS}/mnt/chromeos/shared" 2>/dev/null)" = "/mnt/shared" ]; then
        pass "/mnt/chromeos/shared -> /mnt/shared symlink"
    else
        fail "/mnt/chromeos/shared -> /mnt/shared symlink (got: $(readlink "${ROOTFS}/mnt/chromeos/shared" 2>/dev/null || echo '<missing>'))"
    fi
fi
pkg_check "/opt/google/cros-containers mountpoint dir exists" \
    test -d "${ROOTFS}/opt/google/cros-containers"

# profile.d
pkg_check "/etc/profile.d/10-baguette-envs.sh present" \
    test -f "${ROOTFS}/etc/profile.d/10-baguette-envs.sh"
pkg_check "/etc/profile.d/sommelier.sh present" \
    test -f "${ROOTFS}/etc/profile.d/sommelier.sh"
pkg_check "/etc/sommelierrc present" test -f "${ROOTFS}/etc/sommelierrc"

# sommelier symlinks: dangling in the rootfs (target is host-mounted at
# runtime) but pointing at the exact cros-vm-tools paths
for lnk in sommelier sommelier.elf; do
    want="/opt/google/cros-containers/bin/${lnk}"
    if [ "${SKIP_BAGUETTE}" -eq 1 ]; then
        skip "/usr/bin/${lnk} -> ${want} (dangling) (--skip-baguette-repo)"
    elif [ "$(readlink "${ROOTFS}/usr/bin/${lnk}" 2>/dev/null)" = "${want}" ] \
         && ! in_chroot test -e "/usr/bin/${lnk}"; then
        pass "/usr/bin/${lnk} -> ${want} (dangling until host mount)"
    else
        fail "/usr/bin/${lnk} -> ${want} (dangling until host mount; got: $(readlink "${ROOTFS}/usr/bin/${lnk}" 2>/dev/null || echo '<missing>'))"
    fi
done

# maitred config + journald forward + first-boot script + preset file
pkg_check "/etc/maitred/50-mount-fonts.textproto present" \
    test -f "${ROOTFS}/etc/maitred/50-mount-fonts.textproto"
pkg_check "journald ForwardToConsole drop-in present" \
    grep -q '^ForwardToConsole=yes' "${ROOTFS}/usr/lib/systemd/journald.conf.d/50-console.conf"
pkg_check "first-boot script /usr/lib/baguette/first-boot-cros executable" \
    test -x "${ROOTFS}/usr/lib/baguette/first-boot-cros"
pkg_check "preset file /usr/lib/systemd/system-preset/50-baguette.preset present" \
    test -f "${ROOTFS}/usr/lib/systemd/system-preset/50-baguette.preset"

# udev rules + dbus activation
pkg_check "udev rule 10-cros-virtwl.rules present" \
    test -f "${ROOTFS}/usr/lib/udev/rules.d/10-cros-virtwl.rules"
pkg_check "udev rule 10-cros-port-listener.rules present" \
    test -f "${ROOTFS}/usr/lib/udev/rules.d/10-cros-port-listener.rules"
pkg_check "dbus activation org.freedesktop.Notifications.service present" \
    test -f "${ROOTFS}/usr/share/dbus-1/services/org.freedesktop.Notifications.service"

# Enabled system units (via preset-all at build time)
SYSTEM_UNITS=(
    'opt-google-cros\x2dcontainers.mount'
    maitred.service
    vshd.service
    first-boot-cros.service
    cros-port-listener.service
    systemd-timesyncd.service
)
for u in "${SYSTEM_UNITS[@]}"; do
    pkg_check "system unit enabled: ${u}" systemctl --root="${ROOTFS}" is-enabled -- "${u}"
done
# dbus is an alias of dbus-broker.service on Arch; accept any positive state
if [ "${SKIP_BAGUETTE}" -eq 1 ]; then
    skip "system unit enabled: dbus.service (--skip-baguette-repo)"
else
    dbus_state="$(systemctl --root="${ROOTFS}" is-enabled -- dbus.service 2>/dev/null || true)"
    case "${dbus_state}" in
        enabled|alias|static) pass "system unit enabled: dbus.service (${dbus_state})" ;;
        *) fail "system unit enabled: dbus.service (got: ${dbus_state:-<none>})" ;;
    esac
fi

# User-session units enabled via vendor wants-symlinks shipped in the packages
USER_WANTS=(sommelier@0.service sommelier-x@0.service sommelier@1.service
            sommelier-x@1.service cros-garcon.service)
for w in "${USER_WANTS[@]}"; do
    pkg_check "user wants-symlink: default.target.wants/${w}" \
        test -L "${ROOTFS}/usr/lib/systemd/user/default.target.wants/${w}"
done
for f in sommelier@.service sommelier-x@.service cros-garcon.service cros-notificationd.service; do
    pkg_check "user unit file: /usr/lib/systemd/user/${f}" \
        test -f "${ROOTFS}/usr/lib/systemd/user/${f}"
done

# ---------------------------------------------------------------------------
echo
echo "== verify-rootfs summary: ${NPASS} passed, ${NFAIL} failed, ${NSKIP} skipped"
[ "${NFAIL}" -eq 0 ]
