#!/usr/bin/env bash
# arch-baguette-v2 image build — rootless-first (no sudo, no docker, no loop
# mounts). Port of the verified techniques in
# /home/r/baguette/dev-workflow/build-arch-baguette-rootless.sh, restructured
# per DESIGN.md ("Image build" section).
#
# Two modes, one script, identical output:
#   rootless (EUID != 0, default) — pacstrap -N / arch-chroot -N, every other
#     privileged step inside `unshare --map-auto --map-root-user`, and
#     mkfs.btrfs --rootdir run INSIDE the userns so files stat as 0:0.
#   rootful  (EUID == 0, CI-container fallback) — same steps without the
#     userns wrappers. UNTESTED on this machine (needs a root environment);
#     kept in strict step-parity with the rootless branch.
#
# Usage: image/build.sh [options]
#   --fast                 zstd -3 instead of the release default -19
#   --dev-user NAME[:PW]   bake a dev user (uid 1000, full 11-group contract
#                          set, linger). Default password: test0000.
#                          Production default: NO user is created.
#   --skip-baguette-repo   build without the local [baguette] repo and its
#                          packages (pipeline smoke-test before packages exist)
#   -h | --help            this text
#
# Env overrides: WORKDIR (default <repo>/build/image), OUTDIR (default
# <repo>/out/image), BAGUETTE_REPO_DIR (default <repo>/out/repo).
#
# Output: $OUTDIR/baguette_arch_rootfs.img.zst (+ .sha256, manifest.txt)
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(dirname "${HERE}")"

WORKDIR="${WORKDIR:-${REPO_ROOT}/build/image}"
OUTDIR="${OUTDIR:-${REPO_ROOT}/out/image}"
BAGUETTE_REPO_DIR="${BAGUETTE_REPO_DIR:-${REPO_ROOT}/out/repo}"

ROOTFS="${WORKDIR}/rootfs"
GPGDIR="${WORKDIR}/gnupg"
PKGCACHE="${WORKDIR}/pkgcache"
IMG="${WORKDIR}/baguette_arch_rootfs.img"
OUT_IMG="${OUTDIR}/baguette_arch_rootfs.img.zst"
MANIFEST="${OUTDIR}/manifest.txt"
IMAGE_LABEL="arch-baguette"   # cosmetic only — nothing may depend on it

# Contract group set maitred's SetUpUser requires (see DESIGN "Verified facts")
CONTRACT_GROUPS="audio,cdrom,dialout,disk,floppy,kvm,netdev,plugdev,sudo,tss,video"

# ---------------------------------------------------------------------------
# Options
# ---------------------------------------------------------------------------
ZSTD_LEVEL=19
DEV_USER=""
DEV_PASSWORD="test0000"
SKIP_BAGUETTE_REPO=0

usage() { sed -n '2,/^set -euo/p' "${BASH_SOURCE[0]}" | sed '$d' | sed 's/^# \{0,1\}//'; }

while [ $# -gt 0 ]; do
    case "$1" in
        --fast) ZSTD_LEVEL=3 ;;
        --dev-user)
            shift; [ $# -gt 0 ] || { echo "error: --dev-user needs NAME[:PASSWORD]" >&2; exit 2; }
            DEV_USER="${1%%:*}"
            case "$1" in *:*) DEV_PASSWORD="${1#*:}" ;; esac
            ;;
        --dev-user=*)
            arg="${1#--dev-user=}"
            DEV_USER="${arg%%:*}"
            case "$arg" in *:*) DEV_PASSWORD="${arg#*:}" ;; esac
            ;;
        --skip-baguette-repo) SKIP_BAGUETTE_REPO=1 ;;
        -h|--help) usage; exit 0 ;;
        *) echo "error: unknown option: $1 (see --help)" >&2; exit 2 ;;
    esac
    shift
done

if [ -n "${DEV_USER}" ] && ! printf '%s' "${DEV_USER}" | grep -Eq '^[a-z_][a-z0-9_-]*$'; then
    echo "error: invalid --dev-user name: ${DEV_USER}" >&2
    exit 2
fi

# ---------------------------------------------------------------------------
# Mode selection + privileged-step wrappers
# ---------------------------------------------------------------------------
if [ "${EUID}" -eq 0 ]; then
    # ROOTFUL MODE — UNTESTED (for CI containers; see header). Same steps as
    # rootless, minus the userns wrappers. mkfs still runs in a private mount
    # namespace for the bind-mount-one-level-down trick.
    ROOTLESS=0
    PACSTRAP=(pacstrap)
    ARCH_CHROOT=(arch-chroot)
    UNS_MOUNT=(unshare --mount)
else
    ROOTLESS=1
    PACSTRAP=(pacstrap -N)
    ARCH_CHROOT=(arch-chroot -N)
    UNS_MOUNT=(unshare --map-auto --map-root-user --mount)
fi

# Run a command as (namespace-)root. In rootless mode this is a fresh userns
# with the caller mapped to root + subuid/subgid ranges (--map-auto), which is
# what makes subuid-owned rootfs files writable and pacman-key's EUID==0
# check pass. In rootful mode: run directly (UNTESTED branch).
as_root() {
    if [ "${ROOTLESS}" -eq 1 ]; then
        unshare --map-auto --map-root-user -- "$@"
    else
        "$@"
    fi
}

# ---------------------------------------------------------------------------
# Preflight
# ---------------------------------------------------------------------------
missing=0
for tool in pacstrap arch-chroot mkfs.btrfs zstd systemctl sha256sum; do
    command -v "${tool}" >/dev/null || { echo "error: missing tool: ${tool}" >&2; missing=1; }
done
if [ "${ROOTLESS}" -eq 1 ]; then
    for tool in unshare newuidmap newgidmap; do
        command -v "${tool}" >/dev/null || { echo "error: missing tool: ${tool} (rootless mode)" >&2; missing=1; }
    done
fi
# no grep -q here: with pipefail, grep -q's early exit SIGPIPEs mkfs.btrfs
mkfs.btrfs --help 2>&1 | grep -- '--subvol' >/dev/null \
    || { echo "error: mkfs.btrfs lacks --subvol (need btrfs-progs >= 6.8)" >&2; missing=1; }
[ "${missing}" -eq 0 ] || exit 1

if [ "${SKIP_BAGUETTE_REPO}" -eq 0 ] && [ ! -f "${BAGUETTE_REPO_DIR}/baguette.db" ]; then
    echo "error: local pacman repo not found: ${BAGUETTE_REPO_DIR}/baguette.db" >&2
    echo "  build it first:  scripts/build-repo.sh" >&2
    echo "  or smoke-test the pipeline with:  image/build.sh --skip-baguette-repo" >&2
    exit 1
fi

mkdir -p "${WORKDIR}" "${OUTDIR}" "${PKGCACHE}"

echo "==> mode: $([ "${ROOTLESS}" -eq 1 ] && echo rootless || echo 'rootful (UNTESTED)')"
echo "==> zstd level: ${ZSTD_LEVEL}$([ "${ZSTD_LEVEL}" -eq 3 ] && echo ' (--fast)')"
echo "==> dev user: ${DEV_USER:-<none — production userless image>}"
echo "==> [baguette] repo: $([ "${SKIP_BAGUETTE_REPO}" -eq 1 ] && echo 'SKIPPED' || echo "${BAGUETTE_REPO_DIR}")"

# ---------------------------------------------------------------------------
# [1/9] Clean previous build (rootfs files are subuid-owned -> remove in userns)
# ---------------------------------------------------------------------------
echo "[1/9] Clean previous rootfs/staging/image (pkgcache and gnupg are kept)"
as_root rm -rf "${ROOTFS}" "${WORKDIR}/staging"
rm -f "${IMG}"

# ---------------------------------------------------------------------------
# [2/9] Build-local pacman keyring (host keyring untouched)
# ---------------------------------------------------------------------------
echo "[2/9] Prepare build-local pacman keyring"
if [ ! -f "${GPGDIR}/trustdb.gpg" ]; then
    mkdir -p "${GPGDIR}"
    chmod 700 "${GPGDIR}"
    # pacman-key hard-checks EUID==0; as_root satisfies it (userns wrapper
    # trick in rootless mode) while keeping the keyring user-owned on disk.
    as_root sh -euc "pacman-key --gpgdir '${GPGDIR}' --init && \
        pacman-key --gpgdir '${GPGDIR}' --populate archlinux"
fi

# ---------------------------------------------------------------------------
# [3/9] pacman.conf from template
# ---------------------------------------------------------------------------
echo "[3/9] Generate pacman.conf from image/pacman.conf.in"
cat >"${WORKDIR}/mirrorlist" <<'EOF'
Server = https://geo.mirror.pkgbuild.com/$repo/os/$arch
Server = https://mirror.rackspace.com/archlinux/$repo/os/$arch
Server = https://mirror.leaseweb.net/archlinux/$repo/os/$arch
EOF

sed \
    -e "s|@GPGDIR@|${GPGDIR}|g" \
    -e "s|@CACHEDIR@|${PKGCACHE}|g" \
    -e "s|@MIRRORLIST@|${WORKDIR}/mirrorlist|g" \
    -e "s|@BAGUETTE_REPO@|${BAGUETTE_REPO_DIR}|g" \
    "${HERE}/pacman.conf.in" >"${WORKDIR}/pacman.conf"

if [ "${SKIP_BAGUETTE_REPO}" -eq 1 ]; then
    sed -i '/^# BEGIN baguette repo/,/^# END baguette repo/d' "${WORKDIR}/pacman.conf"
fi

# ---------------------------------------------------------------------------
# [4/9] pacstrap
# ---------------------------------------------------------------------------
echo "[4/9] Bootstrap Arch rootfs (${PACSTRAP[*]})"
# Package set per DESIGN.md "Image build" (trim later if audit shows dead
# weight; keep parity with the official Debian set now).
ARCH_PACKAGES=(
    base archlinux-keyring systemd-sysvcompat sudo btrfs-progs dbus openssh
    acl bash-completion curl wget vim nano xz gnupg tpm2-tools usbutils
    pciutils alsa-utils pipewire pipewire-pulse wireplumber xdg-utils
    xdg-desktop-portal-gtk gsettings-desktop-schemas wayland xorg-xwayland
    xorg-xauth xorg-xrdb xorg-xset xkeyboard-config wl-clipboard
)
BAGUETTE_PACKAGES=(
    baguette-base cros-sommelier cros-garcon cros-wayland
    cros-port-listener cros-notificationd
)
if [ "${SKIP_BAGUETTE_REPO}" -eq 0 ]; then
    ARCH_PACKAGES+=("${BAGUETTE_PACKAGES[@]}")
fi

mkdir -p "${ROOTFS}"
# pacstrap ignores CacheDir from -C configs (only -P honors it) and always
# uses $ROOTFS/var/cache/pacman/pkg. Seed it from the persistent cache with
# hardlinks (same fs) so warm rebuilds skip all downloads...
if compgen -G "${PKGCACHE}/*.pkg.tar.*" >/dev/null; then
    as_root sh -euc "mkdir -p '${ROOTFS}/var/cache/pacman/pkg' && \
        cp -al '${PKGCACHE}/.' '${ROOTFS}/var/cache/pacman/pkg/'"
fi

"${PACSTRAP[@]}" -C "${WORKDIR}/pacman.conf" -G -M "${ROOTFS}" "${ARCH_PACKAGES[@]}"

# ...and evacuate it afterwards: keeps the cache for the next build AND keeps
# ~300 MB of .pkg files OUT of the image ("empty pacman cache" is a DESIGN
# production requirement, asserted by verify-rootfs.sh).
as_root sh -euc "
cp -aln '${ROOTFS}/var/cache/pacman/pkg/.' '${PKGCACHE}/'
rm -f '${ROOTFS}'/var/cache/pacman/pkg/*
"

# ---------------------------------------------------------------------------
# [5/9] In-chroot configuration (parity with official setup_in_guest.sh)
# ---------------------------------------------------------------------------
echo "[5/9] Configure rootfs (${ARCH_CHROOT[*]})"
cat >"${WORKDIR}/configure-rootfs.sh" <<'CONFEOF'
#!/bin/bash
# Runs INSIDE the (userns-)chroot of the target rootfs.
set -eux

echo penguin > /etc/hostname

cat > /etc/hosts <<'EOF'
127.0.0.1 localhost
127.0.1.1 penguin
100.115.92.2 arc
EOF

sed -i 's/^#en_US.UTF-8 UTF-8/en_US.UTF-8 UTF-8/' /etc/locale.gen
locale-gen
echo 'LANG=en_US.UTF-8' > /etc/locale.conf

# In-target keyring so `pacman -Syu` works after first boot.
pacman-key --init
pacman-key --populate archlinux

if [ -n "${DEV_USER:-}" ]; then
    # Dev-only user (--dev-user). The contract groups normally come from
    # baguette-base's sysusers.d; create any missing ones so this also works
    # in --skip-baguette-repo smoke builds (idempotent otherwise).
    IFS=, read -ra groups <<< "${CONTRACT_GROUPS}"
    for g in "${groups[@]}"; do
        getent group "${g}" >/dev/null || groupadd "${g}"
    done
    useradd -m -s /bin/bash --uid 1000 -G "${CONTRACT_GROUPS}" "${DEV_USER}"
    echo "${DEV_USER}:${DEV_PASSWORD}" | chpasswd
    mkdir -p /var/lib/systemd/linger
    touch "/var/lib/systemd/linger/${DEV_USER}"
fi

# Production defaults: no ssh host keys (first-boot-cros regenerates), empty
# machine-id (first boot initializes). Keep these LAST.
rm -f /etc/ssh/ssh_host_*
: > /etc/machine-id
CONFEOF

as_root install -m755 "${WORKDIR}/configure-rootfs.sh" "${ROOTFS}/configure-rootfs.sh"
"${ARCH_CHROOT[@]}" "${ROOTFS}" /usr/bin/env \
    DEV_USER="${DEV_USER}" \
    DEV_PASSWORD="${DEV_PASSWORD}" \
    CONTRACT_GROUPS="${CONTRACT_GROUPS}" \
    /bin/bash /configure-rootfs.sh
as_root rm -f "${ROOTFS}/configure-rootfs.sh"

# arch-chroot bind-mounts the host resolv.conf over /etc/resolv.conf, so the
# final symlink must be created after the chroot exits (maitred/the host
# manage /run/resolv.conf at runtime).
as_root ln -sfnT /run/resolv.conf "${ROOTFS}/etc/resolv.conf"

# ---------------------------------------------------------------------------
# [6/9] Enable units via presets
# ---------------------------------------------------------------------------
echo "[6/9] Apply systemd presets (systemctl --root preset-all)"
# baguette-base ships /usr/lib/systemd/system-preset/50-baguette.preset which
# enables: the cros-containers mount, maitred, vshd, first-boot-cros,
# cros-port-listener, dbus, systemd-timesyncd. User-session units are enabled
# by vendor wants-symlinks shipped inside the packages (no action here).
# In --skip-baguette-repo mode this still runs and just applies Arch's stock
# presets — the smoke image is not expected to boot into a Baguette session.
as_root systemctl --root="${ROOTFS}" preset-all

# ---------------------------------------------------------------------------
# [7/9] Production-cleanliness guarantees + manifest
# ---------------------------------------------------------------------------
echo "[7/9] Cleanliness checks + package manifest"
leftover="$(find "${ROOTFS}/var/cache/pacman/pkg" -mindepth 1 2>/dev/null || true)"
if [ -n "${leftover}" ]; then
    echo "error: pacman cache not empty in final rootfs:" >&2
    echo "${leftover}" >&2
    exit 1
fi
if [ -s "${ROOTFS}/etc/machine-id" ]; then
    echo "error: /etc/machine-id is not empty in final rootfs" >&2
    exit 1
fi

as_root chroot "${ROOTFS}" /usr/bin/pacman -Q >"${MANIFEST}"
echo "==> manifest: ${MANIFEST} ($(wc -l <"${MANIFEST}") packages)"

# ---------------------------------------------------------------------------
# [8/9] btrfs image (content in default subvolume rootfs_subvol)
# ---------------------------------------------------------------------------
echo "[8/9] Create btrfs image (mkfs.btrfs --rootdir --subvol default:rootfs_subvol --shrink)"
# --subvol default:NAME turns rootdir subdir NAME into the default subvolume,
# so bind-mount the rootfs one level down inside a private mount namespace.
# In rootless mode this MUST run inside the userns so files stat as 0:0
# (run outside, every inode would be owned by the calling uid — the classic
# rootless failure mode).
"${UNS_MOUNT[@]}" -- sh -euc "
mkdir -p '${WORKDIR}/staging/rootfs_subvol'
mount --bind '${ROOTFS}' '${WORKDIR}/staging/rootfs_subvol'
mkfs.btrfs -f -L '${IMAGE_LABEL}' \
  --rootdir '${WORKDIR}/staging' \
  --subvol default:rootfs_subvol \
  --shrink \
  '${IMG}'
"

# ---------------------------------------------------------------------------
# [9/9] Compress + checksum
# ---------------------------------------------------------------------------
echo "[9/9] Compress (zstd -${ZSTD_LEVEL}) + sha256"
zstd -f -T0 "-${ZSTD_LEVEL}" "${IMG}" -o "${OUT_IMG}"
(cd "${OUTDIR}" && sha256sum "$(basename "${OUT_IMG}")" | tee "$(basename "${OUT_IMG}").sha256")

echo
echo "Done."
echo "  image:     ${OUT_IMG}"
echo "  checksum:  ${OUT_IMG}.sha256"
echo "  manifest:  ${MANIFEST}"
echo "  raw image: ${IMG} (kept for verify-image.sh)"
echo
echo "Verify:"
VERIFY_FLAGS=""
[ -n "${DEV_USER}" ] && VERIFY_FLAGS+=" --dev-user ${DEV_USER}"
[ "${SKIP_BAGUETTE_REPO}" -eq 1 ] && VERIFY_FLAGS+=" --skip-baguette-repo"
echo "  ${HERE}/tests/verify-rootfs.sh${VERIFY_FLAGS} ${ROOTFS}"
echo "  ${HERE}/tests/verify-image.sh ${IMG}"
if [ -z "${DEV_USER}" ]; then
    echo
    echo "NOTE: userless production image — the first 'vmc start' of a stock"
    echo "userless image hits a garcon-wait timeout (Chrome's installer does"
    echo "user setup in production; expected, see DESIGN.md verified facts)."
fi
