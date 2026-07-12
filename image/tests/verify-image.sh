#!/usr/bin/env bash
# Image-level asserts against a built btrfs image (raw .img or .img.zst).
# See DESIGN.md "Tests". Fully rootless: btrfs check / inspect-internal work
# on image FILES as a regular user; guestfish (qemu appliance, no root) is
# used for mount-level ownership/setuid spot checks when available.
#
# Usage: verify-image.sh <image.img | image.img.zst>
set -euo pipefail

[ $# -eq 1 ] || { echo "usage: $0 <image.img|image.img.zst>" >&2; exit 2; }
IMG_IN="$1"
[ -f "${IMG_IN}" ] || { echo "error: no such file: ${IMG_IN}" >&2; exit 2; }

TMPD=""
# if/fi (not &&): a bare failing test in the EXIT trap would poison the
# script's exit status when TMPD is unset (raw .img input)
cleanup() { if [ -n "${TMPD}" ]; then rm -rf "${TMPD}"; fi; }
trap cleanup EXIT

case "${IMG_IN}" in
    *.zst|*.zstd)
        command -v zstd >/dev/null || { echo "error: zstd required for compressed input" >&2; exit 1; }
        TMPD="$(mktemp -d)"
        IMG="${TMPD}/$(basename "${IMG_IN%.*}")"
        echo "== decompressing ${IMG_IN} -> ${IMG}"
        zstd -d -q "${IMG_IN}" -o "${IMG}"
        ;;
    *) IMG="${IMG_IN}" ;;
esac

NPASS=0 NFAIL=0 NSKIP=0
pass() { NPASS=$((NPASS + 1)); printf 'PASS  %s\n' "$1"; }
fail() { NFAIL=$((NFAIL + 1)); printf 'FAIL  %s\n' "$1"; }
skip() { NSKIP=$((NSKIP + 1)); printf 'SKIP  %s\n' "$1"; }

echo "== verify-image: ${IMG}"

# ---------------------------------------------------------------------------
# 1. Filesystem consistency (btrfs check works on image files as a user)
# ---------------------------------------------------------------------------
if check_out="$(btrfs check --readonly "${IMG}" 2>&1)"; then
    pass "btrfs check --readonly: no errors"
else
    fail "btrfs check --readonly: no errors"
    printf '%s\n' "${check_out}" | sed 's/^/      /'
fi

# ---------------------------------------------------------------------------
# 2. Superblock: label (cosmetic contract)
# ---------------------------------------------------------------------------
label="$(btrfs inspect-internal dump-super "${IMG}" | awk '$1 == "label" {print $2}')"
if [ "${label}" = "arch-baguette" ]; then
    pass "filesystem label is 'arch-baguette'"
else
    fail "filesystem label is 'arch-baguette' (got: '${label}')"
fi

# ---------------------------------------------------------------------------
# 3. Default subvolume is rootfs_subvol (the format concierge expects).
#    Root tree (tree 1) layout, verified against a known-good image:
#      item ... key (ROOT_TREE_DIR DIR_ITEM <hash>)
#          location key (<ID> ROOT_ITEM 0) ... name: default
#      item ... key (FS_TREE ROOT_REF <ID>)
#          root ref key dirid 256 sequence N name rootfs_subvol
# ---------------------------------------------------------------------------
root_tree="$(btrfs inspect-internal dump-tree -t 1 "${IMG}")"
default_id="$(printf '%s\n' "${root_tree}" | awk '
    /ROOT_TREE_DIR DIR_ITEM/ { f = 1 }
    f && /location key/      { loc = $3; gsub(/\(/, "", loc) }
    f && /name: default$/    { print loc; exit }')"
if [ -n "${default_id}" ]; then
    pass "default-subvol DIR_ITEM present (points at root ${default_id})"
else
    fail "default-subvol DIR_ITEM present"
fi
subvol_name="$(printf '%s\n' "${root_tree}" | awk -v id="${default_id:-none}" '
    $0 ~ ("ROOT_REF " id ")") { f = 1; next }
    f && /root ref key/       { print $NF; exit }')"
if [ "${subvol_name}" = "rootfs_subvol" ]; then
    pass "default subvolume is 'rootfs_subvol' (root ${default_id})"
else
    fail "default subvolume is 'rootfs_subvol' (got: '${subvol_name:-<none>}')"
fi

# ---------------------------------------------------------------------------
# 4. Mount-level spot checks via guestfish (rootless qemu appliance):
#    mounting without subvol= must land in the rootfs (default subvol really
#    applies), ownership must be 0:0 (the rootless-build failure mode is
#    everything owned by the calling uid), setuid must survive.
# ---------------------------------------------------------------------------
if ! command -v guestfish >/dev/null; then
    skip "guestfish spot checks (guestfs-tools not installed)"
else
    gf_out="$(guestfish --ro -a "${IMG}" 2>&1 <<'EOF' || true
run
mount /dev/sda /
echo ===LS===
ls /
echo ===SUBVOLS===
btrfs-subvolume-list /
echo ===DEFAULT===
btrfs-subvolume-get-default /
echo ===SHADOW===
stat /etc/shadow
echo ===SUDO===
stat /usr/bin/sudo
EOF
)"
    section() { printf '%s\n' "${gf_out}" | sed -n "/^===$1===\$/,/^===/p" | sed '1d;/^===/d'; }

    if section LS | grep -qx 'etc' && section LS | grep -qx 'usr'; then
        pass "guestfish: default mount lands in the rootfs (etc/ and usr/ at /)"
    else
        fail "guestfish: default mount lands in the rootfs (etc/ and usr/ at /)"
    fi

    subvol_id="$(section SUBVOLS | awk -F: '/btrfssubvolume_id/ {gsub(/ /,"",$2); print $2; exit}')"
    default_gf="$(section DEFAULT | head -1 | tr -d '[:space:]')"
    if [ -n "${subvol_id}" ] && [ "${default_gf}" = "${subvol_id}" ]; then
        pass "guestfish: btrfs default subvolume id matches rootfs_subvol (${subvol_id})"
    else
        fail "guestfish: btrfs default subvolume id matches rootfs_subvol (default=${default_gf:-?} subvol=${subvol_id:-?})"
    fi

    gf_stat() { section "$1" | awk -v k="$2" -F': ' '$1 == k {print $2; exit}'; }
    shadow_mode="$(printf '%o' "$(gf_stat SHADOW mode || echo 0)")"
    if [ "$(gf_stat SHADOW uid)" = "0" ] && [ "$(gf_stat SHADOW gid)" = "0" ] \
       && [ "${shadow_mode}" = "100600" ]; then
        pass "guestfish: /etc/shadow is 0:0 mode 0600"
    else
        fail "guestfish: /etc/shadow is 0:0 mode 0600 (uid=$(gf_stat SHADOW uid) gid=$(gf_stat SHADOW gid) mode=${shadow_mode})"
    fi
    sudo_mode="$(printf '%o' "$(gf_stat SUDO mode || echo 0)")"
    if [ "$(gf_stat SUDO uid)" = "0" ] && [ "$(gf_stat SUDO gid)" = "0" ] \
       && [ "${sudo_mode}" = "104755" ]; then
        pass "guestfish: /usr/bin/sudo is 0:0 setuid (mode 04755)"
    else
        fail "guestfish: /usr/bin/sudo is 0:0 setuid (uid=$(gf_stat SUDO uid) gid=$(gf_stat SUDO gid) mode=${sudo_mode})"
    fi
fi

echo
echo "== verify-image summary: ${NPASS} passed, ${NFAIL} failed, ${NSKIP} skipped"
[ "${NFAIL}" -eq 0 ]
