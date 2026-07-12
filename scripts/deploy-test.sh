#!/usr/bin/env bash
# Deploy a locally-built Baguette image into the RUNNING nested ChromeOS test
# rig and boot-test it. Parameterized port of the verified
# /home/r/baguette/dev-workflow/deploy-test.sh (see DESIGN.md "Tests").
#
# Usage: scripts/deploy-test.sh [IMAGE.zst] [VMNAME]
#   IMAGE   default: <repo>/out/image/baguette_arch_rootfs.img.zst
#   VMNAME  default: v2test
#           REFUSED: 'baguette' (stock reference VM) and 'archtest'
#           (rig-owned dev-workflow VM) are never touched.
#
# Env: VSH_USER (default test; evidence falls back to root for userless
#      images), TESTING_RSA, CROS_SSH_PORT, VM_SIZE (default 10G).
#
# This script does NOT (re)launch the ChromeOS VM. If the rig is down it
# fails fast and points at the RUNBOOK relaunch procedure.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(dirname "${HERE}")"

IMG="${1:-${REPO_ROOT}/out/image/baguette_arch_rootfs.img.zst}"
VM="${2:-v2test}"
VSH_USER="${VSH_USER:-test}"
KEY="${TESTING_RSA:-/home/r/baguette/cros-vm/testing_rsa}"
PORT="${CROS_SSH_PORT:-9222}"
VM_SIZE="${VM_SIZE:-10G}"
RUNBOOK="/home/r/baguette/cros-vm/RUNBOOK.md"
EVIDENCE="${REPO_ROOT}/out/deploy-test-${VM}.log"

case "${VM}" in
    baguette|archtest)
        echo "error: refusing to touch protected VM '${VM}'" >&2
        echo "  'baguette' is the stock known-good reference; 'archtest' belongs" >&2
        echo "  to the dev-workflow loop. Use the default 'v2test' or another name." >&2
        exit 2
        ;;
    "") echo "error: empty VM name" >&2; exit 2 ;;
esac

[ -f "${IMG}" ] || { echo "error: image not found: ${IMG} (build with image/build.sh)" >&2; exit 1; }
[ -f "${KEY}" ] || { echo "error: ssh key not found: ${KEY}" >&2; exit 1; }

SSHOPTS=(-i "${KEY}" -o IdentitiesOnly=yes -o StrictHostKeyChecking=no
         -o UserKnownHostsFile=/dev/null -o ConnectTimeout=10)
SSH=(ssh "${SSHOPTS[@]}" -p "${PORT}" root@127.0.0.1)

BASE="$(basename "${IMG}")"
mkdir -p "$(dirname "${EVIDENCE}")"

# ---------------------------------------------------------------------------
echo "[1/4] Check the ChromeOS rig is up (ssh 127.0.0.1:${PORT})"
if ! HASH="$("${SSH[@]}" 'ls /home/user/' 2>/dev/null)"; then
    cat >&2 <<EOF
error: cannot reach the nested ChromeOS VM on 127.0.0.1:${PORT}.

This script never (re)launches the rig itself. Bring it up first, per
${RUNBOOK} ("Relaunch procedure"):

  setsid -f fish /home/r/baguette/cros-vm/launch-cros-vm.fish \\
    </dev/null >/home/r/baguette/cros-vm/qemu-stdout.log 2>&1
  # then restore session/state:
  bash /home/r/baguette/cros-vm/restore-baguette.sh
EOF
    exit 1
fi
if [ -z "${HASH}" ]; then
    cat >&2 <<EOF
error: rig is up but no active ChromeOS session (no owner hash under /home/user).
Log in first (per ${RUNBOOK}):
  ${SSH[*]} '/usr/local/autotest/bin/autologin.py -d -w --no-popup-notification'
EOF
    exit 1
fi
echo "  owner hash: ${HASH}"

# ---------------------------------------------------------------------------
echo "[2/4] scp image into ChromeOS VM Downloads (+ sha256 verify)"
scp "${SSHOPTS[@]}" -P "${PORT}" "${IMG}" \
    "root@127.0.0.1:/home/user/${HASH}/MyFiles/Downloads/" 2>/dev/null
LOCAL_SHA="$(sha256sum "${IMG}" | awk '{print $1}')"
REMOTE_SHA="$("${SSH[@]}" "sha256sum '/home/user/${HASH}/MyFiles/Downloads/${BASE}'" 2>/dev/null | awk '{print $1}')"
if [ "${LOCAL_SHA}" != "${REMOTE_SHA}" ]; then
    echo "error: sha256 mismatch after scp (local ${LOCAL_SHA} != remote ${REMOTE_SHA:-<none>})" >&2
    exit 1
fi
echo "  sha256 OK: ${LOCAL_SHA}"

# ---------------------------------------------------------------------------
echo "[3/4] Recreate + start VM '${VM}' (size ${VM_SIZE})"
START_RC=0
"${SSH[@]}" 2>/dev/null <<EOF || START_RC=$?
set -e
HASH=\$(ls /home/user/)
VMC() { sudo -u chronos CROS_USER_ID_HASH=\$HASH VMC_NONINTERACTIVE=1 vmc "\$@"; }
VMC stop "${VM}"    >/dev/null 2>&1 || true
VMC destroy "${VM}" >/dev/null 2>&1 || true
VMC create --vm-type baguette --size ${VM_SIZE} \
  --source "/home/user/\${HASH}/MyFiles/Downloads/${BASE}" "${VM}"
timeout 240 sudo -u chronos CROS_USER_ID_HASH=\$HASH VMC_NONINTERACTIVE=1 \
  vmc start --vm-type baguette "${VM}"
EOF
if [ "${START_RC}" -ne 0 ]; then
    echo "WARN: vmc start returned ${START_RC}." >&2
    echo "  Known behavior for USERLESS production images: the first-ever start" >&2
    echo "  times out waiting for garcon (Chrome's installer normally provisions" >&2
    echo "  the user; see DESIGN.md verified facts). The VM itself may still be" >&2
    echo "  booted — attempting evidence capture as root." >&2
fi

# ---------------------------------------------------------------------------
echo "[4/4] In-guest verification (evidence -> ${EVIDENCE})"
capture_evidence() {  # $1 = guest user
    "${SSH[@]}" 2>/dev/null <<EOF
HASH=\$(ls /home/user/)
sudo -u chronos CROS_USER_ID_HASH=\$HASH vsh --vm_name="${VM}" \
  --owner_id=\$HASH --user="$1" -- sh -lc \
  'echo "os-release: \$(. /etc/os-release && echo \$PRETTY_NAME)";
   echo "kernel:     \$(uname -r)";
   echo "system:     \$(systemctl is-system-running)";
   echo "failed:     \$(systemctl --failed --no-legend | wc -l) units";
   echo "id:         \$(id)";
   df -hT / | tail -1'
EOF
}

EV_USER=""
EV_OUT=""
if EV_OUT="$(capture_evidence "${VSH_USER}")" && [ -n "${EV_OUT}" ]; then
    EV_USER="${VSH_USER}"
elif EV_OUT="$(capture_evidence root)" && [ -n "${EV_OUT}" ]; then
    EV_USER="root (user '${VSH_USER}' unavailable — userless image?)"
fi
{
    echo "== deploy-test ${VM} $(date -Is)"
    echo "== image: ${IMG} (sha256 ${LOCAL_SHA})"
    echo "== vmc start rc: ${START_RC}"
    if [ -n "${EV_USER}" ]; then
        echo "== evidence captured as: ${EV_USER}"
        printf '%s\n' "${EV_OUT}"
    else
        echo "== FAILED to capture evidence via vsh"
    fi
} | tee "${EVIDENCE}"
[ -n "${EV_USER}" ] || exit 1

echo
echo "OK: '${VM}' deployed. Enter it with:"
echo "  ${SSH[*]} \\"
echo "    'HASH=\$(ls /home/user/); sudo -u chronos CROS_USER_ID_HASH=\$HASH vsh --vm_name=${VM} --owner_id=\$HASH --user=${VSH_USER}'"
