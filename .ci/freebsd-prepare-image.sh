#!/bin/bash
# Prepares a FreeBSD QEMU image with CI dependencies pre-installed.
#
# Requires FREEBSD_VER and FREEBSD_PACKAGES to be set
# (e.g. via the workflow env).
# Downloads the FreeBSD BASIC-CLOUDINIT qcow2 image, boots it with
# nuageinit to install packages and configure SSH, then compresses
# the result for caching.
#
# Output: freebsd-${FREEBSD_VER}.qcow2

set -o errexit
set -x

FREEBSD_VER="${FREEBSD_VER:?Must set FREEBSD_VER}"
FREEBSD_PACKAGES="${FREEBSD_PACKAGES:?Must set FREEBSD_PACKAGES}"

RELEASE="${FREEBSD_VER}-RELEASE"
BASE_URL="https://download.freebsd.org/releases/VM-IMAGES/${RELEASE}/amd64/Latest"

IMG_NAME="FreeBSD-${RELEASE}-amd64-BASIC-CLOUDINIT-ufs.qcow2"
IMG_XZ="${IMG_NAME}.xz"
OUT_IMG="freebsd-${FREEBSD_VER}.qcow2"

wget -q "${BASE_URL}/CHECKSUM.SHA256" -O freebsd-checksum.txt
wget -q "${BASE_URL}/${IMG_XZ}" -O "${IMG_XZ}"

expected_sha=$(grep "(${IMG_XZ})" freebsd-checksum.txt | awk '{print $NF}')
actual_sha=$(sha256sum "${IMG_XZ}" | awk '{print $1}')
if [ "${expected_sha}" != "${actual_sha}" ]; then
    echo "ERROR: SHA256 mismatch for ${IMG_XZ}" >&2
    echo "  expected: ${expected_sha}" >&2
    echo "  actual:   ${actual_sha}" >&2
    exit 1
fi

xz --decompress --keep "${IMG_XZ}"
mv "${IMG_NAME}" "${OUT_IMG}"
rm -f "${IMG_XZ}"

qemu-img resize "${OUT_IMG}" +8G

KEY_DIR="$(mktemp -d)"
SSH_KEY="${KEY_DIR}/id_ed25519"
ssh-keygen -t ed25519 -f "${SSH_KEY}" -N "" -q

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
. "${SCRIPT_DIR}/freebsd-vm.sh"
export FREEBSD_SSH_KEY="${SSH_KEY}"

freebsd_create_seed "${SSH_KEY}.pub" /tmp/freebsd-seed /tmp/freebsd-seed.iso

OVMF_VARS="/tmp/freebsd-ovmf-vars.fd"
cp "${FREEBSD_OVMF_VARS}" "${OVMF_VARS}"
freebsd_start_vm "${OUT_IMG}" /tmp/freebsd-seed.iso "${OVMF_VARS}"

VM_STOPPED=false
cleanup() {
    if ! ${VM_STOPPED}; then
        freebsd_rsync_from /var/log/nuageinit.log ./ 2>/dev/null || true
        freebsd_stop_vm
    fi
    cp /tmp/freebsd-vm.log ./freebsd-console.log 2>/dev/null || true
    rm -rf "${KEY_DIR}" "${OVMF_VARS}" \
           /tmp/freebsd-seed /tmp/freebsd-seed.iso
}
trap cleanup EXIT

# Image preparation covers two boots: boot 1 (freebsd-update + reboot)
# then boot 2 (package install + runcmds).
freebsd_wait_ssh 90 10
freebsd_wait_firstboot 12 10

# Verify all CI packages were installed successfully.
freebsd_ssh "pkg info ${FREEBSD_PACKAGES}"

# Restore /firstboot so nuageinit re-runs on build job boots to inject
# per-job SSH keys.
freebsd_ssh "touch /firstboot"

freebsd_stop_vm
VM_STOPPED=true

qemu-img convert -c -O qcow2 "${OUT_IMG}" "${OUT_IMG}.tmp"
mv "${OUT_IMG}.tmp" "${OUT_IMG}"

echo "Image ready: ${OUT_IMG} ($(du -sh "${OUT_IMG}" | cut -f1))"
