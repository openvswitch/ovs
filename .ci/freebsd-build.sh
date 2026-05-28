#!/bin/bash
# Builds and tests OVS inside a FreeBSD QEMU VM.
#
# Requires FREEBSD_VER and CC to be set (e.g. via the workflow env).
# The cached image freebsd-${FREEBSD_VER}.qcow2 must exist in the
# current directory (restored from actions/cache by the workflow).

set -o errexit
set -x

FREEBSD_VER="${FREEBSD_VER:?Must set FREEBSD_VER}"
CC="${CC:?Must set CC}"

BASE_IMG="freebsd-${FREEBSD_VER}.qcow2"
RUN_IMG="freebsd-run.qcow2"

if [ ! -f "${BASE_IMG}" ]; then
    echo "ERROR: ${BASE_IMG} not found." >&2
    exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
. "${SCRIPT_DIR}/freebsd-vm.sh"

KEY_DIR="$(mktemp -d)"
SSH_KEY="${KEY_DIR}/id_ed25519"
ssh-keygen -t ed25519 -f "${SSH_KEY}" -N "" -q
export FREEBSD_SSH_KEY="${SSH_KEY}"

# COW overlay keeps the cached base image unmodified.
qemu-img create -f qcow2 -F qcow2 -b "$(realpath "${BASE_IMG}")" "${RUN_IMG}"

freebsd_create_seed "${SSH_KEY}.pub" /tmp/freebsd-seed /tmp/freebsd-seed.iso false

OVMF_VARS="/tmp/freebsd-ovmf-vars.fd"
cp "${FREEBSD_OVMF_VARS}" "${OVMF_VARS}"
freebsd_start_vm "${RUN_IMG}" /tmp/freebsd-seed.iso "${OVMF_VARS}"

cleanup() {
    mkdir -p tests
    freebsd_rsync_from /root/ovs/config.log          ./     2>/dev/null || true
    freebsd_rsync_from /root/ovs/tests/testsuite.log tests/ 2>/dev/null || true
    freebsd_rsync_from /root/ovs/tests/testsuite.dir tests/ 2>/dev/null || true
    freebsd_rsync_from /var/log/nuageinit.log        ./     2>/dev/null || true
    freebsd_stop_vm
    cp /tmp/freebsd-vm.log ./freebsd-console.log 2>/dev/null || true
    rm -rf "${KEY_DIR}" "${RUN_IMG}" "${OVMF_VARS}" \
           /tmp/freebsd-seed /tmp/freebsd-seed.iso
}
trap cleanup EXIT

freebsd_wait_ssh 20 10
freebsd_wait_firstboot 30 5

freebsd_ssh "mkdir -p /root/ovs"
freebsd_rsync_to "$(pwd)/" /root/ovs/

freebsd_ssh "cd /root/ovs && ./boot.sh && \
    ./configure CC=${CC} CFLAGS='-g -O2 -Wall' MAKE=gmake --enable-Werror"

freebsd_ssh "cd /root/ovs && gmake -j8 check TESTSUITEFLAGS=-j8 RECHECK=yes"
