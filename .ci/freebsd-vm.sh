#!/bin/bash
# FreeBSD QEMU VM helpers.  Source this file; do not execute directly.
#
# Requires FREEBSD_SSH_KEY (path to private key) to be set before use.

FREEBSD_SSH_PORT=2222
FREEBSD_VM_PIDFILE=/tmp/freebsd-vm.pid

FREEBSD_OVMF_CODE="/usr/share/OVMF/OVMF_CODE_4M.fd"
FREEBSD_OVMF_VARS="/usr/share/OVMF/OVMF_VARS_4M.fd"

_FREEBSD_SSH_OPTS=(
    -p "$FREEBSD_SSH_PORT"
    -o StrictHostKeyChecking=no
    -o UserKnownHostsFile=/dev/null
    -o ConnectTimeout=5
    -o BatchMode=yes
    -o ServerAliveInterval=15
    -o ServerAliveCountMax=4
    -o LogLevel=ERROR
)

freebsd_ssh() {
    ssh "${_FREEBSD_SSH_OPTS[@]}" -i "${FREEBSD_SSH_KEY}" \
        root@localhost "$@"
}

freebsd_rsync_to() {
    local src="${1:?source required}"
    local dst="${2:?destination required}"

    rsync -az --delete \
        -e "ssh ${_FREEBSD_SSH_OPTS[*]} -i ${FREEBSD_SSH_KEY}" \
        "${src}" "root@localhost:${dst}"
}

freebsd_rsync_from() {
    local src="${1:?source required}"
    local dst="${2:?destination required}"

    rsync -az \
        -e "ssh ${_FREEBSD_SSH_OPTS[*]} -i ${FREEBSD_SSH_KEY}" \
        "root@localhost:${src}" "${dst}"
}

# freebsd_start_vm <image> <seed_iso> <ovmf_vars>
freebsd_start_vm() {
    local img="${1:?image file required}"
    local seed_iso="${2:?seed ISO required}"
    local ovmf_vars="${3:?OVMF vars file required}"

    qemu-system-x86_64 \
        -enable-kvm -cpu host \
        -m 4096 -smp 4 \
        -nographic \
        -netdev "user,id=net0,hostfwd=tcp::${FREEBSD_SSH_PORT}-:22" \
        -device virtio-net-pci,netdev=net0 \
        -drive "file=${img},if=virtio,format=qcow2,cache=unsafe" \
        -device virtio-rng-pci \
        -pidfile "${FREEBSD_VM_PIDFILE}" \
        -device ahci,id=ahci0 \
        -drive "if=none,id=seed,file=${seed_iso},format=raw,media=cdrom,readonly=on" \
        -device ide-cd,bus=ahci0.0,drive=seed \
        -drive "if=pflash,format=raw,readonly=on,file=${FREEBSD_OVMF_CODE}" \
        -drive "if=pflash,format=raw,file=${ovmf_vars}" \
        > /tmp/freebsd-vm.log 2>&1 &

    echo "FreeBSD VM launched (PID $!); log: /tmp/freebsd-vm.log"
}

freebsd_stop_vm() {
    local pid

    [ -f "${FREEBSD_VM_PIDFILE}" ] || return 0
    pid=$(cat "${FREEBSD_VM_PIDFILE}" 2>/dev/null) || return 0

    freebsd_ssh "shutdown -p now" 2>/dev/null || true

    local i
    for i in $(seq 1 30); do
        kill -0 "${pid}" 2>/dev/null || {
            rm -f "${FREEBSD_VM_PIDFILE}"
            return 0
        }
        sleep 2
    done

    kill "${pid}" 2>/dev/null || true
    rm -f "${FREEBSD_VM_PIDFILE}"
}

# freebsd_wait_ssh <max_attempts> <delay>
freebsd_wait_ssh() {
    local max="${1}" delay="${2}" i

    echo "Waiting for SSH on port ${FREEBSD_SSH_PORT} ..."
    for i in $(seq 1 "${max}"); do
        if freebsd_ssh true 2>/dev/null; then
            echo "SSH ready (attempt ${i})."
            return 0
        fi
        echo "  attempt ${i}/${max} ..."
        [ "${i}" != "${max}" ] && sleep "${delay}"
    done

    echo "ERROR: SSH not available after $((max * delay))s." >&2
    return 1
}

# freebsd_wait_firstboot <max_attempts> <delay>
# Waits until /firstboot is removed, meaning nuageinit (and its sshd
# restart runcmd) has finished.  Call after freebsd_wait_ssh.
freebsd_wait_firstboot() {
    local max="${1}" delay="${2}" i

    echo "Waiting for firstboot to complete ..."
    for i in $(seq 1 "${max}"); do
        if freebsd_ssh "test ! -f /firstboot" 2>/dev/null; then
            echo "Firstboot complete (attempt ${i})."
            return 0
        fi
        echo "  attempt ${i}/${max} ..."
        sleep "${delay}"
    done

    echo "ERROR: /firstboot still present after $((max * delay))s." >&2
    return 1
}

# freebsd_create_seed <pubkey_file> <work_dir> <output_iso> [install_packages]
# Creates a NoCloud seed ISO for nuageinit with SSH key injection.
# When install_packages is "true" (default), the seed also includes
# package_update and the CI package list from FREEBSD_PACKAGES
# (used during image preparation).  Pass "false" for build jobs where
# the cached image already has all packages installed.
freebsd_create_seed() {
    local pub_key_file="${1:?public key file required}"
    local work_dir="${2:?work dir required}"
    local out_iso="${3:?output ISO required}"
    local install_packages="${4:-true}"
    local pub_key

    pub_key=$(cat "${pub_key_file}")
    mkdir -p "${work_dir}"

    cat > "${work_dir}/meta-data" <<EOF
instance-id: freebsd-ci
local-hostname: freebsd-ci
EOF

    cat > "${work_dir}/user-data" <<EOF
#cloud-config
users:
  - name: root
    ssh_authorized_keys:
      - ${pub_key}
EOF

    if [ "${install_packages}" = "true" ]; then
        local packages="${FREEBSD_PACKAGES:?Must set FREEBSD_PACKAGES}"
        {
            echo "package_update: true"
            echo "packages:"
            for pkg in ${packages}; do
                echo "  - ${pkg}"
            done
        } >> "${work_dir}/user-data"
    fi

    cat >> "${work_dir}/user-data" <<EOF
runcmd:
  - printf '\nPermitRootLogin yes\n' >> /etc/ssh/sshd_config
  - grep -q kern.coredump /etc/sysctl.conf || echo 'kern.coredump=0' >> /etc/sysctl.conf
  - sysctl -w kern.coredump=0 || true
  - service sshd onerestart || true
EOF

    genisoimage -output "${out_iso}" \
        -volid cidata -rational-rock -joliet \
        "${work_dir}/user-data" "${work_dir}/meta-data" 2>/dev/null

    echo "Seed ISO created: ${out_iso}"
}
