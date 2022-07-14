#!/bin/sh

set -e

if [ ! -x /usr/lib/openvswitch-switch-dpdk/ovs-vswitchd-dpdk ]; then
    echo "DPDK enabled binary not detected - skipping"
    exit 0
fi

sse3flag=$(sed -n "/^flags.*sse3/p" < /proc/cpuinfo | wc -l)
if [ "${sse3flag}" -eq 0 ]; then
    echo "sse3 not available in test environment"
    echo "for adt-virt-qemu please consider adding --qemu-options='-cpu qemu64,+ssse3'"
    echo "SKIPPING"
    exit 0
fi

update-alternatives --set ovs-vswitchd \
    /usr/lib/openvswitch-switch-dpdk/ovs-vswitchd-dpdk
service openvswitch-switch restart

modprobe openvswitch || true

echo "kernel modules loaded: "
# Check that ovs loaded
lsmod | grep "openvswitch"
echo "OK"

echo "Checking daemons: "
pgrep ovs-vswitchd
pgrep ovsdb-server
echo "OK"

echo "stop conflicting openvswitch testcontroller"
systemctl stop openvswitch-testcontroller || true

if dpkg --compare-versions "$(dpkg-query --showformat '${Version}\n' --show mininet)" ge "2.3.0-1"; then
    PYCMD="python3"
else
    PYCMD="python2"
fi

printf "running openflow tests using mininet"
${PYCMD} `dirname $0`/openflow.py 2>&1
echo "OK"
