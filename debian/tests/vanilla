#!/bin/sh

set -e

echo "Checking service status right after install: "
# for transparency we want to see all status and then fail if one is inactive
systemctl status ovsdb-server.service || true
systemctl status ovs-vswitchd.service || true
systemctl status openvswitch-switch.service || true
systemctl is-active ovs-vswitchd.service ovsdb-server.service openvswitch-switch.service
echo "OK"

echo "Checking daemon pids to exist: "
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
