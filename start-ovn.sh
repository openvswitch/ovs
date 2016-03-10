#! /bin/sh
#
# Script to start all of OVN and OVS
#
#
# Install openvswitch and geneve
# modprobe openvswitch
# modprobe geneve
#
# Set directories
OVS_BINDIR=/usr/local/bin ; export OVS_RUNDIR
OVS_SBINDIR=/usr/local/sbin ; export OVS_SBINDIR
OVS_DBDIR=/usr/local/var/run/openvswitch ; export OVS_DBDIR
# Create databases
mkdir -p $OVS_DBDIR
rm -f $OVS_DBDIR/*.db
rm -f $OVS_DBDIR/.*.~lock~
rm -f $OVS_DBDIR/*.pid
$OVS_BINDIR/ovsdb-tool create $OVS_DBDIR/conf.db vswitchd/vswitch.ovsschema
$OVS_BINDIR/ovsdb-tool create $OVS_DBDIR/ovnnb.db ovn/ovn-nb.ovsschema
$OVS_BINDIR/ovsdb-tool create $OVS_DBDIR/ovnsb.db ovn/ovn-sb.ovsschema
$OVS_BINDIR/ovsdb-tool create $OVS_DBDIR/vtep.db vtep/vtep.ovsschema
#
# Start ovsdb server
$OVS_SBINDIR/ovsdb-server --detach --pidfile  -v --log-file --remote=punix:$OVS_DBDIR/db.sock \
    $OVS_DBDIR/ovnsb.db $OVS_DBDIR/ovnnb.db $OVS_DBDIR/vtep.db $OVS_DBDIR/conf.db
#Add a small delay to allow ovsdb-server to launch.
sleep 0.1
#Wait for ovsdb-server to finish launching.
if test ! -e "$OVS_DBDIR"/db.sock; then
    echo -n "Waiting for ovsdb-server to start..."
    while test ! -e "$OVS_DBDIR"/db.sock; do
        sleep 1;
    done
    echo "  Done"
fi
#
# Start OVS daemons
$OVS_BINDIR/ovs-vsctl --no-wait -- init
$OVS_SBINDIR/ovs-vswitchd --pidfile --detach -v --log-file
#
# Add sfi bridge
ovs-vsctl add-br br-int
#
# Start OVN
ovs-vsctl set open . external-ids:system-id=31da7100-b736-406b-985a-69452ae8e5cd
ovs-vsctl set open . external-ids:ovn-remote=unix:$OVS_DBDIR/db.sock
ovs-vsctl set open . external-ids:ovn-bridge=br-int
ovs-vsctl set open . external-ids:ovn-encap-type=geneve
ovs-vsctl set open . external-ids:ovn-encap-ip=127.0.0.1
#
# Start ovn daemons
$OVS_BINDIR/ovn-northd --detach --pidfile -v --log-file
$OVS_BINDIR/ovn-controller --detach --pidfile -v --log-file
$OVS_BINDIR/ovn-controller-vtep --detach --pidfile -v --log-file
