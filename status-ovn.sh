#! /bin/sh
#
# Script to show status of all OVN and OVS daemons
#
#
# Check installed modules
modinfo openvswitch
modinfo geneve
OVS_BINDIR=/usr/local/bin/; export OVS_RUNDIR
OVS_SBINDIR=/usr/local/sbin/; export OVS_SBINDIR
OVS_DBDIR=/usr/local/var/run/openvswitch/; export OVS_DBDIR
OVN_CONTROLLER_VTEP_PID_FILE=$OVS_DBDIR/ovn-controller-vtep.pid; export OVN_CONTROLLER_VTEP_PID_FILE
OVN_CONTROLLER_PID_FILE=$OVS_DBDIR/ovn-controller.pid; export OVN_CONTROLLER_PID_FILE
OVN_NORTHD_PID_FILE=$OVS_DBDIR/ovn-northd.pid; export OVN_NORTHD_PID_FILE
OVS_VSWITCHD_PID_FILE=$OVS_DBDIR/ovs-vswitchd.pid; export OVS_VSWITCHD_PID_FILE
OVSDB_SERVER_PID_FILE=$OVS_DBDIR/ovsdb-server.pid; export OVSDB_SERVER_PID_FILE
#
# Status ovn-controller-vtep daemon
if [[ -e ${OVN_CONTROLLER_VTEP_PID_FILE} ]]; then
    OVN_CONTROLLER_VTEP_PID=$(cat ${OVN_CONTROLLER_VTEP_PID_FILE});
    echo "ovn-controller-vtep running as PID: $OVN_CONTROLLER_VTEP_PID"
fi
#
# Stop ovn-controller daemon
if [[ -e ${OVN_CONTROLLER_PID_FILE} ]]; then
    OVN_CONTROLLER_PID=$(cat ${OVN_CONTROLLER_PID_FILE});
    echo "ovn-controller running as PID: $OVN_CONTROLLER_PID"
fi
#
# Stop ovn-northd daemon
if [[ -e ${OVN_NORTHD_PID_FILE} ]]; then
    OVN_NORTHD_PID=$(cat ${OVN_NORTHD_PID_FILE});
    echo "ovn-northd running as PID: $OVN_NORTHD_PID"
fi
#
# Stop ovs-vswitch daemon
if [[ -e ${OVS_VSWITCHD_PID_FILE} ]]; then
    OVS_VSWITCHD_PID=$(cat ${OVS_VSWITCHD_PID_FILE});
    echo "ovs-vswitch running as PID: $OVS_VSWITCHD_PID"
fi
#
# Stop ovsdb-server daemon
if [[ -e ${OVSDB_SERVER_PID_FILE} ]]; then
    OVSDB_SERVER_PID=$(cat ${OVSDB_SERVER_PID_FILE});
    echo "ovsdb-server running as PID: $OVSDB_SERVER_PID"
fi

