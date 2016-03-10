#! /bin/sh
#
# Script to stop all of OVN and OVS
#
OVS_BINDIR=/usr/local/bin ; export OVS_RUNDIR
OVS_SBINDIR=/usr/local/sbin ; export OVS_SBINDIR
OVS_DBDIR=/usr/local/var/run/openvswitch ; export OVS_DBDIR
OVS_LOGDIR=/usr/local/var/log/openvswitch ; export OVS_LOGDIR
OVN_CONTROLLER_VTEP_PID_FILE=$OVS_DBDIR/ovn-controller-vtep.pid ; export OVN_CONTROLLER_VTEP_PID_FILE
OVN_CONTROLLER_PID_FILE=$OVS_DBDIR/ovn-controller.pid ; export OVN_CONTROLLER_PID_FILE
OVN_NORTHD_PID_FILE=$OVS_DBDIR/ovn-northd.pid ; export OVN_NORTHD_PID_FILE
OVS_VSWITCHD_PID_FILE=$OVS_DBDIR/ovs-vswitchd.pid ; export OVS_VSWITCHD_PID_FILE
OVSDB_SERVER_PID_FILE=$OVS_DBDIR/ovsdb-server.pid ; export OVSDB_SERVER_PID_FILE
#
# Stop ovn-controller-vtep daemon
if [[ -e ${OVN_CONTROLLER_VTEP_PID_FILE} ]]; then
    OVN_CONTROLLER_VTEP_PID=$(cat ${OVN_CONTROLLER_VTEP_PID_FILE});
    kill -9 $OVN_CONTROLLER_VTEP_PID
    rm -f $OVN_CONTROLLER_VTEP_PID_FILE
fi
#
# Stop ovn-controller daemon
if [[ -e ${OVN_CONTROLLER_PID_FILE} ]]; then
    OVN_CONTROLLER_PID=$(cat ${OVN_CONTROLLER_PID_FILE});
    kill -9 $OVN_CONTROLLER_PID
    rm -f $OVN_CONTROLLER_PID_FILE
fi
#
# Stop ovn-northd daemon
if [[ -e ${OVN_NORTHD_PID_FILE} ]]; then
    OVN_NORTHD_PID=$(cat ${OVN_NORTHD_PID_FILE});
    kill -9 $OVN_NORTHD_PID
    rm -f $OVN_NORTHD_PID_FILE
fi
#
# Stop ovs-vswitch daemon
if [[ -e ${OVS_VSWITCHD_PID_FILE} ]]; then
    OVS_VSWITCHD_PID=$(cat ${OVS_VSWITCHD_PID_FILE});
    kill -9 $OVS_VSWITCHD_PID
    rm -f $OVS_VSWITCHD_PID_FILE
fi
#
# Stop ovsdb-server daemon
if [[ -e ${OVSDB_SERVER_PID_FILE} ]]; then
    OVSDB_SERVER_PID=$(cat ${OVSDB_SERVER_PID_FILE});
    kill -9 $OVSDB_SERVER_PID
    rm -f $OVSDB_SERVER_PID_FILE
fi
#
# Clean DB Dir
rm -f $OVS_DBDIR/*.db
rm -f $OVS_DBDIR/.*.~lock~
rm -f $OVS_DBDIR/*.ctl
rm -f $OVS_DBDIR/db.sock
#
# Clean LOGS
rm -r $OVS_LOGDIR/*.log
# Remove kernel modules
# rmmod geneve
# rmmod openvswitch
