import os
PKGDATADIR = os.environ.get("OVS_PKGDATADIR", """/usr/local/share/openvswitch""")
RUNDIR = os.environ.get("OVS_RUNDIR", """/var/run""")
LOGDIR = os.environ.get("OVS_LOGDIR", """/usr/local/var/log""")
BINDIR = os.environ.get("OVS_BINDIR", """/usr/local/bin""")

DBDIR = os.environ.get("OVS_DBDIR")
if not DBDIR:
    sysconfdir = os.environ.get("OVS_SYSCONFDIR")
    if sysconfdir:
        DBDIR = "%s/openvswitch" % sysconfdir
    else:
        DBDIR = """/usr/local/etc/openvswitch"""
