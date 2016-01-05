# The @variables@ in this file are replaced by default directories for
# use in python/ovs/dirs.py in the source directory and replaced by the
# configured directories for use in the installed python/ovs/dirs.py.
#
import os

# Note that the use of """ is to aid in dealing with paths with quotes in them.
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
