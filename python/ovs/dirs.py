# These are the default directories.  They will be replaced by the
# configured directories at install time.

import os
PKGDATADIR = os.environ.get("OVS_PKGDATADIR", "/usr/local/share/openvswitch")
RUNDIR = os.environ.get("OVS_RUNDIR", "/var/run")
LOGDIR = os.environ.get("OVS_LOGDIR", "/usr/local/var/log")
BINDIR = os.environ.get("OVS_BINDIR", "/usr/local/bin")
