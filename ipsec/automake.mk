# Copyright (C) 2017 Nicira, Inc.
#
# Copying and distribution of this file, with or without modification,
# are permitted in any medium without royalty provided the copyright
# notice and this notice are preserved.  This file is offered as-is,
# without warranty of any kind.

scripts_SCRIPTS += ipsec/ovs-monitor-ipsec
EXTRA_DIST += ipsec/ovs-monitor-ipsec.in
FLAKE8_PYFILES += ipsec/ovs-monitor-ipsec.in
CLEANFILES += ipsec/ovs-monitor-ipsec
