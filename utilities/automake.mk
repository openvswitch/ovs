bin_PROGRAMS += \
	utilities/ovs-appctl \
	utilities/ovs-testcontroller \
	utilities/ovs-dpctl \
	utilities/ovs-ofctl \
	utilities/ovs-vsctl
bin_SCRIPTS += utilities/ovs-docker \
	utilities/ovs-pki
if HAVE_PYTHON
bin_SCRIPTS += \
	utilities/ovs-dpctl-top \
	utilities/ovs-l3ping \
	utilities/ovs-parse-backtrace \
	utilities/ovs-pcap \
	utilities/ovs-tcpdump \
	utilities/ovs-tcpundump \
	utilities/ovs-test \
	utilities/ovs-vlan-test
endif
scripts_SCRIPTS += \
	utilities/ovs-check-dead-ifs \
	utilities/ovs-ctl \
	utilities/ovs-save
scripts_DATA += utilities/ovs-lib

completion_SCRIPTS += \
	utilities/ovs-appctl-bashcomp.bash \
	utilities/ovs-vsctl-bashcomp.bash

check_SCRIPTS += \
	utilities/ovs-appctl-bashcomp.bash \
	utilities/ovs-vsctl-bashcomp.bash

EXTRA_DIST += utilities/ovs-sim.in
noinst_SCRIPTS += utilities/ovs-sim

utilities/ovs-lib: $(top_builddir)/config.status

EXTRA_DIST += \
	utilities/gdb/ovs_gdb.py \
	utilities/ovs-appctl-bashcomp.bash \
	utilities/ovs-check-dead-ifs.in \
	utilities/ovs-ctl.in \
	utilities/ovs-dev.py \
	utilities/ovs-docker \
	utilities/ovs-dpctl-top.in \
	utilities/ovs-l3ping.in \
	utilities/ovs-lib.in \
	utilities/ovs-parse-backtrace.in \
	utilities/ovs-pcap.in \
	utilities/ovs-pipegen.py \
	utilities/ovs-pki.in \
	utilities/ovs-save \
	utilities/ovs-tcpdump.in \
	utilities/ovs-tcpundump.in \
	utilities/ovs-test.in \
	utilities/ovs-vlan-test.in \
	utilities/ovs-vsctl-bashcomp.bash \
	utilities/checkpatch.py
MAN_ROOTS += \
	utilities/ovs-appctl.8.in \
	utilities/ovs-testcontroller.8.in \
	utilities/ovs-ctl.8 \
	utilities/ovs-dpctl.8.in \
	utilities/ovs-dpctl-top.8.in \
	utilities/ovs-l3ping.8.in \
	utilities/ovs-ofctl.8.in \
	utilities/ovs-parse-backtrace.8 \
	utilities/ovs-pcap.1.in \
	utilities/ovs-pki.8.in \
	utilities/ovs-tcpdump.8.in \
	utilities/ovs-tcpundump.1.in \
	utilities/ovs-vlan-bug-workaround.8.in \
	utilities/ovs-vsctl.8.in
MAN_FRAGMENTS += utilities/ovs-vlan-bugs.man
CLEANFILES += \
	utilities/ovs-appctl.8 \
	utilities/ovs-ctl \
	utilities/ovs-check-dead-ifs \
	utilities/ovs-testcontroller.8 \
	utilities/ovs-dpctl.8 \
	utilities/ovs-dpctl-top \
	utilities/ovs-dpctl-top.8 \
	utilities/ovs-l3ping \
	utilities/ovs-l3ping.8 \
	utilities/ovs-lib \
	utilities/ovs-ofctl.8 \
	utilities/ovs-parse-backtrace \
	utilities/ovs-pcap \
	utilities/ovs-pcap.1 \
	utilities/ovs-pki \
	utilities/ovs-pki.8 \
	utilities/ovs-sim \
	utilities/ovs-tcpdump \
	utilities/ovs-tcpdump.8 \
	utilities/ovs-tcpundump \
	utilities/ovs-tcpundump.1 \
	utilities/ovs-test \
	utilities/ovs-vlan-test \
	utilities/ovs-vlan-bug-workaround.8 \
	utilities/ovs-vsctl.8

man_MANS += \
	utilities/ovs-appctl.8 \
	utilities/ovs-ctl.8 \
	utilities/ovs-testcontroller.8 \
	utilities/ovs-dpctl.8 \
	utilities/ovs-dpctl-top.8 \
	utilities/ovs-l3ping.8 \
	utilities/ovs-ofctl.8 \
	utilities/ovs-parse-backtrace.8 \
	utilities/ovs-pcap.1 \
	utilities/ovs-pki.8 \
	utilities/ovs-tcpdump.8 \
	utilities/ovs-tcpundump.1 \
	utilities/ovs-vlan-bug-workaround.8 \
	utilities/ovs-vsctl.8

utilities_ovs_appctl_SOURCES = utilities/ovs-appctl.c
utilities_ovs_appctl_LDADD = lib/libopenvswitch.la

utilities_ovs_testcontroller_SOURCES = utilities/ovs-testcontroller.c
utilities_ovs_testcontroller_LDADD = lib/libopenvswitch.la $(SSL_LIBS)

utilities_ovs_dpctl_SOURCES = utilities/ovs-dpctl.c
utilities_ovs_dpctl_LDADD = lib/libopenvswitch.la

utilities_ovs_ofctl_SOURCES = utilities/ovs-ofctl.c
utilities_ovs_ofctl_LDADD = \
	ofproto/libofproto.la \
	lib/libopenvswitch.la

utilities_ovs_vsctl_SOURCES = utilities/ovs-vsctl.c
utilities_ovs_vsctl_LDADD = lib/libopenvswitch.la

if LINUX
sbin_PROGRAMS += utilities/ovs-vlan-bug-workaround
utilities_ovs_vlan_bug_workaround_SOURCES = utilities/ovs-vlan-bug-workaround.c
utilities_ovs_vlan_bug_workaround_LDADD = lib/libopenvswitch.la

noinst_PROGRAMS += utilities/nlmon
utilities_nlmon_SOURCES = utilities/nlmon.c
utilities_nlmon_LDADD = lib/libopenvswitch.la
endif

FLAKE8_PYFILES += utilities/ovs-pcap.in \
	utilities/checkpatch.py utilities/ovs-dev.py \
	utilities/ovs-tcpdump.in \
	utilities/ovs-pipegen.py

include utilities/bugtool/automake.mk
