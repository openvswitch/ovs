bin_PROGRAMS += \
	utilities/ovs-appctl \
	utilities/ovs-controller \
	utilities/ovs-dpctl \
	utilities/ovs-ofctl \
	utilities/ovs-vsctl
bin_SCRIPTS += utilities/ovs-pki utilities/ovs-vsctl utilities/ovs-parse-leaks
if HAVE_PYTHON
bin_SCRIPTS += \
	utilities/ovs-pcap \
	utilities/ovs-tcpundump \
	utilities/ovs-vlan-test
endif
noinst_SCRIPTS += utilities/ovs-pki-cgi
scripts_SCRIPTS += utilities/ovs-ctl utilities/ovs-lib.sh utilities/ovs-save

EXTRA_DIST += \
	utilities/ovs-appctl.8.in \
	utilities/ovs-benchmark.1.in \
	utilities/ovs-controller.8.in \
	utilities/ovs-ctl.in \
	utilities/ovs-dpctl.8.in \
	utilities/ovs-lib.sh.in \
	utilities/ovs-ofctl.8.in \
	utilities/ovs-parse-leaks.8 \
	utilities/ovs-parse-leaks.in \
	utilities/ovs-pcap.1.in \
	utilities/ovs-pcap.in \
	utilities/ovs-pki-cgi.in \
	utilities/ovs-pki.8.in \
	utilities/ovs-pki.in \
	utilities/ovs-save \
	utilities/ovs-tcpundump.1.in \
	utilities/ovs-tcpundump.in \
	utilities/ovs-vlan-bugs.man \
	utilities/ovs-vlan-test.in \
	utilities/ovs-vlan-bug-workaround.8.in \
	utilities/ovs-vlan-test.8.in \
	utilities/ovs-vsctl.8.in
DISTCLEANFILES += \
	utilities/ovs-appctl.8 \
	utilities/ovs-ctl \
	utilities/ovs-benchmark.1 \
	utilities/ovs-controller.8 \
	utilities/ovs-dpctl.8 \
	utilities/ovs-lib.sh \
	utilities/ovs-ofctl.8 \
	utilities/ovs-parse-leaks \
	utilities/ovs-pcap \
	utilities/ovs-pcap.1 \
	utilities/ovs-pki \
	utilities/ovs-pki-cgi \
	utilities/ovs-pki.8 \
	utilities/ovs-tcpundump \
	utilities/ovs-tcpundump.1 \
	utilities/ovs-vlan-test \
	utilities/ovs-vlan-test.8 \
	utilities/ovs-vlan-bug-workaround.8 \
	utilities/ovs-vsctl.8

man_MANS += \
	utilities/ovs-appctl.8 \
	utilities/ovs-benchmark.1 \
	utilities/ovs-controller.8 \
	utilities/ovs-dpctl.8 \
	utilities/ovs-ofctl.8 \
	utilities/ovs-parse-leaks.8 \
	utilities/ovs-pcap.1 \
	utilities/ovs-pki.8 \
	utilities/ovs-tcpundump.1 \
	utilities/ovs-vlan-bug-workaround.8 \
	utilities/ovs-vlan-test.8 \
	utilities/ovs-vsctl.8
dist_man_MANS += utilities/ovs-ctl.8

utilities_ovs_appctl_SOURCES = utilities/ovs-appctl.c
utilities_ovs_appctl_LDADD = lib/libopenvswitch.a

utilities_ovs_controller_SOURCES = utilities/ovs-controller.c
utilities_ovs_controller_LDADD = lib/libopenvswitch.a $(SSL_LIBS)

utilities_ovs_dpctl_SOURCES = utilities/ovs-dpctl.c
utilities_ovs_dpctl_LDADD = lib/libopenvswitch.a

utilities_ovs_ofctl_SOURCES = utilities/ovs-ofctl.c
utilities_ovs_ofctl_LDADD = \
	ofproto/libofproto.a \
	lib/libopenvswitch.a \
	$(SSL_LIBS)

utilities_ovs_vsctl_SOURCES = utilities/ovs-vsctl.c vswitchd/vswitch-idl.c
utilities_ovs_vsctl_LDADD = lib/libopenvswitch.a $(SSL_LIBS)

if HAVE_NETLINK
sbin_PROGRAMS += utilities/ovs-vlan-bug-workaround
utilities_ovs_vlan_bug_workaround_SOURCES = utilities/ovs-vlan-bug-workaround.c
utilities_ovs_vlan_bug_workaround_LDADD = lib/libopenvswitch.a

noinst_PROGRAMS += utilities/nlmon
utilities_nlmon_SOURCES = utilities/nlmon.c
utilities_nlmon_LDADD = lib/libopenvswitch.a
endif

bin_PROGRAMS += utilities/ovs-benchmark
utilities_ovs_benchmark_SOURCES = utilities/ovs-benchmark.c
utilities_ovs_benchmark_LDADD = lib/libopenvswitch.a

include utilities/bugtool/automake.mk
