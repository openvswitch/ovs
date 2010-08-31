bin_PROGRAMS += \
	utilities/ovs-appctl \
	utilities/ovs-controller \
	utilities/ovs-discover \
	utilities/ovs-dpctl \
	utilities/ovs-kill \
	utilities/ovs-ofctl \
	utilities/ovs-openflowd \
	utilities/ovs-vsctl
bin_SCRIPTS += utilities/ovs-pki utilities/ovs-vsctl
noinst_SCRIPTS += utilities/ovs-pki-cgi utilities/ovs-parse-leaks

EXTRA_DIST += \
	utilities/ovs-appctl.8.in \
	utilities/ovs-controller.8.in \
	utilities/ovs-discover.8.in \
	utilities/ovs-dpctl.8.in \
	utilities/ovs-kill.8.in \
	utilities/ovs-ofctl.8.in \
	utilities/ovs-openflowd.8.in \
	utilities/ovs-parse-leaks.8 \
	utilities/ovs-parse-leaks.in \
	utilities/ovs-pki-cgi.in \
	utilities/ovs-pki.8.in \
	utilities/ovs-pki.in \
	utilities/ovs-vsctl.8.in
DISTCLEANFILES += \
	utilities/ovs-appctl.8 \
	utilities/ovs-controller.8 \
	utilities/ovs-discover.8 \
	utilities/ovs-dpctl.8 \
	utilities/ovs-kill.8 \
	utilities/ovs-ofctl.8 \
	utilities/ovs-openflowd.8 \
	utilities/ovs-parse-leaks \
	utilities/ovs-pki \
	utilities/ovs-pki-cgi \
	utilities/ovs-pki.8 \
	utilities/ovs-vsctl.8

man_MANS += \
	utilities/ovs-appctl.8 \
	utilities/ovs-controller.8 \
	utilities/ovs-discover.8 \
	utilities/ovs-dpctl.8 \
	utilities/ovs-kill.8 \
	utilities/ovs-ofctl.8 \
	utilities/ovs-openflowd.8 \
	utilities/ovs-parse-leaks.8 \
	utilities/ovs-pki.8 \
	utilities/ovs-vsctl.8

utilities_ovs_appctl_SOURCES = utilities/ovs-appctl.c
utilities_ovs_appctl_LDADD = lib/libopenvswitch.a

utilities_ovs_controller_SOURCES = utilities/ovs-controller.c
utilities_ovs_controller_LDADD = lib/libopenvswitch.a $(SSL_LIBS)

utilities_ovs_discover_SOURCES = utilities/ovs-discover.c
utilities_ovs_discover_LDADD = lib/libopenvswitch.a

utilities_ovs_dpctl_SOURCES = utilities/ovs-dpctl.c
utilities_ovs_dpctl_LDADD = lib/libopenvswitch.a

utilities_ovs_kill_SOURCES = utilities/ovs-kill.c
utilities_ovs_kill_LDADD = lib/libopenvswitch.a

utilities_ovs_ofctl_SOURCES = utilities/ovs-ofctl.c
utilities_ovs_ofctl_LDADD = lib/libopenvswitch.a $(SSL_LIBS)

utilities_ovs_openflowd_SOURCES = utilities/ovs-openflowd.c
utilities_ovs_openflowd_LDADD = \
	ofproto/libofproto.a \
	lib/libsflow.a \
	lib/libopenvswitch.a \
	$(SSL_LIBS)

utilities_ovs_vsctl_SOURCES = utilities/ovs-vsctl.c vswitchd/vswitch-idl.c
utilities_ovs_vsctl_LDADD = lib/libopenvswitch.a $(SSL_LIBS)

if HAVE_NETLINK
noinst_PROGRAMS += utilities/nlmon
utilities_nlmon_SOURCES = utilities/nlmon.c
utilities_nlmon_LDADD = lib/libopenvswitch.a
endif
