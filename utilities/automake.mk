bin_PROGRAMS += \
	utilities/ovs-appctl \
	utilities/ovs-cfg-mod \
	utilities/ovs-controller \
	utilities/ovs-discover \
	utilities/ovs-dpctl \
	utilities/ovs-kill \
	utilities/ovs-ofctl \
	utilities/ovs-openflowd \
	utilities/ovs-wdt
noinst_PROGRAMS += utilities/nlmon
bin_SCRIPTS += utilities/ovs-pki utilities/ovs-vsctl
noinst_SCRIPTS += utilities/ovs-pki-cgi utilities/ovs-parse-leaks
dist_sbin_SCRIPTS += utilities/ovs-monitor 

EXTRA_DIST += \
	utilities/ovs-appctl.8.in \
	utilities/ovs-cfg-mod.8.in \
	utilities/ovs-controller.8.in \
	utilities/ovs-discover.8.in \
	utilities/ovs-dpctl.8.in \
	utilities/ovs-kill.8.in \
	utilities/ovs-ofctl.8.in \
	utilities/ovs-openflowd.8.in \
	utilities/ovs-parse-leaks.in \
	utilities/ovs-pki-cgi.in \
	utilities/ovs-pki.8.in \
	utilities/ovs-pki.in \
	utilities/ovs-vsctl.8.in \
	utilities/ovs-vsctl.in
DISTCLEANFILES += \
	utilities/ovs-appctl.8 \
	utilities/ovs-cfg-mod.8 \
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
	utilities/ovs-vsctl \
	utilities/ovs-vsctl.8

man_MANS += \
	utilities/ovs-appctl.8 \
	utilities/ovs-cfg-mod.8 \
	utilities/ovs-controller.8 \
	utilities/ovs-discover.8 \
	utilities/ovs-dpctl.8 \
	utilities/ovs-kill.8 \
	utilities/ovs-ofctl.8 \
	utilities/ovs-openflowd.8 \
	utilities/ovs-pki.8 \
	utilities/ovs-vsctl.8

utilities_ovs_appctl_SOURCES = utilities/ovs-appctl.c
utilities_ovs_appctl_LDADD = lib/libopenvswitch.a

utilities_ovs_cfg_mod_SOURCES = utilities/ovs-cfg-mod.c
utilities_ovs_cfg_mod_LDADD = lib/libopenvswitch.a

utilities_ovs_controller_SOURCES = utilities/ovs-controller.c
utilities_ovs_controller_LDADD = lib/libopenvswitch.a $(FAULT_LIBS) $(SSL_LIBS)

utilities_ovs_discover_SOURCES = utilities/ovs-discover.c
utilities_ovs_discover_LDADD = lib/libopenvswitch.a

utilities_ovs_dpctl_SOURCES = utilities/ovs-dpctl.c
utilities_ovs_dpctl_LDADD = lib/libopenvswitch.a $(FAULT_LIBS)

utilities_ovs_kill_SOURCES = utilities/ovs-kill.c
utilities_ovs_kill_LDADD = lib/libopenvswitch.a

utilities_ovs_ofctl_SOURCES = utilities/ovs-ofctl.c
utilities_ovs_ofctl_LDADD = lib/libopenvswitch.a $(FAULT_LIBS) $(SSL_LIBS)

utilities_ovs_openflowd_SOURCES = utilities/ovs-openflowd.c
utilities_ovs_openflowd_LDADD = \
	ofproto/libofproto.a \
	lib/libopenvswitch.a \
	$(FAULT_LIBS) \
	$(SSL_LIBS)

utilities_ovs_wdt_SOURCES = utilities/ovs-wdt.c

utilities_nlmon_SOURCES = utilities/nlmon.c
utilities_nlmon_LDADD = lib/libopenvswitch.a
