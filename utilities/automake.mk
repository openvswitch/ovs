bin_PROGRAMS += \
	utilities/vlogconf \
	utilities/dpctl \
	utilities/ofp-discover \
	utilities/ofp-kill
bin_SCRIPTS += utilities/ofp-pki
noinst_SCRIPTS += utilities/ofp-pki-cgi

EXTRA_DIST += \
	utilities/dpctl.8.in \
	utilities/ofp-discover.8.in \
	utilities/ofp-kill.8.in \
	utilities/ofp-pki-cgi.in \
	utilities/ofp-pki.8.in \
	utilities/ofp-pki.in \
	utilities/vlogconf.8.in
DISTCLEANFILES += \
	utilities/dpctl.8 \
	utilities/ofp-discover.8 \
	utilities/ofp-kill.8 \
	utilities/ofp-pki \
	utilities/ofp-pki.8 \
	utilities/ofp-pki-cgi \
	utilities/vlogconf.8

man_MANS += \
	utilities/dpctl.8 \
	utilities/ofp-discover.8 \
	utilities/ofp-kill.8 \
	utilities/ofp-pki.8 \
	utilities/vlogconf.8

utilities_dpctl_SOURCES = utilities/dpctl.c
utilities_dpctl_LDADD = lib/libopenflow.a $(FAULT_LIBS) $(SSL_LIBS)

utilities_vlogconf_SOURCES = utilities/vlogconf.c
utilities_vlogconf_LDADD = lib/libopenflow.a

utilities_ofp_discover_SOURCES = utilities/ofp-discover.c
utilities_ofp_discover_LDADD = lib/libopenflow.a

utilities_ofp_kill_SOURCES = utilities/ofp-kill.c
utilities_ofp_kill_LDADD = lib/libopenflow.a
