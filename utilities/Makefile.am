include ../Make.vars

bin_PROGRAMS = vlogconf dpctl ofp-discover ofp-kill
bin_SCRIPTS = ofp-pki
noinst_SCRIPTS = ofp-pki-cgi

EXTRA_DIST = ofp-pki.in ofp-pki-cgi.in ofp-pki.8.in ofp-discover.8.in	\
ofp-kill.8.in
DISTCLEANFILES = ofp-pki ofp-pki-cgi ofp-pki.8 ofp-discover.8 ofp-kill.8

dist_man_MANS = vlogconf.8 dpctl.8
man_MANS = ofp-pki.8 ofp-discover.8 ofp-kill.8

dpctl_SOURCES = dpctl.c
dpctl_LDADD = ../lib/libopenflow.a $(FAULT_LIBS) $(SSL_LIBS)

vlogconf_SOURCES = vlogconf.c
vlogconf_LDADD = ../lib/libopenflow.a

ofp_discover_SOURCES = ofp-discover.c
ofp_discover_LDADD = ../lib/libopenflow.a

ofp_kill_SOURCES = ofp-kill.c
ofp_kill_LDADD = ../lib/libopenflow.a

pkidir = $(pkgdatadir)/pki

ofp-pki: ofp-pki.in Makefile
	$(do_subst) < $(srcdir)/ofp-pki.in | $(ro_script) > ofp-pki
	chmod +x ofp-pki
ofp-pki-cgi: ofp-pki-cgi.in Makefile
	$(do_subst) < $(srcdir)/ofp-pki-cgi.in | $(ro_script) > ofp-pki-cgi
	chmod +x ofp-pki-cgi
ofp-pki.8: ofp-pki.8.in Makefile
	($(do_subst) && $(ro_man)) < $(srcdir)/ofp-pki.8.in > ofp-pki.8
ofp-discover.8: ofp-discover.8.in Makefile
	($(do_subst) && $(ro_man)) < $(srcdir)/ofp-discover.8.in > ofp-discover.8
ofp-kill.8: ofp-kill.8.in Makefile
	($(do_subst) && $(ro_man)) < $(srcdir)/ofp-kill.8.in > ofp-kill.8
