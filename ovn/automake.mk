# OVN southbound schema and IDL
EXTRA_DIST += ovn/ovn-sb.ovsschema
pkgdata_DATA += ovn/ovn-sb.ovsschema

# OVN southbound E-R diagram
#
# If "python" or "dot" is not available, then we do not add graphical diagram
# to the documentation.
if HAVE_PYTHON
if HAVE_DOT
ovn/ovn-sb.gv: ovsdb/ovsdb-dot.in ovn/ovn-sb.ovsschema
	$(AM_V_GEN)$(OVSDB_DOT) --no-arrows $(srcdir)/ovn/ovn-sb.ovsschema > $@
ovn/ovn-sb.pic: ovn/ovn-sb.gv ovsdb/dot2pic
	$(AM_V_GEN)(dot -T plain < ovn/ovn-sb.gv | $(PERL) $(srcdir)/ovsdb/dot2pic -f 3) > $@.tmp && \
	mv $@.tmp $@
OVN_SB_PIC = ovn/ovn-sb.pic
OVN_SB_DOT_DIAGRAM_ARG = --er-diagram=$(OVN_SB_PIC)
DISTCLEANFILES += ovn/ovn-sb.gv ovn/ovn-sb.pic
endif
endif

# OVN southbound schema documentation
EXTRA_DIST += ovn/ovn-sb.xml
DISTCLEANFILES += ovn/ovn-sb.5
man_MANS += ovn/ovn-sb.5
ovn/ovn-sb.5: \
	ovsdb/ovsdb-doc ovn/ovn-sb.xml ovn/ovn-sb.ovsschema $(OVN_SB_PIC)
	$(AM_V_GEN)$(OVSDB_DOC) \
		$(OVN_SB_DOT_DIAGRAM_ARG) \
		--version=$(VERSION) \
		$(srcdir)/ovn/ovn-sb.ovsschema \
		$(srcdir)/ovn/ovn-sb.xml > $@.tmp && \
	mv $@.tmp $@

# OVN northbound schema and IDL
EXTRA_DIST += ovn/ovn-nb.ovsschema
pkgdata_DATA += ovn/ovn-nb.ovsschema

# OVN northbound E-R diagram
#
# If "python" or "dot" is not available, then we do not add graphical diagram
# to the documentation.
if HAVE_PYTHON
if HAVE_DOT
ovn/ovn-nb.gv: ovsdb/ovsdb-dot.in ovn/ovn-nb.ovsschema
	$(AM_V_GEN)$(OVSDB_DOT) --no-arrows $(srcdir)/ovn/ovn-nb.ovsschema > $@
ovn/ovn-nb.pic: ovn/ovn-nb.gv ovsdb/dot2pic
	$(AM_V_GEN)(dot -T plain < ovn/ovn-nb.gv | $(PERL) $(srcdir)/ovsdb/dot2pic -f 3) > $@.tmp && \
	mv $@.tmp $@
OVN_NB_PIC = ovn/ovn-nb.pic
OVN_NB_DOT_DIAGRAM_ARG = --er-diagram=$(OVN_NB_PIC)
DISTCLEANFILES += ovn/ovn-nb.gv ovn/ovn-nb.pic
endif
endif

# OVN northbound schema documentation
EXTRA_DIST += ovn/ovn-nb.xml
DISTCLEANFILES += ovn/ovn-nb.5
man_MANS += ovn/ovn-nb.5
ovn/ovn-nb.5: \
	ovsdb/ovsdb-doc ovn/ovn-nb.xml ovn/ovn-nb.ovsschema $(OVN_NB_PIC)
	$(AM_V_GEN)$(OVSDB_DOC) \
		$(OVN_NB_DOT_DIAGRAM_ARG) \
		--version=$(VERSION) \
		$(srcdir)/ovn/ovn-nb.ovsschema \
		$(srcdir)/ovn/ovn-nb.xml > $@.tmp && \
	mv $@.tmp $@

man_MANS += ovn/ovn-architecture.7 ovn/ovn-nbctl.8
EXTRA_DIST += ovn/ovn-architecture.7.xml ovn/ovn-nbctl.8.xml
DISTCLEANFILES += ovn/ovn-nbctl.8 ovn/ovn-architecture.7

SUFFIXES += .xml
%: %.xml
	$(AM_V_GEN)$(run_python) $(srcdir)/build-aux/xml2nroff $< > $@.tmp \
		--version=$(VERSION) \
		PKIDIR='$(PKIDIR)' \
		LOGDIR='$(LOGDIR)' \
		DBDIR='$(DBDIR)' \
		PERL='$(PERL)' \
		PYTHON='$(PYTHON)' \
		RUNDIR='$(RUNDIR)' \
		VERSION='$(VERSION)' \
		localstatedir='$(localstatedir)' \
		pkgdatadir='$(pkgdatadir)' \
		sysconfdir='$(sysconfdir)' \
		bindir='$(bindir)' \
		sbindir='$(sbindir)'
	$(AM_v_at)mv $@.tmp $@

EXTRA_DIST += \
	ovn/TODO \
	ovn/CONTAINERS.OpenStack.md

# ovn-nbctl
bin_PROGRAMS += ovn/ovn-nbctl
ovn_ovn_nbctl_SOURCES = ovn/ovn-nbctl.c
ovn_ovn_nbctl_LDADD = ovn/lib/libovn.la ovsdb/libovsdb.la lib/libopenvswitch.la

include ovn/controller/automake.mk
include ovn/lib/automake.mk
include ovn/northd/automake.mk
include ovn/utilities/automake.mk
