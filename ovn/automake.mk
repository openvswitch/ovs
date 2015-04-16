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

SUFFIXES += .xml
%: %.xml
	$(AM_V_GEN)$(run_python) $(srcdir)/build-aux/xml2nroff \
		--version=$(VERSION) $< > $@.tmp && mv $@.tmp $@

EXTRA_DIST += \
	ovn/TODO \
	ovn/CONTAINERS.OpenStack.md

# ovn-sb IDL
OVSIDL_BUILT += \
	$(srcdir)/ovn/ovn-sb-idl.c \
	$(srcdir)/ovn/ovn-sb-idl.h \
	$(srcdir)/ovn/ovn-sb.ovsidl
EXTRA_DIST += $(srcdir)/ovn/ovn-sb-idl.ann
OVN_SB_IDL_FILES = \
	$(srcdir)/ovn/ovn-sb.ovsschema \
	$(srcdir)/ovn/ovn-sb-idl.ann
$(srcdir)/ovn/ovn-sb-idl.ovsidl: $(OVN_SB_IDL_FILES)
	$(AM_V_GEN)$(OVSDB_IDLC) annotate $(OVN_SB_IDL_FILES) > $@.tmp && \
	mv $@.tmp $@
CLEANFILES += ovn/ovn-sb-idl.c ovn/ovn-sb-idl.h

# ovn-nb IDL
OVSIDL_BUILT += \
	$(srcdir)/ovn/ovn-nb-idl.c \
	$(srcdir)/ovn/ovn-nb-idl.h \
	$(srcdir)/ovn/ovn-nb.ovsidl
EXTRA_DIST += $(srcdir)/ovn/ovn-nb-idl.ann
OVN_NB_IDL_FILES = \
	$(srcdir)/ovn/ovn-nb.ovsschema \
	$(srcdir)/ovn/ovn-nb-idl.ann
$(srcdir)/ovn/ovn-nb-idl.ovsidl: $(OVN_NB_IDL_FILES)
	$(AM_V_GEN)$(OVSDB_IDLC) annotate $(OVN_NB_IDL_FILES) > $@.tmp && \
	mv $@.tmp $@
CLEANFILES += ovn/ovn-nb-idl.c ovn/ovn-nb-idl.h

# libovn
lib_LTLIBRARIES += ovn/libovn.la
ovn_libovn_la_LDFLAGS = \
        -version-info $(LT_CURRENT):$(LT_REVISION):$(LT_AGE) \
        -Wl,--version-script=$(top_builddir)/ovn/libovn.sym \
        $(AM_LDFLAGS)
ovn_libovn_la_SOURCES = \
	ovn/ovn-sb-idl.c \
	ovn/ovn-sb-idl.h \
	ovn/ovn-nb-idl.c \
	ovn/ovn-nb-idl.h

# ovn-nbctl
bin_PROGRAMS += ovn/ovn-nbctl
ovn_ovn_nbctl_SOURCES = ovn/ovn-nbctl.c
ovn_ovn_nbctl_LDADD = ovn/libovn.la ovsdb/libovsdb.la lib/libopenvswitch.la

include ovn/controller/automake.mk
include ovn/lib/automake.mk
include ovn/northd/automake.mk
