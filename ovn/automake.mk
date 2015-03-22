# OVN schema and IDL
EXTRA_DIST += ovn/ovn.ovsschema
pkgdata_DATA += ovn/ovn.ovsschema

# OVN E-R diagram
#
# If "python" or "dot" is not available, then we do not add graphical diagram
# to the documentation.
if HAVE_PYTHON
if HAVE_DOT
ovn/ovn.gv: ovsdb/ovsdb-dot.in ovn/ovn.ovsschema
	$(AM_V_GEN)$(OVSDB_DOT) --no-arrows $(srcdir)/ovn/ovn.ovsschema > $@
ovn/ovn.pic: ovn/ovn.gv ovsdb/dot2pic
	$(AM_V_GEN)(dot -T plain < ovn/ovn.gv | $(PERL) $(srcdir)/ovsdb/dot2pic -f 3) > $@.tmp && \
	mv $@.tmp $@
OVN_PIC = ovn/ovn.pic
OVN_DOT_DIAGRAM_ARG = --er-diagram=$(OVN_PIC)
DISTCLEANFILES += ovn/ovn.gv ovn/ovn.pic
endif
endif

# OVN schema documentation
EXTRA_DIST += ovn/ovn.xml
DISTCLEANFILES += ovn/ovn.5
man_MANS += ovn/ovn.5
ovn/ovn.5: \
	ovsdb/ovsdb-doc ovn/ovn.xml ovn/ovn.ovsschema $(OVN_PIC)
	$(AM_V_GEN)$(OVSDB_DOC) \
		$(OVN_DOT_DIAGRAM_ARG) \
		--version=$(VERSION) \
		$(srcdir)/ovn/ovn.ovsschema \
		$(srcdir)/ovn/ovn.xml > $@.tmp && \
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

man_MANS += ovn/ovn-controller.8 ovn/ovn-architecture.7 ovn/ovn-nbctl.8
EXTRA_DIST += ovn/ovn-controller.8.in ovn/ovn-architecture.7.xml ovn/ovn-nbctl.8.xml

SUFFIXES += .xml
%: %.xml
	$(AM_V_GEN)$(run_python) $(srcdir)/build-aux/xml2nroff \
		--version=$(VERSION) $< > $@.tmp && mv $@.tmp $@

EXTRA_DIST += ovn/TODO

# ovn IDL
OVSIDL_BUILT += \
	$(srcdir)/ovn/ovn-idl.c \
	$(srcdir)/ovn/ovn-idl.h \
	$(srcdir)/ovn/ovn.ovsidl
EXTRA_DIST += $(srcdir)/ovn/ovn-idl.ann
OVN_IDL_FILES = \
	$(srcdir)/ovn/ovn.ovsschema \
	$(srcdir)/ovn/ovn-idl.ann
$(srcdir)/ovn/ovn-idl.ovsidl: $(OVN_IDL_FILES)
	$(AM_V_GEN)$(OVSDB_IDLC) annotate $(OVN_IDL_FILES) > $@.tmp && \
	mv $@.tmp $@
CLEANFILES += ovn/ovn-idl.c ovn/ovn-idl.h

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
	ovn/ovn-idl.c \
	ovn/ovn-idl.h \
	ovn/ovn-nb-idl.c \
	ovn/ovn-nb-idl.h

bin_PROGRAMS += ovn/ovn-nbctl
ovn_ovn_nbctl_SOURCES = ovn/ovn-nbctl.c
ovn_ovn_nbctl_LDADD = ovn/libovn.la ovsdb/libovsdb.la lib/libopenvswitch.la
