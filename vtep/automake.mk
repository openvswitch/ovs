# vtep IDL
OVSIDL_BUILT += \
	vtep/vtep-idl.c \
	vtep/vtep-idl.h \
	vtep/vtep-idl.ovsidl
EXTRA_DIST += vtep/vtep-idl.ann
VTEP_IDL_FILES = \
	$(srcdir)/vtep/vtep.ovsschema \
	$(srcdir)/vtep/vtep-idl.ann
vtep/vtep-idl.ovsidl: $(VTEP_IDL_FILES)
	$(AM_V_GEN)$(OVSDB_IDLC) annotate $(VTEP_IDL_FILES) > $@.tmp && \
	mv $@.tmp $@

# libvtep
lib_LTLIBRARIES += vtep/libvtep.la
vtep_libvtep_la_LDFLAGS = \
	$(OVS_LTINFO) \
	-Wl,--version-script=$(top_builddir)/vtep/libvtep.sym \
	$(AM_LDFLAGS)
nodist_vtep_libvtep_la_SOURCES = \
	vtep/vtep-idl.c \
	vtep/vtep-idl.h

bin_PROGRAMS += \
   vtep/vtep-ctl

MAN_ROOTS += \
   vtep/vtep-ctl.8.in

CLEANFILES += \
   vtep/vtep-ctl.8

man_MANS += \
   vtep/vtep-ctl.8

vtep_vtep_ctl_SOURCES = vtep/vtep-ctl.c
vtep_vtep_ctl_LDADD = vtep/libvtep.la lib/libopenvswitch.la

# ovs-vtep
scripts_SCRIPTS += \
    vtep/ovs-vtep

EXTRA_DIST += vtep/ovs-vtep.in
CLEANFILES += vtep/ovs-vtep

FLAKE8_PYFILES += vtep/ovs-vtep

# VTEP schema and IDL
EXTRA_DIST += vtep/vtep.ovsschema
pkgdata_DATA += vtep/vtep.ovsschema

# VTEP E-R diagram
#
# If "python" or "dot" is not available, then we do not add graphical diagram
# to the documentation.
if HAVE_PYTHON
if HAVE_DOT
vtep/vtep.gv: ovsdb/ovsdb-dot.in vtep/vtep.ovsschema
	$(AM_V_GEN)$(OVSDB_DOT) --no-arrows $(srcdir)/vtep/vtep.ovsschema > $@
vtep/vtep.pic: vtep/vtep.gv ovsdb/dot2pic
	$(AM_V_GEN)(dot -T plain < vtep/vtep.gv | $(PERL) $(srcdir)/ovsdb/dot2pic -f 3) > $@.tmp && \
	mv $@.tmp $@
VTEP_PIC = vtep/vtep.pic
VTEP_DOT_DIAGRAM_ARG = --er-diagram=$(VTEP_PIC)
CLEANFILES += vtep/vtep.gv vtep/vtep.pic
endif
endif

# VTEP schema documentation
EXTRA_DIST += vtep/vtep.xml
CLEANFILES += vtep/vtep.5
man_MANS += vtep/vtep.5
vtep/vtep.5: \
	ovsdb/ovsdb-doc vtep/vtep.xml $(srcdir)/vtep/vtep.ovsschema $(VTEP_PIC)
	$(AM_V_GEN)$(OVSDB_DOC) \
		$(VTEP_DOT_DIAGRAM_ARG) \
		--version=$(VERSION) \
		$(srcdir)/vtep/vtep.ovsschema \
		$(srcdir)/vtep/vtep.xml > $@.tmp && \
	mv $@.tmp $@

# Version checking for vtep.ovsschema.
ALL_LOCAL += vtep/vtep.ovsschema.stamp
vtep/vtep.ovsschema.stamp: vtep/vtep.ovsschema
	$(srcdir)/build-aux/cksum-schema-check $? $@
CLEANFILES += vtep/vtep.ovsschema.stamp
