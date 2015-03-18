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
CLEANFILES += vtep/vtep-idl.c vtep/vtep-idl.h

# libvtep
lib_LTLIBRARIES += vtep/libvtep.la
vtep_libvtep_la_LDFLAGS = \
	-version-info $(LT_CURRENT):$(LT_REVISION):$(LT_AGE) \
	-Wl,--version-script=$(top_builddir)/vtep/libvtep.sym \
	$(AM_LDFLAGS)
vtep_libvtep_la_SOURCES = \
	vtep/vtep-idl.c \
	vtep/vtep-idl.h

bin_PROGRAMS += \
   vtep/vtep-ctl

MAN_ROOTS += \
   vtep/vtep-ctl.8.in

DISTCLEANFILES += \
   vtep/vtep-ctl.8

man_MANS += \
   vtep/vtep-ctl.8

vtep_vtep_ctl_SOURCES = vtep/vtep-ctl.c
vtep_vtep_ctl_LDADD = vtep/libvtep.la lib/libopenvswitch.la

# ovs-vtep
scripts_SCRIPTS += \
    vtep/ovs-vtep

docs += vtep/README.ovs-vtep.md
EXTRA_DIST += vtep/ovs-vtep

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
DISTCLEANFILES += vtep/vtep.gv vtep/vtep.pic
endif
endif

# VTEP schema documentation
EXTRA_DIST += vtep/vtep.xml
DISTCLEANFILES += vtep/vtep.5
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
	@sum=`sed '/cksum/d' $? | cksum`; \
	expected=`sed -n 's/.*"cksum": "\(.*\)".*/\1/p' $?`; \
	if test "X$$sum" = "X$$expected"; then \
	  touch $@; \
	else \
	  ln=`sed -n '/"cksum":/=' $?`; \
	  echo >&2 "$?:$$ln: The checksum \"$$sum\" was calculated from the schema file and does not match cksum field in the schema file - you should probably update the version number and the checksum in the schema file with the value listed here."; \
	  exit 1; \
	fi
CLEANFILES += vtep/vtep.ovsschema.stamp
