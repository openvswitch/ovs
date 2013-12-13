bin_PROGRAMS += \
   vtep/vtep-ctl

MAN_ROOTS += \
   vtep/vtep-ctl.8.in

DISTCLEANFILES += \
   vtep/vtep-ctl.8

man_MANS += \
   vtep/vtep-ctl.8

vtep_vtep_ctl_SOURCES = vtep/vtep-ctl.c
vtep_vtep_ctl_LDADD = lib/libopenvswitch.la $(SSL_LIBS)

# ovs-vtep
scripts_SCRIPTS += \
    vtep/ovs-vtep

EXTRA_DIST += \
    vtep/ovs-vtep \
    vtep/README.ovs-vtep

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
	$(OVSDB_DOT) --no-arrows $(srcdir)/vtep/vtep.ovsschema > $@
vtep/vtep.pic: vtep/vtep.gv ovsdb/dot2pic
	(dot -T plain < vtep/vtep.gv | $(srcdir)/ovsdb/dot2pic -f 3) > $@;
VTEP_PIC = vtep/vtep.pic
VTEP_DOT_DIAGRAM_ARG = --er-diagram=$(VTEP_PIC)
DISTCLEANFILES += vtep/vtep.gv vtep/vtep.pic
endif
endif

# VTEP schema documentation
EXTRA_DIST += vtep/vtep.xml
DISTCLEANFILES += vtep/vtep.5
dist_man_MANS += vtep/vtep.5
$(srcdir)/vtep/vtep.5: \
	ovsdb/ovsdb-doc vtep/vtep.xml vtep/vtep.ovsschema $(VTEP_PIC)
	$(OVSDB_DOC) \
		--title="vtep" \
		$(VTEP_DOT_DIAGRAM_ARG) \
		$(srcdir)/vtep/vtep.ovsschema \
		$(srcdir)/vtep/vtep.xml > $@.tmp
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
	  echo >&2 "$?:$$ln: checksum \"$$sum\" does not match (you should probably update the version number and fix the checksum)"; \
	  exit 1; \
	fi
CLEANFILES += vtep/vtep.ovsschema.stamp
