sbin_PROGRAMS += vswitchd/ovs-vswitchd
man_MANS += vswitchd/ovs-vswitchd.8
if BUILD_BRCOMPAT
  man_MANS += vswitchd/ovs-brcompatd.8
endif
DISTCLEANFILES += \
	vswitchd/ovs-vswitchd.8 \
	vswitchd/ovs-brcompatd.8

vswitchd_ovs_vswitchd_SOURCES = \
	vswitchd/bridge.c \
	vswitchd/bridge.h \
	vswitchd/ovs-vswitchd.c \
	vswitchd/system-stats.c \
	vswitchd/system-stats.h \
	vswitchd/xenserver.c \
	vswitchd/xenserver.h
vswitchd_ovs_vswitchd_LDADD = \
	ofproto/libofproto.a \
	lib/libsflow.a \
	lib/libopenvswitch.a \
	$(SSL_LIBS)
EXTRA_DIST += vswitchd/INTERNALS
MAN_ROOTS += vswitchd/ovs-vswitchd.8.in

if BUILD_BRCOMPAT
if LINUX_DATAPATH
sbin_PROGRAMS += vswitchd/ovs-brcompatd
vswitchd_ovs_brcompatd_SOURCES = \
	vswitchd/ovs-brcompatd.c
vswitchd_ovs_brcompatd_LDADD = lib/libopenvswitch.a $(SSL_LIBS)
endif
MAN_ROOTS += vswitchd/ovs-brcompatd.8.in
endif

# vswitch schema and IDL
EXTRA_DIST += vswitchd/vswitch.ovsschema
pkgdata_DATA += vswitchd/vswitch.ovsschema

# vswitch E-R diagram
#
# There are two complications here.  First, if "python" or "dot" is not
# available, then we have to just use the existing diagram.  Second, different
# "dot" versions produce slightly different output for the same input, but we
# don't want to gratuitously change vswitch.pic if someone tweaks the schema in
# some minor way that doesn't affect the table structure.  To avoid that we
# store a checksum of vswitch.gv in vswitch.pic and only regenerate vswitch.pic
# if vswitch.gv actually changes.
$(srcdir)/vswitchd/vswitch.gv: ovsdb/ovsdb-dot.in vswitchd/vswitch.ovsschema
if HAVE_PYTHON
	$(OVSDB_DOT) $(srcdir)/vswitchd/vswitch.ovsschema > $@
else
	touch $@
endif
$(srcdir)/vswitchd/vswitch.pic: $(srcdir)/vswitchd/vswitch.gv ovsdb/dot2pic
if HAVE_DOT
	sum=`cksum < $(srcdir)/vswitchd/vswitch.gv`;			\
	if grep "$$sum" $@ >/dev/null 2>&1; then			\
	  echo "vswitch.gv unchanged, not regenerating vswitch.pic";	\
	  touch $@;							\
	else								\
	  echo "regenerating vswitch.pic";				\
	  (echo ".\\\" Generated from vswitch.gv with cksum \"$$sum\"";	\
	   dot -T plain < $(srcdir)/vswitchd/vswitch.gv			\
	    | $(srcdir)/ovsdb/dot2pic) > $@;				\
	fi
else
	touch $@
endif
EXTRA_DIST += vswitchd/vswitch.gv vswitchd/vswitch.pic

# vswitch schema documentation
EXTRA_DIST += vswitchd/vswitch.xml
dist_man_MANS += vswitchd/ovs-vswitchd.conf.db.5
$(srcdir)/vswitchd/ovs-vswitchd.conf.db.5: \
	ovsdb/ovsdb-doc.in vswitchd/vswitch.xml vswitchd/vswitch.ovsschema \
	$(srcdir)/vswitchd/vswitch.pic
	$(OVSDB_DOC) \
		--title="ovs-vswitchd.conf.db" \
		--er-diagram=$(srcdir)/vswitchd/vswitch.pic \
		$(srcdir)/vswitchd/vswitch.ovsschema \
		$(srcdir)/vswitchd/vswitch.xml > $@.tmp
	mv $@.tmp $@

# Version checking for vswitch.ovsschema.
ALL_LOCAL += vswitchd/vswitch.ovsschema.stamp
vswitchd/vswitch.ovsschema.stamp: vswitchd/vswitch.ovsschema
	@sum=`sed '/cksum/d' $? | cksum`; \
	expected=`sed -n 's/.*"cksum": "\(.*\)".*/\1/p' $?`; \
	if test "X$$sum" = "X$$expected"; then \
	  touch $@; \
	else \
	  ln=`sed -n '/"cksum":/=' $?`; \
	  echo >&2 "$?:$$ln: checksum \"$$sum\" does not match (you should probably update the version number and fix the checksum)"; \
	  exit 1; \
	fi
CLEANFILES += vswitchd/vswitch.ovsschema.stamp

# Clean up generated files from older OVS versions.  (This is important so that
# #include "vswitch-idl.h" doesn't get the wrong copy.)
CLEANFILES += vswitchd/vswitch-idl.c vswitchd/vswitch-idl.h
