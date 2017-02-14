sbin_PROGRAMS += vswitchd/ovs-vswitchd
man_MANS += vswitchd/ovs-vswitchd.8
CLEANFILES += \
	vswitchd/ovs-vswitchd.8

vswitchd_ovs_vswitchd_SOURCES = \
	vswitchd/bridge.c \
	vswitchd/bridge.h \
	vswitchd/ovs-vswitchd.c \
	vswitchd/system-stats.c \
	vswitchd/system-stats.h \
	vswitchd/xenserver.c \
	vswitchd/xenserver.h
vswitchd_ovs_vswitchd_LDADD = \
	ofproto/libofproto.la \
	lib/libsflow.la \
	lib/libopenvswitch.la
vswitchd_ovs_vswitchd_LDFLAGS = $(AM_LDFLAGS) $(DPDK_vswitchd_LDFLAGS)
MAN_ROOTS += vswitchd/ovs-vswitchd.8.in

# vswitch schema and IDL
EXTRA_DIST += vswitchd/vswitch.ovsschema
pkgdata_DATA += vswitchd/vswitch.ovsschema

# vswitch E-R diagram
#
# If "python" or "dot" is not available, then we do not add graphical diagram
# to the documentation.
if HAVE_PYTHON
if HAVE_DOT
vswitchd/vswitch.gv: ovsdb/ovsdb-dot.in vswitchd/vswitch.ovsschema
	$(AM_V_GEN)$(OVSDB_DOT) --no-arrows $(srcdir)/vswitchd/vswitch.ovsschema > $@
vswitchd/vswitch.pic: vswitchd/vswitch.gv ovsdb/dot2pic
	$(AM_V_GEN)(dot -T plain < vswitchd/vswitch.gv | $(PERL) $(srcdir)/ovsdb/dot2pic -f 3) > $@.tmp && \
	mv $@.tmp $@
VSWITCH_PIC = vswitchd/vswitch.pic
VSWITCH_DOT_DIAGRAM_ARG = --er-diagram=$(VSWITCH_PIC)
CLEANFILES += vswitchd/vswitch.gv vswitchd/vswitch.pic
endif
endif

# vswitch schema documentation
EXTRA_DIST += vswitchd/vswitch.xml
CLEANFILES += vswitchd/ovs-vswitchd.conf.db.5
man_MANS += vswitchd/ovs-vswitchd.conf.db.5
vswitchd/ovs-vswitchd.conf.db.5: \
	ovsdb/ovsdb-doc vswitchd/vswitch.xml vswitchd/vswitch.ovsschema \
	$(VSWITCH_PIC)
	$(AM_V_GEN)$(OVSDB_DOC) \
		$(VSWITCH_DOT_DIAGRAM_ARG) \
		--version=$(VERSION) \
		$(srcdir)/vswitchd/vswitch.ovsschema \
		$(srcdir)/vswitchd/vswitch.xml > $@.tmp && \
	mv $@.tmp $@

# Version checking for vswitch.ovsschema.
ALL_LOCAL += vswitchd/vswitch.ovsschema.stamp
vswitchd/vswitch.ovsschema.stamp: vswitchd/vswitch.ovsschema
	$(srcdir)/build-aux/cksum-schema-check $? $@
CLEANFILES += vswitchd/vswitch.ovsschema.stamp

# Clean up generated files from older OVS versions.  (This is important so that
# #include "vswitch-idl.h" doesn't get the wrong copy.)
CLEANFILES += vswitchd/vswitch-idl.c vswitchd/vswitch-idl.h
