sbin_PROGRAMS += vswitchd/ovs-vswitchd
man_MANS += \
	vswitchd/ovs-vswitchd.8 \
	vswitchd/ovs-brcompatd.8
DISTCLEANFILES += \
	vswitchd/ovs-vswitchd.8 \
	vswitchd/ovs-brcompatd.8

vswitchd_ovs_vswitchd_SOURCES = \
	vswitchd/bridge.c \
	vswitchd/bridge.h \
	vswitchd/proc-net-compat.c \
	vswitchd/proc-net-compat.h \
	vswitchd/ovs-vswitchd.c \
	vswitchd/vswitch-idl.c \
	vswitchd/vswitch-idl.h \
	vswitchd/xenserver.c \
	vswitchd/xenserver.h
vswitchd_ovs_vswitchd_LDADD = \
	ofproto/libofproto.a \
	lib/libsflow.a \
	lib/libopenvswitch.a \
	$(SSL_LIBS)
EXTRA_DIST += \
	vswitchd/ovs-vswitchd.8.in \
	vswitchd/INTERNALS

if HAVE_NETLINK
sbin_PROGRAMS += vswitchd/ovs-brcompatd
vswitchd_ovs_brcompatd_SOURCES = \
	vswitchd/ovs-brcompatd.c \
	vswitchd/vswitch-idl.c \
	vswitchd/vswitch-idl.h
vswitchd_ovs_brcompatd_LDADD = lib/libopenvswitch.a $(SSL_LIBS)
endif
EXTRA_DIST += vswitchd/ovs-brcompatd.8.in

# vswitch schema and IDL
OVSIDL_BUILT += \
	vswitchd/vswitch-idl.c \
	vswitchd/vswitch-idl.h \
	vswitchd/vswitch-idl.ovsidl
VSWITCH_IDL_FILES = vswitchd/vswitch.ovsschema vswitchd/vswitch-idl.ann
EXTRA_DIST += $(VSWITCH_IDL_FILES)
vswitchd/vswitch-idl.ovsidl: $(VSWITCH_IDL_FILES)
	$(OVSDB_IDLC) -C $(srcdir) annotate $(VSWITCH_IDL_FILES) > $@.tmp
	mv $@.tmp $@

# vswitch schema documentation
EXTRA_DIST += vswitchd/vswitch.xml
dist_man_MANS += vswitchd/ovs-vswitchd.conf.db.5
vswitchd/ovs-vswitchd.conf.db.5: \
	ovsdb/ovsdb-doc.in vswitchd/vswitch.xml vswitchd/vswitch.ovsschema
	$(OVSDB_DOC) \
		--title="ovs-vswitchd.conf.db" \
		$(srcdir)/vswitchd/vswitch.ovsschema \
		$(srcdir)/vswitchd/vswitch.xml > $@.tmp
	mv $@.tmp $@
