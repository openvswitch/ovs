sbin_PROGRAMS += vswitchd/ovs-vswitchd vswitchd/ovs-brcompatd
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
	lib/libopenvswitch.a \
	$(SSL_LIBS)

vswitchd_ovs_brcompatd_SOURCES = \
	vswitchd/ovs-brcompatd.c \
	vswitchd/vswitch-idl.c \
	vswitchd/vswitch-idl.h

vswitchd_ovs_brcompatd_LDADD = lib/libopenvswitch.a $(SSL_LIBS)

EXTRA_DIST += \
	vswitchd/ovs-vswitchd.8.in \
	vswitchd/ovs-brcompatd.8.in


# vswitch schema and IDL
OVSIDL_BUILT += \
	vswitchd/vswitch-idl.c \
	vswitchd/vswitch-idl.h \
	vswitchd/vswitch-idl.ovsidl
VSWITCH_IDL_FILES = vswitchd/vswitch.ovsschema vswitchd/vswitch-idl.ann
noinst_DATA += vswitchd/vswitch-idl.txt
EXTRA_DIST += $(VSWITCH_IDL_FILES) vswitchd/vswitch-idl.txt
vswitchd/vswitch-idl.ovsidl: $(VSWITCH_IDL_FILES)
	$(OVSDB_IDLC) -C $(srcdir) annotate $(VSWITCH_IDL_FILES) > $@.tmp
	mv $@.tmp $@
