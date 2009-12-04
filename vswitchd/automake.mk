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
	$(FAULT_LIBS) \
	$(SSL_LIBS)

vswitchd_ovs_brcompatd_SOURCES = \
	vswitchd/ovs-brcompatd.c

vswitchd_ovs_brcompatd_LDADD = \
	lib/libopenvswitch.a \
	$(FAULT_LIBS) 

EXTRA_DIST += \
	vswitchd/ovs-vswitchd.8.in \
	vswitchd/ovs-brcompatd.8.in

EXTRA_DIST += vswitchd/vswitch-idl.ovsidl
BUILT_SOURCES += vswitchd/vswitch-idl.c vswitchd/vswitch-idl.h
DISTCLEANFILES += vswitchd/vswitch-idl.c vswitchd/vswitch-idl.h
noinst_DATA += vswitchd/vswitch-idl.ovsschema
DISTCLEANFILES += vswitchd/vswitch-idl.ovsschema
vswitchd/vswitch-idl.c vswitchd/vswitch-idl.h vswitchd/vswitch-idl.ovsschema: \
	ovsdb/ovsdb-idlc.in
EXTRA_DIST += vswitchd/vswitch-idl.c vswitchd/vswitch-idl.h vswitchd/vswitch-idl.ovsschema
