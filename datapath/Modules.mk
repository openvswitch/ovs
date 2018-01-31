# Some modules should be built and distributed, e.g. openvswitch.
#
# Some modules should be built but not distributed, e.g. third-party
# hwtable modules.
build_multi_modules = \
	openvswitch
both_modules = \
	$(build_multi_modules) \
	vport_geneve \
	vport_gre \
	vport_lisp \
	vport_stt \
	vport_vxlan
# When changing the name of 'build_modules', please also update the
# print-build-modules in Makefile.am.
build_modules = $(both_modules)	# Modules to build
dist_modules = $(both_modules)	# Modules to distribute

openvswitch_sources = \
	actions.c \
	conntrack.c \
	datapath.c \
	dp_notify.c \
	flow.c \
	flow_netlink.c \
	flow_table.c \
	vport.c \
	vport-internal_dev.c \
	vport-netdev.c \
	nsh.c

vport_geneve_sources = vport-geneve.c
vport_vxlan_sources = vport-vxlan.c
vport_gre_sources = vport-gre.c
vport_lisp_sources = vport-lisp.c
vport_stt_sources = vport-stt.c
nsh_sources = nsh.c

openvswitch_headers = \
	compat.h \
	conntrack.h \
	datapath.h \
	flow.h \
	flow_netlink.h \
	flow_table.h \
	vport.h \
	vport-internal_dev.h \
	vport-netdev.h

dist_sources = $(foreach module,$(dist_modules),$($(module)_sources))
dist_headers = $(foreach module,$(dist_modules),$($(module)_headers))
dist_extras = $(foreach module,$(dist_modules),$($(module)_extras))
build_sources = $(foreach module,$(build_modules),$($(module)_sources))
build_headers = $(foreach module,$(build_modules),$($(module)_headers))
build_links = $(notdir $(build_sources))
build_objects = $(notdir $(patsubst %.c,%.o,$(build_sources)))
