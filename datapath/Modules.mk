# Some modules should be built and distributed, e.g. openvswitch.
#
# Some modules should be built but not distributed, e.g. third-party
# hwtable modules.
both_modules = openvswitch
build_modules = $(both_modules)	# Modules to build
dist_modules = $(both_modules)	# Modules to distribute

openvswitch_sources = \
	actions.c \
	datapath.c \
	dp_notify.c \
	flow.c \
	flow_netlink.c \
	flow_table.c \
	vport.c \
	vport-gre.c \
	vport-internal_dev.c \
	vport-lisp.c \
	vport-netdev.c \
	vport-vxlan.c

openvswitch_headers = \
	compat.h \
	datapath.h \
	flow.h \
	flow_netlink.h \
	flow_table.h \
	vlan.h \
	vport.h \
	vport-internal_dev.h \
	vport-netdev.h

openvswitch_extras = \
	README

dist_sources = $(foreach module,$(dist_modules),$($(module)_sources))
dist_headers = $(foreach module,$(dist_modules),$($(module)_headers))
dist_extras = $(foreach module,$(dist_modules),$($(module)_extras))
build_sources = $(foreach module,$(build_modules),$($(module)_sources))
build_headers = $(foreach module,$(build_modules),$($(module)_headers))
build_links = $(notdir $(build_sources))
build_objects = $(notdir $(patsubst %.c,%.o,$(build_sources)))
