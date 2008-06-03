all_modules = $(dist_modules)
dist_modules = openflow unit

openflow_sources = \
	chain.c \
	crc32.c \
	datapath.c \
	datapath_t.c \
	dp_dev.c \
	flow.c \
	forward.c \
	table-hash.c \
	table-linear.c \
	unit-exports.c

openflow_headers = \
	chain.h \
	compat.h \
	crc32.h \
	datapath.h \
	datapath_t.h \
	dp_dev.h \
	flow.h \
	forward.h \
	snap.h \
	table.h \
	unit.h

unit_sources = \
	crc_t.c \
	forward_t.c \
	table_t.c \
	unit.c

dist_sources = $(foreach module,$(dist_modules),$($(module)_sources))
dist_headers = $(foreach module,$(dist_modules),$($(module)_headers))
all_sources = $(foreach module,$(all_modules),$($(module)_sources))
all_headers = $(foreach module,$(all_modules),$($(module)_headers))
all_objects = $(patsubst %.c,%.o,$(all_sources))
all_objdirs = $(addprefix $(builddir)/,$(sort $(dir $(all_objects))))
all_dummies = $(addsuffix /.dummy,$(all_objdirs))
