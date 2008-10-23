bin_PROGRAMS += switch/switch
man_MANS += switch/switch.8

switch_switch_SOURCES = \
	switch/chain.c \
	switch/chain.h \
	switch/crc32.c \
	switch/crc32.h \
	switch/datapath.c \
	switch/datapath.h \
	switch/dp_act.c \
	switch/dp_act.h \
	switch/nx_act.c \
	switch/nx_act.h \
	switch/switch.c \
	switch/switch-flow.c \
	switch/switch-flow.h \
	switch/table.h \
	switch/table-hash.c \
	switch/table-linear.c

switch_switch_LDADD = lib/libopenflow.a $(FAULT_LIBS) $(SSL_LIBS)

EXTRA_DIST += switch/switch.8.in
DISTCLEANFILES += switch/switch.8
