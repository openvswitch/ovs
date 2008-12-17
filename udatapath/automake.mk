bin_PROGRAMS += udatapath/udatapath
man_MANS += udatapath/udatapath.8

udatapath_udatapath_SOURCES = \
	udatapath/chain.c \
	udatapath/chain.h \
	udatapath/crc32.c \
	udatapath/crc32.h \
	udatapath/datapath.c \
	udatapath/datapath.h \
	udatapath/dp_act.c \
	udatapath/dp_act.h \
	udatapath/nx_act.c \
	udatapath/nx_act.h \
	udatapath/nx_msg.c \
	udatapath/nx_msg.h \
	udatapath/udatapath.c \
	udatapath/switch-flow.c \
	udatapath/switch-flow.h \
	udatapath/table.h \
	udatapath/table-hash.c \
	udatapath/table-linear.c

udatapath_udatapath_LDADD = lib/libopenflow.a $(SSL_LIBS) $(FAULT_LIBS)

EXTRA_DIST += udatapath/udatapath.8.in
DISTCLEANFILES += udatapath/udatapath.8
