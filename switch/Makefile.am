include ../Make.vars

bin_PROGRAMS = switch
man_MANS = switch.8

switch_SOURCES = \
	chain.c \
	chain.h \
	crc32.c \
	crc32.h \
	datapath.c \
	datapath.h \
	dp_act.c \
	dp_act.h \
	nx_act.c \
	nx_act.h \
	switch.c \
	switch-flow.c \
	switch-flow.h \
	table.h \
	table-hash.c \
	table-linear.c

switch_LDADD = ../lib/libopenflow.a $(FAULT_LIBS) $(SSL_LIBS)

EXTRA_DIST = switch.8.in
DISTCLEANFILES = switch.8
switch.8: switch.8.in Makefile
	($(do_subst) && $(ro_man)) < $(srcdir)/switch.8.in > switch.8
