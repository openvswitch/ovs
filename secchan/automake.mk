# Copyright (C) 2009 Nicira Networks, Inc.
#
# Copying and distribution of this file, with or without modification,
# are permitted in any medium without royalty provided the copyright
# notice and this notice are preserved.  This file is offered as-is,
# without warranty of any kind.

bin_PROGRAMS += secchan/secchan
man_MANS += secchan/secchan.8

secchan_secchan_SOURCES = secchan/main.c
secchan_secchan_LDADD = \
	secchan/libsecchan.a \
	lib/libopenvswitch.a \
	$(FAULT_LIBS) \
	$(SSL_LIBS)

noinst_LIBRARIES += secchan/libsecchan.a
secchan_libsecchan_a_SOURCES = \
	secchan/discovery.c \
	secchan/discovery.h \
	secchan/executer.c \
	secchan/executer.h \
	secchan/fail-open.c \
	secchan/fail-open.h \
	secchan/in-band.c \
	secchan/in-band.h \
	secchan/netflow.c \
	secchan/netflow.h \
	secchan/ofproto.c \
	secchan/ofproto.h \
	secchan/pktbuf.c \
	secchan/pktbuf.h \
	secchan/pinsched.c \
	secchan/pinsched.h \
	secchan/status.c \
	secchan/status.h

EXTRA_DIST += secchan/secchan.8.in
DISTCLEANFILES += secchan/secchan.8

include secchan/commands/automake.mk
