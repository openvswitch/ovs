# Copyright (C) 2009, 2010, 2011, 2012 Nicira, Inc.
#
# Copying and distribution of this file, with or without modification,
# are permitted in any medium without royalty provided the copyright
# notice and this notice are preserved.  This file is offered as-is,
# without warranty of any kind.

noinst_LIBRARIES += ofproto/libofproto.a
ofproto_libofproto_a_SOURCES = \
	ofproto/collectors.c \
	ofproto/collectors.h \
	ofproto/connmgr.c \
	ofproto/connmgr.h \
	ofproto/fail-open.c \
	ofproto/fail-open.h \
	ofproto/in-band.c \
	ofproto/in-band.h \
	ofproto/names.c \
	ofproto/netflow.c \
	ofproto/netflow.h \
	ofproto/ofproto.c \
	ofproto/ofproto.h \
	ofproto/ofproto-dpif.c \
	ofproto/ofproto-dpif-governor.c \
	ofproto/ofproto-dpif-governor.h \
	ofproto/ofproto-dpif-sflow.c \
	ofproto/ofproto-dpif-sflow.h \
	ofproto/ofproto-provider.h \
	ofproto/pktbuf.c \
	ofproto/pktbuf.h \
	ofproto/pinsched.c \
	ofproto/pinsched.h

MAN_FRAGMENTS += ofproto/ofproto-unixctl.man
