# Copyright (C) 2009 Nicira Networks, Inc.
#
# Copying and distribution of this file, with or without modification,
# are permitted in any medium without royalty provided the copyright
# notice and this notice are preserved.  This file is offered as-is,
# without warranty of any kind.

noinst_LIBRARIES += ofproto/libofproto.a
ofproto_libofproto_a_SOURCES = \
	ofproto/collectors.c \
	ofproto/collectors.h \
	ofproto/discovery.c \
	ofproto/discovery.h \
	ofproto/fail-open.c \
	ofproto/fail-open.h \
	ofproto/in-band.c \
	ofproto/in-band.h \
	ofproto/netflow.c \
	ofproto/netflow.h \
	ofproto/ofproto.c \
	ofproto/ofproto.h \
	ofproto/ofproto-sflow.c \
	ofproto/ofproto-sflow.h \
	ofproto/pktbuf.c \
	ofproto/pktbuf.h \
	ofproto/pinsched.c \
	ofproto/pinsched.h \
	ofproto/status.c \
	ofproto/status.h
