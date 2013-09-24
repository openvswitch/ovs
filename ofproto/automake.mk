# Copyright (C) 2009, 2010, 2011, 2012 Nicira, Inc.
#
# Copying and distribution of this file, with or without modification,
# are permitted in any medium without royalty provided the copyright
# notice and this notice are preserved.  This file is offered as-is,
# without warranty of any kind.

lib_LTLIBRARIES += ofproto/libofproto.la
ofproto_libofproto_la_LDFLAGS = -release $(VERSION)
ofproto_libofproto_la_SOURCES = \
	ofproto/bond.c \
	ofproto/bond.h \
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
	ofproto/ofproto-dpif.h \
	ofproto/ofproto-dpif-ipfix.c \
	ofproto/ofproto-dpif-ipfix.h \
	ofproto/ofproto-dpif-mirror.c \
	ofproto/ofproto-dpif-mirror.h \
	ofproto/ofproto-dpif-monitor.c \
	ofproto/ofproto-dpif-monitor.h \
	ofproto/ofproto-dpif-sflow.c \
	ofproto/ofproto-dpif-sflow.h \
	ofproto/ofproto-dpif-upcall.c \
	ofproto/ofproto-dpif-upcall.h \
	ofproto/ofproto-dpif-xlate.c \
	ofproto/ofproto-dpif-xlate.h \
	ofproto/ofproto-provider.h \
	ofproto/pktbuf.c \
	ofproto/pktbuf.h \
	ofproto/pinsched.c \
	ofproto/pinsched.h \
	ofproto/tunnel.c \
	ofproto/tunnel.h
ofproto_libofproto_la_CPPFLAGS = $(AM_CPPFLAGS)
ofproto_libofproto_la_CFLAGS = $(AM_CFLAGS)
ofproto_libofproto_la_LIBADD = lib/libsflow.la

# Distribute this generated file in order not to require Python at
# build time if ofproto/ipfix.xml is not modified.
ofproto_libofproto_la_SOURCES += ofproto/ipfix-entities.def

BUILT_SOURCES += ofproto/ipfix-entities.def

CLEANFILES += ofproto/ipfix-entities.def

MAN_FRAGMENTS += ofproto/ofproto-unixctl.man ofproto/ofproto-dpif-unixctl.man

# IPFIX entity definition macros generation from IANA's XML definition.
EXTRA_DIST += ofproto/ipfix.xml
dist_noinst_SCRIPTS = ofproto/ipfix-gen-entities
ofproto/ipfix-entities.def: ofproto/ipfix.xml ofproto/ipfix-gen-entities
	$(run_python) $(srcdir)/ofproto/ipfix-gen-entities $< > $@
