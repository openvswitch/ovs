# Copyright (C) 2009, 2010 Nicira Networks, Inc.
#
# Copying and distribution of this file, with or without modification,
# are permitted in any medium without royalty provided the copyright
# notice and this notice are preserved.  This file is offered as-is,
# without warranty of any kind.

noinst_LIBRARIES += lib/libopenvswitch.a

lib_libopenvswitch_a_SOURCES = \
	lib/aes128.c \
	lib/aes128.h \
	lib/backtrace.c \
	lib/backtrace.h \
	lib/bitmap.c \
	lib/bitmap.h \
	lib/byteq.c \
	lib/byteq.h \
	lib/classifier.c \
	lib/classifier.h \
	lib/command-line.c \
	lib/command-line.h \
	lib/compiler.h \
	lib/coverage.c \
	lib/coverage.h \
	lib/coverage-counters.h \
	lib/csum.c \
	lib/csum.h \
	lib/daemon.c \
	lib/daemon.h \
	lib/dhcp-client.c \
	lib/dhcp-client.h \
	lib/dhcp.c \
	lib/dhcp.h \
	lib/dhparams.h \
	lib/dirs.h \
	lib/dpif-netdev.c \
	lib/dpif-provider.h \
	lib/dpif.c \
	lib/dpif.h \
	lib/dynamic-string.c \
	lib/dynamic-string.h \
	lib/entropy.c \
	lib/entropy.h \
	lib/fatal-signal.c \
	lib/fatal-signal.h \
	lib/flow.c \
	lib/flow.h \
	lib/hash.c \
	lib/hash.h \
	lib/hmap.c \
	lib/hmap.h \
	lib/json.c \
	lib/json.h \
	lib/jsonrpc.c \
	lib/jsonrpc.h \
	lib/leak-checker.c \
	lib/leak-checker.h \
	lib/learning-switch.c \
	lib/learning-switch.h \
	lib/list.c \
	lib/list.h \
	lib/lockfile.c \
	lib/lockfile.h \
	lib/mac-learning.c \
	lib/mac-learning.h \
	lib/netdev-provider.h \
	lib/netdev.c \
	lib/netdev.h \
	lib/odp-util.c \
	lib/odp-util.h \
	lib/ofp-parse.c \
	lib/ofp-parse.h \
	lib/ofp-print.c \
	lib/ofp-print.h \
	lib/ofp-util.c \
	lib/ofp-util.h \
	lib/ofpbuf.c \
	lib/ofpbuf.h \
	lib/ovsdb-data.c \
	lib/ovsdb-data.h \
	lib/ovsdb-error.c \
	lib/ovsdb-error.h \
	lib/ovsdb-idl-provider.h \
	lib/ovsdb-idl.c \
	lib/ovsdb-idl.h \
	lib/ovsdb-parser.c \
	lib/ovsdb-parser.h \
	lib/ovsdb-types.c \
	lib/ovsdb-types.h \
	lib/packets.c \
	lib/packets.h \
	lib/pcap.c \
	lib/pcap.h \
	lib/poll-loop.c \
	lib/poll-loop.h \
	lib/port-array.c \
	lib/port-array.h \
	lib/process.c \
	lib/process.h \
	lib/queue.c \
	lib/queue.h \
	lib/random.c \
	lib/random.h \
	lib/rconn.c \
	lib/rconn.h \
	lib/reconnect.c \
	lib/reconnect.h \
	lib/sat-math.h \
	lib/sha1.c \
	lib/sha1.h \
	lib/shash.c \
	lib/shash.h \
	lib/signals.c \
	lib/signals.h \
	lib/socket-util.c \
	lib/socket-util.h \
	lib/sort.c \
	lib/sort.h \
	lib/stream-fd.c \
	lib/stream-fd.h \
	lib/stream-provider.h \
	lib/stream-ssl.h \
	lib/stream-tcp.c \
	lib/stream-unix.c \
	lib/stream.c \
	lib/stream.h \
	lib/string.h \
	lib/svec.c \
	lib/svec.h \
	lib/tag.c \
	lib/tag.h \
	lib/timeval.c \
	lib/timeval.h \
	lib/type-props.h \
	lib/unaligned.h \
	lib/unicode.c \
	lib/unicode.h \
	lib/unixctl.c \
	lib/unixctl.h \
	lib/util.c \
	lib/util.h \
	lib/uuid.c \
	lib/uuid.h \
	lib/valgrind.h \
	lib/vconn-provider.h \
	lib/vconn-stream.c \
	lib/vconn.c \
	lib/vconn.h \
	lib/vlog-modules.def \
	lib/vlog.c \
	lib/vlog.h \
	lib/xtoxll.h
nodist_lib_libopenvswitch_a_SOURCES = \
	lib/coverage-counters.c \
	lib/dirs.c
CLEANFILES += $(nodist_lib_libopenvswitch_a_SOURCES)

noinst_LIBRARIES += lib/libsflow.a
lib_libsflow_a_SOURCES = \
	lib/sflow_api.h \
	lib/sflow.h \
	lib/sflow_agent.c \
	lib/sflow_sampler.c \
	lib/sflow_poller.c \
	lib/sflow_receiver.c
lib_libsflow_a_CFLAGS = $(AM_CFLAGS)
if HAVE_WNO_UNUSED
lib_libsflow_a_CFLAGS += -Wno-unused
endif
if HAVE_WNO_UNUSED_PARAMETER
lib_libsflow_a_CFLAGS += -Wno-unused-parameter
endif

if HAVE_NETLINK
lib_libopenvswitch_a_SOURCES += \
	lib/dpif-linux.c \
	lib/netdev-linux.c \
	lib/netdev-patch.c \
	lib/netdev-tunnel.c \
	lib/netdev-vport.c \
	lib/netdev-vport.h \
	lib/netlink-protocol.h \
	lib/netlink.c \
	lib/netlink.h \
	lib/rtnetlink.c \
	lib/rtnetlink.h
endif

if HAVE_OPENSSL
lib_libopenvswitch_a_SOURCES += lib/stream-ssl.c
nodist_lib_libopenvswitch_a_SOURCES += lib/dhparams.c
lib/dhparams.c: lib/dh1024.pem lib/dh2048.pem lib/dh4096.pem
	(echo '#include "lib/dhparams.h"' &&				\
	 openssl dhparam -C -in $(srcdir)/lib/dh1024.pem -noout &&	\
	 openssl dhparam -C -in $(srcdir)/lib/dh2048.pem -noout &&	\
	 openssl dhparam -C -in $(srcdir)/lib/dh4096.pem -noout)	\
	| sed 's/\(get_dh[0-9]*\)()/\1(void)/' > lib/dhparams.c.tmp
	mv lib/dhparams.c.tmp lib/dhparams.c
endif

EXTRA_DIST += \
	lib/dh1024.pem \
	lib/dh2048.pem \
	lib/dh4096.pem \
	lib/dhparams.h

EXTRA_DIST += \
	lib/common.man \
	lib/common-syn.man \
	lib/daemon.man \
	lib/daemon-syn.man \
	lib/dpif.man \
	lib/leak-checker.man \
	lib/ssl-bootstrap.man \
	lib/ssl-bootstrap-syn.man \
	lib/ssl-peer-ca-cert.man \
	lib/ssl.man \
	lib/ssl-syn.man \
	lib/unixctl.man \
	lib/unixctl-syn.man \
	lib/vconn-active.man \
	lib/vconn-passive.man \
	lib/vlog-unixctl.man \
	lib/vlog-syn.man \
	lib/vlog.man


lib/dirs.c: Makefile
	($(ro_c) && \
	 echo 'const char ovs_pkgdatadir[] = "$(pkgdatadir)";' && \
	 echo 'const char ovs_rundir[] = "@RUNDIR@";' && \
	 echo 'const char ovs_logdir[] = "@LOGDIR@";' && \
	 echo 'const char ovs_bindir[] = "$(bindir)";') > lib/dirs.c.tmp
	mv lib/dirs.c.tmp lib/dirs.c

install-data-local: lib-install-data-local
lib-install-data-local:
	$(MKDIR_P) $(DESTDIR)$(RUNDIR)
	$(MKDIR_P) $(DESTDIR)$(PKIDIR)
	$(MKDIR_P) $(DESTDIR)$(LOGDIR)

# All the source files that have coverage counters.
COVERAGE_FILES = \
	lib/dpif.c \
	lib/flow.c \
	lib/lockfile.c \
	lib/hmap.c \
	lib/mac-learning.c \
	lib/netdev.c \
	lib/netdev-linux.c \
	lib/netlink.c \
	lib/odp-util.c \
	lib/poll-loop.c \
	lib/process.c \
	lib/rconn.c \
	lib/rtnetlink.c \
	lib/stream.c \
	lib/stream-ssl.c \
	lib/timeval.c \
	lib/unixctl.c \
	lib/util.c \
	lib/vconn.c \
	ofproto/ofproto.c \
	ofproto/pktbuf.c \
	vswitchd/bridge.c \
	vswitchd/ovs-brcompatd.c
lib/coverage-counters.c: $(COVERAGE_FILES) lib/coverage-scan.pl
	(cd $(srcdir) && $(PERL) lib/coverage-scan.pl $(COVERAGE_FILES)) > $@.tmp
	mv $@.tmp $@
EXTRA_DIST += lib/coverage-scan.pl

ALL_LOCAL += check-vlog-modules
check-vlog-modules:
	cd $(srcdir) && build-aux/check-vlog-modules
.PHONY: check-vlog-modules
EXTRA_DIST += build-aux/check-vlog-modules
