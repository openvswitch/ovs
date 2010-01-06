# Copyright (C) 2009, 2010 Nicira Networks, Inc.
#
# Copying and distribution of this file, with or without modification,
# are permitted in any medium without royalty provided the copyright
# notice and this notice are preserved.  This file is offered as-is,
# without warranty of any kind.

noinst_LIBRARIES += lib/libopenvswitch.a

lib_libopenvswitch_a_SOURCES = \
	lib/backtrace.c \
	lib/backtrace.h \
	lib/bitmap.c \
	lib/bitmap.h \
	lib/cfg.c \
	lib/cfg.h \
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
	lib/dpif-linux.c \
	lib/dpif-netdev.c \
	lib/dpif-provider.h \
	lib/dpif.c \
	lib/dpif.h \
	lib/dynamic-string.c \
	lib/dynamic-string.h \
	lib/fatal-signal.c \
	lib/fatal-signal.h \
	lib/fault.c \
	lib/fault.h \
	lib/flow.c \
	lib/flow.h \
	lib/hash.c \
	lib/hash.h \
	lib/hmap.c \
	lib/hmap.h \
	lib/leak-checker.c \
	lib/leak-checker.h \
	lib/learning-switch.c \
	lib/learning-switch.h \
	lib/list.c \
	lib/list.h \
	lib/mac-learning.c \
	lib/mac-learning.h \
	lib/netdev-linux.c \
	lib/netdev-provider.h \
	lib/netdev.c \
	lib/netdev.h \
	lib/odp-util.c \
	lib/odp-util.h \
	lib/ofp-print.c \
	lib/ofp-print.h \
	lib/ofpbuf.c \
	lib/ofpbuf.h \
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
	lib/rtnetlink.c \
	lib/rtnetlink.h \
	lib/sat-math.h \
	lib/sha1.c \
	lib/sha1.h \
	lib/shash.c \
	lib/shash.h \
	lib/signals.c \
	lib/signals.h \
	lib/socket-util.c \
	lib/socket-util.h \
	lib/stp.c \
	lib/stp.h \
	lib/string.h \
	lib/svec.c \
	lib/svec.h \
	lib/tag.c \
	lib/tag.h \
	lib/timeval.c \
	lib/timeval.h \
	lib/type-props.h \
	lib/unixctl.c \
	lib/unixctl.h \
	lib/util.c \
	lib/util.h \
	lib/valgrind.h \
	lib/vconn-provider.h \
	lib/vconn-ssl.h \
	lib/vconn-stream.c \
	lib/vconn-stream.h \
	lib/vconn-tcp.c \
	lib/vconn-unix.c \
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

if HAVE_NETLINK
lib_libopenvswitch_a_SOURCES += \
	lib/netlink-protocol.h \
	lib/netlink.c \
	lib/netlink.h
endif

if HAVE_OPENSSL
lib_libopenvswitch_a_SOURCES += \
	lib/vconn-ssl.c 
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
	lib/daemon.man \
	lib/dpif.man \
	lib/leak-checker.man \
	lib/vlog-unixctl.man \
	lib/vlog.man


lib/dirs.c: Makefile
	($(ro_c) && \
	 echo 'const char ovs_pkgdatadir[] = "$(pkgdatadir)";' && \
	 echo 'const char ovs_rundir[] = "@RUNDIR@";' && \
	 echo 'const char ovs_logdir[] = "@LOGDIR@";' && \
	 echo 'const char ovs_bindir[] = "$(bindir)";') > lib/dirs.c.tmp
	mv lib/dirs.c.tmp lib/dirs.c

install-data-local:
	$(MKDIR_P) $(DESTDIR)$(RUNDIR)
	$(MKDIR_P) $(DESTDIR)$(PKIDIR)
	$(MKDIR_P) $(DESTDIR)$(LOGDIR)

# All the source files that have coverage counters.
COVERAGE_FILES = \
	lib/cfg.c \
	lib/dpif.c \
	lib/flow.c \
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
	lib/timeval.c \
	lib/unixctl.c \
	lib/util.c \
	lib/vconn.c \
	ofproto/ofproto.c \
	ofproto/pktbuf.c \
	vswitchd/bridge.c \
	vswitchd/mgmt.c \
	vswitchd/ovs-brcompatd.c
lib/coverage-counters.c: $(COVERAGE_FILES) lib/coverage-scan.pl
	(cd $(srcdir) && $(PERL) lib/coverage-scan.pl $(COVERAGE_FILES)) > $@.tmp
	mv $@.tmp $@
EXTRA_DIST += lib/coverage-scan.pl
