# Copyright (C) 2009, 2010, 2011, 2012, 2013, 2014 Nicira, Inc.
#
# Copying and distribution of this file, with or without modification,
# are permitted in any medium without royalty provided the copyright
# notice and this notice are preserved.  This file is offered as-is,
# without warranty of any kind.

lib_LTLIBRARIES += lib/libopenvswitch.la

lib_libopenvswitch_la_LIBADD = $(SSL_LIBS)

if WIN32
lib_libopenvswitch_la_LIBADD += ${PTHREAD_LIBS}
endif

lib_libopenvswitch_la_LDFLAGS = \
        -version-info $(LT_CURRENT):$(LT_REVISION):$(LT_AGE) \
        -Wl,--version-script=$(top_builddir)/lib/libopenvswitch.sym \
        $(AM_LDFLAGS)

lib_libopenvswitch_la_SOURCES = \
	lib/aes128.c \
	lib/aes128.h \
	lib/async-append.h \
	lib/backtrace.c \
	lib/backtrace.h \
	lib/bfd.c \
	lib/bfd.h \
	lib/bitmap.h \
	lib/bundle.c \
	lib/bundle.h \
	lib/byte-order.h \
	lib/byteq.c \
	lib/byteq.h \
	lib/cfm.c \
	lib/cfm.h \
	lib/classifier.c \
	lib/classifier.h \
	lib/classifier-private.h \
	lib/cmap.c \
	lib/cmap.h \
	lib/command-line.c \
	lib/command-line.h \
	lib/compiler.h \
	lib/connectivity.c \
	lib/connectivity.h \
	lib/coverage.c \
	lib/coverage.h \
	lib/crc32c.c \
	lib/crc32c.h \
	lib/csum.c \
	lib/csum.h \
	lib/daemon.c \
	lib/daemon.h \
	lib/daemon-private.h \
	lib/dhcp.h \
	lib/dummy.c \
	lib/dummy.h \
	lib/dhparams.h \
	lib/dirs.h \
	lib/dpctl.c \
	lib/dpctl.h \
	lib/dp-packet.h \
	lib/dp-packet.c \
	lib/dpif-netdev.c \
	lib/dpif-netdev.h \
	lib/dpif-provider.h \
	lib/dpif.c \
	lib/dpif.h \
	lib/heap.c \
	lib/heap.h \
	lib/dynamic-string.c \
	lib/dynamic-string.h \
	lib/entropy.c \
	lib/entropy.h \
	lib/fat-rwlock.c \
	lib/fat-rwlock.h \
	lib/fatal-signal.c \
	lib/fatal-signal.h \
	lib/flow.c \
	lib/flow.h \
	lib/guarded-list.c \
	lib/guarded-list.h \
	lib/hash.c \
	lib/hash.h \
	lib/hindex.c \
	lib/hindex.h \
	lib/hmap.c \
	lib/hmap.h \
	lib/hmapx.c \
	lib/hmapx.h \
	lib/id-pool.c \
	lib/id-pool.h \
	lib/jhash.c \
	lib/jhash.h \
	lib/json.c \
	lib/json.h \
	lib/jsonrpc.c \
	lib/jsonrpc.h \
	lib/lacp.c \
	lib/lacp.h \
	lib/latch.h \
	lib/learn.c \
	lib/learn.h \
	lib/learning-switch.c \
	lib/learning-switch.h \
	lib/list.h \
	lib/lockfile.c \
	lib/lockfile.h \
	lib/mac-learning.c \
	lib/mac-learning.h \
	lib/match.c \
	lib/match.h \
	lib/mcast-snooping.c \
	lib/mcast-snooping.h \
	lib/memory.c \
	lib/memory.h \
	lib/meta-flow.c \
	lib/meta-flow.h \
	lib/multipath.c \
	lib/multipath.h \
	lib/netdev-dummy.c \
	lib/netdev-provider.h \
	lib/netdev-vport.c \
	lib/netdev-vport.h \
	lib/netdev.c \
	lib/netdev.h \
	lib/netflow.h \
	lib/netlink.c \
	lib/netlink.h \
	lib/nx-match.c \
	lib/nx-match.h \
	lib/odp-execute.c \
	lib/odp-execute.h \
	lib/odp-util.c \
	lib/odp-util.h \
	lib/ofp-actions.c \
	lib/ofp-actions.h \
	lib/ofp-errors.c \
	lib/ofp-errors.h \
	lib/ofp-msgs.c \
	lib/ofp-msgs.h \
	lib/ofp-parse.c \
	lib/ofp-parse.h \
	lib/ofp-print.c \
	lib/ofp-print.h \
	lib/ofp-util.c \
	lib/ofp-util.h \
	lib/ofp-version-opt.h \
	lib/ofp-version-opt.c \
	lib/ofpbuf.c \
	lib/ofpbuf.h \
	lib/ovs-atomic-c11.h \
	lib/ovs-atomic-clang.h \
	lib/ovs-atomic-flag-gcc4.7+.h \
	lib/ovs-atomic-gcc4+.h \
	lib/ovs-atomic-gcc4.7+.h \
	lib/ovs-atomic-i586.h \
	lib/ovs-atomic-locked.c \
	lib/ovs-atomic-locked.h \
	lib/ovs-atomic-msvc.h \
	lib/ovs-atomic-pthreads.h \
	lib/ovs-atomic-x86_64.h \
	lib/ovs-atomic.h \
	lib/ovs-lldp.c \
	lib/ovs-lldp.h \
	lib/ovs-rcu.c \
	lib/ovs-rcu.h \
	lib/ovs-router.h \
	lib/ovs-router.c \
	lib/ovs-thread.c \
	lib/ovs-thread.h \
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
	lib/pcap-file.c \
	lib/pcap-file.h \
	lib/perf-counter.h \
	lib/perf-counter.c \
	lib/poll-loop.c \
	lib/poll-loop.h \
	lib/process.c \
	lib/process.h \
	lib/pvector.c \
	lib/pvector.h \
	lib/random.c \
	lib/random.h \
	lib/rconn.c \
	lib/rconn.h \
	lib/rculist.c \
	lib/rculist.h \
	lib/reconnect.c \
	lib/reconnect.h \
	lib/rstp.c \
	lib/rstp.h \
	lib/rstp-common.h \
	lib/rstp-state-machines.c \
	lib/rstp-state-machines.h \
	lib/sat-math.h \
	lib/seq.c \
	lib/seq.h \
	lib/sha1.c \
	lib/sha1.h \
	lib/shash.c \
	lib/shash.h \
	lib/simap.c \
	lib/simap.h \
	lib/smap.c \
	lib/smap.h \
	lib/socket-util.c \
	lib/socket-util.h \
	lib/sort.c \
	lib/sort.h \
	lib/sset.c \
	lib/sset.h \
	lib/stp.c \
	lib/stp.h \
	lib/stream-fd.c \
	lib/stream-fd.h \
	lib/stream-provider.h \
	lib/stream-ssl.h \
	lib/stream-tcp.c \
	lib/stream.c \
	lib/stream.h \
	lib/stdio.c \
	lib/string.c \
	lib/svec.c \
	lib/svec.h \
	lib/table.c \
	lib/table.h \
	lib/tag.c \
	lib/tag.h \
	lib/timer.c \
	lib/timer.h \
	lib/timeval.c \
	lib/timeval.h \
	lib/tnl-arp-cache.c \
	lib/tnl-arp-cache.h \
	lib/tnl-ports.c \
	lib/tnl-ports.h \
	lib/token-bucket.c \
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
	lib/vlan-bitmap.c \
	lib/vlan-bitmap.h \
	lib/vlandev.c \
	lib/vlandev.h \
	lib/vlog.c \
	lib/vswitch-idl.c \
	lib/vswitch-idl.h \
	lib/lldp/aa-structs.h \
	lib/lldp/lldp.c \
	lib/lldp/lldp-const.h \
	lib/lldp/lldp-tlv.h \
	lib/lldp/lldpd.c \
	lib/lldp/lldpd.h \
	lib/lldp/lldpd-structs.c \
	lib/lldp/lldpd-structs.h

if WIN32
lib_libopenvswitch_la_SOURCES += \
	lib/daemon-windows.c \
	lib/getopt_long.c \
	lib/getrusage-windows.c \
	lib/latch-windows.c \
	lib/route-table-stub.c \
	lib/strsep.c
else
lib_libopenvswitch_la_SOURCES += \
	lib/daemon-unix.c \
	lib/latch-unix.c \
	lib/signals.c \
	lib/signals.h \
	lib/socket-util-unix.c \
	lib/stream-unix.c
endif

EXTRA_DIST += \
	lib/stdio.h.in \
	lib/string.h.in

nodist_lib_libopenvswitch_la_SOURCES = \
	lib/dirs.c
CLEANFILES += $(nodist_lib_libopenvswitch_la_SOURCES)

lib_LTLIBRARIES += lib/libsflow.la
lib_libsflow_la_LDFLAGS = \
        -version-info $(LT_CURRENT):$(LT_REVISION):$(LT_AGE) \
        -Wl,--version-script=$(top_builddir)/lib/libsflow.sym \
        $(AM_LDFLAGS)
lib_libsflow_la_SOURCES = \
	lib/sflow_api.h \
	lib/sflow.h \
	lib/sflow_agent.c \
	lib/sflow_sampler.c \
	lib/sflow_poller.c \
	lib/sflow_receiver.c
lib_libsflow_la_CPPFLAGS = $(AM_CPPFLAGS)
lib_libsflow_la_CFLAGS = $(AM_CFLAGS)
if HAVE_WNO_UNUSED
lib_libsflow_la_CFLAGS += -Wno-unused
endif
if HAVE_WNO_UNUSED_PARAMETER
lib_libsflow_la_CFLAGS += -Wno-unused-parameter
endif

if LINUX
lib_libopenvswitch_la_SOURCES += \
	lib/dpif-netlink.c \
	lib/dpif-netlink.h \
	lib/netdev-linux.c \
	lib/netdev-linux.h \
	lib/netlink-notifier.c \
	lib/netlink-notifier.h \
	lib/netlink-protocol.h \
	lib/netlink-socket.c \
	lib/netlink-socket.h \
	lib/ovs-numa.c \
	lib/ovs-numa.h \
	lib/rtnetlink-link.c \
	lib/rtnetlink-link.h \
	lib/route-table.c \
	lib/route-table.h
endif

if DPDK_NETDEV
lib_libopenvswitch_la_SOURCES += \
       lib/netdev-dpdk.c \
       lib/netdev-dpdk.h
endif

if WIN32
lib_libopenvswitch_la_SOURCES += \
	lib/dpif-netlink.c \
	lib/dpif-netlink.h \
	lib/netdev-windows.c \
	lib/netlink-notifier.c \
	lib/netlink-notifier.h \
	lib/netlink-protocol.h \
	lib/netlink-socket.c \
	lib/netlink-socket.h
endif

if HAVE_POSIX_AIO
lib_libopenvswitch_la_SOURCES += lib/async-append-aio.c
else
lib_libopenvswitch_la_SOURCES += lib/async-append-null.c
endif

if ESX
lib_libopenvswitch_la_SOURCES += \
        lib/route-table-stub.c
endif

if HAVE_IF_DL
lib_libopenvswitch_la_SOURCES += \
	lib/netdev-bsd.c \
	lib/rtbsd.c \
	lib/rtbsd.h \
	lib/route-table-bsd.c
endif

if HAVE_OPENSSL
lib_libopenvswitch_la_SOURCES += lib/stream-ssl.c
nodist_lib_libopenvswitch_la_SOURCES += lib/dhparams.c
lib/dhparams.c: lib/dh1024.pem lib/dh2048.pem lib/dh4096.pem
	$(AM_V_GEN)(echo '#include "lib/dhparams.h"' &&                 \
	 openssl dhparam -C -in $(srcdir)/lib/dh1024.pem -noout &&	\
	 openssl dhparam -C -in $(srcdir)/lib/dh2048.pem -noout &&	\
	 openssl dhparam -C -in $(srcdir)/lib/dh4096.pem -noout)	\
	| sed 's/\(get_dh[0-9]*\)()/\1(void)/' > lib/dhparams.c.tmp &&  \
	mv lib/dhparams.c.tmp lib/dhparams.c
else
lib_libopenvswitch_la_SOURCES += lib/stream-nossl.c
endif

pkgconfig_DATA += \
	$(srcdir)/lib/libopenvswitch.pc \
	$(srcdir)/lib/libsflow.pc

EXTRA_DIST += \
	lib/dh1024.pem \
	lib/dh2048.pem \
	lib/dh4096.pem \
	lib/dirs.c.in

MAN_FRAGMENTS += \
	lib/common.man \
	lib/common-syn.man \
	lib/coverage-unixctl.man \
	lib/daemon.man \
	lib/daemon-syn.man \
	lib/dpctl.man \
	lib/memory-unixctl.man \
	lib/ofp-version.man \
	lib/ovs.tmac \
	lib/service.man \
	lib/service-syn.man \
	lib/ssl-bootstrap.man \
	lib/ssl-bootstrap-syn.man \
	lib/ssl-peer-ca-cert.man \
	lib/ssl.man \
	lib/ssl-syn.man \
	lib/table.man \
	lib/unixctl.man \
	lib/unixctl-syn.man \
	lib/vconn-active.man \
	lib/vconn-passive.man \
	lib/vlog-unixctl.man \
	lib/vlog-syn.man \
	lib/vlog.man

# vswitch IDL
OVSIDL_BUILT += \
	$(srcdir)/lib/vswitch-idl.c \
	$(srcdir)/lib/vswitch-idl.h \
	$(srcdir)/lib/vswitch-idl.ovsidl

EXTRA_DIST += $(srcdir)/lib/vswitch-idl.ann
VSWITCH_IDL_FILES = \
	$(srcdir)/vswitchd/vswitch.ovsschema \
	$(srcdir)/lib/vswitch-idl.ann
$(srcdir)/lib/vswitch-idl.ovsidl: $(VSWITCH_IDL_FILES)
	$(AM_V_GEN)$(OVSDB_IDLC) annotate $(VSWITCH_IDL_FILES) > $@.tmp && \
	mv $@.tmp $@

lib/dirs.c: lib/dirs.c.in Makefile
	$(AM_V_GEN)($(ro_c) && sed < $(srcdir)/lib/dirs.c.in \
		-e 's,[@]srcdir[@],$(srcdir),g' \
		-e 's,[@]LOGDIR[@],"$(LOGDIR)",g' \
		-e 's,[@]RUNDIR[@],"$(RUNDIR)",g' \
		-e 's,[@]DBDIR[@],"$(DBDIR)",g' \
		-e 's,[@]bindir[@],"$(bindir)",g' \
		-e 's,[@]sysconfdir[@],"$(sysconfdir)",g' \
		-e 's,[@]pkgdatadir[@],"$(pkgdatadir)",g') \
	     > lib/dirs.c.tmp && \
	mv lib/dirs.c.tmp lib/dirs.c

lib/meta-flow.inc: $(srcdir)/build-aux/extract-ofp-fields lib/meta-flow.h
	$(AM_V_GEN)$(run_python) $^ --meta-flow > $@.tmp && mv $@.tmp $@
lib/meta-flow.lo: lib/meta-flow.inc
lib/nx-match.inc: $(srcdir)/build-aux/extract-ofp-fields lib/meta-flow.h
	$(AM_V_GEN)$(run_python) $^ --nx-match > $@.tmp && mv $@.tmp $@
lib/nx-match.lo: lib/nx-match.inc
CLEANFILES += lib/meta-flow.inc lib/nx-match.inc
EXTRA_DIST += build-aux/extract-ofp-fields

lib/ofp-actions.inc1: $(srcdir)/build-aux/extract-ofp-actions lib/ofp-actions.c
	$(AM_V_GEN)$(run_python) $^ --prototypes > $@.tmp && mv $@.tmp $@
lib/ofp-actions.inc2: $(srcdir)/build-aux/extract-ofp-actions lib/ofp-actions.c
	$(AM_V_GEN)$(run_python) $^ --definitions > $@.tmp && mv $@.tmp $@
lib/ofp-actions.lo: lib/ofp-actions.inc1 lib/ofp-actions.inc2
CLEANFILES += lib/ofp-actions.inc1 lib/ofp-actions.inc2
EXTRA_DIST += build-aux/extract-ofp-actions

$(srcdir)/lib/ofp-errors.inc: \
	lib/ofp-errors.h include/openflow/openflow-common.h \
	$(srcdir)/build-aux/extract-ofp-errors
	$(AM_V_GEN)$(run_python) $(srcdir)/build-aux/extract-ofp-errors \
		$(srcdir)/lib/ofp-errors.h \
		$(srcdir)/include/openflow/openflow-common.h > $@.tmp && \
	mv $@.tmp $@
$(srcdir)/lib/ofp-errors.c: $(srcdir)/lib/ofp-errors.inc
EXTRA_DIST += build-aux/extract-ofp-errors lib/ofp-errors.inc

$(srcdir)/lib/ofp-msgs.inc: \
	lib/ofp-msgs.h $(srcdir)/build-aux/extract-ofp-msgs
	$(AM_V_GEN)$(run_python) $(srcdir)/build-aux/extract-ofp-msgs \
		$(srcdir)/lib/ofp-msgs.h $@ > $@.tmp && mv $@.tmp $@
$(srcdir)/lib/ofp-msgs.c: $(srcdir)/lib/ofp-msgs.inc
EXTRA_DIST += build-aux/extract-ofp-msgs lib/ofp-msgs.inc

INSTALL_DATA_LOCAL += lib-install-data-local
lib-install-data-local:
	$(MKDIR_P) $(DESTDIR)$(RUNDIR)
	$(MKDIR_P) $(DESTDIR)$(PKIDIR)
	$(MKDIR_P) $(DESTDIR)$(LOGDIR)
	$(MKDIR_P) $(DESTDIR)$(DBDIR)

