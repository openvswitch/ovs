# Copyright (C) 2009, 2010, 2011, 2012, 2013, 2014, 2015, 2016, 2017 Nicira, Inc.
#
# Copying and distribution of this file, with or without modification,
# are permitted in any medium without royalty provided the copyright
# notice and this notice are preserved.  This file is offered as-is,
# without warranty of any kind.

lib_LTLIBRARIES += lib/libopenvswitch.la

lib_libopenvswitch_la_LIBADD = $(SSL_LIBS)
lib_libopenvswitch_la_LIBADD += $(CAPNG_LDADD)

if WIN32
lib_libopenvswitch_la_LIBADD += ${PTHREAD_LIBS}
endif

lib_libopenvswitch_la_LDFLAGS = \
        $(OVS_LTINFO) \
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
	lib/ccmap.c \
	lib/ccmap.h \
	lib/cmap.c \
	lib/cmap.h \
	lib/colors.c \
	lib/colors.h \
	lib/command-line.c \
	lib/command-line.h \
	lib/compiler.h \
	lib/connectivity.c \
	lib/connectivity.h \
	lib/conntrack-icmp.c \
	lib/conntrack-private.h \
	lib/conntrack-tcp.c \
	lib/conntrack-other.c \
	lib/conntrack.c \
	lib/conntrack.h \
	lib/coverage.c \
	lib/coverage.h \
	lib/crc32c.c \
	lib/crc32c.h \
	lib/csum.c \
	lib/csum.h \
	lib/ct-dpif.c \
	lib/ct-dpif.h \
	lib/daemon.c \
	lib/daemon.h \
	lib/daemon-private.h \
	lib/db-ctl-base.c \
	lib/db-ctl-base.h \
	lib/dhcp.h \
	lib/dummy.c \
	lib/dummy.h \
	lib/dhparams.h \
	lib/dirs.h \
	lib/dpctl.c \
	lib/dpctl.h \
	lib/dp-packet.h \
	lib/dp-packet.c \
	lib/dpdk.h \
	lib/dpif-netdev.c \
	lib/dpif-netdev.h \
	lib/dpif-netdev-perf.c \
	lib/dpif-netdev-perf.h \
	lib/dpif-provider.h \
	lib/dpif.c \
	lib/dpif.h \
	lib/heap.c \
	lib/heap.h \
	lib/dynamic-string.c \
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
	lib/hmapx.c \
	lib/hmapx.h \
	lib/id-pool.c \
	lib/id-pool.h \
	lib/jhash.c \
	lib/jhash.h \
	lib/json.c \
	lib/jsonrpc.c \
	lib/jsonrpc.h \
	lib/lacp.c \
	lib/lacp.h \
	lib/latch.h \
	lib/learn.c \
	lib/learn.h \
	lib/learning-switch.c \
	lib/learning-switch.h \
	lib/lockfile.c \
	lib/lockfile.h \
	lib/mac-learning.c \
	lib/mac-learning.h \
	lib/match.c \
	lib/mcast-snooping.c \
	lib/mcast-snooping.h \
	lib/memory.c \
	lib/memory.h \
	lib/meta-flow.c \
	lib/multipath.c \
	lib/multipath.h \
	lib/namemap.c \
	lib/netdev-dpdk.h \
	lib/netdev-dummy.c \
	lib/netdev-provider.h \
	lib/netdev-vport.c \
	lib/netdev-vport.h \
	lib/netdev-vport-private.h \
	lib/netdev.c \
	lib/netdev.h \
	lib/netflow.h \
	lib/netlink.c \
	lib/netlink.h \
	lib/nx-match.c \
	lib/nx-match.h \
	lib/object-collection.c \
	lib/object-collection.h \
	lib/odp-execute.c \
	lib/odp-execute.h \
	lib/odp-util.c \
	lib/odp-util.h \
	lib/ofp-actions.c \
	lib/ofp-bundle.c \
	lib/ofp-connection.c \
	lib/ofp-ed-props.c \
	lib/ofp-errors.c \
	lib/ofp-flow.c \
	lib/ofp-group.c \
	lib/ofp-ipfix.c \
	lib/ofp-match.c \
	lib/ofp-meter.c \
	lib/ofp-monitor.c \
	lib/ofp-msgs.c \
	lib/ofp-packet.c \
	lib/ofp-parse.c \
	lib/ofp-port.c \
	lib/ofp-print.c \
	lib/ofp-prop.c \
	lib/ofp-protocol.c \
	lib/ofp-queue.c \
	lib/ofp-switch.c \
	lib/ofp-table.c \
	lib/ofp-util.c \
	lib/ofp-version-opt.h \
	lib/ofp-version-opt.c \
	lib/ofpbuf.c \
	lib/ovs-atomic-c++.h \
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
	lib/ovs-numa.c \
	lib/ovs-numa.h \
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
	lib/ovsdb-map-op.c \
	lib/ovsdb-map-op.h \
	lib/ovsdb-set-op.c \
	lib/ovsdb-set-op.h \
	lib/ovsdb-condition.h \
	lib/ovsdb-condition.c \
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
	lib/process.c \
	lib/process.h \
	lib/pvector.c \
	lib/pvector.h \
	lib/random.c \
	lib/random.h \
	lib/rconn.c \
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
	lib/simap.c \
	lib/simap.h \
	lib/skiplist.c \
	lib/skiplist.h \
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
	lib/syslog-direct.c \
	lib/syslog-direct.h \
	lib/syslog-libc.c \
	lib/syslog-libc.h \
	lib/syslog-provider.h \
	lib/table.c \
	lib/table.h \
	lib/timer.c \
	lib/timer.h \
	lib/timeval.c \
	lib/timeval.h \
	lib/tnl-neigh-cache.c \
	lib/tnl-neigh-cache.h \
	lib/tnl-ports.c \
	lib/tnl-ports.h \
	lib/netdev-native-tnl.c \
	lib/netdev-native-tnl.h \
	lib/token-bucket.c \
	lib/tun-metadata.c \
	lib/tun-metadata.h \
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
	lib/versions.h \
	lib/vl-mff-map.h \
	lib/vlan-bitmap.c \
	lib/vlan-bitmap.h \
	lib/vlog.c \
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
	lib/if-notifier-stub.c \
	lib/stream-windows.c \
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
	lib/dirs.c \
	lib/vswitch-idl.c \
	lib/vswitch-idl.h
CLEANFILES += $(nodist_lib_libopenvswitch_la_SOURCES)

lib_LTLIBRARIES += lib/libsflow.la
lib_libsflow_la_LDFLAGS = \
        $(OVS_LTINFO) \
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
	lib/dpif-netlink-rtnl.c \
	lib/dpif-netlink-rtnl.h \
	lib/if-notifier.c \
	lib/if-notifier.h \
	lib/netdev-linux.c \
	lib/netdev-linux.h \
	lib/netdev-tc-offloads.c \
	lib/netdev-tc-offloads.h \
	lib/netlink-conntrack.c \
	lib/netlink-conntrack.h \
	lib/netlink-notifier.c \
	lib/netlink-notifier.h \
	lib/netlink-protocol.h \
	lib/netlink-socket.c \
	lib/netlink-socket.h \
	lib/rtnetlink.c \
	lib/rtnetlink.h \
	lib/route-table.c \
	lib/route-table.h \
	lib/tc.c \
	lib/tc.h
endif

if DPDK_NETDEV
lib_libopenvswitch_la_SOURCES += \
	lib/dpdk.c \
	lib/netdev-dpdk.c
else
lib_libopenvswitch_la_SOURCES += \
	lib/dpdk-stub.c
endif

if WIN32
lib_libopenvswitch_la_SOURCES += \
	lib/dpif-netlink.c \
	lib/dpif-netlink.h \
	lib/dpif-netlink-rtnl.h \
	lib/netdev-windows.c \
	lib/netlink-conntrack.c \
	lib/netlink-conntrack.h \
	lib/netlink-notifier.c \
	lib/netlink-notifier.h \
	lib/netlink-protocol.h \
	lib/netlink-socket.c \
	lib/netlink-socket.h \
	lib/wmi.c \
	lib/wmi.h
endif

if HAVE_POSIX_AIO
lib_libopenvswitch_la_SOURCES += lib/async-append-aio.c
else
lib_libopenvswitch_la_SOURCES += lib/async-append-null.c
endif

if ESX
lib_libopenvswitch_la_SOURCES += \
	lib/route-table-stub.c \
	lib/if-notifier-stub.c
endif

if HAVE_IF_DL
lib_libopenvswitch_la_SOURCES += \
	lib/if-notifier-bsd.c \
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
	lib/libopenvswitch.pc \
	lib/libsflow.pc

EXTRA_DIST += \
	lib/dh1024.pem \
	lib/dh2048.pem \
	lib/dh4096.pem \
	lib/common.xml \
	lib/daemon.xml \
	lib/dirs.c.in \
	lib/db-ctl-base.xml \
	lib/ssl.xml \
	lib/ssl-bootstrap.xml \
	lib/table.xml \
	lib/vlog.xml \
	lib/unixctl.xml

MAN_FRAGMENTS += \
	lib/colors.man \
	lib/common.man \
	lib/common-syn.man \
	lib/coverage-unixctl.man \
	lib/daemon.man \
	lib/daemon-syn.man \
	lib/db-ctl-base.man \
	lib/dpctl.man \
	lib/memory-unixctl.man \
	lib/netdev-dpdk-unixctl.man \
	lib/ofp-version.man \
	lib/ovs.tmac \
	lib/service.man \
	lib/service-syn.man \
	lib/ssl-bootstrap.man \
	lib/ssl-bootstrap-syn.man \
	lib/ssl-peer-ca-cert.man \
	lib/ssl-peer-ca-cert-syn.man \
	lib/ssl.man \
	lib/ssl-syn.man \
	lib/ssl-connect.man \
	lib/ssl-connect-syn.man \
	lib/table.man \
	lib/unixctl.man \
	lib/unixctl-syn.man \
	lib/vconn-active.man \
	lib/vconn-passive.man \
	lib/vlog-unixctl.man \
	lib/vlog-syn.man \
	lib/vlog.man

# vswitch IDL
OVSIDL_BUILT += lib/vswitch-idl.c lib/vswitch-idl.h lib/vswitch-idl.ovsidl

EXTRA_DIST += lib/vswitch-idl.ann
lib/vswitch-idl.ovsidl: vswitchd/vswitch.ovsschema lib/vswitch-idl.ann
	$(AM_V_GEN)$(OVSDB_IDLC) annotate $(srcdir)/vswitchd/vswitch.ovsschema $(srcdir)/lib/vswitch-idl.ann > $@.tmp && mv $@.tmp $@

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

lib/meta-flow.inc: $(srcdir)/build-aux/extract-ofp-fields include/openvswitch/meta-flow.h
	$(AM_V_GEN)$(run_python) $< meta-flow $(srcdir)/include/openvswitch/meta-flow.h > $@.tmp
	$(AM_V_at)mv $@.tmp $@
lib/meta-flow.lo: lib/meta-flow.inc
lib/nx-match.inc: $(srcdir)/build-aux/extract-ofp-fields include/openvswitch/meta-flow.h 
	$(AM_V_GEN)$(run_python) $< nx-match $(srcdir)/include/openvswitch/meta-flow.h > $@.tmp
	$(AM_V_at)mv $@.tmp $@
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

lib/ofp-errors.inc: include/openvswitch/ofp-errors.h include/openflow/openflow-common.h \
	$(srcdir)/build-aux/extract-ofp-errors
	$(AM_V_GEN)$(run_python) $(srcdir)/build-aux/extract-ofp-errors \
		$(srcdir)/include/openvswitch/ofp-errors.h \
		$(srcdir)/include/openflow/openflow-common.h > $@.tmp && \
	mv $@.tmp $@
lib/ofp-errors.lo: lib/ofp-errors.inc
CLEANFILES += lib/ofp-errors.inc
EXTRA_DIST += build-aux/extract-ofp-errors

lib/ofp-msgs.inc: include/openvswitch/ofp-msgs.h $(srcdir)/build-aux/extract-ofp-msgs
	$(AM_V_GEN)$(run_python) $(srcdir)/build-aux/extract-ofp-msgs \
		$(srcdir)/include/openvswitch/ofp-msgs.h $@ > $@.tmp && mv $@.tmp $@
lib/ofp-msgs.lo: lib/ofp-msgs.inc
CLEANFILES += lib/ofp-msgs.inc
EXTRA_DIST += build-aux/extract-ofp-msgs

INSTALL_DATA_LOCAL += lib-install-data-local
lib-install-data-local:
	$(MKDIR_P) $(DESTDIR)$(PKIDIR)
	$(MKDIR_P) $(DESTDIR)$(sysconfdir)/openvswitch

man_MANS += lib/ovs-fields.7
CLEANFILES += lib/ovs-fields.7
lib/ovs-fields.7: $(srcdir)/build-aux/extract-ofp-fields include/openvswitch/meta-flow.h lib/meta-flow.xml
	$(AM_V_GEN)PYTHONIOENCODING=utf8 $(run_python) $< \
            --ovs-version=$(VERSION) ovs-fields \
	    $(srcdir)/include/openvswitch/meta-flow.h \
            $(srcdir)/lib/meta-flow.xml > $@.tmp
	$(AM_V_at)mv $@.tmp $@
EXTRA_DIST += lib/meta-flow.xml
