# Copyright (C) 2009, 2010, 2011, 2012, 2013, 2014 Nicira, Inc.
#
# Copying and distribution of this file, with or without modification,
# are permitted in any medium without royalty provided the copyright
# notice and this notice are preserved.  This file is offered as-is,
# without warranty of any kind.

lib_LTLIBRARIES += lib/libopenvswitch.la

lib_libopenvswitch_la_LIBADD = $(SSL_LIBS)
lib_libopenvswitch_la_LDFLAGS = -release $(VERSION)

lib_libopenvswitch_la_SOURCES = \
	lib/aes128.c \
	lib/aes128.h \
	lib/async-append.h \
	lib/backtrace.c \
	lib/backtrace.h \
	lib/bfd.c \
	lib/bfd.h \
	lib/bitmap.c \
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
	lib/dhcp.h \
	lib/dummy.c \
	lib/dummy.h \
	lib/dhparams.h \
	lib/dirs.h \
	lib/dpif-netdev.c \
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
	lib/jhash.c \
	lib/jhash.h \
	lib/json.c \
	lib/json.h \
	lib/jsonrpc.c \
	lib/jsonrpc.h \
	lib/lacp.c \
	lib/lacp.h \
	lib/latch.c \
	lib/latch.h \
	lib/learn.c \
	lib/learn.h \
	lib/learning-switch.c \
	lib/learning-switch.h \
	lib/list.c \
	lib/list.h \
	lib/lockfile.c \
	lib/lockfile.h \
	lib/mac-learning.c \
	lib/mac-learning.h \
	lib/match.c \
	lib/match.h \
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
	lib/ofp-util.def \
	lib/ofp-util.h \
	lib/ofp-version-opt.h \
	lib/ofp-version-opt.c \
	lib/ofpbuf.c \
	lib/ofpbuf.h \
	lib/ovs-atomic-c11.h \
	lib/ovs-atomic-clang.h \
	lib/ovs-atomic-flag-gcc4.7+.h \
	lib/ovs-atomic-gcc4+.c \
	lib/ovs-atomic-gcc4+.h \
	lib/ovs-atomic-gcc4.7+.h \
	lib/ovs-atomic-pthreads.c \
	lib/ovs-atomic-pthreads.h \
	lib/ovs-atomic.h \
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
	lib/poll-loop.c \
	lib/poll-loop.h \
	lib/process.c \
	lib/process.h \
	lib/random.c \
	lib/random.h \
	lib/rconn.c \
	lib/rconn.h \
	lib/reconnect.c \
	lib/reconnect.h \
	lib/sat-math.h \
	lib/seq.c \
	lib/seq.h \
	lib/sha1.c \
	lib/sha1.h \
	lib/shash.c \
	lib/shash.h \
	lib/simap.c \
	lib/simap.h \
	lib/signals.c \
	lib/signals.h \
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
	lib/stream-unix.c \
	lib/stream.c \
	lib/stream.h \
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
	lib/token-bucket.c \
	lib/token-bucket.h \
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
	lib/vlan-bitmap.c \
	lib/vlan-bitmap.h \
	lib/vlandev.c \
	lib/vlandev.h \
	lib/vlog.c \
	lib/vlog.h \
	lib/vswitch-idl.c \
	lib/vswitch-idl.h \
	lib/vtep-idl.c \
	lib/vtep-idl.h
EXTRA_DIST += lib/string.h.in

nodist_lib_libopenvswitch_la_SOURCES = \
	lib/dirs.c
CLEANFILES += $(nodist_lib_libopenvswitch_la_SOURCES)

lib_LTLIBRARIES += lib/libsflow.la
lib_libsflow_la_LDFLAGS = -release $(VERSION)
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

if LINUX_DATAPATH
lib_libopenvswitch_la_SOURCES += \
	lib/dpif-linux.c \
	lib/dpif-linux.h \
	lib/netdev-linux.c \
	lib/netdev-linux.h \
	lib/netlink-notifier.c \
	lib/netlink-notifier.h \
	lib/netlink-protocol.h \
	lib/netlink-socket.c \
	lib/netlink-socket.h \
	lib/rtnetlink-link.c \
	lib/rtnetlink-link.h \
	lib/route-table.c \
	lib/route-table.h
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
	(echo '#include "lib/dhparams.h"' &&				\
	 openssl dhparam -C -in $(srcdir)/lib/dh1024.pem -noout &&	\
	 openssl dhparam -C -in $(srcdir)/lib/dh2048.pem -noout &&	\
	 openssl dhparam -C -in $(srcdir)/lib/dh4096.pem -noout)	\
	| sed 's/\(get_dh[0-9]*\)()/\1(void)/' > lib/dhparams.c.tmp
	mv lib/dhparams.c.tmp lib/dhparams.c
else
lib_libopenvswitch_la_SOURCES += lib/stream-nossl.c
endif

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
	lib/memory-unixctl.man \
	lib/ofp-version.man \
	lib/ovs.tmac \
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
	$(srcdir)/lib/vswitch-idl.ovsidl \
	$(srcdir)/lib/vtep-idl.c \
	$(srcdir)/lib/vtep-idl.h \
	$(srcdir)/lib/vtep-idl.ovsidl

EXTRA_DIST += $(srcdir)/lib/vswitch-idl.ann
VSWITCH_IDL_FILES = \
	$(srcdir)/vswitchd/vswitch.ovsschema \
	$(srcdir)/lib/vswitch-idl.ann
$(srcdir)/lib/vswitch-idl.ovsidl: $(VSWITCH_IDL_FILES)
	$(OVSDB_IDLC) annotate $(VSWITCH_IDL_FILES) > $@.tmp
	mv $@.tmp $@

EXTRA_DIST += $(srcdir)/lib/vtep-idl.ann
VTEP_IDL_FILES = \
	$(srcdir)/vtep/vtep.ovsschema \
	$(srcdir)/lib/vtep-idl.ann
$(srcdir)/lib/vtep-idl.ovsidl: $(VTEP_IDL_FILES)
	$(OVSDB_IDLC) annotate $(VTEP_IDL_FILES) > $@.tmp
	mv $@.tmp $@

lib/dirs.c: lib/dirs.c.in Makefile
	($(ro_c) && sed < $(srcdir)/lib/dirs.c.in \
		-e 's,[@]srcdir[@],$(srcdir),g' \
		-e 's,[@]LOGDIR[@],"$(LOGDIR)",g' \
		-e 's,[@]RUNDIR[@],"$(RUNDIR)",g' \
		-e 's,[@]DBDIR[@],"$(DBDIR)",g' \
		-e 's,[@]bindir[@],"$(bindir)",g' \
		-e 's,[@]sysconfdir[@],"$(sysconfdir)",g' \
		-e 's,[@]pkgdatadir[@],"$(pkgdatadir)",g') \
	     > lib/dirs.c.tmp
	mv lib/dirs.c.tmp lib/dirs.c

$(srcdir)/lib/ofp-errors.inc: \
	lib/ofp-errors.h include/openflow/openflow-common.h \
	$(srcdir)/build-aux/extract-ofp-errors
	$(run_python) $(srcdir)/build-aux/extract-ofp-errors \
		$(srcdir)/lib/ofp-errors.h \
		$(srcdir)/include/openflow/openflow-common.h > $@.tmp
	mv $@.tmp $@
$(srcdir)/lib/ofp-errors.c: $(srcdir)/lib/ofp-errors.inc
EXTRA_DIST += build-aux/extract-ofp-errors lib/ofp-errors.inc

$(srcdir)/lib/ofp-msgs.inc: \
	lib/ofp-msgs.h $(srcdir)/build-aux/extract-ofp-msgs
	$(run_python) $(srcdir)/build-aux/extract-ofp-msgs \
		$(srcdir)/lib/ofp-msgs.h $@ > $@.tmp && mv $@.tmp $@
$(srcdir)/lib/ofp-msgs.c: $(srcdir)/lib/ofp-msgs.inc
EXTRA_DIST += build-aux/extract-ofp-msgs lib/ofp-msgs.inc

INSTALL_DATA_LOCAL += lib-install-data-local
lib-install-data-local:
	$(MKDIR_P) $(DESTDIR)$(RUNDIR)
	$(MKDIR_P) $(DESTDIR)$(PKIDIR)
	$(MKDIR_P) $(DESTDIR)$(LOGDIR)
	$(MKDIR_P) $(DESTDIR)$(DBDIR)

