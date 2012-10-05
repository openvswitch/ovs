# Copyright (C) 2009, 2010, 2011, 2012 Nicira, Inc.
#
# Copying and distribution of this file, with or without modification,
# are permitted in any medium without royalty provided the copyright
# notice and this notice are preserved.  This file is offered as-is,
# without warranty of any kind.

noinst_LIBRARIES += lib/libopenvswitch.a

lib_libopenvswitch_a_SOURCES = \
	lib/aes128.c \
	lib/aes128.h \
	lib/autopath.c \
	lib/autopath.h \
	lib/backtrace.c \
	lib/backtrace.h \
	lib/bitmap.c \
	lib/bitmap.h \
	lib/bond.c \
	lib/bond.h \
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
	lib/coverage.c \
	lib/coverage.h \
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
	lib/fatal-signal.c \
	lib/fatal-signal.h \
	lib/flow.c \
	lib/flow.h \
	lib/hash.c \
	lib/hash.h \
	lib/hmap.c \
	lib/hmap.h \
	lib/hmapx.c \
	lib/hmapx.h \
	lib/json.c \
	lib/json.h \
	lib/jsonrpc.c \
	lib/jsonrpc.h \
	lib/lacp.c \
	lib/lacp.h \
	lib/leak-checker.c \
	lib/leak-checker.h \
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
	lib/netdev.c \
	lib/netdev.h \
	lib/netflow.h \
	lib/netlink.c \
	lib/netlink.h \
	lib/nx-match.c \
	lib/nx-match.h \
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
	lib/process.c \
	lib/process.h \
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
	lib/stress.c \
	lib/stress.h \
	lib/string.c \
	lib/string.h \
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
	lib/worker.c \
	lib/worker.h

nodist_lib_libopenvswitch_a_SOURCES = \
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

if LINUX_DATAPATH
lib_libopenvswitch_a_SOURCES += \
	lib/dpif-linux.c \
	lib/dpif-linux.h \
	lib/netdev-linux.c \
	lib/netdev-linux.h \
	lib/netdev-vport.c \
	lib/netdev-vport.h \
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

if ESX
lib_libopenvswitch_a_SOURCES += \
        lib/route-table-stub.c
endif

if HAVE_IF_DL
lib_libopenvswitch_a_SOURCES += \
	lib/netdev-bsd.c \
	lib/rtbsd.c \
	lib/rtbsd.h \
	lib/route-table-bsd.c
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
else
lib_libopenvswitch_a_SOURCES += lib/stream-nossl.c
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
	lib/leak-checker.man \
	lib/memory-unixctl.man \
	lib/ovs.tmac \
	lib/ssl-bootstrap.man \
	lib/ssl-bootstrap-syn.man \
	lib/ssl-peer-ca-cert.man \
	lib/ssl.man \
	lib/ssl-syn.man \
	lib/stress-unixctl.man \
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
	$(OVSDB_IDLC) annotate $(VSWITCH_IDL_FILES) > $@.tmp
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
	lib/ofp-errors.h $(srcdir)/build-aux/extract-ofp-errors
	$(run_python) $(srcdir)/build-aux/extract-ofp-errors \
		$(srcdir)/lib/ofp-errors.h > $@.tmp && mv $@.tmp $@
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

if !USE_LINKER_SECTIONS
# All distributed sources, with names adjust properly for referencing
# from $(builddir).
all_sources = \
	`for file in $(DIST_SOURCES); do \
		if test -f $$file; then \
			echo $$file; \
		else \
			echo $(VPATH)/$$file; \
		fi; \
	 done`

lib/coverage.$(OBJEXT): lib/coverage.def
lib/coverage.def: $(DIST_SOURCES)
	sed -n 's|^COVERAGE_DEFINE(\([_a-zA-Z0-9]\{1,\}\)).*$$|COVERAGE_COUNTER(\1)|p' $(all_sources) | LC_ALL=C sort -u > $@
CLEANFILES += lib/coverage.def

lib/stress.$(OBJEXT): lib/stress.def
lib/stress.def: $(DIST_SOURCES)
	sed -n '/^STRESS_OPTION(/,/);$$/{s/);$$/)/;p}' $(all_sources) > $@
CLEANFILES += lib/stress.def

lib/vlog.$(OBJEXT): lib/vlog-modules.def
lib/vlog-modules.def: $(DIST_SOURCES)
	sed -n 's|^VLOG_DEFINE_\(THIS_\)\{0,1\}MODULE(\([_a-zA-Z0-9]\{1,\}\)).*$$|VLOG_MODULE(\2)|p' $(all_sources) | LC_ALL=C sort -u > $@
CLEANFILES += lib/vlog-modules.def
endif
