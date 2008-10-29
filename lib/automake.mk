noinst_LIBRARIES += lib/libopenflow.a

lib_libopenflow_a_SOURCES = \
	lib/command-line.c \
	lib/command-line.h \
	lib/compiler.h \
	lib/csum.c \
	lib/csum.h \
	lib/daemon.c \
	lib/daemon.h \
	lib/dhcp-client.c \
	lib/dhcp-client.h \
	lib/dhcp.c \
	lib/dhcp.h \
	lib/dhparams.h \
	lib/dirs.c \
	lib/dirs.h \
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
	lib/learning-switch.c \
	lib/learning-switch.h \
	lib/list.c \
	lib/list.h \
	lib/mac-learning.c \
	lib/mac-learning.h \
	lib/netdev.c \
	lib/netdev.h \
	lib/ofp-print.c \
	lib/ofp-print.h \
	lib/ofpbuf.c \
	lib/ofpbuf.h \
	lib/packets.h \
	lib/poll-loop.c \
	lib/poll-loop.h \
	lib/port-array.c \
	lib/port-array.h \
	lib/queue.c \
	lib/queue.h \
	lib/random.c \
	lib/random.h \
	lib/rconn.c \
	lib/rconn.h \
	lib/sat-math.h \
	lib/socket-util.c \
	lib/socket-util.h \
	lib/stp.c \
	lib/stp.h \
	lib/timeval.c \
	lib/timeval.h \
	lib/type-props.h \
	lib/util.c \
	lib/util.h \
	lib/vconn-provider.h \
	lib/vconn-ssl.h \
	lib/vconn-stream.c \
	lib/vconn-stream.h \
	lib/vconn-tcp.c \
	lib/vconn-unix.c \
	lib/vconn.c \
	lib/vconn.h \
	lib/vlog-modules.def \
	lib/vlog-socket.c \
	lib/vlog-socket.h \
	lib/vlog.c \
	lib/vlog.h \
	lib/xtoxll.h

if HAVE_NETLINK
lib_libopenflow_a_SOURCES += \
	lib/dpif.c \
	lib/dpif.h \
	lib/netlink-protocol.h \
	lib/netlink.c \
	lib/netlink.h \
	lib/vconn-netlink.c
endif

if HAVE_OPENSSL
lib_libopenflow_a_SOURCES += \
	lib/vconn-ssl.c 
nodist_lib_libopenflow_a_SOURCES = lib/dhparams.c
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

CLEANFILES += lib/dirs.c
lib/dirs.c: Makefile
	($(ro_c) && \
	 echo 'const char ofp_pkgdatadir[] = "$(pkgdatadir$)";' && \
	 echo 'const char ofp_rundir[] = "@RUNDIR@";' && \
	 echo 'const char ofp_logdir[] = "@LOGDIR@";') > lib/dirs.c.tmp
	mv lib/dirs.c.tmp lib/dirs.c

install-data-local:
	$(MKDIR_P) $(DESTDIR)$(RUNDIR)
	$(MKDIR_P) $(DESTDIR)$(PKIDIR)
	$(MKDIR_P) $(DESTDIR)$(LOGDIR)
