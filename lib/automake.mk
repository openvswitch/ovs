noinst_LIBRARIES += lib/libopenflow.a

lib_libopenflow_a_SOURCES = \
	lib/command-line.c \
	lib/csum.c \
	lib/daemon.c \
	lib/dhcp-client.c \
	lib/dhcp.c \
	lib/dynamic-string.c \
	lib/fatal-signal.c \
	lib/fault.c \
	lib/flow.c \
	lib/hash.c \
	lib/learning-switch.c \
	lib/list.c \
	lib/mac-learning.c \
	lib/netdev.c \
	lib/ofpbuf.c \
	lib/ofp-print.c \
	lib/poll-loop.c \
	lib/port-array.c \
	lib/queue.c \
	lib/random.c \
	lib/rconn.c \
	lib/socket-util.c \
	lib/timeval.c \
	lib/stp.c \
	lib/util.c \
	lib/vconn-tcp.c \
	lib/vconn-unix.c \
	lib/vconn-stream.c \
	lib/vconn.c \
	lib/vlog-socket.c \
	lib/dirs.c \
	lib/vlog.c

if HAVE_NETLINK
lib_libopenflow_a_SOURCES += \
	lib/dpif.c \
	lib/netlink.c \
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
	 echo 'const char ofp_rundir[] = "@RUNDIR@";' && \
	 echo 'const char ofp_logdir[] = "@LOGDIR@";') > lib/dirs.c.tmp
	mv lib/dirs.c.tmp lib/dirs.c

install-data-local:
	$(MKDIR_P) $(DESTDIR)$(RUNDIR)
	$(MKDIR_P) $(DESTDIR)$(PKIDIR)
	$(MKDIR_P) $(DESTDIR)$(LOGDIR)
