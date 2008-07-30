include ../Make.vars

noinst_LIBRARIES = libopenflow.a

libopenflow_a_SOURCES = \
	buffer.c \
	command-line.c \
	csum.c \
	daemon.c \
	dhcp-client.c \
	dhcp.c \
	dynamic-string.c \
	fatal-signal.c \
	fault.c \
	flow.c \
	hash.c \
	learning-switch.c \
	list.c \
	mac-learning.c \
	netdev.c \
	ofp-print.c \
	poll-loop.c \
	queue.c \
	random.c \
	rconn.c \
	socket-util.c \
	util.c \
	vconn-tcp.c \
	vconn-unix.c \
	vconn-stream.c \
	vconn.c \
	vlog-socket.c \
	vlog.c

if HAVE_NETLINK
libopenflow_a_SOURCES += \
	dpif.c \
	netlink.c \
	vconn-netlink.c
endif

if HAVE_OPENSSL
libopenflow_a_SOURCES += \
	vconn-ssl.c 
nodist_libopenflow_a_SOURCES = dhparams.c
dhparams.c: dh1024.pem dh2048.pem dh4096.pem
	(echo '#include "dhparams.h"' &&			\
	 openssl dhparam -C -in $(srcdir)/dh1024.pem -noout &&	\
	 openssl dhparam -C -in $(srcdir)/dh2048.pem -noout &&	\
	 openssl dhparam -C -in $(srcdir)/dh4096.pem -noout)	\
	| sed 's/\(get_dh[0-9]*\)()/\1(void)/' > dhparams.c.tmp
	mv dhparams.c.tmp dhparams.c
endif

EXTRA_DIST = dh1024.pem dh2048.pem dh4096.pem dhparams.h
