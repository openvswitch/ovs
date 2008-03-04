include ../Make.vars

noinst_LTLIBRARIES = libopenflow.la

libopenflow_la_SOURCES = \
	buffer.c \
	command-line.c \
	dynamic-string.c \
	fatal-signal.c \
	fault.c \
	flow.c \
	hash.c \
	list.c \
	ofp-print.c \
	socket-util.c \
	util.c \
	vconn-tcp.c \
	vconn.c \
	vlog-socket.c \
	vlog.c

if HAVE_NETLINK
libopenflow_la_SOURCES += \
	dpif.c \
	netlink.c \
	vconn-netlink.c
endif
