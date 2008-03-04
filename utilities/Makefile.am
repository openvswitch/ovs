include ../Make.vars

bin_PROGRAMS = vlogconf
if HAVE_NETLINK
bin_PROGRAMS += dpctl
endif

dpctl_SOURCES = dpctl.c
dpctl_LDADD = ../lib/libopenflow.la

vlogconf_SOURCES = vlogconf.c
vlogconf_LDADD = ../lib/libopenflow.la
