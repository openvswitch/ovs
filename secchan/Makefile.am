include ../Make.vars

if HAVE_NETLINK
bin_PROGRAMS = secchan
man_MANS = secchan.8
else
bin_PROGRAMS = 
man_MANS =
endif

secchan_SOURCES = secchan.c
secchan_LDADD = ../lib/libopenflow.a $(FAULT_LIBS) $(SSL_LIBS)

EXTRA_DIST = secchan.8.in
DISTCLEANFILES = secchan.8
secchan.8: secchan.8.in Makefile
	($(do_subst) && $(ro_man)) < $(srcdir)/secchan.8.in > secchan.8
