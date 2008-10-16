bin_PROGRAMS += secchan/secchan
man_MANS += secchan/secchan.8

secchan_secchan_SOURCES = secchan/secchan.c
secchan_secchan_LDADD = lib/libopenflow.a $(FAULT_LIBS) $(SSL_LIBS)

EXTRA_DIST += secchan/secchan.8.in
DISTCLEANFILES += secchan/secchan.8
secchan/secchan.8: secchan/secchan.8.in Makefile
	($(do_subst) && $(ro_man)) \
		< $(srcdir)/secchan/secchan.8.in > secchan/secchan.8
