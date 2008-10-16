bin_PROGRAMS += controller/controller
man_MANS += controller/controller.8
DISTCLEANFILES += controller/controller.8

controller_controller_SOURCES = controller/controller.c
controller_controller_LDADD = lib/libopenflow.a $(FAULT_LIBS) $(SSL_LIBS)

EXTRA_DIST += controller/controller.8.in
controller/controller.8: controller/controller.8.in Makefile
	($(do_subst) && $(ro_man)) \
		< $(srcdir)/controller/controller.8.in \
		> controller/controller.8
