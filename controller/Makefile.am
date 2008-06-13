include ../Make.vars

bin_PROGRAMS = controller
man_MANS = controller.8
DISTCLEANFILES = controller.8

controller_SOURCES = controller.c
controller_LDADD = ../lib/libopenflow.la -ldl

EXTRA_DIST = controller.8.in
controller.8: controller.8.in Makefile
	($(do_subst) && $(ro_man)) < $(srcdir)/controller.8.in > controller.8
