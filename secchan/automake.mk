bin_PROGRAMS += secchan/secchan
man_MANS += secchan/secchan.8

secchan_secchan_SOURCES = \
	secchan/discovery.c \
	secchan/discovery.h \
	secchan/executer.c \
	secchan/executer.h \
	secchan/fail-open.c \
	secchan/fail-open.h \
	secchan/in-band.c \
	secchan/in-band.h \
	secchan/port-watcher.c \
	secchan/port-watcher.h \
	secchan/ratelimit.c \
	secchan/ratelimit.h \
	secchan/secchan.c \
	secchan/secchan.h \
	secchan/status.c \
	secchan/status.h \
	secchan/stp-secchan.c \
	secchan/stp-secchan.h
if SUPPORT_SNAT
secchan_secchan_SOURCES += \
	secchan/snat.c \
	secchan/snat.h
endif
secchan_secchan_LDADD = lib/libopenflow.a $(FAULT_LIBS) $(SSL_LIBS)

EXTRA_DIST += secchan/secchan.8.in
DISTCLEANFILES += secchan/secchan.8

include secchan/commands/automake.mk
