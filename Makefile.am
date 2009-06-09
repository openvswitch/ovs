AUTOMAKE_OPTIONS = foreign subdir-objects
ACLOCAL_AMFLAGS = -I m4
SUBDIRS = datapath

if ENABLE_USERSPACE
AM_CPPFLAGS = $(SSL_CFLAGS)
AM_CPPFLAGS += $(NCURSES_CFLAGS)
AM_CPPFLAGS += $(PCRE_CFLAGS)
AM_CPPFLAGS += -I $(top_srcdir)/include
AM_CPPFLAGS += -I $(top_srcdir)/lib

AM_CFLAGS = -Wstrict-prototypes

if NDEBUG
AM_CPPFLAGS += -DNDEBUG
AM_CFLAGS += -fomit-frame-pointer
else
AM_LDFLAGS = -export-dynamic
endif

CLEANFILES =
DISTCLEANFILES =
EXTRA_DIST = INSTALL.Linux INSTALL.XenServer INSTALL.SSL
TESTS =
TESTS_ENVIRONMENT =
bin_PROGRAMS =
sbin_PROGRAMS =
bin_SCRIPTS =
dist_commands_DATA =
dist_man_MANS =
dist_pkgdata_SCRIPTS =
dist_sbin_SCRIPTS =
man_MANS =
noinst_HEADERS =
noinst_LIBRARIES =
noinst_PROGRAMS =
noinst_SCRIPTS =

EXTRA_DIST += soexpand.pl

ro_c = echo '/* -*- mode: c; buffer-read-only: t -*- */'

SUFFIXES = .in
.in:
	$(PERL) $(srcdir)/soexpand.pl -I$(srcdir) < $< | \
	    sed -e 's,[@]LOGDIR[@],$(LOGDIR),g' \
		-e 's,[@]PKIDIR[@],$(PKIDIR),g' \
                -e 's,[@]RUNDIR[@],$(RUNDIR),g' \
                -e 's,[@]pkgdatadir[@],$(pkgdatadir),g' \
                -e 's,[@]PERL[@],$(PERL),g' > $@

include lib/automake.mk
include secchan/automake.mk
include utilities/automake.mk
include tests/automake.mk
include include/automake.mk
include third-party/automake.mk
include debian/automake.mk
include vswitchd/automake.mk
include xenserver/automake.mk
if HAVE_CURSES
if HAVE_PCRE
include extras/ezio/automake.mk
endif
endif
endif # ENABLE_USERSPACE
