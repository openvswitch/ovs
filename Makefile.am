# Copyright (C) 2007, 2008, 2009, 2010, 2011 Nicira Networks, Inc.
#
# Copying and distribution of this file, with or without modification,
# are permitted in any medium without royalty provided the copyright
# notice and this notice are preserved.  This file is offered as-is,
# without warranty of any kind.

AUTOMAKE_OPTIONS = foreign subdir-objects
ACLOCAL_AMFLAGS = -I m4
SUBDIRS = datapath

AM_CPPFLAGS = $(SSL_CFLAGS)
AM_CPPFLAGS += -I $(top_srcdir)/include
AM_CPPFLAGS += -I $(top_srcdir)/lib
AM_CPPFLAGS += -I $(top_builddir)/lib

AM_CFLAGS = -Wstrict-prototypes
AM_CFLAGS += $(WARNING_FLAGS)

if NDEBUG
AM_CPPFLAGS += -DNDEBUG
AM_CFLAGS += -fomit-frame-pointer
else
AM_LDFLAGS = -export-dynamic
endif

ALL_LOCAL =
BUILT_SOURCES =
CLEANFILES =
CLEAN_LOCAL =
DISTCLEANFILES =
EXTRA_DIST = \
	CodingStyle \
	DESIGN \
	INSTALL.KVM \
	INSTALL.Linux \
	INSTALL.RHEL \
	INSTALL.SSL \
	INSTALL.XenServer \
	INSTALL.bridge \
	INSTALL.userspace \
	NOTICE \
	PORTING \
	README-gcov \
	REPORTING-BUGS \
	SubmittingPatches \
	WHY-OVS \
	boot.sh
bin_PROGRAMS =
sbin_PROGRAMS =
bin_SCRIPTS =
DIST_HOOKS =
dist_man_MANS =
dist_pkgdata_DATA =
dist_pkgdata_SCRIPTS =
dist_sbin_SCRIPTS =
dist_scripts_SCRIPTS =
INSTALL_DATA_LOCAL =
man_MANS =
noinst_DATA =
noinst_HEADERS =
noinst_LIBRARIES =
noinst_man_MANS =
noinst_PROGRAMS =
noinst_SCRIPTS =
OVSIDL_BUILT =
pkgdata_DATA =
sbin_SCRIPTS =
scripts_SCRIPTS =
SUFFIXES =
check_DATA =

scriptsdir = $(pkgdatadir)/scripts

# This ensures that files added to EXTRA_DIST are always distributed,
# even if they are inside an Automake if...endif conditional block that is
# disabled by some particular "configure" run.  For more information, see:
# http://article.gmane.org/gmane.comp.sysutils.automake.general/10891
noinst_HEADERS += $(EXTRA_DIST)

EXTRA_DIST += \
	soexpand.pl

ro_c = echo '/* -*- mode: c; buffer-read-only: t -*- */'
ro_shell = printf '\043 Generated automatically -- do not modify!    -*- buffer-read-only: t -*-\n'

SUFFIXES += .in
.in:
	$(PERL) $(srcdir)/soexpand.pl -I$(srcdir) < $< | \
	    sed \
		-e 's,[@]PKIDIR[@],$(PKIDIR),g' \
                -e 's,[@]LOGDIR[@],$(LOGDIR),g' \
                -e 's,[@]PERL[@],$(PERL),g' \
                -e 's,[@]PYTHON[@],$(PYTHON),g' \
                -e 's,[@]RUNDIR[@],$(RUNDIR),g' \
                -e 's,[@]VERSION[@],$(VERSION),g' \
                -e 's,[@]BUILDNR[@],$(BUILDNR),g' \
                -e 's,[@]localstatedir[@],$(localstatedir),g' \
                -e 's,[@]pkgdatadir[@],$(pkgdatadir),g' \
                -e 's,[@]sysconfdir[@],$(sysconfdir),g' \
                -e 's,[@]bindir[@],$(bindir),g' \
                -e 's,[@]sbindir[@],$(sbindir),g' \
                -e 's,[@]abs_top_srcdir[@],$(abs_top_srcdir),g' \
                -e 's,[@]ovsdbmonitordir[@],$(ovsdbmonitordir),g' \
            > $@.tmp
	@if head -n 1 $@.tmp | grep '#!' > /dev/null; then \
	    echo chmod +x $@.tmp; \
	    chmod +x $@.tmp; \
	fi
	mv $@.tmp $@

# If we're checked out from a Git repository, make sure that every
# file that is in Git is distributed.
ALL_LOCAL += dist-hook-git
dist-hook-git: distfiles
	@if test -e $(srcdir)/.git && (git --version) >/dev/null 2>&1; then \
	  (cd datapath && $(MAKE) distfiles);				    \
	  (cat distfiles; sed 's|^|datapath/|' datapath/distfiles) |	    \
	    sort -u > all-distfiles;					    \
	  (cd $(srcdir) && git ls-files) | grep -v '\.gitignore$$' |	    \
	    sort -u > all-gitfiles;					    \
	  comm -1 -3 all-distfiles all-gitfiles > missing-distfiles;	    \
	  if test -s missing-distfiles; then				    \
	    echo "The distribution is missing the following files:";	    \
	    cat missing-distfiles;					    \
	    exit 1;							    \
	  fi;								    \
	fi
CLEANFILES += all-distfiles all-gitfiles missing-distfiles
# The following is based on commands for the Automake "distdir" target.
distfiles: Makefile
	@srcdirstrip=`echo "$(srcdir)" | sed 's/[].[^$$\\*]/\\\\&/g'`; \
	topsrcdirstrip=`echo "$(top_srcdir)" | sed 's/[].[^$$\\*]/\\\\&/g'`; \
	list='$(DISTFILES)'; \
	for file in $$list; do echo $$file; done | \
	  sed -e "s|^$$srcdirstrip/||;t" \
	      -e "s|^$$topsrcdirstrip/|$(top_builddir)/|;t" | sort -u > $@
CLEANFILES += distfiles

# Check that "struct vlog_ratelimit" is always declared "static".
ALL_LOCAL += rate-limit-check
rate-limit-check:
	@if test -e $(srcdir)/.git && (git --version) >/dev/null 2>&1 && \
	    git --no-pager grep -n -E '^[ 	]+struct vlog_rate_limit.*=' $(srcdir); \
         then \
	    echo "See above for list of violations of the rule that "; \
	    echo "'struct vlog_rate_limit' must always be 'static'"; \
	    exit 1; \
	 fi

dist-hook: $(DIST_HOOKS)
all-local: $(ALL_LOCAL)
clean-local: $(CLEAN_LOCAL)
install-data-local: $(INSTALL_DATA_LOCAL)
.PHONY: $(DIST_HOOKS) $(CLEAN_LOCAL) $(INSTALL_DATA_LOCAL)

include lib/automake.mk
include ofproto/automake.mk
include utilities/automake.mk
include tests/automake.mk
include include/automake.mk
include third-party/automake.mk
include debian/automake.mk
include vswitchd/automake.mk
include ovsdb/automake.mk
include rhel/automake.mk
include xenserver/automake.mk
include python/ovs/automake.mk
