# Copyright (C) 2007-2017 Nicira, Inc.
#
# Copying and distribution of this file, with or without modification,
# are permitted in any medium without royalty provided the copyright
# notice and this notice are preserved.  This file is offered as-is,
# without warranty of any kind.

AUTOMAKE_OPTIONS = foreign subdir-objects
ACLOCAL_AMFLAGS = -I m4
SUBDIRS = datapath

AM_CPPFLAGS = $(SSL_CFLAGS)
AM_LDFLAGS = $(SSL_LDFLAGS)
AM_LDFLAGS += $(OVS_LDFLAGS)

if WIN32
AM_CPPFLAGS += -I $(top_srcdir)/include/windows
AM_CPPFLAGS += -I $(top_srcdir)/datapath-windows/include
AM_CPPFLAGS += $(PTHREAD_INCLUDES)
AM_CPPFLAGS += $(MSVC_CFLAGS)
AM_LDFLAGS += $(PTHREAD_LDFLAGS)
AM_LDFLAGS += $(MSVC64_LDFLAGS)
PLATFORM = $(MSVC_PLATFORM)
endif

AM_CPPFLAGS += -I $(top_srcdir)/include
AM_CPPFLAGS += -I $(top_builddir)/include
AM_CPPFLAGS += -I $(top_srcdir)/lib
AM_CPPFLAGS += -I $(top_builddir)/lib

AM_CPPFLAGS += $(SSL_INCLUDES)

AM_CFLAGS = -Wstrict-prototypes
AM_CFLAGS += $(WARNING_FLAGS)
AM_CFLAGS += $(OVS_CFLAGS)

if DPDK_NETDEV
AM_CFLAGS += -D_FILE_OFFSET_BITS=64
DPDKSTRIP_FLAGS = --dpdk
else
DPDKSTRIP_FLAGS = --nodpdk
endif

if NDEBUG
AM_CPPFLAGS += -DNDEBUG
AM_CFLAGS += -fomit-frame-pointer
endif

AM_CTAGSFLAGS = $(OVS_CTAGS_IDENTIFIERS_LIST)

if WIN32
psep=";"
else
psep=":"
endif
# PYTHONDONTWRITEBYTECODE=yes keeps Python from creating .pyc and .pyo
# files.  Creating .py[co] works OK for any given version of Open
# vSwitch, but it causes trouble if you switch from a version with
# foo/__init__.py into an (older) version with plain foo.py, since
# foo/__init__.pyc will cause Python to ignore foo.py.
run_python = \
	PYTHONPATH=$(top_srcdir)/python$(psep)$$PYTHONPATH \
	PYTHONDONTWRITEBYTECODE=yes $(PYTHON)

ALL_LOCAL =
BUILT_SOURCES =
CLEANFILES =
CLEAN_LOCAL =
DISTCLEANFILES =
PYCOV_CLEAN_FILES = build-aux/check-structs,cover

EXTRA_DIST = \
	AUTHORS.rst \
	CONTRIBUTING.rst \
	LICENSE \
	MAINTAINERS.rst \
	README.rst \
	NOTICE \
	.travis.yml \
	.travis/linux-build.sh \
	.travis/linux-prepare.sh \
	.travis/osx-build.sh \
	.travis/osx-prepare.sh \
	appveyor.yml \
	boot.sh \
	poc/builders/Vagrantfile \
	poc/playbook-centos-builder.yml \
	poc/playbook-fedora-builder.yml \
	poc/playbook-ubuntu-builder.yml \
	$(MAN_FRAGMENTS) \
	$(MAN_ROOTS) \
	Vagrantfile \
	Vagrantfile-FreeBSD \
	.mailmap
bin_PROGRAMS =
sbin_PROGRAMS =
bin_SCRIPTS =
DIST_HOOKS =
dist_man_MANS =
dist_pkgdata_DATA =
dist_pkgdata_SCRIPTS =
dist_sbin_SCRIPTS =
dist_scripts_SCRIPTS =
dist_scripts_DATA =
INSTALL_DATA_LOCAL =
UNINSTALL_LOCAL =
man_MANS =
MAN_FRAGMENTS =
MAN_ROOTS =
noinst_DATA =
noinst_HEADERS =
lib_LTLIBRARIES =
noinst_LTLIBRARIES =
noinst_man_MANS =
noinst_PROGRAMS =
noinst_SCRIPTS =
OVSIDL_BUILT =
pkgdata_DATA =
sbin_SCRIPTS =
scripts_SCRIPTS =
completion_SCRIPTS =
scripts_DATA =
SUFFIXES =
check_DATA =
check_SCRIPTS =
pkgconfig_DATA =
FLAKE8_PYFILES =

if ENABLE_SPARSE_BY_DEFAULT
C ?= 1
endif

scriptsdir = $(pkgdatadir)/scripts
completiondir = $(sysconfdir)/bash_completion.d
pkgconfigdir = $(libdir)/pkgconfig

# This ensures that files added to EXTRA_DIST are always distributed,
# even if they are inside an Automake if...endif conditional block that is
# disabled by some particular "configure" run.  For more information, see:
# http://article.gmane.org/gmane.comp.sysutils.automake.general/10891
noinst_HEADERS += $(EXTRA_DIST)

ro_c = echo '/* -*- mode: c; buffer-read-only: t -*- */'
ro_shell = printf '\043 Generated automatically -- do not modify!    -*- buffer-read-only: t -*-\n'

SUFFIXES += .in
.in:
	$(AM_V_GEN)PYTHONPATH=$$PYTHONPATH$(psep)$(srcdir)/python $(PYTHON) $(srcdir)/build-aux/soexpand.py -I$(srcdir) < $< | \
	  $(PYTHON) $(srcdir)/build-aux/dpdkstrip.py $(DPDKSTRIP_FLAGS) | \
	  sed \
	    -e 's,[@]PKIDIR[@],$(PKIDIR),g' \
	    -e 's,[@]LOGDIR[@],$(LOGDIR),g' \
	    -e 's,[@]DBDIR[@],$(DBDIR),g' \
	    -e 's,[@]PYTHON[@],$(PYTHON),g' \
	    -e 's,[@]RUNDIR[@],$(RUNDIR),g' \
	    -e 's,[@]VERSION[@],$(VERSION),g' \
	    -e 's,[@]localstatedir[@],$(localstatedir),g' \
	    -e 's,[@]pkgdatadir[@],$(pkgdatadir),g' \
	    -e 's,[@]sysconfdir[@],$(sysconfdir),g' \
	    -e 's,[@]bindir[@],$(bindir),g' \
	    -e 's,[@]sbindir[@],$(sbindir),g' \
	    -e 's,[@]abs_builddir[@],$(abs_builddir),g' \
	    -e 's,[@]abs_top_srcdir[@],$(abs_top_srcdir),g' \
	  > $@.tmp
	@if head -n 1 $@.tmp | grep '#!' > /dev/null; then \
	  chmod +x $@.tmp; \
	fi
	$(AM_V_at) mv $@.tmp $@

SUFFIXES += .xml
%: %.xml
	$(AM_V_GEN)$(run_python) $(srcdir)/build-aux/xml2nroff $< > $@.tmp \
	  -I $(srcdir) \
	  --version=$(VERSION) \
	  PKIDIR='$(PKIDIR)' \
	  LOGDIR='$(LOGDIR)' \
	  DBDIR='$(DBDIR)' \
	  PYTHON='$(PYTHON)' \
	  RUNDIR='$(RUNDIR)' \
	  VERSION='$(VERSION)' \
	  localstatedir='$(localstatedir)' \
	  pkgdatadir='$(pkgdatadir)' \
	  sysconfdir='$(sysconfdir)' \
	  bindir='$(bindir)' \
	  sbindir='$(sbindir)'
	$(AM_v_at)mv $@.tmp $@

clean-pycov:
	cd $(srcdir) && rm -f $(PYCOV_CLEAN_FILES)
CLEAN_LOCAL += clean-pycov
.PHONY: clean-pycov

# If we're checked out from a Git repository, make sure that every
# file that is in Git is distributed.
ALL_LOCAL += dist-hook-git
dist-hook-git: distfiles
	@if test -e $(srcdir)/.git && (git --version) >/dev/null 2>&1; then \
	  (cd datapath && $(MAKE) distfiles); \
	  (cat distfiles; sed 's|^|datapath/|' datapath/distfiles) | \
	    LC_ALL=C sort -u > all-distfiles; \
	  (cd $(srcdir) && git ls-files) | grep -v '\.gitignore$$' | \
	    LC_ALL=C sort -u > all-gitfiles; \
	  LC_ALL=C comm -1 -3 all-distfiles all-gitfiles > missing-distfiles; \
	  if test -s missing-distfiles; then \
	    echo "The following files are in git but not the distribution:"; \
	    cat missing-distfiles; \
	    exit 1; \
	  fi; \
	  if LC_ALL=C grep '\.gitignore$$' all-distfiles; then \
	    echo "See above for list of files that are distributed but"; \
	    echo "should not be."; \
	    exit 1; \
	  fi \
	fi
CLEANFILES += all-distfiles all-gitfiles missing-distfiles
# The following is based on commands for the Automake "distdir" target.
distfiles: Makefile
	@srcdirstrip=`echo "$(srcdir)" | sed 's/[].[^$$\\*]/\\\\&/g'`; \
	topsrcdirstrip=`echo "$(top_srcdir)" | sed 's/[].[^$$\\*]/\\\\&/g'`; \
	list='$(DISTFILES)'; \
	for file in $$list; do echo $$file; done | \
	  sed -e "s|^$$srcdirstrip/||;t" \
	      -e "s|^$$topsrcdirstrip/|$(top_builddir)/|;t" | \
	  LC_ALL=C sort -u > $@
CLEANFILES += distfiles
.PHONY: dist-hook-git

# Check that every .c file includes <config.h>.
ALL_LOCAL += config-h-check
config-h-check:
	@cd $(srcdir); \
	if test -e .git && (git --version) >/dev/null 2>&1 && \
	  git --no-pager grep -L '#include <config\.h>' `git ls-files | grep '\.c$$' | \
	    grep -vE '^datapath|^lib/sflow|^third-party|^datapath-windows|^python'`; \
	then \
	  echo "See above for list of violations of the rule that"; \
	  echo "every C source file must #include <config.h>."; \
	  exit 1; \
	fi; \
	if grep '#include' include/openvswitch/*.h | \
	    grep -vE '(<.*>)|("openvswitch)|("openflow)'; \
	then \
	  echo "See above for list of violations of the rule that"; \
	  echo "public openvswitch header file should not include internal library."; \
	  exit 1; \
	fi
.PHONY: config-h-check

# Check for printf() type modifiers that MSVC doesn't support.
ALL_LOCAL += printf-check
printf-check:
	@cd $(srcdir); \
	if test -e .git && (git --version) >/dev/null 2>&1 && \
	  git --no-pager grep -n -E -e '%[-+ #0-9.*]*([ztj]|hh)' --and --not -e 'ovs_scan' `git ls-files | grep '\.[ch]$$' | \
	    grep -vE '^datapath|^lib/sflow|^third-party'`; \
	then \
	  echo "See above for list of violations of the rule that"; \
	  echo "'z', 't', 'j', 'hh' printf() type modifiers are"; \
	  echo "forbidden.  See coding-style.rst for replacements."; \
	  exit 1; \
	fi
.PHONY: printf-check

# Check that certain data structures are always declared "static".
ALL_LOCAL += static-check
static-check:
	@if test -e $(srcdir)/.git && (git --version) >/dev/null 2>&1 && \
	  git --no-pager grep -n -E '^[ 	]+(struct vlog_rate_limit|pthread_once_t|struct ovsthread_once).*=' $(srcdir); \
	then \
	  echo "See above for list of violations of the rule that "; \
	  echo "certain data structures must always be 'static'"; \
	  exit 1; \
	fi
.PHONY: static-check

# Check that assert.h is not used outside a whitelist of files.
ALL_LOCAL += check-assert-h-usage
check-assert-h-usage:
	@if test -e $(srcdir)/.git && (git --version) >/dev/null 2>&1 && \
	  (cd $(srcdir) && git --no-pager grep -l -E '[<]assert.h[>]') | \
	  $(EGREP) -v '^lib/(sflow_receiver|vlog).c$$|^tests/'; \
	then \
	  echo "Files listed above unexpectedly #include <""assert.h"">."; \
	  echo "Please use ovs_assert (from util.h) instead of assert."; \
	  exit 1; \
	fi
.PHONY: check-assert-h-usage

# Check that LITTLE_ENDIAN and BIG_ENDIAN are not used unless BYTE_ORDER is
# also mentioned.  (<endian.h> always defines the former two constants.  They
# must be compared to BYTE_ORDER to get the machine's correct endianness.  But
# it is better to use WORDS_BIGENDIAN.)
ALL_LOCAL += check-endian
check-endian:
	@if test -e $(srcdir)/.git && (git --version) >/dev/null 2>&1 && \
	  (cd $(srcdir) && git --no-pager grep -l -E \
	   -e 'BIG_ENDIAN|LITTLE_ENDIAN' --and --not -e 'BYTE_ORDER' | \
	  $(EGREP) -v '^datapath/'); \
	then \
	  echo "See above for list of files that misuse LITTLE""_ENDIAN"; \
	  echo "or BIG""_ENDIAN.  Please use WORDS_BIGENDIAN instead."; \
	  exit 1; \
	fi
.PHONY: check-endian

ALL_LOCAL += check-echo-n
check-echo-n:
	@if test -e $(srcdir)/.git && (git --version) >/dev/null 2>&1 && \
	  git --no-pager grep -n 'echo'' -n' $(srcdir); \
	then \
	  echo "See above for uses for \"echo"" -n\", which is non-POSIX"; \
	  echo "and does not work with all shells.  Use \"printf\" instead."; \
	  exit 1; \
	fi
.PHONY: check-echo-n

ALL_LOCAL += check-tabs
check-tabs:
	@cd $(srcdir); \
	if test -e .git && (git --version) >/dev/null 2>&1 && \
	  grep -ln "^	" \
	    `git ls-files \
	      | grep -v -f build-aux/initial-tab-whitelist` /dev/null \
	      | $(EGREP) -v ':[ 	]*/?\*'; \
	then \
	  echo "See above for files that use tabs for indentation."; \
	  echo "Please use spaces instead."; \
	  exit 1; \
	fi
.PHONY: check-tabs

ALL_LOCAL += thread-safety-check
thread-safety-check:
	@cd $(srcdir); \
	if test -e .git && (git --version) >/dev/null 2>&1 && \
	  grep -n -f build-aux/thread-safety-blacklist \
	    `git ls-files | grep '\.[ch]$$' \
	      | $(EGREP) -v '^datapath|^lib/sflow|^third-party'` /dev/null \
	      | $(EGREP) -v ':[ 	]*/?\*'; \
	then \
	  echo "See above for list of calls to functions that are"; \
	  echo "blacklisted due to thread safety issues"; \
	  exit 1; \
	fi
EXTRA_DIST += build-aux/thread-safety-blacklist
.PHONY: thread-safety-check

# Check that "ip" is used in preference to "ifconfig", because
# "ifconfig" is not installed ubiquitously anymore.
ALL_LOCAL += check-ifconfig
check-ifconfig:
	@if test -e $(srcdir)/.git && (git --version) >/dev/null 2>&1 && \
	  (cd $(srcdir) && git --no-pager grep -l -E -e 'ifconfig' | \
           $(EGREP) -v 'Makefile.am|ovs-vsctl-bashcomp|openvswitch-custom\.te'); \
	then \
	  echo "See above for list of files that use or reference"; \
          echo "'ifconfig'.  Please use 'ip' instead."; \
	  exit 1; \
	fi
.PHONY: check-ifconfig

if HAVE_GROFF
ALL_LOCAL += manpage-check
manpage-check: $(man_MANS) $(dist_man_MANS) $(noinst_man_MANS)
	@error=false; \
	for manpage in $?; do \
	  LANG=en_US.UTF-8 groff -w mac -w delim -w escape -w input -w missing -w tab -T utf8 -man -p -z $$manpage >$@.tmp 2>&1; \
	  if grep warning: $@.tmp; then error=:; fi; \
	  rm -f $@.tmp; \
	done; \
	if $$error; then exit 1; else touch $@; fi
	$(AM_V_GEN) touch -c $@
CLEANFILES += manpage-check
endif

if HAVE_FLAKE8
ALL_LOCAL += flake8-check
# http://flake8.readthedocs.org/en/latest/user/error-codes.html
# All warnings explicitly selected or ignored should be listed below.
#
# E***, W*** -- warnings from pep8
#   E121 continuation line under-indented for hanging indent (only from flake8 v2.0)
#   E123 closing bracket does not match indentation of opening bracket's line
#   E125 continuation line with same indent as next logical line (only from flake8 v2.0)
#   E126 continuation line over-indented for hanging indent
#   E127 continuation line over-indented for visual indent
#   E128 continuation line under-indented for visual indent
#   E129 visually indented line with same indent as next logical line
#   E131 continuation line unaligned for hanging indent
#   E722 do not use bare except, specify exception instead
#   W503 line break before binary operator
# F*** -- warnings native to flake8
#   F811 redefinition of unused <name> from line <N> (only from flake8 v2.0)
# D*** -- warnings from flake8-docstrings plugin
# H*** -- warnings from flake8 hacking plugin (custom style checks beyond PEP8)
#   H231 Python 3.x incompatible 'except x,y:' construct
#   H232 Python 3.x incompatible octal 077 should be written as 0o77
#   H233 Python 3.x incompatible use of print operator
#   H238 old style class declaration, use new style (inherit from `object`)
FLAKE8_SELECT = H231,H232,H233,H238
FLAKE8_IGNORE = E121,E123,E125,E126,E127,E128,E129,E131,E722,W503,F811,D,H,I
flake8-check: $(FLAKE8_PYFILES)
	$(FLAKE8_WERROR)$(AM_V_GEN) \
	  src='$^' && \
	  flake8 $$src --select=$(FLAKE8_SELECT) $(FLAKE8_FLAGS) && \
	  flake8 $$src --ignore=$(FLAKE8_IGNORE) $(FLAKE8_FLAGS) && \
	  touch $@
endif
CLEANFILES += flake8-check

include $(srcdir)/manpages.mk
$(srcdir)/manpages.mk: $(MAN_ROOTS) build-aux/sodepends.py python/build/soutil.py
	@PYTHONPATH=$$PYTHONPATH$(psep)$(srcdir)/python $(PYTHON) $(srcdir)/build-aux/sodepends.py -I. -I$(srcdir) $(MAN_ROOTS) >$(@F).tmp
	@if cmp -s $(@F).tmp $@; then \
	  touch $@; \
	  rm -f $(@F).tmp; \
	else \
	  mv $(@F).tmp $@; \
	fi
CLEANFILES += manpage-dep-check

if VSTUDIO_DDK
ALL_LOCAL += ovsext
ARCH = x64
ovsext: datapath-windows/ovsext.sln $(srcdir)/datapath-windows/include/OvsDpInterface.h
if VSTUDIO_WIN8
	MSBuild.exe //nologo //maxcpucount datapath-windows/ovsext.sln /target:Build /property:Configuration="Win8$(VSTUDIO_CONFIG)" /property:Version="$(PACKAGE_VERSION)" //p:Platform=$(ARCH)
endif
if VSTUDIO_WIN8_1
	MSBuild.exe //nologo //maxcpucount datapath-windows/ovsext.sln /target:Build /property:Configuration="Win8.1$(VSTUDIO_CONFIG)" /property:Version="$(PACKAGE_VERSION)" //p:Platform=$(ARCH)
endif
if VSTUDIO_WIN10
	MSBuild.exe //nologo //maxcpucount datapath-windows/ovsext.sln /target:Build /property:Configuration="Win10$(VSTUDIO_CONFIG)" /property:Version="$(PACKAGE_VERSION)" //p:Platform=$(ARCH)
endif


CLEAN_LOCAL += ovsext_clean
ovsext_clean: datapath-windows/ovsext.sln
if VSTUDIO_WIN8
	MSBuild.exe //nologo //maxcpucount datapath-windows/ovsext.sln /target:Clean /property:Configuration="Win8$(VSTUDIO_CONFIG)" /property:Version="$(PACKAGE_VERSION)" //p:Platform=$(ARCH)
endif
if VSTUDIO_WIN8_1
	MSBuild.exe //nologo //maxcpucount datapath-windows/ovsext.sln /target:Clean /property:Configuration="Win8.1$(VSTUDIO_CONFIG)" /property:Version="$(PACKAGE_VERSION)" //p:Platform=$(ARCH)
endif
if VSTUDIO_WIN10
	MSBuild.exe //nologo //maxcpucount datapath-windows/ovsext.sln /target:Clean /property:Configuration="Win10$(VSTUDIO_CONFIG)" /property:Version="$(PACKAGE_VERSION)" //p:Platform=$(ARCH)
endif
endif
.PHONY: ovsext

clang-analyze: clean
	@which clang scan-build >/dev/null 2>&1 || \
	  (echo "Unable to find clang/scan-build, Install clang,clang-analyzer packages"; exit 1)
	@$(MKDIR_P) "$(srcdir)/tests/clang-analyzer-results"
	@scan-build -o $(srcdir)/tests/clang-analyzer-results --use-cc=$(CC) $(MAKE)
.PHONY: clang-analyze

dist-hook: $(DIST_HOOKS)
all-local: $(ALL_LOCAL)
clean-local: $(CLEAN_LOCAL)
install-data-local: $(INSTALL_DATA_LOCAL)
uninstall-local: $(UNINSTALL_LOCAL)
.PHONY: $(DIST_HOOKS) $(CLEAN_LOCAL) $(INSTALL_DATA_LOCAL) $(UNINSTALL_LOCAL)

modules_install:
if LINUX_ENABLED
	cd datapath/linux && $(MAKE) modules_install
endif

dist-docs:
	VERSION=$(VERSION) MAKE='$(MAKE)' $(srcdir)/build-aux/dist-docs $(srcdir) $(docs)
.PHONY: dist-docs

include Documentation/automake.mk
include m4/automake.mk
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
include python/automake.mk
include tutorial/automake.mk
include vtep/automake.mk
include datapath-windows/automake.mk
include datapath-windows/include/automake.mk
include windows/automake.mk
include ovn/automake.mk
include selinux/automake.mk
include build-aux/automake.mk
