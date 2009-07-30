# Copyright (C) 2008, 2009 Nicira Networks, Inc.
#
# Copying and distribution of this file, with or without modification,
# are permitted in any medium without royalty provided the copyright
# notice and this notice are preserved.  This file is offered as-is,
# without warranty of any kind.

EXTRA_DIST += extras/ezio/ezio3.ti

if HAVE_CURSES
if HAVE_PCRE
install-data-hook:
	@echo tic -x $(srcdir)/extras/ezio/ezio3.ti
	@if ! tic -x $(srcdir)/extras/ezio/ezio3.ti; then			      \
	  echo "-----------------------------------------------------------"; \
	  echo "Failed to install ezio3 terminfo file.  The ezio-term";	      \
	  echo "program will not work until it has been installed.";	      \
	  echo "Probably, you need to install the 'tic' program from";	      \
	  echo "ncurses, e.g. using a command like:";			      \
	  echo "  apt-get install ncurses-bin";				      \
	  echo "and then re-run \"make install\"";			      \
	  echo "-----------------------------------------------------------"; \
	  exit 1;							      \
	fi

bin_PROGRAMS += extras/ezio/ezio-term
extras_ezio_ezio_term_SOURCES = \
	extras/ezio/byteq.c \
	extras/ezio/byteq.h \
	extras/ezio/ezio-term.c \
	extras/ezio/ezio.c \
	extras/ezio/ezio.h \
	extras/ezio/terminal.c \
	extras/ezio/terminal.h \
	extras/ezio/tty.c \
	extras/ezio/tty.h \
	extras/ezio/vt.h
if HAVE_LINUX_VT_H
extras_ezio_ezio_term_SOURCES += extras/ezio/vt-linux.c
else
extras_ezio_ezio_term_SOURCES += extras/ezio/vt-dummy.c
endif
extras_ezio_ezio_term_LDADD = lib/libopenvswitch.a $(NCURSES_LIBS)

bin_PROGRAMS += extras/ezio/ovs-switchui
extras_ezio_ovs_switchui_SOURCES = extras/ezio/ovs-switchui.c
extras_ezio_ovs_switchui_LDADD = \
	lib/libopenvswitch.a \
	$(NCURSES_LIBS) \
	$(PCRE_LIBS) \
	$(SSL_LIBS) \
	-lm
endif # HAVE_PCRE
endif # HAVE_CURSES
