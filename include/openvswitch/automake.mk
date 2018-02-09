openvswitchincludedir = $(includedir)/openvswitch
openvswitchinclude_HEADERS = \
	include/openvswitch/compiler.h \
	include/openvswitch/dynamic-string.h \
	include/openvswitch/hmap.h \
	include/openvswitch/flow.h \
	include/openvswitch/geneve.h \
	include/openvswitch/json.h \
	include/openvswitch/list.h \
	include/openvswitch/netdev.h \
	include/openvswitch/match.h \
	include/openvswitch/meta-flow.h \
	include/openvswitch/namemap.h \
	include/openvswitch/ofpbuf.h \
	include/openvswitch/ofp-actions.h \
	include/openvswitch/ofp-bundle.h \
	include/openvswitch/ofp-connection.h \
	include/openvswitch/ofp-ed-props.h \
	include/openvswitch/ofp-errors.h \
	include/openvswitch/ofp-flow.h \
	include/openvswitch/ofp-group.h \
	include/openvswitch/ofp-ipfix.h \
	include/openvswitch/ofp-match.h \
	include/openvswitch/ofp-meter.h \
	include/openvswitch/ofp-monitor.h \
	include/openvswitch/ofp-msgs.h \
	include/openvswitch/ofp-packet.h \
	include/openvswitch/ofp-parse.h \
	include/openvswitch/ofp-port.h \
	include/openvswitch/ofp-print.h \
	include/openvswitch/ofp-prop.h \
	include/openvswitch/ofp-protocol.h \
	include/openvswitch/ofp-queue.h \
	include/openvswitch/ofp-switch.h \
	include/openvswitch/ofp-table.h \
	include/openvswitch/ofp-util.h \
	include/openvswitch/packets.h \
	include/openvswitch/poll-loop.h \
	include/openvswitch/rconn.h \
	include/openvswitch/shash.h \
	include/openvswitch/thread.h \
	include/openvswitch/token-bucket.h \
	include/openvswitch/tun-metadata.h \
	include/openvswitch/type-props.h \
	include/openvswitch/types.h \
	include/openvswitch/util.h \
	include/openvswitch/uuid.h \
	include/openvswitch/version.h \
	include/openvswitch/vconn.h \
	include/openvswitch/vlog.h \
	include/openvswitch/nsh.h

if HAVE_CXX
# OVS does not use C++ itself, but it provides public header files
# that a C++ compiler should accept, so when --enable-Werror is in
# effect and a C++ compiler is available, we build a C++ source file
# that #includes all the public headers, as a way to ensure that they
# are acceptable as C++.
noinst_LTLIBRARIES += include/openvswitch/libcxxtest.la
nodist_include_openvswitch_libcxxtest_la_SOURCES = include/openvswitch/cxxtest.cc
include/openvswitch/cxxtest.cc: \
	include/openvswitch/automake.mk $(top_builddir)/config.status
	$(AM_V_GEN){ echo "#include <config.h>"; \
	for header in $(openvswitchinclude_HEADERS); do	\
	  echo $$header; \
	done | sed 's,^include/\(.*\)$$,#include <\1>,'; } > $@
endif

# OVS does not use C++ itself, but it provides public header files
# that a C++ compiler should accept, so we make sure that every public
# header file has the proper extern declaration for use with C++.
#
# Some header files don't declare any external functions, so they
# don't really need extern "C".  We only white list a couple of these
# below, which are the ones that seem unlikely to ever declare
# external functions.  For the rest, we add extern "C" anyway; it
# doesn't hurt.
ALL_LOCAL += cxx-check
cxx-check: $(openvswitchinclude_HEADERS)
	@if LC_ALL=C grep -L 'extern "C"' $^ | \
          $(EGREP) -v 'version.h|compiler.h'; \
	then \
	    echo "See above list of public headers lacking 'extern \"C\"'."; \
	    exit 1; \
	fi
	$(AM_V_GEN)touch $@
CLEANFILES += cxx-check
