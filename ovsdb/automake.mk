# libovsdb
lib_LTLIBRARIES += ovsdb/libovsdb.la
ovsdb_libovsdb_la_LDFLAGS = \
        -version-info $(LT_CURRENT):$(LT_REVISION):$(LT_AGE) \
        -Wl,--version-script=$(top_builddir)/ovsdb/libovsdb.sym \
        $(AM_LDFLAGS)
ovsdb_libovsdb_la_SOURCES = \
	ovsdb/column.c \
	ovsdb/column.h \
	ovsdb/condition.c \
	ovsdb/condition.h \
	ovsdb/execution.c \
	ovsdb/file.c \
	ovsdb/file.h \
	ovsdb/jsonrpc-server.c \
	ovsdb/jsonrpc-server.h \
	ovsdb/log.c \
	ovsdb/log.h \
	ovsdb/mutation.c \
	ovsdb/mutation.h \
	ovsdb/ovsdb.c \
	ovsdb/ovsdb.h \
	ovsdb/monitor.c \
	ovsdb/monitor.h \
	ovsdb/query.c \
	ovsdb/query.h \
	ovsdb/row.c \
	ovsdb/row.h \
	ovsdb/server.c \
	ovsdb/server.h \
	ovsdb/table.c \
	ovsdb/table.h \
	ovsdb/trigger.c \
	ovsdb/trigger.h \
	ovsdb/transaction.c \
	ovsdb/transaction.h
ovsdb_libovsdb_la_CFLAGS = $(AM_CFLAGS)
ovsdb_libovsdb_la_CPPFLAGS = $(AM_CPPFLAGS)

pkgconfig_DATA += \
	$(srcdir)/ovsdb/libovsdb.pc

MAN_FRAGMENTS += \
	ovsdb/remote-active.man \
	ovsdb/remote-passive.man

# ovsdb-tool
bin_PROGRAMS += ovsdb/ovsdb-tool
ovsdb_ovsdb_tool_SOURCES = ovsdb/ovsdb-tool.c
ovsdb_ovsdb_tool_LDADD = ovsdb/libovsdb.la lib/libopenvswitch.la
# ovsdb-tool.1
man_MANS += ovsdb/ovsdb-tool.1
DISTCLEANFILES += ovsdb/ovsdb-tool.1
MAN_ROOTS += ovsdb/ovsdb-tool.1.in

# ovsdb-client
bin_PROGRAMS += ovsdb/ovsdb-client
ovsdb_ovsdb_client_SOURCES = ovsdb/ovsdb-client.c
ovsdb_ovsdb_client_LDADD = ovsdb/libovsdb.la lib/libopenvswitch.la
# ovsdb-client.1
man_MANS += ovsdb/ovsdb-client.1
DISTCLEANFILES += ovsdb/ovsdb-client.1
MAN_ROOTS += ovsdb/ovsdb-client.1.in

# ovsdb-server
sbin_PROGRAMS += ovsdb/ovsdb-server
ovsdb_ovsdb_server_SOURCES = ovsdb/ovsdb-server.c
ovsdb_ovsdb_server_LDADD = ovsdb/libovsdb.la lib/libopenvswitch.la
# ovsdb-server.1
man_MANS += ovsdb/ovsdb-server.1
DISTCLEANFILES += ovsdb/ovsdb-server.1
MAN_ROOTS += ovsdb/ovsdb-server.1.in

# ovsdb-idlc
noinst_SCRIPTS += ovsdb/ovsdb-idlc
EXTRA_DIST += ovsdb/ovsdb-idlc.in
MAN_ROOTS += ovsdb/ovsdb-idlc.1
DISTCLEANFILES += ovsdb/ovsdb-idlc
SUFFIXES += .ovsidl .ovsschema
OVSDB_IDLC = $(run_python) $(srcdir)/ovsdb/ovsdb-idlc.in
.ovsidl.c:
	$(AM_V_GEN)$(OVSDB_IDLC) c-idl-source $< > $@.tmp && mv $@.tmp $@
.ovsidl.h:
	$(AM_V_GEN)$(OVSDB_IDLC) c-idl-header $< > $@.tmp && mv $@.tmp $@

EXTRA_DIST += $(OVSIDL_BUILT)
BUILT_SOURCES += $(OVSIDL_BUILT)

# This must be done late: macros in targets are expanded when the
# target line is read, so if this file were to be included before some
# other file that added to OVSIDL_BUILT, then those files wouldn't get
# the dependency.
#
# However, current versions of Automake seem to output all variable
# assignments before any targets, so it doesn't seem to be a problem,
# at least for now.
$(OVSIDL_BUILT): ovsdb/ovsdb-idlc.in

# ovsdb-doc
EXTRA_DIST += ovsdb/ovsdb-doc
OVSDB_DOC = $(run_python) $(srcdir)/ovsdb/ovsdb-doc

# ovsdb-dot
EXTRA_DIST += ovsdb/ovsdb-dot.in ovsdb/dot2pic
noinst_SCRIPTS += ovsdb/ovsdb-dot
DISTCLEANFILES += ovsdb/ovsdb-dot
OVSDB_DOT = $(run_python) $(srcdir)/ovsdb/ovsdb-dot.in
