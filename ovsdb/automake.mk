# libovsdb
lib_LTLIBRARIES += ovsdb/libovsdb.la
ovsdb_libovsdb_la_LDFLAGS = \
        $(OVS_LTINFO) \
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
	ovsdb/raft.c \
	ovsdb/raft.h \
	ovsdb/raft-private.c \
	ovsdb/raft-private.h \
	ovsdb/raft-rpc.c \
	ovsdb/raft-rpc.h \
	ovsdb/rbac.c \
	ovsdb/rbac.h \
	ovsdb/replication.c \
	ovsdb/replication.h \
	ovsdb/row.c \
	ovsdb/row.h \
	ovsdb/server.c \
	ovsdb/server.h \
	ovsdb/storage.c \
	ovsdb/storage.h \
	ovsdb/table.c \
	ovsdb/table.h \
	ovsdb/trigger.c \
	ovsdb/trigger.h \
	ovsdb/transaction.c \
	ovsdb/transaction.h \
	ovsdb/ovsdb-util.c \
	ovsdb/ovsdb-util.h
ovsdb_libovsdb_la_CFLAGS = $(AM_CFLAGS)
ovsdb_libovsdb_la_CPPFLAGS = $(AM_CPPFLAGS)

pkgconfig_DATA += \
	ovsdb/libovsdb.pc

MAN_FRAGMENTS += ovsdb/ovsdb-schemas.man

# ovsdb-tool
bin_PROGRAMS += ovsdb/ovsdb-tool
ovsdb_ovsdb_tool_SOURCES = ovsdb/ovsdb-tool.c
ovsdb_ovsdb_tool_LDADD = ovsdb/libovsdb.la lib/libopenvswitch.la
# ovsdb-tool.1
man_MANS += ovsdb/ovsdb-tool.1
CLEANFILES += ovsdb/ovsdb-tool.1
MAN_ROOTS += ovsdb/ovsdb-tool.1.in

# ovsdb-client
bin_PROGRAMS += ovsdb/ovsdb-client
ovsdb_ovsdb_client_SOURCES = ovsdb/ovsdb-client.c
ovsdb_ovsdb_client_LDADD = ovsdb/libovsdb.la lib/libopenvswitch.la
# ovsdb-client.1
man_MANS += ovsdb/ovsdb-client.1
CLEANFILES += ovsdb/ovsdb-client.1
MAN_ROOTS += ovsdb/ovsdb-client.1.in

# ovsdb-server
sbin_PROGRAMS += ovsdb/ovsdb-server
ovsdb_ovsdb_server_SOURCES = ovsdb/ovsdb-server.c
ovsdb_ovsdb_server_LDADD = ovsdb/libovsdb.la lib/libopenvswitch.la
# ovsdb-server.1
man_MANS += ovsdb/ovsdb-server.1
CLEANFILES += ovsdb/ovsdb-server.1
MAN_ROOTS += ovsdb/ovsdb-server.1.in

# ovsdb-idlc
noinst_SCRIPTS += ovsdb/ovsdb-idlc
EXTRA_DIST += ovsdb/ovsdb-idlc.in
MAN_ROOTS += ovsdb/ovsdb-idlc.1
CLEANFILES += ovsdb/ovsdb-idlc
SUFFIXES += .ovsidl .ovsschema
OVSDB_IDLC = $(run_python) $(srcdir)/ovsdb/ovsdb-idlc.in
.ovsidl.c:
	$(AM_V_GEN)$(OVSDB_IDLC) c-idl-source $< > $@.tmp && mv $@.tmp $@
.ovsidl.h:
	$(AM_V_GEN)$(OVSDB_IDLC) c-idl-header $< > $@.tmp && mv $@.tmp $@

BUILT_SOURCES += $(OVSIDL_BUILT)
CLEANFILES += $(OVSIDL_BUILT)

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
CLEANFILES += ovsdb/ovsdb-dot
OVSDB_DOT = $(run_python) $(srcdir)/ovsdb/ovsdb-dot.in

EXTRA_DIST += ovsdb/_server.ovsschema
CLEANFILES += ovsdb/_server.ovsschema.inc
ovsdb/ovsdb-server.$(OBJEXT): ovsdb/_server.ovsschema.inc
ovsdb/_server.ovsschema.inc: ovsdb/_server.ovsschema $(srcdir)/build-aux/text2c
	$(AM_V_GEN)$(run_python) $(srcdir)/build-aux/text2c < $< > $@.tmp
	$(AM_V_at)mv $@.tmp $@

# Version checking for _server.ovsschema.
ALL_LOCAL += ovsdb/_server.ovsschema.stamp
ovsdb/_server.ovsschema.stamp: ovsdb/_server.ovsschema
	$(srcdir)/build-aux/cksum-schema-check $? $@
CLEANFILES += ovsdb/_server.ovsschema.stamp

# _Server schema documentation
EXTRA_DIST += ovsdb/_server.xml
CLEANFILES += ovsdb/ovsdb-server.5
man_MANS += ovsdb/ovsdb-server.5
ovsdb/ovsdb-server.5: \
	ovsdb/ovsdb-doc ovsdb/_server.xml ovsdb/_server.ovsschema
	$(AM_V_GEN)$(OVSDB_DOC) \
		--version=$(VERSION) \
		$(srcdir)/ovsdb/_server.ovsschema \
		$(srcdir)/ovsdb/_server.xml > $@.tmp && \
	mv $@.tmp $@

EXTRA_DIST += ovsdb/TODO.rst
