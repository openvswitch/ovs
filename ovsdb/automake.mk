# libovsdb
noinst_LIBRARIES += ovsdb/libovsdb.a
ovsdb_libovsdb_a_SOURCES = \
	ovsdb/column.c \
	ovsdb/column.h \
	ovsdb/condition.c \
	ovsdb/condition.h \
	ovsdb/execution.c \
	ovsdb/jsonrpc-server.c \
	ovsdb/jsonrpc-server.h \
	ovsdb/log.c \
	ovsdb/log.h \
	ovsdb/ovsdb-server.c \
	ovsdb/ovsdb.c \
	ovsdb/ovsdb.h \
	ovsdb/query.c \
	ovsdb/query.h \
	ovsdb/row.c \
	ovsdb/row.h \
	ovsdb/table.c \
	ovsdb/table.h \
	ovsdb/trigger.c \
	ovsdb/trigger.h \
	ovsdb/transaction.c \
	ovsdb/transaction.h

# ovsdb-tool
bin_PROGRAMS += ovsdb/ovsdb-tool
ovsdb_ovsdb_tool_SOURCES = ovsdb/ovsdb-tool.c
ovsdb_ovsdb_tool_LDADD = ovsdb/libovsdb.a lib/libopenvswitch.a
# ovsdb-tool.1
man_MANS += ovsdb/ovsdb-tool.1
DISTCLEANFILES += ovsdb/ovsdb-tool.1
EXTRA_DIST += ovsdb/ovsdb-tool.1.in

# ovsdb-client
bin_PROGRAMS += ovsdb/ovsdb-client
ovsdb_ovsdb_client_SOURCES = ovsdb/ovsdb-client.c
ovsdb_ovsdb_client_LDADD = ovsdb/libovsdb.a lib/libopenvswitch.a
# ovsdb-client.1
man_MANS += ovsdb/ovsdb-client.1
DISTCLEANFILES += ovsdb/ovsdb-client.1
EXTRA_DIST += ovsdb/ovsdb-client.1.in

# ovsdb-server
sbin_PROGRAMS += ovsdb/ovsdb-server
ovsdb_ovsdb_server_SOURCES = ovsdb/ovsdb-server.c
ovsdb_ovsdb_server_LDADD = ovsdb/libovsdb.a lib/libopenvswitch.a $(FAULT_LIBS)
# ovsdb-server.1
man_MANS += ovsdb/ovsdb-server.1
DISTCLEANFILES += ovsdb/ovsdb-server.1
EXTRA_DIST += ovsdb/ovsdb-server.1.in
