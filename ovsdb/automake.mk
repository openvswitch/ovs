# libovsdb
noinst_LIBRARIES += ovsdb/libovsdb.a
ovsdb_libovsdb_a_SOURCES = \
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
EXTRA_DIST += \
	ovsdb/remote-active.man \
	ovsdb/remote-passive.man

# ovsdb-tool
bin_PROGRAMS += ovsdb/ovsdb-tool
ovsdb_ovsdb_tool_SOURCES = ovsdb/ovsdb-tool.c
ovsdb_ovsdb_tool_LDADD = ovsdb/libovsdb.a lib/libopenvswitch.a $(PCRE_LIBS)
# ovsdb-tool.1
man_MANS += ovsdb/ovsdb-tool.1
DISTCLEANFILES += ovsdb/ovsdb-tool.1
EXTRA_DIST += ovsdb/ovsdb-tool.1.in

# ovsdb-client
bin_PROGRAMS += ovsdb/ovsdb-client
ovsdb_ovsdb_client_SOURCES = ovsdb/ovsdb-client.c
ovsdb_ovsdb_client_LDADD = ovsdb/libovsdb.a lib/libopenvswitch.a $(SSL_LIBS) $(PCRE_LIBS)
# ovsdb-client.1
man_MANS += ovsdb/ovsdb-client.1
DISTCLEANFILES += ovsdb/ovsdb-client.1
EXTRA_DIST += ovsdb/ovsdb-client.1.in

# ovsdb-server
sbin_PROGRAMS += ovsdb/ovsdb-server
ovsdb_ovsdb_server_SOURCES = ovsdb/ovsdb-server.c
ovsdb_ovsdb_server_LDADD = ovsdb/libovsdb.a lib/libopenvswitch.a $(SSL_LIBS) $(PCRE_LIBS)
# ovsdb-server.1
man_MANS += ovsdb/ovsdb-server.1
DISTCLEANFILES += ovsdb/ovsdb-server.1
EXTRA_DIST += ovsdb/ovsdb-server.1.in

# ovsdb-idlc
EXTRA_DIST += \
	ovsdb/simplejson/__init__.py \
	ovsdb/simplejson/_speedups.c				\
	ovsdb/simplejson/decoder.py				\
	ovsdb/simplejson/encoder.py				\
	ovsdb/simplejson/scanner.py				\
	ovsdb/simplejson/tests/__init__.py			\
	ovsdb/simplejson/tests/test_check_circular.py		\
	ovsdb/simplejson/tests/test_decode.py			\
	ovsdb/simplejson/tests/test_default.py			\
	ovsdb/simplejson/tests/test_dump.py			\
	ovsdb/simplejson/tests/test_encode_basestring_ascii.py	\
	ovsdb/simplejson/tests/test_fail.py			\
	ovsdb/simplejson/tests/test_float.py			\
	ovsdb/simplejson/tests/test_indent.py			\
	ovsdb/simplejson/tests/test_pass1.py			\
	ovsdb/simplejson/tests/test_pass2.py			\
	ovsdb/simplejson/tests/test_pass3.py			\
	ovsdb/simplejson/tests/test_recursion.py		\
	ovsdb/simplejson/tests/test_scanstring.py		\
	ovsdb/simplejson/tests/test_separators.py		\
	ovsdb/simplejson/tests/test_unicode.py			\
	ovsdb/simplejson/tool.py
noinst_SCRIPTS += ovsdb/ovsdb-idlc
EXTRA_DIST += \
	ovsdb/ovsdb-idlc.in \
	ovsdb/ovsdb-idlc.1
DISTCLEANFILES += ovsdb/ovsdb-idlc
SUFFIXES += .ovsidl .txt
OVSDB_IDLC = $(PYTHON) $(srcdir)/ovsdb/ovsdb-idlc.in
.ovsidl.c:
	$(OVSDB_IDLC) c-idl-source $< > $@.tmp
	mv $@.tmp $@
.ovsidl.h:
	$(OVSDB_IDLC) c-idl-header $< > $@.tmp
	mv $@.tmp $@
.ovsidl.txt:
	$(OVSDB_IDLC) doc $< | fmt -s > $@.tmp
	mv $@.tmp $@

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
