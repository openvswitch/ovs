EXTRA_DIST += \
	$(TESTSUITE_AT) \
	$(TESTSUITE) \
	tests/atlocal.in \
	$(srcdir)/package.m4 \
	$(srcdir)/tests/testsuite
TESTSUITE_AT = \
	tests/testsuite.at \
	tests/lcov-pre.at \
	tests/library.at \
	tests/vconn.at \
	tests/dir_name.at \
	tests/aes128.at \
	tests/uuid.at \
	tests/json.at \
	tests/jsonrpc.at \
	tests/timeval.at \
	tests/lockfile.at \
	tests/reconnect.at \
	tests/ovsdb.at \
	tests/ovsdb-log.at \
	tests/ovsdb-types.at \
	tests/ovsdb-data.at \
	tests/ovsdb-column.at \
	tests/ovsdb-table.at \
	tests/ovsdb-row.at \
	tests/ovsdb-condition.at \
	tests/ovsdb-mutation.at \
	tests/ovsdb-query.at \
	tests/ovsdb-transaction.at \
	tests/ovsdb-execution.at \
	tests/ovsdb-trigger.at \
	tests/ovsdb-file.at \
	tests/ovsdb-server.at \
	tests/ovsdb-monitor.at \
	tests/ovsdb-idl.at \
	tests/stp.at \
	tests/ovs-vsctl.at \
	tests/lcov-post.at
TESTSUITE = $(srcdir)/tests/testsuite
DISTCLEANFILES += tests/atconfig tests/atlocal $(TESTSUITE)

check-local: tests/atconfig tests/atlocal $(TESTSUITE)
	$(SHELL) '$(TESTSUITE)' -C tests AUTOTEST_PATH='utilities:vswitchd:ovsdb:tests' $(TESTSUITEFLAGS)

clean-local:
	test ! -f '$(TESTSUITE)' || $(SHELL) '$(TESTSUITE)' -C tests --clean

AUTOM4TE = autom4te
AUTOTEST = $(AUTOM4TE) --language=autotest
$(TESTSUITE): package.m4 $(TESTSUITE_AT)
	$(AUTOTEST) -I '$(srcdir)' -o $@.tmp $@.at
	mv $@.tmp $@

# The `:;' works around a Bash 3.2 bug when the output is not writeable.
$(srcdir)/package.m4: $(top_srcdir)/configure.ac
	:;{ \
	  echo '# Signature of the current package.' && \
	  echo 'm4_define([AT_PACKAGE_NAME],      [@PACKAGE_NAME@])' && \
	  echo 'm4_define([AT_PACKAGE_TARNAME],   [@PACKAGE_TARNAME@])' && \
	  echo 'm4_define([AT_PACKAGE_VERSION],   [@PACKAGE_VERSION@])' && \
	  echo 'm4_define([AT_PACKAGE_STRING],    [@PACKAGE_STRING@])' && \
	  echo 'm4_define([AT_PACKAGE_BUGREPORT], [@PACKAGE_BUGREPORT@])'; \
	} >'$(srcdir)/package.m4'

noinst_PROGRAMS += tests/test-aes128
tests_test_aes128_SOURCES = tests/test-aes128.c
tests_test_aes128_LDADD = lib/libopenvswitch.a

noinst_PROGRAMS += tests/test-classifier
tests_test_classifier_SOURCES = tests/test-classifier.c
tests_test_classifier_LDADD = lib/libopenvswitch.a

noinst_PROGRAMS += tests/test-csum
tests_test_csum_SOURCES = tests/test-csum.c
tests_test_csum_LDADD = lib/libopenvswitch.a

noinst_PROGRAMS += tests/test-dir_name
tests_test_dir_name_SOURCES = tests/test-dir_name.c
tests_test_dir_name_LDADD = lib/libopenvswitch.a

noinst_PROGRAMS += tests/test-flows
tests_test_flows_SOURCES = tests/test-flows.c
tests_test_flows_LDADD = lib/libopenvswitch.a
dist_check_SCRIPTS = tests/flowgen.pl

noinst_PROGRAMS += tests/test-hash
tests_test_hash_SOURCES = tests/test-hash.c
tests_test_hash_LDADD = lib/libopenvswitch.a

noinst_PROGRAMS += tests/test-hmap
tests_test_hmap_SOURCES = tests/test-hmap.c
tests_test_hmap_LDADD = lib/libopenvswitch.a

noinst_PROGRAMS += tests/test-json
tests_test_json_SOURCES = tests/test-json.c
tests_test_json_LDADD = lib/libopenvswitch.a

noinst_PROGRAMS += tests/test-jsonrpc
tests_test_jsonrpc_SOURCES = tests/test-jsonrpc.c
tests_test_jsonrpc_LDADD = lib/libopenvswitch.a $(SSL_LIBS)

noinst_PROGRAMS += tests/test-list
tests_test_list_SOURCES = tests/test-list.c
tests_test_list_LDADD = lib/libopenvswitch.a

noinst_PROGRAMS += tests/test-lockfile
tests_test_lockfile_SOURCES = tests/test-lockfile.c
tests_test_lockfile_LDADD = lib/libopenvswitch.a

noinst_PROGRAMS += tests/test-ovsdb
tests_test_ovsdb_SOURCES = tests/test-ovsdb.c tests/idltest.c tests/idltest.h
tests_test_ovsdb_LDADD = ovsdb/libovsdb.a lib/libopenvswitch.a $(SSL_LIBS)
EXTRA_DIST += tests/uuidfilt.pl tests/idltest.ovsidl
BUILT_SOURCES += tests/idltest.c tests/idltest.h
noinst_DATA += tests/idltest.ovsschema
DISTCLEANFILES += tests/idltest.ovsschema
tests/idltest.c tests/idltest.h tests/idltest.ovsschema: ovsdb/ovsdb-idlc.in
tests/idltest.c: tests/idltest.h
EXTRA_DIST += tests/idltest.c tests/idltest.h tests/idltest.ovsschema

noinst_PROGRAMS += tests/test-reconnect
tests_test_reconnect_SOURCES = tests/test-reconnect.c
tests_test_reconnect_LDADD = lib/libopenvswitch.a

noinst_PROGRAMS += tests/test-sha1
tests_test_sha1_SOURCES = tests/test-sha1.c
tests_test_sha1_LDADD = lib/libopenvswitch.a

noinst_PROGRAMS += tests/test-timeval
tests_test_timeval_SOURCES = tests/test-timeval.c
tests_test_timeval_LDADD = lib/libopenvswitch.a

noinst_PROGRAMS += tests/test-type-props
tests_test_type_props_SOURCES = tests/test-type-props.c

noinst_PROGRAMS += tests/test-dhcp-client
tests_test_dhcp_client_SOURCES = tests/test-dhcp-client.c
tests_test_dhcp_client_LDADD = lib/libopenvswitch.a

noinst_PROGRAMS += tests/test-stp
tests_test_stp_SOURCES = tests/test-stp.c
tests_test_stp_LDADD = lib/libopenvswitch.a

noinst_PROGRAMS += tests/test-uuid
tests_test_uuid_SOURCES = tests/test-uuid.c
tests_test_uuid_LDADD = lib/libopenvswitch.a

noinst_PROGRAMS += tests/test-vconn
tests_test_vconn_SOURCES = tests/test-vconn.c
tests_test_vconn_LDADD = lib/libopenvswitch.a $(SSL_LIBS)
EXTRA_DIST += \
	tests/testpki-cacert.pem \
	tests/testpki-cert.pem \
	tests/testpki-privkey.pem \
	tests/testpki-req.pem

