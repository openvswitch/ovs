EXTRA_DIST += \
	$(TESTSUITE_AT) \
	$(TESTSUITE) \
	tests/atlocal.in \
	$(srcdir)/package.m4 \
	$(srcdir)/tests/testsuite
TESTSUITE_AT = \
	tests/testsuite.at \
	tests/ovsdb-macros.at \
	tests/library.at \
	tests/bundle.at \
	tests/classifier.at \
	tests/check-structs.at \
	tests/daemon.at \
	tests/daemon-py.at \
	tests/ofp-print.at \
	tests/ovs-ofctl.at \
	tests/multipath.at \
	tests/autopath.at \
	tests/vconn.at \
	tests/file_name.at \
	tests/aes128.at \
	tests/uuid.at \
	tests/json.at \
	tests/jsonrpc.at \
	tests/jsonrpc-py.at \
	tests/timeval.at \
	tests/lockfile.at \
	tests/reconnect.at \
	tests/ofproto-macros.at \
	tests/ofproto.at \
	tests/ovsdb.at \
	tests/ovsdb-log.at \
	tests/ovsdb-types.at \
	tests/ovsdb-data.at \
	tests/ovsdb-column.at \
	tests/ovsdb-table.at \
	tests/ovsdb-row.at \
	tests/ovsdb-schema.at \
	tests/ovsdb-condition.at \
	tests/ovsdb-mutation.at \
	tests/ovsdb-query.at \
	tests/ovsdb-transaction.at \
	tests/ovsdb-execution.at \
	tests/ovsdb-trigger.at \
	tests/ovsdb-tool.at \
	tests/ovsdb-server.at \
	tests/ovsdb-monitor.at \
	tests/ovsdb-idl.at \
	tests/ovsdb-idl-py.at \
	tests/ovs-vsctl.at \
	tests/interface-reconfigure.at
TESTSUITE = $(srcdir)/tests/testsuite
DISTCLEANFILES += tests/atconfig tests/atlocal

AUTOTEST_PATH = utilities:vswitchd:ovsdb:tests

check-local: tests/atconfig tests/atlocal $(TESTSUITE)
	$(SHELL) '$(TESTSUITE)' -C tests AUTOTEST_PATH=$(AUTOTEST_PATH) $(TESTSUITEFLAGS)

# lcov support

lcov_wrappers = \
	tests/lcov/ovs-appctl \
	tests/lcov/ovs-vsctl \
	tests/lcov/ovsdb-client \
	tests/lcov/ovsdb-server \
	tests/lcov/ovsdb-tool \
	tests/lcov/test-aes128 \
	tests/lcov/test-bundle \
	tests/lcov/test-byte-order \
	tests/lcov/test-classifier \
	tests/lcov/test-csum \
	tests/lcov/test-file_name \
	tests/lcov/test-flows \
	tests/lcov/test-hash \
	tests/lcov/test-hmap \
	tests/lcov/test-json \
	tests/lcov/test-jsonrpc \
	tests/lcov/test-list \
	tests/lcov/test-lockfile \
	tests/lcov/test-multipath \
	tests/lcov/test-ovsdb \
	tests/lcov/test-packets \
	tests/lcov/test-random \
	tests/lcov/test-reconnect \
	tests/lcov/test-sha1 \
	tests/lcov/test-timeval \
	tests/lcov/test-type-props \
	tests/lcov/test-unix-socket \
	tests/lcov/test-uuid \
	tests/lcov/test-vconn

$(lcov_wrappers): tests/lcov-wrapper.in
	@test -d tests/lcov || mkdir tests/lcov
	sed -e 's,[@]abs_top_builddir[@],$(abs_top_builddir),' \
	    -e 's,[@]wrap_program[@],$@,' \
		$(top_srcdir)/tests/lcov-wrapper.in > $@.tmp
	chmod +x $@.tmp
	mv $@.tmp $@
CLEANFILES += $(lcov_wrappers)
EXTRA_DIST += tests/lcov-wrapper.in

LCOV = lcov -b $(abs_top_builddir) -d $(abs_top_builddir) -q
check-lcov: all tests/atconfig tests/atlocal $(TESTSUITE) $(lcov_wrappers)
	rm -fr tests/coverage.html tests/coverage.info
	$(LCOV) -c -i -o - > tests/coverage.info
	$(SHELL) '$(TESTSUITE)' -C tests CHECK_LCOV=true DISABLE_LCOV=false AUTOTEST_PATH='tests/lcov:$(AUTOTEST_PATH)' $(TESTSUITEFLAGS); \
		rc=$$?; \
		echo "Producing coverage.html..."; \
		cd tests && genhtml -q -o coverage.html coverage.info; \
		exit $$rc

# valgrind support

valgrind_wrappers = \
	tests/valgrind/ovs-appctl \
	tests/valgrind/ovs-vsctl \
	tests/valgrind/ovsdb-client \
	tests/valgrind/ovsdb-server \
	tests/valgrind/ovsdb-tool \
	tests/valgrind/test-aes128 \
	tests/valgrind/test-bundle \
	tests/valgrind/test-byte-order \
	tests/valgrind/test-classifier \
	tests/valgrind/test-csum \
	tests/valgrind/test-file_name \
	tests/valgrind/test-flows \
	tests/valgrind/test-hash \
	tests/valgrind/test-hmap \
	tests/valgrind/test-json \
	tests/valgrind/test-jsonrpc \
	tests/valgrind/test-list \
	tests/valgrind/test-lockfile \
	tests/valgrind/test-multipath \
	tests/valgrind/test-openflowd \
	tests/valgrind/test-ovsdb \
	tests/valgrind/test-packets \
	tests/valgrind/test-random \
	tests/valgrind/test-reconnect \
	tests/valgrind/test-sha1 \
	tests/valgrind/test-timeval \
	tests/valgrind/test-type-props \
	tests/valgrind/test-unix-socket \
	tests/valgrind/test-uuid \
	tests/valgrind/test-vconn

$(valgrind_wrappers): tests/valgrind-wrapper.in
	@test -d tests/valgrind || mkdir tests/valgrind
	sed -e 's,[@]wrap_program[@],$@,' \
		$(top_srcdir)/tests/valgrind-wrapper.in > $@.tmp
	chmod +x $@.tmp
	mv $@.tmp $@
CLEANFILES += $(valgrind_wrappers)
EXTRA_DIST += tests/valgrind-wrapper.in

VALGRIND = valgrind --log-file=valgrind.%p --leak-check=full \
	--suppressions=$(abs_top_srcdir)/tests/openssl.supp --num-callers=20
EXTRA_DIST += tests/openssl.supp
check-valgrind: all tests/atconfig tests/atlocal $(TESTSUITE) $(valgrind_wrappers)
	$(SHELL) '$(TESTSUITE)' -C tests CHECK_VALGRIND=true VALGRIND='$(VALGRIND)' AUTOTEST_PATH='tests/valgrind:$(AUTOTEST_PATH)' -d $(TESTSUITEFLAGS)
	@echo
	@echo '----------------------------------------------------------------------'
	@echo 'Valgrind output can be found in tests/testsuite.dir/*/valgrind.*'
	@echo '----------------------------------------------------------------------'

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
	  echo 'm4_define([AT_PACKAGE_NAME],      [$(PACKAGE_NAME)])' && \
	  echo 'm4_define([AT_PACKAGE_TARNAME],   [$(PACKAGE_TARNAME)])' && \
	  echo 'm4_define([AT_PACKAGE_VERSION],   [$(PACKAGE_VERSION)])' && \
	  echo 'm4_define([AT_PACKAGE_STRING],    [$(PACKAGE_STRING)])' && \
	  echo 'm4_define([AT_PACKAGE_BUGREPORT], [$(PACKAGE_BUGREPORT)])'; \
	} >'$(srcdir)/package.m4'

noinst_PROGRAMS += tests/test-aes128
tests_test_aes128_SOURCES = tests/test-aes128.c
tests_test_aes128_LDADD = lib/libopenvswitch.a

noinst_PROGRAMS += tests/test-bundle
tests_test_bundle_SOURCES = tests/test-bundle.c
tests_test_bundle_LDADD = lib/libopenvswitch.a

noinst_PROGRAMS += tests/test-classifier
tests_test_classifier_SOURCES = tests/test-classifier.c
tests_test_classifier_LDADD = lib/libopenvswitch.a

noinst_PROGRAMS += tests/test-csum
tests_test_csum_SOURCES = tests/test-csum.c
tests_test_csum_LDADD = lib/libopenvswitch.a

noinst_PROGRAMS += tests/test-file_name
tests_test_file_name_SOURCES = tests/test-file_name.c
tests_test_file_name_LDADD = lib/libopenvswitch.a

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

noinst_PROGRAMS += tests/test-multipath
tests_test_multipath_SOURCES = tests/test-multipath.c
tests_test_multipath_LDADD = lib/libopenvswitch.a

noinst_PROGRAMS += tests/test-openflowd
EXTRA_DIST += tests/test-openflowd.8.in
DISTCLEANFILES += tests/test-openflowd.8
noinst_man_MANS += tests/ovs-openflowd.8
tests_test_openflowd_SOURCES = tests/test-openflowd.c
tests_test_openflowd_LDADD = \
	ofproto/libofproto.a \
	lib/libsflow.a \
	lib/libopenvswitch.a \
	$(SSL_LIBS)


noinst_PROGRAMS += tests/test-packets
tests_test_packets_SOURCES = tests/test-packets.c
tests_test_packets_LDADD = lib/libopenvswitch.a

noinst_PROGRAMS += tests/test-random
tests_test_random_SOURCES = tests/test-random.c
tests_test_random_LDADD = lib/libopenvswitch.a

noinst_PROGRAMS += tests/test-unix-socket
tests_test_unix_socket_SOURCES = tests/test-unix-socket.c
tests_test_unix_socket_LDADD = lib/libopenvswitch.a

noinst_PROGRAMS += tests/test-ovsdb
tests_test_ovsdb_SOURCES = \
	tests/test-ovsdb.c \
	tests/idltest.c \
	tests/idltest.h
EXTRA_DIST += tests/uuidfilt.pl tests/ovsdb-monitor-sort.pl
tests_test_ovsdb_LDADD = ovsdb/libovsdb.a lib/libopenvswitch.a $(SSL_LIBS)

# idltest schema and IDL
OVSIDL_BUILT +=	tests/idltest.c tests/idltest.h tests/idltest.ovsidl
IDLTEST_IDL_FILES = tests/idltest.ovsschema tests/idltest.ann
EXTRA_DIST += $(IDLTEST_IDL_FILES)
tests/idltest.ovsidl: $(IDLTEST_IDL_FILES)
	$(OVSDB_IDLC) -C $(srcdir) annotate $(IDLTEST_IDL_FILES) > $@.tmp
	mv $@.tmp $@

tests/idltest.c: tests/idltest.h

noinst_PROGRAMS += tests/test-reconnect
tests_test_reconnect_SOURCES = tests/test-reconnect.c
tests_test_reconnect_LDADD = lib/libopenvswitch.a

noinst_PROGRAMS += tests/test-sha1
tests_test_sha1_SOURCES = tests/test-sha1.c
tests_test_sha1_LDADD = lib/libopenvswitch.a

noinst_PROGRAMS += tests/test-timeval
tests_test_timeval_SOURCES = tests/test-timeval.c
tests_test_timeval_LDADD = lib/libopenvswitch.a

noinst_PROGRAMS += tests/test-strtok_r
tests_test_strtok_r_SOURCES = tests/test-strtok_r.c

noinst_PROGRAMS += tests/test-type-props
tests_test_type_props_SOURCES = tests/test-type-props.c

noinst_PROGRAMS += tests/test-util
tests_test_util_SOURCES = tests/test-util.c
tests_test_util_LDADD = lib/libopenvswitch.a

noinst_PROGRAMS += tests/test-uuid
tests_test_uuid_SOURCES = tests/test-uuid.c
tests_test_uuid_LDADD = lib/libopenvswitch.a

noinst_PROGRAMS += tests/test-vconn
tests_test_vconn_SOURCES = tests/test-vconn.c
tests_test_vconn_LDADD = lib/libopenvswitch.a $(SSL_LIBS)

noinst_PROGRAMS += tests/test-byte-order
tests_test_byte_order_SOURCES = tests/test-byte-order.c
tests_test_byte_order_LDADD = lib/libopenvswitch.a

# Python tests.
EXTRA_DIST += \
	tests/test-daemon.py \
	tests/test-json.py \
	tests/test-jsonrpc.py \
	tests/test-ovsdb.py \
	tests/test-reconnect.py

if HAVE_OPENSSL
TESTPKI_FILES = \
	tests/testpki-cacert.pem \
	tests/testpki-cert.pem \
	tests/testpki-privkey.pem \
	tests/testpki-req.pem \
	tests/testpki-cert2.pem \
	tests/testpki-privkey2.pem \
	tests/testpki-req2.pem
check_DATA += $(TESTPKI_FILES)
CLEANFILES += $(TESTPKI_FILES)

tests/testpki-cacert.pem: tests/pki/stamp; cp tests/pki/switchca/cacert.pem $@
tests/testpki-cert.pem: tests/pki/stamp; cp tests/pki/test-cert.pem $@
tests/testpki-req.pem: tests/pki/stamp; cp tests/pki/test-req.pem $@
tests/testpki-privkey.pem: tests/pki/stamp; cp tests/pki/test-privkey.pem $@
tests/testpki-cert2.pem: tests/pki/stamp; cp tests/pki/test2-cert.pem $@
tests/testpki-req2.pem: tests/pki/stamp; cp tests/pki/test2-req.pem $@
tests/testpki-privkey2.pem: tests/pki/stamp; cp tests/pki/test2-privkey.pem $@

OVS_PKI = $(SHELL) $(srcdir)/utilities/ovs-pki.in --dir=tests/pki --log=tests/ovs-pki.log
tests/pki/stamp:
	rm -f tests/pki/stamp
	rm -rf tests/pki
	$(OVS_PKI) init
	$(OVS_PKI) req+sign tests/pki/test
	$(OVS_PKI) req+sign tests/pki/test2
	: > tests/pki/stamp
CLEANFILES += tests/ovs-pki.log

CLEAN_LOCAL += clean-pki
clean-pki:
	rm -f tests/pki/stamp
	rm -rf tests/pki
endif
