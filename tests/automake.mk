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
	tests/stp.at \
	tests/ovs-vsctl.at \
	tests/lcov-post.at
TESTSUITE = $(srcdir)/tests/testsuite
DISTCLEANFILES += tests/atconfig tests/atlocal $(TESTSUITE)

check-local: tests/atconfig tests/atlocal $(TESTSUITE)
	$(SHELL) '$(TESTSUITE)' -C tests AUTOTEST_PATH='utilities:vswitchd:tests' $(TESTSUITEFLAGS)

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

noinst_PROGRAMS += tests/test-classifier
tests_test_classifier_SOURCES = tests/test-classifier.c
tests_test_classifier_LDADD = lib/libopenvswitch.a

noinst_PROGRAMS += tests/test-csum
tests_test_csum_SOURCES = tests/test-csum.c
tests_test_csum_LDADD = lib/libopenvswitch.a

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

noinst_PROGRAMS += tests/test-list
tests_test_list_SOURCES = tests/test-list.c
tests_test_list_LDADD = lib/libopenvswitch.a

noinst_PROGRAMS += tests/test-sha1
tests_test_sha1_SOURCES = tests/test-sha1.c
tests_test_sha1_LDADD = lib/libopenvswitch.a

noinst_PROGRAMS += tests/test-strtok_r
tests_test_strtok_r_SOURCES = tests/test-strtok_r.c

noinst_PROGRAMS += tests/test-type-props
tests_test_type_props_SOURCES = tests/test-type-props.c

noinst_PROGRAMS += tests/test-dhcp-client
tests_test_dhcp_client_SOURCES = tests/test-dhcp-client.c
tests_test_dhcp_client_LDADD = lib/libopenvswitch.a $(FAULT_LIBS)

noinst_PROGRAMS += tests/test-stp
tests_test_stp_SOURCES = tests/test-stp.c
tests_test_stp_LDADD = lib/libopenvswitch.a

noinst_PROGRAMS += tests/test-vconn
tests_test_vconn_SOURCES = tests/test-vconn.c
tests_test_vconn_LDADD = lib/libopenvswitch.a $(SSL_LIBS)

