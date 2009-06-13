TESTS += tests/test-classifier
noinst_PROGRAMS += tests/test-classifier
tests_test_classifier_SOURCES = tests/test-classifier.c
tests_test_classifier_LDADD = lib/libopenvswitch.a

TESTS += tests/test-csum
noinst_PROGRAMS += tests/test-csum
tests_test_csum_SOURCES = tests/test-csum.c
tests_test_csum_LDADD = lib/libopenvswitch.a

TESTS += tests/test-flows.sh
noinst_PROGRAMS += tests/test-flows
tests_test_flows_SOURCES = tests/test-flows.c
tests_test_flows_LDADD = lib/libopenvswitch.a
dist_check_SCRIPTS = tests/test-flows.sh tests/flowgen.pl

TESTS += tests/test-hash
noinst_PROGRAMS += tests/test-hash
tests_test_hash_SOURCES = tests/test-hash.c
tests_test_hash_LDADD = lib/libopenvswitch.a

TESTS += tests/test-hmap
noinst_PROGRAMS += tests/test-hmap
tests_test_hmap_SOURCES = tests/test-hmap.c
tests_test_hmap_LDADD = lib/libopenvswitch.a

TESTS += tests/test-list
noinst_PROGRAMS += tests/test-list
tests_test_list_SOURCES = tests/test-list.c
tests_test_list_LDADD = lib/libopenvswitch.a

TESTS += tests/test-sha1
noinst_PROGRAMS += tests/test-sha1
tests_test_sha1_SOURCES = tests/test-sha1.c
tests_test_sha1_LDADD = lib/libopenvswitch.a

TESTS += tests/test-type-props
noinst_PROGRAMS += tests/test-type-props
tests_test_type_props_SOURCES = tests/test-type-props.c

noinst_PROGRAMS += tests/test-dhcp-client
tests_test_dhcp_client_SOURCES = tests/test-dhcp-client.c
tests_test_dhcp_client_LDADD = lib/libopenvswitch.a $(FAULT_LIBS)

TESTS += tests/test-stp.sh
EXTRA_DIST += tests/test-stp.sh
noinst_PROGRAMS += tests/test-stp

tests_test_stp_SOURCES = tests/test-stp.c
tests_test_stp_LDADD = lib/libopenvswitch.a
stp_files = \
	tests/test-stp-ieee802.1d-1998 \
	tests/test-stp-ieee802.1d-2004-fig17.4 \
	tests/test-stp-ieee802.1d-2004-fig17.6 \
	tests/test-stp-ieee802.1d-2004-fig17.7 \
	tests/test-stp-iol-op-1.1 \
	tests/test-stp-iol-op-1.4 \
	tests/test-stp-iol-op-3.1 \
	tests/test-stp-iol-op-3.3 \
	tests/test-stp-iol-io-1.1 \
	tests/test-stp-iol-io-1.2 \
	tests/test-stp-iol-io-1.4 \
	tests/test-stp-iol-io-1.5
TESTS_ENVIRONMENT += stp_files='$(stp_files)'

EXTRA_DIST += $(stp_files)

TESTS += tests/test-vconn
noinst_PROGRAMS += tests/test-vconn
tests_test_vconn_SOURCES = tests/test-vconn.c
tests_test_vconn_LDADD = lib/libopenvswitch.a $(SSL_LIBS)

