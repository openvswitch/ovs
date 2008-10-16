TESTS += tests/test-list
noinst_PROGRAMS += tests/test-list
tests_test_list_SOURCES = tests/test-list.c
tests_test_list_LDADD = lib/libopenflow.a

TESTS += tests/test-type-props
noinst_PROGRAMS += tests/test-type-props
tests_test_type_props_SOURCES = tests/test-type-props.c

noinst_PROGRAMS += tests/test-dhcp-client
tests_test_dhcp_client_SOURCES = tests/test-dhcp-client.c
tests_test_dhcp_client_LDADD = lib/libopenflow.a $(FAULT_LIBS)

TESTS += tests/test-stp.sh
EXTRA_DIST += tests/test-stp.sh
noinst_PROGRAMS += tests/test-stp

tests_test_stp_SOURCES = tests/test-stp.c
tests_test_stp_LDADD = lib/libopenflow.a
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
