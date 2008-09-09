include ../Make.vars

TESTS = test-list
noinst_PROGRAMS = test-list
test_list_SOURCES = test-list.c
test_list_LDADD = ../lib/libopenflow.a

TESTS += test-type-props
noinst_PROGRAMS += test-type-props
test_type_props_SOURCES = test-type-props.c

noinst_PROGRAMS += test-dhcp-client
test_dhcp_client_SOURCES = test-dhcp-client.c
test_dhcp_client_LDADD = ../lib/libopenflow.a $(FAULT_LIBS)

TESTS += test-stp.sh
EXTRA_DIST = test-stp.sh
noinst_PROGRAMS += test-stp

test_stp_SOURCES = test-stp.c
test_stp_LDADD = ../lib/libopenflow.a
stp_files = \
	test-stp-ieee802.1d-1998 \
	test-stp-ieee802.1d-2004-fig17.4 \
	test-stp-ieee802.1d-2004-fig17.6 \
	test-stp-ieee802.1d-2004-fig17.7 \
	test-stp-iol-op-1.1 \
	test-stp-iol-op-1.4 \
	test-stp-iol-op-3.1 \
	test-stp-iol-op-3.3 \
	test-stp-iol-io-1.1 \
	test-stp-iol-io-1.2 \
	test-stp-iol-io-1.4 \
	test-stp-iol-io-1.5
TESTS_ENVIRONMENT = stp_files='$(stp_files)'

EXTRA_DIST += $(stp_files)
