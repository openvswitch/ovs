include ../Make.vars

TESTS = test-list

check_PROGRAMS = test-list

test_list_SOURCES = test-list.c
test_list_LDADD = ../lib/libopenflow.a

TESTS += test-type-props
check_PROGRAMS += test-type-props
test_type_props_SOURCES = test-type-props.c

noinst_PROGRAMS = test-dhcp-client
test_dhcp_client_SOURCES = test-dhcp-client.c
test_dhcp_client_LDADD = ../lib/libopenflow.a $(FAULT_LIBS)

