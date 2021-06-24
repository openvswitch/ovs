EXTRA_DIST += \
	$(COMMON_MACROS_AT) \
	$(TESTSUITE_AT) \
	$(SYSTEM_TESTSUITE_AT) \
	$(SYSTEM_KMOD_TESTSUITE_AT) \
	$(SYSTEM_USERSPACE_TESTSUITE_AT) \
	$(SYSTEM_TSO_TESTSUITE_AT) \
	$(SYSTEM_AFXDP_TESTSUITE_AT) \
	$(SYSTEM_OFFLOADS_TESTSUITE_AT) \
	$(SYSTEM_DPDK_TESTSUITE_AT) \
	$(OVSDB_CLUSTER_TESTSUITE_AT) \
	$(TESTSUITE) \
	$(SYSTEM_KMOD_TESTSUITE) \
	$(SYSTEM_USERSPACE_TESTSUITE) \
	$(SYSTEM_TSO_TESTSUITE) \
	$(SYSTEM_AFXDP_TESTSUITE) \
	$(SYSTEM_OFFLOADS_TESTSUITE) \
	$(SYSTEM_DPDK_TESTSUITE) \
	$(OVSDB_CLUSTER_TESTSUITE) \
	tests/atlocal.in \
	$(srcdir)/package.m4 \
	$(srcdir)/tests/testsuite \
	$(srcdir)/tests/testsuite.patch

COMMON_MACROS_AT = \
	tests/ovsdb-macros.at \
	tests/ovs-macros.at \
	tests/ofproto-macros.at

TESTSUITE_AT = \
	tests/testsuite.at \
	tests/completion.at \
	tests/checkpatch.at \
	tests/library.at \
	tests/heap.at \
	tests/bundle.at \
	tests/classifier.at \
	tests/check-structs.at \
	tests/daemon.at \
	tests/daemon-py.at \
	tests/ofp-actions.at \
	tests/ofp-print.at \
	tests/ofp-util.at \
	tests/ofp-errors.at \
	tests/ovs-ofctl.at \
	tests/fuzz-regression.at \
	tests/fuzz-regression-list.at \
	tests/odp.at \
	tests/mpls-xlate.at \
	tests/multipath.at \
	tests/bfd.at \
	tests/cfm.at \
	tests/lacp.at \
	tests/lib.at \
	tests/learn.at \
	tests/vconn.at \
	tests/file_name.at \
	tests/aes128.at \
	tests/unixctl-py.at \
	tests/uuid.at \
	tests/json.at \
	tests/jsonrpc.at \
	tests/jsonrpc-py.at \
	tests/pmd.at \
	tests/alb.at \
	tests/tunnel.at \
	tests/tunnel-push-pop.at \
	tests/tunnel-push-pop-ipv6.at \
	tests/ovs-router.at \
	tests/lockfile.at \
	tests/reconnect.at \
	tests/ovs-vswitchd.at \
	tests/dpif-netdev.at \
	tests/dpctl.at \
	tests/ofproto-dpif.at \
	tests/bridge.at \
	tests/ofproto.at \
	tests/netdev-type.at \
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
	tests/ovsdb-replication.at \
	tests/ovsdb-server.at \
	tests/ovsdb-client.at \
	tests/ovsdb-monitor.at \
	tests/ovsdb-idl.at \
	tests/ovsdb-lock.at \
	tests/ovsdb-rbac.at \
	tests/ovs-vsctl.at \
	tests/ovs-xapi-sync.at \
	tests/stp.at \
	tests/rstp.at \
	tests/interface-reconfigure.at \
	tests/vlog.at \
	tests/vtep-ctl.at \
	tests/auto-attach.at \
	tests/mcast-snooping.at \
	tests/packet-type-aware.at \
	tests/nsh.at \
	tests/drop-stats.at

EXTRA_DIST += $(FUZZ_REGRESSION_TESTS)
FUZZ_REGRESSION_TESTS = \
	tests/fuzz-regression/flow_extract_fuzzer-5112775280951296 \
	tests/fuzz-regression/flow_extract_fuzzer-5457710546944000 \
	tests/fuzz-regression/json_parser_fuzzer-4790908707930112 \
	tests/fuzz-regression/ofp_print_fuzzer-4584019764183040 \
	tests/fuzz-regression/ofp_print_fuzzer-4730143510626304 \
	tests/fuzz-regression/ofp_print_fuzzer-4854119633256448 \
	tests/fuzz-regression/ofp_print_fuzzer-5070973479944192 \
	tests/fuzz-regression/ofp_print_fuzzer-5072291707748352 \
	tests/fuzz-regression/ofp_print_fuzzer-5147430386401280 \
	tests/fuzz-regression/ofp_print_fuzzer-5168455220199424 \
	tests/fuzz-regression/ofp_print_fuzzer-5190507327127552 \
	tests/fuzz-regression/ofp_print_fuzzer-5204186701496320 \
	tests/fuzz-regression/ofp_print_fuzzer-5394482341085184 \
	tests/fuzz-regression/ofp_print_fuzzer-5395207246839808 \
	tests/fuzz-regression/ofp_print_fuzzer-5647458888581120 \
	tests/fuzz-regression/ofp_print_fuzzer-5674119268925440 \
	tests/fuzz-regression/ofp_print_fuzzer-5674419757252608 \
	tests/fuzz-regression/ofp_print_fuzzer-5677588436484096 \
	tests/fuzz-regression/ofp_print_fuzzer-5706562554298368 \
	tests/fuzz-regression/ofp_print_fuzzer-5722747668791296 \
	tests/fuzz-regression/ofp_print_fuzzer-6285128790704128 \
	tests/fuzz-regression/ofp_print_fuzzer-6470117922701312 \
	tests/fuzz-regression/ofp_print_fuzzer-6502620041576448 \
	tests/fuzz-regression/ofp_print_fuzzer-6540965472632832
$(srcdir)/tests/fuzz-regression-list.at: tests/automake.mk
	$(AM_V_GEN)for name in $(FUZZ_REGRESSION_TESTS); do \
            basename=`echo $$name | sed 's,^.*/,,'`; \
	    echo "TEST_FUZZ_REGRESSION([$$basename])"; \
	done > $@.tmp && mv $@.tmp $@

OVSDB_CLUSTER_TESTSUITE_AT = \
	tests/ovsdb-cluster-testsuite.at \
	tests/ovsdb-execution.at \
	tests/ovsdb-cluster.at

SYSTEM_KMOD_TESTSUITE_AT = \
	tests/system-common-macros.at \
	tests/system-kmod-testsuite.at \
	tests/system-kmod-macros.at

SYSTEM_USERSPACE_TESTSUITE_AT = \
	tests/system-userspace-testsuite.at \
	tests/system-userspace-macros.at \
	tests/system-userspace-packet-type-aware.at \
	tests/system-route.at

SYSTEM_TSO_TESTSUITE_AT = \
	tests/system-tso-testsuite.at \
	tests/system-tap.at \
	tests/system-tso-macros.at

SYSTEM_AFXDP_TESTSUITE_AT = \
	tests/system-userspace-macros.at \
	tests/system-afxdp-testsuite.at \
	tests/system-afxdp-macros.at \
	tests/system-afxdp.at

SYSTEM_TESTSUITE_AT = \
	tests/system-common-macros.at \
	tests/system-layer3-tunnels.at \
	tests/system-traffic.at \
	tests/system-ipsec.at \
	tests/system-interface.at

SYSTEM_OFFLOADS_TESTSUITE_AT = \
	tests/system-common-macros.at \
	tests/system-offloads-traffic.at \
	tests/system-offloads-testsuite.at

SYSTEM_DPDK_TESTSUITE_AT = \
	tests/system-common-macros.at \
	tests/system-dpdk-macros.at \
	tests/system-dpdk-testsuite.at \
	tests/system-dpdk.at

check_SCRIPTS += tests/atlocal

TESTSUITE = $(srcdir)/tests/testsuite
TESTSUITE_PATCH = $(srcdir)/tests/testsuite.patch
TESTSUITE_DIR = $(abs_top_builddir)/tests/testsuite.dir
SYSTEM_KMOD_TESTSUITE = $(srcdir)/tests/system-kmod-testsuite
SYSTEM_USERSPACE_TESTSUITE = $(srcdir)/tests/system-userspace-testsuite
SYSTEM_TSO_TESTSUITE = $(srcdir)/tests/system-tso-testsuite
SYSTEM_AFXDP_TESTSUITE = $(srcdir)/tests/system-afxdp-testsuite
SYSTEM_OFFLOADS_TESTSUITE = $(srcdir)/tests/system-offloads-testsuite
SYSTEM_DPDK_TESTSUITE = $(srcdir)/tests/system-dpdk-testsuite
OVSDB_CLUSTER_TESTSUITE = $(srcdir)/tests/ovsdb-cluster-testsuite
DISTCLEANFILES += tests/atconfig tests/atlocal

AUTOTEST_PATH = utilities:vswitchd:ovsdb:vtep:tests:ipsec:$(PTHREAD_WIN32_DIR_DLL):$(SSL_DIR)

check-local:
	set $(SHELL) '$(TESTSUITE)' -C tests AUTOTEST_PATH=$(AUTOTEST_PATH); \
	"$$@" $(TESTSUITEFLAGS) || \
	(test -z "$$(find $(TESTSUITE_DIR) -name 'asan.*')" && \
	 test X'$(RECHECK)' = Xyes && "$$@" --recheck)

# Python Coverage support.
# Requires coverage.py http://nedbatchelder.com/code/coverage/.

COVERAGE = coverage
COVERAGE_FILE='$(abs_srcdir)/.coverage'
check-pycov: all clean-pycov
	PYTHONDONTWRITEBYTECODE=yes COVERAGE_FILE=$(COVERAGE_FILE) PYTHON3='$(COVERAGE) run -p' $(SHELL) '$(TESTSUITE)' -C tests AUTOTEST_PATH=$(AUTOTEST_PATH) $(TESTSUITEFLAGS)
	@cd $(srcdir) && $(COVERAGE) combine && COVERAGE_FILE=$(COVERAGE_FILE) $(COVERAGE) annotate
	@echo
	@echo '----------------------------------------------------------------------'
	@echo 'Annotated coverage source has the ",cover" extension.'
	@echo '----------------------------------------------------------------------'
	@echo
	@COVERAGE_FILE=$(COVERAGE_FILE) $(COVERAGE) report

# lcov support
# Requires build with --enable-coverage and lcov/genhtml in $PATH
CLEAN_LOCAL += clean-lcov
clean-lcov:
	rm -fr tests/lcov

LCOV_OPTS = -b $(abs_top_builddir) -d $(abs_top_builddir) -q -c --rc lcov_branch_coverage=1
GENHTML_OPTS = -q --branch-coverage --num-spaces 4
check-lcov: all $(check_DATA) clean-lcov
	find . -name '*.gcda' | xargs -n1 rm -f
	-set $(SHELL) '$(TESTSUITE)' -C tests AUTOTEST_PATH=$(AUTOTEST_PATH); \
	"$$@" $(TESTSUITEFLAGS) || (test X'$(RECHECK)' = Xyes && "$$@" --recheck)
	$(MKDIR_P) tests/lcov
	lcov $(LCOV_OPTS) -o tests/lcov/coverage.info
	genhtml $(GENHTML_OPTS) -o tests/lcov tests/lcov/coverage.info
	@echo "coverage report generated at tests/lcov/index.html"

# valgrind support

valgrind_wrappers = \
	tests/valgrind/ovs-appctl \
	tests/valgrind/ovs-ofctl \
	tests/valgrind/ovs-vsctl \
	tests/valgrind/ovs-vswitchd \
	tests/valgrind/ovsdb-client \
	tests/valgrind/ovsdb-server \
	tests/valgrind/ovsdb-tool \
	tests/valgrind/ovstest \
	tests/valgrind/test-ovsdb \
	tests/valgrind/test-skiplist \
	tests/valgrind/test-strtok_r \
	tests/valgrind/test-type-props

$(valgrind_wrappers): tests/valgrind-wrapper.in
	@$(MKDIR_P) tests/valgrind
	$(AM_V_GEN) sed -e 's,[@]wrap_program[@],$@,' \
		$(top_srcdir)/tests/valgrind-wrapper.in > $@.tmp && \
	chmod +x $@.tmp && \
	mv $@.tmp $@
CLEANFILES += $(valgrind_wrappers)
EXTRA_DIST += tests/valgrind-wrapper.in

VALGRIND = valgrind --log-file=valgrind.%p \
	--leak-check=full --track-origins=yes \
	--suppressions=$(abs_top_srcdir)/tests/glibc.supp \
	--suppressions=$(abs_top_srcdir)/tests/openssl.supp --num-callers=20
HELGRIND = valgrind --log-file=helgrind.%p --tool=helgrind \
	--suppressions=$(abs_top_srcdir)/tests/glibc.supp \
	--suppressions=$(abs_top_srcdir)/tests/openssl.supp --num-callers=20
EXTRA_DIST += tests/glibc.supp tests/openssl.supp
check-valgrind: all $(valgrind_wrappers) $(check_DATA)
	$(SHELL) '$(TESTSUITE)' -C tests CHECK_VALGRIND=true VALGRIND='$(VALGRIND)' AUTOTEST_PATH='tests/valgrind:$(AUTOTEST_PATH)' -d $(TESTSUITEFLAGS)
	@echo
	@echo '----------------------------------------------------------------------'
	@echo 'Valgrind output can be found in tests/testsuite.dir/*/valgrind.*'
	@echo '----------------------------------------------------------------------'
check-ovsdb-cluster-valgrind: all $(valgrind_wrappers) $(check_DATA)
	$(SHELL) '$(OVSDB_CLUSTER_TESTSUITE)' -C tests CHECK_VALGRIND=true VALGRIND='$(VALGRIND)' AUTOTEST_PATH='tests/valgrind:$(AUTOTEST_PATH)' -d $(TESTSUITEFLAGS) -j1
	@echo
	@echo '----------------------------------------------------------------------'
	@echo 'Valgrind output can be found in tests/ovsdb-cluster-testsuite.dir/*/valgrind.*'
	@echo '----------------------------------------------------------------------'
check-kernel-valgrind: all $(valgrind_wrappers) $(check_DATA)
	$(SHELL) '$(SYSTEM_KMOD_TESTSUITE)' -C tests VALGRIND='$(VALGRIND)' AUTOTEST_PATH='tests/valgrind:$(AUTOTEST_PATH)' -d $(TESTSUITEFLAGS) -j1
	@echo
	@echo '----------------------------------------------------------------------'
	@echo 'Valgrind output can be found in tests/system-kmod-testsuite.dir/*/valgrind.*'
	@echo '----------------------------------------------------------------------'
check-userspace-valgrind: all $(valgrind_wrappers) $(check_DATA)
	$(SHELL) '$(SYSTEM_USERSPACE_TESTSUITE)' -C tests VALGRIND='$(VALGRIND)' AUTOTEST_PATH='tests/valgrind:$(AUTOTEST_PATH)' -d $(TESTSUITEFLAGS) -j1
	@echo
	@echo '----------------------------------------------------------------------'
	@echo 'Valgrind output can be found in tests/system-userspace-testsuite.dir/*/valgrind.*'
	@echo '----------------------------------------------------------------------'
check-afxdp-valgrind: all $(valgrind_wrappers) $(check_DATA)
	$(SHELL) '$(SYSTEM_AFXDP_TESTSUITE)' -C tests VALGRIND='$(VALGRIND)' AUTOTEST_PATH='tests/valgrind:$(AUTOTEST_PATH)' -d $(TESTSUITEFLAGS) -j1
	@echo
	@echo '----------------------------------------------------------------------'
	@echo 'Valgrind output can be found in tests/system-afxdp-testsuite.dir/*/valgrind.*'
	@echo '----------------------------------------------------------------------'
check-offloads-valgrind: all $(valgrind_wrappers) $(check_DATA)
	$(SHELL) '$(SYSTEM_OFFLOADS_TESTSUITE)' -C tests VALGRIND='$(VALGRIND)' AUTOTEST_PATH='tests/valgrind:$(AUTOTEST_PATH)' -d $(TESTSUITEFLAGS) -j1
	@echo
	@echo '----------------------------------------------------------------------'
	@echo 'Valgrind output can be found in tests/system-offloads-testsuite.dir/*/valgrind.*'
	@echo '----------------------------------------------------------------------'
check-tso-valgrind: all $(valgrind_wrappers) $(check_DATA)
	$(SHELL) '$(SYSTEM_TSO_TESTSUITE)' -C tests VALGRIND='$(VALGRIND)' AUTOTEST_PATH='tests/valgrind:$(AUTOTEST_PATH)' -d $(TESTSUITEFLAGS) -j1
	@echo
	@echo '----------------------------------------------------------------------'
	@echo 'Valgrind output can be found in tests/system-tso-testsuite.dir/*/valgrind.*'
	@echo '----------------------------------------------------------------------'
check-helgrind: all $(valgrind_wrappers) $(check_DATA)
	-$(SHELL) '$(TESTSUITE)' -C tests CHECK_VALGRIND=true VALGRIND='$(HELGRIND)' AUTOTEST_PATH='tests/valgrind:$(AUTOTEST_PATH)' -d $(TESTSUITEFLAGS)


# OFTest support.

check-oftest: all
	$(AM_V_at)srcdir='$(srcdir)' $(SHELL) $(srcdir)/tests/run-oftest
EXTRA_DIST += tests/run-oftest

# Ryu support.
check-ryu: all
	$(AM_V_at)srcdir='$(srcdir)' $(SHELL) $(srcdir)/tests/run-ryu
EXTRA_DIST += tests/run-ryu

# Run kmod tests. Assume kernel modules has been installed or linked into the kernel
check-kernel: all
	set $(SHELL) '$(SYSTEM_KMOD_TESTSUITE)' -C tests  AUTOTEST_PATH='$(AUTOTEST_PATH)'; \
	"$$@" $(TESTSUITEFLAGS) -j1 || (test X'$(RECHECK)' = Xyes && "$$@" --recheck)

# Testing the out of tree Kernel module
check-kmod: all
	$(MAKE) modules_install
	modprobe -r -a vport-geneve vport-gre vport-lisp vport-stt vport-vxlan openvswitch
	$(MAKE) check-kernel

check-system-userspace: all
	set $(SHELL) '$(SYSTEM_USERSPACE_TESTSUITE)' -C tests  AUTOTEST_PATH='$(AUTOTEST_PATH)'; \
	"$$@" $(TESTSUITEFLAGS) -j1 || (test X'$(RECHECK)' = Xyes && "$$@" --recheck)

check-system-tso: all
	set $(SHELL) '$(SYSTEM_TSO_TESTSUITE)' -C tests  AUTOTEST_PATH='$(AUTOTEST_PATH)'; \
	"$$@" $(TESTSUITEFLAGS) -j1 || (test X'$(RECHECK)' = Xyes && "$$@" --recheck)

check-afxdp: all
	set $(SHELL) '$(SYSTEM_AFXDP_TESTSUITE)' -C tests  AUTOTEST_PATH='$(AUTOTEST_PATH)' $(TESTSUITEFLAGS) -j1; \
	"$$@" || (test X'$(RECHECK)' = Xyes && "$$@" --recheck)

check-offloads: all
	set $(SHELL) '$(SYSTEM_OFFLOADS_TESTSUITE)' -C tests  AUTOTEST_PATH='$(AUTOTEST_PATH)'; \
	"$$@" $(TESTSUITEFLAGS) -j1 || (test X'$(RECHECK)' = Xyes && "$$@" --recheck)

check-dpdk: all
	set $(SHELL) '$(SYSTEM_DPDK_TESTSUITE)' -C tests  AUTOTEST_PATH='$(AUTOTEST_PATH)'; \
	"$$@" $(TESTSUITEFLAGS) -j1 || (test X'$(RECHECK)' = Xyes && "$$@" --recheck)

clean-local:
	test ! -f '$(TESTSUITE)' || $(SHELL) '$(TESTSUITE)' -C tests --clean

# Run OVSDB cluster tests.
check-ovsdb-cluster: all
	set $(SHELL) '$(OVSDB_CLUSTER_TESTSUITE)' -C tests  AUTOTEST_PATH='$(AUTOTEST_PATH)'; \
	"$$@" $(TESTSUITEFLAGS) -j1 || (test X'$(RECHECK)' = Xyes && "$$@" --recheck)

AUTOTEST = $(AUTOM4TE) --language=autotest

if WIN32
$(TESTSUITE): package.m4 $(TESTSUITE_AT) $(COMMON_MACROS_AT) $(TESTSUITE_PATCH)
	$(AM_V_GEN)$(AUTOTEST) -I '$(srcdir)' -o testsuite.tmp $@.at
	patch -p0 testsuite.tmp $(TESTSUITE_PATCH)
	$(AM_V_at)mv testsuite.tmp $@
else
$(TESTSUITE): package.m4 $(TESTSUITE_AT) $(COMMON_MACROS_AT)
	$(AM_V_GEN)$(AUTOTEST) -I '$(srcdir)' -o $@.tmp $@.at
	$(AM_V_at)mv $@.tmp $@
endif

$(SYSTEM_KMOD_TESTSUITE): package.m4 $(SYSTEM_TESTSUITE_AT) $(SYSTEM_KMOD_TESTSUITE_AT) $(COMMON_MACROS_AT)
	$(AM_V_GEN)$(AUTOTEST) -I '$(srcdir)' -o $@.tmp $@.at
	$(AM_V_at)mv $@.tmp $@

$(SYSTEM_USERSPACE_TESTSUITE): package.m4 $(SYSTEM_TESTSUITE_AT) $(SYSTEM_USERSPACE_TESTSUITE_AT) $(COMMON_MACROS_AT)
	$(AM_V_GEN)$(AUTOTEST) -I '$(srcdir)' -o $@.tmp $@.at
	$(AM_V_at)mv $@.tmp $@

$(SYSTEM_TSO_TESTSUITE): package.m4 $(SYSTEM_TESTSUITE_AT) $(SYSTEM_TSO_TESTSUITE_AT) $(COMMON_MACROS_AT)
	$(AM_V_GEN)$(AUTOTEST) -I '$(srcdir)' -o $@.tmp $@.at
	$(AM_V_at)mv $@.tmp $@

$(SYSTEM_AFXDP_TESTSUITE): package.m4 $(SYSTEM_TESTSUITE_AT) $(SYSTEM_AFXDP_TESTSUITE_AT) $(COMMON_MACROS_AT)
	$(AM_V_GEN)$(AUTOTEST) -I '$(srcdir)' -o $@.tmp $@.at
	$(AM_V_at)mv $@.tmp $@

$(SYSTEM_OFFLOADS_TESTSUITE): package.m4 $(SYSTEM_TESTSUITE_AT) $(SYSTEM_OFFLOADS_TESTSUITE_AT) $(COMMON_MACROS_AT)
	$(AM_V_GEN)$(AUTOTEST) -I '$(srcdir)' -o $@.tmp $@.at
	$(AM_V_at)mv $@.tmp $@

$(SYSTEM_DPDK_TESTSUITE): package.m4 $(SYSTEM_TESTSUITE_AT) $(SYSTEM_DPDK_TESTSUITE_AT) $(COMMON_MACROS_AT)
	$(AM_V_GEN)$(AUTOTEST) -I '$(srcdir)' -o $@.tmp $@.at
	$(AM_V_at)mv $@.tmp $@

$(OVSDB_CLUSTER_TESTSUITE): package.m4 $(OVSDB_CLUSTER_TESTSUITE_AT) $(COMMON_MACROS_AT)
	$(AM_V_GEN)$(AUTOTEST) -I '$(srcdir)' -o $@.tmp $@.at
	$(AM_V_at)mv $@.tmp $@

# The `:;' works around a Bash 3.2 bug when the output is not writeable.
$(srcdir)/package.m4: $(top_srcdir)/configure.ac
	$(AM_V_GEN):;{ \
	  echo '# Signature of the current package.' && \
	  echo 'm4_define([AT_PACKAGE_NAME],      [$(PACKAGE_NAME)])' && \
	  echo 'm4_define([AT_PACKAGE_TARNAME],   [$(PACKAGE_TARNAME)])' && \
	  echo 'm4_define([AT_PACKAGE_VERSION],   [$(PACKAGE_VERSION)])' && \
	  echo 'm4_define([AT_PACKAGE_STRING],    [$(PACKAGE_STRING)])' && \
	  echo 'm4_define([AT_PACKAGE_BUGREPORT], [$(PACKAGE_BUGREPORT)])'; \
	} >'$(srcdir)/package.m4'

noinst_PROGRAMS += tests/test-ovsdb
tests_test_ovsdb_SOURCES = tests/test-ovsdb.c
nodist_tests_test_ovsdb_SOURCES = tests/idltest.c tests/idltest.h
tests_test_ovsdb_LDADD = ovsdb/libovsdb.la lib/libopenvswitch.la

noinst_PROGRAMS += tests/test-lib
tests_test_lib_SOURCES = \
	tests/test-lib.c
tests_test_lib_LDADD = lib/libopenvswitch.la

# idltest schema and IDL
OVSIDL_BUILT += tests/idltest.c tests/idltest.h tests/idltest.ovsidl
IDLTEST_IDL_FILES = tests/idltest.ovsschema tests/idltest.ann
EXTRA_DIST += $(IDLTEST_IDL_FILES) tests/idltest2.ovsschema
tests/idltest.ovsidl: $(IDLTEST_IDL_FILES)
	$(AM_V_GEN)$(OVSDB_IDLC) -C $(srcdir) annotate $(IDLTEST_IDL_FILES) > $@.tmp && \
	mv $@.tmp $@

tests/idltest.c: tests/idltest.h

noinst_PROGRAMS += tests/ovstest
tests_ovstest_SOURCES = \
	tests/ovstest.c \
	tests/ovstest.h \
	tests/test-aes128.c \
	tests/test-atomic.c \
	tests/test-bundle.c \
	tests/test-byte-order.c \
	tests/test-classifier.c \
	tests/test-ccmap.c \
	tests/test-cmap.c \
	tests/test-conntrack.c \
	tests/test-csum.c \
	tests/test-flows.c \
	tests/test-hash.c \
	tests/test-heap.c \
	tests/test-hindex.c \
	tests/test-hmap.c \
	tests/test-json.c \
	tests/test-jsonrpc.c \
	tests/test-list.c \
	tests/test-lockfile.c \
	tests/test-multipath.c \
	tests/test-netflow.c \
	tests/test-odp.c \
	tests/test-ofpbuf.c \
	tests/test-packets.c \
	tests/test-random.c \
	tests/test-rcu.c \
	tests/test-reconnect.c \
	tests/test-rstp.c \
	tests/test-sflow.c \
	tests/test-sha1.c \
	tests/test-skiplist.c \
	tests/test-stp.c \
	tests/test-unixctl.c \
	tests/test-util.c \
	tests/test-uuid.c \
	tests/test-bitmap.c \
	tests/test-vconn.c \
	tests/test-aa.c \
	tests/test-stopwatch.c

if !WIN32
tests_ovstest_SOURCES += \
	tests/test-unix-socket.c
endif

if LINUX
tests_ovstest_SOURCES += \
	tests/test-netlink-conntrack.c
endif

tests_ovstest_LDADD = lib/libopenvswitch.la

noinst_PROGRAMS += tests/test-stream
tests_test_stream_SOURCES = tests/test-stream.c
tests_test_stream_LDADD = lib/libopenvswitch.la

noinst_PROGRAMS += tests/test-strtok_r
tests_test_strtok_r_SOURCES = tests/test-strtok_r.c

noinst_PROGRAMS += tests/test-type-props
tests_test_type_props_SOURCES = tests/test-type-props.c

# Python tests.
CHECK_PYFILES = \
	tests/appctl.py \
	tests/flowgen.py \
	tests/ovsdb-monitor-sort.py \
	tests/test-daemon.py \
	tests/test-json.py \
	tests/test-jsonrpc.py \
	tests/test-l7.py \
	tests/test-ovsdb.py \
	tests/test-reconnect.py \
	tests/test-stream.py \
	tests/MockXenAPI.py \
	tests/test-unix-socket.py \
	tests/test-unixctl.py \
	tests/test-vlog.py \
	tests/uuidfilt.py \
	tests/sendpkt.py

EXTRA_DIST += $(CHECK_PYFILES)
PYCOV_CLEAN_FILES += $(CHECK_PYFILES:.py=.py,cover) .coverage

FLAKE8_PYFILES += $(CHECK_PYFILES)

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

tests/testpki-cacert.pem: tests/pki/stamp
	$(AM_V_GEN)cp tests/pki/switchca/cacert.pem $@
tests/testpki-cert.pem: tests/pki/stamp
	$(AM_V_GEN)cp tests/pki/test-cert.pem $@
tests/testpki-req.pem: tests/pki/stamp
	$(AM_V_GEN)cp tests/pki/test-req.pem $@
tests/testpki-privkey.pem: tests/pki/stamp
	$(AM_V_GEN)cp tests/pki/test-privkey.pem $@
tests/testpki-cert2.pem: tests/pki/stamp
	$(AM_V_GEN)cp tests/pki/test2-cert.pem $@
tests/testpki-req2.pem: tests/pki/stamp
	$(AM_V_GEN)cp tests/pki/test2-req.pem $@
tests/testpki-privkey2.pem: tests/pki/stamp
	$(AM_V_GEN)cp tests/pki/test2-privkey.pem $@

OVS_PKI = $(SHELL) $(srcdir)/utilities/ovs-pki.in --dir=tests/pki --log=tests/ovs-pki.log
tests/pki/stamp:
	$(AM_V_at)rm -f tests/pki/stamp
	$(AM_V_at)rm -rf tests/pki
	$(AM_V_GEN)$(OVS_PKI) init && \
	$(OVS_PKI) req+sign tests/pki/test && \
	$(OVS_PKI) req+sign tests/pki/test2 && \
	: > tests/pki/stamp
CLEANFILES += tests/ovs-pki.log

CLEAN_LOCAL += clean-pki
clean-pki:
	rm -f tests/pki/stamp
	rm -rf tests/pki
endif

include tests/oss-fuzz/automake.mk
