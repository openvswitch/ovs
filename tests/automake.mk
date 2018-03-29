EXTRA_DIST += \
	$(COMMON_MACROS_AT) \
	$(TESTSUITE_AT) \
	$(SYSTEM_TESTSUITE_AT) \
	$(SYSTEM_KMOD_TESTSUITE_AT) \
	$(SYSTEM_USERSPACE_TESTSUITE_AT) \
	$(SYSTEM_OFFLOADS_TESTSUITE_AT) \
	$(TESTSUITE) \
	$(SYSTEM_KMOD_TESTSUITE) \
	$(SYSTEM_USERSPACE_TESTSUITE) \
	$(SYSTEM_OFFLOADS_TESTSUITE) \
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
	tests/ovsdb-cluster.at \
	tests/ovs-vsctl.at \
	tests/ovs-xapi-sync.at \
	tests/stp.at \
	tests/rstp.at \
	tests/interface-reconfigure.at \
	tests/vlog.at \
	tests/vtep-ctl.at \
	tests/auto-attach.at \
	tests/ovn.at \
	tests/ovn-northd.at \
	tests/ovn-nbctl.at \
	tests/ovn-sbctl.at \
	tests/ovn-controller.at \
	tests/ovn-controller-vtep.at \
	tests/mcast-snooping.at \
	tests/packet-type-aware.at \
	tests/nsh.at

SYSTEM_KMOD_TESTSUITE_AT = \
	tests/system-common-macros.at \
	tests/system-kmod-testsuite.at \
	tests/system-kmod-macros.at

SYSTEM_USERSPACE_TESTSUITE_AT = \
	tests/system-userspace-testsuite.at \
	tests/system-ovn.at \
	tests/system-userspace-macros.at \
	tests/system-userspace-packet-type-aware.at

SYSTEM_TESTSUITE_AT = \
	tests/system-common-macros.at \
	tests/system-ovn.at \
	tests/system-layer3-tunnels.at \
	tests/system-traffic.at \
	tests/system-interface.at

SYSTEM_OFFLOADS_TESTSUITE_AT = \
	tests/system-common-macros.at \
	tests/system-offloads-traffic.at \
	tests/system-offloads-testsuite.at

check_SCRIPTS += tests/atlocal

TESTSUITE = $(srcdir)/tests/testsuite
TESTSUITE_PATCH = $(srcdir)/tests/testsuite.patch
SYSTEM_KMOD_TESTSUITE = $(srcdir)/tests/system-kmod-testsuite
SYSTEM_USERSPACE_TESTSUITE = $(srcdir)/tests/system-userspace-testsuite
SYSTEM_OFFLOADS_TESTSUITE = $(srcdir)/tests/system-offloads-testsuite
DISTCLEANFILES += tests/atconfig tests/atlocal

AUTOTEST_PATH = utilities:vswitchd:ovsdb:vtep:tests:$(PTHREAD_WIN32_DIR_DLL):$(SSL_DIR):ovn/controller-vtep:ovn/northd:ovn/utilities:ovn/controller

check-local:
	set $(SHELL) '$(TESTSUITE)' -C tests AUTOTEST_PATH=$(AUTOTEST_PATH) $(TESTSUITEFLAGS); \
	"$$@" || (test X'$(RECHECK)' = Xyes && "$$@" -j1 --recheck)

# Python Coverage support.
# Requires coverage.py http://nedbatchelder.com/code/coverage/.

COVERAGE = coverage
COVERAGE_FILE='$(abs_srcdir)/.coverage'
check-pycov: all clean-pycov
	PYTHONDONTWRITEBYTECODE=yes COVERAGE_FILE=$(COVERAGE_FILE) PYTHON='$(COVERAGE) run -p' $(SHELL) '$(TESTSUITE)' -C tests AUTOTEST_PATH=$(AUTOTEST_PATH) $(TESTSUITEFLAGS)
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
	-set $(SHELL) '$(TESTSUITE)' -C tests AUTOTEST_PATH=$(AUTOTEST_PATH) $(TESTSUITEFLAGS); \
	"$$@" || (test X'$(RECHECK)' = Xyes && "$$@" -j1 --recheck)
	$(MKDIR_P) tests/lcov
	lcov $(LCOV_OPTS) -o tests/lcov/coverage.info
	genhtml $(GENHTML_OPTS) -o tests/lcov tests/lcov/coverage.info
	@echo "coverage report generated at tests/lcov/index.html"

# valgrind support

valgrind_wrappers = \
	tests/valgrind/ovn-controller \
	tests/valgrind/ovn-nbctl \
	tests/valgrind/ovn-northd \
	tests/valgrind/ovn-sbctl \
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

VALGRIND = valgrind --log-file=valgrind.%p --leak-check=full \
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
check-kernel-valgrind: all $(valgrind_wrappers) $(check_DATA)
	set $(SHELL) '$(SYSTEM_KMOD_TESTSUITE)' -C tests VALGRIND='$(VALGRIND)' AUTOTEST_PATH='tests/valgrind:$(AUTOTEST_PATH)' -d $(TESTSUITEFLAGS) -j1; \
	"$$@" || (test X'$(RECHECK)' = Xyes && "$$@" --recheck)
	@echo
	@echo '----------------------------------------------------------------------'
	@echo 'Valgrind output can be found in tests/system-kmod-testsuite.dir/*/valgrind.*'
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
	set $(SHELL) '$(SYSTEM_KMOD_TESTSUITE)' -C tests  AUTOTEST_PATH='$(AUTOTEST_PATH)' $(TESTSUITEFLAGS) -j1; \
	"$$@" || (test X'$(RECHECK)' = Xyes && "$$@" --recheck)

# Testing the out of tree Kernel module
check-kmod: all
	$(MAKE) modules_install
	modprobe -r -a vport-geneve vport-gre vport-lisp vport-stt vport-vxlan openvswitch
	$(MAKE) check-kernel

check-system-userspace: all
	set $(SHELL) '$(SYSTEM_USERSPACE_TESTSUITE)' -C tests  AUTOTEST_PATH='$(AUTOTEST_PATH)' $(TESTSUITEFLAGS) -j1; \
	"$$@" || (test X'$(RECHECK)' = Xyes && "$$@" --recheck)

check-offloads: all
	set $(SHELL) '$(SYSTEM_OFFLOADS_TESTSUITE)' -C tests  AUTOTEST_PATH='$(AUTOTEST_PATH)' $(TESTSUITEFLAGS) -j1; \
	"$$@" || (test X'$(RECHECK)' = Xyes && "$$@" --recheck)

clean-local:
	test ! -f '$(TESTSUITE)' || $(SHELL) '$(TESTSUITE)' -C tests --clean

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

$(SYSTEM_OFFLOADS_TESTSUITE): package.m4 $(SYSTEM_TESTSUITE_AT) $(SYSTEM_OFFLOADS_TESTSUITE_AT) $(COMMON_MACROS_AT)
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

if DPDK_NETDEV
noinst_PROGRAMS += tests/test-dpdkr
tests_test_dpdkr_SOURCES = \
	tests/dpdk/ring_client.c
tests_test_dpdkr_LDADD = lib/libopenvswitch.la $(LIBS)
endif

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
	tests/test-ovn.c \
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

tests_ovstest_LDADD = lib/libopenvswitch.la ovn/lib/libovn.la

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
