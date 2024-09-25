ovstest_pyfiles = \
	python/ovstest/__init__.py \
	python/ovstest/args.py \
	python/ovstest/rpcserver.py \
	python/ovstest/tcp.py \
	python/ovstest/tests.py \
	python/ovstest/udp.py \
	python/ovstest/util.py \
	python/ovstest/vswitch.py

ovs_pyfiles = \
	python/ovs/__init__.py \
	python/ovs/compat/__init__.py \
	python/ovs/compat/sortedcontainers/__init__.py \
	python/ovs/compat/sortedcontainers/sortedlist.py \
	python/ovs/compat/sortedcontainers/sorteddict.py \
	python/ovs/compat/sortedcontainers/sortedset.py \
	python/ovs/daemon.py \
	python/ovs/dns_resolve.py \
	python/ovs/db/__init__.py \
	python/ovs/db/custom_index.py \
	python/ovs/db/data.py \
	python/ovs/db/error.py \
	python/ovs/db/idl.py \
	python/ovs/db/parser.py \
	python/ovs/db/schema.py \
	python/ovs/db/types.py \
	python/ovs/fatal_signal.py \
	python/ovs/fcntl_win.py \
	python/ovs/flow/__init__.py \
	python/ovs/flow/decoders.py \
	python/ovs/flow/filter.py \
	python/ovs/flow/flow.py \
	python/ovs/flow/kv.py \
	python/ovs/flow/list.py \
	python/ovs/flow/odp.py \
	python/ovs/flow/ofp.py \
	python/ovs/flow/ofp_act.py \
	python/ovs/flow/ofp_fields.py \
	python/ovs/json.py \
	python/ovs/jsonrpc.py \
	python/ovs/ovsuuid.py \
	python/ovs/poller.py \
	python/ovs/process.py \
	python/ovs/reconnect.py \
	python/ovs/socket_util.py \
	python/ovs/stream.py \
	python/ovs/timeval.py \
	python/ovs/unixctl/__init__.py \
	python/ovs/unixctl/client.py \
	python/ovs/unixctl/server.py \
	python/ovs/util.py \
	python/ovs/version.py \
	python/ovs/vlog.py \
	python/ovs/winutils.py

ovs_pytests = \
	python/ovs/tests/test_decoders.py \
	python/ovs/tests/test_dns_resolve.py \
	python/ovs/tests/test_filter.py \
	python/ovs/tests/test_kv.py \
	python/ovs/tests/test_list.py \
	python/ovs/tests/test_odp.py \
	python/ovs/tests/test_ofp.py

ovs_flowviz = \
	python/ovs/flowviz/__init__.py \
	python/ovs/flowviz/console.py \
	python/ovs/flowviz/format.py \
	python/ovs/flowviz/html_format.py \
	python/ovs/flowviz/main.py \
	python/ovs/flowviz/odp/__init__.py \
	python/ovs/flowviz/odp/cli.py \
	python/ovs/flowviz/odp/graph.py \
	python/ovs/flowviz/odp/html.py \
	python/ovs/flowviz/odp/tree.py \
	python/ovs/flowviz/ofp/__init__.py \
	python/ovs/flowviz/ofp/cli.py \
	python/ovs/flowviz/ofp/logic.py \
	python/ovs/flowviz/ofp/html.py \
	python/ovs/flowviz/ovs-flowviz \
	python/ovs/flowviz/process.py

# These python files are used at build time but not runtime,
# so they are not installed.
EXTRA_DIST += \
	python/ovs_build_helpers/__init__.py \
	python/ovs_build_helpers/extract_ofp_fields.py \
	python/ovs_build_helpers/nroff.py \
	python/ovs_build_helpers/soutil.py

# PyPI support.
EXTRA_DIST += \
	python/ovs/compat/sortedcontainers/LICENSE \
	python/ovs/flowviz/ovs-flowviz.conf \
	python/README.rst \
	python/setup.py \
	python/test_requirements.txt

# C extension support.
EXTRA_DIST += python/ovs/_json.c

PYFILES = $(ovs_pyfiles) python/ovs/dirs.py python/setup.py $(ovstest_pyfiles) $(ovs_pytests) \
	$(ovs_flowviz)

EXTRA_DIST += $(PYFILES)
PYCOV_CLEAN_FILES += $($(filter %.py, PYFILES):.py=.py,cover) python/ovs/flowviz/ovs-flowviz,cover

FLAKE8_PYFILES += \
	$(filter-out python/ovs/compat/% python/ovs/dirs.py python/setup.py,$(PYFILES)) \
	python/ovs_build_helpers/__init__.py \
	python/ovs_build_helpers/extract_ofp_fields.py \
	python/ovs_build_helpers/nroff.py \
	python/ovs_build_helpers/soutil.py \
	python/ovs/dirs.py.template \
	python/setup.py.template

nobase_pkgdata_DATA = $(ovs_pyfiles) $(ovstest_pyfiles) $(ovs_flowviz)
nobase_pkgdata_DATA += python/ovs/flowviz/ovs-flowviz.conf

ovs-install-data-local:
	$(MKDIR_P) python/ovs
	sed \
		-e '/^##/d' \
		-e 's,[@]pkgdatadir[@],$(pkgdatadir),g' \
		-e 's,[@]RUNDIR[@],$(RUNDIR),g' \
		-e 's,[@]LOGDIR[@],$(LOGDIR),g' \
		-e 's,[@]bindir[@],$(bindir),g' \
		-e 's,[@]sysconfdir[@],$(sysconfdir),g' \
		-e 's,[@]DBDIR[@],$(DBDIR),g' \
		< $(srcdir)/python/ovs/dirs.py.template \
		> python/ovs/dirs.py.tmp
	$(MKDIR_P) $(DESTDIR)$(pkgdatadir)/python/ovs
	$(INSTALL_DATA) python/ovs/dirs.py.tmp $(DESTDIR)$(pkgdatadir)/python/ovs/dirs.py
	rm python/ovs/dirs.py.tmp

.PHONY: python-sdist
python-sdist: $(srcdir)/python/ovs/version.py $(ovs_pyfiles) python/ovs/dirs.py python/setup.py
	cd python/ && $(PYTHON3) -m build --sdist

.PHONY: pypi-upload
pypi-upload: python-sdist
	twine upload python/dist/ovs-$(VERSION).tar.gz

install-data-local: ovs-install-data-local

UNINSTALL_LOCAL += ovs-uninstall-local
ovs-uninstall-local:
	rm -f $(DESTDIR)$(pkgdatadir)/python/ovs/dirs.py

ALL_LOCAL += $(srcdir)/python/ovs/version.py
$(srcdir)/python/ovs/version.py: config.status
	$(AM_V_GEN)$(ro_shell) > $(@F).tmp && \
	echo 'VERSION = "$(VERSION)$(VERSION_SUFFIX)"' >> $(@F).tmp && \
	if cmp -s $(@F).tmp $@; then touch $@; else cp $(@F).tmp $@; fi; rm $(@F).tmp

ALL_LOCAL += $(srcdir)/python/ovs/dirs.py
$(srcdir)/python/ovs/dirs.py: python/ovs/dirs.py.template
	$(AM_V_GEN)sed \
		-e '/^##/d' \
		-e 's,[@]pkgdatadir[@],$(pkgdatadir),g' \
		-e 's,[@]RUNDIR[@],$(RUNDIR),g' \
		-e 's,[@]LOGDIR[@],$(LOGDIR),g' \
		-e 's,[@]bindir[@],$(bindir),g' \
		-e 's,[@]sysconfdir[@],$(sysconfdir),g' \
		-e 's,[@]DBDIR[@],$(sysconfdir)/openvswitch,g' \
		< $? > $@.tmp && \
	mv $@.tmp $@
EXTRA_DIST += python/ovs/dirs.py.template
CLEANFILES += python/ovs/dirs.py

ALL_LOCAL += $(srcdir)/python/setup.py
$(srcdir)/python/setup.py: python/setup.py.template config.status
	$(AM_V_GEN)sed \
		-e 's,[@]VERSION[@],$(VERSION),g' \
		< $(srcdir)/python/setup.py.template > $(@F).tmp && \
	if cmp -s $(@F).tmp $@; then touch $@; else cp $(@F).tmp $@; fi; rm $(@F).tmp
EXTRA_DIST += python/setup.py.template
CLEANFILES += python/setup.py

EXTRA_DIST += python/TODO.rst

$(srcdir)/python/ovs/flow/ofp_fields.py: $(srcdir)/build-aux/gen_ofp_field_decoders include/openvswitch/meta-flow.h
	$(AM_V_GEN)$(run_python) $< $(srcdir)/include/openvswitch/meta-flow.h > $@.tmp
	$(AM_V_at)mv $@.tmp $@
EXTRA_DIST += python/ovs/flow/ofp_fields.py
CLEANFILES += python/ovs/flow/ofp_fields.py
