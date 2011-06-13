run_python = PYTHONPATH=$(top_srcdir)/python:$$PYTHON_PATH $(PYTHON)

ovs_pyfiles = \
	python/ovs/__init__.py \
	python/ovs/daemon.py \
	python/ovs/db/__init__.py \
	python/ovs/db/data.py \
	python/ovs/db/error.py \
	python/ovs/db/idl.py \
	python/ovs/db/parser.py \
	python/ovs/db/schema.py \
	python/ovs/db/types.py \
	python/ovs/fatal_signal.py \
	python/ovs/json.py \
	python/ovs/jsonrpc.py \
	python/ovs/ovsuuid.py \
	python/ovs/poller.py \
	python/ovs/process.py \
	python/ovs/reconnect.py \
	python/ovs/socket_util.py \
	python/ovs/stream.py \
	python/ovs/timeval.py \
	python/ovs/util.py
EXTRA_DIST += $(ovs_pyfiles) python/ovs/dirs.py

if HAVE_PYTHON
nobase_pkgdata_DATA = $(ovs_pyfiles)
ovs-install-data-local:
	$(MKDIR_P) python/ovs
	(echo "import os" && \
	 echo 'PKGDATADIR = os.environ.get("OVS_PKGDATADIR", """$(pkgdatadir)""")' && \
	 echo 'RUNDIR = os.environ.get("OVS_RUNDIR", """@RUNDIR@""")' && \
	 echo 'LOGDIR = os.environ.get("OVS_LOGDIR", """@LOGDIR@""")' && \
	 echo 'BINDIR = os.environ.get("OVS_BINDIR", """$(bindir)""")') \
		> python/ovs/dirs.py.tmp
	$(MKDIR_P) $(DESTDIR)$(pkgdatadir)/python/ovs
	$(INSTALL_DATA) python/ovs/dirs.py.tmp $(DESTDIR)$(pkgdatadir)/python/ovs/dirs.py
	rm python/ovs/dirs.py.tmp
else
ovs-install-data-local:
	@:
endif
install-data-local: ovs-install-data-local

uninstall-local: ovs-uninstall-local
ovs-uninstall-local:
	rm -f $(DESTDIR)$(pkgdatadir)/python/ovs/dirs.py
