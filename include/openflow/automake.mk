openflowincludedir = $(includedir)/openflow
openflowinclude_HEADERS = \
	include/openflow/intel-ext.h \
	include/openflow/netronome-ext.h \
	include/openflow/nicira-ext.h \
	include/openflow/openflow-1.0.h \
	include/openflow/openflow-1.1.h \
	include/openflow/openflow-1.2.h \
	include/openflow/openflow-1.3.h \
	include/openflow/openflow-1.4.h \
	include/openflow/openflow-1.5.h \
	include/openflow/openflow-common.h \
	include/openflow/openflow.h

if HAVE_PYTHON
SUFFIXES += .h .hstamp

.h.hstamp:
	$(AM_V_GEN)$(run_python) $(srcdir)/build-aux/check-structs -I$(srcdir)/include $< && \
	touch $@

HSTAMP_FILES = $(openflowinclude_HEADERS:.h=.hstamp)
CLEANFILES += $(HSTAMP_FILES)
ALL_LOCAL += $(HSTAMP_FILES)
$(HSTAMP_FILES): build-aux/check-structs $(openflowinclude_HEADERS)
endif

EXTRA_DIST += build-aux/check-structs

