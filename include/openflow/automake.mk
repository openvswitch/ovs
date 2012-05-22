noinst_HEADERS += \
	include/openflow/nicira-ext.h \
	include/openflow/openflow-1.0.h \
	include/openflow/openflow-1.1.h \
	include/openflow/openflow-1.2.h \
	include/openflow/openflow-common.h \
	include/openflow/openflow.h

if HAVE_PYTHON
SUFFIXES += .h .hstamp

.h.hstamp:
	$(run_python) $(srcdir)/build-aux/check-structs -I$(srcdir)/include $<
	touch $@

HSTAMP_FILES = \
	include/openflow/nicira.hstamp \
	include/openflow/openflow-1.0.hstamp \
	include/openflow/openflow-1.1.hstamp \
	include/openflow/openflow-1.2.hstamp \
	include/openflow/openflow.hstamp
CLEANFILES += $(HSTAMP_FILES)
ALL_LOCAL += $(HSTAMP_FILES)
$(HSTAMP_FILES): build-aux/check-structs

include/openflow/openflow-1.0.hstamp: include/openflow/openflow-common.h
include/openflow/openflow-1.1.hstamp: include/openflow/openflow-common.h
include/openflow/nicira-ext.hstamp: \
	include/openflow/openflow-1.0.h \
	include/openflow/openflow-1.1.h \
	include/openflow/openflow-1.2.h \
	include/openflow/openflow-common.h \
	include/openflow/openflow.h
endif

EXTRA_DIST += build-aux/check-structs

