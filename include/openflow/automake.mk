noinst_HEADERS += \
	include/openflow/nicira-ext.h \
	include/openflow/openflow-1.0.h \
	include/openflow/openflow.h

if HAVE_PYTHON
SUFFIXES += .h .hstamp

.h.hstamp:
	$(PYTHON) $(srcdir)/build-aux/check-structs -I$(srcdir)/include $<
	touch $@

HSTAMP_FILES = \
	include/openflow/openflow.hstamp \
	include/openflow/openflow-1.0.hstamp \
	include/openflow/nicira.hstamp
ALL_LOCAL += $(HSTAMP_FILES)
$(HSTAMP_FILES): build-aux/check-structs

include/openflow/openflow-1.0.hstamp: include/openflow/openflow.h
include/openflow/nicira-ext.hstamp: \
	include/openflow/openflow-1.0.h \
	include/openflow/openflow.h
endif

EXTRA_DIST += build-aux/check-structs

