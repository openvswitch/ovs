noinst_HEADERS += \
	include/openflow/openflow-mgmt.h \
	include/openflow/nicira-ext.h \
	include/openflow/openflow.h

if HAVE_PYTHON
all-local: include/openflow/openflow.h.stamp
include/openflow/openflow.h.stamp: \
	include/openflow/openflow.h build-aux/check-structs
	$(PYTHON) $(srcdir)/build-aux/check-structs $(srcdir)/include/openflow/openflow.h
	touch $@
DISTCLEANFILES += include/openflow/openflow.h.stamp

all-local: include/openflow/nicira-ext.h.stamp
include/openflow/nicira-ext.h.stamp: include/openflow/openflow.h include/openflow/nicira-ext.h build-aux/check-structs
	$(PYTHON) $(srcdir)/build-aux/check-structs $(srcdir)/include/openflow/openflow.h $(srcdir)/include/openflow/nicira-ext.h
	touch $@
DISTCLEANFILES += include/openflow/nicira-ext.h.stamp
endif

EXTRA_DIST += build-aux/check-structs

