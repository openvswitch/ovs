BUILT_SOURCES += include/odp-netlink.h

include/odp-netlink.h: datapath/linux/compat/include/linux/openvswitch.h \
                       build-aux/extract-odp-netlink-h
	$(AM_V_GEN)sed -f $(srcdir)/build-aux/extract-odp-netlink-h < $< > $@
EXTRA_DIST += build-aux/extract-odp-netlink-h
CLEANFILES += include/odp-netlink.h

include include/openflow/automake.mk
include include/openvswitch/automake.mk
include include/sparse/automake.mk
include include/windows/automake.mk
