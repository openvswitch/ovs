BUILT_SOURCES += include/odp-netlink.h include/odp-netlink-macros.h

include/odp-netlink.h: datapath/linux/compat/include/linux/openvswitch.h \
                       build-aux/extract-odp-netlink-h
	$(AM_V_GEN)sed -f $(srcdir)/build-aux/extract-odp-netlink-h < $< > $@

include/odp-netlink-macros.h: include/odp-netlink.h \
                              build-aux/extract-odp-netlink-macros-h
	$(AM_V_GEN)sh -f $(srcdir)/build-aux/extract-odp-netlink-macros-h $< > $@

EXTRA_DIST += build-aux/extract-odp-netlink-h build-aux/extract-odp-netlink-macros-h
CLEANFILES += include/odp-netlink.h include/odp-netlink-macros.h

include include/openflow/automake.mk
include include/openvswitch/automake.mk
include include/sparse/automake.mk
include include/windows/automake.mk
include include/linux/automake.mk
