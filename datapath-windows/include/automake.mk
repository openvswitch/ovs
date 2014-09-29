BUILT_SOURCES += $(srcdir)/datapath-windows/include/OvsDpInterface.h

$(srcdir)/datapath-windows/include/OvsDpInterface.h: \
         datapath/linux/compat/include/linux/openvswitch.h \
         build-aux/extract-odp-netlink-windows-dp-h
	$(AM_V_GEN)sed -f $(srcdir)/build-aux/extract-odp-netlink-windows-dp-h < $< > $@

EXTRA_DIST += $(srcdir)/build-aux/extract-odp-netlink-windows-dp-h

CLEANFILES += $(srcdir)/datapath-windows/include/OvsDpInterface.h
