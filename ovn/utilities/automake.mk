scripts_SCRIPTS += \
    ovn/utilities/ovn-ctl

man_MANS += \
    ovn/utilities/ovn-ctl.8 \
    ovn/utilities/ovn-nbctl.8

EXTRA_DIST += \
    ovn/utilities/ovn-ctl \
    ovn/utilities/ovn-ctl.8.xml \
    ovn/utilities/ovn-nbctl.8.xml

DISTCLEANFILES += \
    ovn/utilities/ovn-ctl.8 \
    ovn/utilities/ovn-nbctl.8

# ovn-nbctl
bin_PROGRAMS += ovn/utilities/ovn-nbctl
ovn_utilities_ovn_nbctl_SOURCES = ovn/utilities/ovn-nbctl.c
ovn_utilities_ovn_nbctl_LDADD = ovn/lib/libovn.la ovsdb/libovsdb.la lib/libopenvswitch.la
