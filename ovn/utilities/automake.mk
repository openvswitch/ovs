scripts_SCRIPTS += \
    ovn/utilities/ovn-ctl

man_MANS += \
    ovn/utilities/ovn-ctl.8 \
    ovn/utilities/ovn-nbctl.8 \
    ovn/utilities/ovn-sbctl.8

MAN_ROOTS += ovn/utilities/ovn-sbctl.8.in

# Docker drivers
bin_SCRIPTS += \
    ovn/utilities/ovn-docker-overlay-driver \
    ovn/utilities/ovn-docker-underlay-driver

EXTRA_DIST += \
    ovn/utilities/ovn-ctl \
    ovn/utilities/ovn-ctl.8.xml \
    ovn/utilities/ovn-docker-overlay-driver \
    ovn/utilities/ovn-docker-underlay-driver \
    ovn/utilities/ovn-nbctl.8.xml

DISTCLEANFILES += \
    ovn/utilities/ovn-ctl.8 \
    ovn/utilities/ovn-nbctl.8 \
    ovn/utilities/ovn-sbctl.8

# ovn-nbctl
bin_PROGRAMS += ovn/utilities/ovn-nbctl
ovn_utilities_ovn_nbctl_SOURCES = ovn/utilities/ovn-nbctl.c
ovn_utilities_ovn_nbctl_LDADD = ovn/lib/libovn.la ovsdb/libovsdb.la lib/libopenvswitch.la

# ovn-sbctl
bin_PROGRAMS += ovn/utilities/ovn-sbctl
ovn_utilities_ovn_sbctl_SOURCES = ovn/utilities/ovn-sbctl.c
ovn_utilities_ovn_sbctl_LDADD = ovn/lib/libovn.la ovsdb/libovsdb.la lib/libopenvswitch.la
