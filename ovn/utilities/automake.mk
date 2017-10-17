scripts_SCRIPTS += \
    ovn/utilities/ovn-ctl \
    ovn/utilities/ovndb-servers.ocf

man_MANS += \
    ovn/utilities/ovn-ctl.8 \
    ovn/utilities/ovn-nbctl.8 \
    ovn/utilities/ovn-sbctl.8 \
    ovn/utilities/ovn-trace.8 \
    ovn/utilities/ovn-detrace.1

MAN_ROOTS += \
    ovn/utilities/ovn-sbctl.8.in \
    ovn/utilities/ovn-detrace.1.in

# Docker drivers
bin_SCRIPTS += \
    ovn/utilities/ovn-docker-overlay-driver \
    ovn/utilities/ovn-docker-underlay-driver \
    ovn/utilities/ovn-detrace

EXTRA_DIST += \
    ovn/utilities/ovn-ctl \
    ovn/utilities/ovn-ctl.8.xml \
    ovn/utilities/ovn-docker-overlay-driver.in \
    ovn/utilities/ovn-docker-underlay-driver.in \
    ovn/utilities/ovn-nbctl.8.xml \
    ovn/utilities/ovn-trace.8.xml \
    ovn/utilities/ovn-detrace.in \
    ovn/utilities/ovndb-servers.ocf

CLEANFILES += \
    ovn/utilities/ovn-ctl.8 \
    ovn/utilities/ovn-docker-overlay-driver \
    ovn/utilities/ovn-docker-underlay-driver \
    ovn/utilities/ovn-nbctl.8 \
    ovn/utilities/ovn-sbctl.8 \
    ovn/utilities/ovn-trace.8 \
    ovn/utilities/ovn-detrace.1 \
    ovn/utilities/ovn-detrace

# ovn-nbctl
bin_PROGRAMS += ovn/utilities/ovn-nbctl
ovn_utilities_ovn_nbctl_SOURCES = ovn/utilities/ovn-nbctl.c
ovn_utilities_ovn_nbctl_LDADD = ovn/lib/libovn.la ovsdb/libovsdb.la lib/libopenvswitch.la

# ovn-sbctl
bin_PROGRAMS += ovn/utilities/ovn-sbctl
ovn_utilities_ovn_sbctl_SOURCES = ovn/utilities/ovn-sbctl.c
ovn_utilities_ovn_sbctl_LDADD = ovn/lib/libovn.la ovsdb/libovsdb.la lib/libopenvswitch.la

# ovn-trace
bin_PROGRAMS += ovn/utilities/ovn-trace
ovn_utilities_ovn_trace_SOURCES = ovn/utilities/ovn-trace.c
ovn_utilities_ovn_trace_LDADD = ovn/lib/libovn.la ovsdb/libovsdb.la lib/libopenvswitch.la

include ovn/utilities/bugtool/automake.mk
