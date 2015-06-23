scripts_SCRIPTS += \
    ovn/utilities/ovn-ctl

man_MANS += \
    ovn/utilities/ovn-ctl.8

EXTRA_DIST += \
    ovn/utilities/ovn-ctl \
    ovn/utilities/ovn-ctl.8.xml

DISTCLEANFILES += \
    ovn/utilities/ovn-ctl.8
