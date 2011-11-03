# Copyright (C) 2009, 2010, 2011 Nicira Networks, Inc.
#
# Copying and distribution of this file, with or without modification,
# are permitted in any medium without royalty provided the copyright
# notice and this notice are preserved.  This file is offered as-is,
# without warranty of any kind.

EXTRA_DIST += \
	rhel/README.RHEL \
	rhel/automake.mk \
	rhel/etc_init.d_openvswitch \
	rhel/etc_logrotate.d_openvswitch \
	rhel/etc_sysconfig_network-scripts_ifdown-ovs \
	rhel/etc_sysconfig_network-scripts_ifup-ovs \
	rhel/kmodtool-openvswitch-el5.sh \
	rhel/openvswitch-kmod-rhel5.spec \
	rhel/openvswitch-kmod-rhel5.spec.in \
	rhel/openvswitch-kmod-rhel6.spec \
	rhel/openvswitch-kmod-rhel6.spec.in \
	rhel/openvswitch.spec \
	rhel/openvswitch.spec.in \
	rhel/usr_share_openvswitch_scripts_sysconfig.template

update_spec = \
  ($(ro_shell) && sed -e 's,[@]VERSION[@],$(VERSION),g') \
    < $(srcdir)/rhel/$(@F).in > $(@F).tmp || exit 1; \
  if cmp -s $(@F).tmp $@; then touch $@; rm $(@F).tmp; else mv $(@F).tmp $@; fi

$(srcdir)/rhel/openvswitch-kmod-rhel5.spec: rhel/openvswitch-kmod-rhel5.spec.in $(top_builddir)/config.status
	$(update_spec)

$(srcdir)/rhel/openvswitch-kmod-rhel6.spec: rhel/openvswitch-kmod-rhel6.spec.in $(top_builddir)/config.status
	$(update_spec)

$(srcdir)/rhel/openvswitch.spec: rhel/openvswitch.spec.in $(top_builddir)/config.status
	$(update_spec)
