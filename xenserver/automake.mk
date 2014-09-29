# Copyright (C) 2009, 2010, 2011, 2012, 2014 Nicira, Inc.
#
# Copying and distribution of this file, with or without modification,
# are permitted in any medium without royalty provided the copyright
# notice and this notice are preserved.  This file is offered as-is,
# without warranty of any kind.

EXTRA_DIST += \
	xenserver/GPLv2 \
	xenserver/LICENSE \
	xenserver/README \
	xenserver/automake.mk \
	xenserver/etc_init.d_openvswitch \
	xenserver/etc_init.d_openvswitch-xapi-update \
	xenserver/etc_logrotate.d_openvswitch \
	xenserver/etc_profile.d_openvswitch.sh \
	xenserver/etc_xapi.d_plugins_openvswitch-cfg-update \
	xenserver/etc_xensource_scripts_vif \
	xenserver/openvswitch-xen.spec \
	xenserver/openvswitch-xen.spec.in \
	xenserver/opt_xensource_libexec_InterfaceReconfigure.py \
	xenserver/opt_xensource_libexec_InterfaceReconfigureBridge.py \
	xenserver/opt_xensource_libexec_InterfaceReconfigureVswitch.py \
	xenserver/opt_xensource_libexec_interface-reconfigure \
	xenserver/usr_lib_xsconsole_plugins-base_XSFeatureVSwitch.py \
	xenserver/usr_share_openvswitch_scripts_ovs-xapi-sync \
	xenserver/usr_share_openvswitch_scripts_sysconfig.template

$(srcdir)/xenserver/openvswitch-xen.spec: xenserver/openvswitch-xen.spec.in $(top_builddir)/config.status
	$(AM_V_GEN)($(ro_shell) && sed -e 's,[@]VERSION[@],$(VERSION),g') \
		< $(srcdir)/xenserver/$(@F).in > $(@F).tmp || exit 1; \
	if cmp -s $(@F).tmp $@; then touch $@; rm $(@F).tmp; else mv $(@F).tmp $@; fi
