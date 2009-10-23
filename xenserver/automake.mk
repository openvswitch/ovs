# Copyright (C) 2009 Nicira Networks, Inc.
#
# Copying and distribution of this file, with or without modification,
# are permitted in any medium without royalty provided the copyright
# notice and this notice are preserved.  This file is offered as-is,
# without warranty of any kind.

EXTRA_DIST += \
	xenserver/README \
	xenserver/etc_init.d_vswitch \
	xenserver/etc_init.d_vswitch-xapi-update \
	xenserver/etc_logrotate.d_vswitch \
	xenserver/etc_profile.d_vswitch.sh \
	xenserver/etc_xapi.d_plugins_vswitch-cfg-update \
	xenserver/etc_xensource_scripts_vif \
	xenserver/opt_xensource_libexec_interface-reconfigure \
	xenserver/usr_lib_xsconsole_plugins-base_XSFeatureVSwitch.py \
	xenserver/usr_sbin_brctl \
	xenserver/usr_sbin_xen-bugtool \
	xenserver/usr_share_vswitch_scripts_sysconfig.template \
	xenserver/usr_share_vswitch_scripts_dump-vif-details \
	xenserver/usr_share_vswitch_scripts_refresh-xs-network-uuids \
	xenserver/vswitch-xen.spec
