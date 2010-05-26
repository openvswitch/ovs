EXTRA_DIST += \
	debian/changelog \
	debian/compat \
	debian/control \
	debian/control.modules.in \
	debian/copyright \
	debian/corekeeper.cron.daily \
	debian/corekeeper.init \
	debian/dirs \
	debian/openvswitch-common.dirs \
	debian/openvswitch-common.install \
	debian/openvswitch-common.manpages \
	debian/openvswitch-controller.README.Debian \
	debian/openvswitch-controller.default \
	debian/openvswitch-controller.dirs \
	debian/openvswitch-controller.init \
	debian/openvswitch-controller.install \
	debian/openvswitch-controller.manpages \
	debian/openvswitch-controller.postinst \
	debian/openvswitch-datapath-module-_KVERS_.postinst.modules.in \
	debian/openvswitch-datapath-source.README.Debian \
	debian/openvswitch-datapath-source.copyright \
	debian/openvswitch-datapath-source.dirs \
	debian/openvswitch-datapath-source.install \
	debian/openvswitch-monitor.default \
	debian/openvswitch-monitor.dirs \
	debian/openvswitch-monitor.init \
	debian/openvswitch-monitor.install \
	debian/openvswitch-pki-server.apache2 \
	debian/openvswitch-pki-server.dirs \
	debian/openvswitch-pki-server.install \
	debian/openvswitch-pki-server.postinst \
	debian/openvswitch-pki.postinst \
	debian/openvswitch-switch-config.dirs \
	debian/openvswitch-switch-config.install \
	debian/openvswitch-switch-config.manpages \
	debian/openvswitch-switch-config.overrides \
	debian/openvswitch-switch-config.templates \
	debian/openvswitch-switch.README.Debian \
	debian/openvswitch-switch.dirs \
	debian/openvswitch-switch.init \
	debian/openvswitch-switch.install \
	debian/openvswitch-switch.logrotate \
	debian/openvswitch-switch.manpages \
	debian/openvswitch-switch.postinst \
	debian/openvswitch-switch.postrm \
	debian/openvswitch-switch.template \
	debian/openvswitch-switchui.copyright \
	debian/openvswitch-switchui.default \
	debian/openvswitch-switchui.dirs \
	debian/openvswitch-switchui.init \
	debian/openvswitch-switchui.install \
	debian/openvswitch-wdt.default \
	debian/openvswitch-wdt.dirs \
	debian/openvswitch-wdt.init \
	debian/openvswitch-wdt.install \
	debian/ovs-switch-setup \
	debian/ovs-switch-setup.8 \
	debian/po/POTFILES.in \
	debian/po/templates.pot \
	debian/reconfigure \
	debian/rules \
	debian/rules.modules

dist-hook:
	$(srcdir)/build-aux/update-debian-changelog '$(distdir)/debian/changelog' '$(VERSION)'
EXTRA_DIST += build-aux/check-structs
