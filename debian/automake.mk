EXTRA_DIST += \
	debian/changelog \
	debian/compat \
	debian/control \
	debian/control.modules.in \
	debian/copyright \
	debian/copyright.in \
	debian/corekeeper.cron.daily \
	debian/corekeeper.init \
	debian/corekeeper.override \
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
	debian/openvswitch-pki-server.apache2 \
	debian/openvswitch-pki-server.dirs \
	debian/openvswitch-pki-server.install \
	debian/openvswitch-pki-server.postinst \
	debian/openvswitch-pki.postinst \
	debian/openvswitch-switch.README.Debian \
	debian/openvswitch-switch.dirs \
	debian/openvswitch-switch.init \
	debian/openvswitch-switch.install \
	debian/openvswitch-switch.logrotate \
	debian/openvswitch-switch.manpages \
	debian/openvswitch-switch.postinst \
	debian/openvswitch-switch.postrm \
	debian/openvswitch-switch.template \
	debian/rules \
	debian/rules.modules

check-debian-changelog-version:
	@if $(FGREP) '($(VERSION))' $(srcdir)/debian/changelog >/dev/null; \
	then								   \
	  :;								   \
	else								   \
	  echo "Update debian/changelog to mention version $(VERSION)";	   \
	  exit 1;							   \
	fi
ALL_LOCAL += check-debian-changelog-version
DIST_HOOKS += check-debian-changelog-version

$(srcdir)/debian/copyright: AUTHORS debian/copyright.in
	{ sed -n -e '/%AUTHORS%/q' -e p < $(srcdir)/debian/copyright.in;   \
	  sed '1,/^$$/d' $(srcdir)/AUTHORS |				   \
		sed -n -e '/^$$/q' -e 's/^/  /p';			   \
	  sed -e '1,/%AUTHORS%/d' $(srcdir)/debian/copyright.in;	   \
	} > $@

DISTCLEANFILES += debian/copyright
