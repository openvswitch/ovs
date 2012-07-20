EXTRA_DIST += \
	debian/changelog \
	debian/compat \
	debian/control \
	debian/control.modules.in \
	debian/copyright \
	debian/copyright.in \
	debian/dkms.conf.in \
	debian/dirs \
	debian/openvswitch-brcompat.install \
	debian/openvswitch-brcompat.manpages \
	debian/openvswitch-brcompat.postinst \
	debian/openvswitch-brcompat.postrm \
	debian/openvswitch-common.dirs \
	debian/openvswitch-common.docs \
	debian/openvswitch-common.install \
	debian/openvswitch-common.manpages \
	debian/openvswitch-controller.README.Debian \
	debian/openvswitch-controller.default \
	debian/openvswitch-controller.dirs \
	debian/openvswitch-controller.init \
	debian/openvswitch-controller.install \
	debian/openvswitch-controller.manpages \
	debian/openvswitch-controller.postinst \
	debian/openvswitch-controller.postrm \
	debian/openvswitch-datapath-module-_KVERS_.postinst.modules.in \
	debian/openvswitch-datapath-dkms.postinst \
	debian/openvswitch-datapath-dkms.prerm \
	debian/openvswitch-datapath-source.README.Debian \
	debian/openvswitch-datapath-source.copyright \
	debian/openvswitch-datapath-source.dirs \
	debian/openvswitch-datapath-source.install \
	debian/openvswitch-ipsec.dirs \
	debian/openvswitch-ipsec.init \
	debian/openvswitch-ipsec.install \
	debian/openvswitch-pki.dirs \
	debian/openvswitch-pki.postinst \
	debian/openvswitch-pki.postrm \
	debian/openvswitch-switch.README.Debian \
	debian/openvswitch-switch.dirs \
	debian/openvswitch-switch.init \
	debian/openvswitch-switch.install \
	debian/openvswitch-switch.logrotate \
	debian/openvswitch-switch.manpages \
	debian/openvswitch-switch.postinst \
	debian/openvswitch-switch.postrm \
	debian/openvswitch-switch.template \
	debian/openvswitch-switch.links \
	debian/openvswitch-test.dirs \
	debian/openvswitch-test.install \
	debian/openvswitch-test.manpages \
	debian/ovsdbmonitor.install \
	debian/ovsdbmonitor.manpages \
	debian/ovs-monitor-ipsec \
	debian/python-openvswitch.dirs \
	debian/python-openvswitch.install \
	debian/rules \
	debian/rules.modules \
	debian/ifupdown.sh \
	debian/source/format

check-debian-changelog-version:
	@DEB_VERSION=`echo '$(VERSION)' | sed 's/pre/~pre/'`;		     \
	if $(FGREP) '($(DEB_VERSION)' $(srcdir)/debian/changelog >/dev/null; \
	then								     \
	  :;								     \
	else								     \
	  echo "Update debian/changelog to mention version $(VERSION)";	     \
	  exit 1;							     \
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
