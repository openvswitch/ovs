EXTRA_DIST += \
	debian/changelog \
	debian/compat \
	debian/control \
	debian/control.modules.in \
	debian/copyright \
	debian/copyright.in \
	debian/dkms.conf.in \
	debian/dirs \
	debian/libopenvswitch.install \
	debian/libopenvswitch-dev.install \
	debian/openvswitch-common.dirs \
	debian/openvswitch-common.docs \
	debian/openvswitch-common.install \
	debian/openvswitch-common.manpages \
	debian/openvswitch-datapath-module-_KVERS_.postinst.modules.in \
	debian/openvswitch-datapath-dkms.postinst \
	debian/openvswitch-datapath-dkms.prerm \
	debian/openvswitch-datapath-source.README.Debian \
	debian/openvswitch-datapath-source.copyright \
	debian/openvswitch-datapath-source.dirs \
	debian/openvswitch-datapath-source.install \
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
	debian/openvswitch-testcontroller.README.Debian \
	debian/openvswitch-testcontroller.default \
	debian/openvswitch-testcontroller.dirs \
	debian/openvswitch-testcontroller.init \
	debian/openvswitch-testcontroller.install \
	debian/openvswitch-testcontroller.manpages \
	debian/openvswitch-testcontroller.postinst \
	debian/openvswitch-testcontroller.postrm \
	debian/openvswitch-vtep.default \
	debian/openvswitch-vtep.dirs \
	debian/openvswitch-vtep.init \
	debian/openvswitch-vtep.install \
	debian/openvswitch-vtep.manpages \
	debian/ovn-central.dirs \
	debian/ovn-central.init \
	debian/ovn-central.install \
	debian/ovn-central.manpages \
	debian/ovn-central.postinst \
	debian/ovn-central.postrm \
	debian/ovn-central.template \
	debian/ovn-controller-vtep.init \
	debian/ovn-controller-vtep.install \
	debian/ovn-controller-vtep.manpages \
	debian/ovn-common.install \
	debian/ovn-common.manpages \
	debian/ovn-common.postinst \
	debian/ovn-common.postrm \
	debian/ovn-docker.install \
	debian/ovn-host.dirs \
	debian/ovn-host.init \
	debian/ovn-host.install \
	debian/ovn-host.manpages \
	debian/ovn-host.postinst \
	debian/ovn-host.postrm \
	debian/ovn-host.template \
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

$(srcdir)/debian/copyright: AUTHORS.rst debian/copyright.in
	$(AM_V_GEN) \
	{ sed -n -e '/%AUTHORS%/q' -e p < $(srcdir)/debian/copyright.in;   \
	  sed '34,/^$$/d' $(srcdir)/AUTHORS.rst |			   \
		sed -n -e '/^$$/q' -e 's/^/  /p';			   \
	  sed -e '34,/%AUTHORS%/d' $(srcdir)/debian/copyright.in;	   \
	} > $@

CLEANFILES += debian/copyright
