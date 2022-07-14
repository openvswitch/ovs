EXTRA_DIST += \
	debian/README.Debian \
	debian/changelog \
	debian/clean \
	debian/control \
	debian/copyright \
	debian/copyright.in \
	debian/dirs \
	debian/gbp.conf \
	debian/ifupdown.sh \
	debian/ltmain-whole-archive.diff \
	debian/not-installed \
	debian/openvswitch-common.dirs \
	debian/openvswitch-common.install \
	debian/openvswitch-common.lintian-overrides \
	debian/openvswitch-doc.doc-base \
	debian/openvswitch-doc.install \
	debian/openvswitch-ipsec.init \
	debian/openvswitch-ipsec.install \
	debian/openvswitch-ipsec.service \
	debian/openvswitch-pki.dirs \
	debian/openvswitch-pki.postinst \
	debian/openvswitch-pki.postrm \
	debian/openvswitch-source.dirs \
	debian/openvswitch-source.docs \
	debian/openvswitch-source.install \
	debian/openvswitch-switch-dpdk.README.Debian \
	debian/openvswitch-switch-dpdk.install \
	debian/openvswitch-switch-dpdk.postinst \
	debian/openvswitch-switch-dpdk.prerm \
	debian/openvswitch-switch.README.Debian \
	debian/openvswitch-switch.default \
	debian/openvswitch-switch.dirs \
	debian/openvswitch-switch.init \
	debian/openvswitch-switch.install \
	debian/openvswitch-switch.links \
	debian/openvswitch-switch.lintian-overrides \
	debian/openvswitch-switch.logrotate \
	debian/openvswitch-switch.ovs-record-hostname.service \
	debian/openvswitch-switch.ovs-vswitchd.service \
	debian/openvswitch-switch.ovsdb-server.service \
	debian/openvswitch-switch.postinst \
	debian/openvswitch-switch.postrm \
	debian/openvswitch-switch.preinst \
	debian/openvswitch-switch.prerm \
	debian/openvswitch-switch.service \
	debian/openvswitch-test.install \
	debian/openvswitch-testcontroller.README.Debian \
	debian/openvswitch-testcontroller.default \
	debian/openvswitch-testcontroller.dirs \
	debian/openvswitch-testcontroller.init \
	debian/openvswitch-testcontroller.install \
	debian/openvswitch-testcontroller.postinst \
	debian/openvswitch-testcontroller.postrm \
	debian/openvswitch-vtep.default \
	debian/openvswitch-vtep.dirs \
	debian/openvswitch-vtep.init \
	debian/openvswitch-vtep.install \
	debian/ovs-systemd-reload \
	debian/patches/ovs-ctl-ipsec.patch \
	debian/patches/series \
	debian/rules \
	debian/source/format \
	debian/source/lintian-overrides \
	debian/tests/control \
	debian/tests/dpdk \
	debian/tests/openflow.py \
	debian/tests/vanilla \
	debian/watch

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
	  tail -n +28 $(srcdir)/AUTHORS.rst | sed '1,/^$$/d' |		   \
		sed -n -e '/^$$/q' -e 's/^/  /p';			   \
	  sed -e '1,/%AUTHORS%/d' $(srcdir)/debian/copyright.in;	   \
	} > $@

DISTCLEANFILES += debian/copyright
