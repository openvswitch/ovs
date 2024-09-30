EXTRA_DIST += \
	debian/README.Debian \
	debian/changelog \
	debian/clean \
	debian/control.in \
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


update_deb_copyright = \
	$(AM_V_GEN) \
	{ sed -n -e '/%AUTHORS%/q' -e p < $(srcdir)/debian/copyright.in;   \
	  tail -n +28 $(srcdir)/AUTHORS.rst | sed '1,/^$$/d' |		   \
		sed -n -e '/^$$/q' -e 's/^/  /p';			   \
	  sed -e '1,/%AUTHORS%/d' $(srcdir)/debian/copyright.in;	   \
	} > debian/copyright

debian/copyright: AUTHORS.rst debian/copyright.in
	$(update_deb_copyright)

CLEANFILES += debian/copyright


if DPDK_NETDEV
update_deb_control = \
	$(AM_V_GEN) sed -e 's/^\# DPDK_NETDEV //' \
		< $(srcdir)/debian/control.in > debian/control
DEB_BUILD_OPTIONS ?= nocheck parallel=`nproc`
else
update_deb_control = \
	$(AM_V_GEN) grep -v '^\# DPDK_NETDEV' \
		< $(srcdir)/debian/control.in > debian/control
DEB_BUILD_OPTIONS ?= nocheck parallel=`nproc` nodpdk
endif

debian/control: $(srcdir)/debian/control.in Makefile
	$(update_deb_control)

CLEANFILES += debian/control


debian: debian/copyright debian/control
.PHONY: debian


debian-deb: debian
	@if test X"$(srcdir)" != X"$(top_builddir)"; then			\
		echo "Debian packages should be built from $(abs_srcdir)/";	\
		exit 1;								\
	fi
	$(MAKE) distclean
	$(update_deb_copyright)
	$(update_deb_control)
	$(AM_V_GEN) fakeroot debian/rules clean
	$(AM_V_GEN) DEB_BUILD_OPTIONS="$(DEB_BUILD_OPTIONS)" \
		fakeroot debian/rules binary
