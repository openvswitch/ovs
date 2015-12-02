docs += \
	tutorial/Tutorial.md \
	tutorial/OVN-Tutorial.md
EXTRA_DIST += \
	tutorial/ovs-sandbox \
	tutorial/t-setup \
	tutorial/t-stage0 \
	tutorial/t-stage1 \
	tutorial/t-stage2 \
	tutorial/t-stage3 \
	tutorial/t-stage4 \
	tutorial/ovn/env1/setup.sh \
	tutorial/ovn/env1/packet1.sh \
	tutorial/ovn/env1/packet2.sh \
	tutorial/ovn/env1/add-third-port.sh \
	tutorial/ovn/env2/setup.sh \
	tutorial/ovn/env2/packet1.sh \
	tutorial/ovn/env2/packet2.sh \
	tutorial/ovn/env3/setup.sh \
	tutorial/ovn/env3/packet1.sh \
	tutorial/ovn/env3/packet2.sh \
	tutorial/ovn/env4/setup1.sh \
	tutorial/ovn/env4/setup2.sh \
	tutorial/ovn/env4/packet1.sh \
	tutorial/ovn/env4/packet2.sh \
	tutorial/ovn/env4/packet3.sh \
	tutorial/ovn/env4/packet4.sh \
	tutorial/ovn/env4/packet5.sh \
	tutorial/ovn/env5/setup.sh \
	tutorial/ovn/env5/packet1.sh \
	tutorial/ovn/env5/packet2.sh \
	tutorial/ovn/env6/setup.sh \
	tutorial/ovn/env6/add-acls.sh

sandbox: all
	cd $(srcdir)/tutorial && MAKE=$(MAKE) ./ovs-sandbox -b $(abs_builddir) $(SANDBOXFLAGS)
