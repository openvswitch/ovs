EXTRA_DIST += \
	tutorial/Tutorial \
	tutorial/ovs-sandbox \
	tutorial/t-setup \
	tutorial/t-stage0 \
	tutorial/t-stage1 \
	tutorial/t-stage2 \
	tutorial/t-stage3 \
	tutorial/t-stage4

sandbox: all
	cd $(srcdir)/tutorial && ./ovs-sandbox -b $(abs_builddir)
