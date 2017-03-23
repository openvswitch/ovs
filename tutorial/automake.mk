EXTRA_DIST += \
	tutorial/ovs-sandbox \
	tutorial/t-setup \
	tutorial/t-stage0 \
	tutorial/t-stage1 \
	tutorial/t-stage2 \
	tutorial/t-stage3 \
	tutorial/t-stage4 \
	tutorial/ovn-setup.sh
sandbox: all
	cd $(srcdir)/tutorial && MAKE=$(MAKE) HAVE_OPENSSL=$(HAVE_OPENSSL) \
		./ovs-sandbox -b $(abs_builddir) $(SANDBOXFLAGS)
