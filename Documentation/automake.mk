EXTRA_DIST += \
	Documentation/group-selection-method-property.txt \
	Documentation/_static/logo.png \
	Documentation/conf.py \
	Documentation/index.rst \
	Documentation/contents.rst \
	Documentation/intro/index.rst \
	Documentation/intro/why-ovs.rst \
	Documentation/intro/install/index.rst \
	Documentation/intro/install/bash-completion.rst \
	Documentation/intro/install/debian.rst \
	Documentation/intro/install/dpdk-advanced.rst \
	Documentation/intro/install/dpdk.rst \
	Documentation/intro/install/fedora.rst \
	Documentation/intro/install/general.rst \
	Documentation/intro/install/netbsd.rst \
	Documentation/intro/install/rhel.rst \
	Documentation/intro/install/userspace.rst \
	Documentation/intro/install/windows.rst \
	Documentation/intro/install/xenserver.rst \
	Documentation/tutorials/index.rst \
	Documentation/tutorials/ovn-basics.rst \
	Documentation/tutorials/ovs-advanced.rst \
	Documentation/topics/index.rst \
	Documentation/topics/bonding.rst \
	Documentation/topics/datapath.rst \
	Documentation/topics/design.rst \
	Documentation/topics/dpdk.rst \
	Documentation/topics/high-availability.rst \
	Documentation/topics/integration.rst \
	Documentation/topics/openflow.rst \
	Documentation/topics/ovsdb-replication.rst \
	Documentation/topics/porting.rst \
	Documentation/topics/windows.rst \
	Documentation/howto/index.rst \
	Documentation/howto/docker.rst \
	Documentation/howto/kvm.rst \
	Documentation/howto/libvirt.rst \
	Documentation/howto/selinux.rst \
	Documentation/howto/ssl.rst \
	Documentation/howto/native-tunneling.rst \
	Documentation/howto/lisp.rst \
	Documentation/howto/openstack-containers.rst \
	Documentation/howto/vtep.rst \
	Documentation/ref/index.rst \
	Documentation/faq/index.rst \
	Documentation/faq/configuration.rst \
	Documentation/faq/contributing.rst \
	Documentation/faq/design.rst \
	Documentation/faq/general.rst \
	Documentation/faq/issues.rst \
	Documentation/faq/openflow.rst \
	Documentation/faq/qos.rst \
	Documentation/faq/releases.rst \
	Documentation/faq/terminology.rst \
	Documentation/faq/vlan.rst \
	Documentation/faq/vxlan.rst \
	Documentation/internals/index.rst \
	Documentation/internals/authors.rst \
	Documentation/internals/bugs.rst \
	Documentation/internals/committer-grant-revocation.rst \
	Documentation/internals/committer-responsibilities.rst \
	Documentation/internals/mailing-lists.rst \
	Documentation/internals/maintainers.rst \
	Documentation/internals/release-process.rst \
	Documentation/internals/security.rst \
	Documentation/internals/contributing/index.rst \
	Documentation/internals/contributing/coding-style.rst \
	Documentation/internals/contributing/coding-style-windows.rst \
	Documentation/internals/contributing/documentation-style.rst \
	Documentation/internals/contributing/submitting-patches.rst

# You can set these variables from the command line.
SPHINXOPTS =
SPHINXBUILD = sphinx-build
SPHINXSRCDIR = $(srcdir)/Documentation
SPHINXBUILDDIR = $(builddir)/Documentation/_build

# Internal variables.
PAPEROPT_a4 = -D latex_paper_size=a4
PAPEROPT_letter = -D latex_paper_size=letter
ALLSPHINXOPTS = -W -d $(SPHINXBUILDDIR)/doctrees $(PAPEROPT_$(PAPER)) $(SPHINXOPTS) $(SPHINXSRCDIR)

.PHONY: htmldocs
htmldocs:
	rm -rf $(SPHINXBUILDDIR)/*
	$(SPHINXBUILD) -b html $(ALLSPHINXOPTS) $(SPHINXBUILDDIR)/html
