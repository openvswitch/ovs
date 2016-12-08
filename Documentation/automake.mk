docs += \
	Documentation/group-selection-method-property.txt \
	Documentation/OVSDB-replication.rst

EXTRA_DIST += \
	Documentation/_static/logo.png \
	Documentation/conf.py \
	Documentation/index.rst \
	Documentation/contents.rst \
	Documentation/intro/index.rst \
	Documentation/intro/install/index.rst \
	Documentation/tutorials/index.rst \
	Documentation/topics/index.rst \
	Documentation/howto/index.rst \
	Documentation/ref/index.rst \
	Documentation/faq/index.rst \
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
SPHINXBUILDDIR = $(srcdir)/Documentation/_build

# Internal variables.
PAPEROPT_a4 = -D latex_paper_size=a4
PAPEROPT_letter = -D latex_paper_size=letter
# TODO(stephenfin): Add '-W' flag here once we've integrated required docs
ALLSPHINXOPTS = -d $(SPHINXBUILDDIR)/doctrees $(PAPEROPT_$(PAPER)) $(SPHINXOPTS) $(SPHINXSRCDIR)

.PHONY: htmldocs
htmldocs:
	rm -rf $(SPHINXBUILDDIR)/*
	$(SPHINXBUILD) -b html $(ALLSPHINXOPTS) $(SPHINXBUILDDIR)/html
