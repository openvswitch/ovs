docs += \
	Documentation/committer-responsibilities.rst \
	Documentation/committer-grant-revocation.rst \
	Documentation/group-selection-method-property.txt \
	Documentation/OVSDB-replication.rst \
	Documentation/release-process.rst

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
	Documentation/internals/index.rst

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
