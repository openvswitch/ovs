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
	Documentation/contents.rst

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
