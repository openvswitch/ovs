SUBDIRS = 
if L26_ENABLED
SUBDIRS += linux-2.6
endif

EXTRA_DIST = $(dist_headers) $(dist_sources)

# Suppress warnings about GNU extensions in Modules.mk files.
AUTOMAKE_OPTIONS = -Wno-portability

include Modules.mk
include linux-2.6/Modules.mk

# The following is based on commands for the Automake "distdir" target.
distfiles: Makefile
	@srcdirstrip=`echo "$(srcdir)" | sed 's/[].[^$$\\*]/\\\\&/g'`; \
	topsrcdirstrip=`echo "$(top_srcdir)" | sed 's/[].[^$$\\*]/\\\\&/g'`; \
	list='$(DISTFILES)'; \
	for file in $$list; do echo $$file; done | \
	  sed -e "s|^$$srcdirstrip/||;t" \
	      -e "s|^$$topsrcdirstrip/|$(top_builddir)/|;t" | sort -u > $@
CLEANFILES = distfiles
