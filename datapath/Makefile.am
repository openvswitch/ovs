SUBDIRS = tests
if L26_ENABLED
SUBDIRS += linux-2.6
endif
if L24_ENABLED
SUBDIRS += linux-2.4
endif

EXTRA_DIST = $(dist_headers) $(dist_sources)

include Modules.mk
include linux-2.4/Modules.mk
include linux-2.6/Modules.mk
