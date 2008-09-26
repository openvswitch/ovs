SUBDIRS = 
if L26_ENABLED
SUBDIRS += linux-2.6
endif
if L24_ENABLED
SUBDIRS += linux-2.4
endif

EXTRA_DIST = $(dist_headers) $(dist_sources)
EXTRA_DIST += hwtable_dummy/Modules.mk hwtable_dummy/hwtable_dummy.c

# Suppress warnings about GNU extensions in Modules.mk files.
AUTOMAKE_OPTIONS = -Wno-portability

include Modules.mk
include linux-2.4/Modules.mk
include linux-2.6/Modules.mk
