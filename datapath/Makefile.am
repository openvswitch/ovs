SUBDIRS = 
if L26_ENABLED
SUBDIRS += linux-2.6
endif

EXTRA_DIST = $(dist_headers) $(dist_sources)

# Suppress warnings about GNU extensions in Modules.mk files.
AUTOMAKE_OPTIONS = -Wno-portability

include Modules.mk
include linux-2.6/Modules.mk
