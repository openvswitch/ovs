SUBDIRS =
if LINUX_ENABLED
SUBDIRS += linux
endif

EXTRA_DIST = $(dist_headers) $(dist_sources) $(dist_extras)

# Suppress warnings about GNU extensions in Modules.mk files.
AUTOMAKE_OPTIONS = -Wno-portability

include Modules.mk
include linux/Modules.mk

# The following is based on commands for the Automake "distdir" target.
distfiles: Makefile
	@srcdirstrip=`echo "$(srcdir)" | sed 's/[].[^$$\\*]/\\\\&/g'`; \
	topsrcdirstrip=`echo "$(top_srcdir)" | sed 's/[].[^$$\\*]/\\\\&/g'`; \
	list='$(DISTFILES)'; \
	for file in $$list; do echo $$file; done | \
	  sed -e "s|^$$srcdirstrip/||;t" \
	      -e "s|^$$topsrcdirstrip/|$(top_builddir)/|;t" | sort -u > $@
CLEANFILES = distfiles

# Print name of all modules.
print-build-modules:
	@if test -z "$(build_modules)"; \
	then \
	   echo "Could not find any kernel module."; \
	   exit 1; \
	fi
	@echo "$(build_modules)" | tr '_' '-';

if !WIN32
COMPAT_GET_FUNCTIONS := find $(top_srcdir)/datapath/linux/compat -name "*.h" \
	-exec sed -n '/^[a-z][a-z]* \*\?[A-Za-z0-9_][A-Za-z0-9_]*([a-z]/p; /^struct [a-z0-9_][a-z0-9_]* \*\?[A-Za-z0-9_][A-Za-z0-9_]*([a-z]/p' {} \; | tr -d '*' | cut -d '(' -f1 | rev | cut -d ' ' -f1 | rev
COMPAT_GET_EXPORTS := find $(top_srcdir)/datapath/linux/compat -name "*.c" \
	-exec sed -n 's/^EXPORT_SYMBOL[A-Z_]*(\([a-z_][a-z_]*\));$$/\1/p' {} \;
COMPAT_FUNCTIONS := $(shell $(COMPAT_GET_FUNCTIONS))
COMPAT_EXPORTS := $(shell $(COMPAT_GET_EXPORTS))

# Checks that all public functions are 'rpl_' or 'ovs_' prefixed.
# Checks that all EXPORT_SYMBOL_GPL() export 'rpl_' or 'ovs_' prefixed functions.
check-export-symbol:
	@for fun_ in $(COMPAT_FUNCTIONS); do \
	   if ! grep -- $${fun_} $(top_srcdir)/datapath/linux/compat/build-aux/export-check-whitelist > /dev/null; then \
	      if ! echo $${fun_} | grep -q -E '^(rpl|ovs)_'; then \
	         echo "error: $${fun_}() needs to be prefixed with 'rpl_' or 'ovs_'."; \
	         exit 1; \
	      fi; \
	   fi; \
	done
	@for fun_ in $(COMPAT_EXPORTS); do \
	   if ! echo $${fun_} | grep -q -E '^(rpl|ovs)_'; then \
	      echo "error: $${fun_}() needs to be prefixed with 'rpl_' or 'ovs_'."; \
	      exit 1; \
	   fi; \
	done

all-local: check-export-symbol
endif
