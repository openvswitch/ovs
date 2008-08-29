AUTOMAKE_OPTIONS=foreign
ACLOCAL_AMFLAGS = -I m4
SUBDIRS = \
	lib \
	datapath \
	secchan \
	controller \
	utilities \
	switch \
	tests \
	include \
	third-party
if HAVE_EXT
SUBDIRS += ext
endif

DIST_SUBDIRS = $(SUBDIRS)

EXTRA_DIST = README.hwtables
