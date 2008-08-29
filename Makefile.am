AUTOMAKE_OPTIONS=foreign
ACLOCAL_AMFLAGS = -I m4
SUBDIRS = lib datapath secchan controller
if HAVE_IF_PACKET
SUBDIRS += switch
endif
SUBDIRS += utilities tests include third-party
if HAVE_EXT
SUBDIRS += ext
endif

EXTRA_DIST = README.hwtables
