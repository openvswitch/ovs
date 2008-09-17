# The goal of -Wno-syntax here is just to suppress the Automake warning
# about overriding distdir, below.
AUTOMAKE_OPTIONS=foreign -Wno-syntax
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
	third-party \
	debian
if HAVE_EXT
SUBDIRS += ext
distdir = $(PACKAGE)+ext-$(VERSION)
endif

DIST_SUBDIRS = $(SUBDIRS)

EXTRA_DIST = README.hwtables

if HAVE_DPKG_BUILDPACKAGE
distcheck-hook: 
	cd $(srcdir) && dpkg-buildpackage -rfakeroot -us -uc
	cd $(srcdir) && fakeroot ./debian/rules clean
else
distcheck-hook: 
endif
