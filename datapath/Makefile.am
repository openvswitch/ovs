SUBDIRS = tests
if L26_ENABLED
SUBDIRS += linux-2.6
endif
if UML_ENABLED
SUBDIRS += linux-2.6-uml
endif
if L24_ENABLED
SUBDIRS += linux-2.4
endif

EXTRA_DIST = linux-2.6 linux-2.4 linux-2.6-uml\
			datapath.c snap.h chain.c  crc32.c  crc_t.c\
			flow.h forward.h table-hash.c table-mac.c\
            unit.c unit.h datapath.h  chain.h  crc32.h\
            flow.c  forward.c  forward_t.c table.h\
            table-linear.c  table_t.c    unit-exports.c\
			datapath_t.c datapath_t.h compat.h\
			dp_dev.c

# Do not include header and source files from the top of the linux-*
# directories, as these are just symbolic links to the files in
# "datapath".
dist-hook:
	rm -rf `find $(distdir)/linux-* -name Module.symvers`
	rm -rf `find $(distdir)/linux-* -name .*.cmd`
	rm -rf `find $(distdir)/linux-* -name .*.swp`
	rm -rf `find $(distdir)/linux-* -name .*.d`
	rm -rf `find $(distdir)/linux-* -name .tmp_versions`
	rm -rf `find $(distdir)/linux-* -name *.o`
	rm -rf `find $(distdir)/linux-* -name *.ko`
	rm -rf `find $(distdir)/linux-* -name Makefile`
	rm -rf `find $(distdir)/linux-* -name .gitignore`
	rm -f $(distdir)/linux-*/*.h
	rm -f $(distdir)/linux-*/*.c
