lib_LTLIBRARIES += ovn/lib/libovn.la
ovn_lib_libovn_la_LDFLAGS = \
        $(OVS_LTINFO) \
        -Wl,--version-script=$(top_builddir)/ovn/lib/libovn.sym \
        $(AM_LDFLAGS)
ovn_lib_libovn_la_SOURCES = \
	ovn/lib/acl-log.c \
	ovn/lib/acl-log.h \
	ovn/lib/actions.c \
	ovn/lib/chassis-index.c \
	ovn/lib/chassis-index.h \
	ovn/lib/expr.c \
	ovn/lib/extend-table.h \
	ovn/lib/extend-table.c \
	ovn/lib/lex.c \
	ovn/lib/ovn-l7.h \
	ovn/lib/ovn-util.c \
	ovn/lib/ovn-util.h \
	ovn/lib/logical-fields.c \
	ovn/lib/logical-fields.h
nodist_ovn_lib_libovn_la_SOURCES = \
	ovn/lib/ovn-nb-idl.c \
	ovn/lib/ovn-nb-idl.h \
	ovn/lib/ovn-sb-idl.c \
	ovn/lib/ovn-sb-idl.h

# ovn-sb IDL
OVSIDL_BUILT += \
	ovn/lib/ovn-sb-idl.c \
	ovn/lib/ovn-sb-idl.h \
	ovn/lib/ovn-sb-idl.ovsidl
EXTRA_DIST += ovn/lib/ovn-sb-idl.ann
OVN_SB_IDL_FILES = \
	$(srcdir)/ovn/ovn-sb.ovsschema \
	$(srcdir)/ovn/lib/ovn-sb-idl.ann
ovn/lib/ovn-sb-idl.ovsidl: $(OVN_SB_IDL_FILES)
	$(AM_V_GEN)$(OVSDB_IDLC) annotate $(OVN_SB_IDL_FILES) > $@.tmp && \
	mv $@.tmp $@

# ovn-nb IDL
OVSIDL_BUILT += \
	ovn/lib/ovn-nb-idl.c \
	ovn/lib/ovn-nb-idl.h \
	ovn/lib/ovn-nb-idl.ovsidl
EXTRA_DIST += ovn/lib/ovn-nb-idl.ann
OVN_NB_IDL_FILES = \
	$(srcdir)/ovn/ovn-nb.ovsschema \
	$(srcdir)/ovn/lib/ovn-nb-idl.ann
ovn/lib/ovn-nb-idl.ovsidl: $(OVN_NB_IDL_FILES)
	$(AM_V_GEN)$(OVSDB_IDLC) annotate $(OVN_NB_IDL_FILES) > $@.tmp && \
	mv $@.tmp $@

