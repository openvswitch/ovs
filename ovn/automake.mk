# OVN southbound schema and IDL
EXTRA_DIST += ovn/ovn-sb.ovsschema
pkgdata_DATA += ovn/ovn-sb.ovsschema

# OVN southbound E-R diagram
#
# If "python" or "dot" is not available, then we do not add graphical diagram
# to the documentation.
if HAVE_PYTHON
if HAVE_DOT
ovn/ovn-sb.gv: ovsdb/ovsdb-dot.in ovn/ovn-sb.ovsschema
	$(AM_V_GEN)$(OVSDB_DOT) --no-arrows $(srcdir)/ovn/ovn-sb.ovsschema > $@
ovn/ovn-sb.pic: ovn/ovn-sb.gv ovsdb/dot2pic
	$(AM_V_GEN)(dot -T plain < ovn/ovn-sb.gv | $(PERL) $(srcdir)/ovsdb/dot2pic -f 3) > $@.tmp && \
	mv $@.tmp $@
OVN_SB_PIC = ovn/ovn-sb.pic
OVN_SB_DOT_DIAGRAM_ARG = --er-diagram=$(OVN_SB_PIC)
CLEANFILES += ovn/ovn-sb.gv ovn/ovn-sb.pic
endif
endif

# OVN southbound schema documentation
EXTRA_DIST += ovn/ovn-sb.xml
CLEANFILES += ovn/ovn-sb.5
man_MANS += ovn/ovn-sb.5
ovn/ovn-sb.5: \
	ovsdb/ovsdb-doc ovn/ovn-sb.xml ovn/ovn-sb.ovsschema $(OVN_SB_PIC)
	$(AM_V_GEN)$(OVSDB_DOC) \
		$(OVN_SB_DOT_DIAGRAM_ARG) \
		--version=$(VERSION) \
		$(srcdir)/ovn/ovn-sb.ovsschema \
		$(srcdir)/ovn/ovn-sb.xml > $@.tmp && \
	mv $@.tmp $@

# OVN northbound schema and IDL
EXTRA_DIST += ovn/ovn-nb.ovsschema
pkgdata_DATA += ovn/ovn-nb.ovsschema

# OVN northbound E-R diagram
#
# If "python" or "dot" is not available, then we do not add graphical diagram
# to the documentation.
if HAVE_PYTHON
if HAVE_DOT
ovn/ovn-nb.gv: ovsdb/ovsdb-dot.in ovn/ovn-nb.ovsschema
	$(AM_V_GEN)$(OVSDB_DOT) --no-arrows $(srcdir)/ovn/ovn-nb.ovsschema > $@
ovn/ovn-nb.pic: ovn/ovn-nb.gv ovsdb/dot2pic
	$(AM_V_GEN)(dot -T plain < ovn/ovn-nb.gv | $(PERL) $(srcdir)/ovsdb/dot2pic -f 3) > $@.tmp && \
	mv $@.tmp $@
OVN_NB_PIC = ovn/ovn-nb.pic
OVN_NB_DOT_DIAGRAM_ARG = --er-diagram=$(OVN_NB_PIC)
CLEANFILES += ovn/ovn-nb.gv ovn/ovn-nb.pic
endif
endif

# OVN northbound schema documentation
EXTRA_DIST += ovn/ovn-nb.xml
CLEANFILES += ovn/ovn-nb.5
man_MANS += ovn/ovn-nb.5
ovn/ovn-nb.5: \
	ovsdb/ovsdb-doc ovn/ovn-nb.xml ovn/ovn-nb.ovsschema $(OVN_NB_PIC)
	$(AM_V_GEN)$(OVSDB_DOC) \
		$(OVN_NB_DOT_DIAGRAM_ARG) \
		--version=$(VERSION) \
		$(srcdir)/ovn/ovn-nb.ovsschema \
		$(srcdir)/ovn/ovn-nb.xml > $@.tmp && \
	mv $@.tmp $@

man_MANS += ovn/ovn-architecture.7
EXTRA_DIST += ovn/ovn-architecture.7.xml
CLEANFILES += ovn/ovn-architecture.7

EXTRA_DIST += \
	ovn/TODO.rst

# Version checking for ovn-nb.ovsschema.
ALL_LOCAL += ovn/ovn-nb.ovsschema.stamp
ovn/ovn-nb.ovsschema.stamp: ovn/ovn-nb.ovsschema
	$(srcdir)/build-aux/cksum-schema-check $? $@
CLEANFILES += ovn/ovn-nb.ovsschema.stamp

# Version checking for ovn-sb.ovsschema.
ALL_LOCAL += ovn/ovn-sb.ovsschema.stamp
ovn/ovn-sb.ovsschema.stamp: ovn/ovn-sb.ovsschema
	$(srcdir)/build-aux/cksum-schema-check $? $@
CLEANFILES += ovn/ovn-sb.ovsschema.stamp

include ovn/controller/automake.mk
include ovn/controller-vtep/automake.mk
include ovn/lib/automake.mk
include ovn/northd/automake.mk
include ovn/utilities/automake.mk
