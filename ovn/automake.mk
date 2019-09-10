EXTRA_DIST += ovn/ovn-sb.ovsschema \
	      ovn/ovn-sb.xml \
	      ovn/ovn-nb.ovsschema \
	      ovn/ovn-nb.xml

include ovn/lib/automake.mk
include ovn/utilities/automake.mk
