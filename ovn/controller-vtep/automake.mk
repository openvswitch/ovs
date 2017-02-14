bin_PROGRAMS += ovn/controller-vtep/ovn-controller-vtep
ovn_controller_vtep_ovn_controller_vtep_SOURCES = \
	ovn/controller-vtep/binding.c \
	ovn/controller-vtep/binding.h \
	ovn/controller-vtep/gateway.c \
	ovn/controller-vtep/gateway.h \
	ovn/controller-vtep/ovn-controller-vtep.c \
	ovn/controller-vtep/ovn-controller-vtep.h \
	ovn/controller-vtep/vtep.c \
	ovn/controller-vtep/vtep.h
ovn_controller_vtep_ovn_controller_vtep_LDADD = ovn/lib/libovn.la lib/libopenvswitch.la vtep/libvtep.la
man_MANS += ovn/controller-vtep/ovn-controller-vtep.8
EXTRA_DIST += ovn/controller-vtep/ovn-controller-vtep.8.xml
CLEANFILES += ovn/controller-vtep/ovn-controller-vtep.8
