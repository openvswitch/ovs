bin_PROGRAMS += ovn/controller/ovn-controller
ovn_controller_ovn_controller_SOURCES = \
	ovn/controller/bindings.c \
	ovn/controller/bindings.h \
	ovn/controller/chassis.c \
	ovn/controller/chassis.h \
	ovn/controller/ofctrl.c \
	ovn/controller/ofctrl.h \
	ovn/controller/ovn-controller.c \
	ovn/controller/ovn-controller.h \
	ovn/controller/pipeline.c \
	ovn/controller/pipeline.h
ovn_controller_ovn_controller_LDADD = ovn/lib/libovn.la lib/libopenvswitch.la
man_MANS += ovn/controller/ovn-controller.8
EXTRA_DIST += ovn/controller/ovn-controller.8.xml
