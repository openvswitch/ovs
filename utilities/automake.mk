bin_PROGRAMS += \
	utilities/ovs-appctl \
	utilities/ovs-testcontroller \
	utilities/ovs-dpctl \
	utilities/ovs-ofctl \
	utilities/ovs-vsctl \
	utilities/gnmi-cli \
	utilities/ovs_pipeline_builder
bin_SCRIPTS += utilities/ovs-docker \
	utilities/ovs-pki \
	utilities/ovs-pcap \
	utilities/ovs-tcpdump \
	utilities/ovs-tcpundump \
	utilities/ovs-dpctl-top \
	utilities/ovs-l3ping \
	utilities/ovs-parse-backtrace \
	utilities/ovs-test \
	utilities/ovs-p4ctl \
	utilities/ovs-vlan-test
scripts_SCRIPTS += \
	utilities/ovs-check-dead-ifs \
	utilities/ovs-ctl \
	utilities/ovs-kmod-ctl \
	utilities/ovs-save
scripts_DATA += utilities/ovs-lib

completion_SCRIPTS += \
	utilities/ovs-appctl-bashcomp.bash \
	utilities/ovs-vsctl-bashcomp.bash

check_SCRIPTS += \
	utilities/ovs-appctl-bashcomp.bash \
	utilities/ovs-vsctl-bashcomp.bash

EXTRA_DIST += utilities/ovs-sim.in
noinst_SCRIPTS += utilities/ovs-sim

utilities/ovs-lib: $(top_builddir)/config.status

EXTRA_DIST += \
	utilities/gdb/ovs_gdb.py \
	utilities/ovs-appctl-bashcomp.bash \
	utilities/ovs-check-dead-ifs.in \
	utilities/ovs-ctl.in \
	utilities/ovs-dev.py \
	utilities/ovs-docker \
	utilities/ovs-dpctl-top.in \
	utilities/ovs-kmod-ctl.in \
	utilities/ovs-l3ping.in \
	utilities/ovs-lib.in \
	utilities/ovs-parse-backtrace.in \
	utilities/ovs-pcap.in \
	utilities/ovs-pipegen.py \
	utilities/ovs-pki.in \
	utilities/ovs-save \
	utilities/ovs-tcpdump.in \
	utilities/ovs-tcpundump.in \
	utilities/ovs-test.in \
	utilities/ovs-vlan-test.in \
	utilities/ovs-vsctl-bashcomp.bash \
	utilities/checkpatch.py \
	utilities/ovs-p4ctl.in \
	utilities/docker/Makefile \
	utilities/docker/ovs-override.conf \
	utilities/docker/start-ovs \
	utilities/docker/create_ovs_db.sh \
	utilities/docker/debian/Dockerfile \
	utilities/docker/debian/build-kernel-modules.sh
MAN_ROOTS += \
	utilities/ovs-testcontroller.8.in \
	utilities/ovs-dpctl.8.in \
	utilities/ovs-dpctl-top.8.in \
	utilities/ovs-kmod-ctl.8 \
	utilities/ovs-ofctl.8.in \
	utilities/ovs-pcap.1.in \
	utilities/ovs-vsctl.8.in
CLEANFILES += \
	utilities/ovs-ctl \
	utilities/ovs-check-dead-ifs \
	utilities/ovs-testcontroller.8 \
	utilities/ovs-dpctl.8 \
	utilities/ovs-dpctl-top \
	utilities/ovs-dpctl-top.8 \
	utilities/ovs-kmod-ctl \
	utilities/ovs-l3ping \
	utilities/ovs-lib \
	utilities/ovs-ofctl.8 \
	utilities/ovs-parse-backtrace \
	utilities/ovs-pcap \
	utilities/ovs-pcap.1 \
	utilities/ovs-pki \
	utilities/ovs-sim \
	utilities/ovs-tcpdump \
	utilities/ovs-tcpundump \
	utilities/ovs-test \
	utilities/ovs-vlan-test \
	utilities/ovs-vsctl.8 \
	utilities/ovs-p4ctl

man_MANS += \
	utilities/ovs-testcontroller.8 \
	utilities/ovs-dpctl.8 \
	utilities/ovs-dpctl-top.8 \
	utilities/ovs-kmod-ctl.8 \
	utilities/ovs-ofctl.8 \
	utilities/ovs-pcap.1 \
	utilities/ovs-vsctl.8


utilities_ovs_appctl_SOURCES = utilities/ovs-appctl.c
utilities_ovs_appctl_LDADD = lib/libopenvswitch.la

utilities_ovs_testcontroller_SOURCES = utilities/ovs-testcontroller.c
utilities_ovs_testcontroller_LDADD = lib/libopenvswitch.la $(SSL_LIBS)

utilities_ovs_dpctl_SOURCES = utilities/ovs-dpctl.c
utilities_ovs_dpctl_LDADD = lib/libopenvswitch.la

utilities_ovs_ofctl_SOURCES = utilities/ovs-ofctl.c
utilities_ovs_ofctl_LDADD = \
	ofproto/libofproto.la \
	lib/libopenvswitch.la

utilities_ovs_vsctl_SOURCES = utilities/ovs-vsctl.c
utilities_ovs_vsctl_LDADD = lib/libopenvswitch.la

utilities_gnmi_cli_SOURCES = utilities/gnmi_cli.cc
utilities_gnmi_cli_LDADD = lib/libopenvswitch.la
utilities_gnmi_cli_LDADD += -lgrpc -lprotobuf -lgflags -lgrpc++
utilities_gnmi_cli_LDADD += p4proto/p4rt/libp4rt.la
utilities_gnmi_cli_CPPFLAGS = $(AM_CPPFLAGS)
utilities_gnmi_cli_CPPFLAGS += -I ./p4proto/p4rt/proto/p4
utilities_gnmi_cli_CPPFLAGS += -I /usr/local/include

utilities_ovs_pipeline_builder_SOURCES = stratum/stratum/hal/bin/barefoot/bf_pipeline_builder.cc
utilities_ovs_pipeline_builder_LDADD = p4proto/bfIntf/libbfIntf.la
utilities_ovs_pipeline_builder_LDADD += p4proto/p4rt/libp4rt.la
utilities_ovs_pipeline_builder_LDADD += -lprotobuf -lgflags
utilities_ovs_pipeline_builder_CPPFLAGS = $(AM_CPPFLAGS)
utilities_ovs_pipeline_builder_CPPFLAGS += -I .
utilities_ovs_pipeline_builder_CPPFLAGS += -I ./stratum
utilities_ovs_pipeline_builder_CPPFLAGS += -I ./p4proto/p4rt/proto

if LINUX
noinst_PROGRAMS += utilities/nlmon
utilities_nlmon_SOURCES = utilities/nlmon.c
utilities_nlmon_LDADD = lib/libopenvswitch.la
endif

FLAKE8_PYFILES += utilities/ovs-pcap.in \
	utilities/checkpatch.py utilities/ovs-dev.py \
	utilities/ovs-check-dead-ifs.in \
	utilities/ovs-tcpdump.in \
	utilities/ovs-pipegen.py

include utilities/bugtool/automake.mk
