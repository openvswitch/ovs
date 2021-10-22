lib_LTLIBRARIES += p4proto/bfIntf/libbfIntf.la

p4proto_bfIntf_libbfIntf_la_LDFLAGS = \
        $(OVS_LTINFO) \
        -Wl,--version-script=$(top_builddir)/p4proto/bfIntf/libbfIntf.sym \
        $(AM_LDFLAGS)

LIB_ABSL := -labsl_strings -labsl_synchronization -labsl_graphcycles_internal \
            -labsl_stacktrace -labsl_symbolize -labsl_malloc_internal \
            -labsl_debugging_internal -labsl_demangle_internal -labsl_time \
            -labsl_strings_internal -labsl_throw_delegate \
            -labsl_base -labsl_spinlock_wait -labsl_int128 -labsl_raw_logging_internal \
            -labsl_log_severity -labsl_civil_time -labsl_civil_time -labsl_time_zone \
            -labsl_status -labsl_cord -labsl_cord_internal -labsl_cordz_info \
            -labsl_cordz_handle -labsl_cordz_sample_token -labsl_cordz_functions \
            -labsl_exponential_biased -labsl_str_format_internal -labsl_hash \
            -labsl_raw_hash_set -labsl_city -labsl_bad_optional_access \
            -labsl_bad_variant_access -labsl_low_level_hash

if P4TOFINO
p4proto_bfIntf_libbfIntf_la_LIBADD = $(LIB_ABSL)
p4proto_bfIntf_libbfIntf_la_LIBADD += -lgrpc -lprotobuf -lglog -lgflags -lgrpc++
p4proto_bfIntf_libbfIntf_la_LIBADD += -lbfutils -lbfsys -ldriver
else
p4proto_bfIntf_libbfIntf_la_LIBADD = $(LIB_ABSL)
p4proto_bfIntf_libbfIntf_la_LIBADD += -lgrpc -lprotobuf -lglog -lgflags -lgrpc++
p4proto_bfIntf_libbfIntf_la_LIBADD += -ltarget_utils -lbf_switchd_lib -ltargetsys -ldriver
endif

SUFFIXES += .proto
EXTRA_DIST += external/gnmi/gnmi.proto
EXTRA_DIST += external/gnmi_ext/gnmi_ext.proto
EXTRA_DIST += stratum
EXTRA_DIST += external/PATCH-01-STRATUM

bfIntf_PROTOBUF_GENFILES = \
    stratum/stratum/hal/lib/barefoot/bf.pb.h \
    stratum/stratum/hal/lib/barefoot/bf.pb.cc \
    stratum/stratum/public/proto/p4_table_defs.pb.h \
    stratum/stratum/public/proto/p4_table_defs.pb.cc \
    stratum/stratum/public/proto/p4_annotation.pb.h \
    stratum/stratum/public/proto/p4_annotation.pb.cc \
    stratum/stratum/hal/lib/p4/p4_control.pb.h \
    stratum/stratum/hal/lib/p4/p4_control.pb.cc \
    stratum/stratum/hal/lib/p4/common_flow_entry.pb.h \
    stratum/stratum/hal/lib/p4/common_flow_entry.pb.cc \
    stratum/stratum/hal/lib/p4/p4_table_map.pb.h \
    stratum/stratum/hal/lib/p4/p4_table_map.pb.cc \
    stratum/stratum/hal/lib/p4/p4_pipeline_config.pb.h \
    stratum/stratum/hal/lib/p4/p4_pipeline_config.pb.cc \
    stratum/stratum/hal/lib/common/common.pb.cc \
    stratum/stratum/hal/lib/common/common.pb.h \
    p4proto/p4rt/proto/google/rpc/code.pb.cc \
    p4proto/p4rt/proto/google/rpc/code.pb.h

p4proto_bfIntf_libbfIntf_la_SOURCES = $(bfIntf_PROTOBUF_GENFILES)
p4proto_bfIntf_libbfIntf_la_SOURCES += \
    p4proto/bfIntf/bf_interface.cc \
    p4proto/bfIntf/bf_interface.h \
    p4proto/bfIntf/bf_chassis_manager.cc \
    p4proto/bfIntf/bf_chassis_manager.h \
    stratum/stratum/hal/lib/barefoot/bf_sde_wrapper.cc \
    stratum/stratum/hal/lib/barefoot/bf_sde_wrapper.h \
    stratum/stratum/hal/lib/barefoot/bf_sde_interface.h \
    stratum/stratum/hal/lib/barefoot/bfrt_action_profile_manager.cc \
    stratum/stratum/hal/lib/barefoot/bfrt_counter_manager.cc \
    stratum/stratum/hal/lib/barefoot/bfrt_packetio_manager.cc \
    stratum/stratum/hal/lib/barefoot/bfrt_pre_manager.cc \
    stratum/stratum/hal/lib/barefoot/bfrt_table_manager.cc \
    stratum/stratum/hal/lib/barefoot/bfrt_id_mapper.cc \
    stratum/stratum/hal/lib/barefoot/bfrt_node.cc \
    stratum/stratum/hal/lib/p4/utils.cc \
    stratum/stratum/hal/lib/barefoot/utils.cc \
    stratum/stratum/glue/status/status.cc \
    stratum/stratum/glue/status/statusor.cc \
    stratum/stratum/hal/lib/barefoot/bf_pipeline_utils.cc \
    stratum/stratum/hal/lib/p4/p4_info_manager.cc \
    stratum/stratum/lib/timer_daemon.cc \
    stratum/stratum/hal/lib/common/utils.cc \
    stratum/stratum/hal/lib/barefoot/bfrt_switch.cc

BUILT_SOURCES += $(bfIntf_PROTOBUF_GENFILES)

stratum/stratum/hal/lib/barefoot/bf.pb.cc stratum/stratum/hal/lib/barefoot/bf.pb.h: $(top_srcdir)/stratum/stratum/hal/lib/barefoot/bf.proto
	$(AM_V_GEN)@PROTOC@ -I$(top_srcdir)/stratum -I$(top_srcdir)/p4runtime/proto --cpp_out=$(top_srcdir)/stratum $(top_srcdir)/stratum/stratum/hal/lib/barefoot/bf.proto

stratum/stratum/public/proto/p4_table_defs.pb.cc stratum/stratum/public/proto/p4_table_defs.pb.h: $(top_srcdir)/stratum/stratum/public/proto/p4_table_defs.proto
	$(AM_V_GEN)@PROTOC@ -I$(top_srcdir)/stratum --cpp_out=$(top_srcdir)/stratum $(top_srcdir)/stratum/stratum/public/proto/p4_table_defs.proto

stratum/stratum/public/proto/p4_annotation.pb.cc stratum/stratum/public/proto/p4_annotation.pb.h: $(top_srcdir)/stratum/stratum/public/proto/p4_annotation.proto
	$(AM_V_GEN)@PROTOC@ -I$(top_srcdir)/stratum --cpp_out=$(top_srcdir)/stratum $(top_srcdir)/stratum/stratum/public/proto/p4_annotation.proto

stratum/stratum/hal/lib/p4/p4_control.pb.cc stratum/stratum/hal/lib/p4/p4_control.pb.h: $(top_srcdir)/stratum/stratum/hal/lib/p4/p4_control.proto
	$(AM_V_GEN)@PROTOC@ -I$(top_srcdir)/stratum --cpp_out=$(top_srcdir)/stratum $(top_srcdir)/stratum/stratum/hal/lib/p4/p4_control.proto

stratum/stratum/hal/lib/p4/common_flow_entry.pb.cc stratum/stratum/hal/lib/p4/common_flow_entry.pb.h: $(top_srcdir)/stratum/stratum/hal/lib/p4/common_flow_entry.proto
	$(AM_V_GEN)@PROTOC@ -I$(top_srcdir)/stratum -I$(top_srcdir)/p4runtime/proto  -I/usr/local/include -I$(top_srcdir)/external/googleapis --cpp_out=$(top_srcdir)/stratum $(top_srcdir)/stratum/stratum/hal/lib/p4/common_flow_entry.proto

stratum/stratum/hal/lib/p4/p4_table_map.pb.cc stratum/stratum/hal/lib/p4/p4_table_map.pb.h: $(top_srcdir)/stratum/stratum/hal/lib/p4/p4_table_map.proto
	$(AM_V_GEN)@PROTOC@ -I$(top_srcdir)/stratum -I$(top_srcdir)/external/googleapis -I$(top_srcdir)/p4runtime/proto --cpp_out=$(top_srcdir)/stratum $(top_srcdir)/stratum/stratum/hal/lib/p4/p4_table_map.proto

stratum/stratum/hal/lib/p4/p4_pipeline_config.pb.cc stratum/stratum/hal/lib/p4/p4_pipeline_config.pb.h: $(top_srcdir)/stratum/stratum/hal/lib/p4/p4_pipeline_config.proto
	$(AM_V_GEN)@PROTOC@ -I$(top_srcdir)/stratum -I$(top_srcdir)/p4runtime/proto -I$(top_srcdir)/external/googleapis --cpp_out=$(top_srcdir)/stratum $(top_srcdir)/stratum/stratum/hal/lib/p4/p4_pipeline_config.proto

stratum/stratum/hal/lib/common/common.pb.cc stratum/stratum/hal/lib/common/common.pb.h: $(top_srcdir)/stratum/stratum/hal/lib/common/common.proto
	$(AM_V_GEN)@PROTOC@ -I$(top_srcdir)/stratum --cpp_out=$(top_srcdir)/stratum $(top_srcdir)/stratum/stratum/hal/lib/common/common.proto

p4proto/p4rt/proto/google/rpc/code.pb.cc p4proto/p4rt/proto/google/rpc/code.pb.h: $(top_srcdir)/external/googleapis/google/rpc/code.proto
	$(AM_V_GEN)@PROTOC@ -I$(top_srcdir)/external/googleapis --cpp_out=$(top_srcdir)/p4proto/p4rt/proto/ $(top_srcdir)/external/googleapis/google/rpc/code.proto

if P4TOFINO
p4proto_bfIntf_libbfIntf_la_CPPFLAGS = $(AM_CPPFLAGS)
p4proto_bfIntf_libbfIntf_la_CPPFLAGS += -DSDE_9_5_0 -DP4TOFINO
else
p4proto_bfIntf_libbfIntf_la_CPPFLAGS = $(AM_CPPFLAGS)
p4proto_bfIntf_libbfIntf_la_CPPFLAGS += -DSDE_9_5_0
endif
p4proto_bfIntf_libbfIntf_la_CPPFLAGS += -I .
p4proto_bfIntf_libbfIntf_la_CPPFLAGS += -I ./stratum
p4proto_bfIntf_libbfIntf_la_CPPFLAGS += -I ./stratum/stratum/public/proto
p4proto_bfIntf_libbfIntf_la_CPPFLAGS += -I ./external
p4proto_bfIntf_libbfIntf_la_CPPFLAGS += -I ./p4proto
p4proto_bfIntf_libbfIntf_la_CPPFLAGS += -I ./p4proto/p4rt/proto
p4proto_bfIntf_libbfIntf_la_CPPFLAGS += -I ./p4proto/bfIntf
p4proto_bfIntf_libbfIntf_la_CPPFLAGS += -I ./p4proto/p4rt/proto/p4

p4proto_bfIntf_libbfIntf_la_CFLAGS = $(AM_CFLAGS)

pkgconfig_DATA += \
        p4proto/bfIntf/libbfIntf.pc

CLEANFILES += p4proto/bfIntf/libbfIntf.sym
CLEANFILES += p4proto/bfIntf/libbfIntf.pc
CLEANFILES += $(bfIntf_PROTOBUF_GENFILES)
