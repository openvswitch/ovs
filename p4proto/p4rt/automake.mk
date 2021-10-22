lib_LTLIBRARIES += p4proto/p4rt/libp4rt.la

p4proto_p4rt_libp4rt_la_LDFLAGS = \
        $(OVS_LTINFO) \
        -Wl,--version-script=$(top_builddir)/p4proto/p4rt/libp4rt.sym \
        $(AM_LDFLAGS)

p4proto_p4rt_libp4rt_la_LIBADD = $(LIB_ABSL)
p4proto_p4rt_libp4rt_la_LIBADD += -lgrpc -lprotobuf -lglog -lgflags -lgrpc++
p4proto_p4rt_libp4rt_la_LIBADD += p4proto/bfIntf/libbfIntf.la

SUFFIXES += .proto
EXTRA_DIST += p4proto/p4rt/README
EXTRA_DIST += p4proto/p4rt/LICENSE
EXTRA_DIST += p4proto/p4rt
EXTRA_DIST += external/googleapis
EXTRA_DIST += external/gnmi/gnmi.proto
EXTRA_DIST += external/gnmi_ext/gnmi_ext.proto
EXTRA_DIST += external/dpdk_vhost_config.pb.txt

p4rt_PROTOBUF_GEN_FILES = \
    stratum/stratum/public/proto/error.pb.cc \
    stratum/stratum/public/proto/error.pb.h \
    stratum/stratum/hal/lib/p4/forwarding_pipeline_configs.pb.cc \
    stratum/stratum/hal/lib/p4/forwarding_pipeline_configs.pb.h \
    stratum/stratum/hal/lib/phal/db.pb.cc \
    stratum/stratum/hal/lib/phal/db.pb.h \
    p4proto/p4rt/proto/google/rpc/status.pb.cc \
    p4proto/p4rt/proto/google/rpc/status.pb.h \
    p4proto/p4rt/proto/p4/v1/p4runtime.pb.cc \
    p4proto/p4rt/proto/p4/v1/p4runtime.pb.h \
    p4proto/p4rt/proto/p4/v1/p4runtime.grpc.pb.cc \
    p4proto/p4rt/proto/p4/v1/p4runtime.grpc.pb.h \
    p4proto/p4rt/proto/p4/v1/p4data.pb.cc \
    p4proto/p4rt/proto/p4/v1/p4data.pb.h \
    p4proto/p4rt/proto/p4/config/v1/p4types.pb.cc \
    p4proto/p4rt/proto/p4/config/v1/p4types.pb.h \
    p4proto/p4rt/proto/p4/config/v1/p4info.pb.cc \
    p4proto/p4rt/proto/p4/config/v1/p4info.pb.h \
    p4proto/p4rt/proto/p4/gnmi/gnmi.grpc.pb.cc \
    p4proto/p4rt/proto/p4/gnmi/gnmi.grpc.pb.h \
    p4proto/p4rt/proto/p4/gnmi/gnmi.pb.cc \
    p4proto/p4rt/proto/p4/gnmi/gnmi.pb.h \
    p4proto/p4rt/proto/p4/gnmi_ext/gnmi_ext.grpc.pb.cc \
    p4proto/p4rt/proto/p4/gnmi_ext/gnmi_ext.grpc.pb.h \
    p4proto/p4rt/proto/p4/gnmi_ext/gnmi_ext.pb.cc \
    p4proto/p4rt/proto/p4/gnmi_ext/gnmi_ext.pb.h

p4proto_p4rt_libp4rt_la_SOURCES = $(p4rt_PROTOBUF_GEN_FILES)
p4proto_p4rt_libp4rt_la_SOURCES += \
    stratum/stratum/glue/gtl/cleanup.h \
    stratum/stratum/public/lib/error.cc \
    stratum/stratum/public/lib/error.h \
    stratum/stratum/glue/integral_types.h \
    stratum/stratum/glue/logging.cc \
    stratum/stratum/glue/logging.h \
    stratum/stratum/lib/macros.h \
    stratum/stratum/glue/status/posix_error_space.cc \
    stratum/stratum/glue/status/posix_error_space.h \
    stratum/stratum/glue/status/status.cc \
    stratum/stratum/glue/status/status.h \
    stratum/stratum/glue/status/status_macros.cc \
    stratum/stratum/glue/status/status_macros.h \
    stratum/stratum/glue/status/statusor.cc \
    stratum/stratum/glue/status/statusor.h \
    stratum/stratum/lib/utils.cc \
    stratum/stratum/lib/utils.h \
    stratum/stratum/hal/lib/common/error_buffer.cc \
    stratum/stratum/hal/lib/common/error_buffer.h \
    stratum/stratum/lib/channel/channel.h \
    stratum/stratum/lib/channel/channel_internal.h \
    stratum/stratum/hal/lib/common/channel_writer_wrapper.h \
    stratum/stratum/hal/lib/common/server_writer_wrapper.h \
    stratum/stratum/hal/lib/common/writer_interface.h \
    p4proto/p4rt/yang_parse_tree.h \
    p4proto/p4rt/yang_parse_tree.cc \
    p4proto/p4rt/yang_parse_tree_paths.h \
    p4proto/p4rt/yang_parse_tree_paths.cc \
    p4proto/p4rt/config_monitoring_service.cc \
    p4proto/p4rt/config_monitoring_service.h \
    p4proto/p4rt/p4_service.cc \
    p4proto/p4rt/p4_service.h \
    p4proto/p4rt/p4_service_interface.cc \
    p4proto/p4rt/p4_service_interface.h \
    p4proto/p4rt/gnmi_publisher.cc \
    p4proto/p4rt/gnmi_publisher.h \
    stratum/stratum/lib/security/auth_policy_checker.cc

BUILT_SOURCES += $(p4rt_PROTOBUF_GEN_FILES)

stratum/stratum/public/proto/error.pb.cc stratum/stratum/public/proto/error.pb.h: $(top_srcdir)/stratum/stratum/public/proto/error.proto
	$(AM_V_GEN)@PROTOC@ -I$(top_srcdir)/stratum/stratum/public/proto --cpp_out=$(top_srcdir)/stratum/stratum/public/proto $(top_srcdir)/stratum/stratum/public/proto/error.proto

stratum/stratum/hal/lib/p4/forwarding_pipeline_configs.pb.cc stratum/stratum/hal/lib/p4/forwarding_pipeline_configs.pb.h: $(top_srcdir)/stratum/stratum/hal/lib/p4/forwarding_pipeline_configs.proto
	$(AM_V_GEN)@PROTOC@ -I$(top_srcdir)/stratum/stratum/hal/lib/p4 -I$(top_srcdir)/p4runtime/proto -I$(top_srcdir)/external/googleapis --cpp_out=$(top_srcdir)/stratum/stratum/hal/lib/p4 $(top_srcdir)/stratum/stratum/hal/lib/p4/forwarding_pipeline_configs.proto

p4proto/p4rt/proto/google/rpc/status.pb.cc p4proto/p4rt/proto/google/rpc/status.pb.h: $(top_srcdir)/external/googleapis/google/rpc/status.proto
	$(AM_V_GEN)@PROTOC@ -I$(top_srcdir)/external/googleapis --cpp_out=$(top_srcdir)/p4proto/p4rt/proto $(top_srcdir)/external/googleapis/google/rpc/status.proto

p4proto/p4rt/proto/p4/v1/p4runtime.pb.cc p4proto/p4rt/proto/p4/v1/p4runtime.pb.h: $(top_srcdir)/p4runtime/proto/p4/v1/p4runtime.proto
	$(AM_V_GEN)@PROTOC@ -I$(top_srcdir)/external/googleapis -I/usr/local/include -I$(top_srcdir)/p4runtime/proto --cpp_out=$(top_srcdir)/p4proto/p4rt/proto $(top_srcdir)/p4runtime/proto/p4/v1/p4runtime.proto

p4proto/p4rt/proto/p4/v1/p4runtime.grpc.pb.cc p4proto/p4rt/proto/p4/v1/p4runtime.grpc.pb.h: $(top_srcdir)/p4runtime/proto/p4/v1/p4runtime.proto
	$(AM_V_GEN)@PROTOC@ -I$(top_srcdir)/external/googleapis -I/usr/local/include -I$(top_srcdir)/p4runtime/proto --grpc_out=$(top_srcdir)/p4proto/p4rt/proto --plugin=protoc-gen-grpc=`which grpc_cpp_plugin` $(top_srcdir)/p4runtime/proto/p4/v1/p4runtime.proto

p4proto/p4rt/proto/p4/v1/p4data.pb.cc p4proto/p4rt/proto/p4/v1/p4data.pb.h: $(top_srcdir)/p4runtime/proto/p4/v1/p4data.proto
	$(AM_V_GEN)@PROTOC@ -I$(top_srcdir)/p4runtime/proto --cpp_out=$(top_srcdir)/p4proto/p4rt/proto $(top_srcdir)/p4runtime/proto/p4/v1/p4data.proto

p4proto/p4rt/proto/p4/config/v1/p4types.pb.cc p4proto/p4rt/proto/p4/config/v1/p4types.pb.h: $(top_srcdir)/p4runtime/proto/p4/config/v1/p4types.proto
	$(AM_V_GEN)@PROTOC@ -I$(top_srcdir)/p4runtime/proto --cpp_out=$(top_srcdir)/p4proto/p4rt/proto $(top_srcdir)/p4runtime/proto/p4/config/v1/p4types.proto

p4proto/p4rt/proto/p4/config/v1/p4info.pb.cc p4proto/p4rt/proto/p4/config/v1/p4info.pb.h: $(top_srcdir)/p4runtime/proto/p4/config/v1/p4info.proto
	$(AM_V_GEN)@PROTOC@ -I$(top_srcdir)/p4runtime/proto --cpp_out=$(top_srcdir)/p4proto/p4rt/proto $(top_srcdir)/p4runtime/proto/p4/config/v1/p4info.proto

stratum/stratum/hal/lib/phal/db.pb.cc stratum/stratum/hal/lib/phal/db.pb.h: $(top_srcdir)/stratum/stratum/hal/lib/phal/db.proto
	$(AM_V_GEN)@PROTOC@ -I$(top_srcdir)/stratum --cpp_out=$(top_srcdir)/stratum $(top_srcdir)/stratum/stratum/hal/lib/phal/db.proto

p4proto/p4rt/proto/p4/gnmi/gnmi.pb.cc p4proto/p4rt/proto/p4/gnmi/gnmi.pb.h: $(top_srcdir)/external/gnmi/gnmi.proto
	$(AM_V_GEN)@PROTOC@ -I$(top_srcdir)/external --cpp_out=$(top_srcdir)/p4proto/p4rt/proto/p4/ $(top_srcdir)/external/gnmi/gnmi.proto

p4proto/p4rt/proto/p4/gnmi/gnmi.grpc.pb.cc p4proto/p4rt/proto/p4/gnmi/gnmi.grpc.pb.h: $(top_srcdir)/external/gnmi/gnmi.proto
	$(AM_V_GEN)@PROTOC@ -I$(top_srcdir)/external --grpc_out=$(top_srcdir)/p4proto/p4rt/proto/p4/ --plugin=protoc-gen-grpc=`which grpc_cpp_plugin` $(top_srcdir)/external/gnmi/gnmi.proto

p4proto/p4rt/proto/p4/gnmi_ext/gnmi_ext.pb.cc p4proto/p4rt/proto/p4/gnmi_ext/gnmi_ext.pb.h: $(top_srcdir)/external/gnmi_ext/gnmi_ext.proto
	$(AM_V_GEN)@PROTOC@ -I$(top_srcdir)/external --cpp_out=$(top_srcdir)/p4proto/p4rt/proto/p4/ $(top_srcdir)/external/gnmi_ext/gnmi_ext.proto

p4proto/p4rt/proto/p4/gnmi_ext/gnmi_ext.grpc.pb.cc p4proto/p4rt/proto/p4/gnmi_ext/gnmi_ext.grpc.pb.h: $(top_srcdir)/external/gnmi_ext/gnmi_ext.proto
	$(AM_V_GEN)@PROTOC@ -I$(top_srcdir)/external --grpc_out=$(top_srcdir)/p4proto/p4rt/proto/p4/ --plugin=protoc-gen-grpc=`which grpc_cpp_plugin` $(top_srcdir)/external/gnmi_ext/gnmi_ext.proto

p4proto_p4rt_libp4rt_la_CPPFLAGS = $(AM_CPPFLAGS)
p4proto_p4rt_libp4rt_la_CPPFLAGS += -I .
p4proto_p4rt_libp4rt_la_CPPFLAGS += -I ./stratum
p4proto_p4rt_libp4rt_la_CPPFLAGS += -I ./stratum/stratum/public/proto
p4proto_p4rt_libp4rt_la_CPPFLAGS += -I ./external
p4proto_p4rt_libp4rt_la_CPPFLAGS += -I ./p4proto
p4proto_p4rt_libp4rt_la_CPPFLAGS += -I ./p4proto/p4rt
p4proto_p4rt_libp4rt_la_CPPFLAGS += -I ./p4proto/p4rt/proto
p4proto_p4rt_libp4rt_la_CPPFLAGS += -I ./p4proto/bfIntf
p4proto_p4rt_libp4rt_la_CPPFLAGS += -I /usr/local/lib
p4proto_p4rt_libp4rt_la_CPPFLAGS += -I ./p4proto/p4rt/proto/p4

p4proto_p4rt_libp4rt_la_CFLAGS = $(AM_CFLAGS)

pkgconfig_DATA += \
        p4proto/p4rt/libp4rt.pc

CLEANFILES += p4proto/p4rt/libp4rt.sym
CLEANFILES += p4proto/p4rt/libp4rt.pc
CLEANFILES += $(p4rt_PROTOBUF_GEN_FILES)
