OSS_FUZZ_TARGETS = \
	tests/oss-fuzz/flow_extract_target \
	tests/oss-fuzz/json_parser_target \
	tests/oss-fuzz/ofp_print_target \
	tests/oss-fuzz/odp_target \
	tests/oss-fuzz/miniflow_target \
	tests/oss-fuzz/ofctl_parse_target
EXTRA_PROGRAMS += $(OSS_FUZZ_TARGETS)
oss-fuzz-targets: $(OSS_FUZZ_TARGETS)

tests_oss_fuzz_flow_extract_target_SOURCES = \
	tests/oss-fuzz/flow_extract_target.c \
	tests/oss-fuzz/fuzzer.h
tests_oss_fuzz_flow_extract_target_LDADD = lib/libopenvswitch.la
tests_oss_fuzz_flow_extract_target_LDFLAGS = $(LIB_FUZZING_ENGINE) -lc++

tests_oss_fuzz_json_parser_target_SOURCES = \
	tests/oss-fuzz/json_parser_target.c \
	tests/oss-fuzz/fuzzer.h
tests_oss_fuzz_json_parser_target_LDADD = lib/libopenvswitch.la
tests_oss_fuzz_json_parser_target_LDFLAGS = $(LIB_FUZZING_ENGINE) -lc++

tests_oss_fuzz_ofp_print_target_SOURCES = \
	tests/oss-fuzz/ofp_print_target.c \
	tests/oss-fuzz/fuzzer.h
tests_oss_fuzz_ofp_print_target_LDADD = lib/libopenvswitch.la
tests_oss_fuzz_ofp_print_target_LDFLAGS = $(LIB_FUZZING_ENGINE) -lc++

tests_oss_fuzz_odp_target_SOURCES = \
        tests/oss-fuzz/odp_target.c \
        tests/oss-fuzz/fuzzer.h
tests_oss_fuzz_odp_target_LDADD = lib/libopenvswitch.la
tests_oss_fuzz_odp_target_LDFLAGS = $(LIB_FUZZING_ENGINE) -lc++

tests_oss_fuzz_miniflow_target_SOURCES = \
        tests/oss-fuzz/miniflow_target.c \
        tests/oss-fuzz/fuzzer.h
tests_oss_fuzz_miniflow_target_LDADD = lib/libopenvswitch.la
tests_oss_fuzz_miniflow_target_LDFLAGS = $(LIB_FUZZING_ENGINE) -lc++

tests_oss_fuzz_ofctl_parse_target_SOURCES = \
        tests/oss-fuzz/ofctl_parse_target.c \
        tests/oss-fuzz/fuzzer.h
tests_oss_fuzz_ofctl_parse_target_LDADD = lib/libopenvswitch.la
tests_oss_fuzz_ofctl_parse_target_LDFLAGS = $(LIB_FUZZING_ENGINE) -lc++

EXTRA_DIST += \
	tests/oss-fuzz/config/flow_extract_target.options \
	tests/oss-fuzz/config/json_parser_target.options \
	tests/oss-fuzz/config/ofp_print_target.options \
	tests/oss-fuzz/config/odp_target.options \
	tests/oss-fuzz/config/miniflow_target.options \
        tests/oss-fuzz/config/ofctl_parse_target.options \
	tests/oss-fuzz/config/ovs.dict \
	tests/oss-fuzz/config/odp.dict \
	tests/oss-fuzz/config/ofp-flow.dict
