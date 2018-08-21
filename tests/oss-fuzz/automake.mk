OSS_FUZZ_TARGETS = \
	tests/oss-fuzz/flow_extract_target \
	tests/oss-fuzz/json_parser_target \
	tests/oss-fuzz/ofp_print_target
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

EXTRA_DIST += \
	tests/oss-fuzz/config/flow_extract_target.options \
	tests/oss-fuzz/config/json_parser_target.options \
	tests/oss-fuzz/config/ofp_print_target.options \
	tests/oss-fuzz/config/ovs.dict
