#ifndef UNIT_H
#define UNIT_H 1

/* List of unit tests. */
#define UNIT_TESTS				\
	UNIT_TEST(table_t)					  \
	UNIT_TEST(crc_t)						\
	UNIT_TEST(forward_t)

/* Prototype a function run_<NAME> for each of the unit tests. */
#define UNIT_TEST(NAME) void run_##NAME(void);
UNIT_TESTS
#undef UNIT_TEST

void unit_fail_function(const char *function, const char *msg, ...)
	__attribute__((format(printf, 2, 3)));
#define unit_fail(...) unit_fail_function(__func__, __VA_ARGS__)

int unit_failed(void);

#endif /* unit.h */
