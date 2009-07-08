#include <config.h>
#include "type-props.h"
#include <stdio.h>
#include <stdlib.h>

#define MUST_SUCCEED(EXPRESSION)                    \
    if (!(EXPRESSION)) {                            \
        fprintf(stderr, "%s:%d: %s failed\n",       \
                __FILE__, __LINE__, #EXPRESSION);   \
        exit(EXIT_FAILURE);                         \
    }

#define TEST_TYPE(type, minimum, maximum, is_signed)    \
    MUST_SUCCEED(TYPE_IS_INTEGER(type));                \
    MUST_SUCCEED(TYPE_IS_SIGNED(type) == is_signed);    \
    MUST_SUCCEED(TYPE_MAXIMUM(type) == maximum);        \
    MUST_SUCCEED(TYPE_MINIMUM(type) == minimum);

int
main (void) 
{
    TEST_TYPE(char, CHAR_MIN, CHAR_MAX, (CHAR_MIN < 0));

    TEST_TYPE(signed char, SCHAR_MIN, SCHAR_MAX, 1);
    TEST_TYPE(short int, SHRT_MIN, SHRT_MAX, 1);
    TEST_TYPE(int, INT_MIN, INT_MAX, 1);
    TEST_TYPE(long int, LONG_MIN, LONG_MAX, 1);
    TEST_TYPE(long long int, LLONG_MIN, LLONG_MAX, 1);

    TEST_TYPE(unsigned char, 0, UCHAR_MAX, 0);
    TEST_TYPE(unsigned short int, 0, USHRT_MAX, 0);
    TEST_TYPE(unsigned int, 0, UINT_MAX, 0);
    TEST_TYPE(unsigned long int, 0, ULONG_MAX, 0);
    TEST_TYPE(unsigned long long int, 0, ULLONG_MAX, 0);

    MUST_SUCCEED(!(TYPE_IS_INTEGER(float)));
    MUST_SUCCEED(!(TYPE_IS_INTEGER(double)));
    MUST_SUCCEED(!(TYPE_IS_INTEGER(long double)));

    return 0;
}
