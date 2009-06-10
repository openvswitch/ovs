#ifndef STRING_WRAPPER_H
#define STRING_WRAPPER_H 1

#include_next <string.h>

/* Glibc 2.7 has a bug in strtok_r when compiling with optimization that can
 * cause segfaults if the delimiters argument is a compile-time constant that
 * has exactly 1 character:
 *
 *      http://sources.redhat.com/bugzilla/show_bug.cgi?id=5614
 *
 * The bug is only present in the inline version of strtok_r(), so force the
 * out-of-line version to be used instead. */
#if HAVE_STRTOK_R_BUG
#undef strtok_r
#endif

#endif /* string.h wrapper */
