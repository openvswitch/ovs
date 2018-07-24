/*
 * Copyright (c) 2008, 2009, 2010, 2011, 2012, 2013, 2014, 2015, 2016 Nicira, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <config.h>
#include "util.h"
#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include "bitmap.h"
#include "byte-order.h"
#include "coverage.h"
#include "ovs-rcu.h"
#include "ovs-thread.h"
#include "socket-util.h"
#include "timeval.h"
#include "openvswitch/vlog.h"
#ifdef HAVE_PTHREAD_SET_NAME_NP
#include <pthread_np.h>
#endif
#ifdef _WIN32
#include <shlwapi.h>
#endif

VLOG_DEFINE_THIS_MODULE(util);

#ifdef __linux__
#define LINUX 1
#include <asm/param.h>
#else
#define LINUX 0
#endif

COVERAGE_DEFINE(util_xalloc);

/* argv[0] without directory names. */
char *program_name;

/* Name for the currently running thread or process, for log messages, process
 * listings, and debuggers. */
DEFINE_PER_THREAD_MALLOCED_DATA(char *, subprogram_name);

/* --version option output. */
static char *program_version;

/* Buffer used by ovs_strerror() and ovs_format_message(). */
DEFINE_STATIC_PER_THREAD_DATA(struct { char s[128]; },
                              strerror_buffer,
                              { "" });

static char *xreadlink(const char *filename);

void
ovs_assert_failure(const char *where, const char *function,
                   const char *condition)
{
    /* Prevent an infinite loop (or stack overflow) in case VLOG_ABORT happens
     * to trigger an assertion failure of its own. */
    static int reentry = 0;

    switch (reentry++) {
    case 0:
        VLOG_ABORT("%s: assertion %s failed in %s()",
                   where, condition, function);
        OVS_NOT_REACHED();

    case 1:
        fprintf(stderr, "%s: assertion %s failed in %s()",
                where, condition, function);
        abort();

    default:
        abort();
    }
}

void
out_of_memory(void)
{
    ovs_abort(0, "virtual memory exhausted");
}

void *
xcalloc(size_t count, size_t size)
{
    void *p = count && size ? calloc(count, size) : malloc(1);
    COVERAGE_INC(util_xalloc);
    if (p == NULL) {
        out_of_memory();
    }
    return p;
}

void *
xzalloc(size_t size)
{
    return xcalloc(1, size);
}

void *
xmalloc(size_t size)
{
    void *p = malloc(size ? size : 1);
    COVERAGE_INC(util_xalloc);
    if (p == NULL) {
        out_of_memory();
    }
    return p;
}

void *
xrealloc(void *p, size_t size)
{
    p = realloc(p, size ? size : 1);
    COVERAGE_INC(util_xalloc);
    if (p == NULL) {
        out_of_memory();
    }
    return p;
}

void *
xmemdup(const void *p_, size_t size)
{
    void *p = xmalloc(size);
    nullable_memcpy(p, p_, size);
    return p;
}

char *
xmemdup0(const char *p_, size_t length)
{
    char *p = xmalloc(length + 1);
    memcpy(p, p_, length);
    p[length] = '\0';
    return p;
}

char *
xstrdup(const char *s)
{
    return xmemdup0(s, strlen(s));
}

char * MALLOC_LIKE
nullable_xstrdup(const char *s)
{
    return s ? xstrdup(s) : NULL;
}

bool
nullable_string_is_equal(const char *a, const char *b)
{
    return a ? b && !strcmp(a, b) : !b;
}

char *
xvasprintf(const char *format, va_list args)
{
    va_list args2;
    size_t needed;
    char *s;

    va_copy(args2, args);
    needed = vsnprintf(NULL, 0, format, args);

    s = xmalloc(needed + 1);

    vsnprintf(s, needed + 1, format, args2);
    va_end(args2);

    return s;
}

void *
x2nrealloc(void *p, size_t *n, size_t s)
{
    *n = *n == 0 ? 1 : 2 * *n;
    return xrealloc(p, *n * s);
}

/* Allocates and returns 'size' bytes of memory aligned to a cache line and in
 * dedicated cache lines.  That is, the memory block returned will not share a
 * cache line with other data, avoiding "false sharing".
 *
 * Use free_cacheline() to free the returned memory block. */
void *
xmalloc_cacheline(size_t size)
{
#ifdef HAVE_POSIX_MEMALIGN
    void *p;
    int error;

    COVERAGE_INC(util_xalloc);
    error = posix_memalign(&p, CACHE_LINE_SIZE, size ? size : 1);
    if (error != 0) {
        out_of_memory();
    }
    return p;
#else
    /* Allocate room for:
     *
     *     - Header padding: Up to CACHE_LINE_SIZE - 1 bytes, to allow the
     *       pointer to be aligned exactly sizeof(void *) bytes before the
     *       beginning of a cache line.
     *
     *     - Pointer: A pointer to the start of the header padding, to allow us
     *       to free() the block later.
     *
     *     - User data: 'size' bytes.
     *
     *     - Trailer padding: Enough to bring the user data up to a cache line
     *       multiple.
     *
     * +---------------+---------+------------------------+---------+
     * | header        | pointer | user data              | trailer |
     * +---------------+---------+------------------------+---------+
     * ^               ^         ^
     * |               |         |
     * p               q         r
     *
     */
    void *p = xmalloc((CACHE_LINE_SIZE - 1)
                      + sizeof(void *)
                      + ROUND_UP(size, CACHE_LINE_SIZE));
    bool runt = PAD_SIZE((uintptr_t) p, CACHE_LINE_SIZE) < sizeof(void *);
    void *r = (void *) ROUND_UP((uintptr_t) p + (runt ? CACHE_LINE_SIZE : 0),
                                CACHE_LINE_SIZE);
    void **q = (void **) r - 1;
    *q = p;
    return r;
#endif
}

/* Like xmalloc_cacheline() but clears the allocated memory to all zero
 * bytes. */
void *
xzalloc_cacheline(size_t size)
{
    void *p = xmalloc_cacheline(size);
    memset(p, 0, size);
    return p;
}

/* Frees a memory block allocated with xmalloc_cacheline() or
 * xzalloc_cacheline(). */
void
free_cacheline(void *p)
{
#ifdef HAVE_POSIX_MEMALIGN
    free(p);
#else
    if (p) {
        void **q = (void **) p - 1;
        free(*q);
    }
#endif
}

char *
xasprintf(const char *format, ...)
{
    va_list args;
    char *s;

    va_start(args, format);
    s = xvasprintf(format, args);
    va_end(args);

    return s;
}

/* Similar to strlcpy() from OpenBSD, but it never reads more than 'size - 1'
 * bytes from 'src' and doesn't return anything. */
void
ovs_strlcpy(char *dst, const char *src, size_t size)
{
    if (size > 0) {
        size_t len = strnlen(src, size - 1);
        memcpy(dst, src, len);
        dst[len] = '\0';
    }
}

/* Copies 'src' to 'dst'.  Reads no more than 'size - 1' bytes from 'src'.
 * Always null-terminates 'dst' (if 'size' is nonzero), and writes a zero byte
 * to every otherwise unused byte in 'dst'.
 *
 * Except for performance, the following call:
 *     ovs_strzcpy(dst, src, size);
 * is equivalent to these two calls:
 *     memset(dst, '\0', size);
 *     ovs_strlcpy(dst, src, size);
 *
 * (Thus, ovs_strzcpy() is similar to strncpy() without some of the pitfalls.)
 */
void
ovs_strzcpy(char *dst, const char *src, size_t size)
{
    if (size > 0) {
        size_t len = strnlen(src, size - 1);
        memcpy(dst, src, len);
        memset(dst + len, '\0', size - len);
    }
}

/*
 * Returns true if 'str' ends with given 'suffix'.
 */
int
string_ends_with(const char *str, const char *suffix)
{
    int str_len = strlen(str);
    int suffix_len = strlen(suffix);

    return (str_len >= suffix_len) &&
           (0 == strcmp(str + (str_len - suffix_len), suffix));
}

/* Prints 'format' on stderr, formatting it like printf() does.  If 'err_no' is
 * nonzero, then it is formatted with ovs_retval_to_string() and appended to
 * the message inside parentheses.  Then, terminates with abort().
 *
 * This function is preferred to ovs_fatal() in a situation where it would make
 * sense for a monitoring process to restart the daemon.
 *
 * 'format' should not end with a new-line, because this function will add one
 * itself. */
void
ovs_abort(int err_no, const char *format, ...)
{
    va_list args;

    va_start(args, format);
    ovs_abort_valist(err_no, format, args);
}

/* Same as ovs_abort() except that the arguments are supplied as a va_list. */
void
ovs_abort_valist(int err_no, const char *format, va_list args)
{
    ovs_error_valist(err_no, format, args);
    abort();
}

/* Prints 'format' on stderr, formatting it like printf() does.  If 'err_no' is
 * nonzero, then it is formatted with ovs_retval_to_string() and appended to
 * the message inside parentheses.  Then, terminates with EXIT_FAILURE.
 *
 * 'format' should not end with a new-line, because this function will add one
 * itself. */
void
ovs_fatal(int err_no, const char *format, ...)
{
    va_list args;

    va_start(args, format);
    ovs_fatal_valist(err_no, format, args);
}

/* Same as ovs_fatal() except that the arguments are supplied as a va_list. */
void
ovs_fatal_valist(int err_no, const char *format, va_list args)
{
    ovs_error_valist(err_no, format, args);
    exit(EXIT_FAILURE);
}

/* Prints 'format' on stderr, formatting it like printf() does.  If 'err_no' is
 * nonzero, then it is formatted with ovs_retval_to_string() and appended to
 * the message inside parentheses.
 *
 * 'format' should not end with a new-line, because this function will add one
 * itself. */
void
ovs_error(int err_no, const char *format, ...)
{
    va_list args;

    va_start(args, format);
    ovs_error_valist(err_no, format, args);
    va_end(args);
}

/* Same as ovs_error() except that the arguments are supplied as a va_list. */
void
ovs_error_valist(int err_no, const char *format, va_list args)
{
    const char *subprogram_name = get_subprogram_name();
    int save_errno = errno;

    if (subprogram_name[0]) {
        fprintf(stderr, "%s(%s): ", program_name, subprogram_name);
    } else {
        fprintf(stderr, "%s: ", program_name);
    }

    vfprintf(stderr, format, args);
    if (err_no != 0) {
        fprintf(stderr, " (%s)", ovs_retval_to_string(err_no));
    }
    putc('\n', stderr);

    errno = save_errno;
}

/* Many OVS functions return an int which is one of:
 * - 0: no error yet
 * - >0: errno value
 * - EOF: end of file (not necessarily an error; depends on the function called)
 *
 * Returns the appropriate human-readable string. The caller must copy the
 * string if it wants to hold onto it, as the storage may be overwritten on
 * subsequent function calls.
 */
const char *
ovs_retval_to_string(int retval)
{
    return (!retval ? ""
            : retval == EOF ? "End of file"
            : ovs_strerror(retval));
}

/* This function returns the string describing the error number in 'error'
 * for POSIX platforms.  For Windows, this function can be used for C library
 * calls.  For socket calls that are also used in Windows, use sock_strerror()
 * instead.  For WINAPI calls, look at ovs_lasterror_to_string(). */
const char *
ovs_strerror(int error)
{
    enum { BUFSIZE = sizeof strerror_buffer_get()->s };
    int save_errno;
    char *buffer;
    char *s;

    if (error == 0) {
        /*
         * strerror(0) varies among platforms:
         *
         *   Success
         *   No error
         *   Undefined error: 0
         *
         * We want to provide a consistent result here because
         * our testsuite has test cases which strictly matches
         * log messages containing this string.
         */
        return "Success";
    }

    save_errno = errno;
    buffer = strerror_buffer_get()->s;

#if STRERROR_R_CHAR_P
    /* GNU style strerror_r() might return an immutable static string, or it
     * might write and return 'buffer', but in either case we can pass the
     * returned string directly to the caller. */
    s = strerror_r(error, buffer, BUFSIZE);
#else  /* strerror_r() returns an int. */
    s = buffer;
    if (strerror_r(error, buffer, BUFSIZE)) {
        /* strerror_r() is only allowed to fail on ERANGE (because the buffer
         * is too short).  We don't check the actual failure reason because
         * POSIX requires strerror_r() to return the error but old glibc
         * (before 2.13) returns -1 and sets errno. */
        snprintf(buffer, BUFSIZE, "Unknown error %d", error);
    }
#endif

    errno = save_errno;

    return s;
}

/* Sets global "program_name" and "program_version" variables.  Should
 * be called at the beginning of main() with "argv[0]" as the argument
 * to 'argv0'.
 *
 * 'version' should contain the version of the caller's program.  If 'version'
 * is the same as the VERSION #define, the caller is assumed to be part of Open
 * vSwitch.  Otherwise, it is assumed to be an external program linking against
 * the Open vSwitch libraries.
 *
 */
void
ovs_set_program_name(const char *argv0, const char *version)
{
    char *basename;
#ifdef _WIN32
    size_t max_len = strlen(argv0) + 1;

    SetErrorMode(GetErrorMode() | SEM_NOGPFAULTERRORBOX);
#if _MSC_VER < 1900
     /* This function is deprecated from 1900 (Visual Studio 2015) */
    _set_output_format(_TWO_DIGIT_EXPONENT);
#endif

    basename = xmalloc(max_len);
    _splitpath_s(argv0, NULL, 0, NULL, 0, basename, max_len, NULL, 0);
#else
    const char *slash = strrchr(argv0, '/');
    basename = xstrdup(slash ? slash + 1 : argv0);
#endif

    assert_single_threaded();
    free(program_name);
    /* Remove libtool prefix, if it is there */
    if (strncmp(basename, "lt-", 3) == 0) {
        char *tmp_name = basename;
        basename = xstrdup(basename + 3);
        free(tmp_name);
    }
    program_name = basename;

    free(program_version);
    if (!strcmp(version, VERSION)) {
        program_version = xasprintf("%s (Open vSwitch) "VERSION"\n",
                                    program_name);
    } else {
        program_version = xasprintf("%s %s\n"
                                    "Open vSwitch Library "VERSION"\n",
                                    program_name, version);
    }
}

/* Returns the name of the currently running thread or process. */
const char *
get_subprogram_name(void)
{
    const char *name = subprogram_name_get();
    return name ? name : "";
}

/* Sets 'subprogram_name' as the name of the currently running thread or
 * process.  (This appears in log messages and may also be visible in system
 * process listings and debuggers.) */
void
set_subprogram_name(const char *subprogram_name)
{
    char *pname = xstrdup(subprogram_name ? subprogram_name : program_name);
    free(subprogram_name_set(pname));

#if HAVE_GLIBC_PTHREAD_SETNAME_NP
    pthread_setname_np(pthread_self(), pname);
#elif HAVE_NETBSD_PTHREAD_SETNAME_NP
    pthread_setname_np(pthread_self(), "%s", pname);
#elif HAVE_PTHREAD_SET_NAME_NP
    pthread_set_name_np(pthread_self(), pname);
#endif
}

unsigned int
get_page_size(void)
{
    static unsigned int cached;

    if (!cached) {
#ifndef _WIN32
        long int value = sysconf(_SC_PAGESIZE);
#else
        long int value;
        SYSTEM_INFO sysinfo;
        GetSystemInfo(&sysinfo);
        value = sysinfo.dwPageSize;
#endif
        if (value >= 0) {
            cached = value;
        }
    }

    return cached;
}

/* Returns the time at which the system booted, as the number of milliseconds
 * since the epoch, or 0 if the time of boot cannot be determined. */
long long int
get_boot_time(void)
{
    static long long int cache_expiration = LLONG_MIN;
    static long long int boot_time;

    ovs_assert(LINUX);

    if (time_msec() >= cache_expiration) {
        static const char stat_file[] = "/proc/stat";
        char line[128];
        FILE *stream;

        cache_expiration = time_msec() + 5 * 1000;

        stream = fopen(stat_file, "r");
        if (!stream) {
            VLOG_ERR_ONCE("%s: open failed (%s)",
                          stat_file, ovs_strerror(errno));
            return boot_time;
        }

        while (fgets(line, sizeof line, stream)) {
            long long int btime;
            if (ovs_scan(line, "btime %lld", &btime)) {
                boot_time = btime * 1000;
                goto done;
            }
        }
        VLOG_ERR_ONCE("%s: btime not found", stat_file);
    done:
        fclose(stream);
    }
    return boot_time;
}

/* Returns a pointer to a string describing the program version.  The
 * caller must not modify or free the returned string.
 */
const char *
ovs_get_program_version(void)
{
    return program_version;
}

/* Returns a pointer to a string describing the program name.  The
 * caller must not modify or free the returned string.
 */
const char *
ovs_get_program_name(void)
{
    return program_name;
}

/* Print the version information for the program.  */
void
ovs_print_version(uint8_t min_ofp, uint8_t max_ofp)
{
    printf("%s", program_version);
    if (min_ofp || max_ofp) {
        printf("OpenFlow versions %#x:%#x\n", min_ofp, max_ofp);
    }
}

/* Writes the 'size' bytes in 'buf' to 'stream' as hex bytes arranged 16 per
 * line.  Numeric offsets are also included, starting at 'ofs' for the first
 * byte in 'buf'.  If 'ascii' is true then the corresponding ASCII characters
 * are also rendered alongside. */
void
ovs_hex_dump(FILE *stream, const void *buf_, size_t size,
             uintptr_t ofs, bool ascii)
{
    const uint8_t *buf = buf_;
    const size_t per_line = 16; /* Maximum bytes per line. */

    while (size > 0) {
        size_t i;

        /* Number of bytes on this line. */
        size_t start = ofs % per_line;
        size_t end = per_line;
        if (end - start > size) {
            end = start + size;
        }
        size_t n = end - start;

        /* Print line. */
        fprintf(stream, "%08"PRIxMAX" ",
                (uintmax_t) ROUND_DOWN(ofs, per_line));
        for (i = 0; i < start; i++) {
            fprintf(stream, "   ");
        }
        for (; i < end; i++) {
            fprintf(stream, "%c%02x",
                    i == per_line / 2 ? '-' : ' ', buf[i - start]);
        }
        if (ascii) {
            fprintf(stream, " ");
            for (; i < per_line; i++) {
                fprintf(stream, "   ");
            }
            fprintf(stream, "|");
            for (i = 0; i < start; i++) {
                fprintf(stream, " ");
            }
            for (; i < end; i++) {
                int c = buf[i - start];
                putc(c >= 32 && c < 127 ? c : '.', stream);
            }
            for (; i < per_line; i++) {
                fprintf(stream, " ");
            }
            fprintf(stream, "|");
        }
        fprintf(stream, "\n");

        ofs += n;
        buf += n;
        size -= n;
    }
}

bool
str_to_int(const char *s, int base, int *i)
{
    long long ll;
    bool ok = str_to_llong(s, base, &ll);

    if (!ok || ll < INT_MIN || ll > INT_MAX) {
        *i = 0;
        return false;
    }
    *i = ll;
    return true;
}

bool
str_to_long(const char *s, int base, long *li)
{
    long long ll;
    bool ok = str_to_llong(s, base, &ll);

    if (!ok || ll < LONG_MIN || ll > LONG_MAX) {
        *li = 0;
        return false;
    }
    *li = ll;
    return true;
}

bool
str_to_llong(const char *s, int base, long long *x)
{
    char *tail;
    bool ok = str_to_llong_with_tail(s, &tail, base, x);
    if (*tail != '\0') {
        *x = 0;
        return false;
    }
    return ok;
}

bool
str_to_llong_with_tail(const char *s, char **tail, int base, long long *x)
{
    int save_errno = errno;
    errno = 0;
    *x = strtoll(s, tail, base);
    if (errno == EINVAL || errno == ERANGE || *tail == s) {
        errno = save_errno;
        *x = 0;
        return false;
    } else {
        errno = save_errno;
        return true;
    }
}

bool
str_to_uint(const char *s, int base, unsigned int *u)
{
    long long ll;
    bool ok = str_to_llong(s, base, &ll);
    if (!ok || ll < 0 || ll > UINT_MAX) {
        *u = 0;
        return false;
    } else {
        *u = ll;
        return true;
    }
}

bool
str_to_ullong(const char *s, int base, unsigned long long *x)
{
    int save_errno = errno;
    char *tail;

    errno = 0;
    *x = strtoull(s, &tail, base);
    if (errno == EINVAL || errno == ERANGE || tail == s || *tail != '\0') {
        errno = save_errno;
        *x = 0;
        return false;
    } else {
        errno = save_errno;
        return true;
    }
}

bool
str_to_llong_range(const char *s, int base, long long *begin,
                   long long *end)
{
    char *tail;
    if (str_to_llong_with_tail(s, &tail, base, begin)
        && *tail == '-'
        && str_to_llong(tail + 1, base, end)) {
        return true;
    }
    *begin = 0;
    *end = 0;
    return false;
}

/* Converts floating-point string 's' into a double.  If successful, stores
 * the double in '*d' and returns true; on failure, stores 0 in '*d' and
 * returns false.
 *
 * Underflow (e.g. "1e-9999") is not considered an error, but overflow
 * (e.g. "1e9999)" is. */
bool
str_to_double(const char *s, double *d)
{
    int save_errno = errno;
    char *tail;
    errno = 0;
    *d = strtod(s, &tail);
    if (errno == EINVAL || (errno == ERANGE && *d != 0)
        || tail == s || *tail != '\0') {
        errno = save_errno;
        *d = 0;
        return false;
    } else {
        errno = save_errno;
        return true;
    }
}

/* Returns the value of 'c' as a hexadecimal digit. */
int
hexit_value(unsigned char c)
{
    static const signed char tbl[UCHAR_MAX + 1] = {
#define TBL(x)                                  \
        (  x >= '0' && x <= '9' ? x - '0'       \
         : x >= 'a' && x <= 'f' ? x - 'a' + 0xa \
         : x >= 'A' && x <= 'F' ? x - 'A' + 0xa \
         : -1)
#define TBL0(x)  TBL(x),  TBL((x) + 1),   TBL((x) + 2),   TBL((x) + 3)
#define TBL1(x) TBL0(x), TBL0((x) + 4),  TBL0((x) + 8),  TBL0((x) + 12)
#define TBL2(x) TBL1(x), TBL1((x) + 16), TBL1((x) + 32), TBL1((x) + 48)
        TBL2(0), TBL2(64), TBL2(128), TBL2(192)
    };

    return tbl[c];
}

/* Returns the integer value of the 'n' hexadecimal digits starting at 's', or
 * UINTMAX_MAX if one of those "digits" is not really a hex digit.  Sets '*ok'
 * to true if the conversion succeeds or to false if a non-hex digit is
 * detected. */
uintmax_t
hexits_value(const char *s, size_t n, bool *ok)
{
    uintmax_t value;
    size_t i;

    value = 0;
    for (i = 0; i < n; i++) {
        int hexit = hexit_value(s[i]);
        if (hexit < 0) {
            *ok = false;
            return UINTMAX_MAX;
        }
        value = (value << 4) + hexit;
    }
    *ok = true;
    return value;
}

/* Parses the string in 's' as an integer in either hex or decimal format and
 * puts the result right justified in the array 'valuep' that is 'field_width'
 * big. If the string is in hex format, the value may be arbitrarily large;
 * integers are limited to 64-bit values. (The rationale is that decimal is
 * likely to represent a number and 64 bits is a reasonable maximum whereas
 * hex could either be a number or a byte string.)
 *
 * On return 'tail' points to the first character in the string that was
 * not parsed as part of the value. ERANGE is returned if the value is too
 * large to fit in the given field. */
int
parse_int_string(const char *s, uint8_t *valuep, int field_width, char **tail)
{
    unsigned long long int integer;
    int i;

    if (!strncmp(s, "0x", 2) || !strncmp(s, "0X", 2)) {
        uint8_t *hexit_str;
        int len = 0;
        int val_idx;
        int err = 0;

        s += 2;
        hexit_str = xmalloc(field_width * 2);

        for (;;) {
            uint8_t hexit;
            bool ok;

            s += strspn(s, " \t\r\n");
            hexit = hexits_value(s, 1, &ok);
            if (!ok) {
                *tail = CONST_CAST(char *, s);
                break;
            }

            if (hexit != 0 || len) {
                if (DIV_ROUND_UP(len + 1, 2) > field_width) {
                    err = ERANGE;
                    goto free;
                }

                hexit_str[len] = hexit;
                len++;
            }
            s++;
        }

        val_idx = field_width;
        for (i = len - 1; i >= 0; i -= 2) {
            val_idx--;
            valuep[val_idx] = hexit_str[i];
            if (i > 0) {
                valuep[val_idx] += hexit_str[i - 1] << 4;
            }
        }

        memset(valuep, 0, val_idx);

free:
        free(hexit_str);
        return err;
    }

    errno = 0;
    integer = strtoull(s, tail, 0);
    if (errno) {
        return errno;
    }

    for (i = field_width - 1; i >= 0; i--) {
        valuep[i] = integer;
        integer >>= 8;
    }
    if (integer) {
        return ERANGE;
    }

    return 0;
}

/* Returns the current working directory as a malloc()'d string, or a null
 * pointer if the current working directory cannot be determined. */
char *
get_cwd(void)
{
    long int path_max;
    size_t size;

    /* Get maximum path length or at least a reasonable estimate. */
#ifndef _WIN32
    path_max = pathconf(".", _PC_PATH_MAX);
#else
    path_max = MAX_PATH;
#endif
    size = (path_max < 0 ? 1024
            : path_max > 10240 ? 10240
            : path_max);

    /* Get current working directory. */
    for (;;) {
        char *buf = xmalloc(size);
        if (getcwd(buf, size)) {
            return xrealloc(buf, strlen(buf) + 1);
        } else {
            int error = errno;
            free(buf);
            if (error != ERANGE) {
                VLOG_WARN("getcwd failed (%s)", ovs_strerror(error));
                return NULL;
            }
            size *= 2;
        }
    }
}

static char *
all_slashes_name(const char *s)
{
    return xstrdup(s[0] == '/' && s[1] == '/' && s[2] != '/' ? "//"
                   : s[0] == '/' ? "/"
                   : ".");
}

#ifndef _WIN32
/* Returns the directory name portion of 'file_name' as a malloc()'d string,
 * similar to the POSIX dirname() function but thread-safe. */
char *
dir_name(const char *file_name)
{
    size_t len = strlen(file_name);
    while (len > 0 && file_name[len - 1] == '/') {
        len--;
    }
    while (len > 0 && file_name[len - 1] != '/') {
        len--;
    }
    while (len > 0 && file_name[len - 1] == '/') {
        len--;
    }
    return len ? xmemdup0(file_name, len) : all_slashes_name(file_name);
}

/* Returns the file name portion of 'file_name' as a malloc()'d string,
 * similar to the POSIX basename() function but thread-safe. */
char *
base_name(const char *file_name)
{
    size_t end, start;

    end = strlen(file_name);
    while (end > 0 && file_name[end - 1] == '/') {
        end--;
    }

    if (!end) {
        return all_slashes_name(file_name);
    }

    start = end;
    while (start > 0 && file_name[start - 1] != '/') {
        start--;
    }

    return xmemdup0(file_name + start, end - start);
}
#endif /* _WIN32 */

bool
is_file_name_absolute(const char *fn)
{
#ifdef _WIN32
    /* Use platform specific API */
    return !PathIsRelative(fn);
#else
    /* An absolute path begins with /. */
    return fn[0] == '/';
#endif
}

/* If 'file_name' is absolute, returns a copy of 'file_name'.  Otherwise,
 * returns an absolute path to 'file_name' considering it relative to 'dir',
 * which itself must be absolute.  'dir' may be null or the empty string, in
 * which case the current working directory is used.
 *
 * Returns a null pointer if 'dir' is null and getcwd() fails. */
char *
abs_file_name(const char *dir, const char *file_name)
{
    /* If it's already absolute, return a copy. */
    if (is_file_name_absolute(file_name)) {
        return xstrdup(file_name);
    }

    /* If a base dir was supplied, use it.  We assume, without checking, that
     * the base dir is absolute.*/
    if (dir && dir[0]) {
        char *separator = dir[strlen(dir) - 1] == '/' ? "" : "/";
        return xasprintf("%s%s%s", dir, separator, file_name);
    }

#if _WIN32
    /* It's a little complicated to make an absolute path on Windows because a
     * relative path might still specify a drive letter.  The OS has a function
     * to do the job for us, so use it. */
    char abs_path[MAX_PATH];
    DWORD n = GetFullPathName(file_name, sizeof abs_path, abs_path, NULL);
    return n > 0 && n <= sizeof abs_path ? xmemdup0(abs_path, n) : NULL;
#else
    /* Outside Windows, do the job ourselves. */
    char *cwd = get_cwd();
    if (!cwd) {
        return NULL;
    }
    char *abs_name = xasprintf("%s/%s", cwd, file_name);
    free(cwd);
    return abs_name;
#endif
}

/* Like readlink(), but returns the link name as a null-terminated string in
 * allocated memory that the caller must eventually free (with free()).
 * Returns NULL on error, in which case errno is set appropriately. */
static char *
xreadlink(const char *filename)
{
#ifdef _WIN32
    errno = ENOENT;
    return NULL;
#else
    size_t size;

    for (size = 64; ; size *= 2) {
        char *buf = xmalloc(size);
        ssize_t retval = readlink(filename, buf, size);
        int error = errno;

        if (retval >= 0 && retval < size) {
            buf[retval] = '\0';
            return buf;
        }

        free(buf);
        if (retval < 0) {
            errno = error;
            return NULL;
        }
    }
#endif
}

/* Returns a version of 'filename' with symlinks in the final component
 * dereferenced.  This differs from realpath() in that:
 *
 *     - 'filename' need not exist.
 *
 *     - If 'filename' does exist as a symlink, its referent need not exist.
 *
 *     - Only symlinks in the final component of 'filename' are dereferenced.
 *
 * For Windows platform, this function returns a string that has the same
 * value as the passed string.
 *
 * The caller must eventually free the returned string (with free()). */
char *
follow_symlinks(const char *filename)
{
#ifndef _WIN32
    struct stat s;
    char *fn;
    int i;

    fn = xstrdup(filename);
    for (i = 0; i < 10; i++) {
        char *linkname;
        char *next_fn;

        if (lstat(fn, &s) != 0 || !S_ISLNK(s.st_mode)) {
            return fn;
        }

        linkname = xreadlink(fn);
        if (!linkname) {
            VLOG_WARN("%s: readlink failed (%s)",
                      filename, ovs_strerror(errno));
            return fn;
        }

        if (linkname[0] == '/') {
            /* Target of symlink is absolute so use it raw. */
            next_fn = linkname;
        } else {
            /* Target of symlink is relative so add to 'fn''s directory. */
            char *dir = dir_name(fn);

            if (!strcmp(dir, ".")) {
                next_fn = linkname;
            } else {
                char *separator = dir[strlen(dir) - 1] == '/' ? "" : "/";
                next_fn = xasprintf("%s%s%s", dir, separator, linkname);
                free(linkname);
            }

            free(dir);
        }

        free(fn);
        fn = next_fn;
    }

    VLOG_WARN("%s: too many levels of symlinks", filename);
    free(fn);
#endif
    return xstrdup(filename);
}

/* Pass a value to this function if it is marked with
 * __attribute__((warn_unused_result)) and you genuinely want to ignore
 * its return value.  (Note that every scalar type can be implicitly
 * converted to bool.) */
void ignore(bool x OVS_UNUSED) { }

/* Returns an appropriate delimiter for inserting just before the 0-based item
 * 'index' in a list that has 'total' items in it. */
const char *
english_list_delimiter(size_t index, size_t total)
{
    return (index == 0 ? ""
            : index < total - 1 ? ", "
            : total > 2 ? ", and "
            : " and ");
}

/* Returns the number of trailing 0-bits in 'n'.  Undefined if 'n' == 0. */
#if __GNUC__ >= 4 || _MSC_VER
/* Defined inline in util.h. */
#else
/* Returns the number of trailing 0-bits in 'n'.  Undefined if 'n' == 0. */
int
raw_ctz(uint64_t n)
{
    uint64_t k;
    int count = 63;

#define CTZ_STEP(X)                             \
    k = n << (X);                               \
    if (k) {                                    \
        count -= X;                             \
        n = k;                                  \
    }
    CTZ_STEP(32);
    CTZ_STEP(16);
    CTZ_STEP(8);
    CTZ_STEP(4);
    CTZ_STEP(2);
    CTZ_STEP(1);
#undef CTZ_STEP

    return count;
}

/* Returns the number of leading 0-bits in 'n'.  Undefined if 'n' == 0. */
int
raw_clz64(uint64_t n)
{
    uint64_t k;
    int count = 63;

#define CLZ_STEP(X)                             \
    k = n >> (X);                               \
    if (k) {                                    \
        count -= X;                             \
        n = k;                                  \
    }
    CLZ_STEP(32);
    CLZ_STEP(16);
    CLZ_STEP(8);
    CLZ_STEP(4);
    CLZ_STEP(2);
    CLZ_STEP(1);
#undef CLZ_STEP

    return count;
}
#endif

#if NEED_COUNT_1BITS_8
#define INIT1(X)                                \
    ((((X) & (1 << 0)) != 0) +                  \
     (((X) & (1 << 1)) != 0) +                  \
     (((X) & (1 << 2)) != 0) +                  \
     (((X) & (1 << 3)) != 0) +                  \
     (((X) & (1 << 4)) != 0) +                  \
     (((X) & (1 << 5)) != 0) +                  \
     (((X) & (1 << 6)) != 0) +                  \
     (((X) & (1 << 7)) != 0))
#define INIT2(X)   INIT1(X),  INIT1((X) +  1)
#define INIT4(X)   INIT2(X),  INIT2((X) +  2)
#define INIT8(X)   INIT4(X),  INIT4((X) +  4)
#define INIT16(X)  INIT8(X),  INIT8((X) +  8)
#define INIT32(X) INIT16(X), INIT16((X) + 16)
#define INIT64(X) INIT32(X), INIT32((X) + 32)

const uint8_t count_1bits_8[256] = {
    INIT64(0), INIT64(64), INIT64(128), INIT64(192)
};
#endif

/* Returns true if the 'n' bytes starting at 'p' are 'byte'. */
bool
is_all_byte(const void *p_, size_t n, uint8_t byte)
{
    const uint8_t *p = p_;
    size_t i;

    for (i = 0; i < n; i++) {
        if (p[i] != byte) {
            return false;
        }
    }
    return true;
}

/* Returns true if the 'n' bytes starting at 'p' are zeros. */
bool
is_all_zeros(const void *p, size_t n)
{
    return is_all_byte(p, n, 0);
}

/* Returns true if the 'n' bytes starting at 'p' are 0xff. */
bool
is_all_ones(const void *p, size_t n)
{
    return is_all_byte(p, n, 0xff);
}

/* Copies 'n_bits' bits starting from bit 'src_ofs' in 'src' to the 'n_bits'
 * starting from bit 'dst_ofs' in 'dst'.  'src' is 'src_len' bytes long and
 * 'dst' is 'dst_len' bytes long.
 *
 * If you consider all of 'src' to be a single unsigned integer in network byte
 * order, then bit N is the bit with value 2**N.  That is, bit 0 is the bit
 * with value 1 in src[src_len - 1], bit 1 is the bit with value 2, bit 2 is
 * the bit with value 4, ..., bit 8 is the bit with value 1 in src[src_len -
 * 2], and so on.  Similarly for 'dst'.
 *
 * Required invariants:
 *   src_ofs + n_bits <= src_len * 8
 *   dst_ofs + n_bits <= dst_len * 8
 *   'src' and 'dst' must not overlap.
 */
void
bitwise_copy(const void *src_, unsigned int src_len, unsigned int src_ofs,
             void *dst_, unsigned int dst_len, unsigned int dst_ofs,
             unsigned int n_bits)
{
    const uint8_t *src = src_;
    uint8_t *dst = dst_;

    src += src_len - (src_ofs / 8 + 1);
    src_ofs %= 8;

    dst += dst_len - (dst_ofs / 8 + 1);
    dst_ofs %= 8;

    if (src_ofs == 0 && dst_ofs == 0) {
        unsigned int n_bytes = n_bits / 8;
        if (n_bytes) {
            dst -= n_bytes - 1;
            src -= n_bytes - 1;
            memcpy(dst, src, n_bytes);

            n_bits %= 8;
            src--;
            dst--;
        }
        if (n_bits) {
            uint8_t mask = (1 << n_bits) - 1;
            *dst = (*dst & ~mask) | (*src & mask);
        }
    } else {
        while (n_bits > 0) {
            unsigned int max_copy = 8 - MAX(src_ofs, dst_ofs);
            unsigned int chunk = MIN(n_bits, max_copy);
            uint8_t mask = ((1 << chunk) - 1) << dst_ofs;

            *dst &= ~mask;
            *dst |= ((*src >> src_ofs) << dst_ofs) & mask;

            src_ofs += chunk;
            if (src_ofs == 8) {
                src--;
                src_ofs = 0;
            }
            dst_ofs += chunk;
            if (dst_ofs == 8) {
                dst--;
                dst_ofs = 0;
            }
            n_bits -= chunk;
        }
    }
}

/* Zeros the 'n_bits' bits starting from bit 'dst_ofs' in 'dst'.  'dst' is
 * 'dst_len' bytes long.
 *
 * If you consider all of 'dst' to be a single unsigned integer in network byte
 * order, then bit N is the bit with value 2**N.  That is, bit 0 is the bit
 * with value 1 in dst[dst_len - 1], bit 1 is the bit with value 2, bit 2 is
 * the bit with value 4, ..., bit 8 is the bit with value 1 in dst[dst_len -
 * 2], and so on.
 *
 * Required invariant:
 *   dst_ofs + n_bits <= dst_len * 8
 */
void
bitwise_zero(void *dst_, unsigned int dst_len, unsigned dst_ofs,
             unsigned int n_bits)
{
    uint8_t *dst = dst_;

    if (!n_bits) {
        return;
    }

    dst += dst_len - (dst_ofs / 8 + 1);
    dst_ofs %= 8;

    if (dst_ofs) {
        unsigned int chunk = MIN(n_bits, 8 - dst_ofs);

        *dst &= ~(((1 << chunk) - 1) << dst_ofs);

        n_bits -= chunk;
        if (!n_bits) {
            return;
        }

        dst--;
    }

    while (n_bits >= 8) {
        *dst-- = 0;
        n_bits -= 8;
    }

    if (n_bits) {
        *dst &= ~((1 << n_bits) - 1);
    }
}

/* Sets to 1 all of the 'n_bits' bits starting from bit 'dst_ofs' in 'dst'.
 * 'dst' is 'dst_len' bytes long.
 *
 * If you consider all of 'dst' to be a single unsigned integer in network byte
 * order, then bit N is the bit with value 2**N.  That is, bit 0 is the bit
 * with value 1 in dst[dst_len - 1], bit 1 is the bit with value 2, bit 2 is
 * the bit with value 4, ..., bit 8 is the bit with value 1 in dst[dst_len -
 * 2], and so on.
 *
 * Required invariant:
 *   dst_ofs + n_bits <= dst_len * 8
 */
void
bitwise_one(void *dst_, unsigned int dst_len, unsigned dst_ofs,
            unsigned int n_bits)
{
    uint8_t *dst = dst_;

    if (!n_bits) {
        return;
    }

    dst += dst_len - (dst_ofs / 8 + 1);
    dst_ofs %= 8;

    if (dst_ofs) {
        unsigned int chunk = MIN(n_bits, 8 - dst_ofs);

        *dst |= ((1 << chunk) - 1) << dst_ofs;

        n_bits -= chunk;
        if (!n_bits) {
            return;
        }

        dst--;
    }

    while (n_bits >= 8) {
        *dst-- = 0xff;
        n_bits -= 8;
    }

    if (n_bits) {
        *dst |= (1 << n_bits) - 1;
    }
}

/* Scans the 'n_bits' bits starting from bit 'dst_ofs' in 'dst' for 1-bits.
 * Returns false if any 1-bits are found, otherwise true.  'dst' is 'dst_len'
 * bytes long.
 *
 * If you consider all of 'dst' to be a single unsigned integer in network byte
 * order, then bit N is the bit with value 2**N.  That is, bit 0 is the bit
 * with value 1 in dst[dst_len - 1], bit 1 is the bit with value 2, bit 2 is
 * the bit with value 4, ..., bit 8 is the bit with value 1 in dst[dst_len -
 * 2], and so on.
 *
 * Required invariant:
 *   dst_ofs + n_bits <= dst_len * 8
 */
bool
bitwise_is_all_zeros(const void *p_, unsigned int len, unsigned int ofs,
                     unsigned int n_bits)
{
    const uint8_t *p = p_;

    if (!n_bits) {
        return true;
    }

    p += len - (ofs / 8 + 1);
    ofs %= 8;

    if (ofs) {
        unsigned int chunk = MIN(n_bits, 8 - ofs);

        if (*p & (((1 << chunk) - 1) << ofs)) {
            return false;
        }

        n_bits -= chunk;
        if (!n_bits) {
            return true;
        }

        p--;
    }

    while (n_bits >= 8) {
        if (*p) {
            return false;
        }
        n_bits -= 8;
        p--;
    }

    if (n_bits && *p & ((1 << n_bits) - 1)) {
        return false;
    }

    return true;
}

/* Scans the bits in 'p' that have bit offsets 'start' (inclusive) through
 * 'end' (exclusive) for the first bit with value 'target'.  If one is found,
 * returns its offset, otherwise 'end'.  'p' is 'len' bytes long.
 *
 * If you consider all of 'p' to be a single unsigned integer in network byte
 * order, then bit N is the bit with value 2**N.  That is, bit 0 is the bit
 * with value 1 in p[len - 1], bit 1 is the bit with value 2, bit 2 is the bit
 * with value 4, ..., bit 8 is the bit with value 1 in p[len - 2], and so on.
 *
 * Required invariant:
 *   start <= end
 */
unsigned int
bitwise_scan(const void *p, unsigned int len, bool target, unsigned int start,
             unsigned int end)
{
    unsigned int ofs;

    for (ofs = start; ofs < end; ofs++) {
        if (bitwise_get_bit(p, len, ofs) == target) {
            break;
        }
    }
    return ofs;
}

/* Scans the bits in 'p' that have bit offsets 'start' (inclusive) through
 * 'end' (exclusive) for the first bit with value 'target', in reverse order.
 * If one is found, returns its offset, otherwise 'end'.  'p' is 'len' bytes
 * long.
 *
 * If you consider all of 'p' to be a single unsigned integer in network byte
 * order, then bit N is the bit with value 2**N.  That is, bit 0 is the bit
 * with value 1 in p[len - 1], bit 1 is the bit with value 2, bit 2 is the bit
 * with value 4, ..., bit 8 is the bit with value 1 in p[len - 2], and so on.
 *
 * To scan an entire bit array in reverse order, specify start == len * 8 - 1
 * and end == -1, in which case the return value is nonnegative if successful
 * and -1 if no 'target' match is found.
 *
 * Required invariant:
 *   start >= end
 */
int
bitwise_rscan(const void *p, unsigned int len, bool target, int start, int end)
{
    const uint8_t *s = p;
    int start_byte = len - (start / 8 + 1);
    int end_byte = len - (end / 8 + 1);
    int ofs_byte;
    int ofs;
    uint8_t the_byte;

    /* Find the target in the start_byte from starting offset */
    ofs_byte = start_byte;
    the_byte = s[ofs_byte];
    for (ofs = start % 8; ofs >= 0; ofs--) {
        if (((the_byte & (1u << ofs)) != 0) == target) {
            break;
        }
    }
    if (ofs < 0) {
        /* Target not found in start byte, continue searching byte by byte */
        for (ofs_byte = start_byte + 1; ofs_byte <= end_byte; ofs_byte++) {
            if ((target && s[ofs_byte])
                    || (!target && (s[ofs_byte] != 0xff))) {
               break;
            }
        }
        if (ofs_byte > end_byte) {
            return end;
        }
        the_byte = s[ofs_byte];
        /* Target is in the_byte, find it bit by bit */
        for (ofs = 7; ofs >= 0; ofs--) {
            if (((the_byte & (1u << ofs)) != 0) == target) {
                break;
            }
        }
    }
    int ret = (len - ofs_byte) * 8 - (8 - ofs);
    if (ret < end) {
        return end;
    }
    return ret;
}

/* Copies the 'n_bits' low-order bits of 'value' into the 'n_bits' bits
 * starting at bit 'dst_ofs' in 'dst', which is 'dst_len' bytes long.
 *
 * If you consider all of 'dst' to be a single unsigned integer in network byte
 * order, then bit N is the bit with value 2**N.  That is, bit 0 is the bit
 * with value 1 in dst[dst_len - 1], bit 1 is the bit with value 2, bit 2 is
 * the bit with value 4, ..., bit 8 is the bit with value 1 in dst[dst_len -
 * 2], and so on.
 *
 * Required invariants:
 *   dst_ofs + n_bits <= dst_len * 8
 *   n_bits <= 64
 */
void
bitwise_put(uint64_t value,
            void *dst, unsigned int dst_len, unsigned int dst_ofs,
            unsigned int n_bits)
{
    ovs_be64 n_value = htonll(value);
    bitwise_copy(&n_value, sizeof n_value, 0,
                 dst, dst_len, dst_ofs,
                 n_bits);
}

/* Returns the value of the 'n_bits' bits starting at bit 'src_ofs' in 'src',
 * which is 'src_len' bytes long.
 *
 * If you consider all of 'src' to be a single unsigned integer in network byte
 * order, then bit N is the bit with value 2**N.  That is, bit 0 is the bit
 * with value 1 in src[src_len - 1], bit 1 is the bit with value 2, bit 2 is
 * the bit with value 4, ..., bit 8 is the bit with value 1 in src[src_len -
 * 2], and so on.
 *
 * Required invariants:
 *   src_ofs + n_bits <= src_len * 8
 *   n_bits <= 64
 */
uint64_t
bitwise_get(const void *src, unsigned int src_len,
            unsigned int src_ofs, unsigned int n_bits)
{
    ovs_be64 value = htonll(0);

    bitwise_copy(src, src_len, src_ofs,
                 &value, sizeof value, 0,
                 n_bits);
    return ntohll(value);
}

/* Returns the value of the bit with offset 'ofs' in 'src', which is 'len'
 * bytes long.
 *
 * If you consider all of 'src' to be a single unsigned integer in network byte
 * order, then bit N is the bit with value 2**N.  That is, bit 0 is the bit
 * with value 1 in src[len - 1], bit 1 is the bit with value 2, bit 2 is the
 * bit with value 4, ..., bit 8 is the bit with value 1 in src[len - 2], and so
 * on.
 *
 * Required invariants:
 *   ofs < len * 8
 */
bool
bitwise_get_bit(const void *src_, unsigned int len, unsigned int ofs)
{
    const uint8_t *src = src_;

    return (src[len - (ofs / 8 + 1)] & (1u << (ofs % 8))) != 0;
}

/* Sets the bit with offset 'ofs' in 'dst', which is 'len' bytes long, to 0.
 *
 * If you consider all of 'dst' to be a single unsigned integer in network byte
 * order, then bit N is the bit with value 2**N.  That is, bit 0 is the bit
 * with value 1 in dst[len - 1], bit 1 is the bit with value 2, bit 2 is the
 * bit with value 4, ..., bit 8 is the bit with value 1 in dst[len - 2], and so
 * on.
 *
 * Required invariants:
 *   ofs < len * 8
 */
void
bitwise_put0(void *dst_, unsigned int len, unsigned int ofs)
{
    uint8_t *dst = dst_;

    dst[len - (ofs / 8 + 1)] &= ~(1u << (ofs % 8));
}

/* Sets the bit with offset 'ofs' in 'dst', which is 'len' bytes long, to 1.
 *
 * If you consider all of 'dst' to be a single unsigned integer in network byte
 * order, then bit N is the bit with value 2**N.  That is, bit 0 is the bit
 * with value 1 in dst[len - 1], bit 1 is the bit with value 2, bit 2 is the
 * bit with value 4, ..., bit 8 is the bit with value 1 in dst[len - 2], and so
 * on.
 *
 * Required invariants:
 *   ofs < len * 8
 */
void
bitwise_put1(void *dst_, unsigned int len, unsigned int ofs)
{
    uint8_t *dst = dst_;

    dst[len - (ofs / 8 + 1)] |= 1u << (ofs % 8);
}

/* Sets the bit with offset 'ofs' in 'dst', which is 'len' bytes long, to 'b'.
 *
 * If you consider all of 'dst' to be a single unsigned integer in network byte
 * order, then bit N is the bit with value 2**N.  That is, bit 0 is the bit
 * with value 1 in dst[len - 1], bit 1 is the bit with value 2, bit 2 is the
 * bit with value 4, ..., bit 8 is the bit with value 1 in dst[len - 2], and so
 * on.
 *
 * Required invariants:
 *   ofs < len * 8
 */
void
bitwise_put_bit(void *dst, unsigned int len, unsigned int ofs, bool b)
{
    if (b) {
        bitwise_put1(dst, len, ofs);
    } else {
        bitwise_put0(dst, len, ofs);
    }
}

/* Flips the bit with offset 'ofs' in 'dst', which is 'len' bytes long.
 *
 * If you consider all of 'dst' to be a single unsigned integer in network byte
 * order, then bit N is the bit with value 2**N.  That is, bit 0 is the bit
 * with value 1 in dst[len - 1], bit 1 is the bit with value 2, bit 2 is the
 * bit with value 4, ..., bit 8 is the bit with value 1 in dst[len - 2], and so
 * on.
 *
 * Required invariants:
 *   ofs < len * 8
 */
void
bitwise_toggle_bit(void *dst_, unsigned int len, unsigned int ofs)
{
    uint8_t *dst = dst_;

    dst[len - (ofs / 8 + 1)] ^= 1u << (ofs % 8);
}

/* ovs_scan */

struct scan_spec {
    unsigned int width;
    enum {
        SCAN_DISCARD,
        SCAN_CHAR,
        SCAN_SHORT,
        SCAN_INT,
        SCAN_LONG,
        SCAN_LLONG,
        SCAN_INTMAX_T,
        SCAN_PTRDIFF_T,
        SCAN_SIZE_T
    } type;
};

static const char *
skip_spaces(const char *s)
{
    while (isspace((unsigned char) *s)) {
        s++;
    }
    return s;
}

static const char *
scan_int(const char *s, const struct scan_spec *spec, int base, va_list *args)
{
    const char *start = s;
    uintmax_t value;
    bool negative;
    int n_digits;

    negative = *s == '-';
    s += *s == '-' || *s == '+';

    if ((!base || base == 16) && *s == '0' && (s[1] == 'x' || s[1] == 'X')) {
        base = 16;
        s += 2;
    } else if (!base) {
        base = *s == '0' ? 8 : 10;
    }

    if (s - start >= spec->width) {
        return NULL;
    }

    value = 0;
    n_digits = 0;
    while (s - start < spec->width) {
        int digit = hexit_value(*s);

        if (digit < 0 || digit >= base) {
            break;
        }
        value = value * base + digit;
        n_digits++;
        s++;
    }
    if (!n_digits) {
        return NULL;
    }

    if (negative) {
        value = -value;
    }

    switch (spec->type) {
    case SCAN_DISCARD:
        break;
    case SCAN_CHAR:
        *va_arg(*args, char *) = value;
        break;
    case SCAN_SHORT:
        *va_arg(*args, short int *) = value;
        break;
    case SCAN_INT:
        *va_arg(*args, int *) = value;
        break;
    case SCAN_LONG:
        *va_arg(*args, long int *) = value;
        break;
    case SCAN_LLONG:
        *va_arg(*args, long long int *) = value;
        break;
    case SCAN_INTMAX_T:
        *va_arg(*args, intmax_t *) = value;
        break;
    case SCAN_PTRDIFF_T:
        *va_arg(*args, ptrdiff_t *) = value;
        break;
    case SCAN_SIZE_T:
        *va_arg(*args, size_t *) = value;
        break;
    }
    return s;
}

static const char *
skip_digits(const char *s)
{
    while (*s >= '0' && *s <= '9') {
        s++;
    }
    return s;
}

static const char *
scan_float(const char *s, const struct scan_spec *spec, va_list *args)
{
    const char *start = s;
    long double value;
    char *tail;
    char *copy;
    bool ok;

    s += *s == '+' || *s == '-';
    s = skip_digits(s);
    if (*s == '.') {
        s = skip_digits(s + 1);
    }
    if (*s == 'e' || *s == 'E') {
        s++;
        s += *s == '+' || *s == '-';
        s = skip_digits(s);
    }

    if (s - start > spec->width) {
        s = start + spec->width;
    }

    copy = xmemdup0(start, s - start);
    value = strtold(copy, &tail);
    ok = *tail == '\0';
    free(copy);
    if (!ok) {
        return NULL;
    }

    switch (spec->type) {
    case SCAN_DISCARD:
        break;
    case SCAN_INT:
        *va_arg(*args, float *) = value;
        break;
    case SCAN_LONG:
        *va_arg(*args, double *) = value;
        break;
    case SCAN_LLONG:
        *va_arg(*args, long double *) = value;
        break;

    case SCAN_CHAR:
    case SCAN_SHORT:
    case SCAN_INTMAX_T:
    case SCAN_PTRDIFF_T:
    case SCAN_SIZE_T:
        OVS_NOT_REACHED();
    }
    return s;
}

static void
scan_output_string(const struct scan_spec *spec,
                   const char *s, size_t n,
                   va_list *args)
{
    if (spec->type != SCAN_DISCARD) {
        char *out = va_arg(*args, char *);
        memcpy(out, s, n);
        out[n] = '\0';
    }
}

static const char *
scan_string(const char *s, const struct scan_spec *spec, va_list *args)
{
    size_t n;

    for (n = 0; n < spec->width; n++) {
        if (!s[n] || isspace((unsigned char) s[n])) {
            break;
        }
    }
    if (!n) {
        return NULL;
    }

    scan_output_string(spec, s, n, args);
    return s + n;
}

static const char *
parse_scanset(const char *p_, unsigned long *set, bool *complemented)
{
    const uint8_t *p = (const uint8_t *) p_;

    *complemented = *p == '^';
    p += *complemented;

    if (*p == ']') {
        bitmap_set1(set, ']');
        p++;
    }

    while (*p && *p != ']') {
        if (p[1] == '-' && p[2] != ']' && p[2] > *p) {
            bitmap_set_multiple(set, *p, p[2] - *p + 1, true);
            p += 3;
        } else {
            bitmap_set1(set, *p++);
        }
    }
    if (*p == ']') {
        p++;
    }
    return (const char *) p;
}

static const char *
scan_set(const char *s, const struct scan_spec *spec, const char **pp,
         va_list *args)
{
    unsigned long set[BITMAP_N_LONGS(UCHAR_MAX + 1)];
    bool complemented;
    unsigned int n;

    /* Parse the scan set. */
    memset(set, 0, sizeof set);
    *pp = parse_scanset(*pp, set, &complemented);

    /* Parse the data. */
    n = 0;
    while (s[n]
           && bitmap_is_set(set, (unsigned char) s[n]) == !complemented
           && n < spec->width) {
        n++;
    }
    if (!n) {
        return NULL;
    }
    scan_output_string(spec, s, n, args);
    return s + n;
}

static const char *
scan_chars(const char *s, const struct scan_spec *spec, va_list *args)
{
    unsigned int n = spec->width == UINT_MAX ? 1 : spec->width;

    if (strlen(s) < n) {
        return NULL;
    }
    if (spec->type != SCAN_DISCARD) {
        memcpy(va_arg(*args, char *), s, n);
    }
    return s + n;
}

static bool
ovs_scan__(const char *s, int *n, const char *format, va_list *args)
{
    const char *const start = s;
    bool ok = false;
    const char *p;

    p = format;
    while (*p != '\0') {
        struct scan_spec spec;
        unsigned char c = *p++;
        bool discard;

        if (isspace(c)) {
            s = skip_spaces(s);
            continue;
        } else if (c != '%') {
            if (*s != c) {
                goto exit;
            }
            s++;
            continue;
        } else if (*p == '%') {
            if (*s++ != '%') {
                goto exit;
            }
            p++;
            continue;
        }

        /* Parse '*' flag. */
        discard = *p == '*';
        p += discard;

        /* Parse field width. */
        spec.width = 0;
        while (*p >= '0' && *p <= '9') {
            spec.width = spec.width * 10 + (*p++ - '0');
        }
        if (spec.width == 0) {
            spec.width = UINT_MAX;
        }

        /* Parse type modifier. */
        switch (*p) {
        case 'h':
            if (p[1] == 'h') {
                spec.type = SCAN_CHAR;
                p += 2;
            } else {
                spec.type = SCAN_SHORT;
                p++;
            }
            break;

        case 'j':
            spec.type = SCAN_INTMAX_T;
            p++;
            break;

        case 'l':
            if (p[1] == 'l') {
                spec.type = SCAN_LLONG;
                p += 2;
            } else {
                spec.type = SCAN_LONG;
                p++;
            }
            break;

        case 'L':
        case 'q':
            spec.type = SCAN_LLONG;
            p++;
            break;

        case 't':
            spec.type = SCAN_PTRDIFF_T;
            p++;
            break;

        case 'z':
            spec.type = SCAN_SIZE_T;
            p++;
            break;

        default:
            spec.type = SCAN_INT;
            break;
        }

        if (discard) {
            spec.type = SCAN_DISCARD;
        }

        c = *p++;
        if (c != 'c' && c != 'n' && c != '[') {
            s = skip_spaces(s);
        }
        switch (c) {
        case 'd':
            s = scan_int(s, &spec, 10, args);
            break;

        case 'i':
            s = scan_int(s, &spec, 0, args);
            break;

        case 'o':
            s = scan_int(s, &spec, 8, args);
            break;

        case 'u':
            s = scan_int(s, &spec, 10, args);
            break;

        case 'x':
        case 'X':
            s = scan_int(s, &spec, 16, args);
            break;

        case 'e':
        case 'f':
        case 'g':
        case 'E':
        case 'G':
            s = scan_float(s, &spec, args);
            break;

        case 's':
            s = scan_string(s, &spec, args);
            break;

        case '[':
            s = scan_set(s, &spec, &p, args);
            break;

        case 'c':
            s = scan_chars(s, &spec, args);
            break;

        case 'n':
            if (spec.type != SCAN_DISCARD) {
                *va_arg(*args, int *) = s - start;
            }
            break;
        }

        if (!s) {
            goto exit;
        }
    }
    if (n) {
        *n = s - start;
    }

    ok = true;
exit:
    return ok;
}

/* This is an implementation of the standard sscanf() function, with the
 * following exceptions:
 *
 *   - It returns true if the entire format was successfully scanned and
 *     converted, false if any conversion failed.
 *
 *   - The standard doesn't define sscanf() behavior when an out-of-range value
 *     is scanned, e.g. if a "%"PRIi8 conversion scans "-1" or "0x1ff".  Some
 *     implementations consider this an error and stop scanning.  This
 *     implementation never considers an out-of-range value an error; instead,
 *     it stores the least-significant bits of the converted value in the
 *     destination, e.g. the value 255 for both examples earlier.
 *
 *   - Only single-byte characters are supported, that is, the 'l' modifier
 *     on %s, %[, and %c is not supported.  The GNU extension 'a' modifier is
 *     also not supported.
 *
 *   - %p is not supported.
 */
bool
ovs_scan(const char *s, const char *format, ...)
{
    va_list args;
    bool res;

    va_start(args, format);
    res = ovs_scan__(s, NULL, format, &args);
    va_end(args);
    return res;
}

/*
 * This function is similar to ovs_scan(), with an extra parameter `n` added to
 * return the number of scanned characters.
 */
bool
ovs_scan_len(const char *s, int *n, const char *format, ...)
{
    va_list args;
    bool success;
    int n1;

    va_start(args, format);
    success = ovs_scan__(s + *n, &n1, format, &args);
    va_end(args);
    if (success) {
        *n = *n + n1;
    }
    return success;
}

void
xsleep(unsigned int seconds)
{
    ovsrcu_quiesce_start();
#ifdef _WIN32
    Sleep(seconds * 1000);
#else
    sleep(seconds);
#endif
    ovsrcu_quiesce_end();
}

/* High resolution sleep. */
void
xnanosleep(uint64_t nanoseconds)
{
    ovsrcu_quiesce_start();
#ifndef _WIN32
    int retval;
    struct timespec ts_sleep;
    nsec_to_timespec(nanoseconds, &ts_sleep);

    int error = 0;
    do {
        retval = nanosleep(&ts_sleep, NULL);
        error = retval < 0 ? errno : 0;
    } while (error == EINTR);
#else
    HANDLE timer = CreateWaitableTimer(NULL, FALSE, NULL);
    if (timer) {
        LARGE_INTEGER duetime;
        duetime.QuadPart = -nanoseconds;
        if (SetWaitableTimer(timer, &duetime, 0, NULL, NULL, FALSE)) {
            WaitForSingleObject(timer, INFINITE);
        } else {
            VLOG_ERR_ONCE("SetWaitableTimer Failed (%s)",
                           ovs_lasterror_to_string());
        }
        CloseHandle(timer);
    } else {
        VLOG_ERR_ONCE("CreateWaitableTimer Failed (%s)",
                       ovs_lasterror_to_string());
    }
#endif
    ovsrcu_quiesce_end();
}

/* Determine whether standard output is a tty or not. This is useful to decide
 * whether to use color output or not when --color option for utilities is set
 * to `auto`.
 */
bool
is_stdout_a_tty(void)
{
    char const *t = getenv("TERM");
    return (isatty(STDOUT_FILENO) && t && strcmp(t, "dumb") != 0);
}

#ifdef _WIN32

char *
ovs_format_message(int error)
{
    enum { BUFSIZE = sizeof strerror_buffer_get()->s };
    char *buffer = strerror_buffer_get()->s;

    if (error == 0) {
        /* See ovs_strerror */
        return "Success";
    }

    FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
                  NULL, error, 0, buffer, BUFSIZE, NULL);
    return buffer;
}

/* Returns a null-terminated string that explains the last error.
 * Use this function to get the error string for WINAPI calls. */
char *
ovs_lasterror_to_string(void)
{
    return ovs_format_message(GetLastError());
}

int
ftruncate(int fd, off_t length)
{
    int error;

    error = _chsize_s(fd, length);
    if (error) {
        return -1;
    }
    return 0;
}

OVS_CONSTRUCTOR(winsock_start) {
    WSADATA wsaData;
    int error;

    error = WSAStartup(MAKEWORD(2, 2), &wsaData);
    if (error != 0) {
        VLOG_FATAL("WSAStartup failed: %s", sock_strerror(sock_errno()));
   }
}
#endif
