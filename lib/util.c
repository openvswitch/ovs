/*
 * Copyright (c) 2008, 2009, 2010, 2011, 2012 Nicira, Inc.
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
#include <assert.h>
#include <errno.h>
#include <limits.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include "byte-order.h"
#include "coverage.h"
#include "openvswitch/types.h"
#include "vlog.h"

VLOG_DEFINE_THIS_MODULE(util);

COVERAGE_DEFINE(util_xalloc);

/* argv[0] without directory names. */
const char *program_name;

/* Ordinarily "" but set to "monitor" for a monitor process or "worker" for a
 * worker process. */
const char *subprogram_name = "";

/* --version option output. */
static char *program_version;

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
    memcpy(p, p_, size);
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
    static char unknown[48];

    if (!retval) {
        return "";
    }
    if (retval > 0) {
        return strerror(retval);
    }
    if (retval == EOF) {
        return "End of file";
    }
    snprintf(unknown, sizeof unknown, "***unknown return value: %d***", retval);
    return unknown;
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
 * The 'date' and 'time' arguments should likely be called with
 * "__DATE__" and "__TIME__" to use the time the binary was built.
 * Alternatively, the "set_program_name" macro may be called to do this
 * automatically.
 */
void
set_program_name__(const char *argv0, const char *version, const char *date,
                   const char *time)
{
    const char *slash = strrchr(argv0, '/');
    program_name = slash ? slash + 1 : argv0;

    free(program_version);

    if (!strcmp(version, VERSION)) {
        program_version = xasprintf("%s (Open vSwitch) "VERSION"\n"
                                    "Compiled %s %s\n",
                                    program_name, date, time);
    } else {
        program_version = xasprintf("%s %s\n"
                                    "Open vSwitch Library "VERSION"\n"
                                    "Compiled %s %s\n",
                                    program_name, version, date, time);
    }
}

/* Returns a pointer to a string describing the program version.  The
 * caller must not modify or free the returned string.
 */
const char *
get_program_version(void)
{
    return program_version;
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

  while (size > 0)
    {
      size_t start, end, n;
      size_t i;

      /* Number of bytes on this line. */
      start = ofs % per_line;
      end = per_line;
      if (end - start > size)
        end = start + size;
      n = end - start;

      /* Print line. */
      fprintf(stream, "%08jx  ", (uintmax_t) ROUND_DOWN(ofs, per_line));
      for (i = 0; i < start; i++)
        fprintf(stream, "   ");
      for (; i < end; i++)
        fprintf(stream, "%02hhx%c",
                buf[i - start], i == per_line / 2 - 1? '-' : ' ');
      if (ascii)
        {
          for (; i < per_line; i++)
            fprintf(stream, "   ");
          fprintf(stream, "|");
          for (i = 0; i < start; i++)
            fprintf(stream, " ");
          for (; i < end; i++) {
              int c = buf[i - start];
              putc(c >= 32 && c < 127 ? c : '.', stream);
          }
          for (; i < per_line; i++)
            fprintf(stream, " ");
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
    *i = ll;
    return ok;
}

bool
str_to_long(const char *s, int base, long *li)
{
    long long ll;
    bool ok = str_to_llong(s, base, &ll);
    *li = ll;
    return ok;
}

bool
str_to_llong(const char *s, int base, long long *x)
{
    int save_errno = errno;
    char *tail;
    errno = 0;
    *x = strtoll(s, &tail, base);
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
str_to_uint(const char *s, int base, unsigned int *u)
{
    return str_to_int(s, base, (int *) u);
}

bool
str_to_ulong(const char *s, int base, unsigned long *ul)
{
    return str_to_long(s, base, (long *) ul);
}

bool
str_to_ullong(const char *s, int base, unsigned long long *ull)
{
    return str_to_llong(s, base, (long long *) ull);
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
hexit_value(int c)
{
    switch (c) {
    case '0': case '1': case '2': case '3': case '4':
    case '5': case '6': case '7': case '8': case '9':
        return c - '0';

    case 'a': case 'A':
        return 0xa;

    case 'b': case 'B':
        return 0xb;

    case 'c': case 'C':
        return 0xc;

    case 'd': case 'D':
        return 0xd;

    case 'e': case 'E':
        return 0xe;

    case 'f': case 'F':
        return 0xf;

    default:
        return -1;
    }
}

/* Returns the integer value of the 'n' hexadecimal digits starting at 's', or
 * UINT_MAX if one of those "digits" is not really a hex digit.  If 'ok' is
 * nonnull, '*ok' is set to true if the conversion succeeds or to false if a
 * non-hex digit is detected. */
unsigned int
hexits_value(const char *s, size_t n, bool *ok)
{
    unsigned int value;
    size_t i;

    value = 0;
    for (i = 0; i < n; i++) {
        int hexit = hexit_value(s[i]);
        if (hexit < 0) {
            if (ok) {
                *ok = false;
            }
            return UINT_MAX;
        }
        value = (value << 4) + hexit;
    }
    if (ok) {
        *ok = true;
    }
    return value;
}

/* Returns the current working directory as a malloc()'d string, or a null
 * pointer if the current working directory cannot be determined. */
char *
get_cwd(void)
{
    long int path_max;
    size_t size;

    /* Get maximum path length or at least a reasonable estimate. */
    path_max = pathconf(".", _PC_PATH_MAX);
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
                VLOG_WARN("getcwd failed (%s)", strerror(error));
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

/* If 'file_name' starts with '/', returns a copy of 'file_name'.  Otherwise,
 * returns an absolute path to 'file_name' considering it relative to 'dir',
 * which itself must be absolute.  'dir' may be null or the empty string, in
 * which case the current working directory is used.
 *
 * Returns a null pointer if 'dir' is null and getcwd() fails. */
char *
abs_file_name(const char *dir, const char *file_name)
{
    if (file_name[0] == '/') {
        return xstrdup(file_name);
    } else if (dir && dir[0]) {
        char *separator = dir[strlen(dir) - 1] == '/' ? "" : "/";
        return xasprintf("%s%s%s", dir, separator, file_name);
    } else {
        char *cwd = get_cwd();
        if (cwd) {
            char *abs_name = xasprintf("%s/%s", cwd, file_name);
            free(cwd);
            return abs_name;
        } else {
            return NULL;
        }
    }
}

/* Like readlink(), but returns the link name as a null-terminated string in
 * allocated memory that the caller must eventually free (with free()).
 * Returns NULL on error, in which case errno is set appropriately. */
char *
xreadlink(const char *filename)
{
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
 * The caller must eventually free the returned string (with free()). */
char *
follow_symlinks(const char *filename)
{
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
            VLOG_WARN("%s: readlink failed (%s)", filename, strerror(errno));
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

/* Given a 32 bit word 'n', calculates floor(log_2('n')).  This is equivalent
 * to finding the bit position of the most significant one bit in 'n'.  It is
 * an error to call this function with 'n' == 0. */
int
log_2_floor(uint32_t n)
{
    assert(n);

#if !defined(UINT_MAX) || !defined(UINT32_MAX)
#error "Someone screwed up the #includes."
#elif __GNUC__ >= 4 && UINT_MAX == UINT32_MAX
    return 31 - __builtin_clz(n);
#else
    {
        int log = 0;

#define BIN_SEARCH_STEP(BITS)                   \
        if (n >= (1 << BITS)) {                 \
            log += BITS;                        \
            n >>= BITS;                         \
        }
        BIN_SEARCH_STEP(16);
        BIN_SEARCH_STEP(8);
        BIN_SEARCH_STEP(4);
        BIN_SEARCH_STEP(2);
        BIN_SEARCH_STEP(1);
#undef BIN_SEARCH_STEP
        return log;
    }
#endif
}

/* Given a 32 bit word 'n', calculates ceil(log_2('n')).  It is an error to
 * call this function with 'n' == 0. */
int
log_2_ceil(uint32_t n)
{
    return log_2_floor(n) + !IS_POW2(n);
}

/* Returns the number of trailing 0-bits in 'n'.  Undefined if 'n' == 0. */
#if !defined(UINT_MAX) || !defined(UINT32_MAX)
#error "Someone screwed up the #includes."
#elif __GNUC__ >= 4 && UINT_MAX == UINT32_MAX
/* Defined inline in util.h. */
#else
static int
raw_ctz(uint32_t n)
{
    unsigned int k;
    int count = 31;

#define CTZ_STEP(X)                             \
    k = n << (X);                               \
    if (k) {                                    \
        count -= X;                             \
        n = k;                                  \
    }
    CTZ_STEP(16);
    CTZ_STEP(8);
    CTZ_STEP(4);
    CTZ_STEP(2);
    CTZ_STEP(1);
#undef CTZ_STEP

    return count;
}
#endif

/* Returns the number of 1-bits in 'x', between 0 and 32 inclusive. */
int
popcount(uint32_t x)
{
    /* In my testing, this implementation is over twice as fast as any other
     * portable implementation that I tried, including GCC 4.4
     * __builtin_popcount(), although nonportable asm("popcnt") was over 50%
     * faster. */
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

    static const uint8_t popcount8[256] = {
        INIT64(0), INIT64(64), INIT64(128), INIT64(192)
    };

    return (popcount8[x & 0xff] +
            popcount8[(x >> 8) & 0xff] +
            popcount8[(x >> 16) & 0xff] +
            popcount8[x >> 24]);
}

/* Returns true if the 'n' bytes starting at 'p' are zeros. */
bool
is_all_zeros(const uint8_t *p, size_t n)
{
    size_t i;

    for (i = 0; i < n; i++) {
        if (p[i] != 0x00) {
            return false;
        }
    }
    return true;
}

/* Returns true if the 'n' bytes starting at 'p' are 0xff. */
bool
is_all_ones(const uint8_t *p, size_t n)
{
    size_t i;

    for (i = 0; i < n; i++) {
        if (p[i] != 0xff) {
            return false;
        }
    }
    return true;
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
