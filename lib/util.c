/*
 * Copyright (c) 2008, 2009, 2010, 2011 Nicira Networks.
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
#include <unistd.h>
#include "coverage.h"
#include "vlog.h"

VLOG_DEFINE_THIS_MODULE(util);

COVERAGE_DEFINE(util_xalloc);

const char *program_name;

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
    ovs_error_valist(err_no, format, args);
    va_end(args);

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

    fprintf(stderr, "%s: ", program_name);
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

/* Sets program_name based on 'argv0'.  Should be called at the beginning of
 * main(), as "set_program_name(argv[0]);".  */
void set_program_name(const char *argv0)
{
    const char *slash = strrchr(argv0, '/');
    program_name = slash ? slash + 1 : argv0;
}

/* Print the version information for the program.  */
void
ovs_print_version(char *date, char *time,
                  uint8_t min_ofp, uint8_t max_ofp)
{
    printf("%s (Open vSwitch) "VERSION BUILDNR"\n", program_name);
    printf("Compiled %s %s\n", date, time);
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
