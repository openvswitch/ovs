/*
 * Copyright (c) 2008, 2009, 2010 Nicira Networks.
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
#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "coverage.h"
#include "vlog.h"

VLOG_DEFINE_THIS_MODULE(util)

const char *program_name;

void
out_of_memory(void)
{
    ovs_fatal(0, "virtual memory exhausted");
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

void
ovs_strlcpy(char *dst, const char *src, size_t size)
{
    if (size > 0) {
        size_t n = strlen(src);
        size_t n_copy = MIN(n, size - 1);
        memcpy(dst, src, n_copy);
        dst[n_copy] = '\0';
    }
}

void
ovs_fatal(int err_no, const char *format, ...)
{
    va_list args;

    fprintf(stderr, "%s: ", program_name);
    va_start(args, format);
    vfprintf(stderr, format, args);
    va_end(args);
    if (err_no != 0)
        fprintf(stderr, " (%s)",
                err_no == EOF ? "end of file" : strerror(err_no));
    putc('\n', stderr);

    exit(EXIT_FAILURE);
}

void
ovs_error(int err_no, const char *format, ...)
{
    int save_errno = errno;
    va_list args;

    fprintf(stderr, "%s: ", program_name);
    va_start(args, format);
    vfprintf(stderr, format, args);
    va_end(args);
    if (err_no != 0) {
        fprintf(stderr, " (%s)",
                err_no == EOF ? "end of file" : strerror(err_no));
    }
    putc('\n', stderr);

    errno = save_errno;
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
    }

    NOT_REACHED();
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
    if (!len) {
        return xstrdup((file_name[0] == '/'
                        && file_name[1] == '/'
                        && file_name[2] != '/') ? "//"
                       : file_name[0] == '/' ? "/"
                       : ".");
    } else {
        return xmemdup0(file_name, len);
    }
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
