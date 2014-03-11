/*
 * Copyright (c) 2013 Nicira, Inc.
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

#include <stdio.h>
#include <sys/types.h>

#ifdef _WIN32
#undef snprintf
#undef vsnprintf

int
ovs_snprintf(char *s, size_t n, const char *format, ... )
{
    va_list args;
    int len;

    va_start(args, format);
    len = ovs_vsnprintf(s, n, format, args);
    va_end(args);

    return len;
}

int
ovs_vsnprintf(char *s, size_t n, const char *format, va_list args)
{
    int needed = _vscprintf(format, args);
    if (s && n) {
        vsnprintf(s, n, format, args);
        s[n - 1] = '\0';
    }
    return needed;
}

int
fseeko(FILE *stream, off_t offset, int whence)
{
    int error;
    error = _fseeki64(stream, offset, whence);
    if (error) {
        return -1;
    }
    return error;
}
#endif  /* _WIN32 */
