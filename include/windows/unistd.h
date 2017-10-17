/*
 * Copyright (c) 2014 Nicira, Inc.
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
#ifndef _UNISTD_H
#define _UNISTD_H   1

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <direct.h>
#include <windefs.h>

#define fsync _commit
#define getcwd _getcwd

/* Standard file descriptors.  */
#define STDIN_FILENO    0   /* Standard input.  */
#define STDOUT_FILENO   1   /* Standard output.  */
#define STDERR_FILENO   2   /* Standard error output.  */

#define _SC_UIO_MAXIOV                  2
#define _XOPEN_IOV_MAX                 16

#define _SC_PAGESIZE                    0x1
#define _SC_NPROCESSORS_ONLN            0x2
#define _SC_PHYS_PAGES                  0x4


static __inline pid_t getpid(void)
{
    /* Since _getpid: https://msdn.microsoft.com/en-us/library/t2y34y40.aspx
     * uses GetCurrentProcessId behind the scenes it is safe to assume no
     * casting is required */
    return GetCurrentProcessId();
}

__inline int GetNumLogicalProcessors(void)
{
    SYSTEM_INFO info_temp;
    GetSystemInfo(&info_temp);
    long int n_cores = info_temp.dwNumberOfProcessors;
    return n_cores;
}

__inline long sysconf(int type)
{
    long value = -1;
    long page_size = -1;
    SYSTEM_INFO sys_info;
    MEMORYSTATUSEX status;

    switch (type) {
    case _SC_NPROCESSORS_ONLN:
        value = GetNumLogicalProcessors();
        break;

    case _SC_PAGESIZE:
        GetSystemInfo(&sys_info);
        value = sys_info.dwPageSize;
        break;

    case _SC_PHYS_PAGES:
        status.dwLength = sizeof(status);
        page_size = sysconf(_SC_PAGESIZE);
        if (GlobalMemoryStatusEx(&status) && page_size != -1) {
            value = status.ullTotalPhys / page_size;
        }
        break;

    default:
        break;
    }

    return value;
}

/* On Windows, a console is a specialized character device, and isatty() only
 * reports whether a file description is a character device and thus reports
 * that devices such as /dev/null are ttys.  This replacement avoids that
 * problem. */
#undef isatty
#define isatty(fd) rpl_isatty(fd)
static __inline int
rpl_isatty(int fd)
{
    HANDLE h = (HANDLE) _get_osfhandle(fd);
    DWORD st;
    return (_isatty(STDOUT_FILENO)
            && h != INVALID_HANDLE_VALUE
            && GetConsoleMode(h, &st));
}

#endif /* unistd.h  */
