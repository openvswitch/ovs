/*
 * Copyright (c) 2014 VMware, Inc.
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

#include "precomp.h"

#include "Debug.h"
#ifdef DBG
#define OVS_DBG_DEFAULT  OVS_DBG_INFO
#else
#define OVS_DBG_DEFAULT  OVS_DBG_ERROR
#endif

UINT32  ovsLogFlags = 0xffffffff;
UINT32  ovsLogLevel = OVS_DBG_DEFAULT;

#define OVS_LOG_BUFFER_SIZE 384

/*
 * --------------------------------------------------------------------------
 * OvsLog --
 *  Utility function to log to the Windows debug console.
 * --------------------------------------------------------------------------
 */
VOID
OvsLog(UINT32 level,
       UINT32 flag,
       CHAR *funcName,
       UINT32 line,
       CHAR *format,
       ...)
{
    va_list args;
    CHAR buf[OVS_LOG_BUFFER_SIZE];

    if (level > ovsLogLevel || (ovsLogFlags & flag) == 0) {
        return;
    }

    buf[0] = 0;
    va_start(args, format);
    RtlStringCbVPrintfA(buf, sizeof (buf), format, args);
    va_end(args);

    DbgPrintEx(DPFLTR_IHVNETWORK_ID, level, "%s:%lu %s\n", funcName, line, buf);
}
