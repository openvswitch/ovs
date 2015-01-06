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

#ifndef __DEBUG_H_
#define __DEBUG_H_ 1

#define OVS_DBG_INIT     BIT32(0)
#define OVS_DBG_SWITCH   BIT32(1)
#define OVS_DBG_VPORT    BIT32(2)
#define OVS_DBG_FLOW     BIT32(3)
#define OVS_DBG_QOS      BIT32(4)
#define OVS_DBG_USER     BIT32(5)
#define OVS_DBG_EXECUTE  BIT32(6)
#define OVS_DBG_EVENT    BIT32(7)
#define OVS_DBG_DISPATCH BIT32(8)
#define OVS_DBG_OID      BIT32(9)
#define OVS_DBG_STATUS   BIT32(10)
#define OVS_DBG_CHECKSUM BIT32(11)
#define OVS_DBG_VXLAN    BIT32(12)
#define OVS_DBG_GRE      BIT32(13)
#define OVS_DBG_GRE64    BIT32(14)
#define OVS_DBG_ACTION   BIT32(15)
#define OVS_DBG_DATAPATH BIT32(16)
#define OVS_DBG_PROPERTY BIT32(17)
#define OVS_DBG_IPHELPER BIT32(18)
#define OVS_DBG_BUFMGMT  BIT32(19)
#define OVS_DBG_OTHERS   BIT32(21)
#define OVS_DBG_NETLINK  BIT32(22)
#define OVS_DBG_TUNFLT   BIT32(23)

#define OVS_DBG_RESERVED BIT32(31)
//Please add above OVS_DBG_RESERVED.

#define OVS_DBG_ERROR    DPFLTR_ERROR_LEVEL
#define OVS_DBG_WARN     DPFLTR_WARNING_LEVEL
#define OVS_DBG_TRACE    DPFLTR_TRACE_LEVEL
#define OVS_DBG_INFO     DPFLTR_INFO_LEVEL
#define OVS_DBG_LOUD     (DPFLTR_INFO_LEVEL + 1)



VOID OvsLog(UINT32 level, UINT32 flag, CHAR *funcName,
            UINT32 line, CHAR *format, ...);


#define OVS_LOG_LOUD(_format, ...) \
   OvsLog(OVS_DBG_LOUD, OVS_DBG_MOD, __FUNCTION__, __LINE__, _format,  __VA_ARGS__)

#define OVS_LOG_INFO(_format, ...) \
   OvsLog(OVS_DBG_INFO, OVS_DBG_MOD, __FUNCTION__, __LINE__, _format, __VA_ARGS__)

#define OVS_LOG_TRACE(_format, ...) \
   OvsLog(OVS_DBG_TRACE, OVS_DBG_MOD, __FUNCTION__, __LINE__, _format, __VA_ARGS__)

#define OVS_LOG_ERROR(_format, ...) \
   OvsLog(OVS_DBG_ERROR, OVS_DBG_MOD, __FUNCTION__, __LINE__, _format, __VA_ARGS__)

#define OVS_LOG_WARN(_format, ...) \
   OvsLog(OVS_DBG_WARN, OVS_DBG_MOD, __FUNCTION__, __LINE__, _format, __VA_ARGS__)

#if DBG
#define OVS_VERIFY_IRQL(_x)  \
    if (KeGetCurrentIrql() != (KIRQL)_x) { \
        OVS_LOG_WARN("expected IRQL %u, actual IRQL: %u", \
                     _x, KeGetCurrentIrql()); \
    }

#define OVS_VERIFY_IRQL_LE(_x)  \
    if (KeGetCurrentIrql() > (KIRQL)_x) { \
        OVS_LOG_WARN("expected IRQL <= %u, actual IRQL: %u", \
                     _x, KeGetCurrentIrql()); \
    }

#else
#define OVS_VERIFY_IRQL(_x)
#define OVS_VERIFY_IRQL_LE(_x)
#endif

#endif /* __DEBUG_H_ */
