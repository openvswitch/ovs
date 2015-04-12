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

#ifndef __UTIL_H_
#define __UTIL_H_ 1

#define OVS_MEMORY_TAG                  'TSVO'
#define OVS_FIX_SIZE_NBL_POOL_TAG       'FSVO'
#define OVS_VARIABLE_SIZE_NBL_POOL_TAG  'VSVO'
#define OVS_NBL_ONLY_POOL_TAG           'OSVO'
#define OVS_NET_BUFFER_POOL_TAG         'NSVO'
#define OVS_OTHER_POOL_TAG              'MSVO'
#define OVS_MDL_POOL_TAG                'BSVO'
#define OVS_DATAPATH_POOL_TAG           'DSVO'
#define OVS_EVENT_POOL_TAG              'ESVO'
#define OVS_FLOW_POOL_TAG               'LSVO'
#define OVS_VXLAN_POOL_TAG              'XSVO'
#define OVS_IPHELPER_POOL_TAG           'HSVO'
#define OVS_OID_POOL_TAG                'ASVO'
#define OVS_SWITCH_POOL_TAG             'SSVO'
#define OVS_USER_POOL_TAG               'USVO'
#define OVS_VPORT_POOL_TAG              'PSVO'

VOID *OvsAllocateMemory(size_t size);
VOID *OvsAllocateMemoryWithTag(size_t size, ULONG tag);
VOID *OvsAllocateAlignedMemory(size_t size, UINT16 align);
VOID OvsFreeMemory(VOID *ptr);
VOID OvsFreeMemoryWithTag(VOID *ptr, ULONG tag);
VOID OvsFreeAlignedMemory(VOID *ptr);

#define LIST_FORALL(_headPtr, _itemPtr) \
    for (_itemPtr = (_headPtr)->Flink;  \
         _itemPtr != _headPtr;          \
         _itemPtr = (_itemPtr)->Flink)

#define LIST_FORALL_SAFE(_headPtr, _itemPtr, _nextPtr)                \
    for (_itemPtr = (_headPtr)->Flink, _nextPtr = (_itemPtr)->Flink; \
         _itemPtr != _headPtr;                                       \
         _itemPtr = _nextPtr, _nextPtr = (_itemPtr)->Flink)

#define LIST_FORALL_REVERSE(_headPtr, _itemPtr) \
    for (_itemPtr = (_headPtr)->Blink;  \
         _itemPtr != _headPtr;          \
         _itemPtr = (_itemPtr)->Blink)

#define LIST_FORALL_REVERSE_SAFE(_headPtr, _itemPtr, _nextPtr)        \
    for (_itemPtr = (_headPtr)->Blink, _nextPtr = (_itemPtr)->Blink; \
         _itemPtr != _headPtr;                                       \
         _itemPtr = _nextPtr, _nextPtr = (_itemPtr)->Blink)

VOID OvsAppendList(PLIST_ENTRY dst, PLIST_ENTRY src);


#define MIN(_a, _b) (_a) > (_b) ? (_b) : (_a)
#define ARRAY_SIZE(_x)  ((sizeof(_x))/sizeof (_x)[0])
#define OVS_SWITCH_PORT_ID_INVALID  (NDIS_SWITCH_PORT_ID)(-1)

#ifndef htons
#define htons(_x)    _byteswap_ushort((USHORT)(_x))
#define ntohs(_x)    _byteswap_ushort((USHORT)(_x))
#define htonl(_x)    _byteswap_ulong((ULONG)(_x))
#define ntohl(_x)    _byteswap_ulong((ULONG)(_x))
#endif

#define OVS_INIT_OBJECT_HEADER(_obj, _type, _revision, _size) \
    {                                                         \
        PNDIS_OBJECT_HEADER hdrp = _obj;                      \
        hdrp->Type = _type;                                   \
        hdrp->Revision = _revision;                           \
        hdrp->Size = _size;                                   \
    }


#define BIT16(_x)                       ((UINT16)0x1 << (_x))
#define BIT32(_x)                       ((UINT32)0x1 << (_x))

BOOLEAN OvsCompareString(PVOID string1, PVOID string2);

#endif /* __UTIL_H_ */
