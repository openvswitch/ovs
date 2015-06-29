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

#ifndef __TUNNEL_H_
#define __TUNNEL_H_ 1

//
// OVS_TUNNEL_PENDED_PACKET is the object type we used to store all information
// needed for out-of-band packet modification and re-injection. This type
// also points back to the flow context the packet belongs to.

typedef struct OVS_TUNNEL_PENDED_PACKET_
{
   /* Common fields for inbound and outbound traffic */
   NET_BUFFER_LIST *netBufferList;

   UINT32 ipHeaderSize;
   UINT32 transportHeaderSize;
   FWPS_CLASSIFY_OUT *classifyOut;
} OVS_TUNNEL_PENDED_PACKET;

//
// Shared function prototypes
//
VOID OvsTunnelClassify(const FWPS_INCOMING_VALUES *inFixedValues,
                       const FWPS_INCOMING_METADATA_VALUES *inMetaValues,
                       VOID *layerData,
                       const VOID *classifyContext,
                       const FWPS_FILTER *filter,
                       UINT64 flowContext,
                       FWPS_CLASSIFY_OUT *classifyOut);


NTSTATUS OvsTunnelNotify(FWPS_CALLOUT_NOTIFY_TYPE notifyType,
                         const GUID *filterKey,
                         const FWPS_FILTER *filter);

#endif /* __TUNNEL_H_ */
