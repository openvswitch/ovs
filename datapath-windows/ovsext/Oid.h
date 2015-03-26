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

#ifndef __OID_H_
#define __OID_H_ 1

NDIS_STATUS OvsQuerySwitchActivationComplete(POVS_SWITCH_CONTEXT switchContext,
                                             BOOLEAN *switchActive);
NDIS_STATUS OvsGetPortsOnSwitch(POVS_SWITCH_CONTEXT switchContext,
                                PNDIS_SWITCH_PORT_ARRAY *portArrayOut);
NDIS_STATUS OvsGetNicsOnSwitch(POVS_SWITCH_CONTEXT switchContext,
                               PNDIS_SWITCH_NIC_ARRAY *nicArrayOut);
VOID OvsFreeSwitchPortsArray(PNDIS_SWITCH_PORT_ARRAY portsArray);
VOID OvsFreeSwitchNicsArray(PNDIS_SWITCH_NIC_ARRAY nicsArray);

#endif /* __OID_H_ */
