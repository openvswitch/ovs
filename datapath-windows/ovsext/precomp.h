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

#include <ndis.h>
#include <netiodef.h>
#include <intsafe.h>
#include <ntintsafe.h>
#include <ntstrsafe.h>
#include <Strsafe.h>

#include "OvsTypes.h"
#include "..\include\OvsPub.h"
#include "OvsUtil.h"
/*
 * Include openvswitch.h from userspace. Changing the location the file from
 * include/linux is pending discussion.
 */
#include "..\include\OvsDpInterface.h"
