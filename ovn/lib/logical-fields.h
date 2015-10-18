/* Copyright (c) 2015 Nicira, Inc.
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

#ifndef OVN_LOGICAL_FIELDS_H
#define OVN_LOGICAL_FIELDS_H 1

#include "meta-flow.h"

/* Logical fields.
 *
 * These values are documented in ovn-architecture(7), please update the
 * documentation if you change any of them. */
#define MFF_LOG_DATAPATH MFF_METADATA /* Logical datapath (64 bits). */
#define MFF_LOG_CT_ZONE  MFF_REG5     /* Logical conntrack zone (32 bits). */
#define MFF_LOG_INPORT   MFF_REG6     /* Logical input port (32 bits). */
#define MFF_LOG_OUTPORT  MFF_REG7     /* Logical output port (32 bits). */

/* Logical registers.
 *
 * Make sure these don't overlap with the logical fields! */
#define MFF_LOG_REGS \
    MFF_LOG_REG(MFF_REG0) \
    MFF_LOG_REG(MFF_REG1) \
    MFF_LOG_REG(MFF_REG2) \
    MFF_LOG_REG(MFF_REG3) \
    MFF_LOG_REG(MFF_REG4)

#endif /* ovn/lib/logical-fields.h */
