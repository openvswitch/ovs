/*
 * Copyright (c) 2014, 2015 Nicira, Inc.
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

#ifndef OFP_PROP_H
#define OFP_PROP_H 1

/* OpenFlow 1.3+ property support
 * ==============================
 *
 * Several OpenFlow 1.3+ messages use properties that take the common form
 * shown by "struct ofp_prop_header".  This module provides support for
 * serializing and deserializing properties in this format.
 */

#include <stddef.h>
#include <stdint.h>
#include "ofp-errors.h"
#include "openvswitch/types.h"

struct ofpbuf;

/* Deserializing properties.  */
enum ofperr ofpprop_pull__(struct ofpbuf *msg, struct ofpbuf *property,
                           unsigned int alignment, uint16_t *typep);
enum ofperr ofpprop_pull(struct ofpbuf *msg, struct ofpbuf *property,
                         uint16_t *typep);

/* Serializing properties. */
void ofpprop_put(struct ofpbuf *, uint16_t type,
                 const void *value, size_t len);
void ofpprop_put_bitmap(struct ofpbuf *, uint16_t type, uint64_t bitmap);

size_t ofpprop_start(struct ofpbuf *, uint16_t type);
void ofpprop_end(struct ofpbuf *, size_t start_ofs);

/* Logging errors while deserializing properties.
 *
 * The attitude that a piece of code should take when it deserializes an
 * unknown property type depends on the code in question:
 *
 *    - In a "loose" context (with LOOSE set to true), that is, where the code
 *      is parsing the property to find out about the state or the capabilities
 *      of some piece of the system, generally an unknown property type is not
 *      a big deal, because it only means that there is additional information
 *      that the receiver does not understand.
 *
 *    - In a "strict" context (with LOOSE set to false), that is, where the
 *      code is parsing the property to change the state or configuration of a
 *      part of the system, generally an unknown property type is an error,
 *      because it means that the receiver is being asked to configure the
 *      system in some way it doesn't understand.
 *
 * Given LOOSE, this macro automatically logs chooses an appropriate log
 * level. */
#define OFPPROP_LOG(RL, LOOSE, ...)                         \
    VLOG_RL(RL, (LOOSE) ? VLL_DBG : VLL_WARN, __VA_ARGS__)

#endif /* ofp-prop.h */
