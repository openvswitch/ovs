/*
 * Copyright (c) 2013, 2014 Alexandru Copot <alex.mihai.c@gmail.com>, with support from IXIA.
 * Copyright (c) 2013, 2014 Daniel Baluta <dbaluta@ixiacom.com>
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

#ifndef BUNDLES_H
#define BUNDLES_H 1

#include <sys/types.h>

#include "ofp-msgs.h"
#include "connmgr.h"
#include "ofp-util.h"

#ifdef  __cplusplus
extern "C" {
#endif


enum ofperr ofp_bundle_open(struct ofconn *ofconn, uint32_t id, uint16_t flags);

enum ofperr ofp_bundle_close(struct ofconn *ofconn, uint32_t id, uint16_t flags);

enum ofperr ofp_bundle_commit(struct ofconn *ofconn, uint32_t id, uint16_t flags);

enum ofperr ofp_bundle_discard(struct ofconn *ofconn, uint32_t id);

enum ofperr ofp_bundle_add_message(struct ofconn *ofconn,
                                   struct ofputil_bundle_add_msg *badd);

void ofp_bundle_remove_all(struct ofconn *ofconn);

#ifdef  __cplusplus
}
#endif

#endif
