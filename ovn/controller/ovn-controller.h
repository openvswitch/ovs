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


#ifndef OVN_CONTROLLER_H
#define OVN_CONTROLLER_H 1

struct controller_ctx {
    char *chassis_name;             /* Name for this chassis. */
    const char *br_int_name;        /* Name of local integration bridge. */
    struct ovsdb_idl *ovnsb_idl;
    struct ovsdb_idl *ovs_idl;

    const struct ovsrec_bridge *br_int;
};

#endif /* ovn/ovn-controller.h */
