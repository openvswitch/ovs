/*
 * Copyright (c) 2008, 2009, 2010, 2011, 2013 Nicira, Inc.
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
#ifndef OPENVSWITCH_LIST_H
#define OPENVSWITCH_LIST_H 1

/* Doubly linked list head or element. */
struct ovs_list {
    struct ovs_list *prev;     /* Previous list element. */
    struct ovs_list *next;     /* Next list element. */
};

#define OVS_LIST_INITIALIZER(LIST) { LIST, LIST }

#endif /* list.h */
