/*
 * Copyright (c) 2015 Nicira, Inc.
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

#ifndef OVN_ACTIONS_H
#define OVN_ACTIONS_H 1

#include <stdint.h>
#include "compiler.h"

struct expr;
struct lexer;
struct ofpbuf;
struct shash;
struct simap;

char *actions_parse(struct lexer *, const struct shash *symtab,
                    const struct simap *ports, const struct simap *ct_zones,
                    uint8_t first_ptable, uint8_t n_tables, uint8_t cur_ltable,
                    uint8_t output_ptable, struct ofpbuf *ofpacts,
                    struct expr **prereqsp)
    OVS_WARN_UNUSED_RESULT;
char *actions_parse_string(const char *s, const struct shash *symtab,
                           const struct simap *ports,
                           const struct simap *ct_zones, uint8_t first_ptable,
                           uint8_t n_tables, uint8_t cur_ltable,
                           uint8_t output_ptable, struct ofpbuf *ofpacts,
                           struct expr **prereqsp)
    OVS_WARN_UNUSED_RESULT;

#endif /* ovn/actions.h */
