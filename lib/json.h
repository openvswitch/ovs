/*
 * Copyright (c) 2024 Canonical Ltd.
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

#ifndef JSON_H
#define JSON_H 1

#include "openvswitch/json.h"

static inline void
json_destroy_with_yield(struct json *json)
{
    if (json && !--json->count) {
        json_destroy__(json, true);
    }
}

struct json *json_serialized_object_create_with_yield(const struct json *);

#endif /* JSON_H */
