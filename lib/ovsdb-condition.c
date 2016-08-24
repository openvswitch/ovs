/* Copyright (c) 2009, 2010, 2011, 2012, 2013, 2014, 2015, 2016 Nicira, Inc.
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

#include <config.h>

#include <string.h>
#include "ovsdb-error.h"
#include "ovsdb-condition.h"

struct ovsdb_error *
ovsdb_function_from_string(const char *name, enum ovsdb_function *function)
{
#define OVSDB_FUNCTION(ENUM, NAME)              \
    if (!strcmp(name, NAME)) {                  \
        *function = ENUM;                       \
        return NULL;                            \
    }
    OVSDB_FUNCTIONS;
#undef OVSDB_FUNCTION

    return ovsdb_syntax_error(NULL, "unknown function",
                              "No function named %s.", name);
}

const char *
ovsdb_function_to_string(enum ovsdb_function function)
{
    switch (function) {
#define OVSDB_FUNCTION(ENUM, NAME) case ENUM: return NAME;
        OVSDB_FUNCTIONS;
#undef OVSDB_FUNCTION
    }

    return NULL;
}
