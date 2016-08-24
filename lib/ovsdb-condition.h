/* Copyright (c) 2009, 2010, 2011, 2012, 2013, 2014, 2015 Nicira, Inc.
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

#ifndef OVSDB_LIB_CONDITION_H
#define OVSDB_LIB_CONDITION_H 1

/* These list is ordered first with boolean functions and then in
 * ascending order of the fraction of tables row that they are
 * (heuristically) expected to leave in query results. */
#define OVSDB_FUNCTIONS                         \
    OVSDB_FUNCTION(OVSDB_F_FALSE, "false")            \
    OVSDB_FUNCTION(OVSDB_F_TRUE, "true")              \
    OVSDB_FUNCTION(OVSDB_F_EQ, "==")                  \
    OVSDB_FUNCTION(OVSDB_F_INCLUDES, "includes")      \
    OVSDB_FUNCTION(OVSDB_F_LE, "<=")                  \
    OVSDB_FUNCTION(OVSDB_F_LT, "<")                   \
    OVSDB_FUNCTION(OVSDB_F_GE, ">=")                  \
    OVSDB_FUNCTION(OVSDB_F_GT, ">")                   \
    OVSDB_FUNCTION(OVSDB_F_EXCLUDES, "excludes")      \
    OVSDB_FUNCTION(OVSDB_F_NE, "!=")

enum ovsdb_function {
#define OVSDB_FUNCTION(ENUM, NAME) ENUM,
    OVSDB_FUNCTIONS
#undef OVSDB_FUNCTION
    OVSDB_F_LAST = OVSDB_F_NE
};

struct ovsdb_error * ovsdb_function_from_string(const char *name,
                                                enum ovsdb_function *function);
const char * ovsdb_function_to_string(enum ovsdb_function function);

#endif /* ovsdb-condition.h */
