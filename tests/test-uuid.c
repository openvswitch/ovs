/*
 * Copyright (c) 2009, 2014 Nicira, Inc.
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
#include "uuid.h"
#include <stdio.h>
#include "ovstest.h"

static void
test_uuid_main(int argc, char *argv[])
{
    struct uuid uuid;

    if (argc == 1) {
        uuid_generate(&uuid);
    } else if (argc == 2) {
        if (!uuid_from_string(&uuid, argv[1])) {
            ovs_fatal(0, "\"%s\" is not a valid UUID", argv[1]);
        }
    } else {
        ovs_fatal(0, "usage: %s [UUID]", argv[0]);
    }

    printf(UUID_FMT"\n", UUID_ARGS(&uuid));
}

OVSTEST_REGISTER("test-uuid", test_uuid_main);
