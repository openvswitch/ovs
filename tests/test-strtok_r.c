/*
 * Copyright (c) 2010 Nicira, Inc.
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
#include <stdio.h>
#include <string.h>

/* Some versions of glibc 2.7 has a bug in strtok_r when with optimization that
 * can cause segfaults:
 *      http://sources.redhat.com/bugzilla/show_bug.cgi?id=5614.
 *
 * Open vSwitch works around this problem by supplying a replacement string.h.
 * This test program verifies that the workaround is in place.
 */
int
main(void)
{
    char string[] = ":::";
    char *save_ptr = (char *) 0xc0ffee;
    char *token1, *token2;
    token1 = strtok_r(string, ":", &save_ptr);
    token2 = strtok_r(NULL, ":", &save_ptr);
    printf ("%s %s\n", token1 ? token1 : "NULL", token2 ? token2 : "NULL");
    return 0;
}
