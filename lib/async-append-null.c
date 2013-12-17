/* Copyright (c) 2013 Nicira, Inc.
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

/* This is a null implementation of the asynchronous I/O interface for systems
 * that don't have a form of asynchronous I/O. */

#include "async-append.h"

#include <stdlib.h>
#include <unistd.h>

#include "util.h"

struct async_append *
async_append_create(int fd OVS_UNUSED)
{
    return NULL;
}

void
async_append_destroy(struct async_append *ap)
{
    ovs_assert(ap == NULL);
}

void
async_append_write(struct async_append *ap OVS_UNUSED,
                   const void *data OVS_UNUSED, size_t size OVS_UNUSED)
{
    OVS_NOT_REACHED();
}

void
async_append_flush(struct async_append *ap OVS_UNUSED)
{
    OVS_NOT_REACHED();
}
