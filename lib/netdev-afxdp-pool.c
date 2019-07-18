/*
 * Copyright (c) 2018, 2019 Nicira, Inc.
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

#include "dp-packet.h"
#include "netdev-afxdp-pool.h"
#include "openvswitch/util.h"

/* Note:
 * umem_elem_push* shouldn't overflow because we always pop
 * elem first, then push back to the stack.
 */
static inline void
umem_elem_push_n__(struct umem_pool *umemp, int n, void **addrs)
{
    void *ptr;

    ovs_assert(umemp->index + n <= umemp->size);

    ptr = &umemp->array[umemp->index];
    memcpy(ptr, addrs, n * sizeof(void *));
    umemp->index += n;
}

void umem_elem_push_n(struct umem_pool *umemp, int n, void **addrs)
{
    ovs_spin_lock(&umemp->lock);
    umem_elem_push_n__(umemp, n, addrs);
    ovs_spin_unlock(&umemp->lock);
}

static inline void
umem_elem_push__(struct umem_pool *umemp, void *addr)
{
    ovs_assert(umemp->index + 1 <= umemp->size);

    umemp->array[umemp->index++] = addr;
}

void
umem_elem_push(struct umem_pool *umemp, void *addr)
{
    ovs_spin_lock(&umemp->lock);
    umem_elem_push__(umemp, addr);
    ovs_spin_unlock(&umemp->lock);
}

static inline int
umem_elem_pop_n__(struct umem_pool *umemp, int n, void **addrs)
{
    void *ptr;

    if (OVS_UNLIKELY(umemp->index - n < 0)) {
        return -ENOMEM;
    }

    umemp->index -= n;
    ptr = &umemp->array[umemp->index];
    memcpy(addrs, ptr, n * sizeof(void *));

    return 0;
}

int
umem_elem_pop_n(struct umem_pool *umemp, int n, void **addrs)
{
    int ret;

    ovs_spin_lock(&umemp->lock);
    ret = umem_elem_pop_n__(umemp, n, addrs);
    ovs_spin_unlock(&umemp->lock);

    return ret;
}

static inline void *
umem_elem_pop__(struct umem_pool *umemp)
{
    if (OVS_UNLIKELY(umemp->index - 1 < 0)) {
        return NULL;
    }

    return umemp->array[--umemp->index];
}

void *
umem_elem_pop(struct umem_pool *umemp)
{
    void *ptr;

    ovs_spin_lock(&umemp->lock);
    ptr = umem_elem_pop__(umemp);
    ovs_spin_unlock(&umemp->lock);

    return ptr;
}

static void **
umem_pool_alloc__(unsigned int size)
{
    void **bufs;

    bufs = xmalloc_pagealign(size * sizeof *bufs);
    memset(bufs, 0, size * sizeof *bufs);

    return bufs;
}

int
umem_pool_init(struct umem_pool *umemp, unsigned int size)
{
    umemp->array = umem_pool_alloc__(size);
    if (!umemp->array) {
        return -ENOMEM;
    }

    umemp->size = size;
    umemp->index = 0;
    ovs_spin_init(&umemp->lock);
    return 0;
}

void
umem_pool_cleanup(struct umem_pool *umemp)
{
    free_pagealign(umemp->array);
    umemp->array = NULL;
    ovs_spin_destroy(&umemp->lock);
}

unsigned int
umem_pool_count(struct umem_pool *umemp)
{
    return umemp->index;
}

/* AF_XDP metadata init/destroy. */
int
xpacket_pool_init(struct xpacket_pool *xp, unsigned int size)
{
    xp->array = xmalloc_pagealign(size * sizeof *xp->array);
    xp->size = size;

    memset(xp->array, 0, size * sizeof *xp->array);

    return 0;
}

void
xpacket_pool_cleanup(struct xpacket_pool *xp)
{
    free_pagealign(xp->array);
    xp->array = NULL;
}
