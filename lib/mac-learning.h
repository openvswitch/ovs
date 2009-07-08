/*
 * Copyright (c) 2008, 2009 Nicira Networks.
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#ifndef MAC_LEARNING_H
#define MAC_LEARNING_H 1

#include "packets.h"
#include "tag.h"

struct mac_learning *mac_learning_create(void);
void mac_learning_destroy(struct mac_learning *);
tag_type mac_learning_learn(struct mac_learning *,
                            const uint8_t src[ETH_ADDR_LEN], uint16_t vlan,
                            uint16_t src_port);
int mac_learning_lookup(const struct mac_learning *,
                        const uint8_t dst[ETH_ADDR_LEN], uint16_t vlan);
int mac_learning_lookup_tag(const struct mac_learning *,
                            const uint8_t dst[ETH_ADDR_LEN],
                            uint16_t vlan, tag_type *tag);
void mac_learning_flush(struct mac_learning *);
void mac_learning_run(struct mac_learning *, struct tag_set *);
void mac_learning_wait(struct mac_learning *);

#endif /* mac-learning.h */
