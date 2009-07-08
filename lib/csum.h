/*
 * Copyright (c) 2008 Nicira Networks.
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

#ifndef CSUM_H
#define CSUM_H 1

#include <stddef.h>
#include <stdint.h>

uint16_t csum(const void *, size_t);
uint32_t csum_add16(uint32_t partial, uint16_t);
uint32_t csum_add32(uint32_t partial, uint32_t);
uint32_t csum_continue(uint32_t partial, const void *, size_t);
uint16_t csum_finish(uint32_t partial);
uint16_t recalc_csum16(uint16_t old_csum, uint16_t old_u16, uint16_t new_u16);
uint16_t recalc_csum32(uint16_t old_csum, uint32_t old_u32, uint32_t new_u32);

#endif /* csum.h */
