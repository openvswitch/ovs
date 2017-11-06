/*
 * Copyright (c) 2008, 2009, 2010, 2011, 2013, 2015 Nicira, Inc.
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
#include "csum.h"
#include "unaligned.h"
#include <sys/types.h>
#include <netinet/in.h>

#ifndef __CHECKER__
/* Returns the IP checksum of the 'n' bytes in 'data'.
 *
 * The return value has the same endianness as the data.  That is, if 'data'
 * consists of a packet in network byte order, then the return value is a value
 * in network byte order, and if 'data' consists of a data structure in host
 * byte order, then the return value is in host byte order. */
ovs_be16
csum(const void *data, size_t n)
{
    return csum_finish(csum_continue(0, data, n));
}

/* Adds the 'n' bytes in 'data' to the partial IP checksum 'partial' and
 * returns the updated checksum.  (To start a new checksum, pass 0 for
 * 'partial'.  To obtain the finished checksum, pass the return value to
 * csum_finish().) */
uint32_t
csum_continue(uint32_t partial, const void *data_, size_t n)
{
    const ovs_be16 *data = data_;

    for (; n > 1; n -= 2, data++) {
        partial = csum_add16(partial, get_unaligned_be16(data));
    }
    if (n) {
#ifdef WORDS_BIGENDIAN
        partial += (*(uint8_t *) data) << 8;
#else
        partial += *(uint8_t *) data;
#endif
    }
    return partial;
}

/* Returns the IP checksum corresponding to 'partial', which is a value updated
 * by some combination of csum_add16(), csum_add32(), and csum_continue().
 *
 * The return value has the same endianness as the checksummed data.  That is,
 * if the data consist of a packet in network byte order, then the return value
 * is a value in network byte order, and if the data are a data structure in
 * host byte order, then the return value is in host byte order. */
ovs_be16
csum_finish(uint32_t partial)
{
    while (partial >> 16) {
        partial = (partial & 0xffff) + (partial >> 16);
    }
    return ~partial;
}

/* Returns the new checksum for a packet in which the checksum field previously
 * contained 'old_csum' and in which a field that contained 'old_u16' was
 * changed to contain 'new_u16'. */
ovs_be16
recalc_csum16(ovs_be16 old_csum, ovs_be16 old_u16, ovs_be16 new_u16)
{
    /* Ones-complement arithmetic is endian-independent, so this code does not
     * use htons() or ntohs().
     *
     * See RFC 1624 for formula and explanation. */
    uint16_t hc_complement = ~old_csum;
    uint16_t m_complement = ~old_u16;
    uint16_t m_prime = new_u16;
    uint32_t sum = hc_complement + m_complement + m_prime;
    return csum_finish(sum);
}

/* Returns the new checksum for a packet in which the checksum field previously
 * contained 'old_csum' and in which a field that contained 'old_u32' was
 * changed to contain 'new_u32'. */
ovs_be16
recalc_csum32(ovs_be16 old_csum, ovs_be32 old_u32, ovs_be32 new_u32)
{
    return recalc_csum16(recalc_csum16(old_csum, old_u32, new_u32),
                         old_u32 >> 16, new_u32 >> 16);
}

/* Returns the new checksum for a packet in which the checksum field previously
 * contained 'old_csum' and in which a field that contained the 6 bytes at
 * 'old_mac' was changed to contain the 6 bytes at 'new_mac'. */
ovs_be16
recalc_csum48(ovs_be16 old_csum, const struct eth_addr old_mac,
              const struct eth_addr new_mac)
{
    ovs_be16 new_csum = old_csum;

    for (int i = 0; i < 3; ++i) {
        new_csum = recalc_csum16(new_csum, old_mac.be16[i], new_mac.be16[i]);
    }

    return new_csum;
}

/* Returns the new checksum for a packet in which the checksum field previously
 * contained 'old_csum' and in which a field that contained 'old_u32[4]' was
 * changed to contain 'new_u32[4]'. */
ovs_be16
recalc_csum128(ovs_be16 old_csum, ovs_16aligned_be32 old_u32[4],
               const struct in6_addr *new_in6)
{
    ovs_be16 new_csum = old_csum;
#ifndef s6_addr32
    ovs_be32 new_u32[4];
    memcpy(new_u32, new_in6, sizeof new_u32);
#else
    const ovs_be32 *new_u32 = new_in6->s6_addr32;
#endif
    int i;

    for (i = 0; i < 4; ++i) {
        new_csum = recalc_csum32(new_csum,
                                 get_16aligned_be32(&old_u32[i]), new_u32[i]);
    }
    return new_csum;
}
#else  /* __CHECKER__ */
/* Making sparse happy with these functions also makes them unreadable, so
 * don't bother to show it their implementations. */
#endif
