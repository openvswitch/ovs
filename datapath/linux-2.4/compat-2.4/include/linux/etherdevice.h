#ifndef __LINUX_ETHERDEVICE_WRAPPER_H
#define __LINUX_ETHERDEVICE_WRAPPER_H 1

#include_next <linux/etherdevice.h>
#include <linux/random.h>

/**
 * is_multicast_ether_addr - Determine if the Ethernet address is a multicast.
 * @addr: Pointer to a six-byte array containing the Ethernet address
 *
 * Return true if the address is a multicast address.
 * By definition the broadcast address is also a multicast address.
 */
static inline int is_multicast_ether_addr(const u8 *addr)
{
    return (0x01 & addr[0]);
}

/**
 * is_local_ether_addr - Determine if the Ethernet address is locally-assigned
 * one (IEEE 802).
 * @addr: Pointer to a six-byte array containing the Ethernet address
 *
 * Return true if the address is a local address.
 */
static inline int is_local_ether_addr(const u8 *addr)
{
    return (0x02 & addr[0]);
}

/**
 * is_broadcast_ether_addr - Determine if the Ethernet address is broadcast
 * @addr: Pointer to a six-byte array containing the Ethernet address
 *
 * Return true if the address is the broadcast address.
 */
static inline int is_broadcast_ether_addr(const u8 *addr)
{
    return (addr[0] & addr[1] & addr[2] & addr[3] & addr[4] & addr[5]) == 0xff;
}

/**
 * random_ether_addr - Generate software assigned random Ethernet address
 * @addr: Pointer to a six-byte array containing the Ethernet address
 *
 * Generate a random Ethernet address (MAC) that is not multicast
 * and has the local assigned bit set.
 */
static inline void random_ether_addr(u8 *addr)
{
	get_random_bytes (addr, ETH_ALEN);
	addr [0] &= 0xfe;	/* clear multicast bit */
	addr [0] |= 0x02;	/* set local assignment bit (IEEE802) */
}

/**
 * compare_ether_addr - Compare two Ethernet addresses
 * @addr1: Pointer to a six-byte array containing the Ethernet address
 * @addr2: Pointer other six-byte array containing the Ethernet address
 *
 * Compare two ethernet addresses, returns 0 if equal
 */
static inline unsigned compare_ether_addr(const u8 *addr1, const u8 *addr2)
{
    const u16 *a = (const u16 *) addr1;
    const u16 *b = (const u16 *) addr2;

    return ((a[0] ^ b[0]) | (a[1] ^ b[1]) | (a[2] ^ b[2])) != 0;
}

#endif
