#ifndef MAC_H
#define MAC_H 1

#include <string.h>
#include <inttypes.h>
#include <stdbool.h>
#include "packets.h"

static inline bool mac_is_multicast(const uint8_t mac[ETH_ADDR_LEN])
{
    return mac[0] & 0x80;
}

static inline bool mac_is_private(const uint8_t mac[ETH_ADDR_LEN])
{
    return mac[0] & 0x40;
}

static inline bool mac_is_broadcast(const uint8_t mac[ETH_ADDR_LEN])
{
    return (mac[0] & mac[1] & mac[2] & mac[3] & mac[4] & mac[5]) == 0xff;
}

static inline bool mac_is_zero(const uint8_t mac[ETH_ADDR_LEN])
{
    return (mac[0] | mac[1] | mac[2] | mac[3] | mac[4] | mac[5]) == 0;
}

static inline bool mac_equals(const uint8_t a[ETH_ADDR_LEN],
                              const uint8_t b[ETH_ADDR_LEN]) 
{
    return !memcmp(a, b, ETH_ADDR_LEN);
}

#define MAC_FMT                                                         \
    "%02"PRIx8":%02"PRIx8":%02"PRIx8":%02"PRIx8":%02"PRIx8":%02"PRIx8
#define MAC_ARGS(mac)                                           \
    (mac)[0], (mac)[1], (mac)[2], (mac)[3], (mac)[4], (mac)[5]


#endif /* mac.h */
