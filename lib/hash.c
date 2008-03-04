#include "hash.h"

uint32_t
hash_fnv(const void *p_, size_t n, uint32_t basis)
{
    const uint8_t *p = p_;
    uint32_t hash = basis;
    while (n--) {
        hash *= HASH_FNV_PRIME;
        hash ^= *p++;
    }
    return hash;
}
