#ifndef HASH_H
#define HASH_H 1

#include <stddef.h>
#include <stdint.h>

#define HASH_FNV_BASIS UINT32_C(2166136261)
#define HASH_FNV_PRIME UINT32_C(16777619)

uint32_t hash_fnv(const void *, size_t, uint32_t basis);

#endif /* hash.h */
