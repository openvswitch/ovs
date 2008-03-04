#ifndef CRC32_H
#define CRC32_H 1

#include <linux/types.h>
#ifndef __KERNEL__
#include <stdint.h>
#endif
#include <stddef.h>

#define CRC32_TABLE_BITS 8
#define CRC32_TABLE_SIZE (1u << CRC32_TABLE_BITS)

struct crc32 {
		unsigned int table[CRC32_TABLE_SIZE];
};

void crc32_init(struct crc32 *, unsigned int polynomial);
unsigned int crc32_calculate(const struct crc32 *,
							 const void *data_, size_t n_bytes);


#endif /* crc32.h */
