/*
 * Distributed under the terms of the GNU GPL version 2.
 * Copyright (c) 2007, 2008 The Board of Trustees of The Leland 
 * Stanford Junior University
 */

#include "crc32.h"

void crc32_init(struct crc32 *crc, unsigned int polynomial)
{
	int i;

	for (i = 0; i < CRC32_TABLE_SIZE; ++i) {
		unsigned int reg = i << 24;
		int j;
		for (j = 0; j < CRC32_TABLE_BITS; j++) {
			int topBit = (reg & 0x80000000) != 0;
			reg <<= 1;
			if (topBit)
				reg ^= polynomial;
			}
			crc->table[i] = reg;
	}
}

unsigned int crc32_calculate(const struct crc32 *crc,
			const void *data_, size_t n_bytes)
{
	// FIXME: this can be optimized by unrolling, see linux-2.6/lib/crc32.c.
	const uint8_t *data = data_;
	unsigned int result = 0;
	size_t i;

	for (i = 0; i < n_bytes; i++) {
		unsigned int top = result >> 24;
		top ^= data[i];
		result = (result << 8) ^ crc->table[top];
	}
	return result;
}
