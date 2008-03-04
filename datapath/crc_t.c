/*
 * Distributed under the terms of the GNU GPL version 2.
 * Copyright (c) 2007 The Board of Trustees of The Leland Stanford Junior Univer
sity
 */

#include <linux/string.h>
#include <linux/kernel.h>

#include "crc32.h"
#include "unit.h"


static void
print_error(unsigned int poly, char *data,
			unsigned int expected, unsigned int calculated)
{
	unit_fail("crc error: poly=%x data=%s expected=%x calculated=%x\n",
				poly, data, expected, calculated);
}

void
run_crc_t(void)
{
	struct crc32 crc;
	unsigned int val, i, j;

	char *data[3] = { "h3rei$@neX@mp13da7@sTr117G0fCH@r$",
				"1324lkqasdf0-[LKJD0;asd,.cv;/asd0:\"'~`co29",
				"6" };

	unsigned int polys[2] = { 0x04C11DB7,
				0x1EDC6F41 };

	unsigned int crc_values[2][3] = { 
				{ 0xDE1040C3, 0x65343A0B, 0xCEB42022 },
				{ 0x6C149FAE, 0x470A6B73, 0x4D3AA134 } };
	for (i = 0; i < 2; i++) {
		crc32_init(&crc, polys[i]);
		for (j = 0; j < 3; j++) {
			val = crc32_calculate(&crc, data[j], strlen(data[j]));
			if (val != crc_values[i][j]) {
				print_error(polys[i], data[j], crc_values[i][j], val);
			}
		}
	}
}
