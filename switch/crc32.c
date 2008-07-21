/* Copyright (c) 2008 The Board of Trustees of The Leland Stanford
 * Junior University
 * 
 * We are making the OpenFlow specification and associated documentation
 * (Software) available for public use and benefit with the expectation
 * that others will use, modify and enhance the Software and contribute
 * those enhancements back to the community. However, since we would
 * like to make the Software available for broadest use, with as few
 * restrictions as possible permission is hereby granted, free of
 * charge, to any person obtaining a copy of this Software to deal in
 * the Software under the copyrights without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 * 
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT.  IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 * 
 * The name and trademarks of copyright holder(s) may NOT be used in
 * advertising or publicity pertaining to the Software or any
 * derivatives without specific, written prior permission.
 */

#include <config.h>
#include "crc32.h"

void
crc32_init(struct crc32 *crc, unsigned int polynomial)
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

unsigned int
crc32_calculate(const struct crc32 *crc, const void *data_, size_t n_bytes)
{
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
