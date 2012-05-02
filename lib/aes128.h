/*
 * Copyright (c) 2009 Nicira, Inc.
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

/*
 * Based on rijndael.txt by Philip J. Erdelsky, downloaded from
 * http://www.efgh.com/software/rijndael.htm on September 24, 2009.  The
 * license information there is: "Public domain; no restrictions on use."
 * The Apache license above applies only to Nicira's modifications to the
 * original code.
 */

#ifndef AES128_H
#define AES128_H

#include <stdint.h>

struct aes128 {
    uint32_t rk[128/8 + 28];
};

void aes128_schedule(struct aes128 *, const uint8_t key[16]);
void aes128_encrypt(const struct aes128 *, const void *, void *);

#endif  /* aes128.h */
