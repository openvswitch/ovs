/*
 * Copyright (c) 2009, 2010 Nicira, Inc.
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
#include <ctype.h>
#include "aes128.h"
#include "util.h"

static void
hex_to_uint8(const char *input, uint8_t *output, size_t n)
{
    size_t i;

    if (strlen(input) != n * 2) {
        goto error;
    }
    for (i = 0; i < n; i++) {
        bool ok;

        output[i] = hexits_value(&input[i * 2], 2, &ok);
        if (!ok) {
            goto error;
        }
    }
    return;

error:
    ovs_fatal(0, "\"%s\" is not exactly %zu hex digits", input, n * 2);
}

int
main(int argc, char *argv[])
{
    struct aes128 aes;
    uint8_t plaintext[16];
    uint8_t ciphertext[16];
    uint8_t key[16];
    size_t i;

    if (argc != 3) {
        ovs_fatal(0, "usage: %s KEY PLAINTEXT, where KEY and PLAINTEXT each "
                  "consist of 32 hex digits", argv[0]);
    }

    hex_to_uint8(argv[1], key, 16);
    hex_to_uint8(argv[2], plaintext, 16);

    aes128_schedule(&aes, key);
    aes128_encrypt(&aes, plaintext, ciphertext);
    for (i = 0; i < 16; i++) {
        printf("%02x", ciphertext[i]);
    }
    putchar('\n');

    return 0;
}
