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

#include "unicode.h"

#include <inttypes.h>

#include "openvswitch/dynamic-string.h"
#include "util.h"

/* Returns the unicode code point corresponding to leading surrogate 'leading'
 * and trailing surrogate 'trailing'.  The return value will not make any
 * sense if 'leading' or 'trailing' are not in the correct ranges for leading
 * or trailing surrogates. */
int
utf16_decode_surrogate_pair(int leading, int trailing)
{
    /*
     *  Leading surrogate:         110110wwwwxxxxxx
     * Trailing surrogate:         110111xxxxxxxxxx
     *         Code point: 000uuuuuxxxxxxxxxxxxxxxx
     */
    int w = (leading >> 6) & 0xf;
    int u = w + 1;
    int x0 = leading & 0x3f;
    int x1 = trailing & 0x3ff;
    return (u << 16) | (x0 << 10) | x1;
}

/* Returns the number of Unicode characters in UTF-8 string 's'. */
size_t
utf8_length(const char *s_)
{
    const uint8_t *s;
    size_t length;

    length = 0;
    for (s = (const uint8_t *) s_; *s != '\0'; s++) {
        /* The most-significant bits of the first byte in a character are one
         * of 2#01, 2#00, or 2#11.  2#10 is a continuation byte. */
        length += (*s & 0xc0) != 0x80;
    }
    return length;
}

static char *
invalid_utf8_sequence(const uint8_t *s, int n, size_t *lengthp)
{
    struct ds msg;
    int i;

    if (lengthp) {
        *lengthp = 0;
    }

    ds_init(&msg);
    ds_put_cstr(&msg, "invalid UTF-8 sequence");
    for (i = 0; i < n; i++) {
        ds_put_format(&msg, " 0x%02"PRIx8, s[i]);
    }
    return ds_steal_cstr(&msg);
}

struct utf8_sequence {
    uint8_t octets[5][2];
};

static const struct utf8_sequence *
lookup_utf8_sequence(uint8_t c)
{
    static const struct utf8_sequence seqs[] = {
        { { { 0x01, 0x7f },
            { 0, 0 }, { 0, 0 }, { 0, 0 }, { 0, 0 } } },

        { { { 0xc2, 0xdf }, { 0x80, 0xbf },
            { 0, 0 }, { 0, 0 }, { 0, 0 } } },

        { { { 0xe0, 0xe0 }, { 0xa0, 0xbf }, { 0x80, 0xbf },
            {0,0}, {0, 0 } } },

        { { { 0xe1, 0xec }, { 0x80, 0xbf }, { 0x80, 0xbf },
            { 0, 0 }, { 0, 0 } } },

        { { { 0xed, 0xed }, { 0x80, 0x9f }, { 0x80, 0xbf },
            { 0, 0 }, { 0, 0 } } },

        { { { 0xee, 0xef }, { 0x80, 0xbf }, { 0x80, 0xbf },
            { 0, 0 }, { 0, 0 } } },

        { { { 0xf0, 0xf0 }, { 0x90, 0xbf }, { 0x80, 0xbf }, { 0x80, 0xbf },
            { 0, 0 } } },

        { { { 0xf1, 0xf3 }, { 0x80, 0xbf }, { 0x80, 0xbf }, { 0x80, 0xbf },
            { 0, 0 } } },

        { { { 0xf4, 0xf4 }, { 0x80, 0x8f }, { 0x80, 0xbf }, { 0x80, 0xbf },
            { 0, 0 } } },
    };

    size_t i;

    for (i = 0; i < ARRAY_SIZE(seqs); i++) {
        const uint8_t *o = seqs[i].octets[0];
        if (c >= o[0] && c <= o[1]) {
            return &seqs[i];
        }
    }
    return NULL;
}

/* Checks that 's' is a valid, null-terminated UTF-8 string.  If so, returns a
 * null pointer and sets '*lengthp' to the number of Unicode characters in
 * 's'.  If not, returns an error message that the caller must free and sets
 * '*lengthp' to 0.
 *
 * 'lengthp' may be NULL if the length is not needed. */
char *
utf8_validate(const char *s_, size_t *lengthp)
{
    size_t length = 0;
    const uint8_t *s;

    for (s = (const uint8_t *) s_; *s != '\0'; ) {
        length++;
        if (s[0] < 0x80) {
            s++;
        } else {
            const struct utf8_sequence *seq;
            int i;

            seq = lookup_utf8_sequence(s[0]);
            if (!seq) {
                return invalid_utf8_sequence(s, 1, lengthp);
            }

            for (i = 1; seq->octets[i][0]; i++) {
                const uint8_t *o = seq->octets[i];
                if (s[i] < o[0] || s[i] > o[1]) {
                    return invalid_utf8_sequence(s, i + 1, lengthp);
                }
            }
            s += i;
        }
    }
    if (lengthp) {
        *lengthp = length;
    }
    return NULL;
}
