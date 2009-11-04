/*
 * Copyright (c) 2009 Nicira Networks.
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
