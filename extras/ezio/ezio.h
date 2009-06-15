/* Copyright (c) 2008, 2009 Nicira Networks, Inc.
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

#ifndef EZIO_H
#define EZIO_H 1

#include <stdbool.h>
#include <stdint.h>

/* Constants for visual representation of a row in an EZIO icon. */
#define e_____ 0x00
#define e____X 0x01
#define e___X_ 0x02
#define e___XX 0x03
#define e__X__ 0x04
#define e__X_X 0x05
#define e__XX_ 0x06
#define e__XXX 0x07
#define e_X___ 0x08
#define e_X__X 0x09
#define e_X_X_ 0x0a
#define e_X_XX 0x0b
#define e_XX__ 0x0c
#define e_XX_X 0x0d
#define e_XXX_ 0x0e
#define e_XXXX 0x0f
#define eX____ 0x10
#define eX___X 0x11
#define eX__X_ 0x12
#define eX__XX 0x13
#define eX_X__ 0x14
#define eX_X_X 0x15
#define eX_XX_ 0x16
#define eX_XXX 0x17
#define eXX___ 0x18
#define eXX__X 0x19
#define eXX_X_ 0x1a
#define eXX_XX 0x1b
#define eXXX__ 0x1c
#define eXXX_X 0x1d
#define eXXXX_ 0x1e
#define eXXXXX 0x1f

struct ezio {
    uint8_t icons[8][8];
    uint8_t chars[2][40];
    int x, y, x_ofs;
    bool show_cursor;
    bool blink_cursor;
};

void ezio_init(struct ezio *);
void ezio_set_icon(struct ezio *, int idx,
                   int row0, int row1, int row2, int row3,
                   int row4, int row5, int row6, int row7);
void ezio_set_default_icon(struct ezio *, int idx);
void ezio_clear(struct ezio *);
void ezio_put_char(struct ezio *, int x, int y, uint8_t c);
void ezio_line_feed(struct ezio *);
void ezio_newline(struct ezio *);
void ezio_delete_char(struct ezio *, int x, int y, int n);
void ezio_delete_line(struct ezio *, int y, int n);
void ezio_insert_char(struct ezio *, int x, int y, int n);
void ezio_insert_line(struct ezio *, int y, int n);
void ezio_scroll_left(struct ezio *, int n);
void ezio_scroll_right(struct ezio *, int n);
void ezio_scroll_up(struct ezio *, int n);
void ezio_scroll_down(struct ezio *, int n);
bool ezio_chars_differ(const struct ezio *, const struct ezio *,
                       int x0, int x1, int *xp, int *yp);

#endif /* ezio.h */
