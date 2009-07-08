/* Copyright (c) 2008, 2009 Nicira Networks, Inc.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 * In addition, as a special exception, Nicira Networks gives permission
 * to link the code of its release of vswitchd with the OpenSSL project's
 * "OpenSSL" library (or with modified versions of it that use the same
 * license as the "OpenSSL" library), and distribute the linked
 * executables.  You must obey the GNU General Public License in all
 * respects for all of the code used other than "OpenSSL".  If you modify
 * this file, you may extend this exception to your version of the file,
 * but you are not obligated to do so.  If you do not wish to do so,
 * delete this exception statement from your version.
 *
 */

#include <config.h>
#include "ezio.h"
#include <assert.h>
#include <stddef.h>
#include <string.h>
#include "util.h"

static void remove_elements(uint8_t *p, size_t n_elems, size_t elem_size,
                            int pos, int n_del);
static void insert_elements(uint8_t *p, size_t n_elems, size_t elem_size,
                            int pos, int n_insert);
static int range(int value, int min, int max);

void
ezio_init(struct ezio *e)
{
    memset(e->icons, 0, sizeof e->icons);
    ezio_clear(e);
    e->x_ofs = 0;
    e->show_cursor = true;
    e->blink_cursor = false;
}

void
ezio_set_icon(struct ezio *e, int idx,
              int row0, int row1, int row2, int row3,
              int row4, int row5, int row6, int row7)
{
    e->icons[idx][0] = row0;
    e->icons[idx][1] = row1;
    e->icons[idx][2] = row2;
    e->icons[idx][3] = row3;
    e->icons[idx][4] = row4;
    e->icons[idx][5] = row5;
    e->icons[idx][6] = row6;
    e->icons[idx][7] = row7;
}

void
ezio_set_default_icon(struct ezio *e, int idx)
{
    uint8_t *icon;

    assert(idx >= 0 && idx < 8);
    icon = e->icons[idx];
    if (idx == 6) {
        ezio_set_icon(e, idx,
                      e_____,
                      eX____,
                      e_X___,
                      e__X__,
                      e___X_,
                      e____X,
                      e_____,
                      e_____);
    } else if (idx == 7) {
        ezio_set_icon(e, idx,
                      e_____,
                      e_____,
                      e_X___,
                      eX_X_X,
                      eX_X_X,
                      e___X_,
                      e_____,
                      e_____);
    } else {
        ezio_set_icon(e, idx,
                      e_____,
                      e_____,
                      e_____,
                      e_____,
                      e_____,
                      e_____,
                      e_____,
                      e_____);
    }
}

void
ezio_clear(struct ezio *e)
{
    memset(e->chars, ' ', sizeof e->chars);
    e->x = e->y = 0;
}

void
ezio_put_char(struct ezio *e, int x, int y, uint8_t c)
{
    assert(x >= 0 && x <= 39);
    assert(y >= 0 && y <= 1);
    e->chars[y][x] = c != 0xfe ? c : 0xff;
}

void
ezio_line_feed(struct ezio *e)
{
    if (++e->y >= 2) {
        e->y = 1;
        ezio_scroll_up(e, 1);
    }
}

void
ezio_newline(struct ezio *e)
{
    e->x = 0;
    ezio_line_feed(e);
}

void
ezio_delete_char(struct ezio *e, int x, int y, int n)
{
    remove_elements(&e->chars[y][0], 40, 1, x, n);
}

void
ezio_delete_line(struct ezio *e, int y, int n)
{
    remove_elements(e->chars[0], 2, 40, y, n);
}

void
ezio_insert_char(struct ezio *e, int x, int y, int n)
{
    insert_elements(&e->chars[y][0], 40, 1, x, n);
}

void
ezio_insert_line(struct ezio *e, int y, int n)
{
    insert_elements(&e->chars[0][0], 2, 40, y, n);
}

void
ezio_scroll_left(struct ezio *e, int n)
{
    int y;
    for (y = 0; y < 2; y++) {
        ezio_delete_char(e, 0, y, n);
    }
}

void
ezio_scroll_right(struct ezio *e, int n)
{
    int y;

    for (y = 0; y < 2; y++) {
        ezio_insert_char(e, 0, y, n);
    }
}

void
ezio_scroll_up(struct ezio *e, int n)
{
    ezio_delete_line(e, 0, n);
}

void
ezio_scroll_down(struct ezio *e, int n)
{
    ezio_insert_line(e, 0, n);
}

bool
ezio_chars_differ(const struct ezio *a, const struct ezio *b, int x0, int x1,
                  int *xp, int *yp)
{
    int x, y;

    x0 = range(x0, 0, 39);
    x1 = range(x1, 1, 40);
    for (y = 0; y < 2; y++) {
        for (x = x0; x < x1; x++) {
            if (a->chars[y][x] != b->chars[y][x]) {
                *xp = x;
                *yp = y;
                return true;
            }
        }
    }
    return false;
}

static void
remove_elements(uint8_t *p, size_t n_elems, size_t elem_size,
                int pos, int n_del)
{
    if (pos >= 0 && pos < n_elems) {
        n_del = MIN(n_del, n_elems - pos);
        memmove(p + elem_size * pos,
                p + elem_size * (pos + n_del),
                elem_size * (n_elems - pos - n_del));
        memset(p + elem_size * (n_elems - n_del), ' ', n_del * elem_size);
    }
}

static void
insert_elements(uint8_t *p, size_t n_elems, size_t elem_size,
                int pos, int n_insert)
{
    if (pos >= 0 && pos < n_elems) {
        n_insert = MIN(n_insert, n_elems - pos);
        memmove(p + elem_size * (pos + n_insert),
                p + elem_size * pos,
                elem_size * (n_elems - pos - n_insert));
        memset(p + elem_size * pos, ' ', n_insert * elem_size);
    }
}

static int
range(int value, int min, int max)
{
    return value < min ? min : value > max ? max : value;
}

