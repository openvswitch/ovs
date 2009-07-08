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

#ifndef BYTEQ_H
#define BYTEQ_H 1

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* Maximum number of bytes in a byteq. */
#define BYTEQ_SIZE 512

/* General-purpose circular queue of bytes. */
struct byteq {
    uint8_t buffer[BYTEQ_SIZE]; /* Circular queue. */
    unsigned int head;          /* Head of queue. */
    unsigned int tail;          /* Chases the head. */
};

void byteq_init(struct byteq *);
int byteq_used(const struct byteq *);
int byteq_avail(const struct byteq *);
bool byteq_is_empty(const struct byteq *);
bool byteq_is_full(const struct byteq *);
void byteq_put(struct byteq *, uint8_t c);
void byteq_putn(struct byteq *, const void *, size_t n);
void byteq_put_string(struct byteq *, const char *);
uint8_t byteq_get(struct byteq *);
int byteq_write(struct byteq *, int fd);
int byteq_read(struct byteq *, int fd);

#endif /* byteq.h */
