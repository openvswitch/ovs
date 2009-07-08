/* Copyright (c) 2008, 2009 Nicira Networks
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
 */


#ifndef VSWITCHD_CFG_H
#define VSWITCHD_CFG_H 1

#include <stdbool.h>
#include <stdint.h>
#include <unistd.h>
#include "compiler.h"
#include "sha1.h"

struct svec;
struct ofpbuf;

int cfg_set_file(const char *file_name);
int cfg_read(void);
int cfg_lock(uint8_t *cookie, int timeout);
void cfg_unlock(void);
int cfg_write(void);
int cfg_write_data(uint8_t *data, size_t len);
bool cfg_is_dirty(void);

void cfg_get_all(struct svec *);

#define CFG_COOKIE_LEN SHA1HashSize
int cfg_get_cookie(uint8_t *cookie);

void cfg_buf_put(struct ofpbuf *buffer);
void cfg_get_subsections(struct svec *, const char *, ...) PRINTF_FORMAT(2, 3);

enum cfg_flags {
    /* Types allowed. */
    CFG_STRING = 1 << 0,        /* Arbitrary content. */
    CFG_KEY = 1 << 0,           /* Valid key name. */
    CFG_INT = 1 << 2,           /* Integer value. */
    CFG_BOOL = 1 << 3,          /* Boolean. */
    CFG_IP = 1 << 4,            /* IPv4 address. */
    CFG_MAC = 1 << 5,           /* MAC address. */
    CFG_VLAN = 1 << 6,          /* Integer in range 0...4095. */
    CFG_DPID = 1 << 7,          /* 12 hexadecimal digits. */

    /* Number allowed. */
    CFG_REQUIRED = 1 << 8,      /* At least one value allowed. */
    CFG_MULTIPLE = 1 << 9       /* More than one value allowed. */
};
void cfg_register(const char *key_spec, enum cfg_flags);

void cfg_add_entry(const char *key, ...) PRINTF_FORMAT(1, 2);
void cfg_del_entry(const char *key, ...) PRINTF_FORMAT(1, 2);
void cfg_del_section(const char *key, ...) PRINTF_FORMAT(1, 2);
void cfg_del_match(const char *pattern, ...) PRINTF_FORMAT(1, 2);
void cfg_get_section(struct svec *svec, const char *key, ...) 
    PRINTF_FORMAT(2, 3);

bool cfg_has(const char *key, ...) PRINTF_FORMAT(1, 2);
bool cfg_is_valid(enum cfg_flags, const char *key, ...) PRINTF_FORMAT(2, 3);
bool cfg_has_section(const char *key, ...) PRINTF_FORMAT(1, 2);
int cfg_count(const char *key, ...) PRINTF_FORMAT(1, 2);

const char *cfg_get_string(int idx, const char *key, ...) PRINTF_FORMAT(2, 3);
const char *cfg_get_key(int idx, const char *key, ...) PRINTF_FORMAT(2, 3);
int cfg_get_int(int idx, const char *key, ...) PRINTF_FORMAT(2, 3);
bool cfg_get_bool(int idx, const char *key, ...) PRINTF_FORMAT(2, 3);
uint32_t cfg_get_ip(int idx, const char *key, ...) PRINTF_FORMAT(2, 3);
uint64_t cfg_get_mac(int idx, const char *key, ...) PRINTF_FORMAT(2, 3);
int cfg_get_vlan(int idx, const char *key, ...) PRINTF_FORMAT(2, 3);
uint64_t cfg_get_dpid(int idx, const char *key, ...) PRINTF_FORMAT(2, 3);

void cfg_get_all_strings(struct svec *, const char *key, ...)
    PRINTF_FORMAT(2, 3);
void cfg_get_all_keys(struct svec *, const char *key, ...) PRINTF_FORMAT(2, 3);

#endif /* vswitchd/cfg.h */
