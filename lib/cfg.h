/* Copyright (c) 2008, 2009 Nicira Networks
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


#ifndef VSWITCHD_CFG_H
#define VSWITCHD_CFG_H 1

#include <stdbool.h>
#include <stdint.h>
#include <unistd.h>
#include "compiler.h"
#include "sha1.h"

struct svec;
struct ofpbuf;

void cfg_init(void);
int cfg_set_file(const char *file_name);
int cfg_read(void);
int cfg_lock(uint8_t *cookie, int timeout);
void cfg_unlock(void);
int cfg_write(void);
int cfg_write_data(uint8_t *data, size_t len);
bool cfg_is_dirty(void);

void cfg_get_all(struct svec *);

#define CFG_COOKIE_LEN SHA1_DIGEST_SIZE
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
void cfg_get_matches(struct svec *svec, const char *pattern, ...)
    PRINTF_FORMAT(2, 3);
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
