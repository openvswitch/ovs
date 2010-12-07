/*
 * Copyright (c) 2010 Nicira Networks.
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

#ifndef NX_MATCH_H
#define NX_MATCH_H 1

#include <stdint.h>

struct cls_rule;
struct flow;
struct ofpbuf;
struct nx_action_reg_load;
struct nx_action_reg_move;

/* Nicira Extended Match (NXM) flexible flow match helper functions.
 *
 * See include/openflow/nicira-ext.h for NXM specification.
 */

int nx_pull_match(struct ofpbuf *, unsigned int match_len, uint16_t priority,
                  struct cls_rule *);
int nx_put_match(struct ofpbuf *, const struct cls_rule *);

char *nx_match_to_string(const uint8_t *, unsigned int match_len);
int nx_match_from_string(const char *, struct ofpbuf *);

int nxm_check_reg_move(const struct nx_action_reg_move *, const struct flow *);
int nxm_check_reg_load(const struct nx_action_reg_load *, const struct flow *);

void nxm_execute_reg_move(const struct nx_action_reg_move *, struct flow *);
void nxm_execute_reg_load(const struct nx_action_reg_load *, struct flow *);

/* Upper bound on the length of an nx_match.  The longest nx_match (assuming
 * we implement 4 registers) would be:
 *
 *                   header  value  mask  total
 *                   ------  -----  ----  -----
 *  NXM_OF_IN_PORT      4       2    --      6
 *  NXM_OF_ETH_DST_W    4       6     6     16
 *  NXM_OF_ETH_SRC      4       6    --     10
 *  NXM_OF_ETH_TYPE     4       2    --      6
 *  NXM_OF_VLAN_TCI     4       2     2      8
 *  NXM_OF_IP_TOS       4       1    --      5
 *  NXM_OF_IP_PROTO     4       2    --      6
 *  NXM_OF_IP_SRC_W     4       4     4     12
 *  NXM_OF_IP_DST_W     4       4     4     12
 *  NXM_OF_TCP_SRC      4       2    --      6
 *  NXM_OF_TCP_DST      4       2    --      6
 *  NXM_NX_REG_W(0)     4       4     4     12
 *  NXM_NX_REG_W(1)     4       4     4     12
 *  NXM_NX_REG_W(2)     4       4     4     12
 *  NXM_NX_REG_W(3)     4       4     4     12
 *  NXM_NX_TUN_ID_W     4       8     8     20
 *  -------------------------------------------
 *  total                                  161
 *
 * So this value is conservative.
 */
#define NXM_MAX_LEN 192

/* This is my guess at the length of a "typical" nx_match, for use in
 * predicting space requirements. */
#define NXM_TYPICAL_LEN 64

#endif /* nx-match.h */
