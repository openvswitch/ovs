/* Copyright (c) 2008 The Board of Trustees of The Leland Stanford
 * Junior University
 *
 * We are making the OpenFlow specification and associated documentation
 * (Software) available for public use and benefit with the expectation
 * that others will use, modify and enhance the Software and contribute
 * those enhancements back to the community. However, since we would
 * like to make the Software available for broadest use, with as few
 * restrictions as possible permission is hereby granted, free of
 * charge, to any person obtaining a copy of this Software to deal in
 * the Software under the copyrights without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT.  IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 *
 * The name and trademarks of copyright holder(s) may NOT be used in
 * advertising or publicity pertaining to the Software or any
 * derivatives without specific, written prior permission.
 */

#ifndef STP_H
#define STP_H 1

/* This is an implementation of Spanning Tree Protocol as described in IEEE
 * 802.1D-1998, clauses 8 and 9.  Section numbers refer to this standard.  */

#include <stdbool.h>
#include <stdint.h>
#include "compiler.h"
#include "util.h"

/* Ethernet address used as the destination for STP frames. */
extern const uint8_t stp_eth_addr[6];

/* LLC field values used for STP frames. */
#define STP_LLC_SSAP 0x42
#define STP_LLC_DSAP 0x42
#define STP_LLC_CNTL 0x03

/* Bridge identifier.  Top 16 bits are a priority value (numerically lower
 * values are higher priorities).  Bottom 48 bits are MAC address of bridge. */
typedef uint64_t stp_identifier;

/* Basic STP functionality. */
#define STP_MAX_PORTS 255
struct stp *stp_create(const char *name, stp_identifier bridge_id,
                       void (*send_bpdu)(const void *bpdu, size_t bpdu_size,
                                         int port_no, void *aux),
                       void *aux);
void stp_destroy(struct stp *);
void stp_tick(struct stp *, int elapsed);
void stp_set_bridge_id(struct stp *, stp_identifier bridge_id);
void stp_set_bridge_priority(struct stp *, uint16_t new_priority);

/* STP properties. */
const char *stp_get_name(const struct stp *);
stp_identifier stp_get_bridge_id(const struct stp *);
stp_identifier stp_get_designated_root(const struct stp *);
bool stp_is_root_bridge(const struct stp *);
int stp_get_root_path_cost(const struct stp *);

/* Obtaining STP ports. */
struct stp_port *stp_get_port(struct stp *, int port_no);
struct stp_port *stp_get_root_port(struct stp *);
bool stp_get_changed_port(struct stp *, struct stp_port **portp);

/* State of an STP port.
 *
 * A port is in exactly one state at any given time, but distinct bits are used
 * for states to allow testing for more than one state with a bit mask. */
enum stp_state {
    STP_DISABLED = 1 << 0,       /* 8.4.5: Disabled by management. */
    STP_LISTENING = 1 << 1,      /* 8.4.2: Not learning or relaying frames. */
    STP_LEARNING = 1 << 2,       /* 8.4.3: Learning but not relaying frames. */
    STP_FORWARDING = 1 << 3,     /* 8.4.4: Learning and relaying frames. */
    STP_BLOCKING = 1 << 4        /* 8.4.1: Initial boot state. */
};
const char *stp_state_name(enum stp_state);
bool stp_forward_in_state(enum stp_state);
bool stp_learn_in_state(enum stp_state);

void stp_received_bpdu(struct stp_port *, const void *bpdu, size_t bpdu_size);

struct stp *stp_port_get_stp(struct stp_port *);
int stp_port_no(const struct stp_port *);
enum stp_state stp_port_get_state(const struct stp_port *);
void stp_port_enable(struct stp_port *);
void stp_port_disable(struct stp_port *);
void stp_port_set_priority(struct stp_port *, uint8_t new_priority);
void stp_port_set_path_cost(struct stp_port *, unsigned int path_cost);
void stp_port_set_speed(struct stp_port *, unsigned int speed);
void stp_port_enable_change_detection(struct stp_port *);
void stp_port_disable_change_detection(struct stp_port *);

#endif /* stp.h */
