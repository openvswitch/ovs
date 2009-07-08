/*
 * Copyright (c) 2009 Nicira Networks.
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#ifndef OPENFLOW_OPENFLOW_MGMT_H
#define OPENFLOW_OPENFLOW_MGMT_H 1

#include "openflow/nicira-ext.h"

enum ofmp_type {
    OFMPT_CAPABILITY_REQUEST,
    OFMPT_CAPABILITY_REPLY,
    OFMPT_RESOURCES_REQUEST,
    OFMPT_RESOURCES_UPDATE,
    OFMPT_CONFIG_REQUEST,
    OFMPT_CONFIG_UPDATE,
    OFMPT_CONFIG_UPDATE_ACK,
    OFMPT_ERROR
};

/* Header on all OpenFlow management packets. */
struct ofmp_header {
    struct nicira_header header;
    uint16_t type;           /* One of OFMPT_* above. */
    uint8_t pad[2];
};
OFP_ASSERT(sizeof(struct ofmp_header) == sizeof(struct nicira_header) + 4);


/* Generic TLV header. */
struct ofmp_tlv {
    uint16_t type;        /* Type of value (one of OFMPTLV_*). */
    uint16_t len;         /* Length of TLV (includes this header). */
    uint8_t data[0];      /* Value of data as defined by type and length. */
};
OFP_ASSERT(sizeof(struct ofmp_tlv) == 4);

/* Universal TLV terminator.  Used to indicate end of TLV list. */
struct ofmp_tlv_end {
    uint16_t type;        /* Type is 0. */
    uint16_t len;         /* Length is 4. */
};
OFP_ASSERT(sizeof(struct ofmp_tlv_end) == 4);


/* Bitmask of capability description styles. */
enum ofmp_capability_format {
    OFMPCAF_SIMPLE  = 0 << 0,             /* "ovs-vswitchd.conf" style. */
};

/* Body of capbility request.
 *
 * OFMPT_CAPABILITY_REQUEST (controller -> switch) */
struct ofmp_capability_request {
    struct ofmp_header header;
    uint32_t format;                      /* One of OFMPCAF_*. */
};
OFP_ASSERT(sizeof(struct ofmp_capability_request) == 24);

/* Body of reply to capability request.  
 *
 * OFMPT_CAPABILITY_REPLY (switch -> controller). */
struct ofmp_capability_reply {
    struct ofmp_header header;
    uint32_t format;                      /* One of OFMPCAF_*. */
    uint64_t mgmt_id;                     /* Management ID. */
    uint8_t data[0];
};
OFP_ASSERT(sizeof(struct ofmp_capability_reply) == 32);


/* Resource TLV for datapath description. */
struct ofmptsr_dp {
    uint16_t type;                        /* OFMPTSR_DP. */
    uint16_t len;                         /* 28. */
    uint8_t pad[4];
    uint64_t dp_id;                       /* Datapath ID. */
    uint8_t name[OFP_MAX_PORT_NAME_LEN];  /* Null-terminated name. */
};
OFP_ASSERT(sizeof(struct ofmptsr_dp) == 32);

/* TLV types for switch resource descriptions. */
enum ofmp_switch_resources {
    OFMPTSR_END = 0,                      /* Terminator. */
    OFMPTSR_DP,                           /* Datapath. */
};

/* Body of resources request.
 *
 * OFMPT_RESOURCES_REQUEST (controller -> switch) */
struct ofmp_resources_request {
    struct ofmp_header header;
};

/* Body of capbility update.  Sent in response to a resources request or
 * sent asynchronously when resources change on the switch. 
 *
 * OFMPT_RESOURCES_UPDATE (switch -> controller) */
struct ofmp_resources_update {
    struct ofmp_header header;
    uint8_t data[0];
};
OFP_ASSERT(sizeof(struct ofmp_resources_update) == 20);


/* Bitmask of capability description styles. */
enum ofmp_config_format {
    OFMPCOF_SIMPLE  = 0 << 0,           /* "ovs-vswitchd.conf" style. */
};

#define CONFIG_COOKIE_LEN 20

/* Body of configuration request.
 *
 * OFMPT_CONFIG_REQUEST (controller -> switch) */
struct ofmp_config_request {
    struct ofmp_header header;
    uint32_t format;                    /* One of OFMPCOF_*. */
};
OFP_ASSERT(sizeof(struct ofmp_config_request) == 24);

/* Body of configuration update.  Sent in response to a configuration 
 * request from the controller.  May be sent asynchronously by either
 * the controller or switch to modify configuration or notify of
 * changes, respectively.  If sent by the controller, the switch must
 * respond with a OFMPT_CONFIG_UPDATE_ACK.
 *
 * OFMPT_CONFIG_UPDATE (switch <-> controller) */
struct ofmp_config_update {
    struct ofmp_header header;
    uint32_t format;                    /* One of OFMPCOF_*. */
    uint8_t cookie[CONFIG_COOKIE_LEN];  /* Cookie of config attempting to be
                                         * replaced by this update. */
    uint8_t data[0];
};
OFP_ASSERT(sizeof(struct ofmp_config_update) == 44);

/* Bitmask of configuration update ack flags. */
enum ofmp_config_update_ack_flags {
    OFMPCUAF_SUCCESS = 1 << 0,          /* Config succeeded. */
};

/* Body of configuration update ack.  Sent in response to a configuration 
 * udpate request.
 *
 * OFMPT_CONFIG_UPDATE_ACK (switch -> controller) */
struct ofmp_config_update_ack {
    struct ofmp_header header;
    uint32_t format;                    /* One of OFMPCOF_*. */
    uint32_t flags;                     /* One of OFMPCUAF_*. */
    uint8_t cookie[CONFIG_COOKIE_LEN];  /* Cookie of current configuration 
                                         * being used in the switch. */
};
OFP_ASSERT(sizeof(struct ofmp_config_update_ack) == 48);

/* Values for 'type' in ofmp_error_msg. */
enum ofmp_error_type {
    OFMPET_BAD_CONFIG                   /* Problem with configuration. */
};

/* ofmp_error_msg 'code' values for OFMPET_BAD_CONFIG.  'data' contains
 * at least the first 64 bytes of the failed request. */
enum ofmp_bad_config_code {
    OFMPBCC_BUSY,                       /* Config updating, try again. */
    OFMPBCC_OLD_COOKIE,                 /* Config has changed. */
};

/* Body of error message.  May be sent by either the switch or the
 * controller to indicate some error condition.
 *
 * OFMPT_ERROR (switch <-> controller) */
struct ofmp_error_msg {
    struct ofmp_header header;

    uint16_t type;            /* One of OFMPET_*. */
    uint16_t code;            /* Code depending on 'type'. */
    uint8_t data[0];          /* Variable-length data.  Interpreted based 
                                 on the type and code. */
};
OFP_ASSERT(sizeof(struct ofmp_error_msg) == 24);

#endif /* openflow/openflow-mgmt.h */
