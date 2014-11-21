/* Copyright (c) 2008, 2014 The Board of Trustees of The Leland Stanford
* Junior University
* Copyright (c) 2011, 2014 Open Networking Foundation
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

/* OpenFlow: protocol between controller and datapath. */

#ifndef OPENFLOW_15_H
#define OPENFLOW_15_H 1

#include <openflow/openflow-common.h>

/* Group commands */
enum ofp15_group_mod_command {
    /* Present since OpenFlow 1.1 - 1.4 */
    OFPGC15_ADD    = 0,       /* New group. */
    OFPGC15_MODIFY = 1,       /* Modify all matching groups. */
    OFPGC15_DELETE = 2,       /* Delete all matching groups. */

    /* New in OpenFlow 1.5 */
    OFPGC15_INSERT_BUCKET = 3,/* Insert action buckets to the already available
                                 list of action buckets in a matching group */
    /* OFPGCXX_YYY = 4, */    /* Reserved for future use. */
    OFPGC15_REMOVE_BUCKET = 5,/* Remove all action buckets or any specific
                                 action bucket from matching group */
};

/* Group bucket property types.  */
enum ofp15_group_bucket_prop_type {
    OFPGBPT15_WEIGHT                 = 0,  /* Select groups only. */
    OFPGBPT15_WATCH_PORT             = 1,  /* Fast failover groups only. */
    OFPGBPT15_WATCH_GROUP            = 2,  /* Fast failover groups only. */
    OFPGBPT15_EXPERIMENTER      = 0xFFFF,  /* Experimenter defined. */
};

/* Group bucket weight property, for select groups only. */
struct ofp15_group_bucket_prop_weight {
    ovs_be16         type;    /* OFPGBPT15_WEIGHT. */
    ovs_be16         length;  /* 8. */
    ovs_be16         weight;  /* Relative weight of bucket. */
    uint8_t          pad[2];  /* Pad to 64 bits. */
};
OFP_ASSERT(sizeof(struct ofp15_group_bucket_prop_weight) == 8);

/* Group bucket watch port or watch group property, for fast failover groups
 * only. */
struct ofp15_group_bucket_prop_watch {
    ovs_be16         type;    /* OFPGBPT15_WATCH_PORT or OFPGBPT15_WATCH_GROUP. */
    ovs_be16         length;  /* 8. */
    ovs_be32         watch;   /* The port or the group.  */
};
OFP_ASSERT(sizeof(struct ofp15_group_bucket_prop_watch) == 8);

/* Bucket for use in groups. */
struct ofp15_bucket {
    ovs_be16 len;                   /* Length the bucket in bytes, including
                                       this header and any padding to make it
                                       64-bit aligned. */
    ovs_be16 action_array_len;      /* Length of all actions in bytes. */
    ovs_be32 bucket_id;             /* Bucket Id used to identify bucket*/
    /* Followed by exactly len - 8 bytes of group bucket properties. */
    /* Followed by:
     *   - Exactly 'action_array_len' bytes containing an array of
     *     struct ofp_action_*.
     *   - Zero or more bytes of group bucket properties to fill out the
     *     overall length in header.length. */
};
OFP_ASSERT(sizeof(struct ofp15_bucket) == 8);

/* Bucket Id can be any value between 0 and OFPG_BUCKET_MAX */
enum ofp15_group_bucket {
    OFPG15_BUCKET_MAX   = 0xffffff00, /* Last usable bucket ID */
    OFPG15_BUCKET_FIRST = 0xfffffffd, /* First bucket ID in the list of action
                                         buckets of a group. This is applicable
                                         for OFPGC15_INSERT_BUCKET and
                                         OFPGC15_REMOVE_BUCKET commands */
    OFPG15_BUCKET_LAST  = 0xfffffffe, /* Last bucket ID in the list of action
                                         buckets of a group. This is applicable
                                         for OFPGC15_INSERT_BUCKET and
                                         OFPGC15_REMOVE_BUCKET commands */
    OFPG15_BUCKET_ALL   = 0xffffffff  /* All action buckets in a group,
                                         This is applicable for
                                         only OFPGC15_REMOVE_BUCKET command */
};

/* Group property types.  */
enum ofp_group_prop_type {
    OFPGPT15_EXPERIMENTER      = 0xFFFF,  /* Experimenter defined. */
};

/* Group setup and teardown (controller -> datapath). */
struct ofp15_group_mod {
    ovs_be16 command;             /* One of OFPGC15_*. */
    uint8_t type;                 /* One of OFPGT11_*. */
    uint8_t pad;                  /* Pad to 64 bits. */
    ovs_be32 group_id;            /* Group identifier. */
    ovs_be16 bucket_array_len;    /* Length of action buckets data. */
    uint8_t pad1[2];              /* Pad to 64 bits. */
    ovs_be32 command_bucket_id;   /* Bucket Id used as part of
                                   * OFPGC15_INSERT_BUCKET and
                                   * OFPGC15_REMOVE_BUCKET commands
                                   * execution.*/
    /* Followed by:
     *   - Exactly 'bucket_array_len' bytes containing an array of
     *     struct ofp15_bucket.
     *   - Zero or more bytes of group properties to fill out the overall
     *     length in header.length. */
};
OFP_ASSERT(sizeof(struct ofp15_group_mod) == 16);

/* Body of reply to OFPMP_GROUP_DESC request. */
struct ofp15_group_desc_stats {
    ovs_be16 length;              /* Length of this entry. */
    uint8_t type;                 /* One of OFPGT11_*. */
    uint8_t pad;                  /* Pad to 64 bits. */
    ovs_be32 group_id;            /* Group identifier. */
    ovs_be16 bucket_list_len;     /* Length of action buckets data. */
    uint8_t pad2[6];              /* Pad to 64 bits. */
    /* Followed by:
     *   - Exactly 'bucket_list_len' bytes containing an array of
     *     struct ofp_bucket.
     *   - Zero or more bytes of group properties to fill out the overall
     *     length in header.length. */
};
OFP_ASSERT(sizeof(struct ofp15_group_desc_stats) == 16);

#endif /* openflow/openflow-1.5.h */
