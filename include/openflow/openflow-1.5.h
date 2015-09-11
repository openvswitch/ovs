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

/* Body for ofp15_multipart_request of type OFPMP_PORT_DESC. */
struct ofp15_port_desc_request {
    ovs_be32 port_no;         /* All ports if OFPP_ANY. */
    uint8_t pad[4];            /* Align to 64 bits. */
};
OFP_ASSERT(sizeof(struct ofp15_port_desc_request) == 8);

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

/* Body for ofp15_multipart_request of type OFPMP_GROUP_DESC. */
struct ofp15_group_desc_request {
    ovs_be32 group_id;         /* All groups if OFPG_ALL. */
    uint8_t pad[4];            /* Align to 64 bits. */
};
OFP_ASSERT(sizeof(struct ofp15_group_desc_request) == 8);

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

/* Table Features request commands */
enum ofp15_table_features_command {
    OFPTFC_REPLACE = 0,    /* Replace full pipeline. */
    OFPTFC_MODIFY  = 1,    /* Modify flow tables capabilities. */
    OFPTFC_ENABLE  = 2,    /* Enable flow tables in the pipeline. */
    OFPTFC_DISABLE = 3,    /* Disable flow tables in pipeline. */
};

/* Flags of features supported by the table. */
enum ofp15_table_feature_flag {
    OFPTFF_INGRESS_TABLE = 1 << 0, /* Can be configured as ingress table. */
    OFPTFF_EGRESS_TABLE  = 1 << 1, /* Can be configured as egress table. */
    OFPTFF_FIRST_EGRESS  = 1 << 4, /* Is the first egress table. */
};

/* Common header for all Table Feature Properties */
struct ofp15_table_feature_prop_header {
    ovs_be16    type;   /* One of OFPTFPT_*. */
    ovs_be16    length; /* Length in bytes of this property. */
};
OFP_ASSERT(sizeof(struct ofp15_table_feature_prop_header) == 4);

/* Body for ofp_multipart_request of type OFPMP_TABLE_FEATURES./
 * Body of reply to OFPMP_TABLE_FEATURES request. */
struct ofp15_table_features {
    ovs_be16 length;          /* Length is padded to 64 bits. */
    uint8_t table_id;         /* Identifier of table. Lower numbered tables
                               * are consulted first. */
    uint8_t command;          /* One of OFPTFC_*. */
    ovs_be32 features;        /* Bitmap of OFPTFF_* values. */
    char name[OFP_MAX_TABLE_NAME_LEN];
    ovs_be64 metadata_match;  /* Bits of metadata table can match. */
    ovs_be64 metadata_write;  /* Bits of metadata table can write. */

    /* In OF1.3 this field was named 'config' and it was useless because OF1.3
     * did not define any OFPTC_* bits.
     *
     * OF1.4 renamed this field to 'capabilities' and added OFPTC14_EVICTION
     * and OFPTC14_VACANCY_EVENTS. */
    ovs_be32 capabilities;    /* Bitmap of OFPTC_* values */

    ovs_be32 max_entries;     /* Max number of entries supported. */

    /* Table Feature Property list */
    /* struct ofp15_table_feature_prop_header properties[0]; */
};
OFP_ASSERT(sizeof(struct ofp15_table_features) == 64);

/* Table Feature property types.
 * Low order bit cleared indicates a property for a regular Flow Entry.
 * Low order bit set indicates a property for the Table-Miss Flow Entry. */
enum ofp15_table_feature_prop_type {
    OFPTFPT15_INSTRUCTIONS         = 0, /* Instructions property. */
    OFPTFPT15_INSTRUCTIONS_MISS    = 1, /* Instructions for table-miss. */
    OFPTFPT15_NEXT_TABLES          = 2, /* Next Table property. */
    OFPTFPT15_NEXT_TABLES_MISS     = 3, /* Next Table for table-miss. */
    OFPTFPT15_WRITE_ACTIONS        = 4, /* Write Actions property. */
    OFPTFPT15_WRITE_ACTIONS_MISS   = 5, /* Write Actions for table-miss. */
    OFPTFPT15_APPLY_ACTIONS        = 6, /* Apply Actions property. */
    OFPTFPT15_APPLY_ACTIONS_MISS   = 7, /* Apply Actions for table-miss. */
    OFPTFPT15_MATCH                = 8, /* Match property. */
    OFPTFPT15_WILDCARDS            = 10, /* Wildcards property. */
    OFPTFPT15_WRITE_SETFIELD       = 12, /* Write Set-Field property. */
    OFPTFPT15_WRITE_SETFIELD_MISS  = 13, /* Write Set-Field for table-miss. */
    OFPTFPT15_APPLY_SETFIELD       = 14, /* Apply Set-Field property. */
    OFPTFPT15_APPLY_SETFIELD_MISS  = 15, /* Apply Set-Field for table-miss. */
    OFPTFPT15_TABLE_SYNC_FROM      = 16, /* Table synchronisation property. */
    OFPTFPT15_WRITE_COPYFIELD      = 18, /* Write Copy-Field property. */
    OFPTFPT15_WRITE_COPYFIELD_MISS = 19, /* Write Copy-Field for table-miss. */
    OFPTFPT15_APPLY_COPYFIELD      = 20, /* Apply Copy-Field property. */
    OFPTFPT15_APPLY_COPYFIELD_MISS = 21, /* Apply Copy-Field for table-miss. */
    OFPTFPT15_PACKET_TYPES         = 22, /* Packet types property. */
    OFPTFPT15_EXPERIMENTER         = 0xFFFE, /* Experimenter property. */
    OFPTFPT15_EXPERIMENTER_MISS    = 0xFFFF, /* Experimenter for table-miss. */
};

/* Instructions property */
struct ofp15_table_feature_prop_instructions {
    ovs_be16    type;    /* One of OFPTFPT15_INSTRUCTIONS,
                          * OFPTFPT15_INSTRUCTIONS_MISS. */
    ovs_be16    length;  /* Length in bytes of this property. */
    /* Followed by:
     *   - Exactly (length - 4) bytes containing the instruction ids, then
     *   - Exactly (length + 7)/8*8 - (length) (between 0 and 7)
     *     bytes of all-zero bytes */
    /* struct ofp11_instruction instruction_ids[0];  List of instructions
                                                     without any data */
};
OFP_ASSERT(sizeof(struct ofp15_table_feature_prop_instructions) == 4);

/* Next Tables property */
struct ofp15_table_feature_prop_next_tables {
    ovs_be16    type;   /* One of OFPTFPT15_NEXT_TABLES,
                         * OFPTFPT15_NEXT_TABLES_MISS.
                         * OFPTFPT15_TABLE_SYNC_FROM. */
    ovs_be16    length; /* Length in bytes of this property. */
    /* Followed by:
     *   - Exactly (length - 4) bytes containing the table_ids, then
     *   - Exactly (length + 7)/8*8 - (length) (between 0 and 7)
     *     bytes of all-zero bytes */
    /* uint8_t     next_table_ids[0]; */
};
OFP_ASSERT(sizeof(struct ofp15_table_feature_prop_next_tables) == 4);

/* Actions property */
struct ofp15_table_feature_prop_actions {
    ovs_be16    type;   /* One of OFPTFPT15_WRITE_ACTIONS,
                         * OFPTFPT15_WRITE_ACTIONS_MISS,
                         * OFPTFPT15_APPLY_ACTIONS,
                         * OFPTFPT15_APPLY_ACTIONS_MISS. */
    ovs_be16    length; /* Length in bytes of this property. */
    /* Followed by:
     *   - Exactly (length - 4) bytes containing the action_ids, then
     *   - Exactly (length + 7)/8*8 - (length) (between 0 and 7)
     *     bytes of all-zero bytes */
    /* struct ofp_action_header action_ids[0];     List of actions
                                                   without any data */
};
OFP_ASSERT(sizeof(struct ofp15_table_feature_prop_actions) == 4);

/* Match, Wildcard or Set-Field property */
struct ofp15_table_feature_prop_oxm {
    ovs_be16    type;   /* One of OFPTFPT15_MATCH, OFPTFPT15_WILDCARDS,
                         * OFPTFPT15_WRITE_SETFIELD,
                         * OFPTFPT15_WRITE_SETFIELD_MISS,
                         * OFPTFPT15_APPLY_SETFIELD,
                         * OFPTFPT15_APPLY_SETFIELD_MISS.
                         * OFPTFPT15_WRITE_COPYFIELD,
                         * OFPTFPT15_WRITE_COPYFIELD_MISS,
                         * OFPTFPT15_APPLY_COPYFIELD,
                         * OFPTFPT15_APPLY_COPYFIELD_MISS. */
    ovs_be16    length; /* Length in bytes of this property. */
    /* Followed by:
     *   - Exactly (length - 4) bytes containing the oxm_ids, then
     *   - Exactly (length + 7)/8*8 - (length) (between 0 and 7)
     *     bytes of all-zero bytes */
    /* ovs_be32    oxm_ids[0];     Array of OXM headers */
};
OFP_ASSERT(sizeof(struct ofp15_table_feature_prop_oxm) == 4);

/* Packet types property */
struct ofp15_table_feature_prop_oxm_values {
    ovs_be16 type;    /* OFPTFPT15_PACKET_TYPES. */
    ovs_be16 length;  /* Length in bytes of this property. */
    /* Followed by:
     *   - Exactly (length - 4) bytes containing the oxm values, then
     *   - Exactly (length + 7)/8*8 - (length) (between 0 and 7)
     *     bytes of all-zero bytes */
    /*uint32_t oxm_values[0];     Array of OXM values */
};
OFP_ASSERT(sizeof(struct ofp15_table_feature_prop_oxm_values) == 4);

/* Experimenter table feature property */
struct ofp15_table_feature_prop_experimenter {
    ovs_be16    type;     /* One of OFPTFPT15_EXPERIMENTER,
                           * OFPTFPT15_EXPERIMENTER_MISS. */
    ovs_be16    length;   /* Length in bytes of this property. */
    ovs_be32    experimenter; /* Experimenter ID which takes the same form
                               * as in struct ofp_experimenter_header. */
    ovs_be32    exp_type;     /* Experimenter defined. */
    /* Followed by:
     *   - Exactly (length - 12) bytes containing the experimenter data, then
     *   - Exactly (length + 7)/8*8 - (length) (between 0 and 7)
     *     bytes of all-zero bytes */
    /* ovs_be32    experimenter_data[0]; */
};
OFP_ASSERT(sizeof(struct ofp15_table_feature_prop_experimenter) == 12);

#endif /* openflow/openflow-1.5.h */
