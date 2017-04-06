/* Copyright (c) 2008 The Board of Trustees of The Leland Stanford
 * Junior University
 * Copyright (c) 2011, 2013, 2014 Open Networking Foundation
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

/*
 * Copyright (c) 2017 Nicira, Inc.
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

#ifndef OPENFLOW_16_H
#define OPENFLOW_16_H 1

#include <openflow/openflow-common.h>

#define OFP16_MAX_PORT_NAME_LEN  64

/* Bitmap of hardware address types supported by an OpenFlow port. */
enum ofp16_hardware_address_type {
    OFPPHAT16_EUI48 = 1 << 0,   /* 48-bit Ethernet address. */
    OFPPHAT16_EUI64 = 1 << 1,   /* 64-bit Ethernet address. */
};

struct ofp16_port {
    ovs_be32 port_no;
    ovs_be16 length;
    ovs_be16 hw_addr_type;            /* Zero or more OFPPHAT16_*. */
    struct eth_addr hw_addr;          /* EUI-48 hardware address. */
    uint8_t pad[2];                   /* Align to 64 bits. */
    struct eth_addr64 hw_addr64;      /* EUI-64 hardware address */
    char name[OFP16_MAX_PORT_NAME_LEN]; /* Null-terminated */

    ovs_be32 config;        /* Bitmap of OFPPC_* flags. */
    ovs_be32 state;         /* Bitmap of OFPPS_* flags. */

    /* Followed by 0 or more OFPPDPT14_* properties.  (OpenFlow 1.6 (draft)
     * defines the same properties as OpenFlow 1.4.) */
};
OFP_ASSERT(sizeof(struct ofp16_port) == 96);

struct ofp16_port_mod {
    ovs_be32 port_no;
    ovs_be16 hw_addr_type;       /* Zero or more OFPPHAT16_*. */
    uint8_t pad[2];              /* Align to 64 bits. */
    struct eth_addr hw_addr;
    uint8_t pad2[2];
    struct eth_addr64 hw_addr64; /* EUI-64 hardware address */

    ovs_be32 config;        /* Bitmap of OFPPC_* flags. */
    ovs_be32 mask;          /* Bitmap of OFPPC_* flags to be changed. */

    /* Followed by 0 or more OFPPMPT14_* properties.  (OpenFlow 1.6 (draft)
     * defines the same properties as OpenFlow 1.4.) */
};
OFP_ASSERT(sizeof(struct ofp16_port_mod) == 32);


#endif /* openflow/openflow-1.6.h */
