/* Copyright (c) 2008, 2011, 2012 The Board of Trustees of The Leland Stanford
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

/*
 * Copyright (c) 2008, 2009, 2010, 2011 Nicira Networks.
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

/* OpenFlow: protocol between controller and datapath. */

#ifndef OPENFLOW_11_H
#define OPENFLOW_11_H 1

#include "openflow/openflow-common.h"

/* OpenFlow 1.1 uses 32-bit port numbers.  Open vSwitch, for now, uses OpenFlow
 * 1.0 port numbers internally.  We map them to OpenFlow 1.0 as follows:
 *
 * OF1.1                    <=>  OF1.0
 * -----------------------       ---------------
 * 0x00000000...0x0000feff  <=>  0x0000...0xfeff  "physical" ports
 * 0x0000ff00...0xfffffeff  <=>  not supported
 * 0xffffff00...0xffffffff  <=>  0xff00...0xffff  "reserved" OFPP_* ports
 *
 * OFPP11_OFFSET is the value that must be added or subtracted to convert
 * an OpenFlow 1.0 reserved port number to or from, respectively, the
 * corresponding OpenFlow 1.1 reserved port number.
 */
#define OFPP11_MAX    0xffffff00
#define OFPP11_OFFSET (OFPP11_MAX - OFPP_MAX)

/* OpenFlow 1.1 specific message types, in addition to the common message
 * types. */
enum ofp11_type {
    /* Controller command messages. */
    OFPT11_PACKET_OUT = 13,     /* Controller/switch message */
    OFPT11_FLOW_MOD,            /* Controller/switch message */
    OFPT11_GROUP_MOD,           /* Controller/switch message */
    OFPT11_PORT_MOD,            /* Controller/switch message */
    OFPT11_TABLE_MOD,           /* Controller/switch message */

    /* Statistics messages. */
    OFPT11_STATS_REQUEST,       /* Controller/switch message */
    OFPT11_STATS_REPLY,         /* Controller/switch message */

    /* Barrier messages. */
    OFPT11_BARRIER_REQUEST,     /* Controller/switch message */
    OFPT11_BARRIER_REPLY,       /* Controller/switch message */

    /* Queue Configuration messages. */
    OFPT11_QUEUE_GET_CONFIG_REQUEST,  /* Controller/switch message */
    OFPT11_QUEUE_GET_CONFIG_REPLY,    /* Controller/switch message */
};

#endif /* openflow/openflow-1.1.h */
