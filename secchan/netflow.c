/*
 * Copyright (c) 2008, 2009 Nicira Networks.
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

#include <config.h>
#include "netflow.h"
#include <arpa/inet.h>
#include <errno.h>
#include <stdlib.h>
#include <unistd.h>
#include "cfg.h"
#include "flow.h"
#include "netflow.h"
#include "ofpbuf.h"
#include "ofproto.h"
#include "packets.h"
#include "socket-util.h"
#include "svec.h"
#include "timeval.h"
#include "util.h"
#include "xtoxll.h"

#define THIS_MODULE VLM_netflow
#include "vlog.h"

#define NETFLOW_V5_VERSION 5

/* Every NetFlow v5 message contains the header that follows.  This is
 * followed by up to thirty records that describe a terminating flow.
 * We only send a single record per NetFlow message.
 */
struct netflow_v5_header {
    uint16_t version;              /* NetFlow version is 5. */
    uint16_t count;                /* Number of records in this message. */
    uint32_t sysuptime;            /* System uptime in milliseconds. */
    uint32_t unix_secs;            /* Number of seconds since Unix epoch. */
    uint32_t unix_nsecs;           /* Number of residual nanoseconds
                                      after epoch seconds. */
    uint32_t flow_seq;             /* Number of flows since sending
                                      messages began. */
    uint8_t  engine_type;          /* Engine type. */
    uint8_t  engine_id;            /* Engine id. */
    uint16_t sampling_interval;    /* Set to zero. */
};
BUILD_ASSERT_DECL(sizeof(struct netflow_v5_header) == 24);

/* A NetFlow v5 description of a terminating flow.  It is preceded by a
 * NetFlow v5 header.
 */
struct netflow_v5_record {
    uint32_t src_addr;             /* Source IP address. */
    uint32_t dst_addr;             /* Destination IP address. */
    uint32_t nexthop;              /* IP address of next hop.  Set to 0. */
    uint16_t input;                /* Input interface index. */
    uint16_t output;               /* Output interface index. */
    uint32_t packet_count;         /* Number of packets. */
    uint32_t byte_count;           /* Number of bytes. */
    uint32_t init_time;            /* Value of sysuptime on first packet. */
    uint32_t used_time;            /* Value of sysuptime on last packet. */

    /* The 'src_port' and 'dst_port' identify the source and destination
     * port, respectively, for TCP and UDP.  For ICMP, the high-order
     * byte identifies the type and low-order byte identifies the code
     * in the 'dst_port' field. */
    uint16_t src_port;
    uint16_t dst_port;

    uint8_t  pad1;
    uint8_t  tcp_flags;            /* Union of seen TCP flags. */
    uint8_t  ip_proto;             /* IP protocol. */
    uint8_t  ip_tos;               /* IP TOS value. */
    uint16_t src_as;               /* Source AS ID.  Set to 0. */
    uint16_t dst_as;               /* Destination AS ID.  Set to 0. */
    uint8_t  src_mask;             /* Source mask bits.  Set to 0. */
    uint8_t  dst_mask;             /* Destination mask bits.  Set to 0. */
    uint8_t  pad[2];
};
BUILD_ASSERT_DECL(sizeof(struct netflow_v5_record) == 48);

struct netflow {
    uint8_t engine_type;          /* Value of engine_type to use. */
    uint8_t engine_id;            /* Value of engine_id to use. */
    long long int boot_time;      /* Time when netflow_create() was called. */
    int *fds;                     /* Sockets for NetFlow collectors. */
    size_t n_fds;                 /* Number of Netflow collectors. */
    bool add_id_to_iface;         /* Put the 7 least signficiant bits of 
                                   * 'engine_id' into the most signficant 
                                   * bits of the interface fields. */
    uint32_t netflow_cnt;         /* Flow sequence number for NetFlow. */
    struct ofpbuf packet;         /* NetFlow packet being accumulated. */
};

static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 5);

static int
open_collector(char *dst)
{
    char *save_ptr;
    const char *host_name;
    const char *port_string;
    struct sockaddr_in sin;
    int retval;
    int fd;

    /* Glibc 2.7 has a bug in strtok_r when compiling with optimization that
     * can cause segfaults here:
     * http://sources.redhat.com/bugzilla/show_bug.cgi?id=5614.
     * Using "::" instead of the obvious ":" works around it. */
    host_name = strtok_r(dst, ":", &save_ptr);
    port_string = strtok_r(NULL, ":", &save_ptr);
    if (!host_name) {
        ovs_error(0, "%s: bad peer name format", dst);
        return -EAFNOSUPPORT;
    }
    if (!port_string) {
        ovs_error(0, "%s: bad port format", dst);
        return -EAFNOSUPPORT;
    }

    memset(&sin, 0, sizeof sin);
    sin.sin_family = AF_INET;
    if (lookup_ip(host_name, &sin.sin_addr)) {
        return -ENOENT;
    }
    sin.sin_port = htons(atoi(port_string));

    fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) {
        VLOG_ERR("%s: socket: %s", dst, strerror(errno));
        return -errno;
    }

    retval = set_nonblocking(fd);
    if (retval) {
        close(fd);
        return -retval;
    }

    retval = connect(fd, (struct sockaddr *) &sin, sizeof sin);
    if (retval < 0) {
        int error = errno;
        VLOG_ERR("%s: connect: %s", dst, strerror(error));
        close(fd);
        return -error;
    }

    return fd;
}

void
netflow_expire(struct netflow *nf, const struct ofexpired *expired)
{
    struct netflow_v5_header *nf_hdr;
    struct netflow_v5_record *nf_rec;
    struct timeval now;

    /* NetFlow only reports on IP packets. */
    if (expired->flow.dl_type != htons(ETH_TYPE_IP)) {
        return;
    }

    time_timeval(&now);

    if (!nf->packet.size) {
        nf_hdr = ofpbuf_put_zeros(&nf->packet, sizeof *nf_hdr);
        nf_hdr->version = htons(NETFLOW_V5_VERSION);
        nf_hdr->count = htons(0);
        nf_hdr->sysuptime = htonl(time_msec() - nf->boot_time);
        nf_hdr->unix_secs = htonl(now.tv_sec);
        nf_hdr->unix_nsecs = htonl(now.tv_usec * 1000);
        nf_hdr->flow_seq = htonl(nf->netflow_cnt++);
        nf_hdr->engine_type = nf->engine_type;
        nf_hdr->engine_id = nf->engine_id;
        nf_hdr->sampling_interval = htons(0);
    }

    nf_hdr = nf->packet.data;
    nf_hdr->count = htons(ntohs(nf_hdr->count) + 1);

    nf_rec = ofpbuf_put_zeros(&nf->packet, sizeof *nf_rec);
    nf_rec->src_addr = expired->flow.nw_src;
    nf_rec->dst_addr = expired->flow.nw_dst;
    nf_rec->nexthop = htons(0);
    if (nf->add_id_to_iface) {
        uint16_t iface = (nf->engine_id & 0x7f) << 9;
        nf_rec->input = htons(iface | (expired->flow.in_port & 0x1ff));
        nf_rec->output = htons(iface);
        printf("input: %x\n", ntohs(nf_rec->input));
    } else {
        nf_rec->input = htons(expired->flow.in_port);
        nf_rec->output = htons(0);
    }
    nf_rec->packet_count = htonl(MIN(expired->packet_count, UINT32_MAX));
    nf_rec->byte_count = htonl(MIN(expired->byte_count, UINT32_MAX));
    nf_rec->init_time = htonl(expired->created - nf->boot_time);
    nf_rec->used_time = htonl(MAX(expired->created, expired->used)
                             - nf->boot_time);
    if (expired->flow.nw_proto == IP_TYPE_ICMP) {
        /* In NetFlow, the ICMP type and code are concatenated and
         * placed in the 'dst_port' field. */
        uint8_t type = ntohs(expired->flow.tp_src);
        uint8_t code = ntohs(expired->flow.tp_dst);
        nf_rec->src_port = htons(0);
        nf_rec->dst_port = htons((type << 8) | code);
    } else {
        nf_rec->src_port = expired->flow.tp_src;
        nf_rec->dst_port = expired->flow.tp_dst;
    }
    nf_rec->tcp_flags = expired->tcp_flags;
    nf_rec->ip_proto = expired->flow.nw_proto;
    nf_rec->ip_tos = expired->ip_tos;

    /* NetFlow messages are limited to 30 records.  A length of 1400
     * bytes guarantees that the limit is not exceeded.  */
    if (nf->packet.size >= 1400) {
        netflow_run(nf);
    }
}

void
netflow_run(struct netflow *nf)
{
    size_t i;

    if (!nf->packet.size) {
        return;
    }

    for (i = 0; i < nf->n_fds; i++) {
        if (send(nf->fds[i], nf->packet.data, nf->packet.size, 0) == -1) {
            VLOG_WARN_RL(&rl, "netflow message send failed: %s",
                         strerror(errno));
        }
    }
    nf->packet.size = 0;
}

static void
clear_collectors(struct netflow *nf)
{
    size_t i;

    for (i = 0; i < nf->n_fds; i++) {
        close(nf->fds[i]);
    }
    free(nf->fds);
    nf->fds = NULL;
    nf->n_fds = 0;
}

int
netflow_set_collectors(struct netflow *nf, const struct svec *collectors_)
{
    struct svec collectors;
    int error = 0;
    size_t i;

    clear_collectors(nf);

    svec_clone(&collectors, collectors_);
    svec_sort_unique(&collectors);

    nf->fds = xmalloc(sizeof *nf->fds * collectors.n);
    for (i = 0; i < collectors.n; i++) {
        const char *name = collectors.names[i];
        char *tmpname = xstrdup(name);
        int fd = open_collector(tmpname);
        free(tmpname);
        if (fd >= 0) {
            nf->fds[nf->n_fds++] = fd;
        } else {
            VLOG_WARN("couldn't open connection to collector (%s), "
                      "ignoring %s\n", strerror(-fd), name);
            if (!error) {
                error = -fd;
            }
        }
    }

    svec_destroy(&collectors);
    return error;
}

void 
netflow_set_engine(struct netflow *nf, uint8_t engine_type, 
        uint8_t engine_id, bool add_id_to_iface)
{
    nf->engine_type = engine_type;
    nf->engine_id = engine_id;
    nf->add_id_to_iface = add_id_to_iface;
}

struct netflow *
netflow_create(void)
{
    struct netflow *nf = xmalloc(sizeof *nf);
    nf->engine_type = 0;
    nf->engine_id = 0;
    nf->boot_time = time_msec();
    nf->fds = NULL;
    nf->n_fds = 0;
    nf->add_id_to_iface = false;
    nf->netflow_cnt = 0;
    ofpbuf_init(&nf->packet, 1500);
    return nf;
}

void
netflow_destroy(struct netflow *nf)
{
    if (nf) {
        ofpbuf_uninit(&nf->packet);
        clear_collectors(nf);
        free(nf);
    }
}
