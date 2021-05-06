/*
 * Copyright (c) 2009, 2010, 2012, 2013, 2014, 2015 Nicira, Inc.
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

#include <config.h>
#include "pcap-file.h"
#include <errno.h>
#include <inttypes.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include "byte-order.h"
#include "compiler.h"
#include "dp-packet.h"
#include "flow.h"
#include "openvswitch/hmap.h"
#include "packets.h"
#include "timeval.h"
#include "unaligned.h"
#include "util.h"
#include "openvswitch/vlog.h"

VLOG_DEFINE_THIS_MODULE(pcap);

enum ts_resolution {
    PCAP_USEC,
    PCAP_NSEC,
};

enum network_type {
    PCAP_ETHERNET = 1,
    PCAP_LINUX_SLL = 0x71
};

struct pcap_file {
    FILE *file;
    enum ts_resolution resolution;
    enum network_type network;
};

struct pcap_hdr {
    uint32_t magic_number;   /* magic number */
    uint16_t version_major;  /* major version number */
    uint16_t version_minor;  /* minor version number */
    int32_t thiszone;        /* GMT to local correction */
    uint32_t sigfigs;        /* accuracy of timestamps */
    uint32_t snaplen;        /* max length of captured packets */
    uint32_t network;        /* data link type */
};
BUILD_ASSERT_DECL(sizeof(struct pcap_hdr) == 24);

struct pcaprec_hdr {
    uint32_t ts_sec;         /* timestamp seconds */
    uint32_t ts_subsec;      /* timestamp subseconds */
    uint32_t incl_len;       /* number of octets of packet saved in file */
    uint32_t orig_len;       /* actual length of packet */
};
BUILD_ASSERT_DECL(sizeof(struct pcaprec_hdr) == 16);

struct pcap_file *
ovs_pcap_open(const char *file_name, const char *mode)
{
    struct stat s;
    struct pcap_file *p_file;
    int error;

    ovs_assert(!strcmp(mode, "rb") ||
               !strcmp(mode, "wb") ||
               !strcmp(mode, "ab"));

    p_file = xmalloc(sizeof *p_file);
    p_file->file = fopen(file_name, mode);
    p_file->resolution = PCAP_USEC;
    if (p_file->file == NULL) {
        VLOG_WARN("%s: failed to open pcap file for %s (%s)", file_name,
                  (mode[0] == 'r' ? "reading"
                   : mode[0] == 'w' ? "writing"
                   : "appending"),
                  ovs_strerror(errno));
        return NULL;
    }

    switch (mode[0]) {
    case 'r':
        error = ovs_pcap_read_header(p_file);
        if (error) {
            errno = error;
            ovs_pcap_close(p_file);
            return NULL;
        }
        break;

    case 'w':
        ovs_pcap_write_header(p_file);
        break;

    case 'a':
        if (!fstat(fileno(p_file->file), &s) && !s.st_size) {
            ovs_pcap_write_header(p_file);
        }
        break;

    default:
        OVS_NOT_REACHED();
    }

    return p_file;
}

struct pcap_file *
ovs_pcap_stdout(void)
{
    struct pcap_file *p_file = xmalloc(sizeof *p_file);
    p_file->file = stdout;
    return p_file;
}

int
ovs_pcap_read_header(struct pcap_file *p_file)
{
    struct pcap_hdr ph;
    if (fread(&ph, sizeof ph, 1, p_file->file) != 1) {
        int error = ferror(p_file->file) ? errno : EOF;
        VLOG_WARN("failed to read pcap header: %s", ovs_retval_to_string(error));
        return error;
    }
    bool byte_swap;
    if (ph.magic_number == 0xa1b2c3d4 || ph.magic_number == 0xd4c3b2a1) {
        byte_swap = ph.magic_number == 0xd4c3b2a1;
        p_file->resolution = PCAP_USEC;
    } else if (ph.magic_number == 0xa1b23c4d ||
               ph.magic_number == 0x4d3cb2a1) {
        byte_swap = ph.magic_number == 0x4d3cb2a1;
        p_file->resolution = PCAP_NSEC;
    } else {
        VLOG_WARN("bad magic 0x%08"PRIx32" reading pcap file "
                  "(expected 0xa1b2c3d4, 0xa1b23c4d, 0xd4c3b2a1, "
                  "or 0x4d3cb2a1)", ph.magic_number);
        return EPROTO;
    }
    p_file->network = byte_swap ? uint32_byteswap(ph.network) : ph.network;
    if (p_file->network != PCAP_ETHERNET &&
        p_file->network != PCAP_LINUX_SLL) {
        VLOG_WARN("unknown network type %u reading pcap file",
                  (unsigned int) p_file->network);
        return EPROTO;
    }
    return 0;
}

void
ovs_pcap_write_header(struct pcap_file *p_file)
{
    /* The pcap reader is responsible for figuring out endianness based on the
     * magic number, so the lack of htonX calls here is intentional. */
    struct pcap_hdr ph;
    ph.magic_number = 0xa1b2c3d4;
    ph.version_major = 2;
    ph.version_minor = 4;
    ph.thiszone = 0;
    ph.sigfigs = 0;
    ph.snaplen = 1518;
    ph.network = 1;             /* Ethernet */
    ignore(fwrite(&ph, sizeof ph, 1, p_file->file));
    fflush(p_file->file);
}

int
ovs_pcap_read(struct pcap_file *p_file, struct dp_packet **bufp,
              long long int *when)
{
    struct pcaprec_hdr prh;
    struct dp_packet *buf;
    void *data;
    size_t len;
    bool swap;

    *bufp = NULL;

    /* Read header. */
    if (fread(&prh, sizeof prh, 1, p_file->file) != 1) {
        if (ferror(p_file->file)) {
            int error = errno;
            VLOG_WARN("failed to read pcap record header: %s",
                      ovs_retval_to_string(error));
            return error;
        } else {
            return EOF;
        }
    }

    /* Calculate length. */
    len = prh.incl_len;
    swap = len > 0xffff;
    if (swap) {
        len = uint32_byteswap(len);
        if (len > 0xffff) {
            VLOG_WARN("bad packet length %"PRIuSIZE" or %"PRIu32" "
                      "reading pcap file",
                      len, uint32_byteswap(len));
            return EPROTO;
        }
    }

    /* Calculate time. */
    if (when) {
        uint32_t ts_sec = swap ? uint32_byteswap(prh.ts_sec) : prh.ts_sec;
        uint32_t ts_subsec = swap ? uint32_byteswap(prh.ts_subsec)
                                  : prh.ts_subsec;
        ts_subsec = p_file->resolution == PCAP_USEC ? ts_subsec / 1000
                                                    : ts_subsec / 1000000;
        *when = ts_sec * 1000LL + ts_subsec;
    }

    /* Read packet. Packet type is Ethernet */
    buf = dp_packet_new(len);
    data = dp_packet_put_uninit(buf, len);
    if (fread(data, len, 1, p_file->file) != 1) {
        int error = ferror(p_file->file) ? errno : EOF;
        VLOG_WARN("failed to read pcap packet: %s",
                  ovs_retval_to_string(error));
        dp_packet_delete(buf);
        return error;
    }

    if (p_file->network == PCAP_LINUX_SLL) {
        /* This format doesn't include the destination Ethernet address, which
         * is weird. */

        struct sll_header {
            ovs_be16 packet_type;
            ovs_be16 arp_hrd;
            ovs_be16 lla_len;
            struct eth_addr dl_src;
            ovs_be16 reserved;
            ovs_be16 protocol;
        };
        const struct sll_header *sll;
        if (len < sizeof *sll) {
            VLOG_WARN("pcap packet too short for SLL header");
            dp_packet_delete(buf);
            return EPROTO;
        }

        /* Pull Linux SLL header. */
        sll = dp_packet_pull(buf, sizeof *sll);
        if (sll->lla_len != htons(6)) {
            ovs_hex_dump(stdout, sll, sizeof *sll, 0, false);
            VLOG_WARN("bad SLL header");
            dp_packet_delete(buf);
            return EPROTO;
        }

        /* Push Ethernet header. */
        struct eth_header eth = {
            /* eth_dst is all zeros because the format doesn't include it. */
            .eth_src = sll->dl_src,
            .eth_type = sll->protocol,
        };
        dp_packet_push(buf, &eth, sizeof eth);
    }

    *bufp = buf;
    return 0;
}

void
ovs_pcap_write(struct pcap_file *p_file, struct dp_packet *buf)
{
    struct pcaprec_hdr prh;
    struct timeval tv;

    ovs_assert(dp_packet_is_eth(buf));

    xgettimeofday(&tv);
    prh.ts_sec = tv.tv_sec;
    prh.ts_subsec = tv.tv_usec;
    prh.incl_len = dp_packet_size(buf);
    prh.orig_len = dp_packet_size(buf);
    ignore(fwrite(&prh, sizeof prh, 1, p_file->file));
    ignore(fwrite(dp_packet_data(buf), dp_packet_size(buf), 1, p_file->file));
    fflush(p_file->file);
}

void
ovs_pcap_close(struct pcap_file *p_file)
{
    if (p_file->file != stdout) {
        fclose(p_file->file);
    }
    free(p_file);
}

struct tcp_key {
    ovs_be32 nw_src, nw_dst;
    ovs_be16 tp_src, tp_dst;
};

struct tcp_stream {
    struct hmap_node hmap_node;
    struct tcp_key key;
    uint32_t seq_no;
    struct dp_packet payload;
};

struct tcp_reader {
    struct hmap streams;
};

static void
tcp_stream_destroy(struct tcp_reader *r, struct tcp_stream *stream)
{
    hmap_remove(&r->streams, &stream->hmap_node);
    dp_packet_uninit(&stream->payload);
    free(stream);
}

/* Returns a new data structure for extracting TCP stream data from an
 * Ethernet packet capture */
struct tcp_reader *
tcp_reader_open(void)
{
    struct tcp_reader *r;

    r = xmalloc(sizeof *r);
    hmap_init(&r->streams);
    return r;
}

/* Closes and frees 'r'. */
void
tcp_reader_close(struct tcp_reader *r)
{
    struct tcp_stream *stream, *next_stream;

    HMAP_FOR_EACH_SAFE (stream, next_stream, hmap_node, &r->streams) {
        tcp_stream_destroy(r, stream);
    }
    hmap_destroy(&r->streams);
    free(r);
}

static struct tcp_stream *
tcp_stream_lookup(struct tcp_reader *r,
                  const struct tcp_key *key, uint32_t hash)
{
    struct tcp_stream *stream;

    HMAP_FOR_EACH_WITH_HASH (stream, hmap_node, hash, &r->streams) {
        if (!memcmp(&stream->key, key, sizeof *key)) {
            return stream;
        }
    }
    return NULL;
}

static struct tcp_stream *
tcp_stream_new(struct tcp_reader *r, const struct tcp_key *key, uint32_t hash)
{
    struct tcp_stream *stream;

    stream = xmalloc(sizeof *stream);
    hmap_insert(&r->streams, &stream->hmap_node, hash);
    memcpy(&stream->key, key, sizeof *key);
    stream->seq_no = 0;
    dp_packet_init(&stream->payload, 2048);
    return stream;
}

/* Processes 'packet' through TCP reader 'r'.  The caller must have already
 * extracted the packet's headers into 'flow', using flow_extract().
 *
 * If 'packet' is a TCP packet, then the reader attempts to reconstruct the
 * data stream.  If successful, it returns an dp_packet that represents the data
 * stream so far.  The caller may examine the data in the dp_packet and pull off
 * any data that it has fully processed.  The remaining data that the caller
 * does not pull off will be presented again in future calls if more data
 * arrives in the stream.
 *
 * Returns null if 'packet' doesn't add new data to a TCP stream. */
struct dp_packet *
tcp_reader_run(struct tcp_reader *r, const struct flow *flow,
               const struct dp_packet *packet)
{
    struct tcp_stream *stream;
    struct tcp_header *tcp;
    struct dp_packet *payload;
    unsigned int l7_length;
    struct tcp_key key;
    uint32_t hash;
    uint32_t seq;
    uint8_t flags;
    const char *l7 = dp_packet_get_tcp_payload(packet);

    if (flow->dl_type != htons(ETH_TYPE_IP)
        || flow->nw_proto != IPPROTO_TCP
        || !l7) {
        return NULL;
    }
    tcp = dp_packet_l4(packet);
    flags = TCP_FLAGS(tcp->tcp_ctl);
    l7_length = dp_packet_get_tcp_payload_length(packet);
    seq = ntohl(get_16aligned_be32(&tcp->tcp_seq));

    /* Construct key. */
    memset(&key, 0, sizeof key);
    key.nw_src = flow->nw_src;
    key.nw_dst = flow->nw_dst;
    key.tp_src = flow->tp_src;
    key.tp_dst = flow->tp_dst;
    hash = hash_bytes(&key, sizeof key, 0);

    /* Find existing stream or start a new one for a SYN or if there's data. */
    stream = tcp_stream_lookup(r, &key, hash);
    if (!stream) {
        if (flags & TCP_SYN || l7_length) {
            stream = tcp_stream_new(r, &key, hash);
            stream->seq_no = flags & TCP_SYN ? seq + 1 : seq;
        } else {
            return NULL;
        }
    }

    payload = &stream->payload;
    if (flags & TCP_SYN || !stream->seq_no) {
        dp_packet_clear(payload);
        stream->seq_no = seq + 1;
        return NULL;
    } else if (flags & (TCP_FIN | TCP_RST)) {
        tcp_stream_destroy(r, stream);
        return NULL;
    } else if (seq == stream->seq_no) {
        /* Shift all of the existing payload to the very beginning of the
         * allocated space, so that we reuse allocated space instead of
         * continually expanding it. */
        dp_packet_shift(payload, (char *) dp_packet_base(payload) - (char *) dp_packet_data(payload));

        dp_packet_put(payload, l7, l7_length);
        stream->seq_no += l7_length;
        return payload;
    } else {
        return NULL;
    }
}
