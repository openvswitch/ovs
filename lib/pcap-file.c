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
    uint32_t ts_usec;        /* timestamp microseconds */
    uint32_t incl_len;       /* number of octets of packet saved in file */
    uint32_t orig_len;       /* actual length of packet */
};
BUILD_ASSERT_DECL(sizeof(struct pcaprec_hdr) == 16);

FILE *
ovs_pcap_open(const char *file_name, const char *mode)
{
    struct stat s;
    FILE *file;
    int error;

    ovs_assert(!strcmp(mode, "rb") ||
               !strcmp(mode, "wb") ||
               !strcmp(mode, "ab"));

    file = fopen(file_name, mode);
    if (file == NULL) {
        VLOG_WARN("%s: failed to open pcap file for %s (%s)", file_name,
                  (mode[0] == 'r' ? "reading"
                   : mode[0] == 'w' ? "writing"
                   : "appending"),
                  ovs_strerror(errno));
        return NULL;
    }

    switch (mode[0]) {
    case 'r':
        error = ovs_pcap_read_header(file);
        if (error) {
            errno = error;
            fclose(file);
            return NULL;
        }
        break;

    case 'w':
        ovs_pcap_write_header(file);
        break;

    case 'a':
        if (!fstat(fileno(file), &s) && !s.st_size) {
            ovs_pcap_write_header(file);
        }
        break;

    default:
        OVS_NOT_REACHED();
    }
    return file;
}

int
ovs_pcap_read_header(FILE *file)
{
    struct pcap_hdr ph;
    if (fread(&ph, sizeof ph, 1, file) != 1) {
        int error = ferror(file) ? errno : EOF;
        VLOG_WARN("failed to read pcap header: %s", ovs_retval_to_string(error));
        return error;
    }
    if (ph.magic_number != 0xa1b2c3d4 && ph.magic_number != 0xd4c3b2a1) {
        VLOG_WARN("bad magic 0x%08"PRIx32" reading pcap file "
                  "(expected 0xa1b2c3d4 or 0xd4c3b2a1)", ph.magic_number);
        return EPROTO;
    }
    return 0;
}

void
ovs_pcap_write_header(FILE *file)
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
    ignore(fwrite(&ph, sizeof ph, 1, file));
    fflush(file);
}

int
ovs_pcap_read(FILE *file, struct dp_packet **bufp, long long int *when)
{
    struct pcaprec_hdr prh;
    struct dp_packet *buf;
    void *data;
    size_t len;
    bool swap;

    *bufp = NULL;

    /* Read header. */
    if (fread(&prh, sizeof prh, 1, file) != 1) {
        if (ferror(file)) {
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
            VLOG_WARN("bad packet length %"PRIuSIZE" or %"PRIu32
                      "reading pcap file",
                      len, uint32_byteswap(len));
            return EPROTO;
        }
    }

    /* Calculate time. */
    if (when) {
        uint32_t ts_sec = swap ? uint32_byteswap(prh.ts_sec) : prh.ts_sec;
        uint32_t ts_usec = swap ? uint32_byteswap(prh.ts_usec) : prh.ts_usec;
        *when = ts_sec * 1000LL + ts_usec / 1000;
    }

    /* Read packet. Packet type is Ethernet */
    buf = dp_packet_new(len);
    data = dp_packet_put_uninit(buf, len);
    if (fread(data, len, 1, file) != 1) {
        int error = ferror(file) ? errno : EOF;
        VLOG_WARN("failed to read pcap packet: %s",
                  ovs_retval_to_string(error));
        dp_packet_delete(buf);
        return error;
    }
    *bufp = buf;
    return 0;
}

void
ovs_pcap_write(FILE *file, struct dp_packet *buf)
{
    struct pcaprec_hdr prh;
    struct timeval tv;

    ovs_assert(buf->packet_type == htonl(PT_ETH));

    xgettimeofday(&tv);
    prh.ts_sec = tv.tv_sec;
    prh.ts_usec = tv.tv_usec;
    prh.incl_len = dp_packet_size(buf);
    prh.orig_len = dp_packet_size(buf);
    ignore(fwrite(&prh, sizeof prh, 1, file));
    ignore(fwrite(dp_packet_data(buf), dp_packet_size(buf), 1, file));
    fflush(file);
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
    l7_length = (char *) dp_packet_tail(packet) - l7;
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
