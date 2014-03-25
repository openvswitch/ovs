/*
 * Copyright (c) 2009, 2010, 2012, 2013 Nicira, Inc.
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
#include "flow.h"
#include "hmap.h"
#include "ofpbuf.h"
#include "packets.h"
#include "timeval.h"
#include "unaligned.h"
#include "vlog.h"

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
pcap_open(const char *file_name, const char *mode)
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
        error = pcap_read_header(file);
        if (error) {
            errno = error;
            fclose(file);
            return NULL;
        }
        break;

    case 'w':
        pcap_write_header(file);
        break;

    case 'a':
        if (!fstat(fileno(file), &s) && !s.st_size) {
            pcap_write_header(file);
        }
        break;

    default:
        OVS_NOT_REACHED();
    }
    return file;
}

int
pcap_read_header(FILE *file)
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
pcap_write_header(FILE *file)
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
}

int
pcap_read(FILE *file, struct ofpbuf **bufp, long long int *when)
{
    struct pcaprec_hdr prh;
    struct ofpbuf *buf;
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

    /* Read packet. */
    buf = ofpbuf_new(len);
    data = ofpbuf_put_uninit(buf, len);
    if (fread(data, len, 1, file) != 1) {
        int error = ferror(file) ? errno : EOF;
        VLOG_WARN("failed to read pcap packet: %s",
                  ovs_retval_to_string(error));
        ofpbuf_delete(buf);
        return error;
    }
    *bufp = buf;
    return 0;
}

void
pcap_write(FILE *file, struct ofpbuf *buf)
{
    struct pcaprec_hdr prh;
    struct timeval tv;

    xgettimeofday(&tv);
    prh.ts_sec = tv.tv_sec;
    prh.ts_usec = tv.tv_usec;
    prh.incl_len = buf->size;
    prh.orig_len = buf->size;
    ignore(fwrite(&prh, sizeof prh, 1, file));
    ignore(fwrite(buf->data, buf->size, 1, file));
}

struct tcp_key {
    ovs_be32 nw_src, nw_dst;
    ovs_be16 tp_src, tp_dst;
};

struct tcp_stream {
    struct hmap_node hmap_node;
    struct tcp_key key;
    uint32_t seq_no;
    struct ofpbuf payload;
};

struct tcp_reader {
    struct hmap streams;
};

static void
tcp_stream_destroy(struct tcp_reader *r, struct tcp_stream *stream)
{
    hmap_remove(&r->streams, &stream->hmap_node);
    ofpbuf_uninit(&stream->payload);
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
tcp_stream_lookup(struct tcp_reader *r, const struct flow *flow)
{
    struct tcp_stream *stream;
    struct tcp_key key;
    uint32_t hash;

    memset(&key, 0, sizeof key);
    key.nw_src = flow->nw_src;
    key.nw_dst = flow->nw_dst;
    key.tp_src = flow->tp_src;
    key.tp_dst = flow->tp_dst;
    hash = hash_bytes(&key, sizeof key, 0);

    HMAP_FOR_EACH_WITH_HASH (stream, hmap_node, hash, &r->streams) {
        if (!memcmp(&stream->key, &key, sizeof key)) {
            return stream;
        }
    }

    stream = xmalloc(sizeof *stream);
    hmap_insert(&r->streams, &stream->hmap_node, hash);
    memcpy(&stream->key, &key, sizeof key);
    stream->seq_no = 0;
    ofpbuf_init(&stream->payload, 2048);
    return stream;
}

/* Processes 'packet' through TCP reader 'r'.  The caller must have already
 * extracted the packet's headers into 'flow', using flow_extract().
 *
 * If 'packet' is a TCP packet, then the reader attempts to reconstruct the
 * data stream.  If successful, it returns an ofpbuf that represents the data
 * stream so far.  The caller may examine the data in the ofpbuf and pull off
 * any data that it has fully processed.  The remaining data that the caller
 * does not pull off will be presented again in future calls if more data
 * arrives in the stream.
 *
 * Returns null if 'packet' doesn't add new data to a TCP stream. */
struct ofpbuf *
tcp_reader_run(struct tcp_reader *r, const struct flow *flow,
               const struct ofpbuf *packet)
{
    struct tcp_stream *stream;
    struct tcp_header *tcp;
    struct ofpbuf *payload;
    uint32_t seq;
    uint8_t flags;

    if (flow->dl_type != htons(ETH_TYPE_IP)
        || flow->nw_proto != IPPROTO_TCP
        || !packet->l7) {
        return NULL;
    }

    stream = tcp_stream_lookup(r, flow);
    payload = &stream->payload;

    tcp = packet->l4;
    flags = TCP_FLAGS(tcp->tcp_ctl);
    seq = ntohl(get_16aligned_be32(&tcp->tcp_seq));
    if (flags & TCP_SYN) {
        ofpbuf_clear(payload);
        stream->seq_no = seq + 1;
        return NULL;
    } else if (flags & (TCP_FIN | TCP_RST)) {
        tcp_stream_destroy(r, stream);
        return NULL;
    } else if (seq == stream->seq_no) {
        size_t length;

        /* Shift all of the existing payload to the very beginning of the
         * allocated space, so that we reuse allocated space instead of
         * continually expanding it. */
        ofpbuf_shift(payload, (char *) payload->base - (char *) payload->data);

        length = (char *) ofpbuf_tail(packet) - (char *) packet->l7;
        ofpbuf_put(payload, packet->l7, length);
        stream->seq_no += length;
        return payload;
    } else {
        return NULL;
    }
}
