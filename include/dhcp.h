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

#ifndef DHCP_H
#define DHCP_H 1

#include <stdint.h>
#include "packets.h"
#include "util.h"

struct ds;
struct ofpbuf;

/* Values for 'op' field. */
#define DHCP_BOOTREQUEST        1        /* Message sent by DHCP client. */
#define DHCP_BOOTREPLY          2        /* Message sent by DHCP server. */

/* Bits in 'flags' field. */
#define DHCP_FLAGS_BROADCAST    0x8000 /* Server must broadcast all replies. */
#define DHCP_FLAGS_MBZ          0x7fff /* Must be zero. */

/* First four bytes of 'options' field. */
#define DHCP_OPTS_COOKIE 0x63825363

#define DHCP_HEADER_LEN 236
struct dhcp_header {
    uint8_t op;                 /* DHCP_BOOTREQUEST or DHCP_BOOTREPLY. */
    uint8_t htype;              /* ARP_HRD_ETHERNET (typically). */
    uint8_t hlen;               /* ETH_ADDR_LEN (typically). */
    uint8_t hops;               /* Hop count; set to 0 by client. */
    uint32_t xid;               /* Transaction ID. */
    uint16_t secs;              /* Since client started address acquisition. */
    uint16_t flags;             /* DHCP_FLAGS_*. */
    uint32_t ciaddr;            /* Client IP, if it has a lease for one. */
    uint32_t yiaddr;            /* Client ("your") IP address. */
    uint32_t siaddr;            /* Next server IP address. */
    uint32_t giaddr;            /* Relay agent IP address. */
    uint8_t chaddr[16];         /* Client hardware address. */
    char sname[64];             /* Optional server host name. */
    char file[128];             /* Boot file name. */
    /* Followed by variable-length options field. */
};
BUILD_ASSERT_DECL(DHCP_HEADER_LEN == sizeof(struct dhcp_header));

#define DHCP_ARGS                                                             \
    DHCP_ARG(FIXED, 0)          /* Fixed-length option (PAD and END only). */ \
    DHCP_ARG(IP, 4)             /* IP addresses. */                           \
    DHCP_ARG(SECS, 4)           /* 32-bit duration in seconds. */             \
    DHCP_ARG(STRING, 1)         /* NVT string, optionally null-terminated. */ \
    DHCP_ARG(UINT8, 1)          /* 8-bit unsigned integer. */                 \
    DHCP_ARG(UINT16, 2)         /* 16-bit unsigned integer. */                \
    DHCP_ARG(UINT32, 4)         /* 32-bit unsigned integer. */                \
    DHCP_ARG(BOOLEAN, 1)        /* Boolean octet (0 or 1). */

/* DHCP option argument types. */
enum dhcp_arg_type {
#define DHCP_ARG(NAME, SIZE) DHCP_ARG_##NAME,
    DHCP_ARGS
#undef DHCP_ARG
};

#define DHCP_MSGS                                                             \
    DHCP_MSG(DHCPDISCOVER, 1)   /* Client->server: What IPs are available? */ \
    DHCP_MSG(DHCPOFFER, 2)      /* Server->client: This IP is available. */   \
    DHCP_MSG(DHCPREQUEST, 3)    /* Client->server: I want that IP. */         \
    DHCP_MSG(DHCPDECLINE, 4)    /* Client->server: That IP is in use!. */     \
    DHCP_MSG(DHCPACK, 5)        /* Server->client: You can have that IP. */   \
    DHCP_MSG(DHCPNAK, 6)        /* Server->client: You can't have that IP. */ \
    DHCP_MSG(DHCPRELEASE, 7)    /* Client->server: I'm done with this IP. */  \
    DHCP_MSG(DCHPINFORM, 8)     /* Client->server: I'm using this IP. */

/* DHCP message type (this is the argument for the DHCP_MSG_TYPE option). */
enum dhcp_msg_type {
#define DHCP_MSG(NAME, VALUE) NAME = VALUE,
    DHCP_MSGS
#undef DHCP_MSG
};
const char *dhcp_type_name(enum dhcp_msg_type);

/* DHCP allows for 256 standardized options and 256 vendor-specific options.
 * We put them in a single array, with the standard options at the
 * beginning. */
#define DHCP_N_OPTIONS          512
#define DHCP_VENDOR_OFS         256

/* DHCP options. */
#define DHCP_OPTS                                                       \
    /*                                        arg   min  max         */ \
    /*          name                    code  type  args args        */ \
    DHCP_OPT(PAD,                       0, FIXED,   0, 0)               \
    DHCP_OPT(END,                     255, FIXED,   0, 0)               \
    DHCP_OPT(SUBNET_MASK,               1, IP,      1, 1)               \
    DHCP_OPT(TIME_OFFSET,               2, SECS,    1, 1)               \
    DHCP_OPT(ROUTER,                    3, IP,      1, SIZE_MAX)        \
    /* Time Server Option is obsolete. */                               \
    /* Name Server Option is obsolete. */                               \
    DHCP_OPT(DNS_SERVER,                6, IP,      1, SIZE_MAX)        \
    /* Log Server Option is obsolete. */                                \
    /* Cookie Server Option is obsolete. */                             \
    DHCP_OPT(LPR_SERVER,                9, IP,      1, SIZE_MAX)        \
    /* Impress Server Option is obsolete. */                            \
    /* Resource Location Server Option is obsolete. */                  \
    DHCP_OPT(HOST_NAME,                12, STRING,  1, SIZE_MAX)        \
    DHCP_OPT(BOOT_FILE_SIZE,           13, UINT16,  1, 1)               \
    /* Merit Dump File option is obsolete. */                           \
    DHCP_OPT(DOMAIN_NAME,              15, STRING,  1, SIZE_MAX)        \
    /* Swap Server option is obsolete. */                               \
    DHCP_OPT(ROOT_PATH,                17, STRING,  1, SIZE_MAX)        \
    DHCP_OPT(EXTENSIONS_PATH,          18, STRING,  1, SIZE_MAX)        \
    DHCP_OPT(IP_FORWARDING,            19, BOOLEAN, 1, 1)               \
    DHCP_OPT(SOURCE_ROUTING,           20, BOOLEAN, 1, 1)               \
    DHCP_OPT(POLICY_FILTER,            21, IP,      2, SIZE_MAX)        \
    DHCP_OPT(MAX_DGRAM_REASSEMBLY,     22, UINT16,  1, 1)               \
    DHCP_OPT(IP_TTL,                   23, UINT8,   1, 1)               \
    DHCP_OPT(PATH_MTU_TIMEOUT,         24, SECS,    1, 1)               \
    DHCP_OPT(PATH_MTU_PLATEAU,         25, UINT16,  2, SIZE_MAX)        \
    DHCP_OPT(MTU,                      26, UINT16,  1, 1)               \
    DHCP_OPT(ALL_SUBNETS_ARE_LOCAL,    27, BOOLEAN, 1, 1)               \
    DHCP_OPT(BROADCAST_ADDRESS,        28, IP,      1, 1)               \
    DHCP_OPT(PERFORM_MASK_DISCOVERY,   29, BOOLEAN, 1, 1)               \
    DHCP_OPT(MASK_SUPPLIER,            30, BOOLEAN, 1, 1)               \
    DHCP_OPT(PERFORM_ROUTER_DISCOVERY, 31, BOOLEAN, 1, 1)               \
    DHCP_OPT(ROUTER_SOLICITATION,      32, IP,      1, 1)               \
    DHCP_OPT(STATIC_ROUTE,             33, IP,      2, SIZE_MAX)        \
    /* Trailer Encapsulation Option is obsolete. */                     \
    DHCP_OPT(ARP_CACHE_TIMEOUT,        35, SECS,    1, 1)               \
    DHCP_OPT(ETHERNET_ENCAPSULATION,   36, BOOLEAN, 1, 1)               \
    DHCP_OPT(TCP_TTL,                  37, UINT8,   1, 1)               \
    DHCP_OPT(TCP_KEEPALIVE_INTERVAL,   38, SECS,    1, 1)               \
    DHCP_OPT(TCP_KEEPALIVE_GARBAGE,    39, BOOLEAN, 1, 1)               \
    DHCP_OPT(NIS_DOMAIN,               40, STRING,  1, SIZE_MAX)        \
    DHCP_OPT(NIS_SERVERS,              41, IP,      1, SIZE_MAX)        \
    DHCP_OPT(NTP_SERVERS,              42, IP,      1, SIZE_MAX)        \
    DHCP_OPT(VENDOR_SPECIFIC,          43, UINT8,   1, SIZE_MAX)        \
    DHCP_OPT(NETBIOS_NS,               44, IP,      1, SIZE_MAX)        \
    DHCP_OPT(NETBIOS_DDS,              45, IP,      1, SIZE_MAX)        \
    DHCP_OPT(NETBIOS_NODE_TYPE,        46, UINT8,   1, 1)               \
    DHCP_OPT(NETBIOS_SCOPE,            47, STRING,  1, SIZE_MAX)        \
    DHCP_OPT(X_FONT_SERVER,            48, IP,      1, SIZE_MAX)        \
    DHCP_OPT(XDM,                      49, IP,      1, SIZE_MAX)        \
    DHCP_OPT(NISPLUS_DOMAIN,           64, STRING,  1, SIZE_MAX)        \
    DHCP_OPT(NISPLUS_SERVERS,          65, IP,      1, SIZE_MAX)        \
    DHCP_OPT(MOBILE_IP_HOME_AGENT,     68, IP,      0, SIZE_MAX)        \
    DHCP_OPT(SMTP_SERVER,              69, IP,      1, SIZE_MAX)        \
    DHCP_OPT(POP3_SERVER,              70, IP,      1, SIZE_MAX)        \
    DHCP_OPT(NNTP_SERVER,              71, IP,      1, SIZE_MAX)        \
    DHCP_OPT(WWW_SERVER,               72, IP,      1, SIZE_MAX)        \
    DHCP_OPT(FINGER_SERVER,            73, IP,      1, SIZE_MAX)        \
    DHCP_OPT(IRC_SERVER,               74, IP,      1, SIZE_MAX)        \
    /* StreetTalk Server Option is obsolete. */                         \
    /* StreetTalk Directory Assistance Server Option is obsolete. */    \
    DHCP_OPT(REQUESTED_IP,             50, IP,      1, 1)               \
    DHCP_OPT(LEASE_TIME,               51, SECS,    1, 1)               \
    DHCP_OPT(OPTION_OVERLOAD,          52, UINT8,   1, 1)               \
    DHCP_OPT(TFTP_SERVER,              66, STRING,  1, SIZE_MAX)        \
    DHCP_OPT(BOOTFILE_NAME,            67, STRING,  1, SIZE_MAX)        \
    DHCP_OPT(DHCP_MSG_TYPE,            53, UINT8,   1, 1)               \
    DHCP_OPT(SERVER_IDENTIFIER,        54, IP,      1, 1)               \
    DHCP_OPT(PARAMETER_REQUEST_LIST,   55, UINT8,   1, SIZE_MAX)        \
    DHCP_OPT(MESSAGE,                  56, STRING,  1, SIZE_MAX)        \
    DHCP_OPT(MAX_DHCP_MSG_SIZE,        57, UINT16,  1, 1)               \
    DHCP_OPT(T1,                       58, SECS,    1, 1)               \
    DHCP_OPT(T2,                       59, SECS,    1, 1)               \
    DHCP_OPT(VENDOR_CLASS,             60, STRING,  1, SIZE_MAX)        \
    DHCP_OPT(CLIENT_ID,                61, UINT8,   2, SIZE_MAX)        \
    DHCP_VNDOPT(OFP_CONTROLLER_VCONN,   1, STRING,  1, SIZE_MAX)        \
    DHCP_VNDOPT(OFP_PKI_URI,            2, STRING,  1, SIZE_MAX)

/* Shorthand for defining vendor options (used above). */
#define DHCP_VNDOPT(NAME, CODE, ARG, MIN, MAX) \
    DHCP_OPT(NAME, (CODE) + DHCP_VENDOR_OFS, ARG, MIN, MAX)

/* DHCP option codes. */
enum {
#define DHCP_OPT(NAME, VALUE, ARGTYPE, MIN_ARGS, MAX_ARGS) \
    DHCP_CODE_##NAME = VALUE,
DHCP_OPTS
#undef DHCP_OPT
};

/* The contents of a DHCP option.
 *
 * DHCP options can (rarely) be present but lack content.  To represent such an
 * option, 'n' is 0 and 'data' is non-null (but does not point to anything
 * useful).  */
struct dhcp_option {
    size_t n;                   /* Number of bytes of data. */
    void *data;                 /* Data. */
};

const char *dhcp_option_to_string(const struct dhcp_option *, int code,
                                  struct ds *);
bool dhcp_option_equals(const struct dhcp_option *,
                        const struct dhcp_option *);

/* Abstracted DHCP protocol message, to make them easier to manipulate than
 * through raw protocol buffers. */
struct dhcp_msg {
    /* For use by calling code. */
    uint8_t op;                 /* DHCP_BOOTREQUEST or DHCP_BOOTREPLY. */
    uint32_t xid;               /* Transaction ID. */
    uint16_t secs;              /* Since client started address acquisition. */
    uint16_t flags;             /* DHCP_FLAGS_*. */
    uint32_t ciaddr;            /* Client IP, if it has a lease for one. */
    uint32_t yiaddr;            /* Client ("your") IP address. */
    uint32_t siaddr;            /* Next server IP address. */
    uint32_t giaddr;            /* Relay agent IP address. */
    uint8_t chaddr[ETH_ADDR_LEN]; /* Client hardware address. */
    enum dhcp_msg_type type;    /* DHCP_CODE_DHCP_MSG_TYPE option argument. */
    struct dhcp_option options[DHCP_N_OPTIONS]; /* Indexed by option code. */

    /* For direct use only by dhcp_msg_*() functions. */
    uint8_t *data;
    size_t data_used, data_allocated;
};

void dhcp_msg_init(struct dhcp_msg *);
void dhcp_msg_uninit(struct dhcp_msg *);
void dhcp_msg_copy(struct dhcp_msg *, const struct dhcp_msg *);
void dhcp_msg_put(struct dhcp_msg *, int code, const void *, size_t);
void dhcp_msg_put_bool(struct dhcp_msg *, int code, bool);
void dhcp_msg_put_secs(struct dhcp_msg *, int code, uint32_t);
void dhcp_msg_put_ip(struct dhcp_msg *, int code, uint32_t);
void dhcp_msg_put_string(struct dhcp_msg *, int code, const char *);
void dhcp_msg_put_uint8(struct dhcp_msg *, int code, uint8_t);
void dhcp_msg_put_uint8_array(struct dhcp_msg *, int code,
                              const uint8_t[], size_t n);
void dhcp_msg_put_uint16(struct dhcp_msg *, int code, uint16_t);
void dhcp_msg_put_uint16_array(struct dhcp_msg *, int code,
                               const uint16_t[], size_t n);
const void *dhcp_msg_get(const struct dhcp_msg *, int code, size_t offset,
                         size_t size);
bool dhcp_msg_get_bool(const struct dhcp_msg *, int code,
                       size_t offset, bool *);
bool dhcp_msg_get_secs(const struct dhcp_msg *, int code,
                       size_t offset, uint32_t *);
bool dhcp_msg_get_ip(const struct dhcp_msg *, int code,
                     size_t offset, uint32_t *);
char *dhcp_msg_get_string(const struct dhcp_msg *, int code);
bool dhcp_msg_get_uint8(const struct dhcp_msg *, int code,
                        size_t offset, uint8_t *);
bool dhcp_msg_get_uint16(const struct dhcp_msg *, int code,
                         size_t offset, uint16_t *);
const char *dhcp_msg_to_string(const struct dhcp_msg *, bool multiline,
                               struct ds *);
int dhcp_parse(struct dhcp_msg *, const struct ofpbuf *);
void dhcp_assemble(const struct dhcp_msg *, struct ofpbuf *);

#endif /* dhcp.h */
