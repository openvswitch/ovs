/* Copyright (c) 2002-2009 InMon Corp. Licensed under the terms of either the
 *   Sun Industry Standards Source License 1.1, that is available at:
 *    http://host-sflow.sourceforge.net/sissl.html
 * or the InMon sFlow License, that is available at:
 *    http://www.inmon.com/technology/sflowlicense.txt
 */

#ifndef SFLOW_H
#define SFLOW_H 1

#ifdef _WIN32
#include "windefs.h"
#endif

typedef enum {
    SFL_DSCLASS_IFINDEX = 0,
    SFL_DSCLASS_VLAN = 1,
    SFL_DSCLASS_PHYSICAL_ENTITY = 2,
    SFL_DSCLASS_LOGICAL_ENTITY = 3
} SFL_DSCLASS;

enum SFLAddress_type {
    SFLADDRESSTYPE_IP_V4 = 1,
    SFLADDRESSTYPE_IP_V6 = 2
};

typedef struct {
    u_int32_t addr;
} SFLIPv4;

typedef struct {
    u_char addr[16];
} SFLIPv6;

typedef union _SFLAddress_value {
    SFLIPv4 ip_v4;
    SFLIPv6 ip_v6;
} SFLAddress_value;

typedef struct _SFLAddress {
    u_int32_t type;           /* enum SFLAddress_type */
    SFLAddress_value address;
} SFLAddress;

/* Packet header data */

#define SFL_DEFAULT_HEADER_SIZE 128
#define SFL_DEFAULT_COLLECTOR_PORT 6343
#define SFL_DEFAULT_SAMPLING_RATE 400
#define SFL_DEFAULT_POLLING_INTERVAL 30

/* The header protocol describes the format of the sampled header */
enum SFLHeader_protocol {
    SFLHEADER_ETHERNET_ISO8023     = 1,
    SFLHEADER_ISO88024_TOKENBUS    = 2,
    SFLHEADER_ISO88025_TOKENRING   = 3,
    SFLHEADER_FDDI                 = 4,
    SFLHEADER_FRAME_RELAY          = 5,
    SFLHEADER_X25                  = 6,
    SFLHEADER_PPP                  = 7,
    SFLHEADER_SMDS                 = 8,
    SFLHEADER_AAL5                 = 9,
    SFLHEADER_AAL5_IP              = 10, /* e.g. Cisco AAL5 mux */
    SFLHEADER_IPv4                 = 11,
    SFLHEADER_IPv6                 = 12,
    SFLHEADER_MPLS                 = 13
};

/* raw sampled header */

typedef struct _SFLSampled_header {
    u_int32_t header_protocol;            /* (enum SFLHeader_protocol) */
    u_int32_t frame_length;               /* Original length of packet before sampling */
    u_int32_t stripped;                   /* header/trailer bytes stripped by sender */
    u_int32_t header_length;              /* length of sampled header bytes to follow */
    u_int8_t *header_bytes;               /* Header bytes */
} SFLSampled_header;

/* decoded ethernet header */

typedef struct _SFLSampled_ethernet {
    u_int32_t eth_len;       /* The length of the MAC packet excluding
				lower layer encapsulations */
    u_int8_t src_mac[8];    /* 6 bytes + 2 pad */
    u_int8_t dst_mac[8];
    u_int32_t eth_type;
} SFLSampled_ethernet;

/* decoded IP version 4 header */

typedef struct _SFLSampled_ipv4 {
    u_int32_t length;      /* The length of the IP packet
			      excluding lower layer encapsulations */
    u_int32_t protocol;    /* IP Protocol type (for example, TCP = 6, UDP = 17) */
    SFLIPv4   src_ip;      /* Source IP Address */
    SFLIPv4   dst_ip;      /* Destination IP Address */
    u_int32_t src_port;    /* TCP/UDP source port number or equivalent */
    u_int32_t dst_port;    /* TCP/UDP destination port number or equivalent */
    u_int32_t tcp_flags;   /* TCP flags */
    u_int32_t tos;         /* IP type of service */
} SFLSampled_ipv4;

/* decoded IP version 6 data */

typedef struct _SFLSampled_ipv6 {
    u_int32_t length;       /* The length of the IP packet
			       excluding lower layer encapsulations */
    u_int32_t protocol;     /* IP Protocol type (for example, TCP = 6, UDP = 17) */
    SFLIPv6   src_ip;       /* Source IP Address */
    SFLIPv6   dst_ip;       /* Destination IP Address */
    u_int32_t src_port;     /* TCP/UDP source port number or equivalent */
    u_int32_t dst_port;     /* TCP/UDP destination port number or equivalent */
    u_int32_t tcp_flags;    /* TCP flags */
    u_int32_t priority;     /* IP priority */
} SFLSampled_ipv6;

/* Extended data types */

/* Extended switch data */

typedef struct _SFLExtended_switch {
    u_int32_t src_vlan;       /* The 802.1Q VLAN id of incomming frame */
    u_int32_t src_priority;   /* The 802.1p priority */
    u_int32_t dst_vlan;       /* The 802.1Q VLAN id of outgoing frame */
    u_int32_t dst_priority;   /* The 802.1p priority */
} SFLExtended_switch;

/* Extended router data */

typedef struct _SFLExtended_router {
    SFLAddress nexthop;               /* IP address of next hop router */
    u_int32_t src_mask;               /* Source address prefix mask bits */
    u_int32_t dst_mask;               /* Destination address prefix mask bits */
} SFLExtended_router;

/* Extended gateway data */
enum SFLExtended_as_path_segment_type {
    SFLEXTENDED_AS_SET = 1,      /* Unordered set of ASs */
    SFLEXTENDED_AS_SEQUENCE = 2  /* Ordered sequence of ASs */
};

typedef struct _SFLExtended_as_path_segment {
    u_int32_t type;   /* enum SFLExtended_as_path_segment_type */
    u_int32_t length; /* number of AS numbers in set/sequence */
    union {
	u_int32_t *set;
	u_int32_t *seq;
    } as;
} SFLExtended_as_path_segment;

typedef struct _SFLExtended_gateway {
    SFLAddress nexthop;                       /* Address of the border router that should
						 be used for the destination network */
    u_int32_t as;                             /* AS number for this gateway */
    u_int32_t src_as;                         /* AS number of source (origin) */
    u_int32_t src_peer_as;                    /* AS number of source peer */
    u_int32_t dst_as_path_segments;           /* number of segments in path */
    SFLExtended_as_path_segment *dst_as_path; /* list of seqs or sets */
    u_int32_t communities_length;             /* number of communities */
    u_int32_t *communities;                   /* set of communities */
    u_int32_t localpref;                      /* LocalPref associated with this route */
} SFLExtended_gateway;

typedef struct _SFLString {
    u_int32_t len;
    char *str;
} SFLString;

/* Extended user data */

typedef struct _SFLExtended_user {
    u_int32_t src_charset;  /* MIBEnum value of character set used to encode a string - See RFC 2978
			       Where possible UTF-8 encoding (MIBEnum=106) should be used. A value
			       of zero indicates an unknown encoding. */
    SFLString src_user;
    u_int32_t dst_charset;
    SFLString dst_user;
} SFLExtended_user;

/* Extended URL data */

enum SFLExtended_url_direction {
    SFLEXTENDED_URL_SRC = 1, /* URL is associated with source address */
    SFLEXTENDED_URL_DST = 2  /* URL is associated with destination address */
};

typedef struct _SFLExtended_url {
    u_int32_t direction;   /* enum SFLExtended_url_direction */
    SFLString url;         /* URL associated with the packet flow.
			      Must be URL encoded */
    SFLString host;        /* The host field from the HTTP header */
} SFLExtended_url;

/* Extended MPLS data */

typedef struct _SFLLabelStack {
    u_int32_t depth;
    u_int32_t *stack; /* first entry is top of stack - see RFC 3032 for encoding */
} SFLLabelStack;

typedef struct _SFLExtended_mpls {
    SFLAddress nextHop;        /* Address of the next hop */
    SFLLabelStack in_stack;
    SFLLabelStack out_stack;
} SFLExtended_mpls;

/* Extended NAT data
   Packet header records report addresses as seen at the sFlowDataSource.
   The extended_nat structure reports on translated source and/or destination
   addesses for this packet. If an address was not translated it should
   be equal to that reported for the header. */

typedef struct _SFLExtended_nat {
    SFLAddress src;    /* Source address */
    SFLAddress dst;    /* Destination address */
} SFLExtended_nat;

/* additional Extended MPLS stucts */

typedef struct _SFLExtended_mpls_tunnel {
    SFLString tunnel_lsp_name;  /* Tunnel name */
    u_int32_t tunnel_id;        /* Tunnel ID */
    u_int32_t tunnel_cos;       /* Tunnel COS value */
} SFLExtended_mpls_tunnel;

typedef struct _SFLExtended_mpls_vc {
    SFLString vc_instance_name; /* VC instance name */
    u_int32_t vll_vc_id;        /* VLL/VC instance ID */
    u_int32_t vc_label_cos;     /* VC Label COS value */
} SFLExtended_mpls_vc;

/* Extended MPLS FEC
   - Definitions from MPLS-FTN-STD-MIB mplsFTNTable */

typedef struct _SFLExtended_mpls_FTN {
    SFLString mplsFTNDescr;
    u_int32_t mplsFTNMask;
} SFLExtended_mpls_FTN;

/* Extended MPLS LVP FEC
   - Definition from MPLS-LDP-STD-MIB mplsFecTable
   Note: mplsFecAddrType, mplsFecAddr information available
   from packet header */

typedef struct _SFLExtended_mpls_LDP_FEC {
    u_int32_t mplsFecAddrPrefixLength;
} SFLExtended_mpls_LDP_FEC;

/* Extended VLAN tunnel information
   Record outer VLAN encapsulations that have
   been stripped. extended_vlantunnel information
   should only be reported if all the following conditions are satisfied:
   1. The packet has nested vlan tags, AND
   2. The reporting device is VLAN aware, AND
   3. One or more VLAN tags have been stripped, either
   because they represent proprietary encapsulations, or
   because switch hardware automatically strips the outer VLAN
   encapsulation.
   Reporting extended_vlantunnel information is not a substitute for
   reporting extended_switch information. extended_switch data must
   always be reported to describe the ingress/egress VLAN information
   for the packet. The extended_vlantunnel information only applies to
   nested VLAN tags, and then only when one or more tags has been
   stripped. */

typedef SFLLabelStack SFLVlanStack;
typedef struct _SFLExtended_vlan_tunnel {
    SFLVlanStack stack;  /* List of stripped 802.1Q TPID/TCI layers. Each
			    TPID,TCI pair is represented as a single 32 bit
			    integer. Layers listed from outermost to
			    innermost. */
} SFLExtended_vlan_tunnel;

enum SFLFlow_type_tag {
    /* enterprise = 0, format = ... */
    SFLFLOW_HEADER    = 1,      /* Packet headers are sampled */
    SFLFLOW_ETHERNET  = 2,      /* MAC layer information */
    SFLFLOW_IPV4      = 3,      /* IP version 4 data */
    SFLFLOW_IPV6      = 4,      /* IP version 6 data */
    SFLFLOW_EX_SWITCH    = 1001,      /* Extended switch information */
    SFLFLOW_EX_ROUTER    = 1002,      /* Extended router information */
    SFLFLOW_EX_GATEWAY   = 1003,      /* Extended gateway router information */
    SFLFLOW_EX_USER      = 1004,      /* Extended TACAS/RADIUS user information */
    SFLFLOW_EX_URL       = 1005,      /* Extended URL information */
    SFLFLOW_EX_MPLS      = 1006,      /* Extended MPLS information */
    SFLFLOW_EX_NAT       = 1007,      /* Extended NAT information */
    SFLFLOW_EX_MPLS_TUNNEL  = 1008,   /* additional MPLS information */
    SFLFLOW_EX_MPLS_VC      = 1009,
    SFLFLOW_EX_MPLS_FTN     = 1010,
    SFLFLOW_EX_MPLS_LDP_FEC = 1011,
    SFLFLOW_EX_VLAN_TUNNEL  = 1012,   /* VLAN stack */
};

typedef union _SFLFlow_type {
    SFLSampled_header header;
    SFLSampled_ethernet ethernet;
    SFLSampled_ipv4 ipv4;
    SFLSampled_ipv6 ipv6;
    SFLExtended_switch sw;
    SFLExtended_router router;
    SFLExtended_gateway gateway;
    SFLExtended_user user;
    SFLExtended_url url;
    SFLExtended_mpls mpls;
    SFLExtended_nat nat;
    SFLExtended_mpls_tunnel mpls_tunnel;
    SFLExtended_mpls_vc mpls_vc;
    SFLExtended_mpls_FTN mpls_ftn;
    SFLExtended_mpls_LDP_FEC mpls_ldp_fec;
    SFLExtended_vlan_tunnel vlan_tunnel;
} SFLFlow_type;

typedef struct _SFLFlow_sample_element {
    struct _SFLFlow_sample_element *nxt;
    u_int32_t tag;  /* SFLFlow_type_tag */
    u_int32_t length;
    SFLFlow_type flowType;
} SFLFlow_sample_element;

enum SFL_sample_tag {
    SFLFLOW_SAMPLE = 1,              /* enterprise = 0 : format = 1 */
    SFLCOUNTERS_SAMPLE = 2,          /* enterprise = 0 : format = 2 */
    SFLFLOW_SAMPLE_EXPANDED = 3,     /* enterprise = 0 : format = 3 */
    SFLCOUNTERS_SAMPLE_EXPANDED = 4  /* enterprise = 0 : format = 4 */
};

/* Format of a single flow sample */

typedef struct _SFLFlow_sample {
    /* u_int32_t tag;    */         /* SFL_sample_tag -- enterprise = 0 : format = 1 */
    /* u_int32_t length; */
    u_int32_t sequence_number;      /* Incremented with each flow sample
				       generated */
    u_int32_t source_id;            /* fsSourceId */
    u_int32_t sampling_rate;        /* fsPacketSamplingRate */
    u_int32_t sample_pool;          /* Total number of packets that could have been
				       sampled (i.e. packets skipped by sampling
				       process + total number of samples) */
    u_int32_t drops;                /* Number of times a packet was dropped due to
				       lack of resources */
    u_int32_t input;                /* SNMP ifIndex of input interface.
				       0 if interface is not known. */
    u_int32_t output;               /* SNMP ifIndex of output interface,
				       0 if interface is not known.
				       Set most significant bit to indicate
				       multiple destination interfaces
				       (i.e. in case of broadcast or multicast)
				       and set lower order bits to indicate
				       number of destination interfaces.
				       Examples:
				       0x00000002  indicates ifIndex = 2
				       0x00000000  ifIndex unknown.
				       0x80000007  indicates a packet sent
				       to 7 interfaces.
				       0x80000000  indicates a packet sent to
				       an unknown number of
				       interfaces greater than 1.*/
    u_int32_t num_elements;
    SFLFlow_sample_element *elements;
} SFLFlow_sample;

/* same thing, but the expanded version (for full 32-bit ifIndex numbers) */

typedef struct _SFLFlow_sample_expanded {
    /* u_int32_t tag;    */         /* SFL_sample_tag -- enterprise = 0 : format = 1 */
    /* u_int32_t length; */
    u_int32_t sequence_number;      /* Incremented with each flow sample
				       generated */
    u_int32_t ds_class;             /* EXPANDED */
    u_int32_t ds_index;             /* EXPANDED */
    u_int32_t sampling_rate;        /* fsPacketSamplingRate */
    u_int32_t sample_pool;          /* Total number of packets that could have been
				       sampled (i.e. packets skipped by sampling
				       process + total number of samples) */
    u_int32_t drops;                /* Number of times a packet was dropped due to
				       lack of resources */
    u_int32_t inputFormat;          /* EXPANDED */
    u_int32_t input;                /* SNMP ifIndex of input interface.
				       0 if interface is not known. */
    u_int32_t outputFormat;         /* EXPANDED */
    u_int32_t output;               /* SNMP ifIndex of output interface,
				       0 if interface is not known. */
    u_int32_t num_elements;
    SFLFlow_sample_element *elements;
} SFLFlow_sample_expanded;

/* Counter types */

/* Generic interface counters - see RFC 1573, 2233 */

typedef struct _SFLIf_counters {
    u_int32_t ifIndex;
    u_int32_t ifType;
    u_int64_t ifSpeed;
    u_int32_t ifDirection;        /* Derived from MAU MIB (RFC 2668)
				     0 = unknown, 1 = full-duplex,
				     2 = half-duplex, 3 = in, 4 = out */
    u_int32_t ifStatus;           /* bit field with the following bits assigned:
				     bit 0 = ifAdminStatus (0 = down, 1 = up)
				     bit 1 = ifOperStatus (0 = down, 1 = up) */
    u_int64_t ifInOctets;
    u_int32_t ifInUcastPkts;
    u_int32_t ifInMulticastPkts;
    u_int32_t ifInBroadcastPkts;
    u_int32_t ifInDiscards;
    u_int32_t ifInErrors;
    u_int32_t ifInUnknownProtos;
    u_int64_t ifOutOctets;
    u_int32_t ifOutUcastPkts;
    u_int32_t ifOutMulticastPkts;
    u_int32_t ifOutBroadcastPkts;
    u_int32_t ifOutDiscards;
    u_int32_t ifOutErrors;
    u_int32_t ifPromiscuousMode;
} SFLIf_counters;

/* Ethernet interface counters - see RFC 2358 */
typedef struct _SFLEthernet_counters {
    u_int32_t dot3StatsAlignmentErrors;
    u_int32_t dot3StatsFCSErrors;
    u_int32_t dot3StatsSingleCollisionFrames;
    u_int32_t dot3StatsMultipleCollisionFrames;
    u_int32_t dot3StatsSQETestErrors;
    u_int32_t dot3StatsDeferredTransmissions;
    u_int32_t dot3StatsLateCollisions;
    u_int32_t dot3StatsExcessiveCollisions;
    u_int32_t dot3StatsInternalMacTransmitErrors;
    u_int32_t dot3StatsCarrierSenseErrors;
    u_int32_t dot3StatsFrameTooLongs;
    u_int32_t dot3StatsInternalMacReceiveErrors;
    u_int32_t dot3StatsSymbolErrors;
} SFLEthernet_counters;

/* Token ring counters - see RFC 1748 */

typedef struct _SFLTokenring_counters {
    u_int32_t dot5StatsLineErrors;
    u_int32_t dot5StatsBurstErrors;
    u_int32_t dot5StatsACErrors;
    u_int32_t dot5StatsAbortTransErrors;
    u_int32_t dot5StatsInternalErrors;
    u_int32_t dot5StatsLostFrameErrors;
    u_int32_t dot5StatsReceiveCongestions;
    u_int32_t dot5StatsFrameCopiedErrors;
    u_int32_t dot5StatsTokenErrors;
    u_int32_t dot5StatsSoftErrors;
    u_int32_t dot5StatsHardErrors;
    u_int32_t dot5StatsSignalLoss;
    u_int32_t dot5StatsTransmitBeacons;
    u_int32_t dot5StatsRecoverys;
    u_int32_t dot5StatsLobeWires;
    u_int32_t dot5StatsRemoves;
    u_int32_t dot5StatsSingles;
    u_int32_t dot5StatsFreqErrors;
} SFLTokenring_counters;

/* 100 BaseVG interface counters - see RFC 2020 */

typedef struct _SFLVg_counters {
    u_int32_t dot12InHighPriorityFrames;
    u_int64_t dot12InHighPriorityOctets;
    u_int32_t dot12InNormPriorityFrames;
    u_int64_t dot12InNormPriorityOctets;
    u_int32_t dot12InIPMErrors;
    u_int32_t dot12InOversizeFrameErrors;
    u_int32_t dot12InDataErrors;
    u_int32_t dot12InNullAddressedFrames;
    u_int32_t dot12OutHighPriorityFrames;
    u_int64_t dot12OutHighPriorityOctets;
    u_int32_t dot12TransitionIntoTrainings;
    u_int64_t dot12HCInHighPriorityOctets;
    u_int64_t dot12HCInNormPriorityOctets;
    u_int64_t dot12HCOutHighPriorityOctets;
} SFLVg_counters;

typedef struct _SFLVlan_counters {
    u_int32_t vlan_id;
    u_int64_t octets;
    u_int32_t ucastPkts;
    u_int32_t multicastPkts;
    u_int32_t broadcastPkts;
    u_int32_t discards;
} SFLVlan_counters;

/* Counters data */

enum SFLCounters_type_tag {
    /* enterprise = 0, format = ... */
    SFLCOUNTERS_GENERIC      = 1,
    SFLCOUNTERS_ETHERNET     = 2,
    SFLCOUNTERS_TOKENRING    = 3,
    SFLCOUNTERS_VG           = 4,
    SFLCOUNTERS_VLAN         = 5
};

typedef union _SFLCounters_type {
    SFLIf_counters generic;
    SFLEthernet_counters ethernet;
    SFLTokenring_counters tokenring;
    SFLVg_counters vg;
    SFLVlan_counters vlan;
} SFLCounters_type;

typedef struct _SFLCounters_sample_element {
    struct _SFLCounters_sample_element *nxt; /* linked list */
    u_int32_t tag; /* SFLCounters_type_tag */
    u_int32_t length;
    SFLCounters_type counterBlock;
} SFLCounters_sample_element;

typedef struct _SFLCounters_sample {
    /* u_int32_t tag;    */       /* SFL_sample_tag -- enterprise = 0 : format = 2 */
    /* u_int32_t length; */
    u_int32_t sequence_number;    /* Incremented with each counters sample
				     generated by this source_id */
    u_int32_t source_id;          /* fsSourceId */
    u_int32_t num_elements;
    SFLCounters_sample_element *elements;
} SFLCounters_sample;

/* same thing, but the expanded version, so ds_index can be a full 32 bits */
typedef struct _SFLCounters_sample_expanded {
    /* u_int32_t tag;    */       /* SFL_sample_tag -- enterprise = 0 : format = 2 */
    /* u_int32_t length; */
    u_int32_t sequence_number;    /* Incremented with each counters sample
				     generated by this source_id */
    u_int32_t ds_class;           /* EXPANDED */
    u_int32_t ds_index;           /* EXPANDED */
    u_int32_t num_elements;
    SFLCounters_sample_element *elements;
} SFLCounters_sample_expanded;

#define SFLADD_ELEMENT(_sm, _el) do { (_el)->nxt = (_sm)->elements; (_sm)->elements = (_el); } while(0)

/* Format of a sample datagram */

enum SFLDatagram_version {
    SFLDATAGRAM_VERSION2 = 2,
    SFLDATAGRAM_VERSION4 = 4,
    SFLDATAGRAM_VERSION5 = 5
};

typedef struct _SFLSample_datagram_hdr {
    u_int32_t datagram_version;      /* (enum SFLDatagram_version) = VERSION5 = 5 */
    SFLAddress agent_address;        /* IP address of sampling agent */
    u_int32_t sub_agent_id;          /* Used to distinguishing between datagram
					streams from separate agent sub entities
					within an device. */
    u_int32_t sequence_number;       /* Incremented with each sample datagram
					generated */
    u_int32_t uptime;                /* Current time (in milliseconds since device
					last booted). Should be set as close to
					datagram transmission time as possible.*/
    u_int32_t num_records;           /* Number of tag-len-val flow/counter records to follow */
} SFLSample_datagram_hdr;

#define SFL_MAX_DATAGRAM_SIZE 1500
#define SFL_MIN_DATAGRAM_SIZE 200
#define SFL_DEFAULT_DATAGRAM_SIZE 1400

#define SFL_DATA_PAD 400

#endif /* SFLOW_H */
