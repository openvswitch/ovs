#ifndef OFP_PCAP_H
#define OFP_PCAP_H

#include <stdint.h>
#include <sys/time.h>
#include <stdio.h>

#define OFP_PCAP_VERSION_MAJOR 2
#define OFP_PCAP_VERSION_MINOR 4

#define TCPDUMP_MAGIC 0xa1b2c3d4

#define OFP_LINKTYPE_ETHERNET 1

#define OFP_PCAP_ERRBUF_SIZE  256

/* Swap the byte order regardless of the architecture */
#define SWAPLONG(x) \
	((((x)&0xff)<<24) | (((x)&0xff00)<<8) | (((x)&0xff0000)>>8) | (((x)&0xff000000)>>24))
#define SWAPSHORT(x) \
	((((x)&0xff)<<8) | (((x)&0xff00)>>8))

struct ofp_pcap {
	FILE *fp;               /* File pointer to currently processed file */
	int swapped;            /* Indicate whether endian-ness needs to change */
	char *buf;              /* Buffer to hold packet data */
	size_t bufsize;         /* Size of buffer */
	char *errbuf;		    /* Pointer to buffer to hold error message */
};

struct pcap_file_header {
	uint32_t magic;         /* Magic number */
	uint16_t version_major; /* Version number major */
	uint16_t version_minor; /* Version number minor */
	int32_t  thiszone;      /* Gmt to local correction */
	uint32_t sigfigs;       /* Accuracy of timestamps */
	uint32_t snaplen;       /* Max length saved portion of each pkt */
	uint32_t linktype;      /* Data link type (LINKTYPE_*) */
};

/*
 * This is a timeval as stored in disk in a dumpfile.
 * It has to use the same types everywhere, independent of the actual
 * `struct timeval'
 */
struct pcap_timeval {
	int32_t tv_sec;         /* Seconds */
	int32_t tv_usec;        /* Microseconds */
};

/*
 * How a `pcap_pkthdr' is actually stored in the dumpfile.
 */
struct pcap_pkthdr {
	struct pcap_timeval ts; /* Time stamp */
	uint32_t caplen;        /* Length of portion present */
	uint32_t len;           /* Length this packet (off wire) */
};

int ofp_pcap_open(struct ofp_pcap *p, const char *fname, char *errbuf);
char *ofp_pcap_next(struct ofp_pcap *p, struct pcap_pkthdr *hdr);
void ofp_pcap_close(struct ofp_pcap *p);

#endif /* ofp_pcap.h */
