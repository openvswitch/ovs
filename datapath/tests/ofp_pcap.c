/* A cheap knock-off of the pcap library to remove that dependency. */

#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include "ofp_pcap.h"

int
ofp_pcap_open(struct ofp_pcap *p, const char *fname, char *errbuf)
{
	FILE *fp;
	struct pcap_file_header hdr;
	size_t amt_read;

	fp = fopen(fname, "r");

	memset((char *)p, 0, sizeof(*p));

	amt_read = fread((char *)&hdr, 1, sizeof(hdr), fp);
	if (amt_read != sizeof(hdr)) {
		snprintf(errbuf, OFP_PCAP_ERRBUF_SIZE, "error reading dump file");
		goto error;
	}

	if (hdr.magic != TCPDUMP_MAGIC) {
		hdr.magic         = SWAPLONG(hdr.magic);
		hdr.version_major = SWAPSHORT(hdr.version_major);
		hdr.version_minor = SWAPSHORT(hdr.version_minor);
		hdr.thiszone      = SWAPLONG(hdr.thiszone);
		hdr.sigfigs       = SWAPLONG(hdr.sigfigs);
		hdr.snaplen       = SWAPLONG(hdr.snaplen);
		hdr.linktype      = SWAPLONG(hdr.linktype);

		p->swapped = 1;
	}

	p->fp = fp;
	p->errbuf = errbuf;
	p->bufsize = hdr.snaplen+sizeof(struct pcap_pkthdr);
	p->buf = malloc(p->bufsize);
	if (!p->buf) {
		snprintf(errbuf, OFP_PCAP_ERRBUF_SIZE, "error allocating buffer");
		goto error;
	}

	if (hdr.version_major < OFP_PCAP_VERSION_MAJOR) {
		snprintf(errbuf, OFP_PCAP_ERRBUF_SIZE, "archaic file format");
		goto error;
	}

	return 0;

error:
	if (p->buf)
		free(p->buf);
	return 1;
}

char *
ofp_pcap_next(struct ofp_pcap *p, struct pcap_pkthdr *hdr)
{
	size_t amt_read;

	amt_read = fread(hdr, 1, sizeof(*hdr), p->fp);
	if (amt_read != sizeof(*hdr)) {
		snprintf(p->errbuf, OFP_PCAP_ERRBUF_SIZE, "error reading dump file");
		return NULL;
	}

	if (p->swapped) {
		hdr->caplen = SWAPLONG(hdr->caplen);
		hdr->len = SWAPLONG(hdr->len);
		hdr->ts.tv_sec = SWAPLONG(hdr->ts.tv_sec);
		hdr->ts.tv_usec = SWAPLONG(hdr->ts.tv_usec);
	}

	if (hdr->caplen > p->bufsize) {
		snprintf(p->errbuf, OFP_PCAP_ERRBUF_SIZE, "error reading dump file");
		return NULL;
	}

	amt_read = fread((char *)p->buf, 1, hdr->caplen, p->fp);
	if (amt_read != hdr->caplen){
		snprintf(p->errbuf, OFP_PCAP_ERRBUF_SIZE, "error reading dump file");
		return NULL;
	}

	return p->buf;
}

void
ofp_pcap_close(struct ofp_pcap *p)
{
	fclose(p->fp);
	free(p->buf);
}

