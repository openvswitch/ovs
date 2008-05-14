#ifndef SNAP_H
#define SNAP_H 1

#include <linux/llc.h>

#define SNAP_OUI_LEN 3


struct snap_hdr
{
	uint8_t  dsap;  /* Always 0xAA */
	uint8_t  ssap;  /* Always 0xAA */
	uint8_t  ctrl;
	uint8_t  oui[SNAP_OUI_LEN];
	uint16_t ethertype;
} __attribute__ ((packed));

static inline int snap_get_ethertype(struct sk_buff *skb, uint16_t *ethertype)
{
	struct snap_hdr *sh = (struct snap_hdr *)(skb->data 
				+ sizeof(struct ethhdr));
	if (((sh->dsap & 0xFE) != LLC_SAP_SNAP) 
				|| ((sh->ssap & 0xFE) != LLC_SAP_SNAP)
				|| (!memcmp(sh->oui, "\0\0\0", SNAP_OUI_LEN)))
		return -EINVAL;

	*ethertype = sh->ethertype;

	return 0;
}

#endif /* snap.h */
