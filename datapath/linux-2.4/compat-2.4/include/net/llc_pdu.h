#ifndef __NET_LLC_PDU_H
#define __NET_LLC_PDU_H 1

/* Un-numbered PDU format (3 bytes in length) */
struct llc_pdu_un {
    u8 dsap;
    u8 ssap;
    u8 ctrl_1;
};

#endif
