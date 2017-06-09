#ifndef _CONNTRACK_NAT_H
#define _CONNTRACK_NAT_H

#include "precomp.h"
#include "Flow.h"
#include "Debug.h"
#include <stddef.h>
#include "Conntrack.h"

#define NAT_HASH_TABLE_SIZE ((UINT32)1 << 10)
#define NAT_HASH_TABLE_MASK (NAT_HASH_TABLE_SIZE - 1)

typedef struct OVS_NAT_ENTRY {
    LIST_ENTRY link;
    LIST_ENTRY reverseLink;
    OVS_CT_KEY key;
    OVS_CT_KEY value;
    POVS_CT_ENTRY  ctEntry;
} OVS_NAT_ENTRY, *POVS_NAT_ENTRY;

__inline static BOOLEAN OvsIsForwardNat(UINT16 natAction) {
    return !!(natAction & (NAT_ACTION_SRC | NAT_ACTION_DST));
}

NTSTATUS OvsNatInit();
VOID OvsNatFlush(UINT16 zone);

VOID OvsNatAddEntry(OVS_NAT_ENTRY* entry);

VOID OvsNatDeleteEntry(POVS_NAT_ENTRY entry);
VOID OvsNatDeleteKey(const OVS_CT_KEY *key);
VOID OvsNatCleanup();

POVS_NAT_ENTRY OvsNatLookup(const OVS_CT_KEY *ctKey, BOOLEAN reverse);
BOOLEAN OvsNatTranslateCtEntry(OVS_CT_ENTRY *ctEntry);
VOID OvsNatPacket(OvsForwardingContext *ovsFwdCtx, const OVS_CT_ENTRY *entry,
                  UINT16 natAction, OvsFlowKey *key, BOOLEAN reverse);

#endif
