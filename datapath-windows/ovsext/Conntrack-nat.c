#include "Conntrack-nat.h"
#include "Jhash.h"

PLIST_ENTRY ovsNatTable = NULL;
PLIST_ENTRY ovsUnNatTable = NULL;

/*
 *---------------------------------------------------------------------------
 * OvsHashNatKey
 *     Hash NAT related fields in a Conntrack key.
 *---------------------------------------------------------------------------
 */
static __inline UINT32
OvsHashNatKey(const OVS_CT_KEY *key)
{
    UINT32 hash = 0;
#define HASH_ADD(field) \
    hash = OvsJhashBytes(&key->field, sizeof(key->field), hash)

    HASH_ADD(src.addr.ipv4_aligned);
    HASH_ADD(dst.addr.ipv4_aligned);
    HASH_ADD(src.port);
    HASH_ADD(dst.port);
    HASH_ADD(zone);
    /* icmp_id and port overlap in the union */
    HASH_ADD(src.icmp_type);
    HASH_ADD(dst.icmp_type);
    HASH_ADD(src.icmp_code);
    HASH_ADD(dst.icmp_code);

#undef HASH_ADD
    return hash;
}

/*
 *---------------------------------------------------------------------------
 * OvsNatKeyAreSame
 *     Compare NAT related fields in a Conntrack key.
 *---------------------------------------------------------------------------
 */
static __inline BOOLEAN
OvsNatKeyAreSame(const OVS_CT_KEY *key1, const OVS_CT_KEY *key2)
{
    // XXX: Compare IPv6 key as well
#define FIELD_COMPARE(field) \
    if (key1->field != key2->field) return FALSE

    FIELD_COMPARE(src.addr.ipv4_aligned);
    FIELD_COMPARE(dst.addr.ipv4_aligned);
    FIELD_COMPARE(src.port);
    FIELD_COMPARE(dst.port);
    FIELD_COMPARE(zone);
    /* icmp_id and port overlap in the union */
    FIELD_COMPARE(src.icmp_type);
    FIELD_COMPARE(dst.icmp_type);
    FIELD_COMPARE(src.icmp_code);
    FIELD_COMPARE(dst.icmp_code);
    return TRUE;
#undef FIELD_COMPARE
}

/*
 *---------------------------------------------------------------------------
 * OvsNatGetBucket
 *     Returns the row of NAT table that has the same hash as the given NAT
 *     hash key. If isReverse is TRUE, returns the row of reverse NAT table
 *     instead.
 *---------------------------------------------------------------------------
 */
static __inline PLIST_ENTRY
OvsNatGetBucket(const OVS_CT_KEY *key, BOOLEAN isReverse)
{
    uint32_t hash = OvsHashNatKey(key);
    if (isReverse) {
        return &ovsUnNatTable[hash & NAT_HASH_TABLE_MASK];
    } else {
        return &ovsNatTable[hash & NAT_HASH_TABLE_MASK];
    }
}

/*
 *---------------------------------------------------------------------------
 * OvsNatInit
 *     Initialize NAT related resources.
 *---------------------------------------------------------------------------
 */
NTSTATUS OvsNatInit()
{
    ASSERT(ovsNatTable == NULL);

    /* Init the Hash Buffer */
    ovsNatTable = OvsAllocateMemoryWithTag(
        sizeof(LIST_ENTRY) * NAT_HASH_TABLE_SIZE,
        OVS_CT_POOL_TAG);
    if (ovsNatTable == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    ovsUnNatTable = OvsAllocateMemoryWithTag(
        sizeof(LIST_ENTRY) * NAT_HASH_TABLE_SIZE,
        OVS_CT_POOL_TAG);
    if (ovsUnNatTable == NULL) {
        OvsFreeMemoryWithTag(ovsNatTable, OVS_CT_POOL_TAG);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    for (int i = 0; i < NAT_HASH_TABLE_SIZE; i++) {
        InitializeListHead(&ovsNatTable[i]);
        InitializeListHead(&ovsUnNatTable[i]);
    }

    return STATUS_SUCCESS;
}

/*
 *----------------------------------------------------------------------------
 * OvsNatFlush
 *     Flushes out all NAT entries that match the given zone.
 *----------------------------------------------------------------------------
 */
VOID OvsNatFlush(UINT16 zone)
{
    PLIST_ENTRY link, next;
    for (int i = 0; i < NAT_HASH_TABLE_SIZE; i++) {
        LIST_FORALL_SAFE(&ovsNatTable[i], link, next) {
            POVS_NAT_ENTRY entry =
                CONTAINING_RECORD(link, OVS_NAT_ENTRY, link);
            /* zone is a non-zero value */
            if (!zone || zone == entry->key.zone) {
                OvsNatDeleteEntry(entry);
            }
        }
    }
}

/*
 *----------------------------------------------------------------------------
 * OvsNatCleanup
 *     Releases all NAT related resources.
 *----------------------------------------------------------------------------
 */
VOID OvsNatCleanup()
{
    if (ovsNatTable == NULL) {
       return;
    }
    OvsFreeMemoryWithTag(ovsNatTable, OVS_CT_POOL_TAG);
    OvsFreeMemoryWithTag(ovsUnNatTable, OVS_CT_POOL_TAG);
    ovsNatTable = NULL;
    ovsUnNatTable = NULL;
}

/*
 *----------------------------------------------------------------------------
 * OvsNatPacket
 *     Performs NAT operation on the packet by replacing the source/destinaton
 *     address/port based on natAction. If reverse is TRUE, perform unNAT
 *     instead.
 *----------------------------------------------------------------------------
 */
VOID
OvsNatPacket(OvsForwardingContext *ovsFwdCtx,
             const OVS_CT_ENTRY *entry,
             UINT16 natAction,
             OvsFlowKey *key,
             BOOLEAN reverse)
{
    UINT32 natFlag;
    const struct ct_endpoint* endpoint;
    LOCK_STATE_EX lockState;
    /* XXX: Move conntrack locks out of NAT after implementing lock in NAT. */
    NdisAcquireRWLockRead(entry->lock, &lockState, 0);
    /* When it is NAT, only entry->rev_key contains NATTED address;
       When it is unNAT, only entry->key contains the UNNATTED address;*/
    const OVS_CT_KEY *ctKey = reverse ? &entry->key : &entry->rev_key;
    BOOLEAN isSrcNat;

    if (!(natAction & (NAT_ACTION_SRC | NAT_ACTION_DST))) {
        NdisReleaseRWLock(entry->lock, &lockState);
        return;
    }
    isSrcNat = (((natAction & NAT_ACTION_SRC) && !reverse) ||
                ((natAction & NAT_ACTION_DST) && reverse));

    if (isSrcNat) {
        /* Flag is set to SNAT for SNAT case and the reverse DNAT case */
        natFlag = OVS_CS_F_SRC_NAT;
        /* Note that ctKey is the key in the other direction, so
           endpoint has to be reverted, i.e. ctKey->dst for SNAT
           and ctKey->src for DNAT */
        endpoint = &ctKey->dst;
    } else {
        natFlag = OVS_CS_F_DST_NAT;
        endpoint = &ctKey->src;
    }
    key->ct.state |= natFlag;
    if (ctKey->dl_type == htons(ETH_TYPE_IPV4)) {
        OvsUpdateAddressAndPort(ovsFwdCtx,
                                endpoint->addr.ipv4_aligned,
                                endpoint->port, isSrcNat,
                                !reverse);
        if (isSrcNat) {
            key->ipKey.nwSrc = endpoint->addr.ipv4_aligned;
        } else {
            key->ipKey.nwDst = endpoint->addr.ipv4_aligned;
        }
    } else if (ctKey->dl_type == htons(ETH_TYPE_IPV6)){
        // XXX: IPv6 packet not supported yet.
        NdisReleaseRWLock(entry->lock, &lockState);
        return;
    }
    if (natAction & (NAT_ACTION_SRC_PORT | NAT_ACTION_DST_PORT)) {
        if (isSrcNat) {
            if (key->ipKey.l4.tpSrc != 0) {
                key->ipKey.l4.tpSrc = endpoint->port;
            }
        } else {
            if (key->ipKey.l4.tpDst != 0) {
                key->ipKey.l4.tpDst = endpoint->port;
            }
        }
    }
    NdisReleaseRWLock(entry->lock, &lockState);
}


/*
 *----------------------------------------------------------------------------
 * OvsNatHashRange
 *     Compute hash for a range of addresses specified in natInfo.
 *----------------------------------------------------------------------------
 */
static UINT32 OvsNatHashRange(const OVS_CT_ENTRY *entry, UINT32 basis)
{
    UINT32 hash = basis;
#define HASH_ADD(field) \
    hash = OvsJhashBytes(&field, sizeof(field), hash)

    HASH_ADD(entry->natInfo.minAddr);
    HASH_ADD(entry->natInfo.maxAddr);
    HASH_ADD(entry->key.dl_type);
    HASH_ADD(entry->key.nw_proto);
    HASH_ADD(entry->key.zone);
#undef HASH_ADD
    return hash;
}

/*
 *----------------------------------------------------------------------------
 * OvsNatAddEntry
 *     Add an entry to the NAT table. Also updates the reverse NAT lookup
 *     table.
 *----------------------------------------------------------------------------
 */
VOID
OvsNatAddEntry(OVS_NAT_ENTRY* entry)
{
    InsertHeadList(OvsNatGetBucket(&entry->key, FALSE),
                   &entry->link);
    InsertHeadList(OvsNatGetBucket(&entry->value, TRUE),
                   &entry->reverseLink);
}

/*
 *----------------------------------------------------------------------------
 * OvsNatTranslateCtEntry
 *     Update an Conntrack entry with NAT information. Translated address and
 *     port will be generated and write back to the conntrack entry as a
 *     result.
 *     Note: For ICMP, only address is translated.
 *----------------------------------------------------------------------------
 */
BOOLEAN
OvsNatTranslateCtEntry(OVS_CT_ENTRY *entry)
{
    const uint16_t MIN_NAT_EPHEMERAL_PORT = 1024;
    const uint16_t MAX_NAT_EPHEMERAL_PORT = 65535;

    uint16_t minPort;
    uint16_t maxPort;
    uint16_t firstPort;
    uint32_t addrDelta = 0;
    uint32_t addrIndex;
    struct ct_addr ctAddr, maxCtAddr;
    uint16_t port;
    BOOLEAN allPortsTried;
    BOOLEAN originalPortsTried;
    struct ct_addr firstAddr;

    uint32_t hash = OvsNatHashRange(entry, 0);

    if ((entry->natInfo.natAction & NAT_ACTION_SRC) &&
        (!(entry->natInfo.natAction & NAT_ACTION_SRC_PORT))) {
        firstPort = minPort = maxPort = ntohs(entry->key.src.port);
    } else if ((entry->natInfo.natAction & NAT_ACTION_DST) &&
               (!(entry->natInfo.natAction & NAT_ACTION_DST_PORT))) {
        firstPort = minPort = maxPort = ntohs(entry->key.dst.port);
    } else {
        uint16_t portDelta = entry->natInfo.maxPort - entry->natInfo.minPort;
        uint16_t portIndex = (uint16_t) hash % (portDelta + 1);
        firstPort = entry->natInfo.minPort + portIndex;
        minPort = entry->natInfo.minPort;
        maxPort = entry->natInfo.maxPort;
    }

    memset(&ctAddr, 0, sizeof ctAddr);
    memset(&maxCtAddr, 0, sizeof maxCtAddr);
    maxCtAddr = entry->natInfo.maxAddr;

    if (entry->key.dl_type == htons(ETH_TYPE_IPV4)) {
        addrDelta = ntohl(entry->natInfo.maxAddr.ipv4_aligned) -
                    ntohl(entry->natInfo.minAddr.ipv4_aligned);
        addrIndex = hash % (addrDelta + 1);
        ctAddr.ipv4_aligned = htonl(
            ntohl(entry->natInfo.minAddr.ipv4_aligned) + addrIndex);
    } else {
        // XXX: IPv6 not supported
        return FALSE;
    }

    port = firstPort;
    allPortsTried = FALSE;
    originalPortsTried = FALSE;
    firstAddr = ctAddr;
    for (;;) {
        if (entry->natInfo.natAction & NAT_ACTION_SRC) {
            entry->rev_key.dst.addr = ctAddr;
            if (entry->rev_key.nw_proto != IPPROTO_ICMP) {
                entry->rev_key.dst.port = htons(port);
            }
        } else {
            entry->rev_key.src.addr = ctAddr;
            if (entry->rev_key.nw_proto != IPPROTO_ICMP) {
                entry->rev_key.src.port = htons(port);
            }
        }

        OVS_NAT_ENTRY *natEntry = OvsNatLookup(&entry->rev_key, TRUE);

        if (!natEntry) {
            natEntry = OvsAllocateMemoryWithTag(sizeof(*natEntry),
                                                OVS_CT_POOL_TAG);
            if (!natEntry) {
               return FALSE;
            }
            memcpy(&natEntry->key, &entry->key,
                   sizeof natEntry->key);
            memcpy(&natEntry->value, &entry->rev_key,
                   sizeof natEntry->value);
            natEntry->ctEntry = entry;
            OvsNatAddEntry(natEntry);
            return TRUE;
        } else if (!allPortsTried) {
            if (minPort == maxPort) {
                allPortsTried = TRUE;
            } else if (port == maxPort) {
                port = minPort;
            } else {
                port++;
            }
            if (port == firstPort) {
                allPortsTried = TRUE;
            }
        } else {
            if (memcmp(&ctAddr, &maxCtAddr, sizeof ctAddr)) {
                if (entry->key.dl_type == htons(ETH_TYPE_IPV4)) {
                    ctAddr.ipv4_aligned = htonl(
                        ntohl(ctAddr.ipv4_aligned) + 1);
                } else {
                    // XXX: IPv6 not supported
                    return FALSE;
                }
            } else {
                ctAddr = entry->natInfo.minAddr;
            }
            if (!memcmp(&ctAddr, &firstAddr, sizeof ctAddr)) {
                if (!originalPortsTried) {
                    originalPortsTried = TRUE;
                    ctAddr = entry->natInfo.minAddr;
                    minPort = MIN_NAT_EPHEMERAL_PORT;
                    maxPort = MAX_NAT_EPHEMERAL_PORT;
                } else {
                    break;
                }
            }
            firstPort = minPort;
            port = firstPort;
            allPortsTried = FALSE;
        }
    }
    return FALSE;
}

/*
 *----------------------------------------------------------------------------
 * OvsNatLookup
 *     Look up a NAT entry with the given key in the NAT table.
 *     If reverse is TRUE, look up a NAT entry with the given value instead.
 *----------------------------------------------------------------------------
 */
POVS_NAT_ENTRY
OvsNatLookup(const OVS_CT_KEY *ctKey, BOOLEAN reverse)
{
    PLIST_ENTRY link;
    POVS_NAT_ENTRY entry;

    LIST_FORALL(OvsNatGetBucket(ctKey, reverse), link) {
        if (reverse) {
            entry = CONTAINING_RECORD(link, OVS_NAT_ENTRY, reverseLink);

            if (OvsNatKeyAreSame(ctKey, &entry->value)) {
                return entry;
            }
        } else {
            entry = CONTAINING_RECORD(link, OVS_NAT_ENTRY, link);

            if (OvsNatKeyAreSame(ctKey, &entry->key)) {
                return entry;
            }
        }
    }
    return NULL;
}

/*
 *----------------------------------------------------------------------------
 * OvsNatDeleteEntry
 *     Delete a NAT entry.
 *----------------------------------------------------------------------------
 */
VOID
OvsNatDeleteEntry(POVS_NAT_ENTRY entry)
{
    if (entry == NULL) {
        return;
    }
    RemoveEntryList(&entry->link);
    RemoveEntryList(&entry->reverseLink);
    OvsFreeMemoryWithTag(entry, OVS_CT_POOL_TAG);
}

/*
 *----------------------------------------------------------------------------
 * OvsNatDeleteKey
 *     Delete a NAT entry with the given key.
 *----------------------------------------------------------------------------
 */
VOID
OvsNatDeleteKey(const OVS_CT_KEY *key)
{
    OvsNatDeleteEntry(OvsNatLookup(key, FALSE));
}
