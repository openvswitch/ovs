/* Copyright (c) 2009, 2010, 2011, 2012, 2013 Nicira, Inc.
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
 * limitations under the License. */

#include <config.h>

#include "ofproto-dpif-mirror.h"

#include <errno.h>

#include "hmap.h"
#include "hmapx.h"
#include "ofproto.h"
#include "vlan-bitmap.h"
#include "openvswitch/vlog.h"

VLOG_DEFINE_THIS_MODULE(ofproto_dpif_mirror);

#define MIRROR_MASK_C(X) UINT32_C(X)
BUILD_ASSERT_DECL(sizeof(mirror_mask_t) * CHAR_BIT >= MAX_MIRRORS);

struct mbridge {
    struct mirror *mirrors[MAX_MIRRORS];
    struct hmap mbundles;

    bool need_revalidate;
    bool has_mirrors;

    struct ovs_refcount ref_cnt;
};

struct mbundle {
    struct hmap_node hmap_node; /* In parent 'mbridge' map. */
    struct ofbundle *ofbundle;

    mirror_mask_t src_mirrors;  /* Mirrors triggered when packet received. */
    mirror_mask_t dst_mirrors;  /* Mirrors triggered when packet sent. */
    mirror_mask_t mirror_out;   /* Mirrors that output to this mbundle. */
};

struct mirror {
    struct mbridge *mbridge;    /* Owning ofproto. */
    size_t idx;                 /* In ofproto's "mirrors" array. */
    void *aux;                  /* Key supplied by ofproto's client. */

    /* Selection criteria. */
    struct hmapx srcs;          /* Contains "struct mbundle*"s. */
    struct hmapx dsts;          /* Contains "struct mbundle*"s. */
    unsigned long *vlans;       /* Bitmap of chosen VLANs, NULL selects all. */

    /* Output (exactly one of out == NULL and out_vlan == -1 is true). */
    struct mbundle *out;        /* Output port or NULL. */
    int out_vlan;               /* Output VLAN or -1. */
    mirror_mask_t dup_mirrors;  /* Bitmap of mirrors with the same output. */

    /* Counters. */
    int64_t packet_count;       /* Number of packets sent. */
    int64_t byte_count;         /* Number of bytes sent. */
};

static struct mirror *mirror_lookup(struct mbridge *, void *aux);
static struct mbundle *mbundle_lookup(const struct mbridge *,
                                      struct ofbundle *);
static void mbundle_lookup_multiple(const struct mbridge *, struct ofbundle **,
                                  size_t n_bundles, struct hmapx *mbundles);
static int mirror_scan(struct mbridge *);
static void mirror_update_dups(struct mbridge *);

struct mbridge *
mbridge_create(void)
{
    struct mbridge *mbridge;

    mbridge = xzalloc(sizeof *mbridge);
    ovs_refcount_init(&mbridge->ref_cnt);

    hmap_init(&mbridge->mbundles);
    return mbridge;
}

struct mbridge *
mbridge_ref(const struct mbridge *mbridge_)
{
    struct mbridge *mbridge = CONST_CAST(struct mbridge *, mbridge_);
    if (mbridge) {
        ovs_refcount_ref(&mbridge->ref_cnt);
    }
    return mbridge;
}

void
mbridge_unref(struct mbridge *mbridge)
{
    struct mbundle *mbundle, *next;
    size_t i;

    if (!mbridge) {
        return;
    }

    if (ovs_refcount_unref(&mbridge->ref_cnt) == 1) {
        for (i = 0; i < MAX_MIRRORS; i++) {
            if (mbridge->mirrors[i]) {
                mirror_destroy(mbridge, mbridge->mirrors[i]->aux);
            }
        }

        HMAP_FOR_EACH_SAFE (mbundle, next, hmap_node, &mbridge->mbundles) {
            mbridge_unregister_bundle(mbridge, mbundle->ofbundle);
        }

        hmap_destroy(&mbridge->mbundles);
        free(mbridge);
    }
}

bool
mbridge_has_mirrors(struct mbridge *mbridge)
{
    return mbridge ? mbridge->has_mirrors : false;
}

/* Returns true if configurations changes in 'mbridge''s mirrors require
 * revalidation. */
bool
mbridge_need_revalidate(struct mbridge *mbridge)
{
    return mbridge->need_revalidate;
}

void
mbridge_register_bundle(struct mbridge *mbridge, struct ofbundle *ofbundle)
{
    struct mbundle *mbundle;

    mbundle = xzalloc(sizeof *mbundle);
    mbundle->ofbundle = ofbundle;
    hmap_insert(&mbridge->mbundles, &mbundle->hmap_node,
                hash_pointer(ofbundle, 0));
}

void
mbridge_unregister_bundle(struct mbridge *mbridge, struct ofbundle *ofbundle)
{
    struct mbundle *mbundle = mbundle_lookup(mbridge, ofbundle);
    size_t i;

    if (!mbundle) {
        return;
    }

    for (i = 0; i < MAX_MIRRORS; i++) {
        struct mirror *m = mbridge->mirrors[i];
        if (m) {
            if (m->out == mbundle) {
                mirror_destroy(mbridge, m->aux);
            } else if (hmapx_find_and_delete(&m->srcs, mbundle)
                       || hmapx_find_and_delete(&m->dsts, mbundle)) {
                mbridge->need_revalidate = true;
            }
        }
    }

    hmap_remove(&mbridge->mbundles, &mbundle->hmap_node);
    free(mbundle);
}

mirror_mask_t
mirror_bundle_out(struct mbridge *mbridge, struct ofbundle *ofbundle)
{
    struct mbundle *mbundle = mbundle_lookup(mbridge, ofbundle);
    return mbundle ? mbundle->mirror_out : 0;
}

mirror_mask_t
mirror_bundle_src(struct mbridge *mbridge, struct ofbundle *ofbundle)
{
    struct mbundle *mbundle = mbundle_lookup(mbridge, ofbundle);
    return mbundle ? mbundle->src_mirrors : 0;
}

mirror_mask_t
mirror_bundle_dst(struct mbridge *mbridge, struct ofbundle *ofbundle)
{
    struct mbundle *mbundle = mbundle_lookup(mbridge, ofbundle);
    return mbundle ? mbundle->dst_mirrors : 0;
}

int
mirror_set(struct mbridge *mbridge, void *aux, const char *name,
           struct ofbundle **srcs, size_t n_srcs,
           struct ofbundle **dsts, size_t n_dsts,
           unsigned long *src_vlans, struct ofbundle *out_bundle,
           uint16_t out_vlan)
{
    struct mbundle *mbundle, *out;
    mirror_mask_t mirror_bit;
    struct mirror *mirror;
    struct hmapx srcs_map;          /* Contains "struct ofbundle *"s. */
    struct hmapx dsts_map;          /* Contains "struct ofbundle *"s. */

    mirror = mirror_lookup(mbridge, aux);
    if (!mirror) {
        int idx;

        idx = mirror_scan(mbridge);
        if (idx < 0) {
            VLOG_WARN("maximum of %d port mirrors reached, cannot create %s",
                      MAX_MIRRORS, name);
            return EFBIG;
        }

        mirror = mbridge->mirrors[idx] = xzalloc(sizeof *mirror);
        mirror->mbridge = mbridge;
        mirror->idx = idx;
        mirror->aux = aux;
        mirror->out_vlan = -1;
    }

    /* Get the new configuration. */
    if (out_bundle) {
        out = mbundle_lookup(mbridge, out_bundle);
        if (!out) {
            mirror_destroy(mbridge, mirror->aux);
            return EINVAL;
        }
        out_vlan = -1;
    } else {
        out = NULL;
    }
    mbundle_lookup_multiple(mbridge, srcs, n_srcs, &srcs_map);
    mbundle_lookup_multiple(mbridge, dsts, n_dsts, &dsts_map);

    /* If the configuration has not changed, do nothing. */
    if (hmapx_equals(&srcs_map, &mirror->srcs)
        && hmapx_equals(&dsts_map, &mirror->dsts)
        && vlan_bitmap_equal(mirror->vlans, src_vlans)
        && mirror->out == out
        && mirror->out_vlan == out_vlan)
    {
        hmapx_destroy(&srcs_map);
        hmapx_destroy(&dsts_map);
        return 0;
    }

    hmapx_swap(&srcs_map, &mirror->srcs);
    hmapx_destroy(&srcs_map);

    hmapx_swap(&dsts_map, &mirror->dsts);
    hmapx_destroy(&dsts_map);

    free(mirror->vlans);
    mirror->vlans = vlan_bitmap_clone(src_vlans);

    mirror->out = out;
    mirror->out_vlan = out_vlan;

    /* Update mbundles. */
    mirror_bit = MIRROR_MASK_C(1) << mirror->idx;
    HMAP_FOR_EACH (mbundle, hmap_node, &mirror->mbridge->mbundles) {
        if (hmapx_contains(&mirror->srcs, mbundle)) {
            mbundle->src_mirrors |= mirror_bit;
        } else {
            mbundle->src_mirrors &= ~mirror_bit;
        }

        if (hmapx_contains(&mirror->dsts, mbundle)) {
            mbundle->dst_mirrors |= mirror_bit;
        } else {
            mbundle->dst_mirrors &= ~mirror_bit;
        }

        if (mirror->out == mbundle) {
            mbundle->mirror_out |= mirror_bit;
        } else {
            mbundle->mirror_out &= ~mirror_bit;
        }
    }

    mbridge->has_mirrors = true;
    mirror_update_dups(mbridge);

    return 0;
}

void
mirror_destroy(struct mbridge *mbridge, void *aux)
{
    struct mirror *mirror = mirror_lookup(mbridge, aux);
    mirror_mask_t mirror_bit;
    struct mbundle *mbundle;
    int i;

    if (!mirror) {
        return;
    }

    mirror_bit = MIRROR_MASK_C(1) << mirror->idx;
    HMAP_FOR_EACH (mbundle, hmap_node, &mbridge->mbundles) {
        mbundle->src_mirrors &= ~mirror_bit;
        mbundle->dst_mirrors &= ~mirror_bit;
        mbundle->mirror_out &= ~mirror_bit;
    }

    hmapx_destroy(&mirror->srcs);
    hmapx_destroy(&mirror->dsts);
    free(mirror->vlans);

    mbridge->mirrors[mirror->idx] = NULL;
    free(mirror);

    mirror_update_dups(mbridge);

    mbridge->has_mirrors = false;
    for (i = 0; i < MAX_MIRRORS; i++) {
        if (mbridge->mirrors[i]) {
            mbridge->has_mirrors = true;
            break;
        }
    }
}

int
mirror_get_stats(struct mbridge *mbridge, void *aux, uint64_t *packets,
                 uint64_t *bytes)
{
    struct mirror *mirror = mirror_lookup(mbridge, aux);

    if (!mirror) {
        *packets = *bytes = UINT64_MAX;
        return 0;
    }

    *packets = mirror->packet_count;
    *bytes = mirror->byte_count;

    return 0;
}

void
mirror_update_stats(struct mbridge *mbridge, mirror_mask_t mirrors,
                    uint64_t packets, uint64_t bytes)
{
    if (!mbridge || !mirrors) {
        return;
    }

    for (; mirrors; mirrors = zero_rightmost_1bit(mirrors)) {
        struct mirror *m;

        m = mbridge->mirrors[raw_ctz(mirrors)];

        if (!m) {
            /* In normal circumstances 'm' will not be NULL.  However,
             * if mirrors are reconfigured, we can temporarily get out
             * of sync in facet_revalidate().  We could "correct" the
             * mirror list before reaching here, but doing that would
             * not properly account the traffic stats we've currently
             * accumulated for previous mirror configuration. */
            continue;
        }

        m->packet_count += packets;
        m->byte_count += bytes;
    }
}

/* Retrieves the mirror in 'mbridge' represented by the first bet set of
 * 'mirrors'.  Returns true if such a mirror exists, false otherwise.
 * The caller takes ownership of, and is expected to deallocate, 'vlans' */
bool
mirror_get(struct mbridge *mbridge, int index, unsigned long **vlans,
           mirror_mask_t *dup_mirrors, struct ofbundle **out, int *out_vlan)
{
    struct mirror *mirror;

    if (!mbridge) {
        return false;
    }

    mirror = mbridge->mirrors[index];
    if (!mirror) {
        return false;
    }

    *vlans = vlan_bitmap_clone(mirror->vlans);
    *dup_mirrors = mirror->dup_mirrors;
    *out = mirror->out ? mirror->out->ofbundle : NULL;
    *out_vlan = mirror->out_vlan;
    return true;
}

/* Helpers. */

static struct mbundle *
mbundle_lookup(const struct mbridge *mbridge, struct ofbundle *ofbundle)
{
    struct mbundle *mbundle;

    HMAP_FOR_EACH_IN_BUCKET (mbundle, hmap_node, hash_pointer(ofbundle, 0),
                             &mbridge->mbundles) {
        if (mbundle->ofbundle == ofbundle) {
            return mbundle;
        }
    }
    return NULL;
}

/* Looks up each of the 'n_ofbundlees' pointers in 'ofbundlees' as mbundles and
 * adds the ones that are found to 'mbundles'. */
static void
mbundle_lookup_multiple(const struct mbridge *mbridge,
                        struct ofbundle **ofbundles, size_t n_ofbundles,
                        struct hmapx *mbundles)
{
    size_t i;

    hmapx_init(mbundles);
    for (i = 0; i < n_ofbundles; i++) {
        struct mbundle *mbundle = mbundle_lookup(mbridge, ofbundles[i]);
        if (mbundle) {
            hmapx_add(mbundles, mbundle);
        }
    }
}

static int
mirror_scan(struct mbridge *mbridge)
{
    int idx;

    for (idx = 0; idx < MAX_MIRRORS; idx++) {
        if (!mbridge->mirrors[idx]) {
            return idx;
        }
    }
    return -1;
}

static struct mirror *
mirror_lookup(struct mbridge *mbridge, void *aux)
{
    int i;

    for (i = 0; i < MAX_MIRRORS; i++) {
        struct mirror *mirror = mbridge->mirrors[i];
        if (mirror && mirror->aux == aux) {
            return mirror;
        }
    }

    return NULL;
}

/* Update the 'dup_mirrors' member of each of the mirrors in 'ofproto'. */
static void
mirror_update_dups(struct mbridge *mbridge)
{
    int i;

    for (i = 0; i < MAX_MIRRORS; i++) {
        struct mirror *m = mbridge->mirrors[i];

        if (m) {
            m->dup_mirrors = MIRROR_MASK_C(1) << i;
        }
    }

    for (i = 0; i < MAX_MIRRORS; i++) {
        struct mirror *m1 = mbridge->mirrors[i];
        int j;

        if (!m1) {
            continue;
        }

        for (j = i + 1; j < MAX_MIRRORS; j++) {
            struct mirror *m2 = mbridge->mirrors[j];

            if (m2 && m1->out == m2->out && m1->out_vlan == m2->out_vlan) {
                m1->dup_mirrors |= MIRROR_MASK_C(1) << j;
                m2->dup_mirrors |= m1->dup_mirrors;
            }
        }
    }
}
