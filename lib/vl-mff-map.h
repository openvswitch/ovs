/*
 * Copyright (c) 2017 Nicira, Inc.
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

#ifndef VL_MFF_MAP_H
#define VL_MFF_MAP_H 1

#include "cmap.h"
#include "openvswitch/thread.h"

/* Variable length mf_fields mapping map. This is a single writer,
 * multiple-reader hash table that a writer must hold the following mutex
 * to access this map. */
struct vl_mff_map {
    struct cmap cmap;       /* Contains 'struct mf_field' */
    struct ovs_mutex mutex;
};

/* Variable length fields. */
enum ofperr mf_vl_mff_map_clear(struct vl_mff_map *vl_mff_map, bool)
    OVS_REQUIRES(vl_mff_map->mutex);
enum ofperr mf_vl_mff_map_mod_from_tun_metadata(
    struct vl_mff_map *vl_mff_map, const struct ofputil_tlv_table_mod *)
    OVS_REQUIRES(vl_mff_map->mutex);
const struct mf_field * mf_get_vl_mff(const struct mf_field *,
                                      const struct vl_mff_map *);
bool mf_vl_mff_invalid(const struct mf_field *, const struct vl_mff_map *);
void mf_vl_mff_set_tlv_bitmap(const struct mf_field *, uint64_t *tlv_bitmap);
void mf_vl_mff_ref(const struct vl_mff_map *, uint64_t tlv_bitmap);
void mf_vl_mff_unref(const struct vl_mff_map *, uint64_t tlv_bitmap);
enum ofperr mf_vl_mff_nx_pull_header(struct ofpbuf *,
                                     const struct vl_mff_map *,
                                     const struct mf_field **, bool *masked,
                                     uint64_t *tlv_bitmap);
enum ofperr mf_vl_mff_nx_pull_entry(struct ofpbuf *, const struct vl_mff_map *,
                                    const struct mf_field **, union mf_value *,
                                    union mf_value *, uint64_t *tlv_bitmap);
enum ofperr mf_vl_mff_mf_from_nxm_header(uint32_t header,
                                         const struct vl_mff_map *,
                                         const struct mf_field **,
                                         uint64_t *tlv_bitmap);
#endif /* vl-mff-map.h */
