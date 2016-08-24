/*
 * Copyright (c) 2016 Nicira, Inc.
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

#ifndef VERSIONS_H
#define VERSIONS_H 1

#include "ovs-atomic.h"
#include "openvswitch/type-props.h"

typedef uint64_t ovs_version_t;

#define OVS_VERSION_MIN 0                  /* Default version number to use. */
#define OVS_VERSION_MAX (TYPE_MAXIMUM(ovs_version_t) - 1)
#define OVS_VERSION_NOT_REMOVED TYPE_MAXIMUM(ovs_version_t)

/*
 * OVS_VERSION_NOT_REMOVED has a special meaning for 'remove_version',
 * meaning that the rule has been added but not yet removed.
 */
struct versions {
    ovs_version_t add_version;              /* Version object was added in. */
    ATOMIC(ovs_version_t) remove_version;   /* Version object is removed in. */
};

#define VERSIONS_INITIALIZER(ADD, REMOVE) \
    (struct versions){ ADD, ATOMIC_VAR_INIT(REMOVE) }

static inline void
versions_set_remove_version(struct versions *versions, ovs_version_t version)
{
    atomic_store_relaxed(&versions->remove_version, version);
}

static inline bool
versions_visible_in_version(const struct versions *versions,
                            ovs_version_t version)
{
    ovs_version_t remove_version;

    /* C11 does not want to access an atomic via a const object pointer. */
    atomic_read_relaxed(&CONST_CAST(struct versions *,
                                    versions)->remove_version,
                        &remove_version);

    return versions->add_version <= version && version < remove_version;
}

static inline bool
versions_is_eventually_invisible(const struct versions *versions)
{
    ovs_version_t remove_version;

    /* C11 does not want to access an atomic via a const object pointer. */
    atomic_read_relaxed(&CONST_CAST(struct versions *,
                                    versions)->remove_version,
                        &remove_version);

    return remove_version < OVS_VERSION_NOT_REMOVED;
}

#endif /* VERSIONS_H */
