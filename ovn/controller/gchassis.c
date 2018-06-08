/* Copyright (c) 2017, Red Hat, Inc.
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

#include <config.h>

#include "gchassis.h"
#include "lport.h"
#include "lib/sset.h"
#include "openvswitch/vlog.h"
#include "ovn/lib/chassis-index.h"
#include "ovn/lib/ovn-sb-idl.h"

VLOG_DEFINE_THIS_MODULE(gchassis);

/* gateway_chassis ordering
 */
static int
compare_chassis_prio_(const void *a_, const void *b_)
{
    const struct gateway_chassis *gc_a = a_;
    const struct gateway_chassis *gc_b = b_;
    int prio_diff = gc_b->db->priority - gc_a->db->priority;
    if (!prio_diff) {
        return strcmp(gc_b->db->name, gc_a->db->name);
    }
    return prio_diff;
}

struct ovs_list*
gateway_chassis_get_ordered(struct ovsdb_idl_index *sbrec_chassis_by_name,
                            const struct sbrec_port_binding *binding)
{
    const char *redir_chassis_str;
    const struct sbrec_chassis *redirect_chassis = NULL;

    /* XXX: redirect-chassis SBDB option handling is supported for backwards
     * compatibility with N-1 version of ovn-northd. This support can
     * be removed in OVS 2.9 where Gateway_Chassis list on the port binding
     * will always be populated by northd */
    redir_chassis_str = smap_get(&binding->options, "redirect-chassis");

    if (redir_chassis_str) {
        redirect_chassis = chassis_lookup_by_name(sbrec_chassis_by_name,
                                                  redir_chassis_str);
        if (!redirect_chassis) {
            static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 1);
            VLOG_WARN_RL(&rl, "chassis name (%s) in redirect-chassis option "
                              "of logical port %s not known",
                              redir_chassis_str, binding->logical_port);
        }
    }

    if (!redirect_chassis && binding->n_gateway_chassis == 0) {
        return NULL;
    }

    struct gateway_chassis *gateway_chassis = NULL;
    int n = 0;

    if (binding->n_gateway_chassis) {
        gateway_chassis = xmalloc(sizeof *gateway_chassis *
                                  binding->n_gateway_chassis);
        for (n = 0; n < binding->n_gateway_chassis; n++) {
            gateway_chassis[n].db = binding->gateway_chassis[n];
            gateway_chassis[n].virtual_gwc = false;
        }
        qsort(gateway_chassis, n, sizeof *gateway_chassis,
              compare_chassis_prio_);
    } else if (redirect_chassis) {
        /* When only redirect_chassis is available, return a single
         * virtual entry that it's not on OVSDB, this way the code
         * handling the returned list will be uniform, regardless
         * of gateway_chassis being populated or redirect-chassis option
         * being used */
        gateway_chassis = xmalloc(sizeof *gateway_chassis);
        struct sbrec_gateway_chassis *gwc =
            xzalloc(sizeof *gateway_chassis->db);
        sbrec_gateway_chassis_init(gwc);
        gwc->name = xasprintf("%s_%s", binding->logical_port,
                                       redirect_chassis->name);
        gwc->chassis = CONST_CAST(struct sbrec_chassis *, redirect_chassis);
        gateway_chassis->db = gwc;
        gateway_chassis->virtual_gwc = true;
        n++;
    }

    struct ovs_list *list = NULL;
    if (n) {
        list = xmalloc(sizeof *list);
        ovs_list_init(list);

        int i;
        for (i = 0; i < n; i++) {
            ovs_list_push_back(list, &gateway_chassis[i].node);
        }
    }

    return list;
}

bool
gateway_chassis_contains(const struct ovs_list *gateway_chassis,
                         const struct sbrec_chassis *chassis) {
    struct gateway_chassis *chassis_item;
    if (gateway_chassis) {
        LIST_FOR_EACH (chassis_item, node, gateway_chassis) {
            if (chassis_item->db->chassis
                && !strcmp(chassis_item->db->chassis->name, chassis->name)) {
                return true;
            }
        }
    }
    return false;
}

void
gateway_chassis_destroy(struct ovs_list *list)
{
    if (!list) {
        return;
    }

    /* XXX: This loop is for backwards compatibility with redirect-chassis
     * which we insert as a single virtual Gateway_Chassis on the ordered
     * list */
    struct gateway_chassis *chassis_item;
    LIST_FOR_EACH (chassis_item, node, list) {
        if (chassis_item->virtual_gwc) {
            free(chassis_item->db->name);
            free(CONST_CAST(struct sbrec_gateway_chassis *, chassis_item->db));
        }
    }

    free(ovs_list_front(list));
    free(list);
}

bool
gateway_chassis_in_pb_contains(const struct sbrec_port_binding *binding,
                               const struct sbrec_chassis *chassis)
{
    if (!binding || !chassis) {
        return false;
    }

    /* XXX: redirect-chassis handling for backwards compatibility,
     * with older ovs-northd during upgrade phase, can be removed
     * for OVS 2.9 */
    const char *redirect_chassis = smap_get(&binding->options,
                                            "redirect-chassis");
    if (binding->n_gateway_chassis) {
        int n;
        for (n = 0; n < binding->n_gateway_chassis; n++) {
            if (binding->gateway_chassis[n]->chassis
                && !strcmp(binding->gateway_chassis[n]->chassis->name,
                           chassis->name)) {
                return true;
            }
        }
    } else if (redirect_chassis) {
        return !strcmp(redirect_chassis, chassis->name);
    }

    return false;
}

bool
gateway_chassis_is_active(const struct ovs_list *gateway_chassis,
                          const struct sbrec_chassis *local_chassis,
                          const struct sset *active_tunnels)
{
    struct gateway_chassis *gwc;

    if (!gateway_chassis
        || (gateway_chassis && ovs_list_is_empty(gateway_chassis))) {
        return false;
    }
    /* if there's only one chassis, and local chassis is on the list
     * it's not HA and it's the equivalent of being active */
    if (ovs_list_is_singleton(gateway_chassis) &&
        gateway_chassis_contains(gateway_chassis, local_chassis)) {
        return true;
    }

    /* if there are no other tunnels active, we assume that the
     * connection providing tunneling is down, hence we're down */
    if (sset_is_empty(active_tunnels)) {
        return false;
    }

    /* gateway_chassis is an ordered list, by priority, of chassis
     * hosting the redirect of the port */
    LIST_FOR_EACH (gwc, node, gateway_chassis) {
        if (!gwc->db->chassis) {
            continue;
        }
        /* if we found the chassis on the list, and we didn't exit before
         * on the active_tunnels check for other higher priority chassis
         * being active, then this chassis is master. */
        if (!strcmp(gwc->db->chassis->name, local_chassis->name)) {
            return true;
        }
        /* if we find this specific chassis on the list to have an active
         * tunnel, then 'local_chassis' is not master */
        if (sset_contains(active_tunnels, gwc->db->chassis->name)) {
            return false;
        }
    }
    return false;
}
