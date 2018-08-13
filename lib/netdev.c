/*
 * Copyright (c) 2008, 2009, 2010, 2011, 2012, 2013, 2014, 2016, 2017 Nicira, Inc.
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
#include "netdev.h"

#include <errno.h>
#include <inttypes.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#ifndef _WIN32
#include <ifaddrs.h>
#include <net/if.h>
#include <sys/ioctl.h>
#endif

#include "cmap.h"
#include "coverage.h"
#include "dpif.h"
#include "dp-packet.h"
#include "openvswitch/dynamic-string.h"
#include "fatal-signal.h"
#include "hash.h"
#include "openvswitch/list.h"
#include "netdev-dpdk.h"
#include "netdev-provider.h"
#include "netdev-vport.h"
#include "odp-netlink.h"
#include "openflow/openflow.h"
#include "packets.h"
#include "openvswitch/ofp-print.h"
#include "openvswitch/poll-loop.h"
#include "seq.h"
#include "openvswitch/shash.h"
#include "smap.h"
#include "socket-util.h"
#include "sset.h"
#include "svec.h"
#include "openvswitch/vlog.h"
#include "flow.h"
#include "util.h"
#ifdef __linux__
#include "tc.h"
#endif

VLOG_DEFINE_THIS_MODULE(netdev);

COVERAGE_DEFINE(netdev_received);
COVERAGE_DEFINE(netdev_sent);
COVERAGE_DEFINE(netdev_add_router);
COVERAGE_DEFINE(netdev_get_stats);

struct netdev_saved_flags {
    struct netdev *netdev;
    struct ovs_list node;           /* In struct netdev's saved_flags_list. */
    enum netdev_flags saved_flags;
    enum netdev_flags saved_values;
};

/* Protects 'netdev_shash' and the mutable members of struct netdev. */
static struct ovs_mutex netdev_mutex = OVS_MUTEX_INITIALIZER;

/* All created network devices. */
static struct shash netdev_shash OVS_GUARDED_BY(netdev_mutex)
    = SHASH_INITIALIZER(&netdev_shash);

/* Mutual exclusion of */
static struct ovs_mutex netdev_class_mutex OVS_ACQ_BEFORE(netdev_mutex)
    = OVS_MUTEX_INITIALIZER;

/* Contains 'struct netdev_registered_class'es. */
static struct cmap netdev_classes = CMAP_INITIALIZER;

struct netdev_registered_class {
    struct cmap_node cmap_node; /* In 'netdev_classes', by class->type. */
    const struct netdev_class *class;

    /* Number of references: one for the class itself and one for every
     * instance of the class. */
    struct ovs_refcount refcnt;
};

static bool netdev_flow_api_enabled = false;

/* This is set pretty low because we probably won't learn anything from the
 * additional log messages. */
static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(5, 20);

static void restore_all_flags(void *aux OVS_UNUSED);
void update_device_args(struct netdev *, const struct shash *args);

int
netdev_n_txq(const struct netdev *netdev)
{
    return netdev->n_txq;
}

int
netdev_n_rxq(const struct netdev *netdev)
{
    return netdev->n_rxq;
}

bool
netdev_is_pmd(const struct netdev *netdev)
{
    return netdev->netdev_class->is_pmd;
}

bool
netdev_has_tunnel_push_pop(const struct netdev *netdev)
{
    return netdev->netdev_class->push_header
           && netdev->netdev_class->pop_header;
}

static void
netdev_initialize(void)
    OVS_EXCLUDED(netdev_mutex)
{
    static struct ovsthread_once once = OVSTHREAD_ONCE_INITIALIZER;

    if (ovsthread_once_start(&once)) {
        fatal_signal_add_hook(restore_all_flags, NULL, NULL, true);

        netdev_vport_patch_register();

#ifdef __linux__
        netdev_register_provider(&netdev_linux_class);
        netdev_register_provider(&netdev_internal_class);
        netdev_register_provider(&netdev_tap_class);
        netdev_vport_tunnel_register();
#endif
#if defined(__FreeBSD__) || defined(__NetBSD__)
        netdev_register_provider(&netdev_tap_class);
        netdev_register_provider(&netdev_bsd_class);
#endif
#ifdef _WIN32
        netdev_register_provider(&netdev_windows_class);
        netdev_register_provider(&netdev_internal_class);
        netdev_vport_tunnel_register();
#endif
        ovsthread_once_done(&once);
    }
}

/* Performs periodic work needed by all the various kinds of netdevs.
 *
 * If your program opens any netdevs, it must call this function within its
 * main poll loop. */
void
netdev_run(void)
    OVS_EXCLUDED(netdev_mutex)
{
    netdev_initialize();

    struct netdev_registered_class *rc;
    CMAP_FOR_EACH (rc, cmap_node, &netdev_classes) {
        if (rc->class->run) {
            rc->class->run(rc->class);
        }
    }
}

/* Arranges for poll_block() to wake up when netdev_run() needs to be called.
 *
 * If your program opens any netdevs, it must call this function within its
 * main poll loop. */
void
netdev_wait(void)
    OVS_EXCLUDED(netdev_mutex)
{
    netdev_initialize();

    struct netdev_registered_class *rc;
    CMAP_FOR_EACH (rc, cmap_node, &netdev_classes) {
        if (rc->class->wait) {
            rc->class->wait(rc->class);
        }
    }
}

static struct netdev_registered_class *
netdev_lookup_class(const char *type)
{
    struct netdev_registered_class *rc;
    CMAP_FOR_EACH_WITH_HASH (rc, cmap_node, hash_string(type, 0),
                             &netdev_classes) {
        if (!strcmp(type, rc->class->type)) {
            return rc;
        }
    }
    return NULL;
}

/* Initializes and registers a new netdev provider.  After successful
 * registration, new netdevs of that type can be opened using netdev_open(). */
int
netdev_register_provider(const struct netdev_class *new_class)
    OVS_EXCLUDED(netdev_class_mutex, netdev_mutex)
{
    int error;

    ovs_mutex_lock(&netdev_class_mutex);
    if (netdev_lookup_class(new_class->type)) {
        VLOG_WARN("attempted to register duplicate netdev provider: %s",
                   new_class->type);
        error = EEXIST;
    } else {
        error = new_class->init ? new_class->init() : 0;
        if (!error) {
            struct netdev_registered_class *rc;

            rc = xmalloc(sizeof *rc);
            cmap_insert(&netdev_classes, &rc->cmap_node,
                        hash_string(new_class->type, 0));
            rc->class = new_class;
            ovs_refcount_init(&rc->refcnt);
        } else {
            VLOG_ERR("failed to initialize %s network device class: %s",
                     new_class->type, ovs_strerror(error));
        }
    }
    ovs_mutex_unlock(&netdev_class_mutex);

    return error;
}

/* Unregisters a netdev provider.  'type' must have been previously registered
 * and not currently be in use by any netdevs.  After unregistration new
 * netdevs of that type cannot be opened using netdev_open().  (However, the
 * provider may still be accessible from other threads until the next RCU grace
 * period, so the caller must not free or re-register the same netdev_class
 * until that has passed.) */
int
netdev_unregister_provider(const char *type)
    OVS_EXCLUDED(netdev_class_mutex, netdev_mutex)
{
    struct netdev_registered_class *rc;
    int error;

    netdev_initialize();

    ovs_mutex_lock(&netdev_class_mutex);
    rc = netdev_lookup_class(type);
    if (!rc) {
        VLOG_WARN("attempted to unregister a netdev provider that is not "
                  "registered: %s", type);
        error = EAFNOSUPPORT;
    } else if (ovs_refcount_unref(&rc->refcnt) != 1) {
        ovs_refcount_ref(&rc->refcnt);
        VLOG_WARN("attempted to unregister in use netdev provider: %s",
                  type);
        error = EBUSY;
    } else  {
        cmap_remove(&netdev_classes, &rc->cmap_node,
                    hash_string(rc->class->type, 0));
        ovsrcu_postpone(free, rc);
        error = 0;
    }
    ovs_mutex_unlock(&netdev_class_mutex);

    return error;
}

/* Clears 'types' and enumerates the types of all currently registered netdev
 * providers into it.  The caller must first initialize the sset. */
void
netdev_enumerate_types(struct sset *types)
    OVS_EXCLUDED(netdev_mutex)
{
    netdev_initialize();
    sset_clear(types);

    struct netdev_registered_class *rc;
    CMAP_FOR_EACH (rc, cmap_node, &netdev_classes) {
        sset_add(types, rc->class->type);
    }
}

static const char *
netdev_vport_type_from_name(const char *name)
{
    struct netdev_registered_class *rc;
    const char *type;
    CMAP_FOR_EACH (rc, cmap_node, &netdev_classes) {
        const char *dpif_port = netdev_vport_class_get_dpif_port(rc->class);
        if (dpif_port && !strncmp(name, dpif_port, strlen(dpif_port))) {
            type = rc->class->type;
            return type;
        }
    }
    return NULL;
}

/* Check that the network device name is not the same as any of the registered
 * vport providers' dpif_port name (dpif_port is NULL if the vport provider
 * does not define it) or the datapath internal port name (e.g. ovs-system).
 *
 * Returns true if there is a name conflict, false otherwise. */
bool
netdev_is_reserved_name(const char *name)
    OVS_EXCLUDED(netdev_mutex)
{
    netdev_initialize();

    struct netdev_registered_class *rc;
    CMAP_FOR_EACH (rc, cmap_node, &netdev_classes) {
        const char *dpif_port = netdev_vport_class_get_dpif_port(rc->class);
        if (dpif_port && !strncmp(name, dpif_port, strlen(dpif_port))) {
            return true;
        }
    }

    if (!strncmp(name, "ovs-", 4)) {
        struct sset types;
        const char *type;

        sset_init(&types);
        dp_enumerate_types(&types);
        SSET_FOR_EACH (type, &types) {
            if (!strcmp(name+4, type)) {
                sset_destroy(&types);
                return true;
            }
        }
        sset_destroy(&types);
    }

    return false;
}

/* Opens the network device named 'name' (e.g. "eth0") of the specified 'type'
 * (e.g. "system") and returns zero if successful, otherwise a positive errno
 * value.  On success, sets '*netdevp' to the new network device, otherwise to
 * null.
 *
 * Some network devices may need to be configured (with netdev_set_config())
 * before they can be used.
 *
 * Before opening rxqs or sending packets, '*netdevp' may need to be
 * reconfigured (with netdev_is_reconf_required() and netdev_reconfigure()).
 * */
int
netdev_open(const char *name, const char *type, struct netdev **netdevp)
    OVS_EXCLUDED(netdev_mutex)
{
    struct netdev *netdev;
    int error = 0;

    if (!name[0]) {
        /* Reject empty names.  This saves the providers having to do this.  At
         * least one screwed this up: the netdev-linux "tap" implementation
         * passed the name directly to the Linux TUNSETIFF call, which treats
         * an empty string as a request to generate a unique name. */
        return EINVAL;
    }

    netdev_initialize();

    ovs_mutex_lock(&netdev_mutex);
    netdev = shash_find_data(&netdev_shash, name);

    if (netdev &&
        type && type[0] && strcmp(type, netdev->netdev_class->type)) {

        if (netdev->auto_classified) {
            /* If this device was first created without a classification type,
             * for example due to routing or tunneling code, and they keep a
             * reference, a "classified" call to open will fail. In this case
             * we remove the classless device, and re-add it below. We remove
             * the netdev from the shash, and change the sequence, so owners of
             * the old classless device can release/cleanup. */
            if (netdev->node) {
                shash_delete(&netdev_shash, netdev->node);
                netdev->node = NULL;
                netdev_change_seq_changed(netdev);
            }

            netdev = NULL;
        } else {
            error = EEXIST;
        }
    }

    if (!netdev) {
        struct netdev_registered_class *rc;

        rc = netdev_lookup_class(type && type[0] ? type : "system");
        if (rc && ovs_refcount_try_ref_rcu(&rc->refcnt)) {
            netdev = rc->class->alloc();
            if (netdev) {
                memset(netdev, 0, sizeof *netdev);
                netdev->netdev_class = rc->class;
                netdev->auto_classified = type && type[0] ? false : true;
                netdev->name = xstrdup(name);
                netdev->change_seq = 1;
                netdev->reconfigure_seq = seq_create();
                netdev->last_reconfigure_seq =
                    seq_read(netdev->reconfigure_seq);
                netdev->node = shash_add(&netdev_shash, name, netdev);

                /* By default enable one tx and rx queue per netdev. */
                netdev->n_txq = netdev->netdev_class->send ? 1 : 0;
                netdev->n_rxq = netdev->netdev_class->rxq_alloc ? 1 : 0;

                ovs_list_init(&netdev->saved_flags_list);

                error = rc->class->construct(netdev);
                if (!error) {
                    netdev_change_seq_changed(netdev);
                } else {
                    ovs_refcount_unref(&rc->refcnt);
                    seq_destroy(netdev->reconfigure_seq);
                    free(netdev->name);
                    ovs_assert(ovs_list_is_empty(&netdev->saved_flags_list));
                    shash_delete(&netdev_shash, netdev->node);
                    rc->class->dealloc(netdev);
                }
            } else {
                error = ENOMEM;
            }
        } else {
            VLOG_WARN("could not create netdev %s of unknown type %s",
                      name, type);
            error = EAFNOSUPPORT;
        }
    }

    if (!error) {
        netdev->ref_cnt++;
        *netdevp = netdev;
    } else {
        *netdevp = NULL;
    }
    ovs_mutex_unlock(&netdev_mutex);

    return error;
}

/* Returns a reference to 'netdev_' for the caller to own. Returns null if
 * 'netdev_' is null. */
struct netdev *
netdev_ref(const struct netdev *netdev_)
    OVS_EXCLUDED(netdev_mutex)
{
    struct netdev *netdev = CONST_CAST(struct netdev *, netdev_);

    if (netdev) {
        ovs_mutex_lock(&netdev_mutex);
        ovs_assert(netdev->ref_cnt > 0);
        netdev->ref_cnt++;
        ovs_mutex_unlock(&netdev_mutex);
    }
    return netdev;
}

/* Reconfigures the device 'netdev' with 'args'.  'args' may be empty
 * or NULL if none are needed. */
int
netdev_set_config(struct netdev *netdev, const struct smap *args, char **errp)
    OVS_EXCLUDED(netdev_mutex)
{
    if (netdev->netdev_class->set_config) {
        const struct smap no_args = SMAP_INITIALIZER(&no_args);
        char *verbose_error = NULL;
        int error;

        error = netdev->netdev_class->set_config(netdev,
                                                 args ? args : &no_args,
                                                 &verbose_error);
        if (error) {
            VLOG_WARN_BUF(verbose_error ? NULL : errp,
                          "%s: could not set configuration (%s)",
                          netdev_get_name(netdev), ovs_strerror(error));
            if (verbose_error) {
                if (errp) {
                    *errp = verbose_error;
                } else {
                    free(verbose_error);
                }
            }
        }
        return error;
    } else if (args && !smap_is_empty(args)) {
        VLOG_WARN_BUF(errp, "%s: arguments provided to device that is not configurable",
                      netdev_get_name(netdev));
    }
    return 0;
}

/* Returns the current configuration for 'netdev' in 'args'.  The caller must
 * have already initialized 'args' with smap_init().  Returns 0 on success, in
 * which case 'args' will be filled with 'netdev''s configuration.  On failure
 * returns a positive errno value, in which case 'args' will be empty.
 *
 * The caller owns 'args' and its contents and must eventually free them with
 * smap_destroy(). */
int
netdev_get_config(const struct netdev *netdev, struct smap *args)
    OVS_EXCLUDED(netdev_mutex)
{
    int error;

    smap_clear(args);
    if (netdev->netdev_class->get_config) {
        error = netdev->netdev_class->get_config(netdev, args);
        if (error) {
            smap_clear(args);
        }
    } else {
        error = 0;
    }

    return error;
}

const struct netdev_tunnel_config *
netdev_get_tunnel_config(const struct netdev *netdev)
    OVS_EXCLUDED(netdev_mutex)
{
    if (netdev->netdev_class->get_tunnel_config) {
        return netdev->netdev_class->get_tunnel_config(netdev);
    } else {
        return NULL;
    }
}

/* Returns the id of the numa node the 'netdev' is on.  If the function
 * is not implemented, returns NETDEV_NUMA_UNSPEC. */
int
netdev_get_numa_id(const struct netdev *netdev)
{
    if (netdev->netdev_class->get_numa_id) {
        return netdev->netdev_class->get_numa_id(netdev);
    } else {
        return NETDEV_NUMA_UNSPEC;
    }
}

static void
netdev_unref(struct netdev *dev)
    OVS_RELEASES(netdev_mutex)
{
    ovs_assert(dev->ref_cnt);
    if (!--dev->ref_cnt) {
        const struct netdev_class *class = dev->netdev_class;
        struct netdev_registered_class *rc;

        dev->netdev_class->destruct(dev);

        if (dev->node) {
            shash_delete(&netdev_shash, dev->node);
        }
        free(dev->name);
        seq_destroy(dev->reconfigure_seq);
        dev->netdev_class->dealloc(dev);
        ovs_mutex_unlock(&netdev_mutex);

        rc = netdev_lookup_class(class->type);
        ovs_refcount_unref(&rc->refcnt);
    } else {
        ovs_mutex_unlock(&netdev_mutex);
    }
}

/* Closes and destroys 'netdev'. */
void
netdev_close(struct netdev *netdev)
    OVS_EXCLUDED(netdev_mutex)
{
    if (netdev) {
        ovs_mutex_lock(&netdev_mutex);
        netdev_unref(netdev);
    }
}

/* Removes 'netdev' from the global shash and unrefs 'netdev'.
 *
 * This allows handler and revalidator threads to still retain references
 * to this netdev while the main thread changes interface configuration.
 *
 * This function should only be called by the main thread when closing
 * netdevs during user configuration changes. Otherwise, netdev_close should be
 * used to close netdevs. */
void
netdev_remove(struct netdev *netdev)
{
    if (netdev) {
        ovs_mutex_lock(&netdev_mutex);
        if (netdev->node) {
            shash_delete(&netdev_shash, netdev->node);
            netdev->node = NULL;
            netdev_change_seq_changed(netdev);
        }
        netdev_unref(netdev);
    }
}

/* Parses 'netdev_name_', which is of the form [type@]name into its component
 * pieces.  'name' and 'type' must be freed by the caller. */
void
netdev_parse_name(const char *netdev_name_, char **name, char **type)
{
    char *netdev_name = xstrdup(netdev_name_);
    char *separator;

    separator = strchr(netdev_name, '@');
    if (separator) {
        *separator = '\0';
        *type = netdev_name;
        *name = xstrdup(separator + 1);
    } else {
        *name = netdev_name;
        *type = xstrdup("system");
    }
}

/* Attempts to open a netdev_rxq handle for obtaining packets received on
 * 'netdev'.  On success, returns 0 and stores a nonnull 'netdev_rxq *' into
 * '*rxp'.  On failure, returns a positive errno value and stores NULL into
 * '*rxp'.
 *
 * Some kinds of network devices might not support receiving packets.  This
 * function returns EOPNOTSUPP in that case.*/
int
netdev_rxq_open(struct netdev *netdev, struct netdev_rxq **rxp, int id)
    OVS_EXCLUDED(netdev_mutex)
{
    int error;

    if (netdev->netdev_class->rxq_alloc && id < netdev->n_rxq) {
        struct netdev_rxq *rx = netdev->netdev_class->rxq_alloc();
        if (rx) {
            rx->netdev = netdev;
            rx->queue_id = id;
            error = netdev->netdev_class->rxq_construct(rx);
            if (!error) {
                netdev_ref(netdev);
                *rxp = rx;
                return 0;
            }
            netdev->netdev_class->rxq_dealloc(rx);
        } else {
            error = ENOMEM;
        }
    } else {
        error = EOPNOTSUPP;
    }

    *rxp = NULL;
    return error;
}

/* Closes 'rx'. */
void
netdev_rxq_close(struct netdev_rxq *rx)
    OVS_EXCLUDED(netdev_mutex)
{
    if (rx) {
        struct netdev *netdev = rx->netdev;
        netdev->netdev_class->rxq_destruct(rx);
        netdev->netdev_class->rxq_dealloc(rx);
        netdev_close(netdev);
    }
}

/* Attempts to receive a batch of packets from 'rx'.  'batch' should point to
 * the beginning of an array of NETDEV_MAX_BURST pointers to dp_packet.  If
 * successful, this function stores pointers to up to NETDEV_MAX_BURST
 * dp_packets into the array, transferring ownership of the packets to the
 * caller, stores the number of received packets in 'batch->count', and returns
 * 0.
 *
 * The implementation does not necessarily initialize any non-data members of
 * 'batch'.  That is, the caller must initialize layer pointers and metadata
 * itself, if desired, e.g. with pkt_metadata_init() and miniflow_extract().
 *
 * Returns EAGAIN immediately if no packet is ready to be received or another
 * positive errno value if an error was encountered. */
int
netdev_rxq_recv(struct netdev_rxq *rx, struct dp_packet_batch *batch,
                int *qfill)
{
    int retval;

    retval = rx->netdev->netdev_class->rxq_recv(rx, batch, qfill);
    if (!retval) {
        COVERAGE_INC(netdev_received);
    } else {
        batch->count = 0;
    }
    return retval;
}

/* Arranges for poll_block() to wake up when a packet is ready to be received
 * on 'rx'. */
void
netdev_rxq_wait(struct netdev_rxq *rx)
{
    rx->netdev->netdev_class->rxq_wait(rx);
}

/* Discards any packets ready to be received on 'rx'. */
int
netdev_rxq_drain(struct netdev_rxq *rx)
{
    return (rx->netdev->netdev_class->rxq_drain
            ? rx->netdev->netdev_class->rxq_drain(rx)
            : 0);
}

/* Configures the number of tx queues of 'netdev'. Returns 0 if successful,
 * otherwise a positive errno value.
 *
 * 'n_txq' specifies the exact number of transmission queues to create.
 *
 * The change might not effective immediately.  The caller must check if a
 * reconfiguration is required with netdev_is_reconf_required() and eventually
 * call netdev_reconfigure() before using the new queues.
 *
 * On error, the tx queue configuration is unchanged */
int
netdev_set_tx_multiq(struct netdev *netdev, unsigned int n_txq)
{
    int error;

    error = (netdev->netdev_class->set_tx_multiq
             ? netdev->netdev_class->set_tx_multiq(netdev, MAX(n_txq, 1))
             : EOPNOTSUPP);

    if (error && error != EOPNOTSUPP) {
        VLOG_DBG_RL(&rl, "failed to set tx queue for network device %s:"
                    "%s", netdev_get_name(netdev), ovs_strerror(error));
    }

    return error;
}

enum netdev_pt_mode
netdev_get_pt_mode(const struct netdev *netdev)
{
    return (netdev->netdev_class->get_pt_mode
            ? netdev->netdev_class->get_pt_mode(netdev)
            : NETDEV_PT_LEGACY_L2);
}

/* Sends 'batch' on 'netdev'.  Returns 0 if successful (for every packet),
 * otherwise a positive errno value.  Returns EAGAIN without blocking if
 * at least one the packets cannot be queued immediately.  Returns EMSGSIZE
 * if a partial packet was transmitted or if a packet is too big or too small
 * to transmit on the device.
 *
 * The caller must make sure that 'netdev' supports sending by making sure that
 * 'netdev_n_txq(netdev)' returns >= 1.
 *
 * If the function returns a non-zero value, some of the packets might have
 * been sent anyway.
 *
 * The caller transfers ownership of all the packets to the network device,
 * regardless of success.
 *
 * If 'concurrent_txq' is true, the caller may perform concurrent calls
 * to netdev_send() with the same 'qid'. The netdev provider is responsible
 * for making sure that these concurrent calls do not create a race condition
 * by using locking or other synchronization if required.
 *
 * The network device is expected to maintain one or more packet
 * transmission queues, so that the caller does not ordinarily have to
 * do additional queuing of packets.  'qid' specifies the queue to use
 * and can be ignored if the implementation does not support multiple
 * queues. */
int
netdev_send(struct netdev *netdev, int qid, struct dp_packet_batch *batch,
            bool concurrent_txq)
{
    int error = netdev->netdev_class->send(netdev, qid, batch,
                                           concurrent_txq);
    if (!error) {
        COVERAGE_INC(netdev_sent);
    }
    return error;
}

/* Pop tunnel header, build tunnel metadata and resize 'batch->packets'
 * for further processing.
 *
 * The caller must make sure that 'netdev' support this operation by checking
 * that netdev_has_tunnel_push_pop() returns true. */
void
netdev_pop_header(struct netdev *netdev, struct dp_packet_batch *batch)
{
    struct dp_packet *packet;
    size_t i, size = dp_packet_batch_size(batch);

    DP_PACKET_BATCH_REFILL_FOR_EACH (i, size, packet, batch) {
        packet = netdev->netdev_class->pop_header(packet);
        if (packet) {
            /* Reset the checksum offload flags if present, to avoid wrong
             * interpretation in the further packet processing when
             * recirculated.*/
            reset_dp_packet_checksum_ol_flags(packet);
            dp_packet_batch_refill(batch, packet, i);
        }
    }
}

void
netdev_init_tnl_build_header_params(struct netdev_tnl_build_header_params *params,
                                    const struct flow *tnl_flow,
                                    const struct in6_addr *src,
                                    struct eth_addr dmac,
                                    struct eth_addr smac)
{
    params->flow = tnl_flow;
    params->dmac = dmac;
    params->smac = smac;
    params->s_ip = src;
    params->is_ipv6 = !IN6_IS_ADDR_V4MAPPED(src);
}

int netdev_build_header(const struct netdev *netdev,
                        struct ovs_action_push_tnl *data,
                        const struct netdev_tnl_build_header_params *params)
{
    if (netdev->netdev_class->build_header) {
        return netdev->netdev_class->build_header(netdev, data, params);
    }
    return EOPNOTSUPP;
}

/* Push tunnel header (reading from tunnel metadata) and resize
 * 'batch->packets' for further processing.
 *
 * The caller must make sure that 'netdev' support this operation by checking
 * that netdev_has_tunnel_push_pop() returns true. */
int
netdev_push_header(const struct netdev *netdev,
                   struct dp_packet_batch *batch,
                   const struct ovs_action_push_tnl *data)
{
    struct dp_packet *packet;
    DP_PACKET_BATCH_FOR_EACH (i, packet, batch) {
        netdev->netdev_class->push_header(netdev, packet, data);
        pkt_metadata_init(&packet->md, data->out_port);
    }

    return 0;
}

/* Registers with the poll loop to wake up from the next call to poll_block()
 * when the packet transmission queue has sufficient room to transmit a packet
 * with netdev_send().
 *
 * The network device is expected to maintain one or more packet
 * transmission queues, so that the caller does not ordinarily have to
 * do additional queuing of packets.  'qid' specifies the queue to use
 * and can be ignored if the implementation does not support multiple
 * queues. */
void
netdev_send_wait(struct netdev *netdev, int qid)
{
    if (netdev->netdev_class->send_wait) {
        netdev->netdev_class->send_wait(netdev, qid);
    }
}

/* Attempts to set 'netdev''s MAC address to 'mac'.  Returns 0 if successful,
 * otherwise a positive errno value. */
int
netdev_set_etheraddr(struct netdev *netdev, const struct eth_addr mac)
{
    return netdev->netdev_class->set_etheraddr(netdev, mac);
}

/* Retrieves 'netdev''s MAC address.  If successful, returns 0 and copies the
 * the MAC address into 'mac'.  On failure, returns a positive errno value and
 * clears 'mac' to all-zeros. */
int
netdev_get_etheraddr(const struct netdev *netdev, struct eth_addr *mac)
{
    int error;

    error = netdev->netdev_class->get_etheraddr(netdev, mac);
    if (error) {
        memset(mac, 0, sizeof *mac);
    }
    return error;
}

/* Returns the name of the network device that 'netdev' represents,
 * e.g. "eth0".  The caller must not modify or free the returned string. */
const char *
netdev_get_name(const struct netdev *netdev)
{
    return netdev->name;
}

/* Retrieves the MTU of 'netdev'.  The MTU is the maximum size of transmitted
 * (and received) packets, in bytes, not including the hardware header; thus,
 * this is typically 1500 bytes for Ethernet devices.
 *
 * If successful, returns 0 and stores the MTU size in '*mtup'.  Returns
 * EOPNOTSUPP if 'netdev' does not have an MTU (as e.g. some tunnels do not).
 * On other failure, returns a positive errno value.  On failure, sets '*mtup'
 * to 0. */
int
netdev_get_mtu(const struct netdev *netdev, int *mtup)
{
    const struct netdev_class *class = netdev->netdev_class;
    int error;

    error = class->get_mtu ? class->get_mtu(netdev, mtup) : EOPNOTSUPP;
    if (error) {
        *mtup = 0;
        if (error != EOPNOTSUPP) {
            VLOG_DBG_RL(&rl, "failed to retrieve MTU for network device %s: "
                         "%s", netdev_get_name(netdev), ovs_strerror(error));
        }
    }
    return error;
}

/* Sets the MTU of 'netdev'.  The MTU is the maximum size of transmitted
 * (and received) packets, in bytes.
 *
 * If successful, returns 0.  Returns EOPNOTSUPP if 'netdev' does not have an
 * MTU (as e.g. some tunnels do not).  On other failure, returns a positive
 * errno value. */
int
netdev_set_mtu(struct netdev *netdev, int mtu)
{
    const struct netdev_class *class = netdev->netdev_class;
    int error;

    error = class->set_mtu ? class->set_mtu(netdev, mtu) : EOPNOTSUPP;
    if (error && error != EOPNOTSUPP) {
        VLOG_WARN_RL(&rl, "failed to set MTU for network device %s: %s",
                     netdev_get_name(netdev), ovs_strerror(error));
    }

    return error;
}

/* If 'user_config' is true, the user wants to control 'netdev''s MTU and we
 * should not override it.  If 'user_config' is false, we may adjust
 * 'netdev''s MTU (e.g., if 'netdev' is internal). */
void
netdev_mtu_user_config(struct netdev *netdev, bool user_config)
{
    if (netdev->mtu_user_config != user_config) {
        netdev_change_seq_changed(netdev);
        netdev->mtu_user_config = user_config;
    }
}

/* Returns 'true' if the user explicitly specified an MTU value for 'netdev'.
 * Otherwise, returns 'false', in which case we are allowed to adjust the
 * device MTU. */
bool
netdev_mtu_is_user_config(struct netdev *netdev)
{
    return netdev->mtu_user_config;
}

/* Returns the ifindex of 'netdev', if successful, as a positive number.  On
 * failure, returns a negative errno value.
 *
 * The desired semantics of the ifindex value are a combination of those
 * specified by POSIX for if_nametoindex() and by SNMP for ifIndex.  An ifindex
 * value should be unique within a host and remain stable at least until
 * reboot.  SNMP says an ifindex "ranges between 1 and the value of ifNumber"
 * but many systems do not follow this rule anyhow.
 *
 * Some network devices may not implement support for this function.  In such
 * cases this function will always return -EOPNOTSUPP.
 */
int
netdev_get_ifindex(const struct netdev *netdev)
{
    int (*get_ifindex)(const struct netdev *);

    get_ifindex = netdev->netdev_class->get_ifindex;

    return get_ifindex ? get_ifindex(netdev) : -EOPNOTSUPP;
}

/* Stores the features supported by 'netdev' into each of '*current',
 * '*advertised', '*supported', and '*peer' that are non-null.  Each value is a
 * bitmap of "enum ofp_port_features" bits, in host byte order.  Returns 0 if
 * successful, otherwise a positive errno value.  On failure, all of the
 * passed-in values are set to 0.
 *
 * Some network devices may not implement support for this function.  In such
 * cases this function will always return EOPNOTSUPP. */
int
netdev_get_features(const struct netdev *netdev,
                    enum netdev_features *current,
                    enum netdev_features *advertised,
                    enum netdev_features *supported,
                    enum netdev_features *peer)
{
    int (*get_features)(const struct netdev *netdev,
                        enum netdev_features *current,
                        enum netdev_features *advertised,
                        enum netdev_features *supported,
                        enum netdev_features *peer);
    enum netdev_features dummy[4];
    int error;

    if (!current) {
        current = &dummy[0];
    }
    if (!advertised) {
        advertised = &dummy[1];
    }
    if (!supported) {
        supported = &dummy[2];
    }
    if (!peer) {
        peer = &dummy[3];
    }

    get_features = netdev->netdev_class->get_features;
    error = get_features
                    ? get_features(netdev, current, advertised, supported,
                                   peer)
                    : EOPNOTSUPP;
    if (error) {
        *current = *advertised = *supported = *peer = 0;
    }
    return error;
}

/* Returns the maximum speed of a network connection that has the NETDEV_F_*
 * bits in 'features', in bits per second.  If no bits that indicate a speed
 * are set in 'features', returns 'default_bps'. */
uint64_t
netdev_features_to_bps(enum netdev_features features,
                       uint64_t default_bps)
{
    enum {
        F_1000000MB = NETDEV_F_1TB_FD,
        F_100000MB = NETDEV_F_100GB_FD,
        F_40000MB = NETDEV_F_40GB_FD,
        F_10000MB = NETDEV_F_10GB_FD,
        F_1000MB = NETDEV_F_1GB_HD | NETDEV_F_1GB_FD,
        F_100MB = NETDEV_F_100MB_HD | NETDEV_F_100MB_FD,
        F_10MB = NETDEV_F_10MB_HD | NETDEV_F_10MB_FD
    };

    return (  features & F_1000000MB ? UINT64_C(1000000000000)
            : features & F_100000MB  ? UINT64_C(100000000000)
            : features & F_40000MB   ? UINT64_C(40000000000)
            : features & F_10000MB   ? UINT64_C(10000000000)
            : features & F_1000MB    ? UINT64_C(1000000000)
            : features & F_100MB     ? UINT64_C(100000000)
            : features & F_10MB      ? UINT64_C(10000000)
                                     : default_bps);
}

/* Returns true if any of the NETDEV_F_* bits that indicate a full-duplex link
 * are set in 'features', otherwise false. */
bool
netdev_features_is_full_duplex(enum netdev_features features)
{
    return (features & (NETDEV_F_10MB_FD | NETDEV_F_100MB_FD | NETDEV_F_1GB_FD
                        | NETDEV_F_10GB_FD | NETDEV_F_40GB_FD
                        | NETDEV_F_100GB_FD | NETDEV_F_1TB_FD)) != 0;
}

/* Set the features advertised by 'netdev' to 'advertise'.  Returns 0 if
 * successful, otherwise a positive errno value. */
int
netdev_set_advertisements(struct netdev *netdev,
                          enum netdev_features advertise)
{
    return (netdev->netdev_class->set_advertisements
            ? netdev->netdev_class->set_advertisements(
                    netdev, advertise)
            : EOPNOTSUPP);
}

static const char *
netdev_feature_to_name(uint32_t bit)
{
    enum netdev_features f = bit;

    switch (f) {
    case NETDEV_F_10MB_HD:    return "10MB-HD";
    case NETDEV_F_10MB_FD:    return "10MB-FD";
    case NETDEV_F_100MB_HD:   return "100MB-HD";
    case NETDEV_F_100MB_FD:   return "100MB-FD";
    case NETDEV_F_1GB_HD:     return "1GB-HD";
    case NETDEV_F_1GB_FD:     return "1GB-FD";
    case NETDEV_F_10GB_FD:    return "10GB-FD";
    case NETDEV_F_40GB_FD:    return "40GB-FD";
    case NETDEV_F_100GB_FD:   return "100GB-FD";
    case NETDEV_F_1TB_FD:     return "1TB-FD";
    case NETDEV_F_OTHER:      return "OTHER";
    case NETDEV_F_COPPER:     return "COPPER";
    case NETDEV_F_FIBER:      return "FIBER";
    case NETDEV_F_AUTONEG:    return "AUTO_NEG";
    case NETDEV_F_PAUSE:      return "AUTO_PAUSE";
    case NETDEV_F_PAUSE_ASYM: return "AUTO_PAUSE_ASYM";
    }

    return NULL;
}

void
netdev_features_format(struct ds *s, enum netdev_features features)
{
    ofp_print_bit_names(s, features, netdev_feature_to_name, ' ');
    ds_put_char(s, '\n');
}

/* Assigns 'addr' as 'netdev''s IPv4 address and 'mask' as its netmask.  If
 * 'addr' is INADDR_ANY, 'netdev''s IPv4 address is cleared.  Returns a
 * positive errno value. */
int
netdev_set_in4(struct netdev *netdev, struct in_addr addr, struct in_addr mask)
{
    return (netdev->netdev_class->set_in4
            ? netdev->netdev_class->set_in4(netdev, addr, mask)
            : EOPNOTSUPP);
}

static int
netdev_get_addresses_by_name(const char *device_name,
                             struct in6_addr **addrsp, int *n_addrsp)
{
    struct netdev *netdev;
    int error = netdev_open(device_name, NULL, &netdev);
    if (error) {
        *addrsp = NULL;
        *n_addrsp = 0;
        return error;
    }

    struct in6_addr *masks;
    error = netdev_get_addr_list(netdev, addrsp, &masks, n_addrsp);
    netdev_close(netdev);
    free(masks);
    return error;
}

/* Obtains an IPv4 address from 'device_name' and save the address in '*in4'.
 * Returns 0 if successful, otherwise a positive errno value. */
int
netdev_get_in4_by_name(const char *device_name, struct in_addr *in4)
{
    struct in6_addr *addrs;
    int n;
    int error = netdev_get_addresses_by_name(device_name, &addrs, &n);

    in4->s_addr = 0;
    if (!error) {
        error = ENOENT;
        for (int i = 0; i < n; i++) {
            if (IN6_IS_ADDR_V4MAPPED(&addrs[i])) {
                in4->s_addr = in6_addr_get_mapped_ipv4(&addrs[i]);
                error = 0;
                break;
            }
        }
    }
    free(addrs);

    return error;
}

/* Obtains an IPv4 or IPv6 address from 'device_name' and save the address in
 * '*in6', representing IPv4 addresses as v6-mapped.  Returns 0 if successful,
 * otherwise a positive errno value. */
int
netdev_get_ip_by_name(const char *device_name, struct in6_addr *in6)
{
    struct in6_addr *addrs;
    int n;
    int error = netdev_get_addresses_by_name(device_name, &addrs, &n);

    *in6 = in6addr_any;
    if (!error) {
        error = ENOENT;
        for (int i = 0; i < n; i++) {
            if (!in6_is_lla(&addrs[i])) {
                *in6 = addrs[i];
                error = 0;
                break;
            }
        }
    }
    free(addrs);

    return error;
}

/* Adds 'router' as a default IP gateway for the TCP/IP stack that corresponds
 * to 'netdev'. */
int
netdev_add_router(struct netdev *netdev, struct in_addr router)
{
    COVERAGE_INC(netdev_add_router);
    return (netdev->netdev_class->add_router
            ? netdev->netdev_class->add_router(netdev, router)
            : EOPNOTSUPP);
}

/* Looks up the next hop for 'host' for the TCP/IP stack that corresponds to
 * 'netdev'.  If a route cannot not be determined, sets '*next_hop' to 0,
 * '*netdev_name' to null, and returns a positive errno value.  Otherwise, if a
 * next hop is found, stores the next hop gateway's address (0 if 'host' is on
 * a directly connected network) in '*next_hop' and a copy of the name of the
 * device to reach 'host' in '*netdev_name', and returns 0.  The caller is
 * responsible for freeing '*netdev_name' (by calling free()). */
int
netdev_get_next_hop(const struct netdev *netdev,
                    const struct in_addr *host, struct in_addr *next_hop,
                    char **netdev_name)
{
    int error = (netdev->netdev_class->get_next_hop
                 ? netdev->netdev_class->get_next_hop(
                        host, next_hop, netdev_name)
                 : EOPNOTSUPP);
    if (error) {
        next_hop->s_addr = 0;
        *netdev_name = NULL;
    }
    return error;
}

/* Populates 'smap' with status information.
 *
 * Populates 'smap' with 'netdev' specific status information.  This
 * information may be used to populate the status column of the Interface table
 * as defined in ovs-vswitchd.conf.db(5). */
int
netdev_get_status(const struct netdev *netdev, struct smap *smap)
{
    return (netdev->netdev_class->get_status
            ? netdev->netdev_class->get_status(netdev, smap)
            : EOPNOTSUPP);
}

/* Returns all assigned IP address to  'netdev' and returns 0.
 * API allocates array of address and masks and set it to
 * '*addr' and '*mask'.
 * Otherwise, returns a positive errno value and sets '*addr', '*mask
 * and '*n_addr' to NULL.
 *
 * The following error values have well-defined meanings:
 *
 *   - EADDRNOTAVAIL: 'netdev' has no assigned IPv6 address.
 *
 *   - EOPNOTSUPP: No IPv6 network stack attached to 'netdev'.
 *
 * 'addr' may be null, in which case the address itself is not reported. */
int
netdev_get_addr_list(const struct netdev *netdev, struct in6_addr **addr,
                     struct in6_addr **mask, int *n_addr)
{
    int error;

    error = (netdev->netdev_class->get_addr_list
             ? netdev->netdev_class->get_addr_list(netdev, addr, mask, n_addr): EOPNOTSUPP);
    if (error && addr) {
        *addr = NULL;
        *mask = NULL;
        *n_addr = 0;
    }

    return error;
}

/* On 'netdev', turns off the flags in 'off' and then turns on the flags in
 * 'on'.  Returns 0 if successful, otherwise a positive errno value. */
static int
do_update_flags(struct netdev *netdev, enum netdev_flags off,
                enum netdev_flags on, enum netdev_flags *old_flagsp,
                struct netdev_saved_flags **sfp)
    OVS_EXCLUDED(netdev_mutex)
{
    struct netdev_saved_flags *sf = NULL;
    enum netdev_flags old_flags;
    int error;

    error = netdev->netdev_class->update_flags(netdev, off & ~on, on,
                                               &old_flags);
    if (error) {
        VLOG_WARN_RL(&rl, "failed to %s flags for network device %s: %s",
                     off || on ? "set" : "get", netdev_get_name(netdev),
                     ovs_strerror(error));
        old_flags = 0;
    } else if ((off || on) && sfp) {
        enum netdev_flags new_flags = (old_flags & ~off) | on;
        enum netdev_flags changed_flags = old_flags ^ new_flags;
        if (changed_flags) {
            ovs_mutex_lock(&netdev_mutex);
            *sfp = sf = xmalloc(sizeof *sf);
            sf->netdev = netdev;
            ovs_list_push_front(&netdev->saved_flags_list, &sf->node);
            sf->saved_flags = changed_flags;
            sf->saved_values = changed_flags & new_flags;

            netdev->ref_cnt++;
            ovs_mutex_unlock(&netdev_mutex);
        }
    }

    if (old_flagsp) {
        *old_flagsp = old_flags;
    }
    if (sfp) {
        *sfp = sf;
    }

    return error;
}

/* Obtains the current flags for 'netdev' and stores them into '*flagsp'.
 * Returns 0 if successful, otherwise a positive errno value.  On failure,
 * stores 0 into '*flagsp'. */
int
netdev_get_flags(const struct netdev *netdev_, enum netdev_flags *flagsp)
{
    struct netdev *netdev = CONST_CAST(struct netdev *, netdev_);
    return do_update_flags(netdev, 0, 0, flagsp, NULL);
}

/* Sets the flags for 'netdev' to 'flags'.
 * Returns 0 if successful, otherwise a positive errno value. */
int
netdev_set_flags(struct netdev *netdev, enum netdev_flags flags,
                 struct netdev_saved_flags **sfp)
{
    return do_update_flags(netdev, -1, flags, NULL, sfp);
}

/* Turns on the specified 'flags' on 'netdev':
 *
 *    - On success, returns 0.  If 'sfp' is nonnull, sets '*sfp' to a newly
 *      allocated 'struct netdev_saved_flags *' that may be passed to
 *      netdev_restore_flags() to restore the original values of 'flags' on
 *      'netdev' (this will happen automatically at program termination if
 *      netdev_restore_flags() is never called) , or to NULL if no flags were
 *      actually changed.
 *
 *    - On failure, returns a positive errno value.  If 'sfp' is nonnull, sets
 *      '*sfp' to NULL. */
int
netdev_turn_flags_on(struct netdev *netdev, enum netdev_flags flags,
                     struct netdev_saved_flags **sfp)
{
    return do_update_flags(netdev, 0, flags, NULL, sfp);
}

/* Turns off the specified 'flags' on 'netdev'.  See netdev_turn_flags_on() for
 * details of the interface. */
int
netdev_turn_flags_off(struct netdev *netdev, enum netdev_flags flags,
                      struct netdev_saved_flags **sfp)
{
    return do_update_flags(netdev, flags, 0, NULL, sfp);
}

/* Restores the flags that were saved in 'sf', and destroys 'sf'.
 * Does nothing if 'sf' is NULL. */
void
netdev_restore_flags(struct netdev_saved_flags *sf)
    OVS_EXCLUDED(netdev_mutex)
{
    if (sf) {
        struct netdev *netdev = sf->netdev;
        enum netdev_flags old_flags;

        netdev->netdev_class->update_flags(netdev,
                                           sf->saved_flags & sf->saved_values,
                                           sf->saved_flags & ~sf->saved_values,
                                           &old_flags);

        ovs_mutex_lock(&netdev_mutex);
        ovs_list_remove(&sf->node);
        free(sf);
        netdev_unref(netdev);
    }
}

/* Looks up the ARP table entry for 'ip' on 'netdev'.  If one exists and can be
 * successfully retrieved, it stores the corresponding MAC address in 'mac' and
 * returns 0.  Otherwise, it returns a positive errno value; in particular,
 * ENXIO indicates that there is no ARP table entry for 'ip' on 'netdev'. */
int
netdev_arp_lookup(const struct netdev *netdev,
                  ovs_be32 ip, struct eth_addr *mac)
{
    int error = (netdev->netdev_class->arp_lookup
                 ? netdev->netdev_class->arp_lookup(netdev, ip, mac)
                 : EOPNOTSUPP);
    if (error) {
        *mac = eth_addr_zero;
    }
    return error;
}

/* Returns true if carrier is active (link light is on) on 'netdev'. */
bool
netdev_get_carrier(const struct netdev *netdev)
{
    int error;
    enum netdev_flags flags;
    bool carrier;

    netdev_get_flags(netdev, &flags);
    if (!(flags & NETDEV_UP)) {
        return false;
    }

    if (!netdev->netdev_class->get_carrier) {
        return true;
    }

    error = netdev->netdev_class->get_carrier(netdev, &carrier);
    if (error) {
        VLOG_DBG("%s: failed to get network device carrier status, assuming "
                 "down: %s", netdev_get_name(netdev), ovs_strerror(error));
        carrier = false;
    }

    return carrier;
}

/* Returns the number of times 'netdev''s carrier has changed. */
long long int
netdev_get_carrier_resets(const struct netdev *netdev)
{
    return (netdev->netdev_class->get_carrier_resets
            ? netdev->netdev_class->get_carrier_resets(netdev)
            : 0);
}

/* Attempts to force netdev_get_carrier() to poll 'netdev''s MII registers for
 * link status instead of checking 'netdev''s carrier.  'netdev''s MII
 * registers will be polled once ever 'interval' milliseconds.  If 'netdev'
 * does not support MII, another method may be used as a fallback.  If
 * 'interval' is less than or equal to zero, reverts netdev_get_carrier() to
 * its normal behavior.
 *
 * Returns 0 if successful, otherwise a positive errno value. */
int
netdev_set_miimon_interval(struct netdev *netdev, long long int interval)
{
    return (netdev->netdev_class->set_miimon_interval
            ? netdev->netdev_class->set_miimon_interval(netdev, interval)
            : EOPNOTSUPP);
}

/* Retrieves current device stats for 'netdev'. */
int
netdev_get_stats(const struct netdev *netdev, struct netdev_stats *stats)
{
    int error;

    /* Statistics are initialized before passing it to particular device
     * implementation so all values are filtered out by default. */
    memset(stats, 0xFF, sizeof *stats);

    COVERAGE_INC(netdev_get_stats);
    error = (netdev->netdev_class->get_stats
             ? netdev->netdev_class->get_stats(netdev, stats)
             : EOPNOTSUPP);
    if (error) {
        /* In case of error all statistics are filtered out */
        memset(stats, 0xff, sizeof *stats);
    }
    return error;
}

/* Retrieves current device custom stats for 'netdev'. */
int
netdev_get_custom_stats(const struct netdev *netdev,
                        struct netdev_custom_stats *custom_stats)
{
    int error;
    memset(custom_stats, 0, sizeof *custom_stats);
    error = (netdev->netdev_class->get_custom_stats
             ? netdev->netdev_class->get_custom_stats(netdev, custom_stats)
             : EOPNOTSUPP);

    return error;
}


/* Attempts to set input rate limiting (policing) policy, such that up to
 * 'kbits_rate' kbps of traffic is accepted, with a maximum accumulative burst
 * size of 'kbits' kb. */
int
netdev_set_policing(struct netdev *netdev, uint32_t kbits_rate,
                    uint32_t kbits_burst)
{
    return (netdev->netdev_class->set_policing
            ? netdev->netdev_class->set_policing(netdev,
                    kbits_rate, kbits_burst)
            : EOPNOTSUPP);
}

/* Adds to 'types' all of the forms of QoS supported by 'netdev', or leaves it
 * empty if 'netdev' does not support QoS.  Any names added to 'types' should
 * be documented as valid for the "type" column in the "QoS" table in
 * vswitchd/vswitch.xml (which is built as ovs-vswitchd.conf.db(8)).
 *
 * Every network device supports disabling QoS with a type of "", but this type
 * will not be added to 'types'.
 *
 * The caller must initialize 'types' (e.g. with sset_init()) before calling
 * this function.  The caller is responsible for destroying 'types' (e.g. with
 * sset_destroy()) when it is no longer needed.
 *
 * Returns 0 if successful, otherwise a positive errno value. */
int
netdev_get_qos_types(const struct netdev *netdev, struct sset *types)
{
    const struct netdev_class *class = netdev->netdev_class;
    return (class->get_qos_types
            ? class->get_qos_types(netdev, types)
            : 0);
}

/* Queries 'netdev' for its capabilities regarding the specified 'type' of QoS,
 * which should be "" or one of the types returned by netdev_get_qos_types()
 * for 'netdev'.  Returns 0 if successful, otherwise a positive errno value.
 * On success, initializes 'caps' with the QoS capabilities; on failure, clears
 * 'caps' to all zeros. */
int
netdev_get_qos_capabilities(const struct netdev *netdev, const char *type,
                            struct netdev_qos_capabilities *caps)
{
    const struct netdev_class *class = netdev->netdev_class;

    if (*type) {
        int retval = (class->get_qos_capabilities
                      ? class->get_qos_capabilities(netdev, type, caps)
                      : EOPNOTSUPP);
        if (retval) {
            memset(caps, 0, sizeof *caps);
        }
        return retval;
    } else {
        /* Every netdev supports turning off QoS. */
        memset(caps, 0, sizeof *caps);
        return 0;
    }
}

/* Obtains the number of queues supported by 'netdev' for the specified 'type'
 * of QoS.  Returns 0 if successful, otherwise a positive errno value.  Stores
 * the number of queues (zero on failure) in '*n_queuesp'.
 *
 * This is just a simple wrapper around netdev_get_qos_capabilities(). */
int
netdev_get_n_queues(const struct netdev *netdev,
                    const char *type, unsigned int *n_queuesp)
{
    struct netdev_qos_capabilities caps;
    int retval;

    retval = netdev_get_qos_capabilities(netdev, type, &caps);
    *n_queuesp = caps.n_queues;
    return retval;
}

/* Queries 'netdev' about its currently configured form of QoS.  If successful,
 * stores the name of the current form of QoS into '*typep', stores any details
 * of configuration as string key-value pairs in 'details', and returns 0.  On
 * failure, sets '*typep' to NULL and returns a positive errno value.
 *
 * A '*typep' of "" indicates that QoS is currently disabled on 'netdev'.
 *
 * The caller must initialize 'details' as an empty smap (e.g. with
 * smap_init()) before calling this function.  The caller must free 'details'
 * when it is no longer needed (e.g. with smap_destroy()).
 *
 * The caller must not modify or free '*typep'.
 *
 * '*typep' will be one of the types returned by netdev_get_qos_types() for
 * 'netdev'.  The contents of 'details' should be documented as valid for
 * '*typep' in the "other_config" column in the "QoS" table in
 * vswitchd/vswitch.xml (which is built as ovs-vswitchd.conf.db(8)). */
int
netdev_get_qos(const struct netdev *netdev,
               const char **typep, struct smap *details)
{
    const struct netdev_class *class = netdev->netdev_class;
    int retval;

    if (class->get_qos) {
        retval = class->get_qos(netdev, typep, details);
        if (retval) {
            *typep = NULL;
            smap_clear(details);
        }
        return retval;
    } else {
        /* 'netdev' doesn't support QoS, so report that QoS is disabled. */
        *typep = "";
        return 0;
    }
}

/* Attempts to reconfigure QoS on 'netdev', changing the form of QoS to 'type'
 * with details of configuration from 'details'.  Returns 0 if successful,
 * otherwise a positive errno value.  On error, the previous QoS configuration
 * is retained.
 *
 * When this function changes the type of QoS (not just 'details'), this also
 * resets all queue configuration for 'netdev' to their defaults (which depend
 * on the specific type of QoS).  Otherwise, the queue configuration for
 * 'netdev' is unchanged.
 *
 * 'type' should be "" (to disable QoS) or one of the types returned by
 * netdev_get_qos_types() for 'netdev'.  The contents of 'details' should be
 * documented as valid for the given 'type' in the "other_config" column in the
 * "QoS" table in vswitchd/vswitch.xml (which is built as
 * ovs-vswitchd.conf.db(8)).
 *
 * NULL may be specified for 'details' if there are no configuration
 * details. */
int
netdev_set_qos(struct netdev *netdev,
               const char *type, const struct smap *details)
{
    const struct netdev_class *class = netdev->netdev_class;

    if (!type) {
        type = "";
    }

    if (class->set_qos) {
        if (!details) {
            static const struct smap empty = SMAP_INITIALIZER(&empty);
            details = &empty;
        }
        return class->set_qos(netdev, type, details);
    } else {
        return *type ? EOPNOTSUPP : 0;
    }
}

/* Queries 'netdev' for information about the queue numbered 'queue_id'.  If
 * successful, adds that information as string key-value pairs to 'details'.
 * Returns 0 if successful, otherwise a positive errno value.
 *
 * 'queue_id' must be less than the number of queues supported by 'netdev' for
 * the current form of QoS (e.g. as returned by netdev_get_n_queues(netdev)).
 *
 * The returned contents of 'details' should be documented as valid for the
 * given 'type' in the "other_config" column in the "Queue" table in
 * vswitchd/vswitch.xml (which is built as ovs-vswitchd.conf.db(8)).
 *
 * The caller must initialize 'details' (e.g. with smap_init()) before calling
 * this function.  The caller must free 'details' when it is no longer needed
 * (e.g. with smap_destroy()). */
int
netdev_get_queue(const struct netdev *netdev,
                 unsigned int queue_id, struct smap *details)
{
    const struct netdev_class *class = netdev->netdev_class;
    int retval;

    retval = (class->get_queue
              ? class->get_queue(netdev, queue_id, details)
              : EOPNOTSUPP);
    if (retval) {
        smap_clear(details);
    }
    return retval;
}

/* Configures the queue numbered 'queue_id' on 'netdev' with the key-value
 * string pairs in 'details'.  The contents of 'details' should be documented
 * as valid for the given 'type' in the "other_config" column in the "Queue"
 * table in vswitchd/vswitch.xml (which is built as ovs-vswitchd.conf.db(8)).
 * Returns 0 if successful, otherwise a positive errno value.  On failure, the
 * given queue's configuration should be unmodified.
 *
 * 'queue_id' must be less than the number of queues supported by 'netdev' for
 * the current form of QoS (e.g. as returned by netdev_get_n_queues(netdev)).
 *
 * This function does not modify 'details', and the caller retains ownership of
 * it. */
int
netdev_set_queue(struct netdev *netdev,
                 unsigned int queue_id, const struct smap *details)
{
    const struct netdev_class *class = netdev->netdev_class;
    return (class->set_queue
            ? class->set_queue(netdev, queue_id, details)
            : EOPNOTSUPP);
}

/* Attempts to delete the queue numbered 'queue_id' from 'netdev'.  Some kinds
 * of QoS may have a fixed set of queues, in which case attempts to delete them
 * will fail with EOPNOTSUPP.
 *
 * Returns 0 if successful, otherwise a positive errno value.  On failure, the
 * given queue will be unmodified.
 *
 * 'queue_id' must be less than the number of queues supported by 'netdev' for
 * the current form of QoS (e.g. as returned by
 * netdev_get_n_queues(netdev)). */
int
netdev_delete_queue(struct netdev *netdev, unsigned int queue_id)
{
    const struct netdev_class *class = netdev->netdev_class;
    return (class->delete_queue
            ? class->delete_queue(netdev, queue_id)
            : EOPNOTSUPP);
}

/* Obtains statistics about 'queue_id' on 'netdev'.  On success, returns 0 and
 * fills 'stats' with the queue's statistics; individual members of 'stats' may
 * be set to all-1-bits if the statistic is unavailable.  On failure, returns a
 * positive errno value and fills 'stats' with values indicating unsupported
 * statistics. */
int
netdev_get_queue_stats(const struct netdev *netdev, unsigned int queue_id,
                       struct netdev_queue_stats *stats)
{
    const struct netdev_class *class = netdev->netdev_class;
    int retval;

    retval = (class->get_queue_stats
              ? class->get_queue_stats(netdev, queue_id, stats)
              : EOPNOTSUPP);
    if (retval) {
        stats->tx_bytes = UINT64_MAX;
        stats->tx_packets = UINT64_MAX;
        stats->tx_errors = UINT64_MAX;
        stats->created = LLONG_MIN;
    }
    return retval;
}

/* Initializes 'dump' to begin dumping the queues in a netdev.
 *
 * This function provides no status indication.  An error status for the entire
 * dump operation is provided when it is completed by calling
 * netdev_queue_dump_done().
 */
void
netdev_queue_dump_start(struct netdev_queue_dump *dump,
                        const struct netdev *netdev)
{
    dump->netdev = netdev_ref(netdev);
    if (netdev->netdev_class->queue_dump_start) {
        dump->error = netdev->netdev_class->queue_dump_start(netdev,
                                                             &dump->state);
    } else {
        dump->error = EOPNOTSUPP;
    }
}

/* Attempts to retrieve another queue from 'dump', which must have been
 * initialized with netdev_queue_dump_start().  On success, stores a new queue
 * ID into '*queue_id', fills 'details' with configuration details for the
 * queue, and returns true.  On failure, returns false.
 *
 * Queues are not necessarily dumped in increasing order of queue ID (or any
 * other predictable order).
 *
 * Failure might indicate an actual error or merely that the last queue has
 * been dumped.  An error status for the entire dump operation is provided when
 * it is completed by calling netdev_queue_dump_done().
 *
 * The returned contents of 'details' should be documented as valid for the
 * given 'type' in the "other_config" column in the "Queue" table in
 * vswitchd/vswitch.xml (which is built as ovs-vswitchd.conf.db(8)).
 *
 * The caller must initialize 'details' (e.g. with smap_init()) before calling
 * this function.  This function will clear and replace its contents.  The
 * caller must free 'details' when it is no longer needed (e.g. with
 * smap_destroy()). */
bool
netdev_queue_dump_next(struct netdev_queue_dump *dump,
                       unsigned int *queue_id, struct smap *details)
{
    const struct netdev *netdev = dump->netdev;

    if (dump->error) {
        return false;
    }

    dump->error = netdev->netdev_class->queue_dump_next(netdev, dump->state,
                                                        queue_id, details);

    if (dump->error) {
        netdev->netdev_class->queue_dump_done(netdev, dump->state);
        return false;
    }
    return true;
}

/* Completes queue table dump operation 'dump', which must have been
 * initialized with netdev_queue_dump_start().  Returns 0 if the dump operation
 * was error-free, otherwise a positive errno value describing the problem. */
int
netdev_queue_dump_done(struct netdev_queue_dump *dump)
{
    const struct netdev *netdev = dump->netdev;
    if (!dump->error && netdev->netdev_class->queue_dump_done) {
        dump->error = netdev->netdev_class->queue_dump_done(netdev,
                                                            dump->state);
    }
    netdev_close(dump->netdev);
    return dump->error == EOF ? 0 : dump->error;
}

/* Iterates over all of 'netdev''s queues, calling 'cb' with the queue's ID,
 * its statistics, and the 'aux' specified by the caller.  The order of
 * iteration is unspecified, but (when successful) each queue is visited
 * exactly once.
 *
 * Calling this function may be more efficient than calling
 * netdev_get_queue_stats() for every queue.
 *
 * 'cb' must not modify or free the statistics passed in.
 *
 * Returns 0 if successful, otherwise a positive errno value.  On error, some
 * configured queues may not have been included in the iteration. */
int
netdev_dump_queue_stats(const struct netdev *netdev,
                        netdev_dump_queue_stats_cb *cb, void *aux)
{
    const struct netdev_class *class = netdev->netdev_class;
    return (class->dump_queue_stats
            ? class->dump_queue_stats(netdev, cb, aux)
            : EOPNOTSUPP);
}


/* Returns the class type of 'netdev'.
 *
 * The caller must not free the returned value. */
const char *
netdev_get_type(const struct netdev *netdev)
{
    return netdev->netdev_class->type;
}

/* Returns the class associated with 'netdev'. */
const struct netdev_class *
netdev_get_class(const struct netdev *netdev)
{
    return netdev->netdev_class;
}

/* Returns the netdev with 'name' or NULL if there is none.
 *
 * The caller must free the returned netdev with netdev_close(). */
struct netdev *
netdev_from_name(const char *name)
    OVS_EXCLUDED(netdev_mutex)
{
    struct netdev *netdev;

    ovs_mutex_lock(&netdev_mutex);
    netdev = shash_find_data(&netdev_shash, name);
    if (netdev) {
        netdev->ref_cnt++;
    }
    ovs_mutex_unlock(&netdev_mutex);

    return netdev;
}

/* Fills 'device_list' with devices that match 'netdev_class'.
 *
 * The caller is responsible for initializing and destroying 'device_list' and
 * must close each device on the list. */
void
netdev_get_devices(const struct netdev_class *netdev_class,
                   struct shash *device_list)
    OVS_EXCLUDED(netdev_mutex)
{
    struct shash_node *node;

    ovs_mutex_lock(&netdev_mutex);
    SHASH_FOR_EACH (node, &netdev_shash) {
        struct netdev *dev = node->data;

        if (dev->netdev_class == netdev_class) {
            dev->ref_cnt++;
            shash_add(device_list, node->name, node->data);
        }
    }
    ovs_mutex_unlock(&netdev_mutex);
}

/* Extracts pointers to all 'netdev-vports' into an array 'vports'
 * and returns it.  Stores the size of the array into '*size'.
 *
 * The caller is responsible for freeing 'vports' and must close
 * each 'netdev-vport' in the list. */
struct netdev **
netdev_get_vports(size_t *size)
    OVS_EXCLUDED(netdev_mutex)
{
    struct netdev **vports;
    struct shash_node *node;
    size_t n = 0;

    if (!size) {
        return NULL;
    }

    /* Explicitly allocates big enough chunk of memory. */
    ovs_mutex_lock(&netdev_mutex);
    vports = xmalloc(shash_count(&netdev_shash) * sizeof *vports);
    SHASH_FOR_EACH (node, &netdev_shash) {
        struct netdev *dev = node->data;

        if (netdev_vport_is_vport_class(dev->netdev_class)) {
            dev->ref_cnt++;
            vports[n] = dev;
            n++;
        }
    }
    ovs_mutex_unlock(&netdev_mutex);
    *size = n;

    return vports;
}

const char *
netdev_get_type_from_name(const char *name)
{
    struct netdev *dev;
    const char *type;
    type = netdev_vport_type_from_name(name);
    if (type == NULL) {
        dev = netdev_from_name(name);
        type = dev ? netdev_get_type(dev) : NULL;
        netdev_close(dev);
    }
    return type;
}

struct netdev *
netdev_rxq_get_netdev(const struct netdev_rxq *rx)
{
    ovs_assert(rx->netdev->ref_cnt > 0);
    return rx->netdev;
}

const char *
netdev_rxq_get_name(const struct netdev_rxq *rx)
{
    return netdev_get_name(netdev_rxq_get_netdev(rx));
}

int
netdev_rxq_get_queue_id(const struct netdev_rxq *rx)
{
    return rx->queue_id;
}

static void
restore_all_flags(void *aux OVS_UNUSED)
{
    struct shash_node *node;

    SHASH_FOR_EACH (node, &netdev_shash) {
        struct netdev *netdev = node->data;
        const struct netdev_saved_flags *sf;
        enum netdev_flags saved_values;
        enum netdev_flags saved_flags;

        saved_values = saved_flags = 0;
        LIST_FOR_EACH (sf, node, &netdev->saved_flags_list) {
            saved_flags |= sf->saved_flags;
            saved_values &= ~sf->saved_flags;
            saved_values |= sf->saved_flags & sf->saved_values;
        }
        if (saved_flags) {
            enum netdev_flags old_flags;

            netdev->netdev_class->update_flags(netdev,
                                               saved_flags & saved_values,
                                               saved_flags & ~saved_values,
                                               &old_flags);
        }
    }
}

uint64_t
netdev_get_change_seq(const struct netdev *netdev)
{
    return netdev->change_seq;
}

#ifndef _WIN32
/* This implementation is shared by Linux and BSD. */

static struct ifaddrs *if_addr_list;
static struct ovs_mutex if_addr_list_lock = OVS_MUTEX_INITIALIZER;

void
netdev_get_addrs_list_flush(void)
{
    ovs_mutex_lock(&if_addr_list_lock);
    if (if_addr_list) {
        freeifaddrs(if_addr_list);
        if_addr_list = NULL;
    }
    ovs_mutex_unlock(&if_addr_list_lock);
}

int
netdev_get_addrs(const char dev[], struct in6_addr **paddr,
                 struct in6_addr **pmask, int *n_in)
{
    struct in6_addr *addr_array, *mask_array;
    const struct ifaddrs *ifa;
    int cnt = 0, i = 0;
    int retries = 3;

    ovs_mutex_lock(&if_addr_list_lock);
    if (!if_addr_list) {
        int err;

retry:
        err = getifaddrs(&if_addr_list);
        if (err) {
            ovs_mutex_unlock(&if_addr_list_lock);
            return -err;
        }
        retries--;
    }

    for (ifa = if_addr_list; ifa; ifa = ifa->ifa_next) {
        if (!ifa->ifa_name) {
            if (retries) {
                /* Older versions of glibc have a bug on race condition with
                 * address addition which may cause one of the returned
                 * ifa_name values to be NULL. In such case, we know that we've
                 * got an inconsistent dump. Retry but beware of an endless
                 * loop. */
                freeifaddrs(if_addr_list);
                goto retry;
            } else {
                VLOG_WARN("Proceeding with an inconsistent dump of "
                          "interfaces from the kernel. Some may be missing");
            }
        }
        if (ifa->ifa_addr && ifa->ifa_name && ifa->ifa_netmask) {
            int family;

            family = ifa->ifa_addr->sa_family;
            if (family == AF_INET || family == AF_INET6) {
                if (!strncmp(ifa->ifa_name, dev, IFNAMSIZ)) {
                    cnt++;
                }
            }
        }
    }

    if (!cnt) {
        ovs_mutex_unlock(&if_addr_list_lock);
        return EADDRNOTAVAIL;
    }
    addr_array = xzalloc(sizeof *addr_array * cnt);
    mask_array = xzalloc(sizeof *mask_array * cnt);
    for (ifa = if_addr_list; ifa; ifa = ifa->ifa_next) {
        if (ifa->ifa_name
            && ifa->ifa_addr
            && ifa->ifa_netmask
            && !strncmp(ifa->ifa_name, dev, IFNAMSIZ)
            && sa_is_ip(ifa->ifa_addr)) {
            addr_array[i] = sa_get_address(ifa->ifa_addr);
            mask_array[i] = sa_get_address(ifa->ifa_netmask);
            i++;
        }
    }
    ovs_mutex_unlock(&if_addr_list_lock);
    if (paddr) {
        *n_in = cnt;
        *paddr = addr_array;
        *pmask = mask_array;
    } else {
        free(addr_array);
        free(mask_array);
    }
    return 0;
}
#endif

void
netdev_wait_reconf_required(struct netdev *netdev)
{
    seq_wait(netdev->reconfigure_seq, netdev->last_reconfigure_seq);
}

bool
netdev_is_reconf_required(struct netdev *netdev)
{
    return seq_read(netdev->reconfigure_seq) != netdev->last_reconfigure_seq;
}

/* Give a chance to 'netdev' to reconfigure some of its parameters.
 *
 * If a module uses netdev_send() and netdev_rxq_recv(), it must call this
 * function when netdev_is_reconf_required() returns true.
 *
 * Return 0 if successful, otherwise a positive errno value.  If the
 * reconfiguration fails the netdev will not be able to send or receive
 * packets.
 *
 * When this function is called, no call to netdev_rxq_recv() or netdev_send()
 * must be issued. */
int
netdev_reconfigure(struct netdev *netdev)
{
    const struct netdev_class *class = netdev->netdev_class;

    netdev->last_reconfigure_seq = seq_read(netdev->reconfigure_seq);

    return (class->reconfigure
            ? class->reconfigure(netdev)
            : EOPNOTSUPP);
}

int
netdev_flow_flush(struct netdev *netdev)
{
    const struct netdev_class *class = netdev->netdev_class;

    return (class->flow_flush
            ? class->flow_flush(netdev)
            : EOPNOTSUPP);
}

int
netdev_flow_dump_create(struct netdev *netdev, struct netdev_flow_dump **dump)
{
    const struct netdev_class *class = netdev->netdev_class;

    return (class->flow_dump_create
            ? class->flow_dump_create(netdev, dump)
            : EOPNOTSUPP);
}

int
netdev_flow_dump_destroy(struct netdev_flow_dump *dump)
{
    const struct netdev_class *class = dump->netdev->netdev_class;

    return (class->flow_dump_destroy
            ? class->flow_dump_destroy(dump)
            : EOPNOTSUPP);
}

bool
netdev_flow_dump_next(struct netdev_flow_dump *dump, struct match *match,
                      struct nlattr **actions, struct dpif_flow_stats *stats,
                      struct dpif_flow_attrs *attrs, ovs_u128 *ufid,
                      struct ofpbuf *rbuffer, struct ofpbuf *wbuffer)
{
    const struct netdev_class *class = dump->netdev->netdev_class;

    return (class->flow_dump_next
            ? class->flow_dump_next(dump, match, actions, stats, attrs,
                                    ufid, rbuffer, wbuffer)
            : false);
}

int
netdev_flow_put(struct netdev *netdev, struct match *match,
                struct nlattr *actions, size_t act_len,
                const ovs_u128 *ufid, struct offload_info *info,
                struct dpif_flow_stats *stats)
{
    const struct netdev_class *class = netdev->netdev_class;

    return (class->flow_put
            ? class->flow_put(netdev, match, actions, act_len, ufid,
                              info, stats)
            : EOPNOTSUPP);
}

int
netdev_flow_get(struct netdev *netdev, struct match *match,
                struct nlattr **actions, const ovs_u128 *ufid,
                struct dpif_flow_stats *stats,
                struct dpif_flow_attrs *attrs, struct ofpbuf *buf)
{
    const struct netdev_class *class = netdev->netdev_class;

    return (class->flow_get
            ? class->flow_get(netdev, match, actions, ufid, stats, attrs, buf)
            : EOPNOTSUPP);
}

int
netdev_flow_del(struct netdev *netdev, const ovs_u128 *ufid,
                struct dpif_flow_stats *stats)
{
    const struct netdev_class *class = netdev->netdev_class;

    return (class->flow_del
            ? class->flow_del(netdev, ufid, stats)
            : EOPNOTSUPP);
}

int
netdev_init_flow_api(struct netdev *netdev)
{
    const struct netdev_class *class = netdev->netdev_class;

    if (!netdev_is_flow_api_enabled()) {
        return EOPNOTSUPP;
    }

    return (class->init_flow_api
            ? class->init_flow_api(netdev)
            : EOPNOTSUPP);
}

uint32_t
netdev_get_block_id(struct netdev *netdev)
{
    const struct netdev_class *class = netdev->netdev_class;

    return (class->get_block_id
            ? class->get_block_id(netdev)
            : 0);
}

bool
netdev_is_flow_api_enabled(void)
{
    return netdev_flow_api_enabled;
}

/* Protects below port hashmaps. */
static struct ovs_mutex netdev_hmap_mutex = OVS_MUTEX_INITIALIZER;

static struct hmap port_to_netdev OVS_GUARDED_BY(netdev_hmap_mutex)
    = HMAP_INITIALIZER(&port_to_netdev);
static struct hmap ifindex_to_port OVS_GUARDED_BY(netdev_hmap_mutex)
    = HMAP_INITIALIZER(&ifindex_to_port);

struct port_to_netdev_data {
    struct hmap_node portno_node; /* By (dpif_class, dpif_port.port_no). */
    struct hmap_node ifindex_node; /* By (dpif_class, ifindex). */
    struct netdev *netdev;
    struct dpif_port dpif_port;
    const struct dpif_class *dpif_class;
    int ifindex;
};

static uint32_t
netdev_ports_hash(odp_port_t port, const struct dpif_class *dpif_class)
{
    return hash_int(odp_to_u32(port), hash_pointer(dpif_class, 0));
}

static struct port_to_netdev_data *
netdev_ports_lookup(odp_port_t port_no, const struct dpif_class *dpif_class)
    OVS_REQUIRES(netdev_hmap_mutex)
{
    struct port_to_netdev_data *data;

    HMAP_FOR_EACH_WITH_HASH (data, portno_node,
                             netdev_ports_hash(port_no, dpif_class),
                             &port_to_netdev) {
        if (data->dpif_class == dpif_class
            && data->dpif_port.port_no == port_no) {
            return data;
        }
    }
    return NULL;
}

int
netdev_ports_insert(struct netdev *netdev, const struct dpif_class *dpif_class,
                    struct dpif_port *dpif_port)
{
    struct port_to_netdev_data *data;
    int ifindex = netdev_get_ifindex(netdev);

    if (ifindex < 0) {
        return ENODEV;
    }

    ovs_mutex_lock(&netdev_hmap_mutex);
    if (netdev_ports_lookup(dpif_port->port_no, dpif_class)) {
        ovs_mutex_unlock(&netdev_hmap_mutex);
        return EEXIST;
    }

    data = xzalloc(sizeof *data);
    data->netdev = netdev_ref(netdev);
    data->dpif_class = dpif_class;
    dpif_port_clone(&data->dpif_port, dpif_port);
    data->ifindex = ifindex;

    hmap_insert(&port_to_netdev, &data->portno_node,
                netdev_ports_hash(dpif_port->port_no, dpif_class));
    hmap_insert(&ifindex_to_port, &data->ifindex_node, ifindex);
    ovs_mutex_unlock(&netdev_hmap_mutex);

    netdev_init_flow_api(netdev);

    return 0;
}

struct netdev *
netdev_ports_get(odp_port_t port_no, const struct dpif_class *dpif_class)
{
    struct port_to_netdev_data *data;
    struct netdev *ret = NULL;

    ovs_mutex_lock(&netdev_hmap_mutex);
    data = netdev_ports_lookup(port_no, dpif_class);
    if (data) {
        ret = netdev_ref(data->netdev);
    }
    ovs_mutex_unlock(&netdev_hmap_mutex);

    return ret;
}

int
netdev_ports_remove(odp_port_t port_no, const struct dpif_class *dpif_class)
{
    struct port_to_netdev_data *data;
    int ret = ENOENT;

    ovs_mutex_lock(&netdev_hmap_mutex);

    data = netdev_ports_lookup(port_no, dpif_class);
    if (data) {
        dpif_port_destroy(&data->dpif_port);
        netdev_close(data->netdev); /* unref and possibly close */
        hmap_remove(&port_to_netdev, &data->portno_node);
        hmap_remove(&ifindex_to_port, &data->ifindex_node);
        free(data);
        ret = 0;
    }

    ovs_mutex_unlock(&netdev_hmap_mutex);

    return ret;
}

odp_port_t
netdev_ifindex_to_odp_port(int ifindex)
{
    struct port_to_netdev_data *data;
    odp_port_t ret = 0;

    ovs_mutex_lock(&netdev_hmap_mutex);
    HMAP_FOR_EACH_WITH_HASH (data, ifindex_node, ifindex, &ifindex_to_port) {
        if (data->ifindex == ifindex) {
            ret = data->dpif_port.port_no;
            break;
        }
    }
    ovs_mutex_unlock(&netdev_hmap_mutex);

    return ret;
}

void
netdev_ports_flow_flush(const struct dpif_class *dpif_class)
{
    struct port_to_netdev_data *data;

    ovs_mutex_lock(&netdev_hmap_mutex);
    HMAP_FOR_EACH (data, portno_node, &port_to_netdev) {
        if (data->dpif_class == dpif_class) {
            netdev_flow_flush(data->netdev);
        }
    }
    ovs_mutex_unlock(&netdev_hmap_mutex);
}

struct netdev_flow_dump **
netdev_ports_flow_dump_create(const struct dpif_class *dpif_class, int *ports)
{
    struct port_to_netdev_data *data;
    struct netdev_flow_dump **dumps;
    int count = 0;
    int i = 0;

    ovs_mutex_lock(&netdev_hmap_mutex);
    HMAP_FOR_EACH (data, portno_node, &port_to_netdev) {
        if (data->dpif_class == dpif_class) {
            count++;
        }
    }

    dumps = count ? xzalloc(sizeof *dumps * count) : NULL;

    HMAP_FOR_EACH (data, portno_node, &port_to_netdev) {
        if (data->dpif_class == dpif_class) {
            if (netdev_flow_dump_create(data->netdev, &dumps[i])) {
                continue;
            }

            dumps[i]->port = data->dpif_port.port_no;
            i++;
        }
    }
    ovs_mutex_unlock(&netdev_hmap_mutex);

    *ports = i;
    return dumps;
}

int
netdev_ports_flow_del(const struct dpif_class *dpif_class,
                      const ovs_u128 *ufid,
                      struct dpif_flow_stats *stats)
{
    struct port_to_netdev_data *data;

    ovs_mutex_lock(&netdev_hmap_mutex);
    HMAP_FOR_EACH (data, portno_node, &port_to_netdev) {
        if (data->dpif_class == dpif_class
            && !netdev_flow_del(data->netdev, ufid, stats)) {
            ovs_mutex_unlock(&netdev_hmap_mutex);
            return 0;
        }
    }
    ovs_mutex_unlock(&netdev_hmap_mutex);

    return ENOENT;
}

int
netdev_ports_flow_get(const struct dpif_class *dpif_class, struct match *match,
                      struct nlattr **actions, const ovs_u128 *ufid,
                      struct dpif_flow_stats *stats,
                      struct dpif_flow_attrs *attrs, struct ofpbuf *buf)
{
    struct port_to_netdev_data *data;

    ovs_mutex_lock(&netdev_hmap_mutex);
    HMAP_FOR_EACH (data, portno_node, &port_to_netdev) {
        if (data->dpif_class == dpif_class
            && !netdev_flow_get(data->netdev, match, actions,
                                ufid, stats, attrs, buf)) {
            ovs_mutex_unlock(&netdev_hmap_mutex);
            return 0;
        }
    }
    ovs_mutex_unlock(&netdev_hmap_mutex);
    return ENOENT;
}

void
netdev_free_custom_stats_counters(struct netdev_custom_stats *custom_stats)
{
    if (custom_stats) {
        if (custom_stats->counters) {
            free(custom_stats->counters);
            custom_stats->counters = NULL;
            custom_stats->size = 0;
        }
    }
}

#ifdef __linux__
static void
netdev_ports_flow_init(void)
{
    struct port_to_netdev_data *data;

    ovs_mutex_lock(&netdev_hmap_mutex);
    HMAP_FOR_EACH (data, portno_node, &port_to_netdev) {
       netdev_init_flow_api(data->netdev);
    }
    ovs_mutex_unlock(&netdev_hmap_mutex);
}

void
netdev_set_flow_api_enabled(const struct smap *ovs_other_config)
{
    if (smap_get_bool(ovs_other_config, "hw-offload", false)) {
        static struct ovsthread_once once = OVSTHREAD_ONCE_INITIALIZER;

        if (ovsthread_once_start(&once)) {
            netdev_flow_api_enabled = true;

            VLOG_INFO("netdev: Flow API Enabled");

            tc_set_policy(smap_get_def(ovs_other_config, "tc-policy",
                                       TC_POLICY_DEFAULT));

            netdev_ports_flow_init();

            ovsthread_once_done(&once);
        }
    }
}
#else
void
netdev_set_flow_api_enabled(const struct smap *ovs_other_config OVS_UNUSED)
{
}
#endif
