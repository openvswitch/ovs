/*
* Copyright (c) 2021 Intel Corporation.
*
* Licensed under the Apache License, Version 2.0 (the "License");
* you may not use this file except in compliance with the License.
* You may obtain a copy of the License at:
*
* http://www.apache.org/licenses/LICENSE-2.0
*
* Unless required by applicable law or agreed to in writing, software
* distributed under the License is distributed on an "AS IS" BASIS,
* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
* See the License for the specific language governing permissions and
* limitations under the License.
*/

#include <config.h>
#include <errno.h>
#include <string.h>
#include <pthread.h>

#include "unixctl.h"
#include "openvswitch/vlog.h"
#include "openvswitch/shash.h"
#include "lib/vswitch-idl.h"
#include "p4proto.h"

#ifdef P4SAI
#include "switchlink/switchlink.h"
#endif

#include "p4proto-provider.h"
#include "bfIntf/bf_interface.h"
#include "p4rt/p4_service_interface.h"

#define P4_TDI_INSTALL_PATH "/usr"
#define P4_TDI_CFG_FILE "/usr/share/stratum/target_skip_p4_no_bsp.conf"

const char bf_sde_install[] = P4_TDI_INSTALL_PATH;
const char bf_switchd_cfg[] = P4_TDI_CFG_FILE;
const bool bf_switchd_background = true;

VLOG_DEFINE_THIS_MODULE(p4proto);

/*TODO: Define SWITCHLINK_ENABLE flag?*/
//extern int switchlink_init(void);

/* This URL is used by external gNMI, gNOI and P4Runtime clients.
 * TCP port 9339 is an IANA-reserved port for gNMI and gNOI.
 * TCP port 9559 is an IANA-reserved port for P4Runtime. */
const char grpc_server_ports[] = "0.0.0.0:9339,0.0.0.0:9559";

/* All p4 devices, indexed by name. */
static struct hmap all_p4devices = HMAP_INITIALIZER(&all_p4devices);

static unixctl_cb_func p4proto_dump_cache;

pthread_t p4_server_tid;
pthread_t switchlink_tid;

void *
p4_server_start(void *data OVS_UNUSED)
{
    enum status_code rc;

    p4_server_init(grpc_server_ports);

    rc = p4_server_run();
    if (rc != SUCCESS) {
        VLOG_ERR("Cannot start P4 Server, returned with error %d", rc);
    }

    return NULL;
}

void
p4proto_init(void)
{
    int rc;
    int status = 0;

    /* TODO:
      1. Maintain with_switchlink, with_switchsai and with_p4proto in
         configure script and pass flags via Makefile/CLI
      2. dpdk_init() should also mimic bmv2_model_init() behaviour and few
         calls to SAI layer should happen before switchlink.
         (start_switch_api_rpc_server, start_p4_sai_thrift_rpc_server,
          switch_sai_init, switchlink_init, etc)
      3. Figure out steps required to configure adapter-specific
         initializations before switchlink calls, if any?
    */
   #ifdef P4SAI
   bool with_switchlink =true;

    /* TODO: Conditional check - ifdef SWITCHLINK_ENABLE? */
   if (with_switchlink) {
        rc = pthread_create(&switchlink_tid, NULL, switchlink_init, NULL);
        if (rc) {
            VLOG_DBG("Switchlink thread creation failed, error %d", rc);
            return;
        }

        pthread_setname_np(switchlink_tid, "switchlink_init");
        VLOG_DBG("Switchlink thread with ID %lu spawned", switchlink_tid);
    }
    #endif

    unixctl_command_register("p4device/dump-cache", "[p4-device-id/all]", 1, 1,
                             p4proto_dump_cache, NULL);

    status = bf_p4_init(bf_sde_install, bf_switchd_cfg, bf_switchd_background);
    if (status != 0){
        VLOG_ERR("Not able to initialize the bf_switchd_lib, error %d", status);
    }

    rc = pthread_create(&p4_server_tid, NULL, p4_server_start, NULL);
    if (rc) {
        VLOG_DBG("P4 Server thread creation failed, error %d", rc);
        return;
    }

    pthread_setname_np(p4_server_tid, "p4_server");
    VLOG_DBG("P4 Server thread with ID %lu spawned", p4_server_tid);
}

void p4_server_cleanup(void)
{
    pthread_cancel(p4_server_tid);
    p4_server_shutdown();
}

/* Handling all deinit functionality */
void
p4proto_deinit(void)
{
    VLOG_DBG("Func called: %s", __func__);
    p4_server_cleanup();
}

/* Create p4proto structure and initialize structure members. */
void
p4proto_create(uint64_t device_id)
{
    struct p4proto *p4p;

    p4p = xzalloc(sizeof *p4p);

    p4p->dev_id = device_id;
    hmap_init(&p4p->bridges);
    hmap_insert(&all_p4devices, &p4p->node, hash_uint64(p4p->dev_id));
    VLOG_DBG("[%s]: Created P4 device %"PRIu64, __func__, device_id);
}

/* Destroy p4proto structure and remove associated bridges for the device */
void
p4proto_destroy(uint64_t device_id)
{
    struct p4proto *p4p;

    p4p = p4device_lookup(device_id);

    if (p4p) {
        hmap_remove(&all_p4devices, &p4p->node);
        free(p4p->type);
        free(p4p->name);

        if (p4p->config_file) {
            /* Send a delete or some event to SDE */
            free(p4p->config_file);
        }
        hmap_destroy(&p4p->bridges);
        free(p4p);
        VLOG_DBG("[%s]: Removed P4 device %"PRIu64, __func__, device_id);
    }
}

// TODO: Use right protoype after stratum integration
// p4proto_delete(const char *name, const char *type)
int
p4proto_delete(void)
{
    VLOG_DBG("Func called: %s", __func__);
    return 0;
}

void
p4proto_exit(void)
{
    VLOG_DBG("Func called: %s", __func__);
}

/* Find 'p4proto' structure from 'all_p4devices' based on device_id.
 * Return found structure or else return NULL */
struct p4proto*
p4device_lookup(uint64_t device_id)
{
    struct p4proto *p4p;

    HMAP_FOR_EACH(p4p, node, &all_p4devices) {
        if (p4p->dev_id == device_id) {
            VLOG_DBG("[%s] Found P4 device %"PRIu64, __func__, device_id);
            return p4p;
        }
    }
    VLOG_DBG("[%s] Couldnt find P4 device %"PRIu64, __func__, device_id);
    return NULL;
}

uint64_t get_device_id_from_bridge_name(char *br_name)
{
    uint64_t device_id = 0;
    struct p4proto *p4p;
    HMAP_FOR_EACH(p4p, node, &all_p4devices) {
        if (hmap_first_with_hash(&p4p->bridges, hash_string(br_name, 0))) {
                device_id = p4p->dev_id;
                break;
        }
    }
     return device_id;
}

/* Based on list of p4devices in 'new_p4_devices' received from OVSDB
 * either add or remove p4 device information from all_p4devices hmap.
 * Also, update list of bridges associated with each P4 device. */
void
p4proto_add_del_devices(struct shash *new_p4_devices)
{
    const struct ovsrec_p4_device *device_cfg;
    const struct ovsrec_bridge *br_cfg;
    struct p4proto *device, *next_device;
    struct hmap all_p4device_bridges;
    struct shash_node *bridges;
    struct hmap_node *br_node;
    uint64_t device_id;
    size_t list;

    /* Delete old p4 device from cache. */
    HMAP_FOR_EACH_SAFE (device, next_device, node, &all_p4devices) {
        device_id = device->dev_id;
        char *key = xasprintf("%"PRIu64, device_id);
        if (!shash_find_data(new_p4_devices, key)) {
            p4proto_destroy(device_id);
        }
        free(key);
    }

    /* Add new p4 device to cache. */
    SHASH_FOR_EACH(bridges, new_p4_devices) {
        device_cfg = bridges->data;
        device_id = (uint64_t)*device_cfg->device_id;
        if (!hmap_first_with_hash(&all_p4devices, hash_uint64(device_id))) {
            p4proto_create(device_id);
        }

        if (device_cfg->config_file_path) {
            p4proto_update_config_file(device_id, device_cfg->config_file_path);
        }

        /* Check if any bridge is added or deleted to/from a p4 device.
         * if added, then add bridge node to p4 device bridge list.
         * if deleted, then remove bridge node from p4 device bridge list. */

        hmap_init(&all_p4device_bridges);

        for (list = 0; list < device_cfg->n_bridges; list++) {
            br_cfg = device_cfg->bridges[list];
            br_node = get_bridge_node(br_cfg->name);
            if (br_node) {
                hmap_insert(&all_p4device_bridges, br_node,
                            hash_string(br_cfg->name, 0));
                p4proto_update_bridge(device_id, br_node, br_cfg->name);
            }
        }

        device = p4device_lookup(device_id);

        if (device) {
            /* Loop through all bridges in a p4 device and validate which
             * bridge from p4 device is deleted in OVSDB and remove it from
             * p4device as well. */
            p4proto_delete_bridges(&device->bridges, &all_p4device_bridges,
                                   device->dev_id);
        }
        hmap_destroy(&all_p4device_bridges);
    }

}

/* Update config file path for a p4 device */
void
p4proto_update_config_file(uint64_t device_id, const char *file_path)
{
    struct p4proto *p4p;

    p4p = p4device_lookup(device_id);

    if (p4p) {
        if (!p4p->config_file) {
            p4p->config_file = xstrdup(file_path);
            VLOG_DBG("[%s]: Added config file :%s: for P4 device %"PRIu64,
                     __func__, file_path, device_id);
            /* TODO send an Add event to SDE about the config file*/
        } else if (strcmp(file_path, p4p->config_file)) {
            /* TODO send an delete event to SDE about old config file*/
            VLOG_DBG("[%s]: Updated config file from :%s: to :%s: for "
                     "P4 device %"PRIu64, __func__, p4p->config_file,
                     file_path, device_id);
            free(p4p->config_file);
            p4p->config_file = xstrdup(file_path);
            /* TODO send an Add event to SDE about the new config file*/
        }
    }
}

/* Associate new bridge to the p4 device */
void
p4proto_update_bridge(uint64_t device_id, struct hmap_node *br_node,
                      const char *br_name)
{
    struct p4proto *p4p;

    p4p = p4device_lookup(device_id);

    if (p4p && !hmap_first_with_hash(&p4p->bridges, hash_string(br_name, 0))) {
        hmap_insert(&p4p->bridges, br_node, hash_string(br_name, 0));
        VLOG_DBG("[%s]: Added bridge %s to P4 device %"PRIu64,
                 __func__, br_name, device_id);
        /* TODO Send an event regarding bridge add */
    }
}

/* Remove a bridge from P4 device */
void
p4proto_remove_bridge(struct hmap_node *br_node, const char *br_name)
{
    struct p4proto *p4p;

    HMAP_FOR_EACH(p4p, node, &all_p4devices) {
        if (hmap_first_with_hash(&p4p->bridges, hash_string(br_name, 0))) {
            VLOG_DBG("[%s]: Deleted bridge %s from P4 device %"PRIu64,
                     __func__, br_name, p4p->dev_id);
            hmap_remove(&p4p->bridges, br_node);
            /* TODO Send an event regarding bridge delete */
        }
    }
}

static void
p4proto_dump_device(struct ds *ds, struct p4proto *device)
{
    ds_put_format(ds, "\n\ttype=%s", device->type);
    ds_put_format(ds, "\n\tname=%s", device->type);
    ds_put_format(ds, "\n\tConfig file=%s", device->config_file);
    ds_put_format(ds, "\n\tTotal no of bridges=%lu",
                    hmap_count(&device->bridges));
    p4proto_dump_bridge_names(ds, &device->bridges);
    ds_put_format(ds, "\n");
}

/* Loop through all p4 devices and print particular p4 device's
 * local data or print for all available p4 devices */
static void
p4proto_dump_cache(struct unixctl_conn *conn, int argc OVS_UNUSED,
                   const char *argv[], void *aux OVS_UNUSED)
{
    struct ds results;
    struct p4proto *device;
    uint64_t device_id;
    bool search_all_devices = !strcmp(argv[1], "all") ? true : false;

    ds_init(&results);
    HMAP_FOR_EACH (device, node, &all_p4devices) {
        device_id = device->dev_id;
        if (!search_all_devices) {
            if (device->dev_id == atoi(argv[1])) {
                ds_put_format(&results, "\nCache for device_id : %"PRIu64,
                              device_id);
                p4proto_dump_device(&results, device);
                break;
            }
            continue;
        }
        ds_put_format(&results, "\nCache for device_id : %"PRIu64, device_id);
        p4proto_dump_device(&results, device);
    }
    unixctl_command_reply(conn, ds_cstr(&results));
    ds_destroy(&results);
}
