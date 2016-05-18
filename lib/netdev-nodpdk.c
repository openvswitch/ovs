#include <config.h>
#include "netdev-dpdk.h"
#include "smap.h"
#include "ovs-thread.h"
#include "openvswitch/vlog.h"

VLOG_DEFINE_THIS_MODULE(dpdk);

void
dpdk_init(const struct smap *ovs_other_config)
{
    static struct ovsthread_once once = OVSTHREAD_ONCE_INITIALIZER;

    if (ovsthread_once_start(&once)) {
        if (smap_get_bool(ovs_other_config, "dpdk-init", false)) {
            VLOG_ERR("DPDK not supported in this copy of Open vSwitch.");
        }
        ovsthread_once_done(&once);
    }
}
