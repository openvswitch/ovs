/*
 * Copyright (c) 2009, 2010, 2011, 2012, 2013, 2014, 2016 Nicira, Inc.
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
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <net/if.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>
#include <time.h>

#ifdef DPDK_NETDEV
#include <rte_cycles.h>
#include <rte_flow.h>
#endif

#include "dpif-netdev.h"
#include "netdev-provider.h"
#include "include/openvswitch/vlog.h"
#include "netdev-dpdk.h"
#include "hw-pipeline.h"

VLOG_DEFINE_THIS_MODULE(hw_pipeline);

struct set_rte_action {
    void (*set)(struct rte_flow_action *, uint32_t data, size_t *);
};

static struct dp_netdev_flow *hw_pipeline_read_flow(flow_tag_pool *p,
                                                    uint32_t flow_tag);
static int hw_pipeline_send_insert_flow(struct dp_netdev *dp,
                                        odp_port_t in_port,
                                        struct dp_netdev_flow *flow,
                                        struct flow *masks,
                                        int rxqid);

uint32_t hw_pipeline_ft_pool_get(flow_tag_pool *p,
        struct dp_netdev_flow *flow);

bool hw_pipeline_ft_pool_free(flow_tag_pool *p,uint32_t flow_tag);

bool hw_pipeline_ft_pool_is_valid(flow_tag_pool *p);

static int hw_pipeline_remove_flow(struct dp_netdev *dp,
                                   msg_hw_flow *ptr_rule);

static int hw_pipeline_create_external_rule(struct dp_netdev *dp,
                                            msg_sw_flow *ptr_rule,
                                            struct set_rte_action *action,
                                            size_t action_num,
                                            struct rte_flow **hw_flow_h);

static void hw_pipeline_item_array_build(struct set_rte_item *item_any_flow,
                                         struct flow *mask,
                                         size_t *buf_size,
                                         size_t *item_num);

static inline struct rte_flow *hw_pipeline_rte_flow_create(
        struct dp_netdev *dp,
        struct flow *flow,
        struct flow *mask,
        odp_port_t in_port,
        struct set_rte_item item_op[],
        struct set_rte_action action_op[],
        uint32_t action_data[],
        size_t item_op_size,
        size_t action_op_size,
        size_t buf_size,
        size_t table_id);


// Internal functions Flow Tags Pool

uint32_t hw_pipeline_ft_pool_init(flow_tag_pool *p,uint32_t pool_size);
uint32_t hw_pipeline_ft_pool_uninit(flow_tag_pool *p);

struct dp_netdev_flow *hw_pipeline_ft_pool_read_flow(flow_tag_pool *p,
                                                     uint32_t handle);

// Internal functions Message Queue

static int hw_pipeline_msg_queue_init(msg_queue *message_queue,
                                      unsigned core_id);
static int hw_pipeline_msg_queue_clear(msg_queue *message_queue);

static int hw_pipeline_send_remove_flow(struct dp_netdev *dp,
                                        uint32_t flow_tag,ovs_u128 *ufidp);

void *hw_pipeline_thread(void *pdp);

/*****************************************************************************/
//    HW Flow Tags Pool
//        A pool of unique tags used by the OVS
//        The flow tag is used as an interface with the HW.
//        If there is a match between a packet & a rule then
//        the flow tag is received by the OVS in the fdir.hash in the rte_mbuf
//        With this flow tag the OVS find the associated flow.
//        The Pool is per pmd_thread.
//        Each flow points on a flow tag and vice versa.
/*****************************************************************************/
bool hw_pipeline_ft_pool_is_valid(flow_tag_pool *p)
{
    rte_spinlock_lock(&p->lock);
    if (p->ft_data != NULL && p->pool_size>0) {
        VLOG_DBG("The pool is allocated & its size is : %d\n", p->pool_size);
        rte_spinlock_unlock(&p->lock);
        return true;
    }

    VLOG_DBG("The pool is invalid its size is : %d\n", p->pool_size);
    rte_spinlock_unlock(&p->lock);
    return false;
}

flow_elem *hw_pipeline_ft_pool_read_elem(struct dp_netdev *dp,
                                         uint32_t handle)
{
    uint32_t index;
    flow_elem *elem;

    if (OVS_UNLIKELY(dp == NULL)) {
        VLOG_ERR("no dp pointer \n");
        return NULL;
    }

    index = OVS_FLOW_TAG_INDEX_GET(handle);
    if (OVS_UNLIKELY(index >= HW_MAX_FLOW_TAG)) {
        VLOG_ERR("index out of range\n");
        return NULL;
    }

    rte_spinlock_lock(&dp->ft_pool.lock);
    elem = &dp->ft_pool.ft_data[index];
    rte_spinlock_unlock(&dp->ft_pool.lock);

    return elem;
}


inline struct dp_netdev_flow *hw_pipeline_ft_pool_read_flow(flow_tag_pool *p,
                                                            uint32_t handle)
{
    uint32_t index;
    struct dp_netdev_flow *flow=NULL;
    index = OVS_FLOW_TAG_INDEX_GET(handle);
    if (OVS_UNLIKELY(index >= HW_MAX_FLOW_TAG)) {
        VLOG_ERR("index out of range\n");
        return NULL;
    }

    rte_spinlock_lock(&p->lock);
    p->ft_data[index].valid =true;
    flow = p->ft_data[index].sw_flow;
    rte_spinlock_unlock(&p->lock);

    return flow;
}

uint32_t hw_pipeline_ft_pool_init(flow_tag_pool *p,
                                  uint32_t pool_size)
{
    uint32_t ii=0;

    if (OVS_UNLIKELY(pool_size > HW_MAX_FLOW_TAG || p == NULL)) {
        VLOG_ERR("pool size is too big or pool is NULL \n");
        return -1;
    }
    p->ft_data = (flow_elem *)xmalloc(pool_size * sizeof(flow_elem));
    if (OVS_UNLIKELY(p->ft_data == NULL)) {
        VLOG_ERR("No free memory for the pool \n");
        return -1;
    }
    memset(p->ft_data,0,(pool_size * sizeof(flow_elem)));
    rte_spinlock_init(&p->lock);
    rte_spinlock_lock(&p->lock);
    p->head=0;
    p->tail=0;
    p->pool_size = pool_size;
    for (ii=0;ii<pool_size;ii++) {
        p->ft_data[ii].next = ii+1;
        rte_spinlock_init(&p->ft_data[ii].lock);
    }
    p->ft_data[pool_size-1].next = HW_NO_FREE_FLOW_TAG;
    rte_spinlock_unlock(&p->lock);
    return 0;
}

uint32_t hw_pipeline_ft_pool_uninit(flow_tag_pool *p)
{
    uint32_t ii=0;

    if (OVS_UNLIKELY(p==NULL||p->ft_data==NULL)) {
        VLOG_ERR("No pool or no data allocated \n");
        return -1;
    }
    rte_spinlock_lock(&p->lock);
    p->head=0;
    p->tail=0;
    for (ii=0; ii < p->pool_size; ii++) {
        p->ft_data[ii].next = 0;
        p->ft_data[ii].valid=false;
    }
    free(p->ft_data);
    rte_spinlock_unlock(&p->lock);
    return 0;
}
/*
 *  hw_pipeline_ft_pool_get returns an index from the pool
 *  The index is returned from the head.
 *
 *  The function deals with 3 cases:
 *        1. no more indexes in the pool . returns HW_NO_FREE_FLOW_TAG
 *        2. There is an index:
 *        		a. This is the last index
 *        		b. This is the common index
 * */
uint32_t hw_pipeline_ft_pool_get(flow_tag_pool *p,struct dp_netdev_flow *flow)
{
    uint32_t next;
    uint32_t index;

    rte_spinlock_lock(&p->lock);
    if (p->head != HW_NO_FREE_FLOW_TAG) {
        //(case 2b , see function header above)
        // returns the current head & update the head to head.next
        index = p->head;
        next = p->ft_data[index].next;
        p->head = next;
        if (next == HW_NO_FREE_FLOW_TAG) {
            //last index (case 2a , see function header above)
            p->tail = HW_NO_FREE_FLOW_TAG;
        }
        p->ft_data[index].sw_flow = flow;
        p->ft_data[index].valid = true;
        rte_spinlock_unlock(&p->lock);
        return index;
    }
    else {
    // no more free tags ( case 1, see function header above)
        rte_spinlock_unlock(&p->lock);
        VLOG_DBG("No more flow tags \n");
        return HW_NO_FREE_FLOW_TAG;
    }

    rte_spinlock_unlock(&p->lock);
    return index;
}
/*
 *  hw_pipeline_ft_pool_free returns an index to the pool.
 *  The index is returned to the tail.
 *  The function deals with 3 cases:
 *        1. index out of range in the pool . returns false
 *        2. There is an place in the pool :
 *        		a. This is the last place .
 *        		b. This is the common index .
 * */
bool hw_pipeline_ft_pool_free(flow_tag_pool *p,
                              uint32_t handle)
{
    uint32_t index ,tail;

    index = OVS_FLOW_TAG_INDEX_GET(handle);
    if(OVS_UNLIKELY(index >= HW_MAX_FLOW_TAG)) {
    // ( case 1, see function header above)
        VLOG_ERR("index out of range \n");
        return false;
    }
    rte_spinlock_lock(&p->lock);
    tail = p->tail;
    if (tail == HW_NO_FREE_FLOW_TAG) {
    // last place in the pool ( case 2a, see function header above)
        p->head = index;
    }
    else {
    // common case ( case 2b, see function header above)
        p->ft_data[tail].next = index;  // old tail next points on index
    }
    // current tail is updated to be index & its next HW_NO_FREE_FLOW_TAG
    p->tail = index;
    p->ft_data[index].next = HW_NO_FREE_FLOW_TAG;
    p->ft_data[index].valid = false;
    rte_spinlock_unlock(&p->lock);
    return true;
}

/*************************************************************************/
// Msg Queue
//  A queue that contains pairs : (flow , key )
//  The queue is used a communication channel between pmd_thread_main &
//  hw_pipeline_thread .
//  The  hw_pipeline_thread dequeue (key,flow ) from the msg queue
//  & calls emc_hw_insert that inserts classifier rules
//  to hardware flow tables.
//  The pmd_thread_main enqueue (key,flow) into the msg qeueue and continues.
/*************************************************************************/
static int hw_pipeline_msg_queue_init(msg_queue *message_queue,
        unsigned core_id)
{
    int ret;
    const char dir[] = "/tmp";
    const char fifo[] = "/tmp/msgq_pipe";
    char fifo_pmd[20];

    sprintf(fifo_pmd,"%s%d",fifo,core_id);
    message_queue->tv.tv_sec = 0;
    message_queue->tv.tv_usec = HW_PIPELINE_MSGQ_TO;

    strcpy(message_queue->pipeName,fifo_pmd);

    if (mkdir(dir, 0755) == -1 && errno != EEXIST) {
        VLOG_ERR("Failed to create directory: ");
        return -1;
    }

    ret = mkfifo(fifo_pmd,0666);
    if (OVS_UNLIKELY(ret < 0)) {
        if (errno==EEXIST) {
            ret = unlink(fifo_pmd);
            if (OVS_UNLIKELY(ret < 0)) {
                VLOG_ERR("Remove fifo failed .\n");
                return -1;
            }
            ret = mkfifo(fifo_pmd,0666 );
            if (OVS_UNLIKELY(ret < 0)) {
                if (errno==EEXIST) {
                    VLOG_ERR("That file already exists.\n");
                    VLOG_ERR("(or we passed in a symbolic link,");
                    VLOG_ERR(" which we did not.)\n");
                    return -1;
                }
            }
        }
        else if (errno==EROFS) {
            VLOG_ERR("The name file resides on a read-only file-system\n");
            return -1;
        }
        else {
            VLOG_ERR("mkfifo failed %x \n",errno);
            return -1;
        }
    }
    message_queue->readFd  = open(message_queue->pipeName,
            O_RDONLY|O_NONBLOCK);
    if (OVS_UNLIKELY(message_queue->readFd == -1)) {
        VLOG_ERR("Error creating read file descriptor");
        return -1;
    }
    message_queue->writeFd = open(message_queue->pipeName,
            O_WRONLY|O_NONBLOCK);
    if (OVS_UNLIKELY(message_queue->writeFd == -1)) {
        VLOG_ERR("Error creating write file descriptor");
        return -1;
    }
    return 0;
}

static int hw_pipeline_msg_queue_clear(msg_queue *message_queue)
{
    int ret =0;
    ret = close(message_queue->readFd);
    if (OVS_UNLIKELY( ret == -1 )) {
        VLOG_ERR("Error while closing the read file descriptor.");
        return -1;
    }
    ret = close(message_queue->writeFd);
    if (OVS_UNLIKELY( ret == -1 )) {
        VLOG_ERR("Error while closing the write file descriptor.");
        return -1;
    }

    ret = unlink(message_queue->pipeName);
    if (OVS_UNLIKELY( ret < 0 )) {
        VLOG_ERR("Remove fifo failed .\n");
        return -1;
    }

    return 0;
}


static bool hw_pipeline_msg_queue_enqueue(msg_queue *message_queue,
                                          msg_queue_elem *data)
{
    ssize_t ret =0;

    ret = write(message_queue->writeFd, data, sizeof(msg_queue_elem));
    if (OVS_UNLIKELY( ret == -1)) {
        switch (errno) {
            case EBADF:
                VLOG_ERR("FD is non-valid , or is not open for writing.\n");
                break;
            case EFBIG:
                VLOG_ERR("File is too large.\n");
                break;
            case EINTR:
                VLOG_ERR("interrupted by a signal\n");
                break;
            case EIO:
                VLOG_ERR("hardware error\n");
                break;
            case ENOSPC:
                VLOG_ERR("The device's file is full\n");
                break;
            case EPIPE:
                VLOG_ERR("FIFO that isn't open for reading\n");
                break;
            case EINVAL:
                VLOG_ERR("Not aligned to the block size");
                break;
            default:
                break;
        }
        return false;
    }
    return true;
}

static int hw_pipeline_msg_queue_dequeue(msg_queue *message_queue,
                                         msg_queue_elem *data)
{
    ssize_t ret=0;
    int err=0;
    fd_set readset;
    int readFd = (*(int *)&message_queue->readFd);
    FD_ZERO(&readset);
    FD_SET(readFd, &readset);
        // Now, check for readability
    err = select(readFd+1,&readset,NULL, NULL,&message_queue->tv);

    if (OVS_LIKELY(err>0 && FD_ISSET(readFd, &readset))) {
        // Clear flags
        FD_CLR(readFd, &readset);

        ret = read(readFd, data, sizeof(msg_queue_elem));
        if (OVS_UNLIKELY( ret == -1)) {
            VLOG_ERR("Error reading from the  file descriptor.");
            return ret;
        }
    }
    else {
        VLOG_DBG("File descriptor is not set .");
        return err;
    }

    return 0;
}

inline void
hw_pipeline_get_packet_md(struct netdev *netdev,
                          struct dp_packet *packet,
                          struct pipeline_md *ppl_md)
{
    if(netdev->netdev_class->get_pipeline) {
        netdev->netdev_class->get_pipeline(netdev, packet, ppl_md);
    }
}


enum {
    ITEM_SET_MASK,
    ITEM_SET_SPEC
};

static inline void
rte_item_set_eth(struct flow *flow,
                 struct rte_flow_item *item,
                 size_t *offset,
                 int mode)
{
    struct rte_flow_item_eth *eth;

    switch (mode) {
       case ITEM_SET_MASK:
           eth = (struct rte_flow_item_eth *)item->mask;
           break;
       case ITEM_SET_SPEC:
           eth = (struct rte_flow_item_eth *)item->spec;
           break;
       default:
           return;
    }
    item->type = RTE_FLOW_ITEM_TYPE_ETH;
    *offset += sizeof(struct rte_flow_item_eth);

    memcpy(&eth->dst, &flow->dl_dst.ea[0], sizeof(eth->dst));
    memcpy(&eth->src, &flow->dl_src.ea[0], sizeof(eth->src));
}

static inline void
rte_item_set_eth_vlan(struct flow *flow,
                      struct rte_flow_item *item,
                      size_t *offset,
                      int mode)
{
    struct rte_flow_item_vlan *vlan ;

    switch (mode) {
       case ITEM_SET_MASK:
           vlan = (struct rte_flow_item_vlan *)item->mask;
           break;
       case ITEM_SET_SPEC:
          vlan = (struct rte_flow_item_vlan *)item->spec;
          break;
       default:
           return;
    }
    item->type = RTE_FLOW_ITEM_TYPE_VLAN;
    *offset += sizeof(*vlan);
    vlan->tci= flow->vlans[0].tci;
    vlan->tpid=flow->vlans[0].tpid;
}


static inline void
rte_item_set_ip(struct flow *flow,
                struct rte_flow_item *item,
                size_t *offset,
                int mode)
{
    struct rte_flow_item_ipv4 *ip;

    switch (mode) {
        case ITEM_SET_MASK:
            ip = (struct rte_flow_item_ipv4 *)item->mask;
            break;
        case ITEM_SET_SPEC:
          ip = (struct rte_flow_item_ipv4 *)item->spec;
          break;
        default:
          return;
    }
    item->type = RTE_FLOW_ITEM_TYPE_IPV4;
    *offset += sizeof(*ip);

    ip->hdr.src_addr = flow->nw_src;
    ip->hdr.dst_addr = flow->nw_dst;

    VLOG_INFO("%s - src ip: %d.%d.%d.%d dst ip: %d.%d.%d.%d\n",
          __func__,
          (ip->hdr.src_addr >> 0) & 0xff,
          (ip->hdr.src_addr >> 8) & 0xff,
          (ip->hdr.src_addr >> 16) & 0xff,
          (ip->hdr.src_addr >> 24) & 0xff,
          (ip->hdr.dst_addr >> 0) & 0xff,
          (ip->hdr.dst_addr >> 8) & 0xff,
          (ip->hdr.dst_addr >> 16) & 0xff,
          (ip->hdr.dst_addr >> 24) & 0xff);
}

static inline void
rte_item_set_udp(struct flow *flow,
                 struct rte_flow_item *item,
                 size_t *offset,
                 int mode)
{
    struct rte_flow_item_udp *udp;

    switch (mode) {
       case ITEM_SET_MASK:
           udp = (struct rte_flow_item_udp *)item->mask;
           break;
       case ITEM_SET_SPEC:
          udp = (struct rte_flow_item_udp *)item->spec;
          break;
       default:
           return;
    }

    item->type = RTE_FLOW_ITEM_TYPE_UDP;
    *offset += sizeof(struct rte_flow_item_udp);

    udp->hdr.dst_port = flow->tp_dst;
    udp->hdr.src_port = flow->tp_src;
}

static inline void
rte_item_set_end(__attribute__ ((unused))struct flow *flow,
                 struct rte_flow_item *item,
                 __attribute__ ((unused))size_t *offset,
                 __attribute__ ((unused))int mode)
{
    item->type = RTE_FLOW_ITEM_TYPE_END;
}

static inline void
rte_action_set_mark(struct rte_flow_action *action,
                    uint32_t data,
                    size_t *offset)
{
    struct rte_flow_action_mark *mark =
                (struct rte_flow_action_mark *)action->conf;
    action->type = RTE_FLOW_ACTION_TYPE_MARK;
    *offset += sizeof(*mark);
    mark->id = data;
}

static inline void
rte_action_set_queue(struct rte_flow_action *action,
                     uint32_t data,
                     size_t *offset)
{
    struct rte_flow_action_queue *queue =
            (struct rte_flow_action_queue *)action->conf;
    action->type = RTE_FLOW_ACTION_TYPE_QUEUE;
    *offset += sizeof(*queue);

    queue->index = data;
}

static inline void
rte_action_set_end(struct rte_flow_action *action,
            __attribute__ ((unused))uint32_t data,
            __attribute__ ((unused))size_t *offset)
{
    action->type = RTE_FLOW_ACTION_TYPE_END;
}

struct set_rte_action action_mark_flow[] = {
    { .set = rte_action_set_mark },
    { .set = rte_action_set_queue },
    { .set = rte_action_set_end },
};

static inline int hw_pipeline_rte_flow_create_and_save(
        odp_port_t in_port,
        struct dp_netdev *dp,
        struct flow *flow,
        struct flow *mask,
        struct set_rte_item item_op[],
        struct set_rte_action action_op[],
        uint32_t action_data[],
        size_t item_op_size,
        size_t action_op_size,
        size_t buf_size,
        size_t table_id,
        struct rte_flow **hw_flow_h)
{

    *hw_flow_h = hw_pipeline_rte_flow_create(dp,flow,mask,in_port, item_op,
            action_op, action_data,item_op_size,action_op_size,
            buf_size,table_id);
    if (OVS_UNLIKELY(*hw_flow_h == NULL)) {
        VLOG_ERR("Can not insert rule to HW \n");
        return -1;
    }
    return 0;
}
static inline struct rte_flow *hw_pipeline_rte_flow_create(
        struct dp_netdev *dp,
        struct flow *flow,
        struct flow *mask,
        odp_port_t in_port,
        struct set_rte_item item_op[],
        struct set_rte_action action_op[],
        uint32_t action_data[],
        size_t item_op_size,
        size_t action_op_size,
        size_t buf_size,
        size_t table_id)
{
    struct rte_flow_attr attr = {.ingress = 1};
    struct rte_flow_item item[item_op_size];
    struct rte_flow_action action[action_op_size];
    struct rte_flow_error error = {0};
    struct rte_flow *hw_flow_ptr;
    uint8_t buf[buf_size];
    struct dp_netdev_port *dp_port;
    size_t offset = 0;
    size_t i;
    int ret;

    memset(item, 0, sizeof(item[0]) * item_op_size);
    memset(action, 0, sizeof(action[0]) * action_op_size);
    memset(buf, 0, sizeof(buf[0]) * buf_size);

    attr.priority = table_id;
    for (i = 0; i < item_op_size; i++) {
        item[i].spec = &buf[offset];
        item_op[i].set(flow, &item[i], &offset,ITEM_SET_SPEC);
        item[i].mask = &buf[offset];
        item_op[i].set(mask, &item[i], &offset,ITEM_SET_MASK);
    }

    for (i = 0; i < action_op_size; i++) {
        action[i].conf = buf + offset;
        action_op[i].set(&action[i], action_data[i], &offset);
    }

    ret = get_port_by_number(dp,in_port,&dp_port);
    if (OVS_UNLIKELY(ret)) {
        VLOG_INFO("Can't get pmd port\n");
        return NULL;
    }

    hw_flow_ptr = netdev_dpdk_rte_flow_validate(dp_port->netdev, &attr, item,
            action, &error);
    if (OVS_UNLIKELY(hw_flow_ptr == NULL)) {
        VLOG_INFO("Can't insert (%s)\n", error.message);
        return NULL;
    }

    return hw_flow_ptr;
}

void hw_pipeline_item_array_build(struct set_rte_item *item_any_flow,
                                  struct flow *mask,
                                  size_t *buf_size,
                                  size_t *item_num)
{
    int ii=0;
    struct eth_addr eth_mac;

    *buf_size =0;
    memset(&eth_mac,0,sizeof(struct eth_addr));

    VLOG_INFO("dl_dst : %x %x %x %x %x %x\n",mask->dl_dst.ea[0],
            mask->dl_dst.ea[1],mask->dl_dst.ea[2],
            mask->dl_dst.ea[3],mask->dl_dst.ea[4],
            mask->dl_dst.ea[5]);
    VLOG_INFO("dl_src : %x %x %x %x %x %x\n",mask->dl_src.ea[0],
            mask->dl_src.ea[1],mask->dl_src.ea[2],
            mask->dl_src.ea[3],mask->dl_src.ea[4],
            mask->dl_src.ea[5]);

    if (memcmp(&mask->dl_dst,&eth_mac,sizeof(struct eth_addr))!=0
    || memcmp(&mask->dl_src,&eth_mac,sizeof(struct eth_addr))!=0) {
        VLOG_INFO("rte_item_eth\n");
        item_any_flow[ii++].set = rte_item_set_eth;
        *buf_size += sizeof(struct rte_flow_item_eth);
        *buf_size += sizeof(struct rte_flow_item_eth);
        if (mask->nw_src!=0 || mask->nw_dst!=0) {
            VLOG_INFO("rte_item_ip\n");
            item_any_flow[ii++].set = rte_item_set_ip;
            *buf_size += sizeof(struct rte_flow_item_ipv4);
            *buf_size += sizeof(struct rte_flow_item_ipv4);
            if (mask->tp_dst!=0 || mask->tp_src!=0) {
                item_any_flow[ii++].set = rte_item_set_udp;
                *buf_size += sizeof(struct rte_flow_item_udp);
                *buf_size += sizeof(struct rte_flow_item_udp);
            }
        }
    }

    item_any_flow[ii].set = rte_item_set_end;
    *item_num=ii+1;
    return;
}


inline static void hw_pipeline_prepare_action(uint32_t flow_tag,int rxqid,
        size_t *buf_size,uint32_t *action_data)
{
    *buf_size += sizeof(struct rte_flow_action_mark) +
                 sizeof(struct rte_flow_action_queue);
    /* actions order:
     * Flow Tag mark
     * queue
     * end
     */
    action_data[0] = flow_tag;
    action_data[1] = rxqid;
    action_data[2] = 0;
    return;
}

/*
 This case intend to deal with all cases but VxLAN

  The flow attribute group is set to 0
  The flow item is flexible
  The flow action is flow tag marking plus destination queue
  flow tag is unique and taken from a pool of tags.
  It is saved for lookup later on in the processing phase.

*/

static int hw_pipeline_create_external_rule(struct dp_netdev *dp,
                                           msg_sw_flow *ptr_rule,
                                           struct set_rte_action *action,
                                           size_t action_num,
                                           struct rte_flow **hw_flow_h)
{
    struct flow *sw_flow = (struct flow *)&ptr_rule->sw_flow.flow;
    struct flow *hw_flow = sw_flow;
    uint32_t flow_tag = ptr_rule->sw_flow.cr.flow_tag;
    struct flow *wildcard_mask =  &ptr_rule->sw_flow_mask;
    size_t item_num = 0;
    size_t buf_size =   0;
    struct set_rte_item item_any_flow[] = {
                { .set = NULL },
                { .set = NULL },
                { .set = NULL },
                { .set = NULL },
                { .set = NULL },
    };
    uint32_t action_data[action_num];
    int ret =0;

    hw_pipeline_item_array_build(item_any_flow,wildcard_mask,&buf_size,
            &item_num);

    hw_pipeline_prepare_action(flow_tag,ptr_rule->rxqid,&buf_size,action_data);

    ret = hw_pipeline_rte_flow_create_and_save(hw_flow->in_port.odp_port, dp,
                                               hw_flow, wildcard_mask,
                                               item_any_flow,
                                               action, action_data,
                                               item_num, action_num,
                                               buf_size, 0, hw_flow_h);
    if (OVS_UNLIKELY(ret == -1)) {
        VLOG_ERR("Rule with flow_tag can not be inserted : %x  \n",flow_tag);
        return -1;
    }

    return 0;
}

static int hw_pipeline_send_remove_flow(struct dp_netdev *dp,uint32_t flow_tag,
        ovs_u128 *ufidp)
{
    msg_queue_elem rule;

    rule.data.rm_flow.in_port=
        dp->ft_pool.ft_data[flow_tag].sw_flow->flow.in_port.odp_port;
    rule.data.rm_flow.flow_tag = flow_tag;
    memcpy(&rule.data.rm_flow.ufid,ufidp,sizeof(ovs_u128));
    rule.mode = HW_PIPELINE_REMOVE_RULE;

    if (OVS_UNLIKELY(
            !hw_pipeline_msg_queue_enqueue(&dp->message_queue,&rule))) {
        VLOG_INFO("queue overflow");
        return -1;
    }

    return 0;
}

static struct dp_netdev_flow *hw_pipeline_read_flow(flow_tag_pool *p,
        uint32_t handle)
{
    struct dp_netdev_flow *netdev_flow=NULL;
    netdev_flow = hw_pipeline_ft_pool_read_flow(p,handle);
    if (OVS_UNLIKELY(netdev_flow == NULL)) {
        VLOG_INFO("No flow found");
        return NULL;
    }
    VLOG_INFO("flow found with tag %x\n",netdev_flow->cr.flow_tag);
    VLOG_INFO("flow found with handle %x\n",handle);
    return netdev_flow;
}

static int hw_pipeline_send_insert_flow(struct dp_netdev *dp,
        odp_port_t in_port, struct dp_netdev_flow *flow, struct flow *masks,
        int rxqid)
{
    msg_queue_elem rule;

    rule.data.sw_flow.in_port = in_port;
    rule.data.sw_flow.rxqid   = rxqid;
    memcpy(&rule.data.sw_flow.sw_flow,flow,sizeof(struct dp_netdev_flow));
    memcpy(&rule.data.sw_flow.sw_flow_mask,masks,sizeof(struct flow));
    rule.mode = HW_PIPELINE_INSERT_RULE;
    if (OVS_UNLIKELY(
        !hw_pipeline_msg_queue_enqueue(&dp->message_queue,&rule))) {
        VLOG_ERR("queue overflow");
        return -1;
    }
    return 0;
}

static inline int
hw_pipeline_insert_flow(struct dp_netdev *dp,msg_sw_flow *ptr_rule)
{
    bool drop_action = false;
    int ret =-1;
    bool found_tun_pop=false;
    struct rte_flow *hw_flow_h;

    /* Program the NICs */
    dpif_netdev_find_action_active(&ptr_rule->sw_flow,&drop_action,
            &found_tun_pop);
    if (drop_action) {
        if ((dpif_netdev_vport_is_tunnel(dp, ptr_rule->in_port) ||
            ptr_rule->sw_flow.flow.nw_proto == GRE_PROTOCOL )
            && found_tun_pop) {
            VLOG_INFO("Internal table , drop rule\n");
        }
        else {
            VLOG_INFO("External table , drop rule\n");
        }
        return ret;
    }
    if (dpdk_netdev_is_dpdk_port(dp,ptr_rule->in_port)) {
        if ((dpif_netdev_vport_is_tunnel(dp, ptr_rule->in_port) ||
            ptr_rule->sw_flow.flow.nw_proto == GRE_PROTOCOL )
            && found_tun_pop) {
            VLOG_INFO("External table , tunneling rule\n");
        }
        else {
            ret = hw_pipeline_create_external_rule(dp,ptr_rule,
                    action_mark_flow,ARRAY_SIZE(action_mark_flow),&hw_flow_h);
            dp->ft_pool.ft_data[ptr_rule->sw_flow.cr.flow_tag].hw_flow_h =
                    hw_flow_h;
        }
    }
    else {
    //  the internal header of a tunnel.
        if ((dpif_netdev_vport_is_tunnel(dp, ptr_rule->in_port) ||
           ptr_rule->sw_flow.flow.nw_proto == GRE_PROTOCOL )
           && found_tun_pop) {
            // nested tunnel .
            VLOG_INFO("internal table , tunneling rule\n");
        }
        else
        {
            // No offloading for internal ports which are not tunnel.
            // return Tag to the pool & return.
            VLOG_INFO("free flow_tag:%x\n",ptr_rule->sw_flow.cr.flow_tag);
            if (OVS_UNLIKELY(!hw_pipeline_ft_pool_free(&dp->ft_pool,
                    ptr_rule->sw_flow.cr.flow_tag))) {
                    VLOG_ERR("tag is out of range");
                    return ret;
            }
            return 0;
        }
    }
    if (OVS_UNLIKELY(ret == -1)) {
        VLOG_ERR("create_rule failed to insert rule ");
    }
    return ret;
}

static int hw_pipeline_remove_flow(struct dp_netdev *dp,
                                   msg_hw_flow *ptr_rule)
{
    struct dp_netdev_port *dp_port;
    struct rte_flow_error error;
    int ret=0;
    struct rte_flow *hw_flow_h;

    ret = get_port_by_number(dp, ptr_rule->in_port,&dp_port);
    if (OVS_UNLIKELY(ret)) {
        VLOG_INFO("Can't get pmd port\n");
        return -1;
    }
    hw_flow_h = dp->ft_pool.ft_data[ptr_rule->flow_tag].hw_flow_h;
    ret =rte_flow_destroy(dp_port->port_no,hw_flow_h,&error);
    return ret;
}

void *hw_pipeline_thread(void *pdp)
{
    msg_queue_elem ptr_rule;
    int ret =0;
    struct dp_netdev *dp= (struct dp_netdev *)pdp;
    msg_queue *msgq = &dp->message_queue;

    ptr_rule.mode = HW_PIPELINE_NO_RULE;
    ovsrcu_quiesce_start();
    if (dp->ppl_md.id == HW_OFFLOAD_PIPELINE) {
        VLOG_INFO(" HW_OFFLOAD_PIPELINE is set \n");
    }
    else {
        VLOG_INFO(" HW_OFFLOAD_PIPELINE is off \n");
    }
    while(1) {
        // listen to read_socket :
        // call the rte_flow_create ( flow , wildcard mask)
        ret = hw_pipeline_msg_queue_dequeue(msgq,&ptr_rule);
        if (ret != 0) {
            continue;
        }
        if (ptr_rule.mode == HW_PIPELINE_REMOVE_RULE) {
            ret =hw_pipeline_remove_flow(dp,&ptr_rule.data.rm_flow);
            if (OVS_UNLIKELY(ret)) {
                VLOG_ERR(" hw_pipeline_remove_flow failed to remove flow  \n");
            }
        }
        ptr_rule.mode = HW_PIPELINE_NO_RULE;
    }
    ovsrcu_quiesce_end();
    return NULL;
}
int hw_pipeline_init(struct dp_netdev *dp)
{
    int ret=0;
    static uint32_t id=0;
    VLOG_INFO("hw_pipeline_init\n");
    ret = hw_pipeline_ft_pool_init(&dp->ft_pool,HW_MAX_FLOW_TAG);
    if (OVS_UNLIKELY(ret != 0)) {
        VLOG_ERR(" hw_pipeline_ft_pool_init failed \n");
        return ret;
    }
    ret = hw_pipeline_msg_queue_init(&dp->message_queue,id++);
    if (OVS_UNLIKELY(ret != 0)) {
        VLOG_ERR(" hw_pipeline_msg_queue_init failed \n");
        return ret;
    }
    dp->thread_ofload = ovs_thread_create("ft_offload",hw_pipeline_thread,dp);
    dp->ppl_md.id = HW_OFFLOAD_PIPELINE;
    return 0;
}

int hw_pipeline_uninit(struct dp_netdev *dp)
{
    int ret=0;
    ret = hw_pipeline_ft_pool_uninit(&dp->ft_pool);
    if (OVS_UNLIKELY( ret != 0 )) {
        VLOG_ERR(" hw_pipeline_ft_pool_uninit failed \n");
        return ret;
    }
    ret = hw_pipeline_msg_queue_clear(&dp->message_queue);
    if (OVS_UNLIKELY( ret != 0 )) {
        VLOG_ERR(" hw_pipeline_msg_queue_clear failed \n");
        return ret;
    }
    xpthread_join(dp->thread_ofload, NULL);
    dp->ppl_md.id = DEFAULT_SW_PIPELINE;
    return 0;
}

bool hw_pipeline_dpcls_lookup(struct dp_netdev *dp,
                              struct pipeline_md *md_tags,
                              const size_t cnt,
                              int *lookup_cnt)
{
    int index =0 ;
    struct dp_netdev_flow *netdev_flow = NULL;
    bool all_found = true;
    bool never_lookup = true;

    for (index=0;index<cnt;index++) {
        if (md_tags[index].flow_tag == HW_NO_FREE_FLOW_TAG) {
            continue;
        }
        never_lookup = false;
        netdev_flow = hw_pipeline_lookup_flow(dp,
            md_tags[index].flow_tag,lookup_cnt);
        if (netdev_flow == NULL) {
            VLOG_INFO("flow== NULL && miss_any=true");
            all_found=false;
        }
    }
    if (never_lookup) {
        return false;
    }
    return all_found;
}

/* Insert 'rule' into 'cls'.
 * Get a unique tag from pool
 * The function sends a message to the message queue
 * to insert a rule to HW, but
 * in the context of hw_pipeline_thread
 * */
void
hw_pipeline_dpcls_insert(struct dp_netdev *dp,
                         struct dp_netdev_flow *netdev_flow,
                         struct dpcls_rule *rule,
                         odp_port_t in_port,
                         struct flow *wc_masks,
                         int rxqid)
{
    uint32_t flow_tag=HW_NO_FREE_FLOW_TAG;

    flow_tag = hw_pipeline_ft_pool_get(&dp->ft_pool,netdev_flow);
    if (OVS_UNLIKELY(flow_tag == HW_NO_FREE_FLOW_TAG)) {
        VLOG_INFO("No more free Tags \n");
        return;
    }

    rule->flow_tag = flow_tag;

    if (OVS_UNLIKELY(hw_pipeline_send_insert_flow(dp,in_port,netdev_flow,
        wc_masks,rxqid)== -1)) {
        VLOG_ERR("The Message Queue is FULL \n");
        return;
    }
}

/* Removes 'rule' from 'cls', also distracting the 'rule'.
 * Free the unique tag back to pool.
 * The function sends a message to the message queue
 * to insert a rule to HW, but
 * in the context of hw_pipeline_thread
 * */
void
hw_pipeline_dpcls_remove(struct dp_netdev *dp,
                         struct dpcls_rule *rule)
{
    if (hw_pipeline_send_remove_flow(dp,rule->flow_tag,rule->ufidp)==-1) {
        VLOG_ERR("The Message Queue is FULL \n");
        return;
    }
    if (OVS_LIKELY(hw_pipeline_ft_pool_is_valid(&dp->ft_pool))) {
      if (OVS_UNLIKELY(
            !hw_pipeline_ft_pool_free(&dp->ft_pool,rule->flow_tag))) {
            VLOG_ERR("tag is out of range");
            return;
      }
    }
}

struct dp_netdev_flow *
hw_pipeline_lookup_flow(struct dp_netdev *dp,
                        uint32_t flow_tag,
                        int *lookup_cnt)
{
    struct dp_netdev_flow *netdev_flow=NULL;
    if (OVS_UNLIKELY(flow_tag == HW_NO_FREE_FLOW_TAG)) {
        return NULL;
    }
    netdev_flow = hw_pipeline_read_flow(&dp->ft_pool,flow_tag);
    if (netdev_flow != NULL) {
        if (lookup_cnt != NULL) {
            *lookup_cnt=+1;
        }
    }
    else {
        VLOG_ERR("No flow found : netdev_flow %p for flow_tag %x",
                 netdev_flow,flow_tag);
    }
    return netdev_flow;
}
