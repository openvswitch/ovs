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

#include "dpif-netdev.h"
#include "include/openvswitch/vlog.h"
#include "hw-pipeline.h"
          
VLOG_DEFINE_THIS_MODULE(hw_pipeline);

// Internal functions Flow Tags Pool

uint32_t hw_pipeline_ft_pool_init(flow_tag_pool *p,uint32_t pool_size);
// Internal functions Message Queue

static int hw_pipeline_msg_queue_init(msg_queue *message_queue,
                                      unsigned core_id);

void *hw_pipeline_thread(void *pdp);

uint32_t hw_pipeline_ft_pool_init(flow_tag_pool *p,
                                  uint32_t pool_size)
{
    uint32_t ii=0;

    if(OVS_UNLIKELY(pool_size > HW_MAX_FLOW_TAG || p == NULL ))
    {
        VLOG_ERR("pool size is too big or pool is NULL \n");
        return -1;
    }

    p->ft_data = (flow_elem *)xmalloc(pool_size * sizeof(flow_elem));
    if( OVS_UNLIKELY(p->ft_data == NULL))
    {
        VLOG_ERR("No free memory for the pool \n");
        return -1;
    }
    memset(p->ft_data,0,(pool_size * sizeof(flow_elem)));

    rte_spinlock_init(&p->lock);

    rte_spinlock_lock(&p->lock);
    p->head=0;
    p->tail=0;
    p->pool_size = pool_size;
    for(ii=0;ii<pool_size;ii++)
    {
        p->ft_data[ii].next = ii+1;
        rte_spinlock_init(&p->ft_data[ii].lock);
    }

    p->ft_data[pool_size-1].next = HW_NO_FREE_FLOW_TAG;
    rte_spinlock_unlock(&p->lock);
    return 0;
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

    if (mkdir(dir, 0755) == -1 && errno != EEXIST)
    {
        VLOG_ERR("Failed to create directory: ");
        return -1;
    }

    ret = mkfifo(fifo_pmd,0666);
    if (OVS_UNLIKELY(ret < 0)) {
        if(errno==EEXIST){
            ret = unlink(fifo_pmd);
            if (OVS_UNLIKELY(ret < 0)) {
                VLOG_ERR("Remove fifo failed .\n");
                return -1;
            }
            ret = mkfifo(fifo_pmd,0666 );
            if (OVS_UNLIKELY(ret < 0)) {
                if(errno==EEXIST){
                    VLOG_ERR("That file already exists.\n");
                    VLOG_ERR("(or we passed in a symbolic link,");
                    VLOG_ERR(" which we did not.)\n");
                    return -1;
                }
            }
        }
        else if(errno==EROFS){
            VLOG_ERR("The name file resides on a read-only file-system\n");
            return -1;
        }
        else
        {
            VLOG_ERR("mkfifo failed %x \n",errno);
            return -1;
        }
    }

    message_queue->readFd  = open(message_queue->pipeName,
            O_RDONLY|O_NONBLOCK);
    if(OVS_UNLIKELY(message_queue->readFd == -1))
    {
        VLOG_ERR("Error creating read file descriptor");
        return -1;
    }
    message_queue->writeFd = open(message_queue->pipeName,
            O_WRONLY|O_NONBLOCK);
    if(OVS_UNLIKELY(message_queue->writeFd == -1))
    {
        VLOG_ERR("Error creating write file descriptor");
        return -1;
    }
    return 0;
}

void *hw_pipeline_thread(void *pdp)
{
    struct dp_netdev *dp= (struct dp_netdev *)pdp;    
    ovsrcu_quiesce_start();
    
    if( dp->ppl_md.id == HW_OFFLOAD_PIPELINE){
        VLOG_INFO(" HW_OFFLOAD_PIPELINE is set \n");
    }
    else{
        VLOG_INFO(" HW_OFFLOAD_PIPELINE is off \n");
    }
    while(1) {
        // listen to read_socket :
        // call the rte_flow_create ( flow , wildcard mask)
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
    if(OVS_UNLIKELY(ret != 0))
    {
        VLOG_ERR(" hw_pipeline_ft_pool_init failed \n");
        return ret;
    }
    ret = hw_pipeline_msg_queue_init(&dp->message_queue,id++);
    if(OVS_UNLIKELY(ret != 0))
    {
        VLOG_ERR(" hw_pipeline_msg_queue_init failed \n");
        return ret;
    }
    dp->thread_ofload = ovs_thread_create("ft_offload",hw_pipeline_thread,dp);
    dp->ppl_md.id = HW_OFFLOAD_PIPELINE;

    return 0;
}
