/*
 * Copyright (c) 2012 Ed Maste. All rights reserved.
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

#include "route-table.h"

#include <sys/socket.h>
#include <sys/types.h>

#include <net/if.h>
#include <net/route.h>
#include <net/if_dl.h>
#include <netinet/in.h>

#include <string.h>
#include <unistd.h>

#include "util.h"

static int pid;
static unsigned int register_count = 0;

bool
route_table_get_name(ovs_be32 ip, char name[IFNAMSIZ])
{
    struct {
        struct rt_msghdr rtm;
        char space[512];
    } rtmsg;

    struct rt_msghdr *rtm = &rtmsg.rtm;
    struct sockaddr_dl *ifp = NULL;
    struct sockaddr_in *sin;
    struct sockaddr *sa;
    static int seq;
    int i, len, namelen, rtsock;

    rtsock = socket(PF_ROUTE, SOCK_RAW, 0);
    if (rtsock < 0)
        return false;

    memset(&rtmsg, 0, sizeof(rtmsg));

    rtm->rtm_msglen = sizeof(struct rt_msghdr) + sizeof(struct sockaddr_in);
    rtm->rtm_version = RTM_VERSION;
    rtm->rtm_type = RTM_GET;
    rtm->rtm_addrs = RTA_DST | RTA_IFP;
    rtm->rtm_seq = ++seq;

    sin = (struct sockaddr_in *)(rtm + 1);
    sin->sin_len = len = sizeof(struct sockaddr_in);
    sin->sin_family = AF_INET;
    sin->sin_addr.s_addr = ip;

    if ((write(rtsock, (char *)&rtmsg, rtm->rtm_msglen)) < 0) {
        close(rtsock);
        return false;
    }

    do {
        len = read(rtsock, (char *)&rtmsg, sizeof(rtmsg));
    } while (len > 0 && (rtmsg.rtm.rtm_seq != seq ||
        rtmsg.rtm.rtm_pid != pid));

    close(rtsock);

    if (len < 0) {
        return false;
    }

    sa = (struct sockaddr *)(rtm + 1);
    for (i = 1; i; i <<= 1) {
        if (rtm->rtm_addrs & i) {
            if (i == RTA_IFP && sa->sa_family == AF_LINK &&
              ALIGNED_CAST(struct sockaddr_dl *, sa)->sdl_nlen) {
                ifp = ALIGNED_CAST(struct sockaddr_dl *, sa);
                namelen = ifp->sdl_nlen;
                if (namelen > IFNAMSIZ - 1)
                    namelen = IFNAMSIZ - 1;
                memcpy(name, ifp->sdl_data, namelen);
                name[namelen] = '\0';
                return true;
            }
#if defined(__FreeBSD__)
            sa = (struct sockaddr *)((char *)sa + SA_SIZE(sa));
#elif defined(__NetBSD__)
            sa = (struct sockaddr *)((char *)sa + RT_ROUNDUP(sa->sa_len));
#else
#error unimplemented
#endif
        }
    }
    return false;
}

uint64_t
route_table_get_change_seq(void)
{
    return 0;
}

void
route_table_register(void)
{
    if (!register_count)
    {
        pid = getpid();
    }

    register_count++;
}

void
route_table_unregister(void)
{
    register_count--;
}

void
route_table_run(void)
{
}

void
route_table_wait(void)
{
}
