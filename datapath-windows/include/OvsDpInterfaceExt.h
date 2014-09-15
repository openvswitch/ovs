/*
 * Copyright (c) 2014 VMware, Inc.
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

#ifndef __OVS_DP_INTERFACE_EXT_H_
#define __OVS_DP_INTERFACE_EXT_H_ 1

/* Windows kernel datapath extensions to the standard datapath interface. */

/* Version number of the datapath interface extensions. */
#define OVS_DATAPATH_EXT_VERSION 1

/* Name of the device. */
#define OVS_DEVICE_NAME_NT     L"\\Device\\OpenvSwitchDevice"
#define OVS_DEVICE_NAME_DOS    L"\\DosDevices\\OpenvSwitchDevice"
#define OVS_DEVICE_NAME_USER   TEXT("\\\\.\\OpenvSwitchDevice")

#define OVS_IOCTL_DEVICE_TYPE 45000

/* We used Direct I/O (zero copy) for the buffers. */
#define OVS_IOCTL_START   0x100
#define OVS_IOCTL_READ \
    CTL_CODE (OVS_IOCTL_DEVICE_TYPE, OVS_IOCTL_START + 0x0, METHOD_OUT_DIRECT,\
              FILE_READ_ACCESS)
#define OVS_IOCTL_WRITE \
    CTL_CODE (OVS_IOCTL_DEVICE_TYPE, OVS_IOCTL_START + 0x1, METHOD_IN_DIRECT,\
              FILE_READ_ACCESS)
#define OVS_IOCTL_TRANSACT \
    CTL_CODE (OVS_IOCTL_DEVICE_TYPE, OVS_IOCTL_START + 0x2, METHOD_OUT_DIRECT,\
              FILE_WRITE_ACCESS)

/*
 * On platforms that support netlink natively, the operating system assigns a
 * dynamic value to a netlink family when it is registered. In the absense of
 * such mechanism, defined hard-coded values that are known both to userspace
 * and kernel.
 */
#define OVS_WIN_NL_INVALID_FAMILY_ID         0
#define OVS_WIN_NL_CTRL_FAMILY_ID            (NLMSG_MIN_TYPE + 1)
#define OVS_WIN_NL_DATAPATH_FAMILY_ID        (NLMSG_MIN_TYPE + 2)
#define OVS_WIN_NL_PACKET_FAMILY_ID          (NLMSG_MIN_TYPE + 3)
#define OVS_WIN_NL_VPORT_FAMILY_ID           (NLMSG_MIN_TYPE + 4)
#define OVS_WIN_NL_FLOW_FAMILY_ID            (NLMSG_MIN_TYPE + 5)

#define OVS_WIN_NL_INVALID_MCGRP_ID          0
#define OVS_WIN_NL_MCGRP_START_ID            100
#define OVS_WIN_NL_VPORT_MCGRP_ID            (OVS_WIN_NL_MCGRP_START_ID + 1)

/*
 * Define a family of netlink command specific to Windows. This is part of the
 * extensions.
 */
#define OVS_WIN_CONTROL_FAMILY   "ovs_win_control"
#define OVS_WIN_CONTROL_MCGROUP  "ovs_win_control"
#define OVS_WIN_CONTROL_VERSION  1
#define OVS_WIN_CONTROL_ATTR_MAX (__OVS_FLOW_ATTR_MAX - 1)

/* Commands available under the OVS_WIN_CONTROL_FAMILY. */
enum ovs_win_control_cmd {
    OVS_CTRL_CMD_WIN_GET_PID,
    OVS_CTRL_CMD_WIN_PEND_REQ,
    OVS_CTRL_CMD_MC_SUBSCRIBE_REQ,
};

/* NL Attributes for joining/unjoining an MC group */
enum ovs_nl_mcast_attr {
    OVS_NL_ATTR_MCAST_GRP,   /* (UINT32) Join an MC group */
    OVS_NL_ATTR_MCAST_JOIN,  /* (UINT8) 1/0 - Join/Unjoin */
};

typedef struct ovs_dp_stats OVS_DP_STATS;

#endif /* __OVS_DP_INTERFACE_EXT_H_ */
