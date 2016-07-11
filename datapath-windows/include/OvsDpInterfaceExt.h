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

#define OVS_IOCTL_START   0x100
/* We used Direct I/O (zero copy) for the buffers. */
/* Non-Netlink-based IOCTLs. */
#define OVS_IOCTL_GET_PID \
    CTL_CODE (OVS_IOCTL_DEVICE_TYPE, OVS_IOCTL_START + 0x0, METHOD_BUFFERED,\
              FILE_WRITE_ACCESS)
/* Netlink-based IOCTLs. */
#define OVS_IOCTL_READ \
    CTL_CODE (OVS_IOCTL_DEVICE_TYPE, OVS_IOCTL_START + 0x1, METHOD_OUT_DIRECT,\
              FILE_READ_ACCESS)
#define OVS_IOCTL_READ_EVENT \
    CTL_CODE (OVS_IOCTL_DEVICE_TYPE, OVS_IOCTL_START + 0x2, METHOD_OUT_DIRECT, \
              FILE_READ_ACCESS)
#define OVS_IOCTL_READ_PACKET \
    CTL_CODE (OVS_IOCTL_DEVICE_TYPE, OVS_IOCTL_START + 0x3, METHOD_OUT_DIRECT, \
              FILE_READ_ACCESS)
#define OVS_IOCTL_WRITE \
    CTL_CODE (OVS_IOCTL_DEVICE_TYPE, OVS_IOCTL_START + 0x4, METHOD_IN_DIRECT,\
              FILE_READ_ACCESS)
#define OVS_IOCTL_TRANSACT \
    CTL_CODE (OVS_IOCTL_DEVICE_TYPE, OVS_IOCTL_START + 0x5, METHOD_OUT_DIRECT,\
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
#define OVS_WIN_NL_NETDEV_FAMILY_ID          (NLMSG_MIN_TYPE + 6)
/*
 * Conntrack Family is defined in OvsDpInterfaceCtExt.h
 * OVS_WIN_NL_CT_FAMILY_ID is not used in the messages, but used internally
 * in the kernel as a placeholder to enable parsing out the ct family cmds.
 */

#define OVS_WIN_NL_CT_FAMILY_ID              (NLMSG_MIN_TYPE + 7)

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

/* Commands available under the OVS_WIN_CONTROL_FAMILY. */
enum ovs_win_control_cmd {
    OVS_CTRL_CMD_WIN_PEND_REQ,
    OVS_CTRL_CMD_WIN_PEND_PACKET_REQ,
    OVS_CTRL_CMD_MC_SUBSCRIBE_REQ,
    OVS_CTRL_CMD_PACKET_SUBSCRIBE_REQ,

    /* This command logically belongs to the Vport family */
    OVS_CTRL_CMD_EVENT_NOTIFY,
    OVS_CTRL_CMD_READ_NOTIFY,

    /* Used for Socket property */
    OVS_CTRL_CMD_SOCK_PROP
};

/* NL Attributes for joining/unjoining an MC group */
enum ovs_nl_mcast_attr {
    OVS_NL_ATTR_MCAST_GRP,        /* (UINT32) Join an MC group */
    OVS_NL_ATTR_MCAST_JOIN,       /* (UINT8) 1/0 - Join/Unjoin */
    OVS_NL_ATTR_PACKET_SUBSCRIBE, /* (UNINT8): 1/0 - subscribe/unsubscribe */
    OVS_NL_ATTR_PACKET_PID,       /* (UNINT32) netlink PID to receive upcalls */
    __OVS_NL_ATTR_CTRL_MAX
};
#define OVS_WIN_CONTROL_ATTR_MAX (__OVS_NL_ATTR_CTRL_MAX - 1)

/*
 * Netdev family of commands specific to Windows.
 */
#define OVS_WIN_NETDEV_FAMILY   "ovs_win_netdev"
#define OVS_WIN_NETDEV_MCGROUP  "ovs_win_netdev"
#define OVS_WIN_NETDEV_VERSION  1

enum ovs_win_netdev_cmd {
    OVS_WIN_NETDEV_CMD_UNSPEC,
    OVS_WIN_NETDEV_CMD_GET,     /* information about the netdev. */
};

/**
 * For every vport on the datapath, there is a corresponding netdev.  General
 * network device attributes of a vport that are not specific to OVS, such as
 * MTU are represented using a netdev.  For convenience, some of the vport
 * attributes are also included as netdev attributes.
 *
 * enum ovs_win_netdev_attr - attributes for %OVS_WIN_NETDEV_* commands.
 * @OVS_WIN_NETDEV_ATTR_PORT_NO: 32-bit port number of the vport within the
 * datapath.
 * @OVS_WIN_NETDEV_ATTR_TYPE: 32-bit %OVS_VPORT_TYPE_* constant describing
 * the type of vport.
 * @OVS_WIN_NETDEV_ATTR_NAME: Name of vport.  Maximum length %IFNAMSIZ-1 bytes
 * plus a null terminator.
 * @OVS_WIN_NETDEV_ATTR_MAC_ADDR: MAC address of the vport.  %ETH_ADDR_LEN bytes
 * long.
 * @OVS_WIN_NETDEV_ATTR_MTU : 32-bit MTU of the vport.
 * @OVS_WIN_NETDEV_ATTR_IF_FLAGS: 32-bit %OVS_WIN_NETDEV_IFF_* interface flags
 * of the vport.
 *
 * These attributes follow the &struct ovs_header within the Generic Netlink
 * payload for %OVS_WIN_NETDEV_* commands.
 *
 * For all requests, if %OVS_WIN_NETDEV_ATTR_NAME is specified then it is used
 * to look up the netdev to operate on; dp_idx from the &struct
 * ovs_header is not relevant for the look up.
 */
enum ovs_win_netdev_attr {
    OVS_WIN_NETDEV_ATTR_UNSPEC,
    OVS_WIN_NETDEV_ATTR_PORT_NO,     /* u32 port number within datapath. */
    OVS_WIN_NETDEV_ATTR_TYPE,        /* u32 OVS_NETDEV_TYPE_* constant. */
    OVS_WIN_NETDEV_ATTR_NAME,        /* string name, up to IFNAMSIZ bytes long. */
    OVS_WIN_NETDEV_ATTR_MAC_ADDR,    /* MAC address of the vport. */
    OVS_WIN_NETDEV_ATTR_MTU,         /* MTU of the vport. */
    OVS_WIN_NETDEV_ATTR_IF_FLAGS,    /* Interface flags o the vport. */
    __OVS_WIN_NETDEV_ATTR_MAX
};
#define OVS_WIN_NETDEV_ATTR_MAX (__OVS_WIN_NETDEV_ATTR_MAX - 1)

#define OVS_WIN_NETDEV_IFF_UP                   (1 << 0)
#define OVS_WIN_NETDEV_IFF_PROMISC              (1 << 1)

typedef struct ovs_dp_stats OVS_DP_STATS;
typedef enum ovs_vport_type OVS_VPORT_TYPE;

/* NL Attributes for setting socket attributes */
enum ovs_nl_sock_attr {
    /* (UINT32) Netlink Protocol set in Userspace and read in Kernel */
    OVS_NL_ATTR_SOCK_PROTO,
    /* (UINT32) Instance PID set in Kernel and read in Userspace */
    OVS_NL_ATTR_SOCK_PID,
    __OVS_NL_ATTR_SOCK_MAX
};
#define OVS_WIN_SOCK_ATTR_MAX (__OVS_NL_ATTR_SOCK_MAX - 1)

#endif /* __OVS_DP_INTERFACE_EXT_H_ */
