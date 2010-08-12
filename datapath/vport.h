/*
 * Copyright (c) 2010 Nicira Networks.
 * Distributed under the terms of the GNU GPL version 2.
 *
 * Significant portions of this file may be copied from parts of the Linux
 * kernel, by Linus Torvalds and others.
 */

#ifndef VPORT_H
#define VPORT_H 1

#include <linux/list.h>
#include <linux/seqlock.h>
#include <linux/skbuff.h>
#include <linux/spinlock.h>

#include "datapath.h"
#include "openvswitch/datapath-protocol.h"
#include "odp-compat.h"

struct vport;
struct dp_port;

/* The following definitions are for users of the vport subsytem: */

int vport_user_add(const struct odp_vport_add __user *);
int vport_user_mod(const struct odp_vport_mod __user *);
int vport_user_del(const char __user *udevname);

#ifdef CONFIG_COMPAT
int compat_vport_user_add(struct compat_odp_vport_add __user *);
int compat_vport_user_mod(struct compat_odp_vport_mod __user *);
#endif

int vport_user_stats_get(struct odp_vport_stats_req __user *);
int vport_user_stats_set(struct odp_vport_stats_req __user *);
int vport_user_ether_get(struct odp_vport_ether __user *);
int vport_user_ether_set(struct odp_vport_ether __user *);
int vport_user_mtu_get(struct odp_vport_mtu __user *);
int vport_user_mtu_set(struct odp_vport_mtu __user *);

void vport_lock(void);
void vport_unlock(void);

int vport_init(void);
void vport_exit(void);

struct vport *vport_add(const char *name, const char *type, const void __user *config);
int vport_mod(struct vport *, const void __user *config);
int vport_del(struct vport *);

struct vport *vport_locate(const char *name);

int vport_attach(struct vport *, struct dp_port *);
int vport_detach(struct vport *);

int vport_set_mtu(struct vport *, int mtu);
int vport_set_addr(struct vport *, const unsigned char *);
int vport_set_stats(struct vport *, struct odp_vport_stats *);

const char *vport_get_name(const struct vport *);
const char *vport_get_type(const struct vport *);
const unsigned char *vport_get_addr(const struct vport *);

struct dp_port *vport_get_dp_port(const struct vport *);
struct kobject *vport_get_kobj(const struct vport *);
int vport_get_stats(struct vport *, struct odp_vport_stats *);

unsigned vport_get_flags(const struct vport *);
int vport_is_running(const struct vport *);
unsigned char vport_get_operstate(const struct vport *);

int vport_get_ifindex(const struct vport *);
int vport_get_iflink(const struct vport *);

int vport_get_mtu(const struct vport *);

int vport_send(struct vport *, struct sk_buff *);

/* The following definitions are for implementers of vport devices: */

struct vport_percpu_stats {
	u64 rx_bytes;
	u64 rx_packets;
	u64 tx_bytes;
	u64 tx_packets;
	seqcount_t seqlock;
};

struct vport_err_stats {
	u64 rx_dropped;
	u64 rx_errors;
	u64 rx_frame_err;
	u64 rx_over_err;
	u64 rx_crc_err;
	u64 tx_dropped;
	u64 tx_errors;
	u64 collisions;
};

struct vport {
	struct hlist_node hash_node;
	const struct vport_ops *ops;
	struct dp_port *dp_port;

	struct vport_percpu_stats *percpu_stats;

	spinlock_t stats_lock;
	struct vport_err_stats err_stats;
	struct odp_vport_stats offset_stats;
};

#define VPORT_F_REQUIRED	(1 << 0) /* If init fails, module loading fails. */
#define VPORT_F_GEN_STATS	(1 << 1) /* Track stats at the generic layer. */
#define VPORT_F_TUN_ID		(1 << 2) /* Sets OVS_CB(skb)->tun_id. */

/**
 * struct vport_ops - definition of a type of virtual port
 *
 * @type: Name of port type, such as "netdev" or "internal" to be matched
 * against the device type when a new port needs to be created.
 * @flags: Flags of type VPORT_F_* that influence how the generic vport layer
 * handles this vport.
 * @init: Called at module initialization.  If VPORT_F_REQUIRED is set then the
 * failure of this function will cause the module to not load.  If the flag is
 * not set and initialzation fails then no vports of this type can be created.
 * @exit: Called at module unload.
 * @create: Create a new vport called 'name' with vport type specific
 * configuration 'config' (which must be copied from userspace before use).  On
 * success must allocate a new vport using vport_alloc().
 * @modify: Modify the configuration of an existing vport.  May be null if
 * modification is not supported.
 * @destroy: Destroy and free a vport using vport_free().  Prior to destruction
 * @detach will be called followed by synchronize_rcu().
 * @attach: Attach a previously created vport to a datapath.  After attachment
 * packets may be sent and received.  Prior to attachment any packets may be
 * silently discarded.  May be null if not needed.
 * @detach: Detach a vport from a datapath.  May be null if not needed.
 * @set_mtu: Set the device's MTU.  May be null if not supported.
 * @set_addr: Set the device's MAC address.  May be null if not supported.
 * @set_stats: Provides stats as an offset to be added to the device stats.
 * May be null if not supported.
 * @get_name: Get the device's name.
 * @get_addr: Get the device's MAC address.
 * @get_kobj: Get the kobj associated with the device (may return null).
 * @get_stats: Fill in the transmit/receive stats.  May be null if stats are
 * not supported or if generic stats are in use.  If defined and
 * VPORT_F_GEN_STATS is also set, the error stats are added to those already
 * collected.
 * @get_dev_flags: Get the device's flags.
 * @is_running: Checks whether the device is running.
 * @get_operstate: Get the device's operating state.
 * @get_ifindex: Get the system interface index associated with the device.
 * May be null if the device does not have an ifindex.
 * @get_iflink: Get the system interface index associated with the device that
 * will be used to send packets (may be different than ifindex for tunnels).
 * May be null if the device does not have an iflink.
 * @get_mtu: Get the device's MTU.
 * @send: Send a packet on the device.  Returns the length of the packet sent.
 */
struct vport_ops {
	const char *type;
	u32 flags;

	/* Called at module init and exit respectively. */
	int (*init)(void);
	void (*exit)(void);

	/* Called with RTNL lock. */
	struct vport *(*create)(const char *name, const void __user *config);
	int (*modify)(struct vport *, const void __user *config);
	int (*destroy)(struct vport *);

	int (*attach)(struct vport *);
	int (*detach)(struct vport *);

	int (*set_mtu)(struct vport *, int mtu);
	int (*set_addr)(struct vport *, const unsigned char *);
	int (*set_stats)(const struct vport *, struct odp_vport_stats *);

	/* Called with rcu_read_lock or RTNL lock. */
	const char *(*get_name)(const struct vport *);
	const unsigned char *(*get_addr)(const struct vport *);
	struct kobject *(*get_kobj)(const struct vport *);
	int (*get_stats)(const struct vport *, struct odp_vport_stats *);

	unsigned (*get_dev_flags)(const struct vport *);
	int (*is_running)(const struct vport *);
	unsigned char (*get_operstate)(const struct vport *);

	int (*get_ifindex)(const struct vport *);
	int (*get_iflink)(const struct vport *);

	int (*get_mtu)(const struct vport *);

	int (*send)(struct vport *, struct sk_buff *);
};

enum vport_err_type {
	VPORT_E_RX_DROPPED,
	VPORT_E_RX_ERROR,
	VPORT_E_RX_FRAME,
	VPORT_E_RX_OVER,
	VPORT_E_RX_CRC,
	VPORT_E_TX_DROPPED,
	VPORT_E_TX_ERROR,
	VPORT_E_COLLISION,
};

struct vport *vport_alloc(int priv_size, const struct vport_ops *);
void vport_free(struct vport *);

#define VPORT_ALIGN 8

/**
 *	vport_priv - access private data area of vport
 *
 * @vport: vport to access
 *
 * If a nonzero size was passed in priv_size of vport_alloc() a private data
 * area was allocated on creation.  This allows that area to be accessed and
 * used for any purpose needed by the vport implementer.
 */
static inline void *vport_priv(const struct vport *vport)
{
	return (u8 *)vport + ALIGN(sizeof(struct vport), VPORT_ALIGN);
}

/**
 *	vport_from_priv - lookup vport from private data pointer
 *
 * @priv: Start of private data area.
 *
 * It is sometimes useful to translate from a pointer to the private data
 * area to the vport, such as in the case where the private data pointer is
 * the result of a hash table lookup.  @priv must point to the start of the
 * private data area.
 */
static inline struct vport *vport_from_priv(const void *priv)
{
	return (struct vport *)(priv - ALIGN(sizeof(struct vport), VPORT_ALIGN));
}

void vport_receive(struct vport *, struct sk_buff *);
void vport_record_error(struct vport *, enum vport_err_type err_type);

/* List of statically compiled vport implementations.  Don't forget to also
 * add yours to the list at the top of vport.c. */
extern struct vport_ops netdev_vport_ops;
extern struct vport_ops internal_vport_ops;
extern struct vport_ops patch_vport_ops;
extern struct vport_ops gre_vport_ops;
extern struct vport_ops capwap_vport_ops;

#endif /* vport.h */
