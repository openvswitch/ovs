/*
 * Copyright (c) 2010, 2011 Nicira Networks.
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

struct vport;
struct vport_parms;

/* The following definitions are for users of the vport subsytem: */

int vport_init(void);
void vport_exit(void);

struct vport *vport_add(const struct vport_parms *);
int vport_del(struct vport *);

struct vport *vport_locate(const char *name);

int vport_set_mtu(struct vport *, int mtu);
int vport_set_addr(struct vport *, const unsigned char *);
int vport_set_stats(struct vport *, struct rtnl_link_stats64 *);

const char *vport_get_name(const struct vport *);
enum odp_vport_type vport_get_type(const struct vport *);
const unsigned char *vport_get_addr(const struct vport *);

struct kobject *vport_get_kobj(const struct vport *);
int vport_get_stats(struct vport *, struct rtnl_link_stats64 *);

unsigned vport_get_flags(const struct vport *);
int vport_is_running(const struct vport *);
unsigned char vport_get_operstate(const struct vport *);

int vport_get_ifindex(const struct vport *);
int vport_get_iflink(const struct vport *);

int vport_get_mtu(const struct vport *);

int vport_set_options(struct vport *, struct nlattr *options);
int vport_get_options(const struct vport *, struct sk_buff *);

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
	u64 tx_dropped;
	u64 tx_errors;
};

/**
 * struct vport - one port within a datapath
 * @rcu: RCU callback head for deferred destruction.
 * @port_no: Index into @dp's @ports array.
 * @dp: Datapath to which this port belongs.
 * @kobj: Represents /sys/class/net/<devname>/brport.
 * @linkname: The name of the link from /sys/class/net/<datapath>/brif to this
 * &struct vport.  (We keep this around so that we can delete it if the
 * device gets renamed.)  Set to the null string when no link exists.
 * @node: Element in @dp's @port_list.
 * @sflow_pool: Number of packets that were candidates for sFlow sampling,
 * regardless of whether they were actually chosen and sent down to userspace.
 * @hash_node: Element in @dev_table hash table in vport.c.
 * @ops: Class structure.
 * @percpu_stats: Points to per-CPU statistics used and maintained by the vport
 * code if %VPORT_F_GEN_STATS is set to 1 in @ops flags, otherwise unused.
 * @stats_lock: Protects @err_stats and @offset_stats.
 * @err_stats: Points to error statistics used and maintained by the vport code
 * if %VPORT_F_GEN_STATS is set to 1 in @ops flags, otherwise unused.
 * @offset_stats: Added to actual statistics as a sop to compatibility with
 * XAPI for Citrix XenServer.  Deprecated.
 */
struct vport {
	struct rcu_head rcu;
	u16 port_no;
	struct datapath	*dp;
	struct kobject kobj;
	char linkname[IFNAMSIZ];
	struct list_head node;
	atomic_t sflow_pool;

	struct hlist_node hash_node;
	const struct vport_ops *ops;

	struct vport_percpu_stats __percpu *percpu_stats;

	spinlock_t stats_lock;
	struct vport_err_stats err_stats;
	struct rtnl_link_stats64 offset_stats;
};

#define VPORT_F_REQUIRED	(1 << 0) /* If init fails, module loading fails. */
#define VPORT_F_GEN_STATS	(1 << 1) /* Track stats at the generic layer. */
#define VPORT_F_FLOW		(1 << 2) /* Sets OVS_CB(skb)->flow. */
#define VPORT_F_TUN_ID		(1 << 3) /* Sets OVS_CB(skb)->tun_id. */

/**
 * struct vport_parms - parameters for creating a new vport
 *
 * @name: New vport's name.
 * @type: New vport's type.
 * @options: %ODP_VPORT_ATTR_OPTIONS attribute from Netlink message, %NULL if
 * none was supplied.
 * @dp: New vport's datapath.
 * @port_no: New vport's port number.
 */
struct vport_parms {
	const char *name;
	enum odp_vport_type type;
	struct nlattr *options;

	/* For vport_alloc(). */
	struct datapath *dp;
	u16 port_no;
};

/**
 * struct vport_ops - definition of a type of virtual port
 *
 * @type: %ODP_VPORT_TYPE_* value for this type of virtual port.
 * @flags: Flags of type VPORT_F_* that influence how the generic vport layer
 * handles this vport.
 * @init: Called at module initialization.  If VPORT_F_REQUIRED is set then the
 * failure of this function will cause the module to not load.  If the flag is
 * not set and initialzation fails then no vports of this type can be created.
 * @exit: Called at module unload.
 * @create: Create a new vport configured as specified.  On success returns
 * a new vport allocated with vport_alloc(), otherwise an ERR_PTR() value.
 * @destroy: Destroys a vport.  Must call vport_free() on the vport but not
 * before an RCU grace period has elapsed.
 * @set_options: Modify the configuration of an existing vport.  May be %NULL
 * if modification is not supported.
 * @get_options: Appends vport-specific attributes for the configuration of an
 * existing vport to a &struct sk_buff.  May be %NULL for a vport that does not
 * have any configuration.
 * @set_mtu: Set the device's MTU.  May be null if not supported.
 * @set_addr: Set the device's MAC address.  May be null if not supported.
 * @get_name: Get the device's name.
 * @get_addr: Get the device's MAC address.
 * @get_config: Get the device's configuration.
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
 * @get_mtu: Get the device's MTU.  May be %NULL if the device does not have an
 * MTU (as e.g. some tunnels do not).
 * @send: Send a packet on the device.  Returns the length of the packet sent.
 */
struct vport_ops {
	enum odp_vport_type type;
	u32 flags;

	/* Called at module init and exit respectively. */
	int (*init)(void);
	void (*exit)(void);

	/* Called with RTNL lock. */
	struct vport *(*create)(const struct vport_parms *);
	int (*destroy)(struct vport *);

	int (*set_options)(struct vport *, struct nlattr *);
	int (*get_options)(const struct vport *, struct sk_buff *);

	int (*set_mtu)(struct vport *, int mtu);
	int (*set_addr)(struct vport *, const unsigned char *);

	/* Called with rcu_read_lock or RTNL lock. */
	const char *(*get_name)(const struct vport *);
	const unsigned char *(*get_addr)(const struct vport *);
	void (*get_config)(const struct vport *, void *);
	struct kobject *(*get_kobj)(const struct vport *);
	int (*get_stats)(const struct vport *, struct rtnl_link_stats64 *);

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
	VPORT_E_TX_DROPPED,
	VPORT_E_TX_ERROR,
};

struct vport *vport_alloc(int priv_size, const struct vport_ops *, const struct vport_parms *);
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
extern const struct vport_ops netdev_vport_ops;
extern const struct vport_ops internal_vport_ops;
extern const struct vport_ops patch_vport_ops;
extern const struct vport_ops gre_vport_ops;
extern const struct vport_ops capwap_vport_ops;

#endif /* vport.h */
