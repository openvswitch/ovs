#ifndef DP_DEV_H
#define DP_DEV_H 1

struct dp_dev {
	struct datapath *dp;
	int port_no;

	struct net_device *dev;
	struct net_device_stats stats;
	struct sk_buff_head xmit_queue;
	struct work_struct xmit_work;

	struct list_head list;
};

static inline struct dp_dev *dp_dev_priv(struct net_device *netdev)
{
	return netdev_priv(netdev);
}

struct net_device *dp_dev_create(struct datapath *, const char *, int port_no);
void dp_dev_destroy(struct net_device *);
int dp_dev_recv(struct net_device *, struct sk_buff *);
int is_dp_dev(struct net_device *);
struct datapath *dp_dev_get_dp(struct net_device *);

#endif /* dp_dev.h */
