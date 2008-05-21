#ifndef DP_DEV_H
#define DP_DEV_H 1

int dp_dev_setup(struct datapath *);
void dp_dev_destroy(struct datapath *);
int dp_dev_recv(struct net_device *, struct sk_buff *);
int is_dp_dev(struct net_device *);

#endif /* dp_dev.h */
