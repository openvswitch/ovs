#include <linux/kernel.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/rcupdate.h>
#include <linux/skbuff.h>
#include <linux/workqueue.h>
#include <linux/dmi.h>

#include "datapath.h"
#include "forward.h"

struct dp_dev {
	struct net_device_stats stats;
	struct datapath *dp;
	struct sk_buff_head xmit_queue;
	struct work_struct xmit_work;
};


static struct dp_dev *dp_dev_priv(struct net_device *netdev) 
{
	return netdev_priv(netdev);
}

static struct net_device_stats *dp_dev_get_stats(struct net_device *netdev)
{
	struct dp_dev *dp_dev = dp_dev_priv(netdev);
	return &dp_dev->stats;
}

int dp_dev_recv(struct net_device *netdev, struct sk_buff *skb) 
{
	int len = skb->len;
	struct dp_dev *dp_dev = dp_dev_priv(netdev);
	skb->dev = netdev;
	skb->pkt_type = PACKET_HOST;
	skb->protocol = eth_type_trans(skb, netdev);
	if (in_interrupt())
		netif_rx(skb);
	else
		netif_rx_ni(skb);
	netdev->last_rx = jiffies;
	dp_dev->stats.rx_packets++;
	dp_dev->stats.rx_bytes += len;
	return len;
}

static int dp_dev_mac_addr(struct net_device *dev, void *p)
{
	struct sockaddr *addr = p;

	if (netif_running(dev))
		return -EBUSY;
	if (!is_valid_ether_addr(addr->sa_data))
		return -EADDRNOTAVAIL;
	memcpy(dev->dev_addr, addr->sa_data, dev->addr_len);
	return 0;
}

static int dp_dev_xmit(struct sk_buff *skb, struct net_device *netdev)
{
	struct dp_dev *dp_dev = dp_dev_priv(netdev);
	struct datapath *dp = dp_dev->dp;

	/* By orphaning 'skb' we will screw up socket accounting slightly, but
	 * the effect is limited to the device queue length.  If we don't
	 * do this, then the sk_buff will be destructed eventually, but it is
	 * harder to predict when. */
	skb_orphan(skb);

	/* We are going to modify 'skb', by sticking it on &dp_dev->xmit_queue,
	 * so we need to have our own clone.  (At any rate, fwd_port_input()
	 * will need its own clone, so there's no benefit to queuing any other
	 * way.) */
	skb = skb_share_check(skb, GFP_ATOMIC);
	if (!skb)
		return 0;

	dp_dev->stats.tx_packets++;
	dp_dev->stats.tx_bytes += skb->len;

	if (skb_queue_len(&dp_dev->xmit_queue) >= dp->netdev->tx_queue_len) {
		/* Queue overflow.  Stop transmitter. */
		netif_stop_queue(dp->netdev);

		/* We won't see all dropped packets individually, so overrun
		 * error is appropriate. */
		dp_dev->stats.tx_fifo_errors++;
	}
	skb_queue_tail(&dp_dev->xmit_queue, skb);
	dp->netdev->trans_start = jiffies;

	schedule_work(&dp_dev->xmit_work);

	return 0;
}

static void dp_dev_do_xmit(struct work_struct *work)
{
	struct dp_dev *dp_dev = container_of(work, struct dp_dev, xmit_work);
	struct datapath *dp = dp_dev->dp;
	struct sk_buff *skb;

	while ((skb = skb_dequeue(&dp_dev->xmit_queue)) != NULL) {
		skb_reset_mac_header(skb);
		rcu_read_lock();
		fwd_port_input(dp->chain, skb, dp->local_port);
		rcu_read_unlock();
	}
	netif_wake_queue(dp->netdev);
}

static int dp_dev_open(struct net_device *netdev)
{
	netif_start_queue(netdev);
	return 0;
}

static int dp_dev_stop(struct net_device *netdev)
{
	netif_stop_queue(netdev);
	return 0;
}

/* Check if the DMI UUID contains a Nicira mac address that should be 
 * used for this interface.  The UUID is assumed to be RFC 4122
 * compliant. */
static void
set_uuid_mac(struct net_device *netdev)
{
	const char *uuid = dmi_get_system_info(DMI_PRODUCT_UUID);
	const char *uptr;
	uint8_t mac[ETH_ALEN];
	int i;

	if (!uuid || *uuid == '\0' || strlen(uuid) != 36)
		return;

	/* We are only interested version 1 UUIDs, since the last six bytes
	 * are an IEEE 802 MAC address. */
	if (uuid[14] != '1') 
		return;

	/* Pull out the embedded MAC address.  The kernel's sscanf doesn't
	 * support field widths on hex digits, so we use this hack. */
	uptr = uuid + 24;
	for (i=0; i<ETH_ALEN; i++) {
		unsigned char d[3];
		
		d[0] = *uptr++;
		d[1] = *uptr++;
		d[2] = '\0';
		
		mac[i] = simple_strtoul(d, NULL, 16);
	}

	/* If this is a Nicira one, then use it. */
	if (mac[0] != 0x00 || mac[1] != 0x23 || mac[2] != 0x20) 
		return;

	memcpy(netdev->dev_addr, mac, ETH_ALEN);
}

static void
do_setup(struct net_device *netdev)
{
	ether_setup(netdev);

	netdev->get_stats = dp_dev_get_stats;
	netdev->hard_start_xmit = dp_dev_xmit;
	netdev->open = dp_dev_open;
	netdev->stop = dp_dev_stop;
	netdev->tx_queue_len = 100;
	netdev->set_mac_address = dp_dev_mac_addr;

	netdev->flags = IFF_BROADCAST | IFF_MULTICAST;

	random_ether_addr(netdev->dev_addr);

	/* Set the OUI to the Nicira one. */
	netdev->dev_addr[0] = 0x00;
	netdev->dev_addr[1] = 0x23;
	netdev->dev_addr[2] = 0x20;

	/* Set the top bits to indicate random Nicira address. */
	netdev->dev_addr[3] |= 0xc0;
}


int dp_dev_setup(struct datapath *dp)
{
	struct dp_dev *dp_dev;
	struct net_device *netdev;
	char of_name[8];
	int err;

	snprintf(of_name, sizeof of_name, "of%d", dp->dp_idx);
	netdev = alloc_netdev(sizeof(struct dp_dev), of_name, do_setup);
	if (!netdev)
		return -ENOMEM;

	err = register_netdev(netdev);
	if (err) {
		free_netdev(netdev);
		return err;
	}

	/* For "of0", we check the DMI UUID to see if a Nicira mac address
	 * is available to use instead of the random one just generated. */
	if (dp->dp_idx == 0) 
		set_uuid_mac(netdev);

	dp_dev = dp_dev_priv(netdev);
	dp_dev->dp = dp;
	skb_queue_head_init(&dp_dev->xmit_queue);
	INIT_WORK(&dp_dev->xmit_work, dp_dev_do_xmit);
	dp->netdev = netdev;
	return 0;
}

void dp_dev_destroy(struct datapath *dp)
{
	struct dp_dev *dp_dev = dp_dev_priv(dp->netdev);

	netif_tx_disable(dp->netdev);
	synchronize_net();
	skb_queue_purge(&dp_dev->xmit_queue);
	unregister_netdev(dp->netdev);
	free_netdev(dp->netdev);
}

int is_dp_dev(struct net_device *netdev) 
{
	return netdev->open == dp_dev_open;
}
