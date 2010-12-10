#include <linux/if_link.h>
#include <linux/netdevice.h>

/* Linux 2.6.28 introduced dev_get_stats():
 * const struct net_device_stats *dev_get_stats(struct net_device *dev);
 *
 * Linux 2.6.36 changed dev_get_stats() to:
 * struct rtnl_link_stats64 *dev_get_stats(struct net_device *dev,
 *                                         struct rtnl_link_stats64 *storage);
 */
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,36)
struct rtnl_link_stats64 *dev_get_stats(struct net_device *dev,
					struct rtnl_link_stats64 *storage)
{
	const struct net_device_stats *stats;

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,29)
	stats = dev->get_stats(dev);
#else  /* 2.6.28 < kernel version < 2.6.36 */
	stats = (dev_get_stats)(dev);
#endif /* 2.6.28 < kernel version < 2.6.36 */

	storage->rx_packets = stats->rx_packets;
	storage->tx_packets = stats->tx_packets;
	storage->rx_bytes = stats->rx_bytes;
	storage->tx_bytes = stats->tx_bytes;
	storage->rx_errors = stats->rx_errors;
	storage->tx_errors = stats->tx_errors;
	storage->rx_dropped = stats->rx_dropped;
	storage->tx_dropped = stats->tx_dropped;
	storage->multicast = stats->multicast;
	storage->collisions = stats->collisions;
	storage->rx_length_errors = stats->rx_length_errors;
	storage->rx_over_errors = stats->rx_over_errors;
	storage->rx_crc_errors = stats->rx_crc_errors;
	storage->rx_frame_errors = stats->rx_frame_errors;
	storage->rx_fifo_errors = stats->rx_fifo_errors;
	storage->rx_missed_errors = stats->rx_missed_errors;
	storage->tx_aborted_errors = stats->tx_aborted_errors;
	storage->tx_carrier_errors = stats->tx_carrier_errors;
	storage->tx_fifo_errors = stats->tx_fifo_errors;
	storage->tx_heartbeat_errors = stats->tx_heartbeat_errors;
	storage->tx_window_errors = stats->tx_window_errors;
	storage->rx_compressed = stats->rx_compressed;
	storage->tx_compressed = stats->tx_compressed;

	return storage;
}
#endif	/* kernel version < 2.6.36 */
