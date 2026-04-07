/* Kernel module to enable carrier and wake TX queues for wlan0 */
/* Uses hardcoded offsets from kernel 4.19.81-perf+ on billie */

struct net_device;
struct netdev_queue;
struct net;

extern struct net init_net;
extern struct net_device *dev_get_by_name(struct net *, const char *);
extern void netif_carrier_on(struct net_device *);
extern void netif_tx_wake_queue(struct netdev_queue *);

/* Offsets discovered from wlan driver disassembly:
 * dev->_tx           at offset 0x380 (896)
 * dev->num_tx_queues at offset 0x388 (904)
 * sizeof(netdev_queue) = 0x140 (320)
 */
#define DEV_TX_OFFSET       0x380
#define DEV_NUM_TX_OFFSET   0x388
#define NETDEV_QUEUE_SIZE   0x140

static const char __mod_license[] __attribute__((section(".modinfo"), used)) = "license=GPL";
static const char __mod_vermagic[] __attribute__((section(".modinfo"), used)) = "vermagic=4.19.81-perf+ SMP preempt mod_unload modversions aarch64";

int init_module(void)
{
	struct net_device *dev;
	char *devp;
	struct netdev_queue *tx_base;
	unsigned int num_queues;
	unsigned int i;

	dev = dev_get_by_name(&init_net, "wlan0");
	if (!dev)
		return -19;

	devp = (char *)dev;

	/* Enable carrier */
	netif_carrier_on(dev);

	/* Read _tx pointer and num_tx_queues */
	tx_base = *(struct netdev_queue **)(devp + DEV_TX_OFFSET);
	num_queues = *(unsigned int *)(devp + DEV_NUM_TX_OFFSET);

	/* Wake all TX queues */
	for (i = 0; i < num_queues; i++) {
		struct netdev_queue *txq = (struct netdev_queue *)
			((char *)tx_base + i * NETDEV_QUEUE_SIZE);
		netif_tx_wake_queue(txq);
	}

	/* dev_put is inline, skip it */
	return 0;
}

void cleanup_module(void)
{
}
