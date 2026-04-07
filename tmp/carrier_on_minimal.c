/* Minimal kernel module - no kernel headers needed */

/* Forward declarations of kernel types and functions */
struct net_device;
struct net;

/* These are kernel exported symbols */
extern struct net init_net;
extern struct net_device *dev_get_by_name(struct net *, const char *);
extern void dev_put(struct net_device *);
extern void netif_carrier_on(struct net_device *);
extern void netif_tx_start_all_queues(struct net_device *);

/* Module metadata - required for insmod */
static const char __mod_license[] __attribute__((section(".modinfo"), used)) = "license=GPL";
static const char __mod_vermagic[] __attribute__((section(".modinfo"), used)) = "vermagic=4.19.81-perf+ SMP preempt mod_unload modversions aarch64";

int init_module(void)
{
	struct net_device *dev = dev_get_by_name(&init_net, "wlan0");
	if (!dev)
		return -19; /* -ENODEV */
	netif_carrier_on(dev);
	netif_tx_start_all_queues(dev);
	dev_put(dev);
	return 0;
}

void cleanup_module(void)
{
}
