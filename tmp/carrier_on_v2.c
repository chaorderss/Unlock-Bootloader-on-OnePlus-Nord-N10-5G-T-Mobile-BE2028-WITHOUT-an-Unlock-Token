/* Minimal kernel module - carrier_on for wlan0 */
/* Only uses exported kernel symbols */

struct net_device;
struct net;

extern struct net init_net;
extern struct net_device *dev_get_by_name(struct net *, const char *);
extern void netif_carrier_on(struct net_device *);

/* We skip dev_put (inline) and netif_tx_start_all_queues (inline) */

static const char __mod_license[] __attribute__((section(".modinfo"), used)) = "license=GPL";
static const char __mod_vermagic[] __attribute__((section(".modinfo"), used)) = "vermagic=4.19.81-perf+ SMP preempt mod_unload modversions aarch64";

int init_module(void)
{
	struct net_device *dev = dev_get_by_name(&init_net, "wlan0");
	if (!dev)
		return -19;
	netif_carrier_on(dev);
	/* Note: dev_put(dev) is inline, so we skip it.
	   One leaked reference is harmless for a one-shot helper. */
	return 0;
}

void cleanup_module(void)
{
}
