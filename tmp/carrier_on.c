#include <linux/module.h>
#include <linux/netdevice.h>

static char *ifname = "wlan0";
module_param(ifname, charp, 0);

static int __init carrier_on_init(void)
{
	struct net_device *dev;

	dev = dev_get_by_name(&init_net, ifname);
	if (!dev) {
		pr_err("carrier_on: device %s not found\n", ifname);
		return -ENODEV;
	}

	netif_carrier_on(dev);
	netif_tx_start_all_queues(dev);
	pr_info("carrier_on: enabled carrier and TX queues on %s\n", ifname);

	dev_put(dev);
	return 0;
}

static void __exit carrier_on_exit(void)
{
}

module_init(carrier_on_init);
module_exit(carrier_on_exit);
MODULE_LICENSE("GPL");
