#include <linux/module.h>
#include <linux/types.h>
#include <linux/timer.h>
#include <linux/skbuff.h>
#include <linux/gfp.h>
#include <net/xfrm.h>
#include <linux/jhash.h>
#include <linux/in.h>
#include <linux/inetdevice.h>

static int if_priv_flags_event(struct notifier_block *this, unsigned long event,
			 void *ptr)
{
	struct net_device *dev = ptr;
	char *p;

	if (event == NETDEV_REGISTER) {
		if ((p = strstr(dev->name, "wlan"))) {
			dev->priv_flags |= 0x4000000;		// wlan interface
			if (strstr(p + sizeof("wlan"), "wds"))	// wds
				dev->priv_flags |= 0x8000000;
			else if (strstr(p + sizeof("wlan"), "vxd"))	// extender
				dev->priv_flags |= 0x10000000;
		}
	};

	return NOTIFY_DONE;
}

static struct notifier_block if_priv_flags_notifier = {
	.notifier_call = if_priv_flags_event,
};

static int __init if_priv_flags_init(void)
{
	register_netdevice_notifier(&if_priv_flags_notifier);
	return 0;
}

static void __exit if_priv_flags_exit(void)
{
	unregister_netdevice_notifier(&if_priv_flags_notifier);
}

module_init(if_priv_flags_init);
module_exit(if_priv_flags_exit);
