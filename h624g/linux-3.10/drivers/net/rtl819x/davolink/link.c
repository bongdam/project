#include <linux/kernel.h>
#include <linux/workqueue.h>
#include <linux/timer.h>
#include <dvflag.h>

#include "version.h"
#include <net/rtl/rtl_types.h>
#include <net/rtl/rtl_glue.h>
#include <net/rtl/rtl865x_netif.h>
#include "AsicDriver/asicRegs.h"

/* cancel blocking on a port unplugged */
extern int pstp_ratelimit_cancel(unsigned int port);

static void probe_link_work_func(struct work_struct *);
static void probe_link_func(unsigned long data);

static struct timer_list probe_link_timer;
static DECLARE_WORK(probe_link_work, probe_link_work_func);
static int probe_link_counter;
static unsigned int link_status_saved;

void (*os_link_notifier)(void);

static void trigger_probe_link(void)
{
	probe_link_counter = 3;
	if (!timer_pending(&probe_link_timer))
		mod_timer(&probe_link_timer, jiffies + (HZ << 1));
}

static void notify_port_link_change(unsigned int state)
{
	u32 old, i, port;
	u32 mask = DF_LANLINK1|DF_LANLINK2|DF_LANLINK3|DF_LANLINK4|DF_WANLINK;

	old = mask & dvflag_get();
	mask = old ^ state;
	if (mask) {
		dvflag_set(state, mask);
		for (i = 0; i < (sizeof(u32) * BITS_PER_BYTE); i++) {
			if (!(mask & (1 << i)) || (state & (1 << i)))
				continue;
			switch (1 << i) {
			case DF_LANLINK1:
				port = 0;
				break;
			case DF_LANLINK2:
				port = 1;
				break;
			case DF_LANLINK3:
				port = 2;
				break;
			case DF_LANLINK4:
				port = 3;
				break;
			case DF_WANLINK:
				port = 4;
				break;
			default:
				continue;
			}
			pstp_ratelimit_cancel(port);
		}
	}
}

static void probe_link_work_func(struct work_struct *unused)
{
	unsigned int i, link_status;

	if (probe_link_counter > 0) {
		--probe_link_counter;
		link_status = 0;
		for (i = 0; i < 5; i++) {
			if (READ_MEM32(PSRP0 + (i << 2)) & PortStatusLinkUp) {
				switch (1 << i) {
				case RTL_LANPORT_MASK_1:
					link_status |= DF_LANLINK1; break;
				case RTL_LANPORT_MASK_2:
					link_status |= DF_LANLINK2; break;
				case RTL_LANPORT_MASK_3:
					link_status |= DF_LANLINK3; break;
				case RTL_LANPORT_MASK_4:
					link_status |= DF_LANLINK4; break;
				case RTL_WANPORT_MASK:
					link_status |= DF_WANLINK; break;
				default:
					break;
				}
			}
		}

		if (link_status != link_status_saved) {
			link_status_saved = link_status;
			notify_port_link_change(link_status_saved);
			probe_link_counter = 0;
		}
	}

	del_timer(&probe_link_timer);
	if (probe_link_counter > 0)
		mod_timer(&probe_link_timer, jiffies + HZ);
}

static void probe_link_func(unsigned long data)
{
	/*
	 * We can't do our recovery in softirq context and it's not
	 * performance critical, so we schedule it.
	 */
	schedule_work(&probe_link_work);
}

void setup_probe_link(void)
{
	if (os_link_notifier == NULL) {
		setup_timer(&probe_link_timer, probe_link_func, 0);
		smp_mb();
		os_link_notifier = trigger_probe_link;
		trigger_probe_link();
	}
}

void del_probe_link(void)
{
	if (os_link_notifier) {
		os_link_notifier = NULL;
		smp_mb();
		del_timer(&probe_link_timer);
	}
}
