#include <linux/kernel.h>
#include <linux/workqueue.h>
#include <linux/timer.h>
#include <linux/bitops.h>
#include <dvflag.h>

#include "version.h"
#include <net/rtl/rtl_types.h>
#include <net/rtl/rtl_glue.h>
#include <net/rtl/rtl865x_netif.h>
#include "AsicDriver/asicRegs.h"

#define PROBE_DURATION (HZ << 1)	/* MUST be greater than 1 sec */

/* DVW-2700 has nothing to do with 1/2 Giga */
#if defined(CONFIG_RTL_8367R_SUPPORT) || defined(CONFIG_RTL_83XX_SUPPORT)
#define Speed(v) (((v) & PortStatusLinkSpeed_MASK) >> PortStatusLinkSpeed_OFFSET)
#define SpeedMaskLen 2
#endif

#if defined(CONFIG_STP) && defined(CONFIG_PREVENT_LOOP)
/* cancel blocking on a port unplugged */
extern int pstp_ratelimit_cancel(unsigned int port);
#endif

static void probe_link_work_func(struct work_struct *);
static void probe_link_func(unsigned long data);

static struct timer_list probe_link_timer;
static DECLARE_WORK(probe_link_work, probe_link_work_func);
static unsigned long probe_link_expiry;
static unsigned int link_status_saved;
#ifdef Speed
static unsigned int link_speed_saved;
#endif

void (*os_link_notifier)(void);

static void trigger_probe_link(void)
{
	probe_link_expiry = jiffies + PROBE_DURATION;
	if (!timer_pending(&probe_link_timer))
		probe_link_func(probe_link_timer.data);
		/*
		  It happened that two green and blue leds had been turned up cocurrently
		  for a short time, which came from deferred handling of linkage.
		 */
		/* mod_timer(&probe_link_timer, jiffies + (HZ << 1)); */
}

static void notify_port_link_change(unsigned int state)
{
	const u32 maskall = DF_LANLINK1|DF_LANLINK2|DF_LANLINK3|DF_LANLINK4|DF_WANLINK;
	u32 old, mask;

	old = maskall & dvflag_get();
	mask = old ^ state;
	if (mask) {
		dvflag_set(state, mask);
#if defined(CONFIG_STP) && defined(CONFIG_PREVENT_LOOP)
		do {
			u32 i;
			for (i = 0; i < (sizeof(u32) * BITS_PER_BYTE); i++) {
				if (!(mask & (1 << i)) || (state & (1 << i)))
					continue;
				if ((i << i) & maskall)
					pstp_ratelimit_cancel(i);
			}
		} while (0);
#endif
	}
}

static void probe_link_work_func(struct work_struct *unused)
{
	u32 mask = DF_LANLINK1|DF_LANLINK2|DF_LANLINK3|DF_LANLINK4|DF_WANLINK;
	unsigned int i, link_status, value, sys_link_flg;
	long remain;
#ifdef Speed
	unsigned int link_speed = 0;

	BUILD_BUG_ON((PortStatusLinkSpeed_MASK >> PortStatusLinkSpeed_OFFSET) != ((1 << SpeedMaskLen) - 1));
#endif
	del_timer(&probe_link_timer);

	remain = (long)probe_link_expiry - (long)jiffies;

	link_status = 0;
	while (mask) {
		i = __ffs(mask);
		mask ^= (1 << i);

#ifndef PRTNR_END
# error PRTNR_XXX must be defined globally!
#endif
		sys_link_flg = (1 << i);
		value = READ_MEM32(PSRP0 + (i << 2));
		if (value & PortStatusLinkUp) {
			link_status |= sys_link_flg;
#ifdef Speed
			link_speed |= (Speed(value) << (i * SpeedMaskLen));
#endif
		}
		/* There are two cases of prompt notification
		 *  - Link-off
		 *  - Link speed not 100mbps
		 * Therefore notification would be deferred 1 second at 100mbps speed which
		 * is likely to be half-way to 500mbps.
		 */
		do {
			if ((link_status ^ link_status_saved) & sys_link_flg) {
				if (link_status & sys_link_flg) {
#ifdef Speed
					if (Speed(value) == PortStatusLinkSpeed100M && remain >= HZ)
						break;
#endif
					link_status_saved |= sys_link_flg;
				} else
					link_status_saved &= ~sys_link_flg;
				notify_port_link_change(link_status_saved);
			}
		} while (0);
	}
#ifdef Speed
	link_speed_saved = link_speed;
#endif
	if (remain <= 0)
		return;
	else if (remain > HZ)	/* fine frequency 100ms */
		mod_timer(&probe_link_timer, jiffies + clamp_t(long, remain, remain, (HZ / 10)));
	else	/* coarse frequency 500ms */
		mod_timer(&probe_link_timer, jiffies + clamp_t(long, remain, remain, (HZ / 2)));
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
