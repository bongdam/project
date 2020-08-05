#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <syslog.h>
#include <unistd.h>

#include <net/if.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>
#include <sys/sysinfo.h>

#include <libytool.h>
#include <shutils.h>
#include <bcmnvram.h>
#include "instrument.h"

#define WLAN_MBSSID_NUM 		4

static long vap_up_tid;
#ifdef CONFIG_WLAN0_RX_FREEZE_CRUDE_WORKAROUND
static long restart_wlan_tid;
static long restart_wlan_expiry;
#endif

enum {
	NET_LINKDOWN = -1,
	NET_LINKUP
};

static int if_upflag(const char *name)
{
	int fd, status = NET_LINKDOWN;
	struct ifreq ifr;

	if ((fd = socket(AF_INET, SOCK_DGRAM, 0)) < 0)
		return NET_LINKDOWN;

	strncpy(ifr.ifr_name, name, sizeof(ifr.ifr_name));
	if (!ioctl(fd, SIOCGIFFLAGS, &ifr) && (ifr.ifr_flags & IFF_UP))
		status = NET_LINKUP;
	close(fd);
	return status;
}

#ifdef CONFIG_WLAN0_RX_FREEZE_CRUDE_WORKAROUND
static int wlan_down_up(int wlan_id)
{
	char name[IFNAMSIZ];
	int blk = 1;

	yfcat("/proc/sys/private/all_sta_block", "%d", &blk);
	if (blk) {
		snprintf(name, sizeof(name), "wlan%d", wlan_id);
		ifconfig(name, 0, NULL, NULL);
		yecho("/proc/sys/private/all_sta_block", "0\n");
		ifconfig(name, IFUP, NULL, NULL);
/* APACRTL-104 */
		yexecl(NULL, "iwpriv wlan0 write_reg b,808,66");
	}
	return 0;
}
#endif

static int __virt_wl_up(long id, unsigned long on)
{
	int i, ii;
	char name[32], vap[64];
	unsigned int va_mask[2];

	(void)id;
	vap_up_tid = 0;

	for (i = 0; i < 2; i++) {
		va_mask[i] = 0;
		sprintf(name, "WLAN%d_WLAN_DISABLED", i);
		if (nvram_get_int(name, 0) == 1)
			continue;
		for (ii = 0; ii < WLAN_MBSSID_NUM; ii++) {
			/* regard wlan0-va3 wlan1-va3 as a main ssid and never turn it off */
			if (!on && ii == 3)
				continue;
			snprintf(vap, sizeof(vap), "WLAN%d_VAP%d_WLAN_DISABLED", i, ii);
			if (nvram_get_int(vap, 0) == 1)
				continue;
			va_mask[i] |= (1 << ii);
		}
	}

	for (i = 0; i < 2; i++) {
		if (va_mask[i] == 0)
			continue;
		sprintf(name, "wlan%d", i);
#if 0	/* do not touch main ssid */
		if (!on)
			ifconfig(name, 0, NULL, NULL);
#endif
		for (ii = 0; ii < WLAN_MBSSID_NUM; ii++) {
			if (!(va_mask[i] & (1 << ii)))
				continue;
			snprintf(vap, sizeof(vap), "%s-va%d", name, ii);
			ifconfig(vap, (on) ? IFUP : 0, NULL, NULL);
		}
#if 0	/* do not touch main ssid */
		if (!on || (if_upflag(name) != NET_LINKUP))
			ifconfig(name, IFUP, NULL, NULL);
#endif
	}

	return 0;
}

int virtual_ssid_enable(int on)
{
	struct timeval tv = { .tv_usec = 0 };
	itimer_cancel(vap_up_tid, NULL);
	tv.tv_sec = (on) ? 1 : 10;
	vap_up_tid = itimer_creat(on, __virt_wl_up, &tv);
	return 0;
}

#ifdef CONFIG_WLAN0_RX_FREEZE_CRUDE_WORKAROUND
static int poll_restart_wlan(long id, unsigned long wlan_id)
{
	struct sysinfo info;

	sysinfo(&info);
	if (info.uptime >= restart_wlan_expiry) {
		wlan_down_up(wlan_id);
		restart_wlan_tid = 0;
		return 0;
	} else
		return 1;
}

static void __attribute__ ((constructor)) schedule_wlan0_reboot(void)
{
	if (!nvram_get_int("WLAN0_WLAN_DISABLED", 0)) {
		struct timeval tv = { tv.tv_sec = 1, .tv_usec = 0 };

		restart_wlan_expiry = nvram_get_int("x_restart_wlan_expiry", 35);
		restart_wlan_tid = itimer_creat(0UL, poll_restart_wlan, &tv);
	} else
		yecho("/proc/sys/private/all_sta_block", "0\n");
}
#endif
