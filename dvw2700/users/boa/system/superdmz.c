#include <stdio.h>
#include <stdlib.h>
#include <memory.h>
#include <signal.h>
#include <arpa/inet.h>
#include <sys/stat.h>
#include "apmib.h"

#include <bcmnvram.h>
#include <libytool.h>
#include <dvflag.h>
#include "sysconf.h"
#include "sys_utility.h"
#include "custom.h"

extern int run_ipt_restore(char *pathname, char *opt, int try);
extern unsigned int in_faton(const char *path, const char *name);

int disable_sdmz(char *ifc)
{
	int fd;
	char pathnam[] = "/var/XXXXXX";
	char buf[128];
	struct in_addr gip, gmask, subnet, router, lip, lmask;

	if (!isFileExist("/var/ntwk_sdmz"))
		return -1;

	yecho("/proc/rtl865x/ip", "del external\n");
	yecho(PRIVATE_SYSFS_DIR "twin_inaddr", "0\n");
	gip.s_addr = in_faton("/var/ntwk_sdmz", "WAN_IP");
	gmask.s_addr = in_faton("/var/ntwk_sdmz", "WAN_NMASK");
	router.s_addr = in_faton("/var/ntwk_sdmz", "WAN_ROUTER");
	lip.s_addr = in_faton("/var/ntwk_sdmz", "LAN_IP");
	lmask.s_addr = in_faton("/var/ntwk_sdmz", "LAN_NMASK");

	unlink("/var/ntwk_sdmz");
	if (gip.s_addr)
		route_del("br0", 0, inet_ntoa(gip), "0.0.0.0", "255.255.255.255");
	if (router.s_addr)
		route_del(NULL, 0, "0.0.0.0", inet_ntoa(router), "0.0.0.0");
	subnet.s_addr = gip.s_addr & gmask.s_addr;
	if (subnet.s_addr) {
		sprintf(buf, "%u.%u.%u.%u", NIPQUAD(subnet.s_addr));
		route_del(ifc, 0, buf, "0.0.0.0", inet_ntoa(gmask));
	}

	fd = mkstemp(pathnam);
	/* filter table */
	dprintf(fd, "*filter\n");
	dprintf(fd, "-D FORWARD -i %s -d %u.%u.%u.%u -j ACCEPT\n", ifc, NIPQUAD(gip.s_addr));
	dprintf(fd, "-D INPUT -i %s -p udp --dport 67:68 -j DROP\n", ifc);
	dprintf(fd, "-D ACL -i br0 -s %u.%u.%u.%u -j ACCEPT\n", NIPQUAD(gip.s_addr));
	dprintf(fd, "COMMIT\n");
	/* nat table */
	dprintf(fd, "*nat\n");
	dprintf(fd, "-D PREROUTING -i %s -p udp --dport 67:68 -j DNAT --to %u.%u.%u.%u\n",
	        ifc, NIPQUAD(lip.s_addr));
	dprintf(fd, "-D PREROUTING -p icmp -i %s -d %u.%u.%u.%u -j DNAT --to %u.%u.%u.%u\n",
	        ifc, NIPQUAD(gip.s_addr), NIPQUAD(lip.s_addr));
	dprintf(fd, "-D POSTROUTING -o %s -s %u.%u.%u.%u/%u.%u.%u.%u -j SNAT --to-source %u.%u.%u.%u\n",
	        ifc, NIPQUAD(lip.s_addr), NIPQUAD(lmask.s_addr), NIPQUAD(gip.s_addr));
	dprintf(fd, "-D POSTROUTING -o %s -s %u.%u.%u.%u -j SNAT --to-source %u.%u.%u.%u\n",
	        ifc, NIPQUAD(gip.s_addr), NIPQUAD(gip.s_addr));
	dprintf(fd, "-D POSTROUTING -s %u.%u.%u.%u/%u.%u.%u.%u -d %u.%u.%u.%u -j ACCEPT\n",
	        NIPQUAD(lip.s_addr), NIPQUAD(lmask.s_addr), NIPQUAD(gip.s_addr));
	dprintf(fd, "COMMIT\n");
	close(fd);
	run_ipt_restore(pathnam, "--noflush", 10);
	unlink(pathnam);

	sprintf(buf, "/proc/sys/net/ipv4/conf/%s/proxy_arp", ifc);
	yecho(buf, "0\n");
	yecho("/proc/sys/net/ipv4/conf/br0/proxy_arp", "0\n");
	yecho("/proc/fast_nat", "2\n");

	if (!run_fcommand("/var/run/acl_superdmz_permit", "aclwrite del"))
		unlink("/var/run/acl_superdmz_permit");
	return 0;
}

static unsigned long route_dfl(const char *ifc)
{
	unsigned long gt, addr = 0;
	char dev[64];
	int flgs;
	FILE *f;

	f = fopen("/proc/net/route", "r");
	if (!f)
		return 0;
	fscanf(f, "%*[^\n]\n");
	while (!addr) {
		if (fscanf(f, "%63s%*x%lx%X%*[^\n]\n", dev, &gt, &flgs) != 3)
			break;
		if (!strcmp(dev, ifc) && test_all_bits(RTF_UP | RTF_GATEWAY, flgs))
			addr = gt;
	}
	fclose(f);
	return addr;
}

int enable_sdmz(char *ifc)
{
	int fd;
	char pathnam[] = "/var/XXXXXX";
	char buf[128];
	struct in_addr gip, gmask, subnet, router, lip, lmask;
	int dhcpclnt = -1, echoreply = 0;

	disable_sdmz(ifc);

	if (!getInAddr(ifc, IP_ADDR_T, &gip) ||
	    !getInAddr(ifc, NET_MASK_T, &gmask) ||
	    !getInAddr("br0", IP_ADDR_T, &lip) ||
	    !getInAddr("br0", NET_MASK_T, &lmask) ||
	    !(router.s_addr = route_dfl(ifc)))
		return -1;

#if defined(CONFIG_APP_IGMPPROXY)
	if (nvram_atoi("IGMP_PROXY_DISABLED", 0) == 0) {
		int i = 0;
		while (access("/tmp/.igmpproxy_init", F_OK) != 0) {
			fprintf(stderr, "enable_sdmz: waiting for igmpproxy run\n");
			usleep(100 * 1000);
			i++;
			if (i > 50) { /* max 5 sec */
				break;
			}
		}
	}
#endif

	yecho("/proc/rtl865x/ip", "del external\n");

	ifconfig(ifc, IFUP, "0.0.0.0", NULL);
	yecho(PRIVATE_SYSFS_DIR "up_ifname", "%s\n", ifc);
	yecho(PRIVATE_SYSFS_DIR "twin_inaddr", "0x%08x\n", gip.s_addr);

	subnet.s_addr = gip.s_addr & gmask.s_addr;
	sprintf(buf, "%u.%u.%u.%u", NIPQUAD(subnet.s_addr));
	route_add(ifc, 0, buf, "0.0.0.0", inet_ntoa(gmask));
	route_add(NULL, 0, "0.0.0.0", inet_ntoa(router), "0.0.0.0");
	route_add("br0", 0, inet_ntoa(gip), "0.0.0.0", "255.255.255.255");

	fd = mkstemp(pathnam);
	/* filter table */
	dprintf(fd, "*filter\n");
	/* FORWARD chain in filter table */
	dprintf(fd, "-I FORWARD -i %s -d %u.%u.%u.%u -j ACCEPT\n", ifc, NIPQUAD(gip.s_addr));
	/* PREROUTING chain in filter nat */
	// When using raw socket in dhcpc, so using filter like under that avoid icmp(unreachable)
	// compensate the defect in SDMZ
	apmib_get(MIB_WAN_DHCP, (void *)&dhcpclnt);
	if (dhcpclnt == DHCP_CLIENT)
		dprintf(fd, "-I INPUT 1 -i %s -p udp --dport 67:68 -j DROP\n", ifc);
	dprintf(fd, "-I ACL -i br0 -s %u.%u.%u.%u -j ACCEPT\n", NIPQUAD(gip.s_addr));
	dprintf(fd, "COMMIT\n");

	/* nat table */
	dprintf(fd, "*nat\n");
	if (dhcpclnt == DHCP_CLIENT)
		dprintf(fd, "-I PREROUTING 1 -i %s -p udp --dport 67:68 -j DNAT --to %u.%u.%u.%u\n",
		        ifc, NIPQUAD(lip.s_addr));

	apmib_get(MIB_PING_WAN_ACCESS_ENABLED, (void *)&echoreply);
	if (echoreply)
		dprintf(fd, "-A PREROUTING -p icmp -i %s -d %u.%u.%u.%u -j DNAT --to %u.%u.%u.%u\n",
		        ifc, NIPQUAD(gip.s_addr), NIPQUAD(lip.s_addr));

	/* INPUT chain in filter nat : for igmp join/leave from sdmz'ed HOST (mangle src addr to 10.10.100.100 */
	dprintf(fd, "-I INPUT 1 -i br0 -p 2 -s %u.%u.%u.%u -j SNAT --to 10.10.100.100\n", NIPQUAD(gip.s_addr));

	/* POSTROUTING chain in filter nat */
	dprintf(fd, "-I POSTROUTING -o %s -s %u.%u.%u.%u/%u.%u.%u.%u -j SNAT --to-source %u.%u.%u.%u\n",
	        ifc, NIPQUAD(lip.s_addr), NIPQUAD(lmask.s_addr), NIPQUAD(gip.s_addr));
	dprintf(fd, "-I POSTROUTING -o %s -s %u.%u.%u.%u -j SNAT --to-source %u.%u.%u.%u\n",
	        ifc, NIPQUAD(gip.s_addr), NIPQUAD(gip.s_addr));
	dprintf(fd, "-I POSTROUTING -s %u.%u.%u.%u/%u.%u.%u.%u -d %u.%u.%u.%u -j ACCEPT\n",
	        NIPQUAD(lip.s_addr), NIPQUAD(lmask.s_addr), NIPQUAD(gip.s_addr));

	dprintf(fd, "COMMIT\n");
	close(fd);
	run_ipt_restore(pathnam, "--noflush", 10);
	unlink(pathnam);

	sprintf(buf, "/proc/sys/net/ipv4/conf/%s/proxy_arp", ifc);
	yecho(buf, "1\n");
	yecho("/proc/sys/net/ipv4/conf/br0/proxy_arp", "1\n");

	//yecho("/proc/net/flush_conntrack", "igmp icmp\n");
	yecho("/proc/fast_nat", "2\n");
	yecho("/proc/rtl865x/ip", "add 0.0.0.0 %u.%u.%u.%u napt\n", NIPQUAD(gip.s_addr));
	//yecho("/proc/sdmz_status", "1\n");

	yecho("/var/ntwk_sdmz",
	      "WAN_IP=%u.%u.%u.%u\n"
	      "WAN_NMASK=%u.%u.%u.%u\n"
	      "WAN_ROUTER=%u.%u.%u.%u\n"
	      "LAN_IP=%u.%u.%u.%u\n"
	      "LAN_NMASK=%u.%u.%u.%u\n",
	      NIPQUAD(gip.s_addr), NIPQUAD(gmask.s_addr), NIPQUAD(router.s_addr),
	      NIPQUAD(lip.s_addr), NIPQUAD(lmask.s_addr));

	if (!run_fcommand("/var/run/acl_ipspoof_drop", "aclwrite del")) {
		sprintf(buf, "br0 -a permit -r ip -i %u.%u.%u.%u/255.255.255.255_0.0.0.0/0.0.0.0",
		        NIPQUAD(gip.s_addr));
		add_fcommand("/var/run/acl_superdmz_permit", 0, "aclwrite add", buf);
		run_fcommand("/var/run/acl_ipspoof_drop", "aclwrite add");
	}

	return 0;
}
