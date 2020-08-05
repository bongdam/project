/* jihyun@davo150617 jcode#2 */
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include <errno.h>
#include <assert.h>
#include <fcntl.h>
#include <time.h>
#include <syslog.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>
#include <getopt.h>
#include <sys/wait.h>
#include <8192cd.h>
#include <libytool.h>
#include <bcmnvram.h>
#include <net/if.h>
#include <shutils.h>
#include "custom.h"

static int wlan_state_check(const char *wlan_if)
{
	int skfd = 0;
	struct ifreq ifr;

	if ( (skfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0)
		return 0;

	strncpy(ifr.ifr_name, wlan_if, IFNAMSIZ);

	if (ioctl(skfd, SIOCGIFFLAGS, &ifr) < 0) {
		close(skfd);
		return -1;
	}

	close(skfd);

	return (ifr.ifr_flags & IFF_UP)? 1 : 0;
}

static void wlan_reset_doit(const char *wlbit, int on)
{
	char v;
	char name[IFNAMSIZ];
	int i;

	if ( !on ) {
		for ( i =0; i < 2; i++) {
			for (v = 0; v < 5; v++) {
				if ( !(wlbit[i] & (1<<v)) )
					continue;
				if ( v == 0 ) snprintf(name, sizeof(name), "wlan%d", i);
				else snprintf(name, sizeof(name), "wlan%d-va%d", i, v-1);
				yexecl(NULL, "iwpriv %s das [%d] smart_reset", name, RTL8192CD_IOCTL_ALL_DEL_STA);
			}
		}
	}
	for ( i= 0; i < 2; i++ ) {
		if ( (wlbit[i] & 1) ) {
			yexecl(NULL, "ifconfig wlan%d %s", i, ((on)?"up":"down"));
			if (on) {
			    if (i == 0) /* 5G site_survey on_goning time */
				    usleep(15000000);
				else        /* 2G site_survey on_goning time */
				    usleep(3000000);
/* APACRTL-104 */
				if (i == 0)
					yexecl(NULL, "iwpriv wlan0 write_reg b,808,66");
				yexecl(NULL, "iwpriv wlan%d autoch", i);
			}
		}
	}
}

void usage_exit(void)
{
	fprintf(stderr,	"smartreset wl0 x wl1 x (x: main(1)|va0(2)|va1(4)|va2(8)|va3(16)\n");

	exit(-1);
}

int main (int argc, char *argv[])
{
	int c, i, wlan_if = 0, status_wlan = 0;
	int option_index = 0;
	char if_name[32];
	unsigned char wlstatebit[2] = {0,};

	while(1) {
		static struct option long_options[] = {
			{"wl0",		required_argument,	0, 'x'},
			{"wl1",		required_argument,	0, 'y'},
			{0, 0, 0, 0}
		};
		/* getopt_long stores the option index here. */
		if ( (c = getopt_long (argc, argv, "x:y:", long_options, &option_index)) < 0 )
			break;

		switch (c) {
			case 'x':
			{
				wlstatebit[0] = strtoul(optarg, NULL, 16);
				break;
			}
			case 'y':
			{
				wlstatebit[1] = strtoul(optarg, NULL, 16);
				break;
			}
			case '?':
			default:
			{
				usage_exit();
				break;
			}
		}
	}
	wlan_reset_doit(&wlstatebit[0], 0);
	usleep(1500000);
	wlan_reset_doit(&wlstatebit[0], 1);
	usleep(8500000);
	yexecl(NULL, "sh -c \"apscanTrap &\"");

	for (i = 0; i < 2; i++) {
		if (wlstatebit[i] & 0x1) {
			snprintf(if_name, sizeof(if_name), "wlan%d", i);
			status_wlan += wlan_state_check(if_name);
			wlan_if++;
			if ( i == 1 &&
				nvram_match("WLAN1_CHANNEL", "0") &&
				nvram_match("x_wlan1_auto_bonding", "1") )
				yexecl(NULL, "sh -c \"snmp -m 8 &\"");
		}
	}

	if (wlan_if) {
		if (status_wlan == wlan_if)
			yexecl(NULL, "sh -c \"snmp -m 7 &\"");
	}

	/* restart childguard */
	killall(SIGKILL, "child_guard");
	start_childguard();

	return 0;
}