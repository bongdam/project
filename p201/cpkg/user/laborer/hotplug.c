#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "notice.h"
#include <dvflag.h>
#include "instrument.h"
#include <shutils.h>
#include "conf.h"

#ifndef TRUE
#define TRUE    1
#define FALSE   0
#endif

extern int rtnetaddress(const char *ifname, struct in_addr *in);

static void run_cmd(char *event, int state)
{
	char *argv[3];
	int opmode;
	struct in_addr wan_ip = { .s_addr = 0 };

	if (fork())
		return;

	yclosefrom(STDERR_FILENO + 1);
	opmode = conf_opmode();
	setenv("STATE", state ? "1" : "0", 1);
	setenv("OP_MODE", opmode ? "1" : "0", 1);
	rtnetaddress(!opmode ? "nas0" : "br0", &wan_ip);
	setenv("WAN_IPADDR", inet_ntoa(wan_ip), 1);

	argv[0] = "/usr/bin/hotplug-call";
	argv[1] = event;
	argv[2] = NULL;
	execvp(argv[0], argv);
	exit(127);
}

/*
 * if WANLINK and WANBOUND concerned, with one of them or none of them set,
 * youn should consume FALSE and raise oneshot FALSE.
 */
static int wan_up(struct notice_block *nb, u_int event, u_int full_event)
{
	full_event &= nb->concern;
	if (nb->concern == full_event) {
		if (nb->data != full_event)
			run_cmd((nb->concern & DF_INETUP) ? "inetup" : "bound", TRUE);
	} else if (nb->concern == nb->data && nb->data != full_event)
		run_cmd((nb->concern & DF_INETUP) ? "inetup" : "bound", FALSE);
	nb->data = full_event;
	return NOTICE_DONE;
}

static struct notice_block bound_nb = {
	.notice_call = wan_up,
	.concern = DF_WANBOUND,
	.priority = 50,
};

static struct notice_block bound_plugged_nb = {
	.notice_call = wan_up,
	.concern = DF_INETUP,
	.priority = 49,
};

static void __attribute__ ((constructor)) register_hotplug_call(void)
{
	dev_event_chain_register(&bound_nb);
	dev_event_chain_register(&bound_plugged_nb);
}
