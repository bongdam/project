// gwka.c
// gateway keep alive by arping

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <dvflag.h>
#include "arping.h"
#include <linux/route.h>
#include "instrument.h"
#include "notice.h"

static long ka_tid = 0;
static struct neighbor *geigh = NULL;
static char *script = NULL;
static char *file = NULL;
static char interface[16];
static int interval, timeout;
struct in_addr serverid;

static int gwka_poll(long tid, unsigned long data);

static void gwka_abort(struct neighbor *neigh, int rcode)
{
	if (ka_tid)
		ka_tid = ({ itimer_cancel(ka_tid, NULL); 0; });
	geigh = NULL;
}

static void gwka_callback(struct neighbor *neigh, int rcode)
{
	int ucast, intvl = interval * 1000;

	if (rcode != 1 && !(neigh->he.sll_addr[0] & 0x01)) {
		/* point-to-point arp request failed, try broadcast lastly */
		ucast = 0;
		intvl = timeout - 500;	/* (interval - timeout) of arping */
	} else {
		if (rcode == 0 && script && script[0])
			yexecl(NULL, "%s %s", script, interface);
		/* keep broadcast if failed before, keep unicast otherwise */
		ucast = !!(rcode == 1);
	}
	/* reset global pointer */
	geigh = NULL;
	ka_tid = schedule(ucast, gwka_poll, intvl);
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
		if (!strcmp(dev, ifc) && test_all_bits(RTF_UP|RTF_GATEWAY, flgs))
			addr = gt;
	}
	fclose(f);
	return addr;
}

static int gateway(struct in_addr *gw, const char *intf)
{
	if (serverid.s_addr && serverid.s_addr != -1U)
		gw->s_addr = serverid.s_addr;
	else if (!(gw->s_addr = route_dfl(intf)) || gw->s_addr == -1U)
		return -1;
	return 0;
}

static int gwka_poll(long tid, unsigned long ucast)
{
	char cmd[128];
	char *args[12];
	struct in_addr gw, sip = { .s_addr = 0 };
	int n, prerequisite = 0;
	u_int32_t flg = dev_event_current();

	if (file) {
		if (!((flg & (DF_WANLINK)) ^ (DF_WANLINK))) {
			if (yfcat(file, "%hhu.%hhu.%hhu.%hhu", FIPQUAD(sip)) == 4 &&
			    sip.s_addr && sip.s_addr != -1U)
				prerequisite = 1;
		}
	} else if (!((flg & (DF_WANLINK|DF_WANBOUND)) ^ (DF_WANLINK|DF_WANBOUND)))
		prerequisite = 1;

	if (prerequisite && !gateway(&gw, interface)) {
		n = snprintf(cmd, sizeof(cmd), "arping -I %s -i %d -c 3 %s",
		             interface, timeout, (ucast) ? "-u " : "");
		if (sip.s_addr)
			n += snprintf(cmd + n, sizeof(cmd) - n, "-s %s ", inet_ntoa(sip));
		snprintf(cmd + n, sizeof(cmd) - n, "%s", inet_ntoa(gw));
		n = ystrargs(cmd, args, _countof(args), " ", 0);
		geigh = arping_main(n, args, STDERR_FILENO);
		if (geigh) {
			geigh->cb = gwka_callback;
			ka_tid = 0;
			return 0;
		}
	}
	ka_tid = schedule(0UL, gwka_poll, 1000);
	return 0;
}

/*
Options:
	-q              Stop keep alive
	-s file         File with sender ip
        -S script       Script to be executed on no reply
        -i interval     Keep alive interval seconds
        -w timeout      Seconds to wait for next arping
        -I device       Network interface
        -d destination  host rather than gateway in route
 */
static int mod_gwka(int argc, char **argv, int fd)
{
	char *s = NULL, *path = NULL;
	int opt, intvl = 60, tout = 2;
	struct in_addr dest = { .s_addr = 0 };
	char dev[sizeof(interface)] = { [0] = '\0' };

	optind = 0;	/* reset to 0, rather than the traditional value of 1 */
	while ((opt = getopt(argc, argv, "s:S:i:I:qw:d:")) != -1) {
		switch (opt) {
		case 's':
			path = alloca(strlen(optarg) + 1);
			strcpy(path, optarg);
			break;
		case 'S':
			s = alloca(strlen(optarg) + 1);
			strcpy(s, optarg);
			break;
		case 'q':
			if (geigh) {
				/* replace original callback with aborting one */
				geigh->cb = gwka_abort;
				free(geigh->script);
				geigh->script = NULL;
				select_event_free(select_event_getbyfd(geigh->fd));
			} else
				gwka_abort(NULL, -1);
			return 0;
		case 'i':
			intvl = strtol(optarg, NULL, 0);
			if (intvl < 10)
				intvl = 10;
			break;
		case 'I':
			strlcpy(dev, optarg, sizeof(dev));
			break;
		case 'w':
			tout = strtol(optarg, NULL, 0);
			if (tout < 1)
				tout = 1;
			break;
		case 'd':
			dest.s_addr = inet_addr(optarg);
			if (dest.s_addr || dest.s_addr != -1U)
				break;
		default:
			dprintf(fd, "Invalid option\n");
			return 1;
		}
	}

	if (dev[0] == '\0')
		return 0;

	/* Must cancel KA run before */
	if (ka_tid)
		return 0;

	strcpy(interface, dev);
	interval = intvl;
	timeout = tout * 1000;
	serverid = dest;
	free(script);
	script = (s && s[0]) ? strdup(s) : NULL;
	free(file);
	file = (path && path[0]) ? strdup(path) : NULL;
	ka_tid = schedule(1UL, gwka_poll, 10 * 1000);	/* arbitrary 10 seconds later */
	return 0;
}

static void __attribute__((constructor)) register_gwka_module(void)
{
	fifo_cmd_register("gwka",
		"\t[-s file] [-S script] [-q] [-i interval] [-I device] [-w timeout] [-d destination]",
		"Gwateway Keep Alive", mod_gwka);
}
