// garp.c
// duplicate address detection
// conform to rfc5227

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
#include <shutils.h>

static long dad_tid = 0;
static struct neighbor *dad = NULL;
static char *script = NULL;
static char *file = NULL;
static char interface[16];

static int garp_send_poll(long tid, unsigned long update);
extern int rtnetaddress(const char *ifname, struct in_addr *in);

static void garp_send_abort(struct neighbor *neigh, int rcode)
{
	if (dad_tid)
		dad_tid = ({ itimer_cancel(dad_tid, NULL); 0; });
	dad = NULL;
}

static void garping_send_cb(struct neighbor *neigh, int rcode)
{
	char buf[18];

	dad = NULL;
	dad_tid = 0L;
	if (rcode != 1) {
		if (neigh->src.s_addr == INADDR_ANY)
			dad_tid = schedule(1, garp_send_poll, 1000 - 500);
	} else if (script && script[0])
		yexecl(NULL, "%s %s %s %s", script, interface,
		       inet_ntoa(neigh->dst),
		       ether_etoa(neigh->he.sll_addr, buf));
}

static int garp_send_poll(long tid, unsigned long update)
{
	char cmd[128];
	char *args[12];
	struct in_addr sip = { .s_addr = 0 };
	int n;
	u_int32_t flg = dev_event_current();

	if (file) {
		if (!((flg & (DF_WANLINK)) ^ (DF_WANLINK)))
			yfcat(file, "%hhu.%hhu.%hhu.%hhu", FIPQUAD(sip));
	} else if (!((flg & (DF_WANLINK|DF_WANBOUND)) ^ (DF_WANLINK|DF_WANBOUND)))
		rtnetaddress(interface, &sip);

	if (sip.s_addr && sip.s_addr != -1U) {
		n = snprintf(cmd, sizeof(cmd), "arping -D -I %s -c %d ",
		             interface, update ? 1 : 3);
		if (update)
			n += snprintf(cmd + n, sizeof(cmd) - n, "-s %s ", inet_ntoa(sip));
		snprintf(cmd + n, sizeof(cmd) - n, "%s", inet_ntoa(sip));
		n = ystrargs(cmd, args, _countof(args), " ", 0);
		dad = arping_main(n, args, STDERR_FILENO);
		if (dad)
			dad->cb = garping_send_cb;
	}

	dad_tid = 0L;
	return 0;
}

static int garp_send_cb(struct notice_block *nb,
			u_int event, u_int full_event)
{
	if ((event & full_event) && !dad_tid && !dad)
		dad_tid = schedule(0, garp_send_poll, 10);
	return NOTICE_DONE;
}

static struct notice_block garp_send = {
	.notice_call = garp_send_cb,
	.concern = DF_WANLINK | DF_WANBOUND,
	.priority = 90,
};

/*
Options:
	-q              Quit sending GARP
	-s file         File with sender ip
	-S script       Script to be executed on no reply
	-I device       Network interface
 */
static int mode_garp(int argc, char **argv, int fd)
{
	char *s = NULL, *path = NULL;
	int opt;
	char dev[sizeof(interface)] = { [0] = '\0' };

	optind = 0;	/* reset to 0, rather than the traditional value of 1 */
	while ((opt = getopt(argc, argv, "s:S:I:q")) != -1) {
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
			if (dad) {
				/* replace original callback with aborting one */
				dad->cb = garp_send_abort;
				free(dad->script);
				dad->script = NULL;
				select_event_free(select_event_getbyfd(dad->fd));
			} else
				garp_send_abort(NULL, -1);
			dev_event_chain_deregister(&garp_send);
			/* set explicit signature */
			garp_send.next = NULL;
			return 0;
		case 'I':
			strlcpy(dev, optarg, sizeof(dev));
			break;
		default:
			dprintf(fd, "Invalid option\n");
			return 1;
		}
	}

	if (dev[0] == '\0')
		return 0;

	/* Must cancel GARPing run before */
	if (garp_send.next)
		return 0;
	dev_event_chain_register(&garp_send);
	strcpy(interface, dev);
	free(script);
	script = (s && s[0]) ? strdup(s) : NULL;
	free(file);
	file = (path && path[0]) ? strdup(path) : NULL;
	dad_tid = schedule(0, garp_send_poll, 0);
	return 0;
}

static void __attribute__((constructor)) register_garp_send_module(void)
{
	fifo_cmd_register("garp",
		"\t[-s file] [-S script] [-q] [-I device]",
		"Dupldate Address Detect", mode_garp);
}
