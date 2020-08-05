#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <syslog.h>
#include "notice.h"
#include <dvflag.h>
#include "instrument.h"

#include <shutils.h>
#include <brdio.h>
#undef dprintf

static char pidfile[128];

struct link_status {
	const unsigned int bpos;
	const char *name;
	unsigned long tstamp; /* centisecond */
};

static unsigned long centisecond(void)
{
	struct timespec ts;
	ygettime(&ts);
	return (ts.tv_sec * 100) + (ts.tv_nsec / 10000000);
}

static int dhcpc_waker_cb(struct notice_block *nb,
			u_int event, u_int full_event)
{
	unsigned long now = centisecond();
	int pid;

	if ((event & full_event) && (DF_INITED & full_event)) {
		if (((long)(now - nb->data) >= 150) &&
		    (yfcat(pidfile, "%d", &pid) > 0) && (pid > 1))
			kill(pid, SIGUSR1);
	}
	nb->data = now;
	return NOTICE_DONE;
}

static struct notice_block dhcpc_waker = {
	.notice_call = dhcpc_waker_cb,
	.concern = DF_WANLINK,
	.priority = 101,
};

unsigned int switch_port_status(int portno)
{
	struct phreq phr;
	int fd;

	if (portno < PH_MINPORT || portno > PH_MAXPORT)
		return 0;

	memset(&phr, 0, sizeof(phr));
	fd = open("/proc/brdio", O_RDWR);
	if (fd < 0)
		return 0;
	phr.phr_port = portno;
	if (ioctl(fd, PHGIO, &phr))
		perror("PHGIO");
	close(fd);
	return phr.phr_optmask;
}

static int plug_logger_cb(struct notice_block *nb,
			u_int event, u_int full_event)
{
	struct link_status *p = (struct link_status *)nb->data;
	int up, speed;

	up = !!(event & full_event);
	if (up) {
		unsigned int phystat = switch_port_status(ffs(p->bpos) - 1);

		if (phystat & PHF_10M)
			speed = 10;
		else if (phystat & PHF_100M)
			speed = 100;
		else if (phystat & PHF_500M)
			speed = 500;
		else
			speed = 1000;

		syslog(LOG_INFO, "%s Link %dMb/s %s 연결됨", p->name,
		       speed, (phystat & PHF_FDX) ? "Full" : "Half");
	} else
		syslog(LOG_INFO, "%s Link 연결 끊어짐", p->name);

	p->tstamp = centisecond();

	return NOTICE_DONE;
}

static struct link_status status[] = {
	{
	 .bpos = DF_WANLINK,
	 .name = "WAN",
	 },
	{
	 .bpos = DF_LANLINK1,
	 .name = "LAN1",
	 },
	{
	 .bpos = DF_LANLINK2,
	 .name = "LAN2",
	 },
	{
	 .bpos = DF_LANLINK3,
	 .name = "LAN3",
	 },
	{
	 .bpos = DF_LANLINK4,
	 .name = "LAN4",
	 },
};

static struct notice_block plug_block[_countof(status)];

static void __attribute__ ((constructor)) register_plug_event_notice(void)
{
	ssize_t i;

	for (i = 0; i < _countof(plug_block); i++) {
		plug_block[i].notice_call = plug_logger_cb;
		plug_block[i].concern = status[i].bpos;
		plug_block[i].data = (unsigned long)&status[i];
		plug_block[i].priority = 100;	/* must precede wan.c */
		dev_event_chain_register(&plug_block[i]);
	}
}

static int mod_link_watcher(int argc, char **argv, int fd)
{
	struct link_status *p;
	char *name;
	int i, n = 0;
	u_int32_t event = dev_event_current();

	name = (argc > 1) ? argv[1] : NULL;
	if (name && ((i = !strcasecmp(name, "add")) || !strcasecmp(name, "del"))) {
		if (argc > 2 && !strcasecmp(argv[2], "dhcpc")) {
			dev_event_chain_deregister(&dhcpc_waker);
			if (i && argc > 3) {
				strlcpy(pidfile, argv[3], sizeof(pidfile));
				dhcpc_waker.data = centisecond();
				dev_event_chain_register(&dhcpc_waker);
			}
		}
	} else {
		for (i = 0; i < _countof(status); i++) {
			p = &status[i];
			if (name == NULL || !strcmp(name, p->name)) {
				n += dprintf(fd, "%lu %s %s\n", p->tstamp,
					p->name, (event & p->bpos) ? "UP" : "DOWN");
				if (name)
					break;
			}
		}
	}
	return 0;
}

static void __attribute__ ((constructor)) register_link_watcher_module(void)
{
	fifo_cmd_register("link_watcher",
			"\t[WAN|LAN1|LAN2|LAN3|LAN4]",
			"Show link status", mod_link_watcher);
}
