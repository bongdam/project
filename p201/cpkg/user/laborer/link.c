#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <syslog.h>
#include <netinet/in.h>
#include "notice.h"
#include <dvflag.h>
#include "instrument.h"
#include <shutils.h>

#undef dprintf

struct link_status {
	const unsigned int bpos;
	const char *name;
};

static int plug_logger_cb(struct notice_block *nb,
			u_int event, u_int full_event)
{
	struct link_status *p = (struct link_status *)nb->data;
	int up;

	up = !!(event & full_event);
	if (up)
		syslog(LOG_INFO, "%s Link Up", p->name);
	else
		syslog(LOG_INFO, "%s Link Down", p->name);

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
