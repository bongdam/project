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
#include "conf.h"

extern long schedule(unsigned long, int (*)(long, unsigned long), int);

static long tid;

int pidof_dhcpc(const char *name)
{
	char buf[64];
	snprintf(buf, sizeof(buf), "/var/run/udhcpc-%s.pid", name);
	return fget_and_test_pid(buf);
}

static int kill_dhcpc(long id, unsigned long signum)
{
	int pid = pidof_dhcpc(conf_ifwan());

	tid = 0;
	if (pid > 0) {
		kill(pid, (int)signum);
		if (signum == SIGUSR2)
			tid = schedule(SIGUSR1, kill_dhcpc, 500);
	}
	return 0;
}

static int
dhcpc_tirgger_cb(struct notice_block *nb, u_int event, u_int full_event)
{
	if ((event & full_event) && !tid)
		tid = schedule((full_event & (DF_WANBOUND | DF_WANIPFILE)) ?
			SIGUSR2 : SIGUSR1, kill_dhcpc, 100);

	return NOTICE_DONE;
}

static struct notice_block dhcpc_nb = {
	.notice_call = dhcpc_tirgger_cb,
	.concern = DF_WANLINK,
	.priority = 99,
};

static void __attribute__ ((constructor)) register_dhcpc_notice(void)
{
	dev_event_chain_register(&dhcpc_nb);
}
