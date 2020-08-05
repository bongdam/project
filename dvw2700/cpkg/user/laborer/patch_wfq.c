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

static int patch_wfq_cb(struct notice_block *nb,
			u_int event, u_int full_event)
{
	char buf[32];
	int port, rate_1k = 0;

	if (event & full_event) {
		port = ffs(event & full_event) - 1;
		sprintf(buf, "x_QOS_RATE_ENABLE_%d", port);
		if (nvram_get_int(buf, 0)) {
			sprintf(buf, "x_QOS_RATE_O_%d", port);
			rate_1k = nvram_get_int(buf, 0);
		}

		if (!rate_1k)
			yexecl(NULL, "dvqos -P %d", port);
	}
	return NOTICE_DONE;
}

static struct notice_block wfq_patch = {
	.notice_call = patch_wfq_cb,
	.concern = DF_WANLINK | DF_LANLINK1 | DF_LANLINK2 | DF_LANLINK3 | DF_LANLINK4,
	.priority = 101,
};

static void __attribute__ ((constructor)) register_wfq_patch_notice(void)
{
	dev_event_chain_register(&wfq_patch);
}
