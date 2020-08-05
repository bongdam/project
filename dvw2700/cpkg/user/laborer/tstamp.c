#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <stdlib.h>
#include <unistd.h>
#include "notice.h"
#include <dvflag.h>
#include "instrument.h"
#include <time.h>
#include <libytool.h>
#undef dprintf

static int tstamp_cb(struct notice_block *nb,
			u_int event, u_int full_event)
{
	time_t t;
	struct tm *tmp;
	char buf[32];

	if (event & full_event) {
		t = time(NULL);
		tmp = localtime(&t);
		if (!tmp)	 /* paranoia check */
			return NOTICE_DONE;

		strftime(buf, sizeof(buf), "%F %T", tmp);
		yecho("/tmp/.wanup", "%s\n", buf);
		if (nb->concern & DF_NTPSYNC) {
			nb->concern = DF_WANLINK;	/* replace concerned flag */
			yecho("/tmp/.uptime", "%s\n", buf);
		}
	}
	return NOTICE_DONE;
}

static struct notice_block tstamper = {
	.notice_call = tstamp_cb,
	.concern = DF_NTPSYNC,
	.priority = 50,
};

static void __attribute__ ((constructor)) register_tstamper(void)
{
	dev_event_chain_register(&tstamper);
}
