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

static int
reset_tirgger_cb(struct notice_block *nb, u_int event, u_int full_event)
{
	yecho("/sys/module/rtl_gpio_r/parameters/sysled",
	      "1 %d 100 100 1", (event & full_event) ? -1 : 0);
	return NOTICE_DONE;
}

static struct notice_block reset_nb = {
	.notice_call = reset_tirgger_cb,
	.concern = DF_RSTASSERTED,
	.priority = 100,
};

static void __attribute__ ((constructor)) register_reset_notice(void)
{
	dev_event_chain_register(&reset_nb);
}

static int
wps_tirgger_cb(struct notice_block *nb, u_int event, u_int full_event)
{
	yecho("/sys/module/rtl_gpio_r/parameters/sysled",
	      "1 %d 1000 1000 1", (event & full_event) ? -1 : 0);
	return NOTICE_DONE;
}

static struct notice_block wps_nb = {
	.notice_call = wps_tirgger_cb,
	.concern = DF_WPSASSERTED,
	.priority = 100,
};

static void __attribute__ ((constructor)) register_wps_notice(void)
{
	dev_event_chain_register(&wps_nb);
}

