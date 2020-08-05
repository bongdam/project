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
#include <bcmnvram.h>

#undef dprintf

enum { RB_ON1 = 0, RB_OFF1, RB_ON2, RB_OFF2, RB_RLQSH };

static long restart_tid, upload_tid, wps_tid;

struct gpio_led_desc {
	const char *name;
	long data;
	int (* connect)(const char *name, long data);
	int (* disconnect)(const char *name, long data);
};

static int gpio_connect_output(const char *name, long data);
static int gpio_disconnect(const char *name, long data);
static int wlan_led_connect(const char *name, long data);
static int wlan_led_disconnect(const char *name, long data);

static const struct gpio_led_desc gpio_ledd[] = {
	{
	 .name = "G6",
	 .connect = gpio_connect_output,
	 .disconnect = gpio_disconnect,
	},
	{
	 .name = "G7",
	 .connect = gpio_connect_output,
	 .disconnect = gpio_disconnect,
	},
	{
	 .name = "H0",
	 .connect = gpio_connect_output,
	 .disconnect = gpio_disconnect,
	},
	{
	 .name = "H1",
	 .connect = gpio_connect_output,
	 .disconnect = gpio_disconnect,
	},
	{
	 .name = "H2",
	 .connect = gpio_connect_output,
	 .disconnect = gpio_disconnect,
	},
	{
	 .name = "B4",
	 .data = (long)"/proc/wlan1/led",
	 .connect = wlan_led_connect,
	 .disconnect = wlan_led_disconnect,
	},
	{
	 .name = "B5",
	 .data = (long)"/proc/wlan0/led",
	 .connect = wlan_led_connect,
	 .disconnect = wlan_led_disconnect,
	},
	{
	 .name = NULL,
	},
};

/* wlan's led descriptors should be contiguous */
static const struct gpio_led_desc *gpio_wl_ledd;

static int gpio_send_command(const char *name, int cmd)
{
	int fd, rc = -1;

	fd = open("/proc/brdio", O_RDWR);
	if (fd != -1) {
		rc = ioctl(fd, cmd, (void *)name);
		close(fd);
	}
	return rc;
}

static int gpio_connect_output(const char *name, long data)
{
	return gpio_send_command(name, GPIOCOUT);
}

static int gpio_disconnect(const char *name, long data)
{
	char buf[sizeof(int) << 1];

	snprintf(buf, sizeof(int), "%s", name);
	*(unsigned int *)&buf[sizeof(int)] = 0;	/* LED# usage */
	return gpio_send_command(buf, GPIODECFG);
}

static int wlan_led_connect(const char *name, long data)
{
	/* disable control by wlan drv */
	return yecho((char *)data, "0\n");
}

static int wlan_led_disconnect(const char *name, long data)
{
	/* restore control to wlan drv */
	return yecho((char *)data, "2\n");
}

static int dev_event_set(unsigned setb, unsigned mask)
{
	unsigned int cmd[2] = { [0] = setb, [1] = mask, };
	int fd = open("/proc/dvflag", O_RDWR);
	if (fd > -1) {
		write(fd, cmd, sizeof(cmd));
		close(fd);
		return 0;
	}
	return -1;
}

static int cancel_led_script_fsm(int *pstate)
{
	const struct gpio_led_desc *p;

	for (p = gpio_ledd; p->name; p++)
		p->disconnect(p->name, p->data);
	free(pstate);
	return 0;
}

static int cancel_wlan_led_script_fsm(int *pstate)
{
	const struct gpio_led_desc *p = gpio_wl_ledd;
	int i;

	for (i = 0; p && (i < 2); i++, p++)
		p->disconnect(p->name, p->data);
	free(pstate);
	return 0;
}

static int restart_led_script_dofsm(long id, int *pstate)
{
	const struct gpio_led_desc *p;
	int state = (*pstate)++;

	switch (state) {
	case RB_ON1:
		for (p = gpio_ledd; p->name; p++)
			p->connect(p->name, p->data);
	/* fall through */
	case RB_ON2:
		for (p = gpio_ledd; p->name; p++)
			gpio_send_command(p->name, GPIOSLOUT);
		break;
	case RB_OFF1:
	case RB_OFF2:
		for (p = gpio_ledd; p->name; p++)
			gpio_send_command(p->name, GPIOSHOUT);
		break;
	default:
		p = &gpio_ledd[state - RB_RLQSH];
		p->disconnect(p->name, p->data);
		if ((p + 1)->name == NULL) {
			free(pstate);
			if (dev_event_current() & DF_REBOOTING)
				dev_event_set(0, DF_REBOOTING);
			restart_tid = 0;
			return 0;
		}
		break;
	}
	do {
		struct timeval tv = { .tv_sec = 0, };

		if (id == 0)
			tv.tv_usec = 500000;
		else if (state == RB_OFF2)
			tv.tv_usec = 200000;
		else
			return 1;

		restart_tid = itimer_creat((unsigned long)pstate,
				(void *)restart_led_script_dofsm, &tv);
	} while (0);

	return 0;
}

static int dev_restart_notify(struct notice_block *nb,
			u_int event, u_int full_event)
{
	if (event & full_event) {
		if (full_event & (DF_UPLOADING | DF_RSTASSERTED))
			dev_event_set(0, DF_REBOOTING);
		else if (restart_tid == 0)
			restart_led_script_dofsm(0, (int *)calloc(sizeof(int), 1));
	} else
		restart_tid = ({ itimer_cancel(restart_tid, (void *)cancel_led_script_fsm); 0; });
	return NOTICE_DONE;
}

static struct notice_block on_reboot_nb = {
	.notice_call = dev_restart_notify,
	.concern = DF_REBOOTING,
};

static int dev_restore_default_notify(struct notice_block *nb,
			u_int event, u_int full_event)
{
	if (event & full_event) {
		if (full_event & (DF_UPLOADING | DF_REBOOTING)) {
			if (full_event & DF_REBOOTING)
				dev_event_set(0, DF_REBOOTING);
		} else if (restart_tid == 0) {
#ifdef __CONFIG_LABORER_JOB_RELOAD__
			fprintf(stderr, "Going to Reload Default\n");
			yexecl(NULL, "sh -c \"{ flash reset /bin/preclean; reboot; }&\"");
#endif
			restart_led_script_dofsm(0, (int *)calloc(sizeof(int), 1));
		}
	} else
		restart_tid = ({ itimer_cancel(restart_tid, (void *)cancel_led_script_fsm); 0; });
	return NOTICE_DONE;
}

static struct notice_block on_restore_default_nb = {
	.notice_call = dev_restore_default_notify,
	.concern = DF_RSTASSERTED,
};

static int upload_led_script_dofsm(long id, int *pstate)
{
	const struct gpio_led_desc *p;
	int state = (*pstate)++;

	if (state == 0) {
		struct timeval tv = { .tv_sec = 1, .tv_usec = 0 };

		for (p = gpio_ledd; p->name; p++)
			p->connect(p->name, p->data);
		upload_tid = itimer_creat((unsigned long)pstate,
					(void *)upload_led_script_dofsm, &tv);
	}

	for (p = gpio_ledd; p->name; p++)
		gpio_send_command(p->name, (state & 1) ? GPIOSHOUT : GPIOSLOUT);
	return 1;
}

static int dev_upload_notify(struct notice_block *nb,
			u_int event, u_int full_event)
{
	if (event & full_event) {
		if (!upload_tid && !(full_event & (DF_REBOOTING | DF_RSTASSERTED)))
			upload_led_script_dofsm(0, (int *)calloc(sizeof(int), 1));
	} else
		upload_tid = ({ itimer_cancel(upload_tid, (void *)cancel_led_script_fsm); 0; });
	return NOTICE_DONE;
}

static struct notice_block on_upload_nb = {
	.notice_call = dev_upload_notify,
	.concern = DF_UPLOADING,
};

static int wps_led_script_dofsm(long id, int *pstate)
{
	const struct gpio_led_desc *p = gpio_wl_ledd;
	int i, state = (*pstate)++;

	if (state == 0) {
		struct timeval tv = { .tv_sec = 1, .tv_usec = 0 };

		for (i = 0; p && (i < 2); i++, p++)
			p->connect(p->name, p->data);
		wps_tid = itimer_creat((unsigned long)pstate,
					(void *)wps_led_script_dofsm, &tv);
	}

	for (i = 0; p && (i < 2); i++, p++)
		gpio_send_command(p->name, (state & 1) ? GPIOSHOUT : GPIOSLOUT);
	return 1;
}

static int dev_wps_notify(struct notice_block *nb,
			u_int event, u_int full_event)
{
	if (event & full_event) {
		if (!wps_tid && !(full_event & (DF_UPLOADING | DF_REBOOTING | DF_RSTASSERTED)))
			wps_led_script_dofsm(0, (int *)calloc(sizeof(int), 1));
	} else
		wps_tid = ({ itimer_cancel(wps_tid, (void *)cancel_wlan_led_script_fsm); 0; });
	return NOTICE_DONE;
}

static struct notice_block on_wps_nb = {
	.notice_call = dev_wps_notify,
	.concern = DF_WPSASSERTED,
};

static void __attribute__ ((constructor)) register_on_reboot_notice(void)
{
	const struct gpio_led_desc *p;

	for (p = gpio_ledd; p->name && !gpio_wl_ledd; p++) {
		if (!strcasecmp(p->name, __tostring(GPIO_LED_2G)) ||
		    !strcasecmp(p->name, __tostring(GPIO_LED_5G)))
			gpio_wl_ledd = p;
	}

	dev_event_chain_register(&on_reboot_nb);
	dev_event_chain_register(&on_restore_default_nb);
	dev_event_chain_register(&on_upload_nb);
	dev_event_chain_register(&on_wps_nb);
}
