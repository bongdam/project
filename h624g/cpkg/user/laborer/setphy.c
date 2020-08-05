#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <libytool.h>
#include <shutils.h>
#include <bcmnvram.h>
#include "instrument.h"
#include "cmd.h"

static long timer_id;
static int mask;

static int phyconfig(const char *cmd, int port)
{
	char buf[128], name[24];
	char *args[12];
	char *p;

	sprintf(name, "x_port_%d_config", port);
	p = nvram_get(name);
	if (p != NULL)
		snprintf(buf, sizeof(buf), "phyconfig %d %s", port, p);
	else
		snprintf(buf, sizeof(buf), "phyconfig %d up_auto_%srxpause_txpause",
			 port, (port != 4) ? "-" : "");
	if (ystrargs(buf, args, _countof(args), "_ \t\r\n", 0) > 2) {
		yexecv(args, NULL, 0, NULL);
		return 0;
	}
	return -1;
}

static int phyconf_worker(long id, unsigned long arg)
{
	int port;
	struct timeval tv = { .tv_sec = 1, .tv_usec = 0 };

	for (port = 4; port >= 0; port--) {
		if (mask & (1 << port))
			continue;
		mask |= (1 << port);
		phyconfig("up", port);
		yecho("/proc/gpio", "P%d0\n", port + 2);
		if (id == 0)
			timer_id = itimer_creat(0, phyconf_worker, &tv);
		return 1;
	}
	timer_id = 0;
	return 0;
}

static int mod_setphy(int argc, char **argv, char *response_pipe)
{
	int port, fd = open_reply_pipe(response_pipe);

	if (argc > 1) {
		if (!strcmp(argv[1], "down")) {
			for (port = 4; port >= 0; port--) {
				yexecl(NULL, "phyconfig %d down", port);
				yecho("/proc/gpio", "p%d1\n", port + 2);
			}
		} else if (!strcmp(argv[1], "up") && timer_id == 0) {
			mask = 0;
			phyconf_worker(0, 0);
		}
	}
	if (fd > -1) {
		dprintf(fd, "\n");	/* to wake up reader */
		close(fd);
	}
	return 0;
}

static void __attribute__ ((constructor)) register_setphy_module(void)
{
	fifo_cmd_register("setphy", NULL,
			"configure switch ports in background", mod_setphy);
}
