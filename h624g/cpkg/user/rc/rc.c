#include <stdio.h>
#include <stdlib.h>
#include <limits.h>
#include <time.h>
#include <unistd.h>
#include <errno.h>
#include <syslog.h>
#include <signal.h>
#include <fcntl.h> /* for open */
#include <string.h>
#include <sys/klog.h>
#include <sys/types.h>
#include <sys/mount.h>
#include <sys/reboot.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <sys/time.h>
#include <sys/utsname.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <sys/utsname.h> /* for uname */
#include <net/if_arp.h>
#include <dirent.h>

#include <shutils.h>
#include <libytool.h>
#include "rc.h"

static int noconsole = 0;

static void
sysinit(void)
{
	const char **p;
	const char *rwdirs[] = {
		"/var/tmp",	"/var/web",	"/var/log",
		"/var/run",	"/var/lock",	"/var/system",
		"/var/dnrd",	"/var/lib",	"/var/lib/misc",
		"/var/home",	"/var/linuxigd",
		"/var/udhcpc",	"/var/udhcpd",
		/* pptp */
		"/var/ppp",	"/var/ppp/peers",
		/* samba */
		"/var/config",	"/var/private",	"/var/tmp/usb",
		/*"/var/net-snmp",*/
		"/var/myca",
		"/var/1x",
		NULL
	};

	/* /proc */
	mount("proc", "/proc", "proc", MS_MGC_VAL, NULL);
	/* /var */
	mount("ramfs", "/var", "ramfs", MS_MGC_VAL, NULL);

	for (p = rwdirs; *p; p++)
		mkdir(*p, 0777);

	yexecl("2>/dev/null", "cp /etc/tmp/pics* /var/linuxigd");
	yexecl(NULL, "cp /bin/pppoe.sh /var/ppp/true");
	yexecl(NULL, "cp /etc/shadow.sample /var/shadow");
}

/* States */
enum {
	RESTART,
	STOP,
	START,
	TIMER,
	IDLE
};
static int state = START;
static int signalled = -1;

static void
rc_signal(int sig)
{
	if (sig == SIGHUP) {
		dprint("signalling RESTART\n");
		signalled = RESTART;
	}
	else if (sig == SIGUSR2) {
		dprint("signalling START\n");
		signalled = START;
	}
	else if (sig == SIGINT) {
		dprint("signalling STOP\n");
		signalled = STOP;
	}
	else if (sig == SIGALRM) {
		dprint("signalling TIMER\n");
		signalled = TIMER;
	}
}

int
do_timer(void)
{
	return 0;
}

/* Main loop */
static void
main_loop(void)
{
	sigset_t sigset;
	pid_t shell_pid = 0;

	/* Basic initialization */
	sysinit();

	/* Setup signal handlers */
	signal_init();
	signal(SIGHUP, rc_signal);
	signal(SIGUSR2, rc_signal);
	signal(SIGINT, rc_signal);
	signal(SIGALRM, rc_signal);
	sigemptyset(&sigset);

	/* Add loopback */
	config_loopback();

	/* Loop forever */
	for (;;) {
		switch (state) {
		case RESTART:
			dprint("RESTART\n");
			/* Fall through */
		case STOP:
			dprint("STOP\n");
			if (state == STOP) {
				state = IDLE;
				break;
			}
			/* Fall through */
		case START:
			dprint("START\n");
			/* Fall through */
		case TIMER:
			dprint("TIMER\n");
			do_timer();
			/* Fall through */
		case IDLE:
			dprint("IDLE\n");
			state = IDLE;
			/* Wait for user input or state change */
			while (signalled == -1) {
				if (!noconsole && (!shell_pid || kill(shell_pid, 0) != 0))
					shell_pid = run_shell(0, 1);
				else {

					sigsuspend(&sigset);
				}
			}
			state = signalled;
			signalled = -1;
			break;
		default:
			dprint("UNKNOWN\n");
			return;
		}
	}
}

int
main(int argc, char **argv)
{
	const char *base = base_name(argv[0]);

	/* init */
	if (strstr(base, "preinit") || strstr(base, "init")) {
		main_loop();
		return 0;
	}

	/* Set TZ for all rc programs */
	//setenv("TZ", nvram_safe_get("time_zone"), 1);

	/* rc [stop|start|restart ] */
	if (strstr(base, "rc")) {
		if (argv[1]) {
			if (strncmp(argv[1], "start", 5) == 0)
				return kill(1, SIGUSR2);
			else if (strncmp(argv[1], "stop", 4) == 0)
				return kill(1, SIGINT);
			else if (strncmp(argv[1], "restart", 7) == 0)
				return kill(1, SIGHUP);
		} else {
			fprintf(stderr, "usage: rc [start|stop|restart]\n");
			return EINVAL;
		}
	}
#ifdef __RTK_EQUIVALENT__
#ifdef __CONFIG_NAT__
	/* ppp */
	else if (strstr(base, "ip-up"))
		return ipup_main(argc, argv);
	else if (strstr(base, "ip-down"))
		return ipdown_main(argc, argv);
	/* udhcpc [ deconfig bound renew ] */
	else if (strstr(base, "udhcpc"))
		return udhcpc_wan(argc, argv);
#endif	/* __CONFIG_NAT__ */
	/* ldhclnt [ deconfig bound renew ] */
	else if (strstr(base, "ldhclnt"))
		return udhcpc_lan(argc, argv);
	/* stats [ url ] */
	else if (strstr(base, "stats"))
		return http_stats(argv[1] ? : nvram_safe_get("stats_server"));
	/* erase [device] */
	else if (strstr(base, "erase")) {
		if (argv[1] && ((!strcmp(argv[1], "boot")) ||
			(!strcmp(argv[1], "linux")) ||
			(!strcmp(argv[1], "linux2")) ||
			(!strcmp(argv[1], "rootfs")) ||
			(!strcmp(argv[1], "rootfs2")) ||
			(!strcmp(argv[1], "confmtd")) ||
			(!strcmp(argv[1], "nvram")))) {

			return mtd_erase(argv[1]);
		} else {
			fprintf(stderr, "usage: erase [device]\n");
			return EINVAL;
		}
	}
	/* write [path] [device] */
	else if (strstr(base, "write")) {
		if (argc >= 3)
			return mtd_write(argv[1], argv[2]);
		else {
			fprintf(stderr, "usage: write [path] [device]\n");
			return EINVAL;
		}
	}
	/* hotplug [event] */
	else if (strstr(base, "hotplug")) {
		if (argc >= 2) {
			if (!strcmp(argv[1], "net"))
				return hotplug_net();
			else if (!strcmp(argv[1], "usb"))
				return hotplug_usb();
			else if (!strcmp(argv[1], "block"))
				return hotplug_block();
#if defined(LINUX_2_6_36)
			else if (!strcmp(argv[1], "platform"))
				return coma_uevent();
#endif /* LINUX_2_6_36 */
		} else {
			fprintf(stderr, "usage: hotplug [event]\n");
			return EINVAL;
		}
	}
#endif
	return EINVAL;
}
