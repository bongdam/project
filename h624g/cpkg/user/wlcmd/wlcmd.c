#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdarg.h>
#include <unistd.h>

#include <libytool.h>
#include "wlcmd.h"
#include "wl_iwpriv.h"

char *program_name;
char interface[12] = "wlan0";   /* default: 5GHz */
char file[24];

extern int optind;
extern int opterr;
extern char *optarg;

/*---------------------------------------------------------------------------*/
static void mkfile(void)
{
	sprintf(file, "/proc/dv_%s/wl_cmd", interface);
}

static void usage(void)
{
	mkfile();

	fprintf(stderr, "Usage: %s [<options>] command\n", program_name);
	fprintf(stderr, "-i <interface>: WLAN interface (wlan0, wlan1)\n");
	fprintf(stderr, "-n <counts>: the number of frames to send\n");
	fprintf(stderr, "-d <ms>: delay(interval) of each frames to send\n");
	fprintf(stderr, "\n");
	fprintf(stderr, "command:\n");
	wl_iwpriv_cmd_table_print(stderr);
	yfecho(file, O_WRONLY|O_CREAT|O_TRUNC, 0644, "help\n");
	yexecl(NULL, "cat %s", file);
	exit(1);
}

/*---------------------------------------------------------------------------*/
static int wl_iwpriv_command_processing(int argc, char **argv)
{
	char *p, buf[100];
	
	if (wl_iwpriv_cmd_supported(argv[0])) {
		if (argc > 1) {
			wl_iwpriv_set_mib(interface, argv[0], argv[1]);
		} else {
			p = wl_iwpriv_get_mib(interface, argv[0], buf, sizeof(buf));
			if (p) {
				printf("%s\n", p);
			}
		}
		return (1);
	}

	return (0);
}

/*---------------------------------------------------------------------------*/

int main(int argc, char **argv)
{
	int op, i, log_flag;
	char *cp;
	char buf[200], cmd[80];
	int loop_count=0, interval_ms=0;
	int dump_mode=0;

	if ((cp = strrchr(argv[0], '/')) != NULL)
		program_name = cp + 1;
	else
		program_name = argv[0];

	opterr = 0;
	while ((op = getopt(argc, argv, "i:n:d:h")) != -1) {
		switch (op) {
		case 'i':
			snprintf(interface, sizeof(interface), "%s", optarg);
			break;

		case 'n':
			loop_count = atoi(optarg);
			break;

		case 'd':
			interval_ms = atoi(optarg)*1000;
			break;

		case 'h':
		default:
			usage();
			/* NOTREACHED */
		}
	}

	mkfile();

	if (optind>=argc)
		usage();

	/* check iwpriv mib control */
	if (wl_iwpriv_command_processing(argc-optind, &argv[optind])) {
		return (0);
	}

	/* to enable log by "set_mib", ioctl */
	i = optind;
	if ((i+1) < argc) {
		if (!strcmp(argv[i], "log_flag")) {
			log_flag = strtoul(argv[i+1], NULL, 0);
			sprintf(cmd, "rssi%s %d", strcmp(interface, "wlan0")?"1":"",
									  (log_flag&3)?1:0);
			yexecl(NULL, cmd);
		} else if (!strcmp(argv[i], "dump")) {
			dump_mode = 1;
		}
	}

	/* merge argvs to buffer*/
	for (i=optind, buf[0]='\0'; i<argc; i++) {
		sprintf(buf+strlen(buf), " %s", argv[i]);
	}
	if (buf[0]=='\0') {
		usage();
		return (0);
	}

	if (!strcmp(argv[optind], "frame_send")) {
		do {
			yfecho(file, O_WRONLY|O_CREAT|O_TRUNC, 0644, "%s\n", buf);
			if (interval_ms > 0) {
				usleep(interval_ms);
			}
		} while (--loop_count > 0);
	} else {
		/* normal commands */
		yfecho(file, O_WRONLY|O_CREAT|O_TRUNC, 0644, "%s\n", buf);
	}

	/* print out results */
	if ((optind+1)==argc || dump_mode) {
		yexecl(NULL, "cat %s", file);
	}

    return (0);
}

