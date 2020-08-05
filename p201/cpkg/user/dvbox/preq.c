#define _GNU_SOURCE
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <signal.h>
#include <nmpipe.h>
#include "dvbox.h"

static struct nmpipe *namedp = NULL;

void signal_handler(int sig, siginfo_t *siginfo, void *notused)
{
	prelease(namedp);
	exit(1);
}

static int fifocmd_main(int argc, char **argv, const char *pathname)
{
	struct sigaction sa;
	char *p, buf[512];
	int i, len;

	if (argc < 2) {
		fprintf(stderr, "Must take at least command name as parameter\n");
		return 0;
	}
	argc--; argv++;

	for (i = len = 0; i < argc; i++)
		len += (strlen(argv[i]) + 2);
	p = (char *)malloc(len);
	len = sprintf(p, "%s", argv[0]);
	for (i = 1; i < argc; i++)
		len += sprintf(&p[len], " %s", argv[i]);

	sa.sa_sigaction = signal_handler;
	sigemptyset(&sa.sa_mask);
	sa.sa_flags = SA_SIGINFO;
	sigaction(SIGINT, &sa, 0);	/* Interrupt (ANSI).  */

	namedp = prequest(p, pathname);
	if (namedp) {
		while (1) {
			if (presponse(namedp, buf, sizeof(buf)) <= 0)
				break;
			fprintf(stdout, "%s", buf);
		}
		prelease(namedp);
	}
	free(p);
	return 0;
}

static int preq_main(int argc, char **argv)
{
	return fifocmd_main(argc, argv, "/var/laborer");
}
REG_APL_LEAF(preq);
