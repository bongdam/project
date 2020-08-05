#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <signal.h>
#include <alloca.h>
#include <nmpipe.h>
#include "dvbox.h"

extern int fifo_sendreq(const char *command);
static struct nmpipe *namedp = NULL;

static void signal_handler(int sig, siginfo_t *siginfo, void *notused)
{
	if (namedp)
		unlink(namedp->path);
	exit(EXIT_FAILURE);
}

static int preq_main(int argc, char **argv)
{
	struct sigaction sa;
	char *p, buf[512];
	int i, len, opt, cont = 0, intvl = 2;

	while ((opt = getopt(argc, argv, "ti:")) != -1) {
		switch (opt) {
		case 't':
			cont = 1;
			break;
		case 'i':
			intvl = strtol(optarg, NULL, 0);
			if (intvl <= 0)
				intvl = 2;
			break;
		}

	}
	if (optind >= argc) {
		fprintf(stderr, "Must take at least command name as parameter\n");
		return 0;
	}

	for (i = optind, len = 0; i < argc; i++)
		len += (strlen(argv[i]) + 2);
	p = (char *)alloca(len);
	len = sprintf(p, "%s", argv[optind]);
 	for (i = optind + 1; i < argc; i++)
		len += sprintf(&p[len], " %s", argv[i]);

	sa.sa_sigaction = signal_handler;
	sigemptyset(&sa.sa_mask);
	sa.sa_flags = SA_SIGINFO;
	sigaction(SIGINT, &sa, 0);	/* Interrupt (ANSI).  */

	namedp = prequest(p);
	if (namedp) {
		do {
			while (presponse(namedp, buf, sizeof(buf)) > 0)
				fprintf(stdout, "%s", buf);
		} while (cont && ({ sleep(intvl); 1; }) && fifo_sendreq(p) > 0);
		prelease(namedp);
	}
	return 0;
}
REG_APL_LEAF(preq);
