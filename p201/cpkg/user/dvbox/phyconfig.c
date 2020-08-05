#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <brdio.h>
#include "dvbox.h"

#define BRDIO_FILE  "/proc/brdio"

#define B "\033[1m"
#define R "\033[0m"

static const char *manpage =\
B"NAME\n\t"R"phyconfig - configure NIC PHY per port\n"
B"SYNOPSIS"R"\n"
"\tphyconfig [port-no]\n"
"\tphyconfig port-no options\n"
B"DESCRIPTION"R"\n"
"\tPhyconfig is used to configure the kernel-resident NIC port configuration.\n"
B"PORT-NO"R"\n"
"\tPort number "B"0"R","B"1"R","B"2"R","B"3"R" and "B"4"R" available\n"
B"OPTIONS"R"\n"
"\t"B"auto"R"\n"
"\t\tThis parameter sets auto negotation and ignores "B"duplex"R" and "B"speed"R", if any.\n"
"\t"B"duplex type"R"\n"
"\t\tSet the duplex for the specified port. type includes "B"full"R" and "B"half"R"\n"
"\t"B"speed value"R"\n"
"\t\tSet the speed for the specified port. value includes "B"10"R", "B"100"R" and "B"1000"R"\n"
"\t"B"[-]rxpause"R"\n"
"\t\tEnable or disable RX pause control per port.\n"
"\t"B"[-]txpause"R"\n"
"\t\tEnable or disable TX pause control per port.\n";

/*
 * Here are the bit masks for the "flags" member of struct options below.
 * N_ signifies no arg prefix; M_ signifies arg prefixed by '-'.
 * CLR clears the flag; SET sets the flag; ARG signifies (optional) arg.
 */
#define N_CLR            0x01
#define M_CLR            0x02
#define N_SET            0x04
#define M_SET            0x08
#define N_ARG            0x10
#define M_ARG            0x20

#define M_MASK           (M_CLR | M_SET | M_ARG)
#define N_MASK           (N_CLR | N_SET | N_ARG)
#define SET_MASK         (N_SET | M_SET)
#define CLR_MASK         (N_CLR | M_CLR)
#define SET_CLR_MASK     (SET_MASK | CLR_MASK)
#define ARG_MASK         (M_ARG | N_ARG)

struct arg1opt {
	const char *name;
	const unsigned char flags;
	const unsigned int selector;
};

struct options {
	const char *name;
	const unsigned char flags;
	const struct arg1opt *argop;
	const unsigned int selector;
};

static const struct arg1opt ArgDuplex[] = {
	{ "full",   N_SET,      PHF_FDX },
	{ "half",   N_CLR,      PHF_FDX },
	{ NULL,     0,          0 }
};

static const struct arg1opt ArgSpeed[] = {
	{ "10",     N_SET,      PHF_10M },
	{ "100",    N_SET,      PHF_100M },
	{ "1000",   N_SET,      PHF_1000M },
	{ "1G",     N_SET,      PHF_1000M },
	{ NULL,     0,          0 }
};

static const struct options OptArray[] = {
	{ "up",          N_SET,         NULL,       PHF_PWRUP },
	{ "down",        N_CLR,         NULL,       PHF_PWRUP },
	{ "auto",        N_SET,         NULL,       PHF_AUTONEG },
	{ "duplex",      N_ARG | N_CLR, ArgDuplex,  PHF_AUTONEG },
	{ "speed",       N_ARG | N_CLR, ArgSpeed,   PHF_AUTONEG | PHF_SPEEDMASK },
	{ "rxpause",     N_SET | M_CLR, NULL,       PHF_RXPAUSE },
	{ "txpause",     N_SET | M_CLR, NULL,       PHF_TXPAUSE },
	{ "force",       N_SET,         NULL,       PHF_OVERWREG },
	{ "reset",       N_SET,         NULL,       PHF_RESET },
	{ NULL,          0,             NULL,       0 }
};

static int display_phystatus(const char *appname, const char *portno)
{
	int fd;
	int i, s = PH_MINPORT, e = PH_MAXPORT;
	char *p;
	struct phreq phr;
	char buffer[256];
	int n;

	if (portno && !strcmp(portno, "--help"))
		fprintf(stdout, "%s\n", manpage);
	else {
		if (portno) {
			s = (int)strtol(portno, &p, 10);
			if (*p || s < PH_MINPORT || s > PH_MAXPORT)
				error_msg_and_die("%s: invalid port: '%s'", appname, portno);
			e = s;
		}

		fd = open(BRDIO_FILE, O_RDWR);
		if (fd < 0)
			error_msg_and_die("%s: %s: %m", appname, BRDIO_FILE);

		for (i = s; i <= e; i++) {
			memset(&phr, 0, sizeof(phr));
			phr.phr_port = i;
			if (ioctl(fd, PHGIO, &phr)) {
				perror("PHGIO");
				break;
			}

			n = sprintf(buffer, "Port%d\tLink state is ", i);
			if (!(phr.phr_optmask & PHF_LINKUP))
				sprintf(&buffer[n], "DOWN.\n\n");
			else
				sprintf(&buffer[n], "UP. Duplex is %s with %s.\n"
					"\tRx pause is %s and TX pause is %s.\n"
					"\tForce mode %s. EEE %s\n\n",
					(phr.phr_optmask & PHF_FDX ? "FULL" : "HALF"),
					((phr.phr_optmask & PHF_10M) ? "10Mbps" :
					 ((phr.phr_optmask & PHF_100M) ? "100Mbps" :
					  ((phr.phr_optmask & PHF_1000M) ? "1Gbps" :
					   ((phr.phr_optmask & PHF_500M) ? "500M" : "UNKNOWN")))),
					phr.phr_optmask & PHF_RXPAUSE ? "ENABLED" : "DISABLED",
					phr.phr_optmask & PHF_TXPAUSE ? "ENABLED" : "DISABLED",
					((phr.phr_optmask & PHF_ENFORCE_POLL) ? "POLLING LINK-UP" :
					 ((phr.phr_optmask & PHF_ENFORCE_NO_AUTONEG) ? "OFF-AUTO-NEG" : "DISABLED")),
					 (phr.phr_optmask & PHF_EEE) ? "ENABLED" : "DISABLED");

			printf(buffer);
		}
		close(fd);
	}

	return 0;
}

static int phyconfig_main(int argc, char **argv)
{
	struct phreq phr;
	char *p, *q;
	unsigned char mask;
	const struct options *op;
	const struct arg1opt *ao;
	int fd;
	const char *appname = "phyconfig";

	++argv;
	--argc;

	if (argc <= 1)
		return display_phystatus(appname, argc ? *argv : NULL);

	memset(&phr, 0, sizeof(phr));
	phr.phr_port = (int)strtol(*argv, &p, 10);
	if (*p || phr.phr_port < PH_MINPORT || phr.phr_port > PH_MAXPORT)
		error_msg_and_die("%s: invalid port: '%s'", appname, *argv);

	while (*++argv != NULL) {
		p = *argv;
		mask = N_MASK;
		if (*p == '-') {
			p++;
			mask = M_MASK;
		}

		for (op = OptArray; op->name; op++) {	/* Find table entry. */
			if (strcmp(p, op->name) == 0) {	/* If name matches... */
				mask &= op->flags;
				if (mask)	/* set the mask and go. */
					goto FOUND_ARG;
				/* If we get here, there was a valid arg with an */
				/* invalid '-' prefix. */
				error_msg_and_die("%s: bad: '%s'", appname, p - 1);
			}
		}

		error_msg_and_die("%s: invalid option: '%s'", appname,
				  (mask == N_MASK) ? p : p - 1);

 FOUND_ARG:
		if ((mask & SET_MASK)) {
			phr.phr_option |= op->selector;
			phr.phr_optmask |= op->selector;
		} else if ((mask & CLR_MASK)) {
			phr.phr_option &= ~op->selector;
			phr.phr_optmask |= op->selector;
		}

		if (mask & ARG_MASK) {
			if (op->argop) {
				q = *++argv;
				if (!q)
					error_msg_and_die("%s: need argument: '%s'", appname, p);

				for (ao = op->argop; ao->name; ao++) {
					if (strcmp(q, ao->name) == 0) {
						if (ao->flags & N_SET) {
							phr.phr_option |= ao->selector;
							phr.phr_optmask |= ao->selector;
						} else if (ao->flags & N_CLR) {
							phr.phr_option &= ~ao->selector;
							phr.phr_optmask |= ao->selector;
						}
						break;
					}
				}
				if (!ao->name)
					error_msg_and_die("%s: invalid argument: '%s'", appname, q);
			}
		}
	}

	fd = open(BRDIO_FILE, O_RDWR);
	if (fd < 0)
		error_msg_and_die(BRDIO_FILE ": %m");
	if (ioctl(fd, PHSIO, &phr))
		perror("PHSIO");
	close(fd);
	return 0;
}
REG_APL_LEAF(phyconfig);
