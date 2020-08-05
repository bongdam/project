#include <stdio.h>
#include <errno.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sched.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <sys/poll.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/mman.h>
#include <ctype.h>

#include <dvflag.h>
#include <brdio.h>
#include <bcmnvram.h>
#include <libytool.h>
#include <shutils.h>
#include <furl.h>
#include <nmpipe.h>

#define MAX_TRY     4
#define MAX_TIMEO   4000
#define DEV_STATS_POS_RX_CRC   1

int wmmmap_main(int argc, char *argv[]);
int mping_main(int argc, char **argv);

static int safe_strtoul(const char *nptr, unsigned int *ulptr, int base)
{
	char *endptr;
	unsigned int tmp;
	int saved_errno = errno;

	if (!nptr || !nptr[0])
		return -1;
	errno = 0;
	tmp = strtoul(nptr, &endptr, base);
	if (errno)
		return -1;

	if (!endptr || *endptr) {
		errno = EINVAL;
		return -1;
	}

	errno = saved_errno;
	*ulptr = tmp;
	return 0;
}

static int dvflag_main(int argc, char *argv[])
{
	int i, fd, verbose = 1;
	unsigned int flag;
	unsigned int val[2];
	struct {
		unsigned flg;
		const char *name;
	} maps[] = {
		{ DF_WANLINK, "WANLINK" },
		{ DF_LANLINK1, "LANLINK1" },
		{ DF_LANLINK2, "LANLINK2" },
		{ DF_LANLINK3, "LANLINK3" },
		{ DF_LANLINK4, "LANLINK4" },
		{ DF_WANBOUND, "WANBOUND" },
		{ DF_LANBOUND, "LANBOUND" },
		{ DF_IPADDRDUP, "IPADDRDUP" },
		{ DF_UPLOADING, "UPLOADING" },
		{ DF_SOFTRESET, "SOFTRESET" },
		{ DF_IGMPQUERYRCV, "IGMPQUERYRCV" },
		{ DF_NTPSYNC, "NTPSYNC" },
		{ DF_INITED, "INITED" },
		{ DF_WLCLNT_UP, "WLCLNT_UP" }, /* APACRTL-94 */
		{ 0, NULL} };

	fd = open("/proc/dvflag", O_RDWR);
	if (fd != -1) {
		if (argc == 3) {
			for (i = 0; maps[i].name; i++) {
				if (!strcmp(maps[i].name, argv[1])) {
					val[0] = (atoi(argv[2])) ? maps[i].flg : 0;
					val[1] = maps[i].flg;
					write(fd, val, sizeof(val));
					verbose = 0;
					break;
				}
			}
		}
		read(fd, (void *)&flag, sizeof(int));
		close(fd);
		for (i = 0; verbose && maps[i].name; i++)
			printf("%s=%d\n", maps[i].name, !!(flag & maps[i].flg));
		exit(EXIT_SUCCESS);
		return 0;
	}
	exit(EXIT_FAILURE);
	return -1;
}

static void mio_usage(int op)
{
	if (op == 0)
		fprintf(stderr, "Usage: md <address> <length>\n");
	else
		fprintf(stderr, "Usage: mm -bhw <address> <value>\n");
	exit(EXIT_SUCCESS);
}

static void mdisp(unsigned char *p, unsigned int s, unsigned char *base)
{
	int i, c;

	while ((int)s > 0) {
		printf("%08x: ", (unsigned int)base);

		for (i = 0; i < 16; i++) {
			if (i < (int)s)
				printf("%02x ", p[i] & 0xFF);
			else
				printf("   ");

			if (i == 7)
				printf(" ");
		}
		printf(" |");
		for (i = 0; i < 16; i++) {
			if (i < (int)s) {
				c = p[i] & 0xFF;
				if ((c < 0x20) || (c >= 0x7F))
					c = '.';
			} else
				c = ' ';

			printf("%c", c);
		}
		printf("|\n");
		s -= 16;
		p += 16;
		base += 16;
	}
}

static struct mareq *mkcmd(char *paddr, char *plen, char *pval)
{
	struct mareq *req;
	unsigned int addr;
	unsigned int len;
	unsigned int val;

	if (safe_strtoul(paddr, &addr, 16) ||
	    safe_strtoul(plen, &len, 0) ||
	    (pval && safe_strtoul(pval, &val, 0)))
		return NULL;

	if (len > 0x1000)
		len = 0x1000;

	req = (struct mareq *)malloc(sizeof(*req) + ((len + 3) & ~3));
	if (req) {
		req->mar_addr = addr;
		req->mar_len = len;
		if (pval)
			memcpy(&req->buf, &((char *)&val)[4 - len], len);	/* big-endian */
	}

	return req;
}

static int md(int argc, char **argv)
{
	struct mareq *req;
	int fd, good = 0;

	if (argc != 3)
		mio_usage(0);

	req = mkcmd(argv[1], argv[2], NULL);
	if (!req) {
		perror("md");
		exit(EXIT_FAILURE);
	}

	fd = open("/proc/brdio", O_RDWR);
	if (fd != -1) {
		good = !ioctl(fd, MIO_READ, req);
		close(fd);
	}

	if (good)
		mdisp((unsigned char *)req->buf, req->mar_len,
		      (unsigned char *)req->mar_addr);

	free(req);
	return 0;
}

static int mm(int argc, char **argv)
{
	struct mareq *req;
	int fd, len = 0, good = 0;
	char *thisarg;
	char tmp[16];

	argc--;
	argv++;
	/* Parse any options */
	while (argc >= 1 && **argv == '-') {
		thisarg = *argv;
		thisarg++;

		switch (*thisarg) {
		case 'b':
			len = 1;
			break;
		case 'h':
			len = 2;
			break;
		case 'w':
			len = 4;
			break;
		default:
			mio_usage(1);
			break;
		}
		argc--;
		argv++;
	}

	if (len == 0 || argc != 2)
		mio_usage(1);

	sprintf(tmp, "%d", len);
	req = mkcmd(argv[0], tmp, argv[1]);
	if (!req) {
		perror("mm");
		exit(EXIT_FAILURE);
	}

	fd = open("/proc/brdio", O_RDWR);
	if (fd != -1) {
		good = !ioctl(fd, MIO_WRITE, req);
		close(fd);
	}

	if (!good)
		fprintf(stderr, "mm error: %s\n", strerror(errno));

	free(req);
	return 0;
}

static int do_wget(struct fwstat *fbuf, int *exp, int timeo, const char *url)
{
	char cmd[256];
	int try;
	long begin, delay;

	snprintf(cmd, sizeof(cmd), "wget -q -O - \"%s\"", url);
	for (try = 0; try < MAX_TRY; try++) {
		begin = ygettime(NULL);
		/* put the 5 mins cap */
		delay = (*exp < 7) ? (3 * (1 << *exp)) : 300;
		delay += ((rand() % 3) + 1);
		++*exp;
		if (!furl(cmd, timeo, (p_read_f)fw_read_callback, (void *)fbuf))
			return (!fbuf->lasterror && fbuf->rcvlen > 0) ? 0 : -1;

		delay -= ((long)ygettime(NULL) - begin);
		if (delay > 0)
			sleep(delay);
	}
	return -1;
}

static int furl_main(int argc, char **argv)
{
	struct fwstat fbuf;
	char *mm;
	int exp, status;

	if (argc < 2)
		exit(EXIT_FAILURE);

	mm = mmap(NULL, MAX_FWSIZE, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
	if (mm == MAP_FAILED) {
		perror("mmap");
		exit(EXIT_FAILURE);

	}
	exp = 0;

	memset(&fbuf, 0, sizeof(fbuf));
	fbuf.fmem = mm;
	fbuf.caplen = MAX_FWSIZE;
	if (do_wget(&fbuf, &exp, MAX_TIMEO, argv[1]) == 0) {
		fprintf(stderr, "Image length %d\n", fbuf.rcvlen);
		fw_parse_bootline(&fbuf.blnfo);
		status = fw_validate(&fbuf);
		if (!status && !(status = fw_dualize(&fbuf))) {
			status = fw_write(&fbuf, NULL, NULL);
			if (!status) {
				munmap(mm, MAX_FWSIZE);
				mm = MAP_FAILED;
				fprintf(stderr, "Upgrade done successfully\n");
				exit(EXIT_SUCCESS);
			}
		}
	} else
		status = -EGETFW;

	if (mm != MAP_FAILED)
		munmap(mm, MAX_FWSIZE);

	fprintf(stderr, "%s\n", fw_strerror(status));
	exit(EXIT_FAILURE);
	return 0;
}

static int validate_bootversion(char *bver)
{
	int i, len = strlen(bver);

	if (len != 4 || bver[0] != 'V')
		return -1;
	for (i = 1; i < 4; i++)
		if (!isalnum(bver[i]))
			return -1;
	return 0;
}

static int current_bootversion(char *bver, int len)
{
	struct mareq *req;
	int fd;

	req = mkcmd("0xbd00000c", "4", NULL);	/* 12 bytes offset */
	if (!req)
		return -1;
	memset(bver, 0, len);
	fd = open("/proc/brdio", O_RDWR);
	if (fd != -1) {
		if (!ioctl(fd, MIO_READ, req))
			memcpy(bver, req->buf, 4);
		close(fd);
	}
	free(req);

	return validate_bootversion(bver);
}

static int upboot(int argc, char **argv)
{
	struct stat sb;
	char bver[8];
	char buffer[8];
	struct fwstat fbuf;
	int fd, opt, status = -1, force = 0;

	while ((opt = getopt(argc, argv, "f")) != -1) {
		switch (opt) {
		case 'f':
			force = 1;
			break;
		default:
			exit(EXIT_FAILURE);
		}
	}

	if (optind >= argc)
		exit(EXIT_FAILURE);

	if (argc < 2 || lstat(argv[optind], &sb) || sb.st_size < USHRT_MAX)
		exit(EXIT_FAILURE);

	if (current_bootversion(bver, sizeof(bver)))
		exit(EXIT_FAILURE);

	memset(&fbuf, 0, sizeof(fbuf));
	fd = open(argv[optind], O_RDONLY);
	if (fd < 0)
		exit(EXIT_FAILURE);
	lseek(fd, 0x1c, SEEK_SET);
	read(fd, buffer, 4);
	buffer[4] = '\0';
	if (validate_bootversion(buffer) || (!force && strcmp(bver, buffer) >= 0))
		goto abort;

	lseek(fd, 0, SEEK_SET);
	fprintf(stderr, "replacing %c.%c.%c with %c.%c.%c bootrom\n",
		bver[1], bver[2], bver[3], buffer[1], buffer[2], buffer[3]);

	fbuf.fmem = (char *)malloc(sb.st_size);
	fbuf.caplen = fbuf.rcvlen = sb.st_size;
	if (fbuf.fmem == NULL) {
		perror("upboot");
		goto abort;
	}
	if (sb.st_size != read(fd, fbuf.fmem, sb.st_size)) {
		perror("lacking count");
		goto abort;
	}

	status = fw_validate(&fbuf);
	if (!status) {
		status = fw_write_back(&fbuf, NULL, NULL, NULL, NULL);
		if (!status)
			fprintf(stdout, "Upgrading boot done\n");
	}
abort:
	if (fbuf.fmem)
		free(fbuf.fmem);
	close(fd);

	return status;
}

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

static void error_msg_and_die(const char *fmt, ...)
{
	va_list va;

	va_start(va, fmt);
	vfprintf(stderr, fmt, va);
	va_end(va);
	fprintf(stderr, "\n");
	exit(EXIT_FAILURE);
}

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
			error_msg_and_die("%s: %s: %s", appname, BRDIO_FILE, strerror(errno));

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
		error_msg_and_die(BRDIO_FILE ": %s", strerror(errno));
	if (ioctl(fd, PHSIO, &phr))
		perror("PHSIO");
	close(fd);
	return 0;
}

static void mirror_nvram_parse(int *on, int *from, int *to)
{
	char *p;
	char val[40];
	char *p_on, *p_f, *p_t;

	*on = *from = *to = 0;
	p_on = p_f = p_t = NULL;

	p = nvram_get("x_mirror");
	if (p) {
		strncpy(val, p, sizeof(val)-1);
		val[sizeof(val)-1]=0;

		p_on = strtok(val, "_\r\n");
		if (p_on) p_f = strtok(NULL, "_\r\n");
		if (p_f)  p_t = strtok(NULL, "_\r\n");

		if (p_on) *on   = (strcmp(p_on, "on")==0) ? 1:0;
		if (p_f)  *from = strtol(p_f, NULL, 0);
		if (p_t)  *to   = strtol(p_t, NULL, 0);
	}
}

static int mirror_main(int argc, char *argv[])
{
	int on, from, to;
	char cmd[80];

	if (argc < 2)
		goto usage_mirror;

	if (strcmp(argv[1], "clear")==0) {
		nvram_set("x_mirror", "off_0_0");
		nvram_commit();
		on = from = to = 0;
	} else if (strcmp(argv[1], "set")==0) {
		if (argc < 4)
			goto usage_mirror;
		on = 1;
		from = strtol(argv[2], NULL, 0);
		to = strtol(argv[3], NULL, 0);
		snprintf(cmd, sizeof(cmd), "on_%d_%d", from, to);
		nvram_set("x_mirror", cmd);
		nvram_commit();
	} else if (strcmp(argv[1], "print")==0) {
		mirror_nvram_parse(&on, &from, &to);
		fprintf(stdout, "%d,%d,%d", on, from, to);
		return 0;
	} else if (strcmp(argv[1], "apply")==0) {
		mirror_nvram_parse(&on, &from, &to);
	} else {
		goto usage_mirror;
	}

	// apply mirror to system
	if (on)
		yfecho("/proc/rtl865x/mirrorPort", O_WRONLY, 0644, "mirror %d %d %d\n", 1<<from, 1<<from, 1<<to);
	else
		yfecho("/proc/rtl865x/mirrorPort", O_WRONLY, 0644, "mirror 0 0 0\n");

	return 0;

usage_mirror:
	fprintf(stderr, "Usage: mirror apply|clear\n");
	fprintf(stderr, "              set from to\n");
	if (argc==1) {
		// print current setting
		mirror_nvram_parse(&on, &from, &to);
		fprintf(stderr, "current setting: %s", on?"on":"off");
		if (on)
			fprintf(stderr, " [%d]->[%d]", from, to);
		fprintf(stderr, "\n");

	}
	return -1;
}

static struct nmpipe *namedp = NULL;

void signal_handler(int sig, siginfo_t *siginfo, void *notused)
{
	if (namedp)
		unlink(namedp->path);
	exit(1);
}

static int preq_main(int argc, char **argv)
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

	namedp = prequest(p);
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

static unsigned long long get_byte_counts(int pos)
{
    FILE *fp;
    char *tmp, *value;
    char buffer[512];
    unsigned long long cnt[2] = {0};
    int i;

    if((fp=fopen("/proc/asicCounter","r"))!=NULL) {
        i = 0;
        while(fgets(buffer, 512, fp)) {
            if(i==6) {
                value = buffer;
                tmp = strsep(&value, ":");
                ydespaces(value);
                tmp = strsep(&value, " ");
                cnt[0] = strtoull(tmp, NULL, 10);
                ydespaces(value);
                tmp = strsep(&value, " ");
                ydespaces(value);
                tmp = strsep(&value, " ");
                ydespaces(value);
                tmp = strsep(&value, " ");
                ydespaces(value);
                tmp = strsep(&value, " ");
                ydespaces(value);
                tmp = strsep(&value, " ");
                ydespaces(value);
                tmp = strsep(&value, " ");
                cnt[1] = strtoul(tmp, NULL, 10);
                ydespaces(value);
            }
            i++;
        }
        fclose(fp);
    }
	return (cnt[pos]);
}

static int auto_trap_main(int argc, char **argv)
{
	int fd, flag, ntp = 0;
	unsigned long long rx_crc = 0;

	nvram_set("x_autoreboot_success", "0");
	nvram_commit();

	while (1) {
		fd = open("/proc/dvflag", O_RDONLY);
		if (fd >= 0) {
			if (read(fd, (void *)&flag, sizeof(flag)) > 0) {
				if (flag & DF_NTPSYNC)
					ntp = 1;
			}
			close(fd);
		}

		if (ntp)
		break;
		sleep(1);
	}

	rx_crc = get_byte_counts(DEV_STATS_POS_RX_CRC);
	yexecl(NULL, "sh -c \"snmp -m 4 %llu &\"", rx_crc);

	return 0;
}

static int apscan_trap_main(int argc, char **argv)
{
	int fd, flag, ntp = 0;

	while (1) {
		fd = open("/proc/dvflag", O_RDONLY);
		if (fd >= 0) {
			if (read(fd, (void *)&flag, sizeof(flag)) > 0) {
				if (flag & DF_NTPSYNC)
					ntp = 1;
			}
			close(fd);
		}

		if (ntp)
		break;
		sleep(1);
	}

	yexecl(NULL, "sh -c \"snmp -m 11 &\"" );
	return 0;
}

#ifdef __CONFIG_GNT2100__
static int ont_main(int argc, char **argv)
{
	/* fake the first argument */
	argc++;
	argv--;
	return preq_main(argc, argv);
}
#endif

#define NR_OF_ITEM(name, type)  (sizeof(name) / sizeof(type))

struct applet {
	const char *name;
	int (*main) (int argc, char **argv);
};

static struct applet applets[] = {
	{ "dvflag", dvflag_main },
	{ "md", md },
	{ "mm", mm },
	{ "furl", furl_main },
	{ "phyconfig", phyconfig_main },
	{ "mirror", mirror_main },
	{ "preq", preq_main },
#ifdef __CONFIG_GNT2100__
	{ "ont", ont_main },
#endif
	{ "wmmmap",  wmmmap_main },
	{ "ub", upboot },
	{ "resetTrap", auto_trap_main },
	{ "apscanTrap", apscan_trap_main },
	{ "mping", mping_main }
};

static int applet_compare(const struct applet *m1, const struct applet *m2)
{
	return strcmp(m1->name, m2->name);
}

static void __attribute__ ((constructor)) init_applet(void)
{
	qsort(applets, NR_OF_ITEM(applets, struct applet),
	      sizeof(struct applet), (void *)applet_compare);
}

int main(int argc, char **argv)
{
	const char *applet_name = argv[0];
	struct applet key;
	struct applet *applet;

	if (applet_name[0] == '-')
		applet_name++;
	applet_name = base_name(applet_name);

	key.name = applet_name;
	applet = bsearch(&key, applets, NR_OF_ITEM(applets, struct applet),
			 sizeof(struct applet), (void *)applet_compare);

	if (applet)
		return applet->main(argc, argv);
	else
		fprintf(stderr, "Unknown applet name\n");
	return 0;
}
