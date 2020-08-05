#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <getopt.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <net/if.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/mman.h>
#include <libytool.h>
#include "qos_reg.h"
#include "do_cmd.h"

#define DVQOS_OP_GETREGS  1
#define DVQOS_OP_READREG  2
#define DVQOS_OP_WRITEREG 3

// arg of READREG/WRITEREG
struct qos_reg_t {
	int reg;
	unsigned int val;
};

///////////////////////////////////
// config interface     & string utils
///////////////////////////////////
#define	PROG "dvqos"

int verbose = 0;

void do_reg(void);
void do_add_basic(char *intf);
int qos_port_rate(int port, char *cmd, int rate_1k);
int patch_wfq_rate(int port, unsigned int val);

static void *mem_read_align(void *dst, const void *src, size_t n)
{
	char *d = (char *)dst;
	u_int32_t val;
	const u_int32_t *p = (u_int32_t *)(((u_int32_t)src) & ~3);
	size_t i;

	if ((i = (((u_int32_t)src) & 3))) {
		for (val = *p++; n > 0 && i < 4; n--)
			*d++ = ((char *)&val)[i++];
	}

	for (; n >= 4; n -= 4) {
		val = *p++;
		*d++ = ((char *)&val)[0];
		*d++ = ((char *)&val)[1];
		*d++ = ((char *)&val)[2];
		*d++ = ((char *)&val)[3];
	}

	if (n > 0) {
		val = *p++;
		for (i = 0; n > 0 && i < 4; n--)
			*d++ = ((char *)&val)[i++];
	}
	return dst;
}

static void *mem_write_align(void *dst, const void *src, size_t n)
{
	const char *p = (char *)src;
	u_int32_t val;
	u_int32_t *d = (u_int32_t *)(((u_int32_t)dst) & ~3);
	size_t i;

	if ((i = (((u_int32_t)dst) & 3)) && n > 0) {
		for (val = *d; n > 0 && i < 4; n--)
			((char *)&val)[i++] = *p++;
		*d++ = val;
	}

	for (; n >= 4; n -= 4) {
		((char *)&val)[0] = *p++;
		((char *)&val)[1] = *p++;;
		((char *)&val)[2] = *p++;;
		((char *)&val)[3] = *p++;;
		*d++ = val;
	}

	if (n > 0) {
		val = *d;
		for (i = 0; n > 0 && i < 4; n--)
			((char *)&val)[i++] = *p++;
		*d++ = val;
	}

	return dst;
}

static void do_ioctl(int op, struct qos_reg_t *p)
{
	int fd, len;
	unsigned int mask, maplen;
	unsigned long addr, offset, pos;
	char *mptr;

	fd = open("/dev/mem", O_RDWR | O_SYNC);
	if (fd == -1) {
		perror("/dev/mem: %m\n");
		exit(EXIT_FAILURE);
	}
	len = (op == DVQOS_OP_GETREGS) ? 516 : sizeof(int);
	addr = p->reg + 0x1b804700;

	mask = (unsigned)getpagesize() - 1;
	offset = addr & ~mask;
	pos = addr - offset;
	maplen = ((len + pos) + mask) & ~mask;
	mptr = (char *)mmap(0, maplen,
		PROT_READ | ((op == DVQOS_OP_WRITEREG) ? PROT_WRITE : 0),
		MAP_SHARED, fd, offset);
	if ((void *)mptr != MAP_FAILED) {
		switch (op) {
		case DVQOS_OP_WRITEREG:
			mem_write_align(&mptr[pos], &p->val, len);
			break;
		case DVQOS_OP_READREG:
			mem_read_align(&p->val, &mptr[pos], len);
			break;
		default:
			mem_read_align((void *)p, &mptr[pos], len);
			break;
		}
		munmap((void *)mptr, maplen);
	}
	close(fd);
	if ((void *)mptr == MAP_FAILED) {
		perror("mmap: %m\n");
		exit(EXIT_FAILURE);
	}
}

unsigned int read_qos_reg(int off)
{
	struct qos_reg_t data;

	memset(&data, 0, sizeof(data));
	data.reg = off;
	do_ioctl(DVQOS_OP_READREG, &data);
	return data.val;
}

void write_qos_reg(int off, unsigned int val)
{
	struct qos_reg_t data;

	data.reg = off;
	data.val = val;
	do_ioctl(DVQOS_OP_WRITEREG, &data);
}

void set_qos_reg32(int off, unsigned int clr, unsigned int nv)
{
	unsigned int v;

	v = read_qos_reg(off);
	v = (v & clr) | nv;

	write_qos_reg(off, v);
}

/////////////////////////////////
// do_reg()
/////////////////////////////////

static inline unsigned int get_bits(unsigned int data, unsigned int sft, unsigned int mask)
{
	return (data >> sft) & mask;
}

void do_reg(void)
{
	union {
		unsigned char data[600];
		struct qos_reg_t R;
	} res;
	unsigned int *ptr;
	int off;
	int i;

	memset(res.data, 0xff, sizeof(res));
	res.R.reg = 0;
	do_ioctl(DVQOS_OP_GETREGS, (struct qos_reg_t *)&res.R);
	ptr = (unsigned int *)res.data;

	// parse memory
	printf("%03X: %08X\n", 0, ptr[0]);

	for (i = 0; i < 3; i++) {
		off = 4 + i * 4;
		printf("%03X: %08X (%04X %04X)\n", off, ptr[off / 4],
		       get_bits(ptr[off / 4], 16, 0x0000ffff),
		       get_bits(ptr[off / 4], 0, 0x0000ffff));
	}

	off = 0x14;
	printf("%03X: %08X (%X %X %X %X	%X %X %X %X	%X)\n", off, ptr[off / 4],
	       get_bits(ptr[off / 4], 24, 0x00000007), get_bits(ptr[off / 4], 21, 0x00000007),
	       get_bits(ptr[off / 4], 18, 0x00000007), get_bits(ptr[off / 4], 15, 0x00000007),
	       get_bits(ptr[off / 4], 12, 0x00000007), get_bits(ptr[off / 4], 9, 0x00000007),
	       get_bits(ptr[off / 4], 6, 0x00000007), get_bits(ptr[off / 4], 3, 0x00000007),
	       get_bits(ptr[off / 4], 0, 0x00000007));

	for (i = 0; i < 7; i++) {
		off = 0x18 + i * 4;
		printf("%03X: %08X (%X %X %X %X	%X %X %X %X)\n", off, ptr[off / 4],
		       get_bits(ptr[off / 4], 21, 0x00000007),
		       get_bits(ptr[off / 4], 18, 0x00000007),
		       get_bits(ptr[off / 4], 15, 0x00000007),
		       get_bits(ptr[off / 4], 12, 0x00000007),
		       get_bits(ptr[off / 4], 9, 0x00000007),
		       get_bits(ptr[off / 4], 6, 0x00000007),
		       get_bits(ptr[off / 4], 3, 0x00000007),
		       get_bits(ptr[off / 4], 0, 0x00000007));
	}

	for (i = 0; i < 7; i++) {
		off = 0x34 + i * 4;
		printf("%03X: %08X (%X %X %X %X	%X %X %X %X	%X %X)\n", off, ptr[off / 4],
		       get_bits(ptr[off / 4], 27, 0x00000007),
		       get_bits(ptr[off / 4], 24, 0x00000007),
		       get_bits(ptr[off / 4], 21, 0x00000007),
		       get_bits(ptr[off / 4], 18, 0x00000007),
		       get_bits(ptr[off / 4], 15, 0x00000007),
		       get_bits(ptr[off / 4], 12, 0x00000007),
		       get_bits(ptr[off / 4], 9, 0x00000007),
		       get_bits(ptr[off / 4], 6, 0x00000007),
		       get_bits(ptr[off / 4], 3, 0x00000007),
		       get_bits(ptr[off / 4], 0, 0x00000007));
	}

	off = 0x50;
	printf("%03X: %08X (%02X %02X %02X %02X	%02X)\n", off, ptr[off / 4],
	       get_bits(ptr[off / 4], 16, 0x0000000f),
	       get_bits(ptr[off / 4], 12, 0x0000000f),
	       get_bits(ptr[off / 4], 8, 0x0000000f),
	       get_bits(ptr[off / 4], 4, 0x0000000f), get_bits(ptr[off / 4], 0, 0x0000000f));

	off = 0x54;
	printf("%03X: %08X (%X %X %X %X	%X %X %X)\n", off, ptr[off / 4],
	       get_bits(ptr[off / 4], 18, 0x00000007),
	       get_bits(ptr[off / 4], 15, 0x00000007),
	       get_bits(ptr[off / 4], 12, 0x00000007),
	       get_bits(ptr[off / 4], 9, 0x00000007),
	       get_bits(ptr[off / 4], 6, 0x00000007),
	       get_bits(ptr[off / 4], 3, 0x00000007), get_bits(ptr[off / 4], 0, 0x00000007));

	for (i = 0; i < 5; i++) {
		off = 0x58 + i * 4;
		printf("%03X: %08X (%X %X %X %X	%X %X %X %X)\n", off, ptr[off / 4],
		       get_bits(ptr[off / 4], 28, 0x00000007),
		       get_bits(ptr[off / 4], 24, 0x00000007),
		       get_bits(ptr[off / 4], 20, 0x00000007),
		       get_bits(ptr[off / 4], 16, 0x00000007),
		       get_bits(ptr[off / 4], 12, 0x00000007),
		       get_bits(ptr[off / 4], 8, 0x00000007),
		       get_bits(ptr[off / 4], 4, 0x00000007),
		       get_bits(ptr[off / 4], 0, 0x00000007));
	}

	off = 0x6c;
	printf("%03X: %08X (%02X %X	%X %X %X %X	%X %X %X)\n", off, ptr[off / 4],
	       get_bits(ptr[off / 4], 24, 0x000000ff),
	       get_bits(ptr[off / 4], 21, 0x00000007),
	       get_bits(ptr[off / 4], 18, 0x00000007),
	       get_bits(ptr[off / 4], 15, 0x00000007),
	       get_bits(ptr[off / 4], 12, 0x00000007),
	       get_bits(ptr[off / 4], 9, 0x00000007),
	       get_bits(ptr[off / 4], 6, 0x00000007),
	       get_bits(ptr[off / 4], 3, 0x00000007), get_bits(ptr[off / 4], 0, 0x00000007));

	off = 0x70;
	printf("%03X: %08X (%X %02X	%02X %02X %02X %02X)\n", off, ptr[off / 4],
	       get_bits(ptr[off / 4], 31, 0x00000001),
	       get_bits(ptr[off / 4], 24, 0x0000003f),
	       get_bits(ptr[off / 4], 18, 0x0000003f),
	       get_bits(ptr[off / 4], 12, 0x0000003f),
	       get_bits(ptr[off / 4], 6, 0x00000003f), get_bits(ptr[off / 4], 0, 0x00000003f));

	off = 0x74;
	printf("%03X: %08X (%02X %02X %02X %02X)\n", off, ptr[off / 4],
	       get_bits(ptr[off / 4], 23, 0x000000ff),
	       get_bits(ptr[off / 4], 12, 0x0000003f),
	       get_bits(ptr[off / 4], 6, 0x00000003f), get_bits(ptr[off / 4], 0, 0x00000003f));

	off = 0x78;
	printf("%03X: %08X (%02X %02X)\n", off, ptr[off / 4],
	       get_bits(ptr[off / 4], 3, 0x000000007), get_bits(ptr[off / 4], 0, 0x000000007));

	for (i = 0; i < 42; i++) {
		off = 0x100 + i * 4;
		printf("%03X: %08X (%X %02X	%04X)\n", off, ptr[off / 4],
		       get_bits(ptr[off / 4], 24, 0x00000007),
		       get_bits(ptr[off / 4], 16, 0x000000ff),
		       get_bits(ptr[off / 4], 0, 0x00003fff));
	}
	for (i = 0; i < 7; i++) {
		off = 0x1b0 + i * 12;
		printf("%03X: %08X (%04X)\n", off, ptr[off / 4],
		       get_bits(ptr[off / 4], 0, 0x00003fff));

		off += 4;
		printf("%03X: %08X (%X %02X	%X %02X	%X %02X	%X %02X)\n", off, ptr[off / 4],
		       get_bits(ptr[off / 4], 31, 0x00000001),
		       get_bits(ptr[off / 4], 24, 0x0000007f),
		       get_bits(ptr[off / 4], 23, 0x00000001),
		       get_bits(ptr[off / 4], 16, 0x0000007f),
		       get_bits(ptr[off / 4], 15, 0x00000001),
		       get_bits(ptr[off / 4], 8, 0x0000007f),
		       get_bits(ptr[off / 4], 7, 0x00000001),
		       get_bits(ptr[off / 4], 0, 0x0000007f));

		off += 4;
		printf("%03X: %08X (%X %02X	%X %02X)\n", off, ptr[off / 4],
		       get_bits(ptr[off / 4], 15, 0x00000001),
		       get_bits(ptr[off / 4], 8, 0x0000007f),
		       get_bits(ptr[off / 4], 7, 0x00000001),
		       get_bits(ptr[off / 4], 0, 0x0000007f));
	}
}

int sep_str(char *buf, char **av, int n, char *delim)
{
	int ac;
	char *p, *s;

	for (ac = 0; ac < n; ac++)
		av[ac] = NULL;

	s = buf;
	for (ac = 0; ac < n; ac++) {
		p = strsep(&s, delim);
		if (p) {
			av[ac] = p;
		} else
			break;
	}
	return ac;
}

///////////////////////////////////
// add basic rule. currently telnet     drop rule
///////////////////////////////////
static unsigned int get_ifaddr(const char *device)
{
	struct ifreq ifr;
	struct sockaddr_in *sin;
	int fd;

	/*
	 * Create dummy socket to perform an ioctl upon.
	 */
	fd = socket(PF_INET, SOCK_DGRAM, 0);
	if (fd < 0) {
		return (0);
	}

	memset(&ifr, 0, sizeof(ifr));
	sin = (struct sockaddr_in *)&ifr.ifr_addr;
	strncpy(ifr.ifr_name, device, sizeof(ifr.ifr_name));

	ifr.ifr_addr.sa_family = AF_INET;

	if (ioctl(fd, SIOCGIFADDR, (char *)&ifr) < 0) {
		close(fd);
		return (0);
	}
	close(fd);
	return (sin->sin_addr.s_addr);
}

void wait_until_intf_up(void)	// youngho DAVO
{
	FILE *f;
	int opmode = -1;

	// check if     mode is nat, if in bridge mode , wait until     bridge done.
	f = fopen("/var/sys_op", "r");
	if (f) {
		if (fscanf(f, "%d", &opmode) != 1)
			opmode = -1;
		fclose(f);
	}

	if (opmode == 0) {
		// wait until ip address will be acquired for WAN
		while (get_ifaddr("eth1") == 0) {
			sleep(1);
		}
		printf("WAN IP acquired\n");
	} else if (opmode == 1) {
		// bridge mode
		while (access("/var/bridge_done", F_OK) != 0) {
			sleep(1);
		}
		printf("Bridge IP done for qos.\n");
	}
}

void do_add_basic(char *intf)
{
	struct in_addr in;
	char ipstr[20];
	char cmd[120];

	// wait until intf up...
	wait_until_intf_up();

	in.s_addr = get_ifaddr(intf);

	if (verbose)
		fprintf(stderr, "dvqos:add basic - %s IP acquired\n", intf);

	strcpy(ipstr, inet_ntoa(in));
	sprintf(cmd,
		"aclwrite add %s -o 7 -r tcp -p 0:65535_23:23 -i any_%s/255.255.255.255 -q -a drop",
		intf, ipstr);

	if (verbose > 0) {
		printf("dvqos:add basic[%s]\n", cmd);
	}
	yexecl(NULL, cmd);
}

void usage_exit(void)
{
	qos_port_usage(PROG);
	qos_remark_usage(PROG);
	fprintf(stderr, "%s reg : dump qos registers\n", PROG);
	fprintf(stderr, "%s apply : apply configured values to system.\n", PROG);

	exit(EXIT_FAILURE);
}

int main(int argc, char *argv[])
{
	int i, c, rate;

	verbose = 0;
	while (1) {
		static struct option long_options[] = {
			{"verbose", no_argument, &verbose, 1},
			{"reg", no_argument, 0, 'r'},
			{"basic", required_argument, 0, 'b'},
			{"port", required_argument, 0, 'p'},
			{"remark", required_argument, 0, 'k'},
			{"apply", no_argument, 0, 'a'},
			{"throttle", required_argument, 0, 't'},
			{0, 0, 0, 0}
		};
		/* getopt_long stores the option index here. */
		int option_index = 0;

		if ((c = getopt_long(argc, argv, "rab:p:k:t:P:", long_options, &option_index)) < 0)
			break;

		switch (c) {
		case 'r':
			do_reg();
			exit(EXIT_SUCCESS);
		case 'b':
			do_add_basic(optarg);
			exit(EXIT_SUCCESS);
		case 'p':
			argv += 2;
			argc -= 2;
			exit(do_port(argc, argv) ? EXIT_SUCCESS : EXIT_FAILURE);
		case 'k':
			argv += 2;
			argc -= 2;
			exit(do_remark(argc, argv) ? EXIT_SUCCESS : EXIT_FAILURE);
		case 'a':
			qos_port_apply();
			qos_remark_apply();
			qos_rule_apply();
			exit(EXIT_SUCCESS);
		case 't':
			// throttle inrate|outrate 64
			if (argc > 3) {
				rate = strtoul(argv[3], NULL, 0);	//unit 1k
				for (i = 0; i < 5; i++)
					qos_port_rate(i, optarg, rate);
				exit(EXIT_SUCCESS);
			}
			exit(EXIT_FAILURE);
		case 'P':
			i = patch_wfq_rate(strtoul(optarg, NULL, 0), 0);
			exit(i ? EXIT_FAILURE : EXIT_FAILURE);
		case '?':
		default:
			usage_exit();
		}
	}
	return 0;
}
