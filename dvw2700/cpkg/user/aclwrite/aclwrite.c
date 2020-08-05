#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <linux/if_ether.h>
#include <fcntl.h>
#include <errno.h>

#include "rtl865x_netif.h"
#include <acl_write.h>

#define isspace(c) ((((c) == ' ') || (((unsigned int)((c) - 9)) <= (13 - 9))))

union in_addr_un {
	uint32_t	all[4];
	in_addr_t	ip;
	in_addr_t	ip6[4];
	struct in_addr	in;
	struct in6_addr	in6;
};

#define USAGE \
	"aclwrite [options] cmd intf\n" \
	"  cmd: add|del|flush\n" \
	"  intf: eth1|br0|...\n" \
	"  options:\n" \
	"    -d in|out  (direction)\n" \
	"    -a permit|drop|cpu|prio|drop_pps|drop_bps|redir (action type)\n" \
	"    -o pktOpApp\n" \
	"    -r ruleType\n" \
	"       ruleType: mac/ip/udp/tcp/sfilter/dfilter/ipv6\n" \
	"    -m macSrc[_macDst] (MAC xx:xx:xx:xx:xx:xx)\n" \
	"    -i srcIP[/mask[_dstIP/mask]] (IP)\n" \
	"    -p SPortBegin[:SPortEnd[_DPortBegin:DPortEnd]]\n" \
	"    -P PhysicalPortList[/mask] (PORT: port1|port2|port3|...)\n" \
	"    -v VlanIndex[/mask]\n" \
	"    -y priority\n"	\
	"    -n netifIdx\n"	\
	"    -3 ignore l3l4 rule\n"	\
	"    -4 ignore l4 rule\n"   \
	"    -t IP_TOS[/mask]\n"   \
	"    -T IP_PROTO[/mask]\n"   \
	"    -q QoS rule\n" \
	"    -c chain number\n" \
	"    -Q verbose\n" \
	"    -L flowLabel[/mask]\n" \
	"    -C trafficClass[/mask]\n" \
	"    -H nextHeader[/mask]\n" \
	"    -f tcpflag[/mask] (fin|syn|rst|psh|ack|urg)\n"

static char *prog;

static void say_error_and_die(int usage, const char *s, ...) __attribute__((noreturn));
static void say_error_and_die(int usage, const char *s, ...)
{
	va_list p;

	if (s) {
		va_start(p, s);
		vfprintf(stderr, s, p);
		va_end(p);
	}

	if (usage)
		fprintf(stderr, "%s", USAGE);

	exit(EXIT_FAILURE);
}

#define RULE_INVALID	-1

#define ACTION_NONE     -1

typedef struct {
	unsigned char m[ETH_ALEN];
	unsigned char mask[ETH_ALEN];
} t_mac;

typedef struct {
	unsigned short begin;
	unsigned short end;
} t_range_port;

typedef struct {
	union in_addr_un ip;
	union in_addr_un mask;
} t_ip;

int af_inet = AF_INET;
int prio = -1;
t_mac smac, smac_mask, dmac, dmac_mask;
t_range_port sport, dport;
t_ip sip, dip;
uint16 sportlist, sportlist_mask;
uint16 vlan_idx, vlan_idx_mask;
char ignore_l3l4rule, ignore_l4rule;
uint16 netif_idx;
uint8 iptos_v, iptos_m;
uint8 ipproto_v, ipproto_m;
uint8 is_qos_rule = 0;
uint16 h_proto[2];
uint8 tclass, tclass_m;
uint32 flowlabel, flowlabel_m;
uint8 nexthdr, nexthdr_m, tcpflag, tcpflag_m;
int ratelim_idx = -1;
int chain = 0;
int verbose = 0;

#define _countof(x) (sizeof(x) / sizeof((x)[0]))

static char *despaces(char *s)
{
	char *p, *q;
	int c;

	/* skip leading spaces */
	for (p = s; (c = *p) && isspace(c); p++) ;
	/* run to the end of string */
	for (q = p; *q; c = *q++) ;
	for (q--; p < q && isspace(c); c = *q)
		*q-- = '\0';
	if (p != s) {
		for (q = s; *p; *q++ = *p++) ;
		*q = 0;
	}
	return s;
}

static int sep_args(char *line, char *ag[], unsigned agsz, const char *delim)
{
	char *q, *p = line;
	unsigned i, ac = 0;

	while ((q = strsep(&p, delim))) {
		despaces(q);
		if (ac < agsz)
			ag[ac++] = q;
	}

	for (i = ac; i < agsz; i++)
		ag[i] = NULL;

	return (int)ac;
}

static int ether_pton(const char *s, unsigned char *addr)
{
	char tmp[32];
	char *q, *p = (char *)tmp;
	int i;

	if (!s || !addr)
		return -1;

	strncpy(tmp, s, sizeof(tmp) - 1);
	tmp[sizeof(tmp) - 1] = '\0';
	despaces(tmp);
	for (i = 0; (q = strsep(&p, ":-")); i++) {
		if (*q) {
			if (i < ETH_ALEN) {
				int n = (int)strtol(q, &q, 16);
				if (!*q && n >= 0 && n < 256)
					*addr++ = (unsigned char)n;
				else
					break;
				continue;
			}
		}
		return -1;
	}

	return (i == ETH_ALEN) ? 0 : -1;
}

int get_direction(char *s)
{
	return (!strcmp(s, "out")) ? RTL865X_ACL_EGRESS : RTL865X_ACL_INGRESS;
}

int get_action(char *s)
{
	if (strcmp(s, "permit") == 0)
		return RTL865X_ACL_PERMIT;
	else if (strcmp(s, "drop") == 0)
		return RTL865X_ACL_DROP;
	else if (strcmp(s, "cpu") == 0)
		return RTL865X_ACL_TOCPU;
	else if (strncmp(s, "pri", 3) == 0)
		return RTL865X_ACL_PRIORITY;
	else if (strcmp(s, "drop_pps") == 0)
		return RTL865X_ACL_DROP_RATE_EXCEED_PPS;
	else if (strcmp(s, "drop_bps") == 0)
		return RTL865X_ACL_DROP_RATE_EXCEED_BPS;
	else if (strcmp(s, "redir") == 0)
		return RTL865X_ACL_REDIRECT_ETHER;
	return ACTION_NONE;
}

static int parse_ether_addr(t_mac *m, char *s)
{
	char *args[4];

	sep_args(s, args, _countof(args), "/");
	if (args[0] == NULL)
		return 0;
	if (strcmp(args[0], "any")) {
		if (ether_pton(args[0], m->m))
			say_error_and_die(0, "%s: Invalid HW address\n", args[0]);
		else if (args[1]) {
			if (ether_pton(args[1], m->mask))
				say_error_and_die(0, "%s: Invalid HW address\n", args[1]);
		} else
			ether_pton("ff:ff:ff:ff:ff:ff", m->mask);
	} else if (args[1] == NULL) {
		memset(m, 0, sizeof(*m));
	} else
		say_error_and_die(0, "%s: Too many argument\n", args[1]);
	return 1;
}

/* 00:08:52:00:00:00/FF:FF:FF:00:00:00_any */
static int get_mac(t_mac *f, t_mac *t, char *s)
{
	char *args[4];

	if (s == NULL)
		return 0;
	memset(f, 0, sizeof(*f));
	memset(t, 0, sizeof(*t));
	sep_args(s, args, _countof(args), "_");
	if (args[0] == NULL || !parse_ether_addr(f, args[0]))
		return 0;
	if (args[1])
		return parse_ether_addr(t, args[1]);
	return 1;
}

static int parse_port_range(t_range_port *r, char *s)
{
	char *args[4];
	char *ep;

	sep_args(s, args, _countof(args), ":");
	if (args[0] == NULL)
		return 0;

	if (strcmp(args[0], "any")) {
		r->begin = strtol(args[0], &ep, 0);
		if (*ep || ep == args[0])
			say_error_and_die(0, "%s: Invalid port number\n", args[0]);
		if (args[1]) {
			r->end = strtol(args[1], &ep, 0);
			if (*ep || ep == args[1])
				say_error_and_die(0, "%s: Invalid port number\n", args[1]);
		} else
			r->end = r->begin;
		if (r->begin > r->end)
			say_error_and_die(0, "Beginning port(%u) be smaller than end one(%u)\n",
					r->begin, r->end);
	} else if (args[1] == NULL) {
		r->begin = 0;
		r->end = USHRT_MAX;
	} else
		say_error_and_die(0, "%s: Too many argument\n", args[1]);

	return 1;
}

static int get_port(t_range_port *f, t_range_port *t, char *s)
{
	char *args[4];

	if (s == NULL)
		return 0;

	memset(f, 0, sizeof(*f));
	memset(t, 0, sizeof(*t));

	sep_args(s, args, _countof(args), "_");
	if (args[0] == NULL || !parse_port_range(f, args[0]))
		return 0;
	if (args[1])
		return parse_port_range(t, args[1]);
	return 1;
}

static inline void in_addr_domask(union in_addr_un *d, union in_addr_un *a, union in_addr_un *b)
{
	d->all[0] = a->all[0] & b->all[0];
	d->all[1] = a->all[1] & b->all[1];
	d->all[2] = a->all[2] & b->all[2];
	d->all[3] = a->all[3] & b->all[3];
}

static inline int in_addr_none(int af, const union in_addr_un *a)
{
	switch (af) {
	case AF_INET:
		return (a->in.s_addr == INADDR_NONE);
	case AF_INET6:
		return (~a->in6.s6_addr32[0] | ~a->in6.s6_addr32[1] |
			~a->in6.s6_addr32[2] | ~a->in6.s6_addr32[3]) == 0;
	default:
		say_error_and_die(0, "Invalid address family\n");
		return 0;
	}
}

static void prefix_to_netmask(u_int32_t *mask, unsigned int prefix_len)
{
	if (prefix_len == 0) {
		mask[0] = mask[1] = mask[2] = mask[3] = 0;
	} else if (prefix_len <= 32) {
		mask[0] <<= 32 - prefix_len;
		mask[1] = mask[2] = mask[3] = 0;
	} else if (prefix_len <= 64) {
		mask[1] <<= 32 - (prefix_len - 32);
		mask[2] = mask[3] = 0;
	} else if (prefix_len <= 96) {
		mask[2] <<= 32 - (prefix_len - 64);
		mask[3] = 0;
	} else if (prefix_len <= 128) {
		mask[3] <<= 32 - (prefix_len - 96);
	}
	mask[0] = htonl(mask[0]);
	mask[1] = htonl(mask[1]);
	mask[2] = htonl(mask[2]);
	mask[3] = htonl(mask[3]);
}

static int parse_in_addr(int af, t_ip *t, char *s)
{
	char *args[4];
	char *ep;
	int i, cmask;

	if (sep_args(s, args, _countof(args), "/") < 1)
		return 0;

	if (strcmp(args[0], "any")) {
		/* ip address */
		if ((inet_pton(af, args[0], t->ip.all) != 1) ||
		    in_addr_none(af, &t->ip))
			say_error_and_die(0, "%s: Invalid address\n", args[0]);

		memset(t->mask.all, 0xff, sizeof(t->mask));
		/* mask */
		if (args[1]) {
			if (inet_pton(af, args[1], t->mask.all) != 1) {
				if (errno == EAFNOSUPPORT)
					say_error_and_die(0, "%d: Not supported address family\n", af);
				cmask = strtol(args[1], &ep, 10);
				if (*ep || ep == args[1])
					say_error_and_die(0, "%s: Invalid address\n", args[1]);
				switch (af) {
				case AF_INET:
					if (cmask < 0 || cmask > 32)
						say_error_and_die(0, "%d: Invalid mask number\n", cmask);
					cmask = 32 - cmask;
					for (i = 0; cmask > 0; i++, cmask--)
						t->mask.in.s_addr ^= (1 << i);
					t->mask.in.s_addr = htonl(t->mask.in.s_addr);
					break;
				case AF_INET6:
					if (cmask < 0 || cmask > 128)
						say_error_and_die(0, "%d: Invalid prefix length\n", cmask);
					prefix_to_netmask(t->mask.ip6, cmask);
					break;
				default:
					say_error_and_die(0, "%d: Not supported address family\n", af);
					break;
				}
			}
		}
	} else if (args[1] == NULL) {
		memset(t, 0, sizeof(*t));
	} else
		say_error_and_die(0, "%s: Too many argument\n", args[1]);

	in_addr_domask(&t->ip, &t->ip, &t->mask);
	return 1;
}

int get_ip(int af, t_ip *f, t_ip *t, char *s)
{
	char *args[4];

	if (s == NULL)
		return 0;

	memset(f, 0, sizeof(*f));
	memset(t, 0, sizeof(*t));

	sep_args(s, args, _countof(args), "_");
	if (args[0] == NULL || !parse_in_addr(af, f, args[0]))
		return 0;
	if (args[1])
		return parse_in_addr(af, t, args[1]);
	return 1;
}

int get_rule_type(char *arg)
{
	if (!strcmp(arg, "mac"))
		return RTL865X_ACL_MAC;
	else if (!strcmp(arg, "ip"))
		return RTL865X_ACL_IP;
	else if (!strcmp(arg, "tcp"))
		return RTL865X_ACL_TCP;
	else if (!strcmp(arg, "udp"))
		return RTL865X_ACL_UDP;
	else if (!strcmp(arg, "sfilter"))
		return RTL865X_ACL_SRCFILTER;
	else if (!strcmp(arg, "dfilter"))
		return RTL865X_ACL_DSTFILTER;
	else if (!strcmp(arg, "ipv6")) {
		af_inet = AF_INET6;
		return RTL865X_ACL_IPV6;
	}
	say_error_and_die(0, "%s: Invalid rule type.\n", arg);
}

static int get_u32_mask(u_int32_t *p, u_int32_t *m, char *s)
{
	char *args[4];
	char *ep;

	if (s == NULL || (sep_args(s, args, _countof(args), "/") < 1))
		return 0;

	*p = strtoul(args[0], &ep, 0);
	if (*ep || ep == args[0])
		say_error_and_die(0, "%s: Invalid number\n", args[0]);

	if (args[1]) {
		*m = strtoul(args[1], NULL, 0);
		if (*ep || ep == args[0])
			say_error_and_die(0, "%s: Invalid number\n", args[1]);
	}

	return 1;
}

int get_u16_mask(uint16 *p, uint16 *m, char *s)
{
	u_int32_t val[2] = { [1] = USHRT_MAX };

	get_u32_mask(&val[0], &val[1], s);
	if (val[0] > USHRT_MAX || val[1] > USHRT_MAX)
		say_error_and_die(0, "Too big number [0~%u]\n", USHRT_MAX);
	*p = (u_int16_t)val[0];
	*m = (u_int16_t)val[1];
	return 1;
}

int get_portlist(uint16 *p, uint16 *m, char *s)
{
	return get_u16_mask(p, m, s);
}

int get_vlan_idx(uint16 *v, uint16 *m, char *s)
{
	return get_u16_mask(v, m, s);
}

int get_u8_mask(uint8 *v, uint8 *m, char *s)
{
	u_int32_t val[2] = { [1] = 255 };

	get_u32_mask(&val[0], &val[1], s);
	if (val[0] > 255 || val[1] > 255)
		say_error_and_die(0, "Too big number [0~255]\n");
	*v = (u_int8_t)val[0];
	*m = (u_int8_t)val[1];
	return 1;
}

int write_acl_cmd(struct dvCmdAcl_t *p)
{
	int fd, len;

	fd = open("/proc/rtl865x/acl", O_WRONLY);
	if (fd < 0)
		return -1;
	len = write(fd, p, sizeof(*p));
	close(fd);
	return len;
}

static void ntohl_in6(uint32_t *dst, uint32_t *src)
{
	int i;
	for (i = 0; i < 4; i++)
		*dst++ = ntohl(*src++);
}

/* 0x3/0xff or syn|fin/0xff or ack/psh,ack */
static int parse_tcp_flag(char *s, unsigned char *val)
{
	char *q, *p = s;
	unsigned char tmp;

	tmp = strtol(s, &q, 0);
	if (s == q || *q) {
		for (tmp = 0; (q = strsep(&p, ",|")) != NULL; ) {
			despaces(q);
			if (!*q)
				continue;
			if (!strcasecmp(q, "fin"))
				tmp |= 0x1;
			else if (!strcasecmp(q, "syn"))
				tmp |= 0x2;
			else if (!strcasecmp(q, "rst"))
				tmp |= 0x4;
			else if (!strcasecmp(q, "psh"))
				tmp |= 0x8;
			else if (!strcasecmp(q, "ack"))
				tmp |= 0x10;
			else if (!strcasecmp(q, "urg"))
				tmp |= 0x20;
			else
				say_error_and_die(0, "%s: Unknown flag name\n", q);
		}
	}
	*val = tmp;
	return 1;
}

static int get_tcp_flag(char *s, unsigned char *flg, unsigned char *mask)
{
	char *args[4];

	if (s == NULL)
		return 0;
	*mask = *flg = 0;
	sep_args(s, args, _countof(args), "/");
	if (args[0])
		parse_tcp_flag(args[0], flg);
	if (args[1])
		return parse_tcp_flag(args[1], mask);
	else
		*mask = *flg;
	return 1;
}

int main(int argc, char *argv[])
{
	int ruleType = RULE_INVALID;
	char *dir = "in";
	int opApp = RTL865X_ACL_L3_AND_L4;
	int act = ACTION_NONE;
	char *cmd;
	char *intf;
	struct dvCmdAcl_t dvcmd;
	rtl865x_AclRule_t *R;
	int opt;
	int bottom = 0;

	cmd = strrchr(argv[0], '/');
	if (cmd)
		prog = cmd + 1;
	else
		prog = argv[0];

	if (argc < 3)
		say_error_and_die(1, "%s: Too few argument\n", prog);

	// process option string
	while ((opt = getopt(argc, argv, "d:a:r:o:m:M:i:p:P:v:y:n:34t:T:qc:L:C:H:l:bQf:")) != -1) {
		switch (opt) {
		case 'd':
			dir = optarg;
			break;
		case 'a':
			act = get_action(optarg);
			break;
		case 'o':
			opApp = atoi(optarg);
			break;
		case 'm':
			get_mac(&smac, &dmac, optarg);
			break;
		case 'r':
			ruleType = get_rule_type(optarg);
			break;
		case 'p':
			get_port(&sport, &dport, optarg);
			break;
		case 'i':
			if (ruleType == RULE_INVALID)
				say_error_and_die(0, "rule-specifier must be preceded\n");
			get_ip(af_inet, &sip, &dip, optarg);
			break;
		case 'P':
			get_portlist(&sportlist, &sportlist_mask, optarg);
			break;
		case 'v':
			get_vlan_idx(&vlan_idx, &vlan_idx_mask, optarg);
			break;
		case 'y':
			prio = atoi(optarg);
			break;
		case '3':
			ignore_l3l4rule = 1;
			break;
		case '4':
			ignore_l4rule = 1;
			break;
		case 'n':
			netif_idx = atoi(optarg);
			break;
		case 't':	// ip tos / mask
			get_u8_mask(&iptos_v, &iptos_m, optarg);
			break;
		case 'T':	// ip proto / mask
			get_u8_mask(&ipproto_v, &ipproto_m, optarg);
			break;
		case 'q':	// QOS rule
			is_qos_rule = 1;
			break;
		case 'M':
			get_u16_mask(&h_proto[0], &h_proto[1], optarg);
			break;
		case 'c':
			chain = strtol(optarg, NULL, 0);
			break;
		case 'b':
			bottom = 1;
			break;
		case 'Q':
			verbose = 1;
			break;
		case 'L':	/* Flowlabel */
			flowlabel_m = UINT_MAX;
			get_u32_mask(&flowlabel, &flowlabel_m, optarg);
			break;
		case 'C':	/* Traffic class */
			get_u8_mask(&tclass, &tclass_m, optarg);
			break;
		case 'H':
			get_u8_mask(&nexthdr, &nexthdr_m, optarg);
			break;
		case 'l':
			ratelim_idx = strtol(optarg, NULL, 0);
			break;
		case 'f':
			get_tcp_flag(optarg, &tcpflag, &tcpflag_m);
			break;
		default:
			say_error_and_die(1, "%s: Unknown option (-%c)\n", prog, opt);
			return -1;
		}
	}

	if (optind + 2 > argc)
		say_error_and_die(1, "%s: cmd or intf missed.\n", prog);

	cmd = argv[optind];
	intf = argv[optind + 1];

	memset(&dvcmd, 0, sizeof(dvcmd));
	strcpy(dvcmd.intf, intf);
	strcpy(dvcmd.dir, dir);
	R = &dvcmd.rule;

	if (is_qos_rule)
		strcpy(dvcmd.chain, "qos");
	else
		*((int *)&dvcmd.chain[0]) = chain;

	if (strcmp(cmd, "flush") == 0) {
		strcpy(dvcmd.cmd, "flush");
		write_acl_cmd(&dvcmd);
		return 0;
	}

	if (ruleType == RULE_INVALID)
		say_error_and_die(1, "%s: Rule type missed.\n", prog);

	if (strcmp(cmd, "add") == 0)
		strcpy(dvcmd.cmd, "add");
	else if (strcmp(cmd, "del") == 0)
		strcpy(dvcmd.cmd, "del");
	else
		say_error_and_die(0, "%s: Unknown command '%s'.\n", prog, cmd);

	dvcmd.keep_at_tail = bottom;

	// generate target struct
	if (act == ACTION_NONE)
		say_error_and_die(0, "%s: Action not specified.\n", prog);

	if (act == RTL865X_ACL_PRIORITY) {
		if (prio == -1)
			say_error_and_die(0, "%s: Priority not specified.\n", prog);
		R->priority_ = prio;
	} else if (act == RTL865X_ACL_DROP_RATE_EXCEED_PPS ||
	           act == RTL865X_ACL_DROP_RATE_EXCEED_BPS) {
		if (ratelim_idx < 0 || ratelim_idx >= (1 << 4))
			say_error_and_die(0, "%s: ratelimtIdx_ not specified.\n", prog);
		R->ratelimtIdx_ = ratelim_idx;
	}

	R->actionType_ = act;
	R->pktOpApp_ = opApp;
	R->ruleType_ = ruleType;
	R->netifIdx_ = netif_idx;

	switch (ruleType) {
	case RTL865X_ACL_MAC:
		memcpy(R->srcMac_.octet, smac.m, ETH_ALEN);
		memcpy(R->srcMacMask_.octet, smac.mask, ETH_ALEN);
		memcpy(R->dstMac_.octet, dmac.m, 6);
		memcpy(R->dstMacMask_.octet, dmac.mask, ETH_ALEN);
		R->typeLen_ = h_proto[0];
		R->typeLenMask_ = h_proto[1];
		break;
	case RTL865X_ACL_UDP:
	case RTL865X_ACL_TCP:
		if (ruleType == RTL865X_ACL_TCP) {
			R->tcpFlagMask_ = tcpflag_m;
			R->tcpFlag_ = tcpflag;
		}
		if (ruleType == RTL865X_ACL_UDP) {
			R->udpSrcPortLB_ = sport.begin;
			R->udpSrcPortUB_ = sport.end;
			R->udpDstPortLB_ = dport.begin;
			R->udpDstPortUB_ = dport.end;
		} else {
			R->tcpSrcPortLB_ = sport.begin;
			R->tcpSrcPortUB_ = sport.end;
			R->tcpDstPortLB_ = dport.begin;
			R->tcpDstPortUB_ = dport.end;
		}
		/* fall thru */
	case RTL865X_ACL_IP:
		R->srcIpAddr_ = ntohl(sip.ip.ip);
		R->srcIpAddrMask_ = ntohl(sip.mask.ip);
		R->dstIpAddr_ = ntohl(dip.ip.ip);
		R->dstIpAddrMask_ = ntohl(dip.mask.ip);
		R->tos_ = iptos_v;
		R->tosMask_ = iptos_m;
		if (ruleType == RTL865X_ACL_IP) {
			R->ipProto_ = ipproto_v;
			R->ipProtoMask_ = ipproto_m;
		}
		break;
	case RTL865X_ACL_SRCFILTER:
		memcpy(R->srcFilterMac_.octet, smac.m, ETH_ALEN);
		memcpy(R->srcFilterMacMask_.octet, smac.mask, ETH_ALEN);
		R->srcFilterPort_ = sportlist;
		R->srcFilterPortMask_ = sportlist_mask;
		R->srcFilterVlanIdx_ = vlan_idx;
		R->srcFilterVlanIdxMask_ = vlan_idx_mask;
		R->srcFilterIpAddr_ = ntohl(sip.ip.ip);
		R->srcFilterIpAddrMask_ = ntohl(sip.mask.ip);
		R->srcFilterPortLowerBound_ = sport.begin;
		R->srcFilterPortUpperBound_ = sport.end;
		R->srcFilterIgnoreL3L4_ = ignore_l3l4rule;
		R->srcFilterIgnoreL4_ = ignore_l4rule;
		break;
	case RTL865X_ACL_DSTFILTER:
		memcpy(R->dstFilterMac_.octet, dmac.m, ETH_ALEN);
		memcpy(R->dstFilterMacMask_.octet, dmac.mask, ETH_ALEN);
		R->dstFilterVlanIdx_ = vlan_idx;
		R->dstFilterVlanIdxMask_ = vlan_idx_mask;
		R->dstFilterIpAddr_ = ntohl(sip.ip.ip);
		R->dstFilterIpAddrMask_ = ntohl(sip.mask.ip);
		R->dstFilterPortLowerBound_ = sport.begin;
		R->dstFilterPortUpperBound_ = sport.end;
		R->dstFilterIgnoreL3L4_ = ignore_l3l4rule;
		R->dstFilterIgnoreL4_ = ignore_l4rule;
		break;
	case RTL865X_ACL_IPV6:
		*((int *)&dvcmd.chain[0]) = RTL865X_ACL_IPV6_USED;
		ntohl_in6(R->un_ty.L3V6._srcIpV6Addr.v6_addr32, sip.ip.ip6);
		ntohl_in6(R->un_ty.L3V6._srcIpV6AddrMask.v6_addr32, sip.mask.ip6);
		ntohl_in6(R->un_ty.L3V6._dstIpV6Addr.v6_addr32, dip.ip.ip6);
		ntohl_in6(R->un_ty.L3V6._dstIpV6AddrMask.v6_addr32, dip.mask.ip6);
		R->un_ty.L3V6._flowLabel = flowlabel;
		R->un_ty.L3V6._flowLabelMask = flowlabel_m;
		R->un_ty.L3V6._trafficClass = tclass;
		R->un_ty.L3V6._trafficClassMask = tclass_m;
		R->un_ty.L3V6._nextheader = nexthdr;
		R->un_ty.L3V6._nextheaderMask = nexthdr_m;
		R->ipv6EntryType_ = 1;
		if (write_acl_cmd(&dvcmd) > 0) {
			R->ipv6EntryType_ = 0;
			write_acl_cmd(&dvcmd);
		}
		return 0;
	default:
		say_error_and_die(0, "%s: Unknown rule type.\n", prog);
		return -1;
	}

	write_acl_cmd(&dvcmd);
	return 0;
}
