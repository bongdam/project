#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <alloca.h>
#include <errno.h>
#include <time.h>
#include <unistd.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <stdbool.h>
#include <endian.h>
#include "httpd.h"
#include <arpa/inet.h>
#include <error.h>
#include <sys/signal.h>
#include <itimer.h>
#include <libytool.h>
#include <dvflag.h>
#include "instrument.h"

#ifndef _NDEBUG
static int verbose;
#endif

static int fdns_netconf_cb(struct notice_block_expand *p,
			u_int event, u_int full_event)
{
	union sockaddr_union su;

	full_event &= p->nb.concern;
	if (p->event != full_event) {
		p->event = full_event;
		select_event_getsockname(p->base, &su);
		yexecl(NULL, "%s %d %u.%u.%u.%u:%u",
		       p->script, (full_event != p->nb.concern),
		       NIPQUAD(su.sin.sin_addr), ntohs(su.sin.sin_port));
	}
	return NOTICE_DONE;
}

enum {
	/* can tweak this */
	DEFAULT_TTL = 3,

	/* cannot get bigger packets than 512 per RFC1035. */
	MAX_PACK_LEN = 512,
	IP_STRING_LEN = sizeof(".xxx.xxx.xxx.xxx"),
	MAX_NAME_LEN = IP_STRING_LEN - 1 + sizeof(".in-addr.arpa"),
	REQ_A = 1,
	REQ_PTR = 12,
};

#define move_from_unaligned16(v, u16p) (memcpy(&(v), (u16p), 2))

#define move_to_unaligned16(u16p, v) do { \
	uint16_t __t = (v); \
	memcpy((u16p), &__t, 2); \
} while (0)

#define move_to_unaligned32(u32p, v) do { \
	uint32_t __t = (v); \
	memcpy((u32p), &__t, 4); \
} while (0)

/* the message from client and first part of response msg */
struct dns_head {
	uint16_t id;
	uint16_t flags;
	uint16_t nquer;
	uint16_t nansw;
	uint16_t nauth;
	uint16_t nadd;
};

struct type_and_class {
	uint16_t type PACKED;
	uint16_t class PACKED;
} PACKED;

int process_packet(uint32_t conf_ttl, uint8_t *buf, struct in_addr fake_ip)
{
	struct dns_head *head;
	struct type_and_class *unaligned_type_class;
	const char *err_msg;
	char *query_string;
	char *answstr;
	uint8_t *answb;
	uint16_t outr_rlen;
	uint16_t outr_flags;
	uint16_t type;
	uint16_t class;
	int query_len;

	head = (struct dns_head *)buf;
	if (head->nquer == 0) {
		DIAG("packet has 0 queries, ignored\n");
		return 0; /* don't reply */
	}
	if (head->flags & htons(0x8000)) { /* QR bit */
		DIAG("response packet, ignored\n");
		return 0; /* don't reply */
	}
	/* QR = 1 "response", RCODE = 4 "Not Implemented" */
	outr_flags = htons(0x8000 | 4);
	err_msg = NULL;

	/* start of query string */
	query_string = (void *)(head + 1);
	/* caller guarantees strlen is <= MAX_PACK_LEN */
	query_len = strlen(query_string) + 1;
	/* may be unaligned! */
	unaligned_type_class = (void *)(query_string + query_len);
	query_len += sizeof(*unaligned_type_class);
	/* where to append answer block */
	answb = (void *)(unaligned_type_class + 1);

	/* OPCODE != 0 "standard query"? */
	if ((head->flags & htons(0x7800)) != 0) {
		err_msg = "opcode != 0";
		goto empty_packet;
	}
	move_from_unaligned16(class, &unaligned_type_class->class);
	if (class != htons(1)) { /* not class INET? */
		err_msg = "class != 1";
		goto empty_packet;
	}
	move_from_unaligned16(type, &unaligned_type_class->type);
	if (type != htons(REQ_A) && type != htons(REQ_PTR)) {
		/* we can't handle this query type */
//TODO: happens all the time with REQ_AAAA (0x1c) requests - implement those?
		err_msg = "type is !REQ_A and !REQ_PTR";
		goto empty_packet;
	}

	/* look up the name */
	answstr = (char *)&fake_ip.s_addr;
	DIAG("'%s'->'%s'\n", query_string, answstr);
	outr_rlen = 4;
	if (answstr && type == htons(REQ_PTR)) {
		/* returning a host name */
		outr_rlen = strlen(answstr) + 1;
	}
	if (!answstr
	 || (unsigned)(answb - buf) + query_len + 4 + 2 + outr_rlen > MAX_PACK_LEN
	) {
		/* QR = 1 "response"
		 * AA = 1 "Authoritative Answer"
		 * RCODE = 3 "Name Error" */
		err_msg = "name is not found";
		outr_flags = htons(0x8000 | 0x0400 | 3);
		goto empty_packet;
	}

	/* Append answer Resource Record */
	memcpy(answb, query_string, query_len); /* name, type, class */
	answb += query_len;
	move_to_unaligned32((uint32_t *)answb, htonl(conf_ttl));
	answb += 4;
	move_to_unaligned16((uint16_t *)answb, htons(outr_rlen));
	answb += 2;
	memcpy(answb, answstr, outr_rlen);
	answb += outr_rlen;

	/* QR = 1 "response",
	 * AA = 1 "Authoritative Answer",
	 * TODO: need to set RA bit 0x80? One user says nslookup complains
	 * "Got recursion not available from SERVER, trying next server"
	 * "** server can't find HOSTNAME"
	 * RCODE = 0 "success"
	 */
	outr_flags = htons(0x8000 | 0x0400 | 0);
	/* we have one answer */
	head->nansw = htons(1);

empty_packet:
	if ((outr_flags & htons(0xf)) != 0) { /* not a positive response */
		DIAG("%s, %s\n", err_msg, "dropping query");
		return 0;
	}
	head->flags |= outr_flags;
	head->nauth = head->nadd = 0;
	head->nquer = htons(1); // why???

	return answb - buf;
}

static int fdnsd_recv(struct select_event_base *base, int fd)
{
	uint8_t buf[MAX_PACK_LEN + 1] ALIGNED(4);
	struct sockaddr_in from;
	socklen_t addrlen;
	struct in_addr fake_addr = { .s_addr = (in_addr_t)((struct notice_block *)base->data)->data, };
	int r, n;

	addrlen = sizeof(struct sockaddr_in);
	r = recvfrom(fd, buf, sizeof(buf), 0, (struct sockaddr *)&from, &addrlen);
	if (r < 12 || r > MAX_PACK_LEN)
		return r;
	buf[r] = '\0'; /* paranoia */
	n = process_packet(DEFAULT_TTL, buf, fake_addr);
	if (n <= 0)
		return r;
	sendto(fd, buf, n, 0, (struct sockaddr *)&from, sizeof(struct sockaddr_in));
	return r;
}

#define fdnsd_fdset select_event_fdset_dfl

static int fdnsd_close(struct select_event_base *base, int fd)
{
	struct notice_block_expand *p = (struct notice_block_expand *)base->data;
	if (p != NULL) {
		dev_event_chain_deregister(&p->nb);
		/* hack for deleting rules if any added */
		p->event = 0;
		fdns_netconf_cb(p, 0, p->nb.concern);
		free(p);
	}
	return 0;
}

static struct select_event_operation fdnsd_op = {
	._fdset = fdnsd_fdset,
	._read = fdnsd_recv,
	._close = fdnsd_close,
};

static int fdnsd_run(struct in_addr addr, unsigned short port,
		struct in_addr fake_addr, int fderr, const char *script)
{
	union sockaddr_union su;
	struct select_event_base *base;
	struct notice_block_expand *p = NULL;

	base = select_event_socket(AF_INET, SOCK_DGRAM, 0);
	if (base == NULL)
		return -1;

	memset(&su, 0, sizeof(su));
	su.sin.sin_family = AF_INET;
	su.sin.sin_addr = addr;
	su.sin.sin_port = htons(port);
	if (select_event_bind(base, &su)) {
		dprintf(fderr, "%m\n");
		select_event_free(base);
		return -1;
	}

	if (script && script[0]) {
		p = (struct notice_block_expand *)calloc(sizeof(struct notice_block_expand), 1);
		strlcpy(p->script, script, sizeof(p->script));
		p->nb.notice_call = (notice_fn_t)fdns_netconf_cb;
		p->nb.concern = DF_WANLINK | DF_WANIPFILE;
		p->nb.priority = 80;
		p->nb.data = fake_addr.s_addr;
		p->base = base;
		p->event = p->nb.concern & ~dev_event_current();
		fdns_netconf_cb(p, 0, dev_event_current());
		dev_event_chain_register(&p->nb);
	}

	select_event_attach(base, &fdnsd_op, (void *)p);
	snprintf(base->name, sizeof(base->name), "udp://%u.%u.%u.%u:%u/%u.%u.%u.%u",
	         NIPQUAD(addr), port, NIPQUAD(fake_addr));
	return 0;
}

/*
Options:
	-p port         Listen port
	-s addr         Binding address
	-f addr         Fake IP address
	-q              Stop
	-S script       Script to run
 */
static int mod_fdnsd(int argc, char **argv, int fd)
{
	struct in_addr bound, fake;
	unsigned short port = 53;
	int opt, quit = 0;
	char script[MAX_SCRIPTPATH] = { [0] = '\0' };

	bound.s_addr = fake.s_addr = INADDR_ANY;
	optind = 0;	/* reset to 0, rather than the traditional value of 1 */
	while ((opt = getopt(argc, argv, "p:s:f:qS:")) != -1) {
		switch (opt) {
		case 'q':
			quit = 1;
			break;
		case 'p':
			port = htons(strtol(optarg, NULL, 0));
			break;
		case 's':
			if (inet_pton(AF_INET, optarg, &bound) == 1)
				break;
			return ({ dprintf(fd, "Invalid option\n"); 1; });
		case 'S':
			strlcpy(script, optarg, sizeof(script));
			break;
		case 'f':
			if (inet_pton(AF_INET, optarg, &fake) == 1)
				break;
		default:
			dprintf(fd, "Invalid option\n");
			return 1;
		}
	}
	if (quit)
		select_event_freebyname("udp://%u.%u.%u.%u:%u", NIPQUAD(bound), port);
	else if (fake.s_addr && fake.s_addr != INADDR_NONE)
		fdnsd_run(bound, port, fake, fd, script);
	return 0;
}

static void __attribute__((constructor)) register_fdnsd_module(void)
{
	fifo_cmd_register("fdnsd",
		"\t[-p port] [-s address] [-f addr]",
		"fake dnsd", mod_fdnsd);
}
