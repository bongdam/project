#include <arpa/inet.h>
#include <signal.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <time.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/sendfile.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <libytool.h>
#include <bcmnvram.h>

#define ALIGNED(m) __attribute__ ((__aligned__(m)))
#define PACKED __attribute__ ((__packed__))

int DEBUG = 0;

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

struct type_and_class {
	uint16_t type PACKED;
	uint16_t class PACKED;
} PACKED;

/* the message from client and first part of response msg */
struct dns_head {
	uint16_t id;
	uint16_t flags;
	uint16_t nquer;
	uint16_t nansw;
	uint16_t nauth;
	uint16_t nadd;
};

typedef struct sockaddr SA;

static int getInAddr(char *interface, struct in_addr *pAddr)
{
    struct ifreq ifr;
    int skfd = 0, found = 0;
    struct sockaddr_in *addr;

    skfd = socket(AF_INET, SOCK_DGRAM, 0);
	if (skfd < 0)
		return 0;

	strcpy(ifr.ifr_name, interface);

	if (ioctl(skfd, SIOCGIFFLAGS, &ifr) < 0) {
		close(skfd);
		return 0;
	}

	if (ioctl(skfd, SIOCGIFADDR, &ifr) == 0) {
		addr = ((struct sockaddr_in *)&ifr.ifr_addr);
		*pAddr = *((struct in_addr *)&addr->sin_addr);
		found = 1;
	}

	close(skfd);
	return found;
}

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
		if (DEBUG)
			fprintf(stderr, "packet has 0 queries, ignored\n");
		return 0; /* don't reply */
	}
	if (head->flags & htons(0x8000)) { /* QR bit */
		if (DEBUG)
			fprintf(stderr, "response packet, ignored\n");
		return 0; /* don't reply */
	}

	/* QR = 1 "response", RCODE = 4 "Not Implemented" */
	outr_flags = htons(0x8000 | 4);
	err_msg = NULL;

	/* start of query string */
	query_string = (void *)(head + 1);
	if (DEBUG)
		fprintf(stderr, "query_string = %s\n", query_string);
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
	if (DEBUG)
		fprintf(stderr, "'%s'->'%s'\n", query_string, answstr);
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
		if (DEBUG)
			fprintf(stderr, "%s, %s\n", err_msg, "dropping query");
		return 0;
	}
	head->flags |= outr_flags;
	head->nauth = head->nadd = 0;
	head->nquer = htons(1); // why???

	return answb - buf;
}

static int fdnsd_recv(int fd)
{
	uint8_t buf[MAX_PACK_LEN + 1] ALIGNED(4);
	struct sockaddr_in from;
	socklen_t addrlen;
	struct in_addr fake_addr;
	int r, n;

	getInAddr("br0", &fake_addr);
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

int open_listenfd(int port)
{
	int listenfd, optval = 1;
	struct sockaddr_in serveraddr;
	int val = 0;
	struct in_addr intaddr;

	/* Create a socket descriptor */
	if ((listenfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0)
		return -1;

	/* close server socket on exec */
	if (fcntl(listenfd, F_SETFD, 1) < 0)
		return -1;

	/* Eliminates "Address already in use" error from bind. */
	if (setsockopt(listenfd, SOL_SOCKET, SO_REUSEADDR, (const void *)&optval , sizeof(int)) < 0)
		return -1;

	/* Listenfd will be an endpoint for all requests to port
		on any IP address for this host */
	memset(&serveraddr, 0, sizeof(serveraddr));
	serveraddr.sin_family = AF_INET;
	yfcat("/var/sys_op", "%d", &val);
	if (val == 0) {
		if (getInAddr("br0", &intaddr))
			serveraddr.sin_addr.s_addr = intaddr.s_addr;
	}
	serveraddr.sin_port = htons((unsigned short)port);

	if (bind(listenfd, (SA *)&serveraddr, sizeof(serveraddr)) < 0)
		return -1;

	return listenfd;
}

int main(int argc, char** argv)
{
	unsigned short port = 53;
	struct timeval tv, *p_tv = NULL;
	int count, opt, listenfd;
	fd_set fdset;

	while ((opt = getopt(argc, argv, "p:D")) != -1) {
		switch (opt) {
			case 'p':
				port = strtol(optarg, NULL, 10);
				break;
			case 'D':
				DEBUG = 1;
				break;
			default :
				break;
		}
	}

	listenfd = open_listenfd(port);
	if (listenfd > 0) {
		if (DEBUG)
			printf("listen on port %d, fd is %d\n", port, listenfd);
	} else {
		perror("ERROR");
		exit(listenfd);
	}

	// Ignore SIGPIPE signal, so if browser cancels the request, it
	// won't kill the whole process.
	signal(SIGPIPE, SIG_IGN);

	while(1)
	{
		tv.tv_sec = 1;
		tv.tv_usec = 0;
		p_tv = &tv;

		FD_ZERO(&fdset);
		FD_SET(listenfd, &fdset);
		count = select(listenfd + 1, &fdset, NULL, NULL, p_tv);
		if (count > 0) {
			if (FD_ISSET(listenfd, &fdset))
				fdnsd_recv(listenfd);
		} else {
			switch (count) {
				case 0:
					break;
				default:
					if (errno == EINTR)
						continue;
					if (DEBUG)
						printf("select returned %d\n", count);
					break;
			}
		}
	}

	if (listenfd)
		close(listenfd);

	return 0;
}
