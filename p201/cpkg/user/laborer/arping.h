#ifndef __arping_h_
#define __arping_h_

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <linux/if_arp.h>
#include <linux_list.h>		/* libselect_event */

#define FIPQUAD(addr) \
    ((unsigned char *)&(addr)) + 0, \
    ((unsigned char *)&(addr)) + 1, \
    ((unsigned char *)&(addr)) + 2, \
    ((unsigned char *)&(addr)) + 3

enum {
	DAD = 1,
	UNICASTING = 2,
	STRICT = 4
};

struct neighbor {
	struct list_head list;
	struct in_addr src, dst;
	struct sockaddr_ll me, he;
	int fd;			/* raw socket descriptor */
	long tid;		/* timer id which called back on no response */
	unsigned int copt;	/* control option mask */
	char *script;
	void (*cb)(struct neighbor *, int rcode);
	int transmit, timeout, interval;
};

struct neighbor *arping_main(int argc, char **argv, int fd);
long schedule(unsigned long data,
              int (*func)(long, unsigned long), int timeout);
#endif
