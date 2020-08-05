/* Copyright 1998 by the Massachusetts Institute of Technology.
 *
 * Permission to use, copy, modify, and distribute this
 * software and its documentation for any purpose and without
 * fee is hereby granted, provided that the above copyright
 * notice appear in all copies and that both that copyright
 * notice and this permission notice appear in supporting
 * documentation, and that the name of M.I.T. not be used in
 * advertising or publicity pertaining to distribution of the
 * software without specific, written prior permission.
 * M.I.T. makes no representations about the suitability of
 * this software for any purpose.  It is provided "as is"
 * without express or implied warranty.
 */

static const char rcsid[] = "$Id: aprovis.c,v 1.1.1.1 2010-04-12 02:11:36 youngho Exp $";

#include <sys/types.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <netdb.h>
#include "ares.h"
#include "ares_dns.h"

extern int __lg_gethostbyname(const char *qname, const char *auxiliary_ns, unsigned long *iplist, int *iplen);

int main(int argc, char **argv)
{
	unsigned long iplist[12];
    int i, iplen = sizeof(iplist) / sizeof(unsigned long);
    int server_id;  /* jjj, APR-101 additional provisioning requirement of LG-Dacom */

    if (argc < 2) {
        fprintf(stderr, "usage: aprovis {host|addr} [dacom's NS]\n");
        exit(1);
    }
    if ((server_id = __lg_gethostbyname(argv[1], 0, iplist, &iplen)) < 0) {
        if (argc > 2) {
            iplen = sizeof(iplist) / sizeof(unsigned long);
            server_id = __lg_gethostbyname(argv[1], argv[2], iplist, &iplen);
        }
    }

    if (server_id >=0 && iplen) {
        if (argc > 2)
            server_id += 2;
        printf("%d <-- server index (0=1st, 1=2nd, 2=aux server)\n", server_id);
    }

    for (i = 0; i < iplen; i++)
        printf("%s\n", inet_ntoa(*((struct in_addr *)&iplist[i])));

    return 0;
}
