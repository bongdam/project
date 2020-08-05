
static const char rcsid[] = "$Id: lg_gethostbyname.c,v 1.1.1.1 2010-04-12 02:11:36 youngho Exp $";

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

#ifndef INADDR_NONE
#define INADDR_NONE 0xffffffff
#endif


static void callback(unsigned int *arg, int status, struct hostent *host);

int __lg_gethostbyname(const char *qname, const char *auxiliary_ns, unsigned long *iplist, int *iplen)
{
    ares_channel channel;
    int optmask = ARES_OPT_FLAGS;
    int status, nfds;
    struct ares_options options;
    struct hostent *hostent;
    fd_set read_fds, write_fds;
    struct timeval *tvp, tv;
    char *errmem;
    struct in_addr addr;
    unsigned int param[3];

    if (iplist == 0 || iplen == 0 || *iplen <= 0) {
        fprintf(stderr, "__ares_gethostbyname: invalid parameter\n");
        return -1;
    }
    param[0] = (unsigned int)iplist;
    param[1] = (unsigned int) * iplen;
    param[2] = (unsigned int)iplen;
    *iplen = 0;

    if (auxiliary_ns) {
        options.flags = ARES_FLAG_NOCHECKRESP;
        options.servers = NULL;
        options.nservers = 0;

        /* Add a server, and specify servers in the option mask. */
        hostent = gethostbyname(auxiliary_ns);
        if (!hostent || hostent->h_addrtype != AF_INET) {
            fprintf(stderr, "__ares_gethostbyname: server %s not found.\n", auxiliary_ns);
            return -1;
        }
        options.servers = malloc(sizeof(struct in_addr));
        if (!options.servers) {
            fprintf(stderr, "__ares_gethostbyname: out of memory\n");
            return -1;
        }
        memcpy(&options.servers[0], hostent->h_addr, sizeof(struct in_addr));
        options.nservers = 1;
        optmask |= ARES_OPT_SERVERS;

        status = ares_init_options(&channel, &options, optmask);
        if (status != ARES_SUCCESS) {
            fprintf(stderr, "ares_init_options: %s\n", ares_strerror(status, &errmem));
            ares_free_errmem(errmem);
            return -1;
        }
    } else {
        status = ares_init(&channel);
        if (status != ARES_SUCCESS) {
            fprintf(stderr, "ares_init: %s\n", ares_strerror(status, &errmem));
            ares_free_errmem(errmem);
            return -1;
        }
    }

    addr.s_addr = inet_addr(qname);
    if (addr.s_addr == INADDR_NONE)
        ares_gethostbyname(channel, qname, AF_INET, (ares_host_callback)callback, (void *)param);
    else
        ares_gethostbyaddr(channel, &addr, sizeof(addr), AF_INET, (ares_host_callback)callback, (void *)param);

    status = 0;
    /* Wait for all queries to complete. */
    while (1) {
        FD_ZERO(&read_fds);
        FD_ZERO(&write_fds);
        nfds = ares_fds(channel, &read_fds, &write_fds);
        if (nfds == 0)
            break;
        tvp = ares_timeout(channel, NULL, &tv);
        select(nfds, &read_fds, &write_fds, NULL, tvp);
        status = ares_process(channel, &read_fds, &write_fds);
    }

    ares_destroy(channel);
    return (*iplen > 0) ? status : -1;
}

static void callback(unsigned int *arg, int status, struct hostent *host)
{
    struct in_addr addr;
    char **p;
    unsigned int *iplist = (unsigned int *)arg[0];
    unsigned int i, limit = arg[1];

    if (status == ARES_SUCCESS) {
        i = 0;
        for (p = host->h_addr_list; *p; p++) {
            if (i >= limit)
                break;
            memcpy(&addr, *p, sizeof(struct in_addr));
            iplist[i++] = addr.s_addr;
        }
        *((unsigned int *)arg[2]) = i;
    }
}
