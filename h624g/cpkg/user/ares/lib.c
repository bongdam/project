#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "ares.h"

struct host_in_addr {
    struct in_addr *ip;
    int len, result;
};

static void
callback(void *arg, int status, unsigned char *abuf, int alen)
{
    struct ahostent *host = (struct ahostent *)arg;
    struct host_in_addr *hi;
    char **p;
    int i = 0;

    if (host == NULL)
        return;
    ares_errno = status;
    if (status ==  ARES_SUCCESS) {
        if (!ares_host_parse(arg, status, abuf, alen) &&
            host->u.a_addr_list != NULL) {
            hi = (struct host_in_addr *)host->a_priv;
            for (p = host->u.a_addr_list; *p; p++) {
                if (hi->result >= hi->len)
                    break;
                hi->ip[hi->result++].s_addr = host->u.a_in_addr[i++]->s_addr;
            }
        }
    }
    ares_free_areshost(host);
}

int read_resolver(unsigned int *ns, int siz)
{
    FILE *fp;
    char buffer[128];
    char *p, *plast;
    int i;
    unsigned int tmp;

    if (!ns || siz <= 0)
        return 0;

    for (i = 0; i < siz; i++)
        ns[i] = 0;

    i = 0;
    if ((fp = fopen("/etc/resolv.conf", "r"))) {
        while (fgets(buffer, sizeof(buffer), fp) && i < siz) {
            p = strtok_r(buffer, " \t\r\n", &plast);
            if (p && !strcasecmp(p, "nameserver")) {
                p = strtok_r(NULL, " \t\r\n", &plast);
                if (p != NULL) {
                    tmp = inet_addr(p);
                    if (tmp && tmp != (unsigned int)-1)
                        ns[i++] = tmp;
                }
            }
        }
        fclose(fp);
    }
    return i;
}

int res_gethostbyname(const char *name, struct in_addr *ip, int len)
{
    struct host_in_addr hi = { ip, len, 0 };
    struct ares_options options;
    int optmask = ARES_OPT_FLAGS;
    ares_channel chan;
    fd_set readset;
    int i, maxfd;
    struct timeval *tvp, tv;
    unsigned int server[2];

    ares_errno = 0;
    if (!ip || len <= 0)
        return 0;

    if (inet_aton(name, ip))
        return 1;

    memset(&options, 0, sizeof(options));
    options.flags = ARES_FLAG_NOCHECKRESP;
    options.nservers = read_resolver(server, 2);
    if (options.nservers <= 0)
        return 0;
    options.servers = malloc(sizeof(struct in_addr) * options.nservers);
    for (i = 0; i < options.nservers; i++)
        options.servers[i].s_addr = server[i];
    optmask |= ARES_OPT_SERVERS;
    optmask |= (ARES_OPT_TIMEOUT | ARES_OPT_TRIES);
    options.timeout = 1;
    options.tries = 2;

    ares_do_init(&chan, &options, optmask);
    if (options.servers)
        free(options.servers);
    ares_do_query(chan, name, C_IN, T_A, callback, (void *)&hi);
    for (;;) {
        FD_ZERO(&readset);
        maxfd = ares_do_fdset(chan, &readset);
        if (maxfd <= 0)
            break;
        tvp = ares_do_timeout(chan, NULL, &tv);
        if (select(maxfd + 1, &readset, NULL, NULL, tvp) < 0) {
            if (errno != EINTR)
                break;
            continue;
        }
        ares_do_process(chan, &readset);
    }
    ares_do_fini(chan);
    return hi.result;
}
