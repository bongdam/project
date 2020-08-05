#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <sys/time.h>
#include <netdb.h>

#include "ares.h"
#include "ares_dns.h"

#define Burst_MAX_iplist 12

struct bulk_hostname {
	char hostname[64];
	unsigned long iplist[Burst_MAX_iplist];
	int iplen;
	int resolv;
	unsigned int port;
	char *host;
};

struct bulk_gethostbyname {
	int state;
	ares_channel channel;
	struct dns_bulk_result **result;
	int *rescnt;
	int repeat_count;
	int count;
	int poll_granule;
	struct bulk_hostname *hostdata;
};

extern int ares_errno;
extern int ares_host_parse(void *arg, int status, unsigned char *abuf, int alen);
extern int ares_do_fdset(ares_channel channel, fd_set * read_fds
#ifdef SUPPORT_TCP
			 , fd_set * write_fds
#endif
    );
extern void ares_do_process(ares_channel channel, fd_set * read_fds
#ifdef SUPPORT_TCP
			    , fd_set * write_fds
#endif
    );
extern struct timeval *ares_do_timeout(ares_channel channel, struct timeval *maxtv,
				       struct timeval *tvbuf);
extern void ares_do_fini(ares_channel channel);
extern int ares_do_init(ares_channel * channelptr, struct ares_options *options, int optmask);
extern void ares_free_areshost(struct ahostent *host);
extern int read_resolver(unsigned int *ns, int siz);

static void callback(void *arg, int status, struct hostent *host);
static struct bulk_gethostbyname *init_bulk_hostbyname(int, char *[], int);
static void free_bulk_hostbyname(struct bulk_gethostbyname *bulk_data);
static struct dns_bulk_result *pack_bulk_result(struct bulk_gethostbyname *, int *, int);

#if BULK_DNS_CACHE
#define DNS_CACHE_FOLDER "/tmp/dns_cache"

static char *despaces(char *s)
{
	char *p, *q;
	int c;

	/* skip leading spaces */
	for (p = s; (c = *p) && (isspace(c) || iscntrl(c)); p++) ;
	/* run to the end of string */
	for (q = p; *q; c = *q++) ;
	for (q--; p < q && (isspace(c) || iscntrl(c)); c = *q)
		*q-- = '\0';
	if (p != s) {
		for (q = s; *p; *q++ = *p++) ;
		*q = 0;
	}
	return s;
}

static void dns_cache_update(struct bulk_gethostbyname *bulk_data)
{
	FILE *fp;
	char buf[256 + sizeof(DNS_CACHE_FOLDER) + 1], tmp[32];
	int i, j;

	for (i = 0; i < bulk_data->count; i++) {
		if (bulk_data->hostdata[i].resolv == 0)
			continue;

		snprintf(buf, sizeof(buf), "%s/%s", DNS_CACHE_FOLDER,
			 bulk_data->hostdata[i].hostname);
#if 0
		if (0 == access(buf, F_OK))
			continue;
#endif
		if ((fp = fopen(buf, "w"))) {
			for (j = 0; j < bulk_data->hostdata[i].iplen; j++) {
				fprintf(fp, "%s\n", inet_ntop(AF_INET,
					&(bulk_data->hostdata[i].iplist[j]), tmp, sizeof(tmp)));
			}
			fclose(fp);
		}
	}
}

static int dns_cache_lookup(struct bulk_hostname *hostdata)
{
	FILE *fp;
	struct in_addr addr;
	char buf[1024];

	if (!hostdata)
		return 0;
	sprintf(buf, "%s/%s", DNS_CACHE_FOLDER, hostdata->hostname);
	if ((fp = fopen(buf, "r")) != NULL) {
		while (fgets(buf, sizeof(buf), fp)) {
			despaces(buf);
			if (!buf[0])
				continue;
			addr.s_addr = inet_addr(buf);
			if (addr.s_addr != INADDR_NONE) {
				memcpy(&hostdata->iplist[hostdata->iplen], &addr,
				       sizeof(struct in_addr));
				hostdata->iplen = hostdata->iplen + 1;
				hostdata->resolv = 1;
			}
		}
		fclose(fp);
	}
	return hostdata->resolv;
}
#endif

static struct bulk_gethostbyname *init_bulk_hostbyname(int argc, char *argv[], int repeat_count)
{
	struct bulk_gethostbyname *h;
	int i, j, k;

	if (argc == 0)
		return NULL;

	if (!(h = (struct bulk_gethostbyname *)calloc(1, sizeof(struct bulk_gethostbyname))))
		return NULL;

	h->count = argc * repeat_count;
	if (!(h->hostdata =
	      (struct bulk_hostname *)calloc(1, sizeof(struct bulk_hostname) * h->count))) {
		free(h);
		return NULL;
	}

	for (j = k = 0; j < repeat_count; j++) {
		for (i = 0; i < argc; i++) {
			sprintf(h->hostdata[k].hostname, "%s", argv[i]);
			h->hostdata[k].host = argv[i];
			k++;
		}
	}

	return h;
}

static void free_bulk_hostbyname(struct bulk_gethostbyname *h)
{
	if (h == NULL)
		return;
	free(h->hostdata);
	free(h);
}

static void callback(void *arg, int status, struct hostent *host)
{
	struct in_addr addr;
	char *mem, **p;
	struct bulk_hostname *hostdata;

	hostdata = (struct bulk_hostname *)arg;
	if (status != ARES_SUCCESS) {
		fprintf(stderr, "%s[%s]\n", ares_strerror(status, &mem), hostdata->hostname);
		ares_free_errmem(mem);
		return;
	}
	for (p = host->h_addr_list; *p && hostdata->iplen < Burst_MAX_iplist; p++) {
		memcpy(&addr, *p, sizeof(struct in_addr));
		hostdata->iplist[hostdata->iplen] = addr.s_addr;
		hostdata->iplen++;
		hostdata->resolv = 1;
	}
}

//type : 0=Network type, 1=Host type
static struct dns_bulk_result *pack_bulk_result(struct bulk_gethostbyname *h, int *count, int type)
{
	int i, j;
	struct dns_bulk_result *res;
	int index;

	*count = 0;
	index = 0;
	for (i = 0; i < h->count; i++)
		index = index + h->hostdata[i].iplen;

	if (index == 0)
		return NULL;
	res = (struct dns_bulk_result *)malloc(sizeof(struct dns_bulk_result) * index);
	if (!res)
		return NULL;

	index = 0;
	for (i = 0; i < h->count; i++) {
		for (j = 0; j < h->hostdata[i].iplen; j++) {
			res[index].ip = h->hostdata[i].iplist[j];
			res[index].port = h->hostdata[i].port;
			res[index].host = h->hostdata[i].host;
			index++;
		}
	}

	*count = index;
	return res;
}

void *create_bulk_query(char **argv, int argc, struct dns_bulk_result **result,
			int *rescnt, int repeat_count)
{
	struct bulk_gethostbyname *bulk_data;
	ares_channel channel;
	struct bulk_hostname *hostdata;
	struct in_addr addr;
	char *p;
	int port, i, status;
	char *errmem;

	*rescnt = 0;
	*result = NULL;
#if BULK_DNS_CACHE
	if (0 != access(DNS_CACHE_FOLDER, F_OK)) {
		printf("dns cache folder not exist!\n");
		if (!mkdir(DNS_CACHE_FOLDER, 509)) {
			printf("create dns cache folder (%s)\n", DNS_CACHE_FOLDER);
		}
	}
#endif
	status = ares_init(&channel);
	if (status != ARES_SUCCESS) {
		fprintf(stderr, "ares_init: %s\n", ares_strerror(status, &errmem));
		ares_free_errmem(errmem);
		return NULL;
	}
	bulk_data = init_bulk_hostbyname(argc, argv, repeat_count);
	if (bulk_data == NULL) {
		ares_destroy(channel);
		return NULL;
	}

	for (i = 0; i < bulk_data->count; i++) {
		p = strchr(bulk_data->hostdata[i].hostname, ':');
		if (p) {
			*p = '\0';
			p++;
			port = atoi(p);
			bulk_data->hostdata[i].port = htons(port);
		} else {
			bulk_data->hostdata[i].port = 0;
		}
	}
	bulk_data->state = 0;
	bulk_data->channel = channel;
	bulk_data->rescnt = rescnt;
	bulk_data->result = result;
	bulk_data->repeat_count = repeat_count;

	for (i = 0; i < bulk_data->count; i++) {
		hostdata = &(bulk_data->hostdata[i]);
#if BULK_DNS_CACHE
		if (dns_cache_lookup(hostdata)) {
			continue;
		}
#endif
		addr.s_addr = inet_addr(hostdata->hostname);
		if (addr.s_addr == INADDR_NONE) {
			ares_gethostbyname(channel, hostdata->hostname, AF_INET, callback,
					   (void *)(&(bulk_data->hostdata[i])));
		} else {
			memcpy(&hostdata->iplist[0], &addr, sizeof(struct in_addr));
			hostdata->iplen = 1;
			hostdata->resolv = 1;
		}
	}
	return (void *)bulk_data;
}

int poll_bulk_query(void *handle)
{
	struct bulk_gethostbyname *h = (struct bulk_gethostbyname *)handle;
	int nfds;
	fd_set read_fds, write_fds;
	struct timeval *tvp, tv;

	if (h == NULL || h->state)
		return -1;

	FD_ZERO(&read_fds);
	FD_ZERO(&write_fds);
	nfds = ares_fds(h->channel, &read_fds, &write_fds);
	if (nfds <= 0) {
		h->state = 1;
		return 0;
	}
	if (h->poll_granule > 0) {
		struct timeval maxtv = { 0, h->poll_granule * 1000 };
		tvp = ares_timeout(h->channel, &maxtv, &tv);
	} else
		tvp = ares_timeout(h->channel, NULL, &tv);
	select(nfds + 1, &read_fds, NULL, NULL, tvp);
	ares_process(h->channel, &read_fds, &write_fds);
	return 1;
}

int destroy_bulk_query(void **handle)
{
	struct bulk_gethostbyname *h;

	if (handle == NULL || (h = (struct bulk_gethostbyname *)*handle) == NULL)
		return -1;
	if (h->channel)
		ares_destroy(h->channel);
#if BULK_DNS_CACHE
	dns_cache_update(h);
#endif
	*(h->result) = pack_bulk_result(h, h->rescnt, 0);
	free_bulk_hostbyname(h);
	*handle = NULL;
	return 0;
}

void dns_bulk_query(char **argv, int argc, struct dns_bulk_result **result,
		    int *rescnt, int repeat_count)
{
	struct bulk_gethostbyname *h;

	h = create_bulk_query(argv, argc, result, rescnt, repeat_count);
	while (poll_bulk_query(h) == 1) ;
	destroy_bulk_query((void **)&h);
}

int set_granule(void *handle, int granularity)
{
	struct bulk_gethostbyname *h = (struct bulk_gethostbyname *)handle;
	int old_granule;

	if (handle == NULL)
		return -1;
	old_granule = h->poll_granule;
	h->poll_granule = granularity;
	return old_granule;
}

int res_gethostbyname(const char *name, struct in_addr *ip, int len)
{
	struct dns_bulk_result *result;
	struct bulk_gethostbyname *h;
	int i, count;

	h = create_bulk_query((char **)&name, 1, &result, &count, 1);
	while (poll_bulk_query(h) == 1) ;
	destroy_bulk_query((void **)&h);

	for (i = 0; i < count && i < len; i++)
		ip[i].s_addr = result[i].ip;
	if (result)
		free(result);
	return i;
}
