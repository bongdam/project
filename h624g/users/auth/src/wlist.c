#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>

#ifdef __ASUS_DVD__
#include "./dlisten/wireless_asus_2421.h"
#else
#include <linux/wireless.h>
#endif
#include <libytool.h>

#include <8192cd.h>
#include "1x_ioctl.h"
#include "dv_dbg.h"
#include "ares.h"

#define ARRAY_SIZE(X) (sizeof(X) / sizeof((X)[0]))

#define MAX_WLIST_URL 128

struct poll_mquery {
	int state;
	int tries, quota;
	struct dns_bulk_result *result;
	void *handle;
	int rescnt;
	char *host[MAX_WLIST_URL];
};

struct wlist_conf {
	unsigned int count;
	struct wlist_conf_host {
		unsigned int ip;
		unsigned short port;
		unsigned short resv;
	} host[0];
};

static struct poll_mquery *glob_mq = NULL;

static void dump_query_result(struct dns_bulk_result *result, int rescnt)
{
	int i;

	if (result != NULL) {
		for (i = 0; i < rescnt; i++)
			DVDBG_PRINT("%s() %s:%d %s\n", __FUNCTION__, inet_ntoa(*((struct in_addr *)&result[i].ip)),
				    ntohs(result[i].port), result[i].host);
	}
}

static int in_compar(const struct dns_bulk_result *r1,
		     const struct dns_bulk_result *r2)
{
	if (r1->ip == r2->ip)
		return 0;
	if (r1->ip > r2->ip)
		return 1;
	return -1;
}

static void make_wlist_conf(struct dns_bulk_result *result, int rescnt,
			    struct wlist_conf **param, int *plen)
{
	int len;
	struct wlist_conf *p;
	int i;

	*param = NULL;
	*plen = 0;

	len = sizeof(unsigned int) + sizeof(struct wlist_conf_host) * rescnt;
	p = (void *)malloc(len);
	if (!p)
		return;

	p->count = rescnt;
	if (rescnt > 0) {
		for (i = 0; i < rescnt; i++) {
			p->host[i].ip = result[i].ip;
			p->host[i].port = result[i].port;
		}
	}
	*param = p;
	*plen = len;
}

static int iwpriv_wlist(int cmd, struct iwreq *wrq)
{
	int skfd = socket(AF_INET, SOCK_DGRAM, 0);
	int res = -1;

	if (skfd == -1)
		return -1;

	DVDBG_PRINT("data='%s' len=%d\n", wrq->u.data.pointer, wrq->u.data.length);
	if (ioctl(skfd, cmd, wrq) < 0)
		perror("iwpriv_wlist");
	else
		res = 0;
	close(skfd);
	return res;
}


static int webrd_init_wlist(char *wlname, char *redir_host, struct dns_bulk_result *result, int rescnt)
{
	int res;
	char tmp[256];
	int plen = 0;
	struct wlist_conf *param = NULL;
	struct iwreq wrq;

	if (wlname == NULL || !wlname[0])
		return -1;
	strncpy(tmp, redir_host, sizeof(tmp));
	strncpy(wrq.ifr_name, wlname, IFNAMSIZ);
	wrq.u.data.pointer = tmp;
	wrq.u.data.length = strlen(tmp) + 1;
	wrq.u.data.flags = RTL8192CD_IOCTL_WLIST_RDHOST_SET;
	iwpriv_wlist(SIOCIWCUSTOM, &wrq);

	qsort(result, rescnt, sizeof(struct dns_bulk_result), (void *)in_compar);
	dump_query_result(result, rescnt);
	make_wlist_conf(result, rescnt, &param, &plen);
	if (!param)
		return -1;

	strncpy(wrq.ifr_name, wlname, IFNAMSIZ);
	wrq.u.data.pointer = (caddr_t)param;
	wrq.u.data.length = plen;
	wrq.u.data.flags = RTL8192CD_IOCTL_WLIST_SET;
	res = iwpriv_wlist(SIOCIWCUSTOM, &wrq);
	if (param)
		free(param);
	return res;
}

extern unsigned long alarm_counter;

void dns_query_work(char *ifname, char *filename, char *redir_host)
{
	struct poll_mquery *mq = (struct poll_mquery *)glob_mq;
	char tmp[128];
	int i, c;

	/* allocate & initialize reentrant query structure */
	if (mq == NULL) {
		FILE *fp;
		if (strlen(redir_host)<3)
			goto abort;
		mq = (struct poll_mquery *)calloc(1, sizeof(struct poll_mquery));
		c = 0;
		mq->host[c++] = strdup(redir_host);
		fp = fopen(filename, "r");
		if (fp) {
			while (fgets(tmp, sizeof(tmp), fp)!=NULL) {
				ydespaces(tmp);
				if(strlen(tmp)<5)
					continue;
				mq->host[c++] = strdup(tmp);
				if(c>=MAX_WLIST_URL)
					break;
			}
			fclose(fp);
		}
		glob_mq = mq;
	} else if (mq->state)
		--mq->quota;

	switch (mq->state) {
	case 3:
		if (mq->quota > 0)
			break;
		//mq->state = 0;
		/* fall thru */
	case 0:
		/* send queries */
		for (i = c = 0; i < ARRAY_SIZE(mq->host); i++) {
			if (mq->host[i])
				c++;
		}
		if (c == 0)
			goto quit;

		mq->handle = create_bulk_query(mq->host, c, &mq->result, &mq->rescnt, 1);

		if (mq->handle == NULL)
			goto quit;
		DVDBG_PRINT("Querying %s ...\n", mq->host[0]);
		mq->state = 1;
		mq->quota = (10 * (1000000 / LIB1X_BASIC_TIMER_UNIT)) << (mq->tries++ % 3);
		set_granule(mq->handle, LIB1X_BASIC_TIMER_UNIT / 1000 / 2);
		/* fall thru */
	case 1:
		if (poll_bulk_query(mq->handle) != 1)
			mq->state = 2;
		break;
	case 2:
		/* destroy_bulk_query shall pack the result along with the literal meaning */
	 	if (mq->handle)
	 		destroy_bulk_query(&mq->handle);
		if (mq->rescnt > 0) {
			webrd_init_wlist(ifname, redir_host, mq->result, mq->rescnt);
			goto quit;
		}
		mq->state = 3;
		break;
	}
	return;

 quit:
	for (i = 0; i < ARRAY_SIZE(mq->host); i++) {
		if (mq->host[i])
			free(mq->host[i]);
	}
 	if (mq->result)
 		free(mq->result);
 	if (mq->handle)
 		destroy_bulk_query(&mq->handle);
	free(mq);
	glob_mq = NULL;
 abort:
	_redirect_used = REDIR_READY;
}
