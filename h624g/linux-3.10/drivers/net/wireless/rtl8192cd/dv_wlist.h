#ifndef __DV_WLIST_H__
#define __DV_WLIST_H__

struct wlist_conf {
	unsigned int count;
	struct wlist_conf_host {
		unsigned int ip;
		unsigned short port;
		unsigned short resv;
	} host[0];
};

int wlist_search(void *handle, unsigned int ip, unsigned short port, int is_tcp);
int wlist_init(void **handle, struct wlist_conf *conf);
int wauth_set_wlist(void *params, int p_len, void **_wlist);

#endif

