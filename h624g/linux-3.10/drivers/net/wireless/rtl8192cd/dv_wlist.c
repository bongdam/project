#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/proc_fs.h>
#include <linux/netdevice.h>
#include <linux/compiler.h>
#include <linux/init.h>
#include <linux/types.h>
#include <linux/errno.h>

#include "8192cd_debug.h"
#include "dv_wlist.h"

#define _MALLOC(x)	kmalloc(x, GFP_ATOMIC)
#define _FREE(x) 	kfree(x)

#define DBG 0
struct white_port_list
{
	unsigned short port;
	struct white_port_list *next;
};

struct white_list_ip
{
	unsigned int ip;
	struct white_port_list *port_list;
};

struct white_list
{
	int count;
	struct white_list_ip *ip;
	int alloc_count;
};

struct white_list_handle {
	struct white_list *act;
	struct white_list *bk;
};

inline int search_white_list_port_tcp(struct white_list_ip *ip, unsigned short port)
{
    struct white_port_list *temp;
    temp = ip->port_list;
    while (temp!=NULL) {
        if ( (temp->port==0) || (temp->port==port) )
            return 1;
        temp = temp->next;
    }
	return 0;
}

inline int search_white_list_port_udp(struct white_list_ip *ip, unsigned short port)
{
    struct white_port_list *temp;
    temp = ip->port_list;
    while (temp!=NULL) {
        if (temp->port==0)
            return 1;
        temp = temp->next;
    }
	return 0;
}

static struct white_list_ip *search_white_list_ip(struct white_list *list, unsigned int ip)
{
    int start, end, index;
    //struct white_list_ip *ip_list;

	if (list->alloc_count == 0)
		return NULL;

    start = 0;
    end = list->count - 1;
    while(start <= end) {
        index = (start + end) / 2;
        if (list->ip[index].ip == ip) {
            return (&(list->ip[index]));
        } else if (list->ip[index].ip < ip) {
            start = index + 1;
        } else {
            end = index - 1;
        }
    }
	return NULL;
}

static void add_white_list_port(struct white_list_ip *ip, unsigned short port)
{
    struct white_port_list *temp;

	if (search_white_list_port_tcp(ip, port)) {
		DEBUG_INFO("<1>%s():0x%08x : %04x add aborted\n", __FUNCTION__, ip->ip, port);
		return;
	}
	
    temp =  _MALLOC(sizeof(struct white_port_list));
    temp->next = ip->port_list;
    temp->port = port;
    ip->port_list = temp;
	DEBUG_INFO("<1>%s():0x%08x : %04x added\n", __FUNCTION__, ip->ip, port);
}

static void add_white_list_ip(struct white_list *list, unsigned int ip, unsigned short port)
{
    struct white_list_ip *ip_list;
    if (list==NULL)
        return;
	if( (list->count==0) || ((ip_list = search_white_list_ip(list, ip)) == NULL) ) { // donot exist in list
        ip_list = &list->ip[list->count];
        ip_list->ip = ip;
	    ip_list->port_list=NULL;
	    list->count++;
	}
    add_white_list_port(ip_list, port);
}

static void free_white_list(struct white_list *list)
{
    int i;
    struct white_list_ip *ip;
    struct white_port_list *port;

    for (i=0; i<list->count; i++) {
        ip = &(list->ip[i]);
        while (ip->port_list!=NULL) {
            port = ip->port_list;
            ip->port_list = ip->port_list->next;
            _FREE(port);
        }
    }
	if (list->ip)
    	_FREE(list->ip);
    _FREE(list);
}

#if DBG
static void print_white_list(struct white_list *list)
{
	int i;
	char *p;
	struct white_list_ip *ip_list;
	struct white_port_list *temp_port;
	struct in_addr laddr;
	printk ("\n=======================\n");
	printk ("white_list_count=%d\n", list->count);
	for (i=0; i<list->count; i++) {
		ip_list = &(list->ip[i]);
		laddr.s_addr= ip_list->ip;
		printk ("ip=0x%08x(%pI4)", laddr.s_addr, (void *)&laddr.s_addr);
		temp_port = ip_list->port_list;
		while (temp_port!=NULL) {
			printk (", %d", temp_port->port);
			temp_port = temp_port->next;
		}
		printk ("\n");
	}
}
#endif

static struct white_list *init_white_list(struct white_list **cur_list, struct white_list **bak_list, struct wlist_conf *conf)
{
    struct white_list *list;
	int i;

	if (*bak_list!=NULL) {
	    free_white_list(*bak_list);
    }
    *bak_list = *cur_list;

	if (!(list = _MALLOC(sizeof(struct white_list))))
	    return NULL;

	list->alloc_count = conf->count;
	if (conf->count>0) {
		list->ip = (struct white_list_ip *)_MALLOC(list->alloc_count * sizeof(struct white_list_ip));
		if (!list->ip) {
			_FREE(list);
			return NULL;
		}
		memset(list->ip, 0, list->alloc_count * sizeof(struct white_list_ip));
	} else 
		list->ip = NULL;

	list->count = 0;

	for (i=0; i<list->alloc_count; i++) {
		add_white_list_ip(list, conf->host[i].ip, (unsigned short)conf->host[i].port);
		if (list->count >= list->alloc_count)
			break;
	}
	DEBUG_INFO("<1>wlist total %d/%d entries\n", list->count, list->alloc_count);

	*cur_list = list;

	return list;
}

// return value
//      1 : match whitelist rule.
//      0 : 302 found (redirect packet)
static int search(struct white_list *list, unsigned int ip, unsigned short port, int is_tcp)
{
    struct white_list_ip *ip_list;

	if (!list) return 0;

	if( (ip_list = search_white_list_ip(list, ip)) != NULL) { // exist in list
        if (is_tcp) {
	        return search_white_list_port_tcp(ip_list, port);
        } else {
	        return search_white_list_port_udp(ip_list, port);
	    }
	}

    return 0;
}

int wlist_search(void *_list, unsigned int ip, unsigned short port, int is_tcp)
{
	struct white_list_handle *list = (struct white_list_handle *)_list;

	if (!list) return 0;

	return search(list->act, ip, port, is_tcp);
}

int wlist_init(void **_handle, struct wlist_conf *conf)
{
	struct white_list_handle **handle = (struct white_list_handle **)_handle;

	if (*handle == NULL) {
		*handle = _MALLOC(sizeof(struct white_list_handle));
		if (!*handle)
			return -1;
		memset(*handle, 0, sizeof(**handle));
	}
	if (init_white_list(&(*handle)->act, &(*handle)->bk, conf)==NULL) {
		_FREE(*handle);
		*handle=NULL;
		return -2;
	}
#if DBG
	print_white_list((*handle)->act);	
#endif
	return 0;
}

int wauth_set_wlist(void *params, int p_len, void **_wlist)
{
    struct wlist_conf *conf = (struct wlist_conf *)params;

    if (p_len < sizeof(unsigned int) + conf->count*sizeof(struct wlist_conf_host)) {
        return -10;
    }
    return wlist_init(_wlist, conf);
}

