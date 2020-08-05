#ifndef __1X_PMK_CACHE_H__
#define __1X_PMK_CACHE_H__

#include "1x_common.h"
#include "1x_list.h"

extern struct _WPA2_PMKSA_Node* get_pmksa_node();
extern struct _WPA2_PMKSA_Node* find_pmksa_by_supp(u_char* mac);
extern void dump_pmk_cache(void);
extern struct _WPA2_PMKSA_Node* find_pmksa(u_char* pmkid);
extern void del_pmksa_by_spa(u_char* spa);
extern int is_pmksa_empty(void);
void cache_pmksa(struct _WPA2_PMKSA_Node* pmksa_node);
#if 1
#define wpa2_hexdump(a, b, c) {}
#else
#define wpa2_hexdump(a, b, c) _wap2_hexdump(a, b, c)
extern void _wpa2_hexdump(char* name, u_char * buf, int size );
#endif

#endif

