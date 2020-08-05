#ifndef __AUTH_DV_UTILS_H__
#define __AUTH_DV_UTILS_H__
 
void dv_resolver_init(void);
pid_t dv_resolver_exec(char *name);
int get_addr_from_file(char *prefix, char *name, char *ip_str, int ip_str_len);
void save_results(char *prefix, char *res, char *dst);

#endif
