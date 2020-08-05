#ifndef __WL_IWPRIV_H__
#define __WL_IWPRIV_H__

#include <stdio.h>

extern int wl_iwpriv_cmd_supported(char *mibname);
extern int wl_iwpriv_cmd_table_print(FILE *fp);
extern int wl_iwpriv_set_mib(char *ifname, char *mibname, char *val);
extern char *wl_iwpriv_get_mib(char *ifname, char *mibname, char *buf, int sz);

#endif //__WL_IWPRIV_H__
