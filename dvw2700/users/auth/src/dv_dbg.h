#ifndef __DVDBG_H__
#define __DVDBG_H__

extern char *g_wlan_name;
extern int _redirect_used;

extern int mib_get(int id, void *value);
extern void dns_query_work(char *ifname, char *filename, char *redir_host);

enum { REDIR_NONE, REDIR_RESOLV, REDIR_READY };

#if defined(__DAVO__)
extern int dv_debug_enabled;
extern int dv_dbg_printf(char *fmt, ...);

#define DVDBG_PRINT( ... ) do{if(dv_debug_enabled) dv_dbg_printf( __VA_ARGS__ );} while(0)
#define DVDBG_PRINT2( ... ) do{if(dv_debug_enabled) dv_dbg_printf( __VA_ARGS__ );} while(0)
//#define DVDBG_PRINT2( ... ) do{dv_dbg_printf( __VA_ARGS__ );} while(0)
#else
#define DVDBG_PRINT( ... ) do{} while(0)
#define DVDBG_PRINT2( ... ) do{} while(0)
#endif

#ifndef MACF
#define MACF                "%02x:%02x:%02x:%02x:%02x:%02x"
#endif
#ifndef ETHER_ETOA
#define ETHER_ETOA(ea)      (unsigned char)(ea)[0], \
							(unsigned char)(ea)[1], \
							(unsigned char)(ea)[2], \
							(unsigned char)(ea)[3], \
							(unsigned char)(ea)[4], \
							(unsigned char)(ea)[5]
#endif
#endif
