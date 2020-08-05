#ifndef _TIMER_H_
#define _TIMER_H_

#include <stdarg.h>

#undef EXPORT_FUNCTION

#ifndef __MISC_C_
#	define EXPORT_FUNCTION extern
#else
#	define EXPORT_FUNCTION
#endif

EXPORT_FUNCTION int stricmp(char *s1, char *s2);
EXPORT_FUNCTION unsigned long mhtol(unsigned char *str, int str_len);
EXPORT_FUNCTION char *flash_read(const char *keyword, char *value, int size);
EXPORT_FUNCTION char *flash_readf(char *buf, int bufsize, const char *fmt, ...);
EXPORT_FUNCTION int flash_readf_int(const char *keyword, ...);
EXPORT_FUNCTION void flash_set(const char *keyword, const char *value);
EXPORT_FUNCTION char *trim_spaces(char *str);
EXPORT_FUNCTION void string_to_hex(char *string, char *key, int len);
EXPORT_FUNCTION int hex_to_string(char *string, char *key, int len);
EXPORT_FUNCTION int simple_ether_atoe(char *strVal, unsigned char *MacAddr);
EXPORT_FUNCTION int parse_line(char *line, char *argv[], int argvLen, const char *delim);
EXPORT_FUNCTION int get_wan_ip(long *addr, char *buf);
EXPORT_FUNCTION int read_ip(const char *path, in_addr_t *addr, char *s);
int fread_line(const char *path, char *buf, int len);
//EXPORT_FUNCTION int getMiscData(char *interface, struct _misc_data_ *pData)
#ifndef FALSE
#define FALSE 0
#endif

#ifndef TRUE
#define TRUE 1
#endif

#endif // _TIMER_H_

