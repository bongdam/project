#ifndef __TMS_MISC_H__
#define __TMS_MISC_H__

int tms_dbg;
#define	DEBUG(x,args...)	do{if (tms_dbg) fprintf(stderr,	" TMS: %s:%d " x, __FUNCTION__,	__LINE__, ##args);}while(0)

unsigned int confirm_server_ip(char	*ip_info, char *ip_n, int ip_n_len);
int getIfHwAddr(char *devname, char *mac);
void get_sys_ver(char *v, int len);
char *read_line(char *p, char *out, int maxlen);
int my_sleep(int sec);
int my_sleep_msec(int msec);
void ether_toa(char *val, unsigned char *mac);
int write_pid(const char *pid_file);
int test_pid(const char *pid_file);
int read_int(const char *file, int def);
int strtoi(const char *s, int *ret);
int safe_atoi(const char *s, int ndefault);
#endif
