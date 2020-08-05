#ifndef _custom_h_
#define _custom_h_

#include <arpa/inet.h>
#include <typedefs.h>
#include <bcmnvram.h>
#include <libytool.h>
#include <shutils.h>

#define NIPQUAD(addr) \
    ((unsigned char *)&(addr))[0], \
    ((unsigned char *)&(addr))[1], \
    ((unsigned char *)&(addr))[2], \
    ((unsigned char *)&(addr))[3]

struct nameserver_addr {
	int na_family;
	union {
		in_addr_t na_addr;
		struct in6_addr na_addr6;
	};
};

int commit_nameserver(const char *, struct nameserver_addr *, int, int);
int rmdup_nameserver(struct nameserver_addr *, int);
int sort_nameserver(const char *, struct nameserver_addr *, int, int);
int commit_search(const char *path, char *domains);

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))
#endif

int test_and_run(const char *comm, char *cmdline, int sig);
int start_rtnetlnk(int opmode, int ntwk_mode);
int start_arprobe(int opmode, int ntwk_mode);
int start_telnetd(void);
int start_holepunch(void);
int start_autoreboot(void);
int start_snmp(void);
void set_lan_restrict(void);
/* APACRTL-524 */
int start_childguard(void);

#define ENCRYPT_ADD_VAL 100
#define DECRYPT_ADD_VAL -100
void shift_str(char *src, char *dst, int tmp);
void cal_md5(char *plain_txt, char *md5_txt);
void cal_sha256(char *plain_txt, char *md5_txt);
char *b64_encode(unsigned char *src, int src_len, unsigned char *space, int space_len);
int b64_decode(const char *str, unsigned char *space, int size);

int set_jumbo_frm();
/*int sdmz_configured(char *host, int size);*/
#define sdmz_configured(host, size)	({ (void)host; (void)size; 0; })

FILE *locked_fopen(const char *path, const char *mode, int wait);
void locked_fclose(FILE * f);

struct abuffer {
	char *buf;
	size_t size, count;
};

int run_fcommand(const char *path, const char *fmt, ...);
int add_fcommand(const char *path, int pos, const char *pcmd, const char *cmd);

int safe_atoi(const char *s, int ndefault);
int nvram_atoi(char *name, int dfl);
char *init_abuffer(struct abuffer *, size_t);
void fini_abuffer(struct abuffer *);
int aprintf(struct abuffer *m, const char *f, ...);
#ifdef CONFIG_NVRAM_APMIB
void set_timeZone(void);
#endif	/* CONFIG_NVRAM_APMIB */
int fget_and_test_pid(const char *filename);
void calc_use_data(char *ret_str, unsigned long data_h, unsigned long data_l);
void enable_telnet(void);

int route_del_gateway(char *name);
char *read_line(const char *path, char *s, size_t size);

void start_provisioning(void);
void start_httpd(void);
int get_repeater_mode(void);	/* APACRTL-84  smlee 20151029 */
int start_fdns(void);

#endif	/* _custom_h_ */
