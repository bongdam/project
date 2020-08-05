#ifndef _custom_h_
#define _custom_h_

#include <arpa/inet.h>
#include <typedefs.h>
#include <bcmnvram.h>
#include <libytool.h>
#include <shutils.h>
#include <syslog.h>

#define NIPQUAD(addr) \
    ((unsigned char *)&(addr))[0], \
    ((unsigned char *)&(addr))[1], \
    ((unsigned char *)&(addr))[2], \
    ((unsigned char *)&(addr))[3]

#ifndef NQF
#  define NQF "%u.%u.%u.%u"
#endif

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))
#endif

int test_and_run(const char *comm, char *cmdline, int sig);
int start_telnetd(void);
int start_snmp(void);
int start_gateway_keepalive(const char *intf, const char *alternative);
int start_dad(int opmode);

#ifdef CONFIG_NF_NAT_TWINIP
int sdmz_configured(char *host, int size);
int enable_sdmz(char *ifc);
int disable_sdmz(char *ifc);
#define PRIVATE_SYSFS_DIR	"/proc/sys/private/"
#else
#define sdmz_configured(host, size)	({ (void)host; (void)size; 0; })
#endif

struct abuffer {
	char *buf;
	size_t size, count;
};

int run_fcommand(const char *path, const char *fmt, ...);
int add_fcommand(const char *path, int pos, const char *pcmd, const char *fmt, ...);

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

int route_del_gateway(char *name);
char *read_line(const char *path, char *s, size_t size);

int get_repeater_mode(void);	/* APACRTL-84  smlee 20151029 */

int iwpriv_set_mib(char *ifname, const char *fmt, ...);

int test_and_kill_pid(const char *pidfile, int signo);

int strbcat(char *str, size_t size, int nodup, const char *word);

int dotted_to_addr(const char *s, in_addr_t *addr);
in_addr_t nvram_inet_addr(char *name);

struct proto_addrs
{
	struct in_addr addr;
	struct in_addr mask;
	unsigned short port;
};

int parse_proto_address(char *var, struct proto_addrs *paddr);
void wl_connect_limit_count_set(void);
void wl_port_shared_restrict(void);

void var_ntwinfo_init(void);
#define VAR_WAN_IP_FILE 	"/var/wan_ip"
#define VAR_NETMASK_FILE 	"/var/netmask"
#define VAR_GATEWAY_FILE 	"/var/gateway"
#define VAR_DNS_FILE 		"/var/dns"

char *b64_encode(unsigned char *src, int src_len, unsigned char *space, int space_len);
int b64_decode(const char *str, unsigned char *space, int size);
void cal_sha256(char *plain_txt, char *sha256_txt);
#define AUTOUP_STATE "/tmp/autoup_state"
char *showApmsState();
void avoid_same_network(in_addr_t wanip, in_addr_t wanmask);

//iptables make rule
void web_remote_access(char *iface, int opmode, int flt_fd, int nat_fd);
void snmp_make_rules(char *iface, int opmode, int flt_fd, int nat_fd);
void telnet_make_rules(char *iface, int opmode, int fltd, int natd);

int start_captive_service_failure(void);
void check_change_wanip(char *new_ip);
#endif	/* _custom_h_ */
