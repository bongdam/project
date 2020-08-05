/*
 * vpnconf.c
 *
 * APACRTL-128, IPSec/PPTP/L2TP VPN
 *
 * 1) Build configuration files for VPN configuration at system booting.
 * 2) Launch VPN application by WAN link status
 * 3) Build scripts called in VPN application
 * 4) Control iptables and routing table by VPN connection status.
 */

/* System include files */
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <stdarg.h>
#include <errno.h>
#include <signal.h>
#include <sys/ioctl.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

/* Local include files */
#include "apmib.h"
#include "mibtbl.h"

#include "sys_utility.h"
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "nvram_mib/nvram_mib.h"
#include <bcmnvram.h>
#include <libytool.h>
#include <shutils.h>
#include "vpnconf.h"

/*==========================================================================*/
/* Define */
#ifndef MIN
#define MIN(a, b) (((a)>(b))?(a):(b))
#endif

/*==========================================================================*/
/* Variables */
char wan_ifname[24];
char wan_ipaddr[24];
char program[24] = "vpnconf";
int f_debug = 0;

char *dummy_dev = "> /dev/null";

/*==========================================================================*/
static int check_server_connectivity(char *name);

#define nvram_atoi(name, dfl)	(int)strtol(nvram_get(name) ? : __tostring_1(dfl), NULL, 0)

/*==========================================================================*/
static void init_variables(int argc, char *argv[])
{
	struct in_addr wanaddr;
	char *p;

	/* get WAN interface name */
	strncpy(wan_ifname, "eth1", sizeof(wan_ifname));

	/* get WAN IP address */
	if (getInAddr(wan_ifname, IP_ADDR_T, (void *)&wanaddr) != 0) {
		p = inet_ntoa(wanaddr);
		if (p != NULL) {
			strcpy(wan_ipaddr, p);
		}
	}

	/* set program name */
	if (argc > 0 && argv[0] != NULL)
		strncpy(program, argv[0], sizeof(program));

	/* set program name */
	f_debug = nvram_atoi("vpn_debug", 0);
	if (f_debug) {
		dummy_dev = NULL;
	}
}

/*
 * get_iptables_num: get number of 1st item of 1st line after
 *					 excuting cmd
 */
static int get_iptables_num(char *cmd)
{
	char _cmd[200], file[40];
	int number = 0;

	sprintf(file, "/tmp/tmp%d", getpid());
	sprintf(_cmd, "%s > %s", cmd, file);
	system(_cmd);
	yfcat(file, "%d", &number);

	unlink(file);
	return (number);
}

/*
 * netmask_num_to_ipaddr: convert netmask number to subnet mask notation
 *					ex) <ip>/24 --> "255.255.255.0"
 */
static int netmask_num_to_ipaddr(char *buf, int sz, int masknum)
{
	struct in_addr addr;

	if (masknum < 0 || masknum > 32 || buf == NULL || sz < 20)
		return (-1);

	addr.s_addr = htonl((0xffffffff << (32 - masknum)) & 0xffffffff);
	snprintf(buf, sz, "%s", inet_ntoa(addr));

	return (0);
}

/*
 * get_ippool_range: return range string of ip address and pool size
 *					ex) 192.168.1.10,10 --> "192.168.1.10-19"
 */
static char *get_ippool_range(char *buf, int sz, char *start, int num)
{
	char *p;
	int	i;

	strcpy(buf, "error");
	if (num > 0 && num < 254) {
		p = strrchr(start, '.');
		if (p && (i = atoi(p + 1)) > 0 && i > 0 && i + num < 254) {
			snprintf(buf, sz, "%s-%d", start, i + num - 1);
		}
	}

	return (buf);
}

/*
 * get_min_ip_of_subnet: return 1st vaild ip address of given subnet
 *					ex) 192.168.1.0/24 --> "192.168.1.1"
 */
static char *get_min_ip_of_subnet(char *buf, int sz, char *ip_subnet)
{
	char *p, *q, tmp[40];
	struct in_addr addr;
	int	err, mn;

	strcpy(buf, "error");
	strncpy(tmp, ip_subnet, sizeof(tmp));
	p = tmp;
	q = strsep(&p, "/");
	if (p && q) {
		mn = atoi(p);
		err = inet_aton(q, &addr);
		if (mn > 0 && mn < 32 && err != 0) {
			addr.s_addr &= htonl((0xffffffff << (32 - mn)) & 0xffffffff);
			addr.s_addr |= htonl(1L);
			snprintf(buf, sz, "%s", inet_ntoa(addr));
		}
	}
	return (buf);
}

static int nvram_vmatch(char *fmt, const char *val, ...)
{
	char *p, buffer[128];
	va_list args;
	int ret = 0;

	va_start(args, val);
	p = yvasprintf(buffer, sizeof(buffer), fmt, args);
	va_end(args);

	if (p != NULL) {
		ret = nvram_match(p, val);
		if (p != buffer)
			free(p);
	}
	return (ret);
}

static char *nvram_safe_vget(char *fmt, ...)
{
	char *p, *q, buffer[128];
	va_list args;

	va_start(args, fmt);
	p = yvasprintf(buffer, sizeof(buffer), fmt, args);
	va_end(args);

	q = NULL;
	if (p != NULL) {
		q = nvram_get(p);
		if (p != buffer)
			free(p);
	}
	return (q != NULL ? q : "");
}

static int is_l2tp_enc_needed(void)
{
	static int f_need = -1;

	if (f_need < 0) {
		if (nvram_match("vpn_pptp_enable", "1") &&
		    nvram_match("vpn_pptp_protocol", "l2tp") &&
		    nvram_match("vpn_pptp_encryption", "1")) {
			f_need = 1;
		} else {
			f_need = 0;
		}
	}
	return (f_need);
}

static unsigned long upseconds(void)
{
	unsigned long ret;
	yfcat("/proc/uptime", "%ld", &ret);
	return (ret);
}

static int command_and_grep_count(char *command, char *str)
{
	FILE *fp;
	char cmd[100], buf[100], file[40];
	int count = 0;

	snprintf(file, sizeof(file), "/tmp/tmp%d", getpid());
	snprintf(cmd, sizeof(cmd), "%s | grep \"%s\" > %s", command, str, file);
	system(cmd);

	fp =  fopen(file, "r");
	if (fp) {
		while (fgets(buf, sizeof(buf), fp)) {
			if (strstr(buf, str) != NULL && strstr(buf, "grep") == NULL)
				count += 1;
		}
		fclose(fp);
	}
	unlink(file);

	return (count);
}

/*==========================================================================*/
/* IPSec VPN */
static int ipsec_vpn_config_build(void)
{
	FILE *fp;
	int i, f_active;
	int dpddelay, dpdtimeout;
	char	buf[40];

	f_active = nvram_match("vpn_ipsec_enable", "1") ? 1 : 0;

	// strong swan config
	fp = fopen(STRONGSWAN_CONFIG_FILE, "w");
	if (fp != NULL) {
		fprintf(fp, "charon {\n");
		fprintf(fp, "  load = sha1 sha2 md5 aes des hmac gmp random nonce kernel-netlink socket-default updown stroke\n");
		fprintf(fp, "}\n");
		fclose(fp);
	}

	// ipsec updown script
	yfecho(IPSEC_VPN_SCRIPT, O_WRONLY | O_CREAT | O_TRUNC, 0744,
	       "/usr/libexec/ipsec/_updown iptables; %s script ipsec $PLUTO_VERB $PLUTO_CONNECTION\n", program);

	// ipsec config
	fp = fopen(IPSEC_CONFIG_FILE, "w");
	if (fp != NULL) {
		fprintf(fp, "config setup\n");
		fprintf(fp, "  # strictcrlpolicy=yes\n");
		fprintf(fp, "  # uniqueids = no\n");
		if (!f_debug) {
			fprintf(fp, "  charondebug=\"net 0, enc 0\"\n");	/* disable DPD syslog */
		}
		fprintf(fp, "\n");
		fprintf(fp, "conn %%default\n");
		//fprintf(fp, "  ikelifetime=%dm\n", 10800);	// 3hours
		//fprintf(fp, "  lifekey=%dm\n", 3600);			// 1hour
		//fprintf(fp, "  margintime=%dm\n", 9);			// 9min
		//fprintf(fp, "  keyingtries=%d\n", 3);
		fprintf(fp, "  keyexchange=%s\n", "ikev1");
		fprintf(fp, "  authby=secret\n");
		fprintf(fp, "  leftupdown=%s\n", IPSEC_VPN_SCRIPT);

		if (f_active) {
			for (i = 0; i < IPSEC_MAX_SESSION; i++) {
				if (nvram_vmatch("vpn_ipsec%d_active", "1", i)) {
					fprintf(fp, "\n");
					fprintf(fp, "conn %s\n", nvram_safe_vget("vpn_ipsec%d_conn_name", i));

					/* local setting */
					fprintf(fp, "  left=%%any\n");
					fprintf(fp, "  leftsubnet=%s\n", nvram_safe_vget("vpn_ipsec%d_local_subnet", i));
					if (nvram_vmatch("vpn_ipsec%d_local_fqdn", "1", i)) {
						fprintf(fp, "  leftid=@%s\n", nvram_safe_vget("vpn_ipsec%d_local_id", i));
					} else {
						fprintf(fp, "  leftid=%s\n", wan_ipaddr);
					}

					/* remote setting */
					if (nvram_vmatch("vpn_ipsec%d_server_mode", "1", i)) {
						fprintf(fp, "  right=%%any\n");
					} else {
						fprintf(fp, "  right=%s\n",  nvram_safe_vget("vpn_ipsec%d_remote_host", i));
					}
					fprintf(fp, "  rightsubnet=%s\n", nvram_safe_vget("vpn_ipsec%d_remote_subnet", i));
					if (nvram_vmatch("vpn_ipsec%d_remote_fqdn", "1", i)) {
						fprintf(fp, "  rightid=@%s\n", nvram_safe_vget("vpn_ipsec%d_remote_id", i));
					} else {
						fprintf(fp, "  rightid=%s\n", nvram_safe_vget("vpn_ipsec%d_remote_host", i));
					}
					fprintf(fp, "  auto=add\n");

					/* authentication & encryption algorithm */
					if (!nvram_vmatch("vpn_ipsec%d_ike", "auto", i)) {
						fprintf(fp, "  ike=%s!\n", nvram_safe_vget("vpn_ipsec%d_ike", i));
					}
					if (nvram_vmatch("vpn_ipsec%d_protocol", "esp", i)) {
						if (!nvram_vmatch("vpn_ipsec%d_esp", "auto", i)) {
							fprintf(fp, "  esp=%s!\n", nvram_safe_vget("vpn_ipsec%d_esp", i));
						}
					} else if (nvram_vmatch("vpn_ipsec%d_protocol", "ah", i)) {
						if (nvram_vmatch("vpn_ipsec%d_ah", "auto", i)) {
							fprintf(fp, "  ah=%s\n", "md5,sha1!");
						} else {
							fprintf(fp, "  ah=%s\n", nvram_safe_vget("vpn_ipsec%d_ah", i));
						}
					}
					/* DPD action */
					if (!nvram_vmatch("vpn_ipsec%d_dpd_disable", "1", i)) {
						if (nvram_vmatch("vpn_ipsec%d_server_mode", "1", i)) {
							fprintf(fp, "  dpdaction=clear\n");
						} else {
							fprintf(fp, "  dpdaction=restart\n");
						}
					}
					dpddelay = atoi(nvram_safe_vget("vpn_ipsec%d_dpddelay"));
					if (dpddelay >= 2) {
						dpdtimeout = atoi(nvram_safe_vget("vpn_ipsec%d_dpdtimeout"));
						if (dpdtimeout >= dpddelay) {
							fprintf(fp, "  dpddelay=%d\n", dpddelay);
							fprintf(fp, "  dpdtimeout=%d\n", dpdtimeout);
						}
					}
				}
			}
		}

		// for L2TP/IPSec host-2-host transport
		if (is_l2tp_enc_needed()) {
			fprintf(fp, "\n");
			fprintf(fp, "conn %s\n", L2TP_IPSEC_CONN_NAME);
			fprintf(fp, "  left=%%any\n");
			fprintf(fp, "  leftsubnet=%s[%s]\n",
			        get_min_ip_of_subnet(buf, sizeof(buf), nvram_safe_get("vpn_pptp_local_subnet")),
			        "17/1701");
			fprintf(fp, "  leftid=@%s\n", L2TP_IPSEC_FQDN_NAME);
			if (nvram_match("vpn_pptp_mode", "server")) {
				fprintf(fp, "  right=%%any\n");
			} else {
				fprintf(fp, "  right=%s\n", nvram_safe_get("vpn_pptp_remote_host"));
			}
			fprintf(fp, "  rightsubnet=%s[%s]\n",
			        get_min_ip_of_subnet(buf, sizeof(buf), nvram_safe_get("vpn_pptp_remote_subnet")),
			        "17/1701");
			fprintf(fp, "  rightid=@%s\n", L2TP_IPSEC_FQDN_NAME);
			fprintf(fp, "  auto=add\n");
			fprintf(fp, "  authby=psk\n");
			fprintf(fp, "  rekey=no\n");
		}
		fclose(fp);
	}

	// ipsec secrets
	fp = fopen(IPSEC_SECRETS_FILE, "w");
	if (fp != NULL) {
		if (f_active) {
			for (i = 0; i < IPSEC_MAX_SESSION; i++) {
				if (nvram_vmatch("vpn_ipsec%d_active", "1", i)) {
					if (nvram_vmatch("vpn_ipsec%d_local_fqdn", "1", i)) {
						fprintf(fp, "@%s : PSK \"%s\"\n",
						        nvram_safe_vget("vpn_ipsec%d_local_id", i),
						        nvram_safe_vget("vpn_ipsec%d_psk", i));
					} else {
						fprintf(fp, "%s : PSK \"%s\"\n", wan_ipaddr, nvram_safe_vget("vpn_ipsec%d_psk", i));
					}
					if (nvram_vmatch("vpn_ipsec%d_remote_fqdn", "1", i)) {
						fprintf(fp, "@%s : PSK \"%s\"\n",
						        nvram_safe_vget("vpn_ipsec%d_remote_id", i),
						        nvram_safe_vget("vpn_ipsec%d_psk", i));
					} else {
						fprintf(fp, "%s : PSK \"%s\"\n",
						        nvram_safe_vget("vpn_ipsec%d_remote_host", i),
						        nvram_safe_vget("vpn_ipsec%d_psk", i));
					}
				}
			}
		}

		// for L2TP/IPSec host-2-host transport
		if (is_l2tp_enc_needed()) {
			fprintf(fp, "\n");
			fprintf(fp, "@%s : PSK \"%s\"\n", L2TP_IPSEC_FQDN_NAME,
			        nvram_safe_get("vpn_pptp_psk"));
		}
		fclose(fp);
	}

	return (0);
}

static void ipsec_vpn_client_start(char *name, int index)
{
	char pattern[80], remote_var[40];
	int count = 0;

	if (index < 0) {
		sprintf(remote_var, "vpn_pptp_remote_host");
	} else {
		sprintf(remote_var, "vpn_ipsec%d_remote_host", index);
	}

	if (!check_server_connectivity(remote_var)) {
		return;
	}

	snprintf(pattern, sizeof(pattern), "ipsec up %s", name);
	count = command_and_grep_count("ps", pattern);
	if (count == 0) {
		yexecl(dummy_dev, "sh -c \"ipsec up %s &\"", name);
	}
}

static int ipsec_vpn_start(void)
{
	int	i;
	char *p;

	yexecl(NULL, "ipsec restart");
	sleep(1);

	if (nvram_match("vpn_ipsec_enable", "1")) {
		for (i = 0; i < IPSEC_MAX_SESSION; i++) {
			if (nvram_vmatch("vpn_ipsec%d_active", "1", i) &&
			    !nvram_vmatch("vpn_ipsec%d_server_mode", "1", i)) {
				p = nvram_safe_vget("vpn_ipsec%d_conn_name", i);
				if (p && *p) {
					sleep(1);
					ipsec_vpn_client_start(p, i);
				}
			}
		}
	}

	return (0);
}

static int ipsec_vpn_filter_init(void)
{
	int i;

	yexecl(NULL, "iptables -I INPUT -p udp --dport 4500 -j ACCEPT");
	yexecl(NULL, "iptables -I INPUT -p udp --dport 500 -j ACCEPT");
	yexecl(NULL, "iptables -I INPUT -p 50 -j ACCEPT");
	yexecl(NULL, "iptables -I INPUT -p 51 -j ACCEPT");

	// to accept ping from remote host
	yexecl(NULL, "iptables -A INPUT -i %s -p icmp -d %s -j ACCEPT",
	       wan_ifname, nvram_safe_get("x_user_ip"));

	if (nvram_match("vpn_ipsec_enable", "1")) {
		for (i = 0; i < IPSEC_MAX_SESSION; i++) {
			if (nvram_vmatch("vpn_ipsec%d_active", "1", i)) {
				int line_no;

				line_no = get_iptables_num("iptables -n -t nat -L POSTROUTING -v --line-number | grep MASQUERADE");
				yexecl(NULL, "iptables -t nat -I POSTROUTING %d -o %s -s %s -d %s -j ACCEPT",
				       line_no,
				       wan_ifname,
				       nvram_safe_vget("vpn_ipsec%d_local_subnet", i),
				       nvram_safe_vget("vpn_ipsec%d_remote_subnet", i));
			}
		}
	}

	// for L2TP/IPSec host-2-host transport
	if (is_l2tp_enc_needed() &&
	    nvram_match("vpn_pptp_mode", "server")) {
		yexecl(NULL, "iptables -A INPUT -p udp -m policy --dir in --pol ipsec -m udp --dport 1701 -j ACCEPT");
	}
	return (0);
}

/*==========================================================================*/
/* PPTP VPN */
static int pptp_vpn_server_config_build(void)
{
	FILE *fp;
	int max_conn = 1;
	char *p, buf[40];

	// pptp vpn script
	yfecho(PPTP_VPN_SCRIPT, O_WRONLY | O_CREAT | O_TRUNC, 0744, "%s script pptp $@\n", program);

	// pptpd server config
	fp = fopen(PPTP_SERVER_CONFIG_FILE, "w");
	if (fp != NULL) {
		if (!nvram_match("vpn_pptp_lan2lan", "1")) {
			max_conn = nvram_atoi("vpn_pptp_max_conn", 1);
		}
		fprintf(fp, "connections %d\n", max_conn);	// client-2-lan only
		fprintf(fp, "localip %s\n", wan_ipaddr);
		fprintf(fp, "remoteip %s\n", get_ippool_range(buf, sizeof(buf), nvram_safe_get("vpn_pptp_ippool"), max_conn));
		fclose(fp);
	}

	// ppp options
	fp = fopen(PPTP_OPTION_FILE, "w");
	if (fp != NULL) {
		if ((p = nvram_get("vpn_pptp_dns1")) != NULL)
			fprintf(fp, "ms-dns %s\n", p);
		if ((p = nvram_get("vpn_pptp_dns2")) != NULL)
			fprintf(fp, "ms-dns %s\n", p);
		fprintf(fp, "mtu %d\n", nvram_atoi("vpn_pptp_mtu", 1400));
		fprintf(fp, "lock\n");
		fprintf(fp, "noauth\n");
		fprintf(fp, "nopcomp\n");
		fprintf(fp, "noaccomp\n");
		fprintf(fp, "nobsdcomp\n");
		fprintf(fp, "nodeflate\n");
		fprintf(fp, "usepeerdns\n");
		fprintf(fp, "holdoff 2\n");
		fprintf(fp, "refuse-eap\n");
		fprintf(fp, "refuse-pap\n");
		fprintf(fp, "refuse-chap\n");
		fprintf(fp, "lcp-echo-interval %d\n", nvram_atoi("vpn_pptp_lcp_interval", 10));
		fprintf(fp, "lcp-echo-failure %d\n", nvram_atoi("vpn_pptp_lcp_retry", 3));
		fprintf(fp, "require-mschap-v2\n");
		if (nvram_match("vpn_pptp_encryption", "1")) {
			fprintf(fp, "refuse-mschap\n");
			fprintf(fp, "+mppe required,stateless\n");
		}
		fprintf(fp, "vpnscript %s\n", PPTP_VPN_SCRIPT);
		if (f_debug) {
			fprintf(fp, "debug\n");
		}
		fclose(fp);
	}

	// ppp secrets
	fp = fopen(PPTP_CHAP_SECRETS_FILE, "w");
	if (fp != NULL) {
		fprintf(fp, "# Secrets for authentication using CHAP\n");
		fprintf(fp, "# client  server  secret  IP addresses\n");
		fprintf(fp, "%s * %s *\n", nvram_safe_get("vpn_pptp_account"), nvram_safe_get("vpn_pptp_password"));
		fclose(fp);
	}

	return (0);
}

static int pptp_vpn_server_start(void)
{
	yexecl(NULL, "pptpd -c %s -e /bin/pppd %s",
	       PPTP_SERVER_CONFIG_FILE,
	       f_debug ? "-d" : "");
	return (0);
}

/*---------------------------------------------------------------------------*/

static int pptp_vpn_client_config_build(void)
{
	FILE *fp;

	// pptp vpn script
	yfecho(PPTP_VPN_SCRIPT, O_WRONLY | O_CREAT | O_TRUNC, 0744, "%s script pptp $@\n", program);

	// pptp client config
	fp = fopen(PPTP_CLIENT_CONFIG_FILE, "w");
	if (fp != NULL) {
//		fprintf(fp, "plugin accel-pptp\n");
//		fprintf(fp, "pptp_server %s\n", nvram_safe_get("vpn_pptp_remote_host"));
		fprintf(fp, "remotename PPTP\n");
		fprintf(fp, "linkname PPTP\n");
		fprintf(fp, "ipparam PPTP\n");
		fprintf(fp, "persist\n");
		fprintf(fp, "noauth\n");
		fprintf(fp, "nopcomp\n");
		fprintf(fp, "noaccomp\n");
		fprintf(fp, "nobsdcomp\n");
		fprintf(fp, "nodetach\n");
		fprintf(fp, "novj\n");
		fprintf(fp, "name %s\n", nvram_safe_get("vpn_pptp_account"));
		fprintf(fp, "pty \"pptp %s --nolaunchpppd\"\n", nvram_safe_get("vpn_pptp_remote_host"));
		fprintf(fp, "mtu %d\n", nvram_atoi("vpn_pptp_mtu", 1400));
		fclose(fp);
	}

	// ppp options
	fp = fopen(PPTP_OPTION_FILE, "w");
	if (fp != NULL) {
		fprintf(fp, "lock\n");
		fprintf(fp, "noauth\n");
		fprintf(fp, "nopcomp\n");
		fprintf(fp, "noaccomp\n");
		fprintf(fp, "nobsdcomp\n");
		fprintf(fp, "nodeflate\n");
		fprintf(fp, "usepeerdns\n");
		fprintf(fp, "holdoff 2\n");
		fprintf(fp, "refuse-eap\n");
		fprintf(fp, "refuse-pap\n");
		fprintf(fp, "lcp-echo-interval %d\n", nvram_atoi("vpn_pptp_lcp_interval", 10));
		fprintf(fp, "lcp-echo-failure %d\n", nvram_atoi("vpn_pptp_lcp_retry", 3));
		fprintf(fp, "name %s\n", nvram_safe_get("vpn_pptp_account"));
		if (nvram_match("vpn_pptp_encryption", "1")) {
			fprintf(fp, "+mppe required,stateless\n");
		} else {
			fprintf(fp, "noccp\n");
		}
		fprintf(fp, "vpnscript %s\n", PPTP_VPN_SCRIPT);
		if (f_debug) {
			fprintf(fp, "debug\n");
		}
		fclose(fp);
	}

	// ppp secrets
	fp = fopen(PPTP_CHAP_SECRETS_FILE, "w");
	if (fp != NULL) {
		fprintf(fp, "# Secrets for authentication using CHAP\n");
		fprintf(fp, "# client  server  secret  IP addresses\n");
		fprintf(fp, "%s PPTP %s *\n", nvram_safe_get("vpn_pptp_account"), nvram_safe_get("vpn_pptp_password"));
		fclose(fp);
	}

	return (0);
}

static int pptp_vpn_client_start(void)
{
	char *remote;
	int count = 0;

	if (!check_server_connectivity("vpn_pptp_remote_host")) {
		return (0);
	}

	count = command_and_grep_count("ps", "pppd call");

	if (count < 1) {
		remote = strrchr(PPTP_CLIENT_CONFIG_FILE, '/');
		if (remote != NULL && *(remote + 1) != '\0') {
			yexecl(dummy_dev, "sh -c \"pppd call %s &\"", remote + 1);
		}
	} else if (count == 1) {
		// give SIGHUP to pppd
		yexecl(dummy_dev, "sh -c \"killall -1 pppd\"");
	} else if (count > 1) {
		// no action because pppd is connecting to remote server.
	}

	return (0);
}

static int pptp_vpn_filter_init(void)
{
	int line_no;

	yexecl(NULL, "iptables -I INPUT -i %s -p tcp -m tcp --dport 1723 -j ACCEPT", wan_ifname);
	yexecl(NULL, "iptables -I INPUT -i %s -p 47 -j ACCEPT", wan_ifname);

	line_no = get_iptables_num("iptables -L FORWARD -v --line-number -n | tail -n 1");
	yexecl(NULL, "iptables -I FORWARD %d -i %s -j ACCEPT", line_no, "ppp0");

	// to accept ping from remote host
	yexecl(NULL, "iptables -A INPUT -i ppp+ -p icmp -j ACCEPT");

	if (nvram_match("vpn_pptp_mode", "server") && !nvram_match("vpn_pptp_lan2lan", "1")) {
		int i, max_conn = nvram_atoi("vpn_pptp_max_conn", 1);

		max_conn = MIN(max_conn, 10);
		for (i = 1; i < max_conn; i++) {
			yexecl(NULL, "iptables -I FORWARD %d -i %s%d -j ACCEPT", line_no, "ppp", i);
		}
	}

	return (0);
}

static int pptp_vpn_conn_script(char *ifname)
{
	char *p, *q, buf[40], mask[24];
	int line_no;

	if (nvram_match("vpn_pptp_lan2lan", "1")) {
		strncpy(buf, nvram_safe_get("vpn_pptp_remote_subnet"), sizeof(buf));
		p = buf;
		q = strsep(&p, "/");

		if (p && q && netmask_num_to_ipaddr(mask, sizeof(mask), atoi(p)) == 0) {
			yexecl(dummy_dev, "route add -net %s netmask %s dev %s",
			       q, mask, ifname);
		}
		line_no = get_iptables_num("iptables -n -t nat -L POSTROUTING -v --line-number | grep MASQUERADE");
		yexecl(dummy_dev, "iptables -t nat -I POSTROUTING %d -o %s -s %s -d %s -j ACCEPT",
		       line_no,
		       ifname,
		       nvram_safe_get("vpn_pptp_local_subnet"),
		       nvram_safe_get("vpn_pptp_remote_subnet"));
	}
	if (!nvram_match("vpn_pptp_proxy_arp_disable", "1") && nvram_match("vpn_pptp_mode", "server")) {
		yexecl(">/proc/sys/net/ipv4/conf/br0/proxy_arp", "echo \"1\"");
	}

	return (0);
}

/*==========================================================================*/
/* L2TP VPN */

static int l2tp_vpn_config_build(void)
{
	FILE *fp;
	char *p, buf[40];
	int max_conn = 1;

	// l2tp vpn script
	yfecho(PPTP_VPN_SCRIPT, O_WRONLY | O_CREAT | O_TRUNC, 0744, "%s script l2tp $@\n", program);

	// l2tp config
	fp = fopen(L2TP_CONFIG_FILE, "w");
	if (fp != NULL) {
		fprintf(fp, "[global]\n");
		fprintf(fp, "port = 1701\n");
		fprintf(fp, "auth file = %s\n", L2TP_CHAP_SECRETS_FILE);
		fprintf(fp, "\n");

		// L2TP client config
		fprintf(fp, "[lac client]\n");
		if (is_l2tp_enc_needed()) {
			// It's changed by ipsec tunnel due to NAT traversal
			// the target lns is the LAN IP (br0 I/F) address of remote host.
			// ex) 192.168.35.1
			fprintf(fp, "lns = %s\n", get_min_ip_of_subnet(buf, sizeof(buf), nvram_safe_get("vpn_pptp_remote_subnet")));
		} else {
			fprintf(fp, "lns = %s\n", nvram_safe_get("vpn_pptp_remote_host"));
		}
		fprintf(fp, "require chap = yes\n");
		fprintf(fp, "name = %s\n", nvram_safe_get("vpn_pptp_account"));
		fprintf(fp, "pppoptfile = %s\n", L2TP_OPTION_FILE);
		fprintf(fp, "\n");

		// L2TP server config
		fprintf(fp, "[lns default]\n");
//		fprintf(fp, "local ip = %s\n", wan_ipaddr);
		fprintf(fp, "local ip = %s\n", get_min_ip_of_subnet(buf, sizeof(buf), nvram_safe_get("vpn_pptp_local_subnet")));
		if (!nvram_match("vpn_pptp_lan2lan", "1")) {
			max_conn = nvram_atoi("vpn_pptp_max_conn", 1);
		}
		fprintf(fp, "ip range = %s\n", get_ippool_range(buf, sizeof(buf), nvram_safe_get("vpn_pptp_ippool"), max_conn));
		fprintf(fp, "require chap = yes\n");
		fprintf(fp, "require authentication = yes\n");
		fprintf(fp, "length bit = yes\n");
		fprintf(fp, "pppoptfile = %s\n", L2TP_OPTION_FILE);
		fclose(fp);
	}

	// l2tp options
	fp = fopen(L2TP_OPTION_FILE, "w");
	if (fp != NULL) {
		fprintf(fp, "noauth\n");
		fprintf(fp, "nopcomp\n");
		fprintf(fp, "noaccomp\n");
		fprintf(fp, "nobsdcomp\n");
		fprintf(fp, "nodeflate\n");
		fprintf(fp, "usepeerdns\n");
		fprintf(fp, "holdoff 2\n");
		fprintf(fp, "novj\n");
		fprintf(fp, "noccp\n");
		//fprintf(fp, "holdoff 2\n");
		fprintf(fp, "refuse-eap\n");
		fprintf(fp, "refuse-pap\n");
		fprintf(fp, "lcp-echo-interval %d\n", nvram_atoi("vpn_pptp_lcp_interval", 10));
		fprintf(fp, "lcp-echo-failure %d\n", nvram_atoi("vpn_pptp_lcp_retry", 3));
		fprintf(fp, "name %s\n", nvram_safe_get("vpn_pptp_account"));
		fprintf(fp, "mtu %d\n", nvram_atoi("vpn_pptp_mtu", 1400));
		fprintf(fp, "mru %d\n", nvram_atoi("vpn_pptp_mtu", 1400));
		if (nvram_match("vpn_pptp_mode", "server")) {
			if ((p = nvram_get("vpn_pptp_dns1")) != NULL)
				fprintf(fp, "ms-dns %s\n", p);
			if ((p = nvram_get("vpn_pptp_dns2")) != NULL)
				fprintf(fp, "ms-dns %s\n", p);
		}
		fprintf(fp, "vpnscript %s\n", L2TP_VPN_SCRIPT);
		if (f_debug) {
			fprintf(fp, "debug\n");
		}
		fclose(fp);
	}

	// l2tp secrets
	fp = fopen(L2TP_CHAP_SECRETS_FILE, "w");
	if (fp != NULL) {
		fprintf(fp, "# Secrets for authentication using CHAP\n");
		fprintf(fp, "# client  server  secret  IP addresses\n");
		fprintf(fp, "%s * %s *\n", nvram_safe_get("vpn_pptp_account"), nvram_safe_get("vpn_pptp_password"));
		fclose(fp);
	}

	return (0);
}

static void l2tp_vpn_client_start(void)
{
//	char *remote;
	char cmd[80], str[40];
	int count;

	if (!check_server_connectivity("vpn_pptp_remote_host")) {
		if (access("/var/run/l2tp-control", F_OK)) {
			yexecl(NULL, "killall xl2tpd");
			sleep(1);
		}
		if (is_l2tp_enc_needed()) {
			yexecl(NULL, "ipsec down %s", L2TP_IPSEC_CONN_NAME);
		}
		return;
	}

	// for L2TP/IPSec host-2-host transport
	if (is_l2tp_enc_needed()) {
		snprintf(cmd, sizeof(cmd), "ipsec status %s", L2TP_IPSEC_CONN_NAME);
		snprintf(str, sizeof(str), "%s{", L2TP_IPSEC_CONN_NAME);
		count = command_and_grep_count(cmd, str);

		if (count <= 0) {
			ipsec_vpn_client_start(L2TP_IPSEC_CONN_NAME, -1);
			/* jmchoi: In my testing, it's more safe
			   to try next time after connect ipsec tunnel */
			return;
		}
	}

	if (access("/var/run/l2tp-control", F_OK) != 0) {
		yexecl(NULL, "sh -c \"xl2tpd\"");
		/* jmchoi: In my testing, it's more safe
		   to try next time after connect ipsec tunnel */
		if (f_debug) {
			cprintf("\nxl2tpd start\n");
		}
		return;
	}

	count = command_and_grep_count("ps", "pppd");

	if (count < 1) {
		if (f_debug) {
			cprintf("\nxl2tpd client start\n");
		}
		yexecl("> /var/run/l2tp-control", "echo \"c client\"");
	} else {
		// no action because pppd is connecting to remote server.
	}
}

static int l2tp_vpn_start(void)
{
	yexecl(NULL, "killall xl2tpd");
	yexecl(NULL, "sh -c \"xl2tpd\"");
	if (nvram_match("vpn_pptp_mode", "client") && !is_l2tp_enc_needed()) {
		sleep(1);
		l2tp_vpn_client_start();
	}
	return (0);
}

static int l2tp_vpn_filter_init(void)
{
	int line_no;
	char buf1[40], buf2[40];

	yexecl(NULL, "iptables -I INPUT -i %s -p tcp --dport 1701 -j ACCEPT", wan_ifname);
	yexecl(NULL, "iptables -I INPUT -i %s -p udp --dport 1701 -j ACCEPT", wan_ifname);

	line_no = get_iptables_num("iptables -L FORWARD -v --line-number -n | tail -n 1");
	yexecl(NULL, "iptables -I FORWARD %d -i %s -j ACCEPT", line_no, "ppp0");

	// to accept ping from remote host
	yexecl(NULL, "iptables -A INPUT -i ppp+ -p icmp -j ACCEPT");

	if (nvram_match("vpn_pptp_mode", "server") && !nvram_match("vpn_pptp_lan2lan", "1")) {
		int i, max_conn = nvram_atoi("vpn_pptp_max_conn", 1);
		for (i = 1; i < max_conn; i++) {
			yexecl(NULL, "iptables -I FORWARD %d -i %s%d -j ACCEPT", line_no, "ppp", i);
		}
	}
	if (is_l2tp_enc_needed()) {
		line_no = get_iptables_num("iptables -n -t nat -L POSTROUTING -v --line-number | grep MASQUERADE");
		yexecl(NULL, "iptables -I POSTROUTING %d -t nat -p udp --dport 1701 -s %s -d %s -j ACCEPT",
		       line_no,
		       get_min_ip_of_subnet(buf1, sizeof(buf1), nvram_safe_get("vpn_pptp_local_subnet")),
		       get_min_ip_of_subnet(buf2, sizeof(buf2), nvram_safe_get("vpn_pptp_remote_subnet")));
	}
	return (0);
}

static int l2tp_vpn_conn_script(char *remote_ip)
{
	return (pptp_vpn_conn_script(remote_ip));
}

/*==========================================================================*/
void update_ppp_info_file(char *proto, char *updown, char *ifname, char *localip, char *remoteip)
{
	char file[100];

	snprintf(file,  sizeof(file), "%s%s", PPP_INFO_FILE_PREFIX, ifname);

	if (!strcmp(updown, "up")) {
		if (nvram_match("vpn_pptp_lan2lan", "1")) {
			localip = nvram_safe_get("vpn_pptp_local_subnet");
			remoteip = nvram_safe_get("vpn_pptp_remote_subnet");
		}
		yfecho(file, O_WRONLY | O_CREAT | O_TRUNC, 0644, "%s %s %s %s %lu\n",
		       ifname,
		       proto,
		       localip,
		       remoteip,
		       upseconds());
	} else {
		unlink(file);
	}
}

/*==========================================================================*/
static void vpn_config_init(void)
{
	// L2TP VPN is using IPSec tunnel when it's encrypted.
	if (nvram_match("vpn_ipsec_enable", "1") || is_l2tp_enc_needed()) {
		ipsec_vpn_config_build();
		ipsec_vpn_filter_init();
		ipsec_vpn_start();
	}

	if (nvram_match("vpn_pptp_enable", "1")) {
		if (nvram_match("vpn_pptp_protocol", "pptp")) {
			if (nvram_match("vpn_pptp_mode", "server")) {
				pptp_vpn_server_config_build();
				pptp_vpn_filter_init();
				pptp_vpn_server_start();
			} else {
				pptp_vpn_client_config_build();
				pptp_vpn_filter_init();
				pptp_vpn_client_start();
			}
		} else if (nvram_match("vpn_pptp_protocol", "l2tp")) {
			l2tp_vpn_config_build();
			l2tp_vpn_filter_init();
			l2tp_vpn_start();
		}
	}
}

static void vpn_build_dir(void)
{
	if (access("/var/ipsec", F_OK) != 0) {
		mkdir("/var/ipsec", 0666);
		mkdir("/var/ipsec/ipsec.d", 0666);
		mkdir("/var/ipsec/ipsec.d/aacerts", 0666);
		mkdir("/var/ipsec/ipsec.d/acerts", 0666);
		mkdir("/var/ipsec/ipsec.d/cacerts", 0666);
		mkdir("/var/ipsec/ipsec.d/certs", 0666);
		mkdir("/var/ipsec/ipsec.d/ocspcerts", 0666);
		mkdir("/var/ipsec/ipsec.d/private", 0666);
		mkdir("/var/ipsec/ipsec.d/reqs", 0666);
		mkdir("/var/ipsec/ipsec.d/crls", 0666);
	}
}

// usage: vpnconfig script pptp|l2tp up|down <ifname> <local ip> <remote ip>
static void vpn_script_run(int argc, char **argv)
{
	if (!strcmp(argv[2], "ipsec")) {
		if (argc > 4) {
			// to notify laberer
			yexecl(dummy_dev, "preq vpn_check update ipsec %s", argv[4]);
		}
	} else {
		if (!strcmp(argv[3], "up")) {
			if (argc < 7) {
				fprintf(stderr, "invalid arguments\n");
				exit(1);
			}
			if (!strcmp(argv[2], "pptp")) {
				pptp_vpn_conn_script(argv[4]);
			} else if (!strcmp(argv[2], "l2tp")) {
				l2tp_vpn_conn_script(argv[4]);
			}
			update_ppp_info_file(argv[2], argv[3], argv[4], argv[5], argv[6]);
			// to notify laberer
			yexecl(dummy_dev, "preq vpn_check update %s %s", argv[2], argv[4]);
		} else if (!strcmp(argv[3], "down")) {
			// TODO: set linke down
			if (argc > 4) {
				update_ppp_info_file(argv[2], argv[3], argv[4], NULL, NULL);
				// to notify laberer
				yexecl(dummy_dev, "preq vpn_check update %s %s", argv[2], argv[4]);
			}
		} else {
			fprintf(stderr, "invalid arguments\n");
		}
	}
}

// usage: vpnconfig start pptp|l2tp|ipsec [conn-name]
static void vpn_start_client(char *proto, char *name)
{
	int i;

	if (!strcmp(proto, "pptp")) {
		pptp_vpn_client_start();
	} else if (!strcmp(proto, "l2tp")) {
		l2tp_vpn_client_start();
	} else if (!strcmp(proto, "ipsec")) {
		if (name == NULL) {
			fprintf(stderr, "invalid arguments\n");
			exit(1);
		}
		for (i = 0; i < IPSEC_MAX_SESSION; i++) {
			if (nvram_vmatch("vpn_ipsec%d_conn_name", name, i)) {
				ipsec_vpn_client_start(name, i);
				break;
			}
		}
	} else {
		fprintf(stderr, "invalid arguments\n");
	}
}

/*==========================================================================*/
static int check_server_connectivity(char *name)
{
	int ret = 0;
	FILE *fp;
	char *argv[] = { "ping", "-c", "1", NULL, NULL };
	char file[40], redir[40], buf[100], *host, *p;
	char d_host[60], d_result[60];

	host = nvram_safe_get(name);
	argv[3] = host;
	sprintf(file, "/tmp/ping%d", getpid());
	sprintf(redir, ">%s 2>&1", file);

	yexecv(argv, redir, 3, NULL);
	d_host[0] = d_result[0] = '\0';

	fp = fopen(file, "r");
	if (fp != NULL) {
		while (fgets(buf, sizeof(buf), fp) != NULL) {
			//PING www.abc.co.kr (1.1.1.1): 56 data bytes
			if (f_debug && !strncmp(buf, "PING", 4) && strstr(buf, host) != NULL) {
				snprintf(d_host, sizeof(d_host), "%s", buf);
			}
			//1 packets transmitted, 1 packets received, 0% packet loss
			if (strstr(buf, "packets") != NULL) {
				if (f_debug)
					snprintf(d_result, sizeof(d_result), "%s", buf);

				if ((p = strchr(buf, ',')) != NULL) {
					ret = atoi(p + 1);
					break;
				}
			}
		}
		fclose(fp);
	}

	if (f_debug) {
		cprintf("VPN check server\n%s%s", d_host, d_result);
	}

	unlink(file);
	return (ret == 1);
}

/*==========================================================================*/
static void usage(char *program)
{
	fprintf(stderr, "\nusage:\n");
	fprintf(stderr, "%s init\n", program);
	fprintf(stderr, "%s script pptp|l2tp up|down <ifname> <local-ip> <remote-ip>\n", program);
	fprintf(stderr, "%s start l2tp|pptp|ipsec [conn-name]\n", program);
	fprintf(stderr, "\n");
}

/*
 * 1) Initialize VPN parameters
 * # vpnconf init
 *
*/
int main(int argc, char **argv)
{
	if (argc < 2) {
		usage(argv[0]);
		exit(1);
	}

	init_variables(argc, argv);

	if (!strcmp(argv[1], "init")) {
		vpn_build_dir();
		vpn_config_init();
	} else if (!strcmp(argv[1], "script")) {
		if (argc < 4) {
			usage(argv[0]);
			exit(1);
		}
		vpn_script_run(argc, argv);
	} else if (!strcmp(argv[1], "start")) {
		if (argc < 3) {
			usage(argv[0]);
			exit(1);
		}
		vpn_start_client(argv[2], argv[3]);
	} else {
		fprintf(stderr, "invalid arguments\n");
	}

	return (0);
}
