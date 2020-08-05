#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <ctype.h>
#include <sys/utsname.h>
#include <bcmnvram.h>
#include <syslog.h>
#include "instrument.h"
#include "cmd.h"
#include "vpnconf.h"

enum _vpn_flag {
	VPN_TYPE_IPSEC	 =	0x0001,
	VPN_TYPE_PPTP	 =	0x0002,
	VPN_TYPE_L2TP	 =	0x0004,
	VPN_TYPE_CLIENT	 =	0x0008,
	VPN_TYPE_ENCRYP  =	0x0010,
	VPN_TYPE_LAN2LAN =	0x0020,
	VPN_TYPE_AH 	 =	0x0040,
	VPN_TYPE_ACTIVE	 =	0x0100,
};

enum _vpn_status {
	VPN_STATE_DISCONNECT	= 0,
	VPN_STATE_CONNECTED	= 1,
	VPN_STATE_CONNECTING	= 2
};

enum {
	DBG_POLL = 0x01,
	DBG_START_CMD = 0x02,
	DBG_UPDATE_CMD = 0x04,
};

#define VPN_CHECK_PERIOD	7	// seconds

#define TIME_2010_YEAR	1262271600L

typedef struct _vpn_info {
	int state;
	unsigned long flag;	// _vpn_flag
	unsigned long conn_time;	// the uptime to connection
	unsigned long next_try;		// the time to try next call to recovery
	char name[80];
	char enc[80];
	char net_info[80];
	char start_cmd[80];
	unsigned long pkts[2];	//0: rx, 1::tx
	struct _vpn_info *next;
} vpn_info_t;

static vpn_info_t *hd;
static long timer_id;
static int verbose = 0;
static int debug = 0;
static int link_chk_interval_pptp = 30;
static int link_chk_interval_ipsec = 30;

/*--------------------------------------------------------------------------*/
static unsigned long upseconds(void)
{
	unsigned long ret;
	yfcat("/proc/uptime", "%ld", &ret);
	return (ret);
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

static char *ipsec_conn_name_pos(char *s, char *n, int *phase)
{
	char *q;

	*phase = 0;
	while (*s == ' ' || *s == '\t')
		s++;
	if (strncmp(s, n, strlen(n)) == 0) {
		q = s + strlen(n);
		if (*q == '[') {
			*phase = 1;
		} else if (*q == '{') {
			*phase = 2;
		}
		return (s);
	}
	return (NULL);
}

static int get_net_dev_stats(char *devname, unsigned long *tx, unsigned long *rx)
{
	FILE *fp;
	char buf[200], *ag[40];
	int n, ret = 0;

	fp = fopen("/proc/net/dev", "r");
	if (fp) {
		while (fgets(buf, sizeof(buf), fp)) {
			if (strstr(buf, devname) != NULL) {
				n = ystrargs(buf, ag, 40, ": ", 0);
				*tx = strtoul(ag[2], NULL, 10);
				*rx = strtoul(ag[10], NULL, 10);
				ret = 1;
			}
		}
		fclose(fp);
	}
	return (ret);
}

/*--------------------------------------------------------------------------*/
/*
 * file example: /etc/ppp/info_ppp0
 *	ppp0 l2tp 192.168.36.3 192.168.36.1 1464492275
 */
static void check_pptp_l2tp_vpn(char *name)
{
	char file[40], ifname[20], proto[20], local[40], remote[40];
	unsigned long upsec;
	vpn_info_t *ptr;
	unsigned long now = upseconds();

	if (debug & DBG_UPDATE_CMD && name != NULL)
		syslog(LOG_INFO, "vpn_check %lu update pptp/l2tp %s", now, name);

	for (ptr = hd; ptr != NULL; ptr = ptr->next) {
		if ((name == NULL) && (ptr->flag & (VPN_TYPE_PPTP | VPN_TYPE_L2TP)) &&
		    (ptr->state == VPN_STATE_CONNECTED)) {
			if (ptr->next_try > now) {
				// we need check connection for long term.
				continue;
			}
			ptr->next_try = now + link_chk_interval_pptp;
		}
		if ((ptr->flag & (VPN_TYPE_PPTP | VPN_TYPE_L2TP)) &&
		    (name == NULL || !strcmp(name, ptr->name))) {
			snprintf(file,  sizeof(file), "%s%s", PPP_INFO_FILE_PREFIX, ptr->name);
			if (yfcat(file, "%s%s%s%s%lu", ifname, proto, local, remote, &upsec) == 5) {
				if (!strcmp(ifname, ptr->name)) {
					ptr->conn_time = upsec;
					ptr->next_try = now + link_chk_interval_pptp;
					snprintf(ptr->net_info, sizeof(ptr->net_info), "%s === %s", local, remote);
					get_net_dev_stats(ptr->name, &ptr->pkts[1], &ptr->pkts[0]);
					ptr->state = VPN_STATE_CONNECTED;
				}
			} else {
				if (ptr->state) {
					ptr->state = VPN_STATE_DISCONNECT;
				}
			}
		}
	}
}

/*--------------------------------------------------------------------------*/
/*
 * file example: "ipsec statusall"
 * Security Associations (1 up, 0 connecting):
 *   l2tptunnel[1]: ESTABLISHED 6 hours ago, 192.168.1.2[pptp-ipsec-tunnel]...172.17.124.88[pptp-ipsec-tunnel]
 *   l2tptunnel[1]: IKEv1 SPIs: 77f344f5bd48fa16_i* f487636bcd8352a3_r, rekeying disabled
 *   l2tptunnel[1]: IKE proposal: AES_CBC_128/HMAC_SHA2_256_128/PRF_HMAC_SHA2_256/MODP_3072
 *   l2tptunnel{1}:  INSTALLED, TUNNEL, reqid 1, ESP in UDP SPIs: c3dfd752_i ca9aa6a6_o
 *   l2tptunnel{1}:  AES_CBC_128/HMAC_SHA2_256_128, 35468 bytes_i (802 pkts, 36s ago), 35435 bytes_o (800 pkts, 36s ago), rekeying disabled
 *   l2tptunnel{1}:   192.168.35.1/32[17/l2tp] === 192.168.36.1/32[17/l2tp]
 */
static void check_ipsec_vpn(char *name)
{
	char _cmd[100], file[40];
	char buf[200], *p, *ag[20];
	int phase, n, i, j, step, found;
	FILE *fp;
	vpn_info_t *ptr;
	unsigned long now = upseconds();

	if (debug & DBG_UPDATE_CMD && name != NULL)
		syslog(LOG_INFO, "vpn_check %lu update ipsec %s", now, name);

	snprintf(file, sizeof(file), "/tmp/tmp%d", getpid());
	snprintf(_cmd, sizeof(_cmd), "ipsec statusall > %s", file);
	system(_cmd);

	fp = fopen(file, "r");
	if (fp) {
		for (ptr = hd; ptr != NULL; ptr = ptr->next) {
			if ((name == NULL) && (ptr->flag & VPN_TYPE_IPSEC) &&
			    (ptr->state == VPN_STATE_CONNECTED)) {
				if (ptr->next_try > now) {
					// we need check connection for long term.
					continue;
				}
				ptr->next_try = now + link_chk_interval_ipsec;
			}

			if ((ptr->flag & VPN_TYPE_IPSEC) &&
			    (name == NULL || !strcmp(name, ptr->name))) {
				step = 0;
				found = 0;
				while (fgets(buf, sizeof(buf), fp)) {
					switch (step) {
					case 0:	//start
						if (strncmp(buf, "Security Associations", 21) == 0)
							step = 1;
						break;
					case 1:
						p = ipsec_conn_name_pos(buf, ptr->name, &phase);
						if (p == NULL)
							break;
						step = 2;
						found = 1;
					// fall through
					case 2:
						p = ipsec_conn_name_pos(buf, ptr->name, &phase);
						if (p == NULL) {
							step = -1;
							break;
						}
						if (phase == 1) {
							// IKE phase
							if (strstr(p, "ESTABLISHED") != NULL) {
								if (ptr->state != VPN_STATE_CONNECTED) {
									ptr->conn_time = now;
									ptr->next_try = now + link_chk_interval_ipsec;
								}
								ptr->state = VPN_STATE_CONNECTED;
							} else if (strstr(p, "CONNECTING") != NULL) {
								ptr->state = VPN_STATE_CONNECTING;
							}
						} else if (phase == 2) {
							// ESP phase
							if (strstr(p, "INSTALLED") != NULL) {
								if (strstr(p, "AH") != NULL) {
									ptr->flag |= VPN_TYPE_AH;
								}
							} else if (strstr(p, "bytes_i") != NULL) {
								n = ystrargs(p, ag, 20, ":,()", 0);
								for (i = 0, j = 0; i < n && j < 2; i++) {
									if (strstr(ag[i], "pkts") != NULL) {
										ptr->pkts[j++] = (unsigned long)strtoul(ag[i], NULL, 10);
									}
									if (strstr(ag[i], "AES") != NULL ||
									    strstr(ag[i], "DES") != NULL ||
									    strstr(ag[i], "SHA") != NULL ||
									    strstr(ag[i], "MD5") != NULL) {
										strncpy(ptr->enc, ag[i], sizeof(ptr->enc));
									}
								}
							} else if (strstr(p, "===") != NULL) {
								n = ystrargs(p, ag, 20, ":", 0);
								for (i = 0; i < n; i++) {
									if (strstr(ag[i], "===") != NULL) {
										strncpy(ptr->net_info, ag[i], sizeof(ptr->net_info));
										break;
									}
								}
							}
						}
						break;
					default:
						break;
					} //switch (step)
					if (step < 0)
						break;
				} //while(fgets(buf, sizeof(buf), fp))
				// reset connection info
				if (found == 0) {
					if (ptr->state) {
						ptr->state = VPN_STATE_DISCONNECT;
					}
				}
				rewind(fp);
			} //if (ptr->flag & VPN_TYPE_IPSEC)
		} //for (ptr=hd; ptr!=NULL; ptr=ptr->next)
		fclose(fp);
	}

	unlink(file);
}

/*--------------------------------------------------------------------------*/
static char *get_state_str(vpn_info_t *ptr)
{
	switch (ptr->state) {
	case VPN_STATE_DISCONNECT:
		return ("Disconnect");
	case VPN_STATE_CONNECTING:
		return ("Connecting");
	case VPN_STATE_CONNECTED:
		return ("Connected");
	default:
		break;
	}
	return ("-");
}

static char *get_proto_str(vpn_info_t *ptr)
{
	if (ptr->flag & VPN_TYPE_IPSEC) return ("IPSec");
	if (ptr->flag & VPN_TYPE_PPTP)  return ("PPTP");
	if (ptr->flag & VPN_TYPE_L2TP)  return ("L2TP");
	return ("-");
}

static char *get_lan2lan_str(vpn_info_t *ptr)
{
	if (ptr->flag & VPN_TYPE_LAN2LAN) return ("LAN-2-LAN");
	return ("Client-2-LAN");
}

static char *get_server_client_str(vpn_info_t *ptr)
{
	if (ptr->flag & VPN_TYPE_CLIENT) return ("Client");
	return ("Server");
}

static char *get_auth_encrypt_str(vpn_info_t *ptr)
{
	if (ptr->state == VPN_STATE_CONNECTED) {
		if (ptr->enc[0] != '\0') {
			return (ptr->enc);
		}
	}
	return ("-");
}

static char *get_net_info_str(vpn_info_t *ptr)
{
	if (ptr->state == VPN_STATE_CONNECTED) {
		if (ptr->net_info[0] != '\0') {
			return (ptr->net_info);
		}
	}
	return ("-");
}

static char *get_conn_time_str(vpn_info_t *ptr, char *buf, int buf_sz)
{
	time_t now;
	struct tm *tm;

	strncpy(buf, "-", buf_sz);
	if (ptr->state == VPN_STATE_CONNECTED) {
		now = time(NULL);
		if (now > TIME_2010_YEAR) {
			now -= upseconds() - ptr->conn_time;
			tm = localtime(&now);
			snprintf(buf, buf_sz, "%04d-%02d-%02d %02d:%02d:%02d",
			         tm->tm_year + 1900, tm->tm_mon + 1, tm->tm_mday,
			         tm->tm_hour, tm->tm_min, tm->tm_sec);
		}
	}
	return (buf);
}

static char *get_elapsed_time_str(vpn_info_t *ptr, char *buf, int buf_sz)
{
	strncpy(buf, "-", buf_sz);
	if (ptr->state == VPN_STATE_CONNECTED) {
		int elapsed = (int)(upseconds() - ptr->conn_time);
		snprintf(buf, buf_sz, "%ddays %02d:%02d:%02d",
		         elapsed / (24 * 3600),
		         elapsed % (24 * 3600) / 3600,
		         elapsed % (3600) / 60,
		         elapsed % 60);
	}
	return (buf);
}

/*--------------------------------------------------------------------------*/
// no, name, prptocol, state, lan-2-lan, server/client, auth/encrypt, net-info,
static int print_vpn_info(int fd, char *name)
{
	vpn_info_t *ptr;
	char tmp[40], tmp1[40];
	int i, len = 0;

	for (ptr = hd, i = 0; ptr != NULL; ptr = ptr->next, i++) {
		if (name == NULL || !strcmp(name, "all") || !strcmp(name, ptr->name)) {
			if (ptr->flag & (VPN_TYPE_PPTP | VPN_TYPE_L2TP))
				check_pptp_l2tp_vpn(ptr->name);
			if (ptr->flag & VPN_TYPE_IPSEC)
				check_ipsec_vpn(ptr->name);

			len += dprintf(fd, "%d,%s,%s,%s,%s,%s,%s,%s,%s,%s,%lu,%lu\n",
			               i + 1,	//for WEB GUI, staring from 1 instead of 0
			               ptr->name,
			               get_proto_str(ptr),
			               get_state_str(ptr),
			               get_lan2lan_str(ptr),
			               get_server_client_str(ptr),
			               get_auth_encrypt_str(ptr),
			               get_net_info_str(ptr),
			               get_conn_time_str(ptr, tmp, sizeof(tmp)),
			               get_elapsed_time_str(ptr, tmp1, sizeof(tmp1)),
			               ptr->pkts[0],
			               ptr->pkts[1]);
			if (name != NULL && strcmp(name, "all") != 0)
				break;
		}
	}
	return len;
}

/*--------------------------------------------------------------------------*/
static void reset_vpn_info(void)
{
	vpn_info_t *p, *q;
	for (p = hd; p != NULL; p = q) {
		q = p->next;
		free(p);
	}
	hd = NULL;
}

static vpn_info_t *add_new_vpn_info(int flag, char *name)
{
	vpn_info_t *p, *ptr = malloc(sizeof(vpn_info_t));
	if (ptr) {
		memset(ptr, 0, sizeof(*ptr));
		ptr->flag = flag;
		strncpy(ptr->name, name, sizeof(ptr->name));
		if (hd == NULL)
			hd = ptr;
		else {
			for (p = hd; p->next != NULL; p = p->next)
				;
			p->next = ptr;
		}
	}
	return (ptr);
}

/*static vpn_info_t *search_vpn_info(int flag, char *name)
{
	vpn_info_t *ptr;

	for (ptr = hd; ptr != NULL; ptr = ptr->next) {
		if (((ptr->flag & flag) == flag) && !strcmp(ptr->name, name)) {
			return (ptr);
		}
	}
	return (NULL);
}*/

static int nvram_atoi(char *name, int dfl)
{
	char *p = nvram_get(name);
	return (p) ? (int)strtol(p, NULL, 0) : dfl;
}

/*--------------------------------------------------------------------------*/
static int check_vpn_watchdog(long id, unsigned long arg)
{
	vpn_info_t *ptr;

	// check vpn state
	check_ipsec_vpn(NULL);
	check_pptp_l2tp_vpn(NULL);

	if (debug & DBG_POLL)
		syslog(LOG_INFO, "vpn_check %lu", upseconds());

	// recover disconnected vpn
	for (ptr = hd; ptr != NULL; ptr = ptr->next) {
		if ((ptr->state != VPN_STATE_CONNECTED) && ptr->start_cmd[0] != '\0') {
			yexecl(NULL, ptr->start_cmd);
			if (debug & DBG_START_CMD)
				syslog(LOG_INFO, "vpn_check %lu start-cmd: %s", upseconds(), ptr->start_cmd);
		}
	}

	return 1;
}

static long check_vpn_status(time_t interval)
{
	struct timeval tv = {.tv_sec = interval, .tv_usec = 0 };
	unsigned long flag;
	int	i, n, enabled = 0;
	vpn_info_t *ptr;
	char name[40];

	// clear & free structure
	reset_vpn_info();

	tv.tv_sec = (interval > VPN_CHECK_PERIOD) ? interval : VPN_CHECK_PERIOD;

	// pptp/l2tp
	if (nvram_match("vpn_pptp_enable", "1") && ++enabled) {
		flag = VPN_TYPE_ACTIVE;
		if (nvram_match("vpn_pptp_protocol", "pptp")) flag |= VPN_TYPE_PPTP;
		if (nvram_match("vpn_pptp_protocol", "l2tp")) flag |= VPN_TYPE_L2TP;
		if (nvram_match("vpn_pptp_mode", "client"))   flag |= VPN_TYPE_CLIENT;
		if (nvram_match("vpn_pptp_lan2lan", "1"))	  flag |= VPN_TYPE_LAN2LAN;
		if (nvram_match("vpn_pptp_encryption", "1"))  flag |= VPN_TYPE_ENCRYP;

		if (!(flag & VPN_TYPE_LAN2LAN) && !(flag & VPN_TYPE_CLIENT)) {
			// server & client-to-lan mode only
			n = nvram_atoi("vpn_pptp_max_conn", 1);
		} else {
			n = 1;
		}
		for (i = 0; i < n; i++) {
			snprintf(name, sizeof(name), "ppp%d", i);
			ptr = add_new_vpn_info(flag, name);
			if (flag & VPN_TYPE_ENCRYP) {
				if (flag & VPN_TYPE_PPTP) {
					strcpy(ptr->enc, "MPPE-128");
				} else if (flag & VPN_TYPE_L2TP) {
					strcpy(ptr->enc, L2TP_IPSEC_CONN_NAME);
				}
			}
			if (flag & VPN_TYPE_LAN2LAN && flag & VPN_TYPE_CLIENT) {
				if (flag & VPN_TYPE_L2TP) {
					snprintf(ptr->start_cmd, sizeof(ptr->start_cmd), "sh -c \"vpnconf start l2tp &\"");
				} else {
					snprintf(ptr->start_cmd, sizeof(ptr->start_cmd), "sh -c \"vpnconf start pptp &\"");
				}
			}
		}

		// ipsec tunnel of L2TP
		if (nvram_match("vpn_pptp_enable", "1") &&
		    nvram_match("vpn_pptp_protocol", "l2tp") &&
		    nvram_match("vpn_pptp_encryption", "1")) {
			flag = VPN_TYPE_ACTIVE | VPN_TYPE_IPSEC | VPN_TYPE_ENCRYP | VPN_TYPE_LAN2LAN;
			if (nvram_match("vpn_pptp_mode", "client"))
				flag |= VPN_TYPE_CLIENT;
			ptr = add_new_vpn_info(flag, L2TP_IPSEC_CONN_NAME);
		}

		link_chk_interval_pptp = nvram_atoi("vpn_pptp_chk_interval", 30);
	}

	// IPSec
	if (nvram_match("vpn_ipsec_enable", "1") && ++enabled) {
		for (i = 0; i < IPSEC_MAX_SESSION; i++) {
			if (nvram_vmatch("vpn_ipsec%d_active", "1", i)) {
				flag = VPN_TYPE_ACTIVE | VPN_TYPE_IPSEC | VPN_TYPE_ENCRYP;
				if (nvram_vmatch("vpn_ipsec%d_server_mode", "0", i)) flag |= VPN_TYPE_CLIENT;
				if (!nvram_vmatch("vpn_ipsec%d_lan2lan", "0", i))   flag |= VPN_TYPE_LAN2LAN;
				ptr = add_new_vpn_info(flag, nvram_safe_vget("vpn_ipsec%d_conn_name", i));
				if (flag & VPN_TYPE_LAN2LAN && flag & VPN_TYPE_CLIENT) {
					snprintf(ptr->start_cmd, sizeof(ptr->start_cmd), "sh -c \"vpnconf start ipsec %s &\"", ptr->name);
				}
			}
		}

		link_chk_interval_ipsec = nvram_atoi("vpn_ipsec_chk_interval", 30);
	}

	return (enabled) ? itimer_creat(0UL, check_vpn_watchdog, &tv) : 0;
}

static int mod_vpn_check(int argc, char **argv, int fd)
{
	int i, len = 0;

	if (argc > 2) {
		if (!strcmp("interval", argv[1])) {
			i = strtol(argv[2], NULL, 0);
			if (i > 0) {
				if (timer_id)
					itimer_cancel(timer_id, NULL);
				timer_id = check_vpn_status(i);
			} else if (timer_id) {
				itimer_cancel(timer_id, NULL);;
				timer_id = 0;
			}
		} else if (!strcmp("verbose", argv[1])) {
			verbose = !!strtol(argv[2], NULL, 0);
		} else if (!strcmp("state", argv[1])) {
			len = print_vpn_info(fd, argv[2]);
		} else if (!strcmp("debug", argv[1])) {
			debug = strtol(argv[2], NULL, 0);
		} else if (!strcmp("update", argv[1])) {
			if (argc > 3) {
				if (!strcmp("ipsec", argv[2]))
					check_ipsec_vpn(argv[3]);
				else
					check_pptp_l2tp_vpn(argv[3]);
			}
		}
	}

	if (len == 0) {
		dprintf(fd, "\n");
		// TODO
		if (verbose)
			print_vpn_info(fd, NULL);
	}
	return 0;
}

static void __attribute__((constructor)) register_vpn_check_module(void)
{
	fifo_cmd_register("vpn_check", "\t[verbose <1|0>]\n\t[interval <secs>]",
	                  "control vpn server/client check module", mod_vpn_check);
	timer_id = check_vpn_status(10);
}
