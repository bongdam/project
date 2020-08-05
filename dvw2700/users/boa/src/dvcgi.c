#include <string.h>
#include <stdarg.h>
#include <stdlib.h>
#include <unistd.h>
#include <crypt.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <sys/sysinfo.h>
#include <signal.h>
#include <net/if.h>
#include <stdint.h>
#include <linux/atm.h>
#include <linux/atmdev.h>
#include <ctype.h>
#include <stdio.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/un.h>
#include <libytool.h>
#include <brdio.h>
#ifdef __CONFIG_GNT2100__
#include <nmpipe.h>
#endif
#include "boa.h"
#include "globals.h"
#include "apmib.h"
#include "apform.h"
#include "utility.h"
#include "asp_page.h"
#include "nvram_mib/nvram_mib.h"
#include <bcmnvram.h>
#include <custom.h>

typedef struct __cgiparam_t {
	struct __cgiparam_t *next;
	char *name;
	char *value;
	char data[0];
} cgiparam_t;

typedef struct {
	char command[64];
	int (*handler)(request *wp, struct abuffer * m, char *data);
	int need_run_script;
	int need_reboot;
	int need_factory;
} cgicommand_t;

extern int g_port_info[PRTNR_MAX];
extern unsigned int switch_port_status(int portno);

static int dvcgi_handler_reboot(request *wp, struct abuffer *m, char *data)
{
	if (data && data[0] != '1')
		return -1;
	return 0;
}

static int dvcgi_handler_factoryDefault(request *wp, struct abuffer *m, char *data)
{

	if (data && data[0] != '1')
		return -1;
	return 0;
}

static int dvcgi_handler_tftpServer(request *wp, struct abuffer *m, char *data)
{
	int opmode;
	char ip[32];

	memset(ip, 0, sizeof(ip));
	opmode = nvram_atoi("OP_MODE", 0);

	if (opmode == GATEWAY_MODE) {
		nvram_get_r("IP_ADDR", ip, sizeof(ip));
	} else if (opmode == BRIDGE_MODE){
		yfcat("/var/wan_ip", "%s", ip);
		if ( strlen(ip) < 6 ) {
			aprintf(m, "TELNET Access fail: invalid wan ip  <br>\r\n");
			return 0;
		}
	}

	if (data && data[0] == '1') {
		yexecl(NULL, "sh -c \"telnetd &\"");
		yexecl(NULL, "iptables -t nat -A PREROUTING -p tcp --dport 2323 -j DNAT --to %s:2323", ip);
		yexecl(NULL, "iptables -A INPUT -p tcp --dport 2323 -j TELNMS");
		yexecl(NULL, "iptables -I TELNMS -p tcp --dport 2323 -j ACCEPT");
	} else if (data && data[0] == '0') {
		yexecl(NULL, "killall telnetd");
		yexecl(NULL, "iptables -t nat -D PREROUTING -p tcp --dport 2323 -j DNAT --to %s:2323", ip);
		yexecl(NULL, "iptables -D INPUT -p tcp --dport 2323 -j TELNMS");
		yexecl(NULL, "iptables -D TELNMS -p tcp --dport 2323 -j ACCEPT");
	}

	aprintf(m, "TELNET Access %s<br>\r\n", (data == NULL || data[0] != '1') ? "Refused" : "Permitted");

	return 0;
}

static int dvcgi_handler_led(request *wp, struct abuffer *m, char *data)
{
	if (data && data[0] == '0') {	//led off
		yexecl(NULL, "/etc/tool/led connect");
		yexecl(NULL, "/etc/tool/led off");
	} else if (data && data[0] == '1') {	//led on
		yexecl(NULL, "/etc/tool/led connect");
		yexecl(NULL, "/etc/tool/led on");
	}

	return 0;
}

static int dvcgi_handler_diag_Button(request *wp, struct abuffer *m, char *data)
{
	if (data && (!strcmp(data, "reset") || !strcmp(data, "wps"))) {
		system("echo 864000 > /proc/factory_btn_test");
		return 0;
	}
	return -1;

}

static int dvcgi_handler_diag_result(request *wp, struct abuffer *m, char *data)
{
	FILE *fp;
	char buf[64];
	char btn_name[8];
	int ii=0;
	int btn_press=0;

	if (data && !strcmp(data, "reset")) {
		snprintf(btn_name, sizeof(btn_name), "RESET");
	} else if (data && !strcmp(data, "wps")) {
		snprintf(btn_name, sizeof(btn_name), "WPS");
	} else {
		return -1;
	}

	if ((fp = fopen("/proc/factory_btn_test", "r")) == NULL)
		return -1;

	while (fgets(buf, sizeof(buf), fp) != NULL && ii < 2) {
		if (strstr(buf, btn_name)) {
			sscanf(buf, "%*s %d %*s", &btn_press);
			break;
		}
		ii++;
	}
	fclose(fp);

	if (btn_press == 1)
		aprintf(m, "\"%sDiagPass\"", data);
	else
		aprintf(m, "\"%sDiagFail\"", data);

	return 0;
}

static int dvcgi_handler_info_system(request *wp, struct abuffer *m, char *data)
{
	int i, j;
	char name[80];
	char buf[128];
	char *p_buf;
	char link_speed[5][10];
	unsigned int phy_status[5];
	struct sockaddr sa;
	struct sockaddr vsa;
	unsigned hnib, lnib;
	unsigned char mac_addr[6];
	char btver[4];
	int mtd;
	char rev[8];
	char model[32];
	char serial[64];
	char ssid[64];
	char extra_serial[32];

	mtd = open("/dev/mtd0", O_RDONLY);
	if (mtd > -1) {
		lseek(mtd, 0xc, SEEK_SET);
		read(mtd, btver, sizeof(btver));
		close(mtd);
	} else
		memcpy(btver, "----", sizeof(btver));

	aprintf(m, "<html><head><meta HTTP-EQUIV='Pragma' CONTENT='no-cache'>\r\n");
	aprintf(m, "<meta HTTP-equiv=\"Cache-Control\" content=\"no-cache\">\r\n");
	aprintf(m, "<meta http-equiv=\"Content-Type\" content=\"text/html\" charset=\"utf-8\"></head>\r\n");
	aprintf(m, "<span style=\"font-family:fixedsys\"><br>\r\n");
	yfcat("/etc/version", "%s %s", buf, rev);
	aprintf(m, "Firmware Version:&nbsp;%s (%s)<br>\r\n", buf, rev);
	aprintf(m, "Boot Version:&nbsp;%c.%c.%c<br>\r\n", btver[1], btver[2], btver[3]);
	aprintf(m, "H/W Version:&nbsp;Unknown<br>\r\n");
	nvram_get_r_def("DEVICE_NAME", model, sizeof(model), "");
	aprintf(m, "ModelName:&nbsp;%s<br>\r\n", model);
	getInAddr("br0", HW_ADDR, (void *)&sa);
	aprintf(m, "Base MAC Address:&nbsp;%02x-%02x-%02x-%02x-%02x-%02x<br><br>\r\n",
			(unsigned char)sa.sa_data[0], (unsigned char)sa.sa_data[1], (unsigned char)sa.sa_data[2],
			(unsigned char)sa.sa_data[3], (unsigned char)sa.sa_data[4], (unsigned char)sa.sa_data[5]);
	aprintf(m, "LAN MAC Address:&nbsp;%02x-%02x-%02x-%02x-%02x-%02x<br>\r\n",
			(unsigned char)sa.sa_data[0], (unsigned char)sa.sa_data[1], (unsigned char)sa.sa_data[2],
			(unsigned char)sa.sa_data[3], (unsigned char)sa.sa_data[4], (unsigned char)sa.sa_data[5]);
	getInAddr("eth1", HW_ADDR, (void *)&sa);
	aprintf(m, "WAN MAC Address:&nbsp;%02x-%02x-%02x-%02x-%02x-%02x<br>\r\n",
			(unsigned char)sa.sa_data[0], (unsigned char)sa.sa_data[1], (unsigned char)sa.sa_data[2],
			(unsigned char)sa.sa_data[3], (unsigned char)sa.sa_data[4], (unsigned char)sa.sa_data[5]);
	nvram_get_r_def("HW_SERIAL_NO", serial, sizeof(serial), "");
	aprintf(m, "Serial Number: %s (길이:<font color=red>%d</font>)<br>\r\n", serial, strlen(serial));
	nvram_get_r_def("HW_EXTRA_SN", extra_serial, sizeof(extra_serial), "");
	aprintf(m, "Extra Serial: %s (길이:<font color=red>%d</font>)<br><br>\r\n", extra_serial, strlen(extra_serial));

	for (i = 0; i < 2; i++) {
		if (i == 0) {
			aprintf(m, "<5G>&nbsp;<br>\r\n");
			getInAddr("wlan0", HW_ADDR, (void *)&sa);
		} else {
			aprintf(m, "<2.4G>&nbsp;<br>\r\n");
			getInAddr("wlan1", HW_ADDR, (void *)&sa);
		}
		sprintf(name, "WLAN%d_SSID", i);
		memset(ssid, 0, sizeof(ssid));
		nvram_get_r_def(name, ssid, sizeof(ssid), "");
		aprintf(m, "WLAN%d(<font color=red>%s</font>): %02x-%02x-%02x-%02x-%02x-%02x<br>\r\n", i, ssid,
				(unsigned char)sa.sa_data[0], (unsigned char)sa.sa_data[1], (unsigned char)sa.sa_data[2],
				(unsigned char)sa.sa_data[3], (unsigned char)sa.sa_data[4], (unsigned char)sa.sa_data[5]);

		memcpy(mac_addr, (unsigned char *)&sa.sa_data[0], sizeof(mac_addr));
		hnib = mac_addr[0] >> 4;
		lnib = mac_addr[0] & 0xF;

		for (j = 0; j < 4; j++) {
			hnib = (hnib + 1) & 0xF;
			mac_addr[0] = (hnib << 4) + (lnib | 2);
			sprintf(name, "WLAN%d_VAP%d_WLAN_DISABLED", i, j);
			p_buf = nvram_get(name);
			if (p_buf && !strcmp(p_buf, "0")) {
				sprintf(name, "wlan%d-va%d", i, j);
				getInAddr(name, HW_ADDR, (void *)&vsa);
				aprintf(m, "WLAN%d-VA%d: %02x-%02x-%02x-%02x-%02x-%02x | %02x-%02x-%02x-%02x-%02x-%02x<br>\r\n", i, j,
						mac_addr[0], mac_addr[1], mac_addr[2], mac_addr[3], mac_addr[4], mac_addr[5],
						(unsigned char)vsa.sa_data[0], (unsigned char)vsa.sa_data[1], (unsigned char)vsa.sa_data[2],
						(unsigned char)vsa.sa_data[3], (unsigned char)vsa.sa_data[4], (unsigned char)vsa.sa_data[5]);
			} else {
				aprintf(m, "WLAN%d-VA%d: %02x-%02x-%02x-%02x-%02x-%02x | Interface down<br>\r\n", i, j,
						mac_addr[0], mac_addr[1], mac_addr[2], mac_addr[3], mac_addr[4], mac_addr[5]);
			}
		}
		sprintf(name, "WLAN%d_CHANNEL", i);
		p_buf = nvram_get(name);
		if (p_buf && !strcmp(p_buf, "0"))
			aprintf(m, "Channel: auto<br>\r\n");
		else
			aprintf(m, "Channel: %s<br>\r\n", p_buf);

		sprintf(name, "WLAN%d_WLAN_DISABLED", i);
		p_buf = nvram_get(name);
		if (p_buf && !strcmp(p_buf, "0"))
			aprintf(m, "Status: Enabled<br><br>\r\n");
		else
			aprintf(m, "Status: Disabled<br><br>\r\n");
	}

	for (i = 0; i < PRTNR_MAX; i++) {
		j = g_port_info[i];
		phy_status[i] = switch_port_status(j);

		if (phy_status[i] & PHF_LINKUP) {
			if (phy_status[i] & PHF_100M)
				sprintf(link_speed[i], "100M");
			else if (phy_status[i] & PHF_1000M)
				sprintf(link_speed[i], "1000M");
			else if (phy_status[i] & PHF_500M)
				sprintf(link_speed[i], "500M");
			else
				sprintf(link_speed[i], "10M");
		} else {
			sprintf(link_speed[i], "Down");
		}
	}

	aprintf(m, "WAN: <font color=red>%s</font> LAN1: <font color=red>%s</font>\r\n",
		link_speed[0], link_speed[1]);
	aprintf(m, "LAN2: <font color=red>%s</font> LAN3: <font color=red>%s</font>\r\n",
		link_speed[2], link_speed[3]);
	aprintf(m, "LAN4: <font color=red>%s</font><br>\r\n", link_speed[4]);
	aprintf(m, "</span></html>");

	return 0;
}

static int dvcgi_handler_wireless_clt_rssi_show(request *wp, struct abuffer *m, char *data)
{
	int i, l = 0;
	FILE *fp;
	char line[256];
	int found = 0;
	const char *band = (data && strstr(data, "2.4")) ? "wlan1" : "wlan0";
	char ssid_name[30];
	char fullpath[80];

	aprintf(m, "<span style=\"font-family:fixedsys\"><br>\r\n");
	for (i = 0; i < 5; i++) {
		ssid_name[l] = 0;
		if (i == 0)
			l = sprintf(&ssid_name[l], band);
		else
			sprintf(&ssid_name[l], "-va%d", i - 1);

		sprintf(fullpath, "/proc/%s/sta_info", ssid_name);
		if ((fp = fopen(fullpath, "r"))) {
			while (fgets(line, sizeof(line), fp)) {
				ydespaces(line);
				if (strstr(&line[0], "hwaddr") != 0) {
					aprintf(m, "%s%s: client %s ", ssid_name,
						(i == 0) ? "&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;" : "", &line[0]);
					continue;
				}
				if (strstr(&line[0], "rssi") != 0) {
					aprintf(m, " %s \r\n<br>", &line[0]);
					found = 1;
				}
			}
			fclose(fp);
		}
	}
	if (!found)
		aprintf(m, "After connecting wifi client, Retry command!");
	aprintf(m, "\r\n<br>");
	aprintf(m, "</span>");

	return 0;
}

#define MAX_CHAN_RANGE	200
#define SKB_5G_MAX_NUM	19
#define SKB_2G_MAX_NUM	13
#define SKB_GRP_MAX_NUM	14

typedef struct {
	int ch[20];
	int val[20];
	int err[20];
} chan_info_t;
chan_info_t chan_info;

int idx_2g[SKB_2G_MAX_NUM] =
  { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13 };
int idx_5g[SKB_5G_MAX_NUM] =
  { 36, 40, 44, 48, 52, 56, 60, 64, 100, 104, 108, 112, 116, 120, 124, 149, 153, 157, 161 };

typedef struct {
	char str[64];
	int cnt;
	int chk; // range check, DIFF값은 체크 안함
	int grp;
} chk_tx_power_t;

chk_tx_power_t chk_tx_power_2g[] = {
	{"HW_WLAN1_TX_POWER_CCK_A", 13, 1, 0},
	{"HW_WLAN1_TX_POWER_CCK_B", 13, 1, 0},
	{"HW_WLAN1_TX_POWER_HT40_1S_A", 13, 1, 0},
	{"HW_WLAN1_TX_POWER_HT40_1S_B", 13, 1, 0},
	{"HW_WLAN1_TX_POWER_DIFF_HT40_2S",13, 0, 0},
	{"HW_WLAN1_TX_POWER_DIFF_HT20", 13, 0, 0},
	{"HW_WLAN1_TX_POWER_DIFF_OFDM", 13, 0, 0},
	{"", 0, 0, 0},
};

chk_tx_power_t chk_tx_power_5g[] = {
	{"HW_WLAN0_TX_POWER_5G_HT40_1S_A", 170, 1, 0},
	{"HW_WLAN0_TX_POWER_5G_HT40_1S_B", 170, 1, 0},
	{"HW_WLAN0_TX_POWER_DIFF_5G_20BW1S_OFDM1T_A", 14, 0, 1},
	{"HW_WLAN0_TX_POWER_DIFF_5G_20BW1S_OFDM1T_B", 14, 0, 1},
#if 0
	{"HW_WLAN0_TX_POWER_DIFF_5G_80BW1S_160BW1S_B", 14, 0, 1},
	{"HW_WLAN0_TX_POWER_DIFF_5G_80BW1S_160BW1S_C", 14, 0, 1},
#endif
	{"", 0, 0, 0},
};

static int cal_chk(char *str, int ch, int val)
{
	int ret = 0;

	if (!strcmp("HW_WLAN1_TX_POWER_CCK_A", str)) {
		if (val < 25 || val > 36) {
			ret = 1;
		}
	} else if (!strcmp("HW_WLAN1_TX_POWER_CCK_B", str)) {
		if (val < 27 || val > 41) {
			ret = 1;
		}
	} else if (!strcmp("HW_WLAN1_TX_POWER_HT40_1S_A", str)) {
		if (val < 35 || val > 47) {
			ret = 1;
		}
	} else if (!strcmp("HW_WLAN1_TX_POWER_HT40_1S_B", str)) {
		if (val < 37 || val > 51) {
			ret = 1;
		}
	} else if (!strcmp("HW_WLAN0_TX_POWER_5G_HT40_1S_A", str)) {
		if (36 <= ch && ch <= 48) {
			if (val < 21 || val > 36) {
				ret = 1;
			}
		} else if (52 <= ch && ch <= 64) {
			if (val < 22 || val > 38) {
				ret = 1;
			}
		} else if (100 <= ch && ch <= 116) {
			if (val < 22 || val > 39) {
				ret = 1;
			}
		} else if (120 <= ch && ch <= 124) {
			if (val < 22 || val > 39) {
				ret = 1;
			}
		} else if (149 <= ch && ch <= 161) {
			if (val < 31 || val > 46) {
				ret = 1;
			}
		}
	} else if (!strcmp("HW_WLAN0_TX_POWER_5G_HT40_1S_B", str)) {
		if (36 <= ch && ch <= 48) {
			if (val < 25 || val > 41) {
				ret = 1;
			}
		} else if (52 <= ch && ch <= 64) {
			if (val < 26 || val > 41) {
				ret = 1;
			}
		} else if (100 <= ch && ch <= 116) {
			if (val < 24 || val > 39) {
				ret = 1;
			}
		} else if (120 <= ch && ch <= 124) {
			if (val < 24 || val > 39) {
				ret = 1;
			}
		} else if (149 <= ch && ch <= 161) {
			if (val < 27 || val > 43) {
				ret = 1;
			}
		}
	}

	return ret;
}

static void channel_chk(struct abuffer *m, int wlan_id, char *str, int cnt, int chk, int grp)
{
	int i, c = 0, ret = 0;
	int max, err_cnt = 0;
	int val[MAX_CHAN_RANGE];
	char buf[400];
	char *p;

	if (wlan_id == 0) { // 5g
		if (grp)
			max = SKB_GRP_MAX_NUM;
		else
			max = SKB_5G_MAX_NUM;
	} else { // 2.4g
		max = SKB_2G_MAX_NUM;
	}

	memset(buf, 0, sizeof(buf));
	nvram_get_r(str, buf, sizeof(buf));
	p = buf;
	for (i = 0; i < cnt; i++) {
		ret = sscanf(p, "%02x", &val[i]);

		if (ret <= 0 || val[i] == 0)
			val[i] = -1;

		if (grp) {
			chan_info.val[i] = val[i];
		} else {
			if (chan_info.ch[c] == (i + 1)) {
				chan_info.val[c] = val[i];
				if (chk) {
					ret = cal_chk(str, i + 1, chan_info.val[c]);
					if (ret == 0) {
						chan_info.err[c] = 0;
					} else {
						chan_info.err[c] = 1;
						err_cnt++;
					}
				}
				c++;
			}
		}
		p += 2;
	}

	if (err_cnt > 0 && chk) {
		aprintf(m, "[%s] (<font color=\"red\">Abnormal</font>)<br>", str);
		aprintf(m, "Channel: ");
		for (i = 0; i < max; i++) {
			if (chan_info.err[i] == 1)
				aprintf(m, "%d ", chan_info.ch[i]);
		}
		aprintf(m, "<br><br>");
	} else if (chk) {
		aprintf(m, "[%s] (<font color=\"green\">Normal</font>)<br>", str);
	}

	if (chk == 0) {
		aprintf(m, "[%s]<br>", str);
		for (i = 0; i < max; i++) {
			aprintf(m, "%d ", chan_info.val[i]);
		}
		aprintf(m, "<br><br>");
	}
}

static int dvcgi_handler_cal_show(request *wp, struct abuffer *m, char *data)
{
	int i;
	const char *band = (data && strstr(data, "2.4")) ? "WLAN1" : "WLAN0";
	int wlan_idx;
	chk_tx_power_t *p;
	int max;
	char *p_buf;

	if (!strcmp(band, "WLAN1")) {
		wlan_idx = 1;
		max = SKB_2G_MAX_NUM;
		p_buf = nvram_get("HW_WLAN1_11N_THER");
		aprintf(m, "HW_WLAN1_11N_THER %s<br><br><br>\r\n", p_buf);
		for (i = 0; i < max; i++)
			chan_info.ch[i] = idx_2g[i];
		p = &chk_tx_power_2g[0];
	} else {
		wlan_idx = 0;
		max = SKB_5G_MAX_NUM;
		p_buf = nvram_get("HW_WLAN0_11N_THER");
		aprintf(m, "HW_WLAN0_11N_THER %s<br><br><br>\r\n", p_buf);
		for (i = 0; i < max; i++)
			chan_info.ch[i] = idx_5g[i];
		p = &chk_tx_power_5g[0];
	}
	aprintf(m, "Wireless %sG HW Tx Power checking...<br><br>\r\n", wlan_idx ? "2.4" : "5");

	for (; p->str[0]; p++) {
		if (p->chk)
			channel_chk(m, wlan_idx, p->str, p->cnt, 1, p->grp);
	}

#if 0
	aprintf(m, "< Reference ><br>");

	if (wlan_idx) {
		aprintf(m, "<img src=\"graphics/cal_base_2g.png\" border=0><br><br>\r\n");
	} else {
		aprintf(m, "<img src=\"graphics/cal_base_5g.png\" border=0><br><br>\r\n");
	}
#else
	aprintf(m, "<br><br>");
#endif
	aprintf(m, "--- Current AP Tx Power (Decimal) ---<br>");

	aprintf(m, "(Available Channel)<br>");
	for (i = 0; i < max; i++)
		aprintf(m, "%d ", chan_info.ch[i]);
	aprintf(m, "<br><br>");

	if (wlan_idx)
		p = &chk_tx_power_2g[0];
	else
		p = &chk_tx_power_5g[0];

	for (; p->str[0]; p++)
		channel_chk(m, wlan_idx, p->str, p->cnt, 0, p->grp);

	return 0;
}

#if 0
static const char *usocknam = "/var/slogd.sock";

/* size of control buffer to send/recv one file descriptor */
#define	CONTROLLEN	CMSG_LEN(sizeof(int))

static struct cmsghdr *cmptr = NULL;	/* malloc'ed first time */

/*
 * Pass a file descriptor to another process.
 * If fd<0, then -fd is sent back instead as the error status.
 */
static int send_fd(int fd, int fd_to_send)
{
	struct iovec iov[1];
	struct msghdr msg;
	char buf[2];		/* send_fd()/recv_fd() 2-byte protocol */

	iov[0].iov_base = buf;
	iov[0].iov_len = 2;
	msg.msg_iov = iov;
	msg.msg_iovlen = 1;
	msg.msg_name = NULL;
	msg.msg_namelen = 0;

	if (fd_to_send < 0) {
		msg.msg_control = NULL;
		msg.msg_controllen = 0;
		buf[1] = -fd_to_send;	/* nonzero status means error */
		if (buf[1] == 0)
			buf[1] = 1;	/* -256, etc. would screw up protocol */
	} else {
		if (cmptr == NULL && (cmptr = malloc(CONTROLLEN)) == NULL)
			return -1;
		cmptr->cmsg_level = SOL_SOCKET;
		cmptr->cmsg_type = SCM_RIGHTS;
		cmptr->cmsg_len = CONTROLLEN;
		msg.msg_control = cmptr;
		msg.msg_controllen = CONTROLLEN;
		*(int *)CMSG_DATA(cmptr) = fd_to_send;	/* the fd to pass */
		buf[1] = 0;	/* zero status means OK */
	}

	buf[0] = 0;		/* null byte flag to recv_fd() */
	if (sendmsg(fd, &msg, 0) != 2)
		return -1;
	return 0;
}

static int handler_dumplog(request *wp, struct abuffer *m, char *data)
{
	int fd, clen;
	struct sockaddr_un sun;

	if ((fd = socket(AF_UNIX, SOCK_STREAM, 0)) < 0) {
		perror(__func__);
		return -1;
	}

	bzero(&sun, sizeof(sun));
	sun.sun_family = AF_UNIX;
	strcpy(sun.sun_path, usocknam);
	if (!connect(fd, (struct sockaddr *)&sun, sizeof(sun))) {
		char *q, *p = strstr(wp->buffer, "Content-Length:");
		if (p) {
			for (q = p; *q && (*q != '\r' && *q != '\n'); q++)
				;
			clen = (int)(q - p);
			if (clen > 0 && !memcmp(q, "\r\n", 2)) {
				memmove(p, &q[2], clen + 2);
				wp->buffer_end -= (clen + 2);
			}
		}
		req_flush(wp);
		if (send_fd(fd, wp->fd))
			perror("send_fd");
	} else
		perror("connect");
	close(fd);
	return 0;
}

static int dvcgi_handler_check_wan_link_speed(request *wp, struct abuffer *m, char *data)
{
	char duplex[8];
	int link_speed = 0;

	link_speed = switch_port_status(PRTNR_WAN0); // Wan link check.

	if (link_speed & PHF_FDX)
		snprintf(duplex, sizeof(duplex), "FULL");
	else
		snprintf(duplex, sizeof(duplex), "HALF");

	if (link_speed & PHF_LINKUP) {
		if (link_speed & PHF_1000M)
			aprintf(m, "Link state is UP. Duplex is %s with 1Gbps", duplex);
		else if (link_speed & PHF_100M)
			aprintf(m, "Link state is UP. Duplex is %s with 100Mbps", duplex);
		else if (link_speed & PHF_500M)
			aprintf(m, "Link state is UP. Duplex is %s with 500Mbps", duplex);
		else
			aprintf(m, "Link state is UP. Duplex is %s with 10Mbps", duplex);
	} else {
		aprintf(m, "Link state is DOWN");
	}

	return 0;
}
#endif

static int dvcgi_handler_sys_mode(request *wp, struct abuffer *m, char *data)
{
	if (!data)
		return -1;

	if (data[0] == '0') { // Set NAT
		nvram_set("OP_MODE", "0");
		nvram_set("DHCP", "2");
	} else if (data[0] == '1') { // Set Bridge
		nvram_set("OP_MODE", "1");
		nvram_set("DHCP", "0");
	} else {
		return -1;
	}
	nvram_commit();

	return 0;
}

#define LOG_PATH "/var/log/messages"
static int dvcgi_handler_log_clear(request *wp, struct abuffer *m, char *data)
{
	char file[24];
	int logfile_rotate = 99;
	int file_cnt = 0;

	killall(SIGTERM, "syslogd");	/* kill syslogd */
	system("rm /var/log/messages*"); /* delete syslog */

	while (1) {
		snprintf(file, sizeof(file), "%s.%d", LOG_PATH, logfile_rotate);
		if (access(file, F_OK) == 0)
			file_cnt += 1;
		if (logfile_rotate == 0)
			break;
		logfile_rotate--;
	}
	if (access(LOG_PATH, F_OK) == 0)
		file_cnt += 1;

	if (file_cnt > 0)
		aprintf(m, "System Log Clear Fail!!!<br>\n");
	else
		aprintf(m, "System Log Clear Complete!!!<br>\n");

	return 0;
}

static int dvcgi_handler_mp_run(request *wp, struct abuffer *m, char *data)
{
	const char *lnpath = "/var/log/mfg-run";
	struct stat buf;
	int rc = -1;

	switch (strtol(data ? : "-1", NULL, 0)) {
		case 0:
			rc = unlink(lnpath);
			killall(SIGTERM, "UDPserver");
			break;
		case 1:
			if (stat(lnpath, &buf) || (!S_ISLNK(buf.st_mode) && ({ unlink(lnpath); 1; })))
				rc = symlink("/etc/tool/mfg-run", lnpath);
			yexecl(NULL, "/etc/tool/mfg-run");
			break;
		default:
			return -1;
	}

	if (rc == 0)
		sync();

	return 0;
}

static const cgicommand_t CgiCommands[] = {
	/*command, handler, need_run_script, need_reboot, need_factory*/
	{ "tftpServer", dvcgi_handler_tftpServer, 0, 0, 0},
	{ "diag_LED", dvcgi_handler_led, 0, 0, 0 },
	{ "diag_Button", dvcgi_handler_diag_Button, 0, 0, 0 },
	{ "diag_result", dvcgi_handler_diag_result, 0, 0, 0 },
	{ "info_system.htm", dvcgi_handler_info_system, 0, 0, 0 },
	{ "sys_factoryDefault", dvcgi_handler_factoryDefault, 0, 0, 1 },
	{ "sys_reboot", dvcgi_handler_reboot, 0, 1, 0 },
	{ "info_rssi_show.htm", dvcgi_handler_wireless_clt_rssi_show, 0, 0, 0 },
	{ "info_cal_show.htm", dvcgi_handler_cal_show, 0, 0, 0 },
	{ "sys_mode", dvcgi_handler_sys_mode, 0, 1, 0 },
	{ "logclear", dvcgi_handler_log_clear, 0, 0, 0 },
	{ "mp_run", dvcgi_handler_mp_run, 0, 0 ,0 },
#if 0
	{"check_wan_link_speed", dvcgi_handler_check_wan_link_speed, 0, 0, 0},
	{"dumplog", handler_dumplog, 0, 0, 0},
#endif

	{"", NULL, 0, 0}
};

static cgiparam_t *cgiparam_parse(char *query)
{
	cgiparam_t *cparm, *top, *eol;
	char *p, *q;
	int len;

	top = eol = NULL;
	p = strtok(query, "&");
	while (p) {
		q = strstr(p, "=");
		if (q)
			len = sizeof(cgiparam_t) + (q - p) + 1 + strlen(q + 1) + 1;
		else
			len = sizeof(cgiparam_t) + strlen(p) + 1;

		cparm = (cgiparam_t *)calloc(len, 1);
		if (!cparm)
			return NULL;

		cparm->name = cparm->data;
		if (q) {
			strncpy(cparm->name, p, q - p);
			cparm->value = &cparm->name[(int)(q - p) + 1];
			sprintf(cparm->value, q + 1);
		} else {
			sprintf(cparm->name, p);
			cparm->value = &cparm->name[strlen(cparm->name)];
		}

		if (eol == NULL) {
			eol = cparm;
			top = cparm;
		} else {
			eol->next = cparm;
			eol = cparm;
		}

		p = strtok(NULL, "&");
	}

	return top;
}

static void free_cgiparam(cgiparam_t *p)
{
	cgiparam_t *s, *t;

	s = p;
	while (s) {
		t = s->next;
		free(s);
		s = t;
	}
}

static const cgicommand_t *cgihandler_search(char *command)
{
	const cgicommand_t *c;

	for (c = &CgiCommands[0]; c->command[0]; c++) {
		if (!strcmp(c->command, command))
			return c;
	}
	return NULL;
}

static int factory_reset(void)
{
	yexecl(NULL, "dvflag RSTASSERTED 1");
	return 0;
}

void formMfgTest(request *wp, char *path, char *query)
{
	cgiparam_t *params, *temp;
	const cgicommand_t *c;
	struct abuffer m;
	int ret = -1;
	int flag_init, flag_reboot, flag_factory;

	params = cgiparam_parse(wp->query_string);
	flag_init = flag_reboot = flag_factory = 0;
	init_abuffer(&m, 0x400);

	while (params) {
		c = cgihandler_search(params->name);
		if (c && c->handler) {
			ret = c->handler(wp, &m, params->value);
			if (ret < 0) {
				free_cgiparam(params);
				break;
			}

			if (flag_init == 0 && c->need_run_script)
				flag_init = c->need_run_script;
			if (flag_reboot == 0 && c->need_reboot)
				flag_reboot = 1;
			if (flag_factory == 0 && c->need_factory)
				flag_factory = 1;
		}

		temp = params;
		params = params->next;
		free(temp);
	}
	if (ret == 0) {
		if (m.count)
			req_format_write(wp, m.buf);

		if (flag_init) {
			//Todo...
			// Commit();
		}
		if (flag_reboot)
			yexecl(NULL, "reboot");
		if (flag_factory)
			factory_reset();
	}
	fini_abuffer(&m);
}
