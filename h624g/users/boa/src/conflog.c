#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#ifdef WIFI_SIMPLE_CONFIG
#include <sys/time.h>
#endif
#include <syslog.h>
#include "boa.h"
#include "asp_page.h"
#include "apmib.h"
#include "apform.h"
#include "utility.h"

#ifdef CONFIG_NVRAM_APMIB
#include <regex.h>
#include <typedefs.h>
#include <bcmnvram.h>
#include <libytool.h>
#include "nvram_mib/nvram_mib.h"
#endif

extern WLAN_RATE_T tx_fixed_rate[];

#ifndef MAX
#define MAX(a, b)	((a) > (b) ? (a) : (b))
#define MIN(a, b)	((a) < (b) ? (a) : (b))
#endif
#define BAND	(wlan_idx ? "2.4" : "5")

struct id_string_map {
	int id;
	const char *name;
};

static const struct id_string_map band_strings[] = {
	{ 100+ 1 + 3,	"a" },
	{ 100+ 1 + 7,	"n" },
	{ 100+ 1 + 11,	"a/n" },
	{ 100+ 1 + 63,	"ac" },
	{ 100+ 1 + 71,	"n/ac" },
	{ 100+ 1 + 75,	"a/n/ac" },
	{ 200+ 1 + 0,	"b" },
	{ 200+ 1 + 1,	"g" },
	{ 200+ 1 + 2,	"b/g" },
	{ 200+ 1 + 7,	"n" },
	{ 200+ 1 + 9,	"g/n" },
	{ 200+ 1 + 10,	"b/g/n" },
	{ -1,		NULL }
};

static const struct id_string_map encrypt_strings[] = {
	{ ENCRYPT_DISABLED,	"OPEN" },
	{ ENCRYPT_WEP,		"WEP" },
	{ ENCRYPT_WPA,		"WPA" },
	{ ENCRYPT_WPA2,		"WPA2" },
	{ ENCRYPT_WPA2_MIXED,	"WPA-Mixed" },
	{ ENCRYPT_WAPI,		"WAPI" },
	{ -1,			NULL }
};

static const struct id_string_map cipher_strings[] = {
	{ WPA_CIPHER_TKIP,	"TKIP" },
	{ WPA_CIPHER_AES,	"AES" },
	{ WPA_CIPHER_MIXED,	"TKIP/AES" },
	{ -1,			NULL }
};

char *getwlratebyid(WLAN_RATE_T *t, int id)
{
	while (t->id) {
		if (t->id == id)
			return t->rate;
		t++;
	}
	return NULL;
}

const char *getstringbyid(const struct id_string_map *p, int id)
{
	while (p->name && p->id != id)
		p++;
	return p->name;
}

int apmib_nvram_set(const char *name, const char *value)
{
	int res = -1;
	if (!nvram_match(name, value)) {
		res = nvram_set(name, value);
		apmib_set_hist_string_put(name);
	}
	return res;
}

int apmib_nvram_unset(const char *name)
{
	int res = -1;
	if (nvram_get(name)) {
		res = nvram_unset(name);
		apmib_set_hist_string_put(name);
	}
	return res;
}

int apmib_set_hist_fetch(int id, void *value)
{
	int res = apmib_set_hist_search(id);
	if (res > -1)
		apmib_get(id, value);
	return res;
}

/* round-robin buffer */
static char *vrbprintf(const char *fmt, va_list args)
{
	static char buf[512];
	static int cp;
	int n, len = sizeof(buf) - cp;
	char *p = &buf[cp];
	va_list ap;

	va_copy(ap, args);
	n = vsnprintf(p, len, fmt, ap);
	if (n >= len) {
		p = buf;
		cp = 0;
		n = vsnprintf(p, sizeof(buf), fmt, ap);
	}
	va_end(ap);
	cp += (n + 1);
	if (cp >= sizeof(buf))
		cp = 0;
	return p;
}

static char *rbprintf(const char *fmt, ...)
{
	char *p;
	va_list args;

	va_start(args, fmt);
	p = vrbprintf(fmt, args);
	va_end(args);
	return p;
}

/* convert various type from binary to text form
 */
char *apmib_btoa(int type, void *arg, ...)
{
	int n;
	struct in_addr addr;
	uint8_t ea[6];
	uint8_t *p;
	char *q;
	char str[INET6_ADDRSTRLEN];
	va_list ap;
	char **argvp;

	switch (type) {
	case APMIB_INT:
		apmib_get((int)arg, &n);
		return rbprintf("%d", n);
	case APMIB_STR:
		va_start(ap, arg);
		n = va_arg(ap, int);
		va_end(ap);
		if (n <= 0 || n > 384 || (p = (uint8_t *)malloc(n + 1)) == NULL)
			return "";
		apmib_get((int)arg, p);
		q = rbprintf("%s", (char *)p);
		free(p);
		return q;
	case APMIB_IA:
		apmib_get((int)arg, &addr);
		return rbprintf("%s", inet_ntoa(addr));
	case APMIB_MAC:
		apmib_get((int)arg, &ea);
		return rbprintf("%02x:%02x:%02x:%02x:%02x:%02x",
				ea[0], ea[1], ea[2],
				ea[3], ea[4], ea[5]);
	case ETH_ADDR:
		p = (uint8_t *)arg;
		return rbprintf("%02x:%02x:%02x:%02x:%02x:%02x",
				p[0], p[1], p[2], p[3], p[4], p[5]);
	case IN_ADDR:
		addr.s_addr = ((struct in_addr *)arg)->s_addr;
		return rbprintf("%s", inet_ntoa(addr));
	case IN6_ADDR:
		inet_ntop(AF_INET6, arg, str, INET6_ADDRSTRLEN);
		return rbprintf("%s", str);
	case FMT_STR:
		va_start(ap, arg);
		q = vrbprintf((const char *)arg, ap);
		va_end(ap);
		return q;
	case ARGV2STR:
		q = "";
		for (argvp = (char **)arg; *argvp; argvp++)
			q = rbprintf("%s%s ", q, *argvp);
		if (*q)
			q[strlen(q) - 1] = '\0';
		return q;
	default:
		break;
	}
	return "";
}

const char *getportalias(int pid)
{
	const char *aliases[] = { "LAN1", "LAN2", "LAN3", "LAN4", "WAN" };
	if (pid < 0 || pid >= _countof(aliases))
		return "";
	return aliases[pid];
}

static void web_config_wired(int page)
{
	int i, val;
	struct in_addr addr;
	char *p;

	switch (page) {
	case 1:
		if ((i = apmib_set_hist_fetch(MIB_WAN_DHCP, &val)) > -1 ||
		    apmib_set_hist_search_any(MIB_WAN_IP_ADDR,
				MIB_WAN_SUBNET_MASK, MIB_WAN_DEFAULT_GATEWAY, 0)) {
			if (i > -1 && val == DHCP_CLIENT)
				LOG(LOG_INFO, "외부 IP주소 설정 방식이 DHCP로 변경됨");
			else
				LOG(LOG_INFO, "외부 IP주소가 %s/%s 게이트웨이는 %s로 변경됨",
				    apmib_btoa(APMIB_IA, (void *)MIB_WAN_IP_ADDR),
				    apmib_btoa(APMIB_IA, (void *)MIB_WAN_SUBNET_MASK),
				    apmib_btoa(APMIB_IA, (void *)MIB_WAN_DEFAULT_GATEWAY));
		}

		if ((i = apmib_set_hist_search(MIB_DNS_MODE)) > -1 ||
		    apmib_set_hist_search_any(MIB_DNS1, MIB_DNS2, 0)) {
		    	apmib_get(MIB_DNS_MODE, &val);
			if (i > -1 && val == DNS_AUTO)
				LOG(LOG_INFO, "DNS주소가 자동 설정 방식으로 변경됨");
			else if (val == DNS_MANUAL) {
				apmib_get(MIB_DNS2, &addr.s_addr);
				LOG(LOG_INFO, "DNS 1차 주소는 %s%s%s로 변경됨",
				    apmib_btoa(APMIB_IA, (void *)MIB_DNS1),
				    addr.s_addr ? " 2차 주소는 " : "",
				    addr.s_addr ? inet_ntoa(addr) : "");
			}
		}
		if (apmib_set_hist_strstr("x_mac_clone_enable") > -1) {
			if (nvram_match("x_mac_clone_enable", "1"))
				LOG(LOG_INFO, "MAC Clone이 %s을 복제하게 설정됨",
				    apmib_btoa(APMIB_MAC, (void *)MIB_WAN_MAC_ADDR));
			else
				LOG(LOG_INFO, "MAC Clone 기능을 사용하지 않게 변경됨");
		}
		if (apmib_set_hist_fetch(MIB_UPNP_ENABLED, &val) > -1)
			LOG(LOG_INFO, "UPnP 서비스가 %s활성화됨", val ? "" : "비");
		if (apmib_set_hist_fetch(MIB_IGMP_PROXY_DISABLED, &val) > -1)
			LOG(LOG_INFO, "IGMP Proxy 기능이 %s활성화됨", !val ? "" : "비");
		if (apmib_set_hist_fetch(MIB_PING_WAN_ACCESS_ENABLED, &val) > -1)
			LOG(LOG_INFO, "Ping요청에 %s응답 하도록 설정됨", val ? "" : "무");
		if (apmib_set_hist_fetch(MIB_VPN_PASSTHRU_IPSEC_ENABLED, &val) > -1)
			LOG(LOG_INFO, "IPSec VPN pass through가 %s활성화됨", val ? "" : "비");
		if (apmib_set_hist_fetch(MIB_VPN_PASSTHRU_PPTP_ENABLED, &val) > -1)
			LOG(LOG_INFO, "PPTP VPN pass through가 %s활성화됨", val ? "" : "비");
		if (apmib_set_hist_fetch(MIB_VPN_PASSTHRU_L2TP_ENABLED, &val) > -1)
			LOG(LOG_INFO, "L2TP VPN pass through가 %s활성화됨", val ? "" : "비");
		if (apmib_set_hist_strstr("x_telnet_enable") > -1)
			LOG(LOG_INFO, "Telnet daemon이 %s활성화됨", nvram_match("x_telnet_enable", "1") ? "" : "비");
		break;
	case 2:
		if ((i = apmib_set_hist_strstr("x_ipv6_autoconfig_method")) > -1 ||
		    (apmib_set_hist_strstr("x_ipv6_manual_addr") > -1) ||
		    (apmib_set_hist_strstr("x_ipv6_manual_prefix_len") > -1) ||
		    (apmib_set_hist_strstr("x_ipv6_manual_gateway") > -1)) {
		    	p = nvram_safe_get("x_ipv6_autoconfig_method");
		    	if (i > -1 && strcmp(p, "1"))
		    		LOG(LOG_INFO, "IPv6주소가 자동 설정 방식으로 변경됨");
		    	else if (!strcmp(p, "1")) {
		    		p = nvram_safe_get("x_ipv6_manual_gateway");
				LOG(LOG_INFO, "IPv6주소는 %s/%s%s%s로 변경됨",
				    nvram_safe_get("x_ipv6_manual_addr"),
				    nvram_safe_get("x_ipv6_manual_prefix_len"),
				    *p ? " 게이트웨이는 " : "", p);
			}
		}
		if ((i = apmib_set_hist_strstr("x_ipv6_dns_method")) > -1 ||
		    (apmib_set_hist_strstr("x_ipv6_manual_dns1") > -1) ||
		    (apmib_set_hist_strstr("x_ipv6_manual_dns2") > -1)) {
		    	p = nvram_safe_get("x_ipv6_dns_method");
		    	if (i > -1 && strcmp(p, "1"))
				LOG(LOG_INFO, "IPv6 DNS주소가 자동 설정 방식으로 변경됨");
			else if (!strcmp(p, "1")) {
				p = nvram_safe_get("x_ipv6_manual_dns2");
				LOG(LOG_INFO, "IPv6 DNS 1차 주소는 %s%s%s로 변경됨",
				    nvram_safe_get("x_ipv6_manual_dns1"),
				    *p ? " 2차 주소는 " : "", p);
			}
		}
		if (apmib_set_hist_fetch(MIB_CUSTOM_PASSTHRU_ENABLED, &val) > -1)
			LOG(LOG_INFO, "IPv6 Pass through 기능이 %s활성화 됨", !val ? "비" : "");
		break;
	case 3:
		if (apmib_set_hist_search_any(MIB_IP_ADDR, MIB_SUBNET_MASK, 0))
			LOG(LOG_INFO, "내부 IP주소가 %s/%s로 변경됨",
			    apmib_btoa(APMIB_IA, (void *)MIB_IP_ADDR),
			    apmib_btoa(APMIB_IA, (void *)MIB_SUBNET_MASK));
		if ((i = apmib_set_hist_search(MIB_DHCP)) > -1 ||
		    apmib_set_hist_search_any(MIB_DHCP_CLIENT_START,
				MIB_DHCP_CLIENT_END, MIB_DHCP_LEASE_TIME, 0)) {
			apmib_get(MIB_DHCP, &val);
			if (i > -1 && val != DHCP_SERVER)
				LOG(LOG_INFO, "내부 DHCP서버 서비스가 비활성화됨");
			else if (val == DHCP_SERVER)
				LOG(LOG_INFO, "내부 DHCP서버 IP할당 범위는 %s부터 %s이며 임대시간은 %s초로 변경됨",
				    apmib_btoa(APMIB_IA, (void *)MIB_DHCP_CLIENT_START),
				    apmib_btoa(APMIB_IA, (void *)MIB_DHCP_CLIENT_END),
				    apmib_btoa(APMIB_INT, (void *)MIB_DHCP_LEASE_TIME));
		}
		if (apmib_set_hist_fetch(MIB_STP_ENABLED, &val) > -1)
			LOG(LOG_INFO, "자가 Loop 감시 기능이 %s활성화됨", val ? "" : "비");
		if (apmib_set_hist_strstr("OPTION82") > -1)
			LOG(LOG_INFO, "단말의 DHCP요청에 옵션82 추가 기능이 %s활성화됨",
			    nvram_match("OPTION82", "checked") ? "" : "비");
		break;
	default:
		break;
	}
}

static void web_config_wireless(int page, char *arg)
{
	const int txpwrarray[] = { 100, 70, 50, 35, 15 };
	int i, val, val2;
	char buf[64], name[64], *p;
	char *args[8], *args2[8], **argp;

	if (vwlan_idx > 0 || page == 3)
		sprintf(name, "%s(%sG)", apmib_btoa(APMIB_STR, (void *)MIB_WLAN_SSID, 33), BAND);
	else
		sprintf(name, "%sG", BAND);

	switch (page) {
	case 1:
		if (apmib_set_hist_fetch(MIB_WLAN_WLAN_DISABLED, &val) > -1)
			LOG(LOG_INFO, "%s 무선을 사용%s함으로 설정함", name, val ? " 안 " : "");
		if (apmib_set_hist_search(MIB_WLAN_SSID) > -1) {
			if (vwlan_idx > 0)
				LOG(LOG_INFO, "%sG 다중 AP%d 무선 SSID가 %s로 설정됨", BAND, vwlan_idx - 1,
				    apmib_btoa(APMIB_STR, (void *)MIB_WLAN_SSID, 33));
			else
				LOG(LOG_INFO, "%s 무선 SSID가 %s로 설정됨", name,
				    apmib_btoa(APMIB_STR, (void *)MIB_WLAN_SSID, 33));
		}
		if (apmib_set_hist_fetch(MIB_WLAN_BAND, &val) > -1)
			LOG(LOG_INFO, "%s 무선 모드가 %s로 설정됨", name,
			    getstringbyid(band_strings, (wlan_idx + 1) * 100 + val));
		if (apmib_set_hist_fetch(MIB_WLAN_CHANNEL_BONDING, &val) > -1)
			LOG(LOG_INFO, "%s 무선 채널 Width가 %sMhz로 설정됨", name,
			    !val ? "20" : (val == 1 ? "20/40" : "20/40/80"));
		if ((i = apmib_set_hist_search(MIB_WLAN_CHANNEL)) > -1 ||
		    apmib_set_hist_fetch(MIB_WLAN_CONTROL_SIDEBAND, &val2) > -1) {
		    	apmib_get(MIB_WLAN_CHANNEL, &val);
			if (i > -1 && val == 0)
				LOG(LOG_INFO, "%s 무선 채널이 자동 선택 방식으로 설정됨", name);
			else if (val && (i < 0 || apmib_get(MIB_WLAN_CONTROL_SIDEBAND, &val2)))
				LOG(LOG_INFO, "%s 무선 채널이 수동 %d번 Control-Sideband가 %s로 설정됨",
				    name, val, val2 == 0 ? "Upper" : "Lower");
		}
		if (apmib_set_hist_fetch(MIB_WLAN_HIDDEN_SSID, &val) > -1)
			LOG(LOG_INFO, "%s 무선 SSID가 %s으로 설정됨", name, val ? "Hidden" : "알림");
		if ((i = apmib_set_hist_search(MIB_WLAN_RATE_ADAPTIVE_ENABLED)) > -1 ||
		    apmib_set_hist_fetch(MIB_WLAN_FIX_RATE, &val2) > -1) {
		    	apmib_get(MIB_WLAN_RATE_ADAPTIVE_ENABLED, &val);
		    	if (i > -1 && val)
		    		LOG(LOG_INFO, "%s 무선 데이터 전송율이 자동 방식으로 설정됨", name);
		    	else if (!val && (i < 0 || apmib_get(MIB_WLAN_FIX_RATE, &val2))) {
		    		p = getwlratebyid(tx_fixed_rate, val2) ? : "";
		    		LOG(LOG_INFO, "%s 무선 데이터 전송율이 %s%s 고정으로 설정됨", name,
		    		    p, (p[0] != 'M') ? "M" : "");
			}
		}
		if (apmib_set_hist_search_any(MIB_WLAN_TX_RESTRICT, MIB_WLAN_RX_RESTRICT, 0))
			LOG(LOG_INFO, "%s 무선 속도 제한이 전송은 %sMbps 수신은 %sMpbs 설정됨", name,
			    apmib_btoa(APMIB_INT, (void *)MIB_WLAN_TX_RESTRICT),
			    apmib_btoa(APMIB_INT, (void *)MIB_WLAN_RX_RESTRICT));
		get_wlan_name(buf, vwlan_idx, "max_conn");
		if (apmib_set_hist_strstr(buf) > -1)
			 LOG(LOG_INFO, "%s 무선 동시 접속을 %s개 단말로 제한하도록 설정됨",
			     name, nvram_safe_get(buf));
		break;
	case 2:
		if (apmib_set_hist_fetch(MIB_WLAN_FRAG_THRESHOLD, &val) > -1)
			LOG(LOG_INFO, "%s 무선의 Fragment threshold가 %d로 설정됨", name, val);
		if (apmib_set_hist_fetch(MIB_WLAN_RTS_THRESHOLD, &val) > -1)
			LOG(LOG_INFO, "%s 무선의 RTS threshold가 %d로 설정됨", name, val);
		if (apmib_set_hist_fetch(MIB_WLAN_BEACON_INTERVAL, &val) > -1)
			LOG(LOG_INFO, "%s 무선의 Beacon interval이 %dTU로 설정됨", name, val);
		if (apmib_set_hist_fetch(MIB_WLAN_PREAMBLE_TYPE, &val) > -1)
			LOG(LOG_INFO, "%s 무선의 %s preamble이 설정됨", name, (val == LONG_PREAMBLE) ? "Long" : "Short");
		if (apmib_set_hist_fetch(MIB_WLAN_IAPP_DISABLED, &val) > -1)
			LOG(LOG_INFO, "%s 무선의 IAPP기능을 사용%s함으로 설정함", name, val ? " 안 " : "");
		if (apmib_set_hist_fetch(MIB_WLAN_PROTECTION_DISABLED, &val) > -1)
			LOG(LOG_INFO, "%s 무선의 Protection을 사용%s함으로 설정함", name, val ? " 안 " : "");
		if (apmib_set_hist_fetch(MIB_WLAN_AGGREGATION, &val) > -1)
			LOG(LOG_INFO, "%s 무선의 Aggregation을 사용%s함으로 설정함", name, (val == DISABLED) ? " 안 " : "");
		if (apmib_set_hist_fetch(MIB_WLAN_SHORT_GI, &val) > -1)
			LOG(LOG_INFO, "%s 무선의 Short guard interval을 사용%s함으로 설정함", name, (!val) ? " 안 " : "");
		if (apmib_set_hist_fetch(MIB_WLAN_BLOCK_RELAY, &val) > -1)
			LOG(LOG_INFO, "%s 무선의 Isolation을 사용%s함으로 설정함", name, (!val) ? " 안 " : "");
		if (apmib_set_hist_fetch(MIB_WLAN_STBC_ENABLED, &val) > -1)
			LOG(LOG_INFO, "%s 무선의 STBC을 사용%s함으로 설정함", name, (!val) ? " 안 " : "");
		if (apmib_set_hist_fetch(MIB_WLAN_LDPC_ENABLED, &val) > -1)
			LOG(LOG_INFO, "%s 무선의 LDPC을 사용%s함으로 설정함", name, (!val) ? " 안 " : "");
		if (apmib_set_hist_fetch(MIB_WLAN_COEXIST_ENABLED, &val) > -1)
			LOG(LOG_INFO, "%s 무선의 20/40MHz coexistence을 사용%s함으로 설정함", name, (!val) ? " 안 " : "");
		if (apmib_set_hist_fetch(MIB_WLAN_TX_BEAMFORMING, &val) > -1)
			LOG(LOG_INFO, "%s 무선의 TX beamforming을 사용%s함으로 설정함", name, (!val) ? " 안 " : "");
		if (apmib_set_hist_fetch(MIB_WLAN_MC2U_DISABLED, &val) > -1)
			LOG(LOG_INFO, "%s 무선의 Mcast to Ucast을 사용%s함으로 설정함", name, (!val) ? " 안 " : "");
		if (apmib_set_hist_fetch(MIB_WLAN_TDLS_PROHIBITED, &val) > -1)
			LOG(LOG_INFO, "%s 무선의 TDLS 금지를 사용%s함으로 설정함", name, (!val) ? " 안 " : "");
		if (apmib_set_hist_fetch(MIB_WLAN_TDLS_CS_PROHIBITED, &val) > -1)
			LOG(LOG_INFO, "%s 무선의 TDLS채널전환 금지을 사용%s함으로 설정함", name, (!val) ? " 안 " : "");
		if (apmib_set_hist_strstr("x_dfs_enable") > -1)
			LOG(LOG_INFO, "%s 무선의 DFS을 사용%s함으로 설정함", name, (!nvram_match("x_dfs_enable", "1")) ? " 안 " : "");
		if (apmib_set_hist_fetch(MIB_WLAN_LOWEST_MLCST_RATE, &val) > -1) {
			if (val == 0)
				LOG(LOG_INFO, "%s 무선의 Multicast 전송율이 Auto로 설정됨", name);
			else if ((p = getwlratebyid(tx_fixed_rate, val)))
				LOG(LOG_INFO, "%s 무선의 Multicast 전송율이 %s%s 고정으로 설정됨", name,
				    p, (p[0] != 'M') ? "M" : "");
		}
		val = vwlan_idx;
		for (vwlan_idx = 0; vwlan_idx < 5; vwlan_idx++) {
			if (vwlan_idx == 1 || vwlan_idx == 4) // VoIP SSID, wlan_vap3
				continue;
			get_wlan_name(buf, vwlan_idx, "rssi_threshold");
			if (apmib_set_hist_strstr(buf) > -1)
				LOG(LOG_INFO, "%s 무선 %s의 접속 제한 RSSI가 -%sdBm으로 설정됨",
				    BAND, apmib_btoa(APMIB_STR, (void *)MIB_WLAN_SSID, 33), nvram_safe_get(buf));
		}
		vwlan_idx = val;

		if (apmib_set_hist_strstr("x_bs_rssi_th") > -1)
			LOG(LOG_INFO, "%s 무선의 Handover RSSI threshold을 %s로 설정함", name, nvram_safe_get("x_bs_rssi_th"));
		if (apmib_set_hist_strstr("x_bs_tcp_pps_check_time") > -1)
			LOG(LOG_INFO, "%s 무선의 Handover 감시 시간을 %s초로 설정함", name, nvram_safe_get("x_bs_tcp_pps_check_time"));
		if (apmib_set_hist_strstr("x_bs_tcp_pkts_threshold") > -1)
			LOG(LOG_INFO, "%s 무선의 Handover 초당 패킷 발생수를 %s로 설정함", name, nvram_safe_get("x_bs_tcp_pkts_threshold"));
		if (apmib_set_hist_fetch(MIB_WLAN_RFPOWER_SCALE, &val) > -1)
			LOG(LOG_INFO, "%s 무선 출력 Power가 %d%%로 설정됨", name, txpwrarray[val]);
		break;
	case 3:
		if (apmib_set_hist_fetch(MIB_WLAN_ENCRYPT, &val) > -1)
			LOG(LOG_INFO, "%s 암호화 방식이 %s로 설정됨", name, getstringbyid(encrypt_strings, val));
		if (apmib_set_hist_fetch(MIB_WLAN_WPA_AUTH, &val) > -1)
			LOG(LOG_INFO, "%s 인증 모드가 %s로 설정됨", name, (val == WPA_AUTH_PSK) ? "PSK" : "RADIUS");
		if (apmib_set_hist_fetch(MIB_WLAN_WPA_CIPHER_SUITE, &val) > -1)
			LOG(LOG_INFO, "%s 암호화 WPA Cipher가 %s로 설정됨", name, getstringbyid(cipher_strings, val));
		if (apmib_set_hist_fetch(MIB_WLAN_WPA2_CIPHER_SUITE, &val) > -1)
			LOG(LOG_INFO, "%s 암호화 WPA2 Cipher가 %s로 설정됨", name, getstringbyid(cipher_strings, val));
		if (apmib_set_hist_search(MIB_WLAN_WPA_PSK) > -1)
			LOG(LOG_INFO, "%s 암호화 PSK가 ********로 설정됨", name);

		if (apmib_set_hist_fetch(MIB_WLAN_ENABLE_1X, &val) > -1)
			LOG(LOG_INFO, "%s 무선 802.1x 인증을 사용%s함으로 설정함", name, val ? "" : " 안 ");
		if (apmib_set_hist_fetch(MIB_WLAN_MAC_AUTH_ENABLED, &val) > -1)
			LOG(LOG_INFO, "%s 무선 맥 인증을 사용%s함으로 설정함", name, val ? "" : " 안 ");

		if (apmib_set_hist_search_any(MIB_WLAN_RS_IP, MIB_WLAN_RS_PORT, 0))
			LOG(LOG_INFO, "%s 무선 인증서버 주소가 %s:%s로 변경됨", name,
			    apmib_btoa(APMIB_IA, (void *)MIB_WLAN_RS_IP),
			    apmib_btoa(APMIB_INT, (void *)MIB_WLAN_RS_PORT));
		if (apmib_set_hist_search(MIB_WLAN_RS_PASSWORD) > -1)
			LOG(LOG_INFO, "%s 무선 인증서버의 비밀번호가 ********로 설정됨", name);
		if (apmib_set_hist_search_any(MIB_WLAN_RS_MAXRETRY, MIB_WLAN_RS_INTERVAL_TIME, 0))
			LOG(LOG_INFO, "%s 무선 인증서버의 재시도 횟수/간격이 %s/%s로 설정됨", name,
			    apmib_btoa(APMIB_INT, (void *)MIB_WLAN_RS_MAXRETRY),
			    apmib_btoa(APMIB_INT, (void *)MIB_WLAN_RS_INTERVAL_TIME));

		if (apmib_set_hist_search_any(MIB_WLAN_ACCOUNT_RS_IP, MIB_WLAN_ACCOUNT_RS_PORT, 0))
			LOG(LOG_INFO, "%s 무선 계정서버 주소가 %s:%s로 변경됨", name,
			    apmib_btoa(APMIB_IA, (void *)MIB_WLAN_ACCOUNT_RS_IP),
			    apmib_btoa(APMIB_INT, (void *)MIB_WLAN_ACCOUNT_RS_PORT));
		if (apmib_set_hist_search(MIB_WLAN_ACCOUNT_RS_PASSWORD) > -1)
			LOG(LOG_INFO, "%s 무선 계정서버의 비밀번호가 ********로 설정됨", name);
		if (apmib_set_hist_search_any(MIB_WLAN_ACCOUNT_RS_MAXRETRY, MIB_WLAN_ACCOUNT_RS_INTERVAL_TIME, 0))
			LOG(LOG_INFO, "%s 무선 계정서버의 재시도 횟수/간격이 %s/%s로 설정됨", name,
			    apmib_btoa(APMIB_INT, (void *)MIB_WLAN_ACCOUNT_RS_MAXRETRY),
			    apmib_btoa(APMIB_INT, (void *)MIB_WLAN_ACCOUNT_RS_INTERVAL_TIME));
		if (apmib_set_hist_fetch(MIB_WLAN_ACCOUNT_RS_ENABLED, &val2) > -1 && !val2)
			LOG(LOG_INFO, "%s 무선 계정서버 사용을 취소함", name);
		if (apmib_set_hist_search_any(MIB_WLAN_ACCOUNT_RS_UPDATE_ENABLED, MIB_WLAN_ACCOUNT_RS_UPDATE_DELAY, 0)) {
			apmib_get(MIB_WLAN_ACCOUNT_RS_UPDATE_ENABLED, &val);
			if (val == 0)
				LOG(LOG_INFO, "%s 무선 계정서버의 갱신 기능을 사용 안 함으로 설정함", name);
			else if (apmib_get(MIB_WLAN_ACCOUNT_RS_UPDATE_DELAY, &val))
				LOG(LOG_INFO, "%s 무선 계정서버의 갱신 지연을 %d초로 설정함", name, val);
		}
		if (apmib_set_hist_fetch(MIB_WLAN_WEP, &val) > -1)
			LOG(LOG_INFO, "%s 무선 암호화 WEP가 %d Key길이로 설정됨", name, (val == WEP64) ? 64 : 128);
		for (i = MIB_WLAN_WEP64_KEY1; i <= MIB_WLAN_WEP64_KEY4; i++) {
			if (apmib_set_hist_search(i) > -1)
				LOG(LOG_INFO, "%s 무선 암호화 WEP 64Bit Key%d가 ********로 변경됨",
				    name, i - MIB_WLAN_WEP64_KEY1 + 1);
		}
		for (i = MIB_WLAN_WEP128_KEY1; i <= MIB_WLAN_WEP128_KEY1; i++) {
			if (apmib_set_hist_search(i) > -1)
				LOG(LOG_INFO, "%s 무선 암호화 WEP 128Bit Key%d가 ********로 변경됨",
				    name, i - MIB_WLAN_WEP128_KEY1 + 1);
		}
		break;
	case 4:
		get_wlan_name(buf, 0, "WLS_REDIR_ENABLE");
		val = nvram_atoi(buf, 0);
		if (apmib_set_hist_strstr(buf) > -1)
			LOG(LOG_INFO, "%s Web Redirection 기능을 사용%s함으로 설정함",
			    name, val ? "" : " 안 ");
		if (val == 0)
			break;
		get_wlan_name(buf, 0, "WLS_REDIR_HOST");
		if (apmib_set_hist_strstr(buf) > -1) {
			p = nvram_safe_get(buf);
			LOG(LOG_INFO, "%s Web Redirection 연결 URL이 %s%s",
			    name, p[0] ? p : "", p[0] ? "로 설정됨" : "삭제됨");
		}
		for (i = val = 0; i < 5; i++) {
			p = rbprintf("WLS_REDIR_ALLOW%d", i);
			get_wlan_name(buf, 0, p);
			p = nvram_get(buf);
			if (p && p[0])
				args[val++] = p;
		}
		args[val] = NULL;
		val2 = (arg) ? ystrargs(arg, args2, _countof(args2), " \r\n\t", 0) : 0;
		for (i = 0; i < val2; ) {
			for (argp = args; *argp && strcmp(*argp, args2[i]); argp++) ;
			if (*argp) {
				for (val--; *argp; argp++)
					*argp = argp[1];
				for (argp = &args2[i]; *argp; argp++)
					*argp = argp[1];
				val2--;
			} else
				i++;
		}
		if (val2)
			LOG(LOG_INFO, "%s Web Redirection 허용 URL에서 %s이 삭제됨", name, apmib_btoa(ARGV2STR, args2));
		if (val)
			LOG(LOG_INFO, "%s Web Redirection 허용 URL에 %s이 추가됨", name, apmib_btoa(ARGV2STR, args));
		break;
	case 8:
		if ((i = apmib_set_hist_strstr("x_wlan_reset_enable")) > -1 ||
		    apmib_set_hist_strstr("x_wlan_reset_interval_day") > -1 ||
		    apmib_set_hist_strstr("x_wlan_reset_bw_kbps") > -1 ||
		    apmib_set_hist_strstr("x_wlan_reset_triger_time") > -1) {
			val = nvram_atoi("x_wlan_reset_enable", 1);
			if (i > -1 && val == 0)
				LOG(LOG_INFO, "무선 리셋 기능을 사용 안 함");
			else if (val) {
			    	sscanf(nvram_safe_get("x_wlan_reset_triger_time"), "%d_%d", &val, &val2);
				LOG(LOG_INFO, "무선 리셋 기능이 %s일 주기로 %d~%d시 사이에 %sKB/m 조건에서 수행하도록 설정됨",
				    nvram_safe_get("x_wlan_reset_interval_day"), val, val2, nvram_safe_get("x_wlan_reset_bw_kbps"));
			}
		}
		break;
	default:
		break;
	}
}

static void web_config_firewall(int page, char *arg)
{
	char *p, *q;
	int i, val, changed;
	const int mask = (2 | 0x200 | 0x400 | 0x1000 | 0x4000 | 0x800000);

	switch (page) {
	case 4:
		if ((i = apmib_set_hist_search(MIB_DMZ_ENABLED)) > -1 ||
		    apmib_set_hist_search(MIB_DMZ_HOST) > -1) {
		    	apmib_get(MIB_DMZ_ENABLED, &val);
			if (i > -1 && val == 0)
				LOG(LOG_INFO, "DMZ 호스트 기능을 사용 안 함으로 설정함");
			else if (val == 1)
				LOG(LOG_INFO, "DMZ 호스트를 %s로 설정함",
				    apmib_btoa(APMIB_IA, (void *)MIB_DMZ_HOST));
		}
		break;
	case 5:
		val = *(int *)arg & mask;
		if (apmib_set_hist_fetch(MIB_DOS_ENABLED, &i) > -1) {
			i &= mask;
			changed = i ^ val;
			if (changed & 2)
				LOG(LOG_INFO, "DoS공격 TCP Syn Flood에 대해 방어 기능이 %s됨", (i & 2) ? "활성화" : "해제");
			if (changed & 0x200)
				LOG(LOG_INFO, "DoS공격 TCP Portscan에 대해 방어 기능이 %s됨", (i & 0x200) ? "활성화" : "해제");
			if (changed & 0x400)
				LOG(LOG_INFO, "DoS공격 ICMP Smurf에 대해 방어 기능이 %s됨", (i & 0x400) ? "활성화" : "해제");
			if (changed & 0x1000)
				LOG(LOG_INFO, "DoS공격 IP Spoofing에 대해 방어 기능이 %s됨", (i & 0x1000) ? "활성화" : "해제");
			if (changed & 0x4000)
				LOG(LOG_INFO, "DoS공격 Ping Of Death에 대해 방어 기능이 %s됨", (i & 0x4000) ? "활성화" : "해제");
		}

		if ((i = apmib_set_hist_strstr("x_pingSecEnabled")) > -1 ||
		    apmib_set_hist_strstr("x_icmp_reply_rate") > -1) {
		    	if (nvram_match("x_pingSecEnabled", "1"))
				LOG(LOG_INFO, "PING 요청에 대한 응답율을 %s/초로 설정함", nvram_safe_get("x_icmp_reply_rate"));
			else if (i > -1)
				LOG(LOG_INFO, "PING 요청에 대한 응답율 설정을 해제함");
		}

		if (apmib_set_hist_strstr("x_noreply_tracert") > -1)
			LOG(LOG_INFO, "Trace route 요청에 %s응답하도록 설정함",
			    nvram_match("x_noreply_tracert", "1") ? "무" : "");

		if (apmib_set_hist_strstr("x_ARP_DEFENDER_ENABLE") > -1)
			LOG(LOG_INFO, "ARP Spoofing 방어 기능을 %s함",
			    nvram_match("x_ARP_DEFENDER_ENABLE", "1") ? "사용" : "해제");

		if (apmib_set_hist_strstr("x_input_policy_accept") > -1)
			LOG(LOG_INFO, "CPU인입 이상 트랙픽 제어 기능을 %s함",
			    nvram_match("x_input_policy_accept", "1") ? "사용" : "해제");

		if (apmib_set_hist_strstr("x_snmp_input_rate") > -1) {
			i = nvram_atoi("x_snmp_input_rate", 0);
			LOG(LOG_INFO, "SNMP 인입 허용율을 %s",
			    (i == 0) ? "제한하지 않음" : apmib_btoa(FMT_STR, "%d/초로 설정함", i));
		}

		if (apmib_set_hist_fetch(MIB_DOS_BLOCK_TIME, &i) > -1)
			LOG(LOG_INFO, "Source IP Blocking 시간을 %s",
			    (i == 0) ? "제한하지 않음" : apmib_btoa(FMT_STR, "%d초로 설정함", i));
		break;
	case 6:
		val = nvram_atoi("x_LANRESTRICT_ENABLE", 0);
		if (apmib_set_hist_strstr("x_LANRESTRICT_ENABLE") > -1)
			LOG(LOG_INFO, "LAN 제한 기능을 사용%s함으로 설정함", val ? "" : " 안 ");
		if (val == 0)
			break;
		for (i = 1; i <= 4; i++) {
			p = apmib_btoa(FMT_STR, "x_LANRESTRICT_ENABLE_PORT%d", i);
			if (!nvram_atoi(p, 0))
				continue;
			if (apmib_set_hist_strstr(p) > -1 ||
			    apmib_set_hist_strstr(apmib_btoa(FMT_STR, "x_LANRESTRICT_MAXNUM%d", i)) > -1)
				LOG(LOG_INFO, "LAN%d에 %s개 호스트로 접속 제한함",
				    i, nvram_safe_get(apmib_btoa(FMT_STR, "x_LANRESTRICT_MAXNUM%d", i)));
		}
		break;
	case 7:
		val = nvram_atoi("x_BCSTORM_CTRL_ENABLE", 0);
		if (apmib_set_hist_strstr("x_BCSTORM_CTRL_ENABLE") > -1)
			LOG(LOG_INFO, "Broadcast Storm 제어 기능을 사용%s함으로 설정함", val ? "" : " 안 ");
		if (val == 0)
			break;
		if (apmib_set_hist_strstr("x_BCSTORM_CTRL_PERCENT") > -1)
			LOG(LOG_INFO, "Broadcast Storm 제어 기능의 전송율을 %s%%로 설정함",
			    nvram_safe_get("x_BCSTORM_CTRL_PERCENT"));
		p = "";
		for (i = 0; i <= 4; i++) {
			q = apmib_btoa(FMT_STR, "x_BCSTORM_PORT%d_ENABLE", i);
			if (apmib_set_hist_strstr(q) > -1 && nvram_atoi(q, 0)) {
				if (i < 4)
					p = apmib_btoa(FMT_STR, "%sLAN%d ", p, i + 1);
				else
					p = apmib_btoa(FMT_STR, "%sWAN ", p, i + 1);
			}
		}
		if (p[0])
			LOG(LOG_INFO, "Broadcast Storm 제어 기능을 %.*s에 적용함", strlen(p) - 1, p);
		break;
	default:
		break;
	}
}

static void web_config_management(int page)
{
	int i, val, val2;
	char *p;
	char remote_server[64] = {0,};
	const char *dayofweek[] = { "일", "월", "화", "수", "목", "금", "토" };

	switch (page) {
	case 3:
		if (apmib_set_hist_fetch(MIB_IGMP_FAST_LEAVE_DISABLED, &val) > -1)
			LOG(LOG_INFO, "IGMP Fast Leave을 사용%s함으로 설정함", val ? " 안 " : "");
		apmib_get(MIB_OP_MODE, &val);
		if (val) {
			i = nvram_atoi("x_igmp_querier", 0);
			if (apmib_set_hist_strstr("x_igmp_querier") > -1 && !i)
				LOG(LOG_INFO, "Bridge모드에서 IGMP Membership Query을 사용안함");

			if (i && (apmib_set_hist_strstr("x_igmp_querier_interval") > -1 ||
			    apmib_set_hist_strstr("x_igmp_querier_auto") > -1))
				LOG(LOG_INFO, "Bridge모드에서 IGMP Membership Query을 %s주기로 %s(으)로 설정함",
				    nvram_safe_get("x_igmp_querier_interval"),
				    nvram_match("x_igmp_querier_auto", "1") ? "Auto" : "강제발생");
		}
		val = nvram_atoi("x_igmp_joinlimit_enable", 0);
		if (apmib_set_hist_strstr("x_igmp_joinlimit_enable") > -1)
			LOG(LOG_INFO, "IGMP Join 개수 제한을 사용%s함으로 설정함", val ? "" : " 안 ");
		for (i = 1; val && i <= 4; i++) {
			p = apmib_btoa(FMT_STR, "x_igmp_limite_lan%d", i);
			if (apmib_set_hist_strstr(p) > -1)
				LOG(LOG_INFO, "LAN%d의 IGMP Join 개수를 %s로 제한함", i, nvram_safe_get(p));
		}
		break;
	case 4:
		val = nvram_atoi("x_holepunch_enabled", 1);
		if (apmib_set_hist_strstr("x_holepunch_enabled") > -1)
			LOG(LOG_INFO, "Holepunch기능을 사용%s함으로 설정함", val ? "" : " 안 ");
		if (val && (apmib_set_hist_strstr("x_holepunch_cserver") > -1 ||
		    apmib_set_hist_strstr("x_holepunch_cport") > -1))
			LOG(LOG_INFO, "Holepunch 서버 주소를 ********로 변경함");
		break;
	case 7:
		apmib_get(MIB_DDNS_ENABLED, &val);
		if (apmib_set_hist_search(MIB_DDNS_ENABLED) > -1)
			LOG(LOG_INFO, "DDNS서비스를 사용%s함으로 설정함", val ? "" : " 안 ");
		if (val && apmib_set_hist_search_any(MIB_DDNS_TYPE, MIB_DDNS_USER,
				MIB_DDNS_PASSWORD, MIB_DDNS_DOMAIN_NAME, 0)) {
			apmib_get(MIB_DDNS_TYPE, &i);
			LOG(LOG_INFO, "DDNS서비스 공급자는 %s, 도메인 명은 %s, 사용자는 %s 그리고 비밀번호는 ******로 설정함",
			    !i ? "DynDNS" : "TZO", apmib_btoa(APMIB_STR, (void *)MIB_DDNS_DOMAIN_NAME, 80),
			    apmib_btoa(APMIB_STR, (void *)MIB_DDNS_USER, 80));
		}
		break;
	case 8:
		apmib_get(MIB_NTP_ENABLED, &val);
		if (apmib_set_hist_search(MIB_NTP_ENABLED) > -1)
			LOG(LOG_INFO, "NTP시간 동기를 사용%s함으로 설정함", val ? "" : " 안 ");
		if (val && (apmib_set_hist_search(MIB_NTP_SERVER_ID) > -1 ||
		    apmib_set_hist_strstr("x_ntp_server_ip1") > -1 ||
		    apmib_set_hist_strstr("x_ntp_server_ip2") > -1 ||
		    apmib_set_hist_strstr("x_ntp_server_ip3") > -1 )) {
			apmib_get(MIB_NTP_SERVER_ID, &i);
			LOG(LOG_INFO, "NTP서버 주소를 %s %s %s 로 설정함",
					nvram_safe_get("x_ntp_server_ip1"),	nvram_safe_get("x_ntp_server_ip2"),	nvram_safe_get("x_ntp_server_ip3"));
		}
		break;
	case 9:
		apmib_get(MIB_SCRLOG_ENABLED, &val);
		if (apmib_set_hist_search(MIB_SCRLOG_ENABLED) > -1)
			LOG(LOG_INFO, "로그 기록을 사용%s함으로 설정함", (val & 1) ? "" : " 안 ");
		if ((val & 1) && (apmib_set_hist_search(MIB_REMOTELOG_ENABLED) > -1 || apmib_set_hist_strstr("x_remote_logserver") > -1)) {
			apmib_get(MIB_REMOTELOG_ENABLED, &val);
			if (val) {
				nvram_get_r_def("x_remote_logserver", remote_server, sizeof(remote_server), "syslogap.skbroadband.com:10614");
				translate_control_code(remote_server);
				LOG(LOG_INFO, "원격 로그 서버 %s을 사용하도록 설정함", remote_server);
			} else
				LOG(LOG_INFO, "원격 로그을 사용하지 않음");
		}
		break;
	case 10:
		if (apmib_set_hist_strstr("x_ldap_autoup_enabled") > -1) {
			val = nvram_atoi("x_ldap_autoup_enabled", 0);
			LOG(LOG_INFO, "LDAP 설정이 %s으로 설정됨",
			    !val ? "사용 안함" : (val == 1) ? "LDAD CFG설정" : "수동설정");
		}
		if (apmib_set_hist_strstr("x_ldap_autoup_domain") > -1 ||
		    apmib_set_hist_strstr("x_ldap_autoup_file") > -1)
			LOG(LOG_INFO, "LDAP 펌웨어 URL이 ******** 파일명이 ********로 변경됨");
		if (apmib_set_hist_strstr("x_autoup_prefix_use") > -1 ||
		    apmib_set_hist_strstr("x_ldap_autoup_prefix") > -1)
			LOG(LOG_INFO, "LDAP 상대 경로가 ********로 변경됨");
		if (apmib_set_hist_strstr("x_autoup_auth_svr") > -1)
			LOG(LOG_INFO, "LDAP 서버 URL이 ********로 변경됨");
		break;
	case 11:
		val = nvram_atoi("x_auto_reboot_enable", 0);
		if (apmib_set_hist_strstr("x_auto_reboot_enable") > -1)
			LOG(LOG_INFO, "자동 리부팅 기능을 사용%s함으로 설정함", val ? "" : " 안 ");
		if (val == 0)
			break;
		val = nvram_atoi("x_autoreboot_userforce", 0);
		if (apmib_set_hist_strstr("x_autoreboot_userforce") > -1)
			LOG(LOG_INFO, "자동 리부팅 수동 설정을 사용%s함으로 설정함", val ? "" : " 안 ");
		if (val && (apmib_set_hist_strstr("x_auto_reboot_on_idle") > -1 ||
		    apmib_set_hist_strstr("x_auto_wan_port_idle") > -1 ||
		    apmib_set_hist_strstr("x_auto_uptime") > -1 ||
		    apmib_set_hist_strstr("x_auto_bw_kbps") > -1 ||
		    apmib_set_hist_strstr("x_auto_hour_range") > -1 ||
		    apmib_set_hist_strstr("x_autoreboot_week") > -1)) {
			val = nvram_atoi("x_auto_reboot_on_idle", 1);
			if (val == 0)
				LOG(LOG_INFO, "자동 리부팅을 미실시 하도록 설정함");
			else {
				i = nvram_atoi("x_autoreboot_week", 5);
				i = MAX(0, MIN(i, 6));
				LOG(LOG_INFO, "자동 리부팅을 장비 시작 후 %s후 첫 %s요일 %s시 사이에 데이터 사용량%s 리부팅하도록 설정함",
				    nvram_safe_get("x_auto_uptime"), dayofweek[i], nvram_safe_get("x_auto_hour_range"),
				    !nvram_match("x_auto_wan_port_idle", "1") ?
					"에 관계없이" : apmib_btoa(FMT_STR, "이 %skbps 이하일 때", nvram_safe_get("x_auto_bw_kbps")));
			}
		}
		break;
	case 12:
		if (apmib_set_hist_strstr("x_USER_PASSWORD") > -1)
			LOG(LOG_INFO, "비밀번호를 변경함");
		break;
	case 13:
		i = nvram_atoi("x_autoup_enabled", 1) << 0;
		i |= (nvram_atoi("x_ldap_enabled", 0) << 1);
		if (apmib_set_hist_strstr("x_autoup_enabled") > -1 ||
		    apmib_set_hist_strstr("x_ldap_enabled") > -1) {
			switch (i) {
			case 0:	// disable
				LOG(LOG_INFO, "자동 업그레이드 기능을 사용 안 함으로 설정함");
				return;
			case 2:	// (1 << 1 | 0 << 0)
				LOG(LOG_INFO, "자동 업그레이드 기능을 LDAP으로 설정함");
				return;
			case 1:	// (0 << 1 | 1 << 0)
				LOG(LOG_INFO, "자동 업그레이드 기능을 SWMS로 설정함");
				break;
			default:
				return;
			}
		}
		if (i != 1)
			break;
		if (apmib_set_hist_strstr("x_autoup_domain") > -1)
			LOG(LOG_INFO, "자동 업그레이드 서버 URL이 변경됨");
		if (apmib_set_hist_strstr("x_autoup_file") > -1)
			LOG(LOG_INFO, "자동 업그레이드 파일명이 변경됨");
		if (apmib_set_hist_strstr("x_autoup_prefix") > -1)
			LOG(LOG_INFO, "자동 업그레이드 상대 PATH가 변경됨");
		break;
	case 14:
		if (apmib_set_hist_strstr("x_jumbo_enable") > -1)
			LOG(LOG_INFO, "점보 프레임 처리 기능을 사용%s함으로 설정함",
			    nvram_match("x_jumbo_enable", "0") ? " 안 " : "");
		break;
	case 16:
		val = nvram_atoi("x_SNMP_ENABLE", 1);
		if (apmib_set_hist_strstr("x_SNMP_ENABLE") > -1)
			LOG(LOG_INFO, "SNMP 기능을 사용%s함으로 설정함", val ? "" : " 안 ");
		if (val == 0)
			break;
		for (i = 1; i <= 2; i++) {
			p = apmib_btoa(FMT_STR, "x_SNMP_COM%d", i);
			if (apmib_set_hist_strstr(p) > -1) {
				sscanf(nvram_safe_get(p), "%d_%d", &val, &val2);
				if (val == 0) {
					LOG(LOG_INFO, "SNMP %s을 사용 안 함으로 설정함", (i == 1) ? "Get" : "Set");
					continue;
				}
				LOG(LOG_INFO, "SNMP %s을 %s access로 설정함",
				    (i == 1) ? "Get" : "Set", val2 ? "RW" : "RO");
			}
			p = apmib_btoa(FMT_STR, "x_SNMP_%s_COMMUNITY", (i == 1) ? "GET" : "SET");
			if (apmib_set_hist_strstr(p) > -1)
				LOG(LOG_INFO, "SNMP %s Community가 변경됨", (i == 1) ? "Get" : "Set");
		}
		val = nvram_atoi("x_SNMP_TRAP_ENABLE", 1);
		if (apmib_set_hist_strstr("x_SNMP_TRAP_ENABLE") > -1)
			LOG(LOG_INFO, "SNMP TRAP을 사용%s함으로 설정함", val ? "" : " 안 ");
		if (val == 0)
			break;
		if (apmib_set_hist_strstr("x_SNMP_TRAP_COMMUNITY") > -1)
			LOG(LOG_INFO, "SNMP TRAP Community가 변경됨");
		if (apmib_set_hist_strstr("x_SNMP_TRAP_SERVER") > -1)
			LOG(LOG_INFO, "SNMP TRAP 서버1이 ********로 변경됨");
		if (apmib_set_hist_strstr("x_WIFI_TRAP_SERVER") > -1)
			LOG(LOG_INFO, "SNMP TRAP 서버2가 ********로 변경됨");
		break;
	default:
		break;
	}
}

char *web_log_wlname(char *buf, size_t len)
{
	if (buf && len) {
		if (vwlan_idx > 0)
			snprintf(buf, len, "%s(%sG)",
				 apmib_btoa(APMIB_STR, (void *)MIB_WLAN_SSID, 33), BAND);
		else
			snprintf(buf, len, "%sG", BAND);
	}
	return buf;
}

void web_config_trace(int klass, int page, ...)
{
	va_list ap;
	char *p = NULL;

	if (apmib_set_hist_peek() < 0)
		return;

	switch (klass << 16 | page) {
	case ((1 << 16) | 1):
	case ((1 << 16) | 2):
	case ((1 << 16) | 3):
	case ((1 << 16) | 4):
		web_config_wired(page);
		break;
	case ((2 << 16) | 4):
		va_start(ap, page);
		p = va_arg(ap, char *);
		va_end(ap);

	case ((2 << 16) | 1):
	case ((2 << 16) | 2):
	case ((2 << 16) | 3):
	case ((2 << 16) | 8):
		web_config_wireless(page, p);
		break;

	case ((3 << 16) | 5):
		va_start(ap, page);
		p = va_arg(ap, char *);
		va_end(ap);

	case ((3 << 16) | 4):
	case ((3 << 16) | 6):
	case ((3 << 16) | 7):
		web_config_firewall(page, p);
		break;
	case ((5 << 16) | 3):
	case ((5 << 16) | 4):
	case ((5 << 16) | 7):
	case ((5 << 16) | 8):
	case ((5 << 16) | 9):
	case ((5 << 16) | 10):
	case ((5 << 16) | 11):
	case ((5 << 16) | 12):
	case ((5 << 16) | 13):
	case ((5 << 16) | 14):
	case ((5 << 16) | 16):
		web_config_management(page);
		break;
	default:
		break;
	}
}

