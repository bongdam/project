#include <stdio.h>
#include <stdlib.h>
#include <malloc.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#ifdef CONFIG_IPV6
#include <linux/if_addr.h>
#endif
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include "apmib.h"
#include "mibtbl.h"

#include <typedefs.h>
#include <bcmnvram.h>
#include <libytool.h>
#include <shutils.h>
#include "nvram_mib.h"

#ifdef VOIP_SUPPORT
#error VOIP_SUPPORT Must NOT be defined!
#endif
#ifndef MIB_TLV
#error MIB_TLV Must be defined!
#endif

int wlan_idx = 0;	// interface index
int vwlan_idx = 0;	// initially set interface index to root
int wlan_idx_bak = 0;
int vwlan_idx_bak = 0;
int ypriority = 0;
int nm_errno;

#ifndef _NDEBUG
#define isspace(c) ((((c) == ' ') || (((unsigned int)((c) - 9)) <= (13 - 9))))

static const char *strpriority(int prio)
{
	switch (prio) {
	case L_CRIT:
		return "|crit|";
	case L_ERR:
		return "|err |";
	case L_WARN:
		return "|warn|";
	case L_INFO:
		return "|info|";
	default:
		return "";
	}
}

int yprintf(int level, const char *fmt, ...)
{
	va_list args;
	char buffer[128], *p, *LF = "";
	int n;

	if (!ypriority) {
		p = nvram_safe_get("x_user_loglevel");
		ypriority = strtol(p, NULL, 0) ? : L_ERR;
	}

	if (ypriority < level)
		return -1;

	p = buffer;
	va_start(args, fmt);
	n = yvasnprintf(&p, sizeof(buffer), fmt, args);
	va_end(args);
	if (p == NULL)
		return -1;

	if (n == 0 || !isspace(p[n - 1]))
		LF = "\n";
	if (isatty(STDERR_FILENO))
		fprintf(stderr, "%s%s%s", strpriority(level), p, LF);
	else
		cprintf("%s%s%s", strpriority(level), p, LF);

        if (p != buffer)
                free(p);
	return 0;
}
#endif

void apmib_save_wlanIdx(void)
{
	wlan_idx_bak = wlan_idx;
	vwlan_idx_bak = vwlan_idx;
}

void apmib_recov_wlanIdx(void)
{
	wlan_idx = wlan_idx_bak;
	vwlan_idx = vwlan_idx_bak;
}

void wlan_interface_change(int interface, int vap)
{
	apmib_save_wlanIdx();
	wlan_idx = interface;
	vwlan_idx = vap;
}

int apmib_sem_lock(void)
{
	return 0;
}

int apmib_sem_unlock(void)
{
	return 0;
}

int apmib_shm_free(void *shm_memory, int shm_key)
{
	return 0;
}

char *apmib_hwconf(void)
{
	_DEBUG(L_WARN, "not implemented");
	return (char *)-ENOSYS;
}

char *apmib_dsconf(void)
{
	_DEBUG(L_WARN, "not implemented");
	return (char *)-ENOSYS;
}

int flash_read_raw_mib(unsigned char **compFile)
{
	_DEBUG(L_WARN, "not implemented");
	return 1;
}

int flash_write_raw_mib(unsigned char **compFile)
{
	_DEBUG(L_WARN, "not implemented");
	return 1;
}

char *apmib_csconf(void)
{
	_DEBUG(L_WARN, "not implemented");
	return (char *)-ENOSYS;
}

int apmib_init_HW(void)
{
	return 1;
}

int apmib_init(void)
{
	return 1;
}

char *apmib_load_hwconf(void)
{
	return (char *)-ENOSYS;
}

char *apmib_load_dsconf(void)
{
	return (char *)-ENOSYS;
}

char *apmib_load_csconf(void)
{
	return (char *)-ENOSYS;
}

int apmib_reinit(void)
{
	return apmib_init();
}

#ifdef HOME_GATEWAY
# ifdef CONFIG_IPV6
static int i6_str2radvdcfg(radvdCfgParam_Tp dst, const char *s)
{
	char *args[40], **argv;
	int i;
	char *p = (s) ? strdup(s) : NULL;

	if (p == NULL || dst == NULL)
		return 0;
	if (ystrargs(p, args, _countof(args), ",", 1) < 33) {
		free(p);
		return 0;
	}
	memset(dst, 0, sizeof(*dst));
	dst->enabled =  (uint8)strtoul(args[0], NULL, 0);
	/* interface */
	strncpy(dst->interface.Name, args[1], IFNAMESIZE);
	dst->interface.MaxRtrAdvInterval = strtoul(args[2], NULL, 0);
	dst->interface.MinRtrAdvInterval = strtoul(args[3], NULL, 0);
	dst->interface.MinDelayBetweenRAs = strtoul(args[4], NULL, 0);
	dst->interface.AdvManagedFlag = (uint8)strtoul(args[5], NULL, 0);
	dst->interface.AdvOtherConfigFlag = (uint8)strtoul(args[6], NULL, 0);
	dst->interface.AdvLinkMTU = strtoul(args[7], NULL, 0);
	dst->interface.AdvReachableTime = strtoul(args[8], NULL, 0);
	dst->interface.AdvRetransTimer = strtoul(args[9], NULL, 0);
	dst->interface.AdvCurHopLimit = (uint8)strtoul(args[10], NULL, 0);
	dst->interface.AdvDefaultLifetime = (uint16)strtoul(args[11], NULL, 0);
	strncpy(dst->interface.AdvDefaultPreference, args[12], IFNAMESIZE);
	dst->interface.AdvSourceLLAddress = (uint8)strtoul(args[13], NULL, 0);
	dst->interface.UnicastOnly = (uint8)strtoul(args[14], NULL, 0);

	argv = &args[15];
	for (i = 0; i < MAX_PREFIX_NUM; i++) {
		struct AdvPrefix *prefix = &dst->interface.prefix[i];
		if (inet_pton(AF_INET6, *argv++, (void *)prefix->Prefix) != 1) {
			free(p);
			return 0;
		}
		prefix->PrefixLen = (uint8)strtoul(*argv++, NULL, 0);
		prefix->AdvOnLinkFlag = (uint8)strtoul(*argv++, NULL, 0);
		prefix->AdvAutonomousFlag = (uint8)strtoul(*argv++, NULL, 0);
		prefix->AdvValidLifetime = strtoul(*argv++, NULL, 0);
		prefix->AdvPreferredLifetime = strtoul(*argv++, NULL, 0);
		prefix->AdvRouterAddr = (uint8)strtoul(*argv++, NULL, 0);
		strncpy(prefix->if6to4, *argv++, IFNAMESIZE);
		prefix->enabled = (uint8)strtoul(*argv++, NULL, 0);
	}

	free(p);
	return 1;
}

static int i6_str2dnsv6cfg(dnsv6CfgParam_Tp dst, const char *s)
{
	char *args[4];
	char *p = (s) ? strdup(s) : NULL;

	if (p == NULL || dst == NULL)
		return 0;
	if (ystrargs(p, args, _countof(args), ",", 1) < 2) {
		free(p);
		return 0;
	}
	memset(dst, 0, sizeof(*dst));
	dst->enabled = (uint8)strtoul(args[0], NULL, 0);
	strncpy(dst->routerName, args[1], NAMSIZE);
	free(p);
	return 1;
}

static int i6_str2dhcp6scfg(dhcp6sCfgParam_Tp dst, const char *s)
{
	char *args[8];
	char *p = (s) ? strdup(s) : NULL;

	if (p == NULL || dst == NULL)
		return 0;
	if (ystrargs(p, args, _countof(args), ",", 1) < 5) {
		free(p);
		return 0;
	}
	memset(dst, 0, sizeof(*dst));
	dst->enabled = (uint8)strtoul(args[0], NULL, 0);
	strncpy(dst->DNSaddr6, args[1], sizeof(dst->DNSaddr6));
	strncpy(dst->addr6PoolS, args[2], sizeof(dst->addr6PoolS));
	strncpy(dst->addr6PoolE, args[3], sizeof(dst->addr6PoolE));
	strncpy(dst->interfaceNameds, args[4], NAMSIZE);
	free(p);
	return 1;
}

static int i6_str2dhcp6ccfg(dhcp6cCfgParam_Tp dst, const char *s)
{
	char *args[8];
	char *p = (s) ? strdup(s) : NULL;

	if (p == NULL || dst == NULL)
		return 0;
	if (ystrargs(p, args, _countof(args), ",", 1) < 5) {
		free(p);
		return 0;
	}
	memset(dst, 0, sizeof(*dst));
	dst->enabled = (uint8)strtoul(args[0], NULL, 0);
	strncpy(dst->ifName, args[1], NAMSIZE);
	dst->dhcp6pd.sla_len = strtoul(args[2], NULL, 0);
	dst->dhcp6pd.sla_id = strtoul(args[3], NULL, 0);
	strncpy(dst->dhcp6pd.ifName, args[4], NAMSIZE);
	free(p);
	return 1;
}

static int i6_str2addrip6cfg(addrIPv6CfgParam_t *dst, const char *s)
{
	char *args[8];
	char *p = (s) ? strdup(s) : NULL;
	int rc = 1;

	if (p == NULL || dst == NULL)
		return 0;
	if (ystrargs(p, args, _countof(args), ",", 1) < 5) {
		free(p);
		return 0;
	}
	dst->enabled = strtol(args[0], NULL, 0);
	dst->prefix_len[0] = strtol(args[1], NULL, 0);
	dst->prefix_len[1] = strtol(args[2], NULL, 0);
	if (inet_pton(AF_INET6, args[3], (void *)dst->addrIPv6[0]) != 1 ||
	    inet_pton(AF_INET6, args[4], (void *)dst->addrIPv6[1]) != 1)
	    	rc = 0;
    	free(p);
    	return rc;
}

static int i6_str2addr6cfg(addr6CfgParam_Tp dst, const char *s)
{
	char *args[8];
	char *p = (s) ? strdup(s) : NULL;
	int rc = 1;

	if (p == NULL || dst == NULL)
		return 0;
	if (ystrargs(p, args, _countof(args), ",", 1) < 2) {
		free(p);
		return 0;
	}
	dst->prefix_len = strtol(args[0], NULL, 0);
	if (inet_pton(AF_INET6, args[1], (void *)dst->addrIPv6) != 1)
	    	rc = 0;
    	free(p);
    	return rc;
}

static int i6_str2tunnelcfg(tunnelCfgParam_Tp dst, const char *s)
{
	dst->enabled = (uint8)strtoul((s) ? : "", NULL, 0);
	return 1;
}
# endif
#endif

int apmib_trans_type(void *value, const char *string, const struct mib *mib)
{
	if (string == NULL)
		return 0;

	switch (mib->type) {
	case BYTE_T:
	case WORD_T:
	case DWORD_T:
		*((int *)value) = (int)strtol(string, NULL, 0);
		break;
	case STRING_T:
		strcpy((char *)value, string);
		break;
	case BYTE5_T:
		return yxatoi((unsigned char *)value, string, 5 << 1);
	case BYTE6_T:
		return yxatoi((unsigned char *)value, string, 6 << 1);
	case BYTE13_T:
		return yxatoi((unsigned char *)value, string, 13 << 1);
	case BYTE_ARRAY_T:
		if (mib->id == MIB_L2TP_PAYLOAD)
			return yxatoi((unsigned char *)value, string, MAX_L2TP_BUFF_LEN << 1);
		else
			return yxatoi((unsigned char *)value, string, mib->size << 1);
	case IA_T:
		return (inet_pton(AF_INET, string, (void *)value) > 0);

#ifdef HOME_GATEWAY
# ifdef CONFIG_IPV6
	case RADVDPREFIX_T:
		return i6_str2radvdcfg((radvdCfgParam_Tp)value, string);
	case DNSV6_T:
		return i6_str2dnsv6cfg((dnsv6CfgParam_Tp)value, string);
	case DHCPV6S_T:
		return i6_str2dhcp6scfg((dhcp6sCfgParam_Tp)value, string);
	case DHCPV6C_T:
		return i6_str2dhcp6ccfg((dhcp6cCfgParam_Tp)value, string);
	case ADDR6_T:
		return i6_str2addrip6cfg((addrIPv6CfgParam_t *)value, string);
	case ADDRV6_T:
		return i6_str2addr6cfg((addr6CfgParam_Tp)value, string);
	case TUNNEL6_T:
		return i6_str2tunnelcfg((tunnelCfgParam_Tp)value, string);
# endif
#endif
	default:
		return 0;
	}
	return 1;
}

int apmib_get(int id, void *value)
{
	char name[80];	/* mib_table_entry_T:name is 40 bytes array */
	const struct mib *mib;

	mib = ysearch_mib_struct(id);
	if (mib == NULL) {
		_DEBUG(L_ERR, "%d id not found", id);
		return 0;
	}

	if (mib->type > TABLE_LIST_T)
		return apmib_get_tblarray(id, value, mib);

	ynvram_name(name, sizeof(name), mib->name, mib->section);
	return apmib_trans_type(value, nvram_safe_get(name), mib);
}

static int _apmib_set(int id, void *value)
{
	char name[80];	/* mib_table_entry_T:name is 40 bytes array */
	const struct mib *mib;
	unsigned int mib_num_id = 0;
	unsigned int id_orig;
#if defined(MIB_MOD_TBL_ENTRY)
	unsigned int mod_tbl = 0;
#endif
	int i, max_chan_num = MAX_2G_CHANNEL_NUM_MIB;
	char *p;
	unsigned char *q, *tmp;
#ifdef HOME_GATEWAY
# ifdef CONFIG_IPV6
	char i6_abuf[INET6_ADDRSTRLEN];
	char i6_abuf2[INET6_ADDRSTRLEN];
# endif
#endif
	id_orig = id;

	if (id_orig & MIB_ADD_TBL_ENTRY) {
		id = ((id_orig & MIB_ID_MASK) - 1) | (MIB_TABLE_LIST);
		mib_num_id = (id_orig & MIB_ID_MASK) - 2;
	} else if (id_orig & MIB_DEL_TBL_ENTRY) {
#if defined(MIB_MOD_TBL_ENTRY)
		if (id_orig & MIB_MOD_TBL_ENTRY) {
			id_orig &= ~MIB_MOD_TBL_ENTRY;
			id = id_orig;
			mod_tbl = 1;
		}
#endif
		id = ((id_orig & MIB_ID_MASK) - 2) | (MIB_TABLE_LIST);
		mib_num_id = (id_orig & MIB_ID_MASK) - 3;
	} else if (id_orig & MIB_DELALL_TBL_ENTRY) {
		id = ((id_orig & MIB_ID_MASK) - 3) | (MIB_TABLE_LIST);
		mib_num_id = (id_orig & MIB_ID_MASK) - 4;
	}

	mib = ysearch_mib_struct(id);
	if (mib == NULL) {
		nm_errno = ENM_NOMIB;
		return 0;
	}

	if (mib->type > TABLE_LIST_T) {
		if (id_orig & MIB_ADD_TBL_ENTRY)
			return apmib_add_tblarray(id, value, mib, mib_num_id);
		else if(id_orig & MIB_DEL_TBL_ENTRY) {
#if defined(MIB_MOD_TBL_ENTRY)
			if (mod_tbl == 1)
				return apmib_mod_tblentry();
			else
#endif
			return apmib_del_tblarray(id, value, mib, mib_num_id, 0);
		} else if (id_orig & MIB_DELALL_TBL_ENTRY)
			return apmib_del_tblarray(id, value, mib, mib_num_id, 1);
		return 0;
	}

	ynvram_name(name, sizeof(name), mib->name, mib->section);

	switch (mib->type) {
	case BYTE_T:
		ynvram_put("%s=%d", name, (unsigned char)(*((int *)value)));
		break;
	case WORD_T:
		ynvram_put("%s=%d", name, (unsigned short)(*((int *)value)));
		break;
	case DWORD_T:
		ynvram_put("%s=%lu", name, (unsigned long)(*((int *)value)));
		break;
	case STRING_T:
		if (strlen((const char *)value) >= mib->size)
			return FALSE;
		ynvram_put("%s=%s", name, (char *)value);
		break;
	case BYTE5_T:
		return ynvram_putarray(name, value, 5);
	case BYTE6_T:
		return ynvram_putarray(name, value, 6);
	case BYTE13_T:
		return ynvram_putarray(name, value, 13);
	case BYTE_ARRAY_T:
#ifdef VPN_SUPPORT
		if (id == MIB_IPSEC_RSA_FILE)
			return ynvram_putarray(name, value, MAX_RSA_FILE_LEN);
		else
#endif
		if (id == MIB_L2TP_PAYLOAD)
			return ynvram_putarray(name, value, MAX_L2TP_BUFF_LEN);
		else
#ifdef VOIP_SUPPORT
# ifndef VOIP_SUPPORT_TLV_CFG
		if (id == MIB_VOIP_CFG)
			return ynvram_putarray(name, value, mib->size);
		else
# endif
#endif	/*VOIP_SUPPORT */
		{
			tmp = (unsigned char *)value;
#if defined(CONFIG_RTL_8196B)
			max_chan_num = (id == MIB_HW_TX_POWER_CCK) ? MAX_CCK_CHAN_NUM : MAX_OFDM_CHAN_NUM;
#elif defined(CONFIG_RTL_8198C) || \
      defined(CONFIG_RTL_8196C) || \
      defined(CONFIG_RTL_8198)  || \
      defined(CONFIG_RTL_819XD) || \
      defined(CONFIG_RTL_8196E)
                        if ((id >= MIB_HW_TX_POWER_CCK_A && id <= MIB_HW_TX_POWER_DIFF_OFDM))
				max_chan_num = MAX_2G_CHANNEL_NUM_MIB;
			else if ((id >= MIB_HW_TX_POWER_5G_HT40_1S_A && id <= MIB_HW_TX_POWER_DIFF_5G_OFDM)
# if defined(CONFIG_WLAN_HAL_8814AE)
				|| (id >= MIB_HW_TX_POWER_5G_HT40_1S_C && id <= MIB_HW_TX_POWER_5G_HT40_1S_D)
# endif
				)
				max_chan_num = MAX_5G_CHANNEL_NUM_MIB;
#endif
#if defined(CONFIG_RTL_8812_SUPPORT)
			if (((id >= MIB_HW_TX_POWER_DIFF_20BW1S_OFDM1T_A) && (id <= MIB_HW_TX_POWER_DIFF_OFDM4T_CCK4T_A)) ||
			    ((id >= MIB_HW_TX_POWER_DIFF_20BW1S_OFDM1T_B) && (id <= MIB_HW_TX_POWER_DIFF_OFDM4T_CCK4T_B)))
				max_chan_num = MAX_2G_CHANNEL_NUM_MIB;
			if (((id >= MIB_HW_TX_POWER_DIFF_5G_20BW1S_OFDM1T_A) && (id <= MIB_HW_TX_POWER_DIFF_5G_80BW4S_160BW4S_A)) ||
			    ((id >= MIB_HW_TX_POWER_DIFF_5G_20BW1S_OFDM1T_B) && (id <= MIB_HW_TX_POWER_DIFF_5G_80BW4S_160BW4S_B))
# if defined(CONFIG_WLAN_HAL_8814AE)
			    || ((id >= MIB_HW_TX_POWER_DIFF_5G_20BW1S_OFDM1T_C) && (id <= MIB_HW_TX_POWER_DIFF_5G_80BW4S_160BW4S_C)) ||
			    ((id >= MIB_HW_TX_POWER_DIFF_5G_20BW1S_OFDM1T_D) && (id <= MIB_HW_TX_POWER_DIFF_5G_80BW4S_160BW4S_D))
# endif
			    )
				max_chan_num = MAX_5G_DIFF_NUM;
#endif

			if (tmp[0] == 2) {
				if (tmp[3] == 0xff) { // set one channel value
					p = nvram_get(name);
					q = (unsigned char *)calloc(mib->size, 1);
					if (p != NULL)
						yxatoi(q, p, mib->size << 1);
					q[tmp[1] - 1] = tmp[2];
					i = ynvram_putarray(name, q, mib->size);
					free(q);
					return i;
				}
			} else
				return ynvram_putarray(name, &tmp[1], max_chan_num);
		}
		break;
	case IA_T:
		ynvram_put("%s=%s", name, inet_ntoa(*(struct in_addr *)value));
		break;
#ifdef HOME_GATEWAY
# ifdef CONFIG_IPV6
	case RADVDPREFIX_T: {
		radvdCfgParam_Tp p = (radvdCfgParam_Tp)value;

		if (inet_ntop(AF_INET6, p->interface.prefix[0].Prefix, i6_abuf, INET6_ADDRSTRLEN) == NULL ||
		    inet_ntop(AF_INET6, p->interface.prefix[1].Prefix, i6_abuf2, INET6_ADDRSTRLEN) == NULL)
			return 0;

		ynvram_put("%s=%u,%s,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%s,%u,%u,%s,%u,%u,%u,%u,%u,%u,%s,%u,%s,%u,%u,%u,%u,%u,%u,%s,%d",
			name,
			p->enabled,
			p->interface.Name,
			p->interface.MaxRtrAdvInterval,
			p->interface.MinRtrAdvInterval,
			p->interface.MinDelayBetweenRAs,
			p->interface.AdvManagedFlag,
			p->interface.AdvOtherConfigFlag,
			p->interface.AdvLinkMTU,
			p->interface.AdvReachableTime,
			p->interface.AdvRetransTimer,
			p->interface.AdvCurHopLimit,
			p->interface.AdvDefaultLifetime,
			p->interface.AdvDefaultPreference,
			p->interface.AdvSourceLLAddress,
			p->interface.UnicastOnly,
			i6_abuf,
			p->interface.prefix[0].PrefixLen,
			p->interface.prefix[0].AdvOnLinkFlag,
			p->interface.prefix[0].AdvAutonomousFlag,
			p->interface.prefix[0].AdvValidLifetime,
			p->interface.prefix[0].AdvPreferredLifetime,
			p->interface.prefix[0].AdvRouterAddr,
			p->interface.prefix[0].if6to4,
			p->interface.prefix[0].enabled,
			i6_abuf2,
			p->interface.prefix[1].PrefixLen,
			p->interface.prefix[1].AdvOnLinkFlag,
			p->interface.prefix[1].AdvAutonomousFlag,
			p->interface.prefix[1].AdvValidLifetime,
			p->interface.prefix[1].AdvPreferredLifetime,
			p->interface.prefix[1].AdvRouterAddr,
			p->interface.prefix[1].if6to4,
			p->interface.prefix[1].enabled);
		break;
	}
	case DNSV6_T: {
		dnsv6CfgParam_Tp p = (dnsv6CfgParam_Tp)value;
		ynvram_put("%s=%d,%s", name, p->enabled, p->routerName);
		break;
	}
	case DHCPV6S_T: {
		dhcp6sCfgParam_Tp p = (dhcp6sCfgParam_Tp)value;
		ynvram_put("%s=%d,%s,%s,%s,%s", name,
			p->enabled, p->DNSaddr6, p->addr6PoolS, p->addr6PoolE, p->interfaceNameds);
		break;
	}
	case DHCPV6C_T: {
		dhcp6cCfgParam_Tp p = (dhcp6cCfgParam_Tp)value;
		ynvram_put("%s=%d,%s,%d,%d,%s", name,
			p->enabled, p->ifName, p->dhcp6pd.sla_len, p->dhcp6pd.sla_id, p->dhcp6pd.ifName);
		break;
	}
	case ADDR6_T: {
		addrIPv6CfgParam_t *p = (addrIPv6CfgParam_t *)value;
		if (inet_ntop(AF_INET6, p->addrIPv6[0], i6_abuf, INET6_ADDRSTRLEN) == NULL ||
		    inet_ntop(AF_INET6, p->addrIPv6[1], i6_abuf2, INET6_ADDRSTRLEN) == NULL)
			return 0;
		ynvram_put("%s=%d,%d,%d,%s,%s", name,
			p->enabled, p->prefix_len[0], p->prefix_len[1], i6_abuf, i6_abuf2);
		break;
	}
	case ADDRV6_T: {
		addr6CfgParam_Tp p = (addr6CfgParam_Tp)value;
		if (inet_ntop(AF_INET6, p->addrIPv6, i6_abuf, INET6_ADDRSTRLEN) == NULL)
			return 0;
		ynvram_put("%s=%d,%s", name, p->prefix_len, i6_abuf);
		break;
	}
	case TUNNEL6_T:
		ynvram_put("%s=%d", name, ((tunnelCfgParam_Tp)value)->enabled);
		break;
# endif
#endif
	default:
		return 0;
	}

	return 1;
}

int apmib_set(int id, void *value)
{
	int res, prev_nm_errno = nm_errno;

	nm_errno = 0;
	res = _apmib_set(id, value);
	if (res) {
		if (nm_errno != ENM_IDENTICAL)
			apmib_set_hist_put(id);
		nm_errno = prev_nm_errno;
	} else
		_DEBUG(L_ERR, "id %d: %s", id, apmib_strerror(nm_errno));
	return res;
}

int apmib_update(CONFIG_DATA_T type)
{
	nvram_commit();
	return 1;
}

#ifndef RTL_DEF_SETTING_IN_FW
int apmib_updateDef(void)
{
	return 1;
}
#endif

int save_cs_to_file(void)
{
	return 1;
}

char **apmib_iterate(struct mib_iterator *it)
{
	char **pp = NULL, *p = NULL;
	int i, nmemb, size, exponent = 3;

	for (i = nmemb = size = 0; (p = it->_fetch(it->priv_data, i)); i++) {
		if (!it->_match(p, it->priv_data))
			continue;
		if (size <= nmemb) {
			if (exponent > 12) {	/* up to 4096 */
				nmemb--;
				break;
			}
			size = 1 << exponent++;
			pp = realloc(pp, sizeof(char *) * size);
		}
		pp[nmemb++] = strdup(p);
	}

	if (pp)
		pp[nmemb] = NULL;

	return pp;
}

void swapWlanMibSetting(unsigned char wlanifNumA, unsigned char wlanifNumB)
{
	char *buf, *name, *p;
	char prefix1[16], prefix2[16];
	int len1, len2;
#if VLAN_CONFIG_SUPPORTED
	char *a, *b;
	char tmp[80];
	int i;
	const struct mib *mib;
#endif
#ifdef UNIVERSAL_REPEATER
	int rptEnable1, rptEnable2;
	char rptSsid1[MAX_SSID_LEN], rptSsid2[MAX_SSID_LEN];
#endif

	if (wlanifNumA >= NUM_WLAN_INTERFACE ||
	    wlanifNumB >= NUM_WLAN_INTERFACE ||
	    (wlanifNumA == wlanifNumB))
		return;

	len1 = sprintf(prefix1, "WLAN%d_", wlanifNumA);
	len2 = sprintf(prefix2, "WLAN%d_", wlanifNumB);

	buf = (char *)malloc(MAX_NVRAM_SPACE + 16);
	if (buf == NULL)
		return;

	nvram_getall(&buf[16], MAX_NVRAM_SPACE);
	for (name = &buf[16]; *name; name += strlen(name) + 1) {
		if (!memcmp(name, prefix1, len1)) {
			p = &name[len1 - len2];
			memcpy(p, prefix2, len2);
		} else if (!memcmp(name, prefix2, len2)) {
			p = &name[len2 - len1];
			memcpy(p, prefix1, len1);
		} else
			continue;
		ynvram_put(p);
	}
	free(buf);
#ifdef UNIVERSAL_REPEATER
	memset(rptSsid1, 0x00, MAX_SSID_LEN);
	memset(rptSsid2, 0x00, MAX_SSID_LEN);

	apmib_get(MIB_REPEATER_ENABLED1, (void *)&rptEnable1);
	apmib_get(MIB_REPEATER_ENABLED2, (void *)&rptEnable2);
	apmib_get(MIB_REPEATER_SSID1, (void *)rptSsid1);
	apmib_get(MIB_REPEATER_SSID2, (void *)rptSsid2);

	apmib_set(MIB_REPEATER_ENABLED1, (void *)&rptEnable2);
	apmib_set(MIB_REPEATER_ENABLED2, (void *)&rptEnable1);
	apmib_set(MIB_REPEATER_SSID1, (void *)rptSsid2);
	apmib_set(MIB_REPEATER_SSID2, (void *)rptSsid1);
#endif
#if VLAN_CONFIG_SUPPORTED
	mib = ysearch_mib_struct(MIB_VLANCONFIG_TBL);
	if (mib != NULL) {
		ynvram_name(tmp, sizeof(tmp), mib->name, mib->section);
		for (i = 5; i < 10; i++) {
			a = ynvram_get("%s%d", tmp, i);
			b = ynvram_get("%s%d", tmp, i + 5);
			ynvram_put("%s%d=%s", tmp, i + 5, (a) ? : "");
			ynvram_put("%s%d=%s", tmp, i, (b) ? : "");
		}
	}
#endif
}

static unsigned char _K[16];

static void __attribute__ ((constructor)) apmib_aes_cbc_init_key(void)
{
	//dtAexJt7eb8SxurM
	unsigned char c;

	c = 0x3d; c -= 0xbf; c ^= 15; c += 0x38; c = (c >> 0x5) | (c << 0x3); _K[15] = c;
	c = 0x31; c += 0; c ^= 0x6f; c += 0x33; c = (c >> 0x2) | (c << 0x6); _K[0] = c;
	c = 0x83; c = ~c; c += 0x70; c = (c >> 0x6) | (c << 0x2); c ^= 0xf2; _K[2] = c;
	c = 0xc; c ^= 5; c = (c >> 0x2) | (c << 0x6); c ^= 0x74; c -= 0xec; _K[5] = c;
	c = 0x65; c = ~c; c -= 14; c = (c >> 0x5) | (c << 0x3); c += 14; _K[14] = c;
	c = 0xfd; c += 0xfa; c ^= 0xf8; c -= 0x75; c = ~c; _K[3] = c;
	c = 0x8a; c = ~c; c -= 0x78; c ^= 12; c += 0x87; _K[12] = c;
	c = 0xb0; c -= 4; c = -c; c = (c >> 0x3) | (c << 0x5); c += 0xee; _K[4] = c;
	c = 0x82; c = (c >> 0x7) | (c << 0x1); c = -c; c ^= 0x14; c += 0x48; _K[7] = c;
	c = 0xd7; c += 0x8e; c = -c; c = (c >> 0x3) | (c << 0x5); c += 1; _K[1] = c;
	c = 0xb7; c -= 0x5; c = (c >> 0x2) | (c << 0x6); c += 0x99; c ^= 0x20; _K[8] = c;
	c = 7; c ^= 0xa7; c += 0x1f; c = (c >> 0x2) | (c << 0x6); c += 0x49; _K[10] = c;
	c = 0xc7; c += 0x59; c ^= 0x1c; c = -c; c = (c >> 0x1) | (c << 0x7); _K[9] = c;
	c = 0x98; c -= 0x49; c = (c >> 0x1) | (c << 0x7); c = ~c; c ^= 0xb; _K[11] = c;
	c = 0x79; c += 0xa5; c ^= 0x6f; c = (c >> 0x5) | (c << 0x3); c = ~c; _K[6] = c;
	c = 0x12; c ^= 0xf9; c = -c; c -= 0xc1; c ^= 0x21; _K[13] = c;
}

static char *apmib_file_dfl_decrypt(const char *path, char *tnam)
{
	int fd;
	struct stat sb;

	if (stat(path, &sb) || !S_ISREG(sb.st_mode))
		return NULL;
	fd = mkstemp(tnam);
	if (fd < 0)
		return NULL;
	close(fd);
	if (!yexecl(NULL, "AEScbc -d -k %s -i %s -o %s", _K, path, tnam))
		return tnam;
	unlink(tnam);
	return NULL;
}

const char *apmib_file_dfl(DFL_TYPE_T type)
{
	static char buf[24] = "/var/XXXXXX";

	strncpy(buf, "/var/XXXXXX", sizeof(buf));
	switch (type) {
	case HW_DFL:
		return apmib_file_dfl_decrypt("/etc/hconf.a7c", buf);
	case RUN_DFL:
		return apmib_file_dfl_decrypt("/etc/rconf.a7c", buf);
	case REV_DFL:
		return apmib_file_dfl_decrypt("/etc/conf.a7c", buf);
	default:
		return NULL;
	}
}

char *apmib_strerror(int errnum)
{
	switch (errnum) {
	case ENM_NOSYS:
		return "Function not implemented";
	case ENM_INVAL:
		return "Invalid argument";
	case ENM_IDENTICAL:
		return "Identical value";
	case ENM_MEMORY:
		return "Out of memory";
	case ENM_NOMIB:
		return "MIB entry not found";
	case ENM_BADFMT:
		return "Badly formatted";
	case ENM_BADTYPE:
		return "Type not supported";
	case ENM_OORNG:
		return "Out of range";
	case ENM_FULL:
		return "Entry is full";
	default:
		return "Unknown";
	}
}
