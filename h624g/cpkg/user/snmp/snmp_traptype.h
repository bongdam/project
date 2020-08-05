#ifndef __SNMP_TRAPTYPE_H__
#define __SNMP_TRAPTYPE_H__

void *sendAutoTransmission(void);
void *send_wlall_status_trap(char *msg, int msglen, char *trap_name);
void *send_cpeping_status_trap(char *msg, int msglen);
void *sendAutoRebootTrap(unsigned long wan_crc, char *f_reason);
void *sendPortLinkTrap(unsigned char portinfo);
void *sendLimitedSessionTrap(int wifi_session, int wifi_session_total, char *wan_bitrate, char *wifi_bitrate);
void *sendSmartResetTrap(char *f_reason);
void *sendAutoBandwidthTrap(void);
void *sendHandOverSuccessTrap(void);
void *sendNtpFailTrap(char *fail_server);
void sendwlan1SitesurveyResultTrap(void);
void sendwlan0SitesurveyResultTrap(void);
void *send_sta_fail_trap(char *msg, int msglen);

static inline unsigned char is_zero_ether_addr(const unsigned char *addr)
{
	return !(addr[0] | addr[1] | addr[2] | addr[3] | addr[4] | addr[5]);
}

static inline unsigned char is_multicast_ether_addr(const unsigned char *addr)
{
	return 0x01 & addr[0];
}

static inline unsigned char is_valid_ether_addr(const unsigned char *addr)
{
	return !is_multicast_ether_addr(addr) && !is_zero_ether_addr(addr);
}

#endif
