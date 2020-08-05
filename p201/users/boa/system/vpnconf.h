#ifndef __VPNCONF_H__
#define __VPNCONF_H__

/*
 * to store PPTP/L2TP connection info to file
 * It contains following inforations, seperated by space(' ').
 *   1) interface: ppp0...ppp10
 *   2) protocol (pptp/l2tp)
 *   3) loca-ip
 *   4) remote-ip
 *   5) connection start time (time_t)
 */
#define PPP_INFO_FILE_PREFIX	"/etc/ppp/info_"

/*-----------------------------------------------------------------------*/

#define IPSEC_MAX_SESSION	5

#define IPSEC_CONFIG_FILE	"/etc/ipsec.conf"
#define IPSEC_SECRETS_FILE	"/etc/ipsec.secrets"
#define STRONGSWAN_CONFIG_FILE	"/etc/strongswan.conf"
#define IPSEC_VPN_SCRIPT	"/etc/ipsec.d/ipsec.updown"

#define PPTP_SERVER_CONFIG_FILE	"/etc/ppp/pptpd.conf"
#define PPTP_CLIENT_CONFIG_FILE	"/etc/ppp/peers/rpptp"
#define PPTP_OPTION_FILE	"/etc/ppp/options"
#define PPTP_CHAP_SECRETS_FILE	"/etc/ppp/chap-secrets"
#define PPTP_VPN_SCRIPT		"/etc/ppp/vpnscript"

#define L2TP_CONFIG_FILE	"/etc/ppp/l2tpd.conf"
#define L2TP_OPTION_FILE	PPTP_OPTION_FILE
#define L2TP_CHAP_SECRETS_FILE	PPTP_CHAP_SECRETS_FILE
#define L2TP_VPN_SCRIPT		PPTP_VPN_SCRIPT

#define L2TP_IPSEC_CONN_NAME	"l2tptunnel"
#define L2TP_IPSEC_FQDN_NAME	"pptp-ipsec-tunnel"

#endif	/*__VPNCONF_H__*/
