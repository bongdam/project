/*
 *      Include file of form handler
 *
 *      Authors: David Hsu	<davidhsu@realtek.com.tw>
 *
 *      $Id: apform.h,v 1.45 2010/03/18 08:03:53 bradhuang Exp $
 *
 */

#ifndef _INCLUDE_APFORM_H
#define _INCLUDE_APFORM_H

#include "apmib.h"
#ifndef CSRF_SECURITY_PATCH
# define CSRF_SECURITY_PATCH
#endif
#ifdef __i386__
# define _CONFIG_SCRIPT_PATH	"."
# define _LITTLE_ENDIAN_
#else
# define _CONFIG_SCRIPT_PATH	"/bin"
#endif

#define _CONFIG_SCRIPT_PROG	"init.sh"
#define _WLAN_SCRIPT_PROG	"wlan.sh"
#define _PPPOE_SCRIPT_PROG	"pppoe.sh"
#define _PPTP_SCRIPT_PROG	"pptp.sh"
#define _L2TP_SCRIPT_PROG	"l2tp.sh"
#define _FIREWALL_SCRIPT_PROG	"firewall.sh"
#define _ROUTE_SCRIPT_PROG	"route.sh"
#define _PPPOE_DC_SCRIPT_PROG	"disconnect.sh"
#define _IAPPAUTH_SCRIPT_PROG	"iappauth.sh"
#define _NTP_SCRIPT_PROG	"ntp.sh"
#ifdef HOME_GATEWAY
# ifdef VPN_SUPPORT
#  define _VPN_SCRIPT_PROG	"vpn.sh"
# endif

# ifdef GW_QOS_ENGINE
#  define _QOS_SCRIPT_PROG	    "qos.sh"
# endif

# ifdef QOS_BY_BANDWIDTH
#  define _QOS_SCRIPT_PROG	    "ip_qos.sh"
# endif

# ifdef CONFIG_IPV6
#  define _IPV6_RADVD_SCRIPT_PROG "radvd.sh"
#  define _IPV6_DNSMASQ_SCRIPT_PROG "dnsv6.sh"
#  define _IPV6_DHCPV6S_SCRIPT_PROG "dhcp6s"
#  define _IPV6_LAN_INTERFACE "br0"
#  define _IPV6_WAN_INTERFACE "eth1"
# endif

# ifdef CONFIG_RTL_BT_CLIENT
#  define _BT_SCRIPT_PROG "bt.sh"
# endif
#endif
#define _WLAN_APP_SCRIPT_PROG	"wlanapp.sh"
#define _DHCPD_PROG_NAME	"udhcpd"
#define _DHCPD_PID_PATH		"/var/run"

#define WEB_PAGE_LOGIN	"/index.html"

#define FORM_FW_UPLOAD	"formUpload"
#define FORM_CFG_UPLOAD	"formUploadConfig"

#if defined(CONFIG_APP_TR069) && defined(_CWMP_WITH_SSL_)
# define FORMTR069CACERT "formTR069CPECert"
# define FORMTR069CPECERT "formTR069CACert"
#endif

#ifdef CONFIG_RTL_BT_CLIENT
# define FORM_BT_NEW_TORRENT	"formBTNewTorrent"
#endif

#define MACIE5_CFGSTR	"/plain\x0d\x0a\0x0d\0x0a"
#define WINIE6_STR	"/octet-stream\x0d\x0a\0x0d\0x0a"
#define MACIE5_FWSTR	"/macbinary\x0d\x0a\0x0d\0x0a"
#define OPERA_FWSTR	"/x-macbinary\x0d\x0a\0x0d\0x0a"
#define LINE_FWSTR	"\x0d\x0a\0x0d\0x0a"
#define LINUXFX36_FWSTR "/x-ns-proxy-autoconfig\x0d\x0a\0x0d\0x0a"

#ifdef WLAN_EASY_CONFIG
# define _AUTO_CONFIG_DAEMON_PROG "autoconf"
#endif

#ifdef WIFI_SIMPLE_CONFIG
# define _WSC_DAEMON_PROG 	"wscd"
#endif

#define REBOOT_CHECK
#define APPLY_CHANGE_DIRECT_SUPPORT
#define REDUCE_WEBCLIENT_WAITTIME_SUPPORT

#ifdef REBOOT_CHECK
# ifndef RTK_REINIT_SUPPORT
#  if defined(CONFIG_POCKET_ROUTER_SUPPORT)
#   define APPLY_COUNTDOWN_TIME 35
#  else
#   define APPLY_COUNTDOWN_TIME 20
#  endif
# else
#  define APPLY_COUNTDOWN_TIME 0
# endif
# define APPLY_OK_MSG "<h4>설정 변경 성공!<BR>"
# define APPLY_RESET_MSG "<h4>초기화 성공!<BR>"
# define COUNTDOWN_PAGE "/countDownPage.htm"
extern int needReboot;
extern char okMsg[300];
extern char lastUrl[100];
extern char last_url[];
extern int countDownTime;
extern int run_init_script_flag;
#endif

#ifdef __DAVO__
# define APPLY_REBOOT_COUNTDOWN_TIME	50
#endif
#ifdef CSRF_SECURITY_PATCH
extern void log_boaform(char *form, request * req);
#endif

extern int save_cs_to_file();

///////////////////////////////////////////////////////////////////////////
static __inline__ bool _is_hex(char c)
{
	return (((c >= '0') && (c <= '9')) || ((c >= 'A') && (c <= 'F')) || ((c >= 'a') && (c <= 'f')));
}

// Validate digit
static __inline__ bool _isdigit(char c)
{
	return ((c >= '0') && (c <= '9'));
}

#ifdef __DAVO__
int string_to_hex(const char *s, unsigned char *key, int len);
int string_to_dec(const char *s, int *ret);
#else
static int __inline__ string_to_hex(char *string, unsigned char *key, int len)
{
	char tmpBuf[4];
	int idx, ii = 0;
	for (idx = 0; idx < len; idx += 2) {
		tmpBuf[0] = string[idx];
		tmpBuf[1] = string[idx + 1];
		tmpBuf[2] = 0;
		if (!_is_hex(tmpBuf[0]) || !_is_hex(tmpBuf[1]))
			return 0;

		key[ii++] = (unsigned char)strtol(tmpBuf, (char **)NULL, 16);
	}
	return 1;
}

static int __inline__ string_to_dec(char *string, int *val)
{
	int idx;
	int len = strlen(string);

	for (idx = 0; idx < len; idx++) {
		if (!_isdigit(string[idx]))
			return 0;
	}

	*val = strtol(string, (char **)NULL, 10);
	return 1;
}
#endif

#if defined(CONFIG_RTL_ULINKER)
static int __inline__ ulinker_wlan_mib_copy(CONFIG_WLAN_SETTING_T * dst, CONFIG_WLAN_SETTING_T * src)
{

# if CONFIG_APMIB_SHARED_MEMORY == 1
	if (apmib_sem_lock() != 0)
		return -1;
# endif

	memcpy(dst, src, sizeof(CONFIG_WLAN_SETTING_T));

# if CONFIG_APMIB_SHARED_MEMORY == 1
	if (apmib_sem_unlock() != 0)
		return -1;
# endif

	return 0;
}

static int __inline__ dbg_wlan_mib(int idx)
{
# if BDBG_ULINKER_SWAP_AP_CL_MIB
	fprintf(stderr, "  ==> %d.\n"
		"\tauto[%d], wlan_disable[%d], cur_wl_mode[%d], pre_wl_mode[%d]\n"
		"\troot_wl_mode[%d], root_ssid[%s], root_wl_dis[%d]\n"
		"\tap_wl_mode[%d],	 ap_ssid[%s], ap_wl_dis[%d]\n"
		"\tcl_wl_mode[%d],	 cl_ssid[%s], cl_wl_dis[%d]\n",
		idx,
		pMib->ulinker_auto, pMib->wlan[0][0].wlanDisabled, pMib->ulinker_cur_wl_mode, pMib->ulinker_lst_wl_mode,
		pMib->wlan[0][0].wlanMode, pMib->wlan[0][0].ssid, pMib->wlan[0][0].wlanDisabled,
		pMib->wlan[0][ULINKER_AP_MIB].wlanMode, pMib->wlan[0][ULINKER_AP_MIB].ssid, pMib->wlan[0][ULINKER_AP_MIB].wlanDisabled,
		pMib->wlan[0][ULINKER_CL_MIB].wlanMode, pMib->wlan[0][ULINKER_CL_MIB].ssid, pMib->wlan[0][ULINKER_CL_MIB].wlanDisabled);

#  if defined(UNIVERSAL_REPEATER)
	fprintf(stderr, "\trpt_wl_mode[%d],	 rpt_ssid[%s], rpt_wl_dis[%d]\n",
		pMib->wlan[0][ULINKER_RPT_MIB].wlanMode, pMib->wlan[0][ULINKER_RPT_MIB].ssid, pMib->wlan[0][ULINKER_RPT_MIB].wlanDisabled);
#  endif
# endif
	return 0;
}
#endif

#ifdef __DAVO__
int apmib_update_web(int type);
void update_form_hander_name(request *wp);
#else	/* __DAVO__ */
static int __inline__ apmib_update_web(int type)
{
	int ret;

#if defined(CONFIG_RTL_ULINKER)
	/*
	   For auto mode, we need to keep two wlan mib settings for ap/client.
	   Currently, we use WLAN0_VAP5 for save AP value and WLAN0_VAP6 for Client
	   When user save value to root ap, we will copy it to corresponding mib.
	 */
	if (type == CURRENT_SETTING) {
		extern int set_domain_name_query_ready(int val);
		set_domain_name_query_ready(2);

		dbg_wlan_mib(1);
		if (pMib->ulinker_auto == 1)
			pMib->wlan[0][0].wlanDisabled = 0;

		if (pMib->wlan[0][0].wlanMode == ULINKER_WL_AP) {
			pMib->ulinker_cur_wl_mode = ULINKER_WL_AP;
			pMib->ulinker_lst_wl_mode = ULINKER_WL_CL;

# if defined(UNIVERSAL_REPEATER)
			if (pMib->repeaterEnabled1 == 1) {
				ulinker_wlan_mib_copy(&pMib->wlan[0][ULINKER_RPT_MIB], &pMib->wlan[0][0]);
			} else
# endif
			{
				ulinker_wlan_mib_copy(&pMib->wlan[0][ULINKER_AP_MIB], &pMib->wlan[0][0]);
			}
		} else if (pMib->wlan[0][0].wlanMode == ULINKER_WL_CL) {
			pMib->ulinker_cur_wl_mode = ULINKER_WL_CL;
			pMib->ulinker_lst_wl_mode = ULINKER_WL_AP;

			ulinker_wlan_mib_copy(&pMib->wlan[0][ULINKER_CL_MIB], &pMib->wlan[0][0]);
		}

		/*
		   backup repeater value, because auto mode need to keep repeater disable,
		   we backup this value and restore it when device switch to manual mode.
		 */
		if (pMib->ulinker_auto == 0) {
			pMib->ulinker_repeaterEnabled1 = pMib->repeaterEnabled1;
			pMib->ulinker_repeaterEnabled2 = pMib->repeaterEnabled2;
		}
		dbg_wlan_mib(2);
	}
#endif

	ret = apmib_update(type);

	if (ret == 0)
		return 0;

	if (type & CURRENT_SETTING) {
		save_cs_to_file();
	}
	return ret;
}

static __inline__ void update_form_hander_name(request * wp)
{
	char *last, *nextp;

	last = wp->request_uri;
	while (1) {
		nextp = strstr(last, "/boafrm/");
		if (nextp) {
			last = nextp + 8;
			nextp = last;
			while (*nextp && !isspace(*nextp))
				nextp++;
			*nextp = '\0';
#ifdef CSRF_SECURITY_PATCH
			log_boaform(last, wp);
#endif
		}
		break;
	}
}
#endif /* !__DAVO__ */

#ifdef __DAVO__
void _FAIL_TO_LOGIN(request *wp, const char *msg);
# define FAIL_TO_LOGIN(msg) _FAIL_TO_LOGIN(wp, msg)
#endif

void _ERR_MSG(request *wp, const char *msg);
#define ERR_MSG(msg) _ERR_MSG(wp, msg)

#define REBOOT_WAIT_COMMAND(time) system("reboot &");

#ifdef REBOOT_CHECK
void _REBOOT_WAIT(request *wp, const char *url);

# define REBOOT_WAIT(url) _REBOOT_WAIT(wp, url)

void _FACTORY_WAIT(request *wp, const char *url);
# define FACTORY_WAIT(url) _FACTORY_WAIT(wp, url)

# ifdef __DAVO__
void _DO_APPLY_WAIT(request *wp, const char *url);
#  define DO_APPLY_WAIT(url) _DO_APPLY_WAIT(wp, url)
# endif

# ifdef CSRF_SECURITY_PATCH
#  if defined(APPLY_CHANGE_DIRECT_SUPPORT)
#   ifdef __DAVO__
extern void _OK_MSG(request *wp, const char *url);

#    define OK_MSG(url) _OK_MSG(wp, url)
#   else
#    define OK_MSG(url) { \
	extern void log_boaform(char *form, request *); \
	needReboot = 1; \
	if(strlen(url) == 0) \
		strcpy(url,"/wizard.htm"); \
	req_format_write(wp, "<html><head>"); \
	if(req_get_cstream_var(wp, "save_apply", "")[0]==0){ \
       req_format_write(wp, "<meta http-equiv=\"refresh\" content=\"0;url=%s\"><meta http-equiv=\"Content-Type\" content=\"text/html\" charset=\"utf-8\"></head></html>", url); \
    }else{\
       req_format_write(wp, "<script>function rebootform(){document.getElementById('rebootForm').submit();}</script></head><body onload='rebootform()'><form id='rebootForm' action=/boafrm/formRebootCheck method=POST name='rebootForm'>"); \
	   req_format_write(wp, "<input type='hidden' value='%s' name='submit-url'>",url); \
	   req_format_write(wp, "</form></body></html>");\
	   log_boaform("formRebootCheck",wp);\
	}\
}
#   endif
#   define REBOOT_NOWAIT(url) { \
	extern void log_boaform(char *form, request *);\
	if(strlen(url) == 0) \
		strcpy(url,"/wizard.htm"); \
	req_format_write(wp, "<html><head>"); \
	needReboot = 1; \
	req_format_write(wp, "<script>function rebootform(){document.getElementById('rebootForm').submit();}</script></head><body onload='rebootform()'><form id='rebootForm' action=/boafrm/formRebootCheck method=POST name='rebootForm'>"); \
	req_format_write(wp, "<input type='hidden' value='%s' name='submit-url'>",url); \
	req_format_write(wp, "</form></body></html>");\
	log_boaform("formRebootCheck",wp);\
}
#  else
#   define OK_MSG(url) { \
	extern void log_boaform(char *form,request *);\
	needReboot = 1; \
	if(strlen(url) == 0) \
		strcpy(url,"/wizard.htm"); \
	req_format_write(wp, "<html><head>"); \
	getIncludeCss(wp);\
 	req_format_write(wp, "</head><body><blockquote><h4>Change setting successfully!</h4>Your changes have been saved. The router must be rebooted for the changes to take effect.<br> You can reboot now, or you can continue to make other changes and reboot later.\n"); \
	req_format_write(wp, "<form action=/boafrm/formRebootCheck method=POST name='rebootForm'>"); \
	req_format_write(wp, "<input type='hidden' value='%s' name='submit-url'>",url); \
	req_format_write(wp, "<input id='restartNow' type='submit' value='Reboot Now' onclick=\"return true\" />&nbsp;&nbsp;"); \
	req_format_write(wp, "<input id='restartLater' type='button' value='Reboot Later' OnClick=window.location.replace(\"%s\")>", url); \
	req_format_write(wp, "</form></blockquote></body></html>");\
	log_boaform("formRebootCheck", wp);\
}
#  endif

#  define RET_SURVEY_PAGE(pMsg, url, connectOK, wlan_id, isWizard) { \
	extern void log_boaform(char *form,request *);\
	needReboot = 1; \
	if(strlen(url) == 0) \
		strcpy(url,"/wizard.htm"); \
 	req_format_write(wp, "<html><head>"); \
	getIncludeCss(wp);\
	req_format_write(wp, "</head><body><blockquote><h4>%s</h4>", pMsg); \
 	if(isWizard) req_format_write(wp, "Your changes have been saved. The router must be rebooted for the changes to take effect.<br> You can reboot now, or you can continue to make other changes and reboot later.\n"); \
	req_format_write(wp, "<form action=/boafrm/formSiteSurveyProfile method=POST name='rebootSiteSurveyProfileForm'>"); \
	req_format_write(wp, "<input type='hidden' value='%s' name='submit-url'>",url); \
	if(connectOK) req_format_write(wp, "<td><font size=2><b><input type=\"checkbox\" name=wizardAddProfile%d value=\"ON\">&nbsp;&nbsp;Add to Wireless Profile</b></td><br><br>", wlan_id); \
	if(!connectOK) req_format_write(wp, "<input id='restartLater' name='restartLater' type='submit' value='  OK  ' onclick=\"return true\" />&nbsp;&nbsp;"); \
	if(connectOK) req_format_write(wp, "<input id='restartNow' name='restartNow' type='submit' value='Reboot Now' onclick=\"return true\" />&nbsp;&nbsp;"); \
	if(connectOK) req_format_write(wp, "<input id='restartLater' name='restartLater' type='submit' value='Reboot Later' OnClick=window.location.replace(\"%s\");return true>", url); \
	req_format_write(wp, "</form></blockquote></body></html>");\
	log_boaform("formSiteSurveyProfile",wp);\
}

#  define SUCCESS_INFO(info,url){\
	extern void log_boaform(char *form,request *);\
	req_format_write(wp, "<html><head>"); \
	getIncludeCss(wp);\
	req_format_write(wp, "</head><body><blockquote><h4>%s</h4>", info); \
	req_format_write(wp, "<form action=/boafrm/formWeave method=POST name='weaveForm'>"); \
	req_format_write(wp, "<input type='hidden' value='%s' name='submit-url'>",url); \
	req_format_write(wp, "<input type='submit' value='register_success' name='command'>");\
	req_format_write(wp, "</form></blockquote></body></html>");\
	log_boaform("formWeave",wp);\
}

#  define FAIL_INFO(info,url){\
	extern void log_boaform(char *form,request *);\
	req_format_write(wp, "<html><head>"); \
	getIncludeCss(wp);\
	req_format_write(wp, "</head><body><blockquote><h4>%s</h4>", info); \
	req_format_write(wp, "<form action=/boafrm/formWeave method=POST name='weaveForm'>"); \
	req_format_write(wp, "<input type='hidden' value='%s' name='submit-url'>",url); \
	req_format_write(wp, "<input type='submit' value='register_failed' name='command'>");\
	req_format_write(wp, "</form></blockquote></body></html>");\
	log_boaform("formWeave",wp);\
}
# else
#  define OK_MSG(url) { \
	needReboot = 1; \
	if(strlen(url) == 0) \
		strcpy(url,"/wizard.htm"); \
 	req_format_write(wp, "<html><head>"); \
	getIncludeCss(wp);\
	req_format_write(wp, "</head><body><blockquote><h4>Change setting successfully!</h4>Your changes have been saved. The router must be rebooted for the changes to take effect.<br> You can reboot now, or you can continue to make other changes and reboot later.\n"); \
	req_format_write(wp, "<form action=/boafrm/formRebootCheck method=POST name='rebootForm'>"); \
	req_format_write(wp, "<input type='hidden' value='%s' name='submit-url'>",url); \
	req_format_write(wp, "<input id='restartNow' type='submit' value='Reboot Now' onclick=\"return true\" />&nbsp;&nbsp;"); \
	req_format_write(wp, "<input id='restartLater' type='button' value='Reboot Later' OnClick=window.location.replace(\"%s\")>", url); \
	req_format_write(wp, "</form></blockquote></body></html>");\
}

#  define RET_SURVEY_PAGE(pMsg, url, connectOK, wlan_id, isWizard) { \
	needReboot = 1; \
	if(strlen(url) == 0) \
		strcpy(url,"/wizard.htm"); \
	req_format_write(wp, "<html><head>"); \
	getIncludeCss(wp);\
	req_format_write(wp, "</head><body><blockquote><h4>%s</h4>", pMsg); \
 	if(isWizard) req_format_write(wp, "Your changes have been saved. The router must be rebooted for the changes to take effect.<br> You can reboot now, or you can continue to make other changes and reboot later.\n"); \
	req_format_write(wp, "<form action=/boafrm/formSiteSurveyProfile method=POST name='rebootSiteSurveyProfileForm'>"); \
	req_format_write(wp, "<input type='hidden' value='%s' name='submit-url'>",url); \
	if(connectOK) req_format_write(wp, "<td><font size=2><b><input type=\"checkbox\" name=wizardAddProfile%d value=\"ON\">&nbsp;&nbsp;Add to Wireless Profile</b></td><br><br>", wlan_id); \
	if(!connectOK) req_format_write(wp, "<input id='restartLater' name='restartLater' type='submit' value='  OK  ' onclick=\"return true\" />&nbsp;&nbsp;"); \
	if(connectOK) req_format_write(wp, "<input id='restartNow' name='restartNow' type='submit' value='Reboot Now' onclick=\"return true\" />&nbsp;&nbsp;"); \
	if(connectOK) req_format_write(wp, "<input id='restartLater' name='restartLater' type='submit' value='Reboot Later' OnClick=window.location.replace(\"%s\");return true>", url); \
	req_format_write(wp, "</form></blockquote></body></html>");\
}
#  define SUCCESS_INFO(info,url){\
	req_format_write(wp, "<html><head>"); \
	getIncludeCss(wp);\
	req_format_write(wp, "</head><body><blockquote><h4>%s</h4>", info); \
	req_format_write(wp, "<form action=/boafrm/formWeave method=POST name='weaveForm'>"); \
	req_format_write(wp, "<input type='hidden' value='%s' name='submit-url'>",url); \
	req_format_write(wp, "<input type='submit' value='register_sucess' name='command'>");\
	req_format_write(wp, "</form></blockquote></body></html>");\
}

# endif

#else
# define OK_MSG(url) { \
   	req_format_write(wp, "<html><head>"); \
	getIncludeCss(wp);\
   	req_format_write(wp, "</head><body><blockquote><h4>Change setting successfully!</h4>\n"); \
	if (url[0]) req_format_write(wp, "<form><input type=button value=\"  OK  \" OnClick=window.location.replace(\"%s\")></form></blockquote></body></html>", url);\
	else req_format_write(wp, "<form><input type=button value=\"  OK  \" OnClick=window.close()></form></blockquote></body></html>");\
}
#endif

#define OK_MSG1(msg, url) { \
   	req_format_write(wp, "<html><head>"); \
	getIncludeCss(wp);\
   	req_format_write(wp, "</head><body><blockquote><h4>%s</h4>\n", msg); \
	if (url) req_format_write(wp, "<form><input type=button value=\"  OK  \" OnClick=window.location.replace(\"%s\")></form></blockquote></body></html>", url);\
	else req_format_write(wp, "<form><input type=button value=\"  OK  \" OnClick=window.close()></form></blockquote></body></html>");\
}
//Brad for firmware upgrade
#define OK_MSG_FW(msg, url, c, ip) { \
	req_format_write(wp, "<html><head>");\
	getIncludeCss(wp);\
	req_format_write(wp, "<script language=JavaScript><!--\n");\
	req_format_write(wp, "var count = %d;function get_by_id(id){with(document){return getElementById(id);}}\n", c);\
   	req_format_write(wp, "function do_count_down(){get_by_id(\"show_sec\").innerHTML = count\n");\
	req_format_write(wp, "if(count == 0) {parent.location.href='http://%s/home.htm?t='+new Date().getTime(); return false;}\n", ip);\
	req_format_write(wp, "if (count > 0) {count--;setTimeout('do_count_down()',1000);}}");\
	req_format_write(wp, "//-->\n");\
	req_format_write(wp,"</script></head>");\
	req_format_write(wp, "<body onload=\"do_count_down();\"><blockquote><h4>%s</h4>\n", msg);\
	req_format_write(wp, "<P align=left><h4>Please wait <B><SPAN id=show_sec></SPAN></B>&nbsp;seconds ...</h4></P>");\
	req_format_write(wp, "</blockquote></body></html>");\
}
//Brad add end
#define OK_MSG2(msg, msg1, url) { \
	char tmp[200]; \
	sprintf(tmp, msg, msg1); \
	OK_MSG1(tmp, url); \
}

#ifdef WIFI_SIMPLE_CONFIG
# define START_PBC_MSG \
	"Start PBC successfully!<br><br>" \
	"You have to run Wi-Fi Protected Setup in %s within 2 minutes."
# define START_PIN_MSG \
	"Start PIN successfully!<br><br>" \
	"You have to run Wi-Fi Protected Setup in %s within 2 minutes."
# define SET_PIN_MSG \
	"Applied WPS PIN successfully!<br><br>" \
	"You have to run Wi-Fi Protected Setup within 2 minutes."
# define STOP_MSG \
	"Applied WPS STOP successfully!<br>"
/*for WPS2DOTX brute force attack , unlock*/
# define UNLOCK_MSG \
	"Applied WPS unlock successfully!<br>"
#endif

//////////////////////////////////////////////////////////////////////////
#if defined(HTTP_FILE_SERVER_SUPPORTED)
int dump_directory_index(request * wp, int argc, char **argv);
void formusbdisk_uploadfile(request * wp, char *path, char *query);
int Check_directory_status(request * wp, int argc, char **argv);
int Upload_st(request * wp, int argc, char **argv);
# ifdef HTTP_FILE_SERVER_HTM_UI
int dump_httpFileDir_init(request * wp, int argc, char **argv);
int dump_ListHead(request * wp, int argc, char **argv);
int dumpDirectList(request * wp, int argc, char **argv);
int dump_uploadDiv(request * wp, int argc, char **argv);
# endif
#endif

/* Routines exported in fmmgmt.c */
#ifndef HOME_GATEWAY
extern void formSetTime(request * wp, char *path, char *query);
#endif
extern int sysLogList(request * wp, int argc, char **argv);
extern void formPasswordSetup(request * wp, char *path, char *query);
#if defined(CONFIG_USBDISK_UPDATE_IMAGE)
extern void formUploadFromUsb(request * wp, char *path, char *query);
#endif
extern void formUpload(request * wp, char *path, char *query);
#ifdef CONFIG_RTL_WAPI_SUPPORT
extern void formWapiReKey(request * wp, char *path, char *query);
extern void formUploadWapiCert(request * wp, char *path, char *query);
extern void formUploadWapiCertAS0(request * wp, char *path, char *query);
extern void formUploadWapiCertAS1(request * wp, char *path, char *query);
extern void formWapiCertManagement(request * wp, char *path, char *query);
extern void formWapiCertDistribute(request * wp, char *path, char *query);
#endif

#ifdef CONFIG_RTL_802_1X_CLIENT_SUPPORT
extern void formUpload8021xUserCert(request * wp, char *path, char *query);
#endif
#ifdef CONFIG_RTL_ETH_802DOT1X_CLIENT_MODE_SUPPORT
extern void formUploadEth8021xUserCert(request * wp, char *path, char *query);
#endif
#if defined(CONFIG_RTL_ETH_802DOT1X_SUPPORT)
extern void formEthDot1x(request * wp, char *path, char *query);
extern int getEthDot1xList(request * wp, int argc, char **argv);
#endif

#ifdef TLS_CLIENT
extern void formCertUpload(request * wp, char *path, char *query);
#endif
extern void formSaveConfig(request * wp, char *path, char *query);
extern void formUploadConfig(request * wp, char *path, char *query);
extern void formSchedule(request * wp, char *path, char *query);
#if defined(NEW_SCHEDULE_SUPPORT)
extern void formNewSchedule(request * wp, char *path, char *query);
extern int wlSchList(request * wp, int argc, char **argv);
#endif				// #if defined(NEW_SCHEDULE_SUPPORT)

#ifdef GET_LAN_DEV_INFO_SUPPORT
int showClients(request * wp, int argc, char **argv);
#endif
#if defined(CONFIG_RTL_P2P_SUPPORT)
extern void formWiFiDirect(request * wp, char *path, char *query);
int getWifiP2PState(request * wp, int argc, char **argv);
extern void formWlP2PScan(request * wp, char *path, char *query);
int wlP2PScanTbl(request * wp, int argc, char **argv);
#endif				// #if defined(CONFIG_RTL_P2P_SUPPORT)

extern int getScheduleInfo(request * wp, int argc, char **argv);
extern void formStats(request * wp, char *path, char *query);

//=========add for MESH=========
#ifdef CONFIG_RTK_MESH
extern void formMeshStatus(request * wp, char *path, char *query);
#endif
//=========add for MESH=========

extern void formLogout(request * wp, char *path, char *query);
extern void formSysCmd(request * wp, char *path, char *query);
extern int sysCmdLog(request * wp, int argc, char **argv);
extern void formSysLog(request * wp, char *path, char *query);

#ifdef SYS_DIAGNOSTIC
extern void formDiagnostic(request * wp, char *path, char *query);
#endif

#ifdef CONFIG_APP_SMTP_CLIENT
extern void formSmtpClient(request * wp, char *path, char *query);
#endif

#ifdef HOME_GATEWAY
# ifdef DOS_SUPPORT
extern void formDosCfg(request * wp, char *path, char *query);
# endif
extern void formOpMode(request * wp, char *path, char *query);

# if defined(CONFIG_RTL_ULINKER)
extern void formUlkOpMode(request * wp, char *path, char *query);
# endif			//#if defined(CONFIG_RTL_ULINKER)

# if defined(CONFIG_RTL_FLASH_DUAL_IMAGE_ENABLE)
extern void formDualFirmware(request * wp, char *path, char *query);
# endif

#endif
// by sc_yang
extern void formNtp(request * wp, char *path, char *query);
extern void formWizard(request * wp, char *path, char *query);
extern void formPocketWizard(request * wp, char *path, char *query);

#ifdef CONFIG_CPU_UTILIZATION
extern void formCpuUtilization(request * wp, char *path, char *query);
#endif

#ifdef CONFIG_APP_WEAVE
extern void formWeave(request * wp, char *path, char *query);

#endif

#ifdef REBOOT_CHECK
extern void formRebootCheck(request * wp, char *path, char *query);

# if defined(WLAN_PROFILE)
extern void formSiteSurveyProfile(request * wp, char *path, char *query);
# endif			//#if defined(WLAN_PROFILE)

#endif

#if defined(CONFIG_SNMP)
void formSetSNMP(request * wp, char *path, char *query);
#endif

/* Routines exported in fmget.c */
extern int getIndex(request * wp, int argc, char **argv);
extern int getInfo(request * wp, int argc, char **argv);
extern int isConnectPPP();
extern int FirmwareUpgrade(char *upload_data, int upload_len, int is_root, char *buffer);
#ifdef MULTI_WAN_SUPPORT
/*	add by sen_liu 2012.1.13 for webpage multi_wan get mibInfo	*/
extern int getMultiWanIndex(request * wp, int argc, char **argv);
extern int getWanList(request * wp, int argc, char **argv);
extern int getWanStatusList(request * wp, int argc, char **argv);
extern int getWanStatsList(request * wp, int argc, char **argv);
/*	end	*/
# ifdef CONFIG_IPV6
extern int ipv6_getWanList(request * wp, int argc, char **argv);
extern int ipv6_getLanList(request * wp, int argc, char **argv);
# endif
#endif
//add for MESH
//necessarily, no matter MESH is enable or not ,for  add MESH webpage compatible
extern int getModeCombobox(request * wp, int argc, char **argv);
extern int getDHCPModeCombobox(request * wp, int argc, char **argv);

//=========add for MESH=========
#ifdef CONFIG_RTK_MESH
extern void formMeshSetup(request * wp, char *path, char *query);
extern void formMeshProxy(request * wp, char *path, char *query);
extern int formMeshProxyTbl(request * wp, char *path, char *query);
extern int wlMeshNeighborTable(request * wp, int argc, char **argv);
extern int wlMeshRoutingTable(request * wp, int argc, char **argv);
extern int wlMeshProxyTable(request * wp, int argc, char **argv);
extern int wlMeshRootInfo(request * wp, int argc, char **argv);
extern int wlMeshPortalTable(request * wp, int argc, char **argv);
# ifdef _MESH_ACL_ENABLE_
extern void formMeshACLSetup(request * wp, char *path, char *query);
extern int wlMeshAcList(request * wp, int argc, char **argv);
# endif
#endif
//========add for MESH=========
#ifdef FAST_BSS_TRANSITION
extern void multilang(request * wp, int argc, char **argv);
extern void SSID_select(request * wp, int argc, char **argv);
extern void wlFtKhList(request * wp, int argc, char **argv);
#endif
extern void formWlanSetup(request * wp, char *path, char *query);
extern int wlAcList(request * wp, int argc, char **argv);
extern void formWlAc(request * wp, char *path, char *query);
extern void formAdvanceSetup(request * wp, char *path, char *query);
extern int wirelessClientList(request * wp, int argc, char **argv);
extern void formWirelessTbl(request * wp, char *path, char *query);
extern void formWep(request * wp, char *path, char *query);
extern void formWlSiteSurvey(request * wp, char *path, char *query);
extern int wepHandler(request * wp, char *tmpBuf, int wlan_id);
extern int wlanHandler(request * wp, char *tmpBuf, int *mode, int wlan_id);
extern int wpaHandler(request * wp, char *tmpBuf, int wlan_id);
extern void formWlanRedirect(request * wp, char *path, char *query);
#ifdef TLS_CLIENT
extern int certRootList(request * wp, int argc, char **argv);
extern int certUserList(request * wp, int argc, char **argv);
#endif
#if defined(CONFIG_APP_ZIGBEE)
extern int zigbee_dev_list(request * wp, int argc, char **argv);
extern void formZigBee(request * wp, char *path, char *query);
#endif
int wlSiteSurveyTbl(request * wp, int argc, char **argv);
extern void formWlEncrypt(request * wp, char *path, char *query);

extern void formWlWds(request * wp, char *path, char *query);
extern int wlWdsList(request * wp, int argc, char **argv);

#if defined(WLAN_PROFILE)
extern int wlProfileTblList(request * wp, int argc, char **argv);
extern int wlProfileList(request * wp, int argc, char **argv);
#endif				//#if defined(WLAN_PROFILE)

extern void formWdsEncrypt(request * wp, char *path, char *query);
extern int wdsList(request * wp, int argc, char **argv);
#ifdef WLAN_EASY_CONFIG
extern void sigHandler_autoconf(int signo);
extern void formAutoCfg(request * wp, char *path, char *query);
#endif

#ifdef WIFI_SIMPLE_CONFIG
# ifndef WLAN_EASY_CONFIG
extern void sigHandler_autoconf(int signo);
# endif
extern void formWsc(request * wp, char *path, char *query);
#endif

#ifdef MBSSID
extern int getVirtualIndex(request * wp, int argc, char **argv);
extern int getVirtualInfo(request * wp, int argc, char **argv);
extern void formWlanMultipleAP(request * wp, char *path, char *query);
#endif

#ifdef CONFIG_RTL_AIRTIME
extern void formAirtime(request * wp, char *path, char *query);
extern int airTimeList(request * wp, int argc, char **argv);
#endif

#ifdef CONFIG_RTL_BT_CLIENT
extern void formBTBasicSetting(request * wp, char *path, char *query);
extern void formBTClientSetting(request * wp, char *path, char *query);
extern void formBTFileSetting(request * wp, char *path, char *query);
extern void formBTNewTorrent(request * wp, char *path, char *query);
#endif

#ifdef CONFIG_RTL_TRANSMISSION
extern void formTransmissionBT(request * wp, char *path, char *query);
#endif

#ifndef NO_ACTION
extern void run_init_script(char *arg);
# ifdef REBOOT_CHECK
extern void run_init_script_rebootCheck(char *arg);
# endif
#endif

/* Routines exported in fmtcpip.c */
extern void formTcpipSetup(request * wp, char *path, char *query);
extern int isDhcpClientExist(char *name);
extern void formReflashClientTbl(request * wp, char *path, char *query);
extern int dhcpClientList(request * wp, int argc, char **argv);
extern int tcpipLanHandler(request * wp, char *tmpBuf);
extern int dhcpRsvdIp_List(request * wp, int argc, char **argv);
extern int getPid(char *filename);
#if defined(POWER_CONSUMPTION_SUPPORT)
extern int getPowerConsumption(request * wp, int argc, char **argv);
#endif

#if defined(VLAN_CONFIG_SUPPORTED)
extern int getVlanList(request * wp, int argc, char **argv);
extern void formVlan(request * wp, char *path, char *query);
#endif
#if defined(CONFIG_8021Q_VLAN_SUPPORTED)
extern void formVlan(request * wp, char *path, char *query);
extern int getPortList(request * wp, int argc, char **argv);
extern int getWlanValid(request * wp, int argc, char **argv);
extern int getVlanInfo(request * wp, int argc, char **argv);
extern int getVlanTable(request * wp, int argc, char **argv);
extern int getPVidArray(request * wp, int argc, char **argv);
#endif
#if defined(CONFIG_RTL_92D_SUPPORT) || defined(CONFIG_RTL_8881A_SELECTIVE)
extern void formWlanBand2G5G(request * wp, char *path, char *query);
#endif
#ifdef FAST_BSS_TRANSITION
extern void formFt(request * wp, char *path, char *query);
#endif

#ifdef HOME_GATEWAY
# ifdef MULTI_WAN_SUPPORT

extern void formMultiWanListTcpip(request * wp, char *path, char *query);
extern void formMultiWanTcpipSetup(request * wp, char *path, char *query);
#  ifdef CONFIG_IPV6
extern void formIpv6MultiWanListTcpip(request * wp, char *path, char *query);
extern void formIpv6MultiLanListTcpip(request * wp, char *path, char *query);
extern void formIpv6MultiWanTcpipSetup(request * wp, char *path, char *query);
extern void formIpv6MultiLanTcpipSetup(request * wp, char *path, char *query);
#  endif

# else
extern void formWanTcpipSetup(request * wp, char *path, char *query);

# endif
/* Routines exported in fmfwall.c */
extern void formPortFw(request * wp, char *path, char *query);
extern void formFilter(request * wp, char *path, char *query);
extern int portFwList(request * wp, int argc, char **argv);

# ifdef SAMBA_WEB_SUPPORT
extern void formDiskCfg(request * wp, char *path, char *query);
extern int DiskList(request * wp, int argc, char **argv);
extern void formDiskManagementAnon(request * wp, char *path, char *query);
extern void formDiskManagementUser(request * wp, char *path, char *query);
extern void formDiskManagementGroup(request * wp, char *path, char *query);

extern int Storage_DispalyUser(request * wp, int argc, char **argv);
extern int Storage_DispalyGroup(request * wp, int argc, char **argv);
extern int Storage_GetGroupMember(request * wp, int argc, char **argv);

extern void formDiskCreateUser(request * wp, char *path, char *query);
extern void formDiskCreateGroup(request * wp, char *path, char *query);

extern void formDiskEditUser(request * wp, char *path, char *query);
extern void formDiskEditGroup(request * wp, char *path, char *query);

//extern int Storage_CreateFolder(request *wp, int argc, char **argv);
extern int FolderList(request * wp, int argc, char **argv);
extern int ShareFolderList(request * wp, int argc, char **argv);

extern void formDiskCreateShare(request * wp, char *path, char *query);
extern void formDiskCreateFolder(request * wp, char *path, char *query);
extern int Storage_GeDirRoot(request * wp, int argc, char **argv);

extern int GroupEditName(request * wp, int argc, char **argv);
extern int UserEditName(request * wp, int argc, char **argv);
extern int StorageGetFolderPath(request * wp, int argc, char **argv);
extern int StorageGetAccount(request * wp, int argc, char **argv);
extern int PartitionsList(request * wp, int argc, char **argv);
extern void formDiskFormat(request * wp, char *path, char *query);
extern int getDiskInfo(request * wp, int argc, char **argv);
extern int PartitionList(request * wp, int argc, char **argv);
extern void formDiskPartition(request * wp, char *path, char *query);
# endif

extern int portFilterList(request * wp, int argc, char **argv);
extern int ipFilterList(request * wp, int argc, char **argv);
extern int macFilterList(request * wp, int argc, char **argv);
extern int urlFilterList(request * wp, int argc, char **argv);
extern void formDMZ(request * wp, char *path, char *query);
# if defined(CONFIG_RTK_VLAN_WAN_TAG_SUPPORT)
extern void formVlanWAN(request * wp, char *path, char *query);
# endif
extern void formTriggerPort(request * wp, char *path, char *query);
//extern int triggerPortList(request *wp, int argc, char **argv);
extern int tcpipWanHandler(request * wp, char *tmpBuf, int *dns_changed);
/* Routines exported in fmroute.c */
# ifdef ROUTE_SUPPORT
extern void formRoute(request * wp, char *path, char *query);
extern int staticRouteList(request * wp, int argc, char **argv);
extern int kernelRouteList(request * wp, int argc, char **argv);
#  ifdef RIP6_SUPPORT
extern int kernelRoute6List(request * wp, int argc, char **argv);
#  endif
# endif

# ifdef GW_QOS_ENGINE
extern int qosList(request * wp, int argc, char **argv);
extern void formQoS(request * wp, char *path, char *query);
# endif

# ifdef QOS_BY_BANDWIDTH
extern int ipQosList(request * wp, int argc, char **argv);
extern void formIpQoS(request * wp, char *path, char *query);
extern int l7QosList(request * wp, int argc, char **argv);
# endif

#endif

#ifdef HOME_GATEWAY
/* Routine exported in fmddns.c */
extern void formDdns(request * wp, char *path, char *query);
extern void formOpenvpn(request * wp, char *path, char *query);
extern void formSaveOpenvpnClientConfig(request * wp, char *path, char *query);
#endif

#ifdef HOME_GATEWAY
# ifdef VPN_SUPPORT
/* Routines exported in fmvpn.c */
extern void formVpnSetup(request * wp, char *path, char *query);
extern void formVpnConn(request * wp, char *path, char *query);
//extern int vpnStatList(request *wp, int argc, char **argv);
extern int vpnConnList(request * wp, int argc, char **argv);
extern int vpnRsaList(request * wp, int argc, char **argv);
extern int vpnShowLog(request * wp, int argc, char **argv);
extern void formVpnLog(request * wp, char *path, char *query);
extern int getVpnTblIdx(void);
extern void len2Mask(int len, char *mask);
extern int mask2Len(char *buf);
extern int getVpnKeyMode(void);
extern int getConnStat(char *in_connName);
# endif
# ifdef CONFIG_IPV6
extern void formRadvd(request * wp, char *path, char *query);
#  ifdef CONFIG_APP_RADVD_WAN
extern void formRadvd_wan(request * wp, char *path, char *query);
#  endif
extern void formDnsv6(request * wp, char *path, char *query);
extern void formDhcpv6s(request * wp, char *path, char *query);
extern void formIPv6Addr(request * wp, char *path, char *query);
extern void formIpv6Setup(request * wp, char *path, char *query);
extern void formTunnel6(request * wp, char *path, char *query);
extern uint32 getIPv6Info(request * wp, int argc, char **argv);
extern uint32 getIPv6WanInfo(request * wp, int argc, char **argv);
extern int getIPv6Status(request * wp, int argc, char **argv);
extern int getIPv6BasicInfo(request * wp, int argc, char **argv);
#  ifdef CONFIG_MAP_E_SUPPORT
extern void formMapE(request * wp, char *path, char *query);
#  endif
# endif
#endif
#if defined(WLAN_PROFILE)
extern int getWlProfileInfo(request * wp, int argc, char **argv);
#endif
extern void formStaticDHCP(request * wp, char *path, char *query);

/*+++++added by Jack for Tr-069 configuration+++++
Routines exported in fmtr069.c */
#ifdef CONFIG_APP_TR069
extern void formTR069Config(request * wp, char *path, char *query);
extern int saveTR069Config(request * wp, char *path, char *query);
extern int TR069ConPageShow(request * wp, int argc, char **argv);
# ifdef _CWMP_WITH_SSL_
extern int ShowMNGCertTable(request * wp);
extern void formTR069CACert(request * wp, char *path, char *query);
extern void formTR069CPECert(request * wp, char *path, char *query);
# endif			/*CONFIG_USER_CWMP_WITH_MATRIXSSL */
#endif				/*CONFIG_APP_TR069 */

#ifdef VOIP_SUPPORT
int asp_voip_getInfo(request * wp, int argc, char **argv);
int asp_voip_GeneralGet(request * wp, int argc, char **argv);
int asp_voip_DialPlanGet(request * wp, int argc, char **argv);
int asp_voip_ToneGet(request * wp, int argc, char **argv);
int asp_voip_RingGet(request * wp, int argc, char **argv);
int asp_voip_OtherGet(request * wp, int argc, char **argv);
int asp_voip_ConfigGet(request * wp, int argc, char **argv);
int asp_voip_FwupdateGet(request * wp, int argc, char **argv);
int asp_voip_FxoGet(request * wp, int argc, char **argv);
int asp_voip_NetGet(request * wp, int argc, char **argv);
void asp_voip_GeneralSet(request * wp, char *path, char *query);
void asp_voip_DialPlanSet(request * wp, char *path, char *query);
void asp_voip_ToneSet(request * wp, char *path, char *query);
void asp_voip_RingSet(request * wp, char *path, char *query);
void asp_voip_OtherSet(request * wp, char *path, char *query);
void asp_voip_ConfigSet(request * wp, char *path, char *query);
void asp_voip_FwSet(request * wp, char *path, char *query);
void asp_voip_IvrReqSet(request * wp, char *path, char *query);
void asp_voip_FxoSet(request * wp, char *path, char *query);
void asp_voip_NetSet(request * wp, char *path, char *query);
# ifdef CONFIG_RTK_VOIP_SIP_TLS
int asp_voip_TLSGetCertInfo(request * wp, int argc, char **argv);
void asp_voip_TLSCertUpload(request * wp, char *path, char *query);
# endif
#endif
/*-----end-----*/

/* variables exported in main.c */
extern char *WAN_IF;
extern char *BRIDGE_IF;
extern char *ELAN_IF;
extern char *ELAN2_IF;
extern char *ELAN3_IF;
extern char *ELAN4_IF;

#if defined(HOME_GATEWAY)
extern char *PPPOE_IF;

#else
extern char *BRIDGE_IF;
extern char *ELAN_IF;
#endif
extern char WLAN_IF[];
extern int wlan_num;
#ifdef MBSSID
extern int vwlan_num;
extern int mssid_idx;
#endif

#ifdef __DAVO__
struct ej_handler {
	char *pattern;
	int (*output) (request * wp, int argc, char **argv, void *data);
	void *data;
};

# define __string(_x) #_x
# define __xstring(_x) __string(_x)
# define EJH_LABEL_DEFN(_label)	_label
# define EJARC_P2ALIGNMENT	2
# define EJSECTNAM	".rodata.ytable.ej_handler"
# define EJXSECTNAM	".rodata.xtable.ej_handler"

/* getInfo */
# define EJH_ENTRY(name, func) \
static const struct ej_handler ej ##name \
__attribute__ ((section ( EJSECTNAM ".2." #name))) \
__attribute__ ((__used__)) = { #name, func, NULL }

# define EJH_ENTRY_DATA(name, func, data) \
static const struct ej_handler ej ##name \
__attribute__ ((section ( EJSECTNAM ".2." #name))) \
__attribute__ ((__used__)) = { #name, func, (void *)data }

/* getIndex */
# define EJX_ENTRY(name, func) \
static const struct ej_handler ejx ##name \
__attribute__ ((section ( EJXSECTNAM ".2." #name))) \
__attribute__ ((__used__)) = { #name, func, NULL }

# define EJX_ENTRY_DATA(name, func, data) \
static const struct ej_handler ejx ##name \
__attribute__ ((section ( EJXSECTNAM ".2." #name))) \
__attribute__ ((__used__)) = { #name, func, (void *)data }

extern struct ej_handler *ej_find_handler(char *func);
extern struct ej_handler *ej_find_index(char *func);

extern void formFtpUpload(request * wp, char *path, char *query);
extern void formautoupgrade(request * wp, char *path, char *query);
extern int showAutoUpState(request * wp, int argc, char **argv);
extern void formPortMirror(request * wp, char *path, char *query);
extern void formSNMP(request * wp, char *path, char *query);
extern void formLogin(request * wp, char *path, char *query);
extern void formDiagnostic_ping(request * wp, char *path, char *query);
extern int captcha_img(request * wp, int argc, char **argv);
extern void formBroadcastStormCtrl(request * wp, char *path, char *query);
extern void formPortSetup(request * wp, char *path, char *query);
extern void formWebAcl(request * wp, char *path, char *query);
extern void formConnectVoIP(request * wp, char *path, char *query);
extern int showConnectVoIPtbl(request * wp, int argc, char **argv);
extern void formMacFilter(request * wp, char *path, char *query);
extern void formAclSetup(request * wp, char *path, char *query);
extern int show_acltbl(request * wp, int argc, char **argv);
extern void formQosQue(request * wp, char *path, char *query);
extern void formRemark(request * wp, char *path, char *query);
extern void formWanIpRenewal(request * wp, char *path, char *query);
extern int print_wme_dscp(request * wp, int argc, char **argv);
extern void formWlwmm(request * wp, char *path, char *query);
extern int show_ExceptionLog(request * wp, int argc, char **argv);
extern void formMfgTest(request *wp, char *path, char *query);
#endif				/* __DAVO__ */
void translate_control_code(char *buffer);
extern int getOneDhcpClient(char **ppStart, unsigned long *size, char *ip, char *mac, char *liveTime, time_t now);
extern void get_mono(struct timespec *ts);
extern int check_dup_static_info(unsigned char *webmac, struct in_addr webIp);
#endif				// _INCLUDE_APFORM_H
