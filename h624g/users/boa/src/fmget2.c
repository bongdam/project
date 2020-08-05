/*
 *      Web server handler routines for get info and index (getinfo(), getindex())
 *
 *      Authors: David Hsu	<davidhsu@realtek.com.tw>
 *
 *      $Id: fmget.c,v 1.51 2009/09/04 07:06:05 keith_huang Exp $
 *
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <sys/sysinfo.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "boa.h"
#include "asp_page.h"
#include "apmib.h"
#include "apform.h"
#include "utility.h"
#include "aspvar.h"
#include <brdio.h>
#include <bcmnvram.h>
#include <dvflag.h>
#include "dv_make_uniqcookie.h"

#define FW_VERSION	fwVersion

//#define SDEBUG(fmt, args...) printf("[%s %d]"fmt,__FUNCTION__,__LINE__,## args)
#define SDEBUG(fmt, args...) {}

#ifdef CONFIG_RTL_WAPI_SUPPORT
#define CA_CERT "/var/myca/CA.cert"
//#define AS_CER "/web/as.cer"
#define CA_CER "/web/ca.cer"
#define WAPI_CERT_CHANGED		"/var/tmp/certSatusChanged"
#endif

extern char *fwVersion;	// defined in version.c
#ifdef HOME_GATEWAY
#ifdef VPN_SUPPORT
extern int getIpsecInfo(IPSECTUNNEL_T *entry);
#endif
#endif

#ifdef MULTI_PPPOE

int PPPoE_Number;
char  ppp_iface[32];
#endif
static COUNTRY_IE_ELEMENT countryIEArray[] =
{
	/*
	 format: countryNumber | CountryCode(A2) | support (5G) A band? | support (2.4G)G band? |
	*/
	{8,"AL ",   3, 3, "ALBANIA"},
	{12,"DZ ",  3, 3, "ALGERIA"},
	{32,"AR ",  3, 3, "ARGENTINA"},
	{51,"AM ",  3, 3, "ARMENIA"},
	{36,"AU ",  3, 3, "AUSTRALIA"},
	{40,"AT ",  3, 3, "AUSTRIA"},
	{31,"AZ ",  3, 3, "AZERBAIJAN"},
	{48,"BH ",  3, 3, "BAHRAIN"},
	{112,"BY",  3, 3, "BELARUS"},
	{56,"BE ",  3, 3, "BELGIUM"},
	{84,"BZ ",  3, 3, "BELIZE"},
	{68,"BO ",  3, 3, "BOLIVIA"},
	{76,"BR ",  3, 3, "BRAZIL"},
	{96,"BN ",  3, 3, "BRUNEI"},
	{100,"BG ", 3, 3, "BULGARIA"},
	{124,"CA ", 1, 1, "CANADA"},
	{152,"CL ", 3, 3, "CHILE"},
	{156,"CN ",13,13, "CHINA"},
	{170,"CO ", 1, 1, "COLOMBIA"},
	{188,"CR ", 3, 3, "COSTA RICA"},
	{191,"HR ", 3, 3, "CROATIA"},
	{196,"CY ", 3, 3, "CYPRUS"},
	{203,"CZ ", 3, 3, "CZECH REPUBLIC"},
	{208,"DK ", 3, 3, "DENMARK"},
	{214,"DO ", 1, 1, "DOMINICAN REPUBLIC"},
	{218,"EC ", 3, 3, "ECUADOR"},
	{818,"EG ", 3, 3, "EGYPT"},
	{222,"SV ", 3, 3, "EL SALVADOR"},
	{233,"EE ", 3, 3, "ESTONIA"},
	{246,"FI ", 3, 3, "FINLAND"},
	{250,"FR ", 3, 3, "FRANCE"},
	{268,"GE ", 3, 3, "GEORGIA"},
	{276,"DE ", 3, 3, "GERMANY"},
	{300,"GR ", 3, 3, "GREECE"},
	{320,"GT ", 1, 1, "GUATEMALA"},
	{340,"HN ", 3, 3, "HONDURAS"},
	{344,"HK ", 3, 3, "HONG KONG"},
	{349,"HU ", 3, 3, "HUNGARY"},
	{352,"IS ", 3, 3, "ICELAND"},
	{356,"IN ", 3, 3, "INDIA"},
	{360,"ID ", 3, 3, "INDONESIA"},
	{364,"IR ", 3, 3, "IRAN"},
	{372,"IE ", 3, 3, "IRELAND"},
	{376,"IL ", 7, 7, "ISRAEL"},
	{380,"IT ", 3, 3, "ITALY"},
	{392,"JP ", 6, 6, "JAPAN"},
	{400,"JO ", 3, 3, "JORDAN"},
	{398,"KZ ", 3, 3, "KAZAKHSTAN"},
	{410,"KR ", 3, 3, "NORTH KOREA"},
	{408,"KP ", 3, 3, "KOREA REPUBLIC"},
	{414,"KW ", 3, 3, "KUWAIT"},
	{428,"LV ", 3, 3, "LATVIA"},
	{422,"LB ", 3, 3, "LEBANON"},
	{438,"LI ", 3, 3, "LIECHTENSTEIN"},
	{440,"LT ", 3, 3, "LITHUANIA"},
	{442,"LU ", 3, 3, "LUXEMBOURG"},
	{446,"MO ", 3, 3, "CHINA MACAU"},
	{807,"MK ", 3, 3, "MACEDONIA"},
	{458,"MY ", 3, 3, "MALAYSIA"},
	{484,"MX ", 1, 1, "MEXICO"},
	{492,"MC ", 3, 3, "MONACO"},
	{504,"MA ", 3, 3, "MOROCCO"},
	{528,"NL ", 3, 3, "NETHERLANDS"},
	{554,"NZ ", 3, 3, "NEW ZEALAND"},
	{578,"NO ", 3, 3, "NORWAY"},
	{512,"OM ", 3, 3, "OMAN"},
	{586,"PK ", 3, 3, "PAKISTAN"},
	{591,"PA ", 1, 1, "PANAMA"},
	{604,"PE ", 3, 3, "PERU"},
	{608,"PH ", 3, 3, "PHILIPPINES"},
	{616,"PL ", 3, 3, "POLAND"},
	{620,"PT ", 3, 3, "PORTUGAL"},
	{630,"PR ", 1, 1, "PUERTO RICO"},
	{634,"QA ", 3, 3, "QATAR"},
	{642,"RA ", 3, 3, "ROMANIA"},
	{643,"RU ",12,12, "RUSSIAN"},
	{682,"SA ", 3, 3, "SAUDI ARABIA"},
	{702,"SG ", 3, 3, "SINGAPORE"},
	{703,"SK ", 3, 3, "SLOVAKIA"},
	{705,"SI ", 3, 3, "SLOVENIA"},
	{710,"ZA ", 3, 3, "SOUTH AFRICA"},
	{724,"ES ", 3, 3, "SPAIN"},
	{752,"SE ", 3, 3, "SWEDEN"},
	{756,"CH ", 3, 3, "SWITZERLAND"},
	{760,"SY ", 3, 3, "SYRIAN ARAB REPUBLIC"},
	{158,"TW ",11,11, "TAIWAN"},
	{764,"TH ", 3, 3, "THAILAND"},
	{780,"TT ", 3, 3, "TRINIDAD AND TOBAGO"},
	{788,"TN ", 3, 3, "TUNISIA"},
	{792,"TR ", 3, 3, "TURKEY"},
	{804,"UA ", 3, 3, "UKRAINE"},
	{784,"AE ", 3, 3, "UNITED ARAB EMIRATES"},
	{826,"GB ", 3, 3, "UNITED KINGDOM"},
	{840,"US ", 1, 1, "UNITED STATES"},
	{858,"UY ", 3, 3, "URUGUAY"},
	{860,"UZ ", 1, 1, "UZBEKISTAN"},
	{862,"VE ", 3, 3, "VENEZUELA"},
	{704,"VN ", 3, 3, "VIET NAM"},
	{887,"YE ", 3, 3, "YEMEN"},
	{716,"ZW ", 3, 3, "ZIMBABWE"},
};

static REG_DOMAIN_TABLE_ELEMENT_T Bandtable_2dot4G[]={
		{0, 0,  ""},
		{1, 11, "FCC"},			//FCC
		{2, 11, "IC"},			//IC
		{3, 13, "ETSI"},			//ETSI world
		{4, 13,  "SPAIN"},		//SPAIN
		{5, 4, "FRANCE"},		//FRANCE
		{6, 14, "MKK"},			//MKK , Japan
		{7, 11,  "ISRAEL"},			//ISRAEL
		{8, 14,  "MKK1"},
		{9, 14,  "MKK2"},
		{10,14,  "MKK3"},
		{11,11,  "NCC"},  //NCC (Taiwan)
		{12,13,  "RUSSIAN"},
		{13,13,  "CN "},
		{14,14,  "Global"},
		{15,13,  "World_wide"},
		{16,14,"Test"}
};

static REG_DOMAIN_TABLE_ELEMENT_T Bandtable_5G[]={

		{0, 1 ,""},
		{1, 20 ,"FCC"},
		{2, 12 ,"IC"},
		{3, 19 ,"ETSI"},
		{4, 3 ,"SPAIN"},
		{5, 3 ,"FRANCE"},
		{6, 19 ,"MKK"},
		{7, 19 ,"ISRAEL"},
		{8, 1 ,"MKK1"},
		{9, 1 ,"MKK2"},
		{10, 2 ,"MKK3"},
		{11, 15 ,"NCC"},
		{12, 16 ,"RUSSIAN"},
		{13, 13 ,"CN "},
		{14, 20 ,"GLOBAL"},
		{15, 10,"World_wide"},
		{16, 4,"Test "},
		{17, 1 ,"5M10M"}
};


#if defined(CONFIG_DOMAIN_NAME_QUERY_SUPPORT)
unsigned char WaitCountTime=1;
#endif

#ifdef REBOOT_CHECK
char okMsg[300]={0};
char lastUrl[100]={0};
int countDownTime = 40;
int needReboot = 0;
int run_init_script_flag = 0;
#endif

// added by rock /////////////////////////////////////////
#include <regex.h>
#ifdef VOIP_SUPPORT
#include "web_voip.h"
#endif
void translate_control_code_sprintf(char *buffer)
{
	char tmpBuf[200], *p1 = buffer, *p2 = tmpBuf;


	while (*p1) {
		if (*p1 == '%') {
			memcpy(p2, "%%", 2);
			p2 += 2;
		}
		else
			*p2++ = *p1;
		p1++;
	}
	*p2 = '\0';

	strcpy(buffer, tmpBuf);
}

/////////////////////////////////////////////////////////////////////////////
void translate_control_code(char *buffer)
{
	char tmpBuf[200], *p1 = buffer, *p2 = tmpBuf;


	while (*p1) {
		if (*p1 == '"') {
			memcpy(p2, "&quot;", 6);
			p2 += 6;
		}
		else if (*p1 == '\x27') {
			memcpy(p2, "&#39;", 5);
			p2 += 5;
		}
		else if (*p1 == '\x5c') {
			memcpy(p2, "&#92;", 5);
			p2 += 5;
		}
		else if (*p1 == '\x3c') {
			memcpy(p2, "&#60;", 5);
			p2 += 5;
		}
		else if (*p1 == '\x3e') {
			memcpy(p2, "&#62;", 5);
			p2 += 5;
		}
		else
			*p2++ = *p1;
		p1++;
	}
	*p2 = '\0';

	strcpy(buffer, tmpBuf);
}

#ifdef WIFI_SIMPLE_CONFIG
static void convert_bin_to_str(unsigned char *bin, int len, char *out)
{
	int i;
	char tmpbuf[10];

	out[0] = '\0';

	for (i=0; i<len; i++) {
		sprintf(tmpbuf, "%02x", bin[i]);
		strcat(out, tmpbuf);
	}
}
#endif

/////////////////////////////////////////////////////////////////////////////
#ifdef MULTI_PPPOE

void checkwan(char *waninfo)
{
	DHCP_T dhcp;
	apmib_get( MIB_WAN_DHCP, (void *)&dhcp);
	if(dhcp == PPPOE)
	{
		FILE *pF;
		int num;
		char Name[32];
		if(!strcmp(waninfo,"first"))
			PPPoE_Number = 1;
		else if(!strcmp(waninfo,"second"))
			PPPoE_Number = 2;
		else if(!strcmp(waninfo,"third"))
			PPPoE_Number = 3;
		else if(!strcmp(waninfo,"forth"))
			PPPoE_Number = 4;
		if((pF=fopen("/etc/ppp/ppp_order_info","r+"))==NULL){
			printf("[%s],[%d]Cannot open this file\n",__FUNCTION__,__LINE__);
			return 0;
		}
		while(fscanf(pF,"%d--%s",&num,Name) > 0 ){
			if(PPPoE_Number == num)
				strcpy(ppp_iface,Name);
		}

	}
}

#endif

#ifdef __DAVO__
#define IS_SPECIAL(b) ((b=='\"') || (b=='\'') || (b=='\\'))
inline void escape_special(char *dst, char *src, int dstlen)
{
	int i, j;
	for (i=0, j=0; i<strlen(src); i++, j++) {
		if (IS_SPECIAL(src[i]))
			dst[j++]='\\';
		dst[j]=src[i];
	}
	dst[j]='\0';
}

static int pause_status(int phyid, int tx)
{
	char name[24], buf[80];
	const char *p = (tx) ? "-txpause" : "-rxpause";

	sprintf(name, "x_port_%d_config", phyid);
	nvram_get_r_def(name, buf, sizeof(buf), "up_auto_-rxpause_-txpause");
	return (strstr(buf, p)) ? 0 : 1;
}

void get_modelname(char *model)
{
	yfcat("/etc/version", "%s", model);
}

void get_firmVersion(char *version)
{
	yfcat("/etc/version", "%*s %s", version);
}

static int get_phypot(int hexport)
{
	int i;

	for (i=0; i< 5 ; i++) {
		if (hexport & (0x1 <<i))
			return i;
	}
	return -1;
}

int get_mirror_port(int *from, int *to)
{
	FILE *fp;
	char buf[256];
	int i = 0;
	int argc;
	char *argv[12];

	*from = 0; *to = 0;
	if ( (fp=fopen("/proc/rtl865x/mirrorPort", "r")) ) {
		for (i = 0; fgets(buf, sizeof(buf), fp)!=NULL ; i++) {
			if ( i == 2 || i == 4) {
				if ( (argc = parse_line(buf, argv, 12, " ,:\\\r\n")) > 2 ) {
					if (i == 2) {//FROM
						*from = get_phypot(strtoul(argv[2], NULL, 16));
					} else { //TO
						*to = get_phypot(strtoul(argv[2], NULL, 16));
					}
				}
			}
		}
		fclose(fp);
	}
	return (*from >= 0 && *to >= 0);
}

static int handle_dvport_mirror(request *wp, char *buffer, char *name)
{
	int from;
	int to;
	int mode;

	mode = get_mirror_port(&from, &to);
	if (strcmp(name, "dvport_mirror_enable")==0) {
		sprintf(buffer, "%d", mode);
	} else if (strcmp(name, "dvport_mirror_from")==0) {
		sprintf(buffer, "%d", (from < 0)? 0:from);
	} else if (strcmp(name, "dvport_mirror_to")==0) {
		sprintf(buffer, "%d", (to < 0)? 4: to);
	} else {
		return 0;
	}
	return req_format_write(wp, buffer);
}

#endif

#ifdef __DAVO__
static int handle_igmp_block_table(int port, char* name)
{
	FILE *fp;
	int i, enable=0, port_status=0, thresh=60, period=50, relay=0, drop=0;
	int value=0;

	fp = fopen("/proc/dv_igmp_block", "r");
	if(fp){
		fscanf(fp, "%d\n", &enable);
		for(i=0; i<port; i++){
			fscanf(fp, "%d %d %d %d %d\n", &port_status, &period, &thresh, &relay, &drop);
		}
		fclose(fp);
	}

	if(!strcmp(name,"igmp_block_enabled"))
		return enable;
	else if(!strcmp(name,"igmp_thresh_hold_value"))
		return thresh;
	else if(!strcmp(name,"igmp_block_period_value"))
		return period;

	return value;
}
#endif


/*-----------------------------------------------------------------------------
 * getInfo2
 *-----------------------------------------------------------------------------*/
#ifdef CONFIG_APP_TR069
#define TR069_NOJS_MENU_STR "document.write('"\
    "<tr><td><b>cwmp_tr069_menu</b></td></tr>"\
    "<tr><td><a href=\"skb_tr069config.htm\" target=\"view\">TR-069 config</a></td></tr>"\
    "')"
#ifdef CONFIG_IPV6
#define TR069_IPFILTER_MENU_STR	"document.write('"\
    "<tr><td><a href=\"skb_ip6filter.htm\" target=\"view\">IP Filter</a></td></tr>"\
    "')"
#define TR069_PORTFILTER_MENU "document.write('"\
    "<tr><td><a href=\"skb_portfilter6.htm\" target=\"view\">Port Filter</a></td></tr>"\
    "')"
#else
#define TR069_IPFILTER_MENU_STR "document.write('"\
    "<tr><td><a href=\"skb_ipfilter.htm\" target=\"view\">IP Filter</a></td></tr>"\
    "')"
#endif
#define TR069_PORTFILTER_MENU "document.write('"\
    "<tr><td><a href=\"skb_portfilter.htm\" target=\"view\">Port Filter</a></td></tr>"\
    "')"
#endif

#ifdef __DAVO__
static int pvar_getinfo_dv_port_mirror(request *wp, int argc, char **argv, struct aspvar *v)
{
    char buffer[16] = "";
    yexecl(">/tmp/m_setting", "/bin/mirror print");
    yfcat("/tmp/m_setting", "%s", buffer);
    unlink("/tmp/m_setting");
    return req_format_write(wp, buffer);
}

static int pvar_getinfo_snmp_com_check(request *wp, int argc, char **argv, struct aspvar *v)
{
    const char *name = v->name;
    char buffer[16] = "";

    if (!strcmp(name, "snmp_com1_check"))
	{
		nvram_get_r_def("x_SNMP_COM1", buffer, sizeof(buffer), "1_0");
		if (buffer[0]=='0')
			return 0;
		else
			return req_format_write(wp, "checked");
	}
	else if (!strcmp(name, "snmp_com2_check"))
	{
		nvram_get_r_def("x_SNMP_COM2", buffer, sizeof(buffer), "1_1");
		if (buffer[0]=='0')
			return 0;
		else
			return req_format_write(wp, "checked");
	}

    return 0;
}

static int pvar_getinfo_repeater_interface(request *wp, int argc, char **argv, struct aspvar *v)
{
    char buffer[4]= "";

    nvram_get_r_def("REPEATER_ENABLED2", buffer, sizeof(buffer), "0");
    if (atoi(buffer) == 1) {
        return req_format_write(wp, "%s", "2.4G");
    } else {
        nvram_get_r_def("REPEATER_ENABLED1", buffer, sizeof(buffer), "0");
        if (atoi(buffer) == 1) {
            return req_format_write(wp, "%s", "5G");
        }
        return req_format_write(wp, "%s", "2.4G");
    }
}

static int pvar_getinfo_davoqos(request *wp, int argc, char **argv, struct aspvar *v)
{
    int i,j;
    char namebuf[64] = "";
    char buffer[64] = "";
    char *p;
    const char *name = v->name;

    if (!strcmp(name, "qos_remark_js"))
    {
        int pbs;

        nvram_get_r_def("x_QOS_RM_1Q", buffer, sizeof(buffer), "0_0_1_2_3_4_5_6_7");

        if ((p = strtok(buffer, "_"))==NULL)
            p = "0";

        pbs = strtoul(p, NULL, 16);
        req_format_write(wp, "q_use_tag=%s;\n", pbs?"1":"0");

        for (i=0;i<5;i++) {
            req_format_write(wp, "q_tag_p[%d]=%s;\n", i, (pbs&(0x01<<i))?"1":"0");
        }
        for (i=0;i<8;i++) {
            if ((p = strtok(NULL, "_"))==NULL)
                p = "0";

            req_format_write(wp, "q_tag[%d]=%s;\n", i, p);
        }

        nvram_get_r_def("x_QOS_RM_DSCP", buffer, sizeof(buffer), "0_0_0_0_0_46_46_46_46");

        if ((p = strtok(buffer, "_"))==NULL)
            p = "0";

        pbs = strtoul(p, NULL, 16);
        req_format_write(wp, "q_use_dscp=%s;\n", pbs?"1":"0");

        for (i=0;i<5;i++) {
            req_format_write(wp, "q_dscp_p[%d]=%s;\n", i, (pbs&(0x01<<i))?"1":"0");
        }
        for (i=0;i<8;i++) {
            if ((p = strtok(NULL, "_"))==NULL)
                p = "0";

            req_format_write(wp, "q_dscp[%d]=%s;\n", i, p);
        }
    } else if ( !strcmp(name, "qosQ_init_js")) {
        for (i=0;i<5;i++) {
            sprintf(namebuf, "x_QOS_ENABLE_%d", i);
            nvram_get_r_def(namebuf, buffer, sizeof(buffer), "0");
            req_format_write(wp, "q_enable[%d]=%s;\n", i, buffer);
            sprintf(namebuf, "x_QOS_RATE_ENABLE_%d", i);
            nvram_get_r_def(namebuf, buffer, sizeof(buffer), "0");
            req_format_write(wp, "r_enable[%d]=%s;\n", i, buffer);
            sprintf(namebuf, "x_QOS_RATE_I_%d", i);
            nvram_get_r_def(namebuf, buffer, sizeof(buffer), "0");
            req_format_write(wp, "q_inrate[%d]=%s;\n", i, buffer);
            sprintf(namebuf, "x_QOS_RATE_O_%d", i);
            nvram_get_r_def(namebuf, buffer, sizeof(buffer), "0");
            req_format_write(wp, "q_outrate[%d]=%s;\n", i, buffer);
            for (j=0;j<4;j++) {
                sprintf(namebuf, "x_QOS_Q_%d_%d", i, j);
                nvram_get_r_def(namebuf, buffer, sizeof(buffer), "S_0_1");
                if ((p=strtok(buffer, "_"))==NULL)
                    p = "S";
                req_format_write(wp, "q_qtype[%d][%d]=\"%s\";\n", i, j, toupper(p[0])=='W'?"WFQ":"SPQ");
                if ((p=strtok(NULL, "_"))==NULL)
                    p = "0";
                req_format_write(wp, "q_qrate[%d][%d]=%s;\n", i, j, p);
                if ((p=strtok(NULL, "_"))==NULL)
                    p = "1";
                req_format_write(wp, "q_qweight[%d][%d]=%s;\n", i, j, p);
            }
        }
    }

    return 0;
}
#endif

static int pvar_getinfo_devname(request *wp, int argc, char **argv, struct aspvar *v)
{
    char buffer[32] = "";
    get_modelname(buffer);
    return req_format_write(wp, "%s", buffer);
}

static int pvar_getinfo_saveConfig(request *wp, int argc, char **argv, struct aspvar *v)
{
#ifdef SHRINK_INIT_TIME
    save_cs_to_file();
#endif
    return 0;
}

static int pvar_getinfo_prefix_used(request *wp, int argc, char **argv, struct aspvar *v)
{
    char buffer[4] = "";
    int prefix_use = 0;
    prefix_use = atoi(nvram_get_r_def("x_autoup_prefix_use", buffer, sizeof(buffer), "1"));
    return req_format_write(wp, "%s", (prefix_use)?"true":"false");
}


static int pvar_getinfo_get_wlan_name(request *wp, int argc, char **argv, struct aspvar *v)
{
    const char *name = v->name;
    int index = 0;
    char buffer[128] = "";
	char wlan_name[80] = "";
    char *def;

    if (!strcmp(name, "wlan_max_conn")) {
        get_wlan_name(wlan_name, 0, "max_conn");
        nvram_get_r_def(wlan_name, buffer, sizeof(buffer), "127");
        return req_format_write(wp, "%s", buffer);
    } else if(!strcmp(name, "wlan_rssi_threshold")) {
        get_wlan_name(wlan_name, 0, "rssi_threshold");
        nvram_get_r_def(wlan_name, buffer, sizeof(buffer), "0");
        return req_format_write(wp, "%s", buffer);
    } else if(!strcmp(name, "x_WLS_REDIR_ENABLE")) {
		get_wlan_name(wlan_name, 0, "WLS_REDIR_ENABLE");
		nvram_get_r_def(wlan_name, buffer, sizeof(buffer), "0");
		return req_format_write(wp, "%s", buffer);
	} else if(strstr(name, "_max_conn")) {
        sscanf(name, "wlan_va%d_max_conn", &index);
        get_wlan_name(wlan_name, index+1, "max_conn");
        nvram_get_r_def(wlan_name, buffer, sizeof(buffer), "127");
        return req_format_write(wp, "%s", buffer);
    } else if(strstr(name, "_rssi_threshold")) {
        sscanf(name, "wlan_va%d_rssi_threshold", &index);
        get_wlan_name(wlan_name, index+1, "rssi_threshold");

        if (index == 1)
            def = "75";
        else
            def = "0";

        nvram_get_r_def(wlan_name, buffer, sizeof(buffer), def);
        return req_format_write(wp, "%s", buffer);
    } else if(strstr(name, "x_WLS_REDIR_")) {
		get_wlan_name(wlan_name, 0, (char *)&name[2]);
		nvram_get_r_def(wlan_name, buffer, sizeof(buffer), "");
		return req_format_write(wp, "%s", buffer);
	}

    return 0;
}

static int pvar_getinfo_ipv6_dslite(request *wp, int argc, char **argv, struct aspvar *v)
{
    const char *name = v->name;
#ifdef CONFIG_IPV6
#ifdef CONFIG_DSLITE_SUPPORT
    addr6CfgParam_t ipaddr6;
	if(!strcmp(name, "dsliteAftr"))
	{
		if ( !apmib_get(MIB_IPV6_ADDR_AFTR_PARAM,(void *)&ipaddr6))
			return -1 ;
		sprintf(buffer, "%04x:%04x:%04x:%04x:%04x:%04x:%04x:%04x",
			ipaddr6.addrIPv6[0], ipaddr6.addrIPv6[1], ipaddr6.addrIPv6[2],
			ipaddr6.addrIPv6[3], ipaddr6.addrIPv6[4], ipaddr6.addrIPv6[5],
			ipaddr6.addrIPv6[6], ipaddr6.addrIPv6[7]);
		req_format_write(wp, "%s", buffer);
		return 0;
	}
	else if(!strcmp(name, "ipv6WanIp"))
	{
		if ( !apmib_get(MIB_IPV6_ADDR_WAN_PARAM,(void *)&ipaddr6))
			return -1 ;
		sprintf(buffer, "%04x:%04x:%04x:%04x:%04x:%04x:%04x:%04x",
			ipaddr6.addrIPv6[0], ipaddr6.addrIPv6[1], ipaddr6.addrIPv6[2],
			ipaddr6.addrIPv6[3], ipaddr6.addrIPv6[4], ipaddr6.addrIPv6[5],
			ipaddr6.addrIPv6[6], ipaddr6.addrIPv6[7]);
		req_format_write(wp, "%s", buffer);
		return 0;
	}
	else if(!strcmp(name, "ipv6DefGW"))
	{
		if ( !apmib_get(MIB_IPV6_ADDR_GW_PARAM,(void *)&ipaddr6))
			return -1 ;
		sprintf(buffer, "%04x:%04x:%04x:%04x:%04x:%04x:%04x:%04x",
			ipaddr6.addrIPv6[0], ipaddr6.addrIPv6[1], ipaddr6.addrIPv6[2],
			ipaddr6.addrIPv6[3], ipaddr6.addrIPv6[4], ipaddr6.addrIPv6[5],
			ipaddr6.addrIPv6[6], ipaddr6.addrIPv6[7]);
		req_format_write(wp, "%s", buffer);
		return 0;
	}
#else
	if(!strcmp(name, "dsliteAftr") || !strcmp(name, "ipv6WanIp") || !strcmp(name, "ipv6DefGW"))
	{
		req_format_write(wp, "");
		return 0;
	}
#endif
#else
	if(!strcmp(name, "dsliteAftr") || !strcmp(name, "ipv6WanIp") || !strcmp(name, "ipv6DefGW"))
	{
		req_format_write(wp, "");
		return 0;
	}
#endif
    return 0;
}

#if defined(CONFIG_RTL_ETH_802DOT1X_SUPPORT)
static int pvar_getinfo_ethdot1x(request *wp, int argc, char **argv, struct aspvar *v)
{
    char *name = v->name;
    int intVal = 0;
    char *buffer[4] = "";

	if(!strcmp(name, "ethdot1x_maxportnum"))
	{
		int opmode = 0;

		intVal = MAX_ELAN_DOT1X_PORTNUM - 1;

		if ( !apmib_get( MIB_OP_MODE,	(void *)&opmode) )
			return -1;

		if (opmode ==BRIDGE_MODE || opmode == WISP_MODE)
		{
			#if !defined(CONFIG_RTL_IVL_SUPPORT)
			intVal =  MAX_ELAN_DOT1X_PORTNUM;
			#endif
		}

		sprintf(buffer, "%d", intVal );
		return req_format_write(wp, buffer);
	}
	else if(!strcmp(name, "ethdot1x_mode"))
	{
		if ( !apmib_get( MIB_ELAN_DOT1X_MODE,	(void *)&intVal) )
			return -1;

		if (intVal & ETH_DOT1X_PROXY_MODE_BIT)
			sprintf(buffer, "%d", 1 );
		else
			sprintf(buffer, "%d", 0 );

		return req_format_write(wp, buffer);
	}


}
#endif

static int pvar_getinfo_ethdot1x_onoff(request *wp, int argc, char **argv, struct aspvar *v)
{
    char buffer[4] = "";

#if defined(CONFIG_RTL_ETH_802DOT1X_SUPPORT)
    int intVal = 0;
    apmib_get( MIB_ELAN_ENABLE_1X, (void *)&intVal);
    /* MIB_ELAN_ENABLE_1X bit0-->proxy/snooping enable/disable
     * MIB_ELAN_ENABLE_1X bit1-->client mode enable/disable
     */
    if (intVal & ETH_DOT1X_PROXY_SNOOPING_MODE_ENABLE_BIT)
        sprintf(buffer, "%d", 1 );
    else
        sprintf(buffer, "%d", 0 );
    return req_format_write(wp, buffer);
#else
    sprintf(buffer, "%d", 0 );
    return req_format_write(wp, buffer);
#endif
}

#if defined(CONFIG_RTL_P2P_SUPPORT)
static int pvar_getinfo_p2ptype(request *wp, int argc, char **argv, struct aspvar *v)
{
    int intVal = 0;
    char buffer[4] = "";

    apmib_get( MIB_WLAN_P2P_TYPE, (void *)&intVal);

    if(intVal == 4)
        sprintf(buffer, "%d", 1 );
    else
        sprintf(buffer, "%d", 0 );

    return req_format_write(wp, buffer);
}
#endif

#ifdef __DAVO__
static int pvar_getinfo_auto_upgrade_info(request *wp, int argc, char **argv, struct aspvar *v)
{
    int fd;
    unsigned int flags = 0;

    fd = open("/proc/dvflag", O_RDONLY);
    if (fd > -1) {
        read(fd, (void *)&flags, sizeof(flags));
        close(fd);
    }
    return req_format_write(wp,"%d", test_all_bits(DF_UPLOADING, flags));
}

static int pvar_getinfo_local_connection(request *wp, int argc, char **argv, struct aspvar *v)
{
    long WanIP_long=0;
    char wan_ip[32];
    unsigned long lanip=0, lanmask=0, peer_ip=0;
    int local_connect = 0;
    apmib_get( MIB_IP_ADDR,  (void *)&lanip);
    apmib_get( MIB_SUBNET_MASK,  (void *)&lanmask);
    //check local_connect
    if ( inet_aton(wp->remote_ip_addr, (struct in_addr *)&peer_ip) ) {
        if ( (lanip&lanmask) == (peer_ip&lanmask) ){
            local_connect = 1;
        } else if(sdmz_enable()) {
            if (get_ipaddr_file("/var/wan_ip", &WanIP_long, wan_ip) == 0)
                WanIP_long =0;
            if ( WanIP_long == peer_ip )
                local_connect = 1;
        }
    }
    req_format_write(wp, "%d", local_connect);
    return 0;
}

static int pvar_getinfo_wandns(request *wp, int argc, char **argv, struct aspvar *v)
{
    struct nameserver_addr *ns_addr;
    struct in_addr ns_ina[2];
    int intVal = 0;
    char buffer[200] = ""; //address * 10
    int i = 0;

    ns_ina[0].s_addr = ns_ina[1].s_addr = 0;
    if (!apmib_get(MIB_DNS_MODE, (void *)&intVal))
        return -1;
    /*if (intVal == 1) {
      apmib_get(MIB_DNS1, &ns_ina[0].s_addr);
      apmib_get(MIB_DNS2, &ns_ina[1].s_addr);
      } else {*/
    ns_addr = (struct nameserver_addr *)buffer;
    intVal = sort_nameserver("/etc/resolv.conf", ns_addr,
            sizeof(buffer) / sizeof(struct nameserver_addr),
            AF_INET);
    for (i = 0; i < intVal && i < ARRAY_SIZE(ns_ina); i++)
        ns_ina[i].s_addr = ns_addr[i].na_addr;
    //}
    req_format_write(wp, ("%s<br>"), inet_ntoa(ns_ina[0]));
    req_format_write(wp, ("&nbsp;%s"), inet_ntoa(ns_ina[1]));
    return 0;
}
#endif

static int pvar_getinfo_wlan_country_domain(request *wp, int argc, char **argv, struct aspvar *v)
{
    char tmpStr[64] = "";
    int i = 0;

    if(!strcmp(argv[0],"info_country"))
	{
		if(sizeof(countryIEArray)==0)
			req_format_write(wp, "%s","[]");
		else
		{
			req_format_write(wp, "%s","[");
			for(i=0;i<sizeof(countryIEArray)/sizeof(COUNTRY_IE_ELEMENT);i++)
			{
				/*country code, abb,5g idx,2g idx,name*/
				req_format_write(wp,"[%d,'%.3s',%d,%d,'%s'",countryIEArray[i].countryNumber,countryIEArray[i].countryA2,
					countryIEArray[i].A_Band_Region,countryIEArray[i].G_Band_Region,countryIEArray[i].countryName);
				if(i ==(sizeof(countryIEArray)/sizeof(COUNTRY_IE_ELEMENT)-1))
					req_format_write(wp, "%s","]");
				else
					req_format_write(wp, "%s","],");
			}
			req_format_write(wp, "%s","]");
		}
		return 0;
	}
	else if(!strcmp(argv[0],"info_2g"))
	{
		if(sizeof(Bandtable_2dot4G)==0)
			req_format_write(wp, "%s","[]");
		else
		{
			req_format_write(wp, "%s","[");
			for(i=0;i<sizeof(Bandtable_2dot4G)/sizeof(REG_DOMAIN_TABLE_ELEMENT_T);i++)
			{
				req_format_write(wp,"[%d,%d,'%s'",Bandtable_2dot4G[i].region,Bandtable_2dot4G[i].channel_set,Bandtable_2dot4G[i].area);
				if(i ==(sizeof(Bandtable_2dot4G)/sizeof(REG_DOMAIN_TABLE_ELEMENT_T)-1))
					req_format_write(wp, "%s","]");
				else
					req_format_write(wp, "%s","],");
			}
			req_format_write(wp, "%s","]");
		}
		return 0;
	}
	else if(!strcmp(argv[0],"info_5g"))
	{
		if(sizeof(Bandtable_5G)==0)
			req_format_write(wp, "%s","[]");
		else
		{
			req_format_write(wp, "%s","[");
			for(i=0;i<sizeof(Bandtable_5G)/sizeof(REG_DOMAIN_TABLE_ELEMENT_T);i++)
			{
				req_format_write(wp,"[%d,%d,'%s'",Bandtable_5G[i].region,Bandtable_5G[i].channel_set,Bandtable_5G[i].area);
				if(i ==(sizeof(Bandtable_5G)/sizeof(REG_DOMAIN_TABLE_ELEMENT_T)-1))
					req_format_write(wp, "%s","]");
				else
					req_format_write(wp, "%s","],");
			}
			req_format_write(wp, "%s","]");
		}
		return 0;
	}
	else if(!strcmp(argv[0],"country_str"))
	{
		apmib_get(MIB_WLAN_COUNTRY_STRING, (void *)tmpStr);
		req_format_write(wp,"%s",tmpStr);
		return 0;
	}

    return 0;
}

#ifdef HTTP_FILE_SERVER_HTM_UI
static int pvar_getinfo_current_directory(request *wp, int argc, char **argv, struct aspvar *v)
{
    //printf("%s:%d current_directory=%s\n",__FUNCTION__,__LINE__,httpfile_dirpath);
    if(httpfile_dirpath && strncmp(httpfile_dirpath,"/var/tmp/usb",strlen("/var/tmp/usb"))==0)
    {
        //printf("%s:%d current_directory=%s\n",__FUNCTION__,__LINE__,httpfile_dirpath);
        req_format_write(wp,"%s",((char*)httpfile_dirpath)+strlen("/var/tmp/usb"));
        //printf("%s:%d current_directory=%s\n",__FUNCTION__,__LINE__,httpfile_dirpath);
        return 0;
    }
    else
        return -1;
}
#endif

static int pvar_getinfo_initpage(request *wp, int argc, char **argv, struct aspvar *v)
{
#if defined(CONFIG_POCKET_AP_SUPPORT)
    req_format_write(wp, "%s","skb_status.htm");
#elif defined(CONFIG_RTL_ULINKER)
    int intVal = 0;
    apmib_get( MIB_ULINKER_AUTO, (void *)&intVal);
    if(intVal == 1)
        req_format_write(wp, "%s","skb_wizard.htm");
    else
        req_format_write(wp, "%s","skb_ulinker_opmode.htm");
#else
    req_format_write(wp, "%s","skb_wizard.htm");
#endif

    return 0;
}

static int pvar_getinfo_FwBank(request *wp, int argc, char **argv, struct aspvar *v)
{
    const char *name = v->name;
    int intVal = 0;

	if ( !strcmp(name, "currFwBank"))
	{
#if defined(CONFIG_RTL_FLASH_DUAL_IMAGE_ENABLE)
		int active,backup;
		apmib_get(MIB_DUALBANK_ENABLED, (void *)&intVal);
		get_bank_info(intVal ,&active,&backup);
		intVal = active;
#else
		intVal = 1;
#endif
		req_format_write(wp, "%d",intVal);

		return 0;
	}
	else if ( !strcmp(name, "backFwBank"))
	{
#if defined(CONFIG_RTL_FLASH_DUAL_IMAGE_ENABLE)
		int active,backup;
		apmib_get(MIB_DUALBANK_ENABLED, (void *)&intVal);
		get_bank_info(intVal ,&active,&backup);
		intVal = backup;
#else
		intVal = 2;
#endif
		req_format_write(wp, "%d",intVal);

		return 0;
	}

    return 0;
}

static int pvar_getinfo_accessFromWan(request *wp, int argc, char **argv, struct aspvar *v)
{
    char buffer[32] = "";
    struct in_addr logoin_ip, wan_ip, wan_mask;
    unsigned int i_logoin_ip, i_wan_ip, i_wan_mask;
    unsigned int wan_access_dut=0;
    unsigned int op_mode=0;
#ifdef HOME_GATEWAY
    apmib_get(MIB_WEB_WAN_ACCESS_ENABLED, (void *)&wan_access_dut);
    apmib_get(MIB_OP_MODE, (void *)&op_mode);

    if(wan_access_dut == 1 && op_mode!=BRIDGE_MODE)
    {
        char strWanIP[16];
        char strWanMask[16];
        char strWanDefIP[16];
        char strWanHWAddr[18];

        getWanInfo(strWanIP,strWanMask,strWanDefIP,strWanHWAddr);

        inet_aton(wp->remote_ip_addr, &logoin_ip);
        inet_aton(strWanIP, &wan_ip);
        inet_aton(strWanMask, &wan_mask);

        memcpy(&i_logoin_ip, &logoin_ip, 4);
        memcpy(&i_wan_ip, &wan_ip, 4);
        memcpy(&i_wan_mask, &wan_mask, 4);

        if (i_wan_mask > 0xffffff00)
            i_wan_mask = 0xffffff00;

        if((i_wan_ip & i_wan_mask) != (i_logoin_ip & i_wan_mask))
            wan_access_dut= 0;
    }
#else
    wan_access_dut=0;
#endif
    sprintf(buffer, "%d", wan_access_dut) ;
    req_format_write(wp, buffer);
    return 0;
}

static int pvar_getinfo_redirect_ip(request *wp, int argc, char **argv, struct aspvar *v)
{
    //char buffer[48] = "";
#ifdef HOME_GATEWAY
	struct in_addr	intaddr = { };
    unsigned int wan_access_dut=0;
    apmib_get(MIB_WEB_WAN_ACCESS_ENABLED, (void *)&wan_access_dut);

    if(wan_access_dut == 1)
    {
        struct in_addr lan_ip, lan_mask, logoin_ip, wan_ip, wan_mask;
        unsigned int i_lan_ip, i_lan_mask, i_logoin_ip, i_wan_ip, i_wan_mask;

        char strWanIP[16];
        char strWanMask[16];
        char strWanDefIP[16];
        char strWanHWAddr[18];

        getWanInfo(strWanIP,strWanMask,strWanDefIP,strWanHWAddr);

        inet_aton(strWanIP, &wan_ip);
        inet_aton(strWanMask, &wan_mask);
        inet_aton(wp->remote_ip_addr, &logoin_ip);

        apmib_get( MIB_IP_ADDR,  (void *)&lan_ip);
        apmib_get( MIB_SUBNET_MASK, (void *)&lan_mask);

        memcpy(&i_lan_ip, &lan_ip, 4);
        memcpy(&i_lan_mask, &lan_mask, 4);
        memcpy(&i_logoin_ip, &logoin_ip, 4);
        memcpy(&i_wan_ip, &wan_ip, 4);
        memcpy(&i_wan_mask, &wan_mask, 4);

        if (i_wan_mask > 0xffffff00)
            i_wan_mask = 0xffffff00;

        /*users should change the LAN IP/SUBNET manually when LAN/WAN IP conflict*/
        if((i_lan_ip & i_lan_mask) == (i_logoin_ip & i_lan_mask))
        {
            if ( getInAddr(BRIDGE_IF, IP_ADDR, (void *)&intaddr ) )
                return req_format_write(wp, "%s", inet_ntoa(intaddr) );
            else{
                //apmib_get( MIB_IP_ADDR,  (void *)buffer);
                //return req_format_write(wp, "%s", inet_ntoa(*((struct in_addr *)&buffer[0])));
                apmib_get( MIB_IP_ADDR,  (void *)&intaddr);
                return req_format_write(wp, "%s", inet_ntoa(intaddr));
            }
        }
        else if((i_wan_ip & i_wan_mask) == (i_logoin_ip & i_wan_mask))
        {
            return req_format_write(wp, "%s", strWanIP);

        }
        else
        {
            //apmib_get( MIB_IP_ADDR,  (void *)buffer);
            //return req_format_write(wp, "%s", inet_ntoa(*((struct in_addr *)buffer)));

            apmib_get( MIB_IP_ADDR,  (void *)&intaddr);
            return req_format_write(wp, "%s", inet_ntoa(intaddr));
        }

    }
    else
    {
#endif
        //use MIB_IP_ADDR for changing IP subnet from Wizard. users must reset IP addr after LAN/WAN subnet conflict.
        /*
           if ( getInAddr(BRIDGE_IF, IP_ADDR, (void *)&intaddr ) )
           return req_format_write(wp, "%s", inet_ntoa(intaddr) );
           else
           */
        apmib_get( MIB_IP_ADDR,  (void *)&intaddr);
        return req_format_write(wp, "%s", inet_ntoa(intaddr));

        //apmib_get( MIB_IP_ADDR,  (void *)buffer);
        //return req_format_write(wp, "%s", inet_ntoa(*((struct in_addr *)buffer)));
#ifdef HOME_GATEWAY
    }
#endif
    return 0;
}

static int pvar_getinfo_onoff_tkip_comment(request *wp, int argc, char **argv, struct aspvar *v)
{
    int intVal = 0;

    if(!strcmp(argv[0],"onoff_tkip_comment_start"))
    {
        int wlanMode=0;

        apmib_get(MIB_WLAN_11N_ONOFF_TKIP, (void *)&intVal);
        apmib_get(MIB_WLAN_BAND, (void *)&wlanMode);
        if(intVal == 0 && (wlanMode >= BAND_11N))
            req_format_write(wp, "%s","<!--");
        else
            req_format_write(wp, "%s","");

        return 0;
    }
    else if(!strcmp(argv[0],"onoff_tkip_comment_end"))
    {
        int wlanMode=0;

        apmib_get(MIB_WLAN_11N_ONOFF_TKIP, (void *)&intVal);
        apmib_get(MIB_WLAN_BAND, (void *)&wlanMode);
        if(intVal == 0 && (wlanMode >= BAND_11N))
            req_format_write(wp, "%s","-->");
        else
            req_format_write(wp, "%s","");

        return 0;
    }

    return 0;
}

#ifdef REBOOT_CHECK
static int pvar_getinfo_reboot_check(request *wp, int argc, char **argv, struct aspvar *v)
{
	if(!strcmp(argv[0],"countDownTime"))
	{
		req_format_write(wp, "%d",countDownTime);
		countDownTime = APPLY_COUNTDOWN_TIME;
		return 0;
	}

	else if(!strcmp(argv[0],"okMsg"))
	{
		req_format_write(wp, "%s", okMsg);
		memset(okMsg,0x00,sizeof(okMsg));
		return 0;
	}

	else if(!strcmp(argv[0],"lastUrl"))
	{
		if(strlen(lastUrl) == 0)
			req_format_write(wp, "%s", "/skb_home.htm");
		else
			req_format_write(wp, "%s", lastUrl);

		memset(lastUrl,0x00,sizeof(lastUrl));
		return 0;
	}

    else if(!strcmp(argv[0],"status_warning"))
	{
#ifdef REBOOT_CHECK
		if(needReboot == 1)
		{
			req_format_write(wp, "%s", "<tr><td></td></tr><tr><td><font size=2><font color='#FF0000'> \
 															Below status shows currnt settings, but does not take effect. \
															</font></td></tr>");
		}
		else
#endif
		{
			req_format_write(wp, "%s", "");
		}

		return 0;
	}
    return 0;
}
#endif

#ifdef CONFIG_RTL_BT_CLIENT
extern int bt_getTorrents(struct torrent_t *torrentp, int max);
extern int bt_getClientsInfo(struct ctorrent_t  *ctorrentp, int max);

static int pvar_getinfo_torrents(request *wp, int argc, char **argv, struct aspvar *v)
{
    /*Output torrents*/
    struct torrent_t torrent[20];
    struct ctorrent_t ctorrent[10];
    char tmpbuf[64];
    char tmpbuf1[64];
    int tcounts;
    int ctcounts;
    int i;
    int cindex;

    memset(torrent,0x0,sizeof(struct torrent_t)*20);
    memset(ctorrent,0x0,sizeof(struct ctorrent_t )*10);

    tcounts=bt_getTorrents(torrent,20);
    ctcounts=bt_getClientsInfo(ctorrent,10);
    /*webWrite format: torrentname,btstatus,size,updownsize,seeder,etaratio,uprate,downrate,index*/
    if(tcounts == 0)
    {
        req_format_write(wp,"%s","[]");
        return 0;
    }
    req_format_write(wp,"%s","[");
    for(i=0;i<tcounts;i++)
    {
        if(0==i)
            req_format_write(wp,"%s","[");
        else
            req_format_write(wp,"%s",",[");
        /*0 not running 1 running 2 start_paused*/
        if(0==torrent[i].status)
        {
            /*not running. no ctorrent.*/
            /*name*/
            req_format_write(wp,"'%s'",torrent[i].name);
            /*status*/
            req_format_write(wp,",'%s'","Not Running");
            /*size*/
            req_format_write(wp,",'%s'","N/A");
            /*up/down size*/
            req_format_write(wp,",'%s'","N/A");
            /*seeder/leecher*/
            req_format_write(wp,",'%s'","N/A");
            /*ETA/RATIO*/
            req_format_write(wp,",'%s'","N/A");
            /*uprate*/
            req_format_write(wp,",'%s'","N/A");
            /*downrate*/
            req_format_write(wp,",'%s'","N/A");
            /*torrent index*/
            req_format_write(wp,",'%d'",torrent[i].index);
            /*ctorrent index*/
            req_format_write(wp,",'%d'",torrent[i].ctorrent);
        }
        else if(1==torrent[i].status)
        {
            req_format_write(wp,"'%s'",torrent[i].name);
            if(ctcounts !=0 && torrent[i].ctorrent != (-1))
            {
                if(ctorrent[torrent[i].ctorrent].paused)
                {
                    req_format_write(wp,",'%s'","Paused");
                }
                else
                {
                    req_format_write(wp,",'%s'","Running");
                }
            }
            cindex=torrent[i].ctorrent;
            /*get ctorrent to print others*/
            /*size*/
            sprintf(tmpbuf,"%llu",ctorrent[cindex].size);
            req_format_write(wp,",'%s'",tmpbuf);
            /*down/up size*/
            sprintf(tmpbuf,"%llu",ctorrent[cindex].dl_total);
            sprintf(tmpbuf1,"%llu",ctorrent[cindex].ul_total);
            req_format_write(wp,",'%s/%s'",tmpbuf,tmpbuf1);
            /*seeder/leecher*/
            sprintf(tmpbuf,"%u",ctorrent[cindex].seeders);
            sprintf(tmpbuf1,"%u",ctorrent[cindex].leechers);
            req_format_write(wp,",'%s/%s'",tmpbuf,tmpbuf1);
            /*ETA/RATIO*/
            sprintf(tmpbuf,"%llu",ctorrent[cindex].seed_ratio);
            req_format_write(wp,",'%s'",tmpbuf);
            /*uprate*/
            req_format_write(wp,",'%d'",ctorrent[cindex].ul_rate);
            /*downrate*/
            req_format_write(wp,",'%d'",ctorrent[cindex].dl_rate);
            /*torrent index*/
            req_format_write(wp,",'%d'",torrent[i].index);
            /*ctorrent index*/
            req_format_write(wp,",'%d'",cindex);

        }
        else if(2==torrent[i].status)
        {
            req_format_write(wp,"'%s'",torrent[i].name);
            req_format_write(wp,",'%s'","Paused");
            cindex=torrent[i].ctorrent;
            /*get ctorrent to print others*/
            /*size*/
            sprintf(tmpbuf,"%llu",ctorrent[cindex].size);
            req_format_write(wp,",'%s",tmpbuf);
            /*down/up size*/
            sprintf(tmpbuf,"%llu",ctorrent[cindex].dl_total);
            sprintf(tmpbuf1,"%llu",ctorrent[cindex].ul_total);
            req_format_write(wp,",'%s/%s'",tmpbuf,tmpbuf1);
            /*seeder/leecher*/
            sprintf(tmpbuf,"%u",ctorrent[cindex].seeders);
            sprintf(tmpbuf1,"%u",ctorrent[cindex].leechers);
            req_format_write(wp,",'%s/%s'",tmpbuf,tmpbuf1);
            /*ETA/RATIO*/
            sprintf(tmpbuf,"%llu",ctorrent[cindex].seed_ratio);
            req_format_write(wp,",'%s'",tmpbuf);
            /*uprate*/
            req_format_write(wp,",'%d'",ctorrent[cindex].ul_rate);
            /*downrate*/
            req_format_write(wp,",'%d'",ctorrent[cindex].dl_rate);
            /*torrent index*/
            req_format_write(wp,",'%d'",torrent[i].index);
            /*ctorrent index*/
            req_format_write(wp,",'%d'",cindex);
        }
        req_format_write(wp,"%s","]");
    }
    req_format_write(wp,"%s","]");

    for(i=0;i<tcounts;i++)
    {
        if(torrent[i].name)
            free(torrent[i].name);
    }

    for(i=0;i<ctcounts;i++)
    {
        if(ctorrent[i].valid)
        {
            if(ctorrent[i].fname)
                free(ctorrent[i].fname);
            if(ctorrent[i].msg)
                free(ctorrent[i].msg);
        }
    }
    return 0;
}

extern int  bt_getDetails(int index, struct ctfile_t *file, int max);

static int pvar_getinfo_btfiles(request *wp, int argc, char **argv, struct aspvar *v)
{
    char *ptr;
    int index;
    int filecount;
    char tmpbuf[64];
    struct ctfile_t file[30];

    memset(file,0x0,sizeof(struct ctfile_t)*30);
    ptr=req_get_cstream_var(wp,"ctorrent", "");
    if(ptr)
        index=atoi(ptr);
    else
        return -1;
    /*get index torrent files....*/
    filecount=bt_getDetails(index, file, 30);
    if(0== filecount)
    {
        req_format_write(wp,"%s","[]");
        return 0;
    }
    /*format filename fileno download_percent filesize priority*/
    /*priority is used for indicate if need to download it*/
    req_format_write(wp,"%s","[");
    for(i=0;i<filecount;i++)
    {
        if(0==i)
            req_format_write(wp,"%s","[");
        else
            req_format_write(wp,"%s",",[");

        req_format_write(wp,"'%s'",file[i].filename);
        req_format_write(wp,",'%d'",file[i].fileno);
        req_format_write(wp,",'%d'",file[i].download);
        sprintf(tmpbuf,"%llu",file[i].filesize);
        req_format_write(wp,",'%s'",tmpbuf);
        req_format_write(wp,",'%d'",file[i].priority);

        req_format_write(wp,"%s","]");
    }
    req_format_write(wp,"%s","]");
    for(i=0;i<filecount;i++)
    {
        if(file[filecount].filename)
            free(file[filecount].filename);
    }
    return 0;
}

static int pvar_getinfo_btclientindex(request *wp, int argc, char **argv, struct aspvar *v)
{
    char *ptr=NULL;
    ptr=req_get_cstream_var(wp,"ctorrent", "");
    if(ptr)
        req_format_write(wp, "%s",ptr);
    return 0;
}
#endif

#ifdef CONFIG_RTL_TRANSMISSION
static int pvar_getinfo_bt_enabled(request *wp, int argc, char **argv, struct aspvar *v)
{
    if(!apmib_get(MIB_BT_ENABLED,&intVal))
        return -1;
    if(intVal)
        req_format_write(wp,"checked");
    else
        req_format_write(wp,"");
    return 0;
}
#endif

#ifdef CONFIG_RTL_WAPI_SUPPORT
static int pvar_getinfo_auth_mode_2or3_certification(request *wp, int argc, char **argv, struct aspvar *v)
{
    int intVal = 0;

    if(!apmib_get(MIB_WLAN_WAPI_AUTH_MODE_2or3_CERT,&intVal))
        return -1;

    //printf("val =%d\n",intVal);
    if(intVal !=3)
        req_format_write(wp,"%s","two_certification");
    else
        req_format_write(wp,"%s","three_certification");

    return 0;
}
#endif


static int pvar_getinfo_print_wapiLocalAsCertsUploadForm(request *wp, int argc, char **argv, struct aspvar *v)
{
#ifdef CONFIG_RTL_WAPI_LOCAL_AS_SUPPORT
    req_format_write(wp,"<form method=\"post\" action=\"/boafrm/formUploadWapiCert\" enctype=\"multipart/form-data\" name=\"uploadCACert\">");
    req_format_write(wp,"<table border=\"0\" cellspacing=\"0\" width=\"500\">");
    req_format_write(wp,"<tr><font size=2></font></tr>");
    req_format_write(wp,"<tr><hr size=1 noshade align=top></tr>");
    req_format_write(wp,"<tr><td width=\"0.55\"><font size=2><b>Certificate Type of Local AS:</b></font></td>");
    req_format_write(wp,"<td width=\"0.45\"><font size=2> <input name=\"cert_type\" type=radio value=0 checked>X.509</font></td></tr>");
    req_format_write(wp,"<tr><td width=\"0.55\"><font size=2><b>CA Certificate from Local AS:</b></font></td>");
    req_format_write(wp,"<td width=\"0.45\"><font size=2><input type=\"file\" name=\"ca_binary\" size=20></font></td></tr></table>");
    req_format_write(wp,"<input onclick=sendClicked(this.form) type=button value=\"Upload\" name=\"send\">&nbsp;&nbsp;");
    req_format_write(wp,"<input type=\"reset\" value=\"Reset\" name=\"reset\">");
    req_format_write(wp,"<input type=\"hidden\" value=\"/skb_wlwapiinstallcert.htm\" name=\"submit-url\">");
    req_format_write(wp,"<input type=\"hidden\" value=\"ca\" name=\"uploadcerttype\">");
    req_format_write(wp,"<input type=\"hidden\" value= \"two_certification\" name=\"auth_mode\"></form>");


    req_format_write(wp,"<form method=\"post\" action=\"/boafrm/formUploadWapiCert\" enctype=\"multipart/form-data\" name=\"uploadASUCert\"\
            id=\"uploadASUCert_asu\" style=\"display:none\">");


    req_format_write(wp,"<table border=\"0\" cellspacing=\"0\" width=\"500\">");
    req_format_write(wp,"<tr><font size=2></font></tr>");
    req_format_write(wp,"<tr><td width=\"0.55\"><font size=2><b>ASU Certificate from Local AS:</b></font></td>");
    req_format_write(wp,"<td width=\"0.45\"><font size=2><input type=\"file\" name=\"asu_binary\" size=20></font></td></tr></table>");
    req_format_write(wp,"<input onclick=sendClicked(this.form) type=button value=\"Upload\" name=\"send\">&nbsp;&nbsp;");
    req_format_write(wp,"<input type=\"reset\" value=\"Reset\" name=\"reset\">");
    req_format_write(wp,"<input type=\"hidden\" value=\"/skb_wlwapiinstallcert.htm\" name=\"submit-url\">");
    req_format_write(wp,"<input type=\"hidden\" value=\"asu\" name=\"uploadcerttype\">");
    req_format_write(wp,"<input type=\"hidden\" value= \"two_certification\" name=\"auth_mode\"></form>");

    req_format_write(wp,"<form method=\"post\" action=\"/boafrm/formUploadWapiCert\" enctype=\"multipart/form-data\" name=\"uploadUserCert\">");
    req_format_write(wp,"<table border=\"0\" cellspacing=\"0\" width=\"500\">");
    req_format_write(wp,"<tr><font size=2></font></tr>");
    //		req_format_write(wp,"<tr><hr size=1 noshade align=top></tr>");
    req_format_write(wp,"<tr><td width=\"0.55\"><font size=2><b>User Certificate from Local AS:</b></font></td>");
    req_format_write(wp,"<td width=\"0.45\"><font size=2><input type=\"file\" name=\"user_binary\" size=20></font></td></tr></table>");
    req_format_write(wp,"<input onclick=sendClicked(this.form) type=button value=\"Upload\" name=\"send\">&nbsp;&nbsp;");
    req_format_write(wp,"<input type=\"reset\" value=\"Reset\" name=\"reset\">");
    req_format_write(wp,"<input type=\"hidden\" value=\"/skb_wlwapiinstallcert.htm\" name=\"submit-url\">");
    req_format_write(wp,"<input type=\"hidden\" value=\"user\" name=\"uploadcerttype\">");
    req_format_write(wp,"<input type=\"hidden\" value= \"two_certification\" name=\"auth_mode\"></form>");
#endif
    return 0;
}

#ifdef CONFIG_RTL_WAPI_SUPPORT
static int pvar_getinfo_wapiCert(request *wp, int argc, char **argv, struct aspvar *v)
{
    char *name = v->name;
    char buffer[128] = "";

    if(!strcmp(name, "wapiCert"))
    {
        int index;
        int count;
        int i;
        struct stat status;
        char tmpbuf[10];

        CERTS_DB_ENTRY_Tp cert=(CERTS_DB_ENTRY_Tp)malloc(128*sizeof(CERTS_DB_ENTRY_T));
        //Search Index 1--all, 2--serial.no, 3--owner, 4--type, 5--status
        if (!apmib_get(MIB_WLAN_WAPI_SEARCHINDEX,  (void*)&index))
        {
            free(cert);
            return -1;
        }
        if(!apmib_get(MIB_WLAN_WAPI_SEARCHINFO,  (void*)buffer))
        {
            free(cert);
            return -1;
        }

        /*update wapiCertInfo*/
        system("openssl ca -updatedb 2>/dev/null");
        if (stat(WAPI_CERT_CHANGED, &status) == 0) { // file existed
            system("storeWapiFiles -allUser");
        }

        count=searchWapiCert(cert,index,buffer);
        if(count == 0)
            req_format_write(wp, "%s","[]");
        else
        {
            req_format_write(wp, "%s","[");
            for(i=0;i<count;i++)
            {
                sprintf(tmpbuf, "%08X",cert[i].serial);
                req_format_write(wp,"['%s','%s','%d','%d',",cert[i].userName,tmpbuf,cert[i].validDays,cert[i].validDaysLeft);
                if(0 == cert[i].certType)
                {
                    req_format_write(wp,"'%s',","X.509");
                }
                if(0==cert[i].certStatus)
                {
                    req_format_write(wp,"'%s'","actived");
                }else if(1 ==cert[i].certStatus)
                {
                    req_format_write(wp,"'%s'","expired");
                }else if(2 ==cert[i].certStatus)
                {
                    req_format_write(wp,"'%s'","revoked");
                }
                if(i ==(count-1))
                    req_format_write(wp, "%s","]");
                else
                    req_format_write(wp, "%s","],");
            }
            req_format_write(wp, "%s","]");
        }
        free(cert);
        return 0;
    }
}

static int pvar_getinfo_CerExist(request *wp, int argc, char **argv, struct aspvar *v)
{
    struct stat status;
    char *name = v->name;
    int intVal = 0;

    if (!strcmp(name,"caCerExist")) {
        if (stat(CA_CERT, &status) < 0)
        {
            intVal=0;	//CA_CERT not exist
        }
        else
        {
            intVal=1;	//CA_CERT exists
        }
        req_format_write(wp, "%d",intVal);

    } else if(!strcmp(name,"asCerExist")) {
        if (stat(CA_CER, &status) < 0)
        {
            intVal=0;	//AS_CER not exist
        }
        else
        {
            intVal=1;	//AS_CER exists
        }
        req_format_write(wp, "%d",intVal);
    }

    return 0;
}

static int pvar_getinfo_notSyncSysTime(request *wp, int argc, char **argv, struct aspvar *v)
{
    struct stat status;
    time_t  now;
    struct tm *tnow;
    char buffer[128] = "";
    int intVal = 0;

    if (stat(SYS_TIME_NOT_SYNC_CA, &status) < 0)
    {
        //SYS_TIME_NOT_SYNC_CA not exist

        now=time(0);
        tnow=localtime(&now);
        //printf("now=%ld, %d %d %d %d %d %d, tm_isdst=%d\n",now, 1900+tnow->tm_year,tnow->tm_mon+1,tnow->tm_mday,tnow->tm_hour,tnow->tm_min,tnow->tm_sec, tnow->tm_isdst);//Added for test

        if(1900+tnow->tm_year < 2009)
        {
            intVal=1;	//current year of our system < 2009 which means our system hasn't sync time yet
        }
        else
        {
            intVal=0;	//SYS_TIME_NOT_SYNC_CA not exist and current time >= year 2009 which means our system has sync time already
        }
    }
    else
    {
        intVal=1;	//SYS_TIME_NOT_SYNC_CA exists which means our system hasn't sync time yet
        sprintf(buffer, "rm -f %s 2>/dev/null", SYS_TIME_NOT_SYNC_CA);
        system(buffer);
    }
    req_format_write(wp, "%d",intVal);
    return 0;
}

static int pvar_getinfo_print_wapiMenu(request *wp, int argc, char **argv, struct aspvar *v)
{
#if defined(CONFIG_RTL_8198C) || defined(CONFIG_RTL_8198) || defined(CONFIG_POCKET_ROUTER_SUPPORT) || defined(CONFIG_RTL_8196C) || defined(CONFIG_RTL_819XD) || defined(CONFIG_RTL_8196E)
    req_format_write(wp,"menu.addItem(\"WAPI\");");
    req_format_write(wp,"wlan_wapi = new MTMenu();");
    //#if !defined(CONFIG_RTL_8196C)
    req_format_write(wp,"wlan_wapi.addItem(\"Certification Install\", \"skb_wlwapiinstallcert.htm\", \"\", \"Install Ceritification\");");
#ifdef CONFIG_RTL_WAPI_LOCAL_AS_SUPPORT
    req_format_write(wp,"wlan_wapi.addItem(\"Certification Manage\", \"skb_wlwapiCertManagement.htm\", \"\", \"Manage Ceritification\");");
#endif
    //#endif
    req_format_write(wp,"for(i=0; i < wlan_num ; i++){");
    req_format_write(wp,"wlan_name= \"wlan\" +(i+1);");
    req_format_write(wp,"if(wlan_num == 1)");
    req_format_write(wp,"wlan0_wapi = wlan_wapi ;");
    req_format_write(wp,"else{");
    req_format_write(wp,"if(1 == wlan_support_92D){");
    req_format_write(wp,"if(i==0 && wlan1_phyband != \"\"){");
    req_format_write(wp,"wlan_name=wlan_name+\"(\"+wlan1_phyband+\")\";");
    req_format_write(wp,"}else if(i==1 && wlan2_phyband != \"\"){");
    req_format_write(wp,"wlan_name=wlan_name+\"(\"+wlan2_phyband+\")\";");
    req_format_write(wp,"}else{");
    req_format_write(wp,"continue;}}");
    req_format_write(wp,"if(wlBandMode == 3)");	//3:BANDMODESIGNLE
    req_format_write(wp,"wlan_name = \"wlan1\";");
    req_format_write(wp,"wlan_wapi.addItem(wlan_name);");
    req_format_write(wp,"wlan0_wapi= new MTMenu();}");
    req_format_write(wp,"wlan0_wapi.addItem(\"Key Update\", get_form(\"skb_wlwapiRekey.htm\",i), \"\", \"Key update\");");
    req_format_write(wp,"if(wlan_num != 1)");
    req_format_write(wp,"wlan_wapi.makeLastSubmenu(wlan0_wapi);");
    req_format_write(wp,"}");
    req_format_write(wp,"menu.makeLastSubmenu(wlan_wapi);");
#endif
    return 0;
}
#endif

#ifdef CONFIG_APP_TR069
static int pvar_getinfo_tr069(request *wp, int argc, char **argv, struct aspvar *v)
{
    char *name = v->name;
    int intVal = 0;
    char buffer[16] = "";

    if(!strcmp(name, "tr069-inform-0")) {
		if ( !apmib_get( MIB_CWMP_INFORM_ENABLE, (void *)&intVal) )
			return -1;
		if(intVal == 1){
			return req_format_write(wp, "");
		}else{
			return req_format_write(wp, "checked");
		}
	}else if(!strcmp(name, "tr069-inform-1")) {
		if ( !apmib_get( MIB_CWMP_INFORM_ENABLE, (void *)&intVal) )
			return -1;
		if(intVal == 1){
			return req_format_write(wp, "checked");
		}else{
			return req_format_write(wp, "");
		}
	}else if(!strcmp(name, "inform_interval")) {
		if ( !apmib_get( MIB_CWMP_INFORM_INTERVAL, (void *)&intVal) )
			return -1;
		sprintf(buffer, "%d", intVal );
		return req_format_write(wp, buffer);

	}else if(!strcmp(name, "tr069_interval")) {
		if ( !apmib_get( MIB_CWMP_INFORM_ENABLE, (void *)&intVal) )
			return -1;
		if(intVal == 1){
			return req_format_write(wp, "");
		}else{
			return req_format_write(wp, "disabled");
		}
	} else if(!strcmp(name, "tr069-dbgmsg-0")) {
		if ( !apmib_get( MIB_CWMP_FLAG, (void *)&intVal) )
			return -1;
		if(intVal & CWMP_FLAG_DEBUG_MSG){
			 return req_format_write(wp,"");
		}else{
			return req_format_write(wp,"checked");
		}
	}else if(!strcmp(name, "tr069-dbgmsg-1")) {
		if ( !apmib_get( MIB_CWMP_FLAG, (void *)&intVal) )
			return -1;
		if(intVal & CWMP_FLAG_DEBUG_MSG){
			 return req_format_write(wp,"checked");
		}else{
			 return req_format_write(wp,"");
		}
	}else if(!strcmp(name, "tr069-sendgetrpc-0")) {
		if ( !apmib_get( MIB_CWMP_FLAG, (void *)&intVal) )
			return -1;
		if(intVal & CWMP_FLAG_SENDGETRPC){
			return req_format_write(wp,"");
		}else{
			return req_format_write(wp,"checked");
		}
	}else if(!strcmp(name, "tr069-sendgetrpc-1")) {
		if ( !apmib_get( MIB_CWMP_FLAG, (void *)&intVal) )
			return -1;
		if(intVal & CWMP_FLAG_SENDGETRPC){
			return req_format_write(wp,"checked");
		}else{
			return req_format_write(wp,"");
		}
	}else if(!strcmp(name, "tr069-skipmreboot-0")) {
		if ( !apmib_get( MIB_CWMP_FLAG, (void *)&intVal) )
			return -1;
		if(intVal & CWMP_FLAG_SKIPMREBOOT){
			return req_format_write(wp,"");
		}else{
			return req_format_write(wp,"checked");
		}
	}else if(!strcmp(name, "tr069-skipmreboot-1")) {
		if ( !apmib_get( MIB_CWMP_FLAG, (void *)&intVal) )
			return -1;
		if(intVal & CWMP_FLAG_SKIPMREBOOT){
			return req_format_write(wp,"checked");
		}else{
			return req_format_write(wp,"");
		}
	}else if(!strcmp(name, "tr069-autoexec-0")) {
		if ( !apmib_get( MIB_CWMP_FLAG, (void *)&intVal) )
			return -1;
		if(intVal & CWMP_FLAG_AUTORUN){
			return req_format_write(wp,"");
		}else{
			return req_format_write(wp,"checked");
		}
	}else if(!strcmp(name, "tr069-autoexec-1")) {
		if ( !apmib_get( MIB_CWMP_FLAG, (void *)&intVal) )
			return -1;
		if(intVal & CWMP_FLAG_AUTORUN){
			return req_format_write(wp,"checked");
		}else{
			return req_format_write(wp,"");
		}
	}else if(!strcmp(name, "tr069-delay-0")) {
		if ( !apmib_get( MIB_CWMP_FLAG, (void *)&intVal) )
			return -1;
		if(intVal & CWMP_FLAG_DELAY){
			return req_format_write(wp,"");
		}else{
			return req_format_write(wp,"checked");
		}
	}else if(!strcmp(name, "tr069-delay-1")) {
		if ( !apmib_get( MIB_CWMP_FLAG, (void *)&intVal) )
			return -1;
		if(intVal & CWMP_FLAG_DELAY){
			return req_format_write(wp,"checked");
		}else{
			return req_format_write(wp,"");
		}
	}
    return 0;
}
#endif

#ifdef VOIP_SUPPORT
// added by rock /////////////////////////////////////////
static int pvar_getinfo_voip_(request *wp, int argc, char **argv, struct aspvar *v)
{
    const char *name = v->name;
//#ifdef VOIP_SUPPORT
	if (!strncmp(name, "voip_", 5)) {
		return asp_voip_getInfo(wp, argc, argv);
	} else
//#else
#if 0
	if (!strncmp(name, "voip_", 5)) {
   		return 0;
	}
#endif
    return 0;
}
#endif

/////////added by hf_shi/////////////////
static int pvar_getinfo_ipv6_(request *wp, int argc, char **argv, struct aspvar *v)
{
    const char *name = v->name;
#ifdef CONFIG_IPV6
	if(!strncmp(name, "IPv6_",5)){
			return getIPv6Info(wp, argc, argv);
	}
#else
    if (!strncmp(name, "IPv6_", 5)) {
   		return 0;
	}
#endif
    return 0;
}


#ifdef UNIVERSAL_REPEATER
static int pvar_getinfo_universal_repeater(request *wp, int argc, char **argv, struct aspvar *v)
{
    const char *name = v->name;
    int intVal = 0;
    char buffer[64] = "";
    struct user_net_device_stats stats = { };
	bss_info bss;

	if ( !strcmp(name, "repeaterSSID")) {
		if (wlan_idx == 0)
			intVal = MIB_REPEATER_SSID1;
		else
			intVal = MIB_REPEATER_SSID2;
		apmib_get(intVal, (void *)buffer);
		translate_control_code(buffer);
		return req_format_write(wp, "%s", buffer);
   	}
	else if ( !strcmp(name, "repeaterState")) {
		char *pMsg;
		if (wlan_idx == 0)
			strcpy(buffer, "wlan0-vxd");
		else
			strcpy(buffer, "wlan1-vxd");
		getWlBssInfo(buffer, &bss);
		switch (bss.state) {
		case STATE_DISABLED:
			pMsg = "Disabled";
			break;
		case STATE_IDLE:
			pMsg = "Idle";
			break;
		case STATE_STARTED:
			pMsg = "Started";
			break;
		case STATE_CONNECTED:
			pMsg = "Connected";
			break;
		case STATE_WAITFORKEY:
			pMsg = "Waiting for keys";
			break;
		case STATE_SCANNING:
			pMsg = "Scanning";
			break;
		default:
			pMsg=NULL;
		}
		return req_format_write(wp, "%s", pMsg);
	}
 	else if ( !strcmp(name, "repeaterClientnum")) {
		if (wlan_idx == 0)
			strcpy(buffer, "wlan0-vxd");
		else
			strcpy(buffer, "wlan1-vxd");
 		if(getWlStaNum(buffer, &intVal)<0)
 			intVal=0;
		sprintf(buffer, "%d", intVal );
		return req_format_write(wp, buffer);
	}
	else if ( !strcmp(name, "repeaterSSID_drv")) {
#if defined(CONFIG_RTL_819X) && !defined(CONFIG_WLAN_REPEATER_MODE)// keith. disabled if no this mode in 96c
		return req_format_write(wp, "%s", "e0:00:19:78:01:10");
#else
		if (wlan_idx == 0)
			strcpy(buffer, "wlan0-vxd");
		else
			strcpy(buffer, "wlan1-vxd");
		getWlBssInfo(buffer, &bss);
		memcpy(buffer, bss.ssid, SSID_LEN+1);
		translate_control_code(buffer);
		return req_format_write(wp, "%s", buffer);
#endif
	}
	else if ( !strcmp(name, "repeaterBSSID")) {
		if (wlan_idx == 0)
			strcpy(buffer, "wlan0-vxd");
		else
			strcpy(buffer, "wlan1-vxd");
		getWlBssInfo(buffer, &bss);
		return req_format_write(wp, "%02x:%02x:%02x:%02x:%02x:%02x", bss.bssid[0], bss.bssid[1],
				bss.bssid[2], bss.bssid[3], bss.bssid[4], bss.bssid[5]);
	}
	else if ( !strcmp(name, "wlanRepeaterTxPacketNum")) {
		if (wlan_idx == 0)
			strcpy(buffer, "wlan0-vxd");
		else
			strcpy(buffer, "wlan1-vxd");
		if ( getStats(buffer, &stats) < 0)
			stats.tx_bytes = 0;
		sprintf(buffer, "%llu", stats.tx_bytes);
   		return req_format_write(wp, buffer);

	}
	else if ( !strcmp(name, "wlanRepeaterRxPacketNum")) {
		if (wlan_idx == 0)
			strcpy(buffer, "wlan0-vxd");
		else
			strcpy(buffer, "wlan1-vxd");
		if ( getStats(buffer, &stats) < 0)
			stats.rx_bytes = 0;
		sprintf(buffer, "%llu", stats.rx_bytes);
   		return req_format_write(wp, buffer);
	}

    return 0;
}
#endif	// UNIVERSAL_REPEATER

#if defined(VLAN_CONFIG_SUPPORTED)
static int pvar_getinfo_maxWebVlanNum(request *wp, int argc, char **argv, struct aspvar *v)
{
    char buffer[4] = "";
#if defined(CONFIG_RTL_8198_AP_ROOT) && defined(GMII_ENABLED)
    sprintf(buffer, "%d", MAX_IFACE_VLAN_CONFIG-2 );
#else
    sprintf(buffer, "%d", MAX_IFACE_VLAN_CONFIG-1);
#endif
    return req_format_write(wp, buffer);
}

static int pvar_getinfo_rf_used(request *wp, int argc, char **argv, struct aspvar *v)
{
    char buffer[8] = "";
    struct _misc_data_ misc_data;

    if (getMiscData(WLAN_IF, &misc_data) < 0)
        return -1;
    sprintf(buffer, "%d", misc_data.mimo_tr_used);
    req_format_write(wp, buffer);
    return 0;
}
#endif

static int pvar_getinfo_wizard_menu_onoff(request *wp, int argc, char **argv, struct aspvar *v)
{
    int intVal = 0;
#if defined(CONFIG_POCKET_AP_SUPPORT)
    return req_format_write(wp,"");
#elif defined(CONFIG_RTL_ULINKER)
    apmib_get( MIB_ULINKER_AUTO, (void *)&intVal);
    if(intVal == 1)
        return req_format_write(wp, "menu.addItem('Setup Wizard', 'skb_wizard.htm', '', 'Setup Wizard');" );
    else
        return req_format_write(wp,"");
#else
    return req_format_write(wp, "menu.addItem('Setup Wizard', 'skb_wizard.htm', '', 'Setup Wizard');" );
#endif
    return intVal;
}


static int pvar_getinfo_wlandrv(request *wp, int argc, char **argv, struct aspvar *v)
{
    const char *name = v->name;
	bss_info bss = { };
    char buffer[128] = "";

	if ( !strcmp(name, "ssid_drv")) {
		if ( getWlBssInfo(WLAN_IF, &bss) < 0)
			return -1;
		memcpy(buffer, bss.ssid, SSID_LEN+1);
		translate_control_code(buffer);
		return req_format_write(wp, "%s", buffer);
	}
	else if ( !strcmp(name, "state_drv")) {
		char *pMsg;
		if ( getWlBssInfo(WLAN_IF, &bss) < 0)
			return -1;
		switch (bss.state) {
		case STATE_DISABLED:
			pMsg = "Disabled";
			break;
		case STATE_IDLE:
			pMsg = "Idle";
			break;
		case STATE_STARTED:
			pMsg = "Started";
			break;
		case STATE_CONNECTED:
			pMsg = "Connected";
			break;
		case STATE_WAITFORKEY:
			pMsg = "Waiting for keys";
			break;
		case STATE_SCANNING:
			pMsg = "Scanning";
			break;
		default:
			pMsg=NULL;
		}
		return req_format_write(wp, "%s", pMsg);
	}
	else if ( !strcmp(name, "channel_drv")) {
		if ( getWlBssInfo(WLAN_IF, &bss) < 0)
			return -1;

		if (bss.channel)
			sprintf(buffer, "%d", bss.channel);
		else
			sprintf(&buffer[0], "무선 기능 OFF");
			//strcpy(buffer,"0");
			//buffer[0] = '\0';

		return req_format_write(wp, "%s", buffer);
	}

    return 0;
}

static int pvar_getinfo_bssid(request *wp, int argc, char **argv, struct aspvar *v)
{
    const char *name = v->name;
    int intVal = 0;
	bss_info bss;
	struct sockaddr hwaddr;
	unsigned char *pMacAddr;

    if ( !strcmp(name, "bssid")) {
		apmib_get( MIB_WLAN_WLAN_DISABLED, (void *)&intVal);
		if ( intVal == 0 &&  getInAddr(WLAN_IF, HW_ADDR, (void *)&hwaddr ) ) {
			pMacAddr = (unsigned char *)hwaddr.sa_data;
			return req_format_write(wp, "%02x:%02x:%02x:%02x:%02x:%02x", pMacAddr[0], pMacAddr[1],
				pMacAddr[2], pMacAddr[3], pMacAddr[4], pMacAddr[5]);
		}
		else
			return req_format_write(wp, "00:00:00:00:00:00");
	}
	else if ( !strcmp(name, "bssid_drv")) {
		if ( getWlBssInfo(WLAN_IF, &bss) < 0)
			return -1;
		return req_format_write(wp, "%02x:%02x:%02x:%02x:%02x:%02x", bss.bssid[0], bss.bssid[1],
				bss.bssid[2], bss.bssid[3], bss.bssid[4], bss.bssid[5]);
	}

    return 0;
}


static int pvar_getinfo_wmm_mode(request *wp, int argc, char **argv, struct aspvar *v)
{
    char wmm_mode[32] = "";
    char buffer[8] = "";
    sprintf(wmm_mode, "x_wlan%d_wme_mode", wlan_idx);
    nvram_get_r_def(wmm_mode, buffer, sizeof(buffer), "2");
    return req_format_write(wp, buffer);
}

static int pvar_getinfo_wan_mac_clone_address(request *wp, int argc, char **argv, struct aspvar *v)
{
    char buffer[48] = "";
    char tmpStr[48] = "";
    int intVal = 0;

    sprintf(buffer, "%s", wp->remote_ip_addr);
    //printf("%s:%d####buffer=%s\n", __FUNCTION__,__LINE__,buffer);
    intVal=get_clone_mac_by_ip(buffer, tmpStr);
    //printf("%s:%d####clone_mac=%s\n", __FUNCTION__,__LINE__,tmpStr);
    if(intVal==0)
    {
        strcpy(buffer, tmpStr);
        return req_format_write(wp, buffer);
    }
    else
    {
        apmib_get(MIB_HW_NIC1_ADDR,  (void *)buffer);
        return req_format_write(wp, "%02x%02x%02x%02x%02x%02x", (unsigned char)buffer[0], (unsigned char)buffer[1],
                (unsigned char)buffer[2], (unsigned char)buffer[3], (unsigned char)buffer[4], (unsigned char)buffer[5]);
    }

    return 0;
}


static int pvar_getinfo_ip_conflict(request *wp, int argc, char **argv, struct aspvar *v)
{
    int ip_conflict=0;
    char buffer[64] = "";
    FILE *fp = NULL;

    sprintf(buffer, "<font size='2' color='green'>없음</font>");
    fp = fopen("/tmp/ip_conflict","r");
    if(fp){
        fscanf(fp,"%d\n", &ip_conflict);
        if(ip_conflict == 1){
            sprintf(buffer, "<font size='2' color='red'>IP 충돌</font>");
        }
        fclose(fp);
    }

    return req_format_write(wp, buffer);
}


static int pvar_getinfo_detect_offer(request *wp, int argc, char **argv, struct aspvar *v)
{
    int port = -1;
    FILE *fp = NULL;

    fp = fopen("/proc/dv_bootp_relay/detect_offer", "r");
    if(fp){
        fscanf(fp, "%d", &port);
        fclose(fp);
    }
    return req_format_write(wp, "%d", port);
}


static int pvar_getinfo_dad_duplecheck(request *wp, int argc, char **argv, struct aspvar *v)
{
    char buffer[64] = "";
    const char *name = v->name;

    if ( !strcmp(name, "dad_duplecheck") ) {
        if (INET6_getflags("br0", buffer) & 0x08)
            return req_format_write(wp, "충돌 [%s]", buffer);
        else
            return req_format_write(wp, "정상");
    }

    return 0;
}


static int pvar_getinfo_dhcp(request *wp, int argc, char **argv, struct aspvar *v)
{
	DHCP_T dhcp;
	struct in_addr	intaddr = { };
    int intVal = 0;
    char buffer[16] = "";
    const char *name = v->name;

 	if ( !strcmp(name, "dhcp-current") ) {
        if ( !apmib_get( MIB_DHCP, (void *)&dhcp) )
            return -1;

        if (dhcp==DHCP_CLIENT) {
            if (!isDhcpClientExist(BRIDGE_IF) &&
                    !getInAddr(BRIDGE_IF, IP_ADDR, (void *)&intaddr))
                return req_format_write(wp, "Getting IP from DHCP server...");
            if (isDhcpClientExist(BRIDGE_IF))
                return req_format_write(wp, "DHCP");
        }
        return req_format_write(wp, "Fixed IP");
    } else if ( !strcmp(name, "dhcpLeaseTime")) {
        apmib_get( MIB_DHCP_LEASE_TIME, (void *)&intVal);
        if( (intVal==0) || (intVal<0) || (intVal>10080))
        {
            intVal = 480;
            if(!apmib_set(MIB_DHCP_LEASE_TIME, (void *)&intVal))
            {
                printf("set MIB_DHCP_LEASE_TIME error\n");
            }

            apmib_update(CURRENT_SETTING);
        }
        sprintf(buffer, "%d", intVal);
        return req_format_write(wp, buffer);
    }

    return 0;
}


static int pvar_getinfo_wlan_xTxR(request *wp, int argc, char **argv, struct aspvar *v)
{
    int intVal = 0;
    const char *name = v->name;

    if(!strcmp(name, "wlan_xTxR")) // 0:non-pocketRouter; 3: Router; 2:Bridge AP; 1:Bridge Client
    {
        int chipVersion = getWLAN_ChipVersion();

#if defined(CONFIG_RTL_8812_SUPPORT)
        return req_format_write(wp, "%s","2*2");
#endif

        if(chipVersion == CHIP_RTL8188C)
            return req_format_write(wp, "%s","1*1");
        else if(chipVersion == CHIP_RTL8192C)
            return req_format_write(wp, "%s","2*2");
#if defined(CONFIG_RTL_92D_SUPPORT)
        else if(chipVersion == CHIP_RTL8192D)
        {
            apmib_get(MIB_WLAN_BAND2G5G_SELECT,(void *)&intVal);
            if(BANDMODEBOTH == intVal)
            {
                return req_format_write(wp, "%s","1*1");
            }
            else
            {
                return req_format_write(wp, "%s","2*2");
            }
        }
#endif
        else if(chipVersion == CHIP_RTL8192E)
            return req_format_write(wp, "%s","2*2");
        else
            return req_format_write(wp, "%s","0*0");
    }

    return 0;
}


static int pvar_getinfo_iplan(request *wp, int argc, char **argv, struct aspvar *v)
{
	struct in_addr	intaddr = { };

    if ( getInAddr(BRIDGE_IF, IP_ADDR, (void *)&intaddr ) )
        return req_format_write(wp, "%s", inet_ntoa(intaddr) );
    else{
        //apmib_get( MIB_IP_ADDR,  (void *)buffer);
        //return req_format_write(wp, "%s", inet_ntoa(*((struct in_addr *)buffer)));

        apmib_get( MIB_IP_ADDR,  (void *)&intaddr);
        return req_format_write(wp, "%s", inet_ntoa(intaddr));

    }
}

static int pvar_getinfo_dvport(request *wp, int argc, char **argv, struct aspvar *v)
{
    const char *name = v->name;
    char buffer[32] = "";
    buffer[0]=0;
    return handle_dvport_mirror(wp, buffer, (char *)name);
}


static int pvar_getinfo_pocketRouter_html(request *wp, int argc, char **argv, struct aspvar *v)
{
    const char *name = v->name;
    int intVal = 0;

    if ( !strcmp(name, "pocketRouter_html_wan_hide_s")) {
		apmib_get( MIB_OP_MODE, (void *)&intVal);
#if defined(CONFIG_POCKET_ROUTER_SUPPORT)
		if(intVal == 0)
			req_format_write(wp, "%s","");
		else if(intVal == 1)
			req_format_write(wp, "%s","<!--");
#elif defined(CONFIG_POCKET_AP_SUPPORT)
		req_format_write(wp, "%s","<!--");
#elif defined(CONFIG_RTL_8198_AP_ROOT) || defined(CONFIG_RTL_8197D_AP)
		req_format_write(wp, "%s","<!--");
#else
		req_format_write(wp, "%s","");
#endif
		return 0;
	}
	else if ( !strcmp(name, "pocketRouter_html_wan_hide_e")) {
		apmib_get( MIB_OP_MODE, (void *)&intVal);
#if defined(CONFIG_POCKET_ROUTER_SUPPORT)
		if(intVal == 0)
			req_format_write(wp, "%s","");
		else if(intVal == 1)
			req_format_write(wp, "%s","-->");
#elif defined(CONFIG_POCKET_AP_SUPPORT)
		req_format_write(wp, "%s","-->");
#elif defined(CONFIG_RTL_8198_AP_ROOT) || defined(CONFIG_RTL_8197D_AP)
		req_format_write(wp, "%s","-->");
#else
		req_format_write(wp, "%s","");
#endif
		return 0;
	}
	else if ( !strcmp(name, "pocketRouter_html_lan_hide_s")) {
		apmib_get( MIB_OP_MODE, (void *)&intVal);
#if defined(CONFIG_POCKET_ROUTER_SUPPORT)
		if(intVal == 1)
			req_format_write(wp, "%s","");
		else if(intVal == 0)
			req_format_write(wp, "%s","<!--");
#else
		req_format_write(wp, "%s","");
#endif
		return 0;
	}
	else if ( !strcmp(name, "pocketRouter_html_lan_hide_e")) {
		apmib_get( MIB_OP_MODE, (void *)&intVal);
#if defined(CONFIG_POCKET_ROUTER_SUPPORT)
		if(intVal == 1)
			req_format_write(wp, "%s","");
		else if(intVal == 0)
			req_format_write(wp, "%s","-->");
#else
		req_format_write(wp, "%s","");
#endif
		return 0;
	}

    return 0;
}


static int pvar_getinfo_pocketRouter_Mode(request *wp, int argc, char **argv, struct aspvar *v)
{
    char buffer[8] = "";
    const char *name = v->name;

    if(!strcmp(name, "pocketRouter_Mode")) // 0:non-pocketRouter; 3: Router; 2:Bridge AP; 1:Bridge Client
	{
#if defined(CONFIG_POCKET_ROUTER_SUPPORT) || defined(CONFIG_RTL_ULINKER)
		apmib_get( MIB_OP_MODE, (void *)&intVal);
		if(intVal == 1) //opmode is bridge
		{
			apmib_get( MIB_WLAN_MODE, (void *)&intVal);
			if(intVal == 0) //wlan is AP mode
			{
				sprintf(buffer, "%s", "2" );
			}
			else if(intVal == 1) //wlan is client mode
			{
				sprintf(buffer, "%s", "1" );
			}
			else
			{
				sprintf(buffer, "%s", "0" );
			}
		}
		else if(intVal == 0) //opmode is router
		{
			sprintf(buffer, "%s", "3" );
		}

#elif defined(CONFIG_POCKET_AP_SUPPORT)
		apmib_get( MIB_WLAN_MODE, (void *)&intVal);
		if(intVal == 0) //wlan is AP mode
 		{
			sprintf(buffer, "%s", "2" );
		} else {
			sprintf(buffer, "%s", "1" );
		}
#else
		sprintf(buffer, "%s", "0");
#endif
		return req_format_write(wp, buffer);
	}
    else if(!strcmp(name, "pocketRouter_Mode_countdown")) // 0:non-pocketRouter; 3: Router; 2:Bridge AP; 1:Bridge Client
	{
#if defined(CONFIG_DOMAIN_NAME_QUERY_SUPPORT) || defined(CONFIG_RTL_ULINKER)
		apmib_get( MIB_OP_MODE, (void *)&intVal);
		if(intVal == 1) //opmode is bridge
		{
			apmib_get( MIB_WLAN_MODE, (void *)&intVal);
			if(intVal == 0) //wlan is AP mode
				sprintf(buffer, "%s", "2" );
			else if(intVal == 1) //wlan is client mode
				sprintf(buffer, "%s", "1" );
			else
				sprintf(buffer, "%s", "0" );
		}
		else if(intVal == 0) //opmode is router
		{
			sprintf(buffer, "%s", "3" );
		}

#else
		sprintf(buffer, "%s", "0");
#endif
		return req_format_write(wp, buffer);
	}

    return 0;
}

static int pvar_getinfo_wlanModeByStr(request *wp, int argc, char **argv, struct aspvar *v)
{
    int intVal = 0;
    char buffer[8] = "";

    if ( !apmib_get( MIB_WLAN_MODE, (void *)&intVal) )
        return -1;
    if(intVal==AP_MODE){
        sprintf(buffer, "%s", "AP");
    }else   if(intVal==CLIENT_MODE){
        sprintf(buffer, "%s", "STA");
    }else{
        sprintf(buffer, "%d", intVal);
    }
    return req_format_write(wp,buffer);
}


static int pvar_getinfo_igmp(request *wp, int argc, char **argv, struct aspvar *v)
{
    const char *name = v->name;
    char buffer[16] = "";
    FILE *fp = NULL;
    int intVal = 0;

    if (!strcmp(name, "cfg_igmp_active")){
		apmib_get(MIB_IGMP_PROXY_DISABLED, (void *)&intVal);
		return req_format_write(wp, "%s",(intVal)?"비활성화":"활성화");
	}
	else if (!strcmp(name, "IGMP_FAST_LEAVE")){
		int intValue =0;
		apmib_get(MIB_IGMP_FAST_LEAVE_DISABLED, (void *)&intValue);
		return req_format_write(wp, "%s",(intValue)?"비활성화":"활성화");
	}
    else if ( !strcmp(name, "igmp_jlimit_enabled")) {
		nvram_get_r_def("x_igmp_joinlimit_enable", buffer, sizeof(buffer), "1");
		if (strcmp(buffer, "1")==0)
			return req_format_write(wp, "checked");
		else
			return req_format_write(wp, "");
	}
	else if ( !strcmp(name, "igmp_querier_enabled") ) {
		int enable=0;
		char *value="";

		fp = fopen("/proc/dv_igmp_query_to_lan", "r");
		if(fp){
			fscanf(fp, "%d\n", &enable);
			fclose(fp);
			if(enable)
				value = "checked";
		}
		return req_format_write(wp, value);
	}
	else if ( !strcmp(name, "igmp_block_enabled") ) {
		if( handle_igmp_block_table(0, (char *)name) )
			sprintf(buffer, "checked");
		else
			buffer[0] = '\0';
		return req_format_write(wp, buffer);
	}
	else if ( !strcmp(name, "igmp_thresh_hold_value") ) {
		sprintf(buffer, "%d", handle_igmp_block_table(1,(char *)name));
		return req_format_write(wp, buffer);
	}
	else if ( !strcmp(name, "igmp_block_period_value") ) {
		sprintf(buffer, "%d", handle_igmp_block_table(1, (char *)name));
		return req_format_write(wp, buffer);
	} else
        return 0;
}


static int pvar_getinfo_clientnum(request *wp, int argc, char **argv, struct aspvar *v)
{
    int intVal = 0;
    char buffer[16] = "";

    apmib_get( MIB_WLAN_WLAN_DISABLED, (void *)&intVal);

    if (intVal == 1)	// disable
        intVal = 0;
    else if(!check_wlan_downup(wlan_idx))//if wlanx down
        intVal = 0;
    else {
        if ( getWlStaNum(WLAN_IF, &intVal) < 0)
            intVal = 0;
    }
    sprintf(buffer, "%d", intVal );
    return req_format_write(wp, buffer);
}


static int pvar_getinfo_loginpagessid(request *wp, int argc, char **argv, struct aspvar *v)
{
    char buffer[128] = "";

    if (argc < 2)
        return -1;

    if (strcmp(argv[1], "24g")==0) {
        nvram_get_r_def( "WLAN1_SSID",  buffer, sizeof(buffer), "");
    } else if (strcmp(argv[1], "5g")==0) {
        nvram_get_r_def( "WLAN0_SSID",  buffer, sizeof(buffer), "");
    } else {
        return -1;
    }

    translate_control_code(buffer);
    return req_format_write(wp, "%s", buffer);
}

static int pvar_getinfo_qos(request *wp, int argc, char **argv, struct aspvar *v)
{
    const char *name = v->name;
    char buffer[8] = "";
    int intVal = 0;
    int val = 0;

#if defined(GW_QOS_ENGINE) || defined(QOS_BY_BANDWIDTH)
    if ( !strcmp(name, "qosEnabled")) {
        if ( !apmib_get( MIB_QOS_ENABLED, (void *)&intVal) )
            return -1;
        if ( intVal == 0 )
            strcpy(buffer, "false");
        else
            strcpy(buffer, "true");
        return req_format_write(wp, buffer);	}
    else if ( !strcmp(name, "qosAutoUplinkSpeed")) {
        if ( !apmib_get( MIB_QOS_AUTO_UPLINK_SPEED, (void *)&intVal) )
            return -1;
        if ( intVal == 0 )
            strcpy(buffer, "false");
        else
            strcpy(buffer, "true");
        return req_format_write(wp, buffer);	}
    else if ( !strcmp(name, "qosAutoDownlinkSpeed")) {
        if ( !apmib_get( MIB_QOS_AUTO_DOWNLINK_SPEED, (void *)&val) )
            return -1;

        if(val == 0)
            sprintf(buffer, "%s", "");
        else
            sprintf(buffer, "%s", "checked");

        return req_format_write(wp, buffer);
    }
#endif

    return 0;
}

#ifdef HOME_GATEWAY
#ifdef VPN_SUPPORT
static int pvar_getinfo_vpn(request *wp, int argc, char **argv, struct aspvar *v)
{
    char *name = v->name;
    char buffer[128] = "";

    if( !strcmp(name, "vpnTblIdx")) {
        sprintf(buffer, "%d", getVpnTblIdx());
        return req_format_write(wp, "%s", buffer);
    }
    else if( !strcmp(name, "ipsecConnName")) {
        if ( getIpsecInfo(&entry) < 0)
            sprintf(buffer, "%s", ""); // default
        else
            sprintf(buffer, "%s", entry.connName);

        return req_format_write(wp, "%s", buffer);
    }
    else if( !strcmp(name, "ipsecLocalIp")) {
        if ( getIpsecInfo(&entry) < 0){
            if(getInAddr(BRIDGE_IF, IP_ADDR, (void *)&intaddr ))
                return req_format_write(wp, "%s", inet_ntoa(intaddr) );
            else{
                if ( !apmib_get( MIB_IP_ADDR,  (void *)buffer) )
                    return req_format_write(wp, "0.0.0.0");
                return req_format_write(wp, "%s", inet_ntoa(*((struct in_addr *)buffer)) );
            }
        }
        else
            return req_format_write(wp, "%s", inet_ntoa(*((struct in_addr *) entry.lc_ipAddr)));
    }
    else if( !strcmp(name, "ipsecLocalIpMask")) {
        if ( getIpsecInfo(&entry) < 0){
            if ( getInAddr(BRIDGE_IF, SUBNET_MASK, (void *)&intaddr ))
                return req_format_write(wp, "%s", inet_ntoa(intaddr) );
            else{
                if ( !apmib_get( MIB_SUBNET_MASK,  (void *)buffer) )
                    return req_format_write(wp, "0.0.0.0");
                return req_format_write(wp, "%s", inet_ntoa(*((struct in_addr *)buffer)) );
            }
        }
        else{
            len2Mask(entry.lc_maskLen, buffer);
            return req_format_write(wp, "%s", buffer);
        }
    }
    else if( !strcmp(name, "ipsecRemoteIp")) {
        if ( getIpsecInfo(&entry) < 0)
            return req_format_write(wp, "0.0.0.0");
        else
            return req_format_write(wp, "%s", inet_ntoa(*((struct in_addr *) entry.rt_ipAddr)));
    }
    else if( !strcmp(name, "ipsecRemoteIpMask")) {
        if ( getIpsecInfo(&entry) < 0)
            return req_format_write(wp, "0.0.0.0");
        else{
            len2Mask(entry.rt_maskLen, buffer);
            return req_format_write(wp, "%s", buffer);
        }
    }
    else if( !strcmp(name, "ipsecRemoteGateway")) {
        if ( getIpsecInfo(&entry) < 0)
            return req_format_write(wp, "0.0.0.0");
        else
            return req_format_write(wp, "%s", inet_ntoa(*((struct in_addr *) entry.rt_gwAddr)));

    }
    else if( !strcmp(name, "ipsecSpi")) {
        if ( getIpsecInfo(&entry) < 0)
            sprintf(buffer, "%s", ""); // default
        else
            sprintf(buffer, "%s",entry.spi);

        return req_format_write(wp, "%s", buffer);
    }
    else if( !strcmp(name, "ipsecEncrKey")) {
        if ( getIpsecInfo(&entry) < 0)
            sprintf(buffer, "%s", ""); // default
        else
            sprintf(buffer, "%s",entry.encrKey);

        return req_format_write(wp, "%s", buffer);
    }
    else if( !strcmp(name, "ipsecAuthKey")) {
        if ( getIpsecInfo(&entry) < 0)
            sprintf(buffer, "%s", ""); // default
        else
            sprintf(buffer, "%s",entry.authKey);

        return req_format_write(wp, "%s", buffer);
    }
    else if( !strcmp(name, "ikePsKey")) {
        if ( getIpsecInfo(&entry) < 0)
            sprintf(buffer, "%s", ""); // default
        else
            sprintf(buffer, "%s",entry.psKey);

        return req_format_write(wp, "%s", buffer);
    }
    else if( !strcmp(name, "ikeLifeTime")) {
        if ( getIpsecInfo(&entry) < 0)
            sprintf(buffer, "%d", 3600); // default
        else
            sprintf(buffer, "%lu",entry.ikeLifeTime);

        return req_format_write(wp, "%s", buffer);
    }
    else if( !strcmp(name, "ikeEncr")) {
        if ( getIpsecInfo(&entry) < 0)
            sprintf(buffer, "%d", TRI_DES_ALGO); // default
        else
            sprintf(buffer, "%d",entry.ikeEncr);

        return req_format_write(wp, "%s", buffer);
    }
    else if( !strcmp(name, "ikeAuth")) {
        if ( getIpsecInfo(&entry) < 0)
            sprintf(buffer, "%d", MD5_ALGO); // default
        else
            sprintf(buffer, "%d",entry.ikeAuth);

        return req_format_write(wp, "%s", buffer);
    }
    else if( !strcmp(name, "ikeKeyGroup")) {
        if ( getIpsecInfo(&entry) < 0)
            sprintf(buffer, "%d", DH2_GRP); // default 768 bits
        else
            sprintf(buffer, "%d",entry.ikeKeyGroup);

        return req_format_write(wp, "%s", buffer);
    }
    else if( !strcmp(name, "ipsecLifeTime")) {
        if ( getIpsecInfo(&entry) < 0)
            sprintf(buffer, "%d", 28800); // default
        else
            sprintf(buffer, "%lu",entry.ipsecLifeTime);

        return req_format_write(wp, "%s", buffer);
    }
    else if( !strcmp(name, "ipsecPfs")) {
        if ( getIpsecInfo(&entry) < 0)
            sprintf(buffer, "%d", 1); // default  on
        else
            sprintf(buffer, "%d",entry.ipsecPfs);

        return req_format_write(wp, "%s", buffer);
    }
    else if( !strcmp(name, "ipsecLocalId")) {
        if ( getIpsecInfo(&entry) < 0)
            sprintf(buffer, "%s", "");
        else
            sprintf(buffer, "%s",entry.lcId);

        return req_format_write(wp, "%s", buffer);
    }
    else if( !strcmp(name, "ipsecRemoteId")) {
        if ( getIpsecInfo(&entry) < 0)
            sprintf(buffer, "%s", "");
        else
            sprintf(buffer, "%s",entry.rtId);

        return req_format_write(wp, "%s", buffer);
    }
    else if( !strcmp(name, "rtRsaKey")) {
        if ( getIpsecInfo(&entry) < 0)
            sprintf(buffer, "%s", "");
        else
            sprintf(buffer, "%s",entry.rsaKey);
        return req_format_write(wp, "%s", buffer);
    }

    return 0;
}
#endif
#endif


#ifdef WLAN_EASY_CONFIG
static int pvar_getinfo_autoCfgAlgReq(request *wp, int argc, char **argv, struct aspvar *v)
{
    char *name = v->name;
    int intVal = 0;
    char buffer[128] = "";

	if ( !strcmp(name, "autoCfgAlgReq")) {
		apmib_get( MIB_WLAN_MODE, (void *)&intVal);
		if (intVal==CLIENT_MODE) { // client
			if ( !apmib_get( MIB_WLAN_EASYCFG_ALG_REQ, (void *)&intVal) )
				return -1;
		}
		else {
			if ( !apmib_get( MIB_WLAN_EASYCFG_ALG_SUPP, (void *)&intVal) )
				return -1;
		}
		buffer[0]='\0';
		if (intVal & ACF_ALGORITHM_WEP64)
			strcat(buffer, "WEP64");
		if (intVal & ACF_ALGORITHM_WEP128) {
			if (strlen(buffer) > 0)
				strcat(buffer, "+");
			strcat(buffer, "WEP128");
		}
		if (intVal & ACF_ALGORITHM_WPA_TKIP) {
			if (strlen(buffer) > 0)
				strcat(buffer, "+");
			strcat(buffer, "WPA_TKIP");
		}
		if (intVal & ACF_ALGORITHM_WPA_AES) {
			if (strlen(buffer) > 0)
				strcat(buffer, "+");
			strcat(buffer, "WPA_AES");
		}
		if (intVal & ACF_ALGORITHM_WPA2_TKIP) {
			if (strlen(buffer) > 0)
				strcat(buffer, "+");
			strcat(buffer, "WPA2_TKIP");
		}
		if (intVal & ACF_ALGORITHM_WPA2_AES) {
			if (strlen(buffer) > 0)
				strcat(buffer, "+");
			strcat(buffer, "WPA2_AES");
		}
   		return req_format_write(wp, buffer);
	}
}
#endif // WLAN_EASY_CONFIG

static int pvar_getinfo_waninfo_rom(request *wp, int argc, char **argv, struct aspvar *v)
{
    const char *name = v->name;
	DHCP_T dhcp;
	OPMODE_T opmode=-1;
	char buffer[40] = "";
    char *iface;
	struct in_addr	intaddr = { };

    if ( !strcmp(name, "wan-ip-rom")) {
#ifdef __DAVO__
        if ( !apmib_get( MIB_WAN_DHCP, (void *)&dhcp) )
            return -1;

        if ( dhcp == DHCP_CLIENT) {
            if ( !apmib_get( MIB_OP_MODE, (void *)&opmode) )
                return -1;
            if (opmode == WISP_MODE)
            {
                iface = WLAN_IF;
                if(!getWlanwanlink(WLAN_IF))
                    iface = NULL;
            }
            else
            {
                iface = (opmode == BRIDGE_MODE)?BRIDGE_IF:WAN_IF;
            }
            if ( iface && get_network_info("wan_ip", buffer) )
                return req_format_write(wp, "%s", buffer);
            else
                return req_format_write(wp, "0.0.0.0");
        } else {
            memset(&intaddr, 0, sizeof(intaddr));
            //if ( !apmib_get( MIB_WAN_IP_ADDR,  (void *)buffer) )
            //return req_format_write(wp, "%s", inet_ntoa(*((struct in_addr *)buffer)) );
            if ( !apmib_get( MIB_WAN_IP_ADDR,  (void *)&intaddr) )
                return -1;
            return req_format_write(wp, "%s", inet_ntoa(intaddr));
        }
#else
        //memset(buffer,0x00,sizeof(buffer));
        //apmib_get( MIB_WAN_IP_ADDR,  (void *)buffer);
        //return req_format_write(wp, "%s", inet_ntoa(*((struct in_addr *)buffer)) );

        memset(&intaddr, 0, sizeof(intaddr));
        apmib_get( MIB_WAN_IP_ADDR,  (void *)&intaddr);
        return req_format_write(wp, "%s", inet_ntoa(intaddr));
#endif
    }
    else if ( !strcmp(name, "wan-mask-rom")) {
#ifdef __DAVO__
        if ( !apmib_get( MIB_WAN_DHCP, (void *)&dhcp) )
            return -1;
        if ( dhcp == DHCP_CLIENT) {
            if ( !apmib_get( MIB_OP_MODE, (void *)&opmode) )
                return -1;
            if (opmode == WISP_MODE)
            {
                iface = WLAN_IF;
                if(!getWlanwanlink(WLAN_IF))
                    iface = NULL;
            }
            else
            {
                iface = (opmode == BRIDGE_MODE)?BRIDGE_IF:WAN_IF;
            }
            if ( iface && get_network_info("netmask", buffer))
                return req_format_write(wp, "%s", buffer);
            else
                return req_format_write(wp, "0.0.0.0");
        } else {
            memset(&intaddr, 0, sizeof(intaddr));
            //if ( !apmib_get( MIB_WAN_SUBNET_MASK,  (void *)buffer) )
            if ( !apmib_get( MIB_WAN_SUBNET_MASK,  (void *)&intaddr) )
                return -1;
            //return req_format_write(wp, "%s", inet_ntoa(*((struct in_addr *)buffer)) );
            return req_format_write(wp, "%s", inet_ntoa(intaddr));
        }
#else
        memset(&intaddr, 0, sizeof(intaddr));
        apmib_get( MIB_WAN_SUBNET_MASK,  (void *)&intaddr);
        return req_format_write(wp, "%s", inet_ntoa(intaddr));

        //memset(buffer,0x00,sizeof(buffer));
        //apmib_get( MIB_WAN_SUBNET_MASK,  (void *)buffer);
        //return req_format_write(wp, "%s", inet_ntoa(*((struct in_addr *)buffer)) );
#endif
    }
    else if ( !strcmp(name, "wan-gateway-rom")) {
#ifdef __DAVO__
        if ( !apmib_get( MIB_WAN_DHCP, (void *)&dhcp) )
            return -1;
        if ( dhcp == DHCP_CLIENT) {
            if ( !apmib_get( MIB_OP_MODE, (void *)&opmode) )
                return -1;
            if (opmode == WISP_MODE)
            {
                iface = WLAN_IF;
                if(!getWlanwanlink(WLAN_IF))
                    iface = NULL;
            }
            else
            {
                if( opmode == BRIDGE_MODE )
                    iface = BRIDGE_IF;
                else
                    iface = WAN_IF;
            }
            if ( iface && get_network_info("gateway", buffer))
                return req_format_write(wp, "%s", buffer);
            else
                return req_format_write(wp, "0.0.0.0");
        } else {
            //if ( !apmib_get( MIB_WAN_DEFAULT_GATEWAY,  (void *)buffer) )
            //    return -1;
            //if (!memcmp(buffer, "\x0\x0\x0\x0", 4))
            //    return req_format_write(wp, "0.0.0.0");
            //return req_format_write(wp, "%s", inet_ntoa(*((struct in_addr *)buffer)) );

            memset(&intaddr, 0, sizeof(intaddr));
            if ( !apmib_get( MIB_WAN_DEFAULT_GATEWAY,  (void *)&intaddr))
                return -1;
            if (!intaddr.s_addr)
                return req_format_write(wp, "0.0.0.0");
            return req_format_write(wp, "%s", inet_ntoa(intaddr));
        }
#else
        memset(&intaddr, 0, sizeof(intaddr));
        apmib_get( MIB_WAN_DEFAULT_GATEWAY,  (void *)&intaddr);
        if (!intaddr.s_addr)
            return req_format_write(wp, "0.0.0.0");
        return req_format_write(wp, "%s", inet_ntoa(intaddr));

        //memset(buffer,0x00,sizeof(buffer));
        //apmib_get( MIB_WAN_DEFAULT_GATEWAY,  (void *)buffer);
        //if (!memcmp(buffer, "\x0\x0\x0\x0", 4))
        //    return req_format_write(wp, "0.0.0.0");
        //return req_format_write(wp, "%s", inet_ntoa(*((struct in_addr *)buffer)) );
#endif
    } else
        return 0;
}


static int pvar_getinfo_waninfo(request *wp, int argc, char **argv, struct aspvar *v)
{
    const char *name = v->name;
	char *iface = NULL;
	OPMODE_T opmode=-1;
	int wispWanId=0;
 	struct user_net_device_stats stats;
	char buffer[128] = "";

#ifdef RK_USB3G
	DHCP_T   wantype = -1;
#endif

    if ( !strcmp(name, "wan-ip"))
    {
#if defined(CONFIG_RTL_8198_AP_ROOT) || defined(CONFIG_RTL_8197D_AP)
        return req_format_write(wp, "%s", "0.0.0.0");
#else
#ifdef _ALPHA_DUAL_WAN_SUPPORT_
        char strWanIP[40];
        char strWanMask[40];
        char strWanDefIP[40];
        char strWanHWAddr[40];
#else
        char strWanIP[20];
        char strWanMask[20];
        char strWanDefIP[20];
        char strWanHWAddr[18];
#endif // _ALPHA_DUAL_WAN_SUPPORT_
#ifdef MULTI_PPPOE
        if(argc >=2 && argv[1])
            checkwan(argv[1]);
#endif
        unsigned int n;
        if ( (n=get_network_info("wan_ip", strWanIP)) == 0)
            getWanInfo(strWanIP,strWanMask,strWanDefIP,strWanHWAddr);
        ydespaces(strWanIP);

        return req_format_write(wp, "%s", strWanIP);
#endif
    }
    else if ( !strcmp(name, "wan-mask")) {
#if defined(CONFIG_RTL_8198_AP_ROOT) || defined(CONFIG_RTL_8197D_AP)
        return req_format_write(wp, "%s", "0.0.0.0");
#else
#ifdef _ALPHA_DUAL_WAN_SUPPORT_
        char strWanIP[40];
        char strWanMask[40];
        char strWanDefIP[40];
        char strWanHWAddr[40];
#else
        char strWanIP[20];
        char strWanMask[20];
        char strWanDefIP[20];
        char strWanHWAddr[18];
#endif // _ALPHA_DUAL_WAN_SUPPORT_
#ifdef MULTI_PPPOE
        if(argc >=2 && argv[1])
            checkwan(argv[1]);
#endif
        unsigned int n;
        if ( (n=get_network_info("netmask", strWanMask)) == 0)
            getWanInfo(strWanIP,strWanMask,strWanDefIP,strWanHWAddr);
        ydespaces(strWanMask);

        return req_format_write(wp, "%s", strWanMask);
#endif
    }
    else if ( !strcmp(name, "wan-gateway")) {
#if defined(CONFIG_RTL_8198_AP_ROOT) || defined(CONFIG_RTL_8197D_AP)
        return req_format_write(wp, "%s", "0.0.0.0");
#else
#ifdef _ALPHA_DUAL_WAN_SUPPORT_
        char strWanIP[40];
        char strWanMask[40];
        char strWanDefIP[40];
        char strWanHWAddr[40];
#else
        char strWanIP[20];
        char strWanMask[20];
        char strWanDefIP[20];
        char strWanHWAddr[18];
#endif // _ALPHA_DUAL_WAN_SUPPORT_
#ifdef MULTI_PPPOE
        if(argc >=2 && argv[1])
            checkwan(argv[1]);
#endif
        unsigned int n;
        if ( (n=get_network_info("gateway", strWanDefIP)) == 0)
            getWanInfo(strWanIP,strWanMask,strWanDefIP,strWanHWAddr);
        ydespaces(strWanDefIP);

        return req_format_write(wp, "%s", strWanDefIP);
#endif
    }
    else if ( !strcmp(name, "wan-hwaddr")) {
#if defined(CONFIG_RTL_8198_AP_ROOT) || defined(CONFIG_RTL_8197D_AP)
        return req_format_write(wp, "%s", "0.0.0.0");
#else
        char strWanIP[16];
        char strWanMask[16];
        char strWanDefIP[16];
        char strWanHWAddr[18];
#ifdef MULTI_PPPOE
        if(argc >=2 && argv[1])
            checkwan(argv[1]);
#endif
        getWanInfo(strWanIP,strWanMask,strWanDefIP,strWanHWAddr);

#ifdef RTK_USB3G
        {   /* when wantype is 3G, we dpn't need to show MAC */
            DHCP_T wan_type;
            apmib_get(MIB_WAN_DHCP, (void *)&wan_type);

            if (wan_type == USB3G)
                return req_format_write(wp, "");
        }
#endif /* #ifdef RTK_USB3G */

        return req_format_write(wp, "%s", strWanHWAddr);
#endif
    }
    else if ( !strcmp(name, "wanTxPacketNum")) {
#ifdef RTK_USB3G
        apmib_get(MIB_WAN_DHCP, (void *)&wantype);
#endif
        apmib_get( MIB_OP_MODE, (void *)&opmode);
        if( !apmib_get(MIB_WISP_WAN_ID, (void *)&wispWanId))
            return -1;
        if(opmode == WISP_MODE) {
            if(0 == wispWanId)
                iface = "wlan0";
            else if(1 == wispWanId)
                iface = "wlan1";
        }
#ifdef RTK_USB3G
        else if (wantype == USB3G)
            iface = PPPOE_IF;
#endif
        else
            iface = WAN_IF;
        if ( getStats(iface, &stats) < 0)
            stats.tx_bytes = 0;
        sprintf(buffer, "%llu", stats.tx_bytes);
        return req_format_write(wp, buffer);
    }
    else if ( !strcmp(name, "wanRxPacketNum")) {
#ifdef RTK_USB3G
        apmib_get(MIB_WAN_DHCP, (void *)&wantype);
#endif
        apmib_get( MIB_OP_MODE, (void *)&opmode);
        if( !apmib_get(MIB_WISP_WAN_ID, (void *)&wispWanId))
            return -1;

        if(opmode == WISP_MODE) {
            if(0 == wispWanId)
                iface = "wlan0";
            else if(1 == wispWanId)
                iface = "wlan1";
        }
#ifdef RTK_USB3G
        else if (wantype == USB3G)
            iface = PPPOE_IF;
#endif
        else
            iface = WAN_IF;
        if ( getStats(iface, &stats) < 0)
            stats.rx_bytes = 0;
        sprintf(buffer, "%llu", stats.rx_bytes);
        return req_format_write(wp, buffer);
    } else
        return 0;
}


static int pvar_getinfo_verinfo(request *wp, int argc, char **argv, struct aspvar *v)
{
    const char *name = v->name;
    char buffer[128] = "";

    if ( !strcmp(name, "fwVersion")) {
		get_firmVersion(buffer);
   		return req_format_write(wp, buffer);
	}
	// added by rock /////////////////////////////////////////
	else if ( !strcmp(name, "buildTime")) {
		FILE *fp;
		regex_t re;
		regmatch_t match[2];
		int status;

		fp = fopen("/proc/version", "r");
		if (!fp) {
			fprintf(stderr, "Read /proc/version failed!\n");
			return req_format_write(wp, "Unknown");
	   	}
		else
		{
			fgets(buffer, sizeof(buffer), fp);
			fclose(fp);
		}

		if (regcomp(&re, "#[0-9][0-9]* \\(.*\\)$", 0) == 0)
		{
			status = regexec(&re, buffer, 2, match, 0);
			regfree(&re);
			if (status == 0 &&
				match[1].rm_so >= 0)
			{
				buffer[match[1].rm_eo] = 0;
   				return req_format_write(wp, &buffer[match[1].rm_so]);
			}
		}

		return req_format_write(wp, "Unknown");
	} else
        return 0;
}


static int pvar_getinfo_gateway(request *wp, int argc, char **argv, struct aspvar *v)
{
	struct in_addr	intaddr = { };
    DHCP_T dhcp;
    apmib_get( MIB_DHCP, (void *)&dhcp);
    if ( dhcp == DHCP_SERVER ) {
        // if DHCP server, default gateway is set to LAN IP
        if ( getInAddr(BRIDGE_IF, IP_ADDR, (void *)&intaddr ) )
            return req_format_write(wp, "%s", inet_ntoa(intaddr) );
        else
            return req_format_write(wp, "0.0.0.0");
    }
    else
        if ( getDefaultRoute(BRIDGE_IF, &intaddr) )
            return req_format_write(wp, "%s", inet_ntoa(intaddr) );
        else
            return req_format_write(wp, "0.0.0.0");

    return 0;
}


static int pvar_getinfo_include_css(request *wp, int argc, char **argv, struct aspvar *v)
{
    return getIncludeCss(wp);
}


static int pvar_getinfo_getWanlink(request *wp, int argc, char **argv, struct aspvar *v)
{
	char buffer[4] = "";

    int ret = getWanLink("eth1");
    if (ret < 0)
        sprintf(buffer, "%s", "0");
    else
        sprintf(buffer, "%s", "1");
    return req_format_write(wp, buffer);
}

#if 0
static int pvar_getinfo_userName(request *wp, int argc, char **argv, struct aspvar *v)
{
    char buffer[128] = "";
    //char user[32] = "";
    //unsigned char decode_user[32] = "";
    buffer[0]='\0';
    //if ( !apmib_get(MIB_USER_NAME,  (void *)buffer) )
    //    return -1;
    //memset(decode_user, 0, sizeof(decode_user));
    //b64_decode((const char *)buffer, decode_user, sizeof(decode_user));
    //shift_str((char *)decode_user, user, DECRYPT_ADD_VAL);
    //return req_format_write(wp, T("%s"), user);
	nvram_get_r_def("x_USER_NAME", buffer, sizeof(buffer), "");
    return req_format_write(wp, T("%s"), buffer);
}
#endif

static int pvar_getinfo_wpskey(request *wp, int argc, char **argv, struct aspvar *v)
{
    const char *name = v->name;
    char buffer[256] = "";
	int intVal;

#ifdef WIFI_SIMPLE_CONFIG
 	if ( !strcmp(name, "wps_key")) {
 		int id;
		apmib_get(MIB_WLAN_WSC_ENC, (void *)&intVal);
		buffer[0]='\0';
		if (intVal == WSC_ENCRYPT_WEP) {
			unsigned char tmp[100];
			apmib_get(MIB_WLAN_WEP, (void *)&intVal);
			apmib_get(MIB_WLAN_WEP_DEFAULT_KEY, (void *)&id);
			if (intVal == 1) {
				if (id == 0)
					id = MIB_WLAN_WEP64_KEY1;
				else if (id == 1)
					id = MIB_WLAN_WEP64_KEY2;
				else if (id == 2)
					id = MIB_WLAN_WEP64_KEY3;
				else
					id = MIB_WLAN_WEP64_KEY4;
				apmib_get(id, (void *)tmp);
				convert_bin_to_str(tmp, 5, buffer);
			}
			else {
				if (id == 0)
					id = MIB_WLAN_WEP128_KEY1;
				else if (id == 1)
					id = MIB_WLAN_WEP128_KEY2;
				else if (id == 2)
					id = MIB_WLAN_WEP128_KEY3;
				else
					id = MIB_WLAN_WEP128_KEY4;
				apmib_get(id, (void *)tmp);
				convert_bin_to_str(tmp, 13, buffer);
			}
		}
		else {
			if (intVal==0 || intVal == WSC_ENCRYPT_NONE)
				strcpy(buffer, "N/A");
			else
				apmib_get(MIB_WLAN_WSC_PSK, (void *)buffer);
		}
   		return req_format_write(wp, buffer);
	}
	else if ( !strcmp(name, "wpsRpt_key"))
	{
#if defined(UNIVERSAL_REPEATER) && defined(CONFIG_REPEATER_WPS_SUPPORT)
 		int id;
	    int wlan_idx_keep = wlan_idx;
	    char tmpStr[20] = "";
 		SetWlan_idx("wlan0-vxd");
		apmib_get(MIB_WLAN_WSC_ENC, (void *)&intVal);
		buffer[0]='\0';
		if (intVal == WSC_ENCRYPT_WEP) {
			unsigned char tmp[100];
			apmib_get(MIB_WLAN_WEP, (void *)&intVal);
			apmib_get(MIB_WLAN_WEP_DEFAULT_KEY, (void *)&id);
			if (intVal == 1) {
				if (id == 0)
					id = MIB_WLAN_WEP64_KEY1;
				else if (id == 1)
					id = MIB_WLAN_WEP64_KEY2;
				else if (id == 2)
					id = MIB_WLAN_WEP64_KEY3;
				else
					id = MIB_WLAN_WEP64_KEY4;
				apmib_get(id, (void *)tmp);
				convert_bin_to_str(tmp, 5, buffer);
			}
			else {
				if (id == 0)
					id = MIB_WLAN_WEP128_KEY1;
				else if (id == 1)
					id = MIB_WLAN_WEP128_KEY2;
				else if (id == 2)
					id = MIB_WLAN_WEP128_KEY3;
				else
					id = MIB_WLAN_WEP128_KEY4;
				apmib_get(id, (void *)tmp);
				convert_bin_to_str(tmp, 13, buffer);
			}
		}
		else {
			if (intVal==0 || intVal == WSC_ENCRYPT_NONE)
				strcpy(buffer, "N/A");
			else
				apmib_get(MIB_WLAN_WSC_PSK, (void *)buffer);
		}

		wlan_idx = wlan_idx_keep;
		sprintf(tmpStr,"wlan%d",wlan_idx);
		SetWlan_idx(tmpStr);
		//SetWlan_idx("wlan0");

#else
	bzero(buffer,sizeof(buffer));
#endif //#if defined(UNIVERSAL_REPEATER) && defined(CONFIG_REPEATER_WPS_SUPPORT)
   		return req_format_write(wp, buffer);
	}

#endif 	// WIFI_SIMPLE_CONFIG
    return 0;

}

static int pvar_getinfo_encrypttype(request *wp, int argc, char **argv, struct aspvar *v)
{
	const char *name = v->name;
	char buffer[16] = "";

    if ( !strcmp(name, "wdsEncrypt")) {
        WDS_ENCRYPT_T encrypt;
        if ( !apmib_get( MIB_WLAN_WDS_ENCRYPT,  (void *)&encrypt) )
            return -1;
        if ( encrypt == WDS_ENCRYPT_DISABLED)
            strcpy( buffer, "Disabled");
        else if ( encrypt == WDS_ENCRYPT_WEP64)
            strcpy( buffer, "WEP 64bits");
        else if ( encrypt == WDS_ENCRYPT_WEP128)
            strcpy( buffer, "WEP 128bits");
        else if ( encrypt == WDS_ENCRYPT_TKIP)
            strcpy( buffer, "TKIP");
        else if ( encrypt == WDS_ENCRYPT_AES)
            strcpy( buffer, "AES");
        else
            buffer[0] = '\0';
        return req_format_write(wp, buffer);
    }
    else if ( !strcmp(name, "meshEncrypt")) {
#ifdef CONFIG_RTK_MESH
        ENCRYPT_T encrypt;
        if ( !apmib_get( MIB_WLAN_MESH_ENCRYPT,  (void *)&encrypt) )
            return -1;
        if ( encrypt == ENCRYPT_DISABLED)
            strcpy( buffer, "Disabled");
        else if ( encrypt == ENCRYPT_WPA2)
            strcpy( buffer, "WPA2");
        else
            buffer[0] = '\0';
        return req_format_write(wp, buffer);
#endif
        return req_format_write(wp, "0");
    }
    else
        return 0;
}


static int pvar_getinfo_link_status(request *wp, int argc, char **argv, struct aspvar *v)
{
    const char *name = v->name;
    char buffer[64] = "";
    char var[32] = "";
    int portno = (!strncmp(name, "wan", 3)) ? 4 : (name[3] - '0')-1;
    unsigned int phy_status = switch_port_status(portno);
    int mask = 0;

    sprintf(var, "x_port_%d_config", portno);
    nvram_get_r_def(var, buffer, sizeof(buffer), "up_auto_-rxpause_-txpause");

    if ((phy_status & PHF_LINKUP))
        mask |= 1;
    if ((phy_status & PHF_100M))
        mask |= 2;
    else if ((phy_status & PHF_500M))
        mask |= 4;
    else if ((phy_status & PHF_1000M))
        mask |= 6;
    if ((phy_status & PHF_FDX))
        mask |= 8;

    mask |= 0x20;
    mask |= 0x10;
    if (strstr(buffer, "down"))
        mask &= ~0x10;
    if (strstr(buffer, "half"))
        mask |= 0x40;
    if (strstr(buffer, "1000")) {
        mask |= 0x100;
    } else if (!strstr(buffer, "100"))
        mask |= 0x80;
    if (strstr(buffer, "auto"))
        mask &= ~0x20;
    return req_format_write(wp, "%d", (strstr(name, "linkUp")) ? (mask & 1) : mask);
}


static int pvar_getinfo_link_duplex(request *wp, int argc, char **argv, struct aspvar *v)
{
    const char *name = v->name;
    int duplex = 0;
    int portno = (!strncmp(name, "wan", 3)) ? 4 : (name[3] - '0')-1;
    unsigned int phy_status = switch_port_status(portno);

    if ((phy_status & PHF_LINKUP) && (phy_status & PHF_FDX))
        duplex = 2;
    else if ((phy_status & PHF_LINKUP) && !(phy_status & PHF_FDX))
        duplex = 1;
    else
        duplex = 0;

    return req_format_write(wp, "%d", duplex);
}


static int pvar_getinfo_pause_status(request *wp, int argc, char **argv, struct aspvar *v)
{
    const char *name = v->name;
    return req_format_write(wp, "%d",
            pause_status((!strncmp(name, "wan", 3)) ? 4 : (name[3] - '0')-1,
                !!strstr(name, "tx")));
}


#if defined(CONFIG_RTK_VLAN_WAN_TAG_SUPPORT)
static int pvar_getinfo_rtkvlan(request *wp, int argc, char **argv, struct aspvar *v)
{
    char *name = v->name;
    char buffer[16] = "";
	if(!strcmp(name, "vlan_wan_enable"))
	{
		apmib_get( MIB_VLAN_WAN_ENALE, (void *)&intVal);
		sprintf(buffer, "%s", intVal ? "checked" : "");
		return req_format_write(wp, buffer);
	}
	else if(!strcmp(name, "vlan_wan_bridge_enable"))
	{
		apmib_get( MIB_VLAN_WAN_BRIDGE_ENABLE, (void *)&intVal);
		sprintf(buffer, "%s", intVal ? "checked" : "");
		return req_format_write(wp, buffer);
	}
	else if(!strcmp(name, "vlan_wan_bridge_port_0"))
	{
		apmib_get( MIB_VLAN_WAN_BRIDGE_PORT, (void *)&intVal);
		sprintf(buffer, "%s", (intVal&(1<<3)) ? "checked" : "");
		return req_format_write(wp, buffer);
	}
	else if(!strcmp(name, "vlan_wan_bridge_port_1"))
	{
		apmib_get( MIB_VLAN_WAN_BRIDGE_PORT, (void *)&intVal);
		sprintf(buffer, "%s", (intVal&(1<<2)) ? "checked" : "");
		return req_format_write(wp, buffer);
	}
	else if(!strcmp(name, "vlan_wan_bridge_port_2"))
	{
		apmib_get( MIB_VLAN_WAN_BRIDGE_PORT, (void *)&intVal);
		sprintf(buffer, "%s", (intVal&(1<<1)) ? "checked" : "");
		return req_format_write(wp, buffer);
	}
	else if(!strcmp(name, "vlan_wan_bridge_port_3"))
	{
		apmib_get( MIB_VLAN_WAN_BRIDGE_PORT, (void *)&intVal);
		sprintf(buffer, "%s", (intVal&(1<<0)) ? "checked" : "");
		return req_format_write(wp, buffer);
	}
	else if(!strcmp(name, "vlan_wan_bridge_port_wifi_root"))
	{
		apmib_get( MIB_VLAN_WAN_BRIDGE_PORT, (void *)&intVal);
		sprintf(buffer, "%s", (intVal&(1<<6)) ? "checked" : "");
		return req_format_write(wp, buffer);
	}
	else if(!strcmp(name, "vlan_wan_bridge_port_wifi_vap0"))
	{
		apmib_get( MIB_VLAN_WAN_BRIDGE_PORT, (void *)&intVal);
		sprintf(buffer, "%s", (intVal&(1<<7)) ? "checked" : "");
		return req_format_write(wp, buffer);
	}
	else if(!strcmp(name, "vlan_wan_bridge_port_wifi_vap1"))
	{
		apmib_get( MIB_VLAN_WAN_BRIDGE_PORT, (void *)&intVal);
		sprintf(buffer, "%s", (intVal&(1<<8)) ? "checked" : "");
		return req_format_write(wp, buffer);
	}
	else if(!strcmp(name, "vlan_wan_bridge_port_wifi_vap2"))
	{
		apmib_get( MIB_VLAN_WAN_BRIDGE_PORT, (void *)&intVal);
		sprintf(buffer, "%s", (intVal&(1<<9)) ? "checked" : "");
		return req_format_write(wp, buffer);
	}
	else if(!strcmp(name, "vlan_wan_bridge_port_wifi_vap3"))
	{
		apmib_get( MIB_VLAN_WAN_BRIDGE_PORT, (void *)&intVal);
		sprintf(buffer, "%s", (intVal&(1<<10)) ? "checked" : "");
		return req_format_write(wp, buffer);
	}
	else if(!strcmp(name, "vlan_wan_bridge_multicast_enable"))
	{
		apmib_get( MIB_VLAN_WAN_BRIDGE_MULTICAST_ENABLE, (void *)&intVal);
		sprintf(buffer, "%s", intVal ? "checked" : "");
		return req_format_write(wp, buffer);
	}
	else if(!strcmp(name, "vlan_wan_host_enable"))
	{
		apmib_get( MIB_VLAN_WAN_HOST_ENABLE, (void *)&intVal);
		sprintf(buffer, "%s", intVal ? "checked" : "");
		return req_format_write(wp, buffer);
	}
	else if(!strcmp(name, "vlan_wan_wifi_root_enable"))
	{
		apmib_get( MIB_VLAN_WAN_WIFI_ROOT_ENABLE, (void *)&intVal);
		sprintf(buffer, "%s", intVal ? "checked" : "");
		return req_format_write(wp, buffer);
	}
	else if(!strcmp(name, "vlan_wan_wifi_vap0_enable"))
	{
		apmib_get( MIB_VLAN_WAN_WIFI_VAP0_ENABLE, (void *)&intVal);
		sprintf(buffer, "%s", intVal ? "checked" : "");
		return req_format_write(wp, buffer);
	}
	else if(!strcmp(name, "vlan_wan_wifi_vap1_enable"))
	{
		apmib_get( MIB_VLAN_WAN_WIFI_VAP1_ENABLE, (void *)&intVal);
		sprintf(buffer, "%s", intVal ? "checked" : "");
		return req_format_write(wp, buffer);
	}
	else if(!strcmp(name, "vlan_wan_wifi_vap2_enable"))
	{
		apmib_get( MIB_VLAN_WAN_WIFI_VAP2_ENABLE, (void *)&intVal);
		sprintf(buffer, "%s", intVal ? "checked" : "");
		return req_format_write(wp, buffer);
	}
	else if(!strcmp(name, "vlan_wan_wifi_vap3_enable"))
	{
		apmib_get( MIB_VLAN_WAN_WIFI_VAP3_ENABLE, (void *)&intVal);
		sprintf(buffer, "%s", intVal ? "checked" : "");
		return req_format_write(wp, buffer);
	}

    return 0;
}
#endif


#ifdef __DAVO__
static int pvar_getinfo_davovlan(request *wp, int argc, char **argv, struct aspvar *v)
{
    int index = 0;
    char strVar[16] = "";
    char tmpBuf[100] = "";
    int vid = 0;
    const char *name = v->name;

    //DAVO VLan Section
	if (!strcmp(name, "wan_vlan_pvid")) {

		if (nvram_get_r("x_VLAN_PORT_4", tmpBuf, sizeof(tmpBuf))) {
			index = strtoul(tmpBuf, NULL, 0);
			if (index >= 0 && index < 16) {
				index += 1;
			} else
			 index = 0;
		}
		return req_format_write(wp, "%d", index);
	}
	else if (!strcmp(name, "lan1_vlan_pvid")) {

		if (nvram_get_r("x_VLAN_PORT_0", tmpBuf, sizeof(tmpBuf))) {
			index = strtoul(tmpBuf, NULL, 0);
			if (index >= 0 && index < 16) {
				index += 1;
			} else
				 index = 0;
		}
		return req_format_write(wp, "%d", index);
	}
	else if (!strcmp(name, "lan2_vlan_pvid")) {

		if (nvram_get_r("x_VLAN_PORT_1", tmpBuf, sizeof(tmpBuf))) {
			index = strtoul(tmpBuf, NULL, 0);
			if (index >= 0 && index < 16) {
				index += 1;
			} else
				 index = 0;
		}
		return req_format_write(wp, "%d", index);
	}
	else if (!strcmp(name, "lan3_vlan_pvid")) {

		if (nvram_get_r("x_VLAN_PORT_2", tmpBuf, sizeof(tmpBuf))) {
			index = strtoul(tmpBuf, NULL, 0);
			if (index >= 0 && index < 16) {
				index += 1;
			} else
				 index = 0;
		}
		return req_format_write(wp, "%d", index);
	}
	else if (!strcmp(name, "lan4_vlan_pvid")) {

		if (nvram_get_r("x_VLAN_PORT_3", tmpBuf, sizeof(tmpBuf))) {
			index = strtoul(tmpBuf, NULL, 0);
			if (index >= 0 && index < 16) {
				index += 1;
			} else
				 index = 0;
		}
		return req_format_write(wp, "%d", index);
	}
	else if (!strncmp(name, "vlan_id_", strlen("vlan_id_"))) {
		sscanf(name, "vlan_id_%d", &index);
        //sprintf(index, "%d", argv[1]);
        //index = atoi(argv[1]);
		if (index >= 0 && index < 16) {
			sprintf(strVar, "x_VLAN_%d", index);

			if ( nvram_get_r(strVar, tmpBuf, sizeof(tmpBuf))){
				vid = atoi(tmpBuf);
				if (vid > 0 && vid < 4096)
					return req_format_write(wp, "%d", vid);
			}
		}
		return req_format_write(wp, "0", "");
	}
	else if (!strncmp(name, "vlan_port_", strlen("vlan_port_"))) {

		sscanf(name, "vlan_port_%d", &index);
        //sprintf(index, "%d", argv[1]);
        //index = atoi(argv[1]);
		if (index >= 0 && index < 16) {
			sprintf(strVar, "x_VLAN_%d", index);

			if ( nvram_get_r(strVar, tmpBuf, sizeof(tmpBuf))){
				char *ptr = strchr(tmpBuf, '_');
				char *ptr2;

				if (ptr && strlen(ptr) > 1) {
					int tagged_port;

					ptr += 1;
					ptr2 = strchr(ptr, '_');
					ptr[ptr2-ptr] = 0;

					tagged_port = strtol(ptr, NULL, 16);

					return req_format_write(wp, "%d", tagged_port);
				}
			}
		}
		return req_format_write(wp, "0", "");
	}
	else if (!strncmp(name, "vlan_tagged_", strlen("vlan_tagged_"))) {

		sscanf(name, "vlan_tagged_%d", &index);
        //sprintf(index, "%d", argv[1]);
        //index = atoi(argv[1]);
		if (index >= 0 && index < 16) {
			sprintf(strVar, "x_VLAN_%d", index);

			if ( nvram_get_r(strVar, tmpBuf, sizeof(tmpBuf))){
				char *ptr = strchr(tmpBuf, '_');
				char *ptr2;

				if (ptr && strlen(ptr) > 1) {
					int tagged_val;

					ptr += 1;
					ptr2 = strchr(ptr, '_');
					if (ptr2 && strlen(ptr2) > 1) {
						ptr2 += 1;
						tagged_val = strtol(ptr2, NULL, 16);
						return req_format_write(wp, "%d", tagged_val);
					}
				}
			}
		}
		return req_format_write(wp, "0", "");
	}

    return 0;
}
#endif


static int pvar_getinfo_wlprofile(request *wp, int argc, char **argv, struct aspvar *v)
{
    const char *name = v->name;

    if(!strcmp(name, "wlProfile_checkbox"))
    {
        int profile_enabled_id, wlProfileEnabled;
#if defined(WLAN_PROFILE)
        if(wlan_idx == 0)
        {
            profile_enabled_id = MIB_PROFILE_ENABLED1;
        }
        else
        {
            profile_enabled_id = MIB_PROFILE_ENABLED2;
        }

        apmib_get( profile_enabled_id, (void *)&wlProfileEnabled);

        if(wlProfileEnabled == 1)
            return req_format_write(wp, "%s", "checked");
        else
#endif //#if defined(WLAN_PROFILE)
            return req_format_write(wp, "%s", "");
    }
    else if(!strcmp(name, "wlProfile_value"))
    {
        int profile_enabled_id, wlProfileEnabled;
#if defined(WLAN_PROFILE)
        if(wlan_idx == 0)
        {
            profile_enabled_id = MIB_PROFILE_ENABLED1;
        }
        else
        {
            profile_enabled_id = MIB_PROFILE_ENABLED2;
        }

        apmib_get( profile_enabled_id, (void *)&wlProfileEnabled);

        if(wlProfileEnabled == 1)
            return req_format_write(wp, "%s", "1");
        else
#endif //#if defined(WLAN_PROFILE)
            return req_format_write(wp, "%s", "0");
    }
    else if(!strcmp(name, "wlan_profile_num"))
    {
#if defined(WLAN_PROFILE)
        int profile_num_id, entryNum;
        if(wlan_idx == 0)
        {
            profile_num_id = MIB_PROFILE_NUM1;
        }
        else
        {
            profile_num_id = MIB_PROFILE_NUM2;
        }

        apmib_get(profile_num_id, (void *)&entryNum);
        return req_format_write(wp, "%d", entryNum);
#else
        return req_format_write(wp, "%s", "0");
#endif //#if defined(WLAN_PROFILE)
    }
    else if(!strcmp(name, "wlEnableProfile"))
    {
#if defined(WLAN_PROFILE)
        int profile_enabled_id, profileEnabledVal;
        if(wlan_idx == 0)
        {
            profile_enabled_id = MIB_PROFILE_ENABLED1;
        }
        else
        {
            profile_enabled_id = MIB_PROFILE_ENABLED2;
        }

        apmib_get(profile_enabled_id, (void *)&profileEnabledVal);
        return req_format_write(wp, "%d", profileEnabledVal);
#else
        return req_format_write(wp, "%s", "0");
#endif //#if defined(WLAN_PROFILE)
    }

    return 0;
}


#ifdef HOME_GATEWAY
static int pvar_getinfo_wanDhcp_current(request *wp, int argc, char **argv, struct aspvar *v)
{
    int isWanPhy_Link=0;
    OPMODE_T opmode=-1;
    DHCP_T dhcp;
    char buffer[16] = "";
    char *iface=NULL;
    int wispWanId=0;
    bss_info bss;

#ifdef __DAVO__
    isWanPhy_Link = switch_port_status(4);

    if ( !apmib_get( MIB_OP_MODE, (void *)&opmode) )
        return -1;
    if (opmode == BRIDGE_MODE)
        return req_format_write(wp, "HUB 모드 사용 중");
    if ( !apmib_get( MIB_WAN_DHCP, (void *)&dhcp) )
        return -1;

    if ( dhcp == DHCP_CLIENT) {
        iface = (opmode == WISP_MODE)?WLAN_IF:WAN_IF;
        if (nvram_get_r("x_SDMZ_ENABLED", buffer, sizeof(buffer))) {
            if( !strcmp(buffer,"1")){
                if(isWanPhy_Link& PHF_LINKUP)
                    return req_format_write(wp, "Super DMZ");
                else
                    return req_format_write(wp, "Super DMZ /WAN 연결해제 상태");
            }
        }
        if (!isDhcpClientExist(iface))
            return req_format_write(wp, "DHCP 서버로부터 IP 획득중..");
        else{
            if(!(isWanPhy_Link& PHF_LINKUP))
                return req_format_write(wp, "DHCP /WAN 연결해제 상태");
            else
                return req_format_write(wp, "DHCP IP 획득 성공");
        }
    }
    else if ( dhcp == DHCP_DISABLED ){
        if(!(isWanPhy_Link& PHF_LINKUP))
            return req_format_write(wp, "고정 IP /WAN 연결해제 상태");
        else
            return req_format_write(wp, "고정 IP 연결됨");
    }
    else if ( dhcp ==  PPPOE ) {
        if ( isConnectPPP()){
            if(!(isWanPhy_Link& PHF_LINKUP))
                return req_format_write(wp, "PPPoE /WAN 연결해제 상태");
            else
                return req_format_write(wp, "PPPoE 연결됨");
        }else {
            return req_format_write(wp, "PPPoE 연결안됨");
        }
    }
    else if ( dhcp ==  PPTP ) {
        if ( isConnectPPP()){
            if(!(isWanPhy_Link& PHF_LINKUP))
                return req_format_write(wp, "PPTP /WAN 연결해제 상태");
            else
                return req_format_write(wp, "PPTP 연결됨");
        }else {
            return req_format_write(wp, "PPTP 연결안됨");
        }
    }
    else if (dhcp == L2TP) {
        if ( isConnectPPP()){
            if(!(isWanPhy_Link& PHF_LINKUP))
                return req_format_write(wp, "L2TP 연결안됨");
            else
                return req_format_write(wp, "L2TP 연결됨");
        }else {
            return req_format_write(wp, "L2TP 연결안됨");
        }
    }
#endif
#if defined(CONFIG_RTL_8198_AP_ROOT) || defined(CONFIG_RTL_8197D_AP)
    return req_format_write(wp, "Brian 5BGG");
#else
#ifdef MULTI_PPPOE
    if(argc >=2 && argv[1])
        checkwan(argv[1]);
#endif

    if ( !apmib_get( MIB_OP_MODE, (void *)&opmode) )
        return -1;
    if( !apmib_get(MIB_WISP_WAN_ID, (void *)&wispWanId))
        return -1;
    if ( !apmib_get( MIB_WAN_DHCP, (void *)&dhcp) )
        return -1;

    if(opmode == BRIDGE_MODE){
        return req_format_write(wp, "Disconnected");
    }

    if(opmode != WISP_MODE){
        isWanPhy_Link=getWanLink("eth1");
    }
    if ( dhcp == DHCP_CLIENT) {
        if(opmode == WISP_MODE) {
            if(0 == wispWanId)
                iface = "wlan0";
            else if(1 == wispWanId)
                iface = "wlan1";
#ifdef CONFIG_SMART_REPEATER
            if(getWispRptIface(&iface,wispWanId)<0)
                return -1;
#endif

        }
        else
            iface = WAN_IF;
        if (!isDhcpClientExist(iface))
            return req_format_write(wp, "Getting IP from DHCP server...");
        else{
            if(isWanPhy_Link < 0)
                return req_format_write(wp, "Getting IP from DHCP server...");
            else
                return req_format_write(wp, "DHCP");
        }

    }
    else if ( dhcp == DHCP_DISABLED ){
        if (opmode == WISP_MODE)
        {
            char wan_intf[MAX_NAME_LEN] = {0};
            char lan_intf[MAX_NAME_LEN] = {0};

            getInterfaces(lan_intf,wan_intf);
            //printf("%s %d wan_intf=%s \n", __FUNCTION__, __LINE__, wan_intf);
            memset(&bss, 0x00, sizeof(bss));
            getWlBssInfo(wan_intf, &bss);
            //printf("%s %d wan_intf=%s bss.state=%d\n", __FUNCTION__, __LINE__, wan_intf, bss.state);
            if (bss.state == STATE_CONNECTED){
                return req_format_write(wp, "Fixed IP Connected");
            }
            else
            {
                return req_format_write(wp, "Fixed IP Disconnected");
            }
        }
        else
        {
            if(isWanPhy_Link < 0)
                return req_format_write(wp, "Fixed IP Disconnected");
            else
                return req_format_write(wp, "Fixed IP Connected");
        }
    }
    else if ( dhcp ==  PPPOE ) {

#ifdef _ALPHA_DUAL_WAN_SUPPORT_
        int pppoeWithDhcpEnabled = 0;

        apmib_get(MIB_PPPOE_DHCP_ENABLED, (void *)&pppoeWithDhcpEnabled);

        if (pppoeWithDhcpEnabled) {

            if ( isConnectPPP()){
#ifdef MULTI_PPPOE
                req_format_write(wp, "PPPoE Connected");
#endif
                if(isWanPhy_Link < 0)
                    req_format_write(wp, "PPPoE Disconnected");
                else
                    req_format_write(wp, "PPPoE Connected");
            }else
                req_format_write(wp, "PPPoE Disconnected");
        }
        else {
            if ( isConnectPPP()){
#ifdef MULTI_PPPOE
                return req_format_write(wp, "PPPoE Connected");
#endif
                if(isWanPhy_Link < 0)
                    return req_format_write(wp, "PPPoE Disconnected");
                else
                    return req_format_write(wp, "PPPoE Connected");
            }else
                return req_format_write(wp, "PPPoE Disconnected");
        }
#else // _ALPHA_DUAL_WAN_SUPPORT_
        if ( isConnectPPP()){
#ifdef MULTI_PPPOE
            return req_format_write(wp, "PPPoE Connected");
#endif
            if(isWanPhy_Link < 0)
                return req_format_write(wp, "PPPoE Disconnected");
            else
                return req_format_write(wp, "PPPoE Connected");
        }else
            return req_format_write(wp, "PPPoE Disconnected");
#endif // _ALPHA_DUAL_WAN_SUPPORT_

#ifdef _ALPHA_DUAL_WAN_SUPPORT_
        {
            if (pppoeWithDhcpEnabled) {
                iface = WAN_IF;

                if (!isDhcpClientExist(iface))
                    return req_format_write(wp, " and Getting IP from DHCP server...");
                else{
                    if(isWanPhy_Link < 0)
                        return req_format_write(wp, " and Getting IP from DHCP server...");
                    else
                        return req_format_write(wp, " and DHCP");
                }
            }
        }
#endif // _ALPHA_DUAL_WAN_SUPPORT_
    }
    else if ( dhcp ==  PPTP ) {
        if ( isConnectPPP()){
            if(isWanPhy_Link < 0)
                return req_format_write(wp, "PPTP Disconnected");
            else
                return req_format_write(wp, "PPTP Connected");
        }else
            return req_format_write(wp, "PPTP Disconnected");
    }
    else if ( dhcp ==  L2TP ) { /* # keith: add l2tp support. 20080515 */
        if ( isConnectPPP()){
            if(isWanPhy_Link < 0)
                return req_format_write(wp, "L2TP Disconnected");
            else
                return req_format_write(wp, "L2TP Connected");
        }else
            return req_format_write(wp, "L2TP Disconnected");
    }
#ifdef RTK_USB3G
    else if ( dhcp == USB3G ) {
        int inserted = 0;
        char str[32];

        if (isConnectPPP()){
            return req_format_write(wp, "USB3G Connected");
        }else {
            FILE *fp;
            char str[32];
            int retry = 0;

OPEN_3GSTAT_AGAIN:
            fp = fopen("/var/usb3g.stat", "r");

            if (fp !=NULL) {
                fgets(str, sizeof(str),fp);
                fclose(fp);
            }
            else if (retry < 5) {
                retry++;
                goto OPEN_3GSTAT_AGAIN;
            }

            if (str != NULL && strstr(str, "init")) {
                return req_format_write(wp, "USB3G Modem Initializing...");
            }
            else if (str != NULL && strstr(str, "dial")) {
                return req_format_write(wp, "USB3G Dialing...");
            }
            else if (str != NULL && strstr(str, "remove")) {
                return req_format_write(wp, "USB3G Removed");
            }
            else
                return req_format_write(wp, "USB3G Disconnected");
        }
    }
#endif /* #ifdef RTK_USB3G */
#endif //#if defined(CONFIG_RTL_8198_AP_ROOT)
    return 0;
}
#endif


static int pvar_getinfo_wep(request *wp, int argc, char **argv, struct aspvar *v)
{
	char buffer[32] = "";

    ENCRYPT_T encrypt;

    strcpy( buffer, "Disabled");

#if defined(WLAN_PROFILE)
    int wlan_mode, rptEnabled;
    char ifname[10]={0};
    char openFileStr[60]={0};
    int inUseProfile=-1;
    char inUseProfileStr[80]={0};
    FILE *fp;
    int profile_enabled_id, profileEnabledVal;

    //printf("\r\n wlan_idx=[%d],vwlan_idx=[%d],__[%s-%u]\r\n",wlan_idx,vwlan_idx,__FILE__,__LINE__);

    if(wlan_idx == 0)
    {
        profile_enabled_id = MIB_PROFILE_ENABLED1;
        apmib_get(MIB_REPEATER_ENABLED1, (void *)&rptEnabled);
    }
    else
    {
        profile_enabled_id = MIB_PROFILE_ENABLED2;
        apmib_get(MIB_REPEATER_ENABLED2, (void *)&rptEnabled);
    }

    apmib_get(MIB_WLAN_MODE, (void *)&wlan_mode);


    apmib_get(profile_enabled_id, (void *)&profileEnabledVal);

    if( (vwlan_idx == 0 || vwlan_idx == NUM_VWLAN_INTERFACE)
            && profileEnabledVal == 1
            && (wlan_mode == CLIENT_MODE) ) {

        if( vwlan_idx == NUM_VWLAN_INTERFACE) {
            sprintf(ifname,"wlan%d-vxd",wlan_idx);
        } else {
            sprintf(ifname,"wlan%d",wlan_idx);
        }

        sprintf(openFileStr,"cat /proc/%s/mib_ap_profile | grep in_use_profile",ifname);

        fp = popen(openFileStr, "r");
        if(fp && (NULL != fgets(inUseProfileStr, sizeof(inUseProfileStr),fp))) {
            char *searchPtr;

            searchPtr = strstr(inUseProfileStr,"in_use_profile"); //move to first,
            //printf("\r\n inUseProfileStr[%s],__[%s-%u]\r\n",inUseProfileStr,__FILE__,__LINE__);

            sscanf(searchPtr, "in_use_profile: %d", &inUseProfile);
            pclose(fp);
        }

        //printf("\r\n inUseProfile[%d],__[%s-%u]\r\n",inUseProfile,__FILE__,__LINE__);
        if(inUseProfile >= 0) {
            WLAN_PROFILE_T entry;
            memset(&entry,0x00, sizeof(WLAN_PROFILE_T));
            *((char *)&entry) = (char)(inUseProfile+1);

            if(wlan_idx == 0)
                apmib_get(MIB_PROFILE_TBL1, (void *)&entry);
            else
                apmib_get(MIB_PROFILE_TBL2, (void *)&entry);

            if (entry.encryption == WEP64)
                strcpy( buffer, "WEP 64bits");
            else if (entry.encryption == WEP128)
                strcpy( buffer, "WEP 128bits");
            else if (entry.encryption == 3)
                strcpy( buffer, "WPA");
            else if (entry.encryption == 4)
                strcpy( buffer, "WPA2");
            else if (entry.encryption == 6)
                strcpy( buffer, "WPA-Mixed");
            else
                strcpy( buffer, "Disabled");

            //printf("\r\n buffer[%s],__[%s-%u]\r\n",buffer,__FILE__,__LINE__);
        }
    }
    else
#endif //#if defined(WLAN_PROFILE
    {
        if ( !apmib_get( MIB_WLAN_ENCRYPT,  (void *)&encrypt) )
            return -1;
        if (encrypt == ENCRYPT_DISABLED)
            strcpy( buffer, "Disabled");
        else if (encrypt == ENCRYPT_WPA)
            strcpy( buffer, "WPA");
        else if (encrypt == ENCRYPT_WPA2)
            strcpy( buffer, "WPA2");
        else if (encrypt == (ENCRYPT_WPA | ENCRYPT_WPA2))
            strcpy( buffer, "WPA2 Mixed");
        else if (encrypt == ENCRYPT_WAPI)
            strcpy(buffer,"WAPI");
        else {
            WEP_T wep;
            if ( !apmib_get( MIB_WLAN_WEP,  (void *)&wep) )
                return -1;
            if ( wep == WEP_DISABLED )
                strcpy( buffer, "Disabled");
            else if ( wep == WEP64 )
                strcpy( buffer, "WEP 64bits");
            else if ( wep == WEP128)
                strcpy( buffer, "WEP 128bits");
        }
    }
    return req_format_write(wp, buffer);
}


static int pvar_getinfo_netStat(request *wp, int argc, char **argv, struct aspvar *v)
{
    struct user_net_device_stats stats = { };
    const char *name = v->name;

    if ( !strcmp(name, "wlanTxPacketNum")) {
        if ( getStats(WLAN_IF, &stats) < 0)
            stats.tx_bytes = 0;
        return req_format_write(wp, "%llu", stats.tx_bytes);
    } else if ( !strcmp(name, "wlanRxPacketNum")) {
        if ( getStats(WLAN_IF, &stats) < 0)
            stats.rx_bytes = 0;
        return req_format_write(wp, "%d", stats.rx_bytes);
    } else if ( !strcmp(name, "lanTxPacketNum")) {
        if ( getStats(ELAN_IF, &stats) < 0)
            stats.tx_bytes = 0;
        return req_format_write(wp, "%llu", stats.tx_bytes);
    } else if ( !strcmp(name, "lanRxPacketNum")) {
        if ( getStats(ELAN_IF, &stats) < 0)
            stats.rx_bytes = 0;
        return req_format_write(wp, "%llu", stats.rx_bytes);
#if defined(VLAN_CONFIG_SUPPORTED)
    } else if ( !strcmp(name, "lan2TxPacketNum")) {
        if ( getStats(ELAN2_IF, &stats) < 0)
            stats.tx_bytes = 0;
        return req_format_write(wp, "%llu", stats.tx_bytes);
    }
    else if ( !strcmp(name, "lan2RxPacketNum")) {
        if ( getStats(ELAN2_IF, &stats) < 0)
            stats.rx_bytes = 0;
        return req_format_write(wp, "%llu", stats.rx_bytes);
    }
    else if ( !strcmp(name, "lan3TxPacketNum")) {
        if ( getStats(ELAN3_IF, &stats) < 0)
            stats.tx_bytes = 0;
        return req_format_write(wp, "%llu", stats.tx_bytes);
    }
    else if ( !strcmp(name, "lan3RxPacketNum")) {
        if ( getStats(ELAN3_IF, &stats) < 0)
            stats.rx_bytes = 0;
        return req_format_write(wp, "%llu", stats.rx_bytes);
    }
    else if ( !strcmp(name, "lan4TxPacketNum")) {
        if ( getStats(ELAN4_IF, &stats) < 0)
            stats.tx_bytes = 0;
        return req_format_write(wp, "%llu", stats.tx_bytes);
    }
    else if ( !strcmp(name, "lan4RxPacketNum")) {
        if ( getStats(ELAN4_IF, &stats) < 0)
            stats.rx_bytes = 0;
        return req_format_write(wp, "%llu", stats.rx_bytes);
    }
#else
    } else {
        return req_format_write(wp, "0");
    }
#endif
    return 0;
}

static int pvar_getinfo_running_dnsmod(request *wp, int argc, char **argv, struct aspvar *v)
{
    int i = 0, n = 0;
    char *s = NULL, *p = NULL;
    char buffer[32] = "";

    s = INETx_getdns(AF_INET);
    n = 0;
    for (i = 0, p = s; p && *p; p += (strlen(p) + 1), i++) {
        n += sprintf(&buffer[n],"%s", (i > 0)?"/":"");
        n += sprintf(&buffer[n], "%s", p);
    }
    if ( !buffer[0] )
        sprintf(&buffer[0], "---");
    if (s)
        free(s);
    return req_format_write(wp, "<font color=\"blue\"><b>%s모드</b></font> (%s)",
            (!access("/var/run_static_dns", F_OK))?"수동":"자동",
            buffer);
}

static int pvar_getinfo_bs_rssi_th(request *wp, int argc, char **argv, struct aspvar *v)
{
    const char *name = v->name;
    char buffer[4] = "";

    nvram_get_r_def(name, buffer, sizeof(buffer), "-73");
    return req_format_write(wp, "%d", atoi(buffer)*(-1));
}

static int pvar_getinfo_hostName(request *wp, int argc, char **argv, struct aspvar *v)
{
    char buffer[16] = "";
    gethostname(buffer, sizeof(buffer));
    return req_format_write(wp, "%s", buffer);
}

static int pvar_getInAddr(request *wp, int argc, char **argv, struct aspvar *v)
{
    struct in_addr	intaddr = { };
	struct sockaddr hwaddr = { };
	unsigned char *pMacAddr = NULL;
    int addrtype = v->lparam;
    int iftype = v->warg1;
    char *p_iftype = NULL;

    switch (iftype) {
        case IF_BR:
            p_iftype = BRIDGE_IF;
            break;
        case IF_WAN:
            p_iftype = WAN_IF;
            break;
        default:
            break;
    }

    if (addrtype != HW_ADDR) {
        if ( getInAddr(p_iftype, addrtype, (void *)&intaddr ) )
            return req_format_write(wp, "%s", inet_ntoa(intaddr) );
        else
            return req_format_write(wp, "0.0.0.0");

    } else {
        if ( getInAddr(p_iftype, addrtype, (void *)&hwaddr ) ) {
            pMacAddr = (unsigned char *)hwaddr.sa_data;
            return req_format_write(wp, "%02x:%02x:%02x:%02x:%02x:%02x", pMacAddr[0], pMacAddr[1],
                    pMacAddr[2], pMacAddr[3], pMacAddr[4], pMacAddr[5]);
        }
        else
            return req_format_write(wp, "00:00:00:00:00:00");
    }
}



static struct aspvar pgetvars[] = {
    //
    //define(except DAVO)
    //
#ifdef CONFIG_IPV6
#ifdef CONFIG_DSLITE_SUPPORT
    {"ipv6_comment_start", pvar_printarg, (long)(void *)"", NULL},
    {"ipv6_comment_end", pvar_printarg, (long)(void *)"", NULL},
    {"ipv6_jscomment_start", pvar_printarg, (long)(void *)"", NULL},
    {"ipv6_jscomment_end", pvar_printarg, (long)(void *)"", NULL},
#else
    {"ipv6_comment_start", pvar_printarg, (long)(void *)"<!--", NULL},
    {"ipv6_comment_end", pvar_printarg, (long)(void *)"-->", NULL},
    {"ipv6_jscomment_start", pvar_printarg, (long)(void *)"/*", NULL},
    {"ipv6_jscomment_end", pvar_printarg, (long)(void *)"*/", NULL},
#endif
#else
    {"ipv6_comment_start", pvar_printarg, (long)(void *)"<!--", NULL},
    {"ipv6_comment_end", pvar_printarg, (long)(void *)"-->", NULL},
    {"ipv6_jscomment_start", pvar_printarg, (long)(void *)"/*", NULL},
    {"ipv6_jscomment_end", pvar_printarg, (long)(void *)"*/", NULL},
#endif

#if defined(PPTP_SUPPORT)
    {"pptp_comment_start", pvar_printarg, (long)(void *)"", NULL},
    {"pptp_comment_end", pvar_printarg, (long)(void *)"", NULL},
#else
    {"pptp_comment_start", pvar_printarg, (long)(void *)"<!--", NULL},
    {"pptp_comment_end", pvar_printarg, (long)(void *)"-->", NULL},
#endif

#if defined(L2TP_SUPPORT)
    {"l2tp_comment_start", pvar_printarg, (long)(void *)"", NULL},
    {"l2tp_comment_end", pvar_printarg, (long)(void *)"", NULL},
#else
    {"l2tp_comment_start", pvar_printarg, (long)(void *)"<!--", NULL},
    {"l2tp_comment_end", pvar_printarg, (long)(void *)"-->", NULL},
#endif


#if defined(CONFIG_4G_LTE_SUPPORT)
    {"lte4g_comment_start", pvar_printarg, (long)(void *)"", NULL},
    {"lte4g_comment_end", pvar_printarg, (long)(void *)"", NULL},
    {"lte4g_jscomment_start", pvar_printarg, (long)(void *)"", NULL},
    {"lte4g_jscomment_end", pvar_printarg, (long)(void *)"", NULL},
#else
    {"lte4g_comment_start", pvar_printarg, (long)(void *)"<!--", NULL},
    {"lte4g_comment_end", pvar_printarg, (long)(void *)"-->", NULL},
    {"lte4g_jscomment_start", pvar_printarg, (long)(void *)"/*", NULL},
    {"lte4g_jscomment_end", pvar_printarg, (long)(void *)"*/", NULL},
#endif


#ifdef CONFIG_RTL_ETH_802DOT1X_CLIENT_MODE_SUPPORT
    {"ethernet802dot1xCert_menu", pvar_printarg,
        (long)(void *)"manage.addItem(\"Ethernet 802.1x Cert Install\","
        "get_form(\"skb_ethdot1xCertInstall.htm\",i), \"\","
        " \"Install Ethernet 802.1x certificates\");", NULL },

    {"eth1xclient_comment_start", pvar_printarg, (long)(void *)"", NULL},
    {"eth1xclient_comment_end", pvar_printarg, (long)(void *)"", NULL},
    {"eth1xclient_jscomment_start", pvar_printarg, (long)(void *)"", NULL},
    {"eth1xclient_jscomment_end", pvar_printarg, (long)(void *)"", NULL},
#else
    {"eth1xclient_comment_start", pvar_printarg, (long)(void *)"<!--", NULL},
    {"eth1xclient_comment_end", pvar_printarg, (long)(void *)"-->", NULL},
    {"eth1xclient_jscomment_start", pvar_printarg, (long)(void *)"/*", NULL},
    {"eth1xclient_jscomment_end", pvar_printarg, (long)(void *)"*/", NULL},
    {"ethernet802dot1xCert_menu", pvar_printarg, (long)(void *)"", NULL },
#endif


#ifdef CONFIG_RTK_MESH
    {"meshEncrypt", pvar_getinfo_encrypttype, 0, NULL },
    {"mesh_comment_start", pvar_printarg, (long)(void *)"", NULL},
    {"mesh_comment_end", pvar_printarg, (long)(void *)"", NULL},
    {"mesh_jscomment_start", pvar_printarg, (long)(void *)"", NULL},
    {"mesh_jscomment_end", pvar_printarg, (long)(void *)"", NULL},
    {"meshID", pvar_getmib, MIB_WLAN_MESH_ID, (void *)pwrite_puts_webtrans }, //NY
    {"meshPskValue", pvar_getmib, MIB_WLAN_MESH_WPA_PSK, (void *)pwrite_puts_webtrans }, //NY
#else
    {"mesh_comment_start", pvar_printarg, (long)(void *)"<!--", NULL},
    {"mesh_comment_end", pvar_printarg, (long)(void *)"-->", NULL},
    {"mesh_jscomment_start", pvar_printarg, (long)(void *)"/*", NULL},
    {"mesh_jscomment_end", pvar_printarg, (long)(void *)"*/", NULL},
#endif


#if defined(CONFIG_RTL_8198_AP_ROOT) || defined(CONFIG_RTL_8197D_AP)
    {"wan_access_type_s", pvar_printarg, (long)(void *)"<!--", NULL},
    {"wan_access_type_e", pvar_printarg, (long)(void *)"-->", NULL},
#else
    {"wan_access_type_s", pvar_printarg, (long)(void *)"", NULL},
    {"wan_access_type_e", pvar_printarg, (long)(void *)"", NULL},
#endif


#if defined(CONFIG_RTL_FLASH_DUAL_IMAGE_ENABLE)
    {"onoff_dual_firmware_start", pvar_printarg, (long)(void *)"", NULL },
    {"onoff_dual_firmware_end", pvar_printarg, (long)(void *)"", NULL },
    {"enable_dualFw", pvar_getmib, MIB_DUALBANK_ENABLED, (void *)pwrite_itoa },
#else
    {"onoff_dual_firmware_start", pvar_printarg, (long)(void *)"<!--", NULL },
    {"onoff_dual_firmware_end", pvar_printarg, (long)(void *)"-->", NULL },
    {"enable_dualFw", pvar_printarg, (long)(void *)"1", NULL },
#endif


#if defined(CONFIG_RTL_92D_DMDP)||defined(CONFIG_RTL_DUAL_PCIESLOT_BIWLAN_D)
    {"onoff_dmdphy_comment_start", pvar_printarg, (long)(void *)"", NULL },
    {"onoff_dmdphy_comment_end", pvar_printarg, (long)(void *)"", NULL },
#else
    {"onoff_dmdphy_comment_start", pvar_printarg, (long)(void *)"<!--", NULL },
    {"onoff_dmdphy_comment_end", pvar_printarg, (long)(void *)"-->", NULL },
#endif


#ifdef CONFIG_CPU_UTILIZATION
    {"isCPUdisplayStart", pvavr_printarg, (long)(void *)"", NULL },
    {"isCPUdisplayEndt", pvar_printarg, (long)(void *)"", NULL },
#else
    {"isCPUdisplayStart", pvar_printarg, (long)(void *)"<!--", NULL },
    {"isCPUdisplayEndt", pvar_printarg, (long)(void *)"<!--", NULL },
#endif


#if defined(WLAN_PROFILE)
    {"wlProfileSupport", pvar_printarg, (long)(void *)"1", NULL},
#else
    {"wlProfileSupport", pvar_printarg, (long)(void *)"0", NULL},
#endif


#ifdef  CONFIG_APP_SMTP_CLIENT
    {"smtpclient_enable", pvar_printarg, (long)(void *)"1", NULL},
#else
    {"smtpclient_enable", pvar_printarg, (long)(void *)"0", NULL},
#endif


#if defined(CONFIG_DOMAIN_NAME_QUERY_SUPPORT)
    {"countDownTime_wait", pvar_printarg, WaitCountTime, pwrite_itoa},
#else
    {"countDownTime_wait", pvar_printarg, (long)(void *)"1", NULL},
#endif


#ifdef USE_AUTH
    {"last_url", pvar_printarg, (long)(void *)&last_url[0], NULL},
#endif


#if defined(CONFIG_POCKET_AP_SUPPORT) || defined(CONFIG_RTL_8198_AP_ROOT) \
    || defined(CONFIG_RTL_8197D_AP)
    {"opmode_menu_onoff", pvar_printarg, (long)(void *)"", NULL },
#elif defined(CONFIG_RTL_ULINKER)
    {"opmode_menu_onoff", pvar_printarg, (long)(void *)"menu.addItem('ULinker Operation Mode',"
        " 'skb_ulinker_opmode.htm', '', 'ULinker Operation Mode');", NULL },
#else
    {"opmode_menu_onoff", pvar_printarg, (long)(void *)"menu.addItem('Operation Mode',"
        " 'skb_opmode.htm', '', 'Operation Mode');", NULL },
#endif


#if defined(GW_QOS_ENGINE) && !defined(VOIP_SUPPORT)
    {"qos_root_menu", pvar_printarg, (long)(void *)"menu.addItem('QoS', 'skb_qos.htm', '', 'Setup QoS');", NULL },
#elif defined(QOS_BY_BANDWIDTH) && !defined(VOIP_SUPPORT)
#ifdef CONFIG_IPV6
    {"qos_root_menu", pvar_printarg, (long)(void *)"menu.addItem('QoS', 'skb_ip6_qos.htm', '', 'Setup QoS');", NULL },
#else
    {"qos_root_menu", pvar_printarg, (long)(void *)"menu.addItem('QoS', 'skb_ip_qos.htm', '', 'Setup QoS');", NULL },
#endif
#else
    {"qos_root_menu", pvar_printarg, (long)(void *)"", NULL },
#endif


#if defined(ROUTE_SUPPORT)
    {"route_menu_onoff", pvar_printarg, (long)(void *)"menu.addItem(\"Route Setup\", \"skb_route.htm\","
        " \"\", \"Route Setup\");", NULL },
#else
    {"route_menu_onoff", pvar_printarg, (long)(void *)"", NULL },
#endif


#if defined(DDNS_SUPPORT)
    {"ddns_menu", pvar_printarg, (long)(void *)"manage.addItem(\"DDNS\", \"skb_ddns.htm\","
        " \"\", \"Setup Dynamic DNS\");", NULL },
#else
    {"ddns_menu", pvar_printarg, (long)(void *)"", NULL },
#endif


#ifdef CONFIG_IPV6
    {"ip_filter", pvar_printarg, (long)(void *)"firewall.addItem('IP Filtering', 'skb_ip6filter.htm',"
        " '', 'Setup IP filering');", NULL },
    {"port_filter", pvar_printarg, (long)(void *)"firewall.addItem('Port Filtering', 'skb_portfilter6.htm',"
        " '', 'Setup port filer');", NULL },
#else
    {"ip_filter", pvar_printarg, (long)(void *)"firewall.addItem('IP Filtering', 'skb_ipfilter.htm',"
        " '', 'Setup IP filering');", NULL },
    {"port_filter", pvar_printarg, (long)(void *)"firewall.addItem('Port Filtering', 'skb_portfilter.htm',"
        " '', 'Setup port filer');", NULL },
#endif


#if defined(CONFIG_RTL_ULINKER)
    {"is_ulinker", pvar_printarg, (long)(void *)"1", NULL},
#else
    {"is_ulinker", pvar_printarg, (long)(void *)"0", NULL},
#endif


#if defined(CONFIG_RTL_92D_SUPPORT) || defined(CONFIG_RTL_8881A_SELECTIVE)
    {"wlan_bandMode_menu_onoff", pvar_printarg, (long)(void *)"wlan.addItem('BandMode',"
        " 'skb_wlbandmode.htm', '', 'Setup WLAN Band Mode');", NULL },
#else
    {"wlan_bandMode_menu_onoff", pvar_printarg, (long)(void *)"", NULL },
#endif


#if defined(CONFIG_RTL_DUAL_PCIESLOT_BIWLAN_D)
    {"single_band", pvar_printarg, (long)(void *)"<input type=\"radio\" value=\"3\""
        " name=\"wlBandMode\" onClick=\"\" DISABLED></input>", NULL },
#elif defined(CONFIG_POCKET_AP_SUPPORT) || defined(CONFIG_RTL_8881A_SELECTIVE)
    {"single_band", pvar_printarg, (long)(void *)"<input type=\"radio\" value=\"3\" "
        "name=\"wlBandMode\" onClick=\"\" CHECKED></input>", NULL },
#else
    {"single_band", pvar_printarg, (long)(void *)"<input type=\"radio\" value=\"3\" "
        "name=\"wlBandMode\" onClick=\"\" ></input>", NULL },
#endif


#ifdef CONFIG_APP_BOA_NEW_UI
    {"use_boa_new_ui", pvar_printarg, (long)(void *)"1", NULL},
#else
    {"use_boa_new_ui", pvar_printarg, (long)(void *)"0", NULL},
#endif


#if defined(CONFIG_POCKET_ROUTER_SUPPORT) || defined(CONFIG_RTL_ULINKER)
    {"isPocketRouter", pvar_printarg, (long)(void *)"1", NULL},
#else
    {"isPocketRouter", pvar_printarg, (long)(void *)"0", NULL},
#endif


#if defined(HTTP_FILE_SERVER_SUPPORTED)
    {"homepage", pvar_printarg,  (long)(void *)"skb_http_files.htm", NULL },
#else
    {"homepage", pvar_printarg,  (long)(void *)"skb_home.htm", NULL },
#endif


#ifdef CONFIG_APP_TR069
    {"ipfilter_menu", pvar_printarg, (long)(void *)TR069_IPFILTER_MENU_STR, NULL },
    {"portfilter_menu", pvar_printarg, (long)(void *)TR069_PORTFILTER_MENU, NULL },
    {"tr069-inform-0", pvar_getinfo_tr069, 0, NULL },
    {"tr069-inform-1", pvar_getinfo_tr069, 0, NULL },
    {"inform_interval", pvar_getinfo_tr069, 0, NULL },
    {"tr069_interval", pvar_getinfo_tr069, 0, NULL },
    {"tr069-dbgmsg-0", pvar_getinfo_tr069, 0, NULL },
    {"tr069-dbgmsg-1", pvar_getinfo_tr069, 0, NULL },
    {"tr069-sendgetrpc-0", pvar_getinfo_tr069, 0, NULL },
    {"tr069-sendgetrpc-1", pvar_getinfo_tr069, 0, NULL },
    {"tr069-skipmreboot-0", pvar_getinfo_tr069, 0, NULL },
    {"tr069-skipmreboot-1", pvar_getinfo_tr069, 0, NULL },
    {"tr069-autoexec-0", pvar_getinfo_tr069, 0, NULL },
    {"tr069-autoexec-1", pvar_getinfo_tr069, 0, NULL },
    {"tr069-delay-0", pvar_getinfo_tr069, 0, NULL },
    {"tr069-delay-1", pvar_getinfo_tr069, 0, NULL },
    {"acs_url", pvar_getmib, MIB_CWMP_ACS_URL, (void *)pwrite_puts },
    {"acs_username", pvar_getmib, MIB_CWMP_ACS_USERNAME, (void *)pwrite_puts },
    {"acs_password", pvar_getmib, MIB_CWMP_ACS_PASSWORD, (void *)pwrite_puts },
    {"conreq_name", pvar_getmib, MIB_CWMP_CONREQ_USERNAME, (void *)pwrite_puts },
    {"conreq_pw", pvar_getmib, MIB_CWMP_CONREQ_PASSWORD, (void *)pwrite_puts },
    {"conreq_path", pvar_getmib, MIB_CWMP_CONREQ_PATH, (void *)pwrite_puts },
    {"conreq_port", pvar_getmib, MIB_CWMP_CONREQ_PORT, (void *)pwrite_itoa },
#else
    {"tr069_nojs_menu", pvar_return_zero, 0, NULL },
    {"cwmp_tr069_menu", pvar_return_zero, 0, NULL },
#endif


#if defined(NEW_SCHEDULE_SUPPORT)
    {"maxWebWlSchNum", pvar_printarg, MAX_SCHEDULE_NUM, (void *)pwrite_itoa },
    {"wlsch_onoff", pvar_getmib, MIB_WLAN_SCHEDULE_ENABLED, (void *)pwrite_itoa },
#endif // #if defined(NEW_SCHEDULE_SUPPORT)


#ifdef WLAN_EASY_CONFIG
    {"autoCfgKey", pvar_getmib, MIB_WLAN_EASYCFG_KEY, (void *)pwrite_puts },
    {"autoCfgAlgReq", pvar_getinfo_autoCfgAlgReq, 0, NULL },
#endif


#ifdef WIFI_SIMPLE_CONFIG
    {"pskValueUnmask", pvar_getmib, MIB_WLAN_WPA_PSK, (void *)pwrite_puts_webtrans },
    {"wscLoocalPin", pvar_getmib, MIB_HW_WSC_PIN, (void *)pwrite_puts },
    {"wps_key", pvar_getinfo_wpskey, 0, NULL },
    {"wpsRpt_key", pvar_getinfo_wpskey, 0, NULL },
#endif


#ifdef CONFIG_RTL_802_1X_CLIENT_SUPPORT
    {"rsCertInstall", pvar_printarg,
        (long)(void *)"wlan0.addItem(\"802.1x Cert Install\",get_form(\"skb_rsCertInstall.htm\",i),"
        "\"\", \"Install 802.1x certificates\");", NULL },
    {"is8021xClient", pvar_printarg, (long)(void *)"1", NULL },
    {"eapUserId", pvar_getmib, MIB_WLAN_EAP_USER_ID, (void *)pwrite_puts },
    {"radiusUserName", pvar_getmib, MIB_WLAN_RS_USER_NAME, (void *)pwrite_puts },
    {"radiusUserPass", pvar_getmib, MIB_WLAN_RS_USER_PASSWD, (void *)pwrite_puts },
    {"radiusUserCertPass", pvar_getmib, MIB_WLAN_RS_USER_CERT_PASSWD, (void *)pwrite_puts },
#else
    {"rsCertInstall", pvar_return_zero, 0, NULL },
    {"eapUserId", pvar_printarg, (long)(void *)"", NULL },
    {"radiusUserName", pvar_printarg, (long)(void *)"", NULL },
    {"radiusUserPass", pvar_printarg, (long)(void *)"", NULL },
    {"radiusUserCertPass", pvar_printarg, (long)(void *)"", NULL },
    {"is8021xClient", pvar_printarg, (long)(void *)"0", NULL },
#endif


#ifdef HOME_GATEWAY
#if defined(VLAN_CONFIG_SUPPORTED)
    {"vlan_menu_onoff", pvar_printarg, (long)(void *)"firewall.addItem('VLAN', 'skb_vlan.htm', '', 'Setup VLAN');", NULL},
    {"maxWebVlanNum", pvar_getinfo_maxWebVlanNum, 0, NULL },
    {"vlanOnOff", pvar_getmib, MIB_VLANCONFIG_ENABLED, (void *)pwrite_itoa },
#else
    {"vlan_menu_onoff", pvar_printarg, (long)(void *)"", NULL},
    {"vlanOnOff", pvar_printarg, (long)(void *)"0", NULL },
#endif
#else
#if defined(VLAN_CONFIG_SUPPORTED)
#if defined(CONFIG_RTL_8198_AP_ROOT) || defined(CONFIG_RTL_8197D_AP)
    {"vlan_menu_onoff", pvar_printarg, (long)(void *)"menu.addItem('VLAN', 'skb_vlan.htm', '', 'Setup VLAN');", NULL},
    {"maxWebVlanNum", pvar_getinfo_maxWebVlanNum, 0, NULL },
    {"vlanOnOff", pvar_getmib, MIB_VLANCONFIG_ENABLED, (void *)pwrite_itoa },
    {"wlanMode", pvar_getmib, MIB_WLAN_MODE, (void *)pwrite_itoa },
    {"rf_used", pvar_getinfo_rf_used, 0, NULL },
#endif
#endif
#endif


#ifdef RTK_USB3G
    {"usb3g_comment_start", pvar_printarg, (long)(void *)"", NULL},
    {"usb3g_comment_end", pvar_printarg, (long)(void *)"", NULL},
    {"usb3g_jscomment_start", pvar_printarg, (long)(void *)"", NULL},
    {"usb3g_jscomment_end", pvar_printarg, (long)(void *)"", NULL},

    {"USB3G_PIN", pvar_getmib, MIB_USB3G_PIN, (void *)pwrite_puts_webtrans },
    {"USB3G_APN", pvar_getmib, MIB_USB3G_APN, (void *)pwrite_puts_webtrans },
    {"USB3G_DIALNUM", pvar_getmib, MIB_USB3G_DIALNUM, (void *)pwrite_puts_webtrans },
    {"USB3G_USER", pvar_getmib, MIB_USB3G_USER, (void *)pwrite_puts_webtrans },
    {"USB3G_PASS", pvar_getmib, MIB_USB3G_PASS, (void *)pwrite_puts_webtrans },
    {"USB3GMtuSize", pvar_getmib, MIB_USB3G_MTU_SIZE, (void *)pwrite_puts_webtrans },
#ifdef HOME_GATEWAY
    {"wan-USB3G-idle", pvar_getmib, MIB_USB3G_IDLE_TIME, (void *)pwrite_time_sectomin },
#endif
#else
    {"usb3g_comment_start", pvar_printarg, (long)(void *)"<!--", NULL},
    {"usb3g_comment_end", pvar_printarg, (long)(void *)"-->", NULL},
    {"usb3g_jscomment_start", pvar_printarg, (long)(void *)"/*", NULL},
    {"usb3g_jscomment_end", pvar_printarg, (long)(void *)"*/", NULL},

    {"USB3G", pvar_printarg, (long)(void *)"", NULL },
#ifdef HOME_GATEWAY
    {"wan-USB3G-idle", pvar_printarg, (long)(void *)"", NULL },
#endif
#endif


#ifdef _ALPHA_DUAL_WAN_SUPPORT_
    {"pppVlanId", pvar_getmib, MIB_CWMP_PPPOE_WAN_VLANID, (void *)pwrite_itoa },
#endif


#if defined(CONFIG_RTL_P2P_SUPPORT)
    {"p2p_intent", pvar_getmib, MIB_WLAN_P2P_INTENT, (void *)pwrite_itoa },
    {"p2p_listen_channel", pvar_getmib, MIB_WLAN_P2P_LISTEN_CHANNEL, (void *)pwrite_itoa },
    {"p2p_op_channel", pvar_getmib, MIB_WLAN_P2P_OPERATION_CHANNEL, (void *)pwrite_itoa },
	{"p2p_type", pvar_getinfo_p2ptype, 0, NULL },
#endif


#if defined(CONFIG_RTL_ETH_802DOT1X_SUPPORT)
    {"ethdot1x_type", pvar_getmib, MIB_ELAN_DOT1X_PROXY_TYPE, (void *)pwrite_itoa },
    {"ethdot1x_unicastresp_onoff", pvar_getmib,  MIB_ELAN_EAPOL_UNICAST_ENABLED, (void *)pwrite_itoa },
    {"ethdot1x_radius_ip", pavr_getmib, MIB_ELAN_RS_IP, (void *)pwrite_in_ntoa },
    {"ethdot1x_radius_pass", pavr_getmib, MIB_ELAN_RS_PASSWORD, (void *)pwrite_puts_webtrans },
    {"ethdot1x_radius_port", pavr_getmib, MIB_ELAN_RS_PORT, (void *)pwrite_itoa },
    {"ethdot1x_server_port_number", pavr_getmib, MIB_ELAN_DOT1X_SERVER_PORT, (void *)pwrite_itoa },
    {"ethdot1x_maxportnum", pvar_getinfo_ethdot1x, 0, NULL },
    {"ethdot1x_mode", pvar_getinfo_ethdot1x, 0, NULL },
    {"ethdot1x_menu_onoff", pvar_printarg, (long)(void *)"menu.addItem(\"Ethernet 802.1x Setup\","
        " \"skb_eth_dot1x.htm\", \"\", \"Ethernet 802.1x Setup\");", NULL },
#else
    {"ethdot1x_menu_onoff", pvar_printarg, (long)(void *)"", NULL },
#endif


#ifdef CONFIG_RTL_WAPI_SUPPORT
    {"wapiOption", pvar_printarg, (long)(void *)"<option value=\"7\"> WAPI </option>", NULL },
    {"wapiMenu", pvar_getinfo_print_wapiMenu, 0, NULL },
    {"isWapiSupport", pvar_printarg, (long)(void *)"1", NULL },
    {"auth_mode_2or3_certification", pvar_getinfo_auth_mode_2or3_certification, 0, NULL },
    {"wapiCert", pvar_getinfo_wapiCert, 0, NULL },
    {"caCertExist", pvar_getinfo_CerExist, 0, NULL },
    {"asCerExist", pvar_getinfo_CerExist, 0, NULL },
    {"notSyncSysTime", pvar_getinfo_notSyncSysTime , 0, NULL },
    {"wapiUcastTime", pvar_getmib, MIB_WLAN_WAPI_UCAST_TIME, (void *)pwrite_itoa },
    {"wapiUcastPackets", pvar_getmib, MIB_WLAN_WAPI_UCAST_PACKETS, (void *)pwrite_itoa },
    {"wapiMcastTime", pvar_getmib, MIB_WLAN_WAPI_MCAST_TIME, (void *)pwrite_itoa },
    {"wapiMcastPackets", pvar_getmib, MIB_WLAN_WAPI_MCAST_PACKETS, (void *)pwrite_itoa },
    {"wapiPskValue", pvar_getmib, MIB_WLAN_WAPI_PSK, (void *)pwrite_puts_webtrans },
    {"wapiASIp", pvar_getmib, MIB_WLAN_WAPI_ASIPADDR, (void *)pwrite_in_ntoa, "0.0.0.0" },
    {"wapiCertSel", pvar_getmib, MIB_WLAN_WAPI_CERT_SEL, (void *)pwrite_itoa },

#if defined(CONFIG_RTL_8198C) ||defined(CONFIG_RTL_8198) || defined(CONFIG_POCKET_ROUTER_SUPPORT) \
    || defined(CONFIG_RTL_8196C) || defined(CONFIG_RTL_819XD) || defined(CONFIG_RTL_8196E)
    {"wapiCertSupport", pvar_return_zero, 0, NULL },
#else
    {"wapiCertSupport", pvar_printarg, (long)(void *)"disabled", NULL },
#endif

#ifdef CONFIG_RTL_WAPI_LOCAL_AS_SUPPORT
    {"wapiLocalAsSupport", pvar_printarg, (long)(void *)"true", NULL },
    {"wapiLocalAsOption", pvar_printarg, (long)(void *)"<option value=\"1\"> Use Cert from Local AS </option>", NULL },
#else
    {"wapiLocalAsSupport", pvar_printarg, (long)(void *)"false", NULL },
    {"wapiLocalAsOption", pvar_return_zero, 0, NULL },
#endif

#else //CONFIG_RTL_WAPI_SUPPORT
    {"isWapiSupport", pvar_printarg, (long)(void *)"0", NULL },
    {"wapi", pvar_return_zero, 0, NULL },
    {"wapiLocalAsSupport", pvar_printarg, (long)(void *)"false", NULL },
#endif


#ifdef CONFIG_RTL_BT_CLIENT
    {"bt_enabled", pvar_getmib, MIB_BT_ENABLED, (void *)pwrite_itoa },
    {"bt_status", pvar_return_zero, 0, NULL },
    {"bt_limits", pvar_return_zero, 0, NULL },
    {"BTDDir", pvar_getmib, MIB_BT_DOWNLOAD_DIR, (void *)pwrite_puts },
    {"BTUDir", pvar_getmib, MIB_BT_UPLOAD_DIR, (void *)pwrite_puts },
    {"BTdlimit", pvar_getmib, MIB_BT_TOTAL_DLIMIT, (void *)pwrite_itoa },
    {"BTulimit", pvar_getmib, MIB_BT_TOTAL_ULIMIT, (void *)pwrite_itoa },
    {"BTrefreshtime", pvar_getmib, MIB_BT_REFRESH_TIME, (void *)pwrite_itoa },
    {"rtl_bt_menu", pvar_printarg, (long)(void *)"manage.addItem(\"BT Client\", \"skb_bt.htm\","
        " \"\", \"BT Client\");", NULL },
    {"is_enabled_bt", pvar_printarg, (long)(void *)"1", NULL },
    {"torrents", pvar_getinfo_torrents, 0, NULL },
    {"btfiles", pvar_getinfo_btfiles, 0, NULL },
    {"btclientindex", pvar_getinfo_btclientindex, NULL, NULL },
#else
    {"rtl_bt_menu", pvar_return_zero, 0, NULL },
    {"is_enabled_bt", pvar_printarg, (long)(void *)"0", NULL },
#endif


#ifdef CONFIG_RTL_TRANSMISSION
    {"bt_enabled", pvar_getinfo_bt_enabled, 0, NULL },
    {"BTDDir", pvar_getmib, MIB_BT_DOWNLOAD_DIR, (void *)pwrite_puts },
    {"BTUDir", pvar_getmib, MIB_BT_UPLOAD_DIR, (void *)pwrite_puts },
    {"rtl_trans_bt_menu", pvar_printarg, (long)(void *)"manage.addItem(\"BT Client\","
        " \"skb_transmission.htm\", \"\", \"BT Client\");", NULL },
#else
    {"rtl_bt_menu", pvar_return_zero, 0, NULL },
    {"isEnableBT", pvar_printarg, (long)(void *)"1", NULL },
#endif


#ifdef REBOOT_CHECK
    {"countDownTime", pvar_getinfo_reboot_check, 0, NULL },
    {"okMsg", pvar_getinfo_reboot_check, 0, NULL },
    {"lastUrl", pvar_getinfo_reboot_check, 0, NULL },
#endif


#ifdef HTTP_FILE_SERVER_HTM_UI
    {"current_directory", pvar_getinfo_current_directory, 0, NULL },
#endif


#ifdef UNIVERSAL_REPEATER
    {"repeaterSSID", pvar_getinfo_universal_repeater, 0, NULL },
    {"repeaterClientnum", pvar_getinfo_universal_repeater, 0, NULL },
    {"repeaterSSID_drv", pvar_getinfo_universal_repeater, 0, NULL },
    {"repeaterBSSID", pvar_getinfo_universal_repeater, 0, NULL },
    {"wlanRepeaterTxPacketNum", pvar_getinfo_universal_repeater, 0, NULL },
    {"wlanRepeaterRxPacketNum", pvar_getinfo_universal_repeater, 0, NULL },
#endif


#if defined(CONFIG_SNMP)
    {"snmp_menu", pvar_printarg, (long)(void *)"menu.addItem(\"SNMP\", \"skb_snmp.htm\", \"\", \"SNMP Setup\");", NULL },
    {"snmp_name", pvar_getmib, MIB_SNMP_NAME, (void *)pwrite_puts_webtrans },
    {"snmp_location", pvar_getmib, MIB_SNMP_LOCATION, (void *)pwrite_puts_webtrans },
    {"snmp_contact", pvar_getmib, MIB_SNMP_CONTACT, (void *)pwrite_puts_webtrans },
    {"snmp_rwcommunity", pvar_getmib, MIB_SNMP_RWCOMMUNITY, (void *)pwrite_puts },
    {"snmp_rocommunity", pvar_getmib, MIB_SNMP_ROCOMMUNITY, (void *)pwrite_puts },
    {"snmp_trap1", pvar_getmib, MIB_SNMP_TRAP_RECEIVER1, (void *)pwrite_in_ntoa },
    {"snmp_trap2", pvar_getmib, MIB_SNMP_TRAP_RECEIVER2, (void *)pwrite_in_ntoa },
    {"snmp_trap3", pvar_getmib, MIB_SNMP_TRAP_RECEIVER3, (void *)pwrite_in_ntoa },
#else
    {"snmp_menu", pvar_printarg, (long)"", NULL },
#endif


#ifdef VOIP_SUPPORT
    {"voip_", pvar_getinfo_voip_, 0, NULL },
#endif


#ifdef CONFIG_IPV6
    {"IPv6_", pvar_getinfo_ipv6_, 0, NULL },
#endif


#ifdef CONFIG_APP_TR069
    {"tr069_nojs_menu", pvar_printarg, (long)(void *)TR069_NOJS_MENU_STR, NULL },
    {"cwmp_tr069_menu", pvar_printarg, (long)(void *)"manage.addItem('TR-069 config', 'skb_tr069config.htm',"
        " '', 'Setup TR-069 configuration');", NULL },
#endif


#if defined(HOME_GATEWAY)
#ifdef __DAVO__
    {"wan_vlan_pvid", pvar_getinfo_davovlan, 0, NULL },
    {"lan1_vlan_pvid", pvar_getinfo_davovlan, 0, NULL },
    {"lan2_vlan_pvid", pvar_getinfo_davovlan, 0, NULL },
    {"lan3_vlan_pvid", pvar_getinfo_davovlan, 0, NULL },
    {"lan4_vlan_pvid", pvar_getinfo_davovlan, 0, NULL },

    {"vlan_id_0", pvar_getinfo_davovlan, 0, NULL },
    {"vlan_id_1", pvar_getinfo_davovlan, 0, NULL },
    {"vlan_id_2", pvar_getinfo_davovlan, 0, NULL },
    {"vlan_id_3", pvar_getinfo_davovlan, 0, NULL },
    {"vlan_id_4", pvar_getinfo_davovlan, 0, NULL },
    {"vlan_id_5", pvar_getinfo_davovlan, 0, NULL },
    {"vlan_id_6", pvar_getinfo_davovlan, 0, NULL },
    {"vlan_id_7", pvar_getinfo_davovlan, 0, NULL },
    {"vlan_id_8", pvar_getinfo_davovlan, 0, NULL },
    {"vlan_id_9", pvar_getinfo_davovlan, 0, NULL },
    {"vlan_id_10", pvar_getinfo_davovlan, 0, NULL },
    {"vlan_id_11", pvar_getinfo_davovlan, 0, NULL },
    {"vlan_id_12", pvar_getinfo_davovlan, 0, NULL },
    {"vlan_id_13", pvar_getinfo_davovlan, 0, NULL },
    {"vlan_id_14", pvar_getinfo_davovlan, 0, NULL },
    {"vlan_id_15", pvar_getinfo_davovlan, 0, NULL },

    {"vlan_port_0", pvar_getinfo_davovlan, 0, NULL },
    {"vlan_port_1", pvar_getinfo_davovlan, 0, NULL },
    {"vlan_port_2", pvar_getinfo_davovlan, 0, NULL },
    {"vlan_port_3", pvar_getinfo_davovlan, 0, NULL },
    {"vlan_port_4", pvar_getinfo_davovlan, 0, NULL },
    {"vlan_port_5", pvar_getinfo_davovlan, 0, NULL },
    {"vlan_port_6", pvar_getinfo_davovlan, 0, NULL },
    {"vlan_port_7", pvar_getinfo_davovlan, 0, NULL },
    {"vlan_port_8", pvar_getinfo_davovlan, 0, NULL },
    {"vlan_port_9", pvar_getinfo_davovlan, 0, NULL },
    {"vlan_port_10", pvar_getinfo_davovlan, 0, NULL },
    {"vlan_port_11", pvar_getinfo_davovlan, 0, NULL },
    {"vlan_port_12", pvar_getinfo_davovlan, 0, NULL },
    {"vlan_port_13", pvar_getinfo_davovlan, 0, NULL },
    {"vlan_port_14", pvar_getinfo_davovlan, 0, NULL },
    {"vlan_port_15", pvar_getinfo_davovlan, 0, NULL },

    {"vlan_tagged_0", pvar_getinfo_davovlan, 0, NULL },
    {"vlan_tagged_1", pvar_getinfo_davovlan, 0, NULL },
    {"vlan_tagged_2", pvar_getinfo_davovlan, 0, NULL },
    {"vlan_tagged_3", pvar_getinfo_davovlan, 0, NULL },
    {"vlan_tagged_4", pvar_getinfo_davovlan, 0, NULL },
    {"vlan_tagged_5", pvar_getinfo_davovlan, 0, NULL },
    {"vlan_tagged_6", pvar_getinfo_davovlan, 0, NULL },
    {"vlan_tagged_7", pvar_getinfo_davovlan, 0, NULL },
    {"vlan_tagged_8", pvar_getinfo_davovlan, 0, NULL },
    {"vlan_tagged_9", pvar_getinfo_davovlan, 0, NULL },
    {"vlan_tagged_10", pvar_getinfo_davovlan, 0, NULL },
    {"vlan_tagged_11", pvar_getinfo_davovlan, 0, NULL },
    {"vlan_tagged_12", pvar_getinfo_davovlan, 0, NULL },
    {"vlan_tagged_13", pvar_getinfo_davovlan, 0, NULL },
    {"vlan_tagged_14", pvar_getinfo_davovlan, 0, NULL },
    {"vlan_tagged_15", pvar_getinfo_davovlan, 0, NULL },

    {"wan_link_status", pvar_getinfo_link_status, 0, NULL },
    {"lan1_link_status", pvar_getinfo_link_status, 0, NULL },
    {"lan2_link_status", pvar_getinfo_link_status, 0, NULL },
    {"lan3_link_status", pvar_getinfo_link_status, 0, NULL },
    {"lan4_link_status", pvar_getinfo_link_status, 0, NULL },
    {"wan_linkUp", pvar_getinfo_link_status, 0, NULL },
    {"lan1_linkUp", pvar_getinfo_link_status, 0, NULL },
    {"lan2_linkUp", pvar_getinfo_link_status, 0, NULL },
    {"lan3_linkUp", pvar_getinfo_link_status, 0, NULL },
    {"lan4_linkUp", pvar_getinfo_link_status, 0, NULL },
    {"wan_link_duplex", pvar_getinfo_link_duplex, 0, NULL },
    {"lan1_link_duplex", pvar_getinfo_link_duplex, 0, NULL },
    {"lan2_link_duplex", pvar_getinfo_link_duplex, 0, NULL },
    {"lan3_link_duplex", pvar_getinfo_link_duplex, 0, NULL },
    {"lan4_link_duplex", pvar_getinfo_link_duplex, 0, NULL },


    {"wan_rx_pause", pvar_getinfo_pause_status, 0, NULL },
    {"wan_tx_pause", pvar_getinfo_pause_status, 0, NULL },
    {"lan1_rx_pause", pvar_getinfo_pause_status, 0, NULL },
    {"lan1_tx_pause", pvar_getinfo_pause_status, 0, NULL },
    {"lan2_rx_pause", pvar_getinfo_pause_status, 0, NULL },
    {"lan2_tx_pause", pvar_getinfo_pause_status, 0, NULL },
    {"lan3_rx_pause", pvar_getinfo_pause_status, 0, NULL },
    {"lan3_tx_pause", pvar_getinfo_pause_status, 0, NULL },
    {"lan4_rx_pause", pvar_getinfo_pause_status, 0, NULL },
    {"lan4_tx_pause", pvar_getinfo_pause_status, 0, NULL },

    {"cfg_igmp_active", pvar_getinfo_igmp, 0, NULL },
    {"IGMP_FAST_LEAVE", pvar_getinfo_igmp, 0, NULL },

    {"igmp_expire_time", pvar_getnvram, (long)(void *)"x_igmp_expire_time", "180"},
    {"igmp_query_interval", pvar_getnvram, (long)(void *)"x_igmp_query_interval", "125"},
    {"igmp_query_res_interval", pvar_getnvram, (long)(void *)"x_igmp_query_res_interval", "5"},

    {"detect_offer", pvar_getinfo_detect_offer, 0, NULL },

    {"cfg_format", pvar_getnvram, (long)(void *)"FORMAT_VERSION", NULL},
    {"cfg_file", pvar_getnvram, (long)(void *)"cfg_filename", NULL},

    {"ipv6_manual_addr", pvar_getnvram, (long)(void *)"x_ipv6_manual_addr", ""},
    {"ipv6_manual_prefix_len", pvar_getnvram, (long)(void *)"x_ipv6_manual_prefix_len", ""},
    {"ipv6_manual_gateway", pvar_getnvram, (long)(void *)"x_ipv6_manual_gateway", ""},
    {"ipv6_manual_dns1", pvar_getnvram, (long)(void *)"x_ipv6_manual_dns1", ""},
    {"ipv6_manual_dns2", pvar_getnvram, (long)(void *)"x_ipv6_manual_dns2", ""},

    {"ip_conflict", pvar_getinfo_ip_conflict, 0, NULL },
    {"dad_duplecheck", pvar_getinfo_dad_duplecheck, 0, NULL },

    {"PING_TEST_RESULT", pvar_getnvram, (long)(void *)"x_PING_TEST_RESULT", ""},

    {"igmp_querier_auto", pvar_getnvram, (long)(void *)"x_igmp_querier_auto", "1"},
    {"igmp_jlimit_enabled", pvar_getinfo_igmp, 0, NULL },
    {"igmp_querier_enabled", pvar_getinfo_igmp, 0, NULL },
    {"igmp_querier_interval", pvar_getnvram, (long)(void *)"x_igmp_querier_interval", "125"},
    {"dv_igmp_limite_lan1", pvar_getnvram, (long)(void *)"x_igmp_limite_lan1", "32"},
    {"dv_igmp_limite_lan2", pvar_getnvram, (long)(void *)"x_igmp_limite_lan2", "32"},
    {"dv_igmp_limite_lan3", pvar_getnvram, (long)(void *)"x_igmp_limite_lan3", "32"},
    {"dv_igmp_limite_lan4", pvar_getnvram, (long)(void *)"x_igmp_limite_lan4", "32"},
    {"dv_igmp_limite_sys", pvar_getnvram, (long)(void *)"x_igmp_limite_sys", "128"},
    {"igmp_block_enabled", pvar_getinfo_igmp, 0, NULL },
    {"igmp_thresh_hold_value", pvar_getinfo_igmp, 0, NULL },
    {"igmp_block_period_value", pvar_getinfo_igmp, 0, NULL },
    {"igmp_grpmem_interval", pvar_getnvram, (long)(void *)"x_igmp_grpmem_interval", "60"},

    {"vap3_disabled", pvar_getnvram, (long)(void *)"WLAN0_VAP3_WLAN_DISABLED", NULL},

    {"auto_upgrade_info", pvar_getinfo_auto_upgrade_info, 0, NULL },
    {"x_autoup_domain", pvar_getnvram, (long)(void *)"x_autoup_domain", NULL},
    {"x_autoup_file", pvar_getnvram, (long)(void *)"x_autoup_file", NULL},
    {"x_autoup_prefix", pvar_getnvram, (long)(void *)"x_autoup_prefix", NULL},

    {"sdmzHost", pvar_getnvram, (long)(void *)"x_SDMZ_HOST", NULL},

    {"jumbo_enable", pvar_getnvram, (long)(void *)"x_jumbo_enable", "0"},
    {"jumbo_size", pvar_getnvram, (long)(void *)"x_jumbo_size", "0"},

    {"x_BCSTORM_CTRL_ENABLE", pvar_getnvram, (long)(void *)"x_BCSTORM_CTRL_ENABLE", "0"},
    {"x_BCSTORM_CTRL_PERCENT", pvar_getnvram, (long)(void *)"x_BCSTORM_CTRL_PERCENT", "1"},
    {"x_BCSTORM_CTRL_BPS", pvar_getnvram, (long)(void *)"x_BCSTORM_CTRL_BPS", "3036"},
    {"x_BCSTORM_PORT0_ENABLE", pvar_getnvram, (long)(void *)"x_BCSTORM_PORT0_ENABLE", "0"},
    {"x_BCSTORM_PORT1_ENABLE", pvar_getnvram, (long)(void *)"x_BCSTORM_PORT1_ENABLE", "0"},
    {"x_BCSTORM_PORT2_ENABLE", pvar_getnvram, (long)(void *)"x_BCSTORM_PORT2_ENABLE", "0"},
    {"x_BCSTORM_PORT3_ENABLE", pvar_getnvram, (long)(void *)"x_BCSTORM_PORT3_ENABLE", "0"},
    {"x_BCSTORM_PORT4_ENABLE", pvar_getnvram, (long)(void *)"x_BCSTORM_PORT4_ENABLE", "0"},

    {"pingSecCount", pvar_getnvram, (long)(void *)"x_icmp_reply_rate", "0"},
    {"snmp_input_rate", pvar_getnvram, (long)(void *)"x_snmp_input_rate", "0"},

    {"snmp_com1_check", pvar_getinfo_snmp_com_check, 0, NULL },
    {"snmp_com2_check", pvar_getinfo_snmp_com_check, 0, NULL },
    {"SNMP_GET_COMMUNITY", pvar_getnvram, (long)(void *)"x_SNMP_GET_COMMUNITY", "iptvshro^_"},
    {"SNMP_SET_COMMUNITY", pvar_getnvram, (long)(void *)"x_SNMP_SET_COMMUNITY", "iptvshrw^_"},
    {"snmp_trap_server", pvar_getnvram, (long)(void *)"x_SNMP_TRAP_SERVER", "iptvsh-trap.skbroadband.com"},
    {"snmp_trap_server2", pvar_getnvram, (long)(void *)"x_WIFI_TRAP_SERVER", "iptvap-trap.skbroadband.com"},
    {"SNMP_TRP_COMMUNITY", pvar_getnvram, (long)(void *)"x_SNMP_TRP_COMMUNITY", "iptvshrw^_"},

    {"REPEATER_ENABLED1", pvar_getnvram, (long)(void *)"REPEATER_ENABLED1", "0"},
    {"REPEATER_ENABLED2", pvar_getnvram, (long)(void *)"REPEATER_ENABLED2", "0"},
    {"REPEATER_SSID1", pvar_getnvram, (long)(void *)"REPEATER_SSID1", "0", (void *)pwrite_puts_webtrans },
    {"REPEATER_SSID2", pvar_getnvram, (long)(void *)"REPEATER_SSID2", "0", (void *)pwrite_puts_webtrans },

    {"x_bs_rssi_th", pvar_getinfo_bs_rssi_th, 0, NULL },

    {"local_connection", pvar_getinfo_local_connection, 0, NULL },
    {"wan-dns", pvar_getinfo_wandns, 0, NULL },
    {"repeater_interface", pvar_getinfo_repeater_interface, 0, NULL },

    {"dv_port_mirror", pvar_getinfo_dv_port_mirror, 0, NULL },
    {"dvport_mirror_enable", pvar_getinfo_dvport, 0, NULL },
    {"dvport_mirror_from", pvar_getinfo_dvport, 0, NULL },
    {"dvport_mirror_to", pvar_getinfo_dvport, 0, NULL },

    {"qosQ_init_js", pvar_getinfo_davoqos, 0, NULL },
    {"qos_remark_js", pvar_getinfo_davoqos, 0, NULL },
#endif

#ifdef VPN_SUPPORT
    {"vpnTblIdx", pvar_getinfo_vpn, 0, NULL },
    {"ipsecConnName", pvar_getinfo_vpn, 0, NULL },
    {"ipsecLocalIp", pvar_getinfo_vpn, 0, NULL },
    {"ipsecLocalIpMask", pvar_getinfo_vpn, 0, NULL },
    {"ipsecRemoteIp", pvar_getinfo_vpn, 0, NULL },
    {"ipsecRemoteIpMask", pvar_getinfo_vpn, 0, NULL },
    {"ipsecRemoteGateway", pvar_getinfo_vpn, 0, NULL },
    {"ipsecSpi", pvar_getinfo_vpn, 0, NULL },
    {"ipsecEncrKey", pvar_getinfo_vpn, 0, NULL },
    {"ipsecAuthKey", pvar_getinfo_vpn, 0, NULL },
    {"ikePsKey", pvar_getinfo_vpn, 0, NULL },
    {"ikeLifeTime", pvar_getinfo_vpn, 0, NULL },
    {"ikeEncr", pvar_getinfo_vpn, 0, NULL },
    {"ikeAuth", pvar_getinfo_vpn, 0, NULL },
    {"ikeKeyGroup", pvar_getinfo_vpn, 0, NULL },
    {"ipsecLifeTime", pvar_getinfo_vpn, 0, NULL },
    {"ipsecPfs", pvar_getinfo_vpn, 0, NULL },
    {"ipsecLocalId", pvar_getinfo_vpn, 0, NULL },
    {"ipsecRemoteId", pvar_getinfo_vpn, 0, NULL },
    {"rtRsaKey", pvar_getinfo_vpn, 0, NULL },
#endif

#if defined(CONFIG_RTK_VLAN_WAN_TAG_SUPPORT)
    {"vlan_wan_menu_onoff", pvar_printarg, (long)(void *)"firewall.addItem('VLAN_WAN', 'skb_vlan_wan.htm',"
        " '', 'Setup VLAN WAN TAG');", NULL },
    {"vlan_wan_tag", pvar_getapmib,  MIB_VLAN_WAN_TAG, (void *)pwrite_itoa },
    {"vlan_wan_bridge_tag", pvar_getapmib,  MIB_VLAN_WAN_BRIDGE_TAG, (void *)pwrite_itoa },
    {"vlan_wan_bridge_multicast_tag", pvar_getapmib,  MIB_VLAN_WAN_BRIDGE_MULTICAST_TAG, (void *)pwrite_itoa },
    {"vlan_wan_host_tag", pvar_getapmib,  MIB_VLAN_WAN_HOST_TAG, (void *)pwrite_itoa },
    {"vlan_wan_host_pri", pvar_getapmib, MIB_VLAN_WAN_HOST_PRI, (void *)pwrite_itoa },
    {"vlan_wan_wifi_root_tag", pvar_getapmib, MIB_VLAN_WAN_WIFI_ROOT_TAG, (void *)pwrite_itoa },
    {"vlan_wan_wifi_root_pri", pvar_getapmib, MIB_VLAN_WAN_WIFI_ROOT_PRI, (void *)pwrite_itoa },
    {"vlan_wan_wifi_vap0_tag", pvar_getapmib, MIB_VLAN_WAN_WIFI_VAP0_TAG, (void *)pwrite_itoa },
    {"vlan_wan_wifi_vap0_pri", pvar_getapmib, MIB_VLAN_WAN_WIFI_VAP0_PRI, (void *)pwrite_itoa },
    {"vlan_wan_wifi_vap1_tag", pvar_getapmib, MIB_VLAN_WAN_WIFI_VAP1_TAG, (void *)pwrite_itoa },
    {"vlan_wan_wifi_vap1_pri", pvar_getapmib, MIB_VLAN_WAN_WIFI_VAP1_PRI, (void *)pwrite_itoa },
    {"vlan_wan_wifi_vap2_tag", pvar_getapmib, MIB_VLAN_WAN_WIFI_VAP2_TAG, (void *)pwrite_itoa },
    {"vlan_wan_wifi_vap2_pri", pvar_getapmib, MIB_VLAN_WAN_WIFI_VAP2_PRI, (void *)pwrite_itoa },
    {"vlan_wan_wifi_vap3_tag", pvar_getapmib, MIB_VLAN_WAN_WIFI_VAP3_TAG, (void *)pwrite_itoa },
    {"vlan_wan_wifi_vap3_pri", pvar_getapmib, MIB_VLAN_WAN_WIFI_VAP3_PRI, (void *)pwrite_itoa },
    {"vlan_wan_enable", pvar_getinfo_rtkvlan, 0, NULL },
    {"vlan_wan_bridge_enable", pvar_getinfo_rtkvlan, 0, NULL },
    {"vlan_wan_bridge_port_0", pvar_getinfo_rtkvlan, 0, NULL },
    {"vlan_wan_bridge_port_1", pvar_getinfo_rtkvlan, 0, NULL },
    {"vlan_wan_bridge_port_2", pvar_getinfo_rtkvlan, 0, NULL },
    {"vlan_wan_bridge_port_3", pvar_getinfo_rtkvlan, 0, NULL },
    {"vlan_wan_bridge_port_wifi_root", pvar_getinfo_rtkvlan, 0, NULL },
    {"vlan_wan_bridge_port_wifi_vap0", pvar_getinfo_rtkvlan, 0, NULL },
    {"vlan_wan_bridge_port_wifi_vap1", pvar_getinfo_rtkvlan, 0, NULL },
    {"vlan_wan_bridge_port_wifi_vap2", pvar_getinfo_rtkvlan, 0, NULL },
    {"vlan_wan_bridge_port_wifi_vap3", pvar_getinfo_rtkvlan, 0, NULL },
    {"vlan_wan_bridge_multicast_enable", pvar_getinfo_rtkvlan, 0, NULL },
    {"vlan_wan_host_enable", pvar_getinfo_rtkvlan, 0, NULL },
    {"vlan_wan_wifi_root_enable", pvar_getinfo_rtkvlan, 0, NULL },
    {"vlan_wan_wifi_vap0_enable", pvar_getinfo_rtkvlan, 0, NULL },
    {"vlan_wan_wifi_vap1_enable", pvar_getinfo_rtkvlan, 0, NULL },
    {"vlan_wan_wifi_vap2_enable", pvar_getinfo_rtkvlan, 0, NULL },
    {"vlan_wan_wifi_vap3_enable", pvar_getinfo_rtkvlan, 0, NULL },
#else
    {"vlan_wan_menu_onoff", pvar_printarg, (long)(void *)"", NULL },
#endif

#if defined(GW_QOS_ENGINE) || defined(QOS_BY_BANDWIDTH)
    {"qosManualUplinkSpeed", pvar_getmib, MIB_QOS_MANUAL_UPLINK_SPEED, (void *)pwrite_itoa },
    {"qosManualDownlinkSpeed", pvar_getmib, MIB_QOS_MANUAL_DOWNLINK_SPEED, (void *)pwrite_itoa },
    {"qosEnabled", pvar_getinfo_qos, 0, NULL },
    {"qosAutoUplinkSpeed", pvar_getinfo_qos, 0, NULL },
#endif

#ifdef DOS_SUPPORT
    {"syssynFlood", pvar_getmib, MIB_DOS_SYSSYN_FLOOD, (void *)pwrite_itoa },
    {"sysfinFlood", pvar_getmib, MIB_DOS_SYSFIN_FLOOD, (void *)pwrite_itoa },
    {"sysudpFlood", pvar_getmib, MIB_DOS_SYSUDP_FLOOD, (void *)pwrite_itoa },
    {"sysicmpFlood", pvar_getmib, MIB_DOS_SYSICMP_FLOOD, (void *)pwrite_itoa },
    {"pipsynFlood", pvar_getmib, MIB_DOS_PIPSYN_FLOOD, (void *)pwrite_itoa },
    {"pipfinFlood", pvar_getmib, MIB_DOS_PIPFIN_FLOOD, (void *)pwrite_itoa },
    {"pipudpFlood", pvar_getmib, MIB_DOS_PIPUDP_FLOOD, (void *)pwrite_itoa },
    {"pipicmpFlood", pvar_getmib, MIB_DOS_PIPICMP_FLOOD, (void *)pwrite_itoa },
    {"blockTime", pvar_getmib, MIB_DOS_BLOCK_TIME, (void *)pwrite_itoa },
#endif // DOS_SUPPORT

#if defined(CONFIG_RTL_MULTI_LAN_DEV)
    {"rtlMultiLanDev", pvar_printarg, (long)(void *)"1", NULL },
#else
    {"rtlMultiLanDev", pvar_printarg, (long)(void *)"0", NULL },
#endif

    {"wan-ppp-idle", pvar_getmib, MIB_PPP_IDLE_TIME, (void *)pwrite_time_sectomin },
    {"wan-ppp-idle2", pvar_getmib, MIB_PPP_IDLE_TIME2, (void *)pwrite_time_sectomin },
    {"wan-ppp-idle3", pvar_getmib, MIB_PPP_IDLE_TIME3, (void *)pwrite_time_sectomin },
    {"wan-ppp-idle4", pvar_getmib, MIB_PPP_IDLE_TIME4, (void *)pwrite_time_sectomin },

    {"S1_F1_start", pvar_getmib, MIB_SUBNET1_F1_START, (void *)pwrite_in_ntoa, "0.0.0.0" },
    {"S1_F1_end", pvar_getmib, MIB_SUBNET1_F1_END, (void *)pwrite_in_ntoa, "0.0.0.0" },
    {"S1_F2_start", pvar_getmib, MIB_SUBNET1_F2_START, (void *)pwrite_in_ntoa, "0.0.0.0" },
    {"S1_F2_end", pvar_getmib, MIB_SUBNET1_F2_END, (void *)pwrite_in_ntoa, "0.0.0.0" },
    {"S1_F3_start", pvar_getmib, MIB_SUBNET1_F3_START, (void *)pwrite_in_ntoa, "0.0.0.0" },
    {"S1_F3_end", pvar_getmib, MIB_SUBNET1_F3_END, (void *)pwrite_in_ntoa, "0.0.0.0" },

    {"S2_F1_start", pvar_getmib, MIB_SUBNET2_F1_START, (void *)pwrite_in_ntoa, "0.0.0.0" },
    {"S2_F1_end", pvar_getmib, MIB_SUBNET2_F1_END, (void *)pwrite_in_ntoa, "0.0.0.0" },
    {"S2_F2_start", pvar_getmib, MIB_SUBNET2_F2_START, (void *)pwrite_in_ntoa, "0.0.0.0" },
    {"S2_F2_end", pvar_getmib, MIB_SUBNET2_F2_END, (void *)pwrite_in_ntoa, "0.0.0.0" },
    {"S2_F3_start", pvar_getmib, MIB_SUBNET2_F3_START, (void *)pwrite_in_ntoa, "0.0.0.0" },
    {"S2_F3_end", pvar_getmib, MIB_SUBNET2_F3_END, (void *)pwrite_in_ntoa, "0.0.0.0" },

    {"S3_F1_start", pvar_getmib, MIB_SUBNET3_F1_START, (void *)pwrite_in_ntoa, "0.0.0.0" },
    {"S3_F1_end", pvar_getmib, MIB_SUBNET3_F1_END, (void *)pwrite_in_ntoa, "0.0.0.0" },
    {"S3_F2_start", pvar_getmib, MIB_SUBNET3_F2_START, (void *)pwrite_in_ntoa, "0.0.0.0" },
    {"S3_F2_end", pvar_getmib, MIB_SUBNET3_F2_END, (void *)pwrite_in_ntoa, "0.0.0.0" },
    {"S3_F3_start", pvar_getmib, MIB_SUBNET3_F3_START, (void *)pwrite_in_ntoa, "0.0.0.0" },
    {"S3_F3_end", pvar_getmib, MIB_SUBNET3_F3_END, (void *)pwrite_in_ntoa, "0.0.0.0" },

    {"S4_F1_start", pvar_getmib, MIB_SUBNET4_F1_START, (void *)pwrite_in_ntoa, "0.0.0.0" },
    {"S4_F1_end", pvar_getmib, MIB_SUBNET4_F1_END, (void *)pwrite_in_ntoa, "0.0.0.0" },
    {"S4_F2_start", pvar_getmib, MIB_SUBNET4_F2_START, (void *)pwrite_in_ntoa, "0.0.0.0" },
    {"S4_F2_end", pvar_getmib, MIB_SUBNET4_F2_END, (void *)pwrite_in_ntoa, "0.0.0.0" },
    {"S4_F3_start", pvar_getmib, MIB_SUBNET4_F3_START, (void *)pwrite_in_ntoa, "0.0.0.0" },
    {"S4_F3_end", pvar_getmib, MIB_SUBNET4_F3_END, (void *)pwrite_in_ntoa, "0.0.0.0" },

    {"pppSubNet1", pvar_getmib, MIB_PPP_SUBNET1, (void*)pwrite_puts },

    {"pppUserName2", pvar_getmib, MIB_PPP_USER_NAME2, (void *)pwrite_puts_webtrans },
    {"pppUserName3", pvar_getmib, MIB_PPP_USER_NAME3, (void *)pwrite_puts_webtrans },
    {"pppUserName4", pvar_getmib, MIB_PPP_USER_NAME4, (void *)pwrite_puts_webtrans },

    {"pppPassword2", pvar_getmib, MIB_PPP_PASSWORD2, (void *)pwrite_puts_webtrans },
    {"pppPassword3", pvar_getmib, MIB_PPP_PASSWORD3, (void *)pwrite_puts_webtrans },
    {"pppPassword4", pvar_getmib, MIB_PPP_PASSWORD4, (void *)pwrite_puts_webtrans },

    {"pppServiceName2", pvar_getmib, MIB_PPP_SERVICE_NAME2, (void*)pwrite_puts },
    {"pppServiceName3", pvar_getmib, MIB_PPP_SERVICE_NAME3, (void*)pwrite_puts },
    {"pppServiceName4", pvar_getmib, MIB_PPP_SERVICE_NAME4, (void*)pwrite_puts },

    {"pppMtuSize2", pvar_getmib, MIB_PPP_MTU_SIZE2, (void *)pwrite_itoa },
    {"pppMtuSize3", pvar_getmib, MIB_PPP_MTU_SIZE3, (void *)pwrite_itoa },
    {"pppMtuSize4", pvar_getmib, MIB_PPP_MTU_SIZE4, (void *)pwrite_itoa },

    {"wan-pptp-idle", pvar_getmib, MIB_PPTP_IDLE_TIME, (void *)pwrite_time_sectomin },
    {"wan-l2tp-idle", pvar_getmib, MIB_L2TP_IDLE_TIME, (void *)pwrite_time_sectomin },

    {"dmzHost", pvar_getmib, MIB_DMZ_HOST, (void *)pwrite_in_ntoa, "0.0.0.0" },
    {"wan_mac_clone_address", pvar_getinfo_wan_mac_clone_address, 0, NULL },

    {"wanMac", pvar_getmib, MIB_WAN_MAC_ADDR, (void *)pwrite_etoa_without_colon },
    {"wan_default_mac_address", pvar_getmib, MIB_HW_NIC1_ADDR, (void *)pwrite_etoa },

    {"fixedIpMtuSize", pvar_getmib, MIB_FIXED_IP_MTU_SIZE, (void *)pwrite_itoa },
    {"dhcpMtuSize", pvar_getmib, MIB_DHCP_MTU_SIZE, (void *)pwrite_itoa },

    {"wanDhcp-current", pvar_getinfo_wanDhcp_current, 0, NULL },

    {"wan-ip", pvar_getinfo_waninfo, 0, NULL },
    {"wan-mask", pvar_getinfo_waninfo, 0, NULL },
    {"wan-gateway", pvar_getinfo_waninfo, 0, NULL },
    {"wan-hwaddr", pvar_getinfo_waninfo, 0, NULL },
    {"wanTxPacketNum", pvar_getinfo_waninfo, 0, NULL },
    {"wanRxPacketNum", pvar_getinfo_waninfo, 0, NULL },

    {"ddnsDomainName", pvar_getmib, MIB_DDNS_DOMAIN_NAME, (void *)pwrite_puts },
    {"ddnsUser", pvar_getmib, MIB_DDNS_USER, (void *)pwrite_puts },
    {"ddnsPassword", pvar_getmib, MIB_DDNS_PASSWORD, (void *)pwrite_puts },

    {"wlanMode", pvar_getmib, MIB_WLAN_MODE, (void *)pwrite_itoa },
    {"wlanModeByStr", pvar_getinfo_wlanModeByStr, 0, NULL },

    //{"hostName", pvar_getmib, MIB_HOST_NAME, (void *)pwrite_puts },
#endif //HOME_GATEWAY


    //
    // General Part(nvram, apmib, etc, ...)
    //
    {"uptime", pvar_uptime, 0, NULL},
	{"year", pvar_ctime, 0, NULL},
	{"month", pvar_ctime, 0, NULL},
	{"day", pvar_ctime, 0, NULL},
	{"hour", pvar_ctime, 0, NULL},
	{"minute", pvar_ctime, 0, NULL},
	{"second", pvar_ctime, 0, NULL},

    {"ip", pvar_getInAddr, IP_ADDR, IF_BR },
    {"mask", pvar_getInAddr, SUBNET_MASK, IF_BR},
    {"gateway", pvar_getinfo_gateway, 0, NULL },
    {"hwaddr", pvar_getInAddr, HW_ADDR, IF_BR},

    {"wlanTxPacketNum", pvar_getinfo_netStat, 0, NULL },
    {"wlanRxPacketNum", pvar_getinfo_netStat, 0, NULL },
    {"lanTxPacketNum", pvar_getinfo_netStat, 0, NULL },
    {"lanRxPacketNum", pvar_getinfo_netStat, 0, NULL },
    {"lan2TxPacketNum", pvar_getinfo_netStat, 0, NULL },
    {"lan2RxPacketNum", pvar_getinfo_netStat, 0, NULL },
    {"lan3TxPacketNum", pvar_getinfo_netStat, 0, NULL },
    {"lan3RxPacketNum", pvar_getinfo_netStat, 0, NULL },
    {"lan4TxPacketNum", pvar_getinfo_netStat, 0, NULL },
    {"lan4RxPacketNum", pvar_getinfo_netStat, 0, NULL },

    {"opMode", pvar_getmib, MIB_OP_MODE, (void *)pwrite_itoa },
    {"devname", pvar_getinfo_devname, 0, NULL },
    {"device_name", pvar_getmib, MIB_DEVICE_NAME, (void *)pwrite_puts },
    {"bridgeMac", pvar_getmib, MIB_ELAN_MAC_ADDR, (void *)pwrite_etoa },

    {"dhcpRangeStart", pvar_getmib, MIB_DHCP_CLIENT_START, (void *)pwrite_in_ntoa, "0.0.0.0" },
    {"dhcpRangeEnd", pvar_getmib, MIB_DHCP_CLIENT_END, (void *)pwrite_in_ntoa, "0.0.0.0" },

    {"ntpTimeZone", pvar_getmib, MIB_NTP_TIMEZONE, (void *)pwrite_puts },

    {"ip-lan", pvar_getinfo_iplan, 0, NULL },
    {"ip-rom", pvar_getmib, MIB_IP_ADDR, (void *)pwrite_in_ntoa, "0.0.0.0" },
    {"mask-rom", pvar_getmib, MIB_SUBNET_MASK, (void *)pwrite_in_ntoa, "0.0.0.0" },
    {"gateway-rom", pvar_getmib, MIB_DEFAULT_GATEWAY, (void *)pwrite_in_ntoa, "0.0.0.0" },
    {"static_dhcp_onoff", pvar_getmib, MIB_DHCPRSVDIP_ENABLED, (void *)pwrite_itoa },

    {"wan-dns1", pvar_getmib, MIB_DNS1, (void *)pwrite_in_ntoa, "0.0.0.0" },
    {"wan-dns2", pvar_getmib, MIB_DNS2, (void *)pwrite_in_ntoa, "0.0.0.0" },
    {"wan-dns3", pvar_getmib, MIB_DNS3, (void *)pwrite_in_ntoa, "0.0.0.0" },

  	{"pppServiceName", pvar_getmib, MIB_PPP_SERVICE_NAME, (void *)pwrite_puts },
    {"pppMtuSize", pvar_getmib, MIB_PPP_MTU_SIZE, (void *)pwrite_itoa },
    {"pppUserName", pvar_getmib, MIB_PPP_USER_NAME, (void *)pwrite_puts_webtrans },
    {"pppPassword", pvar_getmib, MIB_PPP_PASSWORD, (void *)pwrite_puts_webtrans },

    {"rtLogServer", pvar_getmib, MIB_REMOTELOG_SERVER, (void *)pwrite_in_ntoa, "0.0.0.0" },
    {"domainName", pvar_getmib, MIB_DOMAIN_NAME, (void *)pwrite_puts },
    {"OPTION82", pvar_getnvram, (long)(void *)"OPTION82", NULL },

    {"pptpIp", pvar_getmib, MIB_PPTP_IP_ADDR, (void *)pwrite_in_ntoa, "0.0.0.0" },
#if defined(CONFIG_DYNAMIC_WAN_IP)
    {"pptpDefGw", pvar_getmib, MIB_PPTP_DEFAULT_GW, (void *)pwrite_in_ntoa, "0.0.0.0" },
#endif
    {"pptpSubnet", pvar_getmib, MIB_PPTP_SUBNET_MASK, (void *)pwrite_in_ntoa, "0.0.0.0" },
    {"pptpServerIp", pvar_getmib, MIB_PPTP_SERVER_IP_ADDR, (void *)pwrite_in_ntoa, "0.0.0.0" },
#if defined(CONFIG_GET_SERVER_IP_BY_DOMAIN)
    {"pptpServerDomain", pvar_getmib, MIB_PPTP_SERVER_DOMAIN, (void *)pwrite_puts },
#endif
    {"pptpMtuSize", pvar_getmib, MIB_PPTP_MTU_SIZE, (void *)pwrite_itoa },
    {"pptpUserName", pvar_getmib, MIB_PPTP_USER_NAME, (void *)pwrite_puts_webtrans },
    {"pptpPassword", pvar_getmib, MIB_PPTP_PASSWORD, (void *)pwrite_puts_webtrans },


    {"l2tpIp", pvar_getmib, MIB_L2TP_IP_ADDR, (void *)pwrite_in_ntoa, "0.0.0.0" },
    {"l2tpSubnet", pvar_getmib, MIB_L2TP_SUBNET_MASK, (void *)pwrite_in_ntoa, "0.0.0.0" },
#if defined(CONFIG_DYNAMIC_WAN_IP)
    {"l2tpDefGw", pvar_getmib, MIB_L2TP_DEFAULT_GW, (void *)pwrite_in_ntoa, "0.0.0.0" },
#endif
#if defined(CONFIG_GET_SERVER_IP_BY_DOMAIN)
    {"l2tpServerDomain", pvar_getmib, MIB_L2TP_SERVER_DOMAIN, (void *)pwrite_puts },
#endif
    {"l2tpServerIp", pvar_getmib, MIB_L2TP_SERVER_IP_ADDR, (void *)pwrite_in_ntoa, "0.0.0.0" },
    {"l2tpMtuSize", pvar_getmib, MIB_L2TP_MTU_SIZE, (void *)pwrite_itoa },
    {"l2tpUserName", pvar_getmib, MIB_L2TP_USER_NAME, (void *)pwrite_puts_webtrans },
    {"l2tpPassword", pvar_getmib, MIB_L2TP_PASSWORD, (void *)pwrite_puts_webtrans },

    {"ssid", pvar_getmib, MIB_WLAN_SSID, (void *)pwrite_puts_webtrans },
    {"channel", pvar_getmib, MIB_WLAN_CHANNEL, (void *)pwrite_itoa },
    {"fragThreshold", pvar_getmib, MIB_WLAN_FRAG_THRESHOLD, (void *)pwrite_itoa },
    {"rtsThreshold", pvar_getmib, MIB_WLAN_RTS_THRESHOLD, (void *)pwrite_itoa },
    {"beaconInterval", pvar_getmib, MIB_WLAN_BEACON_INTERVAL, (void *)pwrite_itoa },
    {"ackTimeout", pvar_getmib, MIB_WLAN_ACK_TIMEOUT, (void *)pwrite_itoa },
    {"dtimPeriod", pvar_getmib, MIB_WLAN_DTIM_PERIOD, (void *)pwrite_itoa },
    {"rateAdaptiveEnable", pvar_getmib, MIB_WLAN_RATE_ADAPTIVE_ENABLED, (void *)pwrite_itoa },
    {"pskValue", pvar_getmib, MIB_WLAN_WPA_PSK, (void *)pwrite_puts_webtrans },
    {"wdsPskValue", pvar_getmib, MIB_WLAN_WDS_PSK, (void *)pwrite_puts_webtrans },
    {"accountRsUpdateDelay", pvar_getmib, MIB_WLAN_ACCOUNT_RS_UPDATE_DELAY, (void *)pwrite_itoa },
    {"rsInterval", pvar_getmib, MIB_WLAN_RS_INTERVAL_TIME, (void *)pwrite_itoa },
    {"rsIp", pvar_getmib, MIB_WLAN_RS_IP, (void *)pwrite_in_ntoa, "0.0.0.0" },
    {"rsPort", pvar_getmib, MIB_WLAN_RS_PORT, (void *)pwrite_itoa },
    {"rsPassword", pvar_getmib, MIB_WLAN_RS_PASSWORD, (void *)pwrite_puts },
    {"accountRsInterval", pvar_getmib, MIB_WLAN_ACCOUNT_RS_INTERVAL_TIME, (void *)pwrite_itoa },
    {"accountRsIp", pvar_getmib, MIB_WLAN_ACCOUNT_RS_IP, (void *)pwrite_in_ntoa, "0.0.0.0" },
    {"accountRsPort", pvar_getmib, MIB_WLAN_ACCOUNT_RS_PORT, (void *)pwrite_itoa },
    {"accountRsPassword", pvar_getmib, MIB_WLAN_ACCOUNT_RS_PORT, (void *)pwrite_itoa },
    {"groupRekeyTime", pvar_getmib, MIB_WLAN_ACCOUNT_RS_PORT, (void *)pwrite_itoa },
    {"wlan_onoff_tkip", pvar_getmib, MIB_WLAN_11N_ONOFF_TKIP, (void *)pwrite_itoa },
    {"RFPower", pvar_getmib, MIB_WLAN_RFPOWER_SCALE, (void *)pwrite_itoa },
    {"wlanband", pvar_getmib, MIB_WLAN_BAND, (void *)pwrite_itoa },
    {"wispWanId", pvar_getmib, MIB_WISP_WAN_ID, (void *)pwrite_itoa },

    {"tx_restrict", pvar_getmib, MIB_WLAN_TX_RESTRICT, (void *)pwrite_itoa },
    {"rx_restrict", pvar_getmib, MIB_WLAN_RX_RESTRICT, (void *)pwrite_itoa },

    {"groupRekeyTimeDay", pvar_getmib, MIB_WLAN_WPA_GROUP_REKEY_TIME, (void *)pwrite_time_sectoday },
    {"groupRekeyTimeHr", pvar_getmib, MIB_WLAN_WPA_GROUP_REKEY_TIME, (void *)pwrite_time_sectohour },
    {"groupRekeyTimeMin", pvar_getmib, MIB_WLAN_WPA_GROUP_REKEY_TIME, (void *)pwrite_time_sectomin },
    {"groupRekeyTimeSec", pvar_getmib, MIB_WLAN_WPA_GROUP_REKEY_TIME, (void *)pwrite_time_sec },

    {"userName", pvar_getnvram, (long)(void *)"x_USER_NAME", NULL},

    {"davo-dns1", pvar_getnvram, (long)(void *)"secret_davo_dns1", "210.220.163.82"},
    {"ntpServerIp1", pvar_getnvram, (long)(void *)"x_ntp_server_ip1", "time.bora.net"},
    {"ntpServerIp2", pvar_getnvram, (long)(void *)"x_ntp_server_ip2", "time-b.nist.gov"},
    {"wl_reset_enable", pvar_getnvram, (long)(void *)"x_wlan_reset_enable", "1"},
    {"wl_reset_interval_day", pvar_getnvram, (long)(void *)"x_wlan_reset_interval_day", "8"},
    {"wl_reset_bw_kbps", pvar_getnvram, (long)(void *)"x_wlan_reset_bw_kbps", "500"},
    {"wl_reset_triger_time", pvar_getnvram, (long)(void *)"x_wlan_reset_triger_time", "3_5"},

    {"ldap_prefix", pvar_getnvram, (long)(void *)"x_ldap_autoup_prefix", NULL },
    {"x_MACFILTER_TBL_NUM", pvar_getnvram, (long)(void *)"x_MACFILTER_TBL_NUM", "0"},
    {"x_ldap_enabled", pvar_getnvram, (long)(void *)"x_ldap_enabled", "0"},
    {"x_ldap_autoup_enabled", pvar_getnvram, (long)(void *)"x_ldap_autoup_enabled", "0"},
    {"x_autoup_auth_svr", pvar_getnvram, (long)(void *)"x_autoup_auth_svr", NULL},
    {"x_ldap_upgrade_server", pvar_getnvram, (long)(void *)"x_ldap_autoup_domain", NULL},
    {"x_ldap_autoup_file", pvar_getnvram, (long)(void *)"x_ldap_autoup_file", NULL},

    {"x_auto_reboot_on_idle", pvar_getnvram, (long)(void *)"x_auto_reboot_on_idle", "1"},
    {"x_auto_wan_port_idle", pvar_getnvram, (long)(void *)"x_auto_wan_port_idle", "1"},
    {"x_auto_uptime", pvar_getnvram, (long)(void *)"x_auto_uptime", "7d"},
    {"x_auto_bw_kbps", pvar_getnvram, (long)(void *)"x_auto_bw_kbps", "1000"},
    {"x_auto_hour_range", pvar_getnvram, (long)(void *)"x_auto_hour_range", "04:30-05:00"},
    {"x_autoreboot_userforce", pvar_getnvram, (long)(void *)"x_autoreboot_userforce", "0"},
    {"x_autoreboot_week", pvar_getnvram, (long)(void *)"x_autoreboot_week", "5-5"},
    {"x_auto_reboot_enable", pvar_getnvram, (long)(void *)"x_auto_reboot_enable", "0"},
    {"x_telnet_enable", pvar_getnvram, (long)(void *)"x_telnet_enable", "0"},
    {"x_holepunch_enabled", pvar_getnvram, (long)(void *)"x_holepunch_enabled", "1"},
    {"x_holepunch_server", pvar_getnvram, (long)(void *)"x_holepunch_server", "aphp.skbroadband.com"},
    {"x_holepunch_port", pvar_getnvram, (long)(void *)"x_holepunch_port", "10219"},

    {"x_mac_clone_enable", pvar_getnvram, (long)(void *)"x_mac_clone_enable", "0"},

    {"powerConsumption_menu", pvar_printarg, (long)"", NULL },


    //
    // custom handler section
    //
    {"running_dnsmod", pvar_getinfo_running_dnsmod, 0, NULL },

    {"pocketRouter_Mode", pvar_getinfo_pocketRouter_Mode, 0, NULL },
    {"pocketRouter_Mode_countdown", pvar_getinfo_pocketRouter_Mode, 0, NULL },

    {"clientnum", pvar_getinfo_clientnum, 0, NULL },
    {"login_page_ssid", pvar_getinfo_loginpagessid, 0, NULL },

    {"wlProfile_checkbox", pvar_getinfo_wlprofile, 0, NULL },
    {"wlProfile_value", pvar_getinfo_wlprofile, 0, NULL },
    {"wlan_profile_num", pvar_getinfo_wlprofile, 0, NULL },
    {"wlEnableProfile", pvar_getinfo_wlprofile, 0, NULL },

    {"wdsEncrypt", pvar_getinfo_encrypttype, 0, NULL },

    {"is_wan_link", pvar_getinfo_getWanlink, 0, NULL },
    {"include_css", pvar_getinfo_include_css, 0, NULL },

    {"fwVersion", pvar_getinfo_verinfo, 0, NULL },
    {"buildTime", pvar_getinfo_verinfo, 0, NULL },

    {"wan-ip-rom", pvar_getinfo_waninfo_rom, 0, NULL },
    {"wan-mask-rom", pvar_getinfo_waninfo_rom, 0, NULL },
    {"wan-gateway-rom", pvar_getinfo_waninfo_rom, 0, NULL },

    {"pocketRouter_html_wan_hide_s", pvar_getinfo_pocketRouter_html, 0, NULL },
    {"pocketRouter_html_wan_hide_e", pvar_getinfo_pocketRouter_html, 0, NULL },
    {"pocketRouter_html_lan_hide_s", pvar_getinfo_pocketRouter_html, 0, NULL },
    {"pocketRouter_html_lan_hide_e", pvar_getinfo_pocketRouter_html, 0, NULL },

    {"dhcp-current", pvar_getinfo_dhcp, 0, NULL },
    {"dhcpLeaseTime",  pvar_getinfo_dhcp, 0, NULL },

    {"wlan_xTxR", pvar_getinfo_wlan_xTxR, 0, NULL },

    {"wmm_mode", pvar_getinfo_wmm_mode, 0, NULL },

    {"wep", pvar_getinfo_wep, 0, NULL},
    {"ssid_drv", pvar_getinfo_wlandrv, 0, NULL },
    {"state_drv", pvar_getinfo_wlandrv, 0, NULL },
    {"channel_drv", pvar_getinfo_wlandrv, 0, NULL },

    {"bssid", pvar_getinfo_bssid, 0, NULL },
    {"bssid_drv", pvar_getinfo_bssid, 0, NULL },

    {"wizard_menu_onoff", pvar_getinfo_wizard_menu_onoff, 0, NULL },

    {"wapiLocalAsCertsUploadForm", pvar_getinfo_print_wapiLocalAsCertsUploadForm, 0, NULL },

    {"status_warning", pvar_getinfo_reboot_check, 0, NULL },
    {"onoff_tkip_comment_start", pvar_getinfo_onoff_tkip_comment, 0, NULL },
    {"onoff_tkip_comment_end", pvar_getinfo_onoff_tkip_comment, 0, NULL },

    {"redirect_ip", pvar_getinfo_redirect_ip, 0, NULL },
    {"accessFromWan", pvar_getinfo_accessFromWan, 0, NULL },

    {"currFwBank", pvar_getinfo_FwBank, 0, NULL },
    {"backFwBank", pvar_getinfo_FwBank, 0, NULL },

    {"initpage", pvar_getinfo_initpage, 0, NULL },

    {"info_country", pvar_getinfo_wlan_country_domain, 0, NULL },
    {"info_2g", pvar_getinfo_wlan_country_domain, 0, NULL },
    {"info_5g", pvar_getinfo_wlan_country_domain, 0, NULL },
    {"country_str", pvar_getinfo_wlan_country_domain, 0, NULL },

    {"ethdot1x_onoff", pvar_getinfo_ethdot1x_onoff, 0, NULL },
    {"dsliteAftr", pvar_getinfo_ipv6_dslite, 0, NULL },
    {"ipv6WanIp", pvar_getinfo_ipv6_dslite, 0, NULL },
    {"ipv6DefGW", pvar_getinfo_ipv6_dslite, 0, NULL },

    {"wlan_max_conn", pvar_getinfo_get_wlan_name, 0, NULL },
    {"wlan_va0_max_conn", pvar_getinfo_get_wlan_name, 0, NULL },
    {"wlan_va1_max_conn", pvar_getinfo_get_wlan_name, 0, NULL },
    {"wlan_va2_max_conn", pvar_getinfo_get_wlan_name, 0, NULL },
    {"wlan_va3_max_conn", pvar_getinfo_get_wlan_name, 0, NULL },
    {"wlan_rssi_threshold", pvar_getinfo_get_wlan_name, 0, NULL },
    {"wlan_va1_rssi_threshold", pvar_getinfo_get_wlan_name, 0, NULL },
    {"wlan_va2_rssi_threshold", pvar_getinfo_get_wlan_name, 0, NULL },
    {"wlan_va3_rssi_threshold", pvar_getinfo_get_wlan_name, 0, NULL },

    {"prefix_used", pvar_getinfo_prefix_used, 0, NULL },
    {"saveConfig", pvar_getinfo_saveConfig, 0, NULL },

    {"x_WLS_REDIR_ENABLE", pvar_getinfo_get_wlan_name, 0, NULL },
	{"x_WLS_REDIR_HOST", pvar_getinfo_get_wlan_name, 0, NULL},
	{"x_WLS_REDIR_ALLOW0", pvar_getinfo_get_wlan_name, 0, NULL},
	{"x_WLS_REDIR_ALLOW1", pvar_getinfo_get_wlan_name, 0, NULL},
	{"x_WLS_REDIR_ALLOW2", pvar_getinfo_get_wlan_name, 0, NULL},
	{"x_WLS_REDIR_ALLOW3", pvar_getinfo_get_wlan_name, 0, NULL},
	{"x_WLS_REDIR_ALLOW4", pvar_getinfo_get_wlan_name, 0, NULL},

    {"hostName", pvar_getinfo_hostName, 0, NULL},


    //
    //End of List
    //
    {"End of List", NULL, 0, NULL}
};


void __attribute__ ((constructor)) pvar_sort(void)
{
	qsort(pgetvars, ARRAY_SIZE(pgetvars),
	      sizeof(struct aspvar),
	      (int (*)(const void *, const void *))pvar_compr);
}


int getInfo(request *wp, int argc, char **argv)
{
    int i = 0;
    char buffer[32] = "";
    struct aspvar k = {.name = argv[0] };
	struct aspvar *p;

    //printf("get parameter=%s\n", argv[0]);
	if (argv[0] == NULL) {
   		fprintf(stderr, "Insufficient args\n");
   		return -1;
   	}

	p = (struct aspvar *)bsearch(&k, pgetvars, ARRAY_SIZE(pgetvars),
				     sizeof(struct aspvar),
				     (int (*)(const void *, const void *))pvar_compr);
	if (p != NULL)
		return p->get(wp, argc, argv, p);

    for(i = 0; i < wlan_num; i++){
		sprintf(buffer, "wlan%d-status", i);
		if ( !strcmp(argv[0], buffer )) {
			wlan_idx = i ;
			sprintf(WLAN_IF, "wlan%d", i);
			return req_format_write(wp,"");
		}
	}

 	return -1;
}



/////////////////////////////////////////////////////////////////////////////
#if defined(CONFIG_RTL_819X) && !defined(CONFIG_WLAN_VAP_SUPPORT)// keith. disabled if no this mode in 96c
	#define DEF_MSSID_NUM 0
#else
//		#if defined(CONFIG_RTL8196B)//we disable mssid first for 96b
//	#define DEF_MSSID_NUM 0
//		#else
#ifdef CONFIG_RTL8196B_GW_8M
	#define DEF_MSSID_NUM 1
#else
	#define DEF_MSSID_NUM 4
#endif
//		#endif
#endif //#if defined(CONFIG_RTL_819X) && !defined(CONFIG_WLAN_VAP_SUPPORT)

request inner_req;
char inner_req_buff[1536];
int inner_getIndex(char *name)
{
	char *inner_argv[1] = {name};

	memset(inner_req_buff, '\0', sizeof(inner_req_buff));
	getIndex(&inner_req, 1, inner_argv);

	if (strlen(inner_req_buff)==0)
		sprintf(inner_req_buff, "\"\"");
	return 0;
}

int inner_getInfo(char *name)
{
	char *inner_argv[1] = {name};

	memset(inner_req_buff, '\0', sizeof(inner_req_buff));
	getInfo(&inner_req, 1, inner_argv);

	if (strlen(inner_req_buff)==0)
		sprintf(inner_req_buff, "\"\"");
	return 0;
}

static int get_macfilter_active_port(void)
{
	int tbl_num = 0, i;
	char buf[128], tmp[128];
	char *args[5], *p;
	int port =0;

	nvram_get_r_def("x_MACFILTER_TBL_NUM", tmp, sizeof(tmp), "0");
	tbl_num = atoi(tmp);
	if (tbl_num == 0)
		return 0;

	for (i = 1; i <= tbl_num; i++) {
		sprintf(tmp, "x_MACFILTER_TBL%d", i);
		nvram_get_r_def(tmp, buf, sizeof(buf), "");
		p = ydespaces(buf);
		if (ystrargs(p, args, 5, ",", 1) >= 2) {
			if (!strcmp(args[1], "01")) {
				port |= 1;
			} else if (!strcmp(args[1], "02")) {
				port |= 2;
			} else if (!strcmp(args[1], "04")) {
				port |= 4;
			} else if (!strcmp(args[1], "08")) {
				port |= 8;
			}
			if (port == 0xf)
				return port;
		}
	}
	return port;
}


#ifdef MBSSID
static int pvar_getindex_print_mwlanvar(request *wp, int argc, char **argv, struct aspvar *v)
{
    int type = v->lparam;

    if (type == MSSID_IDX)
        req_format_write(wp, "%d", mssid_idx);

    return 0;
}
#endif


#ifdef MBSSID
static int pvar_getindex_print_vwlanvar(request *wp, int argc, char **argv, struct aspvar *v)
{
    int type = v->lparam;

    if (type == VWLANVAR_NUM)
        req_format_write(wp, "%d", vwlan_num);
    else if (type == VWLANVAR_IDX)
        req_format_write(wp, "%d", vwlan_idx);

    return 0;
}
#endif


static int pvar_getindex_print_wlanvar(request *wp, int argc, char **argv, struct aspvar *v)
{
    int type = v->lparam;

    if (type == WLANVAR_NUM)
        req_format_write(wp, "%d", wlan_num);
    else if (type == WLANVAR_IDX)
        req_format_write(wp, "%d", wlan_idx);

    return 0;
}


#ifdef __DAVO__
static int pvar_getindex_snmp(request *wp, int argc, char **argv, struct aspvar *v)
{
    const char *name = v->name;
    char buffer[4] = "";

    if ( !strcmp(name, ("snmp_trap_enable"))) {
		nvram_get_r_def("x_SNMP_TRAP_ENABLE", buffer, sizeof(buffer), "1");
		if(buffer[0]=='1')
			req_format_write(wp, "checked");
		else
			return 0;
	}
	else if (!strcmp(name, "snmp_enable")) {
		nvram_get_r_def("x_SNMP_ENABLE", buffer, sizeof(buffer), "1");
		if (buffer[0]=='0')
			return 0;
		else
			return req_format_write(wp, "checked");
	}
	else if ( !strcmp(name, "snmp_com1")) {
		nvram_get_r_def("x_SNMP_COM1", buffer, sizeof(buffer), "1_0");
		if(buffer[2]=='0')
			sprintf(buffer, "%d", 0);
		else
			sprintf(buffer, "%d", 1);
		req_format_write(wp, buffer);
	}
	else if ( !strcmp(name, "snmp_com2")) {
		nvram_get_r_def("x_SNMP_COM2", buffer, sizeof(buffer), "1_1");
		if(buffer[2]=='0')
			sprintf(buffer, "%d", 0);
		else
			sprintf(buffer, "%d", 1);
		req_format_write(wp, buffer);
	}
    return 0;
}


static int pvar_getindex_UseAutoup(request *wp, int argc, char **argv, struct aspvar *v)
{
    int val = 0;
    char buffer[4] = "";
    int swms_enable, ldap_enable;

    val = 0;
    swms_enable = atoi(nvram_get("x_autoup_enabled"));
    ldap_enable = atoi(nvram_get("x_ldap_enabled"));

    if ( swms_enable )
        val = 1;
    else if (ldap_enable)
        val = 2;
    sprintf(buffer, "%d", val);

    req_format_write(wp, buffer);
    return 0;
}

static int pvar_getindex_isAdmin(request *wp, int argc, char **argv, struct aspvar *v)
{
    char buffer[4] = "";
    //char superName[32], decode_super[32], orgsupername[32];
	char superName[65];
    nvram_get_r_def("x_SUPER_NAME", superName, sizeof(superName), "");
    //memset(decode_super, 0, sizeof(decode_super));
    //b64_decode(superName, (unsigned char *)decode_super, sizeof(decode_super));
    //shift_str(decode_super, orgsupername, DECRYPT_ADD_VAL);
    //if (wp->userName && !strcmp(wp->userName, orgsupername))
    if (wp->userName && !strcmp(wp->userName, superName))
        sprintf(buffer, "%d", 0);
    else
        sprintf(buffer, "%d", 1);
    req_format_write(wp, buffer);
    return 0;
}


static int pvar_getindex_macfil_active_port(request *wp, int argc, char **argv, struct aspvar *v)
{
    char buffer[8] = "";
    sprintf(buffer, "%d", get_macfilter_active_port());
    req_format_write(wp, buffer);
    return 0;
}


static int pvar_getindex_swms_enable(request *wp, int argc, char **argv, struct aspvar *v)
{
    char *autoup=NULL;
    char buffer[4] = "";
    sprintf(buffer, "%d", 1);
    autoup = nvram_get("x_autoup_enabled");
    if (autoup != NULL) {
        if (autoup[0] == '0')
            sprintf(buffer, "%d", 0);
        else
            sprintf(buffer, "%d", 1);
    }
    req_format_write(wp, buffer);
    return 0;
}

static int pvar_getindex_dvnv_fast_igmp(request *wp, int argc, char **argv, struct aspvar *v)
{
    char buffer[4] = "";
    int intValue =0;

    apmib_get(MIB_IGMP_FAST_LEAVE_DISABLED, (void *)&intValue);
    if(intValue)
        sprintf(buffer, "%d", 0);
    else
        sprintf(buffer, "%d", 1);
    req_format_write(wp, buffer);
    return 0;
}
#endif


#ifdef CONFIG_CPU_UTILIZATION
static int pvar_getindex_cpunumber(request *wp, int argc, char **argv, struct aspvar *v)
{
    FILE *fh;
    char buf[64], tmp[3];
    char *p, *q;
    int cpu_num=-1;
    char buffer[4] = "";

    fh = fopen("/proc/cpuinfo", "r");
    if (!fh) {
        //			printf("Warning: cannot open /proc/cpuinfo\n");
        return req_format_write(wp, "Warning: cannot open /proc/cpuinfo");
    }

    while(!feof(fh))
    {
        fgets(buf, sizeof buf, fh);

        if(strncmp(buf, "processor", strlen("processor")) == 0)
        {
            p = buf + 9;
            q = tmp;
            while(*p)
            {
                if(*p >= '0' && *p <= '9')
                {
                    *q = *p;
                    q++;
                }
                p++;
            }
            *q='\0';
            cpu_num = atoi(tmp);
        }
    }

    fclose(fh);

    cpu_num++;
    sprintf(buffer, "%d", cpu_num);
    req_format_write(wp, buffer);
    return 0;
}
#endif


#if defined(CONFIG_RTL_ETH_802DOT1X_CLIENT_MODE_SUPPORT)
static int pvar_getindex_wan_eth_dot1x_enabled(request *wp, int argc, char **argv, struct aspvar *v)
{
    int val = 0;
    char buffer[4] = "";
    /* MIB_ELAN_ENABLE_1X bit0-->proxy/snooping enable/disable
     * MIB_ELAN_ENABLE_1X bit1-->client mode enable/disable
     */
    apmib_get(MIB_ELAN_ENABLE_1X,(void *)&val);
    if (val & ETH_DOT1X_CLIENT_MODE_ENABLE_BIT)
    {
        sprintf(buffer, "%d", 1) ;
    }
    else
    {
        sprintf(buffer, "%d", 0) ;
    }
    req_format_write(wp, buffer);
    return 0;
}
#endif


static int pvar_getindex_wizard_wlband_init(request *wp, int argc, char **argv, struct aspvar *v)
{
    int i=0, wlan_idx_ori, vwlan_idx_ori;
	char WLAN_IF_ori[40], inner_buf[2048];

    memset(WLAN_IF_ori, '\0', sizeof(WLAN_IF_ori));
    memset(inner_buf, '\0', sizeof(inner_buf));

    wlan_idx_ori = wlan_idx;
    vwlan_idx_ori = vwlan_idx;
    strcpy(WLAN_IF_ori, WLAN_IF);

    for (i=0; i <wlan_num; i++)
    {
        char tmpbuf[256];
        int val=0;
        sprintf(WLAN_IF, "wlan%d", i);
        SetWlan_idx(WLAN_IF);

        inner_getIndex("wlanDisabled");
        sprintf(tmpbuf, "%s[%d]=%s;\n", "wlanDisabled", wlan_idx, inner_req_buff);
        strcat(inner_buf, tmpbuf);

        inner_getIndex("RFType");
        sprintf(tmpbuf, "%s[%d]=%s;\n", "RFType", wlan_idx, inner_req_buff);
        strcat(inner_buf, tmpbuf);

        inner_getIndex("wlanMode");
        sprintf(tmpbuf, "%s[%d]=%s;\n", "APMode", wlan_idx, inner_req_buff);
        strcat(inner_buf, tmpbuf);

        inner_getIndex("band");
        val = atoi(inner_req_buff);
        if (val > 0) val=val-1;

        sprintf(tmpbuf, "%s[%d]=%d;\n", "bandIdx", wlan_idx, val);
        strcat(inner_buf, tmpbuf);
        sprintf(tmpbuf, "%s[%d]=%d;\n", "bandIdxClient", wlan_idx, val);
        strcat(inner_buf, tmpbuf);

        inner_getIndex("networkType");
        sprintf(tmpbuf, "%s[%d]=%s;\n", "networkType", wlan_idx, inner_req_buff);
        strcat(inner_buf, tmpbuf);

        inner_getIndex("regDomain");
        sprintf(tmpbuf, "%s[%d]=%s;\n", "regDomain", wlan_idx, inner_req_buff);
        strcat(inner_buf, tmpbuf);

        inner_getIndex("channel");
        sprintf(tmpbuf, "%s[%d]=%s;\n", "defaultChan", wlan_idx, inner_req_buff);
        strcat(inner_buf, tmpbuf);

        inner_getIndex("band");
        sprintf(tmpbuf, "%s[%d]=%s;\n", "usedBand", wlan_idx, inner_req_buff);
        strcat(inner_buf, tmpbuf);

        inner_getInfo("ssid");
        sprintf(tmpbuf, "%s[%d]='%s';\n", "ssid", wlan_idx, inner_req_buff);
        translate_control_code_sprintf(tmpbuf);
        strcat(inner_buf, tmpbuf);

        inner_getIndex("encrypt");
        sprintf(tmpbuf, "%s[%d]=%s;\n", "encrypt", wlan_idx, inner_req_buff);
        strcat(inner_buf, tmpbuf);

        inner_getIndex("wep");
        sprintf(tmpbuf, "%s[%d]=%s;\n", "wep", wlan_idx, inner_req_buff);
        strcat(inner_buf, tmpbuf);

        inner_getIndex("defaultKeyId");
        sprintf(tmpbuf, "%s[%d]=%s;\n", "defaultKeyId", wlan_idx, inner_req_buff);
        strcat(inner_buf, tmpbuf);

        inner_getIndex("pskFormat");
        sprintf(tmpbuf, "%s[%d]=%s;\n", "defPskFormat", wlan_idx, inner_req_buff);
        strcat(inner_buf, tmpbuf);

        inner_getIndex("wlanMacClone");
        sprintf(tmpbuf, "%s[%d]=%s;\n", "macClone", wlan_idx, inner_req_buff);
        strcat(inner_buf, tmpbuf);

        inner_getIndex("wpaCipher");
        sprintf(tmpbuf, "%s[%d]='%s';\n", "wpaCipher", wlan_idx, inner_req_buff);
        strcat(inner_buf, tmpbuf);

        inner_getIndex("wpa2Cipher");
        sprintf(tmpbuf, "%s[%d]='%s';\n", "wpa2Cipher", wlan_idx, inner_req_buff);
        strcat(inner_buf, tmpbuf);

        inner_getInfo("pskValue");
        sprintf(tmpbuf, "%s[%d]='%s';\n", "pskValue", wlan_idx, inner_req_buff);
        strcat(inner_buf, tmpbuf);

        inner_getIndex("keyType");
        sprintf(tmpbuf, "%s[%d]=%s;\n", "keyType", wlan_idx, inner_req_buff);
        strcat(inner_buf, tmpbuf);

        inner_getIndex("wapiAuth");
        sprintf(tmpbuf, "%s[%d]=%s;\n", "defWapiAuth", wlan_idx, inner_req_buff);
        strcat(inner_buf, tmpbuf);

        inner_getIndex("wapiPskFormat");
        sprintf(tmpbuf, "%s[%d]=%s;\n", "defWapiPskFormat", wlan_idx, inner_req_buff);
        strcat(inner_buf, tmpbuf);

        inner_getInfo("wapiPskValue");
        sprintf(tmpbuf, "%s[%d]=%s;\n", "defWapiPskValue", wlan_idx, inner_req_buff);
        strcat(inner_buf, tmpbuf);

        inner_getInfo("wapiASIp");
        sprintf(tmpbuf, "%s[%d]=%s;\n", "defWapiASIP", wlan_idx, inner_req_buff);
        strcat(inner_buf, tmpbuf);

        inner_getInfo("wapiCertSel");
        sprintf(tmpbuf, "%s[%d]=%s;\n", "defWapiCertSel", wlan_idx, inner_req_buff);
        strcat(inner_buf, tmpbuf);

        inner_getIndex("ChannelBonding");
        sprintf(tmpbuf, "%s[%d]=%s;\n", "init_bound", wlan_idx, inner_req_buff);
        strcat(inner_buf, tmpbuf);

        inner_getIndex("ControlSideBand");
        sprintf(tmpbuf, "%s[%d]=%s;\n", "init_sideband", wlan_idx, inner_req_buff);
        strcat(inner_buf, tmpbuf);

        inner_getIndex("Band2G5GSupport");
        sprintf(tmpbuf, "%s[%d]=%s;\n", "wlanBand2G5G", wlan_idx, inner_req_buff);
        strcat(inner_buf, tmpbuf);
    }

    wlan_idx  = wlan_idx_ori;
    vwlan_idx = vwlan_idx_ori;
    strcpy(WLAN_IF, WLAN_IF_ori);

    req_format_write(wp, inner_buf);

    return 0;
}


static int pvar_getindex_vlan_val_init(request *wp, int argc, char **argv, struct aspvar *v)
{
    int val = 0;
    int i=0, j=0, ret_i=0, ret_j=0, wlan_idx_ori, vwlan_idx_ori;

    char buffer[50];
	char WLAN_IF_ori[40], inner_buf[2048];

    memset(WLAN_IF_ori, '\0', sizeof(WLAN_IF_ori));
    memset(inner_buf, '\0', sizeof(inner_buf));

    wlan_idx_ori = wlan_idx;
    vwlan_idx_ori = vwlan_idx;
    strcpy(WLAN_IF_ori, WLAN_IF);

    for (i=0; i <wlan_num; i++)
    {
        sprintf(WLAN_IF, "wlan%d", i);
        SetWlan_idx(WLAN_IF);
        if ( !apmib_get( MIB_WLAN_MODE, (void *)&val) ) {
            ret_i = -1;
            break;
        }
        sprintf(buffer, "wlanMode[%d]=%d;\n", wlan_idx, val);
        strcat(inner_buf, buffer);

        if ( !apmib_get( MIB_WLAN_WLAN_DISABLED, (void *)&val) ) {
            ret_i = -1;
            break;
        }
        sprintf(buffer, "wlanDisabled[%d]=%d;\n", wlan_idx, val);
        strcat(inner_buf, buffer);

        for (j=0; j<DEF_MSSID_NUM; j++)
        {
            sprintf(WLAN_IF, "wlan%d-va%d", wlan_idx, vwlan_idx);
            SetWlan_idx(WLAN_IF);
            if ( !apmib_get( MIB_WLAN_WLAN_DISABLED, (void *)&val) ) {
                ret_j = -1;
                break;
            }
            sprintf(buffer, "mssid_disable[%d][%d]=%d;\n", wlan_idx, vwlan_idx-1, val);
            strcat(inner_buf, buffer);
        }

        if (ret_j !=0) {
            ret_i = -1;
            break;
        }
    }

    wlan_idx  = wlan_idx_ori;
    vwlan_idx = vwlan_idx_ori;
    strcpy(WLAN_IF, WLAN_IF_ori);

    if (ret_i == 0)
        req_format_write(wp, inner_buf);

    return ret_i;
}


static int pvar_getindex_set_wlanindex(request *wp, int argc, char **argv, struct aspvar *v)
{
    if(argc > 1) {
        wlan_idx=atoi(argv[argc-1]);
        req_format_write(wp, "");
        return 0;
    } else
        return -1;
}


static int pvar_getindex_getssid(request *wp, int argc, char **argv, struct aspvar *v)
{
    if(!strcmp(argv[0], "2G_ssid"))
    {
        char ssid[MAX_SSID_LEN];
        int ori_wlan_idx = wlan_idx;
        short wlanif;
        unsigned char wlanIfStr[10];

        memset(ssid,0x00,sizeof(ssid));

        wlanif = whichWlanIfIs(PHYBAND_2G);

        if(wlanif >= 0)
        {
            memset(wlanIfStr,0x00,sizeof(wlanIfStr));
            sprintf((char *)wlanIfStr, "wlan%d",wlanif);

            if(SetWlan_idx((char *)wlanIfStr))
            {
                apmib_get(MIB_WLAN_SSID, (void *)ssid);
            }
            wlan_idx = ori_wlan_idx;
        }
        else
        {
            ;//ssid is empty
        }
#ifdef CONFIG_RTL_8812_SUPPORT
        apmib_get(MIB_WLAN_SSID, (void *)ssid);
#endif
        translate_control_code(ssid);
        //		req_format_write(wp, ssid);
        //		return 0;
        return req_format_write(wp, "%s", ssid);
    }
    else if(!strcmp(argv[0], "5G_ssid"))
    {
        char ssid[MAX_SSID_LEN];
        int ori_wlan_idx = wlan_idx;
        short wlanif;
        unsigned char wlanIfStr[10];

        memset(ssid,0x00,sizeof(ssid));

        wlanif = whichWlanIfIs(PHYBAND_5G);

        if(wlanif >= 0)
        {
            memset(wlanIfStr,0x00,sizeof(wlanIfStr));
            sprintf((char *)wlanIfStr, "wlan%d",wlanif);

            if(SetWlan_idx((char *)wlanIfStr))
            {
                apmib_get(MIB_WLAN_SSID, (void *)ssid);
            }
            wlan_idx = ori_wlan_idx;
        }
        else
        {
            ;//ssid is empty
        }
#ifdef CONFIG_RTL_8812_SUPPORT
        apmib_get(MIB_WLAN_SSID, (void *)ssid);
#endif
        translate_control_code(ssid);
        //		req_format_write(wp, ssid);
        //		return 0;
        return req_format_write(wp, "%s", ssid);
    }

    return 0;
}

static int pvar_getindex_phyband(request *wp, int argc, char **argv, struct aspvar *v)
{
    const char *name = v->name;
    char buffer[16] = "";
    int val = 0;

    if ( !strcmp(name, "wlan1_phyband"))
    {
#if defined(CONFIG_RTL_92D_SUPPORT) || defined(CONFIG_RTL_8812_SUPPORT)
        int wlanBand2G5GSelect;
        apmib_get(MIB_WLAN_BAND2G5G_SELECT, (void *)&wlanBand2G5GSelect);
        memset(buffer, 0x00, sizeof(buffer));
        if(SetWlan_idx("wlan0"))
        {
            apmib_get(MIB_WLAN_PHY_BAND_SELECT, (void *)&val);
            if(val == PHYBAND_5G && (wlanBand2G5GSelect==BANDMODE5G || wlanBand2G5GSelect==BANDMODEBOTH || wlanBand2G5GSelect==BANDMODESINGLE))
                sprintf(buffer, "%s", "5GHz") ;
            else if(val == PHYBAND_2G && (wlanBand2G5GSelect==BANDMODE2G || wlanBand2G5GSelect==BANDMODEBOTH || wlanBand2G5GSelect==BANDMODESINGLE))
                sprintf(buffer, "%s", "2.4GHz") ;
            else
                sprintf(buffer, "%s", "") ;
        }
#else
        sprintf(buffer, "%s", "") ;
#endif
        req_format_write(wp, buffer);
        return 0;
    }
    else if ( !strcmp(name, "wlan2_phyband"))
    {
#if defined(CONFIG_RTL_92D_SUPPORT)
        int wlanBand2G5GSelect;
        apmib_get(MIB_WLAN_BAND2G5G_SELECT, (void *)&wlanBand2G5GSelect);
        memset(buffer, 0x00, sizeof(buffer));
        if(SetWlan_idx("wlan1"))
        {
            apmib_get(MIB_WLAN_PHY_BAND_SELECT, (void *)&val);
            if(val == PHYBAND_5G && (wlanBand2G5GSelect==BANDMODE5G || wlanBand2G5GSelect==BANDMODEBOTH))
                sprintf(buffer, "%s", "5GHz") ;
            else if(val == PHYBAND_2G && (wlanBand2G5GSelect==BANDMODE2G || wlanBand2G5GSelect==BANDMODEBOTH))
                sprintf(buffer, "%s", "2.4GHz") ;
            else
                sprintf(buffer, "%s", "") ;
        }
#else
        sprintf(buffer, "%s", "") ;
#endif
        req_format_write(wp, buffer);
        return 0;
    }

    return 0;
}


static int pvar_getindex_wlan_mode_2x2(request *wp, int argc, char **argv, struct aspvar *v)
{
    char buffer[4] = "";
    int val = 0;
    int isWlanMode2x2=0;
#if defined(CONFIG_RTL_92D_SUPPORT)//support 92d
#if defined(CONFIG_RTL_DUAL_PCIESLOT_BIWLAN_D)//support 92C+92D
    apmib_get(MIB_WLAN_PHY_BAND_SELECT, (void *)&val);
    if((int)val == 2)//5G 92D
        isWlanMode2x2=1;

#else//only support 92D
    isWlanMode2x2=1;
#endif
#endif
#if defined(CONFIG_RTL8192E) || defined(CONFIG_RTL_8812_SUPPORT)
    isWlanMode2x2=1;
#endif
    sprintf(buffer, "%d", isWlanMode2x2) ;
    req_format_write(wp, buffer);
    return 0;
}


#ifdef CONFIG_RTL_WAPI_SUPPORT
static int pvar_getindex_ReKeyType(request *wp, int argc, char **argv, struct aspvar *v)
{
    if ( !strcmp(name, "wapiUcastReKeyType"))
        if ( !apmib_get(MIB_WLAN_WAPI_UCASTREKEY, (void *)&val) )
            return -1;

    else if ( !strcmp(name, "wapiMcastReKeyType"))
        if ( !apmib_get(MIB_WLAN_WAPI_MCASTREKEY, (void *)&val) )
            return -1;


    if(0 == val)
    {
        /*default should be off*/
        val = 1;
    }
    sprintf(buffer, "%d", (int)val) ;
    req_format_write(wp, buffer);
    return 0;
}
#endif

static int pvar_getindex_rf_used(request *wp, int argc, char **argv, struct aspvar *v)
{
    char buffer[8] = "";
    struct _misc_data_ misc_data;

    if (getMiscData(WLAN_IF, &misc_data) < 0)
    {
        sprintf(buffer, "%d", 0);
    }
    else
    {
        sprintf(buffer, "%d", misc_data.mimo_tr_used);
    }

    req_format_write(wp, buffer);
    return 0;
}


#ifdef UNIVERSAL_REPEATER
static int pvar_getindex_about_repeater(request *wp, int argc, char **argv, struct aspvar *v)
{
    const char *name = v->name;
    char buffer[50] = "";
	int val = 0;
	int id;

    if ( !strcmp(name, "repeaterEnabled")) {
		if (wlan_idx == 0)
			id = MIB_REPEATER_ENABLED1;
		else
			id = MIB_REPEATER_ENABLED2;
		if ( !apmib_get( id, (void *)&val) )
				return -1;
		sprintf(buffer, "%d", val);
		req_format_write(wp, buffer);
		return 0;
	}
	else if ( !strcmp(name, "isRepeaterEnabled")) {
		int intVal, intVal2;
		if (wlan_idx == 0)
			apmib_get(MIB_REPEATER_ENABLED1, (void *)&intVal);
		else
			apmib_get(MIB_REPEATER_ENABLED2, (void *)&intVal);

		apmib_get(MIB_WLAN_NETWORK_TYPE, (void *)&intVal2);
		apmib_get(MIB_WLAN_MODE, (void *)&val);

		if (intVal != 0 && val != WDS_MODE && !(val==CLIENT_MODE && intVal2==ADHOC))
		{
			val = 1;
		}
		else
		{
			val = 0;
		}

		sprintf(buffer, "%d", val);
		req_format_write(wp, buffer);
		return 0;
	}
	else if ( !strcmp(name, "repeaterMode")) {
		if ( !apmib_get( MIB_WLAN_MODE, (void *)&val) )
			return -1;
		if (val == AP_MODE || val == AP_WDS_MODE || val == AP_MESH_MODE || val == MESH_MODE)
			val = CLIENT_MODE;
		else
			val = AP_MODE;
		sprintf(buffer, "%d", val);
		req_format_write(wp, buffer);
		return 0;
	}

    return 0;
}
#endif


#ifdef CONFIG_RTK_MESH
static int pvar_getindex_meshPskValue(request *wp, int argc, char **argv, struct aspvar *v)
{
    int i;
    char buffer[50] = "";

    buffer[0]='\0';
    if ( !apmib_get(MIB_WLAN_MESH_WPA_PSK,  (void *)buffer) )
        return -1;
    for (i=0; i<strlen(buffer); i++)
        buffer[i]='*';
    buffer[i]='\0';

    return req_format_write(wp, buffer);
}
#endif

static int pvar_getindex_ulinker_opMode(request *wp, int argc, char **argv, struct aspvar *v)
{
    char buffer[4] = "";

    sprintf(buffer, "%d", 2) ;
#if defined(CONFIG_RTL_ULINKER)
    int opMode, wlanMode, rpt_enabled;
    apmib_get( MIB_OP_MODE, (void *)&opMode);
    apmib_get( MIB_WLAN_MODE, (void *)&wlanMode);
    if(wlan_idx == 0)
        apmib_get( MIB_REPEATER_ENABLED1, (void *)&rpt_enabled);
    else
        apmib_get( MIB_REPEATER_ENABLED2, (void *)&rpt_enabled);

    //0:AP; 1:Client; 2:Router; 3:RPT; 4:WISP-RPT
    if(opMode == GATEWAY_MODE)
    {
        sprintf(buffer, "%d", 2) ;
    }
    else if(opMode == WISP_MODE)
    {
        sprintf(buffer, "%d", 4) ;
    }
    else
    {
        if(wlanMode == AP_MODE)
        {
            if(rpt_enabled == 1)
                sprintf(buffer, "%d", 3);
            else
                sprintf(buffer, "%d", 0);
        }
        else
            sprintf(buffer, "%d", 1);

    }

#endif
    req_format_write(wp, buffer);
    return 0;
}


#ifdef HOME_GATEWAY
static int pvar_getindex_wanDhcp_current(request *wp, int argc, char **argv, struct aspvar *v)
{
    char buffer[50] = "";
	DHCP_T dhcp;
	OPMODE_T opmode=-1;
	char *iface=NULL;

#if defined(CONFIG_RTL_8198_AP_ROOT) || defined(CONFIG_RTL_8197D_AP)
    memset(buffer,0x00,sizeof(buffer));
    apmib_get( MIB_WAN_DHCP, (void *)&dhcp);
    sprintf(buffer, "%d", dhcp);
#else
    int wispWanId=0;
    if ( !apmib_get( MIB_WAN_DHCP, (void *)&dhcp) )
        return -1;
    if ( !apmib_get( MIB_OP_MODE, (void *)&opmode) )
        return -1;
    if( !apmib_get(MIB_WISP_WAN_ID, (void *)&wispWanId))
        return -1;
    if(opmode == WISP_MODE) {
        if(0 == wispWanId)
            iface = "wlan0";
        else if(1 == wispWanId)
            iface = "wlan1";
    }
    else
        iface = WAN_IF;
    if ( dhcp == DHCP_CLIENT && !isDhcpClientExist(iface))
        dhcp = DHCP_DISABLED;
    sprintf(buffer, "%d", (int)dhcp);
#endif
    req_format_write(wp, buffer);
    return 0;
}
#endif

static int pvar_getindex_show_wlan_num(request *wp, int argc, char **argv, struct aspvar *v)
{
    char buffer[50] = "";
	int val;

#if defined(CONFIG_RTL_92D_DMDP)||defined(CONFIG_RTL_DUAL_PCIESLOT_BIWLAN_D)
    apmib_get(MIB_WLAN_BAND2G5G_SELECT, (void *)&val);

    if(BANDMODEBOTH == val)
    {
        sprintf(buffer, "%d", wlan_num);
    }
    else
    {
        sprintf(buffer, "%d", wlan_num);
        //sprintf(buffer, "%d", wlan_num-1);
    }
#else
    sprintf(buffer, "%d", wlan_num);
#endif
    req_format_write(wp, buffer);
    return 0;
}


#ifdef HOME_GATEWAY
static int pvar_getindex_passthrough(request *wp, int argc, char **argv, struct aspvar *v)
{
    char buffer[50] = "";
	int val;

    if ( !strcmp(argv[0], "ppoepassthrouh")) {
        if ( !apmib_get( MIB_CUSTOM_PASSTHRU_ENABLED, (void *)&val) )
            return -1;
        sprintf(buffer, "%d", ((int)val& 0x2)?1:0) ;
        req_format_write(wp, buffer);
        return 0;
    }
    else if ( !strcmp(argv[0], "ipv6passthrouh")) {
        if ( !apmib_get( MIB_CUSTOM_PASSTHRU_ENABLED, (void *)&val) )
            return -1;
        sprintf(buffer, "%d", ((int)val& 0x1)?1:0) ;
        req_format_write(wp, buffer);
        return 0;
    }

    return 0;
}
#endif


#ifdef WLAN_EASY_CONFIG
static int pvar_getindex_autoCfgDigestInstall(request *wp, int argc, char **argv, struct aspvar *v)
{
    char buffer[50] = "";
	int val;
    char tmpbuf[100];
    int is_adhoc;

    if ( !apmib_get( MIB_WLAN_MODE, (void *)&val) )
        return -1;

    if (val == CLIENT_MODE) {
        apmib_get( MIB_WLAN_NETWORK_TYPE, (void *)&is_adhoc );
        if (is_adhoc) {
            apmib_get( MIB_WLAN_EASYCFG_MODE, (void *)&val);
            if (!(val & MODE_QUESTION))
                val = 2;
            else {
                apmib_get( MIB_WLAN_EASYCFG_DIGEST, (void *)&tmpbuf);
                if (strlen(tmpbuf))
                    val = 1;
                else
                    val = 0;
            }
        }
        else
            val = 2;
    }
    else {
        if ( !apmib_get( MIB_WLAN_EASYCFG_MODE, (void *)&val) )
            return -1;
        if (!(val & MODE_QUESTION))
            val = 2;
        else {
            if ( !apmib_get( MIB_WLAN_EASYCFG_DIGEST, (void *)&tmpbuf) )
                return -1;
            if (strlen(tmpbuf))
                val = 1;
            else
                val = 0;
        }
    }

    sprintf(buffer, "%d", val);
    req_format_write(wp, buffer);
    return 0;
}


static int pvar_getindex_autoCfgKeyInstall(request *wp, int argc, char **argv, struct aspvar *v)
{
    int val = 0;
    char tmpbuf[100] = "";
    char buffer[100] = "";

    if ( !apmib_get( MIB_WLAN_EASYCFG_KEY, (void *)&tmpbuf) )
        return -1;

    if (strlen(tmpbuf))
        val = 1;
    else
        val = 0;

    sprintf(buffer, "%d", val);
    req_format_write(wp, buffer);
    return 0;
}
#endif


static int pvar_getindex_lockdown_stat(request *wp, int argc, char **argv, struct aspvar *v)
{
    int val = 0;
    char buffer[50] = "";

#define WSCD_LOCK_STAT		("/tmp/wscd_lock_stat")

    struct stat lockdown_status;
    if (stat(WSCD_LOCK_STAT, &lockdown_status) == 0) {
        //printf("[%s %d] %s exist\n",__FUNCTION__,__LINE__,WSCD_LOCK_STAT);
        val=1;
    }else{
        val=0;
    }

    sprintf(buffer, "%d", val);
    req_format_write(wp, buffer);
    return 0;
}

static int pvar_getindex_rpt_type(request *wp, int argc, char **argv, struct aspvar *v)
{
    char buffer[50] = "";

#if defined(UNIVERSAL_REPEATER) && defined(CONFIG_REPEATER_WPS_SUPPORT)
    int val;
	char tmpStr[20];
  	int wlan_idx_keep = wlan_idx;
    const char *name = v->name;

    if ( !strcmp(name, "wscRptConfig") || !strcmp(name, "wpsRpt_auth") ||
            !strcmp(name, "wpsRpt_enc"))
        SetWlan_idx("wlan0-vxd");
    else {
        sprintf(tmpStr,"wlan%d-vxd",wlan_idx);
        SetWlan_idx(tmpStr);
    }

    if (!strcmp(name, "wlanMode_rpt"))
        apmib_get( MIB_WLAN_MODE, (void *)&val);
    else if (!strcmp(name, "networkType_rpt"))
        apmib_get( MIB_WLAN_NETWORK_TYPE, (void *)&val);
    else if (!strcmp(name, "wpa_auth_rpt"))
        apmib_get( MIB_WLAN_NETWORK_TYPE, (void *)&val);
    else if ( !strcmp(name, "encrypt_rpt"))
		apmib_get( MIB_WLAN_ENCRYPT, (void *)&val);
    else if ( !strcmp(name,"enable1x_rpt"))
		apmib_get( MIB_WLAN_ENABLE_1X, (void *)&val);
    else if ( !strcmp(name, "wscRptConfig"))
		apmib_get(MIB_WLAN_WSC_CONFIGURED, (void *)&val);
    else if ( !strcmp(name, "wpsRpt_auth"))
		apmib_get(MIB_WLAN_WSC_AUTH, (void *)&val);
    else if ( !strcmp(name, "wpsRpt_enc"))
		apmib_get(MIB_WLAN_WSC_ENC, (void *)&val);
    else
        return 0;

    sprintf(buffer, "%d", val);
    req_format_write(wp, buffer);
    wlan_idx = wlan_idx_keep;
    sprintf(tmpStr,"wlan%d",wlan_idx);
    SetWlan_idx(tmpStr);
#else
    sprintf(buffer, "%d", 0);
    req_format_write(wp, buffer);
#endif
    return 0;
}

#ifdef HOME_GATEWAY
#ifdef VPN_SUPPORT
static int pvar_getindex_Ipsec(request *wp, int argc, char **argv, struct aspvar *v)
{
    const char *name = v->name;
    char buffer[50] = "";
	IPSECTUNNEL_T entry;

	if ( !strcmp(name, "tunnelEnabled")) {
                if ( getIpsecInfo(&entry) < 0)
			sprintf(buffer, "%d", 1); // default
		else
	        	sprintf(buffer, "%d", entry.enable );
		req_format_write(wp, buffer);
		return 0;
	}
	else if ( !strcmp(name, "ipsecLocalType")) {
                if ( getIpsecInfo(&entry) < 0)
			sprintf(buffer, "%d", SUBNET_ADDR); // subnet Address default
		else
	        	sprintf(buffer, "%d", entry.lcType);
		req_format_write(wp, buffer);
		return 0;
	}
	else if ( !strcmp(name, "ipsecRemoteType")) {
                if ( getIpsecInfo(&entry) < 0)
			sprintf(buffer, "%d", SUBNET_ADDR); // subnet Address default
		else
	        	sprintf(buffer, "%d", entry.rtType);
		req_format_write(wp, buffer);
		return 0;
	}
	else if ( !strcmp(name, "ipsecKeyMode")) {
		if ( getIpsecInfo(&entry) < 0)
			sprintf(buffer, "%d", IKE_MODE); // IKE mode
		else
			sprintf(buffer, "%d", entry.keyMode);

		req_format_write(wp, buffer);
		return 0;
	}
	else if ( !strcmp(name, "ipsecEspEncr")) {
                if ( getIpsecInfo(&entry) < 0)
			sprintf(buffer, "%d", TRI_DES_ALGO); // 3DES
		else
	        	sprintf(buffer, "%d", entry.espEncr);
		req_format_write(wp, buffer);
		return 0;
	}
	else if ( !strcmp(name, "ipsecEspAuth")) {
                if ( getIpsecInfo(&entry) < 0)
			sprintf(buffer, "%d", MD5_ALGO); // MD5
		else
	        	sprintf(buffer, "%d", entry.espAuth);
		req_format_write(wp, buffer);
		return 0;
	}
	else if ( !strcmp(name, "vpnConnectionType")) {
                if ( getIpsecInfo(&entry) < 0)
			sprintf(buffer, "%d", RESPONDER); // responder
		else
	        	sprintf(buffer, "%d", entry.conType);
		req_format_write(wp, buffer);
		return 0;
	}
	else if( !strcmp(name, "ikeConnectStatus")){
                if ( getIpsecInfo(&entry) < 0){
			sprintf(buffer, "%d", 0);
		}
		else{
			if ( getConnStat(entry.connName) < 0)
				sprintf(buffer, "%d", 0);
			else
				sprintf(buffer, "%d",1);
		}
		req_format_write(wp, buffer);
		return 0;
	}
	else if( !strcmp(name, "ipsecLocalIdType")){
                if ( getIpsecInfo(&entry) < 0)
			sprintf(buffer, "%d", 0);
		else
			sprintf(buffer, "%d",entry.lcIdType);
		req_format_write(wp, buffer);
		return 0;
	}
	else if( !strcmp(name, "ipsecRemoteIdType")){
                if ( getIpsecInfo(&entry) < 0)
			sprintf(buffer, "%d", 0);
		else
			sprintf(buffer, "%d",entry.rtIdType);

		req_format_write(wp, buffer);
		return 0;
	}
	else if( !strcmp(name, "ipsecAuthType")) {
                if ( getIpsecInfo(&entry) < 0)
			sprintf(buffer, "%d", 0);
		else
			sprintf(buffer, "%d", entry.authType);

		req_format_write(wp, buffer);
		return 0;
	}

    return 0;
}
#endif
#endif


static int pvar_getindex_defaultKeyId(request *wp, int argc, char **argv, struct aspvar *v)
{
	int val = 0;
    char buffer[16] = "";

    if ( !apmib_get( MIB_WLAN_WEP_DEFAULT_KEY, (void *)&val) )
        return -1;

    val++;

    sprintf(buffer, "%d", (int)val) ;
    req_format_write(wp, buffer);
    return 0;
}

static int pvar_getindex_pppConnectStatus(request *wp, int argc, char **argv, struct aspvar *v)
{
#ifdef HOME_GATEWAY
    const char *name = v->name;
    char buffer[16] = "";

    if ( !strcmp(name, "pppConnectStatus")) {
#ifdef MULTI_PPPOE
		PPPoE_Number = 1;
#endif
		sprintf(buffer, "%d", isConnectPPP());
		req_format_write(wp, buffer);
		return 0;
	}
    else if ( !strcmp(name, "pppConnectStatus2")){
#ifdef MULTI_PPPOE
		PPPoE_Number = 2;
#endif
		sprintf(buffer, "%d", isConnectPPP());
		req_format_write(wp, buffer);
		return 0;
	}
	else if ( !strcmp(name, "pppConnectStatus3")) {
#ifdef MULTI_PPPOE
		PPPoE_Number = 3;
#endif
		sprintf(buffer, "%d", isConnectPPP());
		req_format_write(wp, buffer);
		return 0;
	}
	else if ( !strcmp(name, "pppConnectStatus4")) {
#ifdef MULTI_PPPOE
		PPPoE_Number = 4;
#endif
		sprintf(buffer, "%d", isConnectPPP());
		req_format_write(wp, buffer);
		return 0;
	}
#endif
    return 0;
}

static int pvar_getindex_dhcp_current(request *wp, int argc, char **argv, struct aspvar *v)
{
    DHCP_T dhcp;
    char buffer[4] = "";

    if ( !apmib_get( MIB_DHCP, (void *)&dhcp) )
        return -1;
    if ( dhcp == DHCP_CLIENT && !isDhcpClientExist(BRIDGE_IF))
        dhcp = DHCP_DISABLED;
    sprintf(buffer, "%d", (int)dhcp);
    req_format_write(wp, buffer);
    return 0;
}


static int pvar_getindex_print_nocache(request *wp, int argc, char **argv, struct aspvar *v)
{
    char inner_buf[2048] = "";
    memset(inner_buf, '\0', sizeof(inner_buf));
    sprintf(inner_buf, "%s\n%s\n%s\n",
            "<meta http-equiv=\"Pragma\" content=\"no-cache\">",
            "<meta HTTP-equiv=\"Cache-Control\" content=\"no-cache\">",
            "<meta HTTP-EQUIV=\"Expires\" CONTENT=\"Mon, 01 Jan 1990 00:00:01 GMT\">");
    req_format_write(wp, inner_buf);
    return 0;
}

static struct aspvar pgetindex_vars[] = {
    //
    //define(except DAVO)
    //
#ifdef CONFIG_IPV6
    {"ipv6", pvar_printarg, (long)(void *)"1", NULL },
#else
    {"ipv6", pvar_printarg, (long)(void *)"0", NULL },
#endif


#ifdef ROUTE_SUPPORT
    {"route_setup_onoff", pvar_printarg, (long)(void *)"1", NULL },
#else
    {"route_setup_onoff", pvar_printarg, (long)(void *)"0", NULL },
#endif


#ifdef RTK_USB3G
    {"usb3g", pvar_printarg, (long)(void *)"1", NULL },
#else
    {"usb3g", pvar_printarg, (long)(void *)"0", NULL },
#endif


#ifdef CONFIG_4G_LTE_SUPPORT
    {"lte4g_build", pvar_printarg, (long)(void *)"1", NULL },
#else
    {"lte4g_build", pvar_printarg, (long)(void *)"0", NULL },
#endif

    {"lte4g_enable", pvar_getmib, MIB_LTE4G, (void *)pwrite_itoa },
    {"dhcp", pvar_getmib, MIB_DHCP, (void *)pwrite_itoa },

    {"no-cache", pvar_getindex_print_nocache, 0, NULL },

#if defined(CONFIG_USBDISK_UPDATE_IMAGE)
    {"usb_update_img_enabled", pvar_printarg, (long)(void *)"1", NULL },
#else
    {"usb_update_img_enabled", pvar_printarg, (long)(void *)"0", NULL },
#endif


#ifdef CONFIG_APP_TR069
    {"isDisplayTR069", pvar_printarg, (long)(void *)"1", NULL },
#else
    {"isDisplayTR069", pvar_printarg, (long)(void *)"0", NULL },
#endif


#ifdef DOT11K
    {"is_80211k_support", pvar_printarg, (long)(void *)"1", NULL },
#else
    {"is_80211k_support", pvar_printarg, (long)(void *)"0", NULL },
#endif


#if defined(FAST_BSS_TRANSITION)
    {"is_80211r_support", pvar_printarg, (long)(void *)"1", NULL },
#else
    {"is_80211r_support", pvar_printarg, (long)(void *)"0", NULL },
#endif


#ifdef FAST_BSS_TRANSITION
    {"11r_ftkh_num", pvar_printarg, MAX_VWLAN_FTKH_NUM, (void *)pwrite_itoa },
    {"ft_enable", pvar_getmib, MIB_WLAN_FT_ENABLE, (void *)pwrite_itoa },
    {"_ft_mdid", pvar_getmib, MIB_WLAN_FT_MDID, (void *)pwrite_itoa, (void *)"0"},
    {"_ft_over_ds", pvar_getmib, MIB_WLAN_FT_OVER_DS, (void *)pwrite_itoa },
    {"_ft_res_request", pvar_getmib, MIB_WLAN_FT_RES_REQUEST, (void *)pwrite_itoa },
    {"_ft_r0key_timeout", pvar_getmib, MIB_WLAN_FT_R0KEY_TO, (void *)pwrite_itoa },
    {"_ft_reasoc_timeout", pvar_getmib, MIB_WLAN_FT_REASOC_TO, (void *)pwrite_itoa },
    {"_ft_r0kh_id", pvar_getmib, MIB_WLAN_FT_R0KH_ID, (void *)pwrite_puts, (void *)"0"},
    {"_ft_push", pvar_getmib, MIB_WLAN_FT_PUSH, (void *)pwrite_itoa },
    {"_ft_kh_num", pvar_getmib, MIB_WLAN_FTKH_NUM, (void *)pwrite_itoa },
    {"selectedId", pvar_printarg, vwlan_idx, (void *)pwrite_itoa },
#endif

    {"dhcp-current", pvar_getindex_dhcp_current, 0, NULL },

    {"stp", pvar_getmib, MIB_STP_ENABLED, (void *)pwrite_itoa },
    {"sch_enabled", pvar_getmib, MIB_WLAN_SCHEDULE_ENABLED, (void *)pwrite_itoa },


#if defined(CONFIG_RTL_AP_PACKAGE)
    {"isPureAP", pvar_printarg, (long)(void *)"1", NULL },
#else
    {"isPureAP", pvar_printarg, (long)(void *)"0", NULL },
#endif


#if defined(CONFIG_RTL_8198_AP_ROOT) || defined(HOME_GATEWAY) || defined(CONFIG_RTL_8197D_AP)
    {"wanDNS", pvar_getmib, MIB_DNS_MODE, (void *)pwrite_itoa },
    {"ntpEnabled", pvar_getmib, MIB_NTP_ENABLED, (void *)pwrite_itoa },
    {"DaylightSave", pvar_getmib, MIB_DAYLIGHT_SAVE, (void *)pwrite_itoa },
    {"ntpServerId", pvar_getmib, MIB_NTP_SERVER_ID, (void *)pwrite_itoa },
#if defined(CONFIG_RTL_8198_AP_ROOT) || defined(CONFIG_RTL_8197D_AP)
    {"wanDhcp", pvar_printarg, (long)(void *)"1", NULL },
#else
    {"wanDhcp", pvar_getmib, MIB_WAN_DHCP, (void *)pwrite_itoa },
#endif


#ifdef  MULTI_PPPOE
    {"multiPppoe", pvar_printarg, "1", NULL },
#else
    {"multiPppoe", pvar_printarg, (long)(void *)"0", NULL },
#endif


    {"pppoeNo", pvar_getmib, MIB_PPP_CONNECT_COUNT, (void *)pwrite_itoa, "0" },
    {"subnet1", pvar_getmib, MIB_SUBNET1_COUNT, (void *)pwrite_itoa },
    {"subnet2", pvar_getmib, MIB_SUBNET2_COUNT, (void *)pwrite_itoa },
    {"subnet3", pvar_getmib, MIB_SUBNET3_COUNT, (void *)pwrite_itoa },
    {"subnet4", pvar_getmib, MIB_SUBNET4_COUNT, (void *)pwrite_itoa },

    {"pppConnectType2", pvar_getmib, MIB_PPP_CONNECT_TYPE2, (void *)pwrite_itoa },
    {"pppConnectType3", pvar_getmib, MIB_PPP_CONNECT_TYPE3, (void *)pwrite_itoa },
    {"pppConnectType4", pvar_getmib, MIB_PPP_CONNECT_TYPE4, (void *)pwrite_itoa },

    {"pppConnectStatus2", pvar_getindex_pppConnectStatus, 0, NULL },
    {"pppConnectStatus3", pvar_getindex_pppConnectStatus, 0, NULL },
    {"pppConnectStatus4", pvar_getindex_pppConnectStatus, 0, NULL },


#ifdef CONFIG_GET_SERVER_IP_BY_DOMAIN
    {"enableGetServIpByDomainName", pvar_printarg, (long)(void *)"1", NULL },
#else
    {"enableGetServIpByDomainName", pvar_printarg, (long)(void *)"0", NULL },
#endif


#ifdef CONFIG_GET_SERVER_IP_BY_DOMAIN
    {"pptpGetServIpByDomainName", pvar_getmib, MIB_PPTP_GET_SERV_BY_DOMAIN, (void *)pwrite_itoa },
#else
    {"pptpGetServIpByDomainName", pvar_printarg, (long)(void *)"0", NULL },
#endif


#ifdef CONFIG_GET_SERVER_IP_BY_DOMAIN
    {"l2tpGetServIpByDomainName", pvar_getmib, MIB_L2TP_GET_SERV_BY_DOMAIN, (void *)pwrite_itoa },
#else
    {"l2tpGetServIpByDomainName", pvar_printarg, (long)(void *)"0", NULL },
#endif


    {"wanDhcp-current", pvar_getindex_wanDhcp_current, 0, NULL },


#if defined(HOME_GATEWAY)
#ifdef ROUTE_SUPPORT
    {"nat_enabled", pvar_getmib, MIB_NAT_ENABLED, (void *)pwrite_itoa },
#endif
    {"pppConnectType", pvar_getmib, MIB_PPP_CONNECT_TYPE, (void *)pwrite_itoa },

#if defined(CONFIG_DYNAMIC_WAN_IP)
    {"pptp_wan_ip_mode", pvar_getmib, MIB_PPTP_WAN_IP_DYNAMIC, (void *)pwrite_itoa },
#endif
    {"pptpConnectType", pvar_getmib, MIB_PPTP_CONNECTION_TYPE, (void *)pwrite_itoa },

#if defined(CONFIG_DYNAMIC_WAN_IP)
    {"l2tp_wan_ip_mode", pvar_getmib, MIB_L2TP_WAN_IP_DYNAMIC, (void *)pwrite_itoa },
#endif
    {"l2tpConnectType", pvar_getmib, MIB_L2TP_CONNECTION_TYPE, (void *)pwrite_itoa },


#ifdef RTK_USB3G
    {"USB3GConnectType", pvar_getmib, MIB_USB3G_CONN_TYPE, (void *)pwrite_puts },
#else
    {"USB3GConnectType", pvar_printarg, (long)(void *)"", NULL },
#endif /* #ifdef RTK_USB3G */


    {"pppConnectStatus", pvar_getindex_pppConnectStatus, 0, NULL },

    {"portFwNum", pvar_getmib, MIB_PORTFW_TBL_NUM, (void *)pwrite_itoa },
    {"ipFilterNum", pvar_getmib, MIB_IPFILTER_TBL_NUM, (void *)pwrite_itoa },
    {"portFilterNum", pvar_getmib, MIB_PORTFILTER_TBL_NUM, (void *)pwrite_itoa },
    {"macFilterNum", pvar_getmib, MIB_MACFILTER_TBL_NUM, (void *)pwrite_itoa },
    {"urlFilterNum", pvar_getmib, MIB_URLFILTER_TBL_NUM, (void *)pwrite_itoa },
    {"triggerPortNum", pvar_getmib, MIB_TRIGGERPORT_TBL_NUM, (void *)pwrite_itoa },

#if defined(GW_QOS_ENGINE) || defined(QOS_BY_BANDWIDTH)
    {"qosEnabled", pvar_getmib, MIB_QOS_ENABLED, (void *)pwrite_itoa },
    {"qosAutoUplinkSpeed", pvar_getmib, MIB_QOS_AUTO_UPLINK_SPEED, (void *)pwrite_itoa },
    {"qosRuleNum", pvar_getmib, MIB_QOS_RULE_TBL_NUM, (void *)pwrite_itoa },
    {"qosAutoDownlinkSpeed", pvar_getinfo_qos, 0, NULL },
#endif

#ifdef ROUTE_SUPPORT
    {"staticRouteNum", pvar_getmib, MIB_STATICROUTE_TBL_NUM, (void *)pwrite_itoa },
#endif

    {"portFwEnabled", pvar_getmib, MIB_PORTFW_ENABLED, (void *)pwrite_itoa },
    {"ipFilterEnabled", pvar_getmib, MIB_IPFILTER_ENABLED, (void *)pwrite_itoa },
    {"portFilterEnabled", pvar_getmib, MIB_PORTFILTER_ENABLED, (void *)pwrite_itoa },
    {"macFilterEnabled", pvar_getmib, MIB_MACFILTER_ENABLED, (void *)pwrite_itoa },
    {"triggerPortEnabled", pvar_getmib, MIB_TRIGGERPORT_ENABLED, (void *)pwrite_itoa },

#ifdef ROUTE_SUPPORT
    {"staticRouteEnabled", pvar_getmib, MIB_STATICROUTE_ENABLED, (void *)pwrite_itoa },
#endif

    {"dmzEnabled", pvar_getmib, MIB_DMZ_ENABLED, (void *)pwrite_itoa },

#ifdef _ALPHA_DUAL_WAN_SUPPORT_
    {"pppoeWithDhcpEnabled", pvar_getmib, MIB_PPPOE_DHCP_ENABLED, (void *)pwrite_itoa },
#endif

    {"upnpEnabled", pvar_getmib, MIB_UPNP_ENABLED, (void *)pwrite_itoa },
    {"igmpproxyDisabled", pvar_getmib, MIB_IGMP_PROXY_DISABLED, (void *)pwrite_itoa },

#ifdef ROUTE_SUPPORT
    {"ripEnabled", pvar_getmib, MIB_RIP_ENABLED, (void *)pwrite_itoa },
    {"ripLanTx", pvar_getmib, MIB_RIP_LAN_TX, (void *)pwrite_itoa },
    {"ripLanRx", pvar_getmib, MIB_RIP_LAN_RX, (void *)pwrite_itoa },
#ifdef RIP6_SUPPORT
    {"rip6Support", pvar_printarg, (long)(void *)"1", NULL },
#else
    {"rip6Support", pvar_printarg, (long)(void *)"0", NULL },
#endif

#ifdef RIP6_SUPPORT
    {"rip6Enabled", pvar_getmib, MIB_RIP6_ENABLED, (void *)pwrite_itoa },
#endif
#endif //ROUTE
#endif	//HOME_GATEWAY
#endif	//CONFIG_RTL_8198_AP_ROOT && VLAN_CONFIG_SUPPORT

#ifdef HOME_GATEWAY
#ifdef VPN_SUPPORT
    {"ipsecTunnelNum", pvar_getmib, MIB_IPSECTUNNEL_TBL_NUM, (void *)pwrite_itoa },
    {"ipsecVpnEnabled", pvar_getmib, MIB_IPSECTUNNEL_ENABLED, (void *)pwrite_itoa },
    {"ipsecNattEnabled", pvar_getmib, MIB_IPSEC_NATT_ENABLED, (void *)pwrite_itoa },
    {"tunnelEnabled", pvar_getindex_Ipsec, 0, NULL },
    {"ipsecLocalType", pvar_getindex_Ipsec, 0, NULL },
    {"ipsecRemoteType", pvar_getindex_Ipsec, 0, NULL },
    {"ipsecKeyMode", pvar_getindex_Ipsec, 0, NULL },
    {"ipsecEspEncr", pvar_getindex_Ipsec, 0, NULL },
    {"ipsecEspAuth", pvar_getindex_Ipsec, 0, NULL },
    {"vpnConnectionType", pvar_getindex_Ipsec, 0, NULL },
    {"ikeConnectStatus", pvar_getindex_Ipsec, 0, NULL },
    {"ipsecLocalIdType", pvar_getindex_Ipsec, 0, NULL },
    {"ipsecRemoteIdType", pvar_getindex_Ipsec, 0, NULL },
    {"ipsecRemoteIdType", pvar_getindex_Ipsec, 0, NULL },
    {"ipsecAuthType", pvar_getindex_Ipsec, 0, NULL },
#endif
#endif

    {"channel", pvar_getmib, MIB_WLAN_CHANNEL, (void *)pwrite_itoa },
    {"regDomain", pvar_getmib, MIB_HW_REG_DOMAIN, (void *)pwrite_itoa },

#ifdef URL_FILTER_USER_MODE_SUPPORT
    {"urlFilterUserModeSupport", pvar_printarg, (long)(void *)"1", NULL },
#else
    {"urlFilterUserModeSupport", pvar_printarg, (long)(void *)"0", NULL },
#endif

#ifndef URL_FILTER_USER_MODE_SUPPORT
    {"usrSpecificUrlCommand_start", pvar_printarg, (long)(void *)"<!--", NULL },
    {"usrSpecificUrlCommand_end", pvar_printarg, (long)(void *)"<!--", NULL },
#else
    {"usrSpecificUrlCommand_start", pvar_printarg, (long)(void *)"", NULL },
    {"usrSpecificUrlCommand_end", pvar_printarg, (long)(void *)"", NULL },
#endif

    {"wep", pvar_getmib, MIB_WLAN_WEP, (void *)pwrite_itoa },

    {"defaultKeyId", pvar_getindex_defaultKeyId, 0, NULL },

    {"keyType", pvar_getmib, MIB_WLAN_WEP_KEY_TYPE, (void *)pwrite_itoa },
    {"authType", pvar_getmib, MIB_WLAN_AUTH_TYPE, (void *)pwrite_itoa },
    {"operRate", pvar_getmib, MIB_WLAN_SUPPORTED_RATES, (void *)pwrite_itoa },
    {"basicRate", pvar_getmib, MIB_WLAN_BASIC_RATES, (void *)pwrite_itoa },
    {"preamble", pvar_getmib, MIB_WLAN_PREAMBLE_TYPE, (void *)pwrite_itoa },
    {"hiddenSSID", pvar_getmib, MIB_WLAN_HIDDEN_SSID, (void *)pwrite_itoa },
    {"wmFilterNum", pvar_getmib, MIB_WLAN_MACAC_NUM, (void *)pwrite_itoa },
    {"wlanDisabled", pvar_getmib, MIB_WLAN_WLAN_DISABLED, (void *)pwrite_itoa },
    {"wlanAcNum", pvar_getmib, MIB_WLAN_MACAC_NUM, (void *)pwrite_itoa },
    {"wlanAcEnabled", pvar_getmib, MIB_WLAN_MACAC_ENABLED, (void *)pwrite_itoa },

#if defined(CONFIG_RTK_MESH) && defined(_MESH_ACL_ENABLE_) // below code copy above ACL code
    {"meshAclNum", pvar_getmib, MIB_WLAN_MESH_ACL_NUM, (void *)pwrite_itoa },
    {"meshAclEnabled", pvar_getmib, MIB_WLAN_MESH_ACL_ENABLED, (void *)pwrite_itoa },
#endif

    {"rateAdaptiveEnabled", pvar_getmib, MIB_WLAN_RATE_ADAPTIVE_ENABLED, (void *)pwrite_itoa },
    {"wlanMode", pvar_getmib, MIB_WLAN_MODE, (void *)pwrite_itoa },

    {"networkType", pvar_getmib, MIB_WLAN_NETWORK_TYPE, (void *)pwrite_itoa },

    {"wlanMode_rpt", pvar_getindex_rpt_type, 0, NULL },
    {"networkType_rpt", pvar_getindex_rpt_type, 0, NULL },
    {"lockdown_stat", pvar_getindex_lockdown_stat, 0, NULL },

#ifndef CONFIG_IAPP_SUPPORT
    {"iappDisabled", pvar_printarg, (long)(void *)"-2", NULL },
#else
    {"iappDisabled", pvar_getmib, MIB_WLAN_IAPP_DISABLED, (void *)pwrite_itoa },
#endif

    {"protectionDisabled", pvar_getmib, MIB_WLAN_PROTECTION_DISABLED, (void *)pwrite_itoa },

    {"encrypt", pvar_getmib, MIB_WLAN_ENCRYPT, (void *)pwrite_itoa },
    {"encrypt_rpt", pvar_getindex_rpt_type, 0, NULL },

    {"enable1X", pvar_getmib, MIB_WLAN_ENABLE_1X, (void *)pwrite_itoa },
    {"enable1x_rpt", pvar_getindex_rpt_type, 0, NULL },

    {"enableSuppNonWpa", pvar_getmib, MIB_WLAN_ENABLE_SUPP_NONWPA, (void *)pwrite_itoa },
    {"suppNonWpa", pvar_getmib, MIB_WLAN_SUPP_NONWPA, (void *)pwrite_itoa },
    {"wpaAuth", pvar_getmib, MIB_WLAN_WPA_AUTH, (void *)pwrite_itoa },
    {"wpa_auth_rpt", pvar_getindex_rpt_type, 0, NULL },

#ifdef CONFIG_RTL_802_1X_CLIENT_SUPPORT
    {"clientModeSupport1X", pvar_printarg, (long)(void *)"1", NULL },
#else
    {"clientModeSupport1X", pvar_printarg, (long)(void *)"0", NULL },
#endif


#ifdef CONFIG_RTL_802_1X_CLIENT_SUPPORT
    {"eapType", pvar_getmib, MIB_WLAN_EAP_TYPE, (void *)pwrite_itoa },
#else
    {"eapType", pvar_printarg, (long)(void *)"0", NULL },
#endif


#ifdef CONFIG_RTL_802_1X_CLIENT_SUPPORT
    {"eapInsideType", pvar_getmib, MIB_WLAN_EAP_INSIDE_TYPE, (void *)pwrite_itoa },
#else
    {"eapInsideType", pvar_printarg, (long)(void *)"0", NULL },
#endif

    {"wpaCipher", pvar_getmib, MIB_WLAN_WPA_CIPHER_SUITE, (void *)pwrite_itoa },

#ifdef CONFIG_IEEE80211W
    {"wpa11w", pvar_getmib, MIB_WLAN_IEEE80211W, (void *)pwrite_itoa },
    {"wpa2EnableSHA256", pvar_getmib, MIB_WLAN_SHA256_ENABLE, (void *)pwrite_itoa },
#endif

    {"wpa2Cipher", pvar_getmib, MIB_WLAN_WPA2_CIPHER_SUITE, (void *)pwrite_itoa },
    {"pskFormat", pvar_getmib, MIB_WLAN_PSK_FORMAT, (void *)pwrite_itoa },
    {"accountRsEnabled", pvar_getmib, MIB_WLAN_ACCOUNT_RS_ENABLED, (void *)pwrite_itoa },
    {"accountRsUpdateEnabled", pvar_getmib, MIB_WLAN_ACCOUNT_RS_UPDATE_ENABLED, (void *)pwrite_itoa },
    {"enableMacAuth", pvar_getmib, MIB_WLAN_MAC_AUTH_ENABLED, (void *)pwrite_itoa },
    {"rsRetry", pvar_getmib, MIB_WLAN_RS_MAXRETRY, (void *)pwrite_itoa },
    {"accountRsRetry", pvar_getmib, MIB_WLAN_ACCOUNT_RS_MAXRETRY, (void *)pwrite_itoa },
    {"wlanWdsEnabled", pvar_getmib, MIB_WLAN_WDS_ENABLED, (void *)pwrite_itoa },
    {"wlanWdsNum", pvar_getmib, MIB_WLAN_WDS_NUM, (void *)pwrite_itoa },
    {"wdsEncrypt", pvar_getmib, MIB_WLAN_WDS_ENCRYPT, (void *)pwrite_itoa },
    {"wdsWepFormat", pvar_getmib, MIB_WLAN_WDS_WEP_FORMAT, (void *)pwrite_itoa },
    {"wdsPskFormat", pvar_getmib, MIB_WLAN_WDS_PSK_FORMAT, (void *)pwrite_itoa },
    {"RFType", pvar_getmib, MIB_HW_RF_TYPE, (void *)pwrite_itoa },
    {"band", pvar_getmib, MIB_WLAN_BAND, (void *)pwrite_itoa },
    {"fixTxRate", pvar_getmib, MIB_WLAN_FIX_RATE, (void *)pwrite_itoa },
    {"preAuth", pvar_getmib, MIB_WLAN_WPA2_PRE_AUTH, (void *)pwrite_itoa },
    {"turboMode", pvar_getmib, MIB_WLAN_TURBO_MODE, (void *)pwrite_itoa },
    {"RFPower", pvar_getmib, MIB_WLAN_RFPOWER_SCALE, (void *)pwrite_itoa },


#ifdef WLAN_EASY_CONFIG
    {"autoCfgEnabled", pvar_getmib, MIB_WLAN_EASYCFG_ENABLED, (void *)pwrite_itoa },
    {"autoCfgMode", pvar_getmib, MIB_WLAN_EASYCFG_MODE, (void *)pwrite_itoa },
    {"autoCfgKeyInstall", pvar_getindex_autoCfgKeyInstall, 0, NULL },
    {"autoCfgDigestInstall", pvar_getindex_autoCfgDigestInstall, 0, NULL },
    {"autoCfgWlanMode", pvar_getmib, MIB_WLAN_EASYCFG_WLAN_MODE, (void *)pwrite_itoa },
#endif // WLAN_EASY_CONFIG


#ifdef HOME_GATEWAY
    {"ddnsEnabled", pvar_getmib, MIB_DDNS_ENABLED, (void *)pwrite_itoa },
    {"ddnsType", pvar_getmib, MIB_DDNS_TYPE, (void *)pwrite_itoa },
    {"webWanAccess", pvar_getmib, MIB_WEB_WAN_ACCESS_ENABLED, (void *)pwrite_itoa },
    {"pingWanAccess", pvar_getmib, MIB_PING_WAN_ACCESS_ENABLED, (void *)pwrite_itoa },
    {"VPNPassThruIPsec", pvar_getmib, MIB_VPN_PASSTHRU_IPSEC_ENABLED, (void *)pwrite_itoa },
    {"VPNPassThruPPTP", pvar_getmib, MIB_VPN_PASSTHRU_PPTP_ENABLED, (void *)pwrite_itoa },
    {"VPNPassThruL2TP", pvar_getmib, MIB_VPN_PASSTHRU_L2TP_ENABLED, (void *)pwrite_itoa },
    {"ppoepassthrouh", pvar_getindex_passthrough, 0, NULL },
    {"ipv6passthrouh", pvar_getindex_passthrough, 0, NULL },
    {"urlFilterEnabled", pvar_getmib, MIB_URLFILTER_ENABLED, (void *)pwrite_itoa },
    {"urlFilterMode", pvar_getmib, MIB_URLFILTER_MODE, (void *)pwrite_itoa },
#endif
    {"wispWanId", pvar_getmib, MIB_WISP_WAN_ID, (void *)pwrite_itoa },
    {"opMode", pvar_getmib, MIB_OP_MODE, (void *)pwrite_itoa },
    {"wlan_num", pvar_getindex_print_wlanvar, WLANVAR_NUM, NULL },
    {"show_wlan_num", pvar_getindex_show_wlan_num, 0, NULL },

#ifdef MBSSID
    {"vwlan_num", pvar_getindex_print_vwlanvar, VWLANVAR_NUM, NULL },
#endif

    {"wlan_idx", pvar_getindex_print_wlanvar, WLANVAR_IDX, NULL },
    {"wlanMacClone", pvar_getmib, MIB_WLAN_MACCLONE_ENABLED, (void *)pwrite_itoa },

#if defined(CONFIG_RTL_819X) && !defined(CONFIG_WLAN_CLIENT_MODE)// keith. disabled if no this mode in 96c
    {"isWispDisplay", pvar_printarg, (long)(void *)"0", NULL },
#else
    {"isWispDisplay", pvar_printarg, (long)(void *)"1", NULL },
#endif


#if !defined(UNIVERSAL_REPEATER) || defined(CONFIG_RTL_819X) && !defined(CONFIG_WLAN_CLIENT_MODE)// keith. disabled if no this mode in 96c
    {"isRepeaterDisplay", pvar_printarg, (long)(void *)"0", NULL },
#else
    {"isRepeaterDisplay", pvar_printarg, (long)(void *)"1", NULL },
#endif


#if defined(CONFIG_WLAN_WDS_SUPPORT)
    {"isWDSDefined", pvar_printarg, (long)(void *)"1", NULL },
#else
    {"isWDSDefined", pvar_printarg, (long)(void *)"0", NULL },
#endif


#if defined(CONFIG_RTL_ULINKER)
    {"isOtg_Auto", pvar_getmib, MIB_ULINKER_AUTO, (void *)pwrite_itoa },
#else
    {"isOtg_Auto", pvar_printarg, (long)(void *)"0", NULL },
#endif

    {"ulinker_opMode", pvar_getindex_ulinker_opMode, 0, NULL },

#if defined(CONFIG_RTL_P2P_SUPPORT)
    {"isP2PSupport", pvar_printarg, (long)(void *)"1", NULL },
#else
    {"isP2PSupport", pvar_printarg, (long)(void *)"0", NULL },
#endif


#ifdef STA_CONTROL
    {"staControlEnabled", pvar_getmib, MIB_WLAN_STACTRL_ENABLE, (void *)pwrite_itoa },
    {"staControlPrefer", pvar_getmib, MIB_WLAN_STACTRL_PREFER, (void *)pwrite_itoa },
#endif


#ifdef STA_CONTROL
    {"isStaControlDefined", pvar_printarg, (long)(void *)"1", NULL },
#else
    {"isStaControlDefined", pvar_printarg, (long)(void *)"0", NULL },
#endif


    {"meshPskFormat", pvar_getmib, MIB_WLAN_MESH_PSK_FORMAT, (void *)pwrite_itoa, "0"},
    {"meshEncrypt", pvar_getmib, MIB_WLAN_MESH_ENCRYPT, (void *)pwrite_itoa, "0"},
#ifdef CONFIG_RTK_MESH
    {"wlanMeshEnabled", pvar_getmib, MIB_WLAN_MESH_ENABLE, (void *)pwrite_itoa },
    {"meshRootEnabled", pvar_getmib, MIB_WLAN_MESH_ROOT_ENABLE, (void *)pwrite_itoa },
    //{"meshEncrypt", pvar_getmib, MIB_WLAN_MESH_ENCRYPT, (void *)pwrite_itoa, "0"},
    //{"meshPskFormat", pvar_getmib, MIB_WLAN_MESH_PSK_FORMAT, (void *)pwrite_itoa },

    {"meshPskValue", pvar_getindex_meshPskValue, 0, NULL },

    {"meshWpaAuth", pvar_getmib, MIB_WLAN_MESH_WPA_AUTH, (void *)pwrite_itoa },
    {"meshWpa2Cipher", pvar_getmib, MIB_WLAN_MESH_WPA2_CIPHER_SUITE, (void *)pwrite_itoa },

#ifdef _MESH_ACL_ENABLE_
    {"meshAclEnabled", pvar_getmib, MIB_WLAN_MESH_ACL_ENABLED, (void *)pwrite_itoa },
#endif


#endif // CONFIG_RTK_MESH
    //indispensable!! MESH related , no matter mesh enable or not
#ifdef CONFIG_RTK_MESH
    {"isMeshDefined", pvar_printarg, (long)(void *)"1", NULL },
#else
    {"isMeshDefined", pvar_printarg, (long)(void *)"0", NULL },
#endif


#ifdef CONFIG_NEW_MESH_UIi
    {"isNewMeshUI", pvar_printarg, (long)(void *)"1", NULL },
#else
    {"isNewMeshUI", pvar_printarg, (long)(void *)"0", NULL },
#endif


#ifdef CONFIG_APP_SAMBA
    {"sambaEnabled", pvar_printarg, (long)(void *)"1", NULL },
#else
    {"sambaEnabled", pvar_printarg, (long)(void *)"0", NULL },
#endif

    {"rtLogEnabled", pvar_getmib, MIB_REMOTELOG_ENABLED, (void *)pwrite_itoa },
    {"logEnabled", pvar_getmib, MIB_SCRLOG_ENABLED, (void *)pwrite_itoa },

#ifdef TLS_CLIENT
    {"rootIdx", pvar_getmib, MIB_ROOT_IDX, (void *)pwrite_itoa },
    {"userIdx", pvar_getmib, MIB_USER_IDX, (void *)pwrite_itoa },
    {"rootNum", pvar_getmib, MIB_CERTROOT_TBL_NUM, (void *)pwrite_itoa },
    {"userNum", pvar_getmib, MIB_CERTUSER_TBL_NUM, (void *)pwrite_itoa },
#endif

#ifdef UNIVERSAL_REPEATER
#if defined(RTL_MULTI_REPEATER_MODE_SUPPORT)
    {"multiRepeaterEnabled", pvar_printarg, (long)(void *)"1", NULL },
#else
    {"multiRepeaterEnabled", pvar_printarg, (long)(void *)"0", NULL },
#endif

#if defined(RTL_MULTI_REPEATER_MODE_SUPPORT)
    {"multiAPRepeaterStr", pvar_printarg, (long)(void *)"MultipleAP-MultipleRepeater", NULL },
#else
    {"multiAPRepeaterStr", pvar_printarg, (long)(void *)"multiAPRepeaterStr", NULL },
#endif

    {"repeaterEnabled", pvar_getindex_about_repeater, 0, NULL },
    {"isRepeaterEnabled", pvar_getindex_about_repeater, 0, NULL },
    {"repeaterMode", pvar_getindex_about_repeater, 0, NULL },
#endif // UNIVERSAL_REPEATER

    {"WiFiTest", pvar_getmib, MIB_WIFI_SPECIFIC, (void *)pwrite_itoa },

#ifdef HOME_GATEWAY
#ifdef DOS_SUPPORT
    {"dosEnabled", pvar_getmib, MIB_DOS_ENABLED, (void *)pwrite_itoa },
    {"ARPspoofEnabled", pvar_getnvram, (long)(void *)"x_ARP_DEFENDER_ENABLE", (void *)"0" },
    {"TraceRtEnabled", pvar_getnvram, (long)(void *)"x_noreply_tracert", (void *)"0" },
    {"pingSecEnabled", pvar_getnvram, (long)(void *)"x_pingSecEnabled", (void *)"0" },
    {"NTPDefEnabled", pvar_getnvram, (long)(void *)"x_NTPDefEnabled", (void *)"0" },
    {"DNSRelayEnabled", pvar_getnvram, (long)(void *)"x_DNSRelayEnabled", (void *)"0" },
#endif

    {"pptpSecurity", pvar_getmib, MIB_PPTP_SECURITY_ENABLED, (void *)pwrite_itoa },
    {"pptpCompress", pvar_getmib, MIB_PPTP_MPPC_ENABLED, (void *)pwrite_itoa },
#endif

#ifdef WIFI_SIMPLE_CONFIG
    {"wscDisable", pvar_getmib, MIB_WLAN_WSC_DISABLE, (void *)pwrite_itoa },
    {"wscConfig", pvar_getmib, MIB_WLAN_WSC_CONFIGURED, (void *)pwrite_itoa },
    {"wscRptConfig", pvar_getindex_rpt_type, 0, NULL },

    {"wps_by_reg", pvar_getmib, MIB_WLAN_WSC_CONFIGBYEXTREG, (void *)pwrite_itoa },
    {"wps_auth", pvar_getmib, MIB_WLAN_WSC_AUTH, (void *)pwrite_itoa },

    {"wps_enc", pvar_getmib, MIB_WLAN_WSC_ENC, (void *)pwrite_itoa },
    {"wpsRpt_auth", pvar_getindex_rpt_type, 0, NULL },
    {"wpsRpt_enc", pvar_getindex_rpt_type, 0, NULL },
#endif // WIFI_SIMPLE_CONFIG
#ifdef WLAN_HS2_CONFIG
    {"hs2Enabled", pvar_getmib, MIB_WLAN_HS2_ENABLE, (void *)pwrite_itoa },
#else
    {"hs2Enabled", pvar_printarg, (long)(void *)"-2", NULL },
#endif

    // for WMM
    {"wmmEnabled", pvar_getmib, MIB_WLAN_WMM_ENABLED, (void *)pwrite_itoa },

    //for 11N
    {"ChannelBonding", pvar_getmib, MIB_WLAN_CHANNEL_BONDING, (void *)pwrite_itoa },
    {"ControlSideBand", pvar_getmib, MIB_WLAN_CONTROL_SIDEBAND, (void *)pwrite_itoa },
    {"aggregation", pvar_getmib, MIB_WLAN_AGGREGATION, (void *)pwrite_itoa },
    {"shortGIEnabled", pvar_getmib, MIB_WLAN_SHORT_GI, (void *)pwrite_itoa },
    {"static_dhcp", pvar_getmib, MIB_DHCPRSVDIP_ENABLED, (void *)pwrite_itoa },
    {"wlanAccess", pvar_getmib, MIB_WLAN_ACCESS, (void *)pwrite_itoa },

    {"rf_used", pvar_getindex_rf_used, 0, NULL },

    {"block_relay", pvar_getmib, MIB_WLAN_BLOCK_RELAY, (void *)pwrite_itoa },
    {"tx_stbc", pvar_getmib, MIB_WLAN_STBC_ENABLED, (void *)pwrite_itoa },
    {"tx_ldpc", pvar_getmib, MIB_WLAN_LDPC_ENABLED, (void *)pwrite_itoa },
    {"coexist", pvar_getmib, MIB_WLAN_COEXIST_ENABLED, (void *)pwrite_itoa },
	//### add by sen_liu 2011.3.29 TX Beamforming added to mib in 92D
    {"tx_beamforming", pvar_getmib, MIB_WLAN_TX_BEAMFORMING, (void *)pwrite_itoa },
	//### end
    {"mc2u_disable", pvar_getmib, MIB_WLAN_MC2U_DISABLED, (void *)pwrite_itoa },
    {"tdls_prohibited", pvar_getmib, MIB_WLAN_TDLS_PROHIBITED, (void *)pwrite_itoa },
    {"tdls_cs_prohibited", pvar_getmib, MIB_WLAN_TDLS_CS_PROHIBITED, (void *)pwrite_itoa },
    {"lowestMlcstRate", pvar_getmib, MIB_WLAN_LOWEST_MLCST_RATE, (void *)pwrite_itoa },

#if defined(CONFIG_RTK_VLAN_NEW_FEATURE)
    {"vlan_bridge_feature", pvar_printarg, (long)(void *)"1", NULL },
#else
    {"vlan_bridge_feature", pvar_printarg, (long)(void *)"0", NULL },
#endif

#if defined(CONFIG_RTL_HW_VLAN_SUPPORT)
    {"hw_vlan_support", pvar_printarg, (long)(void *)"1", NULL },
#else
    {"hw_vlan_support", pvar_printarg, (long)(void *)"0", NULL },
#endif

#ifdef MBSSID
    {"mssid_idx", pvar_getindex_print_mwlanvar, MSSID_IDX, NULL },
#endif

    {"wlan_mssid_num", pvar_printarg, DEF_MSSID_NUM, (void *)pwrite_itoa },


#if defined(UNIVERSAL_REPEATER)
    {"wlan_root_mssid_rpt_num", pvar_printarg, NUM_VWLAN+1+1, (void *)pwrite_itoa },
#else
    {"wlan_root_mssid_rpt_num", pvar_printarg, NUM_VWLAN+1, (void *)pwrite_itoa },
#endif


#ifdef CONFIG_RTL_WAPI_SUPPORT
    {"wapiAuth", pvar_getmib, MIB_WLAN_WAPI_AUTH, (void *)pwrite_itoa },
#else
    {"wapiAuth", pvar_printarg, (long)(void *)"0", (void *)pwrite_itoa },
#endif


#ifdef CONFIG_RTL_WAPI_SUPPORT
    {"wapiPskFormat", pvar_getmib, MIB_WLAN_WAPI_PSK_FORMAT, (void *)pwrite_itoa },
#else
    {"wapiPskFormat", pvar_printarg, (long)(void *)"0", NULL },
#endif


#ifdef CONFIG_RTL_WAPI_SUPPORT
    {"wapiUcastReKeyType", pvar_getindex_ReKeyType, 0, NULL },
    {"wapiMcastReKeyType", pvar_getindex_ReKeyType, 0, NULL },
    {"wapiSearchIndex", pvar_getmib, MIB_WLAN_WAPI_SEARCHINDEX, (void *)pwrite_itoa },
#else
    {"wapi", pvar_return_zero, 0, NULL },
#endif


#if defined(NEW_SCHEDULE_SUPPORT)
    {"isSupportNewWlanSch", pvar_printarg, (long)(void *)"1", NULL },
#else
    {"isSupportNewWlanSch", pvar_printarg, (long)(void *)"0", NULL },
#endif


#ifdef CONFIG_RTL_WAPI_SUPPORT
    {"clientModeSupportWapi", pvar_printarg, (long)(void *)"1", NULL },
#else
    {"clientModeSupportWapi", pvar_printarg, (long)(void *)"0", NULL },
#endif


#if defined(UNIVERSAL_REPEATER) && defined(CONFIG_REPEATER_WPS_SUPPORT)
    {"is_rpt_wps_support", pvar_printarg, (long)(void *)"1", NULL },
#else
    {"is_rpt_wps_support", pvar_printarg, (long)(void *)"0", NULL },
#endif


#if defined(UNIVERSAL_REPEATER) && defined(CONFIG_REPEATER_WPS_SUPPORT) && defined(CONFIG_WPS_EITHER_AP_OR_VXD)
    {"wps_either_ap_or_vxd", pvar_printarg, (long)(void *)"1", NULL },
#else
    {"wps_either_ap_or_vxd", pvar_printarg, (long)(void *)"0", NULL },
#endif


#if defined(CONFIG_SNMP)
    {"snmp_enabled", pvar_getmib, MIB_SNMP_ENABLED, (void *)pwrite_itoa },
#endif

    {"wlanBand2G5GSelect", pvar_getmib, MIB_WLAN_BAND2G5G_SELECT, (void *)pwrite_itoa },
    {"Band2G5GSupport", pvar_getmib, MIB_WLAN_PHY_BAND_SELECT, (void *)pwrite_itoa },

#if defined(CONFIG_RTL_92D_SUPPORT)
    {"wlan_support_92D", pvar_printarg, (long)(void *)"1", NULL },
#else
    {"wlan_support_92D", pvar_printarg, (long)(void *)"0", NULL },
#endif


#if defined(CONFIG_RTL_8812_SUPPORT)
    {"wlan_support_8812e", pvar_printarg, (long)(void *)"1", NULL },
#else
    {"wlan_support_8812e", pvar_printarg, (long)(void *)"0", NULL },
#endif


#if defined(CONFIG_RTL_AC2G_256QAM) || defined(CONFIG_WLAN_HAL_8814AE)
    {"wlan_support_ac2g", pvar_printarg, (long)(void *)"1", NULL },
#else
    {"wlan_support_ac2g", pvar_printarg, (long)(void *)"0", NULL },
#endif


#if defined(CONFIG_RTL_8812AR_VN_SUPPORT)
    {"wlan_support_8192f", pvar_printarg, (long)(void *)"1", NULL },
#else
    {"wlan_support_8192f", pvar_printarg, (long)(void *)"0", NULL },
#endif

    {"wlan_mode_2x2", pvar_getindex_wlan_mode_2x2, 0, NULL },

//### edit by sen_liu 2011.4.7 #if #else # endif bug
#if defined(CONFIG_RTL_DUAL_PCIESLOT_BIWLAN_D)	//92D + 92C
    {"wlan_support_92D_concurrent", pvar_printarg, (long)(void *)"2", NULL },
#else
	#if defined(CONFIG_RTL_92D_DMDP) //92D
        {"wlan_support_92D_concurrent", pvar_printarg, (long)(void *)"1", NULL },
	#else //92C
        {"wlan_support_92D_concurrent", pvar_printarg, (long)(void *)"1", NULL },
	#endif
#endif
//### end

    {"wlan1_phyband", pvar_getindex_phyband, 0, NULL },
    {"wlan2_phyband", pvar_getindex_phyband, 0, NULL },


#if defined(CONFIG_RTL_8198_AP_ROOT) && defined(GMII_ENABLED)
    {"maxWebVlanNum", pvar_printarg, MAX_IFACE_VLAN_CONFIG-2, (void *)pwrite_itoa },
#else
    {"maxWebVlanNum", pvar_printarg, MAX_IFACE_VLAN_CONFIG-1, (void *)pwrite_itoa },
#endif

    {"2G_ssid", pvar_getindex_getssid, 0, NULL },
    {"5G_ssid", pvar_getindex_getssid, 0, NULL },

#if defined(CONFIG_RTL_DFS_SUPPORT)
    {"dsf_enable", pvar_getnvram, (long)(void *)"x_dfs_enable", (void *)"0" },
#else
    {"dsf_enable", pvar_printarg, (long)(void *)"0", NULL },
#endif

    {"set_wlanindex", pvar_getindex_set_wlanindex, 0, NULL },
    {"vlan_val_init", pvar_getindex_vlan_val_init, 0, NULL },
    {"wizard_wlband_init", pvar_getindex_wizard_wlband_init, 0, NULL },


#if defined(CONFIG_NETFILTER_XT_MATCH_LAYER7)
    {"is_l7_qos_support", pvar_printarg, (long)(void *)"1", NULL },
#else
    {"is_l7_qos_support", pvar_printarg, (long)(void *)"0", NULL },
#endif


#if defined(CONFIG_RTL_ETH_802DOT1X_CLIENT_MODE_SUPPORT)
    {"wan_eth_dot1x_enabled", pvar_getindex_wan_eth_dot1x_enabled, 0, NULL },
    {"wan_eth_dot1x_eap_type", pvar_getmib, MIB_ELAN_EAP_TYPE, (void *)pwrite_itoa },
    {"eth_eap_inside_type", pvar_getmib, MIB_ELAN_EAP_INSIDE_TYPE, (void *)pwrite_itoa },
    {"eth_eap_phase2_type", pvar_getmib, MIB_ELAN_EAP_PHASE2_TYPE, (void *)pwrite_itoa },
    {"eth_eap_user_id", pvar_getmib, MIB_ELAN_EAP_USER_ID, (void *)pwrite_itoa },
    {"eth_eap_user_name", pvar_getmib, MIB_ELAN_RS_USER_NAME, (void *)pwrite_puts },
    {"eth_eap_user_password", pvar_getmib, MIB_ELAN_RS_USER_PASSWD, (void *)pwrite_puts },
    {"eth_eap_user_key", pvar_getmib, MIB_ELAN_RS_USER_PASSWD, (void *)pwrite_puts },
#endif


#ifdef SAMBA_WEB_SUPPORT
    {"StorageAnonAccessEnable", pvar_getmib, MIB_STORAGE_ANON_ENABLE, (void *)pwrite_itoa },
    {"StorageAnonAccessDiskEnable", pvar_getmib, MIB_STORAGE_ANON_DISK_ENABLE, (void *)pwrite_itoa },
#endif


#ifdef CONFIG_IPV6
#ifdef CONFIG_DSLITE_SUPPORT
    {"dsliteMode", pvar_getmib, MIB_DSLITE_MODE, (void *)pwrite_itoa },
#else
    {"dsliteMode", pvar_printarg, (long)(void *)"0", (void *)pwrite_itoa },
#endif
#else
    {"dsliteMode", pvar_printarg, (long)(void *)"0", (void *)pwrite_itoa },
#endif


#ifdef CONFIG_CPU_UTILIZATION
    {"isDisplayCPU", pvar_printarg, (long)(void *)"1", NULL },
    {"CPUnumber", pvar_getindex_cpunumber, 0, NULL },
    {"CPUsample", pvar_getmib, MIB_CPU_UTILIZATION_INTERVAL, (void *)pwrite_itoa },
    {"CPUenable", pvar_getmib, MIB_ENABLE_CPU_UTILIZATION, (void *)pwrite_itoa },
#else
    {"isDisplayCPU", pvar_printarg, (long)(void *)"0", NULL },
#endif


#ifdef CONFIG_RTL_TRANSMISSION
    {"isEnableBT", pvar_printarg, (long)(void *)"1", NULL },
#else
    {"isEnableBT", pvar_printarg, (long)(void *)"0", NULL },
#endif


#ifdef __DAVO__
    {"swms_enable", pvar_getindex_swms_enable, 0, NULL },
    {"staticDhcpNum", pvar_getmib, MIB_DHCPRSVDIP_TBL_NUM, (void *)pwrite_itoa },
    {"ipv6_autoconfig_method", pvar_getnvram, (long)(void *)"x_ipv6_autoconfig_method", (void *)"0" },
    {"ipv6_dns_method", pvar_getnvram, (long)(void *)"x_ipv6_dns_method", (void *)"0" },
    {"stMappingNum", pvar_getnvram, (long)(void *)"x_STATICMAP_TBL_NUM", (void *)"0" },
    {"portFwNum", pvar_getmib, MIB_PORTFW_TBL_NUM, (void *)pwrite_itoa },
    {"dvnv_fast_igmp", pvar_getindex_dvnv_fast_igmp, 0, NULL },
    {"macfil_active_port", pvar_getindex_macfil_active_port, 0, NULL },
    {"isAdmin", pvar_getindex_isAdmin, 0, NULL },
    {"sdmzEnabled", pvar_getnvram, (long)(void *)"x_SDMZ_ENABLED", (void *)"0" },
    {"UseAutoup", pvar_getindex_UseAutoup, 0, NULL },
    {"input_policy_accept", pvar_getnvram, (long)(void *)"x_input_policy_accept", (void *)"0" },
    {"snmp_trap_enable", pvar_getindex_snmp, 0, NULL },
    {"snmp_enable", pvar_getindex_snmp, 0, NULL },
    {"snmp_com1", pvar_getindex_snmp, 0, NULL },
    {"snmp_com2", pvar_getindex_snmp, 0, NULL },
#endif
    //
    //End of List
    //
    {"End of List", NULL, 0, NULL}
};

void __attribute__ ((constructor)) sort_pgetindex_vars(void)
{
	qsort(pgetindex_vars, ARRAY_SIZE(pgetindex_vars),
	      sizeof(struct aspvar),
	      (int (*)(const void *, const void *))pvar_compr);
}

int getIndex(request *wp, int argc, char **argv)
{
    struct aspvar k = {.name = argv[0] };
	struct aspvar *p;

    if (argv[0] == NULL) {
   		fprintf(stderr, "Insufficient args\n");
   		return -1;
   	}

	p = (struct aspvar *)bsearch(&k, pgetindex_vars, ARRAY_SIZE(pgetindex_vars),
				     sizeof(struct aspvar),
				     (int (*)(const void *, const void *))pvar_compr);
    if (p != NULL)
        return p->get(wp, argc, argv, p);
    else
        return -1;
}

#ifdef MBSSID
int getVirtualIndex(request *wp, int argc, char **argv)
{
	int ret, old;
	char WLAN_IF_old[40];

	old = vwlan_idx;
	vwlan_idx = atoi(argv[--argc]);
#if defined(CONFIG_RTL_ULINKER)
	if(vwlan_idx == 5) //vxd
		vwlan_idx = NUM_VWLAN_INTERFACE;
#endif

	if (vwlan_idx > NUM_VWLAN_INTERFACE) {
		//fprintf(stderr, "###%s:%d wlan_idx=%d vwlan_idx=%d###\n", __FILE__, __LINE__, wlan_idx, vwlan_idx);
		req_format_write(wp, "0");
		vwlan_idx = old;
		return 0;
	}

//#if defined(CONFIG_RTL_8196B)
//	if (vwlan_idx == 5) { //rtl8196b support repeater mode only first, no mssid
//#else
	if (vwlan_idx > 0) {
//#endif
		strcpy(WLAN_IF_old, WLAN_IF);
		sprintf(WLAN_IF, "%s-va%d", WLAN_IF_old, vwlan_idx-1);
	}

	ret = getIndex(wp, argc, argv);

//#if defined(CONFIG_RTL_8196B)
//	if (vwlan_idx == 5)
//#else
	if (vwlan_idx > 0)
//#endif
		strcpy(WLAN_IF, WLAN_IF_old);

	vwlan_idx = old;
	return ret;
}

int getVirtualInfo(request *wp, int argc, char **argv)
{
	int ret, old;
	char WLAN_IF_old[40];

	old = vwlan_idx;
	vwlan_idx = atoi(argv[--argc]);
#if defined(CONFIG_RTL_ULINKER)
		if(vwlan_idx == 5) //vxd
		vwlan_idx = NUM_VWLAN_INTERFACE;
#endif

	if (vwlan_idx > NUM_VWLAN_INTERFACE) {
		//fprintf(stderr, "###%s:%d wlan_idx=%d vwlan_idx=%d###\n", __FILE__, __LINE__, wlan_idx, vwlan_idx);
		req_format_write(wp, "0");
		vwlan_idx = old;
		return 0;
	}

//#if defined(CONFIG_RTL_8196B)
//	if (vwlan_idx == 5) { //rtl8196b support repeater mode only first, no mssid
//#else
	if (vwlan_idx > 0) {
//#endif
		strcpy(WLAN_IF_old, WLAN_IF);
		sprintf(WLAN_IF, "%s-va%d", WLAN_IF_old, vwlan_idx-1);
	}

	ret = getInfo(wp, argc, argv);

//#if defined(CONFIG_RTL_8196B)
//	if (vwlan_idx == 5)
//#else
	if (vwlan_idx > 0)
//#endif
		strcpy(WLAN_IF, WLAN_IF_old);

	vwlan_idx = old;
	return ret;
}
#endif
#ifdef FAST_BSS_TRANSITION
void multilang(request *wp, int argc, char **argv)
{
	return req_format_write(wp,"%s",argv[0]);
}
#endif

#ifdef __DAVO__
extern unsigned int g_daa_hist;
extern unsigned int g_daa_status;
int getInfo_formDaa(request *wp, int argc, char **argv)
{
	char *name;
	FILE *fp;
	char *p, *sp;
	char buf[50];
	int intVal;
	char tmp[80];

	buf[0] = 0;

	name = argv[0];
	if (name == NULL) {
   		fprintf(stderr, "Insufficient args\n");
   		return -1;
   	}

	if ( !strcmp(name, "rfi_test_mode") ) {
		sprintf(tmp, "/proc/wlan%d/rfi_test_mode", atoi(argv[1]));
		fp = fopen(tmp, "r");
		if (!fp)
			return req_format_write(wp, "0");

		if ( fgets(buf, sizeof(buf), fp) ) {
			p = strtok_r(buf, " :\r\n\t", &sp);
			p = strtok_r(NULL," :\r\n\t", &sp);
			fclose(fp);

			return req_format_write(wp, p);
		}
		fclose(fp);
	}
	else if ( !strcmp(name, "wlan_idx") ) {
		sprintf(buf, "%d", wlan_idx);
		return req_format_write(wp, buf);
	}
	else if ( !strcmp(name, "mirror_daa_hist") ) {
		sprintf(buf, "%d", g_daa_hist);
		return req_format_write(wp, buf);
	}
	else if ( !strcmp(name, "mirror_daa_status") ) {
		sprintf(buf, "%d", g_daa_status);
		return req_format_write(wp, buf);
	}
	else if ( !strcmp(name, "wlanDisabled")) {
		if ( !apmib_get( MIB_WLAN_WLAN_DISABLED, (void *)&intVal) )
			return -1;
		sprintf(buf, "%d", intVal);
		return req_format_write(wp, buf);
	}

	return -1;
}
#endif

#ifdef HOME_GATEWAY
/////////////////////////////////////////////////////////////////////////////
int isConnectPPP()
{
	struct stat status;
#ifdef MULTI_PPPOE
	if(PPPoE_Number == 1)
	{
		if ( stat("/etc/ppp/link", &status) < 0)
			return 0;
	}
	else if(PPPoE_Number == 2)
	{
		if ( stat("/etc/ppp/link2", &status) < 0)
			return 0;
	}
	else if(PPPoE_Number ==3)
	{
		if ( stat("/etc/ppp/link3", &status) < 0)
			return 0;
	}
	else if(PPPoE_Number ==4)
	{
		if ( stat("/etc/ppp/link4", &status) < 0)
			return 0;
	}
	else
	{
		if ( stat("/etc/ppp/link", &status) < 0)
			return 0;
	}
#else
	if ( stat("/etc/ppp/link", &status) < 0)
		return 0;
#endif

	return 1;
}
#endif
int getDHCPModeCombobox(request *wp, int argc, char **argv)
{
	int val = 0;
	int lan_dhcp_mode=0;
	int operation_mode=0;
	apmib_get( MIB_WLAN_MODE, (void *)&val);
	apmib_get(MIB_DHCP,(void *)&lan_dhcp_mode);
	apmib_get( MIB_OP_MODE, (void *)&operation_mode);
#if defined(CONFIG_DOMAIN_NAME_QUERY_SUPPORT)
        if((operation_mode==1 && (val==0 ||val==1)) || (operation_mode==0)){
	       if(lan_dhcp_mode == 0){
	 		return req_format_write(wp,"<option selected value=\"0\">Disabled</option>"
	 							"<option value=\"1\">Client</option>"
	 							 "<option value=\"2\">Server</option>"
	 							  "<option value=\"15\">Auto</option>");
	      	  }
		if(lan_dhcp_mode == 1){
	 		return req_format_write(wp,"<option  value=\"0\">Disabled</option>"
	 							"<option selected value=\"1\">Client</option>"
	 							 "<option value=\"2\">Server</option>"
	 							  "<option value=\"15\">Auto</option>");
	      	  }
		if(lan_dhcp_mode == 2){
	 		return req_format_write(wp,"<option  value=\"0\">Disabled</option>"
	 							"<option  value=\"1\">Client</option>"
	 							 "<option selected value=\"2\">Server</option>"
	 							  "<option value=\"15\">Auto</option>");
	      	  }
	       if(lan_dhcp_mode == 15){
	 		return req_format_write(wp,"<option  value=\"0\">Disabled</option>"
	 							"<option  value=\"1\">Client</option>"
	 							 "<option value=\"2\">Server</option>"
	 							 "<option selected value=\"15\">Auto</option>");
	      	  }
    	}
#elif defined(CONFIG_RTL_ULINKER)
		if((operation_mode==1 && (val==0 ||val==1)) || (operation_mode==0) || (operation_mode==2)){
		   if(lan_dhcp_mode == 0){
			return req_format_write(wp,"<option selected value=\"0\">Disabled</option>"
								"<option value=\"1\">Client</option>"
								 "<option value=\"2\">Server</option>"
								  "<option value=\"19\">Auto</option>");
			  }
		if(lan_dhcp_mode == 1){
			return req_format_write(wp,"<option  value=\"0\">Disabled</option>"
								"<option selected value=\"1\">Client</option>"
								 "<option value=\"2\">Server</option>"
								  "<option value=\"19\">Auto</option>");
			  }
		if(lan_dhcp_mode == 2){
			return req_format_write(wp,"<option  value=\"0\">Disabled</option>"
								"<option  value=\"1\">Client</option>"
								 "<option selected value=\"2\">Server</option>"
								  "<option value=\"19\">Auto</option>");
			  }
		   if(lan_dhcp_mode == 19){
			return req_format_write(wp,"<option  value=\"0\">Disabled</option>"
								"<option  value=\"1\">Client</option>"
								 "<option value=\"2\">Server</option>"
								 "<option selected value=\"19\">Auto</option>");
			  }
		}
#else
 	if(lan_dhcp_mode == 0){
 		return req_format_write(wp,"<option selected value=\"0\">Disabled</option>"
 							"<option value=\"1\">Client</option>"
 							 "<option value=\"2\">Server</option>");
      	  }
	if(lan_dhcp_mode == 1){
 		return req_format_write(wp,"<option  value=\"0\">Disabled</option>"
 							"<option selected value=\"1\">Client</option>"
 							 "<option value=\"2\">Server</option>");
      	  }
	if(lan_dhcp_mode == 2){
 		return req_format_write(wp,"<option  value=\"0\">Disabled</option>"
 							"<option  value=\"1\">Client</option>"
 							 "<option selected value=\"2\">Server</option>");
      	  }
#endif
	return 0;
}
#ifdef FAST_BSS_TRANSITION
void SSID_select(request *wp, int argc, char **argv)
{
	int wlan_disable=0,wlan_mode=0,i=0;

	char ssid[MAX_SSID_LEN]={0};
	apmib_get(MIB_WLAN_WLAN_DISABLED,(void*)&wlan_disable);
	apmib_get(MIB_WLAN_MODE,(void*)&wlan_mode);
	apmib_get(MIB_WLAN_SSID,(void*)ssid);
	translate_control_code(ssid);

	if(wlan_disable)
		return req_format_write(wp, "<option selected value=\"0\">wlan disabled</option>");
	if(wlan_mode==AP_MODE)
	{
		req_format_write(wp, "<option value=0>Root AP - %s</option>\n", ssid);
	}

	apmib_save_wlanIdx();

	for (i=1; i<NUM_VWLAN_INTERFACE+1; i++)
	{
			vwlan_idx=i;
			apmib_get(MIB_WLAN_WLAN_DISABLED,(void*)&wlan_disable);
			if(!wlan_disable)
			{
				apmib_get(MIB_WLAN_SSID,(void*)ssid);

				translate_control_code(ssid);
				if(i==NUM_VWLAN_INTERFACE)
					req_format_write(wp, "<option value=%d>wlan%d repeater - %s</option>\n",i,wlan_idx, ssid);
				else
					req_format_write(wp, "<option value=%d>wlan%d - %s</option>\n",i,wlan_idx, ssid);
			}

	}
	apmib_recov_wlanIdx();
}
void wlFtKhList(request *wp, int argc, char **argv)
{
    int nBytesSent=0, entryNum, i, j, intfIndex=-1;
    FTKH_T ftkh_entry={0};
    int colspan;


    char strSsid[MAX_SSID_LEN],strAddr[18], strId[49], strKey[33];

    // show title
    nBytesSent += req_format_write(wp, "<tr>"
            "<td align=center width=\"14%%\" bgcolor=\"#808080\"><font size=\"2\"><b>%s</b></font></td>\n"
            "<td align=center width=\"44%%\" bgcolor=\"#808080\"><font size=\"2\"><b>%s</b></font></td>\n"
            "<td align=center width=\"30%%\" bgcolor=\"#808080\"><font size=\"2\"><b>%s</b></font></td>\n"
            #ifdef DOT11K
            "<td align=center width=\"30%%\" bgcolor=\"#808080\"><font size=\"2\"><b>%s</b></font></td>\n"
            "<td align=center width=\"30%%\" bgcolor=\"#808080\"><font size=\"2\"><b>%s</b></font></td>\n"
            #endif
            "<td align=center width=\"7%%\" bgcolor=\"#808080\"><font size=\"2\"><b>%s</b></font></td></tr>\n",
            "MAC address", ("NAS identifier"),("128-bit key / passphrase"),
            #ifdef DOT11K
            ("Op Class"), ("Channel"),
            #endif
            ("Select"));

    #ifdef DOT11K
    colspan = 6;
    #else
    colspan = 4;
    #endif
    apmib_get(MIB_WLAN_SSID,(void*)&strSsid);
    nBytesSent += req_format_write(wp, "<tr>"
            "<td align=left width=\"100%%\" colspan=\"%d\" bgcolor=\"#A0A0A0\"><font size=\"2\"><b>%s</b></td></tr>\n",
            colspan, strSsid);

    apmib_get(MIB_WLAN_FTKH_NUM,(void*)&entryNum);
    for(i=1;i<=entryNum;i++)
    {
        *((char*)(&ftkh_entry))=(char)i;
        apmib_get(MIB_WLAN_FTKH,(void*)&ftkh_entry);
        //printf("%s:%d mac=%02x%02x%02x%02x%02x%02x kh_nas_id=%s\n",__FUNCTION__,__LINE__,ftkh_entry.macAddr[0],ftkh_entry.macAddr[1],ftkh_entry.macAddr[2]
        //	,ftkh_entry.macAddr[3],ftkh_entry.macAddr[4],ftkh_entry.macAddr[5],ftkh_entry.nas_id);
        snprintf(strAddr, sizeof(strAddr), "%02x:%02x:%02x:%02x:%02x:%02x",
            ftkh_entry.macAddr[0], ftkh_entry.macAddr[1], ftkh_entry.macAddr[2],
            ftkh_entry.macAddr[3], ftkh_entry.macAddr[4], ftkh_entry.macAddr[5]);
            snprintf(strId, sizeof(strId), "%s", ftkh_entry.nas_id);
            snprintf(strKey, sizeof(strKey), "%s", ftkh_entry.key);

        nBytesSent += req_format_write(wp, "<tr>"
                "<td align=center width=\"16%%\" bgcolor=\"#C0C0C0\"><font size=\"2\">%s</td>\n"
                "<td align=center width=\"25%%\" bgcolor=\"#C0C0C0\"><font size=\"2\">%s</td>\n"
                "<td align=center width=\"25%%\" bgcolor=\"#C0C0C0\"><font size=\"2\">%s</td>\n"
                #ifdef DOT11K
                "<td align=center width=\"12%%\" bgcolor=\"#C0C0C0\"><font size=\"2\">%d</td>\n"
                "<td align=center width=\"12%%\" bgcolor=\"#C0C0C0\"><font size=\"2\">%d</td>\n"
                #endif
                "<td align=center width=\"10%%\" bgcolor=\"#C0C0C0\"><input type=\"checkbox\" name=\"kh_entry_%d\" value=\"ON\"></td></tr>\n",
                strAddr, strId, strKey,
                #ifdef DOT11K
                ftkh_entry.opclass, ftkh_entry.channel,
                #endif
                i);
    }


    return nBytesSent;
}

#endif

int getModeCombobox(request *wp, int argc, char **argv)
{
	int val = 0;
	int opmode;
	int wlanBandMode;
	apmib_get( MIB_OP_MODE, (void *)&opmode);
    apmib_get( MIB_WLAN_BAND, (void *)&wlanBandMode);

	if ( !apmib_get( MIB_WLAN_MODE, (void *)&val) )
			return -1;

#ifdef CONFIG_RTK_MESH
#ifdef CONFIG_NEW_MESH_UI
	  if ( val == 0 ) {
      	  	return req_format_write(wp, "<option selected value=\"0\">AP</option>"
   	  	 "<option value=\"1\">Client</option>"
   	  	 "<option value=\"2\">WDS</option>"
   	  	 "<option value=\"3\">AP+WDS</option>"
   	  	 "<option value=\"4\">AP+MESH</option>"
   	  	 "<option value=\"5\">MESH</option>"  );
      	  }
	  if ( val == 1 ) {
     	  	 return req_format_write(wp,"<option value=\"0\">AP</option>"
   	  	 "<option selected value=\"1\">Client </option>"
   	  	 "<option value=\"2\">WDS</option>"
   	  	 "<option value=\"3\">AP+WDS</option>"
   	  	 "<option value=\"4\">AP+MESH</option>"
   	  	 "<option value=\"5\">MESH</option>"  );
      	  }
	  if ( val == 2 ) {
     	  	 return req_format_write(wp,"<option value=\"0\">AP</option>"
   	  	 "<option value=\"1\">Client </option>"
 	  	 "<option selected value=\"2\">WDS</option>"
   	  	 "<option value=\"3\">AP+WDS</option>"
   	  	 "<option value=\"4\">AP+MESH</option>"
   	  	 "<option value=\"5\">MESH</option>"  );
   	  }
	  if ( val == 3 ) {
     	  	 return req_format_write(wp,"<option value=\"0\">AP</option>"
   	  	 "<option value=\"1\">Client </option>"
 	  	 "<option  value=\"2\">WDS</option>"
   	  	 "<option selected value=\"3\">AP+WDS</option>"
   	  	 "<option value=\"4\">AP+MESH</option>"
   	  	 "<option value=\"5\">MESH</option>"  );
   	  }
   	  if ( val == 4 ) {
		 return req_format_write(wp,"<option value=\"0\">AP</option>"
   	  	 "<option value=\"1\">Client</option>"
   	  	 "<option value=\"2\">WDS</option>"
   	  	 "<option value=\"3\">AP+WDS</option>"
   	  	 "<option selected value=\"4\">AP+MESH</option>"
   	  	 "<option value=\"5\">MESH</option>"  );
   	  }
   	  if ( val == 5 ) {
		 return req_format_write(wp,"<option value=\"0\">AP</option>"
   	  	 "<option value=\"1\">Client</option>"
   	  	 "<option value=\"2\">WDS</option>"
   	  	 "<option value=\"3\">AP+WDS</option>"
   	  	 "<option value=\"4\">AP+MESH</option>"
   	  	 "<option selected value=\"5\">MESH</option>"  );
   	  }
	  else
	  return 0;

#else
  	if ( val == 0 ) {
      	  	return req_format_write(wp, "<option selected value=\"0\">AP</option>"
   	  	 "<option value=\"1\">Client</option>"
   	  	 "<option value=\"2\">WDS</option>"
   	  	 "<option value=\"3\">AP+WDS</option>"
   	  	 "<option value=\"4\">AP+MPP</option>"
   	  	 "<option value=\"5\">MPP</option>"
   	  	 "<option value=\"6\">MAP</option>"
   	  	 "<option value=\"7\">MP</option>" );
      	  }
	  if ( val == 1 ) {
     	  	 return req_format_write(wp,"<option value=\"0\">AP</option>"
   	  	 "<option selected value=\"1\">Client </option>"
   	  	 "<option value=\"2\">WDS</option>"
   	  	 "<option value=\"3\">AP+WDS</option>"
   	  	 "<option value=\"4\">AP+MPP</option>"
   	  	 "<option value=\"5\">MPP</option>"
   	  	 "<option value=\"6\">MAP</option>"
   	  	 "<option value=\"7\">MP</option>"  );
      	  }
	  if ( val == 2 ) {
     	  	 return req_format_write(wp,"<option value=\"0\">AP</option>"
   	  	 "<option value=\"1\">Client </option>"
 	  	 "<option selected value=\"2\">WDS</option>"
   	  	 "<option value=\"3\">AP+WDS</option>"
   	  	 "<option value=\"4\">AP+MPP</option>"
   	  	 "<option value=\"5\">MPP</option>"
   	  	 "<option value=\"6\">MAP</option>"
   	  	 "<option value=\"7\">MP</option>"  );
   	  }
	  if ( val == 3 ) {
     	  	 return req_format_write(wp,"<option value=\"0\">AP</option>"
   	  	 "<option value=\"1\">Client </option>"
 	  	 "<option  value=\"2\">WDS</option>"
   	  	 "<option selected value=\"3\">AP+WDS</option>"
   	  	 "<option value=\"4\">AP+MPP</option>"
   	  	 "<option value=\"5\">MPP</option>"
   	  	 "<option value=\"6\">MAP</option>"
   	  	 "<option value=\"7\">MP</option>"  );
   	  }
   	  if ( val == 4 ) {
		 return req_format_write(wp,"<option value=\"0\">AP</option>"
   	  	 "<option value=\"1\">Client</option>"
   	  	 "<option value=\"2\">WDS</option>"
   	  	 "<option value=\"3\">AP+WDS</option>"
   	  	 "<option selected value=\"4\">AP+MPP</option>"
   	  	 "<option value=\"5\">MPP</option>"
   	  	 "<option value=\"6\">MAP</option>"
   	  	 "<option value=\"7\">MP</option>"  );
   	  }
   	  if ( val == 5 ) {
		 return req_format_write(wp,"<option value=\"0\">AP</option>"
   	  	 "<option value=\"1\">Client</option>"
   	  	 "<option value=\"2\">WDS</option>"
   	  	 "<option value=\"3\">AP+WDS</option>"
   	  	 "<option value=\"4\">AP+MPP</option>"
   	  	 "<option selected value=\"5\">MPP</option>"
   	  	 "<option value=\"6\">MAP</option>"
   	  	 "<option value=\"7\">MP</option>"  );
   	  }
   	   if ( val == 6 ) {
		 return req_format_write(wp,"<option value=\"0\">AP</option>"
   	  	 "<option value=\"1\">Client</option>"
   	  	 "<option value=\"2\">WDS</option>"
   	  	 "<option value=\"3\">AP+WDS</option>"
   	  	 "<option value=\"4\">AP+MPP</option>"
   	  	 "<option value=\"5\">MPP</option>"
   	  	 "<option selected value=\"6\">MAP</option>"
   	  	 "<option value=\"7\">MP</option>"  );
   	  }
   	   if ( val == 7 ) {
		 return req_format_write(wp,"<option value=\"0\">AP</option>"
   	  	 "<option value=\"1\">Client</option>"
   	  	 "<option value=\"2\">WDS</option>"
   	  	 "<option value=\"3\">AP+WDS</option>"
   	  	 "<option value=\"4\">AP+MPP</option>"
   	  	 "<option value=\"5\">MPP</option>"
   	  	 "<option value=\"6\">MAP</option>"
   	  	 "<option selected  value=\"7\">MP</option>" );
   	}
	else
   	return 0;
#endif
#else

  	if ( val == 0 ) {
  		char tmp[300];
  		memset(tmp,0x00,sizeof(tmp));
  		sprintf(tmp,"%s","<option selected value=\"0\">AP</option>");
#if defined(CONFIG_RTL_819X) && !defined(CONFIG_WLAN_CLIENT_MODE)// keith. disabled if no this mode in 96c


#else

#if defined(CONFIG_POCKET_ROUTER_SUPPORT)
	if(opmode == BRIDGE_MODE && val == CLIENT_MODE)
	{
   		strcat(tmp,"<option value=\"1\">Client</option>");
	}
	else
	{

	}
#else
   	  strcat(tmp,"<option value=\"1\">Client</option>");
#endif //#if defined(CONFIG_POCKET_ROUTER_SUPPORT)

#endif

#if defined(CONFIG_RTL_819X) && !defined(CONFIG_WLAN_WDS_SUPPORT)// keith. disabled if no this mode in 96c
#else
   	  strcat(tmp,"<option value=\"2\">WDS</option>"
   	  	 "<option value=\"3\">AP+WDS</option>"    );
#endif

#ifdef CONFIG_RTL_P2P_SUPPORT
      SDEBUG("\n");
      if((wlanBandMode&BAND_11A)==0)    // not include 5G
   	  strcat(tmp,"<option value=\"8\">P2P</option> ");
#endif
      return req_format_write(wp,tmp);
      	  }

	  if ( val == 1 ) {
	  	char tmp[300];
  		memset(tmp,0x00,sizeof(tmp));
  		sprintf(tmp,"%s","<option value=\"0\">AP</option>");
#if defined(CONFIG_RTL_819X) && !defined(CONFIG_WLAN_CLIENT_MODE)// keith. disabled if no this mode in 96c
#else
   	  strcat(tmp,"<option selected value=\"1\">Client</option>");
#endif

#if defined(CONFIG_RTL_819X) && !defined(CONFIG_WLAN_WDS_SUPPORT)// keith. disabled if no this mode in 96c
#else
   	  strcat(tmp,"<option value=\"2\">WDS</option>"
   	  	 "<option value=\"3\">AP+WDS</option>"     );
#endif
#ifdef CONFIG_RTL_P2P_SUPPORT
      SDEBUG("\n");
      if((wlanBandMode&BAND_11A)==0)    // not include 5G
   	  strcat(tmp,"<option value=\"8\">P2P</option> ");
#endif

      return req_format_write(wp,tmp);
      	  }

	  if ( val == 2 ) {
		char tmp[300];
  		memset(tmp,0x00,sizeof(tmp));
  		sprintf(tmp,"%s","<option value=\"0\">AP</option>");
#if defined(CONFIG_RTL_819X) && !defined(CONFIG_WLAN_CLIENT_MODE)// keith. disabled if no this mode in 96c
#else

#if defined(CONFIG_POCKET_ROUTER_SUPPORT)
	if(opmode == BRIDGE_MODE && val == CLIENT_MODE)
	{
   	  strcat(tmp,"<option value=\"1\">Client</option>");
	}
	else
	{

	}
#else
	strcat(tmp,"<option value=\"1\">Client</option>");
#endif //#if defined(CONFIG_POCKET_ROUTER_SUPPORT)

#endif

#if defined(CONFIG_RTL_819X) && !defined(CONFIG_WLAN_WDS_SUPPORT)// keith. disabled if no this mode in 96c
#else
   	  strcat(tmp,"<option selected value=\"2\">WDS</option>"
   	  	 "<option value=\"3\">AP+WDS</option>"    );
#endif
#ifdef CONFIG_RTL_P2P_SUPPORT
      SDEBUG("\n");
      if((wlanBandMode&BAND_11A)==0)    // not include 5G
   	  strcat(tmp,"<option value=\"8\">P2P</option> ");
#endif
      return req_format_write(wp,tmp);
   	  }
	  if ( val == 3 ) {
		char tmp[300];
  		memset(tmp,0x00,sizeof(tmp));
  		sprintf(tmp,"%s","<option value=\"0\">AP</option>");
#if defined(CONFIG_RTL_819X) && !defined(CONFIG_WLAN_CLIENT_MODE)// keith. disabled if no this mode in 96c
#else

#if defined(CONFIG_POCKET_ROUTER_SUPPORT)
	if(opmode == BRIDGE_MODE && val == CLIENT_MODE)
	{
   	  strcat(tmp,"<option value=\"1\">Client</option>");
	}
	else
	{

	}
#else
	strcat(tmp,"<option value=\"1\">Client</option>");
#endif //#if defined(CONFIG_POCKET_ROUTER_SUPPORT)

#endif

#if defined(CONFIG_RTL_819X) && !defined(CONFIG_WLAN_WDS_SUPPORT)// keith. disabled if no this mode in 96c
#else
   	  strcat(tmp,"<option value=\"2\">WDS</option>"
   	  	 "<option selected value=\"3\">AP+WDS</option>"   );
#endif
#ifdef CONFIG_RTL_P2P_SUPPORT
      SDEBUG("\n");
      if((wlanBandMode&BAND_11A)==0)    // not include 5G
   	  strcat(tmp,"<option value=\"8\">P2P</option> ");
#endif
      return req_format_write(wp,tmp);
   	  }
#ifdef CONFIG_RTL_P2P_SUPPORT
	  if ( val == 8 ) {
		char tmp[300];
  		memset(tmp,0x00,sizeof(tmp));
  		sprintf(tmp,"%s","<option value=\"0\">AP</option>");
#if defined(CONFIG_RTL_819X) && !defined(CONFIG_WLAN_CLIENT_MODE)// keith. disabled if no this mode in 96c
#else

#if defined(CONFIG_POCKET_ROUTER_SUPPORT)
	if(opmode == BRIDGE_MODE && val == CLIENT_MODE)
	{
   	  strcat(tmp,"<option value=\"1\">Client</option>");
	}
	else
	{

	}
#else
	strcat(tmp,"<option value=\"1\">Client</option>");
#endif //#if defined(CONFIG_POCKET_ROUTER_SUPPORT)

#endif

#if defined(CONFIG_RTL_819X) && !defined(CONFIG_WLAN_WDS_SUPPORT)// keith. disabled if no this mode in 96c
#else
   	  strcat(tmp,"<option value=\"2\">WDS</option>"
   	  	 "<option value=\"3\">AP+WDS</option>"   );
#endif
      SDEBUG("\n");
      if((wlanBandMode&BAND_11A)==0)    // not include 5G
   	  strcat(tmp,"<option selected value=\"8\">P2P</option> ");

      return req_format_write(wp,tmp);
   	  }
#endif
	  else
   	  	return 0;
#endif
}

#ifdef __DAVO__
/* argv[0] - interface name
 * argv[1] - field name
 */
int get_wlan_traffic(request *wp, int argc, char **argv)
{
	FILE *f;
	char buf[80], *args[4];
	char *p = "0";

	if (argc >= 2) {
		snprintf(buf, sizeof(buf), "/proc/%s/stats", argv[0] ? : "");
		f = fopen(buf, "r");
		if (f != NULL) {
			while (fgets(buf, sizeof(buf), f)) {
				if (ystrargs(buf, args, _countof(args), ":", 0) &&
				    strcmp(args[0], argv[1]) == 0) {
					p = args[1] ? : "0";
					break;
				}
			}
			fclose(f);
		}
	}
	return req_format_write(wp, "%lu", strtoul(p, NULL, 0));
}
#endif
