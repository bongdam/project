/*
 *      Utiltiy function for setting firewall filter
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <memory.h>
#include <signal.h>
#include <arpa/inet.h>

#include <sys/stat.h>
#include <bcmnvram.h>

#include "apmib.h"
#include "sysconf.h"
#include "sys_utility.h"


#ifdef __DAVO__
#include "libytool.h"
#include "custom.h"
#endif


#ifdef CONFIG_RTK_VOIP
#include "voip_manager.h"
#endif
#define CONFIG_REFINE_BR_FW_RULE 1	//for smartbit performance
int setFirewallIptablesRules(int argc, char** argv);
char Iptables[]="iptables";
#if defined(CONFIG_APP_EBTABLES)&&defined(CONFIG_EBTABLES_KERNEL_SUPPORT)
char Ebtables[]="ebtables";
#endif
char Ip6tables[]="ip6tables";
char INPUT[]= "INPUT";
char OUTPUT[]= "OUTPUT";
char FORWARD[]= "FORWARD";
char PREROUTING[]="PREROUTING";
char POSTROUTING[]= "POSTROUTING";
char ACCEPT[]= "ACCEPT";
char DROP[]= "DROP";
char RET[]= "RETURN";
//char LOG[]= "LOG";
char MASQUERADE[]="MASQUERADE";
char REDIRECT[]="REDIRECT";
char MARK[]="MARK";
// iptables operations, manupilations, matches, options etc.
char ADD[]= "-A";
char DEL[]= "-D";
char FLUSH[]= "-F";
char INSERT[]="-I";
char NEW[]= "-N";
char POLICY[]= "-P";
char X[]= "-X";
char Z[]= "-Z";
char _dest[]= "-d";
char in[]= "-i";
char jump[]= "-j";
char match[]= "-m";
char out[]= "-o";
char _protocol[]= "-p";
char _src[]= "-s";
char _table[]= "-t";
char nat_table[]= "nat";
char mangle_table[]= "mangle";
char NOT[]= "!";
char _mac[]= "mac";
char mac_src[]= "--mac-source";
char mac_dst[]= "--mac-destination";
char dport[]= "--dport";
char sport[]= "--sport";
char syn[]= "--syn";
char ALL[]= "ALL";
char DNAT[]= "DNAT";
char icmp_type[]="--icmp-type";
char echo_request[]="echo-request";
char echo_reply[]="echo-reply";
char mstate[]="state";
char state[]="--state";
char _udp[]="udp";
char _tcp[]="tcp";
char _icmp[]="icmp";
char RELATED_ESTABLISHED[]= "RELATED,ESTABLISHED";
char INVALID[]="INVALID";
char tcp_flags[]="--tcp-flags";
char MSS_FLAG1[]="SYN,RST";
char MSS_FLAG2[]="SYN";
char clamp[]="--clamp-mss-to-pmtu";
char TCPMSS[]="TCPMSS";
char ip_range[]="iprange";
char src_rnage[]="--src-range";
char dst_rnage[]="--dst-range";
char set_mark[]="--set-mark";

static const char _tc[] = "tc";
static const char _qdisc[] = "qdisc";
static const char _add[] = "add";
static const char _dev[] = "dev";
static const char _root[] = "root";
static const char _handle[] = "handle";
static const char _htb[] = "htb";
static const char _default[] = "default";
static const char _classid[] = "classid";
static const char _rate[] = "rate";
static const char _ceil[] = "ceil";
static const char _sfq[] = "sfq";
static const char _perturb[] = "perturb";
static const char _class[] = "class";
static const char _filter[] = "filter";
static const char _protocol2[] = "protocol";
static const char _ip[] = "ip";
static const char _prio[] = "prio";
static const char _fw[] = "fw";
static const char _parent[] = "parent";
static const char _quantum[] = "quantum";
static const char _r2q[] = "r2q";

#ifdef MULTI_PPPOE
//#define MULTI_PPP_DEBUG

struct PPP_info
{
	char client_ip[20];
	char server_ip[20];
	char ppp_name[5];
	int order;
};
/*
struct subNet
{
	int SubnetCount;
	unsigned char startip[3][20];
	unsigned char endip[3][20];
};*/


char SubNet[4][30];
char flushCmds[12][80];
int CmdCount = 0 ;


//struct subNet SubNets[4];
//br0_info
int pppNumbers = 0;
int info_setting = 0;
struct PPP_info infos[5];
char Br0NetSectAddr[30];
//lan partition info
char  lan_ip[4][40] ;

int get_info()
{
	int subCount;
	unsigned char buffer[30];
	int connectNumber,index = -1;
	FILE *local,*remote,*order,*number,*br0,*pF,*pdev;
	if((local=fopen("/etc/ppp/ppp_local","r+"))==NULL)
	{
		printf("Cannot open this file\n");
		return 0;
	}
	if((remote=fopen("/etc/ppp/ppp_remote","r+"))==NULL)
	{
		printf("Cannot open this file\n");
		return 0;
	}

	if((order=fopen("/etc/ppp/ppp_order_info","r+"))==NULL)
	{
		printf("Cannot open this file\n");
		return 0;
	}

	if((number=fopen("/etc/ppp/lineNumber","r+"))==NULL)
	{
		printf("Cannot open this file\n");
		return 0;
	}
	if((br0=fopen("/etc/ppp/br0_info","r+"))==NULL)
	{
		printf("Cannot open this file\n");
		return 0;
	}
	if((pdev=fopen("/etc/ppp/ppp_device","r+"))==NULL)
	{
		printf("Cannot open this file\n");
		return 0;
	}

	close(order);
	fscanf(br0,"%s",Br0NetSectAddr);
	fscanf(number,"%d",&pppNumbers);

	for( index = 0 ; index < pppNumbers ; ++index)
	{
		int num,i,j;
		char name[5];
		char devname[5];

		fscanf(local,"%s",infos[index].client_ip);
		fscanf(remote,"%s",infos[index].server_ip);
		fscanf(pdev,"%s",devname);
		if((order=fopen("/etc/ppp/ppp_order_info","r+"))==NULL)
			return ;
		while(fscanf(order,"%d--%s",&num,name) > 0 )
		{
#ifdef MULTI_PPP_DEBUG
			printf("devname value is:%s\n",devname);
			printf("name value is:%s\n",name);
			printf("num value is:%d\n",num);
#endif
			if(!strcmp(devname,name))
			{
				infos[index].order = num;
				strcpy(infos[index].ppp_name,devname);
#ifdef MULTI_PPP_DEBUG
				printf("infos[index].order value is:%d\n",infos[index].order);
				printf("infos[index].ppp_name value is:%s\n",infos[index].ppp_name);
#endif
				break;
			}
		}
		fclose(order);
	}
	fclose(local);
	fclose(remote);
	fclose(number);
	fclose(br0);
	fclose(pdev);
	//get the subnet info
	if((pF = fopen("/etc/ppp/ppp_connect_number","r"))==NULL)
	{
		printf("can't open the file\n");
		return 0;
	}
	fscanf(pF,"%d",&connectNumber);		//max value is 4
	fclose(pF);

	//apmib_get( MIB_SUBNET1_F1_START,  (void *)buffer);
	//printf("test-------------%s\n",inet_ntoa(*((struct in_addr *)buffer)));
	if(connectNumber >= 1)
	{
		apmib_get(MIB_PPP_SUBNET1,(void *)buffer);
		strcpy(SubNet[0],buffer);

/*
		apmib_get(MIB_SUBNET1_COUNT, (void *)&subCount);
		SubNets[0].SubnetCount = subCount;
		if(subCount >= 1)
		{
			apmib_get(MIB_SUBNET1_F1_START,(void *)buffer);
			strcpy(SubNets[0].startip[0],inet_ntoa(*((struct in_addr *)buffer)));
			apmib_get(MIB_SUBNET1_F1_END, (void *)buffer);
			strcpy(SubNets[0].endip[0],inet_ntoa(*((struct in_addr *)buffer)));
		}
		if(subCount >= 2)
		{
			apmib_get(MIB_SUBNET1_F2_START,(void *)buffer);
			strcpy(SubNets[0].startip[1],inet_ntoa(*((struct in_addr *)buffer)));
			apmib_get(MIB_SUBNET1_F2_END, (void *)buffer);
			strcpy(SubNets[0].endip[1],inet_ntoa(*((struct in_addr *)buffer)));
		}
		if(subCount >= 3)
		{
			apmib_get(MIB_SUBNET1_F3_START,(void *)buffer);
			strcpy(SubNets[0].startip[2],inet_ntoa(*((struct in_addr *)buffer)));
			apmib_get(MIB_SUBNET1_F3_END, (void *)buffer);
			strcpy(SubNets[0].endip[2],inet_ntoa(*((struct in_addr *)buffer)));
		}
*/
	}
	if(connectNumber >= 2)
	{
		apmib_get(MIB_PPP_SUBNET2,(void *)buffer);
		strcpy(SubNet[1],buffer);

/*
		apmib_get(MIB_SUBNET2_COUNT, (void *)&subCount);
		SubNets[1].SubnetCount = subCount;
		if(subCount >= 1)
		{
			apmib_get(MIB_SUBNET2_F1_START,(void *)buffer);
			strcpy(SubNets[1].startip[0],inet_ntoa(*((struct in_addr *)buffer)));
			apmib_get(MIB_SUBNET2_F1_END, (void *)buffer);
			strcpy(SubNets[1].endip[0],inet_ntoa(*((struct in_addr *)buffer)));
		}
		if(subCount >= 2)
		{
			apmib_get(MIB_SUBNET2_F2_START,(void *)buffer);
			strcpy(SubNets[1].startip[1],inet_ntoa(*((struct in_addr *)buffer)));
			apmib_get(MIB_SUBNET2_F2_END, (void *)buffer);
			strcpy(SubNets[1].endip[1],inet_ntoa(*((struct in_addr *)buffer)));
		}
		if(subCount >= 3)
		{
			apmib_get(MIB_SUBNET2_F3_START,(void *)buffer);
			strcpy(SubNets[1].startip[2],inet_ntoa(*((struct in_addr *)buffer)));
			apmib_get(MIB_SUBNET2_F3_END, (void *)buffer);
			strcpy(SubNets[1].endip[2],inet_ntoa(*((struct in_addr *)buffer)));
		}
*/
	}
	if(connectNumber >= 3)
	{
		apmib_get(MIB_PPP_SUBNET3,(void *)buffer);
		strcpy(SubNet[2],buffer);
/*
		apmib_get(MIB_SUBNET3_COUNT, (void *)&subCount);
		SubNets[2].SubnetCount = subCount;
		if(subCount >= 1)
		{
			apmib_get(MIB_SUBNET3_F1_START,(void *)buffer);
			strcpy(SubNets[2].startip[0],inet_ntoa(*((struct in_addr *)buffer)));
			apmib_get(MIB_SUBNET3_F1_END, (void *)buffer);
			strcpy(SubNets[2].endip[0],inet_ntoa(*((struct in_addr *)buffer)));
		}
		if(subCount >= 2)
		{
			apmib_get(MIB_SUBNET3_F2_START,(void *)buffer);
			strcpy(SubNets[2].startip[1],inet_ntoa(*((struct in_addr *)buffer)));
			apmib_get(MIB_SUBNET3_F2_END, (void *)buffer);
			strcpy(SubNets[2].endip[1],inet_ntoa(*((struct in_addr *)buffer)));
		}
		if(subCount >= 3)
		{
			apmib_get(MIB_SUBNET3_F3_START,(void *)buffer);
			strcpy(SubNets[2].startip[2],inet_ntoa(*((struct in_addr *)buffer)));
			apmib_get(MIB_SUBNET3_F3_END, (void *)buffer);
			strcpy(SubNets[2].endip[2],inet_ntoa(*((struct in_addr *)buffer)));
		}
*/

	}
	if(connectNumber >= 4)
	{
		apmib_get(MIB_PPP_SUBNET4,(void *)buffer);
		strcpy(SubNet[3],buffer);

/*
		apmib_get(MIB_SUBNET4_COUNT, (void *)&subCount);
		SubNets[3].SubnetCount = subCount;
		if(subCount >= 1)
		{
			apmib_get(MIB_SUBNET4_F1_START,(void *)buffer);
			strcpy(SubNets[3].startip[0],inet_ntoa(*((struct in_addr *)buffer)));
			apmib_get(MIB_SUBNET4_F1_END, (void *)buffer);
			strcpy(SubNets[3].endip[0],inet_ntoa(*((struct in_addr *)buffer)));
		}
		if(subCount >= 2)
		{
			apmib_get(MIB_SUBNET4_F2_START,(void *)buffer);
			strcpy(SubNets[3].startip[1],inet_ntoa(*((struct in_addr *)buffer)));
			apmib_get(MIB_SUBNET4_F2_END, (void *)buffer);
			strcpy(SubNets[3].endip[1],inet_ntoa(*((struct in_addr *)buffer)));
		}
		if(subCount >= 3)
		{
			apmib_get(MIB_SUBNET4_F3_START,(void *)buffer);
			strcpy(SubNets[3].startip[2],inet_ntoa(*((struct in_addr *)buffer)));
			apmib_get(MIB_SUBNET4_F3_END, (void *)buffer);
			strcpy(SubNets[3].endip[2],inet_ntoa(*((struct in_addr *)buffer)));
		}
*/
	}
	return 1;
}
void 	print_info()
{
	int index;
	int sub_index;
	int sub_number;
	for(index = 0 ; index < 4 ; ++index)
	{
		/*
		sub_number = SubNets[index].SubnetCount;

		for(sub_index = 0 ;sub_index< sub_number;++sub_index)
		{
			printf("the %d subnet  is:%s\n",sub_index+1);
			printf("the value of startip is:%s\n",SubNets[index].startip[sub_index]);
			printf("the value of endip is:%s\n",SubNets[index].endip[sub_index]);
		}
		printf("--------------------------------------------------------\n");
		*/
	}
}
#endif
extern int apmib_initialized;
extern int getInAddr( char *interface, int type, void *pAddr );
extern int isFileExist(char *file_name);

#ifdef CONFIG_SMART_REPEATER
extern int getWispRptIfaceName(char*pIface,int wlanId);
#endif

#define accept(cond)        ((cond) ? "ACCEPT" : "DROP")
#define drop(cond)        ((cond) ?  "DROP" : "ACCEPT")

#ifdef CONFIG_RTL_HW_NAPT
int update_hwnat_setting();
#endif


#ifdef CONFIG_APP_TR069
extern char acsURLStr[];
#endif //#ifdef CONFIG_APP_TR069

static const char **proto_list(int type)
{
	static const char *udp[] = { "udp", NULL };
	static const char *tcp[] = { "tcp", NULL };
	static const char *tcp_udp[] = { "tcp", "udp", NULL };
	static const char *none[] = { NULL };

	switch (type) {
	case PROTO_TCP:
		return tcp;
	case PROTO_UDP:
		return udp;
    case PROTO_BOTH:
		return tcp_udp;
	default:
		return none;
	}
}

static int put_acl_chain(void)
{
	char nip[30], mask[30];
	int opmode = -1;

	nvram_get_r("IP_ADDR", nip, sizeof(nip));
	nvram_get_r("SUBNET_MASK", mask, sizeof(mask));
	apmib_get(MIB_OP_MODE, (void *)&opmode);

	/* APACRTL-84  smlee 20151029 */
	if (get_repeater_mode() || (opmode == BRIDGE_MODE)) {
		char wanip[64], netmask[64];
		if (yfcat("/var/wan_ip", "%s", wanip) > 0) {
			if (yfcat("/var/netmask", "%s", netmask) > 0) {
				yexecl(NULL, "iptables -I ACL --source %s/%s -p tcp --dport 8080 -j ACCEPT", wanip, netmask);
			}
		}
	}
	yexecl(NULL, "iptables -I ACL --source %s/%s -j ACCEPT", nip, mask);
	yexecl(NULL, "iptables -I ACL --source 210.94.1.0/24 -j ACCEPT");		/* SK public IP*/
	yexecl(NULL, "iptables -I ACL --source 219.248.49.64/26 -j ACCEPT");	/* swms */
	yexecl(NULL, "iptables -I ACL --source 175.122.253.0/24 -j ACCEPT");	/* swms */
	yexecl(NULL, "iptables -I ACL --source 211.234.248.196 -j ACCEPT");		/* SK WIFI SCAN */
	yexecl(NULL, "iptables -I ACL --source 220.120.246.192/26 -j ACCEPT");	/* davo public IP*/
	yexecl(NULL, "iptables -I ACL --source 203.239.46.0/24 -j ACCEPT");		/* hfr public IP*/
	yexecl(NULL, "iptables -I ACL --source 118.36.215.0/24 -j ACCEPT");
	yexecl(NULL, "iptables -I ACL --source 203.236.3.245 -j ACCEPT");		/* 2020-04-22 Required IP */
	yexecl(NULL, "iptables -A ACL -j DROP");

    return 0;
}

#ifdef CONFIG_RTK_VOIP
int set_voip_parameter(char* pInterface){

	#ifdef CONFIG_RTL_HW_NAPT
	unsigned long	dos_enabled = 0;
	int intVal=0;
	int intVal_num=0;
	#endif
#ifdef SLIC_CH_NUM  // old design
	const int total_voip_ports = SLIC_CH_NUM + DECT_CH_NUM + DAA_CH_NUM;
#else
	const int total_voip_ports = g_VoIP_Ports;
#endif
	char rtp_port[20]={0};
	char sip_port[10]={0};
	int index;
	#ifdef CONFIG_RTL_HARDWARE_NAT
	int ivalue = 0;
	#endif
	voipCfgParam_t  voipCfgParam;


	//printf("int set_voip_parameter....\n");
	apmib_get(MIB_VOIP_CFG, (void*)&voipCfgParam);


	for(index = 0; index < total_voip_ports; index++){
		//iptables -A INPUT -i eth1 -p udp --dport 5060 -j ACCEPT
		sprintf(sip_port,"%d", voipCfgParam.ports[index].sip_port);
		RunSystemCmd(NULL_FILE, Iptables, ADD, INPUT, in, pInterface, _protocol, _udp, dport,sip_port ,jump,ACCEPT, NULL_STR);

		// iptables -I PREROUTING -t nat -i eth1 -p udp --dport 5060 -j ACCEPT
		RunSystemCmd(NULL_FILE, Iptables, INSERT, PREROUTING, _table, nat_table , in, pInterface, _protocol, _udp, dport,sip_port ,jump,ACCEPT, NULL_STR);

		sprintf(rtp_port,"%d:%d",voipCfgParam.ports[index].media_port,voipCfgParam.ports[index].media_port+3);
		//iptables -I PREROUTING -t nat -i eth1 -p udp --dport 9000:9003 -j ACCEPT
		RunSystemCmd(NULL_FILE, Iptables, INSERT, PREROUTING, _table, nat_table , in, pInterface, _protocol, _udp, dport, rtp_port ,jump,ACCEPT, NULL_STR);
	}


	#if 0
	def CONFIG_RTL_HW_NAPT
	apmib_get(MIB_URLFILTER_ENABLED,  (void *)&intVal);
	apmib_get(MIB_URLFILTER_TBL_NUM,  (void *)&intVal_num);
	apmib_get(MIB_DOS_ENABLED, (void *)&dos_enabled);
		apmib_get(MIB_SUBNET_MASK,(void*)&ivalue);

	//when dos or urlfilter is enable, hwnat must be turn off!
	if((intVal !=0 && intVal_num>0)||(dos_enabled > 0)||(!voipCfgParam.hwnat_enable))
			RunSystemCmd("/proc/hw_nat", "echo", "0", NULL_STR);
	else if(voipCfgParam.hwnat_enable)
		{
			if((ivalue&HW_NAT_LIMIT_NETMASK)!=HW_NAT_LIMIT_NETMASK)
				RunSystemCmd("/proc/hw_nat", "echo", "0", NULL_STR);
			else
				RunSystemCmd("/proc/hw_nat", "echo", "1", NULL_STR);
		}
	#endif
}
#endif

#ifdef MULTI_PPPOE
int set_QoS(int operation, int wan_type, int wisp_wan_id , char* interface)
#else
int set_QoS(int operation, int wan_type, int wisp_wan_id)
#endif
{

#ifdef __DAVO__
	/* jihyun@davo150602 jcode#0 */
	char buf[32];
	FILE *f;

	nvram_get_r_def("x_DV_QOS_DISABLE", buf, sizeof(buf), "0");
	if (strtol(buf, NULL, 10) == 0L) {
		f = locked_fopen("/var/.qoslock", "w", 1);
		if (f)
			fprintf(f, "applied\n");
		yexecl(NULL, "dvqos --apply");
		locked_fclose(f);
	}
	//
#else
#ifdef   HOME_GATEWAY
	char *br_interface="br0";
	char tmp_args[32]={0}, tmp_args1[32]={0}, tmp_args2[32]={0};
	char tmp_args3[64]={0}, tmp_args4[32]={0};
	char *tmpStr=NULL;
	int wan_pkt_mark=13, lan_pkt_mark=53;
	char iface[20], *pInterface="eth1", *pInterface2=NULL;
	int i, QoS_Enabled=0;
	int QoS_Auto_Uplink=0, QoS_Manual_Uplink=0;
	int QoS_Auto_Downlink=0, QoS_Manual_Downlink=0;
	int QoS_Rule_EntryNum=0;
	char PROC_QOS[128]={0};
	int uplink_speed=102400, downlink_speed=102400;
	IPQOS_T entry;
	int get_wanip=0;
	struct in_addr wanaddr;
	unsigned char str_l7_filter[128]={0};

	int needSetOnce = 1;
//#define QOS_MAC_U32_FILTER 1
#ifdef QOS_MAC_U32_FILTER
	unsigned char macAddr[64]={0};
#endif
#if defined (CONFIG_RTL_8198)|| defined (CONFIG_RTL_8198C)
	uplink_speed=1024000;
	downlink_speed=1024000;
#endif

#ifdef MULTI_PPPOE
	if(!strncmp(interface,"ppp0",3) ||!strncmp(interface,"ppp1",3) || !strncmp(interface,"ppp2",3)
				|| !strncmp(interface,"ppp3",3))
	{
		FILE* fp;
		int pppDeviceNumber;
		if((fp=fopen("/etc/ppp/hasPppoedevice","r+"))==NULL)
		{
#ifdef MULTI_PPP_DEBUG
			printf("Cannot open this file\n");
#endif
			return 0;
		}
		fscanf(fp,"%d",&pppDeviceNumber);
		if(pppDeviceNumber == 1)
			needSetOnce = 1;
		else if( pppDeviceNumber >=2)
			needSetOnce = 0;
	}
#endif
#ifdef MULTI_PPPOE
		if(needSetOnce){
#endif
	RunSystemCmd(NULL_FILE, Iptables, FLUSH, _table, mangle_table, NULL_STR);
	RunSystemCmd(NULL_FILE, Iptables, X, _table, mangle_table, NULL_STR);
	RunSystemCmd(NULL_FILE, Iptables, Z, _table, mangle_table, NULL_STR);
#ifdef MULTI_PPPOE
		}
#endif
	if(operation == WISP_MODE){
		sprintf(iface, "wlan%d", wisp_wan_id);
#if defined(CONFIG_SMART_REPEATER)
		getWispRptIfaceName(iface,wisp_wan_id);
		//strcat(iface, "-vxd");
#endif
		pInterface = iface;
		if (wan_type == PPPOE || wan_type == PPTP /*|| wan_type == L2TP */)
#ifdef MULTI_PPPOE
			pInterface = interface;
#else
			pInterface="ppp0";
#endif
	}else{
		if(operation == GATEWAY_MODE){
			if (wan_type == PPPOE || wan_type == PPTP || wan_type == USB3G /*|| wan_type == L2TP*/)
#ifdef MULTI_PPPOE
			pInterface = interface;
#else
			pInterface="ppp0";
#endif
		} else if (operation == BRIDGE_MODE) {
			pInterface = "br0";
		}
	}

	if(wan_type == L2TP)//wantype is l2tp
		pInterface2="ppp0";

	get_wanip = getInAddr(pInterface, IP_ADDR_T, (void *)&wanaddr);
	if( get_wanip ==0){   //get wan ip fail
		printf("No wan ip currently!\n");
		return 0;
	}

	apmib_get( MIB_QOS_ENABLED, (void *)&QoS_Enabled);
	apmib_get( MIB_QOS_AUTO_UPLINK_SPEED, (void *)&QoS_Auto_Uplink);
	apmib_get( MIB_QOS_MANUAL_UPLINK_SPEED, (void *)&QoS_Manual_Uplink);
	apmib_get( MIB_QOS_MANUAL_DOWNLINK_SPEED, (void *)&QoS_Manual_Downlink);
	apmib_get( MIB_QOS_AUTO_DOWNLINK_SPEED, (void *)&QoS_Auto_Downlink);
	apmib_get( MIB_QOS_RULE_TBL_NUM, (void *)&QoS_Rule_EntryNum);

	RunSystemCmd(NULL_FILE, "tc", "qdisc", "del", "dev", br_interface, "root", NULL_STR);

	//To avoid rule left when wan changed
	RunSystemCmd(NULL_FILE, "tc", "qdisc", "del", "dev", pInterface, "root", NULL_STR);
	RunSystemCmd(NULL_FILE, "tc", "qdisc", "del", "dev", "ppp0", "root", NULL_STR);

	if((strcmp(pInterface, "eth1")!=0)&&(strcmp(pInterface, "ppp0")!=0))
		RunSystemCmd(NULL_FILE, "tc", "qdisc", "del", "dev", pInterface, "root", NULL_STR);

#ifdef MULTI_PPPOE
	if(needSetOnce){
#endif
	sprintf(PROC_QOS, "%s", "0,");

	if(QoS_Enabled==1){
		sprintf(PROC_QOS, "%s", "1,");
	}

	// echo /proc/qos should before tc rules because of qos patch (CONFIG_RTL_QOS_PATCH in kernel)
	RunSystemCmd("/proc/qos", "echo", PROC_QOS, NULL_STR);
#ifdef MULTI_PPPOE
		}
#endif

	if(QoS_Enabled==1){
		if(QoS_Auto_Uplink==0){
			uplink_speed=QoS_Manual_Uplink;
			if(uplink_speed < 100)
				uplink_speed=100;
		}

		// patch for uplink QoS accuracy
#if 0
#ifdef CONFIG_RTL_8198
		if(uplink_speed > 160000)
			uplink_speed=160000;
#else
		if(uplink_speed > 75000)
			uplink_speed=75000;
#endif
#endif

		if(QoS_Auto_Downlink==0){
			downlink_speed=QoS_Manual_Downlink;
			if(downlink_speed < 100)
				downlink_speed=100;
		}
		// patch for downlink QoS accuracy
#if 0
#ifdef CONFIG_RTL_8198
		if(downlink_speed > 130000)
			downlink_speed=130000;
#else
		if(downlink_speed > 70000)
			downlink_speed=70000;
#endif
#endif

		/* total bandwidth section--uplink*/
		RunSystemCmd(NULL_FILE, _tc, _qdisc, _add, _dev, pInterface, _root, _handle, "2:0", _htb, _default, "2", _r2q, "64", NULL_STR);
		//tc qdisc add dev $WAN root handle 2:0 htb default 2 r2q 64
		sprintf(tmp_args, "%dkbit", uplink_speed);
		RunSystemCmd(NULL_FILE, _tc, _class, _add, _dev, pInterface, _parent, "2:0", _classid, "2:1", _htb, _rate, tmp_args, _ceil, tmp_args,  _quantum, "30000", NULL_STR);
		//TC_CMD="tc class add dev $WAN parent 2:0 classid 2:1 htb rate ${UPLINK_SPEED}kbit ceil ${UPLINK_SPEED}kbit"
		RunSystemCmd(NULL_FILE, _tc, _class, _add, _dev, pInterface, _parent, "2:1", _classid, "2:2", _htb, _rate, "1kbit", _ceil, tmp_args, _prio, "256",  _quantum, "30000", NULL_STR);
    		//TC_CMD="tc class add dev $WAN parent 2:1 classid 2:2 htb rate 1kbit ceil ${UPLINK_SPEED}kbit prio 256 quantum 30000"
    		RunSystemCmd(NULL_FILE, _tc, _qdisc, _add, _dev, pInterface, _parent, "2:2", _handle, "102:", _sfq, _perturb, "10", NULL_STR);
    		//TC_CMD="tc qdisc add dev $WAN parent 2:2 handle 102: sfq perturb 10"

#if 1
		if((pInterface2!=NULL)&&strcmp(pInterface2, "ppp0")==0)//wantype is l2tp
		{
			RunSystemCmd(NULL_FILE, _tc, _qdisc, _add, _dev, pInterface2, _root, _handle, "3:0", _htb, _default, "2", _r2q, "64", NULL_STR);
			//tc qdisc add dev $WAN2 root handle 3:0 htb default 2 r2q 64
			sprintf(tmp_args, "%dkbit", uplink_speed);
			RunSystemCmd(NULL_FILE, _tc, _class, _add, _dev, pInterface2, _parent, "3:0", _classid, "3:1", _htb, _rate, tmp_args, _ceil, tmp_args,  _quantum, "30000", NULL_STR);
			//TC_CMD="tc class add dev $WAN2 parent 3:0 classid 3:1 htb rate ${UPLINK_SPEED}kbit ceil ${UPLINK_SPEED}kbit"
			RunSystemCmd(NULL_FILE, _tc, _class, _add, _dev, pInterface2, _parent, "3:1", _classid, "3:2", _htb, _rate, "1kbit", _ceil, tmp_args, _prio, "256",  _quantum, "30000", NULL_STR);
	    		//TC_CMD="tc class add dev $WAN2 parent 3:1 classid 3:2 htb rate 1kbit ceil ${UPLINK_SPEED}kbit prio 256 quantum 30000"
	    		RunSystemCmd(NULL_FILE, _tc, _qdisc, _add, _dev, pInterface2, _parent, "3:2", _handle, "302:", _sfq, _perturb, "10", NULL_STR);
	    		//TC_CMD="tc qdisc add dev $WAN2 parent 3:2 handle 302: sfq perturb 10"
		}
#endif
#ifdef MULTI_PPPOE
			if(needSetOnce){
#endif

		/* total bandwidth section--downlink*/
    		RunSystemCmd(NULL_FILE, _tc, _qdisc, _add, _dev, br_interface, _root, _handle, "5:0", _htb, _default, "2", _r2q, "64",NULL_STR);
    		//tc qdisc add dev $BRIDGE root handle 5:0 htb default 5 r2q 64
    		sprintf(tmp_args, "%dkbit", downlink_speed);
    		RunSystemCmd(NULL_FILE, _tc, _class, _add, _dev, br_interface, _parent, "5:0", _classid, "5:1", _htb, _rate, tmp_args, _ceil, tmp_args,  _quantum, "30000", NULL_STR);
    		//TC_CMD="tc class add dev $BRIDGE parent 5:0 classid 5:1 htb rate ${DOWNLINK_SPEED}kbit ceil ${DOWNLINK_SPEED}kbit"
    		RunSystemCmd(NULL_FILE, _tc, _class, _add, _dev, br_interface, _parent, "5:1", _classid, "5:2", _htb, _rate, "1kbit", _ceil, tmp_args, _prio, "256", _quantum, "30000", NULL_STR);
		//TC_CMD="tc class add dev $BRIDGE parent 5:1 classid 5:5 htb rate 1kbit ceil ${DOWNLINK_SPEED}kbit prio 256 quantum 30000"
		RunSystemCmd(NULL_FILE, _tc, _qdisc, _add, _dev, br_interface, _parent, "5:2", _handle, "502:", _sfq, _perturb, "10", NULL_STR);
		//TC_CMD="tc qdisc add dev $BRIDGE parent 5:5 handle 502: sfq perturb 10"
//		sprintf(PROC_QOS, "%s", "1,");
#ifdef MULTI_PPPOE
		}
#endif

		if(QoS_Rule_EntryNum > 0){
			for (i=1; i<=QoS_Rule_EntryNum; i++) {
				unsigned char command[200]={0};
				*((char *)&entry) = (char)i;
				apmib_get(MIB_QOS_RULE_TBL, (void *)&entry);
				if(entry.enabled > 0){
					if(entry.bandwidth > 0){/*UPlink*/
						sprintf(tmp_args, "%d", wan_pkt_mark);

						if((strcmp(entry.l7_protocol,"") == 0) || (strcmp(entry.l7_protocol,"Disable") == 0))
						{
							sprintf(str_l7_filter,"%s","");
						}
						else
						{
							sprintf(str_l7_filter,"%s %s","-m layer7 --l7proto ", entry.l7_protocol);
						}

						if(entry.mode & QOS_RESTRICT_IP)//if(entry.mode == 5 || entry.mode == 6){
						{
							/*this qos rule is set by IP address*/
							tmpStr = inet_ntoa(*((struct in_addr *)entry.local_ip_start));
							sprintf(tmp_args1, "%s", tmpStr);
							tmpStr = inet_ntoa(*((struct in_addr *)entry.local_ip_end));
							sprintf(tmp_args2, "%s", tmpStr);
							sprintf(tmp_args3, "%s-%s",tmp_args1, tmp_args2);
							//iptables -A PREROUTING -t mangle -m iprange --src-range 192.168.1.11-192.168.1.22 -j MARK --set-mark 13
							//RunSystemCmd(NULL_FILE, Iptables, ADD, PREROUTING, _table, mangle_table , match, ip_range, src_rnage, tmp_args3, str_l7_filter, jump, MARK, set_mark, tmp_args, NULL_STR);
							sprintf(command,"%s %s %s %s %s %s %s %s %s %s %s %s %s %s", Iptables, ADD, PREROUTING, _table, mangle_table , match, ip_range, src_rnage, tmp_args3, str_l7_filter, jump, MARK, set_mark, tmp_args, NULL_STR);
//printf("\r\n command=[%s],__[%s-%u]\r\n",command,__FILE__,__LINE__);
							system(command);
						}
						else if(entry.mode & QOS_RESTRICT_MAC){
							sprintf(tmp_args3, "%02x:%02x:%02x:%02x:%02x:%02x",entry.mac[0], entry.mac[1], entry.mac[2], entry.mac[3], entry.mac[4], entry.mac[5]);
							//iptables -A PREROUTING -t mangle -m mac --mac-source 00:11:22:33:44:55 -j MARK --set-mark 13
							//RunSystemCmd(NULL_FILE, Iptables, ADD, PREROUTING, _table, mangle_table , match, _mac, mac_src, tmp_args3, str_l7_filter, jump, MARK, set_mark, tmp_args, NULL_STR);
							sprintf(command,"%s %s %s %s %s %s %s %s %s %s %s %s %s %s", Iptables, ADD, PREROUTING, _table, mangle_table , match, _mac, mac_src, tmp_args3, str_l7_filter, jump, MARK, set_mark, tmp_args, NULL_STR);
//printf("\r\n command=[%s],__[%s-%u]\r\n",command,__FILE__,__LINE__);
							system(command);
				#ifdef CONFIG_IPV6
							sprintf(command,"%s %s %s %s %s %s %s %s %s %s %s %s %s ", Ip6tables, ADD, PREROUTING, _table, mangle_table , match, _mac, mac_src, tmp_args3, jump, MARK, set_mark, tmp_args, NULL_STR);
							system(command);
				#endif
						}
				#ifdef CONFIG_IPV6
						else if(entry.mode & QOS_RESTRICT_IPV6){
							//ip6tables -A PREROUTING -t mangle -s 2001::1 -j MARK --set-mark 13
							sprintf(command,"%s %s %s %s %s %s %s %s %s %s %s %s %s ",
							Ip6tables, ADD, POSTROUTING, _table, mangle_table , out, pInterface, _src, entry.ip6_src, jump, MARK, set_mark, tmp_args);
							system(command);
						}
				#endif
						else //any
						{
							//iptables -A PREROUTING -t mangle -j MARK --set-mark 13
							//RunSystemCmd(NULL_FILE, Iptables, ADD, PREROUTING, _table, mangle_table , str_l7_filter, jump, MARK, set_mark, tmp_args, NULL_STR);
							sprintf(command,"%s %s %s %s %s %s %s %s %s %s", Iptables, ADD, PREROUTING, _table, mangle_table , str_l7_filter, jump, MARK, set_mark, tmp_args, NULL_STR);
//printf("\r\n command=[%s],__[%s-%u]\r\n",command,__FILE__,__LINE__);
							system(command);
						}

						sprintf(tmp_args1, "2:%d", wan_pkt_mark);
						sprintf(tmp_args2, "%ldkbit", entry.bandwidth);
						sprintf(tmp_args3, "%dkbit", uplink_speed);
						sprintf(tmp_args4, "1%d:", wan_pkt_mark);
						if(entry.mode & QOS_RESTRICT_MIN){//if(entry.mode == 5 || entry.mode == 9){
							RunSystemCmd(NULL_FILE, _tc, _class, _add, _dev, pInterface, _parent, "2:1", _classid, tmp_args1, _htb, _rate, tmp_args2, _ceil, tmp_args3, _prio, "2",  _quantum, "30000",NULL_STR);
							//TC_CMD="tc class add dev $WAN parent 2:1 classid 2:$wan_pkt_mark htb rate ${bandwidth}kbit ceil ${UPLINK_SPEED}kbit prio 2 quantum 30000"
						}else{
							RunSystemCmd(NULL_FILE, _tc, _class, _add, _dev, pInterface, _parent, "2:1", _classid, tmp_args1, _htb, _rate, "1kbit", _ceil, tmp_args2, _prio, "2" , _quantum, "30000", NULL_STR);
							//TC_CMD="tc class add dev $WAN parent 2:1 classid 2:$wan_pkt_mark htb rate 1kbit ceil ${bandwidth}kbit prio 2 quantum 30000"
						}

						RunSystemCmd(NULL_FILE, _tc, _qdisc, _add, _dev, pInterface, _parent, tmp_args1, _handle, tmp_args4, _sfq, _perturb, "10", NULL_STR);
						//TC_CMD="tc qdisc add dev $WAN parent 2:$wan_pkt_mark handle 1$wan_pkt_mark: sfq perturb 10"

						RunSystemCmd(NULL_FILE, _tc, _filter, _add, _dev, pInterface, _parent, "2:0", _prio, "100", _handle, tmp_args, _fw, _classid, tmp_args1, NULL_STR);
						//TC_CMD="tc filter add dev $WAN parent 2:0 protocol ip prio 100 handle $wan_pkt_mark fw classid 2:$wan_pkt_mark"

#if 1
						sprintf(tmp_args1, "3:%d", wan_pkt_mark);
						sprintf(tmp_args2, "%ldkbit", entry.bandwidth);
						sprintf(tmp_args3, "%dkbit", uplink_speed);
						sprintf(tmp_args4, "3%d:", wan_pkt_mark);
						if((pInterface2!=NULL)&&strcmp(pInterface2, "ppp0")==0)//wantype is l2tp
						{
							if(entry.mode & QOS_RESTRICT_MIN){//if(entry.mode == 5 || entry.mode == 9){
								RunSystemCmd(NULL_FILE, _tc, _class, _add, _dev, pInterface2, _parent, "3:1", _classid, tmp_args1, _htb, _rate, tmp_args2, _ceil, tmp_args3, _prio, "2",  _quantum, "30000",NULL_STR);
								//TC_CMD="tc class add dev $WAN2 parent 3:1 classid 3:$wan_pkt_mark htb rate ${bandwidth}kbit ceil ${UPLINK_SPEED}kbit prio 2 quantum 30000"
							}else{
								RunSystemCmd(NULL_FILE, _tc, _class, _add, _dev, pInterface2, _parent, "3:1", _classid, tmp_args1, _htb, _rate, "1kbit", _ceil, tmp_args2, _prio, "2" , _quantum, "30000", NULL_STR);
								//TC_CMD="tc class add dev $WAN2 parent 3:1 classid 3:$wan_pkt_mark htb rate 1kbit ceil ${bandwidth}kbit prio 2 quantum 30000"
							}

							RunSystemCmd(NULL_FILE, _tc, _qdisc, _add, _dev, pInterface2, _parent, tmp_args1, _handle, tmp_args4, _sfq, _perturb, "10", NULL_STR);
							//TC_CMD="tc qdisc add dev $WAN2 parent 3:$wan_pkt_mark handle 3$wan_pkt_mark: sfq perturb 10"

							RunSystemCmd(NULL_FILE, _tc, _filter, _add, _dev, pInterface2, _parent, "3:0", _prio, "100", _handle, tmp_args, _fw, _classid, tmp_args1, NULL_STR);
							//TC_CMD="tc filter add dev $WAN2 parent 3:0 protocol ip prio 100 handle $wan_pkt_mark fw classid 3:$wan_pkt_mark"
						}
#endif

						wan_pkt_mark = wan_pkt_mark+1;
					}
#ifdef MULTI_PPPOE
						if(needSetOnce){
#endif

					if(entry.bandwidth_downlink > 0){/*DOWNlink*/
						sprintf(tmp_args, "%d", lan_pkt_mark);
						if(entry.mode & QOS_RESTRICT_IP){//if(entry.mode == 5 || entry.mode == 6){
							/*this qos rule is set by IP address*/
							tmpStr = inet_ntoa(*((struct in_addr *)entry.local_ip_start));
							sprintf(tmp_args1, "%s", tmpStr);
							tmpStr = inet_ntoa(*((struct in_addr *)entry.local_ip_end));
							sprintf(tmp_args2, "%s", tmpStr);
							sprintf(tmp_args3, "%s-%s",tmp_args1, tmp_args2);

							//RunSystemCmd(NULL_FILE, Iptables, ADD, POSTROUTING, _table, mangle_table , match, ip_range, dst_rnage, tmp_args3, jump, MARK,  set_mark, tmp_args, NULL_STR);
							sprintf(command,"%s %s %s %s %s %s %s %s %s %s %s %s %s %s", Iptables, ADD, POSTROUTING, _table, mangle_table , match, ip_range, dst_rnage, tmp_args3, str_l7_filter, jump, MARK, set_mark, tmp_args, NULL_STR);
//printf("\r\n command=[%s],__[%s-%u]\r\n",command,__FILE__,__LINE__);
							system(command);
						}
						else if(entry.mode & QOS_RESTRICT_MAC){
						#ifndef QOS_MAC_U32_FILTER
							sprintf(tmp_args3, "%02x:%02x:%02x:%02x:%02x:%02x",entry.mac[0], entry.mac[1], entry.mac[2], entry.mac[3], entry.mac[4], entry.mac[5]);
							//RunSystemCmd(NULL_FILE, Iptables, ADD, POSTROUTING, _table, mangle_table , match, _mac, mac_dst, tmp_args3, jump, MARK, set_mark, tmp_args, NULL_STR);
							sprintf(command,"%s %s %s %s %s %s %s %s %s %s %s %s %s %s", Iptables, ADD, POSTROUTING, _table, mangle_table , match, _mac, mac_dst, tmp_args3, str_l7_filter, jump, MARK, set_mark, tmp_args, NULL_STR);
//printf("\r\n command=[%s],__[%s-%u]\r\n",command,__FILE__,__LINE__);
							system(command);
						#else
							sprintf(macAddr, "%02x:%02x:%02x:%02x:%02x:%02x",entry.mac[0], entry.mac[1], entry.mac[2], entry.mac[3], entry.mac[4], entry.mac[5]);
						#endif
		#ifdef CONFIG_IPV6
							sprintf(command,"%s %s %s %s %s %s %s %s %s %s %s %s %s", Ip6tables, ADD, POSTROUTING, _table, mangle_table , match, _mac, mac_dst, tmp_args3, jump, MARK, set_mark, tmp_args, NULL_STR);
							system(command);
		#endif
						}
		#ifdef CONFIG_IPV6
						else if(entry.mode & QOS_RESTRICT_IPV6){
							//ip6tables -A PREROUTING -t mangle -s 2001::1 -j MARK --set-mark 13
							sprintf(command,"%s %s %s %s %s %s %s %s %s %s %s %s %s",
							Ip6tables, ADD, POSTROUTING, _table, mangle_table , out, br_interface, _dest, entry.ip6_src, jump, MARK, set_mark, tmp_args);
							system(command);
						}
		#endif
						else
						{
							sprintf(command,"%s %s %s %s %s %s %s %s %s %s", Iptables, ADD, POSTROUTING, _table, mangle_table , str_l7_filter, jump, MARK, set_mark, tmp_args, NULL_STR);
//printf("\r\n command=[%s],__[%s-%u]\r\n",command,__FILE__,__LINE__);
							system(command);
						}

						sprintf(tmp_args1, "5:%d", lan_pkt_mark);
						sprintf(tmp_args2, "%ldkbit", entry.bandwidth_downlink);
						sprintf(tmp_args3, "%dkbit", downlink_speed);
						sprintf(tmp_args4, "5%d:", lan_pkt_mark);


						if(entry.mode & QOS_RESTRICT_MIN){//if(entry.mode == 5 || entry.mode == 9){
							RunSystemCmd(NULL_FILE, _tc, _class, _add, _dev, br_interface, _parent, "5:1", _classid, tmp_args1, _htb, _rate, tmp_args2, _ceil, tmp_args3, _prio, "2", _quantum, "30000",NULL_STR);
							//TC_CMD="tc class add dev $BRIDGE parent 5:1 classid 5:$lan_pkt_mark htb rate ${bandwidth_dl}kbit ceil ${DOWNLINK_SPEED}kbit prio 2 quantum 30000"
						}else{
							RunSystemCmd(NULL_FILE, _tc, _class, _add, _dev, br_interface, _parent, "5:1", _classid, tmp_args1, _htb, _rate, "1kbit", _ceil, tmp_args2, _prio, "2" ,_quantum, "30000", NULL_STR);
							//TC_CMD="tc class add dev $BRIDGE parent 5:1 classid 5:$lan_pkt_mark htb rate 1kbit ceil ${bandwidth_dl}kbit prio 2 quantum 30000"
						}
						RunSystemCmd(NULL_FILE, _tc, _qdisc, _add, _dev, br_interface, _parent, tmp_args1, _handle, tmp_args4, _sfq, _perturb, "10", NULL_STR);
						//TC_CMD="tc qdisc add dev $BRIDGE parent 5:$lan_pkt_mark handle 5$lan_pkt_mark: sfq perturb 10"
						#ifndef QOS_MAC_U32_FILTER
						RunSystemCmd(NULL_FILE, _tc, _filter, _add, _dev, br_interface, _parent, "5:0", _prio, "100", _handle, tmp_args, _fw, _classid, tmp_args1, NULL_STR);
						//TC_CMD="tc filter add dev $BRIDGE parent 5:0 protocol ip prio 100 handle $lan_pkt_mark fw classid 5:$lan_pkt_mark"
						#else
						if(entry.mode & QOS_RESTRICT_MAC)
							RunSystemCmd(NULL_FILE, _tc, _filter, _add, _dev, br_interface, _parent, "5:0", _protocol2, _ip, _prio, "100", "u32","match", "ether", "dst", macAddr,_classid, tmp_args1, NULL_STR);
						else
							RunSystemCmd(NULL_FILE, _tc, _filter, _add, _dev, br_interface, _parent, "5:0", _protocol2, _ip, _prio, "100", _handle, tmp_args, _fw, _classid, tmp_args1, NULL_STR);
						//TC_CMD="tc filter add dev $WAN2 parent 3:0 protocol ip prio 100 handle $wan_pkt_mark fw classid 3:$wan_pkt_mark"
						#endif
						lan_pkt_mark = lan_pkt_mark+1;
					}
#ifdef MULTI_PPPOE
				  }
#endif
				}
			}
		}
	}

//	RunSystemCmd("/proc/qos", "echo", PROC_QOS, NULL_STR);
#endif
#endif //__DAVO__
	return 0;
}

int setURLFilter(void)
{
	char keywords[500];
	char cmdBuffer[500];
	//char macAddr[30];
	char tmp1[64]={0};
	URLFILTER_T entry;
	int entryNum=0, index;
	int mode,i=0;
	//char c = 22;	//unseen char to distinguish
	//printf("set urlfilter\n");
	/*add URL filter Mode 0:Black list 1:White list*/
	apmib_get(MIB_URLFILTER_MODE,  (void *)&mode);
	apmib_get(MIB_URLFILTER_TBL_NUM, (void *)&entryNum);
	//sprintf(keywords, "%d ", entryNum);
	bzero(keywords,sizeof(keywords));
	for (index=1; index<=entryNum; index++) {
		memset(&entry, '\0', sizeof(entry));
		bzero(tmp1,sizeof(tmp1));
		*((char *)&entry) = (char)index;
		apmib_get(MIB_URLFILTER_TBL, (void *)&entry);
		if(mode!=entry.ruleMode)
			continue;
		strcpy(tmp1,(char *)entry.urlAddr);
		if(!strncmp(tmp1,"http://",7))
			for(i=7;i<sizeof(tmp1);i++)
				tmp1[i-7]=tmp1[i];
	//printf("%s:%d tmp1=%s\n",__FUNCTION__,__LINE__,tmp1);
		if(!strncmp(tmp1,"www.",4))
			for(i=4;i<sizeof(tmp1);i++)
				tmp1[i-4]=tmp1[i];

	//printf("%s:%d entryNum=%d\n",__FUNCTION__,__LINE__,entryNum);
		if(changeDividerToESC(tmp1,sizeof(tmp1)," #:\\")<0)
			return -1;
		//printf("%s:%d tmp1=%s\n",__FUNCTION__,__LINE__,tmp1);
#ifdef URL_FILTER_USER_MODE_SUPPORT
		if(entry.usrMode==0)
			sprintf(tmp1,"%s 0;",tmp1);
		else if(entry.usrMode==1)
			sprintf(tmp1, "%s I%x;", tmp1,*((struct in_addr *)entry.ipAddr));
		else if(entry.usrMode==2){
			sprintf(macAddr,"%02X%02X%02X%02X%02X%02X", entry.macAddr[0], entry.macAddr[1], entry.macAddr[2], entry.macAddr[3], entry.macAddr[4], entry.macAddr[5]);
			sprintf(tmp1, "%s M%s;", tmp1,macAddr);
		}
#else
		sprintf(tmp1, "%s ;", tmp1);
#endif
		//printf("%s:%d tmp1=%s\n",__FUNCTION__,__LINE__,tmp1);
#if defined(CONFIG_RTL_FAST_FILTER)
		memset(cmdBuffer, 0, sizeof(cmdBuffer));
		sprintf(cmdBuffer, "rtk_cmd filter add --url-key %s", tmp1);
		system(cmdBuffer);
#else
		strcat(keywords, tmp1);
#endif
	}

	if(mode)
		RunSystemCmd("/proc/filter_table", "echo", "white", NULL_STR);
	else
		RunSystemCmd("/proc/filter_table", "echo", "black", NULL_STR);
	//sprintf(cmdBuffer, "%s", keywords);
	//RunSystemCmd("/proc/url_filter", "echo", cmdBuffer, NULL_STR);//disable h/w nat when url filter enabled
#if defined(CONFIG_RTL_FAST_FILTER)
#else

	sprintf(cmdBuffer, "add:0#3 3 %s",keywords);
	//printf("%s:%d cmdBuffer=%s\n",__FUNCTION__,__LINE__,cmdBuffer);
	//sleep(1);

	RunSystemCmd("/proc/filter_table", "echo", cmdBuffer, NULL_STR);
#endif

	return 0;
}


int setDoS(unsigned long enabled, int op)
{
#if __DAVO__
	in_addr_t nip, mask;
	unsigned int rate;
	unsigned int blockTime = 0;
	int n, type;
	int synflood, portscan, ipspoof, pingofdeath;
	char tmp[160], inp[24];

//	apmib_get(MIB_DOS_BLOCK_TIME, (void *)&blockTime);
//	apmib_get(MIB_IP_ADDR, (void *)&nip);
//	apmib_get(MIB_SUBNET_MASK, (void *)&mask);

	blockTime = nvram_atoi("DOS_BLOCK_TIME", 0);
	memset(tmp, 0, 160);
	nvram_get_r("IP_ADDR", tmp, sizeof(tmp));
	nip = inet_addr(tmp);

	memset(tmp, 0, 160);
	nvram_get_r("SUBNET_MASK", tmp, sizeof(tmp));
	mask = inet_addr(tmp);

	synflood = !!(enabled & 2);
	portscan = !!(enabled & 0x200);
	ipspoof = !!(enabled & 0x1000);
	pingofdeath = !!(enabled & 0x4000);

	//vfecho("/proc/enable_dos", " %d %X %X 0 0 0 0 0 0 0 0 0 0",
	yfecho("/proc/enable_dos", O_WRONLY|O_TRUNC, 0644, " %d %X %X 0 0 0 0 0 0 0 0 0 0",
	       (op == 2) ? 2 : 0,
	       (op == 2) ? nip : (nip & htonl(0xFFFFFF00)), mask);

	/* clean up, if any */
	if (!run_fcommand("/var/run/acl_ipspoof_permits", "aclwrite del"))
		unlink("/var/run/acl_ipspoof_permits");
	if (!run_fcommand("/var/run/acl_ipspoof_drop", "aclwrite del"))
		unlink("/var/run/acl_ipspoof_drop");
	if (!run_fcommand("/var/run/ipt_dos_drop", "iptables -D"))
		unlink("/var/run/ipt_dos_drop");
	type = getPid_fromFile("/proc/sys/net/ipv4/icmp_ratemask");

	if (enabled & 1) {
		if (portscan) {
			rate = (enabled & 0x800000) ? 10 : 100;
			inp[0] = 0;
			if (op == GATEWAY_MODE)
				strcpy(inp, "-i eth1 ");
			snprintf(tmp, sizeof(tmp), "INPUT %s-p %s -m state --state NEW "
				"-m recent --update --seconds 5 --hitcount %d --blockoff %d -j DROP",
				inp, "udp", rate * 5, blockTime);
			add_fcommand("/var/run/ipt_dos_drop", 0, "iptables -I", tmp);
			snprintf(tmp, sizeof(tmp), "INPUT %s-p %s -m state --state NEW "
				"-m recent --update --seconds 5 --hitcount %d --blockoff %d -j DROP",
				inp, "tcp", rate * 5, blockTime);
			add_fcommand("/var/run/ipt_dos_drop", 0, "iptables -I", tmp);
			snprintf(tmp, sizeof(tmp), "INPUT %s-p %s -m state --state NEW -m recent --set", inp, "udp");
			add_fcommand("/var/run/ipt_dos_drop", 0, "iptables -I", tmp);
			snprintf(tmp, sizeof(tmp), "INPUT %s-p %s -m state --state NEW -m recent --set", inp, "tcp");
			add_fcommand("/var/run/ipt_dos_drop", 0, "iptables -I", tmp);
		}

		rate = nvram_atoi("DOS_SYSSYN_FLOOD", 0);

		//if (synflood && apmib_get(MIB_DOS_SYSSYN_FLOOD, (void *)&rate) && rate > 0)
		if (synflood && rate > 0) {
			snprintf(tmp, sizeof(tmp), "INPUT -p tcp --tcp-flags SYN,FIN,ACK SYN "
				"-m recent --update --seconds 5 --hitcount %d --blockoff %d -j DROP",
				rate * 5, blockTime);
			add_fcommand("/var/run/ipt_dos_drop", 0, "iptables -I", tmp);
			add_fcommand("/var/run/ipt_dos_drop", 0,
				"iptables -I", "INPUT -p tcp --tcp-flags SYN,FIN,ACK SYN -m recent --set");
		}

		yfecho("/proc/sys/net/ipv4/icmp_echo_ignore_broadcasts", O_WRONLY|O_TRUNC, 0644, "%d", !!(enabled & 0x400));

		n = nvram_atoi("x_icmp_reply_rate", 0);
		//n = safe_atoi(dvnv_get("icmp_reply_rate"), 0);
		if (pingofdeath)
			n = 1;		/* overwrite 1/sec */
		if (n > 0) {
			n = 1000 / n;
			if (n < 1)
				n = 1;	/* Not allow unlimited rate */
			yfecho("/proc/sys/net/ipv4/icmp_ratelimit", O_WRONLY|O_TRUNC, 0644, "%d", n);
			type |= (1 << 0);	/* ECHO_REPLY mask */
		}

		if (nvram_atoi("x_noreply_tracert", 0)) {
			add_fcommand("/var/run/ipt_dos_drop", 0,
				"iptables -I", "INPUT -p udp -m ttl --ttl-lt 31 -j DROP");
			add_fcommand("/var/run/ipt_dos_drop", 0,
				"iptables -I", "INPUT -p icmp -m ttl --ttl-lt 31 -j DROP");
			add_fcommand("/var/run/ipt_dos_drop", 0,
				"iptables -I", "FORWARD -p icmp --icmp-type 11 -j DROP");
			add_fcommand("/var/run/ipt_dos_drop", 0,
				"iptables -I", "OUTPUT -p icmp --icmp-type 11 -j DROP");
		}

		if (nvram_atoi("x_NTPDefEnabled", 0)) {
			if (op == GATEWAY_MODE)
				strcpy(inp, "-i eth1 ");

            //Read document =>  http://www.pool.ntp.org/ko/join.html
			snprintf(tmp, sizeof(tmp), "INPUT %s-p udp --dport 123 -m state --state NEW "
				"-m recent --update --seconds 5 --hitcount 50 --blockoff %d -j DROP",
				inp, blockTime);
			add_fcommand("/var/run/ipt_dos_drop", 0, "iptables -I", tmp);
			snprintf(tmp, sizeof(tmp), "INPUT %s-p udp --dport 123 -m state --state NEW -m recent --set", inp);
			add_fcommand("/var/run/ipt_dos_drop", 0, "iptables -I", tmp);
		}

		if (nvram_atoi("x_DNSRelayEnabled", 0)) {
			if (op == GATEWAY_MODE)
				strcpy(inp, "-i eth1 ");

			snprintf(tmp, sizeof(tmp), "INPUT %s-p udp --dport 53 -m state --state NEW "
				"-m recent --update --seconds 5 --hitcount 50 --blockoff %d -j DROP",
				inp, blockTime);
			add_fcommand("/var/run/ipt_dos_drop", 0, "iptables -I", tmp);
			snprintf(tmp, sizeof(tmp), "INPUT %s-p udp --dport 53 -m state --state NEW -m recent --set", inp);
			add_fcommand("/var/run/ipt_dos_drop", 0, "iptables -I", tmp);
		}

		if (ipspoof && op == 0) {
			nip = nip & mask;
			sprintf(tmp, "br0 -a permit -r ip -i %u.%u.%u.%u/%u.%u.%u.%u_0.0.0.0/0.0.0.0 -b",
				NIPQUAD(nip), NIPQUAD(mask));
			add_fcommand("/var/run/acl_ipspoof_permits", 0, "aclwrite add", tmp);
			add_fcommand("/var/run/acl_ipspoof_permits", 1,
				"aclwrite add", "br0 -a permit -r ip -i 0.0.0.0/255.255.255.255_0.0.0.0/0.0.0.0 -b");
			add_fcommand("/var/run/acl_ipspoof_drop", 0,
				"aclwrite add", "br0 -a drop -r ip -i 0.0.0.0/0.0.0.0_0.0.0.0/0.0.0.0 -b");
		}
	} else
		type &= ~(1 << 0);

	yfecho("/proc/sys/net/ipv4/icmp_ratemask", O_WRONLY|O_TRUNC, 0644, "%d", type);
	return 0;

#else
	char cmdBuffer[500];
	unsigned int *dst, *mask;
	unsigned int synsynflood=0;
	unsigned int sysfinflood=0;
	unsigned int sysudpflood=0;
	unsigned int sysicmpflood=0;
	unsigned int pipsynflood=0;
	unsigned int pipfinflood=0;
	unsigned int pipudpflood=0;
	unsigned int pipicmpflood=0;
	unsigned int blockTime=0;
	struct in_addr curIpAddr={0}, curSubnet={0};

	apmib_get(MIB_DOS_SYSSYN_FLOOD, (void *)&synsynflood);
	apmib_get(MIB_DOS_SYSFIN_FLOOD, (void *)&sysfinflood);
	apmib_get(MIB_DOS_SYSUDP_FLOOD, (void *)&sysudpflood);
	apmib_get(MIB_DOS_SYSICMP_FLOOD, (void *)&sysicmpflood);
	apmib_get(MIB_DOS_PIPSYN_FLOOD, (void *)&pipsynflood);
	apmib_get(MIB_DOS_PIPFIN_FLOOD, (void *)&pipfinflood);
	apmib_get(MIB_DOS_PIPUDP_FLOOD, (void *)&pipudpflood);
	apmib_get(MIB_DOS_PIPICMP_FLOOD, (void *)&pipicmpflood);
	apmib_get(MIB_DOS_BLOCK_TIME, (void *)&blockTime);

//	getInAddr("eth1", IP_ADDR_T, (void *)&curIpAddr);
//	getInAddr("eth1", NET_MASK_T, (void *)&curSubnet);
	getInAddr("br0", IP_ADDR_T, (void *)&curIpAddr);
	getInAddr("br0", NET_MASK_T, (void *)&curSubnet);

  	//apmib_get(MIB_IP_ADDR,  (void *)ipbuf);
  	dst = (unsigned int *)&curIpAddr;
  	//apmib_get( MIB_SUBNET_MASK,  (void *)maskbuf);
  	mask = (unsigned int *)&curSubnet;
  	if(op==2){
  		sprintf(cmdBuffer, "echo \" 2 %X %X %ld %d %d %d %d %d %d %d %d %d\" >  /proc/enable_dos", *dst, *mask, enabled, synsynflood, sysfinflood, sysudpflood, sysicmpflood, pipsynflood, pipfinflood, pipudpflood, pipicmpflood, blockTime);
  		  system(cmdBuffer);
  	}else{
  		sprintf(cmdBuffer, "echo \" 0 %X %X %ld %d %d %d %d %d %d %d %d %d\" >  /proc/enable_dos", (*dst & 0xFFFFFF00), *mask, enabled, synsynflood, sysfinflood, sysudpflood, sysicmpflood, pipsynflood, pipfinflood, pipudpflood, pipicmpflood, blockTime);
  		  system(cmdBuffer);
	}
return 0;
#endif

}

int run_fcommand(const char *path, const char *fmt, ...)
{
	va_list va;
	FILE *f;
	char buf[128], command[64];

	f = fopen(path, "r");
	if (f == NULL)
		return -1;
	va_start(va, fmt);
	vsnprintf(command, sizeof(command), fmt, va);
	va_end(va);

	while (fgets(buf, sizeof(buf), f)) {
		ydespaces(buf);
		//_exclp(NULL, "%s %s", command, buf);
		yexecl(NULL, "%s %s", command, buf);
	}
	fclose(f);
	return 0;
}

/* pos : 0 <= specifies the position from the first line of file
 *       -1 intended to delete line matched with cmd.
 */
int add_fcommand(const char *path, int pos, const char *pcmd, const char *cmd)
{
	char tmp[] = "/var/XXXXXX";
	FILE *f, *t;
	char buf[128];
	int len, n;

	if (pcmd)
		yexecl(NULL, "%s %s", pcmd, cmd);
	f = fopen(path, "r");
	if (f == NULL)
		return yfecho(path, O_CREAT|O_WRONLY|O_TRUNC, 0755, "%s", cmd);
//            vfecho(path, "%s", cmd);	/* auto line feed */
	mktemp(tmp);
	t = fopen(tmp, "w+");
	if (t) {
		for (n = len = 0; fgets(buf, sizeof(buf), f); ) {
			ydespaces(buf);
			if (!strcmp(buf, cmd))
				continue;
			if (n++ == pos)
				len = fprintf(t, "%s\n", cmd);
			fprintf(t, "%s\n", buf);
		}

		if (pos >= 0 && len == 0)
			fprintf(t, "%s\n", cmd);
		fclose(t);
	}
	fclose(f);
	if (t)
		rename(tmp, path);
	return 0;
}

int setIpFilter(void)
{
#if defined(__DAVO__)
    int entryNum = 0, index;
	char ipAddr[30] = "";
    char comment[COMMENT_LEN] = "";
    int protoType = 0;
    char tmpStrArr[128] = "";
    char indexStr[32] = "";
#if defined(CONFIG_RTL_FAST_FILTER)
	char protocol[10];
#endif
	const char **proto;

    char *args[5];

	//apmib_get(MIB_IPFILTER_TBL_NUM, (void *)&entryNum);
	nvram_get_r_def("IPFILTER_TBL_NUM", tmpStrArr, sizeof(tmpStrArr), "0");
    entryNum = atoi(tmpStrArr);

	for (index = 1; index <= entryNum; index++) {
        //IPFILTER_TBL1=192.168.1.140,3,test,,4
        sprintf(indexStr, "IPFILTER_TBL%d", index);

        nvram_get_r(indexStr, tmpStrArr, sizeof(tmpStrArr));

        if (ystrargs(tmpStrArr, args, 5, ",", 1) != 5)
            continue;

        strncpy(ipAddr, args[0], strlen(args[0]));
        ipAddr[strlen(args[0])] = '\0';

        strncpy(tmpStrArr, args[1], strlen(args[2]));
        tmpStrArr[strlen(args[1])] = '\0';
        protoType = atoi(tmpStrArr);

        strncpy(comment, args[2], strlen(args[1]));
        comment[strlen(args[2])] = '\0';

#if defined(CONFIG_RTL_FAST_FILTER)
        memset(protocol, 0, sizeof(protocol));
		if (protoType == PROTO_TCP)
			sprintf(protocol, "tcp");
		else if (protoType == PROTO_UDP)
			sprintf(protocol, "udp");
		else if (protoType == PROTO_BOTH)
			sprintf(protocol, "tcp_udp");
		yexecl(NULL, "rtk_cmd filter add --ip-src %s --protocol %s", ipAddr, protocol);
#else
        for (proto = proto_list(protoType); *proto; proto++) {
			yexecl(NULL, "iptables -A FORWARD -p %s -s %s -j DROP", *proto, ipAddr);
			//yexecl(NULL, "iptables -A INPUT -p %s -s %s -j DROP", *proto, ipAddr);
			if (!strcmp(*proto, "udp")) {
			    yexecl(NULL, "iptables -A INPUT -p udp --dport 53:53 -s %s -j DROP", ipAddr);
            }
		}
#endif
	}

	return 0;
#else //__DAVO__
	int entryNum=0, index;
	IPFILTER_T entry;
	char ipAddr[30];
	char *tmpStr;
#if defined(CONFIG_RTL_FAST_FILTER)
	char protocol[10];
	char cmdBuffer[120];
#endif

#if 0
#ifdef MIB_IPFILTER_IMPORT
/* _ctype,	_cname, _crepeat, _mib_name, _mib_type, _mib_parents_ctype, _default_value, _next_tbl */
typedef enum { PROTO_BOTH=3, PROTO_TCP=1, PROTO_UDP=2 } PROTO_TYPE_T;
MIBDEF(unsigned char,	ipAddr, [4],	IPFILTER_IPADDR,	IA_T, IPFILTER_T, 0, 0)
MIBDEF(unsigned char,	protoType,	,	IPFILTER_PROTOTYPE,	BYTE_T, IPFILTER_T, 0, 0)
MIBDEF(unsigned char,	comment, [COMMENT_LEN],	IPFILTER_COMMENT,	STRING_T, IPFILTER_T, 0, 0)
#ifdef CONFIG_IPV6
MIBDEF(unsigned char, 	ip6Addr, [48], 	IPFILTER_IP6ADDR,	STRING_T, IPFILTER_T, 0, 0)
MIBDEF(unsigned char,	ipVer, 	,	IPFILTER_IP_VERSION,	BYTE_T, IPFILTER_T, 0, 0)
#endif
#endif // #ifdef MIB_IPFILTER_IMPORT
#endif

	apmib_get(MIB_IPFILTER_TBL_NUM, (void *)&entryNum);

	for(index=1; index <= entryNum ; index++) {
		memset(&entry, '\0', sizeof(entry));
		*((char *)&entry) = (char)index;
		apmib_get(MIB_IPFILTER_TBL, (void *)&entry);

		tmpStr = inet_ntoa(*((struct in_addr *)entry.ipAddr));
		sprintf(ipAddr, "%s", tmpStr);
#if defined(CONFIG_RTL_FAST_FILTER)
		memset(protocol, 0, sizeof(protocol));
		memset(cmdBuffer, 0, sizeof(cmdBuffer));
		if(entry.protoType==PROTO_TCP){
			sprintf(protocol, "tcp");
		}
		else if(entry.protoType==PROTO_UDP){
			sprintf(protocol, "udp");
		}
		else if(entry.protoType==PROTO_BOTH)	{
			sprintf(protocol, "tcp_udp");
		}
		sprintf(cmdBuffer, "rtk_cmd filter add --ip-src %s --protocol %s", ipAddr, protocol);
		system(cmdBuffer);
#else

#ifdef CONFIG_IPV6
		if(entry.ipVer==IPv4){
#endif
		if(entry.protoType==PROTO_TCP){
			RunSystemCmd(NULL_FILE, Iptables, ADD, FORWARD, _protocol, _tcp, _src, ipAddr, jump, DROP, NULL_STR);
		}
		if(entry.protoType==PROTO_UDP){
			RunSystemCmd(NULL_FILE, Iptables, ADD, FORWARD, _protocol, _udp, _src, ipAddr, jump, DROP, NULL_STR);
			RunSystemCmd(NULL_FILE, Iptables, ADD, INPUT, _protocol, _udp, dport, "53:53", _src, ipAddr, jump, DROP, NULL_STR);
		}
		if(entry.protoType==PROTO_BOTH)	{
			RunSystemCmd(NULL_FILE, Iptables, ADD, FORWARD, _protocol, _tcp, _src, ipAddr, jump, DROP, NULL_STR);
			RunSystemCmd(NULL_FILE, Iptables, ADD, FORWARD, _protocol, _udp, _src, ipAddr, jump, DROP, NULL_STR);
			RunSystemCmd(NULL_FILE, Iptables, ADD, INPUT, _protocol, _udp, dport, "53:53", _src, ipAddr, jump, DROP, NULL_STR);
		}
#ifdef CONFIG_IPV6
		}
		else if(entry.ipVer==IPv6){
			if(entry.protoType==PROTO_TCP){
				RunSystemCmd(NULL_FILE, Ip6tables, ADD, FORWARD, _protocol, _tcp, _src, entry.ip6Addr, jump, DROP, NULL_STR);
			}
			else if(entry.protoType==PROTO_UDP){
				RunSystemCmd(NULL_FILE, Ip6tables, ADD, FORWARD, _protocol, _udp, _src, entry.ip6Addr, jump, DROP, NULL_STR);
				RunSystemCmd(NULL_FILE, Ip6tables, ADD, INPUT, _protocol, _udp, dport, "53", _src, ipAddr, jump, DROP, NULL_STR);
			}
			else if(entry.protoType==PROTO_BOTH){
				RunSystemCmd(NULL_FILE, Ip6tables, ADD, FORWARD, _protocol, _tcp, _src, entry.ip6Addr, jump, DROP, NULL_STR);
				RunSystemCmd(NULL_FILE, Ip6tables, ADD, FORWARD, _protocol, _udp, _src, entry.ip6Addr, jump, DROP, NULL_STR);
				RunSystemCmd(NULL_FILE, Ip6tables, ADD, INPUT, _protocol, _udp, dport, "53", _src, entry.ip6Addr, jump, DROP, NULL_STR);
			}
		}
#endif

#endif

	}
	return 0;
#endif //__DAVO__
}

int setMACFilter(void)
{
#if defined(__DAVO__)
	int tbl_num = 0, p_port, LAN = 0, i;
	char opmode1[32], opmode2[32], opmode3[32], opmode4[32], *opmode;
	char buf[128], tmp[128];
	char *args[5], *p;
	int active_port = 0;

	nvram_get_r_def("x_MACFILTER_TBL_NUM", tmp, sizeof(tmp), "0");
	tbl_num = atoi(tmp);
	if (tbl_num == 0)
		return 0;

	nvram_get_r_def("x_MACFILTER_OPMODE1", opmode1, sizeof(opmode1), "drop");
	nvram_get_r_def("x_MACFILTER_OPMODE2", opmode2, sizeof(opmode2), "drop");
	nvram_get_r_def("x_MACFILTER_OPMODE3", opmode3, sizeof(opmode3), "drop");
	nvram_get_r_def("x_MACFILTER_OPMODE4", opmode4, sizeof(opmode4), "drop");
	// GAPNRTL-47
	// apply drop rule the last.
	if (strcmp(opmode1, "permit") == 0) {
		yexecl(NULL, "aclwrite del br0 -a drop -r sfilter -o 7 -3 -4 -P 1");
	}
	if (strcmp(opmode2, "permit") == 0) {
		yexecl(NULL, "aclwrite del br0 -a drop -r sfilter -o 7 -3 -4 -P 2");
	}
	if (strcmp(opmode3, "permit") == 0) {
		yexecl(NULL, "aclwrite del br0 -a drop -r sfilter -o 7 -3 -4 -P 4");
	}
	if (strcmp(opmode4, "permit") == 0) {
		yexecl(NULL, "aclwrite del br0 -a drop -r sfilter -o 7 -3 -4 -P 8");
	}

	for (i = 1; i <= tbl_num; i++) {
		sprintf(tmp, "x_MACFILTER_TBL%d", i);
		nvram_get_r_def(tmp, buf, sizeof(buf), "");
		if (buf[0] == 0)
			continue;

		p = ydespaces(buf);
		if (ystrargs(p, args, 5, ",", 1) >= 2) {
			if (strcmp(args[1], "01") == 0) {
				opmode = opmode1;
				p_port = 1;
				LAN = 1;
				active_port |= 1;
			} else if (strcmp(args[1], "02") == 0) {
				opmode = opmode2;
				p_port = 2;
				LAN = 2;
				active_port |= 2;
			} else if (strcmp(args[1], "04") == 0) {
				opmode = opmode3;
				p_port = 4;
				LAN = 3;
				active_port |= 4;
			} else if (strcmp(args[1], "08") == 0) {
				opmode = opmode4;
				p_port = 8;
				LAN = 4;
				active_port |= 8;
			} else {
				LAN = 0;
			}
			if (LAN != 0) {
				yexecl(NULL, "aclwrite add br0 -a %s -r sfilter -o 7 -m %s -P %d -3 -4",
						opmode, args[0], p_port);
			}
		}
	}
	if ((active_port & 1) && (strcmp(opmode1, "permit") == 0)) {
		yexecl(NULL, "aclwrite add br0 -a drop -r sfilter -o 7 -3 -4 -P 1");
	}
	if ((active_port & 2) && (strcmp(opmode2, "permit") == 0)) {
		yexecl(NULL, "aclwrite add br0 -a drop -r sfilter -o 7 -3 -4 -P 2");
	}
	if ((active_port & 4) && (strcmp(opmode3, "permit") == 0)) {
		yexecl(NULL, "aclwrite add br0 -a drop -r sfilter -o 7 -3 -4 -P 4");
	}
	if ((active_port & 8) && (strcmp(opmode4, "permit") == 0)) {
		yexecl(NULL, "aclwrite add br0 -a drop -r sfilter -o 7 -3 -4 -P 8");
	}

	return 0;
#else	//__DAVO__
	char macEntry[30];
	int entryNum=0, index;
	MACFILTER_T entry;
	char cmdBuffer[80];

	apmib_get(MIB_MACFILTER_TBL_NUM, (void *)&entryNum);

	for (index=1; index<=entryNum; index++) {
		memset(&entry, '\0', sizeof(entry));
		*((char *)&entry) = (char)index;
		apmib_get(MIB_MACFILTER_TBL, (void *)&entry);
		sprintf(macEntry,"%02X:%02X:%02X:%02X:%02X:%02X", entry.macAddr[0], entry.macAddr[1], entry.macAddr[2], entry.macAddr[3], entry.macAddr[4], entry.macAddr[5]);
#if defined(CONFIG_RTL_FAST_FILTER)
		memset(cmdBuffer, 0, sizeof(cmdBuffer));
		sprintf(cmdBuffer, "rtk_cmd filter add --mac-src %s", macEntry);
		system(cmdBuffer);
#else
#if defined(CONFIG_APP_EBTABLES)&&defined(CONFIG_EBTABLES_KERNEL_SUPPORT)
		RunSystemCmd(NULL_FILE, Ebtables, ADD, INPUT,_src, macEntry, jump, DROP,NULL_STR);
		RunSystemCmd(NULL_FILE, Ebtables, ADD, OUTPUT,_dest, macEntry, jump, DROP,NULL_STR);
#else
		RunSystemCmd(NULL_FILE, Iptables, ADD, FORWARD, match, "mac" ,mac_src, macEntry, jump, DROP, NULL_STR);
		RunSystemCmd(NULL_FILE, Iptables, ADD, INPUT, match, "mac" ,mac_src, macEntry, jump, DROP, NULL_STR);
#endif
#endif
		memset(cmdBuffer, 0, sizeof(cmdBuffer));
		sprintf(cmdBuffer, "rtk_cmd igmp_delete %02X:%02X:%02X:%02X:%02X:%02X", entry.macAddr[0], entry.macAddr[1], entry.macAddr[2], entry.macAddr[3], entry.macAddr[4], entry.macAddr[5]);
		system(cmdBuffer);
	}
#endif // DAVO
	return 0;

}



int setPortFilter(void)
{

#ifdef __DAVO__
    int entryNum = 0, index;
	char fromPort[30] = "";
	char toPort[30] = "";
    int	protoType = 0;
    char tmpStrArr[128] = "";
    char indexStr[32] = "";
	char PortRange[30] = "";
#if defined(CONFIG_RTL_FAST_FILTER)
	char protocol[10];
#endif
	int drop_dns = 0;
	const char **proto;

	char *args[4];

    //apmib_get(MIB_IPFILTER_TBL_NUM, (void *)&entryNum);
	nvram_get_r_def("PORTFILTER_TBL_NUM", tmpStrArr, sizeof(tmpStrArr), "0");
    entryNum = atoi(tmpStrArr);

	for (index = 1; index <= entryNum; index++) {

        //PORTFILTER_TBL1=4141,4242,3,test1
        //PORTFILTER_ENABLED=1
        //PORTFILTER_TBL_NUM=1

        sprintf(indexStr, "PORTFILTER_TBL%d", index);

        nvram_get_r(indexStr, tmpStrArr, sizeof(tmpStrArr));

        if (ystrargs(tmpStrArr, args, 4, ",", 1) != 4)
            continue;

        strncpy(fromPort, args[0], strlen(args[0]));
        fromPort[strlen(args[0])] = '\0';

        strncpy(toPort, args[1], strlen(args[1]));
        toPort[strlen(args[1])] = '\0';

        strncpy(tmpStrArr, args[2], strlen(args[2]));
        tmpStrArr[strlen(args[2])] = '\0';
        protoType = atoi(tmpStrArr);

        //from to
		sprintf(PortRange, "%s:%s", fromPort, toPort);

        proto = proto_list(protoType);

        for (; *proto; proto++) {
			if (!drop_dns && !strcmp(*proto, "udp") && atoi(fromPort) <= 53 && atoi(toPort) >= 53) {
				yexecl(NULL, "iptables -A FORWARD -p udp --dport 53:53 -j DROP");
				drop_dns = 1;
			}
			yexecl(NULL, "iptables -A FORWARD -p %s --dport %s -j DROP", *proto, PortRange);
		}
    }
#else
	char PortRange[30];
	//int DNS_Filter=0;
	int entryNum=0,index;
	PORTFILTER_T entry;
#if defined(CONFIG_RTL_FAST_FILTER)
	char protocol[10];
	char cmdBuffer[120];
#endif
	char cmdName[10];

	apmib_get(MIB_PORTFILTER_TBL_NUM, (void *)&entryNum);
	for (index=1; index<=entryNum; index++) {
		memset(&entry, '\0', sizeof(entry));
		*((char *)&entry) = (char)index;
		apmib_get(MIB_PORTFILTER_TBL, (void *)&entry);
		sprintf(PortRange, "%d:%d", entry.fromPort, entry.toPort);
#if defined(CONFIG_RTL_FAST_FILTER)
		memset(protocol, 0, sizeof(protocol));
		memset(cmdBuffer, 0, sizeof(cmdBuffer));

		if(entry.protoType==PROTO_TCP){
			sprintf(protocol, "tcp");
		}
		else if(entry.protoType==PROTO_UDP){
			sprintf(protocol, "udp");
		}
		else if(entry.protoType==PROTO_BOTH){
			sprintf(protocol, "tcp_udp");
		}
		sprintf(cmdBuffer, "rtk_cmd filter add --port-range-dst %d:%d --protocol %s", entry.fromPort, entry.toPort, protocol);
		system(cmdBuffer);
#else
#ifdef CONFIG_IPV6
		if(entry.ipVer == IPv6)
			sprintf(cmdName,"%s",Ip6tables);
		else
#endif
			sprintf(cmdName,"%s",Iptables);

		if(entry.protoType==PROTO_TCP){
			RunSystemCmd(NULL_FILE, cmdName, ADD, FORWARD, _protocol, _tcp, dport, PortRange, jump, DROP, NULL_STR);
		}

		if(entry.protoType==PROTO_UDP){
			if(entry.fromPort<53 && entry.toPort >= 53){
				RunSystemCmd(NULL_FILE, cmdName, ADD, INPUT, _protocol, _udp, dport, "53:53", jump, DROP, NULL_STR);
			}
			RunSystemCmd(NULL_FILE, cmdName, ADD, FORWARD, _protocol, _udp, dport, PortRange, jump, DROP, NULL_STR);
		}

		if(entry.protoType==PROTO_BOTH)	{
			RunSystemCmd(NULL_FILE, cmdName, ADD, FORWARD, _protocol, _tcp, dport, PortRange, jump, DROP, NULL_STR);
			RunSystemCmd(NULL_FILE, cmdName, ADD, FORWARD, _protocol, _udp, dport, PortRange, jump, DROP, NULL_STR);
			if(entry.fromPort<53 && entry.toPort >= 53){
				RunSystemCmd(NULL_FILE, cmdName, ADD, INPUT, _protocol, _udp, dport, "53:53", jump, DROP, NULL_STR);
			}
		}
#endif
		/*
		if(DNS_Filter==0){
			if(entry.fromPort<= 53 &&  entry.toPort >= 53){
				if(entry.protoType==PROTO_BOTH || (entry.protoType==PROTO_UDP)){
					RunSystemCmd(NULL_FILE, Iptables, ADD, INPUT, _protocol, _udp, dport, "53", jump, DROP, NULL_STR);
				}
			}
			DNS_Filter=1;
		}
		*/

	}
#endif
	return 0;
}

#if defined(CONFIG_RTL_SUPPORT_ACCESS_PORT_FORWARD_FROM_LAN)
int getlansubnet(char *lansubnet)
{

	char *bInterface = "br0";
	int get_br0ip =0;
	int get_br0mask =0;
	//char Br0NetSectAddr[30];
	char * strbr0Ip ,* strbr0Mask ;
	struct in_addr br0addr,br0mask;
	unsigned int numofone ;
	char NumStr[10];

    if (lansubnet == NULL)
        return -1;

    get_br0ip = getInAddr(bInterface, IP_ADDR_T,(void *)&br0addr);
    if(get_br0ip ==0 ){
        printf("No ip currently!\n");
        return -1;
    }
    get_br0mask = getInAddr(bInterface, NET_MASK_T,(void *)&br0mask);
    if( get_br0mask ==0 ){
        printf("No MASK currently!\n");
        return -1;
    }
    br0addr.s_addr &= br0mask.s_addr ;
    for(numofone =0;br0mask.s_addr;++numofone)
        br0mask.s_addr &= br0mask.s_addr-1;
    sprintf (NumStr, "%d", numofone);
    strcpy(lansubnet,inet_ntoa(br0addr));
    strcat(lansubnet,"/");
    strcat(lansubnet,NumStr);

    return 0;
}
#endif


int setPortForward(char *pIfaceWan, char *pIpaddrWan)
{
    char PortRange[60]="";
	char ip[30]="";
	char t_fromPort[40]="";
	int entryNum = 0, index;

    //PORTFW_T entry;

	int l2tp_vpn = 0;
	int pptp_vpn = 0;
	int ipsec_vpn = 0;

    char tmp[128] = "";
    char tmp_v[32] = "";

    char portfw_nvram_idx[13]="";                  /* 1 ~ 9999 */

    int fromPort = 0;
    int toPort = 0;
    int protoType;
    const char **proto;
    char comment[COMMENT_LEN];

    char *args[6];

	//apmib_get(MIB_PORTFW_TBL_NUM, (void *)&entryNum);
    nvram_get_r_def("PORTFW_TBL_NUM", tmp, sizeof(tmp), "0");
    entryNum = atoi(tmp);

    for (index = 1; index <= entryNum; index++) {
        sprintf(portfw_nvram_idx, "PORTFW_TBL%d", index);

        nvram_get_r(portfw_nvram_idx, tmp, sizeof(tmp));

        if (ystrargs(tmp, args, 6, ",|", 1) != 6)
            continue;

        //ip
        strncpy(ip, args[0], strlen(args[0]));
        ip[strlen(args[0])] = '\0';

        //from_port
        strncpy(tmp_v, args[1], strlen(args[1]));
        tmp_v[strlen(args[1])] = '\0';
        fromPort = atoi(tmp_v);

        //to port
        strncpy(tmp_v, args[2], strlen(args[2]));
        tmp_v[strlen(args[2])] = '\0';
        toPort = atoi(tmp_v);

        //proto
        strncpy(tmp_v, args[3], strlen(args[3]));
        tmp_v[strlen(args[3])] = '\0';
        protoType = atoi(tmp_v);

        //t_fromPort
        strncpy(t_fromPort, args[4], strlen(args[4]));
        t_fromPort[strlen(args[4])] = '\0';

        //comment
        strncpy(comment, args[5], strlen(args[5]));
        comment[strlen(args[5])] = '\0';

		sprintf(PortRange, "%d:%d", fromPort, toPort);

		if (fromPort <= 80 && toPort >= 80)
			yexecl(NULL, "iptables -D INPUT -p tcp --dport 80 -i %s -d %s -j DROP", pIfaceWan, pIpaddrWan);

        proto = proto_list(protoType);

		for (; *proto; proto++) {
            yexecl(NULL, "iptables -A PREROUTING -t nat -p %s --dport %s -d %s -j DNAT --to %s:%s",
			      *proto, PortRange, pIpaddrWan, ip, t_fromPort);

			yexecl(NULL, "iptables -A FORWARD -i %s -d %s -p %s --dport %s -j ACCEPT", pIfaceWan, ip, *proto, t_fromPort);
		}

		if (pptp_vpn == 0 && (fromPort <= 1723 && toPort >= 1723)) {
			if (protoType == PROTO_BOTH || (protoType == PROTO_TCP)) {
				yexecl(NULL, "iptables -A PREROUTING -t nat -i %s -p gre -d %s -j DNAT --to %s",
					  pIfaceWan, pIpaddrWan, ip);
				yexecl(NULL, "iptables -A FORWARD -p gre -i %s -j ACCEPT", pIfaceWan);
				pptp_vpn = 1;
			}
		}

		if (l2tp_vpn == 0 && (fromPort <= 1701 && toPort >= 1701)) {
			if (protoType == PROTO_BOTH || (protoType == PROTO_UDP)) {
                yfecho("/proc/nat_l2tp", O_WRONLY|O_TRUNC, 0644, "0");
				l2tp_vpn = 1;
			}
		}

		if (ipsec_vpn == 0 && (fromPort <= 500 && toPort >= 500)) {
			if (protoType == PROTO_BOTH || (protoType == PROTO_UDP)) {
				yexecl(NULL, "iptables -A PREROUTING -t nat -p esp -d %s -j DNAT --to %s", pIpaddrWan, ip);
				yexecl(NULL, "iptables -A PREROUTING -t nat -p udp --dport 4500 -d %s -j DNAT --to %s", pIpaddrWan, ip);
				yexecl(NULL, "iptables -A FORWARD -p udp --dport 4500 -j ACCEPT", NULL_STR);
				yexecl(NULL, "iptables -A FORWARD -p esp -i %s -j ACCEPT", pIfaceWan);
				ipsec_vpn = 1;
			}
		}
	}

	return 0;
}




#if defined(CONFIG_APP_TR069)
void SetRuleFortr069(char *interface, char *wan_addr)
{
	int cwmp_flag = 0;
	int conReqPort = 0;
	char acsUrl[CWMP_ACS_URL_LEN+1] = {0};
	char acsUrlRange[2*(CWMP_ACS_URL_LEN+1)] = {0};
	char conReqPortRange[2*(5+1)] = {0};
//	char strPID[10];
//	int pid=-1;

//printf("\r\n wan_addr=[%s],__[%s-%u]\r\n",wan_addr,__FILE__,__LINE__);
	apmib_get( MIB_CWMP_FLAG, (void *)&cwmp_flag );
#if 0	 //disabled Since webpage form handler has modified
	if(isFileExist(TR069_PID_FILE))
	{


	}
	else
	{
		if(cwmp_flag & CWMP_FLAG_AUTORUN)
		{
			unsigned char acsUrltmp[CWMP_ACS_URL_LEN+1];
			unsigned char *notifyList;
	#if 0
			notifyList=malloc(CWMP_NOTIFY_LIST_LEN);

			if(notifyList==NULL)
			{
				fprintf(stderr,"\r\n ERR:notifyList malloc fail! __[%s-%u]",__FILE__,__LINE__);
			}
			else
			{
				char *lineptr = NULL;
				char *str;
				int firstline = 1;


				memset(notifyList,0x00,CWMP_NOTIFY_LIST_LEN);
				apmib_get(MIB_CWMP_NOTIFY_LIST,(void *)notifyList);

				if(strlen(notifyList) == 0)
				{
					system("echo \"\" > /var/CWMPNotify.txt");

				}
				else
				{

					lineptr = notifyList;

					// A1]A2]A3[B1]B2]B3
					str = strsep(&lineptr,"[");

					//A1]A2]A3
					while(str != NULL)
					{
						char *strptr = str;
						char *str1,*str2,*str3;
						char tmpStr[5];
						char *insertStr=NULL;

						insertStr=malloc(strlen(str));

						if(insertStr != NULL)
						{
							memset(insertStr,0x00,strlen(str));

							//A1]A2]A3
							str1 = strsep(&strptr,"]");
							sprintf(insertStr,"%s",str1);
							//A1

							//A2]A3
							str2 = strsep(&strptr,"]");
							//A2
							memset(tmpStr,0x00,sizeof(tmpStr));
							sprintf(tmpStr," %s",str2);
							strcat(insertStr,tmpStr);

							//A3
							str3 = strsep(&strptr,"]");
							//A3
							memset(tmpStr,0x00,sizeof(tmpStr));
							sprintf(tmpStr," %s\n",str3);
							strcat(insertStr,tmpStr);

	//fprintf(stderr,"\r\n insertStr=[%s] __[%s-%u]",insertStr,__FILE__,__LINE__);


							if(firstline == 1)
								write_line_to_file("/var/CWMPNotify.txt", 1, insertStr);
							else
								write_line_to_file("/var/CWMPNotify.txt", 2, insertStr);

							firstline = 0;

							if(insertStr)
								free(insertStr);

						}

						str = strsep(&lineptr,"["); //get next line
					}
				}

				if(notifyList)
					free(notifyList);
			}
		#endif
			//read flatfs content before start cwmp
			//if(RunSystemCmd(NULL_FILE, "flatfsd", "-r", NULL_STR) !=0){
			//	printf("Read Flatfs Faile, Please check again\n");
			//}
			//system("flatfsd -r");
			apmib_get( MIB_CWMP_ACS_URL, (void *)acsUrltmp);

			//system("/bin/cwmpClient &");
			//memset(acsURLStr,0x00,sizeof(acsURLStr));
			sprintf(acsURLStr,"%s",acsUrltmp);
		}

	}
#endif
	if(cwmp_flag & CWMP_FLAG_AUTORUN)
	{
		apmib_get( MIB_CWMP_CONREQ_PORT, (void *)&conReqPort);
		if(conReqPort >0 && conReqPort<65535)
		{
			//char tmpStr[CWMP_ACS_URL_LEN] = {0};

			apmib_get( MIB_CWMP_ACS_URL, (void *)acsUrl);
//printf("\r\n acsUrl=[%s],__[%s-%u]\r\n",acsUrl,__FILE__,__LINE__);
			if((strstr(acsUrl,"https://") != 0 || strstr(acsUrl,"http://") != 0) && strlen(acsUrl) != 0)
			{
				char *lineptr = acsUrl;
				char *str=NULL;

//printf("\r\n lineptr=[%s],__[%s-%u]\r\n",lineptr,__FILE__,__LINE__);

				str = strsep(&lineptr,"/");
//printf("\r\n str=[%s],__[%s-%u]\r\n",str,__FILE__,__LINE__);
				str = strsep(&lineptr,"/");
//printf("\r\n str=[%s],__[%s-%u]\r\n",str,__FILE__,__LINE__);
				str = strsep(&lineptr,"/");
//printf("\r\n str=[%s],__[%s-%u]\r\n",str,__FILE__,__LINE__);

				if(str != NULL && strlen(str) != 0)
				{
					sprintf(acsUrlRange,"%s-%s",str,str);

					sprintf(conReqPortRange,"%d:%d",conReqPort,conReqPort);
					//iptables -A INPUT -p tcp -m iprange --src-range $ACS_URL-$ACS_URL --dport $CWMP_CONREQ_PORT:$CWMP_CONREQ_PORT -i $WAN -d $EXT_IP -j ACCEPT
					//printf("\r\n acsUrlRange=[%s],__[%s-%u]\r\n",acsUrlRange,__FILE__,__LINE__);
					//printf("\r\n conReqPortRange=[%s],__[%s-%u]\r\n",conReqPortRange,__FILE__,__LINE__);
					//printf("\r\n interface=[%s],__[%s-%u]\r\n",interface,__FILE__,__LINE__);
					//printf("\r\n wan_addr=[%s],__[%s-%u]\r\n",wan_addr,__FILE__,__LINE__);
					//iptables -A INPUT -p tcp --dport 4567:4567 -i eth1 -d 172.21.69.21 -j ACCEPT
					//RunSystemCmd(NULL_FILE, "iptables", "-A", "INPUT", "-p", "tcp", "-m", "iprange", "--src-range", acsUrlRange, "--dport", conReqPortRange, "-i", interface, "-d", wan_addr, "-j", "ACCEPT", NULL_STR);
					RunSystemCmd(NULL_FILE, "iptables", "-A", "INPUT", "-p", "tcp", "--dport", conReqPortRange, "-i", interface, "-d", wan_addr, "-j", "ACCEPT", NULL_STR);
				}
			}



		}

	}

}




void start_tr069(void)
{
	int lan_if = 0;
	int wan_if = 0;
	int port1, port2, port3, port4, port5;
	int bitRate1, bitRate2, bitRate3, bitRate4, bitRate5;
	char mode1[5]="", mode2[5]="", mode3[5]="", mode4[5]="", mode5[5]="";
	char cmd[512];
	int cwmp_flag = 0;

	// port1
	apmib_get( MIB_CWMP_SW_PORT1_DISABLE, (void *)&port1);
	if (port1 == 1) {
		//printf("%s-%s-%d\n", __FILE__, __FUNCTION__, __LINE__);
		system("echo set eth if0 Enable false > /proc/rtl865x/tr181_eth_set");
	}
	else {
		//printf("%s-%s-%d\n", __FILE__, __FUNCTION__, __LINE__);
		apmib_get( MIB_CWMP_SW_PORT1_MAXBITRATE, (void *)&bitRate1);
		if (bitRate1 == 0) {
			bitRate1 = -1;
			apmib_set( MIB_CWMP_SW_PORT1_MAXBITRATE, (void *)&bitRate1);
		}
		memset(cmd, 0, sizeof(cmd));
		sprintf(cmd, "echo set eth if0 MaxBitRate %d > /proc/rtl865x/tr181_eth_set", bitRate1);
		system(cmd);

		usleep(100000);

		apmib_get( MIB_CWMP_SW_PORT1_DUPLEXMODE, (void *)mode1);
		if (strcmp(mode1, "") == 0) {
			sprintf(mode1, "%s", "Auto");
			apmib_set( MIB_CWMP_SW_PORT1_DUPLEXMODE, (void *)mode1);
		}
		memset(cmd, 0, sizeof(cmd));
		sprintf(cmd, "echo set eth if0 DuplexMode %s > /proc/rtl865x/tr181_eth_set", mode1);
		system(cmd);
	}

	usleep(100000);

	// port2
	apmib_get( MIB_CWMP_SW_PORT2_DISABLE, (void *)&port2);
	if (port2 == 1) {
		//printf("%s-%s-%d\n", __FILE__, __FUNCTION__, __LINE__);
		system("echo set eth if1 Enable false > /proc/rtl865x/tr181_eth_set");
	}
	else {

		//printf("%s-%s-%d\n", __FILE__, __FUNCTION__, __LINE__);
		apmib_get( MIB_CWMP_SW_PORT2_MAXBITRATE, (void *)&bitRate2);
		if (bitRate2 == 0) {
			bitRate2 = -1;
			apmib_set( MIB_CWMP_SW_PORT2_MAXBITRATE, (void *)&bitRate2);
		}
		memset(cmd, 0, sizeof(cmd));
		//printf("%s-%s-%d: bitRate=%d\n", __FILE__, __FUNCTION__, __LINE__, bitRate2);
		sprintf(cmd, "echo set eth if1 MaxBitRate %d > /proc/rtl865x/tr181_eth_set", bitRate2);
		system(cmd);

		usleep(100000);

		apmib_get( MIB_CWMP_SW_PORT2_DUPLEXMODE, (void *)mode2);
		if (strcmp(mode2, "") == 0) {
			sprintf(mode2, "%s", "Auto");
			apmib_set( MIB_CWMP_SW_PORT2_DUPLEXMODE, (void *)mode2);
		}
		memset(cmd, 0, sizeof(cmd));
		//printf("%s-%s-%d: mode=%s\n", __FILE__, __FUNCTION__, __LINE__, mode2);
		sprintf(cmd, "echo set eth if1 DuplexMode %s > /proc/rtl865x/tr181_eth_set", mode2);
		system(cmd);
	}

	usleep(100000);

	// port3
	apmib_get( MIB_CWMP_SW_PORT3_DISABLE, (void *)&port3);
	if (port3 == 1) {
		//printf("%s-%s-%d\n", __FILE__, __FUNCTION__, __LINE__);
		system("echo set eth if2 Enable false > /proc/rtl865x/tr181_eth_set");
	}
	else {
		//printf("%s-%s-%d\n", __FILE__, __FUNCTION__, __LINE__);
		apmib_get( MIB_CWMP_SW_PORT3_MAXBITRATE, (void *)&bitRate3);
		if (bitRate3 == 0) {
			bitRate3 = -1;
			apmib_set( MIB_CWMP_SW_PORT3_MAXBITRATE, (void *)&bitRate3);
		}
		memset(cmd, 0, sizeof(cmd));
		sprintf(cmd, "echo set eth if2 MaxBitRate %d > /proc/rtl865x/tr181_eth_set", bitRate3);
		system(cmd);

		usleep(100000);

		apmib_get( MIB_CWMP_SW_PORT3_DUPLEXMODE, (void *)mode3);
		if (strcmp(mode3, "") == 0) {
			sprintf(mode3, "%s", "Auto");
			apmib_set( MIB_CWMP_SW_PORT3_DUPLEXMODE, (void *)mode3);
		}
		memset(cmd, 0, sizeof(cmd));
		sprintf(cmd, "echo set eth if2 DuplexMode %s > /proc/rtl865x/tr181_eth_set", mode3);
		system(cmd);
	}

	usleep(100000);

	// port4
	apmib_get( MIB_CWMP_SW_PORT4_DISABLE, (void *)&port4);
	if (port4 == 1) {
		//printf("%s-%s-%d\n", __FILE__, __FUNCTION__, __LINE__);
		system("echo set eth if3 Enable false > /proc/rtl865x/tr181_eth_set");
	}
	else {
		//printf("%s-%s-%d\n", __FILE__, __FUNCTION__, __LINE__);
		apmib_get( MIB_CWMP_SW_PORT4_MAXBITRATE, (void *)&bitRate4);
		if (bitRate4 == 0) {
			bitRate4 = -1;
			apmib_set( MIB_CWMP_SW_PORT4_MAXBITRATE, (void *)&bitRate4);
		}
		memset(cmd, 0, sizeof(cmd));
		sprintf(cmd, "echo set eth if3 MaxBitRate %d > /proc/rtl865x/tr181_eth_set", bitRate4);
		system(cmd);

		usleep(100000);

		apmib_get( MIB_CWMP_SW_PORT4_DUPLEXMODE, (void *)mode4);
		if (strcmp(mode4, "") == 0) {
			sprintf(mode4, "%s", "Auto");
			apmib_set( MIB_CWMP_SW_PORT4_DUPLEXMODE, (void *)mode4);
		}
		memset(cmd, 0, sizeof(cmd));
		sprintf(cmd, "echo set eth if3 DuplexMode %s > /proc/rtl865x/tr181_eth_set", mode4);
		system(cmd);
	}

	usleep(100000);

	// port5
	apmib_get( MIB_CWMP_SW_PORT5_DISABLE, (void *)&port5);
	if (port5 == 1) {
		//printf("%s-%s-%d\n", __FILE__, __FUNCTION__, __LINE__);
		system("echo set eth if4 Enable false > /proc/rtl865x/tr181_eth_set");
	}
	else {
		//printf("%s-%s-%d\n", __FILE__, __FUNCTION__, __LINE__);
		apmib_get( MIB_CWMP_SW_PORT5_MAXBITRATE, (void *)&bitRate5);
		if (bitRate5 == 0) {
			bitRate5 = -1;
			apmib_set( MIB_CWMP_SW_PORT5_MAXBITRATE, (void *)&bitRate5);
		}
		memset(cmd, 0, sizeof(cmd));
		sprintf(cmd, "echo set eth if4 MaxBitRate %d > /proc/rtl865x/tr181_eth_set", bitRate5);
		system(cmd);

		usleep(100000);

		apmib_get( MIB_CWMP_SW_PORT5_DUPLEXMODE, (void *)mode5);
		if (strcmp(mode5, "") == 0) {
			sprintf(mode5, "%s", "Auto");
			apmib_set( MIB_CWMP_SW_PORT5_DUPLEXMODE, (void *)mode5);
		}
		memset(cmd, 0, sizeof(cmd));
		sprintf(cmd, "echo set eth if4 DuplexMode %s > /proc/rtl865x/tr181_eth_set", mode5);
		system(cmd);
	}

	usleep(100000);

	apmib_get( MIB_CWMP_LAN_ETHIFDISABLE, (void *)&lan_if );
	if (lan_if == 1)
		system("ifconfig eth0 down");
	else
		system("ifconfig eth0 up");

	apmib_get( MIB_CWMP_WAN_ETHIFDISABLE, (void *)&wan_if );
	if (wan_if == 1)
		system("ifconfig eth1 down");
	else
		system("ifconfig eth1 up");

	apmib_get( MIB_CWMP_FLAG, (void *)&cwmp_flag );
	if((cwmp_flag & CWMP_FLAG_AUTORUN) && isFileExist("/bin/cwmpClient") )
	{
		system("flatfsd -r");
		system("/bin/cwmpClient &");

	}
}
#endif
#ifdef MULTI_PPPOE
void setMulPppoeRules(int argc, char** argv)
{
	//dzh add for multi-pppoe route set and lan-partition set
	if(argc >=3 && argv[2] && (strcmp(argv[2], "pppoe")==0))
	{
		system("ifconfig |grep 'P-t-P' | cut  -d ':' -f 2 | cut -d ' ' -f 1 > /etc/ppp/ppp_local");
		system("ifconfig |grep 'P-t-P' | cut  -d ':' -f 3 | cut -d ' ' -f 1 > /etc/ppp/ppp_remote");
		system("ifconfig |grep 'ppp'| cut -d ' ' -f 1 > /etc/ppp/ppp_device");
		system("cat /etc/ppp/ppp_local | wc -l > /etc/ppp/lineNumber");
		if(0 == get_info())
		{
 #ifdef MULTI_PPP_DEBUG
			printf("get info error\n");
 #endif
			return ;
		}
		//print_info();
		if(argc >=4 && argv[3]) //if exist pppoe interface,set interface information
		{
			//set route
			int index ;
			char command[100];
			char flushCmd[100];
			for( index = 0 ; index < pppNumbers ; ++index)
			{
			 	#ifdef MULTI_PPP_DEBUG
				printf("the ppp_name is:%s\n",infos[index].ppp_name);
				printf("the argv[3] is:%s\n",argv[3]);
				#endif
				if(!strcmp(infos[index].ppp_name,argv[3]))//match the interface
				{
					int sub_index;
					//set subnet rules char SubNet[4][30];
					//SubNet[infos[index].order-1];
					/*
					for(sub_index = 0 ; sub_index < SubNets[infos[index].order-1].SubnetCount; ++sub_index)
					{
						//-i eth0
						sprintf(command,
							"iptables -t mangle -A PREROUTING -i eth0 -m iprange --src-range %s-%s -j MARK --set-mark %d",
							SubNets[infos[index].order-1].startip[sub_index],SubNets[infos[index].order-1].endip[sub_index],
							infos[index].order+sub_index+100);
						printf("%s\n",command);
						system(command);

						sprintf(command,"ip rule add fwmark %d table %d pref %d",
							infos[index].order+sub_index+100,
							infos[index].order+30,
							infos[index].order+sub_index+100);
						printf("%s\n",command);
						system(command);

						sprintf(command,"iptables -t nat -A POSTROUTING  -m iprange --src-range %s-%s -o %s -j MASQUERADE",
								SubNets[infos[index].order-1].startip[sub_index],SubNets[infos[index].order-1].endip[sub_index],
									infos[index].ppp_name);
						printf("%s\n",command);
						system(command);

					}
					*/

					FILE* pF;// = fopen("/etc/ppp/flushCmds","w+");
					char path[50];
					sprintf(path,"/etc/ppp/%s.cmd",argv[3]);
					pF = fopen(path,"wt");

					system("ip rule del table 100 >/dev/null 2>&1");
					system("ip route del table 100 >/dev/null 2>&1");
					system(" ip rule add from  192.168.1.0/24 table 100 prio 32765");
					system("ip route add default dev br0 table 100");

					#ifdef MULTI_PPP_DEBUG
					printf("%s\n",command);
					#endif

					//system(command);

					sprintf(command,"ip rule add from %s table %d",
						SubNet[infos[index].order-1],
						infos[index].order+30);
					#ifdef MULTI_PPP_DEBUG
					printf("%s\n",command);
					#endif
					system(command);

					//flush command
					fprintf(pF,"ip rule del table %d >/dev/null 2>&1 \n",infos[index].order+30);
					//iptables -A POSTROUTING -t nat  -s 192.168.1.0/25 -o ppp0 -j MASQUERADE

					sprintf(command,"iptables -A POSTROUTING -t nat -s %s -o %s -j MASQUERADE",
						SubNet[infos[index].order-1],
						infos[index].ppp_name);
					#ifdef MULTI_PPP_DEBUG
					printf("%s\n",command);
					#endif
					system(command);

					//set route

					sprintf(command,"ip route add %s dev %s table %d",infos[index].server_ip,
							infos[index].ppp_name,infos[index].order+10);
					#ifdef MULTI_PPP_DEBUG
					printf("%s\n",command);
					#endif
					system(command);

					fprintf(pF,"ip route del table %d >/dev/null 2>&1 \n",infos[index].order+10);

					sprintf(command,"ip rule add from %s table %d",infos[index].client_ip,
						infos[index].order+10);
					#ifdef MULTI_PPP_DEBUG
					printf("%s\n",command);
					#endif
					system(command);

					fprintf(pF,"ip rule del table %d >/dev/null 2>&1 \n",infos[index].order+10);
					//set lan-partion
					sprintf(command,"ip route add default via %s dev %s table %d",
						infos[index].server_ip,infos[index].ppp_name,
							infos[index].order+30);

					fprintf(pF,"ip route del table %d >/dev/null 2>&1 \n",infos[index].order+30);
					#ifdef MULTI_PPP_DEBUG
					printf("%s\n",command);
					#endif
					system(command);

					sprintf(command,"ip route add %s dev br0 table %d",Br0NetSectAddr,
							infos[index].order+30);
					#ifdef MULTI_PPP_DEBUG
					printf("%s\n",command);
					#endif
					system(command);
					//iptables -A POSTROUTING -t nat -m iprange --src-range 192.168.1.1-192.168.1.50 -o ppp0 -j MASQUERADE
					break;
				}//end if
			}//end for
		}//end if

	}//end if
}
#endif
void setRulesWithOutDevice(int opmode, int wan_dhcp , char* pInterface_wanPhy,char* Interface_wanPhy)
{
	int intVal=0, natEnabled=0;
	int intVal2 = 0;
	int dyn_rt_support=0;
	int intVal_num=0;
	int hw_nat_support=0;
	int my_wan_type = 0;
	unsigned long	dos_enabled = 0;
    char buffer[96] = "";
	char wan_type[8];
    int is_policy_accept;
#ifdef CONFIG_RTL_HW_NAPT
	//int ivalue = 0;
#endif
#if defined(CONFIG_REFINE_BR_FW_RULE)
	int br_rule_refine = 1;
#endif

#if defined(CONFIG_APP_EBTABLES)&&defined(CONFIG_EBTABLES_KERNEL_SUPPORT)
	RunSystemCmd(NULL_FILE,Ebtables,FLUSH,NULL_STR);
	RunSystemCmd(NULL_FILE,Ebtables,X,NULL_STR);
	RunSystemCmd(NULL_FILE,Ebtables,Z,NULL_STR);
#endif
	RunSystemCmd("/proc/sys/net/ipv4/ip_forward", "echo", "0", NULL_STR);//don't enable ip_forward before set MASQUERADE
	RunSystemCmd("/proc/fast_nat", "echo", "2", NULL_STR);//clean conntrack table before set new rules
	RunSystemCmd(NULL_FILE, Iptables, FLUSH, NULL_STR);
	RunSystemCmd(NULL_FILE, Iptables,_table, nat_table, FLUSH, POSTROUTING, NULL_STR);
	RunSystemCmd(NULL_FILE, Iptables,_table, nat_table, FLUSH, PREROUTING, NULL_STR);
	RunSystemCmd(NULL_FILE, Iptables, FLUSH, _table, mangle_table, NULL_STR);
	RunSystemCmd(NULL_FILE, Iptables, FLUSH, INPUT, NULL_STR);
	RunSystemCmd(NULL_FILE, Iptables, FLUSH, OUTPUT, NULL_STR);
	RunSystemCmd(NULL_FILE, Iptables, FLUSH, FORWARD, NULL_STR);
	RunSystemCmd(NULL_FILE, Iptables, POLICY, OUTPUT, ACCEPT, NULL_STR);
#ifdef CONFIG_IPV6
	RunSystemCmd("/dev/null", Ip6tables, FLUSH, INPUT, NULL_STR);
	RunSystemCmd("/dev/null", Ip6tables, FLUSH, OUTPUT, NULL_STR);
	RunSystemCmd("/dev/null", Ip6tables, FLUSH, FORWARD, NULL_STR);
	RunSystemCmd("/dev/null", Ip6tables, POLICY, OUTPUT, ACCEPT, NULL_STR);
#endif


	if(opmode != BRIDGE_MODE){
        is_policy_accept = nvram_atoi("x_input_policy_accept", 0);
        yexecl(NULL, "iptables -P INPUT %s", accept(is_policy_accept));
		//RunSystemCmd(NULL_FILE, Iptables, POLICY, INPUT, DROP, NULL_STR);
	} else {
		RunSystemCmd(NULL_FILE, Iptables, POLICY, INPUT, ACCEPT, NULL_STR);
	}
	if ((opmode == 3) || (opmode == BRIDGE_MODE)) {
		RunSystemCmd(NULL_FILE, Iptables, POLICY, FORWARD, ACCEPT, NULL_STR);
	} else {
        //yexecl(NULL, "iptables -P FORWARD %s", drop(opmode != 3));
		RunSystemCmd(NULL_FILE, Iptables, POLICY, FORWARD, DROP, NULL_STR);
	}


	if(isFileExist("/bin/routed")){
		dyn_rt_support=1;
	}
	if(isFileExist("/proc/hw_nat")){
		hw_nat_support=1;
	}
	if(dyn_rt_support ==1 && opmode != BRIDGE_MODE){
		apmib_get(MIB_NAT_ENABLED, (void *)&natEnabled);
		if(natEnabled==0){
			RunSystemCmd(NULL_FILE, Iptables, POLICY, INPUT, ACCEPT, NULL_STR);
			RunSystemCmd(NULL_FILE, Iptables, POLICY, FORWARD, ACCEPT, NULL_STR);
			//RunSystemCmd("/proc/fast_nat", "echo", "0", NULL_STR);//disable fastpath when nat is disabled
			return;
		}
	}

    nvram_get_r_def("MACFILTER_ENABLED", buffer, sizeof(buffer), "0");
    intVal = atoi(buffer);

    nvram_get_r_def("x_MACFILTER_TBL_NUM", buffer, sizeof(buffer), "0");
    intVal_num = atoi(buffer);

	if(intVal == 1 && intVal_num > 0){
		//set mac filter
		setMACFilter();
		#if defined(CONFIG_REFINE_BR_FW_RULE)
		br_rule_refine = 0;
		#endif
	}

	if(opmode == BRIDGE_MODE)
		return;

	//url filter setting
	apmib_get(MIB_URLFILTER_ENABLED,  (void *)&intVal);
	apmib_get(MIB_URLFILTER_TBL_NUM,  (void *)&intVal_num);

#if defined(CONFIG_RTL_FAST_FILTER)
	system("rtk_cmd filter flush");
#else
	RunSystemCmd("/proc/filter_table", "echo", "flush", NULL_STR);
	RunSystemCmd("/proc/filter_table", "echo", "init", "3",  NULL_STR);
#endif
	if(intVal !=0 && intVal_num>0){
//		RunSystemCmd("/proc/url_filter", "echo", " ", NULL_STR);
		setURLFilter();
#if 0
defined(CONFIG_RTL_HW_NAPT)
		if(opmode==0){
			RunSystemCmd("/proc/hw_nat", "echo", "0", NULL_STR);//disable h/w nat when url filter enabled
		}
#endif
	}else{
//		RunSystemCmd("/proc/url_filter", "echo", "0", NULL_STR);//disable url filter
#if defined(CONFIG_RTL_FAST_FILTER)
#else
		RunSystemCmd("/proc/filter_table", "echo", "flush", NULL_STR);
#endif
#if 0
defined(CONFIG_RTL_HW_NAPT)
		if(opmode==0){
			apmib_get(MIB_SUBNET_MASK,(void*)&ivalue);
			if((ivalue&HW_NAT_LIMIT_NETMASK)!=HW_NAT_LIMIT_NETMASK)
			{
					RunSystemCmd("/proc/hw_nat", "echo", "0", NULL_STR);
			}
			else
			{
				RunSystemCmd("/proc/hw_nat", "echo", "1", NULL_STR);//enable h/w nat when url filter disable
			}
		}
#endif

	}
#if defined(CONFIG_RTL_HW_NAPT)

	RunSystemCmd("/proc/hw_nat", "echo", "9", NULL_STR);
	my_wan_type = 0;
	my_wan_type = wan_dhcp + 80;
	sprintf(wan_type, "%d", my_wan_type);
	RunSystemCmd("/proc/hw_nat", "echo", wan_type, NULL_STR);
#else
	RunSystemCmd("/proc/sw_nat", "echo", "9", NULL_STR);
#endif

	////////////////////////////////////////////////////
	//ip filter setting
	intVal = 0;
//	apmib_get(MIB_IPFILTER_ENABLED,  (void *)&intVal);
//	apmib_get(MIB_IPFILTER_TBL_NUM,  (void *)&intVal_num);

    nvram_get_r_def("IPFILTER_ENABLED", buffer, sizeof(buffer), "0");
    intVal = atoi(buffer);

    nvram_get_r_def("IPFILTER_TBL_NUM", buffer, sizeof(buffer), "0");
    intVal_num = atoi(buffer);

	if(intVal ==1 && intVal_num>0){
			//set ip filter
			setIpFilter();
			#if defined(CONFIG_REFINE_BR_FW_RULE)
			br_rule_refine = 0;
			#endif
	}

	intVal=0;
//	apmib_get(MIB_PORTFILTER_ENABLED,  (void *)&intVal);
//	apmib_get(MIB_PORTFILTER_TBL_NUM, (void *)&intVal_num);

    nvram_get_r_def("PORTFILTER_ENABLED", buffer, sizeof(buffer), "0");
    intVal = atoi(buffer);

    nvram_get_r_def("PORTFILTER_TBL_NUM", buffer, sizeof(buffer), "0");
    intVal_num = atoi(buffer);

	if(intVal==1 && intVal_num>0){
		setPortFilter();
#if defined(CONFIG_REFINE_BR_FW_RULE)
		br_rule_refine = 0;
#endif
	}
	///////////////////////////////////////////////////////////
	apmib_get(MIB_VPN_PASSTHRU_L2TP_ENABLED, (void *)&intVal);
	if(intVal ==0){
		RunSystemCmd(NULL_FILE, Iptables, ADD, FORWARD, _protocol, _udp, dport, "1701", jump, DROP, NULL_STR);
	}
	else if(intVal == 1){
		RunSystemCmd(NULL_FILE, Iptables, ADD, FORWARD, _protocol, _udp, sport, "1701", jump, ACCEPT, NULL_STR);
		RunSystemCmd(NULL_FILE, Iptables, ADD, FORWARD, _protocol, _udp, dport, "1701", jump, ACCEPT, NULL_STR);
	}
	apmib_get(MIB_VPN_PASSTHRU_PPTP_ENABLED, (void *)&intVal2);
	if(intVal2 ==0){
		RunSystemCmd(NULL_FILE, Iptables, ADD, FORWARD, _protocol, _tcp, dport, "1723", jump, DROP, NULL_STR);
	}
	else if(intVal2 == 1){
		RunSystemCmd(NULL_FILE, Iptables, ADD, FORWARD, _protocol, _tcp, dport, "1723", jump, ACCEPT, NULL_STR);
		RunSystemCmd(NULL_FILE, Iptables, ADD, FORWARD, _protocol, _tcp, sport, "1723", jump, ACCEPT, NULL_STR);
		RunSystemCmd(NULL_FILE, Iptables, ADD, FORWARD, _protocol, "47", jump, ACCEPT, NULL_STR); //GRE
	}

	/*
	if((intVal == 1) || (intVal2 == 1)){
		//RunSystemCmd(NULL_FILE, Iptables, ADD, FORWARD, _protocol, _icmp, jump, ACCEPT, NULL_STR);
	//	RunSystemCmd(NULL_FILE, Iptables, ADD, FORWARD, in, pInterface_wanPhy, jump, ACCEPT, NULL_STR);
	}
	*/
	///////////////////////////////////////////////////////////
	RunSystemCmd(NULL_FILE, Iptables, ADD, FORWARD, _protocol, _udp, match, _udp, in, Interface_wanPhy, "--destination" , "224.0.0.0/4", jump, ACCEPT, NULL_STR);
	///////////////////////////////////////////////////////////
	RunSystemCmd(NULL_FILE, Iptables, ADD, INPUT, match, mstate, state, RELATED_ESTABLISHED, jump, ACCEPT, NULL_STR);
	//iptables -I FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu
#if defined(CONFIG_REFINE_BR_FW_RULE)
	if (br_rule_refine)
	{
		RunSystemCmd(NULL_FILE, Iptables, INSERT, FORWARD, in, "br0", jump, ACCEPT, NULL_STR);
		RunSystemCmd(NULL_FILE, Iptables, INSERT, FORWARD, _protocol, _tcp, tcp_flags, MSS_FLAG1, MSS_FLAG2, jump, TCPMSS, clamp, NULL_STR);
		///////////////////////////////////////////////////////////
		RunSystemCmd(NULL_FILE, Iptables, ADD, FORWARD, match, mstate, state, INVALID, jump, DROP, NULL_STR);
	} else
#endif
	{
	RunSystemCmd(NULL_FILE, Iptables, INSERT, FORWARD, _protocol, _tcp, tcp_flags, MSS_FLAG1, MSS_FLAG2, jump, TCPMSS, clamp, NULL_STR);
	///////////////////////////////////////////////////////////
	RunSystemCmd(NULL_FILE, Iptables, ADD, FORWARD, match, mstate, state, INVALID, jump, DROP, NULL_STR);

	RunSystemCmd(NULL_FILE, Iptables, ADD, FORWARD, in, "br0", jump, ACCEPT, NULL_STR);
	}
	///////////////////////////////////////////////////////////
	if(wan_dhcp==4){
		RunSystemCmd(NULL_FILE, Iptables, ADD, FORWARD, in, pInterface_wanPhy, match, mstate, state, RELATED_ESTABLISHED, jump, ACCEPT, NULL_STR);
	}
	///////////////////////////////////////////////////////////

	RunSystemCmd("/tmp/firewall_igd", "echo", "1", NULL_STR);//disable fastpath when port filter is enabled

	//apmib_get(MIB_DOS_ENABLED, (void *)&dos_enabled);
	dos_enabled = nvram_atoi("DOS_ENABLED", 0);

#if 0
	if(dos_enabled > 0){
defined(CONFIG_RTL_HW_NAPT)
	if(opmode == GATEWAY_MODE)
		RunSystemCmd("/proc/hw_nat", "echo", "0", NULL_STR);
	}
#endif

	setDoS(dos_enabled, opmode);

	if(wan_dhcp==PPTP){

		RunSystemCmd(NULL_FILE, Iptables, _table, nat_table, ADD, POSTROUTING, out, pInterface_wanPhy, jump, MASQUERADE, NULL_STR);
	}

	if(wan_dhcp == L2TP){

		RunSystemCmd(NULL_FILE, Iptables, _table, nat_table, ADD, POSTROUTING, out, pInterface_wanPhy, jump, MASQUERADE, NULL_STR);
	}
}


static int set_staticfwd(char *up_ifc, char *up_nip)
{
	char buf[64], name[52];
	char *args[5];
	const char **proto;
	int i, nelem = 0;
    char *p_nelem = NULL;

    p_nelem = nvram_get_r("x_STATICMAP_TBL_NUM", buf, sizeof(buf));

	if (!p_nelem)
		return 0;
    else
		nelem = atoi(buf);

	for (i = 0; i < nelem; i++) {
		sprintf(name, "x_STATICMAP_TBL%d", i);
		if (nvram_get_r(name, buf, sizeof(buf)) == NULL)
			continue;

		if (ystrargs(buf, args, 5, ",", 1) != 5)
			continue;

		if (strcmp(args[2], "1") == 0)
			proto = proto_list(PROTO_TCP);
		else if (strcmp(args[2], "2") == 0)
			proto = proto_list(PROTO_UDP);
		else
			proto = proto_list(PROTO_BOTH);

		for (; *proto; proto++) {
			yexecl(NULL, "iptables -t nat -A PREROUTING -i %s -p %s -s %s --sport %s -d %s --dport %s -j DNAT --to %s",
				  up_ifc, *proto, args[0], args[1], up_nip, args[4], args[3]);
			yexecl(NULL, "iptables -A FORWARD -i %s -p %s -d %s --dport %s -j ACCEPT", up_ifc, *proto, args[3], args[4]);
		}
	}

	return nelem;
}

#ifdef __DAVO__
static void battle_net_ipt(const char *waniface)
{
	struct in_addr ip, mask, man_ip;
	int i;

	getInAddr("br0", IP_ADDR_T, (void *)&ip);
	getInAddr("br0", NET_MASK_T, (void *)&mask);
	yecho("/proc/sys/private/sc/lo_ip", "%lu", ip.s_addr);
	yecho("/proc/sys/private/sc/lo_mask", "%lu", mask.s_addr);

	if (getInAddr(waniface, IP_ADDR_T, (void *)&man_ip) && man_ip.s_addr)
		yecho("/proc/sys/private/sc/man_ip", "%lu", man_ip.s_addr);

	ip.s_addr &= mask.s_addr;
	mask.s_addr = ntohl(mask.s_addr);
	for (i = 0; i < 32; i++)
		if ((mask.s_addr >> i) & 1)
			break;

	yexecl(NULL, "iptables -I FORWARD -p udp --dport 6112 -j ACCEPT");
	yexecl(">/dev/null 2>&1", "iptables -t nat -N sc-in");
	yexecl(">/dev/null 2>&1", "iptables -t nat -N sc-out");
	yexecl(NULL, "iptables -t nat -I POSTROUTING -p udp "
	       "-s %s/%d --sport 6112 --dport 6112 -j sc-out", inet_ntoa(ip), 32 - i);
}
#endif

#ifdef DV_HAIRPIN_ROUTING
static void hairpin_routing_prepare(char *br_interface, char *lan_ip, char *lan_nm)
{
	yexecl(NULL, "iptables -t nat -A PREROUTING -i %s -j PRE_HR\n", br_interface);
	yexecl(NULL, "iptables -t nat -A POSTROUTING -o %s -s %s/%s -j POST_HR\n", br_interface, lan_ip, lan_nm);
}

static void hairpin_routing_start(char *lan_ip, char *lan_nm)
{
	int i;
	int count;
	char *args[6];
	char name[20], val[80];
	char wan_ip[20];
	const char **proto;

	yexecl(NULL, "iptables -t nat -F PRE_HR\n");
	yexecl(NULL, "iptables -t nat -F POST_HR\n");

	yfcat("/var/wan_ip", "%s", wan_ip);

	// port forwarding
	count = nvram_atoi("PORTFW_TBL_NUM", 0);
	if (nvram_match("PORTFW_ENABLED", "1") && (count > 0)) {
		for (i=0; i<count; i++) {
			snprintf(name, sizeof(name), "PORTFW_TBL%d", i+1);
			nvram_get_r(name, val, sizeof(val));
			if (ystrargs(val, args, _countof(args), ",|\r\n", 0) >= 5) {
				if (strcmp(args[3], "1") == 0)
					proto = proto_list(PROTO_TCP);
				else if (strcmp(args[3], "2") == 0)
					proto = proto_list(PROTO_UDP);
				else
					proto = proto_list(PROTO_BOTH);
				for (; *proto; proto++) {
					yexecl(NULL, "iptables -t nat -A PRE_HR -d %s -p %s --dport %s:%s -j DNAT --to %s:%s\n",
							wan_ip, *proto, args[1], args[2], args[0], args[4]);
					yexecl(NULL, "iptables -t nat -A POST_HR -p %s --dport %s:%s -s %s/%s -d %s -j MASQUERADE\n",
							*proto, args[4], args[4], lan_ip, lan_nm, args[0]);
				}
			}
		}
	}

	// dmz
	if (nvram_match("DMZ_ENABLED", "1") && nvram_invmatch("DMZ_HOST", "0.0.0.0")) {
		char dmz_ip[20];

		nvram_get_r("DMZ_HOST", dmz_ip, sizeof(dmz_ip));

		yexecl(NULL, "iptables -t nat -A PRE_HR -p tcp -d %s -j DNAT --to %s\n", wan_ip, dmz_ip);
		yexecl(NULL, "iptables -t nat -A PRE_HR -p udp -d %s -j DNAT --to %s\n", wan_ip, dmz_ip);
		yexecl(NULL, "iptables -t nat -A PRE_HR -p icmp -d %s -j DNAT --to %s\n", wan_ip, dmz_ip);
		yexecl(NULL, "iptables -t nat -A POST_HR -p tcp -s %s/%s -d %s -j MASQUERADE\n", lan_ip, lan_nm, dmz_ip);
		yexecl(NULL, "iptables -t nat -A POST_HR -p udp -s %s/%s -d %s -j MASQUERADE\n", lan_ip, lan_nm, dmz_ip);
		yexecl(NULL, "iptables -t nat -A POST_HR -p icmp -s %s/%s -d %s -j MASQUERADE\n", lan_ip, lan_nm, dmz_ip);
	}
}
#endif

int setFirewallIptablesRules(int argc, char** argv)
{
	int opmode=-1;
	int wan_dhcp=-1;
	char iface[20], *pInterface="eth1";
	char *pInterface_wanPhy="eth1";
	char Interface_wanPhy[20]="eth1";
	int wlaniface=0, get_wanip=0;
	struct in_addr wanaddr;
	char IpAddr[30];
	char WanIpAddr[30], *strWanIp;
	char WanGwIpAddr[30];
	char WanPhyIpAddr[30];
	int intVal=0, natEnabled=0;
	int intVal1=0;
	int intVal2 = 0;
	int dyn_rt_support=0;
	int intVal_num=0;
#ifdef MULTI_PPPOE
	int isNeedSetOnce = 1;
#endif
	int wan_type=0;
	//add for DMZ
	//echo 192.168.1.0/24 >/etc/ppp/br0_info
	char *bInterface = "br0";
	int get_br0ip =0;
	int get_br0mask =0;
	char Br0NetSectAddr[30];
	struct in_addr br0addr,br0mask;
	unsigned int numofone ;
	char NumStr[10];
#ifdef CONFIG_RTL_HW_NAPT
	//int ivalue = 0;
#endif
#ifdef _ALPHA_DUAL_WAN_SUPPORT_
	struct in_addr ipaddr;
	char ipaddr_str[16];
#endif
	char nip[30], lan_nip[30], val[16];
	char buffer[20];

	printf("Init Firewall Rules....\n");
#ifdef MULTI_PPPOE

	wait_lable:
	if (isFileExist("/etc/ppp/firewall_lock") == 1) {
		system("rm -f /etc/ppp/firewall_lock");
	}else{
		sleep(1);
		goto wait_lable;
	}
	if(argc >=4 && argv[3] && (!strncmp(argv[3],"ppp",3)))
	{
		if(!isFileExist("/etc/ppp/hasPppoedevice"))
		{
			system("echo 1 > /etc/ppp/hasPppoedevice");
			isNeedSetOnce = 1;
		}else{
			isNeedSetOnce = 0;
		}
	}
#endif
	nvram_get_r("IP_ADDR", lan_nip, sizeof(lan_nip));
	memset(WanPhyIpAddr,'\0',30);
	apmib_get(MIB_OP_MODE, (void *)&opmode);
	apmib_get(MIB_WAN_DHCP, (void *)&wan_dhcp);
	if(opmode == WISP_MODE){
		apmib_get(MIB_WISP_WAN_ID, (void *)&wlaniface);
		sprintf(iface, "wlan%d", wlaniface);
#if defined(CONFIG_SMART_REPEATER)
		getWispRptIfaceName(iface,wlaniface);
		//strcat(iface, "-vxd");
#endif
		pInterface = iface;
		pInterface_wanPhy=iface;
		if (wan_dhcp == PPPOE || wan_dhcp == PPTP || wan_dhcp == L2TP )
#ifdef MULTI_PPPOE
			if(argc >=4 && argv[3])
				pInterface = argv[3];
			else
				pInterface="ppp0";
#else
#ifdef SUPPORT_ZIONCOM_RUSSIA
			if(argc!=-1)
#endif
			pInterface="ppp0";
#endif
	} else {
		if (opmode == GATEWAY_MODE) {
			if (wan_dhcp == PPPOE || wan_dhcp == PPTP || wan_dhcp == L2TP || wan_dhcp == USB3G)
#ifdef MULTI_PPPOE
			if (argc >= 4 && argv[3])
				pInterface = argv[3];
			else
				pInterface = "ppp0";
#else
#if defined(SUPPORT_ZIONCOM_RUSSIA) || defined(_ALPHA_DUAL_WAN_SUPPORT_)
			if (argc != -1)
#endif
			pInterface = "ppp0";
#endif
		} else if (opmode == BRIDGE_MODE) {
			pInterface = "br0";
		}
	}

	get_wanip = getInAddr(pInterface, IP_ADDR_T, (void *)&wanaddr);
	if( get_wanip ==0){   //get wan ip fail
		printf("No wan ip currently!\n");
		goto EXIT_setFirewallIptablesRules;
	}else{
		strWanIp = inet_ntoa(wanaddr);
		strcpy(WanIpAddr, strWanIp);
	}

    killall(SIGTERM, "arp_defender");

    if (opmode == GATEWAY_MODE) {
        memset(WanGwIpAddr, 0, sizeof(WanGwIpAddr));
        yfcat("/var/gateway", "%s", WanGwIpAddr);

        if (nvram_atoi("x_ARP_DEFENDER_ENABLE", 0))
            yexecl(NULL, "/bin/arp_defender %s %s", WanGwIpAddr, pInterface);
            //yexecl(NULL, "/bin/arpon -q -i %s -D", wan_interface);
    }

#ifdef _ALPHA_DUAL_WAN_SUPPORT_
	memset(&ipaddr, 0, sizeof(ipaddr));
	if(wan_dhcp == PPPOE)
	{
		getInAddr(Interface_wanPhy,IP_ADDR_T,(void *)&ipaddr);
		if(ipaddr.s_addr>0)
			strcpy(ipaddr_str, inet_ntoa(ipaddr));
	}
#endif

    yexecl(NULL, "iptables -N ACL");
#ifdef DV_HAIRPIN_ROUTING
    yexecl(NULL, "iptables -t nat -N PRE_HR");
    yexecl(NULL, "iptables -t nat -N POST_HR");
#endif

	//flush fast natp table
	//RunSystemCmd("/proc/net/flush_conntrack", "echo", "1", NULL_STR);
#ifdef MULTI_PPPOE
	if(isNeedSetOnce)
		setRulesWithOutDevice(opmode,wan_dhcp,pInterface_wanPhy,Interface_wanPhy);
#else
		setRulesWithOutDevice(opmode,wan_dhcp,pInterface_wanPhy,Interface_wanPhy);
#endif

#if 0
	intVal = 0;
	apmib_get( MIB_WEB_WAN_ACCESS_ENABLED, (void *)&intVal);
	if(intVal==1){
		RunSystemCmd(NULL_FILE, Iptables, ADD, INPUT, _protocol, _tcp,  dport, "80:80", in, pInterface, _dest, WanIpAddr, jump, ACCEPT, NULL_STR);
#ifdef _ALPHA_DUAL_WAN_SUPPORT_
		if(ipaddr.s_addr>0)
			RunSystemCmd(NULL_FILE, Iptables, ADD, INPUT, _protocol, _tcp,	dport, "80:80", in, Interface_wanPhy, _dest, ipaddr_str, jump, ACCEPT, NULL_STR);
#endif
	}else{
		RunSystemCmd(NULL_FILE, Iptables, ADD, INPUT, _protocol, _tcp,  dport, "80:80", in, pInterface, _dest, WanIpAddr, jump, DROP, NULL_STR);
	}
#endif

	intVal = 0;
	intVal = nvram_atoi("x_fdns_enabled", 1);
	if (intVal) {
		if (opmode == GATEWAY_MODE) {
			//wifi.skbroadband.co.kr
			yexecl(NULL, "iptables -t nat -A PREROUTING -i %s -p udp --dport 53 -m string --algo kmp --hex-string \"|04776966690b736b62726f616462616e6402636f026b72|\" -j DNAT --to-destination %s:53", bInterface, lan_nip);
			//wifi.skbroadband.com
			yexecl(NULL, "iptables -t nat -A PREROUTING -i %s -p udp --dport 53 -m string --algo kmp --hex-string \"|04776966690b736b62726f616462616e6403636f6d|\" -j DNAT --to-destination %s:53", bInterface, lan_nip);
		}
	}

    intVal = 0;
    intVal = atoi(nvram_get_r("WEB_WAN_ACCESS_ENABLED", val, sizeof(val)));

    nvram_get_r("SUBNET_MASK", nip, sizeof(nip));

    if (intVal) {
		if (opmode == GATEWAY_MODE) {
			yexecl(NULL, "iptables -t nat -A PREROUTING -p tcp --dport 8080 -i %s -j DNAT --to %s:80", pInterface, lan_nip);
			yexecl(NULL, "iptables -A INPUT -p tcp --dport 80 -j ACL");
		} else if (opmode == BRIDGE_MODE) {
			yexecl(NULL, "iptables -t nat -A PREROUTING -p tcp ! -d %s --dport 8080 -i %s -j DNAT --to %s:8080", lan_nip, pInterface, lan_nip);
			/* APACRTL-84  smlee 20151029 */
			if (get_repeater_mode()) {
				yexecl(NULL, "iptables -A INPUT -p tcp -i %s --dport 80 -j ACL", pInterface);
			} else {
				yexecl(NULL, "iptables -A INPUT -p tcp -i %s --dport 8080 -j ACL", pInterface);
			}
		}
    }

    //telnet
    intVal = nvram_atoi("x_telnet_enable", 0);
    if (intVal)
		enable_telnet();

    // snmp
	intVal = nvram_atoi("x_snmp_input_rate", 0);
	if (intVal > 0) {
		intVal2 = 0;
		intVal2 = nvram_atoi("DOS_BLOCK_TIME", 0);
		yexecl(NULL, "iptables -A INPUT -p udp --dport 161 -m recent --set");
		yexecl(NULL, "iptables -A INPUT -p udp --dport 161 -m recent --update "
		      "--seconds 5 --hitcount %d --blockoff %d -j DROP", intVal * 5, intVal2);
	}

    intVal = nvram_atoi("x_SNMP_ENABLE", 0);
    if (intVal > 0) {
        yexecl(NULL, "iptables -A INPUT -p udp --dport 161 -j ACL");
        //yexecl(NULL, "iptables -t nat -A PREROUTING -p udp --dport 161 -i %s -j DNAT --to %s:161", pInterface, lan_nip);
    }

    intVal = 0;

    RunSystemCmd(NULL_FILE, Iptables, ADD, INPUT, _protocol, _udp,  dport, "1900:1900", in, pInterface, _dest, "239.255.255.250", jump, DROP, NULL_STR);

#ifdef _ALPHA_DUAL_WAN_SUPPORT_
	if(ipaddr.s_addr>0)
	{
		RunSystemCmd(NULL_FILE, Iptables, ADD, INPUT, _protocol, _tcp,	dport, "!", "80:80", in, Interface_wanPhy, _dest, ipaddr_str, jump, ACCEPT, NULL_STR);
		RunSystemCmd(NULL_FILE, Iptables, ADD, INPUT, _protocol, _udp,	dport, "!", "1900:1900", in, Interface_wanPhy, _dest, ipaddr_str, jump, ACCEPT, NULL_STR);
	}
#endif

	// SNMP setting
    //#ifdef CONFIG_SNMP
    //	intVal = 0;
    //	apmib_get(MIB_SNMP_ENABLED, (void *)&intVal);
    //	if (intVal == 1) {
    //		RunSystemCmd(NULL_FILE, Iptables, ADD, INPUT, _protocol, _udp, dport, "161:161", in, pInterface, _dest, WanIpAddr, jump, ACCEPT, NULL_STR);
    //		/*???where script*/
    //		RunSystemCmd(NULL_FILE, Iptables, ADD, PREROUTING, _table, nat_table, in, pInterface, _protocol, _udp, dport, "161", _dest, WanIpAddr, jump, REDIRECT, "--to-port", "161", NULL_STR);
    //	}
    //#endif
#ifdef __DAVO__
	if (opmode == GATEWAY_MODE) {
		battle_net_ipt(pInterface);

		yecho("/proc/res_ports", "add udp 53 67 68 69 161 162 500 517 518 1720 4500 5060 6112 6667");
		yecho("/proc/res_ports", "add tcp 53 67 68 69 161 162 500 517 518 1720 4500 5060 6112 6667");
	}
#endif
    //Static Fowarding
    set_staticfwd(pInterface, WanIpAddr);

    //Port Fowarding
    nvram_get_r_def("PORTFW_ENABLED", buffer, sizeof(buffer), "0");
    intVal = atoi(buffer);

    memset(buffer, 0x00, sizeof(buffer));

    nvram_get_r_def("PORTFW_TBL_NUM", buffer, sizeof(buffer), "0");
    intVal_num = atoi(buffer);

    memset(buffer, 0x00, sizeof(buffer));

//	apmib_get(MIB_PORTFW_ENABLED,  (void *)&intVal);
//	apmib_get(MIB_PORTFW_TBL_NUM, (void *)&intVal_num);
	if(intVal==1 && intVal_num>0){
		setPortForward(pInterface, WanIpAddr);
	}

#if 0
	// Move to set_init
	apmib_get(MIB_CUSTOM_PASSTHRU_ENABLED, (void *)&intVal);
	RunSystemCmd("/proc/custom_Passthru", "echo", (intVal & 0x1)?"1":"0", NULL_STR);
#endif


	//dzh modify
	apmib_get(MIB_WAN_DHCP,(void *)&wan_type);
	if(wan_type==PPTP)
	{
		RunSystemCmd(NULL_FILE, Iptables, ADD, INPUT, _protocol, "47", in, pInterface_wanPhy, jump, ACCEPT, NULL_STR);
		RunSystemCmd(NULL_FILE, Iptables, ADD, INPUT, _protocol, _tcp, sport ,"1723" ,in, pInterface_wanPhy, jump, ACCEPT, NULL_STR);
	}
	else if(wan_type==L2TP)
	{
		RunSystemCmd(NULL_FILE, Iptables, ADD, INPUT, _protocol, _udp, sport ,"1701" ,in, pInterface_wanPhy, jump, ACCEPT, NULL_STR);
	}
	apmib_get(MIB_VPN_PASSTHRU_IPSEC_ENABLED, (void *)&intVal);
	if(intVal ==0){
#ifdef MULTI_PPPOE
	if(isNeedSetOnce){
#endif
		RunSystemCmd(NULL_FILE, Iptables, ADD, FORWARD, _protocol, _udp, dport, "500", jump, DROP, NULL_STR);
#ifdef MULTI_PPPOE
	}
#endif
	}else{
		RunSystemCmd(NULL_FILE, Iptables, ADD, FORWARD, _protocol, _udp, dport, "500", in ,pInterface, out, "br0", jump, ACCEPT, NULL_STR);
	}

	if((wan_dhcp == DHCP_CLIENT && !sdmz_configured(NULL, 0)) || wan_dhcp == PPTP || wan_dhcp == L2TP)
	{
		yexecl(NULL, "iptables -I INPUT -i %s -p udp --dport 68 -j ACCEPT", pInterface);
		//RunSystemCmd(NULL_FILE, Iptables, ADD, INPUT, _protocol, _udp, dport, "68", in ,pInterface, jump, ACCEPT, NULL_STR);
	}

    //	if (wan_dhcp == DHCP_CLIENT && !sdmz_configured(NULL, 0))
    //		yexecl(NULL, "iptables -I INPUT -i %s -p udp --dport 68 -j ACCEPT", pInterface);

    //add for DMZ
	get_br0ip = getInAddr(bInterface, IP_ADDR_T,(void *)&br0addr);
	if(get_br0ip ==0 ){
		printf("No ip currently!\n");
		goto EXIT_setFirewallIptablesRules;
	}
	get_br0mask = getInAddr(bInterface, NET_MASK_T,(void *)&br0mask);
	if( get_br0mask ==0 ){
		printf("No MASK currently!\n");
		goto EXIT_setFirewallIptablesRules;
	}
	br0addr.s_addr &= br0mask.s_addr ;
	for(numofone =0;br0mask.s_addr;++numofone)
		br0mask.s_addr &= br0mask.s_addr-1;
	sprintf (NumStr, "%d", numofone);
	strcpy(Br0NetSectAddr,inet_ntoa(br0addr));
	strcat(Br0NetSectAddr,"/");
	strcat(Br0NetSectAddr,NumStr);
	//echo 192.168.1.0/24 >/etc/ppp/br0_info
//	char *br0info[50];
#ifdef MULTI_PPPOE
	sprintf(br0info,"echo %s > /etc/ppp/br0_info",Br0NetSectAddr);
	system(br0info);
#endif

    //apmib_get(MIB_DMZ_ENABLED, (void *)&intVal);
    intVal = 0;
    nvram_get_r_def("DMZ_ENABLED", buffer, sizeof(buffer), "0");
    intVal = atoi(buffer);

	if (intVal == 1) {
		//apmib_get(MIB_DMZ_HOST, (void *)&nip);
		//strIp = inet_ntoa(*((struct in_addr *)buffer));
        nvram_get_r("DMZ_HOST", buffer, sizeof(buffer));
        strncpy(IpAddr, buffer, sizeof(buffer));
        if(strcmp(IpAddr, "0.0.0.0")){
            strncpy(iface, "eth1", 4);
            iface[4] = '\0';
            printf("iface : %s\n", iface);
			yexecl(NULL, "iptables -A PREROUTING -t nat -p ALL -d %s -j DNAT --to %s", WanIpAddr, IpAddr);
			yexecl(NULL, "iptables -D INPUT -p tcp --dport 80 -i %s -d %s -j DROP", pInterface, WanIpAddr);
			yexecl(NULL, "iptables -A FORWARD -i %s -d %s -p ALL -j ACCEPT", iface, IpAddr);
            //yexecl(NULL, "iptables -A POSTROUTING -t nat -s %s -d %s -j SNAT --to %s");
			//RunSystemCmd(NULL_FILE, Iptables, ADD, POSTROUTING, _table, nat_table,_src,Br0NetSectAddr,_dest, IpAddr, jump, "SNAT","--to", WanIpAddr, NULL_STR);
		}
	}

	put_acl_chain();

	intVal = 0;
	apmib_get( MIB_PING_WAN_ACCESS_ENABLED, (void *)&intVal);
	if(intVal==1){
		RunSystemCmd(NULL_FILE, Iptables, ADD, INPUT, _protocol, _icmp, icmp_type, echo_request,  in, pInterface, _dest, WanIpAddr, jump, ACCEPT, NULL_STR);
		//RunSystemCmd(NULL_FILE, Iptables, ADD, INPUT, _protocol, _icmp, icmp_type, echo_request,  in, pInterface, jump, ACCEPT, NULL_STR);
#ifdef _ALPHA_DUAL_WAN_SUPPORT_
		if(ipaddr.s_addr>0)
			RunSystemCmd(NULL_FILE, Iptables, ADD, INPUT, _protocol, _icmp, icmp_type, echo_request,  in, Interface_wanPhy, _dest, ipaddr_str, jump, ACCEPT, NULL_STR);
#endif
	}else{
		RunSystemCmd(NULL_FILE, Iptables, ADD, INPUT, _protocol, _icmp, icmp_type, echo_request,  in, pInterface, _dest, WanIpAddr, jump, DROP, NULL_STR);
	}

	intVal = 0;
	apmib_get( MIB_IGMP_PROXY_DISABLED, (void *)&intVal);
	if(intVal==0){
#ifdef SUPPORT_ZIONCOM_RUSSIA
		RunSystemCmd(NULL_FILE, Iptables, ADD, INPUT, _protocol, "2", in, Interface_wanPhy, jump, ACCEPT, NULL_STR);
		RunSystemCmd(NULL_FILE, Iptables, ADD, FORWARD, in, Interface_wanPhy, jump, ACCEPT, NULL_STR);
#else
		RunSystemCmd(NULL_FILE, Iptables, ADD, INPUT, _protocol, "2", in, pInterface, jump, ACCEPT, NULL_STR);
#endif
		RunSystemCmd(NULL_FILE, Iptables, ADD, FORWARD, _protocol, _udp, match, _udp, in, pInterface, "--destination" , "224.0.0.0/4", jump, ACCEPT, NULL_STR);
		apmib_get( MIB_WAN_DHCP, (void *)&intVal);
		//if wan is pptp(4) or l2tp(6), add this rule to permit multicast transter from wan to lan
		if(intVal==4 || intVal==6){
#ifdef MULTI_PPPOE
	if(isNeedSetOnce){
#endif
			RunSystemCmd(NULL_FILE, Iptables, ADD, FORWARD, _protocol, _udp, match, _udp, in, Interface_wanPhy, "--destination" , "224.0.0.0/4", jump, ACCEPT, NULL_STR);
#ifdef MULTI_PPPOE
		}
#endif
		}
	}

//modify
	RunSystemCmd(NULL_FILE, Iptables, ADD, INPUT, in, "br0", jump, ACCEPT, NULL_STR);
	RunSystemCmd(NULL_FILE, Iptables, INSERT, INPUT, in, "lo", jump, ACCEPT, NULL_STR);
//	RunSystemCmd(NULL_FILE, Iptables, ADD, INPUT, in, NOT, pInterface, jump, ACCEPT, NULL_STR);

#ifdef CONFIG_RTK_VLAN_WAN_TAG_SUPPORT
 	apmib_get( MIB_VLAN_WAN_BRIDGE_TAG, (void *)&intVal);
	if(intVal!=0)
	{
    	RunSystemCmd(NULL_FILE, Iptables, ADD, INPUT, in, "br1", jump, ACCEPT, NULL_STR);
	}
#endif

	RunSystemCmd(NULL_FILE, Iptables, ADD, FORWARD, _protocol, "50", in, pInterface, out, "br0", jump, ACCEPT, NULL_STR);
	RunSystemCmd(NULL_FILE, Iptables, ADD, FORWARD, in, pInterface, match, mstate, state, RELATED_ESTABLISHED, jump, ACCEPT, NULL_STR);

	if(wan_dhcp == L2TP)
		RunSystemCmd(NULL_FILE, Iptables, ADD, FORWARD, in, pInterface_wanPhy, match, mstate, state, RELATED_ESTABLISHED, jump, ACCEPT, NULL_STR);
	/*when layered driver enable, permit all icmp packet but icmp request...*/
	//RunSystemCmd(NULL_FILE, Iptables, ADD, INPUT, _protocol, "2", in, pInterface, jump, ACCEPT, NULL_STR);



	if(dyn_rt_support ==1){
		apmib_get(MIB_NAT_ENABLED, (void *)&natEnabled);
#if defined(CONFIG_ROUTE)
		apmib_get(MIB_RIP_ENABLED, (void *)&intVal);
		apmib_get(MIB_RIP_WAN_RX, (void *)&intVal1);
#endif
		if(natEnabled==1 && intVal==1){
			if(intVal1==1){
				RunSystemCmd(NULL_FILE, Iptables, ADD, INPUT, in, pInterface, _protocol, _udp, dport, "520", jump, ACCEPT, NULL_STR);
			}
		}
	}

	if (opmode != BRIDGE_MODE) {
		RunSystemCmd(NULL_FILE, Iptables, _table, nat_table, ADD, POSTROUTING, out, pInterface, jump, MASQUERADE, NULL_STR);
	}

	//fix the issue of WISP mode+PPPoE, lan pc can't access DUT
	if(opmode == WISP_MODE && wan_dhcp == PPPOE && isFileExist("/etc/ppp/link"))
	{
		struct in_addr ip_addr, subnet_mask, net_addr;
		char netIp[16], maskIp[16], ipAddr[16];
		char cmdbuf[128];

		apmib_get(MIB_IP_ADDR,  (void *)&ip_addr);
		sprintf(ipAddr, "%s", inet_ntoa(ip_addr));
//		printf("%s:%d ipAddr=%s\n",__FUNCTION__,__LINE__,ipAddr);
		apmib_get(MIB_SUBNET_MASK,	(void *)&subnet_mask);
		sprintf(maskIp, "%s", inet_ntoa(subnet_mask));
//		printf("%s:%d maskIp=%s\n",__FUNCTION__,__LINE__,maskIp);
		net_addr.s_addr=ip_addr.s_addr & subnet_mask.s_addr;
		sprintf(netIp, "%s", inet_ntoa(net_addr));
//		printf("%s:%d netIp=%s\n",__FUNCTION__,__LINE__,netIp);

		sprintf(cmdbuf, "route del -net %s netmask %s dev br0 > /dev/null 2>&1", netIp, maskIp);
		system(cmdbuf);

		sprintf(cmdbuf, "route add -net %s netmask %s dev br0", netIp, maskIp);
		system(cmdbuf);
	}

#ifdef CONFIG_IPV6
	//add rule to avoid DOS attack
#ifdef SUPPORT_DEFEAT_IP_SPOOL_DOS
	RunSystemCmd(NULL_FILE, Ip6tables, POLICY, INPUT, DROP, NULL_STR);
	RunSystemCmd(NULL_FILE, Ip6tables, INSERT, INPUT, in, bInterface, _src, "fe80::/64", jump, ACCEPT, NULL_STR);

	char prefix_buf[256];
	if(isFileExist("/var/radvd.conf"))
	{
		FILE *fp=NULL;
		char line_buf[128];
		char *pline=NULL;

		if((fp=fopen("/var/radvd.conf", "r"))!=NULL)
		{
			while(fgets(line_buf, sizeof(line_buf), fp))
			{
				line_buf[strlen(line_buf)-1]=0;
				if((pline=strstr(line_buf, "prefix"))!=NULL)
				{
					strcpy(prefix_buf, line_buf+7);
					RunSystemCmd(NULL_FILE, Ip6tables, ADD, INPUT, in, bInterface, _src, prefix_buf, jump, ACCEPT, NULL_STR);
				}
			}
			fclose(fp);
		}
	}

	dhcp6sCfgParam_t dhcp6sCfgParam;
	memset(&dhcp6sCfgParam, 0, sizeof(dhcp6sCfgParam));
	apmib_get(MIB_IPV6_DHCPV6S_PARAM,(void *)&dhcp6sCfgParam);

	if(dhcp6sCfgParam.enabled)
	{
		if(dhcp6sCfgParam.addr6PoolS && dhcp6sCfgParam.addr6PoolE)
		{
			sprintf(prefix_buf, "%s-%s", dhcp6sCfgParam.addr6PoolS, dhcp6sCfgParam.addr6PoolE);
			RunSystemCmd(NULL_FILE, Ip6tables, ADD, INPUT, in, bInterface, match, ip_range, src_rnage, prefix_buf, jump, ACCEPT, NULL_STR);
		}
	}
	RunSystemCmd(NULL_FILE, Ip6tables, ADD, INPUT, in, bInterface, jump, DROP, NULL_STR);
#endif
#endif
#ifdef DV_HAIRPIN_ROUTING
	hairpin_routing_prepare(bInterface, lan_nip, nip);
	hairpin_routing_start(lan_nip, nip);
#endif
/*
	RunSystemCmd("/proc/sys/net/ipv4/ip_conntrack_max", "echo", "1280", NULL_STR);
	RunSystemCmd("/proc/sys/net/ipv4/netfilter/ip_conntrack_tcp_timeout_established", "echo", "600", NULL_STR);
	RunSystemCmd("/proc/sys/net/ipv4/netfilter/ip_conntrack_udp_timeout", "echo", "60", NULL_STR);
	RunSystemCmd("/proc/sys/net/ipv4/netfilter/ip_conntrack_tcp_timeout_time_wait", "echo", "5", NULL_STR);
	RunSystemCmd("/proc/sys/net/ipv4/netfilter/ip_conntrack_tcp_timeout_close", "echo", "5", NULL_STR);
*/

//hyking:packet from wan is NOT allowed
#if 0 //defined(CONFIG_RTL_LAYERED_DRIVER_ACL)
	RunSystemCmd(NULL_FILE, "iptables", ADD, INPUT, jump, ACCEPT, NULL_STR);
#else
//	RunSystemCmd(NULL_FILE, "iptables", ADD, INPUT, "!", in, pInterface, jump, ACCEPT, NULL_STR);
#endif

	//RunSystemCmd("/proc/sys/net/ipv4/conf/eth1/arp_ignore", "echo", "1", NULL_STR);
#ifdef MULTI_PPPOE
	if(argc >=4 && argv[3])
		set_QoS(opmode, wan_dhcp, wlaniface,argv[3]);
	else
		set_QoS(opmode, wan_dhcp, wlaniface,"ppp0");
#else
	set_QoS(opmode, wan_dhcp, wlaniface);

#endif

#ifdef CONFIG_RTK_VOIP
	set_voip_parameter(pInterface);
#endif

#ifdef MULTI_PPPOE
	setMulPppoeRules(argc,argv);
#endif
#ifdef CONFIG_RTL_HW_NAPT
		update_hwnat_setting();
#endif

	#if defined(CONFIG_APP_TR069)
// enable tr069 connection request rule
	SetRuleFortr069(pInterface, WanIpAddr);
	#endif //#if defined(CONFIG_APP_TR069)
	system("echo 1 > /etc/ppp/firewall_lock");

#ifdef USE_MINIUPNPD_V1_8
	apmib_get(MIB_UPNP_ENABLED, (void *)&intVal);
	if(intVal==1)
		system("/bin/iptables_init.sh > /dev/null 2>&1");
#endif

EXIT_setFirewallIptablesRules:
	RunSystemCmd("/proc/sys/net/ipv4/ip_forward", "echo", "1", NULL_STR);
	return 0;

}

#ifdef CONFIG_RTL_HW_NAPT
int update_hwnat_setting(void)
{
	int opmode = 0;
	int score;

	if (!apmib_get(MIB_OP_MODE, (void *)&opmode))
		goto error;

//for wisp and bridge(?) mode
	{
		if (opmode == BRIDGE_MODE) {
			yecho("/proc/hw_nat", "2");
			return 0;
		} else if (opmode == WISP_MODE) {
			yecho("/proc/hw_nat", "3");
			return 0;
		}
	}
	if (opmode == GATEWAY_MODE && (score = nvram_atoi("x_napt_hash_score", -1)) > 0)
		yecho("/proc/sys/private/napt_hash_score", "%d", score);
//for subMask
	{
		int ivalue = 0;
		if (!apmib_get(MIB_SUBNET_MASK, (void *)&ivalue))
			goto error;
		if ((ivalue & HW_NAT_LIMIT_NETMASK) != HW_NAT_LIMIT_NETMASK) {
			yecho("/proc/hw_nat", "-1");
			return 0;
		}
	}
#ifdef CONFIG_RTK_VOIP
	//for voip
	{
		voipCfgParam_t voipCfgParam = { 0 };
		if (!apmib_get(MIB_VOIP_CFG, (void *)&voipCfgParam))
			goto error;

		if (!voipCfgParam.hwnat_enable) {
			yecho(HW_NAT_FILE, "0");
			return 0;
		}
	}
#endif

//for url filter
	{
		int urlfilter_enable = 0, urlfilter_num = 0;
		if (!apmib_get(MIB_URLFILTER_ENABLED, (void *)&urlfilter_enable))
			goto error;
		if (!apmib_get(MIB_URLFILTER_TBL_NUM, (void *)&urlfilter_num))
			goto error;
		if (opmode == GATEWAY_MODE && urlfilter_enable != 0
		    && urlfilter_num > 0) {
			yecho("/proc/hw_nat", "0");
			return 0;
		}
	}
//for dos
	{
		int dos_enabled = 0;
		if (!apmib_get(MIB_DOS_ENABLED, (void *)&dos_enabled))
			goto error;
		if (dos_enabled > 0) {
			yecho("/proc/hw_nat", "0");
			return 0;
		}
	}

//for l2tp,pptp
	{
		int wan_dhcp;

		apmib_get(MIB_WAN_DHCP, (void *)&wan_dhcp);
		if ((wan_dhcp == L2TP) || (wan_dhcp == PPTP)) {
			yecho("/proc/hw_nat", "0");
			return 0;
		}
	}
	yecho(HW_NAT_FILE, "1");
	return 0;
 error:
	printf("update hardware nat error!\n");
	yecho("/proc/hw_nat", "-1");
	return -1;
}
#endif
