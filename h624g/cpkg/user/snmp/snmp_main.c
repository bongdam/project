#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <sys/errno.h>
#include <time.h>
#include <unistd.h>
#include <getopt.h>
#include <signal.h>
#include <netdb.h>
#include <wait.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
/*DAVO begin*/
#include <syslog.h>
/*DAVO end*/
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>

#include "snmp_main.h"
#include "skbb_api.h"
#include "snmp_trap.h"
#include "skbb.h"
#include "snmp_response.h"
#include "./engine/asn1.h"
#include "./engine/snmp.h"
#include "./engine/agt_engine.h"
#include "./engine/snmp_community.h"
#include "defines.h"
#if defined(__STATRAP_EVENT__)
/* jihyun@davo160202 jcode#7 -*/
#include "../../../users/auth/include/1x_ioctl.h"
#endif
#include <bcmnvram.h>
#include "misc.h"
#include "snmp_traptype.h"
#include <sys/sysinfo.h>
#include <libytool.h>


#if defined(__STATRAP_EVENT__)
/* jihyun@davo160202 jcode#7 -*/

extern void trap_wl_stainfo(struct wl_info_t *psta_info, struct nlkevent_t *pnlk);
extern int init_wlmonitor(struct wl_info_t *pwl_info);
extern int netlink_fd(void);
extern void catcher_stainfo_fromnetlink(struct wl_info_t *pwl_info, int nfs);

#endif

long get_flash_utiliz(void);
int getInAddr(char *interface, ADDR_T type, void *pAddr);
void get_preWlanSSIDMode(void);
extern int getWlBssInfo(char *interface, bss_info *pInfo);

int root_vwlan_disable[MAX_WLAN_INTF_NUM][2];
int cpeping_trapmode_enable;
int snmpAction = SNMP_NO_ACTION;
int glbSnmpSocket = 0;
int wlsta_pid;
int cpeping_pid;
int g_wl_reset_wlstatebit;
int dns_mode;
int ping_pid;

#if defined(__STATRAP_EVENT__)
/* jihyun@davo160202 jcode#7 -*/

static struct wl_info_t wl_info[MAX_MONITOR_WLINTF]=
{
	{MONITOR_ACTIVE, 	-1, "wlan0",		"", {0} }, //5G Main
	{MONITOR_ACTIVE,	-1, "wlan0-va0", 	"", {0} }, //SK_VoIP
	{MONITOR_DEACTIVE,	-1, "wlan0-va1", 	"", {0} }, //T wifi home
	{MONITOR_DEACTIVE, 	-1, "wlan0-va2", 	"", {0} }, //anyway
	{MONITOR_ACTIVE, 	-1, "wlan0-va3", 	"", {0} }, //HandOver
	{MONITOR_ACTIVE, 	-1, "wlan1",		"", {0} }, //2G Main
	{MONITOR_ACTIVE, 	-1, "wlan1-va0", 	"", {0} }, //SK_VoIP
	{MONITOR_DEACTIVE, 	-1, "wlan1-va1", 	"", {0} }, //T wifi home
	{MONITOR_DEACTIVE, 	-1, "wlan1-va2", 	"", {0} }, //anyway
	{MONITOR_ACTIVE, 	-1, "wlan1-va3", 	"", {0} }, //reserved
};
#endif

/* The structure of trap information list */
typedef struct {
	char trap_srv[64];
	char trap_kind[64];
	char trap_file[64];
	char trap_tmp1[64];
} TIL, *pTIL;

typedef struct {
	char smashSnmpMode[MAX_PARAM_LEN];
	char smashSnmpGetCommunity[MAX_PARAM_LEN];
	char smashSnmpSetCommunity[MAX_PARAM_LEN];
	char smashSnmpTrapMode[MAX_PARAM_LEN];
	char smashSnmpTrapCommunity[MAX_PARAM_LEN];
	char smashSnmpTrapAddress[MAX_PARAM_LEN];
	char smashSnmpAuthenMode[MAX_PARAM_LEN];
} CFGDEF;

TDV_SNMP_CFG dvsnmp_cfg;

/******************************************************
*   The functions 'get_getcommunity()' and 'get_setcoumminty' are
*   used by /engine/agt_engine.c
*
*******************************************************/

char *get_getcommunity()
{
	return dvsnmp_cfg.getcommunity;
}

void set_getcommunity(const char *val)
{
	strncpy(dvsnmp_cfg.getcommunity, val, sizeof(dvsnmp_cfg.getcommunity));
}

char *get_setcommunity()
{
	return dvsnmp_cfg.setcommunity;
}

void set_setcommunity(const char *val)
{
	strncpy(dvsnmp_cfg.setcommunity, val, sizeof(dvsnmp_cfg.setcommunity));
}

void set_trapserver(char *serv_ip)
{
	memset(dvsnmp_cfg.trapserver[0], 0, DVSNMP_MAX_TRAP_SERVER_LEN);
	strncpy(dvsnmp_cfg.trapserver[0], serv_ip, DVSNMP_MAX_TRAP_SERVER_LEN);
}

char *get_trapserver(void)
{
	return dvsnmp_cfg.trapserver[0];
}

void set_trapport(int port)
{
	dvsnmp_cfg.trapport[0] = port;
}

int get_trapport(void)
{
	return dvsnmp_cfg.trapport[0];
}

void setSmashSnmpInfo(char *name, char *value, int length)
{
	if (setValue(name, value) < 0) {
		printf("set error!\n");
	}
}

char *getSmashSnmpInfo(char *target, char *name, int length)
{
	if (target != NULL) {
		snprintf(target, length, "%s", getValue(name));
		return target;

	} else {
		return getValue(name);
	}
}

void commitSmashSnmpInfo(void)
{
	commitValue();
}

void Community_parse(COM_T *com)
{
	char buf[20];
	char *ptr;
	sprintf(buf, "%s", getValue("x_SNMP_COM1"));
	com[0].enable = (buf[0] == '1')? 1:0;
	com[0].type = (buf[2] == '0')? 0:1;   //read_type -> 0 / write_type -> 1
	ptr = getValue("x_SNMP_GET_COMMUNITY");
	if(!ptr)
		strcpy(com[0].Community, "iptvshro^_");
	else
		strcpy(com[0].Community, ptr);

	sprintf(buf, "%s", getValue("x_SNMP_COM2"));
	com[1].enable = (buf[0] == '1')? 1:0;
	com[1].type = (buf[2] == '1')? 1:0;   //read_type -> 0 / write_type -> 1
	ptr = getValue("x_SNMP_SET_COMMUNITY");
	if(!ptr)
		strcpy(com[1].Community, "iptvshrw^_");
	else
		strcpy(com[1].Community, ptr);
}

void load_config(void)
{
	int i;
	char *trap_serv;
	char buff[80];
	char trap_ip[32];
	int ipaddr;
	COM_T com_info[2];

	dns_mode = atoi(getValue("DNS_MODE"));
	Community_parse(&com_info[0]);

	//default value
	snprintf(dvsnmp_cfg.getcommunity, DVSNMP_MAX_COMMUNITY_LEN, "%s", getValue("x_SNMP_GET_COMMUNITY")? :"iptvshro^_");
	snprintf(dvsnmp_cfg.setcommunity, DVSNMP_MAX_COMMUNITY_LEN, "%s", getValue("x_SNMP_SET_COMMUNITY")? :"iptvshrw^_");

	if(com_info[0].enable && !com_info[0].type){	//enabled && read_only
		sprintf(dvsnmp_cfg.getcommunity, "%s", com_info[0].Community);
		if(com_info[1].enable && com_info[1].type)  //enabled && read_write
			sprintf(dvsnmp_cfg.setcommunity, "%s", com_info[1].Community);
	}
	else if(com_info[0].enable && com_info[0].type){ //enabled && read_write
		sprintf(dvsnmp_cfg.setcommunity, "%s", com_info[0].Community);
		if(com_info[1].enable && !com_info[1].type)  //enabled && read_only
			sprintf(dvsnmp_cfg.getcommunity, "%s", com_info[1].Community);
	}

	if(!com_info[0].enable && com_info[1].enable){
		if(!com_info[1].type)						//read_only
			sprintf(dvsnmp_cfg.getcommunity, "%s", com_info[1].Community);
		else 								//read_write
			sprintf(dvsnmp_cfg.setcommunity, "%s", com_info[1].Community);
	}

	snprintf(dvsnmp_cfg.trpcommunity, DVSNMP_MAX_COMMUNITY_LEN, "%s", getValue("x_SNMP_TRAP_COMMUNITY")? :"iptvshrw^_");
	snprintf(dvsnmp_cfg.snmp_authen_mode, MAX_PARAM_LEN, "%s", getValue("x_SNMP_TRAP_AUTH_MODE")? :"0");
	snprintf(buff, sizeof(buff), "%s", getValue("x_SNMP_PORT"));
	if((dvsnmp_cfg.snmpport = atoi(buff)) <= 0)
		dvsnmp_cfg.snmpport = 161;

	sprintf(buff, "%s", getValue("x_SNMP_TRAP_ENABLE")? :"1");

	if (!strcmp(buff, "1")) {
		for (i = 0; i < DVSNMP_MAX_TRAP_SERVER; i++) {
			trap_serv = getValue("x_SNMP_TRAP_SERVER");
			if (trap_serv != NULL) {
				ipaddr = inet_addr(trap_serv);
				if (ipaddr == INADDR_NONE) {
					struct addrinfo host, *addr;
					struct sockaddr_in *sin;
					int errnum;

					memset(&host, 0, sizeof(struct addrinfo));
					host.ai_family = AF_UNSPEC;
					host.ai_socktype = 0;
					host.ai_flags = AI_PASSIVE;
					host.ai_protocol = 0;
					host.ai_canonname = NULL;
					host.ai_addr = NULL;
					host.ai_next = NULL;
					errnum = getaddrinfo(trap_serv, NULL, &host, &addr);
					if (errnum != 0) {
						fprintf(stderr, "[%s] getaddrinfo(): %s\n", __FUNCTION__, gai_strerror(errnum));
						break;
					}
					sin = (void*)addr->ai_addr;
					inet_ntop(AF_INET, &sin->sin_addr, trap_ip, sizeof(trap_ip));
					freeaddrinfo(addr);
				} else {
					inet_ntop(AF_INET, &ipaddr, trap_ip, sizeof(trap_ip));
				}

				strncpy(dvsnmp_cfg.trapserver[i], trap_ip,
						DVSNMP_MAX_TRAP_SERVER_LEN);
				dvsnmp_cfg.trapport[i] = 162;
			}
		}
	}
}

#if defined(__STATRAP_EVENT__)
/* jihyun@davo160202 jcode#7 -*/

static void forceout_stamon(void)
{
	struct iwreq wrq;
	int wl_ioclt_fd;
	int i, j;
	RTL_STA_INFO staInfo[MAX_SUPPLICANT_NUM + 1];
	struct nlkevent_t nlk_fake;
	struct monitor_sta_t *monitor_sta;

	if ( (wl_ioclt_fd=socket(AF_INET, SOCK_DGRAM, 0)) < 0)
		return;

	for ( i = 0; i < MAX_MONITOR_WLINTF; i++) {
		if ( !wl_info[i].monitor || wl_info[i].ifindex < 0 )
			continue;

		memset(staInfo, 0, sizeof(staInfo));
		snprintf(wrq.ifr_name, IFNAMSIZ, "%s", wl_info[i].ifname);
		wrq.u.data.pointer = (caddr_t) &staInfo[0];
		wrq.u.data.length = sizeof(RTL_STA_INFO) * (MAX_SUPPLICANT_NUM + 1);
		*((unsigned char *)wrq.u.data.pointer) = MAX_SUPPLICANT_NUM;

		if ( ioctl(wl_ioclt_fd, SIOCGIWRTLSTAINFO, &wrq) < 0 )
			continue;

		for ( j = 0; j < MAX_SUPPLICANT_NUM; j++) {
			if ( staInfo[j].aid > 0 ) {
				monitor_sta = ((struct monitor_sta_t *)&nlk_fake.event_msg[0]);
				nlk_fake.event = 2;
				nlk_fake.event_msglen = sizeof(struct monitor_sta_t);
				memset(&monitor_sta->mac[0], &staInfo[j].addr[0], 6);
				monitor_sta->link_time = staInfo[j].link_time;
				monitor_sta->tx_only_data_packets = staInfo[j].tx_only_data_packets;
				monitor_sta->rx_only_data_packets = staInfo[j].rx_only_data_packets;
				monitor_sta->tx_only_data_bytes = staInfo[j].tx_only_data_bytes;
				monitor_sta->tx_only_data_bytes_high = staInfo[j].tx_only_data_bytes_high;
				monitor_sta->rx_only_data_bytes = staInfo[j].rx_only_data_bytes;
				monitor_sta->rx_only_data_bytes_high = staInfo[j].rx_only_data_bytes_high;

				trap_wl_stainfo(&wl_info[i], &nlk_fake);
			}
		}
	}
	close(wl_ioclt_fd);
}
#endif


static void sigTermAgent(int sig)
{
	(void)sig;

#if defined(__STATRAP_EVENT__)
/* jihyun@davo160202 jcode#7 -*/
	forceout_stamon();
#endif

	if (ping_pid > 0 && !kill(ping_pid, SIGTERM))
		sleep(1);

	if (wlsta_pid > 0)
		kill(wlsta_pid, SIGTERM);

	if (cpeping_pid > 0)
		kill(cpeping_pid, SIGTERM);

	DV_UNLINK(SNMP_AGENT_PID_FILE);
	DV_EXIT(0);
}

void sigusr_handler(int sig)
{
	if(sig == SIGUSR1) {
		get_preWlanSSIDMode();
		init_securityConfig();
	}
#if !defined(__STATRAP_EVENT__)
	else if (sig == SIGUSR2) {
		monitor_wlsta_print();
	}
#endif

}

/****************************************************************************
** FUNCTION:
**
** PURPOSE:
**
** PARAMETERS:
**
** RETURNS:
**
*****************************************************************************
*/

static void child_wait_handle(int sig)
{
	(void)sig;
	waitpid(-1, NULL, WNOHANG);
}



/*
 * The main routine with which the SNMP-agent is started.
 */

/****************************************************************************
** FUNCTION:
**
** PURPOSE:
**
** PARAMETERS:
**
** RETURNS:
**
*****************************************************************************
*/
void get_preWlanSSIDMode(void)
{
	int i, j;
	char tmp[20];
	char buf[20];
	int val;

	for(j = 2; j > 0; j--)
	{
		for ( i = 0; i < 5; i++ ) {
			if (i == 0) {
				sprintf(tmp, "WLAN%d_WLAN_DISABLED", j - 1);
			}
			else {
				sprintf(tmp, "WLAN%d_VAP%d_WLAN_DISABLED", j - 1, i - 1);
			}
			sprintf(buf, "%s", getValue(tmp));
			val = strtoul(buf, NULL, 10);
			root_vwlan_disable[i][j - 1] = val;

			if( !strcmp(buf, "0") )
				g_wl_reset_wlstatebit |= (1<<i);

		}
	}
}


#define ASIC_COL_NUM 8

#define RX_ASIC						0
#define TX_ASIC						1

#define OCTETS_ASIC 				1
#define UNICAST_ASIC 				2
#define MULTICAST_ASIC 				3
#define BROADCAST_ASIC				4
#define JAB_ERROR_DISCARDS_ASIC		5
#define FRAG_ERROR_DEFERED_ASIC		6
#define FCS_PAUSE_ASIC				7

static void get_port_asicinfo(int dir, void *portinfo, int packet_kind)
{
	FILE *fp;
	char buf[256];
	char *argv[ASIC_COL_NUM];
	int i, argc;
	int f_port;
	int find_dir = -1;

	if ( packet_kind < OCTETS_ASIC || packet_kind > FCS_PAUSE_ASIC )
		return;

	buf[0] = 0;
	if ( (fp=fopen("/proc/asicCounter", "r")) ) {
		while( fgets(buf, sizeof(buf), fp)) {
			if ( (argc = parse_line(buf, argv, ASIC_COL_NUM, " :|\r\n\t")) ) {
				for ( i = 0; i < argc; i++ ) {
					if ( find_dir != TX_ASIC && !strcmp(argv[i], "Transmit") )
						find_dir = TX_ASIC;
					else if ( find_dir != RX_ASIC && !strcmp(argv[i], "Receive") )
						find_dir = RX_ASIC;

					if ( (f_port = (argv[0][0]-'0')) > 4)
						continue;

					if ( find_dir >= 0 ) {
						if ( dir == find_dir ) {
							if ( packet_kind == OCTETS_ASIC) {
								((unsigned long long*)portinfo)[f_port] = strtoull(argv[packet_kind], NULL, 10);
							}
							else {
								((unsigned long *)portinfo)[f_port] = strtoul(argv[packet_kind], NULL, 10);
							}
							break;
						}
					}
				}
			}
			buf[0] = 0;
		}
		fclose(fp);
	}
}


static int snmpAgentMain(void)
{
	int count, pid;
	int snmp_socket;
	fd_set fdset;
	char *snmp_enable;
	FILE *pidfile;
	struct timeval tv, *p_tv = NULL;
	struct sigaction sa;
	struct in_addr nip;
	FILE *fp;
	int webPid;
	char buf[80];
	int wifi_trap_en;
	unsigned long portinfo[5];
#if defined(__STATRAP_EVENT__)
/* jihyun@davo160202 jcode#7 -*/
	int nlfd, max_fd;
#endif
	if (DV_ACCESS(SNMP_AGENT_PID_FILE, F_OK) == 0)
		return 0;

	snmp_enable = getSmashSnmpInfo(NULL, "x_SNMP_ENABLE", 0);
	if (snmp_enable != NULL && !strcmp(snmp_enable, "0")) {
		printf("Snmp agent mode is set disabled\n");
		return 0;
	}
	/* Daemonize and log PID */
	/* Comment out daemon() to remove zombie process */
	if (daemon(1, 1) == -1) {
		perror("daemon");
		exit(errno);
	}

	get_preWlanSSIDMode();
	get_prePortfwConfig();

	load_config();              //default configuration values

	/* SNMP-agent initialisation functions */
	init_securityConfig();
	init_port_status();         // FOR SK BMT port config Load....
	init_SKBB_MIB();            // FOR SK BMT
	init_ping_test_t();
	init_cpeping_test_t();
#if defined(__STATRAP_EVENT__)
/* jihyun@davo160202 jcode#7 -*/
	init_wlmonitor(&wl_info[0]);
#endif
	set_community(dvsnmp_cfg.getcommunity);
	set_community(dvsnmp_cfg.setcommunity);
	ensure_communities();

	signal(SIGTERM, sigTermAgent);
	signal(SIGSEGV, sigTermAgent);
	signal(SIGUSR1, sigusr_handler);
#if !defined(__STATRAP_EVENT__)
	signal(SIGUSR2, sigusr_handler);
#endif
	snprintf(buf, sizeof(buf), "0");
	if (strtol(buf, NULL, 0) == 0L) {
		sa.sa_handler = child_wait_handle;
		sigemptyset(&sa.sa_mask);
		sa.sa_flags =0;
		sigaction(SIGCHLD, &sa, 0);

		nvram_get_r_def("x_snmp_wifi_trap", buf, sizeof(buf), "1");
		wifi_trap_en = atoi(buf);

		if (wifi_trap_en) {
#if !defined(__STATRAP_EVENT__)
			if ((wlsta_pid = fork()) == 0) {
				monitor_wlsta_attend();
				DV_EXIT(0);
			}
#endif
		}
		if  ( (cpeping_pid = fork()) == 0) {
			cpe_ping_init();
			DV_EXIT(0);
		}
	}

	/* Open the network */
	nip.s_addr = 0;
	snmp_socket = snmp_open_connection(nip.s_addr, dvsnmp_cfg.snmpport);
	glbSnmpSocket = snmp_socket;
#if defined(__STATRAP_EVENT__)
/* jihyun@davo160202 jcode#7 -*/
	max_fd = snmp_socket;
	if ( (nlfd = netlink_fd()) > 0 )
		max_fd = (snmp_socket > nlfd)? snmp_socket: nlfd;
#endif
	pid = getpid();

	if ((pidfile = DV_FOPEN(SNMP_AGENT_PID_FILE, "w")) != NULL) {
		fprintf(pidfile, "%d\n", pid);
		fclose(pidfile);
	} else {
		printf("file open error!\n");
#if defined(__STATRAP_EVENT__)
/* jihyun@davo160202 jcode#7 -*/
		if ( nlfd > 0)
			close(nlfd);
#endif
		close(snmp_socket);
		return 0;
	}
	/* Listen to the network */
	while (1) {
		tv.tv_sec = 3;
		tv.tv_usec = 0;
		p_tv = &tv;

		FD_ZERO(&fdset);
		FD_SET(snmp_socket, &fdset);
#if defined(__STATRAP_EVENT__)
/* jihyun@davo160202 jcode#7 -*/
		FD_SET(nlfd, &fdset);
		count = select(max_fd+1, &fdset, NULL, NULL, p_tv);
#else
		count = select(snmp_socket+1, &fdset, NULL, NULL, p_tv);
#endif

		if (count > 0) {
			if (FD_ISSET(snmp_socket, &fdset)) {
				snmp_process_message(snmp_socket);
			}
#if defined(__STATRAP_EVENT__)
/* jihyun@davo160202 jcode#7 -*/
			else if ( FD_ISSET(nlfd, &fdset)) {
				catcher_stainfo_fromnetlink(&wl_info[0], nlfd);
			}
#endif
		} else {
			switch (count) {
			case 0:
				if (snmpAction == SNMP_RESTART) {
					printf("snmp message : system restart\n");
					//system("sysconf init gw all");
					fp = fopen("/var/run/webs.pid", "r");
					if (fp) {
						fgets(buf, sizeof(buf), fp);
						fclose(fp);
						webPid = atoi(buf);
						if (webPid != 0)
							kill(webPid, SIGUSR1);
					}
					snmpAction = SNMP_NO_ACTION;
				} else if (snmpAction == SNMP_REBOOT) {
					memset(&portinfo[0], 0, sizeof(portinfo));
					get_port_asicinfo(RX_ASIC, portinfo, FCS_PAUSE_ASIC);
					printf("snmp message : system reboot\n");
					syslog(LOG_INFO, "system reboot in snmpd.(w:%d|l1:%d|l2:%d|l3:%d|l4:%d)",
								portinfo[4], portinfo[0], portinfo[1], portinfo[2], portinfo[3]);
					system("reboot");
				} else if (snmpAction == SNMP_MANUAL_UPGRADE) {
					printf("snmp message : tftp manual upgrade start!!!\n");
					executeManualUpgrade();
					snmpAction = SNMP_NO_ACTION;
				}
				else if ( (snmpAction&SNMP_WEB_RESTART) == SNMP_WEB_RESTART ) {
					snmpAction &= ~SNMP_WEB_RESTART;
					system("killall webs 2 > /dev/null");
					unlink("/var/run/webs.pid");
					system("webs &");
				}
				else if ( (snmpAction&SNMP_SAVE_APPLY) == SNMP_SAVE_APPLY ) {
					SaveAndApply__();
					snmpAction &= ~SNMP_SAVE_APPLY;
				}
				break;
			case -1:
				if (errno == EINTR) {
					continue;
				} else {
					perror("select");
				}
				break;
			default:
				fprintf(stdout, "select returned %d\n", count);
			}
		}
	}
#if defined(__STATRAP_EVENT__)
/* jihyun@davo160202 jcode#7 -*/
	if ( nlfd > 0)
		close(nlfd);
#endif
	close(snmp_socket);

	return 0;
}

static int cmd_show_snmp(void)
{
	DV_PRINTF("\n===============================================================================\n\n");
	DV_PRINTF("  * SNMP Configurations *\n\n");
	DV_PRINTF("===============================================================================\n\n");
	DV_PRINTF(" MAIN Configurations.\n");
	DV_PRINTF("   snmp mode      (snmp)   : %s\n", getSmashSnmpInfo(NULL, "snmp_enable", 0));
	DV_PRINTF("   get community  (getcom) : %s\n", getSmashSnmpInfo(NULL, "SNMP_GET_COMMUNITY", 0));
	DV_PRINTF("   set community  (setcom) : %s\n\n", getSmashSnmpInfo(NULL, "SNMP_SET_COMMUNITY", 0));
	DV_PRINTF("===============================================================================\n\n");
	DV_PRINTF(" TRAP Configurations.\n");
	DV_PRINTF("   trap mode      (trap)   : %s\n", getSmashSnmpInfo(NULL, "snmp_trap_enable", 0));
	DV_PRINTF("   trap auth. mode(trau)   : %s\n", getSmashSnmpInfo(NULL, "snmp_trap_auth_mode", 0));
	DV_PRINTF("   trap community (trcom)  : %s\n", getSmashSnmpInfo(NULL, "SNMP_TRP_COMMUNITY", 0));
	DV_PRINTF("   trap server    (trsrv)  : %s\n\n", getSmashSnmpInfo(NULL, "snmp_trap_server", 0));
	DV_PRINTF("===============================================================================\n");

	return 1;
}

/****************************************************************************
** FUNCTION:
**
** PURPOSE:
**
** PARAMETERS:
**
** RETURNS:
**
*****************************************************************************
*/

static void printUsage(void)
{

	DV_PRINTF
		("usage:    snmpd   -h                              HELP\n"
		 "  -a [(s)tart|s(t)op]                 [Start | Stop] agent daemon\n"
		 "  -m [trap-type] [file-name|\'NULL\'] Send trap message\n"
		 "  -T [(o)n|of(f)]                     Set trap mode\n"
		 "  -A [(o)n|of(f)]                     Set trap authentication mode\n"
		 "  -g Getcommunity                     Set getcommunity\n"
		 "  -s Setcommunity                     Set setcommunity\n"
		 "  -t Trapcommunity                    Set trapcommunity\n"
		 "  -S Trap Server IP                   Set trap server IP\n"
		 "  -d                          Display the configurations of the SNMP\n"
		 "\n"
		 "\n"
		 "TRAP TYPE\n"
		 "\n"
		 "  Type name       Value\n"
		 "  ------------------------------\n"
		 "  cold start      1\n"
		 "  warm start      2\n"
		 "  link down       3\n"
		 "  link up         4\n"
		 "  authentication failure  5\n" "\n" "\n");
}

static int snmpTrapMain(TIL list)
{
	char *enable;
	int wifi_session, wifi_session_total;
	char wan_bitrate[80], wlan_bitrate[80], fail_reason[64];
	char *sp, *p;
	unsigned long val;

	enable = getValue("x_SNMP_TRAP_ENABLE")? : "1";
	if(atoi(enable)==0)
		return 1;

	snprintf(dvsnmp_cfg.trpcommunity, DVSNMP_MAX_COMMUNITY_LEN, "%s", getValue("x_SNMP_TRAP_COMMUNITY")? :"iptvshrw^_");

	switch ((int)list.trap_kind[0]) {
	case 1:
		sendAutoTransmission();
		break;
	case 2:
		break;
	case 3:
		break;
	case 4:
		if ( !(p = strtok_r(list.trap_file, " \r\n\t_", &sp)) )
			break;
		val = strtoul(p, NULL, 10);
		snprintf(fail_reason, sizeof(fail_reason), "%s", list.trap_tmp1);
		sendAutoRebootTrap(val, fail_reason);
		break;
	case 5:
		sendPortLinkTrap((unsigned char)list.trap_file[0]);
		break;
	case 6:
		if ( !(p = strtok_r(list.trap_file, " \r\n\t_", &sp)) )
			break;
		wifi_session = strtoul(p, NULL, 10);
		if ( !(p = strtok_r(NULL, " \r\n\t_", &sp)) )
			break;
		wifi_session_total = strtoul(p, NULL, 10);

		if ( !(p = strtok_r(list.trap_tmp1, " \r\n\t_", &sp)) )
			break;
		snprintf(wan_bitrate, sizeof(wan_bitrate), "%s", p);
		if ( !(p = strtok_r(NULL, " \r\n\t_", &sp)) )
			break;
		snprintf(wlan_bitrate, sizeof(wlan_bitrate), "%s", p);
		sendLimitedSessionTrap(wifi_session, wifi_session_total, wan_bitrate, wlan_bitrate);
		break;
	case 7:
		snprintf(fail_reason, sizeof(fail_reason), "%s", list.trap_file);
		sendSmartResetTrap(fail_reason);
		break;
	case 8:
		sendAutoBandwidthTrap();
		break;
	case 9:
		sendHandOverSuccessTrap();
		break;
	case 10:
		snprintf(fail_reason, sizeof(fail_reason), "%s", list.trap_file);
		sendNtpFailTrap(fail_reason);
		break;
	case 11:
		usleep(15000000);
		sendwlan1SitesurveyResultTrap();
		sendwlan0SitesurveyResultTrap();
		break;
	default:
		DV_PRINTF("trap argument error\n");
		break;
	}
	return (0);
}

int main(int argc, char *argv[])
{
	static int init = 0;
	int c, pid;
	TIL list;                   /*the struct of trap information list */
	FILE *pidfile;

	if (argc < 2) {
		printUsage();
		return (0);
	}

	if (init == 0) {
		INIT_TIL(list);
		init = 1;
	}

	while (1) {
		int option_index = 0;
		static const struct option arg_options[] = {
			{"help", no_argument, 0, 'h'},
			{"[start | stop] agent daemon", required_argument, 0, 'a'},
			{"Send trap message", required_argument, 0, 'm'},
			{"Set trap mode", required_argument, 0, 'T'},
			{"Set authentication mode", required_argument, 0, 'A'},
			{"Set getcommunity", required_argument, 0, 'g'},
			{"Set setcommunity", required_argument, 0, 's'},
			{"Set trapcommunity", required_argument, 0, 't'},
			{"Set trap server IP", required_argument, 0, 'S'},
			{"Display the statue", no_argument, 0, 'd'},
			{0, 0, 0, 0}
		};

		c = getopt_long(argc, argv, "hd::a:m:t:f:T:g:s:t:A:S:",
						arg_options, &option_index);
		if (c == -1)
			break;

		switch (c) {
		case 'a':
			if (STRONGCMP('s', 'S')) {
				snmpAgentMain();
			} else if (STRONGCMP('t', 'T')) {
				if (DV_ACCESS(SNMP_AGENT_PID_FILE, F_OK) == 0) {        // pid file exist
					if ((pidfile =
						 DV_FOPEN(SNMP_AGENT_PID_FILE, "r")) != NULL) {
						DV_FSCANF(pidfile, "%d", &pid);
						DV_FCLOSE(pidfile);
						if (pid != 0) {
							kill(pid, SIGTERM);
						}
						unlink(SNMP_AGENT_PID_FILE);
					}
				}
			}
			break;
		case 'm':
			if (argc < 3) {
				printUsage();
				return -1;
			} else {
				INIT_TIL(list);
				list.trap_kind[0] = atoi(argv[2]);
				if ( argc > 3) {
					if ( (int)list.trap_kind[0] == 4 || (int)list.trap_kind[0] == 6 || (int)list.trap_kind[0] == 7 || (int)list.trap_kind[0] == 10) {
						sprintf(&list.trap_file[0],"%s", argv[3]);
					} else {
						list.trap_file[0] = strtoul(argv[3], NULL, 10);
					}
					if ( argc > 4)
						sprintf(&list.trap_tmp1[0],"%s", argv[4]);
				}
				snmpTrapMain(list);
			}
			break;
		case 'T':
			if (STRONGCMP('o', 'O')) {
				setSmashSnmpInfo("snmp_trap_enable", "1", 0);
			} else if (STRONGCMP('f', 'F')) {
				setSmashSnmpInfo("snmp_trap_enable", "0", 0);
			}
			commitSmashSnmpInfo();
			return 0;
		case 'A':
			if (STRONGCMP('o', 'O')) {
				setSmashSnmpInfo("snmp_trap_auth_mode", "1", 0);
			} else if (STRONGCMP('f', 'F')) {
				setSmashSnmpInfo("snmp_trap_auth_mode", "0", 0);
			}
			commitSmashSnmpInfo();
			return 0;
		case 'g':
			setSmashSnmpInfo("snmp_get_community", argv[2], 0);
			commitSmashSnmpInfo();
			return 0;
		case 's':
			setSmashSnmpInfo("snmp_set_community", argv[2], 0);
			commitSmashSnmpInfo();
			return 0;
		case 't':
			setSmashSnmpInfo("snmp_trap_community", argv[2], 0);
			commitSmashSnmpInfo();
			return 0;
		case 'S':
			setSmashSnmpInfo("snmp_trap_serveraddr", argv[2], 0);
			commitSmashSnmpInfo();
			return 0;
		case 'h':
			printUsage();
			return 0;
		case 'd':
			cmd_show_snmp();
			return 0;

		default:
			printUsage();
			return 0;
		}
	}                           // end while

	/*the report of send trap message */
//      if (is_trap_send_mode == true && ready_to_send != 3)
//              DV_PRINTF("Need more arguments.\n");
	return 0;
}
