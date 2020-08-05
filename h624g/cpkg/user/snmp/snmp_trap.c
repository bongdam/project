#include <stdio.h>
#include <ctype.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/time.h>
#include <unistd.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <errno.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <sys/file.h>
#include <signal.h>
#include <sys/wait.h>
#include <syslog.h>
#include <sys/sysinfo.h>
#include <brdio.h>
#include "./engine/asn1.h"
#include "./engine/snmp.h"
#include "./engine/agt_engine.h"
#include "./engine/snmp_community.h"

#include "snmp_main.h"
#include "snmp_trap.h"


extern TDV_SNMP_CFG dvsnmp_cfg;

/*
 *  Make request id
 */
static unsigned long get_request_id(void)
{
	return ((rand() << 16) + rand());
}

unsigned int current_sysUpTime(void)
{
	FILE *fp;
	int proc_time, proc_time2;

	if ((fp = fopen("/proc/uptime", "r")) == NULL)
		return 0;

	fscanf(fp, "%d.%d", &proc_time, &proc_time2);
	fclose(fp);
	return (proc_time * 100) + proc_time2;
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

int snmp_send_trap(raw_snmp_info_t *pMsg, char *trap_ip, unsigned short trap_port, char *trap_name)
{
	int trap_sock;
	struct sockaddr_in server_addr;
	int ret;

	trap_sock = socket(AF_INET, SOCK_DGRAM, 0);

	if (trap_port == 0)
		trap_port = 162;

	if (trap_sock < 0) {
		perror("socket");
		return (2);
	}
	server_addr.sin_family = AF_INET;
	server_addr.sin_addr.s_addr = inet_addr(trap_ip);
	server_addr.sin_port = htons(trap_port);
	if ((ret = sendto(trap_sock, (char *)pMsg->response,
					pMsg->response_length, 0,
					(struct sockaddr *)&server_addr,
					sizeof(server_addr))) < 0) {
		perror("sendto trapSocket");
		syslog(LOG_NOTICE, "SNMP: fail sent %s to %s:%d\n", trap_name, trap_ip, trap_port);
		close(trap_sock);
		return 1;
	}
	syslog(LOG_NOTICE, "SNMP: sent %s to %s:%d\n", trap_name, trap_ip, trap_port);

	close(trap_sock);
	return 0;

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

unsigned char *make_trap_v2c_headr(raw_snmp_info_t * pMsg,
								   int *p_out_length, oid * pTrapOid,
								   int oid_len)
{
	oid oid_sysUpTime[] = { O_sysUpTime };
#if 0
	oid oid_trapOid[] = { O_snmpTraps };
#else
	oid oid_trapOid[] = { O_snmpTrapOID, 0 };
#endif
	Oid oid_obj;
	unsigned char *out_data;

	pMsg->mesg.version = SNMP_VERSION_2C;
	pMsg->mesg.pdutype = SNMP_TRP2_REQ_PDU;
	strcpy(pMsg->mesg.community, dvsnmp_cfg.trpcommunity);
	pMsg->mesg.community_length = strlen(pMsg->mesg.community);
	pMsg->mesg.community_id = 0;

	pMsg->mesg.request_id = get_request_id();
	out_data = (unsigned char *)build_snmp_response_without_list_of_varbind(pMsg);
	RETURN_ON_BUILD_ERROR(out_data, "build request id");

	// build sysUpTIme
	oid_obj.namelen = sizeof(oid_sysUpTime) / sizeof(oid);
	memcpy(oid_obj.name, oid_sysUpTime, sizeof(oid_sysUpTime));
	long_return = (long)current_sysUpTime();
	out_data = snmp_build_varbind(out_data, &oid_obj, SNMP_TIMETICKS,
								sizeof(long),
								(unsigned char *)&long_return,
								p_out_length);
	RETURN_ON_BUILD_ERROR(out_data, "build trap sysUpTime");

	// build Trap oid
	oid_obj.namelen = sizeof(oid_trapOid) / sizeof(oid);
	memcpy(oid_obj.name, oid_trapOid, sizeof(oid_trapOid));
	out_data = snmp_build_varbind(out_data, &oid_obj, SNMP_OBJID,
								oid_len, (unsigned char *)pTrapOid,
								p_out_length);
	RETURN_ON_BUILD_ERROR(out_data, "build trap trapOid");

	return (out_data);
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

unsigned char *make_trap_tail(raw_snmp_info_t * pMsg, char *out_data,
							  int *p_out_length)
{
	pMsg->response_packet_end = out_data;
	*p_out_length = correct_snmp_response_with_lengths(pMsg, 0, 0);
	out_data = asn_build_sequence(pMsg->response_pdu,
					p_out_length,
								pMsg->mesg.pdutype,
								pMsg->response_packet_end -
								pMsg->response_request_id);
	RETURN_ON_BUILD_ERROR(out_data, "build trap pdu type");
	return (out_data);

}

struct tm * get_trapevent_time(time_t *pctime, int delaysec)
{
	int i;
	long wan_ip;
	
	if ( !pctime || delaysec < 0 )
		return NULL;

	i = 0;
	while(1) {
		if ( !(switch_port_status(4) & PHF_LINKUP ) ||
			 get_wan_ip(&wan_ip, NULL) == 0 || wan_ip == 0 )
			 return NULL;
		if ( !access("/tmp/ntp_ok", F_OK)) {
			*pctime = (time((time_t *)0) - i);
			return (localtime(pctime));
		}
		if ( !delaysec--)
			break;
		i++;
		sleep(1);
		
	}
	return NULL;
}

