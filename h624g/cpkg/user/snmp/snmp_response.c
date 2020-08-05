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

//#include "dvnvlib.h"
#include "./engine/asn1.h"
#include "./engine/snmp.h"
#include "./engine/agt_engine.h"
#include "./engine/snmp_community.h"

#include "snmp_main.h"
#include "snmp_response.h"

extern TDV_SNMP_CFG    dvsnmp_cfg;

/*
 *  Make request id
 */
static unsigned long get_request_id(void)
{
    return ((rand()<<16)+rand());
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
//DACOM BMT start
#define NMS_PORT	3304
//DACOM BMT end

#define NEON20_TEST
int snmp_send_response(raw_snmp_info_t *pMsg, int rsocket)
{
#if defined(NEON20_TEST)
	int	resp_sock;
	char wan_ipaddr[16], *dmz_mode = NULL;
#else
    int      resp_sock = rsocket;
#endif
	int ret = 0;
	char *nms_ip=NULL;
    struct sockaddr_in   server_addr, client_addr;

#if defined(NEON20_TEST)
	memset(&client_addr, 0, sizeof(client_addr));
//	dmz_mode = dvnv_get_safe("dmz_mode");

	if (dmz_mode && strcmp(dmz_mode, "sdmz") != 0) { // Not super dmz mode
		int             fd = 0;
		struct ifreq    iface;
		struct in_addr	ia;

		if ((fd = socket(AF_INET, SOCK_DGRAM, 0)) == -1) {
			printf("SNMP: Can't create snmp response socket!\n");
			return -1;
		}

//		dvnv_get_r_safe("wan_ifname", iface.ifr_name, IFNAMSIZ);
		if(ioctl(fd, SIOCGIFADDR, &iface) != 0) {
			close(fd);
			printf("SNMP: Can't get WAN IP address!\n");
			return -1;
		}
		ia.s_addr = ((struct sockaddr_in *)(&(iface.ifr_addr)))->sin_addr.s_addr;

		close(fd);

		strcpy(wan_ipaddr, inet_ntoa(ia));

		resp_sock = socket(AF_INET, SOCK_DGRAM, 0);
		if (resp_sock < 0){
			perror("socket");
			printf("SNMP: %s:%d error calling socket()\n.", __FILE__, __LINE__);
			return(-1);
		}

        client_addr.sin_addr.s_addr = ia.s_addr;
		client_addr.sin_port = htons(161);
    	client_addr.sin_family = AF_INET;

		if (bind(resp_sock, (struct sockaddr *)&client_addr,
					sizeof(client_addr))){
			perror("bind");
			printf ("SNMP: error calling \"bind()\"\n.");
			close(resp_sock);
			return(2);
		}
	} else { // Super dmz mode
		resp_sock = rsocket;
	}


#endif
//DACOM BMT start
//	nms_ip = dvnv_get_safe("nat_aware");
//DACOM BMT end
	if (nms_ip != NULL) {
    	server_addr.sin_family = AF_INET;
		inet_aton(nms_ip, &server_addr.sin_addr);
        server_addr.sin_port = htons(NMS_PORT);
        if (sendto(resp_sock, (char *)pMsg->response, pMsg->response_length, 0,
                   (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0){
			//close(resp_sock);
        	perror("sendto respSocket");
			ret = -1;
        }
	}
	if (dmz_mode && strcmp(dmz_mode, "sdmz") != 0) // Not super dmz mode
		close(resp_sock);
	return ret;
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

unsigned char *make_resp_v2c_headr(raw_snmp_info_t *pMsg, int *p_out_length)
{
    unsigned char *out_data;

    pMsg->mesg.version = SNMP_VERSION_2C;
    pMsg->mesg.pdutype = SNMP_GET_RSP_PDU;
    strcpy(pMsg->mesg.community, dvsnmp_cfg.getcommunity);
    pMsg->mesg.community_length = strlen(pMsg->mesg.community);
    pMsg->mesg.community_id = 0;

    pMsg->mesg.request_id = get_request_id();
    out_data = (unsigned char*)build_snmp_response_without_list_of_varbind(pMsg);
    RETURN_ON_BUILD_ERROR(out_data, "build request id");

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

unsigned char *make_resp_tail(raw_snmp_info_t *pMsg, char *out_data, int *p_out_length)
{
    pMsg->response_packet_end = out_data;

    *p_out_length = correct_snmp_response_with_lengths( pMsg, 0, 0 );
    out_data = asn_build_sequence(pMsg->response_pdu, p_out_length,
                                  pMsg->mesg.pdutype,
                                  pMsg->response_packet_end - pMsg->response_request_id);
    RETURN_ON_BUILD_ERROR(out_data, "build trap pdu type");

    return(out_data);
}
