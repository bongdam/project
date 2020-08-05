#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <linux/netlink.h>
#include <net/rtl/rtl_types.h>

#include "rtk_cmd.h"
#include "rtk_83xx_hw_qos.h"

//#define QOS_DEBUG 1

#if defined(QOS_DEBUG)
#define RTK_QOS_PRINTF(format, args...) printf(format, ## args)
#else
#define RTK_QOS_PRINTF(format, args...)
#endif

/*	rtk_cmd 83xxqos Priority_Assign Port_Based port0 3 port1 4 port2 5
*/
static inline int rtk_83xx_port_based_priority_assign(int _num, char* _param[], qos83xx_cmd_info_p send_data)
{
	int i, temp;
	int ret = 0;

	if((_param[3] != NULL) && (!(memcmp(_param[3],"Port_Based",strlen(_param[3]))))){
			send_data->action=PORT_BASED_PRIORITY_ASSIGN_83XX;
			for(i=4; i<_num; i++)
			{
				if((_param[i] != NULL) && (strlen(_param[i]) == 5) && (!(memcmp(_param[i],"port",(strlen(_param[i])-1))))){
					temp = _param[i][4] - '0';
					if((_param[i+1] != NULL) && (strlen(_param[i+1]) == 1) && (*(_param[i+1]) >= '0') && (*(_param[i+1]) < '8')){
						send_data->qos_data.port_based_priority.val[temp] = *(_param[i+1]) - '0';
						send_data->qos_data.port_based_priority.valmask |= 1 << temp;
						ret += 1;
						RTK_QOS_PRINTF("83XX Priority %d is good for port[%d]\n", send_data->qos_data.port_based_priority.val[temp], temp);
					}else{
							goto QOS_ERROR;
					}
				}
			}
			RTK_QOS_PRINTF("Portmask is %x\n", send_data->qos_data.port_based_priority.valmask);
		}
	return ret;
QOS_ERROR:
	return 0;
}

/*	rtk_cmd 83xxqos Priority_Assign Dot1p_Based dot1p0 3 dot1p1 5 dot1p2 7 dot1p3 0
*/
static inline int rtk_83xx_dot1p_based_priority_assign(int _num, char* _param[], qos83xx_cmd_info_p send_data)
{
	int i, temp;
	int ret = 0;

	if((_param[3] != NULL) && (!(memcmp(_param[3],"Dot1p_Based",strlen(_param[3]))))){
			send_data->action = DOT1P_BASED_PRIORITY_ASSIGN_83XX;
			for(i=4; i<_num; i++)
			{
				if((_param[i] != NULL) && (strlen(_param[i]) == 6) && (!(memcmp(_param[i], "dot1p", (strlen(_param[i]) -1))))){
					temp = _param[i][5] - '0';
					if((_param[i+1] != NULL) && (strlen(_param[i+1]) == 1) && (*(_param[i+1]) >= '0') && (*(_param[i+1]) < '8')){
						send_data->qos_data.dot1p_based_priority.val[temp] = *(_param[i+1]) - '0';
						send_data->qos_data.dot1p_based_priority.valmask |= 1 << temp;
						ret += 1;
						RTK_QOS_PRINTF("Priority %d is good for dot1p[%d]\n", send_data->qos_data.dot1p_based_priority.val[temp], temp);
					}else{
							goto QOS_ERROR;
					}
				}
			}
			RTK_QOS_PRINTF("Dot1pmask is %x\n", send_data->qos_data.dot1p_based_priority.valmask);
		}
	return ret;
QOS_ERROR:
	return 0;
}

/*	rtk_cmd 83xxqos Priority_Assign Dscp_Based dscp32 1 dscp6 7
*/
static inline int rtk_83xx_dscp_based_priority_assign(int _num, char* _param[], qos83xx_cmd_info_p send_data)
{
	int i, temp;
	int ret = 0;

	 if((_param[3] != NULL) && (!(memcmp(_param[3],"Dscp_Based",strlen(_param[3]))))){
			send_data->action = DSCP_BASED_PRIORITY_ASSIGN_83XX;
			for(i=4; i<_num; i++)
			{
				if((_param[i] != NULL) && (((strlen(_param[i]) == 5) && (!(memcmp(_param[i], "dscp", (strlen(_param[i]) -1))))) ||
				  ((strlen(_param[i]) == 6) && (!(memcmp(_param[i], "dscp", (strlen(_param[i]) -2))))))){
					if(strlen(_param[i]) == 6)
						temp = (_param[i][4] - '0')*10 + (_param[i][5] - '0');
					else
						temp = _param[i][4] - '0';

					if((_param[i+1] != NULL) && (strlen(_param[i+1]) == 1) && (*(_param[i+1]) >= '0') && (*(_param[i+1]) < '8')){
						send_data->qos_data.dscp_based_priority.dscp[temp] = *(_param[i+1]) - '0';
						if(temp < 32)
							send_data->qos_data.dscp_based_priority.dscpmask1 |= 1 << temp;
						else
							send_data->qos_data.dscp_based_priority.dscpmask2 |= 1 << (temp-32);
						ret += 1;
						RTK_QOS_PRINTF("Priority %d is good for dscp[%d]\n", send_data->qos_data.dscp_based_priority.dscp[temp], temp);
					}else{
							goto QOS_ERROR;
					}
				}
			}
			RTK_QOS_PRINTF("Dscpmask1 is %x. Dscpmask2 is %x\n", send_data->qos_data.dscp_based_priority.dscpmask1, send_data->qos_data.dscp_based_priority.dscpmask2);
		}
	return ret;
 QOS_ERROR:
	return 0;
}


/*	rtk_cmd 83xxqos Queue_Num port0 1 port2 4
*/
static inline int rtk_83xx_queue_number(int _num, char* _param[], qos83xx_cmd_info_p send_data)
{
	int i, temp;
	int ret = 0;

	send_data->action = QUEUE_NUMBER_83XX;
	for(i=3; i<_num; i++)
	{
		if((_param[i] != NULL) && (strlen(_param[i]) == 5) && (!(memcmp(_param[i],"port",(strlen(_param[i])-1))))){
			temp = _param[i][4] - '0';
			// 8 queues per port on 83xx 
			if((_param[i+1] != NULL) && (strlen(_param[i+1]) == 1) && (*(_param[i+1]) > '0') && (*(_param[i+1]) < '9'))
			{
				send_data->qos_data.queue_num.val[temp] = *(_param[i+1]) - '0';
				send_data->qos_data.queue_num.valmask |= 1 << temp;
				ret += 1;
				RTK_QOS_PRINTF("83XX Queue number %d is good for port[%d]\n", send_data->qos_data.queue_num.val[temp], temp);
			}else{
					goto QOS_ERROR;
			}
		}
	}
	RTK_QOS_PRINTF("queue num mask is %x\n", send_data->qos_data.queue_num.valmask);
	return ret;
QOS_ERROR:
	return 0;

}

/*	users can config multiple queues type for a port once a time
	example:
	rtk_cmd 83xxqos Queue_Type STRICT port0 q0 q3 q4 port2 q4 q5
*/
static inline int rtk_83xx_queue_type_strict(int _num, char* _param[], qos83xx_cmd_info_p send_data)
{
	int i, j, temp_port, temp_queue;
	int ret = 0;

	if((_param[3] != NULL) && (!(memcmp(_param[3],"STRICT",strlen(_param[3]))))){
		send_data->action = QUEUE_TYPE_STRICT_83XX;
		for(i=4; i<_num; i++)
		{
			if((_param[i] != NULL) && (strlen(_param[i]) == 5) && (!(memcmp(_param[i],"port",(strlen(_param[i])-1))))){
				temp_port = _param[i][4] - '0';
				for(j=i+1; j<_num; j++)
				{
					if((_param[j] != NULL) && (strlen(_param[j]) == 2) && (!(memcmp(_param[j],"q",(strlen(_param[j])-1))))){
						temp_queue = _param[j][1] - '0';
						send_data->qos_data.queue_type.queue[temp_port][temp_queue] = 255;
						send_data->qos_data.queue_type.portmask |= 1<<temp_port;
						send_data->qos_data.queue_type.queuemask |= 1<<temp_queue;
						ret += 1;
					}else{
						break;
					}
				}
			}
		}
	}
	return ret;
}

/*	users can config multiple queues type for a port once a time
	example:
	rtk_cmd 83xxqos Queue_Type WEIGHTED port0 q0 5 q3 127 port2 q4 19 q5 20
*/
static inline int rtk_83xx_queue_type_weighted(int _num, char* _param[], qos83xx_cmd_info_p send_data)
{
	int i, j, temp_port, temp_queue, temp;
	int ret = 0;

	if((_param[3] != NULL) && (!(memcmp(_param[3],"WEIGHTED",strlen(_param[3]))))){
		send_data->action = QUEUE_TYPE_WEIGHTED_83XX;
		for(i=4; i<_num; i++)
		{
			if((_param[i] != NULL) && (strlen(_param[i]) == 5) && (!(memcmp(_param[i],"port",(strlen(_param[i])-1))))){
				temp_port = _param[i][4] - '0';
				for(j=i+1; j<_num; j=j+2)
				{
					if((_param[j] != NULL) && (strlen(_param[j]) == 2) && (!(memcmp(_param[j],"q",(strlen(_param[j])-1))))){
						temp_queue = _param[j][1] - '0';
						if(_param[j+1] != NULL){
							if(strlen(_param[j+1])== 1)
								temp = *(_param[j+1]) - '0';
							else if(strlen(_param[j+1])== 2)
								temp = (_param[j+1][0] - '0')*10 + (_param[j+1][1] - '0');
							else if(strlen(_param[j+1])== 3)
								temp = (_param[j+1][0] - '0')*100 + (_param[j+1][1] - '0')*10 + (_param[j+1][2] - '0');

							if(temp > 127 || temp <= 0)
								goto QOS_ERROR;

							send_data->qos_data.queue_type.queue[temp_port][temp_queue] = temp;
							send_data->qos_data.queue_type.portmask |= 1<<temp_port;
							send_data->qos_data.queue_type.queuemask |= 1<<temp_queue;
							ret += 1;
						}else{
							goto QOS_ERROR;
						}
					}
					else{
						break;
					}
				}
			}
		}
	}
	return ret;
QOS_ERROR:
	return 0;
}

/*	rtk_cmd 83xxqos Priority_to_Qid pri0 5 pri1 4
*/
static inline int rtk_83xx_priority_to_qid(int _num, char* _param[], qos83xx_cmd_info_p send_data)
{
	int i, temp;
	int ret = 0;

	send_data->action = PRIORITY_TO_QID_83XX;

	for(i=3; i<_num; i++)
	{
		if((_param[i] != NULL) && (strlen(_param[i]) == 4) && (!(memcmp(_param[i],"pri",(strlen(_param[i])-1))))){
			temp = _param[i][3] - '0';
			if((_param[i+1] != NULL) && (strlen(_param[i+1]) == 1) && (*(_param[i+1]) >= '0') && (*(_param[i+1]) < '8')){
				send_data->qos_data.sys_priority.val[temp] = *(_param[i+1]) - '0';
				send_data->qos_data.sys_priority.valmask |= 1 << temp;
				ret += 1;
				RTK_QOS_PRINTF("83xx Qid %d is good for priority[%d]\n", send_data->qos_data.port_based_priority.val[temp], temp);
			}else{
					goto QOS_ERROR;
			}
		}
	}
	return ret;
QOS_ERROR:
	return 0;
}

/*	rtk_cmd 83xxqos Priority_Decision port 1 acl 127 dscp 1 dot1p 1 svlan 1 cvlan 1 dmac 1 smac 1
*/
static inline int rtk_83xx_priority_decision(int _num, char* _param[], qos83xx_cmd_info_p send_data)
{
	int i, temp;
	int ret = 0;

	send_data->action = PRIORITY_DECISION_83XX;
	for(i=3; i<_num; i++)
	{
		if((_param[i] != NULL) && (strlen(_param[i]) == 4) && (!(memcmp(_param[i], "port", (strlen(_param[i])))))){
			if((_param[i+1] != NULL) && strlen(_param[i+1])){
				temp = atoi(_param[i+1]);
				if(temp > 0xFF)
					goto QOS_ERROR;
				
				send_data->qos_data.pri_decision.decision[0] = temp;
				ret += 1;
			}else{
					goto QOS_ERROR;
			}
		}
		else if((_param[i] != NULL) && (strlen(_param[i]) == 3) && (!(memcmp(_param[i], "acl", (strlen(_param[i])))))){
			if((_param[i+1] != NULL) && strlen(_param[i+1])){
				temp = atoi(_param[i+1]);
				if(temp > 0xFF)
					goto QOS_ERROR;
				
				send_data->qos_data.pri_decision.decision[1] = temp;
				ret += 1;
			}else{
					goto QOS_ERROR;
			}
		}
		else if((_param[i] != NULL) && (strlen(_param[i]) == 4) && (!(memcmp(_param[i], "dscp", (strlen(_param[i])))))){
			if((_param[i+1] != NULL) && strlen(_param[i+1])){
				temp = atoi(_param[i+1]);
				if(temp > 0xFF)
					goto QOS_ERROR;
				
				send_data->qos_data.pri_decision.decision[2] = temp;
				ret += 1;
			}else{
					goto QOS_ERROR;
			}
		}
		else if((_param[i] != NULL) && (strlen(_param[i]) == 5) && (!(memcmp(_param[i], "dot1p", (strlen(_param[i])))))){
			if((_param[i+1] != NULL) && strlen(_param[i+1])){
				temp = atoi(_param[i+1]);
				if(temp > 0xFF)
					goto QOS_ERROR;
				
				send_data->qos_data.pri_decision.decision[3] = temp;
				ret += 1;
			}else{
					goto QOS_ERROR;
			}
		}
		else if((_param[i] != NULL) && (strlen(_param[i]) == 5) && (!(memcmp(_param[i], "svlan", (strlen(_param[i])))))){
			if((_param[i+1] != NULL) && strlen(_param[i+1])){
				temp = atoi(_param[i+1]);

				if(temp > 0xFF)
					goto QOS_ERROR;
				send_data->qos_data.pri_decision.decision[4] = temp;
				ret += 1;
			}else{
					goto QOS_ERROR;
			}
		}
		else if((_param[i] != NULL) && (strlen(_param[i]) == 5) && (!(memcmp(_param[i], "cvlan", (strlen(_param[i])))))){
			if((_param[i+1] != NULL) && strlen(_param[i+1])){
				temp = atoi(_param[i+1]);

				if(temp > 0xFF)
					goto QOS_ERROR;
				send_data->qos_data.pri_decision.decision[5] = temp;
				ret += 1;
			}else{
					goto QOS_ERROR;
			}
		}
		else if((_param[i] != NULL) && (strlen(_param[i]) == 4) && (!(memcmp(_param[i], "dmac", (strlen(_param[i])))))){
			if((_param[i+1] != NULL) && strlen(_param[i+1])){
				temp = atoi(_param[i+1]);

				if(temp > 0xFF)
					goto QOS_ERROR;
				send_data->qos_data.pri_decision.decision[6] = temp;
				ret += 1;
			}else{
					goto QOS_ERROR;
			}
		}
		
		else if((_param[i] != NULL) && (strlen(_param[i]) == 4) && (!(memcmp(_param[i], "smac", (strlen(_param[i])))))){
			if((_param[i+1] != NULL) && strlen(_param[i+1])){
				temp = atoi(_param[i+1]);

				if(temp > 0xFF)
					goto QOS_ERROR;
				send_data->qos_data.pri_decision.decision[7] = temp;
				ret += 1;
			}else{
					goto QOS_ERROR;
			}
		}
	}

	return ret;
QOS_ERROR:
	return 0;
}

/*	rtk_cmd 83xxqos Remark DOT1P port0 pri0 5 pri1 6 port2 pri2 3
*/
static inline int rtk_83xx_dot1p_remark(int _num, char* _param[], qos83xx_cmd_info_p send_data)
{
	int i, j, temp_port, temp_pri;
	int ret = 0;

	if((_param[3] != NULL) && (strlen(_param[3]) == 5)&& (!(memcmp(_param[3],"DOT1P",strlen(_param[3]))))){
		send_data->action = DOT1P_REMARK_83XX;

		for(i = 0; i < 8; i++){
			send_data->qos_data.dot1p_remark.remark[i] = 255;
		}
		
		for(i=4; i<_num; i++)
		{
			if((_param[i] != NULL) && (strlen(_param[i]) == 5) && (!(memcmp(_param[i],"port",(strlen(_param[i])-1))))){
				temp_port = _param[i][4] - '0';
				for(j=i+1; j<_num; j=j+2)
				{
					if((_param[j] != NULL) && (strlen(_param[j]) == 4) && (!(memcmp(_param[j],"pri",(strlen(_param[j])-1))))){
						temp_pri = _param[j][3] - '0';
						if((_param[j+1] != NULL) && (strlen(_param[j+1]) == 1) && (*(_param[j+1]) >= '0') && (*(_param[j+1]) < '8')){
							send_data->qos_data.dot1p_remark.remark[temp_pri] = *(_param[j+1]) - '0';
							send_data->qos_data.dot1p_remark.portmask |= 1<<temp_port;
							send_data->qos_data.dot1p_remark.prioritymask |= 1<<temp_pri;
							ret += 1;
						}else{
								goto QOS_ERROR;
						}
					}
					else{
						break;
					}
				}
			}
		}

	}
	return ret;
QOS_ERROR:
	return 0;
}

/*	rtk_cmd 83xxqos Remark DSCP pri1 5 pri7 60 pri2 0
dw bb804770
*/
static inline int rtk_83xx_dscp_remark(int _num, char* _param[], qos83xx_cmd_info_p send_data)
{
	int i, temp_pri, temp;
	int ret = 0;

	if((_param[3] != NULL) && (strlen(_param[3]) == 4)&& (!(memcmp(_param[3],"DSCP",strlen(_param[3]))))){
		send_data->action = DSCP_REMARK_83XX;

		for(i = 0; i < 8; i++){
			send_data->qos_data.dscp_remark.remark[i] = 255;
		}
		
		for(i=4; i<_num; i++)
		{
			if((_param[i] != NULL) && (strlen(_param[i]) == 4) && (!(memcmp(_param[i], "pri",(strlen(_param[i])-1))))){
				temp_pri = _param[i][3] - '0';
				if((_param[i+1] != NULL) && ((strlen(_param[i+1]) == 1) || (strlen(_param[i+1]) == 2))){
					if(strlen(_param[i+1]) == 1)
						temp = *(_param[i+1]) - '0';
					else
						temp = (_param[i+1][0] - '0')*10 + (_param[i+1][1] - '0');

					if(temp > 63)
						goto QOS_ERROR;

					send_data->qos_data.dscp_remark.remark[temp_pri] = temp;
					send_data->qos_data.dscp_remark.prioritymask |= 1<<temp_pri;
					ret += 1;
					//printf("port[%d], priority[%d], ret is %d, remark is %d\n", send_data->qos_data.dscp_remark.portmask,
						//send_data->qos_data.dscp_remark.prioritymask, ret, send_data->qos_data.dscp_remark.remark[temp_port][temp_pri] );
				}else{
						goto QOS_ERROR;
				}
			}
		}
	}

	return ret;
QOS_ERROR:
	return 0;
}

#ifndef RTL8367B_QOS_RATE_INPUT_MAX
#define RTL8367B_QOS_RATE_INPUT_MAX         (0x1FFFF * 8)
#endif

#ifndef RTL8367B_QOS_RATE_INPUT_MIN
#define RTL8367B_QOS_RATE_INPUT_MIN         8
#endif

/*	rtk_cmd 83xxqos Port_Rate port0 1000 port1 2000 (kbps)
*/
static inline int rtk_83xx_port_rate(int _num, char* _param[], qos83xx_cmd_info_p send_data)
{	
	int i, ret = 0;
	unsigned int temp_port, rate;
	
	send_data->action = PORT_RATE_83XX;
	for(i = 3; i < _num; i++){
		if((_param[i] != NULL) && (strlen(_param[i]) == 5) && (!(memcmp(_param[i],"port",(strlen(_param[i])-1))))){
			temp_port = _param[i][4] - '0';
			if(temp_port > 7)
				goto QOS_ERROR;

			if(_param[i+1] != NULL){
				rate = strtol(_param[i+1], NULL, 10);
				if(rate > RTL8367B_QOS_RATE_INPUT_MAX || rate < RTL8367B_QOS_RATE_INPUT_MIN)
					goto QOS_ERROR;
				
				send_data->qos_data.port_rate.portmask |= 1<<temp_port;
				send_data->qos_data.port_rate.rate[temp_port] = rate;
				ret += 1;
			}
			else{
				goto QOS_ERROR;
			}
		}
	}

	return ret;
QOS_ERROR:
	return 0;
}

/*	rtk_cmd 83xxqos Rate port4 q0 1000 q2 2000 (kbps???)
*/
static inline int rtk_83xx_queue_rate(int _num, char* _param[], qos83xx_cmd_info_p send_data)
{
	int queue_id, temp_port, rate;
	int i, j, ret = 0;
	
	send_data->action = QUEUE_RATE_83XX;
	for(i = 3; i < _num; i++){
		if((_param[i] != NULL) && (strlen(_param[i]) == 5) && (!(memcmp(_param[i],"port",(strlen(_param[i])-1))))){
			temp_port = _param[i][4] - '0';
			if(temp_port > 7)
				goto QOS_ERROR;
			
			for(j = i+1; j < _num; j = j+2){
				if((_param[j] != NULL) && (strlen(_param[j]) == 2) && (!(memcmp(_param[j],"q",(strlen(_param[j])-1))))){
					queue_id = _param[j][1] - '0';
				
					if(_param[j+1] != NULL){
						rate = strtol(_param[j+1], NULL, 10);
						if(rate > RTL8367B_QOS_RATE_INPUT_MAX || rate < RTL8367B_QOS_RATE_INPUT_MIN)
							goto QOS_ERROR;
						
						send_data->qos_data.queue_rate.portmask |= (1 << temp_port);
						send_data->qos_data.queue_rate.queuemask |= (1 << queue_id);
						send_data->qos_data.queue_rate.rate[temp_port][queue_id] = rate;
						ret += 1;
					}
					else{
						goto QOS_ERROR;
					}
				}
				else{
					break;
				}
			}
		}
	}
	
	return ret;
QOS_ERROR:
	return 0;
}

int rtk_83xx_hw_qos_parse(int _num, char* _param[])
{
#if defined(CONFIG_RTL_83XX_QOS_SUPPORT)
	qos83xx_cmd_info_t send_data, recv_data;
	struct nl_data_info send_info,recv_info;

	memset(&send_data, 0, sizeof(qos83xx_cmd_info_t));

	if((_param[2] != NULL) && (!(memcmp(_param[2],"Priority_Assign",strlen(_param[2])))))
	{
		if(rtk_83xx_port_based_priority_assign(_num, _param, &send_data) > 0){
			RTK_QOS_PRINTF("83xx Port based priority assign ok!\n");
		}else if(rtk_83xx_dot1p_based_priority_assign(_num, _param, &send_data) > 0){
			RTK_QOS_PRINTF("83xx 802.1P based priority assign ok!\n");
		}else if(rtk_83xx_dscp_based_priority_assign(_num, _param, &send_data) > 0){
			RTK_QOS_PRINTF("83xx Dscp based priority assign ok!\n");
		}
		else{
			printf("83xx Priority assign failed!\n");
			return FAILED;
		}
	}
	else if((_param[2] != NULL) && (!(memcmp(_param[2],"Queue_Num",strlen(_param[2])))))
	{
		if(rtk_83xx_queue_number(_num, _param, &send_data) > 0){
			RTK_QOS_PRINTF("83xx Queue number assign ok!\n");
		}else{
			RTK_QOS_PRINTF("83xx Queue number assign failed!\n");
			return FAILED;
		}
	}
	else if((_param[2] != NULL) && (!(memcmp(_param[2],"Queue_Type",strlen(_param[2])))))
	{
		if(rtk_83xx_queue_type_strict(_num, _param, &send_data) > 0){
			RTK_QOS_PRINTF("83xx Queue STRICT type assign ok\n");
		}else if(rtk_83xx_queue_type_weighted(_num, _param, &send_data) > 0){
			RTK_QOS_PRINTF("83xx Queue WEIGHTED type assign ok\n");
		}else{
			RTK_QOS_PRINTF("83xx Queue type assign failed\n");
			return FAILED;
		}
	}
	else if((_param[2] != NULL) && (!(memcmp(_param[2],"Priority_to_Qid",strlen(_param[2])))))
	{
		if(rtk_83xx_priority_to_qid(_num, _param, &send_data) > 0){
			RTK_QOS_PRINTF("83xx Priority mapping to qid ok!\n");
		}else{
			RTK_QOS_PRINTF("83xx Priority mapping to qid failed!\n");
			return FAILED;
		}
	}
	else if((_param[2] != NULL) && (!(memcmp(_param[2],"Priority_Decision",strlen(_param[2])))))
	{
		if(rtk_83xx_priority_decision(_num, _param, &send_data) > 0){
			RTK_QOS_PRINTF("83xx Priority decision configure ok!\n");
		}else{
			RTK_QOS_PRINTF("83xx Priority decision configure failed!\n");
			return FAILED;
		}
	}
	else if((_param[2] != NULL) && (!(memcmp(_param[2],"Remark",strlen(_param[2])))))
	{
		if((_param[3] != NULL) && (!(memcmp(_param[3],"DISABLE",strlen(_param[3]))))){
			if((_param[4] != NULL) && (!(memcmp(_param[4],"DSCP",strlen(_param[4]))))){
				send_data.action = DISABLE_83XX_DSCP_REMARK;
			}
			else if((_param[4] != NULL) && (!(memcmp(_param[4],"DOT1P",strlen(_param[4]))))){
				send_data.action = DISABLE_83XX_DOT1P_REMARK;
			}
			else{
				RTK_QOS_PRINTF("83xx Remark configure failed!\n");
				return FAILED;
			}
		}
		else if(rtk_83xx_dot1p_remark(_num, _param, &send_data) > 0){
			RTK_QOS_PRINTF("83xx 802.1P remark configure ok!\n");
		}else if(rtk_83xx_dscp_remark(_num, _param, &send_data) > 0){
			RTK_QOS_PRINTF("83xx Dscp remark configure ok!\n");
		}else{
			RTK_QOS_PRINTF("83xx Remark configure failed!\n");
			return FAILED;
		}
	}
	else if((_param[2] != NULL) && (!(memcmp(_param[2],"Rate",strlen(_param[2])))))
	{
		if(rtk_83xx_queue_rate(_num, _param, &send_data) > 0){
			RTK_QOS_PRINTF("83xx Queue rate configure ok!\n");
		}else{
			RTK_QOS_PRINTF("83xx Queue rate configure failed!\n");
			return FAILED;
		}
	}
	else if((_param[2] != NULL) && (!(memcmp(_param[2],"Port_Rate",strlen(_param[2])))))
	{
		if(rtk_83xx_port_rate(_num, _param, &send_data) > 0){
			RTK_QOS_PRINTF("83xx Port rate configure ok!\n");
		}else{
			RTK_QOS_PRINTF("83xx Port rate configure failed!\n");
			return FAILED;
		}
	}
	else if((_param[2] != NULL) && (!(memcmp(_param[2],"SHOW",strlen(_param[2])))))
	{	
		if((_param[3] != NULL) && (!(memcmp(_param[3],"PORT_BASED_PRI",strlen(_param[3]))))){
			send_data.action = PORT_BASED_PRIORITY_SHOW_83XX;
		}
		else if((_param[3] != NULL) && (!(memcmp(_param[3],"DOT1P_BASED_PRI",strlen(_param[3]))))){
			send_data.action = DOT1P_BASED_PRIORITY_SHOW_83XX;
		}
		else if((_param[3] != NULL) && (!(memcmp(_param[3],"DSCP_BASED_PRI",strlen(_param[3]))))){
			send_data.action = DSCP_BASED_PRIORITY_SHOW_83XX;
		}
		else if((_param[3] != NULL) && (!(memcmp(_param[3],"CVLAN_BASED_PRI",strlen(_param[3]))))){
			send_data.action = CVLAN_BASED_PRIORITY_SHOW_83XX;
		}
		else if((_param[3] != NULL) && (!(memcmp(_param[3],"SVLAN_BASED_PRI",strlen(_param[3]))))){
			send_data.action = SVLAN_BASED_PRIORITY_SHOW_83XX;
		}
		else if((_param[3] != NULL) && (!(memcmp(_param[3],"DMAC_BASED_PRI",strlen(_param[3]))))){
			send_data.action = DMAC_BASED_PRIORITY_SHOW_83XX;
		}
		else if((_param[3] != NULL) && (!(memcmp(_param[3],"SMAC_BASED_PRI",strlen(_param[3]))))){
			send_data.action = SMAC_BASED_PRIORITY_SHOW_83XX;
		}
		else if((_param[3] != NULL) && (!(memcmp(_param[3],"QUEUE_NUMBER",strlen(_param[3]))))){
			send_data.action = QUEUE_NUMBER_SHOW_83XX;
		}
		else if((_param[3] != NULL) && (!(memcmp(_param[3],"QUEUE_TYPE_STRICT",strlen(_param[3]))))){
			send_data.action = QUEUE_TYPE_STRICT_SHOW_83XX;
		}
		else if((_param[3] != NULL) && (!(memcmp(_param[3],"QUEUE_TYPE_WEIGHTED",strlen(_param[3]))))){
			send_data.action = QUEUE_TYPE_WEIGHTED_SHOW_83XX;
		}
		else if((_param[3] != NULL) && (!(memcmp(_param[3],"PRIORITY_TO_QID",strlen(_param[3]))))){
			send_data.action = PRIORITY_TO_QID_SHOW_83XX;
		}
		else if((_param[3] != NULL) && (!(memcmp(_param[3],"PRIORITY_DECISION",strlen(_param[3]))))){
			send_data.action = PRIORITY_DECISION_SHOW_83XX;
		}
		else if((_param[3] != NULL) && (!(memcmp(_param[3],"DOT1P_REMARK",strlen(_param[3]))))){
			send_data.action = DOT1P_REMARK_SHOW_83XX;
		}
		else if((_param[3] != NULL) && (!(memcmp(_param[3],"DSCP_REMARK",strlen(_param[3]))))){
			send_data.action = DSCP_REMARK_SHOW_83XX;
		}
		else if((_param[3] != NULL) && (!(memcmp(_param[3],"QUEUE_RATE",strlen(_param[3]))))){
			send_data.action = QUEUE_RATE_SHOW_83XX;
		}
		else if((_param[3] != NULL) && (!(memcmp(_param[3],"PORT_RATE",strlen(_param[3]))))){
			send_data.action = PORT_RATE_SHOW_83XX;
		}
		else if((_param[3] != NULL) && (!(memcmp(_param[3],"STATUS",strlen(_param[3]))))){
			send_data.action = QOS_STATUS_SHOW_83XX;
		}
		else{
			printf("rtk 83xxqos show failed!\n");
			return FAILED;
		}
	}
	else if((_param[2] != NULL) && (!(memcmp(_param[2],"ENABLE",strlen(_param[2]))))){
		send_data.action = QOS_ENABLE_83XX;
	}
	else if((_param[2] != NULL) && (!(memcmp(_param[2],"DISABLE",strlen(_param[2]))))){
		send_data.action = QOS_DISABLE_83XX;
	}
	else
	{
		printf("This command is not formal rtk 83xxqos cmd, please try again!\n");
		return FAILED;
	}

	send_info.len 	= sizeof(qos83xx_cmd_info_t);
	send_info.data 	= &send_data;
	recv_info.len	= sizeof(qos83xx_cmd_info_t);
	recv_info.data	= &recv_data;
	rtk_netlink(NETLINK_RTK_HW_83XX_QOS, &send_info, &recv_info);
#endif	
	return SUCCESS;
}


