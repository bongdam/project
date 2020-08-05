#ifndef RTK_83XX_HW_QOS_H
#define RTK_83XX_HW_QOS_H

#define PORT_BASED_PRIORITY_ASSIGN_83XX 		1
#define PORT_BASED_PRIORITY_SHOW_83XX 			2

#define DOT1P_BASED_PRIORITY_ASSIGN_83XX		3
#define DOT1P_BASED_PRIORITY_SHOW_83XX 			4

#define DSCP_BASED_PRIORITY_ASSIGN_83XX 		5
#define DSCP_BASED_PRIORITY_SHOW_83XX 			6

#define CVLAN_BASED_PRIORITY_ASSIGN_83XX 		7
#define CVLAN_BASED_PRIORITY_SHOW_83XX 			8

#define SVLAN_BASED_PRIORITY_ASSIGN_83XX		9
#define SVLAN_BASED_PRIORITY_SHOW_83XX			10

#define DMAC_BASED_PRIORITY_ASSIGN_83XX 		11
#define DMAC_BASED_PRIORITY_SHOW_83XX 			12

#define SMAC_BASED_PRIORITY_ASSIGN_83XX 		13
#define SMAC_BASED_PRIORITY_SHOW_83XX 			14

#define QUEUE_NUMBER_83XX 						15
#define QUEUE_NUMBER_SHOW_83XX 					16

#define QUEUE_TYPE_STRICT_83XX 					17
#define QUEUE_TYPE_STRICT_SHOW_83XX 			18

#define QUEUE_TYPE_WEIGHTED_83XX 				19
#define QUEUE_TYPE_WEIGHTED_SHOW_83XX 			20

#define PRIORITY_TO_QID_83XX 					21
#define PRIORITY_TO_QID_SHOW_83XX 				22

#define PRIORITY_DECISION_83XX 					23
#define PRIORITY_DECISION_SHOW_83XX				24

#define DOT1P_REMARK_83XX 						25
#define DOT1P_REMARK_SHOW_83XX 					26

#define DSCP_REMARK_83XX 						27
#define DSCP_REMARK_SHOW_83XX					28

#define QUEUE_RATE_83XX 						29
#define QUEUE_RATE_SHOW_83XX 					30

#define PORT_RATE_83XX 							31
#define PORT_RATE_SHOW_83XX 					32

#define QOS_ENABLE_83XX							33	
#define QOS_DISABLE_83XX						34
#define QOS_STATUS_SHOW_83XX					35

#define DISABLE_83XX_DSCP_REMARK			36
#define DISABLE_83XX_DOT1P_REMARK			37

typedef struct {
	int action;
	union{
		struct{
			char val[8];
			unsigned int valmask;
		} port_based_priority, dot1p_based_priority, queue_num, sys_priority;
		struct{
			unsigned char dscp[64];
			unsigned int dscpmask1;
			unsigned int dscpmask2;
		}dscp_based_priority;
		struct{
			unsigned char queue[8][8];
			unsigned int portmask;
			unsigned int queuemask;
		}queue_type;
		struct{
			unsigned int decision[8];
		}pri_decision;
		struct{
			unsigned char remark[8];
			unsigned int portmask;
			unsigned int prioritymask;
		}dot1p_remark, dscp_remark;
		struct{
			unsigned int portmask;
			unsigned int queuemask;
			unsigned int rate[8][8];
		}queue_rate;
		struct{
			unsigned int portmask;
			unsigned int rate[8];
		}port_rate;
	} qos_data;
} qos83xx_cmd_info_t, *qos83xx_cmd_info_p;

int rtk_83xx_hw_qos_parse(int _num, char* _param[]);
#endif
