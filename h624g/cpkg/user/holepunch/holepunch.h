#ifndef __HOLEPUNCHING_H__
#define __HOLEPUNCHING_H__

#define HZ 1

#define TICK2USEC(x) ((x)*10000)
#define TICK2SEC(x) (x)
#define SEC2TICK(x) (x)

#define TMR_REBOOT  0
#define TMR_KA 		1
#define TMR_SVRPOLL	2
#define TMR_REPORT	3
#define TMR_IGMP		4
#define TMR_RESOURCE	5
#define TMR_TRAFFIC		6
#define TMR_MAX		7

#define LOCAL_MCAST(x)  (((x) &0xFFFFFF00) == 0xE0000000)
#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))

#define TIME_AFTER_EQ(unknown, known) ((long)(known)-(long)(unknown) <= 0)

#define read_pid(file) read_int(file,0)
#define HOLEPUNCH_PID_FILE     "/var/run/holepunch.pid"

#define HOLE_DEBUG(mask, fmt, arg ...) do { if (g_debug_flag & (mask))  printf(fmt, ## arg); } while(0)
#define PORT_STATUS_COUNTER_MAX 0x0fffffff

#define Keep_live_time 60		//replace "holepunch_control_interval"
#define Send_report_time 3600

#define HOLEPUNCH_VERSION "2.1.8"
#define SNMPWALK_RESULT "/tmp/.snmpwalk_result"

typedef enum {
	CMD_TYPE_ID_CMD = 1,
	CMD_TYPE_ID_KEEP_ALIVE,
	CMD_TYPE_ID_ACK,
	CMD_TYPE_ID_ERROR,
	CMD_TYPE_ID_END
} CMD_TYPE_ID;

typedef enum {
	KEY_ID_SEQ = 1,
	KEY_ID_RESP_SEQ,
	KEY_ID_T,
	KEY_ID_NEED_ACK,
	KEY_ID_ARGS,
	KEY_ID_RESULT,
	KEY_ID_CMD,
	KEY_ID_END
} KEYID;

typedef enum {
	CMD_ID_RESET = 1,
	CMD_GET_REPORT_SVR_INFO,
	CMD_GET_WIFI_STATUS,
	CMD_SET_WIFI_STATUS,
	CMD_GET_SSID_STATUS,
	CMD_SET_SSID_STATUS,
	CMD_GET_SSID_RATE,
	CMD_SET_SSID_RATE,
	CMD_GET_IGMP_JOIN_TABLE,
	CMD_GET_PORT_STATUS,
	CMD_GET_RESOURCE_STATUS,
	CMD_START_PORT_STATUS_REPORT,
	CMD_SEND_PORT_STATUS_REPORT,
	CMD_STOP_PORT_STATUS_REPORT,
	CMD_START_IGMP_JOIN_TABLE_REPORT,
	CMD_STOP_IGMP_JOIN_TABLE_REPORT,
	CMD_SEND_IGMP_JOIN_TABLE_REPORT,
	CMD_START_RESOURCE_STATUS_REPORT,
	CMD_STOP_RESOURCE_STATUS_REPORT,
	CMD_SEND_RESOURCE_STATUS_REPORT,
	CMD_GET_VERSION,
	CMD_GET_SNMP,
	CMD_SET_SNMP,
	CMD_GET_SNMPWALK,
	CMD_TRAFFIC_REPORT,
	CMD_STOP_TRAFFIC_REPORT,
	CMD_SEND_TRAFFIC_REPORT,
	CMD_SET_ADMIN_PW_INIT,
	CMD_ID_CRC,
	CMD_ID_END
} CMD_ID;

struct _AP_info {
	char sysname[32];
	char version[32];
	char mac_wan[13];
	char mac_wifi[13];
	char mac_wifi_5g[13];
	char IP[16];
};

struct _HolePunching_PKT {
	int seq;
	int resp_seq;
	CMD_TYPE_ID cmd_type;
	int need_ack;
	char args[256];
	CMD_ID cmd;
	char result[1024];
};

#define TYPE_INT	0x1
#define TYPE_CHAR	0x2
#define TYPE_STR	0x4

struct _Hole_punch_info {
	unsigned int control_server_ip;
	unsigned short control_server_port;
	unsigned int report_server_ip;
	unsigned short report_server_port;
	unsigned int seq;
	int sock_fd;
	struct _AP_info ap_info;
};

struct _Port_status {
	unsigned int count;
	int interval;
	unsigned int stop_count;
	int seq;
	int resp_seq;
	CMD_TYPE_ID cmd_type;
	CMD_ID cmd;
	char result[256];
};

struct _Igmp_join {
	unsigned int count;
	int interval;
	unsigned int stop_count;
};

struct _traffic_status {
	unsigned int count;
	int interval;
	unsigned int stop_count;
};

struct _Resource_status {
	unsigned int count;
	int interval;
	unsigned int stop_count;
};

struct _port_status {
	unsigned long long inputOCT;
	unsigned long long outputOCT;
	unsigned long CRC;
};

struct _wlan_status {
    unsigned char addr[6];
	unsigned long wlanOutBytes;
	unsigned long wlanInBytes;
	int check;
	int rssi;
	char txrate[24];
};

typedef struct {
	char *name;
	KEYID id;
	int must;
	int type;
} key_variable;

typedef struct {
	char *name;
	CMD_ID id;
	int type;
} cmd_variable;

typedef struct {
	char *name;
	CMD_TYPE_ID id;
} cmd_type_variable;

#define MAX_STATION_NUM 64
#define STA_INFO_FLAG_ASOC 0x04

#endif
