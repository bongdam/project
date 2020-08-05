#ifndef	__DAVO_SNMP_H__
#define	__DAVO_SNMP_H__

typedef struct {
    char trap_srv[64];
    char trap_kind[64];
    char trap_file[64];
} TIL, *pTIL;

#define INIT_TIL(target) \
	do { \
        target.trap_srv[0] = target.trap_kind[0] = target.trap_file[0] = '\0'; \
	} while(0)

#define STRONGCMP(x, x2)	(optarg[0] == (x) || optarg[0] == (x2))
#define SNMP_AGENT_PID_FILE     "/var/run/snmp_agentd.pid"
#define SNMP_TRAP_PID_FILE     "/var/run/snmp_trapd.pid"

#define DVSNMP_MAX_COMMUNITY_LEN    80
#define DVSNMP_MAX_TRAP_SERVER_LEN  80
#define DVSNMP_MAX_TRAP_SERVER      1

typedef struct DAVO_SNMP_CFG {
    char getcommunity[DVSNMP_MAX_COMMUNITY_LEN];
    char setcommunity[DVSNMP_MAX_COMMUNITY_LEN];
    char trpcommunity[DVSNMP_MAX_COMMUNITY_LEN];
    unsigned short snmpport;
	char trapserver[DVSNMP_MAX_TRAP_SERVER][DVSNMP_MAX_TRAP_SERVER_LEN];
} TDV_SNMP_CFG;

TDV_SNMP_CFG dvsnmp_cfg;

char *get_getcommunity();
char *get_setcommunity();

int snmptrapmain(void);
#endif
