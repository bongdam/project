#ifndef _SNMP_TRAP_H__
#define _SNMP_TRAP_H__

/*
**  Oid for Trap (MIB-2)
*/
/* MIB object snmpMIB = snmpModules, 1 */
# define I_snmpMIB   1
# define O_snmpMIB   1, 3, 6, 1, 6, 3, 1

/* MIB object snmpMIBObjects = snmpMIB, 1 */
# define I_snmpMIBObjects    1
# define O_snmpMIBObjects    1, 3, 6, 1, 6, 3, 1, 1

/* MIB object sysUpTime = system, 3 */
# define I_sysUpTime 3
# define O_sysUpTime 1, 3, 6, 1, 2, 1, 1, 3

/* MIB object snmpTrap = snmpMIBObjects, 4 */
# define I_snmpTrap  4
# define O_snmpTrap  1, 3, 6, 1, 6, 3, 1, 1, 4

/* MIB object snmpTrapOID = snmpTrap, 1 */
# define I_snmpTrapOID   1
# define O_snmpTrapOID   1, 3, 6, 1, 6, 3, 1, 1, 4, 1

/* MIB object snmpTrapEnterprise = snmpTrap, 3 */
# define I_snmpTrapEnterprise    3
# define O_snmpTrapEnterprise    1, 3, 6, 1, 6, 3, 1, 1, 4, 3

/* MIB object snmpTraps = snmpMIBObjects, 5 */
# define I_snmpTraps 5
# define O_snmpTraps 1, 3, 6, 1, 6, 3, 1, 1, 5

/* MIB object coldStart = snmpTraps, 1 */
# define I_coldStart 1
# define O_coldStart 1, 3, 6, 1, 6, 3, 1, 1, 5, 1

/* MIB object warmStart = snmpTraps, 2 */
# define I_warmStart 2
# define O_warmStart 1, 3, 6, 1, 6, 3, 1, 1, 5, 2

/* MIB object linkDown = snmpTraps, 3 */
# define I_linkDown  3
# define O_linkDown  1, 3, 6, 1, 6, 3, 1, 1, 5, 3

/* MIB object linkUp = snmpTraps, 4 */
# define I_linkUp    4
# define O_linkUp    1, 3, 6, 1, 6, 3, 1, 1, 5, 4

/* MIB object authenticationFailure = snmpTraps, 5 */
# define I_authenticationFailure 5
# define O_authenticationFailure 1, 3, 6, 1, 6, 3, 1, 1, 5, 5

/* MIB object snmpSet = snmpMIBObjects, 6 */
# define I_snmpSet   6
# define O_snmpSet   1, 3, 6, 1, 6, 3, 1, 1, 6

/* MIB object snmpSetSerialNo = snmpSet, 1 */
# define I_snmpSetSerialNo   1
# define O_snmpSetSerialNo   1, 3, 6, 1, 6, 3, 1, 1, 6, 1

/* MIB object snmpMIBConformance = snmpMIB, 2 */
# define I_snmpMIBConformance    2
# define O_snmpMIBConformance    1, 3, 6, 1, 6, 3, 1, 2

/* MIB object snmpMIBCompliances = snmpMIBConformance, 1 */
# define I_snmpMIBCompliances    1
# define O_snmpMIBCompliances    1, 3, 6, 1, 6, 3, 1, 2, 1

/* MIB object snmpMIBGroups = snmpMIBConformance, 2 */
# define I_snmpMIBGroups 2
# define O_snmpMIBGroups 1, 3, 6, 1, 6, 3, 1, 2, 2

/* MIB object snmpBasicCompliance = snmpMIBCompliances, 2 */
# define I_snmpBasicCompliance   2
# define O_snmpBasicCompliance   1, 3, 6, 1, 6, 3, 1, 2, 1, 2

/* MIB object snmpGroup = snmpMIBGroups, 8 */
# define I_snmpGroup 8
# define O_snmpGroup 1, 3, 6, 1, 6, 3, 1, 2, 2, 8

/* MIB object snmpCommunityGroup = snmpMIBGroups, 9 */
# define I_snmpCommunityGroup    9
# define O_snmpCommunityGroup    1, 3, 6, 1, 6, 3, 1, 2, 2, 9

/* MIB object snmpSetGroup = snmpMIBGroups, 5 */
# define I_snmpSetGroup  5
# define O_snmpSetGroup  1, 3, 6, 1, 6, 3, 1, 2, 2, 5

/* MIB object systemGroup = snmpMIBGroups, 6 */
# define I_systemGroup   6
# define O_systemGroup   1, 3, 6, 1, 6, 3, 1, 2, 2, 6

/* MIB object snmpBasicNotificationsGroup = snmpMIBGroups, 7 */
# define I_snmpBasicNotificationsGroup   7
# define O_snmpBasicNotificationsGroup   1, 3, 6, 1, 6, 3, 1, 2, 2, 7

#define NTP_OK "/tmp/ntp_ok"
#define HALF_DAY 43200

typedef struct {
	unsigned long period;
	unsigned long next;
} traptime_t;

typedef struct {
	traptime_t normal; // 30min, 1800sec
	traptime_t wlaninfo; // 1440min, 86400sec
	traptime_t client; // 720min, 43200sec
	traptime_t dummy; // 1min, 60sec, nothing random
	int dnsmode;
	char dns2[16];
} traplist_t;
#endif
