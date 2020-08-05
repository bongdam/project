#ifndef	_CJHV_AP_MIB_
#define	_CJHV_AP_MIB_

#define MAX_SNMP_STR 128
#define MAX_SNMP_OID 128

typedef struct glbBuffer {
	char gb_string[MAX_SNMP_STR];
	long gb_long;
	oid gb_oid[MAX_SNMP_OID];
	unsigned long gb_ip_address;
	unsigned long gb_counter;
	unsigned long gb_gauge;
	long gb_integer;
}*p_GB, GB;

void init_CJHV_AP_MIB();
void register_subtrees_of_CJHV_AP_MIB();

/* MIB object cjhv = enterprises, 6882 */
#define	I_cjhv	6882
#define	O_cjhv	1, 3, 6, 1, 4, 1, 6882

/* MIB object cjhvApModule = cjhv, 1 */
#define	I_cjhvApModule	1
#define	O_cjhvApModule	1, 3, 6, 1, 4, 1, 6882, 1

/* MIB object cjhvApBasicInfo = cjhvApModule, 1 */
#define	I_cjhvApBasicInfo	1
#define	O_cjhvApBasicInfo	1, 3, 6, 1, 4, 1, 6882, 1, 1

/* MIB object cjhvApConfigInfo = cjhvApModule, 2 */
#define	I_cjhvApConfigInfo	2
#define	O_cjhvApConfigInfo	1, 3, 6, 1, 4, 1, 6882, 1, 2

/* MIB object cjhvApStatus = cjhvApModule, 3 */
#define	I_cjhvApStatus	3
#define	O_cjhvApStatus	1, 3, 6, 1, 4, 1, 6882, 1, 3

/* MIB object cjhvApDiag = cjhvApModule, 4 */
#define	I_cjhvApDiag	4
#define	O_cjhvApDiag	1, 3, 6, 1, 4, 1, 6882, 1, 4

/* MIB object cjhvApTrap = cjhvApModule, 5 */
#define	I_cjhvApTrap	5
#define	O_cjhvApTrap	1, 3, 6, 1, 4, 1, 6882, 1, 5

/* MIB object cjhvApSystemInfo = cjhvApBasicInfo, 1 */
#define	I_cjhvApSystemInfo	1
#define	O_cjhvApSystemInfo	1, 3, 6, 1, 4, 1, 6882, 1, 1, 1

/* MIB object cjhvApSysModelName = cjhvApSystemInfo, 1 */
#define	I_cjhvApSysModelName	1
#define	O_cjhvApSysModelName	1, 3, 6, 1, 4, 1, 6882, 1, 1, 1, 1

/* MIB object cjhvApSysFirmwareVersion = cjhvApSystemInfo, 2 */
#define	I_cjhvApSysFirmwareVersion	2
#define	O_cjhvApSysFirmwareVersion	1, 3, 6, 1, 4, 1, 6882, 1, 1, 1, 2

/* MIB object cjhvApSysuptime = cjhvApSystemInfo, 3 */
#define	I_cjhvApSysuptime	3
#define	O_cjhvApSysuptime	1, 3, 6, 1, 4, 1, 6882, 1, 1, 1, 3

/* MIB object cjhvApSysCpu = cjhvApSystemInfo, 4 */
#define	I_cjhvApSysCpu	4
#define	O_cjhvApSysCpu	1, 3, 6, 1, 4, 1, 6882, 1, 1, 1, 4

/* MIB object cjhvApSysMemory = cjhvApSystemInfo, 5 */
#define	I_cjhvApSysMemory	5
#define	O_cjhvApSysMemory	1, 3, 6, 1, 4, 1, 6882, 1, 1, 1, 5

/* MIB object cjhvApWanUpTime = cjhvApSystemInfo, 6 */
#define	I_cjhvApWanUpTime	6
#define	O_cjhvApWanUpTime	1, 3, 6, 1, 4, 1, 6882, 1, 1, 1, 6

/* MIB object cjhvApSysFirmStatus = cjhvApSystemInfo, 7 */
#define	I_cjhvApSysFirmStatus	7
#define	O_cjhvApSysFirmStatus	1, 3, 6, 1, 4, 1, 6882, 1, 1, 1, 7

/* MIB object cjhvApSysWANCRC = cjhvApSystemInfo, 8 */
#define	I_cjhvApSysWANCRC	8
#define	O_cjhvApSysWANCRC	1, 3, 6, 1, 4, 1, 6882, 1, 1, 1, 8

/* MIB object cjhvApWanConfig = cjhvApConfigInfo, 1 */
#define	I_cjhvApWanConfig	1
#define	O_cjhvApWanConfig	1, 3, 6, 1, 4, 1, 6882, 1, 2, 1

/* MIB object cjhvApWanStatus = cjhvApWanConfig, 1 */
#define	I_cjhvApWanStatus	1
#define	O_cjhvApWanStatus	1, 3, 6, 1, 4, 1, 6882, 1, 2, 1, 1

/* MIB object cjhvApWanMacAddress = cjhvApWanConfig, 2 */
#define	I_cjhvApWanMacAddress	2
#define	O_cjhvApWanMacAddress	1, 3, 6, 1, 4, 1, 6882, 1, 2, 1, 2

/* MIB object cjhvApWanIpAddress = cjhvApWanConfig, 3 */
#define	I_cjhvApWanIpAddress	3
#define	O_cjhvApWanIpAddress	1, 3, 6, 1, 4, 1, 6882, 1, 2, 1, 3

/* MIB object cjhvApWanSubnetMask = cjhvApWanConfig, 4 */
#define	I_cjhvApWanSubnetMask	4
#define	O_cjhvApWanSubnetMask	1, 3, 6, 1, 4, 1, 6882, 1, 2, 1, 4

/* MIB object cjhvApWanDefaultGW = cjhvApWanConfig, 5 */
#define	I_cjhvApWanDefaultGW	5
#define	O_cjhvApWanDefaultGW	1, 3, 6, 1, 4, 1, 6882, 1, 2, 1, 5

/* MIB object cjhvApWanDNS1 = cjhvApWanConfig, 6 */
#define	I_cjhvApWanDNS1	6
#define	O_cjhvApWanDNS1	1, 3, 6, 1, 4, 1, 6882, 1, 2, 1, 6

/* MIB object cjhvApWanDNS2 = cjhvApWanConfig, 7 */
#define	I_cjhvApWanDNS2	7
#define	O_cjhvApWanDNS2	1, 3, 6, 1, 4, 1, 6882, 1, 2, 1, 7

/* MIB object cjhvApWanSetup = cjhvApWanConfig, 9 */
#define	I_cjhvApWanSetup	9
#define	O_cjhvApWanSetup	1, 3, 6, 1, 4, 1, 6882, 1, 2, 1, 9

/* MIB object cjhvApWanObtainIpMethodSet = cjhvApWanSetup, 1 */
#define	I_cjhvApWanObtainIpMethodSet	1
#define	O_cjhvApWanObtainIpMethodSet	1, 3, 6, 1, 4, 1, 6882, 1, 2, 1, 9, 1

/* MIB object cjhvApWanIpAddressSet = cjhvApWanSetup, 2 */
#define	I_cjhvApWanIpAddressSet	2
#define	O_cjhvApWanIpAddressSet	1, 3, 6, 1, 4, 1, 6882, 1, 2, 1, 9, 2

/* MIB object cjhvApWanSubnetMaskSet = cjhvApWanSetup, 3 */
#define	I_cjhvApWanSubnetMaskSet	3
#define	O_cjhvApWanSubnetMaskSet	1, 3, 6, 1, 4, 1, 6882, 1, 2, 1, 9, 3

/* MIB object cjhvApWanDefaultGWSet = cjhvApWanSetup, 4 */
#define	I_cjhvApWanDefaultGWSet	4
#define	O_cjhvApWanDefaultGWSet	1, 3, 6, 1, 4, 1, 6882, 1, 2, 1, 9, 4

/* MIB object cjhvApWanDNS1Set = cjhvApWanSetup, 5 */
#define	I_cjhvApWanDNS1Set	5
#define	O_cjhvApWanDNS1Set	1, 3, 6, 1, 4, 1, 6882, 1, 2, 1, 9, 5

/* MIB object cjhvApWanDNS2Set = cjhvApWanSetup, 6 */
#define	I_cjhvApWanDNS2Set	6
#define	O_cjhvApWanDNS2Set	1, 3, 6, 1, 4, 1, 6882, 1, 2, 1, 9, 6

/* MIB object cjhvApLanConfig = cjhvApConfigInfo, 2 */
#define	I_cjhvApLanConfig	2
#define	O_cjhvApLanConfig	1, 3, 6, 1, 4, 1, 6882, 1, 2, 2

/* MIB object cjhvApLanMacAddress = cjhvApLanConfig, 1 */
#define	I_cjhvApLanMacAddress	1
#define	O_cjhvApLanMacAddress	1, 3, 6, 1, 4, 1, 6882, 1, 2, 2, 1

/* MIB object cjhvApLanIpAddress = cjhvApLanConfig, 2 */
#define	I_cjhvApLanIpAddress	2
#define	O_cjhvApLanIpAddress	1, 3, 6, 1, 4, 1, 6882, 1, 2, 2, 2

/* MIB object cjhvApLanSubnetMask = cjhvApLanConfig, 3 */
#define	I_cjhvApLanSubnetMask	3
#define	O_cjhvApLanSubnetMask	1, 3, 6, 1, 4, 1, 6882, 1, 2, 2, 3

/* MIB object cjhvApLanSetup = cjhvApLanConfig, 4 */
#define	I_cjhvApLanSetup	4
#define	O_cjhvApLanSetup	1, 3, 6, 1, 4, 1, 6882, 1, 2, 2, 4

/* MIB object cjhvApLanIpAddressSet = cjhvApLanSetup, 1 */
#define	I_cjhvApLanIpAddressSet	1
#define	O_cjhvApLanIpAddressSet	1, 3, 6, 1, 4, 1, 6882, 1, 2, 2, 4, 1

/* MIB object cjhvApLanSubnetMaskSet = cjhvApLanSetup, 2 */
#define	I_cjhvApLanSubnetMaskSet	2
#define	O_cjhvApLanSubnetMaskSet	1, 3, 6, 1, 4, 1, 6882, 1, 2, 2, 4, 2

/* MIB object cjhvApLanDhcpEnable = cjhvApLanSetup, 3 */
#define	I_cjhvApLanDhcpEnable	3
#define	O_cjhvApLanDhcpEnable	1, 3, 6, 1, 4, 1, 6882, 1, 2, 2, 4, 3

/* MIB object cjhvApLanDhcpStartIPAddress = cjhvApLanSetup, 4 */
#define	I_cjhvApLanDhcpStartIPAddress	4
#define	O_cjhvApLanDhcpStartIPAddress	1, 3, 6, 1, 4, 1, 6882, 1, 2, 2, 4, 4

/* MIB object cjhvApLanDhcpEndIPAddress = cjhvApLanSetup, 5 */
#define	I_cjhvApLanDhcpEndIPAddress	5
#define	O_cjhvApLanDhcpEndIPAddress	1, 3, 6, 1, 4, 1, 6882, 1, 2, 2, 4, 5

/* MIB object cjhvApWlanConfig = cjhvApConfigInfo, 3 */
#define	I_cjhvApWlanConfig	3
#define	O_cjhvApWlanConfig	1, 3, 6, 1, 4, 1, 6882, 1, 2, 3

/* MIB object cjhvApWlanBasicConfig = cjhvApWlanConfig, 1 */
#define	I_cjhvApWlanBasicConfig	1
#define	O_cjhvApWlanBasicConfig	1, 3, 6, 1, 4, 1, 6882, 1, 2, 3, 1

/* MIB object cjhvApWlanMode = cjhvApWlanBasicConfig, 1 */
#define	I_cjhvApWlanMode	1
#define	O_cjhvApWlanMode	1, 3, 6, 1, 4, 1, 6882, 1, 2, 3, 1, 1

/* MIB object cjhvApWlanBand = cjhvApWlanBasicConfig, 2 */
#define	I_cjhvApWlanBand	2
#define	O_cjhvApWlanBand	1, 3, 6, 1, 4, 1, 6882, 1, 2, 3, 1, 2

/* MIB object cjhvApWlanChannelWidth = cjhvApWlanBasicConfig, 3 */
#define	I_cjhvApWlanChannelWidth	3
#define	O_cjhvApWlanChannelWidth	1, 3, 6, 1, 4, 1, 6882, 1, 2, 3, 1, 3

/* MIB object cjhvApWlanCtrlSideband = cjhvApWlanBasicConfig, 4 */
#define	I_cjhvApWlanCtrlSideband	4
#define	O_cjhvApWlanCtrlSideband	1, 3, 6, 1, 4, 1, 6882, 1, 2, 3, 1, 4

/* MIB object cjhvApWlanChannelNumber = cjhvApWlanBasicConfig, 5 */
#define	I_cjhvApWlanChannelNumber	5
#define	O_cjhvApWlanChannelNumber	1, 3, 6, 1, 4, 1, 6882, 1, 2, 3, 1, 5

/* MIB object cjhvApWlanDataRate = cjhvApWlanBasicConfig, 6 */
#define	I_cjhvApWlanDataRate	6
#define	O_cjhvApWlanDataRate	1, 3, 6, 1, 4, 1, 6882, 1, 2, 3, 1, 6

/* MIB object cjhvApWlanDataRate = cjhvApWlanBasicConfig, 7 */
#define	I_cjhvApWlanMode_5G		7
#define	O_cjhvApWlanMode_5G		1, 3, 6, 1, 4, 1, 6882, 1, 2, 3, 1, 7

/* MIB object cjhvApWlanDataRate = cjhvApWlanBasicConfig, 8 */
#define	I_cjhvApWlanBand_5G		8
#define	O_cjhvApWlanBand_5G		1, 3, 6, 1, 4, 1, 6882, 1, 2, 3, 1, 8

/* MIB object cjhvApWlanDataRate = cjhvApWlanBasicConfig, 9 */
#define	I_cjhvApWlanChannelWidth_5G		9
#define	O_cjhvApWlanChannelWidth_5G		1, 3, 6, 1, 4, 1, 6882, 1, 2, 3, 1, 9

/* MIB object cjhvApWlanDataRate = cjhvApWlanBasicConfig, 10 */
#define	I_cjhvApWlanChannelNumber_5G	10
#define	O_cjhvApWlanChannelNumber_5G	1, 3, 6, 1, 4, 1, 6882, 1, 2, 3, 1, 10

/* MIB object cjhvApWlanDataRate = cjhvApWlanBasicConfig, 11 */
#define	I_cjhvApWlanDataRate_5G		11
#define	O_cjhvApWlanDataRate_5G		1, 3, 6, 1, 4, 1, 6882, 1, 2, 3, 1, 11

/* MIB object cjhvApWlanSsidConfig = cjhvApWlanConfig, 2 */
#define	I_cjhvApWlanSsidConfig	2
#define	O_cjhvApWlanSsidConfig	1, 3, 6, 1, 4, 1, 6882, 1, 2, 3, 2

/* MIB object cjhvApWlanSsidConfigTable = cjhvApWlanSsidConfig, 1 */
#define	I_cjhvApWlanSsidConfigTable	1
#define	O_cjhvApWlanSsidConfigTable	1, 3, 6, 1, 4, 1, 6882, 1, 2, 3, 2, 1

/* MIB object cjhvApWlanSsidConfigEntry = cjhvApWlanSsidConfigTable, 1 */
#define	I_cjhvApWlanSsidConfigEntry	1
#define	O_cjhvApWlanSsidConfigEntry	1, 3, 6, 1, 4, 1, 6882, 1, 2, 3, 2, 1, 1

/* MIB object cjhvApWlanSsidConfigIndex = cjhvApWlanSsidConfigEntry, 1 */
#define	I_cjhvApWlanSsidConfigIndex	1
#define	O_cjhvApWlanSsidConfigIndex	1, 3, 6, 1, 4, 1, 6882, 1, 2, 3, 2, 1, 1, 1

/* MIB object cjhvApWlanSSID = cjhvApWlanSsidConfigEntry, 2 */
#define	I_cjhvApWlanSSID	2
#define	O_cjhvApWlanSSID	1, 3, 6, 1, 4, 1, 6882, 1, 2, 3, 2, 1, 1, 2

/* MIB object cjhvApWlanSSIDMode = cjhvApWlanSsidConfigEntry, 3 */
#define	I_cjhvApWlanSSIDMode	3
#define	O_cjhvApWlanSSIDMode	1, 3, 6, 1, 4, 1, 6882, 1, 2, 3, 2, 1, 1, 3

/* MIB object cjhvApWlanBcastSSIDMode = cjhvApWlanSsidConfigEntry, 4 */
#define	I_cjhvApWlanBcastSSIDMode	4
#define	O_cjhvApWlanBcastSSIDMode	1, 3, 6, 1, 4, 1, 6882, 1, 2, 3, 2, 1, 1, 4

/* MIB object cjhvApWlanSecEncrytion = cjhvApWlanSsidConfigEntry, 5 */
#define	I_cjhvApWlanSecEncrytion	5
#define	O_cjhvApWlanSecEncrytion	1, 3, 6, 1, 4, 1, 6882, 1, 2, 3, 2, 1, 1, 5

/* MIB object cjhvApWlanSecEncrytion = cjhvApWlanSsidConfigEntry, 6 */
#define	I_cjhvApWlanRateLimit		6
#define	O_cjhvApWlanRateLimit		1, 3, 6, 1, 4, 1, 6882, 1, 2, 3, 2, 1, 1, 6

/* MIB object cjhvApDummyIndex = cjhvApWlanConfig, 3 */
#define	I_cjhvApDummyIndex		3
#define	O_cjhvApDummyIndex		1, 3, 6, 1, 4, 1, 6882, 1, 2, 3, 3

/* MIB object cjhvApDummyIndex1 = cjhvApDummyIndex, 1 */
#define	I_cjhvApDummyIndex1		1
#define	O_cjhvApDummyIndex1		1, 3, 6, 1, 4, 1, 6882, 1, 2, 3, 3, 1

/* MIB object cjhvApDummyIndex2 = cjhvApDummyIndex, 2 */
#define	I_cjhvApDummyIndex2		2
#define	O_cjhvApDummyIndex2		1, 3, 6, 1, 4, 1, 6882, 1, 2, 3, 3, 2

/* MIB object cjhvApDummyIndex3 = cjhvApDummyIndex, 3 */
#define	I_cjhvApDummyIndex3		3
#define	O_cjhvApDummyIndex3		1, 3, 6, 1, 4, 1, 6882, 1, 2, 3, 3, 3

/* MIB object cjhvApDummyIndex4 = cjhvApDummyIndex, 4 */
#define	I_cjhvApDummyIndex4		4
#define	O_cjhvApDummyIndex4		1, 3, 6, 1, 4, 1, 6882, 1, 2, 3, 3, 4

/* MIB object cjhvApDummyIndex5 = cjhvApDummyIndex, 5 */
#define	I_cjhvApDummyIndex5		5
#define	O_cjhvApDummyIndex5		1, 3, 6, 1, 4, 1, 6882, 1, 2, 3, 3, 5

/* MIB object cjhvApDummyIndex6 = cjhvApDummyIndex, 6 */
#define	I_cjhvApDummyIndex6		6
#define	O_cjhvApDummyIndex6		1, 3, 6, 1, 4, 1, 6882, 1, 2, 3, 3, 6

/* MIB object cjhvApDummyIndex7 = cjhvApDummyIndex, 7 */
#define	I_cjhvApDummyIndex7		7
#define	O_cjhvApDummyIndex7		1, 3, 6, 1, 4, 1, 6882, 1, 2, 3, 3, 7

/* MIB object cjhvApDummyIndex8 = cjhvApDummyIndex, 8 */
#define	I_cjhvApDummyIndex8		8
#define	O_cjhvApDummyIndex8		1, 3, 6, 1, 4, 1, 6882, 1, 2, 3, 3, 8

/* MIB object cjhvApDummyIndex9 = cjhvApDummyIndex, 9 */
#define	I_cjhvApDummyIndex9		9
#define	O_cjhvApDummyIndex9		1, 3, 6, 1, 4, 1, 6882, 1, 2, 3, 3, 9

/* MIB object cjhvApDummyIndex10 = cjhvApDummyIndex, 10 */
#define	I_cjhvApDummyIndex10		10
#define	O_cjhvApDummyIndex10		1, 3, 6, 1, 4, 1, 6882, 1, 2, 3, 3, 10

/* MIB object cjhvApWlanAdjacentChannel = cjhvApWlanConfig, 6 */
#define	I_cjhvApWlanAdjacentChannel	6
#define	O_cjhvApWlanAdjacentChannel	1, 3, 6, 1, 4, 1, 6882, 1, 2, 3, 6

/* MIB object cjhvApWlanAdjacentChannelTable = cjhvApWlanAdjacentChannel, 1 */
#define	I_cjhvApWlanAdjacentChannelTable	1
#define	O_cjhvApWlanAdjacentChannelTable	1, 3, 6, 1, 4, 1, 6882, 1, 2, 3, 6, 1

/* MIB object cjhvApWlanAdjacentChannelEntry = cjhvApWlanAdjacentChannelTable, 1 */
#define	I_cjhvApWlanAdjacentChannelEntry	1
#define	O_cjhvApWlanAdjacentChannelEntry	1, 3, 6, 1, 4, 1, 6882, 1, 2, 3, 6, 1, 1

/* MIB object cjhvApWlanAdjacentChannelIndex = cjhvApWlanAdjacentChannelEntry, 1 */
#define	I_cjhvApWlanAdjacentChannelIndex	1
#define	O_cjhvApWlanAdjacentChannelIndex	1, 3, 6, 1, 4, 1, 6882, 1, 2, 3, 6, 1, 1, 1

/* MIB object cjhvApWlanAdjacentChannelNumber = cjhvApWlanAdjacentChannelEntry, 2 */
#define	I_cjhvApWlanAdjacentChannelNumber	2
#define	O_cjhvApWlanAdjacentChannelNumber	1, 3, 6, 1, 4, 1, 6882, 1, 2, 3, 6, 1, 1, 2

/* MIB object cjhvApWlanAdjacentChannelCount = cjhvApWlanAdjacentChannelEntry, 3 */
#define	I_cjhvApWlanAdjacentChannelCount	3
#define	O_cjhvApWlanAdjacentChannelCount	1, 3, 6, 1, 4, 1, 6882, 1, 2, 3, 6, 1, 1, 3

/* MIB object cjhvApWlanDataRate = cjhvApWlanBasicConfig, 7 */
#define	I_cjhvApBestChannelAlgorithm	2
#define	O_cjhvApBestChannelAlgorithm	1, 3, 6, 1, 4, 1, 6882, 1, 2, 3, 6,	2

/* MIB object cjhvApWlanAdjacentChannelTrap = cjhvApWlanAdjacentChannel, 2 */
#define	I_cjhvApWlanAdjacentChannelTrap	5
#define	O_cjhvApWlanAdjacentChannelTrap	1, 3, 6, 1, 4, 1, 6882, 1, 2, 3, 6, 5

/* MIB object cjhvApWlanAdjacentChannelTrap1 = cjhvApWlanAdjacentChannelTrap, 1 */
#define	I_cjhvApWlanAdjacentChannelTrap1	1
#define	O_cjhvApWlanAdjacentChannelTrap1	1, 3, 6, 1, 4, 1, 6882, 1, 2, 3, 6, 5, 1

/* MIB object cjhvApWlanAdjacentChannelTrapIndex1 = cjhvApWlanAdjacentChannelTrap1, 1 */
#define	I_cjhvApWlanAdjacentChannelTrapIndex1	1
#define	O_cjhvApWlanAdjacentChannelTrapIndex1	1, 3, 6, 1, 4, 1, 6882, 1, 2, 3, 6, 5, 1, 1

/* MIB object cjhvApWlanAdjacentChannelTrapNumber1 = cjhvApWlanAdjacentChannelTrap1, 2 */
#define	I_cjhvApWlanAdjacentChannelTrapNumber1	2
#define	O_cjhvApWlanAdjacentChannelTrapNumber1	1, 3, 6, 1, 4, 1, 6882, 1, 2, 3, 6, 5, 1, 2

/* MIB object cjhvApWlanAdjacentChannelTrapCount1 = cjhvApWlanAdjacentChannelTrap1, 3 */
#define	I_cjhvApWlanAdjacentChannelTrapCount1	3
#define	O_cjhvApWlanAdjacentChannelTrapCount1	1, 3, 6, 1, 4, 1, 6882, 1, 2, 3, 6, 5, 1, 3

/* MIB object cjhvApWlanAdjacentChannelTrap2 = cjhvApWlanAdjacentChannelTrap, 2 */
#define	I_cjhvApWlanAdjacentChannelTrap2	2
#define	O_cjhvApWlanAdjacentChannelTrap2	1, 3, 6, 1, 4, 1, 6882, 1, 2, 3, 6, 5, 2

/* MIB object cjhvApWlanAdjacentChannelTrapIndex2 = cjhvApWlanAdjacentChannelTrap2, 1 */
#define	I_cjhvApWlanAdjacentChannelTrapIndex2	1
#define	O_cjhvApWlanAdjacentChannelTrapIndex2	1, 3, 6, 1, 4, 1, 6882, 1, 2, 3, 6, 5, 2, 1

/* MIB object cjhvApWlanAdjacentChannelTrapNumber2 = cjhvApWlanAdjacentChannelTrap2, 2 */
#define	I_cjhvApWlanAdjacentChannelTrapNumber2	2
#define	O_cjhvApWlanAdjacentChannelTrapNumber2	1, 3, 6, 1, 4, 1, 6882, 1, 2, 3, 6, 5, 2, 2

/* MIB object cjhvApWlanAdjacentChannelTrapCount2 = cjhvApWlanAdjacentChannelTrap2, 3 */
#define	I_cjhvApWlanAdjacentChannelTrapCount2	3
#define	O_cjhvApWlanAdjacentChannelTrapCount2	1, 3, 6, 1, 4, 1, 6882, 1, 2, 3, 6, 5, 2, 3

/* MIB object cjhvApWlanAdjacentChannelTrap3 = cjhvApWlanAdjacentChannelTrap, 3 */
#define	I_cjhvApWlanAdjacentChannelTrap3	3
#define	O_cjhvApWlanAdjacentChannelTrap3	1, 3, 6, 1, 4, 1, 6882, 1, 2, 3, 6, 5, 3

/* MIB object cjhvApWlanAdjacentChannelTrapIndex3 = cjhvApWlanAdjacentChannelTrap3, 1 */
#define	I_cjhvApWlanAdjacentChannelTrapIndex3	1
#define	O_cjhvApWlanAdjacentChannelTrapIndex3	1, 3, 6, 1, 4, 1, 6882, 1, 2, 3, 6, 5, 3, 1

/* MIB object cjhvApWlanAdjacentChannelTrapNumber3 = cjhvApWlanAdjacentChannelTrap3, 2 */
#define	I_cjhvApWlanAdjacentChannelTrapNumber3	2
#define	O_cjhvApWlanAdjacentChannelTrapNumber3	1, 3, 6, 1, 4, 1, 6882, 1, 2, 3, 6, 5, 3, 2

/* MIB object cjhvApWlanAdjacentChannelTrapCount3 = cjhvApWlanAdjacentChannelTrap3, 3 */
#define	I_cjhvApWlanAdjacentChannelTrapCount3	3
#define	O_cjhvApWlanAdjacentChannelTrapCount3	1, 3, 6, 1, 4, 1, 6882, 1, 2, 3, 6, 5, 3, 3

/* MIB object cjhvApWlanAdjacentChannelTrap4 = cjhvApWlanAdjacentChannelTrap, 4 */
#define	I_cjhvApWlanAdjacentChannelTrap4	4
#define	O_cjhvApWlanAdjacentChannelTrap4	1, 3, 6, 1, 4, 1, 6882, 1, 2, 3, 6, 5, 4

/* MIB object cjhvApWlanAdjacentChannelTrapIndex4 = cjhvApWlanAdjacentChannelTrap4, 1 */
#define	I_cjhvApWlanAdjacentChannelTrapIndex4	1
#define	O_cjhvApWlanAdjacentChannelTrapIndex4	1, 3, 6, 1, 4, 1, 6882, 1, 2, 3, 6, 5, 4, 1

/* MIB object cjhvApWlanAdjacentChannelTrapNumber4 = cjhvApWlanAdjacentChannelTrap4, 2 */
#define	I_cjhvApWlanAdjacentChannelTrapNumber4	2
#define	O_cjhvApWlanAdjacentChannelTrapNumber4	1, 3, 6, 1, 4, 1, 6882, 1, 2, 3, 6, 5, 4, 2

/* MIB object cjhvApWlanAdjacentChannelTrapCount4 = cjhvApWlanAdjacentChannelTrap4, 3 */
#define	I_cjhvApWlanAdjacentChannelTrapCount4	3
#define	O_cjhvApWlanAdjacentChannelTrapCount4	1, 3, 6, 1, 4, 1, 6882, 1, 2, 3, 6, 5, 4, 3

/* MIB object cjhvApWlanAdjacentChannelTrap5 = cjhvApWlanAdjacentChannelTrap, 5 */
#define	I_cjhvApWlanAdjacentChannelTrap5	5
#define	O_cjhvApWlanAdjacentChannelTrap5	1, 3, 6, 1, 4, 1, 6882, 1, 2, 3, 6, 5, 5

/* MIB object cjhvApWlanAdjacentChannelTrapIndex5 = cjhvApWlanAdjacentChannelTrap5, 1 */
#define	I_cjhvApWlanAdjacentChannelTrapIndex5	1
#define	O_cjhvApWlanAdjacentChannelTrapIndex5	1, 3, 6, 1, 4, 1, 6882, 1, 2, 3, 6, 5, 5, 1

/* MIB object cjhvApWlanAdjacentChannelTrapNumber5 = cjhvApWlanAdjacentChannelTrap5, 2 */
#define	I_cjhvApWlanAdjacentChannelTrapNumber5	2
#define	O_cjhvApWlanAdjacentChannelTrapNumber5	1, 3, 6, 1, 4, 1, 6882, 1, 2, 3, 6, 5, 5, 2

/* MIB object cjhvApWlanAdjacentChannelTrapCount5 = cjhvApWlanAdjacentChannelTrap5, 3 */
#define	I_cjhvApWlanAdjacentChannelTrapCount5	3
#define	O_cjhvApWlanAdjacentChannelTrapCount5	1, 3, 6, 1, 4, 1, 6882, 1, 2, 3, 6, 5, 5, 3

/* MIB object cjhvApWlanAdjacentChannelTrap6 = cjhvApWlanAdjacentChannelTrap, 6 */
#define	I_cjhvApWlanAdjacentChannelTrap6	6
#define	O_cjhvApWlanAdjacentChannelTrap6	1, 3, 6, 1, 4, 1, 6882, 1, 2, 3, 6, 5, 6

/* MIB object cjhvApWlanAdjacentChannelTrapIndex6 = cjhvApWlanAdjacentChannelTrap6, 1 */
#define	I_cjhvApWlanAdjacentChannelTrapIndex6	1
#define	O_cjhvApWlanAdjacentChannelTrapIndex6	1, 3, 6, 1, 4, 1, 6882, 1, 2, 3, 6, 5, 6, 1

/* MIB object cjhvApWlanAdjacentChannelTrapNumber6 = cjhvApWlanAdjacentChannelTrap6, 2 */
#define	I_cjhvApWlanAdjacentChannelTrapNumber6	2
#define	O_cjhvApWlanAdjacentChannelTrapNumber6	1, 3, 6, 1, 4, 1, 6882, 1, 2, 3, 6, 5, 6, 2

/* MIB object cjhvApWlanAdjacentChannelTrapCount6 = cjhvApWlanAdjacentChannelTrap6, 3 */
#define	I_cjhvApWlanAdjacentChannelTrapCount6	3
#define	O_cjhvApWlanAdjacentChannelTrapCount6	1, 3, 6, 1, 4, 1, 6882, 1, 2, 3, 6, 5, 6, 3

/* MIB object cjhvApWlanAdjacentChannelTrap7 = cjhvApWlanAdjacentChannelTrap, 7 */
#define	I_cjhvApWlanAdjacentChannelTrap7	7
#define	O_cjhvApWlanAdjacentChannelTrap7	1, 3, 6, 1, 4, 1, 6882, 1, 2, 3, 6, 5, 7

/* MIB object cjhvApWlanAdjacentChannelTrapIndex7 = cjhvApWlanAdjacentChannelTrap7, 1 */
#define	I_cjhvApWlanAdjacentChannelTrapIndex7	1
#define	O_cjhvApWlanAdjacentChannelTrapIndex7	1, 3, 6, 1, 4, 1, 6882, 1, 2, 3, 6, 5, 7, 1

/* MIB object cjhvApWlanAdjacentChannelTrapNumber7 = cjhvApWlanAdjacentChannelTrap7, 2 */
#define	I_cjhvApWlanAdjacentChannelTrapNumber7	2
#define	O_cjhvApWlanAdjacentChannelTrapNumber7	1, 3, 6, 1, 4, 1, 6882, 1, 2, 3, 6, 5, 7, 2

/* MIB object cjhvApWlanAdjacentChannelTrapCount7 = cjhvApWlanAdjacentChannelTrap7, 3 */
#define	I_cjhvApWlanAdjacentChannelTrapCount7	3
#define	O_cjhvApWlanAdjacentChannelTrapCount7	1, 3, 6, 1, 4, 1, 6882, 1, 2, 3, 6, 5, 7, 3

/* MIB object cjhvApWlanAdjacentChannelTrap8 = cjhvApWlanAdjacentChannelTrap, 8 */
#define	I_cjhvApWlanAdjacentChannelTrap8	8
#define	O_cjhvApWlanAdjacentChannelTrap8	1, 3, 6, 1, 4, 1, 6882, 1, 2, 3, 6, 5, 8

/* MIB object cjhvApWlanAdjacentChannelTrapIndex8 = cjhvApWlanAdjacentChannelTrap8, 1 */
#define	I_cjhvApWlanAdjacentChannelTrapIndex8	1
#define	O_cjhvApWlanAdjacentChannelTrapIndex8	1, 3, 6, 1, 4, 1, 6882, 1, 2, 3, 6, 5, 8, 1

/* MIB object cjhvApWlanAdjacentChannelTrapNumber8 = cjhvApWlanAdjacentChannelTrap8, 2 */
#define	I_cjhvApWlanAdjacentChannelTrapNumber8	2
#define	O_cjhvApWlanAdjacentChannelTrapNumber8	1, 3, 6, 1, 4, 1, 6882, 1, 2, 3, 6, 5, 8, 2

/* MIB object cjhvApWlanAdjacentChannelTrapCount8 = cjhvApWlanAdjacentChannelTrap8, 3 */
#define	I_cjhvApWlanAdjacentChannelTrapCount8	3
#define	O_cjhvApWlanAdjacentChannelTrapCount8	1, 3, 6, 1, 4, 1, 6882, 1, 2, 3, 6, 5, 8, 3

/* MIB object cjhvApWlanAdjacentChannelTrap9 = cjhvApWlanAdjacentChannelTrap, 9 */
#define	I_cjhvApWlanAdjacentChannelTrap9	9
#define	O_cjhvApWlanAdjacentChannelTrap9	1, 3, 6, 1, 4, 1, 6882, 1, 2, 3, 6, 5, 9

/* MIB object cjhvApWlanAdjacentChannelTrapIndex9 = cjhvApWlanAdjacentChannelTrap9, 1 */
#define	I_cjhvApWlanAdjacentChannelTrapIndex9	1
#define	O_cjhvApWlanAdjacentChannelTrapIndex9	1, 3, 6, 1, 4, 1, 6882, 1, 2, 3, 6, 5, 9, 1

/* MIB object cjhvApWlanAdjacentChannelTrapNumber9 = cjhvApWlanAdjacentChannelTrap9, 2 */
#define	I_cjhvApWlanAdjacentChannelTrapNumber9	2
#define	O_cjhvApWlanAdjacentChannelTrapNumber9	1, 3, 6, 1, 4, 1, 6882, 1, 2, 3, 6, 5, 9, 2

/* MIB object cjhvApWlanAdjacentChannelTrapCount9 = cjhvApWlanAdjacentChannelTrap9, 3 */
#define	I_cjhvApWlanAdjacentChannelTrapCount9	3
#define	O_cjhvApWlanAdjacentChannelTrapCount9	1, 3, 6, 1, 4, 1, 6882, 1, 2, 3, 6, 5, 9, 3

/* MIB object cjhvApWlanAdjacentChannelTrap10 = cjhvApWlanAdjacentChannelTrap, 10 */
#define	I_cjhvApWlanAdjacentChannelTrap10	10
#define	O_cjhvApWlanAdjacentChannelTrap10	1, 3, 6, 1, 4, 1, 6882, 1, 2, 3, 6, 5, 10

/* MIB object cjhvApWlanAdjacentChannelTrapIndex10 = cjhvApWlanAdjacentChannelTrap10, 1 */
#define	I_cjhvApWlanAdjacentChannelTrapIndex10	1
#define	O_cjhvApWlanAdjacentChannelTrapIndex10	1, 3, 6, 1, 4, 1, 6882, 1, 2, 3, 6, 5, 10, 1

/* MIB object cjhvApWlanAdjacentChannelTrapNumber10 = cjhvApWlanAdjacentChannelTrap10, 2 */
#define	I_cjhvApWlanAdjacentChannelTrapNumber10	2
#define	O_cjhvApWlanAdjacentChannelTrapNumber10	1, 3, 6, 1, 4, 1, 6882, 1, 2, 3, 6, 5, 10, 2

/* MIB object cjhvApWlanAdjacentChannelTrapCount10 = cjhvApWlanAdjacentChannelTrap10, 3 */
#define	I_cjhvApWlanAdjacentChannelTrapCount10	3
#define	O_cjhvApWlanAdjacentChannelTrapCount10	1, 3, 6, 1, 4, 1, 6882, 1, 2, 3, 6, 5, 10, 3

/* MIB object cjhvApWlanAdjacentChannelTrap11 = cjhvApWlanAdjacentChannelTrap, 11 */
#define	I_cjhvApWlanAdjacentChannelTrap11	11
#define	O_cjhvApWlanAdjacentChannelTrap11	1, 3, 6, 1, 4, 1, 6882, 1, 2, 3, 6, 5, 11

/* MIB object cjhvApWlanAdjacentChannelTrapIndex11 = cjhvApWlanAdjacentChannelTrap11, 1 */
#define	I_cjhvApWlanAdjacentChannelTrapIndex11	1
#define	O_cjhvApWlanAdjacentChannelTrapIndex11	1, 3, 6, 1, 4, 1, 6882, 1, 2, 3, 6, 5, 11, 1

/* MIB object cjhvApWlanAdjacentChannelTrapNumber11 = cjhvApWlanAdjacentChannelTrap11, 2 */
#define	I_cjhvApWlanAdjacentChannelTrapNumber11	2
#define	O_cjhvApWlanAdjacentChannelTrapNumber11	1, 3, 6, 1, 4, 1, 6882, 1, 2, 3, 6, 5, 11, 2

/* MIB object cjhvApWlanAdjacentChannelTrapCount11 = cjhvApWlanAdjacentChannelTrap11, 3 */
#define	I_cjhvApWlanAdjacentChannelTrapCount11	3
#define	O_cjhvApWlanAdjacentChannelTrapCount11	1, 3, 6, 1, 4, 1, 6882, 1, 2, 3, 6, 5, 11, 3

/* MIB object cjhvApWlanAdjacentChannelTrap12 = cjhvApWlanAdjacentChannelTrap, 12 */
#define	I_cjhvApWlanAdjacentChannelTrap12	12
#define	O_cjhvApWlanAdjacentChannelTrap12	1, 3, 6, 1, 4, 1, 6882, 1, 2, 3, 6, 5, 12

/* MIB object cjhvApWlanAdjacentChannelTrapIndex12 = cjhvApWlanAdjacentChannelTrap12, 1 */
#define	I_cjhvApWlanAdjacentChannelTrapIndex12	1
#define	O_cjhvApWlanAdjacentChannelTrapIndex12	1, 3, 6, 1, 4, 1, 6882, 1, 2, 3, 6, 5, 12, 1

/* MIB object cjhvApWlanAdjacentChannelTrapNumber12 = cjhvApWlanAdjacentChannelTrap12, 2 */
#define	I_cjhvApWlanAdjacentChannelTrapNumber12	2
#define	O_cjhvApWlanAdjacentChannelTrapNumber12	1, 3, 6, 1, 4, 1, 6882, 1, 2, 3, 6, 5, 12, 2

/* MIB object cjhvApWlanAdjacentChannelTrapCount12 = cjhvApWlanAdjacentChannelTrap12, 3 */
#define	I_cjhvApWlanAdjacentChannelTrapCount12	3
#define	O_cjhvApWlanAdjacentChannelTrapCount12	1, 3, 6, 1, 4, 1, 6882, 1, 2, 3, 6, 5, 12, 3

/* MIB object cjhvApWlanAdjacentChannelTrap13 = cjhvApWlanAdjacentChannelTrap, 13 */
#define	I_cjhvApWlanAdjacentChannelTrap13	13
#define	O_cjhvApWlanAdjacentChannelTrap13	1, 3, 6, 1, 4, 1, 6882, 1, 2, 3, 6, 5, 13

/* MIB object cjhvApWlanAdjacentChannelTrapIndex13 = cjhvApWlanAdjacentChannelTrap13, 1 */
#define	I_cjhvApWlanAdjacentChannelTrapIndex13	1
#define	O_cjhvApWlanAdjacentChannelTrapIndex13	1, 3, 6, 1, 4, 1, 6882, 1, 2, 3, 6, 5, 13, 1

/* MIB object cjhvApWlanAdjacentChannelTrapNumber13 = cjhvApWlanAdjacentChannelTrap13, 2 */
#define	I_cjhvApWlanAdjacentChannelTrapNumber13	2
#define	O_cjhvApWlanAdjacentChannelTrapNumber13	1, 3, 6, 1, 4, 1, 6882, 1, 2, 3, 6, 5, 13, 2

/* MIB object cjhvApWlanAdjacentChannelTrapCount13 = cjhvApWlanAdjacentChannelTrap13, 3 */
#define	I_cjhvApWlanAdjacentChannelTrapCount13	3
#define	O_cjhvApWlanAdjacentChannelTrapCount13	1, 3, 6, 1, 4, 1, 6882, 1, 2, 3, 6, 5, 13, 3

/* MIB object cjhvApWlanAdjacentChannelTrap14 = cjhvApWlanAdjacentChannelTrap, 14 */
#define	I_cjhvApWlanAdjacentChannelTrap14	14
#define	O_cjhvApWlanAdjacentChannelTrap14	1, 3, 6, 1, 4, 1, 6882, 1, 2, 3, 6, 5, 14

/* MIB object cjhvApWlanAdjacentChannelTrapIndex14 = cjhvApWlanAdjacentChannelTrap14, 1 */
#define	I_cjhvApWlanAdjacentChannelTrapIndex14	1
#define	O_cjhvApWlanAdjacentChannelTrapIndex14	1, 3, 6, 1, 4, 1, 6882, 1, 2, 3, 6, 5, 14, 1

/* MIB object cjhvApWlanAdjacentChannelTrapNumber14 = cjhvApWlanAdjacentChannelTrap14, 2 */
#define	I_cjhvApWlanAdjacentChannelTrapNumber14	2
#define	O_cjhvApWlanAdjacentChannelTrapNumber14	1, 3, 6, 1, 4, 1, 6882, 1, 2, 3, 6, 5, 14, 2

/* MIB object cjhvApWlanAdjacentChannelTrapCount14 = cjhvApWlanAdjacentChannelTrap14, 3 */
#define	I_cjhvApWlanAdjacentChannelTrapCount14	3
#define	O_cjhvApWlanAdjacentChannelTrapCount14	1, 3, 6, 1, 4, 1, 6882, 1, 2, 3, 6, 5, 14, 3

/* MIB object cjhvApWlanAdjacentChannelTrap15 = cjhvApWlanAdjacentChannelTrap, 15 */
#define	I_cjhvApWlanAdjacentChannelTrap15	15
#define	O_cjhvApWlanAdjacentChannelTrap15	1, 3, 6, 1, 4, 1, 6882, 1, 2, 3, 6, 5, 15

/* MIB object cjhvApWlanAdjacentChannelTrapIndex15 = cjhvApWlanAdjacentChannelTrap15, 1 */
#define	I_cjhvApWlanAdjacentChannelTrapIndex15	1
#define	O_cjhvApWlanAdjacentChannelTrapIndex15	1, 3, 6, 1, 4, 1, 6882, 1, 2, 3, 6, 5, 15, 1

/* MIB object cjhvApWlanAdjacentChannelTrapNumber15 = cjhvApWlanAdjacentChannelTrap15, 2 */
#define	I_cjhvApWlanAdjacentChannelTrapNumber15	2
#define	O_cjhvApWlanAdjacentChannelTrapNumber15	1, 3, 6, 1, 4, 1, 6882, 1, 2, 3, 6, 5, 15, 2

/* MIB object cjhvApWlanAdjacentChannelTrapCount15 = cjhvApWlanAdjacentChannelTrap15, 3 */
#define	I_cjhvApWlanAdjacentChannelTrapCount15	3
#define	O_cjhvApWlanAdjacentChannelTrapCount15	1, 3, 6, 1, 4, 1, 6882, 1, 2, 3, 6, 5, 15, 3

/* MIB object cjhvApWlanAdjacentChannelTrap16 = cjhvApWlanAdjacentChannelTrap, 16 */
#define	I_cjhvApWlanAdjacentChannelTrap16	16
#define	O_cjhvApWlanAdjacentChannelTrap16	1, 3, 6, 1, 4, 1, 6882, 1, 2, 3, 6, 5, 16

/* MIB object cjhvApWlanAdjacentChannelTrapIndex16 = cjhvApWlanAdjacentChannelTrap16, 1 */
#define	I_cjhvApWlanAdjacentChannelTrapIndex16	1
#define	O_cjhvApWlanAdjacentChannelTrapIndex16	1, 3, 6, 1, 4, 1, 6882, 1, 2, 3, 6, 5, 16, 1

/* MIB object cjhvApWlanAdjacentChannelTrapNumber16 = cjhvApWlanAdjacentChannelTrap16, 2 */
#define	I_cjhvApWlanAdjacentChannelTrapNumber16	2
#define	O_cjhvApWlanAdjacentChannelTrapNumber16	1, 3, 6, 1, 4, 1, 6882, 1, 2, 3, 6, 5, 16, 2

/* MIB object cjhvApWlanAdjacentChannelTrapCount16 = cjhvApWlanAdjacentChannelTrap16, 3 */
#define	I_cjhvApWlanAdjacentChannelTrapCount16	3
#define	O_cjhvApWlanAdjacentChannelTrapCount16	1, 3, 6, 1, 4, 1, 6882, 1, 2, 3, 6, 5, 16, 3

/* MIB object cjhvApWlanAdjacentChannelTrap17 = cjhvApWlanAdjacentChannelTrap, 17 */
#define	I_cjhvApWlanAdjacentChannelTrap17	17
#define	O_cjhvApWlanAdjacentChannelTrap17	1, 3, 6, 1, 4, 1, 6882, 1, 2, 3, 6, 5, 17

/* MIB object cjhvApWlanAdjacentChannelTrapIndex17 = cjhvApWlanAdjacentChannelTrap17, 1 */
#define	I_cjhvApWlanAdjacentChannelTrapIndex17	1
#define	O_cjhvApWlanAdjacentChannelTrapIndex17	1, 3, 6, 1, 4, 1, 6882, 1, 2, 3, 6, 5, 17, 1

/* MIB object cjhvApWlanAdjacentChannelTrapNumber17 = cjhvApWlanAdjacentChannelTrap17, 2 */
#define	I_cjhvApWlanAdjacentChannelTrapNumber17	2
#define	O_cjhvApWlanAdjacentChannelTrapNumber17	1, 3, 6, 1, 4, 1, 6882, 1, 2, 3, 6, 5, 17, 2

/* MIB object cjhvApWlanAdjacentChannelTrapCount17 = cjhvApWlanAdjacentChannelTrap17, 3 */
#define	I_cjhvApWlanAdjacentChannelTrapCount17	3
#define	O_cjhvApWlanAdjacentChannelTrapCount17	1, 3, 6, 1, 4, 1, 6882, 1, 2, 3, 6, 5, 17, 3

/* MIB object cjhvApWlanAdjacentChannelTrap18 = cjhvApWlanAdjacentChannelTrap, 18 */
#define	I_cjhvApWlanAdjacentChannelTrap18	18
#define	O_cjhvApWlanAdjacentChannelTrap18	1, 3, 6, 1, 4, 1, 6882, 1, 2, 3, 6, 5, 18

/* MIB object cjhvApWlanAdjacentChannelTrapIndex18 = cjhvApWlanAdjacentChannelTrap18, 1 */
#define	I_cjhvApWlanAdjacentChannelTrapIndex18	1
#define	O_cjhvApWlanAdjacentChannelTrapIndex18	1, 3, 6, 1, 4, 1, 6882, 1, 2, 3, 6, 5, 18, 1

/* MIB object cjhvApWlanAdjacentChannelTrapNumber18 = cjhvApWlanAdjacentChannelTrap18, 2 */
#define	I_cjhvApWlanAdjacentChannelTrapNumber18	2
#define	O_cjhvApWlanAdjacentChannelTrapNumber18	1, 3, 6, 1, 4, 1, 6882, 1, 2, 3, 6, 5, 18, 2

/* MIB object cjhvApWlanAdjacentChannelTrapCount18 = cjhvApWlanAdjacentChannelTrap18, 3 */
#define	I_cjhvApWlanAdjacentChannelTrapCount18	3
#define	O_cjhvApWlanAdjacentChannelTrapCount18	1, 3, 6, 1, 4, 1, 6882, 1, 2, 3, 6, 5, 18, 3

/* MIB object cjhvApWlanAdjacentChannelTrap19 = cjhvApWlanAdjacentChannelTrap, 19 */
#define	I_cjhvApWlanAdjacentChannelTrap19	19
#define	O_cjhvApWlanAdjacentChannelTrap19	1, 3, 6, 1, 4, 1, 6882, 1, 2, 3, 6, 5, 19

/* MIB object cjhvApWlanAdjacentChannelTrapIndex19 = cjhvApWlanAdjacentChannelTrap19, 1 */
#define	I_cjhvApWlanAdjacentChannelTrapIndex19	1
#define	O_cjhvApWlanAdjacentChannelTrapIndex19	1, 3, 6, 1, 4, 1, 6882, 1, 2, 3, 6, 5, 19, 1

/* MIB object cjhvApWlanAdjacentChannelTrapNumber19 = cjhvApWlanAdjacentChannelTrap19, 2 */
#define	I_cjhvApWlanAdjacentChannelTrapNumber19	2
#define	O_cjhvApWlanAdjacentChannelTrapNumber19	1, 3, 6, 1, 4, 1, 6882, 1, 2, 3, 6, 5, 19, 2

/* MIB object cjhvApWlanAdjacentChannelTrapCount19 = cjhvApWlanAdjacentChannelTrap19, 3 */
#define	I_cjhvApWlanAdjacentChannelTrapCount19	3
#define	O_cjhvApWlanAdjacentChannelTrapCount19	1, 3, 6, 1, 4, 1, 6882, 1, 2, 3, 6, 5, 19, 3

/* MIB object cjhvApWlanAdjacentChannelTrap20 = cjhvApWlanAdjacentChannelTrap, 20 */
#define	I_cjhvApWlanAdjacentChannelTrap20	20
#define	O_cjhvApWlanAdjacentChannelTrap20	1, 3, 6, 1, 4, 1, 6882, 1, 2, 3, 6, 5, 20

/* MIB object cjhvApWlanAdjacentChannelTrapIndex20 = cjhvApWlanAdjacentChannelTrap20, 1 */
#define	I_cjhvApWlanAdjacentChannelTrapIndex20	1
#define	O_cjhvApWlanAdjacentChannelTrapIndex20	1, 3, 6, 1, 4, 1, 6882, 1, 2, 3, 6, 5, 20, 1

/* MIB object cjhvApWlanAdjacentChannelTrapNumber20 = cjhvApWlanAdjacentChannelTrap20, 2 */
#define	I_cjhvApWlanAdjacentChannelTrapNumber20	2
#define	O_cjhvApWlanAdjacentChannelTrapNumber20	1, 3, 6, 1, 4, 1, 6882, 1, 2, 3, 6, 5, 20, 2

/* MIB object cjhvApWlanAdjacentChannelTrapCount20 = cjhvApWlanAdjacentChannelTrap20, 3 */
#define	I_cjhvApWlanAdjacentChannelTrapCount20	3
#define	O_cjhvApWlanAdjacentChannelTrapCount20	1, 3, 6, 1, 4, 1, 6882, 1, 2, 3, 6, 5, 20, 3

/* MIB object cjhvApWlanAdjacentChannelTrap21 = cjhvApWlanAdjacentChannelTrap, 21 */
#define	I_cjhvApWlanAdjacentChannelTrap21	21
#define	O_cjhvApWlanAdjacentChannelTrap21	1, 3, 6, 1, 4, 1, 6882, 1, 2, 3, 6, 5, 21

/* MIB object cjhvApWlanAdjacentChannelTrapIndex21 = cjhvApWlanAdjacentChannelTrap21, 1 */
#define	I_cjhvApWlanAdjacentChannelTrapIndex21	1
#define	O_cjhvApWlanAdjacentChannelTrapIndex21	1, 3, 6, 1, 4, 1, 6882, 1, 2, 3, 6, 5, 21, 1

/* MIB object cjhvApWlanAdjacentChannelTrapNumber21 = cjhvApWlanAdjacentChannelTrap21, 2 */
#define	I_cjhvApWlanAdjacentChannelTrapNumber21	2
#define	O_cjhvApWlanAdjacentChannelTrapNumber21	1, 3, 6, 1, 4, 1, 6882, 1, 2, 3, 6, 5, 21, 2

/* MIB object cjhvApWlanAdjacentChannelTrapCount21 = cjhvApWlanAdjacentChannelTrap21, 3 */
#define	I_cjhvApWlanAdjacentChannelTrapCount21	3
#define	O_cjhvApWlanAdjacentChannelTrapCount21	1, 3, 6, 1, 4, 1, 6882, 1, 2, 3, 6, 5, 21, 3

/* MIB object cjhvApWlanAdjacentChannelTrap22 = cjhvApWlanAdjacentChannelTrap, 22 */
#define	I_cjhvApWlanAdjacentChannelTrap22	22
#define	O_cjhvApWlanAdjacentChannelTrap22	1, 3, 6, 1, 4, 1, 6882, 1, 2, 3, 6, 5, 22

/* MIB object cjhvApWlanAdjacentChannelTrapIndex22 = cjhvApWlanAdjacentChannelTrap22, 1 */
#define	I_cjhvApWlanAdjacentChannelTrapIndex22	1
#define	O_cjhvApWlanAdjacentChannelTrapIndex22	1, 3, 6, 1, 4, 1, 6882, 1, 2, 3, 6, 5, 22, 1

/* MIB object cjhvApWlanAdjacentChannelTrapNumber22 = cjhvApWlanAdjacentChannelTrap22, 2 */
#define	I_cjhvApWlanAdjacentChannelTrapNumber22	2
#define	O_cjhvApWlanAdjacentChannelTrapNumber22	1, 3, 6, 1, 4, 1, 6882, 1, 2, 3, 6, 5, 22, 2

/* MIB object cjhvApWlanAdjacentChannelTrapCount22 = cjhvApWlanAdjacentChannelTrap22, 3 */
#define	I_cjhvApWlanAdjacentChannelTrapCount22	3
#define	O_cjhvApWlanAdjacentChannelTrapCount22	1, 3, 6, 1, 4, 1, 6882, 1, 2, 3, 6, 5, 22, 3

/* MIB object cjhvApWlanAdjacentChannelTrap23 = cjhvApWlanAdjacentChannelTrap, 23 */
#define	I_cjhvApWlanAdjacentChannelTrap23	23
#define	O_cjhvApWlanAdjacentChannelTrap23	1, 3, 6, 1, 4, 1, 6882, 1, 2, 3, 6, 5, 23

/* MIB object cjhvApWlanAdjacentChannelTrapIndex23 = cjhvApWlanAdjacentChannelTrap23, 1 */
#define	I_cjhvApWlanAdjacentChannelTrapIndex23	1
#define	O_cjhvApWlanAdjacentChannelTrapIndex23	1, 3, 6, 1, 4, 1, 6882, 1, 2, 3, 6, 5, 23, 1

/* MIB object cjhvApWlanAdjacentChannelTrapNumber23 = cjhvApWlanAdjacentChannelTrap23, 2 */
#define	I_cjhvApWlanAdjacentChannelTrapNumber23	2
#define	O_cjhvApWlanAdjacentChannelTrapNumber23	1, 3, 6, 1, 4, 1, 6882, 1, 2, 3, 6, 5, 23, 2

/* MIB object cjhvApWlanAdjacentChannelTrapCount23 = cjhvApWlanAdjacentChannelTrap23, 3 */
#define	I_cjhvApWlanAdjacentChannelTrapCount23	3
#define	O_cjhvApWlanAdjacentChannelTrapCount23	1, 3, 6, 1, 4, 1, 6882, 1, 2, 3, 6, 5, 23, 3

/* MIB object cjhvApWlanAdjacentChannelTrap24 = cjhvApWlanAdjacentChannelTrap, 24 */
#define	I_cjhvApWlanAdjacentChannelTrap24	24
#define	O_cjhvApWlanAdjacentChannelTrap24	1, 3, 6, 1, 4, 1, 6882, 1, 2, 3, 6, 5, 24

/* MIB object cjhvApWlanAdjacentChannelTrapIndex24 = cjhvApWlanAdjacentChannelTrap24, 1 */
#define	I_cjhvApWlanAdjacentChannelTrapIndex24	1
#define	O_cjhvApWlanAdjacentChannelTrapIndex24	1, 3, 6, 1, 4, 1, 6882, 1, 2, 3, 6, 5, 24, 1

/* MIB object cjhvApWlanAdjacentChannelTrapNumber24 = cjhvApWlanAdjacentChannelTrap24, 2 */
#define	I_cjhvApWlanAdjacentChannelTrapNumber24	2
#define	O_cjhvApWlanAdjacentChannelTrapNumber24	1, 3, 6, 1, 4, 1, 6882, 1, 2, 3, 6, 5, 24, 2

/* MIB object cjhvApWlanAdjacentChannelTrapCount24 = cjhvApWlanAdjacentChannelTrap24, 3 */
#define	I_cjhvApWlanAdjacentChannelTrapCount24	3
#define	O_cjhvApWlanAdjacentChannelTrapCount24	1, 3, 6, 1, 4, 1, 6882, 1, 2, 3, 6, 5, 24, 3

/* MIB object cjhvApWlanAdjacentChannelTrap25 = cjhvApWlanAdjacentChannelTrap, 25 */
#define	I_cjhvApWlanAdjacentChannelTrap25	25
#define	O_cjhvApWlanAdjacentChannelTrap25	1, 3, 6, 1, 4, 1, 6882, 1, 2, 3, 6, 5, 25

/* MIB object cjhvApWlanAdjacentChannelTrapIndex25 = cjhvApWlanAdjacentChannelTrap25, 1 */
#define	I_cjhvApWlanAdjacentChannelTrapIndex25	1
#define	O_cjhvApWlanAdjacentChannelTrapIndex25	1, 3, 6, 1, 4, 1, 6882, 1, 2, 3, 6, 5, 25, 1

/* MIB object cjhvApWlanAdjacentChannelTrapNumber25 = cjhvApWlanAdjacentChannelTrap25, 2 */
#define	I_cjhvApWlanAdjacentChannelTrapNumber25	2
#define	O_cjhvApWlanAdjacentChannelTrapNumber25	1, 3, 6, 1, 4, 1, 6882, 1, 2, 3, 6, 5, 25, 2

/* MIB object cjhvApWlanAdjacentChannelTrapCount25 = cjhvApWlanAdjacentChannelTrap25, 3 */
#define	I_cjhvApWlanAdjacentChannelTrapCount25	3
#define	O_cjhvApWlanAdjacentChannelTrapCount25	1, 3, 6, 1, 4, 1, 6882, 1, 2, 3, 6, 5, 25, 3

/* MIB object cjhvApWlanAdjacentChannelTrap26 = cjhvApWlanAdjacentChannelTrap, 26 */
#define	I_cjhvApWlanAdjacentChannelTrap26	26
#define	O_cjhvApWlanAdjacentChannelTrap26	1, 3, 6, 1, 4, 1, 6882, 1, 2, 3, 6, 5, 26

/* MIB object cjhvApWlanAdjacentChannelTrapIndex26 = cjhvApWlanAdjacentChannelTrap26, 1 */
#define	I_cjhvApWlanAdjacentChannelTrapIndex26	1
#define	O_cjhvApWlanAdjacentChannelTrapIndex26	1, 3, 6, 1, 4, 1, 6882, 1, 2, 3, 6, 5, 26, 1

/* MIB object cjhvApWlanAdjacentChannelTrapNumber26 = cjhvApWlanAdjacentChannelTrap26, 2 */
#define	I_cjhvApWlanAdjacentChannelTrapNumber26	2
#define	O_cjhvApWlanAdjacentChannelTrapNumber26	1, 3, 6, 1, 4, 1, 6882, 1, 2, 3, 6, 5, 26, 2

/* MIB object cjhvApWlanAdjacentChannelTrapCount26 = cjhvApWlanAdjacentChannelTrap26, 3 */
#define	I_cjhvApWlanAdjacentChannelTrapCount26	3
#define	O_cjhvApWlanAdjacentChannelTrapCount26	1, 3, 6, 1, 4, 1, 6882, 1, 2, 3, 6, 5, 26, 3

/* MIB object cjhvApWlanAdjacentChannelTrap27 = cjhvApWlanAdjacentChannelTrap, 27 */
#define	I_cjhvApWlanAdjacentChannelTrap27	27
#define	O_cjhvApWlanAdjacentChannelTrap27	1, 3, 6, 1, 4, 1, 6882, 1, 2, 3, 6, 5, 27

/* MIB object cjhvApWlanAdjacentChannelTrapIndex27 = cjhvApWlanAdjacentChannelTrap27, 1 */
#define	I_cjhvApWlanAdjacentChannelTrapIndex27	1
#define	O_cjhvApWlanAdjacentChannelTrapIndex27	1, 3, 6, 1, 4, 1, 6882, 1, 2, 3, 6, 5, 27, 1

/* MIB object cjhvApWlanAdjacentChannelTrapNumber27 = cjhvApWlanAdjacentChannelTrap27, 2 */
#define	I_cjhvApWlanAdjacentChannelTrapNumber27	2
#define	O_cjhvApWlanAdjacentChannelTrapNumber27	1, 3, 6, 1, 4, 1, 6882, 1, 2, 3, 6, 5, 27, 2

/* MIB object cjhvApWlanAdjacentChannelTrapCount27 = cjhvApWlanAdjacentChannelTrap27, 3 */
#define	I_cjhvApWlanAdjacentChannelTrapCount27	3
#define	O_cjhvApWlanAdjacentChannelTrapCount27	1, 3, 6, 1, 4, 1, 6882, 1, 2, 3, 6, 5, 27, 3

/* MIB object cjhvApWlanAdjacentChannelTrap28 = cjhvApWlanAdjacentChannelTrap, 28 */
#define	I_cjhvApWlanAdjacentChannelTrap28	28
#define	O_cjhvApWlanAdjacentChannelTrap28	1, 3, 6, 1, 4, 1, 6882, 1, 2, 3, 6, 5, 28

/* MIB object cjhvApWlanAdjacentChannelTrapIndex28 = cjhvApWlanAdjacentChannelTrap28, 1 */
#define	I_cjhvApWlanAdjacentChannelTrapIndex28	1
#define	O_cjhvApWlanAdjacentChannelTrapIndex28	1, 3, 6, 1, 4, 1, 6882, 1, 2, 3, 6, 5, 28, 1

/* MIB object cjhvApWlanAdjacentChannelTrapNumber28 = cjhvApWlanAdjacentChannelTrap28, 2 */
#define	I_cjhvApWlanAdjacentChannelTrapNumber28	2
#define	O_cjhvApWlanAdjacentChannelTrapNumber28	1, 3, 6, 1, 4, 1, 6882, 1, 2, 3, 6, 5, 28, 2

/* MIB object cjhvApWlanAdjacentChannelTrapCount28 = cjhvApWlanAdjacentChannelTrap28, 3 */
#define	I_cjhvApWlanAdjacentChannelTrapCount28	3
#define	O_cjhvApWlanAdjacentChannelTrapCount28	1, 3, 6, 1, 4, 1, 6882, 1, 2, 3, 6, 5, 28, 3

/* MIB object cjhvApWlanAdjacentChannelTrap29 = cjhvApWlanAdjacentChannelTrap, 29 */
#define	I_cjhvApWlanAdjacentChannelTrap29	29
#define	O_cjhvApWlanAdjacentChannelTrap29	1, 3, 6, 1, 4, 1, 6882, 1, 2, 3, 6, 5, 29

/* MIB object cjhvApWlanAdjacentChannelTrapIndex29 = cjhvApWlanAdjacentChannelTrap29, 1 */
#define	I_cjhvApWlanAdjacentChannelTrapIndex29	1
#define	O_cjhvApWlanAdjacentChannelTrapIndex29	1, 3, 6, 1, 4, 1, 6882, 1, 2, 3, 6, 5, 29, 1

/* MIB object cjhvApWlanAdjacentChannelTrapNumber29 = cjhvApWlanAdjacentChannelTrap29, 2 */
#define	I_cjhvApWlanAdjacentChannelTrapNumber29	2
#define	O_cjhvApWlanAdjacentChannelTrapNumber29	1, 3, 6, 1, 4, 1, 6882, 1, 2, 3, 6, 5, 29, 2

/* MIB object cjhvApWlanAdjacentChannelTrapCount29 = cjhvApWlanAdjacentChannelTrap29, 3 */
#define	I_cjhvApWlanAdjacentChannelTrapCount29	3
#define	O_cjhvApWlanAdjacentChannelTrapCount29	1, 3, 6, 1, 4, 1, 6882, 1, 2, 3, 6, 5, 29, 3

/* MIB object cjhvApWlanAdjacentChannelTrap30 = cjhvApWlanAdjacentChannelTrap, 30 */
#define	I_cjhvApWlanAdjacentChannelTrap30	30
#define	O_cjhvApWlanAdjacentChannelTrap30	1, 3, 6, 1, 4, 1, 6882, 1, 2, 3, 6, 5, 30

/* MIB object cjhvApWlanAdjacentChannelTrapIndex30 = cjhvApWlanAdjacentChannelTrap30, 1 */
#define	I_cjhvApWlanAdjacentChannelTrapIndex30	1
#define	O_cjhvApWlanAdjacentChannelTrapIndex30	1, 3, 6, 1, 4, 1, 6882, 1, 2, 3, 6, 5, 30, 1

/* MIB object cjhvApWlanAdjacentChannelTrapNumber30 = cjhvApWlanAdjacentChannelTrap30, 2 */
#define	I_cjhvApWlanAdjacentChannelTrapNumber30	2
#define	O_cjhvApWlanAdjacentChannelTrapNumber30	1, 3, 6, 1, 4, 1, 6882, 1, 2, 3, 6, 5, 30, 2

/* MIB object cjhvApWlanAdjacentChannelTrapCount30 = cjhvApWlanAdjacentChannelTrap30, 3 */
#define	I_cjhvApWlanAdjacentChannelTrapCount30	3
#define	O_cjhvApWlanAdjacentChannelTrapCount30	1, 3, 6, 1, 4, 1, 6882, 1, 2, 3, 6, 5, 30, 3

/* MIB object cjhvApWlanAdjacentChannelTrap31 = cjhvApWlanAdjacentChannelTrap, 31 */
#define	I_cjhvApWlanAdjacentChannelTrap31	31
#define	O_cjhvApWlanAdjacentChannelTrap31	1, 3, 6, 1, 4, 1, 6882, 1, 2, 3, 6, 5, 31

/* MIB object cjhvApWlanAdjacentChannelTrapIndex31 = cjhvApWlanAdjacentChannelTrap31, 1 */
#define	I_cjhvApWlanAdjacentChannelTrapIndex31	1
#define	O_cjhvApWlanAdjacentChannelTrapIndex31	1, 3, 6, 1, 4, 1, 6882, 1, 2, 3, 6, 5, 31, 1

/* MIB object cjhvApWlanAdjacentChannelTrapNumber31 = cjhvApWlanAdjacentChannelTrap31, 2 */
#define	I_cjhvApWlanAdjacentChannelTrapNumber31	2
#define	O_cjhvApWlanAdjacentChannelTrapNumber31	1, 3, 6, 1, 4, 1, 6882, 1, 2, 3, 6, 5, 31, 2

/* MIB object cjhvApWlanAdjacentChannelTrapCount31 = cjhvApWlanAdjacentChannelTrap31, 3 */
#define	I_cjhvApWlanAdjacentChannelTrapCount31	3
#define	O_cjhvApWlanAdjacentChannelTrapCount31	1, 3, 6, 1, 4, 1, 6882, 1, 2, 3, 6, 5, 31, 3

/* MIB object cjhvApWlanAdvancedConfig = cjhvApWlanConfig, 7 */
#define	I_cjhvApWlanAdvancedConfig	7
#define	O_cjhvApWlanAdvancedConfig	1, 3, 6, 1, 4, 1, 6882, 1, 2, 3, 7

/* MIB object cjhvApWlanAdvFragmentThreshold = cjhvApWlanAdvancedConfig, 1 */
#define	I_cjhvApWlanAdvFragmentThreshold	1
#define	O_cjhvApWlanAdvFragmentThreshold	1, 3, 6, 1, 4, 1, 6882, 1, 2, 3, 7, 1

/* MIB object cjhvApWlanAdvRTSThreshold = cjhvApWlanAdvancedConfig, 2 */
#define	I_cjhvApWlanAdvRTSThreshold	2
#define	O_cjhvApWlanAdvRTSThreshold	1, 3, 6, 1, 4, 1, 6882, 1, 2, 3, 7, 2

/* MIB object cjhvApWlanAdvBeaconInterval = cjhvApWlanAdvancedConfig, 3 */
#define	I_cjhvApWlanAdvBeaconInterval	3
#define	O_cjhvApWlanAdvBeaconInterval	1, 3, 6, 1, 4, 1, 6882, 1, 2, 3, 7, 3

/* MIB object cjhvApWlanAdvPreambleType = cjhvApWlanAdvancedConfig, 4 */
#define	I_cjhvApWlanAdvPreambleType	4
#define	O_cjhvApWlanAdvPreambleType	1, 3, 6, 1, 4, 1, 6882, 1, 2, 3, 7, 4

/* MIB object cjhvApWlanAdvRFOutputPower = cjhvApWlanAdvancedConfig, 5 */
#define	I_cjhvApWlanAdvRFOutputPower	5
#define	O_cjhvApWlanAdvRFOutputPower	1, 3, 6, 1, 4, 1, 6882, 1, 2, 3, 7, 5

/* MIB object cjhvApWlanAdvancedConfig_5g = cjhvApWlanConfig, 8 */
#define	I_cjhvApWlanAdvancedConfig_5g	8
#define	O_cjhvApWlanAdvancedConfig_5g	1, 3, 6, 1, 4, 1, 6882, 1, 2, 3, 8

/* MIB object cjhvApWlanAdvFragmentThreshold_5g = cjhvApWlanAdvancedConfig_5g, 1 */
#define	I_cjhvApWlanAdvFragmentThreshold_5g		1
#define	O_cjhvApWlanAdvFragmentThreshold_5g		1, 3, 6, 1, 4, 1, 6882, 1, 2, 3, 8, 1

/* MIB object cjhvApWlanAdvRTSThreshold_5g = cjhvApWlanAdvancedConfig_5g, 2 */
#define	I_cjhvApWlanAdvRTSThreshold_5g		2
#define	O_cjhvApWlanAdvRTSThreshold_5g		1, 3, 6, 1, 4, 1, 6882, 1, 2, 3, 8, 2

/* MIB object cjhvApWlanAdvBeaconInterval_5g = cjhvApWlanAdvancedConfig_5g, 3 */
#define	I_cjhvApWlanAdvBeaconInterval_5g	3
#define	O_cjhvApWlanAdvBeaconInterval_5g	1, 3, 6, 1, 4, 1, 6882, 1, 2, 3, 8, 3

/* MIB object cjhvApWlanAdvPreambleType_5g = cjhvApWlanAdvancedConfig_5g, 4 */
#define	I_cjhvApWlanAdvPreambleType_5g		4
#define	O_cjhvApWlanAdvPreambleType_5g		1, 3, 6, 1, 4, 1, 6882, 1, 2, 3, 8, 4

/* MIB object cjhvApWlanAdvRFOutputPower_5g = cjhvApWlanAdvancedConfig_5g, 5 */
#define	I_cjhvApWlanAdvRFOutputPower_5g		5
#define	O_cjhvApWlanAdvRFOutputPower_5g		1, 3, 6, 1, 4, 1, 6882, 1, 2, 3, 8, 5

/* MIB object cjhvApWlanClientInfo = cjhvApConfigInfo, 4 */
#define	I_cjhvApWlanClientInfo	4
#define	O_cjhvApWlanClientInfo	1, 3, 6, 1, 4, 1, 6882, 1, 2, 4

/* MIB object cjhvApWlanClientTable = cjhvApWlanClientInfo, 1 */
#define	I_cjhvApWlanClientTable	1
#define	O_cjhvApWlanClientTable	1, 3, 6, 1, 4, 1, 6882, 1, 2, 4, 1

/* MIB object cjhvApWlanClientEntry = cjhvApWlanClientTable, 1 */
#define	I_cjhvApWlanClientEntry	1
#define	O_cjhvApWlanClientEntry	1, 3, 6, 1, 4, 1, 6882, 1, 2, 4, 1, 1

/* MIB object cjhvApWlanClientIndex = cjhvApWlanClientEntry, 1 */
#define	I_cjhvApWlanClientIndex	1
#define	O_cjhvApWlanClientIndex	1, 3, 6, 1, 4, 1, 6882, 1, 2, 4, 1, 1, 1

/* MIB object cjhvApWlanClientMac = cjhvApWlanClientEntry, 2 */
#define	I_cjhvApWlanClientMac	2
#define	O_cjhvApWlanClientMac	1, 3, 6, 1, 4, 1, 6882, 1, 2, 4, 1, 1, 2

/* MIB object cjhvApWlanClientIp = cjhvApWlanClientEntry, 3 */
#define	I_cjhvApWlanClientIp	3
#define	O_cjhvApWlanClientIp	1, 3, 6, 1, 4, 1, 6882, 1, 2, 4, 1, 1, 3

/*150831 add  ClientName / ClientMode / ClientBand / ClientRssi / ClientCRC Table */
/* MIB object cjhvApWlanClientName = cjhvApWlanClientEntry, 4 */
#define	I_cjhvApWlanClientName	4
#define	O_cjhvApWlanClientName	1, 3, 6, 1, 4, 1, 6882, 1, 2, 4, 1, 1, 4

/* MIB object cjhvApWlanClientMode = cjhvApWlanClientEntry, 5 */
#define	I_cjhvApWlanClientMode	5
#define	O_cjhvApWlanClientMode	1, 3, 6, 1, 4, 1, 6882, 1, 2, 4, 1, 1, 5

/* MIB object cjhvApWlanClientBand = cjhvApWlanClientEntry, 6 */
#define	I_cjhvApWlanClientBand	6
#define	O_cjhvApWlanClientBand	1, 3, 6, 1, 4, 1, 6882, 1, 2, 4, 1, 1, 6

/* MIB object cjhvApWlanClientRssi = cjhvApWlanClientEntry, 7 */
#define	I_cjhvApWlanClientRssi	7
#define	O_cjhvApWlanClientRssi	1, 3, 6, 1, 4, 1, 6882, 1, 2, 4, 1, 1, 7

/* MIB object cjhvApWlanClientRssi = cjhvApWlanClientEntry, 7 */
#define	I_cjhvApWlanClientCRC	8
#define	O_cjhvApWlanClientCRC	1, 3, 6, 1, 4, 1, 6882, 1, 2, 4, 1, 1, 8

/* MIB object cjhvApWlanClientInfoTrap = cjhvApWlanClientInfo, 2 */
#define	I_cjhvApWlanClientInfoTrap	2
#define	O_cjhvApWlanClientInfoTrap	1, 3, 6, 1, 4, 1, 6882, 1, 2, 4, 2

/* MIB object cjhvApWlanClientInfoTrap1 = cjhvApWlanClientInfoTrap, 1 */
#define	I_cjhvApWlanClientInfoTrap1	1
#define	O_cjhvApWlanClientInfoTrap1	1, 3, 6, 1, 4, 1, 6882, 1, 2, 4, 2, 1

/* MIB object cjhvApWlanClientInfoTrapIndex1 = cjhvApWlanClientInfoTrap1, 1 */
#define	I_cjhvApWlanClientInfoTrapIndex1	1
#define	O_cjhvApWlanClientInfoTrapIndex1	1, 3, 6, 1, 4, 1, 6882, 1, 2, 4, 2, 1, 1

/* MIB object cjhvApWlanClientTrapMac1 = cjhvApWlanClientInfoTrap1, 2 */
#define	I_cjhvApWlanClientTrapMac1	2
#define	O_cjhvApWlanClientTrapMac1	1, 3, 6, 1, 4, 1, 6882, 1, 2, 4, 2, 1, 2

/* MIB object cjhvApWlanClientTrapIp1 = cjhvApWlanClientInfoTrap1, 3 */
#define	I_cjhvApWlanClientTrapIp1	3
#define	O_cjhvApWlanClientTrapIp1	1, 3, 6, 1, 4, 1, 6882, 1, 2, 4, 2, 1, 3

/* MIB object cjhvApWlanClientTrapName1 = cjhvApWlanClientInfoTrap1, 4 */
#define	I_cjhvApWlanClientTrapName1		4
#define	O_cjhvApWlanClientTrapName1		1, 3, 6, 1, 4, 1, 6882, 1, 2, 4, 2, 1, 4

/* MIB object cjhvApWlanClientTrapMode1 = cjhvApWlanClientInfoTrap1, 5 */
#define	I_cjhvApWlanClientTrapMode1		5
#define	O_cjhvApWlanClientTrapMode1		1, 3, 6, 1, 4, 1, 6882, 1, 2, 4, 2, 1, 5

/* MIB object cjhvApWlanClientTrapBand1 = cjhvApWlanClientInfoTrap1, 6 */
#define	I_cjhvApWlanClientTrapBand1		6
#define	O_cjhvApWlanClientTrapBand1		1, 3, 6, 1, 4, 1, 6882, 1, 2, 4, 2, 1, 6

/* MIB object cjhvApWlanClientTrapRssi1 = cjhvApWlanClientInfoTrap1, 7 */
#define	I_cjhvApWlanClientTrapRssi1		7
#define	O_cjhvApWlanClientTrapRssi1		1, 3, 6, 1, 4, 1, 6882, 1, 2, 4, 2, 1, 7

/* MIB object cjhvApWlanClientInfoTrap2 = cjhvApWlanClientInfoTrap, 2 */
#define	I_cjhvApWlanClientInfoTrap2	2
#define	O_cjhvApWlanClientInfoTrap2	1, 3, 6, 1, 4, 1, 6882, 1, 2, 4, 2, 2

/* MIB object cjhvApWlanClientInfoTrapIndex2 = cjhvApWlanClientInfoTrap2, 1 */
#define	I_cjhvApWlanClientInfoTrapIndex2	1
#define	O_cjhvApWlanClientInfoTrapIndex2	1, 3, 6, 1, 4, 1, 6882, 1, 2, 4, 2, 2, 1

/* MIB object cjhvApWlanClientTrapMac2 = cjhvApWlanClientInfoTrap2, 2 */
#define	I_cjhvApWlanClientTrapMac2	2
#define	O_cjhvApWlanClientTrapMac2	1, 3, 6, 1, 4, 1, 6882, 1, 2, 4, 2, 2, 2

/* MIB object cjhvApWlanClientTrapIp2 = cjhvApWlanClientInfoTrap2, 3 */
#define	I_cjhvApWlanClientTrapIp2	3
#define	O_cjhvApWlanClientTrapIp2	1, 3, 6, 1, 4, 1, 6882, 1, 2, 4, 2, 2, 3

/* MIB object cjhvApWlanClientTrapName2 = cjhvApWlanClientInfoTrap2, 4 */
#define	I_cjhvApWlanClientTrapName2		4
#define	O_cjhvApWlanClientTrapName2		1, 3, 6, 1, 4, 1, 6882, 1, 2, 4, 2, 2, 4

/* MIB object cjhvApWlanClientTrapMode2 = cjhvApWlanClientInfoTrap2, 5 */
#define	I_cjhvApWlanClientTrapMode2		5
#define	O_cjhvApWlanClientTrapMode2		1, 3, 6, 1, 4, 1, 6882, 1, 2, 4, 2, 2, 5

/* MIB object cjhvApWlanClientTrapBand2 = cjhvApWlanClientInfoTrap2, 6 */
#define	I_cjhvApWlanClientTrapBand2		6
#define	O_cjhvApWlanClientTrapBand2		1, 3, 6, 1, 4, 1, 6882, 1, 2, 4, 2, 2, 6

/* MIB object cjhvApWlanClientTrapRssi2 = cjhvApWlanClientInfoTrap2, 7 */
#define	I_cjhvApWlanClientTrapRssi2		7
#define	O_cjhvApWlanClientTrapRssi2		1, 3, 6, 1, 4, 1, 6882, 1, 2, 4, 2, 2, 7

/* MIB object cjhvApWlanClientInfoTrap3 = cjhvApWlanClientInfoTrap, 3 */
#define	I_cjhvApWlanClientInfoTrap3	3
#define	O_cjhvApWlanClientInfoTrap3	1, 3, 6, 1, 4, 1, 6882, 1, 2, 4, 2, 3

/* MIB object cjhvApWlanClientInfoTrapIndex3 = cjhvApWlanClientInfoTrap3, 1 */
#define	I_cjhvApWlanClientInfoTrapIndex3	1
#define	O_cjhvApWlanClientInfoTrapIndex3	1, 3, 6, 1, 4, 1, 6882, 1, 2, 4, 2, 3, 1

/* MIB object cjhvApWlanClientTrapMac3 = cjhvApWlanClientInfoTrap3, 2 */
#define	I_cjhvApWlanClientTrapMac3	2
#define	O_cjhvApWlanClientTrapMac3	1, 3, 6, 1, 4, 1, 6882, 1, 2, 4, 2, 3, 2

/* MIB object cjhvApWlanClientTrapIp3 = cjhvApWlanClientInfoTrap3, 3 */
#define	I_cjhvApWlanClientTrapIp3	3
#define	O_cjhvApWlanClientTrapIp3	1, 3, 6, 1, 4, 1, 6882, 1, 2, 4, 2, 3, 3

/* MIB object cjhvApWlanClientTrapName3 = cjhvApWlanClientInfoTrap3, 4 */
#define	I_cjhvApWlanClientTrapName3		4
#define	O_cjhvApWlanClientTrapName3		1, 3, 6, 1, 4, 1, 6882, 1, 2, 4, 2, 3, 4

/* MIB object cjhvApWlanClientTrapMode3 = cjhvApWlanClientInfoTrap3, 5 */
#define	I_cjhvApWlanClientTrapMode3		5
#define	O_cjhvApWlanClientTrapMode3		1, 3, 6, 1, 4, 1, 6882, 1, 2, 4, 2, 3, 5

/* MIB object cjhvApWlanClientTrapBand3 = cjhvApWlanClientInfoTrap3, 6 */
#define	I_cjhvApWlanClientTrapBand3		6
#define	O_cjhvApWlanClientTrapBand3		1, 3, 6, 1, 4, 1, 6882, 1, 2, 4, 2, 3, 6

/* MIB object cjhvApWlanClientTrapRssi3 = cjhvApWlanClientInfoTrap3, 7 */
#define	I_cjhvApWlanClientTrapRssi3		7
#define	O_cjhvApWlanClientTrapRssi3		1, 3, 6, 1, 4, 1, 6882, 1, 2, 4, 2, 3, 7

/* MIB object cjhvApWlanClientInfoTrap4 = cjhvApWlanClientInfoTrap, 4 */
#define	I_cjhvApWlanClientInfoTrap4	4
#define	O_cjhvApWlanClientInfoTrap4	1, 3, 6, 1, 4, 1, 6882, 1, 2, 4, 2, 4

/* MIB object cjhvApWlanClientInfoTrapIndex4 = cjhvApWlanClientInfoTrap4, 1 */
#define	I_cjhvApWlanClientInfoTrapIndex4	1
#define	O_cjhvApWlanClientInfoTrapIndex4	1, 3, 6, 1, 4, 1, 6882, 1, 2, 4, 2, 4, 1

/* MIB object cjhvApWlanClientTrapMac4 = cjhvApWlanClientInfoTrap4, 2 */
#define	I_cjhvApWlanClientTrapMac4	2
#define	O_cjhvApWlanClientTrapMac4	1, 3, 6, 1, 4, 1, 6882, 1, 2, 4, 2, 4, 2

/* MIB object cjhvApWlanClientTrapIp4 = cjhvApWlanClientInfoTrap4, 3 */
#define	I_cjhvApWlanClientTrapIp4	3
#define	O_cjhvApWlanClientTrapIp4	1, 3, 6, 1, 4, 1, 6882, 1, 2, 4, 2, 4, 3

/* MIB object cjhvApWlanClientTrapName4 = cjhvApWlanClientInfoTrap4, 4 */
#define	I_cjhvApWlanClientTrapName4		4
#define	O_cjhvApWlanClientTrapName4		1, 3, 6, 1, 4, 1, 6882, 1, 2, 4, 2, 4, 4

/* MIB object cjhvApWlanClientTrapMode4 = cjhvApWlanClientInfoTrap4, 5 */
#define	I_cjhvApWlanClientTrapMode4		5
#define	O_cjhvApWlanClientTrapMode4		1, 3, 6, 1, 4, 1, 6882, 1, 2, 4, 2, 4, 5

/* MIB object cjhvApWlanClientTrapBand4 = cjhvApWlanClientInfoTrap4, 6 */
#define	I_cjhvApWlanClientTrapBand4		6
#define	O_cjhvApWlanClientTrapBand4		1, 3, 6, 1, 4, 1, 6882, 1, 2, 4, 2, 4, 6

/* MIB object cjhvApWlanClientTrapRssi4 = cjhvApWlanClientInfoTrap4, 7 */
#define	I_cjhvApWlanClientTrapRssi4		7
#define	O_cjhvApWlanClientTrapRssi4		1, 3, 6, 1, 4, 1, 6882, 1, 2, 4, 2, 4, 7

/* MIB object cjhvApWlanClientInfoTrap5 = cjhvApWlanClientInfoTrap, 5 */
#define	I_cjhvApWlanClientInfoTrap5	5
#define	O_cjhvApWlanClientInfoTrap5	1, 3, 6, 1, 4, 1, 6882, 1, 2, 4, 2, 5

/* MIB object cjhvApWlanClientInfoTrapIndex5 = cjhvApWlanClientInfoTrap5, 1 */
#define	I_cjhvApWlanClientInfoTrapIndex5	1
#define	O_cjhvApWlanClientInfoTrapIndex5	1, 3, 6, 1, 4, 1, 6882, 1, 2, 4, 2, 5, 1

/* MIB object cjhvApWlanClientTrapMac5 = cjhvApWlanClientInfoTrap5, 2 */
#define	I_cjhvApWlanClientTrapMac5	2
#define	O_cjhvApWlanClientTrapMac5	1, 3, 6, 1, 4, 1, 6882, 1, 2, 4, 2, 5, 2

/* MIB object cjhvApWlanClientTrapIp5 = cjhvApWlanClientInfoTrap5, 3 */
#define	I_cjhvApWlanClientTrapIp5	3
#define	O_cjhvApWlanClientTrapIp5	1, 3, 6, 1, 4, 1, 6882, 1, 2, 4, 2, 5, 3

/* MIB object cjhvApWlanClientTrapName5 = cjhvApWlanClientInfoTrap5, 4 */
#define	I_cjhvApWlanClientTrapName5		4
#define	O_cjhvApWlanClientTrapName5		1, 3, 6, 1, 4, 1, 6882, 1, 2, 4, 2, 5, 4

/* MIB object cjhvApWlanClientTrapMode5 = cjhvApWlanClientInfoTrap5, 5 */
#define	I_cjhvApWlanClientTrapMode5		5
#define	O_cjhvApWlanClientTrapMode5		1, 3, 6, 1, 4, 1, 6882, 1, 2, 4, 2, 5, 5

/* MIB object cjhvApWlanClientTrapBand5 = cjhvApWlanClientInfoTrap5, 6 */
#define	I_cjhvApWlanClientTrapBand5		6
#define	O_cjhvApWlanClientTrapBand5		1, 3, 6, 1, 4, 1, 6882, 1, 2, 4, 2, 5, 6

/* MIB object cjhvApWlanClientTrapRssi5 = cjhvApWlanClientInfoTrap5, 7 */
#define	I_cjhvApWlanClientTrapRssi5		7
#define	O_cjhvApWlanClientTrapRssi5		1, 3, 6, 1, 4, 1, 6882, 1, 2, 4, 2, 5, 7

/* MIB object cjhvApWlanClientInfoTrap6 = cjhvApWlanClientInfoTrap, 6 */
#define	I_cjhvApWlanClientInfoTrap6	6
#define	O_cjhvApWlanClientInfoTrap6	1, 3, 6, 1, 4, 1, 6882, 1, 2, 4, 2, 6

/* MIB object cjhvApWlanClientInfoTrapIndex6 = cjhvApWlanClientInfoTrap6, 1 */
#define	I_cjhvApWlanClientInfoTrapIndex6	1
#define	O_cjhvApWlanClientInfoTrapIndex6	1, 3, 6, 1, 4, 1, 6882, 1, 2, 4, 2, 6, 1

/* MIB object cjhvApWlanClientTrapMac6 = cjhvApWlanClientInfoTrap6, 2 */
#define	I_cjhvApWlanClientTrapMac6	2
#define	O_cjhvApWlanClientTrapMac6	1, 3, 6, 1, 4, 1, 6882, 1, 2, 4, 2, 6, 2

/* MIB object cjhvApWlanClientTrapIp6 = cjhvApWlanClientInfoTrap6, 3 */
#define	I_cjhvApWlanClientTrapIp6	3
#define	O_cjhvApWlanClientTrapIp6	1, 3, 6, 1, 4, 1, 6882, 1, 2, 4, 2, 6, 3

/* MIB object cjhvApWlanClientTrapName6 = cjhvApWlanClientInfoTrap6, 4 */
#define	I_cjhvApWlanClientTrapName6		4
#define	O_cjhvApWlanClientTrapName6		1, 3, 6, 1, 4, 1, 6882, 1, 2, 4, 2, 6, 4

/* MIB object cjhvApWlanClientTrapMode6 = cjhvApWlanClientInfoTrap6, 5 */
#define	I_cjhvApWlanClientTrapMode6		5
#define	O_cjhvApWlanClientTrapMode6		1, 3, 6, 1, 4, 1, 6882, 1, 2, 4, 2, 6, 5

/* MIB object cjhvApWlanClientTrapBand6 = cjhvApWlanClientInfoTrap6, 6 */
#define	I_cjhvApWlanClientTrapBand6		6
#define	O_cjhvApWlanClientTrapBand6		1, 3, 6, 1, 4, 1, 6882, 1, 2, 4, 2, 6, 6

/* MIB object cjhvApWlanClientTrapRssi6 = cjhvApWlanClientInfoTrap6, 7 */
#define	I_cjhvApWlanClientTrapRssi6		7
#define	O_cjhvApWlanClientTrapRssi6		1, 3, 6, 1, 4, 1, 6882, 1, 2, 4, 2, 6, 7

/* MIB object cjhvApWlanClientInfoTrap7 = cjhvApWlanClientInfoTrap, 7 */
#define	I_cjhvApWlanClientInfoTrap7	7
#define	O_cjhvApWlanClientInfoTrap7	1, 3, 6, 1, 4, 1, 6882, 1, 2, 4, 2, 7

/* MIB object cjhvApWlanClientInfoTrapIndex7 = cjhvApWlanClientInfoTrap7, 1 */
#define	I_cjhvApWlanClientInfoTrapIndex7	1
#define	O_cjhvApWlanClientInfoTrapIndex7	1, 3, 6, 1, 4, 1, 6882, 1, 2, 4, 2, 7, 1

/* MIB object cjhvApWlanClientTrapMac7 = cjhvApWlanClientInfoTrap7, 2 */
#define	I_cjhvApWlanClientTrapMac7	2
#define	O_cjhvApWlanClientTrapMac7	1, 3, 6, 1, 4, 1, 6882, 1, 2, 4, 2, 7, 2

/* MIB object cjhvApWlanClientTrapIp7 = cjhvApWlanClientInfoTrap7, 3 */
#define	I_cjhvApWlanClientTrapIp7	3
#define	O_cjhvApWlanClientTrapIp7	1, 3, 6, 1, 4, 1, 6882, 1, 2, 4, 2, 7, 3

/* MIB object cjhvApWlanClientTrapName7 = cjhvApWlanClientInfoTrap7, 4 */
#define	I_cjhvApWlanClientTrapName7		4
#define	O_cjhvApWlanClientTrapName7		1, 3, 6, 1, 4, 1, 6882, 1, 2, 4, 2, 7, 4

/* MIB object cjhvApWlanClientTrapCrc7 = cjhvApWlanClientInfoTrap7, 5 */
#define	I_cjhvApWlanClientTrapCrc7		5
#define	O_cjhvApWlanClientTrapCrc7		1, 3, 6, 1, 4, 1, 6882, 1, 2, 4, 2, 7, 5

/* MIB object cjhvApWlanClientInfoTrap8 = cjhvApWlanClientInfoTrap, 8 */
#define	I_cjhvApWlanClientInfoTrap8	8
#define	O_cjhvApWlanClientInfoTrap8	1, 3, 6, 1, 4, 1, 6882, 1, 2, 4, 2, 8

/* MIB object cjhvApWlanClientInfoTrapIndex8 = cjhvApWlanClientInfoTrap8, 1 */
#define	I_cjhvApWlanClientInfoTrapIndex8	1
#define	O_cjhvApWlanClientInfoTrapIndex8	1, 3, 6, 1, 4, 1, 6882, 1, 2, 4, 2, 8, 1

/* MIB object cjhvApWlanClientTrapMac8 = cjhvApWlanClientInfoTrap8, 2 */
#define	I_cjhvApWlanClientTrapMac8	2
#define	O_cjhvApWlanClientTrapMac8	1, 3, 6, 1, 4, 1, 6882, 1, 2, 4, 2, 8, 2

/* MIB object cjhvApWlanClientTrapIp8 = cjhvApWlanClientInfoTrap8, 3 */
#define	I_cjhvApWlanClientTrapIp8	3
#define	O_cjhvApWlanClientTrapIp8	1, 3, 6, 1, 4, 1, 6882, 1, 2, 4, 2, 8, 3

/* MIB object cjhvApWlanClientTrapName8 = cjhvApWlanClientInfoTrap8, 4 */
#define	I_cjhvApWlanClientTrapName8		4
#define	O_cjhvApWlanClientTrapName8		1, 3, 6, 1, 4, 1, 6882, 1, 2, 4, 2, 8, 4

/* MIB object cjhvApWlanClientTrapCrc8 = cjhvApWlanClientInfoTrap8, 5 */
#define	I_cjhvApWlanClientTrapCrc8		5
#define	O_cjhvApWlanClientTrapCrc8		1, 3, 6, 1, 4, 1, 6882, 1, 2, 4, 2, 8, 5

/* MIB object cjhvApWlanClientInfoTrap9 = cjhvApWlanClientInfoTrap, 9 */
#define	I_cjhvApWlanClientInfoTrap9	9
#define	O_cjhvApWlanClientInfoTrap9	1, 3, 6, 1, 4, 1, 6882, 1, 2, 4, 2, 9

/* MIB object cjhvApWlanClientInfoTrapIndex9 = cjhvApWlanClientInfoTrap9, 1 */
#define	I_cjhvApWlanClientInfoTrapIndex9	1
#define	O_cjhvApWlanClientInfoTrapIndex9	1, 3, 6, 1, 4, 1, 6882, 1, 2, 4, 2, 9, 1

/* MIB object cjhvApWlanClientTrapMac9 = cjhvApWlanClientInfoTrap9, 2 */
#define	I_cjhvApWlanClientTrapMac9	2
#define	O_cjhvApWlanClientTrapMac9	1, 3, 6, 1, 4, 1, 6882, 1, 2, 4, 2, 9, 2

/* MIB object cjhvApWlanClientTrapIp9 = cjhvApWlanClientInfoTrap9, 3 */
#define	I_cjhvApWlanClientTrapIp9	3
#define	O_cjhvApWlanClientTrapIp9	1, 3, 6, 1, 4, 1, 6882, 1, 2, 4, 2, 9, 3

/* MIB object cjhvApWlanClientTrapName9 = cjhvApWlanClientInfoTrap9, 4 */
#define	I_cjhvApWlanClientTrapName9		4
#define	O_cjhvApWlanClientTrapName9		1, 3, 6, 1, 4, 1, 6882, 1, 2, 4, 2, 9, 4

/* MIB object cjhvApWlanClientTrapCrc9 = cjhvApWlanClientInfoTrap9, 5 */
#define	I_cjhvApWlanClientTrapCrc9		5
#define	O_cjhvApWlanClientTrapCrc9		1, 3, 6, 1, 4, 1, 6882, 1, 2, 4, 2, 9, 5

/* MIB object cjhvApWlanClientInfoTrap10 = cjhvApWlanClientInfoTrap, 10 */
#define	I_cjhvApWlanClientInfoTrap10	10
#define	O_cjhvApWlanClientInfoTrap10	1, 3, 6, 1, 4, 1, 6882, 1, 2, 4, 2, 10

/* MIB object cjhvApWlanClientInfoTrapIndex10 = cjhvApWlanClientInfoTrap10, 1 */
#define	I_cjhvApWlanClientInfoTrapIndex10	1
#define	O_cjhvApWlanClientInfoTrapIndex10	1, 3, 6, 1, 4, 1, 6882, 1, 2, 4, 2, 10, 1

/* MIB object cjhvApWlanClientTrapMac10 = cjhvApWlanClientInfoTrap10, 2 */
#define	I_cjhvApWlanClientTrapMac10	2
#define	O_cjhvApWlanClientTrapMac10	1, 3, 6, 1, 4, 1, 6882, 1, 2, 4, 2, 10, 2

/* MIB object cjhvApWlanClientTrapIp10 = cjhvApWlanClientInfoTrap10, 3 */
#define	I_cjhvApWlanClientTrapIp10	3
#define	O_cjhvApWlanClientTrapIp10	1, 3, 6, 1, 4, 1, 6882, 1, 2, 4, 2, 10, 3

/* MIB object cjhvApWlanClientTrapName10 = cjhvApWlanClientInfoTrap10, 4 */
#define	I_cjhvApWlanClientTrapName10		4
#define	O_cjhvApWlanClientTrapName10		1, 3, 6, 1, 4, 1, 6882, 1, 2, 4, 2, 10, 4

/* MIB object cjhvApWlanClientTrapCrc10 = cjhvApWlanClientInfoTrap10, 5 */
#define	I_cjhvApWlanClientTrapCrc10		5
#define	O_cjhvApWlanClientTrapCrc10		1, 3, 6, 1, 4, 1, 6882, 1, 2, 4, 2, 10, 5

/* MIB object cjhvApSecurityConfig = cjhvApConfigInfo, 5 */
#define	I_cjhvApSecurityConfig	5
#define	O_cjhvApSecurityConfig	1, 3, 6, 1, 4, 1, 6882, 1, 2, 5

/* MIB object cjhvApSecwepConfigTable = cjhvApSecurityConfig, 1 */
#define	I_cjhvApSecwepConfigTable	1
#define	O_cjhvApSecwepConfigTable	1, 3, 6, 1, 4, 1, 6882, 1, 2, 5, 1

/* MIB object cjhvApSecwepConfigEntry = cjhvApSecwepConfigTable, 1 */
#define	I_cjhvApSecwepConfigEntry	1
#define	O_cjhvApSecwepConfigEntry	1, 3, 6, 1, 4, 1, 6882, 1, 2, 5, 1, 1

/* MIB object cjhvApSecwepConfigSSIDIndex = cjhvApSecwepConfigEntry, 1 */
#define	I_cjhvApSecwepConfigSSIDIndex	1
#define	O_cjhvApSecwepConfigSSIDIndex	1, 3, 6, 1, 4, 1, 6882, 1, 2, 5, 1, 1, 1

/* MIB object cjhvApSecwepSecSSID = cjhvApSecwepConfigEntry, 2 */
#define	I_cjhvApSecwepSecSSID	2
#define	O_cjhvApSecwepSecSSID	1, 3, 6, 1, 4, 1, 6882, 1, 2, 5, 1, 1, 2

/* MIB object cjhvApSecwep8021xAuthMode = cjhvApSecwepConfigEntry, 3 */
#define	I_cjhvApSecwep8021xAuthMode	3
#define	O_cjhvApSecwep8021xAuthMode	1, 3, 6, 1, 4, 1, 6882, 1, 2, 5, 1, 1, 3

/* MIB object cjhvApSecwepMacAuthMode = cjhvApSecwepConfigEntry, 4 */
#define	I_cjhvApSecwepMacAuthMode	4
#define	O_cjhvApSecwepMacAuthMode	1, 3, 6, 1, 4, 1, 6882, 1, 2, 5, 1, 1, 4

/* MIB object cjhvApSecwepAuthMethod = cjhvApSecwepConfigEntry, 5 */
#define	I_cjhvApSecwepAuthMethod	5
#define	O_cjhvApSecwepAuthMethod	1, 3, 6, 1, 4, 1, 6882, 1, 2, 5, 1, 1, 5

/* MIB object cjhvApSecwepAuthKeyLength = cjhvApSecwepConfigEntry, 6 */
#define	I_cjhvApSecwepAuthKeyLength	6
#define	O_cjhvApSecwepAuthKeyLength	1, 3, 6, 1, 4, 1, 6882, 1, 2, 5, 1, 1, 6

/* MIB object cjhvApSecwepKeyFormat = cjhvApSecwepConfigEntry, 7 */
#define	I_cjhvApSecwepKeyFormat	7
#define	O_cjhvApSecwepKeyFormat	1, 3, 6, 1, 4, 1, 6882, 1, 2, 5, 1, 1, 7

/* MIB object cjhvApSecwepEncryptionKey = cjhvApSecwepConfigEntry, 8 */
#define	I_cjhvApSecwepEncryptionKey	8
#define	O_cjhvApSecwepEncryptionKey	1, 3, 6, 1, 4, 1, 6882, 1, 2, 5, 1, 1, 8

/* MIB object cjhvApSecwepKeyIndex = cjhvApSecwepConfigEntry, 9 */
#define	I_cjhvApSecwepKeyIndex	9
#define	O_cjhvApSecwepKeyIndex	1, 3, 6, 1, 4, 1, 6882, 1, 2, 5, 1, 1, 9

/* MIB object cjhvApSecwpaxConfigTable = cjhvApSecurityConfig, 2 */
#define	I_cjhvApSecwpaxConfigTable	2
#define	O_cjhvApSecwpaxConfigTable	1, 3, 6, 1, 4, 1, 6882, 1, 2, 5, 2

/* MIB object cjhvApSecwpaxConfigEntry = cjhvApSecwpaxConfigTable, 1 */
#define	I_cjhvApSecwpaxConfigEntry	1
#define	O_cjhvApSecwpaxConfigEntry	1, 3, 6, 1, 4, 1, 6882, 1, 2, 5, 2, 1

/* MIB object cjhvApSecwpaxConfigSSIDIndex = cjhvApSecwpaxConfigEntry, 1 */
#define	I_cjhvApSecwpaxConfigSSIDIndex	1
#define	O_cjhvApSecwpaxConfigSSIDIndex	1, 3, 6, 1, 4, 1, 6882, 1, 2, 5, 2, 1, 1

/* MIB object cjhvApSecwpaxSecSSID = cjhvApSecwpaxConfigEntry, 2 */
#define	I_cjhvApSecwpaxSecSSID	2
#define	O_cjhvApSecwpaxSecSSID	1, 3, 6, 1, 4, 1, 6882, 1, 2, 5, 2, 1, 2

/* MIB object cjhvApSecwpaxAuthMode = cjhvApSecwpaxConfigEntry, 3 */
#define	I_cjhvApSecwpaxAuthMode	3
#define	O_cjhvApSecwpaxAuthMode	1, 3, 6, 1, 4, 1, 6882, 1, 2, 5, 2, 1, 3

/* MIB object cjhvApSecwpaxCipherSuite = cjhvApSecwpaxConfigEntry, 4 */
#define	I_cjhvApSecwpaxCipherSuite	4
#define	O_cjhvApSecwpaxCipherSuite	1, 3, 6, 1, 4, 1, 6882, 1, 2, 5, 2, 1, 4

/* MIB object cjhvApSecwpaxKeyFormat = cjhvApSecwpaxConfigEntry, 5 */
#define	I_cjhvApSecwpaxKeyFormat	5
#define	O_cjhvApSecwpaxKeyFormat	1, 3, 6, 1, 4, 1, 6882, 1, 2, 5, 2, 1, 5

/* MIB object cjhvApSecwpaxPreSharedKey = cjhvApSecwpaxConfigEntry, 6 */
#define	I_cjhvApSecwpaxPreSharedKey	6
#define	O_cjhvApSecwpaxPreSharedKey	1, 3, 6, 1, 4, 1, 6882, 1, 2, 5, 2, 1, 6

/* MIB object cjhvApSecwpamixConfigTable = cjhvApSecurityConfig, 3 */
#define	I_cjhvApSecwpamixConfigTable	3
#define	O_cjhvApSecwpamixConfigTable	1, 3, 6, 1, 4, 1, 6882, 1, 2, 5, 3

/* MIB object cjhvApSecwpamixConfigEntry = cjhvApSecwpamixConfigTable, 1 */
#define	I_cjhvApSecwpamixConfigEntry	1
#define	O_cjhvApSecwpamixConfigEntry	1, 3, 6, 1, 4, 1, 6882, 1, 2, 5, 3, 1

/* MIB object cjhvApSecwpamixConfigSSIDIndex = cjhvApSecwpamixConfigEntry, 1 */
#define	I_cjhvApSecwpamixConfigSSIDIndex	1
#define	O_cjhvApSecwpamixConfigSSIDIndex	1, 3, 6, 1, 4, 1, 6882, 1, 2, 5, 3, 1, 1

/* MIB object cjhvApSecwpamixSecSSID = cjhvApSecwpamixConfigEntry, 2 */
#define	I_cjhvApSecwpamixSecSSID	2
#define	O_cjhvApSecwpamixSecSSID	1, 3, 6, 1, 4, 1, 6882, 1, 2, 5, 3, 1, 2

/* MIB object cjhvApSecwpamixAuthMode = cjhvApSecwpamixConfigEntry, 3 */
#define	I_cjhvApSecwpamixAuthMode	3
#define	O_cjhvApSecwpamixAuthMode	1, 3, 6, 1, 4, 1, 6882, 1, 2, 5, 3, 1, 3

/* MIB object cjhvApSecwpamixCipherSuite = cjhvApSecwpamixConfigEntry, 4 */
#define	I_cjhvApSecwpamixCipherSuite	4
#define	O_cjhvApSecwpamixCipherSuite	1, 3, 6, 1, 4, 1, 6882, 1, 2, 5, 3, 1, 4

/* MIB object cjhvApSecwpamix2CipherSuite = cjhvApSecwpamixConfigEntry, 5 */
#define	I_cjhvApSecwpamix2CipherSuite	5
#define	O_cjhvApSecwpamix2CipherSuite	1, 3, 6, 1, 4, 1, 6882, 1, 2, 5, 3, 1, 5

/* MIB object cjhvApSecwpamixKeyFormat = cjhvApSecwpamixConfigEntry, 6 */
#define	I_cjhvApSecwpamixKeyFormat	6
#define	O_cjhvApSecwpamixKeyFormat	1, 3, 6, 1, 4, 1, 6882, 1, 2, 5, 3, 1, 6

/* MIB object cjhvApSecwpamixPreSharedKey = cjhvApSecwpamixConfigEntry, 7 */
#define	I_cjhvApSecwpamixPreSharedKey	7
#define	O_cjhvApSecwpamixPreSharedKey	1, 3, 6, 1, 4, 1, 6882, 1, 2, 5, 3, 1, 7

/* MIB object cjhvApPortConfig = cjhvApConfigInfo, 6 */
#define	I_cjhvApPortConfig	6
#define	O_cjhvApPortConfig	1, 3, 6, 1, 4, 1, 6882, 1, 2, 6

/* MIB object cjhvApDevPortMode = cjhvApPortConfig, 1 */
#define	I_cjhvApDevPortMode	1
#define	O_cjhvApDevPortMode	1, 3, 6, 1, 4, 1, 6882, 1, 2, 6, 1

/* MIB object cjhvApDevPortTable = cjhvApPortConfig, 2 */
#define	I_cjhvApDevPortTable	2
#define	O_cjhvApDevPortTable	1, 3, 6, 1, 4, 1, 6882, 1, 2, 6, 2

/* MIB object cjhvApDevPortEntry = cjhvApDevPortTable, 1 */
#define	I_cjhvApDevPortEntry	1
#define	O_cjhvApDevPortEntry	1, 3, 6, 1, 4, 1, 6882, 1, 2, 6, 2, 1

/* MIB object cjhvApDevPortIndex = cjhvApDevPortEntry, 1 */
#define	I_cjhvApDevPortIndex	1
#define	O_cjhvApDevPortIndex	1, 3, 6, 1, 4, 1, 6882, 1, 2, 6, 2, 1, 1

/* MIB object cjhvApDevPortNumber = cjhvApDevPortEntry, 2 */
#define	I_cjhvApDevPortNumber	2
#define	O_cjhvApDevPortNumber	1, 3, 6, 1, 4, 1, 6882, 1, 2, 6, 2, 1, 2

/* MIB object cjhvApDevPortName = cjhvApDevPortEntry, 3 */
#define	I_cjhvApDevPortName	3
#define	O_cjhvApDevPortName	1, 3, 6, 1, 4, 1, 6882, 1, 2, 6, 2, 1, 3

/* MIB object cjhvApDevPortNego = cjhvApDevPortEntry, 4 */
#define	I_cjhvApDevPortNego	4
#define	O_cjhvApDevPortNego	1, 3, 6, 1, 4, 1, 6882, 1, 2, 6, 2, 1, 4

/* MIB object cjhvApDevPortSpeed = cjhvApDevPortEntry, 5 */
#define	I_cjhvApDevPortSpeed	5
#define	O_cjhvApDevPortSpeed	1, 3, 6, 1, 4, 1, 6882, 1, 2, 6, 2, 1, 5

/* MIB object cjhvApDevPortDuplex = cjhvApDevPortEntry, 6 */
#define	I_cjhvApDevPortDuplex	6
#define	O_cjhvApDevPortDuplex	1, 3, 6, 1, 4, 1, 6882, 1, 2, 6, 2, 1, 6

/* MIB object cjhvApDevPortOnOff = cjhvApDevPortEntry, 7 */
#define	I_cjhvApDevPortOnOff	7
#define	O_cjhvApDevPortOnOff	1, 3, 6, 1, 4, 1, 6882, 1, 2, 6, 2, 1, 7

/* MIB object cjhvApDevPortStatus = cjhvApDevPortEntry, 8 */
#define	I_cjhvApDevPortStatus	8
#define	O_cjhvApDevPortStatus	1, 3, 6, 1, 4, 1, 6882, 1, 2, 6, 2, 1, 8

/* MIB object cjhvApIgmpConfig = cjhvApConfigInfo, 7 */
#define	I_cjhvApIgmpConfig	7
#define	O_cjhvApIgmpConfig	1, 3, 6, 1, 4, 1, 6882, 1, 2, 7

/* MIB object cjhvApIgmpIpMulticastEnable = cjhvApIgmpConfig, 1 */
#define	I_cjhvApIgmpIpMulticastEnable	1
#define	O_cjhvApIgmpIpMulticastEnable	1, 3, 6, 1, 4, 1, 6882, 1, 2, 7, 1

/* MIB object cjhvApIgmpSelectMode = cjhvApIgmpConfig, 2 */
#define	I_cjhvApIgmpSelectMode	2
#define	O_cjhvApIgmpSelectMode	1, 3, 6, 1, 4, 1, 6882, 1, 2, 7, 2

/* MIB object cjhvApIgmpFastLeaveEnable = cjhvApIgmpConfig, 3 */
#define	I_cjhvApIgmpFastLeaveEnable	3
#define	O_cjhvApIgmpFastLeaveEnable	1, 3, 6, 1, 4, 1, 6882, 1, 2, 7, 3

/* MIB object cjhvApIgmpProxyMemberExpireTime = cjhvApIgmpConfig, 4 */
#define	I_cjhvApIgmpProxyMemberExpireTime	4
#define	O_cjhvApIgmpProxyMemberExpireTime	1, 3, 6, 1, 4, 1, 6882, 1, 2, 7, 4

/* MIB object cjhvApSnmpConfig = cjhvApConfigInfo, 8 */
#define	I_cjhvApSnmpConfig	8
#define	O_cjhvApSnmpConfig	1, 3, 6, 1, 4, 1, 6882, 1, 2, 8

/* MIB object cjhvApSnmpEnable = cjhvApSnmpConfig, 1 */
#define	I_cjhvApSnmpEnable	1
#define	O_cjhvApSnmpEnable	1, 3, 6, 1, 4, 1, 6882, 1, 2, 8, 1

/* MIB object cjhvApSnmpRoCommunityName = cjhvApSnmpConfig, 2 */
#define	I_cjhvApSnmpRoCommunityName	2
#define	O_cjhvApSnmpRoCommunityName	1, 3, 6, 1, 4, 1, 6882, 1, 2, 8, 2

/* MIB object cjhvApSnmpRwCommunityName = cjhvApSnmpConfig, 3 */
#define	I_cjhvApSnmpRwCommunityName	3
#define	O_cjhvApSnmpRwCommunityName	1, 3, 6, 1, 4, 1, 6882, 1, 2, 8, 3

/* MIB object cjhvApSnmpListenPort = cjhvApSnmpConfig, 4 */
#define	I_cjhvApSnmpListenPort	4
#define	O_cjhvApSnmpListenPort	1, 3, 6, 1, 4, 1, 6882, 1, 2, 8, 4

/* MIB object cjhvApSnmpTrapEnable = cjhvApSnmpConfig, 5 */
#define	I_cjhvApSnmpTrapEnable	5
#define	O_cjhvApSnmpTrapEnable	1, 3, 6, 1, 4, 1, 6882, 1, 2, 8, 5

/* MIB object cjhvApSnmpTrapCommunityName = cjhvApSnmpConfig, 6 */
#define	I_cjhvApSnmpTrapCommunityName	6
#define	O_cjhvApSnmpTrapCommunityName	1, 3, 6, 1, 4, 1, 6882, 1, 2, 8, 6

/* MIB object cjhvApSnmpTrapDestinationIp = cjhvApSnmpConfig, 7 */
#define	I_cjhvApSnmpTrapDestinationIp	7
#define	O_cjhvApSnmpTrapDestinationIp	1, 3, 6, 1, 4, 1, 6882, 1, 2, 8, 7

/* MIB object cjhvApSnmpTrapDestinationPort = cjhvApSnmpConfig, 8 */
#define	I_cjhvApSnmpTrapDestinationPort	8
#define	O_cjhvApSnmpTrapDestinationPort	1, 3, 6, 1, 4, 1, 6882, 1, 2, 8, 8

/* MIB object cjhvApSyslogConfig = cjhvApConfigInfo, 9 */
#define	I_cjhvApSyslogConfig	9
#define	O_cjhvApSyslogConfig	1, 3, 6, 1, 4, 1, 6882, 1, 2, 9

/* MIB object cjhvApSysLogEnable = cjhvApSyslogConfig, 1 */
#define	I_cjhvApSysLogEnable	1
#define	O_cjhvApSysLogEnable	1, 3, 6, 1, 4, 1, 6882, 1, 2, 9, 1

/* MIB object cjhvApSysLogRemoteLogEnable = cjhvApSyslogConfig, 2 */
#define	I_cjhvApSysLogRemoteLogEnable	2
#define	O_cjhvApSysLogRemoteLogEnable	1, 3, 6, 1, 4, 1, 6882, 1, 2, 9, 2

/* MIB object cjhvApSysLogRemoteLogServer = cjhvApSyslogConfig, 3 */
#define	I_cjhvApSysLogRemoteLogServer	3
#define	O_cjhvApSysLogRemoteLogServer	1, 3, 6, 1, 4, 1, 6882, 1, 2, 9, 3

/* MIB object cjhvApNtpConfig = cjhvApConfigInfo, 10 */
#define	I_cjhvApNtpConfig	10
#define	O_cjhvApNtpConfig	1, 3, 6, 1, 4, 1, 6882, 1, 2, 10

/* MIB object cjhvApNtpServer1Name = cjhvApNtpConfig, 1 */
#define	I_cjhvApNtpServer1Name	1
#define	O_cjhvApNtpServer1Name	1, 3, 6, 1, 4, 1, 6882, 1, 2, 10, 1

/* MIB object cjhvApNtpServer2Name = cjhvApNtpConfig, 2 */
#define	I_cjhvApNtpServer2Name	2
#define	O_cjhvApNtpServer2Name	1, 3, 6, 1, 4, 1, 6882, 1, 2, 10, 2

/* MIB object cjhvApDmzInfo = cjhvApConfigInfo, 11 */
#define	I_cjhvApDmzInfo	11
#define	O_cjhvApDmzInfo	1, 3, 6, 1, 4, 1, 6882, 1, 2, 11

/* MIB object cjhvApDmzEnable = cjhvApDmzInfo, 1 */
#define	I_cjhvApDmzEnable	1
#define	O_cjhvApDmzEnable	1, 3, 6, 1, 4, 1, 6882, 1, 2, 11, 1

/* MIB object cjhvApDmzType = cjhvApDmzInfo, 2 */
#define	I_cjhvApDmzType	2
#define	O_cjhvApDmzType	1, 3, 6, 1, 4, 1, 6882, 1, 2, 11, 2

/* MIB object cjhvApDmzMac = cjhvApDmzInfo, 3 */
#define	I_cjhvApDmzMac	3
#define	O_cjhvApDmzMac	1, 3, 6, 1, 4, 1, 6882, 1, 2, 11, 3

/* MIB object cjhvApDmzIp = cjhvApDmzInfo, 4 */
#define	I_cjhvApDmzIp	4
#define	O_cjhvApDmzIp	1, 3, 6, 1, 4, 1, 6882, 1, 2, 11, 4

/* MIB object cjhvApPortFwdInfo = cjhvApConfigInfo, 12 */
#define	I_cjhvApPortFwdInfo	12
#define	O_cjhvApPortFwdInfo	1, 3, 6, 1, 4, 1, 6882, 1, 2, 12

/* MIB object cjhvApPortFwdTable = cjhvApPortFwdInfo, 1 */
#define	I_cjhvApPortFwdTable	1
#define	O_cjhvApPortFwdTable	1, 3, 6, 1, 4, 1, 6882, 1, 2, 12, 1

/* MIB object cjhvApPortFwdEntry = cjhvApPortFwdTable, 1 */
#define	I_cjhvApPortFwdEntry	1
#define	O_cjhvApPortFwdEntry	1, 3, 6, 1, 4, 1, 6882, 1, 2, 12, 1, 1

/* MIB object cjhvApPortFwdIndex = cjhvApPortFwdEntry, 1 */
#define	I_cjhvApPortFwdIndex	1
#define	O_cjhvApPortFwdIndex	1, 3, 6, 1, 4, 1, 6882, 1, 2, 12, 1, 1, 1

/* MIB object cjhvApPortFwdEnable = cjhvApPortFwdEntry, 2 */
#define	I_cjhvApPortFwdEnable	2
#define	O_cjhvApPortFwdEnable	1, 3, 6, 1, 4, 1, 6882, 1, 2, 12, 1, 1, 2

/* MIB object cjhvApPortFwdName = cjhvApPortFwdEntry, 3 */
#define	I_cjhvApPortFwdName	3
#define	O_cjhvApPortFwdName	1, 3, 6, 1, 4, 1, 6882, 1, 2, 12, 1, 1, 3

/* MIB object cjhvApPortFwdIp = cjhvApPortFwdEntry, 4 */
#define	I_cjhvApPortFwdIp	4
#define	O_cjhvApPortFwdIp	1, 3, 6, 1, 4, 1, 6882, 1, 2, 12, 1, 1, 4

/* MIB object cjhvApPortFwdWanStartPort = cjhvApPortFwdEntry, 5 */
#define	I_cjhvApPortFwdWanStartPort	5
#define	O_cjhvApPortFwdWanStartPort	1, 3, 6, 1, 4, 1, 6882, 1, 2, 12, 1, 1, 5

/* MIB object cjhvApPortFwdWanEndPort = cjhvApPortFwdEntry, 6 */
#define	I_cjhvApPortFwdWanEndPort	6
#define	O_cjhvApPortFwdWanEndPort	1, 3, 6, 1, 4, 1, 6882, 1, 2, 12, 1, 1, 6

/* MIB object cjhvApPortFwdLanStartPort = cjhvApPortFwdEntry, 7 */
#define	I_cjhvApPortFwdLanStartPort	7
#define	O_cjhvApPortFwdLanStartPort	1, 3, 6, 1, 4, 1, 6882, 1, 2, 12, 1, 1, 7

/* MIB object cjhvApPortFwdLanEndPort = cjhvApPortFwdEntry, 8 */
#define	I_cjhvApPortFwdLanEndPort	8
#define	O_cjhvApPortFwdLanEndPort	1, 3, 6, 1, 4, 1, 6882, 1, 2, 12, 1, 1, 8

/* MIB object cjhvApPortFwdProtocol = cjhvApPortFwdEntry, 9 */
#define	I_cjhvApPortFwdProtocol	9
#define	O_cjhvApPortFwdProtocol	1, 3, 6, 1, 4, 1, 6882, 1, 2, 12, 1, 1, 9

/* MIB object cjhvApSetPortFwd = cjhvApConfigInfo, 13 */
#define	I_cjhvApSetPortFwd	13
#define	O_cjhvApSetPortFwd	1, 3, 6, 1, 4, 1, 6882, 1, 2, 13

/* MIB object cjhvApSetPortFwdIndex = cjhvApSetPortFwd, 1 */
#define	I_cjhvApSetPortFwdIndex	1
#define	O_cjhvApSetPortFwdIndex	1, 3, 6, 1, 4, 1, 6882, 1, 2, 13, 1

/* MIB object cjhvApSetPortFwdEnable = cjhvApSetPortFwd, 2 */
#define	I_cjhvApSetPortFwdEnable	2
#define	O_cjhvApSetPortFwdEnable	1, 3, 6, 1, 4, 1, 6882, 1, 2, 13, 2

/* MIB object cjhvApSetPortFwdName = cjhvApSetPortFwd, 3 */
#define	I_cjhvApSetPortFwdName	3
#define	O_cjhvApSetPortFwdName	1, 3, 6, 1, 4, 1, 6882, 1, 2, 13, 3

/* MIB object cjhvApSetPortFwdIp = cjhvApSetPortFwd, 4 */
#define	I_cjhvApSetPortFwdIp	4
#define	O_cjhvApSetPortFwdIp	1, 3, 6, 1, 4, 1, 6882, 1, 2, 13, 4

/* MIB object cjhvApSetPortFwdWanStartPort = cjhvApSetPortFwd, 5 */
#define	I_cjhvApSetPortFwdWanStartPort	5
#define	O_cjhvApSetPortFwdWanStartPort	1, 3, 6, 1, 4, 1, 6882, 1, 2, 13, 5

/* MIB object cjhvApSetPortFwdWanEndPort = cjhvApSetPortFwd, 6 */
#define	I_cjhvApSetPortFwdWanEndPort	6
#define	O_cjhvApSetPortFwdWanEndPort	1, 3, 6, 1, 4, 1, 6882, 1, 2, 13, 6

/* MIB object cjhvApSetPortFwdLanStartPort = cjhvApSetPortFwd, 7 */
#define	I_cjhvApSetPortFwdLanStartPort	7
#define	O_cjhvApSetPortFwdLanStartPort	1, 3, 6, 1, 4, 1, 6882, 1, 2, 13, 7

/* MIB object cjhvApSetPortFwdLanEndPort = cjhvApSetPortFwd, 8 */
#define	I_cjhvApSetPortFwdLanEndPort	8
#define	O_cjhvApSetPortFwdLanEndPort	1, 3, 6, 1, 4, 1, 6882, 1, 2, 13, 8

/* MIB object cjhvApSetPortFwdProtocol = cjhvApSetPortFwd, 9 */
#define	I_cjhvApSetPortFwdProtocol	9
#define	O_cjhvApSetPortFwdProtocol	1, 3, 6, 1, 4, 1, 6882, 1, 2, 13, 9

/* MIB object cjhvApTelnetInfo = cjhvApConfigInfo, 14 */
#define	I_cjhvApTelnetInfo	14
#define	O_cjhvApTelnetInfo	1, 3, 6, 1, 4, 1, 6882, 1, 2, 14

/* MIB object cjhvApTelnetInfoEnable = cjhvApTelnetInfo, 1 */
#define	I_cjhvApTelnetInfoEnable	1
#define	O_cjhvApTelnetInfoEnable	1, 3, 6, 1, 4, 1, 6882, 1, 2, 14, 1

/* MIB object cjhvApConfigInfo = cjhvApConfigInfo, 15 */
#define	I_cjhvApACLInfo	15
#define	O_cjhvApACLInfo	1, 3, 6, 1, 4, 1, 6882, 1, 2, 15

/* MIB object cjhvApACLInfoEnable = cjhvApACLInfoEnable, 1 */
#define	I_cjhvApACLInfoEnable	1
#define	O_cjhvApACLInfoEnable	1, 3, 6, 1, 4, 1, 6882, 1, 2, 15, 1

/* MIB object cjhvApConfigInfo = cjhvApConfigInfo, 16 */
#define	I_cjhvApWebinfo	16
#define	O_cjhvApWebinfo	1, 3, 6, 1, 4, 1, 6882, 1, 2, 16

/* MIB object cjhvApWebinfoEnable = cjhvApWebinfoEnable, 1 */
#define	I_cjhvApWebinfoEnable	1
#define	O_cjhvApWebinfoEnable	1, 3, 6, 1, 4, 1, 6882, 1, 2, 16, 1

/* MIB object cjhvApConfigInfo = cjhvApConfigInfo, 17 */
#define	I_cjhvApSecurityinfo	17
#define	O_cjhvApSecurityinfo	1, 3, 6, 1, 4, 1, 6882, 1, 2, 17

/* MIB object cjhvApAttackSourceIP = cjhvApAttackSourceIP, 1 */
#define	I_cjhvApAttackSourceIP	1
#define	O_cjhvApAttackSourceIP	1, 3, 6, 1, 4, 1, 6882, 1, 2, 17, 1

/* MIB object cjhvApChangeTime = cjhvApChangeTime, 2 */
#define	I_cjhvApChangeTime	2
#define	O_cjhvApChangeTime	1, 3, 6, 1, 4, 1, 6882, 1, 2, 17, 2

/* MIB object cjhvApChangeDNS1 = cjhvApChangeDNS1, 3 */
#define	I_cjhvApChangeDNS1	3
#define	O_cjhvApChangeDNS1	1, 3, 6, 1, 4, 1, 6882, 1, 2, 17, 3

/* MIB object cjhvApChangeDNS2 = cjhvApChangeDNS2, 4 */
#define	I_cjhvApChangeDNS2	4
#define	O_cjhvApChangeDNS2	1, 3, 6, 1, 4, 1, 6882, 1, 2, 17, 4

/* MIB object cjhvApIgmpStatus = cjhvApStatus, 1 */
#define	I_cjhvApIgmpStatus	1
#define	O_cjhvApIgmpStatus	1, 3, 6, 1, 4, 1, 6882, 1, 3, 1

/* MIB object cjhvApIgmpJoinTable = cjhvApIgmpStatus, 1 */
#define	I_cjhvApIgmpJoinTable	1
#define	O_cjhvApIgmpJoinTable	1, 3, 6, 1, 4, 1, 6882, 1, 3, 1, 1

/* MIB object cjhvApIgmpJoinEntry = cjhvApIgmpJoinTable, 1 */
#define	I_cjhvApIgmpJoinEntry	1
#define	O_cjhvApIgmpJoinEntry	1, 3, 6, 1, 4, 1, 6882, 1, 3, 1, 1, 1

/* MIB object cjhvApIgmpJoinIndex = cjhvApIgmpJoinEntry, 1 */
#define	I_cjhvApIgmpJoinIndex	1
#define	O_cjhvApIgmpJoinIndex	1, 3, 6, 1, 4, 1, 6882, 1, 3, 1, 1, 1, 1

/* MIB object cjhvApIgmpJoinIpAddress = cjhvApIgmpJoinEntry, 2 */
#define	I_cjhvApIgmpJoinIpAddress	2
#define	O_cjhvApIgmpJoinIpAddress	1, 3, 6, 1, 4, 1, 6882, 1, 3, 1, 1, 1, 2

/* MIB object cjhvApIgmpJoinMemberNumber = cjhvApIgmpJoinEntry, 3 */
#define	I_cjhvApIgmpJoinMemberNumber	3
#define	O_cjhvApIgmpJoinMemberNumber	1, 3, 6, 1, 4, 1, 6882, 1, 3, 1, 1, 1, 3

/* MIB object cjhvApIgmpJoinPort = cjhvApIgmpJoinEntry, 4 */
#define	I_cjhvApIgmpJoinPort	4
#define	O_cjhvApIgmpJoinPort	1, 3, 6, 1, 4, 1, 6882, 1, 3, 1, 1, 1, 4

/* MIB object cjhvApMulticastTable = cjhvApIgmpStatus, 2 */
#define	I_cjhvApMulticastTable	2
#define	O_cjhvApMulticastTable	1, 3, 6, 1, 4, 1, 6882, 1, 3, 1, 2

/* MIB object cjhvApMulticastEntry = cjhvApMulticastTable, 1 */
#define	I_cjhvApMulticastEntry	1
#define	O_cjhvApMulticastEntry	1, 3, 6, 1, 4, 1, 6882, 1, 3, 1, 2, 1

/* MIB object cjhvApMulticastIndex = cjhvApMulticastEntry, 1 */
#define	I_cjhvApMulticastIndex	1
#define	O_cjhvApMulticastIndex	1, 3, 6, 1, 4, 1, 6882, 1, 3, 1, 2, 1, 1

/* MIB object cjhvApMulticastJoinIpAddress = cjhvApMulticastEntry, 2 */
#define	I_cjhvApMulticastJoinIpAddress	2
#define	O_cjhvApMulticastJoinIpAddress	1, 3, 6, 1, 4, 1, 6882, 1, 3, 1, 2, 1, 2

/* MIB object cjhvApMulticastPortNumber = cjhvApMulticastEntry, 3 */
#define	I_cjhvApMulticastPortNumber	3
#define	O_cjhvApMulticastPortNumber	1, 3, 6, 1, 4, 1, 6882, 1, 3, 1, 2, 1, 3

/* MIB object cjhvApMulticastPortName = cjhvApMulticastEntry, 4 */
#define	I_cjhvApMulticastPortName	4
#define	O_cjhvApMulticastPortName	1, 3, 6, 1, 4, 1, 6882, 1, 3, 1, 2, 1, 4

/* MIB object cjhvApMulticastOperation = cjhvApMulticastEntry, 5 */
#define	I_cjhvApMulticastOperation	5
#define	O_cjhvApMulticastOperation	1, 3, 6, 1, 4, 1, 6882, 1, 3, 1, 2, 1, 5

/* MIB object cjhvApMulticastInPkts = cjhvApMulticastEntry, 6 */
#define	I_cjhvApMulticastInPkts	6
#define	O_cjhvApMulticastInPkts	1, 3, 6, 1, 4, 1, 6882, 1, 3, 1, 2, 1, 6

/* MIB object cjhvApMulticastOutPkts = cjhvApMulticastEntry, 7 */
#define	I_cjhvApMulticastOutPkts	7
#define	O_cjhvApMulticastOutPkts	1, 3, 6, 1, 4, 1, 6882, 1, 3, 1, 2, 1, 7

/* MIB object cjhvApTraffic = cjhvApStatus, 2 */
#define	I_cjhvApTraffic		2
#define	O_cjhvApTraffic		1, 3, 6, 1, 4, 1, 6882, 1, 3, 2

/* MIB object cjhvApTrafficTable = cjhvApTraffic, 1 */
#define	I_cjhvApTrafficTable	1
#define	O_cjhvApTrafficTable	1, 3, 6, 1, 4, 1, 6882, 1, 3, 2, 1

/* MIB object cjhvApTrafficEntry = cjhvApTrafficTable, 1 */
#define	I_cjhvApTrafficEntry	1
#define	O_cjhvApTrafficEntry	1, 3, 6, 1, 4, 1, 6882, 1, 3, 2, 1, 1

/* MIB object cjhvApPortTrafficIndex = cjhvApTrafficEntry, 1 */
#define	I_cjhvApPortTrafficIndex	1
#define	O_cjhvApPortTrafficIndex	1, 3, 6, 1, 4, 1, 6882, 1, 3, 2, 1, 1, 1

/* MIB object cjhvApPortTraffiName = cjhvApTrafficEntry, 2 */
#define	I_cjhvApPortTraffiName	2
#define	O_cjhvApPortTraffiName	1, 3, 6, 1, 4, 1, 6882, 1, 3, 2, 1, 1, 2

/* MIB object cjhvApPortTraffiTX = cjhvApTrafficEntry, 3 */
#define	I_cjhvApPortTraffiTX	3
#define	O_cjhvApPortTraffiTX	1, 3, 6, 1, 4, 1, 6882, 1, 3, 2, 1, 1, 3

/* MIB object cjhvApPortTraffiRX = cjhvApTrafficEntry, 4 */
#define	I_cjhvApPortTraffiRX	4
#define	O_cjhvApPortTraffiRX	1, 3, 6, 1, 4, 1, 6882, 1, 3, 2, 1, 1, 4


/* MIB object cjhvApSystemRemoteResetConfig = cjhvApDiag, 1 */
#define	I_cjhvApSystemRemoteResetConfig	1
#define	O_cjhvApSystemRemoteResetConfig	1, 3, 6, 1, 4, 1, 6882, 1, 4, 1

/* MIB object cjhvApSystemRemoteReset = cjhvApSystemRemoteResetConfig, 1 */
#define	I_cjhvApSystemRemoteReset	1
#define	O_cjhvApSystemRemoteReset	1, 3, 6, 1, 4, 1, 6882, 1, 4, 1, 1

/* MIB object cjhvApPingTest = cjhvApDiag, 2 */
#define	I_cjhvApPingTest	2
#define	O_cjhvApPingTest	1, 3, 6, 1, 4, 1, 6882, 1, 4, 2

/* MIB object pingAddress = cjhvApPingTest, 1 */
#define	I_pingAddress	1
#define	O_pingAddress	1, 3, 6, 1, 4, 1, 6882, 1, 4, 2, 1

/* MIB object pingPacketCount = cjhvApPingTest, 2 */
#define	I_pingPacketCount	2
#define	O_pingPacketCount	1, 3, 6, 1, 4, 1, 6882, 1, 4, 2, 2

/* MIB object pingPacketSize = cjhvApPingTest, 3 */
#define	I_pingPacketSize	3
#define	O_pingPacketSize	1, 3, 6, 1, 4, 1, 6882, 1, 4, 2, 3

/* MIB object pingPacketTimeout = cjhvApPingTest, 4 */
#define	I_pingPacketTimeout	4
#define	O_pingPacketTimeout	1, 3, 6, 1, 4, 1, 6882, 1, 4, 2, 4

/* MIB object pingDelay = cjhvApPingTest, 5 */
#define	I_pingDelay	5
#define	O_pingDelay	1, 3, 6, 1, 4, 1, 6882, 1, 4, 2, 5

/* MIB object pingTrapOnCompletion = cjhvApPingTest, 6 */
#define	I_pingTrapOnCompletion	6
#define	O_pingTrapOnCompletion	1, 3, 6, 1, 4, 1, 6882, 1, 4, 2, 6

/* MIB object pingSentPackets = cjhvApPingTest, 7 */
#define	I_pingSentPackets	7
#define	O_pingSentPackets	1, 3, 6, 1, 4, 1, 6882, 1, 4, 2, 7

/* MIB object pingReceivedPackets = cjhvApPingTest, 8 */
#define	I_pingReceivedPackets	8
#define	O_pingReceivedPackets	1, 3, 6, 1, 4, 1, 6882, 1, 4, 2, 8

/* MIB object pingMinRtt = cjhvApPingTest, 9 */
#define	I_pingMinRtt	9
#define	O_pingMinRtt	1, 3, 6, 1, 4, 1, 6882, 1, 4, 2, 9

/* MIB object pingAvgRtt = cjhvApPingTest, 10 */
#define	I_pingAvgRtt	10
#define	O_pingAvgRtt	1, 3, 6, 1, 4, 1, 6882, 1, 4, 2, 10

/* MIB object pingMaxRtt = cjhvApPingTest, 11 */
#define	I_pingMaxRtt	11
#define	O_pingMaxRtt	1, 3, 6, 1, 4, 1, 6882, 1, 4, 2, 11

/* MIB object pingCompleted = cjhvApPingTest, 12 */
#define	I_pingCompleted	12
#define	O_pingCompleted	1, 3, 6, 1, 4, 1, 6882, 1, 4, 2, 12

/* MIB object pingTestStartTime = cjhvApPingTest, 13 */
#define	I_pingTestStartTime	13
#define	O_pingTestStartTime	1, 3, 6, 1, 4, 1, 6882, 1, 4, 2, 13

/* MIB object pingTestEndTime = cjhvApPingTest, 14 */
#define	I_pingTestEndTime	14
#define	O_pingTestEndTime	1, 3, 6, 1, 4, 1, 6882, 1, 4, 2, 14

/* MIB object pingResultCode = cjhvApPingTest, 15 */
#define	I_pingResultCode	15
#define	O_pingResultCode	1, 3, 6, 1, 4, 1, 6882, 1, 4, 2, 15

/* MIB object cjhvApSystemFactoryDefault = cjhvApDiag, 3 */
#define	I_cjhvApSystemFactoryDefault	3
#define	O_cjhvApSystemFactoryDefault	1, 3, 6, 1, 4, 1, 6882, 1, 4, 3

/* MIB object cjhvApSystemFactoryDefaultSet = cjhvApSystemFactoryDefault, 1 */
#define	I_cjhvApSystemFactoryDefaultSet	1
#define	O_cjhvApSystemFactoryDefaultSet	1, 3, 6, 1, 4, 1, 6882, 1, 4, 3, 1

/* MIB object cjhvApSystemSoftReset = cjhvApDiag, 4 */
#define	I_cjhvApSystemSoftReset	4
#define	O_cjhvApSystemSoftReset	1, 3, 6, 1, 4, 1, 6882, 1, 4, 4

/* MIB object cjhvApSystemSoftResetSet = cjhvApSystemSoftReset, 1 */
#define	I_cjhvApSystemSoftResetSet	1
#define	O_cjhvApSystemSoftResetSet	1, 3, 6, 1, 4, 1, 6882, 1, 4, 4, 1

/* MIB object cjhvApSystemSoftResetResult = cjhvApSystemSoftReset, 2 */
#define	I_cjhvApSystemSoftResetResult	2
#define	O_cjhvApSystemSoftResetResult	1, 3, 6, 1, 4, 1, 6882, 1, 4, 4, 2

/* MIB object cjhvApTrapNormal = cjhvApTrap, 1 */
#define	I_cjhvApTrapNormal	1
#define	O_cjhvApTrapNormal	1, 3, 6, 1, 4, 1, 6882, 1, 5, 1

/* MIB object cjhvApTrapPing = cjhvApTrap, 2 */
#define	I_cjhvApTrapPing	2
#define	O_cjhvApTrapPing	1, 3, 6, 1, 4, 1, 6882, 1, 5, 2

/* MIB object cjhvApDummyTrap = cjhvApTrap, 3 */
#define	I_cjhvApDummyTrap	3
#define	O_cjhvApDummyTrap	1, 3, 6, 1, 4, 1, 6882, 1, 5, 3

/* MIB object cjhvApWlanInfoTrap = cjhvApTrap, 4 */
#define	I_cjhvApWlanInfoTrap	4
#define	O_cjhvApWlanInfoTrap	1, 3, 6, 1, 4, 1, 6882, 1, 5, 4

/* MIB object cjhvApClientInfoTrap = cjhvApTrap, 5 */
#define	I_cjhvApClientInfoTrap	5
#define	O_cjhvApClientInfoTrap	1, 3, 6, 1, 4, 1, 6882, 1, 5, 5

/* MIB object cjhvApTrapSecurity = cjhvApTrap, 6 */
#define	I_cjhvApTrapSecurity	6
#define	O_cjhvApTrapSecurity	1, 3, 6, 1, 4, 1, 6882, 1, 5, 6

/* MIB object cjhvApTrapSecurity = cjhvApTrap, 7 */
#define	I_cjhvApTrapSoftReset	7
#define	O_cjhvApTrapSoftReset	1, 3, 6, 1, 4, 1, 6882, 1, 5, 7

/* Put here additional MIB specific include definitions */

#endif
