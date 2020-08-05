#ifndef	_SKBB_MIB_
#define	_SKBB_MIB_

#include "engine/asn1.h"

/* required include files (IMPORTS) */
#define MAX_SNMP_STR 256
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

#if 0
#define PH_MINPORT      0
#define PHGIO 3

#define PH_MINPORT      0
#define PH_MAXPORT      4
#define PHF_PWRUP       0x01
#define PHF_LINKUP      PHF_PWRUP
#define PHF_AUTONEG     0x02
#define PHF_FDX         0x04
#define PHF_10M         0x08
#define PHF_100M        0x10
#define PHF_1000M       0x20
#define PHF_RXPAUSE     0x40
#define PHF_TXPAUSE     0x80
#define PHF_RESET       0x100
#define PHF_OVERWREG    0x10000
#endif

void init_SKBB_MIB();
void register_subtrees_of_SKBB_MIB();

/* defined objects in this module */

/* MIB object system = mib_2, 1 */
#define I_system    1
#define O_system    1, 3, 6, 1, 2, 1, 1

/* MIB object sysObjectID = system, 2 */
#define	I_sysObjectID	2
#define	O_sysObjectID	1, 3, 6, 1, 2, 1, 1, 2

#define	I_sysUptime	3
#define	O_sysUptime	1, 3, 6, 1, 2, 1, 1, 3

/* MIB object ifIndex = ifEntry, 1 */
#define	I_ifIndex		1
#define I_ifDescr		2
#define I_ifType		3
#define I_ifMtu			4
#define I_ifSpeed		5
#define I_ifPhyAddr		6
#define I_ifAdminStatus	7
#define I_ifOperStatus	8
#define I_ifLastChange	9
#define I_ifInOctets	10
#define I_ifInErrors	14
#define I_ifOutOctets	16


/* MIB object SKBB = enterprises, 16183 */
#define	I_skbb		16183
#define	O_skbb		1, 3, 6, 1, 4, 1, 16183

#define I_autoTransmission 2
#define O_autoTransmission 1, 3, 6, 1, 4, 1, 16183, 3, 6, 1

/* MIB object SKBBEntry = SKBB, 3 */
#define	I_skbbEntry	3
#define	O_skbbEntry	1, 3, 6, 1, 4, 1, 16183, 3

/* MIB object information = skbbEntry, 1 */
#define	I_information	1
#define	O_information	1, 3, 6, 1, 4, 1, 16183, 3, 1

#define I_SystemInfo	1
#define O_SystemInfo	1, 3, 6, 1, 4, 1, 16183, 3, 1, 1

/* MIB object modelName = SystemInfo, 1 */
#define	I_modelName	1
#define	O_modelName	1, 3, 6, 1, 4, 1, 16183, 3, 1, 1, 1

/* MIB object version = SystemInfo, 2 */
#define	I_version	2
#define	O_version	1, 3, 6, 1, 4, 1, 16183, 3, 1, 1, 2

/* MIB Object ConfigInfo = skbbEndtry, 2 */
#define I_configInfo	2
#define O_configInfo	1, 3, 6, 1, 4, 1, 16183, 3, 2

/* MIB object WanConfig = configInfo, 1 */
#define I_WanConfig				1
#define O_WanConfig				1, 3, 6, 1, 4, 1, 16183, 3, 2, 1
#define I_wanMacAddress			1
#define O_wanMacAddress			1, 3, 6, 1, 4, 1, 16183, 3, 2, 1, 1
#define I_wanIpAddress			2
#define O_wanIpAddress			1, 3, 6, 1, 4, 1, 16183, 3, 2, 1, 2
#define I_wanSubnetMask			3
#define O_wanSubnetMask			1, 3, 6, 1, 4, 1, 16183, 3, 2, 1, 3
#define I_wanDefGateway			4
#define O_wanDefGateway			1, 3, 6, 1, 4, 1, 16183, 3, 2, 1, 4
#define I_wanDNS1				5
#define O_wanDNS1				1, 3, 6, 1, 4, 1, 16183, 3, 2, 1, 5
#define I_wanDNS2				6
#define O_wanDNS2				1, 3, 6, 1, 4, 1, 16183, 3, 2, 1, 6
#define I_wanSetup				7
#define O_wanSetup				1, 3, 6, 1, 4, 1, 16183, 3, 2, 1, 7
#define I_wanObtainIpMethod		1
#define O_wanObtainIpMethod		1, 3, 6, 1, 4, 1, 16183, 3, 2, 1, 7, 1
#define I_wanIpAddresSet		2
#define O_wanIpAddresSet		1, 3, 6, 1, 4, 1, 16183, 3, 2, 1, 7, 2
#define I_wanSubnetMaskSet		3
#define O_wanSubnetMaskSet		1, 3, 6, 1, 4, 1, 16183, 3, 2, 1, 7, 3
#define I_wanDefaultGWSet		4
#define O_wanDefaultGWSet		1, 3, 6, 1, 4, 1, 16183, 3, 2, 1, 7, 4
#define I_wanDNS1Set			5
#define O_wanDNS1Set			1, 3, 6, 1, 4, 1, 16183, 3, 2, 1, 7, 5
#define I_wanDNS2Set			6
#define O_wanDNS2Set			1, 3, 6, 1, 4, 1, 16183, 3, 2, 1, 7, 6
#define I_wanDNSMode			7
#define O_wanDNSMode			1, 3, 6, 1, 4, 1, 16183, 3, 2, 1, 7, 7
#define I_wanDNSMethod			8
#define O_wanDNSMethod			1, 3, 6, 1, 4, 1, 16183, 3, 2, 1, 7, 8
#define I_LanConfig				2
#define O_LanConfig				1, 3, 6, 1, 4, 1, 16183, 3, 2, 2
#define I_lanMacAddress			1
#define O_lanMacAddress			1, 3, 6, 1, 4, 1, 16183, 3, 2, 2, 1
#define I_lanIpAddress			2
#define O_lanIpAddress			1, 3, 6, 1, 4, 1, 16183, 3, 2, 2, 2
#define I_lanSubnetMask			3
#define O_lanSubnetMask			1, 3, 6, 1, 4, 1, 16183, 3, 2, 2, 3
#define I_lanSetup				4
#define O_lanSetup				1, 3, 6, 1, 4, 1, 16183, 3, 2, 2, 4
#define I_lanIpAddressSet		1
#define O_lanIpAddressSet		1, 3, 6, 1, 4, 1, 16183, 3, 2, 2, 4, 1
#define I_lanSubnetMaskSet		2
#define O_lanSubnetMaskSet		1, 3, 6, 1, 4, 1, 16183, 3, 2, 2, 4, 2
#define I_lanDhcpEnable			3
#define O_lanDhcpEnable			1, 3, 6, 1, 4, 1, 16183, 3, 2, 2, 4, 3
#define I_lanDhcpStartIp		4
#define O_lanDhcpStartIp		1, 3, 6, 1, 4, 1, 16183, 3, 2, 2, 4, 4
#define I_lanDhcpEndIp			5
#define O_lanDhcpEndIp			1, 3, 6, 1, 4, 1, 16183, 3, 2, 2, 4, 5
#define I_wlanState				6
#define O_wlanState				1, 3, 6, 1, 4, 1, 16183, 3, 2, 2, 4, 6
#define I_wlanReset				7
#define O_wlanReset				1, 3, 6, 1, 4, 1, 16183, 3, 2, 2, 4, 7

/* Wireless LAN Parameter			*/
#define I_wlanConfig			3
#define O_wlanConfig			1, 3, 6, 1, 4, 1, 16183, 3, 2, 3
#define I_wlanBasicConfig		1
#define O_wlanBasicConfig		1, 3, 6, 1, 4, 1, 16183, 3, 2, 3, 1
#define I_wlanMode				1
#define O_wlanMode				1, 3, 6, 1, 4, 1, 16183, 3, 2, 3, 1, 1
#define I_wlanBand				2
#define O_wlanBand				1, 3, 6, 1, 4, 1, 16183, 3, 2, 3, 1, 2
#define I_wlanChannelWidth 		3
#define O_wlanChannelWidth 		1, 3, 6, 1, 4, 1, 16183, 3, 2, 3, 1, 3
#define I_wlanControlSideband	4
#define O_wlanControlSideband	1, 3, 6, 1, 4, 1, 16183, 3, 2, 3, 1, 4
#define I_wlanChannelNumber		5
#define O_wlanChannelNumber		1, 3, 6, 1, 4, 1, 16183, 3, 2, 3, 1, 5
#define I_wlanDateRate			6
#define O_wlanDateRate			1, 3, 6, 1, 4, 1, 16183, 3, 2, 3, 1, 6

#define I_wlan1session			15
#define O_wlan1session			1, 3, 6, 1, 4, 1, 16183, 3, 2, 3, 1, 15

#define I_wlan1sessionLimit		16
#define O_wlan1sessionLimit		1, 3, 6, 1, 4, 1, 16183, 3, 2, 3, 1, 16

#define I_wlan1autoband			19
#define O_wlan1autoband			1, 3, 6, 1, 4, 1, 16183, 3, 2, 3, 1, 19

#define I_wlan0session			17
#define O_wlan0session			1, 3, 6, 1, 4, 1, 16183, 3, 2, 3, 1, 17

#define I_wlan0sessionLimit		18
#define O_wlan0sessionLimit		1, 3, 6, 1, 4, 1, 16183, 3, 2, 3, 1, 18

#define I_wlan0autoband			20
#define O_wlan0autoband			1, 3, 6, 1, 4, 1, 16183, 3, 2, 3, 1, 20


#define I_wlanConfigTable		7
#define O_wlanConfigTable		1, 3, 6, 1, 4, 1, 16183, 3, 2, 3, 1, 7
#define I_wlanConfigEntry		1
#define O_wlanConfigEntry		1, 3, 6, 1, 4, 1, 16183, 3, 2, 3, 1, 7, 1
#define I_wlanConfigIndex		1
#define O_wlanConfigIndex		1, 3, 6, 1, 4, 1, 16183, 3, 2, 3, 1, 7, 1, 1
#define I_wlanSSID				2
#define O_wlanSSID				1, 3, 6, 1, 4, 1, 16183, 3, 2, 3, 1, 7, 1, 2
#define I_wlanSSIDMode			3
#define O_wlanSSIDMode			1, 3, 6, 1, 4, 1, 16183, 3, 2, 3, 1, 7, 1, 3
#define I_wlanBcastSSIDMode		4
#define O_wlanBcastSSIDMode		1, 3, 6, 1, 4, 1, 16183, 3, 2, 3, 1, 7, 1, 4
#define I_wlanSecEncryption		5
#define O_wlanSecEncryption		1, 3, 6, 1, 4, 1, 16183, 3, 2, 3, 1, 7, 1, 5

#define I_wlanRateLimit			6
#define O_wlanRateLimit			1, 3, 6, 1, 4, 1, 16183, 3, 2, 3, 1, 7, 1, 6
#define I_wlanTxInfo			7
#define O_wlanTxInfo			1, 3, 6, 1, 4, 1, 16183, 3, 2, 3, 1, 7, 1, 7
#define I_wlanRxInfo			8
#define O_wlanRxInfo			1, 3, 6, 1, 4, 1, 16183, 3, 2, 3, 1, 7, 1, 8

#define I_WlanMacAddress_2g		19
#define O_WlanMacAddress_2g		1, 3, 6, 1, 4, 1, 16183, 3, 2, 3, 1, 7, 1, 19
#define I_WlanMacAddress_5g		20
#define O_WlanMacAddress_5g		1, 3, 6, 1, 4, 1, 16183, 3, 2, 3, 1, 7, 1, 20

#define I_wlanMode_5g						8
#define O_wlanMode_5g						1, 3, 6, 1, 4, 1, 16183, 3, 2, 3, 1, 8
#define I_wlanBand_5g						9
#define O_wlanBand_5g						1, 3, 6, 1, 4, 1, 16183, 3, 2, 3, 1, 9
#define I_wlanChannelWidth_5g			10
#define O_wlanChannelWidth_5g			1, 3, 6, 1, 4, 1, 16183, 3, 2, 3, 1, 10
#define I_wlanCtrlSideband_5g			11
#define O_wlanCtrlSideband_5g			1, 3, 6, 1, 4, 1, 16183, 3, 2, 3, 1, 11
#define I_wlanChannelNumber_5g			12
#define O_wlanChannelNumber_5g			1, 3, 6, 1, 4, 1, 16183, 3, 2, 3, 1, 12
#define I_wlanDateRate_5g						13
#define O_wlanDataRate_5g						1, 3, 6, 1, 4, 1, 16183, 3, 2, 3, 1, 13
#define I_wlanConfigTable_5g			14
#define O_wlanConfigTable_5g			1, 3, 6, 1, 4, 1, 16183, 3, 2, 3, 1, 14
#define I_wlanConfigEntry_5g			1
#define O_wlanConfigEntry_5g			1, 3, 6, 1, 4, 1, 16183, 3, 2, 3, 1, 14, 1
#define I_wlanConfigIndex_5g			1
#define O_wlanConfigIndex_5g			1, 3, 6, 1, 4, 1, 16183, 3, 2, 3, 1, 14, 1, 1
#define I_wlanSSID_5g							2
#define O_wlanSSID_5g							1, 3, 6, 1, 4, 1, 16183, 3, 2, 3, 1, 14, 1, 2
#define I_wlanSSIDMode_5g					3
#define O_wlanSSIDMode_5g					1, 3, 6, 1, 4, 1, 16183, 3, 2, 3, 1, 14, 1, 3
#define I_wlanBcastSSIDMode_5g			4
#define O_wlanBcastSSIDMode_5g			1, 3, 6, 1, 4, 1, 16183, 3, 2, 3, 1, 14, 1, 4
#define I_wlanSecEncryption_5g			5
#define O_wlanSecEncryption_5g			1, 3, 6, 1, 4, 1, 16183, 3, 2, 3, 1, 14, 1, 5
#define I_wlanRateLimit_5g			6
#define O_wlanRateLimit_5g			1, 3, 6, 1, 4, 1, 16183, 3, 2, 3, 1, 14, 1, 6
#define I_wlanTxInfo_5g					7
#define O_wlanTxInfo_5g					1, 3, 6, 1, 4, 1, 16183, 3, 2, 3, 1, 14, 1, 7
#define I_wlanRxInfo_5g					8
#define O_wlanRxInfo_5g					1, 3, 6, 1, 4, 1, 16183, 3, 2, 3, 1, 14, 1, 8


#define I_wlanAdvancedConfig	2
#define O_wlanAdvancedConfig	1, 3, 6, 1, 4, 1, 16183, 3, 2, 3, 2
#define I_wlanFragmentThreshold	1
#define O_wlanFragmentThreshold	1, 3, 6, 1, 4, 1, 16183, 3, 2, 3, 2, 1
#define I_wlanRTSThreshold		2
#define O_wlanRTSThreshold		1, 3, 6, 1, 4, 1, 16183, 3, 2, 3, 2, 2
#define I_wlanBeaconInterval	3
#define O_wlanBeaconInterval	1, 3, 6, 1, 4, 1, 16183, 3, 2, 3, 2, 3
#define I_wlanPreambleType		4
#define O_wlanPreambleType		1, 3, 6, 1, 4, 1, 16183, 3, 2, 3, 2, 4
#define I_wlanIAPPEnable		5
#define O_wlanIAPPEnable		1, 3, 6, 1, 4, 1, 16183, 3, 2, 3, 2, 5
#define I_wlanRFOutputPower		6
#define O_wlanRFOutputPower		1, 3, 6, 1, 4, 1, 16183, 3, 2, 3, 2, 6
#define I_wlanFragmentThreshold_5g	7
#define O_wlanFragmentThreshold_5g	1, 3, 6, 1, 4, 1, 16183, 3, 2, 3, 2, 7
#define I_wlanRTSThreshold_5g			8
#define O_wlanRTSThreshold_5g			1, 3, 6, 1, 4, 1, 16183, 3, 2, 3, 2, 8
#define I_wlanBeaconInterval_5g			9
#define O_wlanBeaconInterval_5g			1, 3, 6, 1, 4, 1, 16183, 3, 2, 3, 2, 9
#define I_wlanPreambleType_5g			10
#define O_wlanPreambleType_5g			1, 3, 6, 1, 4, 1, 16183, 3, 2, 3, 2, 10
#define I_wlanIAPPEnable_5g			11
#define O_wlanIAPPEnable_5g			1, 3, 6, 1, 4, 1, 16183, 3, 2, 3, 2, 11
#define I_wlanRFOutputPower_5g			12
#define O_wlanRFOutputPower_5g			1, 3, 6, 1, 4, 1, 16183, 3, 2, 3, 2, 12


#define I_SecurityConfig		4
#define O_SecurityConfig		1, 3, 6, 1, 4, 1, 16183, 3, 2, 4
#define I_SecConfigTable		1
#define O_SecConfigTable		1, 3, 6, 1, 4, 1, 16183, 3, 2, 4, 1

#define I_SecConfigEntry		1
#define O_SecConfigEntry		1, 3, 6, 1, 4, 1, 16183, 3, 2, 4, 1, 1

#define I_SecConfigSSIDIndex	1
#define O_SecConfigSSIDIndex	1, 3, 6, 1, 4, 1, 16183, 3, 2, 4, 1, 1, 1
#define I_SecSSID				2
#define O_SecSSID				1, 3, 6, 1, 4, 1, 16183, 3, 2, 4, 1, 1, 2
#define I_SecRadiusServerIP		3
#define O_SecRadiusServerIP		1, 3, 6, 1, 4, 1, 16183, 3, 2, 4, 1, 1, 3
#define I_SecRadiusServerPort	4
#define O_SecRadiusServerPort	1, 3, 6, 1, 4, 1, 16183, 3, 2, 4, 1, 1, 4
#define I_SecRadiusServerPwd	5
#define O_SecRadiusServerPwd	1, 3, 6, 1, 4, 1, 16183, 3, 2, 4, 1, 1, 5
#define I_SecAccountMode		6
#define O_SecAccountMode		1, 3, 6, 1, 4, 1, 16183, 3, 2, 4, 1, 1, 6
#define I_SecAccountServerIP	7
#define O_SecAccountServerIP	1, 3, 6, 1, 4, 1, 16183, 3, 2, 4, 1, 1, 7
#define	I_SecAccountServerPort	8
#define O_SecAccountServerPort	1, 3, 6, 1, 4, 1, 16183, 3, 2, 4, 1, 1, 8
#define I_SecAccountServerPwd	9
#define O_SecAccountServerPwd 	1, 3, 6, 1, 4, 1, 16183, 3, 2, 4, 1, 1, 9

#define I_SecWEPConfigTable		2
#define O_SecWEPConfigTable		1, 3, 6, 1, 4, 1, 16183, 3, 2, 4, 2

#define I_SecWEPConfigEntry		1
#define O_SecWEPConfigEntry		1, 3, 6, 1, 4, 1, 16183, 3, 2, 4, 2, 1

#define I_SecWEPConfigSSIDIndex	1
#define O_SecWEPConfigSSIDIndex	1, 3, 6, 1, 4, 1, 16183, 3, 2, 4, 2, 1, 1
#define I_SecWEPSecSSID			2
#define O_SecWEPSecSSID			1, 3, 6, 1, 4, 1, 16183, 3, 2, 4, 2, 1, 2
#define I_SecWEP8021xAuthMode	3
#define O_SecWEP8021xAuthMode	1, 3, 6, 1, 4, 1, 16183, 3, 2, 4, 2, 1, 3
#define I_SecWEPMacAuthMode		4
#define O_SecWEPMacAuthMode		1, 3, 6, 1, 4, 1, 16183, 3, 2, 4, 2, 1, 4
#define I_SecWEPAuthMethod		5
#define O_SecWEPAuthMethod		1, 3, 6, 1, 4, 1, 16183, 3, 2, 4, 2, 1, 5
#define I_SecWEPAuthKeySize		6
#define O_SecWEPAuthKeySize		1, 3, 6, 1, 4, 1, 16183, 3, 2, 4, 2, 1, 6
#define	I_SecWEPAuthEnable		7
#define O_SecWEPAuthEnable		1, 3, 6, 1, 4, 1, 16183, 3, 2, 4, 2, 1, 7
#define I_SecWEPKeyFormat		8
#define O_SecWEPKeyFormat		1, 3, 6, 1, 4, 1, 16183, 3, 2, 4, 2, 1, 8
#define I_SecWEPEncryptionKey	9
#define O_SecWEPEncryptionKey	1, 3, 6, 1, 4, 1, 16183, 3, 2, 4, 2, 1, 9
#define I_SecWEPKeyIndex		10
#define O_SecWEPKeyIndex		1, 3, 6, 1, 4, 1, 16183, 3, 2, 4, 2, 1, 10

#define I_SecWPAxConfigTable	3
#define O_SecWPAxConfigTable	1, 3, 6, 1, 4, 1, 16183, 3, 2, 4, 3

#define I_SecWPAxConfigEntry	1
#define O_SecWPAxConfigEntry	1, 3, 6, 1, 4, 1, 16183, 3, 2, 4, 3, 1

#define I_SecWPAxConfigSSIDIndex	1
#define O_SecWPAxConfigSSIDIndex	1, 3, 6, 1, 4, 1, 16183, 3, 2, 4, 3, 1, 1
#define I_SecWPAxConfigSSID		2
#define O_SecWPAxConfigSSID		1, 3, 6, 1, 4, 1, 16183, 3, 2, 4, 3, 1, 2
#define I_SecWPAxAuthMode		3
#define O_SecWPAxAuthMode		1, 3, 6, 1, 4, 1, 16183, 3, 2, 4, 3, 1, 3
#define I_SecWPAxCipherSuite	4
#define O_SecWPAxCipherSuite	1, 3, 6, 1, 4, 1, 16183, 3, 2, 4, 3, 1, 4
#define I_SecWPAxKeyFormat		5
#define O_SecWPAxKeyFormat		1, 3, 6, 1, 4, 1, 16183, 3, 2, 4, 3, 1, 5
#define I_SecWPAxPreSharedKey	6
#define O_SecWPAxPreSharedKey	1, 3, 6, 1, 4, 1, 16183, 3, 2, 4, 3, 1, 6

#define I_SecWPAmixConfigTable	4
#define O_SecWPAmixConfigTable	1, 3, 6, 1, 4, 1, 16183, 3, 2, 4, 4
#define I_SecWPAmixConfigEntry	1
#define O_SecWPAmixConfigEntry	1, 3, 6, 1, 4, 1, 16183, 3, 2, 4, 4, 1
#define I_SecWPAmixConfigSSIDIndex	1
#define O_SecWPAmixConfigSSIDIndex	1, 3, 6, 1, 4, 1, 16183, 3, 2, 4, 4, 1, 1
#define I_SecWPAmixSecSSID		2
#define O_SecWPAmixSecSSID		1, 3, 6, 1, 4, 1, 16183, 3, 2, 4, 4, 1, 2
#define I_SecWPAmixAuthMode		3
#define O_SecWPAmixAuthMode		1, 3, 6, 1, 4, 1, 16183, 3, 2, 4, 4, 1, 3
#define I_SecWPAmixCipherSuite	4
#define O_SecWPAmixCipherSuite	1, 3, 6, 1, 4, 1, 16183, 3, 2, 4, 4, 1, 4
#define I_SecWPAmix2CipherSuite	5
#define O_SecWPAmix2CipherSuite	1, 3, 6, 1, 4, 1, 16183, 3, 2, 4, 4, 1, 5
#define I_SecWPAmixKeyFormat	6
#define O_SecWPAmixKeyFormat	1, 3, 6, 1, 4, 1, 16183, 3, 2, 4, 4, 1, 6
#define I_SecWPAmixPreSharedKey	7
#define O_SecWPAmixPreSharedKey	1, 3, 6, 1, 4, 1, 16183, 3, 2, 4, 4, 1, 7


#define I_SecConfigTable_5g		5
#define O_SecConfigTable_5g		1, 3, 6, 1, 4, 1, 16183, 3, 2, 4, 5

#define I_SecConfigEntry_5g		1
#define O_SecConfigEntry_5g		1, 3, 6, 1, 4, 1, 16183, 3, 2, 4, 5, 1

#define I_SecConfigSSIDIndex_5g		1
#define O_SecConfigSSIDIndex_5g		1, 3, 6, 1, 4, 1, 16183, 3, 2, 4, 5, 1, 1
#define I_SecSSID_5g				2
#define O_SecSSID_5g				1, 3, 6, 1, 4, 1, 16183, 3, 2, 4, 5, 1, 2
#define I_SecRadiusServerIP_5g		3
#define O_SecRadiusServerIP_5g		1, 3, 6, 1, 4, 1, 16183, 3, 2, 4, 5, 1, 3
#define I_SecRadiusServerPort_5g	4
#define O_SecRadiusServerPort_5g	1, 3, 6, 1, 4, 1, 16183, 3, 2, 4, 5, 1, 4
#define I_SecRadiusServerPwd_5g		5
#define O_SecRadiusServerPwd_5g		1, 3, 6, 1, 4, 1, 16183, 3, 2, 4, 5, 1, 5
#define I_SecAccountMode_5g		6
#define O_SecAccountMode_5g		1, 3, 6, 1, 4, 1, 16183, 3, 2, 4, 5, 1, 6
#define I_SecAccountServerIP_5g		7
#define O_SecAccountServerIP_5g		1, 3, 6, 1, 4, 1, 16183, 3, 2, 4, 5, 1, 7
#define	I_SecAccountServerPort_5g	8
#define O_SecAccountServerPort_5g	1, 3, 6, 1, 4, 1, 16183, 3, 2, 4, 5, 1, 8
#define I_SecAccountServerPwd_5g	9
#define O_SecAccountServerPwd_5g	1, 3, 6, 1, 4, 1, 16183, 3, 2, 4, 5, 1, 9

#define I_SecWEPConfigTable_5g		6
#define O_SecWEPConfigTable_5g		1, 3, 6, 1, 4, 1, 16183, 3, 2, 4, 6

#define I_SecWEPConfigEntry_5g		1
#define O_SecWEPConfigEntry_5g		1, 3, 6, 1, 4, 1, 16183, 3, 2, 4, 6, 1

#define I_SecWEPConfigSSIDIndex_5g	1
#define O_SecWEPConfigSSIDIndex_5g	1, 3, 6, 1, 4, 1, 16183, 3, 2, 4, 6, 1, 1
#define I_SecWEPSecSSID_5g			2
#define O_SecWEPSecSSID_5g			1, 3, 6, 1, 4, 1, 16183, 3, 2, 4, 6, 1, 2
#define I_SecWEP8021xAuthMode_5g	3
#define O_SecWEP8021xAuthMode_5g	1, 3, 6, 1, 4, 1, 16183, 3, 2, 4, 6, 1, 3
#define I_SecWEPMacAuthMode_5g		4
#define O_SecWEPMacAuthMode_5g		1, 3, 6, 1, 4, 1, 16183, 3, 2, 4, 6, 1, 4
#define I_SecWEPAuthMethod_5g		5
#define O_SecWEPAuthMethod_5g		1, 3, 6, 1, 4, 1, 16183, 3, 2, 4, 6, 1, 5
#define I_SecWEPAuthKeySize_5g		6
#define O_SecWEPAuthKeySize_5g		1, 3, 6, 1, 4, 1, 16183, 3, 2, 4, 6, 1, 6
#define	I_SecWEPAuthEnable_5g		7
#define O_SecWEPAuthEnable_5g		1, 3, 6, 1, 4, 1, 16183, 3, 2, 4, 6, 1, 7
#define I_SecWEPKeyFormat_5g		8
#define O_SecWEPKeyFormat_5g		1, 3, 6, 1, 4, 1, 16183, 3, 2, 4, 6, 1, 8
#define I_SecWEPEncryptionKey_5g	9
#define O_SecWEPEncryptionKey_5g	1, 3, 6, 1, 4, 1, 16183, 3, 2, 4, 6, 1, 9
#define I_SecWEPKeyIndex_5g		10
#define O_SecWEPKeyIndex_5g		1, 3, 6, 1, 4, 1, 16183, 3, 2, 4, 6, 1, 10

#define I_SecWPAxConfigTable_5g	7
#define O_SecWPAxConfigTable_5g	1, 3, 6, 1, 4, 1, 16183, 3, 2, 4, 7

#define I_SecWPAxConfigEntry_5g	1
#define O_SecWPAxConfigEntry_5g	1, 3, 6, 1, 4, 1, 16183, 3, 2, 4, 7, 1

#define I_SecWPAxConfigSSIDIndex_5g	1
#define O_SecWPAxConfigSSIDIndex_5g	1, 3, 6, 1, 4, 1, 16183, 3, 2, 4, 7, 1, 1
#define I_SecWPAxSecSSID_5g		2
#define O_SecWPAxSecSSID_5g		1, 3, 6, 1, 4, 1, 16183, 3, 2, 4, 7, 1, 2
#define I_SecWPAxAuthMode_5g		3
#define O_SecWPAxAuthMode_5g		1, 3, 6, 1, 4, 1, 16183, 3, 2, 4, 7, 1, 3
#define I_SecWPAxCipherSuite_5g	4
#define O_SecWPAxCipherSuite_5g	1, 3, 6, 1, 4, 1, 16183, 3, 2, 4, 7, 1, 4
#define I_SecWPAxKeyFormat_5g		5
#define O_SecWPAxKeyFormat_5g		1, 3, 6, 1, 4, 1, 16183, 3, 2, 4, 7, 1, 5
#define I_SecWPAxPreSharedKey_5g	6
#define O_SecWPAxPreSharedKey_5g	1, 3, 6, 1, 4, 1, 16183, 3, 2, 4, 7, 1, 6

#define I_SecWPAmixConfigTable_5g	8
#define O_SecWPAmixConfigTable_5g	1, 3, 6, 1, 4, 1, 16183, 3, 2, 4, 8

#define I_SecWPAmixConfigEntry_5g	1
#define O_SecWPAmixConfigEntry_5g	1, 3, 6, 1, 4, 1, 16183, 3, 2, 4, 8, 1

#define I_SecWPAmixConfigSSIDIndex_5g	1
#define O_SecWPAmixConfigSSIDIndex_5g	1, 3, 6, 1, 4, 1, 16183, 3, 2, 4, 8, 1, 1
#define I_SecWPAmixSecSSID_5g		2
#define O_SecWPAmixSecSSID_5g		1, 3, 6, 1, 4, 1, 16183, 3, 2, 4, 8, 1, 2
#define I_SecWPAmixAuthMode_5g		3
#define O_SecWPAmixAuthMode_5g		1, 3, 6, 1, 4, 1, 16183, 3, 2, 4, 8, 1, 3
#define I_SecWPAmixCipherSuite_5g	4
#define O_SecWPAmixCipherSuite_5g	1, 3, 6, 1, 4, 1, 16183, 3, 2, 4, 8, 1, 4
#define I_SecWPAmix2CipherSuite_5g	5
#define O_SecWPAmix2CipherSuite_5g	1, 3, 6, 1, 4, 1, 16183, 3, 2, 4, 8, 1, 5
#define I_SecWPAmixKeyFormat_5g	6
#define O_SecWPAmixKeyFormat_5g	1, 3, 6, 1, 4, 1, 16183, 3, 2, 4, 8, 1, 6
#define I_SecWPAmixPreSharedKey_5g	7
#define O_SecWPAmixPreSharedKey_5g	1, 3, 6, 1, 4, 1, 16183, 3, 2, 4, 8, 1, 7

#define I_DevicePortConfig	5
#define O_DevicePortConfig	1, 3, 6, 1, 4, 1, 16183, 3, 2, 5

#define I_DevicePortMode		1
#define O_DevicePortMode		1, 3, 6, 1, 4, 1, 16183, 3, 2, 5, 1
#define I_DevicePortTable		2
#define O_DevicePortTable		1, 3, 6, 1, 4, 1, 16183, 3, 2, 5, 2
#define I_DevicePortEntry		1
#define O_DevicePortEntry		1, 3, 6, 1, 4, 1, 16183, 3, 2, 5, 2, 1
#define I_DevicePortIndex		1
#define O_DevicePortIndex		1, 3, 6, 1, 4, 1, 16183, 3, 2, 5, 2, 1, 1
#define I_DevicePortNumber		2
#define O_DevicePortNumber		1, 3, 6, 1, 4, 1, 16183, 3, 2, 5, 2, 1, 2
#define I_DevicePortName		3
#define O_DevicePortName		1, 3, 6, 1, 4, 1, 16183, 3, 2, 5, 2, 1, 3
#define I_DevicePortNego		4
#define O_DevicePortNego		1, 3, 6, 1, 4, 1, 16183, 3, 2, 5, 2, 1, 4
#define I_DevicePortSpeed		5
#define O_DevicePortSpeed		1, 3, 6, 1, 4, 1, 16183, 3, 2, 5, 2, 1, 5
#define I_DevicePortDuplex		6
#define O_DevicePortDuplex		1, 3, 6, 1, 4, 1, 16183, 3, 2, 5, 2, 1, 6
#define I_DevicePortOnOff		7
#define O_DevicePortOnOff		1, 3, 6, 1, 4, 1, 16183, 3, 2, 5, 2, 1, 7
#define I_DevicePortGigaLite	8
#define O_DevicePortGigaLite	1, 3, 6, 1, 4, 1, 16183, 3, 2, 5, 2, 1, 8

#define I_WanportTraffic		3
#define O_WanportTraffic		1, 3, 6, 1, 4, 1, 16183, 3, 2, 5, 3

#define I_IgmpConfig					6
#define O_IgmpConfig					1, 3, 6, 1, 4, 1, 16183, 3, 2, 6
#define I_IgmpMulticastEnable			1
#define O_IgmpMulticastEnable			1, 3, 6, 1, 4, 1, 16183, 3, 2, 6, 1
#define I_IgmpSelectMode				2
#define O_IgmpSelectMode				1, 3, 6, 1, 4, 1, 16183, 3, 2, 6, 2
#define I_IgmpFastLeaveEnable			3
#define O_IgmpFastLeaveEnable			1, 3, 6, 1, 4, 1, 16183, 3, 2, 6, 3
#define I_IgmpProxyMemberExpireTime		4
#define O_IgmpProxyMemberExpireTime		1, 3, 6, 1, 4, 1, 16183, 3, 2, 6, 4
#define I_IgmpProxyQueryInterval		5
#define O_IgmpProxyQueryInterval		1, 3, 6, 1, 4, 1, 16183, 3, 2, 6, 5
#define I_IgmpProxyQueryResInterval		6
#define O_IgmpProxyQueryResInterval		1, 3, 6, 1, 4, 1, 16183, 3, 2, 6, 6
#define I_IgmpProxyGroupMemberInterval	7
#define O_IgmpProxyGroupMemberInterval	1, 3, 6, 1, 4, 1, 16183, 3, 2, 6, 7
#define I_IgmpProxyGroupQueryInterval	8
#define O_IgmpProxyGroupQueryInterval	1, 3, 6, 1, 4, 1, 16183, 3, 2, 6, 8

#define I_fwUpgradeConfig			7
#define O_fwUpgradeConfig			1, 3, 6, 1, 4, 1, 16183, 3, 2, 7
#define I_autoUpgradeConfig			1
#define O_autoUpgradeConfig			1, 3, 6, 1, 4, 1, 16183, 3, 2, 7, 1
#define I_AutoUpgradeEnable			1
#define O_AutoUpgradeEnable			1, 3, 6, 1, 4, 1, 16183, 3, 2, 7, 1, 1
#define I_AutoUpgradeServer			2
#define O_AutoUpgradeServer			1, 3, 6, 1, 4, 1, 16183, 3, 2, 7, 1, 2
#define I_AutoUpgradePrefix			3
#define O_AutoUpgradePrefix			1, 3, 6, 1, 4, 1, 16183, 3, 2, 7, 1, 3
#define I_AutoUpgradeFile			4
#define O_AutoUpgradeFile			1, 3, 6, 1, 4, 1, 16183, 3, 2, 7, 1, 4

#define I_ManualUpgradeConfig		2
#define O_ManualUpgradeConfig		1, 3, 6, 1, 4, 1, 16183, 3, 2, 7, 2

#define I_ManualUpgradeServer		1
#define O_ManualUpgradeServer		1, 3, 6, 1, 4, 1, 16183, 3, 2, 7, 2, 1

#define I_ManualUpgradePrefix		2
#define O_ManualUpgradePrefix		1, 3, 6, 1, 4, 1, 16183, 3, 2, 7, 2, 2

#define I_ManualUpgradeFile			3
#define O_ManualUpgradeFile			1, 3, 6, 1, 4, 1, 16183, 3, 2, 7, 2, 3

#define I_ManualUpgradeExecute		4
#define O_ManualUpgradeExecute		1, 3, 6, 1, 4, 1, 16183, 3, 2, 7, 2, 4

#define I_snmpConfig				8
#define O_snmpConfig				1, 3, 6, 1, 4, 1, 16183, 3, 2, 8
#define I_snmpEnable				1
#define O_snmpEnable				1, 3, 6, 1, 4, 1, 16183, 3, 2, 8, 1
#define I_snmpCommunityTable		2
#define O_snmpCommunityTable		1, 3, 6, 1, 4, 1, 16183, 3, 2, 8, 2
#define I_snmpCommunityEntry		1
#define O_snmpCommunityEntry		1, 3, 6, 1, 4, 1, 16183, 3, 2, 8, 2, 1

#define I_snmpCommunityIndex		1
#define O_snmpCommunityIndex		1, 3, 6, 1, 4, 1, 16183, 3, 2, 8, 2, 1, 1
#define I_snmpCommunityName			2
#define O_snmpCommunityName			1, 3, 6, 1, 4, 1, 16183, 3, 2, 8, 2, 1, 2
#define I_snmpCommunityType			3
#define O_snmpCommunityType			1, 3, 6, 1, 4, 1, 16183, 3, 2, 8, 2, 1, 3
#define I_snmpCommunityAdmin		4
#define O_snmpCommunityAdmin		1, 3, 6, 1, 4, 1, 16183, 3, 2, 8, 2, 1, 4

#define I_snmpTrapDestinationTable	3
#define O_snmpTrapDestinationTable	1, 3, 6, 1, 4, 1, 16183, 3, 2, 8, 3
#define I_snmpTrapDestinationEntry	1
#define O_snmpTrapDestinationEntry	1, 3, 6, 1, 4, 1, 16183, 3, 2, 8, 3, 1

#define I_snmpTrapDestinationIndex	1
#define O_snmpTrapDestinationIndex	1, 3, 6, 1, 4, 1, 16183, 3, 2, 8, 3, 1, 1
#define I_snmpTrapDestination		 2
#define O_snmpTrapDestination		1, 3, 6, 1, 4, 1, 16183, 3, 2, 8, 3, 1, 2
#define I_snmpTrapCommunityName		3
#define O_snmpTrapCommunityName		1, 3, 6, 1, 4, 1, 16183, 3, 2, 8, 3, 1, 3
#define I_snmpTrapDestinationAdmin	 4
#define O_snmpTrapDestinationAdmin	1, 3, 6, 1, 4, 1, 16183, 3, 2, 8, 3, 1, 4

#define I_sysLogConfig				9
#define O_sysLogConfig				1, 3, 6, 1, 4, 1, 16183, 3, 2, 9
#define I_sysLogEnable				1
#define O_sysLogEnable				1, 3, 6, 1, 4, 1, 16183, 3, 2, 9, 1
#define I_sysLogRemoteLogEnable		2
#define O_sysLogRemoteLogEnable		1, 3, 6, 1, 4, 1, 16183, 3, 2, 9, 2
#define I_sysLogRemoteLogServer		3
#define O_sysLogRemoteLogServer		1, 3, 6, 1, 4, 1, 16183, 3, 2, 9, 3

#define I_ntpConfig					10
#define O_ntpConfig					1, 3, 6, 1, 4, 1, 16183, 3, 2, 10
#define I_ntpServer1Name			1
#define O_ntpServer1Name			1, 3, 6, 1, 4, 1, 16183, 3, 2, 10, 1
#define I_ntpServer2Name			2
#define O_ntpServer2Name			1, 3, 6, 1, 4, 1, 16183, 3, 2, 10, 2
#define I_ntpServer3Name			3
#define O_ntpServer3Name			1, 3, 6, 1, 4, 1, 16183, 3, 2, 10, 3

#define I_QosConfig					11
#define O_QosConfig					1, 3, 6, 1, 4, 1, 16183, 3, 2, 11
#define I_QosPortRateLimitTable		1
#define O_QosPortRateLimitTable		1, 3, 6, 1, 4, 1, 16183, 3, 2, 11, 1
#define I_PortRateLimitEntry		1
#define O_PortRateLimitEntry		1, 3, 6, 1, 4, 1, 16183, 3, 2, 11, 1, 1
#define I_PortRateLimitIndex		1
#define O_PortRateLimitIndex		1, 3, 6, 1, 4, 1, 16183, 3, 2, 11, 1, 1, 1
#define I_PortRateLimitPortNumber	2
#define O_PortRateLimitPortNumber	1, 3, 6, 1, 4, 1, 16183, 3, 2, 11, 1, 1, 2
#define I_PortRateLimitPortName		3
#define O_PortRateLimitPortName		1, 3, 6, 1, 4, 1, 16183, 3, 2, 11, 1, 1, 3
#define I_PortRateLimitMode			4
#define O_PortRateLimitMode			1, 3, 6, 1, 4, 1, 16183, 3, 2, 11, 1, 1, 4
#define I_PortRateLimitIncomming	5
#define O_PortRateLimitIncomming	1, 3, 6, 1, 4, 1, 16183, 3, 2, 11, 1, 1, 5
#define I_PortRateLimitOutgoing		6
#define O_PortRateLimitOutgoing		1, 3, 6, 1, 4, 1, 16183, 3, 2, 11, 1, 1, 6
#define I_PortFlowControl			7
#define O_PortFlowControl			1, 3, 6, 1, 4, 1, 16183, 3, 2, 11, 1, 1, 7

#define I_PortQosTable				2
#define O_PortQosTable				1, 3, 6, 1, 4, 1, 16183, 3, 2, 11, 2
#define I_PortQosEntry				1
#define O_PortQosEntry				1, 3, 6, 1, 4, 1, 16183, 3, 2, 11, 2, 1
#define I_PortQosIndex				1
#define O_PortQosIndex				1, 3, 6, 1, 4, 1, 16183, 3, 2, 11, 2, 1, 1
#define I_PortQosPortNumber			2
#define O_PortQosPortNumber			1, 3, 6, 1, 4, 1, 16183, 3, 2, 11, 2, 1, 2
#define I_PortQosPortName			3
#define O_PortQosPortName			1, 3, 6, 1, 4, 1, 16183, 3, 2, 11, 2, 1, 3
#define I_PortQosPriority			4
#define O_PortQosPriority			1, 3, 6, 1, 4, 1, 16183, 3, 2, 11, 2, 1, 4

#define I_QosClassfyTable			3
#define O_QosClassfyTable			1, 3, 6, 1, 4, 1, 16183, 3, 2, 11, 3

#define I_QosClassfyEntry			1
#define O_QosClassfyEntry			1, 3, 6, 1, 4, 1, 16183, 3, 2, 11, 3, 1
#define I_QosClassIndex				1
#define O_QosClassIndex				1, 3, 6, 1, 4, 1, 16183, 3, 2, 11, 3, 1, 1
#define I_QosClassDstIp				2
#define O_QosClassDstIp				1, 3, 6, 1, 4, 1, 16183, 3, 2, 11, 3, 1, 2
#define I_QosClassSrcIp				3
#define O_QosClassSrcIp				1, 3, 6, 1, 4, 1, 16183, 3, 2, 11, 3, 1, 3
#define I_QosClassDstPortStart		4
#define O_QosClassDstPortStart		1, 3, 6, 1, 4, 1, 16183, 3, 2, 11, 3, 1, 4
#define I_QosClassDstPortEnd		5
#define O_QosClassDstPortEnd		1, 3, 6, 1, 4, 1, 16183, 3, 2, 11, 3, 1, 5
#define I_QosClassSrcPortStart		6
#define O_QosClassSrcPortStart		1, 3, 6, 1, 4, 1, 16183, 3, 2, 11, 3, 1, 6
#define I_QosClassSrcPortEnd		7
#define O_QosClassSrcPortEnd		1, 3, 6, 1, 4, 1, 16183, 3, 2, 11, 3, 1, 7
#define I_QosClassDstMac			8
#define O_QosClassDstMac			1, 3, 6, 1, 4, 1, 16183, 3, 2, 11, 3, 1, 8
#define I_QosClassSrcMac			9
#define O_QosClassSrcMac				1, 3, 6, 1, 4, 1, 16183, 3, 2, 11, 3, 1, 9
#define I_QosClassProtocol			10
#define O_QosClassProtocol			1, 3, 6, 1, 4, 1, 16183, 3, 2, 11, 3, 1, 10
#define I_QosClassCos				11
#define O_QosClassCos				1, 3, 6, 1, 4, 1, 16183, 3, 2, 11, 3, 1, 11
#define I_QosClassIpTosType			12
#define O_QosClassIPTosType			1, 3, 6, 1, 4, 1, 16183, 3, 2, 11, 3, 1, 12
#define I_QosClassIpTos				13
#define O_QosClassIpTos				1, 3, 6, 1, 4, 1, 16183, 3, 2, 11, 3, 1, 13
#define I_QosClassEthType			14
#define O_QosClassEthType			1, 3, 6, 1, 4, 1, 16183, 3, 2, 11, 3, 1, 14
#define I_QosClassMarkIndex			15
#define O_QosClassMarkIndex			1, 3, 6, 1, 4, 1, 16183, 3, 2, 11, 3, 1, 15

#define I_QosMarkTable				4
#define O_QosMarkTable				1, 3, 6, 1, 4, 1, 16183, 3, 2, 11, 4
#define I_QosMarkTableEntry			1
#define O_QosMarkTableEntry				1, 3, 6, 1, 4, 1, 16183, 3, 2, 11, 4, 1
#define I_QosMarkIndex				1
#define O_QosMarkIndex				1, 3, 6, 1, 4, 1, 16183, 3, 2, 11, 4, 1, 1
#define I_QosMarkCosRemark			2
#define O_QosMarkCosRemark			1, 3, 6, 1, 4, 1, 16183, 3, 2, 11, 4, 1, 2
#define I_QosMarkDscpRemark			3
#define O_QosMarkDscpRemark			1, 3, 6, 1, 4, 1, 16183, 3, 2, 11, 4, 1, 3
#define I_QosMarkPriority			4
#define O_QosMarkPriority			1, 3, 6, 1, 4, 1, 16183, 3, 2, 11, 4, 1, 4

#define I_QosScheduleTable			5
#define O_QosScheduleTable			1, 3, 6, 1, 4, 1, 16183, 3, 2, 11, 5
#define I_QosScheduleTableEntry		1
#define O_QosScheduleTableEntry		1, 3, 6, 1, 4, 1, 16183, 3, 2, 11, 5, 1
#define I_QosSchedulePortNumber		1
#define O_QosSchedulePortNumber		1, 3, 6, 1, 4, 1, 16183, 3, 2, 11, 5, 1, 1
#define I_QosSchedulePortName		2
#define O_QosSchedulePortName		1, 3, 6, 1, 4, 1, 16183, 3, 2, 11, 5, 1, 2
#define I_QosScheduleQueue			3
#define O_QosScheduleQueue			1, 3, 6, 1, 4, 1, 16183, 3, 2, 11, 5, 1, 3
#define I_QosScheduleMode			4
#define O_QosScheduleMode			1, 3, 6, 1, 4, 1, 16183, 3, 2, 11, 5, 1, 4
#define I_QosScheduleWeight			5
#define O_QosScheduleWeight			1, 3, 6, 1, 4, 1, 16183, 3, 2, 11, 5, 1, 5

#define I_AccessControlConfig				12
#define O_AccessControlConfig				1, 3, 6, 1, 4, 1, 16183, 3, 2, 12

#define I_LanAccessControlConfig			1
#define O_LanAccessControlConfig			1, 3, 6, 1, 4, 1, 16183, 3, 2, 12, 1
#define I_LanAccessControlModeTable			1
#define O_LanAccessControlModeTable			1, 3, 6, 1, 4, 1, 16183, 3, 2, 12, 1, 1
#define I_LanAccessControlModeEntry			1
#define O_LanAccessControlModeEntry			1, 3, 6, 1, 4, 1, 16183, 3, 2, 12, 1, 1, 1
#define I_LanAccessControlPortIndex			1
#define O_LanAccessControlPortIndex			1, 3, 6, 1, 4, 1, 16183, 3, 2, 12, 1, 1, 1, 1
#define I_LanAccessControlPortNumber		2
#define O_LanAccessControlPortNumber		1, 3, 6, 1, 4, 1, 16183, 3, 2, 12, 1, 1, 1, 2
#define I_LanAccessControlPortName			3
#define O_LanAccessControlPortName			1, 3, 6, 1, 4, 1, 16183, 3, 2, 12, 1, 1, 1, 3
#define I_LanAccessControlPortOpMode		4
#define O_LanAccessControlPortOpMode		1, 3, 6, 1, 4, 1, 16183, 3, 2, 12, 1, 1, 1, 4

#define I_LanAccessControlListConfig		2
#define O_LanAccessControlListConfig		1, 3, 6, 1, 4, 1, 16183, 3, 2, 12, 1, 2
#define I_LanAccessControlListSetPortNumber	1
#define O_LanAccessControlListSetPortNumber	1, 3, 6, 1, 4, 1, 16183, 3, 2, 12, 1, 2, 1
#define I_LanAccessControlListSetPortName	2
#define O_LanAccessControlListSetPortName	1, 3, 6, 1, 4, 1, 16183, 3, 2, 12, 1, 2, 2
#define I_LanAccessControlListSetMacAddr	3
#define O_LanAccessControlListSetMacAddr	1, 3, 6, 1, 4, 1, 16183, 3, 2, 12, 1, 2, 3
#define I_LanAccessControlListSetComment	4
#define O_LanAccessControlListSetComment	1, 3, 6, 1, 4, 1, 16183, 3, 2, 12, 1, 2, 4
#define I_LanAccessControlListAdd			5
#define O_LanAccessControlListAdd			1, 3, 6, 1, 4, 1, 16183, 3, 2, 12, 1, 2, 5
#define I_LanAccessControlListDel			6
#define O_LanAccessControlListDel			1, 3, 6, 1, 4, 1, 16183, 3, 2, 12, 1, 2, 6
#define I_LanAccessControlListDelAll		7
#define O_LanAccessControlListDelAll		1, 3, 6, 1, 4, 1, 16183, 3, 2, 12, 1, 2, 7
#define I_LanAccessControlListTable			8
#define O_LanAccessControlListTable		1, 3, 6, 1, 4, 1, 16183, 3, 2, 12, 1, 2, 8

#define I_LanAccessControlListEntry			1
#define O_LanAccessControlListEntry			1, 3, 6, 1, 4, 1, 16183, 3, 2, 12, 1, 2, 8, 1
#define I_LanAccessControlListIndex			1
#define O_LanAccessControlListIndex			1, 3, 6, 1, 4, 1, 16183, 3, 2, 12, 1, 2, 8, 1, 1
#define I_LanAccessControlListPortNumber	2
#define O_LanAccessControlListPortNumber	1, 3, 6, 1, 4, 1, 16183, 3, 2, 12, 1, 2, 8, 1, 2
#define I_LanAccessControlListPortName		3
#define O_LanAccessControlListPortName		1, 3, 6, 1, 4, 1, 16183, 3, 2, 12, 1, 2, 8, 1, 3
#define I_LanAccessControlListMacAddr		4
#define O_LanAccessControlListMacAddr		1, 3, 6, 1, 4, 1, 16183, 3, 2, 12, 1, 2, 8, 1, 4
#define I_LanAccessControlListDescription	5
#define O_LanAccessControlListDescription	1, 3, 6, 1, 4, 1, 16183, 3, 2, 12, 1, 2, 8, 1, 5

#define I_LanAccessControlMode				3
#define O_LanAccessControlMode				1, 3, 6, 1, 4, 1, 16183, 3, 2, 12, 1, 3

#define I_WLanAccessControlConfig 			2
#define O_WLanAccessControlConfig 			1, 3, 6, 1, 4, 1, 16183, 3, 2, 12, 2
#define I_wlanAccessControlModeTable		1
#define O_WLanAccessControlModeTable		1, 3, 6, 1, 4, 1, 16183, 3, 2, 12, 2, 1
#define I_wlanAccessControlModeEntry		1
#define O_WLanAccessControlModeEntry		1, 3, 6, 1, 4, 1, 16183, 3, 2, 12, 2, 1, 1
#define I_wlanAccessControlSSIDIndex		1
#define O_wlanAccessControlSSIDIndex		1, 3, 6, 1, 4, 1, 16183, 3, 2, 12, 2, 1, 1, 1
#define I_wlanAccessControlSSID				2
#define O_wlanAccessControlSSID				1, 3, 6, 1, 4, 1, 16183, 3, 2, 12, 2, 1, 1, 2
#define I_wlanAccessControlOpMode			3
#define O_wlanAccessControlOpMode			1, 3, 6, 1, 4, 1, 16183, 3, 2, 12, 2, 1, 1, 3

#define I_wlanAccessControlListConfig		2
#define O_wlanAccessControlListConfig		1, 3, 6, 1, 4, 1, 16183, 3, 2, 12, 2, 2
#define I_wlanAccessControlSetSSIDIndex		1
#define O_wlanAccessControlSetSSIDIndex		1, 3, 6, 1, 4, 1, 16183, 3, 2, 12, 2, 2, 1
#define I_wlanAccessControlSetSSID			2
#define O_wlanAccessControlSetSSID			1, 3, 6, 1, 4, 1, 16183, 3, 2, 12, 2, 2, 2
#define I_wlanAccessControlListSetMacAddr	3
#define O_wlanAccessControlListSetMacAddr	1, 3, 6, 1, 4, 1, 16183, 3, 2, 12, 2, 2, 3
#define I_wlanAccessControlListSetComment	4
#define O_wlanAccessControlListSetComment	1, 3, 6, 1, 4, 1, 16183, 3, 2, 12, 2, 2, 4
#define I_wlanAccessControlListAdd			5
#define O_wlanAccessControlListAdd			1, 3, 6, 1, 4, 1, 16183, 3, 2, 12, 2, 2, 5
#define I_wlanAccessControlListDel			6
#define O_wlanAccessControlListDel			1, 3, 6, 1, 4, 1, 16183, 3, 2, 12, 2, 2, 6
#define I_wlanAccessControlListDelAll		7
#define O_wlanAccessControlListDelAll		1, 3, 6, 1, 4, 1, 16183, 3, 2, 12, 2, 2, 7
#define I_wlanAccessControlListTable		8
#define O_wlanAccessControlListTable		1, 3, 6, 1, 4, 1, 16183, 3, 2, 12, 2, 2, 8
#define I_wlanAccessControlListEntry		1
#define O_wlanAccessControlListEntry		1, 3, 6, 1, 4, 1, 16183, 3, 2, 12, 2, 2, 8, 1
#define I_wlanAccessControlListIndex		1
#define O_wlanAccessControlListIndex		1, 3, 6, 1, 4, 1, 16183, 3, 2, 12, 2, 2, 8, 1, 1
#define I_wlanAccessControlListSSIDIndex	2
#define O_wlanAccessControlListSSIDIndex	1, 3, 6, 1, 4, 1, 16183, 3, 2, 12, 2, 2, 8, 1, 2
#define I_wlanAccessControlListSSID			3
#define O_wlanAccessControlListSSID			1, 3, 6, 1, 4, 1, 16183, 3, 2, 12, 2, 2, 8, 1, 3
#define I_wlanAccessControlListHwAddr		4
#define O_wlanAccessControlListHwAddr		1, 3, 6, 1, 4, 1, 16183, 3, 2, 12, 2, 2, 8, 1, 4
#define I_wlanAccessControlListDescription	5
#define O_wlanAccessControlListDescription	1, 3, 6, 1, 4, 1, 16183, 3, 2, 12, 2, 2, 8, 1, 5

#define I_WLanAccessControlConfig_5g 			3
#define O_WLanAccessControlConfig_5g 			1, 3, 6, 1, 4, 1, 16183, 3, 2, 12, 3
#define I_wlanAccessControlModeTable_5g		1
#define O_WLanAccessControlModeTable_5g		1, 3, 6, 1, 4, 1, 16183, 3, 2, 12, 3, 1
#define I_wlanAccessControlModeEntry_5g		1
#define O_WLanAccessControlModeEntry_5g		1, 3, 6, 1, 4, 1, 16183, 3, 2, 12, 3, 1, 1
#define I_wlanAccessControlSSIDIndex_5g		1
#define O_wlanAccessControlSSIDIndex_5g		1, 3, 6, 1, 4, 1, 16183, 3, 2, 12, 3, 1, 1, 1
#define I_wlanAccessControlSSID_5g				2
#define O_wlanAccessControlSSID_5g				1, 3, 6, 1, 4, 1, 16183, 3, 2, 12, 3, 1, 1, 2
#define I_wlanAccessControlOpMode_5g			3
#define O_wlanAccessControlOpMode_5g			1, 3, 6, 1, 4, 1, 16183, 3, 2, 12, 3, 1, 1, 3

#define I_wlanAccessControlListConfig_5g		2
#define O_wlanAccessControlListConfig_5g		1, 3, 6, 1, 4, 1, 16183, 3, 2, 12, 3, 2
#define I_wlanAccessControlSetSSIDIndex_5g		1
#define O_wlanAccessControlSetSSIDIndex_5g		1, 3, 6, 1, 4, 1, 16183, 3, 2, 12, 3, 2, 1
#define I_wlanAccessControlSetSSID_5g			2
#define O_wlanAccessControlSetSSID_5g			1, 3, 6, 1, 4, 1, 16183, 3, 2, 12, 3, 2, 2
#define I_wlanAccessControlListSetMacAddr_5g	3
#define O_wlanAccessControlListSetMacAddr_5g	1, 3, 6, 1, 4, 1, 16183, 3, 2, 12, 3, 2, 3
#define I_wlanAccessControlListSetComment_5g	4
#define O_wlanAccessControlListSetComment_5g	1, 3, 6, 1, 4, 1, 16183, 3, 2, 12, 3, 2, 4
#define I_wlanAccessControlListAdd_5g			5
#define O_wlanAccessControlListAdd_5g			1, 3, 6, 1, 4, 1, 16183, 3, 2, 12, 3, 2, 5
#define I_wlanAccessControlListDel_5g			6
#define O_wlanAccessControlListDel_5g			1, 3, 6, 1, 4, 1, 16183, 3, 2, 12, 3, 2, 6
#define I_wlanAccessControlListDelAll_5g		7
#define O_wlanAccessControlListDelAll_5g		1, 3, 6, 1, 4, 1, 16183, 3, 2, 12, 3, 2, 7
#define I_wlanAccessControlListTable_5g		8
#define O_wlanAccessControlListTable_5g		1, 3, 6, 1, 4, 1, 16183, 3, 2, 12, 3, 2, 8
#define I_wlanAccessControlListEntry_5g		1
#define O_wlanAccessControlListEntry_5g		1, 3, 6, 1, 4, 1, 16183, 3, 2, 12, 3, 2, 8, 1
#define I_wlanAccessControlListIndex_5g		1
#define O_wlanAccessControlListIndex_5g		1, 3, 6, 1, 4, 1, 16183, 3, 2, 12, 3, 2, 8, 1, 1
#define I_wlanAccessControlListSSIDIndex_5g	2
#define O_wlanAccessControlListSSIDIndex_5g	1, 3, 6, 1, 4, 1, 16183, 3, 2, 12, 3, 2, 8, 1, 2
#define I_wlanAccessControlListSSID_5g			3
#define O_wlanAccessControlListSSID_5g			1, 3, 6, 1, 4, 1, 16183, 3, 2, 12, 3, 2, 8, 1, 3
#define I_wlanAccessControlListHwAddr_5g		4
#define O_wlanAccessControlListHwAddr_5g		1, 3, 6, 1, 4, 1, 16183, 3, 2, 12, 3, 2, 8, 1, 4
#define I_wlanAccessControlListDescription_5g	5
#define O_wlanAccessControlListDescription_5g	1, 3, 6, 1, 4, 1, 16183, 3, 2, 12, 3, 2, 8, 1, 5

#define I_vlanConfig						13
#define O_vlanConfig						1, 3, 6, 1, 4, 1, 16183, 3, 2, 13
#define I_vlanConfigTable					1
#define O_vlanConfigTable					1, 3, 6, 1, 4, 1, 16183, 3, 2, 13, 1
#define I_vlanConfigEntry					1
#define O_vlanConfigEntry					1, 3, 6, 1, 4, 1, 16183, 3, 2, 13, 1, 1
#define I_vlanConfigIndex					1
#define O_vlanConfigIndex					1, 3, 6, 1, 4, 1, 16183, 3, 2, 13, 1, 1, 1
#define I_vlanConfigVid						2
#define O_vlanConfigVid						1, 3, 6, 1, 4, 1, 16183, 3, 2, 13, 1, 1, 2
#define I_vlanConfigMemberPort				3
#define O_vlanConfigMemberPort				1, 3, 6, 1, 4, 1, 16183, 3, 2, 13, 1, 1, 3

#define I_portfwConfig						14
#define O_portfwConfig						1, 3, 6, 1, 4, 1, 16183, 3, 2, 14
#define I_portfwConfigtype					1
#define O_portfwConfigtype					1, 3, 6, 1, 4, 1, 16183, 3, 2, 14, 1
#define I_portfwConfigExternalPortStrat		2
#define O_portfwConfigExternalPortStrat		1, 3, 6, 1, 4, 1, 16183, 3, 2, 14, 2
#define I_portfwConfigExternalPortEnd		3
#define O_portfwConfigExternalPortEnd		1, 3, 6, 1, 4, 1, 16183, 3, 2, 14, 3
#define I_portfwConfigIpAddress				4
#define O_portfwConfigIpAddress				1, 3, 6, 1, 4, 1, 16183, 3, 2, 14, 4
#define I_portfwConfigInternalPortStrat		5
#define O_portfwConfigInternalPortStrat		1, 3, 6, 1, 4, 1, 16183, 3, 2, 14, 5
#define I_portfwConfigInternalPortEnd		6
#define O_portfwConfigInternalPortEnd		1, 3, 6, 1, 4, 1, 16183, 3, 2, 14, 6
#define I_portfwConfigAdd					7
#define O_portfwConfigAdd					1, 3, 6, 1, 4, 1, 16183, 3, 2, 14, 7
#define I_portfwConfigDel					8
#define O_portfwConfigDel					1, 3, 6, 1, 4, 1, 16183, 3, 2, 14, 8
#define I_portfwConfigDelAll				9
#define O_portfwConfigDelAll				1, 3, 6, 1, 4, 1, 16183, 3, 2, 14, 9
#define I_portfwConfigTable					10
#define O_portfwConfigTable					1, 3, 6, 1, 4, 1, 16183, 3, 2, 14, 10
#define I_portfwConfigListEntry				1
#define O_portfwConfigListEntry				1, 3, 6, 1, 4, 1, 16183, 3, 2, 14, 10, 1
#define I_portfwConfigListIndex				1
#define O_portfwConfigListIndex				1, 3, 6, 1, 4, 1, 16183, 3, 2, 14, 10, 1, 1
#define I_portfwConfigListExternalPortStart 2
#define O_portfwConfigListExternalPortStart 1, 3, 6, 1, 4, 1, 16183, 3, 2, 14, 10, 1, 2
#define I_portfwConfigListExternalPortEnd	3
#define O_portfwConfigListExternalPortEnd	1, 3, 6, 1, 4, 1, 16183, 3, 2, 14, 10, 1, 3
#define I_portfwConfigListIpAddres			4
#define O_portfwConfigListIpAddres			1, 3, 6, 1, 4, 1, 16183, 3, 2, 14, 10, 1, 4
#define I_portfwConfigListInternalPortStart	5
#define O_portfwConfigListInternalPortStart	1, 3, 6, 1, 4, 1, 16183, 3, 2, 14, 10, 1, 5
#define I_portfwConfigListInternalPortEnd	6
#define O_portfwConfigListInternalPortEnd	1, 3, 6, 1, 4, 1, 16183, 3, 2, 14, 10, 1, 6

#define I_Status							3
#define O_Status							1, 3, 6, 1, 4, 1, 16183, 3, 3
#define I_IgmpStatus						1
#define O_IgmpStatus						1, 3, 6, 1, 4, 1, 16183, 3, 3, 1
#define I_IgmpJoinTable						1
#define O_IgmpJoinTable						1, 3, 6, 1, 4, 1, 16183, 3, 3, 1, 1
#define I_IgmpJoinEntry						1
#define O_IgmpJoinEntry						1, 3, 6, 1, 4, 1, 16183, 3, 3, 1, 1, 1
#define I_IgmpJoinIndex						1
#define O_IgmpJoinIndex						1, 3, 6, 1, 4, 1, 16183, 3, 3, 1, 1, 1, 1
#define I_IgmpJoinIpAddress					2
#define O_IgmpJoinIpAddress					1, 3, 6, 1, 4, 1, 16183, 3, 3, 1, 1, 1, 2
#define I_IgmpJoinMemberNumber				3
#define O_IgmpJoinMemberNumber				1, 3, 6, 1, 4, 1, 16183, 3, 3, 1, 1, 1, 3
#define I_IgmpJoinPort						4
#define O_IgmpJoinPort						1, 3, 6, 1, 4, 1, 16183, 3, 3, 1, 1, 1, 4

#define I_multicastTable					2
#define O_multicastTable					1, 3, 6, 1, 4, 1, 16183, 3, 3, 1, 2
#define I_multicastEntry					1
#define O_multicastEntry					1, 3, 6, 1, 4, 1, 16183, 3, 3, 1, 2, 1
#define I_multicastIndex					1
#define O_multicastIndex					1, 3, 6, 1, 4, 1, 16183, 3, 3, 1, 2, 1, 1
#define I_multicastJoinIpAddress			2
#define O_multicastJoinIpAddress			1, 3, 6, 1, 4, 1, 16183, 3, 3, 1, 2, 1, 2
#define I_multicastPortNumber				3
#define O_multicastPortNumber				1, 3, 6, 1, 4, 1, 16183, 3, 3, 1, 2, 1, 3
#define I_multicastPortName					4
#define O_multicastPortName					1, 3, 6, 1, 4, 1, 16183, 3, 3, 1, 2, 1, 4
#define I_multicastOperation				5
#define O_multicastOperation				1, 3, 6, 1, 4, 1, 16183, 3, 3, 1, 2, 1, 5
#define I_multicastInPackets				6
#define O_multicastInPackets				1, 3, 6, 1, 4, 1, 16183, 3, 3, 1, 2, 1, 6
#define I_multicastOutPackets				7
#define O_multicastOutPackets				1, 3, 6, 1, 4, 1, 16183, 3, 3, 1, 2, 1, 7

#define I_SysLogStatus				2
#define O_SysLogStatus				1, 3, 6, 1, 4, 1, 16183, 3, 3, 2
#define I_SysLogTable				1
#define O_SysLogTable				1, 3, 6, 1, 4, 1, 16183, 3, 3, 2, 1
#define I_SysLogEntry				1
#define O_SysLogEntry				1, 3, 6, 1, 4, 1, 16183, 3, 3, 2, 1, 1
#define I_SysLogIndex				1
#define O_SysLogIndex				1, 3, 6, 1, 4, 1, 16183, 3, 3, 2, 1, 1, 1
#define I_SysLogString				2
#define O_SysLogString				1, 3, 6, 1, 4, 1, 16183, 3, 3, 2, 1, 1, 2

#define I_HostInfoOnPort			3
#define O_HostInfoOnPort			1, 3, 6, 1, 4, 1, 16183, 3, 3, 3
#define I_HostInfoOnPortTable		1
#define O_HostInfoOnPortTable		1, 3, 6, 1, 4, 1, 16183, 3, 3, 3, 1
#define I_HostInfoOnPortEntry		1
#define O_HostInfoOnPortEntry		1, 3, 6, 1, 4, 1, 16183, 3, 3, 3, 1, 1
#define I_HostInfoOnPortIndex		1
#define O_HostInfoOnPortIndex		1, 3, 6, 1, 4, 1, 16183, 3, 3, 3, 1, 1, 1
#define I_PortNumber				2
#define O_PortNumber				1, 3, 6, 1, 4, 1, 16183, 3, 3, 3, 1, 1, 2
#define I_PortName					3
#define O_PortName					1, 3, 6, 1, 4, 1, 16183, 3, 3, 3, 1, 1, 3
#define I_PortHostMacAddr			4
#define O_PortHostMacAddr			1, 3, 6, 1, 4, 1, 16183, 3, 3, 3, 1, 1, 4
#define I_PortHostIpAddr			5
#define O_PortHostIpAddr			1, 3, 6, 1, 4, 1, 16183, 3, 3, 3, 1, 1, 5

#define I_PortStatus				4
#define O_PortStatus				1, 3, 6, 1, 4, 1, 16183, 3, 3, 4
#define I_PortStatusTable			1
#define O_PortStatusTable			1, 3, 6, 1, 4, 1, 16183, 3, 3, 4, 1
#define I_PortStatusEntry			1
#define O_PortStatusEntry			1, 3, 6, 1, 4, 1, 16183, 3, 3, 4, 1, 1
#define I_PortStatusIndex			1
#define O_PortStatusIndex			1, 3, 6, 1, 4, 1, 16183, 3, 3, 4, 1, 1, 1
#define I_PortStatusNumber			2
#define O_PortStatusNumber			1, 3, 6, 1, 4, 1, 16183, 3, 3, 4, 1, 1, 2
#define I_PortStatusName			3
#define O_PortStatusName			1, 3, 6, 1, 4, 1, 16183, 3, 3, 4, 1, 1, 3
#define I_PortStatusInBps			4
#define O_PortStatusInBps			1, 3, 6, 1, 4, 1, 16183, 3, 3, 4, 1, 1, 4
#define I_PortStatusOutBps			5
#define O_PortStatusOutBps			1, 3, 6, 1, 4, 1, 16183, 3, 3, 4, 1, 1, 5
#define I_PortStatusCRC				6
#define O_PortStatusCRC				1, 3, 6, 1, 4, 1, 16183, 3, 3, 4, 1, 1, 6

#define I_wlanActiveStatus			5
#define O_wlanActiveStatus			1, 3, 6, 1, 4, 1, 16183, 3, 3, 5
#define I_wlanActiveStatusTable		1
#define O_wlanActiveStatusTable		1, 3, 6, 1, 4, 1, 16183, 3, 3, 5, 1
#define I_wlanActiveStatusEntry		1
#define O_wlanActiveStatusEntry		1, 3, 6, 1, 4, 1, 16183, 3, 3, 5, 1, 1

#define I_wlanActiveIndex			1
#define O_wlanActiveIndex			1, 3, 6, 1, 4, 1, 16183, 3, 3, 5, 1, 1, 1
#define I_wlanActiveSSID			2
#define O_wlanActiveSSID			1, 3, 6, 1, 4, 1, 16183, 3, 3, 5, 1, 1, 2
#define I_wlanActiveMacAddr			3
#define O_wlanActiveMacAddr			1, 3, 6, 1, 4, 1, 16183, 3, 3, 5, 1, 1, 3
#define I_wlanActiveMode				4
#define O_wlanActiveMode				1, 3, 6, 1, 4, 1, 16183, 3, 3, 5, 1, 1, 4
#define I_wlanActiveAuthResult		5
#define O_wlanActiveAuthResult		1, 3, 6, 1, 4, 1, 16183, 3, 3, 5, 1, 1, 5
#define I_wlanActiveRSSI			6
#define O_wlanActiveRSSI			1, 3, 6, 1, 4, 1, 16183, 3, 3, 5, 1, 1, 6

#define I_wlanScanActiveStatus			6
#define O_wlanScanActiveStatus			1, 3, 6, 1, 4, 1, 16183, 3, 3, 6
#define I_wlanScanActiveStatusTable		1
#define O_wlanScanActiveStatusTable		1, 3, 6, 1, 4, 1, 16183, 3, 3, 6, 1
#define I_wlanScanActiveStatusEntry		1
#define O_wlanScanActiveStatusEntry		1, 3, 6, 1, 4, 1, 16183, 3, 3, 6, 1, 1

#define I_SHUBWLANSCANACTIVEINDEX     		1
#define O_SHUBWLANSCANACTIVEINDEX     		1, 3, 6, 1, 4, 1, 16183, 3, 3, 6, 1, 1, 1

#define I_SHUBWLANSCANACTIVESSID      		2
#define O_SHUBWLANSCANACTIVESSID      		1, 3, 6, 1, 4, 1, 16183, 3, 3, 6, 1, 1, 2

#define I_SHUBWLANSCANACTIVEBSSID       	3
#define O_SHUBWLANSCANACTIVEBSSID       	1, 3, 6, 1, 4, 1, 16183, 3, 3, 6, 1, 1, 3

#define I_SHUBWLANSCANACTIVECHANNEL      	4
#define O_SHUBWLANSCANACTIVECHANNEL      	1, 3, 6, 1, 4, 1, 16183, 3, 3, 6, 1, 1, 4

#define I_SHUBWLANSCANACTIVEENCRYPT       	5
#define O_SHUBWLANSCANACTIVEENCRYPT       	1, 3, 6, 1, 4, 1, 16183, 3, 3, 6, 1, 1, 5

#define I_SHUBWLANSCANACTIVERSSI      		6
#define O_SHUBWLANSCANACTIVERSSI      		1, 3, 6, 1, 4, 1, 16183, 3, 3, 6, 1, 1, 6

#define I_SHUBWLANSCAN					2
#define O_SHUBWLANSCAN					1, 3, 6, 1, 4, 1, 16183, 3, 3, 6, 2

#define I_SHUBWLANSCAN_DOIT				1
#define O_SHUBWLANSCAN_DOIT				1, 3, 6, 1, 4, 1, 16183, 3, 3, 6, 2, 1

#define I_Resource						7
#define O_Resource     					1, 3, 6, 1, 4, 1, 16183, 3, 3, 7

#define I_CPU_Utilization				1
#define O_CPU_Utilization     			1, 3, 6, 1, 4, 1, 16183, 3, 3, 7, 1

#define I_RAM_Utilization				2
#define O_RAM_Utilization     			1, 3, 6, 1, 4, 1, 16183, 3, 3, 7, 2

#define I_Flash_Utilization				3
#define O_Flash_Utilization     		1, 3, 6, 1, 4, 1, 16183, 3, 3, 7, 3

#define I_System_Log				8
#define O_System_Log     			1, 3, 6, 1, 4, 1, 16183, 3, 3, 8

#define I_Delete_System_Log				1
#define O_Delete_System_Log     		1, 3, 6, 1, 4, 1, 16183, 3, 3, 8, 1

#define I_wlanActiveStatus_5g			9
#define O_wlanActiveStatus_5g			1, 3, 6, 1, 4, 1, 16183, 3, 3, 9
#define I_wlanActiveStatusTable_5g		1
#define O_wlanActiveStatusTable_5g		1, 3, 6, 1, 4, 1, 16183, 3, 3, 9, 1
#define I_wlanActiveStatusEntry_5g		1
#define O_wlanActiveStatusEntry_5g		1, 3, 6, 1, 4, 1, 16183, 3, 3, 9, 1, 1

#define I_wlanActiveIndex_5g			1
#define O_wlanActiveIndex_5g			1, 3, 6, 1, 4, 1, 16183, 3, 3, 9, 1, 1, 1
#define I_wlanActiveSSID_5g			2
#define O_wlanActiveSSID_5g			1, 3, 6, 1, 4, 1, 16183, 3, 3, 9, 1, 1, 2
#define I_wlanActiveMacAddr_5g			3
#define O_wlanActiveMacAddr_5g			1, 3, 6, 1, 4, 1, 16183, 3, 3, 9, 1, 1, 3
#define I_wlanActiveMode_5g				4
#define O_wlanActiveMode_5g				1, 3, 6, 1, 4, 1, 16183, 3, 3, 9, 1, 1, 4
#define I_wlanActiveAuthResult_5g		5
#define O_wlanActiveAuthResult_5g		1, 3, 6, 1, 4, 1, 16183, 3, 3, 9, 1, 1, 5
#define I_wlanActiveRSSI_5g			6
#define O_wlanActiveRSSI_5g			1, 3, 6, 1, 4, 1, 16183, 3, 3, 9, 1, 1, 6

#define I_wlanScanActiveStatus_5g			10
#define O_wlanScanActiveStatus_5g			1, 3, 6, 1, 4, 1, 16183, 3, 3, 10
#define I_wlanScanActiveStatusTable_5g		1
#define O_wlanScanActiveStatusTable_5g		1, 3, 6, 1, 4, 1, 16183, 3, 3, 10, 1
#define I_wlanScanActiveStatusEntry_5g	1
#define O_wlanScanActiveStatusEntry_5g		1, 3, 6, 1, 4, 1, 16183, 3, 3, 10, 1, 1

#define I_SHUBWLANSCANACTIVEINDEX_5g     		1
#define O_SHUBWLANSCANACTIVEINDEX_5g     		1, 3, 6, 1, 4, 1, 16183, 3, 3, 10, 1, 1, 1

#define I_SHUBWLANSCANACTIVESSID_5g      		2
#define O_SHUBWLANSCANACTIVESSID_5g      		1, 3, 6, 1, 4, 1, 16183, 3, 3, 10, 1, 1, 2

#define I_SHUBWLANSCANACTIVEBSSID_5g       	3
#define O_SHUBWLANSCANACTIVEBSSID_5g       	1, 3, 6, 1, 4, 1, 16183, 3, 3, 10, 1, 1, 3

#define I_SHUBWLANSCANACTIVECHANNEL_5g      	4
#define O_SHUBWLANSCANACTIVECHANNEL_5g      	1, 3, 6, 1, 4, 1, 16183, 3, 3, 10, 1, 1, 4

#define I_SHUBWLANSCANACTIVEENCRYPT_5g       	5
#define O_SHUBWLANSCANACTIVEENCRYPT_5g       	1, 3, 6, 1, 4, 1, 16183, 3, 3, 10, 1, 1, 5

#define I_SHUBWLANSCANACTIVERSSI_5g      		6
#define O_SHUBWLANSCANACTIVERSSI_5g      		1, 3, 6, 1, 4, 1, 16183, 3, 3, 10, 1, 1, 6

#define I_SHUBWLANSCAN_5g					2
#define O_SHUBWLANSCAN_5g					1, 3, 6, 1, 4, 1, 16183, 3, 3, 10, 2

#define I_SHUBWLANSCAN_DOIT_5g				1
#define O_SHUBWLANSCAN_DOIT_5g				1, 3, 6, 1, 4, 1, 16183, 3, 3, 10, 2, 1

#define I_SystemDiag				4
#define O_SystemDiag				1, 3, 6, 1, 4, 1, 16183, 3, 4
#define I_SystemRemoteResetConfig	1
#define O_SystemRemoteResetConfig	1, 3, 6, 1, 4, 1, 16183, 3, 4, 1
#define I_SystemRemoteReset			1
#define O_SystemRemoteReset			1, 3, 6, 1, 4, 1, 16183, 3, 4, 1, 1
#define I_AutoResetMode				2
#define O_AutoResetMode				1, 3, 6, 1, 4, 1, 16183, 3, 4, 1, 2
#define I_AutoResetWanTraffic		3
#define O_AutoResetWanTraffic		1, 3, 6, 1, 4, 1, 16183, 3, 4, 1, 3

#define I_pingTest					2
#define O_pingTest					1, 3, 6, 1, 4, 1, 16183, 3, 4, 2
#define I_pingTable					1
#define O_pingTable					1, 3, 6, 1, 4, 1, 16183, 3, 4, 2, 1
#define I_pingEntry					1
#define O_pingEntry					1, 3, 6, 1, 4, 1, 16183, 3, 4, 2, 1, 1
#define I_pingSerialNumber			1
#define O_pingSerialNumber			1, 3, 6, 1, 4, 1, 16183, 3, 4, 2, 1, 1, 1
#define I_pingProtocol				2
#define O_pingProtocol				1, 3, 6, 1, 4, 1, 16183, 3, 4, 2, 1, 1, 2
#define I_pingAddress				3
#define O_pingAddress				1, 3, 6, 1, 4, 1, 16183, 3, 4, 2, 1, 1, 3
#define I_pingPacketCount			4
#define O_pingPacketCount			1, 3, 6, 1, 4, 1, 16183, 3, 4, 2, 1, 1, 4
#define I_pingPacketSize			5
#define O_pingPacketSize			1, 3, 6, 1, 4, 1, 16183, 3, 4, 2, 1, 1, 5
#define I_pingPacketTimeout			6
#define O_pingPacketTimeout			1, 3, 6, 1, 4, 1, 16183, 3, 4, 2, 1, 1, 6
#define I_pingDelay					7
#define O_pingDelay					1, 3, 6, 1, 4, 1, 16183, 3, 4, 2, 1, 1, 7
#define I_pingTraponCompletion		8
#define O_pingTraponCompletion		1, 3, 6, 1, 4, 1, 16183, 3, 4, 2, 1, 1, 8
#define I_pingSentPackets			9
#define O_pingSentPackets			1, 3, 6, 1, 4, 1, 16183, 3, 4, 2, 1, 1, 9
#define I_pingReceivePackets		10
#define O_pingReceivePackets		1, 3, 6, 1, 4, 1, 16183, 3, 4, 2, 1, 1, 10
#define I_pingMinRtt				11
#define O_pingMinRtt				1, 3, 6, 1, 4, 1, 16183, 3, 4, 2, 1, 1, 11
#define I_pingAvgRtt				12
#define O_pingAvgRtt				1, 3, 6, 1, 4, 1, 16183, 3, 4, 2, 1, 1, 12
#define I_pingMaxRtt				13
#define O_pingMaxRtt				1, 3, 6, 1, 4, 1, 16183, 3, 4, 2, 1, 1, 13
#define I_pingCompleted				14
#define O_pingCompleted				1, 3, 6, 1, 4, 1, 16183, 3, 4, 2, 1, 1, 14
#define I_pingEntryOwner			15
#define O_pingEntryOwner			1, 3, 6, 1, 4, 1, 16183, 3, 4, 2, 1, 1, 15
#define I_pingEntryStatus			16
#define O_pingEntryStatus			1, 3, 6, 1, 4, 1, 16183, 3, 4, 2, 1, 1, 16

#define I_cpePing					3
#define O_cpePing					1, 3, 6, 1, 4, 1, 16183, 3, 4, 3

#define I_cpePingTable		1
#define O_cpePingTable		1, 3, 6, 1, 4, 1, 16183, 3, 4, 3, 1
#define I_cpePingEntry		1
#define O_cpePingEnrry		1, 3, 6, 1, 4, 1, 16183, 3, 4, 3, 1, 1
#define I_cpePingTablePortIndex		1
#define O_cpePingTablePortIndex		1, 3, 6, 1, 4, 1, 16183, 3, 4, 3, 1, 1, 1
#define I_cpePingTableAction		2
#define O_cpePingTableAction		1, 3, 6, 1, 4, 1, 16183, 3, 4, 3, 1, 1, 2
#define I_cpePingTableCpeMac		3
#define O_cpePingTableCpeMac		1, 3, 6, 1, 4, 1, 16183, 3, 4, 3, 1, 1, 3
#define I_cpePingTableAddress		4
#define O_cpePingTableAddress		1, 3, 6, 1, 4, 1, 16183, 3, 4, 3, 1, 1, 4
#define I_cpePingTableRttMin		5
#define O_cpePingTableRttMin		1, 3, 6, 1, 4, 1, 16183, 3, 4, 3, 1, 1, 5
#define I_cpePingTableRttAvg		6
#define O_cpePingTableRttAvg		1, 3, 6, 1, 4, 1, 16183, 3, 4, 3, 1, 1, 6
#define I_cpePingTableRttMax		7
#define O_cpePingTableRttMax		1, 3, 6, 1, 4, 1, 16183, 3, 4, 3, 1, 1, 7
#define I_cpePingTableTimeout		8
#define O_cpePingTableTimeout		1, 3, 6, 1, 4, 1, 16183, 3, 4, 3, 1, 1, 8
#define I_cpePingTrap		2
#define O_cpePingTrap		1, 3, 6, 1, 4, 1, 16183, 3, 4, 3, 2
#define I_cpePingTrapSet		1
#define O_cpePingTrapSet		1, 3, 6, 1, 4, 1, 16183, 3, 4, 3, 2, 1

#define I_FactoryReset				4
#define O_FactoryReset				1, 3, 6, 1, 4, 1, 16183, 3, 4, 4
#define I_FactoryResetSet			4
#define O_FactoryResetSet			1, 3, 6, 1, 4, 1, 16183, 3, 4, 4, 4
#define I_AdminAccountReset			5
#define O_AdminAccountReset			1, 3, 6, 1, 4, 1, 16183, 3, 4, 4, 5
#define I_AdminAccountResetSet		1
#define O_AdminAccountResetSet		1, 3, 6, 1, 4, 1, 16183, 3, 4, 4, 5, 1

#define I_IgmpJoinTest				10
#define O_IgmpJoinTest				1, 3, 6, 1, 4, 1, 16183, 3, 4, 10
#define I_IgmpJoinGroupAddr			1
#define O_IgmpJoinGroupAddr			1, 3, 6, 1, 4, 1, 16183, 3, 4, 10, 1
#define I_IgmpJoinGroupPort			2
#define O_IgmpJoinGroupPort			1, 3, 6, 1, 4, 1, 16183, 3, 4, 10, 2
#define I_IgmpJoinVersion			3
#define O_IgmpJoinVersion			1, 3, 6, 1, 4, 1, 16183, 3, 4, 10, 3
#define I_IgmpJoinMessage			4
#define O_IgmpJoinMessage			1, 3, 6, 1, 4, 1, 16183, 3, 4, 10, 4

#define I_Extra						5
#define O_Extra						1, 3, 6, 1, 4, 1, 16183, 3, 5
#define I_ConfigSave				1
#define O_ConfigSave				1, 3, 6, 1, 4, 1, 16183, 3, 5, 1
#define I_ConfigSaveAndApply		1
#define O_ConfigSaveAndApply		1, 3, 6, 1, 4, 1, 16183, 3, 5, 1, 1
#define I_ConfigMode				2
#define O_ConfigMode				1, 3, 6, 1, 4, 1, 16183, 3, 5, 2
#define I_SystemInitConfMode		1
#define O_SystemInitConfMode		1, 3, 6, 1, 4, 1, 16183, 3, 5, 2, 1

#define I_ConfigRootAccount			3
#define O_ConfigRootAccount			1, 3, 6, 1, 4, 1, 16183, 3, 5, 3
#define I_SystemConfigRootAccount	1
#define O_SystemConfigRootAccount	1, 3, 6, 1, 4, 1, 16183, 3, 5, 3, 1
#define I_SystemConfigAdminAccount	2
#define O_SystemConfigAdminAccount	1, 3, 6, 1, 4, 1, 16183, 3, 5, 3, 2
#define I_RootAccountMode			3
#define O_RootAccountMode			1, 3, 6, 1, 4, 1, 16183, 3, 5, 3, 3

#define I_ConfigIpv6PassThru		4
#define O_ConfigIpv6PassThru		1, 3, 6, 1, 4, 1, 16183, 3, 5, 4
#define I_Ipv6PassThru				1
#define O_Ipv6PassThru				1, 3, 6, 1, 4, 1, 16183, 3, 5, 4, 1

#define I_AutoReset					5
#define O_AutoReset					1, 3, 6, 1, 4, 1, 16183, 3, 5, 5

#define I_AutoResetActive			1
#define O_AutoResetActive			1, 3, 6, 1, 4, 1, 16183, 3, 5, 5, 1

#define I_AutoResetWanCRC			2
#define O_AutoResetWanCRC			1, 3, 6, 1, 4, 1, 16183, 3, 5, 5, 2

#define I_Trap						6
#define O_Trap						1, 3, 6, 1, 4, 1, 16183, 3, 6
#define I_newIpAllocation			1
#define O_newIpAllocation			1, 3, 6, 1, 4, 1, 16183, 3, 6, 1

#define I_CpepingEntryTrap			3
#define O_CpepingEntryTrap			1, 3, 6, 1, 4, 1, 16183, 3, 6, 3
#define I_CpepingEntryTrapLeaf		1
#define O_CpepingEntryTrapLeaf 		1, 3, 6, 1, 4, 1, 16183, 3, 6, 3, 1

#define I_AutoReootTrap				4
#define O_AutoReootTrap				1, 3, 6, 1, 4, 1, 16183, 3, 6, 4
#define I_AutoReootTrapLeaf			1
#define O_AutoReootTrapLeaf 		1, 3, 6, 1, 4, 1, 16183, 3, 6, 4, 1

#define I_PortLinkTrapRoot			5
#define O_PortLinkTrapRoot			1, 3, 6, 1, 4, 1, 16183, 3, 6, 5
#define I_PortLinkTrapLeaf			1
#define O_PortLinkTrapLeaf 			O_PortLinkTrapRoot, 1

#define I_LimitSessionTrapRoot		6
#define O_LimitSessionTrapRoot		1, 3, 6, 1, 4, 1, 16183, 3, 6, 6
#define I_LimitSessionTrapLeaf		1
#define O_LimitSessionTrapLeaf 		O_LimitSessionTrapRoot, 1

#define I_SmartResetTrapRoot		7
#define O_SmartResetTrapRoot		1, 3, 6, 1, 4, 1, 16183, 3, 6, 7
#define I_SmartResetTrapLeaf		1
#define O_SmartResetTrapLeaf 		O_SmartResetTrapRoot, 1

#define I_AutoBandwidthTrapRoot		8
#define O_AutoBandwidthTrapRoot		1, 3, 6, 1, 4, 1, 16183, 3, 6, 8
#define I_AutoBandwidthTrapLeaf		1
#define O_AutoBandwidthTrapLeaf 	O_AutoBandwidthTrapRoot, 1

#define I_HandOverSuccessTrapRoot	9
#define O_HandOverSuccessTrapRoot	1, 3, 6, 1, 4, 1, 16183, 3, 6, 9
#define I_HandOverSuccessTrapLeaf	1
#define O_HandOverSuccessTrapLeaf 	O_HandOverSuccessTrapRoot, 1

#define I_NtpFailTrapRoot			0
#define O_NtpFailTrapRoot			1, 3, 6, 1, 4, 1, 16183, 3, 7, 0
#define I_NtpFailTrapLeaf			1
#define O_NtpFailTrapLeaf 			O_NtpFailTrapRoot, 1

#define I_SitesurveyResultTrapRoot	1
#define O_SitesurveyResultTrapRoot	1, 3, 6, 1, 4, 1, 16183, 3, 7, 1
#define I_SitesurveyResultTrapLeaf	1
#define O_SitesurveyResultTrapLeaf 	O_SitesurveyResultTrapRoot, 1

#define I_StaConnectFailTrapRoot	1
#define O_StaConnectFailTrapRoot	1, 3, 6, 1, 4, 1, 16183, 3, 8, 1
#define I_StaConnectFailTrapLeaf	1
#define O_StaConnectFailTrapLeaf 	O_StaConnectFailTrapRoot, 1

/* Put here additional MIB specific include definitions */

#define I_ConnectInfoEntry			2
#define O_ConnectInfoEntry			1, 3, 6, 1, 4, 1, 16183, 3, 6, 2
#define I_ConnectStatus				1
#define O_ConnectStauts				1, 3, 6, 1, 4, 1, 16183, 3, 6, 2, 1
#define I_ConnectUptime				2
#define O_ConnectUptime				1, 3, 6, 1, 4, 1, 16183, 3, 6, 2, 2
#define I_ConnectLastingtime		3
#define O_ConnectLastingtime		1, 3, 6, 1, 4, 1, 16183, 3, 6, 2, 3
#define I_ConnectApMacAddr			4
#define O_ConnectApMacAddr			1, 3, 6, 1, 4, 1, 16183, 3, 6, 2, 4
#define I_ConnectcpeMacAddr			5
#define O_ConnectcpeMacAddr			1, 3, 6, 1, 4, 1, 16183, 3, 6, 2, 5
#define I_ConnectSSID				6
#define O_ConnectSSID				1, 3, 6, 1, 4, 1, 16183, 3, 6, 2, 6
#define I_ConnectPacketsCount		6
#define O_ConnectPacketsCount		1, 3, 6, 1, 4, 1, 16183, 3, 6, 2, 6

#define I_cpePingTrapEntry			3
#define O_cpePingTrapEntry			1, 3, 6, 1, 4, 1, 16183, 3, 6, 3
#define I_cpePortNumber				1
#define O_cpePortNumber				1, 3, 6, 1, 4, 1, 16183, 3, 6, 3, 1
#define I_cpeMacAddr				2
#define O_cpeMacAddr				1, 3, 6, 1, 4, 1, 16183, 3, 6, 3, 2
#define I_cpeIpAddr					3
#define O_cpeIpAddr					1, 3, 6, 1, 4, 1, 16183, 3, 6, 3, 3
#define I_cpeMinRtt					4
#define O_cpeMinRtt					1, 3, 6, 1, 4, 1, 16183, 3, 6, 3, 4
#define I_cpeAvgRtt					5
#define O_cpeAvgRtt					1, 3, 6, 1, 4, 1, 16183, 3, 6, 3, 5
#define I_cpeMaxRtt					6
#define O_cpeMaxRtt					1, 3, 6, 1, 4, 1, 16183, 3, 6, 3, 6
#define I_cpeTimeout				6
#define O_cpeTimeout				1, 3, 6, 1, 4, 1, 16183, 3, 6, 3, 6

#define I_AutoResetTrapEntry			4
#define O_AutoResetTrapEntry			1, 3, 6, 1, 4, 1, 16183, 3, 6, 4
#define I_AutoResetApLocalTime			1
#define O_AutoResetApLocalTime			1, 3, 6, 1, 4, 1, 16183, 3, 6, 4, 1
#define I_AutoResetApMacAddr			2
#define O_AutoResetApMacAddr			1, 3, 6, 1, 4, 1, 16183, 3, 6, 4, 2

#define	I_advancedEntry					4
#define	O_advancedEntry					1, 3, 6, 1, 4, 1, 16183, 4
#define	I_advancedInformation			1
#define	O_advancedInformation			1, 3, 6, 1, 4, 1, 16183, 4, 1
#define	I_advancedSystemInfo			1
#define	O_advancedSystemInfo			1, 3, 6, 1, 4, 1, 16183, 4, 1, 1
#define	I_advancedSystemConfig			1
#define	O_advancedSystemConfig			1, 3, 6, 1, 4, 1, 16183, 4, 1, 1, 1
#define	I_advancedWirelessConfig		1
#define	O_advancedWirelessConfig		1, 3, 6, 1, 4, 1, 16183, 4, 1, 1, 1, 1
#define	I_advancedWirelessHandover		1
#define	O_advancedWirelessHandover		1, 3, 6, 1, 4, 1, 16183, 4, 1, 1, 1, 1, 1

#endif	//_SKBB_MIB_
