typedef enum {
	IP_ADDR,
	SUBNET_MASK,
	DEFAULT_GATEWAY,
	HW_ADDR
} ADDR_T;


typedef struct __wanConfig_T__ {
	unsigned char	madAddr[6];
	int				obtainedMethod;
	unsigned int	IpAddr;
	unsigned int	subnetMask;
	unsigned int	defGateway;
	unsigned int	DNS[2];
	int				autoDNS;
	int				changed;
} _wanConfig_T_;

typedef struct __lanConfig_T__ {
	unsigned char 	macAddr[6];
	unsigned int 	IpAddr;
	unsigned int 	subnetMask;
	int				dhcpEnable;
	long			dhcpStartIp;
	long 			dhcpEndIp;
	int				changed;
}_lanConfig_T_;

typedef struct __wlanBasicConfig_T__ {
	int		wlanMode;			// 1 = Enable, 0 = Disable
	int		wlanBand;			// 1 ~ 11
	int		wlanBonding;
	int		wlanAutoBonding;
	int		CtrlSideBand;
	int		channelNumber;
	int		DataRate;
	int		sessionLimit;
	int		handover;			// 1 = Enable, 0 = Disable
	int		changed;
}_wlanBasicConfig_T_;

typedef struct __wlanMulitSSIDConfig_T__ {
	char	ssid[64];			// ssid name
	int		ssidMode;			// enable/disable SSID
	int		bssid;				// broadcast SSID
	int		enc;
	int		ratelimit;
	int		changed;
}_wlanMultiSSIDConfig_T_;

typedef struct __wlanAdvConfig_T__ {
	int		frag_threshold;
	int		rts_threshold;
	int		beacon_intv;
	int		preamble_type;
	int		iapp;
	int		rfoutpwr;
	int		changed;
}_wlanadvConfig_T_;

typedef struct __SecRadiusConfig_T__ {
	unsigned int		radiusIP;
	int					radiusPort;
	char				radiusPasswd[80];
	int					serverMode;
	unsigned int 		accountIP;
	int					accountPort;
	char				accountPasswd[80];
} _SecRadiusConfig_T_;

typedef struct __SecWEPConfig_T__ {
	char		WEPAuthEnable;
	char		WEP8021xAuthMode;	//1=enable, 2=disable
	char		WEPMacAuthMode;		//1=enable, 2=disable
	char		WEPAuthMethod;		//1=open-system, 2=Shared Key, 3=Auto
	char		WEPAuthKeySize;		//1=64bit, 2=128bit
	char		WEPKeyFormat;		//1=ascii, 2=hexa
	short		WEPKeyIndex;		//1~4
	char		EncryptionKey[28];
} _SecWEPConfig_T_;

typedef struct __SecWPAxConfig_T__ {
	char		WPAxAuthMode;		// 1=enterprize, 2=personal
	char		WPAxCipherSuite;	// 1=TKIP, 2=AES, 3=TKIP_n_AES
	char		WPAxKeyFormat;		// 1=PassPhrase, 2=Hex_64Characters
	char		KeyLength;			// PassPhrase minimum 8 byte, HexChracter 64 Characters
	char		*PreSharedKey;
} _SecWPAxConfig_T_;

typedef struct __SecWPAmixConfig_T__ {
	char		WPAmixAuthMode;		// 1=enterprize, 2=personal
	char		WPAmixCipherSuite;	// 1=TKIP, 2=AES, 3=TKIP_n_AES
	char		WPAmix2CipherSuite;	// 1=TKIP, 2=AES, 3=TKIP_n_AES
	char		WPAmixKeyFormat;		// 1=PassPhrase, 2=Hex_64Characters
	char		*PreSharedKey;
} _SecWPAmixConfig_T_;

typedef struct __SecurityConfig_T__{
	int						changed[5]; 	// 0 = not changed, 1= changed
	int						securityMode[5]; // 0 = disable, 1= WEP, 2=WPA 3=WPA2 4=WPA mixed...
	_SecRadiusConfig_T_		secRadiusConfig[5];
	_SecWEPConfig_T_		secWEPConfig[5];
	_SecWPAxConfig_T_		secWPAxConfig[5];
	_SecWPAmixConfig_T_		secWPAmixConfig[5];
} _SecurityConfig_T_;

typedef struct __portConfig_T__ {
	char		port_config[64];
	int 		changed;
}_portConfig_T_;

typedef struct __portLimit_T__ {
	int			slimit;
	int 		changed;
}_portLimit_T_;

typedef struct __IGMPConfig_T__ {
	int			igmpEnable;
	int			fastleaveEnable;
	int			MemExpTime;
	int			QryIntv;
	int			GrpRespIntv;
	int			GrpmemIntv;
	int			GrpQryIntv;
	int 		changed;
}_IGMPConfig_T_;

typedef struct __SNMPConfig_T__ {
	int			snmpEnable;
	char		getcommName[64];
	int			getcommType;
	int			getcommAdmin;
	char		setcommName[64];
	int			setcommType;
	int			setcommAdmin;
	char		trapDest[11][64];
	char 		trapName[64];
	int			trapAdmin;
	int 		commchanged;
	int 		trapSrvchanged[8];
	int 		trapchanged;
}_SNMPConfig_T_;

typedef struct __syslogConfig_T__ {
	int			logEnable;
	int			rlogEnable;
	char		rlogServer[64];
	int 		changed;
}_syslogConfig_T_;

typedef struct __ntpConfig_T__ {
	char		ntpServer[3][32];
	int 		changed;
}_ntpConfig_T_;

typedef struct __QosConfig_T__ {
	int			limitMode;
	int			Rxlimit;
	int			Txlimit;
	int 		flowCtrl;
	int 		changed;
}_QosConfig_T_;

typedef struct __PortfwConfig_T__ {
	char 			name[16];
	unsigned long	ipaddr;
	int				startport;
	int				endport;
	int				slanport;
	int				elanport;
	int				protocol;
	int				changed;
} _PortFw_tbl_T_;

_wanConfig_T_ wanConfig;
_lanConfig_T_ lanConfig;
_wlanBasicConfig_T_ wlanBasicConfig[2];
_wlanMultiSSIDConfig_T_ wlanMultiConfig[5][2];
_wlanadvConfig_T_ wlanAdvConfig[2];
_SecurityConfig_T_ securityConfig[2];
_portConfig_T_ portConfig[5];
_portLimit_T_ portLimit;
_IGMPConfig_T_ IGMPConfig;
_SNMPConfig_T_ SNMPConfig;
_syslogConfig_T_ syslogConfig;
_ntpConfig_T_ ntpConfig;
_QosConfig_T_ QosConfig[5];
_PortFw_tbl_T_ portfw_entry;
_PortFw_tbl_T_ portfw_tbl[20];
_PortFw_tbl_T_ check_entry;

struct _misc_data_ {
	unsigned char	mimo_tr_hw_support;
	unsigned char	mimo_tr_used;
	unsigned char	resv[30];
};

typedef struct active_wlan_sta_info {
	unsigned char	mac[6];
	unsigned char	mode;
	unsigned char	AuthResult;
	char			SSID[33];
	unsigned char	rssi;
	unsigned long	snr;
	unsigned long	ber;
} ACTIVE_WLSTA_INFO_T, *ACTIVE_WLSTA_INFO_Tp;

typedef struct {
//	unsigned short protocol;
	char	pingAddress[64];
	int		pktCount;
	int		pktSize;
	int		pktTimeout;
	int		pktDelay;
	short	TrapOnComplete;
// ping Test Result
	unsigned int sentPktCount;
	unsigned int recvPktCount;
	unsigned int minPingTime;
	unsigned int avgPingTime;
	unsigned int maxPingTime;
	short		pingCompleted;
	char		pingOwner[256];
	short		EntryStatus;
	int 		pid;
} _PING_TEST_T;

