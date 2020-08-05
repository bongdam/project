/* General includes */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/in.h>
#include <unistd.h>
#include <fcntl.h>

/* SNMP includes */
#include "asn1.h"
#include "snmp.h"
#include "agt_mib.h"
#include "agt_engine.h"
#include "cjhv_mib.h"
#include "snmp_main.h"
#include "cjhv_api.h"

GB public_mib_buffer;
unsigned int adjacent_channel[13];
unsigned int best_channel[13];
extern int dmz_type;

unsigned long mhtol(unsigned char *str, int str_len)
{
    int i;
    unsigned long ulret = 0;

    for (i = 0; i < str_len; i++) {
        ulret = (ulret << 8) | str[i];
    }

    return ulret;
}

/* ======================= SYSTEM INFO ================================= */
/* The model name of AP */
unsigned char *
var_cjhvApSysModelName(int *var_len, snmp_info_t *mesg,
        int (**write_method)())
{
	/* Add value computations */
	get_modelName(public_mib_buffer.gb_string, sizeof(public_mib_buffer.gb_string));
	/* Set size (in bytes) and return address of the variable */
	*var_len = strlen(public_mib_buffer.gb_string);
	return (unsigned char *)public_mib_buffer.gb_string;
}

/* The Firmware version of AP */
unsigned char *
var_cjhvApSysFirmwareVersion(int *var_len, snmp_info_t *mesg,
        int (**write_method)())
{
	/* Add value computations */
	get_version(public_mib_buffer.gb_string, sizeof(public_mib_buffer.gb_string));
	/* Set size (in bytes) and return address of the variable */
	*var_len = strlen(public_mib_buffer.gb_string);
	return (unsigned char *)public_mib_buffer.gb_string;
}

/* The time (in hundredths of a second) since the ap was last initialized (system up time) */
unsigned char *
var_cjhvApSysuptime(int *var_len, snmp_info_t *mesg,
        int (**write_method)())
{
	/* Add value computations */
	get_uptime(public_mib_buffer.gb_string, sizeof(public_mib_buffer.gb_string), UPTIME);
	/* Set size (in bytes) and return address of the variable */
	*var_len = strlen(public_mib_buffer.gb_string);
	return (unsigned char *)public_mib_buffer.gb_string;
}

/* CPU Usage of AP */
unsigned char *
var_cjhvApSysCpu(int *var_len, snmp_info_t *mesg,
        int (**write_method)())
{
	/* Add value computations */
	public_mib_buffer.gb_long = get_cpu_utiliz();
	*write_method = 0;
	*var_len = sizeof(public_mib_buffer.gb_long);
	return (unsigned char *)&public_mib_buffer.gb_long;
}

/* Memory Usage of AP */
unsigned char *
var_cjhvApSysMemory(int *var_len, snmp_info_t *mesg,
        int (**write_method)())
{
	/* Add value computations */
	public_mib_buffer.gb_long = get_ram_utiliz();
	*write_method = 0;
	*var_len = sizeof(public_mib_buffer.gb_long);
	return (unsigned char *)&public_mib_buffer.gb_long;
}

/* The time (in hundredths of a second) since the ap wan port status changed (wan port uptime) */
unsigned char *
var_cjhvApWanuptime(int *var_len, snmp_info_t *mesg,
        int (**write_method)())
{
	get_uptime(public_mib_buffer.gb_string, sizeof(public_mib_buffer.gb_string), WANUPTIME);
	/* Set size (in bytes) and return address of the variable */
	*var_len = strlen(public_mib_buffer.gb_string);
	return (unsigned char *)public_mib_buffer.gb_string;
}

/* firmware status of AP */
unsigned char *
var_cjhvApSysFirmStatus(int *var_len, snmp_info_t *mesg,
		int (**write_method)())
{
	public_mib_buffer.gb_long = get_sys_status();
	/* Set size (in bytes) and return address of the variable */
	*var_len = sizeof(public_mib_buffer.gb_long);
	return (unsigned char *)&public_mib_buffer.gb_long;
}

unsigned char *
var_cjhvApSysWANCRC(int *var_len, snmp_info_t *mesg,
        int (**write_method)())
{
	public_mib_buffer.gb_counter = get_portStatusCrc(PRTNR_WAN0);
	*var_len = sizeof(public_mib_buffer.gb_counter);
	*write_method = 0;
	return (unsigned char *)&public_mib_buffer.gb_counter;
}
/* ======================= SYSTEM INFO ================================= */

/* cjhvApSystemInfo_tree */
static oid cjhvApSystemInfo_oid[] = { O_cjhvApSystemInfo };
static Object cjhvApSystemInfo_variables[] = {
    { SNMP_STRING, (RONLY| SCALAR), var_cjhvApSysModelName,
                 {2, { I_cjhvApSysModelName, 0 }}},
    { SNMP_STRING, (RONLY| SCALAR), var_cjhvApSysFirmwareVersion,
                 {2, { I_cjhvApSysFirmwareVersion, 0 }}},
    { SNMP_STRING, (RONLY| SCALAR), var_cjhvApSysuptime,
                 {2, { I_cjhvApSysuptime, 0 }}},
    { SNMP_INTEGER, (RWRITE| SCALAR), var_cjhvApSysCpu,
                 {2, { I_cjhvApSysCpu, 0 }}},
    { SNMP_INTEGER, (RWRITE| SCALAR), var_cjhvApSysMemory,
                 {2, { I_cjhvApSysMemory, 0 }}},
    { SNMP_STRING, (RONLY| SCALAR), var_cjhvApWanuptime,
                 {2, { I_cjhvApWanUpTime, 0 }}},
    { SNMP_INTEGER, (RONLY| SCALAR), var_cjhvApSysFirmStatus,
                 {2, { I_cjhvApSysFirmStatus, 0 }}},
    { SNMP_COUNTER, (RONLY| SCALAR), var_cjhvApSysWANCRC,
                 {2, { I_cjhvApSysWANCRC, 0 }}},
    { 0 }
    };
static SubTree cjhvApSystemInfo_tree =  { NULL, cjhvApSystemInfo_variables,
	        (sizeof(cjhvApSystemInfo_oid)/sizeof(oid)), cjhvApSystemInfo_oid };
/* cjhvApSystemInfo_tree */

/* ======================= WAN STATUS ================================= */
unsigned char *
var_cjhvApWanStatus(int *var_len, snmp_info_t *mesg,
        int (**write_method)())
{
     public_mib_buffer.gb_long = get_wan_status();
    /* Set size (in bytes) and return address of the variable */
    *var_len = sizeof(public_mib_buffer.gb_long);

    return (unsigned char *)&public_mib_buffer.gb_long;
}

unsigned char *
var_cjhvApWanMacAddress(int *var_len, snmp_info_t *mesg,
        int (**write_method)())
{
    get_mac(public_mib_buffer.gb_string, sizeof(public_mib_buffer.gb_string));

    /* Set size (in bytes) and return address of the variable */
    *var_len = 6;
    return (unsigned char *)public_mib_buffer.gb_string;
}

unsigned char *
var_cjhvApWanIpAddress(int *var_len, snmp_info_t *mesg,
        int (**write_method)())
{
   	/* Add value computations */
	get_wanIpAddress(&public_mib_buffer.gb_ip_address);
	/* Set size (in bytes) and return address of the variable */
	*var_len = sizeof(public_mib_buffer.gb_ip_address);

	return (unsigned char *)&public_mib_buffer.gb_ip_address;
}

unsigned char *
var_cjhvApWanSubnetMask(int *var_len, snmp_info_t *mesg,
        int (**write_method)())
{
    get_wanSubnetMask(&public_mib_buffer.gb_ip_address);
    *var_len = sizeof(public_mib_buffer.gb_ip_address);

    return (unsigned char *)&public_mib_buffer.gb_ip_address;
}

unsigned char *
var_cjhvApWanDefaultGW(int *var_len, snmp_info_t *mesg,
        int (**write_method)())
{
    /* Add value computations */
    get_gwIpAddress(&public_mib_buffer.gb_ip_address);
    /* Set size (in bytes) and return address of the variable */
    *var_len = sizeof(public_mib_buffer.gb_ip_address);

    return (unsigned char *)&public_mib_buffer.gb_ip_address;
}

unsigned char *
var_cjhvApWanDNS1(int *var_len, snmp_info_t *mesg,
        int (**write_method)())
{
    get_dnsAddress(&public_mib_buffer.gb_ip_address, 1);
    *var_len = sizeof(public_mib_buffer.gb_ip_address);

    return (unsigned char *)&public_mib_buffer.gb_ip_address;
}

unsigned char *
var_cjhvApWanDNS2(int *var_len, snmp_info_t *mesg,
        int (**write_method)())
{
    get_dnsAddress(&public_mib_buffer.gb_ip_address, 2);
    *var_len = sizeof(public_mib_buffer.gb_ip_address);

    return (unsigned char *)&public_mib_buffer.gb_ip_address;
}

int write_wanMode(int action, unsigned char *var_val, unsigned char varval_type, int var_val_len, unsigned char *statP, Oid * name)
{
	int ret = 1;

	switch (action) {
		case RESERVE1:
			break;
		case RESERVE2:
			break;
		case COMMIT:
			ret = set_wanMethod((int)mhtol(var_val, var_val_len));
			break;
		case ACTION:
			break;
		case FREE:
			break;
	}

	return (ret == 0) ? SNMP_ERROR_WRONGVALUE : 0;
}

unsigned char *
var_cjhvApWanObtainIpMethodSet(int *var_len, snmp_info_t *mesg,
        int (**write_method)())
{
    public_mib_buffer.gb_long = get_wan_status();
    *write_method = (int (*)())&write_wanMode;
    /* Set size (in bytes) and return address of the variable */
    *var_len = sizeof(public_mib_buffer.gb_long);

    return (unsigned char *)&public_mib_buffer.gb_long;
}

int write_wanIpAddress(int action, unsigned char *var_val, unsigned char varval_type, int var_val_len, unsigned char *statP, Oid * name)
{
	int ret = 1;

	switch (action) {
		case RESERVE1:
			break;
		case RESERVE2:
			break;
		case COMMIT:
			ret = set_wanIpAddress(var_val, var_val_len);
			break;
		case ACTION:
			break;
		case FREE:
			break;
	}

	return (ret == 0) ? SNMP_ERROR_WRONGVALUE : 0;
}

unsigned char *
var_cjhvApWanIpAddressSet(int *var_len, snmp_info_t *mesg,
        int (**write_method)())
{
    get_wanIpAddress(&public_mib_buffer.gb_ip_address);
    *write_method = (int (*)())&write_wanIpAddress;
    /* Set size (in bytes) and return address of the variable */
    *var_len = sizeof(public_mib_buffer.gb_ip_address);

    return (unsigned char *)&public_mib_buffer.gb_ip_address;
}

int write_wanSubnetMask(int action,
						unsigned char *var_val, unsigned char varval_type, int var_val_len, unsigned char *statP, Oid * name)
{
	int ret = 1;

	switch (action) {
		case RESERVE1:
			break;
		case RESERVE2:
			break;
		case COMMIT:
			ret = set_wanSubnetMask(var_val, var_val_len);
			break;
		case ACTION:
			break;
		case FREE:
			break;
	}

	return (ret == 0) ? SNMP_ERROR_WRONGVALUE : 0;
}

unsigned char *
var_cjhvApWanSubnetMaskSet(int *var_len, snmp_info_t *mesg,
        int (**write_method)())
{
    get_wanSubnetMask(&public_mib_buffer.gb_ip_address);
    *write_method = (int (*)())&write_wanSubnetMask;
    *var_len = sizeof(public_mib_buffer.gb_ip_address);

    return (unsigned char *)&public_mib_buffer.gb_ip_address;
}

int write_wanDefaultGW(int action,
					   unsigned char *var_val, unsigned char varval_type, int var_val_len, unsigned char *statP, Oid * name)
{
	int ret = 1;

	switch (action) {
		case RESERVE1:
			break;
		case RESERVE2:
			break;
		case COMMIT:
			ret = set_wanDefaultGW(var_val, var_val_len);
			break;
		case ACTION:
			break;
		case FREE:
			break;
	}

	return (ret == 0) ? SNMP_ERROR_WRONGVALUE : 0;
}

unsigned char *
var_cjhvApWanDefaultGWSet(int *var_len, snmp_info_t *mesg,
        int (**write_method)())
{
    /* Add value computations */
    get_gwIpAddress(&public_mib_buffer.gb_ip_address);
    *write_method = (int (*)())&write_wanDefaultGW;
    /* Set size (in bytes) and return address of the variable */
    *var_len = sizeof(public_mib_buffer.gb_ip_address);

    return (unsigned char *)&public_mib_buffer.gb_ip_address;
}

unsigned char *
var_cjhvApWanDNS1Set(int *var_len, snmp_info_t *mesg,
        int (**write_method)())
{
    get_dnsAddress(&public_mib_buffer.gb_ip_address, 1);
    *write_method = 0;
    *var_len = sizeof(public_mib_buffer.gb_ip_address);

    return (unsigned char *)&public_mib_buffer.gb_ip_address;
}

int write_wanDNS2(int action,
				  unsigned char *var_val, unsigned char varval_type, int var_val_len, unsigned char *statP, Oid * name)
{
	int ret = 1;

	switch (action) {
	case RESERVE1:
		break;
	case RESERVE2:
		break;
	case COMMIT:
		ret = set_wanDNS2(var_val, var_val_len);
		break;
	case ACTION:
		break;
	case FREE:
		break;
	}

	return (ret == 0) ? SNMP_ERROR_WRONGVALUE : 0;
}

unsigned char *
var_cjhvApWanDNS2Set(int *var_len, snmp_info_t *mesg,
        int (**write_method)())
{
    get_dnsAddress(&public_mib_buffer.gb_ip_address, 2);
    *write_method = (int (*)())&write_wanDNS2;
    *var_len = sizeof(public_mib_buffer.gb_ip_address);

    return (unsigned char *)&public_mib_buffer.gb_ip_address;
}
/* ======================= WAN STATUS ================================= */

/* cjhvApWanConfig_tree */
static oid cjhvApWanConfig_oid[] = { O_cjhvApWanConfig };
static Object cjhvApWanConfig_variables[] = {
    { SNMP_INTEGER, (RONLY| SCALAR), var_cjhvApWanStatus,
                 {2, { I_cjhvApWanStatus, 0 }}},
    { SNMP_STRING, (RONLY| SCALAR), var_cjhvApWanMacAddress,
                 {2, { I_cjhvApWanMacAddress, 0 }}},
    { SNMP_IPADDRESS, (RONLY| SCALAR), var_cjhvApWanIpAddress,
                 {2, { I_cjhvApWanIpAddress, 0 }}},
    { SNMP_IPADDRESS, (RONLY| SCALAR), var_cjhvApWanSubnetMask,
                 {2, { I_cjhvApWanSubnetMask, 0 }}},
    { SNMP_IPADDRESS, (RONLY| SCALAR), var_cjhvApWanDefaultGW,
                 {2, { I_cjhvApWanDefaultGW, 0 }}},
    { SNMP_IPADDRESS, (RONLY| SCALAR), var_cjhvApWanDNS1,
                 {2, { I_cjhvApWanDNS1, 0 }}},
    { SNMP_IPADDRESS, (RONLY| SCALAR), var_cjhvApWanDNS2,
                 {2, { I_cjhvApWanDNS2, 0 }}},
    { SNMP_INTEGER, (RWRITE| SCALAR), var_cjhvApWanObtainIpMethodSet,
                 {3, { I_cjhvApWanSetup, I_cjhvApWanObtainIpMethodSet, 0 }}},
    { SNMP_IPADDRESS, (RWRITE| SCALAR), var_cjhvApWanIpAddressSet,
                 {3, { I_cjhvApWanSetup, I_cjhvApWanIpAddressSet, 0 }}},
    { SNMP_IPADDRESS, (RWRITE| SCALAR), var_cjhvApWanSubnetMaskSet,
                 {3, { I_cjhvApWanSetup, I_cjhvApWanSubnetMaskSet, 0 }}},
    { SNMP_IPADDRESS, (RWRITE| SCALAR), var_cjhvApWanDefaultGWSet,
                 {3, { I_cjhvApWanSetup, I_cjhvApWanDefaultGWSet, 0 }}},
    { SNMP_IPADDRESS, (RONLY| SCALAR), var_cjhvApWanDNS1Set,
                 {3, { I_cjhvApWanSetup, I_cjhvApWanDNS1Set, 0 }}},
    { SNMP_IPADDRESS, (RWRITE| SCALAR), var_cjhvApWanDNS2Set,
                 {3, { I_cjhvApWanSetup, I_cjhvApWanDNS2Set, 0 }}},
    { 0 }
    };
static SubTree cjhvApWanConfig_tree =  { NULL, cjhvApWanConfig_variables,
	        (sizeof(cjhvApWanConfig_oid)/sizeof(oid)), cjhvApWanConfig_oid};
/* cjhvApWanConfig_tree */

/* ======================= LAN STATUS ================================= */
unsigned char *
var_cjhvApLanMacAddress(int *var_len, snmp_info_t *mesg,
        int (**write_method)())
{
    get_lanMac(public_mib_buffer.gb_string, sizeof(public_mib_buffer.gb_string));
    /* Set size (in bytes) and return address of the variable */
    *var_len = 6;
    return (unsigned char *)&public_mib_buffer.gb_string;
}

unsigned char *
var_cjhvApLanIpAddress(int *var_len, snmp_info_t *mesg,
        int (**write_method)())
{
    /* Add value computations */
    get_lanIpAddress(&public_mib_buffer.gb_ip_address);
    /* Set size (in bytes) and return address of the variable */
    *var_len = sizeof(public_mib_buffer.gb_ip_address);
    return (unsigned char *)&public_mib_buffer.gb_ip_address;
}

unsigned char *
var_cjhvApLanSubnetMask(int *var_len, snmp_info_t *mesg,
        int (**write_method)())
{
    /* Add value computations */
    get_lanSubnetMask(&public_mib_buffer.gb_ip_address);
    /* Set size (in bytes) and return address of the variable */
    *var_len = sizeof(public_mib_buffer.gb_ip_address);
    return (unsigned char *)&public_mib_buffer.gb_ip_address;
}

int write_lanIPAddress(int action,
					   unsigned char *var_val, unsigned char varval_type, int var_val_len, unsigned char *statP, Oid * name)
{
	int ret = 1;

	switch (action) {
		case RESERVE1:
			break;
		case RESERVE2:
			break;
		case COMMIT:
			ret = set_lanIPAddress(var_val, var_val_len);
			break;
		case ACTION:
			break;
		case FREE:
			break;
	}

	return (ret == 0) ? SNMP_ERROR_WRONGVALUE : 0;
}

unsigned char *
var_cjhvApLanIpAddressSet(int *var_len, snmp_info_t *mesg,
        int (**write_method)())
{
	/* Add value computations */
	get_lanIpAddress(&public_mib_buffer.gb_ip_address);
	/* Set write-function (uncomment if you want to implement it)  */
	*write_method = (int (*)())&write_lanIPAddress;
	/* Set size (in bytes) and return address of the variable */
	*var_len = sizeof(public_mib_buffer.gb_ip_address);
	return (unsigned char *)&public_mib_buffer.gb_ip_address;
}

int write_lanSubnetMask(int action,
						unsigned char *var_val, unsigned char varval_type, int var_val_len, unsigned char *statP, Oid * name)
{
	int ret = 1;

	switch (action) {
		case RESERVE1:
			break;
		case RESERVE2:
			break;
		case COMMIT:
			ret = set_lanSubnetMask(var_val, var_val_len);
			break;
		case ACTION:
			break;
		case FREE:
			break;
	}

	return (ret == 0) ? SNMP_ERROR_WRONGVALUE : 0;
}

unsigned char *
var_cjhvApLanSubnetMaskSet(int *var_len, snmp_info_t *mesg,
        int (**write_method)())
{
	/* Add value computations */
	get_lanSubnetMask(&public_mib_buffer.gb_ip_address);
	/* Set write-function (uncomment if you want to implement it)  */
	*write_method = (int (*)())&write_lanSubnetMask;
	/* Set size (in bytes) and return address of the variable */
	*var_len = sizeof(public_mib_buffer.gb_ip_address);
	return (unsigned char *)&public_mib_buffer.gb_ip_address;
}

int write_dhcpServer(int action,
					 unsigned char *var_val, unsigned char varval_type, int var_val_len, unsigned char *statP, Oid * name)
{
	int ret = 1;

	switch (action) {
		case RESERVE1:
			break;
		case RESERVE2:
			break;
		case COMMIT:
			ret = set_dhcpServer((int)mhtol(var_val, var_val_len));
			break;
		case ACTION:
			break;
		case FREE:
			break;
	}

	return (ret == 0) ? SNMP_ERROR_WRONGVALUE : 0;
}

unsigned char *
var_cjhvApLanDhcpEnable(int *var_len, snmp_info_t *mesg,
        int (**write_method)())
{
	/* Add value computations */
	public_mib_buffer.gb_long = get_dhcpServer();
	/* Set write-function (uncomment if you want to implement it)  */
	*write_method = (int (*)())&write_dhcpServer;
	/* Set size (in bytes) and return address of the variable */
	*var_len = sizeof(long);
	return (unsigned char *)&public_mib_buffer.gb_long;
}

int write_ipPoolStartAddress(int action,
							 unsigned char *var_val, unsigned char varval_type, int var_val_len,
							 unsigned char *statP, Oid * name)
{
	int ret = 1;

	switch (action) {
		case RESERVE1:
			break;
		case RESERVE2:
			break;
		case COMMIT:
			ret = set_ipPoolStartAddress(var_val, var_val_len);
			break;
		case ACTION:
			break;
		case FREE:
			break;
	}

	return (ret == 0) ? SNMP_ERROR_WRONGVALUE : 0;
}

unsigned char *
var_cjhvApLanDhcpStartIPAddress(int *var_len, snmp_info_t *mesg,
        int (**write_method)())
{
    /* Add value computations */
    get_ipPoolStartAddress(&public_mib_buffer.gb_ip_address);
    /* Set write-function (uncomment if you want to implement it)  */
    *write_method = (int (*)())&write_ipPoolStartAddress;
    /* Set size (in bytes) and return address of the variable */
    *var_len = sizeof(public_mib_buffer.gb_ip_address);
    return (unsigned char *)&public_mib_buffer.gb_ip_address;
}

int write_ipPoolEndAddress(int action,
						   unsigned char *var_val, unsigned char varval_type, int var_val_len, unsigned char *statP, Oid * name)
{
	int ret = 1;

	switch (action) {
	case RESERVE1:
		break;
	case RESERVE2:
		break;
	case COMMIT:
		ret = set_ipPoolEndAddress(var_val, var_val_len);
		break;
	case ACTION:
		break;
	case FREE:
		break;
	}

	return (ret == 0) ? SNMP_ERROR_WRONGVALUE : 0;
}

unsigned char *
var_cjhvApLanDhcpEndIPAddress(int *var_len, snmp_info_t *mesg,
        int (**write_method)())
{
	/* Add value computations */
	get_ipPoolEndAddress(&public_mib_buffer.gb_ip_address);
	/* Set write-function (uncomment if you want to implement it)  */
	*write_method = (int (*)())&write_ipPoolEndAddress;
	/* Set size (in bytes) and return address of the variable */
	*var_len = sizeof(public_mib_buffer.gb_ip_address);
	return (unsigned char *)&public_mib_buffer.gb_ip_address;
}
/* ======================= LAN STATUS ================================= */

/* cjhvApLanConfig_tree */
static oid cjhvApLanConfig_oid[] = { O_cjhvApLanConfig };
static Object cjhvApLanConfig_variables[] = {
    { SNMP_STRING, (RONLY| SCALAR), var_cjhvApLanMacAddress,
                 {2, { I_cjhvApLanMacAddress, 0 }}},
    { SNMP_IPADDRESS, (RONLY| SCALAR), var_cjhvApLanIpAddress,
                 {2, { I_cjhvApLanIpAddress, 0 }}},
    { SNMP_IPADDRESS, (RONLY| SCALAR), var_cjhvApLanSubnetMask,
                 {2, { I_cjhvApLanSubnetMask, 0 }}},
    { SNMP_IPADDRESS, (RWRITE| SCALAR), var_cjhvApLanIpAddressSet,
                 {3, { I_cjhvApLanSetup, I_cjhvApLanIpAddressSet, 0 }}},
    { SNMP_IPADDRESS, (RWRITE| SCALAR), var_cjhvApLanSubnetMaskSet,
                 {3, { I_cjhvApLanSetup, I_cjhvApLanSubnetMaskSet, 0 }}},
    { SNMP_INTEGER, (RWRITE| SCALAR), var_cjhvApLanDhcpEnable,
                 {3, { I_cjhvApLanSetup, I_cjhvApLanDhcpEnable, 0 }}},
    { SNMP_IPADDRESS, (RWRITE| SCALAR), var_cjhvApLanDhcpStartIPAddress,
                 {3, { I_cjhvApLanSetup, I_cjhvApLanDhcpStartIPAddress, 0 }}},
    { SNMP_IPADDRESS, (RWRITE| SCALAR), var_cjhvApLanDhcpEndIPAddress,
                 {3, { I_cjhvApLanSetup, I_cjhvApLanDhcpEndIPAddress, 0 }}},
    { 0 }
    };
static SubTree cjhvApLanConfig_tree =  { NULL, cjhvApLanConfig_variables,
	        (sizeof(cjhvApLanConfig_oid)/sizeof(oid)), cjhvApLanConfig_oid};
/* cjhvApLanConfig_tree */

/* ======================= WLAN BASIC ================================= */
int write_wlanMode(int action,
				   unsigned char *var_val, unsigned char varval_type, int var_val_len, unsigned char *statP, Oid * name)
{
	int ret = 1;

	switch (action) {
		case RESERVE1:
			break;
		case RESERVE2:
			break;
		case COMMIT:
			ret = set_wlanMode((int)mhtol(var_val, var_val_len), WLAN_2G);
			break;
		case ACTION:
			break;
		case FREE:
			break;
	}

	return (ret == 0) ? SNMP_ERROR_WRONGVALUE : 0;
}

unsigned char *
var_cjhvApWlanMode(int *var_len, snmp_info_t *mesg,
        int (**write_method)())
{
    public_mib_buffer.gb_long = get_wlanMode(WLAN_2G);
    *write_method = (int (*)())&write_wlanMode;
    *var_len = sizeof(long);

    return (unsigned char *)&public_mib_buffer.gb_long;
}

int write_wlanBand(int action,
				   unsigned char *var_val, unsigned char varval_type, int var_val_len, unsigned char *statP, Oid * name)
{
	int ret = 1;

	switch (action) {
		case RESERVE1:
			break;
		case RESERVE2:
			break;
		case COMMIT:
			ret = set_wlanBand((int)mhtol(var_val, var_val_len), WLAN_2G);
			break;
		case ACTION:
			break;
		case FREE:
			break;
	}

	return (ret == 0) ? SNMP_ERROR_WRONGVALUE : 0;
}

unsigned char *
var_cjhvApWlanBand(int *var_len, snmp_info_t *mesg,
        int (**write_method)())
{
    public_mib_buffer.gb_long = get_wlanBand(WLAN_2G);
    *write_method = (int (*)())&write_wlanBand;
    *var_len = sizeof(long);

    return (unsigned char *)&public_mib_buffer.gb_long;
}

int write_wlanChannelWidth(int action,
				   unsigned char *var_val, unsigned char varval_type, int var_val_len, unsigned char *statP, Oid * name)
{
	int ret = 1;

	switch (action) {
		case RESERVE1:
			break;
		case RESERVE2:
			break;
		case COMMIT:
			ret = set_wlanChannelWidth((int)mhtol(var_val, var_val_len), WLAN_2G);
			break;
		case ACTION:
			break;
		case FREE:
			break;
		}

	return (ret == 0) ? SNMP_ERROR_WRONGVALUE : 0;
}

unsigned char *
var_cjhvApWlanChannelWidth(int *var_len, snmp_info_t *mesg,
        int (**write_method)())
{
    public_mib_buffer.gb_long = get_wlanChannelWidth(WLAN_2G);
    *write_method = (int (*)())&write_wlanChannelWidth;
    *var_len = sizeof(long);

    return (unsigned char *)&public_mib_buffer.gb_long;
}

int write_wlanCtrlSideBand(int action,
						   unsigned char *var_val, unsigned char varval_type, int var_val_len, unsigned char *statP, Oid * name)
{
	int ret = 1;

	switch (action) {
		case RESERVE1:
			break;
		case RESERVE2:
			break;
		case COMMIT:
			ret = set_wlanCtrlSideBand((int)mhtol(var_val, var_val_len), WLAN_2G);
			break;
		case ACTION:
			break;
		case FREE:
			break;
	}

	return (ret == 0) ? SNMP_ERROR_WRONGVALUE : 0;
}

unsigned char *
var_cjhvApWlanCtrlSideband(int *var_len, snmp_info_t *mesg,
        int (**write_method)())
{
    public_mib_buffer.gb_long = get_wlanCtrlSideBand(WLAN_2G);
    *write_method = (int (*)())&write_wlanCtrlSideBand;
    *var_len = sizeof(long);

    return (unsigned char *)&public_mib_buffer.gb_long;
}

int write_wlanChannelNumber(int action,
							unsigned char *var_val, unsigned char varval_type, int var_val_len,
							unsigned char *statP, Oid * name)
{
	int ret = 1;

	switch (action) {
		case RESERVE1:
			break;
		case RESERVE2:
			break;
		case COMMIT:
			ret = set_wlanChannelNumber((int)mhtol(var_val, var_val_len), WLAN_2G);
			break;
		case ACTION:
			break;
		case FREE:
			break;
	}

	return (ret == 0) ? SNMP_ERROR_WRONGVALUE : 0;
}

unsigned char *
var_cjhvApWlanChannelNumber(int *var_len, snmp_info_t *mesg,
        int (**write_method)())
{
    public_mib_buffer.gb_long = get_wlanChannelNumber(WLAN_2G);
    *write_method = (int (*)())&write_wlanChannelNumber;
    *var_len = sizeof(long);

    return (unsigned char *)&public_mib_buffer.gb_long;
}

int write_wlanDateRate(int action,
					   unsigned char *var_val, unsigned char varval_type, int var_val_len, unsigned char *statP, Oid * name)
{
	int ret = 1;

	switch (action) {
		case RESERVE1:
			break;
		case RESERVE2:
			break;
		case COMMIT:
			ret = set_wlanDateRate((int)mhtol(var_val, var_val_len), WLAN_2G);
			break;
		case ACTION:
			break;
		case FREE:
			break;
	}

	return (ret == 0) ? SNMP_ERROR_WRONGVALUE : 0;
}

unsigned char *
var_cjhvApWlanDataRate(int *var_len, snmp_info_t *mesg,
        int (**write_method)())
{
    public_mib_buffer.gb_long = get_wlanDateRate(WLAN_2G);
    *write_method = (int (*)())&write_wlanDateRate;
    *var_len = sizeof(long);

    return (unsigned char *)&public_mib_buffer.gb_long;
}

int write_wlanMode_5g(int action,
				   unsigned char *var_val, unsigned char varval_type, int var_val_len, unsigned char *statP, Oid * name)
{
	int ret = 1;

	switch (action) {
		case RESERVE1:
			break;
		case RESERVE2:
			break;
		case COMMIT:
			ret = set_wlanMode((int)mhtol(var_val, var_val_len), WLAN_5G);
			break;
		case ACTION:
			break;
		case FREE:
			break;
	}

	return (ret == 0) ? SNMP_ERROR_WRONGVALUE : 0;
}

unsigned char *
var_cjhvApWlanMode_5g(int *var_len, snmp_info_t *mesg,
        int (**write_method)())
{
    public_mib_buffer.gb_long = get_wlanMode(WLAN_5G);
    *write_method = (int (*)())&write_wlanMode_5g;
    *var_len = sizeof(long);

    return (unsigned char *)&public_mib_buffer.gb_long;
}

int write_wlanBand_5g(int action,
				   unsigned char *var_val, unsigned char varval_type, int var_val_len, unsigned char *statP, Oid * name)
{
	int ret = 1;

	switch (action) {
		case RESERVE1:
			break;
		case RESERVE2:
			break;
		case COMMIT:
			ret = set_wlanBand((int)mhtol(var_val, var_val_len), WLAN_5G);
			break;
		case ACTION:
			break;
		case FREE:
			break;
	}

	return (ret == 0) ? SNMP_ERROR_WRONGVALUE : 0;
}

unsigned char *
var_cjhvApWlanBand_5g(int *var_len, snmp_info_t *mesg,
        int (**write_method)())
{
    public_mib_buffer.gb_long = get_wlanBand(WLAN_5G);
    *write_method = (int (*)())&write_wlanBand_5g;
    *var_len = sizeof(long);

    return (unsigned char *)&public_mib_buffer.gb_long;
}

int write_wlanChannelWidth_5g(int action,
				   unsigned char *var_val, unsigned char varval_type, int var_val_len, unsigned char *statP, Oid * name)
{
	int ret = 1;

	switch (action) {
		case RESERVE1:
			break;
		case RESERVE2:
			break;
		case COMMIT:
			ret = set_wlanChannelWidth((int)mhtol(var_val, var_val_len), WLAN_5G);
			break;
		case ACTION:
			break;
		case FREE:
			break;
		}

	return (ret == 0) ? SNMP_ERROR_WRONGVALUE : 0;
}

unsigned char *
var_cjhvApWlanChannelWidth_5g(int *var_len, snmp_info_t *mesg,
        int (**write_method)())
{
    public_mib_buffer.gb_long = get_wlanChannelWidth(WLAN_5G);
    *write_method = (int (*)())&write_wlanChannelWidth_5g;
    *var_len = sizeof(long);

    return (unsigned char *)&public_mib_buffer.gb_long;
}

int write_wlanChannelNumber_5g(int action,
							unsigned char *var_val, unsigned char varval_type, int var_val_len,
							unsigned char *statP, Oid * name)
{
	int ret = 1;

	switch (action) {
		case RESERVE1:
			break;
		case RESERVE2:
			break;
		case COMMIT:
			ret = set_wlanChannelNumber((int)mhtol(var_val, var_val_len), WLAN_5G);
			break;
		case ACTION:
			break;
		case FREE:
			break;
	}

	return (ret == 0) ? SNMP_ERROR_WRONGVALUE : 0;
}

unsigned char *
var_cjhvApWlanChannelNumber_5g(int *var_len, snmp_info_t *mesg,
        int (**write_method)())
{
    public_mib_buffer.gb_long = get_wlanChannelNumber(WLAN_5G);
    *write_method = (int (*)())&write_wlanChannelNumber_5g;
    *var_len = sizeof(long);

    return (unsigned char *)&public_mib_buffer.gb_long;
}

int write_wlanDateRate_5g(int action,
					   unsigned char *var_val, unsigned char varval_type, int var_val_len, unsigned char *statP, Oid * name)
{
	int ret = 1;

	switch (action) {
		case RESERVE1:
			break;
		case RESERVE2:
			break;
		case COMMIT:
			ret = set_wlanDateRate((int)mhtol(var_val, var_val_len), WLAN_5G);
			break;
		case ACTION:
			break;
		case FREE:
			break;
	}

	return (ret == 0) ? SNMP_ERROR_WRONGVALUE : 0;
}

unsigned char *
var_cjhvApWlanDataRate_5g(int *var_len, snmp_info_t *mesg,
        int (**write_method)())
{
    public_mib_buffer.gb_long = get_wlanDateRate(WLAN_5G);
    *write_method = (int (*)())&write_wlanDateRate_5g;
    *var_len = sizeof(long);

    return (unsigned char *)&public_mib_buffer.gb_long;
}
/* ======================= WLAN BASIC ================================= */

/* cjhvApWlanBasicConfig_tree */
static oid cjhvApWlanBasicConfig_oid[] = { O_cjhvApWlanBasicConfig };
static Object cjhvApWlanBasicConfig_variables[] = {
    { SNMP_INTEGER, (RWRITE| SCALAR), var_cjhvApWlanMode,
                 {2, { I_cjhvApWlanMode, 0 }}},
    { SNMP_INTEGER, (RWRITE| SCALAR), var_cjhvApWlanBand,
                 {2, { I_cjhvApWlanBand, 0 }}},
    { SNMP_INTEGER, (RWRITE| SCALAR), var_cjhvApWlanChannelWidth,
                 {2, { I_cjhvApWlanChannelWidth, 0 }}},
    { SNMP_INTEGER, (RWRITE| SCALAR), var_cjhvApWlanCtrlSideband,
                 {2, { I_cjhvApWlanCtrlSideband, 0 }}},
    { SNMP_INTEGER, (RWRITE| SCALAR), var_cjhvApWlanChannelNumber,
                 {2, { I_cjhvApWlanChannelNumber, 0 }}},
    { SNMP_INTEGER, (RWRITE| SCALAR), var_cjhvApWlanDataRate,
                 {2, { I_cjhvApWlanDataRate, 0 }}},
    { SNMP_INTEGER, (RWRITE| SCALAR), var_cjhvApWlanMode_5g,
                 {2, { I_cjhvApWlanMode_5G, 0 }}},
    { SNMP_INTEGER, (RWRITE| SCALAR), var_cjhvApWlanBand_5g,
                 {2, { I_cjhvApWlanBand_5G, 0 }}},
    { SNMP_INTEGER, (RWRITE| SCALAR), var_cjhvApWlanChannelWidth_5g,
                 {2, { I_cjhvApWlanChannelWidth_5G, 0 }}},
    { SNMP_INTEGER, (RWRITE| SCALAR), var_cjhvApWlanChannelNumber_5g,
                 {2, { I_cjhvApWlanChannelNumber_5G, 0 }}},
    { SNMP_INTEGER, (RWRITE| SCALAR), var_cjhvApWlanDataRate_5g,
                 {2, { I_cjhvApWlanDataRate_5G, 0 }}},
    { 0 }
    };
static SubTree cjhvApWlanBasicConfig_tree =  { NULL, cjhvApWlanBasicConfig_variables,
	        (sizeof(cjhvApWlanBasicConfig_oid)/sizeof(oid)), cjhvApWlanBasicConfig_oid};
/* cjhvApWlanBasicConfig_tree */

/* ======================= WLAN SSID CONFIG ================================= */
int write_wlanSSID(int action,
				   unsigned char *var_val, unsigned char varval_type, int var_val_len, unsigned char *statP, Oid * name)
{
	int wl_index = name->name[(name->namelen - 1)];
	int ret = 1;

	switch (action) {
		case RESERVE1:
			break;
		case RESERVE2:
			break;
		case COMMIT:
			ret = set_wlanSSID(wl_index, var_val, var_val_len);
			break;
		case ACTION:
			break;
		case FREE:
			break;
	}

	return (ret == 0) ? SNMP_ERROR_WRONGVALUE : 0;
}

int write_wlanSSIDMode(int action,
					   unsigned char *var_val, unsigned char varval_type, int var_val_len, unsigned char *statP, Oid * name)
{
	int wl_index = name->name[(name->namelen - 1)];
	int ret = 1;

	switch (action) {
		case RESERVE1:
			break;
		case RESERVE2:
			break;
		case COMMIT:
			ret = set_wlanSSIDMode(wl_index, (int)mhtol(var_val, var_val_len));
			break;
		case ACTION:
			break;
		case FREE:
			break;
	}

	return (ret == 0) ? SNMP_ERROR_WRONGVALUE : 0;
}

int write_wlanBSSID(int action,
					unsigned char *var_val, unsigned char varval_type, int var_val_len, unsigned char *statP, Oid * name)
{
	int wl_index = name->name[(name->namelen - 1)];
	int ret = 1;

	switch (action) {
		case RESERVE1:
			break;
		case RESERVE2:
			break;
		case COMMIT:
			ret = set_wlanBSSID(wl_index, (int)mhtol(var_val, var_val_len));
			break;
		case ACTION:
			break;
		case FREE:
			break;
	}

	return (ret == 0) ? SNMP_ERROR_WRONGVALUE : 0;
}

int write_wlanSecEncryption(int action,
							unsigned char *var_val, unsigned char varval_type, int var_val_len,
							unsigned char *statP, Oid * name)
{
	int wl_index = name->name[(name->namelen - 1)];
	int ret = 1;

	switch (action) {
		case RESERVE1:
			break;
		case RESERVE2:
			break;
		case COMMIT:
			ret = set_wlanSecEncryption(wl_index, (int)mhtol(var_val, var_val_len));
			break;
		case ACTION:
			break;
		case FREE:
			break;
	}

	return (ret == 0) ? SNMP_ERROR_WRONGVALUE : 0;
}

int write_WlanRateLimit(int action,
							unsigned char *var_val, unsigned char varval_type, int var_val_len,
							unsigned char *statP, Oid * name)
{
	int wl_index = name->name[(name->namelen - 1)];
	int ret = 1;

	switch (action) {
		case RESERVE1:
			break;
		case RESERVE2:
			break;
		case COMMIT:
			ret = set_wlanRateLimit(wl_index, (int)mhtol(var_val, var_val_len));
			break;
		case ACTION:
			break;
		case FREE:
			break;
	}

	return (ret == 0) ? SNMP_ERROR_WRONGVALUE : 0;
}

unsigned char *
var_cjhvApWlanSsidConfigEntry(int *var_len,
        Oid *newoid, Oid *reqoid, int searchType,
        snmp_info_t *mesg, int (**write_method)())
{
	int column = newoid->name[(newoid->namelen - 1)];
	int result;
	int index = newoid->namelen++;
	int wl_index = 0;

	while (wl_index < 8) {
		newoid->name[index] = wl_index;
		result = compare(reqoid, newoid);
		if (((searchType == EXACT) && (result == 0)) || ((searchType == NEXT) && (result < 0))) {
			break;
		}
		wl_index++;
	}

	if (wl_index >= 8) {
		return (unsigned char *)NO_MIBINSTANCE;
	}

	switch (column) {
	case I_cjhvApWlanSsidConfigIndex:
		public_mib_buffer.gb_long = wl_index + 1;
		*write_method = 0;
		*var_len = sizeof(long);
		return (unsigned char *)&public_mib_buffer.gb_long;
	case I_cjhvApWlanSSID:
		get_wlanSSID(wl_index, public_mib_buffer.gb_string, sizeof(public_mib_buffer.gb_string));
		*var_len = strlen(public_mib_buffer.gb_string);
		*write_method = (int (*)())&write_wlanSSID;
		return (unsigned char *)public_mib_buffer.gb_string;
	case I_cjhvApWlanSSIDMode:
		public_mib_buffer.gb_long = get_wlanSSIDMode(wl_index);
		*write_method = (int (*)())&write_wlanSSIDMode;
		*var_len = sizeof(long);
		return (unsigned char *)&public_mib_buffer.gb_long;
	case I_cjhvApWlanBcastSSIDMode:
		public_mib_buffer.gb_long = get_wlanBSSID(wl_index);
		*write_method = (int (*)())&write_wlanBSSID;
		*var_len = sizeof(long);
		return (unsigned char *)&public_mib_buffer.gb_long;
	case I_cjhvApWlanSecEncrytion:
		public_mib_buffer.gb_long = get_wlanSecEncryption(wl_index);
		*write_method = (int (*)())&write_wlanSecEncryption;
		*var_len = sizeof(long);
		return (unsigned char *)&public_mib_buffer.gb_long;
	case I_cjhvApWlanRateLimit:
		public_mib_buffer.gb_long = get_wlanRateLimit(wl_index);
		*write_method = (int (*)())&write_WlanRateLimit;
		*var_len = sizeof(long);
		return (unsigned char *)&public_mib_buffer.gb_long;
	default:
		return NO_MIBINSTANCE;
	}
	return NO_MIBINSTANCE;
}
/* ======================= WLAN SSID CONFIG ================================= */

/* cjhvApWlanSsidConfigEntry_tree */
static oid cjhvApWlanSsidConfigEntry_oid[] = { O_cjhvApWlanSsidConfigEntry };
static Object cjhvApWlanSsidConfigEntry_variables[] = {
    { SNMP_INTEGER, (RWRITE| COLUMN), var_cjhvApWlanSsidConfigEntry,
                {1, { I_cjhvApWlanSsidConfigIndex }}},
    { SNMP_STRING, (RWRITE| COLUMN), var_cjhvApWlanSsidConfigEntry,
                {1, { I_cjhvApWlanSSID }}},
    { SNMP_INTEGER, (RWRITE| COLUMN), var_cjhvApWlanSsidConfigEntry,
                {1, { I_cjhvApWlanSSIDMode }}},
    { SNMP_INTEGER, (RWRITE| COLUMN), var_cjhvApWlanSsidConfigEntry,
                {1, { I_cjhvApWlanBcastSSIDMode }}},
    { SNMP_INTEGER, (RWRITE| COLUMN), var_cjhvApWlanSsidConfigEntry,
                {1, { I_cjhvApWlanSecEncrytion }}},
    { SNMP_INTEGER, (RWRITE| COLUMN), var_cjhvApWlanSsidConfigEntry,
                {1, { I_cjhvApWlanRateLimit }}},
    { 0 }
    };
static SubTree cjhvApWlanSsidConfigEntry_tree =  { NULL, cjhvApWlanSsidConfigEntry_variables,
	        (sizeof(cjhvApWlanSsidConfigEntry_oid)/sizeof(oid)), cjhvApWlanSsidConfigEntry_oid};
/* cjhvApWlanSsidConfigEntry_tree */

/* ======================= DUMMY INDEX ================================= */
unsigned char *
var_cjhvApDummyIndex(int *var_len, snmp_info_t *mesg,
        int (**write_method)())
{
    public_mib_buffer.gb_long = 0;
    *write_method = NULL;
    *var_len = sizeof(long);

    return (unsigned char *)&public_mib_buffer.gb_long;
}
/* ======================= DUMMY INDEX ================================= */

/* cjhvApDummyIndex_tree */
static oid cjhvApDummyIndex_oid[] = { O_cjhvApDummyIndex };
static Object cjhvApDummyIndex_variables[] = {
    { SNMP_INTEGER, (RONLY| SCALAR), var_cjhvApDummyIndex,
                 {2, { I_cjhvApDummyIndex1, 0 }}},
    { SNMP_INTEGER, (RONLY| SCALAR), var_cjhvApDummyIndex,
                 {2, { I_cjhvApDummyIndex2, 0 }}},
    { SNMP_INTEGER, (RONLY| SCALAR), var_cjhvApDummyIndex,
                 {2, { I_cjhvApDummyIndex3, 0 }}},
    { SNMP_INTEGER, (RONLY| SCALAR), var_cjhvApDummyIndex,
                 {2, { I_cjhvApDummyIndex4, 0 }}},
    { SNMP_INTEGER, (RONLY| SCALAR), var_cjhvApDummyIndex,
                 {2, { I_cjhvApDummyIndex5, 0 }}},
    { SNMP_INTEGER, (RONLY| SCALAR), var_cjhvApDummyIndex,
                 {2, { I_cjhvApDummyIndex6, 0 }}},
    { SNMP_INTEGER, (RONLY| SCALAR), var_cjhvApDummyIndex,
                 {2, { I_cjhvApDummyIndex7, 0 }}},
    { SNMP_INTEGER, (RONLY| SCALAR), var_cjhvApDummyIndex,
                 {2, { I_cjhvApDummyIndex8, 0 }}},
    { SNMP_INTEGER, (RONLY| SCALAR), var_cjhvApDummyIndex,
                 {2, { I_cjhvApDummyIndex9, 0 }}},
    { SNMP_INTEGER, (RONLY| SCALAR), var_cjhvApDummyIndex,
                 {2, { I_cjhvApDummyIndex10, 0 }}},
    { 0 }
    };
static SubTree cjhvApDummyIndex_tree =  { NULL, cjhvApDummyIndex_variables,
	        (sizeof(cjhvApDummyIndex_oid)/sizeof(oid)), cjhvApDummyIndex_oid};
/* cjhvApDummyIndex_tree */

/* ======================= SITE SURVEY INFO ================================= */
unsigned char *var_cjhvApWlanAdjacentChannelEntry(int *var_len,
                                        Oid * newoid, Oid * reqoid, int searchType, snmp_info_t * mesg, int (**write_method) ())
{
    int column = newoid->name[(newoid->namelen - 1)];
    int result;
    int ii = newoid->namelen++;
    int idx = 0;
    static int scan = -1;
    static int scan_num = -1;
    static int count = 0;

	if(scan == - 1 ) {
    	if(get_wlanMode(WLAN_2G) == 1) {
			if (surveyRequest(WLAN_2G) < 0)
				return NO_MIBINSTANCE;
			scan_num = getWlanScanInfo(WLAN_2G);
		}
    	scan = 0;
    }

    if (scan_num == -1) {
      	scan = -1;
        return NO_MIBINSTANCE;
    }

    while (idx + 1 <= scan_num) {
        newoid->name[ii] = idx;
        result = compare(reqoid, newoid);
        if (((searchType == EXACT) && (result == 0)) || ((searchType == NEXT) && (result < 0))) {
            break;
        }
        idx++;
    }

	if (idx + 1 > scan_num) {
		if(count >= scan_num){
			count = 0;
			scan = -1;
		}
		return NO_MIBINSTANCE;
	}

	switch(column) {
		case I_cjhvApWlanAdjacentChannelIndex:
		{
			public_mib_buffer.gb_long = idx + 1;
			*var_len = sizeof(long);
			return (unsigned char *)&public_mib_buffer.gb_long;
		}
		case I_cjhvApWlanAdjacentChannelNumber:
		{
			public_mib_buffer.gb_long = idx + 1;
			*var_len = sizeof(long);
			return (unsigned char *)&public_mib_buffer.gb_long;
		}
		case I_cjhvApWlanAdjacentChannelCount:
		{
			public_mib_buffer.gb_long = adjacent_channel[idx];
			count++;
			if (count > scan_num)
				count = scan_num;
			*var_len = sizeof(long);
			return (unsigned char *)&public_mib_buffer.gb_long;
		}
		default:
		{
			return (unsigned char *)NO_MIBINSTANCE;
		}
	}
	return NO_MIBINSTANCE;
}

int write_wlanBestChannel(int action,
					   unsigned char *var_val, unsigned char varval_type, int var_val_len, unsigned char *statP, Oid * name)
{
	int ret = 1;

	switch (action) {
		case RESERVE1:
			break;
		case RESERVE2:
			break;
		case COMMIT:
			ret = set_BestChannelAlgorithm(WLAN_2G, (int)mhtol(var_val, var_val_len));
			break;
		case ACTION:
			break;
		case FREE:
			break;
	}

	return (ret == 0) ? SNMP_ERROR_WRONGVALUE : 0;
}

unsigned char *
var_I_cjhvApBestChannelAlgorithm(int *var_len, snmp_info_t *mesg,
        int (**write_method)())
{

   	public_mib_buffer.gb_long = get_BestChannelAlgorithm();
   	*write_method = (int (*)())&write_wlanBestChannel;
   	*var_len = sizeof(long);

    return (unsigned char *)&public_mib_buffer.gb_long;
}

/* ======================= SITE SURVEY INFO ================================= */

/* cjhvApWlanAdjacentChannelEntry_tree */
static oid cjhvApWlanAdjacentChannelEntry_oid[] = { O_cjhvApWlanAdjacentChannel };
static Object cjhvApWlanAdjacentChannelEntry_variables[] = {
    { SNMP_INTEGER, (RONLY| COLUMN), var_cjhvApWlanAdjacentChannelEntry,
                {3, { I_cjhvApWlanAdjacentChannelTable, I_cjhvApWlanAdjacentChannelEntry, I_cjhvApWlanAdjacentChannelIndex }}},
    { SNMP_INTEGER, (RWRITE| COLUMN), var_cjhvApWlanAdjacentChannelEntry,
                {3, { I_cjhvApWlanAdjacentChannelTable, I_cjhvApWlanAdjacentChannelEntry, I_cjhvApWlanAdjacentChannelNumber }}},
    { SNMP_INTEGER, (RWRITE| COLUMN), var_cjhvApWlanAdjacentChannelEntry,
                {3, { I_cjhvApWlanAdjacentChannelTable, I_cjhvApWlanAdjacentChannelEntry, I_cjhvApWlanAdjacentChannelCount }}},
	{ SNMP_INTEGER, (RWRITE| SCALAR), var_I_cjhvApBestChannelAlgorithm,
                {2, { I_cjhvApBestChannelAlgorithm, 0 }}},
    { 0 }
    };

static SubTree cjhvApWlanAdjacentChannelEntry_tree =  { NULL, cjhvApWlanAdjacentChannelEntry_variables,
	        (sizeof(cjhvApWlanAdjacentChannelEntry_oid)/sizeof(oid)), cjhvApWlanAdjacentChannelEntry_oid};
/* cjhvApWlanAdjacentChannelEntry_tree */

/* ======================= CHANNEL TRAP INFO ================================= */
unsigned char *
var_cjhvApWlanAdjacentChannelTrap(int *var_len, snmp_info_t *mesg,
        int (**write_method)())
{
    public_mib_buffer.gb_long = 1;
    *write_method = NULL;
    *var_len = sizeof(long);

    return (unsigned char *)&public_mib_buffer.gb_long;
}
/* ======================= CHANNEL TRAP INFO ================================= */

/* cjhvApWlanAdjacentChannelTrap_tree */
static oid cjhvApWlanAdjacentChannelTrap1_oid[] = { O_cjhvApWlanAdjacentChannelTrap1 };
static Object cjhvApWlanAdjacentChannelTrap1_variables[] = {
    { SNMP_INTEGER, (RONLY| SCALAR), var_cjhvApWlanAdjacentChannelTrap,
                 {2, { I_cjhvApWlanAdjacentChannelTrapIndex1, 0 }}},
    { SNMP_INTEGER, (RWRITE| SCALAR), var_cjhvApWlanAdjacentChannelTrap,
                 {2, { I_cjhvApWlanAdjacentChannelTrapNumber1, 0 }}},
    { SNMP_INTEGER, (RWRITE| SCALAR), var_cjhvApWlanAdjacentChannelTrap,
                 {2, { I_cjhvApWlanAdjacentChannelTrapCount1, 0 }}},
    { 0 }
    };
static SubTree cjhvApWlanAdjacentChannelTrap1_tree =  { NULL, cjhvApWlanAdjacentChannelTrap1_variables,
	        (sizeof(cjhvApWlanAdjacentChannelTrap1_oid)/sizeof(oid)), cjhvApWlanAdjacentChannelTrap1_oid};

static oid cjhvApWlanAdjacentChannelTrap2_oid[] = { O_cjhvApWlanAdjacentChannelTrap2 };
static Object cjhvApWlanAdjacentChannelTrap2_variables[] = {
    { SNMP_INTEGER, (RONLY| SCALAR), var_cjhvApWlanAdjacentChannelTrap,
                 {2, { I_cjhvApWlanAdjacentChannelTrapIndex2, 0 }}},
    { SNMP_INTEGER, (RWRITE| SCALAR), var_cjhvApWlanAdjacentChannelTrap,
                 {2, { I_cjhvApWlanAdjacentChannelTrapNumber2, 0 }}},
    { SNMP_INTEGER, (RWRITE| SCALAR), var_cjhvApWlanAdjacentChannelTrap,
                 {2, { I_cjhvApWlanAdjacentChannelTrapCount2, 0 }}},
    { 0 }
    };
static SubTree cjhvApWlanAdjacentChannelTrap2_tree =  { NULL, cjhvApWlanAdjacentChannelTrap2_variables,
	        (sizeof(cjhvApWlanAdjacentChannelTrap2_oid)/sizeof(oid)), cjhvApWlanAdjacentChannelTrap2_oid};

static oid cjhvApWlanAdjacentChannelTrap3_oid[] = { O_cjhvApWlanAdjacentChannelTrap3 };
static Object cjhvApWlanAdjacentChannelTrap3_variables[] = {
    { SNMP_INTEGER, (RONLY| SCALAR), var_cjhvApWlanAdjacentChannelTrap,
                 {2, { I_cjhvApWlanAdjacentChannelTrapIndex3, 0 }}},
    { SNMP_INTEGER, (RWRITE| SCALAR), var_cjhvApWlanAdjacentChannelTrap,
                 {2, { I_cjhvApWlanAdjacentChannelTrapNumber3, 0 }}},
    { SNMP_INTEGER, (RWRITE| SCALAR), var_cjhvApWlanAdjacentChannelTrap,
                 {2, { I_cjhvApWlanAdjacentChannelTrapCount3, 0 }}},
    { 0 }
    };
static SubTree cjhvApWlanAdjacentChannelTrap3_tree =  { NULL, cjhvApWlanAdjacentChannelTrap3_variables,
	        (sizeof(cjhvApWlanAdjacentChannelTrap3_oid)/sizeof(oid)), cjhvApWlanAdjacentChannelTrap3_oid};

static oid cjhvApWlanAdjacentChannelTrap4_oid[] = { O_cjhvApWlanAdjacentChannelTrap4 };
static Object cjhvApWlanAdjacentChannelTrap4_variables[] = {
    { SNMP_INTEGER, (RONLY| SCALAR), var_cjhvApWlanAdjacentChannelTrap,
                 {2, { I_cjhvApWlanAdjacentChannelTrapIndex4, 0 }}},
    { SNMP_INTEGER, (RWRITE| SCALAR), var_cjhvApWlanAdjacentChannelTrap,
                 {2, { I_cjhvApWlanAdjacentChannelTrapNumber4, 0 }}},
    { SNMP_INTEGER, (RWRITE| SCALAR), var_cjhvApWlanAdjacentChannelTrap,
                 {2, { I_cjhvApWlanAdjacentChannelTrapCount4, 0 }}},
    { 0 }
    };
static SubTree cjhvApWlanAdjacentChannelTrap4_tree =  { NULL, cjhvApWlanAdjacentChannelTrap4_variables,
	        (sizeof(cjhvApWlanAdjacentChannelTrap4_oid)/sizeof(oid)), cjhvApWlanAdjacentChannelTrap4_oid};

static oid cjhvApWlanAdjacentChannelTrap5_oid[] = { O_cjhvApWlanAdjacentChannelTrap5 };
static Object cjhvApWlanAdjacentChannelTrap5_variables[] = {
    { SNMP_INTEGER, (RONLY| SCALAR), var_cjhvApWlanAdjacentChannelTrap,
                 {2, { I_cjhvApWlanAdjacentChannelTrapIndex5, 0 }}},
    { SNMP_INTEGER, (RWRITE| SCALAR), var_cjhvApWlanAdjacentChannelTrap,
                 {2, { I_cjhvApWlanAdjacentChannelTrapNumber5, 0 }}},
    { SNMP_INTEGER, (RWRITE| SCALAR), var_cjhvApWlanAdjacentChannelTrap,
                 {2, { I_cjhvApWlanAdjacentChannelTrapCount5, 0 }}},
    { 0 }
    };
static SubTree cjhvApWlanAdjacentChannelTrap5_tree =  { NULL, cjhvApWlanAdjacentChannelTrap5_variables,
	        (sizeof(cjhvApWlanAdjacentChannelTrap5_oid)/sizeof(oid)), cjhvApWlanAdjacentChannelTrap5_oid};

static oid cjhvApWlanAdjacentChannelTrap6_oid[] = { O_cjhvApWlanAdjacentChannelTrap6 };
static Object cjhvApWlanAdjacentChannelTrap6_variables[] = {
    { SNMP_INTEGER, (RONLY| SCALAR), var_cjhvApWlanAdjacentChannelTrap,
                 {2, { I_cjhvApWlanAdjacentChannelTrapIndex6, 0 }}},
    { SNMP_INTEGER, (RWRITE| SCALAR), var_cjhvApWlanAdjacentChannelTrap,
                 {2, { I_cjhvApWlanAdjacentChannelTrapNumber6, 0 }}},
    { SNMP_INTEGER, (RWRITE| SCALAR), var_cjhvApWlanAdjacentChannelTrap,
                 {2, { I_cjhvApWlanAdjacentChannelTrapCount6, 0 }}},
    { 0 }
    };
static SubTree cjhvApWlanAdjacentChannelTrap6_tree =  { NULL, cjhvApWlanAdjacentChannelTrap6_variables,
	        (sizeof(cjhvApWlanAdjacentChannelTrap6_oid)/sizeof(oid)), cjhvApWlanAdjacentChannelTrap6_oid};

static oid cjhvApWlanAdjacentChannelTrap7_oid[] = { O_cjhvApWlanAdjacentChannelTrap7 };
static Object cjhvApWlanAdjacentChannelTrap7_variables[] = {
    { SNMP_INTEGER, (RONLY| SCALAR), var_cjhvApWlanAdjacentChannelTrap,
                 {2, { I_cjhvApWlanAdjacentChannelTrapIndex7, 0 }}},
    { SNMP_INTEGER, (RWRITE| SCALAR), var_cjhvApWlanAdjacentChannelTrap,
                 {2, { I_cjhvApWlanAdjacentChannelTrapNumber7, 0 }}},
    { SNMP_INTEGER, (RWRITE| SCALAR), var_cjhvApWlanAdjacentChannelTrap,
                 {2, { I_cjhvApWlanAdjacentChannelTrapCount7, 0 }}},
    { 0 }
    };
static SubTree cjhvApWlanAdjacentChannelTrap7_tree =  { NULL, cjhvApWlanAdjacentChannelTrap7_variables,
	        (sizeof(cjhvApWlanAdjacentChannelTrap7_oid)/sizeof(oid)), cjhvApWlanAdjacentChannelTrap7_oid};

static oid cjhvApWlanAdjacentChannelTrap8_oid[] = { O_cjhvApWlanAdjacentChannelTrap8 };
static Object cjhvApWlanAdjacentChannelTrap8_variables[] = {
    { SNMP_INTEGER, (RONLY| SCALAR), var_cjhvApWlanAdjacentChannelTrap,
                 {2, { I_cjhvApWlanAdjacentChannelTrapIndex8, 0 }}},
    { SNMP_INTEGER, (RWRITE| SCALAR), var_cjhvApWlanAdjacentChannelTrap,
                 {2, { I_cjhvApWlanAdjacentChannelTrapNumber8, 0 }}},
    { SNMP_INTEGER, (RWRITE| SCALAR), var_cjhvApWlanAdjacentChannelTrap,
                 {2, { I_cjhvApWlanAdjacentChannelTrapCount8, 0 }}},
    { 0 }
    };
static SubTree cjhvApWlanAdjacentChannelTrap8_tree =  { NULL, cjhvApWlanAdjacentChannelTrap8_variables,
	        (sizeof(cjhvApWlanAdjacentChannelTrap8_oid)/sizeof(oid)), cjhvApWlanAdjacentChannelTrap8_oid};

static oid cjhvApWlanAdjacentChannelTrap9_oid[] = { O_cjhvApWlanAdjacentChannelTrap9 };
static Object cjhvApWlanAdjacentChannelTrap9_variables[] = {
    { SNMP_INTEGER, (RONLY| SCALAR), var_cjhvApWlanAdjacentChannelTrap,
                 {2, { I_cjhvApWlanAdjacentChannelTrapIndex9, 0 }}},
    { SNMP_INTEGER, (RWRITE| SCALAR), var_cjhvApWlanAdjacentChannelTrap,
                 {2, { I_cjhvApWlanAdjacentChannelTrapNumber9, 0 }}},
    { SNMP_INTEGER, (RWRITE| SCALAR), var_cjhvApWlanAdjacentChannelTrap,
                 {2, { I_cjhvApWlanAdjacentChannelTrapCount9, 0 }}},
    { 0 }
    };
static SubTree cjhvApWlanAdjacentChannelTrap9_tree =  { NULL, cjhvApWlanAdjacentChannelTrap9_variables,
	        (sizeof(cjhvApWlanAdjacentChannelTrap9_oid)/sizeof(oid)), cjhvApWlanAdjacentChannelTrap9_oid};

static oid cjhvApWlanAdjacentChannelTrap10_oid[] = { O_cjhvApWlanAdjacentChannelTrap10 };
static Object cjhvApWlanAdjacentChannelTrap10_variables[] = {
    { SNMP_INTEGER, (RONLY| SCALAR), var_cjhvApWlanAdjacentChannelTrap,
                 {2, { I_cjhvApWlanAdjacentChannelTrapIndex10, 0 }}},
    { SNMP_INTEGER, (RWRITE| SCALAR), var_cjhvApWlanAdjacentChannelTrap,
                 {2, { I_cjhvApWlanAdjacentChannelTrapNumber10, 0 }}},
    { SNMP_INTEGER, (RWRITE| SCALAR), var_cjhvApWlanAdjacentChannelTrap,
                 {2, { I_cjhvApWlanAdjacentChannelTrapCount10, 0 }}},
    { 0 }
    };
static SubTree cjhvApWlanAdjacentChannelTrap10_tree =  { NULL, cjhvApWlanAdjacentChannelTrap10_variables,
	        (sizeof(cjhvApWlanAdjacentChannelTrap10_oid)/sizeof(oid)), cjhvApWlanAdjacentChannelTrap10_oid};

static oid cjhvApWlanAdjacentChannelTrap11_oid[] = { O_cjhvApWlanAdjacentChannelTrap11 };
static Object cjhvApWlanAdjacentChannelTrap11_variables[] = {
    { SNMP_INTEGER, (RONLY| SCALAR), var_cjhvApWlanAdjacentChannelTrap,
                 {2, { I_cjhvApWlanAdjacentChannelTrapIndex11, 0 }}},
    { SNMP_INTEGER, (RWRITE| SCALAR), var_cjhvApWlanAdjacentChannelTrap,
                 {2, { I_cjhvApWlanAdjacentChannelTrapNumber11, 0 }}},
    { SNMP_INTEGER, (RWRITE| SCALAR), var_cjhvApWlanAdjacentChannelTrap,
                 {2, { I_cjhvApWlanAdjacentChannelTrapCount11, 0 }}},
    { 0 }
    };
static SubTree cjhvApWlanAdjacentChannelTrap11_tree =  { NULL, cjhvApWlanAdjacentChannelTrap11_variables,
	        (sizeof(cjhvApWlanAdjacentChannelTrap11_oid)/sizeof(oid)), cjhvApWlanAdjacentChannelTrap11_oid};

static oid cjhvApWlanAdjacentChannelTrap12_oid[] = { O_cjhvApWlanAdjacentChannelTrap12 };
static Object cjhvApWlanAdjacentChannelTrap12_variables[] = {
    { SNMP_INTEGER, (RONLY| SCALAR), var_cjhvApWlanAdjacentChannelTrap,
                 {2, { I_cjhvApWlanAdjacentChannelTrapIndex12, 0 }}},
    { SNMP_INTEGER, (RWRITE| SCALAR), var_cjhvApWlanAdjacentChannelTrap,
                 {2, { I_cjhvApWlanAdjacentChannelTrapNumber12, 0 }}},
    { SNMP_INTEGER, (RWRITE| SCALAR), var_cjhvApWlanAdjacentChannelTrap,
                 {2, { I_cjhvApWlanAdjacentChannelTrapCount12, 0 }}},
    { 0 }
    };
static SubTree cjhvApWlanAdjacentChannelTrap12_tree =  { NULL, cjhvApWlanAdjacentChannelTrap12_variables,
	        (sizeof(cjhvApWlanAdjacentChannelTrap12_oid)/sizeof(oid)), cjhvApWlanAdjacentChannelTrap12_oid};

static oid cjhvApWlanAdjacentChannelTrap13_oid[] = { O_cjhvApWlanAdjacentChannelTrap13 };
static Object cjhvApWlanAdjacentChannelTrap13_variables[] = {
    { SNMP_INTEGER, (RONLY| SCALAR), var_cjhvApWlanAdjacentChannelTrap,
                 {2, { I_cjhvApWlanAdjacentChannelTrapIndex13, 0 }}},
    { SNMP_INTEGER, (RWRITE| SCALAR), var_cjhvApWlanAdjacentChannelTrap,
                 {2, { I_cjhvApWlanAdjacentChannelTrapNumber13, 0 }}},
    { SNMP_INTEGER, (RWRITE| SCALAR), var_cjhvApWlanAdjacentChannelTrap,
                 {2, { I_cjhvApWlanAdjacentChannelTrapCount13, 0 }}},
    { 0 }
    };
static SubTree cjhvApWlanAdjacentChannelTrap13_tree =  { NULL, cjhvApWlanAdjacentChannelTrap13_variables,
	        (sizeof(cjhvApWlanAdjacentChannelTrap13_oid)/sizeof(oid)), cjhvApWlanAdjacentChannelTrap13_oid};

static oid cjhvApWlanAdjacentChannelTrap14_oid[] = { O_cjhvApWlanAdjacentChannelTrap14 };
static Object cjhvApWlanAdjacentChannelTrap14_variables[] = {
    { SNMP_INTEGER, (RONLY| SCALAR), var_cjhvApWlanAdjacentChannelTrap,
                 {2, { I_cjhvApWlanAdjacentChannelTrapIndex14, 0 }}},
    { SNMP_INTEGER, (RWRITE| SCALAR), var_cjhvApWlanAdjacentChannelTrap,
                 {2, { I_cjhvApWlanAdjacentChannelTrapNumber14, 0 }}},
    { SNMP_INTEGER, (RWRITE| SCALAR), var_cjhvApWlanAdjacentChannelTrap,
                 {2, { I_cjhvApWlanAdjacentChannelTrapCount14, 0 }}},
    { 0 }
    };
static SubTree cjhvApWlanAdjacentChannelTrap14_tree =  { NULL, cjhvApWlanAdjacentChannelTrap14_variables,
	        (sizeof(cjhvApWlanAdjacentChannelTrap14_oid)/sizeof(oid)), cjhvApWlanAdjacentChannelTrap14_oid};

static oid cjhvApWlanAdjacentChannelTrap15_oid[] = { O_cjhvApWlanAdjacentChannelTrap15 };
static Object cjhvApWlanAdjacentChannelTrap15_variables[] = {
    { SNMP_INTEGER, (RONLY| SCALAR), var_cjhvApWlanAdjacentChannelTrap,
                 {2, { I_cjhvApWlanAdjacentChannelTrapIndex15, 0 }}},
    { SNMP_INTEGER, (RWRITE| SCALAR), var_cjhvApWlanAdjacentChannelTrap,
                 {2, { I_cjhvApWlanAdjacentChannelTrapNumber15, 0 }}},
    { SNMP_INTEGER, (RWRITE| SCALAR), var_cjhvApWlanAdjacentChannelTrap,
                 {2, { I_cjhvApWlanAdjacentChannelTrapCount15, 0 }}},
    { 0 }
    };
static SubTree cjhvApWlanAdjacentChannelTrap15_tree =  { NULL, cjhvApWlanAdjacentChannelTrap15_variables,
	        (sizeof(cjhvApWlanAdjacentChannelTrap15_oid)/sizeof(oid)), cjhvApWlanAdjacentChannelTrap15_oid};

static oid cjhvApWlanAdjacentChannelTrap16_oid[] = { O_cjhvApWlanAdjacentChannelTrap16 };
static Object cjhvApWlanAdjacentChannelTrap16_variables[] = {
    { SNMP_INTEGER, (RONLY| SCALAR), var_cjhvApWlanAdjacentChannelTrap,
                 {2, { I_cjhvApWlanAdjacentChannelTrapIndex16, 0 }}},
    { SNMP_INTEGER, (RWRITE| SCALAR), var_cjhvApWlanAdjacentChannelTrap,
                 {2, { I_cjhvApWlanAdjacentChannelTrapNumber16, 0 }}},
    { SNMP_INTEGER, (RWRITE| SCALAR), var_cjhvApWlanAdjacentChannelTrap,
                 {2, { I_cjhvApWlanAdjacentChannelTrapCount16, 0 }}},
    { 0 }
    };
static SubTree cjhvApWlanAdjacentChannelTrap16_tree =  { NULL, cjhvApWlanAdjacentChannelTrap16_variables,
	        (sizeof(cjhvApWlanAdjacentChannelTrap16_oid)/sizeof(oid)), cjhvApWlanAdjacentChannelTrap16_oid};

static oid cjhvApWlanAdjacentChannelTrap17_oid[] = { O_cjhvApWlanAdjacentChannelTrap17 };
static Object cjhvApWlanAdjacentChannelTrap17_variables[] = {
    { SNMP_INTEGER, (RONLY| SCALAR), var_cjhvApWlanAdjacentChannelTrap,
                 {2, { I_cjhvApWlanAdjacentChannelTrapIndex17, 0 }}},
    { SNMP_INTEGER, (RWRITE| SCALAR), var_cjhvApWlanAdjacentChannelTrap,
                 {2, { I_cjhvApWlanAdjacentChannelTrapNumber17, 0 }}},
    { SNMP_INTEGER, (RWRITE| SCALAR), var_cjhvApWlanAdjacentChannelTrap,
                 {2, { I_cjhvApWlanAdjacentChannelTrapCount17, 0 }}},
    { 0 }
    };
static SubTree cjhvApWlanAdjacentChannelTrap17_tree =  { NULL, cjhvApWlanAdjacentChannelTrap17_variables,
	        (sizeof(cjhvApWlanAdjacentChannelTrap17_oid)/sizeof(oid)), cjhvApWlanAdjacentChannelTrap17_oid};

static oid cjhvApWlanAdjacentChannelTrap18_oid[] = { O_cjhvApWlanAdjacentChannelTrap18 };
static Object cjhvApWlanAdjacentChannelTrap18_variables[] = {
    { SNMP_INTEGER, (RONLY| SCALAR), var_cjhvApWlanAdjacentChannelTrap,
                 {2, { I_cjhvApWlanAdjacentChannelTrapIndex18, 0 }}},
    { SNMP_INTEGER, (RWRITE| SCALAR), var_cjhvApWlanAdjacentChannelTrap,
                 {2, { I_cjhvApWlanAdjacentChannelTrapNumber18, 0 }}},
    { SNMP_INTEGER, (RWRITE| SCALAR), var_cjhvApWlanAdjacentChannelTrap,
                 {2, { I_cjhvApWlanAdjacentChannelTrapCount18, 0 }}},
    { 0 }
    };
static SubTree cjhvApWlanAdjacentChannelTrap18_tree =  { NULL, cjhvApWlanAdjacentChannelTrap18_variables,
	        (sizeof(cjhvApWlanAdjacentChannelTrap18_oid)/sizeof(oid)), cjhvApWlanAdjacentChannelTrap18_oid};

static oid cjhvApWlanAdjacentChannelTrap19_oid[] = { O_cjhvApWlanAdjacentChannelTrap19 };
static Object cjhvApWlanAdjacentChannelTrap19_variables[] = {
    { SNMP_INTEGER, (RONLY| SCALAR), var_cjhvApWlanAdjacentChannelTrap,
                 {2, { I_cjhvApWlanAdjacentChannelTrapIndex19, 0 }}},
    { SNMP_INTEGER, (RWRITE| SCALAR), var_cjhvApWlanAdjacentChannelTrap,
                 {2, { I_cjhvApWlanAdjacentChannelTrapNumber19, 0 }}},
    { SNMP_INTEGER, (RWRITE| SCALAR), var_cjhvApWlanAdjacentChannelTrap,
                 {2, { I_cjhvApWlanAdjacentChannelTrapCount19, 0 }}},
    { 0 }
    };
static SubTree cjhvApWlanAdjacentChannelTrap19_tree =  { NULL, cjhvApWlanAdjacentChannelTrap19_variables,
	        (sizeof(cjhvApWlanAdjacentChannelTrap19_oid)/sizeof(oid)), cjhvApWlanAdjacentChannelTrap19_oid};

static oid cjhvApWlanAdjacentChannelTrap20_oid[] = { O_cjhvApWlanAdjacentChannelTrap20 };
static Object cjhvApWlanAdjacentChannelTrap20_variables[] = {
    { SNMP_INTEGER, (RONLY| SCALAR), var_cjhvApWlanAdjacentChannelTrap,
                 {2, { I_cjhvApWlanAdjacentChannelTrapIndex20, 0 }}},
    { SNMP_INTEGER, (RWRITE| SCALAR), var_cjhvApWlanAdjacentChannelTrap,
                 {2, { I_cjhvApWlanAdjacentChannelTrapNumber20, 0 }}},
    { SNMP_INTEGER, (RWRITE| SCALAR), var_cjhvApWlanAdjacentChannelTrap,
                 {2, { I_cjhvApWlanAdjacentChannelTrapCount20, 0 }}},
    { 0 }
    };
static SubTree cjhvApWlanAdjacentChannelTrap20_tree =  { NULL, cjhvApWlanAdjacentChannelTrap20_variables,
	        (sizeof(cjhvApWlanAdjacentChannelTrap20_oid)/sizeof(oid)), cjhvApWlanAdjacentChannelTrap20_oid};

static oid cjhvApWlanAdjacentChannelTrap21_oid[] = { O_cjhvApWlanAdjacentChannelTrap21 };
static Object cjhvApWlanAdjacentChannelTrap21_variables[] = {
    { SNMP_INTEGER, (RONLY| SCALAR), var_cjhvApWlanAdjacentChannelTrap,
                 {2, { I_cjhvApWlanAdjacentChannelTrapIndex21, 0 }}},
    { SNMP_INTEGER, (RWRITE| SCALAR), var_cjhvApWlanAdjacentChannelTrap,
                 {2, { I_cjhvApWlanAdjacentChannelTrapNumber21, 0 }}},
    { SNMP_INTEGER, (RWRITE| SCALAR), var_cjhvApWlanAdjacentChannelTrap,
                 {2, { I_cjhvApWlanAdjacentChannelTrapCount21, 0 }}},
    { 0 }
    };
static SubTree cjhvApWlanAdjacentChannelTrap21_tree =  { NULL, cjhvApWlanAdjacentChannelTrap21_variables,
	        (sizeof(cjhvApWlanAdjacentChannelTrap21_oid)/sizeof(oid)), cjhvApWlanAdjacentChannelTrap21_oid};

static oid cjhvApWlanAdjacentChannelTrap22_oid[] = { O_cjhvApWlanAdjacentChannelTrap22 };
static Object cjhvApWlanAdjacentChannelTrap22_variables[] = {
    { SNMP_INTEGER, (RONLY| SCALAR), var_cjhvApWlanAdjacentChannelTrap,
                 {2, { I_cjhvApWlanAdjacentChannelTrapIndex22, 0 }}},
    { SNMP_INTEGER, (RWRITE| SCALAR), var_cjhvApWlanAdjacentChannelTrap,
                 {2, { I_cjhvApWlanAdjacentChannelTrapNumber22, 0 }}},
    { SNMP_INTEGER, (RWRITE| SCALAR), var_cjhvApWlanAdjacentChannelTrap,
                 {2, { I_cjhvApWlanAdjacentChannelTrapCount22, 0 }}},
    { 0 }
    };
static SubTree cjhvApWlanAdjacentChannelTrap22_tree =  { NULL, cjhvApWlanAdjacentChannelTrap22_variables,
	        (sizeof(cjhvApWlanAdjacentChannelTrap22_oid)/sizeof(oid)), cjhvApWlanAdjacentChannelTrap22_oid};

static oid cjhvApWlanAdjacentChannelTrap23_oid[] = { O_cjhvApWlanAdjacentChannelTrap23 };
static Object cjhvApWlanAdjacentChannelTrap23_variables[] = {
    { SNMP_INTEGER, (RONLY| SCALAR), var_cjhvApWlanAdjacentChannelTrap,
                 {2, { I_cjhvApWlanAdjacentChannelTrapIndex23, 0 }}},
    { SNMP_INTEGER, (RWRITE| SCALAR), var_cjhvApWlanAdjacentChannelTrap,
                 {2, { I_cjhvApWlanAdjacentChannelTrapNumber23, 0 }}},
    { SNMP_INTEGER, (RWRITE| SCALAR), var_cjhvApWlanAdjacentChannelTrap,
                 {2, { I_cjhvApWlanAdjacentChannelTrapCount23, 0 }}},
    { 0 }
    };
static SubTree cjhvApWlanAdjacentChannelTrap23_tree =  { NULL, cjhvApWlanAdjacentChannelTrap23_variables,
	        (sizeof(cjhvApWlanAdjacentChannelTrap23_oid)/sizeof(oid)), cjhvApWlanAdjacentChannelTrap23_oid};

static oid cjhvApWlanAdjacentChannelTrap24_oid[] = { O_cjhvApWlanAdjacentChannelTrap24 };
static Object cjhvApWlanAdjacentChannelTrap24_variables[] = {
    { SNMP_INTEGER, (RONLY| SCALAR), var_cjhvApWlanAdjacentChannelTrap,
                 {2, { I_cjhvApWlanAdjacentChannelTrapIndex24, 0 }}},
    { SNMP_INTEGER, (RWRITE| SCALAR), var_cjhvApWlanAdjacentChannelTrap,
                 {2, { I_cjhvApWlanAdjacentChannelTrapNumber24, 0 }}},
    { SNMP_INTEGER, (RWRITE| SCALAR), var_cjhvApWlanAdjacentChannelTrap,
                 {2, { I_cjhvApWlanAdjacentChannelTrapCount24, 0 }}},
    { 0 }
    };
static SubTree cjhvApWlanAdjacentChannelTrap24_tree =  { NULL, cjhvApWlanAdjacentChannelTrap24_variables,
	        (sizeof(cjhvApWlanAdjacentChannelTrap24_oid)/sizeof(oid)), cjhvApWlanAdjacentChannelTrap24_oid};

static oid cjhvApWlanAdjacentChannelTrap25_oid[] = { O_cjhvApWlanAdjacentChannelTrap25 };
static Object cjhvApWlanAdjacentChannelTrap25_variables[] = {
    { SNMP_INTEGER, (RONLY| SCALAR), var_cjhvApWlanAdjacentChannelTrap,
                 {2, { I_cjhvApWlanAdjacentChannelTrapIndex25, 0 }}},
    { SNMP_INTEGER, (RWRITE| SCALAR), var_cjhvApWlanAdjacentChannelTrap,
                 {2, { I_cjhvApWlanAdjacentChannelTrapNumber25, 0 }}},
    { SNMP_INTEGER, (RWRITE| SCALAR), var_cjhvApWlanAdjacentChannelTrap,
                 {2, { I_cjhvApWlanAdjacentChannelTrapCount25, 0 }}},
    { 0 }
    };
static SubTree cjhvApWlanAdjacentChannelTrap25_tree =  { NULL, cjhvApWlanAdjacentChannelTrap25_variables,
	        (sizeof(cjhvApWlanAdjacentChannelTrap25_oid)/sizeof(oid)), cjhvApWlanAdjacentChannelTrap25_oid};

static oid cjhvApWlanAdjacentChannelTrap26_oid[] = { O_cjhvApWlanAdjacentChannelTrap26 };
static Object cjhvApWlanAdjacentChannelTrap26_variables[] = {
    { SNMP_INTEGER, (RONLY| SCALAR), var_cjhvApWlanAdjacentChannelTrap,
                 {2, { I_cjhvApWlanAdjacentChannelTrapIndex26, 0 }}},
    { SNMP_INTEGER, (RWRITE| SCALAR), var_cjhvApWlanAdjacentChannelTrap,
                 {2, { I_cjhvApWlanAdjacentChannelTrapNumber26, 0 }}},
    { SNMP_INTEGER, (RWRITE| SCALAR), var_cjhvApWlanAdjacentChannelTrap,
                 {2, { I_cjhvApWlanAdjacentChannelTrapCount26, 0 }}},
    { 0 }
    };
static SubTree cjhvApWlanAdjacentChannelTrap26_tree =  { NULL, cjhvApWlanAdjacentChannelTrap26_variables,
	        (sizeof(cjhvApWlanAdjacentChannelTrap26_oid)/sizeof(oid)), cjhvApWlanAdjacentChannelTrap26_oid};

static oid cjhvApWlanAdjacentChannelTrap27_oid[] = { O_cjhvApWlanAdjacentChannelTrap27 };
static Object cjhvApWlanAdjacentChannelTrap27_variables[] = {
    { SNMP_INTEGER, (RONLY| SCALAR), var_cjhvApWlanAdjacentChannelTrap,
                 {2, { I_cjhvApWlanAdjacentChannelTrapIndex27, 0 }}},
    { SNMP_INTEGER, (RWRITE| SCALAR), var_cjhvApWlanAdjacentChannelTrap,
                 {2, { I_cjhvApWlanAdjacentChannelTrapNumber27, 0 }}},
    { SNMP_INTEGER, (RWRITE| SCALAR), var_cjhvApWlanAdjacentChannelTrap,
                 {2, { I_cjhvApWlanAdjacentChannelTrapCount27, 0 }}},
    { 0 }
    };
static SubTree cjhvApWlanAdjacentChannelTrap27_tree =  { NULL, cjhvApWlanAdjacentChannelTrap27_variables,
	        (sizeof(cjhvApWlanAdjacentChannelTrap27_oid)/sizeof(oid)), cjhvApWlanAdjacentChannelTrap27_oid};

static oid cjhvApWlanAdjacentChannelTrap28_oid[] = { O_cjhvApWlanAdjacentChannelTrap28 };
static Object cjhvApWlanAdjacentChannelTrap28_variables[] = {
    { SNMP_INTEGER, (RONLY| SCALAR), var_cjhvApWlanAdjacentChannelTrap,
                 {2, { I_cjhvApWlanAdjacentChannelTrapIndex28, 0 }}},
    { SNMP_INTEGER, (RWRITE| SCALAR), var_cjhvApWlanAdjacentChannelTrap,
                 {2, { I_cjhvApWlanAdjacentChannelTrapNumber28, 0 }}},
    { SNMP_INTEGER, (RWRITE| SCALAR), var_cjhvApWlanAdjacentChannelTrap,
                 {2, { I_cjhvApWlanAdjacentChannelTrapCount28, 0 }}},
    { 0 }
    };
static SubTree cjhvApWlanAdjacentChannelTrap28_tree =  { NULL, cjhvApWlanAdjacentChannelTrap28_variables,
	        (sizeof(cjhvApWlanAdjacentChannelTrap28_oid)/sizeof(oid)), cjhvApWlanAdjacentChannelTrap28_oid};

static oid cjhvApWlanAdjacentChannelTrap29_oid[] = { O_cjhvApWlanAdjacentChannelTrap29 };
static Object cjhvApWlanAdjacentChannelTrap29_variables[] = {
    { SNMP_INTEGER, (RONLY| SCALAR), var_cjhvApWlanAdjacentChannelTrap,
                 {2, { I_cjhvApWlanAdjacentChannelTrapIndex29, 0 }}},
    { SNMP_INTEGER, (RWRITE| SCALAR), var_cjhvApWlanAdjacentChannelTrap,
                 {2, { I_cjhvApWlanAdjacentChannelTrapNumber29, 0 }}},
    { SNMP_INTEGER, (RWRITE| SCALAR), var_cjhvApWlanAdjacentChannelTrap,
                 {2, { I_cjhvApWlanAdjacentChannelTrapCount29, 0 }}},
    { 0 }
    };
static SubTree cjhvApWlanAdjacentChannelTrap29_tree =  { NULL, cjhvApWlanAdjacentChannelTrap29_variables,
	        (sizeof(cjhvApWlanAdjacentChannelTrap29_oid)/sizeof(oid)), cjhvApWlanAdjacentChannelTrap29_oid};

static oid cjhvApWlanAdjacentChannelTrap30_oid[] = { O_cjhvApWlanAdjacentChannelTrap30 };
static Object cjhvApWlanAdjacentChannelTrap30_variables[] = {
    { SNMP_INTEGER, (RONLY| SCALAR), var_cjhvApWlanAdjacentChannelTrap,
                 {2, { I_cjhvApWlanAdjacentChannelTrapIndex30, 0 }}},
    { SNMP_INTEGER, (RWRITE| SCALAR), var_cjhvApWlanAdjacentChannelTrap,
                 {2, { I_cjhvApWlanAdjacentChannelTrapNumber30, 0 }}},
    { SNMP_INTEGER, (RWRITE| SCALAR), var_cjhvApWlanAdjacentChannelTrap,
                 {2, { I_cjhvApWlanAdjacentChannelTrapCount30, 0 }}},
    { 0 }
    };
static SubTree cjhvApWlanAdjacentChannelTrap30_tree =  { NULL, cjhvApWlanAdjacentChannelTrap30_variables,
	        (sizeof(cjhvApWlanAdjacentChannelTrap30_oid)/sizeof(oid)), cjhvApWlanAdjacentChannelTrap30_oid};

static oid cjhvApWlanAdjacentChannelTrap31_oid[] = { O_cjhvApWlanAdjacentChannelTrap31 };
static Object cjhvApWlanAdjacentChannelTrap31_variables[] = {
    { SNMP_INTEGER, (RONLY| SCALAR), var_cjhvApWlanAdjacentChannelTrap,
                 {2, { I_cjhvApWlanAdjacentChannelTrapIndex31, 0 }}},
    { SNMP_INTEGER, (RWRITE| SCALAR), var_cjhvApWlanAdjacentChannelTrap,
                 {2, { I_cjhvApWlanAdjacentChannelTrapNumber31, 0 }}},
    { SNMP_INTEGER, (RWRITE| SCALAR), var_cjhvApWlanAdjacentChannelTrap,
                 {2, { I_cjhvApWlanAdjacentChannelTrapCount31, 0 }}},
    { 0 }
    };
static SubTree cjhvApWlanAdjacentChannelTrap31_tree =  { NULL, cjhvApWlanAdjacentChannelTrap31_variables,
	        (sizeof(cjhvApWlanAdjacentChannelTrap31_oid)/sizeof(oid)), cjhvApWlanAdjacentChannelTrap31_oid};
/* cjhvApWlanAdjacentChannelTrap_tree */

/* ======================= WLAN ADVANCE CONFIG ================================= */
int write_cjhvApWlanAdvFragmentThreshold(int action,
				   unsigned char *var_val, unsigned char varval_type, int var_val_len, unsigned char *statP, Oid * name)
{
	int ret = 1;

	switch (action) {
		case RESERVE1:
			break;
		case RESERVE2:
			break;
		case COMMIT:
			ret = set_wlanFragmentThreshold(WLAN_2G, (int)mhtol(var_val, var_val_len));
			break;
		case ACTION:
			break;
		case FREE:
			break;
	}

	return (ret == 0) ? SNMP_ERROR_WRONGVALUE : 0;
}

unsigned char *
var_cjhvApWlanAdvFragmentThreshold(int *var_len, snmp_info_t *mesg,
        int (**write_method)())
{
    public_mib_buffer.gb_long = get_wlanFragmentThreshold(WLAN_2G);
    *write_method = (int (*)())&write_cjhvApWlanAdvFragmentThreshold;
    *var_len = sizeof(long);

    return (unsigned char *)&public_mib_buffer.gb_long;
}

int write_cjhvApWlanAdvRTSThreshold(int action,
				   unsigned char *var_val, unsigned char varval_type, int var_val_len, unsigned char *statP, Oid * name)
{
	int ret = 1;

	switch (action) {
		case RESERVE1:
			break;
		case RESERVE2:
			break;
		case COMMIT:
			ret = set_wlanRTSThreshold(WLAN_2G, (int)mhtol(var_val, var_val_len));
			break;
		case ACTION:
			break;
		case FREE:
			break;
	}

	return (ret == 0) ? SNMP_ERROR_WRONGVALUE : 0;
}

unsigned char *
var_cjhvApWlanAdvRTSThreshold(int *var_len, snmp_info_t *mesg,
        int (**write_method)())
{
    public_mib_buffer.gb_long = get_wlanRTSThreshold(WLAN_2G);
    *write_method = (int (*)())&write_cjhvApWlanAdvRTSThreshold;
    *var_len = sizeof(long);

    return (unsigned char *)&public_mib_buffer.gb_long;
}

int write_cjhvApWlanAdvBeaconInterval(int action,
				   unsigned char *var_val, unsigned char varval_type, int var_val_len, unsigned char *statP, Oid * name)
{
	int ret = 1;

	switch (action) {
		case RESERVE1:
			break;
		case RESERVE2:
			break;
		case COMMIT:
			ret = set_wlanBeaconInterval(WLAN_2G, (int)mhtol(var_val, var_val_len));
			break;
		case ACTION:
			break;
		case FREE:
			break;
	}

	return (ret == 0) ? SNMP_ERROR_WRONGVALUE : 0;
}

unsigned char *
var_cjhvApWlanAdvBeaconInterval(int *var_len, snmp_info_t *mesg,
        int (**write_method)())
{
    public_mib_buffer.gb_long = get_wlanBeaconInterval(WLAN_2G);
    *write_method = (int (*)())&write_cjhvApWlanAdvBeaconInterval;
    *var_len = sizeof(long);

    return (unsigned char *)&public_mib_buffer.gb_long;
}

int write_cjhvApWlanAdvPreambleType(int action,
				   unsigned char *var_val, unsigned char varval_type, int var_val_len, unsigned char *statP, Oid * name)
{
	int ret = 1;

	switch (action) {
		case RESERVE1:
			break;
		case RESERVE2:
			break;
		case COMMIT:
			ret = set_wlanPreambleType(WLAN_2G, (int)mhtol(var_val, var_val_len));
			break;
		case ACTION:
			break;
		case FREE:
			break;
	}

	return (ret == 0) ? SNMP_ERROR_WRONGVALUE : 0;
}

unsigned char *
var_cjhvApWlanAdvPreambleType(int *var_len, snmp_info_t *mesg,
        int (**write_method)())
{
    public_mib_buffer.gb_long = get_wlanPreambleType(WLAN_2G);
    *write_method = (int (*)())&write_cjhvApWlanAdvPreambleType;
    *var_len = sizeof(long);

    return (unsigned char *)&public_mib_buffer.gb_long;
}

int write_cjhvApWlanAdvRFOutputPower(int action,
				   unsigned char *var_val, unsigned char varval_type, int var_val_len, unsigned char *statP, Oid * name)
{
	int ret = 1;

	switch (action) {
		case RESERVE1:
			break;
		case RESERVE2:
			break;
		case COMMIT:
			ret = set_wlanRFOutputPower(WLAN_2G, (int)mhtol(var_val, var_val_len));
			break;
		case ACTION:
			break;
		case FREE:
			break;
	}

	return (ret == 0) ? SNMP_ERROR_WRONGVALUE : 0;
}

unsigned char *
var_cjhvApWlanAdvRFOutputPower(int *var_len, snmp_info_t *mesg,
        int (**write_method)())
{
    public_mib_buffer.gb_long = get_wlanRFOutputPower(WLAN_2G);
    *write_method = (int (*)())&write_cjhvApWlanAdvRFOutputPower;
    *var_len = sizeof(long);

    return (unsigned char *)&public_mib_buffer.gb_long;
}

int write_cjhvApWlanAdvFragmentThreshold_5g(int action,
				   unsigned char *var_val, unsigned char varval_type, int var_val_len, unsigned char *statP, Oid * name)
{
	int ret = 1;

	switch (action) {
		case RESERVE1:
			break;
		case RESERVE2:
			break;
		case COMMIT:
			ret = set_wlanFragmentThreshold(WLAN_5G, (int)mhtol(var_val, var_val_len));
			break;
		case ACTION:
			break;
		case FREE:
			break;
	}

	return (ret == 0) ? SNMP_ERROR_WRONGVALUE : 0;
}

unsigned char *
var_cjhvApWlanAdvFragmentThreshold_5g(int *var_len, snmp_info_t *mesg,
        int (**write_method)())
{
    public_mib_buffer.gb_long = get_wlanFragmentThreshold(WLAN_5G);
    *write_method = (int (*)())&write_cjhvApWlanAdvFragmentThreshold_5g;
    *var_len = sizeof(long);

    return (unsigned char *)&public_mib_buffer.gb_long;
}

int write_cjhvApWlanAdvRTSThreshold_5g(int action,
				   unsigned char *var_val, unsigned char varval_type, int var_val_len, unsigned char *statP, Oid * name)
{
	int ret = 1;

	switch (action) {
		case RESERVE1:
			break;
		case RESERVE2:
			break;
		case COMMIT:
			ret = set_wlanRTSThreshold(WLAN_5G, (int)mhtol(var_val, var_val_len));
			break;
		case ACTION:
			break;
		case FREE:
			break;
	}

	return (ret == 0) ? SNMP_ERROR_WRONGVALUE : 0;
}

unsigned char *
var_cjhvApWlanAdvRTSThreshold_5g(int *var_len, snmp_info_t *mesg,
        int (**write_method)())
{
    public_mib_buffer.gb_long = get_wlanRTSThreshold(WLAN_5G);
    *write_method = (int (*)())&write_cjhvApWlanAdvRTSThreshold_5g;
    *var_len = sizeof(long);

    return (unsigned char *)&public_mib_buffer.gb_long;
}

int write_cjhvApWlanAdvBeaconInterval_5g(int action,
				   unsigned char *var_val, unsigned char varval_type, int var_val_len, unsigned char *statP, Oid * name)
{
	int ret = 1;

	switch (action) {
		case RESERVE1:
			break;
		case RESERVE2:
			break;
		case COMMIT:
			ret = set_wlanBeaconInterval(WLAN_5G, (int)mhtol(var_val, var_val_len));
			break;
		case ACTION:
			break;
		case FREE:
			break;
	}

	return (ret == 0) ? SNMP_ERROR_WRONGVALUE : 0;
}

unsigned char *
var_cjhvApWlanAdvBeaconInterval_5g(int *var_len, snmp_info_t *mesg,
        int (**write_method)())
{
    public_mib_buffer.gb_long = get_wlanBeaconInterval(WLAN_5G);
    *write_method = (int (*)())&write_cjhvApWlanAdvBeaconInterval_5g;
    *var_len = sizeof(long);

    return (unsigned char *)&public_mib_buffer.gb_long;
}

int write_cjhvApWlanAdvPreambleType_5g(int action,
				   unsigned char *var_val, unsigned char varval_type, int var_val_len, unsigned char *statP, Oid * name)
{
	int ret = 1;

	switch (action) {
		case RESERVE1:
			break;
		case RESERVE2:
			break;
		case COMMIT:
			ret = set_wlanPreambleType(WLAN_5G, (int)mhtol(var_val, var_val_len));
			break;
		case ACTION:
			break;
		case FREE:
			break;
	}

	return (ret == 0) ? SNMP_ERROR_WRONGVALUE : 0;
}

unsigned char *
var_cjhvApWlanAdvPreambleType_5g(int *var_len, snmp_info_t *mesg,
        int (**write_method)())
{
    public_mib_buffer.gb_long = get_wlanPreambleType(WLAN_5G);
    *write_method = (int (*)())&write_cjhvApWlanAdvPreambleType_5g;
    *var_len = sizeof(long);

    return (unsigned char *)&public_mib_buffer.gb_long;
}

int write_cjhvApWlanAdvRFOutputPower_5g(int action,
				   unsigned char *var_val, unsigned char varval_type, int var_val_len, unsigned char *statP, Oid * name)
{
	int ret = 1;

	switch (action) {
		case RESERVE1:
			break;
		case RESERVE2:
			break;
		case COMMIT:
			ret = set_wlanRFOutputPower(WLAN_5G, (int)mhtol(var_val, var_val_len));
			break;
		case ACTION:
			break;
		case FREE:
			break;
	}

	return (ret == 0) ? SNMP_ERROR_WRONGVALUE : 0;
}

unsigned char *
var_cjhvApWlanAdvRFOutputPower_5g(int *var_len, snmp_info_t *mesg,
        int (**write_method)())
{
    public_mib_buffer.gb_long = get_wlanRFOutputPower(WLAN_5G);
    *write_method = (int (*)())&write_cjhvApWlanAdvRFOutputPower_5g;
    *var_len = sizeof(long);

    return (unsigned char *)&public_mib_buffer.gb_long;
}
/* ======================= WLAN ADVANCE CONFIG ================================= */

/* cjhvApWlanAdvancedConfig_tree */
static oid cjhvApWlanAdvancedConfig_oid[] = { O_cjhvApWlanAdvancedConfig };
static Object cjhvApWlanAdvancedConfig_variables[] = {
    { SNMP_INTEGER, (RWRITE| SCALAR), var_cjhvApWlanAdvFragmentThreshold,
                 {2, { I_cjhvApWlanAdvFragmentThreshold, 0 }}},
    { SNMP_INTEGER, (RWRITE| SCALAR), var_cjhvApWlanAdvRTSThreshold,
                 {2, { I_cjhvApWlanAdvRTSThreshold, 0 }}},
    { SNMP_INTEGER, (RWRITE| SCALAR), var_cjhvApWlanAdvBeaconInterval,
                 {2, { I_cjhvApWlanAdvBeaconInterval, 0 }}},
    { SNMP_INTEGER, (RWRITE| SCALAR), var_cjhvApWlanAdvPreambleType,
                 {2, { I_cjhvApWlanAdvPreambleType, 0 }}},
    { SNMP_INTEGER, (RWRITE| SCALAR), var_cjhvApWlanAdvRFOutputPower,
                 {2, { I_cjhvApWlanAdvRFOutputPower, 0 }}},
    { 0 }
    };
static SubTree cjhvApWlanAdvancedConfig_tree =  { NULL, cjhvApWlanAdvancedConfig_variables,
	        (sizeof(cjhvApWlanAdvancedConfig_oid)/sizeof(oid)), cjhvApWlanAdvancedConfig_oid};
/* cjhvApWlanAdvancedConfig_tree */

/* cjhvApWlanAdvancedConfig_tree_5g */
static oid cjhvApWlanAdvancedConfig_5g_oid[] = { O_cjhvApWlanAdvancedConfig_5g };
static Object cjhvApWlanAdvancedConfig_variables_5g[] = {
    { SNMP_INTEGER, (RWRITE| SCALAR), var_cjhvApWlanAdvFragmentThreshold_5g,
                 {2, { I_cjhvApWlanAdvFragmentThreshold_5g, 0 }}},
    { SNMP_INTEGER, (RWRITE| SCALAR), var_cjhvApWlanAdvRTSThreshold_5g,
                 {2, { I_cjhvApWlanAdvRTSThreshold_5g, 0 }}},
    { SNMP_INTEGER, (RWRITE| SCALAR), var_cjhvApWlanAdvBeaconInterval_5g,
                 {2, { I_cjhvApWlanAdvBeaconInterval_5g, 0 }}},
    { SNMP_INTEGER, (RWRITE| SCALAR), var_cjhvApWlanAdvPreambleType_5g,
                 {2, { I_cjhvApWlanAdvPreambleType_5g, 0 }}},
    { SNMP_INTEGER, (RWRITE| SCALAR), var_cjhvApWlanAdvRFOutputPower_5g,
                 {2, { I_cjhvApWlanAdvRFOutputPower_5g, 0 }}},
    { 0 }
    };
static SubTree cjhvApWlanAdvancedConfig_tree_5g =  { NULL, cjhvApWlanAdvancedConfig_variables_5g,
	        (sizeof(cjhvApWlanAdvancedConfig_5g_oid)/sizeof(oid)), cjhvApWlanAdvancedConfig_5g_oid};
/* cjhvApWlanAdvancedConfig_tree_5g */

/* ======================= CLIENT INFO ================================= */
unsigned char *
var_cjhvApWlanClientEntry(int *var_len, Oid *newoid, Oid *reqoid, int searchType, snmp_info_t *mesg, int (**write_method)())
{
	int column = newoid->name[(newoid->namelen - 1)];
	int result;
	int ii = newoid->namelen++;
	int idx = 0;
	static int num = -1;
	static int host_num = 7;
	static int wlclient_num = 0;
	static int count = 0;
	char value[12] = {0,};

	if (num == -1) {
		if (get_wlanMode(WLAN_2G) == 1)
			wlclient_num = wirelessClientList(WLAN_2G, wlclient_num);
		if (wlclient_num < 6 && get_wlanMode(WLAN_5G) == 1)
			wlclient_num += wirelessClientList(WLAN_5G, wlclient_num);
		if (wlclient_num > 6)
			wlclient_num = 6;
		num = wlclient_num;
		nvram_get_r_def("OP_MODE", value, sizeof(value), "0");
		if(value[0] == '0')
			num += initHostInfo();
		if(num > 10)
			num = 10;
	}

	while (idx + 1 <= num) {
		newoid->name[ii] = idx;
		result = compare(reqoid, newoid);
		if (((searchType == EXACT) && (result == 0)) || ((searchType == NEXT) && (result < 0))) {
			break;
		}
		idx++;
	}

	if(num == 0) {
		num= -1;
		wlclient_num = 0;
		host_num = 7;
	}

	if (idx + 1 > num){
		if(count >= num){
			count = 0;
			num = -1;
			wlclient_num = 0;
			host_num = 7;
		}
		return (unsigned char *)NO_MIBINSTANCE;
	}

    *write_method = 0;
    switch (column) {
	case I_cjhvApWlanClientIndex:
		if(idx + 1 <= wlclient_num)
			public_mib_buffer.gb_long = idx + 1;
		else
			public_mib_buffer.gb_long = host_num++;
		*var_len = sizeof(long);
		return (unsigned char *)&public_mib_buffer.gb_long;
	case I_cjhvApWlanClientMac:
		if(idx + 1 <= wlclient_num)
			get_wlanStaMac(idx, public_mib_buffer.gb_string, sizeof(public_mib_buffer.gb_string));
		else
			get_hostInfoMac((idx - wlclient_num), public_mib_buffer.gb_string, sizeof(public_mib_buffer.gb_string));
		*var_len = 6;
		return (unsigned char *)public_mib_buffer.gb_string;
	case I_cjhvApWlanClientIp:
		if(idx + 1 <= wlclient_num)
			get_wlanStaipaddr(idx, &public_mib_buffer.gb_ip_address);
		else
			get_hostInfoipAddr((idx - wlclient_num), &public_mib_buffer.gb_ip_address);
		*var_len = sizeof(public_mib_buffer.gb_ip_address);
		return (unsigned char *)&public_mib_buffer.gb_ip_address;
	case I_cjhvApWlanClientName:
		if(idx + 1 <= wlclient_num)
			get_wlanStaName(idx, public_mib_buffer.gb_string, sizeof(public_mib_buffer.gb_string));
		else
			get_hostInfoName((idx - wlclient_num), public_mib_buffer.gb_string, sizeof(public_mib_buffer.gb_string));
		*var_len = strlen(public_mib_buffer.gb_string);
		return (unsigned char *)public_mib_buffer.gb_string;
	case I_cjhvApWlanClientMode:
		if(idx + 1 <= wlclient_num)
    		get_wlanStaMode(idx, &public_mib_buffer.gb_long);
    	else
    		public_mib_buffer.gb_long = 0;
    	*var_len = sizeof(long);
	   	return (unsigned char *)&public_mib_buffer.gb_long;
	case I_cjhvApWlanClientBand:
    	if(idx + 1 <= wlclient_num)
    		get_wlanStaBand(idx, &public_mib_buffer.gb_long);
    	else
    		public_mib_buffer.gb_long = 0;
    	*var_len = sizeof(long);
	   	return (unsigned char *)&public_mib_buffer.gb_long;
	case I_cjhvApWlanClientRssi:
		if (idx + 1 <= wlclient_num)
			get_wlanStaRssi(idx , public_mib_buffer.gb_string, sizeof(public_mib_buffer.gb_string));
		else
			snprintf(public_mib_buffer.gb_string, sizeof(public_mib_buffer.gb_string), "0");
		*var_len = strlen(public_mib_buffer.gb_string);
		return (unsigned char *)public_mib_buffer.gb_string;
	case I_cjhvApWlanClientCRC:
		if(idx + 1 <= wlclient_num)
			public_mib_buffer.gb_counter = 0;
		else
			get_hostInfoCrc((idx - wlclient_num), &public_mib_buffer.gb_counter);
		count++;
		if(count > num)
			count = num;
		*var_len = sizeof(public_mib_buffer.gb_counter);
		return (unsigned char *)&public_mib_buffer.gb_counter;
    default:
    	return NO_MIBINSTANCE;
    }
    return NO_MIBINSTANCE;
}
/* ======================= CLIENT INFO ================================= */

/* cjhvApWlanClientEntry_tree */
static oid cjhvApWlanClientEntry_oid[] = { O_cjhvApWlanClientEntry };
static Object cjhvApWlanClientEntry_variables[] = {
    { SNMP_INTEGER, (RONLY| COLUMN), var_cjhvApWlanClientEntry,
                {1, { I_cjhvApWlanClientIndex }}},
    { SNMP_STRING, (RONLY| COLUMN), var_cjhvApWlanClientEntry,
                {1, { I_cjhvApWlanClientMac }}},
    { SNMP_IPADDRESS, (RONLY| COLUMN), var_cjhvApWlanClientEntry,
                {1, { I_cjhvApWlanClientIp }}},
    { SNMP_STRING, (RONLY| COLUMN), var_cjhvApWlanClientEntry,
                {1, { I_cjhvApWlanClientName }}},
    { SNMP_INTEGER, (RONLY| COLUMN), var_cjhvApWlanClientEntry,
                {1, { I_cjhvApWlanClientMode }}},
    { SNMP_INTEGER, (RONLY| COLUMN), var_cjhvApWlanClientEntry,
                {1, { I_cjhvApWlanClientBand }}},
    { SNMP_STRING, (RONLY| COLUMN), var_cjhvApWlanClientEntry,
                {1, { I_cjhvApWlanClientRssi }}},
    { SNMP_COUNTER, (RONLY| COLUMN), var_cjhvApWlanClientEntry,
                {1, { I_cjhvApWlanClientCRC }}},
    { 0 }
    };
static SubTree cjhvApWlanClientEntry_tree =  { NULL, cjhvApWlanClientEntry_variables,
	        (sizeof(cjhvApWlanClientEntry_oid)/sizeof(oid)), cjhvApWlanClientEntry_oid};
/* cjhvApWlanClientEntry_tree */

/* ======================= CLIENT TRAP INFO ================================= */
unsigned char *
var_cjhvApWlanClientInfoTrap(int *var_len, snmp_info_t *mesg,
        int (**write_method)())
{
    public_mib_buffer.gb_long = 1;
    *write_method = 0;
    *var_len = sizeof(long);

    return (unsigned char *)&public_mib_buffer.gb_long;
}
/* ======================= CLIENT TRAP INFO ================================= */

/* cjhvApWlanClientInfoTrap_tree */
static oid cjhvApWlanClientInfoTrap1_oid[] = { O_cjhvApWlanClientInfoTrap1 };
static Object cjhvApWlanClientInfoTrap1_variables[] = {
    { SNMP_INTEGER, (RONLY| SCALAR), var_cjhvApWlanClientInfoTrap,
                 {2, { I_cjhvApWlanClientInfoTrapIndex1, 0 }}},
    { SNMP_STRING, (RONLY| SCALAR), var_cjhvApWlanClientInfoTrap,
                 {2, { I_cjhvApWlanClientTrapMac1, 0 }}},
    { SNMP_IPADDRESS, (RONLY| SCALAR), var_cjhvApWlanClientInfoTrap,
                 {2, { I_cjhvApWlanClientTrapIp1, 0 }}},
    { 0 }
    };
static SubTree cjhvApWlanClientInfoTrap1_tree =  { NULL, cjhvApWlanClientInfoTrap1_variables,
	        (sizeof(cjhvApWlanClientInfoTrap1_oid)/sizeof(oid)), cjhvApWlanClientInfoTrap1_oid};

static oid cjhvApWlanClientInfoTrap2_oid[] = { O_cjhvApWlanClientInfoTrap2 };
static Object cjhvApWlanClientInfoTrap2_variables[] = {
    { SNMP_INTEGER, (RONLY| SCALAR), var_cjhvApWlanClientInfoTrap,
                 {2, { I_cjhvApWlanClientInfoTrapIndex2, 0 }}},
    { SNMP_STRING, (RONLY| SCALAR), var_cjhvApWlanClientInfoTrap,
                 {2, { I_cjhvApWlanClientTrapMac2, 0 }}},
    { SNMP_IPADDRESS, (RONLY| SCALAR), var_cjhvApWlanClientInfoTrap,
                 {2, { I_cjhvApWlanClientTrapIp2, 0 }}},
    { 0 }
    };
static SubTree cjhvApWlanClientInfoTrap2_tree =  { NULL, cjhvApWlanClientInfoTrap2_variables,
	        (sizeof(cjhvApWlanClientInfoTrap2_oid)/sizeof(oid)), cjhvApWlanClientInfoTrap2_oid};

static oid cjhvApWlanClientInfoTrap3_oid[] = { O_cjhvApWlanClientInfoTrap3 };
static Object cjhvApWlanClientInfoTrap3_variables[] = {
    { SNMP_INTEGER, (RONLY| SCALAR), var_cjhvApWlanClientInfoTrap,
                 {2, { I_cjhvApWlanClientInfoTrapIndex3, 0 }}},
    { SNMP_STRING, (RONLY| SCALAR), var_cjhvApWlanClientInfoTrap,
                 {2, { I_cjhvApWlanClientTrapMac3, 0 }}},
    { SNMP_IPADDRESS, (RONLY| SCALAR), var_cjhvApWlanClientInfoTrap,
                 {2, { I_cjhvApWlanClientTrapIp3, 0 }}},
    { 0 }
    };
static SubTree cjhvApWlanClientInfoTrap3_tree =  { NULL, cjhvApWlanClientInfoTrap3_variables,
	        (sizeof(cjhvApWlanClientInfoTrap3_oid)/sizeof(oid)), cjhvApWlanClientInfoTrap3_oid};

static oid cjhvApWlanClientInfoTrap4_oid[] = { O_cjhvApWlanClientInfoTrap4 };
static Object cjhvApWlanClientInfoTrap4_variables[] = {
    { SNMP_INTEGER, (RONLY| SCALAR), var_cjhvApWlanClientInfoTrap,
                 {2, { I_cjhvApWlanClientInfoTrapIndex4, 0 }}},
    { SNMP_STRING, (RONLY| SCALAR), var_cjhvApWlanClientInfoTrap,
                 {2, { I_cjhvApWlanClientTrapMac4, 0 }}},
    { SNMP_IPADDRESS, (RONLY| SCALAR), var_cjhvApWlanClientInfoTrap,
                 {2, { I_cjhvApWlanClientTrapIp4, 0 }}},
    { 0 }
    };
static SubTree cjhvApWlanClientInfoTrap4_tree =  { NULL, cjhvApWlanClientInfoTrap4_variables,
	        (sizeof(cjhvApWlanClientInfoTrap4_oid)/sizeof(oid)), cjhvApWlanClientInfoTrap4_oid};

static oid cjhvApWlanClientInfoTrap5_oid[] = { O_cjhvApWlanClientInfoTrap5 };
static Object cjhvApWlanClientInfoTrap5_variables[] = {
    { SNMP_INTEGER, (RONLY| SCALAR), var_cjhvApWlanClientInfoTrap,
                 {2, { I_cjhvApWlanClientInfoTrapIndex5, 0 }}},
    { SNMP_STRING, (RONLY| SCALAR), var_cjhvApWlanClientInfoTrap,
                 {2, { I_cjhvApWlanClientTrapMac5, 0 }}},
    { SNMP_IPADDRESS, (RONLY| SCALAR), var_cjhvApWlanClientInfoTrap,
                 {2, { I_cjhvApWlanClientTrapIp5, 0 }}},
    { 0 }
    };
static SubTree cjhvApWlanClientInfoTrap5_tree =  { NULL, cjhvApWlanClientInfoTrap5_variables,
	        (sizeof(cjhvApWlanClientInfoTrap5_oid)/sizeof(oid)), cjhvApWlanClientInfoTrap5_oid};

static oid cjhvApWlanClientInfoTrap6_oid[] = { O_cjhvApWlanClientInfoTrap6 };
static Object cjhvApWlanClientInfoTrap6_variables[] = {
    { SNMP_INTEGER, (RONLY| SCALAR), var_cjhvApWlanClientInfoTrap,
                 {2, { I_cjhvApWlanClientInfoTrapIndex6, 0 }}},
    { SNMP_STRING, (RONLY| SCALAR), var_cjhvApWlanClientInfoTrap,
                 {2, { I_cjhvApWlanClientTrapMac6, 0 }}},
    { SNMP_IPADDRESS, (RONLY| SCALAR), var_cjhvApWlanClientInfoTrap,
                 {2, { I_cjhvApWlanClientTrapIp6, 0 }}},
    { 0 }
    };
static SubTree cjhvApWlanClientInfoTrap6_tree =  { NULL, cjhvApWlanClientInfoTrap6_variables,
	        (sizeof(cjhvApWlanClientInfoTrap6_oid)/sizeof(oid)), cjhvApWlanClientInfoTrap6_oid};

static oid cjhvApWlanClientInfoTrap7_oid[] = { O_cjhvApWlanClientInfoTrap7 };
static Object cjhvApWlanClientInfoTrap7_variables[] = {
    { SNMP_INTEGER, (RONLY| SCALAR), var_cjhvApWlanClientInfoTrap,
                 {2, { I_cjhvApWlanClientInfoTrapIndex7, 0 }}},
    { SNMP_STRING, (RONLY| SCALAR), var_cjhvApWlanClientInfoTrap,
                 {2, { I_cjhvApWlanClientTrapMac7, 0 }}},
    { SNMP_IPADDRESS, (RONLY| SCALAR), var_cjhvApWlanClientInfoTrap,
                 {2, { I_cjhvApWlanClientTrapIp7, 0 }}},
    { 0 }
    };
static SubTree cjhvApWlanClientInfoTrap7_tree =  { NULL, cjhvApWlanClientInfoTrap7_variables,
	        (sizeof(cjhvApWlanClientInfoTrap7_oid)/sizeof(oid)), cjhvApWlanClientInfoTrap7_oid};

static oid cjhvApWlanClientInfoTrap8_oid[] = { O_cjhvApWlanClientInfoTrap8 };
static Object cjhvApWlanClientInfoTrap8_variables[] = {
    { SNMP_INTEGER, (RONLY| SCALAR), var_cjhvApWlanClientInfoTrap,
                 {2, { I_cjhvApWlanClientInfoTrapIndex8, 0 }}},
    { SNMP_STRING, (RONLY| SCALAR), var_cjhvApWlanClientInfoTrap,
                 {2, { I_cjhvApWlanClientTrapMac8, 0 }}},
    { SNMP_IPADDRESS, (RONLY| SCALAR), var_cjhvApWlanClientInfoTrap,
                 {2, { I_cjhvApWlanClientTrapIp8, 0 }}},
    { 0 }
    };
static SubTree cjhvApWlanClientInfoTrap8_tree =  { NULL, cjhvApWlanClientInfoTrap8_variables,
	        (sizeof(cjhvApWlanClientInfoTrap8_oid)/sizeof(oid)), cjhvApWlanClientInfoTrap8_oid};

static oid cjhvApWlanClientInfoTrap9_oid[] = { O_cjhvApWlanClientInfoTrap9 };
static Object cjhvApWlanClientInfoTrap9_variables[] = {
    { SNMP_INTEGER, (RONLY| SCALAR), var_cjhvApWlanClientInfoTrap,
                 {2, { I_cjhvApWlanClientInfoTrapIndex9, 0 }}},
    { SNMP_STRING, (RONLY| SCALAR), var_cjhvApWlanClientInfoTrap,
                 {2, { I_cjhvApWlanClientTrapMac9, 0 }}},
    { SNMP_IPADDRESS, (RONLY| SCALAR), var_cjhvApWlanClientInfoTrap,
                 {2, { I_cjhvApWlanClientTrapIp9, 0 }}},
    { 0 }
    };
static SubTree cjhvApWlanClientInfoTrap9_tree =  { NULL, cjhvApWlanClientInfoTrap9_variables,
	        (sizeof(cjhvApWlanClientInfoTrap9_oid)/sizeof(oid)), cjhvApWlanClientInfoTrap9_oid};

static oid cjhvApWlanClientInfoTrap10_oid[] = { O_cjhvApWlanClientInfoTrap10 };
static Object cjhvApWlanClientInfoTrap10_variables[] = {
    { SNMP_INTEGER, (RONLY| SCALAR), var_cjhvApWlanClientInfoTrap,
                 {2, { I_cjhvApWlanClientInfoTrapIndex10, 0 }}},
    { SNMP_STRING, (RONLY| SCALAR), var_cjhvApWlanClientInfoTrap,
                 {2, { I_cjhvApWlanClientTrapMac10, 0 }}},
    { SNMP_IPADDRESS, (RONLY| SCALAR), var_cjhvApWlanClientInfoTrap,
                 {2, { I_cjhvApWlanClientTrapIp10, 0 }}},
    { 0 }
    };
static SubTree cjhvApWlanClientInfoTrap10_tree =  { NULL, cjhvApWlanClientInfoTrap10_variables,
	        (sizeof(cjhvApWlanClientInfoTrap10_oid)/sizeof(oid)), cjhvApWlanClientInfoTrap10_oid};
/* cjhvApWlanClientInfoTrap_tree */

/* ======================= WEP SECURITY INFO ================================= */
int write_secWEP8021xAuthMode(int action,
							  unsigned char *var_val, unsigned char varval_type, int var_val_len, unsigned char *statP, Oid * name)
{
	int ret = 1;
	int wl_index = name->name[(name->namelen - 1)];

	switch (action) {
		case RESERVE1:
			break;
		case RESERVE2:
			break;
		case COMMIT:
			ret = set_secWEP8021xAuthMode(wl_index, (int)mhtol(var_val, var_val_len));
			break;
		case ACTION:
			break;
		case FREE:
			break;
	}

	return (ret == 0) ? SNMP_ERROR_WRONGVALUE : 0;
}

int write_secWEPMacAuthMode(int action,
				   unsigned char *var_val, unsigned char varval_type, int var_val_len, unsigned char *statP, Oid * name)
{
	int ret = 1;
	int wl_index = name->name[(name->namelen - 1)];

	switch (action) {
		case RESERVE1:
			break;
		case RESERVE2:
			break;
		case COMMIT:
			ret = set_secWEPMacAuthMode(wl_index, (int)mhtol(var_val, var_val_len));
			break;
		case ACTION:
			break;
		case FREE:
			break;
	}

	return (ret == 0) ? SNMP_ERROR_WRONGVALUE : 0;
}

int write_secWEPAuthMethod(int action,
						   unsigned char *var_val, unsigned char varval_type, int var_val_len, unsigned char *statP, Oid * name)
{
	int ret = 1;
	int wl_index = name->name[(name->namelen - 1)];

	switch (action) {
		case RESERVE1:
			break;
		case RESERVE2:
			break;
		case COMMIT:
			ret = set_secWEPAuthMethod(wl_index, (int)mhtol(var_val, var_val_len));
			break;
		case ACTION:
			break;
		case FREE:
			break;
	}

	return (ret == 0) ? SNMP_ERROR_WRONGVALUE : 0;
}

int write_secWEPAuthKeySize(int action,
							unsigned char *var_val, unsigned char varval_type, int var_val_len, unsigned char *statP, Oid * name)
{
	int ret = 1;
	int wl_index = name->name[(name->namelen - 1)];

	switch (action) {
		case RESERVE1:
			break;
		case RESERVE2:
			break;
		case COMMIT:
			ret = set_secWEPKeySize(wl_index, (int)mhtol(var_val, var_val_len));
			break;
		case ACTION:
			break;
		case FREE:
			break;
	}

	return (ret == 0) ? SNMP_ERROR_WRONGVALUE : 0;
}

int write_secWEPKeyFormat(int action,
						  unsigned char *var_val, unsigned char varval_type, int var_val_len, unsigned char *statP, Oid * name)
{
	int ret = 1;
	int wl_index = name->name[(name->namelen - 1)];

	switch (action) {
		case RESERVE1:
			break;
		case RESERVE2:
			break;
		case COMMIT:
			ret = set_secWEPKeyFormat(wl_index, (int)mhtol(var_val, var_val_len));
			break;
		case ACTION:
			break;
		case FREE:
			break;
	}

	return (ret == 0) ? SNMP_ERROR_WRONGVALUE : 0;
}

int write_secWEPEncryptionKey(int action,
							  unsigned char *var_val, unsigned char varval_type, int var_val_len, unsigned char *statP, Oid * name)
{
	int ret = 1;
	int wl_index = name->name[(name->namelen - 1)];

	switch (action) {
		case RESERVE1:
			break;
		case RESERVE2:
			break;
		case COMMIT:
			ret = set_secWEPEncryptionKey(wl_index, (char *)var_val, var_val_len);
			break;
		case ACTION:
			break;
		case FREE:
			break;
	}

	return (ret == 0) ? SNMP_ERROR_WRONGVALUE : 0;
}

int write_secWEPKeyIndex(int action,
						 unsigned char *var_val, unsigned char varval_type, int var_val_len, unsigned char *statP, Oid * name)
{
	int ret = 1;
	int wl_index = name->name[(name->namelen - 1)];

	switch (action) {
		case RESERVE1:
			break;
		case RESERVE2:
			break;
		case COMMIT:
			ret = set_secWEPKeyIndex(wl_index, (int)mhtol(var_val, var_val_len));
			break;
		case ACTION:
			break;
		case FREE:
			break;
	}

	return (ret == 0) ? SNMP_ERROR_WRONGVALUE : 0;
}

unsigned char *
var_cjhvApSecwepConfigEntry(int *var_len, Oid *newoid, Oid *reqoid, int searchType, snmp_info_t *mesg, int (**write_method)())
{
	int column = newoid->name[(newoid->namelen - 1)];
	int result;
	int index = newoid->namelen++;
	int wl_index = 0;

	while (wl_index < 8) {
		newoid->name[index] = wl_index;
		result = compare(reqoid, newoid);
		if (((searchType == EXACT) && (result == 0)) || ((searchType == NEXT) && (result < 0))) {
			break;
		}
		wl_index++;
	}

	if (wl_index >= 8) {
		return (unsigned char *)NO_MIBINSTANCE;
	}

	switch (column) {
	case I_cjhvApSecwepConfigSSIDIndex:
		public_mib_buffer.gb_long = wl_index + 1;
		*var_len = sizeof(long);
		*write_method = 0;
		return (unsigned char *)&public_mib_buffer.gb_long;
	case I_cjhvApSecwepSecSSID:
		get_wlanSSID(wl_index, public_mib_buffer.gb_string, sizeof(public_mib_buffer.gb_string));
		*var_len = strlen(public_mib_buffer.gb_string);
		*write_method = 0;
		return (unsigned char *)public_mib_buffer.gb_string;
	case I_cjhvApSecwep8021xAuthMode:
		public_mib_buffer.gb_long = get_secWEP8021xAuthMode(wl_index);
		*var_len = sizeof(long);
		*write_method = (int (*)())&write_secWEP8021xAuthMode;
		return (unsigned char *)&public_mib_buffer.gb_long;
	case I_cjhvApSecwepMacAuthMode:
		public_mib_buffer.gb_long = get_secWEPMacAuthMode(wl_index);
		*var_len = sizeof(long);
		*write_method = (int (*)())&write_secWEPMacAuthMode;
		return (unsigned char *)&public_mib_buffer.gb_long;
	case I_cjhvApSecwepAuthMethod:
		public_mib_buffer.gb_long = get_secWEPAuthMethod(wl_index);
		*var_len = sizeof(long);
		*write_method = (int (*)())&write_secWEPAuthMethod;
		return (unsigned char *)&public_mib_buffer.gb_long;
	case I_cjhvApSecwepAuthKeyLength:
		public_mib_buffer.gb_long = get_secWEPKeySize(wl_index);
		*var_len = sizeof(long);
		*write_method = (int (*)())&write_secWEPAuthKeySize;
		return (unsigned char *)&public_mib_buffer.gb_long;
	case I_cjhvApSecwepKeyFormat:
		public_mib_buffer.gb_long = get_secWEPKeyFormat(wl_index);
		*var_len = sizeof(long);
		*write_method = (int (*)())&write_secWEPKeyFormat;
		return (unsigned char *)&public_mib_buffer.gb_long;
	case I_cjhvApSecwepEncryptionKey:
		get_secWEPEncryptionKey(wl_index, public_mib_buffer.gb_string, sizeof(public_mib_buffer.gb_string));
		*var_len = strlen(public_mib_buffer.gb_string);
		*write_method = (int (*)())&write_secWEPEncryptionKey;
		return (unsigned char *)public_mib_buffer.gb_string;
	case I_cjhvApSecwepKeyIndex:
		public_mib_buffer.gb_long = get_secWEPKeyIndex(wl_index);
		*var_len = sizeof(long);
		*write_method = (int (*)())&write_secWEPKeyIndex;
		return (unsigned char *)&public_mib_buffer.gb_long;
	default:
		return NO_MIBINSTANCE;
    }
    return NO_MIBINSTANCE;
}
/* ======================= WEP SECURITY INFO ================================= */

/* cjhvApSecwepConfigEntry_tree */
static oid cjhvApSecwepConfigEntry_oid[] = { O_cjhvApSecwepConfigEntry };
static Object cjhvApSecwepConfigEntry_variables[] = {
    { SNMP_INTEGER, (RWRITE| COLUMN), var_cjhvApSecwepConfigEntry,
                {1, { I_cjhvApSecwepConfigSSIDIndex }}},
    { SNMP_STRING, (RWRITE| COLUMN), var_cjhvApSecwepConfigEntry,
                {1, { I_cjhvApSecwepSecSSID }}},
    { SNMP_INTEGER, (RWRITE| COLUMN), var_cjhvApSecwepConfigEntry,
                {1, { I_cjhvApSecwep8021xAuthMode }}},
    { SNMP_INTEGER, (RWRITE| COLUMN), var_cjhvApSecwepConfigEntry,
                {1, { I_cjhvApSecwepMacAuthMode }}},
    { SNMP_INTEGER, (RWRITE| COLUMN), var_cjhvApSecwepConfigEntry,
                {1, { I_cjhvApSecwepAuthMethod }}},
    { SNMP_INTEGER, (RWRITE| COLUMN), var_cjhvApSecwepConfigEntry,
                {1, { I_cjhvApSecwepAuthKeyLength }}},
    { SNMP_INTEGER, (RWRITE| COLUMN), var_cjhvApSecwepConfigEntry,
                {1, { I_cjhvApSecwepKeyFormat }}},
    { SNMP_STRING, (RWRITE| COLUMN), var_cjhvApSecwepConfigEntry,
                {1, { I_cjhvApSecwepEncryptionKey }}},
    { SNMP_INTEGER, (RWRITE| COLUMN), var_cjhvApSecwepConfigEntry,
                {1, { I_cjhvApSecwepKeyIndex }}},
    { 0 }
    };
static SubTree cjhvApSecwepConfigEntry_tree =  { NULL, cjhvApSecwepConfigEntry_variables,
	        (sizeof(cjhvApSecwepConfigEntry_oid)/sizeof(oid)), cjhvApSecwepConfigEntry_oid};
/* cjhvApSecwepConfigEntry_tree */

/* ======================= WPA SECURITY INFO ================================= */
int write_secWPAxAuthMode(int action,
						  unsigned char *var_val, unsigned char varval_type, int var_val_len, unsigned char *statP, Oid * name)
{
	int ret = 1;
	int wl_index = name->name[(name->namelen - 1)];

	switch (action) {
		case RESERVE1:
			break;
		case RESERVE2:
			break;
		case COMMIT:
			ret = set_secWPAxAuthMode(wl_index, (int)mhtol(var_val, var_val_len));
			break;
		case ACTION:
			break;
		case FREE:
			break;
	}

	return (ret == 0) ? SNMP_ERROR_WRONGVALUE : 0;
}

int write_secWPAxCipherSuite(int action,
							 unsigned char *var_val, unsigned char varval_type, int var_val_len, unsigned char *statP, Oid * name)
{
	int ret = 1;
	int wl_index = name->name[(name->namelen - 1)];

	switch (action) {
		case RESERVE1:
			break;
		case RESERVE2:
			break;
		case COMMIT:
			ret = set_secWPAxCipherSuite(wl_index, (int)mhtol(var_val, var_val_len));
			break;
		case ACTION:
			break;
		case FREE:
			break;
	}

	return (ret == 0) ? SNMP_ERROR_WRONGVALUE : 0;
}

int write_secWPAxKeyFormat(int action,
						   unsigned char *var_val, unsigned char varval_type, int var_val_len, unsigned char *statP, Oid * name)
{
	int ret = 1;
	int wl_index = name->name[(name->namelen - 1)];

	switch (action) {
		case RESERVE1:
			break;
		case RESERVE2:
			break;
		case COMMIT:
			ret = set_secWPAxKeyFormat(wl_index, (int)mhtol(var_val, var_val_len));
			break;
		case ACTION:
			break;
		case FREE:
			break;
	}

	return (ret == 0) ? SNMP_ERROR_WRONGVALUE : 0;
}

int write_secWPAxPreSharedKey(int action,
							  unsigned char *var_val, unsigned char varval_type, int var_val_len, unsigned char *statP, Oid * name)
{
	int ret = 1;
	int wl_index = name->name[(name->namelen - 1)];

	switch (action) {
		case RESERVE1:
			break;
		case RESERVE2:
			break;
		case COMMIT:
			ret = set_secWPAxPreSharedKey(wl_index, (char *)var_val, var_val_len);
			break;
		case ACTION:
			break;
		case FREE:
			break;
	}

	return (ret == 0) ? SNMP_ERROR_WRONGVALUE : 0;
}

unsigned char *
var_cjhvApSecwpaxConfigEntry(int *var_len, Oid *newoid, Oid *reqoid, int searchType, snmp_info_t *mesg, int (**write_method)())
{
    int column = newoid->name[(newoid->namelen - 1)];
    int result;
    int index = newoid->namelen++;
    int wl_index = 0;

	while (wl_index < 8) {
		newoid->name[index] = wl_index;
		result = compare(reqoid, newoid);
		if (((searchType == EXACT) && (result == 0)) || ((searchType == NEXT) && (result < 0))) {
			break;
		}
		wl_index++;
	}

	if (wl_index >= 8) {
		return (unsigned char *)NO_MIBINSTANCE;
	}

    switch (column) {
	case I_cjhvApSecwpaxConfigSSIDIndex:
		public_mib_buffer.gb_long = wl_index + 1;
		*var_len = sizeof(long);
		*write_method = 0;
		return (unsigned char *)&public_mib_buffer.gb_long;
	case I_cjhvApSecwpaxSecSSID:
		get_wlanSSID(wl_index, public_mib_buffer.gb_string, sizeof(public_mib_buffer.gb_string));
		*var_len = strlen(public_mib_buffer.gb_string);
		*write_method = 0;
		return (unsigned char *)public_mib_buffer.gb_string;
	case I_cjhvApSecwpaxAuthMode:
		public_mib_buffer.gb_long = get_secWPAxAuthMode(wl_index);
		*var_len = sizeof(long);
		*write_method = (int (*)())&write_secWPAxAuthMode;
		return (unsigned char *)&public_mib_buffer.gb_long;
	case I_cjhvApSecwpaxCipherSuite:
		public_mib_buffer.gb_long = get_secWPAxCipherSuite(wl_index);
		*var_len = sizeof(long);
		*write_method = (int (*)())&write_secWPAxCipherSuite;
		return (unsigned char *)&public_mib_buffer.gb_long;
	case I_cjhvApSecwpaxKeyFormat:
		public_mib_buffer.gb_long = get_secWPAxKeyFormat(wl_index);
		*var_len = sizeof(long);
		*write_method = (int (*)())&write_secWPAxKeyFormat;
		return (unsigned char *)&public_mib_buffer.gb_long;
	case I_cjhvApSecwpaxPreSharedKey:
		get_secWPAxPreSharedKey(wl_index, public_mib_buffer.gb_string, sizeof(public_mib_buffer.gb_string));
		*var_len = strlen(public_mib_buffer.gb_string);
		*write_method = (int (*)())&write_secWPAxPreSharedKey;
		return (unsigned char *)public_mib_buffer.gb_string;
        default:
            return NO_MIBINSTANCE;
    }
    return NO_MIBINSTANCE;
}
/* ======================= WPA SECURITY INFO ================================= */

/* cjhvApSecwpaxConfigEntry_tree */
static oid cjhvApSecwpaxConfigEntry_oid[] = { O_cjhvApSecwpaxConfigEntry };
static Object cjhvApSecwpaxConfigEntry_variables[] = {
    { SNMP_INTEGER, (RWRITE| COLUMN), var_cjhvApSecwpaxConfigEntry,
                {1, { I_cjhvApSecwpaxConfigSSIDIndex }}},
    { SNMP_STRING, (RWRITE| COLUMN), var_cjhvApSecwpaxConfigEntry,
                {1, { I_cjhvApSecwpaxSecSSID }}},
    { SNMP_INTEGER, (RWRITE| COLUMN), var_cjhvApSecwpaxConfigEntry,
                {1, { I_cjhvApSecwpaxAuthMode }}},
    { SNMP_INTEGER, (RWRITE| COLUMN), var_cjhvApSecwpaxConfigEntry,
                {1, { I_cjhvApSecwpaxCipherSuite }}},
    { SNMP_INTEGER, (RWRITE| COLUMN), var_cjhvApSecwpaxConfigEntry,
                {1, { I_cjhvApSecwpaxKeyFormat }}},
    { SNMP_STRING, (RWRITE| COLUMN), var_cjhvApSecwpaxConfigEntry,
                {1, { I_cjhvApSecwpaxPreSharedKey }}},
    { 0 }
    };
static SubTree cjhvApSecwpaxConfigEntry_tree =  { NULL, cjhvApSecwpaxConfigEntry_variables,
	        (sizeof(cjhvApSecwpaxConfigEntry_oid)/sizeof(oid)), cjhvApSecwpaxConfigEntry_oid};
/* cjhvApSecwpaxConfigEntry_tree */

/* ======================= WPA-Mixed SECURITY INFO ================================= */
int write_secWPAmixAuthMode(int action,
							unsigned char *var_val, unsigned char varval_type, int var_val_len, unsigned char *statP, Oid * name)
{
	int ret = 1;
	int wl_index = name->name[(name->namelen - 1)];

	switch (action) {
		case RESERVE1:
			break;
		case RESERVE2:
			break;
		case COMMIT:
			ret = set_secWPAmixAuthMode(wl_index, (int)mhtol(var_val, var_val_len));
			break;
		case ACTION:
			break;
		case FREE:
			break;
	}

	return (ret == 0) ? SNMP_ERROR_WRONGVALUE : 0;
}

int write_secWPAmixCipherSuite(int action,
							   unsigned char *var_val, unsigned char varval_type, int var_val_len, unsigned char *statP, Oid * name)
{
	int ret = 1;
	int wl_index = name->name[(name->namelen - 1)];

	switch (action) {
		case RESERVE1:
			break;
		case RESERVE2:
			break;
		case COMMIT:
			ret = set_secWPAmixCipherSuite(wl_index, (int)mhtol(var_val, var_val_len));
			break;
		case ACTION:
			break;
		case FREE:
			break;
	}

	return (ret == 0) ? SNMP_ERROR_WRONGVALUE : 0;
}

int write_secWPAmix2CipherSuite(int action,
								unsigned char *var_val, unsigned char varval_type, int var_val_len, unsigned char *statP, Oid * name)
{
	int ret = 1;
	int wl_index = name->name[(name->namelen - 1)];

	switch (action) {
		case RESERVE1:
			break;
		case RESERVE2:
			break;
		case COMMIT:
			ret = set_secWPAmix2CipherSuite(wl_index, (int)mhtol(var_val, var_val_len));
			break;
		case ACTION:
			break;
		case FREE:
			break;
	}

	return (ret == 0) ? SNMP_ERROR_WRONGVALUE : 0;
}

int write_secWPAmixKeyFormat(int action,
							 unsigned char *var_val, unsigned char varval_type, int var_val_len, unsigned char *statP, Oid * name)
{
	int ret = 1;
	int wl_index = name->name[(name->namelen - 1)];

	switch (action) {
		case RESERVE1:
			break;
		case RESERVE2:
			break;
		case COMMIT:
			ret = set_secWPAmixKeyFormat(wl_index, (int)mhtol(var_val, var_val_len));
			break;
		case ACTION:
			break;
		case FREE:
			break;
	}

	return (ret == 0) ? SNMP_ERROR_WRONGVALUE : 0;
}

int write_secWPAmixPreSharedKey(int action,
								unsigned char *var_val, unsigned char varval_type, int var_val_len, unsigned char *statP, Oid * name)
{
	int ret = 1;
	int wl_index = name->name[(name->namelen - 1)];

	switch (action) {
	case RESERVE1:
		break;
	case RESERVE2:
		break;
	case COMMIT:
		ret = set_secWPAmixPreSharedKey(wl_index, (char *)var_val, var_val_len);
		break;
	case ACTION:
		break;
	case FREE:
		break;
	}

	return (ret == 0) ? SNMP_ERROR_WRONGVALUE : 0;
}

unsigned char *
var_cjhvApSecwpamixConfigEntry(int *var_len, Oid *newoid, Oid *reqoid, int searchType, snmp_info_t *mesg, int (**write_method)())
{
	int column = newoid->name[(newoid->namelen - 1)];
	int result;

	int index = newoid->namelen++;
	int wl_index = 0;

	while (wl_index < 8) {
		newoid->name[index] = wl_index;
		result = compare(reqoid, newoid);
		if (((searchType == EXACT) && (result == 0)) || ((searchType == NEXT) && (result < 0))) {
			break;
		}
		wl_index++;
	}

	if (wl_index >= 8) {
		return (unsigned char *)NO_MIBINSTANCE;
	}

    switch (column) {
	case I_cjhvApSecwpamixConfigSSIDIndex:
		public_mib_buffer.gb_long = wl_index + 1;
		*var_len = sizeof(long);
		*write_method = 0;
		return (unsigned char *)&public_mib_buffer.gb_long;
	case I_cjhvApSecwpamixSecSSID:
		get_wlanSSID(wl_index, public_mib_buffer.gb_string, sizeof(public_mib_buffer.gb_string));
		*var_len = strlen(public_mib_buffer.gb_string);
		*write_method = 0;
		return (unsigned char *)public_mib_buffer.gb_string;
	case I_cjhvApSecwpamixAuthMode:
		public_mib_buffer.gb_long = get_secWPAmixAuthMode(wl_index);
		*var_len = sizeof(long);
		*write_method = (int (*)())&write_secWPAmixAuthMode;
		return (unsigned char *)&public_mib_buffer.gb_long;
	case I_cjhvApSecwpamixCipherSuite:
		public_mib_buffer.gb_long = get_secWPAmixCipherSuite(wl_index);
		*var_len = sizeof(long);
		*write_method = (int (*)())&write_secWPAmixCipherSuite;
		return (unsigned char *)&public_mib_buffer.gb_long;
	case I_cjhvApSecwpamix2CipherSuite:
		public_mib_buffer.gb_long = get_secWPAmix2CipherSuite(wl_index);
		*var_len = sizeof(long);
		*write_method = (int (*)())&write_secWPAmix2CipherSuite;
		return (unsigned char *)&public_mib_buffer.gb_long;
	case I_cjhvApSecwpamixKeyFormat:
		public_mib_buffer.gb_long = get_secWPAmixKeyFormat(wl_index);
		*var_len = sizeof(long);
		*write_method = (int (*)())&write_secWPAmixKeyFormat;
		return (unsigned char *)&public_mib_buffer.gb_long;
	case I_cjhvApSecwpamixPreSharedKey:
		get_secWPAmixPreSharedKey(wl_index, public_mib_buffer.gb_string, sizeof(public_mib_buffer.gb_string));
		*var_len = strlen(public_mib_buffer.gb_string);
		*write_method = (int (*)())&write_secWPAmixPreSharedKey;
		return (unsigned char *)public_mib_buffer.gb_string;
        default:
            return NO_MIBINSTANCE;
    }
    return NO_MIBINSTANCE;
}
/* ======================= WPA-Mixed SECURITY INFO ================================= */

/* cjhvApSecwpamixConfigEntry_tree */
static oid cjhvApSecwpamixConfigEntry_oid[] = { O_cjhvApSecwpamixConfigEntry };
static Object cjhvApSecwpamixConfigEntry_variables[] = {
    { SNMP_INTEGER, (RWRITE| COLUMN), var_cjhvApSecwpamixConfigEntry,
                {1, { I_cjhvApSecwpamixConfigSSIDIndex }}},
    { SNMP_STRING, (RWRITE| COLUMN), var_cjhvApSecwpamixConfigEntry,
                {1, { I_cjhvApSecwpamixSecSSID }}},
    { SNMP_INTEGER, (RWRITE| COLUMN), var_cjhvApSecwpamixConfigEntry,
                {1, { I_cjhvApSecwpamixAuthMode }}},
    { SNMP_INTEGER, (RWRITE| COLUMN), var_cjhvApSecwpamixConfigEntry,
                {1, { I_cjhvApSecwpamixCipherSuite }}},
    { SNMP_INTEGER, (RWRITE| COLUMN), var_cjhvApSecwpamixConfigEntry,
                {1, { I_cjhvApSecwpamix2CipherSuite }}},
    { SNMP_INTEGER, (RWRITE| COLUMN), var_cjhvApSecwpamixConfigEntry,
                {1, { I_cjhvApSecwpamixKeyFormat }}},
    { SNMP_STRING, (RWRITE| COLUMN), var_cjhvApSecwpamixConfigEntry,
                {1, { I_cjhvApSecwpamixPreSharedKey }}},
    { 0 }
    };
static SubTree cjhvApSecwpamixConfigEntry_tree =  { NULL, cjhvApSecwpamixConfigEntry_variables,
	        (sizeof(cjhvApSecwpamixConfigEntry_oid)/sizeof(oid)), cjhvApSecwpamixConfigEntry_oid};
/* cjhvApSecwpamixConfigEntry_tree */

/* ======================= PORT CONFIG ================================= */
int write_cjhvApDevPortMode(int action,
	unsigned char *var_val, unsigned char varval_type, int var_val_len,
	unsigned char *statP, Oid *name)
{
    int ret = 1;

    switch (action) {
    	case RESERVE1:
			break;
		case RESERVE2:
			break;
		case COMMIT:
			ret = set_devicePortMode((int)mhtol(var_val, var_val_len));
			break;
		case ACTION:
			break;
		case FREE:
			break;
    }

   return (ret == 0) ? SNMP_ERROR_WRONGVALUE : 0;
}

unsigned char *
var_cjhvApDevPortMode(int *var_len, snmp_info_t *mesg,
        int (**write_method)())
{
	public_mib_buffer.gb_long = get_devicePortMode();
	*write_method = (int (*)())&write_cjhvApDevPortMode;
	*var_len = sizeof(long);

	return (unsigned char *)&public_mib_buffer.gb_long;
}

int write_DevicePortNego(int action, unsigned char *var_val, unsigned char varval_type, int var_val_len, unsigned char *statP, Oid * name)
{
	int port_index = name->name[(name->namelen - 1)];
	int ret = 1;

	switch (action) {
		case RESERVE1:
			break;
		case RESERVE2:
			break;
		case COMMIT:
			ret = set_DevicePortNego((port_index + 1), (int)mhtol(var_val, var_val_len));
			break;
		case ACTION:
			break;
		case FREE:
			break;
	}

	return (ret == 0)? SNMP_ERROR_WRONGVALUE : 0;
}

int write_DevicePortSpeed(int action, unsigned char *var_val, unsigned char varval_type, int var_val_len, unsigned char *statP, Oid * name)
{
	int port_index = name->name[(name->namelen - 1)];
	int ret = 1;

	switch (action) {
		case RESERVE1:
			break;
		case RESERVE2:
			break;
		case COMMIT:
			ret = set_DevicePortSpeed((port_index + 1), (int)mhtol(var_val, var_val_len));
			break;
		case ACTION:
			break;
		case FREE:
			break;
	}

	return (ret == 0)? SNMP_ERROR_WRONGVALUE : 0;
}

int write_DevicePortDuplex(int action, unsigned char *var_val, unsigned char varval_type, int var_val_len, unsigned char *statP, Oid * name)
{
	int port_index = name->name[(name->namelen - 1)];
	int ret = 1;

	switch (action) {
		case RESERVE1:
			break;
		case RESERVE2:
			break;
		case COMMIT:
			ret = set_DevicePortDuplex((port_index + 1), (int)mhtol(var_val, var_val_len));
			break;
		case ACTION:
			break;
		case FREE:
			break;
	}

	return (ret == 0)? SNMP_ERROR_WRONGVALUE : 0;
}

int write_DevicePortOnOff(int action, unsigned char *var_val, unsigned char varval_type, int var_val_len, unsigned char *statP, Oid * name)
{
	int port_index = name->name[(name->namelen - 1)];
	int ret = 1;

	switch (action) {
		case RESERVE1:
			break;
		case RESERVE2:
			break;
		case COMMIT:
			ret = set_DevicePortOnOff((port_index + 1), (int)mhtol(var_val, var_val_len));
			break;
		case ACTION:
			break;
		case FREE:
			break;
	}

	return (ret == 0)? SNMP_ERROR_WRONGVALUE : 0;
}

unsigned char *
var_cjhvApDevPortEntry(int *var_len,
        Oid *newoid, Oid *reqoid, int searchType,
        snmp_info_t *mesg, int (**write_method)())
{
	int column = newoid->name[(newoid->namelen - 1)];
	int result;
	int index = newoid->namelen++;
	int port_index = 0;

	while (port_index < PH_MAXPORT) {
		newoid->name[index] = port_index;
		result = compare(reqoid, newoid);
		if (((searchType == EXACT) && (result == 0)) || ((searchType == NEXT) && (result < 0))) {
			break;
		}
		port_index++;
	}

 	if (port_index >= PH_MAXPORT) {
		return (unsigned char *)NO_MIBINSTANCE;
	}

    switch (column) {
	case I_cjhvApDevPortIndex:
		public_mib_buffer.gb_long = port_index + 1;
		*write_method = 0;
		*var_len = sizeof(long);
		return (unsigned char *)&public_mib_buffer.gb_long;
	case I_cjhvApDevPortNumber:
		public_mib_buffer.gb_long = port_index + 1;
		*write_method = 0;
		*var_len = sizeof(long);
		return (unsigned char *)&public_mib_buffer.gb_long;
	case I_cjhvApDevPortName:
		get_DevportName(port_index + 1, public_mib_buffer.gb_string, sizeof(public_mib_buffer.gb_string));
		*var_len = strlen(public_mib_buffer.gb_string);
		*write_method = 0;
		return (unsigned char *)public_mib_buffer.gb_string;
	case I_cjhvApDevPortNego:
		public_mib_buffer.gb_long = get_DevicePortNego(port_index + 1);
		*write_method = (int (*)())&write_DevicePortNego;
		*var_len = sizeof(long);
		return (unsigned char *)&public_mib_buffer.gb_long;
	case I_cjhvApDevPortSpeed:
		public_mib_buffer.gb_long = get_DevicePortSpeed(port_index + 1);
		*write_method = (int (*)())&write_DevicePortSpeed;
		*var_len = sizeof(long);
		return (unsigned char *)&public_mib_buffer.gb_long;
	case I_cjhvApDevPortDuplex:
		public_mib_buffer.gb_long = get_DevicePortDuplex(port_index + 1);
		*var_len = sizeof(long);
		*write_method = (int (*)())&write_DevicePortDuplex;
		return (unsigned char *)&public_mib_buffer.gb_long;
	case I_cjhvApDevPortOnOff:
		public_mib_buffer.gb_long = get_DevicePortOnOff(port_index + 1);
		*var_len = sizeof(long);
		*write_method = (int (*)())&write_DevicePortOnOff;
		return (unsigned char *)&public_mib_buffer.gb_long;
	case I_cjhvApDevPortStatus:
		public_mib_buffer.gb_long = get_DevicePortStatus(port_index + 1);
		*var_len = sizeof(long);
		*write_method = 0;
		return (unsigned char *)&public_mib_buffer.gb_long;
        default:
            return NO_MIBINSTANCE;
    }
}
/* ======================= PORT CONFIG ================================= */

/* cjhvApPortConfig_tree */
static oid cjhvApPortConfig_oid[] = { O_cjhvApPortConfig };
static Object cjhvApPortConfig_variables[] = {
    { SNMP_INTEGER, (RWRITE| SCALAR), var_cjhvApDevPortMode,
                 {2, { I_cjhvApDevPortMode, 0 }}},
    { SNMP_INTEGER, (RONLY| COLUMN), var_cjhvApDevPortEntry,
                {3, { I_cjhvApDevPortTable, I_cjhvApDevPortEntry, I_cjhvApDevPortIndex }}},
    { SNMP_INTEGER, (RONLY| COLUMN), var_cjhvApDevPortEntry,
                {3, { I_cjhvApDevPortTable, I_cjhvApDevPortEntry, I_cjhvApDevPortNumber }}},
    { SNMP_STRING, (RONLY| COLUMN), var_cjhvApDevPortEntry,
                {3, { I_cjhvApDevPortTable, I_cjhvApDevPortEntry, I_cjhvApDevPortName }}},
    { SNMP_INTEGER, (RWRITE| COLUMN), var_cjhvApDevPortEntry,
                {3, { I_cjhvApDevPortTable, I_cjhvApDevPortEntry, I_cjhvApDevPortNego }}},
    { SNMP_INTEGER, (RWRITE| COLUMN), var_cjhvApDevPortEntry,
                {3, { I_cjhvApDevPortTable, I_cjhvApDevPortEntry, I_cjhvApDevPortSpeed }}},
    { SNMP_INTEGER, (RWRITE| COLUMN), var_cjhvApDevPortEntry,
                {3, { I_cjhvApDevPortTable, I_cjhvApDevPortEntry, I_cjhvApDevPortDuplex }}},
    { SNMP_INTEGER, (RWRITE| COLUMN), var_cjhvApDevPortEntry,
                {3, { I_cjhvApDevPortTable, I_cjhvApDevPortEntry, I_cjhvApDevPortOnOff }}},
    { SNMP_INTEGER, (RWRITE| COLUMN), var_cjhvApDevPortEntry,
                {3, { I_cjhvApDevPortTable, I_cjhvApDevPortEntry, I_cjhvApDevPortStatus }}},
    { 0 }
    };
static SubTree cjhvApPortConfig_tree =  { NULL, cjhvApPortConfig_variables,
	        (sizeof(cjhvApPortConfig_oid)/sizeof(oid)), cjhvApPortConfig_oid};
/* cjhvApPortConfig_tree */

/* ======================= IGMP CONFIG ================================= */
int	write_cjhvApIgmpIpMulticastEnable(int action,
	unsigned char *var_val, unsigned char varval_type, int var_val_len,
	unsigned char *statP, Oid *name)
{
    int ret = 1;

    switch (action) {
    	case RESERVE1:
        	break;
    	case RESERVE2:
        	break;
    	case COMMIT:
    		ret = set_IgmpMulticastEnable((int)mhtol(var_val, var_val_len));
       		break;
    	case ACTION:
        	break;
    	case FREE:
        	break;
    }

    return (ret == 0) ? SNMP_ERROR_WRONGVALUE : 0;
}

unsigned char *
var_cjhvApIgmpIpMulticastEnable(int *var_len, snmp_info_t *mesg,
        int (**write_method)())
{
    public_mib_buffer.gb_long = get_IgmpMulticastEnable();
    *write_method = (int (*)())&write_cjhvApIgmpIpMulticastEnable;
    *var_len = sizeof(long);

    return (unsigned char *)&public_mib_buffer.gb_long;
}

unsigned char *
var_cjhvApIgmpSelectMode(int *var_len, snmp_info_t *mesg,
        int (**write_method)())
{
    public_mib_buffer.gb_long = get_IgmpSelectMode();
    *write_method = 0;
    *var_len = sizeof(long);

    return (unsigned char *)&public_mib_buffer.gb_long;
}

int	write_cjhvApIgmpFastLeaveEnable(int action,
	unsigned char *var_val, unsigned char varval_type, int var_val_len,
	unsigned char *statP, Oid *name)
{
    int ret = 1;

    switch (action) {
    	case RESERVE1:
        	break;
    	case RESERVE2:
        	break;
    	case COMMIT:
    		ret = set_IgmpFastLeaveEnable((int)mhtol(var_val, var_val_len));
       	break;
    	case ACTION:
        	break;
    	case FREE:
        	break;
    }

    return (ret == 0) ? SNMP_ERROR_WRONGVALUE : 0;
}

unsigned char *
var_cjhvApIgmpFastLeaveEnable(int *var_len, snmp_info_t *mesg,
        int (**write_method)())
{
    public_mib_buffer.gb_long = get_IgmpFastLeaveEnable();
    *write_method = (int (*)())&write_cjhvApIgmpFastLeaveEnable;
    *var_len = sizeof(long);

    return (unsigned char *)&public_mib_buffer.gb_long;
}

int write_cjhvApIgmpProxyMemberExpireTime(int action,
	unsigned char *var_val, unsigned char varval_type, int var_val_len,
	unsigned char *statP, Oid *name)
{
    int ret = 1;

    switch (action) {
    	case RESERVE1:
        	break;
    	case RESERVE2:
        	break;
    	case COMMIT:
    		ret = set_IgmpProxyMemberExpireTime((int)mhtol(var_val, var_val_len));
       	break;
    	case ACTION:
        	break;
    	case FREE:
        	break;
    }

    return (ret == 0) ? SNMP_ERROR_WRONGVALUE : 0;
}

unsigned char *
var_cjhvApIgmpProxyMemberExpireTime(int *var_len, snmp_info_t *mesg,
        int (**write_method)())
{
    public_mib_buffer.gb_long = get_IgmpProxyMemberExpireTime();
    *write_method = (int (*)())&write_cjhvApIgmpProxyMemberExpireTime;
    *var_len = sizeof(long);

    return (unsigned char *)&public_mib_buffer.gb_long;
}
/* ======================= IGMP CONFIG ================================= */

/* cjhvApIgmpConfig_tree */
static oid cjhvApIgmpConfig_oid[] = { O_cjhvApIgmpConfig };
static Object cjhvApIgmpConfig_variables[] = {
    { SNMP_INTEGER, (RWRITE| SCALAR), var_cjhvApIgmpIpMulticastEnable,
                 {2, { I_cjhvApIgmpIpMulticastEnable, 0 }}},
    { SNMP_INTEGER, (RONLY| SCALAR), var_cjhvApIgmpSelectMode,
                 {2, { I_cjhvApIgmpSelectMode, 0 }}},
    { SNMP_INTEGER, (RWRITE| SCALAR), var_cjhvApIgmpFastLeaveEnable,
                 {2, { I_cjhvApIgmpFastLeaveEnable, 0 }}},
    { SNMP_INTEGER, (RWRITE| SCALAR), var_cjhvApIgmpProxyMemberExpireTime,
                 {2, { I_cjhvApIgmpProxyMemberExpireTime, 0 }}},
    { 0 }
    };
static SubTree cjhvApIgmpConfig_tree =  { NULL, cjhvApIgmpConfig_variables,
	        (sizeof(cjhvApIgmpConfig_oid)/sizeof(oid)), cjhvApIgmpConfig_oid};
/* cjhvApIgmpConfig_tree */

/* ======================= SNMP CONFIG ================================= */
int	write_cjhvApSnmpEnable(int action,
	unsigned char *var_val, unsigned char varval_type, int var_val_len,
	unsigned char *statP, Oid *name)
{
    int ret = 1;

    switch (action) {
    	case RESERVE1:
        	break;
    	case RESERVE2:
        	break;
    	case COMMIT:
    		ret = set_snmpEnable((int)mhtol(var_val, var_val_len));
			break;
    	case ACTION:
        	break;
    	case FREE:
        	break;
    }

	return (ret == 0) ? SNMP_ERROR_WRONGVALUE : 0;
}

unsigned char *
var_cjhvApSnmpEnable(int *var_len, snmp_info_t *mesg,
        int (**write_method)())
{
    public_mib_buffer.gb_long = get_snmpEnable();
    *write_method = (int (*)())&write_cjhvApSnmpEnable;
    *var_len = sizeof(long);

    return (unsigned char *)&public_mib_buffer.gb_long;
}

int	write_cjhvApSnmpRoCommunityName(int action,
	unsigned char *var_val, unsigned char varval_type, int var_val_len,
	unsigned char *statP, Oid *name)
{
	int ret = 1;

    switch (action) {
    	case RESERVE1:
        	break;
    	case RESERVE2:
        	break;
    	case COMMIT:
    		ret = set_getCommunityName(var_val, var_val_len);
			break;
		case ACTION:
			break;
    	case FREE:
        	break;
    }

    return (ret == 0) ? SNMP_ERROR_WRONGVALUE : 0;
}

unsigned char *
var_cjhvApSnmpRoCommunityName(int *var_len, snmp_info_t *mesg,
        int (**write_method)())
{
    get_getCommunityName(public_mib_buffer.gb_string, sizeof(public_mib_buffer.gb_string));
    *var_len = strlen(public_mib_buffer.gb_string);
    *write_method = (int (*)())&write_cjhvApSnmpRoCommunityName;

    return (unsigned char *)public_mib_buffer.gb_string;
}

int	write_cjhvApSnmpRwCommunityName(int action,
	unsigned char *var_val, unsigned char varval_type, int var_val_len,
	unsigned char *statP, Oid *name)
{
	int ret = 1;

	switch (action) {
		case RESERVE1:
			break;
		case RESERVE2:
			break;
		case COMMIT:
			ret = set_setCommunityName(var_val, var_val_len);
			break;
		case ACTION:
			break;
		case FREE:
			break;
    }

    return (ret == 0) ? SNMP_ERROR_WRONGVALUE : 0;
}

unsigned char *
var_cjhvApSnmpRwCommunityName(int *var_len, snmp_info_t *mesg,
        int (**write_method)())
{
    get_setCommunityName(public_mib_buffer.gb_string, sizeof(public_mib_buffer.gb_string));
    *var_len = strlen(public_mib_buffer.gb_string);
    *write_method = (int (*)())&write_cjhvApSnmpRwCommunityName;

    return (unsigned char *)public_mib_buffer.gb_string;
}

int	write_cjhvApSnmpListenPort(int action,
	unsigned char *var_val, unsigned char varval_type, int var_val_len,
	unsigned char *statP, Oid *name)
{
	int ret = 1;

	switch (action) {
		case RESERVE1:
			break;
		case RESERVE2:
			break;
		case COMMIT:
			ret = set_snmpListenport((int)mhtol(var_val, var_val_len));
			break;
		case ACTION:
			break;
		case FREE:
			break;
    }

    return (ret == 0) ? SNMP_ERROR_WRONGVALUE : 0;
}

unsigned char *
var_cjhvApSnmpListenPort(int *var_len, snmp_info_t *mesg,
        int (**write_method)())
{
    public_mib_buffer.gb_long = get_snmpListenport();
    *write_method = (int (*)())&write_cjhvApSnmpListenPort;
    *var_len = sizeof(long);

    return (unsigned char *)&public_mib_buffer.gb_long;
}

int	write_cjhvApSnmpTrapEnable(int action,
	unsigned char *var_val, unsigned char varval_type, int var_val_len,
	unsigned char *statP, Oid *name)
{
	int ret = 1;

	switch (action) {
		case RESERVE1:
			break;
		case RESERVE2:
			break;
		case COMMIT:
			ret = set_TrapEnable((int)mhtol(var_val, var_val_len));
			break;
		case ACTION:
			break;
		case FREE:
			break;
    }

     return (ret == 0) ? SNMP_ERROR_WRONGVALUE : 0;
}

unsigned char *
var_cjhvApSnmpTrapEnable(int *var_len, snmp_info_t *mesg,
        int (**write_method)())
{
    public_mib_buffer.gb_long = get_TrapEnable();
    *write_method = (int (*)())&write_cjhvApSnmpTrapEnable;
    *var_len = sizeof(long);

    return (unsigned char *)&public_mib_buffer.gb_long;
}

int	write_cjhvApSnmpTrapCommunityName(int action,
	unsigned char *var_val, unsigned char varval_type, int var_val_len,
	unsigned char *statP, Oid *name)
{
	int ret = 1;

	switch (action) {
		case RESERVE1:
			break;
		case RESERVE2:
			break;
		case COMMIT:
			ret = set_snmpTrapCommunityName(var_val, var_val_len);
			break;
		case ACTION:
			break;
		case FREE:
			break;
    }

    return (ret == 0) ? SNMP_ERROR_WRONGVALUE : 0;
}

unsigned char *
var_cjhvApSnmpTrapCommunityName(int *var_len, snmp_info_t *mesg,
        int (**write_method)())
{
    get_snmpTrapCommunityName(public_mib_buffer.gb_string, sizeof(public_mib_buffer.gb_string));
    *var_len = strlen(public_mib_buffer.gb_string);
    *write_method = (int (*)())&write_cjhvApSnmpTrapCommunityName;

    return (unsigned char *)public_mib_buffer.gb_string;
}

int	write_cjhvApSnmpTrapDestinationIp(int action,
	unsigned char *var_val, unsigned char varval_type, int var_val_len,
	unsigned char *statP, Oid *name)
{
	int ret = 1;

	switch (action) {
		case RESERVE1:
			break;
		case RESERVE2:
			break;
		case COMMIT:
			ret = set_snmpTrapDestination(var_val, var_val_len);
			break;
		case ACTION:
			break;
		case FREE:
			break;
    }

   return (ret == 0) ? SNMP_ERROR_WRONGVALUE : 0;
}

unsigned char *
var_cjhvApSnmpTrapDestinationIp(int *var_len, snmp_info_t *mesg,
        int (**write_method)())
{
    get_snmpTrapDestination(public_mib_buffer.gb_string, sizeof(public_mib_buffer.gb_string));
    *var_len = strlen(public_mib_buffer.gb_string);
    *write_method = (int (*)())&write_cjhvApSnmpTrapDestinationIp;

    return (unsigned char *)public_mib_buffer.gb_string;
}

int	write_cjhvApSnmpTrapDestinationPort(int action,
	unsigned char *var_val, unsigned char varval_type, int var_val_len,
	unsigned char *statP, Oid *name)
{
	int ret = 1;

	switch (action) {
		case RESERVE1:
			break;
		case RESERVE2:
			break;
		case COMMIT:
			ret = set_snmpTrapPort((int)mhtol(var_val, var_val_len));
			break;
		case ACTION:
			break;
		case FREE:
			break;
    }

   return (ret == 0) ? SNMP_ERROR_WRONGVALUE : 0;
}

unsigned char *
var_cjhvApSnmpTrapDestinationPort(int *var_len, snmp_info_t *mesg,
        int (**write_method)())
{
    public_mib_buffer.gb_long = get_snmpTrapPort();
    *write_method = (int (*)())&write_cjhvApSnmpTrapDestinationPort;
    *var_len = sizeof(long);

    return (unsigned char *)&public_mib_buffer.gb_long;
}
/* ======================= SNMP CONFIG ================================= */

/* cjhvApSnmpConfig_tree */
static oid cjhvApSnmpConfig_oid[] = { O_cjhvApSnmpConfig };
static Object cjhvApSnmpConfig_variables[] = {
    { SNMP_INTEGER, (RWRITE| SCALAR), var_cjhvApSnmpEnable,
                 {2, { I_cjhvApSnmpEnable, 0 }}},
    { SNMP_STRING, (RWRITE| SCALAR), var_cjhvApSnmpRoCommunityName,
                 {2, { I_cjhvApSnmpRoCommunityName, 0 }}},
    { SNMP_STRING, (RWRITE| SCALAR), var_cjhvApSnmpRwCommunityName,
                 {2, { I_cjhvApSnmpRwCommunityName, 0 }}},
    { SNMP_INTEGER, (RWRITE| SCALAR), var_cjhvApSnmpListenPort,
                 {2, { I_cjhvApSnmpListenPort, 0 }}},
    { SNMP_INTEGER, (RWRITE| SCALAR), var_cjhvApSnmpTrapEnable,
                 {2, { I_cjhvApSnmpTrapEnable, 0 }}},
    { SNMP_STRING, (RWRITE| SCALAR), var_cjhvApSnmpTrapCommunityName,
                 {2, { I_cjhvApSnmpTrapCommunityName, 0 }}},
    { SNMP_STRING, (RWRITE| SCALAR), var_cjhvApSnmpTrapDestinationIp,
                 {2, { I_cjhvApSnmpTrapDestinationIp, 0 }}},
    { SNMP_INTEGER, (RWRITE| SCALAR), var_cjhvApSnmpTrapDestinationPort,
                 {2, { I_cjhvApSnmpTrapDestinationPort, 0 }}},
    { 0 }
    };
static SubTree cjhvApSnmpConfig_tree =  { NULL, cjhvApSnmpConfig_variables,
	        (sizeof(cjhvApSnmpConfig_oid)/sizeof(oid)), cjhvApSnmpConfig_oid};
/* cjhvApSnmpConfig_tree */

/* ======================= SYSLOG CONFIG ================================= */
int	write_cjhvApSysLogEnable(int action,
	unsigned char *var_val, unsigned char varval_type, int var_val_len,
	unsigned char *statP, Oid *name)
{
    int ret = 1;

    switch (action) {
    	case RESERVE1:
        	break;
    	case RESERVE2:
        	break;
    	case COMMIT:
    		ret = set_sysLogEnable((int)mhtol(var_val, var_val_len));
       	break;
    	case ACTION:
        	break;
    	case FREE:
        	break;
    }

    return (ret == 0) ? SNMP_ERROR_WRONGVALUE : 0;
}

unsigned char *
var_cjhvApSysLogEnable(int *var_len, snmp_info_t *mesg,
        int (**write_method)())
{
    public_mib_buffer.gb_long = get_sysLogEnable();
    *write_method = (int (*)())&write_cjhvApSysLogEnable;
    *var_len = sizeof(long);

    return (unsigned char *)&public_mib_buffer.gb_long;
}

int	write_cjhvApSysLogRemoteLogEnable(int action,
	unsigned char *var_val, unsigned char varval_type, int var_val_len,
	unsigned char *statP, Oid *name)
{
    int ret = 1;

	switch (action) {
		case RESERVE1:
			break;
		case RESERVE2:
			break;
		case COMMIT:
			ret = set_sysLogRemoteLogEnable((int)mhtol(var_val, var_val_len));
			break;
		case ACTION:
			break;
		case FREE:
			break;
	}

	return (ret == 0) ? SNMP_ERROR_WRONGVALUE : 0;
}

unsigned char *
var_cjhvApSysLogRemoteLogEnable(int *var_len, snmp_info_t *mesg,
        int (**write_method)())
{
    public_mib_buffer.gb_long = get_sysLogRemoteLogEnable();
    *write_method = (int (*)())&write_cjhvApSysLogRemoteLogEnable;
    *var_len = sizeof(long);

    return (unsigned char *)&public_mib_buffer.gb_long;
}

int	write_cjhvApSysLogRemoteLogServer(int action,
	unsigned char *var_val, unsigned char varval_type, int var_val_len,
	unsigned char *statP, Oid *name)
{
	int ret = 1;

	switch (action) {
		case RESERVE1:
			break;
		case RESERVE2:
			break;
		case COMMIT:
			ret = set_sysLogRemoteLogServer(var_val, var_val_len);
			break;
		case ACTION:
			break;
		case FREE:
			break;
    }

    return (ret == 0) ? SNMP_ERROR_WRONGVALUE : 0;
}

unsigned char *
var_cjhvApSysLogRemoteLogServer(int *var_len, snmp_info_t *mesg,
        int (**write_method)())
{
    get_sysLogRemoteLogServer(public_mib_buffer.gb_string, sizeof(public_mib_buffer.gb_string));
    *write_method = (int (*)())&write_cjhvApSysLogRemoteLogServer;
    *var_len = strlen(public_mib_buffer.gb_string);

    return (unsigned char *)public_mib_buffer.gb_string;
}
/* ======================= SYSLOG CONFIG ================================= */

/* cjhvApSyslogConfig_tree */
static oid cjhvApSyslogConfig_oid[] = { O_cjhvApSyslogConfig };
static Object cjhvApSyslogConfig_variables[] = {
    { SNMP_INTEGER, (RWRITE| SCALAR), var_cjhvApSysLogEnable,
                 {2, { I_cjhvApSysLogEnable, 0 }}},
    { SNMP_INTEGER, (RWRITE| SCALAR), var_cjhvApSysLogRemoteLogEnable,
                 {2, { I_cjhvApSysLogRemoteLogEnable, 0 }}},
    { SNMP_STRING, (RWRITE| SCALAR), var_cjhvApSysLogRemoteLogServer,
                 {2, { I_cjhvApSysLogRemoteLogServer, 0 }}},
    { 0 }
    };
static SubTree cjhvApSyslogConfig_tree =  { NULL, cjhvApSyslogConfig_variables,
	        (sizeof(cjhvApSyslogConfig_oid)/sizeof(oid)), cjhvApSyslogConfig_oid};
/* cjhvApSyslogConfig_tree */

/* ======================= NTP CONFIG ================================= */
int write_cjhvApNtpServer1Name(int action,
				   unsigned char *var_val, unsigned char varval_type, int var_val_len, unsigned char *statP, Oid * name)
{
	int ret = 1;

	switch (action) {
		case RESERVE1:
			break;
		case RESERVE2:
			break;
		case COMMIT:
			ret = set_ntpServer(1, var_val, var_val_len);
			break;
		case ACTION:
			break;
		case FREE:
			break;
	}

	return (ret == 0) ? SNMP_ERROR_WRONGVALUE : 0;
}

unsigned char *
var_cjhvApNtpServer1Name(int *var_len, snmp_info_t *mesg,
        int (**write_method)())
{
    get_ntpServer(1, public_mib_buffer.gb_string, sizeof(public_mib_buffer.gb_string));
    *write_method = (int (*)())&write_cjhvApNtpServer1Name;
    *var_len = strlen(public_mib_buffer.gb_string);

    return (unsigned char *)public_mib_buffer.gb_string;
}

int write_cjhvApNtpServer2Name(int action,
				   unsigned char *var_val, unsigned char varval_type, int var_val_len, unsigned char *statP, Oid * name)
{
	int ret = 1;

	switch (action) {
		case RESERVE1:
			break;
		case RESERVE2:
			break;
		case COMMIT:
			ret = set_ntpServer(2, var_val, var_val_len);
			break;
		case ACTION:
			break;
		case FREE:
			break;
	}

	return (ret == 0) ? SNMP_ERROR_WRONGVALUE : 0;
}

unsigned char *
var_cjhvApNtpServer2Name(int *var_len, snmp_info_t *mesg,
        int (**write_method)())
{
    get_ntpServer(2, public_mib_buffer.gb_string, sizeof(public_mib_buffer.gb_string));
    *write_method = (int (*)())&write_cjhvApNtpServer2Name;
    *var_len = strlen(public_mib_buffer.gb_string);

    return (unsigned char *)public_mib_buffer.gb_string;
}
/* ======================= NTP CONFIG ================================= */

/* cjhvApNtpConfig_tree */
static oid cjhvApNtpConfig_oid[] = { O_cjhvApNtpConfig };
static Object cjhvApNtpConfig_variables[] = {
    { SNMP_STRING, (RWRITE| SCALAR), var_cjhvApNtpServer1Name,
                 {2, { I_cjhvApNtpServer1Name, 0 }}},
    { SNMP_STRING, (RWRITE| SCALAR), var_cjhvApNtpServer2Name,
                 {2, { I_cjhvApNtpServer2Name, 0 }}},
    { 0 }
    };
static SubTree cjhvApNtpConfig_tree =  { NULL, cjhvApNtpConfig_variables,
	        (sizeof(cjhvApNtpConfig_oid)/sizeof(oid)), cjhvApNtpConfig_oid};
/* cjhvApNtpConfig_tree */

/* ======================= DMZ CONFIG ================================= */
int	write_cjhvApDmzEnable(int action,
	unsigned char *var_val, unsigned char varval_type, int var_val_len,
	unsigned char *statP, Oid *name)
{
	int ret = 1;

	switch (action) {
		case RESERVE1:
			break;
		case RESERVE2:
			break;
		case COMMIT:
			ret = set_dmzEnable((int)mhtol(var_val, var_val_len));
			break;
		case ACTION:
			break;
		case FREE:
			break;
    }

    return (ret == 0) ? SNMP_ERROR_WRONGVALUE : 0;
}

unsigned char *
var_cjhvApDmzEnable(int *var_len, snmp_info_t *mesg,
        int (**write_method)())
{
    public_mib_buffer.gb_long = get_dmzEnable();
    *write_method = (int (*)())&write_cjhvApDmzEnable;
    *var_len = sizeof(long);

    return (unsigned char *)&public_mib_buffer.gb_long;
}

int	write_cjhvApDmzType(int action,
	unsigned char *var_val, unsigned char varval_type, int var_val_len,
	unsigned char *statP, Oid *name)
{
    int ret = 1;

    switch (action) {
		case RESERVE1:
			break;
		case RESERVE2:
			break;
		case COMMIT:
			ret = set_dmzType((int)mhtol(var_val, var_val_len));
			break;
		case ACTION:
			break;
		case FREE:
			break;
    }

    return (ret == 0) ? SNMP_ERROR_WRONGVALUE : 0;
}

unsigned char *
var_cjhvApDmzType(int *var_len, snmp_info_t *mesg,
        int (**write_method)())
{
    public_mib_buffer.gb_long = get_dmzType();
    *write_method = (int (*)())&write_cjhvApDmzType;
    *var_len = sizeof(long);

    return (unsigned char *)&public_mib_buffer.gb_long;
}

int	write_cjhvApDmzMac(int action,
	unsigned char *var_val, unsigned char varval_type, int var_val_len,
	unsigned char *statP, Oid *name)
{

	int ret = 1;

	switch (action) {
		case RESERVE1:
			break;
		case RESERVE2:
			break;
		case COMMIT:
			ret = set_superdmzMac(var_val, var_val_len);
			break;
		case ACTION:
			break;
		case FREE:
			break;
    }

    return (ret == 0) ? SNMP_ERROR_WRONGVALUE : 0;
}

unsigned char *
var_cjhvApDmzMac(int *var_len, snmp_info_t *mesg,
        int (**write_method)())
{
    get_dmzMac(public_mib_buffer.gb_string, sizeof(public_mib_buffer.gb_string));
    *write_method = (int (*)())&write_cjhvApDmzMac;
    *var_len = 6;
	if (dmz_type == 0 || dmz_type == 2)
		return NULL;
    return (unsigned char *)public_mib_buffer.gb_string;
}

int	write_cjhvApDmzIp(int action,
	unsigned char *var_val, unsigned char varval_type, int var_val_len,
	unsigned char *statP, Oid *name)
{

	int ret = 1;

	switch (action) {
		case RESERVE1:
			break;
		case RESERVE2:
			break;
		case COMMIT:
			ret = set_dmzIpAddress(var_val);
			break;
		case ACTION:
			break;
		case FREE:
			break;
    }

    return (ret == 0) ? SNMP_ERROR_WRONGVALUE : 0;
}

unsigned char *
var_cjhvApDmzIp(int *var_len, snmp_info_t *mesg,
        int (**write_method)())
{
    get_dmzIpAddress(&public_mib_buffer.gb_ip_address);
    *write_method = (int (*)())&write_cjhvApDmzIp;
    *var_len = sizeof(public_mib_buffer.gb_ip_address);

	if (dmz_type == 0 || dmz_type == 1)
		return NULL;

    return (unsigned char *)&public_mib_buffer.gb_ip_address;
}
/* ======================= DMZ CONFIG ================================= */

/* cjhvApDmzInfo_tree */
static oid cjhvApDmzInfo_oid[] = { O_cjhvApDmzInfo };
static Object cjhvApDmzInfo_variables[] = {
    { SNMP_INTEGER, (RWRITE| SCALAR), var_cjhvApDmzEnable,
                 {2, { I_cjhvApDmzEnable, 0 }}},
    { SNMP_INTEGER, (RWRITE| SCALAR), var_cjhvApDmzType,
                 {2, { I_cjhvApDmzType, 0 }}},
    { SNMP_STRING, (RWRITE| SCALAR), var_cjhvApDmzMac,
                 {2, { I_cjhvApDmzMac, 0 }}},
    { SNMP_IPADDRESS, (RWRITE| SCALAR), var_cjhvApDmzIp,
                 {2, { I_cjhvApDmzIp, 0 }}},
    { 0 }
    };
static SubTree cjhvApDmzInfo_tree =  { NULL, cjhvApDmzInfo_variables,
	        (sizeof(cjhvApDmzInfo_oid)/sizeof(oid)), cjhvApDmzInfo_oid};
/* cjhvApDmzInfo_tree */

/* ======================= PORTFW CONFIG ================================= */
unsigned char *
var_cjhvApPortFwdEntry(int *var_len,
        Oid *newoid, Oid *reqoid, int searchType,
        snmp_info_t *mesg, int (**write_method)())
{
	int column = newoid->name[(newoid->namelen - 1)];
	int result;
	int index = newoid->namelen++;
	int tbl_index = 0;
	static int tbl_entryNum = 0;
	char value[12] = {0,};

	if (tbl_entryNum == 0) {
		nvram_get_r_def("PORTFW_TBL_NUM", value, sizeof(value), "0");
		tbl_entryNum = strtoul(value, NULL, 10);
	}

	while (tbl_index < tbl_entryNum) {
		newoid->name[index] = tbl_index;
		result = compare(reqoid, newoid);
		if (((searchType == EXACT) && (result == 0)) || ((searchType == NEXT) && (result < 0))) {
			break;
		}
		tbl_index++;
	}

	if (tbl_index >= tbl_entryNum) {
		tbl_entryNum = 0;
		return NO_MIBINSTANCE;
	}

	*write_method = 0;
    switch (column) {
	case I_cjhvApPortFwdIndex:
		public_mib_buffer.gb_long = tbl_index + 1;
		*var_len = sizeof(long);
		return (unsigned char *)&public_mib_buffer.gb_long;
	case I_cjhvApPortFwdEnable:
		public_mib_buffer.gb_long = get_PortFwEnable();
		*var_len = sizeof(long);
		return (unsigned char *)&public_mib_buffer.gb_long;
	case I_cjhvApPortFwdName:
		get_PortFwName(tbl_index + 1, public_mib_buffer.gb_string, sizeof(public_mib_buffer.gb_string));
		*var_len = strlen(public_mib_buffer.gb_string);
		return (unsigned char *)public_mib_buffer.gb_string;
	case I_cjhvApPortFwdIp:
   		get_PortfwIpAddress(tbl_index + 1, &public_mib_buffer.gb_ip_address);
    	*var_len = sizeof(public_mib_buffer.gb_ip_address);
    	return (unsigned char *)&public_mib_buffer.gb_ip_address;
	case I_cjhvApPortFwdWanStartPort:
		get_portFwStartPort(tbl_index + 1, &public_mib_buffer.gb_long);
		*var_len = sizeof(long);
		return (unsigned char *)&public_mib_buffer.gb_long;
	case I_cjhvApPortFwdWanEndPort:
		get_portFwEndPort(tbl_index + 1, &public_mib_buffer.gb_long);
		*var_len = sizeof(long);
		return (unsigned char *)&public_mib_buffer.gb_long;
	case I_cjhvApPortFwdLanStartPort:
		get_portFwLanPort(tbl_index + 1, &public_mib_buffer.gb_long);
		*var_len = sizeof(long);
		return (unsigned char *)&public_mib_buffer.gb_long;
	case I_cjhvApPortFwdLanEndPort:
	    return (unsigned char *) NO_MIBINSTANCE;
	case I_cjhvApPortFwdProtocol:
		get_portFwProtocol(tbl_index + 1, &public_mib_buffer.gb_long);
		*var_len = sizeof(long);
		return (unsigned char *)&public_mib_buffer.gb_long;
        default:
            return NO_MIBINSTANCE;
    }
    return (unsigned char *)NO_MIBINSTANCE;
}

int write_setPortfwIndex(int action,
					 unsigned char *var_val, unsigned char varval_type, int var_val_len, unsigned char *statP, Oid * name)
{
	int ret = 1;

	switch (action) {
		case RESERVE1:
			break;
		case RESERVE2:
			break;
		case COMMIT:
			ret = set_portfwIndex((int)mhtol(var_val, var_val_len));
			break;
		case ACTION:
			break;
		case FREE:
			break;
	}

	return (ret == 0) ? SNMP_ERROR_WRONGVALUE : 0;
}

unsigned char *
var_cjhvApPortFwIndex(int *var_len, snmp_info_t *mesg,
        int (**write_method)())
{
    public_mib_buffer.gb_long = get_setPortfwIndex();
    *write_method = (int (*)())&write_setPortfwIndex;
    *var_len = sizeof(long);

    return (unsigned char *)&public_mib_buffer.gb_long;
}

int write_setPortfwEnable(int action,
					 unsigned char *var_val, unsigned char varval_type, int var_val_len, unsigned char *statP, Oid * name)
{
	int ret = 1;

	switch (action) {
		case RESERVE1:
			break;
		case RESERVE2:
			break;
		case COMMIT:
			ret = set_portfwEnable((int)mhtol(var_val, var_val_len));
			break;
		case ACTION:
			break;
		case FREE:
			break;
	}

	return (ret == 0) ? SNMP_ERROR_WRONGVALUE : 0;
}

unsigned char *
var_cjhvApPortFwEnable(int *var_len, snmp_info_t *mesg,
        int (**write_method)())
{
    public_mib_buffer.gb_long = get_setPortfwEnable();
    *write_method = (int (*)())&write_setPortfwEnable;
    *var_len = sizeof(long);

    return (unsigned char *)&public_mib_buffer.gb_long;
}

int	write_cjhvApPortfwName(int action,
	unsigned char *var_val, unsigned char varval_type, int var_val_len,
	unsigned char *statP, Oid *name)
{
	int ret = 1;

	switch (action) {
		case RESERVE1:
			break;
		case RESERVE2:
			break;
		case COMMIT:
			ret = set_portfwName(var_val, var_val_len);
			break;
		case ACTION:
			break;
		case FREE:
			break;
    }

	return (ret == 0) ? SNMP_ERROR_WRONGVALUE : 0;
}

unsigned char *
var_cjhvApPortFwName(int *var_len, snmp_info_t *mesg,
        int (**write_method)())
{
    get_setPortFwName(public_mib_buffer.gb_string, sizeof(public_mib_buffer.gb_string));
    *var_len = strlen(public_mib_buffer.gb_string);
    *write_method = (int (*)())&write_cjhvApPortfwName;

    return (unsigned char *)public_mib_buffer.gb_string;
}

int write_portfwip(int action,
					   unsigned char *var_val, unsigned char varval_type, int var_val_len, unsigned char *statP, Oid * name)
{
	int ret = 1;

	switch (action) {
		case RESERVE1:
			break;
		case RESERVE2:
			break;
		case COMMIT:
			ret = set_portfwAddress(var_val);
			break;
		case ACTION:
			break;
		case FREE:
			break;
	}

	return (ret == 0) ? SNMP_ERROR_WRONGVALUE : 0;
}

unsigned char *
var_cjhvApPortFwIp(int *var_len, snmp_info_t *mesg,
        int (**write_method)())
{
    get_portfwAddress(&public_mib_buffer.gb_ip_address);
    *write_method = (int (*)())&write_portfwip;
    *var_len = sizeof(public_mib_buffer.gb_ip_address);

    return (unsigned char *)&public_mib_buffer.gb_ip_address;
}

int write_setPortfwSport(int action,
					 unsigned char *var_val, unsigned char varval_type, int var_val_len, unsigned char *statP, Oid * name)
{
	int ret = 1;

	switch (action) {
		case RESERVE1:
			break;
		case RESERVE2:
			break;
		case COMMIT:
			ret = set_portfwSport((int)mhtol(var_val, var_val_len));
			break;
		case ACTION:
			break;
		case FREE:
			break;
	}

	return (ret == 0) ? SNMP_ERROR_WRONGVALUE : 0;
}

unsigned char *
var_cjhvApPortFwSport(int *var_len, snmp_info_t *mesg,
        int (**write_method)())
{
    public_mib_buffer.gb_long = get_setPortfwSport();
    *write_method = (int (*)())&write_setPortfwSport;
    *var_len = sizeof(long);

    return (unsigned char *)&public_mib_buffer.gb_long;
}

int write_setPortfwEport(int action,
					 unsigned char *var_val, unsigned char varval_type, int var_val_len, unsigned char *statP, Oid * name)
{
	int ret = 1;

	switch (action) {
		case RESERVE1:
			break;
		case RESERVE2:
			break;
		case COMMIT:
			ret = set_portfwEport((int)mhtol(var_val, var_val_len));
			break;
		case ACTION:
			break;
		case FREE:
			break;
	}

	return (ret == 0) ? SNMP_ERROR_WRONGVALUE : 0;
}

unsigned char *
var_cjhvApPortFwEport(int *var_len, snmp_info_t *mesg,
        int (**write_method)())
{
    public_mib_buffer.gb_long = get_setPortfwEport();
    *write_method = (int (*)())&write_setPortfwEport;
    *var_len = sizeof(long);

    return (unsigned char *)&public_mib_buffer.gb_long;
}

int write_setPortfwLanport(int action,
					 unsigned char *var_val, unsigned char varval_type, int var_val_len, unsigned char *statP, Oid * name)
{
	int ret = 1;

	switch (action) {
		case RESERVE1:
			break;
		case RESERVE2:
			break;
		case COMMIT:
			ret = set_portfwLanport((int)mhtol(var_val, var_val_len));
			break;
		case ACTION:
			break;
		case FREE:
			break;
	}

	return (ret == 0) ? SNMP_ERROR_WRONGVALUE : 0;
}

unsigned char *
var_cjhvApPortFwLanport(int *var_len, snmp_info_t *mesg,
        int (**write_method)())
{
    public_mib_buffer.gb_long = get_setPortfwLanport();
    *write_method = (int (*)())&write_setPortfwLanport;
    *var_len = sizeof(long);

    return (unsigned char *)&public_mib_buffer.gb_long;
}

int write_setPortfwLanEport(int action,
					 unsigned char *var_val, unsigned char varval_type, int var_val_len, unsigned char *statP, Oid * name)
{
	int ret = 1;

	switch (action) {
		case RESERVE1:
			break;
		case RESERVE2:
			break;
		case COMMIT:
			ret = set_portfwLanEport((int)mhtol(var_val, var_val_len));
			break;
		case ACTION:
			break;
		case FREE:
			break;
	}

	return (ret == 0) ? SNMP_ERROR_WRONGVALUE : 0;
}

unsigned char *
var_cjhvApPortFwLanEport(int *var_len, snmp_info_t *mesg,
        int (**write_method)())
{
    public_mib_buffer.gb_long = 0;
    *write_method = (int (*)())&write_setPortfwLanEport;
    *var_len = sizeof(long);

    return (unsigned char *)&public_mib_buffer.gb_long;
}

 int write_setPortfwprotocol(int action,
					 unsigned char *var_val, unsigned char varval_type, int var_val_len, unsigned char *statP, Oid * name)
{
	int ret = 1;

	switch (action) {
		case RESERVE1:
			break;
		case RESERVE2:
			break;
		case COMMIT:
			ret = set_portfwprotocol((int)mhtol(var_val, var_val_len));
			break;
		case ACTION:
			break;
		case FREE:
			break;
	}

	return (ret == 0) ? SNMP_ERROR_WRONGVALUE : 0;
}

unsigned char *
var_cjhvApPortFwProtocol(int *var_len, snmp_info_t *mesg,
        int (**write_method)())
{
    public_mib_buffer.gb_long = get_setPortfwprotocol();
    *write_method = (int (*)())&write_setPortfwprotocol;
    *var_len = sizeof(long);

    return (unsigned char *)&public_mib_buffer.gb_long;
}
/* ======================= PORTFW CONFIG ================================= */

/* cjhvApPortFwdEntry_tree */
static oid cjhvApPortFwdEntry_oid[] = { O_cjhvApPortFwdEntry };
static Object cjhvApPortFwdEntry_variables[] = {
    { SNMP_INTEGER, (RONLY| COLUMN), var_cjhvApPortFwdEntry,
                {1, { I_cjhvApPortFwdIndex }}},
    { SNMP_INTEGER, (RWRITE| COLUMN), var_cjhvApPortFwdEntry,
                {1, { I_cjhvApPortFwdEnable }}},
    { SNMP_STRING, (RWRITE| COLUMN), var_cjhvApPortFwdEntry,
                {1, { I_cjhvApPortFwdName }}},
    { SNMP_IPADDRESS, (RWRITE| COLUMN), var_cjhvApPortFwdEntry,
                {1, { I_cjhvApPortFwdIp }}},
    { SNMP_INTEGER, (RWRITE| COLUMN), var_cjhvApPortFwdEntry,
                {1, { I_cjhvApPortFwdWanStartPort }}},
    { SNMP_INTEGER, (RWRITE| COLUMN), var_cjhvApPortFwdEntry,
                {1, { I_cjhvApPortFwdWanEndPort }}},
    { SNMP_INTEGER, (RWRITE| COLUMN), var_cjhvApPortFwdEntry,
                {1, { I_cjhvApPortFwdLanStartPort }}},
    { SNMP_INTEGER, (RWRITE| COLUMN), var_cjhvApPortFwdEntry,
                {1, { I_cjhvApPortFwdLanEndPort }}},
    { SNMP_INTEGER, (RWRITE| COLUMN), var_cjhvApPortFwdEntry,
                {1, { I_cjhvApPortFwdProtocol }}},
    { 0 }
    };
static SubTree cjhvApPortFwdEntry_tree =  { NULL, cjhvApPortFwdEntry_variables,
	        (sizeof(cjhvApPortFwdEntry_oid)/sizeof(oid)), cjhvApPortFwdEntry_oid};
/* cjhvApPortFwdEntry_tree */

/* cjhvApSetPortFwd_tree */
static oid cjhvApSetPortFw_oid[] = { O_cjhvApSetPortFwd };
static Object cjhvApPortFwInfo_variables[] = {
    { SNMP_INTEGER, (RWRITE| SCALAR), var_cjhvApPortFwIndex,
                 {2, { I_cjhvApSetPortFwdIndex, 0 }}},
    { SNMP_INTEGER, (RWRITE| SCALAR), var_cjhvApPortFwEnable,
                 {2, { I_cjhvApSetPortFwdEnable, 0 }}},
    { SNMP_STRING, (RWRITE| SCALAR), var_cjhvApPortFwName,
                 {2, { I_cjhvApSetPortFwdName, 0 }}},
    { SNMP_IPADDRESS, (RWRITE| SCALAR), var_cjhvApPortFwIp,
                 {2, { I_cjhvApSetPortFwdIp, 0 }}},
    { SNMP_INTEGER, (RWRITE| SCALAR), var_cjhvApPortFwSport,
                 {2, { I_cjhvApSetPortFwdWanStartPort, 0 }}},
    { SNMP_INTEGER, (RWRITE| SCALAR), var_cjhvApPortFwEport,
                 {2, { I_cjhvApSetPortFwdWanEndPort, 0 }}},
    { SNMP_INTEGER, (RWRITE| SCALAR), var_cjhvApPortFwLanport,
                 {2, { I_cjhvApSetPortFwdLanStartPort, 0 }}},
    { SNMP_INTEGER, (RWRITE| SCALAR), var_cjhvApPortFwLanEport,
                 {2, { I_cjhvApSetPortFwdLanEndPort, 0 }}},
    { SNMP_INTEGER, (RWRITE| SCALAR), var_cjhvApPortFwProtocol,
                 {2, { I_cjhvApSetPortFwdProtocol, 0 }}},
    { 0 }
    };
static SubTree cjhvApSetPortFwd_tree =  { NULL, cjhvApPortFwInfo_variables,
	        (sizeof(cjhvApSetPortFw_oid)/sizeof(oid)), cjhvApSetPortFw_oid};
/* cjhvApSetPortFwd_tree */

/* ======================= TELNET CONFIG ================================= */
int	write_cjhvApTelnetInfoEnable(int action,
	unsigned char *var_val, unsigned char varval_type, int var_val_len,
	unsigned char *statP, Oid *name)
{
	int ret = 1;

	switch (action) {
		case RESERVE1:
			break;
		case RESERVE2:
			break;
		case COMMIT:
			ret = set_telnetEnable((int)mhtol(var_val, var_val_len));
			break;
		case ACTION:
			break;
		case FREE:
			break;
    }

    return (ret == 0) ? SNMP_ERROR_WRONGVALUE : 0;
}

unsigned char *
var_cjhvApTelnetInfoEnable(int *var_len, snmp_info_t *mesg,
        int (**write_method)())
{
    public_mib_buffer.gb_long = get_telnetEnable();
    *write_method = (int (*)())&write_cjhvApTelnetInfoEnable;
    *var_len = sizeof(long);

    return (unsigned char *)&public_mib_buffer.gb_long;
}
/* ======================= TELNET CONFIG ================================= */

/* cjhvApTelnetInfo_tree */
static oid cjhvApTelnetInfo_oid[] = { O_cjhvApTelnetInfo };
static Object cjhvApTelnetInfo_variables[] = {
    { SNMP_INTEGER, (RWRITE| SCALAR), var_cjhvApTelnetInfoEnable,
                 {2, { I_cjhvApTelnetInfoEnable, 0 }}},
    { 0 }
    };
static SubTree cjhvApTelnetInfo_tree =  { NULL, cjhvApTelnetInfo_variables,
	        (sizeof(cjhvApTelnetInfo_oid)/sizeof(oid)), cjhvApTelnetInfo_oid};
/* cjhvApTelnetInfo_tree */

/* ======================= ACL CONFIG ================================= */
int	write_cjhvApaclInfoEnable(int action,
	unsigned char *var_val, unsigned char varval_type, int var_val_len,
	unsigned char *statP, Oid *name)
{
	int ret = 1;

	switch (action) {
		case RESERVE1:
			break;
		case RESERVE2:
			break;
		case COMMIT:
			ret = set_aclEnable((int)mhtol(var_val, var_val_len));
			break;
		case ACTION:
			break;
		case FREE:
			break;
    }

	return (ret == 0) ? SNMP_ERROR_WRONGVALUE : 0;
}

unsigned char *
var_cjhvApACLInfoEnable(int *var_len, snmp_info_t *mesg,
        int (**write_method)())
{
	public_mib_buffer.gb_long = get_aclEnable();
	*write_method = (int (*)())&write_cjhvApaclInfoEnable;
	*var_len = sizeof(long);
	return (unsigned char *)&public_mib_buffer.gb_long;
}
/* ======================= ACL CONFIG ================================= */

/* cjhvApACLInfo_tree */
static oid cjhvApACLInfo_oid[] = { O_cjhvApACLInfo };
static Object cjhvApACLInfo_variables[] = {
    { SNMP_INTEGER, (RWRITE| SCALAR), var_cjhvApACLInfoEnable,
                 {2, { I_cjhvApACLInfoEnable, 0 }}},
    { 0 }
    };
static SubTree cjhvApACLInfo_tree =  { NULL, cjhvApACLInfo_variables,
	        (sizeof(cjhvApACLInfo_oid)/sizeof(oid)), cjhvApACLInfo_oid};
/* cjhvApACLInfo_tree */

/* ======================= WEBMAN CONFIG ================================= */
int	write_cjhvApWebInfoEnable(int action,
	unsigned char *var_val, unsigned char varval_type, int var_val_len,
	unsigned char *statP, Oid *name)
{
	int ret = 1;

	switch (action) {
		case RESERVE1:
			break;
		case RESERVE2:
			break;
		case COMMIT:
			ret = set_WebEnable((int)mhtol(var_val, var_val_len));
			break;
		case ACTION:
			break;
		case FREE:
			break;
    }

    return (ret == 0) ? SNMP_ERROR_WRONGVALUE : 0;
}

unsigned char *
var_cjhvApWebInfoEnable(int *var_len, snmp_info_t *mesg,
        int (**write_method)())
{
    public_mib_buffer.gb_long = get_WebEnable();
    *write_method = (int (*)())&write_cjhvApWebInfoEnable;
    *var_len = sizeof(long);
    return (unsigned char *)&public_mib_buffer.gb_long;
}
/* ======================= WEBMAN CONFIG ================================= */

/* cjhvApWebInfo_tree */
static oid cjhvApWebInfo_oid[] = { O_cjhvApWebinfo };
static Object cjhvApWebInfo_variables[] = {
    { SNMP_INTEGER, (RWRITE| SCALAR), var_cjhvApWebInfoEnable,
                 {2, { I_cjhvApWebinfoEnable, 0 }}},
    { 0 }
    };
static SubTree cjhvApWebInfo_tree =  { NULL, cjhvApWebInfo_variables,
	        (sizeof(cjhvApWebInfo_oid)/sizeof(oid)), cjhvApWebInfo_oid};
/* cjhvApWebInfo_tree */

/* ======================= DNS CHANGE INFO ================================= */
unsigned char *
var_cjhvApAttackSourceIP(int *var_len, snmp_info_t *mesg,
        int (**write_method)())
{
    get_attackIp(&public_mib_buffer.gb_ip_address);
    *var_len = sizeof(public_mib_buffer.gb_ip_address);
	*write_method = 0;
    return (unsigned char *)&public_mib_buffer.gb_ip_address;
}

unsigned char *
var_cjhvApChangeTime(int *var_len, snmp_info_t *mesg,
        int (**write_method)())
{
    get_attackTime(public_mib_buffer.gb_string, sizeof(public_mib_buffer.gb_string));
    *var_len = strlen(public_mib_buffer.gb_string);
	*write_method = 0;
    return (unsigned char *)public_mib_buffer.gb_string;
}

unsigned char *
var_cjhvApChangeDNS1(int *var_len, snmp_info_t *mesg,
        int (**write_method)())
{
	get_dnsAddress(&public_mib_buffer.gb_ip_address, 1);
    *var_len = sizeof(public_mib_buffer.gb_ip_address);
	*write_method = 0;
    return (unsigned char *)&public_mib_buffer.gb_ip_address;
}

unsigned char *
var_cjhvApChangeDNS2(int *var_len, snmp_info_t *mesg,
        int (**write_method)())
{
   	get_dnsAddress(&public_mib_buffer.gb_ip_address, 2);
    *var_len = sizeof(public_mib_buffer.gb_ip_address);
    *write_method = 0;
    return (unsigned char *)&public_mib_buffer.gb_ip_address;
}
/* ======================= DNS CHANGE INFO ================================= */

/* cjhvApSecurityinfo_tree */
static oid cjhvApSecurityinfo_oid[] = { O_cjhvApSecurityinfo };
static Object cjhvApSecurityinfo_variables[] = {
    { SNMP_IPADDRESS, (RONLY| SCALAR), var_cjhvApAttackSourceIP,
                 {2, { I_cjhvApAttackSourceIP, 0 }}},
    { SNMP_STRING, (RONLY| SCALAR), var_cjhvApChangeTime,
                 {2, { I_cjhvApChangeTime, 0 }}},
	{ SNMP_IPADDRESS, (RONLY| SCALAR), var_cjhvApChangeDNS1,
                 {2, { I_cjhvApChangeDNS1, 0 }}},
	{ SNMP_IPADDRESS, (RONLY| SCALAR), var_cjhvApChangeDNS2,
                 {2, { I_cjhvApChangeDNS2, 0 }}},
    { 0 }
    };
static SubTree cjhvApSecurityinfo_tree =  { NULL, cjhvApSecurityinfo_variables,
	        (sizeof(cjhvApSecurityinfo_oid)/sizeof(oid)), cjhvApSecurityinfo_oid};
/* cjhvApSecurityinfo_tree */

/* ======================= IGMP JOIN INFO ================================= */
unsigned char *
var_cjhvApIgmpJoinEntry(int *var_len,
        Oid *newoid, Oid *reqoid, int searchType,
        snmp_info_t *mesg, int (**write_method)())
{
	static _igmp_snoop_t igmp[MAXTBLNUM];
	int column = newoid->name[(newoid->namelen - 1)];
	int result;
	int ii = newoid->namelen++;
	int idx = 0;
	static int count = 0;

	if (count == 0) {
		memset(&igmp, 0, sizeof(igmp));
		count = igmp_snoop_table_info(igmp);
	}

	while (idx < count) {
		newoid->name[ii] = idx;
		result = compare(reqoid, newoid);
		if (((searchType == EXACT) && (result == 0)) || ((searchType == NEXT) && (result < 0))) {
			break;
		}
		idx++;
	}

	if (idx >= count) {
		count = 0;
		return (unsigned char *)NO_MIBINSTANCE;
	}

    *write_method = 0;
    switch (column) {
	case I_cjhvApIgmpJoinIndex:
		public_mib_buffer.gb_long = idx + 1;
		*var_len = sizeof(long);
		return (unsigned char *)&public_mib_buffer.gb_long;
	case I_cjhvApIgmpJoinIpAddress:
		get_igmpJoinIpAddress(&igmp[idx], &public_mib_buffer.gb_ip_address);
		*var_len = sizeof(public_mib_buffer.gb_ip_address);
		return (unsigned char *)&public_mib_buffer.gb_ip_address;
	case I_cjhvApIgmpJoinMemberNumber:
		public_mib_buffer.gb_long = igmp[idx].join_mbn;
		*var_len = sizeof(long);
		return (unsigned char *)&public_mib_buffer.gb_long;
	case I_cjhvApIgmpJoinPort:
		public_mib_buffer.gb_long = igmp[idx].join_port;
		*var_len = sizeof(long);
		return (unsigned char *)&public_mib_buffer.gb_long;
        default:
            return NO_MIBINSTANCE;
    }
}
/* ======================= IGMP JOIN INFO ================================= */

/* cjhvApIgmpJoinEntry_tree */
static oid cjhvApIgmpJoinEntry_oid[] = { O_cjhvApIgmpJoinEntry };
static Object cjhvApIgmpJoinEntry_variables[] = {
    { SNMP_INTEGER, (RONLY| COLUMN), var_cjhvApIgmpJoinEntry,
                {1, { I_cjhvApIgmpJoinIndex }}},
    { SNMP_IPADDRESS, (RONLY| COLUMN), var_cjhvApIgmpJoinEntry,
                {1, { I_cjhvApIgmpJoinIpAddress }}},
    { SNMP_INTEGER, (RONLY| COLUMN), var_cjhvApIgmpJoinEntry,
                {1, { I_cjhvApIgmpJoinMemberNumber }}},
    { SNMP_INTEGER, (RONLY| COLUMN), var_cjhvApIgmpJoinEntry,
                {1, { I_cjhvApIgmpJoinPort }}},
    { 0 }
    };
static SubTree cjhvApIgmpJoinEntry_tree =  { NULL, cjhvApIgmpJoinEntry_variables,
	        (sizeof(cjhvApIgmpJoinEntry_oid)/sizeof(oid)), cjhvApIgmpJoinEntry_oid};
/* cjhvApIgmpJoinEntry_tree */

/* ======================= MULTICAST INFO ================================= */
unsigned char *
var_cjhvApMulticastEntry(int *var_len,
        Oid *newoid, Oid *reqoid, int searchType,
        snmp_info_t *mesg, int (**write_method)())
{
	static _igmp_snoop_t igmp[MAXTBLNUM];
	static int count = 0;
	int column = newoid->name[(newoid->namelen - 1)];
	int result;
	int ii = newoid->namelen++;
	int idx = 0;

	if (count == 0) {
		memset(&igmp, 0, sizeof(igmp));
		count = igmp_snoop_table_info(igmp);
	}

	while (idx < count) {
		newoid->name[ii] = idx;
		result = compare(reqoid, newoid);
		if (((searchType == EXACT) && (result == 0)) || ((searchType == NEXT) && (result < 0))) {
			break;
		}
		idx++;
	}

	if (idx >= count) {
		count = 0;
		return (unsigned char *)NO_MIBINSTANCE;
	}

    *write_method = 0;
    *var_len = sizeof(long);
    switch (column) {
	case I_cjhvApMulticastIndex:
		public_mib_buffer.gb_long = idx + 1;
		*var_len = sizeof(long);
		return (unsigned char *)&public_mib_buffer.gb_long;
	case I_cjhvApMulticastJoinIpAddress:
		get_multicastJoinIpAddress(&igmp[idx], &public_mib_buffer.gb_ip_address);
		*var_len = sizeof(public_mib_buffer.gb_ip_address);
		return (unsigned char *)&public_mib_buffer.gb_ip_address;
	case I_cjhvApMulticastPortNumber:
		public_mib_buffer.gb_long = get_multicastPortNumber(&igmp[idx]);
		*var_len = sizeof(long);
		return (unsigned char *)&public_mib_buffer.gb_long;
	case I_cjhvApMulticastPortName:
		get_multicastPortName(&igmp[idx], public_mib_buffer.gb_string, sizeof(public_mib_buffer.gb_string));
		*var_len = strlen(public_mib_buffer.gb_string);
		return (unsigned char *)public_mib_buffer.gb_string;
	case I_cjhvApMulticastOperation:
		public_mib_buffer.gb_long = 1; //run
		*var_len = sizeof(long);
		return (unsigned char *)&public_mib_buffer.gb_long;
	case I_cjhvApMulticastInPkts:
		get_multicastInPackets(&igmp[idx], &public_mib_buffer.gb_counter);
		*var_len = sizeof(public_mib_buffer.gb_counter);
		return (unsigned char *)&public_mib_buffer.gb_counter;
	case I_cjhvApMulticastOutPkts:
		get_multicastOutPackets(&igmp[idx], &public_mib_buffer.gb_counter);
		*var_len = sizeof(public_mib_buffer.gb_counter);
		return (unsigned char *)&public_mib_buffer.gb_counter;
        default:
            return NO_MIBINSTANCE;
    }
}
/* ======================= MULTICAST INFO ================================= */

/* cjhvApMulticastEntry_tree */
static oid cjhvApMulticastEntry_oid[] = { O_cjhvApMulticastEntry };
static Object cjhvApMulticastEntry_variables[] = {
    { SNMP_INTEGER, (RONLY| COLUMN), var_cjhvApMulticastEntry,
                {1, { I_cjhvApMulticastIndex }}},
    { SNMP_IPADDRESS, (RONLY| COLUMN), var_cjhvApMulticastEntry,
                {1, { I_cjhvApMulticastJoinIpAddress }}},
    { SNMP_INTEGER, (RONLY| COLUMN), var_cjhvApMulticastEntry,
                {1, { I_cjhvApMulticastPortNumber }}},
    { SNMP_STRING, (RONLY| COLUMN), var_cjhvApMulticastEntry,
                {1, { I_cjhvApMulticastPortName }}},
    { SNMP_INTEGER, (RONLY| COLUMN), var_cjhvApMulticastEntry,
                {1, { I_cjhvApMulticastOperation }}},
    { SNMP_COUNTER, (RONLY| COLUMN), var_cjhvApMulticastEntry,
                {1, { I_cjhvApMulticastInPkts }}},
    { SNMP_COUNTER, (RONLY| COLUMN), var_cjhvApMulticastEntry,
                {1, { I_cjhvApMulticastOutPkts }}},
    { 0 }
    };
static SubTree cjhvApMulticastEntry_tree =  { NULL, cjhvApMulticastEntry_variables,
	        (sizeof(cjhvApMulticastEntry_oid)/sizeof(oid)), cjhvApMulticastEntry_oid};
/* cjhvApMulticastEntry_tree */

/* ======================= TRAFFIC INFO ================================= */
unsigned char *
var_cjhvApTrafficEntry(int *var_len,
        Oid *newoid, Oid *reqoid, int searchType,
        snmp_info_t *mesg, int (**write_method)())
{
    int column = newoid->name[(newoid->namelen - 1)];
    int result;
    int ii = newoid->namelen++;
    int idx = 0;

    while (idx < 10) {
    	newoid->name[ii] = idx;
    	result = compare(reqoid, newoid);
    	if (((searchType == EXACT) && (result == 0)) || ((searchType == NEXT) && (result < 0))) {
    		break;
    	}
    	idx++;
    }

    if (idx >= 10) {
    	return (unsigned char *)NO_MIBINSTANCE;
    }

    *write_method = 0;
    switch (column) {
	case I_cjhvApPortTrafficIndex:
		public_mib_buffer.gb_long = idx + 1;
		*var_len = sizeof(long);
		return (unsigned char *)&public_mib_buffer.gb_long;
	case I_cjhvApPortTraffiName:
		if(idx < 2)
			snprintf(public_mib_buffer.gb_string, sizeof(public_mib_buffer.gb_string), "%s", (idx) ? "LAN" : "WAN");
		else
			get_wlanSSID((idx - 2), public_mib_buffer.gb_string, sizeof(public_mib_buffer.gb_string));
		*var_len = strlen(public_mib_buffer.gb_string);
		return (unsigned char *)public_mib_buffer.gb_string;
	case I_cjhvApPortTraffiTX:
		if(idx < 2)
			get_portStatusOutBytes(idx, &public_mib_buffer.gb_counter);
		else
			get_wlanOutTrafficInfo((idx - 2), &public_mib_buffer.gb_counter);
		*var_len = sizeof(public_mib_buffer.gb_counter);
		return (unsigned char *)&public_mib_buffer.gb_counter;
	case I_cjhvApPortTraffiRX:
		if(idx < 2)
			get_portStatusInBytes(idx, &public_mib_buffer.gb_counter);
		else
			get_wlanInTrafficInfo((idx - 2), &public_mib_buffer.gb_counter);
		*var_len = sizeof(public_mib_buffer.gb_counter);
		return (unsigned char *)&public_mib_buffer.gb_counter;
    default:
        return NO_MIBINSTANCE;
    }
}
/* ======================= TRAFFIC INFO ================================= */

/* cjhvApTrafficEntry_tree */
static oid cjhvApTrafficEntry_oid[] = { O_cjhvApTrafficEntry };
static Object cjhvApTrafficEntry_variables[] = {
    { SNMP_INTEGER, (RONLY| COLUMN), var_cjhvApTrafficEntry,
                {1, { I_cjhvApPortTrafficIndex }}},
    { SNMP_STRING, (RONLY| COLUMN), var_cjhvApTrafficEntry,
                {1, { I_cjhvApPortTraffiName }}},
    { SNMP_INTEGER, (RONLY| COLUMN), var_cjhvApTrafficEntry,
                {1, { I_cjhvApPortTraffiTX }}},
    { SNMP_INTEGER, (RONLY| COLUMN), var_cjhvApTrafficEntry,
                {1, { I_cjhvApPortTraffiRX }}},
    { 0 }
    };
static SubTree cjhvApTrafficEntry_tree =  { NULL, cjhvApTrafficEntry_variables,
	        (sizeof(cjhvApTrafficEntry_oid)/sizeof(oid)), cjhvApTrafficEntry_oid};
/* cjhvApTrafficEntry_tree */

/* ======================= RESET CONFIG ================================= */
int	write_cjhvApSystemRemoteReset(int action,
	unsigned char *var_val, unsigned char varval_type, int var_val_len, unsigned char *statP, Oid *name)
{
	int ret = 1;

	switch (action) {
		case RESERVE1:
			break;
		case RESERVE2:
			break;
		case COMMIT:
			ret = set_faultreset((int)mhtol(var_val, var_val_len));
			break;
		case ACTION:
			break;
		case FREE:
			break;
    }

    return (ret == 0) ? SNMP_ERROR_WRONGVALUE : 0;
}

unsigned char *
var_cjhvApSystemRemoteReset(int *var_len, snmp_info_t *mesg,
        int (**write_method)())
{
    public_mib_buffer.gb_long = 0;
    *write_method = (int (*)())&write_cjhvApSystemRemoteReset;
    *var_len = sizeof(long);
    return (unsigned char *)&public_mib_buffer.gb_long;
}
/* ======================= RESET CONFIG ================================= */

/* cjhvApSystemRemoteResetConfig_tree */
static oid cjhvApSystemRemoteResetConfig_oid[] = { O_cjhvApSystemRemoteResetConfig };
static Object cjhvApSystemRemoteResetConfig_variables[] = {
    { SNMP_INTEGER, (RWRITE| SCALAR), var_cjhvApSystemRemoteReset,
                 {2, { I_cjhvApSystemRemoteReset, 0 }}},
    { 0 }
    };
static SubTree cjhvApSystemRemoteResetConfig_tree =  { NULL, cjhvApSystemRemoteResetConfig_variables,
	        (sizeof(cjhvApSystemRemoteResetConfig_oid)/sizeof(oid)), cjhvApSystemRemoteResetConfig_oid};
/* cjhvApSystemRemoteResetConfig_tree */

/* ======================= PING TEST CONFIG ================================= */
int	write_pingAddress(int action,
	unsigned char *var_val, unsigned char varval_type, int var_val_len, unsigned char *statP, Oid *name)
{
	int ret = 1;

	switch (action) {
		case RESERVE1:
			break;
		case RESERVE2:
			break;
		case COMMIT:
			ret = set_pingAddress(var_val, var_val_len);
			break;
		case ACTION:
			break;
		case FREE:
			break;
	}

	return (ret == 0) ? SNMP_ERROR_WRONGVALUE : 0;
}

unsigned char *
var_pingAddress(int *var_len, snmp_info_t *mesg,
        int (**write_method)())
{
	get_pingAddress(public_mib_buffer.gb_string, sizeof(public_mib_buffer.gb_string));
	*var_len = strlen(public_mib_buffer.gb_string);
	*write_method = (int (*)())&write_pingAddress;
	return (unsigned char *)public_mib_buffer.gb_string;
}

int	write_pingPacketCount(int action,
	unsigned char *var_val, unsigned char varval_type, int var_val_len, unsigned char *statP, Oid *name)
{
	int ret = 1;

	switch (action) {
		case RESERVE1:
			break;
		case RESERVE2:
			break;
		case COMMIT:
			ret = set_pktCount((int)mhtol(var_val, var_val_len));
			break;
		case ACTION:
			break;
		case FREE:
			break;
	}

	return (ret == 0) ? SNMP_ERROR_WRONGVALUE : 0;
}

unsigned char *
var_pingPacketCount(int *var_len, snmp_info_t *mesg,
        int (**write_method)())
{
    get_pktCount(&public_mib_buffer.gb_counter);
    *var_len = sizeof(public_mib_buffer.gb_counter);
    *write_method = (int (*)())&write_pingPacketCount;
    return (unsigned char *)&public_mib_buffer.gb_counter;
}

int	write_pingPacketSize(int action,
	unsigned char *var_val, unsigned char varval_type, int var_val_len, unsigned char *statP, Oid *name)
{
	int ret = 1;

	switch (action) {
		case RESERVE1:
			break;
		case RESERVE2:
			break;
		case COMMIT:
			ret = set_pktSize((int)mhtol(var_val, var_val_len));
			break;
		case ACTION:
			break;
		case FREE:
			break;
    }

	return (ret == 0) ? SNMP_ERROR_WRONGVALUE : 0;
}

unsigned char *
var_pingPacketSize(int *var_len, snmp_info_t *mesg,
        int (**write_method)())
{
	get_pktSize(&public_mib_buffer.gb_counter);
	*var_len = sizeof(&public_mib_buffer.gb_counter);
	*write_method = (int (*)())&write_pingPacketSize;
	return (unsigned char *)&public_mib_buffer.gb_counter;
}

int	write_pingPacketTimeout(int action,
	unsigned char *var_val, unsigned char varval_type, int var_val_len,
	unsigned char *statP, Oid *name)
{
	int ret = 1;

	switch (action) {
		case RESERVE1:
			break;
		case RESERVE2:
			break;
		case COMMIT:
			ret = set_pktTimeout((int)mhtol(var_val, var_val_len));
			break;
		case ACTION:
			break;
		case FREE:
			break;
    }

	return (ret == 0) ? SNMP_ERROR_WRONGVALUE : 0;
}

unsigned char *
var_pingPacketTimeout(int *var_len, snmp_info_t *mesg,
        int (**write_method)())
{
    get_pktTimeout(&public_mib_buffer.gb_counter);
    *var_len = sizeof(public_mib_buffer.gb_counter);
    *write_method = (int (*)())&write_pingPacketTimeout;
    return (unsigned char *)&public_mib_buffer.gb_counter;
}

int	write_pingDelay(int action,
	unsigned char *var_val, unsigned char varval_type, int var_val_len,
	unsigned char *statP, Oid *name)
{
	int ret = 1;

	switch (action) {
		case RESERVE1:
			break;
		case RESERVE2:
			break;
		case COMMIT:
			ret = set_pktDelay((int)mhtol(var_val, var_val_len));
			break;
		case ACTION:
			break;
		case FREE:
			break;
	}

    return (ret == 0) ? SNMP_ERROR_WRONGVALUE : 0;
}

unsigned char *
var_pingDelay(int *var_len, snmp_info_t *mesg,
        int (**write_method)())
{
    get_pktDelay(&public_mib_buffer.gb_counter);
    *var_len = sizeof(public_mib_buffer.gb_counter);
    *write_method = (int (*)())&write_pingDelay;
    return (unsigned char *)&public_mib_buffer.gb_counter;
}

int	write_pingTrapOnCompletion(int action,
	unsigned char *var_val, unsigned char varval_type, int var_val_len,
	unsigned char *statP, Oid *name)
{
	int ret = 1;

	switch (action) {
		case RESERVE1:
			break;
		case RESERVE2:
			break;
		case COMMIT:
			ret = set_TrapOnCompletion((int)mhtol(var_val, var_val_len));
			break;
		case ACTION:
			break;
		case FREE:
			break;
	}

    return (ret == 0) ? SNMP_ERROR_WRONGVALUE : 0;
}

unsigned char *
var_pingTrapOnCompletion(int *var_len, snmp_info_t *mesg,
        int (**write_method)())
{
    get_TrapOnCompletion(&public_mib_buffer.gb_long);
    *var_len = sizeof(long);
    *write_method = (int (*)())&write_pingTrapOnCompletion;
    return (unsigned char *)&public_mib_buffer.gb_long;
}

unsigned char *
var_pingSentPackets(int *var_len, snmp_info_t *mesg,
        int (**write_method)())
{
    get_sentPktCount(&public_mib_buffer.gb_counter);
    *var_len = sizeof(public_mib_buffer.gb_counter);
    *write_method = 0;
    return (unsigned char *)&public_mib_buffer.gb_counter;
}

unsigned char *
var_pingReceivedPackets(int *var_len, snmp_info_t *mesg,
        int (**write_method)())
{
    get_recvPktCount(&public_mib_buffer.gb_counter);
    *var_len = sizeof(public_mib_buffer.gb_counter);
    *write_method = 0;
    return (unsigned char *)&public_mib_buffer.gb_counter;
}

unsigned char *
var_pingMinRtt(int *var_len, snmp_info_t *mesg,
        int (**write_method)())
{
    get_minPingTime(&public_mib_buffer.gb_counter);
    *var_len = sizeof(public_mib_buffer.gb_counter);
    *write_method = 0;
    return (unsigned char *)&public_mib_buffer.gb_counter;
}

unsigned char *
var_pingAvgRtt(int *var_len, snmp_info_t *mesg,
        int (**write_method)())
{
    get_avgPingTime(&public_mib_buffer.gb_counter);
    *var_len = sizeof(public_mib_buffer.gb_counter);
    *write_method = 0;
    return (unsigned char *)&public_mib_buffer.gb_counter;
}

unsigned char *
var_pingMaxRtt(int *var_len, snmp_info_t *mesg,
        int (**write_method)())
{
    get_maxPingTime(&public_mib_buffer.gb_counter);
    *var_len = sizeof(public_mib_buffer.gb_counter);
    *write_method = 0;
    return (unsigned char *)&public_mib_buffer.gb_counter;
}

unsigned char *
var_pingCompleted(int *var_len, snmp_info_t *mesg,
        int (**write_method)())
{
    get_pingCompleted(&public_mib_buffer.gb_long);
    *var_len = sizeof(long);
    *write_method = 0;
    return (unsigned char *)&public_mib_buffer.gb_long;
}

unsigned char *
var_pingTestStartTime(int *var_len, snmp_info_t *mesg,
        int (**write_method)())
{
    get_pingStarttime(public_mib_buffer.gb_string, sizeof(public_mib_buffer.gb_string));
    *var_len = strlen(public_mib_buffer.gb_string);
    *write_method = 0;
    return (unsigned char *)public_mib_buffer.gb_string;
}

unsigned char *
var_pingTestEndTime(int *var_len, snmp_info_t *mesg,
        int (**write_method)())
{
    get_pingEndtime(public_mib_buffer.gb_string, sizeof(public_mib_buffer.gb_string));
    *var_len = strlen(public_mib_buffer.gb_string);
    *write_method = 0;
    return (unsigned char *)public_mib_buffer.gb_string;
}

int	write_pingResultCode(int action,
	unsigned char *var_val, unsigned char varval_type, int var_val_len,
	unsigned char *statP, Oid *name)
{
    int ret = 1;

	switch (action) {
		case RESERVE1:
			break;
		case RESERVE2:
			break;
		case COMMIT:
			ret = set_pingResultCode((int)mhtol(var_val, var_val_len));
			break;
		case ACTION:
			break;
		case FREE:
			break;
	}

	return (ret == 0) ? SNMP_ERROR_WRONGVALUE : 0;
}


unsigned char *
var_pingResultCode(int *var_len, snmp_info_t *mesg,
        int (**write_method)())
{
    get_pingResultCode(&public_mib_buffer.gb_long);
    *var_len = sizeof(long);
    *write_method = (int (*)())&write_pingResultCode;
    return (unsigned char *)&public_mib_buffer.gb_long;
}
/* ======================= PING TEST CONFIG ================================= */

/* cjhvApPingTest_tree */
static oid cjhvApPingTest_oid[] = { O_cjhvApPingTest };
static Object cjhvApPingTest_variables[] = {
    { SNMP_STRING, (RWRITE| SCALAR), var_pingAddress,
                 {2, { I_pingAddress, 0 }}},
    { SNMP_INTEGER, (RWRITE| SCALAR), var_pingPacketCount,
                 {2, { I_pingPacketCount, 0 }}},
    { SNMP_INTEGER, (RWRITE| SCALAR), var_pingPacketSize,
                 {2, { I_pingPacketSize, 0 }}},
    { SNMP_INTEGER, (RWRITE| SCALAR), var_pingPacketTimeout,
                 {2, { I_pingPacketTimeout, 0 }}},
    { SNMP_INTEGER, (RWRITE| SCALAR), var_pingDelay,
                 {2, { I_pingDelay, 0 }}},
    { SNMP_INTEGER, (RWRITE| SCALAR), var_pingTrapOnCompletion,
                 {2, { I_pingTrapOnCompletion, 0 }}},
    { SNMP_COUNTER, (RONLY| SCALAR), var_pingSentPackets,
                 {2, { I_pingSentPackets, 0 }}},
    { SNMP_COUNTER, (RONLY| SCALAR), var_pingReceivedPackets,
                 {2, { I_pingReceivedPackets, 0 }}},
    { SNMP_INTEGER, (RONLY| SCALAR), var_pingMinRtt,
                 {2, { I_pingMinRtt, 0 }}},
    { SNMP_INTEGER, (RONLY| SCALAR), var_pingAvgRtt,
                 {2, { I_pingAvgRtt, 0 }}},
    { SNMP_INTEGER, (RONLY| SCALAR), var_pingMaxRtt,
                 {2, { I_pingMaxRtt, 0 }}},
    { SNMP_INTEGER, (RONLY| SCALAR), var_pingCompleted,
                 {2, { I_pingCompleted, 0 }}},
    { SNMP_STRING, (RONLY| SCALAR), var_pingTestStartTime,
                 {2, { I_pingTestStartTime, 0 }}},
    { SNMP_STRING, (RONLY| SCALAR), var_pingTestEndTime,
                 {2, { I_pingTestEndTime, 0 }}},
    { SNMP_INTEGER, (RWRITE| SCALAR), var_pingResultCode,
                 {2, { I_pingResultCode, 0 }}},
    { 0 }
    };
static SubTree cjhvApPingTest_tree =  { NULL, cjhvApPingTest_variables,
	        (sizeof(cjhvApPingTest_oid)/sizeof(oid)), cjhvApPingTest_oid};
/* cjhvApPingTest_tree */

/* ======================= FACTORY MODE CONFIG ================================= */
int	write_cjhvApSystemFactoryDefaultSet(int action,
	unsigned char *var_val, unsigned char varval_type, int var_val_len, unsigned char *statP, Oid *name)
{
	int ret = 1;

	switch (action) {
		case RESERVE1:
			break;
		case RESERVE2:
			break;
		case COMMIT:
			ret = set_factoryreset((int)mhtol(var_val, var_val_len));
			break;
		case ACTION:
			break;
		case FREE:
			break;
	}

	return (ret == 0) ? SNMP_ERROR_WRONGVALUE : 0;
}

unsigned char *
var_cjhvApSystemFactoryDefaultSet(int *var_len, snmp_info_t *mesg,
        int (**write_method)())
{
    public_mib_buffer.gb_long = 0;
    *write_method = (int (*)())&write_cjhvApSystemFactoryDefaultSet;
    *var_len = sizeof(long);

    return (unsigned char *)&public_mib_buffer.gb_long;
}
/* ======================= FACTORY MODE CONFIG ================================= */

/* cjhvApSystemFactoryDefault_tree */
static oid cjhvApSystemFactoryDefault_oid[] = { O_cjhvApSystemFactoryDefault };
static Object cjhvApSystemFactoryDefault_variables[] = {
    { SNMP_INTEGER, (RWRITE| SCALAR), var_cjhvApSystemFactoryDefaultSet,
                 {2, { I_cjhvApSystemFactoryDefaultSet, 0 }}},
    { 0 }
    };
static SubTree cjhvApSystemFactoryDefault_tree =  { NULL, cjhvApSystemFactoryDefault_variables,
	        (sizeof(cjhvApSystemFactoryDefault_oid)/sizeof(oid)), cjhvApSystemFactoryDefault_oid};
/* cjhvApSystemFactoryDefault_tree */

/* ======================= SOFT RESET CONFIG ================================= */
int	write_cjhvApSystemSoftResetSet(int action,
	unsigned char *var_val, unsigned char varval_type, int var_val_len, unsigned char *statP, Oid *name)
{
	int ret = 1;

	switch (action) {
		case RESERVE1:
			break;
		case RESERVE2:
			break;
		case COMMIT:
			ret = set_softreset((int)mhtol(var_val, var_val_len));
			break;
		case ACTION:
			break;
		case FREE:
			break;
    }

	return (ret == 0) ? SNMP_ERROR_WRONGVALUE : 0;
}

unsigned char *
var_cjhvApSystemSoftResetSet(int *var_len, snmp_info_t *mesg, int (**write_method)())
{
    get_cjhvApSystemSoftReset(&public_mib_buffer.gb_counter);
    *write_method = (int (*)())&write_cjhvApSystemSoftResetSet;
    *var_len = sizeof(public_mib_buffer.gb_counter);
    return (unsigned char *)&public_mib_buffer.gb_counter;
}

unsigned char *
var_cjhvApSystemSoftResetResult(int *var_len, snmp_info_t *mesg, int (**write_method)())
{
	get_cjhvApSystemSoftReset(&public_mib_buffer.gb_counter);
	*write_method = 0;
	*var_len = sizeof(public_mib_buffer.gb_counter);
	return (unsigned char *)&public_mib_buffer.gb_counter;
}
/* ======================= SOFT RESET CONFIG ================================= */

/* cjhvApSystemSoftReset_tree */
static oid cjhvApSystemSoftReset_oid[] = { O_cjhvApSystemSoftReset };
static Object cjhvApSystemSoftReset_variables[] = {
    { SNMP_INTEGER, (RWRITE| SCALAR), var_cjhvApSystemSoftResetSet,
                 {2, { I_cjhvApSystemSoftResetSet, 0 }}},
    { SNMP_INTEGER, (RONLY| SCALAR), var_cjhvApSystemSoftResetResult,
                 {2, { I_cjhvApSystemSoftResetResult, 0 }}},
    { 0 }
    };
static SubTree cjhvApSystemSoftReset_tree =  { NULL, cjhvApSystemSoftReset_variables,
	        (sizeof(cjhvApSystemSoftReset_oid)/sizeof(oid)), cjhvApSystemSoftReset_oid};
/* cjhvApSystemSoftReset_tree */

/* This is the MIB registration function. This should be called */
/* within the init_CJHV_AP_MIB-function */
void init_CJHV_AP_MIB()
{
    register_subtrees_of_CJHV_AP_MIB();
}

void register_subtrees_of_CJHV_AP_MIB()
{
    insert_group_in_mib(&cjhvApSystemInfo_tree);
    insert_group_in_mib(&cjhvApWanConfig_tree);
    insert_group_in_mib(&cjhvApLanConfig_tree);
    insert_group_in_mib(&cjhvApWlanBasicConfig_tree);
    insert_group_in_mib(&cjhvApWlanSsidConfigEntry_tree);
    insert_group_in_mib(&cjhvApDummyIndex_tree);
    insert_group_in_mib(&cjhvApWlanAdjacentChannelEntry_tree);
    insert_group_in_mib(&cjhvApWlanAdjacentChannelTrap1_tree);
    insert_group_in_mib(&cjhvApWlanAdjacentChannelTrap2_tree);
    insert_group_in_mib(&cjhvApWlanAdjacentChannelTrap3_tree);
    insert_group_in_mib(&cjhvApWlanAdjacentChannelTrap4_tree);
    insert_group_in_mib(&cjhvApWlanAdjacentChannelTrap5_tree);
    insert_group_in_mib(&cjhvApWlanAdjacentChannelTrap6_tree);
    insert_group_in_mib(&cjhvApWlanAdjacentChannelTrap7_tree);
    insert_group_in_mib(&cjhvApWlanAdjacentChannelTrap8_tree);
    insert_group_in_mib(&cjhvApWlanAdjacentChannelTrap9_tree);
    insert_group_in_mib(&cjhvApWlanAdjacentChannelTrap10_tree);
    insert_group_in_mib(&cjhvApWlanAdjacentChannelTrap11_tree);
    insert_group_in_mib(&cjhvApWlanAdjacentChannelTrap12_tree);
    insert_group_in_mib(&cjhvApWlanAdjacentChannelTrap13_tree);
    insert_group_in_mib(&cjhvApWlanAdjacentChannelTrap14_tree);
    insert_group_in_mib(&cjhvApWlanAdjacentChannelTrap15_tree);
    insert_group_in_mib(&cjhvApWlanAdjacentChannelTrap16_tree);
    insert_group_in_mib(&cjhvApWlanAdjacentChannelTrap17_tree);
    insert_group_in_mib(&cjhvApWlanAdjacentChannelTrap18_tree);
    insert_group_in_mib(&cjhvApWlanAdjacentChannelTrap19_tree);
    insert_group_in_mib(&cjhvApWlanAdjacentChannelTrap20_tree);
    insert_group_in_mib(&cjhvApWlanAdjacentChannelTrap21_tree);
    insert_group_in_mib(&cjhvApWlanAdjacentChannelTrap22_tree);
    insert_group_in_mib(&cjhvApWlanAdjacentChannelTrap23_tree);
    insert_group_in_mib(&cjhvApWlanAdjacentChannelTrap24_tree);
    insert_group_in_mib(&cjhvApWlanAdjacentChannelTrap25_tree);
    insert_group_in_mib(&cjhvApWlanAdjacentChannelTrap26_tree);
    insert_group_in_mib(&cjhvApWlanAdjacentChannelTrap27_tree);
    insert_group_in_mib(&cjhvApWlanAdjacentChannelTrap28_tree);
    insert_group_in_mib(&cjhvApWlanAdjacentChannelTrap29_tree);
    insert_group_in_mib(&cjhvApWlanAdjacentChannelTrap30_tree);
    insert_group_in_mib(&cjhvApWlanAdjacentChannelTrap31_tree);
    insert_group_in_mib(&cjhvApWlanAdvancedConfig_tree);
    insert_group_in_mib(&cjhvApWlanAdvancedConfig_tree_5g);
    insert_group_in_mib(&cjhvApWlanClientEntry_tree);
    insert_group_in_mib(&cjhvApWlanClientInfoTrap1_tree);
    insert_group_in_mib(&cjhvApWlanClientInfoTrap2_tree);
    insert_group_in_mib(&cjhvApWlanClientInfoTrap3_tree);
    insert_group_in_mib(&cjhvApWlanClientInfoTrap4_tree);
    insert_group_in_mib(&cjhvApWlanClientInfoTrap5_tree);
    insert_group_in_mib(&cjhvApWlanClientInfoTrap6_tree);
    insert_group_in_mib(&cjhvApWlanClientInfoTrap7_tree);
    insert_group_in_mib(&cjhvApWlanClientInfoTrap8_tree);
    insert_group_in_mib(&cjhvApWlanClientInfoTrap9_tree);
    insert_group_in_mib(&cjhvApWlanClientInfoTrap10_tree);
    insert_group_in_mib(&cjhvApSecwepConfigEntry_tree);
    insert_group_in_mib(&cjhvApSecwpaxConfigEntry_tree);
    insert_group_in_mib(&cjhvApSecwpamixConfigEntry_tree);
    insert_group_in_mib(&cjhvApPortConfig_tree);
    insert_group_in_mib(&cjhvApIgmpConfig_tree);
    insert_group_in_mib(&cjhvApSnmpConfig_tree);
    insert_group_in_mib(&cjhvApSyslogConfig_tree);
    insert_group_in_mib(&cjhvApNtpConfig_tree);
    insert_group_in_mib(&cjhvApDmzInfo_tree);
    insert_group_in_mib(&cjhvApPortFwdEntry_tree);
    insert_group_in_mib(&cjhvApSetPortFwd_tree);
    insert_group_in_mib(&cjhvApTelnetInfo_tree);
    insert_group_in_mib(&cjhvApACLInfo_tree);
    insert_group_in_mib(&cjhvApWebInfo_tree);
    insert_group_in_mib(&cjhvApSecurityinfo_tree);
    insert_group_in_mib(&cjhvApIgmpJoinEntry_tree);
    insert_group_in_mib(&cjhvApMulticastEntry_tree);
    insert_group_in_mib(&cjhvApTrafficEntry_tree);
    insert_group_in_mib(&cjhvApSystemRemoteResetConfig_tree);
    insert_group_in_mib(&cjhvApPingTest_tree);
    insert_group_in_mib(&cjhvApSystemFactoryDefault_tree);
    insert_group_in_mib(&cjhvApSystemSoftReset_tree);
}
