/*
 *      Utiltiy function for setting bridge
 *
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <memory.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include "apmib.h"
#include "custom.h"

#define DEFAULT_DNS1 "180.182.54.1"
#define DEFAULT_DNS2 "210.220.163.82"

static int set_opt_dns(FILE * f_fp);

int sdmz_configured(char *host, int size)
{
	int opmode;
	char *p, buf[32];

	apmib_get(MIB_OP_MODE, (void *)&opmode);
	if (opmode == 0) {
		if (host == NULL || size <= 0) {
			p = buf;
			size = sizeof(buf);
		} else
			p = host;
		if (nvram_atoi("x_sdmz_enable", 0) == 1) {
			_nvram_get_r("x_sdmz_host", p, size, "");
			if (p[0])
				return 1;
		}
	}
	return 0;
}

unsigned int in_faton(const char *path, const char *name)
{
	char buf[64];
	FILE *f;
	char *p;
	unsigned int addr = 0;

	f = fopen(path, "r");
	if (f) {
		while (fgets(buf, sizeof(buf), f)) {
			ydespaces(buf);
			p = strchr(buf, '=');
			if (!p)
				continue;
			*p++ = '\0';
			if (strncmp(buf, name, strlen(name)))
				continue;
			addr = inet_addr(ydespaces(p));
			break;
		}
		fclose(f);
	}
	return addr;
}

void create_dhcpd_conf(const char *filename, char *interface, int mode)
{
	unsigned int arg[16];
#define nip	arg[0]
#define dns1	arg[1]
#define dns2	arg[2]
#define dns3	arg[3]
	char *p;
	int i, n, dns_mode = 0;
	FILE *f;
	int dns_fail;

	f = fopen(filename, "w");
	if (!f)
		f = stdout;

	fprintf(f, "interface %s\n", interface);

	apmib_get(MIB_DHCP_CLIENT_START, (void *)&nip);
	fprintf(f, "start %u.%u.%u.%u\n", NIPQUAD(nip));

	apmib_get(MIB_DHCP_CLIENT_END, (void *)&nip);
	fprintf(f, "end %u.%u.%u.%u\n", NIPQUAD(nip));

	apmib_get(MIB_SUBNET_MASK, (void *)&nip);
	fprintf(f, "opt subnet %u.%u.%u.%u\n", NIPQUAD(nip));

	apmib_get(MIB_DHCP_LEASE_TIME, (void *)&n);
	/* cap to 1 week(7 days) */
	if (n <= 0 || n > 604800) {
		n = 3600;
		apmib_set(MIB_DHCP_LEASE_TIME, (void *)&n);
		apmib_update(CURRENT_SETTING);
	}
	fprintf(f, "opt lease %d\n", n);

	if (mode == 1)		//ap
		apmib_get(MIB_DEFAULT_GATEWAY, (void *)&nip);
	else
		apmib_get(MIB_IP_ADDR, (void *)&nip);

	if (nip) {
		fprintf(f, "opt router %u.%u.%u.%u\n", NIPQUAD(nip));
#ifdef HOME_GATEWAY
		if (mode != 1) {
			apmib_get(MIB_DNS_MODE, (void *)&dns_mode);
			if (dns_mode == 0) {
				/* @note: APNRTL-287 */
				if ((dns_fail = set_opt_dns(f))) {
					fprintf(f, "opt dns %s\n", DEFAULT_DNS1);
					fprintf(f, "opt dns %s\n", DEFAULT_DNS2);
				}
			}
		}
#endif
	}

	if ((mode == 1) || (mode == 2 && dns_mode == 1)) {
		dns1 = dns2 = dns3 = 0;
#ifdef HOME_GATEWAY
		apmib_get(MIB_DNS1, (void *)&dns1);
		apmib_get(MIB_DNS2, (void *)&dns2);
		apmib_get(MIB_DNS3, (void *)&dns3);

		if (dns1)
			fprintf(f, "opt dns %u.%u.%u.%u\n", NIPQUAD(dns1));
		if (dns2)
			fprintf(f, "opt dns %u.%u.%u.%u\n", NIPQUAD(dns2));
		if (dns3)
			fprintf(f, "opt dns %u.%u.%u.%u\n", NIPQUAD(dns3));

#ifdef CONFIG_DOMAIN_NAME_QUERY_SUPPORT
		apmib_get(MIB_IP_ADDR, (void *)&nip);
		fprintf(f, "opt dns %u.%u.%u.%u\n", NIPQUAD(nip));
#endif
#endif				/* HOME_GATEWAY */
		if (!dns1 && !dns2 && !dns3) {
			if (mode == 1)
				apmib_get(MIB_DEFAULT_GATEWAY, (void *)&nip);
			else
				apmib_get(MIB_IP_ADDR, (void *)&nip);
			if (nip)
				fprintf(f, "opt dns %u.%u.%u.%u\n", NIPQUAD(nip));
		}
	}

	memset(arg, 0, sizeof(arg));
	p = (char *)&arg[0];
	apmib_get(MIB_DOMAIN_NAME, (void *)p);
	if (*p)
		fprintf(f, "opt domain %s\n", p);

	/*static dhcp DHCPRSVDIP_T static_lease 000102030405 192.168.1.199 */
	n = 0;
	apmib_get(MIB_DHCPRSVDIP_ENABLED, (void *)&n);
	if (n == 1) {
		n = 0;
		apmib_get(MIB_DHCPRSVDIP_TBL_NUM, (void *)&n);
		for (i = 1; i <= n; i++) {
			DHCPRSVDIP_T slease;

			*((char *)&slease) = (char)i;
			apmib_get(MIB_DHCPRSVDIP_TBL, (void *)&slease);
			fprintf(f, "static_lease %02x%02x%02x%02x%02x%02x %u.%u.%u.%u\n",
				slease.macAddr[0], slease.macAddr[1],
				slease.macAddr[2], slease.macAddr[3],
				slease.macAddr[4], slease.macAddr[5],
				slease.ipAddr[0], slease.ipAddr[1], slease.ipAddr[2], slease.ipAddr[3]);
		}
	}

	fprintf(f, "dhcp_protection %d\n", nvram_atoi("x_dhcpd_protect", 1));

	if (nvram_atoi("x_sdmz_enable", 0) == 1) {
		_nvram_get_r("x_sdmz_host", p, sizeof(arg), "");
		if (*p) {
			struct in_addr nip;

			fprintf(f, "sdmz 1\n");
			fprintf(f, "dmz_host_mac %s\n", p);

			nip.s_addr = in_faton("/var/ntwk_sdmz", "WAN_IP");
			if (nip.s_addr)
				fprintf(f, "dmz_host_ip %u.%u.%u.%u\n",
					NIPQUAD(nip.s_addr));

			nip.s_addr = in_faton("/var/ntwk_sdmz", "WAN_NMASK");
			if (nip.s_addr)
				fprintf(f, "dmz_host_mask %u.%u.%u.%u\n",
					NIPQUAD(nip.s_addr));

			nip.s_addr = in_faton("/var/ntwk_sdmz", "WAN_ROUTER");
			if (nip.s_addr)
				fprintf(f, "dmz_host_gw %u.%u.%u.%u\n",
					NIPQUAD(nip.s_addr));
			//fprintf(f, "dmz_host_dns1 168.126.63.1\n");
		}
	}

	if (f != stdout)
		fclose(f);
#undef nip
#undef dns1
#undef dns2
#undef dns3
}

/* @note: APNRTL-287 */
static int set_opt_dns(FILE * f_fp)
{
	FILE *fp;
	char *p, *sp;
	char buf[80];
	int set_fail = 1;

	if (!(fp = fopen("/etc/resolv.conf", "r")))
		return set_fail;
	while (fgets(buf, sizeof(buf), fp)) {
		strtok_r(buf, " \r\n\t", &sp);
		if ((p = strtok_r(NULL, " \r\n\t", &sp))) {
			fprintf(f_fp, "opt dns %s\n", &p[0]);
			set_fail = 0;
		}
	}
	fclose(fp);
	return set_fail;
}

void var_ntwinfo_init(void)
{
	yfecho(VAR_WAN_IP_FILE, O_WRONLY|O_CREAT|O_TRUNC, 0644, "0.0.0.0");
	yfecho(VAR_NETMASK_FILE, O_WRONLY|O_CREAT|O_TRUNC, 0644, "0.0.0.0");
	yfecho(VAR_GATEWAY_FILE, O_WRONLY|O_CREAT|O_TRUNC, 0644, "0.0.0.0");
}

//
