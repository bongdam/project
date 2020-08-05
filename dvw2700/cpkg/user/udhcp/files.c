/*
 * files.c -- DHCP server file manipulation *
 * Rewrite by Russ Dill <Russ.Dill@asu.edu> July 2001
 */

#include <unistd.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/file.h>
#include <arpa/inet.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <ctype.h>
#include <netdb.h>
#include <endian.h>

#include "debug.h"
#include "dhcpd.h"
#include "files.h"
#include "options.h"
#include "leases.h"
#include <libytool.h>

#define _PATH_DHCPS_VOIP_LEASES "/var/lib/misc/udhcpd_voip.lease"

/* on these functions, make sure you datatype matches */
static int read_ip(char *line, void *arg)
{
	struct in_addr *addr = arg;
	struct hostent *host;
	int retval = 1;

	if (!inet_aton(line, addr)) {
		if ((host = gethostbyname(line)))
			addr->s_addr = *((unsigned long *)host->h_addr_list[0]);
		else
			retval = 0;
	}
	return retval;
}

static int read_str(char *line, void *arg)
{
	char **dest = arg;

	if (*dest)
		free(*dest);
	*dest = strdup(line);
	dewhites(*dest);
	return 1;
}

static int read_u32(char *line, void *arg)
{
	u_int32_t *dest = arg;
	char *endptr;
	*dest = strtoul(line, &endptr, 0);
	return endptr[0] == '\0';
}

static int read_yn(char *line, void *arg)
{
	char *dest = arg;
	int retval = 1;

	if (!strcasecmp("yes", line))
		*dest = 1;
	else if (!strcasecmp("no", line))
		*dest = 0;
	else
		retval = 0;

	return retval;
}

/* read a dhcp option and add it to opt_list */
static int read_opt(char *line, void *arg)
{
	struct option_set **opt_list = arg;
	char *opt, *val, *endptr;
	struct dhcp_option *option = NULL;
	int retval = 0, length = 0;
	char buffer[255];
	u_int16_t result_u16;
	u_int32_t result_u32;
	int i;

	if (!(opt = strtok(line, " \t=")))
		return 0;

	for (i = 0; options[i].code; i++)
		if (!strcmp(options[i].name, opt)) {
			option = &(options[i]);
			break;
		}

	if (!option)
		return 0;

	do {
		val = strtok(NULL, ", \t");
		if (val) {
			length = option_lengths[option->flags & TYPE_MASK];
			retval = 0;
			switch (option->flags & TYPE_MASK) {
			case OPTION_IP:
				retval = read_ip(val, buffer);
				break;
			case OPTION_IP_PAIR:
				retval = read_ip(val, buffer);
				if (!(val = strtok(NULL, ", \t/-")))
					retval = 0;
				if (retval)
					retval = read_ip(val, buffer + 4);
				break;
			case OPTION_STRING:
				length = strlen(val);
				if (length > 0) {
					if (length > 254)
						length = 254;
					memcpy(buffer, val, length);
					retval = 1;
				}
				break;
			case OPTION_BOOLEAN:
				retval = read_yn(val, buffer);
				break;
			case OPTION_U8:
				buffer[0] = strtoul(val, &endptr, 0);
				retval = (endptr[0] == '\0');
				break;
			case OPTION_U16:
				result_u16 = htons(strtoul(val, &endptr, 0));
				memcpy(buffer, &result_u16, 2);
				retval = (endptr[0] == '\0');
				break;
			case OPTION_S16:
				result_u16 = htons(strtol(val, &endptr, 0));
				memcpy(buffer, &result_u16, 2);
				retval = (endptr[0] == '\0');
				break;
			case OPTION_U32:
				result_u32 = htonl(strtoul(val, &endptr, 0));
				memcpy(buffer, &result_u32, 4);
				retval = (endptr[0] == '\0');
				break;
			case OPTION_S32:
				result_u32 = htonl(strtol(val, &endptr, 0));
				memcpy(buffer, &result_u32, 4);
				retval = (endptr[0] == '\0');
				break;
			default:
				break;
			}
			if (retval)
				attach_option(opt_list, option, buffer, length);
		}
	} while (val && retval && option->flags & OPTION_LIST);
	return retval;
}

static inline int x2n(int c)
{
	return ((c >= '0') && (c <= '9')) ? (c - '0') : ((c & 0xf) + 9);
}

/* XX:XX:XX:XX:XX:XX
   XX-XX-XX-XX-XX-XX
   XXXXXXXXXXXX
 */
static int read_eha(char *s, void *arg)
{
	unsigned char *addr = (unsigned char *)arg;
	char tmp[32];
	char *q, *p;
	int i, n;

	snprintf(tmp, sizeof(tmp), "%s", s);
	p = dewhites(tmp);

	if (strlen(p) == 12 && strspn(p, "0123456789abcdefABCDEF") == 12) {
		for (i = 0; i < 6; i++, p += 2)
			addr[i] = x2n(p[0]) * 16 + x2n(p[1]);
		return 1;
	}

	for (i = 0; (q = strsep(&p, ":-")); i++) {
		if (*q) {
			if (i < 6) {
				n = (int)strtol(q, &q, 16);
				if (!*q && n >= 0 && n < 256)
					*addr++ = (unsigned char)n;
				else
					break;
				continue;
			}
		}
		break;
	}

	return ! !(i == 6);
}

static int read_static_lease(char *line, void *arg)
{
	char tmp[80];
	struct in_addr in;
	unsigned char eha[ETH_ALEN];
	char *p, *plast;
	struct static_lease *lease;

	snprintf(tmp, sizeof(tmp), "%s", line);
	dewhites(tmp);

	p = strtok_r(tmp, " \t=", &plast);
	if (p == NULL || !read_eha(p, eha))
		return 0;

	p = strtok_r(NULL, " \t=", &plast);
	if (p == NULL || inet_aton(p, &in) == 0)
		return 0;

	lease = (struct static_lease *)malloc(sizeof(struct static_lease));
	if (lease == 0)
		return 0;

	lease->ipaddr = in.s_addr;
	memcpy(lease->chaddr, eha, ETH_ALEN);

	list_add_tail((struct list_head *)lease, (struct list_head *)arg);
	return 1;
}

static struct config_keyword keywords[] = {
	/* keyword         handler     variable address                default */
	{"start", read_ip, &(server_config.start), "192.168.0.20"},
	{"end", read_ip, &(server_config.end), "192.168.0.254"},
	{"interface", read_str, &(server_config.interface), "eth0"},
	{"option", read_opt, &(server_config.options), ""},
	{"opt", read_opt, &(server_config.options), ""},
	{"max_leases", read_u32, &(server_config.max_leases), "254"},
#ifndef LEASE_WRITE_THRU
	{"remaining", read_yn, &(server_config.remaining), "yes"},
#endif
	{"auto_time", read_u32, &(server_config.auto_time), "7200"},
	{"decline_time", read_u32, &(server_config.decline_time), "3600"},
	{"conflict_time", read_u32, &(server_config.conflict_time), "3600"},
	{"offer_time", read_u32, &(server_config.offer_time), "60"},
	{"min_lease", read_u32, &(server_config.min_lease), "60"},
	{"lease_file", read_str, &(server_config.lease_file), "/var/lib/misc/udhcpd.leases"},
	{"pidfile", read_str, &(server_config.pidfile), "/var/run/udhcpd.pid"},
	{"notify_file", read_str, &(server_config.notify_file), ""},
	{"siaddr", read_ip, &(server_config.siaddr), "0.0.0.0"},
	{"sname", read_str, &(server_config.sname), ""},
	{"boot_file", read_str, &(server_config.boot_file), ""},
	{"sdmz", read_u32, &(server_config.sdmz_enabled), "0"},
	{"dmz_host_ip", read_ip, &(server_config.dmz_host_ip), "0.0.0.0"},
	{"dmz_host_gw", read_ip, &(server_config.dmz_host_gw), "0.0.0.0"},
	{"dmz_host_mask", read_ip, &(server_config.dmz_host_mask), "0.0.0.0"},
	{"dmz_host_mac", read_eha, &server_config.sdmz_chaddr[0], ""},
	{"static_lease", read_static_lease, &(server_config.static_leases), ""},
	{"probe_period", read_u32, &(server_config.probe_period), "60"},
	{"dhcp_protection", read_u32, &(server_config.dhcp_protection), ""},
	{"", NULL, NULL, ""}
};

int read_config(char *file)
{
	FILE *in;
	char buffer[256], *token, *line;
	int i;

	for (i = 0; strlen(keywords[i].keyword); i++)
		if (strlen(keywords[i].def))
			keywords[i].handler(keywords[i].def, keywords[i].var);

	if (!(in = fopen(file, "r"))) {
		LOG(LOG_ERR, "unable to open config file: %s", file);
		return 0;
	}

	while (fgets(buffer, sizeof(buffer), in)) {
		if (strchr(buffer, '\n'))
			*(strchr(buffer, '\n')) = '\0';
		if (strchr(buffer, '#'))
			*(strchr(buffer, '#')) = '\0';
		token = buffer + strspn(buffer, " \t");
		if (*token == '\0')
			continue;
		line = token + strcspn(token, " \t=");
		if (*line == '\0')
			continue;
		*line = '\0';
		line++;

		/* eat leading whitespace */
		line = line + strspn(line, " \t=");
		/* eat trailing whitespace */
		for (i = strlen(line); i > 0 && isspace(line[i - 1]); i--) ;
		line[i] = '\0';

		for (i = 0; strlen(keywords[i].keyword); i++)
			if (!strcasecmp(token, keywords[i].keyword))
				if (!keywords[i].handler(line, keywords[i].var)) {
					/* reset back to the default value */
					keywords[i].handler(keywords[i].def,
							    keywords[i].var);
				}
	}
	fclose(in);
	return 1;
}

/* the dummy var is here so this can be a signal handler */
void write_leases(void)
{
	FILE *f, *f2 = NULL;
	struct dhcpOfferedAddr *lease = leases;
	unsigned int i;
#ifndef LEASE_WRITE_THRU
	time_t curr;
	u_int32_t lease_time, expires;
#endif

	if (!(f = fopen(server_config.lease_file, "w"))) {
		LOG(LOG_ERR, "Unable to open %s for writing", server_config.lease_file);
		return;
	}
#ifndef LEASE_WRITE_THRU
	if (server_config.remaining)
		curr = monotonic_sec();
#endif
	for (i = 0; i < server_config.max_leases; i++, lease++) {
		if (lease->yiaddr != 0) {
#ifdef LEASE_WRITE_THRU
			fwrite(lease, sizeof(*lease), 1, f);
#else
			expires = lease->expires;	/* back-up & keep host byte-order */
			if (server_config.remaining) {
				if (lease_expired(lease))
					lease_time = 0;
				else
					lease_time = lease->expires - curr;
			} else
				lease_time = lease->expires;

			lease->expires = lease_time;
			fwrite(lease, sizeof(*lease), 1, f);
			lease->expires = expires;
#endif	/* LEASE_WRITE_THRU */

			if (lease->VoIP_Device == 1 && !lease_expired(lease)) {
				if (f2 == NULL)
					f2 = fopen(_PATH_DHCPS_VOIP_LEASES, "w");
				if (f2)
					fprintf(f2, "%s %u.%u.%u.%u %u\n",
						ether_ntoa(lease->chaddr),
						NIPQUAD(lease->yiaddr),
#ifdef LEASE_WRITE_THRU
						lease->expires
#else
						lease_time
#endif
						);
			}
		}
	}

	fclose(f);
	if (f2)
		fclose(f2);

	if (server_config.notify_file)
		yexecl(NULL, "%s %s", server_config.notify_file, server_config.lease_file);
}

void read_leases(char *file)
{
	FILE *f;
	unsigned int i = 0;
	struct dhcpOfferedAddr lease, *oldest;
	struct static_lease *slease;
	time_t curr = monotonic_sec();

	if (!(f = fopen(file, "r"))) {
		/* LOG(LOG_ERR, "Unable to open %s for reading", file); */
		return;
	}

	while (i < server_config.max_leases && (fread(&lease, sizeof lease, 1, f) == 1)) {
		slease = find_static_by_yiaddr(lease.yiaddr);
		if (slease && memcmp(slease->chaddr, lease.chaddr, 6))
			continue;

		if (ntohl(lease.yiaddr) >= ntohl(server_config.start) &&
		    ntohl(lease.yiaddr) <= ntohl(server_config.end)) {
#ifndef LEASE_WRITE_THRU
			if (!server_config.remaining)
#endif
				lease.expires -= curr;

			if (!(oldest = add_lease(lease.chaddr, lease.yiaddr, lease.expires))) {
				LOG(LOG_WARNING, "Too many leases while loading %s\n", file);
				break;
			}
			strncpy(oldest->hostname, lease.hostname, sizeof(oldest->hostname) - 1);
			oldest->hostname[sizeof(oldest->hostname) - 1] = '\0';
			oldest->VoIP_Device = ntohl(lease.VoIP_Device);
			i++;
		}
	}

	DEBUG(LOG_INFO, "Read %d leases", i);
	fclose(f);
}
