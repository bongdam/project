/* script.c
 *
 * Functions to call the DHCP client notification scripts
 *
 * Russ Dill <Russ.Dill@asu.edu> July 2001
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

#include <string.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <errno.h>

#include "options.h"
#include "dhcpd.h"
#include "dhcpc.h"
#include "packet.h"
#include "options.h"
#include "debug.h"

/* Fill dest with the text of option 'option'. */
static void fill_options(struct cbuffer *m,
			 unsigned char *option, struct dhcp_option *type_p)
{
	int type, optlen;
	u_int16_t val_u16;
	int16_t val_s16;
	u_int32_t val_u32;
	int32_t val_s32;
	int len = option[OPT_LEN - 2];

	cbprintf(m, "%s=", type_p->name);

	type = type_p->flags & TYPE_MASK;
	optlen = option_lengths[type];
	for(;;) {
		switch (type) {
		case OPTION_IP_PAIR:
			cbprintf(m, "%u.%u.%u.%u/", option[0], option[1], option[2], option[3]);
			option += 4;
			optlen = 4;
		case OPTION_IP:	/* Works regardless of host byte order. */
			cbprintf(m, "%u.%u.%u.%u", option[0], option[1], option[2], option[3]);
 			break;
		case OPTION_BOOLEAN:
			cbprintf(m, *option ? "yes" : "no");
			break;
		case OPTION_U8:
			cbprintf(m, "%u", *option);
			break;
		case OPTION_U16:
			memcpy(&val_u16, option, 2);
			cbprintf(m, "%u", ntohs(val_u16));
			break;
		case OPTION_S16:
			memcpy(&val_s16, option, 2);
			cbprintf(m, "%d", ntohs(val_s16));
			break;
		case OPTION_U32:
			memcpy(&val_u32, option, 4);
			cbprintf(m, "%lu", (unsigned long)ntohl(val_u32));
			break;
		case OPTION_S32:
			memcpy(&val_s32, option, 4);
			cbprintf(m, "%ld", (long)ntohl(val_s32));
			break;
		case OPTION_STRING:
			cbprintf(m, "%.*s", len, option);
			return;	 /* Short circuit this case */
		}
		option += optlen;
		len -= optlen;
		if (len <= 0)
			break;
		cbprintf(m, " ");
	}
}


static char *find_env(const char *prefix, char *defaultstr)
{
	extern char **environ;
	char **ptr;
	const int len = strlen(prefix);

	for (ptr = environ; *ptr != NULL; ptr++) {
		if (strncmp(prefix, *ptr, len) == 0)
			return *ptr;
	}
	return defaultstr;
}

/* put all the paramaters into an environment */
static char **fill_envp(struct dhcpMessage *packet)
{
	struct double_null_cbuf envcb;
	char *p, **envp;
	int i;
	char over = 0;
	unsigned char *temp;

	memset(&envcb, 0, sizeof(envcb));
	envcb.cb.size = 256;
	envcb.cb.buf = malloc(envcb.cb.size);

	nnull_printf(&envcb, "interface=%s", client_config.interface);
	nnull_printf(&envcb, "%s", find_env("PATH", "PATH=/bin:/usr/bin:/sbin:/usr/sbin"));
	nnull_printf(&envcb, "%s", find_env("HOME", "HOME=/"));

	if (packet != NULL) {
		nnull_printf(&envcb, "ip=" NQF, NIPQUAD(packet->yiaddr));

		for (i = 0; options[i].code; i++) {
			if (!(temp = get_option(packet, options[i].code))) {
				if (options[i].code == 0x6)
					nnull_printf(&envcb, "dns=180.182.54.1 210.220.163.82");
				continue;
			}
			fill_options(&envcb.cb, temp, &options[i]);
			nnull_pad(&envcb);
		}

		if (packet->siaddr)
			nnull_printf(&envcb, "siaddr=" NQF, NIPQUAD(packet->siaddr));

		if ((temp = get_option(packet, DHCP_OPTION_OVER)))
			over = *temp;

		if (!(over & FILE_FIELD) && packet->file[0])
			nnull_printf(&envcb, "boot_file=%.*s",
				     sizeof(packet->file) - 1, packet->file);

		if (!(over & SNAME_FIELD) && packet->sname[0])
			nnull_printf(&envcb, "sname=%.*s",
				     sizeof(packet->sname) - 1, packet->sname);
	}

	envp = (char **)malloc(sizeof(char *) * envcb.argc + 1);
	i = 0;
	for (p = envcb.cb.buf; p[0]; p += (strlen(p) + 1))
		envp[i++] = p;
	envp[i] = NULL;
	return envp;
}

/* Call a script with a par file and env vars */
void run_script(struct dhcpMessage *packet, const char *name)
{
	int pid;
	char **envp;

	if (client_config.script == NULL)
		return;

	/* call script */
	pid = fork();
	if (pid) {
		waitpid(pid, NULL, 0);
		return;
	} else if (pid == 0) {
		envp = fill_envp(packet);

		/* close fd's? */

		/* exec script */
		DEBUG(LOG_INFO, "execle'ing %s", client_config.script);
		execle(client_config.script, client_config.script, name, NULL, envp);
		/*
		   LOG(LOG_ERR, "script %s failed: %s",
		   client_config.script, strerror(errno));
		 */
		exit(1);
	}
}
