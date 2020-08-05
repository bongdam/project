/* dhcpd.c
 *
 * Moreton Bay DHCP Server
 * Copyright (C) 1999 Matthew Ramsay <matthewr@moreton.com.au>
 *			Chris Trew <ctrew@moreton.com.au>
 *
 * Rewrite by Russ Dill <Russ.Dill@asu.edu> July 2001
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

#define _GNU_SOURCE
#include <fcntl.h>
#include <string.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <time.h>
#include <sys/time.h>
#include "debug.h"
#include "dhcpd.h"
#include "arpping.h"
#include "socket.h"
#include "options.h"
#include "files.h"
#include "leases.h"
#include "packet.h"
#include "serverpacket.h"
#include "pidfile.h"

#include <bcmnvram.h>

int probe_server_main(const int, int);
static int probe_pid;

/* globals */
struct dhcpOfferedAddr *leases;
struct server_config_t server_config;
static int signal_pipe[2];

static char VoIP_Device_STR[32] = {0};

static void chld_handler(int sig)
{
	pid_t pid;

	(void)sig;
	while ((pid = waitpid(-1, NULL, WNOHANG)) > 0)
		if (probe_pid == pid)
			probe_pid = 0;
}

/* Exit and cleanup */
static void exit_server(int retval)
{
	pidfile_delete(server_config.pidfile);
	CLOSE_LOG();
	exit(retval);
}

/* Signal handler */
static void signal_handler(int sig)
{
	if (send(signal_pipe[1], &sig, sizeof(sig), MSG_DONTWAIT) < 0) {
		LOG(LOG_ERR, "DHCPD failed to send signal: %s",
			strerror(errno));
	}
}

#ifdef COMBINED_BINARY
int udhcpd_main(int argc, char *argv[])
#else
int main(int argc, char *argv[])
#endif
{
	fd_set rfds;
	struct timeval tv;
	int max_sock, server_socket = -1;
	int bytes, retval;
	struct dhcpMessage packet;
	unsigned char *state;
	unsigned char *server_id_opt, *requested_ip_opt;
	u_int32_t server_id_align, requested_nip;
	unsigned long timeout_end;
	struct option_set *option;
	struct dhcpOfferedAddr *lease, fake_lease;
	struct static_lease *slease;
	int pid_fd, halt = 0;
	int sig;
	u_int8_t haddress[16];

	OPEN_LOG("udhcpd");
	LOG(LOG_INFO, "DHCPD START");
	memset(&server_config, 0, sizeof(struct server_config_t));
	INIT_LIST_HEAD(&server_config.static_leases);

	if (argc < 2)
		read_config(DHCPD_CONF_FILE);
	else
		read_config(argv[1]);

	pid_fd = pidfile_acquire(server_config.pidfile);
	pidfile_write_release(pid_fd);

	nvram_get_r_def("VoIP_DEVICE_STR", VoIP_Device_STR, sizeof(VoIP_Device_STR), "Voice Device");

	if ((option = find_option(server_config.options, DHCP_LEASE_TIME))) {
		memcpy(&server_config.lease, option->data + 2, 4);
		server_config.lease = ntohl(server_config.lease);
	} else
		server_config.lease = LEASE_TIME;

	leases = malloc(sizeof(struct dhcpOfferedAddr) * server_config.max_leases);
	memset(leases, 0, sizeof(struct dhcpOfferedAddr) * server_config.max_leases);
	read_leases(server_config.lease_file);

	if (read_interface(server_config.interface, &server_config.ifindex,
			   &server_config.server, server_config.arp) < 0)
		exit_server(1);

#ifndef DEBUGGING
	pid_fd = pidfile_acquire(server_config.pidfile);	/* hold lock during fork. */
	if (daemon(0, 0) == -1) {
		perror("fork");
		exit_server(1);
	}
	pidfile_write_release(pid_fd);
#endif
	socketpair(AF_UNIX, SOCK_STREAM, 0, signal_pipe);
	signal(SIGUSR1, signal_handler);
	signal(SIGUSR2, SIG_IGN);
	signal(SIGTERM, signal_handler);
	signal(SIGCHLD, chld_handler);

	if (server_config.dhcp_protection > 0) {
		probe_pid = fork();
		if (probe_pid == 0) {
			for (sig = 0; sig < (_NSIG - 1); sig++)
				signal(sig, SIG_DFL);
			probe_server_main((server_config.probe_period < 30) ? \
					  30000 : (server_config.probe_period * 1000),
					  signal_pipe[1]);
			exit_server(0);
		}
	}

	timeout_end = monotonic_sec() + server_config.auto_time;

	while (1) {		/* loop until universe collapses */
		if (server_socket < 0)
			if ((server_socket = listen_socket(INADDR_ANY, SERVER_PORT, server_config.interface)) < 0) {
				LOG(LOG_ERR, "FATAL: couldn't create server socket, %s", strerror(errno));
				exit_server(0);
			}

		FD_ZERO(&rfds);
		FD_SET(server_socket, &rfds);
		FD_SET(signal_pipe[0], &rfds);
		if (server_config.auto_time) {
			tv.tv_sec = timeout_end - monotonic_sec();
			tv.tv_usec = 0;
		}
		if (!server_config.auto_time || tv.tv_sec > 0) {
			max_sock = server_socket > signal_pipe[0] ? server_socket : signal_pipe[0];
			retval = select(max_sock + 1, &rfds, NULL, NULL,
					server_config.auto_time ? &tv : NULL);
		} else
			retval = 0;	/* If we already timed out, fall through */


		if (retval == 0) {
			write_leases();
			timeout_end = monotonic_sec() + server_config.auto_time;
			continue;
		} else if (retval < 0) {
			if (errno != EINTR)
				DEBUG(LOG_INFO, "DHCPD select: %s", strerror(errno));
			continue;
		}

		if (FD_ISSET(signal_pipe[0], &rfds)) {
			if (read(signal_pipe[0], &sig, sizeof(sig)) > 0) {
				switch (sig) {
				case SIGUSR1:
					write_leases();
					/* why not just reset the timeout, eh */
					timeout_end = monotonic_sec() + server_config.auto_time;
					break;
				case SIGTERM:
					/* Alwasy leave a lease files - young 2011-09-24 */
					write_leases();
					if (probe_pid > 0 && !kill(probe_pid, SIGTERM))
						sleep(1);	/* should be interrupted before timed out */
					exit_server(0);
					break;
				case USIGSTOP:
				case USIGCONT:
					halt = !!(sig == USIGSTOP);
					break;
				}
			}
			if ((retval - 1) == 0)
				continue;
		}

		if ((bytes = get_packet(&packet, server_socket)) < 0) {	/* this waits for a packet - idle */
			if (bytes == -1 && errno != EINTR) {
				DEBUG(LOG_INFO, "error on read, %s, reopening socket", strerror(errno));
				close(server_socket);
				server_socket = -1;
			}
			continue;
		}

		if (halt)
			continue;

		if ((state = get_option(&packet, DHCP_MESSAGE_TYPE)) == NULL) {
			DEBUG(LOG_ERR, "couldn't get option from packet, ignoring");
			continue;
		}

		server_id_opt = get_option(&packet, DHCP_SERVER_ID);
		if (server_id_opt) {
			memcpy(&server_id_align, server_id_opt, 4);
			if (server_id_align != server_config.server) {
				DEBUG(LOG_INFO, "server ID doesn't match, ignoring");
				//APNRTL-329 fixed
				continue;
			}
		}

		slease = find_static_by_chaddr(packet.chaddr);
		if (slease) {
			memset(&fake_lease, 0, sizeof(fake_lease));
			memcpy(&fake_lease.chaddr, &packet.chaddr, 6);
			fake_lease.yiaddr = slease->ipaddr;
			fake_lease.expires = 0;
			lease = &fake_lease;
		} else
			lease = find_lease_by_chaddr(packet.chaddr);

		requested_ip_opt = get_option(&packet, DHCP_REQUESTED_IP);
		if (requested_ip_opt) {
			memcpy(&requested_nip, requested_ip_opt, 4);
		}

		switch (state[0]) {
		case DHCPDISCOVER:
			LOG(LOG_INFO, "DHCPD DISCOVER RECEIVE[%s]", ether_ntoa(packet.chaddr));
			sendOffer(&packet, &lease);
			if (lease) {
				unsigned char *temp;

				if ((temp = get_option(&packet, DHCP_VENDOR)) &&
				    (temp[-1] >= 1) &&
				    !strncmp((char *)temp, VoIP_Device_STR, temp[-1]))
					lease->VoIP_Device = 1;
				else
					lease->VoIP_Device = 0;
			}
			break;
		case DHCPREQUEST:
			if (!requested_ip_opt) {
				LOG(LOG_INFO, "DHCPD REQUEST RECEIVE [%s]", ether_ntoa(packet.chaddr));
				requested_nip = packet.ciaddr;
				if (requested_nip == 0) {
					DEBUG(LOG_INFO, "no requested IP and no ciaddr, ignoring");
					break;
				}
			} else {
				LOG(LOG_INFO, "DHCPD REQUEST RECEIVE [" NQF "]", NIPQUAD(requested_nip));
			}

// addon
			if (sdmz_host_match(packet.chaddr, packet.hlen)) {
				FILE *f;
				u_int32_t tmp;

				/* After a WAN's ip address had been lost, the lease of super-dmz
				 * host must be cleared, thereby dhcpd would assign an ip address
				 * within LAN's subnet. - young 2011/10/07
				 */
				tmp = server_config.dmz_host_ip;
				f = fopen("/proc/sys/private/twin_inaddr", "r");
				if (f) {
					server_config.dmz_host_ip = INADDR_ANY;
					fscanf(f, "%u", &server_config.dmz_host_ip);
					fclose(f);
				}

				if (lease != NULL) {
					if ((!server_config.dmz_host_ip && (tmp == lease->yiaddr)) ||
						(server_config.dmz_host_ip && (server_config.dmz_host_ip != lease->yiaddr))) {
						memset(lease, 0, sizeof(struct dhcpOfferedAddr));
						sendNAK(&packet);
#ifdef LEASE_WRITE_THRU
						write_leases();
#endif
						break;
					}
				} else if (server_config.dmz_host_ip &&
					   ((requested_ip_opt && requested_nip != server_config.dmz_host_ip) ||
						(packet.ciaddr && packet.ciaddr != server_config.dmz_host_ip))) {
					sendNAK(&packet);
					break;
				}
			}
//
			if (lease && requested_nip == lease->yiaddr) {
				/* client requested or configured IP matches the lease.
				 * ACK it, and bump lease expiration time. */
				sendACK(&packet, lease->yiaddr);
#ifdef LEASE_WRITE_THRU
				write_leases();
#endif
				break;
			}
			/* No lease for this MAC, or lease IP != requested IP */
			if (server_id_opt    /* client is in SELECTING state */
			 || requested_ip_opt /* client is in INIT-REBOOT state */
			) {
				/* "No, we don't have this IP for you" */
				/* @note: if exist lease about ciaddr, need to delete it for giving refresh ip*/
				if (lease)
					memset(lease, 0, sizeof(struct dhcpOfferedAddr));
				sendNAK(&packet);
			}
			/* client is in RENEWING or REBINDING */
			else if (lease == NULL &&
				 (ntohl(packet.ciaddr) >= ntohl(server_config.start) &&
				  ntohl(packet.ciaddr) <= ntohl(server_config.end)) &&
				 !find_lease_by_yiaddr(packet.ciaddr) &&
				 (arpping(packet.ciaddr, haddress, server_config.server,
						  server_config.arp, server_config.interface)
				  || !memcmp(haddress, packet.chaddr, 6))) {
				sendACK(&packet, packet.ciaddr);
			} else {
				/* @note: if exist lease about ciaddr, need to delete it for giving refresh ip*/
				if (lease)
					memset(lease, 0, sizeof(struct dhcpOfferedAddr));
				sendNAK(&packet);
			}
#ifdef LEASE_WRITE_THRU
			write_leases();
#endif
			break;
		case DHCPDECLINE:
			LOG(LOG_INFO, "DHCPD DECLINE RECEIVE [%s]", ether_ntoa(packet.chaddr));
			if (lease) {
				memset(lease->chaddr, 0, 16);
				lease->expires = monotonic_sec() + server_config.decline_time;
#ifdef LEASE_WRITE_THRU
				write_leases();
#endif
			}
			break;
		case DHCPRELEASE:
			LOG(LOG_INFO, "DHCPD RELEASE RECEIVE [" NQF "]", NIPQUAD(packet.ciaddr));
			if (lease) {
				lease->expires = monotonic_sec();
#ifdef LEASE_WRITE_THRU
				write_leases();
#endif
			}
			break;
		case DHCPINFORM:
			LOG(LOG_INFO, "DHCPD INFORM RECEIVE [%s]", ether_ntoa(packet.chaddr));
			send_inform(&packet);
			break;
		default:
			LOG(LOG_WARNING, "unsupported DHCP message (%02x) -- ignoring", state[0]);
		}
	}
	return 0;
}
