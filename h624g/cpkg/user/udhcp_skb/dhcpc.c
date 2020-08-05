/* dhcpc.c
 *
 * udhcp DHCP client
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

#include <stdio.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/file.h>
#include <unistd.h>
#include <getopt.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <signal.h>
#include <time.h>
#include <string.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <errno.h>
#include <dvflag.h>

#include "dhcpd.h"
#include "dhcpc.h"
#include "options.h"
#include "clientpacket.h"
#include "packet.h"
#include "script.h"
#include "socket.h"
#include "debug.h"
#include "pidfile.h"
#include "arpping.h"
#include "version.h"

extern int setlastmsg(int type);

static int state;
static unsigned long requested_ip;	/* = 0 */
static unsigned long server_addr;
static int packet_num;		/* = 0 */
static int fd = -1;
static int signal_pipe[2];
static unsigned char *eh_dst;
static unsigned char server_eha[6];
static int repeated_nak;	/* Case in which "DIS>OFF<REQ>NAK<" repeated fastly */

#define LISTEN_NONE 0
#define LISTEN_KERNEL 1
#define LISTEN_RAW 2
static int listen_mode;
/* addon */
static int sdmz = 0;
static void server_haddr(struct dhcpMessage *);

#define DEFAULT_SCRIPT	"/usr/share/udhcpc/default.script"

struct client_config_t client_config = {
	/* Default options. */
	abort_if_no_lease:0,
	foreground:0,
	quit_after_lease:0,
	background_if_no_lease:0,
	interface:"eth0",
	pidfile:NULL,
	script:DEFAULT_SCRIPT,
	clientid:NULL,
	hostname:NULL,
	ifindex:0,
	arp:	"\0\0\0\0\0\0",		/* appease gcc-3.0 */
	snoop_request:0,		/* APNRTL-288 */
};

#ifndef BB_VER
static void show_usage(void)
{
	printf("Usage: udhcpc [OPTIONS]\n\n"
		   "  -c, --clientid=CLIENTID         Client identifier\n"
		   "  -H, --hostname=HOSTNAME         Client hostname\n"
		   "  -h                              Alias for -H\n"
		   "  -f, --foreground                Do not fork after getting lease\n"
		   "  -b, --background                Fork to background if lease cannot be\n"
		   "                                  immediately negotiated.\n"
		   "  -i, --interface=INTERFACE       Interface to use (default: eth0)\n"
		   "  -n, --now                       Exit with failure if lease cannot be\n"
		   "                                  immediately negotiated.\n"
		   "  -p, --pidfile=file              Store process ID of daemon in file\n"
		   "  -q, --quit                      Quit after obtaining lease\n"
		   "  -r, --request=IP                IP address to request (default: none)\n"
		   "  -s, --script=file               Run file at dhcp events (default:\n"
		   "                                  " DEFAULT_SCRIPT ")\n"
		   "  -v, --version                   Display version\n");
	exit(0);
}
#endif

/* Exit and cleanup */
static void exit_client(int retval)
{
	pidfile_delete(client_config.pidfile);
	CLOSE_LOG();
	exit(retval);
}

static void prepare_socket(void)
{
	if (fd > -1)
		return;

	switch (listen_mode) {
	case LISTEN_KERNEL:
		fd = listen_socket(INADDR_ANY, CLIENT_PORT, client_config.interface);
		break;
	case LISTEN_RAW:
		fd = raw_socket(client_config.ifindex);
		break;
	default:
		return;
	}
	if (fd < 0) {
		LOG(LOG_ERR, "FATAL: couldn't listen on socket, %s", strerror(errno));
		exit_client(0);
	}
}

/* just a little helper */
static void change_mode(int new_mode)
{
	DEBUG(LOG_INFO, "entering %s listen mode",
		  new_mode ? (new_mode == 1 ? "kernel" : "raw") : "none");

	if (new_mode != LISTEN_NONE && listen_mode == new_mode)
		return;

	if (fd >= 0)
		close(fd);
	fd = -1;
	listen_mode = new_mode;

	prepare_socket();
}

static void perform_init(void)
{
	switch (state) {
	case BOUND:
	case RENEWING:
	case REBINDING:
	case RENEW_REQUESTED:	/* impatient are we? fine, square 1 */
		run_script(NULL, "deconfig");
	default:
		break;
	}
	/* start things over */
	change_mode(LISTEN_RAW);
	state = INIT_SELECTING;
	packet_num = 0;
	setlastmsg(0);	/* APACRTL-79 */
}

static void perform_release(unsigned long xid, int sig)
{
	/* send release packet */
	switch (state) {
	case BOUND:
	case RENEWING:
	case REBINDING:
		if (sig == SIGHUP) {
			LOG(LOG_DEBUG, "DHCPC DECLINE " L_SENTFOR);
			send_decline(xid, server_addr, requested_ip);		/* unicast */
		} else {
			LOG(LOG_DEBUG, "DHCPC RELEASE " L_SENTFOR);
			send_release(server_addr, requested_ip, eh_dst);	/* unicast */
		}
	/* fall through */
	case RENEW_REQUESTED:
		run_script(NULL, "deconfig");
		break;
	default:
		break;
	}

	change_mode(LISTEN_NONE);
	state = RELEASED;
}

static void signal_handler(int sig)
{
	if (write(signal_pipe[1], &sig, sizeof(sig)) < 0)
		LOG(LOG_ERR, "DHCPC failed to send signal: %s", strerror(errno));
}

static void background(void)
{
	int pid_fd;

	pid_fd = pidfile_acquire(client_config.pidfile);	/* hold lock during fork. */
	while (pid_fd >= 0 && pid_fd < 3)
		pid_fd = dup(pid_fd);	/* don't let daemon close it */

	if (daemon(0, 0) == -1) {
		perror("fork");
		exit_client(1);
	}
	client_config.foreground = 1;	/* Do not fork again. */
	pidfile_write_release(pid_fd);
}

#define timer_cmp(a, b, CMP)				\
  (((a)->tv_sec == (b)->tv_sec) ?			\
   (((signed)(a)->tv_usec - (signed)(b)->tv_usec) CMP 0) :\
   (((signed)(a)->tv_sec - (signed)(b)->tv_sec) CMP 0))

#define timeout_set(res, a, b) \
  do {\
	struct timeval __tv = { .tv_sec = (b),\
				.tv_usec = 0 };\
	timeradd(&(a), &__tv, &(res));\
  } while (0)

#ifdef COMBINED_BINARY
int udhcpc_main(int argc, char *argv[])
#else
int main(int argc, char *argv[])
#endif
{
	unsigned char *temp, *message;
	struct timeval timeout, now, start = { 0, 100000 };
	unsigned xid = 0;
	long t1 = 0, t2 = 0;
	unsigned long lease;
	fd_set rfds;
	int retval;		//__DAVO__
	struct timeval tv;
	int c, spare, len;
	struct dhcpMessage packet;
	struct in_addr temp_addr;
	int pid_fd;
	int sig, max_fd;
	u_int8_t haddress[16];

	static struct option arg_options[] = {
		{"clientid", required_argument, 0, 'c'},
		{"foreground", no_argument, 0, 'f'},
		{"background", no_argument, 0, 'b'},
		{"hostname", required_argument, 0, 'H'},
		{"hostname", required_argument, 0, 'h'},
		{"interface", required_argument, 0, 'i'},
		{"now", no_argument, 0, 'n'},
		{"pidfile", required_argument, 0, 'p'},
		{"quit", no_argument, 0, 'q'},
		{"request", required_argument, 0, 'r'},
		{"script", required_argument, 0, 's'},
		{"version", no_argument, 0, 'v'},
		{"help", no_argument, 0, '?'},
		{"snooping", no_argument, 0, 'o'},
		{"sdmz", required_argument, 0, 'm'},
		{0, 0, 0, 0}
	};

	/* get options */
	while (1) {
		int option_index = 0;
		c = getopt_long(argc, argv, "c:fbH:h:i:np:qr:s:vom:",
				arg_options, &option_index);
		if (c == -1)
			break;

		switch (c) {
		case 'c':
			len = strlen(optarg) > 255 ? 255 : strlen(optarg);
			if (client_config.clientid)
				free(client_config.clientid);
			client_config.clientid = malloc(len + 2);
			client_config.clientid[OPT_CODE] = DHCP_CLIENT_ID;
			client_config.clientid[OPT_LEN] = len;
			client_config.clientid[OPT_DATA] = '\0';
			strncpy((char *)client_config.clientid + OPT_DATA, optarg, len);
			break;
		case 'f':
			client_config.foreground = 1;
			break;
		case 'b':
			client_config.background_if_no_lease = 1;
			break;
		case 'h':
		case 'H':
			len = strlen(optarg) > 255 ? 255 : strlen(optarg);
			if (client_config.hostname)
				free(client_config.hostname);
			client_config.hostname = malloc(len + 2);
			client_config.hostname[OPT_CODE] = DHCP_HOST_NAME;
			client_config.hostname[OPT_LEN] = len;
			strncpy((char *)client_config.hostname + 2, optarg, len);
			break;
		case 'i':
			client_config.interface = optarg;
			break;
		case 'n':
			client_config.abort_if_no_lease = 1;
			break;
		case 'p':
			client_config.pidfile = optarg;
			break;
		case 'q':
			client_config.quit_after_lease = 1;
			break;
		case 'r':
			requested_ip = inet_addr(optarg);
			break;
		case 's':
			client_config.script = optarg;
			break;
		case 'v':
			printf("udhcpcd, version %s\n\n", DHCP_VERSION);
			exit_client(0);
			break;
		case 'o':
			client_config.snoop_request = 1;
			break;
		case 'm':
			sdmz = strtol(optarg, NULL, 10);
			break;
		default:
			show_usage();
		}
	}

	pid_fd = pidfile_acquire(client_config.pidfile);
	pidfile_write_release(pid_fd);

	if (read_interface(client_config.interface, &client_config.ifindex,
			   NULL, client_config.arp) < 0)
		exit_client(1);

	if (!client_config.clientid) {
		client_config.clientid = malloc(6 + 3);
		client_config.clientid[OPT_CODE] = DHCP_CLIENT_ID;
		client_config.clientid[OPT_LEN] = 7;
		client_config.clientid[OPT_DATA] = 1;
		memcpy(client_config.clientid + 3, client_config.arp, 6);
	}

	/* ensure that stdin/stdout/stderr are never returned by pipe() */
	if (fcntl(STDIN_FILENO, F_GETFL) == -1)
		(void)open("/dev/null", O_RDONLY);
	if (fcntl(STDOUT_FILENO, F_GETFL) == -1)
		(void)open("/dev/null", O_WRONLY);
	if (fcntl(STDERR_FILENO, F_GETFL) == -1)
		(void)open("/dev/null", O_WRONLY);

	OPEN_LOG("udhcpc");
	LOG(LOG_DEBUG, "DHCPC " L_CLIENT " " L_STARTUP);
	pipe(signal_pipe);
	/*signal(SIGUSR1, signal_handler);*/
	signal(SIGUSR2, signal_handler);
	signal(SIGHUP, 	signal_handler);
	signal(SIGTERM, signal_handler);

	state = INIT_SELECTING;
	run_script(NULL, "deconfig");
	/* NOTE:
	 * The link event has been deferred a little seconds on purpose, which
	 * might cause USR1 to be sent after bound. The resulting 4-way DHCP
	 * message exchange happened once more unnecessarily.
	 */
	signal(SIGUSR1, SIG_IGN);
	wait_for_flags(DF_WANLINK, 0, 5000);
	signal(SIGUSR1, signal_handler);

	change_mode(LISTEN_RAW);
	getmonotime(&now);
	/* avoid race-condition between USR1 sender and intial DISCOVER */
	timeradd(&now, &start, &timeout);

	for (;;) {
		if (sdmz && state == INIT_SELECTING)
			eh_dst = NULL;
		prepare_socket();
		getmonotime(&now);
		if (timer_cmp(&timeout, &now, >)) {
			timersub(&timeout, &now, &tv);

			FD_ZERO(&rfds);
			FD_SET(signal_pipe[0], &rfds);
			max_fd = signal_pipe[0];
			if (listen_mode) {
				FD_SET(fd, &rfds);
				max_fd = MAX(fd, max_fd);
			}
			retval = select(max_fd + 1, &rfds, NULL, NULL, &tv);
			getmonotime(&now);
		} else
			retval = 0;	/* If we already timed out, fall through */

		if (retval == 0) {
			/* timeout dropped to zero */
			switch (state) {
			case INIT_SELECTING:
				if (packet_num < 7) {
					if (packet_num == 0)
						xid = random_xid();

					/* send discover packet */
					send_discover(xid, requested_ip);	/* broadcast */
					timeout_set(timeout, now, (1 << packet_num));
					packet_num++;
				} else {
					if (client_config.background_if_no_lease)
						background();
					else if (client_config.abort_if_no_lease)
						exit_client(1);
					/* wait to try again */
					packet_num = 0;
					timeout = now;
				}
				break;
			case REQUESTING:
				if (packet_num < 7) {
					send_selecting(xid, server_addr, requested_ip);	/* broadcast */
					timeout_set(timeout, now, (1 << packet_num));
					packet_num++;
				} else {
					/* timed out, go back to init state */
					state = INIT_SELECTING;
					timeout = now;
					packet_num = 0;
					change_mode(LISTEN_RAW);
				}
				break;
			case BOUND:
				/* Lease is starting to run out, time to enter renewing state */
				state = RENEWING;
				change_mode(sdmz ? LISTEN_RAW : LISTEN_KERNEL);
				DEBUG(LOG_INFO, "Entering renew state");
				/* fall right through */
			case RENEW_REQUESTED:	/* manual renew by SIGUSR1 */
			case RENEWING:
/* RFC 2131 4.4.5 paragraph 8th:
	In both RENEWING and REBINDING states, if the client receives no
	response to its DHCPREQUEST message, the client SHOULD wait one-half
	of the remaining time until T2 (in RENEWING state) and one-half of
	the remaining lease time (in REBINDING state), down to a minimum of
	60 seconds, before retransmitting the DHCPREQUEST message.
*/
				if ((spare = (t2 - t1)) > 0) {
					send_renew(xid, server_addr, requested_ip, eh_dst);	/* unicast */
					if (!(c = spare >> 1))	/* APNRTL-289 */
						c = 1;
					timeout_set(timeout, now, c);
					t1 += c;
					break;
				}
				/* Timed out, enter rebinding state */
				state = REBINDING;
				DEBUG(LOG_INFO, "Entering rebinding state");
				change_mode(LISTEN_RAW);
				packet_num = 0;
				/* fall right through */
			case REBINDING:
				/* Either set a new T2, or enter INIT state */
				if ((spare = (lease - t2)) > 0) {
					send_renew(xid, 0, requested_ip, NULL);	/* broadcast */
					if (!(c = spare >> 1))	/* APNRTL-289 */
						c = 1;
					timeout_set(timeout, now, c);
					t2 += c;
				} else {
					/* timed out, enter init state */
					state = INIT_SELECTING;
					run_script(NULL, "deconfig");
					timeout = now;
					packet_num = 0;
					change_mode(LISTEN_RAW);
				}
				break;
			case RELEASED:
				/* yah, I know, *you* say it would never happen */
				timeout_set(timeout, now, sizeof(int) - 1);
				break;
			}
		} else if (retval > 0 && listen_mode != LISTEN_NONE && FD_ISSET(fd, &rfds)) {
			/* a packet is ready, read it */
			if (listen_mode == LISTEN_KERNEL)
				len = get_packet(&packet, fd);
			else
				len = get_raw_packet(&packet, fd);

			if (len == -1 && errno != EINTR) {
				DEBUG(LOG_INFO, "error on read, %s, reopening socket", strerror(errno));
				change_mode(listen_mode);	/* just close and reopen */
			}
			if (len < 0)
				continue;

			if (packet.xid != xid) {
				DEBUG(LOG_INFO, "Ignoring XID %lx (our xid is %lx)",
					  (unsigned long)packet.xid, xid);
				continue;
			}

			if ((message = get_option(&packet, DHCP_MESSAGE_TYPE)) == NULL) {
				DEBUG(LOG_ERR, "couldnt get option from packet -- ignoring");
				continue;
			}

			switch (state) {
			case INIT_SELECTING:
				/* Must be a DHCPOFFER to one of our xid's */
				if (*message == DHCPOFFER) {
					if ((temp = get_option(&packet, DHCP_SERVER_ID))) {
						memcpy(&server_addr, temp, 4);
						xid = packet.xid;
						requested_ip = packet.yiaddr;

						/* enter requesting state */
						state = REQUESTING;
						timeout = now;
						packet_num = 0;
						LOG(LOG_INFO, "DHCPC OFFER " L_RCVFROM);
					} else {
						DEBUG(LOG_ERR, "No server ID in message");
					}
				}
				break;
			case RENEW_REQUESTED:
			case REQUESTING:
			case RENEWING:
			case REBINDING:
				packet_num = 0;
				if (*message == DHCPACK) {
					if (!(temp = get_option(&packet, DHCP_LEASE_TIME)))
						lease = 60 * 60;
					else {
						memcpy(&lease, temp, 4);
						lease = ntohl(lease);
					}

					/* enter bound state */
					t1 = lease / 2;
					/* little fixed point for n * .875 */
					t2 = (lease * 0x7) >> 3;
					temp_addr.s_addr = packet.yiaddr;
					LOG((state == REQUESTING || state == REBINDING) ? LOG_INFO : LOG_DEBUG,
					    "DHCPC ACK " L_ACKED, inet_ntoa(temp_addr), lease);
					start = now;
					timeout_set(timeout, start, t1);
					requested_ip = packet.yiaddr;
					if ((state != RENEWING && state != REBINDING) &&
					    ({ memcpy(haddress, client_config.arp, 6); 1; }) &&
					    !arpping(packet.yiaddr, haddress, packet.yiaddr,
							client_config.arp, client_config.interface) &&
					    memcmp(haddress, client_config.arp, 6)) {
						send_decline(xid, server_addr, requested_ip);
						state = INIT_SELECTING;
						change_mode(LISTEN_RAW);
						packet_num = 0;
						t1 = 10;	/* RFC2131 3.1.5 */
						timeout_set(timeout, now, t1);
					} else {
						run_script(&packet, ((state == RENEWING || state == REBINDING) ? "renew" : "bound"));
						state = BOUND;
						change_mode(LISTEN_NONE);
					}
					repeated_nak = 0;
					if (client_config.quit_after_lease)
						exit_client(0);
					if (!client_config.foreground)
						background();
					/* addon */
					if (sdmz && eh_dst == NULL && state == BOUND)
						server_haddr(&packet);
				} else if (*message == DHCPNAK) {
					/* return to init state */
					LOG(LOG_DEBUG, "DHCPC NAK " L_RCVED);
					run_script(&packet, "nak");
					if (state != REQUESTING)
						run_script(NULL, "deconfig");
					state = INIT_SELECTING;
					timeout_set(timeout, now, repeated_nak);
					requested_ip = 0;
					if (++repeated_nak > 2)
						repeated_nak = 2;
					change_mode(LISTEN_RAW);
				}
				break;
			case BOUND:
			case RELEASED:
				/* ignore all packets */
				break;
			}
		} else if (retval > 0 && FD_ISSET(signal_pipe[0], &rfds)) {
			if (read(signal_pipe[0], &sig, sizeof(sig)) < 0) {
				DEBUG(LOG_ERR, "Could not read signal: %s", strerror(errno));
				continue;	/* probably just EINTR */
			}
			switch (sig) {
			case SIGUSR1:
				perform_init();
				getmonotime(&timeout);
				continue;
			case SIGUSR2:
			case SIGHUP:
				perform_release(xid, sig);
				/* maximum seconds to be in slumber */
				timeout_set(timeout, now, sizeof(int) - 1);
				continue;
			case SIGTERM:
				exit_client(0);
				break;
			}
		} else if (retval == -1 && errno == EINTR) {
			/* a signal was caught */
		} else {
			/* An error occured */
			DEBUG(LOG_ERR, "Error on select");
		}
	}
	return 0;
}

static void server_haddr(struct dhcpMessage *packet)
{
	u_int32_t siaddr = 0;
	unsigned char *opt;
	unsigned char shaddr[6] = { 0 };

	if ((opt = get_option(packet, DHCP_SERVER_ID)))
		memcpy(&siaddr, opt, 4);
	else
		siaddr = server_addr;

	if (!siaddr)
		return;

	if (!arplookup(siaddr, shaddr, client_config.interface) ||
		!arpping(siaddr, shaddr, packet->yiaddr, client_config.arp,
			 client_config.interface)) {
		 if (memcmp(shaddr, MAC_BCAST_ADDR, 6) &&
			 memcmp(shaddr, "\000\000\000\000\000\000", 6))
			 memcpy(server_eha, shaddr, 6);
			 eh_dst = server_eha;
	}
}
