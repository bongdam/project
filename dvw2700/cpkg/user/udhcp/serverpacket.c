/* serverpacket.c
 *
 * Constuct and send DHCP server packets
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

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include <time.h>

#include "packet.h"
#include "debug.h"
#include "dhcpd.h"
#include "options.h"
#include "leases.h"
#include "files.h"

static void add_sdmz_option_string(struct dhcpMessage *packet,
				   struct option_set *curr);

/* send a packet to giaddr using the kernel ip stack */
static int send_packet_to_relay(struct dhcpMessage *payload)
{
	DEBUG(LOG_INFO, "Forwarding packet to relay");
	return kernel_packet(payload, server_config.server, SERVER_PORT,
			     payload->giaddr, SERVER_PORT);
}

/* send a packet to a specific arp address and ip address by creating our own ip packet */
static int send_packet_to_client(struct dhcpMessage *payload,
				 int force_broadcast)
{
	unsigned char *chaddr;
	u_int32_t ciaddr;

	if (force_broadcast) {
		DEBUG(LOG_INFO, "broadcasting packet to client (NAK)");
		ciaddr = INADDR_BROADCAST;
		chaddr = MAC_BCAST_ADDR;
	} else if (payload->ciaddr) {
		DEBUG(LOG_INFO, "unicasting packet to client ciaddr");
		ciaddr = payload->ciaddr;
		chaddr = payload->chaddr;
	} else if (ntohs(payload->flags) & BROADCAST_FLAG) {
		DEBUG(LOG_INFO, "broadcasting packet to client (requested)");
		ciaddr = INADDR_BROADCAST;
		chaddr = MAC_BCAST_ADDR;
	} else {
		DEBUG(LOG_INFO, "unicasting packet to client yiaddr");
		ciaddr = payload->yiaddr;
		chaddr = payload->chaddr;
	}
	return raw_packet(payload, server_config.server, SERVER_PORT,
			  ciaddr, CLIENT_PORT, chaddr, server_config.ifindex);
}

/* send a dhcp packet, if force broadcast is set, the packet will be broadcast to the client */
static int send_packet(struct dhcpMessage *payload, int force_broadcast)
{
	int ret;

	if (payload->giaddr)
		ret = send_packet_to_relay(payload);
	else
		ret = send_packet_to_client(payload, force_broadcast);
	return ret;
}

static void init_packet(struct dhcpMessage *packet,
			struct dhcpMessage *oldpacket, char type)
{
	init_header(packet, type);
	packet->xid = oldpacket->xid;
	memcpy(packet->chaddr, oldpacket->chaddr, 16);
	packet->flags = oldpacket->flags;
	packet->giaddr = oldpacket->giaddr;
	packet->ciaddr = oldpacket->ciaddr;
	add_simple_option(packet->options, DHCP_SERVER_ID, server_config.server);
}

/* add in the bootp options */
static void add_bootp_options(struct dhcpMessage *packet)
{
	packet->siaddr = server_config.siaddr;
	if (server_config.sname)
		strncpy((char *)packet->sname, server_config.sname,
			sizeof(packet->sname) - 1);
	if (server_config.boot_file)
		strncpy((char *)packet->file, server_config.boot_file,
			sizeof(packet->file) - 1);
}

static u_int32_t select_lease_time(struct dhcpMessage *packet)
{
	u_int32_t lease_time_sec = server_config.lease;
	u_int8_t *lease_time_opt = get_option(packet, DHCP_LEASE_TIME);
	if (lease_time_opt) {
		memcpy(&lease_time_sec, lease_time_opt, 4);
		lease_time_sec = ntohl(lease_time_sec);
		if (lease_time_sec > server_config.lease)
			lease_time_sec = server_config.lease;
		if (lease_time_sec < server_config.min_lease)
			lease_time_sec = server_config.min_lease;
	}
	return lease_time_sec;
}

/* MUST be called only by sendOffer */
static int
requested_ip_assignable(struct dhcpMessage *oldpacket, u_int32_t req_align)
{
	struct dhcpOfferedAddr *lease;

	if ((ntohl(req_align) < ntohl(server_config.start)) ||
	    (ntohl(req_align) > ntohl(server_config.end)))
		return 0;

	/* find_static_by_chaddr() preceded below before entering this function */
	if (find_static_by_yiaddr(req_align))
		return 0;

	lease = find_lease_by_yiaddr(req_align);
	if (lease && memcmp(lease->chaddr, oldpacket->chaddr, ETH_ALEN)) {
		if (!lease_expired(lease))
			return 0;
		clear_lease(lease->chaddr, lease->yiaddr);
#ifdef LEASE_WRITE_THRU
		write_leases();
#endif
	}
	/* if a lease exists with the same HW address but has a different IP address
	 * it is cleared by add_lease! */
	return 1;
}

/* send a DHCP OFFER to a DHCP DISCOVER */
int sendOffer(struct dhcpMessage *oldpacket, struct dhcpOfferedAddr **please)
{
	struct dhcpMessage packet;
	struct dhcpOfferedAddr *lease = NULL;
	struct static_lease *slease;
	u_int32_t req_align, lease_time_sec;
	unsigned char *req;
	struct option_set *curr;
	int rc, sdmz_client = 0;

	if (please)
		*please = NULL;

	init_packet(&packet, oldpacket, DHCPOFFER);

	if (sdmz_host_match(oldpacket->chaddr, oldpacket->hlen))
		sdmz_client = (server_config.dmz_host_ip) ? 1 : 2;

	if (sdmz_client == 1) {
		packet.yiaddr = server_config.dmz_host_ip;
	}
	else if ((slease = find_static_by_chaddr(oldpacket->chaddr))) {
		packet.yiaddr = slease->ipaddr;
	}
	else if ((req = get_option(oldpacket, DHCP_REQUESTED_IP)) &&
	         memcpy(&req_align, req, 4) &&
	         requested_ip_assignable(oldpacket, req_align)) {
		packet.yiaddr = req_align;
	}
	else if ((lease = find_lease_by_chaddr(oldpacket->chaddr))) {
		slease = find_static_by_yiaddr(lease->yiaddr);
		if (slease) {
			clear_lease(lease->chaddr, lease->yiaddr);
#ifdef LEASE_WRITE_THRU
			write_leases();
#endif
		} else if (!check_ip(lease->yiaddr, lease->chaddr))
			packet.yiaddr = lease->yiaddr;
#ifdef LEASE_WRITE_THRU
		else
			write_leases();
#endif

		/* If check_ip returns 1, it means that lease was cleared and then lease
		 * was created with lease->yiaddr and the HW address of any arp responder.
		 * After returning from check_ip, it cann't be sured that lease->yiaddr
		 * has zero-ip or the previous ip prior to calling check_ip or an unpredictable one.
		 */
	} else {
		packet.yiaddr = find_address(oldpacket->chaddr);
	}

	if (!packet.yiaddr) {
		LOG(LOG_WARNING, L_NOLEASE);
		return -1;
	}

	if (!(lease = add_lease(packet.chaddr, packet.yiaddr, server_config.offer_time))) {
		LOG(LOG_WARNING, L_LEASEFULL);
		return -1;
	} else if (please)
		*please = lease;

	if (sdmz_client != 0)
		lease_time_sec = 60;
	else
		lease_time_sec = select_lease_time(oldpacket);
	add_simple_option(packet.options, DHCP_LEASE_TIME, htonl(lease_time_sec));

	curr = server_config.options;
	if (sdmz_client == 1)
		add_sdmz_option_string(&packet, curr);
	else {
		while (curr) {
			if (curr->data[OPT_CODE] != DHCP_LEASE_TIME)
				add_option_string(packet.options, curr->data);
			curr = curr->next;
		}
	}

	add_bootp_options(&packet);
	rc = send_packet(&packet, 0);
	if (rc > 0)
		LOG(LOG_INFO, "DHCPD OFFER SENT [" NQF "]", NIPQUAD(packet.yiaddr));
	return rc;
}

int sendNAK(struct dhcpMessage *oldpacket)
{
	struct dhcpMessage packet;

	init_packet(&packet, oldpacket, DHCPNAK);
	LOG(LOG_INFO, "DHCPD NAK SENT [%s]", ether_ntoa(oldpacket->chaddr));
	
	return send_packet(&packet, 1);
}

int sendACK(struct dhcpMessage *oldpacket, u_int32_t yiaddr)
{
	struct dhcpMessage packet;
	struct option_set *curr;
	struct dhcpOfferedAddr *lease;
	u_int32_t lease_time_sec;
	int sdmz_client = 0;

	init_packet(&packet, oldpacket, DHCPACK);

	if (sdmz_host_match(oldpacket->chaddr, oldpacket->hlen))
		sdmz_client = (server_config.dmz_host_ip) ? 1 : 2;

	packet.yiaddr = yiaddr;

	if (sdmz_client != 0)
		lease_time_sec = 60;
	else
		lease_time_sec = select_lease_time(oldpacket);
	add_simple_option(packet.options, DHCP_LEASE_TIME, htonl(lease_time_sec));

	curr = server_config.options;
	if (sdmz_client == 1) {
		packet.yiaddr = server_config.dmz_host_ip;
		add_sdmz_option_string(&packet, curr);
	} else {
		while (curr) {
			if (curr->data[OPT_CODE] != DHCP_LEASE_TIME)
				add_option_string(packet.options, curr->data);
			curr = curr->next;
		}
	}

	add_bootp_options(&packet);

	if (send_packet(&packet, 0) < 0)
		return -1;
	LOG(LOG_INFO, "DHCPD ACK SENT %s[" NQF "]",
	    sdmz_client ? "SuperDMZ Host " : "", NIPQUAD(packet.yiaddr));

	lease = add_lease(packet.chaddr, packet.yiaddr, lease_time_sec);
	if (lease) {
		u_int8_t *hostname_opt = get_option(oldpacket, DHCP_HOST_NAME);

		if (hostname_opt)
			sprintf(lease->hostname, "%.*s",
				MIN(hostname_opt[-1], sizeof(lease->hostname) - 1),
				hostname_opt);
		else
			lease->hostname[0] = '\0';
	}
	return 0;
}

int send_inform(struct dhcpMessage *oldpacket)
{
	struct dhcpMessage packet;
	struct option_set *curr;

	init_packet(&packet, oldpacket, DHCPACK);

	curr = server_config.options;

	while (curr) {
		if (curr->data[OPT_CODE] != DHCP_LEASE_TIME)
			add_option_string(packet.options, curr->data);
		curr = curr->next;
	}

	add_bootp_options(&packet);

	if (send_packet(&packet, 0) < 0)
		return -1;

	return 0;
}

static void
add_sdmz_option_string(struct dhcpMessage *packet, struct option_set *curr)
{
	for (; curr; curr = curr->next) {
		switch (curr->data[OPT_CODE]) {
		case DHCP_ROUTER:
			add_simple_option(packet->options, DHCP_ROUTER, server_config.dmz_host_gw);
			break;
		case DHCP_SUBNET:
			add_simple_option(packet->options, DHCP_SUBNET, server_config.dmz_host_mask);
			break;
		case DHCP_LEASE_TIME:
		case DHCP_T1:
			continue;
		default:
			add_option_string(packet->options, curr->data);
			break;;
		}
	}
}
