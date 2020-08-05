#ifndef _SERVERPACKET_H
#define _SERVERPACKET_H

#include "leases.h"

int sendOffer(struct dhcpMessage *oldpacket, struct dhcpOfferedAddr **please);
int sendNAK(struct dhcpMessage *oldpacket);
int sendACK(struct dhcpMessage *oldpacket, u_int32_t yiaddr);
int send_inform(struct dhcpMessage *oldpacket);


#endif
