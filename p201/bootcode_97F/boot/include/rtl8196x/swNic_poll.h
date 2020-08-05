/*
* ----------------------------------------------------------------
* Copyright c                  Realtek Semiconductor Corporation, 2002  
* All rights reserved.
* 
*
* Abstract: Switch core polling mode NIC header file.
*
* ---------------------------------------------------------------
*/


#ifndef _SWNIC_H
#define _SWNIC_H
#define CONFIG_RTL865XC 1

#define NIC_MAX_RX_DESC_NUM		4
#define NIC_MAX_TX_DESC_NUM		4

/* --------------------------------------------------------------------
 * ROUTINE NAME - swNic_init
 * --------------------------------------------------------------------
 * FUNCTION: This service initializes the switch NIC.
 * INPUT   : 
        userNeedRxPkthdrRingCnt[RTL865X_SWNIC_RXRING_MAX_PKTDESC]: Number of Rx pkthdr descriptors. of each ring
        userNeedRxMbufRingCnt: Number of Rx mbuf descriptors.
        userNeedTxPkthdrRingCnt[RTL865X_SWNIC_TXRING_MAX_PKTDESC]: Number of Tx pkthdr descriptors. of each ring
        clusterSize: Size of a mbuf cluster.
 * OUTPUT  : None.
 * RETURN  : Upon successful completion, the function returns ENOERR. 
        Otherwise, 
		EINVAL: Invalid argument.
 * NOTE    : None.
 * -------------------------------------------------------------------*/
int32 swNic_init(uint32 userNeedRxPkthdrRingCnt[],
                 uint32 userNeedRxMbufRingCnt,
                 uint32 userNeedTxPkthdrRingCnt[],
                 uint32 clusterSize);

/* --------------------------------------------------------------------
 * ROUTINE NAME - swNic_intHandler
 * --------------------------------------------------------------------
 * FUNCTION: This function is the NIC interrupt handler.
 * INPUT   :
		intPending: Pending interrupts.
 * OUTPUT  : None.
 * RETURN  : None.
 * NOTE    : None.
 * -------------------------------------------------------------------*/
void swNic_intHandler(uint32 intPending);

int32 swNic_receive(void** input, uint32* pLen);
int32 swNic_send(void * output, uint32 len);
void swNic_txDone(void); 

#if defined(CONFIG_RTL_SWITCH_NEW_DESCRIPTOR)

#define	RD_M_EXTSIZE_OFFSET		16	/* [31:16] FirstFrag */

#define ETH_ALEN		6		/* Octets in one ethernet addr */
#define ETH_P_IP		0x0800		/* Internet Protocol packet */
#define ETH_P_8021Q		0x8100		/* 802.1Q VLAN Extended Header */
#define VLAN_HLEN		4		/* The additional bytes required by VLAN */

#define PKTHDR_PPTP		1

#define	IPPROTO_ICMP	1		/* control message protocol */
#define	IPPROTO_IGMP	2		/* group mgmt protocol */
#define	IPPROTO_TCP		6		/* tcp */
#define	IPPROTO_UDP		17		/* user datagram protocol */
#define	IPPROTO_GRE		47		/* General Routing Encap. */
#endif

#endif /* _SWNIC_H */
