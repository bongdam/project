/*
* ----------------------------------------------------------------
* Copyright c                  Realtek Semiconductor Corporation, 2002
* All rights reserved.
*
*
* Abstract: Switch core polling mode NIC driver source code.
*
*
* ---------------------------------------------------------------
*/
#include <string.h>
#include <strings.h>
#include <stdlib.h>
#include <linux/config.h>
#include <rtl_types.h>
#include <rtl_errno.h>
#include <rtl8196x/loader.h>
#include <rtl8196x/asicregs.h>
#include <rtl8196x/swNic_poll.h>
#include <linux/string.h>

#ifdef CONFIG_NIC_LOOPBACK
#define _FAST_TX		1
#endif

/* refer to rtl865xc_swNic.c & rtl865xc_swNic.h
 */
#define RTL865X_SWNIC_RXRING_MAX_PKTDESC	6
#define RTL865X_SWNIC_TXRING_MAX_PKTDESC	4

/* RX Ring */
static uint32*	rxPkthdrRing[RTL865X_SWNIC_RXRING_MAX_PKTDESC];					/* Point to the starting address of RX pkt Hdr Ring */
static uint32	rxPkthdrRingCnt[RTL865X_SWNIC_RXRING_MAX_PKTDESC];				/* Total pkt count for each Rx descriptor Ring */
//static uint32	rxPkthdrRingIndex[RTL865X_SWNIC_RXRING_MAX_PKTDESC];			/* Current Index for each Rx descriptor Ring */

/* TX Ring */
static uint32*	txPkthdrRing[RTL865X_SWNIC_TXRING_MAX_PKTDESC];				/* Point to the starting address of TX pkt Hdr Ring */

static uint32	txPkthdrRingCnt[RTL865X_SWNIC_TXRING_MAX_PKTDESC];			/* Total pkt count for each Tx descriptor Ring */
//static uint32	txPkthdrRingFreeIndex[RTL865X_SWNIC_TXRING_MAX_PKTDESC];	/* Point to the entry can be set to SEND packet */

#define txPktHdrRingFull(idx)	(((txPkthdrRingFreeIndex[idx] + 1) & (txPkthdrRingMaxIndex[idx])) == (txPkthdrRingDoneIndex[idx]))

/* Mbuf */
uint32* rxMbufRing=NULL;                                                     /* Point to the starting address of MBUF Ring */
uint32	rxMbufRingCnt;													/* Total MBUF count */

static uint32  size_of_cluster;

/* descriptor ring tracing pointers */
static int32   currRxPkthdrDescIndex;      /* Rx pkthdr descriptor to be handled by CPU */
static int32   currRxMbufDescIndex;        /* Rx mbuf descriptor to be handled by CPU */
static int32   currTxPkthdrDescIndex;      /* Tx pkthdr descriptor to be handled by CPU */
static int32 txPktDoneDescIndex;

/* debug counters */
static int32   rxPktCounter;
static int32   txPktCounter;

#define     BUF_FREE            0x00   /* Buffer is Free  */
#define     BUF_USED            0x80   /* Buffer is occupied */
#define     BUF_ASICHOLD        0x80   /* Buffer is hold by ASIC */
#define     BUF_DRIVERHOLD      0xc0   /* Buffer is hold by driver */

//--------------------------------------------------------------------------
/* mbuf header associated with each cluster
*/
struct mBuf
{
	struct mBuf *m_next;
	struct pktHdr *m_pkthdr;            /* Points to the pkthdr structure */

#ifdef _LITTLE_ENDIAN
	int8      m_reserved2;              /* padding */
	int8      m_flags;                  /* mbuf flags; see below */
	uint16    m_len;                    /* data bytes used in this cluster */
#else
	uint16    m_len;                    /* data bytes used in this cluster */
	int8      m_flags;                  /* mbuf flags; see below */
	int8      m_reserved2;              /* padding */
#endif

#define MBUF_FREE            BUF_FREE   /* Free. Not occupied. should be on free list   */
#define MBUF_USED            BUF_USED   /* Buffer is occupied */
#define MBUF_EXT             0x10       /* has associated with an external cluster, this is always set. */
#define MBUF_PKTHDR          0x08       /* is the 1st mbuf of this packet */
#define MBUF_EOR             0x04       /* is the last mbuf of this packet. Set only by ASIC*/

	uint8     *m_data;                  /*  location of data in the cluster */
	uint8     *m_extbuf;                /* start of buffer*/

#ifdef _LITTLE_ENDIAN
	int8      m_reserved[2];            /* padding */
	uint16    m_extsize;                /* sizeof the cluster */
#else
	uint16    m_extsize;                /* sizeof the cluster */
	int8      m_reserved[2];            /* padding */
#endif

};
//--------------------------------------------------------------------------
/* pkthdr records packet specific information. Each pkthdr is exactly 32 bytes.
 first 20 bytes are for ASIC, the rest 12 bytes are for driver and software usage.
*/
struct pktHdr
{
	union
	{
		struct pktHdr *pkthdr_next;     /*  next pkthdr in free list */
		struct mBuf *mbuf_first;        /*  1st mbuf of this pkt */
	} PKTHDRNXT;
#define ph_nextfree         PKTHDRNXT.pkthdr_next
#define ph_mbuf             PKTHDRNXT.mbuf_first

#ifdef _LITTLE_ENDIAN
	uint16    ph_srcExtPortNum: 2;      /* Both in RX & TX. Source extension port number. */
	uint16    ph_l2Trans: 1;            /* l2Trans - copy from HSA bit 129 */
	uint16    ph_isOriginal: 1;         /* isOriginal - DP included cpu port or more than one ext port */
	uint16    ph_hwFwd: 1;              /* hwFwd - copy from HSA bit 200 */
	uint16    ph_reserved2: 3;          /* reserved */
	uint16    ph_extPortList: 4;        /* dest extension port list. must be 0 for TX */
	uint16    ph_queueId: 3;            /* bit 2~0: Queue ID */
	uint16    ph_reserved1: 1;           /* reserved */
	uint16    ph_len;                   /*   total packet length */

#else
	uint16    ph_len;                   /*   total packet length */
	uint16    ph_reserved1: 1;           /* reserved */
	uint16    ph_queueId: 3;            /* bit 2~0: Queue ID */
	uint16    ph_extPortList: 4;        /* dest extension port list. must be 0 for TX */
	uint16    ph_reserved2: 3;          /* reserved */
	uint16    ph_hwFwd: 1;              /* hwFwd - copy from HSA bit 200 */
	uint16    ph_isOriginal: 1;         /* isOriginal - DP included cpu port or more than one ext port */
	uint16    ph_l2Trans: 1;            /* l2Trans - copy from HSA bit 129 */
	uint16    ph_srcExtPortNum: 2;      /* Both in RX & TX. Source extension port number. */
#endif

#ifdef _LITTLE_ENDIAN
	uint16    ph_reason;                /* indicates wht the packet is received by CPU */
	uint16    ph_linkID: 7;             /* for WLAN WDS multiple tunnel */
	uint16    ph_pppoeIdx: 3;
	uint16    ph_pppeTagged: 1;         /* the tag status after ALE */
	uint16    ph_LLCTagged: 1;          /* the tag status after ALE */
	uint16    ph_vlanTagged: 1;         /* the tag status after ALE */
	uint16    ph_type: 3;
#else
	uint16    ph_type: 3;
	uint16    ph_vlanTagged: 1;         /* the tag status after ALE */
	uint16    ph_LLCTagged: 1;          /* the tag status after ALE */
	uint16    ph_pppeTagged: 1;         /* the tag status after ALE */
	uint16    ph_pppoeIdx: 3;
	uint16    ph_linkID: 7;             /* for WLAN WDS multiple tunnel */
	uint16    ph_reason;                /* indicates wht the packet is received by CPU */
#endif


#define PKTHDR_ETHERNET      0
#define PKTHDR_IP            2
#define PKTHDR_ICMP          3
#define PKTHDR_IGMP          4
#define PKTHDR_TCP           5
#define PKTHDR_UDP           6

#ifdef _LITTLE_ENDIAN
	uint8     ph_portlist;              /* RX: source port number, TX: destination portmask */
	uint8     ph_orgtos;                /* RX: original TOS of IP header's value before remarking, TX: undefined */
	uint16    ph_flags;                 /*  NEW:Packet header status bits */
#else
	uint16    ph_flags;                 /*  NEW:Packet header status bits */
	uint8     ph_orgtos;                /* RX: original TOS of IP header's value before remarking, TX: undefined */
	uint8     ph_portlist;              /* RX: source port number, TX: destination portmask */
#endif

#define PKTHDR_FREE          (BUF_FREE << 8)        /* Free. Not occupied. should be on free list   */
#define PKTHDR_USED          (BUF_USED << 8)
#define PKTHDR_ASICHOLD      (BUF_ASICHOLD<<8)      /* Hold by ASIC */
#define PKTHDR_DRIVERHOLD    (BUF_DRIVERHOLD<<8)    /* Hold by driver */
#define PKTHDR_CPU_OWNED     0x4000
#define PKT_INCOMING         0x1000     /* Incoming: packet is incoming */
#define PKT_OUTGOING         0x0800     /*  Outgoing: packet is outgoing */
#define PKT_BCAST            0x0100     /*send/received as link-level broadcast  */
#define PKT_MCAST            0x0080     /*send/received as link-level multicast   */
#define PKTHDR_PPPOE_AUTOADD    0x0004  /* PPPoE header auto-add */
#define CSUM_TCPUDP_OK       0x0001     /*Incoming:TCP or UDP cksum checked */
#define CSUM_IP_OK           0x0002     /* Incoming: IP header cksum has checked */
#define CSUM_TCPUDP          0x0001     /*Outgoing:TCP or UDP cksum offload to ASIC*/
#define CSUM_IP              0x0002     /* Outgoing: IP header cksum offload to ASIC*/

#ifdef _LITTLE_ENDIAN
	uint16     ph_flags2;
	uint16     ph_vlanId: 12;
	uint16     ph_txPriority: 3;
	uint16     ph_vlanId_resv: 1;

	int8	ph_reserved[3];		/* padding */
	uint8	ph_ptpPkt:1;		/* 1: PTP */
	uint8	ph_ptpVer:2;		/* PTP version, 0: 1588v1; 1: 1588v2 or 802.1as; others: reserved */
	uint8	ph_ptpMsgType:4;	/* message type */
	uint8	ph_ptpResv:1;

#else
	uint16     ph_vlanId_resv: 1;
	uint16     ph_txPriority: 3;
	uint16     ph_vlanId: 12;
	uint16     ph_flags2;

	uint8      ph_ptpResv:1;
	uint8      ph_ptpMsgType:4;	/* message type */
	uint8      ph_ptpVer:2;	/* PTP version, 0: 1588v1; 1: 1588v2 or 802.1as; others: reserved */
	uint8      ph_ptpPkt:1;	/* 1: PTP */
	int8       ph_reserved[3];            /* padding */
#endif
};
//--------------------------------------------------------------------------

extern char eth0_mac[6];

#ifdef _LITTLE_ENDIAN
#define swab16(x) \
           (((x & (uint16)0x00ffU) << 8) | \
            ((x & (uint16)0xff00U) >> 8))

#define swab32(x) \
            (((x & (uint32)0x000000ffUL) << 24) | \
             ((x & (uint32)0x0000ff00UL) <<  8) | \
             ((x & (uint32)0x00ff0000UL) >>  8) | \
             ((x & (uint32)0xff000000UL) >> 24))

#define htonl(x) swab32(x)
#define htons(x) swab16(x)
#else
#define htonl(x) (x)
#define htons(x) (x)
#endif

#pragma ghs section text=".iram"
/*************************************************************************
*   FUNCTION
*       swNic_intHandler
*
*   DESCRIPTION
*       This function is the handler of NIC interrupts
*
*   INPUTS
*       intPending      Pending interrupt sources.
*
*   OUTPUTS
*       None
*************************************************************************/
void swNic_intHandler(uint32 intPending)
{
	return;
}

uint8 pktbuf[2048];


#if defined(CONFIG_RTL_SWITCH_NEW_DESCRIPTOR)

/* NEW RX Ring */
static int32	New_rxDescRingCnt[NEW_NIC_MAX_RX_RING];
static uint32	New_rxDescRing_base[NEW_NIC_MAX_RX_RING];
static struct dma_rx_desc	*New_rxDescRing[NEW_NIC_MAX_RX_RING] = {NULL};
static struct dma_rx_desc	staticNew_rxDescRing[NEW_NIC_MAX_RX_RING][NIC_MAX_RX_DESC_NUM];
static uint8	rx_skb_space[NEW_NIC_MAX_RX_RING][NIC_MAX_RX_DESC_NUM][SIZE_OF_CLUSTER_FOR_RTL8197F_VG_UBOOT];

/* NEW TX Ring */
static uint32	New_txDescRingCnt[NEW_NIC_MAX_TX_RING];
static uint32	New_txDescRing_base[NEW_NIC_MAX_TX_RING];
static struct dma_tx_desc	*New_txDescRing[NEW_NIC_MAX_TX_RING] = {NULL};
static struct dma_tx_desc	staticNew_txDescRing[NEW_NIC_MAX_TX_RING][NIC_MAX_TX_DESC_NUM];

static uint32 TxCDP_reg[NEW_NIC_MAX_TX_RING] = {CPUTPDCR0, CPUTPDCR1, CPUTPDCR2, CPUTPDCR3};

#define UNCACHE_MASK			0x20000000

#if 0
void New_swNic_dump_tx_ring(void)
{
	uint32 i, j, k, regVal, nicAddrMask;
	struct dma_tx_desc *desc;
	CPUTXPCDCR_t cputxpcdcr;
	DMA_CR0_t dma_cr0;
	int currentFound;

	regVal = DMA_CR0;
	dma_cr0.wrd = REG32(regVal);
	nicAddrMask = ~((0xf - dma_cr0.bf.MSBAddrMark) << 28);

	regVal = CPUTXPCDCR;
	cputxpcdcr.wrd = REG32(regVal);

	dprintf(" => currTxPkthdrDescIndex= %d, txPktDoneDescIndex= %d\n", currTxPkthdrDescIndex, txPktDoneDescIndex);

	for (i=0; i<NEW_NIC_MAX_TX_RING; i++)
	{
		/* ring #i is not enabled */
		if ( !(cputxpcdcr.bf.cf_txdcp_en >> i) & 0x1)
		{
			continue;
		}

		currentFound = 0;
		for (j=0; j < New_txDescRingCnt[i]; j++)
		{
			dprintf( "New_txDescRing["  "%d"  "]["  "%d"  "]: 0x%x\t",
			         i, j, ((unsigned int)&New_txDescRing[i][j] | UNCACHE_MASK));

			desc = (struct dma_tx_desc *)((unsigned int)&New_txDescRing[i][j] | UNCACHE_MASK);
			if(!desc)
			{
				dprintf("\n");
				break;
			}
			dprintf( "\t[%s]", desc->opts0.bf.own ? "NIC" : "CPU");
			dprintf( "\t%s", desc->opts0.bf.eor ? "EOR" : "");
			if( ((uint32)desc & nicAddrMask) == ( (REG32(CPUTPDCR(i)) | UNCACHE_MASK) & nicAddrMask) )
			{
				dprintf( " <= Current" );
				currentFound = 1;
				dprintf("\n");
			}
			else
			{
				dprintf("\n");
			}

			dprintf("opts0(0x%x) ",  desc->opts0.wrd);
			dprintf("opts1(0x%x) ", desc->opts1.wrd);
			dprintf("opts2(0x%x) ",  desc->opts2.wrd);
			dprintf("opts3(0x%x) ",  desc->opts3.wrd);
			dprintf("opts4(0x%x) ",  desc->opts4.wrd);
			dprintf("opts5(0x%x)\n",  desc->opts5.wrd);
		}

		if(!currentFound)
		{
			dprintf( "[Warning] (uint32)desc: 0x%x\tREG32(CPUTPDCR(%d), 0x%x): 0x%x\n",
			         (uint32)desc, i, CPUTPDCR(i), REG32(CPUTPDCR(i)));
		}
		dprintf("\n");
	}
}

void New_swNic_dump_rx_ring(void)
{
	uint32 i, j, k, regVal, nicAddrMask;
	struct dma_rx_desc *desc;
	DMA_CR0_t dma_cr0;
	int currentFound, hw_idx;
	uint32 cdp_value;

	regVal = DMA_CR0;
	dma_cr0.wrd = REG32(regVal);
	nicAddrMask = ~((0xf - dma_cr0.bf.MSBAddrMark) << 28);

	cdp_value =	REG32(CPURPDCR0);
	hw_idx = (cdp_value	- New_rxDescRing_base[0]) / sizeof(struct dma_rx_desc);
	dprintf(" => currRxPkthdrDescIndex= %d, CPURPDCR0= 0x%x, hw_idx= %d\n",
	        currRxPkthdrDescIndex, REG32(CPURPDCR0), hw_idx);

	for (i=0; i<NEW_NIC_MAX_RX_RING; i++)
	{
		/* ring #i is not enabled */
		if ( New_rxDescRing_base == NULL )
		{
			continue;
		}

		if (New_rxDescRingCnt[i] == 0)
			continue;

		currentFound = 0;
		for (j=0; j < New_rxDescRingCnt[i]; j++)
		{
			dprintf( "New_rxDescRing["  "%d"  "]["  "%d"  "]: 0x%x\t",
			         i, j, ((unsigned int)&New_rxDescRing[i][j] | UNCACHE_MASK));

			desc = (struct dma_rx_desc *)((unsigned int)&New_rxDescRing[i][j] | UNCACHE_MASK);
			if(!desc)
			{
				printf("\n");
				break;
			}
			dprintf( "[%s]", desc->opts0.bf.own ? "NIC" : "CPU");
			dprintf( "\t%s", desc->opts0.bf.eor ? "EOR" : "");
			if( ((uint32)desc & nicAddrMask) == ( (REG32(CPURPDCR(i)) | UNCACHE_MASK) & nicAddrMask) )
			{
				dprintf( " <= Current" );
				currentFound = 1;
				dprintf("\n");
			}
			else
			{
				dprintf("\n");
			}

			dprintf("opts0(0x%x) ",  desc->opts0.wrd);
			dprintf("opts1(0x%x) ",  desc->opts1.wrd);
			dprintf("opts2(0x%x) ",   desc->opts2.wrd);
			dprintf("opts3(0x%x) ",   desc->opts3.wrd);
			dprintf("opts4(0x%x) ",  desc->opts4.wrd);
			dprintf("opts5(0x%x)\n",  desc->opts5.wrd);
		}

		if(!currentFound)
		{
			dprintf( "[Warning] (uint32)desc: 0x%x\tREG32(CPURPDCR(%d), 0x%x): 0x%x\n",
			         (uint32)desc, i, CPURPDCR(i), REG32(CPURPDCR(i)));
		}
		dprintf("\n");
	}
}
#endif

int32 swNic_init(uint32 userNeedRxPkthdrRingCnt[],
                 uint32 userNeedRxMbufRingCnt,
                 uint32 userNeedTxPkthdrRingCnt[],
                 uint32 clusterSize)
{
	uint32 i, j;
	static uint32 totalRxPkthdrRingCnt = 0, totalTxPkthdrRingCnt = 0;

	dprintf("use Switch new descriptor\n");

	/* 1. Allocate Rx descriptors of rings */
	if (New_rxDescRing[0] == NULL)
	{
		for (i = 0; i < NEW_NIC_MAX_RX_RING; i++)
		{
			New_rxDescRingCnt[i] = userNeedRxPkthdrRingCnt[i];

			/* ring #i is not configured */
			if (New_rxDescRingCnt[i] == 0)
			{
				New_rxDescRing[i] = NULL;
				continue;
			}

			/* make it align with 97G cpu cacahe line before memset */
			New_rxDescRing[i] = staticNew_rxDescRing[i];
			ASSERT_CSP( (uint32) New_rxDescRing[i] & 0x0fffffff );

			memset(New_rxDescRing[i], 0x0, New_rxDescRingCnt[i] * sizeof(struct dma_rx_desc));
			totalRxPkthdrRingCnt += New_rxDescRingCnt[i];
		}

		if (totalRxPkthdrRingCnt == 0)
		{
			goto err_out;
		}
	}

	/* Initialize Rx packet	header descriptors */
	for (i=0; i<NEW_NIC_MAX_RX_RING; i++)
	{
		for (j=0; j<New_rxDescRingCnt[i]; j++)
		{
			if (0 == New_rxDescRingCnt[i])
			{
				continue;
			}

			/* offset 2 bytes for 4 bytes align of ip packet */
			New_rxDescRing[i][j].opts1.wrd = (uint32)(rx_skb_space[i][j] + 2);
			New_rxDescRing[i][j].opts1.wrd |= UNCACHE_MASK;

			memset(rx_skb_space[i][j], 0x0, clusterSize);

			if (j == (New_rxDescRingCnt[i] - 1)) /* add EOR bit to last tx desc. */
			{
				New_rxDescRing[i][j].opts0.wrd = ( DESC_SWCORE_OWNED | DESC_WRAP | (clusterSize << RD_M_EXTSIZE_OFFSET) );
			}
			else
			{
				New_rxDescRing[i][j].opts0.wrd = ( DESC_SWCORE_OWNED | (clusterSize << RD_M_EXTSIZE_OFFSET) );
			}

		}

		/* Fill Rx desc. to reg. to update FDP with uncached address */
		if (NULL != New_rxDescRing[i])
		{
			New_rxDescRing_base[i] = ((uint32) New_rxDescRing[i]) | UNCACHE_MASK;
		}
		REG32(CPURPDCR(i)) = New_rxDescRing_base[i];
	}
	flush_dcache_range((uint8 *)staticNew_rxDescRing, (uint8 *)staticNew_rxDescRing + (sizeof(struct dma_rx_desc) * NEW_NIC_MAX_RX_RING * NIC_MAX_RX_DESC_NUM)-1);

	/* 2. Allocate Tx descriptor rings */
	if (New_txDescRing[0] == NULL)
	{
		for (i=0; i<NEW_NIC_MAX_TX_RING; i++)
		{
			New_txDescRingCnt[i] = userNeedTxPkthdrRingCnt[i];
			if (New_txDescRingCnt[i] == 0)
			{
				New_txDescRing[i] = NULL;
				continue;
			}
			/* make sure all operates at un-cache */
			New_txDescRing[i] = staticNew_txDescRing[i];
			ASSERT_CSP( (uint32) New_txDescRing[i] & 0x0fffffff );

			/* make it align with 97G cpu cacahe line before memset */
			memset(New_txDescRing[i], 0, New_txDescRingCnt[i] * sizeof(struct dma_tx_desc));
			totalTxPkthdrRingCnt += New_txDescRingCnt[i];

		}

		if (totalTxPkthdrRingCnt == 0)
		{
			goto err_out;
		}
	}

	/* Initialize index of Tx pkthdr descriptor */
	for	(i=0; i<NEW_NIC_MAX_TX_RING; i++)
	{
		if (0 == New_txDescRingCnt[i])
		{
			continue;
		}

		for (j=0; j<New_txDescRingCnt[i]; j++)
		{
			New_txDescRing[i][j].opts0.wrd &= ~DESC_SWCORE_OWNED; // Set all the tx desc to RISC owned

			if( j == (New_txDescRingCnt[i] - 1) )
			{
				/* add EOR bit to last tx desc. */
				New_txDescRing[i][j].opts0.wrd |= DESC_WRAP;
			}
		}

		/* Fill Tx desc. to reg. to update FDP with uncached address */
		if (NULL != New_txDescRing[i])
		{
			New_txDescRing_base[i] = ((uint32) New_txDescRing[i]) | UNCACHE_MASK;
		}
		REG32(TxCDP_reg[i]) = New_txDescRing_base[i];
	}
	flush_dcache_range((uint8 *)staticNew_txDescRing, (uint8 *)staticNew_txDescRing + (sizeof(struct dma_tx_desc) * NEW_NIC_MAX_TX_RING * NIC_MAX_TX_DESC_NUM)-1);

	/* Maximum TX packet header 0 descriptor entries.
		the register only provide 16-bit for each tx ring,
		this way (set TX_RING0_TAIL_AWARE bit) CAN NOT used when tx desc number is larger than 2730.
	*/
	DMA_CR1_t dma_cr1;
	dma_cr1.wrd = REG32(DMA_CR1);
	dma_cr1.bf.Txcp0maxlen = (New_txDescRingCnt[0] - 1) * (sizeof(struct dma_tx_desc)); /* tells nic tx where to fetch last TxD's w0 */
	dma_cr1.bf.Txcp1maxlen = (New_txDescRingCnt[1] - 1) * (sizeof(struct dma_tx_desc)); /* tells nic tx where to fetch last TxD's w0 */
	REG32(DMA_CR1) = dma_cr1.wrd;

	DMA_CR3_t dma_cr3;
	dma_cr3.wrd = REG32(DMA_CR3);
	dma_cr3.bf.Txcp2maxlen = (New_txDescRingCnt[2] - 1) * (sizeof(struct dma_tx_desc)); /* tells nic tx where to fetch last TxD's w0 */
	dma_cr3.bf.Txcp3maxlen = (New_txDescRingCnt[3] - 1) * (sizeof(struct dma_tx_desc)); /* tells nic tx where to fetch last TxD's w0 */
	REG32(DMA_CR3) = dma_cr3.wrd;

	DMA_CR2_t dma_cr2;
	dma_cr2.wrd = REG32(DMA_CR2);
	dma_cr2.bf.Rxphmaxlen = (New_rxDescRingCnt[0] - 1) * (sizeof(struct dma_rx_desc)); /* tells nic rx where to fetch last RxD's w0 */
	REG32(DMA_CR2) = dma_cr2.wrd;

	DMA_CR4_t dma_cr4;
	dma_cr4.wrd = REG32(DMA_CR4);
	dma_cr4.bf.Txph0TailAware = TRUE; /* if the Txcp0maxlen is shorter than the real EOR, the ring will just wrap around early; vice versa */
	dma_cr4.bf.Txph1TailAware = TRUE; /* if the Txcp1maxlen is shorter than the real EOR, the ring will just wrap around early; vice versa */
	dma_cr4.bf.Txph2TailAware = TRUE; /* if the Txcp2maxlen is shorter than the real EOR, the ring will just wrap around early; vice versa */
	dma_cr4.bf.Txph3TailAware = TRUE; /* if the Txcp3maxlen is shorter than the real EOR, the ring will just wrap around early; vice versa */
	dma_cr4.bf.RxphTailAware = TRUE; /* if the Rxphmaxlen is shorter than the real EOR, the ring will just wrap around early; vice versa */
	REG32(DMA_CR4) = dma_cr4.wrd;

	REG32(CPUICR) = TXCMD | RXCMD | BUSBURST_32WORDS | MBUF_2048BYTES;
	REG32(CPUIIMR) = RX_DONE_IE_ALL|TX_DONE_IE_ALL;

	return SUCCESS;

err_out:
	dprintf("ERROR OUT @ [%s:%d]\n", __func__, __LINE__);

	return FAILED;
}

int32 swNic_receive(void **input, uint32 *pLen)
{
	struct pktHdr * pPkthdr;
	int prev_index, ret=-1;
	static int firstTime = 1;
	char	*data;
	struct dma_rx_desc *desc;

	desc = (struct dma_rx_desc *) &New_rxDescRing[0][currRxPkthdrDescIndex];
	desc = (struct dma_rx_desc *)( ((uint32)desc) | UNCACHE_MASK);

	/* Check OWN bit of descriptors */
	if (desc->opts0.bf.own == DESC_RISC_OWNED)
	{
		/* Increment counter */
		rxPktCounter++;

		data = (char *)desc->opts1.wrd;

		if ( (data[0]&0x1) || !memcmp(data, eth0_mac, 6) )
		{
			/* Output packet */
			*input = data;
			*pLen = desc->opts2.bf.len - 4;
			ret = 0;

			if ((*(uint16 *)&(data[12])) == htons(0x8100))
			{
				memcpy(&(data[12]), &(data[16]), *pLen - 16);
			}
		}
		else
			ret = -1;

		if ( !firstTime )
		{
			/* Calculate previous pkthdr index */
			prev_index = currRxPkthdrDescIndex;
			if ( --prev_index < 0 )
				prev_index = New_rxDescRingCnt[0] - 1;

			/* Reset OWN bit */
			desc = (struct dma_rx_desc *) &New_rxDescRing[0][prev_index];
			desc = (struct dma_rx_desc *)( ((uint32)desc) | UNCACHE_MASK);
			desc->opts0.bf.own = DESC_SWCORE_OWNED;
		}
		else
			firstTime = 0;

		/* Increment index */
		if ( ++currRxPkthdrDescIndex == New_rxDescRingCnt[0] )
			currRxPkthdrDescIndex = 0;

		if ( REG32(CPUIISR) & PKTHDR_DESC_RUNOUT_IP_ALL )
		{
			/* Enable and clear interrupt for continue reception */
			REG32(CPUIIMR) |= PKTHDR_DESC_RUNOUT_IE_ALL;
			REG32(CPUIISR) = PKTHDR_DESC_RUNOUT_IP_ALL;
		}

		return ret;
	}
	else
		return -1;
}

struct iphdr
{
#if defined(_LITTLE_ENDIAN)
	uint8	ihl:4,
	        version:4;
#else
	uint8	version:4,
	        ihl:4;
#endif
	uint8	tos;
	uint16	tot_len;
	uint16	id;
	uint16	frag_off;
	uint8	ttl;
	uint8	protocol;
	uint16	check;
	uint32	saddr;
	uint32	daddr;
};

static inline int parse_pkt(struct dma_tx_desc *txd, uint8 *output)
{
	struct iphdr *iph = NULL;
	int16 etherTypeLen;

	etherTypeLen = (*(uint16 *)(output+(ETH_ALEN<<1)));

	if(etherTypeLen==(int16)htons(ETH_P_IP))
	{
		iph = (struct iphdr *)(output+(ETH_ALEN<<1)+2);
	}
	else if(etherTypeLen==(int16)htons(ETH_P_8021Q))
	{
		txd->opts0.bf.vi = 1;
		if(etherTypeLen==(int16)htons(ETH_P_IP))
		{
			iph = (struct iphdr *)(output+(ETH_ALEN<<1)+VLAN_HLEN+2);
		}
	}

	if (iph)
	{
		txd->opts3.bf.ipv4 = 1;
		txd->opts3.bf.ipv4_1st = 1;

		if (iph->protocol == IPPROTO_TCP )
		{
			txd->opts0.bf.type = PKTHDR_TCP;
		}
		else if(iph->protocol == IPPROTO_UDP )
		{
			txd->opts0.bf.type = PKTHDR_UDP;
		}
		else if(iph->protocol == IPPROTO_ICMP )
		{
			txd->opts0.bf.type = PKTHDR_ICMP;
		}
		else if(iph->protocol == IPPROTO_IGMP )
		{
			txd->opts0.bf.type = PKTHDR_IGMP;
		}
		else if(iph->protocol == IPPROTO_GRE )
		{
			txd->opts0.bf.type = PKTHDR_PPTP;
		}
		else
		{
			txd->opts0.bf.type = PKTHDR_IP;
		}
	}
	else
		txd->opts0.bf.type = PKTHDR_ETHERNET;
	return 0;
}

int32 swNic_send(void *output, uint32 len)
{
	uint8 *pktbuf_alligned;
	struct dma_tx_desc *txd;
	uint32 next_index;

	next_index = NEXT_IDX(currTxPkthdrDescIndex, New_txDescRingCnt[0]);
	if (next_index == txPktDoneDescIndex)
	{
		dprintf("Tx Desc full!\n");
		return -1;
	}

	txd = (struct dma_tx_desc *) &New_txDescRing[0][currTxPkthdrDescIndex];
	memset( (void *)txd, 0x0, sizeof(struct dma_tx_desc));
	flush_dcache_range( (uint8 *)txd, ((uint8 *)txd) + sizeof(struct dma_tx_desc)-1);
	txd = (struct dma_tx_desc *)(((uint32)txd) | UNCACHE_MASK);

#ifdef _FAST_TX
	pktbuf_alligned = (uint8 *)output;
#else
	pktbuf_alligned = (uint8 *) (( (uint32) pktbuf & 0xfffffffc) | 0xa0000000);
	/* Copy Packet Content */
	memcpy(pktbuf_alligned, output, len);
#endif

	ASSERT_CSP( txd->opts0.bf.own == DESC_RISC_OWNED );

	txd->opts1.wrd = (uint32)output;

	/* set eor bit when need to wrap around */
	if( currTxPkthdrDescIndex == (New_txDescRingCnt[0]-1)  )
	{
		txd->opts0.bf.eor = 1;
	}

	/* w/o this action, the nic tx will send out all 0x0; but it often cause system crash */
	flush_dcache_range((uint8 *)txd->opts1.wrd, (uint8 *)(txd->opts1.wrd) + len - 1);

	/* Pad small packets and add CRC */
	if ( len < 60 )
		len = 64;
	else
		len = len + 4;

	// do not need to set tail bit after we use DMA_CR1/DMA_CR4 register
	txd->opts0.bf.len = len;
	txd->opts0.bf.fs = 1;
	txd->opts0.bf.ls = 1;

	txd->opts2.bf.m_len = len;
	txd->opts3.bf.l3cs = 1; // swcore re-calculate
	txd->opts3.bf.l4cs = 1; // swcore re-calculate
	txd->opts4.bf.dp = 0x1f; // send to all ports
	txd->opts5.bf.extspa = 0x1; // 0x0: from cpu, 0x1~0x3: from ext.p0~p2

	/* please make sure the addr of mdata is 2-byte align, or will crash under uboot */
	parse_pkt(txd, (uint8 *)txd->opts1.wrd);
	txd->opts0.bf.own = 1; // set own bit after all done.

	/* Set TXFD bit to start send */
	REG32(CPUICR) |= TXFD;
	txPktCounter++;

	currTxPkthdrDescIndex = next_index;
	return 0;
}

void swNic_txDone(void)
{
	struct dma_tx_desc *txd;

	while (txPktDoneDescIndex != currTxPkthdrDescIndex)
	{

		txd = (struct dma_tx_desc *) &New_txDescRing[0][txPktDoneDescIndex];
		txd = (struct dma_tx_desc *)(((uint32)txd) | UNCACHE_MASK);

		if ( txd->opts0.bf.own == DESC_RISC_OWNED )
		{
			if (++txPktDoneDescIndex == New_txDescRingCnt[0])
				txPktDoneDescIndex = 0;
		}
		else
			break;
	}

	return;
}
#else

/*************************************************************************
*   FUNCTION
*       swNic_receive
*
*   DESCRIPTION
*       This function reads one packet from rx descriptors, and return the
*       previous read one to the switch core. This mechanism is based on
*       the assumption that packets are read only when the handling
*       previous read one is done.
*
*   INPUTS
*       None
*
*   OUTPUTS
*       None
*************************************************************************/
int32 swNic_receive(void** input, uint32* pLen)
{
	struct pktHdr * pPkthdr;
	int32 pkthdr_index;
	int32 mbuf_index;
	static int32 firstTime = 1;
	char	*data;
	int	ret=-1;

	/* Check OWN bit of descriptors */
	if ( (rxPkthdrRing[0][currRxPkthdrDescIndex] & DESC_OWNED_BIT) == DESC_RISC_OWNED )
	{
		//ASSERT_ISR(currRxPkthdrDescIndex < rxPkthdrRingCnt[0]);

		/* Fetch pkthdr */
		pPkthdr = (struct pktHdr *) (rxPkthdrRing[0][currRxPkthdrDescIndex] &
		                             ~(DESC_OWNED_BIT | DESC_WRAP));

		//ASSERT_ISR(pPkthdr->ph_len); /* Not allow zero packet length */
		//ASSERT_ISR(pPkthdr->ph_len >= 64);
		//ASSERT_ISR(pPkthdr->ph_len <= 1522);

		/* Increment counter */
		rxPktCounter++;

		data = pPkthdr->ph_mbuf->m_data;
		{
#if defined( CONFIG_NFBI) || defined(CONFIG_NONE_FLASH)
			if ( (data[0]&0x1)||!memcmp(data, eth0_mac, 6) )
#else
			if ( (data[0]&0x1)||!memcmp(data, eth0_mac, 6) )
#endif
			{
				/* Output packet */
				*input = data;
				*pLen = pPkthdr->ph_len - 4;
				ret = 0;

#if 1 // patch for inic
				// for iNic & 8306 board, the received packet will has VLAN tag
				if ((*(unsigned short *)&(data[12])) == htons(0x8100))
				{
					memcpy(&(data[12]), &(data[16]), *pLen - 16);
				}
#endif
			}
			else
				ret = -1;
		}

		if ( !firstTime )
		{
			/* Calculate previous pkthdr and mbuf index */
			pkthdr_index = currRxPkthdrDescIndex;
			if ( --pkthdr_index < 0 )
				pkthdr_index = rxPkthdrRingCnt[0] - 1;
#if 1 //defined(CONFIG_RTL8196D) || defined(CONFIG_RTL8196E)||defined(CONFIG_RTL8881A)
			// for rx descriptor runout
			pPkthdr = (struct pktHdr *) (rxPkthdrRing[0][pkthdr_index] & ~(DESC_OWNED_BIT | DESC_WRAP));
			mbuf_index = ((uint32)(pPkthdr->ph_mbuf) - (rxMbufRing[0] & ~(DESC_OWNED_BIT | DESC_WRAP))) /
			             (sizeof(struct mBuf));
#else
			mbuf_index = currRxMbufDescIndex;
			if ( --mbuf_index < 0 )
				mbuf_index = rxPkthdrRingCnt[0] - 1;
#endif

			/* Reset OWN bit */
			rxPkthdrRing[0][pkthdr_index] |= DESC_SWCORE_OWNED;
			rxMbufRing[mbuf_index] |= DESC_SWCORE_OWNED;
		}
		else
			firstTime = 0;

		/* Increment index */
		if ( ++currRxPkthdrDescIndex == rxPkthdrRingCnt[0] )
			currRxPkthdrDescIndex = 0;
		if ( ++currRxMbufDescIndex == rxMbufRingCnt )
			currRxMbufDescIndex = 0;

		if ( REG32(CPUIISR) & PKTHDR_DESC_RUNOUT_IP_ALL )
		{
			/* Enable and clear interrupt for continue reception */
			REG32(CPUIIMR) |= PKTHDR_DESC_RUNOUT_IE_ALL;
			REG32(CPUIISR) = PKTHDR_DESC_RUNOUT_IP_ALL;
		}
		return ret;
	}
	else
		return -1;
}

/*************************************************************************
*   FUNCTION
*       swNic_send
*
*   DESCRIPTION
*       This function writes one packet to tx descriptors, and waits until
*       the packet is successfully sent.
*
*   INPUTS
*       None
*
*   OUTPUTS
*       None
*************************************************************************/

int32 swNic_send(void * output, uint32 len)
{
	struct pktHdr * pPkthdr;
	//uint8 pktbuf[2048];
	uint8* pktbuf_alligned;

	int next_index;
	if ((currTxPkthdrDescIndex+1) == txPkthdrRingCnt[0])
		next_index = 0;
	else
		next_index = currTxPkthdrDescIndex+1;
	if (next_index == txPktDoneDescIndex)
	{
		dprintf("Tx Desc full!\n");
		return -1;
	}

#ifdef _FAST_TX
	pktbuf_alligned = (uint8 *)output;
#else
	pktbuf_alligned = (uint8 *) (( (uint32) pktbuf & 0xfffffffc) | 0xa0000000);
	/* Copy Packet Content */
	memcpy(pktbuf_alligned, output, len);
#endif

	ASSERT_CSP( ((int32) txPkthdrRing[0][currTxPkthdrDescIndex] & DESC_OWNED_BIT) == DESC_RISC_OWNED );

	/* Fetch packet header from Tx ring */
	pPkthdr = (struct pktHdr *) ((int32) txPkthdrRing[0][currTxPkthdrDescIndex]
	                             & ~(DESC_OWNED_BIT | DESC_WRAP));

	/* Pad small packets and add CRC */
	if ( len < 60 )
		pPkthdr->ph_len = 64;
	else
		pPkthdr->ph_len = len + 4;
	pPkthdr->ph_mbuf->m_len       = pPkthdr->ph_len;
	pPkthdr->ph_mbuf->m_extsize = pPkthdr->ph_len;

	/* Set cluster pointer to buffer */
	pPkthdr->ph_mbuf->m_data    = pktbuf_alligned;
	pPkthdr->ph_mbuf->m_extbuf = pktbuf_alligned;
	pPkthdr->ph_ptpPkt = 0;

	/* Set destination port */
#if defined(CONFIG_RTL8198)
	pPkthdr->ph_portlist = ALL_PORT_MASK;
#else
#define HW_STRAT_ROUTER_MODE 0x00100000
	if((REG32(HW_STRAP)&(HW_STRAT_ROUTER_MODE))==HW_STRAT_ROUTER_MODE)
	{
		pPkthdr->ph_portlist = ALL_PORT_MASK;
	}
	else
	{
		pPkthdr->ph_portlist = AP_MODE_PORT_MASK;//Port 4 Only for AP Mode
	}
#endif
	/* Give descriptor to switch core */
	txPkthdrRing[0][currTxPkthdrDescIndex] |= DESC_SWCORE_OWNED;

	/* Set TXFD bit to start send */
	REG32(CPUICR) |= TXFD;
	txPktCounter++;

	currTxPkthdrDescIndex = next_index;
	return 0;
}

void swNic_txDone(void)
{
	struct pktHdr * pPkthdr;

	while (txPktDoneDescIndex != currTxPkthdrDescIndex)
	{
		if ( (*(volatile uint32 *)&txPkthdrRing[0][txPktDoneDescIndex]
		        & DESC_OWNED_BIT) == DESC_RISC_OWNED )
		{
			pPkthdr = (struct pktHdr *) ((int32) txPkthdrRing[0][txPktDoneDescIndex]
			                             & ~(DESC_OWNED_BIT | DESC_WRAP));

			if (++txPktDoneDescIndex == txPkthdrRingCnt[0])
				txPktDoneDescIndex = 0;
		}
		else
			break;
	}
}

#pragma ghs section text=default

/*************************************************************************
*   FUNCTION
*       swNic_init
*
*   DESCRIPTION
*       This function initializes descriptors and data structures.
*
*   INPUTS
*       userNeedRxPkthdrRingCnt[RTL865X_SWNIC_RXRING_MAX_PKTDESC] :
*          Number of Rx pkthdr descriptors of each ring.
*       userNeedRxMbufRingCnt :
*          Number of Tx mbuf descriptors.
*       userNeedTxPkthdrRingCnt[RTL865X_SWNIC_TXRING_MAX_PKTDESC] :
*          Number of Tx pkthdr descriptors of each ring.
*       clusterSize :
*          Size of cluster.
*
*   OUTPUTS
*       Status.
*************************************************************************/
#define SWNIC_INIT_REFINE	1

#ifdef SWNIC_INIT_REFINE
#define __ALIGN__(x,a)		__ALIGN_MASK(x,(typeof(x))(a)-1)
#define __ALIGN_MASK(x,mask)	(((x)+(mask))&~(mask))
#define PTR_ALIGN(p, a)		((typeof(p))__ALIGN__((unsigned long)(p), (a)))
#endif

int32 swNic_init(uint32 userNeedRxPkthdrRingCnt[RTL865X_SWNIC_RXRING_MAX_PKTDESC],
                 uint32 userNeedRxMbufRingCnt,
                 uint32 userNeedTxPkthdrRingCnt[RTL865X_SWNIC_TXRING_MAX_PKTDESC],
                 uint32 clusterSize)
{
	uint32 i, j, k;
	uint32 totalRxPkthdrRingCnt = 0, totalTxPkthdrRingCnt = 0;
	struct pktHdr *pPkthdrList;
	struct mBuf *pMbufList;
	uint8 * pClusterList;
	struct pktHdr * pPkthdr;
	struct mBuf * pMbuf;

	/* Cluster size is always 2048 */
	size_of_cluster = 2048;

	/* Allocate Rx descriptors of rings */
	for (i = 0; i < RTL865X_SWNIC_RXRING_MAX_PKTDESC; i++)
	{
		rxPkthdrRingCnt[i] = userNeedRxPkthdrRingCnt[i];
		if (rxPkthdrRingCnt[i] == 0)
			continue;

#ifdef SWNIC_INIT_REFINE
		rxPkthdrRing[i] = (uint32 *) malloc(rxPkthdrRingCnt[i] * sizeof(uint32)+32);
		ASSERT_CSP( (uint32) rxPkthdrRing[i] & 0x0fffffff );
		memset(rxPkthdrRing[i],0,rxPkthdrRingCnt[i] * sizeof(uint32)+32);
#else
		rxPkthdrRing[i] = (uint32 *) UNCACHED_MALLOC(rxPkthdrRingCnt[i] * sizeof(uint32));
		ASSERT_CSP( (uint32) rxPkthdrRing[i] & 0x0fffffff );
		memset(rxPkthdrRing[i],0,rxPkthdrRingCnt[i] * sizeof(uint32));
#endif
		totalRxPkthdrRingCnt += rxPkthdrRingCnt[i];
	}

	if (totalRxPkthdrRingCnt == 0)
		return EINVAL;

	/* Allocate Tx descriptors of rings */
	for (i = 0; i < RTL865X_SWNIC_TXRING_MAX_PKTDESC; i++)
	{
		txPkthdrRingCnt[i] = userNeedTxPkthdrRingCnt[i];

		if (txPkthdrRingCnt[i] == 0)
			continue;

#ifdef SWNIC_INIT_REFINE
		txPkthdrRing[i] = (uint32 *) malloc(txPkthdrRingCnt[i] * sizeof(uint32)+32);

		ASSERT_CSP( (uint32) txPkthdrRing[i] & 0x0fffffff );
		memset(txPkthdrRing[i],0,(txPkthdrRingCnt[i] * sizeof(uint32)+32));
#else
		txPkthdrRing[i] = (uint32 *) UNCACHED_MALLOC(txPkthdrRingCnt[i] * sizeof(uint32));

		ASSERT_CSP( (uint32) txPkthdrRing[i] & 0x0fffffff );
		memset(txPkthdrRing[i],0,(txPkthdrRingCnt[i] * sizeof(uint32)));
#endif
		totalTxPkthdrRingCnt += txPkthdrRingCnt[i];
	}

	if (totalTxPkthdrRingCnt == 0)
		return EINVAL;

	/* Allocate MBuf descriptors of rings */
	rxMbufRingCnt = userNeedRxMbufRingCnt;

	if (userNeedRxMbufRingCnt == 0)
		return EINVAL;

#ifdef SWNIC_INIT_REFINE
	rxMbufRing = (uint32 *) malloc(userNeedRxMbufRingCnt * sizeof(uint32)+32);
	ASSERT_CSP( (uint32) rxMbufRing & 0x0fffffff );
	memset(rxMbufRing,0,userNeedRxMbufRingCnt * sizeof(uint32)+32);
	/* Allocate pkthdr */
	pPkthdrList = (struct pktHdr *) malloc(
	                  (totalRxPkthdrRingCnt + totalTxPkthdrRingCnt) * sizeof(struct pktHdr)+32);
	ASSERT_CSP( (uint32) pPkthdrList & 0x0fffffff );
	memset(pPkthdrList,0, (totalRxPkthdrRingCnt + totalTxPkthdrRingCnt) * sizeof(struct pktHdr)+32);
	/* Allocate mbufs */
	pMbufList = (struct mBuf *) malloc(
	                (rxMbufRingCnt + totalTxPkthdrRingCnt) * sizeof(struct mBuf)+32);
	ASSERT_CSP( (uint32) pMbufList & 0x0fffffff );
	memset(pMbufList,0,((rxMbufRingCnt + totalTxPkthdrRingCnt) * sizeof(struct mBuf)+32));
	/* Allocate clusters */
	pClusterList = (uint8 *) malloc(rxMbufRingCnt * size_of_cluster + 8 - 1+2*rxMbufRingCnt+32);
	ASSERT_CSP( (uint32) pClusterList & 0x0fffffff );
	memset(pClusterList,0,(rxMbufRingCnt * size_of_cluster + 8 - 1+2*rxMbufRingCnt+32));

	for (i = 0; i < RTL865X_SWNIC_RXRING_MAX_PKTDESC; i++)
	{
		if (rxPkthdrRingCnt[i] == 0)
			continue;
		flush_dcache_range(rxPkthdrRing[i], ((ulong)(rxPkthdrRing[i]) + rxPkthdrRingCnt[i] * sizeof(uint32)+32));
		rxPkthdrRing[i] = (uint32 *)(0xa0000000 | (uint32)(rxPkthdrRing[i]));
		rxPkthdrRing[i] = PTR_ALIGN(rxPkthdrRing[i], 32);
	}

	for (i = 0; i < RTL865X_SWNIC_TXRING_MAX_PKTDESC; i++)
	{
		if (txPkthdrRingCnt[i] == 0)
			continue;

		flush_dcache_range(txPkthdrRing[i], ((ulong)(txPkthdrRing[i]) + txPkthdrRingCnt[i] * sizeof(uint32)+32));
		txPkthdrRing[i] = (uint32 *)(0xa0000000 | (uint32)(txPkthdrRing[i]));
		txPkthdrRing[i] = PTR_ALIGN(txPkthdrRing[i], 32);
	}

	flush_dcache_range(rxMbufRing, ((ulong)rxMbufRing+ userNeedRxMbufRingCnt * sizeof(uint32)+32));
	rxMbufRing = (uint32 *)(0xa0000000 | (uint32)(rxMbufRing));
	rxMbufRing = PTR_ALIGN(rxMbufRing, 32);
	flush_dcache_range(pPkthdrList, ((ulong)pPkthdrList+ (totalRxPkthdrRingCnt + totalTxPkthdrRingCnt) * sizeof(struct pktHdr)+32));
	pPkthdrList = (struct pktHdr *)(0xa0000000 | (uint32)(pPkthdrList));
	pPkthdrList = PTR_ALIGN(pPkthdrList, 32);
	flush_dcache_range(pMbufList, ((ulong)pMbufList+  (rxMbufRingCnt + totalTxPkthdrRingCnt) * sizeof(struct mBuf)+32));
	pMbufList = (struct mBuf *)(0xa0000000 | (uint32)(pMbufList));
	pMbufList = PTR_ALIGN(pMbufList, 32);
	flush_dcache_range(pClusterList, (pClusterList+ (rxMbufRingCnt * size_of_cluster + 8 - 1+2*rxMbufRingCnt)+32));
	pClusterList = (uint8 *)(0xa0000000 | (uint32)(pClusterList));
	pClusterList = PTR_ALIGN(pClusterList, 32);
#else
	rxMbufRing = (uint32 *) UNCACHED_MALLOC(userNeedRxMbufRingCnt * sizeof(uint32));
	ASSERT_CSP( (uint32) rxMbufRing & 0x0fffffff );
	memset(rxMbufRing,0,userNeedRxMbufRingCnt * sizeof(uint32));
	/* Allocate pkthdr */
	pPkthdrList = (struct pktHdr *) UNCACHED_MALLOC(
	                  (totalRxPkthdrRingCnt + totalTxPkthdrRingCnt) * sizeof(struct pktHdr));
	ASSERT_CSP( (uint32) pPkthdrList & 0x0fffffff );
	memset(pPkthdrList,0, (totalRxPkthdrRingCnt + totalTxPkthdrRingCnt) * sizeof(struct pktHdr));
	/* Allocate mbufs */
	pMbufList = (struct mBuf *) UNCACHED_MALLOC(
	                (rxMbufRingCnt + totalTxPkthdrRingCnt) * sizeof(struct mBuf));
	ASSERT_CSP( (uint32) pMbufList & 0x0fffffff );
	memset(pMbufList,0,((rxMbufRingCnt + totalTxPkthdrRingCnt) * sizeof(struct mBuf)));
	/* Allocate clusters */
	pClusterList = (uint8 *) UNCACHED_MALLOC(rxMbufRingCnt * size_of_cluster + 8 - 1+2*rxMbufRingCnt);
	ASSERT_CSP( (uint32) pClusterList & 0x0fffffff );
	memset(pClusterList,0,(rxMbufRingCnt * size_of_cluster + 8 - 1+2*rxMbufRingCnt));
#endif
	pClusterList = (uint8*)(((uint32) pClusterList + 8 - 1) & ~(8 - 1));

	/* Initialize interrupt statistics counter */
	rxPktCounter = txPktCounter = 0;

	/* Initialize index of Tx pkthdr descriptor */
	currTxPkthdrDescIndex = 0;
	txPktDoneDescIndex=0;

	/* Initialize Tx packet header descriptors */
	for (i = 0; i < RTL865X_SWNIC_TXRING_MAX_PKTDESC; i++)
	{
		for (j = 0; j < txPkthdrRingCnt[i]; j++)
		{
			/* Dequeue pkthdr and mbuf */
			pPkthdr = pPkthdrList++;
			pMbuf = pMbufList++;

			bzero((void *) pPkthdr, sizeof(struct pktHdr));
			bzero((void *) pMbuf, sizeof(struct mBuf));

			pPkthdr->ph_mbuf = pMbuf;
			pPkthdr->ph_len = 0;
			pPkthdr->ph_flags = PKTHDR_USED | PKT_OUTGOING;
			pPkthdr->ph_type = PKTHDR_ETHERNET;
			pPkthdr->ph_portlist = 0;

			pMbuf->m_next = NULL;
			pMbuf->m_pkthdr = pPkthdr;
			pMbuf->m_flags = MBUF_USED | MBUF_EXT | MBUF_PKTHDR | MBUF_EOR;
			pMbuf->m_data = NULL;
			pMbuf->m_extbuf = NULL;
			pMbuf->m_extsize = 0;

			txPkthdrRing[i][j] = (int32) pPkthdr | DESC_RISC_OWNED;
		}

		/* Set wrap bit of the last descriptor */
		if (txPkthdrRingCnt[i] != 0)
			txPkthdrRing[i][txPkthdrRingCnt[i] - 1] |= DESC_WRAP;
	}

	/* Fill Tx packet header FDP */
	REG32(CPUTPDCR0) = (uint32) txPkthdrRing[0];
	REG32(CPUTPDCR1) = (uint32) txPkthdrRing[1];
	REG32(CPUTPDCR2) = (uint32) txPkthdrRing[2];
	REG32(CPUTPDCR3) = (uint32) txPkthdrRing[3];

	/* Initialize index of current Rx pkthdr descriptor */
	currRxPkthdrDescIndex = 0;

	/* Initialize index of current Rx Mbuf descriptor */
	currRxMbufDescIndex = 0;

	/* Initialize Rx packet header descriptors */
	k = 0;

	for (i = 0; i < RTL865X_SWNIC_RXRING_MAX_PKTDESC; i++)
	{
		for (j = 0; j < rxPkthdrRingCnt[i]; j++)
		{
			/* Dequeue pkthdr and mbuf */
			pPkthdr = pPkthdrList++;
			pMbuf = pMbufList++;

			bzero((void *) pPkthdr, sizeof(struct pktHdr));
			bzero((void *) pMbuf, sizeof(struct mBuf));

			/* Setup pkthdr and mbuf */
			pPkthdr->ph_mbuf = pMbuf;
			pPkthdr->ph_len = 0;
			pPkthdr->ph_flags = PKTHDR_USED | PKT_INCOMING;
			pPkthdr->ph_type = PKTHDR_ETHERNET;
			pPkthdr->ph_portlist = 0;
			pMbuf->m_next = NULL;
			pMbuf->m_pkthdr = pPkthdr;
			pMbuf->m_len = 0;
			pMbuf->m_flags = MBUF_USED | MBUF_EXT | MBUF_PKTHDR | MBUF_EOR;
			pMbuf->m_data = NULL;
			pMbuf->m_extsize = size_of_cluster;
			/*offset 2 bytes for 4 bytes align of ip packet*/
			pMbuf->m_data = pMbuf->m_extbuf = (pClusterList+2);
			pClusterList += size_of_cluster;

			/* Setup descriptors */
			rxPkthdrRing[i][j] = (int32) pPkthdr | DESC_SWCORE_OWNED;
			rxMbufRing[k++] = (int32) pMbuf | DESC_SWCORE_OWNED;
		}

		/* Set wrap bit of the last descriptor */
		if (rxPkthdrRingCnt[i] != 0)
			rxPkthdrRing[i][rxPkthdrRingCnt[i] - 1] |= DESC_WRAP;
	}

	rxMbufRing[rxMbufRingCnt - 1] |= DESC_WRAP;

	/* Fill Rx packet header FDP */
	REG32(CPURPDCR0) = (uint32) rxPkthdrRing[0];
	REG32(CPURPDCR1) = (uint32) rxPkthdrRing[1];
	REG32(CPURPDCR2) = (uint32) rxPkthdrRing[2];
	REG32(CPURPDCR3) = (uint32) rxPkthdrRing[3];
	REG32(CPURPDCR4) = (uint32) rxPkthdrRing[4];
	REG32(CPURPDCR5) = (uint32) rxPkthdrRing[5];

	REG32(CPURMDCR0) = (uint32) rxMbufRing;

	//dprintf("addr=%x, val=%x\r\n",(CPUIIMR),REG32(CPUIIMR));
	/* Enable runout interrupts */
	//REG32(CPUIIMR) |= RX_ERR_IE_ALL | TX_ERR_IE_ALL | PKTHDR_DESC_RUNOUT_IE_ALL;  //8651c
	//REG32(CPUIIMR) = 0xffffffff; //RX_DONE_IE_ALL;  //   0xffffffff;  //wei test irq

	//*(volatile unsigned int*)(0xb8010028)=0xffffffff;
	//dprintf("eth0 CPUIIMR status=%x\r\n", *(volatile unsigned int*)(0xb8010028));   //ISR

	/* Enable Rx & Tx. Config bus burst size and mbuf size. */
	//REG32(CPUICR) = TXCMD | RXCMD | BUSBURST_256WORDS | icr_mbufsize;
	//REG32(CPUICR) = TXCMD | RXCMD | BUSBURST_32WORDS | MBUF_2048BYTES;	//8651c
	REG32(CPUICR) = TXCMD | RXCMD | BUSBURST_32WORDS | MBUF_2048BYTES; //wei test irq
	REG32(CPUIIMR) = RX_DONE_IE_ALL | TX_DONE_IE_ALL;

	//dprintf("eth0 CPUIIMR status=%x\r\n", *(volatile unsigned int*)(0xb8010028));   //ISR

	return SUCCESS;
}
#endif

