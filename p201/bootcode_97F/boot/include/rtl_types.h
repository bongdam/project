/*
* Copyright c                  Realtek Semiconductor Corporation, 2002  
* All rights reserved.                                                    
* 
* Abstract : realtek type definition
 *
 * $Author: jasonwang $
 *
 * $Log: rtl_types.h,v $
 * Revision 1.1  2009/11/13 13:22:46  jasonwang
 * Added rtl8196c and 98 bootcode.
 *
 * Revision 1.1.1.1  2007/08/06 10:05:01  root
 * Initial import source to CVS
 *
 * Revision 1.5  2005/09/22 05:22:31  bo_zhao
 * *** empty log message ***
 *
 * Revision 1.1.1.1  2005/09/05 12:38:24  alva
 * initial import for add TFTP server
 *
 * Revision 1.4  2004/08/26 13:53:27  yjlou
 * -: remove all warning messages!
 * +: add compile flags "-Wno-implicit -Werror" in Makefile to treat warning as error!
 *
 * Revision 1.3  2004/05/12 06:35:11  yjlou
 * *: fixed the ASSERT_CSP() and ASSERT_ISR() macro: print #x will cause unpredictable result.
 *
 * Revision 1.2  2004/03/31 01:49:20  yjlou
 * *: all text files are converted to UNIX format.
 *
 * Revision 1.1  2004/03/16 06:36:13  yjlou
 * *** empty log message ***
 *
 * Revision 1.1.1.1  2003/09/25 08:16:56  tony
 *  initial loader tree 
 *
 * Revision 1.1.1.1  2003/05/07 08:16:07  danwu
 * no message
 *
*/



#ifndef _RTL_TYPES_H
#define _RTL_TYPES_H

/*
 * Internal names for basic integral types.  Omit the typedef if
 * not possible for a machine/compiler combination.
 */

typedef unsigned long long	uint64;
typedef long long		int64;
typedef unsigned int	uint32;
typedef int			int32;
typedef unsigned short	uint16;
typedef short			int16;
typedef unsigned char	uint8;
typedef char			int8;

#define UINT32_MAX	UINT_MAX
#define INT32_MIN	INT_MIN
#define INT32_MAX	INT_MAX
#define UINT16_MAX	USHRT_MAX
#define INT16_MIN	SHRT_MIN
#define INT16_MAX	SHRT_MAX
#define UINT8_MAX	UCHAR_MAX
#define INT8_MIN		SCHAR_MIN
#define INT8_MAX	SCHAR_MAX

typedef uint32		memaddr;	
typedef uint32          ipaddr_t;

typedef struct {
    uint16      mac47_32;
    uint16      mac31_16;
    uint16      mac15_0;
    uint16		align;
} macaddr_t;


typedef int8*			calladdr_t;

typedef struct ether_addr_s {
	uint8 octet[6];
} ether_addr_t;

#include "rtl_depend.h"

#ifndef NULL
#define NULL 0
#endif
#ifndef TRUE
#define TRUE 1
#endif
#ifndef FALSE
#define FALSE 0
#endif

#ifndef SUCCESS
#define SUCCESS 	0
#endif
#ifndef FAILED
#define FAILED -1
#endif

#define CLEARBITS(a,b)	((a) &= ~(b))
#define SETBITS(a,b)		((a) |= (b))
#define ISSET(a,b)		(((a) & (b))!=0)
#define ISCLEARED(a,b)	(((a) & (b))==0)

#ifndef max
#define max(a,b)  (((a) > (b)) ? (a) : (b))
#endif			   /* max */

#ifndef min
#define min(a,b)  (((a) < (b)) ? (a) : (b))
#endif			   /* min */


extern int dprintf(char *fmt, ...);
//#define ASSERT_CSP(x) if (!(x)) {dprintf("\nAssertion fail at file %s, function %s, line number %d: (%s).\n", __FILE__, __FUNCTION__, __LINE__, #x); while(1);}
//#define ASSERT_ISR(x) if (!(x)) {printfByPolling("\nAssertion fail at file %s, function %s, line number %d: (%s).\n", __FILE__, __FUNCTION__, __LINE__, #x); while(1);}

//wei add, because we only use polling mode uart-print
#define ASSERT_CSP(x) if (!(x)) {dprintf("\nAssertion fail at file"); while(1);}
#define ASSERT_ISR(x) if (!(x)) {dprintf("\nAssertion fail at file");   while(1);}

#ifdef CONFIG_RTL8197F
#define _LITTLE_ENDIAN		1
#endif

#if defined(CONFIG_RTL_SWITCH_NEW_DESCRIPTOR)

#define SIZE_OF_CLUSTER_FOR_RTL8197F_VG_UBOOT        1792

#define NEW_NIC_MAX_RX_RING                     6
#define NEW_NIC_MAX_TX_RING                     4

#define PREV_IDX(N, RING_SIZE)		( ( (N+RING_SIZE-1) < RING_SIZE) ? (RING_SIZE-1) : (N-1) )
#define NEXT_IDX(N, RING_SIZE)		( ( (N+1) == RING_SIZE) ? 0 : (N+1) )

/* definition for TxD (+) */
typedef volatile union {
        struct {
#ifdef _LITTLE_ENDIAN
                uint32 own		: 1 ; /* bits 0:0 */
                uint32 eor		: 1 ; /* bits 1:1 */
                uint32 ls		: 1 ; /* bits 2:2 */
                uint32 fs		: 1 ; /* bits 3:3 */
                uint32 hwlkup		: 1 ; /* bits 4:4 */
                uint32 bridge		: 1 ; /* bits 5:5 */
                uint32 len		: 17 ; /* bits 22:06 */
                uint32 pppidx		: 3 ; /* bits 25:23 */
                uint32 pi		: 1 ; /* bits 26:26 */
                uint32 li		: 1 ; /* bits 27:27 */
                uint32 vi		: 1 ; /* bits 28:28 */
                uint32 type		: 3 ; /* bits 31:29 */
#endif /* _LITTLE_ENDIAN */
        } bf ;
        uint32 wrd ;
} AAL_NIC_TX_DESC_WORD0_t;

typedef volatile union {
        struct {
                uint32 mdata		: 32 ; /* bits 31:0 */
        } bf ;
        uint32 wrd ;
} AAL_NIC_TX_DESC_WORD1_t;

typedef volatile union {
        struct {
#ifdef _LITTLE_ENDIAN
                uint32 vlantagset	: 9 ; /* bits 8:0 */
                uint32 pqid		: 3 ; /* bits 11:09 */
                uint32 qid		: 3 ; /* bits 14:12 */
                uint32 m_len		: 17 ; /* bits 31:15 */
#endif /* _LITTLE_ENDIAN */
        } bf ;
        uint32 wrd ;
} AAL_NIC_TX_DESC_WORD2_t;

typedef volatile union {
        struct {
#ifdef _LITTLE_ENDIAN
                uint32 dvlanid		: 12 ; /* bits 11:0 */
                uint32 dp_ext		: 3 ; /* bits 14:12 */
                uint32 rsrvd1		: 1 ; /* bits 15:15 */
                uint32 ipv4_1st		: 1 ; /* bits 16:16 */
                uint32 ipv4		: 1 ; /* bits 17:17 */
                uint32 ipv6		: 1 ; /* bits 18:18 */
                uint32 l4cs		: 1 ; /* bits 19:19 */
                uint32 l3cs		: 1 ; /* bits 20:20 */
                uint32 po		: 1 ; /* bits 21:21 */
                uint32 dpri		: 3 ; /* bits 24:22 */
                uint32 ptp_ver		: 2 ; /* bits 26:25 */
                uint32 ptp_typ		: 4 ; /* bits 30:27 */
                uint32 ptp_pkt		: 1 ; /* bits 31:31 */
#endif /* _LITTLE_ENDIAN */
        } bf ;
        uint32 wrd ;
} AAL_NIC_TX_DESC_WORD3_t;

typedef volatile union {
        struct {
#ifdef _LITTLE_ENDIAN
                uint32 ipv6_hdrlen	: 16 ; /* bits 15:0 */
                uint32 linked		: 7 ; /* bits 22:16 */
                uint32 rsrvd1		: 1 ; /* bits 23:23 */
                uint32 dp		: 7 ; /* bits 30:24 */
                uint32 lso		: 1 ; /* bits 31:31 */
#endif /* _LITTLE_ENDIAN */
        } bf ;
        uint32 wrd ;
} AAL_NIC_TX_DESC_WORD4_t;

typedef volatile union {
        struct {
#ifdef _LITTLE_ENDIAN
                uint32 tcp_hlen		: 4 ; /* bits 3:0 */
                uint32 ipv4_hllen	: 4 ; /* bits 7:4 */
                uint32 flags		: 8 ; /* bits 15:8 */
                uint32 mss		: 14 ; /* bits 29:16 */
                uint32 extspa		: 2 ; /* bits 31:30 */
#endif /* _LITTLE_ENDIAN */
        } bf ;
        uint32 wrd ;
} AAL_NIC_TX_DESC_WORD5_t;

typedef struct dma_tx_desc {
#ifdef _LITTLE_ENDIAN
        AAL_NIC_TX_DESC_WORD0_t opts0;	/* w0 */
        AAL_NIC_TX_DESC_WORD1_t opts1;	/* w1 */
        AAL_NIC_TX_DESC_WORD2_t opts2;	/* w2 */
        AAL_NIC_TX_DESC_WORD3_t opts3;	/* w3 */
        AAL_NIC_TX_DESC_WORD4_t opts4;	/* w4 */
        AAL_NIC_TX_DESC_WORD5_t opts5;	/* w5 */
#ifdef CONFIG_NIC_TX_DESC_32_BYTE_ALIGN
        AAL_NIC_TX_DESC_WORD1_t opts6;	/* w6 */
        AAL_NIC_TX_DESC_WORD1_t opts7;	/* w7 */
#endif /* CONFIG_NIC_TX_DESC_32_BYTE_ALIGN */
#endif /* _LITTLE_ENDIAN */
} AAL_NIC_TX_DESC_t;
/* definition for TxD (-) */

/* definition for RxD (+) */
typedef volatile union {
        struct {
#ifdef _LITTLE_ENDIAN
                uint32 own		: 1 ; /* bits 0:0 */
                uint32 eor		: 1 ; /* bits 1:1 */
                uint32 ls		: 1 ; /* bits 2:2 */
                uint32 fs		: 1 ; /* bits 3:3 */
                uint32 rsrvd1		: 1 ; /* bits 15:04 */
                uint32 m_extsize	: 16 ; /* bits 31:16 */
#endif /* _LITTLE_ENDIAN */
        } bf ;
        uint32 wrd ;
} AAL_NIC_RX_DESC_WORD0_t;

typedef volatile union {
        struct {
                uint32 mdata		: 32 ; /* bits 31:0 */
        } bf ;
        uint32 wrd ;
} AAL_NIC_RX_DESC_WORD1_t;

typedef volatile union {
        struct {
#ifdef _LITTLE_ENDIAN
                uint32 len		: 14 ; /* bits 13:0 */
                uint32 rsrvd1		: 3 ; /* bits 16:14 */
                uint32 qid		: 3 ; /* bits 19:17 */
                uint32 dp_ext		: 4 ; /* bits 23:20 */
                uint32 extspa		: 2 ; /* bits 25:24 */
                uint32 rsrvd2		: 6 ; /* bits 31:26 */
#endif /* _LITTLE_ENDIAN */
        } bf ;
        uint32 wrd ;
} AAL_NIC_RX_DESC_WORD2_t;

typedef volatile union {
        struct {
#ifdef _LITTLE_ENDIAN
                uint32 reason		: 16 ; /* bits 15:0 */
                uint32 linkid		: 7 ; /* bits 22:16 */
                uint32 ppp_idx		: 3 ; /* bits 25:23 */
                uint32 po		: 1 ; /* bits 26:26 */
                uint32 lo		: 1 ; /* bits 27:27 */
                uint32 vo		: 1 ; /* bits 28:28 */
                uint32 type		: 3 ; /* bits 31:29 */
#endif /* _LITTLE_ENDIAN */
        } bf ;
        uint32 wrd ;
} AAL_NIC_RX_DESC_WORD3_t;

typedef volatile union {
        struct {
#ifdef _LITTLE_ENDIAN
                uint32 tos		: 8 ; /* bits 7:0 */
                uint32 ipv4		: 1 ; /* bits 8:8 */
                uint32 ipv6		: 1 ; /* bits 9:9 */
                uint32 ipv4_1st		: 1 ; /* bits 10:10 */
                uint32 frag		: 1 ; /* bits 11:11 */
                uint32 last_f		: 1 ; /* bits 12:12 */
                uint32 spa		: 3 ; /* bits 15:13 */
                uint32 dvlanid		: 12 ; /* bits 27:16 */
                uint32 l2act		: 1 ; /* bits 28:28 */
                uint32 ext_vlano	: 3 ; /* bits 31:29 */
#endif /* _LITTLE_ENDIAN */
        } bf ;
        uint32 wrd ;
} AAL_NIC_RX_DESC_WORD4_t;

typedef volatile union {
        struct {
#ifdef _LITTLE_ENDIAN
                uint32 svlanid		: 12 ; /* bits 11:0 */
                uint32 ext_ttl		: 3 ; /* bits 14:12 */
                uint32 rsrvd1		: 1 ; /* bits 15:15 */
                uint32 spri		: 3 ; /* bits 18:16 */
                uint32 dpri		: 3 ; /* bits 21:19 */
                uint32 porg		: 1 ; /* bits 22:22 */
                uint32 lorg		: 1 ; /* bits 23:23 */
                uint32 vorg		: 1 ; /* bits 24:24 */
                uint32 ip_mdf		: 3 ; /* bits 27:25 */
                uint32 org		: 1 ; /* bits 28:28 */
                uint32 fwd		: 1 ; /* bits 29:29 */
                uint32 l4csok		: 1 ; /* bits 30:30 */
                uint32 l3csok		: 1 ; /* bits 31:31 */
#endif /* _LITTLE_ENDIAN */
        } bf ;
        uint32 wrd ;
} AAL_NIC_RX_DESC_WORD5_t;

typedef struct dma_rx_desc {
#ifdef _LITTLE_ENDIAN
        AAL_NIC_RX_DESC_WORD0_t opts0;	/* w0 */
        AAL_NIC_RX_DESC_WORD1_t opts1;	/* w1 */
        AAL_NIC_RX_DESC_WORD2_t opts2;	/* w2 */
        AAL_NIC_RX_DESC_WORD3_t opts3;	/* w3 */
        AAL_NIC_RX_DESC_WORD4_t opts4;	/* w4 */
        AAL_NIC_RX_DESC_WORD5_t opts5;	/* w5 */
#ifdef CONFIG_NIC_RX_DESC_32_BYTE_ALIGN
        AAL_NIC_RX_DESC_WORD1_t opts6;	/* w6 */
        AAL_NIC_RX_DESC_WORD1_t opts7;	/* w7 */
#endif /* CONFIG_NIC_RX_DESC_32_BYTE_ALIGN */
#endif /* _LITTLE_ENDIAN */
} AAL_NIC_RX_DESC_t;
/* definition for RxD (-) */

#endif // end of CONFIG_RTL_SWITCH_NEW_DESCRIPTOR

#endif
