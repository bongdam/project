#ifndef __RTL_CRYPTO_WRAPPER_H__
#define __RTL_CRYPTO_WRAPPER_H__
#include "rtl_types.h"
#include <asm/types.h>
#include <linux/stddef.h>

//#define __RTK_BOOT__

/*******************************************************************/
#define SYSTEM_BASE				0xB8000000

#define CRYPTO_BASE		(SYSTEM_BASE+0xC000)	/* 0xB801C000 */
#define IPSSDAR			(CRYPTO_BASE+0x00)	/* IPSec Source Descriptor Starting Address Register */
#define IPSDDAR			(CRYPTO_BASE+0x04)	/* IPSec Destination Descriptor Starting Address Register */
#define IPSCSR			(CRYPTO_BASE+0x08)	/* IPSec Command/Status Register */
#define IPSCTR			(CRYPTO_BASE+0x0C)	/* IPSec Control Register */

/* IPSec Command/Status Register */
#define IPS_SDUEIP		(1<<15)				/* Source Descriptor Unavailable Error Interrupt Pending */
#define IPS_SDLEIP		(1<<14)				/* Source Descriptor Length Error Interrupt Pending */
#define IPS_DDUEIP		(1<<13)				/* Destination Descriptor Unavailable Error Interrupt Pending */
#define IPS_DDOKIP		(1<<12)				/* Destination Descriptor OK Interrupt Pending */
#define IPS_DABFIP		(1<<11)				/* Data Address Buffer Interrupt Pending */
#define IPS_POLL		(1<<1)				/* Descriptor Polling. Set 1 to kick crypto engine to fetch source descriptor. */
#define IPS_SRST		(1<<0)				/* Software reset, write 1 to reset */

/* IPSec Control Register */
#define IPS_SDUEIE		(1<<15)				/* Source Descriptor Unavailable Error Interrupt Enable */
#define IPS_SDLEIE		(1<<14)				/* Source Descriptor Length Error Interrupt Enable */
#define IPS_DDUEIE		(1<<13)				/* Destination Descriptor Unavailable Error Interrupt Enable */
#define IPS_DDOKIE		(1<<12)				/* Destination Descriptor OK Interrupt Enable */
#define IPS_DABFIE		(1<<11)				/* Data Address Buffer Interrupt Enable */
#define IPS_LBKM		(1<<8)				/* Loopback mode enable */
#define IPS_SAWB		(1<<7)				/* Source Address Write Back */
#define IPS_CKE			(1<<6)				/* Clock enable */
#define IPS_DMBS_MASK	(0x7<<3)			/* Mask for Destination DMA Maximum Burst Size */
#define IPS_DMBS_16		(0x0<<3)			/* 16 Bytes */
#define IPS_DMBS_32		(0x1<<3)			/* 32 Bytes */
#define IPS_DMBS_64		(0x2<<3)			/* 64 Bytes */
#define IPS_DMBS_128	(0x3<<3)			/* 128 Bytes */
#define IPS_SMBS_MASK	(0x7<<0)			/* Mask for SourceDMA Maximum Burst Size */
#define IPS_SMBS_16		(0x0<<0)			/* 16 Bytes */
#define IPS_SMBS_32		(0x1<<0)			/* 32 Bytes */
#define IPS_SMBS_64		(0x2<<0)			/* 64 Bytes */
#define IPS_SMBS_128	(0x3<<0)			/* 128 Bytes */

/*******************************************************************/
#define SUCCESS	0
#define FAILED	-1
#define TRUE	1
#define FALSE	0
#define KERN_CONT	""

#define REG32(reg)				(*(volatile unsigned int *)(reg))
#define READ_MEM32(reg)			REG32(reg)
#define WRITE_MEM32(reg,val)	REG32(reg)=(val)

#define printf(fmt,args...)			prom_printf(fmt ,##args)
#define printk(fmt,args...)			prom_printf(fmt ,##args)
#define rtlglue_printf(fmt,args...)	prom_printf(fmt	,##args)

#define GFP_ATOMIC	0
#define kmalloc(x,y)		malloc(x)
#define kfree(x)			free(x)

#define UNCACHE_MASK		0x20000000
#define KSEG1               0xa0000000
#define KSEG0               0x80000000
#define KSEG_MSK		  	0xE0000000
#define PHYS(addr) 			((uint32)(addr)  & ~KSEG_MSK)
#define CPHYSADDR(addr)		PHYS(addr)
#define CKSEG1ADDR(a)		(CPHYSADDR(a) | KSEG1)
#define CKSEG0ADDR(a)		(CPHYSADDR(a) | KSEG0)

#define assert(x)\
if (!(x)) { \
        int *p=NULL;\
        printf("\nAssertion fail at File %s, In function %s, Line number %d:\nExpression '%s'", __FILE__, __FUNCTION__, __LINE__, #x);\
	*p = 123;\
	while(1){};\
}\

#define unlikely
#define sprintf SprintF
#define jiffies get_timer_jiffies()
#define simple_strtol	strtoul

/********************************crypto helper**************************/
enum {
	DUMP_PREFIX_NONE,
	DUMP_PREFIX_ADDRESS,
	DUMP_PREFIX_OFFSET
};

#define CRYPTO_MAX_ALG_NAME		64
struct crypto_alg {
#if 0
	struct list_head cra_list;
	u32 cra_flags;
#endif
	unsigned int cra_blocksize;
	//unsigned int cra_ctxsize;

	const char cra_name[CRYPTO_MAX_ALG_NAME];
#if 0
	union {
		struct cipher_alg cipher;
		struct digest_alg digest;
		struct compress_alg compress;
	} cra_u;

	struct module *cra_module;
#endif
};

struct crypto_tfm {
#if 0
	u32 crt_flags;

	union {
		struct cipher_tfm cipher;
		struct digest_tfm digest;
		struct compress_tfm compress;
	} crt_u;
#endif
	struct crypto_alg *__crt_alg;
};

struct crypto_cipher {
	struct crypto_tfm base;
};

#if 0

static inline void *crypto_tfm_ctx(struct crypto_tfm *tfm)
{
	return (void *)&tfm[1];
}
#endif

static inline struct crypto_tfm *crypto_cipher_tfm(struct crypto_cipher *tfm)
{
	return &tfm->base;
}

static inline const char *crypto_tfm_alg_name(struct crypto_tfm *tfm)
{
	return tfm->__crt_alg->cra_name;
}

static inline unsigned int crypto_tfm_alg_blocksize(struct crypto_tfm *tfm)
{
	return tfm->__crt_alg->cra_blocksize;
}
static inline unsigned int crypto_cipher_blocksize(struct crypto_cipher *tfm)
{
	return crypto_tfm_alg_blocksize(crypto_cipher_tfm(tfm));
}

#define AES_MAX_KEY_SIZE	32
#define AES_MAX_KEYLENGTH	(15 * 16)
#define AES_MAX_KEYLENGTH_U32	(AES_MAX_KEYLENGTH / sizeof(u32))

struct crypto_aes_ctx {
	u32 key_enc[AES_MAX_KEYLENGTH_U32];
	u32 key_dec[AES_MAX_KEYLENGTH_U32];
	u32 key_length;	
	#if defined(CONFIG_CRYPTO_DEV_REALTEK)
	u8  cbc_key[AES_MAX_KEY_SIZE];
	#endif
};

#define	EINVAL						22	/* Invalid argument */
#define cpu_to_le32(x) 				((__u32)(x))
#define dma_cache_inv(x,y)			invalidate_dcache_range(x,(x+y))
#define _dma_cache_inv(x,y)			dma_cache_inv(x,y)
#define dma_cache_wback(x,y)		flush_dcache_range(x,(x+y))
#define _dma_cache_wback(x,y)		dma_cache_wback(x,y)
#define dma_cache_wback_inv(x,y)	flush_dcache_range(x,(x+y))
#define _dma_cache_wback_inv(x,y)	dma_cache_wback_inv(x,y)

#endif
