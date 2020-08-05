#include "rtl_crypto_wrapper.h"
#include "rtl_crypto_helper.h"
#include "rtl_ipsec.h"
#include <crypto_engine/sw_sim/aes.h>
/* only support AES-CBC AES-CTR */

typedef unsigned int 	UINT32;
typedef unsigned int 	__be32;
typedef unsigned char 	bool;

#define MAX_CRYPTO_SIZE				(16*1024-16)	
#define RTL_CRYPTO_BLOCK_SIZE		16
#define RTL_CRYPTO_IV_LEN			16
#define CACHE_LINE					32

#define ALIGNED(x,alignmask)	(((unsigned int)x + alignmask-1) & ~(alignmask-1))

/* swap */
#define ___swab32(x) \
 	({ \
		UINT32 __x = (x); \
		((UINT32)( \
		(((UINT32)(__x) & (UINT32)0x000000ffUL) << 24) | \
			(((UINT32)(__x) & (UINT32)0x0000ff00UL) <<  8) | \
			(((UINT32)(__x) & (UINT32)0x00ff0000UL) >>  8) | \
			(((UINT32)(__x) & (UINT32)0xff000000UL) >> 24) )); \
	})

#define cpu_to_be32(x) 	___swab32(x)
#define be32_to_cpu(x)	cpu_to_be32(x)
#define ntohl(x)		cpu_to_be32(x)
#define htonl(x)		ntohl(x)

#define RTL_CRYPTO_MAX_KEY_LEN	32

int	rtl_aes_set_dec_key(unsigned char *org_key, unsigned char *dec_key, unsigned int key_len)
{
	AES_KEY aes_key;
	unsigned char temp_key[RTL_CRYPTO_MAX_KEY_LEN] = {0};
	
	memset((void *)&aes_key, 0, sizeof(aes_key));
	
	memcpy(temp_key, org_key, key_len);

	#if 0
	if (crypto_api_dbg){
		printk("\n%s %d  temp key key_len=0x%x \n\n", __func__, __LINE__, key_len);
		rtl_dump_info(temp_key, key_len, "temp key");
		printk("\n\n");
	}
	#endif
	
	AES_set_encrypt_key(temp_key, key_len*8, &aes_key);

	switch (key_len)
	{
		case 128/8:
			memcpy(dec_key, &aes_key.rd_key[4*10], 16);
			break;
		case 192/8:
			memcpy(dec_key, &aes_key.rd_key[4*12], 16);
			memcpy((dec_key+16), &aes_key.rd_key[4*11+2], 8);
			break;
		case 256/8:
			memcpy(dec_key, &aes_key.rd_key[4*14], 16);
			memcpy(dec_key+16, &aes_key.rd_key[4*13], 16);
			break;
		default:
			prom_printf("\n %s: unknown aes key_len=%d\n", __FUNCTION__, key_len);
			//return RTL_CRYPTO_FAILED;
			return -1;
	}

	//return RTL_CRYPTO_SUCCESS;
	return 0;
}


#if 1
//#ifndef RTK_X86_CLE//RTK-CNSD2-NickWu-20061222: for x86 compile
/*cfliu: This function is only for debugging. Should not be used in production code...*/
void memDump (void *start, uint32 size, int8 * strHeader)
{
	int32 row, column, index, index2, max;
	uint32 buffer[5];
	uint8 *buf, *line, ascii[17];
	int8 empty = ' ';

	if(!start ||(size==0))
		return;
	line = (uint8*)start;

	/*
	16 bytes per line
	*/
	if (strHeader)
		rtlglue_printf ("%s", strHeader);
	column = size % 16;
	row = (size / 16) + 1;
	for (index = 0; index < row; index++, line += 16) 
	{
#ifdef RTL865X_TEST
		buf = (uint8*)line;
#else
		/* for un-alignment access */
		buffer[0] = ntohl( READ_MEM32( (((uint32)line)&~3)+ 0 ) );
		buffer[1] = ntohl( READ_MEM32( (((uint32)line)&~3)+ 4 ) );
		buffer[2] = ntohl( READ_MEM32( (((uint32)line)&~3)+ 8 ) );
		buffer[3] = ntohl( READ_MEM32( (((uint32)line)&~3)+12 ) );
		buffer[4] = ntohl( READ_MEM32( (((uint32)line)&~3)+16 ) );
		buf = ((uint8*)buffer) + (((uint32)line)&3);
#endif

		memset (ascii, 0, 17);

		max = (index == row - 1) ? column : 16;
		if ( max==0 ) break; /* If we need not dump this line, break it. */

		rtlglue_printf ("\n%08x: ", (memaddr) line);
		
		//Hex
		for (index2 = 0; index2 < max; index2++)
		{
			if (index2 == 8)
			rtlglue_printf ("  ");
			rtlglue_printf ("%02X", (uint8) buf[index2]);
			ascii[index2] = ((uint8) buf[index2] < 32) ? empty : buf[index2];
			if((index2+1)%4==0)
				rtlglue_printf ("  ");
		}

		if (max != 16)
		{
			if (max < 8)
				rtlglue_printf ("  ");
			for (index2 = 16 - max; index2 > 0; index2--)
				rtlglue_printf ("   ");
		}

		//ASCII
#ifndef CONFIG_RTL_8197F
		rtlglue_printf ("  %s", ascii);
#endif
	}
	rtlglue_printf ("\n");
	return;
}
#endif


int32 rtl_crypto_helper_alloc(void)
{
	return 0;
}

int32 rtl_crypto_helper_free( void )
{
	return 0;
}

int copy_from_user(void *to,const void *from, int c) 
{
  memcpy(to, from, c);
  return 0;
}

void print_hex_dump(const char *level, const char *prefix_str,
			   int prefix_type, int rowsize, int groupsize,
			   const void *buf, size_t len, bool ascii)
{
	return;
}


/* from kernel start */
static  inline void crypto_inc_byte(u8 *a, unsigned int size)
{
	u8 *b = (a + size);
	u8 c;

	for (; size; size--) {
		c = *--b + 1;
		*b = c;
		if (c)
			break;
	}
}

static void crypto_inc(u8 *a, unsigned int size)
{
	__be32 *b = (__be32 *)(a + size);
	u32 c;

	for (; size >= 4; size -= 4) {
		c = be32_to_cpu(*--b) + 1;
		*b = cpu_to_be32(c);
		if (c)
			return;
	}

	crypto_inc_byte(a, size);
}


static int rtl_cipher_do_crypt(int mode,unsigned flag_encrypt,int bsize,u8* real_key,u32 keylen,u8* iv,u8* src,u32 nbytes,u8* dst)
{	
	int err;
	rtl_ipsecScatter_t scatter[1];
	scatter[0].len = (nbytes / bsize) * bsize;
	scatter[0].ptr = (void *) CKSEG1ADDR(src);

	dma_cache_wback((u32) src, nbytes);
	dma_cache_wback((u32) real_key, keylen);
	dma_cache_wback((u32) iv, bsize);
	dma_cache_wback((u32) dst, nbytes);

	err = rtl_ipsecEngine(mode | flag_encrypt,
		-1, 1, scatter,
		(void *) CKSEG1ADDR(dst),
		keylen, (void *) CKSEG1ADDR(real_key),
		0, NULL,
		(void *) CKSEG1ADDR(iv), NULL, NULL,
		0, scatter[0].len);

	if(err < 0){
		return -1;
	}

	dma_cache_wback_inv((u32) dst, nbytes);
	dma_cache_wback_inv((u32) iv, nbytes);

	return nbytes - scatter[0].len;
}

int rtl_cipher_crypt_command(u8 bEncrypt,u8* alg,u32 bsize,u8* key,u32 keylen,u8* orig_iv,u8* src,u32 nbytes,u8* dst)
{
	int err,mode,nbytes0,ret = 0;
	unsigned int  flag_encrypt; 
	unsigned char *en_key,*de_key,*real_key,*real_key0,*iv,*iv0;
	unsigned char padding0[RTL_CRYPTO_BLOCK_SIZE+CACHE_LINE]={0},out_padding0[RTL_CRYPTO_BLOCK_SIZE+CACHE_LINE] = {0};
	unsigned int pad_val = 0,left = 0;
	unsigned int encryptd_len = 0, encrypt_len = 0;
	unsigned char *padding,*out_padding;
	
	/* over flag */
	int i, over_flag = 0;
	unsigned int one = 0, len = 0;			
	u8 over_iv[RTL_CRYPTO_IV_LEN] = {0};

	/* mode */
	if (strcmp(alg, "cbc(aes)") == 0)
		mode = DECRYPT_CBC_AES;
	else if (strcmp(alg, "ecb(aes)") == 0)
		mode = DECRYPT_ECB_AES;
	else if (strcmp(alg, "ctr(aes)") == 0)
		mode = DECRYPT_CTR_AES;
	else{
		prom_printf("%s:%d: not support %s encrypt/decrypt\n",__func__,__LINE__,alg);
		return -1;
	}

	/* cbc padding */
	//if(mode == DECRYPT_CBC_AES)
	{
		left = nbytes % bsize;
		pad_val = bsize - left;
		padding = (unsigned char*)ALIGNED(padding0,CACHE_LINE);
		out_padding = (unsigned char*)ALIGNED(out_padding0,CACHE_LINE);
		
		if(left != 0){
			memset(padding,pad_val,bsize);
			memcpy(padding,src+nbytes/bsize*bsize,left);
		}else{
			if(mode == DECRYPT_CBC_AES){
				left = RTL_CRYPTO_BLOCK_SIZE;
				memset(padding,pad_val,bsize);
			}
		}
	}

	real_key0 = malloc(CACHE_LINE+keylen);
	if(real_key0 == NULL){
		prom_printf("%s:%d,malloc fail\n",__func__,__LINE__);
		return -1;
	}
	
	iv0 = malloc(CACHE_LINE+RTL_CRYPTO_IV_LEN);
	if(iv0 == NULL){
		if(real_key0){
			free(real_key0);
			real_key0 = NULL;
		}
		prom_printf("%s:%d,malloc fail\n",__func__,__LINE__);
		return -1;
	}
	
	/* set key */
	real_key = (unsigned char*)ALIGNED(real_key0,CACHE_LINE);
	if(bEncrypt || mode == DECRYPT_CTR_AES)
		memcpy(real_key,key,keylen);
	else{
		if(rtl_aes_set_dec_key(key,real_key,keylen) < 0){
			ret = -1;
			goto OUT;
		}
	}
	
	/* iv */
	
	iv = (unsigned char*)ALIGNED(iv0,CACHE_LINE);
	if(mode != DECRYPT_ECB_AES)
		memcpy(iv,orig_iv,RTL_CRYPTO_IV_LEN);
	
	/* other */	
	flag_encrypt = bEncrypt ? 4 : 0;
	if(mode == DECRYPT_CTR_AES)
		flag_encrypt = 4;
	
	while(encryptd_len < nbytes){
		encrypt_len = (nbytes-encryptd_len)>=MAX_CRYPTO_SIZE ? MAX_CRYPTO_SIZE: (nbytes-encryptd_len);
		
		over_flag = 0;
		if(mode == DECRYPT_CTR_AES){
			one = *((unsigned int *)(iv + bsize - 4));
			one = htonl(one);
			
			for (i = 0; i < (encrypt_len / bsize); i++)
			{					
				if (one == 0xffffffff)
				{
					over_flag = 1;
					break;
				}
				one++;
			}

			if (over_flag){
				//before ONE overflow 
				len = bsize*(i+1);

				nbytes0 = rtl_cipher_do_crypt(mode,flag_encrypt,bsize,real_key,keylen,iv,src,len,dst);
				if(nbytes0 < 0){
					ret = -1;
					goto OUT;
				}
				src += (len - nbytes0);
				dst += (len - nbytes0);
				#if 1	
				//after ONE overflow,update IV
				memcpy(over_iv, iv, bsize - 4);
				crypto_inc(over_iv, bsize-4);
				memcpy(iv, over_iv, bsize);
				#endif
				nbytes0 = rtl_cipher_do_crypt(mode,flag_encrypt,bsize,real_key,keylen,iv,src,encrypt_len -len,dst);
				if(nbytes0 < 0){
					ret = -1;
					goto OUT;
				}
				/* increment counter in counterblock */
				for (i = 0; i < ((encrypt_len -len) / bsize); i++)
					crypto_inc(iv, bsize);
				src += encrypt_len-len-nbytes0;
				dst += encrypt_len-len-nbytes0;
			}else{
				nbytes0 = rtl_cipher_do_crypt(mode,flag_encrypt,bsize,real_key,keylen,iv,src,encrypt_len,dst);
				if(nbytes0 < 0){
					ret = -1;
					goto OUT;
				}
				for (i = 0; i < (nbytes / bsize); i++)
						crypto_inc(iv, bsize);
				src += encrypt_len - nbytes0;
				dst += encrypt_len - nbytes0;
			}
		}else{
			nbytes0 = rtl_cipher_do_crypt(mode,flag_encrypt,bsize,real_key,keylen,iv,src,encrypt_len,dst);
			if(nbytes0 < 0){
				ret = -1;
				goto OUT;
			}
			src += encrypt_len - nbytes0;
			dst += encrypt_len - nbytes0;
		}

		encryptd_len += encrypt_len;
	}

	/* padding */
	//if(mode == DECRYPT_CBC_AES)
	{
		if(left > 0){
			nbytes0 = rtl_cipher_do_crypt(mode,flag_encrypt,bsize,real_key,keylen,iv,padding,bsize,out_padding);
			if(nbytes0 < 0){
				ret = -1;
				goto OUT;
			}
			memcpy(dst,out_padding,left);
			
			if(mode == DECRYPT_CTR_AES)
				crypto_inc(iv, bsize);
		}
	}
	
OUT:
	if(real_key0){
		free(real_key0);
		real_key0 = NULL;
	}
	if(iv0){
		free(iv0);
		iv0 = NULL;
	}

	return ret;
}


