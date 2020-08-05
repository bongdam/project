#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include "utility.h"
#include "fastcksum.h"

#if defined(CONFIG_RTL_FAST_CHECKSUM_ENABLE)
typedef unsigned long  uLong;
typedef char Bytef;
typedef unsigned int uInt;
	
#define BASE 65521      /* largest prime smaller than 65536 */
#define NMAX 5552
#define Z_NULL NULL
/* NMAX is the largest n such that 255n(n+1)/2 + (n+1)(BASE-1) <= 2^32-1 */
	
#define DO1(buf,i)  {adler += (buf)[i]; sum2 += adler;}
#define DO2(buf,i)  {DO1(buf,i); DO1(buf,i+1);}
#define DO4(buf,i)  {DO2(buf,i); DO2(buf,i+2);}
#define DO8(buf,i)  {DO4(buf,i); DO4(buf,i+4);}
#define DO16(buf)   {DO8(buf,0); DO8(buf,8);}
#define MOD(a) a %= BASE
#define MOD28(a) a %= BASE
#define MOD63(a) a %= BASE
	
/* ========================================================================= */
static uLong adler32(adler, buf, len)
	uLong adler;
	const Bytef *buf;
	uInt len;
{
	unsigned long sum2;
	unsigned n;

	/* split Adler-32 into component sums */
	sum2 = (adler >> 16) & 0xffff;
	adler &= 0xffff;

	/* in case user likes doing a byte at a time, keep it fast */
	if (len == 1) {
		adler += buf[0];
		if (adler >= BASE)
			adler -= BASE;
		sum2 += adler;
		if (sum2 >= BASE)
			sum2 -= BASE;
		return adler | (sum2 << 16);
	}	

	/* initial Adler-32 value (deferred check for len == 1 speed) */
	if (buf == Z_NULL)
		return 1L; 

	/* in case short lengths are provided, keep it somewhat fast */
	if (len < 16) {
		while (len--) {
			adler += *buf++;
			sum2 += adler;
		}	
		if (adler >= BASE)
			adler -= BASE;
		MOD28(sum2);			/* only added so many BASE's */
		return adler | (sum2 << 16);
	}

	/* do length NMAX blocks -- requires just one modulo operation */
	while (len >= NMAX) {
		len -= NMAX;
		n = NMAX / 16;			/* NMAX is divisible by 16 */
		do {
			DO16(buf);			/* 16 sums unrolled */
			buf += 16;
		} while (--n);
		MOD(adler);
		MOD(sum2);
	}

	/* do remaining bytes (less than NMAX, still just one modulo) */
	if (len) {					/* avoid modulos if none remaining */
		while (len >= 16) {
			len -= 16;
			DO16(buf);
			buf += 16;
		}
		while (len--) {
			adler += *buf++;
			sum2 += adler;
		}
		MOD(adler);
		MOD(sum2);
	}

	/* return recombined sums */
	return adler | (sum2 << 16);
}

/*
 * gen_fastcksum():
 *  Generate fast checksum.
 *	Buffer contains of payload length(int) + old checksum of linux or root(short) + magic number(int).
 *	Use this buffer to perform Adler-32 and get an unsigned int fast checksum.
 *	Note:
 *		payload_len: the exact len field value of IMG_HEADER_T stored in flash(should with big endian, check cvimg.c)
 *		old_cksum: the exact old checksum value stored in flash(should with big endian, check cvimg.c).
 */
int gen_fastcksum(unsigned int *cksum, int payload_len, short old_cksum)
{
	char buf[16] = {0};
	int at = 0, i = 0, magic = ___swab32(RTL_FASTCKSUM_ALGO_MAGIC);
	unsigned int tmp = 0;

	if(NULL==cksum)
		return FASTCKSUM_FAILED;

	FCS_DBG("[%s:%d]payload len: 0x%x, old_cksum:0x%x\n", __FUNCTION__, __LINE__, payload_len, old_cksum);

	memcpy(&buf[at], &payload_len, sizeof(int));
	at += sizeof(int);
	memcpy(&buf[at], &old_cksum, sizeof(short));
	at += sizeof(short);
	memcpy(&buf[at], &magic, sizeof(int));
	at += sizeof(int);

	tmp = adler32(0L, NULL, 0); 
    tmp = adler32((unsigned long *)tmp, buf, at);
	*cksum = ___swab32(tmp);

    FCS_DBG("[%s:%d]buf:\n", __FUNCTION__, __LINE__);
    for(i=0; i < at; i++)
    {   
        FCS_DBG("%02x ", buf[i]);
    }   
    FCS_DBG("\n[%s:%d]cksum:0x%x\n", __FUNCTION__, __LINE__, *cksum);

	return FASTCKSUM_SUCCESS;
}

int read_fastcksum_from_flash(unsigned char *buf, int len)
{
	char mtd[32]={0};
	int ret=FASTCKSUM_FAILED, addr = 0;
	int i=0;

	if(NULL==buf || len<=0)
		goto RETURN;

	//fast checksum is only supported in NAND flash now.
#if defined(CONFIG_NAND_FLASH_BOOTING) && defined(CONFIG_FLASH_SIZE)
	addr = CONFIG_FLASH_SIZE - RTL_FASTCKSUM_MTDSIZE;
	if(addr<0)
		goto RETURN;
	
	if(nflashread(buf, (unsigned int)addr, len,0)< 0){
		prom_printf("nand flash read fail,addr=%x,size=%d\n", addr, len);
		return 0;
	}
	
	FCS_DBG("nand flash read buf from %x:\n", addr);
	for(i=0; i<len; i++)
		FCS_DBG("%02x ", buf[i]);
	FCS_DBG("\n");
	
	ret = FASTCKSUM_SUCCESS;
#endif

RETURN:
	return ret;
}

int write_fastcksum_to_flash(unsigned char *buf, int len)
{
	char mtd[32]={0};
	int ret=FASTCKSUM_FAILED, addr=0;
	int i=0;

	if(NULL==buf || len<=0)
		goto RETURN;

	//fast checksum is only supported in NAND flash now.
#if defined(CONFIG_NAND_FLASH_BOOTING) && defined(CONFIG_FLASH_SIZE)
	addr = CONFIG_FLASH_SIZE - RTL_FASTCKSUM_MTDSIZE;
	if(addr<0)
		goto RETURN;

	if(nflashwrite(addr, (unsigned long)buf, len) == 0)
	{
		FCS_DBG("nand flash write buf to %x:\n", addr);
		for(i=0; i<len; i++)
			FCS_DBG("%02x ", buf[i]);
		FCS_DBG("\n");
	}else{
		//write failed
		prom_printf("nand flash write fail,addr=%x,size=%d\n", addr, len);
		goto RETURN;
	}
	
	ret = FASTCKSUM_SUCCESS;
#endif

RETURN:
	return ret;
}

void dump_fastcksum_struct(FASTCKSUM_HEADER_Tp hdr)
{
	FASTCKSUM_PAYLOAD_Tp body = NULL;
	int i=0, count=0;
	
	if(hdr==NULL)
		return ;

	FCS_DBG("Dump fastchecksum structure:\n");
	FCS_DBG("\tlen:%d, sizeof(FASTCKSUM_PAYLOAD_T):%d\n", hdr->len, sizeof(FASTCKSUM_PAYLOAD_T));
	if(hdr->len%sizeof(FASTCKSUM_PAYLOAD_T))
	{
		prom_printf("WARNING: invalid length, exit dump!!\n");
		return;
	}
	count = hdr->len/sizeof(FASTCKSUM_PAYLOAD_T);
	for(i=0; i<count; i++)
	{
		body = ((FASTCKSUM_PAYLOAD_Tp)hdr->payload)+i;
		FCS_DBG("\t[%d]:\n", i);
		FCS_DBG("\t\t Bank:%d\n", body->bank);
		FCS_DBG("\t\t kernel sig:%02x%02x%02x%02x\n", body->linux_sig[0], body->linux_sig[1], body->linux_sig[2], body->linux_sig[3]);
		FCS_DBG("\t\t kernel cksum:0x%x\n", body->linux_cksum);
		FCS_DBG("\t\t root sig:%02x%02x%02x%02x\n", body->root_sig[0], body->root_sig[1], body->root_sig[2], body->root_sig[3]);
		FCS_DBG("\t\t root cksum:0x%x\n", body->root_cksum);
		FCS_DBG("\t\t reserved bitvalue:0x%x\n", body->reserved);
	}
	return ;
}

int revalidation(unsigned char *addr, int size, int *valid)
{

	unsigned char *buf = NULL;
	int ret=FASTCKSUM_FAILED, i=0;
	unsigned short sum = 0;

	if(addr==NULL || size<=0 || valid==NULL)
		goto REVALIDAION_END;
	else
		FCS_DBG("[%s:%d] addr:%x, size:0x%x\n", __FUNCTION__, __LINE__, addr, size);

	//alloc
	buf = (unsigned char *)malloc(size);
	if(buf==NULL)
	{
		prom_printf("[%s:%d] malloc 0x%x bytes failed!\n", __FUNCTION__, __LINE__, size);
		goto REVALIDAION_END;
	}

	//read flash
#ifdef CONFIG_NAND_FLASH_BOOTING
	if(nflashread(buf, (unsigned int)addr, size ,0)< 0){
		prom_printf("nand flash read fail at revalidation,addr=%x,size=%d\n", addr, size);
		goto REVALIDAION_END;
	}
#endif

	//revalidation
	for(i=0; i<size; i+=2)
		sum +=((unsigned short)(((*(buf+1+i))|((*(buf+i))<<8))&0xffff));

	if(sum)
		*valid = 0;
	else
		*valid = 1;
	ret = FASTCKSUM_SUCCESS;

	FCS_DBG("[%s:%d] valid:%d\n", __FUNCTION__, __LINE__, *valid);
REVALIDAION_END:
	if(buf)
		free(buf);
	return ret;
}

#endif /*CONFIG_RTL_FAST_CHECKSUM_ENABLE*/
