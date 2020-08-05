
#include <linux/autoconf2.h>   
#include <asm/rtl8196x.h> 

#include "utility.h"
#include "rtk.h"
#include <string.h>
#include <asm/system.h>
#include <rtl8196x/asicregs.h>
#include <asm/mipsregs.h>
#include <bspchip.h>

#ifdef CONFIG_NAND_FLASH
#include <rtk_nand_api.h>
#endif

#ifdef CONFIG_SD_CARD_BOOTING
#include <rlxboard.h>
#include <ddr/efuse.h>
#include <sys_reg.h>
//#include "../efuse/efuse.h"
#include "../sdcard/arch/include/sdcard_reg.h"
#include "../sdcard/sdcard.h"
#include "../fs/ff.h"
#endif

#ifdef CONFIG_RTL_FAST_CHECKSUM_ENABLE
#include "fastcksum.h"
#endif

#ifdef CONFIG_NAND_FLASH_BOOTING
#undef FLASH_BASE
#define FLASH_BASE 0
#endif
#ifdef __DAVO__
unsigned long return_addr;
unsigned long kernelsp;

static char dl_heap[_SYSTEM_HEAP_SIZE];

int nvram_coincide(SETTING_HEADER_Tp p);
#endif

//#define UTILITY_DEBUG 1
#define NEED_CHKSUM 1

#ifdef CONFIG_RTL_FLASH_DUAL_IMAGE_ENABLE	
#define BANK1_BOOT 1
#define BANK2_BOOT 2

#define GOOD_BANK_MARK_MASK 0x80000000  //goo abnk mark must set bit31 to 1

#define NO_IMAGE_BANK_MARK 0x80000000  
#define OLD_BURNADDR_BANK_MARK 0x80000001 
#define BASIC_BANK_MARK 0x80000002           
#define FORCEBOOT_BANK_MARK 0xFFFFFFF0  //means always boot/upgrade in this bank

#define IN_TFTP_MODE 0
#define IN_BOOTING_MODE 1


int boot_bank=0; 
unsigned long  bank_mark=0;

#endif

#if defined(__DAVO__) && NEED_CHKSUM
static int need_cksum;
#endif

#ifdef CONFIG_RTL_FPGA
unsigned long  glexra_clock=(BSP_CPU0_FREQ/4); // switch
//unsigned long  glexra_clock=40*1000*1000;  //FPGA
//unsigned long  glexra_clock=30*1000*1000;  //FPGA
//unsigned long  glexra_clock=25*1000*1000;  //FPGA
//unsigned long  glexra_clock=33868800;  //FPGA
//unsigned long  glexra_clock=20*1000*1000;  //FPGA
#else
unsigned long  glexra_clock=200*1000*1000;
#endif

#ifdef CONFIG_BOOT_FAIL_CHECK
/*
 * check_bootstatus_register()
 * get boot status register value of current bank.
 * @linuxAddr: the linux.bin start address in flash.
 * Return Value:
 * 	1: can boot current bank
 * 	0: cannot boot current bank
 */
static int check_bootstatus_register(unsigned long linuxAddr)
{
	unsigned int regVal=0, round=0;
	bool failed=true;
	int ret=0;

#ifdef CONFIG_RTL_FLASH_DUAL_IMAGE_ENABLE
	if(linuxAddr>(FLASH_BASE+CONFIG_RTL_FLASH_DUAL_IMAGE_OFFSET))
	{
		regVal = REG32(BSP_DUMMY_REG_BANK2_BOOTSTATUS);
	}else
#endif
		regVal = REG32(BSP_DUMMY_REG_BANK1_BOOTSTATUS);

	failed = (regVal&BOOTFAIL_CHECK_BIT_ISBOOTING)?true:false;
	round = (regVal&(~BOOTFAIL_CHECK_BIT_ISBOOTING));
	//prom_printf("[%s:%d] linuxAddr:%x, regVal:%x, failed:%d, round:%d\n", __FUNCTION__, __LINE__, linuxAddr, regVal, failed, round);
	
	if( failed==false || ( failed==true && round<CONFIG_BOOT_FAIL_THRESHOLD) )
		return 1;
	else
		return 0;
}

static void set_bootstatus_register(unsigned long linuxAddr)
{
	unsigned int regVal=0, round=0;
	bool failed=true;
	int ret=0;

#ifdef CONFIG_RTL_FLASH_DUAL_IMAGE_ENABLE
	if(linuxAddr>(FLASH_BASE+CONFIG_RTL_FLASH_DUAL_IMAGE_OFFSET))
	{
		regVal = REG32(BSP_DUMMY_REG_BANK2_BOOTSTATUS);
	}else
#endif
		regVal = REG32(BSP_DUMMY_REG_BANK1_BOOTSTATUS);

	failed = (regVal&BOOTFAIL_CHECK_BIT_ISBOOTING)?true:false;
	round = (regVal&(~BOOTFAIL_CHECK_BIT_ISBOOTING));
	//prom_printf("[%s:%d] orig: linuxAddr:%x, regVal:%x, failed:%d, round:%d\n", __FUNCTION__, __LINE__, linuxAddr, regVal, failed, round);

	if(failed==false)
	{
		//never started yet or last time bootup succeed, reset round
		round = 1;
	}else{
		//increase round
		round++;
	}

#ifdef CONFIG_RTL_FLASH_DUAL_IMAGE_ENABLE
	if(linuxAddr>(FLASH_BASE+CONFIG_RTL_FLASH_DUAL_IMAGE_OFFSET))
	{
		//prom_printf("[%s:%d] -->bank2: linuxAddr:%x, regVal:%x, failed:%d, round:%d\n", __FUNCTION__, __LINE__, linuxAddr, regVal, failed, round);
		REG32(BSP_DUMMY_REG_BANK2_BOOTSTATUS) = ( BOOTFAIL_CHECK_BIT_ISBOOTING | (round&(~BOOTFAIL_CHECK_BIT_ISBOOTING)) );
	}else
#endif
	{
		//prom_printf("[%s:%d] -->bank1: linuxAddr:%x, regVal:%x, failed:%d, round:%d\n", __FUNCTION__, __LINE__, linuxAddr, regVal, failed, round);
		REG32(BSP_DUMMY_REG_BANK1_BOOTSTATUS) = ( BOOTFAIL_CHECK_BIT_ISBOOTING | (round&(~BOOTFAIL_CHECK_BIT_ISBOOTING)) );
	}
}
#endif/*CONFIG_BOOT_FAIL_CHECK*/

//------------------------------------------------------------------------------------------

//------------------------------------------------------------------------------------------
//check img
unsigned int gCHKKEY_HIT=0;
unsigned int gCHKKEY_CNT=0;
#if defined(CONFIG_NFBI)
// return,  0: not found, 1: linux found, 2:linux with root found
int check_system_image(unsigned long addr,IMG_HEADER_Tp pHeader)
{
	// Read header, heck signature and checksum
	int i, ret=0;
	unsigned short sum=0, *word_ptr;
	unsigned short length=0;
	unsigned short temp16=0;

	if(gCHKKEY_HIT==1)	return 0;
	
    	/*check firmware image.*/
	word_ptr = (unsigned short *)pHeader;
	for (i=0; i<sizeof(IMG_HEADER_T); i+=2, word_ptr++)
		*word_ptr = *((unsigned short *)(addr + i));

	if (!memcmp(pHeader->signature, FW_SIGNATURE, SIG_LEN))
		ret=1;
	else if  (!memcmp(pHeader->signature, FW_SIGNATURE_WITH_ROOT, SIG_LEN))
		ret=2;
	else 
		dprintf("no sys signature at %X!\n",addr);
#if defined(NEED_CHKSUM)	
	if (ret) {
		for (i=0; i<pHeader->len; i+=2) {
			sum += *((unsigned short *)(addr + sizeof(IMG_HEADER_T) + i));
			//prom_printf("x=%x\n", (addr + sizeof(IMG_HEADER_T) + i));
		}

		if ( sum ) {
			//SYSSR: checksum done, but fail
			REG32(NFBI_SYSSR)= (REG32(NFBI_SYSSR)|0x8000) & (~0x4000);
			dprintf("sys checksum error at %X!\n",addr);
			ret=0;
		}
		else {
			//SYSSR: checksum done and OK
			REG32(NFBI_SYSSR)= REG32(NFBI_SYSSR) | 0xc000;
		}
	}
#else
	//SYSSR: checksum done and OK
	REG32(NFBI_SYSSR)= REG32(NFBI_SYSSR) | 0xc000;
#endif
	return (ret);
}

#elif defined(CONFIG_NONE_FLASH)
// return,  0: not found, 1: linux found, 2:linux with root found
int check_system_image(unsigned long addr,IMG_HEADER_Tp pHeader)
{
	// Read header, heck signature and checksum
	int i, ret=0;
	unsigned short sum=0, *word_ptr;
	unsigned short length=0;
	unsigned short temp16=0;

	if(gCHKKEY_HIT==1)	return 0;
	
    	/*check firmware image.*/
	word_ptr = (unsigned short *)pHeader;
	for (i=0; i<sizeof(IMG_HEADER_T); i+=2, word_ptr++)
		*word_ptr = *((unsigned short *)(addr + i));

	if (!memcmp(pHeader->signature, FW_SIGNATURE, SIG_LEN))
		ret=1;
	else if  (!memcmp(pHeader->signature, FW_SIGNATURE_WITH_ROOT, SIG_LEN))
		ret=2;
	else 
		dprintf("no sys signature at %X!\n",addr);
#if defined(NEED_CHKSUM)	
	if (ret) {
		for (i=0; i<pHeader->len; i+=2) {
			sum += *((unsigned short *)(addr + sizeof(IMG_HEADER_T) + i));
			//prom_printf("x=%x\n", (addr + sizeof(IMG_HEADER_T) + i));
		}

		if ( sum ) {
			//SYSSR: checksum done, but fail
			
			dprintf("sys checksum error at %X!\n",addr);
			ret=0;
		}
		else {
			//SYSSR: checksum done and OK
			
		}
	}
#else
	
#endif
	return (ret);
}

#else
#if CHECK_BURN_SERIAL
unsigned long board_rootfs_length=0;
IMG_HEADER_T linux_imghdr;

/* return 0:fail, 2:success, 1: no  burn_serial */
int check_burn_serial(unsigned long addr, IMG_HEADER_Tp pHeader)
{
	int ret = 0;

	if ((pHeader->burnAddr & (1<<31))) {
		unsigned long pad;
		memcpy((void *)(&pad), addr, sizeof(unsigned long));
		BDBG_BSN("\tburnAddr=0x%08x, pad=0x%08x", pHeader->burnAddr, pad);
		if (pHeader->burnAddr == pad) {
			BDBG_BSN(", ok\n");
			ret = 2;
		}
	}
	else {
		BDBG_BSN("\tfail\n");
		ret = 1;
	}

	return ret;
}
#endif
// return,  0: not found, 1: linux found, 2:linux with root found
int check_system_image(unsigned long addr,IMG_HEADER_Tp pHeader,SETTING_HEADER_Tp setting_header)
{
	// Read header, heck signature and checksum
	int i, ret=0;
	unsigned short sum=0;
	unsigned long read=0;
	unsigned short temp16=0;
	char image_sig_check[1]={0};
	char image_sig[4]={0};
	char image_sig_root[4]={0};
	char buf[256];
	
	if(gCHKKEY_HIT==1)
		return 0;

#ifdef CONFIG_NAND_FLASH_BOOTING
	if(nflashread((unsigned int)pHeader,addr,sizeof(IMG_HEADER_T),0)< 0){
		prom_printf("nand flash read fail,addr=%x,size=%d\n",addr,sizeof(IMG_HEADER_T));
		return 0;
	}
#else
        /*check firmware image.*/
	if(!flashread((unsigned long) pHeader, addr, sizeof(IMG_HEADER_T))) {
		prom_printf("SPI flash read fail,addr=%x,size=%d ------> %s line %d!\n",addr,sizeof(IMG_HEADER_T), __FUNCTION__, __LINE__);
		return 0;
	}
#endif

	pHeader->startAddr = ___swab32(pHeader->startAddr);
	pHeader->burnAddr = ___swab32(pHeader->burnAddr);
	pHeader->len = ___swab32(pHeader->len);

	memcpy(image_sig, FW_SIGNATURE, SIG_LEN);
	memcpy(image_sig_root, FW_SIGNATURE_WITH_ROOT, SIG_LEN);

	if (!memcmp(pHeader->signature, image_sig, SIG_LEN))
		ret=1;
	else if  (!memcmp(pHeader->signature, image_sig_root, SIG_LEN))
		ret=2;
	else{
		prom_printf("no sys signature at %X!\n",addr-FLASH_BASE);
	}		
	//prom_printf("ret=%d  sys signature at %X!\n",ret,addr-FLASH_BASE);
	
#if CHECK_BURN_SERIAL
	if (ret) {
		int ret_val = 0;
		BDBG_BSN("==> check linux:\n");
		BDBG_BSN("\tby burn_serial\n");

		memcpy((void *)(&linux_imghdr), (void *)(pHeader), sizeof(IMG_HEADER_T));
#ifndef CONFIG_NAND_FLASH_BOOTING
		ret_val = check_burn_serial(addr+mips_io_port_base+sizeof(IMG_HEADER_T)+pHeader->len, pHeader);
#else
		/* for nand */
		goto SKIP_CHECK_BURN_SERIAL;
#endif
		if (ret_val != 1)
			return ret_val;
	}
	BDBG_BSN("\n\tno burn_serial, check by sum\n");

SKIP_CHECK_BURN_SERIAL:
#endif
	
	if (ret) {
#if defined(CONFIG_RTK_LINUX_SECURE)
		int ret_sig = 1;
		unsigned int len;
		unsigned int sig_addr;

		if (user_interrupt(0) == 1)  //got ESC Key
			return 0;

		sig_addr = pHeader->startAddr - 0x200; //just keep linux on correct memory offset
		flashread(sig_addr|0x20000000, (unsigned int)(addr + sizeof(IMG_HEADER_T)), 0x40);
		unsigned char sig[64];
		int i = 0;
		for( i = 0; i < 64; i++) {
			sig[i] = *(char*)(sig_addr + i);
		}

		len = pHeader->len - 2 -0x40;
		flashread(pHeader->startAddr|0x20000000, (unsigned int)(addr + sizeof(IMG_HEADER_T) + 0x40), len);

		ret_sig = verify_signature(1, pHeader->startAddr, len, sig);
		if (ret_sig != 0) {
			prom_printf("\nERROR: verify Linux image fail\n\n");
			ret = 0;
		} else {
			prom_printf("Linux verified\n\n");
		}

		if (user_interrupt(0) == 1)  //got ESC Key
			return 0;

		return ret; //no need checksum
#endif

#ifdef CONFIG_NAND_FLASH_BOOTING
#if defined(CONFIG_RTL_FAST_CHECKSUM_ENABLE) && defined(CONFIG_FLASH_SIZE)
			int total_bank = 1;
			FASTCKSUM_HEADER_Tp fastcksum_hdr = NULL;
			FASTCKSUM_PAYLOAD_Tp fastcksum_body = NULL;
			int fastcksum_buf_size = 0;
			unsigned int new_checksum = 0;
			short old_checksum = 0;
			
			//init structure
#ifdef CONFIG_RTL_FLASH_DUAL_IMAGE_ENABLE
			total_bank = 2;
#endif
			fastcksum_buf_size = sizeof(FASTCKSUM_HEADER_T) + total_bank*sizeof(FASTCKSUM_PAYLOAD_T);
			fastcksum_hdr = (FASTCKSUM_HEADER_Tp)malloc( fastcksum_buf_size );
			if(NULL==fastcksum_hdr)
			{
				prom_printf("cannot malloc for fastcksum_hdr, abandon upgrade!!!\n");
				return 0;
			}
			memset(fastcksum_hdr, 0x0, fastcksum_buf_size);
			fastcksum_body = (FASTCKSUM_PAYLOAD_Tp)fastcksum_hdr->payload;	//first bank initially
#ifdef CONFIG_RTL_FLASH_DUAL_IMAGE_ENABLE
			if(addr>CONFIG_RTL_FLASH_DUAL_IMAGE_OFFSET)
			{
				FCS_DBG("move to second bank!\n");
				fastcksum_body++;	//second bank
			}
#endif

			//read from flash to structure
			if(FASTCKSUM_FAILED==read_fastcksum_from_flash((unsigned char *)fastcksum_hdr, fastcksum_buf_size))
			{
				prom_printf("cannot read flash data for fastcksum_hdr, abandon upgrade!!!\n");
				free(fastcksum_hdr);
				return 0;
			}
			if(fastcksum_hdr->len != (fastcksum_buf_size-sizeof(FASTCKSUM_HEADER_T)))
			{
				FCS_DBG("WARNING: fastcksum_hdr->len is updated!!! Old:%d, new:%d, sizeof(FASTCKSUM_PAYLOAD_T):%d, total_bank:%d\n", fastcksum_hdr->len, fastcksum_buf_size-sizeof(FASTCKSUM_HEADER_T), sizeof(FASTCKSUM_PAYLOAD_T), total_bank);
				fastcksum_hdr->len = fastcksum_buf_size-sizeof(FASTCKSUM_HEADER_T);
			}
			FCS_DBG("[%s:%d]addr: 0x%x, fastcksum_hdr:0x%x, fastcksum_body:0x%x, fastcksum_hdr->payload:0x%\n", __FUNCTION__, __LINE__, addr, fastcksum_hdr, fastcksum_body, fastcksum_hdr->payload);
			dump_fastcksum_struct(fastcksum_hdr);

			//check linux_sig
			if(memcmp(fastcksum_body->linux_sig, pHeader->signature, SIG_LEN))
			{
				prom_printf("ERROR: linux_sig mismatches!!! %02x%02x%02x%02x : %02x%02x%02x%02x\n", fastcksum_body->linux_sig[0], fastcksum_body->linux_sig[1], 
					fastcksum_body->linux_sig[2], fastcksum_body->linux_sig[3], pHeader->signature[0], pHeader->signature[1], pHeader->signature[2], pHeader->signature[3]);
				free(fastcksum_hdr);
				return 0;
			}else{
				prom_printf("linux_sig check: OK\n");
			}

			//check linux_cksum
			{
				int cal_cksum = 0;
				int linux_len = ___swab32(pHeader->len);	//yes, we need to swab again, revert to value in flash.
				int linux_cksum_offset = 0;
				unsigned short linux_cksum = 0;

				//read the old checksum in linux partition
				linux_cksum_offset = sizeof(IMG_HEADER_T) + pHeader->len - SIZE_OF_CHECKSUM;
				if(nflashread((unsigned long)&linux_cksum, addr+linux_cksum_offset, SIZE_OF_CHECKSUM, 0)< 0){
					prom_printf("[%s:%d]nand flash read fail,addr=%x, linux_cksum_offset=%x, size=%d\n", __FUNCTION__, __LINE__, addr, linux_cksum_offset, SIZE_OF_CHECKSUM);
					free(fastcksum_hdr);
					return 0;
				}
				FCS_DBG("linux_len:%x, linux_cksum: %x\n", linux_len, linux_cksum);
				//calculate fast checksum
				if(FASTCKSUM_FAILED == gen_fastcksum(&cal_cksum, linux_len, linux_cksum))
				{
					prom_printf("[%s:%d]gen_fastcksum fail\n", __FUNCTION__, __LINE__);
					free(fastcksum_hdr);
					return 0;
				}
				FCS_DBG("cal_cksum:%x, fastcksum_body->linux_cksum:%x\n", cal_cksum, fastcksum_body->linux_cksum);
				if(cal_cksum!=fastcksum_body->linux_cksum)
				{
					prom_printf("ERROR: linux_cksum mismatches!!!\n");
					free(fastcksum_hdr);
					return 0;
				}else{
					prom_printf("linux_cksum check: OK\n");
				}
			}

			//check linux_valid
			FCS_DBG("fastcksum_body->reserved:%x\n", fastcksum_body->reserved);
			if(fastcksum_body->reserved&RTL_FASTCKSUM_FIELD_LINUX_VALID==0)
			{
				prom_printf("ERROR: linux.bin cracked!!!\n");
				free(fastcksum_hdr);
				return 0;
			}else{
				prom_printf("linux.bin check: OK\n");
			}

			//house keeping
			if(fastcksum_hdr)
				free(fastcksum_hdr);
			
#else /* !defined(CONFIG_NAND_FLASH_BOOTING) */
			volatile unsigned char *ptr_data = (volatile unsigned char *)DRAM_DIMAGE_ADDR;
			if(nflashread(DRAM_DIMAGE_ADDR,addr,pHeader->len+sizeof(IMG_HEADER_T),1) < 0){
				prom_printf("nand flash read fail,addr=%x,size=%d\n",addr,pHeader->len+sizeof(IMG_HEADER_T));
				return 0;
			}
			#if 1//def CONFIG_RTK_NAND_BBT
			for (i=0; i<pHeader->len; i+=2){
                 #if CONFIG_ESD_SUPPORT//patch for ESD
                  	 REG32(0xb800311c)|= (1<<23);
                 #endif
			
				#if defined(NEED_CHKSUM)	
				sum +=((unsigned short)(((*(ptr_data+1+i+ sizeof(IMG_HEADER_T)))|(*(ptr_data+i+ sizeof(IMG_HEADER_T)))<<8)&0xffff));
				//sum += rtl_inw(ptr_data + sizeof(IMG_HEADER_T) + i);
				#endif
			
			}
			#endif
#endif
#else
		while(pHeader->len - read > 0){
#if 1  //slowly
			gCHKKEY_CNT++;
			if( gCHKKEY_CNT>ACCCNT_TOCHKKEY)
			{	gCHKKEY_CNT=0;
				if ( user_interrupt(0)==1 )  //return 1: got ESC Key
				{
					//prom_printf("ret=%d  ------> line %d!\n",ret,__LINE__);
					return 0;
				}
			}
#else  //speed-up, only support UART, not support GPIO
			if((Get_UART_Data()==ESC)  || (Get_GPIO_SW_IN()!=0))
			{	gCHKKEY_HIT=1; 
				return 0;
			}
#endif
#if defined(NEED_CHKSUM)	
			unsigned long num = (pHeader->len - read > sizeof(buf)) ? sizeof(buf) : pHeader->len - read;
			flashread((unsigned long) buf, addr + sizeof(IMG_HEADER_T) + read, num);
			for(i = 0; i < num; i+=2)
				sum += ___swab16(READ_MEM16(buf + i));
			read += num;	
#endif
		}	
#endif

#if defined(NEED_CHKSUM)			
		if ( sum ) {
			prom_printf("ret=%d,sum=%x  ------> line %d!\n",ret,sum,__LINE__);
			ret=0;
		}
#endif		
	}
	//prom_printf("ret=%d  sys signature at %X!\n",ret,addr-FLASH_BASE);

	return (ret);
}
//------------------------------------------------------------------------------------------

#if 1//ndef CONFIG_DECREASE_BOOTSIZE  //ecos image no need check rootfs
int check_rootfs_image(unsigned long addr)
{
#ifdef CONFIG_SD_CARD_BOOTING
	return 1;
#endif
#ifdef CONFIG_RTK_VOIP
    // Don't check rootfs in voip
         return 1;
#else    
	// Read header, heck signature and checksum
	int i;
	unsigned short sum=0;
	unsigned long length=0, read=0;
	unsigned char tmpbuf[256];	
	
	if(gCHKKEY_HIT==1)
		return 0;

#ifdef CONFIG_NAND_FLASH_BOOTING
	if(nflashread((unsigned int)tmpbuf,addr,16,0)< 0){
		prom_printf("nand flash read fail,addr=%x,size=%d\n",addr,16);
		return 0;
	}			
#else
	if(!flashread((unsigned long) tmpbuf, addr, 16)){
		prom_printf("SPI flash read fail,addr=%x,size=%d ------> %s line %d!\n",addr,sizeof(IMG_HEADER_T), __FUNCTION__, __LINE__);
		return 0;
	}
#endif

	if ( memcmp(tmpbuf, SQSH_SIGNATURE, SIG_LEN) && memcmp(tmpbuf, SQSH_SIGNATURE_LE, SIG_LEN)) {
		prom_printf("no rootfs signature at %X!\n",addr-FLASH_BASE);
		return 0;
	}

#if CHECK_BURN_SERIAL
	board_rootfs_length =
#endif

	length = ___swab32(*(((unsigned long *)tmpbuf) + OFFSET_OF_LEN)) + SIZE_OF_SQFS_SUPER_BLOCK + SIZE_OF_CHECKSUM;

#if defined(CONFIG_RTK_ROOTFS_SECURE)
	int ret_sig = 1;
	unsigned int len;
	unsigned int sig_addr;
	unsigned int rootfs_check_addr = 0x80700000;

	if (user_interrupt(0) == 1)  //return 1: got ESC Key
		return 0;

	flashread( rootfs_check_addr|0x20000000, (unsigned int)addr, length);
	sig_addr = rootfs_check_addr + length - 0x40 - 2;
	unsigned char sig[64];
	for( i = 0; i < 64; i++) {
		sig[i] = *(char*)(sig_addr + i);
	}

	len = length - 0x40 - 2;
	ret_sig = verify_signature(2, rootfs_check_addr, len, sig);
	if (ret_sig != 0) {
		prom_printf("\nERROR: verify rootfs image fail\n\n");
		return 0; //no need checksum
	} else {
		prom_printf("rootfs verified\n\n");
		return 1; //no need checksum
	}
	if (user_interrupt(0) == 1)  //return 1: got ESC Key
		return 0;
#endif

#if CHECK_BURN_SERIAL
{
	struct _rootfs_padding rootfs_padding;
	BDBG_BSN("==> check rootfs:\n");
	BDBG_BSN("\tby burn_serial\n");

#ifndef CONFIG_NAND_FLASH_BOOTING
	memcpy((void *)(&rootfs_padding)+sizeof(rootfs_padding.zero_pad), (void *)(mips_io_port_base + addr + length - SIZE_OF_CHECKSUM), sizeof(struct _rootfs_padding)-sizeof(rootfs_padding.zero_pad));
#else
	/* nand */
	goto SKIP_CHECK_BURN_SERIAL;
#endif

	BDBG_BSN("\trootfs_padding.signature[%s]\n", rootfs_padding.signature);
	if (!memcmp(rootfs_padding.signature, ROOT_SIGNATURE, SIG_LEN)) {
		BDBG_BSN("\tburn_serial=0x%08x, length=0x%08x",
			rootfs_padding.len + SIZE_OF_SQFS_SUPER_BLOCK + SIZE_OF_CHECKSUM, length);

		if (rootfs_padding.len + SIZE_OF_SQFS_SUPER_BLOCK + SIZE_OF_CHECKSUM == length) {
			BDBG_BSN(", ok\n");
			return 1;
		}
		else {
			BDBG_BSN(", fail\n");
			return 0;
		}
	}
	BDBG_BSN("\n\tno burn_serial, check by sum\n");
}

SKIP_CHECK_BURN_SERIAL:
#endif
#ifdef CONFIG_NAND_FLASH_BOOTING
#if defined(CONFIG_RTL_FAST_CHECKSUM_ENABLE) && defined(CONFIG_FLASH_SIZE)
	{
		int total_bank = 1;
		FASTCKSUM_HEADER_Tp fastcksum_hdr = NULL;
		FASTCKSUM_PAYLOAD_Tp fastcksum_body = NULL;
		int fastcksum_buf_size = 0;
		unsigned int new_checksum = 0;
		short old_checksum = 0;
		
		//init structure
#ifdef CONFIG_RTL_FLASH_DUAL_IMAGE_ENABLE
		total_bank = 2;
#endif
		fastcksum_buf_size = sizeof(FASTCKSUM_HEADER_T) + total_bank*sizeof(FASTCKSUM_PAYLOAD_T);
		fastcksum_hdr = (FASTCKSUM_HEADER_Tp)malloc( fastcksum_buf_size );
		if(NULL==fastcksum_hdr)
		{
			prom_printf("cannot malloc for fastcksum_hdr, abandon upgrade!!!\n");
			return 0;
		}
		memset(fastcksum_hdr, 0x0, fastcksum_buf_size);
		fastcksum_body = (FASTCKSUM_PAYLOAD_Tp)fastcksum_hdr->payload;	//first bank initially
#ifdef CONFIG_RTL_FLASH_DUAL_IMAGE_ENABLE
		if(addr>CONFIG_RTL_FLASH_DUAL_IMAGE_OFFSET)
		{
			FCS_DBG("move to second bank!\n");
			fastcksum_body++;	//second bank
		}
#endif

		//read from flash to structure
		if(FASTCKSUM_FAILED==read_fastcksum_from_flash((unsigned char *)fastcksum_hdr, fastcksum_buf_size))
		{
			prom_printf("cannot read flash data for fastcksum_hdr, abandon upgrade!!!\n");
			free(fastcksum_hdr);
			return 0;
		}
		if(fastcksum_hdr->len != (fastcksum_buf_size-sizeof(FASTCKSUM_HEADER_T)))
		{
			FCS_DBG("WARNING: fastcksum_hdr->len is updated!!! Old:%d, new:%d, sizeof(FASTCKSUM_PAYLOAD_T):%d, total_bank:%d\n", fastcksum_hdr->len, fastcksum_buf_size-sizeof(FASTCKSUM_HEADER_T), sizeof(FASTCKSUM_PAYLOAD_T), total_bank);
			fastcksum_hdr->len = fastcksum_buf_size-sizeof(FASTCKSUM_HEADER_T);
		}
		FCS_DBG("[%s:%d]addr: 0x%x, fastcksum_hdr:0x%x, fastcksum_body:0x%x, fastcksum_hdr->payload:0x%\n", __FUNCTION__, __LINE__, addr, fastcksum_hdr, fastcksum_body, fastcksum_hdr->payload);
		dump_fastcksum_struct(fastcksum_hdr);

		//check root_sig
		if(memcmp(fastcksum_body->root_sig, tmpbuf, SIG_LEN))
		{
			prom_printf("ERROR: root_sig mismatches!!! %02x%02x%02x%02x : %02x%02x%02x%02x\n", fastcksum_body->root_sig[0], fastcksum_body->root_sig[1], 
				fastcksum_body->root_sig[2], fastcksum_body->root_sig[3], tmpbuf[0], tmpbuf[1], tmpbuf[2], tmpbuf[3]);
			free(fastcksum_hdr);
			return 0;
		}else{
			prom_printf("root_sig check: OK\n");
		}

		//check root_cksum
		{
			int cal_cksum = 0;
			int root_len = *(((unsigned long *)tmpbuf) + OFFSET_OF_LEN);	//keep the same order as flash stores
			int root_cksum_offset = 0;
			unsigned short root_cksum = 0;

			//read the old checksum in root partition
			root_cksum_offset = ___swab32(root_len) + SIZE_OF_SQFS_SUPER_BLOCK;
			if(nflashread((unsigned long)&root_cksum, addr+root_cksum_offset, SIZE_OF_CHECKSUM, 0)< 0){
				prom_printf("[%s:%d]nand flash read fail,addr=%x, root_cksum_offset=%x, size=%d\n", __FUNCTION__, __LINE__, addr, root_cksum_offset, SIZE_OF_CHECKSUM);
				free(fastcksum_hdr);
				return 0;
			}
			FCS_DBG("root_len:%x, root_cksum: %x\n", root_len, root_cksum);
			//calculate fast checksum
			if(FASTCKSUM_FAILED == gen_fastcksum(&cal_cksum, root_len, root_cksum))
			{
				prom_printf("[%s:%d]gen_fastcksum fail\n", __FUNCTION__, __LINE__);
				free(fastcksum_hdr);
				return 0;
			}
			FCS_DBG("cal_cksum:%x, fastcksum_body->root_cksum:%x\n", cal_cksum, fastcksum_body->root_cksum);
			if(cal_cksum!=fastcksum_body->root_cksum)
			{
				prom_printf("ERROR: root_cksum mismatches!!!\n");
				free(fastcksum_hdr);
				return 0;
			}else{
				prom_printf("root_cksum check: OK\n");
			}
		}

		//check root_valid
		FCS_DBG("fastcksum_body->reserved:%x\n", fastcksum_body->reserved);
		if(fastcksum_body->reserved&RTL_FASTCKSUM_FIELD_ROOT_VALID==0)
		{
			prom_printf("ERROR: root.bin cracked!!!\n");
			free(fastcksum_hdr);
			return 0;
		}else{
			prom_printf("root.bin check: OK\n");
		}

		//house keeping
		if(fastcksum_hdr)
			free(fastcksum_hdr);
	}			
#else /* !defined(CONFIG_NAND_FLASH_BOOTING) */
			volatile unsigned char *ptr_data = (volatile unsigned char *)DRAM_DIMAGE_ADDR;
			if(nflashread(DRAM_DIMAGE_ADDR,addr,length,1) < 0){
				prom_printf("nand flash read fail,addr=%x,size=%d\n",addr,length);
				return 0;
			}
			#if 1//def CONFIG_RTK_NAND_BBT
			for (i=0; i<length; i+=2){
                 #if CONFIG_ESD_SUPPORT//patch for ESD
                  	 REG32(0xb800311c)|= (1<<23);
                  #endif
			
				#if defined(NEED_CHKSUM)	
				sum +=((unsigned short)(((*(ptr_data+1+i))|((*(ptr_data+i))<<8))&0xffff));
				//sum += rtl_inw(ptr_data + sizeof(IMG_HEADER_T) + i);
				#endif
			
			}
			#endif
#endif	
#else

	while(length - read > 0) {
#if 1  //slowly
                 #if CONFIG_ESD_SUPPORT//patch for ESD
                  	 REG32(0xb800311c)|= (1<<23);
                  #endif
			gCHKKEY_CNT++;
			if( gCHKKEY_CNT>ACCCNT_TOCHKKEY)
			{	gCHKKEY_CNT=0;
				if ( user_interrupt(0)==1 )  //return 1: got ESC Key
					return 0;
			}
#else  //speed-up, only support UART, not support GPIO.
			if((Get_UART_Data()==ESC)  || (Get_GPIO_SW_IN()!=0))
			{	gCHKKEY_HIT=1; 
				return 0;
			}
#endif			
#if defined(NEED_CHKSUM)
		unsigned long num = (length - read > sizeof(tmpbuf)) ? sizeof(tmpbuf) : length - read;
		flashread((unsigned long) tmpbuf, addr + read, num);
		for(i = 0; i < num; i+=2)
			sum += ___swab16(READ_MEM16(tmpbuf + i));
		read += num;
#endif
	}
#endif

#if defined(NEED_CHKSUM)		
	if ( sum ) {
		prom_printf("rootfs checksum error at %X!\n",addr-FLASH_BASE);
		return 0;
	}	
#endif	
	return 1;
#endif //CONFIG_RTK_VOIP
}
#endif

#if defined(CONFIG_WEBPAGE_BACKUP)
int check_webpage_image(unsigned long addr)
{
	int i, ret=0;
	unsigned char sum=0;
	unsigned short *word_ptr;
	unsigned short length=0;
	unsigned short temp16=0;
	IMG_HEADER_T pHeader;
	char	image_web[4] = {0};



#ifdef CONFIG_NAND_FLASH_BOOTING
	if(nflashread((unsigned int)&pHeader,addr,sizeof(IMG_HEADER_T),0)< 0){
		prom_printf("nand flash read fail,addr=%x,size=%d\n",addr,sizeof(IMG_HEADER_T));
		return 0;
	}
			
#else
	word_ptr = (unsigned short *)&pHeader;
	for (i=0; i<sizeof(IMG_HEADER_T); i+=2, word_ptr++)
		*word_ptr = READ_MEM16(addr + i);	
#endif

	memcpy(image_web,WEBPAGE_SIGNATURE,SIG_LEN);
	if (!memcmp(pHeader.signature, image_web, SIG_LEN))
		ret=1;
	else{
		prom_printf("no webpage signature at %X!\n",addr-FLASH_BASE);
	}
#ifdef CONFIG_NAND_FLASH_BOOTING
			unsigned char *ptr_data = (volatile unsigned char *)DRAM_DIMAGE_ADDR;
			if(nflashread(DRAM_DIMAGE_ADDR,addr,pHeader->len+sizeof(IMG_HEADER_T),1) < 0){
				prom_printf("nand flash read fail,addr=%x,size=%d\n",addr,pHeader->len+sizeof(IMG_HEADER_T));
				return 0;
			}
			#if 1//def CONFIG_RTK_NAND_BBT
			for (i=0; i<pHeader->len; i++){
                 #if CONFIG_ESD_SUPPORT//patch for ESD
                  	 REG32(0xb800311c)|= (1<<23);
                  #endif
			
				#if defined(NEED_CHKSUM)	
				sum +=(unsigned char)(((*(ptr_data+1+i+ sizeof(IMG_HEADER_T)))|(*(ptr_data+i+ sizeof(IMG_HEADER_T)))<<8)&0xffff);
				//sum += rtl_inw(ptr_data + sizeof(IMG_HEADER_T) + i);
				#endif
			
			}
			#endif
			
#else
	if (ret) {
		for (i=0; i<pHeader.len; i++){
		#if defined(NEED_CHKSUM)
			sum += READ_MEM8(addr+sizeof(IMG_HEADER_T)+i);
		#endif
		}
	}
#endif

#if defined(NEED_CHKSUM)
	if(sum){
		prom_printf("webpage checksum error at %X!\n",addr-FLASH_BASE);
		ret = 0;
	}
#endif
		
	return ret;
}
#endif
//------------------------------------------------------------------------------------------

static int check_image_header(IMG_HEADER_Tp pHeader,SETTING_HEADER_Tp psetting_header,unsigned long bank_offset)
{
	int i,ret=0;
#ifdef __DAVO__
# if NEED_CHKSUM
	need_cksum = !NEED_CHKSUM;
# endif
	if (psetting_header->root_offset) {

		return_addr = (unsigned long)FLASH_BASE + psetting_header->kern_offset;
		ret = check_system_image(return_addr, pHeader, psetting_header);
		if (ret == 2 && (ret = check_rootfs_image((unsigned long)FLASH_BASE + psetting_header->root_offset))) {
# if NEED_CHKSUM
			need_cksum = NEED_CHKSUM;
# endif
			return ret;
		}
	}
# if NEED_CHKSUM
	need_cksum = NEED_CHKSUM;
# endif
#endif

#ifndef CONFIG_NAND_FLASH_BOOTING
	//flash mapping
	return_addr = (unsigned long)FLASH_BASE+CODE_IMAGE_OFFSET+bank_offset;
	ret = check_system_image((unsigned long)FLASH_BASE+CODE_IMAGE_OFFSET+bank_offset,pHeader, psetting_header);

	if(ret==0) {
		return_addr = (unsigned long)FLASH_BASE+CODE_IMAGE_OFFSET2+bank_offset;		
		ret=check_system_image((unsigned long)FLASH_BASE+CODE_IMAGE_OFFSET2+bank_offset,  pHeader, psetting_header);
	}
	if(ret==0) {
		return_addr = (unsigned long)FLASH_BASE+CODE_IMAGE_OFFSET3+bank_offset;				
		ret=check_system_image((unsigned long)FLASH_BASE+CODE_IMAGE_OFFSET3+bank_offset,  pHeader, psetting_header);
	}			
#endif

#ifdef CONFIG_RTL_FLASH_MAPPING_ENABLE	
	i=CONFIG_LINUX_IMAGE_OFFSET_START;	
	while(i<=CONFIG_LINUX_IMAGE_OFFSET_END && (0==ret))
	{
		return_addr=(unsigned long)FLASH_BASE+i+bank_offset; 
	#if ((CODE_IMAGE_OFFSET >= CONFIG_LINUX_IMAGE_OFFSET_START) || \
		(CODE_IMAGE_OFFSET2 >= CONFIG_LINUX_IMAGE_OFFSET_START) || \
		(CODE_IMAGE_OFFSET3 >= CONFIG_LINUX_IMAGE_OFFSET_START)) 
			/*<Coverity: DEADCODE> 
				CONFIG_LINUX_IMAGE_OFFSET_START is lager than CODE_IMAGE_OFFSET/
				CODE_IMAGE_OFFSET2/CODE_IMAGE_OFFSET3
			*/
		if(CODE_IMAGE_OFFSET == i || CODE_IMAGE_OFFSET2 == i || CODE_IMAGE_OFFSET3 == i){
			i += CONFIG_LINUX_IMAGE_OFFSET_STEP; 
			continue;
		}
	#endif
		ret = check_system_image((unsigned long)FLASH_BASE+i+bank_offset, pHeader, psetting_header);
		i += CONFIG_LINUX_IMAGE_OFFSET_STEP; 
	}
#endif

#if 1//ndef CONFIG_DECREASE_BOOTSIZE
	if(ret==2)
        {
#ifndef CONFIG_NAND_FLASH_BOOTING
                ret=check_rootfs_image((unsigned long)FLASH_BASE+ROOT_FS_OFFSET+bank_offset);
                if(ret==0)
                	ret=check_rootfs_image((unsigned long)FLASH_BASE+ROOT_FS_OFFSET+ROOT_FS_OFFSET_OP1+bank_offset);
                if(ret==0)
                	ret=check_rootfs_image((unsigned long)FLASH_BASE+ROOT_FS_OFFSET+ROOT_FS_OFFSET_OP1+ROOT_FS_OFFSET_OP2+bank_offset);
#else
				ret = 0;
#endif	
#ifdef CONFIG_RTL_FLASH_MAPPING_ENABLE
		i = CONFIG_ROOT_IMAGE_OFFSET_START;
		while((i <= CONFIG_ROOT_IMAGE_OFFSET_END) && (0==ret))
		{
		#if ((ROOT_FS_OFFSET >= CONFIG_ROOT_IMAGE_OFFSET_START) || \
			((ROOT_FS_OFFSET + ROOT_FS_OFFSET_OP1) >= CONFIG_ROOT_IMAGE_OFFSET_START) || \
			((ROOT_FS_OFFSET + ROOT_FS_OFFSET_OP1 + ROOT_FS_OFFSET_OP2) >= CONFIG_ROOT_IMAGE_OFFSET_START))
				/*<Coverity: DEADCODE> 
					CONFIG_ROOT_IMAGE_OFFSET_START is lager than ROOT_FS_OFFSET/
					(ROOT_FS_OFFSET + ROOT_FS_OFFSET_OP1)/
					(ROOT_FS_OFFSET + ROOT_FS_OFFSET_OP1 + ROOT_FS_OFFSET_OP2)
				*/
			if( ROOT_FS_OFFSET == i ||
			    (ROOT_FS_OFFSET + ROOT_FS_OFFSET_OP1) == i ||
		            (ROOT_FS_OFFSET + ROOT_FS_OFFSET_OP1 + ROOT_FS_OFFSET_OP2) == i){
				i += CONFIG_ROOT_IMAGE_OFFSET_STEP;
				continue;
			}
		#endif
			ret = check_rootfs_image((unsigned long)FLASH_BASE+i+bank_offset);
			i += CONFIG_ROOT_IMAGE_OFFSET_STEP;
		}
#endif
#if defined(CONFIG_WEBPAGE_BACKUP)
		if(ret)
		{
#ifndef CONFIG_NAND_FLASH_BOOTING
			ret=check_webpage_image((unsigned long)FLASH_BASE+WEBPAGE_OFFSET+bank_offset);
            if(ret==0)
            	ret=check_webpage_image((unsigned long)FLASH_BASE+WEBPAGE_OFFSET+WEBPAGE_OFFSET_OP1+bank_offset);
            if(ret==0)
            	ret=check_webpage_image((unsigned long)FLASH_BASE+WEBPAGE_OFFSET+WEBPAGE_OFFSET_OP1+WEBPAGE_OFFSET_OP2+bank_offset);
#endif

#ifdef CONFIG_RTL_FLASH_MAPPING_ENABLE
		i = CONFIG_WEBPAGE_IMAGE_OFFSET_START;
		while((i <= CONFIG_WEBPAGE_IMAGE_OFFSET_END) && (0==ret))
		{
			if( ROOT_FS_OFFSET == i ||
			    (ROOT_FS_OFFSET + ROOT_FS_OFFSET_OP1) == i ||
		            (ROOT_FS_OFFSET + ROOT_FS_OFFSET_OP1 + ROOT_FS_OFFSET_OP2) == i){
				i += CONFIG_WEBPAGE_IMAGE_OFFSET_STEP;
				continue;
			}
			ret = check_webpage_image((unsigned long)FLASH_BASE+i+bank_offset);
			i += CONFIG_WEBPAGE_IMAGE_OFFSET_STEP;
		}
#endif
			
		}
#endif

	}
#endif
	return ret;
}
//------------------------------------------------------------------------------------------

#ifdef CONFIG_RTL_FLASH_DUAL_IMAGE_ENABLE	

int get_system_header(unsigned long addr, IMG_HEADER_Tp pImgHdr)
{
	unsigned short *word_ptr;
	char image_sig[4] = {0};
	char image_sig_root[4] = {0};
	int  i;

#ifdef CONFIG_NAND_FLASH_BOOTING
	if(nflashread((unsigned int)pImgHdr,addr,sizeof(IMG_HEADER_T),0)< 0){
		prom_printf("nand flash read fail,addr=%x,size=%d\n",addr,sizeof(IMG_HEADER_T));
		return 0;
	}	
#else
	word_ptr = (unsigned short *)pImgHdr;
	for(i = 0; i < sizeof(IMG_HEADER_T); i+=2, word_ptr++)
		*word_ptr = READ_MEM16(addr +i);
#endif
		
	memcpy(image_sig, FW_SIGNATURE, SIG_LEN);
	memcpy(image_sig_root, FW_SIGNATURE_WITH_ROOT, SIG_LEN);
	
	if(!memcmp(pImgHdr->signature, image_sig, SIG_LEN))
		return 1;
	else if(!memcmp(pImgHdr->signature, image_sig_root, SIG_LEN))
		return 2;
	else {
		//prom_printf("MOT: n o sys signature at %X!\n", addr-FLASH_BASE);
		return 0;
	}
}
//------------------------------------------------------------------------------------------

int find_system_header(IMG_HEADER_Tp pImgHdr, unsigned long bank_offset, unsigned long *addr)
{
	int  ret = 0;
	int i=0;
	unsigned long rAddr;

#ifndef CONFIG_NAND_FLASH_BOOTING
	rAddr = (unsigned long)FLASH_BASE+CODE_IMAGE_OFFSET+bank_offset;
	ret = get_system_header(rAddr, pImgHdr);
	if(0 == ret) {
		rAddr = (unsigned long)FLASH_BASE+CODE_IMAGE_OFFSET2+bank_offset;
		ret = get_system_header(rAddr, pImgHdr);
	}
	if(0 == ret) {
		rAddr = (unsigned long)FLASH_BASE+CODE_IMAGE_OFFSET3+bank_offset;
		ret = get_system_header(rAddr, pImgHdr);
	}
#endif
	
#ifdef CONFIG_RTL_FLASH_MAPPING_ENABLE	
	i=CONFIG_LINUX_IMAGE_OFFSET_START;	
	while(i<=CONFIG_LINUX_IMAGE_OFFSET_END && (0==ret))
	{
		rAddr=(unsigned long)FLASH_BASE+i+bank_offset; 

		if(CODE_IMAGE_OFFSET == i || CODE_IMAGE_OFFSET2 == i || CODE_IMAGE_OFFSET3 == i){
			i += CONFIG_LINUX_IMAGE_OFFSET_STEP; 
			continue;
		}
		ret = get_system_header(rAddr, pImgHdr);
		i += CONFIG_LINUX_IMAGE_OFFSET_STEP; 
	}
#endif

	if(0 != ret) {
		*addr = rAddr;
		//return_addr = rAddr;
	}
	
	return ret;
}
//------------------------------------------------------------------------------------------

unsigned long sel_burnbank_offset()
{
	unsigned long burn_offset=0;

	if( ((boot_bank == BANK1_BOOT) && ( bank_mark != FORCEBOOT_BANK_MARK)) ||
	     ((boot_bank == BANK2_BOOT) && ( bank_mark == FORCEBOOT_BANK_MARK))) //burn to bank2
		 burn_offset = CONFIG_RTL_FLASH_DUAL_IMAGE_OFFSET;

	return burn_offset;
}
//------------------------------------------------------------------------------------------

unsigned long get_next_bank_mark()
{
	if( bank_mark < BASIC_BANK_MARK)
		return BASIC_BANK_MARK;
	else if( bank_mark ==  FORCEBOOT_BANK_MARK)	 	
		return bank_mark;
	else
		return bank_mark+1;  
}
//------------------------------------------------------------------------------------------

unsigned long header_to_mark(int  flag, IMG_HEADER_Tp pHeader)
{
	unsigned long ret_mark=NO_IMAGE_BANK_MARK;
	//mark_dual ,  how to diff "no image" "image with no bank_mark(old)" , "boot with lowest priority"
	if(flag) //flag ==0 means ,header is illegal
	{
		if( (pHeader->burnAddr & GOOD_BANK_MARK_MASK) )
			ret_mark=pHeader->burnAddr;	
		else
			ret_mark = OLD_BURNADDR_BANK_MARK;
	}
	return ret_mark;
}
//------------------------------------------------------------------------------------------

int check_dualbank_setting(int in_mode)
{	
	int ret1=0,ret2=0,ret=0,forced=0;
	unsigned long tmp_returnaddr;	
	IMG_HEADER_T tmp_bank_Header,Header,*pHeader=&Header; //0 :bank1 , 1 : bank2
	SETTING_HEADER_T setting_header,*psetting_header=&setting_header;
	unsigned long  tmp_bank_mark1,tmp_bank_mark2; 

	/* MOT debug */
	unsigned long  retAddr1, retAddr2, back_bank_offset = 0;
	int back_bank = 0;
	unsigned long back_bank_mark = 0, bank_offset;

	ret1 = find_system_header(&tmp_bank_Header, 0, &retAddr1);
	ret2 = find_system_header(&Header, CONFIG_RTL_FLASH_DUAL_IMAGE_OFFSET, &retAddr2);
	tmp_bank_mark1 = header_to_mark(ret1, &tmp_bank_Header);
	tmp_bank_mark2 = header_to_mark(ret2, &Header);
	
	if(tmp_bank_mark2 > tmp_bank_mark1) {
#ifdef CONFIG_BOOT_FAIL_CHECK
		if(check_bootstatus_register(retAddr2))
		{
			//can boot from bank2 (normal)
			forced = 0;
			boot_bank = BANK2_BOOT;
			back_bank = BANK1_BOOT;
			bank_mark = tmp_bank_mark2;
			back_bank_mark = tmp_bank_mark1;
			bank_offset = CONFIG_RTL_FLASH_DUAL_IMAGE_OFFSET;
			back_bank_offset = 0;
		}else if(check_bootstatus_register(retAddr1))
		{
			//cannot boot from bank2, switch to try bank1
			forced = 1;
			boot_bank = BANK1_BOOT;
			back_bank = BANK2_BOOT;
			bank_mark = tmp_bank_mark1;
			back_bank_mark = tmp_bank_mark2;
			bank_offset = 0;
			back_bank_offset = CONFIG_RTL_FLASH_DUAL_IMAGE_OFFSET;
		}else
		{
			//should also maintain global variables, for tftp upgrade image to use in checkAutoFlashing().
			//always use the larger bankmark.
			boot_bank = BANK2_BOOT;
			bank_mark = tmp_bank_mark2;	
			prom_printf("[%s:%d] both banks reg check failed!\n", __FUNCTION__, __LINE__);
			return 0;
		}
#else
		//can boot from bank2
		boot_bank = BANK2_BOOT;
		back_bank = BANK1_BOOT;
		bank_mark = tmp_bank_mark2;
		back_bank_mark = tmp_bank_mark1;
		bank_offset = CONFIG_RTL_FLASH_DUAL_IMAGE_OFFSET;
		back_bank_offset = 0;
#endif
	} else {
#ifdef CONFIG_BOOT_FAIL_CHECK
		if(check_bootstatus_register(retAddr1))
		{
			//can boot from bank 1 (normal)
			forced = 0;
			boot_bank = BANK1_BOOT;
			back_bank = BANK2_BOOT;
			bank_mark = tmp_bank_mark1;
			back_bank_mark = tmp_bank_mark2;
			bank_offset = 0;
			back_bank_offset = CONFIG_RTL_FLASH_DUAL_IMAGE_OFFSET;
		}else if(check_bootstatus_register(retAddr2))
		{
			//cannot boot from bank1, switch to try bank2
			forced = 1;
			boot_bank = BANK2_BOOT;
			back_bank = BANK1_BOOT;
			bank_mark = tmp_bank_mark2;
			back_bank_mark = tmp_bank_mark1;
			bank_offset = CONFIG_RTL_FLASH_DUAL_IMAGE_OFFSET;
			back_bank_offset = 0;
		}else
		{
			//should also maintain global variables, for tftp upgrade image to use in checkAutoFlashing().
			//always use the larger bankmark.
			boot_bank = BANK1_BOOT;
			bank_mark = tmp_bank_mark1;
			prom_printf("[%s:%d] both banks reg check failed!\n", __FUNCTION__, __LINE__);
			return 0;
		}
#else
		//can boot from bank 1
		boot_bank = BANK1_BOOT;
		back_bank = BANK2_BOOT;
		bank_mark = tmp_bank_mark1;
		back_bank_mark = tmp_bank_mark2;
		bank_offset = 0;
		back_bank_offset = CONFIG_RTL_FLASH_DUAL_IMAGE_OFFSET;
#endif
	}
	
	prom_printf("bootbank is %d, bankmark %X, forced:%d\n", boot_bank, bank_mark, forced);
	/*TFTP MODE no need to checksum*/
	if(IN_TFTP_MODE == in_mode)
		return (ret1 || ret2);
	
	ret = check_image_header(pHeader, psetting_header, bank_offset);

	if(0 == ret
#ifdef CONFIG_BOOT_FAIL_CHECK
		&& !forced
#endif
	  ) {
		ret = check_image_header(pHeader, psetting_header, back_bank_offset);
		if(0 != ret) {
			boot_bank = back_bank;
			bank_mark = back_bank_mark;
		}
	}
	
	return ret;
}
#endif

#endif //mark_nfbi

#ifdef CONFIG_RTK_BOOTINFO_DUALIMAGE //mark_boot
#define CONFIG_RTK_BOOTINFO_SUPPORT 1
#endif

#ifdef CONFIG_RTK_BOOTINFO_SUPPORT
#include "rtk_bootinfo.c"
BOOTINFO_T bootinfo_ram;
#ifndef CONFIG_NAND_FLASH_BOOTING						
//#define FLASH_MEM_MAP_ADDR 0xbd000000
#define FLASH_MEM_MAP_ADDR 0xb0000000 //mark_97f_dual
#ifdef CONFIG_RTL8198C
#define FLASH_BOOTINFO_OFFSET 0x2a000
#else
#ifdef CONFIG_RTL8197F //97F , is possible to use 64k erase flash , hence don't reuse 2a000 as bootinfo offset , use 30000 as new one
static unsigned int FLASH_BOOTINFO_OFFSET=0x30000;
#else //9XD/8881A/96E
static unsigned int FLASH_BOOTINFO_OFFSET=0xc000;
#endif
#endif
#else
#define FLASH_MEM_MAP_ADDR 		0x0
#define FLASH_BOOTINFO_OFFSET 	0x300000
#endif

//#### bootinfo user define 
//#define USER_MAXBOOTCNT 0    //change to non-zero will  set to bootinfo fixed.

void rtk_flash_write_data(unsigned int flash_addr,unsigned int len,unsigned char* data)
{		
	//ComSrlCmd_ComWriteData(0,flash_addr,len,data);
#ifdef CONFIG_SPI_FLASH
	#ifdef SUPPORT_SPI_MIO_8198_8196C
		spi_flw_image_mio_8198(0,flash_addr,data,len);
	#else
		spi_flw_image(0,flash_addr,data,len);
	#endif
#endif

#ifdef CONFIG_NAND_FLASH_BOOTING
	nflashwrite((unsigned long)flash_addr,(unsigned long)data,(unsigned long)len);
#endif
}

static void  rtk_init_bootinfo(BOOTINFO_P boot)
{
#ifndef CONFIG_NAND_FLASH_BOOTING
	rtk_read_bootinfo_from_flash(FLASH_MEM_MAP_ADDR+FLASH_BOOTINFO_OFFSET,boot);
#else
	nflashread((unsigned int)boot,FLASH_BOOTINFO_OFFSET,sizeof(BOOTINFO_T),0);
#endif

	 if(!rtk_check_bootinfo(boot)) // if not valid bootinfo header use default setting
	 	rtk_reset_bootinfo(boot);	 
}

static void rtk_inc_bootcnt() //increase by 1 to indicate booting record
{
	BOOTINFO_P boot=&bootinfo_ram ;
       boot->data.field.bootcnt ++;        
       prom_printf("bootbank = %d ,bootcnt=%d \n",boot->data.field.bootbank, boot->data.field.bootcnt );//mark_boot	   
       rtk_write_bootinfo_to_flash(FLASH_BOOTINFO_OFFSET,boot,rtk_flash_write_data); 
}

void rtk_update_bootbank(char bank)
{
	BOOTINFO_P boot=&bootinfo_ram ;
	boot->data.field.bootbank = bank;
	boot->data.field.bootcnt = 0;
	rtk_write_bootinfo_to_flash(FLASH_BOOTINFO_OFFSET,boot,rtk_flash_write_data); 
}	

unsigned int  rtk_get_next_bootbank()
{
	unsigned int next_bank=0;
	BOOTINFO_P boot=&bootinfo_ram ;

#ifdef CONFIG_RTK_BOOTINFO_DUALIMAGE	
	//if  toggle mode ,  next bank is toggle
	if( boot->data.field.bootmode == 1 ) 
	{
		if( boot->data.field.bootbank == 0 )
			next_bank = 1;
		else
			next_bank = 0;
	}	
	else	//if normal mode  , nextbank = active bank
#endif
  	      next_bank = boot->data.field.bootbank;	

	return next_bank;
}

static int rtk_check_bank_image(IMG_HEADER_Tp pHeader,SETTING_HEADER_Tp psetting_header,BOOTINFO_P boot)
{	
	int ret=0;
	unsigned int bank_offset=0;	
#ifdef CONFIG_RTK_BOOTINFO_DUALIMAGE
	unsigned char next_bank ;
       
	if(boot->data.field.bootbank == 1 ) // check image depend on bootbank
		bank_offset = CONFIG_RTK_DUALIMAGE_FLASH_OFFSET;
#endif

	ret=check_image_header(pHeader,psetting_header,bank_offset); 
       prom_printf("rtk_check_bank_image ret=%d\n", ret);//mark_boot	

#ifdef CONFIG_RTK_BOOTINFO_DUALIMAGE
	if(!ret) //checksum errot
	{
		next_bank= (unsigned char)rtk_get_next_bootbank();
		prom_printf("checksum error switch to backup bank%d\n", next_bank);//mark_boot	   
		boot->data.field.bootbank = next_bank;
		boot->data.field.bootcnt = 0;
		bank_offset = 0 ;
		if(next_bank == 1 ) // check image depend on bootbank
			bank_offset = CONFIG_RTK_DUALIMAGE_FLASH_OFFSET;		
		ret=check_image_header(pHeader,psetting_header,bank_offset);	
	}
#endif	
	return ret;
}

static int  rtk_ckeck_booting(BOOTINFO_P boot)
{	
	unsigned char next_bank ;
	next_bank= (unsigned char)rtk_get_next_bootbank();

    //if( !boot->data.field.bootmaxcnt )	
	 	//return 1;  //if max=0 mean ignore check

     if(boot->data.field.bootcnt >=  boot->data.field.bootmaxcnt )
     {
#ifdef CONFIG_RTK_BOOTINFO_DUALIMAGE
	  	if(  next_bank != boot->data.field.bootbank  )  
	  	{
	  		prom_printf("bootinf fail maxcnt reached switch to backup bank%d\n", next_bank);//mark_boot
			boot->data.field.bootbank = next_bank;
			boot->data.field.bootcnt = 0;
	  	}	
		 else	
#endif
	    	   return 0;  //reach max booting count , return 0 to indecater fail boot.
      }

     return 1;	  //ok booting
 }
#endif

//------------------------------------------------------------------------------------------

int check_image(IMG_HEADER_Tp pHeader,SETTING_HEADER_Tp psetting_header)
{
	int ret=0;
#if defined(CONFIG_NFBI) || defined(CONFIG_NONE_FLASH)
	prom_printf("---NFBI or ROM booting---\n");
#else
#ifdef CONFIG_RTK_BOOTINFO_SUPPORT
	rtk_init_bootinfo(&bootinfo_ram);
	ret = rtk_ckeck_booting(&bootinfo_ram);
	if(!ret)
		return ret;
#endif
	//only one bank
	#ifndef CONFIG_RTL_FLASH_DUAL_IMAGE_ENABLE

 	#ifndef CONFIG_RTK_BOOTINFO_SUPPORT
 	ret=check_image_header(pHeader,psetting_header,0); 
	#else		
	ret=rtk_check_bank_image(pHeader,psetting_header,&bootinfo_ram); 
	#endif

	/* winfred_wang static mode */
	#ifdef CONFIG_RTL_FLASH_DUAL_IMAGE_STATIC
	#ifndef CONFIG_NAND_FLASH_BOOTING
	#define DST_BUFFER_ADDR	0x80800000	// place to put flash read image
	#else
	#define DST_BUFFER_ADDR	0xa0800000	// place to put flash read image
	#endif
	
	if (ret == 0
		#ifdef CONFIG_BOOT_RESET_ENABLE
			&& !gCHKKEY_HIT
		#endif	
		) {
		printf("Checking bank2...\n");
	 	ret = check_image_header(pHeader, psetting_header, CONFIG_RTL_FLASH_DUAL_IMAGE_OFFSET); 
		if (ret) {
			unsigned long src_addr = return_addr - FLASH_BASE;			
			unsigned long length = CONFIG_RTL_FLASH_DUAL_IMAGE_OFFSET*2 - src_addr;
			#ifndef CONFIG_NAND_FLASH_BOOTING
			printf("Flash read from %X to %X with %X bytes ?\n",src_addr, DST_BUFFER_ADDR, length);
			flashread(DST_BUFFER_ADDR, src_addr, length);
		
			printf("Flash Program from %X to %X with %X bytes ?\n",DST_BUFFER_ADDR, src_addr-CONFIG_RTL_FLASH_DUAL_IMAGE_OFFSET, length);

			spi_flw_image(0,src_addr-CONFIG_RTL_FLASH_DUAL_IMAGE_OFFSET,DST_BUFFER_ADDR, length);
			//flashwrite(src_addr-CONFIG_RTL_FLASH_DUAL_IMAGE_OFFSET, DST_BUFFER_ADDR, length);
			#else
			printf("Flash read from %X to %X with %X bytes ?\n",src_addr, DRAM_DIMAGE_ADDR, length);
			nflashread(DST_BUFFER_ADDR, src_addr, length,0);
		
			printf("Flash Program from %X to %X with %X bytes ?\n",DRAM_DIMAGE_ADDR, src_addr-CONFIG_RTL_FLASH_DUAL_IMAGE_OFFSET, length);
			nflashwrite(src_addr-CONFIG_RTL_FLASH_DUAL_IMAGE_OFFSET, DST_BUFFER_ADDR, length);
			#endif
			
			ret = check_image_header(pHeader,psetting_header,0); 
			if (ret == 0)
				printf("Bank1 image is still invalid after update from bank2!!\n");	
			else
				printf("Copy bank2 to bank1 successfully!\n");				
		}
		else 
			printf("Bank2 is corrupted!\n");
		
	}
	#endif
	
	#else //CONFIG_RTL_FLASH_DUAL_IMAGE_ENABLE
       	ret = check_dualbank_setting(IN_BOOTING_MODE);
	#endif
#endif //end of NFBI else
	return ret;
}

//------------------------------------------------------------------------------------------
//monitor user interrupt
int pollingDownModeKeyword(int key)
{
	int i;
                 #if CONFIG_ESD_SUPPORT//patch for ESD
                  	 REG32(0xb800311c)|= (1<<23);
                  #endif
	if  (Check_UART_DataReady() )
	{
		i=Get_UART_Data();
		Get_UART_Data();
		if( i == key )
		{ 	
#if defined(UTILITY_DEBUG)		
			dprintf("User Press ESC Break Key\r\n");
#endif			
			gCHKKEY_HIT=1;
			return 1;
		}
	}
	return 0;
}
//------------------------------------------------------------------------------------------

#ifdef CONFIG_BOOT_RESET_ENABLE
int pollingPressedButton(int pressedFlag)
{
#ifndef CONFIG_NFBI
#ifndef CONFIG_FPGA_PLATFORM
		// polling if button is pressed --------------------------------------
    		if (pressedFlag == -1 ||  pressedFlag == 1) 
		{

#if defined(RTL8198)
	// vincent: already done in Init_GPIO(). do nothing here
	//		REG32(RTL_GPIO_MUX) =  0x0c0f;
	//		REG32(PEFGHCNR_REG) = REG32(PEFGHCNR_REG)& (~(1<<25) ); //set byte F GPIO7 = gpio
        //     		REG32(PEFGHDIR_REG) = REG32(PEFGHDIR_REG) & (~(1<<25) );  //0 input, 1 out
#endif
		
			if ( Get_GPIO_SW_IN() )			
			{// button pressed
#if defined(UTILITY_DEBUG)			
	    			dprintf("User Press GPIO Break Key\r\n");
#endif	    			
				if (pressedFlag == -1) 
				{
					//SET_TIMER(1*CPU_CLOCK); // wait 1 sec
				}
				pressedFlag = 1;
				gCHKKEY_HIT=1;
#if defined(UTILITY_DEBUG)				
				dprintf("User Press Break Button\r\n",__LINE__);
#endif
				return 1;	//jasonwang//wei add				

			}
			else
		      		pressedFlag = 0;
		}
#if defined(UTILITY_DEBUG)
	dprintf("j=%x\r\n",get_timer_jiffies());
#endif
#endif
#endif //CONFIG_NFBI

	return pressedFlag;
}
#endif
//------------------------------------------------------------------------------------------

//return 0: do nothing; 1: jump to down load mode; 3 jump to debug down load mode
int user_interrupt(unsigned long time)
{
	int i,ret;
	int tickStart=0;
#ifdef SUPPORT_TFTP_CLIENT
	extern int check_tftp_client_state();	
#endif
	
#ifdef CONFIG_BOOT_RESET_ENABLE
	int button_press_detected=-1;
#endif
	
	tickStart=get_timer_jiffies();
#ifdef  SUPPORT_TFTP_CLIENT
	do 
#endif
    {
		ret=pollingDownModeKeyword(ESC);
		if(ret == 1) return 1;
#ifdef CONFIG_BOOT_RESET_ENABLE		
		ret=pollingPressedButton(button_press_detected);
		button_press_detected=ret;
		if(ret > 0) return ret;
#endif		
	}while (
#ifdef SUPPORT_TFTP_CLIENT
	check_tftp_client_state() >= 0
#else
#if 0//def 	CONFIG_BOOT_RESET_ENABLE
	(get_timer_jiffies() - tickStart) < 100
#else
	0
#endif
#endif
	);  // 1 sec
#if defined(UTILITY_DEBUG)
	dprintf("timeout\r\n");
#endif	
#ifdef CONFIG_BOOT_RESET_ENABLE
	if (button_press_detected>0)
	{   
		gCHKKEY_HIT=1;    
		return 1;
	}
#endif	
	return 0;
}
//------------------------------------------------------------------------------------------



//------------------------------------------------------------------------------------------
//init gpio[96c not fix gpio, so close first. fix CPU 390MHz cannot boot from flash.]
void Init_GPIO()
{
#if 0  //rom code disable
#if defined(CONFIG_RTL8198)
#ifndef CONFIG_NFBI
#ifndef CONFIG_RTL8198
	REG32(PABCDCNR_REG) = REG32(PABCDCNR_REG)& (~(1<<5) ); //set byte F GPIO7 = gpio
	REG32(PABCDDIR_REG) = REG32(PABCDDIR_REG) & (~(1<<5) );  //0 input, 1 output, set F bit 7 input
	//modify for light reset led pin in output mode
	REG32(PABCDCNR_REG) = REG32(PABCDCNR_REG)& (~(1<<RESET_LED_PIN) ); 
	REG32(PABCDDIR_REG) = REG32(PABCDDIR_REG) | ((1<<RESET_LED_PIN) ); 
	REG32(PABCDDAT_REG) = REG32(PABCDDAT_REG) | ((1<<RESET_LED_PIN) );  
#else
	REG32(RTL_GPIO_MUX) =  0x0c0f;
	REG32(PEFGHCNR_REG) = REG32(PEFGHCNR_REG)& (~(1<<25) ); //set byte F GPIO7 = gpio
	REG32(PEFGHDIR_REG) = REG32(PEFGHDIR_REG) & (~(1<<25) );  //0 input, 1 output, set F bit 7 input
#endif	
#endif
#endif
#endif
}

//------------------------------------------------------------------------------------------
void console_init(void)
{
  	REG32(BSP_UART0_FCR)=0xc7;		//FIFO Ccontrol Register
  	REG32(BSP_UART0_IER) = 0;

  	REG32(BSP_UART0_LCR) = BSP_LCR_DLAB;		//Divisor latch access bit=1
	REG32(BSP_UART0_DLL) = BSP_UART0_BAUD_DIVISOR & 0x00ff;
	REG32(BSP_UART0_DLM) = (BSP_UART0_BAUD_DIVISOR & 0xff00) >> 8;
//REG32(BSP_UART0_SCR) = 0xA0030; // 57600, 115200
//REG32(BSP_UART0_STSR) = 0xC0; // 57600, 115200
    	REG32(BSP_UART0_LCR) = BSP_CHAR_LEN_8 | BSP_ONE_STOP;	//Divisor latch access bit=0;  8,n,1
   	//rtl_outl( UART_THR,0x41000000);	

	//dprintf("\n\n-------------------------------------------");
	//dprintf("\nUART1 output test ok\n");
}
//-------------------------------------------------------

int CmdEthStartup(int argc, char* argv[])
{

	eth_startup(0);	
	dprintf("\n---Ethernet init Okay!\n");
	sti();

#ifdef SUPPORT_TFTP_CLIENT	
	tftpd_entry(0);		
#else
	tftpd_entry();		
#endif

#ifdef DHCP_SERVER			
	dhcps_entry();
#endif

#ifdef HTTP_SERVER
	httpd_entry();
#endif

	return 0;		
}

void goToDownMode()
{
#ifndef CONFIG_SW_NONE
	if(pollingDownModeKeyword('m')==0)
	{
		CmdEthStartup(1, NULL);
	}
#endif
	monitor();
	return ;
}
//-------------------------------------------------------

#ifdef CONFIG_RTL_FLASH_DUAL_IMAGE_ENABLE		
void set_bankinfo_register()  //in order to notify kernel
{
#define SYSTEM_CONTRL_DUMMY_REG 0xb8003504
	prom_printf("return_addr = %x ,boot bank=%d, bank_mark=0x%x...\n",return_addr,boot_bank,bank_mark);	
	if(boot_bank == BANK2_BOOT)
		REG32(SYSTEM_CONTRL_DUMMY_REG) = (REG32(SYSTEM_CONTRL_DUMMY_REG) | 0x00000001); //mark_dul, issue use function is better
	//prom_printf("2SYSTEM_CONTRL_DUMMY_REG = %x",REG32(SYSTEM_CONTRL_DUMMY_REG));	
}			
#endif		
//-------------------------------------------------------

#ifdef CONFIG_SD_CARD_BOOTING

#define LINUX_ADDR 0xA0A00000
#define PHY_2_NONCACHE_ADDR(addr)   ((addr) | 0x80000000)
#define PHY_2_CACHE_ADDR(addr)      ((addr) | 0xA0000000)
#define CACHE_2_NONCACHE_ADDR(addr) ((addr) | 0x20000000)
#define VIR_2_PHY_ADDR(addr)        ((addr) & (~0xA0000000))
#define LINUX_SIGNATURE		((unsigned char *)"linux")

#define UPLOAD_ADDR 0xA0500000
#define LINUX_HEADER 0x63723663  //cr6c
void init_sdcard(void)
{
	REG32(REG_SD30_2) = REG32(REG_SD30_2) | BIT_SSCLDO_EN;
	REG32(REG_SD30_4) = REG32(REG_SD30_4) | BIT_SSC_PLL_POW | BIT_SSC_PLL_RSTB | BIT_SSC_RSTB;
	ENABLE_EMMC_SD;
	REG32(REG_SD30_1) = (REG32(REG_SD30_1) & BIT_INV_REG_TUNED3318) | BIT_REG_TUNED3318(BIT_REG_TUNED3318_VAL_33V);
	REG32(CR_PAD_CTL) = REG32(CR_PAD_CTL) | TUNE_33_18V;
	REG32(SD_CONFIGURE1) = REG32(SD_CONFIGURE1) | SDCLK_DIV | CLOCK_DIV_256;
	REG32(REG_ENABLE_IP) = REG32(REG_ENABLE_IP) | BIT_CLK_EN_SD30;

	int ret_val;
	ret_val = romcr_sdcard_init();
	if (ret_val != 0) {
		return;
	}
}

void sdcard_booting(void)
{
	unsigned int ret_val;
	FATFS fatFs;
	FIL fil;
	unsigned int br;
	//char filename[20] = "boot_ok.bin";
	//char filename[20] = "nfjrom";
	char filename[20] = "linux.bin";
	unsigned char *addr = UPLOAD_ADDR;
	void (*jump_func)(void);

	//prom_printf("%s(%d): 0x%x, 0x%x\n", __func__, __LINE__, &fatFs, &fil);
	fatFs.win = (unsigned char *)CACHE_2_NONCACHE_ADDR((unsigned int)fatFs.win1);
	ret_val = f_mount(0, (FATFS *)(&fatFs));
	ret_val = f_open((FIL *)(&fil), filename, FA_READ);

	if (ret_val) {
		prom_printf("%s(%d): open file fail(0x%x) \n", __FUNCTION__, __LINE__, ret_val);
		return;
	}

	ret_val = f_read((FIL *)(&fil), addr, fil.fsize, &br);
	prom_printf("%s(%d): read 0x%x byte to 0x%x\n", __func__, __LINE__, fil.fsize, addr);
	f_close(&fil);

	//check linux header
	unsigned long image_header=(int)(addr[0])*0x1000000+(int)(addr[1])*0x10000+(int)(addr[2])*0x100+(int)(addr[3]);	
	if(image_header==LINUX_HEADER)
	{
		unsigned long image_mem=(int)(addr[4])*0x1000000+(int)(addr[5])*0x10000+(int)(addr[6])*0x100+(int)(addr[7]);
		unsigned long image_cache = PHY_2_CACHE_ADDR(image_mem)-0x10; //move image to mem without header 
		FATFS fatFs_linux;
		FIL fil_linux;

		prom_printf("Find Linux header, reload image to 0x%08X\n", image_mem);
		//load image again to linux indicated mem addr
		fatFs_linux.win = (unsigned char *)CACHE_2_NONCACHE_ADDR((unsigned int)fatFs_linux.win1);	
		ret_val = f_mount(0, (FATFS *)(&fatFs_linux));
		ret_val = f_open((FIL *)(&fil_linux), filename, FA_READ);

		if (ret_val) {
			prom_printf("%s(%d): open file fail(0x%x) \n", __FUNCTION__, __LINE__, ret_val);
			return;
		}

		ret_val = f_read((FIL *)(&fil_linux), image_cache, fil_linux.fsize, &br);
		//prom_printf("%s(%d): read 0x%x byte to 0x%x\n", __func__, __LINE__, fil_linux.fsize, image_cache);
		f_close(&fil_linux);
		image_cache += 0x10;
		//prom_printf("%s(%d): addr:0x%x \n", __func__, __LINE__, image_cache); 
		jump_func = (void *)(image_cache);
		jump_func();
	}
	else
	{	
		prom_printf("Not realtek linux header, image header 0x%08x\n", image_header);
		return;
	}

#if 0
	addr+= 0x10;
	dprintf("%s(%d): addr:0x%x \n", __func__, __LINE__, addr);
	jump_func = (void *)(addr);
	jump_func();
#endif	
}
#endif

#if !defined(CONFIG_NONE_FLASH)
void goToLocalStartMode(unsigned long addr,IMG_HEADER_Tp pheader)
{
	unsigned short *word_ptr;
	void	(*jump)(void);
	int i;
	int ret = 0;
	
	//prom_printf("\n---%X\n",return_addr);
#ifdef CONFIG_NAND_FLASH_BOOTING
	if(nflashread((unsigned int)pheader,addr,sizeof(IMG_HEADER_T),0)< 0){
		prom_printf("nand flash read fail,addr=%x,size=%d\n",addr,sizeof(IMG_HEADER_T));
		return;// 0;
	}		
#else
	if(!flashread((unsigned long) pheader, addr, sizeof(IMG_HEADER_T)))
		prom_printf("SPI flash read fail,addr=%x,size=%d\n",addr,sizeof(IMG_HEADER_T));
#endif

	pheader->startAddr = ___swab32(pheader->startAddr);
	pheader->burnAddr = ___swab32(pheader->burnAddr);
	pheader->len = ___swab32(pheader->len);
	
	// move image to SDRAM
#if !defined(CONFIG_NONE_FLASH)	
#ifdef CONFIG_NAND_FLASH_BOOTING
	ret = nflashread( pheader->startAddr|0x20000000,(unsigned int)(addr-FLASH_BASE+sizeof(IMG_HEADER_T)),pheader->len-2,0);
#else
#if !defined(CONFIG_RTK_LINUX_SECURE) //don't need to load flash again.
	ret = flashread( pheader->startAddr|0x20000000,	(unsigned int)(addr-FLASH_BASE+sizeof(IMG_HEADER_T)), pheader->len-2);
#endif
#endif //CONFIG_NAND_FLASH_BOOTING
#endif //CONFIG_NONE_FLASH

	//if ( !user_interrupt(0) )  // See if user escape during copy image
	{
		
		outl(0,GIMR0); // mask all interrupt
#if defined(CONFIG_BOOT_RESET_ENABLE)
		Set_GPIO_LED_OFF();
#endif
#ifdef BSP_SYS_LED_PIN
		REG32(BSP_GPIO_DAT_REG(BSP_SYS_LED_PIN)) &= ~(1 << BSP_GPIO_BIT(BSP_SYS_LED_PIN));
#endif
#if defined(CONFIG_PARAM_PASSING)
		boot_linux_param_init();
#endif
		
		prom_printf("Jump to image start=0x%x...\n", pheader->startAddr);
		
#ifdef CONFIG_RTL_FLASH_DUAL_IMAGE_ENABLE
		set_bankinfo_register();
#endif
#ifdef CONFIG_RTK_BOOTINFO_SUPPORT
		rtk_inc_bootcnt(); 
#endif
		jump = (void *)(pheader->startAddr);
		REG32(0xb8003000) =0;
                REG32(0xb8003004) =0;
		REG32(0xb8003114)=0;
  		REG32(0xb8000010)&=~(1<<11);
  		REG32(0xbbdc0300)=0xffffffff;
  		REG32(0xbbdc0304)=0xffffffff;
		cli();
		flush_cache(); 
#ifdef CONFIG_PARAM_PASSING
		boot_linux_set_ep(pheader->startAddr);
		boot_jump_linux();
#else
		jump();				 // jump to start
#endif
		return ;
	}
	return;
}
#endif

//-------------------------------------------------------

#if 0
void debugGoToLocalStartMode(unsigned long addr,IMG_HEADER_Tp pheader)
{
	unsigned short *word_ptr;
	void	(*jump)(void);
	int i, count=500;

	//prom_printf("\n---%X\n",return_addr);
	word_ptr = (unsigned short *)pheader;
	for (i=0; i<sizeof(IMG_HEADER_T); i+=2, word_ptr++)
	*word_ptr = READ_MEM16(addr + i);
			
	// move image to SDRAM
#if !defined(CONFIG_NONE_FLASH)	
	flashread( pheader->startAddr,	(unsigned int)(addr-FLASH_BASE+sizeof(IMG_HEADER_T)), 	pheader->len-2);
#endif			
	if ( !user_interrupt(0) )  // See if user escape during copy image
	{
		outl(0,GIMR0); // mask all interrupt
#ifdef CONFIG_BOOT_RESET_ENABLE
		Set_GPIO_LED_OFF();
#endif


		REG32(0xb8019004)=0xFE;
		while(count--)
		{continue;}
		
		if(REG32(0xb8019004)!=0xFE)
			prom_printf("fail debug-Jump to image start=0x%x...\n", pheader->startAddr);
		prom_printf("Debug-Jump to image start=0x%x...\n", pheader->startAddr);
		jump = (void *)(pheader->startAddr);
				
		cli();
		flush_cache(); 
		jump();				 // jump to start
	}
}
#endif
//-------------------------------------------------------
//set clk and init console	
void setClkInitConsole(void)
{
	console_init();
	//dprintf("\n=>init console ok\n");
}
//-------------------------------------------------------
//init heap	
void initHeap(void)
{
#if defined(RTL8198)
	/* Initialize malloc mechanism */
	unsigned int heap_addr=((unsigned int)dl_heap&(~7))+8 ;
	unsigned int heap_end=heap_addr+sizeof(dl_heap)-8;
#if defined(CONFIG_RTK_LINUX_SECURE) || defined(CONFIG_RTK_ROOTFS_SECURE)
	heap_addr=((unsigned int)dl_heap&(~0x1F))+8 ;
	heap_end=heap_addr+sizeof(dl_heap)-8;
#endif
  	i_alloc((void *)heap_addr, heap_end);
#endif
	cli();  	
	flush_cache(); // david
}
//-------------------------------------------------------

//-------------------------------------------------------
// init flash 
void initFlash(void)
{
#if defined(CONFIG_SPI_FLASH)
   	sheipa_spi_probe();
#ifdef CONFIG_SPI_FLASH_NUMBER
	int i;
	for (i = 0; i < CONFIG_FLASH_NUMBER ; i++)
		m25p_probe(i);
#else
	m25p_probe(0);
#endif
#endif  

#if defined(CONFIG_NAND_FLASH)
	if(nflashprobe() < 0)
	{
		prom_printf("Error: cannot find nand flash chip\n");
	}
#endif
}

#ifdef CONFIG_I2C_POLLING
//init I2C
void initI2C(void)
{
        dw_i2c_probe();
}
#endif

#ifdef CONFIG_PCIE_INIT

#define SYS_CLK_MANAGE				(SYSTEM_REG_BASE + 0x10)
#define SYS_ENABLE					(SYSTEM_REG_BASE + 0x50)
#define SYS_PCIE_PHY				(SYSTEM_REG_BASE + 0x100)

#define PCIE_RC_EXTENDED_REG_MDIO	(BSP_PCIE_RC_EXTENDED_REG + 0x00)
#define PCIE_RC_EXTENDED_REG_PWRCR	(BSP_PCIE_RC_EXTENDED_REG + 0x08)

#define PCIE_MDIO_REG_OFFSET 		(8)
#define PCIE_MDIO_DATA_OFFSET 		(16)
#define PCIE_MDIO_RDWR_OFFSET 		(0)

#define PCI_CONFIG_BASE1			0xb8b10018
#define PCI_CONFIG_COMMAND			0xb8b10004
#define PCI_CONFIG_LATENCY			0xb8b1000c


#define mdelay(ms)					udelay(1000*ms)
#define printk						prom_printf
extern unsigned long loops_per_sec;

static void PCIE_PHY_MDIO_Write(unsigned int portnum, unsigned int regaddr, unsigned short val)
{
	unsigned int mdioaddr;
	volatile int count;

	mdioaddr = PCIE_RC_EXTENDED_REG_MDIO;

	REG32(mdioaddr) = ( (regaddr&0x1f)<<PCIE_MDIO_REG_OFFSET) | ((val&0xffff)<<PCIE_MDIO_DATA_OFFSET)  | (1<<PCIE_MDIO_RDWR_OFFSET) ; 
	//delay
	for(count = 0; count < 5555; count++)
	{
		// do nothing, just delay
	}
}


static void PCIeMDIOPHYParameterSetRLE0600(unsigned int portnum)
{
	unsigned int temp=0;
	temp =REG32(0xb8000008);
	if((temp&(1<<24))==(1<<24))
	{
		printk("40MHz\r\n");		
		 PCIE_PHY_MDIO_Write(portnum, 0x0f, 0x12f6);
		 PCIE_PHY_MDIO_Write(portnum, 0x00, 0x0071);
		 PCIE_PHY_MDIO_Write(portnum, 0x06, 0x1ac1);
	}
	else
	{
		PCIE_PHY_MDIO_Write(portnum, 0x00, 0x0071);
		PCIE_PHY_MDIO_Write(portnum, 0x06, 0x18c1);
	}



/*
	PCIE_PHY_MDIO_Write(portnum, 0x00, 0x5083);
	PCIE_PHY_MDIO_Write(portnum, 0x04, 0xf048);
	PCIE_PHY_MDIO_Write(portnum, 0x06, 0x19e0);
	PCIE_PHY_MDIO_Write(portnum, 0x19, 0x6c69);
	PCIE_PHY_MDIO_Write(portnum, 0x1d, 0x0000);
	PCIE_PHY_MDIO_Write(portnum, 0x01, 0x0000);
	PCIE_PHY_MDIO_Write(portnum, 0x08, 0x9cc3);
	PCIE_PHY_MDIO_Write(portnum, 0x09, 0x4380);
	PCIE_PHY_MDIO_Write(portnum, 0x03, 0x7b44);
*/
	return;
}


static void PCIE_MDIO_Reset_97F(unsigned int portnum)
{
	unsigned int sys_pcie_phy;

	sys_pcie_phy = SYS_PCIE_PHY;

	// MDIO Reset
	REG32(sys_pcie_phy) = (1<<3) |(0<<1) | (0<<0);     //mdio reset=0,
	REG32(sys_pcie_phy) = (1<<3) |(0<<1) | (1<<0);     //mdio reset=1,
	REG32(sys_pcie_phy) = (1<<3) |(1<<1) | (1<<0);     //bit1 load_done=1
}

void PCIE_PHY_Reset_97F(unsigned int portnum)
{
	unsigned int pcie_phy;

	pcie_phy = PCIE_RC_EXTENDED_REG_PWRCR;

    // PCIE PHY Reset
	REG32(pcie_phy) = 0x01;		//bit7:PHY reset=0   bit0: Enable LTSSM=1
	REG32(pcie_phy) = 0x81;		//bit7: PHY reset=1   bit0: Enable LTSSM=1
}

static void PCIE_MDIO_PHY_Parameter_Set(unsigned int portnum)
{
#ifdef CONFIG_RTK_FPGA
	PCIeMDIOPHYParameterSetRLE0269B(portnum);
#else
	PCIeMDIOPHYParameterSetRLE0600(portnum);
#endif
}

static void PCIE_Device_PERST_97F(unsigned int portnum)
{
	unsigned int sys_enable;

	sys_enable = SYS_ENABLE;

	REG32(sys_enable) &= ~(1<<1);    //perst=0 off.
	mdelay(300);  					//PCIE standadrd: poweron: 100us, after poweron: 100ms
	REG32(sys_enable) |=  (1<<1);   //PERST=1

}

static int PCIE_Check_Link_97F(unsigned int portnum)
{
	unsigned int dbgaddr;
	unsigned int cfgaddr;
	volatile int count = 5;

	dbgaddr = BSP_PCIE_RC_CFG + 0x728;

	//wait for LinkUP
	mdelay(10);

	while(--count)
	{
		mdelay(10);
		if( ( REG32(dbgaddr) & 0x1f) == 0x11)
		{
			break;
		}
	}

	if(count == 0){
		printk("PCIE ->  Cannot LinkUP\r\n" );
		return 0;
	}
	else  //already  linkup
	{
		cfgaddr = BSP_PCIE_EP_CFG;

		REG32(BSP_PCIE_RC_CFG + 0x04) = 0x00100007;
		REG32(BSP_PCIE_EP_CFG + 0x04) = 0x00100007;

		printk("Find PCIE Port, Device:Vender ID=%x\n", REG32(cfgaddr) );
	}

	return 1;
}


int PCIE_reset_procedure_97F(unsigned int PCIeIdx, unsigned int mdioReset)
{
	int result=0;

	// Turn On PCIE IP
	REG32(SYS_CLK_MANAGE) |= (1<<12) | (1<<13) | (1<<18);
	REG32(SYS_CLK_MANAGE) |= (1<<14);
	mdelay(10);

	// Compatible
	//REG32(PCIE_RC_EXTENDED_REG_IPCFG) |= ((PCIeIdx*2+1) << 8);

	if(mdioReset)
	{
		printk("Do MDIO_RESET\r\n");
		mdelay(10);
		PCIE_MDIO_Reset_97F(PCIeIdx);
	}

	mdelay(10);
	PCIE_PHY_Reset_97F(PCIeIdx);
	mdelay(10);

	if(mdioReset)
	{
		PCIE_MDIO_PHY_Parameter_Set(PCIeIdx);
	}

	// PCIE Host Reset
	mdelay(10);
	PCIE_PHY_Reset_97F(PCIeIdx);

	// PCIE Device Reset
	PCIE_Device_PERST_97F(PCIeIdx);

	// Check link
	result = PCIE_Check_Link_97F(PCIeIdx);

	return result;
}


void initPCIE(void)
{
	int i = 0;
	PCIE_reset_procedure_97F(0,1);

	/* Fix the issue to use memory under 1M */
	REG32(0xb8b00000+0x1c)=(2<<4) | (0<<12);   // [7:4]=base [15:12]=limit
	REG32(0xb8b00000+0x20)=(2<<4) | (0<<20);   // [7:4]=base [15:12]=limit
	REG32(0xb8b00000+0x24)=(2<<4) | (0<<20);   // [7:4]=base [15:12]=limit

	*((volatile unsigned long *)PCI_CONFIG_BASE1) = 0x19000004;
	 //DEBUG_INFO("...config_base1 = 0x%08lx\n", *((volatile unsigned long *)PCI_CONFIG_BASE1));
    for(i=0; i<1000000; i++);
    *((volatile unsigned char *)PCI_CONFIG_COMMAND) = 0x07;
    //DEBUG_INFO("...command = 0x%08lx\n", *((volatile unsigned long *)PCI_CONFIG_COMMAND));
    for(i=0; i<1000000; i++);
    *((volatile unsigned short *)PCI_CONFIG_LATENCY) = 0x2000;
    for(i=0; i<1000000; i++);
    //DEBUG_INFO("...latency = 0x%08lx\n", *((volatile unsigned long *)PCI_CONFIG_LATENCY));

}
#endif

//-------------------------------------------------------
//rtk bootcode and enable post
//copy img to sdram and monitor ESC interrupt

void doBooting(int flag, unsigned long addr, IMG_HEADER_Tp pheader)
{
	SETTING_HEADER_T setting_header;
	int ret = 0;
#ifdef __DAVO__
	nvram_coincide(&setting_header);
#endif
#if 1//!(defined(CONFIG_NFBI)||defined(CONFIG_NONE_FLASH))
#ifdef SUPPORT_TFTP_CLIENT	
	extern int check_tftp_client_state();

	if(flag || check_tftp_client_state() >= 0)
#else
	if(flag)
#endif
	{
		switch(user_interrupt(WAIT_TIME_USER_INTERRUPT))
		{
		case LOCALSTART_MODE:
		default:
#ifdef SUPPORT_TFTP_CLIENT
			/* disable Ethernet switch */
			REG32(0xb8000010)= REG32(0xb8000010)&(~(1<<11));
			if (!flag) {
				REG32(BSP_GIMR)=0x0;   //add by jiawenjian
				goToDownMode(); 	
			}	
#endif
#ifdef CONFIG_SD_CARD_BOOTING
			init_sdcard();
			sdcard_booting();
#endif
#if !defined(CONFIG_NONE_FLASH)
CHECK_IMAGE_START:
			ret=check_image(pheader,&setting_header);
			if(ret)
			{
#ifdef CONFIG_BOOT_FAIL_CHECK
				if(check_bootstatus_register(return_addr))
				{
					set_bootstatus_register(return_addr);
				}else
				{
#ifdef CONFIG_RTL_FLASH_DUAL_IMAGE_ENABLE
					//retry the backup bank
					prom_printf("[%s:%d] check status register NOT OK! Retry check_image() for backup bank.\n", __FUNCTION__, __LINE__);
					goto CHECK_IMAGE_START;
#else
					//no backup, go to down mode
					prom_printf("[%s:%d] check status register NOT OK! Goto down mode.\n", __FUNCTION__, __LINE__);
					REG32(BSP_GIMR)=0x0;   //add by jiawenjian
					goToDownMode();	
#endif
				}
#endif
				goToLocalStartMode(return_addr, pheader);	//return_addr is assigned in check_image()
			}else{
				REG32(BSP_GIMR)=0x0;   //add by jiawenjian
				goToDownMode();		
			}
#endif
			break;
		case DOWN_MODE:
			dprintf("\n---Escape booting by user\n");	
			//cli();
			REG32(BSP_GIMR)=0x0;   //add by jiawenjian
			
#ifdef CONFIG_I2C_POLLING
			REG32(GIMR_REG) |= (1<<30);
#endif
			goToDownMode();	
			break;
		}/*switch case */
	}/*if image correct*/
	else
#endif //CONFIG_NFBI
	{
		REG32(BSP_GIMR)=0x0;   //add by jiawenjian
		goToDownMode();		
	}
	return;
}

