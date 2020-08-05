#include "./rtkn_nand/rtknflash.h"
#include <linux/string.h>

unsigned char* rtk_boot_oob_poi = NULL;
struct rtknflash *rtkn;
#define aligned(addr,size)	(addr%size !=0)

/* must block size aligned */
#include "../init/utility.h"
extern unsigned int gCHKKEY_CNT;
static unsigned char *ptr_oob = NULL,*ptr_data = NULL;

static unsigned int block_size,page_size,oob_size,ppb;

#ifdef CONFIG_RTK_NORMAL_BBT
extern unsigned int uboot_scrub;
#endif


/**************************************************************/
/* used erase for one block */
static int nand_erase_block(unsigned int addr)
{
	struct mtd_info *mtd = rtkn->mtd;
	{
		rtkn->curr_page_addr = (addr)/page_size;		
		if(rtknflash_erase1_cmd(rtkn->mtd,rtkn) < 0){
			printf("erase block=%d failed\n",(addr)/block_size);
			return -1;
		}
	}
	
	return 0;
}

static int nand_read_ecc_ob(unsigned int from, unsigned int len, unsigned char *data_buf, unsigned char *oob_buf)
{
	int page_num = 0;
	struct mtd_info *mtd = rtkn->mtd;
	unsigned int read_size = 0,page;

	printf_test("%s:%d\n",__func__,__LINE__);
	if(aligned(from,block_size) != 0){
		printf("addr=%x not page_size=%x aligned\n",from,page_size);
		return -1;
	}

	printf_test("%s:%d\n",__func__,__LINE__);
	while(read_size < len){
		page = (read_size+from)/page_size;

		printf_test("%s:%d\n",__func__,__LINE__);
		if(rtkn_ecc_read_page(rtkn->mtd,rtkn->nand_chip,data_buf+page_num*page_size,1,page) < 0){
			printf("read page = %d failed\n",page);
			return -1;
		}

		printf_test("%s:%d\n",__func__,__LINE__);
		/* copy oob */
		memcpy(oob_buf+page_num*oob_size,rtkn->nand_chip->oob_poi,oob_size);
		page_num++;
		read_size += page_size;
	}

	printf_test("%s:%d\n",__func__,__LINE__);
	return 0;
}

static int nand_write_ecc_ob (unsigned int to, unsigned int len, unsigned char *data_buf, unsigned char *oob_buf)
{
	int page_num = 0;
	struct mtd_info *mtd = rtkn->mtd;
	unsigned int write_size = 0,page;
	
	if(aligned(to,block_size) != 0){
		printf("addr=%x not page_size=%x aligned\n",to,page_size);
		return -1;
	}
	

	while(write_size < len){		
		page = (write_size+to)/page_size;

		rtkn->curr_page_addr = page;
		memcpy(rtkn->nand_chip->oob_poi,oob_buf+page_num*oob_size,oob_size);
		//memcpy(oob_buf,rtkn->nand_chip->oob_poi,oob_size);
		if(rtkn_ecc_write_page(rtkn->mtd,rtkn->nand_chip,data_buf+page_num*page_size,1) < 0){
			printf("read page = %d failed\n",page);
			return -1;
		}
		
		page_num++;
		write_size += page_size;
	}

	return 0;

}

static void nflashcalAddr(unsigned int uiStart, unsigned int uiLenth, unsigned int uiSectorSize, unsigned int* uiStartAddr, unsigned int*  uiStartLen, unsigned int* uiSectorAddr, unsigned int* uiSectorCount, unsigned int* uiEndAddr, unsigned int* uiEndLen)
{
	unsigned int ui;
	// only one sector
	if ((uiStart + uiLenth) < ((uiStart / uiSectorSize + 1) * uiSectorSize))
	{	// start	
		*uiStartAddr = uiStart;
		*uiStartLen = uiLenth;
		//middle
		*uiSectorAddr = 0x00;
		*uiSectorCount = 0x00;
		// end
		*uiEndAddr = 0x00;
		*uiEndLen = 0x00;
	}
	//more then one sector
	else
	{
		// start
		*uiStartAddr = uiStart;
		*uiStartLen = uiSectorSize - (uiStart % uiSectorSize);
		if(*uiStartLen == uiSectorSize)
		{
			*uiStartLen = 0x00;
		}
		// middle
		ui = uiLenth - *uiStartLen;
		*uiSectorAddr = *uiStartAddr + *uiStartLen;
		*uiSectorCount = ui / uiSectorSize;
		//end
		*uiEndAddr = *uiSectorAddr + (*uiSectorCount * uiSectorSize);
		*uiEndLen = ui % uiSectorSize;
	}
	//LDEBUG("calAddr:uiStart=%x; uiSectorSize=%x; uiLenth=%x;-> uiStartAddr=%x; uiStartLen=%x; uiSectorAddr=%x; uiSectorCount=%x; uiEndAddr=%x; uiEndLen=%x;\n",uiStart, uiSectorSize, uiLenth, *uiStartAddr, *uiStartLen, *uiSectorAddr, *uiSectorCount, *uiEndAddr, *uiEndLen);	
}


static int nflashWriteBlock(unsigned int uiAddr, unsigned int uiLen, unsigned char* pucBuffer)
{	
	int flag = 0;
	unsigned int uiStartAddr, uiOffset,start_page,len;
	uiOffset = uiAddr % block_size;
	uiStartAddr = uiAddr - uiOffset;
	//start_page = ((dst)/page_size);


	if(uiOffset == 0 && uiLen == block_size){
		flag = 1;
	}
	
#if 1//def CONFIG_RTK_NAND_BBT
	if(flag != 1){
		if(nand_read_ecc_ob(uiStartAddr, block_size, ptr_data, ptr_oob)){
			printf("%s: read blockv:%x pagev:%x fail!\n",__FUNCTION__, uiStartAddr/block_size, uiStartAddr/page_size);
	        return -1;
		}
		memcpy(ptr_data+uiOffset,pucBuffer,uiLen);
	}

	if(nand_erase_block(uiStartAddr)){
		printf("%s: erase blockv:%x pagev:%x fail!\n",__FUNCTION__, uiStartAddr/block_size, uiStartAddr/page_size);
		return -1;
	}

	if(flag != 1){
		len = uiAddr + uiLen - uiStartAddr;		
		if(nand_write_ecc_ob(uiStartAddr, len, ptr_data, ptr_oob)){
			printf("%s: nand_write_ecc addrv :%x error\n",__FUNCTION__, uiStartAddr);
			return -1;
		}
	}else{
		if(nand_write_ecc_ob(uiStartAddr, block_size, pucBuffer, ptr_oob)){
			printf("%s: nand_write_ecc addrv :%x error\n",__FUNCTION__, uiStartAddr);
			return -1;
		}
	}

#else
	/* need modify */
	while(rtk_block_isbad(start_page*page_size)){
		start_page+=ppb;
	}

	if(rtk_write_ecc_page(start_page*page_size, src+offset, block_size)){
		printf("HW ECC error on this block %d, just skip it!\n", (start_page/ppb));
		goto NEXT_BLOCK;
	}
	offset += block_size;//shift buffer ptr one block each time.

#endif
	return 0;
}

/* 	
	default read at DRAM_DIMAGE_ADDR=0xa0a00000 tmp value
*/
static /*unsigned*/ int nflashReadBlock(unsigned int uiAddr, unsigned int uiLen, unsigned char* pucBuffer,int checkEsc)
{
	
	unsigned int uiOffset,uiStartAddr;
	uiOffset = uiAddr % block_size;
	uiStartAddr = uiAddr - uiOffset;
	int i = 0;
	unsigned char flag = 0;
	//need check;
	//start_page = ((uiAddr)/page_size);

	#if 1//def CONFIG_RTK_NAND_BBT
	if(uiOffset == 0 && uiLen == block_size)
		flag = 1;

	if(flag == 1){
		if(nand_read_ecc_ob(uiStartAddr, block_size, pucBuffer, ptr_oob)){
	        return -1;
		}
	}
	else{
		if(nand_read_ecc_ob(uiStartAddr, block_size, ptr_data, ptr_oob)){
	        return -1;
		}
	}

	if(checkEsc){
		/* because read one block is 128k */
		if ( user_interrupt(0)==1 )  //return 1: got ESC Key
		{
			#if CONFIG_ESD_SUPPORT//patch for ESD
  	 		REG32(0xb800311c)|= (1<<23);
 			#endif
			//prom_printf("ret=%d  ------> line %d!\n",ret,__LINE__);
			return -1;
		}
	}
	#else
	while(rtk_block_isbad(start_page*page_size)){
		start_page+=ppb;
	}
	for(j=0;j<ppb;j++){
		if(rtk_read_ecc_page(start_page+j , ptr_data+ (block_size*i) + (j * page_size), ptr_oob, page_size)){
		    //printf("read ecc page :%d error\n", start_page+j);
			break;
		}
		 if(checkEsc){
		 
		 	gCHKKEY_CNT++;
			if( gCHKKEY_CNT>ppb)
			{	gCHKKEY_CNT=0;
				if ( user_interrupt(0)==1 )  //return 1: got ESC Key
				{
         			#if CONFIG_ESD_SUPPORT//patch for ESD
          	 		REG32(0xb800311c)|= (1<<23);
         			#endif
					//prom_printf("ret=%d  ------> line %d!\n",ret,__LINE__);
					return -1;
				}
			}
		}			     
	}

	#endif
	if(flag == 0)
		memcpy(pucBuffer,ptr_data+uiOffset,uiLen);
	return 0;
	
}

/*----------------------------------------------------------------------------------------------------------------*/
/* nand flash api function */

int nflashwrite(unsigned long dst, unsigned long src, unsigned long length)
{
	unsigned char need_retry = 0;
	unsigned int length2;
#ifdef CONFIG_RTK_NORMAL_BBT
	unsigned int offset;
#endif


	/* nand flash write function */
	unsigned int uiStartAddr, uiStartLen, uiSectorAddr, uiSectorCount, uiEndAddr, uiEndLen;
	int res = 0,i;
	unsigned char *puc = (unsigned char*)src;

	printf_test("%s:%d\n",__func__,__LINE__);
		
	block_size= rtkn->mtd->erasesize;				//change
	page_size = rtkn->mtd->writesize;				//change
	oob_size = rtkn->mtd->oobsize;					//change
	ppb = block_size/page_size;						//constant

	if(length == 0)
		return 0;
	

	printf_test("%s:%d\n",__func__,__LINE__);
	/* malloc */
	ptr_data = (unsigned char*)malloc(sizeof(char)*ppb*page_size);			//ptr_data len constant
	if(ptr_data == NULL ){
		return -1;
	}

	printf_test("%s:%d\n",__func__,__LINE__);
	ptr_oob  = (unsigned char*)malloc((sizeof(char)*ppb*oob_size));			//ptr_oob len constant
	if(ptr_oob == NULL){
		if(ptr_data)
			free(ptr_data);
		return -1;
	}
	printf_test("%s:%d\n",__func__,__LINE__);
	/* malloc 4 byte aligned check */
	if((unsigned int)ptr_data%4 != 0 || (unsigned int)ptr_oob%4 != 0){
		if(ptr_data)
			free(ptr_data);
		if(ptr_oob)
			free(ptr_oob);
		return -1;
	}
	memset(ptr_oob,0xff,(sizeof(char)*ppb*oob_size));
	printf_test("%s:%d\n",__func__,__LINE__);

	
#ifdef 	CONFIG_SPI_NAND_FLASH
	if(page_size != ROM_BOOT_PAGE_SIZE){
		if(dst < BOOT_SIZE){
			block_size = ROM_BOOT_PAGE_SIZE*ppb;
			page_size = ROM_BOOT_PAGE_SIZE;
			oob_size = ROM_BOOT_OOB_SIZE;

			if((dst+length) > BOOT_SIZE){
				need_retry = 1;
				length2 = length + dst - BOOT_SIZE;
				length = BOOT_SIZE - dst;
			}
		}
	}
#endif


WRITE_RETRY:

	nflashcalAddr(dst, length, block_size, &uiStartAddr, &uiStartLen, &uiSectorAddr, &uiSectorCount, &uiEndAddr, &uiEndLen);
	printf_test("%s:%d\n",__func__,__LINE__);
	if((uiSectorCount == 0x00) && (uiEndLen == 0x00))	// all data in the same sector
	{
#ifdef CONFIG_RTK_NORMAL_BBT
		while(1){
			offset = (uiStartAddr/block_size)*block_size;

			if(offset >= rtkn->nand_chip->chipsize){
				prom_printf("%s:%d,read exceed chipsize\n",__func__,__LINE__);
				res = -1;
				goto FINISH;
			}
			
			if(rtkn_block_bad(rtkn->mtd,offset,0)){
				uiStartAddr += block_size;
			}else
				break;
		}
#endif

	
		if(nflashWriteBlock(uiStartAddr, uiStartLen, puc) < 0){
			res = -1;
			goto FINISH;
		}
	}
	else
	{
		if(uiStartLen > 0)
		{
#ifdef CONFIG_RTK_NORMAL_BBT
			while(1){
				offset = (uiStartAddr/block_size)*block_size;
	
				if(offset >= rtkn->nand_chip->chipsize){
					prom_printf("%s:%d,read exceed chipsize\n",__func__,__LINE__);
					res = -1;
					goto FINISH;
				}
				
				if(rtkn_block_bad(rtkn->mtd,offset,0)){
					uiStartAddr += block_size;
					uiSectorAddr += block_size;
					uiEndAddr += block_size;
				}else
					break;
			}
#endif
		
			if(nflashWriteBlock(uiStartAddr, uiStartLen, puc) < 0){
				res = -1;
				goto FINISH;
			}
			puc += uiStartLen;
		}
		for(i = 0; i < uiSectorCount; i++)
		{
#ifdef CONFIG_RTK_NORMAL_BBT
			while(1){	
				if(uiSectorAddr >= rtkn->nand_chip->chipsize){
					prom_printf("%s:%d,read exceed chipsize\n",__func__,__LINE__);
					res = -1;
					goto FINISH;
				}
				
				if(rtkn_block_bad(rtkn->mtd,uiSectorAddr,0)){
					uiSectorAddr += block_size;
					uiEndAddr += block_size;
				}else
					break;
			}
#endif

			if(nflashWriteBlock(uiSectorAddr, block_size,puc) < 0){
				res = -1;
				goto FINISH;
			}
			puc += block_size;
			uiSectorAddr += block_size;
		}
		if(uiEndLen > 0)
		{
#ifdef CONFIG_RTK_NORMAL_BBT
			while(1){	
				if(uiEndAddr >= rtkn->nand_chip->chipsize){
					prom_printf("%s:%d,read exceed chipsize\n",__func__,__LINE__);
					res = -1;
					goto FINISH;
				}
				
				if(rtkn_block_bad(rtkn->mtd,uiEndAddr,0)){
					uiEndAddr += block_size;
				}else
					break;
			}
#endif

			if(nflashWriteBlock(uiEndAddr, uiEndLen, puc) < 0){
				res = -1;
				goto FINISH;
			}
		}
	}

#ifdef 	CONFIG_SPI_NAND_FLASH
	if(need_retry){
		length = length2;
		block_size = rtkn->mtd->erasesize;
		page_size = rtkn->mtd->writesize;
		oob_size = rtkn->mtd->oobsize;
		dst = BOOT_SIZE;
		need_retry = 0;
		goto WRITE_RETRY;
	}
#endif

FINISH:
	if(ptr_oob){
		free(ptr_oob);
		ptr_oob = NULL;
	}
	if(ptr_data){
		free(ptr_data);
		ptr_data = NULL;
	}
	return res;
	
}


int nflashread (unsigned long dst, unsigned int src, unsigned long length,int checkEsc)
{
	unsigned char need_retry = 0;
	unsigned int length2;

	int i,res = 0;
	unsigned int uiStartAddr, uiStartLen, uiSectorAddr, uiSectorCount, uiEndAddr, uiEndLen;
#ifdef CONFIG_RTK_NORMAL_BBT
	unsigned int offset;
#endif
	unsigned char *puc = (unsigned char*)dst;

	block_size= rtkn->mtd->erasesize;		//change
	page_size = rtkn->mtd->writesize;		//change
	oob_size = rtkn->mtd->oobsize;			//change
	ppb = block_size/page_size;				//constant
	
	if(length == 0)
		return 0;

	ptr_data = (unsigned char*)malloc(sizeof(char)*ppb*page_size);		//ptr_data len 	constant
	if(ptr_data == NULL ){
		return -1;
	}
	ptr_oob  = (unsigned char*)malloc((sizeof(char)*ppb*oob_size));		//ptr_oob len 	constant
	if(ptr_oob == NULL){
		if(ptr_data)
			free(ptr_data);
		return -1;
	}

	/* malloc 4 byte aligned check */
	if((unsigned int)ptr_data%4 != 0 || (unsigned int)ptr_oob%4 != 0){
		if(ptr_data)
			free(ptr_data);
		if(ptr_oob)
			free(ptr_oob);
		return -1;
	}
	
#ifdef 	CONFIG_SPI_NAND_FLASH
	if(page_size != ROM_BOOT_PAGE_SIZE){
		if(src < BOOT_SIZE){
			block_size = ROM_BOOT_PAGE_SIZE*ppb;
			page_size = ROM_BOOT_PAGE_SIZE;
			oob_size = ROM_BOOT_OOB_SIZE;
	
			if((src+length) > BOOT_SIZE){
				need_retry = 1;
				length2 = length + src - BOOT_SIZE;
				length = BOOT_SIZE - src;
			}
		}
	}
#endif

READ_RETRY:
	nflashcalAddr(src, length, block_size, &uiStartAddr, &uiStartLen, &uiSectorAddr, &uiSectorCount, &uiEndAddr, &uiEndLen);
	
	
	if((uiSectorCount == 0x00) && (uiEndLen == 0x00))	// all data in the same sector
	{
#ifdef CONFIG_RTK_NORMAL_BBT
		while(1){
			offset = (uiStartAddr/block_size)*block_size;

			if(offset >= rtkn->nand_chip->chipsize){
				prom_printf("%s:%d,read exceed chipsize\n",__func__,__LINE__);
				res = -1;
				goto FINISH;
			}
			
			if(rtkn_block_bad(rtkn->mtd,offset,0)){
				uiStartAddr += block_size;
			}else
				break;
		}
#endif
		if(nflashReadBlock(uiStartAddr, uiStartLen, puc,checkEsc) < 0){
			res = -1;
			goto FINISH;
		}
	}
	else
	{
		if(uiStartLen > 0)
		{
#ifdef CONFIG_RTK_NORMAL_BBT
			while(1){
				offset = (uiStartAddr/block_size)*block_size;
	
				if(offset >= rtkn->nand_chip->chipsize){
					prom_printf("%s:%d,read exceed chipsize\n",__func__,__LINE__);
					res = -1;
					goto FINISH;
				}
				
				if(rtkn_block_bad(rtkn->mtd,offset,0)){
					uiStartAddr += block_size;
					uiSectorAddr +=block_size;
					uiEndAddr += block_size;
				}else
					break;
			}
#endif

			if(nflashReadBlock(uiStartAddr, uiStartLen, puc,checkEsc) < 0){
				res = -1;
				goto FINISH;
			}
			puc += uiStartLen;
		}
		for(i = 0; i < uiSectorCount; i++)
		{
#ifdef CONFIG_RTK_NORMAL_BBT
			while(1){	
				if(uiSectorAddr >= rtkn->nand_chip->chipsize){
					prom_printf("%s:%d,read exceed chipsize\n",__func__,__LINE__);
					res = -1;
					goto FINISH;
				}
				
				if(rtkn_block_bad(rtkn->mtd,uiSectorAddr,0)){
					uiSectorAddr += block_size;
					uiEndAddr += block_size;
				}else
					break;
			}
#endif
		
			if(nflashReadBlock(uiSectorAddr,block_size, puc,checkEsc) < 0){
				res = -1;
				goto FINISH;
			}
			puc += block_size;
			uiSectorAddr += block_size;
		}
		if(uiEndLen > 0)
		{
#ifdef CONFIG_RTK_NORMAL_BBT
			while(1){	
				if(uiEndAddr >= rtkn->nand_chip->chipsize){
					prom_printf("%s:%d,read exceed chipsize\n",__func__,__LINE__);
					res = -1;
					goto FINISH;
				}
				
				if(rtkn_block_bad(rtkn->mtd,uiEndAddr,0)){
					uiEndAddr += block_size;
				}else
					break;
			}
#endif
			if(nflashReadBlock(uiEndAddr, uiEndLen, puc,checkEsc) < 0){
				res = -1;
				goto FINISH;
			}
		}
	}

#ifdef 	CONFIG_SPI_NAND_FLASH
	if(need_retry){
		length = length2;
		block_size = rtkn->mtd->erasesize;
		page_size = rtkn->mtd->writesize;
		oob_size = rtkn->mtd->oobsize;
		src = BOOT_SIZE;
		need_retry = 0;
		goto READ_RETRY;
	}
#endif

FINISH:
	if(ptr_oob){
		free(ptr_oob);
		ptr_oob = NULL;
	}
	if(ptr_data){
		free(ptr_data);
		ptr_data = NULL;
	}
	return res;
}


int nflasherase(unsigned long addr, unsigned long len)
{
	unsigned char need_retry = 0;
	unsigned int length2 = 0;
	unsigned int erased_size = 0;

	block_size= rtkn->mtd->erasesize;				//change
	page_size = rtkn->mtd->writesize;				//change
	oob_size = rtkn->mtd->oobsize;					//change
	ppb = block_size/page_size;						//constant

	if(aligned(addr,block_size) != 0){
		printf("addr=%x not block_size=%x aligned\n",addr,block_size);
		return -1;
	}
	
#ifdef 	CONFIG_SPI_NAND_FLASH
	if(page_size != ROM_BOOT_PAGE_SIZE){
		if(addr < BOOT_SIZE){
			block_size = ROM_BOOT_PAGE_SIZE*ppb;
			page_size = ROM_BOOT_PAGE_SIZE;
			oob_size = ROM_BOOT_OOB_SIZE;
	
			if((addr+len) > BOOT_SIZE){
				need_retry = 1;
				length2 = len + addr - BOOT_SIZE;
				len = BOOT_SIZE - addr;
			}
		}
	}
#endif

ERASE_RETRY:
	while(erased_size < len){
#ifdef CONFIG_RTK_NORMAL_BBT
		if(uboot_scrub == 0){
			while(1){	
				if(addr >= rtkn->nand_chip->chipsize){
					prom_printf("%s:%d,read exceed chipsize\n",__func__,__LINE__);
					return -1;
				}
				
				if(rtkn_block_bad(rtkn->mtd,addr,0)){
					addr += block_size;
				}else
					break;
			}
		}
#endif
		if(nand_erase_block(addr) < 0){
			/* to do */
			;
		}
		addr += block_size;
		erased_size += block_size;
	}


#ifdef 	CONFIG_SPI_NAND_FLASH
	if(need_retry){
		len = length2;
		block_size = rtkn->mtd->erasesize;
		page_size = rtkn->mtd->writesize;
		oob_size = rtkn->mtd->oobsize;
		addr = BOOT_SIZE;
		need_retry = 0;
		goto ERASE_RETRY;
	}
#endif

	return 0;
}

int nflashscanbbt(void)
{
	return 0;
}

int nflashprobe(void)
{
	if(board_nand_init() < 0){
		/* free oob_poi */
		if(rtk_boot_oob_poi != NULL){
			kfree(rtk_boot_oob_poi);
			rtk_boot_oob_poi = NULL;
		}
		return -1;
	}
	return 0;
} 


/* pio read/write must page+oob aligned */

/* must page aligned */
int nflashpioread(unsigned int flashaddr,unsigned int imageaddr,unsigned int len)
{
	int ret = 0;
	unsigned int page;
	unsigned int readlen = 0;

	block_size= rtkn->mtd->erasesize;
	page_size = rtkn->mtd->writesize;
	oob_size = rtkn->mtd->oobsize;	

	if((flashaddr % (page_size+oob_size)) != 0){
		prom_printf("flashaddr must 0x%x aligned\n",(page_size+oob_size)); 
		return -1;
	}

	while(readlen < len){
		page = (flashaddr+readlen)/(page_size+oob_size);
		
		ret = nflashpioread_Page(page,imageaddr+readlen,(page_size+oob_size));
		
		if(ret < 0)
			return -1;

		//flashaddr+= page_size+oob_size;
		readlen += page_size+oob_size;
	}

	return 0;
}

int nflashpiowrite(unsigned int flashaddr,unsigned int imageaddr,unsigned int len)
{
	int ret = 0;
	unsigned int page;
	unsigned int readlen = 0;	

	block_size= rtkn->mtd->erasesize;
	page_size = rtkn->mtd->writesize;
	oob_size = rtkn->mtd->oobsize;	

	if((flashaddr % (page_size+oob_size)) != 0){
		prom_printf("flashaddr must 0x%x aligned\n",(page_size+oob_size)); 
		return -1;
	}

	while(readlen < len){
		page = (flashaddr+readlen)/(page_size+oob_size);
		
		ret = nflashpiowrite_Page(page,imageaddr+readlen,(page_size+oob_size));
		
		if(ret < 0)
			return -1;

		//flashaddr+= page_size+oob_size;
		readlen += page_size+oob_size;
	}

	return 0;
}

void nflashblockcheck(unsigned int blockstart,unsigned int blockend)
{
	/* need to print nand bad block */
	
}

extern unsigned long file_length_to_client;
int nflasheccgen(unsigned char* dma_addr,unsigned char* des_addr,unsigned char* p_eccbuf,unsigned int length)
{
	unsigned int page_num,src_addr,page_start,i;
	page_size = rtkn->mtd->writesize;
	oob_size = rtkn->mtd->oobsize;	 

#ifdef 	CONFIG_SPI_NAND_FLASH
	if(page_size != ROM_BOOT_PAGE_SIZE){
		page_size = ROM_BOOT_PAGE_SIZE;
		oob_size = ROM_BOOT_OOB_SIZE;	
	}
#endif


	page_num = (length + (page_size-1))/page_size;

    memset(des_addr, 0xff,(page_num * (page_size+oob_size)));
    src_addr = (unsigned int)dma_addr;
    for(i = 0; i <= page_num; i++)
    {
    	memset(p_eccbuf,0xff,oob_size);
		memset(des_addr,0xff,rtkn->mtd->writesize+rtkn->mtd->oobsize);
        nflash_ecc_decode_func((void*)src_addr, (void*)des_addr,p_eccbuf,i);
		src_addr = src_addr+ page_size;
		des_addr = des_addr + (rtkn->mtd->writesize+rtkn->mtd->oobsize);
		//des_addr = des_addr + (page_size+oob_size);
		//delay(1000);
    }

	file_length_to_client = page_num*(rtkn->mtd->writesize+rtkn->mtd->oobsize);
	
    return 0;
}


/* get bad block from flash */
int nflashisBadBlock(unsigned int offset,unsigned int length)
{
	unsigned int block,ppb;
	unsigned int block_start,block_end;

	block_size = rtkn->mtd->erasesize;
	page_size = rtkn->mtd->writesize;
	ppb = block_size/page_size;

	if(aligned(offset,block_size)){
		prom_printf("%s:%d,offset should %d aligned\n",__func__,__LINE__,block_size);
		return -1;
	}

	if(aligned(length,block_size)){
		prom_printf("%s:%d,length should %d aligned\n",__func__,__LINE__,block_size);
		return -1;
	}


	block_start = offset/block_size;
	block_end = (offset+length)/block_size;

	for(block = block_start;block <block_end;block++){
		if(nflash_is_bad_block(ppb*block*page_size) != 0)
			prom_printf("%d is bad\n",block);
	}
	return 0;
}

int nflashMarkBadBlock(unsigned int offset)
{
	block_size = rtkn->mtd->erasesize;

	if(aligned(offset,block_size)){
		prom_printf("%s:%d,offset should %d aligned\n",__func__,__LINE__,block_size);
		return -1;
	}

	rtkn_block_markbad(rtkn->mtd,offset);

	return 0;
}

int nflashGetSetFeature(char* cmd,unsigned int address,unsigned int value,unsigned char dieid)
{
	if(strcmp(cmd,"set") == 0){
		nflash_setFeature(address,value,dieid);
	}else if(strcmp(cmd,"get") == 0){
		prom_printf("Get 0x%x address Feature = 0x%x\n",address,nflash_getFeature(address,dieid));
	}else{
		prom_printf("param error\n");
	}

	return 0;
}

int nflashSpeedTest(void)
{
	nflash_speed();
}






/*----------------------------------------------------------------------------------------------------------------*/



