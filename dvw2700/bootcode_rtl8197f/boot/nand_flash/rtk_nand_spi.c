#include "./rtkn_nand/rtknflash.h"
#include <nand_spi/soc.h>

int nflashpioread_Page(unsigned int page,unsigned int imageaddr, int len)
{
	unsigned char dieid = 0;
	unsigned int page_per_die;
	if(rtkn->chip_param.dienum > 1){
		page_per_die = rtkn->chip_param.num_block*rtkn->chip_param.num_chunk_per_block;
		dieid = page/page_per_die;
		nand_spi_die_select(dieid);
	}

	nand_spi_pio_read_data(imageaddr,len,page,0);
	return 0;
}

int nflashpiowrite_Page(unsigned int page,unsigned int imageaddr, int len)
{
	unsigned char dieid = 0;
	unsigned int page_per_die;
	if(rtkn->chip_param.dienum > 1){
		page_per_die = rtkn->chip_param.num_block*rtkn->chip_param.num_chunk_per_block;
		dieid = page/page_per_die;
		nand_spi_die_select(dieid);
	}

	nand_spi_pio_write_data(imageaddr,len,page,0);
	return 0;
}

int nflash_ecc_decode_func(void* src_addr,void*  dest_addr,void* p_eccbuf,unsigned int pagenum)
{
	if(rtkn->chip_param.dienum > 1){
		nand_spi_die_select(0);
	}

	nand_spi_2KB_ecc_encode_buffered((void*)src_addr, (void*)dest_addr,p_eccbuf,pagenum);
	return 0;
}


unsigned int nflash_getFeature(unsigned int address,unsigned char dieid)
{
	if(rtkn->chip_param.dienum > 1)
		nand_spi_die_select(dieid);
	
	return nand_spi_get_feature_register(address);
}

void nflash_setFeature(unsigned int address, unsigned int value,unsigned char dieid)
{
	if(rtkn->chip_param.dienum > 1)
		nand_spi_die_select(dieid);

	nand_spi_set_feature_register(address,value);
	return;
}

int nflashreadTest(void)
{
	unsigned int offset,size,block_size,page_size;
	unsigned int jffs0,jffs1;
	unsigned int len = 0,page;
	unsigned char* buff = NULL;

	block_size = rtkn->mtd->erasesize;
	page_size = rtkn->mtd->writesize;
	
	offset = 0x900000;
	size = 0x1000000;
	buff = (unsigned char*)0xa0a00000;


	/* sio */
	jffs0 = get_timer_jiffies();
	while(len < size){
		page = (offset+len)/page_size;

		nand_spi_chunk_read(buff+len,page,2048,64);
		len += page_size;
	}
	jffs1 = get_timer_jiffies();
	prom_printf("driver read speed: start=0x%x,end=0x%x,speed=%dms/block\n",jffs0,jffs1,((jffs1-jffs0)*10/(size/block_size)));


	jffs0 = get_timer_jiffies();
	if(nflashread((unsigned long)buff,offset,size,0) != 0){
		prom_printf("read fail\n");
		return -1;
	}
	jffs1 = get_timer_jiffies();
	prom_printf("api read speed: start=0x%x,end=0x%x,speed=%dms/block\n",jffs0,jffs1,((jffs1-jffs0)*10/(size/block_size)));

	return 0;
}

int nflashwriteTest(void)
{
	unsigned int offset,size,block_size,page_size;
	unsigned int jffs0,jffs1;
	unsigned int len = 0,page;
	unsigned char* buff = NULL;

	block_size = rtkn->mtd->erasesize;
	page_size = rtkn->mtd->writesize;

	offset = 0x900000;
	size = 0x1000000;
	buff = (unsigned char*)0xa0a00000;
	memset(buff,0xff,size);

	jffs0 = get_timer_jiffies();
	while(len < size){
		page = (offset+len)/page_size;
		nand_spi_chunk_write(buff+len,page,2048,64);
		len += page_size;
	}
	jffs1 = get_timer_jiffies();
	prom_printf("driver write speed: start=0x%x,end=0x%x,speed=%dms/block\n",jffs0,jffs1,((jffs1-jffs0)*10/(size/block_size)));

	jffs0 = get_timer_jiffies();
	if(nflashwrite(offset,(unsigned long)buff,size) != 0){
		prom_printf("write fail\n");
		return -1;
	}
	jffs1 = get_timer_jiffies();
	prom_printf("api write speed: start=0x%x,end=0x%x,speed=%dms/block\n",jffs0,jffs1,((jffs1-jffs0)*10/(size/block_size)));

	return 0;
}


int nflasheraseTest(void)
{
	unsigned int offset,size,block_size,page_size;
	unsigned int jffs0,jffs1;
	unsigned int len = 0,page;
	unsigned char* buff = NULL;

	block_size = rtkn->mtd->erasesize;
	page_size = rtkn->mtd->writesize;

	offset = 0x900000;
	size = 0x1000000;

	jffs0 = get_timer_jiffies();
	if(nflasherase(offset,size) != 0){
		prom_printf("erase fail\n");
		return -1;
	}
	jffs1 = get_timer_jiffies();

	prom_printf("erase speed: start=0x%x,end=0x%x,speed=%dms/block\n",jffs0,jffs1,((jffs1-jffs0)*10/(size/block_size)));
}

void nflash_speed(void)
{
	#define SPI_NAND_IO_TYPE	6
	int i;

	for(i = 0;i <= SPI_NAND_IO_TYPE;i++){
		if(rtkn_test_set_ioCfg(i) == 0){
			nflashreadTest();
			nflasheraseTest();
			nflashwriteTest();
		}
	}
	return;
}

/* nand scan function, used by rtknflash driver */
static unsigned long __ffs(unsigned long value)
{
        int num = 0;

#if BITS_PER_LONG == 64
        if ((value & 0xffffffff) == 0) {
                num += 32;
                value >>= 32;
        }
#endif
        if ((value & 0xffff) == 0) {
                num += 16;
                value >>= 16;
        }
        if ((value & 0xff) == 0) {
                num += 8;
                value >>= 8;
        }
        if ((value & 0xf) == 0) {
                num += 4;
                value >>= 4;
        }
        if ((value & 0x3) == 0) {
                num += 2;
                value >>= 2;
        }
        if ((value & 0x1) == 0)
                num += 1;
        return num;
}

int nand_scan(struct mtd_info *mtd, int maxchips)
{

#if 0
	/* probe chip */
	plr_nand_spi_info_t *nand_info = (plr_nand_spi_info_t *)nand_spi_probe_spi_nand_chip();
	if(nand_info == VZERO){
		printf("cannot find nand spi chip\n");
		return -1;
	}
#else
	if(nand_spi_probe_spi_nand_chip() != 0){
		printf("cannot find nand spi chip\n");
		return -1;
	}
#endif
	
	/* set mtd nand info */
#if 0
	unsigned int chunk_size = nand_info->chunk_size;
	unsigned int ppb = nand_info->num_chunk_per_block;
	unsigned int blocknum = nand_info->num_block; 
#else
	unsigned int chunk_size = rtkn->chip_param.pagesize;
	unsigned int ppb = rtkn->chip_param.num_chunk_per_block;
	unsigned int oobsize = rtkn->chip_param.oobsize;
	unsigned int blocknum = rtkn->chip_param.num_block;
	unsigned int dienum = rtkn->chip_param.dienum;
	unsigned int id = rtkn->chip_param.id;
#endif
	struct nand_chip *nand = rtkn->nand_chip;

	/* nand_chip */
	nand->chipsize = blocknum*ppb*chunk_size*dienum;
	nand->page_shift = __ffs(chunk_size);
    nand->phys_erase_shift = __ffs(ppb*chunk_size);
    nand->chip_shift =  __ffs(nand->chipsize );
    nand->pagemask = (nand->chipsize >> nand->page_shift) - 1;
    nand->numchips = 1;						//temp code 

	/* MTD */
	mtd->erasesize = ppb*chunk_size;
	mtd->writesize = chunk_size;
	mtd->writebufsize = chunk_size;
	mtd->oobsize = oobsize;			
	mtd->erasesize_shift = nand->phys_erase_shift;
	mtd->writesize_shift =  nand->page_shift;
	mtd->size = nand->chipsize;

	/* set chip param */
	rtkn->chip_param.isLastPage = 0;

	prom_printf("\n");
	prom_printf("SPI Nand ID=%x\n",id);
	prom_printf("SPI Nand die chipsize=0x%x byte\n",chunk_size*ppb*blocknum);
	prom_printf("SPI Nand dienum=%d,\n",dienum);
	prom_printf("SPI Nand blocksize=0x%x byte,\n",chunk_size*ppb);
	prom_printf("SPI Nand pagesize=0x%x byte,\n",chunk_size);
	prom_printf("SPI Nand oobsize=0x%x byte,\n",oobsize);
	
	
	
	/* malloc oob_poi */
	nand->oob_poi = (unsigned char*)malloc(mtd->oobsize);
	if(nand->oob_poi == NULL){
		prom_printf("malloc nand->oob_poi fail\n");
		return -1;
	}

	extern unsigned char* rtk_boot_oob_poi;
	rtk_boot_oob_poi = nand->oob_poi;

#if 0
	extern int uboot_scrub;
	uboot_scrub = 1;
	
	if(nflasherase(0,nand->chipsize) < 0){
		prom_printf("erase fail\n");
	}else
		prom_printf("erase success\n");

	uboot_scrub = 0;

#endif

#if 1
	/* bbt init */
	if(rtkn_scan_bbt(mtd) < 0){
		prom_printf("init bbt failed\n");
		return -1;
	}
#endif
	
	return 0;	
}

/*----------------------------------------------------------------------------------------------------------------*/
