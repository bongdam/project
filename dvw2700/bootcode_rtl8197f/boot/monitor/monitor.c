
#include <linux/interrupt.h>
#include <asm/system.h>
#include <string.h>
#include "monitor.h"
#include "etherboot.h"
#include "nic.h"

#include <asm/rtl8196x.h> 
#include <asm/mipsregs.h>	//wei add
#include <asm/cacheops.h>	//wei add

#if defined(CONFIG_SPI_FLASH) 
//#include "spi_flash.h"
#endif

#include <rtl8196x/asicregs.h>        

#include <bspchip.h>
#ifdef CONFIG_RLX5181_TEST
#include "monitor_commands.h"
#include "monitor_commands.c"
#endif

#ifdef CONFIG_RTL8196E
#define SWITCH_CMD 0
#else
#define SWITCH_CMD 1
#endif

#define SYS_INI_STATUS (SYS_BASE +0x04)
#define SYS_HW_STRAP (SYS_BASE +0x08)
#define SYS_CLKMANAGE (SYS_BASE +0x10)
//hw strap
#define ST_SYNC_OCP_OFFSET 9
#define CK_M2X_FREQ_SEL_OFFSET 10
#define ST_CPU_FREQ_SEL_OFFSET 13
#define ST_CPU_FREQDIV_SEL_OFFSET 19
#define ST_BOOTPINSEL (1<<0)
#define ST_DRAMTYPE (1<<1)
#define ST_BOOTSEL (1<<2)
#define ST_PHYID (0x3<<3) //11b 
#define ST_EN_EXT_RST (1<<8)
#define ST_SYNC_OCP (1<<9)
#define ST_NRFRST_TYPE (1<<17)
#define SYNC_LX (1<<18)
#define ST_CPU_FREQDIV_SEL (0x7<<19)
#define ST_EVER_REBOOT_ONCE (1<<23)
#define ST_SYS_DBG_SEL  (0x3f<<24)
#define ST_PINBUS_DBG_SEL (3<<30)

extern unsigned int	_end;

extern unsigned char 	ethfile[20];
extern struct arptable_t	arptable[MAX_ARP];
#define MAIN_PROMPT						"<RealTek>"
#define putchar(x)	serial_outc(x)
#define IPTOUL(a,b,c,d)	((a << 24)| (b << 16) | (c << 8) | d )

#ifdef CONFIG_NIC_LOOPBACK
int nic_loopback = 0;
#endif

#if 1 //wei add for 8198C
extern int CmdL2Disable( int argc, char* argv[] );
extern int CmdCPUCLK( int argc, char* argv[] );
extern int CmdCore1Wakeup( int argc, char* argv[] );
extern int Cmd_Test_TimerX(int argc, char* argv[]);
extern int GPHY_BIST(int argc, char* argv[]);  //wei add
extern int GPHY_DRF_BIST(int argc, char* argv[]);  //wei add

extern int Cmd_AllBistTest(int argc, char* argv[]);  //wei add

#endif



int YesOrNo(void);
int CmdHelp( int argc, char* argv[] );


#if defined(CONFIG_BOOT_DEBUG_ENABLE)
int CmdDumpWord( int argc, char* argv[] );
int CmdDumpByte( int argc, char* argv[] ); //wei add
int CmdWriteWord( int argc, char* argv[] );
int CmdWriteByte( int argc, char* argv[] );
int CmdWriteHword( int argc, char* argv[] );
int CmdWriteAll( int argc, char* argv[] );
int CmdCmp(int argc, char* argv[]);
int CmdMEMCPY(int argc, char* argv[]);
int CmdIp(int argc, char* argv[]);
int CmdAuto(int argc, char* argv[]);
#endif
int CmdLoad(int argc, char* argv[]);

int CmdCfn(int argc, char* argv[]);


//#define CONFIG_PCIE_MODULE 1
#ifdef CONFIG_PCIE_MODULE
extern int PCIE_Host_RESET(int argc, char *argv[]);
extern int PCIE_Host_Init(int argc, char *argv[]);
extern int Test_HostPCIE_DataLoopback(int argc, char *argv[]);
extern int PCIE_PowerDown(int argc, char *argv[]);
extern int HostPCIe_MDIORead(int argc, char* argv[]); 
extern int HostPCIe_MDIOWrite(int argc, char* argv[]); 
extern int PCIE_PHYLoop(int argc, char *argv[]);
extern int HostPCIe_TestINT(int argc, char *argv[]);
#endif



#ifdef CONFIG_SPI_FLASH
	int CmdSFlw(int argc, char* argv[]);
	int CmdFlr(int argc, char* argv[]);
	extern void auto_spi_memtest_8198(unsigned long DRAM_starting_addr, unsigned int spi_clock_div_num);
#endif

#if defined (CONFIG_NAND_FLASH)
int CmdNANDID(int argc, char* argv[]);
int CmdNANDBE(int argc, char* argv[]);
int CmdNANDSCRUB(int argc, char* argv[]);
int CmdNAND_PIO_READ(int argc, char* argv[]);
int CmdNAND_PIO_WRITE(int argc, char* argv[]);
int CmdNANDR(int argc, char* argv[]);
int CmdNANDW(int argc, char* argv[]);
int CmdNANDECCGEN(int argc, char* argv[]);
int  CmdNANDBadBlockDetect(int argc, char* argv[]);
int  CmdNANDMarkBadBlock(int argc, char* argv[]);
int  CmdNANDGetSetFeature(int argc, char* argv[]);
int  CmdNANDSpeedTest(int argc, char* argv[]);
extern char* rtk_nand_read_id(void);
extern int rtk_nand_probe(void);
extern int rtk_erase_block (int page);                      // 1 block=64 page
extern int rtk_read_ecc_page (unsigned long flash_address, unsigned char *image_addr,
unsigned int image_size,char ecc_enable);
extern int rtk_write_ecc_page (unsigned long flash_address, unsigned char *image_addr,
unsigned int image_size);
#if defined(SUPPORT_TFTP_CLIENT)
int CmdTFTPC(int argc, char* argv[]);
int check_tftp_client_state();
#endif
#endif

#if defined(CONFIG_PARAM_PASSING)
int CmdInitrd(int argc, char* argv[]);
#endif

#if defined(CONFIG_FS_JFFS2)
int CmdJffs2Ls(int argc, char* argv[]);
int CmdJffs2Fsinfo(int argc, char* argv[]);
int CmdJffs2Fsload(int argc, char* argv[]);
#endif

//int CmdTimer(int argc, char* argv[]);
//int CmdMTC0SR(int argc, char* argv[]);  //wei add
//int CmdMFC0SR(int argc, char* argv[]);  //wei add
//int CmdTFTP(int argc, char* argv[]);  //wei add
#if defined(CONFIG_BOOT_DEBUG_ENABLE)
#endif

#ifdef CONFIG_IIS_TEST
int TestCmd_IIS( int argc, char* argv[]);
int TestCmd_IISSTOP( int argc, char* argv[]);
int TestCmd_IISSETTING( int argc, char* argv[]);
int TestCmd_I2C( int argc, char* argv[]);
int TestCmd_GPIO(int argc, char* argv[]);
int TestCmd_GPIOR(int argc, char* argv[]);
#endif
//Ziv
#ifdef WRAPPER
	#ifndef CONFIG_SPI_FLASH
		//write bootcode to flash from my content
		int CmdWB(int argc, char* argv[]);

	#endif
	
	#ifdef CONFIG_SPI_FLASH
		int CmdSWB(int argc, char* argv[]);
	#endif
extern char _bootimg_start, _bootimg_end;
#endif




#ifdef  CONFIG_DRAM_TEST
	int Dram_test_entry(int argc, char* argv[]);
	int Dram_test(int argc, char* argv[]);
#endif



#ifdef  CONFIG_SPI_TEST
	int CmdSTEST(int argc, char* argv[]);               //JSW: add for SPI/SDRAM auto-memory-test program
#endif


#ifdef CONFIG_CPUsleep_PowerManagement_TEST
	int CmdCPUSleep(int argc, char* argv[]);
	void CmdCPUSleepIMEM(void);
#endif



#if SWITCH_CMD
int TestCmd_MDIOR(int argc, char* argv[]);  //wei add
int TestCmd_MDIOW(int argc, char* argv[]);  //wei add
#endif

#ifndef CONFIG_RTL8196E
int CmdXModem(int argc, char* argv[]);  //wei add
#endif

#if defined(CONFIG_SW_8367R) || defined(CONFIG_SW_83XX)
int CmdDump8370Reg( int argc, char* argv[] );
int CmdWrite8370Reg( int argc, char* argv[] );
#endif

int CmdEthStartup(int argc, char* argv[]);

#ifdef CONFIG_CRYPTO_DEV_REALTEK
int CmdCrypto(int argc, char* argv[]);
int CmdCrypto_Test(int argc, char* argv[]);
#endif

/*Cyrus Tsai*/
/*move to ehterboot.h
#define TFTP_SERVER 0
#define TFTP_CLIENT 1
*/
extern struct arptable_t  arptable_tftp[3];
/*Cyrus Tsai*/

//extern int flasherase(unsigned long src, unsigned int length);
//extern int flashwrite(unsigned long dst, unsigned long src, unsigned long length);
//extern int flashread (unsigned long dst, unsigned long src, unsigned long length);

extern int write_data(unsigned long dst, unsigned long length, unsigned char *target);
extern int read_data (unsigned long src, unsigned long length, unsigned char *target);

/*Cyrus Tsai*/
extern unsigned long file_length_to_server;
extern unsigned long file_length_to_client;
extern unsigned long image_address; 
/*this is the file length, should extern to flash driver*/
/*Cyrus Tsai*/

#if defined(RTL8198)
#define WRITE_MEM32(addr, val)   (*(volatile unsigned int *) (addr)) = (val)
#define WRITE_MEM16(addr, val)   (*(volatile unsigned short *) (addr)) = (val)
#define READ_MEM32(addr)         (*(volatile unsigned int *) (addr))

#define PCRAM_BASE       (0x4100+SWCORE_BASE)
#define PITCR                  (0x000+PCRAM_BASE)       /* Port Interface Type Control Register */
#define PCRP0                 (0x004+PCRAM_BASE)       /* Port Configuration Register of Port 0 */
#define PCRP1                 (0x008+PCRAM_BASE)       /* Port Configuration Register of Port 1 */
#define PCRP2                 (0x00C+PCRAM_BASE)       /* Port Configuration Register of Port 2 */
#define PCRP3                 (0x010+PCRAM_BASE)       /* Port Configuration Register of Port 3 */
#define PCRP4                 (0x014+PCRAM_BASE)       /* Port Configuration Register of Port 4 */
#define EnablePHYIf        (1<<0)                           /* Enable PHY interface.                    */
#endif




//------------------------------------------------------------------------------
/********   caculate CPU clock   ************/
int check_cpu_speed(void);
void timer_init(unsigned long lexra_clock);
static void timer_interrupt(int num, void *ptr, struct pt_regs * reg);
struct irqaction irq_timer = {timer_interrupt, 0, 8, "timer", NULL, NULL};                                   
static volatile unsigned int jiffies=0;
static void timer_interrupt(int num, void *ptr, struct pt_regs * reg)
{
	//dprintf("jiff=%x\r\n",jiffies);
	//flush_WBcache();
	//rtl_outl(TCIR,rtl_inl(TCIR));
	REG32(BSP_TCIR)|=(1<<29);

	//if(jiffies==0x80)
	//REG32(GIMR_REG)&= ~(1<<8);
	
	jiffies++;
}

volatile unsigned int get_timer_jiffies(void)
{
	return jiffies;
}

//------------------------------------------------------------------------------
void timer_init(unsigned long lexra_clock)
{
    /* Set timer mode and Enable timer */
    REG32(BSP_TCCNR) = (0<<31) | (0<<30);	//using time0
    //REG32(TCCNR_REG) = (1<<31) | (0<<30);	//using counter0

	#define DIVISOR     0xE
	#define DIVF_OFFSET                         16		
    REG32(BSP_CDBR) = (DIVISOR) << DIVF_OFFSET;
    
    /* Set timeout per msec */

	int SysClkRate = lexra_clock;	 /* CPU 200MHz */

	#define TICK_100MS_FREQ  4    /* 10 Hz */
	#define TICK_10MS_FREQ  100  /* 100 Hz */
	#define TICK_1MS_FREQ   1000 /* 1K Hz */
	
	#define TICK_FREQ       TICK_10MS_FREQ	
   
      REG32(BSP_TC0DATA) = (((SysClkRate / DIVISOR) / TICK_FREQ) + 1) <<4;

         
    /* Set timer mode and Enable timer */
    REG32(BSP_TCCNR) = (1<<31) | (1<<30);	//using time0
    /* We must wait n cycles for timer to re-latch the new value of TC1DATA. */
	int c;	
	for( c = 0; c < DIVISOR; c++ );
	

      /* Set interrupt mask register */
    //REG32(GIMR_REG) |= (1<<8);	//request_irq() will set 

    /* Set interrupt routing register */
  // RTL8198
    //REG32(IRR1_REG) = 0x00050004;  //uart:IRQ5,  time0:IRQ4
    REG32(BSP_IRR0) = 0x20000000;
   
    
    /* Enable timer interrupt */
    REG32(BSP_TCIR) = (1<<31);
}
//------------------------------------------------------------------------------

__inline__ void
__delay(unsigned long loops)
{
	__asm__ __volatile__ (
		".set\tnoreorder\n"
		"1:\tbnez\t%0,1b\n\t"
		"subu\t%0,1\n\t"
		".set\treorder"
		:"=r" (loops)
		:"0" (loops));
}



//---------------------------------------------------------------------------
volatile unsigned long loops_per_jiffy = (1<<12);
#define LPS_PREC 8
#define HZ 100
#ifdef RTL8198
unsigned long loops_per_sec = 2490368 * HZ;	// @CPU 500MHz (this will be update in check_cpu_speed())
#else
unsigned long loops_per_sec = 0x1db000 * HZ;	// @CPU 390MHz, DDR 195 MHz (this will be update in check_cpu_speed())
#endif

int check_cpu_speed(void)
{

//#define jiffies REG32(0xb8000000)

	unsigned volatile long ticks, loopbit;
	int lps_precision = LPS_PREC;
      
  // RTL8198
  	request_IRQ(7, &irq_timer, NULL); 

	extern long glexra_clock;
//	printf("timer init\n");
    timer_init(glexra_clock);	

	loops_per_jiffy = (1<<12);
	while (loops_per_jiffy <<= 1) {
		/* wait for "start of" clock tick */
		ticks = jiffies;
		while (ticks == jiffies)
			/* nothing */;
		/* Go .. */
		ticks = jiffies;
		__delay(loops_per_jiffy);
		ticks = jiffies - ticks;
		if (ticks)
			break;
	}
/* Do a binary approximation to get loops_per_jiffy set to equal one clock
   (up to lps_precision bits) */
	loops_per_jiffy >>= 1;
	loopbit = loops_per_jiffy;
	while ( lps_precision-- && (loopbit >>= 1) ) 
	{
		loops_per_jiffy |= loopbit;
		ticks = jiffies;
		while (ticks == jiffies);
		ticks = jiffies;
		__delay(loops_per_jiffy);
		if (jiffies != ticks)	/* longer than 1 tick */
			loops_per_jiffy &= ~loopbit;
	}


	
	//timer_stop();	//wei del, because not close timer
	//free_IRQ(8);
	//prom_printf("cpu run %d.%d MIPS\n", loops_per_jiffy/(500000/HZ),      (loops_per_jiffy/(5000/HZ)) % 100);
	return (((loops_per_jiffy/(500000/HZ))+1)*3) /2; //for 24k 
}
//---------------------------------------------------------------------------


/*
---------------------------------------------------------------------------
;				Monitor
---------------------------------------------------------------------------
*/
extern char** GetArgv(const char* string);


//---------------------------------------------------------------------------------------


#ifdef WRAPPER




#ifdef CONFIG_SPI_FLASH
extern char _bootimg_start, _bootimg_end;
//SPI Write-Back
int CmdSWB(int argc, char* argv[])
{
	unsigned short auto_spi_clock_div_num;//0~7
	unsigned int  cnt=strtoul((const char*)(argv[0]), (char **)NULL, 16);	//JSW check
	char* start = &_bootimg_start;
	char* end  = &_bootimg_end;	   
	unsigned int length = end - start;		
	dprintf("SPI Flash #%d will write 0x%X length of embedded boot code from 0x%X to 0x%X\n", cnt+1,length, start, end);
	dprintf("(Y)es, (N)o->");
	if (YesOrNo())
	{
		 #if defined(SUPPORT_SPI_MIO_8198_8196C)
			spi_flw_image_mio_8198(cnt, 0, (unsigned char*)start , length);	
	  	#else			
			spi_flw_image(cnt, 0, (unsigned char*)start , length);
		#endif
		dprintf("\nSPI Flash Burn OK!\n");
#if 0		
		if(memcpy(0xbd000000, start, length))
			printf("Verify Fail\n");
		else
			printf("Verify OK\n");		

#endif
	}	
	else 
	{
        	dprintf("Abort!\n");	
	}
	return 0;
}

#endif
#if defined (CONFIG_NAND_FLASH)
int CmdNWB(int argc, char* argv[])
{

    unsigned int  cnt=strtoul((const char*)(argv[0]), (char **)NULL, 16);
    char* start = &_bootimg_start;
    char* end  = &_bootimg_end;
    unsigned int length = end - start;

    prom_printf("NAND Flash #%d will write 0x%X length of embedded boot code from 0x%X to 0x%X\n", cnt,length, start, end);
    prom_printf("(Y)es, (N)o->");
    if (YesOrNo())
    {
    	if(nflashwrite(0,start,length) == 0){
			prom_printf("success!\n");
    	}else{
			prom_printf("fail!\n");
    	}
    }
    else
    {
        prom_printf("Abort!\n");
    }
	return 0;
}
#endif
#endif

#if defined(CONFIG_PARAM_PASSING)
int CmdInitrd(int argc, char* argv[])
{
	if(argc != 2)
	{
		dprintf("[usage:] INITRD <initrd_start> <initrd_size>\n");
		return 0;
	}
	unsigned int  initrd_start=strtoul((const char*)(argv[0]), (char **)NULL, 16);
	unsigned int  initrd_end=strtoul((const char*)(argv[1]), (char **)NULL, 16);

	boot_linux_set_initrd(initrd_start,initrd_end);
}
#endif

#if defined(CONFIG_FS_JFFS2)
int CmdJffs2Ls(int argc, char* argv[])
{
	if(argc != 1)
	{
		dprintf("[usage:] JFFS2LS DIR\n");
		return 0;
	}
	
	if(do_jffs2_ls(1,argv) !=0 )
		prom_printf("jffs2ls %s fail\n",argv[0]);

}

int CmdJffs2Fsinfo(int argc, char* argv[])
{

	if(do_jffs2_fsinfo(0,argv) !=0 )
		prom_printf("jffs2fsinfo %s fail\n",argv[0]);

}

int CmdJffs2Fsload(int argc, char* argv[])
{
	if(argc != 2)
	{
		dprintf("[usage:] JFFS2LS off filename\n");
		return 0;
	}

	if(do_jffs2_fsload(2,argv) !=0 )
		prom_printf("jffs2fsload %s fail\n",argv[0]);
}


#endif

#if defined(SUPPORT_TFTP_CLIENT)
unsigned int tftp_from_command = 0;
char tftpfilename[128];
char errmsg[512];
unsigned short errcode = 0;
unsigned int tftp_client_recvdone = 0;
extern int jump_to_test;
extern int retry_cnt;
extern volatile unsigned int last_sent_time;
int CmdTFTPC(int argc, char* argv[])
{
    if(argc != 2)
	{
		dprintf("[usage:] tftp <memroyaddress> <filename>\n");
		tftpd_entry(0);
		return 0;
	}
	unsigned int  address=strtoul((const char*)(argv[0]), (char **)NULL, 16);
	unsigned int len = 0;
	image_address = address;
	memset(tftpfilename,0,128);
	len = strlen(tftpfilename);
	if(len+1 > 128)
	{
		dprintf("filename too long\n");
		return 0;
	}
	memset(errmsg,0,512);
	errcode = 0;
    retry_cnt = 0;
    last_sent_time = 0;
	tftp_client_recvdone = 0;
    jump_to_test = 0;
	strcpy(tftpfilename,(char*)(argv[1]));
	tftpd_entry(1);
	int tickStart = 0;
	int ret = 0;

	tftp_from_command = 1;
	tickStart=get_timer_jiffies();
	do 
    {
		ret=pollingDownModeKeyword(ESC);
		if(ret == 1) break;
	}
	while (
    (!tftp_client_recvdone)&&
    (check_tftp_client_state() >= 0
	||(get_timer_jiffies() - tickStart) < 2000)//20s
	);

	if(!tftp_client_recvdone)
	{
        if(ret == 1)
            dprintf("cancel by user ESC\n");
        else
            dprintf("TFTP timeout\n");
	}
	tftpd_entry(0);
	retry_cnt = 0;
	tftp_from_command = 0;
	tftp_client_recvdone = 0;
    image_address = 0xa0500000;
	return 0;
}
#endif

/*/
---------------------------------------------------------------------------
; Ethernet Download
---------------------------------------------------------------------------
*/




extern unsigned long ETH0_ADD;
int CmdCfn(int argc, char* argv[])
{
	unsigned long		Address = 0;
	void	(*jump)(void);
	if( argc > 0 )
	{
		if(!Hex2Val( argv[0], &Address ))
		{
			dprintf(" Invalid Address(HEX) value.\n");
			return FALSE ;
		}
	}

	dprintf("---Jump to address=%X\n",Address);
	jump = (void *)(Address);
	//outl(0,GIMR0); // mask all interrupt
	REG32(BSP_GIMR)=0;
	cli(); 
	flush_cache(); 
	prom_printf("\nreboot.......\n");
	//REG32(0xb8003114)=0;  //disable timer interrupt
	//REG32(0xb8000010)&=~(1<<11);
	//	
	//REG32(0xbbdc0300)=0xFFFFFFFF;
	//REG32(0xbbdc0304)=0xFFFFFFFF;

#if 0	
#if defined(RTL8198)
#ifndef CONFIG_FPGA_PLATFORM
      /* if the jump-Address is BFC00000, then do watchdog reset */
      if(Address==0xBFC00000)
      	{
      	   *(volatile unsigned long *)(0xB800311c)=0; /*this is to enable 865xc watch dog reset*/
          for( ; ; );
      	}
     else /*else disable PHY to prevent from ethernet disturb Linux kernel booting */
     	{
           WRITE_MEM32(PCRP0, (READ_MEM32(PCRP0)&(~EnablePHYIf )) ); 
           WRITE_MEM32(PCRP1, (READ_MEM32(PCRP1)&(~EnablePHYIf )) ); 
           WRITE_MEM32(PCRP2, (READ_MEM32(PCRP2)&(~EnablePHYIf )) ); 
           WRITE_MEM32(PCRP3, (READ_MEM32(PCRP3)&(~EnablePHYIf )) ); 
           WRITE_MEM32(PCRP4, (READ_MEM32(PCRP4)&(~EnablePHYIf )) ); 
	flush_cache();

     	}
#endif
#endif
#endif
	//flush_cache();
	jump();	
	return 0;
}



//---------------------------------------------------------------------------
#if defined(CONFIG_BOOT_DEBUG_ENABLE)	
//---------------------------------------------------------------------------
/* This command can be used to configure host ip and target ip	*/

extern char eth0_mac[6];
int CmdIp(int argc, char* argv[])
{
	unsigned char  *ptr;
	unsigned int i;
	int  ip[4];
	
	if (argc==0)
	{	
		dprintf(" Target Address=%d.%d.%d.%d\n",
		arptable_tftp[TFTP_SERVER].ipaddr.ip[0], arptable_tftp[TFTP_SERVER].ipaddr.ip[1], 
		arptable_tftp[TFTP_SERVER].ipaddr.ip[2], arptable_tftp[TFTP_SERVER].ipaddr.ip[3]);
#ifdef HTTP_SERVER
		dprintf("   Http Address=%d.%d.%d.%d\n",
		arptable_tftp[HTTPD_ARPENTRY].ipaddr.ip[0], arptable_tftp[HTTPD_ARPENTRY].ipaddr.ip[1], 
		arptable_tftp[HTTPD_ARPENTRY].ipaddr.ip[2], arptable_tftp[HTTPD_ARPENTRY].ipaddr.ip[3]);
#endif
		return 0;	 
	}			
	
	ptr = argv[0];

	for(i=0; i< 4; i++)
	{
		ip[i]=strtol((const char *)ptr,(char **)NULL, 10);		
		ptr = strchr(ptr, '.');
		ptr++;
	}
	arptable_tftp[TFTP_SERVER].ipaddr.ip[0]=ip[0];
	arptable_tftp[TFTP_SERVER].ipaddr.ip[1]=ip[1];
	arptable_tftp[TFTP_SERVER].ipaddr.ip[2]=ip[2];
	arptable_tftp[TFTP_SERVER].ipaddr.ip[3]=ip[3];
/*replace the MAC address middle 4 bytes.*/
	eth0_mac[1]=ip[0];
	eth0_mac[2]=ip[1];
	eth0_mac[3]=ip[2];
	eth0_mac[4]=ip[3];
	arptable_tftp[TFTP_SERVER].node[5]=eth0_mac[5];
	arptable_tftp[TFTP_SERVER].node[4]=eth0_mac[4];
	arptable_tftp[TFTP_SERVER].node[3]=eth0_mac[3];
	arptable_tftp[TFTP_SERVER].node[2]=eth0_mac[2];
	arptable_tftp[TFTP_SERVER].node[1]=eth0_mac[1];
	arptable_tftp[TFTP_SERVER].node[0]=eth0_mac[0];
	prom_printf("Now your Target IP is %d.%d.%d.%d\n", ip[0],ip[1],ip[2],ip[3]);	
	return 0;
}

int CmdDumpWord( int argc, char* argv[] )
{
	
	unsigned long src;
	unsigned int len,i;

	if(argc<1)
	{	dprintf("Wrong argument number!\r\n");
		return 0;
	}
	
	if(argv[0])	
	{	src = strtoul((const char*)(argv[0]), (char **)NULL, 16);
		if(src <0x80000000)
			src|=0x80000000;
	}
	else
	{	dprintf("Wrong argument number!\r\n");
		return 0;		
	}
				
	if(!argv[1])
		len = 1;
	else
	len= strtoul((const char*)(argv[1]), (char **)NULL, 10);			
	while ( (src) & 0x03)
		src++;

	for(i=0; i< len ; i+=4,src+=16)
	{	
		dprintf("%08X:	%08X	%08X	%08X	%08X\n",
		src, *(unsigned long *)(src), *(unsigned long *)(src+4), 
		*(unsigned long *)(src+8), *(unsigned long *)(src+12));
	}
	return 0;
}

//---------------------------------------------------------------------------
int CmdDumpByte( int argc, char* argv[] )
{
	
	unsigned long src;
	unsigned int len,i;

	if(argc<1)
	{	dprintf("Wrong argument number!\r\n");
		return 0;
	}
	
	src = strtoul((const char*)(argv[0]), (char **)NULL, 16);		
	if(!argv[1])
		len = 16;
	else
	len= strtoul((const char*)(argv[1]), (char **)NULL, 10);			


	ddump((unsigned char *)src,len);
	return 0;
}

//---------------------------------------------------------------------------
int CmdWriteWord( int argc, char* argv[] )
{
	
	unsigned long src;
	unsigned int value,i;
	
	src = strtoul((const char*)(argv[0]), (char **)NULL, 16);		
	while ( (src) & 0x03)
		src++;

	for(i=0;i<argc-1;i++,src+=4)
	{
		value= strtoul((const char*)(argv[i+1]), (char **)NULL, 16);	
		*(volatile unsigned int *)(src) = value;
	}
	return 0;
}
//---------------------------------------------------------------------------

//---------------------------------------------------------------------------

int CmdWriteHword( int argc, char* argv[] )
{
	
	unsigned long src;
	unsigned short value,i;
	
	src = strtoul((const char*)(argv[0]), (char **)NULL, 16);		
	
	src &= 0xfffffffe;	

	for(i=0;i<argc-1;i++,src+=2)
	{
		value= strtoul((const char*)(argv[i+1]), (char **)NULL, 16);	
		*(volatile unsigned short *)(src) = value;
	}
	return 0;	
}
#endif
//---------------------------------------------------------------------------
int CmdWriteByte( int argc, char* argv[] )
{
	
	unsigned long src;
	unsigned char value,i;
	
	src = strtoul((const char*)(argv[0]), (char **)NULL, 16);		


	for(i=0;i<argc-1;i++,src++)
	{
		value= strtoul((const char*)(argv[i+1]), (char **)NULL, 16);	
		*(volatile unsigned char *)(src) = value;
	}
	return 0;
}

#if ( defined(CONFIG_I2C_POLLING) && defined(CONFIG_I2C_SLAVE) )
int CmdI2CRW( int argc, char* argv[] )
{

	extern void i2c_write_multi_byte_slave(u8 *data, int size);
	//extern int i2c_read_multi_byte_slave(u8 *data, int size);
	extern int i2c_read_byte(u8 bus, u8 addr);
	u8 r_data[10] = {0};
	int ret;

	while(1)
	{
		//printf("read...\r\n");
		ret = i2c_read_byte_slave();

		if(ret == 0x55)
		{
			hal_delay_us(100);
			cli();
			i2c_write_multi_byte_slave("realtek", 8);
			sti();
			printf("Slave Write Data= %s\n", "realtek");
			//return 0;
		}
		else if(ret == 0xAF)
		{
			printf("END\r\n");
			return 0;
		}

		hal_delay_us(500);
	}

}
#endif

#if ( defined(CONFIG_I2C_POLLING) && defined(CONFIG_I2C_MASTER) )
int MasterCmdI2CSend( int argc, char* argv[] )
{
	extern void i2c_write_byte(u8 bus, u8 addr, u8 data);
	int data;
	data = strtoul((const char*)(argv[0]), (char **)NULL, 16);
	i2c_write_byte(0,0x10,data);
	printf("Master Write Data= %x\n", data);
}
int MasterCmdI2CRead( int argc, char* argv[] )
{		
	extern int i2c_read_multi_byte(u8 bus, u8 addr, u8 subaddr, u8 *data, int size);
	int ret;
	u8 data[100] = {0};
	ret = i2c_read_multi_byte(0, 0x10, 0x35, data, 1);
	printf("Master Read Data= %s\n", data);
}
#endif


int CmdCmp(int argc, char* argv[])
{
	int i;
	unsigned long dst,src;
	unsigned long dst_value, src_value;
	unsigned int length;
	unsigned long error;

	if(argc < 3) {
		dprintf("Parameters not enough!\n");
		return 1;
	}
	dst = strtoul((const char*)(argv[0]), (char **)NULL, 16);
	src = strtoul((const char*)(argv[1]), (char **)NULL, 16);
	length= strtoul((const char*)(argv[2]), (char **)NULL, 16);		
	error = 0;
	for(i=0;i<length;i+=4) {
		dst_value = *(volatile unsigned int *)(dst+i);
		src_value = *(volatile unsigned int *)(src+i);
		if(dst_value != src_value) {		
			dprintf("%dth data(%x %x) error\n",i, dst_value, src_value);
			error = 1;
		}
	}
	if(!error)
		dprintf("No error found\n");
	return 0;
}

int CmdMEMCPY(int argc, char* argv[])
{
	int i;
	unsigned long dst,src;
	unsigned long  src_value;
	unsigned int length;
	unsigned long error;

	if(argc < 3) {
		dprintf("Parameters not enough!\n");
		return 1;
	}
	dst = strtoul((const char*)(argv[0]), (char **)NULL, 16);
	src = strtoul((const char*)(argv[1]), (char **)NULL, 16);
	length= strtoul((const char*)(argv[2]), (char **)NULL, 16);		
	error = 0;
	
	for(i=0;i<length;i+=4) {
		src_value = *(volatile unsigned int *)(src+i);
		*(volatile unsigned int *)(dst+i) = src_value;
	}
	return 0;
}

//---------------------------------------------------------------------------
#ifndef RTL8197B
extern int autoBurn;
int CmdAuto(int argc, char* argv[])
{
	unsigned long addr;


	if(argv[0][0] == '0')
		autoBurn = 0 ;
	else
		autoBurn = 1 ;
	dprintf("AutoBurning=%d\n",autoBurn);
	return 0;
}
#endif


//---------------------------------------------------------------------------
#ifdef CONFIG_HTTP_SERVER
extern unsigned long httpd_mem;
#endif

int CmdLoad(int argc, char* argv[])
{
	unsigned long addr;

	if(argc < 1) 
	{
		dprintf("TFTP Load Addr 0x%x\n",image_address);
		return 1;
	}

	image_address= strtoul((const char*)(argv[0]), (char **)NULL, 16);		
#ifdef CONFIG_HTTP_SERVER
	httpd_mem = image_address;
#endif
	dprintf("Set TFTP Load Addr 0x%x\n",image_address);
	return 0;
}

/*
--------------------------------------------------------------------------
Flash Utility
--------------------------------------------------------------------------
*/
#if defined(CONFIG_SPI_FLASH)
int CmdFli(int argc, char* argv[])
{
	initFlash();
	return 0;
}



int CmdFlr(int argc, char* argv[])
{
	int i;
	unsigned long dst,src;
	unsigned int length;
	//unsigned char TARGET;
//#define  FLASH_READ_BYTE	4096

	dst = strtoul((const char*)(argv[0]), (char **)NULL, 16);
	src = strtoul((const char*)(argv[1]), (char **)NULL, 16);
	length= strtoul((const char*)(argv[2]), (char **)NULL, 16);		
	//length= (length + (FLASH_READ_BYTE - 1)) & FLASH_READ_BYTE;

/*Cyrus Tsai*/
/*file_length_to_server;*/
//length=file_length_to_client;
//length=length & (~0xffff)+0x10000;
//dst=image_address;
file_length_to_client=length;
/*Cyrus Tsai*/

	dprintf("Flash read from %X to %X with %X bytes	?\n",src,dst,length);
	dprintf("(Y)es , (N)o ? --> ");

	if (YesOrNo())
	        //for(i=0;i<length;i++)
	        //   {
		//    if ( flashread(&TARGET, src+i,1) )
		//	printf("Flash Read Successed!, target %X\n",TARGET);
		//    else
		//	printf("Flash Read Failed!\n");
		//  }	
		    if (flashread(dst, src, length))
			dprintf("Flash Read Successed!\n");
		    else
			dprintf("Flash Read Failed!\n");
	else
		dprintf("Abort!\n");
//#undef	FLASH_READ_BYTE		4096
	return 0;
}

// For SPI Calibration
int CmdSPICLB(int argc, char* argv[])
{
	unsigned short baudrate_divider_ocp;
	uint32_t tunning_clk;
	uint32_t tunning_dummy;
	unsigned int    error;
    //unsigned int uid;
		
	if(argc>=1) //check ID before calibration
	{
		u32 jedec_id = flash_get_jedec_id();
		u32 input_id = strtoul((const char*)(argv[0]), (char **)NULL, 16);
		if(jedec_id!=input_id)
		{
			printf("SPI Calibration Error: Wrong id %06X, JEDEC ID %06X  \n", input_id, jedec_id);
			return 0;
		}
		else
			printf("Start calibrate %06X\n", input_id);
	}
	
	//SPI_SECTOR_ERASE_CLB(0x0, 0x40000, 0);
	uint32_t clb_startaddr =0x0;
	clb_startaddr=flash_get_clb_startaddr();
	flash_erase_sector_clb(clb_startaddr, 0x40000);
	
	//SPIwriteWordx1(0x0, 0xa0500000, 0x40000);
	spi_flw_image(0, clb_startaddr, (unsigned char*)0xa0500000 , 0x40000);

	printf("\n==================== SPI Calibration ====================\n");
	printf("\n   CLK                 Tunning_dummy                    \n\n");
	printf("             0       1       2       3       4       5\n");
	for(tunning_clk = 4; tunning_clk >= 1; tunning_clk--) {

		baudrate_divider_ocp=tunning_clk;
		// set baud rate to 25MHz, 33.3MHz, 50MHz, 100MHz
		//spi_flash_setbaudr(&dev, baudrate_divider_ocp);
		flash_setbaudr(baudrate_divider_ocp);
	
		//spi_flash_wait_busy(&dev);
		if(tunning_clk==1)
			printf("%d MHZ", (200/(tunning_clk *2)));
		else
			printf(" %d MHZ", (200/(tunning_clk *2)));
		
		for(tunning_dummy = 0; tunning_dummy <= 5; tunning_dummy++) {
			error = 1;
			//spi_flash_set_dummy_cycle(&dev, DEF_RD_TUNING_DUMMY_CYCLE);
			flash_set_dummy_cycle_clb(tunning_clk, tunning_dummy);
			//spi_flash_map->auto_length = (spi_flash_map->auto_length & 0xffff0000) | tunning_dummy;
			//spi_flash_wait_busy(&dev);
			//uid=flash_device_init(&dev, 0x9f);      // RDID
			//if (flash_device_init(&dev, 0x9f) != 0x13) {
//#if 1 //def SUPPORT_SPI_DIO
				//spi_flash_wait_busy(&dev);
			//sheipa_spi_probe();
			memset((void *)0xa0400000, 0, 0x40000);
			//SPIreadWordx2(0, 0xa0400000, 0x40000);
			flashread(0xa0400000, clb_startaddr, 0x40000);
			error = SPIcmp(0xa0500000, 0xa0400000, 0x40000);
//#endif
			//} else {
			//	error = 1;	
			//}
			if (error!=1) {
				printf("    PASS");
				//printf("\n======================\n");
				//printf("clk=%d MHZ,\ntunning_dummy=%d,\nCalibration PASS!!!\n", (200/(tunning_clk *2)), tunning_dummy);
				//printf("======================\n");
			} else {
				printf("    FAIL");
				//printf("\n======================\n");
				//printf("clk=%d MHZ,\ntunning_dummy=%d,\nCalibration FAIL!!!\n", (200/(tunning_clk *2)), tunning_dummy);
				//printf("======================\n");
			}
			//spi_flash_wait_busy(&dev);
		}
		printf("\n");
	}
	printf("\n================== SPI Calibration end ==================\n\n");
	flash_set_dummy_back();
	return 0;
}
#endif


#ifndef RTL8197B
/* Setting image header */



//---------------------------------------------------------------------------
#endif //RTL8197B

//---------------------------------------------------------------------------

//---------------------------------------------------------------------------

#if !defined(CONFIG_BOOT_DEBUG_ENABLE)
extern char eth0_mac[6];
#endif


//---------------------------------------------------------------------------


int YesOrNo(void)
{
	unsigned char iChar[2];

	GetLine( iChar, 2,1);
	dprintf("\n");//vicadd
	if ((iChar[0] == 'Y') || (iChar[0] == 'y'))
		return 1;
	else
		return 0;
}
//---------------------------------------------------------------------------
#ifdef CONFIG_SPI_FLASH
int CmdSFlw(int argc, char* argv[])
{
	unsigned int  cnt2=0;//strtoul((const char*)(argv[3]), (char **)NULL, 16);	
	unsigned int  dst_flash_addr_offset=strtoul((const char*)(argv[0]), (char **)NULL, 16);		
	unsigned int  src_RAM_addr=strtoul((const char*)(argv[1]), (char **)NULL, 16);
	unsigned int  length=strtoul((const char*)(argv[2]), (char **)NULL, 16);
	unsigned int  end_of_RAM_addr=src_RAM_addr+length;	
	dprintf("Write 0x%x Bytes to SPI flash#%d, offset 0x%x<0x%x>, from RAM 0x%x to 0x%x\n" ,length,cnt2+1,dst_flash_addr_offset,dst_flash_addr_offset+FLASH_BASE,src_RAM_addr,end_of_RAM_addr);
	dprintf("(Y)es, (N)o->");
	if (YesOrNo())
	{
		  #if defined(SUPPORT_SPI_MIO_8198_8196C) && defined(CONFIG_SPI_FLASH)
			spi_flw_image_mio_8198(cnt2, dst_flash_addr_offset, (unsigned char*)src_RAM_addr , length);	
		  #else			
			spi_flw_image(cnt2, dst_flash_addr_offset, (unsigned char*)src_RAM_addr , length);	
		 #endif
	}//end if YES
	else
		dprintf("Abort!\n");
	return 0;
}
#endif
//---------------------------------------------------------------------------
#if SWITCH_CMD
int TestCmd_MDIOR( int argc, char* argv[] )
{
	if(argc < 1) {
		dprintf("Parameters not enough!\n");
		return 1;
	}

//	unsigned int phyid = strtoul((const char*)(argv[0]), (char **)NULL, 16);		
	unsigned int reg = strtoul((const char*)(argv[0]), (char **)NULL, 10);		
	unsigned int data;
	int i,phyid;
	for(i=0;i<32;i++)
	{
		phyid=i;
		//REG32(PABCDDAT_REG) =  0xffff<<8;
	rtl8651_getAsicEthernetPHYReg(phyid,reg,&data); 	
		//REG32(PABCDDAT_REG) =  0<<8;	
	dprintf("PhyID=0x%02x Reg=%02d Data =0x%04x\r\n", phyid, reg,data);

	}
	return 0;
}

int TestCmd_MDIOW( int argc, char* argv[] )
{
	if(argc < 3) {
		dprintf("Parameters not enough!\n");
		return 1;
	}
	
	unsigned int phyid = strtoul((const char*)(argv[0]), (char **)NULL, 16);		
	unsigned int reg = strtoul((const char*)(argv[1]), (char **)NULL, 10);		
	unsigned int data = strtoul((const char*)(argv[2]), (char **)NULL, 16);		

	dprintf("Write PhyID=0x%x Reg=%02d data=0x%x\r\n",phyid, reg,data);
	rtl8651_setAsicEthernetPHYReg(phyid,reg,data); 

	return 0;
}

int CmdPHYregR(int argc, char* argv[])
{
    unsigned long phyid, regnum;
    unsigned int uid,tmp;

    phyid = strtoul((const char*)(argv[0]), (char **)NULL, 16);
    regnum = strtoul((const char*)(argv[1]), (char **)NULL, 16);

    rtl8651_getAsicEthernetPHYReg( phyid, regnum, &tmp );
    uid=tmp;
    dprintf("PHYID=0x%x, regID=0x%x, data=0x%x\r\n", phyid, regnum, uid);
	return 0;
}

int CmdPHYregW(int argc, char* argv[])
{
    unsigned long phyid, regnum;
    unsigned long data;
    unsigned int uid,tmp;

    phyid = strtoul((const char*)(argv[0]), (char **)NULL, 16);
    regnum = strtoul((const char*)(argv[1]), (char **)NULL, 16);
    data= strtoul((const char*)(argv[2]), (char **)NULL, 16);

    rtl8651_setAsicEthernetPHYReg( phyid, regnum, data );
    rtl8651_getAsicEthernetPHYReg( phyid, regnum, &tmp );
    uid=tmp;
    dprintf("PHYID=0x%x ,regID=0x%x, read back data=0x%x\r\n", phyid, regnum, uid);
	return 0;
}

int CmdPhyPageRegR(int argc, char* argv[])
{
    unsigned long phyid, regnum, page;
    unsigned int uid;

    phyid = strtoul((const char*)(argv[0]), (char **)NULL, 16);
    page = strtoul((const char*)(argv[1]), (char **)NULL, 16);
    regnum = strtoul((const char*)(argv[2]), (char **)NULL, 16);

	if (phyid == 0) phyid = 8;
	if(page > 0)
		rtl8651_setAsicEthernetPHYReg( phyid, 31, page  );
	
    rtl8651_getAsicEthernetPHYReg( phyid, regnum, &uid );

	if(page > 0)
		rtl8651_setAsicEthernetPHYReg( phyid, 31, 0  );
	
    dprintf("PHYID=0x%x, page=0x%x, regID=0x%x, data=0x%x\r\n", phyid, page, regnum, uid);
	return 0;
}

int CmdPhyPageRegW(int argc, char* argv[])
{
    unsigned long phyid, regnum, page;
    unsigned long data;
    unsigned int uid;

    phyid = strtoul((const char*)(argv[0]), (char **)NULL, 16);
    page = strtoul((const char*)(argv[1]), (char **)NULL, 16);
    regnum = strtoul((const char*)(argv[2]), (char **)NULL, 16);
    data= strtoul((const char*)(argv[3]), (char **)NULL, 16);

	if (phyid == 0) phyid = 8;
	if(page > 0)
		rtl8651_setAsicEthernetPHYReg( phyid, 31, page  );

    rtl8651_setAsicEthernetPHYReg( phyid, regnum, data );
    rtl8651_getAsicEthernetPHYReg( phyid, regnum, &uid );

	if(page > 0)
		rtl8651_setAsicEthernetPHYReg( phyid, 31, 0  );

    dprintf("PHYID=0x%x, page=0x%x, regID=0x%x, read back data=0x%x\r\n", phyid, page, regnum, uid);
	return 0;
}

extern int rtl865xC_dumpAsicCounter(void);
int CmdAsicCountDump(int argc, char* argv[])
{
	rtl865xC_dumpAsicCounter();
	return 0;
}
#endif

#ifdef CONFIG_IIS_TEST
#define rtlRegRead(addr)        \
        (*(volatile u32 *)addr)

#define rtlRegWrite(addr, val)  \
        ((*(volatile u32 *)addr) = (val))

static inline u32 rtlRegMask(u32 addr, u32 mask, u32 value)
{
	u32 reg;

	reg = rtlRegRead(addr);
	reg &= ~mask;
	reg |= value & mask;
	rtlRegWrite(addr, reg);
	reg = rtlRegRead(addr); /* flush write to the hardware */

	return reg;
}
// config start.
//#define IIS_CODEC_ALC5621 1
#define SOC_TYPE_8881A	1
// config end.

int TestCmd_I2C( int argc, char* argv[])
{
#if defined(IIS_CODEC_ALC5621)
	unsigned int read_write;
	unsigned int register_addr;
	unsigned int register_value;
	unsigned int tmp;

	static unsigned int init_vari=0;

	if(init_vari==0)
	{
		rtlRegMask(0xb8003014, 0x00000F00, 0x00000200);//route iis interrupt
		rtlRegMask(0xb8000010, 0x03DCB000, 0x01DCB000);//enable iis controller clock
		rtlRegMask(0xb8000058, 0x00000001, 0x00000001);//enable 24p576mHz clock
#if 1
		rtlRegMask(0xb8000040, 0x00000007, 0x00000003);//change pin mux to iis-voice pin
		rtlRegMask(0xb8000044, 0x001F80DB, 0x00000049);//change pin mux to iis-voice pin
#endif
		for (tmp=0 ; tmp<5000 ; tmp++);
		init_i2c_gpio();
		init_vari=1;
	}

	read_write = strtoul((const char*)(argv[0]), (char **)NULL, 16);
	register_addr = strtoul((const char*)(argv[1]), (char **)NULL, 16);


	if(read_write==0){

		tmp=ALC5621_fake_read(register_addr);
		//prom_printf( "\n%x\n",tmp);
	}else if(read_write==1){
		register_value = strtoul((const char*)(argv[2]), (char **)NULL, 16);
		write_ALC5621(register_addr, register_value);
	}
		ALC5621_init();
#endif
}

extern void stop_iis(void);

int TestCmd_IISSTOP( int argc, char* argv[])
{
	stop_iis();
	return 0;
}


//[2:0] setting channel 0~5
//
extern int32_t play_channel;
int TestCmd_IISSETTING( int argc, char* argv[])
{
	int temp;
	temp=strtoul((const char*)(argv[0]), (char **)NULL, 16);
	play_channel=temp;
	prom_printf("[c%d]", play_channel);

}
extern volatile int i2s_isr_test_flag;
extern void init_iis(unsigned int setting);
//iis config
//setting[30]44.1kHz: 0->48khz(24.576Mhz) 1->44.1khz(22.579Mhz)
//setting[16:14], 0'b000->8k, 0'b001->16k, 0'b010->24k, 0'b011->32k, 0'b101->48k, 0'b110->96k, sampling_rate
//setting[10:1], iiscr config
//setting[10]DACLRSWAP: 0-> left phase, 1-> right phase.
//setting[9:8]FORMAT: 00-> I2S, 01->Left Justified, 10->Right Justified
//setting[7]LOOP_BACK: 0->disable, 1-> enable loop back
//setting[6]WL: 0-> 16bits, 1-> 24bits.
//setting[5]EDGE_SW: 0->negative edge, 1->positive edge
//setting[4:3]Audio_Mono: 00->stereo audio, 01->5.1 audio, 10->mono
//setting[2:1]TX_ACT: 00->RX_PATH, 01->TX_PATH, 10->TX_RX_PATH (not involve 5.1 audio)
// setting = 0x  92 -> 8k,left,i2s,enable loopback,16bit,negative edge,mono,TX
// setting = 0x4092 -> 16k,left,i2s,enable loopback,16bit,negative edge,mono,TX
// setting = 0x  14 -> 8k,left,i2s,disable loopback,16bit,negative edge,mono,TX_RX
// setting = 0x4014 -> 16k,left,i2s,disable loopback,16bit,negative edge,mono,TX_RX
// setting = 0x 414 -> 8k,right,i2s,disable loopback,16bit,negative edge,mono,TX_RX
// setting = 0x14004 -> 48k,left,i2s,disable loopback,16bit,negative edge,2ch,TX_RX
// setting = 0x  82 -> 8k,left,i2s,enable loopback,16bit,negative edge,2ch,TX
int TestCmd_IIS( int argc, char* argv[])
{
	unsigned int mode;
	static unsigned int init_vari=0;
	unsigned int tmp;

	if(init_vari==0)
	{
#ifdef SOC_TYPE_8881A
		//do 8881a soc iis part init
		rtlRegMask(0xb8003014, 0x00000F00, 0x00000200);//route iis interrupt
		rtlRegMask(0xb8000010, 0x02580000, 0x00580000);//enable iis controller clock select internal pll clk 24p576, active lx2 and lx2_arb
		rtlRegMask(0xb8000058, 0x00000801, 0x00000801);//enable 24p576mHz and 22p579mHz clock
		
		rtlRegMask(0xb8000040, 0x00000380, 0x00000280);//change pin mux to iis-voice pin (p0-mii as iis pin)
		rtlRegMask(0xb8000044, 0x000001ff, 0x00000049);//change pin mux to iis-voice pin (led-sig0~2 as iis pin)

		rtlRegMask(0xb800004c, 0x000FFFFF, 0x00033333);//change pin mux Configure JTAG PAD as IIS
#endif 
#if 0
		rtlRegMask(0xb8003014, 0x00000F00, 0x00000200);//route iis interrupt
		rtlRegMask(0xb8000010, 0x03DCB000, 0x01DCB000);//enable iis controller clock
		rtlRegMask(0xb8000058, 0x00000001, 0x00000001);//enable 24p576mHz clock
#if 1
		rtlRegMask(0xb8000040, 0x00000007, 0x00000003);//change pin mux to iis-voice pin
    #if 1
		rtlRegMask(0xb8000044, 0x001F80DB, 0x00000049);//change pin mux to iis-voice pin (led-sig0~2 as iis pin)
			//ew b8000044 3649
		//rtlRegMask(0xb8000044, 0x001F80DB, 0x00010000);//change pin mux to iis-voice pin (led-p1 as iis-voice pin)
			//ew b8000044 13600
		//rtlRegMask(0xb8000044, 0x001F80DB, 0x000D8000);//change pin mux to iis-voice pin (led-p1~2 as iis-audio pin)
			//ew b8000044 db600
    #endif
#endif
#endif
#if 0	//iis debug mode
		//rtlRegMask(0xb8000094, 0x00000FFF, 0x000000A8);//case A lexra 2 bus
		//rtlRegMask(0xb8000094, 0x00000FFF, 0x00000094);//case A
		//rtlRegMask(0xb8000094, 0x00000FFF, 0x00000090);//case new iis
		rtlRegMask(0xb8000094, 0x00000FFF, 0x00000030);//case C
		rtlRegMask(0xb8000040, 0x3FFF3F1F, 0x2aaa2a17);//change pin mux to debug
		rtlRegMask(0xb8000044, 0x001FB6DB, 0x0016a492);//change pin mux to debug
		
#endif

		for (tmp=0 ; tmp<5000 ; tmp++);
	}

#ifdef IIS_CODEC_ALC5621
#if 1
	if(init_vari==0)
	{
		init_i2c_gpio();
		init_vari=1;
	}

	//init_pcm(0);
	ALC5621_init(0);
#endif
#endif
	mode = strtoul((const char*)(argv[0]), (char **)NULL, 16);
	init_i2s(mode);
	i2s_isr_test_flag=1;
	//while (1)
	while (0)
	{
		if(i2s_isr_test_flag==0)
			break;

	}

	return 0;
}

//#include "pcm/fpga_gpio.h"
int TestCmd_GPIO( int argc, char* argv[])
{
#if 0
#if 1
	static unsigned int init_vari=0;
	static unsigned int data=0;
	if (init_vari==0) {
		init_vari=1;
		_rtl8954C_initGpioPin(GPIO_ID(GPIO_PORT_B, 0), GPIO_CONT_GPIO, GPIO_DIR_OUT, GPIO_INT_DISABLE);
		_rtl8954C_initGpioPin(GPIO_ID(GPIO_PORT_B, 1), GPIO_CONT_GPIO, GPIO_DIR_OUT, GPIO_INT_DISABLE);
		_rtl8954C_initGpioPin(GPIO_ID(GPIO_PORT_C, 1), GPIO_CONT_GPIO, GPIO_DIR_OUT, GPIO_INT_DISABLE);
		_rtl8954C_initGpioPin(GPIO_ID(GPIO_PORT_C, 2), GPIO_CONT_GPIO, GPIO_DIR_OUT, GPIO_INT_DISABLE);
		_rtl8954C_initGpioPin(GPIO_ID(GPIO_PORT_C, 3), GPIO_CONT_GPIO, GPIO_DIR_OUT, GPIO_INT_DISABLE);
	}
	data ^=1;

	_rtl8954C_setGpioDataBit(GPIO_ID(GPIO_PORT_B, 0), data);
	_rtl8954C_setGpioDataBit(GPIO_ID(GPIO_PORT_B, 1), data);
	_rtl8954C_setGpioDataBit(GPIO_ID(GPIO_PORT_C, 1), data);
	_rtl8954C_setGpioDataBit(GPIO_ID(GPIO_PORT_C, 2), data);
	_rtl8954C_setGpioDataBit(GPIO_ID(GPIO_PORT_C, 3), data);
#else

	unsigned int gpio_pin;

	unsigned int gpio_value;

	unsigned int gpio_id;

	static unsigned int init_vari=0;

	if(init_vari==0)
	{
		init_i2c_gpio();
		init_vari=1;
	}

	gpio_pin = strtoul((const char*)(argv[0]), (char **)NULL, 16);
	gpio_value = strtoul((const char*)(argv[1]), (char **)NULL, 16);

	gpio_id = GPIO_ID(GPIO_PORT_F, gpio_pin);


	_rtl8954C_setGpioDataBit(gpio_id, gpio_value);

#endif
#endif
}


int TestCmd_GPIOR( int argc, char* argv[])
{
#if 0
	unsigned int gpio_pin;

	unsigned int gpio_value;

	unsigned int gpio_id;

	static unsigned int init_vari=0;

	if(init_vari==0)
	{
		init_i2c_gpio();
		init_vari=1;
	}

	gpio_pin = strtoul((const char*)(argv[0]), (char **)NULL, 16);
	//gpio_value = strtoul((const char*)(argv[1]), (char **)NULL, 16);

	gpio_id = GPIO_ID(GPIO_PORT_D, gpio_pin);


	_rtl8954C_getGpioDataBit(gpio_id, &gpio_value);


	prom_printf("gpio_pin%d= %d",gpio_pin, gpio_value);
#endif
}

#endif

//==============================================================

#if 0
void MxSpdupThanLexra()
{

	#define SYS_BASE 0xb8000000
	#define SYS_INT_STATUS (SYS_BASE +0x04)
	#define SYS_HW_STRAP   (SYS_BASE +0x08)
	#define SYS_BIST_CTRL   (SYS_BASE +0x14)
	#define SYS_BIST_DONE   (SYS_BASE +0x20)


	//printf("MxSpdupThanLexra\n");

	#define GET_BITVAL(v,bitpos,pat) ((v& ((unsigned int)pat<<bitpos))>>bitpos)
	#define RANG5  0x1f
	unsigned char m2x_freq_sel=GET_BITVAL(REG32(SYS_HW_STRAP), 10, RANG5);
	

	if(m2x_freq_sel>= 0x0f)           // M2x > lexra=200M   
		dprintf("Mx clk > Lexra clk\n");
	else
		return ;

	//-------------------------
  	request_IRQ(8, &irq_timer, NULL); 


	extern long glexra_clock;
       timer_init(glexra_clock);	   //run 10msec
	//--------------------------
	
	#define SYS_HS0_CTRL 0xb80000a0
	#define BIT(x)	(1 << x)	
	REG32(SYS_HS0_CTRL) |= BIT(0) | BIT(1) | BIT(2);   // LX0 > Mx clock
	
	
		#if 1			
			//printf("llx0\n");
			REG32(SYS_BIST_CTRL) |= (1<<2) ;	  //lock bus arb2
			while( (REG32(SYS_BIST_DONE)&(1<<0))==0)  {}; //wait bit to 1, is mean lock ok	

			//printf("llx1\n");
			//REG32(SYS_BIST_CTRL) |= (1<<3) ;	  //lock bus arb4
			//while( (REG32(SYS_BIST_DONE)&(1<<1))==0)  {}; //wait bit to 1, is mean lock ok		

			//printf("llx2\n");
			//REG32(SYS_BIST_CTRL) |= (1<<4) ;	  //lock bus arb6
			//while( (REG32(SYS_BIST_DONE)&(1<<2))==0)  {}; //wait bit to 1, is mean lock ok				
		#endif
		
	//	__asm__ volatile("sleep");	 //need 10 usec to guaretee
	//	__asm__ volatile("nop");


		#if 1
			//printf("ulx0\n");	
			REG32(SYS_BIST_CTRL) &= ~(1<<2);	//unlock
			while( (REG32(SYS_BIST_DONE)&(1<<0))==(1<<0)) {};  //wait bit to 0  unlock

			//printf("ulx1\n");
			//REG32(SYS_BIST_CTRL) &= ~(1<<3);	//unlock
			//while( (REG32(SYS_BIST_DONE)&(1<<1))==(1<<1)) {};  //wait bit to 0  unlock

			//printf("ulx2\n");
			//REG32(SYS_BIST_CTRL) &= ~(1<<4);	//unlock
			//while( (REG32(SYS_BIST_DONE)&(1<<2))==(1<<2)) {};  //wait bit to 0  unlock				
		#endif

			//printf("done\n");

}
#endif
//==============================================================

//------------------------------------------------------------------------
#ifndef CONFIG_RTL8196E
int CmdXModem(int argc, char* argv[])
{
	unsigned char *load_buf = (char*)0x80300000;
	unsigned int jump=0;
	//unsigned char *dest_buf = (char*)0xbd000000;

	if( argc < 1 ) 
	{
		dprintf("Usage: xmodem <buf_addr> [jump]\n");		
		return 0;	
	}
	load_buf = (unsigned char *)strtoul((const char*)(argv[0]), (char **)NULL, 16);
	
	if(argc>1)	
	jump = strtoul((const char*)(argv[1]), (char **)NULL, 16);	
	

	int len;
	len=xmodem_receive(load_buf);
		if(len!=0)
		{	dprintf("Rx len=%d \n", len);			
			return  len;			
		}
		else
			dprintf("Download failed!!\n");


	if(jump)
	{	
		void (*jumpF)(void);
		jumpF = (void *)(load_buf);
	
		REG32(BSP_GIMR)=0; // mask all interrupt	    
		cli();
	
		flush_cache(); 
		prom_printf("\nJump to.......\n");

		jumpF();
	}
	return 0;
}; 
#endif
//==============================================================================
#define cache_op(op,addr)						\
	__asm__ __volatile__(						\
	"	.set	push					\n"	\
	"	.set	noreorder				\n"	\
	"	.set	mips3\n\t				\n"	\
	"	cache	%0, %1					\n"	\
	"	.set	pop					\n"	\
	:								\
	: "i" (op), "R" (*(unsigned char *)(addr)))


//============================================================================

int CmdTimerInit(int argc, char* argv[])
{
#if 0

  	request_IRQ(8, &irq_timer, NULL); 

	extern long glexra_clock;
	printf("=> init timer...\n");
    timer_init(glexra_clock*4);	

#if 0
	jiffies=0;
	int volatile j=jiffies;
	while(1)
	{
		if(j!=jiffies)
		{
			printf("j=%d\n", jiffies);
			j=jiffies;
		}
	}
#endif
	
#else
	int clk=check_cpu_speed();
	dprintf("CPU=%d MHz\n", clk);
#endif

	return 0;
}
//============================================================================

int CmdTest(int argc, char* argv[])
{
	int i,j,s,size,loop,st=0,ed=0;

	if( argc < 1 ) 
	{
		dprintf("Usage: test <len> <loop>\n");		
		return 0;	
	}
	size = strtoul((const char*)(argv[0]), (char **)NULL, 16);
	loop = strtoul((const char*)(argv[1]), (char **)NULL, 16);

	flush_cache();
	//invalidate_cache();
	s=read_32bit_cp0_register_sel(16,  2);
	dprintf("L2 cache ByPass=%d\n", (s&(1<<12))>>12);

	for(j=0; j<loop; j++)
	{
		st=jiffies;

		for(i=0x80300000;i<0x80300000+size; i+=32)   //cacheline
		{
			REG32(i)=REG32(i);
		}
		
		ed=jiffies;
		dprintf("loop=%d, st=%d, ed=%d, spend j=%d\n", j, st,ed,ed-st);		
	}	
	return 0;		
}

unsigned int rand2(void)
{
    static unsigned int x = 123456789;
    static unsigned int y = 362436;
    static unsigned int z = 521288629;
    static unsigned int c = 7654321;

    unsigned long long t, a= 698769069;

    x = 69069 * x + 12345;
    y ^= (y << 13); y ^= (y >> 17); y ^= (y << 5);
    t = a * z + c; c = (t >> 32); z = t;

    return x + y + z;
}

#if 0 //def CONFIG_DRAM_TEST
/* Function Name: 
 * 	_get_DRAM_csnum
 * Descripton:
 *	return DRAN total number of bytes.
 * Input:
 *	None
 * Output:
 * 	None
 * Return:
 *	DRAM total byte number.
 */
unsigned int _get_DRAM_csnum(void)
{
    unsigned int dcr;

    dcr = *((unsigned int *)(DCR_REG));

    return (((dcr>>15)&1) + 1);

}


/* Function Name: 
 * 	memctlc_dram_size
 * Descripton:
 *	return DRAN total number of bytes.
 * Input:
 *	None
 * Output:
 * 	None
 * Return:
 *	DRAM total byte number.
 */
unsigned int memctlc_dram_size(void)
{
    unsigned int dcr;
    int total_bit = 0;


    dcr = *((unsigned int *)(DCR_REG));
    total_bit = 0;
    total_bit += ((dcr>>24)&0x3); //bus width
   // total_bit += ((dcr>>20)&0x3)+11; //row count
    total_bit += ((dcr>>20)&0xf)+11; //row count
    
   // total_bit += ((dcr>>16)&0x7)+8 ; //col count
    total_bit += ((dcr>>16)&0xf)+8 ; //col count

	
    total_bit += ((dcr>>28)&0x3)+1;  //bank count
    total_bit += (dcr>>15)&1;        //Dram Chip Select

    return ((1<<total_bit));


    //return(1<<total_bit);
}

#endif

#ifdef CONFIG_DRAM_TEST
      #define MAX_SAMPLE  0x8000

//#define START_ADDR  0x100000               //1MB
//#define START_ADDR  0x700000              //7MB, 0~7MB can't be tested
//#define START_ADDR  0xFFFFFFF

//#define END_ADDR      0x800000		//8MB
//#define END_ADDR      0x1000000         //16MB
//#define END_ADDR      0x2000000        //32MB
//#define END_ADDR      0x4000000       //64MB
//#define END_ADDR      0x8000000         //128MB      

#define MAX_BURST_COUNTS  0x100000

#define CYGNUM_HAL_RTC_NUMERATOR 1000000000
#define CYGNUM_HAL_RTC_DENOMINATOR 100
#define CYGNUM_HAL_RTC_DIV_FACTOR BSP_DIVISOR
#define CYGNUM_HAL_RTC_PERIOD ((BSP_SYS_CLK_RATE / CYGNUM_HAL_RTC_DIV_FACTOR) / CYGNUM_HAL_RTC_DENOMINATOR)

/* how many counter cycles in a jiffy */
#define CYCLES_PER_JIFFY        CYGNUM_HAL_RTC_PERIOD

#define HAL_CLOCK_READ( _pvalue_ )                                      \
{                                                                       \
        *(_pvalue_) = REG32(BSP_TC0CNT);                                \
        *(_pvalue_) = (REG32(BSP_TC0CNT) >> 4) & 0x0fffffff;            \
}


void hal_delay_us(int us)
{
    unsigned int val1, val2;
    int diff;
    long usticks;
    long ticks;

    // Calculate the number of counter register ticks per microsecond.

    usticks = (CYGNUM_HAL_RTC_PERIOD * CYGNUM_HAL_RTC_DENOMINATOR) / 1000000;

    // Make sure that the value is not zero. This will only happen if the
    // CPU is running at < 2MHz.
    // usticks == 1 is modified by usticks <= 1 for Coverity.
    if( usticks <= 1 ) usticks = 1;

    while( us > 0 )
    {
        int us1 = us;

        // Wait in bursts of less than 10000us to avoid any overflow
        // problems in the multiply.
        if( us1 > 10000 )
            us1 = 10000;

        us -= us1;

        ticks = us1 * usticks;

        HAL_CLOCK_READ(&val1);
        while (ticks > 0) {
            do {
                HAL_CLOCK_READ(&val2);
            } while (val1 == val2);
            diff = val2 - val1;
            if (diff < 0) diff += CYGNUM_HAL_RTC_PERIOD;
            ticks -= diff;
            val1 = val2;
        }
    }
}

int Dram_test(int argc, char* argv[])
{
    unsigned int i, j,k,k2=0;
    unsigned int cache_type=0;
    unsigned int access_type=0;
    unsigned int access_type_rd=0;
    unsigned int Data_pattern=0;
    unsigned int random_test=1;
    unsigned int addr;
    unsigned int burst=0;
    unsigned long int wdata;
    unsigned int samples,test_range;

    unsigned int enable_delay,delay_time,PM_MODE;//JSW:For DRAM Power Management
       
    unsigned int wdata_array[MAX_BURST_COUNTS];         //JSW:It must equal to or more than Burst size
    
	unsigned int delay_u = 0;
	unsigned int start_addr = 0;
	unsigned int end_addr = 0;
    
	unsigned int scan_way = 0;
	unsigned int total_scan = 0;
	unsigned int scan_max = 0;
	unsigned int dram_size = REG32(0xB8000F00);
	unsigned int heap_offset_start = 0;
	unsigned int heap_offset_end = 0;
		
	unsigned int burst_count = 0; 

	//#define RTL8198C_DRAM_TEST_GPIO_B1_PCIE_RSTN
	#ifdef RTL8198C_DRAM_TEST_GPIO_B1_PCIE_RSTN
		#define GPIO_B1_1 REG32(PABCDDAT_REG)|=0x200     //Output "1"
		#define GPIO_B1_0 REG32(PABCDDAT_REG)&=0xFFFFFDFF//Output "0"
				
		REG32(0xb8000104)|=(3<<20);//RTL8198C GPIO_B1 (PCIE_RSTN) trugger , pgin[0]/datg[0] , pin mux setting
		prom_printf("\nRTL8198C  FT2 GPIO init \n");

		RTL8196D_FT2_TEST_GPIOinit();   						  
	#endif
  
    /*JSW: Auto set DRAM test range*/ 
    unsigned int END_ADDR,DCR_VALUE;

	#if 0 //For RTL8881A only
   		END_ADDR= memctlc_dram_size()/_get_DRAM_csnum();

  		if (END_ADDR==0x20000000)//512MB
  			END_ADDR/=2;

   		prom_printf("Set dramtest size from DCR=0x%x \n",END_ADDR);       
	#else
		//END_ADDR=0x00800000; //Test 8MB  
		//END_ADDR=0x08000000; //Test 128MB  
	#endif

    unsigned int keep_W_R_mode;
   
  
		if(argc<13)
		{	
			prom_printf("ex:dramtest <auto> <1-R/W> <2-enable_random_delay> <3-PowerManagementMode><4-cache_type><5-bit_type><6-Data_Pattern><7-Random_mode><8-Scan_way><9-Total_addr_scan><10-Delay time after writing test data><11-Start address><12-End address><13-Burst counts>\r\n");
			prom_printf("<1-R/W>:<0>=R+W, <1>=R,<2>=W\r\n");
			prom_printf("<2-enable_random_delay>: <0>=Disable, <1>=Enable\r\n");
			prom_printf("<3-PowerManagementMode> : <0>=Normal, <1>=PowerDown, <2>=Self Refresh\r\n");
			prom_printf("   		 <3>:Reserved,<4>:CPUSleep + Self Refresh in IMEM   \r\n"); 
			prom_printf("<4-cache_type>:<0>=cached, <1>=un-cached \r\n"); 
			prom_printf("<5-Access_type>:<0>=8bit, <1>=16bit , <2>=32bit \r\n");
			prom_printf("<6-Data_pattern>:<0>=random, <1>=sequential , <2>=0x5a5a5a5a, <3>=0xa5a5a5a5 \r\n");
			prom_printf("<7-Enable random_mode>:<0>=disable, <1>=enable  \r\n");
			prom_printf("<8-Scan_way>:<0>=random, <1>=sequential, <2>=block  (according to burst size) \r\n");
			prom_printf("<9-Total_addr_scan>:<0>=default (0x8000), <1>=total (the size is end addr - start addr)\r\n");
			prom_printf("<10-Delay time after writing test data (microsecond)>: decimal number or 0 mean not to delay. \r\n");
			prom_printf("<11-Start address>: hex address (the addr must be after 0x30000)\r\n");
			prom_printf("<12-End address>: hex address or 0 assigned the end address of memory automatically.\r\n");
			prom_printf("<13-Burst counts>: hex number (max is 0x100000) or 0 assigned default value (0x100). If scan way is block, the count size is the block size.\r\n");
		
			return 1;	
		}

	 keep_W_R_mode= strtoul((const char*)(argv[0]), (char **)NULL, 16);
	 enable_delay= strtoul((const char*)(argv[1]), (char **)NULL, 16);
	 PM_MODE= strtoul((const char*)(argv[2]), (char **)NULL, 16);
	 cache_type=strtoul((const char*)(argv[3]), (char **)NULL, 16);
	 access_type=strtoul((const char*)(argv[4]), (char **)NULL, 16);
	 Data_pattern=strtoul((const char*)(argv[5]), (char **)NULL, 16);
	 random_test=strtoul((const char*)(argv[6]), (char **)NULL, 16);
	 
	 scan_way = strtoul((const char*)(argv[7]), (char **)NULL, 16);
	 total_scan = strtoul((const char*)(argv[8]), (char **)NULL, 16);
	 
	 delay_u = strtoul((const char*)(argv[9]), (char **)NULL, 10);
	 start_addr=strtoul((const char*)(argv[10]), (char **)NULL, 16) & 0xffffffff;
	 end_addr=strtoul((const char*)(argv[11]), (char **)NULL, 16) & 0xffffffff;
	 
	 burst_count=strtoul((const char*)(argv[12]), (char **)NULL, 16);
	 
	 if((end_addr != 0 && end_addr < start_addr))
	 {
	 		prom_printf("End address should be bigger than start address, or use 0 to set the address automatically.\n");	
	 		
	 		return 1;
	 }
	 
	 if(end_addr >= dram_size*1024*1024 || start_addr >= dram_size*1024*1024)
	 {
	 		prom_printf("Address is wrong.\n");
	 	
	 		return 1;
	 }
	 
	 
	 if(burst_count == 0)
	 {
			burst_count = 0x100;	
	 }
	 
	 heap_offset_start = (0x700000 - MAX_BURST_COUNTS * 4 - 0x100000);
	 heap_offset_end = 0x700010;
	 
	 if(end_addr == 0)
		end_addr= dram_size*1024*1024 -1;

	// scan_max = (total_scan?((end_addr - start_addr + 1)/(access_type+1)):MAX_SAMPLE);
	scan_max = (total_scan?((end_addr - start_addr)/(access_type+1)):MAX_SAMPLE);
	
	if(scan_way == 2)
	{
		// scan_max = ((scan_max - 1) / burst_count) + 1;
		scan_max = (scan_max - 1) / burst_count;
		
		if((end_addr-start_addr) > (scan_max * burst_count))
		{
		  scan_max++;
		 }
	}
	
	// modify END_ADDR for 512MB after sample setting
	if(end_addr > (256*1024*1024 - 1))
		END_ADDR = 0xFFFFFFF;
	else
		END_ADDR = end_addr;

	access_type_rd = access_type;

	//prom_printf("END_ADDR 0x%x\n", END_ADDR);
	 
	 
	while(1)
	{
			#if 1                                     //RTL8196_208PIN_SUPPORT_DDR
				prom_printf("\n================================\n");
				k2++;
				prom_printf("\nBegin DRAM Test : %d\n",k2);
				prom_printf("Dram Test parameter:\n" );
				prom_printf("0.CLK_MANAGE(0xb8000010)=%x\n",READ_MEM32(0xb8000010));
				prom_printf("0.CLK_MANAGE2(0xb8000014)=%x\n",READ_MEM32(0xb8000014));
				//prom_printf("0.PAD_CONTROL(0xb8000048)=%x\n",READ_MEM32(PAD_CONTROL_REG) );
				//prom_printf("0.PAD_CONTROL(0xb8000048)=%x\n",READ_MEM32(0xb8000048) );
				//prom_printf("1.DIDER(0xb8001050)=%x\n",READ_MEM32(DDCR_REG) );
				//prom_printf("2.DTR(0xb8001008)=%x\n",READ_MEM32(DTR_REG) );
				//prom_printf("3.DCR(0xb8001004)=%x\n",READ_MEM32(DCR_REG) );
				// prom_printf("4.HS0_CONTROL(0x%x)=0x%x\n", HS0_CONTROL,REG32(HS0_CONTROL));
				prom_printf("5.Burst times=%d \n", burst_count);
				prom_printf("6.cache_type(0:cached)(1:Un-cached)=%d \n",cache_type);
				prom_printf("7.Access_type(0:8bit)(1:16bit)(2:32bit)=%d \n",access_type);
				//prom_printf("8.Tested size=0x%x \n",END_ADDR);        
				//prom_printf("9.Tested addr =0x%x \n",addr);
			
				prom_printf("10.Test sampe number = 0x%x\n", scan_max);
				prom_printf("11.1 Start address=0x%x\n", start_addr);
				prom_printf("11.2 End address=0x%x\n", end_addr);
				prom_printf("11.3 Heap address range=0x%x - 0x%x (this part will be skipped)\n", heap_offset_start, heap_offset_end);
				
			 	prom_printf("12.Delay after writing test data = %d\n", delay_u);
			 	
			#endif

       
			
			for (samples = 0; samples < scan_max; samples++)
			{
				#ifdef RTL8198C_DRAM_TEST_GPIO_B1_PCIE_RSTN
					GPIO_B1_0;//PCIE_RSTN_output "1"
				#endif		
		            
				if(random_test==1)
				{
					cache_type = rand2() % ((unsigned int) 2);
					access_type = rand2()  % ((unsigned int) 3);            	      
				}	    
		          
				// burst = rand2() % (unsigned int) BURST_COUNTS;	
				burst = burst_count;	
		
				if(scan_way == 0)
				{
					addr = 0x80000000 + start_addr + (rand2() % (unsigned int) (end_addr - start_addr));
					
					if((addr & 0x1FFFFFFF) > END_ADDR)  // 512MB
					{
						addr = 0x0 + (addr - 0x8FFFFFFF ) - 1;		
					}
					
				}
				else if (scan_way == 2)
				{
					addr = 0x80000000 + start_addr + burst_count * samples; // block
					
					if((addr & 0x1FFFFFFF) > END_ADDR)  // 512MB
					{
						addr = 0x0 + (addr - 0x8FFFFFFF) - 1;
						//cache_type = 0; // uncache, but make addr no change
					}
				}
				else
				{	
					
					addr = 0x80000000 + start_addr + samples * (access_type_rd + 1);
										
					if((addr & 0x1FFFFFFF) > END_ADDR)
					{
						addr = 0x0 + (addr - 0x8FFFFFFF) - 1;
						//cache_type = 0; // uncache, but make addr no change
					}
				}
				
								

				//cache_type=1;//uncache	  
		 		
		 		if(addr > 0xFFFFFFF)
					addr = cache_type ? (addr | 0x20000000) : addr;
				
				wdata = rand2();
				
				//if (delay_u > 0)
				//prom_printf("Start burst address= %x cache_type %x\n", addr, cache_type);
			
				  
				if (access_type == 0)  //8 bit
				{
					wdata = wdata & 0xFF;
				}
				else if (access_type == 1) //16 bit
				{
					addr = (addr) & 0xFFFFFFFE;
					wdata = wdata & 0xFFFF;
				}
				else //32 bit
				{
					addr = (addr) & 0xFFFFFFFC;
				}
			
				/* Check if Exceed Limit */
				if ( (((addr + (burst << access_type)) & 0x1FFFFFFF) > END_ADDR) || (((addr + (burst << access_type)) & 0x1FFFFFFF) > end_addr))
				{
					burst = (END_ADDR - ((addr) & 0x1FFFFFFF)) >> access_type;
					prom_printf("11.Exceed Limit,burst=%d %x\n", burst, addr);
				}
		
				#if 1
					if (((scan_way > 0) && (samples % 10000 == 0)) || ((scan_way == 0) && (samples % 100 == 0)))
					{
						prom_printf("\nSamples: %d %x\n", samples, addr);
		
		 				#if 1 //JSW @20091106 :For DRAM Test + Power Management 
							if(enable_delay)
							{
								delay_time=rand2() % ((unsigned int) 1000*1000);
								prom_printf(" Delay_time=%d\n",delay_time);
								for(k=0;k<=delay_time;k++); //delay_loop	
										
								// CmdCPUSleepIMEM();
							}
									
							#if 0
								if(PM_MODE)
								{
													
									//set bit[31:30]=0 for default "Normal Mode" and prevent unstable state transition
									//  REG32(MPMR_REG)= 0x3FFFFFFF ;
									REG32(MPMR_REG)= 0x040FFFFF ;
									
									switch(PM_MODE)
									{
										case 0:
											prom_printf("\nDRAM : Normal mode\n");
											//return 0;
											break;
									
										case 1:
											prom_printf("\nDRAM :Auto Power Down mode\n");
											REG32(MPMR_REG)= READ_MEM32(MPMR_REG)|(0x1 <<30) ;
    
											break;
									
										case 2:
											prom_printf("\nDRAM : Set to Self Refresh mode\n");				    
											REG32(MPMR_REG)|= (0x2 <<30) ;	
													     
													    
											break;
									
										case 3:
											prom_printf("\nReserved!\n");			            
											REG32(MPMR_REG)= 0x3FFFFFFF ;
											//return 0;
											break;
									
										case 4:
											prom_printf("\nCPUSleep + Self Refresh in IMEM!\n");
											// CmdCPUSleepIMEM();
											//return 0;
											break;
									
										default :
											prom_printf("\nError Input,should be 0~4\n");
											break;
										}   //end of switch(PM_MODE)
									}//end of if(PM_MODE)	
							#endif
						#endif
						 
					}
				#endif
			
		     
				/* Prepare Write Data */
				for (i = 0; i < burst ; i++)
				{     
					       
		          		
					if(Data_pattern==0)
						wdata = (unsigned int)(rand2());/* Prepare random data */
					else if (Data_pattern==1)
						wdata =( (i<<0)| (i<<8) |(i<<16) |(i<<23));  /* Prepare Sequential Data */   
					else if (Data_pattern==2)
						wdata=0x5a5aa5a5;//fixed data
					else if (Data_pattern==3)
						wdata=0xa5a55a5a;//fixed data
					else
					{
						prom_printf("\nError Data_pattern Input,return \n");
						return 1;
					}
					
		
					if (access_type == 0)               //8 bit
						wdata = wdata & 0xFF;
					else if (access_type == 1)          //16bit
						wdata = wdata & 0xFFFF;
		
					wdata_array[i] = wdata;
		   
				}   
				
				for (i = 0, j = addr; i < burst ; i++)
				{
					if((j >= (0x80000000 + heap_offset_start) && j <= (0x80000000 + heap_offset_end))|| 			
						((j >= (0xa0000000 + heap_offset_start) && j <= (0xa0000000 + heap_offset_end))))
					{
						continue;
					}
			
					if (access_type == 0)
						*(volatile unsigned char *) (j) = wdata_array[i];//8bit
					else if (access_type == 1)
						*(volatile unsigned short *) (j) = wdata_array[i];//16bit
					else
						*(volatile unsigned int *) (j) = wdata_array[i];//32bit
			
					j = j + (1 << access_type);
			        
					//keep reading
					if (keep_W_R_mode==1)
					{
						for (i = 0; i < burst ; i++)	
						{
							if(Data_pattern==0)
							{
								WRITE_MEM32(0xa0700000+(i*4), rand2());                  			
							}
							else if (Data_pattern==1)
								/* Prepare Sequential Data */   
								WRITE_MEM32(0xa0700000+(i*4), ( (i<<0)| (i<<8) |(i<<16) |(i<<23)));					  
							else if (Data_pattern==2 || Data_pattern==3)
								WRITE_MEM32(0xa0700000+(i*4), wdata); 			
						}
						 				 
			            //WRITE_MEM32(0xa0700000+(i*4), 0x5aa5a55a);
			            prom_printf("\nkeep reading\n");
			
						keep_reading:
							for (i = 0; i < burst ; i++)	
							{
								prom_printf("\naddr(0x%x),value=0x%x\n",0xa0700000+(i*4),REG32(0xa0700000+(i*4)));
							}
			
						goto keep_reading;
					}
				}
		
					//keep writing
					if (keep_W_R_mode==2)
					{
						prom_printf("\nkeep writing,writing addr(0xa0800000)=0xa5a55a5a\n");
						prom_printf("\nkeep writing...\n");	
				
						for (i = 0; i < burst ; i++)
						{
							wdata = rand2();
							// wdata=0xa5a55a5a;
							// wdata =( (i<<0)| (i<<8) |(i<<16) |(i<<23));  /* Prepare Sequential Data */  
			
							#if 0
								if (access_type == 0)               //8 bit
									wdata = wdata & 0xFF;
								else if (access_type == 1)          //16bit
									wdata = wdata & 0xFFFF;
							#endif
					
							wdata_array[i] = wdata;				 
						} 
			
							keep_writing:	  
								for (i = 0, j = addr; i < burst ; i++)
								{
									if (access_type == 0)
										*(volatile unsigned char *)  (j) = wdata_array[i];//8bit
									else if (access_type == 1)
										*(volatile unsigned short *)  (j)= wdata_array[i];//16bit
									else
										*(volatile unsigned int *)  (j) = wdata_array[i];//32bit
			
									j = j + (1 << access_type);
								} 
			              
							goto keep_writing;
					}
		
					if (delay_u > 0)
						hal_delay_us(delay_u);
		
					/* Read Verify */
					for (i = 0, j = addr; i < burst ; i++)
					{
						if((j >= (0x80000000 + heap_offset_start) && j <= (0x80000000 + heap_offset_end))||
								(j >= (0xa0000000 + heap_offset_start) && j <= (0xa0000000 + heap_offset_end)))
						{
							continue;
						}
									
						unsigned rdata;
			
						if (access_type == 0)
						{
							rdata = *(volatile unsigned char *) (j);
						}
						else if (access_type == 1)
						{
							rdata = *(volatile unsigned short *) (j);
						}
						else
						{
							rdata = *(volatile unsigned int *) (j);
						}
			          
						//prom_printf("\n==========In Read Verify========= \n");
						// prom_printf("\nrdata: %d\n", rdata);
						//prom_printf("\nwdata_array[i]: %d\n",wdata_array[i]);
						// prom_printf("\n==========End Read Verify========= \n");
					
						if (rdata != wdata_array[i])
						{
							#ifdef RTL8198C_DRAM_TEST_GPIO_B1_PCIE_RSTN
								GPIO_B1_1;//PCIE_RSTN_output "1" means fail
							#endif
			              
							if (cache_type)
								prom_printf("\n==> Uncached Access Address: 0x%X, Type: %d bit, Burst: %d",
								addr, (access_type == 0) ? 8 : (access_type == 1) ? 16 : 32, burst);
							else
								prom_printf("\n==>   Cached Access Address: 0x%X, Type: %d bit, Burst: %d",
								addr, (access_type == 0) ? 8 : (access_type == 1) ? 16 : 32, burst);
	
							prom_printf("\n====> Verify Error! Addr: 0x%X = 0x%X, expected to be 0x%X %x\n", j, rdata, wdata_array[i], &wdata_array[i]);
			
							//HaltLoop:
							//goto HaltLoop;
							return 1;
			
						}
			
						j = j + (1 << access_type);
			
					}//end of reading
		
				}

			if(scan_way > 0)
			{
				prom_printf("End scan\n");
				break;
			}

	}//end while(1)

	return 0;
}

int Dram_test_entry(int argc, char* argv[])
{
	char auto_command[] = "auto";
	char *auto_option_sequence_uncache[] = {"0", "0", "0", "1", "2", "0", "0", "1", "1", "0", "0x30000", "0", "0"};
	char *auto_option_sequence_cache[] = {"0", "0", "0", "0", "2", "0", "0", "1", "1", "0", "0x30000", "0", "0"};
	char *auto_option_block_random[] = {"0", "0", "0", "1", "2", "0", "0", "2", "1", "2000", "0x30000", "0", "0x100000"};
	char *auto_option_random[] = {"0", "1", "0", "1", "2", "0", "1", "0", "1", "0", "0x30000", "0", "0"};

 	if((argc == 1) && (strcmp(argv[0], auto_command) == 0))
	{
		prom_printf("auto scan ddr by order: sequence scan -> block scan -> random scan.\n");
		
		if((Dram_test(13, auto_option_sequence_uncache) > 0) || 
		(Dram_test(13, auto_option_sequence_cache) > 0) ||
		(Dram_test(13, auto_option_block_random) > 0) ||
		(Dram_test(13, auto_option_random) > 0))
		{
			return 1;
		}

		return 0;
	}	
	else
		return Dram_test(argc, argv);

}
#endif

//========================================================

#ifdef CONFIG_NIC_LOOPBACK
static int CmdSetLpbk(int argc, char* argv[])
{
	nic_loopback ^= 1;
	prom_printf("NIC loopback %s.\n", (nic_loopback) ? "enabled" : "disabled");
}
#endif

#if 1
void dump_cp0_reg(void)
{
	unsigned int val;

	val = read_32bit_cp0_register(CP0_STATUS);
	prom_printf("CP0_STATUS=0x%X\n", val);
	val = read_32bit_cp0_register(CP0_CONFIG);
	prom_printf("CP0_CONFIG=0x%X\n", val);
	val = read_32bit_cp0_register_sel(16, 1);
	prom_printf("CP0_CONFIG1=0x%X\n", val);
	val = read_32bit_cp0_register_sel(16, 2);
	prom_printf("CP0_CONFIG2=0x%X\n", val);
	val = read_32bit_cp0_register_sel(16, 3);
	prom_printf("CP0_CONFIG3=0x%X\n", val);
	val = read_32bit_cp0_register_sel(16, 7);
	prom_printf("CP0_CONFIG7=0x%X\n", val);

	val = read_32bit_cp0_register(CP0_PRID);
	prom_printf("CP0_PRID=0x%X\n", val);
	val = read_32bit_cp0_register_sel(15, 1);
	prom_printf("CP0_EBase=0x%X\n", val);
	val = read_32bit_cp0_register_sel(12, 1);
	prom_printf("CP0_IntCtl=0x%X\n", val);
}

int CmdCp0Reg(int argc, char* argv[])
{
	dump_cp0_reg();
	return 0;
}

#ifdef CONFIG_SPI_FLASH
int CmdFlashEraseChip(int argc, char* argv[])
{
#ifdef CONFIG_SPI_FLASH_NUMBER
	if(argc < 1) {	
		prom_printf("Wrong argument number!\r\n");
		return 0;
	}
	unsigned int cnt = strtoul((const char*)(argv[0]), (char **)NULL, 16);
	flash_erase_chip(cnt);
#else
	flash_erase_chip();
#endif

	return 0;
}

int CmdFlashEraseSector(int argc, char* argv[])
{
	unsigned long offset;

	if(argc<1)
	{	prom_printf("Wrong argument number!\r\n");
		return 0;
	}
	
	offset = strtoul((const char*)(argv[0]), (char **)NULL, 16);	
	flash_erase_sector(offset);
	return 0;
}
#endif
#endif
//=========================================================

int CmdCPUCLK(int argc, char* argv[]);


#if defined(CONFIG_TFTP_COMMAND)
extern void autoreboot();
#endif
COMMAND_TABLE	MainCmdTable[] =
{
	{ "?"	  ,0, CmdHelp			, "HELP (?)				    : Print this help message"					},
#if defined(CONFIG_BOOT_DEBUG_ENABLE)												
	{ "DB"	  ,2, CmdDumpByte		, "DB <Address> <Len>"}, //wei add	
	{ "DW"	  ,2, CmdDumpWord		, "DW <Address> <Len>"},  //same command with ICE, easy use
	{ "EB",2, CmdWriteByte, "EB <Address> <Value1> <Value2>..."},	
	{ "EW",2, CmdWriteWord, "EW <Address> <Value1> <Value2>..."},
	{ "CMP",3, CmdCmp, "CMP: CMP <dst><src><length>"},
	{ "IPCONFIG",2, CmdIp, "IPCONFIG:<TargetAddress>"},
	{ "MEMCPY",3, CmdMEMCPY, "MEMCPY:<dst><src><length>"},
#ifndef CONFIG_NONE_FLASH
	{ "AUTOBURN"   ,1, CmdAuto			, "AUTOBURN: 0/1" },
#endif
#endif
#if defined(CONFIG_BOOT_DEBUG_ENABLE)
	{ "LOADADDR"   ,1, CmdLoad			, "LOADADDR: <Load Address>"					},
	{ "J"  ,1, CmdCfn			, "J: Jump to <TargetAddress>"											},
#endif
#if defined(CONFIG_TFTP_COMMAND)
	{ "REBOOT"  ,0, autoreboot, "reboot"											},
#endif

#if defined(CONFIG_BOOT_DEBUG_ENABLE)
#ifdef CONFIG_SPI_FLASH
	{ "FLI"   ,3, CmdFli			, "FLI: Flash init"					},	

	{ "FLR"   ,3, CmdFlr			, "FLR: FLR <dst><src><length>"					},	
	{ "FLW",4, CmdSFlw, "FLW <dst_ROM_offset><src_RAM_addr><length_Byte> <SPI cnt#>: Write to SPI"},	 //JSW
#ifdef WRAPPER
	{ "SWB", 1, CmdSWB, "SWB <SPI cnt#> (<0>=1st_chip,<1>=2nd_chip): SPI Flash WriteBack (for MXIC/Spansion)"}, 	//JSW	
#endif	
#endif
#endif

#if defined (CONFIG_NAND_FLASH)
    { "NANDID",0, CmdNANDID, "NANDID: Read NAND Flash ID"},
    { "NANDBE",2, CmdNANDBE, "NANDBE:<offset><len>"},
    { "NANDSCRUB",2, CmdNANDSCRUB, "NANDSCRUB:<offset><len>"},
    { "NANDPIOR",3,  CmdNAND_PIO_READ, "NANDPIOR:<flash_Paddress><image_addr><image_size>"},
    { "NANDPIOW",3,  CmdNAND_PIO_WRITE, "NANDPIOW:<flash_Paddress><image_addr><image_size>"},
    { "NANDR",3, CmdNANDR, "NANDR:<flash_Paddress><image_addr><image_size>"},
    { "NANDW",3, CmdNANDW, "NANDW:<flash_Paddress><image_addr><image_size>"},
	{ "NANDECCGEN",3,CmdNANDECCGEN,"NANDECCGEN: <source_addr><des_addr><ecc working buffer><length in hex>"},
  	{ "NANDBBD",3, CmdNANDBadBlockDetect, "NANDBBD:<offset><len>"},
  	{ "NANDMARKB",3, CmdNANDMarkBadBlock, "NANDMARKB:<offset>"},
  	{ "NANDFEATURE",3, CmdNANDGetSetFeature, "NANDFEATURE:<cmd> <address> <value>"},
    { "NANDSPEEDT",2,CmdNANDSpeedTest,"NANDT: <cmd> <param>"},
    #ifdef WRAPPER	
	{"NWB", 1, CmdNWB, "NWB <NWB cnt#> (<0>=1st_chip,<1>=2nd_chip): NAND Flash WriteBack "},	
   #endif	
#endif
#if defined(CONFIG_PARAM_PASSING)
	{"INITRD",2,CmdInitrd, "INITRD:<initrd_start><initrd_size>"},
#endif
#if defined(CONFIG_FS_JFFS2)
	{"JFFS2LS",1,CmdJffs2Ls,"JFFS2LS dir: list files in a directory"},
	{"JFFS2FSLOAD",2,CmdJffs2Fsload,"JFFS2FSLOAD off filename: load binary file from flash bank with offset 'off'"},
	{"JFFS2FSINFO",0,CmdJffs2Fsinfo,"JFFS2FSINFO: print information about filesystems"},
#endif
#if defined(SUPPORT_TFTP_CLIENT)
    {"TFTP", 2, CmdTFTPC, "tftp <memoryaddress> <filename>  "},
#endif
#if defined(CONFIG_BOOT_DEBUG_ENABLE)
#if SWITCH_CMD
	{ "MDIOR"   ,0, TestCmd_MDIOR			, "MDIOR:  MDIOR phyid reg"				}, //wei add, 	
	{ "MDIOW"   ,0, TestCmd_MDIOW			, "MDIOW:  MDIOW phyid reg data"				}, //wei add, 	
	{ "PHYR",    2, CmdPHYregR, 			  "PHYR: PHYR <PHYID><reg>"},
	{ "PHYW",    3, CmdPHYregW, 			  "PHYW: PHYW <PHYID><reg><data>"},
	{ "PHYPR",   3, CmdPhyPageRegR, 		  "PHYPR: PHYPR <PHYID><page><reg>"},
	{ "PHYPW",   4, CmdPhyPageRegW, 		  "PHYPW: PHYPW <PHYID><page><reg><data>"},
	{ "COUNTER",  0, CmdAsicCountDump,		  "COUNTER: Dump Asic Counter"},
#endif
#endif

#if defined(CONFIG_BOOT_DEBUG_ENABLE)
#ifndef CONFIG_RTL8196E
	{ "XMOD"   ,1, CmdXModem			, "XMOD <addr>  [jump] "	}, 	//wei add	
#endif
	{ "TI"   ,1, CmdTimerInit			, "TI : timer init "	}, 	//wei add	

	{ "T"   ,1, CmdTest			, "T : test "	}, 	//wei add	
#endif

#ifdef  CONFIG_DRAM_TEST
	{ "DRAMTEST",13,Dram_test_entry , 
"dramtest <1-R/W> <2-enable_random_delay> <3-PowerManagementMode><4-cache_type><5-bit_type><6-Data_Pattern><7-Random_mode><8-Scan_way><9-Total_addr_scan><10-Delay time after writing test data (microsecond)><11-Start address><12-End address><13-Burst counts>\n" },
#endif

#ifdef CONFIG_IIS_TEST
	{ "IIS"		,0, TestCmd_IIS			, "IIS"							},
	{ "IISSTOP"		,0, TestCmd_IISSTOP			, "IISSTOP"							},
	{ "IISSETTING"		,0, TestCmd_IISSETTING		, "IISSETTING mode"					},
	//{ "I2C"		,0, TestCmd_I2C			, "I2C read=0/write=1 register value"			},
	//{ "GPIO"	,0, TestCmd_GPIO		, "GPIO pin value"					},
	//{ "GPIOR"	,0, TestCmd_GPIOR		, "GPIOR pin"					},
#endif
#ifdef CONFIG_PCIE_MODULE
    {"HRST",  1, PCIE_Host_RESET,"HRST: Host Pcie Reset <portnum> <mdio_rst>: "},
    {"HINIT", 1, PCIE_Host_Init, "HINIT: Host init bar <portnum>"},
    {"HLOOP", 1, Test_HostPCIE_DataLoopback,"HLOOP: Test Pci-E data loopback <portnum> <cnt> "},
    {"EPDN",  1, PCIE_PowerDown, "EPDN: PCIE Power Down test <portnum><mode> "},
	{ "EMDIOR"   ,1, HostPCIe_MDIORead			, "EMDIOR: Reg Read <portnum>"},	
	{ "EMDIOW"   ,1, HostPCIe_MDIOWrite			, "EMDIOW <portnum> <reg> <val>:  "},    
    {"ELOOP", 1, PCIE_PHYLoop, "ELOOP <portnum> <start/stop>:  "},
    {"EINT",  1, HostPCIe_TestINT, "EINT <portnum> <loops>:  "},
#endif	

#ifdef CONFIG_NIC_LOOPBACK
	{ "LPBK",	0,	CmdSetLpbk,	"LPBK: NIC loopback enable/disable"},
#endif
#if defined(CONFIG_BOOT_DEBUG_ENABLE)
	{ "ETH"   ,1, CmdEthStartup			, "ETH : startup Ethernet"	},

//	{ "L2DIS"   ,1, CmdL2Disable,		 "L2DIS: L2 disable/enable"	},
	{ "CPUCLK"   ,1, CmdCPUCLK			, "CPUClk: "	},
#endif
#if 0
	{ "C1WAKE"   ,1, CmdCore1Wakeup			, "C1Wake : Core 1 wake Up"	},
//	{ "TIMX"   ,1, Cmd_Test_TimerX			, "TIMX: TimerX : "	},	

	{ "GBIST"   ,1, GPHY_BIST			, "GBIST: GPHY BIST "	},
	{ "GDRF"   ,1, GPHY_DRF_BIST			, "GDRF: GPHY DRF BIST "	},
	
	{ "BISTALL"   ,1, Cmd_AllBistTest			, "BISTALL:  "	},	
#endif		

#if defined(CONFIG_BOOT_DEBUG_ENABLE)
#if 1
	{ "CP0", 0, CmdCp0Reg, "CP0"},
#ifdef CONFIG_SPI_FLASH
	{ "ERASECHIP", 0, CmdFlashEraseChip, "ERASECHIP"},
	{ "ERASESECTOR", 0, CmdFlashEraseSector, "ERASESECTOR"},
	{ "SPICLB",1 , CmdSPICLB, "SPICLB (<flash ID>) : SPI Flash Calibration"},	
#endif
#endif
#endif

#if defined(CONFIG_SW_8367R) || defined(CONFIG_SW_83XX)
	{ "D8",1, CmdDump8370Reg, "D8 <Address>"},
	{ "E8",2, CmdWrite8370Reg, "E8 <Address> <Value>"},
#endif
#ifdef CONFIG_I2C_POLLING
#if defined(CONFIG_I2C_SLAVE)
	{ "I2C", 0, CmdI2CRW, "I2C"},
#elif defined(CONFIG_I2C_MASTER)
	{ "MI2CR", 0, MasterCmdI2CRead, "MI2CR"},
	{ "MI2CW", 1, MasterCmdI2CSend, "Mi2CW <Value>"},
#endif
#endif
#ifdef CONFIG_RLX5181_TEST
#ifdef COMMANDS_TABLE_EX
	COMMANDS_TABLE_EX
#endif
#endif

#ifdef CONFIG_CRYPTO_DEV_REALTEK
	{ "CRYPTO",1,CmdCrypto, "CRYPTO encrypt/decrypt cbc(aes)/ecb(aes)/ctr(aes) blocksize key keylen iv src len dest "},
	{ "CRYPTO_TEST",1,CmdCrypto_Test, "CRYPTO_TEST vector/random [times]/index"},
#endif
};


//==============================================================================
int CmdHelp( int argc, char* argv[] )
{
	int	i ;

    dprintf("----------------- COMMAND MODE HELP ------------------\n");
	for( i=0  ; i < (sizeof(MainCmdTable) / sizeof(COMMAND_TABLE)) ; i++ )
	{
		if( MainCmdTable[i].msg )
		{
			dprintf( "%s\n", MainCmdTable[i].msg );
		}
	}
	/*Cyrus Tsai*/
    
	return TRUE ;
}

//==============================================================================

#if defined(CONFIG_TFTP_COMMAND)
unsigned int maincmd_table_count = 0;
#define MAX_CMD_LEN 256
#endif
#ifdef CONFIG_NEW_CONSOLE_SUPPORT
extern void monitor_real(unsigned int table_count);
void monitor(void)
{
    unsigned int table_count = (sizeof(MainCmdTable) / sizeof(COMMAND_TABLE));
#if defined(CONFIG_TFTP_COMMAND)
	memset(image_address,0,MAX_CMD_LEN);
	maincmd_table_count = (sizeof(MainCmdTable) / sizeof(COMMAND_TABLE));
#endif
	monitor_real(table_count);
}
#else
void monitor(void)
{
	char		buffer[ MAX_MONITOR_BUFFER +1 ];
	int		argc ;
	char**		argv ;
	int		i, retval ;
	
//	i = &_end;
//	i = (i & (~4095)) + 4096;
	//printf("Free Mem Start=%X\n", i);
#if defined(CONFIG_TFTP_COMMAND)
	memset(image_address,0,MAX_CMD_LEN);
	maincmd_table_count = (sizeof(MainCmdTable) / sizeof(COMMAND_TABLE));
#endif
	while(1)
	{	
		 #if CONFIG_ESD_SUPPORT//patch for ESD
                         REG32(0xb800311c)|= (1<<23);
        	#endif
	
		dprintf( "%s", MAIN_PROMPT );
		memset( buffer, 0, MAX_MONITOR_BUFFER );
		GetLine( buffer, MAX_MONITOR_BUFFER,1);
		dprintf( "\n" );
		argc = GetArgc( (const char *)buffer );
		argv = GetArgv( (const char *)buffer );
		if( argc < 1 ) continue ;
		StrUpr( argv[0] );
		for( i=0 ; i < (sizeof(MainCmdTable) / sizeof(COMMAND_TABLE)) ; i++ )
		{
			
			if( ! strcmp( argv[0], MainCmdTable[i].cmd ) )
			{
#if 0
				if (MainCmdTable[i].n_arg != (argc - 1))
					printf("%s\n", MainCmdTable[i].msg);
				else
					retval = MainCmdTable[i].func( argc - 1 , argv+1 );
#endif
				retval = MainCmdTable[i].func( argc - 1 , argv+1 );
				//memset(argv[0],0,sizeof(argv[0]));
				break;
			}
		}
		if(i==sizeof(MainCmdTable) / sizeof(COMMAND_TABLE)) dprintf("Unknown command !\r\n");
	}
}
#endif

#if defined (CONFIG_NAND_FLASH)

int CmdNANDID(int argc, char* argv[])
{
    if(nflashprobe() < 0)
    	prom_printf("cannot get nand chip id\n");
	return 0;
}


int CmdNANDBE(int argc, char* argv[])
{

    if(argc < 2)
    {
        prom_printf("Parameters not enough!\n");
        return 1;
    }

    unsigned int offset = strtoul((const char*)(argv[0]), (char **)NULL, 16);
    unsigned int len = strtoul((const char*)(argv[1]), (char **)NULL, 16);

    prom_printf("NAND flash block erase from offset:0x%X to 0x%X ?\n",offset,(offset+len));
    prom_printf("(Y)es, (N)o->");
	if (YesOrNo())
	{
		if(nflasherase(offset,len) < 0){
			prom_printf("fail\n");
		}else
			prom_printf("success\n");
	}
	else
	{
		prom_printf("Abort!\n");
	}
	return 0;               
}


int CmdNANDSCRUB(int argc, char* argv[])
{

    if(argc < 2)
    {
        prom_printf("Parameters not enough!\n");
        return 1;
    }

    unsigned int offset = strtoul((const char*)(argv[0]), (char **)NULL, 16);
    unsigned int len = strtoul((const char*)(argv[1]), (char **)NULL, 16);

    prom_printf("NAND flash block erase from offset:0x%X to 0x%X ?\n",offset,(offset+len));
    prom_printf("(Y)es, (N)o->");
	if (YesOrNo())
	{
		extern int uboot_scrub;
		uboot_scrub = 1;
		
		if(nflasherase(offset,len) < 0){
			prom_printf("fail\n");
		}else
			prom_printf("success\n");

		uboot_scrub = 0;
	}
	else
	{
		prom_printf("Abort!\n");
	}
	return 0;
}

int CmdNAND_PIO_READ(int argc, char* argv[])
{
	if(argc< 3)
	{	 		
		prom_printf("ex:CmdNAND_PIO_READ:<flash_Paddress><image_addr><image_size>\r\n");
		prom_printf("<flash_Paddress>:NAND Flash's physical address\r\n");
		prom_printf("<image_addr>:source data\r\n");
		prom_printf("<image_size>:data length\r\n");		
	     
		return 1;	
	}   

	unsigned int flash_Paddress_start= strtoul((const char*)(argv[0]), (char **)NULL, 16);
    unsigned int image_addr= strtoul((const char*)(argv[1]), (char **)NULL, 16);
    unsigned int image_size= strtoul((const char*)(argv[2]), (char **)NULL, 16);

    prom_printf("NAND flash PIO read size 0x%X from flash_Paddress 0x%X  to DRAM 0x%X\n",image_size,flash_Paddress_start,image_addr);
	prom_printf("(Y)es, (N)o->");

	/* TTFP SERVER use */
	file_length_to_client=image_size;

	if (YesOrNo()){
		if(nflashpioread(flash_Paddress_start,image_addr,image_size) < 0)
			prom_printf("fail\n");
		else
			prom_printf("success\n");
	}else
	{
		prom_printf("Abort!\n");
	}
	return 0;
}




int CmdNAND_PIO_WRITE(int argc, char* argv[])
{
	if(argc< 3)
	{	 		
		prom_printf("ex:CmdNAND_PIO_WRITE:<flash_Paddress><image_addr><image_size>\r\n");
		prom_printf("<flash_Paddress>:NAND Flash's physical address\r\n");
		prom_printf("<image_addr>:source data\r\n");
		prom_printf("<image_size>:data length\r\n");		
	     
		return 1;	
	}   


	unsigned int flash_Paddress_start= strtoul((const char*)(argv[0]), (char **)NULL, 16);
	unsigned int image_addr= strtoul((const char*)(argv[1]), (char **)NULL, 16);
	unsigned int image_size= strtoul((const char*)(argv[2]), (char **)NULL, 16);


	prom_printf("NAND flash PIO write size 0x%X from DRAM 0x%X to flash_Paddress 0x%X \n",image_size,image_addr,flash_Paddress_start);
	prom_printf("(Y)es, (N)o->");

	if (YesOrNo()){
		if(nflashpiowrite(flash_Paddress_start,image_addr,image_size) < 0)
			prom_printf("fail\n");
		else
			prom_printf("success\n");
	}else{
		prom_printf("Abort!\n");
	}    
	return 0;
}


int CmdNANDR(int argc, char* argv[])
{

    if(argc < 3 )
    {
        prom_printf("Parameters not enough!\n");
        return 1;
    }

    unsigned long flash_address= strtoul((const char*)(argv[0]), (char **)NULL, 16);
    unsigned char *image_addr = (unsigned char *)(strtoul((const char*)(argv[1]), (char **)NULL, 16));
    unsigned int image_size= strtoul((const char*)(argv[2]), (char **)NULL, 16);

	/* TTFP SERVER use */
	file_length_to_client=image_size;
	
    prom_printf("Read NAND Flash from 0x%X to 0x%X with 0x%X bytes ?\n",flash_address,image_addr,image_size);
    prom_printf("(Y)es , (N)o ? --> ");

    if (YesOrNo()) {
        if(nflashread(image_addr,flash_address,image_size,0) == 0)
            prom_printf("Read NAND Flash Successed!\n");
	    else
	        prom_printf("Read NAND Flash Failed!\n");
    }
    else
        prom_printf("Abort!\n");
	return 0;
}


int CmdNANDW(int argc, char* argv[])
{

    if(argc <3 )
    {
        prom_printf("Parameters not enough!\n");
        return 1;
    }

    unsigned long flash_address= strtoul((const char*)(argv[0]), (char **)NULL, 16);
    unsigned char *image_addr = (unsigned char *)(strtoul((const char*)(argv[1]), (char **)NULL, 16));
    unsigned int image_size= strtoul((const char*)(argv[2]), (char **)NULL, 16); 

    prom_printf("Program NAND flash addr %X from %X with %X bytes ?\n",flash_address,image_addr,image_size);
    prom_printf("(Y)es, (N)o->");
    if (YesOrNo())
   		if(nflashwrite(flash_address,image_addr,image_size) == 0)
            prom_printf("Write NAND Write Successed!\n");
	    else
	        prom_printf("Write NAND Flash Failed!\n");
    else
    {
        prom_printf("Abort!\n");
    }
	return 0;
}

int CmdNANDECCGEN(int argc, char* argv[])
{
	#define NAND_PAGE_SIZE 	2048
	#define NAND_SPARE_SIZE 64

	if(argc < 4)
	{
        prom_printf("Parameters not enough!\n");
        return 1;
    }

	unsigned char *dma_addr = (unsigned char *)(strtoul((const char*)(argv[0]), (char **)NULL, 16));
    unsigned char *des_addr = (unsigned char *)(strtoul((const char*)(argv[1]), (char **)NULL, 16));
    unsigned char *p_eccbuf = (unsigned char *)(strtoul((const char*)(argv[2]), (char **)NULL, 16)); 
	unsigned int length= strtoul((const char*)(argv[3]), (char **)NULL, 16); 

	unsigned int pagenum;
	unsigned long image_address_backup;
	pagenum = (length+NAND_PAGE_SIZE-1)/NAND_PAGE_SIZE;
	file_length_to_client = pagenum*(NAND_PAGE_SIZE+NAND_SPARE_SIZE);
	image_address = (unsigned int)des_addr;

	prom_printf("Generate NAND flash ecc from %x with %X bytes,dest_addr=%x ?\n",dma_addr,length,des_addr);
    prom_printf("(Y)es, (N)o->");
	if (YesOrNo())
   		if(nflasheccgen(dma_addr,des_addr,p_eccbuf,length) == 0)
            prom_printf("Write NAND Write Successed!\n");
	    else
	        prom_printf("Write NAND Flash Failed!\n");
    else
    {
        prom_printf("Abort!\n");
    }
	return 0;
}


int  CmdNANDBadBlockDetect(int argc, char* argv[])
{
	if(argc < 2 )
	{
		prom_printf("Parameters not enough!\n");
		return 1;
	}

	unsigned int offset= strtoul((const char*)(argv[0]), (char **)NULL, 16);
	unsigned int length= strtoul((const char*)(argv[1]), (char **)NULL, 16);

	prom_printf("NAND flash bad block detect from 0x%X to 0x%X ?\n",offset,length);
	prom_printf("(Y)es, (N)o->");
	if (YesOrNo())
	{
		nflashisBadBlock(offset,length);     
	}
	else
	{
		prom_printf("Abort!\n");
	}
	return 0;
}


int  CmdNANDMarkBadBlock(int argc, char* argv[])
{
	if(argc < 1)
	{
		prom_printf("Parameters not enough!\n");
		return 1;
	}

	unsigned int offset= strtoul((const char*)(argv[0]), (char **)NULL, 16);

	prom_printf("NAND flash mark  0x%X as bad block?\n",offset);
	prom_printf("(Y)es, (N)o->");
	if (YesOrNo())
	{
		nflashMarkBadBlock(offset);     
	}
	else
	{
		prom_printf("Abort!\n");
	}
	return 0;

}

int CmdNANDGetSetFeature(int argc, char* argv[])
{
	if(argc < 3)
	{
		prom_printf("Parameters not enough!\n");
		return 1;
	}

	unsigned int address = strtoul((const char*)(argv[1]), (char **)NULL, 16);
	unsigned int value = strtoul((const char*)(argv[2]), (char **)NULL, 16);
	unsigned int dieid = strtoul((const char*)(argv[3]), (char **)NULL, 16);
	
	prom_printf("NAND flash %s feature addres=0x%X value=0x%x dieid=%d?\n",argv[0],address,value,dieid);
	prom_printf("(Y)es, (N)o->");
	if (YesOrNo())
	{
		nflashGetSetFeature(argv[0],address,value,dieid);     
	}
	else
	{
		prom_printf("Abort!\n");
	}
	return 0;

}

int CmdNANDSpeedTest(int argc, char* argv[])
{	
	prom_printf("NAND flash Speed Test?\n");
	prom_printf("(Y)es, (N)o->");
	if (YesOrNo())
	{
		nflashSpeedTest();     
	}
	else
	{
		prom_printf("Abort!\n");
	}
	return 0;

}

#endif

#ifdef CONFIG_SW_8367R
//---------------------------------------------------------------------------
int CmdDump8370Reg( int argc, char* argv[] )
{	
	unsigned long src;
	unsigned int value;
	int ret;

	if(argc<1)
	{	prom_printf("Wrong argument number!\r\n");
		return 0;
	}
	
	src = strtoul((const char*)(argv[0]), (char **)NULL, 16);	
	ret = rtl8367b_getAsicReg(src, &value); 
			
	if(ret==0)
		dprintf("rtl8367b_getAsicReg: reg= %x, data= %x\n", src, value);
	else
		dprintf("get fail %d\n", ret);

	return 0;
}

//---------------------------------------------------------------------------
int CmdWrite8370Reg( int argc, char* argv[] )
{	
	unsigned long src;
	unsigned int value;
	int ret;
	
	src = strtoul((const char*)(argv[0]), (char **)NULL, 16);		

	value= strtoul((const char*)(argv[1]), (char **)NULL, 16);
	
	ret = rtl8367b_setAsicReg(src, value); 
			
	if(ret==0)
		dprintf("rtl8367b_setAsicReg: reg= %x, data= %x\n", src, value);
	else
		dprintf("set fail %d\n", ret);
	
	return 0;
}
#elif defined(CONFIG_SW_83XX)
//---------------------------------------------------------------------------
int CmdDump8370Reg( int argc, char* argv[] )
{	
	unsigned long src;
	unsigned int value;
	int ret;

	if(argc<1)
	{	prom_printf("Wrong argument number!\r\n");
		return 0;
	}
	
	src = strtoul((const char*)(argv[0]), (char **)NULL, 16);	
	ret = rtl8367c_getAsicReg(src, &value); 
			
	if(ret==0)
		dprintf("rtl8367c_getAsicReg: reg= %x, data= %x\n", src, value);
	else
		dprintf("get fail %d\n", ret);

	return 0;
}

//---------------------------------------------------------------------------
int CmdWrite8370Reg( int argc, char* argv[] )
{	
	unsigned long src;
	unsigned int value;
	int ret;
	
	src = strtoul((const char*)(argv[0]), (char **)NULL, 16);		

	value= strtoul((const char*)(argv[1]), (char **)NULL, 16);
	
	ret = rtl8367c_setAsicReg(src, value); 
			
	if(ret==0)
		dprintf("rtl8367c_setAsicReg: reg= %x, data= %x\n", src, value);
	else
		dprintf("set fail %d\n", ret);
	
	return 0;
}	
#endif
//---------------------------------------------------------------------------------------
#ifdef CONFIG_CRYPTO_DEV_REALTEK

int CmdCrypto( int argc, char* argv[] )
{
	if(argc < 8){
		prom_printf("Wrong argument number!\r\n");
		return;
	}
	
	int ret;
	unsigned int blocksize,keylen,len;
	unsigned char *crypt,*alg,*key,*src,*dst,*iv;
	
	crypt = argv[0];
	alg = argv[1];
	blocksize = strtoul((const char*)(argv[2]), (char **)NULL, 16);
	key = argv[3];
	keylen = strtoul((const char*)(argv[4]), (char **)NULL, 16);
	iv = argv[5];
	src = strtoul((const char*)(argv[6]), (char **)NULL, 16);
	len = strtoul((const char*)(argv[7]), (char **)NULL, 16);
	dst = strtoul((const char*)(argv[8]), (char **)NULL, 16);

	if(!strcmp(crypt,"encrypt"))
		ret = rtl_cipher_crypt_command(0,alg,blocksize,key,keylen,iv,src,len,dst);
	else if(!strcmp(crypt,"decrypt"))
		ret = rtl_cipher_crypt_command(0,alg,blocksize,key,keylen,iv,src,len,dst);
	else{
		return -1;
	}

}

#ifdef CONFIG_CRYPTO_DEV_REALTEK_TEST
static int CmdCrypto_IndexTest(unsigned int index)
{
	rtk_crypto_test(index);
}

#endif


#include <crypto/rtl_crypto_testcase.h>
static int CmdCrypto_VectorTest(void)
{
	int i,ret,j;
	unsigned out = 0x80b00000;
	
	/* ecb encrypt */
	for(i = 0;i < sizeof(aes_enc_tv_template)/sizeof(struct cipher_testvec);i++){
		ret = rtl_cipher_crypt_command(1,"ecb(aes)",16,aes_enc_tv_template[i].key,aes_enc_tv_template[i].klen,
			aes_enc_tv_template[i].iv,aes_enc_tv_template[i].input,aes_enc_tv_template[i].ilen,out);
		if(ret < 0){
			prom_printf("%s:%d:encrypt ecb(aes),test intem=%d fail\n",__func__,__LINE__,i);
			return -1;
		}

		if(memcmp(aes_enc_tv_template[i].result,out,aes_enc_tv_template[i].rlen) != 0){
			prom_printf("%s:%d:encrypt ecb(aes),test intem=%d fail\n",__func__,__LINE__,i);
			return -1;
		}
	}
	prom_printf("97F HW encrypt engine ecb encrypt vector test success\n");

	/* cbc decrypt */
	for(i = 0;i < sizeof(aes_dec_tv_template)/sizeof(struct cipher_testvec);i++){
		
		
		ret = rtl_cipher_crypt_command(0,"ecb(aes)",16,aes_dec_tv_template[i].key,aes_dec_tv_template[i].klen,
			aes_dec_tv_template[i].iv,aes_dec_tv_template[i].input,aes_dec_tv_template[i].ilen,out);
		if(ret < 0){
			prom_printf("%s:%d:decrypt ecb(aes),test intem=%d fail\n",__func__,__LINE__,i);
			return -1;
		}

		if(memcmp(aes_dec_tv_template[i].result,out,aes_dec_tv_template[i].rlen) != 0){
			prom_printf("%s:%d:decrypt ecb(aes),test intem=%d fail\n",__func__,__LINE__,i);
			return -1;
		}
	}
	prom_printf("97F HW encrypt engine ecb decrypt vector test success\n");


	/* cbc encrypt */
	for(i = 0;i < sizeof(aes_cbc_enc_tv_template)/sizeof(struct cipher_testvec);i++){
		ret = rtl_cipher_crypt_command(1,"cbc(aes)",16,aes_cbc_enc_tv_template[i].key,aes_cbc_enc_tv_template[i].klen,
			aes_cbc_enc_tv_template[i].iv,aes_cbc_enc_tv_template[i].input,aes_cbc_enc_tv_template[i].ilen,out);
		if(ret < 0){
			prom_printf("%s:%d:encrypt cbc(aes),test intem=%d fail\n",__func__,__LINE__,i);
			return -1;
		}

		if(memcmp(aes_cbc_enc_tv_template[i].result,out,aes_cbc_enc_tv_template[i].rlen) != 0){
			prom_printf("%s:%d:encrypt cbc(aes),test intem=%d fail\n",__func__,__LINE__,i);
			return -1;
		}
	}
	prom_printf("97F HW encrypt engine cbc encrypt vector test success\n");

	/* cbc decrypt */
	for(i = 0;i < sizeof(aes_cbc_dec_tv_template)/sizeof(struct cipher_testvec);i++){
		
		
		ret = rtl_cipher_crypt_command(0,"cbc(aes)",16,aes_cbc_dec_tv_template[i].key,aes_cbc_dec_tv_template[i].klen,
			aes_cbc_dec_tv_template[i].iv,aes_cbc_dec_tv_template[i].input,aes_cbc_dec_tv_template[i].ilen,out);
		if(ret < 0){
			prom_printf("%s:%d:decrypt cbc(aes),test intem=%d fail\n",__func__,__LINE__,i);
			return -1;
		}

		if(memcmp(aes_cbc_dec_tv_template[i].result,out,aes_cbc_dec_tv_template[i].rlen) != 0){
			prom_printf("%s:%d:decrypt cbc(aes),test intem=%d fail\n",__func__,__LINE__,i);
			return -1;
		}
	}
	prom_printf("97F HW encrypt engine cbc decrypt vector test success\n");

	/* ctr encrypt */
	for(i = 0;i < sizeof(aes_ctr_enc_tv_template)/sizeof(struct cipher_testvec);i++){		
		
		ret = rtl_cipher_crypt_command(1,"ctr(aes)",16,aes_ctr_enc_tv_template[i].key,aes_ctr_enc_tv_template[i].klen,
			aes_ctr_enc_tv_template[i].iv,aes_ctr_enc_tv_template[i].input,aes_ctr_enc_tv_template[i].ilen,out);
		if(ret < 0){
			prom_printf("%s:%d:encrypt ctr(aes),test intem=%d fail\n",__func__,__LINE__,i);
			return -1;
		}

		if(memcmp(aes_ctr_enc_tv_template[i].result,out,aes_ctr_enc_tv_template[i].rlen) != 0){
			prom_printf("%s:%d:encrypt ctr(aes),test intem=%d fail\n",__func__,__LINE__,i);
			return -1;
		}
	}
	prom_printf("97F HW encrypt engine ctr encrypt vector test success\n");

	/* ctr decrypt */
	for(i = 0;i < sizeof(aes_ctr_dec_tv_template)/sizeof(struct cipher_testvec);i++){
		
		ret = rtl_cipher_crypt_command(0,"ctr(aes)",16,aes_ctr_dec_tv_template[i].key,aes_ctr_dec_tv_template[i].klen,
			aes_ctr_dec_tv_template[i].iv,aes_ctr_dec_tv_template[i].input,aes_ctr_dec_tv_template[i].ilen,out);
		if(ret < 0){
			prom_printf("%s:%d:decrypt ctr(aes),test intem=%d fail\n",__func__,__LINE__,i);
			return -1;
		}
		if(memcmp(aes_ctr_dec_tv_template[i].result,out,aes_ctr_dec_tv_template[i].rlen) != 0){
			prom_printf("%s:%d:decrypt ctr(aes),test intem=%d fail\n",__func__,__LINE__,i);
			return -1;
		}
	}
	prom_printf("97F HW encrypt engine ctr decrypt vector test success\n");

#if 0
	for(i = 0;i < sizeof(aes_ctr_rfc3686_enc_tv_template)/sizeof(struct cipher_testvec);i++){		
		
		ret = rtl_cipher_crypt_command(1,"ctr(aes)",16,aes_ctr_rfc3686_enc_tv_template[i].key,aes_ctr_rfc3686_enc_tv_template[i].klen,
			aes_ctr_rfc3686_enc_tv_template[i].iv,aes_ctr_rfc3686_enc_tv_template[i].input,aes_ctr_rfc3686_enc_tv_template[i].ilen,out);
		if(ret < 0){
			prom_printf("%s:%d:encrypt ctr(aes) rfc3686,test intem=%d fail\n",__func__,__LINE__,i);
			return -1;
		}

		if(memcmp(aes_ctr_rfc3686_enc_tv_template[i].result,out,aes_ctr_rfc3686_enc_tv_template[i].rlen) != 0){
			prom_printf("%s:%d:encrypt ctr(aes) rfc3686,test intem=%d fail\n",__func__,__LINE__,i);
			return -1;
		}
	}
	prom_printf("97F HW encrypt engine rfc3686 ctr encrypt vector test success\n");

	/* ctr decrypt */
	for(i = 0;i < sizeof(aes_ctr_rfc3686_dec_tv_template)/sizeof(struct cipher_testvec);i++){
		
		ret = rtl_cipher_crypt_command(0,"ctr(aes)",16,aes_ctr_rfc3686_dec_tv_template[i].key,aes_ctr_rfc3686_dec_tv_template[i].klen,
			aes_ctr_rfc3686_dec_tv_template[i].iv,aes_ctr_rfc3686_dec_tv_template[i].input,aes_ctr_rfc3686_dec_tv_template[i].ilen,out);
		if(ret < 0){
			prom_printf("%s:%d:decrypt ctr(aes) rfc3686,test intem=%d fail\n",__func__,__LINE__,i);
			return -1;
		}
		if(memcmp(aes_ctr_rfc3686_dec_tv_template[i].result,out,aes_ctr_rfc3686_dec_tv_template[i].rlen) != 0){
			prom_printf("%s:%d:decrypt ctr(aes) rfc3686,test intem=%d fail\n",__func__,__LINE__,i);
			return -1;
		}
	}
	prom_printf("97F HW encrypt engine rfc3686 ctr decrypt vector test success\n");
#endif
}

static unsigned int _rtl_seed = 0xA0A0A0A0;
#define __rtl_random	__rtl_random_v1_00

static u32 __rtl_random_v1_00(u32 rtl_seed)
{
    u32 hi32, lo32;

    hi32 = (rtl_seed>>16)*19;
    lo32 = (rtl_seed&0xffff)*19+37;
    hi32 = hi32^(hi32<<16);
    return ( hi32^lo32 );
}

static u32 rtl_random( void )
{
	_rtl_seed = __rtl_random(_rtl_seed);
    return ( _rtl_seed );
}

static u32 rtl_cipher_crypt_randtest(void)
{
	int i,ret,ret0 = 0;
	unsigned char mode;
	unsigned int keylen,pktlen;
	unsigned char* key;
	unsigned char iv[16];
	unsigned char* src = (unsigned char*)0x80a00000;
	unsigned char* en_dst=(unsigned char*)0x80c00000;
	unsigned char* de_dst=(unsigned char*)0x80e00000;

	/* size = 1~(0x200000 - 1)*/
	pktlen = rtl_random() % 0x200000;
	if(pktlen == 0)
		return 0;
	
	for(i = 0;i < pktlen;i++){
		*(src+i) =(u8)(rtl_random() & 0xff);
	}

	/* key */
	keylen = ((rtl_random() % 3) + 2)*8;
	key = (unsigned char*)malloc(keylen);
	if(key == NULL)
		return -1;
	for(i = 0;i < keylen;i++)
		*(key+i) = (u8)(rtl_random() & 0xff);

	/*iv */
	for(i = 0;i < 16;i++)
		iv[i] = (u8)(rtl_random() & 0xff);

	switch((rtl_random() % 3)){
		case 0:
			/* cbc */
			mode = 0;
			/* encrypt */
			ret = rtl_cipher_crypt_command(1,"cbc(aes)",16,key,keylen,iv,src,pktlen,en_dst);
			if(ret < 0){
				prom_printf("%s:%d,encrypt fail in cbc key=%s,keylen=%d,iv=%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x\n",
							__func__,__LINE__,key,keylen,iv[0],iv[1],iv[2],iv[3],iv[4],iv[5],iv[6],iv[7],iv[8],iv[9],iv[10],iv[11],iv[12],iv[13],iv[14],iv[15]);
				ret0 = -1;
				goto OUT;
			}

			ret = rtl_cipher_crypt_command(0,"cbc(aes)",16,key,keylen,iv,en_dst,pktlen,de_dst);
			if(ret < 0){
				prom_printf("%s:%d,decrypt fail in cbc key=%s,keylen=%d,iv=%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x\n",
							__func__,__LINE__,key,keylen,iv[0],iv[1],iv[2],iv[3],iv[4],iv[5],iv[6],iv[7],iv[8],iv[9],iv[10],iv[11],iv[12],iv[13],iv[14],iv[15]);
				ret0 = -1;
				goto OUT;
			}
			prom_printf("cbc(aes),keylen=%d,pktlen=%d,iv=%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x,",
					keylen,pktlen,iv[0],iv[1],iv[2],iv[3],iv[4],iv[5],iv[6],iv[7],iv[8],iv[9],iv[10],iv[11],iv[12],iv[13],iv[14],iv[15]);
			
			break;
		case 1:
			/* ecb */
			mode = 1;
			/* encrypt */
			ret = rtl_cipher_crypt_command(1,"ecb(aes)",16,key,keylen,iv,src,pktlen,en_dst);
			if(ret < 0){
				prom_printf("%s:%d,encrypt fail in ecb key=%s,keylen=%d,iv=%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x\n",
							__func__,__LINE__,key,keylen,iv[0],iv[1],iv[2],iv[3],iv[4],iv[5],iv[6],iv[7],iv[8],iv[9],iv[10],iv[11],iv[12],iv[13],iv[14],iv[15]);
				ret0 = -1;
				goto OUT;
			}

			ret = rtl_cipher_crypt_command(0,"ecb(aes)",16,key,keylen,iv,en_dst,pktlen,de_dst);
			if(ret < 0){
				prom_printf("%s:%d,decrypt fail in ecb key=%s,keylen=%d,iv=%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x\n",
							__func__,__LINE__,key,keylen,iv[0],iv[1],iv[2],iv[3],iv[4],iv[5],iv[6],iv[7],iv[8],iv[9],iv[10],iv[11],iv[12],iv[13],iv[14],iv[15]);
				ret0 = -1;
				goto OUT;
			}
			prom_printf("ecb(aes),keylen=%d,pktlen=%d,iv=%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x,",
					keylen,pktlen,iv[0],iv[1],iv[2],iv[3],iv[4],iv[5],iv[6],iv[7],iv[8],iv[9],iv[10],iv[11],iv[12],iv[13],iv[14],iv[15]);
			break;
		case 2:
			/* ctr */
			mode = 2;
			/* encrypt */
			ret = rtl_cipher_crypt_command(1,"ctr(aes)",16,key,keylen,iv,src,pktlen,en_dst);
			if(ret < 0){
				prom_printf("%s:%d,encrypt fail in ctr key=%s,keylen=%d,iv=%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x\n",
							__func__,__LINE__,key,keylen,iv[0],iv[1],iv[2],iv[3],iv[4],iv[5],iv[6],iv[7],iv[8],iv[9],iv[10],iv[11],iv[12],iv[13],iv[14],iv[15]);
				ret0 = -1;
				goto OUT;
			}

			ret = rtl_cipher_crypt_command(0,"ctr(aes)",16,key,keylen,iv,en_dst,pktlen,de_dst);
			if(ret < 0){
				prom_printf("%s:%d,decrypt fail in ctr key=%s,keylen=%d,iv=%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x\n",
							__func__,__LINE__,key,keylen,iv[0],iv[1],iv[2],iv[3],iv[4],iv[5],iv[6],iv[7],iv[8],iv[9],iv[10],iv[11],iv[12],iv[13],iv[14],iv[15]);
				ret0 = -1;
				goto OUT;
			}
			prom_printf("ctr(aes),keylen=%d,pktlen=%d,iv=%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x,",
					keylen,pktlen,iv[0],iv[1],iv[2],iv[3],iv[4],iv[5],iv[6],iv[7],iv[8],iv[9],iv[10],iv[11],iv[12],iv[13],iv[14],iv[15]);
			break;
		default:
			prom_printf("should not happen\n");
			ret0 = -1;
			goto OUT;
	}

OUT:
	if(key){
		free(key);
		key = NULL;
	}

	return ret0;
}

static int CmdCrypto_RandomTest(unsigned int times)
{
	unsigned int item = 0;


	while(item < times){
		if(rtl_cipher_crypt_randtest() != 0){
			return -1;
		}else{
			prom_printf(",item=%d\n",item);
		}
		item++;
	}
	prom_printf("random crypt test success\n");
	return 0;
}

int CmdCrypto_Test( int argc, char* argv[])
{
	if(argc < 1){
		prom_printf("Wrong argument number!\r\n");
		return -1;
	}

	if(!strcmp(argv[0],"vector")){
		/* vector test */
		CmdCrypto_VectorTest();
	}else if(!strcmp(argv[0],"random")){
		unsigned int times;
		if(argc == 1){
			times = 100;
		}else{
			times = strtoul((const char*)(argv[1]), (char **)NULL, 0);
		}
		CmdCrypto_RandomTest(times);
	}
#ifdef CONFIG_CRYPTO_DEV_REALTEK_TEST
	else{
		unsigned int index;
		index = strtoul((const char*)(argv[0]), (char **)NULL, 0);
		CmdCrypto_IndexTest(index);
	}
#endif
}

#endif




