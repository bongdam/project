/* jwsyu sdcard booting code 20151001 */

//#include "sysdefs.h"
//#include "reset_def.h"
//#include "error_type.h"
#include "arch/include/sd_error_type.h"
//#include "cr_reg.h"
#include "arch/include/sdcard_reg.h"
#include "include/linux/mmc/mmc.h"
#include "include/linux/mmc/sd.h"
//#include "iso_reg.h"
//#include "mis_reg.h"
//#include "sys_reg_emmc.h"
//#include "uart.h"
//#include "utility.h"
//#include "cache.h"

#include "string.h"

#ifdef TRUE
#undef TRUE
#endif
//#include <rom_def.h>
#include <sys_reg.h>
//#include <bspchip.h>
#include <rlxboard.h>
//#include <common.h>  //for mdelay

#include <ddr/efuse.h> //Afooo
//#include "../efuse/efuse.h"



#include "sdcard.h"
#include <fs/ff.h>

#define prints(_x_)             //dprintf((_x_));
#define print_hex(_x_)          //dprintf(("%x", _x_))
#define print_val(_x_, _y_)     //dprintf(("%x", _x_))


#ifdef CONFIG_FPGA_PLATFORM
//#define BSP_SYS_CLK_RATE	  	(33860000)      //33.86MHz
#define BSP_SYS_CLK_RATE	  	(27000000)      //27MHz
#else
#define BSP_SYS_CLK_RATE	  	(200000000)     //HS1 clock : 200 MHz
#endif
#define BSP_DIVISOR         200

#define BSP_TC_BASE         0xB8003100
#define BSP_TC0CNT          (BSP_TC_BASE + 0x08)

#define CYGNUM_HAL_RTC_NUMERATOR 1000000000
#define CYGNUM_HAL_RTC_DENOMINATOR 100
#define CYGNUM_HAL_RTC_DIV_FACTOR BSP_DIVISOR
#define CYGNUM_HAL_RTC_PERIOD ((BSP_SYS_CLK_RATE / CYGNUM_HAL_RTC_DIV_FACTOR) / CYGNUM_HAL_RTC_DENOMINATOR)
#define HAL_CLOCK_READ( _pvalue_ )					\
{									\
	*(_pvalue_) = REG32(BSP_TC0CNT);				\
	*(_pvalue_) = (REG32(BSP_TC0CNT) >> 4) & 0x0fffffff;		\
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
    if( usticks == 0 ) usticks = 1;
    
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

#define udelay hal_delay_us
void mdelay(unsigned long ms)
{
	udelay(ms*1000);
}
/*
void    udelay        (unsigned long);
void mdelay(unsigned long);
u1Byte check_image_header(PIMG_HEADER_TYPE header, pu1Byte signature);
*/

#if 0
static int swap_endian(u4Byte input)
{
	u4Byte output;

	output = (input & 0xff000000)>>24|
			 (input & 0x00ff0000)>>8|
			 (input & 0x0000ff00)<<8|
			 (input & 0x000000ff)<<24;
	
	return output;
}
#endif

static inline u4Byte rtlRegMask(u4Byte addr, u4Byte mask, u4Byte value)
{
	u4Byte reg;

	reg = REG32(addr);
	reg &= ~mask;
	reg |= value & mask;
	REG32(addr) = reg;
	reg = REG32(addr); /* flush write to the hardware */

	return reg;
}
//end
/************************************************************************
 *  Definitions
*************************************************************************/
/* mmc spec definition */
/*    //jwsyu remove unused tran_exp, tran_mant, tacc_exp, tacc_mant
static const unsigned int tran_exp[] = {
    10000,      100000,     1000000,    10000000,
    0,      0,      0,      0,
};

static const unsigned char tran_mant[] = {
    0,  10, 12, 13, 15, 20, 25, 30,
    35, 40, 45, 50, 55, 60, 70, 80,
};

static const unsigned int tacc_exp[] = {
    1,  10, 100,    1000,   10000,  100000, 1000000, 10000000,
};

static const unsigned int tacc_mant[] = {
    0,  10, 12, 13, 15, 20, 25, 30,
    35, 40, 45, 50, 55, 60, 70, 80,
};
*/
static u1Byte g_cmd[6]={0};

static u4Byte g_bit=0;

#define UNSTUFF_BITS(resp,start,size)                   \
    ({                              \
        const int __size = size;                \
        const u4Byte __mask = (__size < 32 ? 1 << __size : 0) - 1; \
        const int __off = 3 - ((start) / 32);           \
        const int __shft = (start) & 31;            \
        u4Byte __res;                      \
                                    \
        __res = resp[__off] >> __shft;              \
        if (__size + __shft > 32)               \
            __res |= resp[__off-1] << ((32 - __shft) % 32); \
        __res & __mask;                     \
    })


static int bErrorRetry_1=0, bErrorRetry_2=0;
//unsigned int bootcode_blk_no;
//unsigned int secure_fsbl_blk_no;
//unsigned int secure_os_blk_no;
//e_device_type  emmc_card;   //eMMC device data structure
// sdcard data structure
unsigned int            sdcard_rca;                /* relative card address of device */
u4Byte                  sdcard_raw_cid[4];                  /* raw card CID */


#ifdef CR_DEBUG
const char *const sdcard_state_tlb[9] = {
    "STATE_IDLE",
    "STATE_READY",
    "STATE_IDENT",
    "STATE_STBY",
    "STATE_TRAN",
    "STATE_DATA",
    "STATE_RCV",
    "STATE_PRG",
    "STATE_DIS"
};
#if 0
const char *const bit_tlb[4] = {
    "1bit",
    "4bits",
    "8bits",
    "unknow"
};

const char *const clk_tlb[8] = {
    "30MHz",
    "40MHz",
    "49MHz",
    "49MHz",
    "15MHz",
    "20MHz",
    "24MHz",
    "24MHz"
};
#endif
#endif

static unsigned int sys_rsp17_addr;
//static unsigned char* ptr_ext_csd;
//static unsigned int sys_ext_csd_addr;

/************************************************************************
 *  External variables
 ************************************************************************/
extern unsigned int sys_bootcode_address;
extern unsigned int sys_bootcode_size;
extern unsigned int sys_secure_fsbl_size;
extern int sys_secure_os;
extern int sys_boot_enc;
//extern int sys_blind_uwrite;
//int sys_blind_uwrite;

unsigned int get_sdcard_blk_size(unsigned int img_size)
{

   unsigned int blkcount = 0;

   blkcount = img_size/SDCARD_BLOCK_SIZE;
   if(img_size % SDCARD_BLOCK_SIZE)
       blkcount += 1;

   return blkcount;
}


static void romcr_set_div(u4Byte set_div)
{
    u4Byte tmp_div;

    tmp_div = cr_readb(SD_CONFIGURE1) & ~MASK_CLOCK_DIV;
    cr_writeb(tmp_div|set_div,SD_CONFIGURE1);
}

static void romcr_set_bits(u4Byte set_bit)
{
    u4Byte tmp_bits;

    tmp_bits = cr_readb(SD_CONFIGURE1) & ~MASK_BUS_WIDTH;
    cr_writeb(tmp_bits|set_bit,SD_CONFIGURE1);
}

#ifdef CR_DEBUG
static void romcr_show_setting(void)
{
	u4Byte tmp_bits;
#if 1
	tmp_bits = cr_readb(CR_CLK_PAD_DRIVE);
	prints("CR_CLK_PAD_DRIVE=");
	print_hex(tmp_bits);
	prints("\n");
    tmp_bits = cr_readb(CR_CMD_PAD_DRIVE);
	prints("CR_CMD_PAD_DRIVE=");
	print_hex(tmp_bits);
	prints("\n");
    tmp_bits = cr_readb(CR_DAT_PAD_DRIVE);
	prints("CR_DAT_PAD_DRIVE=");
	print_hex(tmp_bits);
	prints("\n");
    tmp_bits = cr_readb(SD_CONFIGURE1);
	prints("SD_CONFIGURE1=");
	print_hex(tmp_bits);
	prints("\n");
    tmp_bits = cr_readb(SD_CONFIGURE2);
	prints("SD_CONFIGURE2=")
	print_hex(tmp_bits);
	prints("\n");
    tmp_bits = cr_readb(SD_CONFIGURE3);
	prints("SD_CONFIGURE3=");
	print_hex(tmp_bits);
	prints("\n");
    tmp_bits = cr_readb(SD_STATUS1);
	prints("SD_STATUS1=");
	print_hex(tmp_bits);
	prints("\n");
    tmp_bits = cr_readb(SD_STATUS2);
	prints("SD_STATUS2=");
	print_hex(tmp_bits);
	prints("\n");
    tmp_bits = cr_readb(SD_BUS_STATUS);
	prints("SD_BUS_STATUS=");
	print_hex(tmp_bits);
	prints("\n");
    tmp_bits = cr_readb(SD_CMD_MODE);
	prints("SD_CMD_MODE=");
	print_hex(tmp_bits);
	prints("\n");
    tmp_bits = cr_readb(SD_SAMPLE_POINT_CTL);
	prints("SD_SAMPLE_POINT_CTL=");
	print_hex(tmp_bits);
	prints("\n");
    tmp_bits = cr_readb(SD_PUSH_POINT_CTL);
	prints("SD_PUSH_POINT_CTL=");
	print_hex(tmp_bits);
	prints("\n");
    tmp_bits = cr_readb(SD_CMD0);
	prints("SD_CMD0=");
	print_hex(tmp_bits);
	prints("\n");
    tmp_bits = cr_readb(SD_CMD1);
	prints("SD_CMD1=");
	print_hex(tmp_bits);
	prints("\n");
    tmp_bits = cr_readb(SD_CMD2);
	prints("SD_CMD2=");
	print_hex(tmp_bits);
	prints("\n");
    tmp_bits = cr_readb(SD_CMD3);
	prints("SD_CMD3=");
	print_hex(tmp_bits);
	prints("\n");
    tmp_bits = cr_readb(SD_CMD4);
	prints("SD_CMD4=");
	print_hex(tmp_bits);
	prints("\n");
    tmp_bits = cr_readb(SD_BLOCK_CNT_L);
	prints("SD_BLOCK_CNT_L=");
	print_hex(tmp_bits);
	prints("\n");
    tmp_bits = cr_readb(SD_TRANSFER);
	prints("SD_TRANSFER=");
	print_hex(tmp_bits);
	prints("\n");
    tmp_bits = cr_readb(SD_DATA_STATE);
	prints("SD_DATA_STATE=");
	print_hex(tmp_bits);
	prints("\n");
    tmp_bits = cr_readb(SD_CMD_STATE);
	prints("SD_CMD_STATE=");
	print_hex(tmp_bits);
	prints("\n");
    tmp_bits = cr_readb(SD_DAT_PAD);
	prints("SD_DAT_PAD=");
	print_hex(tmp_bits);
	prints("\n");
//    tmp_bits = cr_readb();
//	prints("=");
//	print_hex(tmp_bits);
//	prints("\n");
#endif
}
#endif

static u1Byte romcr_get_rsp_len(u1Byte rsp_para)
{
    switch (rsp_para & 0x3) {
    case 0:
        return 0;
    case 1:
        return 6;
    case 2:
        return 16;
    default:
        return 0;
    }
}

static void romcr_read_rsp(unsigned int *rsp, int reg_count)
{
    u1Byte tmpcmd[6]={0};    
    u4Byte *ptr = rsp;

    if ( reg_count == 6 ) {
        tmpcmd[0] = cr_readb(SD_CMD0);
        tmpcmd[1] = cr_readb(SD_CMD1);
        tmpcmd[2] = cr_readb(SD_CMD2);
        tmpcmd[3] = cr_readb(SD_CMD3);
        tmpcmd[4] = cr_readb(SD_CMD4);
        tmpcmd[5] = cr_readb(SD_CMD5);
        //device is big-endian
        REG32(ptr) = (u4Byte)((tmpcmd[3]<<24) |
                 (tmpcmd[2]<<16) |
                 (tmpcmd[1]<<8) |
                  tmpcmd[0]) ;
        REG32(ptr+1) = (u4Byte)((tmpcmd[5]<<8) |
                                (tmpcmd[4]));
        
#ifdef CR_DEBUG
        prints("rsp len 6 : ");
        prints("cmd0: ");
        print_val(tmpcmd[0],2);
        prints(" cmd1: ");
        print_val(tmpcmd[1],2);
        prints(" cmd2: ");
        print_val(tmpcmd[2],2);
        prints(" cmd3: ");
        print_val(tmpcmd[3],2);
        prints(" cmd4: ");
        print_val(tmpcmd[4],2);
        prints(" cmd5: ");
        print_val(tmpcmd[5],2);
        prints(" ptr0: ");
        print_hex(REG32(ptr));
        prints(" ptr1: ");
        print_hex(REG32(ptr+1));
        prints("\n");
#endif
    } else if(reg_count == 16) {
        REG32(ptr+0) = REG32(sys_rsp17_addr+0x00);
        REG32(ptr+1) = REG32(sys_rsp17_addr+0x04);
        REG32(ptr+2) = REG32(sys_rsp17_addr+0x08);
        REG32(ptr+3) = REG32(sys_rsp17_addr+0x0c);
#if 0   // Pedro: advise by jwsyu
        REG32(ptr+4) = REG32(sys_rsp17_addr+0x10);
        REG32(ptr+5) = REG32(sys_rsp17_addr+0x14);
        REG32(ptr+6) = REG32(sys_rsp17_addr+0x18);
        REG32(ptr+7) = REG32(sys_rsp17_addr+0x1c);
#endif

#ifdef CR_DEBUG
        prints("rsp len 16B :[0] 0x");
        print_hex(REG32(ptr+0));
        prints(" [1] 0x");
        print_hex(REG32(ptr+1));
        prints(" [2] 0x");
        print_hex(REG32(ptr+2));
        prints(" [3] 0x");
        print_hex(REG32(ptr+3));
        prints(" [4] 0x");
        print_hex(REG32(ptr+4));
        prints(" [5] 0x");
        print_hex(REG32(ptr+5));
        prints(" [6] 0x");
        print_hex(REG32(ptr+6));
        prints(" [7] 0x");
        print_hex(REG32(ptr+7));
        prints("\n");
#endif
    }
}

static int romcr_wait_opt_end(u1Byte cmdcode,u4Byte cr_rd_cpu_mode)
{
    /* volatile u4Byte i=0; unused*/
    volatile int err;
    /* volatile u1Byte trans_reg=0, dma_reg=0; unused*/
    volatile s4Byte timeend = 0, loops1=0;
    volatile u4Byte /*cpu_acc_reg , unused*/ timeout_cnt=0;

    sync();
    
    cr_writeb(cmdcode|START_EN, SD_TRANSFER);

    sync();
    
    mdelay(5);//add delay 5ms jwsyu 2015.12.07
    if ((cr_readb(SD_TRANSFER) & ERR_STATUS) != 0x0) {
        //transfer error
#ifdef CR_DEBUG  
        //#if 1
        prints("\ncard trans err1 : 0x");
        print_hex(cr_readb(SD_TRANSFER));
        prints("st1 : 0x");
        print_hex(cr_readb(SD_STATUS1));
        prints("st2 : 0x");
        print_hex(cr_readb(SD_STATUS2));
        prints("bus st : 0x");
        print_hex(cr_readb(SD_BUS_STATUS));  
        prints("\n");
#endif
        return RTK_TRANS_FAIL;
    }

    //check1
    if (g_cmd[0] == 0x41) {
        timeend = 10;
        loops1 = 1000;
        err = RTK_RMOV;
        
        while(timeend ) {
            while(loops1--) {
                if ((cr_readb(SD_TRANSFER) & ERR_STATUS) != 0x0) {
                  //transfer error
#ifdef CR_DEBUG
                    prints("\ncard trans err2 : 0x");
                    print_hex(cr_readb(SD_TRANSFER));
                    prints("\n");
#endif
                    return RTK_TRANS_FAIL;
                }
                
                if ((cr_readb(SD_TRANSFER) & (END_STATE|IDLE_STATE))==(END_STATE|IDLE_STATE)) {
#ifdef CR_DEBUG  
                    prints("\ncard transferred \n");
#endif
                    err = RTK_SUCC;
                    break;
                }
                mdelay(1);
            }

            //card busy ??
            if ((cr_readb(SD_CMD1)&0x80)!=0x80) {
#ifdef CR_DEBUG  
                //#if 1
                prints("\ncard busy : retry cmd = 0x");
                print_hex(g_cmd[1]);
                prints("\n");
#endif
                //resend cmd again
                cr_writeb(g_cmd[0], SD_CMD0);
                cr_writeb(g_cmd[1], SD_CMD1);
                cr_writeb(g_cmd[2], SD_CMD2);
                cr_writeb(g_cmd[3], SD_CMD3);
                cr_writeb(g_cmd[4], SD_CMD4);
                cr_writeb(g_cmd[5], SD_CMD5);
                cr_writeb((u1Byte) (cmdcode|START_EN), SD_TRANSFER );    
                loops1 = 1000;
            }
            else {
                break;
            }
            
            mdelay(5);
            timeend--;
        }
    } else {
        //check1
        // TODO: how to decide the timeend value in ASIC ?
        timeend = 10*20*3 *3;  //max time : 600ms
        err = RTK_TOUT;
        while(timeend) {
            sync();
            if ((cr_readb(SD_TRANSFER) & ERR_STATUS) != 0x0) {
                //transfer error
#ifdef CR_DEBUG  
                //#if 1
                prints("\ncard trans err3 : 0x");
                print_hex(cr_readb(SD_TRANSFER));
                prints("\n");
                print_hex(cr_readb(SD_STATUS1));
                prints("\n");
                print_hex(cr_readb(SD_STATUS2));
                prints("\n");
#endif
                return RTK_TRANS_FAIL;
            }
            
            //if multi-read
            if ((cr_rd_cpu_mode == 1)&&(((cr_readb(SD_BLOCK_CNT_H)<<8)|cr_readb(SD_BLOCK_CNT_L)) > 1)){
        	    err = RTK_SUCC;
        		break;
        	}
            
        	if ((cr_readb(SD_TRANSFER) & (END_STATE|IDLE_STATE))==(END_STATE|IDLE_STATE)) {
        	    err = RTK_SUCC;
        		break;
        	}
            mdelay(1);
            timeend--;
        }
        
#ifdef CR_DEBUG
        if (timeend <= 0) {
            prints("\nwait sd transfer done timeout (0x18012193) : 0x");
            print_hex(cr_readb(SD_TRANSFER));
            prints("\nwait sd transfer done timeout (0x18012183) : 0x");
            print_hex(cr_readb(SD_STATUS1));
            prints("\nwait sd transfer done timeout (0x18012184) : 0x");
            print_hex(cr_readb(SD_STATUS2));
            prints("\nwait sd transfer done timeout (0x18012185) : 0x");
            print_hex(cr_readb(SD_BUS_STATUS));
            prints("\n");
			romcr_show_setting();
        }
#endif
    }

    //check2
    //work around for cpu mode that dma status always high, user has to clear it
    if (g_cmd[0] == 0x42) {
        timeout_cnt = 0;
        //polling the buf in 
        mdelay(10);

        //push the buf_full to 0
        mdelay(10);
        
        if (timeend <= 0) {
#ifdef CR_DEBUG
            prints("\ncmd 2 poll cpu_acc timeout : 0x");
            print_hex(REG32(CR_CPU_ACC));
            prints("\n");
#endif
            return ERR_SDCARD_SRAM_DMA_TIME; 
        }
        
        REG32(CR_DMA_CTL3) = 0x00; 

#ifdef CR_DEBUG
        prints("\ncmd 2 poll cpu_acc/dma to 0x");
        print_hex(REG32(CR_CPU_ACC));
        prints(", 0x");
        print_hex(REG32(CR_DMA_CTL3));
        prints("\n");
#endif
    }

    //check3
    if (cr_rd_cpu_mode == 1) {
        timeend = 100*20*3;
        err = RTK_CPU_TOUT;
#ifdef CR_DEBUG  
        prints("\ncr cpu mode - read\n");
#endif
        mdelay(10);
        return RTK_CPU_TOUT;
    }    

    return err;
}

//extern char emmc_dma_rsp_addr[16] __attribute__ ((aligned (8)));
char emmc_dma_rsp_addr[32] __attribute__ ((aligned (32)));
static int romcr_SendCMDGetRSP_Cmd(u1Byte cmd_idx,
                                   u4Byte sd_arg,
                                   s1Byte rsp_para1,
                                   u1Byte rsp_para2,
                                   s1Byte rsp_para3,
                                   u4Byte *rsp)
{
    //extern char emmc_dma_rsp_addr;
    u1Byte rsp_len, tmp_reg=0;
    int err;
    //u4Byte sa=EMMC_DMA_RSP_ADDR/8;
    u4Byte sa=VIR_2_PHY_ADDR((u4Byte)&emmc_dma_rsp_addr)/8;
    u4Byte byte_count = 0x200, block_count = 1;

/*
RET_CMD:
  unused */
    rsp_len = romcr_get_rsp_len(rsp_para2);

#ifdef CR_DEBUG
        prints("cmd_idx=0x");
        print_hex(cmd_idx);
        prints(" cmd_arg=0x");
        print_hex(sd_arg);
        prints(" rsp_para1=0x");
        print_hex((u1Byte)rsp_para1);
        prints(" rsp_para2=0x");
        print_hex(rsp_para2);
        prints(" rsp_para3=0x");
        print_hex((u1Byte)rsp_para3);
        prints(" rsp_len=0x");
        print_val(rsp_len, 2);
        prints("\n");
        prints(" byte_count=0x");
        print_hex(byte_count);
        prints(" block_count=0x");
        print_hex(block_count);
        prints("\n");        
#endif

    if (rsp_para1 != -1)
        cr_writeb((u1Byte)rsp_para1|g_bit, SD_CONFIGURE1);
    
    cr_writeb(rsp_para2, SD_CONFIGURE2);
    
    if (rsp_para3 != -1)
        cr_writeb((u1Byte)rsp_para3, SD_CONFIGURE3);

    g_cmd[0] = (0x40|cmd_idx);
    g_cmd[1] = (sd_arg>>24)&0xff;
    g_cmd[2] = (sd_arg>>16)&0xff;
    g_cmd[3] = (sd_arg>>8)&0xff;
    g_cmd[4] = (sd_arg&0xff);
    g_cmd[5] = 0x00;

#ifdef CR_DEBUG
    prints(" cmd0:");
    print_val(0x40| cmd_idx,2);
    prints(" cmd1:");
    print_val(sd_arg>>24,2);
    prints(" cmd2:");
    print_val((sd_arg>>16)&0xff,2);
    prints(" cmd3:");
    print_val((sd_arg>>8)&0xff,2);
    prints(" cmd4:");
    print_val(sd_arg&0xff,2);
    prints(" cmd5:");
    print_val(0x00,2);

    prints(" transfer:");
    print_val(SD_SENDCMDGETRSP|START_EN,2);
    
    prints("\n");
#endif
    
    cr_writeb(g_cmd[0], SD_CMD0);
    cr_writeb(g_cmd[1],  SD_CMD1);
    cr_writeb(g_cmd[2],  SD_CMD2);
    cr_writeb(g_cmd[3],   SD_CMD3);
    cr_writeb(g_cmd[4],      SD_CMD4);
    cr_writeb(g_cmd[5],      SD_CMD5);

    if (RESP_TYPE_17B & rsp_para2) {        
        tmp_reg = (RSP17_SEL|DDR_WR|DMA_XFER)&0x3f;

#ifdef CR_DEBUG
        prints("-----rsp 17B-----\n");
        prints(" DMA_sa=0x");
        print_hex(sa);
        prints(" DMA_len=0x");
        print_val(1, 2);
        prints(" DMA_setting=0x");
        print_hex(tmp_reg);
        prints(" CPU ACC = 0x");
        print_hex(CPU_MODE_EN);
        prints("\n");
#endif
        
        cr_writeb(byte_count,       SD_BYTE_CNT_L);     //0x24
        cr_writeb(byte_count>>8,    SD_BYTE_CNT_H);     //0x28
        cr_writeb(block_count,      SD_BLOCK_CNT_L);    //0x2C
        cr_writeb(block_count>>8,   SD_BLOCK_CNT_H);    //0x30

        cr_writel(sa, CR_DMA_CTL1);   //espeical for R2
        cr_writel(1, CR_DMA_CTL2);   //espeical for R2
        cr_writel(tmp_reg, CR_DMA_CTL3);   //espeical for R2
    }    
#ifdef CR_DEBUG
    else if (RESP_TYPE_6B & rsp_para2) {        
        prints("-----rsp 6B-----");
    }
#endif

    err = romcr_wait_opt_end(SD_SENDCMDGETRSP,R_W_CMD);

    if(err == RTK_SUCC){
        romcr_read_rsp(rsp, rsp_len);
    } else {
#ifdef CR_DEBUG
        prints("case I : transfer cmd fail - 0x");
        print_hex(err);
        prints("\n");
#endif
        err = ERR_SDCARD_CMD_TOUT_RSP;
    }

    return err;
}
                              
int romcr_sdcard_init(void)
{
    #define MAX_CMD_RETRY_CNT    10
	#define MAX_ACMD41_RETRY_CNT    20
    int rom_err;
    int i;
    /* int rty_cnt; unused*/
    int idle_cnt;
    u4Byte timeend;
    u4Byte rom_resp[4];
    u4Byte SD_Response1;
    int cmd_retry_cnt=0;
    int acmd41_retry_cnt=0;
    //extern char emmc_dma_rsp_addr;

#ifdef CR_DEBUG
    prints("romcr_sdcard_init\n");
#endif

    rtlRegMask(REG_ENABLE_IP, 1, 1); //sd_ctrl_Pwr=1

    //sys_rsp17_addr = CR_DMA_ADDR1 & ~0xff;   //17B
    sys_rsp17_addr = PHY_2_CACHE_ADDR((u4Byte)&emmc_dma_rsp_addr) & ~0xff;   //17B
//    sys_ext_csd_addr = sys_rsp17_addr+0x20; //512B
//    ptr_ext_csd = (u1Byte*)sys_ext_csd_addr;

    // set sd30 8051 mcu register map_sel=1, access enable
    i = cr_readl(CR_SRAM_CTL);
    cr_writel(i | 0x20, CR_SRAM_CTL);

    // stop and reset sd3.0
    cr_writeb( 0x4, CR_CARD_STOP);

    //set clock control
    cr_writel( 0x2102, SD_CKGEN_CTL);

    sdcard_rca = 1;

    //CARD_EXIST
    i = cr_readb( CARD_EXIST );

#ifdef CR_DEBUG
        prints("CARD_EXIST: 0x");
        print_hex(i);
        prints("\n");
    if (i&0x4)
	prints("SD/MMC card in its socket\n");
    if (i&0x20) {
	prints("SD/MMC card write protected\n");
    } else
	prints("SD/MMC card write protect off \n");
#endif


    cr_writeb( 0x2, CARD_SELECT );            //select SD

    cr_writeb( 0x4, CR_CARD_OE );

	udelay(50000);
    rtlRegMask(REG_ENABLE_IP, 1, 0); //sd_ctrl_Pwr=0
	udelay(50000);

    romcr_set_div(SDCLK_DIV | CLOCK_DIV_256);
    //set clock control
    cr_writel( 0x2102, SD_CKGEN_CTL);
    //input clock = 208Mhz, init mode clock <400Khz
    //div256, div4 = 203Khz

    idle_cnt = 5;

RE_IDLE:
    if (bErrorRetry_1) {
        cr_writeb( 0x8, SD_SAMPLE_POINT_CTL );    //sample point = SDCLK / 4 (delay)
        cr_writeb( 0x10, SD_PUSH_POINT_CTL );     //output ahead SDCLK 3/4 
    } else {
        cr_writeb( 0x0, SD_SAMPLE_POINT_CTL );    //sample point = 0 (rising edge)
        cr_writeb( 0x0, SD_PUSH_POINT_CTL );     //output ahead SDCLK 1/2 
    }

    mdelay(100);
    
    /* CMD0 ==> Idle state */
    for(i=0;i<idle_cnt;i++) {

#ifdef CR_DEBUG
    prints("cmd0 idle_cnt:");
    print_hex(i);
    prints("/");
    print_hex(idle_cnt);
    prints("\n");
#endif
        udelay(100);
        rom_err = romcr_SendCMDGetRSP_Cmd(MMC_GO_IDLE_STATE,
                                0x00000000,
                                SD1_R0,
                                0x50|SD_R0,
                                0,
                                rom_resp);
        if (rom_err) {
            bErrorRetry_1 = !bErrorRetry_1;
        }
    }

    /* Idle state ==> CMD8 ==> Idle state*/
    rom_err = 0;
    timeend = 100;

    udelay(1000);
    rom_err = romcr_SendCMDGetRSP_Cmd(SD_SEND_IF_COND,
                                0x1aa,
                                SD1_R0,
                                SD_R7,
                                0,
                                rom_resp);

    if(rom_err) {
        if (cmd_retry_cnt++ <= MAX_CMD_RETRY_CNT) {
            goto RE_IDLE;
        }
        goto err_out;
    }

    if(rom_resp[0] == 0xffffffff) {
		if (cmd_retry_cnt++ <= MAX_CMD_RETRY_CNT) {
	        bErrorRetry_1 = !bErrorRetry_1;
    	    goto RE_IDLE;
		}
		rom_err = ERR_SDCARD_CMD8_FAIL;
		goto err_out;
    }



    /* ACMD41, CMD55 + CMD41 ==> Ready state*/
RE_ACMD41:
    rom_err = 0;
    timeend = 100;

    udelay(1000);
    rom_err = romcr_SendCMDGetRSP_Cmd(MMC_APP_CMD,
                                0x0000000,
                                SD1_R0,
                                SD_R1,
                                0,
                                rom_resp);

    if(rom_err) {
        if (cmd_retry_cnt++ <= MAX_CMD_RETRY_CNT) {
            goto RE_IDLE;
        }
        goto err_out;
    }

    if(rom_resp[0] == 0xffffffff) {
        bErrorRetry_1 = !bErrorRetry_1;
        goto RE_IDLE;
    }

    rom_err = 0;
    timeend = 100;

    udelay(5000);
    rom_err = romcr_SendCMDGetRSP_Cmd(SD_APP_OP_COND,
                                0x50ff8000,
                                SD1_R0,
                                SD_R3,
                                0,
                                rom_resp);

    if(rom_err) {
        if (cmd_retry_cnt++ <= MAX_CMD_RETRY_CNT) {
            goto RE_IDLE;
        }
        goto err_out;
    }

    if(rom_resp[0] == 0xffffffff) {
        bErrorRetry_1 = !bErrorRetry_1;
        goto RE_IDLE;
    }

#ifdef CR_DEBUG
    prints("ACMD41 response:");
    print_hex(rom_resp[0]);
    prints("\n");
#endif
    if((rom_resp[0] & 0x8000) == 0x0) { // card busy
        if (acmd41_retry_cnt++ <= MAX_ACMD41_RETRY_CNT) {
#ifdef CR_DEBUG
            prints("RE_ACMD41\n");
#endif
			mdelay(60); // max acmd41 busy time is 1 sec. jwsyu 20151209 (60*20=1200ms)
            goto RE_ACMD41;
        } 
		rom_err = ERR_SDCARD_ACMD41_FAIL;
        goto err_out;
    }




    /* Ready state ==> CMD2 */
    udelay(1000);
    rom_err = 0;
    
    rom_err = romcr_SendCMDGetRSP_Cmd(MMC_ALL_SEND_CID,
                                0x00000000,
                                SD1_R0,
                                SD_R2,
                                0x10|SD2_R0,
                                //-1,
                                sdcard_raw_cid);

    if(rom_err) {
        bErrorRetry_1 = !bErrorRetry_1;
        if (cmd_retry_cnt++ <= MAX_CMD_RETRY_CNT) {
            goto RE_IDLE;
        }
        goto err_out;
    }
    
    /* Indentification state ==> CMD3 */
    udelay(1000);
    rom_err = 0;

    rom_err = romcr_SendCMDGetRSP_Cmd(SD_SEND_RELATIVE_ADDR,
                                0x00000000,
                                SD1_R0, 
                                SD_R6,
                                0,
                                rom_resp);

    if (rom_err) {
        bErrorRetry_1 = !bErrorRetry_1;
        if (cmd_retry_cnt++ <= MAX_CMD_RETRY_CNT) {
            goto RE_IDLE;
        }
        rom_err = ERR_SDCARD_CMD3_FAIL;
        goto err_out;
    }
    sdcard_rca = ((rom_resp[0]&0xff0000)>>16) | (rom_resp[0]&0xff00);
#ifdef CR_DEBUG
    prints("CMD3 RCA response:");
    print_hex(rom_resp[0]);
    prints(". sdcard_rca:");
    print_hex(sdcard_rca);
    prints("\n");
#endif
    
    /* change divider to non */
    //romcr_set_div(CLOCK_DIV_NON);
    //romcr_set_div(SDCLK_DIV | CLOCK_DIV_128);
    //set clock control
    //cr_writel( 0x2103, SD_CKGEN_CTL);

    /* reset sample ctl */
    if (!bErrorRetry_2) {
        cr_writeb( 0x8, SD_SAMPLE_POINT_CTL );    //sample point = SDCLK / 4
        cr_writeb( 0x10, SD_PUSH_POINT_CTL );     //output ahead SDCLK /4 
    } else {
        cr_writeb( 0x0, SD_SAMPLE_POINT_CTL );    //sample point = SDCLK / 4
        cr_writeb( 0x0, SD_PUSH_POINT_CTL );     //output ahead SDCLK /4 
    }        

    /* Standy-by state ==> CMD7 */
    udelay(1000);
    rom_err = 0;

    rom_err = romcr_SendCMDGetRSP_Cmd(MMC_SELECT_CARD,
                                sdcard_rca << RCA_SHIFTER,
                                0,
                                SD_R1b|CRC16_CAL_DIS,
                                0,
                                rom_resp);

    if(rom_err) {
        bErrorRetry_2 = !bErrorRetry_2;
        if (cmd_retry_cnt++ <= MAX_CMD_RETRY_CNT) {
            goto RE_IDLE;
        }
        rom_err = ERR_SDCARD_CMD7_FAIL;
        goto err_out;
    }

    //rom_err = R1_CURRENT_STATE(rom_resp[0]);
    SD_Response1 = ((rom_resp[0]<<16)&0xff000000) | (rom_resp[0]&0x00ff0000) | ((rom_resp[0]>>16)&0x0000ff00);
#ifdef CR_DEBUG
    print_hex(rom_resp[0]);
    prints(".");
    print_hex(SD_Response1);
    prints("\n");
#endif
    if(SD_Response1 & R1_READY_FOR_DATA) {
        udelay(1);
    } else {
        udelay(30);
    }

    rom_err = 0;

    /* change to 4bits width ==> ACMD6 (CMD55 + CMD6) */
#if 1
    // Note: change BUS_WIDTH
    // need to change 3 lines (2 variables) in the following code
    // for 1-bit mode: SD_BUS_WIDTH_1 and BUS_WIDTH_1
    // for 4-bit mode: SD_BUS_WIDTH_4 and BUS_WIDTH_4
#define ROM_SD_BUS_WIDTH    SD_BUS_WIDTH_4
#define ROM_BUS_WIDTH       BUS_WIDTH_4
    u4Byte arg;
    rom_err = 0;
	g_bit = ROM_BUS_WIDTH;
    arg = ROM_SD_BUS_WIDTH;

    rom_err = romcr_SendCMDGetRSP_Cmd(MMC_APP_CMD,
                                sdcard_rca << RCA_SHIFTER,
                                0,
                                SD_R1b,
                                0,
                                rom_resp);
    if(rom_err)
        goto err_out;

    rom_err = romcr_SendCMDGetRSP_Cmd(SD_APP_SET_BUS_WIDTH,
                                arg,
                                0,
                                SD_R1b|CRC16_CAL_DIS,
                                0,
                                rom_resp);
    if(rom_err)
        goto err_out;
#if 1  //sdcard don't need wait status change complete..
    udelay(1000);
#else
    /* To wait status change complete */
    rom_err = 0;
    timeend = 100;
    do {
        udelay(10);
        rom_err = romcr_SendCMDGetRSP_Cmd(MMC_SEND_STATUS,
                                          sdcard_rca << RCA_SHIFTER,
                                          0x10,
                                          SD_R1|CRC16_CAL_DIS,
                                          0,
                                          rom_resp);

        if(rom_err) {
            goto err_out;
        }

    } while((R1_CURRENT_STATE(rom_resp[0]) == STATE_PRG) && timeend);
#endif
    //if ((rom_resp[0] & R1_SWITCH_ERROR) || (timeend==0))  {
    //    rom_err = ERR_SDCARD_STATUS_FAIL;
    //    goto err_out;
    //} else {
        romcr_set_bits(ROM_BUS_WIDTH); // romcr_set_bits(BUS_WIDTH_8);

		sync();
#ifdef CR_DEBUG
  #if (ROM_BUS_WIDTH == BUS_WIDTH_4)
        prints("SDcard 4-bits mode, clk div 8\n");// default speed up to 25Mhz, 208/8/2=13Mhz.
  #else
        prints("SDcard 1-bits mode, clk div 8\n");// default speed up to 25Mhz, 208/8/2=13Mhz.
  #endif
#endif			
    		/* change divider to non */
    		romcr_set_div(CLOCK_DIV_NON);
		//change driving
//		REG8(CR_CLK_PAD_DRIVE) = 0x66;    // REG8(0x18012130) = 0x66;
//		REG8(CR_CMD_PAD_DRIVE) = 0x64;    // REG8(0x18012131) = 0x64;
//		REG8(CR_DAT_PAD_DRIVE) = 0x66;    // REG8(0x18012132) = 0x66;
		REG8(CR_CLK_PAD_DRIVE) = 1 | (1<<3);    // REG8(0x18012130) = 0x66;
		REG8(CR_CMD_PAD_DRIVE) = 1 | (1<<3);    // REG8(0x18012131) = 0x64;
		REG8(CR_DAT_PAD_DRIVE) = 1 | (1<<3);    // REG8(0x18012132) = 0x66;
		//change clock
		REG32(CR_CKGEN_CTL) = 0x2103;   // REG32(0x18012078) = 0x2101;
		sync();
    //}
#endif

err_out:
    return rom_err;
}

static u1Byte get_rsp_type(struct mmc_command* cmd )
{
    u1Byte rsp_type = 0;

    /* the marked case are used. */
    switch(cmd->opcode) {
        case 3:
        case 7:     // select_card
        //case 12:  // stop_transmission-read case
        case 13:
        case 16:
        case 23:
        case 35:
        case 36:
        case 55:
            rsp_type |= CRC16_CAL_DIS;

        case 8:
        case 11:
        case 14:
        case 19:
        case 17:
        case 18:
        case 20:
        case 24:
        case 25:
        case 26:
        case 27:
        case 30:
        case 42:
        case 56:
            rsp_type |= SD_R1;
            break;
        case 6:
        //case 7:   // deselect_card
        case 12:    // stop_transmission-write case
        case 28:
        case 29:
        case 38:
            rsp_type = SD_R1b|CRC16_CAL_DIS;
            break;
        case 2:
        case 9:
        case 10:
            rsp_type = SD_R2;
            break;
        case 1:
            rsp_type = SD_R3;
            break;
        //case 39:
        //  rsp_type = SD_R4;
        //  break;
        //case 40:
        //  rsp_type = SD_R5;
        //  break;
        default:
            rsp_type = SD_R0;
            break;
    }

    return rsp_type;
}

static int mmc_send_stop( void )
{
    unsigned int rsp_buffer[4];

    return romcr_SendCMDGetRSP_Cmd(MMC_STOP_TRANSMISSION, sdcard_rca << RCA_SHIFTER, -1, SD_R1|CRC16_CAL_DIS, 0, rsp_buffer);
}
#if 0 //not support sram fifo read
u4Byte romcr_read_sram_dma_data(u4Byte sram_buf, u4Byte block_count)
{
	u4Byte i=0,blk_no=0;
    u4Byte fifo_tmp0=0, fifo_tmp1=0;
    s4Byte time_cnt=0;
    u4Byte cpu_acc_reg=0, dma_reg=0,tran_reg=0;
    
    if(sram_buf) {
#ifdef CR_DEBUG
        prints("sram_buf addr: 0x");
        print_hex(sram_buf);
        prints("\n");
        prints("Read data from SRAM FIFO : blk_cnt=0x");
        print_hex(block_count);
        prints("\n");
#endif

        while (block_count--) {
#ifdef CR_DEBUG
            //sys_blind_uwrite = 1;
            prints("\n[blk no. ");
            print_val(block_count+1, 2);
            prints(" \n");
#endif
            
            //1st half blk
            for( i=0; i<512/4; i+=2 ) {
                sync();
                fifo_tmp0 = cr_readl(CR_SRAM_BASE_0+i*4);
                fifo_tmp1 = cr_readl(CR_SRAM_BASE_0+(i+1)*4);
                sync();
                REG32(sram_buf+(blk_no*0x200)+(i*4))= swap_endian(fifo_tmp1);
                REG32(sram_buf+(blk_no*0x200)+(i+1)*4) = swap_endian(fifo_tmp0);
                sync();
#ifdef CR_DEBUG
                prints(" 0x");
                print_hex(REG32(sram_buf+(blk_no*0x200)+(i*4)));
                prints(" 0x");
                print_hex(REG32(sram_buf+(blk_no*0x200)+(i+1)*4));
                if ((i%10 == 0)&&(i!=0)) {
                    prints("\n");
                }
#endif
            }
            
            if (block_count==0) {
                time_cnt=40*500; //1sec to timeout
                for(i=time_cnt;i>0;i--) {
                    tran_reg = REG32(SD_TRANSFER);
                    if ((tran_reg & END_STATE) == END_STATE)
                        break;
                    mdelay(1);
                }
                if (i <= 0) {
                    return ERR_SDCARD_SRAM_DMA_TIME; 
                }
            }
            
            if (block_count>=0)  {
                //get next block
                cpu_acc_reg = REG32(CR_CPU_ACC);
                REG32(CR_CPU_ACC) = cpu_acc_reg|0x3;
                time_cnt=10*1000; //1sec to timeout
                
                for(i=time_cnt;i>0;i--) {
                    cpu_acc_reg = REG32(CR_CPU_ACC);
                    if ((cpu_acc_reg & BUF_FULL) == BUF_FULL) {
                        break;
                    }
                    udelay(100);
                }
                if (i <= 0) {
                    return ERR_SDCARD_SRAM_DMA_TIME; 
                }
                blk_no++;
            }
            
        }
    }
    //sys_blind_uwrite = 0;
    
    //polling the buf_full to 0
#ifdef CR_DEBUG
    prints("\npolling buf_full to 0\n");
#endif

    sync();
    cpu_acc_reg = REG32(CR_CPU_ACC);
    time_cnt=10*500; //1sec to timeout
    
    for(i=time_cnt;i>0;i--) {
        cpu_acc_reg = REG32(CR_CPU_ACC);
        if ((cpu_acc_reg & BUF_FULL) == 0x00) {
            break;
        }
        mdelay(1);
    }
    if (i <= 0) {
        return ERR_SDCARD_SRAM_DMA_TIME; 
    }

//polling dma to 0
#ifdef CR_DEBUG
    prints("polling dma ctl3 to 0\n");
#endif

    time_cnt=10*500; //1sec to timeout
    for(i=time_cnt;i>0;i--) {
        sync();
        dma_reg = REG32(CR_DMA_CTL3);
        if ((dma_reg  & DMA_XFER) == 0x00) {
            break;
        }
        mdelay(1);
    }
    
    if (i <= 0) {
        return ERR_SDCARD_SRAM_DMA_TIME; 
    }

    return 0;
}
#endif
static int romcr_Stream_Cmd(u2Byte cmdcode,struct sd_cmd_pkt *cmd_info)
{
    u1Byte cmd_idx       =   cmd_info->cmd->opcode;
    u4Byte sd_arg       =   cmd_info->cmd->arg;
    u4Byte *rsp         =   cmd_info->cmd->resp;
    u1Byte rsp_para1      =   cmd_info->rsp_para1;
    u1Byte rsp_para2      =   cmd_info->rsp_para2;
    u1Byte rsp_para3      =   cmd_info->rsp_para3;
    int rsp_len         =   cmd_info->rsp_len;
    u2Byte byte_count   =   cmd_info->byte_count;
    u4Byte block_count  =   cmd_info->block_count;
    void *data          =   cmd_info->dma_buffer;
    int err;
    u4Byte phy_addr = (u4Byte)(data);
    u4Byte cpu_mode = 0;

#ifdef CR_DEBUG
    prints("cmd_idx=0x");
    print_hex(cmd_idx);
    prints(" cmd_arg=0x");
    print_hex(sd_arg);
    prints(" rsp_para1=0x");
    print_hex(rsp_para1);
    prints(" rsp_para2=0x");
    print_hex(rsp_para2);
    prints(" rsp_para3=0x");
    print_hex(rsp_para3);
    prints("\n");
    prints(" rsp_len=0x");
    print_hex(rsp_len);
    prints(" byte_count=0x");
    print_hex(byte_count);
    prints(" block_count=0x");
    print_hex(block_count);
    prints("\n");
#endif

    cmd_info->err_case = 0;

    /* for SD_NORMALWRITE/SD_NORMALREAD can't check CRC16 issue */
    if((cmdcode==SD_NORMALWRITE) || (cmdcode==SD_NORMALREAD)) {
        byte_count = 512;
    }

    g_cmd[0] = (0x40|cmd_idx);
    g_cmd[1] = (sd_arg>>24)&0xff;
    g_cmd[2] = (sd_arg>>16)&0xff;
    g_cmd[3] = (sd_arg>>8)&0xff;
    g_cmd[4] = (sd_arg&0xff);
    g_cmd[5] = 0x00;

    cr_writeb(g_cmd[0], SD_CMD0); //0x10
    cr_writeb(g_cmd[1], SD_CMD1); //0x14
    cr_writeb(g_cmd[2], SD_CMD2); //0x18
    cr_writeb(g_cmd[3], SD_CMD3); //0x1C
    cr_writeb(g_cmd[4], SD_CMD4); //0x20

#ifdef CR_DEBUG
    prints(" cmd0:");
    print_val(0x40| cmd_idx,2);
    prints(" cmd1:");
    print_val(sd_arg>>24,2);
    prints(" cmd2:");
    print_val((sd_arg>>16)&0xff,2);
    prints(" cmd3:");
    print_val((sd_arg>>8)&0xff,2);
    prints(" cmd4:");
    print_val(sd_arg&0xff,2);
    prints(" cmd5:");
    print_val(0x00,2);
    prints("\n");
#endif

    
    if (rsp_para1 != -1) {
        cr_writeb(rsp_para1|g_bit, SD_CONFIGURE1);     //0x0C
    }
    cr_writeb(rsp_para2,       SD_CONFIGURE2);     //0x0C
    if (rsp_para3 != -1) {
        cr_writeb(rsp_para3,       SD_CONFIGURE3);     //0x0C
    }
    cr_writeb(byte_count,       SD_BYTE_CNT_L);     //0x24
    cr_writeb(byte_count>>8,    SD_BYTE_CNT_H);     //0x28
    cr_writeb(block_count,      SD_BLOCK_CNT_L);    //0x2C
    cr_writeb(block_count>>8,   SD_BLOCK_CNT_H);    //0x30

   	if( cmd_info->flags & MMC_DATA_WRITE) {
#ifdef CR_DEBUG  
        prints("-----sdcard data write-----\n");
        prints("DMA sa = 0x");
        print_hex(phy_addr/8);
        prints("\nDMA len = 0x");
        print_hex(block_count);
        prints("\nDMA set = 0x");
        print_hex(DMA_XFER);
        prints("\n");
#endif

        cr_writel( 0, CR_CPU_ACC);
        cr_writel( phy_addr/8, CR_DMA_CTL1);
        cr_writel( block_count, CR_DMA_CTL2);
        cr_writel( DMA_XFER, CR_DMA_CTL3);  
    } else {
        if( cmd_info->flags & MMC_SRAM_READ) {
#ifdef CR_DEBUG  
            prints("-----sdcard data sram read (cpu mode)-----\n");
            prints("CR_CPU_ACC(0x18012080) = 0x");
            print_hex(CPU_MODE_EN);
            prints("DMA sa = 0x");
            print_hex(phy_addr/8);
#endif
            //multi-read
            if (cmd_idx == 0x12) {
                cpu_mode = 1;
            }
            cr_writel( CPU_MODE_EN, CR_CPU_ACC);
            cr_writel( phy_addr/8, CR_DMA_CTL1);
#ifdef CR_DEBUG  
            prints("\n");
#endif
        } else {
#ifdef CR_DEBUG  
            prints("-----sdcard data ddr read-----\n");
            prints("DMA sa = 0x");
            print_hex(phy_addr/8);
#endif
            cr_writel( 0x00, CR_CPU_ACC);
            cr_writel( phy_addr/8, CR_DMA_CTL1);
        }
#ifdef CR_DEBUG
        prints("\nDMA len = 0x");
        print_hex(block_count);
        prints("\nDMA set = 0x");
        print_hex(DDR_WR|DMA_XFER);
#endif
        cr_writel( block_count, CR_DMA_CTL2);
        cr_writel( DDR_WR|DMA_XFER, CR_DMA_CTL3);  
#ifdef CR_DEBUG  
       prints("\n");
#endif
    }

    err = romcr_wait_opt_end(cmdcode, cpu_mode);
    
    if(err == RTK_SUCC) {
        if( cmd_info->flags == MMC_SRAM_READ ) {
#if 0 //not support romcr_read_sram_dma_data
            if ((err = romcr_read_sram_dma_data(phy_addr, block_count)) == ERR_SDCARD_SRAM_DMA_TIME) {
                return err;
            }
            udelay(1000);
#endif
        } else {
            romcr_read_rsp(rsp, rsp_len);
        }
    } else {
        cmd_info->err_case = err;
        err = ERR_SDCARD_CMD_TOUT_STR;
    }
/*    
err_out:
  unused */
    return err;
}


static int romcr_Stream(u4Byte tar_addr,
                        u4Byte blk_cnt,
                        u1Byte acc_mod,
                        u1Byte *dma_buffer)
{
    struct sd_cmd_pkt cmd_info;
    struct mmc_command  cmd;
    u2Byte cmdcode;
    int err = -1;
    u1Byte rsp_type;

    cmd_info.cmd = &cmd;
    cmd.arg     = tar_addr;

    if(acc_mod & MMC_DATA_WRITE ){
        cmdcode = SD_AUTOWRITE2;
        cmd.opcode = 24; /* cmd24 is WRITE_BLOCK */
    } else {
        cmdcode = SD_AUTOREAD2;
        cmd.opcode = 17; /* cmd17 is READ_SINGLE_BLOCK */
    }

    /* multi sector accress opcode */
    if(blk_cnt > 1) {
        cmd.opcode++; /* cmd25 is WRITE_MULTIPLE_BLOCK, cmd18 is READ_MULTIPLE_BLOCK */
        cmdcode -= 1;
    }

    rsp_type = get_rsp_type(&cmd);

    cmd_info.rsp_para1       = 0x00;
    cmd_info.rsp_para2       = rsp_type;
    cmd_info.rsp_para3       = 0x05;
    cmd_info.rsp_len        = romcr_get_rsp_len(rsp_type);
    cmd_info.byte_count     = 0x200;
    cmd_info.block_count    = blk_cnt;
    cmd_info.dma_buffer     = dma_buffer;
    cmd_info.flags          = acc_mod;
    
    err = romcr_Stream_Cmd(cmdcode,&cmd_info);
    
    //reset cmd0
    g_cmd[0] = 0x00;
    
    return err;
}


static void sample_ctl_switch(u4Byte bWrite)
{
    bErrorRetry_2 = !bErrorRetry_2;
    if (!bErrorRetry_2) {
#ifdef CR_DEBUG
        prints("mode switch 1\n");
#endif
        if (bWrite == 0) {
            cr_writeb( 0x8, SD_SAMPLE_POINT_CTL );    //sample point = SDCLK / 4
        } else {
            cr_writeb( 0x10, SD_PUSH_POINT_CTL );     //output ahead SDCLK /4 
        }
    } else {
#ifdef CR_DEBUG
        prints("mode switch 0\n");
#endif
        if (bWrite == 0) {
            cr_writeb( 0x0, SD_SAMPLE_POINT_CTL );    //sample point = SDCLK / 4
        } else {
            cr_writeb( 0x0, SD_PUSH_POINT_CTL );     //output ahead SDCLK /4 
        }
    }
    mdelay(5);
    REG8(CR_CARD_STOP) = 0x14;
    mdelay(5);
}

static int romcr_send_status(u1Byte* state)
{
    u4Byte rom_resp[4];
    int rom_err = 0;
    u4Byte SD_Response1;

    rom_err = romcr_SendCMDGetRSP_Cmd(MMC_SEND_STATUS,
                                   sdcard_rca << RCA_SHIFTER,
                                   -1,
                                   SD_R1|CRC16_CAL_DIS,
                                   0,
                                   rom_resp);
    if(rom_err) {
#ifdef CR_DEBUG
        prints("MMC_SEND_STATUS fail\n");
#endif
    } else {
	SD_Response1 = ((rom_resp[0]<<16)&0xff000000) | (rom_resp[0]&0x00ff0000) | ((rom_resp[0]>>16)&0x0000ff00);

#ifdef CR_DEBUG
        prints("rom_resp[0]=");
        print_hex(rom_resp[0]);
	prints(",SD_Response1=");
	print_hex(SD_Response1);
        prints("\n");
#endif

        u1Byte cur_state = R1_CURRENT_STATE(SD_Response1);
        *state = cur_state;
#ifdef CR_DEBUG
        prints("cur_state=");
        prints(sdcard_state_tlb[cur_state]);
        print_hex(cur_state);
        prints("\n");
#endif
    }

    return rom_err;
}

// Note: SD card target address must 8 byte alignment !!!
int romcr_sdcard_blk_ops(u4Byte bWrite, u4Byte tar_addr,u4Byte blk_cnt,u1Byte *dma_buffer)
{
    u1Byte ret_state=0;
    u4Byte tar_dest=0, bRetry=0;
    u4Byte retry_cnt=0, retry_cnt1=0, retry_cnt2=0, retry_cnt3=0;
    int err = 0, err1=0;

#ifdef CR_DEBUG
    prints("romcr_sdcard_blk_ops(");
    print_hex(tar_addr);
    prints(", ");
    print_hex(blk_cnt);
    prints(", ");
    print_hex((u4Byte)dma_buffer);
    prints(")\n");
#endif

RETRY_RD_CMD:

	tar_dest = tar_addr;

    if (!bWrite) {
            err = romcr_Stream( tar_dest, blk_cnt, MMC_DATA_READ, dma_buffer);
    } else {
        err = romcr_Stream( tar_dest, blk_cnt, MMC_DATA_WRITE, dma_buffer);
    }
    
#ifdef CR_DEBUG
    prints("romcr_sdcard_blk_ops(");
    print_hex(__LINE__);
    prints(")\n ");
#endif
    if (err) {
        if (retry_cnt2%3 == 0) {
            sample_ctl_switch(bWrite);
        }
        if (retry_cnt2++ < SDCARD_MAX_STOP_CMD_RETRY_CNT) {
		    prints("romcr_sdcard_blk_ops-error(");
		    print_hex(err);
  			prints(")\n ");
#ifdef CR_DEBUG
			romcr_show_setting();
#endif
            prints("RETRY_RD_CMD\n");
            goto RETRY_RD_CMD;
        }
        return err;
    }
	
    /* To wait status change complete */
    bRetry=0;
    retry_cnt=0;
    retry_cnt1=0;
    
    while(1) {
        err1 = romcr_send_status(&ret_state);
        //1. if cmd sent error, try again
        if (err1) {
            if (retry_cnt%5 == 0) {
                sample_ctl_switch(bWrite);
            }
            if (retry_cnt++ > SDCARD_MAX_CMD_SEND_RETRY_CNT) {
                return ERR_SDCARD_SEND_STATUS_RETRY_FAIL;
            }
            mdelay(1);
            continue;
        }
        
        //2. get state
        if (ret_state != STATE_TRAN) {
            bRetry = 1;
            if (retry_cnt1++ > SDCARD_MAX_STOP_CMD_RETRY_CNT) {
                return ERR_SDCARD_SEND_RW_CMD_RETRY_FAIL;
            }
            mmc_send_stop();
            mdelay(1000);
        } else {
            //out peaceful
            if (bRetry == 0){
				if (bWrite)
					prints(".");
				return 0;
            } else {
                retry_cnt2 = 0;
                if (retry_cnt3++ > SDCARD_MAX_STOP_CMD_RETRY_CNT) {
                    return ERR_SDCARD_SEND_RW_CMD_RETRY_FAIL;
                }
                goto RETRY_RD_CMD;
            }
        }
    }
#if 0
	if (bWrite) {
		prints(".");
    }
    
    return 0;
#endif
}

int load_data_from_sdcard(unsigned int addr, unsigned int blk_num, unsigned char* signature)
{
    s4Byte ret_val;

#if FILE_SYSTEM_FAT
    FATFS fatFs;
    FIL fil;
    u4Byte br;
    char filename[11] = UBOOT_FILE_NAME;
    PIMG_HEADER_TYPE p_header = (PIMG_HEADER_TYPE)addr;

    fatFs.win = (unsigned char *)CACHE_2_NONCACHE_ADDR((unsigned int)fatFs.win1);

    ret_val = f_mount(0, (FATFS *)(&fatFs));
    ret_val = f_open((FIL *)(&fil), filename, FA_READ);

    if (ret_val) {
        prom_printf(("%s(%d): open file fail(0x%x) \n", __FUNCTION__, __LINE__, ret_val));
        return -1;
    }

    ret_val = f_read((FIL *)(&fil), (unsigned char *)addr, fil.fsize, &br);
    prom_printf(("%s(%d): read 0x%x byte to 0x%x\n", __func__, __LINE__, fil.fsize, addr));
    f_close(&fil);
/*
    if (check_image_header(p_header, signature) == FALSE) {
        return -1;
    }
*/
#else
    u4Byte blk_cnt;
    IMG_HEADER_TYPE header;

    blk_cnt = 1;
    ret_val = romcr_sdcard_blk_ops(0, blk_num, blk_cnt, (u1Byte *)(VIR_2_PHY_ADDR(addr)));
    memcpy(&header, (void *)(addr), sizeof(IMG_HEADER_TYPE));
    addr = VIR_2_PHY_ADDR(addr);
/*
    if (check_image_header(&header, signature) == 0) {
        return -1;
    }
*/
    // already load one block by the upper code
    // 1) start from block 1
    // 2) block count = total block -1
    // 3) load address is DMA_ADDR + BLOCK_SIZE
    // NOTE: we don't check checksum in header because only transfer data by internal IP
    blk_cnt = get_sdcard_blk_size(header.len) - 1;
    if (blk_cnt > 0) {
        blk_num++;
        ret_val = romcr_sdcard_blk_ops(0, blk_num, blk_cnt, (u1Byte *)(addr + SDCARD_BLOCK_SIZE));
    }
#endif

    return ret_val;
}

