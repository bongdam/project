#ifndef	__SDCARD_H__
#define __SDCARD_H__

//add by angus for test, reset emmc each time
//#define EMMC_CLKSEL_MASK         (0x07<<12)
//#define CARD_SWITCHCLOCK_30MHZ   (0x04<<12)

//#define dd2 (HW_SEG1&~0x0F)
//#define dd3 0xa0000
#ifndef SDCARD_BLOCK_SIZE
#define SDCARD_BLOCK_SIZE         512
#endif // from ./emmc/include/sysdefs.h:18

//#define CR_DEBUG
#define sync()

/* realtek definition */
#define cr_writel(value,addr)   REG32(addr) = value
#define cr_readl(addr)          REG32(addr)
#define cr_writeb(value,addr)   REG8(addr) = value
#define cr_readb(addr)          REG8(addr)


#define SIG_LEN			    4
typedef struct _IMG_HEADER_TYPE_
{
	unsigned char signature[SIG_LEN];
	unsigned long startAddr;
	unsigned long burnAddr;
	unsigned long len;
} IMG_HEADER_TYPE, *PIMG_HEADER_TYPE;

#define REG_SYS_EMMC_SD_1       (BIT_ACTIVE_LX1ARB|BIT_ACTIVE_LX1)
#define REG_SYS_EMMC_SD_2       (BIT_ACTIVE_SD30|BIT_ACTIVE_SD30_PLL5M)
#define ENABLE_EMMC_SD  \
    do { \
        REG32(REG_CLK_MANAGE) = REG32(REG_CLK_MANAGE) | REG_SYS_EMMC_SD_1;      \
        REG32(REG_CLK_MANAGE2) = REG32(REG_CLK_MANAGE2) | REG_SYS_EMMC_SD_2;    \
    } while(0);
	

#define ON                      0
#define OFF                     1

#define DMA_CMD 3
#define R_W_CMD 2   //read/write command
#define INN_CMD 1   //command work chip inside
#define UIN_CMD 0   //no interrupt rtk command

#define RTK_TRANS_FAIL 6
#define RTK_CPU_TOUT 5 /* cpu mode timeout */
#define RTK_TOUT1 4  /* time out 2nd time */
#define RTK_FAIL 3  /* DMA error & cmd parser error */
#define RTK_RMOV 2  /* card removed */
#define RTK_TOUT 1  /* time out include DMA finish & cmd parser finish */
#define RTK_SUCC 0

#define BYTE_CNT            0x200
#define DMA_BUFFER_SIZE     128*512
#define RTK_NORM_SPEED      0x00
#define RTK_HIGH_SPEED      0x01
#define RTK_1_BITS          0x00
#define RTK_4_BITS          0x10
//#define RTK_8_BITS          0x11
#define RTK_BITS_MASK       0x30
#define RTK_SPEED_MASK      0x01
#define RTK_PHASE_MASK      0x06

/* send status event */
#define STATE_IDLE  0
#define STATE_READY 1
#define STATE_IDENT 2
#define STATE_STBY  3
#define STATE_TRAN  4
#define STATE_DATA  5
#define STATE_RCV   6
#define STATE_PRG   7
#define STATE_DIS   8

#define SDCARD_VDD_30_31  0x00040000  /* VDD voltage 3.0 ~ 3.1 */
#define SDCARD_VDD_31_32  0x00080000  /* VDD voltage 3.1 ~ 3.2 */
#define SDCARD_VDD_32_33  0x00100000  /* VDD voltage 3.2 ~ 3.3 */
#define SDCARD_VDD_33_34  0x00200000  /* VDD voltage 3.3 ~ 3.4 */
#define SDCARD_VDD_34_35  0x00400000  /* VDD voltage 3.4 ~ 3.5 */
#define SDCARD_VDD_35_36  0x00800000  /* VDD voltage 3.5 ~ 3.6 */
#define SDCARD_CARD_BUSY  0x80000000  /* Card Power up status bit */

#define ROM_SDCARD_VDD    (SDCARD_VDD_33_34|SDCARD_VDD_32_33|SDCARD_VDD_31_32|SDCARD_VDD_30_31)
#define SDCARD_SCT_ACC    0x40000000  /* host support sector mode access */

/* static UINT8    addr_mode */
#define ADDR_MODE_BIT   1
#define ADDR_MODE_SEC   0

/* log display option */
#define SHOW_CID
#define SHOW_CSD
#define SHOW_EXT_CSD

int romcr_sdcard_init(void);
int romcr_sdcard_blk_ops(unsigned int bWrite, unsigned int tar_addr, unsigned int blk_cnt, unsigned char *dma_buffer);
unsigned int get_sdcard_blk_size(unsigned int img_size);
int load_data_from_sdcard(unsigned int addr, unsigned int blk_num, unsigned char* signature);

#ifndef __EMMC_H__
/************************************************************************
 *  Structure
 ************************************************************************/








struct mmc_command {
    u4Byte         opcode;
    u4Byte         arg;
    u4Byte         resp[4];
    u4Byte         flags;      /* expected response type */

#define MMC_RSP_PRESENT (1 << 0)
#define MMC_RSP_136     (1 << 1)        /* 136 bit response */
#define MMC_RSP_CRC     (1 << 2)        /* expect valid crc */
#define MMC_RSP_BUSY    (1 << 3)        /* card may send busy */
#define MMC_RSP_OPCODE  (1 << 4)        /* response contains opcode */

#define mmc_cmd_type(cmd)   ((cmd)->flags & MMC_CMD_MASK)
#define MMC_CMD_MASK    (3 << 5)        /* non-SPI command type */
#define MMC_CMD_AC      (0 << 5)
#define MMC_CMD_ADTC    (1 << 5)
#define MMC_CMD_BC      (2 << 5)
#define MMC_CMD_BCR     (3 << 5)

#define MMC_RSP_SPI_S1  (1 << 7)        /* one status byte */
#define MMC_RSP_SPI_S2  (1 << 8)        /* second byte */
#define MMC_RSP_SPI_B4  (1 << 9)        /* four data bytes */
#define MMC_RSP_SPI_BUSY (1 << 10)      /* card may send busy */

/*
 * These are the native response types, and correspond to valid bit
 * patterns of the above flags.  One additional valid pattern
 * is all zeros, which means we don't expect a response.
 */
#define MMC_RSP_NONE    (0)
#define MMC_RSP_R1      (MMC_RSP_PRESENT|MMC_RSP_CRC|MMC_RSP_OPCODE)
#define MMC_RSP_R1B     (MMC_RSP_PRESENT|MMC_RSP_CRC|MMC_RSP_OPCODE|MMC_RSP_BUSY)
#define MMC_RSP_R2      (MMC_RSP_PRESENT|MMC_RSP_136|MMC_RSP_CRC)
#define MMC_RSP_R3      (MMC_RSP_PRESENT)
#define MMC_RSP_R4      (MMC_RSP_PRESENT)
#define MMC_RSP_R5      (MMC_RSP_PRESENT|MMC_RSP_CRC|MMC_RSP_OPCODE)
#define MMC_RSP_R6      (MMC_RSP_PRESENT|MMC_RSP_CRC|MMC_RSP_OPCODE)
#define MMC_RSP_R7      (MMC_RSP_PRESENT|MMC_RSP_CRC|MMC_RSP_OPCODE)

#define mmc_resp_type(cmd)  ((cmd)->flags & (MMC_RSP_PRESENT|MMC_RSP_136|MMC_RSP_CRC|MMC_RSP_BUSY|MMC_RSP_OPCODE))

/*
 * These are the SPI response types for MMC, SD, and SDIO cards.
 * Commands return R1, with maybe more info.  Zero is an error type;
 * callers must always provide the appropriate MMC_RSP_SPI_Rx flags.
 */
#define MMC_RSP_SPI_R1  (MMC_RSP_SPI_S1)
#define MMC_RSP_SPI_R1B (MMC_RSP_SPI_S1|MMC_RSP_SPI_BUSY)
#define MMC_RSP_SPI_R2  (MMC_RSP_SPI_S1|MMC_RSP_SPI_S2)
#define MMC_RSP_SPI_R3  (MMC_RSP_SPI_S1|MMC_RSP_SPI_B4)
#define MMC_RSP_SPI_R4  (MMC_RSP_SPI_S1|MMC_RSP_SPI_B4)
#define MMC_RSP_SPI_R5  (MMC_RSP_SPI_S1|MMC_RSP_SPI_S2)
#define MMC_RSP_SPI_R7  (MMC_RSP_SPI_S1|MMC_RSP_SPI_B4)

#define mmc_spi_resp_type(cmd)  ((cmd)->flags & \
        (MMC_RSP_SPI_S1|MMC_RSP_SPI_BUSY|MMC_RSP_SPI_S2|MMC_RSP_SPI_B4))

/*
 * These are the command types.
 */


    unsigned int        retries;    /* max number of retries */
    unsigned int        error;      /* command error */

/*
 * Standard errno values are used for errors, but some have specific
 * meaning in the MMC layer:
 *
 * ETIMEDOUT    Card took too long to respond
 * EILSEQ       Basic format problem with the received or sent data
 *              (e.g. CRC check failed, incorrect opcode in response
 *              or bad end bit)
 * EINVAL       Request cannot be performed because of restrictions
 *              in hardware and/or the driver
 * ENOMEDIUM    Host can determine that the slot is empty and is
 *              actively failing requests
 */
/* liao ******************************************************************** */
#define MMC_ERR_NONE        0
#define MMC_ERR_TIMEOUT     1
#define MMC_ERR_BADCRC      2
#define MMC_ERR_RMOVE       3
#define MMC_ERR_FAILED      4
#define MMC_ERR_INVALID     5
/* liao &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& */
    //struct mmc_data     *data;      /* data segment associated with cmd */
    //struct mmc_request  *mrq;       /* associated request */
};


struct sd_cmd_pkt {
    struct mmc_command  *cmd;
    u1Byte       *dma_buffer;
    u2Byte      byte_count;
    u2Byte      block_count;
    u4Byte      flags;

#define MMC_DATA_DIR_MASK   (3 << 6)    /* bit 6~7 */
#define MMC_DATA_RAM        (1 << 7)
#define MMC_DATA_WRITE      (1 << 6)
#define MMC_DATA_READ       (0 << 6)
#define MMC_SRAM_WRITE      (MMC_DATA_RAM | MMC_DATA_WRITE)
#define MMC_SRAM_READ       (MMC_DATA_RAM | MMC_DATA_READ)
#define mmc_data_dir(pkt)  (pkt->flags & MMC_DATA_DIR_MASK)

    u1Byte       rsp_para1;
    u1Byte       rsp_para2;
    u1Byte       rsp_para3;
    u1Byte       rsp_len;
    u4Byte      timeout;
    u4Byte*     resp_buf;
    u1Byte       err_case;
};
#endif


#endif // #ifndef	__SDCARD_H__

