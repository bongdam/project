/************************************************************************
 *
 *  sdcard_reg.h
 *
 *  Defines for 8197f sd card registers
 *
 ************************************************************************/

#ifndef SDCARD_REG_H
#define SDCARD_REG_H


/* ==================================================================== */
////////////////////////////////////
/* MMC configure1, for SD_CONFIGURE1 */
#define SD1_R0                      (SDCLK_DIV | CLOCK_DIV_256 | RST_RDWR_FIFO)
/* MMC configure1, for SD_CONFIGURE2 */
#define SD_R0                   RESP_TYPE_NON|CRC7_CHK_DIS   //old=0x04, response none, no response
#define SD_R1                   RESP_TYPE_6B      //old=0x05
#define SD_R1b                  RESP_TYPE_6B|WAIT_BUSY_EN      //old=0x0D
#define SD_R2                   (0x44|RESP_TYPE_17B)     //old=0x06
#define SD_R3                   RESP_TYPE_6B|CRC7_CHK_DIS	//old=0x05
#define SD_R4                   RESP_TYPE_6B     //0x01
#define SD_R5                   RESP_TYPE_6B     //0x01
#define SD_R6                   RESP_TYPE_6B     //0x01
#define SD_R7                   RESP_TYPE_6B     //0x01
/* MMC configure3 , for SD_CONFIGURE3 */
#define SD2_R0                      (RESP_TIMEOUT_EN | ADDR_BYTE_MODE)

/* eMMC control register definition */
//#define CR_DMA_ADDR1                PHY_2_CACHE_ADDR(EMMC_DMA_RSP_ADDR) //0xBFE00000

#define EMMC_BASE_ADDR                      0xB8015000
#define CR_BASE_ADDR             	( EMMC_BASE_ADDR + 0x400 ) // 0x18012000
#define DUMMY_SYS                   0x1801042c
#define SD_BASE_ADDR                0x18010000
#define CR_SRAM_CTL                 (CR_BASE_ADDR)

#define CR_DMA_CTL1                 ( CR_BASE_ADDR + 0x004 )
#define CR_DMA_CTL2                 ( CR_BASE_ADDR + 0x008 )
#define CR_DMA_CTL3                 ( CR_BASE_ADDR + 0x00C )
#define CR_PAD_CTL                  ( CR_BASE_ADDR + 0x074 )
#define CR_CKGEN_CTL                ( CR_BASE_ADDR + 0x078 )
#define CR_CPU_ACC                  ( CR_BASE_ADDR + 0x080 )
#define CR_CARD_STOP                ( CR_BASE_ADDR + 0x103 )
#define CR_CARD_OE                  ( CR_BASE_ADDR + 0x104 )
#define CARD_SELECT                 ( CR_BASE_ADDR + 0x10e )
#define CARD_EXIST                  ( CR_BASE_ADDR + 0x11f )
#define CR_CLK_PAD_DRIVE            ( CR_BASE_ADDR + 0x130 )
#define CR_CMD_PAD_DRIVE            ( CR_BASE_ADDR + 0x131 )
#define CR_DAT_PAD_DRIVE            ( CR_BASE_ADDR + 0x132 )
#define SD_CONFIGURE1               ( CR_BASE_ADDR + 0x180 )
#define SD_CONFIGURE2               ( CR_BASE_ADDR + 0x181 )
#define SD_CONFIGURE3               ( CR_BASE_ADDR + 0x182 )
#define SD_STATUS1                  ( CR_BASE_ADDR + 0x183 )
#define SD_STATUS2                  ( CR_BASE_ADDR + 0x184 )
#define SD_BUS_STATUS               ( CR_BASE_ADDR + 0x185 )
#define SD_CMD_MODE                 ( CR_BASE_ADDR + 0x186 )
#define SD_SAMPLE_POINT_CTL         ( CR_BASE_ADDR + 0x187 )
#define SD_PUSH_POINT_CTL           ( CR_BASE_ADDR + 0x188 )
#define SD_CMD0                     ( CR_BASE_ADDR + 0x189 )
#define SD_CMD1                     ( CR_BASE_ADDR + 0x18A )
#define SD_CMD2                     ( CR_BASE_ADDR + 0x18B )
#define SD_CMD3                     ( CR_BASE_ADDR + 0x18C )
#define SD_CMD4                     ( CR_BASE_ADDR + 0x18D )
#define SD_CMD5                     ( CR_BASE_ADDR + 0x18E )
#define SD_BYTE_CNT_L               ( CR_BASE_ADDR + 0x18F )
#define SD_BYTE_CNT_H               ( CR_BASE_ADDR + 0x190 )
#define SD_BLOCK_CNT_L              ( CR_BASE_ADDR + 0x191 )
#define SD_BLOCK_CNT_H              ( CR_BASE_ADDR + 0x192 )
#define SD_TRANSFER                 ( CR_BASE_ADDR + 0x193 )
#define SD_DDR_DETECT_START         ( CR_BASE_ADDR + 0x194 )
#define SD_CMD_STATE                ( CR_BASE_ADDR + 0x195 )
#define SD_DATA_STATE               ( CR_BASE_ADDR + 0x196 )
#define SD_BUS_TA_STATE             ( CR_BASE_ADDR + 0x197 )
#define SD_STOP_SDCLK_CFG           ( CR_BASE_ADDR + 0x197 )
#define SD_AUTO_RST_FIFO            ( CR_BASE_ADDR + 0x197 )
#define SD_DAT_PAD                  ( CR_BASE_ADDR + 0x197 )
#define SD_DUMMY_4                  ( CR_BASE_ADDR + 0x197 )
#define SD_DUMMY_5                  ( CR_BASE_ADDR + 0x197 )
#define SD_DUTY_CTL                 ( CR_BASE_ADDR + 0x197 )
#define SD_SEQ_RW_CTL               ( CR_BASE_ADDR + 0x198 )
#define SD_CONFIGURE4               ( CR_BASE_ADDR + 0x19F )
#define SD_ADDR_L                   ( CR_BASE_ADDR + 0x1A0 )
#define SD_ADDR_H                   ( CR_BASE_ADDR + 0x1A1 )
#define SD_START_ADDR_0             ( CR_BASE_ADDR + 0x1A2 )
#define SD_START_ADDR_1             ( CR_BASE_ADDR + 0x1A3 )
#define SD_START_ADDR_2             ( CR_BASE_ADDR + 0x1A4 )
#define SD_START_ADDR_3             ( CR_BASE_ADDR + 0x1A5 )
#define SD_RSP_MASK_1               ( CR_BASE_ADDR + 0x1A6 )
#define SD_RSP_MASK_2               ( CR_BASE_ADDR + 0x1A7 )
#define SD_RSP_MASK_3               ( CR_BASE_ADDR + 0x1A8 )
#define SD_RSP_MASK_4               ( CR_BASE_ADDR + 0x1A9 )
#define SD_RSP_DATA_1               ( CR_BASE_ADDR + 0x1AA )
#define SD_RSP_DATA_2               ( CR_BASE_ADDR + 0x1AB )
#define SD_RSP_DATA_3               ( CR_BASE_ADDR + 0x1AC )
#define SD_RSP_DATA_4               ( CR_BASE_ADDR + 0x1AD )
#define SD_WRITE_DELAY              ( CR_BASE_ADDR + 0x1AE )
#define SD_READ_DELAY               ( CR_BASE_ADDR + 0x1AF )
#define CR_SRAM_BASE_0              ( CR_BASE_ADDR + 0x200 )
#define CR_SRAM_BASE_1              ( CR_BASE_ADDR + 0x300 )   
#define SD_CKGEN_CTL                ( CR_BASE_ADDR + 0x078 )
#define EMMC_PAD_CTL                ( CR_BASE_ADDR + 0x074 ) // ( SD_BASE_ADDR + 0x2074 )
#define EMMC_CKGEN_CTL              ( CR_BASE_ADDR + 0x078 ) // ( SD_BASE_ADDR + 0x2078 )

#define CR_CARD_RESP6_0         SD_CMD0                         
#define CR_CARD_RESP6_1         SD_CMD1                         
#define CR_CARD_RESP6_2         SD_CMD2                         
#define CR_CARD_RESP6_3         SD_CMD3                         
#define CR_CARD_RESP6_4         SD_CMD4                         

/* register item define */
/* CR_PAD_CTL                  ( CR_BASE_ADDR + 0x074 ) */
#define TUNE_33_18V             (0x00000001)     //1: 3.3v //0: 1.8v

/* SD_CONFIGURE1 0x18012180 */
#define SDCLK_DIV               (0x00000001<<7)
#define CLOCK_DIV_128           (0x00000000)
#define MASK_CLOCK_DIV          (0x00000003<<6)
#define CLOCK_DIV_NON           (0x00000000)
#define CLOCK_DIV_256           (0x00000001<<6)
#define RST_RDWR_FIFO           (0x00000001<<4)

#define MASK_BUS_WIDTH          (0x00000003)
#define BUS_WIDTH_1             (0x00000000)
#define BUS_WIDTH_4             (0x00000001)
#define BUS_WIDTH_8             (0x00000002)

/* SD_CONFIGURE2 0x18012181 */
#define CRC7_CAL_DIS            (0x00000001<<7)
#define CRC16_CAL_DIS           (0x00000001<<6)
#define WAIT_BUSY_EN            (0x00000001<<3)
#define CRC7_CHK_DIS            (0x00000001<<2)

#define MASK_RESP_TYPE          (0x00000003)
#define RESP_TYPE_NON           (0x00000000)
#define RESP_TYPE_6B            (0x00000001)
#define RESP_TYPE_17B           (0x00000002)

/* SD_CONFIGURE3 0x18012182 */
#define RESP_TIMEOUT_EN         (0x00000001)
#define ADDR_BYTE_MODE          (0x00000001<<1) //byte mode

/* SD_TRANSFER 0x18012193 */
#define START_EN                (0x00000001<<7)
#define END_STATE               (0x00000001<<6)
#define IDLE_STATE               (0x00000001<<5)
#define ERR_STATUS              (0x00000001<<4)

#define MASK_CMD_CODE           (0x0000000F)
#define SD_NORMALWRITE          (0x00000000)
#define SD_AUTOWRITE3           (0x00000001)
#define SD_AUTOWRITE4           (0x00000002)
#define SD_AUTOREAD3            (0x00000005)
#define SD_AUTOREAD4            (0x00000006)
#define SD_SENDCMDGETRSP        (0x00000008)
#define SD_AUTOWRITE1           (0x00000009)
#define SD_AUTOWRITE2           (0x0000000A)
#define SD_NORMALREAD           (0x0000000C)
#define SD_AUTOREAD1            (0x0000000D)
#define SD_AUTOREAD2            (0x0000000E)

/* SD_STATUS1 0x18012183 */
#define CRC7_STATUS             (0x00000001<<7)
#define CRC16_STATUS            (0x00000001<<6)
#define WRT_ERR_BIT             (0x00000001<<5)
#define CRC_TIMEOUT_ERR         (0x00000002)
#define DAT0_LEVEL              (0x00000001)

/* DMA_CTL3 0x1801200c */
#define DMA_XFER                    (0x00000001)
#define DDR_WR                      (0x00000002)
#define RSP17_SEL                   (0x00000001 << 4)
#define DAT64_SEL                   (0x00000001 << 5)

//CPU_ACC, 0x18012080 
#define CPU_MODE_EN                 (0x00000001)
#define BUF_SW_RENEW                (0x00000001<<1)
#define BUF_FULL                    (0x00000001<<2)


/* act_host_clk *** */
#define SYS_CLKSEL              0xB8000204        //0xB8000204
#define EMMC_CLKSEL_MASK         (0x07<<12)
#define CLOCK_SPEED_GAP          (0x03<<12)

#define CARD_SWITCHCLOCK_60MHZ  (0x00<<12)
#define CARD_SWITCHCLOCK_80MHZ  (0x01<<12)
#define CARD_SWITCHCLOCK_98MHZ  (0x02<<12)
#define CARD_SWITCHCLOCK_98MHZS (0x03<<12)
#define CARD_SWITCHCLOCK_30MHZ  (0x04<<12)
#define CARD_SWITCHCLOCK_40MHZ  (0x05<<12)
#define CARD_SWITCHCLOCK_49MHZ  (0x06<<12)
#define CARD_SWITCHCLOCK_49MHZS (0x07<<12)

/* misc definition */
#define RCA_SHIFTER                 16
#define NORMAL_READ_BUF_SIZE        512      //no matter FPGA & QA



#endif
