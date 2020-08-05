#ifndef __HAL8814B_FIRMWARE_H__
#define __HAL8814B_FIRMWARE_H__

/*++
Copyright (c) Realtek Semiconductor Corp. All rights reserved.

Module Name:
	Hal8814BFirmware.h
	
Abstract:
	Defined HAL 8814B Firmware data structure & Define
	    
Major Change History:
	When       Who               What
	---------- ---------------   -------------------------------
	2016-11-28 sky               Create.
--*/

#define OFFSET_VALUE(_v, _f)                \
      (((_v) & _f##_MSK) << _f##_SH)
#define SET_WORD(_w, _v, _f)                \
      (((_w) & ~((_f##_MSK) << (_f##_SH))) | (((_v) & (_f##_MSK)) << (_f##_SH)))
#define SET_CLR_WORD(_v, _f)                \
      (((_v) & (_f##_MSK)) << (_f##_SH))
#define GET_FIELD(_w, _f)         (((_w) >> (_f##_SH)) & (_f##_MSK))
#define GET_FIELD_F(_w, _m, _s)   (((_w) >> (_s)) & (_m))

/* FILE: fwhdr.h */
#define FWHDR_OFFSET_VALUE(_v, _f)      (((_v) & _f##_MSK) << _f##_SH)
#define FWHDR_GET_FIELD(_w, _f)         (((_w) >> (_f##_SH)) & (_f##_MSK))
#define FWHDR_SET_FIELD(_w, _v, _f)     ((_w) |= FWHDR_OFFSET_VALUE(_v, _f))

enum section_desc_type_e {
    _SECTION_TYPE_CONF = 0,
    _SECTION_TYPE_BOOTCODE,     /* for Uncompress compressed section purpose */
    _SECTION_TYPE_DMEM,
    _SECTION_TYPE_IMEM,
    _SECTION_TYPE_SRAM,
    _SECTION_TYPE_DRAM,
    _SECTION_TYPE_FW,
    _SECTION_TYPE_EFUSE,
    _SECTION_TYPE_PATCH,

    /* developement purpose */
    _SECTION_TYPE_IROM,
    _SECTION_TYPE_DROM,
    _SECTION_TYPE_ROM,
    _SECTION_TYPE_FLASH,

    _SECTION_TYPE_UNKNOWN = 0xf,
};

/* word0 */
#define FWHDR_SECTION_DL_ADDR_MSK       (0xffffffff)

#define FWHDR_SECTION_DL_ADDR_SH        (0)

/* word1 */
#define FWHDR_SECTION_LENGTH_MSK        (0xffffff)  /* support max. to 16MB */
#define FWHDR_SECTION_TYPE_MSK          (0xf)

#define FWHDR_SECTION_BIT_CSUM          (1 << 28)
#define FWHDR_SECTION_BIT_COMP          (1 << 29)

#define FWHDR_SECTION_LENGTH_SH         (0)
#define FWHDR_SECTION_TYPE_SH           (24)

struct section_desc_t {
    u32 word0;
    u32 word1;
} __WLAN_ATTRIB_PACK__;

enum fw_download_type_e {
    _FW_DOWNLOAD_IO = 0,
    _FW_DOWNLOAD_DMA,

    _FW_DOWNLOAD_UNKNOWN = 0x7,
};

enum fw_boot_type_e {
    _FW_BOOT_CPU_RST = 0,
    _FW_BOOT_SEL_SRAM,
    _FW_BOOT_SEL_IMEM,
    _FW_BOOT_SEL_ROM,
    _FW_BOOT_SEL_IROM,
    _FW_BOOT_SEL_FLASH,
    _FW_BOOT_SEL_DRAM,

    _FW_BOOT_UNKNOWN = 0xf,
};

/* word0 */
#define FWHDR_HDR_VERSION_MSK      (0xff)
#define FWHDR_DL_TYPE_MSK          (0x7)

#define FWHDR_HDR_VERSION_SH       (0)
#define FWHDR_DL_TYPE_SH           (8)

/* word1 */
#define FWHDR_FW_VERSION_MSK       (0x7fff)
#define FWHDR_FW_SUB_VERSION_MSK   (0xff)
#define FWHDR_FW_PATCH_VERSION_MSK (0xff)

#define FWHDR_BIT_DEBUG_REL        (1 << 15)

#define FWHDR_FW_VERSION_SH        (0)
#define FWHDR_FW_SUB_VERSION_SH    (16)
#define FWHDR_FW_PATCH_VERSION_SH  (24)

/* word2 */
#define FWHDR_FW_SVN_INDEX_MSK     (0xffffffff)

#define FWHDR_FW_SVN_INDEX_SH      (0)

/* word3 */
#define FWHDR_FW_MONTH_MSK         (0xff)
#define FWHDR_FW_DAY_MSK           (0xff)
#define FWHDR_FW_HOUR_MSK          (0xff)
#define FWHDR_FW_MIN_MSK           (0xff)

#define FWHDR_FW_MONTH_SH          (0)
#define FWHDR_FW_DAY_SH            (8)
#define FWHDR_FW_HOUR_SH           (16)
#define FWHDR_FW_MIN_SH            (24)

/* word4 */
#define FWHDR_FW_YEAR_MSK          (0xffff)

#define FWHDR_FW_YEAR_SH           (0)

/* word5 */
/* word6 */
#define FWHDR_SECTION_CNT_MSK      (0xff)

#define FWHDR_SECTION_CNT_SH       (0)

/* word7 */
#define FWHDR_CHECKSUM_MSK         (0xffffffff)

#define FWHDR_CHECKSUM_SH          (0)

/*
 * WORD0: target description
 * WORD1-WORD4: firwmare version control
 * WORD5: download and booting features
 * WORD6: section information
 * WORD7: check sum
 */
struct fwHdr_t {
    u32 word0;
    u32 word1;
    u32 word2;
    u32 word3;
    u32 word4;
    u32 word5;
    u32 word6;
    u32 word7;

    /* keep last */
    struct section_desc_t section[0];
} __WLAN_ATTRIB_PACK__;

#define _INIT_CHECKSUM          (0xFFFFFFFE)


/* FILE: fwdl.h */
#define FWDL_WAIT_CNT   (20000)      /* 1 CNT = 1 MS */ /* FPGA: more time if FPGA dump lots of message when booting */
#define FWDL_POLL_CNT	(100000)

/* should meet to the IDDMA's capability */
#define FWDL_FWD_FW_BLOCK_SIZE      (32 * 1024)

enum fwdl_state_e {
    FWDL_INVALID = 0,
    FWDL_INIT,          /* Extract the FW ball  */
    FWDL_START,         /* FW ball is valid and start download process */
    FWDL_CONF_READY,    /* CONF is ready and prepare to download BOOTCODE */
    FWDL_CPU_READY,     /* Data CPU is ready and prepare to download Data CPU FW */
    FWDL_MEM_READY,     /* DRAM is ready and prepare to download DRAM section */
    FWDL_SW_READY,      /* Data CPU FW is ready and prepare to bring up WiFi */
    FWDL_OFLD_READY,    /* everything is ready */
    FWDL_FW_START,      /* configuration negotiate done (optional) */
};

struct fwdl_dl_section_t {
    u8 *section_ptr;
    u32 dl_addr;
    int dl_len;
};

struct fwdl_ctx_t {
    //struct dev_core_ctx_t *dev_core_ctx;

    u8 *fw;              /* FW ball */
    int fw_len;

    enum fwdl_state_e state;

    /* version */
    u8 hdrVersion;
    u32 fwVersion; /* ver/sub_ver/pach_ver */
    u32 fwRevision;
    u16 fwYear;
    u8  fwMonth;
    u8  fwDay;
    u8  fwHour;
    u8  fwMinute;

    /* download mechanism */
    u8 dl_type;

    /* csum type */
    u8 xor_width;

    /* phase0 CONF */
    struct fwdl_dl_section_t conf;    

    /* phase1 FW prepare to download */
    struct fwdl_dl_section_t fw1;

    /* sections (phase2) prepare to download */
#define FWDL_SECTION_MAX_CNT        (4)
    struct fwdl_dl_section_t dl_section[FWDL_SECTION_MAX_CNT];
    int dl_cnt;

    /* DRAM section (phase3) prepare to download */
    struct fwdl_dl_section_t fw3;

    /* WiFi FW (phase4) prepare to download */
    struct fwdl_dl_section_t fw4;

    void (*report_cb)(HAL_PADAPTER Adapter,
                      enum fwdl_state_e state);

    u8 *working_buf;
};

/* FILE: fwconf_sec.h */
struct fwConfSection_t {
    /* WORD0 */
    u32    entry_addr;

    /* WORD1 */
    u32    mac_addr0_3;        /* FLASH-boot application */

    /* WORD2 */
    u16    mac_addr4_5;        /* FLASH-boot application */
    u8     rsvd_B0[2];

    /* WORD3 */
#define FWCONF_BSSID_NUM_MSK        (0x1f)
#define FWCONF_BSSID_NUM_SH         (0)
#define FWCONF_PORT_NUM_MSK         (0x7)
#define FWCONF_PORT_NUM_SH          (5)
    u8     bssid_port_num;       /* BSSID unit is 4
                                       * PORT exclude Port0 */

#define FWCONF_MACID_NUM_MSK        (0x3f)
#define FWCONF_MACID_NUM_SH         (0)
#define FWCONF_PHY_NUM_MSK          (0x3)
#define FWCONF_PHY_NUM_SH           (6)
    u8     phy_macid_num;        /* unit is 8 */
    u8     rsvd_B1[2];

    /* WORD4 */
    u8     tx_ofld_byte;       /* 8byte unit */
    u8     rx_ofld_byte;       /* 8byte unit */
    u8     rsvd_B2[2];

    /* WORD5 */
#define FWCONF_RXFLAG_RXMODE_MSK      (0x3)
#define FWCONF_RXFLAG_RXMODE_SH       (0)
#define FWCONF_RXFLAG_RXFWD_DESC      BIT(2)
#define FWCONF_RXFLAG_RXFWD_PKTHDR    BIT(3)
#define FWCONF_RXFLAG_RXFWD_MGT2EVT   BIT(4)
    u8     rx_flags;

#define FWCONF_TXFLAG_FLOWCTRL_MSK      (0x7)
#define FWCONF_TXFLAG_FLOWCTRL_SH       (0)
#define FWCONF_TXFLAG_FLOWCTRL_DIS      (0x0)
#define FWCONF_TXFLAG_FLOWCTRL_HW       (0x1)
#define FWCONF_TXFLAG_FLOWCTRL_SW       (0x2)
#define FWCONF_TXFLAG_FLOWCTRL_TP       (0x6)
#define FWCONF_TXFLAG_FLOWCTRL_USER     (0x7)
    u8     tx_flags;
    u8     rsvd_B3[2];

    /* WORD6 */
    u8     rsvd_B4[4];

    /* WORD7 */
#define FWCONF_SYS_UART_BAUDRATE_MSK        (0x3)
#define FWCONF_SYS_UART_BAUDRATE_SH         (0)
#define FWCONF_SYS_UART_BAUDRATE_38400      (0x0)
#define FWCONF_SYS_UART_BAUDRATE_57600      (0x1)
#define FWCONF_SYS_UART_BAUDRATE_115200     (0x2)
#define FWCONF_SYS_PRINT_MODE_MSK           (0x7)
#define FWCONF_SYS_PRINT_MODE_SH            (2)
#define FWCONF_SYS_PRINT_MODE_UART          (0x0)
#define FWCONF_SYS_PRINT_MODE_MEM           (0x1)
#define FWCONF_SYS_PRINT_MODE_EVT           (0x2)
#define FWCONF_SYS_PRINT_MODE_SILENT        (0x7)
    u32    sys;
} __WLAN_ATTRIB_PACK__;

/* FILE: fwconf.h */
enum fwconf_item_e {
    /* FWDL */
    FWCONF_ITEM_ENTRY_ADDRESS = 0,
    FWCONF_ITEM_DEBUG_BOOT,
    FWCONF_ITEM_BOOT_CLOCK_LVL,

    /* PE/WMAC */
    FWCONF_ITEM_MAC_ADDR0_4,
    FWCONF_ITEM_MAC_ADDR5_6,    
    FWCONF_ITEM_PHY_NUM,
    FWCONF_ITEM_MACID_NUM,
    FWCONF_ITEM_BSSID_NUM,
    FWCONF_ITEM_PORT_NUM,

    FWCONF_ITEM_TX_OFLD_BYTE,
    FWCONF_ITEM_TX_FLOWCTRL,

    FWCONF_ITEM_RX_OFLD_BYTE,
    FWCONF_ITEM_RX_MODE,
    FWCONF_ITEM_RX_FWD_DESC,
    FWCONF_ITEM_RX_FWD_PKTHDR,
    FWCONF_ITEM_RX_MGT2EVT,
    FWCONF_ITEM_RX_RAW,

    FWCONF_ITEM_WMAC_OFLD_OPT,
    FWCONF_ITEM_WMAC_MACID_MODE,

    /* HCIDMA */
    FWCONF_ITEM_OFLD_LLT_BNDY,

    /* SYS */
    FWCONF_ITEM_UART_BAUDRATE,
    FWCONF_ITEM_CPU_FWD_FW,
    FWCONF_ITEM_CLOCK_LVL,
    FWCONF_ITEM_PRINT_MODE,
    FWCONF_ITEM_NETDRV,

    /* DEBUG */
    FWCONF_ITEM_MCU_ROM_DL = 0xfc,
    FWCONF_ITEM_UNIT_TEST = 0xfd,
    FWCONF_ITEM_TX_LOOPBACK_MODE = 0xfe,
    FWCONF_ITEM_DBG_LVL = 0xff,
};

enum fwconf_action_e {
    FWCONF_ACTION_RESET,
    FWCONF_ACTION_STORE,
    FWCONF_ACTION_LOAD,
};

/* word0 (Cookies) */
#define FWCONF_COOKIES                  (0x0f8814f0)

/* word1 (Booting) */
#define FWCONF_DEBUG_BOOT_BIT           BIT(0)
#define FWCONF_BOOT_CLOCK_LVL_MSK       (0xf)
#define FWCONF_ENTRY_ADDR_MSK           (0xffffff)

#define FWCONF_BOOT_CLOCK_LVL_SH        (4)
#define FWCONF_ENTRY_ADDR_SH            (8)
#define FWCONF_ENTRY_ADDR_INVALID       (0xffffff)

/* word2 (MAC address) */
#define FWCONF_MAC_ADDR0_4_MSK          (0xffffffff)

#define FWCONF_MAC_ADDR0_4_SH           (0)

/* word3 (MAC address) */
#define FWCONF_MAC_ADDR5_6_MSK          (0xffff)

#define FWCONF_MAC_ADDR5_6_SH           (0)

/* word4 (Resource) */
#define FWCONF_RES_BSSID_NUM_MSK        (0x7f)
#define FWCONF_RES_PORT_NUM_MSK         (0x7)
#define FWCONF_RES_MACID_NUM_MSK        (0x1ff)
#define FWCONF_RES_PHY_NUM_MSK          (0x3)

#define FWCONF_RES_BSSID_NUM_SH         (0)
#define FWCONF_RES_PORT_NUM_SH          (7)
#define FWCONF_RES_MACID_NUM_SH         (10)
#define FWCONF_RES_PHY_NUM_SH           (19)

/* word5 (TxRX Mode) */
#define FWCONF_MODE_TX_OFLD_BYTE_MSK    (0xff)      /* 8byte unit */
#define FWCONF_MODE_RX_OFLD_BYTE_MSK    (0xff)      /* 8byte unit */
#define FWCONF_MODE_RX_MODE_MSK         (0x3)
#define FWCONF_MODE_TX_FLOWCTRL_MSK     (0x7)

#define FWCONF_MODE_TX_OFLD_BYTE_SH     (0)
#define FWCONF_MODE_RX_OFLD_BYTE_SH     (8)
#define FWCONF_MODE_RX_MODE_SH          (16)
#define FWCONF_MODE_TX_FLOWCTRL_SH      (18)

/* word6 (Tx Path) */
/* word7 (Rx Path) */
#define FWCONF_RX_FWD_DESC_BIT          BIT(0)
#define FWCONF_RX_FWD_PKTHDR_BIT        BIT(1)
#define FWCONF_RX_MGT2EVT_BIT           BIT(2)
#define FWCONF_RX_RAW_BIT               BIT(3)

/* word8 (Offload Function) */
#define FWCONF_WMAC_OFLD_OPT_MSK        (0xf)

#define FWCONF_WMAC_OFLD_OPT_SH         (0)

#define _DEV_CORE_FLAG_OFLD_TXDATA      BIT(0)      /* host used: offload AMSDU/TxHdrConv to offload driver */
#define _DEV_CORE_FLAG_OFLD_RXDATA_L2   BIT(1)      /* ofld used: offload DeAMSDU/RxHdrConv to offload driver */
#define _DEV_CORE_FLAG_OFLD_RXDATA      BIT(2)      /* ofld used: offload L3/L4 to offload driver */
#define _DEV_CORE_FLAG_OFLD_RXMGT       BIT(3)      /* ofld used: offload L2 to offload driver */

/* word9 (WMAC Function) */
#define FWCONF_WMAC_MACID_MODE_BIT      BIT(0)

/* word10 (Reserved) */
/* word11 (Hardware Setting) */
#define FWCONF_OFLD_LLT_BNDY_MSK        0xffff

#define FWCONF_OFLD_LLT_BNDY_SH         (0)

/* word12 (System) */
#define FWCONF_UART_BAUDRATE_MSK        (0x3)   /* 0:38400, 1:57600, 2:115200 */
#define FWCONF_CPU_FWD_FW_BIT           BIT(2)
#define FWCONF_CLOCK_LVL_MSK            (0xf)
#define FWCONF_PRINT_MODE_MSK           (0x7)
#define FWCONF_NETDRV_BIT               BIT(10)

#define FWCONF_UART_BAUDRATE_SH         (0)
#define FWCONF_CLOCK_LVL_SH             (3)
#define FWCONF_PRINT_MODE_SH            (7)

/* word 13 (Debug) */
#define FWCONF_UNIT_TEST_MSK            (0xff)
#define FWCONF_DBG_LVL_MSK              (0x7)
#define FWCONF_TX_LOOPBACK_MODE_MSK     (0x3)
#define FWCONF_DEF_MACID_MODE_MSK       (0x1)

#define FWCONF_UNIT_TEST_SH             (24)
#define FWCONF_DBG_LVL_SH               (0)
#define FWCONF_TX_LOOPBACK_MODE_SH      (3)
#define FWCONF_DEF_MACID_MODE_SH        (5)

struct fwconf_t {
    /* NOTE: first two are FIXED for boot-code and quickly access even no full
     *       fw_conf support to save boot-fw size
     */
    u32 cookies;
    u32 boot_conf;

    u32 macAddr0_4;
    u32 macAddr5_6;
    u32 resource_conf;
    u32 txrx_mode;
    u32 tx_flags;
    u32 rx_flags;
    u32 ofld_conf;
    u32 wmac_conf;
    u32 word10;
    u32 dma_conf;
    u32 sys_config;
    u32 sys_debug;
} __WLAN_ATTRIB_PACK__;

/* FILE: hil.h */
enum hil_dnld_action_e {
    HIL_DNLD_ACTION_ENABLE,
    HIL_DNLD_ACTION_DISABLE,
    HIL_DNLD_ACTION_GET,
    HIL_DNLD_ACTION_SET,        
};

enum hil_dnld_opmode_e {
    HIL_DNLD_OPMODE_POLL,
    HIL_DNLD_OPMODE_AUTO,
};

/* FILE: htxbd.h */
#define HTXBD_PAGE_SIZE_PWR         (7)               /* 128 */
#define HTXBD_PAGE_SIZE             (0x1 << HTXBD_PAGE_SIZE_PWR)
#define HTXBD_PAGE_NUM(_len)        (((_len) >> HTXBD_PAGE_SIZE_PWR) +   \
                                     (((_len) & (HTXBD_PAGE_SIZE - 1)) ? 1 : 0))

/* HTXBD - word0 */
#define HTXBD_BD_TXBUFFSIZE_MSK     (0xffff)
#define HTXBD_BD_PSB_MSK            (0xff)
#define HTXBD_BD_TXBUFFSIZE_SH      (0)
#define HTXBD_BD_PSB_SH             (16)

#define HTXBD_BD_BIT_A              BIT(31)
#define HTXBD_BD_BIT_OWN            BIT(31)

/* HTXBD - word1 */
#define HTXBD_BD_PHYADDR_LOW_MSK    (0xffffffff)
#define HTXBD_BD_PHYADDR_LOW_SH     (0)


/* FILE: txdesc.h */
/* word0 */
#define TXDESC_TXPKTSIZE_MSK    	(0xffff)
#define TXDESC_OFFSET_MSK       	(0xff)
#define TXDESC_PKT_OFFSET_MSK   	(0x1f)

#define TXDESC_TXPKTSIZE_SH     	(0)
#define TXDESC_OFFSET_SH        	(16)
#define TXDESC_PKT_OFFSET_SH    	(24)

#define TXDESC_IE_END_BIT       	BIT(31)

struct TXDESC_t {
    u32 word0;
    u32 word1;
    u32 word2;
    u32 word3;    
} __WLAN_ATTRIB_PACK__;

struct TXIE_t {
    u32 word0;
    u32 word1;
} __WLAN_ATTRIB_PACK__;

/* FILE: htxbd.h */
#define HTXBD_ALIGN         (8)
#define HTXBD_NUM_BD        (4)
#define HTXBD_NUM_2LVL_BD   (8)

/* HTXBD - word0 */
#define HTXBD_BD_TXBUFFSIZE_MSK     (0xffff)
#define HTXBD_BD_PSB_MSK            (0xff)
#define HTXBD_BD_TXBUFFSIZE_SH      (0)
#define HTXBD_BD_PSB_SH             (16)

#define HTXBD_BD_BIT_A              BIT(31)
#define HTXBD_BD_BIT_OWN            BIT(31)

/* HTXBD - word1 */
#define HTXBD_BD_PHYADDR_LOW_MSK    (0xffffffff)
#define HTXBD_BD_PHYADDR_LOW_SH     (0)

struct HTXBD_BD_t {
    u32 word0;
    u32 word1;
#if TXBD_SEG_32_64_SEL
    u32 word2;
    u32 word3;
#endif  //TXBD_SEG_32_64_SEL
} __WLAN_ATTRIB_PACK__;

struct DNLD_HTXBD_t {
    struct HTXBD_BD_t HTXBD_BD[HTXBD_NUM_BD];
} __WLAN_ATTRIB_PACK__;


/* FILE: host_hw.h */
#define HW_ADDRESS_INVALID      (0xFFFFFFFF)
#define HW_TARGET_BOOT_FROM_SRAM        (0)
#define HW_TARGET_BOOT_FROM_ROM         (1)

enum hw_type_e {
    HW_TYPE_FPGA,
    HW_TYPE_ASIC,
};

struct hw_rqpn_table_t {
    char name[8];

#define HW_RQPN_CH_NUM  (17)        /* 17 one-to-one queue */
    u32 ch_num;

    u32 page_total;
    u32 page_rsvd;
    u32 pub_ex_ch_mask;

    u32 page_num[HW_RQPN_CH_NUM];
};

/* FILE: hil.h */
struct hil_dnld_info_t {
    u32 atomic_cnt;  /* GET count */
    u32 flags;

    struct TXDESC_t txdesc;

#define MAX_DNLD_TXIE_NUMBER     (6)
    struct TXIE_t txie[MAX_DNLD_TXIE_NUMBER];

    /* keep last */
    u8 content[0];
};

/* FILE: host_register.h */
/* OLFD packet buffer */
#define ADDRESS_OF_TXFF             (0x18C00000)
#define SIZE_OF_OFLD_TXFF           (0x18000)        
#define SIZE_OF_OFLD_RXRING0        (0x1000)
#define SIZE_OF_OFLD_RXRING1        (0x8000)
#define POWER_OF_PAGE               (7)
#define SIZE_OF_PAGE                (1 << POWER_OF_PAGE)
#define NUMBER_OF_PAGE              (SIZE_OF_OFLD_TXFF >> POWER_OF_PAGE)

#define BIT_PCIE_P0BCNQ0_POLL               BIT(28)

#define REG_OFLD_DMA_RQPN_INFO_0        0x7900
#define REG_OFLD_DMA_RQPN_INFO_1        0x7904
#define REG_OFLD_DMA_RQPN_INFO_2        0x7908
#define REG_OFLD_DMA_RQPN_INFO_3        0x790C
#define REG_OFLD_DMA_RQPN_INFO_4        0x7910
#define REG_OFLD_DMA_RQPN_INFO_5        0x7914
#define REG_OFLD_DMA_RQPN_INFO_6        0x7918
#define REG_OFLD_DMA_RQPN_INFO_7        0x791C
#define REG_OFLD_DMA_RQPN_INFO_8        0x7920
#define REG_OFLD_DMA_RQPN_INFO_9        0x7924
#define REG_OFLD_DMA_RQPN_INFO_10       0x7928
#define REG_OFLD_DMA_RQPN_INFO_11       0x792C
#define REG_OFLD_DMA_RQPN_INFO_12       0x7930
#define REG_OFLD_DMA_RQPN_INFO_13       0x7934
#define REG_OFLD_DMA_RQPN_INFO_14       0x7938
#define REG_OFLD_DMA_RQPN_INFO_15       0x793C
#define REG_OFLD_DMA_RQPN_INFO_16       0x7940
#define REG_OFLD_DMA_RQPN_INFO_PUB      0x7818
#define REG_OFLD_RQPN_CTRL_2_V1         0x781C
#define BIT_OFLD_LD_RQPN_V1                 BIT(31)
#define BIT_OFLD_PUB_EX_CH_SH               (0)
#define BIT_OFLD_PUB_EX_CH_MSK              (0x1ffff)

#define BIT_IDDMA_LEN_MSK                   0x3FFFF

#define REG_AXI_IDDMA_SA                0x7D00
#define REG_AXI_IDDMA_DA                0x7D04
#define REG_AXI_IDDMA_CTRL              0x7D08
#define BIT_IDDMA_CSUM_CON_BIT              BIT(24)
#define BIT_IDDMA_CSUM_STS_BIT              BIT(27)
#define BIT_IDDMA_CSUM_BIT                  BIT(29)
#define BIT_IDDMA_OWN_BIT                   BIT(31)
#define REG_AXI_IDDMA_MSK_INT           0x7DE0
#define REG_AXI_IDDMA_CLR_CSUM          0x7DEC
#define REG_AXI_IDDMA_CSUM_VAL          0x7DF0

#define REG_DATA_FW_DBG00       (0x7E00)    /* FWCONF */
#define REG_DATA_FW_DBG01       (0x7E04)    /* FWCONF */
#define REG_DATA_FW_DBG02       (0x7E08)    /* FWCONF */
#define REG_DATA_FW_DBG03       (0x7E0C)    /* FWCONF */
#define REG_DATA_FW_DBG04       (0x7E10)    /* FWCONF */
#define REG_DATA_FW_DBG05       (0x7E14)    /* FWCONF */
#define REG_DATA_FW_DBG06       (0x7E18)    /* FWCONF */
#define REG_DATA_FW_DBG07       (0x7E1C)    /* FWCONF */
#define REG_DATA_FW_DBG08       (0x7E20)    /* FWCONF */
#define REG_DATA_FW_DBG09       (0x7E24)    /* FWCONF */
#define REG_DATA_FW_DBG10       (0x7E28)    /* FWCONF */
#define REG_DATA_FW_DBG11       (0x7E2C)    /* FWCONF */
#define REG_DATA_FW_DBG12       (0x7E30)    /* FWCONF */
#define REG_DATA_FW_DBG13       (0x7E34)    /* FWCONF */
#define REG_DATA_FW_DBG14       (0x7E38)
#define REG_DATA_FW_DBG15       (0x7E3C)    /* FWDL */

#define REG_FWDL_H_STATE            (REG_DATA_FW_DBG15 + 0x0)  /* Host CPU state */
#define REG_FWDL_H_INIT             (0)
#define REG_FWDL_H_CONF_DONE        (1)     /* Announce CONF successfully */
#define REG_FWDL_H_DL0_DONE         (2)     /* Phase2 download successfully */
#define REG_FWDL_H_DL1_DONE         (3)     /* Phase3 download successfully */
#define REG_FWDL_H_FWD_FW_DONE      (4)     /* Phase4 forward successfully */

#define REG_FWDL_D_STATE            (REG_DATA_FW_DBG15 + 0x1)  /* Data CPU state */
#define REG_FWDL_D_INIT             (0)
#define REG_FWDL_D_BOOT_INIT_DONE   (1)     /* Phase1 done */
#define REG_FWDL_D_MEM_INIT_DONE    (2)     /* Phase2 done */
#define REG_FWDL_D_SW_INIT_DONE     (3)     /* Phase3 done */
#define REG_FWDL_D_OFLD_INIT_DONE   (4)     /* Phase4 done */

#define REG_FWDL_H_FWD_FW_INFO      (REG_DATA_FW_DBG15 + 0x2)
#define REG_FWDL_D_FWD_FW_INFO      (REG_DATA_FW_DBG15 + 0x3)
#define REG_FWDL_NULL_FWD_FW_INFO   (0)
#define BIT_FWDL_INFO_BID_MSK       0x7f
#define BIT_FWDL_H_INFO_CONT        BIT(7)

#define REG_INDIRECT_WRITE_VAL  (0x7E70)
#define REG_INDIRECT_WRITE_ADDR (0x7E74)
#define REG_INDIRECT_READ_VAL   (0x7E78)
#define REG_INDIRECT_READ_ADDR  (0x7E7C)

/* FIXME: 0x0100, not defined in halmac_reg2h */
#define BIT_EN_HCI_TO_OFLD_TXDMA         BIT(0)
#define BIT_EN_HCI_TO_OFLD_RXDMA         BIT(1)
#define BIT_EN_OFLD_TXDMA                BIT(2)
#define BIT_EN_OFLD_RXDMA                BIT(3)
#define BIT_EN_SWBCN                     BIT(8)

/* FIXME: 0x1090, not defined in halmac_reg2h */
#define BIT_BOOT_SEL_MSK                 0x3
#define BIT_BOOT_SEL_SH                  6
#define BIT_BOOT_SEL_SRAM                (0x0)
#define BIT_BOOT_SEL_FLASH               (0x1)
#define BIT_BOOT_SEL_ROM                 (0x2)

/* 0x7800~ */
#define REG_OFLD_BCN_CTRL_0             0x7800      /* BCN page offset */
#define BIT_BCN0_VALID                      BIT(15) /* W1C: DMA to TXFF done */

#define REG_OFLD_AUTO_LLT_V1            0x7808
#define BIT_EN_SW_BCN_SEL                   BIT(2)

/* debug API */
#define PRN_ALWAYS      (0)
#define PRN_OFF         (1)
#define PRN_INFO        (2)
#define PRN_DEBUG       (3)
#define PRN_LOUDLY      (4)
#define PRN_ALL         (5)

#define ANSI_COLOR_RED     "\x1b[31m"
#define ANSI_COLOR_GREEN   "\x1b[32m"
#define ANSI_COLOR_YELLOW  "\x1b[33m"
#define ANSI_COLOR_BLUE    "\x1b[34m"
#define ANSI_COLOR_MAGENTA "\x1b[35m"
#define ANSI_COLOR_CYAN    "\x1b[36m"
#define ANSI_COLOR_RESET   "\x1b[0m"

#define _FUNC_IN(_lvl, fmt, ...)						\
	if (GLOBAL_dbg_print >= _lvl) {						\
		printk("%s-->%s[%s]" fmt "\n",					\
				ANSI_COLOR_MAGENTA, ANSI_COLOR_RESET,	\
				__func__,								\
				##__VA_ARGS__);							\
	}

#define _FUNC_OUT(_lvl, fmt, ...)						\
	if (GLOBAL_dbg_print >= _lvl) {						\
		printk("%s<--%s[%s]" fmt "\n",					\
				ANSI_COLOR_YELLOW, ANSI_COLOR_RESET,	\
				__func__,								\
				##__VA_ARGS__); 						\
	}

#define _PRINT(_lvl, fmt, ...)							\
	if (GLOBAL_dbg_print >= _lvl) {						\
		printk("[%s]" fmt "\n", __func__, ##__VA_ARGS__);\
	}

#define _DBG_PRINT(fmt, ...)							\
	if (GLOBAL_dbg_print >= PRN_OFF) {					\
		printk("[%s] " fmt "\n", __func__, ##__VA_ARGS__);	\
	}

#define _ASSERT(_val)									\
		if ((_val)) {									\
				printk("ASSERT! %s:%d [%d]\n",			\
				__func__, __LINE__, (u32)(_val));		\
				BUG();									\
		}

/* function prototype */
int host_hw_ring_dma_init(HAL_PADAPTER Adapter);

BOOLEAN
FirmwareDownload8814B(
    IN  HAL_PADAPTER    Adapter
);

int host_fwdl_phase5(HAL_PADAPTER Adapter, int start);

int _sys_fwlog(HAL_PADAPTER Adapter, struct cil_pkt_t *cil);
int _sys_ready(HAL_PADAPTER Adapter, struct cil_pkt_t *cil);


#define DEF_FWLOG_FILENAME          "/tmp/dcpu.log"

#define FWLOG_SOCKET_GROUP_ID       (0x1)
#define FWLOG_SOCKET_TYPE_FWLOG     (0x99)

struct fwlog_socket_hdr {
#define FWLOG_SOCKET_MLEN_MSK       (0xffff)
#define FWLOG_SOCKET_MSN_MSK        (0xff)

#define FWLOG_SOCKET_MLEN_SH        (0)
#define FWLOG_SOCKET_MSN_SH         (16)
    u32 info;
    u8 msg[0];
} __WLAN_ATTRIB_PACK__;

enum dev_core_state_e {
    DEV_CORE_STATE_INVALID = 0,
    DEV_CORE_STATE_CREATE,
    DEV_CORE_STATE_FWDL_DONE,
    DEV_CORE_STATE_FW_START,
    DEV_CORE_STATE_OPEN,
    DEV_CORE_STATE_FW_STOP,
    DEV_CORE_STATE_DESTORY = 0xff,
};

VOID
D2HPacket88XX
(
	IN  HAL_PADAPTER    Adapter,
	IN  pu1Byte         pBuf,
	IN	int             length
);

void fwlog_file_open(void);
void fwlog_file_close(void);
void fwlog_sock_open(void);
void fwlog_sock_close(void);

/* debug data cpu debug */
#define INDIRECT_READ(m_off, val)               \
    do {                                        \
        RTL_W32(0x7e7c, (m_off & 0x7fffffff));  \
        val = RTL_R32(0x7e78);                  \
    } while (0)


#define DCNT_CHECK_COOKIE       0x70862266
#define DC_SRAM_START           0x1fe00000
#define DC_HCIDMA_START         0x18be0000
#define DC_AXIDMA_START         0x18bc0000

enum dcnt_cat_e {
    DCNT_CAT_CPU = 0,               /* cpu related counters */
    DCNT_CAT_SYS,                   /* system related counters */
    DCNT_CAT_PE,                    /* PE related counters */
    DCNT_CAT_WMAC,                  /* wMAC related counters */
    DCNT_CAT_HV,                    /* HW-Verify related counters */
    DCNT_CAT_TEST,                  /* TEST code counters */
    DCNT_CAT_COOKIE,

    /* keep last */
    DCNT_CAT_NUM,
};

struct dcnt_cpu_t {
#define DCNT_CPU_S_INIT             (0)
#define DCNT_CPU_S_RUN              (1)
#define DCNT_CPU_S_SLEEP            (2)
#define DCNT_CPU_S_EXCEPTION        (3)
#define DCNT_CPU_S_BUS_AHD          (4)
#define DCNT_CPU_S_WDT              (5)
    u32 __cpu_state;

    u32 __cpu_loading;

    u32 __cpu_sleep;
    u32 __cpu_awake_hcidma;
    u32 __cpu_awake_axidma;

    u32 __cpu_exception_cause;
    u32 __cpu_exception_status;
    u32 __cpu_exception_badaddr;
    u32 __cpu_exception_sp;
    u32 __cpu_exception_sp_t;
    u32 __cpu_exception_sp_b;
    u32 __cpu_exception_sp_s;
    u32 __cpu_exception_pc;    
    u32 __cpu_exception_ra;

    u32 __cpu_wp_addr;
    u32 __cpu_wp_ctrl;
    u32 __cpu_wp_mask;

    u32 __bus_ahd_tag;
    u32 __bus_ahd_code;
    u32 __bus_ahd_addr0;
    u32 __bus_ahd_addr1;
    u32 __bus_ahd_pld0;
    u32 __bus_ahd_pld1;
};

struct dcnt_sys_t {
    u32 __bsp_version;
    u32 __boot_step;

    u32 __brd_info;

    u32 __prn_lvl;
    u32 __prn_ctx;

    u32 __isr_cnt[16];           /* per IRQ */
    u32 __isr_run[16];           /* per IRQ */
    u32 __isr_poll[16];          /* per IRQ */

    u32 __os_loop_freeze;
    u32 __os_ldie_run;
    u32 __os_idle_bypass;
    u32 __os_timer_c;
    u32 __os_timer_a;

    u32 __mem_alloc;
    u32 __mem_cp;
    u32 __mem_mv;

    u32 __fwlog;
    u32 __fwlog_curr_head;

    u32 __fwdl_phase6;
};

struct dcnt_pe_t {
    u32 __dev_core_hcidma;
    u32 __dev_core_axidma;
    u32 __hil_hcidma;
    u32 __hil_axidma;

    u32 __hcidma_chan_tx_still[2];
    u32 __hcidma_chan_tx[2];
    u32 __hcidma_chan_txdone[2];
    u32 __hcidma_chan_rx_dispatch;
    u32 __hcidma_chan_rx_still;
    u32 __hcidma_chan_rx;
    u32 __hcidma_chan_rxdone;
    u32 __hcidma_chan_rx_desc_ua;

    u32 __axidma_chan_tx_still[38];
    u32 __axidma_chan_tx[38];
    u32 __axidma_chan_txdone[38];
    u32 __axidma_chan_rx_dispatch[2];
    u32 __axidma_chan_rx_still[2];
    u32 __axidma_chan_rx[2];
    u32 __axidma_chan_rxdone[2];
    u32 __axidma_chan_rx_desc_ua[2];

    u32 __sil_pkt_res_cnt[8];
    u32 __sil_pkt_num[8];
    u32 __sil_pkt_alloc[8];
    u32 __sil_pkt_allocFail[8];
    u32 __sil_pkt_free[8];
    u32 __sil_pkt_freeReuse[8];
    u32 __sil_pkt_freeChain[8];

    u32 __skbuf_alloc_cnt[5];
    u32 __skbuf_free_cnt[5];
    u32 __skbuf_allocFail_cnt[5];
    u32 __err_d2c_ctrl_skbuf;
    u32 __err_d2h_ctrl_skbuf;
	u32 __err_drop_high;	
    u32 __cnt_hiq;
};

#endif
