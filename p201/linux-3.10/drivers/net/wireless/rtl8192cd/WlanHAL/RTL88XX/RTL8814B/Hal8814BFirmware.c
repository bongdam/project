/*++
Copyright (c) Realtek Semiconductor Corp. All rights reserved.

Module Name:
	Hal8814BFirmware.c
	
Abstract:
	Defined RTL8814B HAL Function
	    
Major Change History:
	When       Who               What
	---------- ---------------   -------------------------------
	2016-11-28 sky               Create.	
--*/
#include "HalPrecomp.h"
#if defined(__ECOS)
#include "Hal8814BFirmware.h"
#endif
u32 GLOBAL_dbg_print = PRN_ALWAYS;
struct fwdl_ctx_t GLOBAL_fwdl_ctx;

#define FW4_DL_ADDR 0x18c08000

static inline void __inWrite32(HAL_PADAPTER Adapter,
                               u32 addr,
                               u32 val)
{
    /* MUST in-order */
    HAL_RTL_W32(REG_INDIRECT_WRITE_VAL, val);
    HAL_RTL_W32(REG_INDIRECT_WRITE_ADDR, addr);

    return;
}

static inline void __inRead32(HAL_PADAPTER Adapter,
                              u32 addr,
                              u32 *val)
{
    /* MUST in-order */
    HAL_RTL_W32(REG_INDIRECT_READ_ADDR, addr);
    *val = HAL_RTL_R32(REG_INDIRECT_READ_VAL);

    return;
}

static inline int _host_hw_ring_dma_weight(HAL_PADAPTER Adapter,
                                           u32 weightTable[])
{
    HAL_RTL_W8(REG_AC_CHANNEL0_WEIGHT, 0x1);
    HAL_RTL_W8(REG_AC_CHANNEL1_WEIGHT, 0x1);
    HAL_RTL_W8(REG_AC_CHANNEL2_WEIGHT, 0x1);
    HAL_RTL_W8(REG_AC_CHANNEL3_WEIGHT, 0x1);
    HAL_RTL_W8(REG_AC_CHANNEL4_WEIGHT, 0x1);
    HAL_RTL_W8(REG_AC_CHANNEL5_WEIGHT, 0x1);
    HAL_RTL_W8(REG_AC_CHANNEL6_WEIGHT, 0x1);
    HAL_RTL_W8(REG_AC_CHANNEL7_WEIGHT, 0x1);
    HAL_RTL_W8(REG_AC_CHANNEL8_WEIGHT, 0x1);
    HAL_RTL_W8(REG_AC_CHANNEL9_WEIGHT, 0x1);
    HAL_RTL_W8(REG_AC_CHANNEL10_WEIGHT, 0x1);
    HAL_RTL_W8(REG_AC_CHANNEL11_WEIGHT, 0x1);
    HAL_RTL_W8(REG_AC_CHANNEL12_WEIGHT, 0x1);
    HAL_RTL_W8(REG_AC_CHANNEL13_WEIGHT, 0x1);

    return 0;
}

static struct hw_rqpn_table_t ofld_rqpn_table_default = {
    .name = "RQPNp",

    .ch_num = HW_RQPN_CH_NUM,
    .pub_ex_ch_mask = 0x0,
    .page_total = NUMBER_OF_PAGE,
    .page_rsvd = 0x20,

    .page_num[0] = 0x10,    /* CH0 */
    .page_num[1] = 0x10,    /* CH1 */
    .page_num[2] = 0x10,    /* CH2 */
    .page_num[3] = 0x10,    /* CH3 */
    .page_num[4] = 0x0,     /* CH4 */
    .page_num[5] = 0x0,      /* CH5 */
    .page_num[6] = 0x0,     /* CH6 */
    .page_num[7] = 0x0,     /* CH7 */
    .page_num[8] = 0x0,     /* CH8 */
    .page_num[9] = 0x0,     /* CH9 */
    .page_num[10] = 0x0,    /* CH10 */
    .page_num[11] = 0x0,    /* CH11 */
    .page_num[12] = 0x0,    /* CH12/S0 */
    .page_num[13] = 0x0,    /* CH13/S1 */
    .page_num[14] = 0x10,   /* MGT */
    .page_num[15] = 0x10,   /* BMC */
    .page_num[16] = 0x10,   /* FWCMD */
};

static inline int _hw_ring_dma_rqpn_calc(struct hw_rqpn_table_t *rqpnTable,
                                         int *pubPage,
                                         int *rqpnPage)
{
    int i, usedPage = 0;

    for (i = 0; i < rqpnTable->ch_num; i++)
        usedPage += rqpnTable->page_num[i];

    *pubPage = rqpnTable->page_total - usedPage - rqpnTable->page_rsvd;
    *rqpnPage = usedPage + *pubPage;

    _ASSERT(usedPage == 0);
    _ASSERT(*pubPage <= 0);
    _ASSERT(*rqpnPage >= rqpnTable->page_total);

    _FUNC_OUT(PRN_DEBUG, "name %s tatal %d used %d pub %d rsvd %d",
        rqpnTable->name,
        rqpnTable->page_total,
        usedPage,
        *pubPage,
        rqpnTable->page_rsvd);

    return 0;
}

int host_hw_ring_dma_rqpn_table(struct hw_rqpn_table_t *rqpnTable)
{
    int pubPage, rqpnPage;

    _FUNC_IN(PRN_INFO, "init rqpn");

    /* pick-up a table first at driver initial */

    if (rqpnTable == NULL)
        rqpnTable = &ofld_rqpn_table_default;

    _hw_ring_dma_rqpn_calc(rqpnTable, &pubPage, &rqpnPage);

    _FUNC_OUT(PRN_INFO, "use %s table, use %d pages",
                                            rqpnTable->name,
                                            rqpnPage);

    return rqpnPage;
}

static inline int _host_hw_ring_dma_rqpn(HAL_PADAPTER Adapter)
{
    struct hw_rqpn_table_t *rqpnTable = &ofld_rqpn_table_default;
    int count, rqpnPage, pubPage, gap_page = 2;
    u8 val8;
    u32 val32;

    _ASSERT(!rqpnTable);

    _hw_ring_dma_rqpn_calc(rqpnTable, &pubPage, &rqpnPage);

    HAL_RTL_W16(REG_OFLD_DMA_RQPN_INFO_0, rqpnTable->page_num[0]);
    HAL_RTL_W16(REG_OFLD_DMA_RQPN_INFO_1, rqpnTable->page_num[1]);
    HAL_RTL_W16(REG_OFLD_DMA_RQPN_INFO_2, rqpnTable->page_num[2]);
    HAL_RTL_W16(REG_OFLD_DMA_RQPN_INFO_3, rqpnTable->page_num[3]);
    HAL_RTL_W16(REG_OFLD_DMA_RQPN_INFO_4, rqpnTable->page_num[4]);
    HAL_RTL_W16(REG_OFLD_DMA_RQPN_INFO_5, rqpnTable->page_num[5]);
    HAL_RTL_W16(REG_OFLD_DMA_RQPN_INFO_6, rqpnTable->page_num[6]);
    HAL_RTL_W16(REG_OFLD_DMA_RQPN_INFO_7, rqpnTable->page_num[7]);
    HAL_RTL_W16(REG_OFLD_DMA_RQPN_INFO_8, rqpnTable->page_num[8]);
    HAL_RTL_W16(REG_OFLD_DMA_RQPN_INFO_9, rqpnTable->page_num[9]);
    HAL_RTL_W16(REG_OFLD_DMA_RQPN_INFO_10, rqpnTable->page_num[10]);
    HAL_RTL_W16(REG_OFLD_DMA_RQPN_INFO_11, rqpnTable->page_num[11]);
    HAL_RTL_W16(REG_OFLD_DMA_RQPN_INFO_12, rqpnTable->page_num[12]);
    HAL_RTL_W16(REG_OFLD_DMA_RQPN_INFO_13, rqpnTable->page_num[13]);
    HAL_RTL_W16(REG_OFLD_DMA_RQPN_INFO_14, rqpnTable->page_num[14]);
    HAL_RTL_W16(REG_OFLD_DMA_RQPN_INFO_15, rqpnTable->page_num[15]);
    HAL_RTL_W16(REG_OFLD_DMA_RQPN_INFO_16, rqpnTable->page_num[16]);
    HAL_RTL_W16(REG_OFLD_DMA_RQPN_INFO_PUB, pubPage);

    val32 = (BIT_OFLD_LD_RQPN_V1 |
             OFFSET_VALUE(rqpnTable->pub_ex_ch_mask, BIT_OFLD_PUB_EX_CH));
    HAL_RTL_W32(REG_OFLD_RQPN_CTRL_2_V1, val32);
    HAL_RTL_W16(REG_OFLD_BCN_CTRL_0, (rqpnPage + gap_page));

    count = 10000;
    val8 = HAL_RTL_R8(REG_OFLD_AUTO_LLT_V1);
    val8 |= BIT(0);
    HAL_RTL_W8(REG_OFLD_AUTO_LLT_V1, val8);
    while (val8 & BIT(0)) {
        val8 = HAL_RTL_R8(REG_OFLD_AUTO_LLT_V1);
        if (--count == 0) {
            _ASSERT(1);
        }
    }

    return 0;
}

int host_hw_ring_dma_init(HAL_PADAPTER Adapter)
{
    int ret;

    _FUNC_IN(PRN_DEBUG, "init ring DMA");

    _host_hw_ring_dma_weight(Adapter, NULL);
    ret = _host_hw_ring_dma_rqpn(Adapter);

    return ret;
}

static struct fwConfSection_t _fwconf_section_default = {
    .entry_addr     = 0xffffffff/*cpu_to_le32(FWCONF_BOOT_ENTRY_ADDR_INVALID)*/,

#if defined(__ECOS)
	.mac_addr0_3	= rtk_be32_to_cpu(0x00e04cBB),
	.mac_addr4_5	= rtk_be16_to_cpu(0x8814),
#else
    .mac_addr0_3    = be32_to_cpu(0x00e04cBB),
    .mac_addr4_5    = be16_to_cpu(0x8814),
#endif
    .bssid_port_num = (OFFSET_VALUE(MULTI_BSSID_NUM + CLIENT_BSSID_NUM, FWCONF_BSSID_NUM) |
                       OFFSET_VALUE(MULTI_PORT_NUM, FWCONF_PORT_NUM)),
    .phy_macid_num  = (OFFSET_VALUE((CONFIG_MACID_NUM >> 3), FWCONF_MACID_NUM) |
                       OFFSET_VALUE(1, FWCONF_PHY_NUM)),

    .tx_ofld_byte   = (128/*HIL_DEF_TX_OFFLOAD_SIZE*/ >> 3),
    .rx_ofld_byte   = (128/*HIL_DEF_RX_OFFLOAD_SIZE*/ >> 3),

    .rx_flags       = (1 | FWCONF_RXFLAG_RXFWD_DESC), /* RX Store-Fwd1 mode */

    .sys            = (OFFSET_VALUE(FWCONF_SYS_UART_BAUDRATE_115200,
                                    FWCONF_SYS_UART_BAUDRATE) |
                       OFFSET_VALUE(FWCONF_SYS_PRINT_MODE_UART,
                                    FWCONF_SYS_PRINT_MODE)),
};

static struct fwconf_t fwconfDefault;

static int _fwconf_store(struct fwconf_t *fwconf, HAL_PADAPTER Adapter)
{
    u32 *ptr, reg, words;
    int ret = 0;

    _ASSERT(!fwconf);

    words = (sizeof(struct fwconf_t) / sizeof(u32));
    ptr = (u32 *)fwconf;
    reg = REG_DATA_FW_DBG00;

    _FUNC_IN(PRN_DEBUG, "words %d reg 0x%x", words, reg);

    do {
        HAL_RTL_W32(reg, *ptr++);

        words--;
        reg += sizeof(u32);
    } while(words);

    return ret;
}

static int _fwconf_load(struct fwconf_t *fwconf, HAL_PADAPTER Adapter)
{
    u32 *ptr, val, reg, words;
    int waiting_cnt, ret = 0;

    _ASSERT(!fwconf);

    waiting_cnt = 1000;
    words = (sizeof(struct fwconf_t) / sizeof(u32));
    ptr = (u32 *)fwconf;
    reg = REG_DATA_FW_DBG00;

    _FUNC_IN(PRN_DEBUG, "words %d reg 0x%x", words, reg);

    do {
        val = HAL_RTL_R32(reg);
        waiting_cnt--;
    } while(val != FWCONF_COOKIES);

    do {
        val = HAL_RTL_R32(reg);

        *ptr++ = val;
        words--;;
        reg += sizeof(u32);
    } while(words);

    _FUNC_OUT(PRN_DEBUG, "waiting_cnt %d", waiting_cnt);

    return ret;
}

int fwconf_action(struct fwconf_t *fwconf,
                  enum fwconf_action_e action,
                  HAL_PADAPTER Adapter)
{
    int ret = 0;

    if (fwconf == NULL)
        fwconf = &fwconfDefault;

    _FUNC_IN(PRN_DEBUG, "action %d", action);

    switch (action) {
        case FWCONF_ACTION_RESET:
            memset(fwconf, 0x0, sizeof(*fwconf));
            fwconf->cookies = FWCONF_COOKIES;
            break;

        case FWCONF_ACTION_STORE:
            ret = _fwconf_store(fwconf, Adapter);
            break;

        case FWCONF_ACTION_LOAD:
            ret = _fwconf_load(fwconf, Adapter);
            break;

        default:
            _ASSERT(1);
    };

    _FUNC_OUT(PRN_DEBUG, "ret %d", ret);

    return ret;
}

int fwconf_set(struct fwconf_t *fwconf,
               enum fwconf_item_e fwconf_item,
               u32 val)
{
    int ret = 0;

    if (fwconf == NULL)
        fwconf = &fwconfDefault;

    _ASSERT(fwconf->cookies != FWCONF_COOKIES);

    _FUNC_IN(PRN_DEBUG, "item %d val 0x%x", fwconf_item, val);

    if (fwconf_item == FWCONF_ITEM_ENTRY_ADDRESS)
        fwconf->boot_conf |= OFFSET_VALUE(val, FWCONF_ENTRY_ADDR);
    else if (fwconf_item == FWCONF_ITEM_DEBUG_BOOT)
        fwconf->boot_conf |= (val ? FWCONF_DEBUG_BOOT_BIT : 0);
    else if (fwconf_item == FWCONF_ITEM_BOOT_CLOCK_LVL)
        fwconf->boot_conf |= OFFSET_VALUE(val, FWCONF_BOOT_CLOCK_LVL);
    else if (fwconf_item == FWCONF_ITEM_MAC_ADDR0_4)
        fwconf->macAddr0_4 = OFFSET_VALUE(val, FWCONF_MAC_ADDR0_4);
    else if (fwconf_item == FWCONF_ITEM_MAC_ADDR5_6)
        fwconf->macAddr5_6 = OFFSET_VALUE(val, FWCONF_MAC_ADDR5_6);
    else if (fwconf_item == FWCONF_ITEM_BSSID_NUM)
        fwconf->resource_conf |= OFFSET_VALUE(val, FWCONF_RES_BSSID_NUM);
    else if (fwconf_item == FWCONF_ITEM_PORT_NUM)
        fwconf->resource_conf |= OFFSET_VALUE(val, FWCONF_RES_PORT_NUM);
    else if (fwconf_item == FWCONF_ITEM_MACID_NUM)
        fwconf->resource_conf |= OFFSET_VALUE(val, FWCONF_RES_MACID_NUM);
    else if (fwconf_item == FWCONF_ITEM_PHY_NUM)
        fwconf->resource_conf |= OFFSET_VALUE(val, FWCONF_RES_PHY_NUM);
    else if (fwconf_item == FWCONF_ITEM_TX_OFLD_BYTE)
        fwconf->txrx_mode |= OFFSET_VALUE(val, FWCONF_MODE_TX_OFLD_BYTE);
    else if (fwconf_item == FWCONF_ITEM_TX_FLOWCTRL)
        fwconf->txrx_mode |= OFFSET_VALUE(val, FWCONF_MODE_TX_FLOWCTRL);
    else if (fwconf_item == FWCONF_ITEM_RX_OFLD_BYTE)
        fwconf->txrx_mode |= OFFSET_VALUE(val, FWCONF_MODE_RX_OFLD_BYTE);
    else if (fwconf_item == FWCONF_ITEM_RX_MODE)
        fwconf->txrx_mode |= OFFSET_VALUE(val, FWCONF_MODE_RX_MODE);
    else if (fwconf_item == FWCONF_ITEM_RX_FWD_DESC)
        fwconf->rx_flags |= (val ? FWCONF_RX_FWD_DESC_BIT : 0);
    else if (fwconf_item == FWCONF_ITEM_RX_FWD_PKTHDR)
        fwconf->rx_flags |= (val ? FWCONF_RX_FWD_PKTHDR_BIT : 0);
    else if (fwconf_item == FWCONF_ITEM_RX_MGT2EVT)
        fwconf->rx_flags |= (val ? FWCONF_RX_MGT2EVT_BIT : 0);
    else if (fwconf_item == FWCONF_ITEM_RX_RAW)
        fwconf->rx_flags |= (val ? FWCONF_RX_RAW_BIT : 0);
    else if (fwconf_item == FWCONF_ITEM_WMAC_OFLD_OPT)
        fwconf->ofld_conf |= OFFSET_VALUE(val, FWCONF_WMAC_OFLD_OPT);
    else if (fwconf_item == FWCONF_ITEM_WMAC_MACID_MODE)
        fwconf->wmac_conf |= (val ? FWCONF_WMAC_MACID_MODE_BIT : 0);
    else if (fwconf_item == FWCONF_ITEM_OFLD_LLT_BNDY)
        fwconf->dma_conf |= OFFSET_VALUE(val, FWCONF_OFLD_LLT_BNDY);
    else if (fwconf_item == FWCONF_ITEM_UART_BAUDRATE)
        fwconf->sys_config |= OFFSET_VALUE(val, FWCONF_UART_BAUDRATE);
    else if (fwconf_item == FWCONF_ITEM_CPU_FWD_FW)
        fwconf->sys_config |= (val ? FWCONF_CPU_FWD_FW_BIT : 0);
    else if (fwconf_item == FWCONF_ITEM_CLOCK_LVL)
        fwconf->sys_config |= OFFSET_VALUE(val, FWCONF_CLOCK_LVL);
    else if (fwconf_item == FWCONF_ITEM_PRINT_MODE)
        fwconf->sys_config |= OFFSET_VALUE(val, FWCONF_PRINT_MODE);
    else if (fwconf_item == FWCONF_ITEM_NETDRV)
        fwconf->sys_config |= (val ? FWCONF_NETDRV_BIT : 0);
    else if (fwconf_item == FWCONF_ITEM_TX_LOOPBACK_MODE)
        fwconf->sys_debug |= OFFSET_VALUE(val, FWCONF_TX_LOOPBACK_MODE);
    else if (fwconf_item == FWCONF_ITEM_DBG_LVL)
        fwconf->sys_debug |= OFFSET_VALUE(val, FWCONF_DBG_LVL);
    else if (fwconf_item == FWCONF_ITEM_UNIT_TEST)
        fwconf->sys_debug |= OFFSET_VALUE(val, FWCONF_UNIT_TEST);
    else {
        _ASSERT(1);
    }

    _FUNC_OUT(PRN_DEBUG, "ret %d", ret);

    return ret;
}

int fwconf_get(struct fwconf_t *fwconf,
               enum fwconf_item_e fwconf_item,
               u32 *val)
{
    int ret = 0;

    if (fwconf == NULL)
        fwconf = &fwconfDefault;

    _ASSERT(fwconf->cookies != FWCONF_COOKIES);

    _FUNC_IN(PRN_DEBUG, "item %d", fwconf_item);

    if (fwconf_item == FWCONF_ITEM_ENTRY_ADDRESS)
        *val = GET_FIELD(fwconf->boot_conf, FWCONF_ENTRY_ADDR); 
    else if (fwconf_item == FWCONF_ITEM_DEBUG_BOOT)
        *val = (fwconf->boot_conf & FWCONF_DEBUG_BOOT_BIT ? 1 : 0);
    else if (fwconf_item == FWCONF_ITEM_BOOT_CLOCK_LVL)
        *val = GET_FIELD(fwconf->boot_conf, FWCONF_BOOT_CLOCK_LVL); 
    else if (fwconf_item == FWCONF_ITEM_MAC_ADDR0_4)
        *val = GET_FIELD(fwconf->macAddr0_4, FWCONF_MAC_ADDR0_4); 
    else if (fwconf_item == FWCONF_ITEM_MAC_ADDR5_6)
        *val = GET_FIELD(fwconf->macAddr5_6, FWCONF_MAC_ADDR5_6); 
    else if (fwconf_item == FWCONF_ITEM_BSSID_NUM)
        *val = GET_FIELD(fwconf->resource_conf, FWCONF_RES_BSSID_NUM);
    else if (fwconf_item == FWCONF_ITEM_PORT_NUM)
        *val = GET_FIELD(fwconf->resource_conf, FWCONF_RES_PORT_NUM);
    else if (fwconf_item == FWCONF_ITEM_MACID_NUM)
        *val = GET_FIELD(fwconf->resource_conf, FWCONF_RES_MACID_NUM);
    else if (fwconf_item == FWCONF_ITEM_PHY_NUM)
        *val = GET_FIELD(fwconf->resource_conf, FWCONF_RES_PHY_NUM);
    else if (fwconf_item == FWCONF_ITEM_TX_OFLD_BYTE)
        *val = GET_FIELD(fwconf->txrx_mode, FWCONF_MODE_TX_OFLD_BYTE);
    else if (fwconf_item == FWCONF_ITEM_TX_FLOWCTRL)
        *val = GET_FIELD(fwconf->txrx_mode, FWCONF_MODE_TX_FLOWCTRL);
    else if (fwconf_item == FWCONF_ITEM_RX_OFLD_BYTE)
        *val = GET_FIELD(fwconf->txrx_mode, FWCONF_MODE_RX_OFLD_BYTE);
    else if (fwconf_item == FWCONF_ITEM_RX_MODE)
        *val = GET_FIELD(fwconf->txrx_mode, FWCONF_MODE_RX_MODE);
    else if (fwconf_item == FWCONF_ITEM_RX_FWD_DESC)
        *val = (fwconf->rx_flags & FWCONF_RX_FWD_DESC_BIT ? 1 : 0);
    else if (fwconf_item == FWCONF_ITEM_RX_FWD_PKTHDR)
        *val = (fwconf->rx_flags & FWCONF_RX_FWD_PKTHDR_BIT ? 1 : 0);
    else if (fwconf_item == FWCONF_ITEM_RX_MGT2EVT)
        *val = (fwconf->rx_flags & FWCONF_RX_MGT2EVT_BIT ? 1 : 0);
    else if (fwconf_item == FWCONF_ITEM_RX_RAW)
        *val = (fwconf->rx_flags & FWCONF_RX_RAW_BIT ? 1 : 0);
    else if (fwconf_item == FWCONF_ITEM_WMAC_OFLD_OPT)
        *val = GET_FIELD(fwconf->ofld_conf, FWCONF_WMAC_OFLD_OPT);
    else if (fwconf_item == FWCONF_ITEM_WMAC_MACID_MODE)
        *val = (fwconf->wmac_conf & FWCONF_WMAC_MACID_MODE_BIT ? 1 : 0);
    else if (fwconf_item == FWCONF_ITEM_OFLD_LLT_BNDY)
        *val = GET_FIELD(fwconf->dma_conf, FWCONF_OFLD_LLT_BNDY);
    else if (fwconf_item == FWCONF_ITEM_UART_BAUDRATE)
        *val = GET_FIELD(fwconf->sys_config, FWCONF_UART_BAUDRATE);
    else if (fwconf_item == FWCONF_ITEM_CPU_FWD_FW)
        *val = (fwconf->sys_config & FWCONF_CPU_FWD_FW_BIT ? 1 : 0);
    else if (fwconf_item == FWCONF_ITEM_CLOCK_LVL)
        *val = GET_FIELD(fwconf->sys_config, FWCONF_CLOCK_LVL);
    else if (fwconf_item == FWCONF_ITEM_PRINT_MODE)
        *val = GET_FIELD(fwconf->sys_config, FWCONF_PRINT_MODE);
    else if (fwconf_item == FWCONF_ITEM_NETDRV)
        *val = (fwconf->sys_config & FWCONF_NETDRV_BIT ? 1 : 0);
    else if (fwconf_item == FWCONF_ITEM_TX_LOOPBACK_MODE)
        *val = GET_FIELD(fwconf->sys_debug, FWCONF_TX_LOOPBACK_MODE);
    else if (fwconf_item == FWCONF_ITEM_DBG_LVL)
        *val = GET_FIELD(fwconf->sys_debug, FWCONF_DBG_LVL);
    else if (fwconf_item == FWCONF_ITEM_UNIT_TEST)
        *val = GET_FIELD(fwconf->sys_debug, FWCONF_UNIT_TEST);
    else {
        _ASSERT(1);
    }

    _FUNC_OUT(PRN_DEBUG, "val 0x%08x", *val);
    
    return ret;
}

void fwconf_dump(struct fwconf_t *fwconf)
{
    u8 *macAddr;

    if (fwconf == NULL)
        fwconf = &fwconfDefault;

    macAddr = (u8 *)(&(fwconf->macAddr0_4));

    _DBG_PRINT("==FWCONF");
    _DBG_PRINT("COOKIES - 0x%08x", fwconf->cookies);
    _DBG_PRINT("BOOT_CLOCK_LVL - %d", GET_FIELD(fwconf->boot_conf,
                                                FWCONF_BOOT_CLOCK_LVL));
    _DBG_PRINT("DEBUG_BOOT - %s",
                (fwconf->boot_conf & FWCONF_DEBUG_BOOT_BIT) ?
                                                          "enable" : "disable");
    _DBG_PRINT("ENTRY ADDR - 0x%x", GET_FIELD(fwconf->boot_conf,
                                              FWCONF_ENTRY_ADDR));
    _DBG_PRINT("MAC ADDR - %02x %02x %02x %02x %02x %02x", macAddr[0],
                                                           macAddr[1],
                                                           macAddr[2],
                                                           macAddr[3],
                                                           macAddr[4],
                                                           macAddr[5]);
    _DBG_PRINT("%s : %d", "BSSID_NUM", GET_FIELD(fwconf->resource_conf,
                                                   FWCONF_RES_BSSID_NUM));
    _DBG_PRINT("%s : %d", "PORT_NUM", GET_FIELD(fwconf->resource_conf,
                                                   FWCONF_RES_PORT_NUM));
    _DBG_PRINT("%s : %d", "MACID_NUM", GET_FIELD(fwconf->resource_conf,
                                                   FWCONF_RES_MACID_NUM));
    _DBG_PRINT("%s : %d", "PHY_NUM", GET_FIELD(fwconf->resource_conf,
                                                   FWCONF_RES_PHY_NUM));
    _DBG_PRINT("%s : %d (%d)", "TX_OFLD_BYTE",
                GET_FIELD(fwconf->txrx_mode, FWCONF_MODE_TX_OFLD_BYTE),
                GET_FIELD(fwconf->txrx_mode, FWCONF_MODE_TX_OFLD_BYTE) << 3);
    _DBG_PRINT("%s : %d", "TX_FLOWCTRL",
                GET_FIELD(fwconf->txrx_mode, FWCONF_MODE_TX_FLOWCTRL));
    _DBG_PRINT("%s : %d (%d)", "RX_OFLD_BYTE",
                GET_FIELD(fwconf->txrx_mode, FWCONF_MODE_RX_OFLD_BYTE),
                GET_FIELD(fwconf->txrx_mode, FWCONF_MODE_RX_OFLD_BYTE) << 3);
    _DBG_PRINT("%s : %d", "RX_MODE", GET_FIELD(fwconf->txrx_mode,
                                                 FWCONF_MODE_RX_MODE));
    _DBG_PRINT("%s : %s", "RX_FWD_DESC",
                (fwconf->rx_flags & FWCONF_RX_FWD_DESC_BIT) ?
                                                          "enable" : "disable");
    _DBG_PRINT("%s : %s", "RX_FWD_PKTHDR",
                (fwconf->rx_flags & FWCONF_RX_FWD_PKTHDR_BIT) ?
                                                          "enable" : "disable");
    _DBG_PRINT("%s : %s", "RX_MGT2EVT",
                (fwconf->rx_flags & FWCONF_RX_MGT2EVT_BIT) ?
                                                          "enable" : "disable");
    _DBG_PRINT("%s : %s", "RX_RAW",
                (fwconf->rx_flags & FWCONF_RX_RAW_BIT) ?
                                                          "enable" : "disable");
    _DBG_PRINT("%s : 0x%x", "OFLD_LLT_BNDY", GET_FIELD(fwconf->dma_conf,
                                                 FWCONF_OFLD_LLT_BNDY));
    _DBG_PRINT("%s : %d", "UART_RATE", GET_FIELD(fwconf->sys_config,
                                                 FWCONF_UART_BAUDRATE));
    _DBG_PRINT("%s : %s", "CPU_FWD_FW",
                (fwconf->sys_config & FWCONF_CPU_FWD_FW_BIT) ?
                                                          "enable" : "disable");
    _DBG_PRINT("%s : %d", "CLOCK_LVL", GET_FIELD(fwconf->sys_config,
                                                 FWCONF_CLOCK_LVL));
    _DBG_PRINT("%s : %d", "PRINT_MODE", GET_FIELD(fwconf->sys_config,
                                                  FWCONF_PRINT_MODE));
    _DBG_PRINT("%s : %s", "NETDRV",
                (fwconf->sys_config & FWCONF_NETDRV_BIT) ?
                                                          "enable" : "disable");
    _DBG_PRINT("%s : %d", "TX_LOOPBACK", GET_FIELD(fwconf->sys_debug,
                                                   FWCONF_TX_LOOPBACK_MODE));
    _DBG_PRINT("%s : %d", "DBG_LVL", GET_FIELD(fwconf->sys_debug,
                                                 FWCONF_DBG_LVL));
    _DBG_PRINT("%s : %d", "UNIT_TEST", GET_FIELD(fwconf->sys_debug,
                                                   FWCONF_UNIT_TEST));
    _DBG_PRINT("\n");

    return;
}

int host_hw_target_reset(HAL_PADAPTER Adapter,
                         u8 bootMode,
                         int upCpu)
{
    u32 val;

    _FUNC_IN(PRN_DEBUG, "bootMode %d CPU %d", bootMode, upCpu);

    if (bootMode == HW_TARGET_BOOT_FROM_SRAM)
        bootMode = BIT_BOOT_SEL_SRAM;
    else if (bootMode == HW_TARGET_BOOT_FROM_ROM)
        bootMode = BIT_BOOT_SEL_ROM;
    else {
        _ASSERT(1);
    }

    val = HAL_RTL_R32(REG_DATA_CPU_CTL0) & ~BIT_DATA_CPU_RST;
    HAL_RTL_W32(REG_DATA_CPU_CTL0, val);
    HAL_delay_ms(1);

    val = SET_WORD(val, bootMode, BIT_BOOT_SEL);
    val |= (upCpu ? BIT_DATA_CPU_RST : 0);
    HAL_RTL_W32(REG_DATA_CPU_CTL0, val);
    HAL_delay_ms(1);

    return 0;
}

static inline void ___reset_target(HAL_PADAPTER Adapter,
                                   u8 bootMode,
                                   int upCpu)
{
    int ret;

    ret = host_hw_target_reset(Adapter, bootMode, upCpu);
    _ASSERT(ret);

    return;
}

static void ___sync_fwdl_state(HAL_PADAPTER Adapter,
                               int hostState,
                               u8 *state,
                               int read)
{
    u32 stateAddr;
    char h_string[5][16] = { "H_INIT",
                             "H_CONF_DONE",
                             "H_DL0_DONE",
                             "H_DL1_DONE",
                             "H_FWD_FW_DONE" };
    char d_string[5][20] = { "D_INIT",
                             "D_BOOT_INIT_DONE",
                             "D_MEM_INIT_DONE",
                             "D_SW_INIT_DONE",
                             "D_OFLD_INIT_DONE" };

    if (hostState)
        stateAddr = REG_FWDL_H_STATE;
    else
        stateAddr = REG_FWDL_D_STATE;

    if (read)
        *state = HAL_RTL_R8(stateAddr);
    else
        HAL_RTL_W8(stateAddr, *state);

    _FUNC_OUT(PRN_LOUDLY, "%s %s state %s", (read ? "get" : "set"),
                            (hostState ? "HOST-CPU" : "DATA-CPU"),
                            (hostState ? h_string[*state] : d_string[*state]));

    return;
}

static void ___sync_fwdl_fwd_fw_info(HAL_PADAPTER Adapter,
                                     int hostInfo,
                                     u8 *info,
                                     int read)
{
    u32 stateAddr;

    if (hostInfo)
        stateAddr = REG_FWDL_H_FWD_FW_INFO;
    else
        stateAddr = REG_FWDL_D_FWD_FW_INFO;

    if (read)
        *info = HAL_RTL_R8(stateAddr);
    else
        HAL_RTL_W8(stateAddr, *info);

    _FUNC_OUT(PRN_DEBUG, "%s %s fwd_fw info 0x%02x", (read ? "get" : "set"),
                            (hostInfo ? "HOST-CPU" : "DATA-CPU"),
                            *info);

    return;
}

static inline void __checksum_update(void *checksum, void *input, u8 xor32)
{
    u8 *csum = (u8 *)checksum;
    u8 *ch = (u8 *)input;

    csum[0] ^= ch[0];
    csum[1] ^= ch[1];

    if (xor32) {
        csum[2] ^= ch[2];
        csum[3] ^= ch[3];
    }

    return;
}

static inline int __fw_csum_verify(u8 *fw, int fw_len, u8 xor32)
{
    RTL88XX_FW_HDR *fwHdr = (RTL88XX_FW_HDR *)fw;
    u32 i, calc_csum, fw_csum, init_csum = _INIT_CHECKSUM;
    u8 *ptr;
    int clen = (xor32 ? 4 : 2);

    if (clen == 2)
        init_csum = (init_csum & 0xffff);

    calc_csum = 0;
    fw_csum = fwHdr->rsvd7;
    fwHdr->rsvd7 = cpu_to_le32(init_csum);

    for (i = 0, ptr = fw;
         i < fw_len;
         i += clen, ptr += clen)
        __checksum_update((void *)&calc_csum, (void *)ptr, xor32);

    _PRINT(PRN_DEBUG, "FW csum 0x%08x calc 0x%08x", fw_csum, calc_csum);

    if (fw_csum != calc_csum) {
        _PRINT(PRN_DEBUG, "FW csum mismatch");
        return -EINVAL;
    } else
        return 0;
}

static inline int __section_csum_verify(u8 *sec, int sec_len, u8 xor32)
{
    u32 i, calc_csum = 0;
    u32 init_csum = _INIT_CHECKSUM;
    u8 *ptr;
    int clen = (xor32 ? 4 : 2);

    for (i = 0, ptr = sec;
         i < sec_len;
         i += clen, ptr += clen)
        __checksum_update((void *)&calc_csum, (void *)ptr, xor32);

    _PRINT(PRN_DEBUG, "SECTION calc 0x%08x", calc_csum);

    if (clen == 2)
        init_csum = (init_csum & 0xffff);
    if (cpu_to_le32(calc_csum) != init_csum) {
        _PRINT(PRN_DEBUG, "SECTION csum fail");

        return -EINVAL;
    } else
        return 0;
}

static int _fw_extract_verify(struct fwdl_ctx_t *fwdl_ctx,
                              u8 *fw,
                              int fw_len,
                              u8 *fwExt,
                              int fw_len_Ext,
                              int verify)
{
    struct fwHdr_t *fwHdr;
    struct section_desc_t *section_desc;
    u8 *buf = fwExt;
    int i, len, section_cnt;
    u32 word;
    int ret;

    fwHdr = (struct fwHdr_t *)fwExt;
    //mem_dump("FW-HDR", fwExt, sizeof(RTL88XX_FW_HDR));

    word = le32_to_cpu(fwHdr->word6);
    section_cnt = FWHDR_GET_FIELD(word, FWHDR_SECTION_CNT);
    len = sizeof(struct fwHdr_t) + (section_cnt * sizeof(struct section_desc_t));

    _FUNC_IN(PRN_INFO, "FW len %d sections %d", fw_len_Ext, section_cnt);

    if (verify) {
        /*
         * input FW may const data and need another working buffer
         * for checksum verify
         */
        fwdl_ctx->working_buf = kmalloc(fw_len_Ext, GFP_ATOMIC);
        if (fwdl_ctx->working_buf == NULL)
            return -ENOMEM;
        memset(fwdl_ctx->working_buf, 0, fw_len_Ext);
        memcpy(fwdl_ctx->working_buf, fwExt, fw_len_Ext);
        ret = __fw_csum_verify(fwdl_ctx->working_buf, fw_len_Ext, fwdl_ctx->xor_width);
        kfree(fwdl_ctx->working_buf);
        fwdl_ctx->working_buf = NULL;
        if (ret) {
            printk("csum verify wrong\n");
            return -EINVAL;
        }
    }        

    buf += len;
    fw_len_Ext -= len;
    fwdl_ctx->dl_cnt = 0;
    for (i = 0, section_desc = fwHdr->section;
         i < section_cnt;
         i++, section_desc++) {
        struct fwdl_dl_section_t *dl_section;
        u32 sec_length;
        int sec_type;

        word = le32_to_cpu(section_desc->word1);

        sec_length = FWHDR_GET_FIELD(word, FWHDR_SECTION_LENGTH);
        sec_type = FWHDR_GET_FIELD(word, FWHDR_SECTION_TYPE);
        _PRINT(PRN_INFO, "Found section %d, dl_addr 0x%08x len %d %s %s\n",
                                sec_type,
                                le32_to_cpu(section_desc->word0),
                                sec_length,
                                (word & FWHDR_SECTION_BIT_CSUM ? "S" : ""),
                                (word & FWHDR_SECTION_BIT_COMP ? "C" : ""));

        fw_len_Ext -= sec_length;
        if (fw_len_Ext < 0) {
            _PRINT(PRN_DEBUG, "FW size unsynced (%d)", fw_len_Ext);

            return -EINVAL;
        }

        len = sec_length;

        /* TODO: try to get align_byte from the header? */
        if (word & FWHDR_SECTION_BIT_CSUM)
            len -= 8;

        if (len < 0) {
            _PRINT(PRN_DEBUG, "FW section size is invalid");

            return -EINVAL;
        }

        if (verify && (word & FWHDR_SECTION_BIT_CSUM)) {
            if (__section_csum_verify(buf, sec_length, fwdl_ctx->xor_width))
                return -EINVAL;
        }

        if (fwdl_ctx->dl_cnt == FWDL_SECTION_MAX_CNT) {
            _PRINT(PRN_DEBUG, "only support %d section of phase2 now",
                                                          FWDL_SECTION_MAX_CNT);

            return -ENOSPC;
        }

        /* this section is ok */
        if (sec_type == _SECTION_TYPE_CONF)           /* phase0 */
            dl_section = &fwdl_ctx->conf;
        else if (sec_type == _SECTION_TYPE_BOOTCODE)  /* phase1 */
            dl_section = &fwdl_ctx->fw1;
        else if (sec_type == _SECTION_TYPE_DRAM)      /* phase3 */
            dl_section = &fwdl_ctx->fw3;
        else if (sec_type == _SECTION_TYPE_FW)        /* phase4 */
            dl_section = &fwdl_ctx->fw4;
        else                                          /* phase2 */
            dl_section = &fwdl_ctx->dl_section[fwdl_ctx->dl_cnt++];

        dl_section->dl_addr = le32_to_cpu(section_desc->word0);
        dl_section->dl_len = sec_length;
        dl_section->section_ptr = buf;

        /* to next section */
        buf += sec_length;
    }

    if (fw && (!fwdl_ctx->fw4.section_ptr))
    {
        fwdl_ctx->fw4.dl_addr = FW4_DL_ADDR;
        fwdl_ctx->fw4.dl_len = fw_len;
        fwdl_ctx->fw4.section_ptr = fw;
    }

    if (fw_len_Ext) {
        _PRINT(PRN_DEBUG, "FW size is larger than expected, %d", fw_len_Ext);

        return -EINVAL;
    }

    /* version information */
    fwdl_ctx->fwVersion = le32_to_cpu(fwHdr->word1);
    fwdl_ctx->fwRevision = le32_to_cpu(fwHdr->word2);
    fwdl_ctx->fwMonth  = FWHDR_GET_FIELD(le32_to_cpu(fwHdr->word3), FWHDR_FW_MONTH);
    fwdl_ctx->fwDay    = FWHDR_GET_FIELD(le32_to_cpu(fwHdr->word3), FWHDR_FW_DAY);
    fwdl_ctx->fwHour   = FWHDR_GET_FIELD(le32_to_cpu(fwHdr->word3), FWHDR_FW_HOUR);
    fwdl_ctx->fwMinute = FWHDR_GET_FIELD(le32_to_cpu(fwHdr->word3), FWHDR_FW_MIN);
    fwdl_ctx->fwYear   = FWHDR_GET_FIELD(le32_to_cpu(fwHdr->word4), FWHDR_FW_YEAR);

    /* download mechainsm */
    word = le32_to_cpu(fwHdr->word0);
    fwdl_ctx->dl_type = FWHDR_GET_FIELD(word, FWHDR_DL_TYPE);

    /* no CONF found, using default? */
    if (fwdl_ctx->conf.section_ptr == NULL) {
        fwdl_ctx->conf.section_ptr = (u8 *)(&_fwconf_section_default);
        fwdl_ctx->conf.dl_len = sizeof(struct fwConfSection_t);
    } else {
        /* newer CONF section structure should always larger than current */
        if (fwdl_ctx->conf.dl_len < sizeof(struct fwConfSection_t)) {

        }
    }

    printk("D-FW r%d %d/%d/%d %d:%d %s\n",
           fwdl_ctx->fwRevision,
           fwdl_ctx->fwYear, fwdl_ctx->fwMonth, fwdl_ctx->fwDay,
           fwdl_ctx->fwHour, fwdl_ctx->fwMinute,
           (fwdl_ctx->dl_type == _FW_DOWNLOAD_IO ? "IO" : "DMA"));
    _FUNC_OUT(PRN_INFO, "hdr v%d fw %s%d.%d.%d DL-%s",
                       fwdl_ctx->hdrVersion,
                       (fwdl_ctx->fwVersion & FWHDR_BIT_DEBUG_REL ? "D" : "R"),
                       FWHDR_GET_FIELD(fwdl_ctx->fwVersion, FWHDR_FW_VERSION),
                       FWHDR_GET_FIELD(fwdl_ctx->fwVersion, FWHDR_FW_SUB_VERSION),
                       FWHDR_GET_FIELD(fwdl_ctx->fwVersion, FWHDR_FW_PATCH_VERSION),
                       (fwdl_ctx->dl_type == _FW_DOWNLOAD_IO ? "IO" : "DMA"));

    return 0;
}

static inline void __get_CONF(struct fwdl_ctx_t *fwdl_ctx,
                              struct fwdl_dl_section_t *conf)
{
    struct fwConfSection_t *fwconf_section =
                                  (struct fwConfSection_t *)(conf->section_ptr);
    u8 rx_flags = fwconf_section->rx_flags;
    struct fwconf_t *fwconf = &fwconfDefault;
    int rqpnPage = host_hw_ring_dma_rqpn_table(NULL);

    fwconf_action(NULL, FWCONF_ACTION_RESET, (void *)NULL);

    /* setting from CONF section */
    fwconf_set(NULL, FWCONF_ITEM_ENTRY_ADDRESS,
                            le32_to_cpu(fwconf_section->entry_addr));
    fwconf_set(NULL, FWCONF_ITEM_MAC_ADDR0_4,
                            le32_to_cpu(fwconf_section->mac_addr0_3));
    fwconf_set(NULL, FWCONF_ITEM_MAC_ADDR5_6,
                            (u32)le16_to_cpu((fwconf_section->mac_addr4_5)));
    fwconf_set(NULL, FWCONF_ITEM_BSSID_NUM,
                                       GET_FIELD(fwconf_section->bssid_port_num,
                                                 FWCONF_BSSID_NUM));
    fwconf_set(NULL, FWCONF_ITEM_PORT_NUM,
                                       GET_FIELD(fwconf_section->bssid_port_num,
                                                 FWCONF_PORT_NUM));
    fwconf_set(NULL, FWCONF_ITEM_MACID_NUM,
                                       GET_FIELD(fwconf_section->phy_macid_num,
                                                 FWCONF_MACID_NUM) << 3);
    fwconf_set(NULL, FWCONF_ITEM_PHY_NUM,
                                       GET_FIELD(fwconf_section->phy_macid_num,
                                                 FWCONF_PHY_NUM));
    fwconf_set(NULL, FWCONF_ITEM_TX_OFLD_BYTE, fwconf_section->tx_ofld_byte);
    fwconf_set(NULL, FWCONF_ITEM_RX_OFLD_BYTE, fwconf_section->rx_ofld_byte);
    fwconf_set(NULL, FWCONF_ITEM_RX_MODE,
                            (rx_flags & FWCONF_RXFLAG_RXMODE_MSK));
    fwconf_set(NULL, FWCONF_ITEM_RX_FWD_DESC,
                            (rx_flags & FWCONF_RXFLAG_RXFWD_DESC ? 1 : 0));
    fwconf_set(NULL, FWCONF_ITEM_RX_FWD_PKTHDR,
                            (rx_flags & FWCONF_RXFLAG_RXFWD_PKTHDR ? 1 : 0));
    fwconf_set(NULL, FWCONF_ITEM_RX_MGT2EVT,
                            (rx_flags & FWCONF_RXFLAG_RXFWD_MGT2EVT ? 1 : 0));
    fwconf_set(NULL, FWCONF_ITEM_RX_RAW, wlan_device[0].priv->pshare->rf_ft_var.mp_specific ? 1 : 0);
    fwconf_set(NULL, FWCONF_ITEM_UART_BAUDRATE,
               GET_FIELD(fwconf_section->sys, FWCONF_SYS_UART_BAUDRATE));
    fwconf_set(NULL, FWCONF_ITEM_PRINT_MODE,
               GET_FIELD(fwconf_section->sys, FWCONF_SYS_PRINT_MODE));

    /* setting from driver */
    fwconf_set(NULL, FWCONF_ITEM_WMAC_OFLD_OPT, BIT(1));
                        /* BIT1: OFLD_RXDATA_L2 */
    fwconf_set(NULL, FWCONF_ITEM_OFLD_LLT_BNDY, rqpnPage);
    fwconf_set(NULL, FWCONF_ITEM_CPU_FWD_FW, !!fwdl_ctx->fw4.dl_len);

    fwconf_set(NULL, FWCONF_ITEM_NETDRV, 1);
    fwconf_set(NULL, FWCONF_ITEM_TX_LOOPBACK_MODE, wlan_device[0].priv->pshare->rf_ft_var.loopback);
                        /* 0:disable, 1:short loopback, 2:long loopback */
    fwconf_set(NULL, FWCONF_ITEM_TX_FLOWCTRL, wlan_device[0].priv->pshare->rf_ft_var.flowctrl);
                        /* 0:Disable, 1:HW, 2:SW */

    fwconf_set(NULL, FWCONF_ITEM_WMAC_MACID_MODE, !!(wlan_device[0].priv->pmib->dot11OperationEntry.opmode & WIFI_AP_STATE));
    fwconf_set(NULL, FWCONF_ITEM_DBG_LVL, wlan_device[0].priv->pshare->rf_ft_var.dbglevel);
    fwconf_set(NULL, FWCONF_ITEM_DEBUG_BOOT, 0);
    fwconf_set(NULL, FWCONF_ITEM_UNIT_TEST, wlan_device[0].priv->pshare->rf_ft_var.unittest);

#ifdef FPGA_VERIFICATION
    fwconf_set(NULL, FWCONF_ITEM_CLOCK_LVL, 3);
    fwconf_set(NULL, FWCONF_ITEM_BOOT_CLOCK_LVL, 3);
                        /* 3:PWY binfile, 4:PWD binfile */
#else
    fwconf_set(NULL, FWCONF_ITEM_CLOCK_LVL, 10);
    fwconf_set(NULL, FWCONF_ITEM_BOOT_CLOCK_LVL, 10);
#endif

    return;
}

int host_fwdl_init(struct fwdl_ctx_t *fwdl_ctx,
                   u8 *fw,
                   int len,
                   u8 *fwExt,
                   int lenExt,
                   void (*report_cb)(HAL_PADAPTER Adapter,
                                     enum fwdl_state_e state))
{
    int ret, verify = 1;

    _FUNC_IN(PRN_DEBUG, "len %d last_fw %p last_state %d", lenExt,
                                                           fwdl_ctx->fw,
                                                           fwdl_ctx->state);

    if (fwdl_ctx->fw == NULL) {
        _ASSERT(fwdl_ctx->state);
    } else {
        u8 *tmp = fwdl_ctx->working_buf;

        /* last FWDL not yet finish */
        _ASSERT((fwdl_ctx->state == FWDL_INIT) &&
                (fwdl_ctx->state >= FWDL_SW_READY))

        memset(fwdl_ctx, 0x0, sizeof(fwdl_ctx));
        fwdl_ctx->working_buf = tmp;
    }

    /* parse FW and verify it first */
    ret = _fw_extract_verify(fwdl_ctx, fw, len, fwExt, lenExt, verify);
    if (ret) {
        _PRINT(PRN_INFO, "FW verify fail, ret %d", ret);

        return -EINVAL;
    }

    _PRINT(PRN_DEBUG, "%s phase1 fw and %d phase2 sections %s phase3 fw %s phase4 fw",
                fwdl_ctx->fw1.dl_addr ? "with" : "without",
                fwdl_ctx->dl_cnt,
                fwdl_ctx->fw3.dl_addr ? "with" : "without",
                fwdl_ctx->fw4.dl_addr ? "with" : "without");

    fwdl_ctx->state = FWDL_INIT;
    fwdl_ctx->fw = fwExt;
    fwdl_ctx->fw_len = lenExt;
    fwdl_ctx->xor_width = 0;
    fwdl_ctx->report_cb = report_cb;

    /* load CONF to fwconf module */
    __get_CONF(fwdl_ctx, &fwdl_ctx->conf);

    return 0;
}

void host_hw_post_init(HAL_PADAPTER Adapter,
                       enum fwdl_state_e state)
{
    u8 val8;
    enum hw_type_e hw_type = HW_TYPE_ASIC;

    _FUNC_IN(PRN_DEBUG, "FWDL report %d", state);

    if (hw_type == HW_TYPE_FPGA) {
        /*
         * NOTE: please refer to the MAC_REG_FPGA.txt and the setting here is
         *       only for FPGA purpose and mainly for max. 2MAC throughput
         *       testing.
         */

        val8 = HAL_RTL_R8(0x2);
        val8 |= (BIT(0) | BIT(1));
        HAL_RTL_W8(0x2, val8);          /* enable BB */

        /* ASIC clock is 120Mhz (0x78) */
        HAL_RTL_W8(0x1538, 0x78);       /* TSF clock */
        HAL_RTL_W8(0x638, 0x78);        /* EDCA clock */

        /* TODO: should give a reasonable value, now set max. timeout */
        HAL_RTL_W8(0x639, 0xFF);        /* CCK ack timeout */
        HAL_RTL_W8(0x640, 0xFF);        /* OFDM ack timeout */

        /* MAC AMPDU */
        val8 = HAL_RTL_R8(0x4bc);
        val8 &= ~BIT(6);
        HAL_RTL_W8(0x4bc, val8);        /* disable pre-tx */
        HAL_RTL_W8(0x4ca, 0x3f);        /* number limit */
        HAL_RTL_W32(0x458, 0x3ffff);    /* length limit */
        HAL_RTL_W8(0x455, 0x70);        /* time limit */

        /* MAC TX */
        HAL_RTL_W32(0x1544, 0xfffff);   /* hi queue immediately */
    } else if (hw_type == HW_TYPE_ASIC) {
        val8 = HAL_RTL_R8(0x2);
        val8 |= (BIT(0) | BIT(1));
        HAL_RTL_W8(0x2, val8);          /* enable BB */

        /* ASIC clock is 120Mhz (0x78) */
        HAL_RTL_W8(0x1538, 0x78);       /* TSF clock */
        HAL_RTL_W8(0x638, 0x78);        /* EDCA clock */

        /* TODO: should give a reasonable value, now set max. timeout */
        HAL_RTL_W8(0x639, 0x40);        /* CCK ack timeout */
        HAL_RTL_W8(0x640, 0x40);        /* OFDM ack timeout */

        /* MAC AMPDU */
        val8 = HAL_RTL_R8(0x4bc);
        val8 &= ~BIT(6);
        HAL_RTL_W8(0x4bc, val8);        /* disable pre-tx */
        HAL_RTL_W16(0x4ca, 0x3f3f);     /* number limit */
        HAL_RTL_W32(0x458, 0x3ffff);    /* length limit */
        HAL_RTL_W8(0x455, 0x70);        /* time limit */

        /* MAC TX */
        HAL_RTL_W32(0x1544, 0xfffff);   /* hi queue immediately */

        /* Disable BA parser due to HW bug */
        HAL_RTL_W8(0x426, (HAL_RTL_R8(0x426) & ~BIT(5))); /* disable BA parser function */
    }

    return;
}

int host_hw_enable(HAL_PADAPTER Adapter,
                   enum hw_type_e hw_type)
{
    u32 val32;
    u16 val16;
    u8 val8;

    _FUNC_IN(PRN_DEBUG, "enable the hw");

    /* call halmac api to power on before start to download fw 
     *   halmac_run_pwrseq(halmac_adapter, HALMAC_PWR_SEQ_ENABLE);
     */
    
    /* use lower MAC clock */
    if (hw_type == HW_TYPE_FPGA) {
        _FUNC_IN(PRN_INFO, "FPGA setting");

        /*
         * NOTE: the setting here is only for FPGA purpose and mainly for
         *       max. 2MAC throughput testing.
         */

        /* ASIC clock is 120Mhz (0x78) */
        HAL_RTL_W8(0x26, 0xef);         /* MAC clock select (PCIE) */
    } else if (hw_type == HW_TYPE_ASIC) {
        _FUNC_IN(PRN_INFO, "ASIC setting");
        HAL_RTL_W8(0x26, 0xcf);         /* MAC clock select (PCIE) */
    }

    /* enable offload path */
    val32 = (BIT_EN_RXDMA_OFLD | BIT_EN_TXDMA_OFLD | BIT_EN_PKT_ENG);
    HAL_RTL_W32(REG_DATA_CPU_CTL1, val32);

    val32 = HAL_RTL_R32(REG_CPU_DMEM_CON) & ~BIT_WL_PLATFORM_RST;
    HAL_RTL_W32(REG_CPU_DMEM_CON, val32);
    val32 |= BIT_WL_PLATFORM_RST;
    HAL_RTL_W32(REG_CPU_DMEM_CON, val32);

    HAL_RTL_W8(REG_DATA_CPU_CTL0, 0);
    HAL_delay_ms(1);
    HAL_RTL_W8(REG_DATA_CPU_CTL0, BIT_DATA_PLATFORM_RST);

    /* enable OFLD DMA interface */
    val16 = (BIT_EN_HCI_TO_OFLD_TXDMA |
             BIT_EN_HCI_TO_OFLD_RXDMA |
             BIT_EN_OFLD_TXDMA |
             BIT_EN_OFLD_RXDMA);
    HAL_RTL_W16(REG_CR, val16);

    /* initial TXRX mode to normal */
    HAL_RTL_W8(REG_CR + 3, 0x0);

    return 0;
}

void host_hw_disable(HAL_PADAPTER Adapter)
{
    u16 val16;

    _FUNC_IN(PRN_DEBUG, "disable the hw");

    /* disable OFLD DMA interface */
    val16 = HAL_RTL_R16(REG_CR);
    val16 &= ~(BIT_EN_HCI_TO_OFLD_TXDMA |
               BIT_EN_HCI_TO_OFLD_RXDMA |
               BIT_EN_OFLD_TXDMA |
               BIT_EN_OFLD_RXDMA);
    HAL_RTL_W16(REG_CR, val16);

    /* disable offload path */
    if (0) {
        /*
         * binfile after 20170809 can't disable offload path for
         * saving clock buffer
         */
        HAL_RTL_W32(REG_CPU_DMEM_CON, 0x0);
        HAL_RTL_W32(REG_DATA_CPU_CTL1, 0x0);
        HAL_RTL_W32(REG_DATA_CPU_CTL0, 0x0);
    }

    return;
}

static int host_fwdl_start(HAL_PADAPTER Adapter, struct fwdl_ctx_t *fwdl_ctx)
{
    u8 state;

    _FUNC_IN(PRN_DEBUG, "FW download start");

    _ASSERT(fwdl_ctx->fw == NULL);
    _ASSERT(fwdl_ctx->state != FWDL_INIT);

    state = REG_FWDL_D_INIT;
    ___sync_fwdl_state(Adapter, 0, &state, 0);
    state = REG_FWDL_H_INIT;
    ___sync_fwdl_state(Adapter, 1, &state, 0);

    state = REG_FWDL_NULL_FWD_FW_INFO;
    ___sync_fwdl_fwd_fw_info(Adapter, 0, &state, 0);
    ___sync_fwdl_fwd_fw_info(Adapter, 1, &state, 0);

    fwdl_ctx->state = FWDL_START;

    return 0;
}

static inline int __set_CONF(HAL_PADAPTER Adapter,
                             struct fwdl_dl_section_t *conf)
{
    fwconf_action(NULL, FWCONF_ACTION_STORE, Adapter);
    //fwconf_dump(NULL);

    return 0;
}

static int host_fwdl_phase0(HAL_PADAPTER Adapter, struct fwdl_ctx_t *fwdl_ctx)
{
    u8 state = REG_FWDL_H_CONF_DONE;

    _ASSERT(fwdl_ctx->fw == NULL);
    _ASSERT(fwdl_ctx->state != FWDL_START);

    _FUNC_IN(PRN_DEBUG, "len %d", fwdl_ctx->conf.dl_len);

    ___reset_target(Adapter, HW_TARGET_BOOT_FROM_SRAM, 0);
    if (__set_CONF(Adapter, &fwdl_ctx->conf))
        return -ENOENT;

    fwdl_ctx->state = FWDL_CONF_READY;
    ___sync_fwdl_state(Adapter, 1, &state, 0);

    return 0;
}

int host_hw_fw_io_download(HAL_PADAPTER Adapter,
                           u8 *dl_buf,
                           int dl_len,
                           u32 dl_addr)
{
    u32 i, d, val32;

    _FUNC_IN(PRN_DEBUG, "dl_len %d download to 0x%x", dl_len, dl_addr);

    /* disable loudly output */
    d = GLOBAL_dbg_print;
    GLOBAL_dbg_print = PRN_OFF;

    for (i = dl_addr; i < (dl_addr + dl_len); i += 4, dl_buf += 4)
        __inWrite32(Adapter, i, *((u32 *)dl_buf));

    GLOBAL_dbg_print = d;

    return 0;
}

static inline int __IO_download(HAL_PADAPTER Adapter,
                                u8 *section_ptr,
                                u32 dl_addr,
                                int dl_len)
{
    int ret;

    _FUNC_IN(PRN_DEBUG, "dl_addr 0x%08x dl_len %d", dl_addr, dl_len);

    ret = host_hw_fw_io_download(Adapter, section_ptr, dl_len, dl_addr);
    _ASSERT(ret);

    return 0;
}

int host_hw_dnld_dma_enable(HAL_PADAPTER Adapter,
                                int port,
                                int bdNumber)
{
#define _HEAD_PAGE_OFFSET           (0)     /* start from start only for FWDL */
    u32 val32;
    u16 val16;
    u8 val8;

    _FUNC_IN(PRN_DEBUG, "enable download DMA");

    /* Download-base DMA is only for FW download purpose for Host CPU */
    _ASSERT(port != 0);

    /* enable SW beacon mode */
    val16 = HAL_RTL_R16(REG_CR) | BIT_EN_SWBCN;
    HAL_RTL_W16(REG_CR, val16);

    /* download page offset */
    HAL_RTL_W16(REG_OFLD_BCN_CTRL_0, _HEAD_PAGE_OFFSET);

    /* enable beacon head select and only use port0 */
    val8 = HAL_RTL_R16(REG_OFLD_AUTO_LLT_V1) | BIT_EN_SW_BCN_SEL;
    HAL_RTL_W8(REG_OFLD_AUTO_LLT_V1, val8);

    _ASSERT(bdNumber != 4);

    val32 = HAL_RTL_R32(REG_P0MGQ_RXQ_TXRXBD_NUM) | BIT(29);
    HAL_RTL_W32(REG_P0MGQ_RXQ_TXRXBD_NUM, val32); 

    return 0;
#undef _HEAD_PAGE_OFFSET
}

int host_hw_dnld_dma_disable(HAL_PADAPTER Adapter)
{
    u16 val16;
    u8 val8;

    _FUNC_IN(PRN_DEBUG, "disable download DMA");

    /* disable SW beacon mode */
    val16 = HAL_RTL_R16(REG_CR) & ~BIT_EN_SWBCN;
    HAL_RTL_W16(REG_CR, val16);

    /* give end of page offset */
    HAL_RTL_W16(REG_OFLD_BCN_CTRL_0, NUMBER_OF_PAGE);

    /* disable beacon head select */
    val8 = HAL_RTL_R8(REG_OFLD_AUTO_LLT_V1) & ~BIT_EN_SW_BCN_SEL;
    HAL_RTL_W8(REG_OFLD_AUTO_LLT_V1, val8);

    return 0;
}

static dma_addr_t   ctx_htxbd_dma = 0;
static void         *ctx_htxbd = NULL;
static dma_addr_t   ctx_info_dma = 0;
static void         *ctx_info = NULL;
static int          ctx_info_len = 0;

static inline int __hil_pci_dnld_enable(HAL_PADAPTER Adapter)
{
    int port = 0, bdNum = 4/*HTXBD_NUM_BD*/;
    int ret = 0;

    _FUNC_IN(PRN_DEBUG, "port %d BDs %d", port, bdNum);

    //if (ctx_htxbd)
    //    return ret;

    ret = host_hw_dnld_dma_enable(Adapter, port, bdNum);
    if (ret == 0) {
        //ctx_htxbd = pci_alloc_consistent(Adapter->pshare->pdev, 
        //                                    sizeof(struct DNLD_HTXBD_t), &ctx_htxbd_dma);
        _ASSERT(sizeof(struct DNLD_HTXBD_t) > 128);
        ctx_htxbd = _GET_HAL_DATA(Adapter)->h2d_fwdl_cpu_addr;
        ctx_htxbd_dma = _GET_HAL_DATA(Adapter)->h2d_fwdl_dma_handle;

        memset(ctx_htxbd, 0, PAGE_SIZE);

        /* config DNLD's HTXBD head address to DMA */
        HAL_RTL_W32(REG_P0BCNQ_TXBD_DESA_L_8814B, (u32)ctx_htxbd_dma);
    }

    _FUNC_OUT(PRN_DEBUG, "htxbd %p 0x%x", ctx_htxbd, ctx_htxbd_dma);

    return ret;
}

static inline int __hil_pci_dnld_disable(HAL_PADAPTER Adapter)
{
    int ret = 0;

    _FUNC_IN(PRN_DEBUG, "htxbd %p 0x%x", ctx_htxbd, ctx_htxbd_dma);

    ret = host_hw_dnld_dma_disable(Adapter);
    if (ret == 0) {
        HAL_RTL_W32(REG_P0BCNQ_TXBD_DESA_L_8814B, 0);

        /* free DMA resource */
/*        pci_free_consistent(Adapter->pshare->pdev, 
                         sizeof(struct DNLD_HTXBD_t),
                         ctx_htxbd, ctx_htxbd_dma);*/

/*        if (ctx_info)
            pci_free_consistent(Adapter->pshare->pdev,
                             ctx_info_len,
                             ctx_info, ctx_info_dma);*/

        ctx_htxbd = NULL;
        ctx_htxbd_dma = 0;
        ctx_info = NULL;
        ctx_info_dma = 0;
        ctx_info_len = 0;
    }

    return ret;
}

int host_hw_dnld_dma_poll(HAL_PADAPTER Adapter,
                          int port)
{
    u32 val32, count;
    u16 val16;

    _FUNC_IN(PRN_DEBUG, "poll download DMA, port %d", port);

    _ASSERT(port != 0);
	
#if !defined(__ECOS)
    wmb();
#endif

    /* poll DMA to work */
    val32 = HAL_RTL_R32(REG_P0MGQ_RXQ_TXRXBD_NUM) | BIT_PCIE_P0BCNQ0_POLL;
    HAL_RTL_W32(REG_P0MGQ_RXQ_TXRXBD_NUM, val32);

    /* wait until done */
    count = FWDL_POLL_CNT;
    val16 = HAL_RTL_R16(REG_OFLD_BCN_CTRL_0);
    while (!(val16 & BIT_BCN0_VALID)) {
        if (--count == 0) {
            _ASSERT(1);
        }

        mdelay(1);
        val16 = HAL_RTL_R16(REG_OFLD_BCN_CTRL_0);
    }

    /* clear the DONE bit */
    HAL_RTL_W16(REG_OFLD_BCN_CTRL_0, val16);

    return 0;
}

int host_hw_dnld_dma_block_len(HAL_PADAPTER Adapter,
                               int port)
{
#define _DOWNLOAD_RSVD_SIZE         0x800        /* 2K */
    int len = 0;
    u16 head_offset;

    _ASSERT(port != 0);

    head_offset = HAL_RTL_R16(REG_OFLD_BCN_CTRL_0);
    _ASSERT(head_offset >= NUMBER_OF_PAGE);
    
    if (head_offset == 0) {
        len = _DOWNLOAD_RSVD_SIZE;
    } else {
        /* TODO: get the possible size according the TXFF's size and final
                 reserved page number */
        _ASSERT(1);
    }

    _FUNC_OUT(PRN_DEBUG, "haed_offset %d, max len %d", head_offset, len);

    return len;
#undef _DOWNLOAD_RSVD_SIZE
}

static inline int __hil_pci_dnld_get(HAL_PADAPTER Adapter,
                                     struct TXDESC_t **txdesc,
                                     int *txdesc_txie_len,
                                     u8 **content,
                                     int *content_len)
{
    struct DNLD_HTXBD_t *dnld_htxbd = ctx_htxbd;
    struct hil_dnld_info_t *hil_dnld_info = ctx_info;
    int ret = 0;

    _FUNC_IN(PRN_DEBUG, "htxbd %p info %p", dnld_htxbd, hil_dnld_info);

    _ASSERT(!dnld_htxbd);

    if ((hil_dnld_info == NULL) ||
        (hil_dnld_info && (hil_dnld_info->atomic_cnt == 0))) {
        /* get the support max. download size */
        *content_len = host_hw_dnld_dma_block_len(Adapter, 0);
        _ASSERT(*content_len == 0);

        if (hil_dnld_info == NULL) {
            ctx_info_len = sizeof(struct hil_dnld_info_t) +
                                            *content_len;
            //ctx_info = (struct hil_dnld_info_t *)
            //                 pci_alloc_consistent(Adapter->pshare->pdev,
            //                            ctx_info_len,
            //                            &ctx_info_dma);
            _ASSERT(ctx_info_len > (PAGE_SIZE - (PAGE_SIZE >> 2)));
            ctx_info = _GET_HAL_DATA(Adapter)->h2d_fwdl_cpu_addr + (PAGE_SIZE >> 2);
            ctx_info_dma = _GET_HAL_DATA(Adapter)->h2d_fwdl_dma_handle + (PAGE_SIZE >> 2);
            hil_dnld_info = ctx_info;
        }

        hil_dnld_info->atomic_cnt++;
        *txdesc = &hil_dnld_info->txdesc;
        *txdesc_txie_len = sizeof(struct TXDESC_t) +
                           (sizeof(struct TXIE_t) * MAX_DNLD_TXIE_NUMBER);
        *content = hil_dnld_info->content;

        dnld_htxbd->HTXBD_BD[0].word0 = 0;      /* own to SW */
        dnld_htxbd->HTXBD_BD[1].word0 = 0;
    } else {    /* SW get twice */
        _ASSERT(dnld_htxbd->HTXBD_BD[0].word0 & SET_DESC(HTXBD_BD_BIT_OWN));

        *txdesc = NULL;
        *content = NULL;
        *content_len = 0;
        *txdesc_txie_len = 0;

        ret = -EINVAL;
    }

    _FUNC_OUT(PRN_DEBUG, "ret %d txdesc %p content %p dlen %d clen %d",
                                                    ret,
                                                    *txdesc, 
                                                    *content,
                                                    *txdesc_txie_len,
                                                    *content_len);

    return ret;
}

static void __dump_HTXBD(HAL_PADAPTER Adapter, struct HTXBD_t *htxbd)
{
    struct HTXBD_BD_t *amsdu_bd, *htxbd_bd = (struct HTXBD_BD_t *)htxbd;
    int bdIdx, bdIdx2, bdIdx2Max;

    _DBG_PRINT(">>>>>HTXBD");
    for (bdIdx = 0; bdIdx < HTXBD_NUM_BD; bdIdx++) {
        _DBG_PRINT("<%p> = BD%d[%08x | %08x]", (htxbd_bd + bdIdx),
                                               bdIdx,
                                               GET_DESC(htxbd_bd[bdIdx].word0),
                                               GET_DESC(htxbd_bd[bdIdx].word1));
#if 0
        if (bdIdx && (htxbd_bd[bdIdx].word0 & HTXBD_BD_BIT_A)) {
            amsdu_bd = (struct HTXBD_BD_t *)
                       PCI_PHYS_TO_VIRT(ctx, htxbd_bd[bdIdx].word1);
            bdIdx2Max = (htxbd_bd[bdIdx].word0 & HTXBD_BD_TXBUFFSIZE_MSK) /
                                                      sizeof(struct HTXBD_BD_t);
            _ASSERT(bdIdx2Max > HTXBD_NUM_2LVL_BD);
            for (bdIdx2 = 0; bdIdx2 < bdIdx2Max; bdIdx2++) {            
                _DBG_PRINT("<%p> |----[%08x | %08x]", amsdu_bd + bdIdx2,
                                                      amsdu_bd[bdIdx2].word0,
                                                      amsdu_bd[bdIdx2].word1);
#if 0
                if (amsdu_bd[bdIdx2].word1)
                    dump_bytes("aBD",
                               (u8 *)
                               PCI_PHYS_TO_VIRT(ctx, amsdu_bd[bdIdx2].word1),
                               8);
#endif
            }
        } else {
#if 0
            if (htxbd_bd[bdIdx].word1)
                dump_bytes("BD",
                           (u8 *)
                           PCI_PHYS_TO_VIRT(ctx, htxbd_bd[bdIdx].word1),
                           8);
#endif
        }
#endif
    }
    _DBG_PRINT("\n");

    return;
}

static inline int __hil_pci_dnld_set(HAL_PADAPTER Adapter,
                                     struct TXDESC_t **txdesc,
                                     int *txdesc_txie_len,
                                     u8 **content,
                                     int *content_len)
{
    struct DNLD_HTXBD_t *dnld_htxbd = ctx_htxbd;
    struct hil_dnld_info_t *hil_dnld_info = ctx_info;
    int ret = -1;

    _FUNC_IN(PRN_DEBUG, "htxbd %p info %p", dnld_htxbd, hil_dnld_info);

    _ASSERT(!dnld_htxbd);
    _ASSERT(!hil_dnld_info);

    if (hil_dnld_info->atomic_cnt) {
        int psb = HTXBD_PAGE_NUM(*content_len + *txdesc_txie_len);

        _ASSERT(dnld_htxbd->HTXBD_BD[0].word0 & SET_DESC(HTXBD_BD_BIT_OWN));

        /* TXDESC */
        dnld_htxbd->HTXBD_BD[0].word0 = SET_DESC(HTXBD_BD_BIT_OWN |     /* own to HW */
                                         OFFSET_VALUE(psb, HTXBD_BD_PSB) |
                                         OFFSET_VALUE(*txdesc_txie_len,
                                                      HTXBD_BD_TXBUFFSIZE));
        dnld_htxbd->HTXBD_BD[0].word1 = SET_DESC(virt_to_bus(*txdesc));

        /* CONTENT */
        dnld_htxbd->HTXBD_BD[1].word0 = SET_DESC(OFFSET_VALUE(*content_len,
                                                     HTXBD_BD_TXBUFFSIZE));
        dnld_htxbd->HTXBD_BD[1].word1 = SET_DESC(virt_to_bus(*content));

//        __dump_HTXBD(Adapter, (struct HTXBD_t *)dnld_htxbd);

        /* poll DMA to download */
        ret = host_hw_dnld_dma_poll(Adapter, 0);

        /* WAR: clear OWN bit by SW */
        dnld_htxbd->HTXBD_BD[0].word0 &= SET_DESC(~HTXBD_BD_BIT_OWN);

        hil_dnld_info->atomic_cnt--;
    } else
        ret = -EINVAL;

    return ret;
}

static int hil_pci_dnld(HAL_PADAPTER Adapter,
                        int intfIdx,
                        enum hil_dnld_action_e action,
                        enum hil_dnld_opmode_e opmode,
                        struct TXDESC_t **txdesc,
                        int *txdesc_txie_len,
                        u8 **content,
                        int *content_len)
{
    int ret = -1;

    _FUNC_IN(PRN_DEBUG, "action %d opmode %d", action, opmode);

    _ASSERT(intfIdx != 0);  /* only one support for FWDL */
    _ASSERT(opmode != HIL_DNLD_OPMODE_POLL);

    if (action == HIL_DNLD_ACTION_ENABLE) {
        _ASSERT(intfIdx != 0);

        ret = __hil_pci_dnld_enable(Adapter);
    } else if (action == HIL_DNLD_ACTION_DISABLE) {
        _ASSERT(intfIdx != 0);

        ret = __hil_pci_dnld_disable(Adapter);
    } else if (action == HIL_DNLD_ACTION_GET) {
        _ASSERT((!txdesc) ||
                (!content) ||
                (!txdesc_txie_len) ||
                (!content_len));

        ret = __hil_pci_dnld_get(Adapter,
                                 txdesc,
                                 txdesc_txie_len,
                                 content,
                                 content_len);
    } else if (action == HIL_DNLD_ACTION_SET) {
        _ASSERT((!txdesc) ||
                (!content) ||
                (!txdesc_txie_len) ||
                (!content_len));
        _ASSERT((*content_len == 0) || (*txdesc_txie_len == 0));

        ret = __hil_pci_dnld_set(Adapter,
                                 txdesc,
                                 txdesc_txie_len,
                                 content,
                                 content_len);
    }

    _ASSERT(ret);

    return ret;
}

static int _host_hw_iddma_report(HAL_PADAPTER Adapter)
{
    u16 csum = 0;

    csum = HAL_RTL_R16(REG_AXI_IDDMA_CSUM_VAL);

    _FUNC_OUT(PRN_DEBUG, "IDDMA csum 0x%x", csum);

    if (csum != (_INIT_CHECKSUM & 0xffff))
        return -EFAULT;
    else
        return 0;
}

static int _host_hw_iddma_once(HAL_PADAPTER Adapter,
                               u32 src,
                               u32 des,
                               int len,
                               int first)
{
    u32 val, wait_cnt;

    _FUNC_IN(PRN_DEBUG, "IDDMA 0x%x to 0x%x len %d", src, des, len);

    _ASSERT(len > BIT_IDDMA_LEN_MSK);
    _ASSERT(len & 0x3);

    /* always do csum anyway but whether to check report by the caller */
    HAL_RTL_W32(REG_AXI_IDDMA_MSK_INT, 0x1);
    if (first)
        HAL_RTL_W32(REG_AXI_IDDMA_CLR_CSUM, 0x1);

    val = (BIT_IDDMA_CSUM_CON_BIT |
           BIT_IDDMA_CSUM_BIT |
           BIT_IDDMA_OWN_BIT |
           (len & BIT_IDDMA_LEN_MSK));
    HAL_RTL_W32(REG_AXI_IDDMA_SA, src);
    HAL_RTL_W32(REG_AXI_IDDMA_DA, des);
    HAL_RTL_W32(REG_AXI_IDDMA_CTRL, val);

    /* polling until done */
    wait_cnt = FWDL_POLL_CNT;
    val = HAL_RTL_R32(REG_AXI_IDDMA_CTRL);
    while (val & BIT_IDDMA_OWN_BIT) {
        if (--wait_cnt == 0) {
            _ASSERT(1);
        }

        mdelay(1);
        val = HAL_RTL_R32(REG_AXI_IDDMA_CTRL);
    }

    return 0;
}

static inline int _host_hw_fw_dma_download(HAL_PADAPTER Adapter,
                                           u8 *buf,
                                           int buf_len,
                                           u32 dl_addr,
                                           int doCsum)
{
    struct TXDESC_t *txdesc;
    int block, txdesc_txie_len, content_len, ret = 0;
    u8 *content;
    u16 head_offset;
    u32 d, src = dl_addr;

    head_offset = HAL_RTL_R16(REG_OFLD_BCN_CTRL_0);
    if (src != HW_ADDRESS_INVALID) {
        src = ADDRESS_OF_TXFF +
              (head_offset << POWER_OF_PAGE) +
              sizeof(struct TXDESC_t);
    }

    _PRINT(PRN_DEBUG, "buf_len %d src_start 0x%x", buf_len, src);

    /* disable loudly output */
    d = GLOBAL_dbg_print;
//    GLOBAL_dbg_print = PRN_OFF;

    block = 0;
    while (buf_len > 0) {
        int len;

        /* request DMA resource */
        ret = hil_pci_dnld(Adapter,
                       0,
                       HIL_DNLD_ACTION_GET,
                       HIL_DNLD_OPMODE_POLL,
                       &txdesc,
                       &txdesc_txie_len,
                       &content,
                       &content_len);
        _ASSERT(ret);
        _ASSERT(!txdesc ||
                (txdesc_txie_len == 0) ||
                (txdesc_txie_len < sizeof(struct TXDESC_t)));
        _ASSERT(!content ||
                (content_len == 0));

        /* update download length */
        if (buf_len <= content_len)
            len = buf_len;
        else
            len = content_len;
        buf_len -= len;

        /* update content */
        memcpy(content, buf, len);
        buf += len;

        /* update TXDESC */
        txdesc->word0 = SET_DESC(TXDESC_IE_END_BIT  |
                         OFFSET_VALUE(len, TXDESC_TXPKTSIZE) |
                         OFFSET_VALUE(sizeof(struct TXDESC_t), TXDESC_OFFSET) |
                         OFFSET_VALUE(0x0, TXDESC_PKT_OFFSET));
        txdesc->word1 = SET_DESC(0x00001000); /* QSEL = BCN */
        txdesc->word2 = SET_DESC(0x00000000);
        txdesc->word3 = SET_DESC(0x00009800); /* CHANNEL_DMA = CH19 */

        /* request DMA download */
        txdesc_txie_len = sizeof(struct TXDESC_t);
        content_len = len;
        ret = hil_pci_dnld(Adapter,
                       0,
                       HIL_DNLD_ACTION_SET,
                       HIL_DNLD_OPMODE_POLL,
                       &txdesc,
                       &txdesc_txie_len,
                       &content,
                       &content_len);

        if (src != HW_ADDRESS_INVALID) {
            ret = _host_hw_iddma_once(Adapter,
                                      src,
                                      dl_addr,
                                      len,
                                      (block == 0));
            _ASSERT(ret);

            dl_addr += len;
        }
        block++;
    }
    GLOBAL_dbg_print = d;

    if (doCsum)
        ret = _host_hw_iddma_report(Adapter);

    _FUNC_OUT(PRN_DEBUG, "ret %d total %d blocks", ret, block);

    return ret;
}

int host_hw_fw_dma_download(HAL_PADAPTER Adapter,
                            u8 *dl_buf,
                            int dl_len,
                            u32 dl_addr,
                            int doCsum)
{
    _FUNC_IN(PRN_DEBUG, "dl_len %d download to 0x%x csum %d", dl_len,
                                                              dl_addr,
                                                              doCsum);

    /* no need DMA download anymore */
    if ((dl_buf == NULL) && (dl_len == 0))
        return hil_pci_dnld(Adapter,
                        0,
                        HIL_DNLD_ACTION_DISABLE,
                        HIL_DNLD_OPMODE_POLL,
                        NULL,
                        NULL,
                        NULL,
                        NULL);

    _ASSERT(dl_len == 0);
    hil_pci_dnld(Adapter,
             0,
             HIL_DNLD_ACTION_ENABLE,
             HIL_DNLD_OPMODE_POLL,
             NULL,
             NULL,
             NULL,
             NULL);

    return _host_hw_fw_dma_download(Adapter, dl_buf, dl_len, dl_addr, doCsum);
}

static int host_fwdl_end(HAL_PADAPTER Adapter, struct fwdl_ctx_t *fwdl_ctx)
{
    int ret = 0;

    _FUNC_IN(PRN_DEBUG, "FW download end");

    if (fwdl_ctx->dl_type == _FW_DOWNLOAD_DMA)
        ret = host_hw_fw_dma_download(Adapter, NULL, 0, HW_ADDRESS_INVALID, 0);

    return ret;
}

static inline int __DMA_download(HAL_PADAPTER Adapter,
                                u8 *section_ptr,
                                u32 dl_addr,
                                int dl_len)
{
    int ret = 0;

    _FUNC_IN(PRN_DEBUG, "dl_addr 0x%08x dl_len %d", dl_addr, dl_len);

    ret = host_hw_fw_dma_download(Adapter, section_ptr, dl_len, dl_addr, 1);
    //_ASSERT(ret);

    return ret;
}

static inline int _bootcode_download(HAL_PADAPTER Adapter, struct fwdl_ctx_t *fwdl_ctx)
{

    struct fwdl_dl_section_t *dl_section = &fwdl_ctx->fw1;
    int ret;

    if (fwdl_ctx->dl_type == _FW_DOWNLOAD_IO)
        ret = __IO_download(Adapter,
                            dl_section->section_ptr,
                            dl_section->dl_addr,
                            dl_section->dl_len);
    else
        ret = __DMA_download(Adapter,
                             dl_section->section_ptr,
                             dl_section->dl_addr,
                             dl_section->dl_len);

    if (ret) {
        _PRINT(PRN_DEBUG, "download boot-code fail");

        return ret;
    }
    
    return 0;
}
static inline int _reset_wait_CPU(HAL_PADAPTER Adapter, struct fwdl_ctx_t *fwdl_ctx)
{
    u8 state = 0;
    int wait = FWDL_WAIT_CNT;

    if (fwdl_ctx->fw1.dl_len == 0)
        ___reset_target(Adapter, HW_TARGET_BOOT_FROM_ROM, 1);
    else
        ___reset_target(Adapter, HW_TARGET_BOOT_FROM_SRAM, 1);

    while(wait--) {
        HAL_delay_ms(1);

        /* transit from REG_FWDL_D_INIT --> REG_FWDL_D_BOOT_INIT_DONE */
        ___sync_fwdl_state(Adapter, 0, &state, 1);
        if (state == REG_FWDL_D_BOOT_INIT_DONE)
            break;
    }

    if (wait <= 0)
        return -ENODEV;
    else
        return 0;
}

static int host_fwdl_phase1(HAL_PADAPTER Adapter, struct fwdl_ctx_t *fwdl_ctx)
{
    _ASSERT(fwdl_ctx->fw == NULL);
    _ASSERT(fwdl_ctx->state != FWDL_CONF_READY);

    _FUNC_IN(PRN_DEBUG, "boot-code %s",
                               (fwdl_ctx->fw1.dl_addr ? "download" : "ignore"));

    /* no phase1 need */
    if (fwdl_ctx->fw1.dl_len == 0)
        goto wait_BOOT_INIT_DONE;

    /* download boot-code section */
    if (_bootcode_download(Adapter, fwdl_ctx))
        return -EIO;

wait_BOOT_INIT_DONE:
    /* release CPU reset and wait it ready */
    if (_reset_wait_CPU(Adapter, fwdl_ctx))
        return -ENODEV;

    fwdl_ctx->state = FWDL_CPU_READY;

    return 0;
}

static inline int _sections_download(HAL_PADAPTER Adapter, struct fwdl_ctx_t *fwdl_ctx)
{
    struct fwdl_dl_section_t *dl_section;
    int i, ret;

    for (i = 0, dl_section = fwdl_ctx->dl_section;
         i < fwdl_ctx->dl_cnt;
         i++, dl_section++) {
        if (fwdl_ctx->dl_type == _FW_DOWNLOAD_IO)
            ret = __IO_download(Adapter,
                                dl_section->section_ptr,
                                dl_section->dl_addr,
                                dl_section->dl_len);
        else
            ret = __DMA_download(Adapter,
                                 dl_section->section_ptr,
                                 dl_section->dl_addr,
                                 dl_section->dl_len);

        if (ret) {
            _PRINT(PRN_DEBUG, "download section %d fail", i);

            return ret;
        }
     }
    
    return 0;
}

static inline int _wait_MEM(HAL_PADAPTER Adapter, struct fwdl_ctx_t *fwdl_ctx)
{
    u8 state = 0;
    int wait = FWDL_WAIT_CNT;
    u32 ja = 0;

    ___sync_fwdl_state(Adapter, 0, &state, 1);
    _ASSERT(state != REG_FWDL_D_BOOT_INIT_DONE);

    fwconf_get(NULL, FWCONF_ITEM_ENTRY_ADDRESS, &ja);
    if (ja == FWCONF_ENTRY_ADDR_INVALID) {
        /* need to add several delay before doing CPU reset. Or the downloaded
         * fw could not be executed correctly, e.g. fwdl_finish_phase2() in mBSP 
         */
        HAL_delay_ms(1);
        ___reset_target(Adapter, HW_TARGET_BOOT_FROM_SRAM, 1);
    }

    while(wait--) {
        HAL_delay_ms(1);

        /* transit from REG_FWDL_D_BOOT_INIT_DONE to REG_FWDL_D_MEM_INIT_DONE */
        ___sync_fwdl_state(Adapter, 0, &state, 1); 
        if (state == REG_FWDL_D_MEM_INIT_DONE)
            break;
    }

    if (wait <= 0)
        return -ENODEV;
    else
        return 0;
}

static int host_fwdl_phase2(HAL_PADAPTER Adapter, struct fwdl_ctx_t *fwdl_ctx)
{
    u8 state = 0;

    _ASSERT(fwdl_ctx->fw == NULL);
    _ASSERT(fwdl_ctx->state != FWDL_CPU_READY);

    _FUNC_IN(PRN_DEBUG, "sec cnt %d", fwdl_ctx->dl_cnt);

    /* TODO: which scenario no need sections? */
    if (fwdl_ctx->dl_cnt == 0)
        goto wait_MEM_INIT_DONE;

    /* download all phase2 section */
    if (_sections_download(Adapter, fwdl_ctx))
        return -EIO;

    state = REG_FWDL_H_DL0_DONE;
    ___sync_fwdl_state(Adapter, 1, &state, 0);

wait_MEM_INIT_DONE:
    /* wait all Data CPU's memory blocks ready */
    if (_wait_MEM(Adapter, fwdl_ctx))
        return -ENODEV;    

    fwdl_ctx->state = FWDL_MEM_READY;

    return 0;
}

static inline int _download_DRAM(HAL_PADAPTER Adapter, struct fwdl_ctx_t *fwdl_ctx)
{
    struct fwdl_dl_section_t *dl_section = &fwdl_ctx->fw3;
    int ret;

    if (fwdl_ctx->dl_type == _FW_DOWNLOAD_IO)
        ret = __IO_download(Adapter,
                            dl_section->section_ptr,
                            dl_section->dl_addr,
                            dl_section->dl_len);
    else
        ret = __DMA_download(Adapter,
                             dl_section->section_ptr,
                             dl_section->dl_addr,
                             dl_section->dl_len);

    if (ret) {
        _PRINT(PRN_DEBUG, "download section fail");

        return ret;
    }
    
    return 0;
}

static inline int _wait_SW(HAL_PADAPTER Adapter, struct fwdl_ctx_t *fwdl_ctx)
{
    u8 state = 0;
    int wait = FWDL_WAIT_CNT;

    while(wait--) {
        HAL_delay_ms(1);

        /* transit from REG_FWDL_D_MEM_INIT_DONE to REG_FWDL_D_SW_INIT_DONE */
        ___sync_fwdl_state(Adapter, 0, &state, 1); 
        if (state == REG_FWDL_D_SW_INIT_DONE)
            break;
    }

    if (wait <= 0)
        return -ENODEV;
    else
        return 0;
}

static int host_fwdl_phase3(HAL_PADAPTER Adapter, struct fwdl_ctx_t *fwdl_ctx)
{
    u8 state = 0;

    _ASSERT(fwdl_ctx->state != FWDL_MEM_READY);

    _FUNC_IN(PRN_DEBUG, "DRAM len %d", fwdl_ctx->fw3.dl_len);

    /* no DRAM section need */
    if (fwdl_ctx->fw3.dl_len == 0)
        goto wait_SW_INIT_DONE;

    if (_download_DRAM(Adapter, fwdl_ctx))
        return -ENODEV;

wait_SW_INIT_DONE:
    state = REG_FWDL_H_DL1_DONE;
    ___sync_fwdl_state(Adapter, 1, &state, 0);

    /* wait Data CPU FW ready */
    if (_wait_SW(Adapter, fwdl_ctx))
        return -ENODEV;    

    fwdl_ctx->state = FWDL_SW_READY;

    return 0;
}

static inline int __fw_cpu_forward(HAL_PADAPTER Adapter, struct fwdl_ctx_t *fwdl_ctx)
{
    struct fwdl_dl_section_t *dl_section = &fwdl_ctx->fw4;
    u8 fwd_info, *dl_ptr;
    u32 dl_addr;
    int blocks, dl_len, len, offset, ret = 0;
    int wait_cnt;

    _FUNC_IN(PRN_DEBUG, "dl_addr 0x%08x dl_len %d", dl_section->dl_addr,
                                                    dl_section->dl_len);

    blocks = offset = 0;
    dl_ptr = dl_section->section_ptr;
    dl_len = dl_section->dl_len;

    do {
        if (dl_len > FWDL_FWD_FW_BLOCK_SIZE)
            len = FWDL_FWD_FW_BLOCK_SIZE;
        else
            len = dl_len;

        /*
         * using ping-pong buffer and busy wait until Data CPU move previous
         * block done
         */
        if (blocks >= 2) {
            wait_cnt = 1000;
            do {
                if (--wait_cnt == 0) {
                    ret = -EIO;
                    goto fail;
                }

                HAL_delay_ms(1);
                ___sync_fwdl_fwd_fw_info(Adapter, 0, &fwd_info, 1);
            } while((fwd_info & BIT_FWDL_INFO_BID_MSK) < (blocks - 1));
        }

        if (blocks & 0x1)
            dl_addr = (dl_section->dl_addr + FWDL_FWD_FW_BLOCK_SIZE);
        else
            dl_addr = dl_section->dl_addr;

        if (fwdl_ctx->dl_type == _FW_DOWNLOAD_IO)
            ret = host_hw_fw_io_download(Adapter,
                                          dl_ptr + offset,
                                          len,
                                          dl_addr);
        else
            ret = host_hw_fw_dma_download(Adapter,
                                          dl_ptr + offset,
                                          len,
                                          dl_addr,
                                          0);
        if (ret)
            break;

        dl_len -= len;
        offset += len;
        blocks++;

        /* update host information */
        _ASSERT(blocks > BIT_FWDL_INFO_BID_MSK);
        fwd_info = ((u8)blocks | ((dl_len > 0) ? BIT_FWDL_H_INFO_CONT : 0));
        ___sync_fwdl_fwd_fw_info(Adapter, 1, &fwd_info, 0);
    } while (dl_len > 0);

fail:
    _FUNC_OUT(PRN_DEBUG, "blocks %d ret %d", blocks, ret);

    return ret;
}

static inline int __fw_dma_forward(HAL_PADAPTER Adapter, struct fwdl_ctx_t *fwdl_ctx)
{
    return -EIO;
}

static int _fw_forward(HAL_PADAPTER Adapter, struct fwdl_ctx_t *fwdl_ctx)
{
    /* HW now only support CPU FW forward */
    if (1)
        return __fw_cpu_forward(Adapter, fwdl_ctx);
    else
        return __fw_dma_forward(Adapter, fwdl_ctx);
}

static inline int _wait_ofld_ready(HAL_PADAPTER Adapter, struct fwdl_ctx_t *fwdl_ctx)
{
    u8 state;
    int wait = FWDL_WAIT_CNT;

    while(wait--) {
        HAL_delay_ms(1);

        /* transit from REG_FWDL_D_SW_INIT_DONE to REG_FWDL_D_OFLD_INIT_DONE */
        ___sync_fwdl_state(Adapter, 0, &state, 1); 
        if (state == REG_FWDL_D_OFLD_INIT_DONE)
            break;
    }

    if (wait <= 0)
        return -ENOSYS;
    else
        return 0;
}

int host_fwdl_phase4(HAL_PADAPTER Adapter, struct fwdl_ctx_t *fwdl_ctx, int blockWait)
{
    u8 state;

    _ASSERT(fwdl_ctx->fw == NULL);
    _ASSERT(fwdl_ctx->state != FWDL_SW_READY);

    _FUNC_IN(PRN_DEBUG, "wifi-fw %s",
                                (fwdl_ctx->fw4.dl_addr ? "forward" : "ignore"));

    /* no phase4 need */
    if (fwdl_ctx->fw4.dl_addr == 0)
        goto wait_OFLD_INIT_DONE;

    /* forward FW to Data CPU */
    if (_fw_forward(Adapter, fwdl_ctx))
        return -ENOSYS;

wait_OFLD_INIT_DONE:
    state = REG_FWDL_H_FWD_FW_DONE;
    ___sync_fwdl_state(Adapter, 1, &state, 0);

    /* wait Data/WiFI CPU both ready */
    if (blockWait && _wait_ofld_ready(Adapter, fwdl_ctx))
        return -ENOSYS;    

    fwdl_ctx->state = FWDL_OFLD_READY;

    return 0;
}

static inline int _start_fw(HAL_PADAPTER Adapter, struct fwdl_ctx_t *fwdl_ctx)
{
    struct cil_h2d_sys_config_t *cil_h2d_sys_config;
    int ret=0;

    _FUNC_IN(PRN_DEBUG, "issue first CIL packet");

    rtl88XX_signin_h2d_cmd(Adapter, NULL, h2d_sys_start_fw);

    /* using CIL_D2H_I_SYS_READY event as fw comfirmation hint */
    if ((ret == 0)
#ifdef CHECK_HANGUP
        && (!Adapter->reset_hangup)
#endif
    ) {
#ifdef __ECOS
        int wait = 2;
#else
        int wait = 500;
#endif

        do {
#ifdef __ECOS
			mdelay(10);
#else
            msleep(10);
#endif
            if (--wait == 0) {
                _PRINT(PRN_ALWAYS, "wait FW start fail!");

                ret = -ENXIO;
                break;
            }
        } while(Adapter->pshare->dev_core_state != DEV_CORE_STATE_FW_START);
    }

    if (ret == 0)
        fwdl_ctx->state = FWDL_FW_START;

    return ret;
}

static void __stop_fw_acked(void *handle)
{
    HAL_PADAPTER Adapter = (HAL_PADAPTER)handle;

    _FUNC_IN(PRN_DEBUG, "FW acked last CIL packet, %p", Adapter);

    //_ASSERT(skb_queue_len(&dev_core_ctx->cil_ctx->sync_info.waiting_head));

    _PRINT(PRN_DEBUG, "STATE %d --> %d", Adapter->pshare->dev_core_state,
                                         DEV_CORE_STATE_FW_STOP);
    Adapter->pshare->dev_core_state = DEV_CORE_STATE_FW_STOP;

    /* TODO: now whole system is ready to die and do some thing here. */

    return;
}

static inline int _stop_fw(HAL_PADAPTER Adapter, struct fwdl_ctx_t *fwdl_ctx)
{
    struct cil_h2d_sys_config_t *cil_h2d_sys_config;
    int ret;

    _FUNC_IN(PRN_DEBUG, "issue last CIL packet");

    rtl88XX_signin_h2d_cmd(Adapter, NULL, h2d_sys_stop_fw);

    /* using CIL sync as fw comfirmation hint but currently could ignore  */
    /*currently won't acked by data cpu*/
#if 0
    if (ret == 0) {
        int wait = 500;

        do {
            msleep(1);
            if (--wait == 0) {
                _PRINT(PRN_ALWAYS, "wait FW stop fail!");

                /* not really care about it */
                ret = 0;
                break;
            }
        } while(Adapter->pshare->dev_core_state != DEV_CORE_STATE_FW_STOP);
    }
#endif
    if (ret == 0)
        fwdl_ctx->state = FWDL_OFLD_READY;

    return ret;
}

int host_fwdl_phase5(HAL_PADAPTER Adapter, int start)
{
    struct fwdl_ctx_t *fwdl_ctx = &GLOBAL_fwdl_ctx;
    int ret = 0;

    /*
     * The phase to nigotiate the configuration with offload driver and
     * do nothing if wrong state (for HV_VERIFY)
     *
     */
    if (start) {
        if (fwdl_ctx->state == FWDL_OFLD_READY)
            ret = _start_fw(Adapter, fwdl_ctx);
        else {
            /* Phase5 only valid when FWDL state enter FWDL_OFLD_READY although
             * CIL still works even MCU FWDL fail (stuck in FWDL_SW_READY),
             * but MCU FWDL fail should not happened in release FW ball.
             */
            _PRINT(PRN_INFO, "unexpect state %d", fwdl_ctx->state);
            _ASSERT(1);
        }
    } else {
        if (fwdl_ctx->state == FWDL_FW_START)
            ret = _stop_fw(Adapter, fwdl_ctx);
        else {
            _PRINT(PRN_INFO, "unexpect state %d", fwdl_ctx->state);
            _ASSERT(1);
        }
    }

    _FUNC_OUT(PRN_INFO, "FW %s, ret %d", start ? "start" : "stop", ret);

    return ret;
}

BOOLEAN
FirmwareDownload8814B(
    IN  HAL_PADAPTER    Adapter
)
{
    pu1Byte     pFWStart, pFWStartExt;
    u4Byte      imageSZ, imageSZExt;
    int         ret;
    int         verify = 1;
    u8          *working_tmp;
    struct fwdl_ctx_t *fwdl_ctx = &GLOBAL_fwdl_ctx;

    /* mHSP firmware download procedure
     *    host_fwdl_init
     *    host_hw_enable
     *    host_fwdl_run
     */

    memset(fwdl_ctx, 0, sizeof(*fwdl_ctx));
    if (Adapter->pshare->rf_ft_var.load_fw == 2) { /* load only DataCPU FW */
        imageSZ = 0;
        pFWStart = NULL;
    } else {
        /* fw.bin: wlan fw */
        GetHwReg88XX(Adapter, HW_VAR_FWFILE_SIZE, (pu1Byte)&imageSZ);
        GetHwReg88XX(Adapter, HW_VAR_FWFILE_START, (pu1Byte)&pFWStart);
    }
    /* fwExt.bin: dcpu fw */
    GetHwReg88XX(Adapter, HW_VAR_FWEXTFILE_SIZE, (pu1Byte)&imageSZExt);
    GetHwReg88XX(Adapter, HW_VAR_FWEXTFILE_START, (pu1Byte)&pFWStartExt);

    /* init PHASE */
    host_fwdl_init(fwdl_ctx, pFWStart, imageSZ, pFWStartExt, imageSZExt, host_hw_post_init);
    fwconfDefault.macAddr0_4 = *(u32 *)&Adapter->pmib->dot11OperationEntry.hwaddr[0];
    fwconfDefault.macAddr5_6 = *(u16 *)&Adapter->pmib->dot11OperationEntry.hwaddr[4];
    host_hw_enable(Adapter, HW_TYPE_ASIC);

    /* FW download */
    host_fwdl_start(Adapter, fwdl_ctx);

    /* PHASE 0 : load CONF to fwconf module */
    if (host_fwdl_phase0(Adapter, fwdl_ctx))
        goto fwdl_fail;

    /* PHASE 1 : download boot code section */
    if (host_fwdl_phase1(Adapter, fwdl_ctx)) 
        goto fwdl_fail;

    /* PHASE 2 : download app section */
    if (host_fwdl_phase2(Adapter, fwdl_ctx)) 
        goto fwdl_fail;

    /* PHASE 3 : download DRAM section */
    if (host_fwdl_phase3(Adapter, fwdl_ctx)) 
        goto fwdl_fail;

    /* phase4: forward WiFi CPU FW */
    if (host_fwdl_phase4(Adapter, fwdl_ctx, 1)) 
        goto fwdl_fail;

    if (host_fwdl_end(Adapter, fwdl_ctx))
        goto fwdl_fail;

    if (fwdl_ctx->report_cb)
        fwdl_ctx->report_cb(Adapter, fwdl_ctx->state);

    _PRINT(PRN_DEBUG, "STATE %d --> %d", Adapter->pshare->dev_core_state,
                                         DEV_CORE_STATE_FWDL_DONE);
    Adapter->pshare->dev_core_state = DEV_CORE_STATE_FWDL_DONE;
    _FUNC_IN(PRN_INFO, "FW download done");
    printk("firmware download success.\n");

    return RT_STATUS_SUCCESS;

fwdl_fail:
    if (fwdl_ctx->report_cb)
        fwdl_ctx->report_cb(Adapter, fwdl_ctx->state);

    printk("firmware download failed!!\n");
    return RT_STATUS_FAILURE;
}

#if defined(CONFIG_8814B_FWLOG_FILE)
static mm_segment_t old_fs;
static struct file *fwlog_fp = -EINVAL;

void fwlog_file_open(void)
{
	/* open file for FWLOG */
	old_fs = get_fs();
	set_fs(KERNEL_DS);
	fwlog_fp = filp_open(DEF_FWLOG_FILENAME, (O_RDWR|O_CREAT|O_TRUNC), 0644);
	if (IS_ERR(fwlog_fp)) {
		printk("FWLOG file open failed, fp=%d\n", fwlog_fp);
		return 0;
	}
	printk("FWLOG file open success\n");
}

void fwlog_file_close(void)
{
	if (!IS_ERR(fwlog_fp)) {
		printk("FWLOG file close\n");
		filp_close(fwlog_fp, NULL);
		fwlog_fp = NULL;
		set_fs(old_fs);
	}
}
#endif

#if defined(CONFIG_8814B_FWLOG_NETLINK)
#include <net/sock.h>
#include <net/netlink.h>
#include <linux/skbuff.h>
static struct sock *fwlog_socket = NULL;

int fwlog_sock_bcast(u8 *msg, int msg_len, int type, int grp_id)
{
    struct nlmsghdr *nlhdr;
    struct fwlog_socket_hdr *shdr;
    struct sk_buff *skbuf;
    int buf_len = NLMSG_SPACE(msg_len + sizeof(struct fwlog_socket_hdr));
    u32 src_id = 0x0; /* from kernel */
    int ret = -EIO;
    static u32 seq = 0;

	if (fwlog_socket == NULL)
		return ret;

    skbuf = dev_alloc_skb(buf_len);
    if (skbuf == NULL) {
        printk("get socket buffer fail\n");
        return ret;
    }

    nlhdr = nlmsg_put(skbuf,
                      src_id,
                      0,
                      type,
                      msg_len + sizeof(struct fwlog_socket_hdr),
                      0);
    if (nlhdr == NULL) {
        printk("setup socket buffer fail\n");
        dev_kfree_skb(skbuf);
        return ret;
    }

    /* don't trust any NL's header, using local defined */
    shdr = (struct fwlog_socket_hdr *)nlmsg_data(nlhdr);
    shdr->info = (OFFSET_VALUE(msg_len, FWLOG_SOCKET_MLEN) |
                  OFFSET_VALUE(seq++, FWLOG_SOCKET_MSN));
    memcpy(shdr->msg, msg, msg_len);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,7,0)
    NETLINK_CB(skbuf).portid = src_id; 
#else
	NETLINK_CB(skbuf).pid = src_id; 
#endif
    NETLINK_CB(skbuf).dst_group = grp_id;

    ret = netlink_broadcast(fwlog_socket, skbuf, src_id, grp_id, GFP_KERNEL);
    if (ret < 0)
        printk("Socket bcast fail, skbuf %p grp_id %d\n", skbuf, grp_id);

    return ret;
}

void fwlog_sock_recv(struct sk_buff *skbuf)
{
	//printk("%s\n", __func__);
}

void fwlog_sock_open(void)
{
	struct netlink_kernel_cfg cfg;

	printk("FWLOG socket open\n");
	
	memset(&cfg, 0x0, sizeof(struct netlink_kernel_cfg));
	cfg.groups = 0x0;
	cfg.input = fwlog_sock_recv;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,7,0)
	fwlog_socket = netlink_kernel_create(&init_net, NETLINK_USERSOCK, &cfg);
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(3,6,0)
	fwlog_socket = netlink_kernel_create(&init_net, NETLINK_USERSOCK, THIS_MODULE, &cfg);
#else
	#error "Not porting netlink under this kernel version\n"
#endif
	if (fwlog_socket == NULL)
		printk("fwlog socket create failed\n");
	
	return;
}

void fwlog_sock_close(void)
{
	printk("FWLOG socket close\n");

    if (fwlog_socket)
        netlink_kernel_release(fwlog_socket);
    
    return;
}
#endif

int _sys_fwlog(HAL_PADAPTER Adapter, struct cil_pkt_t *cil)
{
	int cil_len = GET_FIELD(cil->ctrl0, CIL_CTRL_LEN);
#if defined(CONFIG_8814B_FWLOG_PRINTK)
#define FWLOG_INCIDENT_HDR_LEN      (8)
#define FWLOG_CAT_FWLOG             (31)
#define FWLOG_EVT_FWLOG_RAW_STRING  (127)
#define FWLOG_INFO_CAT_MSK          (0x1f)
#define FWLOG_INFO_EVT_MSK          (0x7f)
#define FWLOG_INFO_ARG_MSK          (0xf)
#define FWLOG_INFO_CAT_SH           (0)
#define FWLOG_INFO_EVT_SH           (5)
#define FWLOG_INFO_ARG_SH           (12)

    int remain = cil_len;
    unsigned char *ptr = cil->buf;

    while (remain > 0) {
        unsigned char str[128];
        unsigned long ctrl = cpu_to_le32(*(unsigned long *)(ptr));
        int cat = GET_FIELD(ctrl, FWLOG_INFO_CAT);
        int evt = GET_FIELD(ctrl, FWLOG_INFO_EVT);
        int arg = GET_FIELD(ctrl, FWLOG_INFO_ARG);        
        
        if (cat == FWLOG_CAT_FWLOG && 
            evt == FWLOG_EVT_FWLOG_RAW_STRING) {
            int str_len = *(ptr + FWLOG_INCIDENT_HDR_LEN);
            if (str_len >= sizeof(str))
                str_len = sizeof(str) - 1;
            memcpy(str, ptr+FWLOG_INCIDENT_HDR_LEN+1, str_len);
            str[str_len] = 0;
            printk("%s", str);
        }
        
        remain -= (FWLOG_INCIDENT_HDR_LEN + (arg << 2));
        ptr += (FWLOG_INCIDENT_HDR_LEN + (arg << 2));
    }
#endif
#if defined(CONFIG_8814B_FWLOG_FILE)
	extern struct file *fwlog_fp;
	if (IS_ERR(fwlog_fp))
		return 0;
	vfs_write(fwlog_fp, cil->buf, cil_len, &fwlog_fp->f_pos);
#endif
#if defined(CONFIG_8814B_FWLOG_NETLINK)
	fwlog_sock_bcast(cil->buf, cil_len,
			FWLOG_SOCKET_TYPE_FWLOG, FWLOG_SOCKET_GROUP_ID);
#endif

	return 1;
}

int _sys_ready(HAL_PADAPTER Adapter, struct cil_pkt_t *cil)
{
    struct fwdl_ctx_t *fwdl_ctx = &GLOBAL_fwdl_ctx;
    struct cil_d2h_sys_ready_t *cil_d2h_sys_ready;
    u8 cil_ofldVer;

    _FUNC_IN(PRN_DEBUG, "FW acked first CIL packet, %p", Adapter);

    cil_d2h_sys_ready = (struct cil_d2h_sys_ready_t *)(cil->buf);
    cil_ofldVer = cil_d2h_sys_ready->cil_ofldVer;
    
    /*
     * TODO: compatibility checking. (function-level/mcu-fw-level)
     *       a.CIL version is OK or not.
     *       b.Feature combination is OK or not.
     *       c.MCU FW information is OK or not (for OOB case).
     */
    //CIL_VERSION_OFLD(cil_ctx) = cil_ofldVer;
    if (cil_ofldVer != CIL_VERSION) {
        _PRINT(PRN_ALWAYS, "CIL version %d NOT support!", cil_ofldVer);
    } else {
        u32 fw_version = le32_to_cpu(cil_d2h_sys_ready->fw_version);
        u32 wmac_version = le32_to_cpu(cil_d2h_sys_ready->wmac_version);

        /* mismatch fw version checking */
        if (fwdl_ctx->fwVersion != fw_version) {
            _PRINT(PRN_ALWAYS, "FW comes from OOB? FW header 0x%08x but FW report 0x%08x",
                               fwdl_ctx->fwVersion,
                               fw_version);
        }

        _PRINT(PRN_INFO, "cil v%d fw_ver %s%d.%d.%d fwlog_ver v%d wmac v%d.%d.%d.%d",
                                 cil_ofldVer,
                                 (fw_version & BIT(15) ? "D" : "R"),
                                 (fw_version >> 0) & 0x7fff,
                                 (fw_version >> 16) & 0xff,
                                 (fw_version >> 24) & 0xff,
                                 cil_d2h_sys_ready->fwlog_version,
                                 (wmac_version >> 24) & 0xff,
                                 (wmac_version >> 16) & 0xff,
                                 (wmac_version >> 8) & 0xff,
                                 (wmac_version >> 0) & 0xff);
        _PRINT(PRN_INFO, "feature0 0x%x magAddr 0x%08x",
                                 le32_to_cpu(cil_d2h_sys_ready->sys_feature0),
                                 le32_to_cpu(cil_d2h_sys_ready->dcnt_magicAddr));
        _PRINT(PRN_INFO, "PORT %d MBSSID %d MACID %d peOfld 0x%08x regd %c%c",
                                 le32_to_cpu(cil_d2h_sys_ready->pe_portNum),
                                 le32_to_cpu(cil_d2h_sys_ready->pe_mbssidNum),
                                 le32_to_cpu(cil_d2h_sys_ready->pe_macIdNum),
                                 le32_to_cpu(cil_d2h_sys_ready->pe_ofldFunc),
                                 (char)(cil_d2h_sys_ready->phydm_regd[0]),
                                 (char)(cil_d2h_sys_ready->phydm_regd[1]));
        if (cil_d2h_sys_ready->sys_feature0 & CIL_D2H_SYS_READY_FLAGS_MCU_FW) {
            u8 *fwhdr = cil_d2h_sys_ready->mcu_fwInfo;

            /* TODO: read endian? */
            _PRINT(PRN_INFO, "MCU-FW info sig 0x%04x cat %d func %d v%d.%d.%d SVN%d %d/%d-%d:%d@%d",
                            *((u16 *)(fwhdr + 0)),
                            *(fwhdr + 2),
                            *(fwhdr + 3),
                            *((u16 *)(fwhdr + 4)),
                            *(fwhdr + 6),
                            *(fwhdr + 7),
                            *((u32 *)(fwhdr + 8)),
                            *(fwhdr + 16),
                            *(fwhdr + 17),
                            *(fwhdr + 18),
                            *(fwhdr + 19),
                            *((u16 *)(fwhdr + 20)));
        }

        /* TODO: now whole system is ready to go and do some thing here. */

        _ASSERT(Adapter->pshare->dev_core_state != DEV_CORE_STATE_FWDL_DONE);

        _PRINT(PRN_DEBUG, "STATE %d --> %d", Adapter->pshare->dev_core_state,
                                             DEV_CORE_STATE_FW_START);
        Adapter->pshare->dev_core_state = DEV_CORE_STATE_FW_START;
#if defined(__ECOS)
	fwdl_ctx->state = FWDL_FW_START;
#endif
    }

    return 1;
}

VOID
D2HPacket88XX
(
	IN  HAL_PADAPTER    Adapter,
	IN  pu1Byte         pBuf,
	IN	int             length
)
{
	struct cil_pkt_t *cil;
	u1Byte type, cat, id, pkt_id;
	u2Byte len;

	RT_PRINT_DATA(COMP_RECV, DBG_TRACE, "D2H packet :\n", pBuf, length);
	cil = (struct cil_pkt_t *)pBuf;
#ifdef _BIG_ENDIAN_
	cil->ctrl0 = cpu_to_le32(cil->ctrl0);
	cil->ctrl1 = cpu_to_le32(cil->ctrl1);
#endif

	type = GET_FIELD(cil->ctrl0, CIL_CTRL_TYPE);
	cat = GET_FIELD(cil->ctrl0, CIL_CTRL_CAT);
	id = GET_FIELD(cil->ctrl0, CIL_CTRL_ID);
	len = GET_FIELD(cil->ctrl0, CIL_CTRL_LEN);

	pkt_id = GET_FIELD(cil->ctrl0, CIL_CTRL_PKT_ID);
    if (Adapter->pshare->cil_pkt_id_rx != pkt_id)
    	printk("CIL pkt_id unsync!\n");
	if (++Adapter->pshare->cil_pkt_id_rx > CIL_MAX_PKT_ID)
		Adapter->pshare->cil_pkt_id_rx = 0;

	if (type != CIL_PKT_TYPE_D2H_EVT) {
		printk("[D2H] wrong packet!! type(%d)!\n", type);
		return;
	}

	switch(cat) {
	case CIL_D2H_C_SYS:
		if (id == CIL_D2H_I_SYS_FWLOG)
			_sys_fwlog(Adapter, cil);
		else if (id == CIL_D2H_I_SYS_ACK)
			;//_sys_ack(Adapter, cil);
		else if (id == CIL_D2H_I_SYS_READY)
			_sys_ready(Adapter, cil);
		else
			printk("[D2H] unsupported id!! cat(%d) id(%d)!\n", cat, id);
		break;
	case CIL_D2H_C_WMAC:
		if (id == CIL_D2H_I_WMAC_RAW_C2H)
			GET_HAL_INTERFACE(Adapter)->C2HPacketHandler(Adapter, cil->buf, len);
		break;
	default:
		printk("[D2H] unsupported category!! cat(%d)!\n", cat);
		break;
	}
}

u32 get_ext_fw_version(HALMAC_FW_VERSION *fw_version)
{
    fw_version->version = FWHDR_GET_FIELD(GLOBAL_fwdl_ctx.fwVersion, FWHDR_FW_VERSION);
    fw_version->sub_version = FWHDR_GET_FIELD(GLOBAL_fwdl_ctx.fwVersion, FWHDR_FW_SUB_VERSION);
    fw_version->sub_index = FWHDR_GET_FIELD(GLOBAL_fwdl_ctx.fwVersion, FWHDR_FW_PATCH_VERSION);
    fw_version->build_time.year= GLOBAL_fwdl_ctx.fwYear;
    fw_version->build_time.month = GLOBAL_fwdl_ctx.fwMonth;
    fw_version->build_time.date = GLOBAL_fwdl_ctx.fwDay;
    fw_version->build_time.hour = GLOBAL_fwdl_ctx.fwHour;
    fw_version->build_time.min = GLOBAL_fwdl_ctx.fwMinute;
    return GLOBAL_fwdl_ctx.fwRevision;
}
