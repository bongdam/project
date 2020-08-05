/**
  *  @file Hal88XXHTxDesc.c  : Fill HTXBD/TXdESC/TxPktInfo  (Use 8814A to simulation)
  *  @brief Handle HTXBD/TXdESC/TxPktInfo of Tx-processes in HostCPU
  *
  *  Packet Offload Engine will help RTK WiFi Chip to decrease host platform CPU utilization.
  *  This functon will handle Tx-processes in Host-CPU
  *
  *  Copyright (c) 2015 Realtek Semiconductor Corp.
  *
  *  @author Peter Yu
  *  @date 2015/11/4
 **/

#if !defined(__ECOS) && !defined(CPTCFG_CFG80211_MODULE)
#include "HalPrecomp.h"
#else
#include "../HalPrecomp.h"
#include "../../../../core/WlanHAL/RTL88XX/RTL8814B/Hal8814HTxDesc_core.h"
#define __ALIGN_MASK(x,mask)	(((x)+(mask))&~(mask))
#define ALIGN(x,a)		__ALIGN_MASK((x),(typeof(x))(a)-1)
#endif

#include "Hal8814HTxDesc.h"

#ifdef CONFIG_RTL_PROC_NEW
#define PROC_PRINT(fmt, arg...)	seq_printf(s, fmt, ## arg)
#else
#define PROC_PRINT	printk
#endif

static const struct pci_dma_register_t pci_txdma_reg_map[] = {
    {HCI_TXDMA_CHAN_MGT, REG_P0MGQ_TXBD_DESA_L_8814B, REG_P0MGQ_TXBD_IDX_8814B, REG_P0MGQ_RXQ_TXRXBD_NUM},
    {HCI_TXDMA_CHAN_03, REG_ACH3_TXBD_DESA_L_8814B, REG_ACH3_TXBD_IDX_8814B, (REG_ACH2_ACH3_TXBD_NUM_8814B + 2)},
    {HCI_TXDMA_CHAN_02, REG_ACH2_TXBD_DESA_L_8814B, REG_ACH2_TXBD_IDX_8814B, REG_ACH2_ACH3_TXBD_NUM_8814B},
    {HCI_TXDMA_CHAN_01, REG_ACH1_TXBD_DESA_L_8814B, REG_ACH1_TXBD_IDX_8814B, (REG_ACH0_ACH1_TXBD_NUM_8814B + 2)},
    {HCI_TXDMA_CHAN_00, REG_ACH0_TXBD_DESA_L_8814B, REG_ACH0_TXBD_IDX_8814B, REG_ACH0_ACH1_TXBD_NUM_8814B},
    {HCI_TXDMA_CHAN_04, REG_ACH4_TXBD_DESA_L_8814B, REG_ACH4_TXBD_IDX_8814B, REG_ACH4_ACH5_TXBD_NUM_8814B},
    {HCI_TXDMA_CHAN_05, REG_ACH5_TXBD_DESA_L_8814B, REG_ACH5_TXBD_IDX_8814B, (REG_ACH4_ACH5_TXBD_NUM_8814B + 2)},
    {HCI_TXDMA_CHAN_06, REG_ACH6_TXBD_DESA_L_8814B, REG_ACH6_TXBD_IDX_8814B, REG_ACH6_ACH7_TXBD_NUM_8814B},
    {HCI_TXDMA_CHAN_07, REG_ACH7_TXBD_DESA_L_8814B, REG_ACH7_TXBD_IDX_8814B, (REG_ACH6_ACH7_TXBD_NUM_8814B + 2)},
    {HCI_TXDMA_CHAN_08, REG_ACH8_TXBD_DESA_L_8814B, REG_ACH8_TXBD_IDX_8814B, REG_ACH8_ACH9_TXBD_NUM_8814B},
    {HCI_TXDMA_CHAN_09, REG_ACH9_TXBD_DESA_L_8814B, REG_ACH9_TXBD_IDX_8814B, (REG_ACH8_ACH9_TXBD_NUM_8814B + 2)},
    {HCI_TXDMA_CHAN_10, REG_ACH10_TXBD_DESA_L_8814B, REG_ACH10_TXBD_IDX_8814B, REG_ACH10_ACH11_TXBD_NUM_8814B},
    {HCI_TXDMA_CHAN_11, REG_ACH11_TXBD_DESA_L_8814B, REG_ACH11_TXBD_IDX_8814B, (REG_ACH10_ACH11_TXBD_NUM_8814B + 2)},
    {HCI_TXDMA_CHAN_S0, REG_ACH12_TXBD_DESA_L_8814B, REG_ACH12_TXBD_IDX_8814B, REG_ACH12_ACH13_TXBD_NUM_8814B},
    {HCI_TXDMA_CHAN_S1, REG_ACH13_TXBD_DESA_L_8814B, REG_ACH13_TXBD_IDX_8814B, (REG_ACH12_ACH13_TXBD_NUM_8814B + 2)},
    {HCI_TXDMA_CHAN_HI0, REG_HI0Q_TXBD_DESA_L_8814B, REG_P0HI0Q_TXBD_IDX_8814B, REG_P0HI0Q_HI1Q_TXBD_NUM_8814B},
    {HCI_TXDMA_CHAN_HI1, REG_HI1Q_TXBD_DESA_L_8814B, REG_P0HI1Q_TXBD_IDX_8814B, (REG_P0HI0Q_HI1Q_TXBD_NUM_8814B + 2)},
    {HCI_TXDMA_CHAN_HI2, REG_HI2Q_TXBD_DESA_L_8814B, REG_P0HI2Q_TXBD_IDX_8814B, REG_P0HI2Q_HI3Q_TXBD_NUM_8814B},
    {HCI_TXDMA_CHAN_HI3, REG_HI3Q_TXBD_DESA_L_8814B, REG_P0HI3Q_TXBD_IDX_8814B, (REG_P0HI2Q_HI3Q_TXBD_NUM_8814B + 2)},
    {HCI_TXDMA_CHAN_HI4, REG_HI4Q_TXBD_DESA_L_8814B, REG_P0HI4Q_TXBD_IDX_8814B, REG_P0HI4Q_HI5Q_TXBD_NUM_8814B},
    {HCI_TXDMA_CHAN_HI5, REG_HI5Q_TXBD_DESA_L_8814B, REG_P0HI5Q_TXBD_IDX_8814B, (REG_P0HI4Q_HI5Q_TXBD_NUM_8814B + 2)},
    {HCI_TXDMA_CHAN_HI6, REG_HI6Q_TXBD_DESA_L_8814B, REG_P0HI6Q_TXBD_IDX_8814B, REG_P0HI6Q_HI7Q_TXBD_NUM_8814B},
    {HCI_TXDMA_CHAN_HI7, REG_HI7Q_TXBD_DESA_L_8814B, REG_P0HI7Q_TXBD_IDX_8814B, (REG_P0HI6Q_HI7Q_TXBD_NUM_8814B + 2)},
    {HCI_TXDMA_CHAN_HI8, REG_HI8Q_TXBD_DESA_L_8814B, REG_P0HI8Q_TXBD_IDX_8814B, REG_P0HI8Q_HI9Q_TXBD_NUM_8814B},
    {HCI_TXDMA_CHAN_HI9, REG_HI9Q_TXBD_DESA_L_8814B, REG_P0HI9Q_TXBD_IDX_8814B, (REG_P0HI8Q_HI9Q_TXBD_NUM_8814B + 2)},
    {HCI_TXDMA_CHAN_HI10, REG_HI10Q_TXBD_DESA_L_8814B, REG_P0HI10Q_TXBD_IDX_8814B, REG_P0HI10Q_HI11Q_TXBD_NUM_8814B},
    {HCI_TXDMA_CHAN_HI11, REG_HI11Q_TXBD_DESA_L_8814B, REG_P0HI11Q_TXBD_IDX_8814B, (REG_P0HI10Q_HI11Q_TXBD_NUM_8814B + 2)},
    {HCI_TXDMA_CHAN_HI12, REG_HI12Q_TXBD_DESA_L_8814B, REG_P0HI12Q_TXBD_IDX_8814B, REG_P0HI12Q_HI13Q_TXBD_NUM_8814B},
    {HCI_TXDMA_CHAN_HI13, REG_HI13Q_TXBD_DESA_L_8814B, REG_P0HI13Q_TXBD_IDX_8814B, (REG_P0HI12Q_HI13Q_TXBD_NUM_8814B + 2)},
    {HCI_TXDMA_CHAN_HI14, REG_HI14Q_TXBD_DESA_L_8814B, REG_P0HI14Q_TXBD_IDX_8814B, REG_P0HI14Q_HI15Q_TXBD_NUM_8814B},
    {HCI_TXDMA_CHAN_HI15, REG_HI15Q_TXBD_DESA_L_8814B, REG_P0HI15Q_TXBD_IDX_8814B, (REG_P0HI14Q_HI15Q_TXBD_NUM_8814B + 2)},
    {HCI_TXDMA_CHAN_HI16, REG_HI16Q_TXBD_DESA_L_8814B, REG_P0HI16Q_TXBD_IDX_8814B, REG_P0HI16Q_HI17Q_TXBD_NUM_8814B},
    {HCI_TXDMA_CHAN_HI17, REG_HI17Q_TXBD_DESA_L_8814B, REG_P0HI17Q_TXBD_IDX_8814B, (REG_P0HI16Q_HI17Q_TXBD_NUM_8814B + 2)},
    {HCI_TXDMA_CHAN_HI18, REG_HI18Q_TXBD_DESA_L_8814B, REG_P0HI18Q_TXBD_IDX_8814B, REG_P0HI18Q_HI19Q_TXBD_NUM_8814B},
    {HCI_TXDMA_CHAN_HI19, REG_HI19Q_TXBD_DESA_L_8814B, REG_P0HI19Q_TXBD_IDX_8814B, (REG_P0HI18Q_HI19Q_TXBD_NUM_8814B + 2)},
    {HCI_TXDMA_CHAN_CMD, REG_FWCMDQ_TXBD_DESA_L_8814B, REG_FWCMDQ_TXBD_IDX_8814B, REG_FWCMDQ_TXBD_NUM_8814B},
    {HCI_TXDMA_CHAN_BCN, REG_P0BCNQ_TXBD_DESA_L_8814B, 0, 0},
};

static const struct pci_dma_register_t pci_txdma_reg_map_peofld[] = {
    {HCI_TXDMA_CHAN_MGT, REG_P0MGQ_TXBD_DESA_L_8814B, REG_P0MGQ_TXBD_IDX_8814B, REG_P0MGQ_RXQ_TXRXBD_NUM},
    {HCI_TXDMA_CHAN_BCN, REG_P0BCNQ_TXBD_DESA_L_8814B, 0, 0},
    {HCI_TXDMA_CHAN_CMD, REG_FWCMDQ_TXBD_DESA_L_8814B, REG_FWCMDQ_TXBD_IDX_8814B, REG_FWCMDQ_TXBD_NUM_8814B},
    {HCI_TXDMA_CHAN_HI0, REG_HI0Q_TXBD_DESA_L_8814B, REG_P0HI0Q_TXBD_IDX_8814B, REG_P0HI0Q_HI1Q_TXBD_NUM_8814B},
    {HCI_TXDMA_CHAN_HI1, REG_HI1Q_TXBD_DESA_L_8814B, REG_P0HI1Q_TXBD_IDX_8814B, (REG_P0HI0Q_HI1Q_TXBD_NUM_8814B + 2)},
    {HCI_TXDMA_CHAN_HI2, REG_HI2Q_TXBD_DESA_L_8814B, REG_P0HI2Q_TXBD_IDX_8814B, REG_P0HI2Q_HI3Q_TXBD_NUM_8814B},
    {HCI_TXDMA_CHAN_HI3, REG_HI3Q_TXBD_DESA_L_8814B, REG_P0HI3Q_TXBD_IDX_8814B, (REG_P0HI2Q_HI3Q_TXBD_NUM_8814B + 2)},
    {HCI_TXDMA_CHAN_HI4, REG_HI4Q_TXBD_DESA_L_8814B, REG_P0HI4Q_TXBD_IDX_8814B, REG_P0HI4Q_HI5Q_TXBD_NUM_8814B},
    {HCI_TXDMA_CHAN_HI5, REG_HI5Q_TXBD_DESA_L_8814B, REG_P0HI5Q_TXBD_IDX_8814B, (REG_P0HI4Q_HI5Q_TXBD_NUM_8814B + 2)},
    {HCI_TXDMA_CHAN_HI6, REG_HI6Q_TXBD_DESA_L_8814B, REG_P0HI6Q_TXBD_IDX_8814B, REG_P0HI6Q_HI7Q_TXBD_NUM_8814B},
    {HCI_TXDMA_CHAN_HI7, REG_HI7Q_TXBD_DESA_L_8814B, REG_P0HI7Q_TXBD_IDX_8814B, (REG_P0HI6Q_HI7Q_TXBD_NUM_8814B + 2)},
    {HCI_TXDMA_CHAN_HI8, REG_HI8Q_TXBD_DESA_L_8814B, REG_P0HI8Q_TXBD_IDX_8814B, REG_P0HI8Q_HI9Q_TXBD_NUM_8814B},
    {HCI_TXDMA_CHAN_HI9, REG_HI9Q_TXBD_DESA_L_8814B, REG_P0HI9Q_TXBD_IDX_8814B, (REG_P0HI8Q_HI9Q_TXBD_NUM_8814B + 2)},
    {HCI_TXDMA_CHAN_HI10, REG_HI10Q_TXBD_DESA_L_8814B, REG_P0HI10Q_TXBD_IDX_8814B, REG_P0HI10Q_HI11Q_TXBD_NUM_8814B},
    {HCI_TXDMA_CHAN_HI11, REG_HI11Q_TXBD_DESA_L_8814B, REG_P0HI11Q_TXBD_IDX_8814B, (REG_P0HI10Q_HI11Q_TXBD_NUM_8814B + 2)},
    {HCI_TXDMA_CHAN_HI12, REG_HI12Q_TXBD_DESA_L_8814B, REG_P0HI12Q_TXBD_IDX_8814B, REG_P0HI12Q_HI13Q_TXBD_NUM_8814B},
    {HCI_TXDMA_CHAN_HI13, REG_HI13Q_TXBD_DESA_L_8814B, REG_P0HI13Q_TXBD_IDX_8814B, (REG_P0HI12Q_HI13Q_TXBD_NUM_8814B + 2)},
    {HCI_TXDMA_CHAN_HI14, REG_HI14Q_TXBD_DESA_L_8814B, REG_P0HI14Q_TXBD_IDX_8814B, REG_P0HI14Q_HI15Q_TXBD_NUM_8814B},
    {HCI_TXDMA_CHAN_HI15, REG_HI15Q_TXBD_DESA_L_8814B, REG_P0HI15Q_TXBD_IDX_8814B, (REG_P0HI14Q_HI15Q_TXBD_NUM_8814B + 2)},
    {HCI_TXDMA_CHAN_HI16, REG_HI16Q_TXBD_DESA_L_8814B, REG_P0HI16Q_TXBD_IDX_8814B, REG_P0HI16Q_HI17Q_TXBD_NUM_8814B},
    {HCI_TXDMA_CHAN_HI17, REG_HI17Q_TXBD_DESA_L_8814B, REG_P0HI17Q_TXBD_IDX_8814B, (REG_P0HI16Q_HI17Q_TXBD_NUM_8814B + 2)},
    {HCI_TXDMA_CHAN_HI18, REG_HI18Q_TXBD_DESA_L_8814B, REG_P0HI18Q_TXBD_IDX_8814B, REG_P0HI18Q_HI19Q_TXBD_NUM_8814B},
    {HCI_TXDMA_CHAN_HI19, REG_HI19Q_TXBD_DESA_L_8814B, REG_P0HI19Q_TXBD_IDX_8814B, (REG_P0HI18Q_HI19Q_TXBD_NUM_8814B + 2)},
};

#if (HAL_DEV_BUS_TYPE & (HAL_RT_EMBEDDED_INTERFACE | HAL_RT_PCI_INTERFACE))

/** @brief -- use the prepared H2D_TXBD/H2D_TXDesc
  *
  * @param param_out None
  * @param param_in  Adapter:       which Wi-Fi interface.
  * @return 1: OK, 0: Failed
  * 
 **/
enum rt_status
PrepareH2D_TXBD88XX(
    IN      HAL_PADAPTER Adapter
)
{    
    PHCI_RX_DMA_MANAGER_88XX         pd2h_rx_dma;
    PHCI_TX_DMA_MANAGER_88XX         ph2d_tx_dma;
    PTX_BUFFER_DESCRIPTOR                  ph2d_txbd_head;
    PTX_DESC_88XX             ph2d_txdma_info_head;
    PTX_BUFFER_DESCRIPTOR                  ph2d_txbd;
    pu1Byte                     desc_dma_buf_start;
    pu1Byte                     pdesc_dma_buf;
    PTX_DESC_88XX             ph2d_txdma_info;
    HCI_TX_DMA_QUEUE_OFLD       q_num;
    u4Byte                      i;
    u4Byte                      TotalTXBDNum_NoBcn;
    pu2Byte                     pTXBD_NUM;
    u4Byte                      DMA_MAX_CHANNEL_NUM;  
    struct pci_dma_register_t* pPci_txdma_reg_map;
    u4Byte tx_dma_manager_size;
    
#if (IS_EXIST_RTL8814BE)     
    u2Byte TXBD_NUM[HCI_TXDMA_CHAN_MAX_NUM] =
    {
        TX_MGQ_TXBD_NUM_8814B,		/* CH0 */
        TX_BKQ_TXBD_NUM_8814B,
        TX_BEQ_TXBD_NUM_8814B,
        TX_VIQ_TXBD_NUM_8814B,
        TX_VOQ_TXBD_NUM_8814B,
        TX_CH04Q_TXBD_NUM_8814B,		/* CH4 */
        TX_CH05Q_TXBD_NUM_8814B,
        TX_CH06Q_TXBD_NUM_8814B,
        TX_CH07Q_TXBD_NUM_8814B,
        TX_CH08Q_TXBD_NUM_8814B,		/* CH8 */
        TX_CH09Q_TXBD_NUM_8814B,
        TX_CH10Q_TXBD_NUM_8814B,
        TX_CH11Q_TXBD_NUM_8814B,
        TX_DATAQ1_TXBD_NUM_8814B,		/* S0 12 */
        TX_DATAQ2_TXBD_NUM_8814B,
        TX_HI0Q_TXBD_NUM_8814B,		/* HI0 17 */
        TX_HI1Q_TXBD_NUM_8814B,
        TX_HI2Q_TXBD_NUM_8814B,
        TX_HI3Q_TXBD_NUM_8814B,
        TX_HI4Q_TXBD_NUM_8814B,		/* HI4 */
        TX_HI5Q_TXBD_NUM_8814B,
        TX_HI6Q_TXBD_NUM_8814B,
        TX_HI7Q_TXBD_NUM_8814B,
        TX_HI8Q_TXBD_NUM_8814B,		/* HI8 */
        TX_HI9Q_TXBD_NUM_8814B,
        TX_HI10Q_TXBD_NUM_8814B,
        TX_HI11Q_TXBD_NUM_8814B,
        TX_HI12Q_TXBD_NUM_8814B,		/* HI12 */
        TX_HI13Q_TXBD_NUM_8814B,
        TX_HI14Q_TXBD_NUM_8814B,
        TX_HI15Q_TXBD_NUM_8814B,
        TX_HI16Q_TXBD_NUM_8814B,		/* HI16 */
        TX_HI17Q_TXBD_NUM_8814B,
        TX_HI18Q_TXBD_NUM_8814B,
        TX_HI19Q_TXBD_NUM_8814B,
        TX_CMDQ_TXBD_NUM_OFLD_8814B,		/* CMD 16 */
        TX_BCNQ_TXBD_NUM_OFLD_8814B,		/* BCN 15 */
    };
#endif


#if (IS_RTL8814B_SERIES) //IS_EXIST_RTL8198FEM
       if(IS_HARDWARE_TYPE_8814B(Adapter))  {
        {
            pTXBD_NUM           = TXBD_NUM;
            TotalTXBDNum_NoBcn = TOTAL_NUM_TXBD_NO_BCN_OFLD_8814B;
            DMA_MAX_CHANNEL_NUM = HCI_TXDMA_CHAN_MAX_NUM;  
            pPci_txdma_reg_map = pci_txdma_reg_map;
            tx_dma_manager_size =  sizeof(HCI_TX_DMA_MANAGER_88XX);

        }

       }
#endif //IS_RTL8814B_SERIES


#if CFG_HAL_TX_AMSDU
    pu1Byte                         pdesc_dma_buf_amsdu, desc_dma_buf_start_amsdu;
    PHCI_TX_AMSDU_DMA_MANAGER_88XX  ptx_dma_amsdu;
    PTX_BUFFER_DESCRIPTOR_AMSDU     ptxbd_head_amsdu;
#endif

    //pd2h_rx_dma         = (PHCI_RX_DMA_MANAGER_88XX)(_GET_HAL_DATA(Adapter)->PD2hRxDMA88XX);
    ph2d_tx_dma         = (PHCI_TX_DMA_MANAGER_88XX)(_GET_HAL_DATA(Adapter)->PTxDMA88XX);
    platform_zero_memory(ph2d_tx_dma, tx_dma_manager_size);


#ifdef CONFIG_NET_PCI
     if (HAL_IS_PCIBIOS_TYPE(Adapter)) {
              desc_dma_buf_start        = _GET_HAL_DATA(Adapter)->alloc_dma_buf;
     } else
#endif
     {
              desc_dma_buf_start        = _GET_HAL_DATA(Adapter)->desc_dma_buf;
              platform_zero_memory(desc_dma_buf_start, _GET_HAL_DATA(Adapter)->desc_dma_buf_len);
     }
    

//    desc_dma_buf_start  = _GET_HAL_DATA(Adapter)->alloc_dma_buf;
    //platform_zero_memory(desc_dma_buf_start, _GET_HAL_DATA(Adapter)->h2d_alloc_dma_buf_len);

	pdesc_dma_buf       = ALIGN((unsigned long)desc_dma_buf_start, HAL_PAGE_SIZE);
    //pdesc_dma_buf       = (pu1Byte)HAL_TO_NONCACHE_ADDR((unsigned long)pdesc_dma_buf); /* ?? */
    {
        //ph2d_txbd_head      = (PTX_BUFFER_DESCRIPTOR)(pdesc_dma_buf + TOTAL_NUM_RXBD_8814B * sizeof(RX_BUFFER_DESCRIPTOR));//reserved RX space
#ifdef CONFIG_NET_PCI
      if (HAL_IS_PCIBIOS_TYPE(Adapter))
            ph2d_txbd_head      = (PTX_BUFFER_DESCRIPTOR)(pdesc_dma_buf + TOTAL_NUM_RXBD_8814B * sizeof(RX_BUFFER_DESCRIPTOR));//reserved RX space
      else
#endif
            ph2d_txbd_head      = (PTX_BUFFER_DESCRIPTOR)(pdesc_dma_buf);
        
    }

    ph2d_txdma_info_head = (PTX_DESC_88XX)((pu1Byte)ph2d_txbd_head + sizeof(TX_BUFFER_DESCRIPTOR) * TotalTXBDNum_NoBcn);

    u8 bypass_qnum=0; //only support bypass continues range of queue
    // initiate all tx queue data structures
    for (q_num = 0; q_num < DMA_MAX_CHANNEL_NUM; q_num++)
    {
#if defined(CONFIG_PE_ENABLE)
        if(Adapter->pshare->rf_ft_var.manual_pe_enable){    
            if(pTXBD_NUM[q_num] == 0){ //bypass no need config channel
                bypass_qnum++;
                continue;
            }
        }
#endif  
        
        ph2d_tx_dma->tx_queue[q_num].hw_idx         = 0;
        ph2d_tx_dma->tx_queue[q_num].host_idx       = 0;
        ph2d_tx_dma->tx_queue[q_num].total_txbd_num = pTXBD_NUM[q_num];
        ph2d_tx_dma->tx_queue[q_num].avail_txbd_num = pTXBD_NUM[q_num];
        ph2d_tx_dma->tx_queue[q_num].reg_rwptr_idx  = pPci_txdma_reg_map[q_num].idx_reg_addr;

        if ( 0 == q_num ) {
            ph2d_tx_dma->tx_queue[q_num].pTXBD_head      = ph2d_txbd_head;
            ph2d_tx_dma->tx_queue[q_num].ptx_desc_head = ph2d_txdma_info_head;
        } else {
            
            ph2d_tx_dma->tx_queue[q_num].pTXBD_head      = ph2d_tx_dma->tx_queue[q_num-bypass_qnum-1].pTXBD_head + pTXBD_NUM[q_num-bypass_qnum-1];
            ph2d_tx_dma->tx_queue[q_num].ptx_desc_head = ((PTX_DESC_88XX)ph2d_tx_dma->tx_queue[q_num-bypass_qnum-1].ptx_desc_head) + pTXBD_NUM[q_num-bypass_qnum-1];
            bypass_qnum = 0;
        }
        
        ph2d_txbd       = ph2d_tx_dma->tx_queue[q_num].pTXBD_head;
        ph2d_txdma_info = ph2d_tx_dma->tx_queue[q_num].ptx_desc_head;

        RT_TRACE_F(COMP_INIT, DBG_TRACE, ("QNum: %d, TXBDHead: 0x%p, TXDESCHead: 0x%p\n", \
                                            (u4Byte)q_num, \
                                            ph2d_tx_dma->tx_queue[q_num].pTXBD_head, \
                                            ph2d_tx_dma->tx_queue[q_num].ptx_desc_head
                                            ));
        /*printk("QNum: %d, TXBDHead: 0x%p, TXDESCHead: 0x%p\n", \
                                            (u4Byte)q_num, \
                                            ph2d_tx_dma->tx_queue[q_num].pTXBD_head, \
                                            ph2d_tx_dma->tx_queue[q_num].ptx_desc_head
                                            );*/

        HAL_RTL_W32(pPci_txdma_reg_map[q_num].idx_reg_addr, 0);
        HAL_RTL_W32(pPci_txdma_reg_map[q_num].desc_reg_addr, HAL_VIRT_TO_BUS(ph2d_txbd));
        HAL_RTL_W16(pPci_txdma_reg_map[q_num].num_reg_addr, (pTXBD_NUM[q_num] | (1<<12))); /* NOTE: move from InitHCIDMAReg88XX */

        // assign LowAddress and TxDescLength to each TXBD element
        for(i = 0; i < pTXBD_NUM[q_num]; i++)        
        {   
            SET_DESC_FIELD_CLR(ph2d_txbd[i].TXBD_ELE[0].Dword0, \
                    offsetof(H2D_TXDMA_INFO, txie), \
                    TXBD_DW0_TXBUFSIZE_MSK, TXBD_DW0_TXBUFSIZE_SH);
            SET_DESC_FIELD_CLR(ph2d_txbd[i].TXBD_ELE[0].Dword1, \
                    HAL_VIRT_TO_BUS((unsigned long)&ph2d_txdma_info[i]) + CONFIG_LUNA_SLAVE_PHYMEM_OFFSET_HAL, \
                    TXBD_DW1_PHYADDR_LOW_MSK, TXBD_DW1_PHYADDR_LOW_SH);

            platform_zero_memory(&(ph2d_txbd[i].TXBD_ELE[1]), sizeof(TX_DESC_88XX)*(TXBD_ELE_NUM-1));
			
            RT_TRACE_F(COMP_INIT, DBG_TRACE, ("ptxbd[%ld]: Dword0: 0x%lx, Dword1: 0x%lx\n", \
                                            i, \
                                            GET_DESC(ph2d_txbd[i].TXBD_ELE[0].Dword0), \
                                            GET_DESC(ph2d_txbd[i].TXBD_ELE[0].Dword1)
                                            ));
            
#ifdef TRXBD_CACHABLE_REGION
                        
#ifdef CONFIG_RTL_8198F
#ifdef CONFIG_ENABLE_CCI400
            // With CCI400 ,Do nothing for cache coherent code
#else
            rtl_cache_sync_wback(Adapter,(unsigned long)(&(ph2d_txbd[i].TXBD_ELE[0])), 
                    sizeof(TX_BUFFER_DESCRIPTOR),PCI_DMA_TODEVICE);
            if(q_num==0){
                //printk("flush addr=%x,phyaddr=%x\n",&ph2d_txbd[i].H2D_TXBD_ELE[0], HAL_VIRT_TO_BUS(&ph2d_txbd[i].H2D_TXBD_ELE[0]));
                //printk("Dword0 value = %x\n",ph2d_txbd[i].H2D_TXBD_ELE[0].Dword0);
                //printk("Dword1 value = %x\n",ph2d_txbd[i].H2D_TXBD_ELE[0].Dword1);
            }
#endif //CONFIG_ENABLE_CCI400
#else
            _dma_cache_wback((unsigned long)(&(ph2d_txbd[i].TXBD_ELE[0])), 
                    sizeof(TX_BUFFER_DESCRIPTOR));
                        
#endif //CONFIG_RTL_8198F
                                      
#endif	//TRXBD_CACHABLE_REGION					
        }
    }

#if CFG_HAL_TX_AMSDU
    if ( IS_SUPPORT_TX_AMSDU(Adapter) ) {
        ptx_dma_amsdu = (PHCI_TX_AMSDU_DMA_MANAGER_88XX)(_GET_HAL_DATA(Adapter)->PTxDMAAMSDU88XX);
   
        desc_dma_buf_start_amsdu = _GET_HAL_DATA(Adapter)->desc_dma_buf_amsdu;
        platform_zero_memory(desc_dma_buf_start_amsdu, _GET_HAL_DATA(Adapter)->desc_dma_buf_len_amsdu);

        pdesc_dma_buf_amsdu = (pu1Byte)(_GET_HAL_DATA(Adapter)->desc_dma_buf_virt_amsdu);

        // BK, BE, VI, VO
        ptx_dma_amsdu->tx_amsdu_queue[HCI_TX_AMSDU_DMA_QUEUE_BK].pTXBD_head_amsdu = pdesc_dma_buf_amsdu;
        ptx_dma_amsdu->tx_amsdu_queue[HCI_TX_AMSDU_DMA_QUEUE_BE].pTXBD_head_amsdu = (pu1Byte)ptx_dma_amsdu->tx_amsdu_queue[HCI_TX_AMSDU_DMA_QUEUE_BK].pTXBD_head_amsdu + TX_BKQ_TXBD_NUM * sizeof(TXBD_ELEMENT)* MAX_NUM_OF_MSDU_IN_AMSDU;
        ptx_dma_amsdu->tx_amsdu_queue[HCI_TX_AMSDU_DMA_QUEUE_VI].pTXBD_head_amsdu = (pu1Byte)ptx_dma_amsdu->tx_amsdu_queue[HCI_TX_AMSDU_DMA_QUEUE_BE].pTXBD_head_amsdu + TX_BEQ_TXBD_NUM * sizeof(TXBD_ELEMENT)* MAX_NUM_OF_MSDU_IN_AMSDU;
        ptx_dma_amsdu->tx_amsdu_queue[HCI_TX_AMSDU_DMA_QUEUE_VO].pTXBD_head_amsdu = (pu1Byte)ptx_dma_amsdu->tx_amsdu_queue[HCI_TX_AMSDU_DMA_QUEUE_VI].pTXBD_head_amsdu + TX_VIQ_TXBD_NUM * sizeof(TXBD_ELEMENT)* MAX_NUM_OF_MSDU_IN_AMSDU;
        _GET_HAL_DATA(Adapter)->desc_dma_buf_addr_amsdu[1] = _GET_HAL_DATA(Adapter)->desc_dma_buf_addr_amsdu[0] + TX_BKQ_TXBD_NUM * sizeof(TXBD_ELEMENT)* MAX_NUM_OF_MSDU_IN_AMSDU;
        _GET_HAL_DATA(Adapter)->desc_dma_buf_addr_amsdu[2] = _GET_HAL_DATA(Adapter)->desc_dma_buf_addr_amsdu[1] + TX_BEQ_TXBD_NUM * sizeof(TXBD_ELEMENT)* MAX_NUM_OF_MSDU_IN_AMSDU;
        _GET_HAL_DATA(Adapter)->desc_dma_buf_addr_amsdu[3] = _GET_HAL_DATA(Adapter)->desc_dma_buf_addr_amsdu[2] + TX_VIQ_TXBD_NUM * sizeof(TXBD_ELEMENT)* MAX_NUM_OF_MSDU_IN_AMSDU;    
    }
#endif 

    return RT_STATUS_SUCCESS;
}

#endif
