/**
  *  @file Hal88XXHTxDesc.h  : Data structure of HTXBD/HTxDMAInfo/TxPktInfo  (Use 8814A to simulation)
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

#ifndef _HAL88XXHTXDESC_H
#define _HAL88XXHTXDESC_H

enum rt_status
PrepareH2D_TXBD88XX(
    IN      HAL_PADAPTER    Adapter
);

#endif //#ifndef _HAL88XXHTXDESC_H
