/******************************************************************************
*
* Copyright(c) 2016 - 2017 Realtek Corporation.
*
* This program is free software; you can redistribute it and/or modify it
* under the terms of version 2 of the GNU General Public License as
* published by the Free Software Foundation.
*
* This program is distributed in the hope that it will be useful, but WITHOUT
* ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
* FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for
* more details.
*
*****************************************************************************/
#include "mp_precomp.h"
#include "../phydm_precomp.h"

#if (RTL8710C_SUPPORT == 1)

/* ======================================================================== */
/* These following functions can be used for PHY DM only*/

u32 rega20_8710c;
u32 rega24_8710c;
u32 rega28_8710c;
u32 rega98_8710c;
u32 regaac_8710c;

u8 central_ch_8710c;

#if 0

__iram_odm_func__
s8 phydm_cckrssi_8710c(struct dm_struct *dm, u8 lna_idx, u8 vga_idx)
{
	s8 rx_pwr_all = 0x00;
	
	switch (lna_idx) {
	case 7:
		rx_pwr_all = -45 - (2 * vga_idx);
		break;
	case 5:
		rx_pwr_all = -28 - (2 * vga_idx);
		break;
	case 3:
		rx_pwr_all = -16 - (2 * vga_idx);
		break;
	case 0:
		rx_pwr_all = 10 - (2 * vga_idx);
	default:
		break;
	}

	return rx_pwr_all;
}




__iram_odm_func__
boolean
phydm_rfe_8710c(
	struct dm_struct *dm,
	u8 channel)
{
#if 0
	/* Efuse is not wrote now */
	/* Need to check RFE type finally */
	/*if (dm->rfe_type == 1) {*/
	if (channel <= 14) {
		/* signal source */
		odm_set_bb_reg(dm, R_0xcb0, (MASKBYTE2 | MASKLWORD), 0x704570);
		odm_set_bb_reg(dm, R_0xeb0, (MASKBYTE2 | MASKLWORD), 0x704570);
		odm_set_bb_reg(dm, R_0xcb4, MASKBYTE1, 0x45);
		odm_set_bb_reg(dm, R_0xeb4, MASKBYTE1, 0x45);
	} else if (channel > 35) {
		odm_set_bb_reg(dm, R_0xcb0, (MASKBYTE2 | MASKLWORD), 0x174517);
		odm_set_bb_reg(dm, R_0xeb0, (MASKBYTE2 | MASKLWORD), 0x174517);
		odm_set_bb_reg(dm, R_0xcb4, MASKBYTE1, 0x45);
		odm_set_bb_reg(dm, R_0xeb4, MASKBYTE1, 0x45);
	} else
		return false;

	/* chip top mux */
	odm_set_bb_reg(dm, R_0x64, BIT(29) | BIT(28), 0x3);
	odm_set_bb_reg(dm, R_0x4c, BIT(26) | BIT(25), 0x0);
	odm_set_bb_reg(dm, R_0x40, BIT(2), 0x1);

	/* from s0 or s1 */
	odm_set_bb_reg(dm, R_0x1990, (BIT(5) | BIT(4) | BIT(3) | BIT(2) | BIT(1) | BIT(0)), 0x30);
	odm_set_bb_reg(dm, R_0x1990, (BIT(11) | BIT(10)), 0x3);

	/* input or output */
	odm_set_bb_reg(dm, R_0x974, (BIT(5) | BIT(4) | BIT(3) | BIT(2) | BIT(1) | BIT(0)), 0x3f);
	odm_set_bb_reg(dm, R_0x974, (BIT(11) | BIT(10)), 0x3);

	/* delay 400ns for PAPE */
	odm_set_bb_reg(dm, R_0x810, MASKBYTE3 | BIT(20) | BIT(21) | BIT(22) | BIT(23), 0x211);

	/* antenna switch table */
	odm_set_bb_reg(dm, R_0xca0, MASKLWORD, 0xa555);
	odm_set_bb_reg(dm, R_0xea0, MASKLWORD, 0xa555);

	/* inverse or not */
	odm_set_bb_reg(dm, R_0xcbc, (BIT(5) | BIT(4) | BIT(3) | BIT(2) | BIT(1) | BIT(0)), 0x0);
	odm_set_bb_reg(dm, R_0xcbc, (BIT(11) | BIT(10)), 0x0);
	odm_set_bb_reg(dm, R_0xebc, (BIT(5) | BIT(4) | BIT(3) | BIT(2) | BIT(1) | BIT(0)), 0x0);
	odm_set_bb_reg(dm, R_0xebc, (BIT(11) | BIT(10)), 0x0);
	/*}*/
#endif
	return true;
}

__iram_odm_func__
void phydm_ccapar_8710c(
	struct dm_struct *dm)
{
#if 0
	u32	cca_ifem[9][4] = {
		/*20M*/
		{0x75D97010, 0x75D97010, 0x75D97010, 0x75D97010}, /*Reg82C*/
		{0x00000000, 0x00000000, 0x00000000, 0x00000000}, /*Reg830*/
		{0x00000000, 0x00000000, 0x00000000, 0x00000000}, /*Reg838*/
		/*40M*/
		{0x75D97010, 0x75D97010, 0x75D97010, 0x75D97010}, /*Reg82C*/
		{0x00000000, 0x79a0ea28, 0x00000000, 0x79a0ea28}, /*Reg830*/
		{0x87765541, 0x87766341, 0x87765541, 0x87766341}, /*Reg838*/
		/*80M*/
		{0x75D97010, 0x75D97010, 0x75D97010, 0x75D97010}, /*Reg82C*/
		{0x00000000, 0x00000000, 0x00000000, 0x00000000}, /*Reg830*/
		{0x00000000, 0x87746641, 0x00000000, 0x87746641}
	}; /*Reg838*/

	u32	cca_efem[9][4] = {
		/*20M*/
		{0x75A76010, 0x75A76010, 0x75A76010, 0x75A75010}, /*Reg82C*/
		{0x00000000, 0x00000000, 0x00000000, 0x00000000}, /*Reg830*/
		{0x87766651, 0x87766431, 0x87766451, 0x87766431}, /*Reg838*/
		/*40M*/
		{0x75A75010, 0x75A75010, 0x75A75010, 0x75A75010}, /*Reg82C*/
		{0x00000000, 0x00000000, 0x00000000, 0x00000000}, /*Reg830*/
		{0x87766431, 0x87766431, 0x87766431, 0x87766431}, /*Reg838*/
		/*80M*/
		{0x75BA7010, 0x75BA7010, 0x75BA7010, 0x75BA7010}, /*Reg82C*/
		{0x00000000, 0x00000000, 0x00000000, 0x00000000}, /*Reg830*/
		{0x87766431, 0x87766431, 0x87766431, 0x87766431}
	}; /*Reg838*/

	u8	row, col;
	u32	reg82c, reg830, reg838;

	if (dm->cut_version != ODM_CUT_B)
		return;

	if (bw_8710c == CHANNEL_WIDTH_20)
		row = 0;
	else if (bw_8710c == CHANNEL_WIDTH_40)
		row = 3;
	else
		row = 6;

	if (central_ch_8710c <= 14) {
		if (dm->rx_ant_status == BB_PATH_A || dm->rx_ant_status == BB_PATH_B)
			col = 0;
		else
			col = 1;
	} else {
		if (dm->rx_ant_status == BB_PATH_A || dm->rx_ant_status == BB_PATH_B)
			col = 2;
		else
			col = 3;
	}

	if (dm->rfe_type == 0) {/*iFEM*/
		reg82c = (cca_ifem[row][col] != 0) ? cca_ifem[row][col] : reg82c_8710c;
		reg830 = (cca_ifem[row + 1][col] != 0) ? cca_ifem[row + 1][col] : reg830_8710c;
		reg838 = (cca_ifem[row + 2][col] != 0) ? cca_ifem[row + 2][col] : reg838_8710c;
	} else {/*eFEM*/
		reg82c = (cca_efem[row][col] != 0) ? cca_efem[row][col] : reg82c_8710c;
		reg830 = (cca_efem[row + 1][col] != 0) ? cca_efem[row + 1][col] : reg830_8710c;
		reg838 = (cca_efem[row + 2][col] != 0) ? cca_efem[row + 2][col] : reg838_8710c;
	}

	odm_set_bb_reg(dm, R_0x82c, MASKDWORD, reg82c);
	odm_set_bb_reg(dm, R_0x830, MASKDWORD, reg830);
	odm_set_bb_reg(dm, R_0x838, MASKDWORD, reg838);

	PHYDM_DBG(dm, ODM_PHY_CONFIG,
		  "[%s]: Update CCA parameters for Bcut (Pkt%d, Intf%d, RFE%d), row = %d, col = %d\n",
		  __func__, dm->package_type, dm->support_interface,
		  dm->rfe_type, row, col);
#endif
}

__iram_odm_func__
void phydm_ccapar_by_bw_8710c(
	struct dm_struct *dm,
	enum channel_width bandwidth)
{
#if 0
	u32		reg82c;


	if (dm->cut_version != ODM_CUT_A)
		return;

	/* A-cut */
	reg82c = odm_get_bb_reg(dm, R_0x82c, MASKDWORD);

	if (bandwidth == CHANNEL_WIDTH_20) {
		/* 82c[15:12] = 4 */
		/* 82c[27:24] = 6 */

		reg82c &= (~(0x0f00f000));
		reg82c |= ((0x4) << 12);
		reg82c |= ((0x6) << 24);
	} else if (bandwidth == CHANNEL_WIDTH_40) {
		/* 82c[19:16] = 9 */
		/* 82c[27:24] = 6 */

		reg82c &= (~(0x0f0f0000));
		reg82c |= ((0x9) << 16);
		reg82c |= ((0x6) << 24);
	} else if (bandwidth == CHANNEL_WIDTH_80) {
		/* 82c[15:12] 7 */
		/* 82c[19:16] b */
		/* 82c[23:20] d */
		/* 82c[27:24] 3 */

		reg82c &= (~(0x0ffff000));
		reg82c |= ((0xdb7) << 12);
		reg82c |= ((0x3) << 24);
	}

	odm_set_bb_reg(dm, R_0x82c, MASKDWORD, reg82c);
#endif
}

__iram_odm_func__
void phydm_ccapar_by_rxpath_8710c(
	struct dm_struct *dm)
{
#if 0
	if (dm->cut_version != ODM_CUT_A)
		return;

	if (dm->rx_ant_status == BB_PATH_A || dm->rx_ant_status == BB_PATH_B) {
		/* 838[7:4] = 8 */
		/* 838[11:8] = 7 */
		/* 838[15:12] = 6 */
		/* 838[19:16] = 7 */
		/* 838[23:20] = 7 */
		/* 838[27:24] = 7 */
		odm_set_bb_reg(dm, R_0x838, 0x0ffffff0, 0x777678);
	} else {
		/* 838[7:4] = 3 */
		/* 838[11:8] = 3 */
		/* 838[15:12] = 6 */
		/* 838[19:16] = 6 */
		/* 838[23:20] = 7 */
		/* 838[27:24] = 7 */
		odm_set_bb_reg(dm, R_0x838, 0x0ffffff0, 0x776633);
	}
#endif
}
#endif
__iram_odm_func__
void phydm_rxdfirpar_by_bw_8710c(
	struct dm_struct *dm,
	enum channel_width bandwidth)
{
	odm_set_bb_reg(dm, R_0x864, (BIT(30) | BIT(29)), 0x2);
	odm_set_bb_reg(dm, R_0xc10, (BIT(29) | BIT(28)), 0x3);

	if((bandwidth == CHANNEL_WIDTH_20) || (bandwidth == CHANNEL_WIDTH_10)
		|| (bandwidth == CHANNEL_WIDTH_5)) {
		/* RX DFIR for BW20, BW10 and BW5*/
		odm_set_bb_reg(dm, R_0x954, BIT(19), 0x1);
		odm_set_bb_reg(dm, R_0x954, 0x0ff00000, 0xa3);
	}
	/* PHYDM_DBG(dm, ODM_PHY_CONFIG, "phydm_rxdfirpar_by_bw_8710c\n");*/

}

#if 0
__iram_odm_func__
boolean
phydm_write_txagc_1byte_8710c(
	struct dm_struct *dm,
	u32 power_index,
	enum rf_path path,
	u8 hw_rate)
{
#if (PHYDM_FW_API_FUNC_ENABLE_8710C == 1)
	u32 offset_txagc[2] = {0x1d00, 0x1d80};
	u8 rate_idx = (hw_rate & 0xfc), i;
	u8 rate_offset = (hw_rate & 0x3);
	u32 txagc_content = 0x0;

	/* For debug command only!!!! */

	/* Error handling */
	if (path > RF_PATH_A || hw_rate > 0x53) {
		PHYDM_DBG(dm, ODM_PHY_CONFIG, "[%s]: unsupported path (%d)\n",
			  __func__, path);
		return false;
	}

#if 1
	/* For HW limitation, We can't write TXAGC once a byte. */
	for (i = 0; i < 4; i++) {
		if (i != rate_offset)
			txagc_content = txagc_content | (config_phydm_read_txagc_8710c(dm, path, rate_idx + i) << (i << 3));
		else
			txagc_content = txagc_content | ((power_index & 0x3f) << (i << 3));
	}
	odm_set_bb_reg(dm, (offset_txagc[path] + rate_idx), MASKDWORD, txagc_content);
#else
	odm_write_1byte(dm, (offset_txagc[path] + hw_rate), (power_index & 0x3f));
#endif

	PHYDM_DBG(dm, ODM_PHY_CONFIG,
		  "[%s]: path-%d rate index 0x%x (0x%x) = 0x%x\n", __func__,
		  path, hw_rate, (offset_txagc[path] + hw_rate), power_index);
	return true;
#else
	return false;
#endif
}
#endif

__iram_odm_func__
void phydm_init_hw_info_by_rfe_type_8710c(
	struct dm_struct *dm)
{
#if 0
#if (PHYDM_FW_API_FUNC_ENABLE_8710C == 1)
	dm->is_init_hw_info_by_rfe = false;
	/*
	Let original variable rfe_type to be rfe_type_8710c.
	Varible rfe_type as symbol is used to identify PHY parameter.
	*/
	dm->rfe_type = dm->rfe_type_expand >> 3;

	/*2.4G default rf set with wlg or btg*/
	if (dm->rfe_type_expand == 2 || dm->rfe_type_expand == 4 || dm->rfe_type_expand == 7)
		; //dm->default_rf_set_8710c = SWITCH_TO_BTG;
	else if (dm->rfe_type_expand == 0 || dm->rfe_type_expand == 1 ||
		 dm->rfe_type_expand == 3 || dm->rfe_type_expand == 5 ||
		 dm->rfe_type_expand == 6)
		; //dm->default_rf_set_8710c = SWITCH_TO_WLG;
	else if (dm->rfe_type_expand == 0x22 || dm->rfe_type_expand == 0x24 ||
		 dm->rfe_type_expand == 0x27 || dm->rfe_type_expand == 0x2a ||
		 dm->rfe_type_expand == 0x2c || dm->rfe_type_expand == 0x2f) {
		; //dm->default_rf_set_8710c = SWITCH_TO_BTG;
		odm_cmn_info_init(dm, ODM_CMNINFO_PACKAGE_TYPE, 1);
	} else if (dm->rfe_type_expand == 0x20 || dm->rfe_type_expand == 0x21 ||
		   dm->rfe_type_expand == 0x23 || dm->rfe_type_expand == 0x25 ||
		   dm->rfe_type_expand == 0x26 || dm->rfe_type_expand == 0x28 ||
		   dm->rfe_type_expand == 0x29 || dm->rfe_type_expand == 0x2b ||
		   dm->rfe_type_expand == 0x2d || dm->rfe_type_expand == 0x2e) {
		; //dm->default_rf_set_8710c = SWITCH_TO_WLG;
		odm_cmn_info_init(dm, ODM_CMNINFO_PACKAGE_TYPE, 1);
	}

	if (dm->rfe_type_expand == 3 || dm->rfe_type_expand == 4 ||
	    dm->rfe_type_expand == 0x23 || dm->rfe_type_expand == 0x24 ||
	    dm->rfe_type_expand == 0x2b || dm->rfe_type_expand == 0x2c)
		; //dm->default_ant_num_8710c = SWITCH_TO_ANT2;
	else
		; //dm->default_ant_num_8710c = SWITCH_TO_ANT1;

	dm->is_init_hw_info_by_rfe = true;
/*	PHYDM_DBG(dm, ODM_PHY_CONFIG, "%s: RFE type (%d), rf set (%s)\n",
		__FUNCTION__, dm->rfe_type_expand,
		dm->default_rf_set_8710c == 0 ? "BTG" : "WLG"); */
#endif
#endif
}


/* ======================================================================== */
/* These following functions can be used by driver*/
/*8710C indirect access RF reg 0x18*/
__iram_odm_func__
u32 config_phydm_read_rf_reg_8710c(
	struct dm_struct *dm,
	enum rf_path path,
	u32 reg_addr,
	u32 bit_mask)
{
	u32 value, indirect_readback, offset;
	boolean sipi_indicate;
	u8 cnt=0, i;
	u32 finish_value;
	u8 errorflag = 1;

	/* Error handling.*/
	if (path > RF_PATH_A) {
		PHYDM_DBG(dm, ODM_PHY_CONFIG, "[%s]: unsupported path (%d)\n",
			  __func__, path);
		return INVALID_RF_DATA;
	}

	reg_addr &= 0xff;
	offset = reg_addr;
	value = odm_get_bb_reg(dm, R_0x824, MASKDWORD);
	value = (value & (~bLSSIReadAddress)) | (offset<<23) | bLSSIReadEdge;
	odm_set_bb_reg(dm,R_0x824,MASKDWORD,value & (~bLSSIReadEdge));		

	value = odm_get_bb_reg(dm, R_0x824, MASKDWORD);
	odm_set_bb_reg(dm,R_0x824,MASKDWORD,value & (~bLSSIReadEdge));	
	odm_set_bb_reg(dm,R_0x824,MASKDWORD,value | bLSSIReadEdge);

	for(i=0;i<2;i++)
		ODM_delay_us(MAX_STALL_TIME);	
	ODM_delay_us(10);

	sipi_indicate = odm_get_bb_reg(dm, R_0x820, BIT(8));

	bit_mask &= RFREGOFFSETMASK;

	/* Read RF register indirectly */
	do{
		ODM_delay_us(10);
		ODM_delay_us(50);
		ODM_delay_us(50);
		ODM_delay_us(10);
		
		finish_value = odm_get_bb_reg(dm,R_0x8b8, 0x00100000);
		if(finish_value)
		{
			errorflag = 0;
			break;
			//PHYDM_DBG(dm, ODM_PHY_CONFIG, "phy_RFSerialRead, 
				//BB(%x) = %x,Cnt=%x\n",__func__, path);
		}

	
	}while(cnt++ < 0x5);

	if(errorflag == 0)
	{
		if(sipi_indicate)/*PI */
		{
			indirect_readback=odm_get_bb_reg(dm,R_0x8b8,bit_mask);
		}	
		else /*SI*/
		{
			indirect_readback=odm_get_bb_reg(dm,R_0x8a0,bit_mask);
		}	
	}
	else
	{
		PHYDM_DBG(dm, ODM_PHY_CONFIG,
		  "[%s]: RF-%d 0x%x= 0x%x, bit mask = 0x%x\n", __func__, path,
		  reg_addr,indirect_readback, bit_mask);
	}
	
	PHYDM_DBG(dm, ODM_PHY_CONFIG,
		  "[%s]: RF-%d 0x%x= 0x%x, bit mask = 0x%x\n", __func__, path,
		  reg_addr,indirect_readback, bit_mask);

	return indirect_readback;
}

__iram_odm_func__
boolean
config_phydm_write_rf_reg_8710c(
	struct dm_struct *dm,
	enum rf_path path,
	u32 reg_addr,
	u32 bit_mask,
	u32 data)
{
	u32 data_and_addr = 0, data_original = 0;
	u32 offset_write_rf[1] = {0x840};
	u8 bit_shift;

	/* Error handling.*/
	if (path > RF_PATH_A) {
		PHYDM_DBG(dm, ODM_PHY_CONFIG, "[%s]: unsupported path (%d)\n",
			  __func__, path);
		return false;
	}

	/* Read RF register content first */
	reg_addr &= 0xff;
	bit_mask = bit_mask & RFREGOFFSETMASK;

	if (bit_mask != RFREGOFFSETMASK) {
		data_original = config_phydm_read_rf_reg_8710c(dm, path, 
							reg_addr, 
							RFREGOFFSETMASK);

		/* Error handling. RF is disabled */
		if (config_phydm_read_rf_check_8710c(data_original) == false) {
			PHYDM_DBG(dm, ODM_PHY_CONFIG,
				  "[%s]: Write fail, RF is disable\n",
				  __func__);
			return false;
		}

		/* check bit mask */
		if (bit_mask != 0xfffff) {
			for (bit_shift = 0; bit_shift <= 19; bit_shift++) {
				if (((bit_mask >> bit_shift) & 0x1) == 1)
					break;
			}
			data = ((data_original) & (~bit_mask)) |
				(data << bit_shift);
		}
	}

	/* Put write addr in [27:20]  and write data in [19:00] */
	data_and_addr=((reg_addr << 20) | (data & 0x000fffff)) & 0x0fffffff;
//printf("%s %d data_and_addr:0x%08x\r\n", __func__, __LINE__, data_and_addr);
	/* Write operation */
	odm_set_bb_reg(dm, offset_write_rf[path], MASKDWORD, data_and_addr);
	PHYDM_DBG(dm, ODM_PHY_CONFIG,
		  "[%s]: RF-%d 0x%x = 0x%x (original: 0x%x), bit mask = 0x%x\n",
		  __func__, path, reg_addr, data, data_original, bit_mask);
	return true;
}

__iram_odm_func__
boolean
config_phydm_write_txagc_8710c(
	struct dm_struct *dm,
	u32 power_index,
	enum rf_path path,
	u8 hw_rate)
{
	/*u8	read_back_data; */
	/*for 97F workaroud*/
	/* Input need to be HW rate index, not driver rate index!!!! */

	if (dm->is_disable_phy_api) {
		PHYDM_DBG(dm, ODM_PHY_CONFIG,
			  "%s: disable PHY API for debug!!\n", __func__);
		return true;
	}

	/* Error handling */
	if (path > RF_PATH_A || hw_rate > ODM_RATEMCS7) {
		PHYDM_DBG(dm, ODM_PHY_CONFIG, "%s: unsupported path (%d)\n",
			  __func__, path);
		return false;
	}

	switch (hw_rate) {
	case ODM_RATE1M:	
		odm_set_bb_reg(dm, R_0xe08,0x0000ff00, power_index);
		break;
	case ODM_RATE2M:
		odm_set_bb_reg(dm, R_0x86c,0x0000ff00, power_index);
		break;
	case ODM_RATE5_5M:
		odm_set_bb_reg(dm, R_0x86c,0x00ff0000, power_index);
		break;
	case ODM_RATE11M:
		odm_set_bb_reg(dm, R_0x86c,0xff000000, power_index);
		break;

	case ODM_RATE6M:
		odm_set_bb_reg(dm, R_0xe00,0x000000ff, power_index);
		break;
	case ODM_RATE9M:
		odm_set_bb_reg(dm, R_0xe00,0x0000ff00, power_index);
		break;
	case ODM_RATE12M:
		odm_set_bb_reg(dm, R_0xe00,0x00ff0000, power_index);
		break;
	case ODM_RATE18M:
		odm_set_bb_reg(dm, R_0xe00,0xff000000, power_index);
		break;
	case ODM_RATE24M:
		odm_set_bb_reg(dm, R_0xe04,0x000000ff, power_index);
		break;
	case ODM_RATE36M:
		odm_set_bb_reg(dm, R_0xe04,0x0000ff00, power_index);
		break;
	case ODM_RATE48M:
		odm_set_bb_reg(dm, R_0xe04,0x00ff0000, power_index);
		break;
	case ODM_RATE54M:
		odm_set_bb_reg(dm, R_0xe04,0xff000000, power_index);
		break;

	case ODM_RATEMCS0:
		odm_set_bb_reg(dm, R_0xe10,0x000000ff, power_index);
		break;
	case ODM_RATEMCS1:
		odm_set_bb_reg(dm, R_0xe10,0x0000ff00, power_index);
		break;
	case ODM_RATEMCS2:
		odm_set_bb_reg(dm, R_0xe10,0x00ff0000, power_index);
		break;
	case ODM_RATEMCS3:
		odm_set_bb_reg(dm, R_0xe10,0xff000000, power_index);
		break;
	case ODM_RATEMCS4:
		odm_set_bb_reg(dm, R_0xe14,0x000000ff, power_index);
		break;
	case ODM_RATEMCS5:
		odm_set_bb_reg(dm, R_0xe14,0x0000ff00, power_index);
		break;
	case ODM_RATEMCS6:
		odm_set_bb_reg(dm, R_0xe14,0x00ff0000, power_index);
		break;
	case ODM_RATEMCS7:
		odm_set_bb_reg(dm, R_0xe14,0xff000000, power_index);
		break;

	default:
		PHYDM_DBG(dm, ODM_PHY_CONFIG, "Invalid HWrate!\n");
		break;
	}

	PHYDM_DBG(dm, ODM_PHY_CONFIG, "%s: path-%d rate index 0x%x = 0x%x\n",
		  __func__, path, hw_rate, power_index);
	return true;
}


__iram_odm_func__
u8 config_phydm_read_txagc_8710c(
	struct dm_struct *dm,
	enum rf_path path,
	u8 hw_rate)
{
	u8 read_back_data = 0;

	/* Input need to be HW rate index, not driver rate index!!!! */

	/* Error handling */
	if (path > RF_PATH_A || hw_rate > ODM_RATEMCS7) {
		PHYDM_DBG(dm, ODM_PHY_CONFIG, "%s: unsupported path (%d)\n",
			  __func__, path);
		return INVALID_TXAGC_DATA;
	}

	switch (hw_rate) {
	case ODM_RATE1M:
		read_back_data =
		(u8)odm_get_bb_reg(dm, R_0xe08,0x0000ff00);
		break;
	case ODM_RATE2M:
		read_back_data =
		(u8)odm_get_bb_reg(dm, R_0x86c,0x0000ff00);
		break;
	case ODM_RATE5_5M:
		read_back_data =
		(u8)odm_get_bb_reg(dm, R_0x86c,0x00ff0000);
		break;
	case ODM_RATE11M:
		read_back_data =
		(u8)odm_get_bb_reg(dm, R_0x86c,0xff000000);
		break;

	case ODM_RATE6M:
		read_back_data = 
		(u8)odm_get_bb_reg(dm, R_0xe00,0x000000ff);
		break;
	case ODM_RATE9M:
		read_back_data = 
		(u8)odm_get_bb_reg(dm, R_0xe00,0x0000ff00);
		break;
	case ODM_RATE12M:
		read_back_data = 
		(u8)odm_get_bb_reg(dm, R_0xe00,0x00ff0000);
		break;
	case ODM_RATE18M:
		read_back_data =
		(u8)odm_get_bb_reg(dm, R_0xe00,0xff000000);
		break;
	case ODM_RATE24M:
		read_back_data = 
		(u8)odm_get_bb_reg(dm, R_0xe04,0x000000ff);
		break;
	case ODM_RATE36M:
		read_back_data =
		(u8)odm_get_bb_reg(dm, R_0xe04,0x0000ff00);
		break;
	case ODM_RATE48M:
		read_back_data =
		(u8)odm_get_bb_reg(dm, R_0xe04,0x00ff0000);
		break;
	case ODM_RATE54M:
		read_back_data = 
		(u8)odm_get_bb_reg(dm, R_0xe04,0xff000000);
		break;
	case ODM_RATEMCS0:
		read_back_data = 
		(u8)odm_get_bb_reg(dm,R_0xe10,0x000000ff);
		break;
	case ODM_RATEMCS1:
		read_back_data =
		(u8)odm_get_bb_reg(dm,R_0xe10,0x0000ff00);
		break;
	case ODM_RATEMCS2:
		read_back_data = 
		(u8)odm_get_bb_reg(dm,R_0xe10,0x00ff0000);
		break;
	case ODM_RATEMCS3:
		read_back_data = 
		(u8)odm_get_bb_reg(dm,R_0xe10,0xff000000);
		break;
	case ODM_RATEMCS4:
		read_back_data = 
		(u8)odm_get_bb_reg(dm,R_0xe14,0x000000ff);
		break;
	case ODM_RATEMCS5:
		read_back_data = 
		(u8)odm_get_bb_reg(dm,R_0xe14,0x0000ff00);
		break;
	case ODM_RATEMCS6:
		read_back_data = 
		(u8)odm_get_bb_reg(dm,R_0xe14,0x00ff0000);
		break;
	case ODM_RATEMCS7:
		read_back_data = 
		(u8)odm_get_bb_reg(dm,R_0xe14,0xff000000);
		break;

	default:
		PHYDM_DBG(dm, ODM_PHY_CONFIG, "Invalid HWrate!\n");
		break;
	}

	PHYDM_DBG(dm, ODM_PHY_CONFIG, "%s: path-%d rate index 0x%x = 0x%x\n",
		  __func__, path, hw_rate, read_back_data);
	return read_back_data;
}
#if 0
void phydm_dynamic_spur_det_eliminate_8710c(struct dm_struct *dm)
{
#if 0
	u32	freq[11] = {0xFDCD, 0xFD4D, 0xFCCD, 0xFC4D, 0xFFCD,
	 0xFF4D, 0xFECD, 0xFE4D, 0xFDCD, 0xFCCD, 0xFF9A};
	/* {chnl 3, 4, 5, 6, 7, 8, 9, 10, 11,13,14}*/
	u8	idx = 0;
	BOOLEAN	b_donotch = FALSE;
	u8	initial_gain;
	u32	wlan_channel, cur_ch;
	u32	wlan_bw;
#endif
	PHYDM_DBG(dm, ODM_COMP_API,
		  "phydm_dynamic_spur_det_eliminate:channel = %d, band_width = %d\n",
		  *dm->channel, *dm->band_width);
	/*ADC clk 160M to 80M*/
	if (*dm->band_width == CHANNEL_WIDTH_20) {
		if (*dm->channel == 1) {
			/* ADC clock = 80M clock for BW20*/
			odm_set_bb_reg(dm, R_0x800,
				       (BIT(10) | BIT(9) | BIT(8)), 0x4);
			/* r_adc_upd0 0xce4[29:28] = 2'b01*/
			odm_set_bb_reg(dm, R_0xce4, (BIT(29) | BIT(28)), 0x1);
			/* r_tap_upd 0x864[30:29] = 2'b01*/
			odm_set_bb_reg(dm, R_0x864, (BIT(30) | BIT(29)), 0x1);
			/* Down_factor=4 0xc10[29:28]=0x2*/
			odm_set_bb_reg(dm, R_0xc10, (BIT(29) | BIT(28)), 0x2);
			/* Disable DFIR stage 1 0x954[19]=0*/
			odm_set_bb_reg(dm, R_0x954, BIT(19), 0x0);
			/* DFIR stage0=3 0x54[23:20]=0x3*/
			odm_set_bb_reg(dm, R_0x954, (BIT(23) | BIT(22) | BIT(21) | BIT(20)), 0x3);
		} else {
			/* ADC clock = 160M clock for BW20*/
			odm_set_bb_reg(dm, R_0x800, (BIT(10) | BIT(9) | BIT(8)), 0x5);
			/* r_adc_upd0 0xce4[29:28] = 2'b01*/
			odm_set_bb_reg(dm, R_0xce4, (BIT(29) | BIT(28)), 0x2);
			/* r_tap_upd 0x864[30:29] = 2'b01*/
			odm_set_bb_reg(dm, R_0x864, (BIT(30) | BIT(29)), 0x2);
			/* Down_factor=4 0xc10[29:28]=0x2*/
			odm_set_bb_reg(dm, R_0xc10, (BIT(29) | BIT(28)), 0x2);
			/* Disable DFIR stage 1 0x954[19]=0*/
			odm_set_bb_reg(dm, R_0x954, BIT(19), 0x0);
			/* DFIR stage0=3, stage1=10 0x954[23:20]=0x3 0x948[27:24]=0xa*/
			odm_set_bb_reg(dm, R_0x954, (BIT(23) | BIT(22) | BIT(21) | BIT(20)), 0x3);
			odm_set_bb_reg(dm, R_0x954, (BIT(27) | BIT(26) | BIT(25) | BIT(24)), 0xa);
		}
	}
#if 0

	if (*dm->channel == 3)
		idx = 0;
	else if (*dm->channel == 4)
		idx = 1;
	else if (*dm->channel == 5)
		idx = 2;
	else if (*dm->channel == 6)
		idx = 3;
	else if (*dm->channel == 7)
		idx = 4;
	else if (*dm->channel == 8)
		idx = 5;
	else if (*dm->channel == 9)
		idx = 6;
	else if (*dm->channel == 10)
		idx = 7;
	else if (*dm->channel == 11)
		idx = 8;
	else if (*dm->channel == 13)
		idx = 9;
	else if (*dm->channel == 14)
		idx = 10;
	else
		idx = 15;

	/*If wlan at S1 (both HW control & SW control) */
	/*and current channel=5,6,7,8,13,14*/
	if (idx <= 10) {
		initial_gain = (u8)(odm_get_bb_reg(dm, R_0xc50,
						   MASKBYTE0) & 0x7f);
		odm_write_dig(dm, 0x30);
		odm_set_bb_reg(dm, R_0x88c, (BIT(21) | BIT(20) | BIT(19) |
			       BIT(18)), 0xF);/*disable 3-wire*/
		odm_set_bb_reg(dm, R_0x804, (BIT(5) | BIT(4)), 0x1);
		/* PSD use PATHB*/
		odm_set_bb_reg(dm, R_0x808, MASKDWORD, freq[idx]);
		/* Setup PSD*/
		odm_set_bb_reg(dm, R_0x808, MASKDWORD, 0x400000 | freq[idx]);
		/* Start PSD*/

		delay_ms(30);
		if (odm_get_bb_reg(dm, R_0x8b4, MASKDWORD) >= 0x16)
			b_donotch = TRUE;
		odm_set_bb_reg(dm, R_0x808, MASKDWORD, freq[idx]);
		/* turn off PSD*/
		odm_set_bb_reg(dm, R_0x88c, (BIT(21) | BIT(20) | BIT(19) |
			       BIT(18)), 0x0);/* enable 3-wire*/
		odm_write_dig(dm, initial_gain);
	}
#endif

	if (dm->rfe_type == 5 && *dm->band_width == CHANNEL_WIDTH_20) {
		/*USB QFN40 iLNA iPA STA,BW 20M*/
		switch (*dm->channel) {
		case 5:
			odm_set_bb_reg(dm, R_0xd40, MASKDWORD, 0x06000000);
			odm_set_bb_reg(dm, R_0xd44, MASKDWORD, 0x00000000);
			odm_set_bb_reg(dm, R_0xd48, MASKDWORD, 0x00000000);
			odm_set_bb_reg(dm, R_0xd4c, MASKDWORD, 0x00000000);
			odm_set_bb_reg(dm, R_0xd2c, BIT(28), 0x1);
			/*enable CSI mask*/
			break;
		case 6:
			odm_set_bb_reg(dm, R_0xd40, MASKDWORD, 0x00000600);
			odm_set_bb_reg(dm, R_0xd44, MASKDWORD, 0x00000000);
			odm_set_bb_reg(dm, R_0xd48, MASKDWORD, 0x00000000);
			odm_set_bb_reg(dm, R_0xd4c, MASKDWORD, 0x00000000);
			odm_set_bb_reg(dm, R_0xd2c, BIT(28), 0x1);
			/*enable CSI mask*/
			break;
		case 7:
			odm_set_bb_reg(dm, R_0xd40, MASKDWORD, 0x00000000);
			odm_set_bb_reg(dm, R_0xd44, MASKDWORD, 0x00000000);
			odm_set_bb_reg(dm, R_0xd48, MASKDWORD, 0x00000000);
			odm_set_bb_reg(dm, R_0xd4c, MASKDWORD, 0x06000000);
			odm_set_bb_reg(dm, R_0xd2c, BIT(28), 0x1);
			/*enable CSI mask*/
			break;
		case 8:
			odm_set_bb_reg(dm, R_0xd40, MASKDWORD, 0x00000000);
			odm_set_bb_reg(dm, R_0xd44, MASKDWORD, 0x00000000);
			odm_set_bb_reg(dm, R_0xd48, MASKDWORD, 0x00000000);
			odm_set_bb_reg(dm, R_0xd4c, MASKDWORD, 0x00000600);
			odm_set_bb_reg(dm, R_0xd2c, BIT(28), 0x1);
			/*enable CSI mask*/
			break;
		case 13:
			odm_set_bb_reg(dm, R_0xd40, MASKDWORD, 0x06000000);
			odm_set_bb_reg(dm, R_0xd44, MASKDWORD, 0x00000000);
			odm_set_bb_reg(dm, R_0xd48, MASKDWORD, 0x00000000);
			odm_set_bb_reg(dm, R_0xd4c, MASKDWORD, 0x00000000);
			odm_set_bb_reg(dm, R_0xd2c, BIT(28), 0x1);
			/*enable CSI mask*/
			break;
		case 14:
			odm_set_bb_reg(dm, R_0xd40, MASKDWORD, 0x00000000);
			odm_set_bb_reg(dm, R_0xd44, MASKDWORD, 0x00000000);
			odm_set_bb_reg(dm, R_0xd48, MASKDWORD, 0x00000000);
			odm_set_bb_reg(dm, R_0xd4c, MASKDWORD, 0x00080000);
			odm_set_bb_reg(dm, R_0xd2c, BIT(28), 0x1);
			/*enable CSI mask*/
			break;
		default:
			odm_set_bb_reg(dm, R_0xd2c, BIT(28), 0x0);
			/*disable CSI mask function*/
			break;
		}
	} else if ((dm->rfe_type == 5) &&
		   (*dm->band_width == CHANNEL_WIDTH_40)) {
	/*USB QFN40 iLNA iPA STA,BW 40M*/
		switch (*dm->channel) {
		case 3:
			odm_set_bb_reg(dm, R_0xd40, MASKDWORD, 0x00000000);
			odm_set_bb_reg(dm, R_0xd44, MASKDWORD, 0x06000000);
			odm_set_bb_reg(dm, R_0xd48, MASKDWORD, 0x00000000);
			odm_set_bb_reg(dm, R_0xd4c, MASKDWORD, 0x00000000);
			odm_set_bb_reg(dm, R_0xd2c, BIT(28), 0x1);
			/*enable CSI mask*/
			break;
		case 4:
			odm_set_bb_reg(dm, R_0xd40, MASKDWORD, 0x00000000);
			odm_set_bb_reg(dm, R_0xd44, MASKDWORD, 0x00000600);
			odm_set_bb_reg(dm, R_0xd48, MASKDWORD, 0x00000000);
			odm_set_bb_reg(dm, R_0xd4c, MASKDWORD, 0x00000000);
			odm_set_bb_reg(dm, R_0xd2c, BIT(28), 0x1);
			/*enable CSI mask*/
			break;
		case 5:
			odm_set_bb_reg(dm, R_0xd40, MASKDWORD, 0x06000000);
			odm_set_bb_reg(dm, R_0xd44, MASKDWORD, 0x00000000);
			odm_set_bb_reg(dm, R_0xd48, MASKDWORD, 0x00000000);
			odm_set_bb_reg(dm, R_0xd4c, MASKDWORD, 0x00000000);
			odm_set_bb_reg(dm, R_0xd2c, BIT(28), 0x1);
			/*enable CSI mask*/
			break;
		case 6:
			odm_set_bb_reg(dm, R_0xd40, MASKDWORD, 0x00000600);
			odm_set_bb_reg(dm, R_0xd44, MASKDWORD, 0x00000000);
			odm_set_bb_reg(dm, R_0xd48, MASKDWORD, 0x00000000);
			odm_set_bb_reg(dm, R_0xd4c, MASKDWORD, 0x00000000);
			odm_set_bb_reg(dm, R_0xd2c, BIT(28), 0x1);
			/*enable CSI mask*/
			break;
		case 7:
			odm_set_bb_reg(dm, R_0xd40, MASKDWORD, 0x00000000);
			odm_set_bb_reg(dm, R_0xd44, MASKDWORD, 0x00000000);
			odm_set_bb_reg(dm, R_0xd48, MASKDWORD, 0x00000000);
			odm_set_bb_reg(dm, R_0xd4c, MASKDWORD, 0x04000000);
			odm_set_bb_reg(dm, R_0xd2c, BIT(28), 0x1);
			/*enable CSI mask*/
			break;
		case 8:
			odm_set_bb_reg(dm, R_0xd40, MASKDWORD, 0x00000000);
			odm_set_bb_reg(dm, R_0xd44, MASKDWORD, 0x00000000);
			odm_set_bb_reg(dm, R_0xd48, MASKDWORD, 0x00000000);
			odm_set_bb_reg(dm, R_0xd4c, MASKDWORD, 0x00000600);
			odm_set_bb_reg(dm, R_0xd2c, BIT(28), 0x1);
			/*enable CSI mask*/
			break;
		case 9:
			odm_set_bb_reg(dm, R_0xd40, MASKDWORD, 0x00000000);
			odm_set_bb_reg(dm, R_0xd44, MASKDWORD, 0x00000000);
			odm_set_bb_reg(dm, R_0xd48, MASKDWORD, 0x06000000);
			odm_set_bb_reg(dm, R_0xd4c, MASKDWORD, 0x00000000);
			odm_set_bb_reg(dm, R_0xd2c, BIT(28), 0x1);
			/*enable CSI mask*/
			break;
		case 10:
			odm_set_bb_reg(dm, R_0xd40, MASKDWORD, 0x00000000);
			odm_set_bb_reg(dm, R_0xd44, MASKDWORD, 0x00000000);
			odm_set_bb_reg(dm, R_0xd48, MASKDWORD, 0x00000600);
			odm_set_bb_reg(dm, R_0xd4c, MASKDWORD, 0x00000000);
			odm_set_bb_reg(dm, R_0xd2c, BIT(28), 0x1);
			/*enable CSI mask*/
			break;
		case 11:
			odm_set_bb_reg(dm, R_0xd40, MASKDWORD, 0x00000000);
			odm_set_bb_reg(dm, R_0xd44, MASKDWORD, 0x06000000);
			odm_set_bb_reg(dm, R_0xd48, MASKDWORD, 0x00000000);
			odm_set_bb_reg(dm, R_0xd4c, MASKDWORD, 0x00000000);
			odm_set_bb_reg(dm, R_0xd2c, BIT(28), 0x1);
			/*enable CSI mask*/
			break;
		default:
			odm_set_bb_reg(dm, R_0xd2c, BIT(28), 0x0);
			/*disable CSI mask function*/
			break;
		}
	} else if ((dm->rfe_type == 0 || dm->rfe_type == 1 ||
		   dm->rfe_type == 3 || dm->rfe_type == 7 ||
		   dm->rfe_type == 8) &&
		   (*dm->band_width == CHANNEL_WIDTH_20)) {
		   /*PCIE QFN32 iLNA iPA STA,BW 20M*/
		switch (*dm->channel) {
		case 5:
			odm_set_bb_reg(dm, R_0xd40, MASKDWORD, 0x04000000);
			odm_set_bb_reg(dm, R_0xd44, MASKDWORD, 0x00000000);
			odm_set_bb_reg(dm, R_0xd48, MASKDWORD, 0x00000000);
			odm_set_bb_reg(dm, R_0xd4c, MASKDWORD, 0x00000000);
			odm_set_bb_reg(dm, R_0xd2c, BIT(28), 0x1);
			/*enable CSI mask*/
			break;
		case 6:
			odm_set_bb_reg(dm, R_0xd40, MASKDWORD, 0x00000400);
			odm_set_bb_reg(dm, R_0xd44, MASKDWORD, 0x00000000);
			odm_set_bb_reg(dm, R_0xd48, MASKDWORD, 0x00000000);
			odm_set_bb_reg(dm, R_0xd4c, MASKDWORD, 0x00000000);
			odm_set_bb_reg(dm, R_0xd2c, BIT(28), 0x1);
			/*enable CSI mask*/
			break;
		case 7:
			odm_set_bb_reg(dm, R_0xd40, MASKDWORD, 0x00000000);
			odm_set_bb_reg(dm, R_0xd44, MASKDWORD, 0x00000000);
			odm_set_bb_reg(dm, R_0xd48, MASKDWORD, 0x00000000);
			odm_set_bb_reg(dm, R_0xd4c, MASKDWORD, 0x06000000);
			odm_set_bb_reg(dm, R_0xd2c, BIT(28), 0x1);
			/*enable CSI mask*/
			break;
		case 8:
			odm_set_bb_reg(dm, R_0xd40, MASKDWORD, 0x00000000);
			odm_set_bb_reg(dm, R_0xd44, MASKDWORD, 0x00000000);
			odm_set_bb_reg(dm, R_0xd48, MASKDWORD, 0x00000000);
			odm_set_bb_reg(dm, R_0xd4c, MASKDWORD, 0x00000600);
			odm_set_bb_reg(dm, R_0xd2c, BIT(28), 0x1);
			/*enable CSI mask*/
			break;
		case 13:
			odm_set_bb_reg(dm, R_0xd40, MASKDWORD, 0x04000000);
			odm_set_bb_reg(dm, R_0xd44, MASKDWORD, 0x00000000);
			odm_set_bb_reg(dm, R_0xd48, MASKDWORD, 0x00000000);
			odm_set_bb_reg(dm, R_0xd4c, MASKDWORD, 0x00000000);
			odm_set_bb_reg(dm, R_0xd2c, BIT(28), 0x1);
			/*enable CSI mask*/
			break;
		case 14:
			odm_set_bb_reg(dm, R_0xd40, MASKDWORD, 0x00000000);
			odm_set_bb_reg(dm, R_0xd44, MASKDWORD, 0x00000000);
			odm_set_bb_reg(dm, R_0xd48, MASKDWORD, 0x00000000);
			odm_set_bb_reg(dm, R_0xd4c, MASKDWORD, 0x00080000);
			odm_set_bb_reg(dm, R_0xd2c, BIT(28), 0x1);
			/*enable CSI mask*/
			break;
		default:
			odm_set_bb_reg(dm, R_0xd2c, BIT(28), 0x0);
			/*disable CSI mask function*/
			break;
		}
	} else if ((dm->rfe_type == 0 || dm->rfe_type == 1 ||
		   dm->rfe_type == 3 || dm->rfe_type == 7 ||
		   dm->rfe_type == 8) &&
		   (*dm->band_width == CHANNEL_WIDTH_40)) {
		   /*PCIE QFN32 iLNA iPA STA,BW 40M*/
		switch (*dm->channel) {
		case 3:
			odm_set_bb_reg(dm, R_0xd40, MASKDWORD, 0x00000000);
			odm_set_bb_reg(dm, R_0xd44, MASKDWORD, 0x04000000);
			odm_set_bb_reg(dm, R_0xd48, MASKDWORD, 0x00000000);
			odm_set_bb_reg(dm, R_0xd4c, MASKDWORD, 0x00000000);
			odm_set_bb_reg(dm, R_0xd2c, BIT(28), 0x1);
			/*enable CSI mask*/
			break;
		case 4:
			odm_set_bb_reg(dm, R_0xd40, MASKDWORD, 0x00000000);
			odm_set_bb_reg(dm, R_0xd44, MASKDWORD, 0x00000400);
			odm_set_bb_reg(dm, R_0xd48, MASKDWORD, 0x00000000);
			odm_set_bb_reg(dm, R_0xd4c, MASKDWORD, 0x00000000);
			odm_set_bb_reg(dm, R_0xd2c, BIT(28), 0x1);
			/*enable CSI mask*/
			break;
		case 5:
			odm_set_bb_reg(dm, R_0xd40, MASKDWORD, 0x04000000);
			odm_set_bb_reg(dm, R_0xd44, MASKDWORD, 0x00000000);
			odm_set_bb_reg(dm, R_0xd48, MASKDWORD, 0x00000000);
			odm_set_bb_reg(dm, R_0xd4c, MASKDWORD, 0x00000000);
			odm_set_bb_reg(dm, R_0xd2c, BIT(28), 0x1);
			/*enable CSI mask*/
			break;
		case 6:
			odm_set_bb_reg(dm, R_0xd40, MASKDWORD, 0x00000400);
			odm_set_bb_reg(dm, R_0xd44, MASKDWORD, 0x00000000);
			odm_set_bb_reg(dm, R_0xd48, MASKDWORD, 0x00000000);
			odm_set_bb_reg(dm, R_0xd4c, MASKDWORD, 0x00000000);
			odm_set_bb_reg(dm, R_0xd2c, BIT(28), 0x1);
			/*enable CSI mask*/
			break;
		case 7:
			odm_set_bb_reg(dm, R_0xd40, MASKDWORD, 0x00000000);
			odm_set_bb_reg(dm, R_0xd44, MASKDWORD, 0x00000000);
			odm_set_bb_reg(dm, R_0xd48, MASKDWORD, 0x00000000);
			odm_set_bb_reg(dm, R_0xd4c, MASKDWORD, 0x04000000);
			odm_set_bb_reg(dm, R_0xd2c, BIT(28), 0x1);
			/*enable CSI mask*/
			break;
		case 8:
			odm_set_bb_reg(dm, R_0xd40, MASKDWORD, 0x00000000);
			odm_set_bb_reg(dm, R_0xd44, MASKDWORD, 0x00000000);
			odm_set_bb_reg(dm, R_0xd48, MASKDWORD, 0x00000000);
			odm_set_bb_reg(dm, R_0xd4c, MASKDWORD, 0x00000600);
			odm_set_bb_reg(dm, R_0xd2c, BIT(28), 0x1);
			/*enable CSI mask*/
			break;
		case 9:
			odm_set_bb_reg(dm, R_0xd40, MASKDWORD, 0x00000000);
			odm_set_bb_reg(dm, R_0xd44, MASKDWORD, 0x00000000);
			odm_set_bb_reg(dm, R_0xd48, MASKDWORD, 0x04000000);
			odm_set_bb_reg(dm, R_0xd4c, MASKDWORD, 0x00000000);
			odm_set_bb_reg(dm, R_0xd2c, BIT(28), 0x1);
			/*enable CSI mask*/
			break;
		case 10:
			odm_set_bb_reg(dm, R_0xd40, MASKDWORD, 0x00000000);
			odm_set_bb_reg(dm, R_0xd44, MASKDWORD, 0x00000000);
			odm_set_bb_reg(dm, R_0xd48, MASKDWORD, 0x00000600);
			odm_set_bb_reg(dm, R_0xd4c, MASKDWORD, 0x00000000);
			odm_set_bb_reg(dm, R_0xd2c, BIT(28), 0x1);
			/*enable CSI mask*/
			break;
		case 11:
			odm_set_bb_reg(dm, R_0xd40, MASKDWORD, 0x00000000);
			odm_set_bb_reg(dm, R_0xd44, MASKDWORD, 0x04000000);
			odm_set_bb_reg(dm, R_0xd48, MASKDWORD, 0x00000000);
			odm_set_bb_reg(dm, R_0xd4c, MASKDWORD, 0x00000000);
			odm_set_bb_reg(dm, R_0xd2c, BIT(28), 0x1);
			/*enable CSI mask*/
			break;
		default:
			odm_set_bb_reg(dm, R_0xd2c, BIT(28), 0x0);
			/*disable CSI mask function*/
			break;
		}
	}
}
#endif

__iram_odm_func__
boolean
config_phydm_switch_channel_8710c(
	struct dm_struct *dm,
	u8 central_ch)
{
	struct phydm_dig_struct *dig_t = &dm->dm_dig_table;
	u32 rf_reg18 = 0;
	u32 rf_regdf = 0;
	//u32 rf_reg51 = 0;
	//u32 rf_reg52 = 0;
	boolean rf_reg_status = true;
	boolean rf_reg_status_df = true;
	//boolean rf_reg_status_51 = true;
	//boolean rf_reg_status_52 = true;

	PHYDM_DBG(dm, ODM_PHY_CONFIG, "[%s]====================>\n", __func__);

	if (dm->is_disable_phy_api) {
		PHYDM_DBG(dm, ODM_PHY_CONFIG,
			  "[%s]: disable PHY API for debug!!\n", __func__);
		return true;
	}

	central_ch_8710c = central_ch;
	rf_reg18 = config_phydm_read_rf_reg_8710c(dm, RF_PATH_A, ODM_REG_CHNBW_11N, RFREGOFFSETMASK);
	rf_reg_status = rf_reg_status & config_phydm_read_rf_check_8710c(rf_reg18);

	rf_regdf = config_phydm_read_rf_reg_8710c(dm, RF_PATH_A, ODM_REF_RF_DF_11N, RFREGOFFSETMASK);
	rf_reg_status_df = rf_reg_status_df & config_phydm_read_rf_check_8710c(rf_regdf);

	/*rf_reg51 = config_phydm_read_rf_reg_8710c(dm, RF_PATH_A, ODM_RED_RF_51_11N, RFREGOFFSETMASK);
	rf_reg_status_51 = rf_reg_status_51 & config_phydm_read_rf_check_8710c(rf_reg51);

	rf_reg52 = config_phydm_read_rf_reg_8710c(dm, RF_PATH_A, ODM_RED_RF_52_11N, RFREGOFFSETMASK);
	rf_reg_status_52 = rf_reg_status_52 & config_phydm_read_rf_check_8710c(rf_reg52);*/

	/* Switch band and channel */
	if (central_ch <= 14) {
		/* 2.4G */

		/* 1. RF band and channel*/
		rf_reg18 = (rf_reg18 & (~(BIT(19) | BIT(18) | MASKBYTE0)));
		rf_reg18 = (rf_reg18 | central_ch);

		//rf_regdf = (rf_regdf & (~(BIT(2))));
		if(!(*dm->mp_mode))
		{
			if((central_ch >= 2)&&(central_ch <= 10))
			{
				rf_regdf = (rf_regdf | BIT(2));/*1*/
				//rf_reg51 = 0xAF7F3;
				//rf_reg52 = 0x2A180;
				
			}
			else
			{
				rf_regdf = (rf_regdf &(~(BIT(2))));/*0*/
			}
		}
		/* 2. AGC table selection */
		odm_set_bb_reg(dm, R_0x950, 0x1c000000, 0x0);
		dig_t->agc_table_idx = 0x0;

		/* 3. Set central frequency for clock offset tracking */
		odm_set_bb_reg(dm, 0xd2c, 0x00006000, 0x0);

		/* CCK TX filter parameters */
		if (central_ch == 14) {
			odm_set_bb_reg(dm, R_0xa20, MASKDWORD, 0xe82c0001);
			odm_set_bb_reg(dm, R_0xa24, MASKDWORD, 0x0000b81c);
			odm_set_bb_reg(dm, R_0xa28, MASKLWORD, 0x0000);
			odm_set_bb_reg(dm, R_0xaac, MASKDWORD, 0x00003667);
		} /*else if (central_ch == 13){
			odm_set_bb_reg(dm, R_0xa20, MASKDWORD, 0xf8fe0001);
			odm_set_bb_reg(dm, R_0xa24, MASKDWORD, 0x64b80c1c);
			odm_set_bb_reg(dm, R_0xa28, MASKLWORD, 0x8810);
			odm_set_bb_reg(dm, R_0xaac, MASKDWORD, 0x01235667);
		} */else {
			odm_set_bb_reg(dm, R_0xa20, MASKDWORD, 0xe82c0001);
			odm_set_bb_reg(dm, R_0xa24, MASKDWORD, 0x64b80c1c);
			odm_set_bb_reg(dm, R_0xa28, MASKLWORD, 0x8810);
			odm_set_bb_reg(dm, R_0xaac, MASKDWORD, 0x01235667);
		}

	} 
	else {
		PHYDM_DBG(dm, ODM_PHY_CONFIG,
			  "[%s]: Fail to switch band (ch: %d)\n", __func__,
			  central_ch);
		return false;
	}

	config_phydm_write_rf_reg_8710c(dm, RF_PATH_A, ODM_REG_CHNBW_11N, RFREGOFFSETMASK, rf_reg18);

	if (rf_reg_status == false) {
		PHYDM_DBG(dm, ODM_PHY_CONFIG,
			  "[%s]: Fail to switch channel (ch: %d), because writing RF register is fail\n",
			  __func__, central_ch);
		return false;
	}

	if(!(*dm->mp_mode))
	{
		config_phydm_write_rf_reg_8710c(dm, RF_PATH_A, ODM_REF_RF_DF_11N, RFREGOFFSETMASK, rf_regdf);
		//config_phydm_write_rf_reg_8710c(dm, RF_PATH_A, ODM_RED_RF_51_11N, RFREGOFFSETMASK, rf_reg51);
		//config_phydm_write_rf_reg_8710c(dm, RF_PATH_A, ODM_RED_RF_52_11N, RFREGOFFSETMASK, rf_reg52);
		//odm_set_rf_reg(dm, RF_PATH_A, RF_0x18, RFREGOFFSETMASK, rf_reg18);
		
		if (rf_reg_status_df == false) {
			PHYDM_DBG(dm, ODM_PHY_CONFIG,
				  "[%s]: Fail to write rf df, because writing RF register is fail\n",
				  __func__, central_ch);
			return false;
		}
	}

	/*if (rf_reg_status_51 == false) {
		PHYDM_DBG(dm, ODM_PHY_CONFIG,
			  "[%s]: Fail to write rf 51, because writing RF register is fail\n",
			  __func__, central_ch);
		return false;
	}

	
	if (rf_reg_status_52 == false) {
		PHYDM_DBG(dm, ODM_PHY_CONFIG,
			  "[%s]: Fail to write rf 52, because writing RF register is fail\n",
			  __func__, central_ch);
		return false;
	}*/
	/*2480M CSI mask for channel 13*/
	if (*dm->channel == 13) {
		odm_set_bb_reg(dm, R_0xd40, MASKDWORD, 0x04000000);
		odm_set_bb_reg(dm, R_0xd44, MASKDWORD, 0x00000000);
		odm_set_bb_reg(dm, R_0xd2c, BIT(28), 0x1);/*enable CSI mask*/
	} else {
		odm_set_bb_reg(dm, R_0xd40, MASKDWORD, 0x00000000);
		odm_set_bb_reg(dm, R_0xd44, MASKDWORD, 0x00000000);
		odm_set_bb_reg(dm, R_0xd2c, BIT(28), 0x1);/*disable CSI mask*/
	}
	PHYDM_DBG(dm, ODM_PHY_CONFIG,
		  "[%s]: Success to switch channel (ch: %d)\n", __func__,
		  central_ch);
	return true;
}

__iram_odm_func__
boolean
config_phydm_switch_bandwidth_8710c(
	struct dm_struct *dm,
	u8 primary_ch_idx,
	enum channel_width bandwidth)
{
	u32 rf_reg18;
	boolean rf_reg_status = true;
	u32 bb_reg8ac;

	PHYDM_DBG(dm, ODM_PHY_CONFIG, "[%s]===================>\n", __func__);

	if (dm->is_disable_phy_api) {
		PHYDM_DBG(dm, ODM_PHY_CONFIG,
			  "[%s]: disable PHY API for debug!!\n", __func__);
		return true;
	}

	/* Error handling */
	if (bandwidth >= CHANNEL_WIDTH_MAX || (bandwidth == CHANNEL_WIDTH_40 && primary_ch_idx > 2) || (bandwidth == CHANNEL_WIDTH_80 && primary_ch_idx > 4)) {
		PHYDM_DBG(dm, ODM_PHY_CONFIG,
			  "[%s]: Fail to switch bandwidth (bw: %d, primary ch: %d)\n",
			  __func__, bandwidth, primary_ch_idx);
		return false;
	}

	rf_reg18 = config_phydm_read_rf_reg_8710c(dm, RF_PATH_A, ODM_REG_CHNBW_11N, RFREGOFFSETMASK);
	rf_reg_status = rf_reg_status & config_phydm_read_rf_check_8710c(rf_reg18);

	/* Switch bandwidth */
	switch (bandwidth) {
	case CHANNEL_WIDTH_20: {
		/* Small BW([31:30]) = 0, rf mode(800[0], 900[0]) = 0 for 20M */
		odm_set_bb_reg(dm, ODM_REG_SMALL_BANDWIDTH_11N,
			       (BIT(31) | BIT(30)), 0x0);
		odm_set_bb_reg(dm, ODM_REG_BB_CTRL_11N, BIT(0), 0x0);
		odm_set_bb_reg(dm, ODM_REG_BB_CTRL_PAGE9_11N, BIT(0), 0x0);

		/* ADC clock = 160M clock for BW20*/
		odm_set_bb_reg(dm, ODM_REG_BB_CTRL_11N,
			       (BIT(10) | BIT(9) | BIT(8)), 0x5);

		/* DAC clock = 80M clock for BW20 */
		odm_set_bb_reg(dm, ODM_REG_BB_CTRL_11N,
			       (BIT(14) | BIT(13) | BIT(12)), 0x4);

		/* ADC buffer clock 0xce4[29:28] = 2'b10*/
		odm_set_bb_reg(dm, R_0xce4, (BIT(29) | BIT(28)), 0x2);

		/* RF bandwidth */
		rf_reg18 = (rf_reg18 & (~(BIT(12) | BIT(11) | BIT(10))));
		rf_reg18 = (rf_reg18 | BIT(11) | BIT(10));
		break;
	}
	case CHANNEL_WIDTH_5: {
		/* Small BW([31:30]) = 0, rf mode(800[0], 900[0]) = 0 for 5M */
		odm_set_bb_reg(dm, ODM_REG_SMALL_BANDWIDTH_11N,
			       (BIT(31) | BIT(30)), 0x1);
		odm_set_bb_reg(dm, ODM_REG_BB_CTRL_11N, BIT(0), 0x0);
		odm_set_bb_reg(dm, ODM_REG_BB_CTRL_PAGE9_11N, BIT(0), 0x0);

		/* ADC clock = 40M clock for BW5 */
		odm_set_bb_reg(dm, ODM_REG_BB_CTRL_11N,
			       (BIT(10) | BIT(9) | BIT(8)), 0x3);

		/* DAC clock = 20M clock for BW5 */
		odm_set_bb_reg(dm, ODM_REG_BB_CTRL_11N,
			       (BIT(14) | BIT(13) | BIT(12)), 0x2);

		/* ADC buffer clock 0xce4[29:28] = 2'b00*/
		odm_set_bb_reg(dm, R_0xce4, (BIT(29) | BIT(28)), 0x2);

		/* RF bandwidth */
		rf_reg18 = (rf_reg18 & (~(BIT(12) | BIT(11) | BIT(10))));
		rf_reg18 = (rf_reg18 | BIT(11) | BIT(10));

		break;
	}
	case CHANNEL_WIDTH_10: {
		/* Small BW([31:30]) = 0, rf mode(800[0], 900[0]) = 0 for 10M */
		odm_set_bb_reg(dm, ODM_REG_SMALL_BANDWIDTH_11N,
			       (BIT(31) | BIT(30)), 0x2);
		odm_set_bb_reg(dm, ODM_REG_BB_CTRL_11N, BIT(0), 0x0);
		odm_set_bb_reg(dm, ODM_REG_BB_CTRL_PAGE9_11N, BIT(0), 0x0);

		/* ADC clock = 80M clock for BW10*/
		odm_set_bb_reg(dm, ODM_REG_BB_CTRL_11N,
			       (BIT(10) | BIT(9) | BIT(8)), 0x4);

		/* DAC clock = 40M clock for BW10*/
		odm_set_bb_reg(dm, ODM_REG_BB_CTRL_11N,
			       (BIT(14) | BIT(13) | BIT(12)), 0x3);

		/* ADC buffer clock 0xce4[29:28] = 2'b01*/
		odm_set_bb_reg(dm, R_0xce4, (BIT(29) | BIT(28)), 0x2);

		/* RF bandwidth */
		rf_reg18 = (rf_reg18 & (~(BIT(12) | BIT(11) | BIT(10))));
		rf_reg18 = (rf_reg18 | BIT(11) | BIT(10));

		break;
	}
	default:
		PHYDM_DBG(dm, ODM_PHY_CONFIG,
			  "[%s]: Fail to switch bandwidth (bw: %d, primary ch: %d)\n",
			  __func__, bandwidth, primary_ch_idx);
	}

	/* Write RF register */
	config_phydm_write_rf_reg_8710c(dm, RF_PATH_A, ODM_REG_CHNBW_11N, RFREGOFFSETMASK, rf_reg18);
	//odm_set_rf_reg(dm, RF_PATH_A, ODM_REG_CHNBW_11N, RFREGOFFSETMASK, rf_reg18);

	if (rf_reg_status == false) {
		PHYDM_DBG(dm, ODM_PHY_CONFIG,
			  "[%s]: Fail to switch bandwidth (bw: %d, primary ch: %d), because writing RF register is fail\n",
			  __func__, bandwidth, primary_ch_idx);
		return false;
	}

	/* Modify RX DFIR parameters */
	phydm_rxdfirpar_by_bw_8710c(dm, bandwidth);

	/* Modify CCA parameters */
	/*phydm_ccapar_by_bw_8710c(dm, bandwidth);*/
	/*phydm_ccapar_8710c(dm);*/

	/* Toggle RX path to avoid RX dead zone issue */
	/*odm_set_bb_reg(dm, R_0x808, MASKBYTE0, 0x0);*/
	/*odm_set_bb_reg(dm, R_0x808, MASKBYTE0, 0x11);*/

	/*2480M CSI mask for channel 13*/
	if (*dm->channel == 13) {
		odm_set_bb_reg(dm, R_0xd40, MASKDWORD, 0x04000000);
		odm_set_bb_reg(dm, R_0xd44, MASKDWORD, 0x00000000);
		odm_set_bb_reg(dm, R_0xd2c, BIT(28), 0x1);/*enable CSI mask*/
	} else {
		odm_set_bb_reg(dm, R_0xd40, MASKDWORD, 0x00000000);
		odm_set_bb_reg(dm, R_0xd44, MASKDWORD, 0x00000000);
		odm_set_bb_reg(dm, R_0xd2c, BIT(28), 0x1);/*disable CSI mask*/
	}
	PHYDM_DBG(dm, ODM_PHY_CONFIG,
		  "[%s]: Success to switch bandwidth (bw: %d, primary ch: %d)\n",
		  __func__, bandwidth, primary_ch_idx);
	return true;
}


__iram_odm_func__
boolean
config_phydm_switch_channel_bw_8710c(
	struct dm_struct *dm,
	u8 central_ch,
	u8 primary_ch_idx,
	enum channel_width bandwidth)
{
	/* Switch band */
	//if (config_phydm_switch_band_8710c(dm, central_ch) == false)
		//return false;

	/* Switch channel */
	if (config_phydm_switch_channel_8710c(dm, central_ch) == false)
		return false;

	/* Switch bandwidth */
	if (config_phydm_switch_bandwidth_8710c(dm, primary_ch_idx, bandwidth) == false)
		return false;

	/* Switch CSI Mask*/
	//if (!config_phydm_switch_csimask_8710c(dm, central_ch, bandwidth))
		//return false;

	/* Switch bb powercut */
	//if (!config_phydm_switch_bbpowercut_8710c(dm, central_ch, bandwidth))
		//return false;

	return true;
}

__iram_odm_func__
boolean
config_phydm_trx_mode_8710c(
	struct dm_struct *dm,
	enum bb_path tx_path,
	enum bb_path rx_path,
	boolean is_tx2_path)
{
	return true;
}

__iram_odm_func__
boolean
config_phydm_parameter_init_8710c(
	struct dm_struct *dm,
	enum odm_parameter_init type)
	
{
	if (type == ODM_PRE_SETTING) {
		odm_set_bb_reg(dm, ODM_REG_BB_CTRL_11N,
			       (BIT(25) | BIT(24)), 0x0);
		PHYDM_DBG(dm, ODM_PHY_CONFIG,
			  "%s: Pre setting: disable OFDM and CCK block\n",
			  __func__);
	} else if (type == ODM_POST_SETTING) {
		odm_set_bb_reg(dm, ODM_REG_BB_CTRL_11N,
			       (BIT(25) | BIT(24)), 0x3);
		PHYDM_DBG(dm, ODM_PHY_CONFIG,
			  "%s: Post setting: enable OFDM and CCK block\n",
			  __func__);
	} else {
		PHYDM_DBG(dm, ODM_PHY_CONFIG, "%s: Wrong type!!\n", __func__);
		return false;
	}
	return true;
}

#if 0
__iram_odm_func__
u32 query_phydm_trx_capability_8710c(
	struct dm_struct *dm)
{
#if (PHYDM_FW_API_FUNC_ENABLE_8710C == 1)
	u32 value32 = 0x00000000;

	PHYDM_DBG(dm, ODM_PHY_CONFIG, "[%s]: trx_capability = 0x%x\n", __func__,
		  value32);
	return value32;
#else
	return 0;
#endif
}

__iram_odm_func__
u32 query_phydm_stbc_capability_8710c(
	struct dm_struct *dm)
{
#if (PHYDM_FW_API_FUNC_ENABLE_8710C == 1)
	u32 value32 = 0x00010001;

	PHYDM_DBG(dm, ODM_PHY_CONFIG, "[%s]: stbc_capability = 0x%x\n",
		  __func__, value32);
	return value32;
#else
	return 0;
#endif
}

__iram_odm_func__
u32 query_phydm_ldpc_capability_8710c(
	struct dm_struct *dm)
{
#if (PHYDM_FW_API_FUNC_ENABLE_8710C == 1)
	u32 value32 = 0x01000100;

	PHYDM_DBG(dm, ODM_PHY_CONFIG, "[%s]: ldpc_capability = 0x%x\n",
		  __func__, value32);
	return value32;
#else
	return 0;
#endif
}

__iram_odm_func__
u32 query_phydm_txbf_parameters_8710c(
	struct dm_struct *dm)
{
#if (PHYDM_FW_API_FUNC_ENABLE_8710C == 1)
	u32 value32 = 0x00030003;

	PHYDM_DBG(dm, ODM_PHY_CONFIG, "[%s]: txbf_parameters = 0x%x\n",
		  __func__, value32);
	return value32;
#else
	return 0;
#endif
}

__iram_odm_func__
u32 query_phydm_txbf_capability_8710c(
	struct dm_struct *dm)
{
#if (PHYDM_FW_API_FUNC_ENABLE_8710C == 1)
	u32 value32 = 0x01010001;

	PHYDM_DBG(dm, ODM_PHY_CONFIG, "[%s]: txbf_capability = 0x%x\n",
		  __func__, value32);
	return value32;
#else
	return 0;
#endif
}
#endif 

/* ======================================================================== */
#endif /* RTL8710C_SUPPORT == 1 */
