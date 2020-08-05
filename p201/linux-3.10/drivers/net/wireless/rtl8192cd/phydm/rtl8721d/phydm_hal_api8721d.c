/******************************************************************************
 *
 * Copyright(c) 2007 - 2017 Realtek Corporation.
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

#if (RTL8721D_SUPPORT == 1)

/* ============================================ */
/* These following functions can be used for PHY DM only*/

__iram_odm_func__
#if 0
void
phydm_cca_par_by_bw_8721d(struct dm_struct *dm, enum channel_width, bandwidth)
{
	struct phydm_dig_struct	*dig_tab = &dm->dm_dig_table;
	u32		regc3c;
	u32		regc3c_8_6; /*regc3c[8:6]*/
//	u8		reg_aaa;

	regc3c = odm_get_bb_reg(dm, R_0xc3c, MASKDWORD);
	regc3c_8_6 = ((regc3c & 0x1c0) >> 6);
	regc3c &= (~(0x000001f8));

//	reg_aaa = odm_read_1byte(p_dm, 0xaaa) & 0x1f;
//	p_dm_dig_table->aaa_default = reg_aaa;

	if (dm->rfe_type == 1 && dm->package_type == 1) {
		if (dm->cut_version == ODM_CUT_A) {
			if (bandwidth == CHANNEL_WIDTH_40 &&
			    dm->rx_ant_status != BB_PATH_AB) {
				regc3c |= ((0x1) << 3);
				regc3c |= ((0x0) << 6);
			} else if ((bandwidth == CHANNEL_WIDTH_40) &&
				  (dm->rx_ant_status == BB_PATH_AB)) {
				regc3c |= ((0x1) << 3);
				regc3c |= ((0x3) << 6);
			} else {
				regc3c |= ((0x0) << 3);
				regc3c |= ((0x0) << 6);
			}
		} else {
			regc3c |= ((0x2) << 3);
			regc3c |= ((0x6) << 6);
		}
	} else if ((dm->rfe_type == 1) && (dm->package_type == 2)) {
	/*97FN type1*/
		if (bandwidth == CHANNEL_WIDTH_20) {
			if (dm->rx_ant_status == BB_PATH_AB) {
				regc3c |= ((0x3) << 3);
				regc3c |= (regc3c_8_6 << 6);
			} else {
				regc3c |= ((0x3) << 3);
				regc3c |= (regc3c_8_6 << 6);
			}
			reg_aaa = 0x10;
		} else {
			if (dm->rx_ant_status == BB_PATH_AB) {
				regc3c |= ((0x2) << 3);
				regc3c |= (regc3c_8_6 << 6);
			} else {
				regc3c |= ((0x2) << 3);
				regc3c |= (regc3c_8_6 << 6);
		}
			reg_aaa = 0x12;
	}
		odm_set_bb_reg(dm, R_0xaa8, 0x1f0000, reg_aaa);
		dig_tab->aaa_default = reg_aaa;

	} else if ((dm->rfe_type == 2) && (dm->package_type == 2)) {
		if (bandwidth == CHANNEL_WIDTH_20) {
			if (dm->rx_ant_status == BB_PATH_AB) {
				regc3c |= ((0x1) << 3);
				regc3c |= (regc3c_8_6 << 6);
			} else {
				regc3c |= ((0x2) << 3);
				regc3c |= (regc3c_8_6 << 6);
			}
			reg_aaa = 0xf;
		} else {
			if (dm->rx_ant_status == BB_PATH_AB) {
				regc3c |= ((0x0) << 3);
				regc3c |= (regc3c_8_6 << 6);
			} else {
				regc3c |= ((0x2) << 3);
				regc3c |= (regc3c_8_6 << 6);
			}
			reg_aaa = 0x12;
		}
		odm_set_bb_reg(dm, R_0xaa8, 0x1f0000, reg_aaa);
		dig_tab->aaa_default = reg_aaa;
	} else if ((dm->rfe_type == 3) && (dm->package_type == 2)) {
		if (bandwidth == CHANNEL_WIDTH_20) {
			if (dm->rx_ant_status == BB_PATH_AB) {
				regc3c |= ((0x2) << 3);
				regc3c |= (regc3c_8_6 << 6);
			} else {
				regc3c |= ((0x2) << 3);
				regc3c |= (regc3c_8_6 << 6);
			}
			reg_aaa = 0x10;
		} else {
			if (dm->rx_ant_status == BB_PATH_AB) {
				regc3c |= ((0x1) << 3);
				regc3c |= (regc3c_8_6 << 6);
			} else {
				regc3c |= ((0x1) << 3);
				regc3c |= (regc3c_8_6 << 6);
			}
			reg_aaa = 0x12;
		}
		odm_set_bb_reg(dm, R_0xaa8, 0x1f0000, reg_aaa);
		dig_tab->aaa_default = reg_aaa;
	} else {
		if (dm->cut_version == ODM_CUT_A) {
			if (bandwidth == CHANNEL_WIDTH_20 &&
			    dm->rx_ant_status == BB_PATH_AB) {
				regc3c |= ((0x0) << 3);
				regc3c |= ((0x0) << 6);
			} else {
				regc3c |= ((0x1) << 3);
				regc3c |= ((0x4) << 6);
			}
		} else {
			if (bandwidth == CHANNEL_WIDTH_20) {
				if (dm->rx_ant_status == BB_PATH_AB) {
					regc3c |= ((0x2) << 3);
					regc3c |= (regc3c_8_6 << 6);
				} else {
					regc3c |= ((0x2) << 3);
					regc3c |= (regc3c_8_6 << 6);
				}
				reg_aaa = 0xf;
			} else {
				if (dm->rx_ant_status == BB_PATH_AB) {
					regc3c |= ((0x2) << 3);
					regc3c |= (regc3c_8_6 << 6);
				} else { /*ODM_BW40M*/
					regc3c |= ((0x2) << 3);
					regc3c |= (regc3c_8_6 << 6);
				}
				reg_aaa = 0x12;
			}
			odm_set_bb_reg(dm, R_0xaa8, 0x1f0000, reg_aaa);
			dig_tab->aaa_default = reg_aaa;
		}
	}

	odm_set_bb_reg(dm, R_0xc3c, MASKDWORD, regc3c);
}

void
phydm_cca_par_by_rx_path_8721d(struct dm_struct *dm)
{
	enum channel_width	bandwidth = *dm->band_width;

	phydm_cca_par_by_bw_8721d(dm, bandwidth);
}
#endif

void phydm_cca_par_by_bw_8721d(struct dm_struct *dm,
			       enum channel_width bandwidth)

{
	/* Switch bandwidth */
	switch (bandwidth) {
	case CHANNEL_WIDTH_20: {
		/* CCA threshold for BW20*/
		if (dm->cbw20_adc80) {
			odm_set_bb_reg(dm, R_0x954, 0xf0000000, 0x9);
			odm_set_bb_reg(dm, R_0xc30, 0xf, 0x5);
			odm_set_bb_reg(dm, R_0xc3c, 0x1f8, 0x22);
		} else {
			switch (dm->cca_cbw20_lev) {
			case 1: {
				odm_set_bb_reg(dm, R_0x954, 0xf0000000, 0x7);
				break;
			}
			case 2: {
				odm_set_bb_reg(dm, R_0x954, 0xf0000000, 0x8);
				break;
			}
			case 3: {
				odm_set_bb_reg(dm, R_0x954, 0xf0000000, 0x9);
				break;
			}
			default:
				odm_set_bb_reg(dm, R_0x954, 0xf0000000, 0x6);
			}
			odm_set_bb_reg(dm, R_0xc30, 0xf, 0x8);
			odm_set_bb_reg(dm, R_0xc3c, 0x1f8, 0x19);
		}
		break;
	}
	case CHANNEL_WIDTH_40: {
		/* CCA threshold for BW40 */
		switch (dm->cca_cbw40_lev) {
		case 1: {
			odm_set_bb_reg(dm, R_0x958, 0xf0000, 0x6);
			break;
		}
		case 2: {
			odm_set_bb_reg(dm, R_0x958, 0xf0000, 0x7);
			break;
		}
		case 3: {
			odm_set_bb_reg(dm, R_0x958, 0xf0000, 0x8);
			break;
		}
		default:
			odm_set_bb_reg(dm, R_0x958, 0xf0000, 0x5);
		}
		odm_set_bb_reg(dm, R_0xc84, 0xf0000000, 0x3);
		odm_set_bb_reg(dm, R_0xc3c, 0x1f8, 0x19);
		break;
	}
	case CHANNEL_WIDTH_5: {
		/* CCA threshold for BW5 */
		odm_set_bb_reg(dm, R_0x954, 0xf0000000, 0x0);
		odm_set_bb_reg(dm, R_0xc30, 0xf, 0x3);
		odm_set_bb_reg(dm, R_0xc3c, 0x1f8, 0x0);
		break;
	}
	case CHANNEL_WIDTH_10: {
		/* CCA threshold for BW10 */
		odm_set_bb_reg(dm, R_0x954, 0xf0000000, 0x0);
		odm_set_bb_reg(dm, R_0xc30, 0xf, 0x6);
		odm_set_bb_reg(dm, R_0xc3c, 0x1f8, 0x0);
		break;
	}
	default:
		PHYDM_DBG(dm, ODM_PHY_CONFIG,
			  "%s: Fail to switch bandwidth (bw: %d)\n",
			  __func__, bandwidth);
	}
}

void phydm_rx_dfir_par_by_bw_8721d(struct dm_struct *dm,
				   enum channel_width bandwidth)

{
	/* Switch bandwidth */
	switch (bandwidth) {
	case CHANNEL_WIDTH_20: {
		/* RX DFIR for BW20*/
		if (dm->cbw20_adc80) {
			odm_set_bb_reg(dm, R_0x864, (BIT(30) | BIT(29)), 0x1);
			odm_set_bb_reg(dm, R_0xc10, (BIT(29) | BIT(28)), 0x1);
			odm_set_bb_reg(dm, R_0x954, BIT(19), 0x0);
			odm_set_bb_reg(dm, R_0x954, 0x0ff00000, 0x0);
		} else {
			odm_set_bb_reg(dm, R_0x864, (BIT(30) | BIT(29)), 0x2);
			odm_set_bb_reg(dm, R_0xc10, (BIT(29) | BIT(28)), 0x2);
			odm_set_bb_reg(dm, R_0x954, BIT(19), 0x0);
			odm_set_bb_reg(dm, R_0x954, 0x0ff00000, 0x2);
		}
		break;
	}
	case CHANNEL_WIDTH_40: {
		/* RX DFIR for BW40 */
		odm_set_bb_reg(dm, R_0x864, (BIT(30) | BIT(29)), 0x2);
		odm_set_bb_reg(dm, R_0xc10, (BIT(29) | BIT(28)), 0x2);
		odm_set_bb_reg(dm, R_0x954, BIT(19), 0x0);
		odm_set_bb_reg(dm, R_0x954, 0x0ff00000, 0x3);
		break;
	}
	case CHANNEL_WIDTH_5: {
		/* RX DFIR for BW5 */
		odm_set_bb_reg(dm, R_0x864, (BIT(30) | BIT(29)), 0x3);
		odm_set_bb_reg(dm, R_0xc10, (BIT(29) | BIT(28)), 0x3);
		odm_set_bb_reg(dm, R_0x954, BIT(19), 0x1);
		odm_set_bb_reg(dm, R_0x954, 0x0ff00000, 0x8c);
		break;
	}
	case CHANNEL_WIDTH_10: {
		/* RX DFIR for BW10 */
		odm_set_bb_reg(dm, R_0x864, (BIT(30) | BIT(29)), 0x2);
		odm_set_bb_reg(dm, R_0xc10, (BIT(29) | BIT(28)), 0x2);
		odm_set_bb_reg(dm, R_0x954, BIT(19), 0x1);
		odm_set_bb_reg(dm, R_0x954, 0x0ff00000, 0x82);
		break;
	}
	default:
		PHYDM_DBG(dm, ODM_PHY_CONFIG,
			  "%s: Fail to switch bandwidth (bw: %d)\n",
			  __func__, bandwidth);
	}
}

void phydm_init_hw_info_by_rfe_type_8721d(struct dm_struct *dm)
{
#if 0
	if (dm->rfe_type == 7) {
		/*CUTB+RFE7(PCIE QFN46_SW2576L+SKY85201 wi RX bypass mode);*/
		odm_set_bb_reg(dm, R_0x103c, 0x70000, 0x7);
		odm_set_bb_reg(dm, R_0x4c, 0x6c00000, 0x0);
		odm_set_bb_reg(dm, R_0x64, BIT(29) | BIT(28), 0x3);
		odm_set_bb_reg(dm, R_0x1038, 0x600000 | BIT(4), 0x0);
		odm_set_bb_reg(dm, R_0x944, MASKLWORD, 0x081F);
		odm_set_bb_reg(dm, R_0x930, 0xFFFFF, 0x23200);
		odm_set_bb_reg(dm, R_0x938, 0xFFFFF, 0x23200);
		odm_set_bb_reg(dm, R_0x934, 0xF000, 0x3);
		odm_set_bb_reg(dm, R_0x93c, 0xF000, 0x3);
		odm_set_bb_reg(dm, R_0x968, BIT(2), 0x0);
		odm_set_bb_reg(dm, R_0x920, MASKDWORD, 0x03000003);
		if (tx_path == BB_PATH_A)
			odm_set_bb_reg(dm, R_0x940, MASKDWORD, 0x000007AE);
		else if (tx_path == BB_PATH_B)
			odm_set_bb_reg(dm, R_0x940, MASKDWORD, 0x004007EE);
		else
			odm_set_bb_reg(dm, R_0x940, MASKDWORD, 0x004007AE);
		odm_cmn_info_init(dm, ODM_CMNINFO_EXT_LNA, true);
		odm_cmn_info_init(dm, ODM_CMNINFO_EXT_PA, true);
	} else if (dm->rfe_type == 8) {
		/*CUTB+RFE8(PCIE QFN46_RTL6691+BFP740+RTC6603 wo bypass)*/
		odm_set_bb_reg(dm, R_0x103c, 0x70000, 0x7);
		odm_set_bb_reg(dm, R_0x4c, 0x6c00000, 0x0);
		odm_set_bb_reg(dm, R_0x64, BIT(29) | BIT(28), 0x3);
		odm_set_bb_reg(dm, R_0x1038, 0x600000 | BIT(4), 0x0);
		odm_set_bb_reg(dm, R_0x944, MASKLWORD, 0x081F);
		odm_set_bb_reg(dm, R_0x930, 0xFFFFF, 0x22200);
		odm_set_bb_reg(dm, R_0x938, 0xFFFFF, 0x22200);
		odm_set_bb_reg(dm, R_0x934, 0xF000, 0x2);
		odm_set_bb_reg(dm, R_0x93c, 0xF000, 0x2);
		odm_set_bb_reg(dm, R_0x92c, MASKDWORD, 0x08000400);
		odm_set_bb_reg(dm, R_0x968, BIT(2), 0x0);
		odm_set_bb_reg(dm, R_0x940, MASKDWORD, 0x004007AE);
	}
#endif

	PHYDM_DBG(dm, ODM_PHY_CONFIG,
		  "%s: RFE type (%d)\n",
		  __func__, dm->rfe_type);
}

u32 config_phydm_read_rf_reg_8721d_pi(struct dm_struct *dm,
				      enum rf_path rf_path,
				      u32 reg_addr,
				      u32 bit_mask)
{
	u32 read_v;

	/* [BIT_DAI_RW_EN,BIT_DAI_REG00_WREN] */
	// odm_set_bb_reg(dm, 0x4, (BIT31 | BIT30), 0x0);

	/* r_pi_on =1 */
	odm_set_bb_reg(dm, R_0x820, BIT8, 1);

	/* Read RF register by PI*/
	odm_set_bb_reg(dm, R_0x824, (0xff << 23), reg_addr);
	odm_set_bb_reg(dm, R_0x824, BIT31, 0);
	odm_set_bb_reg(dm, R_0x824, BIT31, 1);
	read_v = odm_get_bb_reg(dm, R_0x8b8, bit_mask);
	return read_v;
}

u32 config_phydm_read_rf_reg_8721d_dai(struct dm_struct *dm,
				       enum rf_path rf_path,
				       u32 reg_addr,
				       u32 bit_mask)
{
	u32 read_v, direct_addr;
	u32 offset_read_rf[1] = {0x1000};

	/* [BIT_DAI_RW_EN,BIT_DAI_REG00_WREN] */
	// odm_set_bb_reg(dm, 0x4, (BIT31 | BIT30), 0x2);

	/* Read RF register by DAI */
	direct_addr = offset_read_rf[rf_path] + (reg_addr << 2);
	read_v = odm_get_bb_reg(dm, direct_addr, bit_mask);
	return read_v;
}

/* ============================================ */

/* ============================================ */
/* These following functions can be used by driver*/

u32 config_phydm_read_rf_reg_8721d(struct dm_struct *dm,
				   enum rf_path rf_path,
				   u32 reg_addr,
				   u32 bit_mask)
{
	u32 read_v;

	/* Error handling.*/
	if (rf_path > RF_PATH_A) {
		PHYDM_DBG(dm, ODM_PHY_CONFIG, "%s: unsupported path (%d)\n",
			  __func__, rf_path);
		return INVALID_RF_DATA;
	}

	/* Calculate offset */
	reg_addr &= 0xff;

	/* RF register only has 20bits */
	bit_mask &= RFREGOFFSETMASK;

	/* Read RF register */
#if 0
	if (dm->cut_version == ODM_CUT_A) {
		read_v = config_phydm_read_rf_reg_8721d_pi(dm, rf_path,
							   reg_addr, bit_mask);
	} else {
		if (reg_addr == 0x0)
			read_v = config_phydm_read_rf_reg_8721d_pi(dm, rf_path,
								   reg_addr,
								   bit_mask);
		else
			read_v = config_phydm_read_rf_reg_8721d_dai(dm, rf_path,
								    reg_addr,
								    bit_mask);
	}
#else
	read_v = config_phydm_read_rf_reg_8721d_dai(dm, rf_path, reg_addr,
						    bit_mask);
#endif
	PHYDM_DBG(dm, ODM_PHY_CONFIG,
		  "%s: RF-%d 0x%x = 0x%x, bit mask = 0x%x\n", __func__, rf_path,
		  reg_addr, read_v, bit_mask);
	return read_v;
}

void
config_phydm_write_rf_reg_8721d_pi(struct dm_struct *dm,
				   enum rf_path rf_path,
				   u32 reg_addr,
				   u32 bit_mask,
				   u32 data)
{
	u32 data_and_addr = 0;
	u32 offset_write_rf[1] = {0x840};

	/* [BIT_DAI_RW_EN,BIT_DAI_REG00_WREN] */
	// odm_set_bb_reg(dm, 0x4, (BIT31 | BIT30), 0x0);

	/* r_pi_on =1*/
	odm_set_bb_reg(dm, R_0x820, BIT8, 1);

	/* Put write addr in [27:20]  and write data in [19:00] */
	data_and_addr = ((reg_addr << 20) | (data & 0x000fffff)) &
			0x0fffffff;

	/* Write operation */
	odm_set_bb_reg(dm, offset_write_rf[rf_path], 0x0fffffff, data_and_addr);
}

void
config_phydm_write_rf_reg_8721d_dai(struct dm_struct *dm,
				    enum rf_path rf_path,
				    u32 reg_addr,
				    u32 bit_mask,
				    u32 data)
{
	u32 direct_addr = 0;
	u32 offset_read_rf[1] = {0x1000};

	/* [BIT_DAI_RW_EN,BIT_DAI_REG00_WREN] */
	// odm_set_bb_reg(dm, 0x4, (BIT31 | BIT30), 0x2);

	/* Write operation */
	direct_addr = offset_read_rf[rf_path] + (reg_addr << 2);
	odm_set_bb_reg(dm, direct_addr, RFREGOFFSETMASK, data);
}

boolean
config_phydm_write_rf_reg_8721d(struct dm_struct *dm,
				enum rf_path rf_path,
				u32 reg_addr,
				u32 bit_mask,
				u32 data)
{
	u32 data_original = 0;
	u8 bit_shift;

	/* Error handling.*/
	if (rf_path > RF_PATH_A) {
		PHYDM_DBG(dm, ODM_PHY_CONFIG, "%s: unsupported path (%d)\n",
			  __func__, rf_path);
		return false;
	}

	/* Calculate offset */
	reg_addr &= 0xff;

	/* RF register only has 20bits */
	bit_mask &= RFREGOFFSETMASK;

	/* Read RF register content first */
	if (bit_mask != RFREGOFFSETMASK) {
		data_original = config_phydm_read_rf_reg_8721d(dm, rf_path,
							       reg_addr,
							       RFREGOFFSETMASK);
		/* Error handling. RF is disabled */
		if (config_phydm_read_rf_check_8721d(data_original) == false) {
			PHYDM_DBG(dm, ODM_PHY_CONFIG,
				  "%s: Write fail, RF is disable\n", __func__);
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

	/* Write operation */
	if (dm->cut_version == ODM_CUT_A) {
		config_phydm_write_rf_reg_8721d_pi(dm, rf_path, reg_addr,
						   bit_mask, data);
	} else {
		if (reg_addr == 0x0)
			config_phydm_write_rf_reg_8721d_pi(dm, rf_path,
							   reg_addr, bit_mask,
							   data);
		else
			config_phydm_write_rf_reg_8721d_dai(dm, rf_path,
							    reg_addr, bit_mask,
							    data);
	}
	PHYDM_DBG(dm, ODM_PHY_CONFIG,
		  "%s: RF-%d 0x%x = 0x%x (original: 0x%x), bit mask = 0x%x\n",
		  __func__, rf_path, reg_addr, data, data_original, bit_mask);
	return true;
}

boolean
config_phydm_write_txagc_8721d(struct dm_struct *dm,
			       u32 power_index,
			       enum rf_path path,
			       u8 hw_rate)
{
	/*u8	read_back_data;	*/
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
		odm_set_bb_reg(dm, REG_TX_AGC_A_CCK_1_MCS32,
			       0x0000ff00, power_index);
		break;
	case ODM_RATE2M:
		odm_set_bb_reg(dm, REG_TX_AGC_B_CCK_11_A_CCK_2_11,
			       0x0000ff00, power_index);
		break;
	case ODM_RATE5_5M:
		odm_set_bb_reg(dm, REG_TX_AGC_B_CCK_11_A_CCK_2_11,
			       0x00ff0000, power_index);
		break;
	case ODM_RATE11M:
		odm_set_bb_reg(dm, REG_TX_AGC_B_CCK_11_A_CCK_2_11,
			       0xff000000, power_index);
		break;

	case ODM_RATE6M:
		odm_set_bb_reg(dm, REG_TX_AGC_A_RATE18_06,
			       0x000000ff, power_index);
		break;
	case ODM_RATE9M:
		odm_set_bb_reg(dm, REG_TX_AGC_A_RATE18_06,
			       0x0000ff00, power_index);
		break;
	case ODM_RATE12M:
		odm_set_bb_reg(dm, REG_TX_AGC_A_RATE18_06,
			       0x00ff0000, power_index);
		break;
	case ODM_RATE18M:
		odm_set_bb_reg(dm, REG_TX_AGC_A_RATE18_06,
			       0xff000000, power_index);
		break;
	case ODM_RATE24M:
		odm_set_bb_reg(dm, REG_TX_AGC_A_RATE54_24,
			       0x000000ff, power_index);
		break;
	case ODM_RATE36M:
		odm_set_bb_reg(dm, REG_TX_AGC_A_RATE54_24,
			       0x0000ff00, power_index);
		break;
	case ODM_RATE48M:
		odm_set_bb_reg(dm, REG_TX_AGC_A_RATE54_24,
			       0x00ff0000, power_index);
		break;
	case ODM_RATE54M:
		odm_set_bb_reg(dm, REG_TX_AGC_A_RATE54_24,
			       0xff000000, power_index);
		break;

	case ODM_RATEMCS0:
		odm_set_bb_reg(dm, REG_TX_AGC_A_MCS03_MCS00,
			       0x000000ff, power_index);
		break;
	case ODM_RATEMCS1:
		odm_set_bb_reg(dm, REG_TX_AGC_A_MCS03_MCS00,
			       0x0000ff00, power_index);
		break;
	case ODM_RATEMCS2:
		odm_set_bb_reg(dm, REG_TX_AGC_A_MCS03_MCS00,
			       0x00ff0000, power_index);
		break;
	case ODM_RATEMCS3:
		odm_set_bb_reg(dm, REG_TX_AGC_A_MCS03_MCS00,
			       0xff000000, power_index);
		break;
	case ODM_RATEMCS4:
		odm_set_bb_reg(dm, REG_TX_AGC_A_MCS07_MCS04,
			       0x000000ff, power_index);
		break;
	case ODM_RATEMCS5:
		odm_set_bb_reg(dm, REG_TX_AGC_A_MCS07_MCS04,
			       0x0000ff00, power_index);
		break;
	case ODM_RATEMCS6:
		odm_set_bb_reg(dm, REG_TX_AGC_A_MCS07_MCS04,
			       0x00ff0000, power_index);
		break;
	case ODM_RATEMCS7:
		odm_set_bb_reg(dm, REG_TX_AGC_A_MCS07_MCS04,
			       0xff000000, power_index);
		break;

	default:
		PHYDM_DBG(dm, ODM_PHY_CONFIG, "Invalid HWrate!\n");
		break;
	}

	PHYDM_DBG(dm, ODM_PHY_CONFIG, "%s: path-%d rate index 0x%x = 0x%x\n",
		  __func__, path, hw_rate, power_index);
	return true;
}

u8 config_phydm_read_txagc_8721d(struct dm_struct *dm,
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
		(u8)odm_get_bb_reg(dm,
		REG_TX_AGC_A_CCK_1_MCS32, 0x0000ff00);
		break;
	case ODM_RATE2M:
		read_back_data =
		(u8)odm_get_bb_reg(dm, REG_TX_AGC_B_CCK_11_A_CCK_2_11,
				   0x0000ff00);
		break;
	case ODM_RATE5_5M:
		read_back_data =
		(u8)odm_get_bb_reg(dm, REG_TX_AGC_B_CCK_11_A_CCK_2_11,
				   0x00ff0000);
		break;
	case ODM_RATE11M:
		read_back_data =
		(u8)odm_get_bb_reg(dm, REG_TX_AGC_B_CCK_11_A_CCK_2_11,
				   0xff000000);
		break;

	case ODM_RATE6M:
		read_back_data = (u8)odm_get_bb_reg(dm, REG_TX_AGC_A_RATE18_06,
						    0x000000ff);
		break;
	case ODM_RATE9M:
		read_back_data = (u8)odm_get_bb_reg(dm, REG_TX_AGC_A_RATE18_06,
						    0x0000ff00);
		break;
	case ODM_RATE12M:
		read_back_data = (u8)odm_get_bb_reg(dm, REG_TX_AGC_A_RATE18_06,
						    0x00ff0000);
		break;
	case ODM_RATE18M:
		read_back_data = (u8)odm_get_bb_reg(dm, REG_TX_AGC_A_RATE18_06,
						    0xff000000);
		break;
	case ODM_RATE24M:
		read_back_data = (u8)odm_get_bb_reg(dm, REG_TX_AGC_A_RATE54_24,
						    0x000000ff);
		break;
	case ODM_RATE36M:
		read_back_data = (u8)odm_get_bb_reg(dm, REG_TX_AGC_A_RATE54_24,
						    0x0000ff00);
		break;
	case ODM_RATE48M:
		read_back_data = (u8)odm_get_bb_reg(dm, REG_TX_AGC_A_RATE54_24,
						    0x00ff0000);
		break;
	case ODM_RATE54M:
		read_back_data = (u8)odm_get_bb_reg(dm, REG_TX_AGC_A_RATE54_24,
						    0xff000000);
		break;
	case ODM_RATEMCS0:
		read_back_data = (u8)odm_get_bb_reg(dm,
						    REG_TX_AGC_A_MCS03_MCS00,
						    0x000000ff);
		break;
	case ODM_RATEMCS1:
		read_back_data = (u8)odm_get_bb_reg(dm,
						    REG_TX_AGC_A_MCS03_MCS00,
						    0x0000ff00);
		break;
	case ODM_RATEMCS2:
		read_back_data = (u8)odm_get_bb_reg(dm,
						    REG_TX_AGC_A_MCS03_MCS00,
						    0x00ff0000);
		break;
	case ODM_RATEMCS3:
		read_back_data = (u8)odm_get_bb_reg(dm,
						    REG_TX_AGC_A_MCS03_MCS00,
						    0xff000000);
		break;
	case ODM_RATEMCS4:
		read_back_data = (u8)odm_get_bb_reg(dm,
						    REG_TX_AGC_A_MCS07_MCS04,
						    0x000000ff);
		break;
	case ODM_RATEMCS5:
		read_back_data = (u8)odm_get_bb_reg(dm,
						    REG_TX_AGC_A_MCS07_MCS04,
						    0x0000ff00);
		break;
	case ODM_RATEMCS6:
		read_back_data = (u8)odm_get_bb_reg(dm,
						    REG_TX_AGC_A_MCS07_MCS04,
						    0x00ff0000);
		break;
	case ODM_RATEMCS7:
		read_back_data = (u8)odm_get_bb_reg(dm,
						    REG_TX_AGC_A_MCS07_MCS04,
						    0xff000000);
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
void phydm_dynamic_spur_det_eliminate_8721d(struct dm_struct *dm)
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
				       (BIT(10) | BIT(9) | BIT(8)), 0x3);
			/* r_adc_upd0 0xca4[27:26] = 2'b01*/
			odm_set_bb_reg(dm, R_0xca4, (BIT(27) | BIT(26)), 0x1);
			/* r_tap_upd 0xe24[21:20] = 2'b01*/
			odm_set_bb_reg(dm, R_0xe24, (BIT(21) | BIT(20)), 0x1);
			/* Down_factor=2 0xc10[29:28]=0x1*/
			odm_set_bb_reg(dm, R_0xc10, (BIT(29) | BIT(28)), 0x1);
			/* Disable DFIR stage 1 0x948[8]=0*/
			odm_set_bb_reg(dm, R_0x948, BIT(8), 0x0);
			/* DFIR stage0=3 0x948[3:0]=0x3*/
			odm_set_bb_reg(dm, R_0x948, (BIT(3) | BIT(2) |
				       BIT(1) | BIT(0)), 0x3);
		} else {
			/* ADC clock = 160M clock for BW20*/
			odm_set_bb_reg(dm, R_0x800, (BIT(10) | BIT(9) | BIT(8)),
				       0x4);
			/* r_adc_upd0 0xca4[27:26] = 2'b10*/
			odm_set_bb_reg(dm, R_0xca4, (BIT(27) | BIT(26)), 0x2);
			/* r_tap_upd 0xe24[21:20] = 2'b10*/
			odm_set_bb_reg(dm, R_0xe24, (BIT(21) | BIT(20)), 0x2);
			/* Down_factor=4 0xc10[29:28]=0x2*/
			odm_set_bb_reg(dm, R_0xc10, (BIT(29) | BIT(28)), 0x2);
			/* enable DFIR stage 1 0x948[8]=1*/
			odm_set_bb_reg(dm, R_0x948, BIT(8), 0x1);
			/* DFIR stage0=3, stage1=10*/
			/*0x948[3:0]=0x3 0x948[7:4]=0xa*/
			odm_set_bb_reg(dm, R_0x948, (BIT(3) | BIT(2) | BIT(1) |
				       BIT(0)), 0x3);
			odm_set_bb_reg(dm, R_0x948, (BIT(7) | BIT(6) | BIT(5) |
				       BIT(4)), 0xa);
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

boolean
config_phydm_switch_band_8721d(struct dm_struct *dm,
			       u8 central_ch)
{
	u32 rf_reg18;
	boolean rf_reg_status = true;

	PHYDM_DBG(dm, ODM_PHY_CONFIG, "%s======================>\n",
		  __func__);

	if (dm->is_disable_phy_api) {
		PHYDM_DBG(dm, ODM_PHY_CONFIG,
			  "%s: disable PHY API for debug!!\n", __func__);
		return true;
	}

	rf_reg18 = config_phydm_read_rf_reg_8721d(dm, RF_PATH_A, 0x18,
						  RFREGOFFSETMASK);
	rf_reg_status = rf_reg_status &
			config_phydm_read_rf_check_8721d(rf_reg18);

	if (central_ch <= 14) {
		/* 2.4G */

		/* Enable CCK block */
		odm_set_bb_reg(dm, 0x800, BIT(24), 0x1);

		/* Disable MAC CCK check */
		odm_set_bb_reg(dm, 0x454, BIT(7), 0x0);

		/* Disable BB CCK check */
		odm_set_bb_reg(dm, 0xa80, BIT(18), 0x0);

		/*CCA Mask*/
		odm_set_bb_reg(dm, 0x814, 0x0000fc00, 15); /*default value*/

		/* RF band */
		rf_reg18 = (rf_reg18 & (~(BIT(17) | BIT(16) |
			    BIT(9) | BIT(8) | MASKBYTE0)));
		rf_reg18 = (rf_reg18 | central_ch);

		/* TXG VCM */
		if (dm->cut_version == ODM_CUT_B) {
			odm_set_rf_reg(dm, RF_PATH_A, 0xEF, 0xfffff, 0x01000);
			odm_set_rf_reg(dm, RF_PATH_A, 0x33, 0xfffff, 0x00009);
			odm_set_rf_reg(dm, RF_PATH_A, 0x3F, 0xfffff, 0x00855);
			odm_set_rf_reg(dm, RF_PATH_A, 0x33, 0xfffff, 0x0000A);
			odm_set_rf_reg(dm, RF_PATH_A, 0x3F, 0xfffff, 0x00855);
			odm_set_rf_reg(dm, RF_PATH_A, 0xEF, 0xfffff, 0x00000);
		}
#if 0
#if (PHYDM_FW_API_FUNC_ENABLE_8721d == 1)
		/* Switch WLG/BTG*/
		if (dm->default_rf_set_8721d == SWITCH_TO_BTG)
			config_phydm_switch_rf_set_8721d(dm, SWITCH_TO_BTG);
		else if (dm->default_rf_set_8721d == SWITCH_TO_WLG)
			config_phydm_switch_rf_set_8721d(dm, SWITCH_TO_WLG);
#endif

		/*RF TXA_TANK LUT mode*/
		odm_set_rf_reg(dm, RF_PATH_A, RF_0xdf, BIT(6), 0x1);

		/*RF TXA_PA_TANK*/
		odm_set_rf_reg(dm, RF_PATH_A, RF_0x64, 0x0000f, 0xf);
#endif
	} else if (central_ch > 35) {
		/* 5G */

		/* Enable BB CCK check */
		odm_set_bb_reg(dm, 0xa80, BIT(18), 0x1);

		/* Enable CCK check */
		odm_set_bb_reg(dm, 0x454, BIT(7), 0x1);

		/* Disable CCK block */
		odm_set_bb_reg(dm, 0x800, BIT(24), 0x0);

		/*CCA Mask*/
		odm_set_bb_reg(dm, 0x814, 0x0000fc00, 15); /*default value*/

		/* RF band and channel */
		rf_reg18 = (rf_reg18 & (~(BIT(17) | BIT(9) | MASKBYTE0)));
		rf_reg18 = (rf_reg18 | BIT(16) | BIT(8) | central_ch);

		/* TXA VCM */
		if (dm->cut_version == ODM_CUT_B) {
			odm_set_rf_reg(dm, RF_PATH_A, 0xEF, 0xfffff, 0x01000);
			odm_set_rf_reg(dm, RF_PATH_A, 0x33, 0xfffff, 0x00009);
			odm_set_rf_reg(dm, RF_PATH_A, 0x3F, 0xfffff, 0x00A55);
			odm_set_rf_reg(dm, RF_PATH_A, 0x33, 0xfffff, 0x0000A);
			odm_set_rf_reg(dm, RF_PATH_A, 0x3F, 0xfffff, 0x00A55);
			odm_set_rf_reg(dm, RF_PATH_A, 0xEF, 0xfffff, 0x00000);
		}

#if 0
#if (PHYDM_FW_API_FUNC_ENABLE_8721d == 1)
		/* Switch WLA */
		config_phydm_switch_rf_set_8721d(dm, SWITCH_TO_WLA);
#endif

		/*RF TXA_TANK LUT mode*/
		odm_set_rf_reg(dm, RF_PATH_A, RF_0xdf, BIT(6), 0x0);
#endif
	} else {
		PHYDM_DBG(dm, ODM_PHY_CONFIG,
			  "%s: Fail to switch band (ch: %d)\n", __func__,
			  central_ch);
		return false;
	}

#if 0
	/*To avoid RTK saturation, reset RTK before switch band/channel*/
	odm_set_rf_reg(dm, RF_PATH_A, 0xDF, BIT(10), 0x1);
	odm_set_rf_reg(dm, RF_PATH_A, 0xDF, BIT(10), 0x0);
#endif
	odm_set_rf_reg(dm, RF_PATH_A, RF_0x18, RFREGOFFSETMASK, rf_reg18);

#if 0
	if (phydm_rfe_8721d(dm, central_ch) == false)
		return false;
#endif

	if (!rf_reg_status) {
		PHYDM_DBG(dm, ODM_PHY_CONFIG,
			  "%s: Fail to switch band (ch: %d), because writing RF register is fail\n",
			  __func__, central_ch);
		return false;
	}

	PHYDM_DBG(dm, ODM_PHY_CONFIG, "%s: Success to switch band (ch: %d)\n",
		  __func__, central_ch);
	return true;
}

boolean
config_phydm_switch_channel_8721d(struct dm_struct *dm,
				  u8 central_ch)
{
	struct phydm_dig_struct *dig_tab = &dm->dm_dig_table;
	u32 rf_reg18;
	u32 temp;
	boolean rf_reg_status = true;

	PHYDM_DBG(dm, ODM_PHY_CONFIG, "%s====================>\n", __func__);

	if (dm->is_disable_phy_api) {
		PHYDM_DBG(dm, ODM_PHY_CONFIG,
			  "%s: disable PHY API for debug!!\n", __func__);
		return true;
	}

	rf_reg18 = config_phydm_read_rf_reg_8721d(dm, RF_PATH_A,
						  ODM_REG_CHNBW_11N,
						  RFREGOFFSETMASK);
	rf_reg_status = rf_reg_status &
			config_phydm_read_rf_check_8721d(rf_reg18);

	/* Switch band and channel */
	if (central_ch <= 14) {
		/* 2.4G */

		/* 1. RF band and channel*/
		rf_reg18 = (rf_reg18 & (~(BIT(19) | BIT(18) | BIT(17) |
			    BIT(16) | BIT(9) | BIT(8) | MASKBYTE0)));
		rf_reg18 = (rf_reg18 | central_ch);

		/* 2. AGC table selection */
		odm_set_bb_reg(dm, 0x950, 0x1c000000, 0x0);
		dig_tab->agc_table_idx = 0x0;

		/* 3. Set central frequency for clock offset tracking */
		odm_set_bb_reg(dm, 0xd2c, 0x00006000, 0x0);

		/*RFAFE voltage indication: 0: 1.8v 1: 3.3v*/
		temp = HAL_READ32((SYSTEM_CTRL_BASE_LP + LP_RW_HSYSON_OFFSET),
				  REG_HS_RFAFE_IND_VIO1833);

		/* CCK TX filter parameters */
		if (central_ch == 14) {
			odm_set_bb_reg(dm, R_0xa20, MASKDWORD, 0xe82c0001);
			odm_set_bb_reg(dm, R_0xa24, MASKDWORD, 0x0000b81c);
			odm_set_bb_reg(dm, R_0xa28, MASKLWORD, 0x0000);
			odm_set_bb_reg(dm, R_0xaac, MASKDWORD, 0x00003667);
		} else if (central_ch == 13) {
			if (temp & BIT_RFAFE_IND_VIO1833) {
				odm_set_bb_reg(dm, R_0xa20, MASKDWORD,
					       0xf8fe0001);
				odm_set_bb_reg(dm, R_0xa24, MASKDWORD,
					       0x64b83030);
				odm_set_bb_reg(dm, R_0xa28, MASKLWORD,
					       0x8810);
				odm_set_bb_reg(dm, R_0xaac, MASKDWORD,
					       0x01234657);
			} else {
				odm_set_bb_reg(dm, R_0xa20, MASKDWORD,
					       0xf8fe0001);
				odm_set_bb_reg(dm, R_0xa24, MASKDWORD,
					       0x64b83030);
				odm_set_bb_reg(dm, R_0xa28, MASKLWORD,
					       0x8810);
				odm_set_bb_reg(dm, R_0xaac, MASKDWORD,
					       0x01234657);
			}
		} else if (central_ch == 12) {
			if (temp & BIT_RFAFE_IND_VIO1833) {
				odm_set_bb_reg(dm, R_0xa20, MASKDWORD,
					       0xe82c0001);
				odm_set_bb_reg(dm, R_0xa24, MASKDWORD,
					       0x64b80c1c);
				odm_set_bb_reg(dm, R_0xa28, MASKLWORD,
					       0x8810);
				odm_set_bb_reg(dm, R_0xaac, MASKDWORD,
					       0x01235667);
			} else {
				odm_set_bb_reg(dm, R_0xa20, MASKDWORD,
					       0xe82c0001);
				odm_set_bb_reg(dm, R_0xa24, MASKDWORD,
					       0x64b80c1c);
				odm_set_bb_reg(dm, R_0xa28, MASKLWORD,
					       0x8810);
				odm_set_bb_reg(dm, R_0xaac, MASKDWORD,
					       0x01235567);
			}
		} else {
			odm_set_bb_reg(dm, R_0xa20, MASKDWORD, 0xe82c0001);
			odm_set_bb_reg(dm, R_0xa24, MASKDWORD, 0x64b80c1c);
			odm_set_bb_reg(dm, R_0xa28, MASKLWORD, 0x8810);
			odm_set_bb_reg(dm, R_0xaac, MASKDWORD, 0x01235667);
		}

		/* CCA parameters level*/
		dm->cca_cbw20_lev = 0;
		dm->cca_cbw40_lev = 0;

	} else if (central_ch > 35) {
		/* 5G */

		/* 1. RF band and channel*/
		rf_reg18 = (rf_reg18 & (~(BIT(19) | BIT(18) | BIT(17) | BIT(9) |
			    MASKBYTE0)));
		rf_reg18 = (rf_reg18 | BIT(16) | BIT(8) | central_ch);

		if (central_ch >= 36 && central_ch <= 64) {
			;
		} else if ((central_ch >= 100) && (central_ch <= 140)) {
			rf_reg18 = (rf_reg18 | BIT(18));
		} else if (central_ch > 140) {
			rf_reg18 = (rf_reg18 | BIT(19));
		} else {
			PHYDM_DBG(dm, ODM_PHY_CONFIG,
				  "%s: Fail to switch channel (RF18) (ch: %d)\n",
				  __func__, central_ch);
			return false;
		}

		/* 2. AGC table selection */
		if (central_ch >= 36 && central_ch <= 64) {
			odm_set_bb_reg(dm, 0x950, 0x1c000000, 0x1);
			dig_tab->agc_table_idx = 0x1;
		} else if ((central_ch >= 100) && (central_ch <= 144)) {
			odm_set_bb_reg(dm, 0x950, 0x1c000000, 0x4);
			dig_tab->agc_table_idx = 0x2;
		} else if (central_ch >= 149) {
			odm_set_bb_reg(dm, 0x950, 0x1c000000, 0x5);
			dig_tab->agc_table_idx = 0x3;
		} else {
			PHYDM_DBG(dm, ODM_PHY_CONFIG,
				  "%s: Fail to switch channel (AGC) (ch: %d)\n",
				  __func__, central_ch);
			return false;
		}

		/* 3. Set central frequency for clock offset tracking */
		if (central_ch >= 36 && central_ch <= 64) {
			odm_set_bb_reg(dm, 0xd2c, 0x00006000, 0x1);
		} else if (central_ch >= 100) {
			odm_set_bb_reg(dm, 0xd2c, 0x00006000, 0x2);
		} else {
			PHYDM_DBG(dm, ODM_PHY_CONFIG,
				  "%s: Fail to switch channel (fc_area) (ch: %d)\n",
				  __func__, central_ch);
			return false;
		}

		/* CCA parameters level*/
		if (central_ch <= 40 || central_ch >= 149 ||
		    (central_ch >= 100 && central_ch <= 116))
			dm->cca_cbw20_lev = 1;
		else if ((central_ch >= 44 && central_ch <= 52) ||
			 (central_ch >= 120 && central_ch <= 144))
			dm->cca_cbw20_lev = 2;
		else
			dm->cca_cbw20_lev = 3;

		if ((central_ch >= 102 && central_ch <= 122) ||
		    central_ch >= 151)
			dm->cca_cbw40_lev = 1;
		else if ((central_ch >= 38 && central_ch <= 50) ||
			 (central_ch >= 126 && central_ch <= 142))
			dm->cca_cbw40_lev = 2;
		else
			dm->cca_cbw40_lev = 3;

	} else {
		PHYDM_DBG(dm, ODM_PHY_CONFIG,
			  "%s: Fail to switch band (ch: %d)\n", __func__,
			  central_ch);
		return false;
	}

#if 0
	/*To avoid RTK saturation, reset RTK before switch band/channel*/
	odm_set_rf_reg(dm, RF_PATH_A, 0xDF, BIT(10), 0x1);
	odm_set_rf_reg(dm, RF_PATH_A, 0xDF, BIT(10), 0x0);
#endif
	odm_set_rf_reg(dm, RF_PATH_A, ODM_REG_CHNBW_11N, RFREGOFFSETMASK,
		       rf_reg18);

	if (!rf_reg_status) {
		PHYDM_DBG(dm, ODM_PHY_CONFIG,
			  "%s: Fail to switch channel (ch: %d), because writing RF register is fail\n",
			  __func__, central_ch);
		return false;
	}

	PHYDM_DBG(dm, ODM_PHY_CONFIG,
		  "%s: Success to switch channel (ch: %d)\n", __func__,
		  central_ch);
	return true;
}

boolean
config_phydm_switch_bandwidth_8721d(struct dm_struct *dm,
				    u8 primary_ch_idx,
				    enum channel_width bandwidth)
{
	u32 rf_reg18;
	boolean rf_reg_status = true;

	PHYDM_DBG(dm, ODM_PHY_CONFIG, "%s===================>\n", __func__);

	if (dm->is_disable_phy_api) {
		PHYDM_DBG(dm, ODM_PHY_CONFIG,
			  "%s: disable PHY API for debug!!\n", __func__);
		return true;
	}

	/* Error handling */

	if ((bandwidth >= CHANNEL_WIDTH_MAX) ||
	    ((bandwidth == CHANNEL_WIDTH_40) && (primary_ch_idx > 2))) {
		PHYDM_DBG(dm, ODM_PHY_CONFIG,
			  "%s: Fail to switch bandwidth (bw: %d, primary ch: %d)\n",
			  __func__, bandwidth, primary_ch_idx);
		return false;
	}

	rf_reg18 = config_phydm_read_rf_reg_8721d(dm, RF_PATH_A,
						  ODM_REG_CHNBW_11N,
						  RFREGOFFSETMASK);
	rf_reg_status = rf_reg_status &
			config_phydm_read_rf_check_8721d(rf_reg18);

	/* Switch bandwidth */
	switch (bandwidth) {
	case CHANNEL_WIDTH_20: {
		/* Small BW([31:30]) = 0, rf mode(800[0], 900[0]) = 0 for 20M */
		odm_set_bb_reg(dm, ODM_REG_SMALL_BANDWIDTH_11N,
			       (BIT(31) | BIT(30)), 0x0);
		odm_set_bb_reg(dm, ODM_REG_BB_CTRL_11N, BIT(0), 0x0);
		odm_set_bb_reg(dm, ODM_REG_BB_CTRL_PAGE9_11N, BIT(0), 0x0);

		if (dm->cbw20_adc80) {
			/* ADC clock = 80M clock for BW20*/
			odm_set_bb_reg(dm, ODM_REG_BB_CTRL_11N,
				       (BIT(10) | BIT(9) | BIT(8)), 0x4);

			/* DAC clock = 80M clock for BW20 */
			odm_set_bb_reg(dm, ODM_REG_BB_CTRL_11N,
				       (BIT(14) | BIT(13) | BIT(12)), 0x4);

			/* ADC buffer clock 0xce4[29:28] = 2'b01*/
			odm_set_bb_reg(dm, R_0xce4, (BIT(29) | BIT(28)), 0x1);
		} else {
			/* ADC clock = 160M clock for BW20*/
			odm_set_bb_reg(dm, ODM_REG_BB_CTRL_11N,
				       (BIT(10) | BIT(9) | BIT(8)), 0x5);

			/* DAC clock = 80M clock for BW20 */
			odm_set_bb_reg(dm, ODM_REG_BB_CTRL_11N,
				       (BIT(14) | BIT(13) | BIT(12)), 0x4);

			/* ADC buffer clock 0xce4[29:28] = 2'b10*/
			odm_set_bb_reg(dm, R_0xce4, (BIT(29) | BIT(28)), 0x2);
		}

		/* RF bandwidth */
		rf_reg18 = (rf_reg18 & (~(BIT(12) | BIT(11) | BIT(10))));
		rf_reg18 = (rf_reg18 | BIT(11) | BIT(10));
		break;
	}
	case CHANNEL_WIDTH_40: {
		/* Small BW([31:30]) = 0, rf mode(800[0], 900[0]) = 1 for 40M */
		odm_set_bb_reg(dm, ODM_REG_SMALL_BANDWIDTH_11N,
			       (BIT(31) | BIT(30)), 0x0);
		odm_set_bb_reg(dm, ODM_REG_BB_CTRL_11N, BIT(0), 0x1);
		odm_set_bb_reg(dm, ODM_REG_BB_CTRL_PAGE9_11N, BIT(0), 0x1);

		/* ADC clock = 160M clock for BW40 no need to setting*/
		/*it will be setting in PHY_REG */
		odm_set_bb_reg(dm, ODM_REG_BB_CTRL_11N,
			       (BIT(10) | BIT(9) | BIT(8)), 0x5);

		/* DAC clock = 80M clock for BW20 = 3'b10*/
		odm_set_bb_reg(dm, ODM_REG_BB_CTRL_11N,
			       (BIT(14) | BIT(13) | BIT(12)), 0x4);

		/* ADC buffer clock 0xce4[29:28] = 2'b10*/
		odm_set_bb_reg(dm, R_0xce4, (BIT(29) | BIT(28)), 0x2);

		/* CCK primary channel: */
		/*1: upper subchannel  0: lower subchannel */
		if (primary_ch_idx == 1)
			odm_set_bb_reg(dm, ODM_REG_CCK_ANTDIV_PARA1_11N,
				       BIT(4), primary_ch_idx);
		else
			odm_set_bb_reg(dm, ODM_REG_CCK_ANTDIV_PARA1_11N,
				       BIT(4), 0);

		/* RF bandwidth */
		rf_reg18 = (rf_reg18 & (~(BIT(12) | BIT(11) | BIT(10))));
		rf_reg18 = (rf_reg18 | BIT(11));
		break;
	}
	case CHANNEL_WIDTH_5: {
		/* Small BW([31:30]) = 1, rf mode(800[0], 900[0]) = 0 for 5M */
		odm_set_bb_reg(dm, ODM_REG_SMALL_BANDWIDTH_11N,
			       (BIT(31) | BIT(30)), 0x1);
		odm_set_bb_reg(dm, ODM_REG_BB_CTRL_11N, BIT(0), 0x0);
		odm_set_bb_reg(dm, ODM_REG_BB_CTRL_PAGE9_11N, BIT(0), 0x0);

		/* ADC clock = 80M clock for BW5 */
		odm_set_bb_reg(dm, ODM_REG_BB_CTRL_11N,
			       (BIT(10) | BIT(9) | BIT(8)), 0x4);

		/* DAC clock = 20M clock for BW5 */
		odm_set_bb_reg(dm, ODM_REG_BB_CTRL_11N,
			       (BIT(14) | BIT(13) | BIT(12)), 0x2);

		/* ADC buffer clock 0xce4[29:28] = 2'b11*/
		odm_set_bb_reg(dm, R_0xce4, (BIT(29) | BIT(28)), 0x3);

		/* RF bandwidth */
		rf_reg18 = (rf_reg18 & (~(BIT(12) | BIT(11) | BIT(10))));
		rf_reg18 = (rf_reg18 | BIT(11) | BIT(10));

		break;
	}
	case CHANNEL_WIDTH_10: {
		/* Small BW([31:30]) = 2, rf mode(800[0], 900[0]) = 0 for 10M */
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

		/* ADC buffer clock 0xce4[29:28] = 2'b10*/
		odm_set_bb_reg(dm, R_0xce4, (BIT(29) | BIT(28)), 0x2);

		/* RF bandwidth */
		rf_reg18 = (rf_reg18 & (~(BIT(12) | BIT(11) | BIT(10))));
		rf_reg18 = (rf_reg18 | BIT(11) | BIT(10));

		break;
	}
	default:
		PHYDM_DBG(dm, ODM_PHY_CONFIG,
			  "%s: Fail to switch bandwidth (bw: %d, primary ch: %d)\n",
			  __func__, bandwidth, primary_ch_idx);
	}

	/* Write RF register */
	odm_set_rf_reg(dm, RF_PATH_A, ODM_REG_CHNBW_11N, RFREGOFFSETMASK,
		       rf_reg18);

	if (!rf_reg_status) {
		PHYDM_DBG(dm, ODM_PHY_CONFIG,
			  "%s: Fail to switch bandwidth (bw: %d, primary ch: %d), because writing RF register is fail\n",
			  __func__, bandwidth, primary_ch_idx);
		return false;
	}

	/* Modify RX DFIR parameters */
	phydm_rx_dfir_par_by_bw_8721d(dm, bandwidth);

	/* Modify CCA parameters */
	phydm_cca_par_by_bw_8721d(dm, bandwidth);

	#ifdef PHYDM_PRIMARY_CCA
	/* Dynamic Primary CCA */
	/*phydm_primary_cca(dm)*/;
	#endif

#if 0
	/*2400M,2440M,2480M CSI mask for PATHB & PATHAB*/
	if (odm_get_bb_reg(dm, ODM_REG_BB_RX_PATH_11N, MASKBYTE0) != 0x11) {
		phydm_dynamic_spur_det_eliminate_8721d(dm);
	} else {
		odm_set_bb_reg(dm, R_0xd2c, BIT(28), 0x0);
		/*disable CSI mask function*/
		/* ADC clock = 160M clock for BW20*/
		odm_set_bb_reg(dm, R_0x800, (BIT(10) | BIT(9) | BIT(8)), 0x4);
		/* r_adc_upd0 0xca4[27:26] = 2'b10*/
		odm_set_bb_reg(dm, R_0xca4, (BIT(27) | BIT(26)), 0x2);
		/* r_tap_upd 0xe24[21:20] = 2'b10*/
		odm_set_bb_reg(dm, R_0xe24, (BIT(21) | BIT(20)), 0x2);
		/* Down_factor=4 0xc10[29:28]=0x2*/
		odm_set_bb_reg(dm, R_0xc10, (BIT(29) | BIT(28)), 0x2);
		/* enable DFIR stage 1 0x948[8]=1*/
		odm_set_bb_reg(dm, R_0x948, BIT(8), 0x1);
		/* DFIR stage0=3, stage1=10 0x948[3:0]=0x3 0x948[7:4]=0xa*/
		odm_set_bb_reg(dm, R_0x948,
			       (BIT(3) | BIT(2) | BIT(1) | BIT(0)), 0x3);
		odm_set_bb_reg(dm, R_0x948,
			       (BIT(7) | BIT(6) | BIT(5) | BIT(4)), 0xa);
	}
#endif

	PHYDM_DBG(dm, ODM_PHY_CONFIG,
		  "%s: Success to switch bandwidth (bw: %d, primary ch: %d)\n",
		  __func__, bandwidth, primary_ch_idx);
	return true;
}

boolean
config_phydm_switch_channel_bw_8721d(struct dm_struct *dm,
				     u8 central_ch,
				     u8 primary_ch_idx,
				     enum channel_width bandwidth)
{
	/* Switch band */
	if (config_phydm_switch_band_8721d(dm, central_ch) == false)
		return false;

	/* Switch channel */
	if (config_phydm_switch_channel_8721d(dm, central_ch) == false)
		return false;

	/* Switch bandwidth */
	if (config_phydm_switch_bandwidth_8721d(dm, primary_ch_idx,
						bandwidth) == false)
		return false;

	return true;
}

boolean
config_phydm_trx_mode_8721d(struct dm_struct *dm,
			    enum bb_path tx_path,
			    enum bb_path rx_path,
			    boolean is_tx2_path)
{
	return true;
}

boolean
config_phydm_parameter_init_8721d(struct dm_struct *dm,
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

/* ======================================================================== */
#endif /* RTL8721D_SUPPORT == 1 */
