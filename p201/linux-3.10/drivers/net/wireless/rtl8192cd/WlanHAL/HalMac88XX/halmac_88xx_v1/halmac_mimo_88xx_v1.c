/******************************************************************************
 *
 * Copyright(c) 2016 - 2019 Realtek Corporation. All rights reserved.
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
 ******************************************************************************/

#include "halmac_mimo_88xx_v1.h"

#if HALMAC_88XX_V1_SUPPORT

#define TXBF_CTRL_CFG	(BIT_ENABLE_NDPA | BIT_NDPA_PARA | BIT_EN_NDPA_INT | \
			 BIT_DIS_NDP_BFEN | BIT_TXBCN_NOBLOCK_NDP)
#define CSI_RATE_MAP	0x292911

static void
cfg_mu_bfee_88xx_v1(struct halmac_adapter *adapter,
		    struct halmac_cfg_mumimo_para *param);

static void
cfg_mu_bfer_88xx_v1(struct halmac_adapter *adapter,
		    struct halmac_cfg_mumimo_para *param);

/**
 * cfg_txbf_88xx_v1() - enable/disable specific user's txbf
 * @adapter : the adapter of halmac
 * @userid : su bfee userid = 0 or 1 to apply TXBF
 * @bw : the sounding bandwidth
 * @txbf_en : 0: disable TXBF, 1: enable TXBF
 * Author : chunchu
 * Return : enum halmac_ret_status
 * More details of status code can be found in prototype document
 */
enum halmac_ret_status
cfg_txbf_88xx_v1(struct halmac_adapter *adapter, u8 userid, enum halmac_bw bw,
		 u8 txbf_en)
{
	u16 tmp42c = 0;
	struct halmac_api *api = (struct halmac_api *)adapter->halmac_api;

	if (txbf_en) {
		switch (bw) {
		case HALMAC_BW_80:
			tmp42c |= BIT_TXBF0_80M_160M;
		case HALMAC_BW_40:
			tmp42c |= BIT_TXBF0_40M;
		case HALMAC_BW_20:
			tmp42c |= BIT_TXBF0_20M;
			break;
		default:
			return HALMAC_RET_INVALID_SOUNDING_SETTING;
		}
	}

	switch (userid) {
	case 0:
		tmp42c |= HALMAC_REG_R16(REG_TXBF_CTRL) &
			~(BIT_TXBF0_20M | BIT_TXBF0_40M | BIT_TXBF0_80M_160M);
		HALMAC_REG_W16(REG_TXBF_CTRL, tmp42c);
		break;
	case 1:
		tmp42c |= HALMAC_REG_R16(REG_TXBF_CTRL + 2) &
			~(BIT_TXBF0_20M | BIT_TXBF0_40M | BIT_TXBF0_80M_160M);
		HALMAC_REG_W16(REG_TXBF_CTRL + 2, tmp42c);
		break;
	default:
		return HALMAC_RET_INVALID_SOUNDING_SETTING;
	}

	PLTFM_MSG_TRACE("[TRACE]%s <===\n", __func__);

	return HALMAC_RET_SUCCESS;
}

/**
 * cfg_mumimo_88xx_v1() -config mumimo
 * @adapter : the adapter of halmac
 * @param : parameters to configure MU PPDU Tx/Rx
 * Author : chunchu
 * Return : enum halmac_ret_status
 * More details of status code can be found in prototype document
 */
enum halmac_ret_status
cfg_mumimo_88xx_v1(struct halmac_adapter *adapter,
		   struct halmac_cfg_mumimo_para *param)
{
	if (param->role == HAL_BFEE)
		cfg_mu_bfee_88xx_v1(adapter, param);
	else
		cfg_mu_bfer_88xx_v1(adapter, param);

	PLTFM_MSG_TRACE("[TRACE]%s <===\n", __func__);

	return HALMAC_RET_SUCCESS;
}

static void
cfg_mu_bfee_88xx_v1(struct halmac_adapter *adapter,
		    struct halmac_cfg_mumimo_para *param)
{
	u8 mu_tbl_sel;
	u32 tmp14c0;
	struct halmac_api *api = (struct halmac_api *)adapter->halmac_api;

	tmp14c0 = HALMAC_REG_R32(REG_MU_TX_CTRL) & ~BIT_MASK_MU_TAB_VALID;
	mu_tbl_sel = (u8)((tmp14c0 >> 8) & 0xf0);
	HALMAC_REG_W32(REG_MU_TX_CTRL, (tmp14c0 | BIT(5)) & ~BIT_MU_EN);

	mu_tbl_sel |= 5;

	HALMAC_REG_W8(REG_MU_TX_CTRL + 1, mu_tbl_sel);
	HALMAC_REG_W32(REG_MU_STA_GID_VLD, param->given_gid_tab[0]);
	HALMAC_REG_W32(REG_MU_STA_USER_POS_INFO, param->given_user_pos[0]);
	HALMAC_REG_W32(REG_MU_STA_USER_POS_INFO + 4, param->given_user_pos[1]);

	HALMAC_REG_W8(REG_MU_TX_CTRL + 1, mu_tbl_sel | (1 << 3));
	HALMAC_REG_W32(REG_MU_STA_GID_VLD, param->given_gid_tab[1]);
	HALMAC_REG_W32(REG_MU_STA_USER_POS_INFO, param->given_user_pos[2]);
	HALMAC_REG_W32(REG_MU_STA_USER_POS_INFO + 4, param->given_user_pos[3]);
}

static void
cfg_mu_bfer_88xx_v1(struct halmac_adapter *adapter,
		    struct halmac_cfg_mumimo_para *param)
{
	struct halmac_api *api = (struct halmac_api *)adapter->halmac_api;
	u8 usr_idx;
	u8 mu_tbl_sel;
	u8 mu_tab_valid = 0;
	u32 gid_valid = 0x00000002;
	u32 tmp14c0;

	tmp14c0 = HALMAC_REG_R32(REG_MU_TX_CTRL) & ~BIT_MASK_MU_TAB_VALID;

	if (param->mu_tx_en == 0) {
		HALMAC_REG_W32(REG_MU_TX_CTRL, tmp14c0 & ~BIT_MU_EN);
		return;
	}

	for (usr_idx = 0; usr_idx < 4; usr_idx++) {
		mu_tbl_sel = (u8)((tmp14c0 >> 8) & 0xf0);
		HALMAC_REG_W8(REG_MU_TX_CTRL + 1, mu_tbl_sel | usr_idx);
		if (param->sounding_sts[usr_idx] == 1) {
			mu_tab_valid |= BIT(usr_idx);
			HALMAC_REG_W32(REG_MU_STA_GID_VLD, gid_valid);
		} else {
			HALMAC_REG_W8(REG_MU_TX_CTRL + 1, mu_tbl_sel | usr_idx);
			HALMAC_REG_W32(REG_MU_STA_GID_VLD, 0);
		}
	}

	HALMAC_REG_W32(REG_MU_TX_CTRL, tmp14c0 | mu_tab_valid);
}

/**
 * cfg_sounding_88xx_v1() - configure general sounding
 * @adapter : the adapter of halmac
 * @role : driver's role, BFer or BFee
 * @rate : set ndpa tx rate if driver is BFer,
 * or set csi response rate if driver is BFee
 * Author : chunchu
 * Return : enum halmac_ret_status
 * More details of status code can be found in prototype document
 */
enum halmac_ret_status
cfg_sounding_88xx_v1(struct halmac_adapter *adapter, enum halmac_snd_role role,
		     enum halmac_data_rate rate)
{
	struct halmac_api *api = (struct halmac_api *)adapter->halmac_api;
	u32 tmp6dc = 0;

	tmp6dc = HALMAC_REG_R32(REG_BBPSF_CTRL) & (~BITS_CSI_RSC)
							& (~BITS_WMAC_CSI_RATE);

	switch (role) {
	case HAL_BFER:
		HALMAC_REG_W32_SET(REG_TXBF_CTRL, TXBF_CTRL_CFG);
		HALMAC_REG_W8(REG_NDPA_RATE, rate);
		HALMAC_REG_W8(REG_SND_PTCL_CTRL + 1, 0x2 | BIT(7));
		HALMAC_REG_W8(REG_SND_PTCL_CTRL + 2, 0x2);
		break;
	case HAL_BFEE:
		HALMAC_REG_W8(REG_SND_PTCL_CTRL, 0xDB);
		HALMAC_REG_W8(REG_SND_PTCL_CTRL + 3, 0x26);
		HALMAC_REG_W8_CLR(REG_RXFLTMAP1, BIT(4));
		HALMAC_REG_W8_CLR(REG_RXFLTMAP4, BIT(4));
		/*Mask csi length threshold to fix tx_sc bug at OFDM rate*/
		HALMAC_REG_W32(REG_CSI_RRSR,
			       BIT_CSI_RRSC_BITMAP(CSI_RATE_MAP) |
			       BIT_OFDM_LEN_TH(0));
		break;
	default:
		return HALMAC_RET_INVALID_SOUNDING_SETTING;
	}

	tmp6dc |= BIT_WMAC_USE_NDPARATE | BIT_CSI_RSC(1) |
					BIT_WMAC_CSI_RATE(HALMAC_VHT_NSS1_MCS5);
	if (BIT_GET_NETYPE0(HALMAC_REG_R32(REG_CR)) == 0x3)
		HALMAC_REG_W32(REG_BBPSF_CTRL, tmp6dc | BIT_CSI_GID_SEL);
	else
		HALMAC_REG_W32(REG_BBPSF_CTRL, tmp6dc & (~BIT_CSI_GID_SEL));

	PLTFM_MSG_TRACE("[TRACE]%s <===\n", __func__);

	return HALMAC_RET_SUCCESS;
}

/**
 * del_sounding_88xx_v1() - reset general sounding
 * @adapter : the adapter of halmac
 * @role : driver's role, BFer or BFee
 * Author : chunchu
 * Return : enum halmac_ret_status
 * More details of status code can be found in prototype document
 */
enum halmac_ret_status
del_sounding_88xx_v1(struct halmac_adapter *adapter, enum halmac_snd_role role)
{
	struct halmac_api *api = (struct halmac_api *)adapter->halmac_api;

	switch (role) {
	case HAL_BFER:
		HALMAC_REG_W8(REG_TXBF_CTRL + 3, 0);
		break;
	case HAL_BFEE:
		HALMAC_REG_W8(REG_SND_PTCL_CTRL, 0);
		break;
	default:
		return HALMAC_RET_INVALID_SOUNDING_SETTING;
	}

	PLTFM_MSG_TRACE("[TRACE]%s <===\n", __func__);

	return HALMAC_RET_SUCCESS;
}

/**
 * su_bfee_entry_init_88xx_v1() - config SU beamformee's registers
 * @adapter : the adapter of halmac
 * @userid : SU bfee userid = 0 or 1 to be added
 * @paid : partial AID of this bfee
 * Author : chunchu
 * Return : enum halmac_ret_status
 * More details of status code can be found in prototype document
 */
enum halmac_ret_status
su_bfee_entry_init_88xx_v1(struct halmac_adapter *adapter, u8 userid, u16 paid)
{
	u16 tmp42c = 0;
	u16 tmp168x = 0;
	struct halmac_api *api = (struct halmac_api *)adapter->halmac_api;

	switch (userid) {
	case 0:
		tmp42c = HALMAC_REG_R16(REG_TXBF_CTRL) &
				~(BIT_MASK_TXBF0_AID | BIT_TXBF0_20M |
				BIT_TXBF0_40M | BIT_TXBF0_80M_160M);
		HALMAC_REG_W16(REG_TXBF_CTRL, tmp42c | paid);
		HALMAC_REG_W16(REG_ASSOCIATED_BFMEE_SEL, paid | BIT(9));
		break;
	case 1:
		tmp42c = HALMAC_REG_R16(REG_TXBF_CTRL + 2) &
				~(BIT_MASK_TXBF1_AID | BIT_TXBF0_20M |
				BIT_TXBF0_40M | BIT_TXBF0_80M_160M);
		HALMAC_REG_W16(REG_TXBF_CTRL + 2, tmp42c | paid);
		HALMAC_REG_W16(REG_ASSOCIATED_BFMEE_SEL + 2, paid | BIT(9));
		break;
	case 2:
		tmp168x = HALMAC_REG_R16(REG_WMAC_ASSOCIATED_MU_BFMEE2);
		tmp168x = BIT_CLEAR_WMAC_MU_BFEE2_AID(tmp168x);
		tmp168x |= (paid | BIT(9));
		HALMAC_REG_W16(REG_WMAC_ASSOCIATED_MU_BFMEE2, tmp168x);
		break;
	case 3:
		tmp168x = HALMAC_REG_R16(REG_WMAC_ASSOCIATED_MU_BFMEE3);
		tmp168x = BIT_CLEAR_WMAC_MU_BFEE3_AID(tmp168x);
		tmp168x |= (paid | BIT(9));
		HALMAC_REG_W16(REG_WMAC_ASSOCIATED_MU_BFMEE3, tmp168x);
		break;
	case 4:
		tmp168x = HALMAC_REG_R16(REG_WMAC_ASSOCIATED_MU_BFMEE4);
		tmp168x = BIT_CLEAR_WMAC_MU_BFEE4_AID(tmp168x);
		tmp168x |= (paid | BIT(9));
		HALMAC_REG_W16(REG_WMAC_ASSOCIATED_MU_BFMEE4, tmp168x);
		break;
	case 5:
		tmp168x = HALMAC_REG_R16(REG_WMAC_ASSOCIATED_MU_BFMEE5);
		tmp168x = BIT_CLEAR_WMAC_MU_BFEE5_AID(tmp168x);
		tmp168x |= (paid | BIT(9));
		HALMAC_REG_W16(REG_WMAC_ASSOCIATED_MU_BFMEE5, tmp168x);
		break;
	default:
		return HALMAC_RET_INVALID_SOUNDING_SETTING;
	}

	PLTFM_MSG_TRACE("[TRACE]%s <===\n", __func__);

	return HALMAC_RET_SUCCESS;
}

/**
 * su_bfee_entry_init_88xx_v1() - config SU beamformer's registers
 * @adapter : the adapter of halmac
 * @param : parameters to configure SU BFER entry
 * Author : chunchu
 * Return : enum halmac_ret_status
 * More details of status code can be found in prototype document
 */
enum halmac_ret_status
su_bfer_entry_init_88xx_v1(struct halmac_adapter *adapter,
			   struct halmac_su_bfer_init_para *param)
{
	u16 mac_addr_h;
	u32 mac_addr_l;
	struct halmac_api *api = (struct halmac_api *)adapter->halmac_api;

	mac_addr_l = rtk_le32_to_cpu(param->bfer_address.addr_l_h.low);
	mac_addr_h = rtk_le16_to_cpu(param->bfer_address.addr_l_h.high);

	switch (param->userid) {
	case 0:
		HALMAC_REG_W32(REG_ASSOCIATED_BFMER0_INFO, mac_addr_l);
		HALMAC_REG_W16(REG_ASSOCIATED_BFMER0_INFO + 4, mac_addr_h);
		HALMAC_REG_W16(REG_ASSOCIATED_BFMER0_INFO + 6, param->paid);
		HALMAC_REG_W16(REG_TX_CSI_RPT_PARAM_BW20, param->csi_para);
		break;
	case 1:
		HALMAC_REG_W32(REG_ASSOCIATED_BFMER1_INFO, mac_addr_l);
		HALMAC_REG_W16(REG_ASSOCIATED_BFMER1_INFO + 4, mac_addr_h);
		HALMAC_REG_W16(REG_ASSOCIATED_BFMER1_INFO + 6, param->paid);
		HALMAC_REG_W16(REG_TX_CSI_RPT_PARAM_BW20 + 2, param->csi_para);
		break;
	default:
		return HALMAC_RET_INVALID_SOUNDING_SETTING;
	}

	PLTFM_MSG_TRACE("[TRACE]%s <===\n", __func__);
	return HALMAC_RET_SUCCESS;
}

/**
 * mu_bfee_entry_init_88xx_v1() - config MU beamformee's registers
 * @adapter : the adapter of halmac
 * @param : parameters to configure MU BFEE entry
 * Author : chunchu
 * Return : enum halmac_ret_status
 * More details of status code can be found in prototype document
 */
enum halmac_ret_status
mu_bfee_entry_init_88xx_v1(struct halmac_adapter *adapter,
			   struct halmac_mu_bfee_init_para *param)
{
	u16 tmp168x = 0;
	u16 tmp14c0;
	struct halmac_api *api = (struct halmac_api *)adapter->halmac_api;

	tmp168x |= param->paid | BIT(9);
	HALMAC_REG_W16((REG_WMAC_MU_BF_CTL + param->userid * 2), tmp168x);

	tmp14c0 = BIT_CLEAR_MU_TAB_SEL(HALMAC_REG_R16(REG_MU_TX_CTRL));

	/*clear GID 0~31*/
	HALMAC_REG_W16(REG_MU_TX_CTRL, tmp14c0 |
					BIT_MU_TAB_SEL(param->userid - 2));
	HALMAC_REG_W32(REG_MU_STA_GID_VLD, 0);

	/*initialize user position of GID0~31*/
	HALMAC_REG_W32(REG_MU_STA_USER_POS_INFO, param->user_position_l);
	HALMAC_REG_W32(REG_MU_STA_USER_POS_INFO + 4, param->user_position_h);

	/*clear GID 32~63, always invalid in 8814B*/
	HALMAC_REG_W16(REG_MU_TX_CTRL, tmp14c0 |
				BIT_MU_TAB_SEL(param->userid - 2) | BIT(11));
	HALMAC_REG_W32(REG_MU_STA_GID_VLD, 0);

	/*initialize user position of GID32~63, for HW verification only*/
	HALMAC_REG_W32(REG_MU_STA_USER_POS_INFO, param->user_position_l_1);
	HALMAC_REG_W32(REG_MU_STA_USER_POS_INFO + 4, param->user_position_h_1);

	PLTFM_MSG_TRACE("[TRACE]%s <===\n", __func__);

	return HALMAC_RET_SUCCESS;
}

/**
 * mu_bfer_entry_init_88xx_v1() - config MU beamformer's registers
 * @adapter : the adapter of halmac
 * @param : parameters to configure MU BFER entry
 * Author : chunchu
 * Return : enum halmac_ret_status
 * More details of status code can be found in prototype document
 */
enum halmac_ret_status
mu_bfer_entry_init_88xx_v1(struct halmac_adapter *adapter,
			   struct halmac_mu_bfer_init_para *param)
{
	u16 tmp1680 = 0;
	u16 mac_addr_h;
	u32 mac_addr_l;
	struct halmac_api *api = (struct halmac_api *)adapter->halmac_api;

	mac_addr_l = rtk_le32_to_cpu(param->bfer_address.addr_l_h.low);
	mac_addr_h = rtk_le16_to_cpu(param->bfer_address.addr_l_h.high);

	HALMAC_REG_W32(REG_ASSOCIATED_BFMER0_INFO, mac_addr_l);
	HALMAC_REG_W16(REG_ASSOCIATED_BFMER0_INFO + 4, mac_addr_h);
	HALMAC_REG_W16(REG_ASSOCIATED_BFMER0_INFO + 6, param->paid);
	HALMAC_REG_W16(REG_TX_CSI_RPT_PARAM_BW20, param->csi_para);

	tmp1680 = HALMAC_REG_R16(REG_WMAC_MU_BF_CTL) & 0xC000;
	tmp1680 |= param->my_aid | (param->csi_length_sel << 12);
	HALMAC_REG_W16(REG_WMAC_MU_BF_CTL, tmp1680);

	PLTFM_MSG_TRACE("[TRACE]%s <===\n", __func__);

	return HALMAC_RET_SUCCESS;
}

/**
 * su_bfee_entry_del_88xx_v1() - reset SU beamformee's registers
 * @adapter : the adapter of halmac
 * @userid : the SU BFee userid to be deleted
 * Author : chunchu
 * Return : enum halmac_ret_status
 * More details of status code can be found in prototype document
 */
enum halmac_ret_status
su_bfee_entry_del_88xx_v1(struct halmac_adapter *adapter, u8 userid)
{
	u16 value16;
	struct halmac_api *api = (struct halmac_api *)adapter->halmac_api;

	switch (userid) {
	case 0:
		value16 = HALMAC_REG_R16(REG_TXBF_CTRL);
		value16 &= ~(BIT_MASK_TXBF0_AID | BIT_TXBF0_20M |
					BIT_TXBF0_40M | BIT_TXBF0_80M_160M);
		HALMAC_REG_W16(REG_TXBF_CTRL, value16);
		HALMAC_REG_W16(REG_ASSOCIATED_BFMEE_SEL, 0);
		break;
	case 1:
		value16 = HALMAC_REG_R16(REG_TXBF_CTRL + 2);
		value16 &= ~(BIT_MASK_TXBF1_AID | BIT_TXBF0_20M |
					BIT_TXBF0_40M | BIT_TXBF0_80M_160M);
		HALMAC_REG_W16(REG_TXBF_CTRL + 2, value16);
		HALMAC_REG_W16(REG_ASSOCIATED_BFMEE_SEL + 2, 0);
		break;
	case 2:
		HALMAC_REG_W16(REG_WMAC_ASSOCIATED_MU_BFMEE2, 0);
		break;
	case 3:
		HALMAC_REG_W16(REG_WMAC_ASSOCIATED_MU_BFMEE3, 0);
		break;
	case 4:
		HALMAC_REG_W16(REG_WMAC_ASSOCIATED_MU_BFMEE4, 0);
		break;
	case 5:
		HALMAC_REG_W16(REG_WMAC_ASSOCIATED_MU_BFMEE5, 0);
		break;
	default:
		return HALMAC_RET_INVALID_SOUNDING_SETTING;
	}

	PLTFM_MSG_TRACE("[TRACE]%s <===\n", __func__);

	return HALMAC_RET_SUCCESS;
}

/**
 * su_bfee_entry_del_88xx_v1() - reset SU beamformer's registers
 * @adapter : the adapter of halmac
 * @userid : the SU BFer userid to be deleted
 * Author : chunchu
 * Return : enum halmac_ret_status
 * More details of status code can be found in prototype document
 */
enum halmac_ret_status
su_bfer_entry_del_88xx_v1(struct halmac_adapter *adapter, u8 userid)
{
	struct halmac_api *api = (struct halmac_api *)adapter->halmac_api;

	switch (userid) {
	case 0:
		HALMAC_REG_W32(REG_ASSOCIATED_BFMER0_INFO, 0);
		HALMAC_REG_W32(REG_ASSOCIATED_BFMER0_INFO + 4, 0);
		break;
	case 1:
		HALMAC_REG_W32(REG_ASSOCIATED_BFMER1_INFO, 0);
		HALMAC_REG_W32(REG_ASSOCIATED_BFMER1_INFO + 4, 0);
		break;
	default:
		return HALMAC_RET_INVALID_SOUNDING_SETTING;
	}

	PLTFM_MSG_TRACE("[TRACE]%s <===\n", __func__);
	return HALMAC_RET_SUCCESS;
}

/**
 * mu_bfee_entry_del_88xx_v1() - reset MU beamformee's registers
 * @adapter : the adapter of halmac
 * @userid : the MU STA userid to be deleted
 * Author : chunchu
 * Return : enum halmac_ret_status
 * More details of status code can be found in prototype document
 */
enum halmac_ret_status
mu_bfee_entry_del_88xx_v1(struct halmac_adapter *adapter, u8 userid)
{
	struct halmac_api *api = (struct halmac_api *)adapter->halmac_api;

	HALMAC_REG_W16(REG_WMAC_MU_BF_CTL + userid * 2, 0);
	HALMAC_REG_W8_CLR(REG_MU_TX_CTRL, BIT(userid - 2));

	PLTFM_MSG_TRACE("[TRACE]%s <===\n", __func__);

	return HALMAC_RET_SUCCESS;
}

/**
 * mu_bfer_entry_del_88xx_v1() -reset MU beamformer's registers
 * @adapter : the adapter of halmac
 * Author : chunchu
 * Return : enum halmac_ret_status
 * More details of status code can be found in prototype document
 */
enum halmac_ret_status
mu_bfer_entry_del_88xx_v1(struct halmac_adapter *adapter)
{
	struct halmac_api *api = (struct halmac_api *)adapter->halmac_api;

	HALMAC_REG_W32(REG_ASSOCIATED_BFMER0_INFO, 0);
	HALMAC_REG_W32(REG_ASSOCIATED_BFMER0_INFO + 4, 0);
	HALMAC_REG_W16(REG_WMAC_MU_BF_CTL, 0);
	HALMAC_REG_W8(REG_MU_TX_CTRL, 0);

	PLTFM_MSG_TRACE("[TRACE]%s <===\n", __func__);

	return HALMAC_RET_SUCCESS;
}

/**
 * cfg_csi_rate_88xx_v1() - config CSI frame Tx rate
 * @adapter : the adapter of halmac
 * @rssi : rssi in decimal value
 * @cur_rate : current CSI frame rate
 * @fixrate_en : enable to fix CSI frame in VHT rate, otherwise legacy OFDM rate
 * @new_rate : API returns the final CSI frame rate
 * Author : chunchu
 * Return : enum halmac_ret_status
 * More details of status code can be found in prototype document
 */
enum halmac_ret_status
cfg_csi_rate_88xx_v1(struct halmac_adapter *adapter, u8 rssi, u8 cur_rate,
		     u8 fixrate_en, u8 *new_rate, u8 *bmp_ofdm54)
{
	u32 csi_cfg;
	struct halmac_api *api = (struct halmac_api *)adapter->halmac_api;

	PLTFM_MSG_TRACE("[TRACE]%s ===>\n", __func__);

	csi_cfg = HALMAC_REG_R32(REG_BBPSF_CTRL) & (~BITS_WMAC_CSI_RATE);

	if (fixrate_en) {
		HALMAC_REG_W32(REG_BBPSF_CTRL,
			       csi_cfg | BIT_CSI_FORCE_RATE_EN |
			       BIT_WMAC_CSI_RATE(cur_rate));
		*new_rate = cur_rate;
	} else {
		HALMAC_REG_W32(REG_BBPSF_CTRL,
			       (csi_cfg & (~BIT_CSI_FORCE_RATE_EN)) |
			       BIT_WMAC_CSI_RATE(HALMAC_VHT_NSS1_MCS5));
		*new_rate = 0;
	}

	return HALMAC_RET_SUCCESS;
}

/**
 * fw_snding_88xx_v1() - fw sounding control
 * @adapter : the adapter of halmac
 * @su_info :
 *	su0_en : enable/disable fw sounding
 *	su0_ndpa_pkt : ndpa pkt, shall include txdesc
 *	su0_pkt_sz : ndpa pkt size, shall include txdesc
 * @mu_info : currently not in use, input NULL is acceptable
 * @period : sounding period, unit is 5ms
 * Author : Ivan Lin
 * Return : enum halmac_ret_status
 * More details of status code can be found in prototype document
 */
enum halmac_ret_status
fw_snding_88xx_v1(struct halmac_adapter *adapter,
		  struct halmac_su_snding_info *su_info,
		  struct halmac_mu_snding_info *mu_info, u8 period)
{
	return HALMAC_RET_NOT_SUPPORT;
}

#endif /* HALMAC_88XX_V1_SUPPORT */
