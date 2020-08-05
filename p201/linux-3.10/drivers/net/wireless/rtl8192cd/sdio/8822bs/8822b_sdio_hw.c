/*
 *  SDIO core routines
 *
 *  Copyright (c) 2017 Realtek Semiconductor Corp.
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License version 2 as
 *  published by the Free Software Foundation.
 */

#define _8822B_SDIO_HW_C_

#ifdef __KERNEL__
#include <linux/module.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#endif

#include "8192cd.h"
#include "8192cd_headers.h"
#include "8192cd_debug.h"
#include "WlanHAL/HalHeader/HalComBit.h"
#include "WlanHAL/HalHeader/HalComReg.h"


extern struct _device_info_ wlan_device[];
extern int drv_registered;


extern int MDL_DEVINIT rtl8192cd_init_one(struct sdio_func *psdio_func,
		const struct sdio_device_id *ent, struct _device_info_ *wdev, int vap_idx);
extern void rtl8192cd_deinit_one(struct rtl8192cd_priv *priv);

extern VOID SetDTIM(IN  HAL_PADAPTER Adapter);


static int MDL_DEVINIT rtw_drv_init(struct sdio_func *psdio_func, const struct sdio_device_id *pdid)
{
	int ret;
#ifdef MBSSID
	int i;
#endif
	printk("%s: sdio_func_id is \"%s\"\n", __func__, sdio_func_id(psdio_func));
	
	ret = rtl8192cd_init_one(psdio_func, pdid, &wlan_device[0], -1);
	if (ret)
		goto error;
	
#ifdef UNIVERSAL_REPEATER
	ret = rtl8192cd_init_one(psdio_func, pdid, &wlan_device[0], -1);
	if (ret)
		goto error;
#endif

#ifdef MBSSID
	for (i = 0; i < RTL8192CD_NUM_VWLAN; i++) {
		ret = rtl8192cd_init_one(psdio_func, pdid, &wlan_device[0], i);
		if (ret)
			goto error;
	}
#endif
	/*
	if(usb_dvobj_init(wlan_device[wlan_index].priv) != SUCCESS) {
		ret = -ENOMEM;
	}
	*/
	
	return 0;

error:
	if (NULL != wlan_device[0].priv) {
		rtl8192cd_deinit_one(wlan_device[0].priv);
		wlan_device[0].priv = NULL;
	}

	return ret;
}

static void MDL_DEVEXIT rtw_dev_remove(struct sdio_func *psdio_func)
{
	struct net_device *dev = sdio_get_drvdata(psdio_func);
	struct rtl8192cd_priv *priv = GET_DEV_PRIV(dev);
	
	printk("%s: sdio_func_id is \"%s\"\n", __func__, sdio_func_id(psdio_func));
	
	sdio_set_drvdata(psdio_func, NULL);

	if (priv) {
		priv->pshare->bDriverStopped = TRUE;
		if (TRUE == drv_registered)
			priv->pshare->bSurpriseRemoved = TRUE;
	}

	if (NULL != wlan_device[0].priv) {
		rtl8192cd_deinit_one(wlan_device[0].priv);
		wlan_device[0].priv = NULL;
	}
}

static const struct sdio_device_id rtw_sdio_id_tbl[] = {
#ifdef CONFIG_RTL_88E_SUPPORT
	{ SDIO_DEVICE(0x024c, 0x8179) },
#endif
#ifdef CONFIG_WLAN_HAL_8192EE
	{ SDIO_DEVICE(0x024c, 0x818b) },
#endif
#ifdef CONFIG_WLAN_HAL_8822BE
	{ SDIO_DEVICE(0x024c, 0xb822) },
#endif
	{}	/* Terminating entry */
};

MODULE_DEVICE_TABLE(sdio, rtw_sdio_id_tbl);

#ifdef CONFIG_POWER_SAVE
static const struct dev_pm_ops rtw_sdio_pm_ops = {
	.prepare = rtw_sdio_prepare,
	.complete = rtw_sdio_complete,
	.suspend = rtw_sdio_suspend,
	.resume	 = rtw_sdio_resume,
};
#endif

struct sdio_driver rtl8192cd_sdio_driver = {
	.name = (char*)DRV_NAME,
	.id_table = rtw_sdio_id_tbl,
	.probe = rtw_drv_init,
	.remove = rtw_dev_remove,
#ifdef CONFIG_POWER_SAVE
	.drv = {
		.owner = THIS_MODULE,
		.pm = &rtw_sdio_pm_ops,
	}
#endif
};

u8 _CardEnable(struct rtl8192cd_priv *priv)
{
	unsigned char errorFlag ;

	if ( RT_STATUS_SUCCESS != GET_HAL_INTERFACE(priv)->InitPONHandler(priv, XTAL_CLK_SEL_40M) ) {
		GET_HAL_INTERFACE(priv)->GetHwRegHandler(priv, HW_VAR_DRV_DBG, (unsigned char *)&errorFlag);
		errorFlag |= DRV_ER_INIT_PON;
		GET_HAL_INTERFACE(priv)->SetHwRegHandler(priv, HW_VAR_DRV_DBG, (unsigned char *)&errorFlag);
		panic_printk("InitPON Failed\n");
		return FAIL;
	} else {
		printk("InitPON OK\n");
	}
	return SUCCESS;
}

#ifdef MBSSID
void rtl8192cd_init_mbssid(struct rtl8192cd_priv *priv)
{
	int i, j;
	unsigned int camData[2];
	unsigned char *macAddr = GET_MY_HWADDR;
	unsigned int inter_bcn_space;
	int nr_vap;
	_irqL irqL;

	SMP_LOCK_MBSSID(&irqL);

	if (IS_ROOT_INTERFACE(priv))
	{
		camData[0] = BIT_MBIDCAM_POLL | BIT_MBIDCAM_WT_EN | BIT_MBIDCAM_VALID | (macAddr[5] << 8) | macAddr[4];
		camData[1] = (macAddr[3] << 24) | (macAddr[2] << 16) | (macAddr[1] << 8) | macAddr[0];
		for (j=1; j>=0; j--) {
			RTL_W32((REG_MBIDCAMCFG_1+4)-4*j, camData[j]);
		}

		// clear the rest area of CAM
		camData[1] = 0;
		for (i=1; i<8; i++) {
			camData[0] = BIT_MBIDCAM_POLL | BIT_MBIDCAM_WT_EN | (i & BIT_MASK_MBIDCAM_ADDR)<<BIT_SHIFT_MBIDCAM_ADDR;
			for (j=1; j>=0; j--) {
				RTL_W32((REG_MBIDCAMCFG_1+4)-4*j, camData[j]);
			}
		}
		
		priv->pshare->bcn_priv[0] = priv;
		priv->pshare->inter_bcn_space = priv->pmib->dot11StationConfigEntry.dot11BeaconPeriod * NET80211_TU_TO_US;

		if (priv->pmib->miscEntry.func_off) {
			priv->func_off_already = 1;
			priv->pshare->nr_bcn = 0;
			RTL_W8(REG_MBSSID_CTRL, RTL_R8(REG_MBSSID_CTRL) & ~BIT0);
		} else {
			priv->pshare->nr_bcn = 1;
			RTL_W8(REG_MBSSID_CTRL, RTL_R8(REG_MBSSID_CTRL) | BIT0);
		}

		RTL_W16(REG_MBSSID_BCN_SPACE,
			(priv->pmib->dot11StationConfigEntry.dot11BeaconPeriod & BIT_MASK_BCN_SPACE0)<<BIT_SHIFT_BCN_SPACE0);
		RTL_W16(REG_MBSSID_BCN_SPACE3 + 2,
			(priv->pmib->dot11StationConfigEntry.dot11BeaconPeriod & BIT_MASK_BCN_SPACE0)<<BIT_SHIFT_BCN_SPACE0);
		
		RTL_W8(REG_BCN_CTRL, 0);
		RTL_W8(REG_DUAL_TSF_RST, 1);
		RTL_W8(REG_BCN_CTRL, BIT_EN_BCN_FUNCTION|BIT_DIS_TSF_UDT|BIT_P0_EN_TXBCN_RPT | BIT_DIS_RX_BSSID_FIT);

		RTL_W32(REG_RCR, RTL_R32(REG_RCR) | BIT_ENMBID);	// MBSSID enable
		
		// SW control use BCNQ0 for Root-only
		RTL_W32(REG_AUTO_LLT_V1, RTL_R32(REG_AUTO_LLT_V1) & ~BIT_R_BCN_HEAD_SEL | BIT_R_EN_BCN_SW_HEAD_SEL);
	}
	else if (IS_VAP_INTERFACE(priv))
	{
		if (priv->pmib->miscEntry.func_off) {
			priv->func_off_already = 1;
			priv->vap_init_seq = 0;
			SMP_UNLOCK_MBSSID(&irqL);
			return;
		}
		
		nr_vap = priv->pshare->nr_bcn;
		priv->vap_init_seq = nr_vap;
		
		SetDTIM(priv);

		camData[0] = BIT_MBIDCAM_POLL | BIT_MBIDCAM_WT_EN | BIT_MBIDCAM_VALID |
				(priv->vap_init_seq & BIT_MASK_MBIDCAM_ADDR)<<BIT_SHIFT_MBIDCAM_ADDR |
				(macAddr[5] << 8) | macAddr[4];
		camData[1] = (macAddr[3] << 24) | (macAddr[2] << 16) | (macAddr[1] << 8) | macAddr[0];
		for (j=1; j>=0; j--) {
			RTL_W32((REG_MBIDCAMCFG_1+4)-4*j, camData[j]);
		}
		
		inter_bcn_space = priv->pmib->dot11StationConfigEntry.dot11BeaconPeriod/(nr_vap+1);
		if (inter_bcn_space > 200)
			inter_bcn_space = 200;
		
		priv->pshare->bcn_priv[nr_vap] = priv;
		priv->pshare->nr_bcn++;
		priv->pshare->inter_bcn_space = inter_bcn_space * NET80211_TU_TO_US;
		
		RTL_W8(REG_MBSSID_CTRL, RTL_R8(REG_MBSSID_CTRL) | BIT(priv->vap_init_seq));
		
		RTL_W16(REG_MBSSID_BCN_SPACE,
			(priv->pmib->dot11StationConfigEntry.dot11BeaconPeriod & BIT_MASK_BCN_SPACE0)<<BIT_SHIFT_BCN_SPACE0);
		RTL_W16(REG_MBSSID_BCN_SPACE3 + 2,
			(inter_bcn_space & BIT_MASK_BCN_SPACE0)<<BIT_SHIFT_BCN_SPACE0);
		
		RTL_W8(REG_BCN_CTRL, 0);
		RTL_W8(REG_DUAL_TSF_RST, 1);
		RTL_W8(REG_BCN_CTRL, BIT_EN_BCN_FUNCTION | BIT_DIS_TSF_UDT|BIT_P0_EN_TXBCN_RPT |BIT_DIS_RX_BSSID_FIT);
		RTL_W8(REG_MBID_NUM, (RTL_R8(REG_MBID_NUM) & ~BIT_MASK_MBID_BCN_NUM) | (nr_vap & BIT_MASK_MBID_BCN_NUM));
		
		RTL_W32(REG_RCR, RTL_R32(REG_RCR) & ~BIT_ENMBID);
		RTL_W32(REG_RCR, RTL_R32(REG_RCR) | BIT_ENMBID);	// MBSSID enable
	}
	
	SMP_UNLOCK_MBSSID(&irqL);
}

extern void hal_fill_bcn_desc(struct rtl8192cd_priv *priv, struct tx_desc *pdesc, void *dat_content, unsigned short txLength, char forceUpdate);

void __rtl8192cd_sort_mbssid_bcn(struct rtl8192cd_priv *priv)
{
	struct rtl8192cd_priv *priv_root, *priv_vap;
	unsigned char *macAddr;
	unsigned char mbssid_ctrl;
	int nr_bcn, nr_vap;
	
	int i, j;
	unsigned int camData[2];
	unsigned int inter_bcn_space;
	
	camData[1] = 0;

	for (i = 0; i <= priv->pshare->nr_bcn; ++i) {
		camData[0] = BIT_MBIDCAM_POLL | BIT_MBIDCAM_WT_EN |
			(i & BIT_MASK_MBIDCAM_ADDR)<<BIT_SHIFT_MBIDCAM_ADDR;
		for (j=1; j>=0; j--) {
			RTL_W32((REG_MBIDCAMCFG_1+4)-4*j, camData[j]);
		}
	}

	nr_bcn = 0;
	mbssid_ctrl = 0x0FF;
	priv_root = GET_ROOT(priv);
	
	macAddr = priv_root->pmib->dot11OperationEntry.hwaddr;
	camData[0] = BIT_MBIDCAM_POLL | BIT_MBIDCAM_WT_EN | BIT_MBIDCAM_VALID |
			(priv_root->vap_init_seq & BIT_MASK_MBIDCAM_ADDR)<<BIT_SHIFT_MBIDCAM_ADDR |
			(macAddr[5] << 8) | macAddr[4];
	camData[1] = (macAddr[3] << 24) | (macAddr[2] << 16) | (macAddr[1] << 8) | macAddr[0];
	for (j=1; j>=0; j--) {
		RTL_W32((REG_MBIDCAMCFG_1+4)-4*j, camData[j]);
	}
	
	if (!priv_root->pmib->miscEntry.func_off) {
		priv_root->func_off_already = 0;
		priv->pshare->bcn_priv[nr_bcn++] = priv_root;
	} else {
		priv_root->func_off_already = 1;
		priv->pshare->bcn_priv[0] = priv_root;
		mbssid_ctrl &= ~BIT0;
	}
	
	for (i = 0; i < RTL8192CD_NUM_VWLAN; ++i) {
		priv_vap = priv_root->pvap_priv[i];
		if (!IS_DRV_OPEN(priv_vap))
			continue;

		if (priv_vap->pmib->miscEntry.func_off) {
			priv_vap->func_off_already = 1;
			continue;
		}
		priv_vap->func_off_already = 0;
		
		priv_vap->vap_init_seq = nr_bcn;
		priv->pshare->bcn_priv[nr_bcn++] = priv_vap;
		
		macAddr = priv_vap->pmib->dot11OperationEntry.hwaddr;
		camData[0] = BIT_MBIDCAM_POLL | BIT_MBIDCAM_WT_EN | BIT_MBIDCAM_VALID |
				(priv_vap->vap_init_seq & BIT_MASK_MBIDCAM_ADDR)<<BIT_SHIFT_MBIDCAM_ADDR |
				(macAddr[5] << 8) | macAddr[4];
		camData[1] = (macAddr[3] << 24) | (macAddr[2] << 16) | (macAddr[1] << 8) | macAddr[0];
		for (j=1; j>=0; j--) {
			RTL_W32((REG_MBIDCAMCFG_1+4)-4*j, camData[j]);
		}
		
		hal_fill_bcn_desc(priv_vap, &priv_vap->tx_descB, priv_vap->beaconbuf,
			priv_vap->tx_beacon_len, 1);
		SetDTIM(priv_vap);

		mbssid_ctrl |= BIT(priv_vap->vap_init_seq);
	}

	priv->pshare->nr_bcn = nr_bcn;
	nr_vap = (nr_bcn > 1) ? (nr_bcn - 1) : 0;
	
	inter_bcn_space = priv_root->pmib->dot11StationConfigEntry.dot11BeaconPeriod/(nr_vap+1);
	if (inter_bcn_space > 200)
		inter_bcn_space = 200;
	priv->pshare->inter_bcn_space = inter_bcn_space * NET80211_TU_TO_US;
	
	RTL_W8(REG_MBID_NUM, nr_vap & BIT_MASK_MBID_BCN_NUM);
	RTL_W8(REG_MBSSID_CTRL, mbssid_ctrl);
	RTL_W32(REG_MBSSID_BCN_SPACE, (inter_bcn_space & BIT_MASK_BCN_SPACE1)<<BIT_SHIFT_BCN_SPACE1
		|(priv_root->pmib->dot11StationConfigEntry.dot11BeaconPeriod & BIT_MASK_BCN_SPACE0)<<BIT_SHIFT_BCN_SPACE0);
	
	RTL_W8(REG_BCN_CTRL, 0);
	//RTL_W8(REG_DUAL_TSF_RST, 1);
	RTL_W8(REG_BCN_CTRL, BIT_EN_BCN_FUNCTION | BIT_DIS_TSF_UDT| BIT_P0_EN_TXBCN_RPT | BIT_DIS_RX_BSSID_FIT);

	// update TBTT prohibit hold time according to current beacon settings
	if (0 == nr_bcn)
		RTL_W32(TBTT_PROHIBIT, (RTL_R32(TBTT_PROHIBIT)&0xfff000ff) | 0x100);
	else if (inter_bcn_space <= 40)
		RTL_W32(TBTT_PROHIBIT, (RTL_R32(TBTT_PROHIBIT)&0xfff000ff) | 0x1df00);
	else if (1 == nr_bcn)
		RTL_W32(TBTT_PROHIBIT, (RTL_R32(TBTT_PROHIBIT)&0xfff000ff) | 0x40000);
	else
		RTL_W32(TBTT_PROHIBIT, (RTL_R32(TBTT_PROHIBIT)&0xfff000ff) | 0x1df00);
	
	if (0 == nr_vap) {
		// Use BCNQ0 for Root-only
		RTL_W8(REG_DWBCN1_CTRL+2, RTL_R8(REG_DWBCN1_CTRL+2) & ~BIT4);
	}
	
	RTL_W32(REG_RCR, RTL_R32(REG_RCR) & ~BIT_ENMBID);
	RTL_W32(REG_RCR, RTL_R32(REG_RCR) | BIT_ENMBID);
}

void rtl8192cd_sort_mbssid_bcn(struct rtl8192cd_priv *priv)
{
	_irqL irqL;

	SMP_LOCK_MBSSID(&irqL);

	__rtl8192cd_sort_mbssid_bcn(priv);
	
	SMP_UNLOCK_MBSSID(&irqL);
}

void rtl8192cd_stop_mbssid(struct rtl8192cd_priv *priv)
{
	int i, j;
	unsigned int camData[2];
	_irqL irqL;
	
	camData[1] = 0;
	
	SMP_LOCK_MBSSID(&irqL);

	if (IS_ROOT_INTERFACE(priv))
	{
		// clear the rest area of CAM
		for (i=0; i<8; i++) {
			camData[0] = BIT_MBIDCAM_POLL | BIT_MBIDCAM_WT_EN | (i & BIT_MASK_MBIDCAM_ADDR)<<BIT_SHIFT_MBIDCAM_ADDR;
			for (j=1; j>=0; j--) {
				RTL_W32((REG_MBIDCAMCFG_1+4)-4*j, camData[j]);
			}
		}
		
		priv->pshare->nr_bcn = 1;
		priv->pshare->bcn_priv[0] = priv;
		priv->pshare->inter_bcn_space = priv->pmib->dot11StationConfigEntry.dot11BeaconPeriod * NET80211_TU_TO_US;

		RTL_W32(REG_RCR, RTL_R32(REG_RCR) & ~BIT_ENMBID);	// MBSSID disable
		RTL_W32(REG_MBSSID_BCN_SPACE,
			(priv->pmib->dot11StationConfigEntry.dot11BeaconPeriod & BIT_MASK_BCN_SPACE0)<<BIT_SHIFT_BCN_SPACE0);

		RTL_W8(REG_BCN_CTRL, 0);
		//RTL_W8(REG_DUAL_TSF_RST, 1);
		RTL_W8(REG_BCN_CTRL, BIT_EN_BCN_FUNCTION | BIT_DIS_TSF_UDT| BIT_P0_EN_TXBCN_RPT);
	}
	else if (IS_VAP_INTERFACE(priv) && (priv->vap_init_seq >= 0))
	{
		if (priv->func_off_already) {
			priv->vap_init_seq = -1;
			SMP_UNLOCK_MBSSID(&irqL);
			return;
		}

		__rtl8192cd_sort_mbssid_bcn(priv);
		priv->vap_init_seq = -1;
	}
	
	SMP_UNLOCK_MBSSID(&irqL);
}

void rtl8192cd_set_mbidcam(struct rtl8192cd_priv *priv, unsigned char *macAddr, unsigned char index)
{
	int j;
	unsigned int camData[2];

	camData[0] = BIT_MBIDCAM_POLL | BIT_MBIDCAM_WT_EN | BIT_MBIDCAM_VALID |
			(index & BIT_MASK_MBIDCAM_ADDR)<<BIT_SHIFT_MBIDCAM_ADDR |
			(macAddr[5] << 8) | macAddr[4];
	camData[1] = (macAddr[3] << 24) | (macAddr[2] << 16) | (macAddr[1] << 8) | macAddr[0];
	for (j=1; j>=0; j--) {
		RTL_W32((REG_MBIDCAMCFG_1+4)-4*j, camData[j]);
	}
}

void rtl8192cd_clear_mbidcam(struct rtl8192cd_priv *priv, unsigned char index)
{
	int j;
	unsigned int camData[2];

	camData[0] = BIT_MBIDCAM_POLL | BIT_MBIDCAM_WT_EN | (index & BIT_MASK_MBIDCAM_ADDR)<<BIT_SHIFT_MBIDCAM_ADDR;
	camData[1] = 0;
	for (j=1; j>=0; j--) {
		RTL_W32((REG_MBIDCAMCFG_1+4)-4*j, camData[j]);
	}
}
#endif // MBSSID

