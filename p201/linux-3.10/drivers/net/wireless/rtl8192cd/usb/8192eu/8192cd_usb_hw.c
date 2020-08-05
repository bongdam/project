/*
 *  RX handle routines
 *
 *  $Id: 8192cd_usb_hw.c,v 1.27.2.31 2010/12/31 08:37:43 family Exp $
 *
 *  Copyright (c) 2009 Realtek Semiconductor Corp.
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License version 2 as
 *  published by the Free Software Foundation.
 */

#define _8192CD_USB_HW_C_

#include "8192cd.h"
#include "8192cd_headers.h"
#include "8192cd_debug.h"
#include "WlanHAL/HalHeader/HalComBit.h"
#include "WlanHAL/HalHeader/HalComReg.h"


extern struct _device_info_ wlan_device[];
extern int drv_registered;

extern int USB_DEVICE_IDX(void);
extern void set_wlandev_idx(int idx);


extern int MDL_DEVINIT rtl8192cd_init_one(struct usb_interface *pusb_intf,
        const struct usb_device_id *ent, struct _device_info_ *wdev, int vap_idx);
extern void rtl8192cd_deinit_one(struct rtl8192cd_priv *priv);

extern VOID SetDTIM(IN  HAL_PADAPTER Adapter);

static int MDL_DEVINIT rtw_drv_init(struct usb_interface *pusb_intf, const struct usb_device_id *pdid)
{
    int ret;
#if defined(MBSSID)
    int i;
#endif

    /*
     * 2009.8.13, by Thomas
     * In this probe function, O.S. will provide the usb interface pointer to driver.
     * We have to increase the reference count of the usb device structure by using the usb_get_dev function.
     */
    usb_get_dev(interface_to_usbdev(pusb_intf));
    ret = rtl8192cd_init_one(pusb_intf, pdid, &wlan_device[USB_DEVICE_IDX()], -1);
    if (ret)
        goto error;

#if defined(UNIVERSAL_REPEATER)
    ret = rtl8192cd_init_one(pusb_intf, pdid, &wlan_device[USB_DEVICE_IDX()], -1);
    if (ret)
        goto error;
#endif

#if defined(MBSSID)
    for (i = 0; i < RTL8192CD_NUM_VWLAN; i++) {
        ret = rtl8192cd_init_one(pusb_intf, pdid, &wlan_device[USB_DEVICE_IDX()], i);
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
    if (NULL != wlan_device[USB_DEVICE_IDX()].priv) {
        rtl8192cd_deinit_one(wlan_device[USB_DEVICE_IDX()].priv);
        wlan_device[USB_DEVICE_IDX()].priv = NULL;
    }

    usb_put_dev(interface_to_usbdev(pusb_intf)); /* decrease the reference count of the usb device structure if driver fail on initialzation */

    return ret;
}

static void MDL_DEVEXIT rtw_dev_remove(struct usb_interface *pusb_intf)
{
    struct net_device *dev = usb_get_intfdata(pusb_intf);
    struct rtl8192cd_priv *priv = GET_DEV_PRIV(dev);

    usb_set_intfdata(pusb_intf, NULL);

    if (priv) {
        priv->pshare->bDriverStopped = TRUE;
        if (TRUE == drv_registered)
            priv->pshare->bSurpriseRemoved = TRUE;
    }

    if (NULL != wlan_device[USB_DEVICE_IDX()].priv) {
        rtl8192cd_deinit_one(wlan_device[USB_DEVICE_IDX()].priv);
        wlan_device[USB_DEVICE_IDX()].priv = NULL;
    }

    usb_put_dev(interface_to_usbdev(pusb_intf)); /* decrease the reference count of the usb device structure when disconnect */
}

static struct usb_device_id rtw_usb_id_tbl[] ={
    /*=== Realtek demoboard ===*/
#if defined(CONFIG_RTL_88E_SUPPORT)
    {USB_DEVICE(USB_VENDER_ID_REALTEK, 0x8179)},/* Default ID */
#elif defined(CONFIG_RTL_92E_SUPPORT)
    {USB_DEVICE_AND_INTERFACE_INFO(USB_VENDER_ID_REALTEK, 0x818B,0xff,0xff,0xff)}, /* Default ID */
    {USB_DEVICE_AND_INTERFACE_INFO(USB_VENDER_ID_REALTEK, 0x818C,0xff,0xff,0xff)}, /* Default ID */
#elif defined(CONFIG_RTL_92F_SUPPORT)
    {USB_DEVICE_AND_INTERFACE_INFO(USB_VENDER_ID_REALTEK, 0xf192,0xff,0xff,0xff)}, /* Default ID */
#else
    #error "triband undefined!!"
#endif

    {}  /* Terminating entry */
};

MODULE_DEVICE_TABLE(usb, rtw_usb_id_tbl);

struct usb_driver rtl8192cd_usb_driver = {
    .name = (char*)DRV_NAME,
    .id_table = rtw_usb_id_tbl,
    .probe = rtw_drv_init,
    .disconnect = rtw_dev_remove,
};

#if defined(MBSSID)
static DEFINE_MUTEX(_mbssid_mutex);
void rtl8192cd_init_mbssid_usb(struct rtl8192cd_priv *priv)
{
    int i, j;
    unsigned int camData[2];
    unsigned char *macAddr = GET_MY_HWADDR;
    unsigned int inter_bcn_space;
    int nr_vap;
    _irqL irqL;

    //SMP_LOCK_MBSSID(&irqL);
    mutex_lock(&_mbssid_mutex);

    if (IS_ROOT_INTERFACE(priv)) {
        camData[0] = BIT_MBIDCAM_POLL | BIT_MBIDCAM_WT_EN | BIT_MBIDCAM_VALID | (macAddr[5] << 8) | macAddr[4];
        camData[1] = (macAddr[3] << 24) | (macAddr[2] << 16) | (macAddr[1] << 8) | macAddr[0];
        for (j=1; j>=0; j--) {
            RTL_W32((REG_MBIDCAMCFG_1+4)-4*j, camData[j]);
        }

        /* clear the rest area of CAM */
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

        RTL_W32(REG_MBSSID_BCN_SPACE,
            (priv->pmib->dot11StationConfigEntry.dot11BeaconPeriod & BIT_MASK_BCN_SPACE1)<<BIT_SHIFT_BCN_SPACE1
            |(priv->pmib->dot11StationConfigEntry.dot11BeaconPeriod & BIT_MASK_BCN_SPACE0)<<BIT_SHIFT_BCN_SPACE0);

        RTL_W8(REG_BCN_CTRL, 0);
        RTL_W8(REG_DUAL_TSF_RST, 1);
        RTL_W8(REG_BCN_CTRL, BIT_EN_BCN_FUNCTION|BIT_DIS_TSF_UDT|BIT_EN_TXBCN_RPT | BIT_DIS_RX_BSSID_FIT);

        RTL_W32(REG_RCR, RTL_R32(REG_RCR) | BIT_ENMBID); /* MBSSID enable */

        /* SW control use BCNQ0 for Root-only */
        RTL_W32(REG_DWBCN1_CTRL, (RTL_R32(REG_DWBCN1_CTRL) & ~BIT20) | BIT17);
    } else if (IS_VAP_INTERFACE(priv)) {
        if (priv->pmib->miscEntry.func_off) {
            priv->func_off_already = 1;
            priv->vap_init_seq = 0;
            //SMP_UNLOCK_MBSSID(&irqL);
            mutex_unlock(&_mbssid_mutex);
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

        RTL_W32(REG_MBSSID_BCN_SPACE, (inter_bcn_space & BIT_MASK_BCN_SPACE1)<<BIT_SHIFT_BCN_SPACE1
            |(priv->pmib->dot11StationConfigEntry.dot11BeaconPeriod & BIT_MASK_BCN_SPACE0)<<BIT_SHIFT_BCN_SPACE0);

        RTL_W8(REG_BCN_CTRL, 0);
        RTL_W8(REG_DUAL_TSF_RST, 1);
        RTL_W8(REG_BCN_CTRL, BIT_EN_BCN_FUNCTION | BIT_DIS_TSF_UDT|BIT_EN_TXBCN_RPT |BIT_DIS_RX_BSSID_FIT);
        RTL_W8(REG_MBID_NUM, (RTL_R8(REG_MBID_NUM) & ~BIT_MASK_MBID_BCN_NUM) | (nr_vap & BIT_MASK_MBID_BCN_NUM));

        RTL_W32(REG_RCR, RTL_R32(REG_RCR) & ~BIT_ENMBID);
        RTL_W32(REG_RCR, RTL_R32(REG_RCR) | BIT_ENMBID); /* MBSSID enable */
    }

    //SMP_UNLOCK_MBSSID(&irqL);
    mutex_unlock(&_mbssid_mutex);
}

extern void hal_fill_bcn_desc(struct rtl8192cd_priv *priv, struct tx_desc *pdesc, void *dat_content, unsigned int txLength, char forceUpdate);

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
    RTL_W8(REG_BCN_CTRL, BIT_EN_BCN_FUNCTION | BIT_DIS_TSF_UDT| BIT_EN_TXBCN_RPT | BIT_DIS_RX_BSSID_FIT);

    /* update TBTT prohibit hold time according to current beacon settings */
    if (0 == nr_bcn)
        RTL_W32(TBTT_PROHIBIT, (RTL_R32(TBTT_PROHIBIT)&0xfff000ff) | 0x100);
    else if (inter_bcn_space <= 40)
        RTL_W32(TBTT_PROHIBIT, (RTL_R32(TBTT_PROHIBIT)&0xfff000ff) | 0x1df00);
    else if (1 == nr_bcn)
        RTL_W32(TBTT_PROHIBIT, (RTL_R32(TBTT_PROHIBIT)&0xfff000ff) | 0x40000);
    else
        RTL_W32(TBTT_PROHIBIT, (RTL_R32(TBTT_PROHIBIT)&0xfff000ff) | 0x1df00);

    if (0 == nr_vap) {
        /* Use BCNQ0 for Root-only */
        RTL_W8(REG_DWBCN1_CTRL+2, RTL_R8(REG_DWBCN1_CTRL+2) & ~BIT4);
    }

    RTL_W32(REG_RCR, RTL_R32(REG_RCR) & ~BIT_ENMBID);
    RTL_W32(REG_RCR, RTL_R32(REG_RCR) | BIT_ENMBID);
}

void rtl8192cd_sort_mbssid_bcn(struct rtl8192cd_priv *priv)
{
    _irqL irqL;

    //SMP_LOCK_MBSSID(&irqL);
    mutex_lock(&_mbssid_mutex);

    __rtl8192cd_sort_mbssid_bcn(priv);

    //SMP_UNLOCK_MBSSID(&irqL);
    mutex_unlock(&_mbssid_mutex);
}

void rtl8192cd_stop_mbssid_usb(struct rtl8192cd_priv *priv)
{
    int i, j;
    unsigned int camData[2];
    _irqL irqL;

    camData[1] = 0;

    //SMP_LOCK_MBSSID(&irqL);
    mutex_lock(&_mbssid_mutex);

    if (IS_ROOT_INTERFACE(priv)) {
        /* clear the rest area of CAM */
        for (i=0; i<8; i++) {
            camData[0] = BIT_MBIDCAM_POLL | BIT_MBIDCAM_WT_EN | (i & BIT_MASK_MBIDCAM_ADDR)<<BIT_SHIFT_MBIDCAM_ADDR;
            for (j=1; j>=0; j--) {
                RTL_W32((REG_MBIDCAMCFG_1+4)-4*j, camData[j]);
            }
        }

        priv->pshare->nr_bcn = 1;
        priv->pshare->bcn_priv[0] = priv;
        priv->pshare->inter_bcn_space = priv->pmib->dot11StationConfigEntry.dot11BeaconPeriod * NET80211_TU_TO_US;

        RTL_W32(REG_RCR, RTL_R32(REG_RCR) & ~BIT_ENMBID); /* MBSSID disable */
        RTL_W32(REG_MBSSID_BCN_SPACE,
            (priv->pmib->dot11StationConfigEntry.dot11BeaconPeriod & BIT_MASK_BCN_SPACE0)<<BIT_SHIFT_BCN_SPACE0);

        RTL_W8(REG_BCN_CTRL, 0);
        //RTL_W8(REG_DUAL_TSF_RST, 1);
        RTL_W8(REG_BCN_CTRL, BIT_EN_BCN_FUNCTION | BIT_DIS_TSF_UDT| BIT_EN_TXBCN_RPT);
    } else if (IS_VAP_INTERFACE(priv) && (priv->vap_init_seq >= 0)) {
        if (priv->func_off_already) {
            priv->vap_init_seq = -1;
            //SMP_UNLOCK_MBSSID(&irqL);
            mutex_unlock(&_mbssid_mutex);
            return;
        }

        __rtl8192cd_sort_mbssid_bcn(priv);
        priv->vap_init_seq = -1;
    }

    //SMP_UNLOCK_MBSSID(&irqL);
    mutex_unlock(&_mbssid_mutex);
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
#endif /* defined(MBSSID) */

