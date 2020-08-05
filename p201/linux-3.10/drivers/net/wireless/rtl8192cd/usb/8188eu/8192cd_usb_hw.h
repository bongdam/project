/*
 *  Header files defines some SDIO TX inline routines
 *
 *  Copyright (c) 2017 Realtek Semiconductor Corp.
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License version 2 as
 *  published by the Free Software Foundation.
 */

#ifndef _8192CD_USB_HW_H_
#define _8192CD_USB_HW_H_

extern struct usb_driver rtl8192cd_usb_driver;

int Load_88E_Firmware(struct rtl8192cd_priv *priv);
u8 _CardEnable(struct rtl8192cd_priv *priv);
int rtl8188eu_InitPowerOn(struct rtl8192cd_priv *priv);
#ifdef MBSSID
void rtl8192cd_init_mbssid(struct rtl8192cd_priv *priv);
void rtl8192cd_stop_mbssid(struct rtl8192cd_priv *priv);
void rtl8192cd_sort_mbssid_bcn(struct rtl8192cd_priv *priv);

void rtl8192cd_set_mbidcam(struct rtl8192cd_priv *priv, unsigned char *macAddr, unsigned char index);
void rtl8192cd_clear_mbidcam(struct rtl8192cd_priv *priv, unsigned char index);
#endif

#endif // _8192CD_USB_HW_H_

