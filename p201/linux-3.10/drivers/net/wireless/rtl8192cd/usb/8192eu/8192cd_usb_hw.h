/*
 *  Header files defines some SDIO TX inline routines
 *
 *  $Id: 8192cd_usb_hw.h,v 1.4.4.5 2010/12/10 06:11:55 family Exp $
 *
 *  Copyright (c) 2009 Realtek Semiconductor Corp.
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License version 2 as
 *  published by the Free Software Foundation.
 */

#ifndef _8192CD_USB_HW_H_
#define _8192CD_USB_HW_H_

extern struct usb_driver rtl8192cd_usb_driver;

u8 _CardEnable(struct rtl8192cd_priv *priv);

#if defined(MBSSID)
void rtl8192cd_init_mbssid_usb(struct rtl8192cd_priv *priv);
void rtl8192cd_stop_mbssid_usb(struct rtl8192cd_priv *priv);
void rtl8192cd_sort_mbssid_bcn(struct rtl8192cd_priv *priv);

void rtl8192cd_set_mbidcam(struct rtl8192cd_priv *priv, unsigned char *macAddr, unsigned char index);
void rtl8192cd_clear_mbidcam(struct rtl8192cd_priv *priv, unsigned char index);
#endif

#endif /* _8192CD_USB_HW_H_ */

