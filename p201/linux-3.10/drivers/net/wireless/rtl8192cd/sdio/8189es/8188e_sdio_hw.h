/*
 *  Header files defines some SDIO TX inline routines
 *
 *  Copyright (c) 2017 Realtek Semiconductor Corp.
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License version 2 as
 *  published by the Free Software Foundation.
 */

#ifndef _8188E_SDIO_HW_H_
#define _8188E_SDIO_HW_H_

extern struct sdio_driver rtl8192cd_sdio_driver;

extern int Load_88E_Firmware(struct rtl8192cd_priv *priv);
extern u8 _CardEnable(struct rtl8192cd_priv *priv);
extern int rtl8188es_InitPowerOn(struct rtl8192cd_priv *priv);

#ifdef CONFIG_EXT_CLK_26M
extern void _InitClockTo26MHz(struct rtl8192cd_priv *priv);
#endif

#ifdef MBSSID
void rtl8192cd_init_mbssid(struct rtl8192cd_priv *priv);
void rtl8192cd_stop_mbssid(struct rtl8192cd_priv *priv);
void rtl8192cd_sort_mbssid_bcn(struct rtl8192cd_priv *priv);

void rtl8192cd_set_mbidcam(struct rtl8192cd_priv *priv, unsigned char *macAddr, unsigned char index);
void rtl8192cd_clear_mbidcam(struct rtl8192cd_priv *priv, unsigned char index);
#endif

#endif // _8188E_SDIO_HW_H_

